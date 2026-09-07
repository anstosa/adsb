"""Reconcile validated station settings into a fixed, isolated receiver stack."""

import argparse
import hashlib
import json
import logging
import math
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen
from uuid import UUID

from adsb_admin.map_defaults import VIEW_DEFAULTS, config_js

NETWORKS = ("adsbexchange", "flightaware", "adsblol", "airplaneslive")
DESTINATIONS = {
    "adsbexchange": ("feed1.adsbexchange.com", "feed.adsbexchange.com", 39008),
    "adsblol": ("in.adsb.lol", "in.adsb.lol", 39009),
    "airplaneslive": ("feed.airplanes.live", "feed.airplanes.live", 39010),
}
IMAGE_PATTERN = re.compile(r"^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$")
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ACTIVATION_PATTERN = re.compile(r"^[0-9a-f]{32}$")
MANAGED_SERVICES = frozenset(("ultrafeeder", "proxy", "airspy", "dump978", "piaware", "cloudflared"))
FLIGHTAWARE_CLAIM_BASE = "https://www.flightaware.com/adsb/piaware/claim/"


# revalidate the unprivileged configuration before applying privileged changes
def validate_settings(value):
    # require the exact persistent schema
    if not isinstance(value, dict) or set(value) != {"revision", "station", "networks"}:
        raise ValueError("invalid settings structure")
    # reject boolean or negative revisions
    if type(value["revision"]) is not int or value["revision"] < 0:
        raise ValueError("invalid revision")
    station = value["station"]
    # require the known station fields
    if not isinstance(station, dict) or set(station) != {"name", "latitude", "longitude", "altitude_m"}:
        raise ValueError("invalid station structure")
    # exclude configuration delimiters from station names
    if not isinstance(station["name"], str) or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,64}", station["name"]):
        raise ValueError("station name must use letters, numbers, spaces, dots, hyphens or underscores")
    # constrain numeric values before serializing decoder options
    for key, lower, upper in (("latitude", -90, 90), ("longitude", -180, 180), ("altitude_m", -500, 10000)):
        number = station[key]
        # require finite in-range coordinates
        if number is not None and (
            type(number) not in (int, float) or not math.isfinite(number) or not lower <= number <= upper
        ):
            raise ValueError("invalid station coordinates")
    # allow only the four supported networks
    if not isinstance(value["networks"], dict) or set(value["networks"]) != set(NETWORKS):
        raise ValueError("unsupported network")
    # accept only known switches and UUID identifiers
    for name, network in value["networks"].items():
        # reject extra per-network options
        if not isinstance(network, dict) or set(network) != {"enabled", "mlat", "feeder_id"}:
            raise ValueError("invalid network structure")
        # require real boolean switches
        if type(network["enabled"]) is not bool or type(network["mlat"]) is not bool:
            raise ValueError("invalid network switch")
        # require textual receiver identifiers
        if not isinstance(network["feeder_id"], str):
            raise ValueError("invalid feeder identifier")
        # validate each nonempty identifier
        if network["feeder_id"]:
            UUID(network["feeder_id"])
        # require actual antenna coordinates for feeds
        if network["enabled"] and any(station[key] is None for key in ("latitude", "longitude", "altitude_m")):
            raise ValueError("station location is required before enabling a feed")
        # preserve stable identities for networks that require them
        if network["enabled"] and name in ("adsbexchange", "adsblol") and not network["feeder_id"]:
            raise ValueError("a stable feeder identifier is required")
    return value


# detect supported receivers without opening or reprogramming USB devices
def detect_hardware(root=Path("/sys/bus/usb/devices")):
    devices = {"airspy": [], "uat": []}
    # inspect USB vendor/product identifiers only
    for device in root.glob("*"):
        try:
            vendor = (device / "idVendor").read_text().strip().lower()
            product = (device / "idProduct").read_text().strip().lower()
        except OSError:
            continue
        # select only known USB receiver families
        if (vendor, product) == ("1d50", "60a1"):
            devices["airspy"].append(device)
        # leave unrelated USB devices untouched
        if vendor == "0bda" and product in ("2832", "2838"):
            devices["uat"].append(device)
    detected = {name: len(matches) == 1 for name, matches in devices.items()}
    # refuse ambiguous multiple-device selection and retain stable serials when exposed
    for name, matches in devices.items():
        # refuse ambiguous device selection
        if len(matches) == 1:
            try:
                serial = (matches[0] / "serial").read_text().strip()
            except OSError:
                continue
            # ignore malformed USB serial descriptors
            if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", serial):
                detected[name + "_serial"] = serial
    return detected


# reject mutable image tags at the privileged deployment boundary
def pinned_image(runtime, name):
    image = runtime["images"][name]
    # reject mutable tags and malformed image digests
    if not isinstance(image, str) or not IMAGE_PATTERN.fullmatch(image):
        raise ValueError("container images must be pinned by digest")
    return image


# apply common process and log limits to managed containers
def container(runtime, name, memory):
    return {
        "image": pinned_image(runtime, name),
        "platform": "linux/amd64",
        "restart": "unless-stopped",
        "mem_limit": memory,
        "logging": {"driver": "json-file", "options": {"max-size": "5m", "max-file": "2"}},
        "security_opt": ["no-new-privileges:true"],
    }


# render only fixed services and destinations from validated settings
def compose_for(settings, runtime, hardware):
    validate_settings(settings)
    station = settings["station"]
    data_dir = runtime["data_dir"]
    source_dir = runtime["source_dir"]
    core = container(runtime, "ultrafeeder", "640m")
    environment = {
        "TZ": "America/Los_Angeles",
        "READSB_NET_ONLY": "true",
        "READSB_NET_BEAST_REDUCE_INTERVAL": "0.5",
        "READSB_STATS_RANGE": "true",
        "PROMETHEUS_ENABLE": "true",
        "UPDATE_TAR1090": "false",
        # serve the reviewed static ui while retaining local decoder routes
        "CUSTOM_HTML": "true",
        # use the display-only fallback until actual site coordinates are known
        "TAR1090_DEFAULTCENTERLAT": VIEW_DEFAULTS["CenterLat"],
        "TAR1090_DEFAULTCENTERLON": VIEW_DEFAULTS["CenterLon"],
        "TAR1090_DEFAULTZOOMLVL": VIEW_DEFAULTS["zoomLvl"],
        "TAR1090_PAGETITLE": "Ballydídean Farm Sanctuary ADS-B",
        "TAR1090_MAPTYPE_TAR1090": "osm",
        # seed reviewed first-visit preferences without replacing browser choices
        "TAR1090_CONFIGJS_APPEND": config_js(),
        "MLAT_USER": station["name"].replace(" ", "_"),
        "LOGLEVEL": "error",
    }
    # omit unknown coordinates rather than inventing a receiver location
    if station["latitude"] is not None and station["longitude"] is not None:
        environment.update(
            {
                "READSB_LAT": str(station["latitude"]),
                "READSB_LON": str(station["longitude"]),
                "TAR1090_DEFAULTCENTERLAT": str(station["latitude"]),
                "TAR1090_DEFAULTCENTERLON": str(station["longitude"]),
            }
        )
    # send elevation only after it is configured
    if station["altitude_m"] is not None:
        environment["READSB_ALT"] = f"{station['altitude_m']}m"
    connectors = []
    services = {"ultrafeeder": core}
    # add real receiver inputs only when the matching radio is attached
    if hardware["airspy"]:
        connectors.append("adsb,airspy,30005,beast_in")
        airspy = container(runtime, "airspy", "256m")
        airspy_env = {
            "TZ": "America/Los_Angeles",
            "AIRSPY_ADSB_SAMPLE_RATE": "12",
            "AIRSPY_ADSB_RF_GAIN": "auto",
            "AIRSPY_ADSB_CPUTIME_TARGET": "90",
            "AIRSPY_ADSB_PREAMBLE_FILTER_MAX": "20",
            "AIRSPY_ADSB_TIMEOUT": "90",
            "AIRSPY_ADSB_PREAMBLE_FILTER_NONCRC": "5",
            "AIRSPY_ADSB_STATS": "true",
        }
        # use the detected serial rather than a changing device index
        if hardware.get("airspy_serial"):
            airspy_env["AIRSPY_ADSB_SERIAL"] = hardware["airspy_serial"]
        airspy.update(
            {
                "device_cgroup_rules": ["c 189:* rwm"],
                "volumes": ["/dev/bus/usb:/dev/bus/usb:ro"],
                "environment": airspy_env,
            }
        )
        services["airspy"] = airspy
    # add the separate UAT decoder without guessing RF tuning or bias power
    if hardware["uat"]:
        connectors.append("adsb,dump978,30978,uat_in")
        uat = container(runtime, "dump978", "256m")
        uat_env = {"TZ": "America/Los_Angeles", "DUMP978_DEVICE_TYPE": "rtlsdr"}
        # select the detected RTL receiver when its serial is available
        if hardware.get("uat_serial"):
            uat_env["DUMP978_RTLSDR_DEVICE"] = hardware["uat_serial"]
        # expose the configured receiver location to the UAT map
        if station["latitude"] is not None and station["longitude"] is not None:
            uat_env.update({"LAT": str(station["latitude"]), "LON": str(station["longitude"])})
        uat.update(
            {
                "device_cgroup_rules": ["c 188:* rwm", "c 189:* rwm"],
                "volumes": ["/dev/bus/usb:/dev/bus/usb:ro"],
                "environment": uat_env,
                "tmpfs": ["/run:exec,size=64m", "/tmp:size=64m", "/var/log:size=32m"],
            }
        )
        environment.update({"ENABLE_978": "yes", "URL_978": "http://dump978/skyaware978"})
        services["dump978"] = uat
    # hardware absence is an additional safeguard against fixture egress
    for name, (host, mlat_host, return_port) in DESTINATIONS.items():
        network = settings["networks"][name]
        # activate only requested feeds with real hardware
        if network["enabled"] and (hardware["airspy"] or hardware["uat"]):
            identifier = f",uuid={network['feeder_id']}" if network["feeder_id"] else ""
            connectors.append(f"adsb,{host},30004,beast_reduce_plus_out{identifier}")
            # gate MLAT independently on the 1090 receiver
            if network["mlat"] and hardware["airspy"]:
                connectors.append(f"mlat,{mlat_host},31090,{return_port}{identifier}")
    environment["ULTRAFEEDER_CONFIG"] = ";".join(connectors)
    core.update(
        {
            "environment": environment,
            "ports": ["127.0.0.1:8078:80", "127.0.0.1:9274:9274"],
            "volumes": [f"{data_dir}/tar1090:/var/globe_history", f"{source_dir}/map-ui:/var/custom_html:ro"],
            "labels": {"station.map-ui.digest": runtime.get("map_ui_digest", "")},
            "tmpfs": ["/run:exec,size=128m", "/tmp:size=64m"],
            "shm_size": "128m",
        }
    )
    flightaware = settings["networks"]["flightaware"]
    # stop the whole FlightAware uploader when its switch is off
    if flightaware["enabled"] and (hardware["airspy"] or hardware["uat"]):
        piaware = container(runtime, "piaware", "256m")
        piaware_env = {
            "TZ": "America/Los_Angeles",
            "RECEIVER_TYPE": "relay",
            "BEASTHOST": "ultrafeeder",
            "BEASTPORT": "30005",
            "PIAWARE_MINIMAL": "true",
            "ALLOW_MLAT": "no",
            "MLAT_RESULTS": "no",
        }
        # retain the configured FlightAware identity
        if flightaware["feeder_id"]:
            piaware_env["FEEDER_ID"] = flightaware["feeder_id"]
        # enable FlightAware MLAT only with the 1090 receiver
        if flightaware["mlat"] and hardware["airspy"]:
            piaware_env.update(
                {
                    "ALLOW_MLAT": "yes",
                    "MLAT_RESULTS": "yes",
                    "MLAT_RESULTS_BEASTHOST": "ultrafeeder",
                    "MLAT_RESULTS_BEASTPORT": "31004",
                }
            )
        # feed UAT through its documented relay rather than pretending it is Beast data
        if hardware["uat"]:
            piaware_env.update(
                {"UAT_RECEIVER_TYPE": "relay", "UAT_RECEIVER_HOST": "dump978", "UAT_RECEIVER_PORT": "30978"}
            )
        piaware.update(
            {
                "environment": piaware_env,
                "depends_on": ["ultrafeeder"],
                # keep absent radio traffic out of process health
                "healthcheck": {
                    "test": ["CMD-SHELL", "pgrep -x piaware >/dev/null"],
                    "interval": "10s",
                    "timeout": "5s",
                    "retries": 3,
                    "start_period": "20s",
                },
                "volumes": [f"{data_dir}/piaware:/var/cache/piaware"],
                "tmpfs": ["/run:exec,size=64m", "/tmp:size=32m"],
            }
        )
        services["piaware"] = piaware
    proxy = container(runtime, "proxy", "64m")
    proxy.update(
        {
            "user": "101:101",
            "cap_drop": ["ALL"],
            "network_mode": "host",
            "labels": {"station.config.digest": runtime.get("proxy_config_digest", "")},
            "volumes": [f"{source_dir}/deploy/nginx.conf:/etc/nginx/nginx.conf:ro"],
            "read_only": True,
            "tmpfs": [
                "/var/cache/nginx:uid=101,gid=101,mode=0700",
                "/var/run:uid=101,gid=101,mode=0700",
                "/tmp:mode=1777",
            ],
        }
    )
    services["proxy"] = proxy
    # expose only the web proxy through a dedicated named tunnel
    if runtime.get("tunnel_enabled"):
        tunnel = container(runtime, "cloudflared", "128m")
        tunnel.update(
            {
                "user": "0:0",
                "cap_drop": ["ALL"],
                "network_mode": "host",
                "labels": {"station.config.digest": runtime.get("tunnel_config_digest", "")},
                "command": ["tunnel", "--no-autoupdate", "--config", "/etc/cloudflared/config.yml", "run"],
                "volumes": [f"{data_dir}/cloudflared:/etc/cloudflared:ro"],
                "read_only": True,
            }
        )
        services["cloudflared"] = tunnel
    return {"name": "adsb", "services": services}


# replace state files atomically without following destination symlinks
def write_json(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


# bound and de-symlink configuration reads at the root trust boundary
def read_settings(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r") as stream:
        metadata = os.fstat(stream.fileno())
        # reject special files and oversized input before decoding
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
            raise ValueError("invalid settings file")
        content = stream.read(65537)
        # defend against growth after the size check
        if len(content) > 65536:
            raise ValueError("settings file too large")
    return validate_settings(json.loads(content))


# build a claim route from configured or provider-persisted identity
def flightaware_claim_url(configured_id, cache_path):
    feeder_id = configured_id
    # read PiAware's assigned identity only when no import overrides it
    if not feeder_id:
        try:
            descriptor = os.open(cache_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "r") as stream:
                metadata = os.fstat(stream.fileno())
                # reject special or oversized provider state
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128:
                    return ""
                feeder_id = stream.read(129).strip().lower()
        except OSError:
            return ""
    # accept only canonical UUID text in a fixed destination
    if not UUID_PATTERN.fullmatch(feeder_id):
        return ""
    return FLIGHTAWARE_CLAIM_BASE + feeder_id


# stop only this project's potential uploaders when configuration cannot be trusted
def stop_uploaders():
    failures = []
    # scope shutdown to this project's uploader services
    for service in ("ultrafeeder", "piaware"):
        try:
            result = subprocess.run(
                [
                    "docker",
                    "ps",
                    "-q",
                    "--filter",
                    "label=com.docker.compose.project=adsb",
                    "--filter",
                    f"label=com.docker.compose.service={service}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
            identifiers = result.stdout.split()
            # validate identifiers before invoking Docker
            if any(not re.fullmatch(r"[a-f0-9]{12,64}", identifier) for identifier in identifiers):
                raise ValueError("unexpected Docker identifier")
            # skip shutdown when no matching containers are running
            if identifiers:
                subprocess.run(
                    ["docker", "stop", "--time", "5", *identifiers], capture_output=True, timeout=20, check=True
                )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            failures.append(service)
            log_failure("stop " + service, error)
    # finish all independent stop attempts before reporting incomplete shutdown
    if failures:
        raise RuntimeError("could not confirm shutdown of " + ", ".join(failures))


# retain actionable journal diagnostics without exposing private identifiers
def log_failure(operation, error):
    detail = getattr(error, "stderr", None) or str(error)
    # normalize captured binary command output before sanitizing
    if isinstance(detail, bytes):
        detail = detail.decode("utf-8", errors="replace")
    detail = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "[identifier]", detail
    )
    detail = re.sub(r"(?i)(token|secret|password|feeder_id|uuid)\s*[=:]\s*[^\s,;]+", r"\1=[redacted]", detail)
    logging.error(
        "%s failed (%s, returncode=%s): %s",
        operation,
        type(error).__name__,
        getattr(error, "returncode", "n/a"),
        detail[:1500],
    )


# reload root-owned runtime and hash mounted files so updates trigger recreation
def load_runtime(path):
    runtime = json.loads(path.read_text())
    source = Path(runtime["source_dir"])
    data = Path(runtime["data_dir"])
    # reject accidental relative deployment paths
    if not source.is_absolute() or not data.is_absolute():
        raise ValueError("runtime paths must be absolute")
    # bind controller observations to one installer activation
    if not isinstance(runtime.get("activation_id"), str) or not ACTIVATION_PATTERN.fullmatch(runtime["activation_id"]):
        raise ValueError("runtime activation identity is invalid")
    runtime["proxy_config_digest"] = hashlib.sha256((source / "deploy/nginx.conf").read_bytes()).hexdigest()
    runtime["map_ui_digest"] = hashlib.sha256((source / "map-ui/version.json").read_bytes()).hexdigest()
    # include credential changes without putting credential contents into labels
    if runtime.get("tunnel_enabled"):
        content = (data / "cloudflared/config.yml").read_bytes() + (data / "cloudflared/credentials.json").read_bytes()
        runtime["tunnel_config_digest"] = hashlib.sha256(content).hexdigest()
    return runtime


# read only the localhost metrics endpoint and bound response size
def connector_metrics():
    try:
        with urlopen("http://127.0.0.1:9274/metrics", timeout=2) as response:
            return response.read(1024 * 1024).decode("utf-8")
    except (OSError, URLError, UnicodeError):
        return None


# report positive connection age as TCP connectivity rather than feed acceptance
def tcp_connected(metrics, host, port=30004):
    # retain telemetry failure as an unknown observation
    if metrics is None:
        return None
    # inspect only the connector metric series
    for line in metrics.splitlines():
        # ignore unrelated metric names
        if not line.startswith("readsb_net_connector_status{"):
            continue
        # match both destination host and port
        if f'host="{host}"' in line and f'port="{port}"' in line:
            try:
                return float(line.rsplit(" ", 1)[1]) > 0
            except ValueError:
                return False
    return False


# classify only containers belonging to this fixed compose project
def service_states(compose_path):
    result = subprocess.run(
        ["docker", "compose", "-p", "adsb", "-f", str(compose_path), "ps", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    content = result.stdout.strip()
    # treat an empty project as stopped
    if not content:
        return {"running": set(), "ready": set(), "starting": set()}
    rows = json.loads(content) if content.startswith("[") else [json.loads(line) for line in content.splitlines()]
    observed = {}
    # require every instance of a service to share the reported state
    for row in rows:
        service = row.get("Service")
        # ignore malformed or unmanaged compose output
        if service not in MANAGED_SERVICES:
            continue
        state = row.get("State")
        health = row.get("Health")
        instance_running = state == "running"
        instance_ready = instance_running and health in (None, "", "healthy")
        instance_starting = instance_running and health == "starting"
        service_state = observed.setdefault(
            service,
            {"running": True, "ready": True, "transitional": True, "has_starting": False},
        )
        service_state["running"] = service_state["running"] and instance_running
        service_state["ready"] = service_state["ready"] and instance_ready
        service_state["transitional"] = service_state["transitional"] and (instance_ready or instance_starting)
        service_state["has_starting"] = service_state["has_starting"] or instance_starting
    running = {service for service, state in observed.items() if state["running"]}
    ready = {service for service, state in observed.items() if state["ready"]}
    starting = {
        service
        for service, state in observed.items()
        if state["running"] and state["transitional"] and state["has_starting"] and not state["ready"]
    }
    return {"running": running, "ready": ready, "starting": starting}


# recreate only unhealthy services in the fixed compose project
def recreate_services(compose_path, services):
    # reject any service name outside the privileged allowlist
    if not services.issubset(MANAGED_SERVICES):
        raise ValueError("unmanaged service recreation requested")
    # skip Docker when every requested service is healthy
    if not services:
        return
    subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            "adsb",
            "-f",
            str(compose_path),
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            *sorted(services),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )


# distinguish requested state, managed process state and actual TCP connectivity
def status_for(settings, hardware, running, metrics, applied_revision, claim_url="", activation_id=""):
    available = hardware["airspy"] or hardware["uat"]
    networks = {}
    # expose only nonsecret operational details
    for name in NETWORKS:
        enabled = settings["networks"][name]["enabled"]
        message = "Disabled; no uploader configured."
        connected = False
        process_running = False
        # keep requested feeds waiting without a receiver
        if enabled and not available:
            message = "Enabled in settings; waiting for physical receiver hardware."
        elif enabled:
            process_running = ("piaware" if name == "flightaware" else "ultrafeeder") in running
            # use connector telemetry only for direct feed destinations
            if name in DESTINATIONS:
                connected = tcp_connected(metrics, DESTINATIONS[name][0]) if process_running else False
                # distinguish telemetry loss from confirmed socket state
                if connected is None:
                    message = "Uploader running; connector telemetry unavailable."
                else:
                    message = (
                        "TCP connected; upstream acceptance is not independently verified."
                        if connected
                        else "Configured; awaiting network connection."
                    )
            else:
                connected = None
                # describe FlightAware enrollment separately from process state
                if process_running and claim_url:
                    message = "Uploader running; claim or verify this receiver with FlightAware."
                elif process_running:
                    message = "Uploader running; waiting for FlightAware to assign a feeder ID."
                else:
                    message = "Uploader is not running."
        networks[name] = {"enabled": enabled, "running": process_running, "connected": connected, "message": message}
        # expose a fixed claim route only for a running FlightAware uploader
        if name == "flightaware" and process_running and claim_url:
            networks[name]["claim_url"] = claim_url
    return {
        "activation_id": activation_id,
        "applied_revision": applied_revision,
        "phase": "ready" if available else "waiting",
        "message": "Receiver services staged."
        if available
        else "Awaiting radios. No simulated aircraft or feed traffic.",
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "networks": networks,
        "hardware": {
            "connected": available,
            "message": f"Airspy: {'detected' if hardware['airspy'] else 'absent'}; 978 RTL-SDR: {'detected' if hardware['uat'] else 'absent'}",
        },
    }


# reconcile desired configuration and retry failures without claiming application
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", default="/etc/adsb/runtime.json")
    parser.add_argument("--data-dir", default="/var/lib/adsb")
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args()
    data = Path(arguments.data_dir)
    status_path = data / "status/status.json"
    last_digest = None
    applied_revision = -1
    activation_id = ""
    # poll for settings changes and USB arrival without exposing a privileged API
    while True:
        try:
            activation_id = ""
            runtime = load_runtime(Path(arguments.runtime))
            activation_id = runtime["activation_id"]
            data = Path(runtime["data_dir"])
            settings_path = data / "config/settings.json"
            compose_path = data / "runtime/compose.json"
            status_path = data / "status/status.json"
            settings = read_settings(settings_path)
            hardware = detect_hardware()
            specification = compose_for(settings, runtime, hardware)
            digest = hashlib.sha256(json.dumps(specification, sort_keys=True).encode()).hexdigest()
            # apply only changed deployment specifications
            if digest != last_digest:
                write_json(compose_path, specification)
                subprocess.run(
                    ["docker", "compose", "-p", "adsb", "-f", str(compose_path), "up", "-d", "--remove-orphans"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=True,
                )
                last_digest = digest
            applied_revision = settings["revision"]
            services = service_states(compose_path)
            claim_url = flightaware_claim_url(
                settings["networks"]["flightaware"]["feeder_id"], data / "piaware/feeder_id"
            )
            status = status_for(
                settings,
                hardware,
                services["running"],
                connector_metrics(),
                applied_revision,
                claim_url,
                activation_id,
            )
            expected_services = set(specification["services"])
            not_ready_services = expected_services - services["ready"]
            failed_services = not_ready_services - services["starting"]
            # heal every requested service rather than only the map core
            if failed_services:
                status.update({"phase": "error", "message": "One or more requested services are unhealthy or stopped."})
                recreate_services(compose_path, failed_services)
                last_digest = None
            # wait for declared health checks without restarting their grace period
            elif not_ready_services:
                status.update({"phase": "starting", "message": "One or more requested services are starting."})
            write_json(status_path, status, 0o640)
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            log_failure("reconciliation", error)
            last_digest = None
            failure_message = "Deployment failed; uploaders have been stopped until valid settings can be applied."
            try:
                stop_uploaders()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                failure_message = "Deployment failed and uploader shutdown could not be confirmed; inspect the controller immediately."
            logging.error("%s", failure_message)
            # never surface configuration values or process output containing identifiers
            write_json(
                status_path,
                {
                    "activation_id": activation_id,
                    "applied_revision": applied_revision,
                    "phase": "error",
                    "message": failure_message,
                    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "networks": {},
                },
                0o640,
            )
        # support bounded verification runs
        if arguments.once:
            return
        time.sleep(5)


# run only as a separately supervised trusted process
if __name__ == "__main__":
    main()
