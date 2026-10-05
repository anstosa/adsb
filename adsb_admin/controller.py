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

from adsb_admin.diagnostics import ReceptionMonitor
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
AUXILIARY_SOURCE_SERVICES = frozenset(("alert-source-1090", "alert-source-978fallback"))
MANAGED_SERVICES = (
    frozenset(("ultrafeeder", "proxy", "airspy", "dump978", "piaware", "cloudflared")) | AUXILIARY_SOURCE_SERVICES
)
FLIGHTAWARE_CLAIM_BASE = "https://www.flightaware.com/adsb/piaware/claim/"
SOURCE_CONTRACT_KEYS = frozenset(
    (
        "schema_version",
        "marker_schema_version",
        "source_state_schema_version",
        "aircraft_json_interval_seconds",
        "stats_interval_seconds",
        "sources",
    )
)


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


# validate the immutable physical source selection
def validate_source_contract(value):
    # require one exact versioned manifest
    if not isinstance(value, dict) or set(value) != SOURCE_CONTRACT_KEYS:
        raise ValueError("invalid alert source contract")
    # bind every reader and publisher to the reviewed schema and cadence
    if (
        value["schema_version"] != 1
        or value["marker_schema_version"] != 1
        or value["source_state_schema_version"] != 2
        or value["aircraft_json_interval_seconds"] != 1
        or value["stats_interval_seconds"] != 10
    ):
        raise ValueError("unsupported alert source contract")
    sources = value["sources"]
    # require both physical bands and no dynamic adapter names
    if not isinstance(sources, dict) or set(sources) != {"1090", "978"}:
        raise ValueError("invalid alert source bands")
    expected = {
        "1090": ("alert-source-1090", "airspy", 30005, "beast_in", "1090"),
        "978": ("alert-source-978fallback", "dump978", 30978, "uat_in", "978"),
    }
    # validate the fixed readsb sources or the one documented native 978 choice
    for band, source in sources.items():
        # require one explicit fixed adapter mode
        if not isinstance(source, dict) or not isinstance(source.get("mode"), str):
            raise ValueError("invalid alert source definition")
        # retain the reviewed native choice only for conditional rollback compatibility
        if band == "978" and source["mode"] == "native-dump978":
            # reject extra endpoints or runtime selection fields
            if source != {
                "mode": "native-dump978",
                "service": "dump978",
                "url": "http://127.0.0.1:8978/skyaware978/data/aircraft.json",
            }:
                raise ValueError("invalid native 978 source")
            continue
        service, input_service, input_port, protocol, directory = expected[band]
        # match every physical connector field exactly
        if source != {
            "mode": "readsb",
            "service": service,
            "input_service": input_service,
            "input_port": input_port,
            "protocol": protocol,
            "directory": directory,
        }:
            raise ValueError("invalid readsb alert source")
    return value


# render one isolated physical-input tracker
def alert_source_container(runtime, band, source):
    service = container(runtime, "ultrafeeder", "64m")
    release = runtime["resolved_source_dir"]
    output = f"{runtime['data_dir']}/alert-source/{source['directory']}"
    service.update(
        {
            "user": "0:0",
            "cap_drop": ["ALL"],
            "read_only": True,
            "entrypoint": ["/opt/adsb-alerts-source/run-source.sh"],
            "environment": {
                "ALERT_SOURCE_BAND": band,
                "ALERT_SOURCE_INPUT_SERVICE": source["input_service"],
                "ALERT_SOURCE_INPUT_PORT": str(source["input_port"]),
                "ALERT_SOURCE_PROTOCOL": source["protocol"],
                "ALERT_SOURCE_ACTIVATION_ID": runtime["activation_id"],
                "ALERT_SOURCE_CONTRACT_DIGEST": runtime["source_contract_digest"],
            },
            "depends_on": [source["input_service"]],
            "volumes": [
                f"{release}/deploy/alerts:/opt/adsb-alerts-source:ro",
                f"{output}:/var/lib/adsb/alert-source",
            ],
            "tmpfs": ["/tmp:size=8m"],
            "labels": {
                "station.alert-source.activation": runtime["activation_id"],
                "station.alert-source.band": band,
                "station.alert-source.contract": runtime["source_contract_digest"],
            },
            "healthcheck": {
                "test": ["CMD", "/opt/adsb-alerts-source/source-health.sh"],
                # docker adds probe runtime to this post-completion interval
                "interval": "1s",
                "timeout": "5s",
                "retries": 3,
                "start_period": "20s",
            },
        }
    )
    return service


# render only fixed services and destinations from validated settings
def compose_for(settings, runtime, hardware):
    validate_settings(settings)
    source_contract = None
    # require the immutable source contract only when a physical source can be rendered
    if (hardware["airspy"] or hardware["uat"]) and runtime.get("source_contract") is not None:
        source_contract = validate_source_contract(runtime["source_contract"])
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
        "MAX_GLOBE_HISTORY": "30",
        "GRAPHS1090_DARKMODE": "true",
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
        environment.update({"ENABLE_AIRSPY": "yes", "URL_AIRSPY": "http://airspy"})
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
                "ports": ["127.0.0.1:8079:80"],
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
                "ports": ["127.0.0.1:8978:80"],
                "environment": uat_env,
                "tmpfs": ["/run:exec,size=64m", "/tmp:size=64m", "/var/log:size=32m"],
            }
        )
        environment.update({"ENABLE_978": "yes", "URL_978": "http://dump978/skyaware978"})
        services["dump978"] = uat
    # attach one isolated 1090 tracker only when its physical receiver exists
    if hardware["airspy"] and source_contract is not None:
        source = source_contract["sources"]["1090"]
        services[source["service"]] = alert_source_container(runtime, "1090", source)
    # attach the conditional fallback only when selected and its physical receiver exists
    if hardware["uat"] and source_contract is not None:
        source_978 = source_contract["sources"]["978"]
        # render only the release-selected fallback mode
        if source_978["mode"] == "readsb":
            services[source_978["service"]] = alert_source_container(runtime, "978", source_978)
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
            "volumes": [
                f"{data_dir}/tar1090:/var/globe_history",
                f"{data_dir}/collectd:/var/lib/collectd",
                f"{source_dir}/map-ui:/var/custom_html:ro",
            ],
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


# validate mandatory exact-pin g0 evidence without executing fixture code
def validate_source_proof(proof, images, health_bytes, catalog_entries):
    # reject an incomplete gate with a bounded public diagnostic
    def require(condition):
        if not condition:
            raise ValueError("alert source selection proof does not match the release")

    # require the isolated sandbox and a measured resident-memory bound
    def sandbox(section, limit):
        require(isinstance(section, dict))
        require(
            section.get("network") == "none"
            and section.get("readonly_root") is True
            and section.get("capabilities") == "none"
        )
        rss = section.get("rss_kib")
        require(type(rss) is int and 0 < rss < limit)

    require(isinstance(proof, dict) and type(proof.get("schema_version")) is int and proof["schema_version"] == 1)
    require(proof.get("image") == images["ultrafeeder"] and proof.get("dump978_image") == images["dump978"])
    require(proof.get("health_sha256") == hashlib.sha256(health_bytes).hexdigest())
    sources = proof.get("sources")
    require(isinstance(sources, list) and len(sources) == 2)
    bands = set()
    # require both measured physical paths and no alternative aircraft ingress
    for source in sources:
        sandbox(source, 64 * 1024)
        band = source.get("band")
        require(type(band) is str and band in ("1090", "978") and band not in bands)
        bands.add(band)
        # bind all positive source-contract assertions
        for key in (
            "no_position",
            "unsupported_counter_progress",
            "kernel_socket_stable",
            "kernel_bytes_progress",
            "empty_output_directory_at_start",
            "fresh_generation_marker",
        ):
            require(source.get(key) is True)
        require(source.get("alternative_aircraft_ingress") is False and source.get("readsb_listening_tcp_ports") == [])
        require(
            type(source.get("first_tracked_message")) is int
            and source["first_tracked_message"] == (2 if band == "1090" else 3)
        )
        require(
            source.get("state_mode") == "0o640"
            and type(source.get("source_state_schema")) is int
            and source["source_state_schema"] == 2
        )
        wait = source.get("startup_statistics_wait_seconds")
        require(type(wait) is int and 10 <= wait <= 20)
        accepted = source.get("accepted")
        initial = source.get("startup_accepted")
        # require bounded decoded counters and an empty startup baseline
        for counters in (accepted, initial):
            require(
                isinstance(counters, list)
                and len(counters) == 2
                and all(type(count) is int and 0 <= count <= 10**15 for count in counters)
            )
        require(sum(accepted) >= 5000 and initial == [0, 0])
        require(band != "978" or source.get("tisb_icao_retained") is True)
    native = proof.get("native978")
    require(
        isinstance(native, dict)
        and native.get("selected") is False
        and native.get("failure_code") == "independent_producer_coverage_unavailable"
    )
    require(native.get("identity_contract_passed") is True and native.get("producer_coverage_contract_passed") is False)
    require(native.get("existing_host_http_endpoint") == "http://127.0.0.1:8978/skyaware978/data/aircraft.json")
    require(type(native.get("native_json_container_port")) is int and native["native_json_container_port"] == 30979)
    require(
        native.get("native_json_tcp_host_port_published") is False and native.get("new_host_ports_allowed") is False
    )
    native_result = native.get("proof")
    sandbox(native_result, 64 * 1024)
    # require the actual native identity and stalled-input counterexample
    for key in (
        "no_position",
        "unsupported_counter_progress",
        "tisb_icao_retained",
        "writer_fresh_while_input_stalled",
        "messages_stable_while_input_stalled",
    ):
        require(native_result.get(key) is True)
    require(native_result.get("producer_coverage_fields_present") is False)
    require(type(native_result.get("first_tracked_message")) is int and native_result["first_tracked_message"] == 2)
    require(
        type(native_result.get("skyaware978_sha256")) is str
        and re.fullmatch(r"[a-f0-9]{64}", native_result["skyaware978_sha256"]) is not None
    )
    worker = proof.get("worker")
    sandbox(worker, 96 * 1024)
    expected = {
        "max_encounters": 10000,
        "encounters": 10000,
        "memory_limit_bytes": 96 * 1024 * 1024,
        "normalized_source_rows": 20000,
        "per_band_source_rows": 10000,
        "pending_event_cap": 1000,
        "pending_events": 1000,
        "pending_jobs": 2000,
        "maintenance_notification_cap": 1000,
        "maintenance_notifications": 1000,
        "maintenance_pending": 1000,
        "maintenance_body_bytes": 8192,
        "provider_dispatches": 0,
        "catalog_entries": catalog_entries,
    }
    # require complete continuity and the maximal enforced workload
    for key, count in expected.items():
        require(type(worker.get(key)) is int and worker[key] == count)
    require(worker.get("continuity_complete") is True and worker.get("channels") == ["email", "pushover"])
    require(worker.get("maintenance_channel") == "email" and worker.get("maintenance_cap_rejected") is True)
    require(worker.get("capacity_error") == "state_capacity_exceeded")
    # validate both process peak and measured cgroup memory
    for key in ("peak_rss_kib", "cgroup_current_kib"):
        require(type(worker.get(key)) is int and 0 < worker[key] < 96 * 1024)
    headroom = proof.get("production_headroom")
    require(isinstance(headroom, dict) and headroom.get("headroom_passed") is True)
    require(type(headroom.get("oom_events_last_24h")) is int and headroom["oom_events_last_24h"] == 0)
    series = []
    # require five real aggregate samples without ongoing swap pressure
    for key in ("mem_available_kib_samples", "vmstat_swap_in_kib_per_second", "vmstat_swap_out_kib_per_second"):
        values = headroom.get(key)
        require(
            isinstance(values, list)
            and len(values) == 5
            and all(type(value) is int and 0 <= value < 10**12 for value in values)
        )
        series.append(values)
    require(not any(series[1]) and not any(series[2]))
    minimum = min(series[0])
    require(minimum - 224 * 1024 >= 256 * 1024)
    expected_capacity = {
        "minimum_mem_available_kib": minimum,
        "planned_incremental_memory_kib": 224 * 1024,
        "residual_after_planned_increment_kib": minimum - 224 * 1024,
        "minimum_residual_requirement_kib": 256 * 1024,
    }
    # prevent a success flag from contradicting its measured headroom
    for key, count in expected_capacity.items():
        require(type(headroom.get(key)) is int and headroom[key] == count)
    captured = headroom.get("captured_at")
    require(type(captured) is str and len(captured) == 20)
    time.strptime(captured, "%Y-%m-%dT%H:%M:%SZ")


# load the immutable optional tracker definition and selection digest
def load_alert_runtime(runtime, resolved_source):
    contract_path = resolved_source / "deploy/alerts/source-contract.json"
    launcher_path = resolved_source / "deploy/alerts/run-source.sh"
    health_path = resolved_source / "deploy/alerts/source-health.sh"
    contract_bytes = contract_path.read_bytes()
    source_contract = validate_source_contract(json.loads(contract_bytes))
    image = pinned_image(runtime, "ultrafeeder")
    health_bytes = health_path.read_bytes()
    proof_path = resolved_source / "deploy/alerts/source-proof.json"
    # reject oversized release evidence before parsing or hashing it
    if proof_path.stat().st_size > 64 * 1024:
        raise ValueError("alert source selection proof is oversized")
    proof_bytes = proof_path.read_bytes()
    proof = json.loads(proof_bytes)
    catalog = json.loads((resolved_source / "deploy/alerts/catalog-manifest.json").read_bytes())
    validate_source_proof(proof, runtime["images"], health_bytes, catalog["entry_count"])
    # retain only the proven immutable fallback selection
    if source_contract["sources"]["978"]["mode"] != "readsb":
        raise ValueError("alert source selection proof does not match the release")
    digest = hashlib.sha256()
    # bind reviewed selection evidence and the immutable image with explicit boundaries
    for content in (contract_bytes, proof_bytes, launcher_path.read_bytes(), health_bytes, image.encode("utf-8")):
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    runtime["source_contract"] = source_contract
    runtime["source_contract_digest"] = digest.hexdigest()


# reload root-owned runtime and hash mounted files so updates trigger recreation
def load_runtime(path, *, strict_alerts=True):
    runtime = json.loads(path.read_text())
    source = Path(runtime["source_dir"])
    data = Path(runtime["data_dir"])
    # reject accidental relative deployment paths
    if not source.is_absolute() or not data.is_absolute():
        raise ValueError("runtime paths must be absolute")
    # bind controller observations to one installer activation
    if not isinstance(runtime.get("activation_id"), str) or not ACTIVATION_PATTERN.fullmatch(runtime["activation_id"]):
        raise ValueError("runtime activation identity is invalid")
    resolved_source = source.resolve(strict=True)
    runtime["resolved_source_dir"] = str(resolved_source)
    # bind the production pointer only to its immutable release root
    if source == Path("/opt/adsb/current") and resolved_source.parent != Path("/opt/adsb/releases"):
        raise ValueError("source release is outside the immutable release root")
    try:
        load_alert_runtime(runtime, resolved_source)
    except Exception as error:
        # keep optional contract failures away from established feeds
        if strict_alerts:
            raise
        logging.warning("alert source contract unavailable: %s", type(error).__name__)
        runtime.update(
            source_contract=None, source_contract_digest="", alert_contract_error="source_contract_unavailable"
        )
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


# read one bounded auxiliary source observation without affecting core reconciliation
def alert_source_state(path, band, activation_id, contract_digest):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            metadata = os.fstat(stream.fileno())
            # reject special and oversized source observations
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
                return None
            value = json.loads(stream.read(65537))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return None
    expected = {
        "schema_version",
        "band",
        "generation",
        "activation_id",
        "contract_digest",
        "sampled_at",
        "process_running",
        "input_connected",
        "input_socket",
        "input_bytes",
    }
    # accept only the current activation and contract projection
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["schema_version"] != 2
        or value["band"] != band
        or value["activation_id"] != activation_id
        or value["contract_digest"] != contract_digest
        or not isinstance(value["generation"], str)
        or not UUID_PATTERN.fullmatch(value["generation"])
        or not isinstance(value["sampled_at"], str)
        or type(value["process_running"]) is not bool
        or type(value["input_connected"]) is not bool
        or not isinstance(value["input_socket"], str)
        or len(value["input_socket"]) > 32
        or (value["input_connected"] and not value["input_socket"].isdigit())
        or type(value["input_bytes"]) is not int
        or not 0 <= value["input_bytes"] <= 10**15
    ):
        return None
    return value


# publish the bounded source contract expected by the unprivileged worker
def _alert_status_for(runtime, hardware, services, data):
    contract = runtime["source_contract"]
    expected_bands = []
    sources = {}
    # include only bands backed by currently detected physical radios
    for band, present in (("1090", hardware["airspy"]), ("978", hardware["uat"])):
        if not present:
            continue
        expected_bands.append(band)
        source = contract["sources"][band]
        projection = {"mode": source["mode"], "service": source["service"], "state": "degraded"}
        # bind readsb generation and connector state to its private observation
        if source["mode"] == "readsb":
            state = alert_source_state(
                data / f"alert-source/{source['directory']}/source-state.json",
                band,
                runtime["activation_id"],
                runtime["source_contract_digest"],
            )
            # show source startup separately from a failed process
            if source["service"] in services["starting"]:
                projection["state"] = "starting"
            # expose only a validated current source observation
            if state is not None:
                projection.update(
                    {
                        "generation": state["generation"],
                        "sampled_at": state["sampled_at"],
                        "process_running": state["process_running"],
                        "input_connected": state["input_connected"],
                    }
                )
            # require both Compose health and connector provenance
            if (
                source["service"] in services["ready"]
                and state is not None
                and state["process_running"]
                and state["input_connected"]
            ):
                projection["state"] = "ready"
        # retain native source lifecycle under the existing dump978 core service
        elif source["service"] in services["ready"]:
            projection["state"] = "ready"
            projection["process_running"] = True
            projection["input_connected"] = True
        sources[band] = projection
    return {
        "activation_id": runtime["activation_id"],
        "source_contract_digest": runtime["source_contract_digest"],
        "expected_bands": expected_bands,
        "sources": sources,
    }


# fence every auxiliary parser failure away from core reconciliation
def alert_status_for(runtime, hardware, services, data):
    try:
        return _alert_status_for(runtime, hardware, services, data)
    except Exception as error:
        logging.warning("alert source projection failed: %s", type(error).__name__)
        expected = [band for band, key in (("1090", "airspy"), ("978", "uat")) if hardware.get(key)]
        return {
            "activation_id": runtime.get("activation_id", ""),
            "source_contract_digest": runtime.get("source_contract_digest", ""),
            "expected_bands": expected,
            "sources": {band: {"state": "degraded"} for band in expected},
        }


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
def status_for(
    settings,
    hardware,
    running,
    metrics,
    applied_revision,
    claim_url="",
    activation_id="",
    reception=None,
    alerts=None,
):
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
    result = {
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
    # attach only prevalidated local reception observations
    if reception is not None:
        result["reception"] = reception
    # attach only the fixed source lifecycle projection
    if alerts is not None:
        result["alerts"] = alerts
    return result


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
    reception_monitor = ReceptionMonitor()
    # poll for settings changes and USB arrival without exposing a privileged API
    while True:
        try:
            activation_id = ""
            runtime = load_runtime(Path(arguments.runtime), strict_alerts=False)
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
            reception = reception_monitor.collect(hardware, services["running"])
            alerts = alert_status_for(runtime, hardware, services, data)
            status = status_for(
                settings,
                hardware,
                services["running"],
                connector_metrics(),
                applied_revision,
                claim_url,
                activation_id,
                reception,
                alerts,
            )
            expected_services = set(specification["services"])
            core_services = expected_services - AUXILIARY_SOURCE_SERVICES
            source_services = expected_services & AUXILIARY_SOURCE_SERVICES
            not_ready_services = core_services - services["ready"]
            failed_services = not_ready_services - services["starting"]
            # preserve the existing core-service health predicate
            if failed_services:
                status.update({"phase": "error", "message": "One or more requested services are unhealthy or stopped."})
                recreate_services(compose_path, failed_services)
                last_digest = None
            # wait for declared health checks without restarting their grace period
            elif not_ready_services:
                status.update({"phase": "starting", "message": "One or more requested services are starting."})
            failed_sources = source_services - services["ready"] - services["starting"]
            # repair only failed auxiliary trackers without degrading or stopping core feeds
            if failed_sources:
                try:
                    recreate_services(compose_path, failed_sources)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    log_failure("alert source recreation", error)
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
