"""Operate and verify only the fixed production ADS-B stack."""

import json
import os
import re
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

VERBS = frozenset({"status", "start", "stop", "restart"})
SYSTEMCTL = "/usr/bin/systemctl"
DOCKER = "/usr/bin/docker"
COMPOSE_PATH = "/var/lib/adsb/runtime/compose.json"
RUNTIME_PATH = Path("/etc/adsb/runtime.json")
STATUS_PATH = Path("/var/lib/adsb/status/status.json")
WORKER_STATUS_PATH = Path("/var/lib/adsb/alerts/worker-status.json")
UNITS = ("adsb-alerts.service", "adsb-controller.service", "adsb-admin.service")
CORE_SERVICES = frozenset({"ultrafeeder", "proxy"})
SOURCE_SERVICES = frozenset({"alert-source-1090", "alert-source-978fallback"})
KNOWN_SERVICES = CORE_SERVICES | SOURCE_SERVICES | {"cloudflared", "airspy", "dump978", "piaware"}
ACTIVATION_PATTERN = re.compile(r"^[0-9a-f]{32}$")
CONTRACT_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
START_TIMEOUT_SECONDS = 90
POLL_SECONDS = 2
COMMAND_ENV = {
    "DOCKER_HOST": "unix:///var/run/docker.sock",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
UNIT_STATES = frozenset({"active", "activating", "deactivating", "failed", "inactive", "unknown"})


# reject redirects so each fixed loopback check has one socket timeout
class NoRedirect(HTTPRedirectHandler):
    # return no replacement request for any redirect response
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


# run fixed commands without inheriting caller-controlled process state
def run_command(arguments, *, timeout):
    try:
        return subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/",
            env=COMMAND_ENV,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


# cap one operation to the remaining readiness budget
def operation_timeout(maximum, deadline):
    # retain fixed standalone status timeouts outside a readiness wait
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    # skip operations after the outer readiness deadline
    if remaining <= 0:
        return None
    return min(maximum, remaining)


# read a bounded regular JSON file without following symlinks
def read_json(path, *, limit=65536):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        metadata = os.fstat(stream.fileno())
        # reject devices and oversized state files
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError("invalid state file")
        content = stream.read(limit + 1)
        # defend against growth after the metadata check
        if len(content) > limit:
            raise ValueError("state file too large")
    return json.loads(content)


# return a validated systemd state without exposing command output
def unit_state(unit, *, deadline=None):
    timeout = operation_timeout(10, deadline)
    # stop before invoking systemd when the outer deadline has expired
    if timeout is None:
        return "unknown"
    result = run_command([SYSTEMCTL, "is-active", unit], timeout=timeout)
    # treat failed execution or unexpected output as unknown
    if result is None:
        return "unknown"
    state = result.stdout.strip()
    # allow only systemd's fixed public states
    if state not in UNIT_STATES:
        return "unknown"
    # require systemd's success code for an active result
    if state == "active" and result.returncode != 0:
        return "unknown"
    # reject contradictory success codes for nonactive results
    if state != "active" and result.returncode == 0:
        return "unknown"
    return state


# parse fixed-project compose state into service health flags
def compose_services(*, deadline=None):
    timeout = operation_timeout(20, deadline)
    # stop before invoking Docker when the outer deadline has expired
    if timeout is None:
        return {}, False
    result = run_command(
        [DOCKER, "compose", "-p", "adsb", "-f", COMPOSE_PATH, "ps", "--all", "--format", "json"],
        timeout=timeout,
    )
    # require a successful scoped Docker query
    if result is None or result.returncode != 0:
        return {}, False
    content = result.stdout.strip()
    # an empty successful query is a confirmed empty project
    if not content:
        return {}, True
    try:
        rows = json.loads(content) if content.startswith("[") else [json.loads(line) for line in content.splitlines()]
    except (json.JSONDecodeError, TypeError):
        return {}, False
    # reject malformed rows rather than guessing container state
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return {}, False
    services = {}
    # retain only bounded state for known fixed service names
    for row in rows:
        name = row.get("Service")
        # make any unexpected project container prevent confirmed shutdown
        if not isinstance(name, str) or name not in KNOWN_SERVICES:
            services["other"] = True
            continue
        state = row.get("State")
        health = row.get("Health")
        healthy = state == "running" and health in (None, "", "healthy")
        services[name] = services.get(name, True) and healthy
    return services, True


# read the exact fixed service set declared by the privileged controller
def declared_services():
    try:
        specification = read_json(Path(COMPOSE_PATH))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return set(), False
    # require the controller's exact top-level compose schema
    if not isinstance(specification, dict) or set(specification) != {"name", "services"}:
        return set(), False
    services = specification.get("services")
    # require the fixed project and a service object
    if specification.get("name") != "adsb" or not isinstance(services, dict):
        return set(), False
    names = set(services)
    # reject malformed, missing-core and unexpected service names
    if (
        not all(isinstance(name, str) for name in names)
        or not CORE_SERVICES.issubset(names)
        or not names.issubset(KNOWN_SERVICES)
    ):
        return set(), False
    return names, True


# read whether the fixed production tunnel is part of the desired stack
def tunnel_enabled():
    try:
        runtime = read_json(RUNTIME_PATH)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None
    # require a JSON object and an actual boolean flag
    if not isinstance(runtime, dict) or type(runtime.get("tunnel_enabled")) is not bool:
        return None
    return runtime["tunnel_enabled"]


# load the exact activation expected from the current runtime
def runtime_activation_id():
    try:
        runtime = read_json(RUNTIME_PATH)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None
    activation_id = runtime.get("activation_id") if isinstance(runtime, dict) else None
    # reject absent or malformed activation provenance
    if not isinstance(activation_id, str) or not ACTIVATION_PATTERN.fullmatch(activation_id):
        return None
    return activation_id


# check a fixed loopback endpoint with proxies disabled
def http_healthy(url, *, deadline=None):
    timeout = operation_timeout(3, deadline)
    # stop before opening a socket when the outer deadline has expired
    if timeout is None:
        return False
    try:
        opener = build_opener(ProxyHandler({}), NoRedirect())
        with opener.open(url, timeout=timeout) as response:
            return response.status == 200
    except (OSError, URLError, ValueError):
        return False


# validate freshness and phase without returning controller-provided messages
def controller_phase(*, now=None, expected_activation=None):
    activation_id = expected_activation if expected_activation is not None else runtime_activation_id()
    # require valid current runtime provenance before trusting status
    if not isinstance(activation_id, str) or not ACTIVATION_PATTERN.fullmatch(activation_id):
        return "unhealthy"
    try:
        status = read_json(STATUS_PATH)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return "unhealthy"
    # accept only explicit nonerror operational phases
    if (
        not isinstance(status, dict)
        or status.get("activation_id") != activation_id
        or status.get("phase") not in {"ready", "waiting"}
    ):
        return "unhealthy"
    try:
        stamp = status["updated_at"]
        # normalize the controller's UTC suffix for strict datetime parsing
        if not isinstance(stamp, str):
            return "unhealthy"
        updated_at = datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)
        current = now or datetime.now(timezone.utc)
        # reject timestamps and injected clocks without explicit timezones
        if updated_at.tzinfo is None or current.tzinfo is None:
            return "unhealthy"
        age = (current - updated_at.astimezone(timezone.utc)).total_seconds()
    except (KeyError, TypeError, ValueError):
        return "unhealthy"
    # reject stale and future-dated observations
    if age < 0 or age > 30:
        return "unhealthy"
    return status["phase"]


# calculate a bounded UTC age from one explicit timestamp
def timestamp_age(value, *, now=None):
    try:
        # accept worker epoch seconds or controller ISO timestamps
        if type(value) in (int, float):
            parsed = datetime.fromtimestamp(value, timezone.utc)
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        else:
            return None
        current = now or datetime.now(timezone.utc)
    except (OSError, OverflowError, TypeError, ValueError):
        return None
    # require timezone-aware values at the trust boundary
    if parsed.tzinfo is None or current.tzinfo is None:
        return None
    return (current - parsed.astimezone(timezone.utc)).total_seconds()


# verify notifier liveness and the selected physical source generations
def alert_infrastructure(*, now=None, deadline=None):
    worker_unit = unit_state("adsb-alerts.service", deadline=deadline)
    result = {
        "infrastructure_ready": False,
        "unit": worker_unit,
        "worker": "unhealthy",
        "sources": "unhealthy",
    }
    try:
        status = read_json(STATUS_PATH)
        worker = read_json(WORKER_STATUS_PATH)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        return result
    activation_id = status.get("activation_id") if isinstance(status, dict) else None
    alerts = status.get("alerts") if isinstance(status, dict) else None
    # require current fixed controller provenance and a bounded source projection
    if (
        not isinstance(activation_id, str)
        or not ACTIVATION_PATTERN.fullmatch(activation_id)
        or not isinstance(alerts, dict)
        or alerts.get("activation_id") != activation_id
        or not isinstance(alerts.get("source_contract_digest"), str)
        or not CONTRACT_DIGEST_PATTERN.fullmatch(alerts["source_contract_digest"])
        or not isinstance(alerts.get("expected_bands"), list)
        or not isinstance(alerts.get("sources"), dict)
    ):
        return result
    expected_bands = alerts["expected_bands"]
    # reject duplicate or invented physical bands
    if any(type(band) is not str or band not in {"1090", "978"} for band in expected_bands) or len(
        expected_bands
    ) != len(set(expected_bands)):
        return result
    # require a current worker bound to this activation and source contract
    if (
        not isinstance(worker, dict)
        or worker.get("schema_version") != 1
        or worker.get("activation_id") != activation_id
        or worker.get("source_contract_digest") != alerts["source_contract_digest"]
        or worker.get("process_running") is not True
        or not isinstance(worker.get("bands"), dict)
    ):
        return result
    worker_age = timestamp_age(worker.get("sampled_at"), now=now)
    worker_ready = worker_unit == "active" and worker_age is not None and 0 <= worker_age <= 30
    result["worker"] = "healthy" if worker_ready else "unhealthy"
    sources_ready = set(alerts["sources"]) == set(expected_bands)
    # require each selected band to expose one current matched process generation
    for band in expected_bands:
        source = alerts["sources"].get(band)
        consumed = worker["bands"].get(band)
        if not isinstance(source, dict) or source.get("state") != "ready":
            sources_ready = False
            continue
        generation = source.get("generation")
        # require the worker to consume this exact healthy source generation
        if (
            not isinstance(generation, str)
            or not generation
            or not isinstance(consumed, dict)
            or consumed.get("state") != "healthy"
            or consumed.get("generation") != generation
        ):
            sources_ready = False
            continue
        # readsb sources must also prove the current process, connector and freshness
        if source.get("mode") == "readsb":
            source_age = timestamp_age(source.get("sampled_at"), now=now)
            if (
                source.get("process_running") is not True
                or source.get("input_connected") is not True
                or source_age is None
                or not 0 <= source_age <= 30
            ):
                sources_ready = False
        # reject any source mode outside the release contract
        elif source.get("mode") != "native-dump978":
            sources_ready = False
    result["sources"] = "healthy" if sources_ready else "unhealthy"
    result["infrastructure_ready"] = worker_ready and sources_ready
    return result


# gather the fixed nonsecret production readiness projection
def collect_status(*, now=None, deadline=None):
    admin = unit_state("adsb-admin.service", deadline=deadline)
    controller = unit_state("adsb-controller.service", deadline=deadline)
    services, compose_ok = compose_services(deadline=deadline)
    declared, declaration_ok = declared_services()
    tunnel = tunnel_enabled()
    tunnel_consistent = tunnel is not None and (("cloudflared" in declared) == tunnel)
    core_declared = declared - SOURCE_SERVICES
    core_observed = {name: healthy for name, healthy in services.items() if name not in SOURCE_SERVICES}
    containers_ok = (
        compose_ok
        and declaration_ok
        and tunnel_consistent
        and set(core_observed) == core_declared
        and all(core_observed.get(name, False) for name in core_declared)
    )
    origin_ok = http_healthy("http://127.0.0.1:8080/healthz", deadline=deadline) and http_healthy(
        "http://127.0.0.1:8080/map/", deadline=deadline
    )
    phase = controller_phase(now=now)
    tunnel_state = "disabled"
    # report an invalid runtime choice as unknown rather than disabled
    if tunnel is None:
        tunnel_state = "unknown"
    # verify Cloudflare's local readiness endpoint when enabled
    if tunnel is True:
        tunnel_state = "healthy" if http_healthy("http://127.0.0.1:20242/ready", deadline=deadline) else "unhealthy"
    running = (
        admin == "active"
        and controller == "active"
        and containers_ok
        and origin_ok
        and phase in {"ready", "waiting"}
        and tunnel_state in {"disabled", "healthy"}
    )
    alerts = alert_infrastructure(now=now, deadline=deadline)
    return {
        "state": "running" if running else "stopped",
        "alerts": alerts,
        "checks": {
            "admin": admin,
            "containers": "healthy" if containers_ok else "unhealthy",
            "controller": controller,
            "controller_status": phase,
            "origin": "healthy" if origin_ok else "unhealthy",
            "tunnel": tunnel_state,
        },
    }


# add a fixed action result without exposing subprocess diagnostics
def action_result(action, success, status, reason=None):
    result = {"action": action, "result": "ok" if success else "failed", **status}
    # include only caller-selected fixed failure text
    if reason is not None:
        result["reason"] = reason
    return result


# start the supervised units and wait for bounded full readiness
def start_stack(*, action="start", timeout=START_TIMEOUT_SECONDS):
    result = run_command(
        [SYSTEMCTL, "start", "adsb-admin.service", "adsb-controller.service", "adsb-alerts.service"], timeout=30
    )
    # refuse readiness when systemd did not accept the fixed start request
    if result is None or result.returncode != 0:
        return action_result(action, False, collect_status(), "systemd start failed")
    deadline = time.monotonic() + timeout
    maximum_attempts = max(1, int(timeout / POLL_SECONDS) + 2)
    status = {"state": "stopped", "checks": {}}
    # cap both elapsed time and attempts to prevent an unbounded wait
    for _attempt in range(maximum_attempts):
        status = collect_status(deadline=deadline)
        # finish as soon as every readiness check passes
        if status["state"] == "running" and status.get("alerts", {}).get("infrastructure_ready") is True:
            return action_result(action, True, status)
        remaining = deadline - time.monotonic()
        # never claim success after the bounded deadline
        if remaining <= 0:
            break
        time.sleep(min(POLL_SECONDS, remaining))
    return action_result(action, False, status, "readiness timed out")


# confirm that units and fixed-project containers are stopped
def stopped_status():
    unit_states = {unit: unit_state(unit) for unit in UNITS}
    services, compose_ok = compose_services()
    units_stopped = all(state in {"failed", "inactive"} for state in unit_states.values())
    confirmed = units_stopped and compose_ok and not services
    return confirmed, {
        "state": "stopped",
        "checks": {
            "alerts": unit_states["adsb-alerts.service"],
            "admin": unit_states["adsb-admin.service"],
            "containers": "stopped" if compose_ok and not services else "unconfirmed",
            "controller": unit_states["adsb-controller.service"],
        },
    }


# stop supervisors first and then only the fixed compose project
def stop_stack(*, action="stop"):
    commands = [
        [SYSTEMCTL, "stop", "adsb-alerts.service"],
        [SYSTEMCTL, "stop", "adsb-controller.service"],
        [SYSTEMCTL, "stop", "adsb-admin.service"],
        [DOCKER, "compose", "-p", "adsb", "-f", COMPOSE_PATH, "down", "--remove-orphans", "--timeout", "10"],
    ]
    commands_ok = True
    # attempt every independent shutdown step even after a failure
    for command in commands:
        result = run_command(command, timeout=30)
        # retain failure while continuing best-effort shutdown
        if result is None or result.returncode != 0:
            commands_ok = False
    confirmed, status = stopped_status()
    success = commands_ok and confirmed
    return action_result(action, success, status, None if success else "shutdown could not be confirmed")


# perform an orderly stop before starting the same fixed stack
def restart_stack():
    stopped = stop_stack(action="restart")
    # never start over an unconfirmed partial shutdown
    if stopped["result"] != "ok":
        return stopped
    return start_stack(action="restart")


# dispatch exactly one fixed verb for the root launcher
def main(argv=None):
    arguments = sys.argv if argv is None else argv
    # reject option syntax, extra arguments and arbitrary verbs
    if len(arguments) != 2 or arguments[1] not in VERBS:
        print('{"error":"expected exactly one of: status, start, stop, restart"}', file=sys.stderr)
        return 64
    # refuse direct nonroot execution before systemd can invoke polkit
    if os.geteuid() != 0:
        print('{"error":"root execution required"}', file=sys.stderr)
        return 77
    verb = arguments[1]
    # status has no mutation and its exit code is the RemoteAgents poll signal
    if verb == "status":
        result = collect_status()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["state"] == "running" else 1
    # map only validated verbs to fixed callables
    operations = {"start": start_stack, "stop": stop_stack, "restart": restart_stack}
    result = operations[verb]()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] == "ok" else 1


# execute only through the isolated root launcher in production
if __name__ == "__main__":
    raise SystemExit(main())
