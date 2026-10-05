"""Persistent settings validation and status projection."""

from __future__ import annotations

import copy
import json
import math
import os
import re
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

NETWORK_NAMES = ("adsbexchange", "flightaware", "adsblol", "airplaneslive")
STATION_KEYS = frozenset(("name", "latitude", "longitude", "altitude_m"))
PUBLIC_NETWORK_KEYS = frozenset(("enabled", "mlat", "feeder_id", "feeder_id_configured"))
STATUS_PHASES = frozenset(("starting", "ready", "error", "waiting"))
RECEPTION_BANDS = ("1090", "978")
RECEPTION_STATES = frozenset(("absent", "stopped", "unavailable", "stale", "monitoring", "quiet", "receiving"))
STATION_NAME_PATTERN = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
REQUIRED_FEEDER_IDS = frozenset(("adsbexchange", "adsblol"))
STATUS_FRESHNESS_SECONDS = 30
MAX_MESSAGES_PER_MINUTE = 10_000_000
UNKNOWN_STATUS_MESSAGE = "controller status stale or unknown"
FLIGHTAWARE_CLAIM_URL_PATTERN = re.compile(
    r"^https://www\.flightaware\.com/adsb/piaware/claim/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


# represent schema-validation failures
class ValidationError(Exception):
    # retain safe field messages
    def __init__(self, fields: dict[str, str]) -> None:
        super().__init__("invalid settings")
        self.fields = fields


# represent optimistic-concurrency conflicts
class RevisionConflict(Exception):
    # retain the current redacted settings
    def __init__(self, current: dict[str, Any]) -> None:
        super().__init__("settings revision conflict")
        self.current = current


# build safe initial settings
def default_settings() -> dict[str, Any]:
    return {
        "revision": 0,
        "station": {"name": "Ballydidean Farm", "latitude": None, "longitude": None, "altitude_m": None},
        "networks": {
            "adsbexchange": {"enabled": False, "mlat": False, "feeder_id": str(uuid.uuid4())},
            "flightaware": {"enabled": False, "mlat": False, "feeder_id": ""},
            "adsblol": {"enabled": False, "mlat": False, "feeder_id": str(uuid.uuid4())},
            "airplaneslive": {"enabled": False, "mlat": False, "feeder_id": ""},
        },
    }


# test a strict integer value
def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# validate exact object keys
def _validate_keys(value: Any, expected: frozenset[str], path: str, fields: dict[str, str]) -> bool:
    # require an object
    if not isinstance(value, dict):
        fields[path] = "must be an object"
        return False
    actual = frozenset(value)
    # reject unknown keys
    for key in sorted(actual - expected):
        fields[f"{path}.{key}"] = "is not allowed"
    # reject missing keys
    for key in sorted(expected - actual):
        fields[f"{path}.{key}"] = "is required"
    return actual == expected


# validate a station name
def _validate_name(value: Any, fields: dict[str, str]) -> str | None:
    # require the controller's bounded safe alphabet
    if not isinstance(value, str) or STATION_NAME_PATTERN.fullmatch(value) is None:
        fields["station.name"] = "must be 1-64 letters, numbers, spaces, dots, hyphens, or underscores"
        return None
    return value


# validate a nullable finite number
def _validate_number(
    value: Any,
    path: str,
    minimum: float,
    maximum: float,
    fields: dict[str, str],
) -> float | None:
    # preserve explicit null values
    if value is None:
        return None
    # reject booleans and non-numbers
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fields[path] = "must be a number or null"
        return None
    number = float(value)
    # require a bounded finite coordinate
    if not math.isfinite(number) or number < minimum or number > maximum:
        fields[path] = f"must be between {minimum:g} and {maximum:g}"
        return None
    return number


# validate and normalize a feeder identifier
def _validate_feeder_id(value: Any, path: str, fields: dict[str, str]) -> str | None:
    # require text input
    if not isinstance(value, str) or value != value.strip():
        fields[path] = "must be a UUID or blank"
        return None
    # preserve an explicit clear operation
    if not value:
        return ""
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        fields[path] = "must be a UUID or blank"
        return None


# validate a complete settings replacement
def validate_settings(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, str] = {}
    # require the top-level contract
    if not _validate_keys(payload, frozenset(("revision", "station", "networks")), "settings", fields):
        raise ValidationError(fields)
    revision = payload["revision"]
    # require a nonnegative revision
    if not _is_int(revision) or revision < 0:
        fields["revision"] = "must be a nonnegative integer"

    station = payload["station"]
    station_valid = _validate_keys(station, STATION_KEYS, "station", fields)
    normalized_station: dict[str, Any] = {}
    # validate station fields only when the object shape is usable
    if station_valid:
        normalized_station = {
            "name": _validate_name(station["name"], fields),
            "latitude": _validate_number(station["latitude"], "station.latitude", -90, 90, fields),
            "longitude": _validate_number(station["longitude"], "station.longitude", -180, 180, fields),
            "altitude_m": _validate_number(station["altitude_m"], "station.altitude_m", -500, 10000, fields),
        }

    networks = payload["networks"]
    networks_valid = _validate_keys(networks, frozenset(NETWORK_NAMES), "networks", fields)
    normalized_networks: dict[str, Any] = {}
    any_enabled = False
    # validate each network when the collection shape is usable
    if networks_valid:
        # retain all known network settings
        for network_name in NETWORK_NAMES:
            network = networks[network_name]
            path = f"networks.{network_name}"
            # allow feeder omission to preserve its secret
            if isinstance(network, dict):
                actual_keys = frozenset(network)
                required_keys = frozenset(("enabled", "mlat"))
                # reject unknown network fields
                for key in sorted(actual_keys - PUBLIC_NETWORK_KEYS):
                    fields[f"{path}.{key}"] = "is not allowed"
                # never accept the redacted display marker on writes
                if "feeder_id_configured" in actual_keys:
                    fields[f"{path}.feeder_id_configured"] = "is read-only"
                # require toggle fields
                for key in sorted(required_keys - actual_keys):
                    fields[f"{path}.{key}"] = "is required"
            else:
                fields[path] = "must be an object"
                continue
            enabled = network.get("enabled")
            mlat = network.get("mlat")
            # require strict booleans
            if not isinstance(enabled, bool):
                fields[f"{path}.enabled"] = "must be a boolean"
            # require strict booleans
            if not isinstance(mlat, bool):
                fields[f"{path}.mlat"] = "must be a boolean"
            preserved_id = current["networks"][network_name]["feeder_id"]
            feeder_id = preserved_id
            # validate an explicitly supplied credential
            if "feeder_id" in network:
                validated_id = _validate_feeder_id(network["feeder_id"], f"{path}.feeder_id", fields)
                # use the new value only when valid
                if validated_id is not None:
                    feeder_id = validated_id
            normalized_networks[network_name] = {"enabled": enabled, "mlat": mlat, "feeder_id": feeder_id}
            # require credentials for networks that cannot self-register safely
            if enabled is True and network_name in REQUIRED_FEEDER_IDS and not feeder_id:
                fields[f"{path}.feeder_id"] = "is required when this network is enabled"
            # track whether station fields become mandatory
            if enabled is True:
                any_enabled = True

    # require complete station data for active feeds
    if any_enabled and station_valid:
        # require all four station fields
        for key, value in normalized_station.items():
            # distinguish the intentionally empty name
            if value is None or value == "":
                fields[f"station.{key}"] = "is required when a network is enabled"
    # reject all accumulated errors together
    if fields:
        raise ValidationError(fields)
    return {"revision": revision, "station": normalized_station, "networks": normalized_networks}


# remove credential values from settings responses
def redact_settings(settings: dict[str, Any]) -> dict[str, Any]:
    result = {"revision": settings["revision"], "station": copy.deepcopy(settings["station"]), "networks": {}}
    # project each network without its identifier
    for network_name in NETWORK_NAMES:
        network = settings["networks"][network_name]
        result["networks"][network_name] = {
            "enabled": network["enabled"],
            "mlat": network["mlat"],
            "feeder_id_configured": bool(network["feeder_id"]),
        }
    return result


# atomically persist private json with restrictive permissions
def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        # remove an abandoned temporary file
        if temporary_path.exists():
            temporary_path.unlink()


# own persistent settings with optimistic concurrency
class SettingsStore:
    # initialize or load persistent settings
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        # initialize a missing file once
        if not self.path.exists():
            _atomic_write(self.path, default_settings())
        self._settings = self._read_validated()
        os.chmod(self.path, 0o600)

    # validate persisted data as trusted schema input
    def _read_validated(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("settings file is unreadable") from exc
        # require the internal schema including feeder ids
        if not isinstance(value, dict) or frozenset(value) != frozenset(("revision", "station", "networks")):
            raise RuntimeError("settings file has an invalid schema")
        networks = value.get("networks")
        # require the complete provider collection before normalization
        if not isinstance(networks, dict) or frozenset(networks) != frozenset(NETWORK_NAMES):
            raise RuntimeError("settings file has an invalid schema")
        # require stored credentials to remain explicit
        for network in networks.values():
            # reject partial private records
            if not isinstance(network, dict) or frozenset(network) != frozenset(("enabled", "mlat", "feeder_id")):
                raise RuntimeError("settings file has an invalid schema")
        current_template = default_settings()
        # validate the persisted shape without preserving generated defaults
        try:
            validated = validate_settings(value, current_template)
        except ValidationError as exc:
            raise RuntimeError("settings file has an invalid schema") from exc
        validated["revision"] = value["revision"]
        return validated

    # return an isolated internal snapshot
    def get_private(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._settings)

    # return an isolated public snapshot
    def get_public(self) -> dict[str, Any]:
        with self._lock:
            return redact_settings(self._settings)

    # replace settings when the client's revision is current
    def update(self, payload: Any) -> dict[str, Any]:
        with self._lock:
            # validate the supplied revision before comparing it
            if not isinstance(payload, dict) or not _is_int(payload.get("revision")):
                raise ValidationError({"revision": "must be a nonnegative integer"})
            # reject stale writes with a fresh safe snapshot
            if payload["revision"] != self._settings["revision"]:
                raise RevisionConflict(redact_settings(self._settings))
            validated = validate_settings(payload, self._settings)
            validated["revision"] = self._settings["revision"] + 1
            _atomic_write(self.path, validated)
            self._settings = validated
            return redact_settings(self._settings)


# build safe unknown reception state
def _unknown_reception() -> dict[str, Any]:
    return {
        band: {
            "hardware_present": None,
            "service_running": None,
            "telemetry_state": "unavailable",
            "messages_per_minute": None,
            "last_activity_at": None,
            "sample_at": None,
        }
        for band in RECEPTION_BANDS
    }


# build a safe unknown controller state
def _unknown_status() -> dict[str, Any]:
    return {
        "applied_revision": 0,
        "phase": "error",
        "message": UNKNOWN_STATUS_MESSAGE,
        "networks": {},
        "updated_at": "",
        "hardware": {"connected": None, "message": UNKNOWN_STATUS_MESSAGE},
        "reception": _unknown_reception(),
    }


# classify one utc controller timestamp
def _fresh_status_timestamp(value: Any, now: datetime) -> tuple[bool, str]:
    # reject absent or oversized timestamp text
    if not isinstance(value, str) or not value or len(value) > 100:
        return False, ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False, ""
    # require an explicitly utc timestamp
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return False, ""
    age_seconds = (now - parsed).total_seconds()
    # reject stale snapshots and excessive future clock skew
    if age_seconds > STATUS_FRESHNESS_SECONDS or age_seconds < -STATUS_FRESHNESS_SECONDS:
        return False, value
    return True, value


# validate one historical utc observation timestamp
def _observation_timestamp(value: Any, now: datetime) -> str | None:
    # reject absent or oversized timestamp text
    if not isinstance(value, str) or not value or len(value) > 100:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # require an explicit utc timestamp
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    # reject activity claims beyond bounded clock skew
    if (parsed - now).total_seconds() > STATUS_FRESHNESS_SECONDS:
        return None
    return value


# project fixed reception fields from private controller status
def _project_reception(value: Any, now: datetime) -> dict[str, Any]:
    result = _unknown_reception()
    # retain the unknown shape for malformed collections
    if not isinstance(value, dict):
        return result
    # sanitize each supported radio band
    for band in RECEPTION_BANDS:
        source = value.get(band)
        # ignore missing or malformed source records
        if not isinstance(source, dict):
            continue
        projected = result[band]
        hardware_present = source.get("hardware_present")
        # preserve only explicit hardware presence
        if isinstance(hardware_present, bool):
            projected["hardware_present"] = hardware_present
        service_running = source.get("service_running")
        # preserve only explicit process state
        if isinstance(service_running, bool):
            projected["service_running"] = service_running
        telemetry_state = source.get("telemetry_state")
        # preserve only fixed telemetry classifications
        if telemetry_state in RECEPTION_STATES:
            projected["telemetry_state"] = telemetry_state
        rate = source.get("messages_per_minute")
        # accept only finite bounded rates
        if (
            not isinstance(rate, bool)
            and isinstance(rate, (int, float))
            and math.isfinite(rate)
            and 0 <= rate <= MAX_MESSAGES_PER_MINUTE
        ):
            projected["messages_per_minute"] = rate
        projected["last_activity_at"] = _observation_timestamp(source.get("last_activity_at"), now)
        projected["sample_at"] = _observation_timestamp(source.get("sample_at"), now)
        # clear rate claims from noncurrent source states
        if projected["telemetry_state"] in ("absent", "stopped", "unavailable", "stale", "monitoring"):
            projected["messages_per_minute"] = None
    return result


# expose a strict status projection without arbitrary fields
def sanitized_status(path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    # return an unknown state before reconciliation
    if not path.exists():
        return _unknown_status()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _unknown_status()
    # reject non-object status documents
    if not isinstance(raw, dict):
        return _unknown_status()
    current_time = now if now is not None else datetime.now(timezone.utc)
    # normalize injected clocks to utc
    if current_time.tzinfo is None:
        raise ValueError("status clock must be timezone-aware")
    current_time = current_time.astimezone(timezone.utc)
    applied_revision = raw.get("applied_revision")
    # coerce malformed revisions to a safe initial value
    if not _is_int(applied_revision) or applied_revision < 0:
        applied_revision = 0
    phase = raw.get("phase")
    # coerce malformed phases to an error state
    if phase not in STATUS_PHASES:
        phase = "error"
    message = raw.get("message")
    # drop structured or oversized messages
    if not isinstance(message, str) or len(message) > 500:
        message = ""
    fresh, updated_at = _fresh_status_timestamp(raw.get("updated_at"), current_time)
    result: dict[str, Any] = {
        "applied_revision": applied_revision,
        "phase": phase,
        "message": message,
        "networks": {},
        "updated_at": updated_at,
        "hardware": {"connected": None, "message": ""},
        "reception": _project_reception(raw.get("reception"), current_time),
    }
    hardware = raw.get("hardware")
    # project the bounded hardware state
    if isinstance(hardware, dict):
        hardware_message = hardware.get("message")
        # drop structured or oversized hardware messages
        if not isinstance(hardware_message, str) or len(hardware_message) > 500:
            hardware_message = ""
        connected = hardware.get("connected")
        # preserve explicit unknown hardware state
        if connected is not None and not isinstance(connected, bool):
            connected = None
        result["hardware"] = {
            "connected": connected,
            "message": hardware_message,
        }
    result["networks"] = {}
    networks = raw.get("networks")
    # project only known network names
    if isinstance(networks, dict):
        # sanitize each supported network
        for network_name in NETWORK_NAMES:
            network = networks.get(network_name)
            # ignore missing or malformed records
            if not isinstance(network, dict):
                continue
            projected: dict[str, Any] = {}
            enabled = network.get("enabled")
            # preserve only explicit enablement intent
            if isinstance(enabled, bool):
                projected["enabled"] = enabled
            running = network.get("running")
            # preserve boolean or unknown process state
            if isinstance(running, bool) or running is None:
                projected["running"] = running
            connected = network.get("connected")
            # preserve boolean or unknown connection state
            if isinstance(connected, bool) or connected is None:
                projected["connected"] = connected
            network_message = network.get("message")
            # preserve only bounded display messages
            if isinstance(network_message, str) and len(network_message) <= 500:
                projected["message"] = network_message
            claim_url = network.get("claim_url")
            # expose only the fixed provider claim route
            if (
                network_name == "flightaware"
                and isinstance(claim_url, str)
                and FLIGHTAWARE_CLAIM_URL_PATTERN.fullmatch(claim_url)
            ):
                projected["claim_url"] = claim_url
            result["networks"][network_name] = projected
    # invalidate operational truth from an old or malformed snapshot
    if not fresh:
        result["phase"] = "error"
        result["message"] = UNKNOWN_STATUS_MESSAGE
        result["hardware"] = {"connected": None, "message": UNKNOWN_STATUS_MESSAGE}
        result["reception"] = _unknown_reception()
        # retain only requested intent while clearing observed state
        for network in result["networks"].values():
            network["running"] = None
            network["connected"] = None
            network["message"] = UNKNOWN_STATUS_MESSAGE
            network.pop("claim_url", None)
    return result
