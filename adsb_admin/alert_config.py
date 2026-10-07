"""Private configuration for station-local aircraft alerts."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import tempfile
import threading
from email.utils import parseaddr
from pathlib import Path
from typing import Any

from adsb_admin.config import RevisionConflict, ValidationError

ALERT_CATEGORIES = ("military", "medical", "news")
ALERT_CHANNELS = ("pushover", "email")
ALERT_SCHEMA_VERSION = 1
MAX_OVERRIDES = 2_000
ICAO_PATTERN = re.compile(r"^[0-9A-F]{6}$")
AIRCRAFT_MODEL_PATTERN = re.compile(r"^[A-Z0-9]{2,4}$")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


# build inert private defaults
def default_alert_settings() -> dict[str, Any]:
    return {
        "schema_version": ALERT_SCHEMA_VERSION,
        "revision": 0,
        "enabled": False,
        "categories": list(ALERT_CATEGORIES),
        "category_channels": {category: list(ALERT_CHANNELS) for category in ALERT_CATEGORIES},
        "pushover": {"app_token": "", "user_key": ""},
        "smtp": {
            "host": "",
            "port": 465,
            "username": "",
            "password": "",
            "from_address": "",
            "to_address": "",
        },
        "overrides": [],
    }


# derive dual-channel routes for a legacy selected-category list
def _legacy_category_channels(categories: Any) -> dict[str, list[str]]:
    selected = categories if isinstance(categories, list) else ()
    # route only recognizable selected category names
    return {category: list(ALERT_CHANNELS) if category in selected else [] for category in ALERT_CATEGORIES}


# validate one complete category-to-channel routing map
def _validated_category_channels(value: Any, fields: dict[str, str]) -> dict[str, list[str]]:
    normalized = {category: [] for category in ALERT_CATEGORIES}
    # require every supported category exactly once
    if not isinstance(value, dict) or frozenset(value) != frozenset(ALERT_CATEGORIES):
        fields["category_channels"] = "must contain exactly military, medical, and news"
        return normalized
    # validate each bounded unique channel list
    for category in ALERT_CATEGORIES:
        channels = value[category]
        # reject unsupported, repeated, or non-array routes
        if (
            not isinstance(channels, list)
            or len(channels) > len(ALERT_CHANNELS)
            or any(channel not in ALERT_CHANNELS for channel in channels)
            or len(set(channels)) != len(channels)
        ):
            fields[f"category_channels.{category}"] = "must contain unique supported channels"
            continue
        normalized[category] = [channel for channel in ALERT_CHANNELS if channel in channels]
    return normalized


# test strict integers
def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# normalize a bounded secret
def _secret(value: Any, path: str, fields: dict[str, str], *, maximum: int = 256) -> str | None:
    # require plain bounded text
    if not isinstance(value, str) or len(value) > maximum or "\r" in value or "\n" in value:
        fields[path] = f"must be at most {maximum} characters"
        return None
    return value


# validate one mail address
def _mailbox(value: Any, path: str, fields: dict[str, str]) -> str | None:
    # reject header injection and oversized values
    if not isinstance(value, str) or not value or len(value) > 254 or "\r" in value or "\n" in value:
        fields[path] = "must be a valid email address"
        return None
    _display, parsed = parseaddr(value)
    # require an unambiguous address with one domain
    if parsed != value or parsed.count("@") != 1 or any(character.isspace() for character in parsed):
        fields[path] = "must be a valid email address"
        return None
    local, domain = parsed.rsplit("@", 1)
    # bound the local and dns portions
    if not local or len(local) > 64 or not HOSTNAME_PATTERN.fullmatch(domain):
        fields[path] = "must be a valid email address"
        return None
    return value


# validate a public smtp hostname
def _hostname(value: Any, fields: dict[str, str]) -> str | None:
    # require a dns name rather than a url or literal
    if not isinstance(value, str) or not HOSTNAME_PATTERN.fullmatch(value) or "." not in value:
        fields["smtp.host"] = "must be a public DNS hostname"
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value.lower()
    # reject all address literals
    if address:
        fields["smtp.host"] = "must be a public DNS hostname"
    return None


# preserve, replace, or explicitly clear a private field
def _merged_secret(
    payload: dict[str, Any],
    current: dict[str, Any],
    name: str,
    path: str,
    fields: dict[str, str],
) -> str:
    clear_name = f"clear_{name}"
    clear = payload.get(clear_name, False)
    # require strict clear flags when supplied
    if not isinstance(clear, bool):
        fields[f"{path}.{clear_name}"] = "must be a boolean"
        clear = False
    supplied = payload.get(name)
    # forbid replacement and clearing together
    if clear and isinstance(supplied, str) and supplied:
        fields[f"{path}.{name}"] = "cannot be replaced and cleared together"
        return current[name]
    # apply an explicit clear
    if clear:
        return ""
    # preserve omitted and blank secret controls
    if supplied is None or supplied == "":
        return current[name]
    validated = _secret(supplied, f"{path}.{name}", fields)
    return current[name] if validated is None else validated


# validate one exact-aircraft or aircraft-model override
def _override(value: Any, index: int, fields: dict[str, str]) -> dict[str, Any] | None:
    path = f"overrides.{index}"
    shared = frozenset(("mode", "categories", "label"))
    # require exactly one supported selector
    if not isinstance(value, dict) or frozenset(value) not in (shared | {"hex"}, shared | {"model"}):
        fields[path] = "must contain exactly one of hex or model, plus mode, categories, and label"
        return None
    selector = "hex" if "hex" in value else "model"
    selector_value = value[selector]
    # select the exact-aircraft grammar
    if selector == "hex":
        # require one canonical six-hex identity
        if not isinstance(selector_value, str) or ICAO_PATTERN.fullmatch(selector_value.upper()) is None:
            fields[f"{path}.hex"] = "must be a six-character ICAO hex address"
            normalized_selector = ""
        else:
            normalized_selector = selector_value.upper()
    else:
        # require one bounded icao type designator
        if not isinstance(selector_value, str) or AIRCRAFT_MODEL_PATTERN.fullmatch(selector_value.upper()) is None:
            fields[f"{path}.model"] = "must be a two-to-four-character ICAO type designator"
            normalized_selector = ""
        else:
            normalized_selector = selector_value.upper()
    mode = value["mode"]
    # restrict override behavior
    if mode not in ("include", "exclude"):
        fields[f"{path}.mode"] = "must be include or exclude"
    categories = value["categories"]
    # require a nonempty unique category subset
    if (
        not isinstance(categories, list)
        or not categories
        or len(categories) > len(ALERT_CATEGORIES)
        or any(category not in ALERT_CATEGORIES for category in categories)
        or len(set(categories)) != len(categories)
    ):
        fields[f"{path}.categories"] = "must contain unique supported categories"
        normalized_categories: list[str] = []
    else:
        normalized_categories = [category for category in ALERT_CATEGORIES if category in categories]
    label = value["label"]
    # bound operator labels and reject control characters
    if not isinstance(label, str) or len(label) > 100 or any(ord(character) < 32 for character in label):
        fields[f"{path}.label"] = "must be at most 100 printable characters"
        label = ""
    return {selector: normalized_selector, "mode": mode, "categories": normalized_categories, "label": label}


# validate and merge a public settings write
def validate_alert_settings(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, str] = {}
    expected = frozenset(("revision", "enabled", "categories", "pushover", "smtp", "overrides"))
    expected_with_routes = expected | {"category_channels"}
    # require the public write contract
    if not isinstance(payload, dict) or frozenset(payload) not in (expected, expected_with_routes):
        raise ValidationError(
            {
                "settings": (
                    "must contain exactly revision, enabled, categories, optional category_channels, "
                    "pushover, smtp, and overrides"
                )
            }
        )
    revision = payload["revision"]
    # require a nonnegative revision
    if not _is_int(revision) or revision < 0:
        fields["revision"] = "must be a nonnegative integer"
    enabled = payload["enabled"]
    # require a strict enabled flag
    if not isinstance(enabled, bool):
        fields["enabled"] = "must be a boolean"
    categories = payload["categories"]
    # require a unique category subset
    if (
        not isinstance(categories, list)
        or len(categories) > len(ALERT_CATEGORIES)
        or any(category not in ALERT_CATEGORIES for category in categories)
        or len(set(categories)) != len(categories)
    ):
        fields["categories"] = "must contain unique supported categories"
        normalized_categories: list[str] = []
    else:
        normalized_categories = [category for category in ALERT_CATEGORIES if category in categories]

    # honor an explicit routing contract or preserve legacy-write intent
    if "category_channels" in payload:
        category_channels = _validated_category_channels(payload["category_channels"], fields)
        routed_categories = [category for category in ALERT_CATEGORIES if category_channels[category]]
        # keep the compatibility category list equal to routed notification types
        if routed_categories != normalized_categories:
            fields["category_channels"] = "nonempty routes must match categories"
    else:
        current_categories = set(current.get("categories", ()))
        current_channels = current.get("category_channels")
        # derive routes only when the current snapshot itself is legacy
        if not isinstance(current_channels, dict):
            current_channels = _legacy_category_channels(current.get("categories"))
        category_channels = {}
        # retain existing routes while defaulting newly selected legacy categories to both
        for category in ALERT_CATEGORIES:
            if category not in normalized_categories:
                category_channels[category] = []
            elif category in current_categories:
                category_channels[category] = list(current_channels.get(category, ()))
            else:
                category_channels[category] = list(ALERT_CHANNELS)

    pushover = payload["pushover"]
    allowed_pushover = frozenset(
        ("app_token", "user_key", "clear_app_token", "clear_user_key", "app_token_configured", "user_key_configured")
    )
    # require a bounded provider object
    if not isinstance(pushover, dict) or not frozenset(pushover).issubset(allowed_pushover):
        fields["pushover"] = "contains unsupported fields"
        pushover = {}
    # reject response-only markers on writes
    for marker in ("app_token_configured", "user_key_configured"):
        # keep markers read-only
        if marker in pushover:
            fields[f"pushover.{marker}"] = "is read-only"
    merged_pushover = {
        "app_token": _merged_secret(pushover, current["pushover"], "app_token", "pushover", fields),
        "user_key": _merged_secret(pushover, current["pushover"], "user_key", "pushover", fields),
    }

    smtp = payload["smtp"]
    allowed_smtp = frozenset(
        (
            "host",
            "port",
            "username",
            "password",
            "from_address",
            "to_address",
            "clear_username",
            "clear_password",
            "username_configured",
            "password_configured",
        )
    )
    # require a bounded smtp object
    if not isinstance(smtp, dict) or not frozenset(smtp).issubset(allowed_smtp):
        fields["smtp"] = "contains unsupported fields"
        smtp = {}
    # reject response-only markers on writes
    for marker in ("username_configured", "password_configured"):
        # keep markers read-only
        if marker in smtp:
            fields[f"smtp.{marker}"] = "is read-only"
    host = smtp.get("host", "")
    # allow an empty draft hostname only while disabled
    if host == "":
        normalized_host = ""
    else:
        normalized_host = _hostname(host, fields) or ""
    port = smtp.get("port", 465)
    # restrict smtp to encrypted standard ports
    if not _is_int(port) or port not in (465, 587):
        fields["smtp.port"] = "must be 465 or 587"
    from_value = smtp.get("from_address", "")
    to_value = smtp.get("to_address", "")
    # permit incomplete address drafts only while disabled
    normalized_from = "" if from_value == "" else (_mailbox(from_value, "smtp.from_address", fields) or "")
    normalized_to = "" if to_value == "" else (_mailbox(to_value, "smtp.to_address", fields) or "")
    merged_smtp = {
        "host": normalized_host,
        "port": port,
        "username": _merged_secret(smtp, current["smtp"], "username", "smtp", fields),
        "password": _merged_secret(smtp, current["smtp"], "password", "smtp", fields),
        "from_address": normalized_from,
        "to_address": normalized_to,
    }

    overrides = payload["overrides"]
    normalized_overrides: list[dict[str, Any]] = []
    # bound the editable aircraft override list
    if not isinstance(overrides, list) or len(overrides) > MAX_OVERRIDES:
        fields["overrides"] = f"must contain at most {MAX_OVERRIDES} entries"
    else:
        # validate each override independently
        for index, value in enumerate(overrides):
            normalized = _override(value, index, fields)
            # retain usable normalized rows
            if normalized is not None:
                normalized_overrides.append(normalized)
    identities = [
        ("hex", entry["hex"]) if "hex" in entry else ("model", entry["model"]) for entry in normalized_overrides
    ]
    # keep each selector unambiguous
    if len(identities) != len(set(identities)):
        fields["overrides"] = "must contain at most one override per ICAO hex address or aircraft model"

    # collapse selected routes for provider-specific credential checks
    selected_channels = {channel for channels in category_channels.values() for channel in channels}
    # require at least one route before activation
    if enabled is True:
        # reject enabled settings without any notification destination
        if not selected_channels:
            fields["category_channels"] = "must select at least one route when alerts are enabled"
        required_fields: list[tuple[str, Any]] = []
        # require push credentials only when a selected type uses push
        if "pushover" in selected_channels:
            required_fields.extend(
                (
                    ("pushover.app_token", merged_pushover["app_token"]),
                    ("pushover.user_key", merged_pushover["user_key"]),
                )
            )
        # require smtp credentials only when a selected type uses email
        if "email" in selected_channels:
            required_fields.extend(
                (
                    ("smtp.host", merged_smtp["host"]),
                    ("smtp.username", merged_smtp["username"]),
                    ("smtp.password", merged_smtp["password"]),
                    ("smtp.from_address", merged_smtp["from_address"]),
                    ("smtp.to_address", merged_smtp["to_address"]),
                )
            )
        # identify each missing selected-channel field without echoing its value
        for path, value in required_fields:
            if not value:
                fields[path] = "is required when alerts are enabled"
    # reject all field failures together
    if fields:
        raise ValidationError(fields)
    return {
        "schema_version": ALERT_SCHEMA_VERSION,
        "revision": revision,
        "enabled": enabled,
        "categories": normalized_categories,
        "category_channels": category_channels,
        "pushover": merged_pushover,
        "smtp": merged_smtp,
        "overrides": normalized_overrides,
    }


# remove all secret values from an api response
def redact_alert_settings(settings: dict[str, Any]) -> dict[str, Any]:
    category_channels = settings.get("category_channels")
    # project migration routes even before the legacy file is rewritten
    if "category_channels" not in settings:
        category_channels = _legacy_category_channels(settings.get("categories"))
    return {
        "revision": settings["revision"],
        "enabled": settings["enabled"],
        "categories": copy.deepcopy(settings["categories"]),
        "category_channels": copy.deepcopy(category_channels),
        "pushover": {
            "app_token_configured": bool(settings["pushover"]["app_token"]),
            "user_key_configured": bool(settings["pushover"]["user_key"]),
        },
        "smtp": {
            "host": settings["smtp"]["host"],
            "port": settings["smtp"]["port"],
            "from_address": settings["smtp"]["from_address"],
            "to_address": settings["smtp"]["to_address"],
            "username_configured": bool(settings["smtp"]["username"]),
            "password_configured": bool(settings["smtp"]["password"]),
        },
        "overrides": copy.deepcopy(settings["overrides"]),
    }


# atomically write one private json document
def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
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
        # remove abandoned temporary output
        if temporary_path.exists():
            temporary_path.unlink()


# own the independent private alert settings document
class AlertSettingsStore:
    # initialize or validate persistent settings
    def __init__(self, path: Path, *, readonly: bool = False) -> None:
        self.path = path
        self.readonly = readonly
        self._lock = threading.Lock()
        # create safe disabled settings once
        if not self.path.exists():
            # keep worker sandboxes unable to create configuration
            if readonly:
                raise RuntimeError("alert settings file is unreadable")
            _atomic_write(self.path, default_alert_settings())
        self._settings = self._read_validated()
        self._mtime_ns = self.path.stat().st_mtime_ns
        # normalize permissions only in the admin-owned writer
        if not readonly:
            os.chmod(self.path, 0o600)

    # validate the complete stored schema
    def _read_validated(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise RuntimeError("alert settings file is unreadable") from exc
        expected = frozenset(default_alert_settings())
        legacy_expected = expected - {"category_channels"}
        # require the current or legacy first-version internal schema
        if (
            not isinstance(value, dict)
            or frozenset(value) not in (expected, legacy_expected)
            or value.get("schema_version") != ALERT_SCHEMA_VERSION
        ):
            raise RuntimeError("alert settings file has an invalid schema")
        pushover = value.get("pushover")
        smtp = value.get("smtp")
        # require complete private provider records before redaction
        if (
            not isinstance(pushover, dict)
            or frozenset(pushover) != frozenset(("app_token", "user_key"))
            or not isinstance(smtp, dict)
            or frozenset(smtp) != frozenset(("host", "port", "username", "password", "from_address", "to_address"))
        ):
            raise RuntimeError("alert settings file has an invalid schema")
        public = redact_alert_settings(value)
        public["pushover"] = {
            "app_token": value["pushover"].get("app_token"),
            "user_key": value["pushover"].get("user_key"),
        }
        public["smtp"].update({"username": value["smtp"].get("username"), "password": value["smtp"].get("password")})
        # remove response-only markers before validation
        for section, markers in (
            (public["pushover"], ("app_token_configured", "user_key_configured")),
            (public["smtp"], ("username_configured", "password_configured")),
        ):
            # delete each generated marker
            for marker in markers:
                section.pop(marker, None)
        try:
            validated = validate_alert_settings(public, default_alert_settings())
        except ValidationError as exc:
            raise RuntimeError("alert settings file has an invalid schema") from exc
        validated["revision"] = value["revision"]
        return validated

    # return an isolated private snapshot
    def get_private(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._settings)

    # reload changes written by the separate admin process
    def refresh(self) -> bool:
        with self._lock:
            try:
                modified = self.path.stat().st_mtime_ns
            except OSError as exc:
                raise RuntimeError("alert settings file is unreadable") from exc
            # avoid reparsing unchanged private settings
            if modified == self._mtime_ns:
                return False
            self._settings = self._read_validated()
            self._mtime_ns = modified
            return True

    # return an isolated redacted snapshot
    def get_public(self) -> dict[str, Any]:
        with self._lock:
            return redact_alert_settings(self._settings)

    # replace editable settings with optimistic concurrency
    def update(self, payload: Any) -> dict[str, Any]:
        with self._lock:
            # prevent accidental writes from the worker store
            if self.readonly:
                raise RuntimeError("alert settings store is read-only")
            # require a comparable client revision
            if not isinstance(payload, dict) or not _is_int(payload.get("revision")):
                raise ValidationError({"revision": "must be a nonnegative integer"})
            # reject stale changes with current safe settings
            if payload["revision"] != self._settings["revision"]:
                raise RevisionConflict(redact_alert_settings(self._settings))
            validated = validate_alert_settings(payload, self._settings)
            validated["revision"] = self._settings["revision"] + 1
            _atomic_write(self.path, validated)
            self._settings = validated
            self._mtime_ns = self.path.stat().st_mtime_ns
            return redact_alert_settings(self._settings)
