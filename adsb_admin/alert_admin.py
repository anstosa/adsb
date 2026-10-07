"""Private admin projections and admin-owned notification test requests."""

from __future__ import annotations

import math
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .alert_config import AlertSettingsStore, _atomic_write
from .alert_sources import read_json
from .alert_store import read_history, read_test_ack
from .config import RevisionConflict, ValidationError

SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
CHANNEL_STATES = frozenset(
    ("pending", "queued", "in_flight", "retry", "accepted", "failed", "expired", "suppressed", "unknown")
)
MAINTENANCE_EMAIL_STATES = frozenset(
    (
        "not_configured",
        "waiting",
        "pending",
        "in_flight",
        "retry",
        "accepted",
        "failed",
        "expired",
        "suppressed",
        "unknown",
    )
)


# project only fixed delivery states and bounded counts
def _channel_projection(value: Any) -> dict[str, Any]:
    # reject malformed or secret-bearing worker state
    if not isinstance(value, dict):
        return {"state": "unknown", "error": None}
    state = value.get("state")
    error = value.get("error")
    counts = {
        key: min(count, 1_000_000)
        for key, count in value.items()
        if key in CHANNEL_STATES and type(count) is int and count >= 0
    }
    # summarize the worker's bounded durable outcomes
    if state not in CHANNEL_STATES:
        state = next((key for key in ("unknown", "retry", "failed", "queued", "accepted") if counts.get(key)), "ready")
    retry_at = value.get("retry_at")
    return {
        "state": state,
        "error": error if isinstance(error, str) and SAFE_CODE.fullmatch(error) else None,
        "counts": counts,
        "retry_at": retry_at if type(retry_at) in (int, float) and math.isfinite(retry_at) else None,
    }


# project only the fixed maintenance email heartbeat
def _maintenance_email_projection(value: Any) -> dict[str, Any]:
    result = {
        "state": "unknown",
        "error": None,
        "reported_at": None,
        "accepted_at": None,
        "retry_at": None,
    }
    # reject malformed or secret-bearing worker state
    if not isinstance(value, dict):
        return result
    state = value.get("state")
    # retain only the fixed worker state vocabulary
    if state in MAINTENANCE_EMAIL_STATES:
        result["state"] = state
    error = value.get("error")
    # expose only bounded machine-readable diagnostics
    if isinstance(error, str) and SAFE_CODE.fullmatch(error):
        result["error"] = error
    # retain only finite timestamps
    for key in ("reported_at", "accepted_at", "retry_at"):
        stamp = value.get(key)
        # exclude booleans and arbitrary nested values
        if type(stamp) in (int, float) and math.isfinite(stamp):
            result[key] = float(stamp)
    return result


# own only alert settings and the fixed test-request handoff
class AlertAdmin:
    # derive isolated private paths from the existing settings namespace
    def __init__(self, settings_path: Path, status_path: Path) -> None:
        self.settings_path = settings_path.with_name("alerts.json")
        self.test_path = settings_path.with_name("alerts-test.json")
        self.state_dir = settings_path.parent.parent / "alerts"
        self.controller_path = status_path
        self._settings: AlertSettingsStore | None = None
        self._settings_lock = threading.Lock()
        self._test_lock = threading.Lock()

    # initialize the optional alert store without breaking station administration
    def settings(self) -> AlertSettingsStore:
        # create disabled defaults through the admin's existing private writer boundary
        with self._settings_lock:
            # serialize initial creation across threaded requests
            if self._settings is None:
                self._settings = AlertSettingsStore(self.settings_path)
            return self._settings

    # return a bounded read-only history page
    def history(self, *, before: str | None, limit: int) -> dict[str, Any]:
        # validate request bounds even before the worker creates the database
        if not 1 <= limit <= 50 or (before is not None and len(before) > 256):
            raise ValueError("invalid history request")
        path = self.state_dir / "alerts.sqlite3"
        # provide an honest initial empty page
        if not path.exists():
            # reject malformed cursor input consistently
            if before is not None:
                raise ValueError("invalid history cursor")
            return {"events": [], "next_cursor": None}
        return read_history(path, before=before, limit=limit)

    # read one safe pending test acknowledgement without writing the worker database
    def test_status(self, *, now: float) -> dict[str, Any] | None:
        envelope = self._test_envelope()
        # an unused slot has no pending request
        if envelope is None:
            return None
        request_id = envelope["request_id"]
        created_at = envelope["created_at"]
        database = self.state_dir / "alerts.sqlite3"
        # a missing initial database has no acknowledgement yet
        acknowledgement = read_test_ack(database, request_id) if database.exists() else None
        # preserve a durable worker acknowledgement when present
        if acknowledgement is not None:
            return acknowledgement
        return {
            "request_id": request_id,
            "state": "queued" if 0 <= now - created_at <= 300 else "expired",
            "created_at": created_at,
            "channels": {},
        }

    # distinguish an unused slot from unsafe unreadable durable rate-limit state
    def _test_envelope(self) -> dict[str, Any] | None:
        try:
            envelope = read_json(self.test_path, 8192)
            request_id = str(uuid.UUID(envelope["request_id"]))
            created_at = float(envelope["created_at"])
            requested_at = float(envelope["last_requested_at"])
            # require the exact bounded admin-owned handoff contract
            if (
                set(envelope) != {"schema_version", "request_id", "revision", "created_at", "last_requested_at"}
                or envelope["schema_version"] != 1
                or type(envelope["revision"]) is not int
                or envelope["revision"] < 0
                or request_id != envelope["request_id"]
                or not math.isfinite(created_at)
                or not math.isfinite(requested_at)
                or created_at <= 0
                or requested_at != created_at
            ):
                raise ValueError("invalid test envelope")
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            raise RuntimeError("test request state is unavailable") from exc
        return envelope

    # project optional notifier health without exposing arbitrary private fields
    def status(self, *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        config = self.settings().get_public()
        configured = {
            "pushover": config["pushover"]["app_token_configured"] and config["pushover"]["user_key_configured"],
            "email": config["smtp"]["username_configured"]
            and config["smtp"]["password_configured"]
            and bool(config["smtp"]["host"] and config["smtp"]["from_address"] and config["smtp"]["to_address"]),
        }
        # require only channels selected for enabled aircraft types
        selected = {channel for category in config["categories"] for channel in config["category_channels"][category]}
        complete = bool(selected) and all(configured[channel] for channel in selected)
        try:
            worker = read_json(self.state_dir / "worker-status.json", 64 * 1024)
            controller = read_json(self.controller_path, 256 * 1024)
            age = current - float(worker["sampled_at"])
            alerts = controller.get("alerts", {})
            running = (
                worker.get("schema_version") == 1
                and worker.get("process_running") is True
                and 0 <= age <= 30
                and worker.get("activation_id") == alerts.get("activation_id")
                and worker.get("source_contract_digest") == alerts.get("source_contract_digest")
            )
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            worker = {}
            running = False
        bands = {}
        source_bands = worker.get("bands", {})
        # retain a fixed independent band projection
        for band in ("1090", "978"):
            source = source_bands.get(band, {}) if isinstance(source_bands, dict) else {}
            state = source.get("state") if isinstance(source, dict) else None
            last_message = source.get("last_message_at") if isinstance(source, dict) else None
            bands[band] = {
                "state": state if running and state in ("healthy", "unknown", "absent") else "unknown",
                "last_message_at": last_message
                if type(last_message) in (int, float) and math.isfinite(last_message) and last_message > 0
                else None,
            }
        # distinguish quiet valid receivers from absent hardware and unknown coverage
        for band in bands.values():
            last = band["last_message_at"]
            if band["state"] == "healthy" and (last is None or current - last > 30):
                band["state"] = "quiet"
        channels = {}
        raw_channels = worker.get("channels", {})
        # keep channel outcomes independent
        for channel in ("pushover", "email"):
            channels[channel] = _channel_projection(
                raw_channels.get(channel) if isinstance(raw_channels, dict) else None
            )
            # keep unused providers from degrading selected delivery channels
            if channel not in selected:
                channels[channel]["state"] = "disabled"
            # describe each provider's own configuration before availability
            elif not configured[channel]:
                channels[channel]["state"] = "not_configured"
            elif not config["enabled"]:
                channels[channel]["state"] = "disabled"
            elif not running:
                channels[channel]["state"] = "unknown"
        version = worker.get("catalog_version")
        version = version if isinstance(version, str) and 0 < len(version) <= 100 else None
        revision = worker.get("applied_revision")
        rejections = worker.get("capacity_rejections")
        rejections = min(rejections, 1_000_000_000) if type(rejections) is int and rejections >= 0 else 0
        capacity_degraded = bool(rejections or worker.get("capacity_error"))
        source_healthy = running and all(value["state"] in ("healthy", "quiet", "absent") for value in bands.values())
        source_state = "unknown"
        # no-radio infrastructure can be ready without claiming active reception
        if source_healthy:
            source_state = (
                "no_radio"
                if all(value["state"] == "absent" for value in bands.values())
                else "quiet"
                if all(value["state"] in ("quiet", "absent") for value in bands.values())
                else "healthy"
            )
        configuration_state = "unavailable" if worker.get("configuration_error") else "ready" if complete else "missing"
        channel_degraded = any(
            value["state"] in ("failed", "retry", "unknown", "expired") for value in channels.values()
        )
        overall = "ready"
        # keep process, configuration, source and provider failures independent
        if not running:
            overall = "degraded"
        elif not config["enabled"]:
            overall = "disabled"
        elif configuration_state != "ready":
            overall = "needs-configuration"
        elif capacity_degraded or not source_healthy or channel_degraded:
            overall = "degraded"
        elif source_state in ("no_radio", "quiet"):
            overall = "no-radio" if source_state == "no_radio" else "quiet"
        return {
            "sampled_at": current,
            "process_running": running,
            "applied_revision": revision if type(revision) is int and revision >= 0 else None,
            "enabled": config["enabled"],
            "capacity_rejections": rejections,
            "capacity_state": "degraded" if capacity_degraded else "ready" if running else "unknown",
            "configuration_state": configuration_state,
            "source_state": source_state,
            "overall_state": overall,
            "bands": bands,
            "channels": channels,
            "catalog": {"version": version, "state": "ready" if running and version else "unknown"},
            "test": self.test_status(now=current),
        }

    # project maintenance email independently from aircraft alert activation
    def maintenance_email_status(self, *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        try:
            config = self.settings().get_public()
            smtp = config["smtp"]
            configured = (
                smtp["username_configured"]
                and smtp["password_configured"]
                and bool(smtp["host"] and smtp["from_address"] and smtp["to_address"])
            )
        except (OSError, RuntimeError, KeyError, TypeError, RecursionError):
            return _maintenance_email_projection(None)
        # describe configuration before worker availability
        if not configured:
            result = _maintenance_email_projection(None)
            result["state"] = "not_configured"
            return result
        try:
            worker = read_json(self.state_dir / "worker-status.json", 64 * 1024)
            sampled_at = worker["sampled_at"]
            age = current - float(sampled_at)
            running = (
                worker.get("schema_version") == 1
                and worker.get("process_running") is True
                and type(sampled_at) in (int, float)
                and math.isfinite(sampled_at)
                and 0 <= age <= 30
                and worker.get("applied_revision") == config["revision"]
            )
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            return _maintenance_email_projection(None)
        # a stale or mismatched worker cannot establish delivery state
        if not running:
            return _maintenance_email_projection(None)
        return _maintenance_email_projection(worker.get("maintenance_email"))

    # enqueue one intentional fixed-content test with durable admin-owned throttling
    def request_test(self, payload: Any, *, now: float | None = None) -> tuple[int, dict[str, Any]]:
        current = time.time() if now is None else now
        # reject any caller-provided provider message or target
        if not isinstance(payload, dict) or set(payload) != {"revision"} or type(payload["revision"]) is not int:
            raise ValidationError({"revision": "must provide exactly one configuration revision"})
        with self._test_lock:
            config = self.settings().get_public()
            # prevent dispatch with stale credentials or destinations
            if payload["revision"] != config["revision"]:
                raise RevisionConflict(config)
            # require explicit enabled complete configuration before any external test
            if not config["enabled"]:
                raise ValidationError({"enabled": "save complete enabled alert settings before testing"})
            envelope = self._test_envelope()
            last_requested = float(envelope["last_requested_at"]) if envelope is not None else 0.0
            pending = self.test_status(now=current)
            database = self.state_dir / "alerts.sqlite3"
            # an existing unavailable database must not permit unsafe slot replacement
            if database.exists():
                read_history(database, limit=1)
            # make retries of an outstanding click idempotent
            if pending is not None and pending["state"] == "queued":
                return 202, {"request_id": pending["request_id"], "status": "queued"}
            # require a readable worker database before creating a new request
            read_history(database, limit=1)
            # retain one request per minute across admin restarts
            if current - last_requested < 60:
                return 429, {"error": "rate_limited", "retry_after": max(1, int(60 - (current - last_requested)))}
            request_id = str(uuid.uuid4())
            _atomic_write(
                self.test_path,
                {
                    "schema_version": 1,
                    "request_id": request_id,
                    "revision": config["revision"],
                    "created_at": current,
                    "last_requested_at": current,
                },
            )
            return 202, {"request_id": request_id, "status": "queued"}
