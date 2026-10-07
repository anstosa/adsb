"""Authenticated fixed-envelope bridge to the privileged update service."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .config import RevisionConflict, ValidationError
from .maintenance import public_report

IDENTIFIER = re.compile(r"[a-f0-9]{64}\Z")
REQUEST_KEYS = {"schema_version", "request_id", "candidate_ids", "generation", "requested_at"}
LEGACY_REQUEST_KEYS = (REQUEST_KEYS - {"candidate_ids"}) | {"candidate_id"}
MAX_BATCH_SIZE = 7
ACTIVE_STATES = {"queued", "preparing", "installing"}
INSTALLABLE_STATES = {"available", "held", "failed", "rolled_back"}
COOLDOWN_SECONDS = 60


# validate a bounded exact selection without silently removing duplicates
def selected_ids(value: object) -> list[str]:
    # reject malformed or ambiguous batches before sorting
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= MAX_BATCH_SIZE
        or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError("invalid update selection")
    return sorted(value)


# read a bounded private regular file without following links
def read_request(path: Path) -> dict | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        # reject special files oversized requests and permissive ownership
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 1024
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("invalid update request file")
        result = json.loads(os.read(descriptor, 1025))
    finally:
        os.close(descriptor)
    # permit only the server-generated fixed envelope
    if (
        not isinstance(result, dict)
        or set(result) not in (REQUEST_KEYS, LEGACY_REQUEST_KEYS)
        or type(result["schema_version"]) is not int
        or result["schema_version"] != 1
        or any(
            not isinstance(result[key], str) or not IDENTIFIER.fullmatch(result[key])
            for key in ("request_id", "generation")
        )
    ):
        raise ValueError("invalid update request")
    # accept an earlier release's pending singleton without widening its authority
    identifiers = selected_ids(result.get("candidate_ids", [result.get("candidate_id")]))
    result.pop("candidate_id", None)
    result["candidate_ids"] = identifiers
    stamp = datetime.fromisoformat(result["requested_at"])
    # require an aware utc clock before exposing pending work
    if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
        raise ValueError("invalid update clock")
    return result


# publish an owner-only document on the same filesystem
def _write_private(path: Path, value: dict, *, exclusive: bool = False) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".update-", delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            json.dump(value, output, separators=(",", ":"), sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        # never overwrite a request that the root service has not claimed
        if exclusive:
            os.link(temporary, path, follow_symlinks=False)
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        # remove only the unpublished temporary document
        if temporary is not None:
            temporary.unlink(missing_ok=True)


# serialize authenticated requests without granting docker or root access
class UpdateAdmin:
    # bind the bridge to existing private configuration and status roots
    def __init__(self, settings_path: Path, status_path: Path) -> None:
        self.request_path = settings_path.with_name("update-request.json")
        self.ledger_path = settings_path.with_name(".update-request-ledger.json")
        self.lock_path = settings_path.with_name(".update-request.lock")
        self.report_path = status_path.with_name("maintenance.json")

    # reflect acknowledged pending work before the root worker publishes progress
    def report(self) -> dict:
        report = public_report(self.report_path, installation_path=self.report_path.with_name("installation.json"))
        try:
            pending = read_request(self.request_path)
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            pending = None
        # overlay only a request bound to the currently displayed snapshot
        if pending is not None and pending["generation"] == report.get("generation"):
            report["installation"] = {
                "state": "queued",
                "candidate_id": pending["candidate_ids"][0],
                "candidate_ids": pending["candidate_ids"],
                "request_id": pending["request_id"],
                "message": "Installation queued; completion has not been reported.",
                "updated_at": pending["requested_at"],
            }
        return report

    # validate an exact batch and queue one fixed request atomically
    def request_install(self, payload: object, *, now: datetime | None = None) -> tuple[int, dict]:
        # reject caller-supplied commands refs paths and extra keys
        if (
            not isinstance(payload, dict)
            or set(payload) not in ({"candidate_ids", "generation"}, {"candidate_id", "generation"})
            or not isinstance(payload.get("generation"), str)
            or not IDENTIFIER.fullmatch(payload["generation"])
        ):
            raise ValidationError({"update": "Select one or more exact updates from the current maintenance report."})
        try:
            identifiers = selected_ids(payload.get("candidate_ids", [payload.get("candidate_id")]))
        except ValueError as error:
            raise ValidationError({"update": "Select one to seven unique updates from the current report."}) from error
        current = now or datetime.now(timezone.utc)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(descriptor)
            # do not serialize on an attacker-selected file or permissive lock
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise ValueError("invalid update request lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            report = self.report()
            installation = report.get("installation", {})
            # idempotently acknowledge the exact active request and reject peers
            if installation.get("state") in ACTIVE_STATES:
                if (
                    installation.get("candidate_ids", [installation.get("candidate_id")]) == identifiers
                    and report.get("generation") == payload["generation"]
                    and IDENTIFIER.fullmatch(str(installation.get("request_id", "")))
                ):
                    return 202, {
                        "state": "queued",
                        "request_id": installation["request_id"],
                        "candidate_id": identifiers[0],
                        "candidate_ids": identifiers,
                    }
                raise RevisionConflict({"error": "update_busy"})
            # require a recent snapshot before granting compatibility authorization
            stamp = datetime.fromisoformat(report["updated_at"]) if report.get("updated_at") else None
            candidates = report.get("updates", [])
            selected = [row for row in candidates if row.get("id") in identifiers]
            if (
                report.get("generation") != payload["generation"]
                or report.get("status") not in {"ok", "attention"}
                or stamp is None
                or not 0 <= (current - stamp).total_seconds() <= 8 * 86400
                or len(selected) != len(identifiers)
                or any(row.get("state") not in INSTALLABLE_STATES for row in selected)
            ):
                raise RevisionConflict({"error": "update_changed"})
            pending = read_request(self.request_path)
            # a stale pending slot must be consumed by the root service first
            if pending is not None:
                raise RevisionConflict({"error": "update_busy"})
            previous = read_request(self.ledger_path)
            # persist a bounded cooldown across sessions and admin restarts
            if previous is not None:
                elapsed = (current - datetime.fromisoformat(previous["requested_at"])).total_seconds()
                if elapsed < COOLDOWN_SECONDS:
                    return 429, {"error": "update_cooldown"}
            request = {
                "schema_version": 1,
                "request_id": secrets.token_hex(32),
                "candidate_ids": identifiers,
                "generation": payload["generation"],
                "requested_at": current.isoformat(),
            }
            _write_private(self.ledger_path, request)
            try:
                _write_private(self.request_path, request, exclusive=True)
            except FileExistsError as error:
                raise RevisionConflict({"error": "update_busy"}) from error
            return 202, {
                "state": "queued",
                "request_id": request["request_id"],
                "candidate_id": identifiers[0],
                "candidate_ids": identifiers,
            }
        finally:
            os.close(descriptor)
