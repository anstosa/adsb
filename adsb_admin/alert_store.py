"""Durable aircraft encounter, history, and delivery outbox state."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import sqlite3
import stat
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from adsb_admin.alert_catalog import normalize_icao
from adsb_admin.alert_delivery import DeliveryResult

STORE_SCHEMA_VERSION = 1
DELIVERY_CHANNELS = ("pushover", "email")
TERMINAL_STATES = frozenset(("accepted", "failed", "expired", "suppressed", "unknown"))
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_PENDING_EVENTS = 1_000
MAX_ENCOUNTERS = 10_000
MAX_MAINTENANCE_NOTIFICATIONS = 1_000


# share bounded retry and ambiguous-send outcomes across notification types
def _delivery_outcome(result: DeliveryResult, *, now: float, deadline: float) -> tuple:
    state = result.state
    error_code = result.error_code[:80] if result.error_code else None
    next_attempt_at = now
    accepted_at = None
    # retain only documented provider acceptance
    if state == "accepted":
        accepted_at = now
    # retry only explicit pre-acceptance transport failures
    elif state == "retry":
        delay = max(5.0, min(float(result.retry_after or 5.0), 300.0))
        next_attempt_at = now + delay
        # preserve the original bounded delivery window
        if next_attempt_at >= deadline:
            state = "expired"
            error_code = "delivery_deadline"
    return state, error_code, accepted_at, next_attempt_at


# encode one opaque history boundary
def _encode_cursor(created_at: float, event_id: str) -> str:
    value = json.dumps([created_at, event_id], separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


# decode one bounded history boundary
def _decode_cursor(value: str | None) -> tuple[float, str] | None:
    # preserve the initial page
    if value is None:
        return None
    # reject oversized or malformed cursors
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("invalid history cursor")
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid history cursor") from exc
    # require one timestamp and event identity
    if (
        not isinstance(decoded, list)
        or len(decoded) != 2
        or isinstance(decoded[0], bool)
        or not isinstance(decoded[0], (int, float))
        or not isinstance(decoded[1], str)
        or len(decoded[1]) > 64
    ):
        raise ValueError("invalid history cursor")
    return float(decoded[0]), decoded[1]


# open a bounded sqlite connection
def _connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    # use sqlite read-only mode for admin projections
    if readonly:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.0)
    else:
        connection = sqlite3.connect(path, timeout=1.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=1000")
    return connection


# project one event page from an existing connection
def _history_query(connection: sqlite3.Connection, before: str | None, limit: int) -> dict[str, Any]:
    # keep every request bounded
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 50:
        raise ValueError("history limit must be between 1 and 50")
    boundary = _decode_cursor(before)
    parameters: list[Any] = []
    where = ""
    # add the opaque keyset boundary
    if boundary is not None:
        where = "WHERE (created_at < ? OR (created_at = ? AND id < ?))"
        parameters.extend((boundary[0], boundary[0], boundary[1]))
    parameters.append(limit)
    rows = connection.execute(
        f"""
        SELECT id, kind, hex, label, categories_json, bands_json, receptions_json, observed_at, created_at
        FROM events
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        parameters,
    ).fetchall()
    event_ids = [row["id"] for row in rows]
    outbox_by_event: dict[str, dict[str, Any]] = {event_id: {} for event_id in event_ids}
    # load at most two channel rows per bounded event page
    if event_ids:
        placeholders = ",".join("?" for _event_id in event_ids)
        channel_rows = connection.execute(
            f"""
            SELECT event_id, channel, state, attempts, error_code, accepted_at
            FROM outbox
            WHERE event_id IN ({placeholders})
            """,
            event_ids,
        ).fetchall()
        # group safe channel projections
        for channel_row in channel_rows:
            outbox_by_event[channel_row["event_id"]][channel_row["channel"]] = {
                "state": channel_row["state"],
                "attempts": channel_row["attempts"],
                "error": channel_row["error_code"],
                "accepted_at": channel_row["accepted_at"],
            }
    events: list[dict[str, Any]] = []
    # decode only worker-authored bounded json fields
    for row in rows:
        events.append(
            {
                "id": row["id"],
                "kind": row["kind"],
                "hex": row["hex"],
                "label": row["label"],
                "categories": json.loads(row["categories_json"]),
                "bands": json.loads(row["bands_json"]),
                "receptions": json.loads(row["receptions_json"]),
                "observed_at": row["observed_at"],
                "created_at": row["created_at"],
                "channels": outbox_by_event[row["id"]],
            }
        )
    next_cursor = None
    # expose a next-page boundary only for a full page
    if len(rows) == limit:
        last = rows[-1]
        next_cursor = _encode_cursor(last["created_at"], last["id"])
    return {"events": events, "next_cursor": next_cursor}


# read private history without obtaining write access
def read_history(path: Path, *, before: str | None = None, limit: int = 50) -> dict[str, Any]:
    connection = _connect(path, readonly=True)
    try:
        return _history_query(connection, before, limit)
    finally:
        connection.close()


# own the single-writer notification database
class AlertStore:
    # initialize additive schema and recover ambiguous leases
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self._lock = threading.RLock()
        self._connection = _connect(path)
        self._initialize()
        os.chmod(self.path, 0o600)

    # create the versioned initial schema
    def _initialize(self) -> None:
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK(kind IN ('aircraft','test')),
                    hex TEXT,
                    label TEXT NOT NULL,
                    categories_json TEXT NOT NULL,
                    bands_json TEXT NOT NULL,
                    receptions_json TEXT NOT NULL DEFAULT '{}',
                    observed_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    config_revision INTEGER NOT NULL,
                    deadline_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_history_idx ON events(created_at DESC, id DESC);
                CREATE TABLE IF NOT EXISTS encounters (
                    hex TEXT PRIMARY KEY,
                    last_seen_at REAL NOT NULL,
                    current_event_id TEXT REFERENCES events(id) ON DELETE SET NULL,
                    notified INTEGER NOT NULL DEFAULT 0 CHECK(notified IN (0,1)),
                    required_bands_json TEXT NOT NULL,
                    label TEXT NOT NULL,
                    categories_json TEXT NOT NULL,
                    rearmed_at REAL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                    channel TEXT NOT NULL CHECK(channel IN ('pushover','email')),
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    accepted_at REAL,
                    next_attempt_at REAL NOT NULL,
                    deadline_at REAL NOT NULL,
                    config_revision INTEGER NOT NULL,
                    message_id TEXT NOT NULL,
                    leased_at REAL,
                    PRIMARY KEY(event_id, channel)
                );
                CREATE INDEX IF NOT EXISTS outbox_due_idx
                    ON outbox(state, next_attempt_at, deadline_at);
                CREATE TABLE IF NOT EXISTS test_ack (
                    request_id TEXT PRIMARY KEY,
                    config_revision INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    state TEXT NOT NULL,
                    error_code TEXT,
                    event_id TEXT REFERENCES events(id) ON DELETE SET NULL
                );
                CREATE TABLE IF NOT EXISTS maintenance_notifications (
                    id TEXT PRIMARY KEY,
                    reported_at REAL NOT NULL,
                    subject TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    config_revision INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    accepted_at REAL,
                    next_attempt_at REAL NOT NULL,
                    deadline_at REAL NOT NULL,
                    message_id TEXT NOT NULL,
                    leased_at REAL
                );
                CREATE INDEX IF NOT EXISTS maintenance_due_idx
                    ON maintenance_notifications(state, next_attempt_at);
                """
            )
            row = self._connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            columns = {column["name"] for column in self._connection.execute("PRAGMA table_info(events)").fetchall()}
            # add the first-version reception qualifier to pre-release databases
            if "receptions_json" not in columns:
                self._connection.execute("ALTER TABLE events ADD COLUMN receptions_json TEXT NOT NULL DEFAULT '{}'")
            encounter_columns = {
                column["name"] for column in self._connection.execute("PRAGMA table_info(encounters)").fetchall()
            }
            # retain encounter notification state independently of retained history
            if "notified" not in encounter_columns:
                self._connection.execute(
                    "ALTER TABLE encounters ADD COLUMN notified INTEGER NOT NULL DEFAULT 0 CHECK(notified IN (0,1))"
                )
                self._connection.execute("UPDATE encounters SET notified=1 WHERE current_event_id IS NOT NULL")
            # initialize or validate the database version
            if row is None:
                self._connection.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(STORE_SCHEMA_VERSION),)
                )
            elif row["value"] != str(STORE_SCHEMA_VERSION):
                raise RuntimeError("unsupported alert database schema")
            # ambiguous process crashes must not resend leased work
            self._connection.execute(
                "UPDATE outbox SET state='unknown', error_code='worker_interrupted', leased_at=NULL "
                "WHERE state='in_flight'"
            )
            # never resend a maintenance email interrupted after leasing
            self._connection.execute(
                "UPDATE maintenance_notifications SET state='unknown', error_code='worker_interrupted', "
                "leased_at=NULL WHERE state='in_flight'"
            )

    # close the writer connection
    def close(self) -> None:
        with self._lock:
            self._connection.close()

    # restore only conservative encounter continuity into a fresh database
    def restore_continuity(self, path: Path) -> int:
        with self._lock:
            initial_counts = self._connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM encounters) AS encounters,
                    (SELECT COUNT(*) FROM events) AS events,
                    (SELECT COUNT(*) FROM outbox) AS outbox
                """
            ).fetchone()
        # never let a stale backup artifact override or block live state
        if any(initial_counts[key] for key in ("encounters", "events", "outbox")):
            return 0
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return 0
        except OSError as exc:
            raise RuntimeError("alert continuity snapshot is unreadable") from exc
        try:
            metadata = os.fstat(descriptor)
            # reject links, special files, and unbounded restore input
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16 * 1024 * 1024:
                raise RuntimeError("alert continuity snapshot is invalid")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(16 * 1024 * 1024 + 1)
        finally:
            os.close(descriptor)
        try:
            value = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("alert continuity snapshot is invalid") from exc
        # require the exact secret-free backup contract
        if (
            not isinstance(value, dict)
            or frozenset(value) != frozenset(("schema_version", "generation", "generated_at", "encounters"))
            or value.get("schema_version") != 1
            or not isinstance(value.get("generation"), str)
            or len(value["generation"]) > 100
            or not isinstance(value.get("encounters"), list)
            or len(value["encounters"]) > MAX_ENCOUNTERS
        ):
            raise RuntimeError("alert continuity snapshot is invalid")
        generated_at = value.get("generated_at")
        # require one finite snapshot clock
        if (
            isinstance(generated_at, bool)
            or not isinstance(generated_at, (int, float))
            or not math.isfinite(float(generated_at))
        ):
            raise RuntimeError("alert continuity snapshot is invalid")
        normalized: list[tuple[str, float, int, str, float | None]] = []
        # validate every row before mutating the fresh database
        for row in value["encounters"]:
            expected = frozenset(("hex", "last_seen_at", "current_event_id", "required_bands", "rearmed_at"))
            # require the exact continuity-only row schema
            if not isinstance(row, dict) or frozenset(row) != expected:
                raise RuntimeError("alert continuity snapshot is invalid")
            hex_id = normalize_icao(row.get("hex"))
            last_seen_at = row.get("last_seen_at")
            current_event_id = row.get("current_event_id")
            required_bands = row.get("required_bands")
            rearmed_at = row.get("rearmed_at")
            # reject unsafe identities, clocks, event markers, and weakened band sets
            if (
                hex_id is None
                or isinstance(last_seen_at, bool)
                or not isinstance(last_seen_at, (int, float))
                or not math.isfinite(float(last_seen_at))
                or (
                    current_event_id is not None
                    and (not isinstance(current_event_id, str) or len(current_event_id) > 64)
                )
                or not isinstance(required_bands, list)
                or not required_bands
                or len(required_bands) != len(set(required_bands))
                or any(band not in ("1090", "978") for band in required_bands)
                or (
                    rearmed_at is not None
                    and (
                        isinstance(rearmed_at, bool)
                        or not isinstance(rearmed_at, (int, float))
                        or not math.isfinite(float(rearmed_at))
                    )
                )
                or (bool(current_event_id) and rearmed_at is not None)
            ):
                raise RuntimeError("alert continuity snapshot is invalid")
            normalized.append(
                (
                    hex_id,
                    float(last_seen_at),
                    1 if current_event_id else 0,
                    json.dumps(sorted(required_bands), separators=(",", ":")),
                    None if rearmed_at is None else float(rearmed_at),
                )
            )
        with self._lock, self._connection:
            counts = self._connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM encounters) AS encounters,
                    (SELECT COUNT(*) FROM events) AS events,
                    (SELECT COUNT(*) FROM outbox) AS outbox
                """
            ).fetchone()
            # never merge backup continuity into live worker state
            if any(counts[key] for key in ("encounters", "events", "outbox")):
                return 0
            # restore no delivery payloads and no historical event rows
            for hex_id, last_seen_at, notified, required_bands_json, rearmed_at in normalized:
                self._connection.execute(
                    """
                    INSERT INTO encounters(
                        hex, last_seen_at, current_event_id, notified,
                        required_bands_json, label, categories_json, rearmed_at
                    ) VALUES(?, ?, NULL, ?, ?, ?, '[]', ?)
                    """,
                    (hex_id, last_seen_at, notified, required_bands_json, hex_id, rearmed_at),
                )
        return len(normalized)

    # ensure a bounded database before adding work
    def _has_capacity(self) -> bool:
        try:
            return not self.path.exists() or self.path.stat().st_size < MAX_DB_BYTES
        except OSError:
            return False

    # observe one fresh local aircraft counter progression atomically
    def observe_aircraft(
        self,
        *,
        hex_id: str,
        label: str,
        categories: tuple[str, ...],
        bands: set[str],
        observed_at: float,
        config_revision: int,
        enabled: bool,
        required_bands: set[str] | None = None,
        receptions: dict[str, str] | None = None,
    ) -> str | None:
        normalized = normalize_icao(hex_id)
        # reject non-catalog identities and unbounded input
        actual_required_bands = set(required_bands or bands)
        actual_receptions = receptions or {band: "direct" for band in bands}
        if (
            normalized is None
            or not bands
            or not bands.issubset({"1090", "978"})
            or not actual_required_bands
            or not actual_required_bands.issubset({"1090", "978"})
            or set(actual_receptions) != bands
            or any(value not in ("direct", "rebroadcast") for value in actual_receptions.values())
        ):
            raise ValueError("invalid aircraft observation")
        # refuse new durable work at the hard database limit
        if not self._has_capacity():
            raise RuntimeError("alert database capacity exceeded")
        categories_json = json.dumps(list(categories), separators=(",", ":"))
        with self._lock, self._connection:
            row = self._connection.execute("SELECT * FROM encounters WHERE hex=?", (normalized,)).fetchone()
            durable_required_bands = actual_required_bands
            current_event_id = None
            notified = False
            # retain every previously required reception band
            if row is not None:
                durable_required_bands.update(json.loads(row["required_bands_json"]))
                current_event_id = row["current_event_id"]
                notified = bool(row["notified"])
                self._connection.execute(
                    """
                    UPDATE encounters
                    SET last_seen_at=?, required_bands_json=?, label=?, categories_json=?, rearmed_at=NULL
                    WHERE hex=?
                    """,
                    (
                        observed_at,
                        json.dumps(sorted(durable_required_bands), separators=(",", ":")),
                        label[:120],
                        categories_json,
                        normalized,
                    ),
                )
            else:
                count = self._connection.execute("SELECT COUNT(*) FROM encounters").fetchone()[0]
                # refuse new identities without evicting required continuity
                if count >= MAX_ENCOUNTERS:
                    raise RuntimeError("alert encounter capacity exceeded")
                self._connection.execute(
                    """
                    INSERT INTO encounters(
                        hex, last_seen_at, current_event_id, notified,
                        required_bands_json, label, categories_json, rearmed_at
                    ) VALUES(?,?,?,0,?,?,?,NULL)
                    """,
                    (
                        normalized,
                        observed_at,
                        None,
                        json.dumps(sorted(durable_required_bands), separators=(",", ":")),
                        label[:120],
                        categories_json,
                    ),
                )
            # keep disabled, unknown, and already-notified encounters silent
            if not enabled or not categories or notified:
                return current_event_id
            pending_events = self._connection.execute(
                """
                SELECT COUNT(DISTINCT event_id) AS count
                FROM outbox WHERE state IN ('pending','retry','in_flight')
                """
            ).fetchone()["count"]
            # expose capacity loss without creating an undeliverable event
            if pending_events >= MAX_PENDING_EVENTS:
                row = self._connection.execute("SELECT value FROM meta WHERE key='capacity_rejections'").fetchone()
                count = 0 if row is None else int(row["value"])
                self._connection.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('capacity_rejections', ?)",
                    (str(count + 1),),
                )
                return None
            event_id = uuid.uuid4().hex
            deadline_at = observed_at + 300.0
            self._connection.execute(
                """
                INSERT INTO events(
                    id, kind, hex, label, categories_json, bands_json, receptions_json,
                    observed_at, created_at, config_revision, deadline_at
                ) VALUES(?, 'aircraft', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    normalized,
                    label[:120],
                    categories_json,
                    json.dumps(sorted(bands), separators=(",", ":")),
                    json.dumps(actual_receptions, separators=(",", ":"), sort_keys=True),
                    observed_at,
                    observed_at,
                    config_revision,
                    deadline_at,
                ),
            )
            # schedule both channels exactly once
            for channel in DELIVERY_CHANNELS:
                self._connection.execute(
                    """
                    INSERT INTO outbox(
                        event_id, channel, state, attempts, error_code, accepted_at,
                        next_attempt_at, deadline_at, config_revision, message_id, leased_at
                    ) VALUES(?, ?, 'pending', 0, NULL, NULL, ?, ?, ?, ?, NULL)
                    """,
                    (
                        event_id,
                        channel,
                        observed_at,
                        deadline_at,
                        config_revision,
                        f"<{event_id}.{channel}@adsb.ballydidean.farm>",
                    ),
                )
            self._connection.execute(
                "UPDATE encounters SET current_event_id=?, notified=1 WHERE hex=?", (event_id, normalized)
            )
            return event_id

    # list encounters that still require absence adjudication
    def active_encounters(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT hex, last_seen_at, current_event_id, notified, required_bands_json, rearmed_at
                FROM encounters LIMIT ?
                """,
                (MAX_ENCOUNTERS + 1,),
            ).fetchall()
        # fail observably rather than silently dropping continuity rows
        if len(rows) > MAX_ENCOUNTERS:
            raise RuntimeError("alert encounter capacity exceeded")
        return [
            {
                "hex": row["hex"],
                "last_seen_at": row["last_seen_at"],
                "current_event_id": row["current_event_id"],
                "notified": bool(row["notified"]),
                "required_bands": set(json.loads(row["required_bands_json"])),
                "rearmed_at": row["rearmed_at"],
            }
            for row in rows
        ]

    # persist a newly required receiver without weakening any prior obligation
    def add_required_band(self, band: str) -> None:
        # accept only fixed physical receiver names
        if band not in ("1090", "978"):
            raise ValueError("invalid required reception band")
        with self._lock, self._connection:
            encounters = self.active_encounters()
            # augment bounded continuity before any absence adjudication
            for encounter in encounters:
                required = encounter["required_bands"]
                # avoid rewriting unchanged durable requirements
                if band not in required:
                    required.add(band)
                    self._connection.execute(
                        "UPDATE encounters SET required_bands_json=? WHERE hex=?",
                        (json.dumps(sorted(required), separators=(",", ":")), encounter["hex"]),
                    )

    # finalize one continuously proven absence
    def mark_rearmed(self, hex_id: str, *, rearmed_at: float) -> bool:
        normalized = normalize_icao(hex_id)
        # reject invalid identities without touching state
        if normalized is None:
            return False
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE encounters
                SET current_event_id=NULL, notified=0, rearmed_at=?
                WHERE hex=? AND (notified=1 OR rearmed_at IS NULL)
                """,
                (rearmed_at, normalized),
            )
            return cursor.rowcount == 1

    # fence stale work and lease bounded due deliveries
    def claim_deliveries(
        self,
        *,
        now: float,
        config_revision: int,
        enabled: bool,
        limit: int = 10,
        channel: str | None = None,
    ) -> list[dict[str, Any]]:
        # bound sender queue growth
        if not isinstance(limit, int) or limit < 1 or limit > 50:
            raise ValueError("delivery claim limit must be between 1 and 50")
        # restrict optional claims to one fixed sender pool
        if channel is not None and channel not in DELIVERY_CHANNELS:
            raise ValueError("invalid delivery channel")
        with self._lock, self._connection:
            # expire every delivery beyond its event deadline
            self._connection.execute(
                """
                UPDATE outbox SET state='expired', error_code='delivery_deadline', leased_at=NULL
                WHERE state IN ('pending','retry') AND deadline_at <= ?
                """,
                (now,),
            )
            # never retarget unstarted work across configuration revisions
            self._connection.execute(
                """
                UPDATE outbox SET state='suppressed', error_code='configuration_changed', leased_at=NULL
                WHERE state IN ('pending','retry') AND config_revision != ?
                """,
                (config_revision,),
            )
            # suppress all unstarted work while disabled
            if not enabled:
                self._connection.execute(
                    """
                    UPDATE outbox SET state='suppressed', error_code='alerts_disabled', leased_at=NULL
                    WHERE state IN ('pending','retry')
                    """
                )
                return []
            channel_filter = "" if channel is None else "AND o.channel=?"
            parameters: list[Any] = [now, config_revision]
            # bind the fixed channel without interpolating it
            if channel is not None:
                parameters.append(channel)
            parameters.append(limit)
            rows = self._connection.execute(
                f"""
                SELECT
                    o.event_id, o.channel, o.attempts, o.deadline_at, o.config_revision, o.message_id,
                    e.kind, e.hex, e.label, e.categories_json, e.bands_json, e.receptions_json,
                    e.observed_at, e.created_at
                FROM outbox o
                JOIN events e ON e.id=o.event_id
                WHERE o.state IN ('pending','retry') AND o.next_attempt_at <= ? AND o.config_revision=?
                {channel_filter}
                ORDER BY CASE o.state WHEN 'pending' THEN 0 ELSE 1 END, e.created_at ASC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            claimed: list[dict[str, Any]] = []
            # lease each selected row within the same transaction
            for row in rows:
                cursor = self._connection.execute(
                    """
                    UPDATE outbox SET state='in_flight', attempts=attempts+1, leased_at=?
                    WHERE event_id=? AND channel=? AND state IN ('pending','retry')
                    """,
                    (now, row["event_id"], row["channel"]),
                )
                # project only successfully leased work
                if cursor.rowcount == 1:
                    claimed.append(
                        {
                            "event_id": row["event_id"],
                            "channel": row["channel"],
                            "attempt": row["attempts"] + 1,
                            "deadline_at": row["deadline_at"],
                            "config_revision": row["config_revision"],
                            "message_id": row["message_id"],
                            "kind": row["kind"],
                            "hex": row["hex"],
                            "label": row["label"],
                            "categories": json.loads(row["categories_json"]),
                            "bands": json.loads(row["bands_json"]),
                            "receptions": json.loads(row["receptions_json"]),
                            "observed_at": row["observed_at"],
                            "created_at": row["created_at"],
                        }
                    )
            return claimed

    # apply one external delivery result after network io completes
    def complete_delivery(
        self,
        event_id: str,
        channel: str,
        result: DeliveryResult,
        *,
        now: float,
    ) -> bool:
        # accept only known safe result states
        if channel not in DELIVERY_CHANNELS or result.state not in ("accepted", "retry", "failed", "unknown"):
            raise ValueError("invalid delivery result")
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT state, deadline_at, attempts FROM outbox WHERE event_id=? AND channel=?",
                (event_id, channel),
            ).fetchone()
            # ignore stale duplicate reports safely
            if row is None or row["state"] != "in_flight":
                return False
            state, error_code, accepted_at, next_attempt_at = _delivery_outcome(
                result, now=now, deadline=row["deadline_at"]
            )
            self._connection.execute(
                """
                UPDATE outbox
                SET state=?, error_code=?, accepted_at=?, next_attempt_at=?, leased_at=NULL
                WHERE event_id=? AND channel=?
                """,
                (state, error_code, accepted_at, next_attempt_at, event_id, channel),
            )
            return True

    # baseline old reports and enqueue each new maintenance result once
    def observe_maintenance(
        self,
        *,
        reported_at: float | None,
        now: float,
        config_revision: int,
        smtp_configured: bool,
        subject: str,
        body: str,
    ) -> str | None:
        # reject malformed clocks and oversized frozen messages
        if (
            not math.isfinite(now)
            or now <= 0
            or (reported_at is not None and (not math.isfinite(reported_at) or not 0 < reported_at <= now))
            or not isinstance(subject, str)
            or not 1 <= len(subject) <= 200
            or any(character in subject for character in "\r\n")
            or not isinstance(body, str)
            or len(body) > 8_192
        ):
            raise ValueError("invalid maintenance notification")
        with self._lock, self._connection:
            cursor = self._connection.execute("SELECT value FROM meta WHERE key='maintenance_report_seen'").fetchone()
            # first activation and restore never replay an existing review
            if cursor is None:
                self._connection.execute(
                    "INSERT INTO meta(key, value) VALUES('maintenance_report_seen', ?)",
                    (str(0 if reported_at is None else reported_at),),
                )
                return None
            # ignore missing, duplicate and older report generations
            if reported_at is None or reported_at <= float(cursor["value"]):
                return None
            self._connection.execute("UPDATE meta SET value=? WHERE key='maintenance_report_seen'", (str(reported_at),))
            # remember unconfigured runs without creating a later backlog
            if not smtp_configured:
                return None
            count = self._connection.execute("SELECT COUNT(*) FROM maintenance_notifications").fetchone()[0]
            # keep the additive queue bounded without changing aircraft state
            if count >= MAX_MAINTENANCE_NOTIFICATIONS or not self._has_capacity():
                raise RuntimeError("maintenance notification capacity exceeded")
            event_id = "maintenance-" + hashlib.sha256(str(reported_at).encode("ascii")).hexdigest()[:32]
            self._connection.execute(
                """
                INSERT INTO maintenance_notifications(
                    id, reported_at, subject, body, created_at, config_revision, state,
                    next_attempt_at, deadline_at, message_id
                ) VALUES(?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (
                    event_id,
                    reported_at,
                    subject,
                    body,
                    now,
                    config_revision,
                    now,
                    now + 300,
                    f"<{event_id}.email@adsb.ballydidean.farm>",
                ),
            )
            return event_id

    # lease maintenance emails independently of aircraft and pushover switches
    def claim_maintenance(
        self, *, now: float, config_revision: int, smtp_configured: bool, limit: int = 1
    ) -> list[dict[str, Any]]:
        # share the existing bounded email sender pool
        if type(limit) is not int or not 1 <= limit <= 2:
            raise ValueError("invalid maintenance claim limit")
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE maintenance_notifications SET state='expired', error_code='delivery_deadline' "
                "WHERE state IN ('pending','retry') AND deadline_at <= ?",
                (now,),
            )
            # never retarget a queued report after settings or credentials change
            self._connection.execute(
                "UPDATE maintenance_notifications SET state='suppressed', error_code='configuration_changed' "
                "WHERE state IN ('pending','retry') AND config_revision != ?",
                (config_revision,),
            )
            # incomplete smtp configuration must not send through stale destinations
            if not smtp_configured:
                self._connection.execute(
                    "UPDATE maintenance_notifications SET state='suppressed', error_code='smtp_not_configured' "
                    "WHERE state IN ('pending','retry')"
                )
                return []
            rows = self._connection.execute(
                "SELECT * FROM maintenance_notifications WHERE state IN ('pending','retry') "
                "AND next_attempt_at <= ? AND config_revision=? ORDER BY created_at ASC LIMIT ?",
                (now, config_revision, limit),
            ).fetchall()
            jobs = []
            # lease each immutable summary inside the single writer transaction
            for row in rows:
                self._connection.execute(
                    "UPDATE maintenance_notifications SET state='in_flight', attempts=attempts+1, leased_at=? "
                    "WHERE id=?",
                    (now, row["id"]),
                )
                jobs.append(
                    {
                        "event_id": row["id"],
                        "kind": "maintenance",
                        "channel": "email",
                        "attempt": row["attempts"] + 1,
                        "deadline_at": row["deadline_at"],
                        "message_id": row["message_id"],
                        "subject": row["subject"],
                        "body": row["body"],
                        "config_revision": row["config_revision"],
                    }
                )
            return jobs

    # persist one smtp-only maintenance outcome without touching aircraft outboxes
    def complete_maintenance(self, event_id: str, result: DeliveryResult, *, now: float) -> bool:
        # use only the transport's fixed safe result states
        if result.state not in ("accepted", "retry", "failed", "unknown"):
            raise ValueError("invalid maintenance delivery result")
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT state, deadline_at FROM maintenance_notifications WHERE id=?", (event_id,)
            ).fetchone()
            # ignore duplicate completion callbacks and interrupted leases
            if row is None or row["state"] != "in_flight":
                return False
            outcome = _delivery_outcome(result, now=now, deadline=row["deadline_at"])
            self._connection.execute(
                "UPDATE maintenance_notifications SET state=?, error_code=?, accepted_at=?, "
                "next_attempt_at=?, leased_at=NULL WHERE id=?",
                (*outcome, event_id),
            )
            return True

    # expose only the latest maintenance delivery outcome
    def maintenance_status(self) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT state, error_code, reported_at, accepted_at, next_attempt_at "
                "FROM maintenance_notifications ORDER BY created_at DESC, id DESC LIMIT 1"
            ).fetchone()
        # remain ready for a new report after baselining existing history
        if row is None:
            return {"state": "waiting", "error": None, "reported_at": None, "accepted_at": None, "retry_at": None}
        return {
            "state": row["state"],
            "error": row["error_code"],
            "reported_at": row["reported_at"],
            "accepted_at": row["accepted_at"],
            "retry_at": row["next_attempt_at"] if row["state"] == "retry" else None,
        }

    # durably acknowledge and optionally enqueue one fixed test request
    def acknowledge_test(
        self,
        request_id: str,
        *,
        config_revision: int,
        created_at: float,
        current_revision: int,
        enabled: bool,
        now: float,
    ) -> dict[str, Any]:
        # accept only canonical bounded request identifiers
        try:
            normalized_request_id = str(uuid.UUID(request_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("invalid test request id") from exc
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT * FROM test_ack WHERE request_id=?", (normalized_request_id,)
            ).fetchone()
            # preserve idempotent acknowledgement
            if existing is not None:
                return self.test_ack(normalized_request_id) or {}
            error_code = None
            # reject expired requests before any delivery work
            if now - created_at > 300 or created_at > now + 30:
                error_code = "test_request_expired"
            # reject stale destinations and secrets
            elif config_revision != current_revision:
                error_code = "configuration_changed"
            # require active complete settings as validated upstream
            elif not enabled:
                error_code = "alerts_disabled"
            # durably refuse invalid requests
            if error_code is not None:
                self._connection.execute(
                    """
                    INSERT INTO test_ack(request_id, config_revision, created_at, state, error_code, event_id)
                    VALUES(?, ?, ?, 'refused', ?, NULL)
                    """,
                    (normalized_request_id, config_revision, created_at, error_code),
                )
                return self.test_ack(normalized_request_id) or {}
            event_id = f"test-{normalized_request_id}"
            deadline_at = created_at + 300.0
            self._connection.execute(
                """
                INSERT INTO events(
                    id, kind, hex, label, categories_json, bands_json, receptions_json,
                    observed_at, created_at, config_revision, deadline_at
                ) VALUES(?, 'test', NULL, 'Notification test', '[]', '[]', '{}', ?, ?, ?, ?)
                """,
                (event_id, created_at, created_at, config_revision, deadline_at),
            )
            # queue one fixed test per channel
            for channel in DELIVERY_CHANNELS:
                self._connection.execute(
                    """
                    INSERT INTO outbox(
                        event_id, channel, state, attempts, error_code, accepted_at,
                        next_attempt_at, deadline_at, config_revision, message_id, leased_at
                    ) VALUES(?, ?, 'pending', 0, NULL, NULL, ?, ?, ?, ?, NULL)
                    """,
                    (
                        event_id,
                        channel,
                        now,
                        deadline_at,
                        config_revision,
                        f"<{event_id}.{channel}@adsb.ballydidean.farm>",
                    ),
                )
            self._connection.execute(
                """
                INSERT INTO test_ack(request_id, config_revision, created_at, state, error_code, event_id)
                VALUES(?, ?, ?, 'queued', NULL, ?)
                """,
                (normalized_request_id, config_revision, created_at, event_id),
            )
            return self.test_ack(normalized_request_id) or {}

    # project one safe test acknowledgement
    def test_ack(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute("SELECT * FROM test_ack WHERE request_id=?", (request_id,)).fetchone()
            # report an unknown request as absent
            if row is None:
                return None
            channels: dict[str, Any] = {}
            # include channel outcomes for a queued event
            if row["event_id"] is not None:
                channel_rows = self._connection.execute(
                    """
                    SELECT channel, state, attempts, error_code, accepted_at
                    FROM outbox WHERE event_id=?
                    """,
                    (row["event_id"],),
                ).fetchall()
                # project each safe delivery outcome
                for channel_row in channel_rows:
                    channels[channel_row["channel"]] = {
                        "state": channel_row["state"],
                        "attempts": channel_row["attempts"],
                        "error": channel_row["error_code"],
                        "accepted_at": channel_row["accepted_at"],
                    }
            state = row["state"]
            # derive a terminal acknowledgement when all deliveries stop
            if channels and all(value["state"] in TERMINAL_STATES for value in channels.values()):
                state = "terminal"
            return {
                "request_id": row["request_id"],
                "state": state,
                "error": row["error_code"],
                "event_id": row["event_id"],
                "created_at": row["created_at"],
                "channels": channels,
            }

    # return one indexed bounded history page
    def history(self, *, before: str | None = None, limit: int = 50) -> dict[str, Any]:
        with self._lock:
            return _history_query(self._connection, before, limit)

    # remove only events older than the promised retention window
    def purge_history(self, *, now: float, days: int = 30, batch: int = 500) -> int:
        # keep retention operations bounded and policy-fixed
        if days < 30 or batch < 1 or batch > 1_000:
            raise ValueError("invalid history retention bounds")
        cutoff = now - days * 86_400
        with self._lock, self._connection:
            rows = self._connection.execute(
                """
                SELECT id FROM events
                WHERE created_at < ?
                  AND id NOT IN (
                      SELECT current_event_id FROM encounters WHERE current_event_id IS NOT NULL
                  )
                ORDER BY created_at ASC LIMIT ?
                """,
                (cutoff, batch),
            ).fetchall()
            event_ids = [row["id"] for row in rows]
            # delete a bounded batch with cascading channel rows
            for event_id in event_ids:
                self._connection.execute("DELETE FROM events WHERE id=?", (event_id,))
            stale_encounters = self._connection.execute(
                """
                SELECT hex FROM encounters
                WHERE current_event_id IS NULL AND rearmed_at IS NOT NULL AND rearmed_at < ?
                ORDER BY rearmed_at ASC LIMIT ?
                """,
                (cutoff, batch),
            ).fetchall()
            # remove only identities already durably rearmed beyond retention
            for encounter in stale_encounters:
                self._connection.execute("DELETE FROM encounters WHERE hex=?", (encounter["hex"],))
            self._connection.execute("DELETE FROM test_ack WHERE created_at < ? AND event_id IS NULL", (cutoff,))
            # retain maintenance delivery outcomes under the same private history policy
            self._connection.execute(
                "DELETE FROM maintenance_notifications WHERE id IN "
                "(SELECT id FROM maintenance_notifications WHERE created_at < ? LIMIT ?)",
                (cutoff, batch),
            )
            return len(event_ids)

    # count safe delivery states for status projection
    def delivery_counts(self) -> dict[str, dict[str, int]]:
        result = {channel: {} for channel in DELIVERY_CHANNELS}
        with self._lock:
            rows = self._connection.execute(
                "SELECT channel, state, COUNT(*) AS count FROM outbox GROUP BY channel, state"
            ).fetchall()
        # group bounded enum-like state strings
        for row in rows:
            result[row["channel"]][row["state"]] = row["count"]
        return result

    # expose each latest durable channel outcome alongside retained counters
    def delivery_status(self) -> dict[str, dict[str, Any]]:
        result = self.delivery_counts()
        with self._lock:
            # read one bounded latest-event projection for each fixed channel
            for channel in DELIVERY_CHANNELS:
                row = self._connection.execute(
                    """
                    SELECT o.state, o.error_code, o.next_attempt_at
                    FROM events e JOIN outbox o ON o.event_id=e.id
                    WHERE o.channel=?
                    ORDER BY e.created_at DESC, e.id DESC LIMIT 1
                    """,
                    (channel,),
                ).fetchone()
                # retain a ready default before the first intentional send
                if row is None:
                    result[channel].update(state="ready", error=None)
                else:
                    result[channel].update(
                        state=row["state"],
                        error=row["error_code"],
                        retry_at=row["next_attempt_at"] if row["state"] == "retry" else None,
                    )
        return result

    # project the cumulative bounded-capacity rejection count
    def capacity_rejections(self) -> int:
        with self._lock:
            row = self._connection.execute("SELECT value FROM meta WHERE key='capacity_rejections'").fetchone()
        # preserve a zero default before any overload
        if row is None:
            return 0
        try:
            return max(0, int(row["value"]))
        except (TypeError, ValueError):
            return 0

    # retain an observable counter when bounded durable state refuses work
    def record_capacity_rejection(self) -> None:
        with self._lock, self._connection:
            row = self._connection.execute("SELECT value FROM meta WHERE key='capacity_rejections'").fetchone()
            count = 0 if row is None else int(row["value"])
            self._connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('capacity_rejections', ?)",
                (str(count + 1),),
            )

    # atomically publish bounded backup continuity without delivery payloads
    def write_continuity_snapshot(self, path: Path, *, generation: str, generated_at: float) -> None:
        encounters = self.active_encounters()
        value = {
            "schema_version": 1,
            "generation": generation[:100],
            "generated_at": generated_at,
            "encounters": [
                {
                    "hex": encounter["hex"],
                    "last_seen_at": encounter["last_seen_at"],
                    "current_event_id": encounter["current_event_id"]
                    or ("restored" if encounter["notified"] else None),
                    "required_bands": sorted(encounter["required_bands"]),
                    "rearmed_at": encounter["rearmed_at"],
                }
                for encounter in encounters
            ],
        }
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
        finally:
            # remove abandoned snapshot output
            if temporary_path.exists():
                temporary_path.unlink()


# read one test acknowledgement without obtaining write access
def read_test_ack(path: Path, request_id: str) -> dict[str, Any] | None:
    connection = _connect(path, readonly=True)
    try:
        row = connection.execute("SELECT * FROM test_ack WHERE request_id=?", (request_id,)).fetchone()
        # report absent ids safely
        if row is None:
            return None
        channels: dict[str, Any] = {}
        # project bounded event channels
        if row["event_id"] is not None:
            channel_rows = connection.execute(
                "SELECT channel, state, attempts, error_code, accepted_at FROM outbox WHERE event_id=?",
                (row["event_id"],),
            ).fetchall()
            # add each safe result
            for channel_row in channel_rows:
                channels[channel_row["channel"]] = {
                    "state": channel_row["state"],
                    "attempts": channel_row["attempts"],
                    "error": channel_row["error_code"],
                    "accepted_at": channel_row["accepted_at"],
                }
        state = row["state"]
        # project terminal state without mutating the database
        if channels and all(value["state"] in TERMINAL_STATES for value in channels.values()):
            state = "terminal"
        return {
            "request_id": row["request_id"],
            "state": state,
            "error": row["error_code"],
            "event_id": row["event_id"],
            "created_at": row["created_at"],
            "channels": channels,
        }
    finally:
        connection.close()
