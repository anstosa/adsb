"""Bounded physical-only source observations and finalized per-band coverage."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

AIRSPY_URL = "http://127.0.0.1:8079/stats.json"
UAT_URL = "http://127.0.0.1:8978/skyaware978/data/aircraft.json"
MAP_URL = "http://127.0.0.1:8078/data/aircraft.json"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ROWS = 10_000
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{6}$")
GENERATION_PATTERN = re.compile(r"^[0-9a-f-]{36}$")


# reject redirects from fixed receiver endpoints
class _NoRedirect(HTTPRedirectHandler):
    # leave redirects as transport failures
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


# validate a finite source number
def _number(value: Any) -> float:
    # reject booleans and invalid clocks
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("invalid source number")
    return float(value)


# validate bounded decoded counters
def _counter(value: Any) -> int:
    # reject floats and corrupted counters
    if type(value) is not int or not 0 <= value <= 10**15:
        raise ValueError("invalid source counter")
    return value


# read one regular private publication without following a file symlink
def read_json(path: Path, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        # reject devices, pipes and oversized files before reading
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("invalid source publication")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(maximum + 1)
        # bound raced file growth
        if len(content) > maximum:
            raise ValueError("oversized source publication")
        try:
            value = json.loads(content)
        except RecursionError as error:
            raise ValueError("invalid nested source publication") from error
        # require structured source data
        if not isinstance(value, dict):
            raise ValueError("invalid source publication")
        return value
    finally:
        os.close(descriptor)


# fetch only the existing fixed local receiver endpoints
def fetch_json(url: str) -> dict[str, Any]:
    # prevent arbitrary endpoint and proxy selection
    if url != MAP_URL:
        raise ValueError("invalid source endpoint")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(url, timeout=0.35) as response:
        content = response.read(MAX_JSON_BYTES + 1)
    # bound transport output before parsing
    if len(content) > MAX_JSON_BYTES:
        raise ValueError("oversized source response")
    value = json.loads(content)
    # require one source object
    if not isinstance(value, dict):
        raise ValueError("invalid source response")
    return value


# normalize a controller timestamp
def _timestamp(value: Any) -> float:
    # accept the fixed controller utc string schema
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid source timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # require an explicit timezone
    if parsed.tzinfo is None:
        raise ValueError("invalid source timestamp")
    return parsed.timestamp()


# require fresh source clocks without tolerating future replay
def _fresh(timestamp: float, now: float, maximum: float) -> None:
    # reject stale, future and invalid publications
    if timestamp <= 0 or not -1 <= now - timestamp <= maximum:
        raise ValueError("stale source publication")


# observe one physical-only tracked aircraft schema
def normalize_aircraft(payload: dict[str, Any], *, now: float, band: str = "1090") -> list[dict[str, Any]]:
    timestamp = _number(payload.get("now"))
    _fresh(timestamp, now, 5)
    _counter(payload.get("messages"))
    rows = payload.get("aircraft")
    # require a bounded tracked view
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("invalid aircraft collection")
    normalized = []
    identities = set()
    # accept only real icao identities with current local counters
    for row in rows:
        # malformed entries invalidate the source rather than prove absence
        if not isinstance(row, dict):
            raise ValueError("invalid aircraft row")
        hex_id = row.get("hex")
        # exclude non-icao identities and mlat or network-only source types
        if (
            not isinstance(hex_id, str)
            or HEX_PATTERN.fullmatch(hex_id) is None
            or row.get("type") in ("mlat", "adsc", "tisb_trackfile", "adsb_other", "adsr_other", "tisb_other")
        ):
            continue
        hex_id = hex_id.upper()
        # avoid ambiguous duplicate identity rows
        if hex_id in identities:
            raise ValueError("duplicate source identity")
        identities.add(hex_id)
        messages = _counter(row.get("messages"))
        seen = _number(row.get("seen"))
        # reject malformed ages without requiring a position
        if seen < 0 or seen > 3600:
            raise ValueError("invalid source age")
        normalized.append(
            {
                "hex": hex_id,
                "messages": messages,
                "seen": seen,
                "observed_at": timestamp - seen - 0.1,
                "last_observed_at": min(now, timestamp - seen + 1.1),
                "reception": "rebroadcast"
                if row.get("type") == "tisb_icao" or (band == "1090" and row.get("type") == "adsr_icao")
                else "direct",
            }
        )
    return normalized


# maintain independent finalized coverage for each selected receiver
class AlertSourceMonitor:
    # bind the adapter to the release manifest and private publications
    def __init__(
        self,
        *,
        root: Path = Path("/var/lib/adsb"),
        manifest_path: Path = Path("/opt/adsb/current/deploy/alerts/source-contract.json"),
        fetcher: Callable[[str], dict[str, Any]] = fetch_json,
    ) -> None:
        from .controller import validate_source_contract

        self.root = root
        self.manifest = validate_source_contract(read_json(manifest_path, 8192))
        # do not silently activate an unproven source adapter
        if any(source["mode"] != "readsb" for source in self.manifest["sources"].values()):
            raise ValueError("source adapter was not selected by the release")
        self.fetcher = fetcher
        self.activation_id = ""
        self.contract_digest = ""
        self._states: dict[str, dict[str, Any]] = {}
        self._bands: dict[str, dict[str, Any]] = {}
        self._last_poll: tuple[float, float] | None = None

    # reset only one receiver's proof and progression baseline
    def _invalidate(self, band: str, now_mono: float) -> dict[str, Any]:
        self._states.pop(band, None)
        self._bands[band] = {"state": "unknown", "last_message_at": None}
        return {
            "band": band,
            "generation": "unknown",
            "healthy": False,
            "coverage_state": "unknown",
            "coverage_since": now_mono,
            "coverage_until": now_mono,
            "aircraft": [],
        }

    # inspect one fixed source generation and its decoded progression
    def _observe(self, band: str, expected: dict[str, Any], now_wall: float, now_mono: float) -> dict[str, Any]:
        directory = self.root / "alert-source" / band
        # reject a replaced publication directory
        if directory.is_symlink():
            raise ValueError("invalid source directory")
        marker = read_json(directory / "source-marker.json", 8192)
        source_state = read_json(directory / "source-state.json", 8192)
        generation = marker.get("generation")
        # bind both publications to the controller's selected immutable activation
        for value in (marker, source_state):
            # reject missing or mismatched provenance
            if (
                value.get("schema_version") != (1 if value is marker else 2)
                or value.get("band") != band
                or value.get("generation") != generation
                or value.get("activation_id") != self.activation_id
                or value.get("contract_digest") != self.contract_digest
            ):
                raise ValueError("source provenance mismatch")
        # require current process and fixed-input connection evidence
        if (
            not isinstance(generation, str)
            or GENERATION_PATTERN.fullmatch(generation) is None
            or expected.get("generation") != generation
            or expected.get("state") != "ready"
            or source_state.get("process_running") is not True
            or source_state.get("input_connected") is not True
        ):
            raise ValueError("source unavailable")
        input_time = _timestamp(source_state.get("sampled_at"))
        _fresh(input_time, now_wall, 7)
        input_bytes = _counter(source_state.get("input_bytes"))
        input_socket = source_state.get("input_socket")
        # require the independently observed kernel socket identity
        if not isinstance(input_socket, str) or not input_socket.isdigit() or len(input_socket) > 32:
            raise ValueError("invalid input socket")
        started_at = _timestamp(marker.get("started_at"))
        payload = read_json(directory / "aircraft.json")
        rows = normalize_aircraft(payload, now=now_wall, band=band)
        stats = read_json(directory / "stats.json", 128 * 1024)
        total = stats.get("total")
        # require the pinned cumulative accepted-message schema
        if not isinstance(total, dict) or not isinstance(total.get("remote"), dict):
            raise ValueError("invalid decoder stats")
        start = _number(total.get("start"))
        end = _number(total.get("end"))
        accepted = total["remote"].get("accepted")
        # reject old-generation files and invalid decoder counters
        if start < started_at or end < start or not isinstance(accepted, list) or len(accepted) != 2:
            raise ValueError("invalid decoder generation")
        _fresh(end, now_wall, 20)
        accepted_count = sum(_counter(value) for value in accepted)
        aircraft_count = _counter(payload.get("messages"))
        source_time = _number(payload.get("now"))
        # reject mixed old aircraft and new stats generations
        if source_time < start or end > source_time + 1:
            raise ValueError("mixed source generation")
        previous = self._states.get(band)
        # establish a conservative initial generation baseline without history replay
        if previous is None or previous["generation"] != generation or previous["start"] != start:
            previous = {
                "generation": generation,
                "start": start,
                "since": now_mono,
                "until": now_mono,
                "end": end,
                "accepted": accepted_count,
                "aircraft_count": aircraft_count,
                "source_time": source_time,
                "input_time": input_time,
                "input_bytes": input_bytes,
                "input_socket": input_socket,
                "kernel_intervals": [],
                "periods": [],
                "tracks": {row["hex"]: row["messages"] for row in rows},
            }
            self._states[band] = previous
            fresh_rows: list[dict[str, Any]] = []
        else:
            # reset on counter rollback or backwards source clocks
            if (
                accepted_count < previous["accepted"]
                or aircraft_count < previous["aircraft_count"]
                or source_time < previous["source_time"]
                or end < previous["end"]
                or input_time < previous["input_time"]
                or input_bytes < previous["input_bytes"]
                or input_socket != previous["input_socket"]
            ):
                raise ValueError("source counter or socket reset")
            # bracket decoded periods with independent stable-socket kernel samples
            if input_time > previous["input_time"]:
                # an unobserved connector interval cannot certify absence
                if input_time - previous["input_time"] > 7:
                    raise ValueError("input observation gap")
                previous["kernel_intervals"].append(
                    (previous["input_time"], input_time, input_bytes - previous["input_bytes"])
                )
                previous["input_time"] = input_time
                previous["input_bytes"] = input_bytes
            # retain a bounded pending finalized decoder period
            if end > previous["end"]:
                # reject missing decoder publication windows
                if end - previous["end"] > 15:
                    raise ValueError("decoder observation gap")
                since_wall = now_wall - (now_mono - previous["since"])
                # discard the partial startup window rather than assuming pre-boot coverage
                if previous["end"] < since_wall:
                    previous["since"] = max(previous["since"], now_mono - (now_wall - end))
                    previous["until"] = previous["since"]
                else:
                    previous["periods"].append((previous["end"], end, accepted_count > previous["accepted"]))
                previous["end"] = end
                previous["accepted"] = accepted_count
            # finalize only after kernel observations bracket the complete decoder window
            while previous["periods"]:
                period_start, period_end, decoded_progress = previous["periods"][0]
                intervals = [
                    interval
                    for interval in previous["kernel_intervals"]
                    if interval[0] < period_end and interval[1] > period_start
                ]
                bracketed = bool(intervals) and intervals[0][0] <= period_start and intervals[-1][1] >= period_end
                # late or missing independent evidence resets continuity within the twenty-second budget
                if not bracketed:
                    if now_wall - period_end > 7:
                        raise ValueError("input coverage bracket missing")
                    break
                # bytes alone never prove valid decoding of an active input
                if not decoded_progress and any(interval[2] > 0 for interval in intervals):
                    raise ValueError("source input stalled")
                previous["until"] = max(previous["since"], now_mono - max(0.0, now_wall - period_end))
                previous["periods"].pop(0)
            # retain only enough kernel history to bracket bounded pending windows
            cutoff = previous["periods"][0][0] if previous["periods"] else previous["end"]
            previous["kernel_intervals"] = [
                interval for interval in previous["kernel_intervals"] if interval[1] >= cutoff
            ]
            fresh_rows = []
            tracks = {}
            # advance observations only from fresh real decoded-message progression
            for row in rows:
                old_count = previous["tracks"].get(row["hex"])
                tracks[row["hex"]] = row["messages"]
                # reject per-track resets as an absence-proof discontinuity
                if old_count is not None and row["messages"] < old_count:
                    raise ValueError("aircraft counter reset")
                # permit first tracked rows after the initial snapshot but never aged rows
                if row["seen"] <= 5 and row["messages"] >= 2 and (old_count is None or row["messages"] > old_count):
                    fresh_rows.append({**row, "fresh": True, "bands": [band]})
            previous.update(
                tracks=tracks,
                aircraft_count=aircraft_count,
                source_time=source_time,
            )
        last_message = self._bands.get(band, {}).get("last_message_at")
        # record only actual local decoded observations
        if fresh_rows:
            last_message = max(row["observed_at"] for row in fresh_rows)
        self._bands[band] = {"state": "healthy", "generation": generation, "last_message_at": last_message}
        return {
            "band": band,
            "generation": generation,
            "observed_at": now_wall,
            "expected": True,
            "healthy": True,
            "coverage_state": "healthy",
            "coverage_since": previous["since"],
            "coverage_until": min(now_mono, previous["until"]),
            "aircraft": fresh_rows,
        }

    # collect bounded independent samples without exposing private runtime configuration
    def poll(self, *, now_wall: float | None = None, now_mono: float | None = None) -> list[dict[str, Any]]:
        wall = time.time() if now_wall is None else now_wall
        mono = time.monotonic() if now_mono is None else now_mono
        # discard continuity across poll gaps or wall-clock adjustments
        if self._last_poll is not None:
            old_wall, old_mono = self._last_poll
            # require continuous monotonic polling and a stable wall mapping
            if not 0 <= mono - old_mono <= 3 or abs((wall - old_wall) - (mono - old_mono)) > 2:
                self._states.clear()
        self._last_poll = (wall, mono)
        try:
            controller = read_json(self.root / "status/status.json", 256 * 1024)
            _fresh(_timestamp(controller.get("updated_at")), wall, 30)
            alerts = controller.get("alerts")
            # require the exact controller activation projection
            if (
                not isinstance(alerts, dict)
                or alerts.get("activation_id") != controller.get("activation_id")
                or re.fullmatch(r"[0-9a-f]{32}", str(alerts.get("activation_id"))) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(alerts.get("source_contract_digest"))) is None
                or not isinstance(alerts.get("expected_bands"), list)
                or any(band not in ("1090", "978") for band in alerts["expected_bands"])
                or not isinstance(alerts.get("sources"), dict)
            ):
                raise ValueError("invalid controller source contract")
            identity = (alerts["activation_id"], alerts["source_contract_digest"])
            # invalidate all prior generations after immutable activation changes
            if identity != (self.activation_id, self.contract_digest):
                self._states.clear()
            self.activation_id, self.contract_digest = identity
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            return [self._invalidate(band, mono) for band in ("1090", "978")]
        samples = []
        # keep removed bands explicitly unknown so persisted obligations cannot shrink
        for band in ("1090", "978"):
            expected = alerts["sources"].get(band)
            # absent hardware cannot prove an encounter's required absence
            if band not in alerts["expected_bands"] or not isinstance(expected, dict):
                samples.append({**self._invalidate(band, mono), "expected": False})
                self._bands[band]["state"] = "absent"
                continue
            try:
                samples.append(self._observe(band, expected, wall, mono))
            except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
                samples.append({**self._invalidate(band, mono), "expected": True})
        candidates = {row["hex"]: row for sample in samples for row in sample["aircraft"]}
        # enrich only already-proven physical sightings from the optional pinned map database
        if candidates:
            try:
                enrichment = self.fetcher(MAP_URL)
                _fresh(_number(enrichment.get("now")), wall, 5)
                metadata = enrichment.get("aircraft")
                # bound the optional map join without treating it as a reception source
                if not isinstance(metadata, list) or len(metadata) > MAX_ROWS:
                    raise ValueError("invalid enrichment")
                flags = {}
                # join only strict known bitfields to physical identities
                for row in metadata:
                    if not isinstance(row, dict) or not isinstance(row.get("hex"), str):
                        continue
                    hex_id = row["hex"].upper()
                    value = row.get("dbFlags")
                    # ignore malformed or unverified integer flag shapes
                    if hex_id in candidates and type(value) is int and 0 <= value <= 127:
                        flags[hex_id] = value
                # apply classification-only data to every overlap observation
                for sample in samples:
                    for row in sample["aircraft"]:
                        if row["hex"] in flags:
                            row["dbFlags"] = flags[row["hex"]]
            except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
                pass
        return samples

    # project only bounded nonsecret worker source status
    def status(self) -> dict[str, Any]:
        return {
            "activation_id": self.activation_id,
            "source_contract_digest": self.contract_digest,
            "bands": dict(self._bands),
        }

    # retain the lifecycle interface without owning sockets or subprocesses
    def close(self) -> None:
        return
