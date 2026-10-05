"""Bounded reception telemetry for locally attached ADS-B radios."""

from __future__ import annotations

import json
import math
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

AIRSPY_STATS_URL = "http://127.0.0.1:8079/stats.json"
UAT_AIRCRAFT_URL = "http://127.0.0.1:8978/skyaware978/data/aircraft.json"
AIRSPY_DF_TYPES = (0, 4, 5, 11, 16, 17, 18, 19, 20, 21)
MAX_TELEMETRY_BYTES = 64 * 1024
MAX_SAMPLE_AGE_SECONDS = 180
MAX_FUTURE_SKEW_SECONDS = 30
MAX_MESSAGES_PER_MINUTE = 10_000_000
MAX_SOURCE_COUNTER = 10**15


# format one source timestamp as utc
def _utc_timestamp(value: float) -> str | None:
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError):
        return None


# read one fixed local telemetry document
def fetch_json(url: str) -> Any | None:
    try:
        with urlopen(url, timeout=2) as response:
            content = response.read(MAX_TELEMETRY_BYTES + 1)
    except (OSError, URLError):
        return None
    # reject oversized telemetry before parsing
    if len(content) > MAX_TELEMETRY_BYTES:
        return None
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None


# validate one embedded telemetry timestamp
def _sample_timestamp(payload: Any, observed_at: float) -> tuple[float | None, str]:
    # require a structured source document
    if not isinstance(payload, dict):
        return None, "unavailable"
    value = payload.get("now")
    # require a finite positive unix timestamp
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, "unavailable"
    timestamp = float(value)
    # reject invalid source clocks
    if not math.isfinite(timestamp) or timestamp <= 0:
        return None, "unavailable"
    age = observed_at - timestamp
    # separate stale source output from malformed telemetry
    if age > MAX_SAMPLE_AGE_SECONDS or age < -MAX_FUTURE_SKEW_SECONDS:
        return timestamp, "stale"
    return timestamp, "current"


# build one source status without claiming reception
def _source_status(hardware_present: bool, service_running: bool, last_activity_at: str | None) -> dict[str, Any]:
    state = "absent" if not hardware_present else "stopped" if not service_running else "unavailable"
    return {
        "hardware_present": hardware_present,
        "service_running": service_running,
        "telemetry_state": state,
        "messages_per_minute": None,
        "last_activity_at": last_activity_at,
        "sample_at": None,
    }


# track source counters without conflating fresh json with radio activity
class ReceptionMonitor:
    # initialize process-local observations
    def __init__(self) -> None:
        self._uat_previous: tuple[float, int] | None = None
        self._last_activity: dict[str, str | None] = {"1090": None, "978": None}

    # collect only fixed loopback telemetry endpoints
    def collect(self, hardware: dict[str, Any], running: set[str], *, now: float | None = None) -> dict[str, Any]:
        observed_at = time.time() if now is None else now
        airspy_payload = fetch_json(AIRSPY_STATS_URL) if hardware.get("airspy") and "airspy" in running else None
        uat_payload = fetch_json(UAT_AIRCRAFT_URL) if hardware.get("uat") and "dump978" in running else None
        return self.observe(hardware, running, airspy_payload, uat_payload, now=observed_at)

    # convert source documents into bounded operational status
    def observe(
        self,
        hardware: dict[str, Any],
        running: set[str],
        airspy_payload: Any,
        uat_payload: Any,
        *,
        now: float,
    ) -> dict[str, Any]:
        return {
            "1090": self._observe_airspy(bool(hardware.get("airspy")), "airspy" in running, airspy_payload, now),
            "978": self._observe_uat(bool(hardware.get("uat")), "dump978" in running, uat_payload, now),
        }

    # interpret Airspy's one-minute df counters
    def _observe_airspy(
        self,
        hardware_present: bool,
        service_running: bool,
        payload: Any,
        observed_at: float,
    ) -> dict[str, Any]:
        result = _source_status(hardware_present, service_running, self._last_activity["1090"])
        # skip telemetry when the receiver is not active
        if not hardware_present or not service_running:
            return result
        sample_time, freshness = _sample_timestamp(payload, observed_at)
        # retain stale source time without treating it as reception
        if freshness == "stale":
            result["telemetry_state"] = "stale"
            result["sample_at"] = _utc_timestamp(sample_time) if sample_time is not None else None
            return result
        # reject missing or malformed source time
        if freshness != "current" or sample_time is None:
            return result
        counts = payload.get("df_counts")
        # require Airspy's indexed df counter array
        if not isinstance(counts, list) or len(counts) <= max(AIRSPY_DF_TYPES):
            return result
        selected: list[float] = []
        # validate only supported Mode-S downlink formats
        for frame_type in AIRSPY_DF_TYPES:
            count = counts[frame_type]
            # reject invalid counters instead of manufacturing a rate
            if isinstance(count, bool) or not isinstance(count, (int, float)):
                return result
            number = float(count)
            # bound the one-minute counter set
            if not math.isfinite(number) or number < 0 or number > MAX_MESSAGES_PER_MINUTE:
                return result
            selected.append(number)
        messages_per_minute = sum(selected)
        # reject an implausible aggregate independently
        if messages_per_minute > MAX_MESSAGES_PER_MINUTE:
            return result
        result["sample_at"] = _utc_timestamp(sample_time)
        # reject timestamps outside the host datetime range
        if result["sample_at"] is None:
            result["telemetry_state"] = "unavailable"
            result["messages_per_minute"] = None
            return result
        result["messages_per_minute"] = round(messages_per_minute, 1)
        result["telemetry_state"] = "receiving" if messages_per_minute > 0 else "quiet"
        # update activity only from a positive radio counter
        if messages_per_minute > 0:
            self._last_activity["1090"] = result["sample_at"]
            result["last_activity_at"] = result["sample_at"]
        return result

    # derive UAT rate from its cumulative receiver counter
    def _observe_uat(
        self,
        hardware_present: bool,
        service_running: bool,
        payload: Any,
        observed_at: float,
    ) -> dict[str, Any]:
        result = _source_status(hardware_present, service_running, self._last_activity["978"])
        # skip telemetry when the receiver is not active
        if not hardware_present or not service_running:
            self._uat_previous = None
            return result
        sample_time, freshness = _sample_timestamp(payload, observed_at)
        # retain stale source time without treating it as reception
        if freshness == "stale":
            self._uat_previous = None
            result["telemetry_state"] = "stale"
            result["sample_at"] = _utc_timestamp(sample_time) if sample_time is not None else None
            return result
        # reject missing or malformed source time
        if freshness != "current" or sample_time is None:
            self._uat_previous = None
            return result
        counter = payload.get("messages")
        # require dump978's bounded cumulative message counter
        if isinstance(counter, bool) or not isinstance(counter, int) or not 0 <= counter <= MAX_SOURCE_COUNTER:
            self._uat_previous = None
            return result
        result["sample_at"] = _utc_timestamp(sample_time)
        # reject timestamps outside the host datetime range
        if result["sample_at"] is None:
            self._uat_previous = None
            return result
        previous = self._uat_previous
        self._uat_previous = (sample_time, counter)
        # distinguish a first sample from confirmed quiet traffic
        if previous is None:
            result["telemetry_state"] = "quiet" if counter == 0 else "monitoring"
            return result
        previous_time, previous_counter = previous
        elapsed = sample_time - previous_time
        # wait for an advancing source clock
        if elapsed <= 0:
            result["telemetry_state"] = "monitoring"
            return result
        # rebaseline after sampling gaps instead of averaging old activity
        if elapsed > MAX_SAMPLE_AGE_SECONDS:
            result["telemetry_state"] = "monitoring"
            return result
        # restart rate calculation after a decoder counter reset
        if counter < previous_counter:
            result["telemetry_state"] = "monitoring"
            return result
        messages_per_minute = (counter - previous_counter) * 60 / elapsed
        # reject corrupted jumps without losing future baseline samples
        if not math.isfinite(messages_per_minute) or messages_per_minute > MAX_MESSAGES_PER_MINUTE:
            return result
        result["messages_per_minute"] = round(messages_per_minute, 1)
        result["telemetry_state"] = "receiving" if counter > previous_counter else "quiet"
        # update activity only when the decoder counter advances
        if counter > previous_counter:
            self._last_activity["978"] = result["sample_at"]
            result["last_activity_at"] = result["sample_at"]
        return result
