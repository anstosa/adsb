"""Bounded physical-only source observations and finalized per-band coverage."""

from __future__ import annotations

import gzip
import io
import json
import math
import os
import re
import stat
import time
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from adsb_admin.alert_catalog import normalize_aircraft_model

AIRSPY_URL = "http://127.0.0.1:8079/stats.json"
UAT_URL = "http://127.0.0.1:8978/skyaware978/data/aircraft.json"
MAP_URL = "http://127.0.0.1:8078/data/aircraft.json"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_DATABASE_COMPRESSED_BYTES = 256 * 1024
MAX_DATABASE_PAGES = 32
MAX_DATABASE_MODELS = 4096
MAX_DATABASE_FETCHES = 4
MAX_AIRCRAFT_METADATA = 4096
MAX_OPERATOR_PREFIXES = 7000
MAX_TYPE_NAMES = 4000
MAX_ROWS = 10_000
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{6}$")
DATABASE_DIRECTORY_PATTERN = re.compile(r"^db-[0-9]+(?:\.[0-9]+){2}$")
DATABASE_PREFIX_PATTERN = re.compile(r"^[0-9A-F]{1,6}$")
DATABASE_METADATA_ROUTES = frozenset(("icao_aircraft_types2", "operators"))
OPERATOR_PREFIX_PATTERN = re.compile(r"^[A-Z]{3}$")
REGISTRATION_PATTERN = re.compile(r"^[A-Z0-9+-]{1,20}$")
GENERATION_PATTERN = re.compile(r"^[0-9a-f-]{36}$")
RELEASE_ROOT = Path(__file__).resolve().parents[1]
MAP_UI_MANIFEST_PATH = RELEASE_ROOT / "deploy/map-ui.json"
EARTH_RADIUS_MI = 3958.7613


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


# load the release-pinned local aircraft database directory
def load_database_directory(manifest_path: Path = MAP_UI_MANIFEST_PATH) -> str:
    manifest = read_json(manifest_path, 64 * 1024)
    dependency = manifest.get("base_image_dependency")
    version = manifest.get("databaseVersion")
    # bind the route to the immutable release manifest
    if (
        manifest.get("schema_version") != 1
        or not isinstance(dependency, dict)
        or not isinstance(version, str)
        or dependency.get("database_directory") != f"db-{version}"
        or DATABASE_DIRECTORY_PATTERN.fullmatch(dependency.get("database_directory", "")) is None
    ):
        raise ValueError("invalid map database manifest")
    return dependency["database_directory"]


# fetch one bounded gzip or json page from the fixed local map endpoint
def fetch_database_json(url: str, database_directory: str) -> dict[str, Any]:
    # reject caller-controlled directory shapes before constructing the route
    if DATABASE_DIRECTORY_PATTERN.fullmatch(database_directory) is None:
        raise ValueError("invalid database directory")
    base_url = f"http://127.0.0.1:8078/{database_directory}/"
    suffix = url.removeprefix(base_url).removesuffix(".js")
    # prevent alternate hosts, paths and encoded traversal
    if (
        url != f"{base_url}{suffix}.js"
        or DATABASE_PREFIX_PATTERN.fullmatch(suffix) is None
        and suffix not in DATABASE_METADATA_ROUTES
    ):
        raise ValueError("invalid database endpoint")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(url, timeout=0.35) as response:
        content = response.read(MAX_DATABASE_COMPRESSED_BYTES + 1)
    # bound the on-wire database page
    if len(content) > MAX_DATABASE_COMPRESSED_BYTES:
        raise ValueError("oversized database response")
    try:
        # decode only the database's native gzip representation
        if content.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream:
                decoded = stream.read(MAX_JSON_BYTES + 1)
        else:
            decoded = content
    except (EOFError, OSError) as error:
        raise ValueError("invalid database compression") from error
    # cap decompression using the existing native-json ceiling
    if len(decoded) > MAX_JSON_BYTES:
        raise ValueError("oversized database document")
    try:
        value = json.loads(decoded)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid database response") from error
    # require one static database page
    if not isinstance(value, dict):
        raise ValueError("invalid database response")
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


# accept one optional finite number inside a closed interval
def _optional_number(value: Any, lower: float, upper: float) -> float | None:
    # discard malformed telemetry without invalidating physical reception
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    number = float(value)
    # keep downstream fields inside their documented physical bounds
    if number < lower or number > upper:
        return None
    return number


# accept one bounded printable metadata string
def _optional_text(value: Any, maximum: int = 120) -> str | None:
    # discard nontext and control-bearing metadata
    if not isinstance(value, str) or len(value) > maximum or any(ord(character) < 32 for character in value):
        return None
    normalized = value.strip()
    return normalized or None


# normalize one registration for callsign safety comparisons
def _registration(value: Any) -> str | None:
    text = _optional_text(value, 20)
    # accept only the pinned database registration alphabet
    if text is None or REGISTRATION_PATTERN.fullmatch(text.upper()) is None:
        return None
    return text.upper()


# retain one bounded physical decoder callsign for later operator lookup
def _flight(value: Any) -> str | None:
    text = _optional_text(value, 32)
    return text.upper() if text is not None else None


# calculate one great-circle distance in statute miles
def _distance_mi(latitude: float, longitude: float, station: tuple[float, float]) -> float:
    station_latitude, station_longitude = station
    latitude_delta = math.radians(latitude - station_latitude)
    longitude_delta = math.radians(longitude - station_longitude)
    origin = math.radians(station_latitude)
    destination = math.radians(latitude)
    haversine = (
        math.sin(latitude_delta / 2) ** 2
        + math.cos(origin) * math.cos(destination) * math.sin(longitude_delta / 2) ** 2
    )
    return 2 * EARTH_RADIUS_MI * math.asin(math.sqrt(min(1.0, haversine)))


# attach bounded current telemetry without changing reception validity
def _attach_telemetry(
    normalized: dict[str, Any],
    row: dict[str, Any],
    *,
    timestamp: float,
    now: float,
    station: tuple[float, float] | None,
) -> None:
    normalized["location_center"] = station
    speed = _optional_number(row.get("gs"), 0, 2_000)
    # retain only a plausible ground-speed measurement
    if speed is not None:
        normalized["speed_knots"] = speed
    heading = _optional_number(row.get("track"), 0, 360)
    # normalize the equivalent full-turn bearing to north
    if heading is not None:
        normalized["heading_degrees"] = heading % 360
    normalized["on_ground"] = row.get("alt_baro") == "ground"
    altitude = _optional_number(row.get("alt_baro"), -10_000, 100_000)
    # fall back to geometric altitude when barometric altitude is absent
    if altitude is None:
        altitude = _optional_number(row.get("alt_geom"), -10_000, 100_000)
    # retain only one defensively bounded altitude
    if altitude is not None:
        normalized["altitude_feet"] = altitude
    flight = _flight(row.get("flight"))
    # retain callsigns only from the physical decoder row
    if flight is not None:
        normalized["_flight"] = flight
    latitude = _optional_number(row.get("lat"), -90, 90)
    longitude = _optional_number(row.get("lon"), -180, 180)
    seen_position = _optional_number(row.get("seen_pos"), 0, 5)
    mlat_fields = row.get("mlat", [])
    mlat_position = (
        not isinstance(mlat_fields, list)
        or any(not isinstance(field, str) for field in mlat_fields)
        or "lat" in mlat_fields
        or "lon" in mlat_fields
    )
    # use only fresh decoder coordinates that are not derived from mlat
    if (
        station is not None
        and latitude is not None
        and longitude is not None
        and seen_position is not None
        and not mlat_position
    ):
        normalized["latitude"] = latitude
        normalized["longitude"] = longitude
        normalized["distance_mi"] = _distance_mi(latitude, longitude, station)
        normalized["position_observed_at"] = min(now, timestamp - seen_position)


# observe one physical-only tracked aircraft schema
def normalize_aircraft(
    payload: dict[str, Any],
    *,
    now: float,
    band: str = "1090",
    station: tuple[float, float] | None = None,
) -> list[dict[str, Any]]:
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
        aircraft = {
            "hex": hex_id,
            "messages": messages,
            "seen": seen,
            "observed_at": timestamp - seen - 0.1,
            "last_observed_at": min(now, timestamp - seen + 1.1),
            "reception": "rebroadcast"
            if row.get("type") == "tisb_icao" or (band == "1090" and row.get("type") == "adsr_icao")
            else "direct",
        }
        _attach_telemetry(aircraft, row, timestamp=timestamp, now=now, station=station)
        normalized.append(aircraft)
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
        database_fetcher: Callable[[str], dict[str, Any]] | None = None,
        metadata_fetcher: Callable[[str], dict[str, Any]] | None = None,
        map_manifest_path: Path = MAP_UI_MANIFEST_PATH,
    ) -> None:
        from .controller import validate_source_contract

        self.root = root
        self.manifest = validate_source_contract(read_json(manifest_path, 8192))
        # do not silently activate an unproven source adapter
        if any(source["mode"] != "readsb" for source in self.manifest["sources"].values()):
            raise ValueError("source adapter was not selected by the release")
        self.fetcher = fetcher
        self.database_directory = load_database_directory(map_manifest_path)
        self.database_fetcher = database_fetcher or (lambda url: fetch_database_json(url, self.database_directory))
        self.metadata_fetcher = metadata_fetcher or (lambda url: fetch_database_json(url, self.database_directory))
        self.activation_id = ""
        self.contract_digest = ""
        self._states: dict[str, dict[str, Any]] = {}
        self._bands: dict[str, dict[str, Any]] = {}
        self._last_poll: tuple[float, float] | None = None
        self._database_pages: OrderedDict[str, tuple[str, ...]] = OrderedDict()
        self._model_cache: OrderedDict[str, str] = OrderedDict()
        self._aircraft_metadata_cache: OrderedDict[str, dict[str, str]] = OrderedDict()
        self._aircraft_cache_completeness: OrderedDict[str, tuple[bool, bool]] = OrderedDict()
        self._operator_cache: dict[str, str] | None = None
        self._type_name_cache: dict[str, str] | None = None
        self._model_cursor = 0

    # read only the bounded configured station coordinates
    def _station_position(self) -> tuple[float, float] | None:
        try:
            settings = read_json(self.root / "config/settings.json", 64 * 1024)
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            return None
        station = settings.get("station")
        # treat unavailable location as optional observation metadata
        if not isinstance(station, dict):
            return None
        latitude = _optional_number(station.get("latitude"), -90, 90)
        longitude = _optional_number(station.get("longitude"), -180, 180)
        # require both coordinates before measuring a radius
        if latitude is None or longitude is None:
            return None
        return latitude, longitude

    # validate one page and retain only bounded normalized metadata
    def _parse_database_page(
        self, prefix: str, document: dict[str, Any], identity: str
    ) -> tuple[tuple[str, ...], dict[str, str], dict[str, dict[str, str]], dict[str, str] | None]:
        # accept only a strict uppercase trie key
        if DATABASE_PREFIX_PATTERN.fullmatch(prefix) is None or not identity.startswith(prefix):
            raise ValueError("invalid database prefix")
        children_value = document.get("children", [])
        # constrain child fanout to the next exact trie level
        if (
            not isinstance(children_value, list)
            or len(children_value) > 16
            or any(
                not isinstance(child, str)
                or len(child) != len(prefix) + 1
                or not child.startswith(prefix)
                or DATABASE_PREFIX_PATTERN.fullmatch(child) is None
                for child in children_value
            )
            or len(set(children_value)) != len(children_value)
        ):
            raise ValueError("invalid database children")
        children = tuple(children_value)
        suffix_length = 6 - len(prefix)
        suffix_pattern = re.compile(rf"^[0-9A-F]{{{suffix_length}}}$")
        retained_models: dict[str, str] = {}
        retained_metadata: dict[str, dict[str, str]] = {}
        target: dict[str, str] | None = None
        # validate every row while retaining only normalized bounded fields
        for suffix, row in document.items():
            # skip the separately validated trie control row
            if suffix == "children":
                continue
            # reject malformed exact aircraft rows
            if (
                not isinstance(suffix, str)
                or suffix_pattern.fullmatch(suffix) is None
                or not isinstance(row, list)
                or len(row) != 4
            ):
                raise ValueError("invalid database row")
            full_identity = f"{prefix}{suffix}"
            model = normalize_aircraft_model(row[1])
            registration = _registration(row[0])
            type_name = _optional_text(row[3])
            metadata = {}
            # retain one validated registration field
            if registration is not None:
                metadata["registration"] = registration
            # retain one validated long type field
            if type_name is not None:
                metadata["type_name"] = type_name
            # keep a bounded positive model sample
            if model is not None and len(retained_models) < MAX_DATABASE_MODELS:
                retained_models[full_identity] = model
            # keep a bounded positive metadata sample
            if metadata and len(retained_metadata) < MAX_AIRCRAFT_METADATA:
                retained_metadata[full_identity] = metadata
            # preserve the requested target even past either sample bound
            if full_identity == identity:
                # retain the target model past the sampling limit
                if model is not None:
                    retained_models[full_identity] = model
                # retain the target metadata past the sampling limit
                if metadata:
                    retained_metadata[full_identity] = metadata
                target = {**metadata, **({"model": model} if model is not None else {})}
        # make the requested result newest during global lru insertion
        if target is not None:
            # refresh the retained target model order
            if identity in retained_models:
                retained_models[identity] = retained_models.pop(identity)
            # refresh the retained target metadata order
            if identity in retained_metadata:
                retained_metadata[identity] = retained_metadata.pop(identity)
        return children, retained_models, retained_metadata, target

    # merge one validated page into the bounded lru caches
    def _cache_database_page(
        self,
        prefix: str,
        children: tuple[str, ...],
        models: dict[str, str],
        metadata: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self._database_pages[prefix] = children
        self._database_pages.move_to_end(prefix)
        # retain at most the most recently parsed prefix pages
        while len(self._database_pages) > MAX_DATABASE_PAGES:
            self._database_pages.popitem(last=False)
        # merge only normalized identity-to-model entries
        for identity, model in models.items():
            self._model_cache[identity] = model
            self._model_cache.move_to_end(identity)
        # evict the least recently used model entries globally
        while len(self._model_cache) > MAX_DATABASE_MODELS:
            self._model_cache.popitem(last=False)

        # merge only validated registration and description metadata
        for identity, fields in (metadata or {}).items():
            self._aircraft_metadata_cache[identity] = fields
            self._aircraft_metadata_cache.move_to_end(identity)
        # evict the least recently used metadata entries globally
        while len(self._aircraft_metadata_cache) > MAX_AIRCRAFT_METADATA:
            self._aircraft_metadata_cache.popitem(last=False)

        present_metadata = metadata or {}
        identities = list(models)
        identities.extend(identity for identity in present_metadata if identity not in models)
        # record which positive halves the immutable exact row originally supplied
        for identity in identities:
            expected_model, expected_metadata = self._aircraft_cache_completeness.get(identity, (False, False))
            self._aircraft_cache_completeness[identity] = (
                expected_model or identity in models,
                expected_metadata or identity in present_metadata,
            )
            self._aircraft_cache_completeness.move_to_end(identity)
        # bound completeness independently from either projected value cache
        while len(self._aircraft_cache_completeness) > MAX_AIRCRAFT_METADATA:
            self._aircraft_cache_completeness.popitem(last=False)

    # resolve one proven physical identity through the pinned static trie
    def _resolve_static_aircraft(self, identity: str, fetch_budget: list[int]) -> dict[str, str]:
        cached_model = self._model_cache.get(identity)
        cached_metadata = self._aircraft_metadata_cache.get(identity)
        completeness = self._aircraft_cache_completeness.get(identity)
        complete = completeness is not None and (
            (not completeness[0] or cached_model is not None) and (not completeness[1] or cached_metadata is not None)
        )
        # reuse only complete validated exact-row projections
        if complete:
            self._aircraft_cache_completeness.move_to_end(identity)
            # refresh one present model projection
            if cached_model is not None:
                self._model_cache.move_to_end(identity)
            # refresh one present metadata projection
            if cached_metadata is not None:
                self._aircraft_metadata_cache.move_to_end(identity)
            return {**(cached_metadata or {}), **({"model": cached_model} if cached_model is not None else {})}
        # walk from the documented one-character root
        for length in range(1, 7):
            prefix = identity[:length]
            next_prefix = identity[: length + 1]
            cached_children = self._database_pages.get(prefix)
            # reuse only a validated positive routing edge
            if length < 6 and cached_children is not None and next_prefix in cached_children:
                self._database_pages.move_to_end(prefix)
                continue
            # stop before exceeding the shared per-poll transport budget
            if fetch_budget[0] <= 0:
                return {}
            fetch_budget[0] -= 1
            url = f"http://127.0.0.1:8078/{self.database_directory}/{prefix}.js"
            document = self.database_fetcher(url)
            children, models, metadata, target = self._parse_database_page(prefix, document, identity)
            self._cache_database_page(prefix, children, models, metadata)
            # return only the exact requested row
            if target is not None:
                return target
            # stop when the page does not delegate this identity
            if length == 6 or next_prefix not in children:
                return {}
        return {}

    # preserve the model-only compatibility helper used by source proof
    def _resolve_static_model(self, identity: str, fetch_budget: list[int]) -> str | None:
        return self._resolve_static_aircraft(identity, fetch_budget).get("model")

    # load one bounded pinned type-description table on demand
    def _load_type_names(self, fetch_budget: list[int]) -> dict[str, str] | None:
        # reuse one immutable activation's validated table
        if self._type_name_cache is not None:
            return self._type_name_cache
        # keep named metadata inside the shared transport allowance
        if fetch_budget[0] <= 0:
            return None
        fetch_budget[0] -= 1
        url = f"http://127.0.0.1:8078/{self.database_directory}/icao_aircraft_types2.js"
        document = self.metadata_fetcher(url)
        # cap the complete fixed table before retaining selected fields
        if len(document) > MAX_TYPE_NAMES:
            raise ValueError("oversized aircraft type table")
        retained: dict[str, str] = {}
        # ignore malformed optional rows without invalidating valid descriptions
        for model, row in document.items():
            normalized = normalize_aircraft_model(model)
            type_name = _optional_text(row[0]) if isinstance(row, list) and len(row) == 3 else None
            # retain only exact normalized keys with one safe description
            if normalized == model and type_name is not None:
                retained[model] = type_name
        self._type_name_cache = retained
        return retained

    # load one bounded pinned operator-prefix table on demand
    def _load_operators(self, fetch_budget: list[int]) -> dict[str, str] | None:
        # reuse one immutable activation's validated table
        if self._operator_cache is not None:
            return self._operator_cache
        # keep named metadata inside the shared transport allowance
        if fetch_budget[0] <= 0:
            return None
        fetch_budget[0] -= 1
        url = f"http://127.0.0.1:8078/{self.database_directory}/operators.js"
        document = self.metadata_fetcher(url)
        # cap the complete fixed table while allowing known nonprefix rows
        if len(document) > MAX_OPERATOR_PREFIXES:
            raise ValueError("oversized operator table")
        retained: dict[str, str] = {}
        # ignore nonprefix and malformed optional rows independently
        for prefix, row in document.items():
            # skip unsupported operator key shapes
            if OPERATOR_PREFIX_PATTERN.fullmatch(prefix) is None or not isinstance(row, dict):
                continue
            name = _optional_text(row.get("n")) if frozenset(row) == frozenset(("n", "c", "r")) else None
            # retain only one bounded operator name per exact prefix
            if name is not None:
                retained[prefix] = name
        self._operator_cache = retained
        return retained

    # resolve one type description through direct or pinned fallback metadata
    def _type_name_for(self, metadata: dict[str, str], model: str | None, fetch_budget: list[int]) -> str | None:
        direct = metadata.get("type_name")
        # prefer the exact aircraft row's description
        if direct is not None:
            return direct
        # fall back only from one validated icao type code
        if model is None:
            return None
        table = self._load_type_names(fetch_budget)
        return table.get(model) if table is not None else None

    # resolve one physical callsign to a pinned operator name
    def _airline_for(self, flight: Any, registration: str | None, fetch_budget: list[int]) -> str | None:
        callsign = _flight(flight)
        # require the conservative three-letter operator callsign shape
        if (
            callsign is None
            or len(callsign) < 4
            or OPERATOR_PREFIX_PATTERN.fullmatch(callsign[:3]) is None
            or re.fullmatch(r"[A-Z]{4}", callsign[:4]) is not None
        ):
            return None
        comparable = callsign.replace("-", "").replace("+", "")
        registered = registration.replace("-", "").replace("+", "") if registration is not None else None
        # never label a tail-number callsign as an airline
        if registered is not None and comparable == registered:
            return None
        operators = self._load_operators(fetch_budget)
        return operators.get(callsign[:3]) if operators is not None else None

    # reset only one receiver's proof and progression baseline
    def _invalidate(self, band: str, now_mono: float, station: tuple[float, float] | None = None) -> dict[str, Any]:
        self._states.pop(band, None)
        self._bands[band] = {"state": "unknown", "last_message_at": None}
        return {
            "band": band,
            "generation": "unknown",
            "healthy": False,
            "coverage_state": "unknown",
            "coverage_since": now_mono,
            "coverage_until": now_mono,
            "location_center": station,
            "aircraft": [],
        }

    # inspect one fixed source generation and its decoded progression
    def _observe(
        self,
        band: str,
        expected: dict[str, Any],
        now_wall: float,
        now_mono: float,
        station: tuple[float, float] | None,
    ) -> dict[str, Any]:
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
        rows = normalize_aircraft(payload, now=now_wall, band=band, station=station)
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
            "location_center": station,
            "aircraft": fresh_rows,
        }

    # collect bounded independent samples without exposing private runtime configuration
    def poll(
        self,
        *,
        now_wall: float | None = None,
        now_mono: float | None = None,
        resolve_models: bool = False,
    ) -> list[dict[str, Any]]:
        wall = time.time() if now_wall is None else now_wall
        mono = time.monotonic() if now_mono is None else now_mono
        station = self._station_position()
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
                self._database_pages.clear()
                self._model_cache.clear()
                self._aircraft_metadata_cache.clear()
                self._aircraft_cache_completeness.clear()
                self._operator_cache = None
                self._type_name_cache = None
                self._model_cursor = 0
            self.activation_id, self.contract_digest = identity
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            return [self._invalidate(band, mono, station) for band in ("1090", "978")]
        samples = []
        # keep removed bands explicitly unknown so persisted obligations cannot shrink
        for band in ("1090", "978"):
            expected = alerts["sources"].get(band)
            # absent hardware cannot prove an encounter's required absence
            if band not in alerts["expected_bands"] or not isinstance(expected, dict):
                samples.append({**self._invalidate(band, mono, station), "expected": False})
                self._bands[band]["state"] = "absent"
                continue
            try:
                samples.append(self._observe(band, expected, wall, mono, station))
            except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
                samples.append({**self._invalidate(band, mono, station), "expected": True})
        observations: dict[str, list[dict[str, Any]]] = {}
        # index only already-proven physical rows for optional metadata joins
        for sample in samples:
            # retain every independently received band row
            for row in sample["aircraft"]:
                observations.setdefault(row["hex"], []).append(row)
        candidates = {identity: rows[-1] for identity, rows in observations.items()}
        models: dict[str, str] = {}
        invalid_map_models = False
        # enrich only already-proven physical sightings from the optional pinned map database
        if candidates:
            try:
                enrichment = self.fetcher(MAP_URL)
                _fresh(_number(enrichment.get("now")), wall, 5)
                metadata = enrichment.get("aircraft")
                # bound the optional map join without treating it as a reception source
                if not isinstance(metadata, list) or len(metadata) > MAX_ROWS:
                    raise ValueError("invalid enrichment")
                flags: dict[str, int] = {}
                joined_models: dict[str, str] = {}
                # join only strict classification metadata to physical identities
                for row in metadata:
                    if not isinstance(row, dict) or not isinstance(row.get("hex"), str):
                        continue
                    hex_id = row["hex"].upper()
                    value = row.get("dbFlags")
                    # ignore malformed or unverified integer flag shapes
                    if hex_id in candidates and type(value) is int and 0 <= value <= 127:
                        flags[hex_id] = value
                    # validate only model metadata that can affect a physical sighting
                    if hex_id in candidates and "t" in row:
                        model = normalize_aircraft_model(row["t"])
                        # reject malformed or conflicting model joins as one enrichment unit
                        if model is None or (hex_id in joined_models and joined_models[hex_id] != model):
                            invalid_map_models = True
                            raise ValueError("invalid model enrichment")
                        joined_models[hex_id] = model
                # apply classification-only data to every overlap observation
                for sample in samples:
                    # enrich each proven per-band observation independently
                    for row in sample["aircraft"]:
                        # attach only a validated matching bitfield
                        if row["hex"] in flags:
                            row["dbFlags"] = flags[row["hex"]]
                        # propagate only validated exact-identity model joins
                        if row["hex"] in joined_models:
                            row["model"] = joined_models[row["hex"]]
                models = joined_models
            except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
                pass
        # fill bounded static metadata only for proven sightings and explicit metadata polls
        if candidates and resolve_models and not invalid_map_models:
            identities = sorted(candidates)
            # rotate the bounded worklist so one deep miss cannot starve later identities
            if identities:
                offset = self._model_cursor % len(identities)
                identities = identities[offset:] + identities[:offset]
                self._model_cursor = (offset + 1) % len(identities)
            fetch_budget = [MAX_DATABASE_FETCHES]
            # resolve and attach each identity inside one shared transport allowance
            for hex_id in identities:
                try:
                    static = self._resolve_static_aircraft(hex_id, fetch_budget)
                except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
                    continue
                model = models.get(hex_id) or static.get("model")
                # preserve a validated map model over its static fallback
                if model is not None:
                    models[hex_id] = model
                try:
                    type_name = self._type_name_for(static, model, fetch_budget)
                except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
                    type_name = None
                # attach one exact identity's metadata to every physical band row
                for row in observations[hex_id]:
                    # attach one validated model projection
                    if model is not None:
                        row["model"] = model
                    # attach one validated long type projection
                    if type_name is not None:
                        row["type_name"] = type_name
                    try:
                        airline = self._airline_for(row.get("_flight"), static.get("registration"), fetch_budget)
                    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
                        airline = None
                    # attach only a pinned operator lookup result
                    if airline is not None:
                        row["airline"] = airline
        # remove the physical callsign work field before returning normalized samples
        for rows in observations.values():
            # clean every independently received band row
            for row in rows:
                row.pop("_flight", None)
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
