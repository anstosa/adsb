"""Fail-closed physical source, progression and coverage contract tests."""

from __future__ import annotations

import gzip
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from adsb_admin.alert_sources import (
    MAP_UI_MANIFEST_PATH,
    MAX_AIRCRAFT_METADATA,
    MAX_DATABASE_FETCHES,
    MAX_DATABASE_MODELS,
    MAX_DATABASE_PAGES,
    MAX_JSON_BYTES,
    MAX_OPERATOR_PREFIXES,
    MAX_TYPE_NAMES,
    AlertSourceMonitor,
    fetch_database_json,
    load_database_directory,
    normalize_aircraft,
    read_json,
)

ROOT = Path(__file__).resolve().parents[1]


# format deterministic controller clocks
def timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


# exercise both source adapters without sockets or provider endpoints
class AlertSourceTest(unittest.TestCase):
    # build private atomic-publication fixtures
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.activation = "a" * 32
        self.digest = "b" * 64
        self.generation = "11111111-1111-4111-8111-111111111111"
        self.upstream = {"1090": 0, "978": 0}
        self.input_socket = {"1090": "100", "978": "200"}
        self.health_time = None
        self.metadata = {"now": 1000, "aircraft": []}
        self.wall = 1000.0
        self.end = 1001.0
        self.accepted = {"1090": 0, "978": 0}
        self.aircraft: dict[str, list] = {"1090": [], "978": []}
        self.expected = ["1090", "978"]
        self.database_documents: dict[str, dict] = {}
        self.database_requests: list[str] = []
        self.metadata_documents: dict[str, dict] = {"icao_aircraft_types2": {}, "operators": {}}
        self.metadata_requests: list[str] = []
        (self.root / "config").mkdir()
        (self.root / "config/settings.json").write_text(
            json.dumps({"station": {"latitude": 48.0, "longitude": -122.0}})
        )
        self.monitor = AlertSourceMonitor(
            root=self.root,
            manifest_path=ROOT / "deploy/alerts/source-contract.json",
            fetcher=self.fetch,
            database_fetcher=self.fetch_database,
            metadata_fetcher=self.fetch_metadata,
        )

    # release isolated fixtures
    def tearDown(self) -> None:
        self.temporary.cleanup()

    # publish one independent fixed producer sample
    def fetch(self, url: str) -> dict:
        return {**self.metadata, "now": self.wall}

    # return one injected immutable database page
    def fetch_database(self, url: str) -> dict:
        prefix = url.rsplit("/", 1)[-1].removesuffix(".js")
        self.database_requests.append(prefix)
        # model a missing fixed local page as a transport failure
        if prefix not in self.database_documents:
            raise OSError("missing database page")
        return self.database_documents[prefix]

    # return one injected fixed named metadata document
    def fetch_metadata(self, url: str) -> dict:
        name = url.rsplit("/", 1)[-1].removesuffix(".js")
        self.metadata_requests.append(name)
        # model a missing named route as a transport failure
        if name not in self.metadata_documents:
            raise OSError("missing metadata document")
        return self.metadata_documents[name]

    # write bounded source fixtures for one polling instant
    def write(self) -> None:
        sources = {}
        # give each band independent decoder and producer counters
        for band in ("1090", "978"):
            directory = self.root / "alert-source" / band
            directory.mkdir(parents=True, exist_ok=True)
            marker = {
                "schema_version": 1,
                "band": band,
                "generation": self.generation,
                "started_at": timestamp(990),
                "activation_id": self.activation,
                "contract_digest": self.digest,
            }
            source_state = {
                **marker,
                "schema_version": 2,
                "sampled_at": timestamp(self.wall if self.health_time is None else self.health_time),
                "process_running": True,
                "input_connected": True,
                "input_socket": self.input_socket[band],
                "input_bytes": self.upstream[band],
            }
            documents = {
                "source-marker.json": marker,
                "source-state.json": source_state,
                "aircraft.json": {"now": self.wall, "messages": self.accepted[band], "aircraft": self.aircraft[band]},
                "stats.json": {
                    "total": {"start": 990.1, "end": self.end, "remote": {"accepted": [self.accepted[band], 0]}}
                },
            }
            # create complete publications as the receiver would
            for name, value in documents.items():
                (directory / name).write_text(json.dumps(value))
            sources[band] = {"state": "ready", "generation": self.generation}
        status = {
            "updated_at": timestamp(self.wall),
            "activation_id": self.activation,
            "alerts": {
                "activation_id": self.activation,
                "source_contract_digest": self.digest,
                "expected_bands": self.expected,
                "sources": sources,
            },
        }
        (self.root / "status").mkdir(exist_ok=True)
        (self.root / "status/status.json").write_text(json.dumps(status))

    # poll one advancing host second
    def poll(self, seconds: float = 1, *, finalize: bool = False, resolve_models: bool = False) -> list[dict]:
        self.wall += seconds
        # publish a new finalized decoder interval only when requested
        if finalize:
            self.end = self.wall
        self.write()
        return self.monitor.poll(now_wall=self.wall, now_mono=self.wall - 900, resolve_models=resolve_models)

    # accept identity without requiring a position and honestly label rebroadcast
    def test_no_position_and_rebroadcast_schema(self) -> None:
        rows = normalize_aircraft(
            {
                "now": 1000,
                "messages": 2,
                "aircraft": [{"hex": "40621d", "messages": 2, "seen": 0, "type": "adsr_icao"}],
            },
            now=1000,
        )
        self.assertEqual("40621D", rows[0]["hex"])
        self.assertEqual("rebroadcast", rows[0]["reception"])
        self.assertIsNone(rows[0]["location_center"])

    # attach bounded decoder telemetry and configured-station distance
    def test_fresh_physical_position_and_telemetry(self) -> None:
        rows = normalize_aircraft(
            {
                "now": 1000,
                "messages": 2,
                "aircraft": [
                    {
                        "hex": "40621d",
                        "messages": 2,
                        "seen": 0,
                        "lat": 48.0,
                        "lon": -122.05,
                        "seen_pos": 2,
                        "gs": 1000,
                        "track": 337.5,
                        "alt_baro": 12500,
                    }
                ],
            },
            now=1000,
            station=(48.0, -122.0),
        )
        row = rows[0]
        self.assertAlmostEqual(2.312, row["distance_mi"], places=3)
        self.assertEqual(998, row["position_observed_at"])
        self.assertEqual(1000, row["speed_knots"])
        self.assertEqual(337.5, row["heading_degrees"])
        self.assertEqual(12500, row["altitude_feet"])
        self.assertFalse(row["on_ground"])
        self.assertEqual(48.0, row["latitude"])
        self.assertEqual(-122.05, row["longitude"])
        self.assertEqual((48.0, -122.0), row["location_center"])

    # omit stale or mlat positions while preserving other direct telemetry
    def test_stale_mlat_and_r_dst_positions_are_never_distance_evidence(self) -> None:
        base = {"hex": "40621d", "messages": 2, "seen": 0, "lat": 48.0, "lon": -122.01, "gs": 90}
        for fields in (
            {"seen_pos": 5.1},
            {"seen_pos": 0, "mlat": ["lat", "lon"]},
            {"r_dst": 1},
        ):
            with self.subTest(fields=fields):
                row = normalize_aircraft(
                    {"now": 1000, "messages": 2, "aircraft": [{**base, **fields}]},
                    now=1000,
                    station=(48.0, -122.0),
                )[0]
                self.assertNotIn("distance_mi", row)
                self.assertNotIn("position_observed_at", row)
                self.assertEqual(90, row["speed_knots"])

    # ignore bad optional fields without invalidating physical presence
    def test_invalid_optional_telemetry_does_not_invalidate_source(self) -> None:
        rows = normalize_aircraft(
            {
                "now": 1000,
                "messages": 2,
                "aircraft": [
                    {
                        "hex": "40621d",
                        "messages": 2,
                        "seen": 0,
                        "lat": "north",
                        "lon": -122,
                        "seen_pos": 0,
                        "gs": -1,
                        "track": 361,
                        "alt_baro": "unknown",
                        "alt_geom": True,
                    }
                ],
            },
            now=1000,
            station=(48.0, -122.0),
        )
        self.assertEqual("40621D", rows[0]["hex"])
        for field in ("distance_mi", "position_observed_at", "speed_knots", "heading_degrees", "altitude_feet"):
            self.assertNotIn(field, rows[0])
        self.assertFalse(rows[0]["on_ground"])

    # expose ground state while retaining a valid geometric-altitude fallback
    def test_ground_state_uses_geometric_altitude_fallback(self) -> None:
        row = normalize_aircraft(
            {
                "now": 1000,
                "messages": 2,
                "aircraft": [{"hex": "40621d", "messages": 2, "seen": 0, "alt_baro": "ground", "alt_geom": 125}],
            },
            now=1000,
        )[0]
        self.assertTrue(row["on_ground"])
        self.assertEqual(125, row["altitude_feet"])

    # reject non-icao and network-only identities
    def test_network_and_nonicao_never_eligible(self) -> None:
        rows = [
            {"hex": "~40621d", "messages": 2, "seen": 0},
            {"hex": "40621d", "messages": 2, "seen": 0, "type": "mlat"},
        ]
        self.assertEqual([], normalize_aircraft({"now": 1000, "messages": 4, "aircraft": rows}, now=1000))

    # suppress boot history and unchanged snapshots but accept a new real message
    def test_counter_progression_not_json_publication(self) -> None:
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 3, "seen": 0, "type": "mode_s"}]
        self.accepted["1090"] = 3
        self.assertEqual([], self.poll()[0]["aircraft"])
        self.assertEqual([], self.poll()[0]["aircraft"])
        self.aircraft["1090"][0]["messages"] = 4
        self.accepted["1090"] = 4
        self.assertTrue(self.poll()[0]["aircraft"][0]["fresh"])

    # read the private station center for one emitted physical row
    def test_monitor_reads_configured_station_center(self) -> None:
        self.poll()
        self.aircraft["1090"] = [
            {
                "hex": "abcdef",
                "messages": 2,
                "seen": 0,
                "lat": 48.0,
                "lon": -122.01,
                "seen_pos": 0,
            }
        ]
        self.accepted["1090"] = 2
        sample = self.poll()[0]
        self.assertEqual((48.0, -122.0), sample["location_center"])
        self.assertEqual((48.0, -122.0), sample["aircraft"][0]["location_center"])
        self.assertAlmostEqual(0.462, sample["aircraft"][0]["distance_mi"], places=3)

    # independently invalidate a stalled decoder while its peer progresses
    def test_same_band_active_stall_breaks_continuity(self) -> None:
        self.poll()
        # sample every second while the producer is active
        for _ in range(9):
            self.upstream["1090"] += 5
            self.upstream["978"] += 1
            self.accepted["978"] += 1
            self.poll()
        samples = self.poll(finalize=True)
        self.assertEqual("unknown", samples[0]["coverage_state"])
        self.assertEqual("healthy", samples[1]["coverage_state"])

    # quiet fresh connected sources finalize without manufacturing messages
    def test_quiet_finalized_window(self) -> None:
        first = self.poll()
        # keep polling while the source's stats window remains open
        for _ in range(9):
            self.poll()
        final = self.poll(finalize=True)
        self.assertGreaterEqual(final[0]["coverage_since"], first[0]["coverage_since"])
        self.assertEqual(111, final[0]["coverage_until"])

    # clock jumps and polling gaps cannot certify absence
    def test_poll_gap_and_clock_jump_rebaseline(self) -> None:
        first = self.poll()[0]
        later = self.poll(5, finalize=True)[0]
        self.assertGreater(later["coverage_since"], first["coverage_since"])
        self.wall += 100
        self.end = self.wall
        self.write()
        shifted = self.monitor.poll(now_wall=self.wall, now_mono=107)[0]
        self.assertEqual(107, shifted["coverage_since"])

    # absence does not silently remove a persisted band obligation
    def test_removed_band_is_explicitly_unknown(self) -> None:
        self.poll()
        self.expected = ["1090"]
        absent = self.poll()[1]
        self.assertFalse(absent["expected"])
        self.assertFalse(absent["healthy"])

    # generation mismatches reject stale output
    def test_wrong_generation_and_old_files(self) -> None:
        self.write()
        path = self.root / "alert-source/1090/source-marker.json"
        value = json.loads(path.read_text())
        value["generation"] = "22222222-2222-4222-8222-222222222222"
        path.write_text(json.dumps(value))
        sample = self.monitor.poll(now_wall=self.wall, now_mono=100)[0]
        self.assertFalse(sample["healthy"])
        self.assertEqual((48.0, -122.0), sample["location_center"])

    # a symlink publication cannot widen the worker's read surface
    def test_symlink_and_oversized_publication_rejected(self) -> None:
        secret = self.root / "private.json"
        secret.write_text("{}")
        alias = self.root / "alias.json"
        alias.symlink_to(secret)
        with self.assertRaises(OSError):
            read_json(alias)
        secret.write_text("x" * 100)
        with self.assertRaises(ValueError):
            read_json(secret, 10)

    # per-track resets break proof rather than replaying an encounter
    def test_counter_reset_fails_closed(self) -> None:
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 4, "seen": 0}]
        self.poll()
        self.aircraft["1090"][0]["messages"] = 2
        self.assertFalse(self.poll()[0]["healthy"])

    # a direct uat frame is transcoded as adsr without becoming an rf rebroadcast
    def test_uat_transcoding_and_actual_tisb_label(self) -> None:
        payload = {
            "now": 1000,
            "messages": 4,
            "aircraft": [
                {"hex": "40621d", "messages": 2, "seen": 0, "type": "adsr_icao"},
                {"hex": "606060", "messages": 2, "seen": 0, "type": "tisb_icao"},
            ],
        }
        rows = normalize_aircraft(payload, now=1000, band="978")
        self.assertEqual(["direct", "rebroadcast"], [row["reception"] for row in rows])

    # a replaced connection never joins continuity even with a larger byte counter
    def test_reconnect_with_higher_counter_invalidates(self) -> None:
        self.poll()
        self.input_socket["1090"] = "999"
        self.upstream["1090"] = 1_000_000
        self.assertFalse(self.poll()[0]["healthy"])

    # counter rollback and missing kernel publication invalidate independently
    def test_kernel_reset_and_stale_health(self) -> None:
        self.upstream["1090"] = 10
        self.poll()
        self.upstream["1090"] = 0
        self.assertFalse(self.poll()[0]["healthy"])
        self.health_time = self.wall - 8
        self.assertFalse(self.poll()[1]["healthy"])

    # wait for a late five-second kernel bracket instead of falsely finalizing quiet
    def test_late_kernel_bracket_finalizes_within_fifteen_seconds(self) -> None:
        self.health_time = 1000
        first = self.poll()[0]
        # emulate exact five-second independent health sampling with one-second polling
        for _ in range(9):
            self.health_time = 1000 + int((self.wall + 1 - 1000) // 5) * 5
            self.poll()
        self.health_time = 1010
        closed = self.poll(finalize=True)[0]
        self.assertEqual(first["coverage_until"], closed["coverage_until"])
        # the next sample brackets the complete decoded period four seconds later
        for _ in range(3):
            self.poll()
        self.health_time = 1015
        proven = self.poll()[0]
        self.assertEqual(111, proven["coverage_until"])
        self.assertEqual(115, self.wall - 900)

    # late positive bytes reject a flat accepted period rather than borrow peer progress
    def test_late_active_input_cannot_be_certified_as_quiet(self) -> None:
        self.health_time = 1000
        self.poll()
        # retain cadence while delaying the final bracketing sample
        for _ in range(9):
            self.health_time = 1000 + int((self.wall + 1 - 1000) // 5) * 5
            self.poll()
        self.health_time = 1010
        self.poll(finalize=True)
        # preserve the last publication until the next five-second probe
        for _ in range(3):
            self.poll()
        self.health_time = 1015
        self.upstream["1090"] = 100
        self.assertFalse(self.poll()[0]["healthy"])

    # merged map metadata only classifies a proven local sighting
    def test_map_flags_are_enrichment_not_reception(self) -> None:
        self.metadata["aircraft"] = [
            {"hex": "abcdef", "dbFlags": 1, "t": "c17", "lat": 48.0, "lon": -122.0, "seen_pos": 0},
            {"hex": "aaaaaa", "dbFlags": 1, "t": "H60"},
        ]
        self.assertEqual([], self.poll()[0]["aircraft"])
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0}]
        self.accepted["1090"] = 2
        row = self.poll()[0]["aircraft"][0]
        self.assertEqual(1, row["dbFlags"])
        self.assertEqual("C17", row["model"])
        self.assertEqual("ABCDEF", row["hex"])
        self.assertNotIn("distance_mi", row)

    # unavailable station configuration omits distance without affecting reception
    def test_missing_station_location_does_not_invalidate_source(self) -> None:
        self.poll()
        (self.root / "config/settings.json").unlink()
        self.aircraft["1090"] = [
            {"hex": "abcdef", "messages": 2, "seen": 0, "lat": 48.0, "lon": -122.01, "seen_pos": 0}
        ]
        self.accepted["1090"] = 2
        sample = self.poll()[0]
        self.assertTrue(sample["healthy"])
        self.assertIsNone(sample["location_center"])
        self.assertEqual("ABCDEF", sample["aircraft"][0]["hex"])
        self.assertNotIn("distance_mi", sample["aircraft"][0])

    # discard optional enrichment when model metadata is invalid or conflicting
    def test_map_model_enrichment_fails_closed_on_conflicts(self) -> None:
        self.poll()
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0}]
        self.accepted["1090"] = 2
        self.metadata["aircraft"] = [
            {"hex": "abcdef", "dbFlags": 1, "t": "C17"},
            {"hex": "ABCDEF", "t": "H60"},
        ]
        conflicted = self.poll()[0]["aircraft"][0]
        self.assertNotIn("model", conflicted)
        self.assertNotIn("dbFlags", conflicted)
        self.aircraft["1090"][0]["messages"] = 3
        self.accepted["1090"] = 3
        self.metadata["aircraft"] = [{"hex": "abcdef", "dbFlags": 1, "t": "C-17"}]
        malformed = self.poll()[0]["aircraft"][0]
        self.assertNotIn("model", malformed)
        self.assertNotIn("dbFlags", malformed)

    # resolve a pinned static model only after a physical observation
    def test_static_model_trie_enriches_physical_sightings_only(self) -> None:
        self.database_documents = {
            "A": {"children": ["AB"]},
            "AB": {"children": ["ABC"]},
            "ABC": {"DEF": ["N123", "p8", "10", "Poseidon"]},
        }
        self.metadata["aircraft"] = [{"hex": "ABCDEF"}]
        self.poll(resolve_models=True)
        self.assertEqual([], self.database_requests)
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0}]
        self.accepted["1090"] = 2
        row = self.poll(resolve_models=True)[0]["aircraft"][0]
        self.assertEqual("P8", row["model"])
        self.assertEqual("Poseidon", row["type_name"])
        self.assertEqual(["A", "AB", "ABC"], self.database_requests)

    # reuse proven routing edges so a deep trie resolves across bounded polls
    def test_deep_static_trie_progresses_across_fetch_budgets(self) -> None:
        self.database_documents = {
            "A": {"children": ["AB"]},
            "AB": {"children": ["ABC"]},
            "ABC": {"children": ["ABCD"]},
            "ABCD": {"children": ["ABCDE"]},
            "ABCDE": {"children": ["ABCDEF"]},
            "ABCDEF": {"": ["N123", "P8", "10", "Poseidon"]},
        }
        self.assertEqual({}, self.monitor._resolve_static_aircraft("ABCDEF", [MAX_DATABASE_FETCHES]))
        self.assertEqual(["A", "AB", "ABC", "ABCD"], self.database_requests)
        resolved = self.monitor._resolve_static_aircraft("ABCDEF", [MAX_DATABASE_FETCHES])
        self.assertEqual("P8", resolved["model"])
        self.assertEqual("Poseidon", resolved["type_name"])
        self.assertEqual(["A", "AB", "ABC", "ABCD", "ABCDE", "ABCDEF"], self.database_requests)

    # refetch a terminal page after its positive identity metadata is evicted
    def test_terminal_page_refetches_after_positive_cache_eviction(self) -> None:
        self.database_documents = {
            "A": {"children": ["AB"]},
            "AB": {"children": ["ABC"]},
            "ABC": {"children": ["ABCD"]},
            "ABCD": {"children": ["ABCDE"]},
            "ABCDE": {"children": ["ABCDEF"]},
            "ABCDEF": {"": ["N123", "P8", "10", "Poseidon"]},
        }
        self.assertEqual("P8", self.monitor._resolve_static_aircraft("ABCDEF", [6])["model"])
        self.monitor._model_cache.pop("ABCDEF")
        self.monitor._aircraft_metadata_cache.pop("ABCDEF")
        self.database_requests.clear()
        restored = self.monitor._resolve_static_aircraft("ABCDEF", [MAX_DATABASE_FETCHES])
        self.assertEqual("P8", restored["model"])
        self.assertEqual(["ABCDEF"], self.database_requests)

    # refetch both halves after model-only pressure evicts one projection
    def test_model_cache_pressure_cannot_return_incomplete_metadata(self) -> None:
        self.database_documents["A"] = {"BCDEF": ["N123", "P8", "10", "Poseidon"]}
        self.assertEqual("P8", self.monitor._resolve_static_aircraft("ABCDEF", [1])["model"])
        pressure = {f"{index:06X}": "H60" for index in range(MAX_DATABASE_MODELS)}
        self.monitor._cache_database_page("B", (), pressure)
        self.assertNotIn("ABCDEF", self.monitor._model_cache)
        self.assertIn("ABCDEF", self.monitor._aircraft_metadata_cache)
        self.database_requests.clear()
        restored = self.monitor._resolve_static_aircraft("ABCDEF", [1])
        self.assertEqual({"model": "P8", "registration": "N123", "type_name": "Poseidon"}, restored)
        self.assertEqual(["A"], self.database_requests)

    # refetch both halves after metadata-only pressure evicts one projection
    def test_metadata_cache_pressure_cannot_return_incomplete_model(self) -> None:
        self.database_documents["A"] = {"BCDEF": ["N123", "P8", "10", "Poseidon"]}
        self.assertEqual("P8", self.monitor._resolve_static_aircraft("ABCDEF", [1])["model"])
        pressure = {f"{index:06X}": {"registration": f"N{index}"} for index in range(MAX_AIRCRAFT_METADATA)}
        self.monitor._cache_database_page("B", (), {}, pressure)
        self.assertIn("ABCDEF", self.monitor._model_cache)
        self.assertNotIn("ABCDEF", self.monitor._aircraft_metadata_cache)
        self.database_requests.clear()
        restored = self.monitor._resolve_static_aircraft("ABCDEF", [1])
        self.assertEqual({"model": "P8", "registration": "N123", "type_name": "Poseidon"}, restored)
        self.assertEqual(["A"], self.database_requests)

    # cache legitimate model-only and metadata-only exact rows without refetching
    def test_known_absent_static_halves_are_complete_cache_hits(self) -> None:
        self.database_documents = {
            "A": {"BCDEF": [None, "P8", "10", None]},
            "B": {"BCDEF": ["N123", None, "10", "Experimental aircraft"]},
        }
        self.assertEqual({"model": "P8"}, self.monitor._resolve_static_aircraft("ABCDEF", [1]))
        self.assertEqual(
            {"registration": "N123", "type_name": "Experimental aircraft"},
            self.monitor._resolve_static_aircraft("BBCDEF", [1]),
        )
        self.database_requests.clear()
        self.assertEqual({"model": "P8"}, self.monitor._resolve_static_aircraft("ABCDEF", [0]))
        self.assertEqual(
            {"registration": "N123", "type_name": "Experimental aircraft"},
            self.monitor._resolve_static_aircraft("BBCDEF", [0]),
        )
        self.assertEqual([], self.database_requests)

    # resolve bounded long type and airline text from fixed pinned metadata
    def test_static_description_and_physical_callsign_operator_lookup(self) -> None:
        self.poll()
        self.database_documents["A"] = {"BCDEF": ["N76KA", "DH3T", "10", None]}
        self.metadata_documents = {
            "icao_aircraft_types2": {"DH3T": ["De Havilland Canada DHC-8-300 Dash 8", "L2T", "L"]},
            "operators": {
                "ASA": {"n": "Alaska Airlines", "c": "United States", "r": "ALASKA"},
                "QXE": {"n": "Horizon Air Industries", "c": "United States", "r": "HORIZON"},
                "_mil": {"n": "ignored", "c": "", "r": ""},
            },
        }
        self.metadata["aircraft"] = [{"hex": "ABCDEF", "flight": "QXE123"}]
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0, "flight": " asa123 "}]
        self.accepted["1090"] = 2
        row = self.poll(resolve_models=True)[0]["aircraft"][0]
        self.assertEqual("DH3T", row["model"])
        self.assertEqual("De Havilland Canada DHC-8-300 Dash 8", row["type_name"])
        self.assertEqual("Alaska Airlines", row["airline"])
        self.assertEqual(["icao_aircraft_types2", "operators"], self.metadata_requests)
        # reject a tail-number callsign even after the metadata caches are warm
        self.aircraft["1090"][0].update(messages=3, flight="N76KA")
        self.accepted["1090"] = 3
        tail = self.poll(resolve_models=True)[0]["aircraft"][0]
        self.assertNotIn("airline", tail)

    # reject ambiguous all-letter callsigns before loading operator metadata
    def test_all_letter_callsign_is_not_an_operator_lookup(self) -> None:
        self.poll()
        self.database_documents["A"] = {"BCDEF": [None, "P8", "10", "Poseidon"]}
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0, "flight": "ASAB12"}]
        self.accepted["1090"] = 2
        row = self.poll(resolve_models=True)[0]["aircraft"][0]
        self.assertNotIn("airline", row)
        self.assertEqual([], self.metadata_requests)
        self.monitor._operator_cache = {"ASA": "Alaska Airlines"}
        self.assertIsNone(self.monitor._airline_for("ASA+123", "ASA-123", [0]))

    # never let network metadata manufacture a static lookup candidate
    def test_static_model_lookup_ignores_network_only_rows(self) -> None:
        self.database_documents["A"] = {"BCDEF": [None, "P8", "10", None]}
        self.metadata["aircraft"] = [{"hex": "ABCDEF"}]
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0, "type": "mlat"}]
        self.accepted["1090"] = 2
        self.poll(resolve_models=True)
        self.assertEqual([], self.database_requests)

    # do not rescue a conflicting map type with the static fallback
    def test_invalid_map_model_disables_static_fallback(self) -> None:
        self.poll()
        self.database_documents["A"] = {"BCDEF": [None, "P8", "10", None]}
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0}]
        self.accepted["1090"] = 2
        self.metadata["aircraft"] = [
            {"hex": "abcdef", "t": "P8"},
            {"hex": "ABCDEF", "t": "H60"},
        ]
        row = self.poll(resolve_models=True)[0]["aircraft"][0]
        self.assertNotIn("model", row)
        self.assertEqual([], self.database_requests)

    # rotate the four-fetch allowance so later identities make progress
    def test_static_fetch_budget_is_bounded_and_fair(self) -> None:
        self.poll()
        identities = [f"{index:X}00001" for index in range(5)]
        self.aircraft["1090"] = [{"hex": identity, "messages": 2, "seen": 0} for identity in identities]
        self.accepted["1090"] = 10
        self.database_documents = {identity[0]: {identity[1:]: [None, "P8", "10", None]} for identity in identities}
        first = self.poll(resolve_models=True)[0]["aircraft"]
        self.assertEqual(MAX_DATABASE_FETCHES, len(self.database_requests) + len(self.metadata_requests))
        self.assertEqual(3, sum("model" in row for row in first))
        self.assertEqual(["icao_aircraft_types2"], self.metadata_requests)
        # advance every physical track for the next fair work slice
        for row in self.aircraft["1090"]:
            row["messages"] += 1
        self.accepted["1090"] += 5
        second = self.poll(resolve_models=True)[0]["aircraft"]
        self.assertEqual(5, sum("model" in row for row in second))
        self.assertEqual(5, len(self.database_requests))

    # validate trie shape and keep both caches within fixed lru limits
    def test_database_page_validation_and_cache_limits(self) -> None:
        with self.assertRaises(ValueError):
            self.monitor._parse_database_page("a", {}, "ABCDEF")
        with self.assertRaises(ValueError):
            self.monitor._parse_database_page("A", {"children": ["Ab"]}, "ABCDEF")
        with self.assertRaises(ValueError):
            self.monitor._parse_database_page("A", {"bcdef": [None, "P8", "10", None]}, "ABCDEF")
        # fill past both independent lru ceilings
        for index in range(MAX_DATABASE_PAGES + 1):
            prefix = f"{index:02X}"
            models = {
                f"{index:02X}{entry:04X}": "P8" for entry in range((MAX_DATABASE_MODELS // MAX_DATABASE_PAGES) + 1)
            }
            self.monitor._cache_database_page(prefix, (), models)
        self.assertEqual(MAX_DATABASE_PAGES, len(self.monitor._database_pages))
        self.assertEqual(MAX_DATABASE_MODELS, len(self.monitor._model_cache))
        self.assertNotIn("00", self.monitor._database_pages)

    # bound all optional pinned metadata caches independently
    def test_aircraft_and_named_metadata_cache_limits(self) -> None:
        metadata = {f"{index:06X}": {"registration": f"N{index}"} for index in range(MAX_AIRCRAFT_METADATA + 1)}
        self.monitor._cache_database_page("A", (), {}, metadata)
        self.assertEqual(MAX_AIRCRAFT_METADATA, len(self.monitor._aircraft_metadata_cache))
        self.assertEqual(MAX_AIRCRAFT_METADATA, len(self.monitor._aircraft_cache_completeness))
        prefixes = [
            f"{first}{second}{third}"
            for first in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            for second in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            for third in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ][:MAX_OPERATOR_PREFIXES]
        self.metadata_documents = {
            "icao_aircraft_types2": {
                f"A{index:03X}": [f"Aircraft type {index}", "L2T", "L"] for index in range(MAX_TYPE_NAMES)
            },
            "operators": {prefix: {"n": f"Operator {prefix}", "c": "Country", "r": "RADIO"} for prefix in prefixes},
        }
        budget = [2]
        self.assertEqual(MAX_TYPE_NAMES, len(self.monitor._load_type_names(budget)))
        self.assertEqual(MAX_OPERATOR_PREFIXES, len(self.monitor._load_operators(budget)))
        self.assertEqual(0, budget[0])

    # clear pinned metadata across immutable controller activation changes
    def test_database_cache_resets_on_activation_change(self) -> None:
        self.poll()
        self.monitor._cache_database_page("A", (), {"ABCDEF": "P8"})
        self.monitor._cache_database_page("B", (), {}, {"BBCDEF": {"type_name": "Test aircraft"}})
        self.monitor._type_name_cache = {"P8": "Poseidon"}
        self.monitor._operator_cache = {"ASA": "Alaska Airlines"}
        self.activation = "c" * 32
        self.poll()
        self.assertEqual({}, self.monitor._database_pages)
        self.assertEqual({}, self.monitor._model_cache)
        self.assertEqual({}, self.monitor._aircraft_metadata_cache)
        self.assertEqual({}, self.monitor._aircraft_cache_completeness)
        self.assertIsNone(self.monitor._type_name_cache)
        self.assertIsNone(self.monitor._operator_cache)

    # bind the manifest and transport helper to fixed local database paths
    def test_database_manifest_and_endpoint_validation(self) -> None:
        self.assertEqual("db-3.14.1715", load_database_directory(MAP_UI_MANIFEST_PATH))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "map-ui.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "databaseVersion": "3.14.1715",
                        "base_image_dependency": {"database_directory": "../../private"},
                    }
                )
            )
            with self.assertRaises(ValueError):
                load_database_directory(path)
        with self.assertRaises(ValueError):
            fetch_database_json("http://127.0.0.1:8078/db-3.14.1715/../A.js", "db-3.14.1715")
        with self.assertRaises(ValueError):
            fetch_database_json("http://127.0.0.1:8078/db-3.14.1715/private.js", "db-3.14.1715")

    # decompress native database pages within both byte ceilings
    def test_database_gzip_and_bomb_limits(self) -> None:
        class Response(io.BytesIO):
            # provide the urllib response context interface
            def __enter__(self):
                return self

            # retain ordinary bytesio cleanup
            def __exit__(self, exc_type, exc, traceback):
                self.close()

        class Opener:
            # return one fixed response body
            def __init__(self, content: bytes) -> None:
                self.content = content

            # ignore the already validated fixed request parameters
            def open(self, url: str, timeout: float) -> Response:
                return Response(self.content)

        url = "http://127.0.0.1:8078/db-3.14.1715/A.js"
        content = gzip.compress(json.dumps({"BCDEF": [None, "P8", "10", None]}).encode())
        with patch("adsb_admin.alert_sources.build_opener", return_value=Opener(content)):
            self.assertIn("BCDEF", fetch_database_json(url, "db-3.14.1715"))
            named = "http://127.0.0.1:8078/db-3.14.1715/operators.js"
            self.assertIn("BCDEF", fetch_database_json(named, "db-3.14.1715"))
        bomb = gzip.compress(b" " * (MAX_JSON_BYTES + 1))
        with patch("adsb_admin.alert_sources.build_opener", return_value=Opener(bomb)):
            with self.assertRaises(ValueError):
                fetch_database_json(url, "db-3.14.1715")


# support direct targeted verification
if __name__ == "__main__":
    unittest.main()
