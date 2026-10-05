"""Fail-closed physical source, progression and coverage contract tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from adsb_admin.alert_sources import AlertSourceMonitor, normalize_aircraft, read_json

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
        self.monitor = AlertSourceMonitor(
            root=self.root,
            manifest_path=ROOT / "deploy/alerts/source-contract.json",
            fetcher=self.fetch,
        )

    # release isolated fixtures
    def tearDown(self) -> None:
        self.temporary.cleanup()

    # publish one independent fixed producer sample
    def fetch(self, url: str) -> dict:
        return {**self.metadata, "now": self.wall}

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
    def poll(self, seconds: float = 1, *, finalize: bool = False) -> list[dict]:
        self.wall += seconds
        # publish a new finalized decoder interval only when requested
        if finalize:
            self.end = self.wall
        self.write()
        return self.monitor.poll(now_wall=self.wall, now_mono=self.wall - 900)

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
        self.assertFalse(self.monitor.poll(now_wall=self.wall, now_mono=100)[0]["healthy"])

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
        self.metadata["aircraft"] = [{"hex": "abcdef", "dbFlags": 1}, {"hex": "aaaaaa", "dbFlags": 1}]
        self.assertEqual([], self.poll()[0]["aircraft"])
        self.aircraft["1090"] = [{"hex": "abcdef", "messages": 2, "seen": 0}]
        self.accepted["1090"] = 2
        row = self.poll()[0]["aircraft"][0]
        self.assertEqual(1, row["dbFlags"])
        self.assertEqual("ABCDEF", row["hex"])


# support direct targeted verification
if __name__ == "__main__":
    unittest.main()
