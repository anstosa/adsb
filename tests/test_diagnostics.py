"""Regression checks for source-specific reception telemetry."""

from __future__ import annotations

import unittest
from unittest import mock

from adsb_admin.diagnostics import ReceptionMonitor


# exercise radio status without opening devices or sockets
class ReceptionMonitorTest(unittest.TestCase):
    # build one valid Airspy minute sample
    def airspy_sample(self, now: float, messages: int = 0) -> dict[str, object]:
        counts = [0] * 32
        counts[17] = messages
        return {"now": now, "df_counts": counts}

    # distinguish missing radios and stopped services
    def test_absent_and_stopped_sources_do_not_claim_telemetry(self) -> None:
        monitor = ReceptionMonitor()
        absent = monitor.observe(
            {"airspy": False, "uat": False},
            set(),
            self.airspy_sample(1_800_000_000, 10),
            {"now": 1_800_000_000, "messages": 10},
            now=1_800_000_000,
        )
        self.assertEqual("absent", absent["1090"]["telemetry_state"])
        self.assertEqual("absent", absent["978"]["telemetry_state"])
        stopped = monitor.observe(
            {"airspy": True, "uat": True},
            set(),
            self.airspy_sample(1_800_000_000, 10),
            {"now": 1_800_000_000, "messages": 10},
            now=1_800_000_000,
        )
        self.assertEqual("stopped", stopped["1090"]["telemetry_state"])
        self.assertEqual("stopped", stopped["978"]["telemetry_state"])

    # reject malformed source documents without manufacturing zero traffic
    def test_malformed_telemetry_is_unavailable(self) -> None:
        monitor = ReceptionMonitor()
        status = monitor.observe(
            {"airspy": True, "uat": True},
            {"airspy", "dump978"},
            {"now": 1_800_000_000, "df_counts": [0]},
            {"now": 1_800_000_000, "messages": -1},
            now=1_800_000_000,
        )
        self.assertEqual("unavailable", status["1090"]["telemetry_state"])
        self.assertEqual("unavailable", status["978"]["telemetry_state"])
        self.assertIsNone(status["1090"]["messages_per_minute"])
        self.assertIsNone(status["978"]["messages_per_minute"])

    # separate stale json files from current zero traffic
    def test_stale_source_samples_are_not_reception(self) -> None:
        monitor = ReceptionMonitor()
        stale_time = 1_800_000_000 - 181
        status = monitor.observe(
            {"airspy": True, "uat": True},
            {"airspy", "dump978"},
            self.airspy_sample(stale_time, 50),
            {"now": stale_time, "messages": 500},
            now=1_800_000_000,
        )
        self.assertEqual("stale", status["1090"]["telemetry_state"])
        self.assertEqual("stale", status["978"]["telemetry_state"])
        self.assertIsNone(status["1090"]["last_activity_at"])
        self.assertIsNone(status["978"]["last_activity_at"])

    # contain source timestamps outside the host datetime range
    def test_huge_future_source_timestamp_cannot_escape_projection(self) -> None:
        monitor = ReceptionMonitor()
        status = monitor.observe(
            {"airspy": True, "uat": True},
            {"airspy", "dump978"},
            self.airspy_sample(1e300, 50),
            {"now": 1e300, "messages": 500},
            now=1_800_000_000,
        )
        self.assertEqual("stale", status["1090"]["telemetry_state"])
        self.assertEqual("stale", status["978"]["telemetry_state"])
        self.assertIsNone(status["1090"]["sample_at"])
        self.assertIsNone(status["978"]["sample_at"])

    # treat a current empty Airspy minute as quiet rather than failed
    def test_zero_airspy_traffic_is_quiet(self) -> None:
        monitor = ReceptionMonitor()
        status = monitor.observe(
            {"airspy": True, "uat": False},
            {"airspy"},
            self.airspy_sample(1_800_000_000),
            None,
            now=1_800_000_000,
        )
        self.assertEqual("quiet", status["1090"]["telemetry_state"])
        self.assertEqual(0, status["1090"]["messages_per_minute"])
        self.assertIsNone(status["1090"]["last_activity_at"])

    # report a real Airspy counter while retaining its active sample time
    def test_healthy_airspy_traffic_reports_message_rate(self) -> None:
        monitor = ReceptionMonitor()
        status = monitor.observe(
            {"airspy": True, "uat": False},
            {"airspy"},
            self.airspy_sample(1_800_000_000, 1_234),
            None,
            now=1_800_000_010,
        )
        self.assertEqual("receiving", status["1090"]["telemetry_state"])
        self.assertEqual(1_234, status["1090"]["messages_per_minute"])
        self.assertEqual("2027-01-15T08:00:00Z", status["1090"]["last_activity_at"])
        quiet = monitor.observe(
            {"airspy": True, "uat": False},
            {"airspy"},
            self.airspy_sample(1_800_000_060),
            None,
            now=1_800_000_060,
        )
        self.assertEqual("quiet", quiet["1090"]["telemetry_state"])
        self.assertEqual("2027-01-15T08:00:00Z", quiet["1090"]["last_activity_at"])

    # derive UAT rate only after its cumulative counter advances
    def test_healthy_and_quiet_uat_samples_preserve_last_activity(self) -> None:
        monitor = ReceptionMonitor()
        first = monitor.observe(
            {"airspy": False, "uat": True},
            {"dump978"},
            None,
            {"now": 1_800_000_000, "messages": 100},
            now=1_800_000_000,
        )
        self.assertEqual("monitoring", first["978"]["telemetry_state"])
        self.assertIsNone(first["978"]["last_activity_at"])
        receiving = monitor.observe(
            {"airspy": False, "uat": True},
            {"dump978"},
            None,
            {"now": 1_800_000_010, "messages": 110},
            now=1_800_000_010,
        )
        self.assertEqual("receiving", receiving["978"]["telemetry_state"])
        self.assertEqual(60, receiving["978"]["messages_per_minute"])
        self.assertEqual("2027-01-15T08:00:10Z", receiving["978"]["last_activity_at"])
        quiet = monitor.observe(
            {"airspy": False, "uat": True},
            {"dump978"},
            None,
            {"now": 1_800_000_020, "messages": 110},
            now=1_800_000_020,
        )
        self.assertEqual("quiet", quiet["978"]["telemetry_state"])
        self.assertEqual(0, quiet["978"]["messages_per_minute"])
        self.assertEqual("2027-01-15T08:00:10Z", quiet["978"]["last_activity_at"])

    # rebaseline UAT after missing telemetry or a long sampling gap
    def test_uat_gap_does_not_present_old_activity_as_current_rate(self) -> None:
        monitor = ReceptionMonitor()
        monitor.observe(
            {"airspy": False, "uat": True},
            {"dump978"},
            None,
            {"now": 1_800_000_000, "messages": 100},
            now=1_800_000_000,
        )
        unavailable = monitor.observe(
            {"airspy": False, "uat": True},
            {"dump978"},
            None,
            None,
            now=1_800_000_005,
        )
        self.assertEqual("unavailable", unavailable["978"]["telemetry_state"])
        after_failure = monitor.observe(
            {"airspy": False, "uat": True},
            {"dump978"},
            None,
            {"now": 1_800_000_010, "messages": 120},
            now=1_800_000_010,
        )
        self.assertEqual("monitoring", after_failure["978"]["telemetry_state"])
        self.assertIsNone(after_failure["978"]["messages_per_minute"])
        long_gap = monitor.observe(
            {"airspy": False, "uat": True},
            {"dump978"},
            None,
            {"now": 1_800_000_200, "messages": 500},
            now=1_800_000_200,
        )
        self.assertEqual("monitoring", long_gap["978"]["telemetry_state"])
        self.assertIsNone(long_gap["978"]["messages_per_minute"])

    # avoid even local http requests for inactive receivers
    def test_collect_skips_inactive_receiver_endpoints(self) -> None:
        monitor = ReceptionMonitor()
        with mock.patch("adsb_admin.diagnostics.fetch_json") as fetch:
            monitor.collect({"airspy": False, "uat": True}, {"airspy"}, now=1_800_000_000)
        fetch.assert_not_called()


# run tests directly
if __name__ == "__main__":
    unittest.main()
