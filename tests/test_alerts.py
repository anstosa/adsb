"""Encounter engine and worker orchestration tests."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from adsb_admin.alert_catalog import AlertCatalog
from adsb_admin.alert_config import AlertSettingsStore
from adsb_admin.alert_delivery import DeliveryResult
from adsb_admin.alert_store import AlertStore
from adsb_admin.alerts import AlertEngine, AlertWorker, dispatch_delivery, read_test_envelope
from adsb_admin.maintenance import IMAGE_NAMES

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# exercise normalized physical-source encounter behavior
class AlertEngineTest(unittest.TestCase):
    # create one isolated engine
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = AlertStore(self.root / "alerts.sqlite3")
        self.catalog = AlertCatalog.from_paths(
            PROJECT_ROOT / "deploy/alerts/catalog.json",
            PROJECT_ROOT / "deploy/alerts/catalog-manifest.json",
        )
        self.engine = AlertEngine(self.store, self.catalog)
        self.settings = {
            "schema_version": 1,
            "revision": 1,
            "enabled": True,
            "categories": ["military", "medical", "news"],
            "pushover": {"app_token": "a", "user_key": "u"},
            "smtp": {
                "host": "smtp.example.com",
                "port": 465,
                "username": "user",
                "password": "password",
                "from_address": "alerts@example.com",
                "to_address": "operator@example.net",
            },
            "overrides": [],
        }

    # close isolated state
    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    # build one normalized source sample
    def sample(
        self,
        mono: float,
        *,
        band: str = "1090",
        messages: int | None = None,
        fresh: bool = False,
        healthy: bool = True,
        coverage_since: float = 0.0,
        coverage_until: float | None = None,
        reception: str = "direct",
        observed_at: float | None = None,
    ) -> dict:
        aircraft = []
        # include one exact news aircraft when requested
        if messages is not None:
            row = {
                "hex": "A2CCA7",
                "messages": messages,
                "observed_at": 1_000.0 + mono if observed_at is None else observed_at,
                "reception": reception,
            }
            # expose adapter-proven progress explicitly
            if fresh:
                row["fresh"] = True
            aircraft.append(row)
        return {
            "band": band,
            "generation": f"generation-{band}",
            "observed_at": 1_000.0 + mono,
            "healthy": healthy,
            "expected": True,
            "coverage_state": "healthy" if healthy else "unknown",
            "coverage_since": coverage_since,
            "coverage_until": mono if coverage_until is None else coverage_until,
            "aircraft": aircraft,
        }

    # create one overlapping event only from fresh physical progress
    def test_startup_snapshot_does_not_replay_and_repeated_updates_stay_one_event(self) -> None:
        created = self.engine.process_samples([self.sample(0, messages=1)], self.settings, 1_000.0, 0.0)
        self.assertEqual([], created)
        created = self.engine.process_samples([self.sample(1, messages=2)], self.settings, 1_001.0, 1.0)
        self.assertEqual(1, len(created))
        created = self.engine.process_samples([self.sample(31, messages=3)], self.settings, 1_031.0, 31.0)
        self.assertEqual([], created)
        history = self.store.history()["events"]
        self.assertEqual(1, len(history))
        self.assertEqual(["news"], history[0]["categories"])
        self.assertEqual({"1090": "direct"}, history[0]["receptions"])

    # rearm only at six hundred seconds of finalized continuous absence
    def test_exact_six_hundred_second_absence_rearms(self) -> None:
        self.engine.process_samples([self.sample(0, messages=1)], self.settings, 1_000.0, 0.0)
        self.engine.process_samples([self.sample(1, messages=2)], self.settings, 1_001.0, 1.0)
        self.engine.process_samples([self.sample(600)], self.settings, 1_600.0, 600.0)
        self.engine.process_samples([self.sample(601)], self.settings, 1_601.0, 601.0)
        self.engine.process_samples([self.sample(602, messages=3)], self.settings, 1_602.0, 602.0)
        self.assertEqual(2, len(self.store.history()["events"]))

    # use actual local observation time rather than a later polling boundary
    def test_return_just_inside_boundary_does_not_rearm_at_later_poll(self) -> None:
        self.engine.process_samples([self.sample(0, messages=1)], self.settings, 1_000.0, 0.0)
        self.engine.process_samples([self.sample(1, messages=2)], self.settings, 1_001.0, 1.0)
        self.engine.process_samples(
            [self.sample(601, messages=3, fresh=True, observed_at=1_600.5)],
            self.settings,
            1_601.0,
            601.0,
        )
        self.assertEqual(1, len(self.store.history()["events"]))

    # an earlier return on either band vetoes rearming the merged sighting
    def test_cross_band_first_observation_fences_boundary(self) -> None:
        self.engine.process_samples([self.sample(0), self.sample(0, band="978")], self.settings, 1000, 0)
        self.engine.process_samples(
            [self.sample(1, messages=2, fresh=True), self.sample(1, band="978")], self.settings, 1001, 1
        )
        self.engine.process_samples(
            [
                self.sample(602, messages=3, fresh=True, observed_at=1600.5),
                self.sample(602, band="978", messages=2, fresh=True, observed_at=1602),
            ],
            self.settings,
            1602,
            602,
        )
        self.assertEqual(1, len(self.store.history()["events"]))

    # pending adjudication must merge delayed earlier evidence before creating another event
    def test_pending_cross_band_earlier_return_vetoes_new_event(self) -> None:
        self.engine.process_samples([self.sample(0), self.sample(0, band="978")], self.settings, 1000, 0)
        self.engine.process_samples(
            [self.sample(1, messages=2, fresh=True), self.sample(1, band="978")], self.settings, 1001, 1
        )
        self.engine.process_samples(
            [
                self.sample(601, messages=3, fresh=True, coverage_until=599),
                self.sample(601, band="978", coverage_until=599),
            ],
            self.settings,
            1601,
            601,
        )
        self.engine.process_samples(
            [
                self.sample(602),
                self.sample(602, band="978", messages=2, fresh=True, observed_at=1600.5),
            ],
            self.settings,
            1602,
            602,
        )
        self.assertEqual(1, len(self.store.history()["events"]))

    # newly present radios add durable obligations before an existing absence can rearm
    def test_new_band_requires_a_full_new_coverage_interval(self) -> None:
        self.engine.process_samples([self.sample(0)], self.settings, 1000, 0)
        self.engine.process_samples([self.sample(1, messages=2, fresh=True)], self.settings, 1001, 1)
        self.assertEqual({"1090"}, self.store.active_encounters()[0]["required_bands"])
        self.engine.process_samples([self.sample(599), self.sample(599, band="978")], self.settings, 1599, 599)
        self.assertEqual({"1090", "978"}, self.store.active_encounters()[0]["required_bands"])
        self.engine.process_samples([self.sample(601), self.sample(601, band="978")], self.settings, 1601, 601)
        self.engine.process_samples(
            [self.sample(602), self.sample(602, band="978", messages=2, fresh=True)], self.settings, 1602, 602
        )
        self.assertEqual(1, len(self.store.history()["events"]))
        self.engine.process_samples([self.sample(1202), self.sample(1202, band="978")], self.settings, 2202, 1202)
        self.engine.process_samples(
            [self.sample(1203), self.sample(1203, band="978", messages=3, fresh=True)], self.settings, 2203, 1203
        )
        self.assertEqual(2, len(self.store.history()["events"]))

    # prevent unknown source time from proving absence
    def test_source_gap_resets_absence_and_missing_band_sample_is_unknown(self) -> None:
        self.engine.process_samples(
            [self.sample(0, band="1090"), self.sample(0, band="978")], self.settings, 1_000.0, 0.0
        )
        self.engine.process_samples(
            [self.sample(1, band="1090", messages=1, fresh=True), self.sample(1, band="978")],
            self.settings,
            1_001.0,
            1.0,
        )
        # omit 978 entirely while 1090 remains healthy
        self.engine.process_samples([self.sample(700, band="1090")], self.settings, 1_700.0, 700.0)
        self.engine.process_samples(
            [self.sample(701, band="1090", messages=2, fresh=True), self.sample(701, band="978", coverage_since=701)],
            self.settings,
            1_701.0,
            701.0,
        )
        self.assertEqual(1, len(self.store.history()["events"]))
        # a new complete 978 coverage epoch must run for another full interval
        self.engine.process_samples(
            [self.sample(1_301, band="1090"), self.sample(1_301, band="978", coverage_since=701)],
            self.settings,
            2_301.0,
            1_301.0,
        )
        self.engine.process_samples(
            [
                self.sample(1_302, band="1090", messages=3, fresh=True),
                self.sample(1_302, band="978", coverage_since=701),
            ],
            self.settings,
            2_302.0,
            1_302.0,
        )
        self.assertEqual(2, len(self.store.history()["events"]))

    # record honest local rebroadcast provenance in event history
    def test_rebroadcast_reception_is_preserved(self) -> None:
        self.engine.process_samples([self.sample(0, band="978")], self.settings, 1_000.0, 0.0)
        self.engine.process_samples(
            [self.sample(1, band="978", messages=1, fresh=True, reception="rebroadcast")],
            self.settings,
            1_001.0,
            1.0,
        )
        event = self.store.history()["events"][0]
        self.assertEqual({"978": "rebroadcast"}, event["receptions"])

    # retain observation state while disabled without replaying old work
    def test_disabled_encounter_notifies_only_on_subsequent_fresh_enabled_update(self) -> None:
        disabled = dict(self.settings)
        disabled["enabled"] = False
        self.engine.process_samples([self.sample(0)], disabled, 1_000.0, 0.0)
        self.engine.process_samples([self.sample(1, messages=1, fresh=True)], disabled, 1_001.0, 1.0)
        self.assertEqual([], self.store.history()["events"])
        self.engine.process_samples([self.sample(2, messages=2, fresh=True)], self.settings, 1_002.0, 2.0)
        self.assertEqual(1, len(self.store.history()["events"]))


# verify aircraft push links without contacting notification providers
class AlertDispatchTest(unittest.TestCase):
    # carry the triggering identity through the encoded provider request
    def test_aircraft_push_includes_selected_aircraft_map_link(self) -> None:
        # normalize casing without confusing distinct triggering aircraft
        for hex_id, url_hex in (("A2CCA7", "a2cca7"), ("a2CcA7", "a2cca7"), ("AE1234", "ae1234")):
            with self.subTest(hex_id=hex_id):
                job = {
                    "kind": "aircraft",
                    "channel": "pushover",
                    "hex": hex_id,
                    "label": "News helicopter",
                    "categories": ["news"],
                    "bands": ["1090"],
                    "receptions": {"1090": "direct"},
                }
                settings = {"pushover": {"app_token": "fixture-app", "user_key": "fixture-user"}}
                with mock.patch(
                    "adsb_admin.alert_delivery._pushover_request", return_value=(200, {}, b'{"status":1}')
                ) as request:
                    result = dispatch_delivery(job, settings)
                self.assertEqual("accepted", result.state)
                request.assert_called_once()
                form = urllib.parse.parse_qs(request.call_args.args[0].decode("utf-8"))
                self.assertEqual([f"https://adsb.ballydidean.farm/map/?icao={url_hex}"], form["url"])
                self.assertEqual(["Open aircraft map"], form["url_title"])
                self.assertEqual(["0"], form["priority"])
                self.assertIn(hex_id, form["message"][0])

    # omit aircraft links for tests and untrusted identities
    def test_push_links_require_a_genuine_aircraft_with_an_exact_icao(self) -> None:
        # reject missing anonymous and query-injecting identities without changing delivery
        for kind, hex_id in (
            ("test", None),
            ("test", "A2CCA7"),
            ("aircraft", None),
            ("aircraft", "~A2CCA7"),
            ("aircraft", "A2CCA7&icao=abcdef"),
        ):
            with self.subTest(kind=kind, hex_id=hex_id):
                job = {
                    "kind": kind,
                    "channel": "pushover",
                    "hex": hex_id,
                    "label": "Fixture",
                    "categories": ["news"],
                    "bands": ["1090"],
                    "receptions": {"1090": "direct"},
                }
                settings = {"pushover": {"app_token": "fixture-app", "user_key": "fixture-user"}}
                with mock.patch(
                    "adsb_admin.alert_delivery._pushover_request", return_value=(200, {}, b'{"status":1}')
                ) as request:
                    result = dispatch_delivery(job, settings)
                self.assertEqual("accepted", result.state)
                request.assert_called_once()
                form = urllib.parse.parse_qs(request.call_args.args[0].decode("utf-8"))
                self.assertNotIn("url", form)
                self.assertNotIn("url_title", form)


# verify independent maintenance scheduling without providers or physical traffic
class MaintenanceWorkerTest(unittest.TestCase):
    # create a smtp-only station with private isolated state
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.wall = 1_000.0
        self.mono = 0.0
        self.sent = []
        self.config = AlertSettingsStore(self.root / "config/alerts.json")
        self.config.update(
            {
                "revision": 0,
                "enabled": False,
                "categories": ["military", "medical", "news"],
                "pushover": {"app_token": "", "user_key": ""},
                "smtp": {
                    "host": "smtp.example.com",
                    "port": 465,
                    "username": "user",
                    "password": "password",
                    "from_address": "alerts@example.com",
                    "to_address": "operator@example.net",
                },
                "overrides": [],
            }
        )
        self.store = AlertStore(self.root / "state/alerts.sqlite3")
        self.catalog = AlertCatalog.from_paths(
            PROJECT_ROOT / "deploy/alerts/catalog.json", PROJECT_ROOT / "deploy/alerts/catalog-manifest.json"
        )
        self.report = self.root / "maintenance.json"

        # provide no radio sightings while software notifications continue
        class Monitor:
            # keep absent radios independent of smtp-only maintenance
            def poll(self, **_kwargs):
                return []

            # retain one fresh bounded heartbeat identity
            def status(self):
                return {"activation_id": "a" * 32, "source_contract_digest": "b" * 64, "bands": {}}

        # record local dispatch requests without contacting notification providers
        def dispatcher(job, _settings):
            self.sent.append(job)
            return DeliveryResult("accepted")

        self.worker = AlertWorker(
            config_store=self.config,
            store=self.store,
            catalog=self.catalog,
            source_monitor=Monitor(),
            status_path=self.root / "state/worker-status.json",
            continuity_path=self.root / "state/continuity.json",
            maintenance_report_path=self.report,
            wall_clock=lambda: self.wall,
            mono_clock=lambda: self.mono,
            dispatcher=dispatcher,
        )

    # close all bounded sender threads before removing private fixtures
    def tearDown(self):
        self.flush()
        self.store.close()
        self.temporary.cleanup()

    # finish only isolated fake delivery work
    def flush(self):
        # wait for both existing pools so callbacks are durable before assertions
        for pool in self.worker._pools.values():
            pool.shutdown(wait=True)
        self.worker._drain_reports()

    # write one valid bounded review fixture at the injected clock
    def write_report(self, at, *, state="ok"):
        value = {
            "updated_at": datetime.fromtimestamp(at, timezone.utc).isoformat(),
            "status": state,
            "reboot_required": False,
            "disk_free_percent": 50.0,
            "removed_expired_artifacts": 2,
            "images": [{"name": name, "review_ref": "example/image", "status": "current"} for name in IMAGE_NAMES],
            "map_status": "current",
        }
        # make ordinary review failures explicit rather than successful empty evidence
        if state == "failed":
            value.update(reboot_required=None, disk_free_percent=None, images=[], map_status="unknown")
        # expose a real candidate in the attention fixture
        elif state == "attention":
            value["images"][0]["status"] = "review"
        self.report.write_text(json.dumps(value))

    # move beyond the bounded maintenance and heartbeat polling intervals
    def tick(self):
        self.wall += 11
        self.mono += 11
        self.worker.run_once()

    # send a new software review even with aircraft disabled and pushover absent
    def test_maintenance_email_is_independent_and_deduplicated(self):
        self.write_report(990)
        self.worker.run_once()
        self.assertEqual([], self.sent)
        self.write_report(1_005, state="attention")
        self.tick()
        self.flush()
        self.assertEqual(1, len(self.sent))
        self.assertEqual(("maintenance", "email"), (self.sent[0]["kind"], self.sent[0]["channel"]))
        self.assertIn("Review needed", self.sent[0]["subject"])
        self.assertIn("Update candidate needs review", self.sent[0]["body"])
        self.assertIn("does not verify whether OS updates were installed", self.sent[0]["body"])
        self.assertEqual([], self.store.history()["events"])
        self.tick()
        self.assertEqual(1, len(self.sent))
        status = json.loads(self.worker.status_path.read_text())
        self.assertFalse(status["enabled"])
        self.assertEqual("accepted", status["maintenance_email"]["state"])

    # freeze a completed review before a newer report replaces the source file
    def test_maintenance_message_snapshot_and_safe_failed_summary(self):
        self.write_report(990)
        self.worker.run_once()
        self.write_report(1_005, state="failed")
        self.tick()
        self.write_report(1_006, state="ok")
        self.flush()
        self.assertEqual(1, len(self.sent))
        self.assertIn("Run failed", self.sent[0]["subject"])
        self.assertIn("Disk free: Unknown", self.sent[0]["body"])
        self.assertIn("Check unavailable", self.sent[0]["body"])
        self.assertNotIn("Review current", self.sent[0]["body"])

    # leave malformed and stale source files non-actionable
    def test_maintenance_invalid_report_is_not_emailed(self):
        self.write_report(990)
        self.worker.run_once()
        self.report.write_text('{"updated_at":"secret","status":"ok"}')
        self.tick()
        self.assertEqual([], self.sent)
        self.assertEqual("waiting", self.store.maintenance_status()["state"])

    # ignore fresh incomplete evidence without consuming a corrected report generation
    def test_maintenance_unknown_report_can_be_corrected_without_replay(self):
        self.write_report(990)
        self.worker.run_once()
        stamp = datetime.fromtimestamp(1_005, timezone.utc).isoformat()
        # incomplete success and explicit unknown states cannot create external work
        for state in ("ok", "unknown", "failed"):
            with self.subTest(state=state):
                self.report.write_text(json.dumps({"updated_at": stamp, "status": state}))
                self.tick()
                self.assertEqual([], self.sent)
                self.assertEqual("waiting", self.store.maintenance_status()["state"])
        self.write_report(1_005, state="attention")
        self.tick()
        self.flush()
        self.assertEqual(1, len(self.sent))
        self.assertIn("Review needed", self.sent[0]["subject"])

    # never dispatch through stale credentials after a failed configuration refresh
    def test_maintenance_configuration_failure_blocks_and_does_not_replay(self):
        self.write_report(990)
        self.worker.run_once()
        self.write_report(1_005)
        with mock.patch.object(self.config, "refresh", side_effect=RuntimeError("unavailable")):
            self.tick()
        self.assertEqual([], self.sent)
        self.tick()
        self.assertEqual([], self.sent)
        self.assertEqual("waiting", self.store.maintenance_status()["state"])

    # use the fixed smtp transport and reject any maintenance push route
    def test_maintenance_dispatch_uses_email_only(self):
        job = {
            "kind": "maintenance",
            "channel": "email",
            "subject": "Fixed subject",
            "body": "Fixed body",
            "message_id": "<fixture.email@example.com>",
        }
        with mock.patch("adsb_admin.alerts.send_email", return_value=DeliveryResult("accepted")) as email:
            with mock.patch("adsb_admin.alerts.send_pushover") as push:
                result = dispatch_delivery(job, self.config.get_private())
                self.assertEqual("accepted", result.state)
                email.assert_called_once()
                self.assertEqual("Fixed subject", email.call_args.kwargs["subject"])
                self.assertEqual("Fixed body", email.call_args.kwargs["body"])
                job["channel"] = "pushover"
                self.assertEqual("failed", dispatch_delivery(job, self.config.get_private()).state)
                push.assert_not_called()


# verify worker scheduling without network calls
class AlertWorkerTest(unittest.TestCase):
    # keep provider work off the source polling thread
    def test_slow_delivery_does_not_block_source_polling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_store = AlertSettingsStore(root / "config/alerts.json")
            payload = {
                "revision": 0,
                "enabled": True,
                "categories": ["news"],
                "pushover": {"app_token": "a", "user_key": "u"},
                "smtp": {
                    "host": "smtp.example.com",
                    "port": 465,
                    "username": "user",
                    "password": "password",
                    "from_address": "alerts@example.com",
                    "to_address": "operator@example.net",
                },
                "overrides": [],
            }
            config_store.update(payload)
            store = AlertStore(root / "state/alerts.sqlite3")
            catalog = AlertCatalog.from_paths(
                PROJECT_ROOT / "deploy/alerts/catalog.json",
                PROJECT_ROOT / "deploy/alerts/catalog-manifest.json",
            )

            # produce one adapter-proven fresh observation
            class Monitor:
                activation_id = "activation"
                contract_digest = "digest"

                # return one healthy sample per poll
                def poll(self, **_kwargs):
                    return [
                        {
                            "band": "1090",
                            "generation": "g",
                            "observed_at": 1_001.0,
                            "healthy": True,
                            "expected": True,
                            "coverage_state": "healthy",
                            "coverage_since": 0.0,
                            "coverage_until": 1.0,
                            "aircraft": [{"hex": "A2CCA7", "messages": 1, "fresh": True, "observed_at": 1_001.0}],
                        }
                    ]

                # project fixed source identity
                def status(self):
                    return {"activation_id": self.activation_id, "source_contract_digest": self.contract_digest}

            wall = [1_001.0]
            mono = [1.0]

            # emulate one provider that blocks outside polling
            def slow_dispatch(_job, _settings):
                time.sleep(0.15)
                return DeliveryResult("accepted")

            worker = AlertWorker(
                config_store=config_store,
                store=store,
                catalog=catalog,
                source_monitor=Monitor(),
                status_path=root / "state/worker-status.json",
                continuity_path=root / "state/continuity.json",
                wall_clock=lambda: wall[0],
                mono_clock=lambda: mono[0],
                dispatcher=slow_dispatch,
            )
            started = time.monotonic()
            worker.run_once()
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.1)
            self.assertEqual(1, len(store.history()["events"]))
            # stop sender pools without starting the run loop
            for pool in worker._pools.values():
                pool.shutdown(wait=True)
            worker._drain_reports()
            states = {channel["state"] for channel in store.history()["events"][0]["channels"].values()}
            self.assertEqual({"accepted"}, states)
            status = json.loads((root / "state/worker-status.json").read_text(encoding="utf-8"))
            self.assertTrue(status["process_running"])
            self.assertEqual("activation", status["activation_id"])
            store.close()

    # accept only the flat fixed test-envelope contract
    def test_test_envelope_is_bounded_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "test.json"
            value = {
                "schema_version": 1,
                "request_id": "02bc8f46-1ea5-4e9f-b99f-17dff8c4201d",
                "revision": 3,
                "created_at": 100.0,
                "last_requested_at": 100.0,
            }
            path.write_text(json.dumps(value), encoding="utf-8")
            request = read_test_envelope(path)
            self.assertEqual(value["request_id"], request["id"])
            value["message"] = "arbitrary"
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertIsNone(read_test_envelope(path))
            path.write_text("[" * 1500 + "0" + "]" * 1500)
            self.assertIsNone(read_test_envelope(path))


# run focused checks directly
if __name__ == "__main__":
    unittest.main()
