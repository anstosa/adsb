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
from adsb_admin.alert_sources import normalize_aircraft
from adsb_admin.alert_store import AlertStore
from adsb_admin.alerts import AlertEngine, AlertWorker, _message_for_job, dispatch_delivery, read_test_envelope
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
            "category_channels": {
                "military": ["pushover", "email"],
                "medical": ["pushover", "email"],
                "news": ["pushover", "email"],
            },
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
        model: str | None = None,
        distance_mi: float | None = 1.0,
    ) -> dict:
        aircraft = []
        # include one exact news aircraft when requested
        if messages is not None:
            row = {
                "hex": "A2CCA7",
                "messages": messages,
                "observed_at": 1_000.0 + mono if observed_at is None else observed_at,
                "reception": reception,
                "distance_mi": distance_mi,
                "position_observed_at": 1_000.0 + mono,
                "speed_knots": 100.0,
                "heading_degrees": 337.5,
                "altitude_feet": 12500.0,
            }
            # expose adapter-proven progress explicitly
            if fresh:
                row["fresh"] = True
            # expose optional map-joined model enrichment
            if model is not None:
                row["model"] = model
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

    # wait for first entry rather than consuming the encounter outside the radius
    def test_outside_detection_alerts_only_after_five_mile_entry(self) -> None:
        self.engine.process_samples([self.sample(1, messages=2, fresh=True, distance_mi=5.001)], self.settings, 1001, 1)
        self.assertEqual([], self.store.history()["events"])
        created = self.engine.process_samples(
            [self.sample(2, messages=3, fresh=True, distance_mi=5.0)], self.settings, 1002, 2
        )
        self.assertEqual(1, len(created))
        self.assertEqual(1, len(self.store.history()["events"]))

    # retain physical continuity across out-of-range and unknown-position sightings
    def test_outside_and_missing_positions_never_rearm_a_present_aircraft(self) -> None:
        self.engine.process_samples([self.sample(1, messages=2, fresh=True)], self.settings, 1001, 1)
        # keep each fresh physical sighting in the same encounter
        for mono, distance in ((400, 10.0), (800, None), (1200, 12.0), (1600, 1.0)):
            created = self.engine.process_samples(
                [self.sample(mono, messages=mono, fresh=True, distance_mi=distance)], self.settings, 1000 + mono, mono
            )
            self.assertEqual([], created)
        self.assertEqual(1, len(self.store.history()["events"]))

    # refuse uncertain positions without refusing reception continuity
    def test_missing_invalid_stale_and_ground_positions_do_not_alert(self) -> None:
        # reject each independent source of proximity uncertainty
        for distance, position_at, ground in (
            (None, 1001, False),
            (True, 1001, False),
            (-1, 1001, False),
            (float("nan"), 1001, False),
            (1, 995.9, False),
            (1, 1003, False),
            (1, 1001, True),
        ):
            with self.subTest(distance=distance, position_at=position_at, ground=ground):
                sample = self.sample(1, messages=2, fresh=True, distance_mi=distance)
                sample["aircraft"][0].update(position_observed_at=position_at, on_ground=ground)
                self.assertEqual([], self.engine.process_samples([sample], self.settings, 1001, 1))
        self.assertEqual([], self.store.history()["events"])
        self.assertEqual(1, len(self.store.active_encounters()))

    # choose the newest physical position independent of band iteration order
    def test_cross_band_newest_position_controls_radius(self) -> None:
        inside = self.sample(1, messages=2, fresh=True, distance_mi=1.0)
        outside = self.sample(1, band="978", messages=2, fresh=True, distance_mi=10.0)
        inside["aircraft"][0]["position_observed_at"] = 1000.0
        outside["aircraft"][0]["position_observed_at"] = 1001.0
        self.assertEqual([], self.engine.process_samples([outside, inside], self.settings, 1001, 1))
        self.assertEqual([], self.store.history()["events"])

    # refuse equally fresh cross-band position disagreements
    def test_cross_band_equal_time_conflicting_positions_do_not_alert(self) -> None:
        inside = self.sample(1, messages=2, fresh=True, distance_mi=1.0)
        outside = self.sample(1, band="978", messages=2, fresh=True, distance_mi=10.0)
        self.assertEqual([], self.engine.process_samples([inside, outside], self.settings, 1001, 1))

    # keep coordinate-conflict detection intact with compact candidate provenance
    def test_equal_distance_different_coordinates_cannot_prove_proximity(self) -> None:
        inside = self.sample(1, messages=2, fresh=True, distance_mi=1.0)
        overlap = self.sample(1, band="978", messages=2, fresh=True, distance_mi=1.0)
        inside["aircraft"][0].update(latitude=47.95, longitude=-122.42)
        overlap["aircraft"][0].update(latitude=47.96, longitude=-122.42)
        self.assertEqual([], self.engine.process_samples([inside, overlap], self.settings, 1001, 1))

    # preserve a qualifying return while finalized receiver coverage catches up
    def test_pending_inside_return_keeps_detection_time_freshness_after_six_seconds(self) -> None:
        self.engine.process_samples([self.sample(1, messages=2, fresh=True)], self.settings, 1001, 1)
        returned = self.sample(601, messages=3, fresh=True, coverage_until=599)
        self.engine.process_samples([returned], self.settings, 1601, 601)
        self.assertTrue(self.engine._pending_returns)
        created = self.engine.process_samples([self.sample(607, coverage_until=607)], self.settings, 1607, 607)
        self.assertEqual(1, len(created))
        self.assertEqual(2, len(self.store.history()["events"]))

    # newer unknown or outside positions invalidate a delayed inside decision
    def test_pending_return_tracks_newer_outside_or_unknown_position(self) -> None:
        # exercise both later unknown and outside positions
        for distance in (None, 10.0):
            with self.subTest(distance=distance):
                self.engine.process_samples([self.sample(1, messages=2, fresh=True)], self.settings, 1001, 1)
                self.engine.process_samples(
                    [self.sample(601, messages=3, fresh=True, coverage_until=599)], self.settings, 1601, 601
                )
                latest = self.sample(602, messages=4, fresh=True, coverage_until=599, distance_mi=distance)
                # model the real adapter's absent position timestamp
                if distance is None:
                    latest["aircraft"][0].pop("position_observed_at")
                self.engine.process_samples([latest], self.settings, 1602, 602)
                self.engine.process_samples([self.sample(607, coverage_until=607)], self.settings, 1607, 607)
                self.assertEqual(1, len(self.store.history()["events"]))
                self.store._connection.execute("DELETE FROM outbox")
                self.store._connection.execute("DELETE FROM encounters")
                self.store._connection.execute("DELETE FROM events")
                self.store._connection.commit()
                self.engine = AlertEngine(self.store, self.catalog)

    # never adjudicate an old-center proximity decision after station changes
    def test_center_change_clears_pending_return_and_restarts_absence_proof(self) -> None:
        center = (47.95, -122.42)
        sample = self.sample(1, messages=2, fresh=True)
        sample["location_center"] = center
        sample["aircraft"][0]["location_center"] = center
        self.engine.process_samples([sample], self.settings, 1001, 1)
        returned = self.sample(601, messages=3, fresh=True, coverage_until=599)
        returned["location_center"] = center
        returned["aircraft"][0]["location_center"] = center
        self.engine.process_samples([returned], self.settings, 1601, 601)
        self.assertTrue(self.engine._pending_returns)
        changed = self.sample(602, coverage_until=602)
        changed["location_center"] = (48.2, -122.7)
        self.assertEqual([], self.engine.process_samples([changed], self.settings, 1602, 602))
        self.assertFalse(self.engine._pending_returns)
        self.assertEqual(602, self.engine._absence_floor["A2CCA7"])
        self.assertEqual(1, len(self.store.history()["events"]))

    # require an explicit center for real adapter samples
    def test_missing_center_cannot_alert_with_a_leftover_position(self) -> None:
        sample = self.sample(1, messages=2, fresh=True)
        sample["location_center"] = None
        sample["aircraft"][0]["location_center"] = (47.95, -122.42)
        self.assertEqual([], self.engine.process_samples([sample], self.settings, 1001, 1))

    # carry physical position and flight fields into both provider payloads
    def test_physical_proximity_description_roundtrip(self) -> None:
        center = (47.950927185907794, -122.4281673583383)
        rows = normalize_aircraft(
            {
                "now": 1001,
                "messages": 2,
                "aircraft": [
                    {
                        "hex": "a2cca7",
                        "messages": 2,
                        "seen": 0,
                        "seen_pos": 0,
                        "lat": center[0],
                        "lon": center[1],
                        "gs": 1000,
                        "track": 337.5,
                        "alt_baro": 12500,
                    }
                ],
            },
            now=1001,
            station=center,
        )
        rows[0].update(fresh=True, model="H60", type_name="Sikorsky UH-60 Black Hawk")
        sample = self.sample(1)
        sample.update(aircraft=rows, location_center=center)
        self.assertEqual(1, len(self.engine.process_samples([sample], self.settings, 1001, 1)))
        jobs = self.store.claim_deliveries(now=1002, config_revision=1, enabled=True)
        with (
            mock.patch("adsb_admin.alerts.send_pushover", return_value=DeliveryResult("accepted")) as push,
            mock.patch("adsb_admin.alerts.send_email", return_value=DeliveryResult("accepted")) as email,
        ):
            # send only through isolated mocked providers
            for job in jobs:
                dispatch_delivery(job, self.settings)
        expected = "A2CCA7 Sikorsky UH-60 Black Hawk flying 1,151 mph NNW at 12,500 feet"
        self.assertEqual("News aircraft above Whidbey", push.call_args.kwargs["title"])
        self.assertEqual("News aircraft above Whidbey", email.call_args.kwargs["subject"])
        self.assertEqual(expected, push.call_args.kwargs["message"])
        self.assertEqual(expected, email.call_args.kwargs["body"])

    # freeze flight text independently of later position updates and retries
    def test_both_channel_jobs_keep_the_triggering_flight_snapshot(self) -> None:
        sample = self.sample(1, messages=2, fresh=True)
        sample["aircraft"][0].update(airline="Example Air", type_name="Boeing 737-800", speed_knots=1000)
        self.engine.process_samples([sample], self.settings, 1001, 1)
        jobs = self.store.claim_deliveries(now=1002, config_revision=1, enabled=True)
        expected = ("News aircraft above Whidbey", "Example Air Boeing 737-800 flying 1,151 mph NNW at 12,500 feet")
        self.assertEqual(2, len(jobs))
        # compare both immutable channel snapshots
        for job in jobs:
            self.assertEqual(expected, _message_for_job(job))

    # union category routes into one immutable channel job per provider
    def test_multi_role_engine_event_uses_union_of_category_routes(self) -> None:
        settings = dict(self.settings)
        settings["category_channels"] = {
            "military": [],
            "medical": ["email"],
            "news": ["pushover"],
        }
        settings["overrides"] = [{"hex": "A2CCA7", "mode": "include", "categories": ["medical"], "label": "Multi-role"}]
        self.engine.process_samples([self.sample(0, messages=1)], settings, 1_000.0, 0.0)
        created = self.engine.process_samples([self.sample(1, messages=2)], settings, 1_001.0, 1.0)
        self.assertEqual(1, len(created))
        event = self.store.history()["events"][0]
        self.assertEqual(["medical", "news"], event["categories"])
        self.assertEqual({"pushover", "email"}, set(event["channels"]))

    # apply model overrides only to physical events carrying joined metadata
    def test_model_override_applies_to_a_physical_event(self) -> None:
        settings = dict(self.settings)
        settings["categories"] = ["medical"]
        settings["category_channels"] = {"military": [], "medical": ["email"], "news": []}
        settings["overrides"] = [{"model": "C17", "mode": "include", "categories": ["medical"], "label": "C-17 fleet"}]
        self.engine.process_samples([self.sample(0)], settings, 1_000.0, 0.0)
        created = self.engine.process_samples(
            [self.sample(1, messages=2, fresh=True, model="C17")],
            settings,
            1_001.0,
            1.0,
        )
        self.assertEqual(1, len(created))
        event = self.store.history()["events"][0]
        self.assertEqual(["medical"], event["categories"])
        self.assertEqual("C-17 fleet", event["label"])

    # filter a full mixed rule set without changing matching semantics
    def test_override_matching_filters_unrelated_and_combined_selectors(self) -> None:
        settings = dict(self.settings)
        settings["categories"] = ["medical", "news"]
        settings["category_channels"] = {"military": [], "medical": ["email"], "news": ["email"]}
        # fill the configured maximum with unrelated exact rules
        unrelated = [
            {"hex": f"{index:06X}", "mode": "include", "categories": ["military"], "label": ""}
            for index in range(1_997)
        ]
        settings["overrides"] = [
            *unrelated,
            {
                "hex": "A2CCA7",
                "model": "C17",
                "mode": "include",
                "categories": ["military"],
                "label": "Invalid combined selector",
            },
            {"model": "C17", "mode": "exclude", "categories": ["news"], "label": ""},
            {"hex": "A2CCA7", "mode": "include", "categories": ["medical"], "label": "Exact aircraft"},
        ]
        with mock.patch.object(self.catalog, "classify", wraps=self.catalog.classify) as classify:
            created = self.engine.process_samples(
                [self.sample(1, messages=2, fresh=True, model="C17")],
                settings,
                1_001.0,
                1.0,
            )
        self.assertEqual(1, len(created))
        self.assertEqual(2, len(classify.call_args.kwargs["overrides"]))
        event = self.store.history()["events"][0]
        self.assertEqual(["medical"], event["categories"])
        self.assertEqual("Exact aircraft", event["label"])

    # rebuild matching rules each cycle even when the revision is unchanged
    def test_same_revision_override_replacement_updates_classification(self) -> None:
        settings = dict(self.settings)
        settings["categories"] = ["medical"]
        settings["category_channels"] = {"military": [], "medical": ["email"], "news": []}
        settings["overrides"] = []
        self.engine.process_samples(
            [self.sample(1, messages=2, fresh=True, model="C17")],
            settings,
            1_001.0,
            1.0,
        )
        self.assertEqual([], self.store.history()["events"])
        replacement = {
            **settings,
            "overrides": [{"model": "C17", "mode": "include", "categories": ["medical"], "label": "Replacement rule"}],
        }
        created = self.engine.process_samples(
            [self.sample(2, messages=3, fresh=True, model="C17")],
            replacement,
            1_002.0,
            2.0,
        )
        self.assertEqual(1, len(created))
        self.assertEqual("Replacement rule", self.store.history()["events"][0]["label"])

    # resolve pending returns with the current cycle's replacement rules
    def test_pending_return_uses_current_same_revision_overrides(self) -> None:
        self.engine.process_samples([self.sample(0), self.sample(0, band="978")], self.settings, 1_000.0, 0.0)
        self.engine.process_samples(
            [self.sample(1, messages=2, fresh=True), self.sample(1, band="978")],
            self.settings,
            1_001.0,
            1.0,
        )
        self.engine.process_samples(
            [
                self.sample(601, messages=3, fresh=True, coverage_until=599, model="C17"),
                self.sample(601, band="978", coverage_until=599),
            ],
            self.settings,
            1_601.0,
            601.0,
        )
        replacement = {
            **self.settings,
            "overrides": [
                {"model": "C17", "mode": "exclude", "categories": ["news"], "label": ""},
                {"hex": "A2CCA7", "mode": "include", "categories": ["medical"], "label": "Exact replacement"},
            ],
        }
        created = self.engine.process_samples(
            [self.sample(602, coverage_until=602), self.sample(602, band="978", coverage_until=602)],
            replacement,
            1_602.0,
            602.0,
        )
        self.assertEqual(1, len(created))
        # select the event created under replacement rules
        replacement_event = next(
            event for event in self.store.history()["events"] if event["label"] == "Exact replacement"
        )
        self.assertEqual(["medical"], replacement_event["categories"])

    # suppress model matching when merged physical sources disagree
    def test_conflicting_cross_band_models_fail_closed(self) -> None:
        settings = dict(self.settings)
        settings["categories"] = ["medical"]
        settings["category_channels"] = {"military": [], "medical": ["email"], "news": []}
        settings["overrides"] = [{"model": "C17", "mode": "include", "categories": ["medical"], "label": "C-17 fleet"}]
        self.engine.process_samples([self.sample(0), self.sample(0, band="978")], settings, 1_000.0, 0.0)
        created = self.engine.process_samples(
            [
                self.sample(1, messages=2, fresh=True, model="C17"),
                self.sample(1, band="978", messages=2, fresh=True, model="H60"),
            ],
            settings,
            1_001.0,
            1.0,
        )
        self.assertEqual([], created)
        self.assertEqual([], self.store.history()["events"])

    # carry model conflicts into a delayed-return candidate
    def test_pending_return_retains_model_conflict(self) -> None:
        self.engine.process_samples([self.sample(0), self.sample(0, band="978")], self.settings, 1_000.0, 0.0)
        self.engine.process_samples(
            [self.sample(1, messages=2, fresh=True), self.sample(1, band="978")],
            self.settings,
            1_001.0,
            1.0,
        )
        self.engine.process_samples(
            [
                self.sample(601, messages=3, fresh=True, coverage_until=599, model="C17"),
                self.sample(601, band="978", coverage_until=599),
            ],
            self.settings,
            1_601.0,
            601.0,
        )
        self.engine.process_samples(
            [
                self.sample(602, coverage_until=599),
                self.sample(602, band="978", messages=2, fresh=True, coverage_until=599, model="H60"),
            ],
            self.settings,
            1_602.0,
            602.0,
        )
        pending = self.engine._pending_returns["A2CCA7"]["candidate"]
        self.assertIsNone(pending["model"])
        self.assertTrue(pending["_model_conflict"])

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
    # format each title and the requested imperial-unit description
    def test_aircraft_notification_format_and_fallbacks(self) -> None:
        # verify every supported title category
        for category in ("medical", "military", "news"):
            job = {
                "kind": "aircraft",
                "hex": "a2cca7",
                "categories": [category],
                "model": "H60",
                "speed_knots": 1000,
                "heading_degrees": 135,
                "altitude_feet": 12345,
            }
            self.assertEqual(
                (f"{category.title()} aircraft above Whidbey", "A2CCA7 H60 flying 1,151 mph SE at 12,345 feet"),
                _message_for_job(job),
            )

    # map all sixteen compass points including north wrapping
    def test_sixteen_point_heading_and_unknown_telemetry(self) -> None:
        directions = (
            "N",
            "NNE",
            "NE",
            "ENE",
            "E",
            "ESE",
            "SE",
            "SSE",
            "S",
            "SSW",
            "SW",
            "WSW",
            "W",
            "WNW",
            "NW",
            "NNW",
        )
        # verify every compass sector
        for index, direction in enumerate(directions):
            job = {
                "kind": "aircraft",
                "hex": "A2CCA7",
                "categories": ["news"],
                "heading_degrees": index * 22.5,
                "speed_knots": 0,
                "altitude_feet": 0,
            }
            self.assertIn(f"0 mph {direction} at 0 feet", _message_for_job(job)[1])
        job.update(heading_degrees=360, speed_knots=float("nan"), altitude_feet=True)
        self.assertIn("unknown speed N at unknown altitude", _message_for_job(job)[1])

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
                self.assertIn(hex_id.upper(), form["message"][0])

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

    # resolve descriptive model metadata for enabled alerts and explicit model rules
    def test_model_resolution_tracks_current_override_configuration(self):
        with mock.patch.object(self.worker.source_monitor, "poll", return_value=[]) as poll:
            self.worker.run_once()
            self.assertFalse(poll.call_args.kwargs["resolve_models"])
            settings = self.config.get_private()
            settings.pop("schema_version")
            settings["overrides"] = [{"model": "H60", "mode": "exclude", "categories": ["military"], "label": ""}]
            self.config.update(settings)
            self.worker.run_once()
            self.assertTrue(poll.call_args.kwargs["resolve_models"])
            settings = self.config.get_private()
            settings.pop("schema_version")
            settings["overrides"] = []
            self.config.update(settings)
            self.worker.run_once()
            self.assertFalse(poll.call_args.kwargs["resolve_models"])

    # enable notification text enrichment without adding a model override
    def test_enabled_alerts_resolve_models_for_flight_descriptions(self):
        settings = self.config.get_private()
        settings.pop("schema_version")
        settings["enabled"] = True
        settings["pushover"] = {"app_token": "fixture", "user_key": "fixture"}
        self.config.update(settings)
        with mock.patch.object(self.worker.source_monitor, "poll", return_value=[]) as poll:
            self.worker.run_once()
        self.assertTrue(poll.call_args.kwargs["resolve_models"])

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

    # deduplicate held candidates and report failed attempts independently
    def test_new_held_and_failure_notices_use_stable_smtp_identity(self):
        self.write_report(990)
        settings = self.config.get_private()
        self.worker._configuration_error = None
        self.worker._process_maintenance(settings, 1000, 10)
        report = {
            "updated_at": datetime.fromtimestamp(1005, timezone.utc).isoformat(),
            "status": "attention",
            "generation": "a" * 64,
            "notice_id": "b" * 64,
            "notify": True,
            "updates": [
                {
                    "id": "c" * 64,
                    "name": "map",
                    "label": "Map",
                    "current_version": "old",
                    "candidate_version": "new",
                    "compatibility": "breaking",
                    "state": "held",
                    "reason": "Basemap removed",
                    "changelog": "Removes a basemap.",
                    "changelog_url": "https://github.com/airplanes-live/tar1090",
                }
            ],
        }
        with mock.patch("adsb_admin.alerts.public_report", return_value=report):
            self.worker._process_maintenance(settings, 1011, 21)
            self.worker._process_maintenance(settings, 1022, 32)
        jobs = self.store.claim_maintenance(now=1022, config_revision=settings["revision"], smtp_configured=True)
        self.assertEqual(1, len(jobs))
        self.assertIn("Updates held", jobs[0]["subject"])
        self.assertIn("Removes a basemap", jobs[0]["body"])
        self.assertIn("https://adsb.ballydidean.farm/admin", jobs[0]["body"])
        self.store.complete_maintenance(jobs[0]["event_id"], DeliveryResult("accepted"), now=1023)
        failed = {
            **report,
            "installation": {
                "state": "rolled_back",
                "request_id": "d" * 64,
                "message": "The previous release was restored.",
            },
        }
        with mock.patch("adsb_admin.alerts.public_report", return_value=failed):
            self.worker._process_maintenance(settings, 1033, 43)
            self.worker._process_maintenance(settings, 1044, 54)
        failures = self.store.claim_maintenance(now=1044, config_revision=settings["revision"], smtp_configured=True)
        self.assertEqual(1, len(failures))
        self.assertIn("Installation failed", failures[0]["subject"])
        self.assertIn("previous release was restored", failures[0]["body"])

    # send a new software review even with aircraft disabled and pushover absent
    def test_missing_update_details_are_held_and_emailed_without_false_success(self):
        self.write_report(990)
        self.worker.run_once()
        report = {
            "updated_at": datetime.fromtimestamp(1005, timezone.utc).isoformat(),
            "status": "attention",
            "generation": "a" * 64,
            "notice_id": "b" * 64,
            "notify": False,
            "updates": [],
            "map_status": "current",
            "images": [{"name": "proxy", "status": "review"}],
        }
        with mock.patch("adsb_admin.alerts.public_report", return_value=report):
            self.tick()
            self.tick()
        self.flush()
        self.assertEqual(1, len(self.sent))
        self.assertIn("Update check unavailable", self.sent[0]["subject"])
        self.assertIn("not installed automatically: proxy", self.sent[0]["body"])

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
    # send requested tests through configured providers regardless of category routes
    def test_requested_test_queues_only_configured_providers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_store = AlertSettingsStore(root / "config/alerts.json")
            config_store.update(
                {
                    "revision": 0,
                    "enabled": True,
                    "categories": ["medical"],
                    "category_channels": {"military": [], "medical": ["email"], "news": []},
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
            store = AlertStore(root / "state/alerts.sqlite3")
            request_path = root / "state/test.json"
            request_id = "02bc8f46-1ea5-4e9f-b99f-17dff8c4201d"
            request_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "request_id": request_id,
                        "revision": 1,
                        "created_at": 100.0,
                        "last_requested_at": 100.0,
                    }
                ),
                encoding="utf-8",
            )
            catalog = AlertCatalog.from_paths(
                PROJECT_ROOT / "deploy/alerts/catalog.json",
                PROJECT_ROOT / "deploy/alerts/catalog-manifest.json",
            )

            # provide the unused source contract for isolated request processing
            class Monitor:
                pass

            worker = AlertWorker(
                config_store=config_store,
                store=store,
                catalog=catalog,
                source_monitor=Monitor(),
                status_path=root / "state/status.json",
                continuity_path=root / "state/continuity.json",
                test_request_path=request_path,
            )
            worker._process_test_request(config_store.get_private(), 101.0)
            self.assertEqual({"email"}, set(store.test_ack(request_id)["channels"]))
            # stop every idle provider pool before removing fixtures
            for pool in worker._pools.values():
                pool.shutdown(wait=True)
            store.close()

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
                            "aircraft": [
                                {
                                    "hex": "A2CCA7",
                                    "messages": 1,
                                    "fresh": True,
                                    "observed_at": 1_001.0,
                                    "distance_mi": 1.0,
                                    "position_observed_at": 1_001.0,
                                }
                            ],
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
