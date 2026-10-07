"""Durable notification encounter, outbox, and history tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from adsb_admin.alert_delivery import DeliveryResult
from adsb_admin.alert_store import AlertStore, read_history, read_test_ack


# exercise one isolated sqlite writer
class AlertStoreTest(unittest.TestCase):
    # create one private database
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "alerts"
        self.path = self.root / "alerts.sqlite3"
        self.store = AlertStore(self.path)

    # close and remove isolated state
    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    # create one qualifying observation
    def observe(
        self,
        *,
        observed_at: float = 100.0,
        revision: int = 1,
        hex_id: str = "A2CCA7",
        categories: tuple[str, ...] = ("news",),
        category_channels: dict[str, list[str]] | None = None,
    ) -> str:
        event_id = self.store.observe_aircraft(
            hex_id=hex_id,
            label="News Helicopter",
            categories=categories,
            bands={"1090"},
            required_bands={"1090", "978"},
            observed_at=observed_at,
            config_revision=revision,
            enabled=True,
            category_channels=category_channels,
        )
        self.assertIsNotNone(event_id)
        return event_id or ""

    # preserve presence without consuming a notification outside the radius
    def test_ineligible_observation_can_notify_on_later_entry(self) -> None:
        arguments = {
            "hex_id": "A2CCA7",
            "label": "News Helicopter",
            "categories": ("news",),
            "bands": {"1090"},
            "observed_at": 100,
            "config_revision": 1,
            "enabled": True,
        }
        self.assertIsNone(self.store.observe_aircraft(**arguments, eligible=False))
        self.assertFalse(self.store.active_encounters()[0]["notified"])
        event = self.store.observe_aircraft(
            **{**arguments, "observed_at": 101},
            eligible=True,
            subject="News aircraft above Whidbey",
            body="A2CCA7 H60 flying 115 mph N at 1,000 feet",
        )
        self.assertIsNotNone(event)
        self.assertTrue(self.store.active_encounters()[0]["notified"])

    # carry the original notification text through retry and process restart
    def test_flight_text_snapshot_survives_restart_and_retry(self) -> None:
        subject = "News aircraft above Whidbey"
        body = "Example Air Boeing 737-800 flying 1,151 mph NNW at 12,500 feet"
        event = self.store.observe_aircraft(
            hex_id="A2CCA7",
            label="News",
            categories=("news",),
            bands={"1090"},
            observed_at=100,
            config_revision=1,
            enabled=True,
            subject=subject,
            body=body,
        )
        job = self.store.claim_deliveries(now=101, config_revision=1, enabled=True, channel="email")[0]
        self.store.complete_delivery(event, "email", DeliveryResult("retry", "smtp_unavailable", 5), now=101)
        self.store.close()
        self.store = AlertStore(self.path)
        retried = self.store.claim_deliveries(now=106, config_revision=1, enabled=True, channel="email")[0]
        self.assertEqual((subject, body), (retried["subject"], retried["body"]))
        self.assertEqual(job["message_id"], retried["message_id"])

    # suppress old detection-only jobs while preserving requested test delivery
    def test_additive_flight_migration_suppresses_only_aircraft_backlog(self) -> None:
        self.observe()
        self.store.acknowledge_test(
            "a" * 32, config_revision=1, current_revision=1, created_at=100, now=100, enabled=True
        )
        self.store._connection.execute("ALTER TABLE events DROP COLUMN subject")
        self.store._connection.execute("ALTER TABLE events DROP COLUMN body")
        self.store._connection.commit()
        self.store.close()
        self.store = AlertStore(self.path)
        history = self.store.history()["events"]
        aircraft = next(row for row in history if row["kind"] == "aircraft")
        test = next(row for row in history if row["kind"] == "test")
        self.assertEqual({"suppressed"}, {channel["state"] for channel in aircraft["channels"].values()})
        self.assertEqual({"alert_policy_changed"}, {channel["error"] for channel in aircraft["channels"].values()})
        self.assertEqual({"pending"}, {channel["state"] for channel in test["channels"].values()})
        self.assertEqual(
            {"test"}, {job["kind"] for job in self.store.claim_deliveries(now=101, config_revision=1, enabled=True)}
        )

    # observe one fixed maintenance review without aircraft delivery work
    def maintenance(self, at: float | None, *, now: float, configured: bool = True, revision: int = 1):
        return self.store.observe_maintenance(
            reported_at=at,
            now=now,
            config_revision=revision,
            smtp_configured=configured,
            subject="ADS-B software maintenance: Review current",
            body="Fixed maintenance summary",
        )

    # baseline old reports and queue one independent immutable email per new review
    def test_maintenance_baselines_dedupes_and_never_creates_aircraft_events(self):
        self.assertIsNone(self.maintenance(90, now=100))
        event_id = self.maintenance(110, now=111)
        self.assertIsNotNone(event_id)
        self.assertIsNone(self.maintenance(110, now=112))
        self.assertEqual([], self.store.claim_deliveries(now=112, config_revision=1, enabled=False))
        jobs = self.store.claim_maintenance(now=112, config_revision=1, smtp_configured=True)
        self.assertEqual(1, len(jobs))
        self.assertEqual(("maintenance", "email"), (jobs[0]["kind"], jobs[0]["channel"]))
        self.assertEqual("Fixed maintenance summary", jobs[0]["body"])
        self.assertEqual([], self.store.history()["events"])
        self.assertEqual([], self.store.active_encounters())

    # a review that began before worker startup is new when first published afterward
    def test_maintenance_missing_initial_report_does_not_hide_next_publication(self):
        self.assertIsNone(self.maintenance(None, now=100))
        self.assertIsNotNone(self.maintenance(90, now=101))

    # never replay reviews missed before private smtp configuration
    def test_maintenance_unconfigured_reports_are_seen_without_backlog(self):
        self.maintenance(90, now=100, configured=False)
        self.assertIsNone(self.maintenance(110, now=111, configured=False))
        self.assertIsNone(self.maintenance(110, now=112, configured=True))
        self.assertEqual("waiting", self.store.maintenance_status()["state"])
        self.assertIsNotNone(self.maintenance(120, now=121))

    # suppress queued summaries rather than retargeting changed destinations
    def test_maintenance_configuration_revision_and_clear_fences(self):
        self.maintenance(90, now=100)
        self.maintenance(110, now=111)
        self.assertEqual([], self.store.claim_maintenance(now=112, config_revision=2, smtp_configured=True))
        self.assertEqual("configuration_changed", self.store.maintenance_status()["error"])
        self.maintenance(120, now=121, revision=2)
        self.assertEqual([], self.store.claim_maintenance(now=122, config_revision=2, smtp_configured=False))
        self.assertEqual("smtp_not_configured", self.store.maintenance_status()["error"])

    # unchanged held candidates do not send a new email on weekly rediscovery
    def test_stable_update_notices_deduplicate_and_consume_unconfigured_holds(self):
        self.maintenance(90, now=100)
        arguments = {
            "reported_at": 110,
            "now": 111,
            "config_revision": 1,
            "smtp_configured": True,
            "subject": "Updates held",
            "body": "Fixed held update",
            "notice_id": "a" * 64,
        }
        self.assertIsNotNone(self.store.observe_maintenance(**arguments))
        self.assertIsNone(self.store.observe_maintenance(**{**arguments, "reported_at": 120, "now": 121}))
        self.store.close()
        self.store = AlertStore(self.path)
        self.assertIsNone(self.store.observe_maintenance(**{**arguments, "reported_at": 130, "now": 131}))
        unconfigured = {**arguments, "notice_id": "b" * 64, "smtp_configured": False}
        self.assertIsNone(self.store.observe_maintenance(**unconfigured))
        self.assertIsNone(self.store.observe_maintenance(**{**unconfigured, "smtp_configured": True}))
        suppressed = {**arguments, "notice_id": "c" * 64, "notify": False}
        self.assertIsNone(self.store.observe_maintenance(**suppressed))
        self.assertIsNone(self.store.observe_maintenance(**{**suppressed, "notify": True}))
        self.assertIsNotNone(self.store.observe_maintenance(**{**arguments, "notice_id": "d" * 64}))

    # empty initial discovery must not suppress the first subsequently held update
    def test_initial_current_report_does_not_hide_first_hold(self):
        arguments = {
            "reported_at": 90,
            "now": 100,
            "config_revision": 1,
            "smtp_configured": True,
            "subject": "Maintenance current",
            "body": "No holds",
            "notice_id": "a" * 64,
            "notice_ids": [],
            "notify": False,
        }
        self.assertIsNone(self.store.observe_maintenance(**arguments))
        held = {
            **arguments,
            "reported_at": 110,
            "now": 111,
            "notice_id": "b" * 64,
            "notice_ids": ["c" * 64],
            "notify": True,
        }
        self.assertIsNotNone(self.store.observe_maintenance(**held))
        self.assertIsNone(self.store.observe_maintenance(**held))

    # removing held candidates must not create a new notice for unchanged peers
    def test_removing_a_hold_does_not_email_unchanged_candidates(self):
        self.maintenance(90, now=100)
        arguments = {
            "reported_at": 110,
            "now": 111,
            "config_revision": 1,
            "smtp_configured": True,
            "subject": "Updates held",
            "body": "Fixed held update",
            "notice_id": "a" * 64,
            "notice_ids": ["b" * 64, "c" * 64],
        }
        self.assertIsNotNone(self.store.observe_maintenance(**arguments))
        self.assertIsNone(
            self.store.observe_maintenance(**{**arguments, "notice_id": "d" * 64, "notice_ids": ["c" * 64]})
        )
        self.assertIsNotNone(
            self.store.observe_maintenance(**{**arguments, "notice_id": "e" * 64, "notice_ids": ["c" * 64, "f" * 64]})
        )

    # stable notice baselines preserve the existing no-replay initialization rule
    def test_initial_stable_notice_is_baselined(self):
        arguments = {
            "reported_at": 90,
            "now": 100,
            "config_revision": 1,
            "smtp_configured": True,
            "subject": "Updates held",
            "body": "Fixed held update",
            "notice_id": "a" * 64,
        }
        self.assertIsNone(self.store.observe_maintenance(**arguments))
        self.assertIsNone(self.store.observe_maintenance(**{**arguments, "reported_at": 110, "now": 111}))
        self.assertIsNotNone(self.store.observe_maintenance(**{**arguments, "notice_id": "b" * 64}))

    # preserve retry windows and stable smtp identifiers without duplicate completion
    def test_maintenance_transport_retry_and_acceptance(self):
        self.maintenance(90, now=100)
        event_id = self.maintenance(110, now=111)
        first = self.store.claim_maintenance(now=112, config_revision=1, smtp_configured=True)[0]
        self.assertTrue(
            self.store.complete_maintenance(event_id, DeliveryResult("retry", "smtp_unavailable", 10), now=113)
        )
        self.assertEqual([], self.store.claim_maintenance(now=122, config_revision=1, smtp_configured=True))
        second = self.store.claim_maintenance(now=123, config_revision=1, smtp_configured=True)[0]
        self.assertEqual(first["message_id"], second["message_id"])
        self.assertEqual(2, second["attempt"])
        self.assertTrue(self.store.complete_maintenance(event_id, DeliveryResult("accepted"), now=124))
        self.assertFalse(self.store.complete_maintenance(event_id, DeliveryResult("accepted"), now=125))
        self.assertEqual("accepted", self.store.maintenance_status()["state"])

    # mark interrupted smtp leases unknown while preserving deduplication across restarts
    def test_maintenance_restart_ambiguity_never_resends(self):
        self.maintenance(90, now=100)
        self.maintenance(110, now=111)
        self.store.claim_maintenance(now=112, config_revision=1, smtp_configured=True)
        self.store.close()
        self.store = AlertStore(self.path)
        self.assertIsNone(self.maintenance(110, now=113))
        self.assertEqual([], self.store.claim_maintenance(now=114, config_revision=1, smtp_configured=True))
        self.assertEqual("unknown", self.store.maintenance_status()["state"])
        self.assertEqual("worker_interrupted", self.store.maintenance_status()["error"])

    # bound maintenance storage and retain delivery results for thirty days
    def test_maintenance_capacity_retention_and_deadline(self):
        self.maintenance(90, now=100)
        self.maintenance(110, now=111)
        with mock.patch("adsb_admin.alert_store.MAX_MAINTENANCE_NOTIFICATIONS", 1):
            with self.assertRaisesRegex(RuntimeError, "maintenance notification capacity"):
                self.maintenance(120, now=121)
        self.assertEqual([], self.store.claim_maintenance(now=411, config_revision=1, smtp_configured=True))
        self.assertEqual("expired", self.store.maintenance_status()["state"])
        self.store.purge_history(now=111 + 30 * 86400)
        self.assertEqual("expired", self.store.maintenance_status()["state"])
        self.store.purge_history(now=112 + 30 * 86400)
        self.assertEqual("waiting", self.store.maintenance_status()["state"])
        self.assertIsNotNone(self.maintenance(120, now=112 + 30 * 86400))

    # create one event and exactly two channel jobs per encounter
    def test_repeated_observation_is_one_event_until_rearmed(self) -> None:
        first = self.observe()
        repeated = self.observe(observed_at=130.0)
        self.assertEqual(first, repeated)
        history = self.store.history()
        self.assertEqual(1, len(history["events"]))
        self.assertEqual({"email", "pushover"}, set(history["events"][0]["channels"]))
        self.assertEqual({"1090", "978"}, self.store.active_encounters()[0]["required_bands"])
        self.assertTrue(self.store.mark_rearmed("A2CCA7", rearmed_at=730.0))
        second = self.observe(observed_at=731.0)
        self.assertNotEqual(first, second)
        self.assertEqual(2, len(self.store.history()["events"]))

    # freeze push-only email-only both off and multi-role routing per encounter
    def test_category_routes_create_only_the_union_of_selected_channel_jobs(self) -> None:
        push = self.observe(
            hex_id="A00001",
            categories=("news",),
            category_channels={"military": [], "medical": [], "news": ["pushover"]},
        )
        email = self.observe(
            hex_id="A00002",
            categories=("medical",),
            category_channels={"military": [], "medical": ["email"], "news": []},
        )
        both = self.observe(
            hex_id="A00003",
            categories=("military",),
            category_channels={"military": ["pushover", "email"], "medical": [], "news": []},
        )
        multi_role = self.observe(
            hex_id="A00004",
            categories=("medical", "news"),
            category_channels={"military": [], "medical": ["email"], "news": ["pushover", "email"]},
        )
        off = self.store.observe_aircraft(
            hex_id="A00005",
            label="Silent fixture",
            categories=("news",),
            bands={"1090"},
            observed_at=100.0,
            config_revision=1,
            enabled=True,
            category_channels={"military": [], "medical": [], "news": []},
        )
        self.assertIsNone(off)
        events = {event["id"]: event for event in self.store.history()["events"]}
        self.assertEqual({"pushover"}, set(events[push]["channels"]))
        self.assertEqual({"email"}, set(events[email]["channels"]))
        self.assertEqual({"pushover", "email"}, set(events[both]["channels"]))
        self.assertEqual({"pushover", "email"}, set(events[multi_role]["channels"]))
        self.assertEqual(4, len(events))

    # enforce the identity cap without evicting existing dedupe or continuity
    def test_identity_capacity_refuses_new_rows_but_preserves_existing_updates(self) -> None:
        first = self.observe()
        with mock.patch("adsb_admin.alert_store.MAX_ENCOUNTERS", 1):
            self.assertEqual(first, self.observe(observed_at=110.0))
            with self.assertRaisesRegex(RuntimeError, "encounter capacity"):
                self.store.observe_aircraft(
                    hex_id="40621D",
                    label="Other",
                    categories=(),
                    bands={"978"},
                    observed_at=111.0,
                    config_revision=1,
                    enabled=False,
                )
            self.assertEqual(1, len(self.store.active_encounters()))
        self.assertEqual(110.0, self.store.active_encounters()[0]["last_seen_at"])

    # reject over-cap snapshots atomically rather than truncating continuity
    def test_snapshot_overflow_preserves_previous_complete_artifact(self) -> None:
        self.observe()
        snapshot = self.root / "continuity.json"
        self.store.write_continuity_snapshot(snapshot, generation="activation-1", generated_at=200.0)
        previous = snapshot.read_bytes()
        self.store.observe_aircraft(
            hex_id="40621D",
            label="Other",
            categories=(),
            bands={"978"},
            observed_at=111.0,
            config_revision=1,
            enabled=False,
        )
        with mock.patch("adsb_admin.alert_store.MAX_ENCOUNTERS", 1):
            with self.assertRaisesRegex(RuntimeError, "encounter capacity"):
                self.store.write_continuity_snapshot(snapshot, generation="activation-2", generated_at=201.0)
        self.assertEqual(previous, snapshot.read_bytes())
        restored = AlertStore(self.root / "restored.sqlite3")
        try:
            with mock.patch("adsb_admin.alert_store.MAX_ENCOUNTERS", 0):
                with self.assertRaisesRegex(RuntimeError, "snapshot is invalid"):
                    restored.restore_continuity(snapshot)
            self.assertEqual([], restored.active_encounters())
        finally:
            restored.close()

    # preserve independent acceptance while retrying the peer channel
    def test_independent_channel_results_and_revision_fence(self) -> None:
        event_id = self.observe()
        jobs = self.store.claim_deliveries(now=101.0, config_revision=1, enabled=True)
        self.assertEqual(2, len(jobs))
        pushover = next(job for job in jobs if job["channel"] == "pushover")
        email = next(job for job in jobs if job["channel"] == "email")
        self.store.complete_delivery(event_id, "pushover", DeliveryResult("accepted"), now=102.0)
        self.store.complete_delivery(event_id, "email", DeliveryResult("retry", "smtp_unavailable", 5), now=102.0)
        latest = self.store.delivery_status()
        self.assertEqual("accepted", latest["pushover"]["state"])
        self.assertEqual("retry", latest["email"]["state"])
        self.assertEqual("smtp_unavailable", latest["email"]["error"])
        self.assertEqual(107.0, latest["email"]["retry_at"])
        retried = self.store.claim_deliveries(now=107.0, config_revision=1, enabled=True)
        self.assertEqual(["email"], [job["channel"] for job in retried])
        self.assertEqual(pushover["message_id"].split(".")[0], email["message_id"].split(".")[0])
        self.store.complete_delivery(event_id, "email", DeliveryResult("retry", "smtp_unavailable", 5), now=107.0)
        self.store.claim_deliveries(now=112.0, config_revision=2, enabled=True)
        channels = self.store.history()["events"][0]["channels"]
        self.assertEqual("accepted", channels["pushover"]["state"])
        self.assertEqual("suppressed", channels["email"]["state"])

    # recover a crash after leasing as explicitly ambiguous
    def test_inflight_restart_becomes_unknown_without_resend(self) -> None:
        self.observe()
        self.store.claim_deliveries(now=101.0, config_revision=1, enabled=True, limit=1)
        self.store.close()
        self.store = AlertStore(self.path)
        channels = self.store.history()["events"][0]["channels"]
        self.assertIn("unknown", {channel["state"] for channel in channels.values()})
        remaining = self.store.claim_deliveries(now=102.0, config_revision=1, enabled=True)
        self.assertEqual(1, len(remaining))

    # expose bounded opaque pagination through a read-only helper
    def test_history_pagination_and_retention(self) -> None:
        first = self.observe(observed_at=100.0)
        self.store.mark_rearmed("A2CCA7", rearmed_at=700.0)
        second = self.observe(observed_at=701.0)
        page = read_history(self.path, limit=1)
        self.assertEqual(second, page["events"][0]["id"])
        self.assertIsNotNone(page["next_cursor"])
        older = read_history(self.path, before=page["next_cursor"], limit=1)
        self.assertEqual(first, older["events"][0]["id"])
        with self.assertRaises(ValueError):
            read_history(self.path, before="not-json", limit=1)
        # retain the event anchoring the active encounter
        self.assertEqual(1, self.store.purge_history(now=4_000_000.0))
        self.assertEqual(second, self.store.history()["events"][0]["id"])

    # acknowledge one test id before scheduling fixed dual-channel work
    def test_test_request_acknowledgement_is_idempotent_and_readonly(self) -> None:
        request_id = str(uuid.uuid4())
        first = self.store.acknowledge_test(
            request_id,
            config_revision=2,
            created_at=100.0,
            current_revision=2,
            enabled=True,
            now=101.0,
        )
        second = self.store.acknowledge_test(
            request_id,
            config_revision=2,
            created_at=100.0,
            current_revision=2,
            enabled=True,
            now=102.0,
        )
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertEqual({"email", "pushover"}, set(first["channels"]))
        self.assertEqual(first, read_test_ack(self.path, request_id))
        stale_id = str(uuid.uuid4())
        stale = self.store.acknowledge_test(
            stale_id,
            config_revision=1,
            created_at=100.0,
            current_revision=2,
            enabled=True,
            now=101.0,
        )
        self.assertEqual("refused", stale["state"])
        self.assertEqual("configuration_changed", stale["error"])

    # queue requested tests only for configured providers when supplied
    def test_test_request_uses_supplied_configured_channels(self) -> None:
        request_id = str(uuid.uuid4())
        acknowledged = self.store.acknowledge_test(
            request_id,
            config_revision=1,
            created_at=100.0,
            current_revision=1,
            enabled=True,
            now=101.0,
            channels=("email",),
        )
        self.assertEqual({"email"}, set(acknowledged["channels"]))

    # refuse inactive requests durably even after every provider is cleared
    def test_disabled_test_request_with_no_configured_channels_is_acknowledged(self) -> None:
        request_id = str(uuid.uuid4())
        acknowledged = self.store.acknowledge_test(
            request_id,
            config_revision=1,
            created_at=100.0,
            current_revision=1,
            enabled=False,
            now=101.0,
            channels=(),
        )
        self.assertEqual("refused", acknowledged["state"])
        self.assertEqual("alerts_disabled", acknowledged["error"])
        self.assertEqual({}, acknowledged["channels"])

    # publish bounded secret-free continuity for encrypted backup
    def test_continuity_snapshot_has_required_bands_without_outbox(self) -> None:
        self.observe()
        snapshot = self.root / "continuity.json"
        self.store.write_continuity_snapshot(snapshot, generation="activation-1", generated_at=200.0)
        value = json.loads(snapshot.read_text(encoding="utf-8"))
        self.assertEqual(1, value["schema_version"])
        self.assertEqual(["1090", "978"], value["encounters"][0]["required_bands"])
        serialized = json.dumps(value)
        self.assertNotIn("outbox", serialized)
        self.assertNotIn("message_id", serialized)
        self.assertEqual(0o600, os.stat(snapshot).st_mode & 0o777)

    # restore encounter dedupe without restoring history or delivery work
    def test_continuity_restore_suppresses_replay_until_new_proven_absence(self) -> None:
        self.observe()
        snapshot = self.root / "continuity.json"
        self.store.write_continuity_snapshot(snapshot, generation="activation-1", generated_at=200.0)
        restored_path = self.root / "restored.sqlite3"
        restored = AlertStore(restored_path)
        try:
            self.assertEqual(1, restored.restore_continuity(snapshot))
            encounter = restored.active_encounters()[0]
            self.assertTrue(encounter["notified"])
            self.assertIsNone(encounter["current_event_id"])
            replay = restored.observe_aircraft(
                hex_id="A2CCA7",
                label="News Helicopter",
                categories=("news",),
                bands={"1090"},
                required_bands={"1090", "978"},
                observed_at=201.0,
                config_revision=1,
                enabled=True,
            )
            self.assertIsNone(replay)
            self.assertEqual([], restored.history()["events"])
            restored.mark_rearmed("A2CCA7", rearmed_at=801.0)
            new_event = restored.observe_aircraft(
                hex_id="A2CCA7",
                label="News Helicopter",
                categories=("news",),
                bands={"1090"},
                required_bands={"1090", "978"},
                observed_at=802.0,
                config_revision=1,
                enabled=True,
            )
            self.assertIsNotNone(new_event)
        finally:
            restored.close()


# run focused checks directly
if __name__ == "__main__":
    unittest.main()
