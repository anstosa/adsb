"""Protected alert administration and fixed-content test handoff contracts."""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from adsb_admin.alert_delivery import DeliveryResult
from adsb_admin.alert_store import AlertStore
from tests import test_admin_server as fixture

TEST_ORIGIN = fixture.TEST_ORIGIN


# reuse the existing live authenticated server fixture without duplicating its tests
class AlertAdminServerTest(unittest.TestCase):
    # keep a readable worker database available without any sender process
    def setUp(self) -> None:
        fixture.AdminServerTest.setUp(self)
        store = AlertStore(self.root / "alerts/alerts.sqlite3")
        store.close()

    tearDown = fixture.AdminServerTest.tearDown
    request = fixture.AdminServerTest.request
    json_request = fixture.AdminServerTest.json_request
    login = fixture.AdminServerTest.login

    # build a complete private draft without contacting a provider
    def payload(self, *, enabled: bool = False, revision: int = 0) -> dict:
        return {
            "revision": revision,
            "enabled": enabled,
            "categories": ["military", "medical", "news"],
            "pushover": {"app_token": "unique-app-token", "user_key": "unique-user-key"},
            "smtp": {
                "host": "smtp.example.org",
                "port": 465,
                "username": "unique-mail-user",
                "password": "unique-mail-password",
                "from_address": "station@example.org",
                "to_address": "operator@example.org",
            },
            "overrides": [],
        }

    # return the same session and csrf headers used by station writes
    def headers(self) -> dict:
        cookie, csrf = self.login()
        return {"Cookie": cookie, "X-CSRF-Token": csrf, "Origin": TEST_ORIGIN}

    # protect all new reads and writes
    def test_authentication_required(self) -> None:
        # require a session for each private projection
        for route in ("config", "status", "history"):
            self.assertEqual(401, self.request("GET", f"/api/admin/alerts/{route}")[0])
        self.assertEqual(
            401,
            self.request("POST", "/api/admin/alerts/test", payload={"revision": 0}, headers={"Origin": TEST_ORIGIN})[0],
        )

    # retain origin and csrf protection on both write routes
    def test_write_boundaries(self) -> None:
        headers = self.headers()
        # validate both mutation routes independently
        for method, route, payload in (("PUT", "config", self.payload()), ("POST", "test", {"revision": 0})):
            without_csrf = {key: value for key, value in headers.items() if key != "X-CSRF-Token"}
            self.assertEqual(
                403, self.request(method, f"/api/admin/alerts/{route}", payload=payload, headers=without_csrf)[0]
            )
            wrong_origin = {**headers, "Origin": "https://attacker.invalid"}
            self.assertEqual(
                403, self.request(method, f"/api/admin/alerts/{route}", payload=payload, headers=wrong_origin)[0]
            )

    # keep credentials write-only and revisions independent
    def test_redaction_and_station_revision_unchanged(self) -> None:
        headers = self.headers()
        status, _, config = self.json_request(
            "PUT", "/api/admin/alerts/config", payload=self.payload(), headers=headers
        )
        self.assertEqual(200, status)
        self.assertEqual(1, config["revision"])
        public = self.request("GET", "/api/admin/alerts/config", headers=headers)[2].decode()
        # never echo any submitted secret through a read or save response
        for secret in ("unique-app-token", "unique-user-key", "unique-mail-user", "unique-mail-password"):
            self.assertNotIn(secret, public)
            self.assertNotIn(secret, json.dumps(config))
        self.assertEqual(0, self.server.application.settings.get_public()["revision"])
        private_path = self.root / "config/alerts.json"
        self.assertEqual(0o600, os.stat(private_path).st_mode & 0o777)

    # report safe conflict and validation projections
    def test_conflict_and_validation(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(), headers=headers)
        status, _, result = self.json_request(
            "PUT", "/api/admin/alerts/config", payload=self.payload(), headers=headers
        )
        self.assertEqual(409, status)
        self.assertNotIn("unique-mail-password", json.dumps(result))
        bad = self.payload(revision=1)
        bad["smtp"]["host"] = "127.0.0.1"
        self.assertEqual(422, self.request("PUT", "/api/admin/alerts/config", payload=bad, headers=headers)[0])

    # keep missing credentials and an absent worker visible without failing core health
    def test_initial_status_and_empty_history(self) -> None:
        headers = self.headers()
        status, response_headers, result = self.json_request("GET", "/api/admin/alerts/status", headers=headers)
        self.assertEqual(200, status)
        self.assertFalse(result["process_running"])
        self.assertEqual("missing", result["configuration_state"])
        self.assertEqual("not_configured", result["channels"]["pushover"]["state"])
        self.assertEqual("private, no-store", response_headers["cache-control"])
        self.assertEqual(
            {"events": [], "next_cursor": None},
            self.json_request("GET", "/api/admin/alerts/history", headers=headers)[2],
        )
        self.assertEqual(200, self.request("GET", "/healthz")[0])

    # maintenance email uses smtp alone and exposes only fixed worker fields
    def test_maintenance_email_projection_is_safe_and_independent(self) -> None:
        headers = self.headers()
        payload = self.payload()
        payload["pushover"] = {"app_token": "", "user_key": ""}
        self.request("PUT", "/api/admin/alerts/config", payload=payload, headers=headers)
        (self.root / "alerts/worker-status.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "sampled_at": 1000,
                    "process_running": True,
                    "applied_revision": 1,
                    "maintenance_email": {
                        "state": "accepted",
                        "error": "<script>",
                        "reported_at": 990,
                        "accepted_at": 1000,
                        "retry_at": None,
                        "recipient": "private@example.org",
                        "injected": "<img src=x onerror=alert(1)>",
                    },
                }
            )
        )
        with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
            result = self.json_request("GET", "/api/admin/maintenance", headers=headers)[2]
        self.assertEqual(
            {
                "state": "accepted",
                "error": None,
                "reported_at": 990.0,
                "accepted_at": 1000.0,
                "retry_at": None,
            },
            result["email_notifications"],
        )
        self.assertNotIn("private@example.org", json.dumps(result))
        self.assertFalse(result["email_notifications"]["state"] == "not_configured")

    # require only the selected provider for aircraft readiness
    def test_single_channel_configuration_and_status(self) -> None:
        headers = self.headers()
        # keep provider availability and routing independent
        for revision, channel in enumerate(("pushover", "email")):
            with self.subTest(channel=channel):
                payload = self.payload(enabled=True, revision=revision)
                payload["categories"] = ["military"]
                payload["category_channels"] = {"military": [channel], "medical": [], "news": []}
                # clear only the unused provider's credentials
                if channel == "pushover":
                    payload["smtp"] = {"clear_username": True, "clear_password": True}
                else:
                    payload["pushover"] = {"clear_app_token": True, "clear_user_key": True}
                status, _, saved = self.json_request(
                    "PUT", "/api/admin/alerts/config", payload=payload, headers=headers
                )
                self.assertEqual(200, status)
                self.assertEqual(payload["category_channels"], saved["category_channels"])
                result = self.json_request("GET", "/api/admin/alerts/status", headers=headers)[2]
                self.assertEqual("ready", result["configuration_state"])
                self.assertEqual("unknown", result["channels"][channel]["state"])
                unused = "email" if channel == "pushover" else "pushover"
                self.assertEqual("disabled", result["channels"][unused]["state"])
                self.assertEqual(0, self.server.application.settings.get_public()["revision"])
                self.status_path.parent.mkdir(parents=True, exist_ok=True)
                self.status_path.write_text(
                    json.dumps({"alerts": {"activation_id": "routing-test", "source_contract_digest": "routing-proof"}})
                )
                (self.root / "alerts/worker-status.json").write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "activation_id": "routing-test",
                            "source_contract_digest": "routing-proof",
                            "sampled_at": 1000,
                            "process_running": True,
                            "bands": {
                                "1090": {"state": "healthy", "last_message_at": 1000},
                                "978": {"state": "healthy", "last_message_at": 1000},
                            },
                            "channels": {channel: {"state": "accepted"}, unused: {"state": "failed"}},
                        }
                    )
                )
                with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
                    result = self.json_request("GET", "/api/admin/alerts/status", headers=headers)[2]
                self.assertEqual("ready", result["overall_state"])
                self.assertEqual("accepted", result["channels"][channel]["state"])
                self.assertEqual("disabled", result["channels"][unused]["state"])

    # stale and legacy workers cannot claim maintenance email delivery
    def test_maintenance_email_requires_current_worker_contract(self) -> None:
        headers = self.headers()
        payload = self.payload()
        payload["pushover"] = {"app_token": "", "user_key": ""}
        self.request("PUT", "/api/admin/alerts/config", payload=payload, headers=headers)
        worker_path = self.root / "alerts/worker-status.json"
        worker_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "sampled_at": 1000,
                    "process_running": True,
                    "applied_revision": 1,
                }
            )
        )
        with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
            legacy = self.json_request("GET", "/api/admin/maintenance", headers=headers)[2]
        self.assertEqual("unknown", legacy["email_notifications"]["state"])
        worker_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "sampled_at": 900,
                    "process_running": True,
                    "applied_revision": 1,
                    "maintenance_email": {"state": "accepted", "accepted_at": 900},
                }
            )
        )
        with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
            stale = self.json_request("GET", "/api/admin/maintenance", headers=headers)[2]
        self.assertEqual("unknown", stale["email_notifications"]["state"])

    # keep overload and latest independent provider errors visible in private status
    def test_capacity_and_provider_failures_do_not_claim_healthy(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        activation = "a" * 32
        digest = "b" * 64
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        self.status_path.write_text(
            json.dumps({"alerts": {"activation_id": activation, "source_contract_digest": digest}})
        )
        value = {
            "schema_version": 1,
            "activation_id": activation,
            "source_contract_digest": digest,
            "sampled_at": 1000.0,
            "process_running": True,
            "bands": {
                "1090": {"state": "healthy", "last_message_at": 1000},
                "978": {"state": "healthy", "last_message_at": 1000},
            },
            "channels": {
                "pushover": {"state": "retry", "error": "pushover_quota", "retry_at": 1100.0},
                "email": {"state": "accepted", "accepted": 1},
            },
            "capacity_rejections": 2,
            "capacity_error": None,
        }
        (self.root / "alerts/worker-status.json").write_text(json.dumps(value))
        with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
            result = self.json_request("GET", "/api/admin/alerts/status", headers=headers)[2]
        self.assertTrue(result["process_running"])
        self.assertEqual("healthy", result["source_state"])
        self.assertEqual("degraded", result["capacity_state"])
        self.assertEqual(2, result["capacity_rejections"])
        self.assertEqual("pushover_quota", result["channels"]["pushover"]["error"])
        self.assertEqual(1100.0, result["channels"]["pushover"]["retry_at"])
        self.assertEqual("accepted", result["channels"]["email"]["state"])
        self.assertEqual("degraded", result["overall_state"])
        value["capacity_rejections"] = 0
        (self.root / "alerts/worker-status.json").write_text(json.dumps(value))
        with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
            provider_only = self.json_request("GET", "/api/admin/alerts/status", headers=headers)[2]
        self.assertEqual("ready", provider_only["capacity_state"])
        self.assertEqual("degraded", provider_only["overall_state"])
        self.assertEqual("accepted", provider_only["channels"]["email"]["state"])
        value["channels"]["pushover"] = {"state": "accepted", "accepted": 1}
        value["bands"] = {"1090": {"state": "healthy"}, "978": {"state": "healthy"}}
        (self.root / "alerts/worker-status.json").write_text(json.dumps(value))
        with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
            quiet = self.json_request("GET", "/api/admin/alerts/status", headers=headers)[2]
        self.assertEqual("quiet", quiet["source_state"])
        self.assertEqual("quiet", quiet["overall_state"])
        value["bands"] = {"1090": {"state": "absent"}, "978": {"state": "absent"}}
        (self.root / "alerts/worker-status.json").write_text(json.dumps(value))
        with patch("adsb_admin.alert_admin.time.time", return_value=1000.0):
            absent = self.json_request("GET", "/api/admin/alerts/status", headers=headers)[2]
        self.assertTrue(absent["process_running"])
        self.assertEqual("no_radio", absent["source_state"])
        self.assertEqual("no-radio", absent["overall_state"])
        self.assertEqual(200, self.request("GET", "/healthz")[0])

    # reject unsupported pagination before database reads
    def test_history_query_bounds(self) -> None:
        headers = self.headers()
        # reject oversized duplicate and unknown query values
        for query in ("limit=0", "limit=51", "limit=1&limit=2", "sql=1", "before=invalid"):
            self.assertEqual(400, self.request("GET", "/api/admin/alerts/history?" + query, headers=headers)[0])

    # an intentional test requires saved enabled settings and no custom provider payload
    def test_test_configuration_and_exact_payload(self) -> None:
        headers = self.headers()
        self.assertEqual(
            422, self.request("POST", "/api/admin/alerts/test", payload={"revision": 0}, headers=headers)[0]
        )
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        self.assertEqual(
            422,
            self.request(
                "POST", "/api/admin/alerts/test", payload={"revision": 1, "message": "aircraft"}, headers=headers
            )[0],
        )
        self.assertEqual(
            409, self.request("POST", "/api/admin/alerts/test", payload={"revision": 0}, headers=headers)[0]
        )

    # repeat pending posts preserve the same durable request even before the worker starts
    def test_pending_request_is_idempotent_across_restart(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        with patch("adsb_admin.alert_admin.time.time", return_value=1000):
            first = self.json_request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)
            second = self.json_request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)
        self.assertEqual(202, first[0])
        self.assertEqual(first[2]["request_id"], second[2]["request_id"])
        self.assertEqual(0o600, os.stat(self.root / "config/alerts-test.json").st_mode & 0o777)

    # the admin retains rate-limit ownership after durable worker acknowledgement
    def test_acknowledgement_and_rate_limit(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        with patch("adsb_admin.alert_admin.time.time", return_value=1000):
            first = self.json_request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)[2]
        store = AlertStore(self.root / "alerts/alerts.sqlite3")
        try:
            store.acknowledge_test(
                first["request_id"], config_revision=1, created_at=1000, current_revision=1, enabled=True, now=1000
            )
            jobs = store.claim_deliveries(now=1000, config_revision=1, enabled=True)
            # simulate transport acceptance only inside the isolated local store
            for job in jobs:
                store.complete_delivery(job["event_id"], job["channel"], DeliveryResult("accepted"), now=1001)
            with patch("adsb_admin.alert_admin.time.time", return_value=1002):
                self.assertEqual(
                    429, self.request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)[0]
                )
            history = self.json_request("GET", "/api/admin/alerts/history", headers=headers)[2]
            self.assertEqual("test", history["events"][0]["kind"])
            self.assertEqual("accepted", history["events"][0]["channels"]["pushover"]["state"])
        finally:
            store.close()

    # broken optional alert state never takes down unrelated administration
    def test_corrupt_optional_state_isolated(self) -> None:
        headers = self.headers()
        path = self.root / "alerts/alerts.sqlite3"
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"not sqlite")
        self.assertEqual(503, self.request("GET", "/api/admin/alerts/history", headers=headers)[0])
        self.assertEqual(200, self.request("GET", "/api/admin/config", headers=headers)[0])
        self.assertEqual(200, self.request("GET", "/healthz")[0])

    # an unsafe existing test slot must not erase its request identity or throttle
    def test_corrupt_test_slot_is_preserved(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        path = self.root / "config/alerts-test.json"
        path.write_bytes(b"{invalid durable state")
        self.assertEqual(
            503, self.request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)[0]
        )
        self.assertEqual(b"{invalid durable state", path.read_bytes())

    # malformed nested publications fail closed without dropping admin requests
    def test_nested_optional_publications_remain_isolated(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        nested = "[" * 1500 + "0" + "]" * 1500
        worker_path = self.root / "alerts/worker-status.json"
        worker_path.write_text(nested)
        status, _, result = self.json_request("GET", "/api/admin/alerts/status", headers=headers)
        self.assertEqual(200, status)
        self.assertFalse(result["process_running"])
        slot = self.root / "config/alerts-test.json"
        slot.write_text(nested)
        self.assertEqual(503, self.request("GET", "/api/admin/alerts/status", headers=headers)[0])
        self.assertEqual(
            503, self.request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)[0]
        )
        self.assertEqual(nested, slot.read_text())
        self.assertEqual(200, self.request("GET", "/api/admin/config", headers=headers)[0])
        self.assertEqual(200, self.request("GET", "/healthz")[0])

    # a corrupt existing worker database cannot permit replacement or new sends
    def test_corrupt_database_refuses_test_slot_mutation(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        self.request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)
        slot = self.root / "config/alerts-test.json"
        original = slot.read_bytes()
        path = self.root / "alerts/alerts.sqlite3"
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"not sqlite")
        self.assertEqual(
            503, self.request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)[0]
        )
        self.assertEqual(original, slot.read_bytes())

    # an unavailable initial worker database refuses new requests without writing the slot
    def test_missing_database_refuses_new_test(self) -> None:
        headers = self.headers()
        self.request("PUT", "/api/admin/alerts/config", payload=self.payload(enabled=True), headers=headers)
        (self.root / "alerts/alerts.sqlite3").unlink()
        self.assertEqual(
            503, self.request("POST", "/api/admin/alerts/test", payload={"revision": 1}, headers=headers)[0]
        )
        self.assertFalse((self.root / "config/alerts-test.json").exists())


# support direct targeted verification
if __name__ == "__main__":
    unittest.main()
