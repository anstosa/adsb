"""Security and persistence tests for the administration server."""

from __future__ import annotations

import http.client
import json
import secrets
import tempfile
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

from adsb_admin.__main__ import _parser
from adsb_admin.auth import LoginRateLimiter, make_password_hash
from adsb_admin.config import NETWORK_NAMES, UNKNOWN_STATUS_MESSAGE, SettingsStore, sanitized_status
from adsb_admin.server import (
    EMBEDDED_SESSION_COOKIE_NAME,
    MAX_BODY_BYTES,
    SECURITY_POLICY,
    AdminApplication,
    create_server,
)

TEST_ORIGIN = "https://receiver.invalid"
FRAME_ORIGIN = "https://framework.santosa.dev"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


# lock provider-owned frontend identity behavior
class AdminFrontendContractTest(unittest.TestCase):
    # lock sanctuary title and favicon branding
    def test_sanctuary_title_and_favicon(self) -> None:
        html = (PROJECT_ROOT / "web/admin.html").read_text(encoding="utf-8")
        favicon = (PROJECT_ROOT / "web/favicon.svg").read_text(encoding="utf-8")
        self.assertIn("<title>Ballydídean Farm Sanctuary ADS-B</title>", html)
        self.assertIn('<link rel="icon" type="image/svg+xml" href="/favicon.svg?v=goose-photo-trace">', html)
        self.assertIn("#C8B744", favicon)
        self.assertIn("#7C5174", favicon)
        self.assertIn("traced silhouette of a goose in flight pointing upper right", favicon)
        self.assertIn('<path fill="#C8B744"', favicon)
        self.assertNotIn('fill="none"', favicon)

    # keep FlightAware outside the local UUID workflow
    def test_flightaware_uses_provider_issued_identity(self) -> None:
        html = (PROJECT_ROOT / "web/admin.html").read_text(encoding="utf-8")
        start = html.index('data-network="flightaware"')
        end = html.index('data-network="adsblol"')
        card = html[start:end]
        self.assertNotIn('id="flightaware-generate"', card)
        self.assertIn("FlightAware assigns", card)
        self.assertIn('id="flightaware-claim"', card)

    # keep source-specific diagnostics and persistent graphs discoverable
    def test_reception_diagnostics_have_separate_radio_cards(self) -> None:
        html = (PROJECT_ROOT / "web/admin.html").read_text(encoding="utf-8")
        script = (PROJECT_ROOT / "web/admin.js").read_text(encoding="utf-8")
        self.assertIn('id="reception-1090-rate"', html)
        self.assertIn('id="reception-978-rate"', html)
        self.assertIn('href="/map/graphs1090/"', html)
        self.assertIn("Quiet 978 MHz traffic is normal", script)
        self.assertIn("Its old JSON timestamp is not being presented as recent radio activity", script)

    # expose the weekly review separately from editable station settings
    def test_maintenance_report_has_a_read_only_card(self) -> None:
        html = (PROJECT_ROOT / "web/admin.html").read_text(encoding="utf-8")
        maintenance_start = html.index('class="panel maintenance-panel"')
        form_start = html.index('id="settings-form"')
        self.assertLess(maintenance_start, form_start)
        self.assertIn('id="maintenance-reboot"', html)
        self.assertIn('id="maintenance-email-notification"', html)
        self.assertIn("are not performed automatically", html)


# provide one live backend per test
class AdminServerTest(unittest.TestCase):
    # start an isolated server
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.web_root = self.root / "web"
        self.web_root.mkdir()
        (self.web_root / "admin.html").write_text("<!doctype html><title>Admin</title>", encoding="utf-8")
        (self.web_root / "admin.js").write_text("console.log('admin')", encoding="utf-8")
        (self.web_root / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'></svg>", encoding="utf-8")
        self.settings_path = self.root / "config" / "settings.json"
        self.status_path = self.root / "status" / "status.json"
        self.password = secrets.token_urlsafe(24)
        application = AdminApplication(
            web_root=self.web_root,
            settings_path=self.settings_path,
            status_path=self.status_path,
            password_hash=make_password_hash(self.password),
            origin=TEST_ORIGIN,
            secure_cookie=True,
        )
        self.server = create_server(("127.0.0.1", 0), application)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.address = self.server.server_address

    # stop the isolated server
    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    # restart with one trusted frame origin
    def enable_embedding(self, frame_origin: str = FRAME_ORIGIN) -> AdminApplication:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        application = AdminApplication(
            web_root=self.web_root,
            settings_path=self.settings_path,
            status_path=self.status_path,
            password_hash=make_password_hash(self.password),
            origin=TEST_ORIGIN,
            secure_cookie=True,
            frame_origin=frame_origin,
        )
        self.server = create_server(("127.0.0.1", 0), application)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.address = self.server.server_address
        return application

    # issue one independent http request
    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Any | None = None,
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(*self.address, timeout=3)
        actual_headers = dict(headers or {})
        body = raw_body
        # encode supplied json consistently
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            actual_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=body, headers=actual_headers)
        response = connection.getresponse()
        content = response.read()
        result_headers = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, result_headers, content

    # decode one json response
    def json_request(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, str], Any]:
        status, headers, content = self.request(*args, **kwargs)
        return status, headers, json.loads(content)

    # log in and return cookie plus csrf
    def login(self) -> tuple[str, str]:
        status, headers, payload = self.json_request(
            "POST",
            "/api/login",
            payload={"password": self.password},
            headers={"Origin": TEST_ORIGIN},
        )
        self.assertEqual(200, status)
        cookie = headers["set-cookie"].split(";", 1)[0]
        return cookie, payload["csrf_token"]

    # build a complete public write shape
    def valid_settings(self, revision: int = 0, *, enabled: bool = False) -> dict[str, Any]:
        networks: dict[str, Any] = {}
        # include every known network
        for network_name in NETWORK_NAMES:
            networks[network_name] = {"enabled": enabled and network_name == "adsbexchange", "mlat": False}
        return {
            "revision": revision,
            "station": {
                "name": "Ballydidean",
                "latitude": 48.1,
                "longitude": -122.5,
                "altitude_m": 38,
            },
            "networks": networks,
        }

    # write one controller status fixture
    def write_status(self, updated_at: str, *, nullable: bool = False) -> None:
        self.status_path.parent.mkdir(exist_ok=True)
        connected = None if nullable else True
        self.status_path.write_text(
            json.dumps(
                {
                    "applied_revision": 7,
                    "phase": "ready",
                    "message": "reconciled",
                    "updated_at": updated_at,
                    "hardware": {"connected": connected, "message": "receiver state"},
                    "reception": {
                        "1090": {
                            "hardware_present": True,
                            "service_running": True,
                            "telemetry_state": "receiving",
                            "messages_per_minute": 1200,
                            "last_activity_at": updated_at,
                            "sample_at": updated_at,
                        },
                        "978": {
                            "hardware_present": True,
                            "service_running": True,
                            "telemetry_state": "quiet",
                            "messages_per_minute": 0,
                            "last_activity_at": None,
                            "sample_at": updated_at,
                        },
                    },
                    "networks": {
                        "flightaware": {
                            "enabled": True,
                            "running": False,
                            "connected": connected,
                            "message": "uploader state",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    # verify public liveness and security headers
    def test_health_is_minimal_and_hardened(self) -> None:
        status, headers, payload = self.json_request("GET", "/healthz")
        self.assertEqual(200, status)
        self.assertEqual({"status": "ok"}, payload)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertEqual(SECURITY_POLICY, headers["content-security-policy"])
        self.assertNotIn("unsafe-inline", headers["content-security-policy"])
        self.assertEqual("DENY", headers["x-frame-options"])

    # verify root and admin static routing
    def test_static_routes_and_root_redirect(self) -> None:
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(303, status)
        self.assertEqual("/map/", headers["location"])
        status, headers, content = self.request("GET", "/admin")
        self.assertEqual(200, status)
        self.assertIn(b"Admin", content)
        self.assertEqual("no-store", headers["cache-control"])
        status, headers, content = self.request("GET", "/favicon.svg")
        self.assertEqual(200, status)
        self.assertEqual("image/svg+xml", headers["content-type"])
        self.assertIn(b"<svg", content)

    # verify traversal and escaping symlinks are blocked
    def test_static_traversal_is_rejected(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        (self.web_root / "escape.txt").symlink_to(outside)
        status, _, _ = self.request("GET", "/%2e%2e/outside.txt")
        self.assertEqual(404, status)
        status, _, _ = self.request("GET", "/escape.txt")
        self.assertEqual(404, status)
        status, _, _ = self.request("GET", "/..%5coutside.txt")
        self.assertEqual(404, status)

    # verify protected reads reject anonymous callers
    def test_admin_reads_require_authentication(self) -> None:
        status, _, payload = self.json_request("GET", "/api/admin/config")
        self.assertEqual(401, status)
        self.assertEqual({"error": "authentication_required"}, payload)
        status, _, payload = self.json_request("GET", "/api/admin/status")
        self.assertEqual(401, status)
        self.assertEqual({"error": "authentication_required"}, payload)
        status, _, payload = self.json_request("GET", "/api/admin/maintenance")
        self.assertEqual(401, status)
        self.assertEqual({"error": "authentication_required"}, payload)

    # keep maintenance reports authenticated bounded and uncached
    def test_maintenance_report_returns_unknown_and_valid_safe_projection(self) -> None:
        cookie, _ = self.login()
        status, headers, payload = self.json_request("GET", "/api/admin/maintenance", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertEqual("private, no-store", headers["cache-control"])
        self.assertEqual("unknown", payload["status"])
        self.assertEqual([], payload["images"])
        self.assertEqual("not_configured", payload["email_notifications"]["state"])
        secret = secrets.token_urlsafe(24)
        report_path = self.status_path.with_name("maintenance.json")
        report_path.parent.mkdir(exist_ok=True)
        report_path.write_text(
            json.dumps(
                {
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "status": "attention",
                    "reboot_required": True,
                    "disk_free_percent": 72.5,
                    "map_status": "current",
                    "images": [
                        {
                            "name": "ultrafeeder",
                            "review_ref": "ghcr.io/sdr-enthusiasts/docker-adsb-ultrafeeder:latest",
                            "status": "review",
                            "secret": secret,
                        }
                    ],
                    "secret": secret,
                }
            ),
            encoding="utf-8",
        )
        status, headers, payload = self.json_request("GET", "/api/admin/maintenance", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertEqual("private, no-store", headers["cache-control"])
        self.assertEqual("attention", payload["status"])
        self.assertTrue(payload["reboot_required"])
        self.assertEqual(72.5, payload["disk_free_percent"])
        self.assertEqual("review", payload["images"][0]["status"])
        self.assertNotIn(secret, json.dumps(payload))

    # optional notifier state cannot hide a valid maintenance report
    def test_maintenance_report_survives_notification_projection_failure(self) -> None:
        cookie, _ = self.login()
        with patch.object(self.server.application.alerts, "settings", side_effect=RuntimeError):
            settings_status, _, settings_payload = self.json_request(
                "GET", "/api/admin/maintenance", headers={"Cookie": cookie}
            )
        self.assertEqual(200, settings_status)
        self.assertEqual("unknown", settings_payload["email_notifications"]["state"])
        with patch.object(self.server.application.alerts, "maintenance_email_status", side_effect=RuntimeError):
            status, headers, payload = self.json_request("GET", "/api/admin/maintenance", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertEqual("private, no-store", headers["cache-control"])
        self.assertEqual("unknown", payload["status"])
        self.assertEqual("unknown", payload["email_notifications"]["state"])

    # verify login requires exact origin and json
    def test_login_rejects_cross_origin_and_forms(self) -> None:
        status, headers, payload = self.json_request(
            "POST",
            "/api/login",
            payload={"password": self.password},
            headers={"Origin": "https://attacker.invalid"},
        )
        self.assertEqual(403, status)
        self.assertEqual({"error": "origin_rejected"}, payload)
        self.assertEqual("close", headers["connection"])
        status, headers, payload = self.json_request(
            "POST",
            "/api/login",
            headers={"Origin": TEST_ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
            raw_body=b"password=value",
        )
        self.assertEqual(415, status)
        self.assertEqual({"error": "json_required"}, payload)
        self.assertEqual("close", headers["connection"])

    # verify credential failures do not reveal validation details
    def test_login_uses_generic_authentication_errors(self) -> None:
        wrong_password = secrets.token_urlsafe(24)
        status, headers, payload = self.json_request(
            "POST",
            "/api/login",
            payload={"password": wrong_password},
            headers={"Origin": TEST_ORIGIN},
        )
        self.assertEqual(401, status)
        self.assertEqual({"error": "invalid_credentials"}, payload)
        status, _, payload = self.json_request(
            "POST",
            "/api/login",
            payload={"unexpected": "value"},
            headers={"Origin": TEST_ORIGIN},
        )
        self.assertEqual(401, status)
        self.assertEqual({"error": "invalid_credentials"}, payload)

    # verify repeated login failures receive a bounded generic throttle response
    def test_login_rate_limit_is_enforced_by_endpoint(self) -> None:
        self.server.application.rate_limiter = LoginRateLimiter(max_attempts=2, window_seconds=60)
        wrong_password = secrets.token_urlsafe(24)
        request_headers = {"Origin": TEST_ORIGIN}
        # consume the configured failure allowance
        for _ in range(2):
            status, _, payload = self.json_request(
                "POST",
                "/api/login",
                payload={"password": wrong_password},
                headers=request_headers,
            )
            self.assertEqual(401, status)
            self.assertEqual({"error": "invalid_credentials"}, payload)
        status, headers, payload = self.json_request(
            "POST",
            "/api/login",
            payload={"password": wrong_password},
            headers=request_headers,
        )
        self.assertEqual(429, status)
        self.assertEqual({"error": "invalid_credentials"}, payload)
        self.assertGreaterEqual(int(headers["retry-after"]), 1)

    # verify successful login establishes a hardened session
    def test_login_session_and_cookie_security(self) -> None:
        cookie, csrf = self.login()
        self.assertTrue(cookie.startswith("__Host-adsb_admin_session="))
        status, headers, payload = self.json_request("GET", "/api/session", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertEqual({"authenticated": True, "csrf_token": csrf}, payload)
        self.assertEqual("private, no-store", headers["cache-control"])
        login_status, login_headers, _ = self.json_request(
            "POST",
            "/api/login",
            payload={"password": self.password},
            headers={"Origin": TEST_ORIGIN},
        )
        self.assertEqual(200, login_status)
        set_cookie = login_headers["set-cookie"]
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("Secure", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        self.assertNotIn("Partitioned", set_cookie)

    # verify local http testing requires an explicit nonsecure cookie mode
    def test_insecure_cookie_mode_is_explicit(self) -> None:
        with self.assertRaises(ValueError):
            AdminApplication(
                web_root=self.web_root,
                settings_path=self.root / "invalid-origin-settings.json",
                status_path=self.status_path,
                password_hash=make_password_hash(self.password),
                origin="http://127.0.0.1:8090",
                secure_cookie=True,
            )
        application = AdminApplication(
            web_root=self.web_root,
            settings_path=self.root / "local-settings.json",
            status_path=self.status_path,
            password_hash=make_password_hash(self.password),
            origin="http://127.0.0.1:8090",
            secure_cookie=False,
        )
        self.assertEqual("adsb_admin_session", application.session_cookie_name)

    # verify only one canonical https parent can enable embedding
    def test_embedding_origin_is_canonical_and_strict(self) -> None:
        application = self.enable_embedding("https://BÜCHER.Example:443/")
        self.assertEqual("https://xn--bcher-kva.example", application.frame_origin)
        invalid_origins = (
            "http://framework.santosa.dev",
            "https://framework.santosa.dev:8443",
            "https://user@framework.santosa.dev",
            "https://framework.santosa.dev/admin",
            "https://framework.santosa.dev//",
            "https://framework.santosa.dev?",
            "https://framework.santosa.dev#",
            "https://*.santosa.dev",
            "https://framework.santosa.dev\\@attacker.invalid",
            "https://framework.santosa.dev\r\nX-Injected: true",
            " https://framework.santosa.dev",
            "https://framework.santosa.dev ",
            "https://framework.santosa.dev:not-a-port",
            "https://[::1",
            "https://[fe80::1%25eth0]",
        )
        # reject every ambiguous or injectable parent
        for frame_origin in invalid_origins:
            with self.subTest(frame_origin=frame_origin), self.assertRaises(ValueError):
                AdminApplication(
                    web_root=self.web_root,
                    settings_path=self.root / "invalid-frame-settings.json",
                    status_path=self.status_path,
                    password_hash=make_password_hash(self.password),
                    origin=TEST_ORIGIN,
                    secure_cookie=True,
                    frame_origin=frame_origin,
                )

    # verify embedding cannot weaken local http cookie mode
    def test_embedding_requires_secure_cookies(self) -> None:
        with self.assertRaises(ValueError):
            AdminApplication(
                web_root=self.web_root,
                settings_path=self.root / "embedded-http-settings.json",
                status_path=self.status_path,
                password_hash=make_password_hash(self.password),
                origin="http://127.0.0.1:8090",
                secure_cookie=False,
                frame_origin=FRAME_ORIGIN,
            )

    # verify configured framing permits only the trusted parent
    def test_embedding_headers_allow_only_the_configured_parent(self) -> None:
        self.enable_embedding()
        status, headers, payload = self.json_request("GET", "/healthz")
        self.assertEqual(200, status)
        self.assertEqual({"status": "ok"}, payload)
        self.assertIn(f"frame-ancestors {FRAME_ORIGIN}", headers["content-security-policy"])
        self.assertNotIn("frame-ancestors 'self'", headers["content-security-policy"])
        self.assertNotIn("frame-ancestors *", headers["content-security-policy"])
        self.assertNotIn("x-frame-options", headers)
        self.assertNotIn("access-control-allow-origin", headers)

    # verify embedded login and logout use matching partitioned cookie attributes
    def test_embedding_cookie_is_partitioned_and_clear_matches(self) -> None:
        application = self.enable_embedding()
        cookie, csrf = self.login()
        self.assertTrue(cookie.startswith(f"{EMBEDDED_SESSION_COOKIE_NAME}="))
        login_status, login_headers, _ = self.json_request(
            "POST",
            "/api/login",
            payload={"password": self.password},
            headers={"Origin": TEST_ORIGIN},
        )
        self.assertEqual(200, login_status)
        set_cookie = login_headers["set-cookie"]
        self.assertIn("Path=/", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("Secure", set_cookie)
        self.assertIn("SameSite=None", set_cookie)
        self.assertIn("Partitioned", set_cookie)
        self.assertNotIn("Domain=", set_cookie)
        status, clear_headers, _ = self.json_request(
            "POST",
            "/api/logout",
            payload={},
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(200, status)
        clear_cookie = clear_headers["set-cookie"]
        # retain every scope attribute while clearing the embedded cookie
        for attribute in ("Path=/", "HttpOnly", "Secure", "SameSite=None", "Partitioned", "Max-Age=0"):
            self.assertIn(attribute, clear_cookie)
        self.assertNotIn("Domain=", clear_cookie)
        self.assertEqual(EMBEDDED_SESSION_COOKIE_NAME, application.session_cookie_name)

    # verify the trusted parent is a frame grant rather than a write origin
    def test_embedding_keeps_writes_bound_to_the_child_origin(self) -> None:
        self.enable_embedding()
        status, _, payload = self.json_request(
            "POST",
            "/api/login",
            payload={"password": self.password},
            headers={"Origin": FRAME_ORIGIN},
        )
        self.assertEqual(403, status)
        self.assertEqual({"error": "origin_rejected"}, payload)
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=self.valid_settings(),
            headers={"Origin": FRAME_ORIGIN},
        )
        self.assertEqual(403, status)
        self.assertEqual({"error": "origin_rejected"}, payload)

        cookie, csrf = self.login()
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=self.valid_settings(),
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie},
        )
        self.assertEqual(403, status)
        self.assertEqual({"error": "csrf_failed"}, payload)
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=self.valid_settings(),
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(200, status)
        self.assertEqual(1, payload["revision"])

    # verify an old standalone cookie cannot shadow the embedded session
    def test_embedding_uses_a_distinct_cookie_name(self) -> None:
        self.enable_embedding()
        cookie, csrf = self.login()
        combined = f"__Host-adsb_admin_session=obsolete; {cookie}"
        status, _, payload = self.json_request("GET", "/api/session", headers={"Cookie": combined})
        self.assertEqual(200, status)
        self.assertEqual({"authenticated": True, "csrf_token": csrf}, payload)

    # verify mutations require a matching csrf token
    def test_config_write_requires_csrf(self) -> None:
        cookie, _ = self.login()
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=self.valid_settings(),
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie},
        )
        self.assertEqual(403, status)
        self.assertEqual({"error": "csrf_failed"}, payload)

    # verify valid writes persist privately and return redacted data
    def test_config_write_is_atomic_private_and_redacted(self) -> None:
        cookie, csrf = self.login()
        feeder_id = str(uuid.uuid4())
        settings = self.valid_settings(enabled=True)
        settings["networks"]["adsbexchange"]["feeder_id"] = feeder_id
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=settings,
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(200, status)
        self.assertEqual(1, payload["revision"])
        self.assertTrue(payload["networks"]["adsbexchange"]["feeder_id_configured"])
        self.assertNotIn(feeder_id, json.dumps(payload))
        private = json.loads(self.settings_path.read_text(encoding="utf-8"))
        self.assertEqual(feeder_id, private["networks"]["adsbexchange"]["feeder_id"])
        self.assertEqual(0o600, self.settings_path.stat().st_mode & 0o777)

    # verify omitted ids preserve and empty ids clear credentials
    def test_feeder_id_omission_preserves_and_empty_clears(self) -> None:
        cookie, csrf = self.login()
        original = json.loads(self.settings_path.read_text(encoding="utf-8"))["networks"]["adsbexchange"]["feeder_id"]
        status, _, _ = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=self.valid_settings(),
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(200, status)
        saved = json.loads(self.settings_path.read_text(encoding="utf-8"))
        self.assertEqual(original, saved["networks"]["adsbexchange"]["feeder_id"])
        cleared = self.valid_settings(revision=1)
        cleared["networks"]["adsbexchange"]["feeder_id"] = ""
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=cleared,
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(200, status)
        self.assertFalse(payload["networks"]["adsbexchange"]["feeder_id_configured"])

    # verify malformed and unknown settings are rejected together
    def test_config_schema_is_strict(self) -> None:
        cookie, csrf = self.login()
        settings = self.valid_settings()
        settings["station"]["unexpected"] = "value"
        settings["networks"]["adsblol"]["enabled"] = 1
        settings["networks"]["flightaware"]["feeder_id"] = "not-an-id"
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=settings,
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(422, status)
        self.assertEqual("invalid_request", payload["error"])
        self.assertIn("station.unexpected", payload["fields"])
        self.assertIn("networks.adsblol.enabled", payload["fields"])
        self.assertIn("networks.flightaware.feeder_id", payload["fields"])

    # verify active feeds require complete station information
    def test_enabled_network_requires_complete_station(self) -> None:
        cookie, csrf = self.login()
        settings = self.valid_settings(enabled=True)
        settings["station"]["latitude"] = None
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=settings,
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(422, status)
        self.assertEqual("is required when a network is enabled", payload["fields"]["station.latitude"])

    # allow PiAware to obtain its provider-issued identifier
    def test_new_flightaware_site_can_start_without_feeder_id(self) -> None:
        cookie, csrf = self.login()
        settings = self.valid_settings()
        settings["networks"]["flightaware"]["enabled"] = True
        status, _, payload = self.json_request(
            "PUT",
            "/api/admin/config",
            payload=settings,
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(200, status)
        self.assertTrue(payload["networks"]["flightaware"]["enabled"])
        self.assertFalse(payload["networks"]["flightaware"]["feeder_id_configured"])

    # reject incomplete private documents instead of synthesizing identities
    def test_persisted_settings_require_complete_network_records(self) -> None:
        persisted = json.loads(self.settings_path.read_text(encoding="utf-8"))
        del persisted["networks"]["adsbexchange"]["feeder_id"]
        self.settings_path.write_text(json.dumps(persisted), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "invalid schema"):
            SettingsStore(self.settings_path)

    # verify stale writes return the current redacted revision
    def test_stale_revision_returns_conflict(self) -> None:
        cookie, csrf = self.login()
        headers = {"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, _ = self.json_request("PUT", "/api/admin/config", payload=self.valid_settings(), headers=headers)
        self.assertEqual(200, status)
        status, _, payload = self.json_request(
            "PUT", "/api/admin/config", payload=self.valid_settings(), headers=headers
        )
        self.assertEqual(409, status)
        self.assertEqual("revision_conflict", payload["error"])
        self.assertEqual(1, payload["config"]["revision"])
        self.assertNotIn("feeder_id", payload["config"]["networks"]["adsbexchange"])

    # verify logout requires csrf and revokes its session
    def test_logout_requires_csrf_and_revokes_session(self) -> None:
        cookie, csrf = self.login()
        status, _, _ = self.json_request(
            "POST",
            "/api/logout",
            payload={},
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": "wrong"},
        )
        self.assertEqual(403, status)
        status, headers, payload = self.json_request(
            "POST",
            "/api/logout",
            payload={},
            headers={"Origin": TEST_ORIGIN, "Cookie": cookie, "X-CSRF-Token": csrf},
        )
        self.assertEqual(200, status)
        self.assertEqual({"authenticated": False}, payload)
        clear_cookie = headers["set-cookie"]
        self.assertTrue(clear_cookie.startswith("__Host-adsb_admin_session="))
        self.assertIn("Max-Age=0", clear_cookie)
        self.assertIn("SameSite=Strict", clear_cookie)
        self.assertIn("Secure", clear_cookie)
        self.assertNotIn("Partitioned", clear_cookie)
        status, _, payload = self.json_request("GET", "/api/session", headers={"Cookie": cookie})
        self.assertEqual({"authenticated": False}, payload)

    # verify status output follows the strict safe projection
    def test_status_projection_drops_secrets_and_unknown_fields(self) -> None:
        self.status_path.parent.mkdir()
        secret = secrets.token_urlsafe(24)
        updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.status_path.write_text(
            json.dumps(
                {
                    "applied_revision": 7,
                    "phase": "ready",
                    "message": "reconciled",
                    "updated_at": updated_at,
                    "hardware": {"connected": True, "message": "receivers online", "serial": secret},
                    "reception": {
                        "1090": {
                            "hardware_present": True,
                            "service_running": True,
                            "telemetry_state": "receiving",
                            "messages_per_minute": 1234.5,
                            "last_activity_at": updated_at,
                            "sample_at": updated_at,
                            "df_counts": [secret],
                            "raw_payload": secret,
                        },
                        "evil": {"raw_payload": secret},
                    },
                    "networks": {
                        "adsbexchange": {
                            "enabled": True,
                            "running": True,
                            "connected": True,
                            "message": "active",
                            "feeder_id": secret,
                            "command": secret,
                        },
                        "unknown": {"message": secret},
                    },
                    "password": secret,
                }
            ),
            encoding="utf-8",
        )
        cookie, _ = self.login()
        status, _, payload = self.json_request("GET", "/api/admin/status", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertEqual(7, payload["applied_revision"])
        self.assertEqual("ready", payload["phase"])
        self.assertTrue(payload["hardware"]["connected"])
        self.assertEqual("active", payload["networks"]["adsbexchange"]["message"])
        self.assertTrue(payload["networks"]["adsbexchange"]["connected"])
        self.assertEqual("receiving", payload["reception"]["1090"]["telemetry_state"])
        self.assertEqual(1234.5, payload["reception"]["1090"]["messages_per_minute"])
        self.assertNotIn("df_counts", payload["reception"]["1090"])
        self.assertNotIn("evil", payload["reception"])
        self.assertNotIn(secret, json.dumps(payload))
        self.assertNotIn("unknown", payload["networks"])

    # expose only a canonical FlightAware claim destination
    def test_status_projection_validates_flightaware_claim_url(self) -> None:
        now = datetime.now(timezone.utc)
        self.write_status(now.isoformat().replace("+00:00", "Z"))
        status = json.loads(self.status_path.read_text(encoding="utf-8"))
        valid_url = "https://www.flightaware.com/adsb/piaware/claim/d35c1a7c-63f9-4cb2-a1c0-bfe272e59f43"
        status["networks"]["flightaware"]["claim_url"] = valid_url
        self.status_path.write_text(json.dumps(status), encoding="utf-8")
        self.assertEqual(valid_url, sanitized_status(self.status_path, now=now)["networks"]["flightaware"]["claim_url"])
        status["networks"]["flightaware"]["claim_url"] = "https://attacker.invalid/claim"
        self.status_path.write_text(json.dumps(status), encoding="utf-8")
        self.assertNotIn("claim_url", sanitized_status(self.status_path, now=now)["networks"]["flightaware"])

    # verify fresh utc controller observations remain authoritative
    def test_fresh_status_preserves_observed_state(self) -> None:
        now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        self.write_status((now - timedelta(seconds=29)).isoformat().replace("+00:00", "Z"))
        payload = sanitized_status(self.status_path, now=now)
        self.assertEqual("ready", payload["phase"])
        self.assertTrue(payload["hardware"]["connected"])
        self.assertFalse(payload["networks"]["flightaware"]["running"])
        self.assertTrue(payload["networks"]["flightaware"]["connected"])
        self.assertEqual(1200, payload["reception"]["1090"]["messages_per_minute"])
        self.assertEqual("quiet", payload["reception"]["978"]["telemetry_state"])

    # verify stale observations retain intent without claiming runtime state
    def test_stale_status_clears_observed_state(self) -> None:
        now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        self.write_status((now - timedelta(seconds=31)).isoformat().replace("+00:00", "Z"))
        payload = sanitized_status(self.status_path, now=now)
        self.assertEqual("error", payload["phase"])
        self.assertEqual(UNKNOWN_STATUS_MESSAGE, payload["message"])
        self.assertIsNone(payload["hardware"]["connected"])
        self.assertTrue(payload["networks"]["flightaware"]["enabled"])
        self.assertIsNone(payload["networks"]["flightaware"]["running"])
        self.assertIsNone(payload["networks"]["flightaware"]["connected"])
        self.assertEqual("unavailable", payload["reception"]["1090"]["telemetry_state"])
        self.assertIsNone(payload["reception"]["1090"]["messages_per_minute"])
        self.assertIsNone(payload["reception"]["1090"]["last_activity_at"])

    # verify excessive future clock skew is not shown as success
    def test_future_status_clears_observed_state(self) -> None:
        now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        self.write_status((now + timedelta(seconds=31)).isoformat().replace("+00:00", "Z"))
        payload = sanitized_status(self.status_path, now=now)
        self.assertEqual("error", payload["phase"])
        self.assertEqual(UNKNOWN_STATUS_MESSAGE, payload["message"])
        self.assertIsNone(payload["networks"]["flightaware"]["running"])
        self.assertIsNone(payload["networks"]["flightaware"]["connected"])

    # verify malformed timestamps are treated as unknown observations
    def test_malformed_status_timestamp_clears_observed_state(self) -> None:
        now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        self.write_status("not-a-timestamp")
        payload = sanitized_status(self.status_path, now=now)
        self.assertEqual("error", payload["phase"])
        self.assertEqual("", payload["updated_at"])
        self.assertEqual(UNKNOWN_STATUS_MESSAGE, payload["networks"]["flightaware"]["message"])

    # verify fresh nullable observations stay explicitly unknown
    def test_null_status_observations_are_preserved(self) -> None:
        now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        self.write_status(now.isoformat().replace("+00:00", "Z"), nullable=True)
        payload = sanitized_status(self.status_path, now=now)
        self.assertEqual("ready", payload["phase"])
        self.assertIsNone(payload["hardware"]["connected"])
        self.assertIsNone(payload["networks"]["flightaware"]["connected"])
        self.assertFalse(payload["networks"]["flightaware"]["running"])

    # reject malformed reception metrics without hiding valid source state
    def test_reception_projection_bounds_metrics_and_timestamps(self) -> None:
        now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        self.write_status(now.isoformat().replace("+00:00", "Z"))
        status = json.loads(self.status_path.read_text(encoding="utf-8"))
        status["reception"]["1090"].update(
            {
                "messages_per_minute": float("inf"),
                "last_activity_at": "not-a-timestamp",
                "sample_at": "2026-09-05T12:01:00Z",
            }
        )
        status["reception"]["978"]["telemetry_state"] = "broken"
        self.status_path.write_text(json.dumps(status), encoding="utf-8")
        payload = sanitized_status(self.status_path, now=now)
        self.assertIsNone(payload["reception"]["1090"]["messages_per_minute"])
        self.assertIsNone(payload["reception"]["1090"]["last_activity_at"])
        self.assertIsNone(payload["reception"]["1090"]["sample_at"])
        self.assertEqual("unavailable", payload["reception"]["978"]["telemetry_state"])
        self.assertIsNone(payload["reception"]["978"]["messages_per_minute"])

    # verify a null status document is unknown rather than stopped
    def test_null_status_document_is_unknown(self) -> None:
        self.status_path.parent.mkdir()
        self.status_path.write_text("null\n", encoding="utf-8")
        payload = sanitized_status(self.status_path)
        self.assertEqual("error", payload["phase"])
        self.assertEqual(UNKNOWN_STATUS_MESSAGE, payload["message"])
        self.assertIsNone(payload["hardware"]["connected"])

    # verify the request body limit is enforced before parsing
    def test_json_body_limit_is_enforced(self) -> None:
        status, headers, payload = self.json_request(
            "POST",
            "/api/login",
            headers={"Origin": TEST_ORIGIN, "Content-Type": "application/json"},
            raw_body=b"x" * (MAX_BODY_BYTES + 1),
        )
        self.assertEqual(413, status)
        self.assertEqual({"error": "invalid_request"}, payload)
        self.assertEqual("close", headers["connection"])

    # verify settings survive application restart without regenerating ids
    def test_restart_preserves_settings_and_generated_ids(self) -> None:
        initial = json.loads(self.settings_path.read_text(encoding="utf-8"))
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        restarted_application = AdminApplication(
            web_root=self.web_root,
            settings_path=self.settings_path,
            status_path=self.status_path,
            password_hash=make_password_hash(self.password),
            origin=TEST_ORIGIN,
            secure_cookie=True,
        )
        self.server = create_server(("127.0.0.1", 0), restarted_application)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.address = self.server.server_address
        reloaded = restarted_application.settings.get_private()
        self.assertEqual(initial, reloaded)


# verify throttling separately with a small deterministic limit
class LoginRateLimitTest(unittest.TestCase):
    # reject requests after the configured attempt count
    def test_rate_limiter_blocks_and_clears(self) -> None:
        limiter = LoginRateLimiter(max_attempts=2, window_seconds=60)
        self.assertEqual((True, 0), limiter.allow("client"))
        self.assertEqual((True, 0), limiter.allow("client"))
        allowed, retry_after = limiter.allow("client")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)
        limiter.clear("client")
        self.assertEqual((True, 0), limiter.allow("client"))


# verify the deployment-facing frame origin input
class AdminCliTest(unittest.TestCase):
    # prefer an explicit flag over the optional environment default
    def test_frame_origin_flag_and_environment(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(_parser().parse_args([]).frame_origin)
        with patch.dict("os.environ", {"ADSB_ADMIN_FRAME_ORIGIN": FRAME_ORIGIN}, clear=False):
            self.assertEqual(FRAME_ORIGIN, _parser().parse_args([]).frame_origin)
            self.assertEqual(
                "https://other.example.com",
                _parser().parse_args(["--frame-origin", "https://other.example.com"]).frame_origin,
            )


# run tests directly
if __name__ == "__main__":
    unittest.main()
