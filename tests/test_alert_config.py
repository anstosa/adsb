"""Private aircraft alert configuration tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from adsb_admin.alert_config import ALERT_CATEGORIES, AlertSettingsStore
from adsb_admin.config import RevisionConflict, ValidationError


# exercise one isolated private settings document
class AlertSettingsStoreTest(unittest.TestCase):
    # create one isolated store
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "config" / "alerts.json"
        self.store = AlertSettingsStore(self.path)

    # remove isolated data
    def tearDown(self) -> None:
        self.temporary.cleanup()

    # build one complete public write
    def payload(self, *, enabled: bool = False) -> dict:
        return {
            "revision": self.store.get_public()["revision"],
            "enabled": enabled,
            "categories": list(ALERT_CATEGORIES),
            "pushover": {"app_token": "app-secret", "user_key": "user-secret"},
            "smtp": {
                "host": "smtp.example.com",
                "port": 465,
                "username": "smtp-user",
                "password": "smtp-secret",
                "from_address": "alerts@example.com",
                "to_address": "operator@example.net",
            },
            "overrides": [],
        }

    # default safely and protect private persistence
    def test_defaults_are_disabled_private_and_redacted(self) -> None:
        public = self.store.get_public()
        self.assertFalse(public["enabled"])
        self.assertEqual(list(ALERT_CATEGORIES), public["categories"])
        self.assertFalse(public["pushover"]["app_token_configured"])
        self.assertEqual(0o600, os.stat(self.path).st_mode & 0o777)
        self.assertEqual(0o700, os.stat(self.path.parent).st_mode & 0o777)
        serialized = json.dumps(public)
        self.assertNotIn('app_token"', serialized)
        self.assertNotIn('password"', serialized)

    # preserve omitted secrets and clear them only explicitly
    def test_secret_preservation_redaction_and_explicit_clear(self) -> None:
        saved = self.store.update(self.payload())
        self.assertTrue(saved["pushover"]["app_token_configured"])
        self.assertTrue(saved["smtp"]["password_configured"])
        replacement = self.payload()
        replacement["revision"] = saved["revision"]
        replacement["pushover"] = {}
        replacement["smtp"].pop("username")
        replacement["smtp"]["password"] = ""
        saved = self.store.update(replacement)
        private = self.store.get_private()
        self.assertEqual("app-secret", private["pushover"]["app_token"])
        self.assertEqual("smtp-user", private["smtp"]["username"])
        self.assertEqual("smtp-secret", private["smtp"]["password"])
        clear = self.payload()
        clear["revision"] = saved["revision"]
        clear["pushover"] = {"clear_app_token": True}
        clear["smtp"]["clear_password"] = True
        clear["smtp"].pop("password")
        saved = self.store.update(clear)
        self.assertFalse(saved["pushover"]["app_token_configured"])
        self.assertFalse(saved["smtp"]["password_configured"])

    # require both complete channels before activation
    def test_enable_requires_complete_both_channel_configuration(self) -> None:
        payload = self.payload(enabled=True)
        payload["smtp"]["password"] = ""
        with self.assertRaises(ValidationError) as caught:
            self.store.update(payload)
        self.assertEqual("is required when alerts are enabled", caught.exception.fields["smtp.password"])
        saved = self.store.update(self.payload(enabled=True))
        self.assertTrue(saved["enabled"])

    # reject unsafe smtp and ambiguous identity controls
    def test_rejects_smtp_injection_private_literal_and_duplicate_overrides(self) -> None:
        payload = self.payload()
        payload["smtp"]["host"] = "127.0.0.1"
        payload["smtp"]["from_address"] = "alerts@example.com\r\nBcc: bad@example.net"
        override = {"hex": "A2CCA7", "mode": "include", "categories": ["news"], "label": "News"}
        payload["overrides"] = [override, dict(override)]
        with self.assertRaises(ValidationError) as caught:
            self.store.update(payload)
        self.assertIn("smtp.host", caught.exception.fields)
        self.assertIn("smtp.from_address", caught.exception.fields)
        self.assertIn("overrides", caught.exception.fields)

    # isolate alert-only optimistic concurrency
    def test_stale_revision_returns_only_redacted_alert_settings(self) -> None:
        stale = self.payload()
        self.store.update(self.payload())
        with self.assertRaises(RevisionConflict) as caught:
            self.store.update(stale)
        serialized = json.dumps(caught.exception.current)
        self.assertNotIn("app-secret", serialized)
        self.assertNotIn("smtp-secret", serialized)

    # retain fail-closed private settings semantics for deeply nested corruption
    def test_nested_private_settings_are_unavailable(self) -> None:
        self.path.write_text("[" * 1500 + "0" + "]" * 1500)
        with self.assertRaises(RuntimeError):
            self.store.refresh()
        self.assertFalse(self.store.get_private()["enabled"])

    # validate worker read-only reloads without changing permissions
    def test_readonly_store_refreshes_and_refuses_writes(self) -> None:
        readonly = AlertSettingsStore(self.path, readonly=True)
        saved = self.store.update(self.payload())
        self.assertTrue(readonly.refresh())
        self.assertEqual(saved["revision"], readonly.get_private()["revision"])
        with self.assertRaises(RuntimeError):
            readonly.update(self.payload())


# run focused checks directly
if __name__ == "__main__":
    unittest.main()
