"""Private aircraft alert configuration tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from adsb_admin.alert_config import ALERT_CATEGORIES, ALERT_CHANNELS, AlertSettingsStore
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
        self.assertEqual(
            {category: list(ALERT_CHANNELS) for category in ALERT_CATEGORIES},
            public["category_channels"],
        )
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

    # require every selected channel before activation
    def test_enable_requires_complete_selected_channel_configuration(self) -> None:
        payload = self.payload(enabled=True)
        payload["smtp"]["password"] = ""
        with self.assertRaises(ValidationError) as caught:
            self.store.update(payload)
        self.assertEqual("is required when alerts are enabled", caught.exception.fields["smtp.password"])
        saved = self.store.update(self.payload(enabled=True))
        self.assertTrue(saved["enabled"])

    # expose legacy routes without rewriting the version-one file
    def test_legacy_file_loads_selected_categories_to_both_without_rewrite(self) -> None:
        legacy_path = self.path.parent / "legacy.json"
        legacy = {
            "schema_version": 1,
            "revision": 7,
            "enabled": False,
            "categories": ["medical"],
            "pushover": {"app_token": "", "user_key": ""},
            "smtp": {
                "host": "",
                "port": 465,
                "username": "",
                "password": "",
                "from_address": "",
                "to_address": "",
            },
            "overrides": [],
        }
        serialized = json.dumps(legacy, separators=(",", ":"))
        legacy_path.write_text(serialized, encoding="utf-8")
        loaded = AlertSettingsStore(legacy_path)
        public = loaded.get_public()
        self.assertEqual(7, public["revision"])
        self.assertEqual(
            {"military": [], "medical": ["pushover", "email"], "news": []},
            public["category_channels"],
        )
        self.assertEqual(serialized, legacy_path.read_text(encoding="utf-8"))

    # fail closed when legacy category values cannot represent supported names
    def test_legacy_file_with_unhashable_category_is_invalid(self) -> None:
        legacy_path = self.path.parent / "invalid-legacy.json"
        legacy = {
            "schema_version": 1,
            "revision": 7,
            "enabled": False,
            "categories": [["medical"]],
            "pushover": {"app_token": "", "user_key": ""},
            "smtp": {
                "host": "",
                "port": 465,
                "username": "",
                "password": "",
                "from_address": "",
                "to_address": "",
            },
            "overrides": [],
        }
        legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "invalid schema"):
            AlertSettingsStore(legacy_path)

    # reject an explicit malformed route value instead of treating it as legacy
    def test_explicit_malformed_route_map_is_invalid(self) -> None:
        malformed_path = self.path.parent / "invalid-routes.json"
        malformed = json.loads(self.path.read_text(encoding="utf-8"))
        malformed["category_channels"] = []
        malformed_path.write_text(json.dumps(malformed), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "invalid schema"):
            AlertSettingsStore(malformed_path)

    # preserve current routes and default only newly selected legacy categories
    def test_legacy_write_preserves_routes_and_defaults_new_categories_to_both(self) -> None:
        explicit = self.payload()
        explicit["categories"] = ["news"]
        explicit["category_channels"] = {"military": [], "medical": [], "news": ["pushover"]}
        saved = self.store.update(explicit)
        legacy = self.payload()
        legacy["revision"] = saved["revision"]
        legacy["categories"] = ["news"]
        saved = self.store.update(legacy)
        self.assertEqual(["pushover"], saved["category_channels"]["news"])
        legacy = self.payload()
        legacy["revision"] = saved["revision"]
        legacy["categories"] = ["medical", "news"]
        saved = self.store.update(legacy)
        self.assertEqual(["pushover", "email"], saved["category_channels"]["medical"])
        self.assertEqual(["pushover"], saved["category_channels"]["news"])

    # require explicit category membership to match nonempty route rows
    def test_explicit_routes_reject_mismatches_and_allow_disabled_empty_selection(self) -> None:
        incomplete = self.payload()
        incomplete["categories"] = ["news"]
        incomplete["category_channels"] = {"military": [], "news": ["pushover"]}
        with self.assertRaises(ValidationError) as caught:
            self.store.update(incomplete)
        self.assertIn("category_channels", caught.exception.fields)
        repeated = self.payload()
        repeated["categories"] = ["news"]
        repeated["category_channels"] = {
            "military": [],
            "medical": [],
            "news": ["pushover", "pushover"],
        }
        with self.assertRaises(ValidationError) as caught:
            self.store.update(repeated)
        self.assertIn("category_channels.news", caught.exception.fields)
        mismatch = self.payload()
        mismatch["categories"] = ["news"]
        mismatch["category_channels"] = {"military": [], "medical": ["email"], "news": ["pushover"]}
        with self.assertRaises(ValidationError) as caught:
            self.store.update(mismatch)
        self.assertIn("category_channels", caught.exception.fields)
        disabled = self.payload()
        disabled["categories"] = []
        disabled["category_channels"] = {category: [] for category in ALERT_CATEGORIES}
        saved = self.store.update(disabled)
        self.assertEqual([], saved["categories"])
        enabled = self.payload(enabled=True)
        enabled["categories"] = []
        enabled["category_channels"] = {category: [] for category in ALERT_CATEGORIES}
        with self.assertRaises(ValidationError) as caught:
            self.store.update(enabled)
        self.assertIn("category_channels", caught.exception.fields)

    # require credentials only for providers used by selected routes
    def test_selected_routes_validate_only_their_provider_credentials(self) -> None:
        push_store = AlertSettingsStore(self.path.parent / "push.json")
        push = self.payload(enabled=True)
        push["revision"] = 0
        push["categories"] = ["news"]
        push["category_channels"] = {"military": [], "medical": [], "news": ["pushover"]}
        push["smtp"] = {
            "host": "",
            "port": 465,
            "username": "",
            "password": "",
            "from_address": "",
            "to_address": "",
        }
        self.assertTrue(push_store.update(push)["enabled"])

        email_store = AlertSettingsStore(self.path.parent / "email.json")
        email = self.payload(enabled=True)
        email["revision"] = 0
        email["categories"] = ["medical"]
        email["category_channels"] = {"military": [], "medical": ["email"], "news": []}
        email["pushover"] = {"app_token": "", "user_key": ""}
        self.assertTrue(email_store.update(email)["enabled"])

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

    # normalize and preserve both supported override selector kinds
    def test_exact_and_model_overrides_round_trip_without_migration(self) -> None:
        payload = self.payload()
        payload["overrides"] = [
            {"hex": "a2cca7", "mode": "include", "categories": ["news"], "label": "Exact aircraft"},
            {"model": "c17", "mode": "exclude", "categories": ["medical"], "label": "Heavy transport"},
        ]
        saved = self.store.update(payload)
        self.assertEqual("A2CCA7", saved["overrides"][0]["hex"])
        self.assertEqual("C17", saved["overrides"][1]["model"])
        reloaded = AlertSettingsStore(self.path)
        self.assertEqual(saved["overrides"], reloaded.get_public()["overrides"])
        self.assertEqual(saved["overrides"], reloaded.get_private()["overrides"])

    # reject ambiguous selectors and invalid or duplicate model designators
    def test_model_override_validation_is_exact_and_unambiguous(self) -> None:
        invalid_models = ("C", "C-17", "C17*", "ABCDE", 17)
        # reject every value outside the bounded icao model grammar
        for model in invalid_models:
            with self.subTest(model=model):
                payload = self.payload()
                payload["overrides"] = [
                    {"model": model, "mode": "include", "categories": ["military"], "label": "Model"}
                ]
                with self.assertRaises(ValidationError) as caught:
                    self.store.update(payload)
                self.assertIn("overrides.0.model", caught.exception.fields)
        payload = self.payload()
        payload["overrides"] = [
            {"model": "c17", "mode": "include", "categories": ["military"], "label": "First"},
            {"model": "C17", "mode": "exclude", "categories": ["news"], "label": "Second"},
        ]
        with self.assertRaises(ValidationError) as caught:
            self.store.update(payload)
        self.assertIn("overrides", caught.exception.fields)
        payload["overrides"] = [
            {
                "hex": "A2CCA7",
                "model": "C17",
                "mode": "include",
                "categories": ["news"],
                "label": "Ambiguous",
            }
        ]
        with self.assertRaises(ValidationError) as caught:
            self.store.update(payload)
        self.assertIn("overrides.0", caught.exception.fields)

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
