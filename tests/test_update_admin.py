"""Fixed update handoff persistence and authorization regressions."""

import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from adsb_admin.config import RevisionConflict, ValidationError
from adsb_admin.update_admin import UpdateAdmin, read_request


# exercise private request files without any privileged service or provider
class UpdateAdminTest(unittest.TestCase):
    # bind a bridge to an isolated private configuration directory
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.admin = UpdateAdmin(self.root / "settings.json", self.root / "status.json")
        self.now = datetime.now(timezone.utc)
        self.payload = {"candidate_ids": ["a" * 64], "generation": "b" * 64}
        self.report = {
            "updated_at": self.now.isoformat(),
            "status": "attention",
            "generation": "b" * 64,
            "updates": [{"id": "a" * 64, "state": "held"}],
            "installation": {"state": "idle"},
        }
        self.projection = patch(
            "adsb_admin.update_admin.public_report", side_effect=lambda _, **_kwargs: self.report.copy()
        )
        self.projection.start()

    # remove isolated state after each operation
    def tearDown(self):
        self.projection.stop()
        self.temporary.cleanup()

    # persist only a fixed owner-only envelope and acknowledge duplicates
    def test_queue_is_exact_private_and_idempotent(self):
        status, result = self.admin.request_install(self.payload, now=self.now)
        self.assertEqual(202, status)
        pending = read_request(self.admin.request_path)
        self.assertEqual({"schema_version", "request_id", "candidate_ids", "generation", "requested_at"}, set(pending))
        self.assertEqual(result["request_id"], pending["request_id"])
        self.assertEqual(0o600, self.admin.request_path.stat().st_mode & 0o777)
        self.assertEqual((202, result), self.admin.request_install(self.payload, now=self.now))
        self.assertEqual("queued", self.admin.report()["installation"]["state"])
        with self.assertRaises(RevisionConflict):
            self.admin.request_install({**self.payload, "candidate_ids": ["c" * 64]}, now=self.now)

    # reject unbound commands malformed keys stale reports and technical blocks
    def test_concurrent_duplicate_clicks_publish_one_request(self):
        # use independent file descriptions like separate request handler threads
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.admin.request_install(self.payload, now=self.now), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(202, results[0][0])
        self.assertEqual(results[0][1]["request_id"], read_request(self.admin.request_path)["request_id"])

    # reject unbound commands malformed keys stale reports and technical blocks
    def test_invalid_stale_and_blocked_candidates_are_not_queued(self):
        # cover arbitrary browser-controlled request shapes
        for value in ({}, [], {**self.payload, "command": "install"}, {**self.payload, "generation": True}):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.admin.request_install(value, now=self.now)
        # require exact current identities and fresh authorizable evidence
        for fields in (
            {"generation": "c" * 64},
            {"updated_at": (self.now - timedelta(days=9)).isoformat()},
            {"updates": [{"id": "a" * 64, "state": "blocked"}]},
            {"status": "unknown"},
        ):
            original = self.report
            self.report = {**original, **fields}
            with self.subTest(fields=fields), self.assertRaises(RevisionConflict):
                self.admin.request_install(self.payload, now=self.now)
            self.report = original
        self.assertFalse(self.admin.request_path.exists())

    # reflect a root claim without creating a second request during installation
    def test_root_progress_and_durable_cooldown(self):
        _, queued = self.admin.request_install(self.payload, now=self.now)
        self.admin.request_path.unlink()
        self.report["installation"] = {**queued, "state": "installing"}
        self.assertEqual((202, queued), self.admin.request_install(self.payload, now=self.now))
        self.report["installation"] = {"state": "failed"}
        self.assertEqual(429, self.admin.request_install(self.payload, now=self.now + timedelta(seconds=1))[0])
        self.assertEqual(202, self.admin.request_install(self.payload, now=self.now + timedelta(seconds=61))[0])

    # authorize a unique exact batch once regardless of checkbox ordering
    def test_batch_is_atomic_idempotent_and_order_independent(self):
        self.report["updates"].append({"id": "c" * 64, "state": "held"})
        payload = {**self.payload, "candidate_ids": ["c" * 64, "a" * 64]}
        status, queued = self.admin.request_install(payload, now=self.now)
        self.assertEqual(status, 202)
        self.assertEqual(queued["candidate_ids"], ["a" * 64, "c" * 64])
        self.assertEqual(self.admin.report()["installation"]["candidate_ids"], queued["candidate_ids"])
        self.assertEqual(
            self.admin.request_install({**payload, "candidate_ids": queued["candidate_ids"]}, now=self.now),
            (status, queued),
        )
        with self.assertRaises(RevisionConflict):
            self.admin.request_install(self.payload, now=self.now)

    # reject malformed selections and every partially installable batch before publication
    def test_batch_validation_rejects_duplicates_and_partial_authorization(self):
        # cover empty duplicate oversized and incorrectly typed selections
        for selection in ([], ["a" * 64] * 2, [f"{index:064x}" for index in range(8)], "a" * 64, [True], ["bad"]):
            with self.subTest(selection=selection), self.assertRaises(ValidationError):
                self.admin.request_install({**self.payload, "candidate_ids": selection}, now=self.now)
        payload = {**self.payload, "candidate_ids": ["a" * 64, "c" * 64]}
        # neither missing nor blocked peers may produce a partial request
        for peers in ([], [{"id": "c" * 64, "state": "blocked"}]):
            self.report["updates"] = [{"id": "a" * 64, "state": "held"}, *peers]
            with self.subTest(peers=peers), self.assertRaises(RevisionConflict):
                self.admin.request_install(payload, now=self.now)
        self.assertFalse(self.admin.request_path.exists())
        self.assertFalse(self.admin.ledger_path.exists())

    # continue accepting a cached previous browser's exact singleton payload
    def test_legacy_singleton_is_normalized_to_batch(self):
        _, queued = self.admin.request_install({"candidate_id": "a" * 64, "generation": "b" * 64}, now=self.now)
        self.assertEqual(queued["candidate_id"], "a" * 64)
        self.assertEqual(queued["candidate_ids"], ["a" * 64])
        self.assertNotIn("candidate_id", read_request(self.admin.request_path))

    # fail closed on links pipes oversized or permissive private handoffs
    def test_special_and_untrusted_request_files_are_rejected(self):
        path = self.admin.request_path
        os.mkfifo(path, 0o600)
        with self.assertRaises(ValueError):
            read_request(path)
        path.unlink()
        path.symlink_to(self.root / "missing")
        with self.assertRaises(OSError):
            read_request(path)
        path.unlink()
        path.write_text("x" * 1025)
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            read_request(path)
        path.write_text(json.dumps({"schema_version": 1}))
        with self.assertRaises(ValueError):
            read_request(path)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            read_request(path)
