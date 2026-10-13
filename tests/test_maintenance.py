"""Safety regressions for unattended receiver maintenance."""

import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from adsb_admin import maintenance
from adsb_admin.maintenance import amd64_digest, collect_report, prune_releases, public_report, release_time
from adsb_admin.update_evidence import ImageEvidence


# validate advisory update checks without contacting registries or changing images
class UpdateReportTests(unittest.TestCase):
    # create the smallest verbose registry descriptor
    def descriptor(self, digest, architecture="amd64"):
        return {"Descriptor": {"digest": digest, "platform": {"os": "linux", "architecture": architecture}}}

    # compare only the receiver platform even when other image variants differ
    def test_digest_selection_handles_indexes_and_single_manifests(self):
        amd64 = self.descriptor("sha256:" + "a" * 64)
        arm64 = self.descriptor("sha256:" + "b" * 64, "arm64")
        self.assertEqual(amd64_digest([arm64, amd64]), "sha256:" + "a" * 64)
        self.assertEqual(amd64_digest(amd64), "sha256:" + "a" * 64)

    # malformed or ambiguous platform metadata must remain unknown
    def test_digest_selection_rejects_missing_and_conflicting_platforms(self):
        # cover invalid envelopes and duplicate target platforms
        for manifest in (
            {},
            {"Descriptor": []},
            {"Descriptor": {"platform": []}},
            self.descriptor("not-a-digest"),
            self.descriptor("sha256:" + "a" * 64, "arm64"),
            [self.descriptor("sha256:" + "a" * 64), self.descriptor("sha256:" + "b" * 64)],
        ):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                amd64_digest(manifest)

    # failed lookups must not prevent publication of the other review results
    def test_registry_failure_is_reported_without_changing_pins(self):
        deploy = Path(__file__).parents[1] / "deploy"
        original = (deploy / "images.json").read_bytes()
        with (
            patch("adsb_admin.maintenance.registry_digest", side_effect=subprocess.TimeoutExpired("docker", 60)),
            patch("adsb_admin.maintenance.map_update_status", return_value="current"),
            self.assertLogs("root", level="WARNING") as logs,
        ):
            report = collect_report(deploy)
        self.assertEqual(report["status"], "attention")
        self.assertEqual([row["status"] for row in report["images"]], ["unknown"] * 6)
        self.assertEqual((deploy / "images.json").read_bytes(), original)
        self.assertTrue(any("ultrafeeder: upstream request timed out" in line for line in logs.output))

    # keep the complete NGINX positive evidence path reachable through an exact alpine tag
    def test_nginx_candidate_binds_alpine_version_tag_and_oci_evidence(self):
        current = ImageEvidence(
            target="docker.io/library/nginx@sha256:" + "a" * 64,
            digest="sha256:" + "a" * 64,
            config_digest="sha256:" + "1" * 64,
            config_size=100,
            version="1.30.4-alpine",
            revision="b" * 40,
            source="https://github.com/nginx/docker-nginx",
            base_name="docker.io/library/alpine:3.22",
            base_digest="sha256:" + "c" * 64,
        )
        candidate = ImageEvidence(
            target="docker.io/library/nginx@sha256:" + "d" * 64,
            digest="sha256:" + "d" * 64,
            config_digest="sha256:" + "2" * 64,
            config_size=101,
            version="1.30.5-alpine",
            revision="e" * 40,
            source="https://github.com/nginx/docker-nginx",
            base_name="docker.io/library/alpine:3.22",
            base_digest="sha256:" + "c" * 64,
        )
        client = Mock()
        client.resolve.side_effect = [current, candidate, candidate]
        with patch.object(
            maintenance,
            "review_nginx_candidate",
            return_value=(
                "compatible",
                "bounded positive evidence",
                "Bugfix only",
                "https://nginx.org/en/CHANGES-1.30",
            ),
        ) as review:
            row = maintenance._image_candidate(
                "proxy",
                current.target,
                "nginx:stable-alpine",
                client,
            )
        self.assertEqual(row["compatibility"], "compatible")
        self.assertEqual(row["state"], "available")
        self.assertEqual(client.resolve.call_args_list[-1].args, ("nginx:1.30.5-alpine",))
        self.assertEqual(review.call_args.args[6:8], (current.base_digest, candidate.base_digest))
        self.assertTrue(review.call_args.args[8])

    # malformed or contradictory success reports must never produce a green badge
    def test_success_requires_complete_consistent_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "maintenance.json"
            base = {"updated_at": datetime.now(timezone.utc).isoformat(), "status": "ok"}
            complete = {
                **base,
                "reboot_required": False,
                "disk_free_percent": 92,
                "map_status": "current",
                # include each managed image once
                "images": [
                    {"name": name, "review_ref": "repo:latest", "status": "current"}
                    for name in ("ultrafeeder", "piaware", "airspy", "dump978", "proxy", "cloudflared")
                ],
            }
            path.write_text(json.dumps(complete))
            self.assertEqual(public_report(path)["status"], "ok")
            # cover missing evidence duplicate roles malformed states and pending work
            for invalid, expected in (
                (base, "unknown"),
                ({**complete, "images": [complete["images"][0]] * 6}, "unknown"),
                ({**complete, "map_status": {}}, "unknown"),
                ({**complete, "disk_free_percent": True}, "unknown"),
                ({**complete, "reboot_required": True}, "attention"),
                ({**complete, "disk_free_percent": 5}, "attention"),
                ({**complete, "map_status": "review"}, "attention"),
            ):
                path.write_text(json.dumps(invalid))
                self.assertEqual(public_report(path)["status"], expected)

    # accept only the explicit public report fields
    def test_report_projection_redacts_unexpected_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "maintenance.json"
            path.write_text(
                json.dumps(
                    {
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                        "status": "attention",
                        "reboot_required": False,
                        "disk_free_percent": 92,
                        "secret": "must-not-leak",
                        "images": [
                            {
                                "name": "proxy",
                                "review_ref": "nginx:stable-alpine",
                                "status": "review",
                                "secret": "hidden",
                            }
                        ],
                    }
                )
            )
            result = public_report(path)
            self.assertEqual(result["status"], "attention")
            self.assertEqual(
                result["images"], [{"name": "proxy", "review_ref": "nginx:stable-alpine", "status": "review"}]
            )
            self.assertNotIn("secret", json.dumps(result))

    # expose the new update contract only for a complete evidence generation
    def test_update_projection_merges_only_matching_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "maintenance.json"
            installation_path = root / "installation.json"
            generation = "a" * 64
            candidate_id = "b" * 64
            report = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "status": "attention",
                "reboot_required": False,
                "disk_free_percent": 80,
                "images": [],
                "map_status": "unknown",
                "generation": generation,
                "updates": [
                    {
                        "id": candidate_id,
                        "name": "proxy",
                        "label": "Nginx proxy",
                        "current_version": "1.30.4",
                        "candidate_version": "1.30.5",
                        "compatibility": "unknown",
                        "state": "held",
                        "reason": "unknown compatibility",
                        "changelog": "é" * 6000 + "\x00hidden",
                        "changelog_url": "https://nginx.org/en/CHANGES-1.30",
                    }
                ],
                "notice_id": "c" * 64,
                "notify": True,
            }
            report_path.write_text(json.dumps(report))
            installation = {
                "schema_version": 1,
                "generation": generation,
                "request_id": "d" * 64,
                "candidate_id": candidate_id,
                "candidate_ids": [candidate_id],
                "state": "queued",
                "message": "queued",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            installation_path.write_text(json.dumps(installation))
            result = public_report(report_path, installation_path=installation_path)
            self.assertEqual(result["generation"], generation)
            self.assertEqual(result["installation"]["state"], "queued")
            self.assertEqual(result["installation"]["candidate_ids"], [candidate_id])
            self.assertEqual(result["notice_id"], "c" * 64)
            self.assertTrue(result["notify"])
            self.assertLessEqual(len(result["updates"][0]["changelog"].encode("utf-8")), 6000)
            self.assertNotIn("\x00", result["updates"][0]["changelog"])
            self.assertLessEqual(
                len(json.dumps(result, ensure_ascii=False).encode("utf-8")), maintenance.MAX_REPORT_BYTES
            )
            # expose every known member of a multi-update transaction
            second_id = "f" * 64
            report["updates"].append({**report["updates"][0], "id": second_id, "name": "cloudflared"})
            report_path.write_text(json.dumps(report))
            installation["candidate_ids"] = [second_id, candidate_id]
            installation_path.write_text(json.dumps(installation))
            self.assertEqual(
                public_report(report_path, installation_path=installation_path)["installation"]["candidate_ids"],
                sorted([candidate_id, second_id]),
            )
            # reject repeated or unknown members and a primary outside the batch
            for identifiers in ([candidate_id, candidate_id], ["e" * 64], [second_id]):
                installation["candidate_ids"] = identifiers
                installation_path.write_text(json.dumps(installation))
                self.assertEqual(
                    public_report(report_path, installation_path=installation_path)["installation"]["state"], "idle"
                )
            installation["candidate_ids"] = [candidate_id]
            # hide installation state from a different discovery generation
            installation["generation"] = "e" * 64
            installation_path.write_text(json.dumps(installation))
            self.assertEqual(
                public_report(report_path, installation_path=installation_path)["installation"]["state"],
                "idle",
            )

    # preserve terminal outcomes across refreshed authorization without exposing stale candidates
    def test_terminal_installation_outcome_survives_refresh_for_bounded_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(timezone.utc)
            report_path = root / "maintenance.json"
            status_path = root / "installation.json"
            report = {
                "updated_at": now.isoformat(),
                "status": "attention",
                "generation": "e" * 64,
                "updates": [],
                "reboot_required": False,
                "disk_free_percent": 80,
                "images": [],
                "map_status": "unknown",
            }
            report_path.write_text(json.dumps(report))
            status = {
                "schema_version": 1,
                "generation": "a" * 64,
                "request_id": "b" * 64,
                "candidate_id": "c" * 64,
                "candidate_ids": ["c" * 64],
                "state": "installed",
                "message": "verified installation",
                "updated_at": now.isoformat(),
            }
            status_path.write_text(json.dumps(status))
            projected = public_report(report_path, installation_path=status_path, now=now)
            self.assertEqual(projected["installation"]["state"], "installed")
            self.assertEqual(projected["installation"]["request_id"], status["request_id"])
            self.assertEqual(projected["generation"], report["generation"])
            self.assertEqual(projected["updates"], [])
            # active stale authorization must remain hidden
            status["state"] = "installing"
            status_path.write_text(json.dumps(status))
            self.assertEqual(
                public_report(report_path, installation_path=status_path, now=now)["installation"]["state"], "idle"
            )
            status["state"] = "failed"
            # future and expired outcomes are never claimed current
            for age in (-1, 8 * 86400 + 1):
                status["updated_at"] = (now - maintenance.timedelta(seconds=age)).isoformat()
                status_path.write_text(json.dumps(status))
                self.assertEqual(
                    public_report(report_path, installation_path=status_path, now=now)["installation"]["state"], "idle"
                )

    # malformed or legacy reports must not accidentally activate install controls
    def test_legacy_and_malformed_update_reports_omit_new_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "maintenance.json"
            legacy = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "status": "attention",
                "reboot_required": False,
                "disk_free_percent": 80,
                "images": [],
                "map_status": "unknown",
            }
            path.write_text(json.dumps(legacy))
            self.assertNotIn("generation", public_report(path))
            path.write_text(json.dumps({**legacy, "generation": "a" * 64, "updates": [{"id": "bad"}]}))
            result = public_report(path)
            self.assertNotIn("generation", result)
            self.assertNotIn("updates", result)

    # missing malformed stale and future reports must never appear successful
    def test_invalid_or_expired_report_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "maintenance.json"
            self.assertEqual(public_report(path)["status"], "unknown")
            # require recent timestamped evidence rather than trusting status strings
            for raw in (
                "not json",
                "[]",
                "x" * 16385,
                json.dumps({"updated_at": "2026-01-01T00:00:00", "status": "ok"}),
                json.dumps(
                    {"updated_at": (datetime.now(timezone.utc) - timedelta(days=9)).isoformat(), "status": "ok"}
                ),
                json.dumps(
                    {"updated_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(), "status": "ok"}
                ),
            ):
                path.write_text(raw)
                self.assertEqual(public_report(path)["status"], "unknown")

    # accept only fresh consistent failures and bounded removal summaries
    def test_failed_report_projection_uses_injected_clock_and_sanitizes_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "maintenance.json"
            now = datetime(2026, 10, 5, 18, 0, tzinfo=timezone.utc)
            failed = {
                "updated_at": (now - timedelta(hours=1)).isoformat(),
                "status": "failed",
                "reboot_required": None,
                "disk_free_percent": None,
                "images": [],
                "map_status": "unknown",
                "removed_expired_artifacts": 3,
                "exception": "must-not-leak",
            }
            path.write_text(json.dumps(failed))
            result = public_report(path, now=now)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["removed_expired_artifacts"], 3)
            self.assertNotIn("exception", json.dumps(result))
            # reject contradictory failures and unsafe counts
            for invalid in (
                {**failed, "images": [{"name": "proxy"}]},
                {**failed, "disk_free_percent": 80},
                {**failed, "removed_expired_artifacts": True},
                {**failed, "removed_expired_artifacts": 100001},
            ):
                path.write_text(json.dumps(invalid))
                self.assertEqual(public_report(path, now=now)["status"], "unknown")
            # use the injected clock for both stale and future boundaries
            for stamp in (now - timedelta(days=9), now + timedelta(seconds=1)):
                path.write_text(json.dumps({**failed, "updated_at": stamp.isoformat()}))
                self.assertEqual(public_report(path, now=now)["status"], "unknown")

    # never follow report links or propagate deeply nested parser failures
    def test_report_reader_rejects_links_and_recursive_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}")
            link = root / "maintenance.json"
            link.symlink_to(target)
            self.assertEqual(public_report(link)["status"], "unknown")
            link.unlink()
            link.write_text("[" * 1100 + "0" + "]" * 1100)
            self.assertEqual(public_report(link)["status"], "unknown")

    # publish a safe failed observation and return nonzero for operational errors
    def test_main_publishes_sanitized_failure_for_prune_and_collection_errors(self):
        cases = (
            (["maintenance"], ValueError("selected release secret"), None, None),
            (["maintenance"], None, OSError("registry credential"), 2),
            (["maintenance", "--report-only"], None, OSError("registry credential"), 0),
        )
        # cover prune failure collect failure and nondestructive report-only failure
        for argv, prune_error, collect_error, expected_count in cases:
            with self.subTest(argv=argv, prune_error=prune_error), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "maintenance.json"
                prune = Mock(side_effect=prune_error, return_value=["old-release", "old-map"])
                collect = Mock(side_effect=collect_error)
                candidates = {
                    "schema_version": 1,
                    "generation": "a" * 64,
                    "source_release": str(Path(directory)),
                    "candidates": [],
                }
                with (
                    patch.object(maintenance, "REPORT_PATH", path),
                    patch.object(maintenance.os, "geteuid", return_value=0),
                    patch.object(maintenance, "_activation_lock", return_value=nullcontext()) as activation_lock,
                    patch.object(maintenance, "prune_releases", prune),
                    patch.object(maintenance, "discover_candidates", return_value=candidates),
                    patch.object(maintenance, "write_candidate_store"),
                    patch.object(maintenance, "collect_report", collect),
                    patch("sys.argv", argv),
                    patch("sys.stdout", new_callable=io.StringIO) as stdout,
                    self.assertRaises(SystemExit) as stopped,
                ):
                    maintenance.main()
                self.assertEqual(stopped.exception.code, 1)
                report = json.loads(path.read_text())
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["removed_expired_artifacts"], expected_count)
                self.assertIsNone(report["reboot_required"])
                self.assertEqual(report["images"], [])
                self.assertNotIn("secret", path.read_text())
                self.assertNotIn("credential", stdout.getvalue())
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o640)
                # preserve report-only nondestructive behavior
                if "--report-only" in argv:
                    activation_lock.assert_not_called()
                    prune.assert_not_called()
                else:
                    activation_lock.assert_called_once_with()
                # skip collection when pruning itself failed
                if prune_error is not None:
                    collect.assert_not_called()

    # hold activation serialization only around retention
    def test_main_releases_activation_lock_before_discovery(self):
        events = []

        # record entry and exit around the destructive phase
        @contextmanager
        def held_lock():
            events.append("lock")
            try:
                yield
            finally:
                events.append("unlock")

        prune = Mock(side_effect=lambda *_: events.append("prune") or [])
        discover = Mock(side_effect=lambda *_: events.append("discover") or {"candidates": []})
        with (
            patch.object(maintenance.os, "geteuid", return_value=0),
            patch.object(maintenance, "_activation_lock", side_effect=held_lock),
            patch.object(maintenance, "prune_releases", prune),
            patch.object(maintenance, "discover_candidates", discover),
            patch.object(maintenance, "write_candidate_store"),
            patch.object(maintenance, "collect_report", return_value={"status": "ok"}),
            patch.object(maintenance, "_write_report"),
            patch("sys.argv", ["maintenance"]),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            maintenance.main()
        self.assertEqual(events, ["lock", "prune", "unlock", "discover"])

    # reject an invalid activation boundary before pruning or discovery
    def test_main_fails_closed_before_prune_when_activation_lock_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "maintenance.json"
            prune = Mock()
            discover = Mock()
            with (
                patch.object(maintenance, "REPORT_PATH", path),
                patch.object(maintenance.os, "geteuid", return_value=0),
                patch.object(maintenance, "_activation_lock", side_effect=ValueError("invalid lock")),
                patch.object(maintenance, "prune_releases", prune),
                patch.object(maintenance, "discover_candidates", discover),
                patch("sys.argv", ["maintenance"]),
                patch("sys.stdout", new_callable=io.StringIO),
                self.assertRaises(SystemExit),
            ):
                maintenance.main()
            prune.assert_not_called()
            discover.assert_not_called()
            self.assertEqual(json.loads(path.read_text())["status"], "failed")

    # keep weekly schedules and security-only policy explicit and reviewable
    def test_weekly_policy_has_no_automatic_reboot_or_mutable_deployment(self):
        deploy = Path(__file__).parents[1] / "deploy"
        timer = (deploy / "apt-upgrade-weekly.conf").read_text()
        self.assertIn("OnCalendar=\nOnCalendar=Tue *-*-* 04:00:00 America/Los_Angeles", timer)
        policy = (deploy / "52unattended-upgrades-adsb").read_text()
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', policy)
        self.assertNotIn('"${distro_id}:${distro_codename}-updates"', policy)
        source = (deploy.parent / "adsb_admin/maintenance.py").read_text()
        self.assertNotIn('"pull"', source)
        self.assertNotIn('"compose"', source)


# exercise retention only inside disposable directories
class RetentionTests(unittest.TestCase):
    # create a paired application and map release
    def make_release(self, root, name):
        application = root / "releases" / name
        map_release = root / "map-ui-releases" / name
        application.mkdir(parents=True)
        map_release.mkdir(parents=True)
        (application / "map-ui").symlink_to(map_release)
        return application, map_release

    # return one projected docker inspection row
    def docker_inspection(self, identifier, mounts, pid):
        return f"{json.dumps(identifier)}\t{json.dumps(mounts)}\t{json.dumps(pid)}\n".encode()

    # render one minimal kernel mount record
    def mount_record(self, root, target):
        return f"36 25 8:1 {root} {target} ro - ext4 /dev/sda rw\n"

    # open and lock only the installer's existing private file
    def test_activation_lock_uses_read_only_validated_descriptor(self):
        directory = Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        lock = Mock(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_dev=8, st_ino=9)
        path = Path("/run/lock/adsb/activation.lock")
        with (
            patch.object(Path, "lstat", side_effect=[directory, lock]),
            patch.object(maintenance.os, "open", return_value=17) as opened,
            patch.object(maintenance.os, "fstat", return_value=lock),
            patch.object(maintenance.fcntl, "flock") as flock,
            patch.object(maintenance.os, "close") as close,
            maintenance._activation_lock(path),
        ):
            pass
        opened.assert_called_once_with(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        flock.assert_called_once_with(17, maintenance.fcntl.LOCK_EX)
        close.assert_called_once_with(17)

    # preserve selected releases and two newest versions regardless of age
    def test_retention_preserves_active_recent_and_unmanaged_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            old, old_map = self.make_release(root, "20260101T000000Z-1")
            active, active_map = self.make_release(root, "20260102T000000Z-1")
            rollback, rollback_map = self.make_release(root, "20260103T000000Z-1")
            newest, newest_map = self.make_release(root, "20260104T000000Z-1")
            (root / "current").symlink_to(active)
            (root / "map-ui").symlink_to(active_map)
            unmanaged = root / "releases/operator-notes"
            unmanaged.mkdir()
            archive = runtime / "code-20260101T000000Z-1.tar.gz"
            archive.touch()
            private = runtime / "compose.json"
            private.write_text("private configuration")
            with patch.object(maintenance, "_container_release_references", return_value=(set(), set())):
                removed = prune_releases(root, runtime, now=datetime(2026, 9, 8, tzinfo=timezone.utc))
            self.assertEqual(set(removed), {str(old), str(old_map), str(archive)})
            # retained rollback artifacts and private files remain intact
            for path in (active, active_map, rollback, rollback_map, newest, newest_map, unmanaged, private):
                self.assertTrue(path.exists())

    # never follow a symlink out of the managed application root
    def test_retention_rejects_foreign_current_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            foreign = root / "foreign"
            foreign.mkdir()
            (root / "current").symlink_to(foreign)
            with self.assertRaises(ValueError):
                prune_releases(root, root / "runtime")
            self.assertTrue(foreign.exists())

    # retain exactly thirty-day-old data and never traverse foreign links
    def test_retention_boundary_and_symlink_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            boundary, boundary_map = self.make_release(root, "20260809T000000Z-1")
            self.make_release(root, "20260901T000000Z-1")
            active, active_map = self.make_release(root, "20260902T000000Z-1")
            (root / "current").symlink_to(active)
            (root / "map-ui").symlink_to(active_map)
            foreign = root / "foreign"
            foreign.mkdir()
            (foreign / "important").touch()
            (root / "releases/20260101T000000Z-1").symlink_to(foreign)
            (root / "map-ui-releases/20260101T000000Z-1").symlink_to(foreign)
            (runtime / "code-20260101T000000Z-1.tar.gz").symlink_to(foreign / "important")
            with patch.object(maintenance, "_container_release_references", return_value=(set(), set())):
                removed = prune_releases(root, runtime, now=datetime(2026, 9, 8, tzinfo=timezone.utc))
            self.assertEqual(removed, [])
            self.assertTrue(boundary.exists())
            self.assertTrue(boundary_map.exists())
            self.assertTrue((foreign / "important").exists())

    # retain every immutable tree still mounted by an adsb container
    def test_retention_preserves_live_kernel_roots_and_expires_unmounted_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            live_app, live_app_map = self.make_release(root, "20260101T000000Z-1")
            live_map_app, live_map = self.make_release(root, "20260102T000000Z-1")
            expired, expired_map = self.make_release(root, "20260103T000000Z-1")
            rollback, rollback_map = self.make_release(root, "20260901T000000Z-1")
            active, active_map = self.make_release(root, "20260902T000000Z-1")
            newest, newest_map = self.make_release(root, "20260903T000000Z-1")
            (live_app / "deploy").mkdir()
            (live_app / "deploy/nginx.conf").touch()
            (root / "current").symlink_to(active)
            (root / "map-ui").symlink_to(active_map)
            identifier = "a" * 64
            foreign = root / "foreign"
            foreign.mkdir()
            (foreign / "important").touch()
            mounts = [
                {"Type": "bind", "Source": str(root / "current/map-ui")},
                {"Type": "bind", "Source": str(foreign)},
            ]
            proc = root / "proc"
            (proc / "123").mkdir(parents=True)
            (proc / "123/mountinfo").write_text(
                self.mount_record(live_app / "deploy/nginx.conf", "/etc/nginx/nginx.conf")
                + self.mount_record(live_map, "/var/custom_html")
                + self.mount_record(foreign, "/var/lib/foreign")
                + self.mount_record("net:[4026531833]", "/run/docker/netns/default")
            )
            archive = runtime / "code-20260103T000000Z-1.tar.gz"
            archive.touch()
            listed = f"{identifier}\n".encode()
            inspected = self.docker_inspection(identifier, mounts, 123)
            with (
                patch.object(maintenance, "PROC_ROOT", proc),
                patch.object(
                    maintenance,
                    "_docker_output",
                    side_effect=[listed, inspected, listed, inspected],
                ) as docker_output,
            ):
                protected_apps, protected_maps = maintenance._container_release_references(root)
                removed = prune_releases(root, runtime, now=datetime(2026, 9, 8, tzinfo=timezone.utc))
            self.assertEqual(protected_apps, {active.resolve(), live_app.resolve()})
            self.assertEqual(protected_maps, {active_map.resolve(), live_map.resolve()})
            self.assertEqual(set(removed), {str(live_map_app), str(expired), str(expired_map), str(archive)})
            self.assertEqual(
                docker_output.call_args_list[0].args[0],
                [
                    "/usr/bin/docker",
                    "ps",
                    "-aq",
                    "--filter",
                    "label=com.docker.compose.project=adsb",
                ],
            )
            self.assertEqual(
                docker_output.call_args_list[1].args[0][1:4],
                ["inspect", "--format", "{{json .Id}}\t{{json .Mounts}}\t{{json .State.Pid}}"],
            )
            # preserve both application and standalone map mount roots
            for path in (
                live_app,
                live_app_map,
                live_map,
                rollback,
                rollback_map,
                active,
                active_map,
                newest,
                newest_map,
                foreign / "important",
            ):
                self.assertTrue(path.exists())

    # abort before deleting anything when docker or proc evidence is unavailable
    def test_retention_fails_closed_on_container_inspection_errors(self):
        # cover docker command failure and a stale positive container pid
        for stale_pid in (False, True):
            with self.subTest(stale_pid=stale_pid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                runtime = root / "runtime"
                runtime.mkdir()
                old, old_map = self.make_release(root, "20260101T000000Z-1")
                self.make_release(root, "20260901T000000Z-1")
                active, active_map = self.make_release(root, "20260902T000000Z-1")
                self.make_release(root, "20260903T000000Z-1")
                (root / "current").symlink_to(active)
                (root / "map-ui").symlink_to(active_map)
                archive = runtime / "code-20260101T000000Z-1.tar.gz"
                archive.touch()
                identifier = "b" * 64
                outputs = [
                    f"{identifier}\n".encode(),
                    self.docker_inspection(identifier, [{"Type": "bind", "Source": str(root / "current")}], 991),
                ]
                effect = outputs if stale_pid else OSError("docker unavailable")
                with (
                    patch.object(maintenance, "PROC_ROOT", root / "empty-proc"),
                    patch.object(maintenance, "_docker_output", side_effect=effect),
                    self.assertRaises((OSError, ValueError)),
                ):
                    prune_releases(root, runtime, now=datetime(2026, 10, 13, tzinfo=timezone.utc))
                # failures occur before application map or archive deletion
                for path in (old, old_map, archive):
                    self.assertTrue(path.exists())

    # reject malformed or unbounded docker projections before pruning
    def test_container_inspection_validates_ids_counts_schema_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identifier = "c" * 64
            cases = (
                (b"bad-id\n", b""),
                (f"{identifier}\n{identifier}\n".encode(), b""),
                (f"{identifier}\n".encode(), b""),
                (f"{identifier}\n".encode(), self.docker_inspection("d" * 64, [], 0)),
                (f"{identifier}\n".encode(), self.docker_inspection(identifier, {}, 0)),
                (
                    f"{identifier}\n".encode(),
                    self.docker_inspection(identifier, [{}] * (maintenance.MAX_CONTAINER_MOUNTS + 1), 0),
                ),
            )
            # validate every external identity and projection boundary
            for listed, inspected in cases:
                with (
                    self.subTest(listed=listed[:20], inspected=inspected[:20]),
                    patch.object(maintenance, "_docker_output", side_effect=[listed, inspected]),
                    self.assertRaises(ValueError),
                ):
                    maintenance._container_release_references(root)

    # bound docker output before parsing daemon-controlled metadata
    def test_docker_output_rejects_failure_and_oversized_output(self):
        # simulate command failure and a response one byte above its budget
        for returncode, payload in ((1, b""), (0, b"12345")):
            # write one controlled command result into the supplied capture file
            def run(_arguments, *, stdout, stderr, timeout):
                stdout.write(payload)
                return Mock(returncode=returncode)

            with (
                self.subTest(returncode=returncode, payload=payload),
                patch.object(maintenance.subprocess, "run", side_effect=run),
                self.assertRaises(ValueError),
            ):
                maintenance._docker_output(["docker"], maximum=4, timeout=1)

    # leave invalid dates and foreign names untouched
    def test_only_installer_names_are_recognized(self):
        self.assertIsNone(release_time("20260230T000000Z-1"))
        self.assertIsNone(release_time("old"))
        self.assertIsNone(release_time("20260101T000000Z-1.extra"))
        self.assertEqual(release_time("20260101T000000Z-1"), datetime(2026, 1, 1, tzinfo=timezone.utc))


# run the focused maintenance regressions
if __name__ == "__main__":
    unittest.main()
