"""Safety tests for exact-candidate update execution."""

import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from adsb_admin import update_worker
from adsb_admin.update_evidence import canonical_hash


# build one internally consistent private candidate
def candidate(*, compatibility="unknown", state="held"):
    evidence = {"schema_version": 1, "target": "sha256:" + "c" * 64}
    evidence_sha256 = canonical_hash(evidence)
    identity = {
        "name": "proxy",
        "kind": "image",
        "current_target": "nginx@sha256:" + "a" * 64,
        "candidate_target": "docker.io/library/nginx@sha256:" + "b" * 64,
        "evidence_sha256": evidence_sha256,
    }
    return {
        "id": canonical_hash(identity),
        "name": "proxy",
        "label": "Nginx proxy",
        "current_version": "1.30.4",
        "candidate_version": "1.30.5",
        "compatibility": compatibility,
        "state": state,
        "reason": "bounded test evidence",
        "changelog": "Bugfix only",
        "changelog_url": "https://nginx.org/en/CHANGES-1.30",
        **identity,
        "evidence": evidence,
        "evidence_sha256": evidence_sha256,
    }


# build one generation bound to a fixed source snapshot
def candidate_store(source_release="/opt/adsb/releases/20261006T000000Z-1", rows=None):
    values = rows if rows is not None else [candidate()]
    generation = canonical_hash(
        {"source_release": source_release, "candidate_ids": sorted(row["id"] for row in values)}
    )
    return {
        "schema_version": 1,
        "generation": generation,
        "source_release": source_release,
        "candidates": values,
    }


class UpdateWorkerTests(unittest.TestCase):
    # keep atomic request claims within one writable systemd mount
    def test_service_claim_paths_share_one_writable_mount(self):
        unit = (Path(__file__).parents[1] / "deploy/adsb-updater.service").read_text()
        # read the single service writable mount declaration
        writable = next(
            line.partition("=")[2].split() for line in unit.splitlines() if line.startswith("ReadWritePaths=")
        )
        self.assertIn("/var/lib/adsb", writable)
        # forbid separately mounted claim source and destination directories
        for sibling in ("/var/lib/adsb/config", "/var/lib/adsb/runtime", "/var/lib/adsb/status"):
            self.assertNotIn(sibling, writable)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("NoNewPrivileges=true", unit)

    # stage every selected pin together while leaving unselected components intact
    def test_manual_batch_stages_one_release_with_only_selected_targets(self):
        first = candidate()
        second = {
            **candidate(),
            "name": "cloudflared",
            "current_target": "cloudflare/cloudflared@sha256:" + "d" * 64,
            "candidate_target": "cloudflare/cloudflared@sha256:" + "e" * 64,
        }
        source = Path("/opt/adsb/releases/batch-fixture")
        original_images = {
            "proxy": first["current_target"],
            "cloudflared": second["current_target"],
            "ultrafeeder": "unchanged-source-pin",
        }

        # model the single trusted release copy without touching a real deployment tree
        def copy_release(_source, destination, **_kwargs):
            (destination / "deploy").mkdir(parents=True)
            (destination / "deploy/images.json").write_text(json.dumps(original_images))

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(update_worker, "CURRENT_PATH") as current,
            patch.object(
                update_worker.shutil, "disk_usage", return_value=SimpleNamespace(free=4 * 1024**3, total=16 * 1024**3)
            ),
            patch.object(update_worker.shutil, "copytree", side_effect=copy_release) as copy,
            patch.object(update_worker, "collect_headroom", return_value={"headroom_passed": True}),
            patch.object(update_worker, "_refresh_proof_headroom") as refresh,
            patch.object(update_worker, "_regenerate_source_proof") as regenerate,
        ):
            current.resolve.return_value = source
            stage = update_worker.stage_candidates(
                {"source_release": str(source)}, [first, second], "f" * 64, runtime=Path(directory)
            )
            staged_images = json.loads((stage / "deploy/images.json").read_text())
            self.assertEqual(
                staged_images,
                {**original_images, "proxy": first["candidate_target"], "cloudflared": second["candidate_target"]},
            )
            self.assertEqual(copy.call_count, 1)
            self.assertEqual(refresh.call_count, 1)
            regenerate.assert_not_called()

    # atomically remove the watched name before accepting a strict request
    def test_claim_request_is_strict_and_one_shot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            request_path = root / "update-request.json"
            request = {
                "schema_version": 1,
                "request_id": "a" * 64,
                "candidate_ids": ["b" * 64, "d" * 64],
                "generation": "c" * 64,
                "requested_at": datetime.now(timezone.utc).isoformat(),
            }
            request_path.write_text(json.dumps(request))
            request_path.chmod(0o600)
            self.assertEqual(
                update_worker.claim_request(request_path, runtime=runtime, adsb_uid=os.getuid()),
                request,
            )
            self.assertFalse(os.path.lexists(request_path))
            self.assertEqual(list(runtime.iterdir()), [])
            # normalize a queued earlier release's singleton before root selection
            legacy = {key: value for key, value in request.items() if key != "candidate_ids"}
            legacy["candidate_id"] = "b" * 64
            request_path.write_text(json.dumps(legacy))
            request_path.chmod(0o600)
            normalized = update_worker.claim_request(request_path, runtime=runtime, adsb_uid=os.getuid())
            self.assertEqual(normalized["candidate_ids"], ["b" * 64])
            self.assertNotIn("candidate_id", normalized)
            # invalid batch envelopes are consumed once without authorizing a subset
            for identifiers in ([], ["b" * 64] * 2, [True], [f"{index:064x}" for index in range(8)]):
                request_path.write_text(json.dumps({**request, "candidate_ids": identifiers}))
                request_path.chmod(0o600)
                with self.subTest(identifiers=identifiers), self.assertRaises(ValueError):
                    update_worker.claim_request(request_path, runtime=runtime, adsb_uid=os.getuid())
                self.assertFalse(os.path.lexists(request_path))
            # invalid permissions are still removed from the watched path
            request_path.write_text(json.dumps(request))
            request_path.chmod(0o644)
            with self.assertRaises(ValueError):
                update_worker.claim_request(request_path, runtime=runtime, adsb_uid=os.getuid())
            self.assertFalse(os.path.lexists(request_path))
            # broken links cannot retrigger PathExists indefinitely
            request_path.symlink_to(root / "missing")
            with self.assertRaises(OSError):
                update_worker.claim_request(request_path, runtime=runtime, adsb_uid=os.getuid())
            self.assertFalse(os.path.lexists(request_path))

    # bind generation and identifiers to the complete evidence contract
    def test_candidate_store_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidates.json"
            store = candidate_store()
            path.write_text(json.dumps(store))
            path.chmod(0o600)
            self.assertEqual(update_worker.load_candidate_store(path, root_uid=os.getuid()), store)
            store["candidates"][0]["evidence"]["target"] = "sha256:" + "d" * 64
            path.write_text(json.dumps(store))
            with self.assertRaises(ValueError):
                update_worker.load_candidate_store(path, root_uid=os.getuid())

    # persist only the fixed root-admin status envelope and permissions
    def test_installation_status_is_bounded_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "installation.json"
            update_worker.write_installation(
                generation="a" * 64,
                request_id="b" * 64,
                candidate_id="c" * 64,
                candidate_ids=["c" * 64],
                state="queued",
                message="queued",
                path=path,
                adsb_gid=os.getgid(),
                root_uid=os.getuid(),
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(update_worker.read_installation(path, root_uid=os.getuid())["state"], "queued")

    # exercise orchestration with real request candidate and status storage
    def _run_fixture(self, rows, prior=None, *, request_ids=None, invalid=None):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
            root = Path(directory)
            source = root / "release"
            source.mkdir()
            runtime = root / "runtime"
            runtime.mkdir()
            current = root / "current"
            current.symlink_to(source)
            store = candidate_store(str(source), rows)
            candidates_path = runtime / "candidates.json"
            candidates_path.write_text(json.dumps(store))
            candidates_path.chmod(0o600)
            status_path = root / "installation.json"
            request_path = root / "request.json"
            # seed one valid prior attempt or an invalid retry fence
            if prior is not None:
                update_worker.write_installation(
                    generation=store["generation"],
                    request_id="f" * 64,
                    candidate_id=prior[0],
                    candidate_ids=prior,
                    state="failed",
                    message="failed",
                    path=status_path,
                    adsb_gid=os.getgid(),
                    root_uid=os.getuid(),
                )
            if invalid is not None:
                status_path.write_text("{}")
                status_path.chmod(invalid)
            if request_ids is not None:
                request_path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "request_id": "d" * 64,
                            "generation": store["generation"],
                            "candidate_ids": request_ids,
                            "requested_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                )
                request_path.chmod(0o600)
            read_status = partial(update_worker.read_installation, status_path, root_uid=os.getuid())
            write_status = partial(
                update_worker.write_installation, path=status_path, adsb_gid=os.getgid(), root_uid=os.getuid()
            )
            patches.enter_context(patch.object(update_worker.os, "geteuid", return_value=0))
            patches.enter_context(
                patch.object(
                    update_worker,
                    "_open_operation_lock",
                    side_effect=lambda: os.open(root / "lock", os.O_CREAT | os.O_RDWR, 0o600),
                )
            )
            patches.enter_context(patch.object(update_worker, "CURRENT_PATH", current))
            patches.enter_context(
                patch.object(
                    update_worker,
                    "claim_request",
                    partial(update_worker.claim_request, request_path, runtime=runtime, adsb_uid=os.getuid()),
                )
            )
            patches.enter_context(
                patch.object(
                    update_worker,
                    "load_candidate_store",
                    partial(update_worker.load_candidate_store, candidates_path, root_uid=os.getuid()),
                )
            )
            patches.enter_context(patch.object(update_worker, "read_installation", read_status))
            patches.enter_context(patch.object(update_worker, "write_installation", write_status))
            patches.enter_context(patch.object(update_worker, "_run_command"))
            patches.enter_context(patch.object(update_worker, "revalidate"))
            stage = patches.enter_context(
                patch.object(update_worker, "stage_candidates", return_value=runtime / "stage")
            )
            patches.enter_context(patch.object(update_worker, "verify_activation"))
            patches.enter_context(patch.object(update_worker, "_start_discovery_refresh"))
            result = update_worker.run()
            selected = stage.call_args.args[1] if stage.called else []
            status = json.loads(status_path.read_text()) if status_path.exists() else None
            return result, selected, status

    # preserve unrelated automatic work after a held manual attempt fails
    def test_run_failed_manual_batch_does_not_fence_unrelated_automatic(self):
        held = candidate()
        compatible = {**candidate(compatibility="compatible", state="available"), "name": "cloudflared"}
        identity = {
            key: compatible[key] for key in ("name", "kind", "current_target", "candidate_target", "evidence_sha256")
        }
        compatible["id"] = canonical_hash(identity)
        result, selected, status = self._run_fixture([held, compatible], [held["id"]])
        self.assertEqual(result, 0)
        self.assertEqual(selected, [compatible])
        self.assertEqual(status["state"], "installed")
        self.assertEqual(set(status["attempted_candidate_ids"]), {held["id"], compatible["id"]})
        # explicit manual retries retain their exact authorization
        result, selected, _ = self._run_fixture([held], [held["id"]], request_ids=[held["id"]])
        self.assertEqual(result, 0)
        self.assertEqual(selected, [held])

    # permit absent ledger but fail closed on invalid stored retry state
    def test_run_invalid_ledger_never_stages_automatic_updates(self):
        row = candidate(compatibility="compatible", state="available")
        result, selected, _ = self._run_fixture([row])
        self.assertEqual(result, 0)
        self.assertEqual(selected, [row])
        for mode in (0o640, 0o600):
            with self.subTest(mode=mode), patch("sys.stderr", new_callable=io.StringIO) as diagnostic:
                result, selected, _ = self._run_fixture([row], invalid=mode)
                self.assertEqual(result, 1)
                self.assertEqual(selected, [])
                self.assertIn("installation status", diagnostic.getvalue().lower())

    # publish a manual rejection without reopening automatic authority through a corrupt fence
    def test_manual_invalid_ledger_reports_rejection_and_fences_all_candidates(self):
        held = candidate()
        compatible = {**candidate(compatibility="compatible", state="available"), "name": "cloudflared"}
        compatible["id"] = canonical_hash(
            {key: compatible[key] for key in ("name", "kind", "current_target", "candidate_target", "evidence_sha256")}
        )
        with patch("sys.stderr", new_callable=io.StringIO):
            result, selected, status = self._run_fixture([held, compatible], request_ids=[held["id"]], invalid=0o640)
        self.assertEqual(result, 1)
        self.assertEqual(selected, [])
        self.assertEqual(status["state"], "rejected")
        self.assertEqual(status["request_id"], "d" * 64)
        self.assertEqual(set(status["attempted_candidate_ids"]), {held["id"], compatible["id"]})

    # do not automatically retry a previously attempted compatible member
    def test_run_failed_automatic_member_is_not_retried(self):
        row = candidate(compatibility="compatible", state="available")
        result, selected, status = self._run_fixture([row], [row["id"]])
        self.assertEqual(result, 0)
        self.assertEqual(selected, [])
        self.assertEqual(status["state"], "failed")

    # make replacement and both claim-parent mutations durable
    def test_status_and_claim_fsync_directory_after_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = []
            real_fsync = os.fsync
            real_replace = os.replace
            real_rename = os.rename

            # record the actual descriptor type rather than mocking storage semantics
            def fsync(descriptor):
                events.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
                real_fsync(descriptor)

            # preserve the atomic file publication and capture its order
            def replace(source, target):
                events.append("replace")
                real_replace(source, target)

            # preserve request movement across the actual sibling directories
            def rename(source, target):
                events.append("rename")
                real_rename(source, target)

            with (
                patch.object(os, "fsync", side_effect=fsync),
                patch.object(os, "replace", side_effect=replace),
                patch.object(os, "rename", side_effect=rename),
            ):
                update_worker.write_installation(
                    generation="a" * 64,
                    request_id="b" * 64,
                    candidate_id="c" * 64,
                    candidate_ids=["c" * 64],
                    state="failed",
                    message="failed",
                    path=root / "status.json",
                    root_uid=os.getuid(),
                    adsb_gid=os.getgid(),
                )
                self.assertEqual(events, ["file", "replace", "directory"])
                request_root = root / "config"
                request_root.mkdir()
                runtime = root / "runtime"
                runtime.mkdir()
                request = request_root / "request.json"
                request.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "request_id": "a" * 64,
                            "generation": "b" * 64,
                            "candidate_ids": ["c" * 64],
                            "requested_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                )
                request.chmod(0o600)
                events.clear()
                update_worker.claim_request(request, runtime=runtime, adsb_uid=os.getuid())
                self.assertEqual(events, ["rename", "directory", "directory", "directory"])
                self.assertFalse(request.exists())
                self.assertEqual(list(runtime.iterdir()), [])

    # retain conservative outcome and nonsecret diagnostics when crash reconciliation cannot prove health
    def test_interrupted_reconciliation_reports_verification_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = candidate()
            store = candidate_store(str(root), [row])
            prior = {
                "generation": store["generation"],
                "request_id": "a" * 64,
                "candidate_id": row["id"],
                "candidate_ids": [row["id"]],
                "state": "installing",
            }
            writer = partial(
                update_worker.write_installation, path=root / "status.json", root_uid=os.getuid(), adsb_gid=os.getgid()
            )
            with (
                patch.object(update_worker, "CURRENT_PATH", root),
                patch.object(update_worker, "verify_activation", side_effect=RuntimeError("secret fixture")),
                patch.object(update_worker, "write_installation", writer),
                patch("sys.stderr", new_callable=io.StringIO) as diagnostic,
            ):
                self.assertEqual(update_worker._reconcile_interrupted(store, prior), "failed")
            self.assertEqual(json.loads((root / "status.json").read_text())["state"], "failed")
            self.assertIn("activation verification failed", diagnostic.getvalue())
            self.assertIn("rollback verification failed", diagnostic.getvalue())
            self.assertNotIn("secret fixture", diagnostic.getvalue())

    # surface a refresh failure without rewriting the terminal attempt
    def test_discovery_refresh_failure_is_visible(self):
        with (
            patch.object(update_worker, "_run_command", side_effect=RuntimeError("secret fixture")),
            patch("sys.stderr", new_callable=io.StringIO) as diagnostic,
        ):
            update_worker._start_discovery_refresh("/opt/adsb/releases/fixture")
        self.assertIn("discovery refresh failed", diagnostic.getvalue().lower())
        self.assertNotIn("secret fixture", diagnostic.getvalue())

    # compute five deltas after discarding cumulative boot swap counters
    def test_headroom_uses_five_fresh_samples(self):
        swaps = [(100, 200), (100, 200), (100, 200), (100, 200), (100, 200), (100, 200)]
        with (
            patch.object(update_worker, "_swap_counters", side_effect=swaps),
            patch.object(update_worker, "_mem_available", side_effect=[900000] * 5),
            patch.object(update_worker, "_oom_events", return_value=0),
        ):
            sleep = Mock()
            result = update_worker.collect_headroom(sleep=sleep)
        self.assertEqual(result["vmstat_swap_in_kib_per_second"], [0] * 5)
        self.assertEqual(result["mem_available_kib_samples"], [900000] * 5)
        self.assertTrue(result["headroom_passed"])
        self.assertEqual(sleep.call_count, 5)

    # pass map dependency names only as inert arguments to an isolated candidate container
    def test_ultrafeeder_map_dependency_check_is_argument_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            deploy = stage / "deploy"
            deploy.mkdir()
            manifest = {
                "base_image_dependency": {
                    "image_role": "ultrafeeder",
                    "html_root": "/usr/local/share/tar1090/html-webroot",
                    "database_directory": "db-3.14.1715",
                    "config": "config.js",
                }
            }
            (deploy / "map-ui.json").write_text(json.dumps(manifest))
            image = "ghcr.io/sdr-enthusiasts/docker-adsb-ultrafeeder@sha256:" + "a" * 64
            with patch.object(update_worker, "_run_command") as run:
                update_worker._verify_ultrafeeder_map_dependencies(stage, image)
            command = run.call_args.args[0]
            self.assertIn("--network=none", command)
            self.assertIn("--pull=never", command)
            self.assertEqual(command[-3:], ["/usr/local/share/tar1090/html-webroot", "db-3.14.1715", "config.js"])
            manifest["base_image_dependency"]["database_directory"] = "../../etc/adsb"
            (deploy / "map-ui.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                update_worker._verify_ultrafeeder_map_dependencies(stage, image)

    # keep held candidates manual and compatible candidates one atomic batch
    def test_candidate_selection_separates_manual_and_automatic(self):
        held = candidate()
        compatible = candidate(compatibility="compatible", state="available")
        compatible["name"] = "cloudflared"
        compatible["current_target"] = "cloudflare/cloudflared@sha256:" + "d" * 64
        compatible["candidate_target"] = "docker.io/cloudflare/cloudflared@sha256:" + "e" * 64
        compatible["evidence_sha256"] = canonical_hash(compatible["evidence"])
        compatible["id"] = canonical_hash(
            {
                "name": compatible["name"],
                "kind": compatible["kind"],
                "current_target": compatible["current_target"],
                "candidate_target": compatible["candidate_target"],
                "evidence_sha256": compatible["evidence_sha256"],
            }
        )
        store = candidate_store(rows=[held, compatible])
        request = {
            "request_id": "f" * 64,
            "candidate_ids": [held["id"]],
            "generation": store["generation"],
        }
        self.assertEqual(update_worker.select_candidates(store, request), ("f" * 64, [held]))
        # manual authorization may combine held and compatible exact candidates
        batch = {**request, "candidate_ids": sorted([held["id"], compatible["id"]])}
        _, selected = update_worker.select_candidates(store, batch)
        self.assertEqual([row["id"] for row in selected], batch["candidate_ids"])
        # missing or technically blocked peers reject the entire selection
        for identifiers in ([held["id"], "a" * 64], [held["id"], held["id"]]):
            with self.subTest(identifiers=identifiers), self.assertRaises(ValueError):
                update_worker.select_candidates(store, {**batch, "candidate_ids": identifiers})
        compatible["state"] = "blocked"
        with self.assertRaises(ValueError):
            update_worker.select_candidates(store, batch)
        compatible["state"] = "available"
        automatic_request, automatic = update_worker.select_candidates(store, None)
        self.assertRegex(automatic_request, r"^[a-f0-9]{64}$")
        self.assertEqual(automatic, [compatible])


if __name__ == "__main__":
    unittest.main()
