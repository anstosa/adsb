"""Regression tests for disposable source-proof container ownership."""

from __future__ import annotations

import datetime as dt
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("source_proof_runner", ROOT / "deploy/alerts/prove-sources.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


# verify exact container ownership without running docker
class DisposableContainerTests(unittest.TestCase):
    # verify every actual fixture invocation has the provider-free security boundary
    def test_main_builds_isolated_container_commands(self):
        prior = json.loads((ROOT / "deploy/alerts/source-proof.json").read_text())
        commands = []

        # return recorded fixture evidence only at the external execution boundary
        def run_json(arguments, *, timeout):
            commands.append(arguments)
            if RUNNER.READSB_PROBE in arguments:
                return prior["sources"][0 if arguments[-2] == "1090" else 1]
            if RUNNER.NATIVE_PROBE in arguments:
                return prior["native978"]["proof"]
            return prior["worker"]

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(RUNNER, "_run_json", side_effect=run_json),
            patch.object(RUNNER, "_load_headroom", return_value=prior["production_headroom"]),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            output = Path(directory) / "proof.json"
            with patch(
                "sys.argv",
                [
                    "prove-sources.py",
                    "--output",
                    str(output),
                    "--headroom-json",
                    "unused",
                    "--headroom-audit-json",
                    "unused",
                ],
            ):
                self.assertEqual(RUNNER.main(), 0)
            self.assertTrue(output.is_file())
        self.assertEqual(len(commands), 4)
        # inspect the real argv for both readers native decoder and worker
        for arguments in commands:
            self.assertEqual(arguments[:2], ["docker", "run"])
            for flag in (
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
            ):
                self.assertIn(flag, arguments)
            self.assertNotIn("--publish", arguments)
            self.assertNotIn("--privileged", arguments)
        self.assertIn("--memory=96m", commands[-1])
        self.assertIn(RUNNER.WORKER_PROBE, commands[-1])

    # keep embedded fixture programs syntactically valid before remote execution
    def test_fixture_programs_compile(self):
        for name in ("READSB_PROBE", "NATIVE_PROBE", "WORKER_PROBE"):
            compile(getattr(RUNNER, name), name, "exec")

    # stage only the immutable worker catalog and metadata contracts
    def test_worker_inputs_include_pinned_local_model_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = RUNNER._stage_worker_inputs(Path(directory))
            for relative in (
                "deploy/alerts/catalog.json",
                "deploy/alerts/catalog-manifest.json",
                "deploy/alerts/source-contract.json",
                "deploy/map-ui.json",
            ):
                self.assertEqual((ROOT / relative).read_bytes(), (root / relative).read_bytes())
                self.assertEqual(0o644, (root / relative).stat().st_mode & 0o777)

    # bind timeout cleanup to the exact privately recorded fixture id
    def test_timeout_removes_only_its_owned_container(self):
        calls = []
        container_id = "a" * 64

        # model docker publishing its id before the client exceeds its deadline
        def run(arguments, **options):
            calls.append((arguments, options))
            if arguments[:2] == ["docker", "run"]:
                cidfile = Path(arguments[arguments.index("--cidfile") + 1])
                self.assertEqual(0o700, cidfile.parent.stat().st_mode & 0o777)
                cidfile.write_text(container_id + "\n")
                raise subprocess.TimeoutExpired(arguments, options["timeout"])
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch.object(RUNNER.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "runtime bound"):
                RUNNER._run_json(["docker", "run", "--rm", "--network=none", "fixture"], timeout=5)
        self.assertEqual(["docker", "rm", "--force", container_id], calls[1][0])
        self.assertEqual(15, calls[1][1]["timeout"])

    # never turn malformed fixture identity data into a docker target
    def test_invalid_container_id_cannot_trigger_cleanup(self):
        calls = []

        # model a failed container launch with invalid identity data
        def run(arguments, **options):
            calls.append(arguments)
            cidfile = Path(arguments[arguments.index("--cidfile") + 1])
            cidfile.write_text("adsb-ultrafeeder-1")
            raise subprocess.CalledProcessError(1, arguments, "", "fixture launch failed")

        with patch.object(RUNNER.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "fixture launch failed"):
                RUNNER._run_json(["docker", "run", "--rm", "fixture"], timeout=5)
        self.assertEqual(1, len(calls))

    # retain successful json results without issuing any cleanup mutation
    def test_success_keeps_result_and_automatic_removal(self):
        with patch.object(
            RUNNER.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, '{"passed":true}', ""),
        ) as run:
            self.assertEqual({"passed": True}, RUNNER._run_json(["docker", "run", "--rm", "fixture"], timeout=5))
        self.assertEqual(1, run.call_count)
        self.assertIn("--cidfile", run.call_args.args[0])


# lock reuse to unchanged recent native inputs without running any containers
class NativeEvidenceReuseTests(unittest.TestCase):
    # retain the original native observation time across worker reproofs
    def test_reuse_preserves_native_clock_and_requires_matching_inputs(self):
        health = (ROOT / "deploy/alerts/source-health.sh").read_text()
        prior = json.loads((ROOT / "deploy/alerts/source-proof.json").read_text())
        now = dt.datetime.now(dt.UTC).replace(microsecond=0)
        original = (now - dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        prior["generated_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        prior["native_evidence_generated_at"] = original
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            # copy immutable sibling provenance for the reuse contract
            for name in ("source-contract.json", "run-source.sh", "prove-sources.py"):
                shutil.copy2(ROOT / "deploy/alerts" / name, Path(directory) / name)
            path.write_text(json.dumps(prior))
            reused = RUNNER._reuse_native_proof(path, health)
            self.assertEqual(reused["native_evidence_generated_at"], original)
            self.assertEqual(reused["sources"], prior["sources"])
            # changed pins health or evidence cannot enter the reuse lane
            for change in ({"image": "different"}, {"health_sha256": "0" * 64}, {"sources": []}):
                path.write_text(json.dumps({**prior, **change}))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    RUNNER._reuse_native_proof(path, health)

    # reject stale future oversized and symlinked reuse artifacts
    def test_reuse_rejects_unsafe_or_stale_artifacts(self):
        health = (ROOT / "deploy/alerts/source-health.sh").read_text()
        prior = json.loads((ROOT / "deploy/alerts/source-proof.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            # copy immutable sibling provenance for the reuse contract
            for name in ("source-contract.json", "run-source.sh", "prove-sources.py"):
                shutil.copy2(ROOT / "deploy/alerts" / name, Path(directory) / name)
            # the original native clock cannot be refreshed by a newer worker timestamp
            for delta in (dt.timedelta(days=-2), dt.timedelta(hours=1)):
                prior["generated_at"] = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                prior["native_evidence_generated_at"] = (dt.datetime.now(dt.UTC) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
                path.write_text(json.dumps(prior))
                with self.subTest(delta=delta), self.assertRaises(ValueError):
                    RUNNER._reuse_native_proof(path, health)
            # changed sibling inputs or native literal programs cannot reuse old observations
            prior.pop("native_evidence_generated_at", None)
            prior["generated_at"] = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            path.write_text(json.dumps(prior))
            for name in ("source-contract.json", "run-source.sh", "prove-sources.py"):
                sibling = Path(directory) / name
                original = sibling.read_text()
                sibling.write_text(
                    original.replace("READSB_PROBE =", "ALTERED_PROBE =") if name == "prove-sources.py" else "changed"
                )
                with self.subTest(name=name), self.assertRaises(ValueError):
                    RUNNER._reuse_native_proof(path, health)
                sibling.write_text(original)
            path.write_text("x" * (64 * 1024 + 1))
            with self.assertRaises(ValueError):
                RUNNER._reuse_native_proof(path, health)
            link = Path(directory) / "linked.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                RUNNER._reuse_native_proof(link, health)


# run the focused fixture lifecycle regressions
if __name__ == "__main__":
    unittest.main()
