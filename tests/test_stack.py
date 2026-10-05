"""Focused tests for the fixed production stack control boundary."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from adsb_admin import stack


# build a concise mocked process result
def process(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


# exercise the isolated command and state helpers
class StackControlTests(unittest.TestCase):
    # pass only a fixed root environment and working directory to subprocesses
    def test_run_command_clears_inherited_environment(self):
        with mock.patch("adsb_admin.stack.subprocess.run", return_value=process()) as run:
            stack.run_command([stack.SYSTEMCTL, "is-active", "adsb-admin.service"], timeout=10)
        _, kwargs = run.call_args
        self.assertEqual("/", kwargs["cwd"])
        self.assertEqual("unix:///var/run/docker.sock", kwargs["env"]["DOCKER_HOST"])
        self.assertNotIn("PYTHONPATH", kwargs["env"])

    # reject arbitrary verbs before any privileged operation
    def test_main_rejects_extra_and_unknown_arguments(self):
        error = io.StringIO()
        with mock.patch("adsb_admin.stack.collect_status") as status:
            with contextlib.redirect_stderr(error):
                unknown = stack.main(["adsb-stack", "shell"])
                extra = stack.main(["adsb-stack", "status", "extra"])
        self.assertEqual(64, unknown)
        self.assertEqual(64, extra)
        status.assert_not_called()
        self.assertIn("expected exactly one", error.getvalue())

    # refuse valid operations from a direct nonroot interpreter invocation
    def test_main_refuses_nonroot_before_status_commands(self):
        error = io.StringIO()
        with mock.patch("adsb_admin.stack.os.geteuid", return_value=1000):
            with mock.patch("adsb_admin.stack.collect_status") as status:
                with contextlib.redirect_stderr(error):
                    result = stack.main(["adsb-stack", "status"])
        self.assertEqual(77, result)
        status.assert_not_called()
        self.assertIn("root execution required", error.getvalue())

    # provide RemoteAgents the documented running or stopped exit signal
    def test_main_status_exit_code_tracks_readiness(self):
        output = io.StringIO()
        with mock.patch("adsb_admin.stack.os.geteuid", return_value=0):
            with mock.patch("adsb_admin.stack.collect_status", return_value={"state": "running", "checks": {}}):
                with contextlib.redirect_stdout(output):
                    running = stack.main(["adsb-stack", "status"])
            with mock.patch("adsb_admin.stack.collect_status", return_value={"state": "stopped", "checks": {}}):
                with contextlib.redirect_stdout(io.StringIO()):
                    stopped = stack.main(["adsb-stack", "status"])
        self.assertEqual(0, running)
        self.assertEqual(1, stopped)
        self.assertEqual({"checks": {}, "state": "running"}, json.loads(output.getvalue()))

    # scope every Docker query to the fixed compose project and file
    def test_compose_query_is_fixed_and_reports_health(self):
        rows = [
            {"Service": "ultrafeeder", "State": "running", "Health": "healthy"},
            {"Service": "proxy", "State": "running", "Health": ""},
            {"Service": "unrelated", "State": "running", "Health": "healthy"},
        ]
        with mock.patch("adsb_admin.stack.run_command", return_value=process(stdout=json.dumps(rows))) as run:
            services, queried = stack.compose_services()
        self.assertTrue(queried)
        self.assertEqual({"ultrafeeder": True, "proxy": True, "other": True}, services)
        self.assertEqual(
            [
                stack.DOCKER,
                "compose",
                "-p",
                "adsb",
                "-f",
                stack.COMPOSE_PATH,
                "ps",
                "--all",
                "--format",
                "json",
            ],
            run.call_args.args[0],
        )

    # consider the normal awaiting-radios controller phase healthy
    def test_status_reports_running_while_awaiting_radios(self):
        with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
            with mock.patch(
                "adsb_admin.stack.compose_services",
                return_value=({"ultrafeeder": True, "proxy": True}, True),
            ):
                with mock.patch("adsb_admin.stack.declared_services", return_value=({"ultrafeeder", "proxy"}, True)):
                    with mock.patch("adsb_admin.stack.tunnel_enabled", return_value=False):
                        with mock.patch("adsb_admin.stack.http_healthy", return_value=True):
                            with mock.patch("adsb_admin.stack.controller_phase", return_value="waiting"):
                                result = stack.collect_status()
        self.assertEqual("running", result["state"])
        self.assertEqual("waiting", result["checks"]["controller_status"])
        self.assertEqual("disabled", result["checks"]["tunnel"])

    # keep auxiliary notifier degradation out of the routine core status signal
    def test_alert_source_failure_does_not_change_core_status_exit(self):
        observed = {
            "ultrafeeder": True,
            "proxy": True,
            "airspy": True,
            "alert-source-1090": False,
        }
        declared = {"ultrafeeder", "proxy", "airspy", "alert-source-1090"}
        with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
            with mock.patch("adsb_admin.stack.compose_services", return_value=(observed, True)):
                with mock.patch("adsb_admin.stack.declared_services", return_value=(declared, True)):
                    with mock.patch("adsb_admin.stack.tunnel_enabled", return_value=False):
                        with mock.patch("adsb_admin.stack.http_healthy", return_value=True):
                            with mock.patch("adsb_admin.stack.controller_phase", return_value="ready"):
                                with mock.patch(
                                    "adsb_admin.stack.alert_infrastructure",
                                    return_value={"infrastructure_ready": False},
                                ):
                                    result = stack.collect_status()
        self.assertEqual("running", result["state"])
        self.assertFalse(result["alerts"]["infrastructure_ready"])

    # nested auxiliary json must not crash the core-only routine status signal
    def test_nested_worker_status_is_degraded_with_core_exit_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root / "status.json"
            worker = root / "worker-status.json"
            status.write_text(json.dumps({"phase": "ready"}))
            worker.write_text("[" * 1500 + "0" + "]" * 1500)
            output = io.StringIO()
            with contextlib.ExitStack() as patches:
                patches.enter_context(mock.patch("adsb_admin.stack.STATUS_PATH", str(status)))
                patches.enter_context(mock.patch("adsb_admin.stack.WORKER_STATUS_PATH", str(worker)))
                patches.enter_context(mock.patch("adsb_admin.stack.os.geteuid", return_value=0))
                patches.enter_context(mock.patch("adsb_admin.stack.unit_state", return_value="active"))
                patches.enter_context(
                    mock.patch(
                        "adsb_admin.stack.compose_services", return_value=({"ultrafeeder": True, "proxy": True}, True)
                    )
                )
                patches.enter_context(
                    mock.patch("adsb_admin.stack.declared_services", return_value=({"ultrafeeder", "proxy"}, True))
                )
                patches.enter_context(mock.patch("adsb_admin.stack.tunnel_enabled", return_value=False))
                patches.enter_context(mock.patch("adsb_admin.stack.http_healthy", return_value=True))
                patches.enter_context(mock.patch("adsb_admin.stack.controller_phase", return_value="ready"))
                patches.enter_context(contextlib.redirect_stdout(output))
                code = stack.main(["adsb-stack", "status"])
        result = json.loads(output.getvalue())
        self.assertEqual(0, code)
        self.assertEqual("running", result["state"])
        self.assertFalse(result["alerts"]["infrastructure_ready"])

    # require the optional connector container and local readiness endpoint
    def test_enabled_tunnel_must_be_running_and_ready(self):
        calls = []

        # fail only the fixed Cloudflare readiness endpoint
        def endpoint(url, **_options):
            calls.append(url)
            return not url.endswith(":20242/ready")

        with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
            with mock.patch(
                "adsb_admin.stack.compose_services",
                return_value=({"ultrafeeder": True, "proxy": True, "cloudflared": True}, True),
            ):
                with mock.patch(
                    "adsb_admin.stack.declared_services",
                    return_value=({"ultrafeeder", "proxy", "cloudflared"}, True),
                ):
                    with mock.patch("adsb_admin.stack.tunnel_enabled", return_value=True):
                        with mock.patch("adsb_admin.stack.http_healthy", side_effect=endpoint):
                            with mock.patch("adsb_admin.stack.controller_phase", return_value="ready"):
                                result = stack.collect_status()
        self.assertEqual("stopped", result["state"])
        self.assertEqual("unhealthy", result["checks"]["tunnel"])
        self.assertIn("http://127.0.0.1:20242/ready", calls)

    # require a declared FlightAware container to be healthy
    def test_unhealthy_declared_piaware_stops_readiness(self):
        observed = {"ultrafeeder": True, "proxy": True, "piaware": False}
        declared = {"ultrafeeder", "proxy", "piaware"}
        with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
            with mock.patch("adsb_admin.stack.compose_services", return_value=(observed, True)):
                with mock.patch("adsb_admin.stack.declared_services", return_value=(declared, True)):
                    with mock.patch("adsb_admin.stack.tunnel_enabled", return_value=False):
                        with mock.patch("adsb_admin.stack.http_healthy", return_value=True):
                            with mock.patch("adsb_admin.stack.controller_phase", return_value="ready"):
                                result = stack.collect_status()
        self.assertEqual("stopped", result["state"])
        self.assertEqual("unhealthy", result["checks"]["containers"])

    # keep duplicate service observations unhealthy when any replica is unhealthy
    def test_unhealthy_duplicate_service_cannot_be_overwritten(self):
        rows = [
            {"Service": "dump978", "State": "exited", "Health": "unhealthy"},
            {"Service": "dump978", "State": "running", "Health": "healthy"},
        ]
        with mock.patch("adsb_admin.stack.run_command", return_value=process(stdout=json.dumps(rows))):
            services, queried = stack.compose_services()
        self.assertTrue(queried)
        self.assertFalse(services["dump978"])

    # require every declared receiver container to be present
    def test_missing_declared_airspy_stops_readiness(self):
        observed = {"ultrafeeder": True, "proxy": True}
        declared = {"ultrafeeder", "proxy", "airspy"}
        with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
            with mock.patch("adsb_admin.stack.compose_services", return_value=(observed, True)):
                with mock.patch("adsb_admin.stack.declared_services", return_value=(declared, True)):
                    with mock.patch("adsb_admin.stack.tunnel_enabled", return_value=False):
                        with mock.patch("adsb_admin.stack.http_healthy", return_value=True):
                            with mock.patch("adsb_admin.stack.controller_phase", return_value="ready"):
                                result = stack.collect_status()
        self.assertEqual("stopped", result["state"])
        self.assertEqual("unhealthy", result["checks"]["containers"])

    # reject unexpected project containers even when required services are healthy
    def test_unexpected_project_container_stops_readiness(self):
        observed = {"ultrafeeder": True, "proxy": True, "other": True}
        declared = {"ultrafeeder", "proxy"}
        with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
            with mock.patch("adsb_admin.stack.compose_services", return_value=(observed, True)):
                with mock.patch("adsb_admin.stack.declared_services", return_value=(declared, True)):
                    with mock.patch("adsb_admin.stack.tunnel_enabled", return_value=False):
                        with mock.patch("adsb_admin.stack.http_healthy", return_value=True):
                            with mock.patch("adsb_admin.stack.controller_phase", return_value="ready"):
                                result = stack.collect_status()
        self.assertEqual("stopped", result["state"])
        self.assertEqual("unhealthy", result["checks"]["containers"])

    # reject stale controller observations at the thirty-second boundary
    def test_stale_controller_status_is_unhealthy(self):
        now = datetime(2026, 9, 5, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_text(
                json.dumps(
                    {
                        "activation_id": "a" * 32,
                        "phase": "waiting",
                        "updated_at": (now - timedelta(seconds=31)).isoformat(),
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(stack, "STATUS_PATH", path):
                self.assertEqual("unhealthy", stack.controller_phase(now=now, expected_activation="a" * 32))

    # reject fresh controller error phases without returning their message
    def test_error_controller_status_is_unhealthy(self):
        now = datetime(2026, 9, 5, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_text(
                json.dumps(
                    {
                        "activation_id": "a" * 32,
                        "phase": "error",
                        "updated_at": now.isoformat(),
                        "message": "private detail",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(stack, "STATUS_PATH", path):
                self.assertEqual("unhealthy", stack.controller_phase(now=now, expected_activation="a" * 32))

    # reject timestamps without an explicit timezone
    def test_naive_controller_timestamp_is_unhealthy(self):
        now = datetime(2026, 9, 5, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_text(
                json.dumps({"activation_id": "a" * 32, "phase": "waiting", "updated_at": "2026-09-05T00:00:00"}),
                encoding="utf-8",
            )
            with mock.patch.object(stack, "STATUS_PATH", path):
                self.assertEqual("unhealthy", stack.controller_phase(now=now, expected_activation="a" * 32))

    # reject a fresh status inherited from the previous selected release
    def test_controller_status_requires_current_activation_identity(self):
        now = datetime(2026, 9, 5, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_text(
                json.dumps({"activation_id": "a" * 32, "phase": "ready", "updated_at": now.isoformat()}),
                encoding="utf-8",
            )
            with mock.patch.object(stack, "STATUS_PATH", path):
                self.assertEqual("unhealthy", stack.controller_phase(now=now, expected_activation="b" * 32))

    # require fresh matching worker and source generations for activation readiness
    def test_alert_infrastructure_requires_current_worker_and_sources(self):
        now = datetime(2026, 9, 5, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status_path = root / "status.json"
            worker_path = root / "worker-status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "activation_id": "a" * 32,
                        "alerts": {
                            "activation_id": "a" * 32,
                            "source_contract_digest": "b" * 64,
                            "expected_bands": ["1090"],
                            "sources": {
                                "1090": {
                                    "mode": "readsb",
                                    "service": "alert-source-1090",
                                    "state": "ready",
                                    "generation": "2de11047-d307-4cce-a43c-4b02958e77c4",
                                    "sampled_at": now.isoformat(),
                                    "process_running": True,
                                    "input_connected": True,
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            worker_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "activation_id": "a" * 32,
                        "source_contract_digest": "b" * 64,
                        "sampled_at": now.timestamp(),
                        "process_running": True,
                        "bands": {
                            "1090": {
                                "state": "healthy",
                                "generation": "2de11047-d307-4cce-a43c-4b02958e77c4",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(stack, "STATUS_PATH", status_path):
                with mock.patch.object(stack, "WORKER_STATUS_PATH", worker_path):
                    with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
                        result = stack.alert_infrastructure(now=now)
        self.assertTrue(result["infrastructure_ready"])
        self.assertEqual("healthy", result["sources"])

    # reject worker-unknown and mismatched generations without changing core readiness
    def test_worker_must_consume_the_current_source_generation(self):
        now = datetime(2026, 9, 5, tzinfo=timezone.utc)
        generation = "2de11047-d307-4cce-a43c-4b02958e77c4"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status_path = root / "status.json"
            worker_path = root / "worker-status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "activation_id": "a" * 32,
                        "alerts": {
                            "activation_id": "a" * 32,
                            "source_contract_digest": "b" * 64,
                            "expected_bands": ["1090"],
                            "sources": {
                                "1090": {
                                    "mode": "readsb",
                                    "service": "alert-source-1090",
                                    "state": "ready",
                                    "generation": generation,
                                    "sampled_at": now.isoformat(),
                                    "process_running": True,
                                    "input_connected": True,
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            worker = {
                "schema_version": 1,
                "activation_id": "a" * 32,
                "source_contract_digest": "b" * 64,
                "sampled_at": now.timestamp(),
                "process_running": True,
                "bands": {"1090": {"state": "unknown", "generation": generation}},
            }
            with mock.patch.object(stack, "STATUS_PATH", status_path):
                with mock.patch.object(stack, "WORKER_STATUS_PATH", worker_path):
                    with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
                        # reject a heartbeat that has not consumed a healthy source
                        worker_path.write_text(json.dumps(worker), encoding="utf-8")
                        unknown = stack.alert_infrastructure(now=now)
                        # reject a healthy claim for a prior source generation
                        worker["bands"]["1090"] = {"state": "healthy", "generation": "stale-generation"}
                        worker_path.write_text(json.dumps(worker), encoding="utf-8")
                        mismatch = stack.alert_infrastructure(now=now)
        self.assertFalse(unknown["infrastructure_ready"])
        self.assertFalse(mismatch["infrastructure_ready"])
        # routine status remains independently governed by the core predicate
        with mock.patch("adsb_admin.stack.unit_state", return_value="active"):
            with mock.patch(
                "adsb_admin.stack.compose_services",
                return_value=({"ultrafeeder": True, "proxy": True, "alert-source-1090": True}, True),
            ):
                with mock.patch(
                    "adsb_admin.stack.declared_services",
                    return_value=({"ultrafeeder", "proxy", "alert-source-1090"}, True),
                ):
                    with mock.patch("adsb_admin.stack.tunnel_enabled", return_value=False):
                        with mock.patch("adsb_admin.stack.http_healthy", return_value=True):
                            with mock.patch("adsb_admin.stack.controller_phase", return_value="ready"):
                                with mock.patch("adsb_admin.stack.alert_infrastructure", return_value=mismatch):
                                    core = stack.collect_status()
        self.assertEqual("running", core["state"])

    # attempt both unit stops and scoped Compose teardown after a failure
    def test_failed_shutdown_attempts_all_steps_and_returns_failure(self):
        results = [
            process(returncode=1),
            process(),
            process(),
            process(),
            process(returncode=3, stdout="inactive\n"),
            process(returncode=3, stdout="inactive\n"),
            process(returncode=3, stdout="inactive\n"),
            process(stdout=""),
        ]
        with mock.patch("adsb_admin.stack.run_command", side_effect=results) as run:
            result = stack.stop_stack()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([stack.SYSTEMCTL, "stop", "adsb-alerts.service"], commands[0])
        self.assertEqual([stack.SYSTEMCTL, "stop", "adsb-controller.service"], commands[1])
        self.assertEqual([stack.SYSTEMCTL, "stop", "adsb-admin.service"], commands[2])
        self.assertEqual(
            [
                stack.DOCKER,
                "compose",
                "-p",
                "adsb",
                "-f",
                stack.COMPOSE_PATH,
                "down",
                "--remove-orphans",
                "--timeout",
                "10",
            ],
            commands[3],
        )
        self.assertEqual("failed", result["result"])

    # confirm a successful stop only after units and containers are observed stopped
    def test_stop_reports_success_after_fixed_project_is_empty(self):
        results = [
            process(),
            process(),
            process(),
            process(),
            process(returncode=3, stdout="inactive\n"),
            process(returncode=3, stdout="inactive\n"),
            process(returncode=3, stdout="inactive\n"),
            process(stdout=""),
        ]
        with mock.patch("adsb_admin.stack.run_command", side_effect=results):
            result = stack.stop_stack()
        self.assertEqual("ok", result["result"])
        self.assertEqual("stopped", result["state"])

    # refuse successful shutdown when systemd state cannot be confirmed
    def test_stop_rejects_unknown_unit_state(self):
        results = [
            process(),
            process(),
            process(),
            process(),
            None,
            process(returncode=3, stdout="inactive\n"),
            process(returncode=3, stdout="inactive\n"),
            process(stdout=""),
        ]
        with mock.patch("adsb_admin.stack.run_command", side_effect=results):
            result = stack.stop_stack()
        self.assertEqual("failed", result["result"])

    # bound start polling and fail rather than claiming partial readiness
    def test_start_times_out_after_bounded_polling(self):
        stopped = {"state": "stopped", "checks": {}}
        with mock.patch("adsb_admin.stack.run_command", return_value=process()):
            with mock.patch("adsb_admin.stack.collect_status", side_effect=[stopped, stopped]) as status:
                with mock.patch("adsb_admin.stack.time.monotonic", side_effect=[0, 0, 1]):
                    with mock.patch("adsb_admin.stack.time.sleep") as sleep:
                        result = stack.start_stack(timeout=1)
        self.assertEqual("failed", result["result"])
        self.assertEqual("readiness timed out", result["reason"])
        self.assertEqual(2, status.call_count)
        sleep.assert_called_once_with(1)

    # require notifier infrastructure during start without changing routine status semantics
    def test_start_waits_for_alert_infrastructure(self):
        core_only = {"state": "running", "checks": {}, "alerts": {"infrastructure_ready": False}}
        complete = {"state": "running", "checks": {}, "alerts": {"infrastructure_ready": True}}
        with mock.patch("adsb_admin.stack.run_command", return_value=process()) as run:
            with mock.patch("adsb_admin.stack.collect_status", side_effect=[core_only, complete]):
                with mock.patch("adsb_admin.stack.time.monotonic", side_effect=[0, 0, 1]):
                    with mock.patch("adsb_admin.stack.time.sleep"):
                        result = stack.start_stack(timeout=2)
        self.assertEqual("ok", result["result"])
        self.assertIn("adsb-alerts.service", run.call_args.args[0])

    # skip subprocesses and sockets after the outer readiness deadline
    def test_expired_readiness_deadline_skips_blocking_operations(self):
        with mock.patch("adsb_admin.stack.time.monotonic", return_value=11):
            with mock.patch("adsb_admin.stack.run_command") as run:
                self.assertEqual("unknown", stack.unit_state("adsb-admin.service", deadline=10))
                self.assertEqual(({}, False), stack.compose_services(deadline=10))
                self.assertFalse(stack.http_healthy("http://127.0.0.1:8080/healthz", deadline=10))
        run.assert_not_called()

    # keep restart stopped when orderly shutdown cannot be confirmed
    def test_restart_does_not_start_after_failed_stop(self):
        failure = {"action": "restart", "result": "failed", "state": "stopped", "checks": {}}
        with mock.patch("adsb_admin.stack.stop_stack", return_value=failure):
            with mock.patch("adsb_admin.stack.start_stack") as start:
                result = stack.restart_stack()
        self.assertEqual(failure, result)
        start.assert_not_called()


# run the focused suite directly or through unittest discovery
if __name__ == "__main__":
    unittest.main()
