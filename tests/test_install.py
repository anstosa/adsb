"""Regression checks for release installation transactions."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from shlex import quote


# exercise the rollback helper without host or service changes
class ReleaseTransactionTests(unittest.TestCase):
    # confine the notifier to read-only inputs and its private state directory
    def test_alert_unit_has_fixed_unprivileged_sandbox(self):
        unit = (Path(__file__).parents[1] / "deploy/adsb-alerts.service").read_text(encoding="utf-8")
        self.assertIn("User=adsb", unit)
        self.assertIn("Group=adsb", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("PrivateDevices=true", unit)
        self.assertIn("ReadWritePaths=/var/lib/adsb/alerts", unit)
        self.assertNotIn("docker.sock", unit)
        self.assertNotIn("EnvironmentFile", unit)
        self.assertIn("MemoryMax=96M", unit)

    # require controller convergence and optional-service health before activation
    def test_activation_uses_full_stack_readiness(self):
        installer = (Path(__file__).parents[1] / "deploy/install.sh").read_text(encoding="utf-8")
        readiness = installer.rindex("/usr/local/sbin/adsb-stack status")
        accepted = installer.index("ACTIVATION_COMPLETE=true", readiness)
        self.assertLess(readiness, accepted)
        self.assertLess(installer.index('systemctl restart "${TIMER_UNITS[@]}"', readiness), accepted)
        self.assertNotIn("systemctl is-active --quiet adsb-admin adsb-controller", installer)

    # restore every pointer and host file after an injected activation failure
    def test_post_staging_failure_restores_previous_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_release = root / "opt/adsb/releases/old"
            new_release = root / "opt/adsb/releases/new"
            old_map = root / "opt/adsb/map-ui-releases/old"
            new_map = root / "opt/adsb/map-ui-releases/new"
            rollback = root / "var/lib/adsb/runtime/rollback"
            destinations = (
                root / "etc/adsb/admin.env",
                root / "etc/adsb/runtime.json",
                root / "usr/local/sbin/adsb-stack",
                root / "etc/sudoers.d/adsb-stack",
                root / "etc/systemd/system/adsb-admin.service",
                root / "etc/systemd/system/adsb-controller.service",
                root / "etc/systemd/system/adsb-alerts.service",
                root / "etc/systemd/system/adsb-maintenance.service",
                root / "etc/systemd/system/adsb-maintenance.timer",
                root / "etc/systemd/system/apt-daily.timer.d/adsb-weekly.conf",
                root / "etc/systemd/system/apt-daily-upgrade.timer.d/adsb-weekly.conf",
                root / "etc/apt/apt.conf.d/52unattended-upgrades-adsb",
            )
            # create the pre-activation host state
            for path in (old_release, new_release, old_map, new_map, rollback):
                path.mkdir(parents=True)
            # create every host destination parent
            for path in destinations:
                path.parent.mkdir(parents=True, exist_ok=True)
            current = root / "opt/adsb/current"
            selected_map = root / "opt/adsb/map-ui"
            current.symlink_to(old_release)
            selected_map.symlink_to(old_map)
            # retain unique content for every restored file
            for index, path in enumerate(destinations):
                path.write_text(f"old-{index}", encoding="utf-8")
            helper = Path(__file__).parents[1] / "deploy/release-transaction.sh"
            # overwrite every snapshotted integration file in the injected failure
            overwrite_paths = " ".join(quote(str(path)) for path in destinations)
            script = f"""
set -euo pipefail
source {quote(str(helper))}
backup_activation_files {quote(str(root))} {quote(str(rollback))}
ln -sfn {quote(str(new_release))} {quote(str(current))}
ln -sfn {quote(str(new_map))} {quote(str(selected_map))}
# overwrite every live host artifact to simulate partial activation
for file in {overwrite_paths}; do
    printf '%s' changed >"$file"
done
rollback_activation {quote(str(root))} {quote(str(rollback))} {quote(str(old_release))} {quote(str(old_map))} false \
    {quote(str(new_release))} {quote(str(new_map))}
"""
            subprocess.run(["bash", "-c", script], check=True)
            self.assertEqual(current.resolve(), old_release)
            self.assertEqual(selected_map.resolve(), old_map)
            # verify every host artifact returned to its prior content
            for index, path in enumerate(destinations):
                self.assertEqual(path.read_text(encoding="utf-8"), f"old-{index}")
            self.assertFalse(new_release.exists())
            self.assertFalse(new_map.exists())

    # stage notifier readiness and stop the old worker before pointer activation
    def test_installer_activates_alert_worker_transactionally(self):
        installer = (Path(__file__).parents[1] / "deploy/install.sh").read_text(encoding="utf-8")
        settings = installer.index("AlertSettingsStore(path)")
        stop_worker = installer.index("systemctl stop adsb-alerts", installer.index("ACTIVATION_STARTED=true"))
        pointer = installer.index('mv -Tf "/opt/adsb/current.$$.next" /opt/adsb/current')
        start_worker = installer.index("systemctl restart adsb-alerts", pointer)
        readiness = installer.index('value.get("alerts", {}).get("infrastructure_ready") is True', start_worker)
        accepted = installer.index("ACTIVATION_COMPLETE=true", readiness)
        self.assertLess(stop_worker, pointer)
        self.assertLess(settings, pointer)
        self.assertLess(pointer, start_worker)
        self.assertLess(start_worker, readiness)
        self.assertLess(readiness, accepted)
        rollback = installer.index("rollback_activation", installer.index("cleanup_install()"))
        remove_sources = installer.index("remove_alert_source_containers", installer.index("cleanup_install()"))
        self.assertLess(remove_sources, rollback)

    # allow an absent first worker but preserve fatal shutdown errors on upgrades
    def test_first_worker_absence_does_not_abort_activation(self):
        installer = (Path(__file__).parents[1] / "deploy/install.sh").read_text(encoding="utf-8")
        start = installer.index("worker_load_state=$(systemctl show adsb-alerts.service")
        end = installer.index('ln -s "$APP_RELEASE"', start)
        block = installer[start:end]
        # execute the actual activation block against bounded systemd shims
        for state, stop_result, expected in (("not-found", 5, 0), ("loaded", 0, 0), ("loaded", 1, 1)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                script = f"""
set -euo pipefail
# emulate only the fixed worker operations
systemctl() {{
    # publish the selected unit presence
    if [[ $1 == show ]]; then
        printf '%s\n' {quote(state)}
        return 0
    fi
    printf '%s' stopped >{quote(str(root / "stopped"))}
    # preserve actionable shutdown diagnostics
    if [[ {stop_result} != 0 ]]; then
        printf '%s' 'worker stop failed' >&2
    fi
    return {stop_result}
}}
{block}
printf '%s' continued >{quote(str(root / "continued"))}
"""
                result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
                self.assertEqual(expected, result.returncode)
                self.assertEqual(state != "not-found", (root / "stopped").exists())
                self.assertEqual(expected == 0, (root / "continued").exists())
                self.assertEqual("worker stop failed" if expected else "", result.stderr)

    # remove newly introduced maintenance files after failed first activation
    def test_rollback_preserves_absent_maintenance_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rollback = root / "rollback"
            rollback.mkdir()
            unit = root / "etc/systemd/system/adsb-maintenance.timer"
            unit.parent.mkdir(parents=True)
            (root / "opt/adsb").mkdir(parents=True)
            helper = Path(__file__).parents[1] / "deploy/release-transaction.sh"
            script = f"""
set -euo pipefail
source {quote(str(helper))}
backup_activation_files {quote(str(root))} {quote(str(rollback))}
printf '%s' new >{quote(str(unit))}
rollback_activation {quote(str(root))} {quote(str(rollback))} '' '' false \
    {quote(str(root / "opt/adsb/new"))} {quote(str(root / "opt/adsb/new-map"))}
"""
            subprocess.run(["bash", "-c", script], check=True)
            self.assertFalse(unit.exists())

    # remove a newly introduced notifier unit after a failed first activation
    def test_rollback_preserves_absent_alert_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rollback = root / "rollback"
            rollback.mkdir()
            unit = root / "etc/systemd/system/adsb-alerts.service"
            unit.parent.mkdir(parents=True)
            (root / "opt/adsb").mkdir(parents=True)
            helper = Path(__file__).parents[1] / "deploy/release-transaction.sh"
            script = f"""
set -euo pipefail
source {quote(str(helper))}
backup_activation_files {quote(str(root))} {quote(str(rollback))}
printf '%s' new >{quote(str(unit))}
rollback_activation {quote(str(root))} {quote(str(rollback))} '' '' false \
    {quote(str(root / "opt/adsb/new"))} {quote(str(root / "opt/adsb/new-map"))}
"""
            subprocess.run(["bash", "-c", script], check=True)
            self.assertFalse(unit.exists())


# run the focused regression suite directly or through unittest discovery
if __name__ == "__main__":
    unittest.main()
