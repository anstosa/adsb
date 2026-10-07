"""Regression tests for automatic release activation and recovery."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
HELPER = ROOT / "deploy/release-transaction.sh"

HOST_ARTIFACTS = (
    "etc/adsb/admin.env",
    "etc/adsb/runtime.json",
    "usr/local/sbin/adsb-stack",
    "etc/sudoers.d/adsb-stack",
    "etc/systemd/system/adsb-admin.service",
    "etc/systemd/system/adsb-controller.service",
    "etc/systemd/system/adsb-alerts.service",
    "etc/systemd/system/adsb-updater.service",
    "etc/systemd/system/adsb-updater.path",
    "etc/systemd/system/adsb-activation-recovery.service",
    "etc/systemd/system/docker.service.d/20-adsb-recovery.conf",
    "etc/systemd/system/adsb-maintenance.service",
    "etc/systemd/system/adsb-maintenance.timer",
    "etc/systemd/system/apt-daily.timer.d/adsb-weekly.conf",
    "etc/systemd/system/apt-daily-upgrade.timer.d/adsb-weekly.conf",
    "etc/apt/apt.conf.d/52unattended-upgrades-adsb",
)


class DurableRecoveryTests(unittest.TestCase):
    # create one complete simulated managed host root
    def _host_root(self, directory: str) -> tuple[Path, Path, Path, Path, Path, Path]:
        root = Path(directory)
        release_id = "20261006T190000Z-42"
        old_release = root / "opt/adsb/releases/old"
        new_release = root / f"opt/adsb/releases/{release_id}"
        old_map = root / "opt/adsb/map-ui-releases/old"
        new_map = root / f"opt/adsb/map-ui-releases/{release_id}"
        rollback = root / f"var/lib/adsb/runtime/activation-{release_id}"
        # create every managed directory with rollback privacy
        for path in (old_release, new_release, old_map, new_map, rollback):
            path.mkdir(parents=True)
        rollback.chmod(0o700)
        # seed exact host integration content
        for index, relative in enumerate(HOST_ARTIFACTS):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"old-{index}", encoding="utf-8")
        (root / "opt/adsb/current").symlink_to(old_release)
        (root / "opt/adsb/map-ui").symlink_to(old_map)
        return root, old_release, new_release, old_map, new_map, rollback

    # recover exact pointers files and unit state from a durable journal
    def test_recovery_replays_bounded_journal_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old_release, new_release, old_map, new_map, rollback = self._host_root(directory)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            systemctl_log = root / "systemctl.log"
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$*" >>"$SYSTEMCTL_LOG"\nexit 0\n',
                encoding="utf-8",
            )
            fake_systemctl.chmod(0o755)
            states = ("true", "true", "true", "true", "false", "false") + ("true", "false") * 5
            script = f"""
set -euo pipefail
source {shlex.quote(str(HELPER))}
backup_activation_files {shlex.quote(str(root))} {shlex.quote(str(rollback))}
write_activation_journal {shlex.quote(str(root))} {shlex.quote(str(rollback))} \\
    {shlex.quote(str(old_release))} {shlex.quote(str(old_map))} false \\
    {shlex.quote(str(new_release))} {shlex.quote(str(new_map))} {"a" * 32} {" ".join(states)}
ln -sfn {shlex.quote(str(new_release))} {shlex.quote(str(root / "opt/adsb/current"))}
ln -sfn {shlex.quote(str(new_map))} {shlex.quote(str(root / "opt/adsb/map-ui"))}
# replace all integration files to model a partial activation
for relative in {" ".join(shlex.quote(item) for item in HOST_ARTIFACTS)}; do
    printf '%s' changed >{shlex.quote(str(root))}/"$relative"
done
recover_activation {shlex.quote(str(root))}
recover_activation {shlex.quote(str(root))}
"""
            environment = os.environ | {
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "SYSTEMCTL_LOG": str(systemctl_log),
            }
            subprocess.run(["bash", "-c", script], check=True, env=environment)
            self.assertEqual(old_release, (root / "opt/adsb/current").resolve())
            self.assertEqual(old_map, (root / "opt/adsb/map-ui").resolve())
            # require exact file restoration
            for index, relative in enumerate(HOST_ARTIFACTS):
                self.assertEqual(f"old-{index}", (root / relative).read_text(encoding="utf-8"))
            self.assertFalse(new_release.exists())
            self.assertFalse(new_map.exists())
            self.assertFalse(rollback.exists())
            self.assertFalse((root / "var/lib/adsb/runtime/activation-journal.json").exists())
            calls = systemctl_log.read_text(encoding="utf-8")
            self.assertIn("enable adsb-updater.path", calls)
            self.assertNotIn("adsb-updater.service", calls)
            self.assertEqual(2, calls.count("daemon-reload"))

    # retain startup guards and their installer across an interrupted recovery
    def test_failed_journal_clear_retains_guards_for_second_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old_release, new_release, old_map, new_map, rollback = self._host_root(directory)
            states = "false false " * 8
            script = f"""
set -euo pipefail
source {shlex.quote(str(HELPER))}
backup_activation_files {shlex.quote(str(root))} {shlex.quote(str(rollback))}
write_activation_journal {shlex.quote(str(root))} {shlex.quote(str(rollback))} \
    {shlex.quote(str(old_release))} {shlex.quote(str(old_map))} false \
    {shlex.quote(str(new_release))} {shlex.quote(str(new_map))} {"a" * 32} {states}
ln -sfn {shlex.quote(str(new_release))} {shlex.quote(str(root / "opt/adsb/current"))}
# model partially activated startup guards
for relative in {" ".join(shlex.quote(item) for item in HOST_ARTIFACTS)}; do
    printf '%s' changed >{shlex.quote(str(root))}/"$relative"
done
systemctl() {{ return 0; }}
# interrupt immediately before durable journal removal
clear_activation_journal() {{ return 1; }}
recover_activation {shlex.quote(str(root))}
"""
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "opt/adsb/current").resolve(), old_release)
            self.assertTrue(new_release.exists())
            self.assertTrue(new_map.exists())
            self.assertTrue((root / "var/lib/adsb/runtime/activation-journal.json").exists())
            # require every guard to survive a second crash
            for relative in HOST_ARTIFACTS:
                if (
                    "systemd/system/adsb-" in relative
                    and "maintenance" not in relative
                    or "docker.service.d" in relative
                ):
                    self.assertEqual((root / relative).read_text(), "changed")
            replay = f"source {shlex.quote(str(HELPER))}; systemctl() {{ return 0; }}; recover_activation {shlex.quote(str(root))}"
            subprocess.run(["bash", "-ec", replay], check=True)
            self.assertFalse(new_release.exists())
            self.assertFalse(rollback.exists())
            # restore exact prior host bytes only after completing recovery
            for index, relative in enumerate(HOST_ARTIFACTS):
                self.assertEqual((root / relative).read_text(), f"old-{index}")

    # reject untrusted recovery paths without changing their target
    def test_recovery_rejects_unmanaged_paths_and_retains_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, new_release, _, new_map, rollback = self._host_root(directory)
            journal = root / "var/lib/adsb/runtime/activation-journal.json"
            units = {
                unit: {"enabled": False, "active": False}
                for unit in (
                    "adsb-admin.service",
                    "adsb-controller.service",
                    "adsb-alerts.service",
                    "adsb-maintenance.timer",
                    "apt-daily.timer",
                    "apt-daily-upgrade.timer",
                    "adsb-updater.path",
                    "adsb-activation-recovery.service",
                )
            }
            document = {
                "schema_version": 1,
                "activation_id": "a" * 32,
                "rollback_dir": str(rollback),
                "current_code": "/tmp/untrusted-release",
                "previous_map": "",
                "legacy_layout": False,
                "app_release": str(new_release),
                "map_release": str(new_map),
                "units": units,
            }
            journal.write_text(json.dumps(document), encoding="utf-8")
            journal.chmod(0o600)
            result = subprocess.run(
                ["bash", "-c", f"source {shlex.quote(str(HELPER))}; recover_activation {shlex.quote(str(root))}"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertTrue(journal.exists())
            self.assertTrue(rollback.exists())
            self.assertTrue(new_release.exists())
            self.assertIn("retaining rollback artifacts", result.stderr)


class UpdaterInstallerContractTests(unittest.TestCase):
    # require failure-propagating gates before the first pointer change
    def test_startup_guards_cover_apps_docker_and_backup(self):
        for name in (
            "adsb-admin.service",
            "adsb-controller.service",
            "adsb-alerts.service",
            "adsb-updater.service",
            "adsb-updater.path",
            "docker-recovery.conf",
        ):
            unit = (ROOT / "deploy" / name).read_text()
            lines = unit.splitlines()
            self.assertTrue(
                any(
                    line.startswith("Requires=") and "adsb-activation-recovery.service" in line.split("=", 1)[1].split()
                    for line in lines
                ),
                name,
            )
            self.assertTrue(
                any(
                    line.startswith("After=") and "adsb-activation-recovery.service" in line.split("=", 1)[1].split()
                    for line in lines
                ),
                name,
            )
        installer = (ROOT / "deploy/install.sh").read_text()
        journal = installer.index('write_activation_journal ""')
        pointer = installer.index('mv -Tf "/opt/adsb/current.$$.next" /opt/adsb/current', journal)
        for source in (
            "ADMIN_UNIT_TEMP",
            "CONTROLLER_UNIT_TEMP",
            "ALERTS_UNIT_TEMP",
            "UPDATER_UNIT_TEMP",
            "UPDATER_PATH_TEMP",
            "DOCKER_GUARD_TEMP",
        ):
            self.assertLess(installer.index(f'mv -f "${source}"', journal), pointer)
        # retain templates for safe installer reconstruction of guarded host files
        for name in (
            "adsb-updater.service",
            "adsb-updater.path",
            "adsb-activation-recovery.service",
            "docker-recovery.conf",
        ):
            self.assertIn(f"$APP_RELEASE/deploy/{name}", installer)
        stream = (ROOT / "deploy/backup/backup-stream.sh").read_text()
        self.assertIn('"$app_path" "$map_path" "${fixed_paths[@]}"', stream)
        # require the complete guarded host bundle in both capture and ownership proof
        proof = (ROOT / "deploy/backup/backup-proof.sh").read_text()
        for name in (
            "adsb-updater.service",
            "adsb-updater.path",
            "adsb-activation-recovery.service",
            "docker.service.d/20-adsb-recovery.conf",
        ):
            self.assertIn(f"etc/systemd/system/{name}", stream)
            self.assertIn(f"require_file /etc/systemd/system/{name} root:root:644", proof)

    # distinguish validated lock contention from invalid lock metadata
    def test_activation_lock_nonblocking_is_safe_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = f"""
set -euo pipefail
source {shlex.quote(str(HELPER))}
prepare_activation_lock {shlex.quote(str(root))} nonblocking
exec 9>&-
exec 8<>{shlex.quote(str(root / "run/lock/adsb/activation.lock"))}
flock -x 8
# only the explicit contention code may skip boot recovery
set +e
prepare_activation_lock {shlex.quote(str(root))} nonblocking
status=$?
[[ $status == 75 ]] || exit 1
exec 8>&-
exec 9>&-
chmod 644 {shlex.quote(str(root / "run/lock/adsb/activation.lock"))}
prepare_activation_lock {shlex.quote(str(root))} nonblocking
status=$?
[[ $status != 0 && $status != 75 ]]
"""
            subprocess.run(["bash", "-c", script], check=True, capture_output=True)

    # keep update mode fixed and separate from first-install bootstrap
    def test_update_mode_uses_fixed_environment_and_global_lock(self):
        installer = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
        self.assertIn("ADMIN_ENV=/etc/adsb/admin.env", installer)
        helper = HELPER.read_text()
        self.assertIn('local lock_path="$root/run/lock/adsb/activation.lock"', helper)
        self.assertIn('"$metadata" != "$expected_uid:$expected_gid:600:1"', helper)
        self.assertNotIn("exec 9>/run/lock", installer)
        self.assertIn("flock -x 9", helper)
        self.assertLess(installer.index("prepare_activation_lock"), installer.index('recover_activation ""'))
        self.assertLess(installer.index('recover_activation ""'), installer.index("apt-get update"))
        self.assertIn("ADSB_UPDATE_BASE_RELEASE", installer)
        self.assertIn('readlink -f /opt/adsb/current) != "$UPDATE_BASE"', installer)
        bootstrap = installer[
            installer.index('if [[ "$INSTALL_MODE" == install ]]') : installer.index("# stage one exact")
        ]
        self.assertIn("apt-get install", bootstrap)
        self.assertIn("useradd --system", bootstrap)
        self.assertNotIn("ADMIN_ENV=$2", installer)

    # require fixed triggers and a fixed root updater command
    def test_updater_units_have_fixed_triggers_and_command(self):
        service = (ROOT / "deploy/adsb-updater.service").read_text(encoding="utf-8")
        path = (ROOT / "deploy/adsb-updater.path").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/bin/python3 -I /opt/adsb/current/adsb_admin/update_worker.py", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("MemoryMax=256M", service)
        self.assertIn("PathChanged=/var/lib/adsb/status/maintenance.json", path)
        self.assertIn("PathExists=/var/lib/adsb/config/update-request.json", path)

    # queue boot-time unit restoration without waiting on Before dependencies
    def test_recovery_unit_uses_nonblocking_activity_restore(self):
        unit = (ROOT / "deploy/adsb-activation-recovery.service").read_text(encoding="utf-8")
        helper = (ROOT / "deploy/release-transaction.sh").read_text(encoding="utf-8")
        installer = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
        self.assertIn("Environment=ADSB_BOOT_RECOVERY=1", unit)
        self.assertIn(
            "Before=docker.service adsb-admin.service adsb-controller.service adsb-alerts.service adsb-updater.path",
            unit,
        )
        self.assertIn("ExecStart=/usr/bin/bash @ADSB_RECOVERY_INSTALLER@ --recover-only", unit)
        self.assertNotIn("/opt/adsb/current/deploy/install.sh", unit)
        self.assertIn("systemctl_options=(--no-block)", helper)
        binding = installer.index('recovery_template.replace("@ADSB_RECOVERY_INSTALLER@", installer)')
        journal = installer.index('write_activation_journal ""', binding)
        recovery_unit = installer.index(
            'mv -f "$RECOVERY_UNIT_TEMP" /etc/systemd/system/adsb-activation-recovery.service',
            journal,
        )
        pointer = installer.index('mv -Tf "/opt/adsb/current.$$.next" /opt/adsb/current', recovery_unit)
        self.assertLess(binding, journal)
        self.assertLess(journal, recovery_unit)
        self.assertLess(recovery_unit, pointer)

    # exercise boot and synchronous activity restoration through fixed systemctl arguments
    def test_boot_recovery_queues_unit_activity_without_updater_service(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log = root / "systemctl.log"
            systemctl = fake_bin / "systemctl"
            systemctl.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$*" >>"$SYSTEMCTL_LOG"\n',
                encoding="utf-8",
            )
            systemctl.chmod(0o755)
            script = f"""
set -euo pipefail
source {shlex.quote(str(HELPER))}
ADSB_BOOT_RECOVERY=1 restore_activation_activity adsb-admin.service true
restore_activation_activity adsb-updater.path true
"""
            environment = os.environ | {
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "SYSTEMCTL_LOG": str(log),
            }
            subprocess.run(["bash", "-c", script], check=True, env=environment)
            self.assertEqual(
                ["--no-block restart adsb-admin.service", "start adsb-updater.path"],
                log.read_text(encoding="utf-8").splitlines(),
            )
            self.assertNotIn("adsb-updater.service", log.read_text(encoding="utf-8"))


# run focused tests directly or through discovery
if __name__ == "__main__":
    unittest.main()
