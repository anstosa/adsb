"""Regression checks for release installation transactions."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from shlex import quote


# exercise the rollback helper without host or service changes
class ReleaseTransactionTests(unittest.TestCase):
    # require controller convergence and optional-service health before activation
    def test_activation_uses_full_stack_readiness(self):
        installer = (Path(__file__).parents[1] / "deploy/install.sh").read_text(encoding="utf-8")
        readiness = installer.rindex("/usr/local/sbin/adsb-stack status")
        accepted = installer.index("ACTIVATION_COMPLETE=true", readiness)
        self.assertLess(readiness, accepted)
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
            script = f"""
set -euo pipefail
source {quote(str(helper))}
backup_activation_files {quote(str(root))} {quote(str(rollback))}
ln -sfn {quote(str(new_release))} {quote(str(current))}
ln -sfn {quote(str(new_map))} {quote(str(selected_map))}
# overwrite every live host artifact to simulate partial activation
for file in {quote(str(root))}/etc/adsb/admin.env {quote(str(root))}/etc/adsb/runtime.json \
    {quote(str(root))}/usr/local/sbin/adsb-stack {quote(str(root))}/etc/sudoers.d/adsb-stack \
    {quote(str(root))}/etc/systemd/system/adsb-admin.service {quote(str(root))}/etc/systemd/system/adsb-controller.service; do
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


# run the focused regression suite directly or through unittest discovery
if __name__ == "__main__":
    unittest.main()
