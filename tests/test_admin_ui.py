"""Opt-in rendered browser regressions for the administration page."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLAYWRIGHT_MODULE = os.environ.get("ADSB_PLAYWRIGHT_MODULE")


# run the executable browser suite only with an explicit playwright path
@unittest.skipUnless(PLAYWRIGHT_MODULE, "set ADSB_PLAYWRIGHT_MODULE to run browser regressions")
class AdminUiBrowserRegressionTest(unittest.TestCase):
    # execute the same script developers can invoke directly
    def test_admin_ui_regressions(self) -> None:
        environment = os.environ.copy()
        result = subprocess.run(
            ["node", "tests/admin-ui-regressions.mjs"],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            0,
            result.returncode,
            msg=f"browser regressions failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
