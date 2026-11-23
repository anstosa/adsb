"""Tests for the receiver-side backup compatibility attestation."""

import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from adsb_admin.config import MAPFLIGHTS_BACKUP_ATTESTATION_CONTENT, mapflights_ready


# test fail-closed recognition without writing under etc
class MapFlightsAttestationTests(unittest.TestCase):
    # accept only the exact owned regular file and bounded contents
    def test_requires_exact_attestation(self):
        marker = MAPFLIGHTS_BACKUP_ATTESTATION_CONTENT
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ready"
            self.assertFalse(mapflights_ready(path))
            path.write_bytes(marker)
            link = path.with_suffix(".link")
            link.symlink_to(path)
            self.assertFalse(mapflights_ready(link))
            valid = {"st_mode": stat.S_IFREG | 0o644, "st_uid": 0, "st_gid": 0, "st_size": len(marker)}
            # check owner, mode and length independently
            for override in ({}, {"st_uid": 1}, {"st_gid": 1}, {"st_mode": stat.S_IFREG | 0o664}, {"st_size": 4096}):
                with (
                    self.subTest(override=override),
                    mock.patch("adsb_admin.config.os.fstat", return_value=SimpleNamespace(**(valid | override))),
                ):
                    self.assertEqual(mapflights_ready(path), not override)
            path.write_bytes(b"x" * len(marker))
            with mock.patch("adsb_admin.config.os.fstat", return_value=SimpleNamespace(**valid)):
                self.assertFalse(mapflights_ready(path))
