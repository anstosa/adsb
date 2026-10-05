import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "deploy/alerts/source-health.sh"
GENERATION = "12345678-1234-4234-9234-123456789abc"
ACTIVATION = "a" * 32
DIGEST = "b" * 64


class SourceHealthTest(unittest.TestCase):
    # create one isolated publication, proc and socket fixture
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.proc = self.root / "proc"
        self.output.mkdir()
        (self.proc / "123").mkdir(parents=True)
        (self.proc / "123/comm").write_text("readsb\n", encoding="ascii")
        self.ss = self.root / "ss"
        self._write_ss(self._socket_output(bytes_received=42))
        self._write_publications()
        self._write_marker()
        content = SCRIPT_PATH.read_text(encoding="utf-8")
        self.python = content.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]

    # release the isolated fixture
    def tearDown(self):
        self.temporary.cleanup()

    # render one pid-owned established socket fixture
    def _socket_output(self, *, bytes_received=None, inode="9876", duplicate=False, port="30005"):
        counter = "" if bytes_received is None else f" bytes_received:{bytes_received}"
        row = (
            f"0 0 172.18.0.2:40000 172.18.0.3:{port} "
            'users:(("readsb",pid=123,fd=8)) '
            f"ino:{inode}\n"
            f" cubic rto:204{counter}\n"
        )
        # duplicate only when testing ambiguous physical inputs
        if duplicate:
            row += row.replace(f"ino:{inode}", "ino:9999")
        return row

    # install a deterministic executable ss fixture
    def _write_ss(self, output, *, exit_code=0):
        self.ss.write_text(
            "#!/bin/sh\ncat <<'EOF'\n" + output + "EOF\n" + f"exit {exit_code}\n",
            encoding="utf-8",
        )
        self.ss.chmod(0o755)

    # publish fresh decoder files without aircraft identifiers
    def _write_publications(self):
        (self.output / "aircraft.json").write_text('{"aircraft":[],"messages":0}\n', encoding="utf-8")
        (self.output / "stats.json").write_text("{}\n", encoding="utf-8")

    # publish one exact immutable marker
    def _write_marker(self, **changes):
        value = {
            "schema_version": 1,
            "band": "1090",
            "generation": GENERATION,
            "started_at": "2026-10-05T19:03:13Z",
            "activation_id": ACTIVATION,
            "contract_digest": DIGEST,
        }
        value.update(changes)
        (self.output / "source-marker.json").write_text(json.dumps(value), encoding="utf-8")

    # execute only the embedded probe against isolated paths
    def _run(self, *, band="1090", port="30005", activation=ACTIVATION, digest=DIGEST):
        return subprocess.run(
            [
                sys.executable,
                "-c",
                self.python,
                str(self.output),
                str(self.proc),
                str(self.ss),
                band,
                port,
                activation,
                digest,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    # load the bounded state publication
    def _state(self):
        return json.loads((self.output / "source-state.json").read_text(encoding="utf-8"))

    # prove healthy and quiet sockets publish exact private schema
    def test_healthy_and_quiet_socket_publications(self):
        started = time.time()
        result = self._run()
        self.assertEqual(0, result.returncode, result.stderr)
        value = self._state()
        self.assertEqual(
            {
                "schema_version",
                "band",
                "generation",
                "activation_id",
                "contract_digest",
                "sampled_at",
                "process_running",
                "input_connected",
                "input_socket",
                "input_bytes",
            },
            set(value),
        )
        self.assertEqual(GENERATION, value["generation"])
        self.assertTrue(value["process_running"])
        self.assertTrue(value["input_connected"])
        self.assertEqual("9876", value["input_socket"])
        self.assertEqual(42, value["input_bytes"])
        self.assertLessEqual(started, (self.output / "source-state.json").stat().st_mtime)
        self.assertEqual(0o640, stat.S_IMODE((self.output / "source-state.json").stat().st_mode))

        self._write_ss(self._socket_output(bytes_received=None))
        quiet = self._run()
        self.assertEqual(0, quiet.returncode, quiet.stderr)
        self.assertEqual(0, self._state()["input_bytes"])

    # reject stale publications while retaining safe process evidence
    def test_stale_publication_fails_closed(self):
        stale = time.time() - 30
        os.utime(self.output / "aircraft.json", (stale, stale))
        result = self._run()
        self.assertEqual(1, result.returncode)
        self.assertTrue(self._state()["process_running"])
        self.assertTrue(self._state()["input_connected"])

    # reject absent decoders and ambiguous physical inputs
    def test_process_and_connector_fail_closed(self):
        (self.proc / "123/comm").write_text("other\n", encoding="ascii")
        missing = self._run()
        self.assertEqual(1, missing.returncode)
        self.assertFalse(self._state()["process_running"])
        self.assertFalse(self._state()["input_connected"])

        (self.proc / "123/comm").write_text("readsb\n", encoding="ascii")
        self._write_ss(self._socket_output(bytes_received=1, duplicate=True))
        ambiguous = self._run()
        self.assertEqual(1, ambiguous.returncode)
        self.assertTrue(self._state()["process_running"])
        self.assertFalse(self._state()["input_connected"])

    # reject altered band ports and marker provenance
    def test_contract_and_generation_fail_closed(self):
        wrong_port = self._run(port="30978")
        self.assertEqual(1, wrong_port.returncode)
        self.assertFalse(self._state()["input_connected"])

        self._write_marker(generation="not-a-generation")
        wrong_generation = self._run()
        self.assertEqual(1, wrong_generation.returncode)
        self.assertEqual("", self._state()["generation"])

    # accept the independently fixed 978 connector contract
    def test_978_contract_is_healthy(self):
        self._write_marker(band="978")
        self._write_ss(self._socket_output(bytes_received=0, port="30978"))
        result = self._run(band="978", port="30978")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("978", self._state()["band"])
        self.assertTrue(self._state()["input_connected"])

    # prevent repeated interpreter startup from returning to the health path
    def test_shell_launches_one_python_interpreter(self):
        content = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertEqual(1, content.count("/usr/bin/python3"))

    # reject symlinked and oversized markers without reading their target
    def test_marker_is_nofollow_and_bounded(self):
        marker = self.output / "source-marker.json"
        marker.unlink()
        target = self.root / "marker-target.json"
        target.write_text("{}", encoding="utf-8")
        marker.symlink_to(target)
        symlinked = self._run()
        self.assertEqual(1, symlinked.returncode)
        self.assertEqual("", self._state()["generation"])

        marker.unlink()
        marker.write_text("{" + (" " * 8193), encoding="utf-8")
        oversized = self._run()
        self.assertEqual(1, oversized.returncode)
        self.assertEqual("", self._state()["generation"])


# allow direct focused execution
if __name__ == "__main__":
    unittest.main()
