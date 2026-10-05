"""regression checks for the isolated encrypted backup boundary"""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from adsb_admin.alert_config import MAX_OVERRIDES, default_alert_settings

REPOSITORY_ROOT = Path(__file__).parents[1]
BACKUP_ROOT = Path(__file__).parents[1] / "deploy/backup"
PROOF_PATH = BACKUP_ROOT / "backup-proof.sh"
VALIDATION_MARKER = "PY_ALERT_BACKUP_VALIDATION"


# extract the production validator exercised by backup proof
def alert_validation_program() -> str:
    proof = PROOF_PATH.read_text(encoding="utf-8")
    opening = f"<<'{VALIDATION_MARKER}'\n"
    start = proof.index(opening) + len(opening)
    end = proof.index(f"\n{VALIDATION_MARKER}\n", start)
    return proof[start:end]


# build one restorable conservative continuity snapshot
def valid_continuity() -> dict:
    return {
        "schema_version": 1,
        "generation": "activation-1",
        "generated_at": 100.0,
        "encounters": [
            {
                "hex": "A2CCA7",
                "last_seen_at": 90.0,
                "current_event_id": None,
                "required_bands": ["1090", "978"],
                "rearmed_at": 95.0,
            }
        ],
    }


# lock the source backup command boundary
class BackupIntegrationTests(unittest.TestCase):
    # run the embedded release-bound validator against isolated artifacts
    def run_alert_validation(self, alerts: object, continuity: object) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alerts_path = root / "alerts.json"
            continuity_path = root / "continuity.json"
            alerts_path.write_text(json.dumps(alerts), encoding="utf-8")
            continuity_path.write_text(json.dumps(continuity), encoding="utf-8")
            return subprocess.run(
                [
                    "python3",
                    "-B",
                    "-",
                    str(REPOSITORY_ROOT),
                    str(alerts_path),
                    str(continuity_path),
                ],
                check=False,
                capture_output=True,
                input=alert_validation_program(),
                text=True,
            )

    # require every source wrapper to parse
    def test_shell_wrappers_parse(self):
        scripts = sorted(BACKUP_ROOT.glob("*.sh"))
        self.assertGreater(len(scripts), 0)
        subprocess.run(["bash", "-n", *(str(path) for path in scripts)], check=True)

    # retain only selected release state
    def test_stream_excludes_history_and_unselected_releases(self):
        stream = (BACKUP_ROOT / "backup-stream.sh").read_text(encoding="utf-8")
        self.assertIn('app_path="opt/adsb/releases/$app_release"', stream)
        self.assertIn('map_path="opt/adsb/map-ui-releases/$map_release"', stream)
        self.assertNotIn("var/lib/adsb/tar1090", stream)
        self.assertNotIn("var/lib/adsb/runtime", stream)
        self.assertNotIn("var/lib/adsb/status", stream)
        self.assertNotIn("alerts.sqlite3", stream)
        self.assertIn("var/lib/adsb/config/alerts.json", stream)
        self.assertIn("var/lib/adsb/alerts/continuity.json", stream)
        self.assertIn("etc/systemd/system/adsb-alerts.service", stream)

    # validate private continuity schema without backing up live delivery state
    def test_proof_checks_alert_ownership_and_conservative_band_set(self):
        proof = PROOF_PATH.read_text(encoding="utf-8")
        self.assertIn("require_file /var/lib/adsb/config/alerts.json adsb:adsb:600", proof)
        self.assertIn("require_file /var/lib/adsb/alerts/continuity.json adsb:adsb:600", proof)
        self.assertIn("MAX_ALERT_SETTINGS_BYTES = 2 * 1024 * 1024", proof)
        self.assertIn("MAX_CONTINUITY_BYTES = 16 * 1024 * 1024", proof)
        self.assertIn("AlertSettingsStore(settings_path, readonly=True)", proof)
        self.assertIn('len(value["encounters"]) > MAX_ENCOUNTERS', proof)
        self.assertIn('value.get("schema_version") != 1', proof)
        self.assertIn('band not in ("1090", "978")', proof)
        self.assertNotIn("alerts.sqlite3", proof)
        self.assertNotIn("restore_continuity", proof)
        self.assertNotIn("AlertStore(", proof)

    # accept exactly the schemas used by the worker and admin store
    def test_proof_alert_validator_accepts_valid_artifacts(self):
        result = self.run_alert_validation(default_alert_settings(), valid_continuity())
        self.assertEqual("", result.stderr)
        self.assertEqual(0, result.returncode)

    # retain every settings row allowed by the release validator
    def test_proof_alert_validator_accepts_maximum_settings(self):
        settings = default_alert_settings()
        # exercise worst-case escaped labels beneath the private file cap
        settings["overrides"] = [
            {
                "hex": f"{index:06X}",
                "mode": "include",
                "categories": ["military", "medical", "news"],
                "label": "\uffff" * 100,
            }
            for index in range(MAX_OVERRIDES)
        ]
        result = self.run_alert_validation(settings, valid_continuity())
        self.assertEqual(0, result.returncode)

    # reject objects that the settings store cannot load
    def test_proof_alert_validator_rejects_malformed_settings_object(self):
        result = self.run_alert_validation({}, valid_continuity())
        self.assertNotEqual(0, result.returncode)

    # reject continuity values that the live restore path cannot safely consume
    def test_proof_alert_validator_rejects_invalid_continuity(self):
        cases: dict[str, dict] = {}

        invalid_icao = valid_continuity()
        invalid_icao["encounters"][0]["hex"] = "NOTHEX"
        cases["invalid icao"] = invalid_icao

        generated_nan = valid_continuity()
        generated_nan["generated_at"] = float("nan")
        cases["nonfinite snapshot clock"] = generated_nan

        seen_infinity = valid_continuity()
        seen_infinity["encounters"][0]["last_seen_at"] = float("inf")
        cases["nonfinite observation clock"] = seen_infinity

        rearmed_nan = valid_continuity()
        rearmed_nan["encounters"][0]["rearmed_at"] = float("nan")
        cases["nonfinite rearm clock"] = rearmed_nan

        conflicting_marker = valid_continuity()
        conflicting_marker["encounters"][0]["current_event_id"] = "event-1"
        cases["event marker with rearm"] = conflicting_marker

        duplicate_identity = valid_continuity()
        duplicate_identity["encounters"].append(copy.deepcopy(duplicate_identity["encounters"][0]))
        cases["duplicate normalized identity"] = duplicate_identity

        # prove every unsafe case fails closed
        for name, continuity in cases.items():
            with self.subTest(name=name):
                result = self.run_alert_validation(default_alert_settings(), continuity)
                self.assertNotEqual(0, result.returncode)

    # bind future upgrades to selected release code
    def test_stable_entrypoints_delegate_to_current_release(self):
        ssh_entrypoint = (BACKUP_ROOT / "ssh-entrypoint.sh").read_text(encoding="utf-8")
        root_entrypoint = (BACKUP_ROOT / "remote-ops-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("/opt/adsb/current/deploy/backup/ssh-dispatch.sh", ssh_entrypoint)
        self.assertIn("/opt/adsb/current/deploy/backup/remote-ops.sh", root_entrypoint)

    # keep container-only map dependencies out of the tar
    def test_stream_excludes_only_pinned_map_links(self):
        stream = (BACKUP_ROOT / "backup-stream.sh").read_text(encoding="utf-8")
        for name in ("db-3.14.1715", "config.js", "upintheair.json"):
            self.assertIn(f'--exclude="$map_path/{name}"', stream)


# run focused checks directly
if __name__ == "__main__":
    unittest.main()
