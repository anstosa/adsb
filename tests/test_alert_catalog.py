"""Pinned aircraft role catalog tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from adsb_admin.alert_catalog import AlertCatalog, CatalogError, normalize_icao

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "deploy/alerts/catalog.json"
MANIFEST_PATH = PROJECT_ROOT / "deploy/alerts/catalog-manifest.json"


# lock the reviewed derivative and exact classification rules
class AlertCatalogTest(unittest.TestCase):
    # load the release catalog once per test
    def setUp(self) -> None:
        self.catalog = AlertCatalog.from_paths(CATALOG_PATH, MANIFEST_PATH)

    # cover all three approved usual-role categories
    def test_known_military_medical_and_news_identities(self) -> None:
        self.assertIn("military", self.catalog.classify("000004").categories)
        self.assertIn("medical", self.catalog.classify("004006").categories)
        self.assertEqual(("news",), self.catalog.classify("a2cca7").categories)
        self.assertEqual(4, self.catalog.manifest["category_counts"]["news"])

    # avoid generic helicopter and uncertain metadata heuristics
    def test_unknown_aircraft_remains_unclassified(self) -> None:
        result = self.catalog.classify("ABCDEF")
        self.assertEqual((), result.categories)
        self.assertEqual((), result.sources)
        self.assertIsNone(normalize_icao("~ABCDEF"))
        self.assertIsNone(normalize_icao("ABCDEF00"))

    # supplement only a verified integer military bit
    def test_db_flags_requires_strict_documented_bit(self) -> None:
        self.assertEqual(("military",), self.catalog.classify("ABCDEF", db_flags=1).categories)
        self.assertEqual((), self.catalog.classify("ABCDEF", db_flags="1").categories)
        self.assertEqual((), self.catalog.classify("ABCDEF", db_flags=True).categories)

    # let exact exclusion override catalog and inclusion membership
    def test_override_exclusion_wins_and_overlap_stays_one_classification(self) -> None:
        overrides = [
            {"hex": "A2CCA7", "mode": "include", "categories": ["medical", "news"], "label": "Local role"},
            {"hex": "A2CCA7", "mode": "exclude", "categories": ["news"], "label": ""},
        ]
        result = self.catalog.classify("A2CCA7", overrides=overrides)
        self.assertEqual(("medical",), result.categories)
        self.assertEqual("Local role", result.label)
        self.assertIn("override", result.sources)

    # fail closed when reviewed bytes no longer match the manifest
    def test_catalog_digest_tamper_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = root / "catalog.json"
            manifest = root / "manifest.json"
            catalog.write_bytes(CATALOG_PATH.read_bytes() + b" ")
            manifest.write_bytes(MANIFEST_PATH.read_bytes())
            with self.assertRaises(CatalogError):
                AlertCatalog.from_paths(catalog, manifest)

    # retain exact pinned provenance and transformation details
    def test_manifest_records_upstream_and_derived_digests(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual("dc611e2cc1c243f61a6d9d913b83613a19e1f858", manifest["upstream"]["commit"])
        self.assertEqual(
            "6a1ae6d60c61e18d096039dc0eb4de1d87c3bfafc500efb615dbe0b703962915",
            manifest["upstream"]["source_sha256"],
        )
        self.assertEqual(["A2CCA7", "A63954", "A7C45A", "ACD27A"], manifest["derivation"]["news_reviewed_hexes"])
        self.assertTrue((PROJECT_ROOT / "deploy/alerts/LICENSE-plane-alert-db").is_file())
        self.assertTrue((PROJECT_ROOT / "deploy/alerts/ATTRIBUTION.md").is_file())


# run focused checks directly
if __name__ == "__main__":
    unittest.main()
