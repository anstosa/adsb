"""Release-owned aircraft role catalog and operator override matching."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from adsb_admin.alert_config import ALERT_CATEGORIES

CATALOG_SCHEMA_VERSION = 1
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_CATALOG_ENTRIES = 50_000
ICAO_PATTERN = re.compile(r"^[0-9A-F]{6}$")
AIRCRAFT_MODEL_PATTERN = re.compile(r"^[A-Z0-9]{2,4}$")


# represent unavailable or invalid release data
class CatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class Classification:
    """Describe usual aircraft roles without asserting a current mission."""

    categories: tuple[str, ...]
    label: str
    sources: tuple[str, ...]


# normalize only standard catalog-compatible identities
def normalize_icao(value: Any) -> str | None:
    # reject anonymous, qualified, and non-text identities
    if not isinstance(value, str):
        return None
    normalized = value.upper()
    # accept exactly six hexadecimal characters
    if ICAO_PATTERN.fullmatch(normalized) is None:
        return None
    return normalized


# normalize one exact icao type designator
def normalize_aircraft_model(value: Any) -> str | None:
    # reject absent and nontext model metadata
    if not isinstance(value, str):
        return None
    normalized = value.upper()
    # accept only bounded alphanumeric type codes
    if AIRCRAFT_MODEL_PATTERN.fullmatch(normalized) is None:
        return None
    return normalized


# read and validate the immutable role catalog
class AlertCatalog:
    # retain validated exact entries and provenance
    def __init__(self, entries: dict[str, Classification], manifest: dict[str, Any]) -> None:
        self._entries = entries
        self.manifest = manifest
        self.version = manifest["catalog_sha256"]

    # load one catalog and its pinned provenance manifest
    @classmethod
    def from_paths(cls, catalog_path: Path, manifest_path: Path) -> AlertCatalog:
        try:
            catalog_bytes = catalog_path.read_bytes()
            manifest_bytes = manifest_path.read_bytes()
        except OSError as exc:
            raise CatalogError("aircraft role catalog is unavailable") from exc
        # bound release input before parsing
        if len(catalog_bytes) > MAX_CATALOG_BYTES or len(manifest_bytes) > 64 * 1024:
            raise CatalogError("aircraft role catalog exceeds its size limit")
        try:
            catalog = json.loads(catalog_bytes)
            manifest = json.loads(manifest_bytes)
        except json.JSONDecodeError as exc:
            raise CatalogError("aircraft role catalog is invalid") from exc
        expected_manifest = frozenset(
            (
                "schema_version",
                "catalog_schema_version",
                "catalog_sha256",
                "derived_at",
                "entry_count",
                "category_counts",
                "upstream",
                "derivation",
            )
        )
        # require the complete manifest contract
        if not isinstance(manifest, dict) or frozenset(manifest) != expected_manifest:
            raise CatalogError("aircraft role catalog manifest is invalid")
        digest = hashlib.sha256(catalog_bytes).hexdigest()
        # bind catalog bytes to the reviewed manifest
        if manifest.get("schema_version") != 1 or manifest.get("catalog_sha256") != digest:
            raise CatalogError("aircraft role catalog digest does not match its manifest")
        # bind source attribution to the approved upstream revision
        upstream = manifest.get("upstream")
        if (
            not isinstance(upstream, dict)
            or upstream.get("commit") != "dc611e2cc1c243f61a6d9d913b83613a19e1f858"
            or upstream.get("source_sha256") != "6a1ae6d60c61e18d096039dc0eb4de1d87c3bfafc500efb615dbe0b703962915"
            or upstream.get("license") != "ODbL-1.0 and DBCL-1.0"
        ):
            raise CatalogError("aircraft role catalog provenance is invalid")
        # require the normalized top-level schema
        if (
            not isinstance(catalog, dict)
            or frozenset(catalog) != frozenset(("schema_version", "entries"))
            or catalog.get("schema_version") != CATALOG_SCHEMA_VERSION
            or not isinstance(catalog.get("entries"), list)
            or len(catalog["entries"]) > MAX_CATALOG_ENTRIES
        ):
            raise CatalogError("aircraft role catalog schema is invalid")
        entries: dict[str, Classification] = {}
        category_counts = {category: 0 for category in ALERT_CATEGORIES}
        # validate each exact identity once
        for row in catalog["entries"]:
            # reject partial or extensible rows
            if not isinstance(row, dict) or frozenset(row) != frozenset(("hex", "label", "categories")):
                raise CatalogError("aircraft role catalog entry is invalid")
            hex_id = normalize_icao(row["hex"])
            label = row["label"]
            categories = row["categories"]
            # reject ambiguous identities and unsafe labels
            if (
                hex_id is None
                or hex_id in entries
                or not isinstance(label, str)
                or not label
                or len(label) > 120
                or any(ord(character) < 32 for character in label)
            ):
                raise CatalogError("aircraft role catalog entry is invalid")
            # require an ordered unique supported category list
            if (
                not isinstance(categories, list)
                or not categories
                or any(category not in ALERT_CATEGORIES for category in categories)
                or len(categories) != len(set(categories))
            ):
                raise CatalogError("aircraft role catalog entry is invalid")
            normalized_categories = tuple(category for category in ALERT_CATEGORIES if category in categories)
            entries[hex_id] = Classification(normalized_categories, label, ("catalog",))
            # count each role independently
            for category in normalized_categories:
                category_counts[category] += 1
        # bind manifest summaries to the loaded derivative
        if manifest.get("entry_count") != len(entries) or manifest.get("category_counts") != category_counts:
            raise CatalogError("aircraft role catalog summary does not match")
        return cls(entries, manifest)

    # classify one physical-view-confirmed aircraft
    def classify(
        self,
        hex_id: Any,
        *,
        db_flags: Any = None,
        model: Any = None,
        overrides: Iterable[dict[str, Any]] = (),
    ) -> Classification:
        normalized = normalize_icao(hex_id)
        # reject identities that cannot safely join the catalog
        if normalized is None:
            return Classification((), "", ())
        base = self._entries.get(normalized)
        categories = set(base.categories if base else ())
        label = base.label if base else normalized
        sources = set(base.sources if base else ())
        # accept only a strict nonnegative integer db flag schema
        if isinstance(db_flags, int) and not isinstance(db_flags, bool) and db_flags >= 0 and db_flags & 1:
            categories.add("military")
            sources.add("dbFlags")
        normalized_model = normalize_aircraft_model(model)
        includes: set[str] = set()
        excludes: set[str] = set()
        model_label = ""
        exact_label = ""
        # apply every matching normalized override defensively
        for override in overrides:
            # ignore malformed rows from non-config callers
            if not isinstance(override, dict):
                continue
            exact_match = normalize_icao(override.get("hex")) == normalized
            model_match = (
                normalized_model is not None and normalize_aircraft_model(override.get("model")) == normalized_model
            )
            # ignore overrides for a different aircraft or model
            if not exact_match and not model_match:
                continue
            mode = override.get("mode")
            values = override.get("categories")
            # ignore malformed category collections
            if not isinstance(values, list):
                continue
            valid_values = {category for category in values if category in ALERT_CATEGORIES}
            # let exclusion win over every inclusion source
            if mode == "exclude":
                excludes.update(valid_values)
            # add explicit safe inclusions
            elif mode == "include":
                includes.update(valid_values)
                override_label = override.get("label")
                # retain model and exact labels separately for precedence
                if isinstance(override_label, str) and override_label:
                    # prefer the narrower exact-aircraft label
                    if exact_match:
                        exact_label = override_label
                    elif model_match:
                        model_label = override_label
        # prefer an exact-aircraft label over a broader model label
        if exact_label:
            label = exact_label
        elif model_label:
            label = model_label
        # record override provenance only when it changes membership
        if includes or excludes:
            sources.add("override")
        categories.update(includes)
        categories.difference_update(excludes)
        ordered = tuple(category for category in ALERT_CATEGORIES if category in categories)
        return Classification(ordered, label, tuple(sorted(sources)))
