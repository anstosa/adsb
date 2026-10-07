"""Safety tests for immutable upstream update evidence."""

import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch

from adsb_admin.update_evidence import (
    TRUSTED_CACHEBUST_SCRIPT_SHA256,
    VERSION_PATTERN,
    _oci_metadata_value,
    canonical_hash,
    inspect_map_archive,
    nginx_patch_compatibility,
    parse_image_reference,
)


class UpdateEvidenceTests(unittest.TestCase):
    # canonical hashes must not depend on insertion order
    def test_canonical_hash_is_stable(self):
        self.assertEqual(canonical_hash({"b": 2, "a": 1}), canonical_hash({"a": 1, "b": 2}))

    # accept digest-bound OCI labels and annotations only when they agree
    def test_oci_metadata_coalesces_annotations_without_hiding_conflicts(self):
        key = "org.opencontainers.image.version"
        self.assertEqual(
            _oci_metadata_value(
                key,
                ({key: "1.30.5-alpine"}, {key: "1.30.5-alpine"}, None),
                maximum=80,
                pattern=VERSION_PATTERN,
            ),
            "1.30.5-alpine",
        )
        self.assertEqual(
            _oci_metadata_value(
                key,
                ({key: "1.30.5-alpine"}, {key: "stable-alpine"}),
                maximum=80,
                pattern=VERSION_PATTERN,
            ),
            "",
        )

    # accept only the fixed Docker Hub and GHCR reference grammar
    def test_image_reference_normalization_is_allowlisted(self):
        self.assertEqual(
            parse_image_reference("nginx:stable-alpine"), ("registry-1.docker.io", "library/nginx", "stable-alpine")
        )
        self.assertEqual(
            parse_image_reference("ghcr.io/example/image@sha256:" + "a" * 64),
            ("ghcr.io", "example/image", "sha256:" + "a" * 64),
        )
        # reject arbitrary registries whitespace and malformed digests
        for value in ("evil.example/image:latest", "nginx latest", "ghcr.io/example/image@sha256:bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_image_reference(value)

    # keep the sole automatic NGINX path reachable only through exhaustive positive evidence
    def test_nginx_positive_gate_requires_every_affirmative_constraint(self):
        changes = """Changes with nginx 1.30.5\n\n    *) Security: fixed one bounded issue.\n\n    *) Bugfix: corrected one regression.\n"""
        docker_changes = [
            {
                "path": "stable/alpine/Dockerfile",
                "patch": "@@ -1 +1 @@\n-ENV NGINX_VERSION 1.30.4\n+ENV NGINX_VERSION 1.30.5",
            }
        ]
        compatibility, _ = nginx_patch_compatibility(
            "1.30.4",
            "1.30.5",
            changes,
            docker_changes,
            current_base_name="docker.io/library/alpine:3.22",
            candidate_base_name="docker.io/library/alpine:3.22",
            current_base_digest="sha256:" + "a" * 64,
            candidate_base_digest="sha256:" + "a" * 64,
            exact_tag_matches=True,
        )
        self.assertEqual(compatibility, "compatible")
        failures = (
            {"candidate_version": "1.30.6"},
            {"changes_text": changes + "\n    *) Change: enabled a new behavior.\n"},
            {"docker_changes": [{"path": "stable/alpine/Dockerfile", "patch": "+RUN curl https://example.invalid"}]},
            {"candidate_base_name": "docker.io/library/alpine:3.23"},
            {"candidate_base_digest": "sha256:" + "b" * 64},
            {"exact_tag_matches": False},
        )
        base = {
            "current_version": "1.30.4",
            "candidate_version": "1.30.5",
            "changes_text": changes,
            "docker_changes": docker_changes,
            "current_base_name": "docker.io/library/alpine:3.22",
            "candidate_base_name": "docker.io/library/alpine:3.22",
            "current_base_digest": "sha256:" + "a" * 64,
            "candidate_base_digest": "sha256:" + "a" * 64,
            "exact_tag_matches": True,
        }
        # fail closed when any single affirmative input is missing
        for override in failures:
            with self.subTest(override=override):
                verdict, _ = nginx_patch_compatibility(**{**base, **override})
                self.assertEqual(verdict, "unknown")

    # derive map metadata only when every fixed integration marker remains exact
    def test_map_archive_inspection_binds_assets_and_script_gate(self):
        commit = "a" * 40
        root = f"tar1090-{commit}"
        current = {
            "tar1090Version": "old",
            "upstream": {"commit": "b" * 40},
            "assets": {"ui2.js": {}, "ui2.css": {}},
            "cachebust": {},
            "local_patches": [{"source": "let aggregator = true;"}],
        }
        index = (
            'let databaseFolder = "https://static.airplanes.live/db";\n'
            '<link rel="icon" type="image/png" href="images/tar1090-favicon.png">\n'
            '<title>tar1090</title></head><div id="sidebar_canvas">'
        )
        files = {
            "html/ui2.js": b"javascript",
            "html/ui2.css": b"css",
            "html/index.html": index.encode(),
            "html/early.js": b"let aggregator = true;",
            "cachebust.sh": b"not the trusted script",
            "cachebust.list": b"ui2.js\nui2.css\n",
            "LICENSE": b"GPL",
        }

        # build one deterministic in-memory source archive
        def build_archive(contents):
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as output:
                # add every exact evidence file under the immutable root
                for name, content in contents.items():
                    info = tarfile.TarInfo(f"{root}/{name}")
                    info.size = len(content)
                    output.addfile(info, io.BytesIO(content))
            return archive.getvalue()

        trusted_list = hashlib.sha256(files["cachebust.list"]).hexdigest()
        current["cachebust"]["list_sha256"] = trusted_list
        # isolate the integration-marker test from the production list pin
        with patch("adsb_admin.update_evidence.TRUSTED_CACHEBUST_LIST_SHA256", trusted_list):
            manifest = inspect_map_archive(build_archive(files), commit, current)
            self.assertEqual(manifest["upstream"]["commit"], commit)
            self.assertEqual(manifest["assets"]["ui2.js"]["sha256"], hashlib.sha256(b"javascript").hexdigest())
            self.assertNotEqual(manifest["cachebust"]["script_sha256"], TRUSTED_CACHEBUST_SCRIPT_SHA256)
            # marker drift is technical failure rather than executable upstream input
            broken = {**files, "html/early.js": b"let aggregator = false;"}
            with self.assertRaises(ValueError):
                inspect_map_archive(build_archive(broken), commit, current)
            # path-like cachebust input is blocked even when every other marker remains valid
            malicious = {**files, "cachebust.list": b"../../etc/adsb/admin.env\n"}
            with self.assertRaises(ValueError):
                inspect_map_archive(build_archive(malicious), commit, current)


if __name__ == "__main__":
    unittest.main()
