#!/usr/bin/env python3
"""Prepare the pinned Airplanes.live tar1090 UI for a custom-html mount."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

SCRIPT_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = SCRIPT_DIR / "map-ui.json"
BRAND_FAVICON_PATH = SCRIPT_DIR.parent / "web" / "favicon.svg"
BRAND_FAVICON_HREF = "favicon.svg?v=goose-photo-trace"
BRAND_TITLE = "Ballydídean Farm Sanctuary ADS-B"
SITE_INFO_HTML_PATH = SCRIPT_DIR.parent / "web" / "map-site-info.html"
SITE_INFO_CSS_PATH = SCRIPT_DIR.parent / "web" / "map-site-info.css"
DOWNLOAD_IO_TIMEOUT_SECONDS = 10
DOWNLOAD_TOTAL_TIMEOUT_SECONDS = 120
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
INDEX_DATABASE_SOURCE = 'let databaseFolder = "https://static.airplanes.live/db";'
INDEX_FAVICON_SOURCE = '<link rel="icon" type="image/png" href="images/tar1090-favicon.png">'
INDEX_TITLE_SOURCE = "<title>tar1090</title>"
BUNDLE_METADATA_FILES = frozenset({"version.json", "provenance.json"})
TRUSTED_CACHEBUST_SCRIPT_SHA256 = "eea2c14191ec4a32dd4d3548148e7455de3ac55f2ab3018f416b884a62454f99"
TRUSTED_CACHEBUST_LIST_SHA256 = "71a9714220b443457a1a0dacae12d5916adcc5e7ab9ad29f9b80d5a38931d9f0"


# parse the stable command-line interface
def parse_args(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("archive", nargs="?", type=Path, help="optional local pinned source archive")
    return parser.parse_args(arguments)


# load the checked-in production pin
def load_manifest() -> dict:
    with MANIFEST_PATH.open(encoding="utf-8") as source:
        return json.load(source)


# detect existing paths including broken symlinks
def path_exists(path: Path) -> bool:
    return os.path.lexists(path)


# hash files without loading them into memory
def file_hash(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        # stream source archives and static assets
        for chunk in iter(lambda: source.read(DOWNLOAD_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


# download the immutable archive into private staging
def download_archive(url: str, destination: Path, expected_size: int) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "adsb-map-ui-preparer/1"})
    deadline = time.monotonic() + DOWNLOAD_TOTAL_TIMEOUT_SECONDS
    with urllib.request.urlopen(request, timeout=DOWNLOAD_IO_TIMEOUT_SECONDS) as response:
        with destination.open("wb") as target:
            total = 0
            # stream through bounded reads with one-byte overflow detection
            while True:
                # enforce the end-to-end deadline before blocking
                if time.monotonic() >= deadline:
                    raise TimeoutError("source archive download exceeded total deadline")
                read_size = min(DOWNLOAD_CHUNK_BYTES, expected_size - total + 1)
                chunk = response.read1(read_size)
                # enforce the end-to-end deadline after each bounded read
                if time.monotonic() >= deadline:
                    raise TimeoutError("source archive download exceeded total deadline")
                # stop only at the remote end of stream
                if not chunk:
                    break
                total += len(chunk)
                # reject an oversized response immediately
                if total > expected_size:
                    raise ValueError(f"source archive size exceeds pinned {expected_size} bytes")
                target.write(chunk)
    # require the exact pinned byte count
    if total != expected_size:
        raise ValueError(f"source archive size mismatch: expected {expected_size}, got {total}")


# reject unexpected local or staged archive sizes
def verify_archive_size(archive: Path, expected_size: int) -> None:
    # require a readable regular source artifact
    if not archive.is_file():
        raise ValueError(f"source archive is not a regular file: {archive}")
    actual_size = archive.stat().st_size
    # reject bytes outside the pinned envelope
    if actual_size != expected_size:
        raise ValueError(f"source archive size mismatch: expected {expected_size}, got {actual_size}")


# validate the archive before extraction or script execution
def verify_archive(archive: Path, expected_sha256: str, expected_size: int) -> None:
    verify_archive_size(archive, expected_size)
    actual_sha256 = file_hash(archive)
    # reject bytes outside the reviewed pin
    if actual_sha256 != expected_sha256:
        raise ValueError(f"source archive checksum mismatch: expected {expected_sha256}, got {actual_sha256}")


# extract only the checksum-pinned source tree
def extract_archive(archive: Path, destination: Path, source_root: str) -> Path:
    with tarfile.open(archive, mode="r:gz") as source:
        members = source.getmembers()
        # reject archives without a source tree
        if not members:
            raise ValueError("source archive is empty")
        # reject unexpected roots and link members
        for member in members:
            member_path = PurePosixPath(member.name)
            # contain every extracted member
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"unsafe source archive path: {member.name}")
            # require the immutable commit root
            if not member_path.parts or member_path.parts[0] != source_root:
                raise ValueError(f"unexpected source archive root: {member.name}")
            # keep archive links out of extraction
            if member.issym() or member.islnk():
                raise ValueError(f"unexpected source archive link: {member.name}")
        source.extractall(destination, members=members, filter="data")
    extracted = destination / source_root
    # require the declared tree after extraction
    if not extracted.is_dir():
        raise ValueError(f"source root was not extracted: {source_root}")
    return extracted


# replace a copied file with an exact base-image link
def install_absolute_link(path: Path, target: str) -> None:
    # replace copied optional integration files
    if path_exists(path):
        # never remove an unexpected directory
        if path.is_dir() and not path.is_symlink():
            raise ValueError(f"cannot replace directory with integration link: {path.name}")
        path.unlink()
    path.symlink_to(target)


# validate every pinned marker before transforming source content
def replace_exact_markers(source: str, replacements: dict[str, str], error_message: str) -> str:
    # reject missing or ambiguous markers in the original source
    for marker in replacements:
        # preserve each caller's integration-specific failure message
        if source.count(marker) != 1:
            raise ValueError(error_message)
    # apply only the fully validated replacement set
    for marker, replacement in replacements.items():
        source = source.replace(marker, replacement)
    return source


# rewrite only the reviewed upstream database declaration
def wire_local_database(index_path: Path, database_directory: str) -> None:
    index = replace_exact_markers(
        index_path.read_text(encoding="utf-8"),
        {INDEX_DATABASE_SOURCE: f"let databaseFolder = '{database_directory}';"},
        "expected external database declaration was not found exactly once",
    )
    index_path.write_text(index, encoding="utf-8")


# replace the upstream browser identity with sanctuary branding
def wire_branding(index_path: Path) -> None:
    index = index_path.read_text(encoding="utf-8")
    replacements = {
        INDEX_FAVICON_SOURCE: f'<link rel="icon" type="image/svg+xml" href="{BRAND_FAVICON_HREF}">',
        INDEX_TITLE_SOURCE: f"<title>{BRAND_TITLE}</title>",
    }
    index = replace_exact_markers(index, replacements, "expected map branding marker was not found exactly once")
    index_path.write_text(index, encoding="utf-8")


# keep sanctuary information above both classic and ui2 sidebar content
def wire_site_info(index_path: Path) -> None:
    index = index_path.read_text(encoding="utf-8")
    markup = SITE_INFO_HTML_PATH.read_text(encoding="utf-8")
    styles = SITE_INFO_CSS_PATH.read_text(encoding="utf-8")
    replacements = {
        "</head>": f'<style id="site-info-styles">\n{styles}</style>\n  </head>',
        '<div id="sidebar_canvas">': f'<div id="sidebar_canvas">\n{markup}',
    }
    index = replace_exact_markers(index, replacements, "expected site info marker was not found exactly once")
    index_path.write_text(index, encoding="utf-8")


# disable the public aggregator before early startup resolves API paths
def wire_local_receiver(early_path: Path, patch: dict) -> None:
    source = replace_exact_markers(
        early_path.read_text(encoding="utf-8"),
        {patch["source"]: patch["replacement"]},
        "expected aggregator declaration was not found exactly once",
    )
    early_path.write_text(source, encoding="utf-8")


# verify source assets before running the upstream cachebuster
def verify_source_assets(html: Path, assets: dict) -> None:
    # verify reviewed UI2 bytes and cache keys
    for name, hashes in assets.items():
        actual_sha256 = file_hash(html / name)
        # reject unexpected source bytes
        if actual_sha256 != hashes["sha256"]:
            raise ValueError(f"source asset checksum mismatch: {name}")
        actual_md5 = file_hash(html / name, "md5")
        # pin output file naming
        if actual_md5 != hashes["md5"]:
            raise ValueError(f"source asset cache key mismatch: {name}")


# run the checksum-pinned upstream cachebust algorithm
def cachebust(source_root: Path, html: Path, expected: dict) -> None:
    script = source_root / "cachebust.sh"
    file_list = source_root / "cachebust.list"
    # require both candidate evidence and source bytes to match the fixed reviewed algorithm
    if expected.get("script_sha256") != TRUSTED_CACHEBUST_SCRIPT_SHA256:
        raise ValueError("candidate cachebust script is outside the trusted gate")
    if file_hash(script) != TRUSTED_CACHEBUST_SCRIPT_SHA256:
        raise ValueError("upstream cachebust script checksum mismatch")
    # require both candidate evidence and bytes to match the reviewed filename list
    if expected.get("list_sha256") != TRUSTED_CACHEBUST_LIST_SHA256:
        raise ValueError("candidate cachebust list is outside the trusted gate")
    if file_hash(file_list) != TRUSTED_CACHEBUST_LIST_SHA256:
        raise ValueError("upstream cachebust list checksum mismatch")
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    }
    subprocess.run(
        ["/bin/bash", str(script), str(file_list), str(html)],
        cwd=html,
        env=environment,
        check=True,
    )


# verify cachebusted output names and references
def verify_cachebusted_assets(html: Path, assets: dict) -> None:
    index = (html / "index.html").read_text(encoding="utf-8")
    # verify output content and index wiring
    for name, hashes in assets.items():
        stem, suffix = name.rsplit(".", 1)
        generated_name = f"{stem}_{hashes['md5']}.{suffix}"
        generated_path = html / generated_name
        # require the original name to be retired
        if path_exists(html / name):
            raise ValueError(f"uncachebusted source asset remains: {name}")
        # preserve source bytes through renaming
        if file_hash(generated_path) != hashes["sha256"]:
            raise ValueError(f"cachebusted asset checksum mismatch: {generated_name}")
        # require the generated index reference
        if generated_name not in index:
            raise ValueError(f"cachebusted asset is not referenced by index: {generated_name}")


# bind every output path, file byte, and integration target
def bundle_digest(html: Path) -> str:
    digest = hashlib.sha256()
    entries = sorted(html.rglob("*"), key=lambda path: path.relative_to(html).as_posix())
    # hash entries in stable relative-path order
    for path in entries:
        relative = path.relative_to(html).as_posix()
        # exclude self-referential generated metadata
        if relative in BUNDLE_METADATA_FILES:
            continue
        encoded_path = relative.encode("utf-8")
        # bind link targets without following them
        if path.is_symlink():
            encoded_target = os.readlink(path).encode("utf-8")
            digest.update(b"link\0" + encoded_path + b"\0" + encoded_target + b"\0")
        # bind directories including empty ones
        elif path.is_dir():
            digest.update(b"directory\0" + encoded_path + b"\0")
        # bind regular file size and bytes
        elif path.is_file():
            digest.update(b"file\0" + encoded_path + b"\0" + path.stat().st_size.to_bytes(8, "big"))
            with path.open("rb") as source:
                # stream static and bundled source bytes
                for chunk in iter(lambda: source.read(DOWNLOAD_CHUNK_BYTES), b""):
                    digest.update(chunk)
        else:
            raise ValueError(f"unsupported bundle entry: {relative}")
    return digest.hexdigest()


# write deterministic public source provenance
def write_provenance(html: Path, manifest: dict) -> None:
    provenance = {**manifest, "bundle_digest": bundle_digest(html)}
    payload = json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    (html / "version.json").write_text(payload, encoding="utf-8")
    (html / "provenance.json").write_text(payload, encoding="utf-8")


# normalize static content independently of the caller umask
def normalize_permissions(html: Path) -> None:
    html.chmod(0o755)
    # normalize every copied static entry
    for directory, directories, files in os.walk(html, followlinks=False):
        root = Path(directory)
        # keep integration links untouched
        for name in directories:
            path = root / name
            # avoid changing base-image targets
            if not path.is_symlink():
                path.chmod(0o755)
        # make only regular static files public
        for name in files:
            path = root / name
            # avoid changing base-image targets
            if not path.is_symlink():
                path.chmod(0o644)


# build the complete custom-html directory in private staging
def build_bundle(source_root: Path, archive: Path, staging_root: Path, manifest: dict) -> Path:
    upstream = manifest["upstream"]
    dependency = manifest["base_image_dependency"]
    html = staging_root / "bundle"
    shutil.copytree(source_root / "html", html)
    wire_local_database(html / "index.html", dependency["database_directory"])
    wire_branding(html / "index.html")
    wire_site_info(html / "index.html")
    shutil.copy2(BRAND_FAVICON_PATH, html / "favicon.svg")
    local_patches = manifest["local_patches"]
    # keep the published patch record exact and bounded
    if len(local_patches) != 1 or local_patches[0]["file"] != "early.js":
        raise ValueError("expected exactly one early.js local patch")
    wire_local_receiver(html / "early.js", local_patches[0])

    integration_root = dependency["html_root"]
    install_absolute_link(html / dependency["config"], f"{integration_root}/{dependency['config']}")
    database = dependency["database_directory"]
    install_absolute_link(html / database, f"{integration_root}/{database}")
    upintheair = dependency["optional_upintheair"]
    install_absolute_link(html / upintheair, f"{integration_root}/{upintheair}")

    verify_source_assets(html, manifest["assets"])
    cachebust(source_root, html, manifest["cachebust"])
    verify_cachebusted_assets(html, manifest["assets"])

    shutil.copy2(source_root / "LICENSE", html / "LICENSE")
    shutil.copyfile(archive, html / upstream["archive_filename"])
    write_provenance(html, manifest)
    normalize_permissions(html)
    return html


# publish without replacing a path created by another process
def publish_bundle(staged: Path, output: Path) -> None:
    try:
        output.mkdir(mode=0o755)
    except FileExistsError as error:
        raise ValueError(f"output already exists: {output}") from error
    try:
        output.chmod(0o755)
        # move staged entries into the exclusively created output
        for entry in staged.iterdir():
            entry.rename(output / entry.name)
        staged.rmdir()
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


# orchestrate verified preparation and atomic path ownership
def prepare(output: Path, local_archive: Path | None) -> None:
    output = output.absolute()
    # fail before inspecting input when output is owned
    if path_exists(output):
        raise ValueError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    upstream = manifest["upstream"]
    expected_size = upstream["archive_size_bytes"]

    with tempfile.TemporaryDirectory(prefix=".map-ui-", dir=output.parent) as temporary:
        staging_root = Path(temporary)
        # download only when no offline source is supplied
        if local_archive is None:
            archive = staging_root / "upstream.tar.gz"
            download_archive(upstream["archive_url"], archive, expected_size)
        else:
            archive = staging_root / "upstream.tar.gz"
            verify_archive_size(local_archive.absolute(), expected_size)
            shutil.copyfile(local_archive.absolute(), archive)
        verify_archive(archive, upstream["archive_sha256"], expected_size)
        source_root = extract_archive(archive, staging_root / "source", upstream["source_root"])
        staged = build_bundle(source_root, archive, staging_root, manifest)
        publish_bundle(staged, output)


# expose concise failures to installers
def main(arguments: list[str] | None = None) -> int:
    options = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        prepare(options.output, options.archive)
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"prepare-map-ui: {error}", file=sys.stderr)
        return 1
    print(f"prepared map UI at {options.output.absolute()}")
    return 0


# run only through the public command interface
if __name__ == "__main__":
    raise SystemExit(main())
