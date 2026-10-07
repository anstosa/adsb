"""Bounded maintenance for the receiver's immutable releases."""

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

# add only this immutable release root for the isolated script entrypoint
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adsb_admin.update_evidence import (
    COMMIT_PATTERN,
    TRUSTED_CACHEBUST_SCRIPT_SHA256,
    RegistryClient,
    canonical_hash,
    github_compare,
    inspect_map_archive,
    map_archive_evidence,
    review_nginx_candidate,
)

RELEASE_NAME = re.compile(r"^(\d{8}T\d{6}Z)-\d+$")
RETENTION_DAYS = 30
REPORT_PATH = Path("/var/lib/adsb/status/maintenance.json")
INSTALLATION_PATH = Path("/var/lib/adsb/status/installation.json")
CANDIDATE_PATH = Path("/var/lib/adsb/runtime/update-candidates.json")
OS_SCHEDULE = "Tuesdays 04:00 America/Los_Angeles"
APPLICATION_POLICY = (
    "Clearly compatible updates install automatically; breaking or unknown updates are held for your Install action"
)
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMAGE_NAMES = ("ultrafeeder", "piaware", "airspy", "dump978", "proxy", "cloudflared")
MAX_REPORT_BYTES = 96 * 1024
MAX_PRIVATE_CANDIDATE_BYTES = 512 * 1024
MAX_REMOVED_ARTIFACTS = 100000
MAX_UPDATES = 7
UPDATE_STATES = frozenset(
    {"available", "held", "queued", "installing", "installed", "failed", "rolled_back", "blocked"}
)
COMPATIBILITY_STATES = frozenset({"compatible", "breaking", "unknown"})
INSTALLATION_STATES = frozenset(
    {"idle", "queued", "preparing", "installing", "installed", "failed", "rolled_back", "rejected"}
)
TERMINAL_INSTALLATION_STATES = frozenset({"installed", "failed", "rolled_back", "rejected"})
INSTALLATION_OUTCOME_TTL_SECONDS = 8 * 86400
HEX64 = re.compile(r"^[a-f0-9]{64}$")
CHANGELOG_HOSTS = frozenset({"github.com", "nginx.org", "docs.nginx.com", "developers.cloudflare.com"})
IMAGE_LABELS = {
    "ultrafeeder": "Ultrafeeder",
    "piaware": "PiAware",
    "airspy": "Airspy ADS-B",
    "dump978": "Dump978",
    "proxy": "Nginx proxy",
    "cloudflared": "Cloudflare tunnel",
}


# compare the actual target architecture rather than unrelated index platforms
def amd64_digest(manifest: object) -> str:
    entries = manifest if isinstance(manifest, list) else [manifest]
    matches = set()
    # inspect every descriptor returned by docker's registry-only command
    for entry in entries:
        # reject unexpected registry response structures
        if not isinstance(entry, dict):
            continue
        descriptor = entry.get("Descriptor", {})
        # reject malformed descriptor envelopes
        if not isinstance(descriptor, dict):
            continue
        platform = descriptor.get("platform", {})
        value = descriptor.get("digest", "")
        # select only the receiver's architecture with a valid immutable digest
        if (
            isinstance(platform, dict)
            and platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
            and isinstance(value, str)
            and DIGEST.fullmatch(value)
        ):
            matches.add(value)
    # do not guess when no unique compatible platform is described
    if len(matches) != 1:
        raise ValueError("no unique linux/amd64 manifest")
    return matches.pop()


# inspect registry metadata without pulling layers or changing running images
def registry_digest(reference: str) -> str:
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.run(
            ["/usr/bin/docker", "manifest", "inspect", "--verbose", reference],
            stdout=output,
            stderr=errors,
            timeout=60,
        )
        # classify bounded diagnostics without logging registry credentials or urls
        if process.returncode:
            errors.seek(0)
            detail = errors.read(4096).decode("utf-8", errors="replace").lower()
            reason = "registry command failed"
            # retain useful failure categories rather than arbitrary remote text
            for marker, message in (
                ("unauthorized", "registry authorization denied"),
                ("denied", "registry authorization denied"),
                ("toomanyrequests", "registry rate limited"),
                ("too many requests", "registry rate limited"),
                ("no such manifest", "registry manifest unavailable"),
                ("not found", "registry manifest unavailable"),
                ("x509", "registry certificate verification failed"),
                ("timeout", "registry request timed out"),
            ):
                # stop at the first recognized nonsecret diagnostic
                if marker in detail:
                    reason = message
                    break
            raise ValueError(reason)
        output.seek(0)
        raw = output.read(1024 * 1024 + 1)
    # bound registry output before decoding it
    if len(raw) > 1024 * 1024:
        raise ValueError("registry manifest exceeds size limit")
    return amd64_digest(json.loads(raw))


# keep failed update checks diagnosable without exposing arbitrary upstream output
def log_lookup_failure(component: str, error: Exception) -> None:
    reason = "upstream metadata unavailable"
    # retain bounded locally generated manifest error categories
    if isinstance(error, ValueError) and str(error) in {
        "registry command failed",
        "registry authorization denied",
        "registry rate limited",
        "registry manifest unavailable",
        "registry certificate verification failed",
        "registry request timed out",
        "no unique linux/amd64 manifest",
        "registry manifest exceeds size limit",
        "map metadata exceeds size limit",
        "map source commit unavailable",
    }:
        reason = str(error)
    elif isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        reason = "upstream request timed out"
    elif isinstance(error, HTTPError):
        reason = f"upstream returned HTTP {error.code}"
    logging.warning("update review failed for %s: %s", component, reason)


# report map source changes without changing the reviewed bundle or its checksum
def map_update_status(deploy: Path) -> str:
    manifest = json.loads((deploy / "map-ui.json").read_text())
    request = urllib.request.Request(
        "https://api.github.com/repos/airplanes-live/tar1090/commits/prod",
        headers={"User-Agent": "adsb-maintenance/1", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(1024 * 1024 + 1)
    # reject oversized or unrecognized upstream metadata
    if len(raw) > 1024 * 1024:
        raise ValueError("map metadata exceeds size limit")
    sha = json.loads(raw).get("sha")
    # require a full source commit rather than trusting arbitrary version text
    if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ValueError("map source commit unavailable")
    return "current" if sha == manifest["upstream"]["commit"] else "review"


# download one bounded HTTPS document from an exact host
def _download(url: str, *, maximum: int, hosts: frozenset[str]) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    # reject credentials redirects and arbitrary destinations before connecting
    if parsed.scheme != "https" or parsed.hostname not in hosts or parsed.username or parsed.password:
        raise ValueError("unsupported upstream URL")
    request = urllib.request.Request(
        url, headers={"User-Agent": "adsb-maintenance/2", "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        final = urllib.parse.urlsplit(response.geturl())
        # require the final response to remain on the intended host set
        if final.scheme != "https" or final.hostname not in hosts or final.username or final.password:
            raise ValueError("unsafe upstream redirect")
        raw = response.read(maximum + 1)
    # bound all metadata and archive downloads
    if len(raw) > maximum:
        raise ValueError("upstream response exceeds size limit")
    return raw


# normalize one display version without trusting arbitrary labels
def _display_version(value: str, digest: str, revision: str = "") -> str:
    # prefer a short bounded OCI label when one is available
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}", value):
        normalized = value.removeprefix("v")
        # disambiguate floating branch labels with their exact bound revision or digest
        if normalized.lower() in {"main", "master", "latest"}:
            bound = revision if COMMIT_PATTERN.fullmatch(revision) else digest.removeprefix("sha256:")
            return f"{normalized} · {bound[:12]}"
        return normalized
    return digest.removeprefix("sha256:")[:12]


# parse an exact GitHub source repository from an OCI label
def _github_repository(source: str) -> str:
    parsed = urllib.parse.urlsplit(source)
    parts = parsed.path.strip("/").removesuffix(".git").split("/")
    # accept only one owner and repository on github.com
    if parsed.scheme == "https" and parsed.hostname == "github.com" and len(parts) == 2:
        repository = "/".join(parts)
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository):
            return repository
    return ""


# retrieve one curated Cloudflared release note without claiming image binding
def _cloudflared_notes(version: str) -> tuple[str, str]:
    if re.fullmatch(r"[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}", version):
        endpoint = f"https://api.github.com/repos/cloudflare/cloudflared/releases/tags/{version}"
        release_url = f"https://github.com/cloudflare/cloudflared/releases/tag/{version}"
        prefix = "Official release notes for the image version label:"
    else:
        endpoint = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
        release_url = "https://github.com/cloudflare/cloudflared/releases"
        prefix = "Latest official release notes, not proven to match this image:"
    try:
        document = json.loads(_download(endpoint, maximum=1024 * 1024, hosts=frozenset({"api.github.com"})))
        body = document.get("body")
        # retain bounded curated text only
        if isinstance(body, str) and body.strip():
            return f"{prefix}\n{body.strip()}"[:6000], release_url
    except (OSError, ValueError, TypeError, HTTPError, json.JSONDecodeError):
        pass
    return f"{prefix}\nRelease notes are unavailable.", release_url


# bind one private candidate identifier to its targets and evidence
def _candidate(
    *,
    name: str,
    label: str,
    current_version: str,
    candidate_version: str,
    compatibility: str,
    state: str,
    reason: str,
    changelog: str,
    changelog_url: str,
    kind: str,
    current_target: str,
    candidate_target: str,
    evidence: dict,
) -> dict:
    evidence_sha256 = canonical_hash(evidence)
    identity = {
        "name": name,
        "kind": kind,
        "current_target": current_target,
        "candidate_target": candidate_target,
        "evidence_sha256": evidence_sha256,
    }
    return {
        "id": canonical_hash(identity),
        "name": name,
        "label": label,
        "current_version": current_version[:160],
        "candidate_version": candidate_version[:160],
        "compatibility": compatibility,
        "state": state,
        "reason": reason[:1000],
        "changelog": changelog[:6000],
        "changelog_url": changelog_url,
        "kind": kind,
        "current_target": current_target,
        "candidate_target": candidate_target,
        "evidence": evidence,
        "evidence_sha256": evidence_sha256,
    }


# discover one exact image candidate without pulling layers
def _image_candidate(name: str, current: str, channel: str, client: RegistryClient) -> dict | None:
    current_evidence = client.resolve(current)
    candidate_evidence = client.resolve(channel)
    # omit channels that still resolve to the selected immutable manifest
    if current_evidence.digest == candidate_evidence.digest:
        return None
    compatibility = "unknown"
    reason = "Compatibility has not been established for this immutable image candidate."
    changelog = "Release notes are unavailable for this exact image candidate."
    changelog_url = ""
    # wrapper-only comparisons cannot establish floating runtime dependency compatibility
    if name in {"ultrafeeder", "piaware", "airspy", "dump978"}:
        repository = _github_repository(candidate_evidence.source)
        if repository and current_evidence.revision and candidate_evidence.revision:
            try:
                wrapper_changes, changelog_url = github_compare(
                    repository,
                    current_evidence.revision,
                    candidate_evidence.revision,
                )
                changelog = f"Wrapper changes only; runtime dependency delta unavailable.\n{wrapper_changes}"
            except (OSError, ValueError, TypeError, HTTPError):
                changelog = (
                    "Wrapper changes only; exact comparison unavailable and runtime dependency delta unavailable."
                )
        reason = "The wrapper and floating runtime dependencies cannot be proven compatible from image metadata."
    elif name == "cloudflared":
        reason = "Cloudflared release history does not support an automatic compatibility claim."
        version = _display_version(candidate_evidence.version, candidate_evidence.digest, candidate_evidence.revision)
        changelog, changelog_url = _cloudflared_notes(version)
    elif name == "proxy":
        current_version = _display_version(current_evidence.version, current_evidence.digest, current_evidence.revision)
        candidate_version = _display_version(
            candidate_evidence.version, candidate_evidence.digest, candidate_evidence.revision
        )
        exact_tag_matches = False
        # bind the mutable stable channel to the exact version tag before any positive verdict
        candidate_release = candidate_evidence.version
        if re.fullmatch(r"\d+\.\d+\.\d+(?:-alpine)?", candidate_release):
            try:
                exact_tag_name = (
                    candidate_release if candidate_release.endswith("-alpine") else f"{candidate_release}-alpine"
                )
                exact_tag = client.resolve(f"nginx:{exact_tag_name}")
                exact_tag_matches = exact_tag.digest == candidate_evidence.digest
            except (OSError, ValueError, TypeError, HTTPError):
                exact_tag_matches = False
        compatibility, reason, changelog, changelog_url = review_nginx_candidate(
            current_version,
            candidate_version,
            current_evidence.revision,
            candidate_evidence.revision,
            current_evidence.base_name,
            candidate_evidence.base_name,
            current_evidence.base_digest,
            candidate_evidence.base_digest,
            exact_tag_matches,
        )
    evidence = {
        "schema_version": 1,
        "current": asdict(current_evidence),
        "candidate": asdict(candidate_evidence),
        "channel": channel,
        "decision": {
            "compatibility": compatibility,
            "reason": reason,
            "changelog_sha256": hashlib.sha256(changelog.encode("utf-8")).hexdigest(),
            "changelog_url": changelog_url,
        },
    }
    return _candidate(
        name=name,
        label=IMAGE_LABELS[name],
        current_version=_display_version(current_evidence.version, current_evidence.digest, current_evidence.revision),
        candidate_version=_display_version(
            candidate_evidence.version, candidate_evidence.digest, candidate_evidence.revision
        ),
        compatibility=compatibility,
        state="available" if compatibility == "compatible" else "held",
        reason=reason,
        changelog=changelog,
        changelog_url=changelog_url,
        kind="image",
        current_target=current,
        candidate_target=candidate_evidence.target,
        evidence=evidence,
    )


# discover one checksum-bound map candidate without executing upstream content
def _map_candidate(deploy: Path) -> dict | None:
    current_manifest = json.loads((deploy / "map-ui.json").read_text(encoding="utf-8"))
    current_commit = current_manifest.get("upstream", {}).get("commit", "")
    raw = _download(
        "https://api.github.com/repos/airplanes-live/tar1090/commits/prod",
        maximum=1024 * 1024,
        hosts=frozenset({"api.github.com"}),
    )
    head = json.loads(raw).get("sha")
    if not isinstance(head, str) or not COMMIT_PATTERN.fullmatch(head):
        raise ValueError("map source commit unavailable")
    # omit the selected exact source commit
    if head == current_commit:
        return None
    archive_url = f"https://codeload.github.com/airplanes-live/tar1090/tar.gz/{head}"
    archive = _download(archive_url, maximum=64 * 1024 * 1024, hosts=frozenset({"codeload.github.com"}))
    technical_reason = ""
    try:
        candidate_manifest = inspect_map_archive(archive, head, current_manifest)
    except (ValueError, TypeError, KeyError):
        candidate_manifest = None
        technical_reason = "The map source changed outside the fixed trusted build and integration gates."
    cache_script = candidate_manifest.get("cachebust", {}).get("script_sha256") if candidate_manifest else ""
    compatibility = "breaking" if head == "ab80a90d253fc0364d8562d25118a148364185f7" else "unknown"
    state = "held"
    reason = (
        "The upstream CARTO basemap removal changes visible map behavior and requires an explicit Install action."
        if compatibility == "breaking"
        else "The map commit changes browser code and has no complete automatic compatibility proof."
    )
    # technically block candidates whose build script is outside the fixed reviewed gate
    if technical_reason or cache_script != TRUSTED_CACHEBUST_SCRIPT_SHA256:
        state = "blocked"
        reason = (
            technical_reason or "The upstream cachebust script changed and is outside the fixed trusted build gate."
        )
    try:
        commit_notes, changelog_url = github_compare("airplanes-live/tar1090", current_commit, head)
        changelog = f"Exact upstream commit comparison:\n{commit_notes}"[:6000]
    except (OSError, ValueError, TypeError, HTTPError):
        changelog = "Exact upstream commit notes are unavailable; review the official comparison."
        changelog_url = f"https://github.com/airplanes-live/tar1090/compare/{current_commit}...{head}"
    evidence = {
        "schema_version": 1,
        "repository": "airplanes-live/tar1090",
        "current_commit": current_commit,
        "candidate_commit": head,
        "archive": map_archive_evidence(archive, head),
        "manifest": candidate_manifest,
        "decision": {
            "compatibility": compatibility,
            "state": state,
            "reason": reason,
            "changelog_sha256": hashlib.sha256(changelog.encode("utf-8")).hexdigest(),
            "changelog_url": changelog_url,
        },
    }
    return _candidate(
        name="map-ui",
        label="Tar1090 map",
        current_version=str(current_manifest.get("tar1090Version", current_commit[:12])),
        candidate_version=head[:12],
        compatibility=compatibility,
        state=state,
        reason=reason,
        changelog=changelog,
        changelog_url=changelog_url,
        kind="map",
        current_target=current_commit,
        candidate_target=head,
        evidence=evidence,
    )


# discover at most the seven fixed application components independently
def discover_candidates(deploy: Path, *, registry: RegistryClient | None = None) -> dict:
    pins = json.loads((deploy / "images.json").read_text(encoding="utf-8"))
    channels = json.loads((deploy / "update-channels.json").read_text(encoding="utf-8"))
    client = registry or RegistryClient()
    candidates = []
    # keep one unavailable upstream from hiding exact candidates for other components
    for name in IMAGE_NAMES:
        try:
            candidate = _image_candidate(name, pins[name], channels[name], client)
            # retain changed exact targets only
            if candidate is not None:
                candidates.append(candidate)
        except (OSError, ValueError, TypeError, KeyError, HTTPError) as error:
            log_lookup_failure(name, error)
    try:
        map_candidate = _map_candidate(deploy)
        # append the fixed seventh component only when its immutable commit changed
        if map_candidate is not None:
            candidates.append(map_candidate)
    except (OSError, ValueError, TypeError, KeyError, HTTPError) as error:
        log_lookup_failure("map", error)
    source_release = str(deploy.parent.resolve())
    candidates.sort(key=lambda candidate: candidate["name"])
    generation = canonical_hash(
        {"source_release": source_release, "candidate_ids": sorted(row["id"] for row in candidates)}
    )
    return {
        "schema_version": 1,
        "generation": generation,
        "source_release": source_release,
        "candidates": candidates[:MAX_UPDATES],
    }


# retain only fields intended for the authenticated admin report
def _public_candidates(store: dict) -> list[dict]:
    public = []
    rows = store.get("candidates") if isinstance(store, dict) else None
    # sanitize every private row independently
    if isinstance(rows, list):
        for row in rows[:MAX_UPDATES]:
            if not isinstance(row, dict) or not HEX64.fullmatch(str(row.get("id", ""))):
                continue
            if row.get("compatibility") not in COMPATIBILITY_STATES or row.get("state") not in UPDATE_STATES:
                continue
            text_fields = {}
            valid = True
            # bound every untrusted display field before publication
            for key, maximum in (
                ("name", 80),
                ("label", 120),
                ("current_version", 160),
                ("candidate_version", 160),
                ("reason", 1000),
                ("changelog", 6000),
            ):
                value = row.get(key)
                if not isinstance(value, str):
                    valid = False
                    break
                cleaned = "".join(
                    character
                    for character in value
                    if ord(character) >= 32 or (key == "changelog" and character in "\n\t")
                )
                encoded = cleaned.encode("utf-8")[:maximum]
                text_fields[key] = encoded.decode("utf-8", errors="ignore")
            if not valid:
                continue
            changelog_url = row.get("changelog_url", "")
            # publish only fixed official https destinations
            if changelog_url:
                parsed = urllib.parse.urlsplit(changelog_url)
                if (
                    parsed.scheme != "https"
                    or parsed.hostname not in CHANGELOG_HOSTS
                    or parsed.username
                    or parsed.password
                    or (parsed.port and parsed.port != 443)
                    or "\\" in changelog_url
                    or any(ord(character) < 32 or ord(character) == 127 for character in changelog_url)
                ):
                    changelog_url = ""
            public.append(
                {
                    "id": row["id"],
                    **text_fields,
                    "compatibility": row["compatibility"],
                    "state": row["state"],
                    "changelog_url": changelog_url,
                }
            )
    return public


# atomically publish root-private JSON before any public report references it
def write_candidate_store(store: dict, path: Path = CANDIDATE_PATH) -> None:
    payload = (json.dumps(store, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_PRIVATE_CANDIDATE_BYTES:
        raise ValueError("private update candidate store exceeds size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix="update-candidates-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        # remove interrupted private publications
        temporary.unlink(missing_ok=True)


# produce a bounded advisory report while preserving every deployment pin
def collect_report(deploy: Path, candidate_store: dict | None = None) -> dict:
    pins = json.loads((deploy / "images.json").read_text())
    channels = json.loads((deploy / "update-channels.json").read_text())
    disk = shutil.disk_usage("/")
    report = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "os_schedule": OS_SCHEDULE,
        "application_policy": APPLICATION_POLICY,
        "reboot_required": Path("/var/run/reboot-required").exists(),
        "disk_free_percent": round(disk.free / disk.total * 100, 1),
        "images": [],
        "map_status": "unknown",
    }
    # attach only a complete private discovery generation
    if (
        isinstance(candidate_store, dict)
        and candidate_store.get("schema_version") == 1
        and HEX64.fullmatch(str(candidate_store.get("generation", "")))
    ):
        updates = _public_candidates(candidate_store)
        held = sorted(
            (row["id"], row["reason"])
            for row in updates
            if row["compatibility"] in {"breaking", "unknown"} and row["state"] in {"held", "blocked"}
        )
        report.update(
            generation=candidate_store["generation"],
            updates=updates,
            notice_id=canonical_hash(held),
            notify=bool(held),
        )
    # keep one failed registry lookup from hiding the other review results
    for name in IMAGE_NAMES:
        reference = channels[name]
        state = "unknown"
        try:
            state = "current" if registry_digest(pins[name]) == registry_digest(reference) else "review"
        except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
            log_lookup_failure(name, error)
        report["images"].append({"name": name, "review_ref": reference, "status": state})
    try:
        report["map_status"] = map_update_status(deploy)
    except (OSError, ValueError, TypeError, KeyError) as error:
        log_lookup_failure("map", error)
    # highlight required review, failed checks, low disk space and pending reboots
    if (
        report["reboot_required"]
        or report["disk_free_percent"] < 15
        or report["map_status"] != "current"
        or any(entry["status"] != "current" for entry in report["images"])
    ):
        report["status"] = "attention"
    return report


# retain only a bounded artifact count or an explicit unavailable value
def _removed_count(value: object) -> int | None:
    # exclude booleans and values outside the report's operational bound
    if type(value) is int and 0 <= value <= MAX_REMOVED_ARTIFACTS:
        return value
    return None


# read only a small regular file without following links or blocking on special files
def _read_report(path: Path, maximum: int = MAX_REPORT_BYTES) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        # reject devices pipes directories and oversized sparse files
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("maintenance report is not a bounded regular file")
        return os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)


# sanitize bounded terminal outcomes separately from current-generation authorization
def _public_installation(path: Path, generation: str, candidate_ids: set[str], *, now: datetime) -> dict:
    idle = {
        "state": "idle",
        "candidate_id": "",
        "candidate_ids": [],
        "request_id": "",
        "message": "",
        "updated_at": "",
    }
    try:
        raw = _read_report(path, 16 * 1024)
        installation = json.loads(raw)
        # require the complete fixed root-written envelope
        if not isinstance(installation, dict) or installation.get("schema_version") != 1:
            return idle
        # require a canonical origin even when reporting an earlier terminal outcome
        if not HEX64.fullmatch(str(installation.get("generation") or "")):
            return idle
        state = installation.get("state")
        candidate_id = installation.get("candidate_id")
        request_id = installation.get("request_id")
        candidate_ids_value = installation.get("candidate_ids")
        message = installation.get("message")
        updated_at = installation.get("updated_at")
        if state not in INSTALLATION_STATES or state == "idle":
            return idle
        if not HEX64.fullmatch(str(candidate_id or "")):
            return idle
        if not HEX64.fullmatch(str(request_id or "")):
            return idle
        if (
            not isinstance(candidate_ids_value, list)
            or not candidate_ids_value
            or len(candidate_ids_value) > MAX_UPDATES
        ):
            return idle
        # bind every unique batch member and the primary identity to this report
        if (
            any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in candidate_ids_value)
            or len(set(candidate_ids_value)) != len(candidate_ids_value)
            or candidate_id not in candidate_ids_value
        ):
            return idle
        if (
            not isinstance(message, str)
            or len(message) > 1000
            or not isinstance(updated_at, str)
            or len(updated_at) > 40
        ):
            return idle
        stamp = datetime.fromisoformat(updated_at)
        # expire terminal notices without weakening the root worker's durable retry fence
        if stamp.tzinfo is None or not 0 <= (now - stamp).total_seconds() <= INSTALLATION_OUTCOME_TTL_SECONDS:
            return idle
        # in-progress state still requires every exact candidate in the displayed generation
        if state not in TERMINAL_INSTALLATION_STATES and (
            installation["generation"] != generation or not set(candidate_ids_value) <= candidate_ids
        ):
            return idle
        return {
            "state": state,
            "candidate_id": candidate_id,
            "candidate_ids": sorted(candidate_ids_value),
            "request_id": request_id,
            "message": message,
            "updated_at": updated_at,
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        return idle


# expose only expected maintenance fields through the authenticated api
def public_report(
    path: Path = REPORT_PATH,
    *,
    installation_path: Path = INSTALLATION_PATH,
    now: datetime | None = None,
) -> dict:
    result = {
        "updated_at": "",
        "status": "unknown",
        "os_schedule": OS_SCHEDULE,
        "application_policy": APPLICATION_POLICY,
        "reboot_required": None,
        "disk_free_percent": None,
        "images": [],
        "map_status": "unknown",
        "removed_expired_artifacts": None,
    }
    try:
        raw = _read_report(path)
        # reject oversized or nonobject documents
        if len(raw) > MAX_REPORT_BYTES:
            return result
        report = json.loads(raw)
        # reject malformed report envelopes
        if not isinstance(report, dict):
            return result
        stamp = datetime.fromisoformat(report["updated_at"])
        current_time = now or datetime.now(timezone.utc)
        # treat future and older-than-eight-day review results as unknown
        if stamp.tzinfo is None or not 0 <= (current_time - stamp).total_seconds() <= 8 * 86400:
            return result
        result["updated_at"] = stamp.isoformat()
        result["status"] = report["status"] if report.get("status") in {"ok", "attention", "failed"} else "unknown"
        # retain only explicit boolean reboot evidence
        if isinstance(report.get("reboot_required"), bool):
            result["reboot_required"] = report["reboot_required"]
        free = report.get("disk_free_percent")
        # reject booleans and nonfinite or out-of-range disk observations
        if type(free) in (int, float) and 0 <= free <= 100:
            result["disk_free_percent"] = free
        result["map_status"] = (
            report.get("map_status") if report.get("map_status") in {"current", "review"} else "unknown"
        )
        result["removed_expired_artifacts"] = _removed_count(report.get("removed_expired_artifacts"))
        entries = report.get("images")
        # sanitize image rows rather than returning arbitrary root-file fields
        if isinstance(entries, list):
            # cap rows to the fixed deployed image roles
            for row in entries[: len(IMAGE_NAMES)]:
                # accept only known roles and short registry references
                if not isinstance(row, dict) or row.get("name") not in IMAGE_NAMES:
                    continue
                reference = row.get("review_ref")
                # omit malformed references and unrecognized states
                if not isinstance(reference, str) or not re.fullmatch(r"[a-z0-9./:_-]{1,200}", reference):
                    continue
                state = row.get("status")
                result["images"].append(
                    {
                        "name": row["name"],
                        "review_ref": reference,
                        "status": state if state in {"current", "review"} else "unknown",
                    }
                )
        generation = report.get("generation")
        update_rows = report.get("updates")
        # activate the new update contract only for one complete generation
        if HEX64.fullmatch(str(generation or "")) and isinstance(update_rows, list) and len(update_rows) <= MAX_UPDATES:
            updates = _public_candidates({"candidates": update_rows})
            # reject partial sanitization rather than hiding malformed root data
            if len(updates) == len(update_rows):
                candidate_ids = {row["id"] for row in updates}
                result.update(
                    generation=generation,
                    updates=updates,
                    installation=_public_installation(installation_path, generation, candidate_ids, now=current_time),
                )
                notice_id = report.get("notice_id")
                notify = report.get("notify")
                # expose optional notification intent only as one complete pair
                if HEX64.fullmatch(str(notice_id or "")) and isinstance(notify, bool):
                    result.update(notice_id=notice_id, notify=notify)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        result["status"] = "unknown"
        return result
    # accept failure only from the fixed unavailable-evidence envelope
    if result["status"] == "failed":
        failure_fields = {
            "reboot_required": None,
            "disk_free_percent": None,
            "images": [],
            "map_status": "unknown",
        }
        consistent = all(key in report and report[key] == value for key, value in failure_fields.items())
        # reject contradictory evidence and invalid optional removal counts
        if not consistent or (
            report.get("removed_expired_artifacts") is not None and result["removed_expired_artifacts"] is None
        ):
            result["status"] = "unknown"
    # require one complete and consistent observation set before displaying success
    if result["status"] == "ok":
        names = [row["name"] for row in result["images"]]
        complete = (
            len(names) == len(IMAGE_NAMES)
            and set(names) == set(IMAGE_NAMES)
            and result["reboot_required"] is not None
            and result["disk_free_percent"] is not None
            and result["map_status"] != "unknown"
            and all(row["status"] != "unknown" for row in result["images"])
        )
        # incomplete evidence cannot establish a successful weekly check
        if not complete:
            result["status"] = "unknown"
        elif (
            result["reboot_required"]
            or result["disk_free_percent"] < 15
            or result["map_status"] != "current"
            or any(row["status"] != "current" for row in result["images"])
        ):
            result["status"] = "attention"
    # keep the encoded response inside the authenticated endpoint budget
    if "updates" in result:
        while len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_REPORT_BYTES:
            longest = max(result["updates"], key=lambda row: len(row["changelog"]), default=None)
            # fail closed if fixed fields alone exceed the budget
            if longest is None or not longest["changelog"]:
                result.pop("generation", None)
                result.pop("updates", None)
                result.pop("installation", None)
                result.pop("notice_id", None)
                result.pop("notify", None)
                break
            longest["changelog"] = longest["changelog"][: max(0, len(longest["changelog"]) * 3 // 4)]
    return result


# create a failure report without copying exception or upstream text
def _failure_report(removed_count: int | None, *, now: datetime | None = None) -> dict:
    return {
        "updated_at": (now or datetime.now(timezone.utc)).isoformat(),
        "status": "failed",
        "os_schedule": OS_SCHEDULE,
        "application_policy": APPLICATION_POLICY,
        "reboot_required": None,
        "disk_free_percent": None,
        "images": [],
        "map_status": "unknown",
        "removed_expired_artifacts": _removed_count(removed_count),
    }


# atomically publish one private maintenance observation
def _write_report(report: dict, path: Path | None = None) -> None:
    target = path or REPORT_PATH
    temporary = None
    payload = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("maintenance report exceeds size limit")
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent, prefix="maintenance-", delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), 0o640)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        # remove an unpublished temporary report after interrupted writes
        if temporary is not None:
            temporary.unlink(missing_ok=True)


# recognize only installer-created release names
def release_time(name: str) -> datetime | None:
    match = RELEASE_NAME.fullmatch(name)
    # leave unfamiliar artifacts under operator control
    if not match:
        return None
    try:
        return datetime.strptime(match[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# prune expired artifacts without deleting selected or recent rollback releases
def prune_releases(application: Path, runtime: Path, *, now: datetime | None = None) -> list[str]:
    current_time = now or datetime.now(timezone.utc)
    cutoff = current_time - timedelta(days=RETENTION_DAYS)
    releases = application / "releases"
    maps = application / "map-ui-releases"
    current = application / "current"
    # fail closed if release provenance is missing or points outside its root
    if (
        not current.is_symlink()
        or not current.resolve().is_dir()
        or current.resolve().parent != releases.resolve()
        or releases.is_symlink()
        or maps.is_symlink()
        or not maps.is_dir()
    ):
        raise ValueError("selected application release is not a managed release")
    entries = []
    # ignore symlinks and names not created by the installer
    for path in releases.iterdir():
        stamp = release_time(path.name)
        # collect only real managed directories
        if stamp is not None and path.is_dir() and not path.is_symlink():
            entries.append((stamp, path))
    entries.sort(reverse=True)
    protected = {current.resolve(), *(path.resolve() for _, path in entries[:2])}
    removed = []
    # keep the active release and at least two newest rollback candidates
    for stamp, path in entries:
        # delete only expired unselected application trees
        if stamp < cutoff and path.resolve() not in protected:
            shutil.rmtree(path)
            removed.append(str(path))
    protected_maps = {(application / "map-ui").resolve()}
    # preserve map assets referenced by every retained application tree
    for path in releases.iterdir():
        map_link = path / "map-ui"
        # only interpret explicit release map symlinks
        if path.is_dir() and not path.is_symlink() and map_link.is_symlink():
            protected_maps.add(map_link.resolve())
    # prune only expired maps with no retained application references
    for path in maps.iterdir():
        stamp = release_time(path.name)
        # reject links and retain selected or referenced map releases
        if (
            stamp is not None
            and stamp < cutoff
            and path.is_dir()
            and not path.is_symlink()
            and path.resolve() not in protected_maps
        ):
            shutil.rmtree(path)
            removed.append(str(path))
    # expire only installer-owned code archives rather than private runtime files
    for path in runtime.glob("code-*.tar.gz"):
        stamp = release_time(path.name.removeprefix("code-").removesuffix(".tar.gz"))
        # preserve recent archives and anything with unexpected filesystem type
        if stamp is not None and stamp < cutoff and path.is_file() and not path.is_symlink():
            path.unlink()
            removed.append(str(path))
    return removed


# run only the fixed receiver maintenance operations
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-only", action="store_true", help="review upstream metadata without deleting old releases"
    )
    args = parser.parse_args()
    # prevent accidental unprivileged writes to the private operational report
    if os.geteuid() != 0:
        raise SystemExit("root execution required")
    removed_count = 0 if args.report_only else None
    try:
        # keep verification runs nondestructive
        if not args.report_only:
            removed = prune_releases(Path("/opt/adsb"), Path("/var/lib/adsb/runtime"))
            removed_count = min(len(removed), MAX_REMOVED_ARTIFACTS)
        deploy = Path(__file__).resolve().parents[1] / "deploy"
        candidate_store = discover_candidates(deploy)
        # publish root-private authorization evidence before its public projection
        write_candidate_store(candidate_store)
        report = collect_report(deploy, candidate_store)
        report["removed_expired_artifacts"] = removed_count
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, RecursionError):
        # publish only a fixed envelope before returning a failed service result
        report = _failure_report(removed_count)
        _write_report(report)
        print(json.dumps(report))
        raise SystemExit(1) from None
    _write_report(report)
    print(json.dumps(report))


# support an isolated systemd interpreter without importing application code
if __name__ == "__main__":
    main()
