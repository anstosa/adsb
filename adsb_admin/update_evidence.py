"""Fail-closed upstream evidence for immutable ADS-B update candidates."""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError

DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")
MAX_METADATA_BYTES = 1024 * 1024
MAX_CHANGELOG_BYTES = 6000
REGISTRY_HOSTS = frozenset({"ghcr.io", "registry-1.docker.io"})
TOKEN_HOSTS = frozenset({"ghcr.io", "auth.docker.io"})
GITHUB_HOSTS = frozenset({"api.github.com", "codeload.github.com"})
DOCUMENTATION_HOSTS = frozenset({"nginx.org", "docs.nginx.com", "developers.cloudflare.com"})
DOCKER_BLOB_HOSTS = frozenset({"production.cloudflare.docker.com", "production.cloudfront.docker.com"})
GHCR_BLOB_HOSTS = frozenset({"pkg-containers.githubusercontent.com"})
TRUSTED_CACHEBUST_SCRIPT_SHA256 = "eea2c14191ec4a32dd4d3548148e7455de3ac55f2ab3018f416b884a62454f99"
TRUSTED_CACHEBUST_LIST_SHA256 = "71a9714220b443457a1a0dacae12d5916adcc5e7ab9ad29f9b80d5a38931d9f0"
MEDIA_TYPES = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


@dataclass(frozen=True, kw_only=True, slots=True)
class ImageEvidence:
    """Exact target and bounded OCI metadata for one linux/amd64 image."""

    target: str
    digest: str
    config_digest: str
    config_size: int
    version: str
    revision: str
    source: str
    base_name: str
    base_digest: str


# hash canonical data without display timestamps
def canonical_hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# coalesce one verified OCI metadata field while rejecting disagreement
def _oci_metadata_value(
    key: str,
    sources: tuple[object, ...],
    *,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    values: set[str] = set()
    # inspect labels and every digest-bound annotation layer
    for source in sources:
        if source is None:
            continue
        if not isinstance(source, dict):
            return ""
        value = source.get(key)
        if value is None or value == "":
            continue
        if not isinstance(value, str) or len(value) > maximum or (pattern is not None and not pattern.fullmatch(value)):
            return ""
        values.add(value)
    # accept exactly one nonconflicting metadata value
    if len(values) != 1:
        return ""
    return values.pop()


# parse one supported registry reference into an immutable request target
def parse_image_reference(reference: str) -> tuple[str, str, str]:
    if not isinstance(reference, str) or not reference or any(character.isspace() for character in reference):
        raise ValueError("invalid image reference")
    name, separator, target = reference.rpartition("@")
    # retain digest references before considering mutable tags
    if separator:
        repository = name
        selector = target
    else:
        repository, tag_separator, tag = reference.rpartition(":")
        # distinguish a tag from the registry port syntax
        if not tag_separator or "/" in tag:
            repository = reference
            selector = "latest"
        else:
            selector = tag
    parts = repository.split("/", 1)
    # normalize Docker Hub shorthand without accepting arbitrary registries
    if len(parts) == 1 or "." not in parts[0]:
        host = "registry-1.docker.io"
        path = repository if "/" in repository else f"library/{repository}"
    else:
        host, path = parts
        host = "registry-1.docker.io" if host in {"docker.io", "index.docker.io"} else host
    if host not in REGISTRY_HOSTS or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,199}", path):
        raise ValueError("unsupported image registry")
    if not (DIGEST_PATTERN.fullmatch(selector) or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}", selector)):
        raise ValueError("invalid image selector")
    return host, path, selector


# allow redirects only inside the fixed upstream host set
class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    # validate each redirect before urllib follows it
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        # reject credentials downgrade controls nonstandard ports and ambiguous separators
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or (parsed.port and parsed.port != 443)
            or "\\" in new_url
            or any(ord(character) < 32 or ord(character) == 127 for character in new_url)
        ):
            raise ValueError("unsafe upstream redirect")
        old_url = urllib.parse.urlsplit(request.full_url)
        immutable_blob = re.search(r"/blobs/sha256:[a-f0-9]{64}$", old_url.path) is not None
        blob_redirect = immutable_blob and (
            (old_url.hostname == "registry-1.docker.io" and parsed.hostname in DOCKER_BLOB_HOSTS)
            or (old_url.hostname == "ghcr.io" and parsed.hostname in GHCR_BLOB_HOSTS)
        )
        if (
            parsed.hostname not in REGISTRY_HOSTS | TOKEN_HOSTS | GITHUB_HOSTS | DOCUMENTATION_HOSTS
            and not blob_redirect
        ):
            raise ValueError("unsafe upstream redirect")
        redirected = super().redirect_request(request, file_pointer, code, message, headers, new_url)
        # never forward a registry bearer token to another host
        if redirected is not None and old_url.hostname != parsed.hostname:
            redirected.remove_header("Authorization")
        return redirected


# read one bounded response and optionally bind its descriptor bytes
def _read_response(response, *, expected_digest: str = "", expected_size: int | None = None) -> bytes:
    raw = response.read(MAX_METADATA_BYTES + 1)
    # reject oversized metadata before parsing
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("upstream metadata exceeds size limit")
    # bind exact descriptor sizes when the parent manifest provides one
    if expected_size is not None and len(raw) != expected_size:
        raise ValueError("descriptor size mismatch")
    # bind downloaded bytes to their immutable descriptor
    if expected_digest and "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError("descriptor digest mismatch")
    return raw


# decode one bounded JSON response
def _json_response(response, *, expected_digest: str = "", expected_size: int | None = None) -> dict:
    value = json.loads(_read_response(response, expected_digest=expected_digest, expected_size=expected_size))
    # require an object at every OCI and GitHub boundary
    if not isinstance(value, dict):
        raise ValueError("upstream metadata is not an object")
    return value


class RegistryClient:
    """Minimal OCI distribution client with bounded bearer authentication."""

    # construct one client with an injectable no-cookie opener
    def __init__(self, opener=None) -> None:
        self.opener = opener or urllib.request.build_opener(_SafeRedirectHandler())

    # perform one registry request with a bounded bearer challenge retry
    def _open(self, url: str, headers: dict[str, str]):
        request = urllib.request.Request(url, headers=headers)
        try:
            return self.opener.open(request, timeout=15)
        except HTTPError as error:
            # retry only one explicit bearer challenge
            if error.code != 401:
                raise
            challenge = error.headers.get("WWW-Authenticate", "")
            error.close()
            match = re.fullmatch(r'Bearer realm="([^"]+)",service="([^"]+)",scope="([^"]+)"', challenge)
            if not match:
                raise ValueError("unsupported registry authentication challenge") from None
            realm, service, scope = match.groups()
            parsed = urllib.parse.urlsplit(realm)
            # keep credentials inside the fixed registry token boundary
            if (
                parsed.scheme != "https"
                or parsed.hostname not in TOKEN_HOSTS
                or parsed.username
                or parsed.password
                or (parsed.port and parsed.port != 443)
                or "\\" in realm
                or any(ord(character) < 32 or ord(character) == 127 for character in realm)
            ):
                raise ValueError("unsupported registry token endpoint")
            request_path = urllib.parse.urlsplit(url).path
            repository_match = re.match(r"^/v2/(.+)/(?:manifests|blobs)/", request_path)
            if not repository_match or scope != f"repository:{repository_match.group(1)}:pull":
                raise ValueError("registry token scope is not the requested repository")
            if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,200}", service):
                raise ValueError("registry token service is invalid")
            query = urllib.parse.urlencode({"service": service, "scope": scope})
            separator = "&" if parsed.query else "?"
            with self.opener.open(urllib.request.Request(realm + separator + query), timeout=15) as token_response:
                token_document = _json_response(token_response)
            token = token_document.get("token") or token_document.get("access_token")
            if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,8192}", token):
                raise ValueError("registry token unavailable")
            authorized = {**headers, "Authorization": f"Bearer {token}"}
            return self.opener.open(urllib.request.Request(url, headers=authorized), timeout=15)

    # fetch one exact OCI JSON descriptor
    def _document(
        self,
        host: str,
        path: str,
        kind: str,
        selector: str,
        *,
        expected_digest: str = "",
        expected_size: int | None = None,
    ) -> tuple[dict, bytes, object]:
        encoded_selector = urllib.parse.quote(selector, safe=":")
        url = f"https://{host}/v2/{path}/{kind}/{encoded_selector}"
        headers = {"Accept": MEDIA_TYPES, "User-Agent": "adsb-update-evidence/1"}
        response = self._open(url, headers)
        with response:
            raw = _read_response(response, expected_digest=expected_digest, expected_size=expected_size)
            response_headers = response.headers
        document = json.loads(raw)
        # accept only object descriptors
        if not isinstance(document, dict):
            raise ValueError("OCI descriptor is not an object")
        return document, raw, response_headers

    # resolve one tag or digest to an exact unique linux/amd64 manifest and config
    def resolve(self, reference: str) -> ImageEvidence:
        host, path, selector = parse_image_reference(reference)
        root, root_raw, root_headers = self._document(
            host,
            path,
            "manifests",
            selector,
            expected_digest=selector if DIGEST_PATTERN.fullmatch(selector) else "",
        )
        root_digest = root_headers.get("Docker-Content-Digest", "")
        computed_root_digest = "sha256:" + hashlib.sha256(root_raw).hexdigest()
        # bind both digest selectors and mutable tags to the registry's exact response bytes
        if not DIGEST_PATTERN.fullmatch(root_digest or "") or root_digest != computed_root_digest:
            raise ValueError("manifest response digest mismatch")
        media_type = root.get("mediaType") or root_headers.get("Content-Type", "").split(";", 1)[0]
        manifest = root
        manifest_raw = root_raw
        manifest_digest = root_digest
        selected: dict = {}
        # select exactly one receiver-platform descriptor from a multi-platform index
        if media_type in {
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        }:
            descriptors = root.get("manifests")
            matches = []
            # inspect every advertised platform descriptor
            if isinstance(descriptors, list):
                for descriptor in descriptors:
                    platform = descriptor.get("platform") if isinstance(descriptor, dict) else None
                    # retain only complete linux/amd64 records
                    if (
                        isinstance(platform, dict)
                        and platform.get("os") == "linux"
                        and platform.get("architecture") == "amd64"
                    ):
                        matches.append(descriptor)
            if len(matches) != 1:
                raise ValueError("no unique linux/amd64 manifest")
            selected = matches[0]
            digest = selected.get("digest")
            size = selected.get("size")
            if (
                not DIGEST_PATTERN.fullmatch(digest or "")
                or type(size) is not int
                or not 0 < size <= MAX_METADATA_BYTES
            ):
                raise ValueError("invalid linux/amd64 descriptor")
            manifest, manifest_raw, manifest_headers = self._document(
                host,
                path,
                "manifests",
                digest,
                expected_digest=digest,
                expected_size=size,
            )
            manifest_digest = manifest_headers.get("Docker-Content-Digest", "") or digest
        # derive the immutable manifest digest from verified response bytes when absent
        computed_manifest_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
        if manifest_digest and manifest_digest != computed_manifest_digest:
            raise ValueError("manifest response digest mismatch")
        manifest_digest = computed_manifest_digest
        config = manifest.get("config")
        if not isinstance(config, dict):
            raise ValueError("image config descriptor unavailable")
        config_digest = config.get("digest")
        config_size = config.get("size")
        if (
            not DIGEST_PATTERN.fullmatch(config_digest or "")
            or type(config_size) is not int
            or not 0 < config_size <= MAX_METADATA_BYTES
        ):
            raise ValueError("invalid image config descriptor")
        config_document, _, _ = self._document(
            host,
            path,
            "blobs",
            config_digest,
            expected_digest=config_digest,
            expected_size=config_size,
        )
        # require the direct manifest config to confirm the receiver platform
        if config_document.get("os") != "linux" or config_document.get("architecture") != "amd64":
            raise ValueError("image config is not linux/amd64")
        labels = config_document.get("config", {}).get("Labels", {})
        labels = labels if isinstance(labels, dict) else {}
        sources = (
            labels,
            root.get("annotations"),
            selected.get("annotations"),
            manifest.get("annotations"),
        )
        version = _oci_metadata_value(
            "org.opencontainers.image.version",
            sources,
            maximum=80,
            pattern=VERSION_PATTERN,
        )
        revision = _oci_metadata_value(
            "org.opencontainers.image.revision",
            sources,
            maximum=40,
            pattern=COMMIT_PATTERN,
        )
        source = _oci_metadata_value("org.opencontainers.image.source", sources, maximum=300)
        base_name = _oci_metadata_value(
            "org.opencontainers.image.base.name",
            sources,
            maximum=200,
            pattern=re.compile(r"^[A-Za-z0-9][A-Za-z0-9./:@_-]{0,199}$"),
        )
        base_digest = _oci_metadata_value(
            "org.opencontainers.image.base.digest",
            sources,
            maximum=71,
            pattern=DIGEST_PATTERN,
        )
        target_host = "docker.io" if host == "registry-1.docker.io" else host
        return ImageEvidence(
            target=f"{target_host}/{path}@{manifest_digest}",
            digest=manifest_digest,
            config_digest=config_digest,
            config_size=config_size,
            version=version,
            revision=revision,
            source=source,
            base_name=base_name,
            base_digest=base_digest,
        )


# fetch one exact bounded GitHub commit comparison
def github_compare(repository: str, base: str, head: str, *, opener=None) -> tuple[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository):
        raise ValueError("invalid GitHub repository")
    if not COMMIT_PATTERN.fullmatch(base) or not COMMIT_PATTERN.fullmatch(head):
        raise ValueError("invalid GitHub comparison commit")
    client = opener or urllib.request.build_opener(_SafeRedirectHandler())
    url = f"https://api.github.com/repos/{repository}/compare/{base}...{head}"
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "adsb-update-evidence/1"}
    )
    with client.open(request, timeout=15) as response:
        document = _json_response(response)
    commits = document.get("commits")
    total_commits = document.get("total_commits")
    if (
        document.get("status") != "ahead"
        or type(total_commits) is not int
        or not 0 < total_commits <= 100
        or not isinstance(commits, list)
        or len(commits) != total_commits
    ):
        raise ValueError("GitHub comparison exceeds commit limit")
    lines = []
    # retain only first-line commit summaries from the exact comparison
    for commit in commits:
        message = commit.get("commit", {}).get("message", "") if isinstance(commit, dict) else ""
        if isinstance(message, str) and message:
            lines.append(message.splitlines()[0][:240])
    changelog = (
        "\n".join(lines)[:MAX_CHANGELOG_BYTES]
        or "Wrapper changes are available; runtime dependency changes are unavailable."
    )
    return changelog, f"https://github.com/{repository}/compare/{base}...{head}"


# obtain exhaustive positive evidence for one official NGINX image patch
def review_nginx_candidate(
    current_version: str,
    candidate_version: str,
    current_revision: str,
    candidate_revision: str,
    current_base_name: str,
    candidate_base_name: str,
    current_base_digest: str,
    candidate_base_digest: str,
    exact_tag_matches: bool,
    *,
    opener=None,
) -> tuple[str, str, str, str]:
    version = re.fullmatch(r"(\d+)\.(\d+)\.\d+(?:-[A-Za-z0-9._-]+)?", candidate_version)
    if (
        not version
        or not COMMIT_PATTERN.fullmatch(current_revision)
        or not COMMIT_PATTERN.fullmatch(candidate_revision)
    ):
        return (
            "unknown",
            "Exact official NGINX changelog or image-wrapper revisions are unavailable.",
            "Changelog unavailable.",
            "",
        )
    client = opener or urllib.request.build_opener(_SafeRedirectHandler())
    branch = f"{version.group(1)}.{version.group(2)}"
    changes_url = f"https://nginx.org/en/CHANGES-{branch}"
    with client.open(
        urllib.request.Request(changes_url, headers={"User-Agent": "adsb-update-evidence/1"}), timeout=15
    ) as response:
        raw_changes = _read_response(response)
    changes = raw_changes.decode("utf-8", errors="strict")
    marker = f"Changes with nginx {candidate_version.split('-', 1)[0]}"
    start = changes.find(marker)
    # require one exact candidate section bounded by the next release heading
    if start < 0 or changes.find(marker, start + 1) >= 0:
        return (
            "unknown",
            "The exact candidate section is absent from the official NGINX changelog.",
            "Changelog unavailable.",
            changes_url,
        )
    end = changes.find("Changes with nginx ", start + len(marker))
    section = changes[start : end if end >= 0 else len(changes)].strip()
    compare_url = f"https://api.github.com/repos/nginx/docker-nginx/compare/{current_revision}...{candidate_revision}"
    with client.open(
        urllib.request.Request(
            compare_url, headers={"Accept": "application/vnd.github+json", "User-Agent": "adsb-update-evidence/1"}
        ),
        timeout=15,
    ) as response:
        comparison = _json_response(response)
    files = comparison.get("files")
    commits = comparison.get("commits")
    total_commits = comparison.get("total_commits")
    if (
        comparison.get("status") != "ahead"
        or type(total_commits) is not int
        or not 0 < total_commits <= 100
        or not isinstance(commits, list)
        or len(commits) != total_commits
        or not isinstance(files, list)
        or len(files) > 100
    ):
        return (
            "unknown",
            "The official image-wrapper comparison is incomplete or oversized.",
            section[:MAX_CHANGELOG_BYTES],
            changes_url,
        )
    changes = []
    # retain bounded changed filenames and exact patch lines for the compatibility gate
    for file_entry in files:
        filename = file_entry.get("filename") if isinstance(file_entry, dict) else None
        patch = file_entry.get("patch") if isinstance(file_entry, dict) else None
        if not isinstance(filename, str) or len(filename) > 240 or not isinstance(patch, str) or len(patch) > 100000:
            return (
                "unknown",
                "The official image-wrapper comparison contains an invalid path.",
                section[:MAX_CHANGELOG_BYTES],
                changes_url,
            )
        changes.append({"path": filename, "patch": patch})
    compatibility, reason = nginx_patch_compatibility(
        current_version,
        candidate_version,
        section,
        changes,
        current_base_name=current_base_name,
        candidate_base_name=candidate_base_name,
        current_base_digest=current_base_digest,
        candidate_base_digest=candidate_base_digest,
        exact_tag_matches=exact_tag_matches,
    )
    return compatibility, reason, section[:MAX_CHANGELOG_BYTES], changes_url


# classify one NGINX stable patch only from exhaustive positive evidence
def nginx_patch_compatibility(
    current_version: str,
    candidate_version: str,
    changes_text: str,
    docker_changes: list[dict[str, str]],
    *,
    current_base_name: str,
    candidate_base_name: str,
    current_base_digest: str,
    candidate_base_digest: str,
    exact_tag_matches: bool,
) -> tuple[str, str]:
    version = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z0-9._-]+))?$")
    current = version.fullmatch(current_version)
    candidate = version.fullmatch(candidate_version)
    # require a same-stable-branch patch increment and unchanged variant
    if (
        not current
        or not candidate
        or current.groups()[:2] != candidate.groups()[:2]
        or current.group(4) != candidate.group(4)
    ):
        return "unknown", "The candidate is not a same-branch NGINX patch with the same image variant."
    if int(candidate.group(3)) != int(current.group(3)) + 1:
        return "unknown", "The candidate is not the immediately following NGINX patch."
    if not exact_tag_matches:
        return "unknown", "The mutable channel digest does not match the exact version tag digest."
    if not current_base_name or current_base_name != candidate_base_name:
        return "unknown", "The candidate base-image identity is unavailable or changed."
    if not DIGEST_PATTERN.fullmatch(current_base_digest) or current_base_digest != candidate_base_digest:
        return "unknown", "The candidate base-image digest is unavailable or changed."
    # allow only generated version and checksum files in the official image wrapper
    allowed_paths = re.compile(r"^(?:stable/)?alpine(?:-slim)?/(?:Dockerfile|versions\.json|checksums\.txt)$")
    if not docker_changes or any(not allowed_paths.fullmatch(change.get("path", "")) for change in docker_changes):
        return "unknown", "The official image wrapper includes packaging or build-logic changes."
    allowed_line = re.compile(
        r"^(?:(?:ENV|ARG)\s+(?:NGINX_VERSION|NJS_VERSION|PKG_RELEASE)(?:=|\s+)[0-9][0-9A-Za-z.+~_-]{0,40}|"
        r'"(?:nginx|njs|checksum|sha256)"\s*:\s*"[A-Za-z0-9._:+/-]+"[,]?|'
        r"[a-f0-9]{64,128}\s+\S+)$",
        re.IGNORECASE,
    )
    # inspect every added and removed patch line rather than trusting its filename
    for change in docker_changes:
        for line in change["patch"].splitlines():
            if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
                continue
            if not allowed_line.fullmatch(line[1:].strip()):
                return "unknown", "The official image wrapper changes executable packaging logic."
    item_count = len(re.findall(r"^\s*\*\)", changes_text, flags=re.MULTILINE))
    categories = re.findall(r"^\s*\*\)\s*([^:]+):", changes_text, flags=re.MULTILINE)
    # require an exhaustive nonempty list containing only Security or Bugfix entries
    if (
        not categories
        or len(categories) != item_count
        or any(category.strip().lower() not in {"security", "bugfix"} for category in categories)
    ):
        return "unknown", "The NGINX changelog is not exhaustively limited to Security and Bugfix entries."
    return (
        "compatible",
        "Same-branch stable patch with only Security/Bugfix entries and generated image metadata changes.",
    )


# build immutable map archive evidence without extracting untrusted content
def map_archive_evidence(archive: bytes, commit: str) -> dict:
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ValueError("invalid map commit")
    if not archive or len(archive) > 64 * 1024 * 1024:
        raise ValueError("map archive size is invalid")
    return {
        "commit": commit,
        "archive_url": f"https://codeload.github.com/airplanes-live/tar1090/tar.gz/{commit}",
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "archive_size_bytes": len(archive),
        "archive_filename": f"airplanes-live-tar1090-{commit[:7]}.tar.gz",
        "source_root": f"tar1090-{commit}",
    }


# derive an exact next map manifest from one checksum-bound source archive
def inspect_map_archive(archive: bytes, commit: str, current_manifest: dict) -> dict:
    evidence = map_archive_evidence(archive, commit)
    source_root = evidence["source_root"]
    required = {
        f"{source_root}/html/ui2.js": "ui2.js",
        f"{source_root}/html/ui2.css": "ui2.css",
        f"{source_root}/html/index.html": "index.html",
        f"{source_root}/html/early.js": "early.js",
        f"{source_root}/cachebust.sh": "cachebust.sh",
        f"{source_root}/cachebust.list": "cachebust.list",
        f"{source_root}/LICENSE": "LICENSE",
    }
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        member_count = 0
        uncompressed_bytes = 0
        # stream archive headers while bounding both member count and declared expansion
        for member in source:
            member_count += 1
            uncompressed_bytes += member.size
            if member_count > 20000 or uncompressed_bytes > 256 * 1024 * 1024:
                raise ValueError("map archive expansion exceeds size limit")
            parts = Path(member.name).parts
            # reject paths links and special entries even though nothing is extracted
            if not parts or parts[0] != source_root or ".." in parts or member.issym() or member.islnk():
                raise ValueError("map archive contains an unsafe member")
            if not (member.isdir() or member.isfile()):
                raise ValueError("map archive contains a special member")
            # retain only the exact small files needed for build evidence
            if member.name in required:
                if member.size > MAX_METADATA_BYTES:
                    raise ValueError("map evidence file exceeds size limit")
                extracted = source.extractfile(member)
                if extracted is None:
                    raise ValueError("map evidence file is unavailable")
                contents[required[member.name]] = extracted.read(MAX_METADATA_BYTES + 1)
        if member_count == 0:
            raise ValueError("map archive is empty")
    if set(contents) != set(required.values()):
        raise ValueError("map archive evidence is incomplete")
    manifest = json.loads(json.dumps(current_manifest))
    upstream = manifest.get("upstream")
    current_cachebust = manifest.get("cachebust")
    # require the existing fixed manifest structure before deriving a candidate
    if (
        not isinstance(upstream, dict)
        or not isinstance(manifest.get("assets"), dict)
        or not isinstance(current_cachebust, dict)
        or current_cachebust.get("list_sha256") != TRUSTED_CACHEBUST_LIST_SHA256
    ):
        raise ValueError("current map manifest is invalid")
    candidate_list_sha256 = hashlib.sha256(contents["cachebust.list"]).hexdigest()
    # never feed a changed upstream filename list to the root-run cachebuster
    if candidate_list_sha256 != TRUSTED_CACHEBUST_LIST_SHA256:
        raise ValueError("map cachebust list changed outside the trusted gate")
    upstream.update(evidence)
    upstream["version"] = commit[:12]
    manifest["tar1090Version"] = f"candidate-{commit[:12]}"
    # bind the two generated browser assets and their deterministic cache names
    for name in ("ui2.js", "ui2.css"):
        manifest["assets"][name] = {
            "sha256": hashlib.sha256(contents[name]).hexdigest(),
            "md5": hashlib.md5(contents[name], usedforsecurity=False).hexdigest(),
        }
    manifest["cachebust"] = {
        "script_sha256": hashlib.sha256(contents["cachebust.sh"]).hexdigest(),
        "list_sha256": candidate_list_sha256,
    }
    index = contents["index.html"].decode("utf-8", errors="strict")
    early = contents["early.js"].decode("utf-8", errors="strict")
    patches = manifest.get("local_patches")
    # preflight every fixed prepare-map marker so technical drift is blocked at discovery
    if not isinstance(patches, list) or len(patches) != 1 or not isinstance(patches[0].get("source"), str):
        raise ValueError("map local patch contract is invalid")
    markers = (
        'let databaseFolder = "https://static.airplanes.live/db";',
        '<link rel="icon" type="image/png" href="images/tar1090-favicon.png">',
        "<title>tar1090</title>",
        "</head>",
        '<div id="sidebar_canvas">',
    )
    if any(index.count(marker) != 1 for marker in markers) or early.count(patches[0]["source"]) != 1:
        raise ValueError("map integration marker changed")
    return manifest
