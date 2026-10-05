"""Bounded maintenance for the receiver's immutable releases."""

import argparse
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

RELEASE_NAME = re.compile(r"^(\d{8}T\d{6}Z)-\d+$")
RETENTION_DAYS = 30
REPORT_PATH = Path("/var/lib/adsb/status/maintenance.json")
OS_SCHEDULE = "Tuesdays 04:00 America/Los_Angeles"
APPLICATION_POLICY = "Pinned releases; updates require review"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMAGE_NAMES = ("ultrafeeder", "piaware", "airspy", "dump978", "proxy", "cloudflared")
MAX_REPORT_BYTES = 16384
MAX_REMOVED_ARTIFACTS = 100000


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


# produce a bounded advisory report while preserving every deployment pin
def collect_report(deploy: Path) -> dict:
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
def _read_report(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        # reject devices pipes directories and oversized sparse files
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REPORT_BYTES:
            raise ValueError("maintenance report is not a bounded regular file")
        return os.read(descriptor, MAX_REPORT_BYTES + 1)
    finally:
        os.close(descriptor)


# expose only expected maintenance fields through the authenticated api
def public_report(path: Path = REPORT_PATH, *, now: datetime | None = None) -> dict:
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
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=target.parent, prefix="maintenance-", delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), 0o640)
            json.dump(report, output)
            output.write("\n")
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
        report = collect_report(Path(__file__).resolve().parents[1] / "deploy")
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
