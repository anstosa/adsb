#!/usr/bin/env bash
# publish bounded source process and connector health
set -euo pipefail
umask 0027

output_dir=/var/lib/adsb/alert-source

# keep the probe inside one interpreter startup on constrained receivers
exec /usr/bin/python3 - "$output_dir" /proc /usr/bin/ss \
    "${ALERT_SOURCE_BAND:-}" "${ALERT_SOURCE_INPUT_PORT:-}" \
    "${ALERT_SOURCE_ACTIVATION_ID:-}" "${ALERT_SOURCE_CONTRACT_DIGEST:-}" <<'PY'
import json
import os
import re
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MARKER_KEYS = {
    "schema_version",
    "band",
    "generation",
    "started_at",
    "activation_id",
    "contract_digest",
}
GENERATION_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
ACTIVATION_PATTERN = re.compile(r"[0-9a-f]{32}")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
PORTS = {"1090": "30005", "978": "30978"}


# read one bounded regular file without following its final component
def read_regular(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        # reject special and oversized trust-boundary inputs
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError("invalid regular file")
        chunks = []
        remaining = limit + 1
        # finish bounded regular-file reads even after a short read
        while remaining:
            chunk = os.read(descriptor, remaining)
            # stop only at the regular-file end
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        # reject growth after the metadata check
        if len(content) > limit:
            raise ValueError("regular file grew")
        return content
    finally:
        os.close(descriptor)


# locate exactly one decoder in this container pid namespace
def readsb_pid(proc_root: Path) -> str:
    matches = []
    # inspect only numeric process directories
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = read_regular(entry / "comm", 64).decode("ascii").strip()
        except (OSError, UnicodeError, ValueError):
            continue
        # retain only the exact decoder process name
        if command == "readsb":
            matches.append(entry.name)
    # reject absent or ambiguous decoder processes
    if len(matches) != 1:
        return ""
    return matches[0]


# require current non-symlink decoder publications
def publications_fresh(output: Path, now: float) -> bool:
    # apply the fixed freshness window to each required publication
    for name, maximum_age in (("aircraft.json", 5), ("stats.json", 20)):
        try:
            metadata = os.stat(output / name, follow_symlinks=False)
        except OSError:
            return False
        # reject links, special files, future files and stalled writers
        age = now - metadata.st_mtime
        if not stat.S_ISREG(metadata.st_mode) or age < 0 or age > maximum_age:
            return False
    return True


# retain only a marker bound to this immutable activation
def marker_generation(output: Path, band: str, activation: str, digest: str) -> str:
    try:
        value = json.loads(read_regular(output / "source-marker.json", 8192).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return ""
    # reject additional marker fields and altered provenance
    if (
        not isinstance(value, dict)
        or set(value) != MARKER_KEYS
        or value.get("schema_version") != 1
        or value.get("band") != band
        or value.get("activation_id") != activation
        or value.get("contract_digest") != digest
    ):
        return ""
    generation = value.get("generation")
    # accept only canonical generated version-four UUIDs
    if not isinstance(generation, str) or GENERATION_PATTERN.fullmatch(generation) is None:
        return ""
    return generation


# inspect exactly one pid-owned physical connector and its kernel byte counter
def socket_observation(ss_path: str, pid: str, port: str) -> tuple[bool, str, int, str]:
    sampled_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    # reject an absent decoder or altered band-to-port mapping before invocation
    if not pid or port not in PORTS.values():
        return False, "", 0, sampled_at
    try:
        result = subprocess.run(
            [ss_path, "-Hntiep", "state", "established"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return False, "", 0, sampled_at
    # bound kernel telemetry before parsing it
    if len(result.stdout) > 65536:
        return False, "", 0, sampled_at
    lines = result.stdout.splitlines()
    sockets = []
    # match only the fixed peer owned by this exact decoder pid
    for index, line in enumerate(lines):
        if f"pid={pid}," not in line or re.search(r":" + re.escape(port) + r"\s", line) is None:
            continue
        inode = re.search(r"\bino:(\d+)", line)
        details = lines[index + 1] if index + 1 < len(lines) else ""
        counter = re.search(r"\bbytes_received:(\d+)", details)
        # accept a quiet established socket when iproute2 omits its zero counter
        if inode is not None and "rto:" in details:
            sockets.append((inode.group(1), int(counter.group(1)) if counter else 0))
    # reject absent or ambiguous physical connectors
    if len(sockets) != 1:
        return False, "", 0, sampled_at
    return True, sockets[0][0], sockets[0][1], sampled_at


# replace the bounded state atomically with private group-readable permissions
def publish_state(output: Path, value: dict) -> None:
    temporary = output / "source-state.json.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o640,
    )
    try:
        metadata = os.fstat(descriptor)
        # reject a non-regular temporary destination
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("invalid state destination")
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, 0o640)
    finally:
        os.close(descriptor)
    os.replace(temporary, output / "source-state.json")


output = Path(sys.argv[1])
proc_root = Path(sys.argv[2])
ss_path = sys.argv[3]
band = sys.argv[4]
port = sys.argv[5]
activation = sys.argv[6]
digest = sys.argv[7]

# reject a replaced publication directory
directory_metadata = os.lstat(output)
if not stat.S_ISDIR(directory_metadata.st_mode) or stat.S_ISLNK(directory_metadata.st_mode):
    raise SystemExit(1)

pid = readsb_pid(proc_root)
process_running = bool(pid)
generation = marker_generation(output, band, activation, digest)
files_fresh = publications_fresh(output, time.time())
contract_valid = (
    PORTS.get(band) == port
    and ACTIVATION_PATTERN.fullmatch(activation) is not None
    and DIGEST_PATTERN.fullmatch(digest) is not None
)
# observe only a fixed contract connector
input_connected, input_socket, input_bytes, sampled_at = socket_observation(
    ss_path, pid, port if contract_valid else ""
)
state = {
    "schema_version": 2,
    "band": band,
    "generation": generation,
    "activation_id": activation,
    "contract_digest": digest,
    "sampled_at": sampled_at,
    "process_running": process_running,
    "input_connected": input_connected,
    "input_socket": input_socket,
    "input_bytes": input_bytes,
}
publish_state(output, state)

# require current process, files, connector and immutable provenance
healthy = process_running and files_fresh and input_connected and bool(generation) and contract_valid
raise SystemExit(0 if healthy else 1)
PY
