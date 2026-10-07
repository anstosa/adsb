"""Root update worker for exact evidence-bound ADS-B release candidates."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# add only this immutable release root for the isolated script entrypoint
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adsb_admin import maintenance
from adsb_admin.update_evidence import canonical_hash

LOCK_PATH = Path("/run/lock/adsb/update-worker.lock")
REQUEST_PATH = Path("/var/lib/adsb/config/update-request.json")
CANDIDATE_PATH = Path("/var/lib/adsb/runtime/update-candidates.json")
INSTALLATION_PATH = Path("/var/lib/adsb/status/installation.json")
RUNTIME_ROOT = Path("/var/lib/adsb/runtime")
CURRENT_PATH = Path("/opt/adsb/current")
MAX_REQUEST_BYTES = 1024
MAX_CANDIDATE_BYTES = 512 * 1024
HEX64 = re.compile(r"^[a-f0-9]{64}$")
INSTALLABLE_STATES = frozenset({"available", "held", "failed", "rolled_back"})
COMMAND_TIMEOUT_SECONDS = 20 * 60


class CandidateDriftError(ValueError):
    """The exact discovery generation changed before activation."""


# open one root-private regular operation lock without following links
def _open_operation_lock(path: Path = LOCK_PATH) -> int:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.lstat()
    # require the shared lock directory to remain root-owned and non-writable
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("update lock directory is unsafe")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    metadata = os.fstat(descriptor)
    # reject foreign precreated or permissive lock objects
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(descriptor)
        raise ValueError("update lock file is unsafe")
    return descriptor


# read one frozen regular file without following links
def _read_regular(path: Path, maximum: int, *, owner: int, mode: int) -> tuple[bytes, os.stat_result, int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        # require exact ownership permissions and bounded regular storage
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_size > maximum
        ):
            raise ValueError("private update file has invalid ownership or type")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum:
            raise ValueError("private update file exceeds size limit")
        return raw, metadata, descriptor
    except Exception:
        os.close(descriptor)
        raise


# flush directory-entry mutations used as durable authorization fences
def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# atomically claim and unlink one unprivileged request before update work
def claim_request(
    path: Path = REQUEST_PATH,
    *,
    runtime: Path = RUNTIME_ROOT,
    adsb_uid: int | None = None,
) -> dict | None:
    # treat only a truly absent path as the automatic-update path
    if not os.path.lexists(path):
        return None
    expected_uid = pwd.getpwnam("adsb").pw_uid if adsb_uid is None else adsb_uid
    claimed = runtime / f"update-request.claimed-{os.getpid()}-{secrets.token_hex(8)}.json"
    descriptor = None
    try:
        # remove the watched name atomically before inspecting even an invalid object
        os.rename(path, claimed)
        _fsync_directory(path.parent)
        _fsync_directory(claimed.parent)
        raw, _, descriptor = _read_regular(claimed, MAX_REQUEST_BYTES, owner=expected_uid, mode=0o600)
        request = json.loads(raw)
        expected_keys = {"schema_version", "request_id", "candidate_ids", "generation", "requested_at"}
        legacy_keys = (expected_keys - {"candidate_ids"}) | {"candidate_id"}
        # permit only fixed new or legacy singleton handoffs
        if (
            not isinstance(request, dict)
            or set(request) not in (expected_keys, legacy_keys)
            or type(request.get("schema_version")) is not int
            or request.get("schema_version") != 1
        ):
            raise ValueError("update request contract is invalid")
        # validate exact identifiers before removing the claimed artifact
        for key in ("request_id", "generation"):
            # reject noncanonical identifiers
            if not isinstance(request.get(key), str) or not HEX64.fullmatch(request[key]):
                raise ValueError("update request identifier is invalid")
        identifiers = request.get("candidate_ids", [request.get("candidate_id")])
        # validate the entire selection before granting any installation authority
        if (
            not isinstance(identifiers, list)
            or not 1 <= len(identifiers) <= maintenance.MAX_UPDATES
            or any(not isinstance(item, str) or not HEX64.fullmatch(item) for item in identifiers)
            or len(set(identifiers)) != len(identifiers)
        ):
            raise ValueError("update request selection is invalid")
        request.pop("candidate_id", None)
        request["candidate_ids"] = sorted(identifiers)
        requested_at = request.get("requested_at")
        if not isinstance(requested_at, str) or len(requested_at) > 40:
            raise ValueError("update request timestamp is invalid")
        try:
            stamp = datetime.fromisoformat(requested_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("update request timestamp is invalid") from error
        current = datetime.now(timezone.utc)
        # revalidate the API's 24-hour request freshness at consumption time
        if stamp.tzinfo is None or not 0 <= (current - stamp.astimezone(timezone.utc)).total_seconds() <= 86400:
            raise ValueError("update request timestamp is stale or in the future")
        return request
    finally:
        if descriptor is not None:
            os.close(descriptor)
        # a claimed non-directory request is never replayed after this worker attempt
        try:
            metadata = os.lstat(claimed)
            if stat.S_ISDIR(metadata.st_mode):
                # remove empty directory attacks but quarantine nonempty trees without traversal
                claimed.rmdir()
            else:
                claimed.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # leave only a uniquely named root-private quarantine artifact
            pass
        _fsync_directory(claimed.parent)


# load and cryptographically revalidate the private candidate store
def load_candidate_store(path: Path = CANDIDATE_PATH, *, root_uid: int = 0) -> dict:
    raw, _, descriptor = _read_regular(path, MAX_CANDIDATE_BYTES, owner=root_uid, mode=0o600)
    try:
        store = json.loads(raw)
    finally:
        os.close(descriptor)
    if not isinstance(store, dict) or set(store) != {"schema_version", "generation", "source_release", "candidates"}:
        raise ValueError("candidate store contract is invalid")
    if (
        type(store.get("schema_version")) is not int
        or store.get("schema_version") != 1
        or not isinstance(store.get("generation"), str)
        or not HEX64.fullmatch(store["generation"])
    ):
        raise ValueError("candidate generation is invalid")
    source_release = store.get("source_release")
    rows = store.get("candidates")
    if not isinstance(source_release, str) or len(source_release) > 300 or not isinstance(rows, list) or len(rows) > 7:
        raise ValueError("candidate store bounds are invalid")
    identifiers = []
    # bind every candidate identifier to exact targets and evidence
    for candidate in rows:
        if not isinstance(candidate, dict):
            raise ValueError("candidate row is invalid")
        evidence = candidate.get("evidence")
        evidence_sha256 = canonical_hash(evidence)
        if candidate.get("evidence_sha256") != evidence_sha256:
            raise ValueError("candidate evidence digest is invalid")
        identity = {
            "name": candidate.get("name"),
            "kind": candidate.get("kind"),
            "current_target": candidate.get("current_target"),
            "candidate_target": candidate.get("candidate_target"),
            "evidence_sha256": evidence_sha256,
        }
        if candidate.get("id") != canonical_hash(identity):
            raise ValueError("candidate identifier is invalid")
        if candidate.get("compatibility") not in {"compatible", "breaking", "unknown"}:
            raise ValueError("candidate compatibility is invalid")
        if candidate.get("state") not in maintenance.UPDATE_STATES:
            raise ValueError("candidate state is invalid")
        identifiers.append(candidate["id"])
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("candidate identifiers are duplicated")
    expected_generation = canonical_hash({"source_release": source_release, "candidate_ids": sorted(identifiers)})
    if store["generation"] != expected_generation:
        raise ValueError("candidate generation does not match its rows")
    return store


# write one root-owned status readable only by the admin group
def write_installation(
    *,
    generation: str,
    request_id: str,
    candidate_id: str,
    candidate_ids: list[str],
    state: str,
    message: str,
    path: Path = INSTALLATION_PATH,
    adsb_gid: int | None = None,
    root_uid: int = 0,
    attempted_candidate_ids: list[str] | None = None,
) -> None:
    # reject unsupported publication states
    if state not in maintenance.INSTALLATION_STATES or state == "idle":
        raise ValueError("invalid installation state")
    payload = {
        "schema_version": 1,
        "generation": generation,
        "request_id": request_id,
        "candidate_id": candidate_id,
        "candidate_ids": candidate_ids,
        "attempted_candidate_ids": sorted(
            candidate_ids if attempted_candidate_ids is None else attempted_candidate_ids
        ),
        "state": state,
        "message": message[:1000],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > 16 * 1024:
        raise ValueError("installation status exceeds size limit")
    group = pwd.getpwnam("adsb").pw_gid if adsb_gid is None else adsb_gid
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix="installation-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchown(descriptor, root_uid, group)
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        # remove interrupted status publications
        temporary.unlink(missing_ok=True)


# read one prior root installation attempt without treating corruption as absence
def read_installation(path: Path = INSTALLATION_PATH, *, root_uid: int = 0) -> dict | None:
    try:
        raw, _, descriptor = _read_regular(path, 16 * 1024, owner=root_uid, mode=0o640)
    except FileNotFoundError:
        return None
    try:
        value = json.loads(raw)
    finally:
        os.close(descriptor)
    # require the complete publication envelope rather than granting a fresh attempt
    required = {
        "schema_version",
        "generation",
        "request_id",
        "candidate_id",
        "candidate_ids",
        "state",
        "message",
        "updated_at",
    }
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - {"attempted_candidate_ids"}
    ):
        raise ValueError("installation status envelope is invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("installation status schema is invalid")
    if any(
        not isinstance(value[key], str) or not HEX64.fullmatch(value[key])
        for key in ("generation", "request_id", "candidate_id")
    ):
        raise ValueError("installation status identity is invalid")
    # normalize prior immutable releases without discarding their retry fence
    attempted = value.get("attempted_candidate_ids", value["candidate_ids"])
    for identifiers in (value["candidate_ids"], attempted):
        minimum = 0 if identifiers is attempted and value["state"] == "rejected" else 1
        # bound both selected members and the durable automatic retry fence
        if (
            not isinstance(identifiers, list)
            or not minimum <= len(identifiers) <= maintenance.MAX_UPDATES
            or any(not isinstance(item, str) or not HEX64.fullmatch(item) for item in identifiers)
            or len(set(identifiers)) != len(identifiers)
        ):
            raise ValueError("installation status candidate set is invalid")
    # rejected requests grant no installation authority beyond the preserved attempt fence
    if value["candidate_id"] not in value["candidate_ids"] or (
        value["state"] != "rejected" and not set(value["candidate_ids"]) <= set(attempted)
    ):
        raise ValueError("installation status attempted set is invalid")
    if value["state"] not in maintenance.INSTALLATION_STATES - {"idle"}:
        raise ValueError("installation status state is invalid")
    if (
        not isinstance(value["message"], str)
        or len(value["message"]) > 1000
        or not isinstance(value["updated_at"], str)
        or len(value["updated_at"]) > 40
    ):
        raise ValueError("installation status text is invalid")
    stamp = datetime.fromisoformat(value["updated_at"])
    if stamp.tzinfo is None:
        raise ValueError("installation status timestamp is invalid")
    value["attempted_candidate_ids"] = sorted(attempted)
    return value


# read one current MemAvailable sample
def _mem_available() -> int:
    with Path("/proc/meminfo").open(encoding="ascii") as source:
        # find the kernel's aggregate available-memory observation
        for line in source:
            if line.startswith("MemAvailable:"):
                fields = line.split()
                if len(fields) == 3 and fields[2] == "kB" and fields[1].isdigit():
                    return int(fields[1])
    raise ValueError("MemAvailable is unavailable")


# read cumulative kernel swap counters
def _swap_counters() -> tuple[int, int]:
    counters = {}
    with Path("/proc/vmstat").open(encoding="ascii") as source:
        # retain only the two fixed page counters
        for line in source:
            key, _, value = line.partition(" ")
            if key in {"pswpin", "pswpout"} and value.strip().isdigit():
                counters[key] = int(value)
    if set(counters) != {"pswpin", "pswpout"}:
        raise ValueError("kernel swap counters are unavailable")
    page_kib = os.sysconf("SC_PAGE_SIZE") // 1024
    return counters["pswpin"] * page_kib, counters["pswpout"] * page_kib


# count bounded kernel OOM evidence from the preceding day
def _oom_events() -> int:
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.run(
            [
                "/usr/bin/journalctl",
                "--dmesg",
                "--since=-24 hours",
                "--output=cat",
                "--grep=Out of memory|Killed process|oom-kill",
            ],
            stdout=output,
            stderr=errors,
            timeout=15,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        if process.returncode not in {0, 1}:
            raise ValueError("kernel OOM audit is unavailable")
        output.seek(0)
        raw = output.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("kernel OOM audit exceeds size limit")
    return len([line for line in raw.splitlines() if line.strip()])


# collect five fresh aggregate capacity observations
def collect_headroom(*, sleep=time.sleep) -> dict:
    memory = []
    swap_in = []
    swap_out = []
    previous_swap = _swap_counters()
    # capture five one-second deltas after discarding cumulative boot counters
    for _index in range(5):
        sleep(1)
        memory.append(_mem_available())
        current_swap = _swap_counters()
        swap_in.append(max(0, current_swap[0] - previous_swap[0]))
        swap_out.append(max(0, current_swap[1] - previous_swap[1]))
        previous_swap = current_swap
    minimum = min(memory)
    planned = 224 * 1024
    residual = minimum - planned
    oom_events = _oom_events()
    passed = oom_events == 0 and not any(swap_in) and not any(swap_out) and residual >= 256 * 1024
    return {
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "headroom_passed": passed,
        "mem_available_kib_samples": memory,
        "minimum_mem_available_kib": minimum,
        "minimum_residual_requirement_kib": 256 * 1024,
        "oom_events_last_24h": oom_events,
        "planned_incremental_memory_kib": planned,
        "residual_after_planned_increment_kib": residual,
        "vmstat_swap_in_kib_per_second": swap_in,
        "vmstat_swap_out_kib_per_second": swap_out,
    }


# run one fixed command with bounded discarded output
def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    expected_release: str = "",
) -> None:
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "DOCKER_CONFIG": "/run/adsb-updater/docker",
    }
    docker_config = Path(environment["DOCKER_CONFIG"])
    docker_config.mkdir(parents=True, exist_ok=True, mode=0o700)
    docker_config.chmod(0o700)
    # pass only the internally observed managed base release to the locked installer
    if expected_release:
        release = Path(expected_release)
        if release.parent != Path("/opt/adsb/releases") or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", release.name):
            raise ValueError("update base release is not a managed path")
        environment["ADSB_UPDATE_BASE_RELEASE"] = str(release)
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            timeout=timeout,
            check=False,
        )
        if process.returncode:
            raise RuntimeError("trusted update command failed")


# verify selected metadata and full stack readiness after installer acceptance
def verify_activation(selected: list[dict]) -> None:
    current = CURRENT_PATH.resolve()
    if current.parent != Path("/opt/adsb/releases"):
        raise ValueError("activated release is outside the managed root")
    images = json.loads((current / "deploy/images.json").read_text(encoding="utf-8"))
    map_manifest = json.loads((current / "deploy/map-ui.json").read_text(encoding="utf-8"))
    # bind the selected pointer to every requested exact target
    for candidate in selected:
        if candidate["kind"] == "image" and images.get(candidate["name"]) != candidate["candidate_target"]:
            raise ValueError("activated image target does not match the candidate")
        if (
            candidate["kind"] == "map"
            and map_manifest.get("upstream", {}).get("commit") != candidate["candidate_target"]
        ):
            raise ValueError("activated map target does not match the candidate")
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.run(
            ["/usr/local/sbin/adsb-stack", "status"],
            stdout=output,
            stderr=errors,
            timeout=30,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        if process.returncode:
            raise RuntimeError("activated stack readiness is unavailable")
        output.seek(0)
        raw = output.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("activated stack status exceeds size limit")
    status = json.loads(raw)
    if not isinstance(status, dict) or status.get("state") != "running":
        raise ValueError("activated stack is not running")
    if status.get("alerts", {}).get("infrastructure_ready") is not True:
        raise ValueError("activated alert infrastructure is not ready")


# refresh only real production headroom when source fixture evidence is unchanged
def _refresh_proof_headroom(stage: Path, headroom: dict) -> None:
    proof_path = stage / "deploy/alerts/source-proof.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    if not isinstance(proof, dict) or not headroom.get("headroom_passed"):
        raise ValueError("fresh production headroom did not pass")
    proof["production_headroom"] = headroom
    proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# prove the candidate ultrafeeder still contains every fixed map dependency
def _verify_ultrafeeder_map_dependencies(stage: Path, image: str) -> None:
    manifest = json.loads((stage / "deploy/map-ui.json").read_text(encoding="utf-8"))
    dependency = manifest.get("base_image_dependency")
    # accept only the fixed container root and inert basename arguments
    if not isinstance(dependency, dict) or dependency.get("image_role") != "ultrafeeder":
        raise ValueError("map base-image dependency metadata is unavailable")
    html_root = dependency.get("html_root")
    database = dependency.get("database_directory")
    config = dependency.get("config")
    if (
        html_root != "/usr/local/share/tar1090/html-webroot"
        or not isinstance(database, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", database)
        or config != "config.js"
    ):
        raise ValueError("map base-image dependency paths are invalid")
    _run_command(
        [
            "/usr/bin/docker",
            "run",
            "--rm",
            "--network=none",
            "--pull=never",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=128m",
            "--entrypoint=/bin/sh",
            image,
            "-eu",
            "-c",
            'test -d "$1/$2" && test -f "$1/$3"',
            "map-dependency-check",
            html_root,
            database,
            config,
        ],
        cwd=stage,
        timeout=2 * 60,
    )


# regenerate exact source fixtures only when their image inputs change
def _regenerate_source_proof(stage: Path, headroom: dict, *, ultrafeeder_changed: bool) -> None:
    proof_path = stage / "deploy/alerts/source-proof.json"
    previous = json.loads(proof_path.read_text(encoding="utf-8"))
    audit = previous.get("production_headroom_transient_audit")
    if not isinstance(audit, dict) or not headroom.get("headroom_passed"):
        raise ValueError("source proof inputs are unavailable")
    images = json.loads((stage / "deploy/images.json").read_text(encoding="utf-8"))
    # seed only the two exact proof-bound images before isolated --pull=never fixtures
    for name in ("ultrafeeder", "dump978"):
        image = images.get(name)
        if not isinstance(image, str) or not re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image):
            raise ValueError("source proof image pin is invalid")
        _run_command(
            ["/usr/bin/docker", "pull", "--platform", "linux/amd64", image],
            cwd=stage,
            timeout=10 * 60,
        )
        # verify fixed map integration only when its actual base image changed
        if name == "ultrafeeder" and ultrafeeder_changed:
            _verify_ultrafeeder_map_dependencies(stage, image)
    with tempfile.TemporaryDirectory(prefix="update-proof-", dir=RUNTIME_ROOT) as directory:
        root = Path(directory)
        headroom_path = root / "headroom.json"
        audit_path = root / "headroom-audit.json"
        expected = {
            "captured_at",
            "mem_available_kib_samples",
            "vmstat_swap_in_kib_per_second",
            "vmstat_swap_out_kib_per_second",
            "oom_events_last_24h",
        }
        # pass only the helper's exact aggregate input schema
        headroom_path.write_text(json.dumps({key: headroom[key] for key in expected}), encoding="utf-8")
        audit_path.write_text(json.dumps({key: audit[key] for key in expected}), encoding="utf-8")
        helper = stage / "deploy/alerts/prove-sources.py"
        if not helper.is_file() or helper.is_symlink():
            raise ValueError("source proof helper is unavailable")
        _run_command(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(helper),
                "--output",
                str(proof_path),
                "--headroom-json",
                str(headroom_path),
                "--headroom-audit-json",
                str(audit_path),
            ],
            cwd=stage,
        )


# stage one trusted current release and apply exact selected targets
def stage_candidates(store: dict, selected: list[dict], request_id: str, *, runtime: Path = RUNTIME_ROOT) -> Path:
    source = Path(store["source_release"])
    resolved_current = CURRENT_PATH.resolve()
    # require the discovery source to remain the selected immutable release
    if source.resolve() != resolved_current or resolved_current.parent != Path("/opt/adsb/releases"):
        raise ValueError("selected release changed after discovery")
    usage = shutil.disk_usage(runtime)
    # retain both a percentage and absolute staging reserve
    if usage.free < max(1024 * 1024 * 1024, usage.total // 20):
        raise ValueError("insufficient disk headroom for update staging")
    stage = runtime / f"update-stage-{request_id}"
    if stage.exists() or stage.is_symlink():
        raise ValueError("update stage already exists")
    try:
        shutil.copytree(source, stage, symlinks=True)
        images_path = stage / "deploy/images.json"
        images = json.loads(images_path.read_text(encoding="utf-8"))
        changed_source_images: set[str] = set()
        # apply every selected candidate only to its fixed release metadata file
        for candidate in selected:
            if candidate["kind"] == "image":
                if images.get(candidate["name"]) != candidate["current_target"]:
                    raise ValueError("staged image target drifted")
                images[candidate["name"]] = candidate["candidate_target"]
                # track only proof-bound image changes
                if candidate["name"] in {"ultrafeeder", "dump978"}:
                    changed_source_images.add(candidate["name"])
            elif candidate["kind"] == "map":
                manifest = candidate.get("evidence", {}).get("manifest")
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("upstream", {}).get("commit") != candidate["candidate_target"]
                ):
                    raise ValueError("map candidate evidence is incomplete")
                (stage / "deploy/map-ui.json").write_text(
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            else:
                raise ValueError("unsupported candidate kind")
        images_path.write_text(json.dumps(images, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        headroom = collect_headroom()
        # regenerate isolated fixtures only for the two proof-bound source images
        if changed_source_images:
            _regenerate_source_proof(
                stage,
                headroom,
                ultrafeeder_changed="ultrafeeder" in changed_source_images,
            )
        else:
            _refresh_proof_headroom(stage, headroom)
        return stage
    except Exception:
        # remove only the stage whose prior absence was proven above
        shutil.rmtree(stage, ignore_errors=True)
        raise


# choose one explicit selected batch or the positively compatible automatic batch
def select_candidates(store: dict, request: dict | None) -> tuple[str, list[dict]]:
    rows = store["candidates"]
    # hold manual authorization to its exact discovery snapshot
    if request is not None:
        # reject refreshed discovery before selecting any member
        if request["generation"] != store["generation"]:
            raise ValueError("requested generation is no longer current")
        identifiers = request["candidate_ids"]
        selected = sorted(
            (candidate for candidate in rows if candidate["id"] in identifiers), key=lambda row: row["id"]
        )
        # reject the whole batch when any candidate disappeared or became blocked
        if len(selected) != len(identifiers) or any(
            candidate["state"] not in INSTALLABLE_STATES for candidate in selected
        ):
            raise ValueError("requested batch is not installable")
        return request["request_id"], selected
    compatible = [
        candidate
        for candidate in rows
        if candidate["compatibility"] == "compatible" and candidate["state"] == "available"
    ]
    return secrets.token_hex(32), compatible


# re-run discovery and require byte-equivalent selected authorization evidence
def revalidate(store: dict, selected: list[dict]) -> None:
    current_deploy = CURRENT_PATH.resolve() / "deploy"
    refreshed = maintenance.discover_candidates(current_deploy)
    if refreshed["generation"] != store["generation"] or refreshed["source_release"] != store["source_release"]:
        raise CandidateDriftError("update discovery changed before installation")
    refreshed_rows = {candidate["id"]: candidate for candidate in refreshed["candidates"]}
    # compare complete evidence-bound rows for every selected candidate
    for candidate in selected:
        if refreshed_rows.get(candidate["id"]) != candidate:
            raise CandidateDriftError("candidate evidence changed before installation")


# start one asynchronous discovery refresh without retrying installation
def _start_discovery_refresh(source_release: str) -> None:
    try:
        _run_command(
            ["/usr/bin/systemctl", "--no-block", "start", "adsb-maintenance.service"],
            cwd=Path(source_release),
            timeout=30,
        )
    except Exception as error:
        # preserve the terminal outcome while exposing a bounded nonsecret diagnostic
        print(f"Update discovery refresh failed ({type(error).__name__}).", file=sys.stderr)


# select every candidate bound to one interrupted status in its original order
def _status_candidates(store: dict, prior: dict) -> list[dict]:
    rows = {candidate["id"]: candidate for candidate in store["candidates"]}
    selected = [rows[identifier] for identifier in prior["candidate_ids"] if identifier in rows]
    if len(selected) != len(prior["candidate_ids"]):
        raise ValueError("interrupted candidate evidence is unavailable")
    return selected


# reconcile one interrupted attempt against the activated pointer and readiness
def _reconcile_interrupted(store: dict, prior: dict) -> str:
    state = "failed"
    message = "The interrupted update attempt could not be proven complete or recovered."
    # an installing status may have committed before its terminal status write
    if prior["state"] == "installing":
        try:
            verify_activation(_status_candidates(store, prior))
        except Exception as error:
            # retain only bounded failure context rather than discarding reconciliation evidence
            print(f"Interrupted update activation verification failed ({type(error).__name__}).", file=sys.stderr)
        else:
            state = "installed"
            message = "The interrupted activation completed and the exact release is healthy."
    # prove both the baseline pointer and health before claiming rollback
    if state == "failed" and prior["state"] == "installing" and CURRENT_PATH.resolve() == Path(store["source_release"]):
        try:
            verify_activation([])
        except Exception as error:
            # avoid claiming recovery without exact pointer and readiness evidence
            print(f"Interrupted update rollback verification failed ({type(error).__name__}).", file=sys.stderr)
        else:
            state = "rolled_back"
            message = "The interrupted activation was recovered to the healthy previous immutable release."
    write_installation(
        generation=prior["generation"],
        request_id=prior["request_id"],
        candidate_id=prior["candidate_id"],
        candidate_ids=prior["candidate_ids"],
        attempted_candidate_ids=prior.get("attempted_candidate_ids", prior["candidate_ids"]),
        state=state,
        message=message,
    )
    # publish the remaining candidates from the newly activated release
    if state == "installed":
        _start_discovery_refresh(store["source_release"])
    return state


# process one request or automatic compatible batch under the operation lock
def run() -> int:
    if os.geteuid() != 0:
        raise SystemExit("root execution required")
    lock_descriptor = _open_operation_lock()
    try:
        # refuse overlapping updater work without waiting behind a stale UI request
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        current = CURRENT_PATH.resolve()
        recovery = current / "deploy/install.sh"
        _run_command([str(recovery), "--recover-only"], cwd=current)
        request = claim_request()
        try:
            store = load_candidate_store()
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            # release a valid manual UI request from its queued state even when discovery storage broke
            if request is not None:
                write_installation(
                    generation=request["generation"],
                    request_id=request["request_id"],
                    candidate_id=request["candidate_ids"][0],
                    candidate_ids=request["candidate_ids"],
                    state="rejected",
                    message="Candidate evidence is unavailable; wait for the next maintenance discovery.",
                )
            return 1
        try:
            prior = read_installation()
        except (OSError, ValueError, TypeError, RecursionError):
            # never install through an unreadable or malformed durable retry fence
            print("Prior installation status is invalid; update execution is blocked.", file=sys.stderr)
            # report a consumed manual request while fencing the entire trusted discovery
            if request is not None:
                write_installation(
                    generation=store["generation"],
                    request_id=request["request_id"],
                    candidate_id=request["candidate_ids"][0],
                    candidate_ids=request["candidate_ids"],
                    attempted_candidate_ids=sorted(candidate["id"] for candidate in store["candidates"]),
                    state="rejected",
                    message="Installation rejected because prior installation status is invalid; automatic updates are blocked for this discovery.",
                )
            return 1
        # reconcile an interrupted active attempt after the installer's durable recovery
        if (
            prior is not None
            and prior["generation"] == store["generation"]
            and prior["state"] in {"preparing", "installing"}
        ):
            prior["state"] = _reconcile_interrupted(store, prior)
        try:
            request_id, selected = select_candidates(store, request)
        except (ValueError, TypeError, KeyError):
            if request is not None:
                write_installation(
                    generation=request["generation"],
                    request_id=request["request_id"],
                    candidate_id=request["candidate_ids"][0],
                    candidate_ids=request["candidate_ids"],
                    attempted_candidate_ids=prior["attempted_candidate_ids"]
                    if prior is not None and prior["generation"] == request["generation"]
                    else [],
                    state="rejected",
                    message="A selected update changed or is no longer installable; the batch was not installed.",
                )
            return 1
        attempted = set()
        # retain every same-generation attempt while permitting unrelated compatible members
        if prior is not None and prior["generation"] == store["generation"]:
            attempted.update(prior.get("attempted_candidate_ids", prior["candidate_ids"]))
        # explicit manual authorization may retry a failed member without widening selection
        if request is None:
            selected = [candidate for candidate in selected if candidate["id"] not in attempted]
        # exit cleanly when no compatible automatic batch is pending
        if not selected:
            return 0
        candidate_ids = [candidate["id"] for candidate in selected]
        candidate_id = candidate_ids[0]
        status = {
            "generation": store["generation"],
            "request_id": request_id,
            "candidate_id": candidate_id,
            "candidate_ids": candidate_ids,
            "attempted_candidate_ids": sorted(attempted | set(candidate_ids)),
        }
        write_installation(**status, state="preparing", message="Revalidating exact update evidence.")
        stage = None
        activation_attempted = False
        try:
            revalidate(store, selected)
            stage = stage_candidates(store, selected, request_id)
            write_installation(**status, state="installing", message="Activating the verified immutable release.")
            activation_attempted = True
            _run_command(
                [str(stage / "deploy/install.sh"), "--update"],
                cwd=stage,
                expected_release=store["source_release"],
            )
            verify_activation(selected)
            write_installation(**status, state="installed", message="The verified immutable release was installed.")
            _start_discovery_refresh(store["source_release"])
        except CandidateDriftError:
            write_installation(
                **status,
                state="rejected",
                message="Candidate evidence changed; wait for the next maintenance discovery.",
            )
            _start_discovery_refresh(store["source_release"])
            return 1
        except Exception:
            outcome = "failed"
            message = "Installation failed before a new release was accepted; recovery was requested."
            # use the still-immutable baseline installer for bounded recovery after activation began
            if activation_attempted:
                baseline = Path(store["source_release"])
                message = "Installation failed and the active release could not be verified as the previous release."
                try:
                    _run_command([str(baseline / "deploy/install.sh"), "--recover-only"], cwd=baseline)
                    # claim rollback only after both the exact pointer and full readiness pass
                    if CURRENT_PATH.resolve() == baseline.resolve():
                        verify_activation([])
                        outcome = "rolled_back"
                        message = "Installation failed and the previous immutable release was restored."
                except Exception:
                    outcome = "failed"
            write_installation(
                **status,
                state=outcome,
                message=message,
            )
            return 1
        finally:
            # discard only this request's private unselected stage
            if stage is not None:
                shutil.rmtree(stage, ignore_errors=True)
        return 0
    finally:
        os.close(lock_descriptor)


# parse the fixed service entrypoint without accepting update targets in argv
def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(arguments)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
