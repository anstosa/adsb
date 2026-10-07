#!/usr/bin/env bash
# restore host integration after a failed release activation

# open the activation lock only beneath a validated root-private directory
prepare_activation_lock() {
    local root=${1:-}
    local mode=${2:-blocking}
    local expected_uid=0
    local expected_gid=0
    local lock_directory="$root/run/lock/adsb"
    local lock_path="$root/run/lock/adsb/activation.lock"
    # isolate regression roots without relaxing production ownership
    if [[ -n "$root" ]]; then
        expected_uid=$(id -u)
        expected_gid=$(id -g)
        mkdir -p -- "$root/run/lock"
    fi
    local metadata
    # reject links and non-directories before any child path access
    if [[ -L "$lock_directory" || ( -e "$lock_directory" && ! -d "$lock_directory" ) ]]; then
        printf '%s\n' 'activation lock directory is invalid' >&2
        return 1
    fi
    # atomically create a missing private parent
    if [[ ! -e "$lock_directory" ]]; then
        mkdir -m 700 -- "$lock_directory" 2>/dev/null || true
    fi
    metadata=$(stat -c '%u:%g:%a' "$lock_directory") || return
    # require exact ownership and privacy after any creation race
    if [[ "$metadata" != "$expected_uid:$expected_gid:700" || -L "$lock_directory" || ! -d "$lock_directory" ]]; then
        printf '%s\n' 'activation lock directory is not root private' >&2
        return 1
    fi
    # reject a pre-existing link before creating or opening the lock
    if [[ -L "$lock_path" || ( -e "$lock_path" && ! -f "$lock_path" ) ]]; then
        printf '%s\n' 'activation lock file is invalid' >&2
        return 1
    fi
    # create a missing file only after validating its private parent
    if [[ ! -e "$lock_path" ]]; then
        (umask 077; : >"$lock_path") || return
    fi
    metadata=$(stat -c '%u:%g:%a:%h' "$lock_path") || return
    # refuse permissive multiply-linked or nonroot lock files
    if [[ "$metadata" != "$expected_uid:$expected_gid:600:1" || -L "$lock_path" || ! -f "$lock_path" ]]; then
        printf '%s\n' 'activation lock file is not root private' >&2
        return 1
    fi
    exec 9<>"$lock_path" || return
    # distinguish contention from filesystem and flock failures
    if [[ "$mode" == nonblocking ]]; then
        flock -x -n -E 75 9
    else
        flock -x 9
    fi
}


# keep maintenance host files in the same activation transaction as the application
MAINTENANCE_ARTIFACTS=(
    '/etc/systemd/system/adsb-maintenance.service|adsb-maintenance.service'
    '/etc/systemd/system/adsb-maintenance.timer|adsb-maintenance.timer'
    '/etc/systemd/system/apt-daily.timer.d/adsb-weekly.conf|apt-daily-weekly.conf'
    '/etc/systemd/system/apt-daily-upgrade.timer.d/adsb-weekly.conf|apt-upgrade-weekly.conf'
    '/etc/apt/apt.conf.d/52unattended-upgrades-adsb|52unattended-upgrades-adsb'
)

# keep fixed application units in the same rollback snapshot
APPLICATION_UNIT_ARTIFACTS=(
    '/etc/systemd/system/adsb-admin.service|adsb-admin.service'
    '/etc/systemd/system/adsb-controller.service|adsb-controller.service'
    '/etc/systemd/system/adsb-alerts.service|adsb-alerts.service'
    '/etc/systemd/system/adsb-updater.service|adsb-updater.service'
    '/etc/systemd/system/adsb-updater.path|adsb-updater.path'
    '/etc/systemd/system/adsb-activation-recovery.service|adsb-activation-recovery.service'
    '/etc/systemd/system/docker.service.d/20-adsb-recovery.conf|docker-recovery.conf'
)

# define the only unit states accepted from a recovery journal
ACTIVATION_STATE_UNITS=(
    adsb-admin.service
    adsb-controller.service
    adsb-alerts.service
    adsb-maintenance.timer
    apt-daily.timer
    apt-daily-upgrade.timer
    adsb-updater.path
    adsb-activation-recovery.service
)

# preserve one host file or record its prior absence
backup_activation_file() {
    local rollback_dir=$1
    local source=$2
    local label=$3
    # copy existing state without following a managed link
    if [[ -e "$source" || -L "$source" ]]; then
        cp -a -- "$source" "$rollback_dir/$label"
    else
        touch "$rollback_dir/$label.absent"
    fi
}

# restore one host file to its exact pre-activation state
restore_activation_file() {
    local rollback_dir=$1
    local destination=$2
    local label=$3
    rm -f -- "$destination" || return
    # replace the prior file when one existed
    if [[ -e "$rollback_dir/$label" || -L "$rollback_dir/$label" ]]; then
        cp -a -- "$rollback_dir/$label" "$destination"
    fi
}

# snapshot every live integration file before pointer selection
backup_activation_files() {
    local root=$1
    local rollback_dir=$2
    local artifact
    backup_activation_file "$rollback_dir" "$root/etc/adsb/admin.env" admin.env
    backup_activation_file "$rollback_dir" "$root/etc/adsb/runtime.json" runtime.json
    backup_activation_file "$rollback_dir" "$root/usr/local/sbin/adsb-stack" adsb-stack
    backup_activation_file "$rollback_dir" "$root/etc/sudoers.d/adsb-stack" sudoers
    # retain every fixed application unit
    for artifact in "${APPLICATION_UNIT_ARTIFACTS[@]}"; do
        backup_activation_file "$rollback_dir" "$root${artifact%%|*}" "${artifact##*|}"
    done
    # retain every weekly scheduling and update-policy file
    for artifact in "${MAINTENANCE_ARTIFACTS[@]}"; do
        backup_activation_file "$rollback_dir" "$root${artifact%%|*}" "${artifact##*|}"
    done
}

# restore pointers and host files after post-staging failure
rollback_activation() {
    local root=$1
    local rollback_dir=$2
    local current_code=$3
    local previous_map=$4
    local legacy_layout=$5
    local app_release=$6
    local map_release=$7
    local defer_guards=${8:-false}
    local current_link="$root/opt/adsb/current"
    local map_link="$root/opt/adsb/map-ui"
    local artifact
    # restore or remove the application pointer
    if [[ -n "$current_code" && "$legacy_layout" != true ]]; then
        rm -f -- "$current_link.rollback" || return
        ln -s "$current_code" "$current_link.rollback" || return
        mv -Tf "$current_link.rollback" "$current_link" || return
    else
        rm -f -- "$current_link" || return
    fi
    # restore or remove the compatibility map pointer
    if [[ -n "$previous_map" ]]; then
        rm -f -- "$map_link.rollback" || return
        ln -s "$previous_map" "$map_link.rollback" || return
        mv -Tf "$map_link.rollback" "$map_link" || return
    else
        rm -f -- "$map_link" || return
    fi
    restore_activation_file "$rollback_dir" "$root/etc/adsb/admin.env" admin.env || return
    restore_activation_file "$rollback_dir" "$root/etc/adsb/runtime.json" runtime.json || return
    restore_activation_file "$rollback_dir" "$root/usr/local/sbin/adsb-stack" adsb-stack || return
    restore_activation_file "$rollback_dir" "$root/etc/sudoers.d/adsb-stack" sudoers || return
    # retain guard-bearing units until durable journal removal during recovery
    if [[ "$defer_guards" != true ]]; then
        for artifact in "${APPLICATION_UNIT_ARTIFACTS[@]}"; do
            restore_activation_file "$rollback_dir" "$root${artifact%%|*}" "${artifact##*|}" || return
        done
    fi
    # restore prior timer schedules and security policy before reloading units
    for artifact in "${MAINTENANCE_ARTIFACTS[@]}"; do
        restore_activation_file "$rollback_dir" "$root${artifact%%|*}" "${artifact##*|}" || return
    done
    # preserve the pinned recovery installer while its journal remains
    if [[ "$defer_guards" != true ]]; then
        rm -rf -- "$app_release" "$map_release"
    fi
}

# write exact rollback metadata before selecting any new release pointer
write_activation_journal() {
    local root=$1
    local rollback_dir=$2
    local current_code=$3
    local previous_map=$4
    local legacy_layout=$5
    local app_release=$6
    local map_release=$7
    local activation_id=$8
    shift 8
    local journal="$root/var/lib/adsb/runtime/activation-journal.json"
    python3 -B - "$journal" "$root" "$rollback_dir" "$current_code" "$previous_map" \
        "$legacy_layout" "$app_release" "$map_release" "$activation_id" "$@" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path

(
    journal_raw,
    root_raw,
    rollback_raw,
    current_raw,
    previous_map_raw,
    legacy_raw,
    app_raw,
    map_release_raw,
    activation_id,
    *states,
) = sys.argv[1:]
units = (
    "adsb-admin.service",
    "adsb-controller.service",
    "adsb-alerts.service",
    "adsb-maintenance.timer",
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "adsb-updater.path",
    "adsb-activation-recovery.service",
)
root = Path(root_raw) if root_raw else Path("/")
expected_uid = 0 if not root_raw else os.getuid()


# accept one direct child of a fixed managed directory
def managed_child(raw: str, relative_parent: str) -> Path:
    path = Path(raw)
    parent = root / relative_parent
    if path.parent != parent or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", path.name) is None:
        raise ValueError("activation journal contains an unmanaged path")
    return path


if len(states) != len(units) * 2 or any(value not in {"true", "false"} for value in states):
    raise ValueError("activation journal contains invalid unit state")
if legacy_raw not in {"true", "false"} or re.fullmatch(r"[a-f0-9]{32}", activation_id) is None:
    raise ValueError("activation journal contains invalid activation metadata")
rollback = managed_child(rollback_raw, "var/lib/adsb/runtime")
app = managed_child(app_raw, "opt/adsb/releases")
map_release = managed_child(map_release_raw, "opt/adsb/map-ui-releases")
if rollback.name != f"activation-{app.name}" or map_release.name != app.name:
    raise ValueError("activation journal release identities differ")
if legacy_raw == "true":
    if Path(current_raw) != root / "opt/adsb":
        raise ValueError("activation journal legacy path is invalid")
elif current_raw:
    managed_child(current_raw, "opt/adsb/releases")
if previous_map_raw:
    managed_child(previous_map_raw, "opt/adsb/map-ui-releases")
if not rollback.is_dir() or rollback.is_symlink():
    raise ValueError("activation rollback directory is invalid")
rollback_stat = rollback.stat()
if rollback_stat.st_uid != expected_uid or stat.S_IMODE(rollback_stat.st_mode) != 0o700:
    raise ValueError("activation rollback directory is not root private")
unit_states = {
    unit: {"enabled": states[index * 2] == "true", "active": states[index * 2 + 1] == "true"}
    for index, unit in enumerate(units)
}
document = {
    "schema_version": 1,
    "activation_id": activation_id,
    "rollback_dir": rollback_raw,
    "current_code": current_raw,
    "previous_map": previous_map_raw,
    "legacy_layout": legacy_raw == "true",
    "app_release": app_raw,
    "map_release": map_release_raw,
    "units": unit_states,
}
journal = Path(journal_raw)
temporary = journal.with_name(f".{journal.name}.{os.getpid()}.next")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, journal)
    os.chmod(journal, 0o600)
    directory = os.open(journal.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    # remove only an unselected temporary journal
    if temporary.exists():
        temporary.unlink()
PY
}

# restore one unit's prior enablement without trusting journal commands
restore_activation_enablement() {
    local unit=$1
    local enabled=$2
    # restore the prior wants link when enabled
    if [[ "$enabled" == true ]]; then
        systemctl enable "$unit"
    else
        systemctl disable "$unit" 2>/dev/null || ! systemctl is-enabled --quiet "$unit" 2>/dev/null
    fi
}

# restore one unit's prior running state without touching the updater service
restore_activation_activity() {
    local unit=$1
    local active=$2
    local -a systemctl_options=()
    # avoid boot ordering deadlocks while recovery holds Before dependencies
    if [[ ${ADSB_BOOT_RECOVERY:-0} == 1 ]]; then
        systemctl_options=(--no-block)
    fi
    # restart long-running services that were previously active
    if [[ "$active" == true ]]; then
        case "$unit" in
            adsb-admin.service|adsb-controller.service|adsb-alerts.service)
                systemctl "${systemctl_options[@]}" restart "$unit"
                ;;
            *)
                systemctl "${systemctl_options[@]}" start "$unit"
                ;;
        esac
    else
        systemctl "${systemctl_options[@]}" stop "$unit" 2>/dev/null || ! systemctl is-active --quiet "$unit" 2>/dev/null
    fi
}

# remove a completed journal durably from its fixed root-owned location
clear_activation_journal() {
    local root=$1
    local journal="$root/var/lib/adsb/runtime/activation-journal.json"
    python3 -B - "$journal" <<'PY'
import os
import sys
from pathlib import Path

journal = Path(sys.argv[1])
# unlink only the fixed caller-selected journal
if journal.exists():
    journal.unlink()
directory = os.open(journal.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

# replay one bounded root-owned journal after an interrupted activation
recover_activation() {
    local root=$1
    local journal="$root/var/lib/adsb/runtime/activation-journal.json"
    local parsed
    local -a fields
    local rollback_dir current_code previous_map legacy_layout app_release map_release
    local unit index artifact
    # return cleanly when no interrupted activation exists
    if [[ ! -e "$journal" && ! -L "$journal" ]]; then
        return 0
    fi
    # parse only data with an exact schema and managed paths
    if ! parsed=$(python3 -B - "$journal" "$root" <<'PY'
import json
import re
import stat
import sys
from pathlib import Path

journal = Path(sys.argv[1])
root = Path(sys.argv[2]) if sys.argv[2] else Path("/")
expected_uid = 0 if not sys.argv[2] else journal.lstat().st_uid
units = (
    "adsb-admin.service",
    "adsb-controller.service",
    "adsb-alerts.service",
    "adsb-maintenance.timer",
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "adsb-updater.path",
    "adsb-activation-recovery.service",
)


# accept one direct child of a fixed managed directory
def managed_child(raw: str, relative_parent: str) -> Path:
    if not isinstance(raw, str):
        raise ValueError("activation journal path is not text")
    path = Path(raw)
    if path.parent != root / relative_parent or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", path.name) is None:
        raise ValueError("activation journal contains an unmanaged path")
    return path


journal_stat = journal.lstat()
if not stat.S_ISREG(journal_stat.st_mode) or journal_stat.st_uid != expected_uid or stat.S_IMODE(journal_stat.st_mode) != 0o600:
    raise ValueError("activation journal is not a root-private regular file")
if journal_stat.st_nlink != 1 or journal_stat.st_size > 16 * 1024:
    raise ValueError("activation journal file bounds are invalid")


# reject duplicate keys at every journal object depth
def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("activation journal contains duplicate keys")
    return value


value = json.loads(journal.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
expected = {
    "schema_version",
    "activation_id",
    "rollback_dir",
    "current_code",
    "previous_map",
    "legacy_layout",
    "app_release",
    "map_release",
    "units",
}
if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
    raise ValueError("activation journal schema is invalid")
if re.fullmatch(r"[a-f0-9]{32}", value["activation_id"] if isinstance(value["activation_id"], str) else "") is None:
    raise ValueError("activation identity is invalid")
if not isinstance(value["legacy_layout"], bool):
    raise ValueError("legacy layout state is invalid")
rollback = managed_child(value["rollback_dir"], "var/lib/adsb/runtime")
app = managed_child(value["app_release"], "opt/adsb/releases")
map_release = managed_child(value["map_release"], "opt/adsb/map-ui-releases")
if rollback.name != f"activation-{app.name}" or map_release.name != app.name:
    raise ValueError("activation journal release identities differ")
current = value["current_code"]
if value["legacy_layout"]:
    if not isinstance(current, str) or Path(current) != root / "opt/adsb":
        raise ValueError("legacy current release path is invalid")
elif current:
    if isinstance(current, str):
        managed_child(current, "opt/adsb/releases")
    else:
        raise ValueError("current release path is invalid")
elif not isinstance(current, str):
    raise ValueError("current release path is invalid")
previous_map = value["previous_map"]
if previous_map:
    managed_child(previous_map, "opt/adsb/map-ui-releases")
elif not isinstance(previous_map, str):
    raise ValueError("previous map path is invalid")
if not rollback.is_dir() or rollback.is_symlink():
    raise ValueError("activation rollback directory is invalid")
rollback_stat = rollback.stat()
if rollback_stat.st_uid != expected_uid or stat.S_IMODE(rollback_stat.st_mode) != 0o700:
    raise ValueError("activation rollback directory is not root private")
state = value["units"]
if not isinstance(state, dict) or set(state) != set(units):
    raise ValueError("activation unit state schema is invalid")
for unit in units:
    if not isinstance(state[unit], dict) or set(state[unit]) != {"enabled", "active"}:
        raise ValueError("activation unit state is invalid")
    if not all(isinstance(state[unit][key], bool) for key in ("enabled", "active")):
        raise ValueError("activation unit state is invalid")
print(value["rollback_dir"])
print(current)
print(previous_map)
print("true" if value["legacy_layout"] else "false")
print(value["app_release"])
print(value["map_release"])
for unit in units:
    print("true" if state[unit]["enabled"] else "false")
    print("true" if state[unit]["active"] else "false")
PY
    ); then
        printf '%s\n' 'interrupted activation journal is invalid; retaining rollback artifacts' >&2
        return 1
    fi
    mapfile -t fields <<<"$parsed"
    # reject truncated parser output before any rollback mutation
    if [[ ${#fields[@]} -ne 22 ]]; then
        printf '%s\n' 'interrupted activation journal is incomplete; retaining rollback artifacts' >&2
        return 1
    fi
    rollback_dir=${fields[0]}
    current_code=${fields[1]}
    previous_map=${fields[2]}
    legacy_layout=${fields[3]}
    app_release=${fields[4]}
    map_release=${fields[5]}
    # stop live candidate processes only during synchronous in-process rollback
    if [[ ${ADSB_BOOT_RECOVERY:-0} != 1 ]]; then
        systemctl stop adsb-alerts.service adsb-controller.service 2>/dev/null || true
    fi
    rollback_activation "$root" "$rollback_dir" "$current_code" "$previous_map" \
        "$legacy_layout" "$app_release" "$map_release" true || return
    systemctl daemon-reload || return
    index=6
    # restore fixed unit enablement before process activity
    for unit in "${ACTIVATION_STATE_UNITS[@]}"; do
        # keep boot recovery enabled until the journal is durably gone
        if [[ "$unit" != adsb-activation-recovery.service ]]; then
            restore_activation_enablement "$unit" "${fields[$index]}" || return
        fi
        index=$((index + 2))
    done
    index=6
    # restore activity except the currently executing recovery unit
    for unit in "${ACTIVATION_STATE_UNITS[@]}"; do
        if [[ "$unit" != adsb-activation-recovery.service ]]; then
            restore_activation_activity "$unit" "${fields[$((index + 1))]}" || return
        fi
        index=$((index + 2))
    done
    # flush restored files and enablement links before committing recovery
    sync -f "$root/opt/adsb" "$root/etc" "$root/var/lib/adsb" "$root/usr/local/sbin" || return
    clear_activation_journal "$root" || return
    # restore prior guards only after the rolled-back state is committed
    for artifact in "${APPLICATION_UNIT_ARTIFACTS[@]}"; do
        restore_activation_file "$rollback_dir" "$root${artifact%%|*}" "${artifact##*|}" || return
    done
    restore_activation_enablement adsb-activation-recovery.service "${fields[20]}" || return
    systemctl daemon-reload || return
    sync -f "$root/etc" || return
    rm -rf -- "$app_release" "$map_release" "$rollback_dir"
}
