#!/usr/bin/env bash
set -euo pipefail

recipient_file=/etc/adsb-backup/recipient.txt
app_link=/opt/adsb/current
map_link=/opt/adsb/map-ui

# require exact root execution
[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}

# require one fixed file contract
require_file() {
    local path=$1
    local receipt=$2

    # reject missing or linked files
    [[ -f "$path" && ! -L "$path" && $(stat -c '%U:%G:%a' "$path") == "$receipt" ]] || {
        printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
        exit 1
    }
}

# require one fixed directory contract
require_directory() {
    local path=$1
    local receipt=$2

    # reject missing or linked directories
    [[ -d "$path" && ! -L "$path" && $(stat -c '%U:%G:%a' "$path") == "$receipt" ]] || {
        printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
        exit 1
    }
}

# require fixed backup tooling
for tool in /usr/bin/age /usr/bin/date /usr/bin/find /usr/bin/mktemp /usr/bin/python3 /usr/bin/readlink /usr/bin/rm /usr/bin/stat /usr/bin/tar; do
    [[ -x "$tool" ]] || {
        printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
        exit 1
    }
done

require_file "$recipient_file" root:root:600
require_file /etc/adsb/admin.env root:root:600
require_file /etc/adsb/runtime.json root:root:600
require_file /var/lib/adsb/config/settings.json adsb:adsb:600
require_file /var/lib/adsb/config/alerts.json adsb:adsb:600
require_file /var/lib/adsb/alerts/continuity.json adsb:adsb:600
require_file /var/lib/adsb/cloudflared/config.yml root:root:600
require_file /var/lib/adsb/cloudflared/credentials.json root:root:600
require_directory /var/lib/adsb/piaware root:root:700
require_file /etc/systemd/system/adsb-admin.service root:root:644
require_file /etc/systemd/system/adsb-controller.service root:root:644
require_file /etc/systemd/system/adsb-alerts.service root:root:644
require_file /etc/systemd/system/adsb-maintenance.service root:root:644
require_file /etc/systemd/system/adsb-maintenance.timer root:root:644
require_file /etc/systemd/system/apt-daily.timer.d/adsb-weekly.conf root:root:644
require_file /etc/systemd/system/apt-daily-upgrade.timer.d/adsb-weekly.conf root:root:644
require_file /etc/apt/apt.conf.d/52unattended-upgrades-adsb root:root:644
require_file /usr/local/bin/adsb-backup-ssh-dispatch root:root:755
require_file /usr/local/sbin/adsb-backup-remote-ops root:root:755
require_file /etc/sudoers.d/adsb-backup root:root:440
require_file /var/lib/adsb-backup/.ssh/authorized_keys root:root:644

recipient=$(<"$recipient_file")

# require one public age recipient
[[ "$recipient" == age1* || "$recipient" == ssh-* ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}

# bind selected immutable releases
[[ -L "$app_link" && -L "$map_link" ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}
app_release=$(/usr/bin/readlink -f -- "$app_link")
map_release=$(/usr/bin/readlink -f -- "$map_link")
[[ "$app_release" =~ ^/opt/adsb/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ &&
   "$map_release" =~ ^/opt/adsb/map-ui-releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ &&
   -d "$app_release" && -d "$map_release" ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}

# require the release-owned map selection
[[ -L "$app_release/map-ui" && $(/usr/bin/readlink -f -- "$app_release/map-ui") == "$map_release" ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}

# require the three pinned container-provided map links
[[ -L "$map_release/db-3.14.1715" && $(/usr/bin/readlink -- "$map_release/db-3.14.1715") == /usr/local/share/tar1090/html-webroot/db-3.14.1715 &&
   -L "$map_release/config.js" && $(/usr/bin/readlink -- "$map_release/config.js") == /usr/local/share/tar1090/html-webroot/config.js &&
   -L "$map_release/upintheair.json" && $(/usr/bin/readlink -- "$map_release/upintheair.json") == /usr/local/share/tar1090/html-webroot/upintheair.json ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}

# reject every other release link
[[ -z $(/usr/bin/find "$app_release" -type l ! -path "$app_release/map-ui" -print -quit) &&
   -z $(/usr/bin/find "$map_release" -type l \
       ! -path "$map_release/db-3.14.1715" \
       ! -path "$map_release/config.js" \
       ! -path "$map_release/upintheair.json" -print -quit) ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}

# validate private alert settings and continuity without touching the live queue
if ! /usr/bin/python3 -B - "$app_release" /var/lib/adsb/config/alerts.json \
    /var/lib/adsb/alerts/continuity.json >/dev/null 2>&1 <<'PY_ALERT_BACKUP_VALIDATION'
import json
import math
import os
import stat
import sys
from pathlib import Path

release = Path(sys.argv[1])
settings_path = Path(sys.argv[2])
continuity_path = Path(sys.argv[3])
sys.path.insert(0, str(release))

from adsb_admin.alert_catalog import normalize_icao
from adsb_admin.alert_config import AlertSettingsStore
from adsb_admin.alert_store import MAX_ENCOUNTERS

MAX_ALERT_SETTINGS_BYTES = 2 * 1024 * 1024
MAX_CONTINUITY_BYTES = 16 * 1024 * 1024


# read one regular file through a no-follow descriptor
def read_bounded(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        # reject linked, special, or oversized private input
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("invalid private backup artifact")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(maximum + 1)
    finally:
        os.close(descriptor)
    # reject growth during the bounded read
    if len(content) > maximum:
        raise ValueError("invalid private backup artifact")
    return content


# apply the release-owned complete settings validator
read_bounded(settings_path, MAX_ALERT_SETTINGS_BYTES)
AlertSettingsStore(settings_path, readonly=True)

# validate continuity without opening or restoring the live sqlite queue
value = json.loads(read_bounded(continuity_path, MAX_CONTINUITY_BYTES))
# require the exact secret-free snapshot schema
if (
    not isinstance(value, dict)
    or frozenset(value) != frozenset(("schema_version", "generation", "generated_at", "encounters"))
    or value.get("schema_version") != 1
    or not isinstance(value.get("generation"), str)
    or len(value["generation"]) > 100
    or not isinstance(value.get("encounters"), list)
    or len(value["encounters"]) > MAX_ENCOUNTERS
):
    raise ValueError("invalid alert continuity snapshot")
generated_at = value.get("generated_at")
# require a finite snapshot clock
if (
    isinstance(generated_at, bool)
    or not isinstance(generated_at, (int, float))
    or not math.isfinite(float(generated_at))
):
    raise ValueError("invalid alert continuity snapshot")
seen_hex_ids: set[str] = set()
# validate every row before certifying the encrypted stream
for row in value["encounters"]:
    expected = frozenset(("hex", "last_seen_at", "current_event_id", "required_bands", "rearmed_at"))
    # reject delivery fields and incomplete continuity rows
    if not isinstance(row, dict) or frozenset(row) != expected:
        raise ValueError("invalid alert continuity snapshot")
    hex_id = normalize_icao(row.get("hex"))
    last_seen_at = row.get("last_seen_at")
    current_event_id = row.get("current_event_id")
    required_bands = row.get("required_bands")
    rearmed_at = row.get("rearmed_at")
    # match the release restore validator and its unique sqlite identity constraint
    if (
        hex_id is None
        or hex_id in seen_hex_ids
        or isinstance(last_seen_at, bool)
        or not isinstance(last_seen_at, (int, float))
        or not math.isfinite(float(last_seen_at))
        or (
            current_event_id is not None
            and (not isinstance(current_event_id, str) or len(current_event_id) > 64)
        )
        or not isinstance(required_bands, list)
        or not required_bands
        or len(required_bands) != len(set(required_bands))
        or any(band not in ("1090", "978") for band in required_bands)
        or (
            rearmed_at is not None
            and (
                isinstance(rearmed_at, bool)
                or not isinstance(rearmed_at, (int, float))
                or not math.isfinite(float(rearmed_at))
            )
        )
        or (bool(current_event_id) and rearmed_at is not None)
    ):
        raise ValueError("invalid alert continuity snapshot")
    seen_hex_ids.add(hex_id)
PY_ALERT_BACKUP_VALIDATION
then
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
fi

printf '{"schemaVersion":1,"service":"adsb","applicationRelease":"%s","mapRelease":"%s","ready":true}\n' \
    "${app_release##*/}" "${map_release##*/}"
