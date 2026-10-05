#!/usr/bin/env bash
set -euo pipefail

recipient_file=/etc/adsb-backup/recipient.txt
proof_command=/opt/adsb/current/deploy/backup/backup-proof.sh
umask 077

# require fixed root-owned inputs
[[ ${EUID:-$(id -u)} -eq 0 && -x "$proof_command" && -f "$recipient_file" ]] || {
    printf '%s\n' 'SOURCE_STATE_MISMATCH' >&2
    exit 1
}

# prove source state before reads
proof=$($proof_command)
recipient=$(<"$recipient_file")
app_release=$(printf '%s\n' "$proof" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["applicationRelease"])')
map_release=$(printf '%s\n' "$proof" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["mapRelease"])')
app_path="opt/adsb/releases/$app_release"
map_path="opt/adsb/map-ui-releases/$map_release"
scratch=$(/usr/bin/mktemp -d /run/adsb-backup.XXXXXXXX)

# remove only the volatile manifest
cleanup() {
    /usr/bin/rm -rf -- "$scratch"
}
trap cleanup EXIT

captured_at=$(/usr/bin/date --utc +%Y-%m-%dT%H:%M:%SZ)
/usr/bin/printf '{"schemaVersion":1,"service":"adsb","capturedAt":"%s","applicationRelease":"%s","mapRelease":"%s","settingsOwner":"adsb:adsb"}\n' \
    "$captured_at" "$app_release" "$map_release" >"$scratch/backup-manifest.json"

fixed_paths=(
    etc/adsb/admin.env
    etc/adsb/runtime.json
    etc/adsb-backup/recipient.txt
    var/lib/adsb/config/settings.json
    var/lib/adsb/cloudflared/config.yml
    var/lib/adsb/cloudflared/credentials.json
    etc/systemd/system/adsb-admin.service
    etc/systemd/system/adsb-controller.service
    etc/systemd/system/adsb-alerts.service
    etc/systemd/system/adsb-maintenance.service
    etc/systemd/system/adsb-maintenance.timer
    etc/systemd/system/apt-daily.timer.d/adsb-weekly.conf
    etc/systemd/system/apt-daily-upgrade.timer.d/adsb-weekly.conf
    etc/apt/apt.conf.d/52unattended-upgrades-adsb
    usr/local/bin/adsb-backup-ssh-dispatch
    usr/local/sbin/adsb-backup-remote-ops
    etc/sudoers.d/adsb-backup
    var/lib/adsb-backup/.ssh/authorized_keys
)

# preserve optional provider and host integration state
for path in \
    var/lib/adsb/piaware/feeder_id \
    var/lib/adsb/piaware/location \
    var/lib/adsb/piaware/location.env \
    etc/systemd/system/adsb-admin.service.d/20-frame-origin.conf \
    etc/systemd/system/reboot.target.d/90-adsb-recovery.conf; do
    # include only present regular files
    if [[ -f "/$path" && ! -L "/$path" ]]; then
        fixed_paths+=("$path")
    fi
done

# preserve optional private alert configuration and bounded encounter continuity
for path in \
    var/lib/adsb/config/alerts.json \
    var/lib/adsb/alerts/continuity.json; do
    # include only regular files already validated by the source proof
    if [[ -f "/$path" && ! -L "/$path" ]]; then
        fixed_paths+=("$path")
    fi
done

# stream only ciphertext to the caller
/usr/bin/tar --create --format=ustar --file=- \
    --directory "$scratch" backup-manifest.json \
    --directory / \
    --exclude="$app_path/map-ui" \
    --exclude="$map_path/db-3.14.1715" \
    --exclude="$map_path/config.js" \
    --exclude="$map_path/upintheair.json" \
    --transform="s#^$app_path#opt/adsb/current#" \
    --transform="s#^$map_path#opt/adsb/current/map-ui#" \
    "$app_path" "$map_path" "${fixed_paths[@]}" |
    /usr/bin/age --encrypt --recipient "$recipient"
