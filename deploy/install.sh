#!/usr/bin/env bash
# install only this application and its required container runtime
set -euo pipefail

# require explicit privilege rather than attempting alternative escalation
if [[ ${EUID} -ne 0 ]]; then
    printf '%s\n' 'run this installer with authorized sudo access' >&2
    exit 1
fi

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_MODE=install
ADMIN_ENV=""
# accept only one documented installer mode
if [[ $# -eq 1 && $1 == --update ]]; then
    INSTALL_MODE=update
    ADMIN_ENV=/etc/adsb/admin.env
elif [[ $# -eq 1 && $1 == --recover-only ]]; then
    INSTALL_MODE=recover
elif [[ $# -eq 1 && $1 != --* ]]; then
    ADMIN_ENV=$1
else
    printf '%s\n' 'usage: install.sh ADMIN_ENV | --update | --recover-only' >&2
    exit 64
fi

# load fixed transaction and recovery operations before taking the global lock
# shellcheck source=deploy/release-transaction.sh
source "$SOURCE_DIR/deploy/release-transaction.sh"

# skip only a validated live activation when systemd starts boot recovery
if [[ "$INSTALL_MODE" == recover && ${ADSB_BOOT_RECOVERY:-0} == 1 ]]; then
    if prepare_activation_lock "" nonblocking; then
        :
    else
        lock_status=$?
        # only explicit lock contention permits dependency startup
        if [[ "$lock_status" == 75 ]]; then
            exit 0
        fi
        exit "$lock_status"
    fi
else
    prepare_activation_lock
fi

# finish any durable interrupted transaction before accepting new activation work
recover_activation ""
# stop after recovery when invoked by the boot recovery unit
if [[ "$INSTALL_MODE" == recover ]]; then
    exit 0
fi

# reject a stale staged update after recovery while still holding the activation lock
if [[ "$INSTALL_MODE" == update ]]; then
    UPDATE_BASE=${ADSB_UPDATE_BASE_RELEASE:-}
    if [[ ! "$UPDATE_BASE" =~ ^/opt/adsb/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ ]] || \
        [[ ! -L /opt/adsb/current ]] || [[ $(readlink -f /opt/adsb/current) != "$UPDATE_BASE" ]]; then
        printf '%s\n' 'automatic update base release changed; rediscovery is required' >&2
        exit 1
    fi
fi

# validate the selected secret source without printing its contents
if [[ ! -s "$ADMIN_ENV" ]] || ! grep -q '^ADSB_ADMIN_PASSWORD_HASH=' "$ADMIN_ENV"; then
    printf '%s\n' 'admin environment must contain a password hash' >&2
    exit 1
fi

# reject an automatic update when the installed bootstrap contract is incomplete
if [[ "$INSTALL_MODE" == update ]]; then
    REQUIRED_UPDATE_COMMANDS=(docker flock install python3 systemctl systemd-analyze tar)
    # require every command used by immutable staging and activation
    for command in "${REQUIRED_UPDATE_COMMANDS[@]}"; do
        command -v "$command" >/dev/null || {
            printf '%s\n' "automatic update prerequisite is missing: $command" >&2
            exit 1
        }
    done
    # require the existing dedicated account and fixed verifier
    if ! id adsb >/dev/null 2>&1 || [[ ! -x /usr/sbin/visudo ]]; then
        printf '%s\n' 'automatic update bootstrap is incomplete' >&2
        exit 1
    fi
    REQUIRED_UPDATE_DIRECTORIES=(
        /opt/adsb/releases
        /opt/adsb/map-ui-releases
        /var/lib/adsb/config
        /var/lib/adsb/alerts
        /var/lib/adsb/alert-source/1090
        /var/lib/adsb/alert-source/978
        /var/lib/adsb/runtime
        /var/lib/adsb/status
    )
    # require all persistent directories before creating a candidate release
    for directory in "${REQUIRED_UPDATE_DIRECTORIES[@]}"; do
        if [[ ! -d "$directory" || -L "$directory" ]]; then
            printf '%s\n' "automatic update directory is invalid: $directory" >&2
            exit 1
        fi
    done
    # require the already bootstrapped container daemon
    if ! systemctl is-active --quiet docker.service; then
        printf '%s\n' 'automatic update requires the active Docker service' >&2
        exit 1
    fi
fi

# bootstrap packages and the service account only during an operator installation
if [[ "$INSTALL_MODE" == install ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install --no-install-recommends -y docker.io docker-compose-v2 python3 ca-certificates curl unattended-upgrades age
    systemctl enable --now docker

    # use a dedicated unprivileged web account without Docker group membership
    if ! id adsb >/dev/null 2>&1; then
        useradd --system --home-dir /var/lib/adsb --shell /usr/sbin/nologin adsb
    fi
    # remove any pre-existing supplementary privilege groups from the dedicated service account
    usermod -G '' adsb
    install -d -m 755 /opt/adsb /opt/adsb/releases /etc/adsb /var/lib/adsb
    install -d -o adsb -g adsb -m 700 /var/lib/adsb/config
    install -d -o adsb -g adsb -m 700 /var/lib/adsb/alerts
    install -d -o root -g adsb -m 2750 /var/lib/adsb/alert-source
    install -d -o root -g adsb -m 2750 /var/lib/adsb/alert-source/1090 /var/lib/adsb/alert-source/978
    install -d -o root -g adsb -m 2750 /var/lib/adsb/status
    install -d -m 700 /var/lib/adsb/runtime /var/lib/adsb/cloudflared
    install -d -m 755 /var/lib/adsb/tar1090 /var/lib/adsb/collectd
    install -d -m 700 /var/lib/adsb/piaware
    # restrict status created by an earlier release
    if [[ -e /var/lib/adsb/status/status.json ]]; then
        chown root:adsb /var/lib/adsb/status/status.json
        chmod 640 /var/lib/adsb/status/status.json
    fi
fi

# stage one exact application tree before changing the selected release
RELEASE_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ACTIVATION_ID=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
APP_RELEASE="/opt/adsb/releases/$RELEASE_ID"
MAP_RELEASE="/opt/adsb/map-ui-releases/$RELEASE_ID"
ROLLBACK_DIR="/var/lib/adsb/runtime/activation-$RELEASE_ID"
ACTIVATION_STARTED=false
ACTIVATION_COMPLETE=false
APPLICATION_READY=false
CURRENT_CODE=""
PREVIOUS_MAP=""
LEGACY_LAYOUT=false
TEMP_PATHS=()

# retain prior unit state for rollback and durable crash recovery
TIMER_UNITS=(adsb-maintenance.timer apt-daily.timer apt-daily-upgrade.timer)
declare -A UNIT_WAS_ENABLED UNIT_WAS_ACTIVE
# record every fixed unit without rejecting a first installation
for unit in "${ACTIVATION_STATE_UNITS[@]}"; do
    UNIT_WAS_ENABLED[$unit]=false
    UNIT_WAS_ACTIVE[$unit]=false
    # retain prior enablement
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        UNIT_WAS_ENABLED[$unit]=true
    fi
    # retain prior process or schedule activity
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        UNIT_WAS_ACTIVE[$unit]=true
    fi
done

# remove only auxiliary source containers from a failed activation
remove_alert_source_containers() {
    local service identifier
    local -a identifiers
    # inspect each fixed auxiliary service independently
    for service in alert-source-1090 alert-source-978fallback; do
        mapfile -t identifiers < <(docker ps -aq \
            --filter label=com.docker.compose.project=adsb \
            --filter "label=com.docker.compose.service=$service")
        # remove only validated Docker identifiers
        for identifier in "${identifiers[@]}"; do
            # refuse unexpected command output during rollback
            if [[ $identifier =~ ^[a-f0-9]{12,64}$ ]]; then
                docker rm -f "$identifier" >/dev/null 2>&1
            fi
        done
    done
}

# roll back every selected host artifact when activation fails
cleanup_install() {
    local exit_code=$?
    local rollback_failed=false
    local temporary
    trap - EXIT
    set +e
    # replay the durable journal after any activation mutation
    if [[ "$ACTIVATION_STARTED" == true && "$ACTIVATION_COMPLETE" != true ]]; then
        # recover only after the durable journal exists
        if [[ -e /var/lib/adsb/runtime/activation-journal.json || -L /var/lib/adsb/runtime/activation-journal.json ]]; then
            systemctl stop adsb-alerts.service adsb-controller.service 2>/dev/null
            remove_alert_source_containers
            # recover_activation validates then calls rollback_activation
            # retain all recovery inputs when exact rollback fails
            if ! recover_activation ""; then
                rollback_failed=true
                printf '%s\n' 'activation rollback failed; retained journal and rollback artifacts' >&2
            fi
        else
            rm -rf -- "$ROLLBACK_DIR"
        fi
    fi
    # remove an unselected release when no durable recovery remains
    if [[ "$ACTIVATION_COMPLETE" != true && "$rollback_failed" != true ]]; then
        rm -rf -- "$APP_RELEASE" "$MAP_RELEASE"
    fi
    # remove staged host files without retaining secret copies
    for temporary in "${TEMP_PATHS[@]}"; do
        rm -f -- "$temporary"
    done
    # remove pre-journal rollback data only when no recovery failed
    if [[ "$ACTIVATION_STARTED" != true && "$rollback_failed" != true ]]; then
        rm -rf -- "$ROLLBACK_DIR"
    fi
    exit "$exit_code"
}
trap cleanup_install EXIT

# identify the current exact tree across legacy and release-based installs
if [[ -L /opt/adsb/current ]]; then
    CURRENT_CODE=$(readlink -f /opt/adsb/current)
    # reject a pointer outside the managed immutable release root
    if [[ "$CURRENT_CODE" != /opt/adsb/releases/* ]]; then
        printf '%s\n' '/opt/adsb/current points outside the managed release root' >&2
        exit 1
    fi
# retain one migration path from the original direct-copy layout
elif [[ -d /opt/adsb/adsb_admin ]]; then
    CURRENT_CODE=/opt/adsb
    LEGACY_LAYOUT=true
# refuse to replace an unexpected current directory
elif [[ -e /opt/adsb/current ]]; then
    printf '%s\n' '/opt/adsb/current must be a managed symlink' >&2
    exit 1
fi
# retain the historical map target for rollback
if [[ -L /opt/adsb/map-ui ]]; then
    PREVIOUS_MAP=$(readlink -f /opt/adsb/map-ui)
    # reject a pointer outside the managed immutable map root
    if [[ "$PREVIOUS_MAP" != /opt/adsb/map-ui-releases/* ]]; then
        printf '%s\n' '/opt/adsb/map-ui points outside the managed release root' >&2
        exit 1
    fi
fi

# preserve a durable code archive before preparing activation
if [[ -n "$CURRENT_CODE" ]]; then
    BACKUP="/var/lib/adsb/runtime/code-$RELEASE_ID.tar.gz"
    tar -czf "$BACKUP" -C "$CURRENT_CODE" adsb_admin web deploy
fi

# build the exact code and verified map releases without touching live pointers
install -d -o root -g root -m 755 "$APP_RELEASE" /opt/adsb/map-ui-releases
cp -a "$SOURCE_DIR/adsb_admin" "$SOURCE_DIR/web" "$SOURCE_DIR/deploy" "$APP_RELEASE/"
# exclude local interpreter caches from the production release
find "$APP_RELEASE" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$APP_RELEASE" -type d -name __pycache__ -empty -delete
chown -R root:root "$APP_RELEASE"
chmod -R go-w "$APP_RELEASE"
python3 "$APP_RELEASE/deploy/prepare-map-ui.py" "$MAP_RELEASE"
ln -s "$MAP_RELEASE" "$APP_RELEASE/map-ui"

# validate the private environment without printing secret values
python3 -B - "$APP_RELEASE" "$ADMIN_ENV" <<'PY'
import shlex
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from adsb_admin.auth import load_password_hash
from adsb_admin.server import _canonical_frame_origin

values = {}
# parse only the two documented systemd environment keys
for raw_line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    # ignore blank and comment-only lines
    if not line or line.startswith("#"):
        continue
    key, separator, raw_value = line.partition("=")
    # reject commands, unknown keys and duplicate configuration
    if separator != "=" or key not in {"ADSB_ADMIN_PASSWORD_HASH", "ADSB_ADMIN_FRAME_ORIGIN"} or key in values:
        raise ValueError("admin environment contains an unsupported setting")
    parsed = shlex.split(raw_value, comments=True, posix=True)
    # require one bounded scalar value
    if len(parsed) != 1 or len(parsed[0]) > 1024:
        raise ValueError("admin environment contains an invalid value")
    values[key] = parsed[0]
load_password_hash(value=values.get("ADSB_ADMIN_PASSWORD_HASH"))
# validate optional embedding before activation
if "ADSB_ADMIN_FRAME_ORIGIN" in values:
    _canonical_frame_origin(values["ADSB_ADMIN_FRAME_ORIGIN"])
PY

# validate the fixed alert source scripts and selection before activation
bash -n "$APP_RELEASE/deploy/alerts/run-source.sh" "$APP_RELEASE/deploy/alerts/source-health.sh"
[[ -x "$APP_RELEASE/deploy/alerts/run-source.sh" && -x "$APP_RELEASE/deploy/alerts/source-health.sh" ]] || {
    printf '%s\n' 'alert source scripts must be executable' >&2
    exit 1
}
python3 -B - "$APP_RELEASE" <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from adsb_admin.controller import validate_source_contract, validate_source_proof
from datetime import datetime, timezone

release = Path(sys.argv[1])
contract = release / "deploy/alerts/source-contract.json"
validate_source_contract(json.loads(contract.read_text(encoding="utf-8")))
proof_path = release / "deploy/alerts/source-proof.json"
# reject oversized evidence before the activation transaction
if proof_path.stat().st_size > 64 * 1024:
    raise SystemExit("alert source proof is oversized")
proof = json.loads(proof_path.read_text(encoding="utf-8"))
images = json.loads((release / "deploy/images.json").read_text(encoding="utf-8"))
catalog = json.loads((release / "deploy/alerts/catalog-manifest.json").read_text(encoding="utf-8"))
validate_source_proof(proof, images, (release / "deploy/alerts/source-health.sh").read_bytes(), catalog["entry_count"])
captured = datetime.strptime(proof["production_headroom"]["captured_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
# require a fresh capacity observation for this activation, not steady reconciliation
if not 0 <= (datetime.now(timezone.utc) - captured).total_seconds() <= 86400:
    raise SystemExit("alert source headroom proof is stale")
PY

# verify the private publication and worker-state ownership contract
[[ $(stat -c '%U:%G:%a' /var/lib/adsb/alerts) == adsb:adsb:700 &&
   $(stat -c '%U:%G:%a' /var/lib/adsb/alert-source) == root:adsb:2750 &&
   $(stat -c '%U:%G:%a' /var/lib/adsb/alert-source/1090) == root:adsb:2750 &&
   $(stat -c '%U:%G:%a' /var/lib/adsb/alert-source/978) == root:adsb:2750 ]] || {
    printf '%s\n' 'alert state directory permissions are invalid' >&2
    exit 1
}

# seed or validate disabled private alert settings before the read-only worker starts
python3 -B - "$APP_RELEASE" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from adsb_admin.alert_config import AlertSettingsStore

path = Path("/var/lib/adsb/config/alerts.json")
AlertSettingsStore(path)
PY
chown adsb:adsb /var/lib/adsb/config/alerts.json
chmod 600 /var/lib/adsb/config/alerts.json

# verify image availability before any live file or pointer changes
python3 - "$APP_RELEASE" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

# pull every immutable image named by the staged release
for image in json.loads((Path(sys.argv[1]) / "deploy/images.json").read_text()).values():
    subprocess.run(["docker", "pull", "--platform", "linux/amd64", image], check=True)
PY

# stage and validate every host integration artifact on its destination filesystem
ADMIN_TEMP="/etc/adsb/admin.env.$$.next"
RUNTIME_TEMP="/etc/adsb/runtime.json.$$.next"
STACK_TEMP="/usr/local/sbin/adsb-stack.$$.next"
SUDOERS_TEMP="/etc/sudoers.d/adsb-stack.$$.next"
ADMIN_UNIT_TEMP="/etc/systemd/system/adsb-admin.service.$$.next"
CONTROLLER_UNIT_TEMP="/etc/systemd/system/adsb-controller.service.$$.next"
ALERTS_UNIT_TEMP="/etc/systemd/system/adsb-alerts.service.$$.next"
UPDATER_UNIT_TEMP="/etc/systemd/system/adsb-updater.service.$$.next"
UPDATER_PATH_TEMP="/etc/systemd/system/adsb-updater.path.$$.next"
RECOVERY_UNIT_TEMP="/etc/systemd/system/adsb-activation-recovery.service.$$.next"
DOCKER_GUARD_TEMP="/etc/systemd/system/docker.service.d/20-adsb-recovery.conf.$$.next"
TEMP_PATHS+=("$ADMIN_TEMP" "$RUNTIME_TEMP" "$STACK_TEMP" "$SUDOERS_TEMP" "$ADMIN_UNIT_TEMP" \
    "$CONTROLLER_UNIT_TEMP" "$ALERTS_UNIT_TEMP" "$UPDATER_UNIT_TEMP" "$UPDATER_PATH_TEMP" "$RECOVERY_UNIT_TEMP" "$DOCKER_GUARD_TEMP")
install -o root -g root -m 600 "$ADMIN_ENV" "$ADMIN_TEMP"
install -o root -g root -m 755 "$APP_RELEASE/deploy/adsb-stack" "$STACK_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-admin.service" "$ADMIN_UNIT_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-controller.service" "$CONTROLLER_UNIT_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-alerts.service" "$ALERTS_UNIT_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-updater.service" "$UPDATER_UNIT_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-updater.path" "$UPDATER_PATH_TEMP"
install -d -o root -g root -m 755 /etc/systemd/system/docker.service.d
install -o root -g root -m 644 "$APP_RELEASE/deploy/docker-recovery.conf" "$DOCKER_GUARD_TEMP"
# bind boot recovery to the exact installer that understands this journal schema
python3 -B - "$APP_RELEASE/deploy/adsb-activation-recovery.service" "$RECOVERY_UNIT_TEMP" \
    "$APP_RELEASE/deploy/install.sh" <<'PY'
import os
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
installer = sys.argv[3]
recovery_template = source.read_text(encoding="utf-8")
# replace exactly one reviewed non-shell placeholder
if recovery_template.count("@ADSB_RECOVERY_INSTALLER@") != 1:
    raise ValueError("recovery unit template is invalid")
destination.write_text(
    recovery_template.replace("@ADSB_RECOVERY_INSTALLER@", installer),
    encoding="utf-8",
)
os.chown(destination, 0, 0)
os.chmod(destination, 0o644)
PY
# prepare weekly maintenance files without modifying active host configuration
for artifact in "${MAINTENANCE_ARTIFACTS[@]}"; do
    destination="${artifact%%|*}"
    install -d -o root -g root -m 755 "$(dirname -- "$destination")"
    temporary="$destination.$$.next"
    install -o root -g root -m 644 "$APP_RELEASE/deploy/${artifact##*|}" "$temporary"
    TEMP_PATHS+=("$temporary")
done
cat >"$SUDOERS_TEMP" <<'EOF'
admin ALL=(root) NOPASSWD: /usr/local/sbin/adsb-stack status, /usr/local/sbin/adsb-stack start, /usr/local/sbin/adsb-stack stop, /usr/local/sbin/adsb-stack restart
EOF
chmod 440 "$SUDOERS_TEMP"
/usr/sbin/visudo -cf "$SUDOERS_TEMP"
systemd-analyze verify "$APP_RELEASE/deploy/adsb-admin.service" "$APP_RELEASE/deploy/adsb-controller.service" \
    "$APP_RELEASE/deploy/adsb-alerts.service" "$APP_RELEASE/deploy/adsb-maintenance.service" \
    "$APP_RELEASE/deploy/adsb-maintenance.timer" "$APP_RELEASE/deploy/adsb-updater.service" \
    "$APP_RELEASE/deploy/adsb-updater.path" "$APP_RELEASE/deploy/adsb-activation-recovery.service"

# prepare the next runtime document while preserving the existing tunnel choice
python3 -B - "$APP_RELEASE" "$RUNTIME_TEMP" "$ACTIVATION_ID" <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from adsb_admin.controller import write_json

runtime_path = Path("/etc/adsb/runtime.json")
runtime = json.loads(runtime_path.read_text()) if runtime_path.exists() else {}
runtime.update(
    source_dir="/opt/adsb/current",
    data_dir="/var/lib/adsb",
    activation_id=sys.argv[3],
    images=json.loads((Path(sys.argv[1]) / "deploy/images.json").read_text()),
)
runtime.setdefault("tunnel_enabled", False)
write_json(Path(sys.argv[2]), runtime)
PY

# snapshot live integration files for an exact rollback
install -d -o root -g root -m 700 "$ROLLBACK_DIR"
backup_activation_files "" "$ROLLBACK_DIR"

# persist exact fixed unit states without executable recovery data
JOURNAL_UNIT_STATES=()
for unit in "${ACTIVATION_STATE_UNITS[@]}"; do
    JOURNAL_UNIT_STATES+=("${UNIT_WAS_ENABLED[$unit]}" "${UNIT_WAS_ACTIVE[$unit]}")
done
# make rollback files durable before publishing their journal
sync -f "$ROLLBACK_DIR"
# route every later failure through durable recovery
ACTIVATION_STARTED=true
write_activation_journal "" "$ROLLBACK_DIR" "$CURRENT_CODE" "$PREVIOUS_MAP" "$LEGACY_LAYOUT" \
    "$APP_RELEASE" "$MAP_RELEASE" "$ACTIVATION_ID" "${JOURNAL_UNIT_STATES[@]}"

# activate the prepared release and host files under rollback protection
# install boot recovery before selecting the new application pointer
mv -f "$RECOVERY_UNIT_TEMP" /etc/systemd/system/adsb-activation-recovery.service
# publish every failure-propagating guard before selecting candidate code
mv -f "$ADMIN_UNIT_TEMP" /etc/systemd/system/adsb-admin.service
mv -f "$CONTROLLER_UNIT_TEMP" /etc/systemd/system/adsb-controller.service
mv -f "$ALERTS_UNIT_TEMP" /etc/systemd/system/adsb-alerts.service
mv -f "$UPDATER_UNIT_TEMP" /etc/systemd/system/adsb-updater.service
mv -f "$UPDATER_PATH_TEMP" /etc/systemd/system/adsb-updater.path
mv -f "$DOCKER_GUARD_TEMP" /etc/systemd/system/docker.service.d/20-adsb-recovery.conf
sync -f /etc/systemd/system "$APP_RELEASE"
systemctl daemon-reload
systemctl enable adsb-activation-recovery.service
# stop the old worker before changing its immutable release pointer
worker_load_state=$(systemctl show adsb-alerts.service --property=LoadState --value)
# a first installation has no existing worker to drain
if [[ "$worker_load_state" != not-found ]]; then
    systemctl stop adsb-alerts
fi
ln -s "$APP_RELEASE" "/opt/adsb/current.$$.next"
mv -Tf "/opt/adsb/current.$$.next" /opt/adsb/current
ln -s "$MAP_RELEASE" "/opt/adsb/map-ui.$$.next"
mv -Tf "/opt/adsb/map-ui.$$.next" /opt/adsb/map-ui
mv -f "$ADMIN_TEMP" /etc/adsb/admin.env
mv -f "$RUNTIME_TEMP" /etc/adsb/runtime.json
mv -f "$STACK_TEMP" /usr/local/sbin/adsb-stack
mv -f "$SUDOERS_TEMP" /etc/sudoers.d/adsb-stack
# select reviewed weekly schedules alongside the application release
for artifact in "${MAINTENANCE_ARTIFACTS[@]}"; do
    destination="${artifact%%|*}"
    mv -f "$destination.$$.next" "$destination"
done
systemctl daemon-reload
systemctl enable adsb-admin adsb-controller adsb-alerts
systemctl restart adsb-admin adsb-controller
systemctl restart adsb-alerts

# require the complete controller and container projection before accepting activation
for _attempt in $(seq 1 45); do
    # stop waiting only after every declared service reaches full readiness
    if stack_status=$(/usr/local/sbin/adsb-stack status 2>/dev/null) && \
        printf '%s' "$stack_status" | python3 -c \
            'import json,sys; value=json.load(sys.stdin); raise SystemExit(not (value.get("state") == "running" and value.get("alerts", {}).get("infrastructure_ready") is True))'; then
        APPLICATION_READY=true
        break
    fi
    sleep 2
done
# trigger the rollback trap when bounded readiness expires
if [[ "$APPLICATION_READY" != true ]]; then
    printf '%s\n' 'activation readiness failed; restoring the previous release' >&2
    exit 1
fi

# enable scheduled work only after application readiness has been verified
systemctl enable "${TIMER_UNITS[@]}"
systemctl restart "${TIMER_UNITS[@]}"
# start update request observation only after application readiness
systemctl enable adsb-updater.path
systemctl restart adsb-updater.path
# flush selected pointers and host integration before committing activation
sync -f /opt/adsb /etc /var/lib/adsb /usr/local/sbin
clear_activation_journal ""
ACTIVATION_COMPLETE=true
rm -rf -- "$ROLLBACK_DIR"

# remove inactive legacy code only after successful activation
if [[ "$LEGACY_LAYOUT" == true ]]; then
    rm -rf -- /opt/adsb/adsb_admin /opt/adsb/web /opt/adsb/deploy
fi
printf '%s\n' 'application installed and verified at http://127.0.0.1:8080'
