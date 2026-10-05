#!/usr/bin/env bash
# install only this application and its required container runtime
set -euo pipefail

# require explicit privilege rather than attempting alternative escalation
if [[ ${EUID} -ne 0 ]]; then
    printf '%s\n' 'run this installer with authorized sudo access' >&2
    exit 1
fi

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ADMIN_ENV=${1:?provide the private admin environment file}

# validate the supplied secret source without printing its contents
if [[ ! -s "$ADMIN_ENV" ]] || ! grep -q '^ADSB_ADMIN_PASSWORD_HASH=' "$ADMIN_ENV"; then
    printf '%s\n' 'admin environment must contain a password hash' >&2
    exit 1
fi

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

# load the isolated pointer and host-file rollback operations
# shellcheck source=deploy/release-transaction.sh
source "$SOURCE_DIR/deploy/release-transaction.sh"

# retain prior service activation state for rollback
ADMIN_WAS_ENABLED=false
CONTROLLER_WAS_ENABLED=false
ALERTS_WAS_ENABLED=false
ADMIN_WAS_ACTIVE=false
CONTROLLER_WAS_ACTIVE=false
ALERTS_WAS_ACTIVE=false
TIMER_UNITS=(adsb-maintenance.timer apt-daily.timer apt-daily-upgrade.timer)
declare -A TIMER_WAS_ENABLED TIMER_WAS_ACTIVE
# record the admin enablement state without failing on a new install
if systemctl is-enabled --quiet adsb-admin 2>/dev/null; then
    ADMIN_WAS_ENABLED=true
fi
# record the controller enablement state without failing on a new install
if systemctl is-enabled --quiet adsb-controller 2>/dev/null; then
    CONTROLLER_WAS_ENABLED=true
fi
# record notifier enablement without failing on a first install
if systemctl is-enabled --quiet adsb-alerts 2>/dev/null; then
    ALERTS_WAS_ENABLED=true
fi
# record the admin process state without failing on a new install
if systemctl is-active --quiet adsb-admin 2>/dev/null; then
    ADMIN_WAS_ACTIVE=true
fi
# record the controller process state without failing on a new install
if systemctl is-active --quiet adsb-controller 2>/dev/null; then
    CONTROLLER_WAS_ACTIVE=true
fi
# record notifier process state without failing on a first install
if systemctl is-active --quiet adsb-alerts 2>/dev/null; then
    ALERTS_WAS_ACTIVE=true
fi
# retain each timer's activation state for a failed installation
for timer in "${TIMER_UNITS[@]}"; do
    TIMER_WAS_ENABLED[$timer]=false
    TIMER_WAS_ACTIVE[$timer]=false
    # record prior enablement without rejecting an absent new timer
    if systemctl is-enabled --quiet "$timer" 2>/dev/null; then
        TIMER_WAS_ENABLED[$timer]=true
    fi
    # retain the previous running schedule
    if systemctl is-active --quiet "$timer" 2>/dev/null; then
        TIMER_WAS_ACTIVE[$timer]=true
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
    trap - EXIT
    set +e
    # restore the previous release and integration files after activation begins
    if [[ "$ACTIVATION_STARTED" == true && "$ACTIVATION_COMPLETE" != true ]]; then
        systemctl stop adsb-alerts 2>/dev/null
        systemctl stop adsb-controller 2>/dev/null
        remove_alert_source_containers
        systemctl stop "${TIMER_UNITS[@]}" 2>/dev/null
        rollback_activation "" "$ROLLBACK_DIR" "$CURRENT_CODE" "$PREVIOUS_MAP" "$LEGACY_LAYOUT" "$APP_RELEASE" "$MAP_RELEASE"
        systemctl daemon-reload
        # restore each timer without enabling work that was previously disabled
        for timer in "${TIMER_UNITS[@]}"; do
            # preserve prior enablement while removing new wants links
            if [[ "${TIMER_WAS_ENABLED[$timer]}" == true ]]; then
                systemctl enable "$timer"
            else
                systemctl disable "$timer" 2>/dev/null
            fi
            # restart only timers that were already running
            if [[ "${TIMER_WAS_ACTIVE[$timer]}" == true ]]; then
                systemctl start "$timer"
            fi
        done
        # restore the prior unit enablement state
        if [[ "$ADMIN_WAS_ENABLED" == true ]]; then
            systemctl enable adsb-admin
        else
            systemctl disable adsb-admin
        fi
        # restore the prior controller enablement state
        if [[ "$CONTROLLER_WAS_ENABLED" == true ]]; then
            systemctl enable adsb-controller
        else
            systemctl disable adsb-controller
        fi
        # restore the prior notifier enablement state
        if [[ "$ALERTS_WAS_ENABLED" == true ]]; then
            systemctl enable adsb-alerts
        else
            systemctl disable adsb-alerts 2>/dev/null
        fi
        # restore the prior admin process state
        if [[ "$ADMIN_WAS_ACTIVE" == true ]]; then
            systemctl restart adsb-admin
        else
            systemctl stop adsb-admin
        fi
        # restore the prior controller process state
        if [[ "$CONTROLLER_WAS_ACTIVE" == true ]]; then
            systemctl restart adsb-controller
        else
            systemctl stop adsb-controller
        fi
        # restart only a notifier that existed and was active before activation
        if [[ "$ALERTS_WAS_ACTIVE" == true ]]; then
            systemctl restart adsb-alerts
        else
            systemctl stop adsb-alerts 2>/dev/null
        fi
    fi
    # remove every unselected or failed release
    if [[ "$ACTIVATION_COMPLETE" != true ]]; then
        rm -rf -- "$APP_RELEASE" "$MAP_RELEASE"
    fi
    # remove staged host files without retaining secret copies
    for temporary in "${TEMP_PATHS[@]}"; do
        rm -f -- "$temporary"
    done
    rm -rf -- "$ROLLBACK_DIR"
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
TEMP_PATHS+=("$ADMIN_TEMP" "$RUNTIME_TEMP" "$STACK_TEMP" "$SUDOERS_TEMP" "$ADMIN_UNIT_TEMP" "$CONTROLLER_UNIT_TEMP" "$ALERTS_UNIT_TEMP")
install -o root -g root -m 600 "$ADMIN_ENV" "$ADMIN_TEMP"
install -o root -g root -m 755 "$APP_RELEASE/deploy/adsb-stack" "$STACK_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-admin.service" "$ADMIN_UNIT_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-controller.service" "$CONTROLLER_UNIT_TEMP"
install -o root -g root -m 644 "$APP_RELEASE/deploy/adsb-alerts.service" "$ALERTS_UNIT_TEMP"
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
    "$APP_RELEASE/deploy/adsb-maintenance.timer"

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

# activate the prepared release and host files under rollback protection
ACTIVATION_STARTED=true
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
mv -f "$ADMIN_UNIT_TEMP" /etc/systemd/system/adsb-admin.service
mv -f "$CONTROLLER_UNIT_TEMP" /etc/systemd/system/adsb-controller.service
mv -f "$ALERTS_UNIT_TEMP" /etc/systemd/system/adsb-alerts.service
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
ACTIVATION_COMPLETE=true

# remove inactive legacy code only after successful activation
if [[ "$LEGACY_LAYOUT" == true ]]; then
    rm -rf -- /opt/adsb/adsb_admin /opt/adsb/web /opt/adsb/deploy
fi
printf '%s\n' 'application installed and verified at http://127.0.0.1:8080'
