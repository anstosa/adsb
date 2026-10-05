#!/usr/bin/env bash
set -euo pipefail

original=${SSH_ORIGINAL_COMMAND:-}

# accept only fixed backup verbs
[[ "$original" == backup-proof || "$original" == backup-stream ]] || {
    printf '%s\n' 'operation denied' >&2
    exit 126
}

exec sudo -n /usr/local/sbin/adsb-backup-remote-ops "$original"
