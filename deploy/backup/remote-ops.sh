#!/usr/bin/env bash
set -euo pipefail

# require root execution through sudo
[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    printf '%s\n' 'error: remote operations must run through sudo' >&2
    exit 1
}
(($# == 1)) || {
    printf '%s\n' 'error: invalid arguments' >&2
    exit 2
}

# expose only backup reads
case "$1" in
    backup-proof) exec /opt/adsb/current/deploy/backup/backup-proof.sh ;;
    backup-stream) exec /opt/adsb/current/deploy/backup/backup-stream.sh ;;
    *) printf '%s\n' 'error: operation denied' >&2; exit 126 ;;
esac
