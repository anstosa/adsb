#!/usr/bin/env bash
set -euo pipefail

# delegate through the selected immutable release
exec /opt/adsb/current/deploy/backup/remote-ops.sh "$@"
