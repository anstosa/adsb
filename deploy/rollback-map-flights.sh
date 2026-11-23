#!/usr/bin/env bash
# select a prior immutable release after removing map.flights settings
set -euo pipefail

# require the one release identity consumed by the transactional installer
if [[ $# -ne 1 || ! $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ ]]; then
    printf '%s\n' 'usage: rollback-map-flights.sh RELEASE' >&2
    exit 64
fi
# keep lock ownership and recovery inside one installer process
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "$SCRIPT_DIR/install.sh" --rollback-map-flights "$1"
