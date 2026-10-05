#!/usr/bin/env bash
# run one fixed physical receiver source without feeder or mlat inputs
set -euo pipefail
umask 0027

output_dir=/var/lib/adsb/alert-source

# accept only the release-rendered source contract
case "${ALERT_SOURCE_BAND:-}" in
    1090)
        expected_service=airspy
        expected_port=30005
        expected_protocol=beast_in
        ;;
    978)
        expected_service=dump978
        expected_port=30978
        expected_protocol=uat_in
        ;;
    *)
        printf '%s\n' 'invalid alert source band' >&2
        exit 64
        ;;
esac

# reject altered connector or activation values
[[ ${ALERT_SOURCE_INPUT_SERVICE:-} == "$expected_service" &&
   ${ALERT_SOURCE_INPUT_PORT:-} == "$expected_port" &&
   ${ALERT_SOURCE_PROTOCOL:-} == "$expected_protocol" &&
   ${ALERT_SOURCE_ACTIVATION_ID:-} =~ ^[0-9a-f]{32}$ &&
   ${ALERT_SOURCE_CONTRACT_DIGEST:-} =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s\n' 'invalid alert source contract' >&2
    exit 64
}

# require the narrow setgid publication directory
[[ -d "$output_dir" && ! -L "$output_dir" ]] || {
    printf '%s\n' 'invalid alert source output directory' >&2
    exit 73
}

generation=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')
started_at=$(/usr/bin/date --utc +%Y-%m-%dT%H:%M:%SZ)

# publish an atomic generation marker before decoder startup
/usr/bin/python3 - "$output_dir" "$ALERT_SOURCE_BAND" "$generation" "$started_at" \
    "$ALERT_SOURCE_ACTIVATION_ID" "$ALERT_SOURCE_CONTRACT_DIGEST" <<'PY'
import json
import os
import sys
from pathlib import Path

output = Path(sys.argv[1])
marker = {
    "schema_version": 1,
    "band": sys.argv[2],
    "generation": sys.argv[3],
    "started_at": sys.argv[4],
    "activation_id": sys.argv[5],
    "contract_digest": sys.argv[6],
}
temporary = output / "source-marker.json.tmp"
with temporary.open("w", encoding="utf-8") as stream:
    json.dump(marker, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(temporary, 0o640)
os.replace(temporary, output / "source-marker.json")
PY

# replace the image init stack with one bounded physical-input tracker
exec /usr/local/bin/readsb \
    --net-only \
    --quiet \
    --net-connector="${ALERT_SOURCE_INPUT_SERVICE},${ALERT_SOURCE_INPUT_PORT},${ALERT_SOURCE_PROTOCOL}" \
    --net-connector-delay=5 \
    --write-json="$output_dir" \
    --write-json-every=1 \
    --stats-every=10
