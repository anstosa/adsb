#!/usr/bin/env bash
# bind only the requested hostname to this station's loopback web proxy
set -euo pipefail

# require authorized host administration
if [[ ${EUID} -ne 0 ]]; then
    printf '%s\n' 'run this script with authorized sudo access' >&2
    exit 1
fi
TUNNEL_ID=${1:?provide the dedicated Cloudflare tunnel UUID}
CREDENTIALS=${2:?provide the private tunnel credentials JSON file}

# verify the origin before enabling an externally reachable connector
curl --fail --silent --show-error http://127.0.0.1:8080/healthz >/dev/null
curl --fail --silent --show-error http://127.0.0.1:8080/map/ >/dev/null

python3 - "$TUNNEL_ID" "$CREDENTIALS" <<'PY'
import json
import os
import sys
from pathlib import Path
from uuid import UUID
sys.path.insert(0, '/opt/adsb/current')
from adsb_admin.controller import write_json

tunnel_id = str(UUID(sys.argv[1]))
credentials = json.loads(Path(sys.argv[2]).read_text())
# reject a credential for another tunnel or an incomplete token file
if credentials.get('TunnelID') != tunnel_id or not credentials.get('TunnelSecret') or not credentials.get('AccountTag'):
    raise ValueError('tunnel credential identity mismatch')
directory = Path('/var/lib/adsb/cloudflared')
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
path = directory / 'credentials.json'
write_json(path, credentials)
configuration = directory / 'config.yml'
temporary = directory / 'config.yml.tmp'
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, 'w') as stream:
    stream.write(f'''# publish only the station web interface
tunnel: {tunnel_id}
credentials-file: /etc/cloudflared/credentials.json
metrics: 127.0.0.1:20242
ingress:
  - hostname: adsb.ballydidean.farm
    service: http://127.0.0.1:8080
  - service: http_status:404
''')
os.replace(temporary, configuration)
runtime_path = Path('/etc/adsb/runtime.json')
runtime = json.loads(runtime_path.read_text())
runtime['tunnel_enabled'] = True
write_json(runtime_path, runtime)
PY
systemctl restart adsb-controller
# confirm that the connector established an edge connection before reporting success
for _attempt in $(seq 1 30); do
    # the connector readiness endpoint confirms at least one edge connection
    if curl --fail --silent http://127.0.0.1:20242/ready >/dev/null; then
        printf '%s\n' 'connector connected; create/verify the matching DNS route and test the external HTTPS URL'
        exit 0
    fi
    sleep 2
done
printf '%s\n' 'connector readiness failed; inspect adsb-controller and cloudflared logs' >&2
exit 1
