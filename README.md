# Ballydidean Farm ADS-B station

Hardware-free production staging for an Airspy Mini (1090 MHz) and an ADSBx Orange RTL-SDR (978 MHz). The public map is at `/map/`; password-protected configuration is at `/admin`.

**Production target:** <https://adsb.ballydidean.farm/admin>. This URL is not evidence of deployment: verify it after installing the origin and enabling its dedicated Cloudflare Tunnel.

## Supported networks

- ADS-B Exchange
- FlightAware / PiAware
- ADSB.lol
- Airplanes.live

FR24 is deliberately excluded. All networks start disabled. Each network has an enabled switch, optional MLAT switch, and stable feeder UUID input. The admin page can generate local UUIDs for the three direct-feed networks; generation does not register a network account. FlightAware is different: PiAware must obtain a provider-issued ID after its first connection, which can then be [claimed](https://www.flightaware.com/adsb/piaware/claim) or replaced with an existing FlightAware ID when preserving a registered site.

Fill the station name, actual antenna latitude/longitude, and elevation in metres before enabling a feed. Saved UUIDs are masked and never returned by the settings API. Leaving a replacement field unchanged preserves the stored identifier; direct-feed clear controls remove their IDs. FlightAware's generated identity remains in its private PiAware cache rather than being treated as an operator-generated credential.

## Architecture and safety

- The Python standard-library web service runs as a dedicated `adsb` user. It cannot access Docker or modify application code.
- A separate root-owned controller revalidates settings and generates a fixed Docker Compose specification. The UI cannot choose commands, images, destinations, paths, or arbitrary environment variables.
- One ultrafeeder instance supplies `readsb`, `tar1090`, and the three direct network connectors. PiAware runs separately only when requested and receiver hardware is present.
- Airspy and dump978 containers start only when exactly one supported receiver of the corresponding type is detected. A detected serial is passed to the decoder. Multiple matching devices are not selected arbitrarily.
- No radio means no outbound uploaders, even if a switch has been enabled in advance. There is no production fixture input or simulated-aircraft generator.
- Only the loopback HTTP proxy is published by Cloudflare Tunnel. Raw receiver ports, Docker, and metrics are not public.
- Admin authentication uses a salted scrypt password hash, random server-side sessions, Secure/HttpOnly/SameSite cookies, CSRF protection, strict write origins, request limits, and login throttling. Optional embedding names one exact HTTPS parent and uses a separate partitioned cookie; it does not grant that parent API write access. Restarting the admin service invalidates sessions, but preserves settings.
- A failed configuration apply attempts to stop this project's potential uploaders. The UI reports deployment errors rather than claiming a failed switch was applied.

### Status meanings

`enabled` is the saved request; `applied_revision` identifies settings processed by the controller. A running uploader is not the same as a TCP connection, and neither proves acceptance by the upstream provider. Receiver USB presence does not prove successful RF reception. Missing connector telemetry remains unknown rather than being reported as a remote disconnection. Requested containers that stop or become unhealthy put the controller into an error phase and are force-recreated within the fixed Compose project. Without hardware, the expected state is an empty map and **awaiting radios**.

Until antenna coordinates are saved, the map shows a display-only U.S. overview; this is not a receiver position. The pinned tar1090 build has an upstream storage-proxy bug at an exactly zero map-center coordinate, so its initial view deliberately avoids zero. Optional terrain-outline data is not configured during hardware-free staging.

New browsers default to canvas aircraft icons because this tar1090 build's initial WebGL render can queue inactive chart layers and starve the selected basemap. Explicit browser preferences are preserved; if an existing WebGL-enabled browser shows a blank map, open `/map/?nowebgl=1` to select the working renderer.

### Experimental map UI

The local map uses Airplanes.live's experimental UI from [tar1090's public `prod` source](https://github.com/airplanes-live/tar1090/tree/0c4e109369620ac679ccc98ca3f090e0e41a3339), pinned to commit `0c4e109369620ac679ccc98ca3f090e0e41a3339`. The new interface is the default when no browser preference is saved. Use `/map/?legacyUI` for a temporary classic view, or **Settings → Switch to classic interface** for a persistent preference.

`deploy/map-ui.json` pins the source archive and its SHA-256. `python3 deploy/prepare-map-ui.py OUTPUT_DIR [LOCAL_ARCHIVE]` verifies that archive before preparing a new cache-busted asset directory. It refuses to overwrite an existing directory and includes the GPL v2-or-later license, upstream source archive, and version provenance. Generated assets are deployment artifacts, not hand-edited source.

Ultrafeeder serves this read-only bundle through its supported `CUSTOM_HTML` mount. Preparation disables the upstream global-aggregator default before cachebusting, so its normal local receiver data, history, generated station configuration, and image-pinned aircraft database remain in use; this does not display Airplanes.live's global traffic or enable its feed. The config/database symlinks depend on the pinned ultrafeeder image and must be revalidated when updating that image. Map tiles and optional aircraft imagery can still load from their upstream providers. Runtime UI updates remain disabled.

## Files and persistent state

| Path | Purpose |
| --- | --- |
| `/opt/adsb/current` | atomically selected exact application and map release |
| `/opt/adsb/releases` | immutable application releases retained for rollback |
| `/opt/adsb/map-ui` | compatibility pointer to the selected immutable custom UI release |
| `/opt/adsb/map-ui-releases` | verified UI releases retained for rollback |
| `/etc/adsb/admin.env` | root-only password hash, not plaintext |
| `/etc/adsb/runtime.json` | root-owned deployment image pins and tunnel flag |
| `/var/lib/adsb/config/settings.json` | private persistent station/network settings |
| `/var/lib/adsb/status/status.json` | private controller status and bounded claim route |
| `/var/lib/adsb/piaware` | private provider-assigned PiAware identity state |
| `/var/lib/adsb/runtime/compose.json` | private rendered container configuration |
| `/var/lib/adsb/cloudflared` | root-only tunnel credentials and ingress configuration |

Do not copy these private files into Git. `deploy/images.json` pins all container images by digest; image changes are deliberate updates rather than implicit pulls of mutable tags.

## Install on the receiver

Prerequisites: Ubuntu 24.04 amd64, SSH access, authorized sudo, outbound package/image access, and approximately 2 GiB RAM. The installer does not reboot, reinstall the OS, modify storage, or change unrelated services.

1. Generate a private environment file **outside this repository** using `adsb_admin.auth.make_password_hash`. Its required setting is `ADSB_ADMIN_PASSWORD_HASH='scrypt$...hash envelope...'`. Quoting is important if it is loaded by a shell; no plaintext password belongs in the file.
2. Transfer this repository's `adsb_admin`, `web`, and `deploy` directories to a staging directory on `adsb`; transfer the private environment file separately with restrictive permissions.
3. Run `sudo bash deploy/install.sh /path/to/private/admin.env`. It installs Ubuntu's Docker/Compose packages, pulls the pinned images, creates the unprivileged web user, and enables the two systemd services.
4. Verify `http://127.0.0.1:8080/healthz`, `/admin`, and `/map/` on the host. The map should be empty without radios. No network should be uploading.

The site password supplied during implementation is stored only as a hash under the operator's private `~/.adsb/admin.env`; it is not included here.

### Enroll FlightAware

For a new site, leave the FlightAware feeder ID blank, enable the feed, and save. PiAware connects without a preset `FEEDER_ID`, receives an ID from FlightAware, and preserves it under `/var/lib/adsb/piaware`. The authenticated admin status then exposes a fixed **Claim or view this FlightAware receiver** link. Claim the receiver, set its precise location and antenna height on the FlightAware statistics page, and confirm MLAT synchronization separately.

Enter a FlightAware feeder ID manually only when importing an existing registered site. The value must be the site's FlightAware-issued **Unique Identifier**; an arbitrary UUID will connect to the service but cannot create or claim a valid site. Do not clear PiAware's private cache during ordinary upgrades.

### Optional RemoteAgents embedding

Embedding is disabled by default: responses use `frame-ancestors 'none'`, `X-Frame-Options: DENY`, and the standalone `SameSite=Strict` session cookie. To permit this site inside one trusted RemoteAgents origin, add the following to the private `/etc/adsb/admin.env` and restart `adsb-admin`:

```sh
ADSB_ADMIN_FRAME_ORIGIN=https://framework.santosa.dev
```

The value must be one canonical HTTPS origin on the default port. Paths, credentials, wildcards, non-default ports, and additional origins are rejected at startup. In this mode the CSP names only that parent, `X-Frame-Options` is omitted, and authentication uses a distinct `Secure; HttpOnly; SameSite=None; Partitioned` cookie. API writes still require the exact child origin (`https://adsb.ballydidean.farm`), JSON, and CSRF; the configured parent is not a write origin and CORS remains disabled.

Partitioned storage means the embedded admin and a standalone tab have separate login sessions. Use a current Chromium browser or Safari 26.2+, whose partitioned-cookie support is described in [WebKit Features in Safari 26.2](https://webkit.org/blog/17640/webkit-features-for-safari-26-2/). In an older browser, an embedded login may remain unauthenticated; use the existing **Open** action and log in in the new tab instead.

## Enable the production tunnel

Use the authenticated operator-side `cloudflared` CLI to create a dedicated tunnel, keeping credentials outside Git:

```sh
cloudflared tunnel create --credentials-file "$HOME/.adsb/adsb-production.json" adsb-production
```

Transfer that credential file securely to the receiver. On the receiver, run:

```sh
sudo bash /opt/adsb/current/deploy/enable-tunnel.sh TUNNEL_UUID /private/path/adsb-production.json
```

Then create the specific DNS route with the authenticated operator-side CLI, without overwriting unrelated records:

```sh
cloudflared tunnel route dns TUNNEL_UUID adsb.ballydidean.farm
```

Verify the exact resulting hostname, tunnel identity, external HTTPS certificate, map assets, unauthorized API rejection, and authenticated admin flows. A DNS record alone is not a successful deployment. The tunnel publishes the web application, not raw ADS-B or MLAT ports.

## Validation

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q adsb_admin
ruff check adsb_admin tests
ruff format --check adsb_admin tests
node --check web/admin.js
bash -n deploy/install.sh deploy/release-transaction.sh deploy/enable-tunnel.sh deploy/remote-stack.sh
shellcheck deploy/install.sh deploy/release-transaction.sh deploy/enable-tunnel.sh deploy/remote-stack.sh
```

Use a private, separate settings directory for browser/integration tests. A local HTTP test server must opt into `--insecure-cookie` and an exact local `--origin`; do not use that flag in production. Never send recorded/synthetic data to provider endpoints.

Run read-only redirect checks against the real nginx proxy after deployment:

```bash
ADSB_PROXY_TEST_URL=https://adsb.ballydidean.farm python3 -m unittest discover -s tests -p test_proxy.py -v
```

Both `/` and `/map` must redirect to relative `/map/`, without leaking the private origin's HTTP scheme or port.

## Operations and rollback

Inspect `systemctl status adsb-admin adsb-controller` and their journals. Container state is available with `docker compose -p adsb -f /var/lib/adsb/runtime/compose.json ps`. Do not publish rendered environment or logs containing identifiers.

RemoteAgents runs `./deploy/remote-stack.sh status`, `start`, `stop`, or `restart` from this checkout. The SSH wrapper invokes only `/usr/local/sbin/adsb-stack` on `adsb`. Installation grants `admin` passwordless sudo for exactly those four arguments; no sudo password is stored in RemoteAgents. The root launcher uses an isolated Python interpreter, a clean environment, fixed paths, and the local Docker socket.

Status checks systemd, containers, the origin, fresh controller state, and Cloudflare readiness when enabled. Waiting for radios is healthy. RemoteAgents uses a binary running/stopped indicator; degraded checks return stopped with details in command output. Stop takes this site's services and containers offline, including its tunnel, without deleting settings, credentials, or receiver history. Start and restart wait for bounded readiness and do not activate disabled feeds.

The RemoteAgents project combines these commands with `externalUrl: "https://adsb.ballydidean.farm"`, not a fictitious local proxy port. Open and split view target the production site directly; external previews offer viewport sizing without proxy-based device emulation. The hostname must resolve and its Cloudflare tunnel must be healthy before the public preview works. Admin embedding additionally requires the exact `ADSB_ADMIN_FRAME_ORIGIN` opt-in above; the **Open** action remains the fallback for browsers without partitioned-cookie support.

Installation stages an exact immutable application tree, prepares its matching map assets, and atomically updates `/opt/adsb/current`; obsolete files from an older release cannot remain active. A random activation identity prevents a fresh status from the previous controller from satisfying the new release's readiness gate. Installation also preserves a timestamped application-code archive in `/var/lib/adsb/runtime/` before selection. To roll back: stop `adsb-controller`, atomically repoint `/opt/adsb/current` to the previous directory under `/opt/adsb/releases`, restore the corresponding reviewed runtime image pins when necessary, and restart `adsb-admin` and `adsb-controller`. The selected application release includes its matching map-release link. Old releases, map releases, and backups are retained for operator-reviewed removal; monitor disk usage during repeated upgrades. Keep private settings and tunnel credentials intact. Stop the fixed `adsb` Compose project if immediate shutdown is needed; do not stop unrelated containers.

## Hardware commissioning remains required

When radios arrive, verify serial assignment and driver ownership, both decoder processes, actual aircraft/message recency, Airspy CPU/thermal margin, UAT traffic, suitable gain, and the LNA/bias-tee power arrangement. No bias-tee enablement is guessed by this deployment. Confirm each provider's station acceptance and MLAT synchronization separately. Repeated host reboot reliability was historically unresolved and is not certified by service-level tests.

Upstream contracts: [ultrafeeder](https://github.com/sdr-enthusiasts/docker-adsb-ultrafeeder), [PiAware](https://github.com/sdr-enthusiasts/docker-piaware), [Airspy](https://github.com/sdr-enthusiasts/airspy_adsb), [dump978](https://github.com/sdr-enthusiasts/docker-dump978), [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/).
