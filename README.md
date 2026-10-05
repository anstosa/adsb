# Ballydidean Farm ADS-B station

Receiver software for an Airspy Mini (1090 MHz) and an ADSBx Orange RTL-SDR (978 MHz), with safe hardware-free staging. The public map is at `/map/`; password-protected configuration and reception diagnostics are at `/admin`.

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

PiAware container health tracks the local PiAware process rather than recent message volume. Provider connectivity and received radio traffic remain separate runtime observations, so a quiet receiver does not make a functioning uploader process unhealthy.

### Reception diagnostics and graphs

The authenticated admin shows separate 1090 MHz and 978 MHz reception observations: message rate, source sample time, and the last positive reception sample seen by the controller. Airspy uses its one-minute Mode-S counters; UAT uses changes in dump978's cumulative receiver counter. These observations do not confuse combined readsb inputs or MLAT returns with local 1090 reception. A current source with no messages is **quiet**, not broken; absent hardware, stopped services, unavailable telemetry, and stale samples remain distinct. A fresh JSON timestamp alone does not prove reception. Activity timestamps are sampled observations, not exact per-message reception times, and reset when the controller restarts.

Built-in reception and system graphs are at `/map/graphs1090/`. Airspy and UAT statistics are connected to graphs1090, and its round-robin database is persisted at `/var/lib/adsb/collectd` across container recreation. Receiver telemetry ports remain bound to loopback; they are not published by the tunnel. Existing UptimeRobot and FlightAware monitoring remain unchanged.

### Own-receiver aircraft notifications

The **Aircraft alerts** section at <https://adsb.ballydidean.farm/admin> sends normal-priority **Pushover** and **SMTP email** for locally received military, medical/air-ambulance, and news aircraft. All three roles are selected by default; there is no rarity or distance filter. Alerts start **disabled** and require both channels to be configured privately before enabling. Enter the Pushover application token/user key and SMTP host, TLS port (465 or 587), login, sender, and recipient in the protected admin. SMTP can be configured while aircraft alerts remain off because maintenance email uses it independently; Pushover is not required for maintenance notices. Saved credentials are write-only; blank replacement fields preserve them. Saving settings never sends a test. The explicit **Queue test notification** action creates a clearly labeled non-aircraft test, with independent channel results.

One ICAO encounter creates one event across both bands. A brief disappearance does not repeat the notification: a new encounter requires at least **600 seconds of continuously verified absence** on every required band. Restart, disconnection, unknown input activity, stale output, or missing previously required hardware cannot establish absence. Source startup snapshots are baselined rather than replayed. Only the separate physical-input trackers qualify aircraft; network/MLAT-only map traffic cannot trigger alerts. TIS-B/rebroadcast is explicitly labeled and may describe relayed traffic rather than direct aircraft reception. Roles describe usual aircraft/operator use, **not a confirmed current mission**.

The bundled, versioned catalog retains attribution and licensing under `deploy/alerts/`; it is incomplete, especially for medical and news aircraft. Exact six-digit ICAO include/exclude overrides can correct coverage without guessing from callsigns. The private history retains 30 days of events and independent provider outcomes. **Accepted** means Pushover or the SMTP server accepted the send, not phone or inbox receipt. Ambiguous post-send failures are shown as unknown and are not automatically resent; transient retries have a five-minute deadline. The normal available-channel dispatch target is 30 seconds, not a guarantee during provider outages or overload.

The unprivileged `adsb-alerts` worker uses a 96 MiB memory limit, a private single-writer SQLite database, two bounded sender threads per channel, 1,000 pending events, 10,000 continuity identities, and a 256 MiB database ceiling. Capacity refusals remain visible in admin status rather than reporting all alerts healthy. Each isolated readsb source has a 64 MiB limit: the selected two-source fallback adds **224 MiB** including the worker, with no new image or host port. The exact-pin native 978 evaluation and fallback rationale, isolated decoder/worker proofs, and resource evidence are release-owned in `deploy/alerts/SOURCE-PROOF.md` and `source-proof.json`; their bytes are bound into the activation contract digest. Fresh kernel socket samples independently bracket ten-second accepted-message statistics, so a quiet receiver is distinguished from active input with stalled decoding. The one-second post-probe Docker interval budgets receiver startup overhead without relaxing the seven-second freshness limit.

Source or provider failures degrade only alert status, not existing feeders or the core stack status. Install/start/restart readiness additionally checks that the worker consumed the expected source generations. Encrypted backups include private alert settings, the unit, and complete conservative encounter continuity; recovery restores **no historical delivery backlog**. Live both-channel acceptance must be verified after real credentials are entered through the admin. Never enter secrets in chat or use simulated aircraft against production/provider endpoints.

### Retention and Tuesday maintenance

Aircraft heatmap/replay history is capped at **30 days** with ultrafeeder's `MAX_GLOBE_HISTORY`. Graphs1090 uses its own fixed-size round-robin history rather than an unbounded sample database. Weekly cleanup also removes installer-named application releases, unreferenced map releases, and code archives older than 30 days. The selected application and map, the two newest application releases, and maps referenced by retained applications are protected. Cleanup does not prune Docker images, private settings, feeder identities, or off-host backups.

Schedules use **America/Los_Angeles**, including daylight-saving time:

| Tuesday time | Operation |
| --- | --- |
| 03:45 | Refresh Ubuntu package indexes through `apt-daily.timer` |
| 04:00 | Apply Ubuntu security updates through `apt-daily-upgrade.timer` |
| 04:30 | Check pinned application/map update candidates and expire old release artifacts |

Timers are persistent: a missed run catches up when the machine returns. Automatic reboots are disabled; security package updates may restart affected services. The policy permits Ubuntu's security pockets and base-release dependencies, not general `-updates`, PPAs, or distribution upgrades.

Application/container upgrades remain reviewed immutable deployments. `deploy/update-channels.json` names advisory upstream channels; the weekly job compares the current and candidate **linux/amd64** manifest digests without pulling images or changing pins. Those channels are review candidates, not claims of drop-in compatibility. The custom map's pinned source commit is compared with upstream `prod`. Registry/API failures remain unknown rather than reporting that software is current. The admin maintenance card shows review results, disk headroom, pending reboot status, and the independent email outcome; reports older than eight days become unknown.

Each newly completed maintenance report queues one **SMTP-only** email when the shared private SMTP settings are complete. This is independent of the aircraft-alert enabled switch and Pushover configuration. Reports completed before notification support or before SMTP configuration are not replayed. The message reports the review result; it does not claim updates were installed, trigger a reboot, or perform application/container upgrades. Live SMTP acceptance remains unverified until real credentials are entered privately through the admin.

Inspect or rerun the non-upgrading review with:

```sh
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer adsb-maintenance.timer
journalctl -u adsb-maintenance.service
sudo python3 -I -B /opt/adsb/current/adsb_admin/maintenance.py --report-only
sudo unattended-upgrade --dry-run -v
```

New browsers center on the configured receiver site at zoom `9.802072478907773`, which displays a **5 mi** scale at the current site's latitude. This is the map's scale bar, not a five-mile radius or aircraft-distance filter. Until a site is configured, the previous display-only center (`47.98176459220005`, `-122.44336120839758`) remains the fallback; it is never sent to the decoder as an antenna position. Optional terrain-outline data is not configured during hardware-free staging.

New browsers default to canvas aircraft icons because this tar1090 build's initial WebGL render can queue inactive chart layers and starve the selected basemap. Explicit browser preferences are preserved; if an existing WebGL-enabled browser shows a blank map, open `/map/?nowebgl=1` to select the working renderer.

### Map defaults

`adsb_admin/map_defaults.py` contains the reviewed first-visit defaults: OpenStreetMap, imperial units, label detail level 1, weather and airspace overlays, selected table columns, descending altitude sorting, and a 434-pixel desktop sidebar. Only aircraft on screen are listed, ground vehicles are hidden, and faded aircraft are not kept visible. Narrow screens retain the hidden-sidebar default. Saved browser values take precedence over these defaults; explicit URL view overrides still work. A fresh browser centers on the actual receiver site without overwriting a previously saved map center or changing antenna configuration.

Tracks for all aircraft start enabled through tar1090's existing `allTracks` startup option, without changing the browser URL. This upstream toggle is session-only, not a saved browser preference: **Tools → Show tracks for all aircraft** can turn it off for the current session, and a reload starts with tracks enabled again.

The controller appends these settings to the generated `config.js` through `TAR1090_CONFIGJS_APPEND`. The zoom key uses tar1090's current-origin/current-path storage proxy; center keys are left to tar1090's saved-view/site-position behavior. Recent searches, bookmarks, `LK_*` values, and `webglTested` are not imported. New visitors use the safe canvas renderer rather than WebGL.

To inspect another browser's preferences, arrange `/map/` in that browser and run this read-only snippet in its developer console (select the map's frame when embedded). In Chromium DevTools, `copy` places the JSON on the clipboard. Review saved locations and other site-local storage before sharing the result.

```javascript
// copy the current view and saved browser preferences
copy(JSON.stringify({
  url: location.href,
  view: {
    centerLonLat: getCenter(),
    zoom: getZoom(),
    rotationRadians: OLMap.getView().getRotation(),
    basemap: MapType_tar1090,
    units: DisplayUnits
  },
  savedPreferences: { ...localStorage }
}, null, 2));
```

Changes require the normal application deployment; do not edit generated map assets or runtime Compose files. Verify new defaults in a fresh private browser window, without clearing an existing user's preferences.

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
| `/var/lib/adsb/config/alerts.json` | private alert credentials, role toggles, and ICAO overrides |
| `/var/lib/adsb/config/alerts-test.json` | admin-owned fixed test request and restart-safe rate limit |
| `/var/lib/adsb/alerts` | private worker database, heartbeat, and backup continuity |
| `/var/lib/adsb/alert-source` | root-owned group-readable physical tracker output |
| `/var/lib/adsb/status/status.json` | private controller status and bounded claim route |
| `/var/lib/adsb/piaware` | private provider-assigned PiAware identity state |
| `/var/lib/adsb/collectd` | persistent graphs1090 round-robin statistics |
| `/var/lib/adsb/tar1090` | aircraft history with 30-day retention |
| `/var/lib/adsb/status/maintenance.json` | bounded weekly update-review and disk/reboot observations |
| `/var/lib/adsb/runtime/compose.json` | private rendered container configuration |
| `/var/lib/adsb/cloudflared` | root-only tunnel credentials and ingress configuration |

Do not copy these private files into Git. `deploy/images.json` pins all container images by digest; image changes are deliberate updates rather than implicit pulls of mutable tags.

## Install on the receiver

Prerequisites: Ubuntu 24.04 amd64, SSH access, authorized sudo, outbound package/image access, and approximately 2 GiB RAM. The installer does not reboot, reinstall the OS, modify storage, or change unrelated services.

1. Generate a private environment file **outside this repository** using `adsb_admin.auth.make_password_hash`. Its required setting is `ADSB_ADMIN_PASSWORD_HASH='scrypt$...hash envelope...'`. Quoting is important if it is loaded by a shell; no plaintext password belongs in the file.
2. Transfer this repository's `adsb_admin`, `web`, and `deploy` directories to a staging directory on `adsb`; transfer the private environment file separately with restrictive permissions.
3. Run `sudo bash deploy/install.sh /path/to/private/admin.env`. It installs Ubuntu's Docker/Compose packages, pulls the pinned images, creates the unprivileged web user, and enables the admin, controller, and alert-worker services plus maintenance timers.
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

Rendered admin regressions are opt-in and use an existing Playwright installation without adding project dependencies:

```sh
ADSB_PLAYWRIGHT_MODULE=/absolute/path/to/node_modules/playwright node tests/admin-ui-regressions.mjs
```

The same environment variable enables the browser case during unittest discovery. The suite serves the actual admin assets on loopback with isolated API responses; it never contacts notification providers.

Run read-only redirect checks against the real nginx proxy after deployment:

```bash
ADSB_PROXY_TEST_URL=https://adsb.ballydidean.farm python3 -m unittest discover -s tests -p test_proxy.py -v
```

Both `/` and `/map` must redirect to relative `/map/`, without leaking the private origin's HTTP scheme or port.

## Operations and rollback

### Encrypted off-host backups

ADS-B uses the existing Blueberry backup engine on **Framework**, with a separate ADS-B configuration, catalog, storage root, age identity, SSH identity, and systemd units. Existing Blueberry archives and jobs are not migrated or changed. The receiver holds only the public age recipient; it streams an encrypted tar archive over a dedicated forced-command SSH account. The Framework private key and age identity remain outside Git in the owner-only `~/.config/blueberry-backups-adsb/` directory.

Backups run daily at **03:00 America/Los_Angeles**, before Tuesday's security update window. Retained-generation integrity checks run daily at **19:00 UTC** (noon Pacific daylight time or 11:00 Pacific standard time), matching the existing Blueberry engine's integrity-cycle deadline. Each generation is published only after checksum verification, age decryption into private tmpfs, safe archive inspection, and validation of the receiver configuration and selected application/map release. This is a restore-content check, not a destructive restore onto the live receiver. The archive includes station/feed settings, the admin password hash, tunnel credentials, PiAware identity, the selected application and map, and the fixed host integration files. It also includes alert credentials and conservative encounter continuity, but never the alert database, outbox, or old delivery backlog. It excludes aircraft history, graphs, old releases, generated Compose/status, and the Framework private keys. The map's three approved container-only symlinks are verified before backup and reconstructed from the pinned manifest during recovery, rather than followed on the host.

Source provisioning is separate from ordinary application upgrades:

```sh
sudo bash /opt/adsb/current/deploy/backup/install-source.sh /private/framework-backup.pub /private/adsb-age-recipient.txt
```

Installed root-owned entrypoints select their implementation from `/opt/adsb/current/deploy/backup/`, so future immutable application deployments also update backup logic. The backup SSH account permits only `backup-proof` and `backup-stream`, with no forwarding, terminal, arbitrary command, or general sudo access.

Framework operational paths:

| Path or unit | Purpose |
| --- | --- |
| `~/.config/blueberry-backups-adsb/adsb-backups.json` | private ADS-B-only engine configuration |
| `~/.local/share/blueberry-backups-adsb/` | isolated encrypted generations and catalog |
| `~/.local/state/blueberry-backups-adsb/` | isolated operational state and public-safe status snapshot |
| `blueberry-backup-adsb.timer` | daily verified backup |
| `blueberry-backup-adsb-integrity-scrub.timer` | daily retained-generation verification |
| `blueberry-backup-adsb-prune.timer` | daily automatic deletion of expired, unprotected generations at 23:45 UTC |

Use `systemctl --user status blueberry-backup-adsb.service` and its journal on Framework. Engine recovery instructions and the isolated profile template are in `/home/ubuntu/blueberry-backups/README.md` and `config/adsb-backups.example.json`. Keep a separately secured recovery copy of the age identity: losing it makes the encrypted archives unrecoverable.

The engine keeps **7 daily, 5 weekly, and 12 monthly restore points per service**, with overlapping tiers sharing a generation. Automatic pruning physically deletes expired, unprotected encrypted generations daily at **23:45 UTC**, after the integrity-check window, with at most **7 oldest eligible generations per service per run**. The latest verified backup and verification/recovery pins are protected; a newer retained replacement must pass local verification before deletion. Catalog or integrity uncertainty and retention-reference disagreements stop pruning, and unknown files, quarantine, and source-host data are never swept. Use the engine's `prune --config <private-config>` command for a read-only dry run; only `--mode apply` permits deletion. Blueberry's Weather/Actionable profile follows the same policy at 23:30 UTC. This off-host policy is separate from the receiver's 30-day aircraft/release cleanup.

### Stack operations

Inspect `systemctl status adsb-admin adsb-controller adsb-alerts` and their journals. Container state is available with `docker compose -p adsb -f /var/lib/adsb/runtime/compose.json ps`. Do not publish rendered environment or logs containing identifiers.

RemoteAgents runs `./deploy/remote-stack.sh status`, `start`, `stop`, or `restart` from this checkout. The SSH wrapper invokes only `/usr/local/sbin/adsb-stack` on `adsb`. Installation grants `admin` passwordless sudo for exactly those four arguments; no sudo password is stored in RemoteAgents. The root launcher uses an isolated Python interpreter, a clean environment, fixed paths, and the local Docker socket.

Status checks systemd, containers, the origin, fresh controller state, and Cloudflare readiness when enabled. Waiting for radios is healthy. RemoteAgents uses a binary running/stopped indicator; degraded checks return stopped with details in command output. Stop takes this site's services and containers offline, including its tunnel, without deleting settings, credentials, or receiver history. Start and restart wait for bounded readiness and do not activate disabled feeds.

The RemoteAgents project combines these commands with `externalUrl: "https://adsb.ballydidean.farm"`, not a fictitious local proxy port. Open and split view target the production site directly; external previews offer viewport sizing without proxy-based device emulation. The hostname must resolve and its Cloudflare tunnel must be healthy before the public preview works. Admin embedding additionally requires the exact `ADSB_ADMIN_FRAME_ORIGIN` opt-in above; the **Open** action remains the fallback for browsers without partitioned-cookie support.

Installation stages an exact immutable application tree, prepares its matching map assets, and atomically updates `/opt/adsb/current`; obsolete files from an older release cannot remain active. A random activation identity prevents a fresh status from the previous controller from satisfying the new release's readiness gate. Installation also preserves a timestamped application-code archive in `/var/lib/adsb/runtime/` before selection. To roll back: stop `adsb-alerts` and `adsb-controller`, atomically repoint `/opt/adsb/current` to the previous directory under `/opt/adsb/releases`, restore the corresponding reviewed runtime image pins when necessary, and restart `adsb-admin` and `adsb-controller`. Restart `adsb-alerts` only when the selected release includes the worker and matching source contract; disable the new unit when reverting to a pre-alert release. The selected application release includes its matching map-release link. Weekly maintenance expires installer-owned artifacts after 30 days while protecting the selected release, two newest application releases, and referenced maps; off-host backups follow their separate retention policy. Keep private settings and tunnel credentials intact. Stop the fixed `adsb` Compose project if immediate shutdown is needed; do not stop unrelated containers.

## Hardware commissioning remains required

When radios arrive, verify serial assignment and driver ownership, both decoder processes, actual aircraft/message recency, Airspy CPU/thermal margin, UAT traffic, suitable gain, and the LNA/bias-tee power arrangement. No bias-tee enablement is guessed by this deployment. Confirm each provider's station acceptance and MLAT synchronization separately. Repeated host reboot reliability was historically unresolved and is not certified by service-level tests.

Upstream contracts: [ultrafeeder](https://github.com/sdr-enthusiasts/docker-adsb-ultrafeeder), [PiAware](https://github.com/sdr-enthusiasts/docker-piaware), [Airspy](https://github.com/sdr-enthusiasts/airspy_adsb), [dump978](https://github.com/sdr-enthusiasts/docker-dump978), [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/).
