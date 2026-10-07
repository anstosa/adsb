# Alert source selection proof

`source-proof.json` is the immutable, release-owned G0 evidence for the alert sources and worker resource limits. The controller hashes its exact bytes into the source contract digest and rejects a release when the required proof fields, pinned image, or source-health hash do not match.

## Selected sources

- 1090 MHz uses the pinned ultrafeeder `readsb` binary with only the Airspy `30005/beast_in` physical connector.
- 978 MHz uses the same pinned `readsb` binary with only the dump978 `30978/uat_in` physical connector.
- Both isolated source proofs used `--network=none`, a read-only root, all capabilities dropped, `no-new-privileges`, and a 64 MiB memory limit. The empty output directory and zero accepted startup statistics demonstrate a fresh generation rather than replayed decoder state. The running `readsb` process exposed no TCP listener and therefore no alternate aircraft ingress.
- The exact release `source-health.sh` independently proved a stable decoder-owned connector socket and increasing kernel `bytes_received` before the decoder's accepted-message counters were trusted. Every invocation used the production five-second timeout: the 1090 proof completed two invocations in at most 4,422 ms, and the 978 proof completed two invocations in at most 4,811 ms.

The recorded 1090 fixture accepted 5,005 messages at 4,560 KiB RSS. The recorded 978 fixture accepted 5,008 messages at 4,488 KiB RSS. Both tracked an ICAO identity before position and advanced an identity counter for an otherwise unsupported valid payload. The 978 proof also retained a qualified TIS-B ICAO identity.

The health probe uses one Python interpreter. Docker starts its next check after the prior check completes, so the fixed one-second post-completion interval budgets receiver-side process startup overhead. A five-second interval produced gaps beyond the worker's seven-second freshness limit on the actual receiver. The five-second probe timeout and seven-second freshness limit remain unchanged; slow or missing observations still invalidate continuity rather than certifying absence.

A separate production runtime-margin observation remains unresolved: its first Docker wall-clock check reached at least five seconds, and the exact exit state was not captured. A later 71-second, 22-sample window was stable, but that follow-up does not establish that the earlier margin warning was remediated.

## Proximity and notification metadata

Position eligibility is separate from physical receiver validity: the worker requires a fresh non-MLAT radio-derived position within five statute miles of the configured Whidbey receiver before creating an aircraft event. Optional missing position or metadata never establishes absence or breaks otherwise valid reception. The trigger snapshot retains fresh-position eligibility while finalized coverage catches up; a newer unknown/outside position or changed/missing station center cannot reuse the old inside-radius decision.

The existing version-pinned local database provides the aircraft row's fourth-field long name, then `icao_aircraft_types2.js` first-field fallback. `operators.js` supplies operator text only through the physical callsign's guarded three-letter prefix; registration callsigns are excluded. This mirrors the [pinned tar1090 metadata contracts](https://github.com/airplanes-live/tar1090/blob/0c4e109369620ac679ccc98ca3f090e0e41a3339/html/planeObject.js#L2369-L2411) and [operator lookup](https://github.com/airplanes-live/tar1090/blob/0c4e109369620ac679ccc98ca3f090e0e41a3339/html/script.js#L496-L569). Only exact fixed localhost trie and named-file routes are allowed, with four shared fetches per poll and the existing compressed/decoded byte ceilings. These metadata joins never admit network-only aircraft or map-derived coordinates.

## Native 978 decision

The pinned dump978 image's native `skyaware978` path passed identity-before-position, unsupported-payload counter, TIS-B identity, and 64 MiB memory checks at 4,808 KiB RSS. It was not selected because it could not satisfy independent producer-coverage proof:

- after its physical input disconnected, `aircraft.json` continued receiving a fresh writer timestamp while its message counter remained flat;
- the JSON contract contains only `aircraft`, `messages`, and `now`, with no independently sourced producer-active, input-connection, or input-byte field;
- the existing native HTTP endpoint at `http://127.0.0.1:8978/skyaware978/data/aircraft.json` serves that same consumer output and therefore is not an independent producer observation;
- native JSON TCP port `30979` is not directly published to the host, and adding a new telemetry path is outside the approved no-new-port contract.

The recorded failure code is `independent_producer_coverage_unavailable`. The documented `readsb-uat` fallback is therefore selected instead of weakening stalled-input detection.

## Worker and host bounds

The network-isolated worker proof loaded the complete 10,684-entry catalog under a 96 MiB container limit. It additionally retained the complete 2,000-rule mixed aircraft/model watchlist and the 32-page/4,096-entry normalized local-model cache through the real pinned database lookup path, plus 4,096 aircraft descriptions with full exact-row completeness tracking, 4,000 type names, and 7,000 operator names. Validated trie routing edges can be reused across polls, so depth-five/six rows resolve within the four-fetch allowance; partially evicted model/description cache projections refetch instead of becoming incomplete permanent hits. Aircraft messages are retained at the full 250-character title and 1,024-character body limits; their persisted lengths are measured, not inferred. It processed the maximum normalized payload of 10,000 rows from each band, retained the enforced 10,000-encounter cap, held the maximum 1,000 pending aircraft events and 2,000 per-channel aircraft jobs, emitted a complete 10,000-row continuity snapshot, surfaced `state_capacity_exceeded`, and performed zero provider dispatches. It additionally retained the complete 1,000-row maintenance notification cap, with every immutable email body at the maximum 8,192 bytes, and rejected the next row observably without creating another sender pool. The freshly measured RSS, peak RSS, and current cgroup usage are recorded in the artifact’s `worker` section; each must remain below the unchanged 96 MiB limit.

Production is sampled five times before deployment. The fresh `production_headroom` observation records actual available memory, zero swap-in/out across all five samples, and zero kernel OOM events over the prior 24 hours. After the approved 224 MiB incremental allocation, the projected residual must remain above the unchanged 256 MiB floor.

The artifact also retains a prior transient observation in `production_headroom_transient_audit`, including its original pass/fail state. A failed sample is not replaced by a fabricated passing result; only a separately measured stable window can satisfy the deployment gate.

## Reproduction

1. Collect the secret-free production headroom JSON with the exact fields shown in `source-proof.json`: a UTC capture time, five `MemAvailable` samples, five `vmstat` swap-in samples, five swap-out samples, and the prior 24-hour kernel OOM count.
2. Ensure both image digests in `deploy/images.json` are already cached. The proof deliberately uses `--pull=never`.
3. Run:

   ```sh
   sudo /usr/bin/python3 deploy/alerts/prove-sources.py \
     --headroom-json /path/to/headroom.json \
     --headroom-audit-json /path/to/prior-headroom.json \
     --output /tmp/source-proof.json
   ```

The command starts only disposable, network-isolated fixture containers. It does not contact notification providers, send aircraft fixtures to production, or leave containers running. `generated_at` records the fresh worker proof. For code-only updates, the guarded `--reuse-native-proof` lane can preserve the original `native_evidence_generated_at` only when the native pins, health script, source contract, launcher, and fixture programs are unchanged and the original observation is less than 24 hours old. It still reruns the full changed-worker capacity proof and captures fresh host headroom. The retained native observations were generated at `2026-10-06T20:13:28Z`; the bound source-health SHA-256 is `29e0b9b1e6bc96b3a7512b1ca5f3e2975190fb0605c17fe2e06ce6ebde15c3c8`. The exact current artifact bytes and measured values remain authoritative in `source-proof.json`.
