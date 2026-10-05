# Alert source selection proof

`source-proof.json` is the immutable, release-owned G0 evidence for the alert sources and worker resource limits. The controller hashes its exact bytes into the source contract digest and rejects a release when the required proof fields, pinned image, or source-health hash do not match.

## Selected sources

- 1090 MHz uses the pinned ultrafeeder `readsb` binary with only the Airspy `30005/beast_in` physical connector.
- 978 MHz uses the same pinned `readsb` binary with only the dump978 `30978/uat_in` physical connector.
- Both isolated source proofs used `--network=none`, a read-only root, all capabilities dropped, `no-new-privileges`, and a 64 MiB memory limit. The empty output directory and zero accepted startup statistics demonstrate a fresh generation rather than replayed decoder state. The running `readsb` process exposed no TCP listener and therefore no alternate aircraft ingress.
- The exact release `source-health.sh` independently proved a stable decoder-owned connector socket and increasing kernel `bytes_received` before the decoder's accepted-message counters were trusted. Every invocation used the production five-second timeout: the 1090 proof completed two invocations in at most 152 ms, and the 978 proof completed two invocations in at most 125 ms.

The recorded 1090 fixture accepted 5,005 messages at 4,944 KiB RSS. The recorded 978 fixture accepted 5,008 messages at 5,064 KiB RSS. Both tracked an ICAO identity before position and advanced an identity counter for an otherwise unsupported valid payload. The 978 proof also retained a qualified TIS-B ICAO identity.

The health probe uses one Python interpreter. Docker starts its next check after the prior check completes, so the fixed one-second post-completion interval budgets receiver-side process startup overhead. A five-second interval produced gaps beyond the worker's seven-second freshness limit on the actual receiver. The five-second probe timeout and seven-second freshness limit remain unchanged; slow or missing observations still invalidate continuity rather than certifying absence.

A separate production runtime-margin observation remains unresolved: its first Docker wall-clock check reached at least five seconds, and the exact exit state was not captured. A later 71-second, 22-sample window was stable, but that follow-up does not establish that the earlier margin warning was remediated.

## Native 978 decision

The pinned dump978 image's native `skyaware978` path passed identity-before-position, unsupported-payload counter, TIS-B identity, and 64 MiB memory checks at 5,080 KiB RSS. It was not selected because it could not satisfy independent producer-coverage proof:

- after its physical input disconnected, `aircraft.json` continued receiving a fresh writer timestamp while its message counter remained flat;
- the JSON contract contains only `aircraft`, `messages`, and `now`, with no independently sourced producer-active, input-connection, or input-byte field;
- the existing native HTTP endpoint at `http://127.0.0.1:8978/skyaware978/data/aircraft.json` serves that same consumer output and therefore is not an independent producer observation;
- native JSON TCP port `30979` is not directly published to the host, and adding a new telemetry path is outside the approved no-new-port contract.

The recorded failure code is `independent_producer_coverage_unavailable`. The documented `readsb-uat` fallback is therefore selected instead of weakening stalled-input detection.

## Worker and host bounds

The network-isolated worker proof loaded the complete 10,684-entry catalog under a 96 MiB container limit. It processed the maximum normalized payload of 10,000 rows from each band, retained the enforced 10,000-encounter cap, held the maximum 1,000 pending aircraft events and 2,000 per-channel aircraft jobs, emitted a complete 10,000-row continuity snapshot, surfaced `state_capacity_exceeded`, and performed zero provider dispatches. It additionally retained the complete 1,000-row maintenance notification cap, with every immutable email body at the maximum 8,192 bytes, and rejected the next row observably without creating another sender pool. Recorded memory was 57,692 KiB RSS, 74,876 KiB peak RSS, and 60,108 KiB current cgroup usage.

Production was sampled five times before deployment. The passing window had 1,104,012 KiB minimum available memory. After the approved 224 MiB incremental allocation, projected residual memory was 874,636 KiB, above the 256 MiB floor. All five swap-in and swap-out samples were zero, and the prior 24 hours contained no kernel OOM event.

The artifact also retains the earlier transient audit window instead of discarding it. That window had 1,026,996 KiB minimum available memory, 797,620 KiB projected residual memory, no swap-out, and no kernel OOM event, but its final swap-in sample was 4 KiB/s. It remains recorded with `headroom_passed: false`; the current fresh passing window contains no swap activity.

## Reproduction

1. Collect the secret-free production headroom JSON with the exact fields shown in `source-proof.json`: a UTC capture time, five `MemAvailable` samples, five `vmstat` swap-in samples, five swap-out samples, and the prior 24-hour kernel OOM count.
2. Ensure both image digests in `deploy/images.json` are already cached. The proof deliberately uses `--pull=never`.
3. Run:

   ```sh
   sudo /usr/bin/python3 tests/prove_alert_sources.py \
     --headroom-json /path/to/headroom.json \
     --headroom-audit-json /path/to/prior-headroom.json \
     --output /tmp/source-proof.json
   ```

The command starts only disposable, network-isolated fixture containers. It does not contact notification providers, send aircraft fixtures to production, or leave containers running. The retained proof was generated at `2026-10-05T20:21:11Z`; its SHA-256 digest is `477b2bfc2a55fe08bd95ebcad2a73f52973f1963680a2a667b2a1428bc2c53dc`, and the bound source-health SHA-256 digest is `29e0b9b1e6bc96b3a7512b1ca5f3e2975190fb0605c17fe2e06ce6ebde15c3c8`.
