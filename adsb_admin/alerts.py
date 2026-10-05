"""Station-local aircraft notification engine and host worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import queue
import signal
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from adsb_admin.alert_catalog import AlertCatalog, normalize_icao
from adsb_admin.alert_config import AlertSettingsStore
from adsb_admin.alert_delivery import DeliveryResult, send_email, send_pushover
from adsb_admin.alert_store import AlertStore
from adsb_admin.maintenance import APPLICATION_POLICY, IMAGE_NAMES, OS_SCHEDULE, public_report


# require only the shared email credentials for maintenance summaries
def _smtp_configured(settings: dict[str, Any]) -> bool:
    smtp = settings["smtp"]
    return all(smtp.get(key) for key in ("host", "username", "password", "from_address", "to_address"))


# format only sanitized review evidence without claiming installed upgrades
def _maintenance_message(report: dict[str, Any]) -> tuple[str, str]:
    states = {"ok": "Review current", "attention": "Review needed", "failed": "Run failed"}
    labels = {"current": "Current", "review": "Update candidate needs review", "unknown": "Check unavailable"}
    state = states.get(report.get("status"), "Report unavailable")
    images = {row["name"]: row["status"] for row in report.get("images", [])}
    components = [f"  {name}: {labels.get(images.get(name), 'Check unavailable')}" for name in IMAGE_NAMES]
    disk = report.get("disk_free_percent")
    disk_label = f"{disk:.1f}%" if disk is not None else "Unknown"
    reboot = report.get("reboot_required")
    reboot_label = "Required" if reboot is True else "Not required" if reboot is False else "Unknown"
    removed = report.get("removed_expired_artifacts")
    body = "\n".join(
        [
            "Software maintenance review for your ADS-B station.",
            f"Review time: {report.get('updated_at') or 'Unknown'}",
            f"Result: {state}",
            "",
            f"OS security update schedule: {OS_SCHEDULE}",
            "This review does not verify whether OS updates were installed.",
            APPLICATION_POLICY + ". No application upgrades or reboots are performed automatically.",
            "",
            "Container review:",
            *components,
            f"Map: {labels.get(report.get('map_status'), 'Check unavailable')}",
            f"Disk free: {disk_label}",
            f"Reboot: {reboot_label}",
            f"Expired release artifacts removed: {removed if removed is not None else 'Unknown'}",
            "",
            "Details: https://adsb.ballydidean.farm/admin",
        ]
    )
    return f"ADS-B software maintenance: {state}", body


ABSENCE_SECONDS = 600.0
RETURN_ADJUDICATION_SECONDS = 20.0
STATUS_INTERVAL_SECONDS = 10.0
POLL_INTERVAL_SECONDS = 1.0


# test finite numeric input without accepting booleans
def _finite_number(value: Any) -> float | None:
    # reject booleans and nonnumbers
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


# atomically persist one worker-owned private json file
def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    finally:
        # remove abandoned output
        if temporary_path.exists():
            temporary_path.unlink()


# build a deterministic bounded retry delay
def _retry_delay(job: dict[str, Any], result: DeliveryResult) -> float:
    base = min(5.0 * (2 ** max(0, job["attempt"] - 1)), 60.0)
    digest = hashlib.sha256(f"{job['event_id']}:{job['channel']}:{job['attempt']}".encode("ascii")).digest()
    jitter = digest[0] / 255.0 * 2.0
    return max(5.0, float(result.retry_after or 0.0), base + jitter)


# format one honest usual-role notification
def _message_for_job(job: dict[str, Any]) -> tuple[str, str]:
    # send the immutable maintenance snapshot through smtp only
    if job["kind"] == "maintenance":
        return job["subject"], job["body"]
    # keep operator tests visibly separate from aircraft events
    if job["kind"] == "test":
        return (
            "ADS-B notification test",
            "This is a requested notification test. It is not an aircraft detection.",
        )
    roles = ", ".join(job["categories"])
    bands = " and ".join(
        f"{band} MHz" + (" (rebroadcast)" if job["receptions"].get(band) == "rebroadcast" else "")
        for band in job["bands"]
    )
    title = f"Locally received {roles} aircraft"
    body = (
        f"{job['label']} ({job['hex']}) was received by this station on {bands}. "
        "Categories describe the aircraft's usual role, not its current mission."
    )
    return title, body


# send one leased delivery without holding database state
def dispatch_delivery(job: dict[str, Any], settings: dict[str, Any]) -> DeliveryResult:
    title, body = _message_for_job(job)
    # never route software maintenance through aircraft push notifications
    if job["kind"] == "maintenance" and job["channel"] != "email":
        return DeliveryResult("failed", "unsupported_channel")
    # select only the fixed configured provider
    if job["channel"] == "pushover":
        return send_pushover(settings["pushover"], title=title, message=body)
    # send the independent email channel
    if job["channel"] == "email":
        return send_email(
            settings["smtp"],
            subject=title,
            body=body,
            message_id=job["message_id"],
        )
    return DeliveryResult("failed", "unsupported_channel")


# adjudicate encounters from normalized physical-source samples
class AlertEngine:
    # start with conservative in-process coverage state
    def __init__(self, store: AlertStore, catalog: AlertCatalog) -> None:
        self.store = store
        self.catalog = catalog
        self._boot_mono: float | None = None
        self._declared_bands: set[str] = set()
        self._coverage: dict[str, dict[str, Any]] = {}
        self._progress: dict[tuple[str, str, str], int] = {}
        self._absence_floor: dict[str, float] = {}
        self._pending_returns: dict[str, dict[str, Any]] = {}
        self.capacity_error: str | None = None

    # reset one band's progress after source uncertainty
    def _reset_band(self, band: str, now_mono: float) -> None:
        self._coverage.pop(band, None)
        stale_keys = [key for key in self._progress if key[0] == band]
        # discard baselines that cross an unknown source interval
        for key in stale_keys:
            self._progress.pop(key, None)
        # restart absence proof for every dependent encounter
        for encounter in self.store.active_encounters():
            # reset only identities that require this band
            if band in encounter["required_bands"]:
                self._absence_floor[encounter["hex"]] = now_mono

    # accept one fresh physical counter progression
    def _is_fresh_aircraft(self, band: str, generation: str, aircraft: dict[str, Any]) -> bool:
        # honor an adapter-proven progression marker when provided
        if aircraft.get("fresh") is True:
            return True
        messages = aircraft.get("messages")
        hex_id = normalize_icao(aircraft.get("hex"))
        # require a strict monotonic per-aircraft counter
        if hex_id is None or not isinstance(messages, int) or isinstance(messages, bool) or messages < 0:
            return False
        key = (band, generation, hex_id)
        previous = self._progress.get(key)
        self._progress[key] = messages
        # baseline initial and reset counters without replaying them
        if previous is None or messages <= previous:
            return False
        return True

    # test whether every required band proves absence through one point
    def _coverage_proof(self, required_bands: set[str], floor: float) -> tuple[bool, float, float]:
        proof_floor = floor
        finalized_until = math.inf
        # require independent coverage from every persisted band
        for band in required_bands:
            coverage = self._coverage.get(band)
            # unknown coverage cannot prove absence
            if coverage is None:
                return False, proof_floor, -math.inf
            proof_floor = max(proof_floor, coverage["since"])
            finalized_until = min(finalized_until, coverage["until"])
        return True, proof_floor, finalized_until

    # observe one merged fresh identity and optionally create its event
    def _apply_candidate(
        self,
        candidate: dict[str, Any],
        settings: dict[str, Any],
        *,
        return_mono: float,
    ) -> str | None:
        hex_id = candidate["hex"]
        classification = self.catalog.classify(
            hex_id,
            db_flags=candidate.get("dbFlags"),
            overrides=settings.get("overrides", ()),
        )
        selected = set(settings.get("categories", ()))
        categories = tuple(category for category in classification.categories if category in selected)
        required_bands = set(self._declared_bands) or set(candidate["bands"])
        try:
            event_id = self.store.observe_aircraft(
                hex_id=hex_id,
                label=classification.label or hex_id,
                categories=categories,
                bands=set(candidate["bands"]),
                receptions=candidate["receptions"],
                required_bands=required_bands,
                observed_at=candidate["observed_at"],
                config_revision=settings["revision"],
                enabled=settings["enabled"],
            )
        except RuntimeError:
            self.capacity_error = "state_capacity_exceeded"
            self.store.record_capacity_rejection()
            return None
        self._absence_floor[hex_id] = candidate.get("last_observed_mono", return_mono)
        return event_id

    # resolve delayed returns after finalized source windows arrive
    def _resolve_pending(self, settings: dict[str, Any], now_mono: float) -> list[str]:
        created: list[str] = []
        active = {encounter["hex"]: encounter for encounter in self.store.active_encounters()}
        # adjudicate each bounded pending return
        for hex_id, pending in list(self._pending_returns.items()):
            encounter = active.get(hex_id)
            # apply immediately when the encounter disappeared or rearmed elsewhere
            if encounter is None or not encounter["notified"]:
                event_id = self._apply_candidate(pending["candidate"], settings, return_mono=pending["return_mono"])
                # retain only newly created events
                if event_id:
                    created.append(event_id)
                self._pending_returns.pop(hex_id, None)
                continue
            boot_floor = self._boot_mono if self._boot_mono is not None else now_mono
            floor = self._absence_floor.get(hex_id, boot_floor)
            continuous, proof_floor, finalized_until = self._coverage_proof(encounter["required_bands"], floor)
            # a later exposed inside-boundary sighting keeps the existing encounter
            if pending["return_mono"] - floor < ABSENCE_SECONDS:
                self._apply_candidate(pending["candidate"], settings, return_mono=now_mono)
                self._pending_returns.pop(hex_id, None)
                continue
            # rearm only after finalized continuous absence through the return
            if (
                continuous
                and finalized_until >= pending["return_mono"]
                and pending["return_mono"] - proof_floor >= ABSENCE_SECONDS
            ):
                self.store.mark_rearmed(hex_id, rearmed_at=pending["candidate"]["observed_at"])
                event_id = self._apply_candidate(pending["candidate"], settings, return_mono=pending["return_mono"])
                # retain only newly created events
                if event_id:
                    created.append(event_id)
                self._pending_returns.pop(hex_id, None)
            # treat an unproven return as the existing encounter after twenty seconds
            elif now_mono >= pending["deadline_mono"]:
                self._apply_candidate(pending["candidate"], settings, return_mono=now_mono)
                self._pending_returns.pop(hex_id, None)
        return created

    # finalize continuously proven absent encounters with no pending return
    def _finalize_absence(self, now_wall: float, now_mono: float) -> None:
        # inspect durable required-band sets
        for encounter in self.store.active_encounters():
            hex_id = encounter["hex"]
            # let pending return adjudication own its boundary
            if hex_id in self._pending_returns:
                continue
            boot_floor = self._boot_mono if self._boot_mono is not None else now_mono
            floor = self._absence_floor.setdefault(hex_id, boot_floor)
            continuous, proof_floor, finalized_until = self._coverage_proof(encounter["required_bands"], floor)
            through = proof_floor + ABSENCE_SECONDS
            # finalize only a full proven absence window
            if continuous and finalized_until >= through and now_mono >= through:
                rearmed_wall = now_wall - max(0.0, now_mono - through)
                self.store.mark_rearmed(hex_id, rearmed_at=rearmed_wall)

    # process one polling cycle without performing external delivery io
    def process_samples(
        self,
        samples: list[dict[str, Any]],
        settings: dict[str, Any],
        now_wall: float,
        now_mono: float,
    ) -> list[str]:
        # establish a conservative process-restart absence floor
        if self._boot_mono is None:
            self._boot_mono = now_mono
            # make every restored encounter prove a fresh full interval
            for encounter in self.store.active_encounters():
                self._absence_floor[encounter["hex"]] = now_mono
        self.capacity_error = None
        candidates: dict[str, dict[str, Any]] = {}
        sampled_bands: set[str] = set()
        # normalize each independently proven band sample
        for sample in samples:
            band = sample.get("band")
            # ignore unknown source types
            if band not in ("1090", "978"):
                continue
            sampled_bands.add(band)
            # do not burden new encounters with hardware that was never declared present
            if sample.get("expected") is True and band not in self._declared_bands:
                self.store.add_required_band(band)
                self._declared_bands.add(band)
            generation = sample.get("generation")
            coverage_since = _finite_number(sample.get("coverage_since"))
            coverage_until = _finite_number(sample.get("coverage_until"))
            healthy = sample.get("healthy") is True and sample.get("coverage_state") == "healthy"
            # reject incomplete or future coverage intervals
            if (
                not healthy
                or not isinstance(generation, str)
                or not generation
                or len(generation) > 100
                or coverage_since is None
                or coverage_until is None
                or coverage_until < coverage_since
                or coverage_until > now_mono + 1.0
            ):
                self._reset_band(band, now_mono)
                continue
            previous_coverage = self._coverage.get(band)
            new_generation = previous_coverage is None or previous_coverage["generation"] != generation
            # reset baselines after a generation or continuity epoch change
            if new_generation or coverage_since > previous_coverage["since"] + 0.001:
                stale_keys = [key for key in self._progress if key[0] == band]
                # discard counters from the prior epoch
                for key in stale_keys:
                    self._progress.pop(key, None)
                effective_since = now_mono if new_generation else coverage_since
                self._coverage[band] = {
                    "generation": generation,
                    "since": effective_since,
                    "until": min(coverage_until, now_mono),
                }
            else:
                previous_coverage["until"] = max(previous_coverage["until"], min(coverage_until, now_mono))
            aircraft_rows = sample.get("aircraft", [])
            # ignore malformed unbounded row collections
            if not isinstance(aircraft_rows, list) or len(aircraft_rows) > 10_000:
                self._reset_band(band, now_mono)
                continue
            new_baselines = {
                (band, generation, normalize_icao(row.get("hex")))
                for row in aircraft_rows
                if isinstance(row, dict) and row.get("fresh") is not True and normalize_icao(row.get("hex"))
            } - set(self._progress)
            # overflow cannot silently turn unobserved returns into absence proof
            if len(self._progress) + len(new_baselines) > 20_000:
                self._reset_band(band, now_mono)
                self.capacity_error = "state_capacity_exceeded"
                continue
            # merge fresh identities across bands into one logical observation
            for aircraft in aircraft_rows:
                # ignore malformed aircraft rows
                if not isinstance(aircraft, dict) or not self._is_fresh_aircraft(band, generation, aircraft):
                    continue
                hex_id = normalize_icao(aircraft.get("hex"))
                observed_at = _finite_number(aircraft.get("observed_at", sample.get("observed_at")))
                # require one current wall-clock local observation
                if hex_id is None or observed_at is None or abs(now_wall - observed_at) > 30.0:
                    continue
                candidate = candidates.setdefault(
                    hex_id,
                    {
                        "hex": hex_id,
                        "bands": set(),
                        "observed_at": observed_at,
                        "first_observed_at": observed_at,
                        "last_observed_at": observed_at,
                        "dbFlags": None,
                        "receptions": {},
                    },
                )
                candidate["bands"].add(band)
                reception = aircraft.get("reception", "direct")
                # preserve explicit rebroadcast provenance defensively
                candidate["receptions"][band] = "rebroadcast" if reception == "rebroadcast" else "direct"
                candidate["observed_at"] = max(candidate["observed_at"], observed_at)
                candidate["first_observed_at"] = min(candidate["first_observed_at"], observed_at)
                last_observed = _finite_number(aircraft.get("last_observed_at", observed_at))
                # retain the latest conservative bound for subsequent absence proof
                if last_observed is not None:
                    candidate["last_observed_at"] = max(candidate["last_observed_at"], min(now_wall, last_observed))
                db_flags = aircraft.get("dbFlags")
                # merge only the verified integer flag schema
                if isinstance(db_flags, int) and not isinstance(db_flags, bool) and db_flags >= 0:
                    candidate["dbFlags"] = (candidate["dbFlags"] or 0) | db_flags
        missing_bands = self._declared_bands - sampled_bands
        # omitted samples represent unknown coverage, not quiet reception
        for band in missing_bands:
            self._reset_band(band, now_mono)
        # merge all current band evidence before adjudicating a delayed return
        for hex_id, candidate in candidates.items():
            candidate["last_observed_mono"] = now_mono - max(0.0, now_wall - candidate["last_observed_at"])
            pending = self._pending_returns.get(hex_id)
            # preserve the earliest return and latest sighting across polling cycles
            if pending is not None:
                saved = pending["candidate"]
                saved["first_observed_at"] = min(saved["first_observed_at"], candidate["first_observed_at"])
                saved["observed_at"] = max(saved["observed_at"], candidate["observed_at"])
                saved["last_observed_mono"] = max(
                    saved.get("last_observed_mono", pending["return_mono"]), candidate["last_observed_mono"]
                )
                saved["bands"].update(candidate["bands"])
                saved["receptions"].update(candidate["receptions"])
                saved["dbFlags"] = (saved.get("dbFlags") or 0) | (candidate.get("dbFlags") or 0)
                pending["return_mono"] = min(
                    pending["return_mono"], now_mono - max(0.0, now_wall - candidate["first_observed_at"])
                )
        pending_before = set(self._pending_returns)
        created = self._resolve_pending(settings, now_mono)
        resolved = pending_before - set(self._pending_returns)
        active = {encounter["hex"]: encounter for encounter in self.store.active_encounters()}
        # discard absence clocks only for durably retired identities
        for hex_id in set(self._absence_floor) - set(active):
            self._absence_floor.pop(hex_id, None)
        # apply or defer each fresh merged identity
        for hex_id, candidate in candidates.items():
            # an existing pending return owns this identity until adjudicated
            if hex_id in self._pending_returns or hex_id in resolved:
                continue
            encounter = active.get(hex_id)
            floor = self._absence_floor.get(hex_id, self._boot_mono)
            observation_age = max(0.0, now_wall - candidate["first_observed_at"])
            return_mono = now_mono - observation_age
            # delay a return that may cross a not-yet-finalized 600-second boundary
            if (
                encounter is not None
                and encounter["notified"]
                and floor is not None
                and return_mono - floor >= ABSENCE_SECONDS
            ):
                continuous, proof_floor, finalized_until = self._coverage_proof(encounter["required_bands"], floor)
                # create a new encounter only with finalized proof
                if continuous and finalized_until >= return_mono and return_mono - proof_floor >= ABSENCE_SECONDS:
                    self.store.mark_rearmed(hex_id, rearmed_at=candidate["observed_at"])
                # wait briefly for the source window to close
                elif continuous and return_mono - proof_floor >= ABSENCE_SECONDS:
                    self._pending_returns.setdefault(
                        hex_id,
                        {
                            "candidate": candidate,
                            "return_mono": return_mono,
                            "deadline_mono": now_mono + RETURN_ADJUDICATION_SECONDS,
                        },
                    )
                    continue
            event_id = self._apply_candidate(candidate, settings, return_mono=return_mono)
            # retain only newly created event identities
            if event_id and (encounter is None or event_id != encounter["current_event_id"]):
                created.append(event_id)
        # adjudicate absence only after every fresh return fences its identity
        self._finalize_absence(now_wall, now_mono)
        return created


# read the admin-owned test request envelope without modifying it
def read_test_envelope(path: Path) -> dict[str, Any] | None:
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    # keep the untrusted handoff bounded
    if len(content) > 8 * 1024:
        return None
    try:
        value = json.loads(content)
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        return None
    # require the fixed admin-owned schema
    if not isinstance(value, dict) or frozenset(value) != frozenset(
        ("schema_version", "request_id", "revision", "created_at", "last_requested_at")
    ):
        return None
    # require the first-version flat envelope
    if value.get("schema_version") != 1:
        return None
    return {"id": value["request_id"], "revision": value["revision"], "created_at": value["created_at"]}


# run polling, database writes, and independent bounded sender pools
class AlertWorker:
    # assemble injected local sources and fixed stores
    def __init__(
        self,
        *,
        config_store: AlertSettingsStore,
        store: AlertStore,
        catalog: AlertCatalog,
        source_monitor: Any,
        status_path: Path,
        continuity_path: Path,
        test_request_path: Path | None = None,
        maintenance_report_path: Path | None = None,
        wall_clock: Callable[[], float] = time.time,
        mono_clock: Callable[[], float] = time.monotonic,
        dispatcher: Callable[[dict[str, Any], dict[str, Any]], DeliveryResult] = dispatch_delivery,
    ) -> None:
        self.config_store = config_store
        self.store = store
        self.catalog = catalog
        self.source_monitor = source_monitor
        self.status_path = status_path
        self.continuity_path = continuity_path
        self.test_request_path = test_request_path
        self.maintenance_report_path = maintenance_report_path
        self.wall_clock = wall_clock
        self.mono_clock = mono_clock
        self.dispatcher = dispatcher
        self.engine = AlertEngine(store, catalog)
        self._stop = threading.Event()
        self._reports: queue.SimpleQueue[tuple[dict[str, Any], DeliveryResult, float]] = queue.SimpleQueue()
        self._pools = {
            "pushover": ThreadPoolExecutor(max_workers=2, thread_name_prefix="alert-pushover"),
            "email": ThreadPoolExecutor(max_workers=2, thread_name_prefix="alert-email"),
        }
        self._futures: dict[str, set[Future[DeliveryResult]]] = {channel: set() for channel in self._pools}
        self._futures_lock = threading.Lock()
        self._last_status_mono = -math.inf
        self._last_purge_mono = -math.inf
        self._source_error: str | None = None
        self._last_maintenance_mono = -math.inf
        self._maintenance_error: str | None = None

    # request one bounded worker shutdown
    def stop(self) -> None:
        self._stop.set()

    # deliver one leased job and classify unexpected exceptions safely
    def _send_job(self, job: dict[str, Any], settings: dict[str, Any]) -> DeliveryResult:
        try:
            result = self.dispatcher(job, settings)
        except Exception:
            return DeliveryResult("unknown", "delivery_exception")
        # add bounded backoff and jitter to retryable results
        if result.state == "retry":
            return DeliveryResult("retry", result.error_code, _retry_delay(job, result))
        return result

    # collect one completed future into the writer queue
    def _delivery_done(self, job: dict[str, Any], future: Future[DeliveryResult]) -> None:
        try:
            result = future.result()
        except Exception:
            result = DeliveryResult("unknown", "delivery_exception")
        self._reports.put((job, result, self.wall_clock()))

    # apply completed network outcomes in the single writer thread
    def _drain_reports(self) -> None:
        while True:
            try:
                job, result, completed_at = self._reports.get_nowait()
            except queue.Empty:
                break
            # keep independent maintenance outcomes outside aircraft outboxes
            if job["kind"] == "maintenance":
                self.store.complete_maintenance(job["event_id"], result, now=completed_at)
            else:
                self.store.complete_delivery(job["event_id"], job["channel"], result, now=completed_at)

    # observe new safe review generations without blocking radio polling
    def _process_maintenance(self, settings: dict[str, Any], now_wall: float, now_mono: float) -> None:
        # keep bounded filesystem work off the one-second hot path
        if self.maintenance_report_path is None or now_mono - self._last_maintenance_mono < 10:
            return
        self._last_maintenance_mono = now_mono
        try:
            report = public_report(self.maintenance_report_path, now=datetime.fromtimestamp(now_wall, timezone.utc))
            # incomplete or malformed reports cannot establish a completed review
            stamp = report.get("updated_at") if report.get("status") in {"ok", "attention", "failed"} else None
            reported_at = datetime.fromisoformat(stamp).timestamp() if stamp else None
            subject, body = _maintenance_message(report)
            self.store.observe_maintenance(
                reported_at=reported_at,
                now=now_wall,
                config_revision=settings["revision"],
                smtp_configured=self._configuration_error is None and _smtp_configured(settings),
                subject=subject,
                body=body,
            )
            self._maintenance_error = None
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, RecursionError):
            # optional review state must not stop aircraft processing or change destinations
            self._maintenance_error = "maintenance_notification_unavailable"

    # submit available independent channel work
    def _submit_due(self, settings: dict[str, Any], now_wall: float) -> None:
        # lease independently so one stalled channel cannot consume the peer pool
        for channel in self._futures:
            with self._futures_lock:
                free_slots = max(0, 2 - len(self._futures[channel]))
            # leave work durable while this channel is full
            if free_slots == 0:
                continue
            jobs = []
            # reserve existing email capacity for an independent maintenance summary
            if channel == "email":
                jobs = self.store.claim_maintenance(
                    now=now_wall,
                    config_revision=settings["revision"],
                    smtp_configured=_smtp_configured(settings),
                    limit=free_slots,
                )
            aircraft_limit = free_slots - len(jobs)
            # preserve normal aircraft suppression and revision fencing
            if aircraft_limit:
                jobs.extend(
                    self.store.claim_deliveries(
                        now=now_wall,
                        config_revision=settings["revision"],
                        enabled=settings["enabled"],
                        limit=aircraft_limit,
                        channel=channel,
                    )
                )
            # submit only to the matching channel pool
            for job in jobs:
                future = self._pools[channel].submit(self._send_job, job, settings)
                with self._futures_lock:
                    self._futures[channel].add(future)

                # remove and report one completed job
                def completed(done: Future[DeliveryResult], *, actual_job: dict[str, Any] = job) -> None:
                    with self._futures_lock:
                        self._futures[actual_job["channel"]].discard(done)
                    self._delivery_done(actual_job, done)

                future.add_done_callback(completed)

    # acknowledge one admin-owned fixed test request
    def _process_test_request(self, settings: dict[str, Any], now_wall: float) -> None:
        # skip when no admin handoff path is configured
        if self.test_request_path is None:
            return
        request = read_test_envelope(self.test_request_path)
        # preserve an empty or invalid slot without guessing
        if request is None:
            return
        try:
            self.store.acknowledge_test(
                request["id"],
                config_revision=request["revision"],
                created_at=request["created_at"],
                current_revision=settings["revision"],
                enabled=settings["enabled"],
                now=now_wall,
            )
        except (KeyError, TypeError, ValueError):
            return

    # read safe source identity for the minimum heartbeat contract
    def _source_status(self) -> dict[str, Any]:
        status_method = getattr(self.source_monitor, "status", None)
        # prefer the monitor's bounded status projection
        if callable(status_method):
            try:
                value = status_method()
            except Exception:
                value = {}
            # accept only an object projection
            if isinstance(value, dict):
                return value
        return {
            "activation_id": getattr(self.source_monitor, "activation_id", ""),
            "source_contract_digest": getattr(self.source_monitor, "contract_digest", ""),
        }

    # publish liveness and backup continuity at most every ten seconds
    def _publish_status(self, settings: dict[str, Any], now_wall: float, now_mono: float) -> None:
        # retain the current heartbeat between intervals
        if now_mono - self._last_status_mono < STATUS_INTERVAL_SECONDS:
            return
        source_status = self._source_status()
        activation_id = source_status.get("activation_id", "")
        contract_digest = source_status.get("source_contract_digest", "")
        value = {
            "schema_version": 1,
            "activation_id": activation_id if isinstance(activation_id, str) else "",
            "source_contract_digest": contract_digest if isinstance(contract_digest, str) else "",
            "sampled_at": now_wall,
            "process_running": True,
            "enabled": settings["enabled"],
            "applied_revision": settings["revision"],
            "catalog_version": self.catalog.version,
            "source_error": self._source_error,
            "configuration_error": getattr(self, "_configuration_error", None),
            "bands": source_status.get("bands", {}),
            "channels": self.store.delivery_status(),
            "capacity_rejections": self.store.capacity_rejections(),
            "capacity_error": self.engine.capacity_error,
            "maintenance_email": self.store.maintenance_status(),
        }
        # maintenance readiness depends on smtp rather than aircraft or radio switches
        if not _smtp_configured(settings):
            value["maintenance_email"]["state"] = "not_configured"
        # surface optional report or configuration failures without claiming delivery readiness
        elif self._maintenance_error or getattr(self, "_configuration_error", None):
            value["maintenance_email"].update(
                state="unknown", error=self._maintenance_error or "configuration_unavailable"
            )
        _atomic_json(self.status_path, value)
        generation = value["activation_id"] or "unavailable"
        self.store.write_continuity_snapshot(self.continuity_path, generation=generation, generated_at=now_wall)
        self._last_status_mono = now_mono

    # execute one nonblocking poll and scheduling cycle
    def run_once(self) -> None:
        now_wall = self.wall_clock()
        now_mono = self.mono_clock()
        self._drain_reports()
        try:
            self.config_store.refresh()
            settings = self.config_store.get_private()
            self._configuration_error = None
        except RuntimeError:
            # keep process liveness visible without using stale destinations
            settings = self.config_store.get_private()
            settings["enabled"] = False
            self._configuration_error = "configuration_unavailable"
        try:
            samples = self.source_monitor.poll(now_wall=now_wall, now_mono=now_mono)
            # reject malformed monitor output as unknown
            if not isinstance(samples, list):
                raise ValueError("source monitor returned invalid samples")
            self._source_error = None
        except Exception:
            samples = []
            self._source_error = "source_unavailable"
        self.engine.process_samples(samples, settings, now_wall, now_mono)
        self._process_maintenance(settings, now_wall, now_mono)
        # do not turn unreadable configuration into an operator-requested suppression
        if self._configuration_error is None:
            self._process_test_request(settings, now_wall)
            self._submit_due(settings, now_wall)
        # keep retention work off the one-second hot path
        if now_mono - self._last_purge_mono >= 3_600:
            self.store.purge_history(now=now_wall)
            self._last_purge_mono = now_mono
        self._publish_status(settings, now_wall, now_mono)

    # run until signaled and drain bounded in-flight transport calls
    def run(self) -> None:
        while not self._stop.is_set():
            started = self.mono_clock()
            self.run_once()
            remaining = max(0.0, POLL_INTERVAL_SECONDS - (self.mono_clock() - started))
            self._stop.wait(remaining)
        # stop accepting new sender work and wait for socket timeouts
        for pool in self._pools.values():
            pool.shutdown(wait=True, cancel_futures=True)
        self._drain_reports()


# parse fixed host-worker paths
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run station-local aircraft notifications")
    parser.add_argument("--config", type=Path, default=Path("/var/lib/adsb/config/alerts.json"))
    parser.add_argument("--test-request", type=Path, default=Path("/var/lib/adsb/config/alerts-test.json"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/adsb/alerts"))
    parser.add_argument("--catalog", type=Path, default=Path("/opt/adsb/current/deploy/alerts/catalog.json"))
    parser.add_argument(
        "--catalog-manifest", type=Path, default=Path("/opt/adsb/current/deploy/alerts/catalog-manifest.json")
    )
    parser.add_argument("--source-root", type=Path, default=Path("/var/lib/adsb"))
    parser.add_argument(
        "--source-manifest", type=Path, default=Path("/opt/adsb/current/deploy/alerts/source-contract.json")
    )
    return parser


# construct the release worker without secrets in argv or environment
def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    from adsb_admin.alert_sources import AlertSourceMonitor

    config_store = AlertSettingsStore(arguments.config, readonly=True)
    store = AlertStore(arguments.state_dir / "alerts.sqlite3")
    store.restore_continuity(arguments.state_dir / "continuity.json")
    catalog = AlertCatalog.from_paths(arguments.catalog, arguments.catalog_manifest)
    source_monitor = AlertSourceMonitor(root=arguments.source_root, manifest_path=arguments.source_manifest)
    worker = AlertWorker(
        config_store=config_store,
        store=store,
        catalog=catalog,
        source_monitor=source_monitor,
        status_path=arguments.state_dir / "worker-status.json",
        continuity_path=arguments.state_dir / "continuity.json",
        test_request_path=arguments.test_request,
        maintenance_report_path=arguments.source_root / "status/maintenance.json",
    )

    # request graceful bounded shutdown on service signals
    def stop_worker(_signum: int, _frame: Any) -> None:
        worker.stop()

    signal.signal(signal.SIGTERM, stop_worker)
    signal.signal(signal.SIGINT, stop_worker)
    try:
        worker.run()
    finally:
        source_monitor.close()
        store.close()
    return 0


# run the host worker module directly
if __name__ == "__main__":
    raise SystemExit(main())
