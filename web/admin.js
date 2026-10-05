"use strict";

const NETWORK_IDS = ["adsbexchange", "flightaware", "adsblol", "airplaneslive"];
const ALERT_CATEGORIES = ["military", "medical", "news"];
const MAX_ALERT_OVERRIDES = 2000;
const ALERT_SECRET_FIELDS = {
  "pushover.app_token": "alerts-pushover-token",
  "pushover.user_key": "alerts-pushover-user-key",
  "smtp.username": "alerts-smtp-username",
  "smtp.password": "alerts-smtp-password"
};
const ALERT_FIELD_ERROR_IDS = {
  categories: "alerts-categories",
  "pushover.app_token": "alerts-pushover-token",
  "pushover.user_key": "alerts-pushover-user-key",
  "smtp.host": "alerts-smtp-host",
  "smtp.port": "alerts-smtp-port",
  "smtp.username": "alerts-smtp-username",
  "smtp.password": "alerts-smtp-password",
  "smtp.from_address": "alerts-smtp-from",
  "smtp.to_address": "alerts-smtp-to",
  overrides: "alerts-overrides"
};
const PHASE_LABELS = {
  starting: "Applying configuration",
  ready: "Software ready",
  error: "Controller error",
  waiting: "Awaiting radios"
};
const RECEPTION_LABELS = {
  absent: "No radio",
  stopped: "Service stopped",
  unavailable: "Unavailable",
  stale: "Stale telemetry",
  monitoring: "Calculating",
  quiet: "Quiet",
  receiving: "Receiving"
};
const FIELD_ERROR_IDS = {
  "station.name": "station-name",
  "station.latitude": "station-latitude",
  "station.longitude": "station-longitude",
  "station.altitude_m": "station-altitude"
};

let csrfToken = "";
let currentRevision = 0;
let statusPollId = null;
let alertRevision = 0;
let alertConfigDirty = false;
let alertConfigHydrated = false;
let alertConfigSaving = false;
let alertSessionGeneration = 0;
let alertHistoryCursor = null;
let alertHistoryLoading = false;
let alertStatusPollCount = 0;
let alertTestPending = false;
let alertTestCooldownUntil = 0;
let alertOverrideSequence = 0;
const feederActions = new Map();
const alertSecretActions = new Map();

// find one required element
function element(id) {
  return document.getElementById(id);
}

// request same-origin json
async function requestJson(path, options = {}) {
  const requestOptions = { ...options };
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");

  // describe json bodies
  if (options.body) {
    headers.set("Content-Type", "application/json");
  }

  requestOptions.headers = headers;
  requestOptions.credentials = "same-origin";
  const response = await fetch(path, requestOptions);
  const responseText = await response.text();
  let data = {};

  // parse nonempty responses
  if (responseText) {
    // tolerate non-json errors
    try {
      data = JSON.parse(responseText);
    } catch (error) {
      data = { error: "The server returned an unreadable response." };
    }
  }

  // surface request failures
  if (!response.ok) {
    const requestError = new Error(data.error || `Request failed with status ${response.status}.`);
    requestError.status = response.status;
    requestError.data = data;
    throw requestError;
  }

  return data;
}

// stop controller polling
function stopStatusPolling() {
  // clear an active timer
  if (statusPollId !== null) {
    window.clearInterval(statusPollId);
    statusPollId = null;
  }
}

// show signed-out state
function showLogin(message = "") {
  stopStatusPolling();
  clearAlertSessionState();
  csrfToken = "";
  element("loading-view").hidden = true;
  element("admin-view").hidden = true;
  element("logout-button").hidden = true;
  element("login-view").hidden = false;
  element("login-error").textContent = message;
  element("login-error").hidden = !message;
  element("password").focus();
}

// show signed-in state
function showAdmin() {
  element("loading-view").hidden = true;
  element("login-view").hidden = true;
  element("admin-view").hidden = false;
  element("logout-button").hidden = false;
}

// handle expired sessions
function handleAuthenticationError(error) {
  // return to login on unauthorized
  if (error.status === 401) {
    showLogin("Your session expired. Sign in again.");
    return true;
  }

  return false;
}

// parse an optional numeric field
function optionalNumber(input) {
  const rawValue = input.value.trim();

  // preserve empty values as null
  if (!rawValue) {
    return null;
  }

  const value = Number(rawValue);

  // reject nonfinite values
  if (!Number.isFinite(value)) {
    throw new Error(`${input.labels[0].textContent} must be a valid number.`);
  }

  return value;
}

// format an optional input value
function setOptionalValue(input, value) {
  // clear null values
  if (value === null || value === undefined) {
    input.value = "";
    return;
  }

  input.value = String(value);
}

// describe requested feed state
function renderRequestedState(networkId, enabled) {
  const requested = element(`${networkId}-requested`);
  requested.textContent = enabled ? "Requested: on" : "Requested: off";
  requested.classList.toggle("state-on", enabled);
  requested.classList.toggle("state-off", !enabled);
}

// synchronize dependent network controls
function syncNetworkControls(networkId) {
  const enabled = element(`${networkId}-enabled`).checked;
  element(`${networkId}-mlat`).disabled = !enabled;
  renderRequestedState(networkId, enabled);
}

// handle a feed enable change
function handleNetworkToggle(event) {
  const networkId = event.currentTarget.dataset.networkId;

  // turn off dependent mlat requests
  if (!event.currentTarget.checked) {
    element(`${networkId}-mlat`).checked = false;
  }

  syncNetworkControls(networkId);
  clearSaveMessage();
}

// note a replacement feeder id
function handleFeederInput(event) {
  const networkId = event.currentTarget.dataset.networkId;
  const value = event.currentTarget.value.trim();

  // send only nonempty replacements
  if (value) {
    feederActions.set(networkId, "replace");
    element(`${networkId}-feeder-hint`).textContent = "New feeder ID will replace the saved value";
    element(`${networkId}-clear`).textContent = "Discard replacement";
    element(`${networkId}-clear`).hidden = false;
  } else {
    feederActions.set(networkId, "unchanged");
    restoreFeederHint(networkId);
  }

  clearSaveMessage();
}

// generate a local replacement uuid
function handleGenerateFeeder(event) {
  const networkId = event.currentTarget.dataset.networkId;
  const feederInput = element(`${networkId}-feeder-id`);

  // require secure uuid support
  if (!window.crypto || typeof window.crypto.randomUUID !== "function") {
    showSaveMessage("This browser cannot generate a secure UUID. Enter a stable feeder ID manually.", "error");
    return;
  }

  feederInput.value = window.crypto.randomUUID();
  feederActions.set(networkId, "replace");
  element(`${networkId}-feeder-hint`).textContent = "New locally generated UUID will replace the saved value";
  element(`${networkId}-clear`).textContent = "Discard replacement";
  element(`${networkId}-clear`).hidden = false;
  clearFieldErrors();
  showSaveMessage("UUID generated locally. Save settings to apply it; no network account was registered.", "progress");
}

// restore the server-backed feeder hint
function restoreFeederHint(networkId) {
  const input = element(`${networkId}-feeder-id`);
  const configured = input.dataset.configured === "true";
  input.value = "";
  element(`${networkId}-feeder-hint`).textContent = configured
    ? "Saved feeder ID: ••••••••"
    : "No feeder ID is configured";
  element(`${networkId}-clear`).textContent = "Clear saved feeder ID";
  element(`${networkId}-clear`).hidden = !configured || networkId === "flightaware";
}

// clear or undo feeder changes
function handleClearFeeder(event) {
  const networkId = event.currentTarget.dataset.networkId;
  const action = feederActions.get(networkId);

  // prevent PiAware cache and settings identities from diverging
  if (networkId === "flightaware" && action !== "replace") {
    return;
  }

  // undo a pending action
  if (action === "clear" || action === "replace") {
    feederActions.set(networkId, "unchanged");
    restoreFeederHint(networkId);
  } else {
    feederActions.set(networkId, "clear");
    element(`${networkId}-feeder-id`).value = "";
    element(`${networkId}-feeder-hint`).textContent = "Saved feeder ID will be cleared";
    element(`${networkId}-clear`).textContent = "Undo clear";
    element(`${networkId}-clear`).hidden = false;
  }

  clearSaveMessage();
}

// apply server configuration to the form
function renderConfig(config) {
  const station = config.station || {};
  const networks = config.networks || {};
  currentRevision = Number.isInteger(config.revision) ? config.revision : 0;
  element("revision-label").textContent = `Revision ${currentRevision}`;
  element("station-name").value = typeof station.name === "string" ? station.name : "";
  setOptionalValue(element("station-latitude"), station.latitude);
  setOptionalValue(element("station-longitude"), station.longitude);
  setOptionalValue(element("station-altitude"), station.altitude_m);

  // render each supported network
  for (const networkId of NETWORK_IDS) {
    const network = networks[networkId] || {};
    const enabled = network.enabled === true;
    const mlat = network.mlat === true;
    const feederInput = element(`${networkId}-feeder-id`);
    element(`${networkId}-enabled`).checked = enabled;
    element(`${networkId}-mlat`).checked = mlat;
    feederInput.dataset.configured = String(network.feeder_id_configured === true);
    feederActions.set(networkId, "unchanged");
    restoreFeederHint(networkId);
    syncNetworkControls(networkId);
  }
}

// describe a controller phase
function renderPhase(status) {
  const phase = typeof status.phase === "string" ? status.phase : "waiting";
  const phaseBadge = element("phase-badge");
  const label = PHASE_LABELS[phase] || "Controller status unknown";
  phaseBadge.className = `phase-badge phase-${PHASE_LABELS[phase] ? phase : "waiting"}`;
  element("phase-label").textContent = label;
}

// describe one feed runtime
function renderNetworkRuntime(networkId, runtime) {
  const output = element(`${networkId}-runtime`);

  // update the provider-issued FlightAware claim action
  if (networkId === "flightaware") {
    const claimLink = element("flightaware-claim");
    const claimUrl = runtime && typeof runtime.claim_url === "string" ? runtime.claim_url : "";
    claimLink.hidden = !claimUrl;
    // retain only server-validated destinations
    if (claimUrl) {
      claimLink.href = claimUrl;
    } else {
      claimLink.removeAttribute("href");
    }
  }

  // handle absent controller data
  if (!runtime) {
    output.textContent = "Controller status unavailable";
    output.className = "runtime-state";
    return;
  }

  // distinguish process state from network acceptance
  if (runtime.running === true) {
    // label tcp presence only
    if (runtime.connected === true) {
      output.textContent = "Uploader running; TCP connected only. Upstream acceptance not verified";
    } else if (runtime.connected === false) {
      output.textContent = "Uploader running; TCP not connected. Upstream acceptance not verified";
    } else {
      output.textContent = "Uploader process running; upstream acceptance not verified";
    }

    output.className = "runtime-state runtime-running";
  } else if (runtime.connected === true) {
    output.textContent = "TCP connected, but uploader process is not reported running. Upstream acceptance not verified";
    output.className = "runtime-state runtime-warning";
  } else if (runtime.enabled === true) {
    output.textContent = runtime.message || "Enabled, but uploader process is not running";
    output.className = "runtime-state runtime-warning";
  } else {
    output.textContent = runtime.message || "Uploader disabled";
    output.className = "runtime-state";
  }
}

// normalize one backend field message
function fieldMessage(value) {
  // join structured message arrays
  if (Array.isArray(value)) {
    return value.join(" ");
  }

  return String(value);
}

// clear backend field validation
function clearFieldErrors() {
  // clear every mapped field
  for (const inputId of Object.values(FIELD_ERROR_IDS)) {
    const input = element(inputId);
    const output = element(`${inputId}-error`);
    input.removeAttribute("aria-invalid");
    output.textContent = "";
    output.hidden = true;
  }
}

// render backend validation messages
function renderFieldErrors(fields) {
  const summary = [];
  clearFieldErrors();

  // render every returned field safely
  for (const [fieldName, rawMessage] of Object.entries(fields || {})) {
    const message = fieldMessage(rawMessage);
    const inputId = FIELD_ERROR_IDS[fieldName];
    summary.push(`${fieldName}: ${message}`);

    // attach known station errors to inputs
    if (inputId) {
      const input = element(inputId);
      const output = element(`${inputId}-error`);
      input.setAttribute("aria-invalid", "true");
      output.textContent = message;
      output.hidden = false;
    }
  }

  return summary.join(" ");
}

// format a controller timestamp
function formatTimestamp(value) {
  // handle absent timestamps
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  // handle invalid timestamps
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

// format one bounded message rate
function formatMessageRate(value) {
  // reject absent or invalid rate claims
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return "—";
  }

  return `${Math.round(value).toLocaleString()} msg/min`;
}

// describe one source-specific receiver
function renderReceptionSource(band, source) {
  const status = source && typeof source.telemetry_state === "string"
    ? source.telemetry_state
    : "unavailable";
  const normalizedStatus = RECEPTION_LABELS[status] ? status : "unavailable";
  const state = element(`reception-${band}-state`);
  state.textContent = RECEPTION_LABELS[normalizedStatus];
  state.className = `reception-state reception-${normalizedStatus}`;
  element(`reception-${band}-rate`).textContent = formatMessageRate(source && source.messages_per_minute);
  element(`reception-${band}-last`).textContent = formatTimestamp(source && source.last_activity_at);
  element(`reception-${band}-sample`).textContent = formatTimestamp(source && source.sample_at);

  const detail = element(`reception-${band}-detail`);
  // explain missing hardware without implying a software fault
  if (normalizedStatus === "absent") {
    detail.textContent = `No ${band} MHz receiver is detected.`;
  } else if (normalizedStatus === "stopped") {
    detail.textContent = "Receiver hardware is detected, but its decoder service is not running.";
  } else if (normalizedStatus === "stale") {
    detail.textContent = "The source JSON is stale. Its timestamp is not being counted as radio reception.";
  } else if (normalizedStatus === "monitoring") {
    detail.textContent = "Telemetry is current; a second counter sample is needed before calculating a rate.";
  } else if (normalizedStatus === "quiet") {
    detail.textContent = band === "978"
      ? "No UAT messages arrived in the latest interval. Quiet 978 MHz traffic is normal."
      : "No Mode-S messages appeared in the latest Airspy one-minute counter sample.";
  } else if (normalizedStatus === "receiving") {
    detail.textContent = "Positive source-specific message counters verify local radio activity.";
  } else {
    detail.textContent = "No valid source telemetry is available; reception is not being inferred from process state.";
  }

  return normalizedStatus;
}

// render separate 1090 and 978 reception truth
function renderReception(reception) {
  const sources = reception || {};
  const states = [];
  // render both supported radio bands
  for (const band of ["1090", "978"]) {
    states.push(renderReceptionSource(band, sources[band]));
  }

  const readinessTitle = element("readiness-title");
  const readinessMessage = element("readiness-message");
  const receivingBands = [];
  // identify only bands with positive source counters
  for (let index = 0; index < states.length; index += 1) {
    // retain the matching fixed band label
    if (states[index] === "receiving") {
      receivingBands.push(["1090", "978"][index]);
    }
  }
  // promote only positive source counters to verified reception
  if (receivingBands.length > 0) {
    readinessTitle.textContent = "Live radio reception verified";
    readinessMessage.textContent = `${receivingBands.join(" and ")} MHz source counters show genuine local messages. A quiet 978 MHz interval is normal and does not indicate failure.`;
  } else if (states.includes("quiet") || states.includes("monitoring")) {
    readinessTitle.textContent = "Receiver telemetry is current";
    readinessMessage.textContent = "No positive source counter is visible in the latest sample. This can be normal during a quiet interval, especially on 978 MHz.";
  } else if (states.includes("stale")) {
    readinessTitle.textContent = "Reception telemetry is stale";
    readinessMessage.textContent = "A source stopped updating. Its old JSON timestamp is not being presented as recent radio activity.";
  } else {
    readinessTitle.textContent = "Awaiting verified local radio reception";
    readinessMessage.textContent = "No current source-specific message counter is available, so live reception is not being claimed.";
  }
}

// render one safe maintenance email state
function renderMaintenanceEmail(value) {
  const notification = alertObject(value);
  const state = typeof notification.state === "string" ? notification.state : "unknown";
  const labels = {
    not_configured: "SMTP not configured",
    waiting: "Waiting for next review",
    pending: "Queued",
    in_flight: "Sending",
    retry: "Retrying",
    accepted: "Accepted by SMTP server",
    failed: "Failed",
    expired: "Failed",
    suppressed: "Suppressed",
    unknown: "Unknown"
  };
  let label = labels[state] || labels.unknown;
  // add only the timestamp relevant to the current outcome
  if (state === "accepted" && notification.accepted_at !== null && notification.accepted_at !== undefined) {
    label = `${label} ${formatAlertTimestamp(notification.accepted_at)}`;
  } else if (state === "retry" && notification.retry_at !== null && notification.retry_at !== undefined) {
    label = `${label} ${formatAlertTimestamp(notification.retry_at)}`;
  }
  element("maintenance-email-notification").textContent = label;
}

// render the bounded weekly maintenance report
function renderMaintenance(report) {
  const status = report && ["ok", "attention", "failed"].includes(report.status) ? report.status : "unknown";
  const state = element("maintenance-state");
  state.className = `maintenance-state maintenance-${status === "failed" ? "attention" : status}`;
  state.textContent = status === "ok"
    ? "Review current"
    : status === "attention"
      ? "Review needed"
      : status === "failed"
        ? "Review failed"
        : "Report unavailable";
  element("maintenance-updated").textContent = formatTimestamp(report && report.updated_at);
  element("maintenance-schedule").textContent = report && report.os_schedule
    ? report.os_schedule
    : "Tuesdays 04:00 America/Los_Angeles";
  element("maintenance-policy").textContent = report && report.application_policy
    ? report.application_policy
    : "Pinned releases; updates require review";
  element("maintenance-disk").textContent = report && typeof report.disk_free_percent === "number"
    ? `${report.disk_free_percent.toFixed(1)}%`
    : "—";
  element("maintenance-reboot").textContent = report && report.reboot_required === true
    ? "Required"
    : report && report.reboot_required === false
      ? "Not required"
      : "Unknown";

  const images = report && Array.isArray(report.images) ? report.images : [];
  let imageReviews = 0;
  // count only reviewed container updates
  for (const image of images) {
    // ignore current or unknown image records
    if (image && image.status === "review") {
      imageReviews += 1;
    }
  }
  const mapReview = report && report.map_status === "review";
  // summarize only server-reviewed release results
  if (status === "unknown") {
    element("maintenance-releases").textContent = "Unknown";
    element("maintenance-summary").textContent = "No completed maintenance report has been received.";
  } else {
    const reviewCount = imageReviews + (mapReview ? 1 : 0);
    element("maintenance-releases").textContent = status === "failed"
      ? "Unknown"
      : reviewCount > 0
        ? `${reviewCount} item${reviewCount === 1 ? "" : "s"} need review`
        : "No reviewed updates pending";
    element("maintenance-summary").textContent = status === "ok"
      ? "The latest Tuesday review completed without an item requiring attention."
      : status === "failed"
        ? "The latest Tuesday review failed and needs operator attention."
        : "The latest Tuesday review found an item that needs operator attention.";
  }
  renderMaintenanceEmail(report && report.email_notifications);
}

// summarize hardware without inventing reception
function renderHardware(hardware) {
  const readinessTitle = element("readiness-title");
  const readinessMessage = element("readiness-message");
  const hardwareStatus = element("hardware-status");

  readinessTitle.textContent = "Awaiting verified local radio reception";

  // report usb presence only
  if (hardware && hardware.connected === true) {
    readinessMessage.textContent = "USB receiver hardware is connected. Device presence does not prove aircraft reception; no live reception has been verified.";
    hardwareStatus.textContent = hardware.message
      ? `USB connected — ${hardware.message}`
      : "USB receiver connected; reception unverified";
  } else if (hardware && hardware.connected === false) {
    readinessMessage.textContent = "No USB receiver connection is reported. Aircraft appear only after local radio hardware connects and receives genuine traffic.";
    hardwareStatus.textContent = hardware.message
      ? `USB not connected — ${hardware.message}`
      : "USB receiver not connected";
  } else {
    readinessMessage.textContent = "The software can be configured now. Aircraft appear only when attached radios receive real traffic; no live reception has been verified.";
    hardwareStatus.textContent = hardware && hardware.message
      ? hardware.message
      : "No radio telemetry reported";
  }
}

// apply controller status
function renderStatus(status) {
  renderPhase(status);
  // keep saved intent distinct from the last applied configuration
  if (status.phase !== "error" && (!Number.isInteger(status.applied_revision) || status.applied_revision < currentRevision)) {
    element("phase-badge").className = "phase-badge phase-starting";
    element("phase-label").textContent = "Saved settings not yet applied";
  }
  element("applied-revision").textContent = Number.isInteger(status.applied_revision)
    ? String(status.applied_revision)
    : "—";
  element("last-update").textContent = formatTimestamp(status.updated_at);
  renderHardware(status.hardware);
  renderReception(status.reception);

  // render all supported runtimes
  for (const networkId of NETWORK_IDS) {
    renderNetworkRuntime(networkId, status.networks && status.networks[networkId]);
  }
}

// refresh the latest weekly maintenance result
async function loadMaintenance() {
  const sessionGeneration = alertSessionGeneration;
  try {
    const report = await requestJson("/api/admin/maintenance");
    // discard a response from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    renderMaintenance(report);
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    renderMaintenance(null);
  }
}

// load current configuration
async function loadConfig() {
  const sessionGeneration = alertSessionGeneration;
  const config = await requestJson("/api/admin/config");
  // discard a response from a session that has since ended
  if (sessionGeneration !== alertSessionGeneration) {
    return;
  }
  renderConfig(config);
}

// refresh current controller status
async function loadStatus() {
  const sessionGeneration = alertSessionGeneration;
  // keep polling failures nonfatal
  try {
    const status = await requestJson("/api/admin/status");
    // discard a response from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    renderStatus(status);
    await loadMaintenance();
    // stop a stale poll before requesting alert health
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    element("phase-badge").className = "phase-badge phase-error";
    element("phase-label").textContent = "Status unavailable";
  }

  // keep alert health independent from core receiver health
  try {
    const alertStatus = await requestJson("/api/admin/alerts/status");
    // discard a response from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    renderAlertStatus(alertStatus);
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    renderAlertStatusUnavailable(error.message || "Alert status is unavailable.");
  }

  alertStatusPollCount += 1;
  // refresh the newest history page without changing settings drafts
  if (alertStatusPollCount % 3 === 0 && !alertHistoryLoading) {
    await loadAlertHistory(true, true);
  }
}

// begin periodic status refreshes
function startStatusPolling() {
  stopStatusPolling();
  statusPollId = window.setInterval(loadStatus, 10000);
}

// load authenticated views
async function loadAdmin() {
  const sessionGeneration = alertSessionGeneration;
  showAdmin();

  // load config before polling
  try {
    await loadConfig();
    // stop a stale login flow before it can hydrate private controls
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // keep an alert-config failure from hiding station controls
    try {
      await loadAlertConfig(true);
    } catch (error) {
      // ignore a failure from a session that has since ended
      if (sessionGeneration !== alertSessionGeneration) {
        return;
      }
      // hand off expired sessions
      if (handleAuthenticationError(error)) {
        return;
      }

      showAlertSaveMessage(error.message || "Unable to load alert configuration.", "error");
    }
    // stop a stale login flow before starting ancillary requests
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    await loadAlertHistory(true, false);
    // stop a stale login flow before requesting current status
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    await loadStatus();
    // keep an old load from starting polling for a newer session
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    startStatusPolling();
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    showSaveMessage(error.message || "Unable to load station configuration.", "error");
  }
}

// submit the password
async function handleLogin(event) {
  event.preventDefault();
  const passwordInput = element("password");
  const loginButton = element("login-button");
  let sessionGeneration = alertSessionGeneration;
  element("login-error").hidden = true;

  // require a password locally
  if (!passwordInput.value) {
    element("login-error").textContent = "Enter the admin password.";
    element("login-error").hidden = false;
    passwordInput.focus();
    return;
  }

  loginButton.disabled = true;
  loginButton.textContent = "Signing in…";

  // submit without retaining the password
  try {
    const session = await requestJson("/api/login", {
      method: "POST",
      body: JSON.stringify({ password: passwordInput.value })
    });
    // discard a response after another session transition
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }

    // require the expected session contract
    if (session.authenticated !== true || typeof session.csrf_token !== "string") {
      throw new Error("The server did not establish an admin session.");
    }

    alertSessionGeneration += 1;
    sessionGeneration = alertSessionGeneration;
    csrfToken = session.csrf_token;
    passwordInput.value = "";
    await loadAdmin();
  } catch (error) {
    // ignore a failure from an older login attempt
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    passwordInput.value = "";
    element("login-error").textContent = error.message || "Sign-in failed.";
    element("login-error").hidden = false;
    passwordInput.focus();
  } finally {
    // avoid changing controls owned by a newer session
    if (sessionGeneration === alertSessionGeneration) {
      loginButton.disabled = false;
      loginButton.textContent = "Sign in";
    }
  }
}

// end the current session
async function handleLogout() {
  const sessionGeneration = alertSessionGeneration;
  element("logout-button").disabled = true;

  // attempt server logout before clearing local state
  try {
    await requestJson("/api/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
      body: JSON.stringify({})
    });
    // discard a response after another session transition
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // ignore already-expired sessions
    if (error.status !== 401) {
      showSaveMessage(error.message || "Logout failed.", "error");
      element("logout-button").disabled = false;
      return;
    }
  }

  element("logout-button").disabled = false;
  showLogin();
}

// assemble a full configuration update
function collectConfig() {
  const latitudeInput = element("station-latitude");
  const longitudeInput = element("station-longitude");

  // use browser constraints first
  if (!element("settings-form").checkValidity()) {
    element("settings-form").reportValidity();
    throw new Error("Correct the highlighted station fields before saving.");
  }

  const latitude = optionalNumber(latitudeInput);
  const longitude = optionalNumber(longitudeInput);
  const networks = {};

  // enforce coordinate ranges explicitly
  if (latitude !== null && (latitude < -90 || latitude > 90)) {
    throw new Error("Latitude must be between −90 and 90 degrees.");
  }

  // enforce coordinate ranges explicitly
  if (longitude !== null && (longitude < -180 || longitude > 180)) {
    throw new Error("Longitude must be between −180 and 180 degrees.");
  }

  // collect supported networks only
  for (const networkId of NETWORK_IDS) {
    const network = {
      enabled: element(`${networkId}-enabled`).checked,
      mlat: element(`${networkId}-mlat`).checked
    };
    const feederAction = feederActions.get(networkId);

    // include an explicit replacement only
    if (feederAction === "replace") {
      network.feeder_id = element(`${networkId}-feeder-id`).value.trim();
    }

    // include an explicit clear only
    if (feederAction === "clear") {
      network.feeder_id = "";
    }

    networks[networkId] = network;
  }

  return {
    revision: currentRevision,
    station: {
      name: element("station-name").value.trim(),
      latitude,
      longitude,
      altitude_m: optionalNumber(element("station-altitude"))
    },
    networks
  };
}

// clear save feedback after edits
function clearSaveMessage() {
  element("save-message").textContent = "";
  element("save-message").className = "save-message";
}

// display save feedback
function showSaveMessage(message, kind) {
  element("save-message").textContent = message;
  element("save-message").className = `save-message save-message-${kind}`;
}

// clear feedback for form edits
function handleSettingsInput() {
  clearFieldErrors();
  clearSaveMessage();
}

// save complete station configuration
async function handleSave(event) {
  event.preventDefault();
  const saveButton = element("save-button");
  const sessionGeneration = alertSessionGeneration;
  let config;

  // validate before changing progress state
  try {
    clearFieldErrors();
    config = collectConfig();
  } catch (error) {
    showSaveMessage(error.message, "error");
    return;
  }

  saveButton.disabled = true;
  saveButton.textContent = "Saving…";
  showSaveMessage("Applying configuration to the station controller…", "progress");

  // persist then reload canonical state
  try {
    await requestJson("/api/admin/config", {
      method: "PUT",
      headers: { "X-CSRF-Token": csrfToken },
      body: JSON.stringify(config)
    });
    // stop an accepted write from changing a newer session
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    await loadConfig();
    // stop an old save before requesting current status
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    await loadStatus();
    // stop an old save before changing newer feedback
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    showSaveMessage(`Settings saved as revision ${currentRevision}. Controller status is shown below.`, "success");
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    // explain optimistic-lock conflicts
    if (error.status === 409) {
      showSaveMessage("These settings changed in another session. Reload the page to review the latest revision before saving again.", "error");
    } else if (error.data && error.data.fields) {
      const validationSummary = renderFieldErrors(error.data.fields);
      showSaveMessage(validationSummary || "The server rejected one or more settings.", "error");
    } else {
      showSaveMessage(error.message || "Unable to save settings.", "error");
    }
  } finally {
    // avoid changing controls owned by a newer session
    if (sessionGeneration === alertSessionGeneration) {
      saveButton.disabled = false;
      saveButton.textContent = "Save settings";
    }
  }
}

// clear private alert state when the session ends
function clearAlertSessionState() {
  alertSessionGeneration += 1;
  alertRevision = 0;
  alertConfigDirty = false;
  alertConfigHydrated = false;
  alertConfigSaving = false;
  alertHistoryCursor = null;
  alertHistoryLoading = false;
  alertStatusPollCount = 0;
  alertTestPending = false;
  alertTestCooldownUntil = 0;
  alertOverrideSequence = 0;
  alertSecretActions.clear();

  // clear every secret field without retaining browser values
  for (const inputId of Object.values(ALERT_SECRET_FIELDS)) {
    const input = element(inputId);
    input.value = "";
    input.dataset.configured = "false";
  }

  element("alerts-override-list").replaceChildren();
  element("alerts-history-list").replaceChildren();
  element("alerts-test-results").replaceChildren();
  // restore controls without waiting for stale request cleanup
  element("login-button").disabled = false;
  element("login-button").textContent = "Sign in";
  element("logout-button").disabled = false;
  element("save-button").disabled = false;
  element("save-button").textContent = "Save settings";
  clearSaveMessage();
  element("alerts-history-loading").hidden = true;
  element("alerts-history-error").textContent = "";
  element("alerts-history-error").hidden = true;
  element("alerts-history-more").disabled = false;
  element("alerts-history-more").hidden = true;
  element("alerts-test-button").disabled = true;
  element("alerts-test-message").textContent = "";
  element("alerts-test-message").className = "save-message";
  element("alerts-save-button").textContent = "Save alert settings";
  showAlertSaveMessage("", "");
  updateAlertConfigControls();
}

// normalize optional status objects
function alertObject(value) {
  // accept plain response objects only
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }

  return {};
}

// format server timestamps supplied as iso text or unix numbers
function formatAlertTimestamp(value) {
  // preserve absent values as unknown
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  let timestamp = value;
  // convert unix seconds while preserving millisecond values
  if (typeof timestamp === "number" && Number.isFinite(timestamp) && Math.abs(timestamp) < 100000000000) {
    timestamp *= 1000;
  }

  const date = new Date(timestamp);
  // avoid presenting invalid dates as real times
  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

// turn a bounded machine state into a readable label
function formatAlertState(value, fallback = "Unknown") {
  // require a useful state string
  if (typeof value !== "string" || !value.trim()) {
    return fallback;
  }

  const normalized = value.trim().replaceAll("_", " ").replaceAll("-", " ");
  return `${normalized.charAt(0).toUpperCase()}${normalized.slice(1)}`;
}

// choose a visual class without trusting server text as css
function alertStateClass(value) {
  const state = typeof value === "string" ? value.toLowerCase() : "unknown";

  // mark positive operational states
  if (["ready", "running", "healthy", "receiving", "accepted", "configured", "active"].includes(state)) {
    return "alert-good";
  }

  // mark explicit failures
  if (["error", "failed", "stopped", "unavailable", "expired", "invalid"].includes(state)) {
    return "alert-bad";
  }

  // mark states that require attention or remain unsettled
  if (["quiet", "stale", "degraded", "unknown", "pending", "queued", "retry", "retrying", "incomplete"].includes(state)) {
    return "alert-warning";
  }

  return "alert-neutral";
}

// render one health card with bounded text
function renderAlertHealthCard(prefix, stateValue, detailValue) {
  const state = typeof stateValue === "string" ? stateValue : "unknown";
  const heading = element(`alerts-${prefix}-state`);
  heading.textContent = formatAlertState(state);
  heading.className = alertStateClass(state);
  element(`alerts-${prefix}-detail`).textContent = typeof detailValue === "string" && detailValue
    ? detailValue
    : "No additional status is available.";
}

// render a status failure without affecting the receiver controller
function renderAlertStatusUnavailable(message) {
  element("alerts-overall-state").textContent = "Status unavailable";
  element("alerts-overall-state").className = "alert-state alert-bad";
  renderAlertHealthCard("worker", "unavailable", message);
  renderAlertHealthCard("source", "unknown", "Local source status is unavailable.");
  renderAlertHealthCard("pushover", "unknown", "Pushover status is unavailable.");
  renderAlertHealthCard("email", "unknown", "Email status is unavailable.");
  element("alerts-1090-state").textContent = "Unknown";
  element("alerts-978-state").textContent = "Unknown";
  element("alerts-1090-time").textContent = "Last message —";
  element("alerts-978-time").textContent = "Last message —";
}

// describe one radio-band status
function renderAlertBand(band, value) {
  const data = alertObject(value);
  element(`alerts-${band}-state`).textContent = formatAlertState(data.state);
  element(`alerts-${band}-time`).textContent = `Last message ${formatAlertTimestamp(data.last_message_at)}`;
}

// describe one independent delivery channel
function renderAlertChannel(prefix, value) {
  const data = alertObject(value);
  const detail = typeof data.error === "string" && data.error
    ? data.error
    : data.state === "accepted"
      ? "The provider accepted the latest attempt; receipt is not confirmed."
      : "No provider error is reported.";
  renderAlertHealthCard(prefix, data.state, detail);
}

// update the test button from pending and cooldown state
function updateAlertTestButton() {
  const button = element("alerts-test-button");
  const coolingDown = Date.now() < alertTestCooldownUntil;
  const alertsEnabled = element("alerts-enabled").checked;
  button.disabled = alertConfigDirty || !alertsEnabled || alertTestPending || coolingDown;

  // distinguish drafts, disabled alerts, a pending request and the local rate limit
  if (alertConfigDirty) {
    button.textContent = "Save changes before testing";
  } else if (!alertsEnabled) {
    button.textContent = "Enable alerts to test";
  } else if (alertTestPending) {
    button.textContent = "Test pending";
  } else if (coolingDown) {
    button.textContent = "Test available in one minute";
  } else {
    button.textContent = "Queue test notification";
  }
}

// render per-channel outcomes for the most recent test
function renderAlertTest(testValue) {
  const test = alertObject(testValue);
  const channels = alertObject(test.channels);
  const container = element("alerts-test-results");
  container.replaceChildren();
  alertTestPending = ["pending", "queued", "running"].includes(test.state);

  // show a request summary only after one exists
  if (typeof test.request_id === "string" && test.request_id) {
    const summary = document.createElement("p");
    summary.textContent = `Latest test ${test.request_id}: ${formatAlertState(test.state)}`;
    container.append(summary);
  }

  // render independent channel states
  for (const [key, label] of [["pushover", "Pushover"], ["email", "Email"]]) {
    const channel = alertObject(channels[key]);
    // omit channels until the server reports them
    if (!channel.state) {
      continue;
    }

    const item = document.createElement("span");
    item.className = `channel-result ${alertStateClass(channel.state)}`;
    item.textContent = `${label}: ${formatAlertState(channel.state)}`;
    container.append(item);
  }

  updateAlertTestButton();
}

// render the isolated alert worker status
function renderAlertStatus(statusValue) {
  const status = alertObject(statusValue);
  const processRunning = status.process_running === true;
  const enabled = status.enabled === true;
  const configurationState = typeof status.configuration_state === "string"
    ? status.configuration_state
    : "unknown";
  const sourceState = typeof status.source_state === "string" ? status.source_state : "unknown";
  const capacityDegraded = status.capacity_state === "degraded";
  const refused = Number.isInteger(status.capacity_rejections) && status.capacity_rejections >= 0
    ? status.capacity_rejections : 0;
  const channels = alertObject(status.channels);
  const channelDegraded = [channels.pushover, channels.email].some(value =>
    ["failed", "retry", "unknown", "expired"].includes(alertObject(value).state));
  const overall = element("alerts-overall-state");

  // keep disabled, incomplete, quiet, degraded and stopped states distinct
  if (!processRunning) {
    overall.textContent = "Worker stopped";
    overall.className = "alert-state alert-bad";
  } else if (!enabled) {
    overall.textContent = "Alerts disabled";
    overall.className = "alert-state alert-neutral";
  } else if (!["ready", "configured", "valid"].includes(configurationState)) {
    overall.textContent = "Configuration needed";
    overall.className = "alert-state alert-warning";
  } else if (capacityDegraded) {
    overall.textContent = "Capacity degraded";
    overall.className = "alert-state alert-warning";
  } else if (["unavailable", "stale", "degraded", "unknown"].includes(sourceState)) {
    overall.textContent = "Source degraded";
    overall.className = "alert-state alert-warning";
  } else if (channelDegraded) {
    overall.textContent = "Delivery degraded";
    overall.className = "alert-state alert-warning";
  } else if (sourceState === "no_radio") {
    overall.textContent = "Listening — no radios";
    overall.className = "alert-state alert-warning";
  } else if (sourceState === "quiet") {
    overall.textContent = "Listening — radio quiet";
    overall.className = "alert-state alert-warning";
  } else {
    overall.textContent = "Alerts active";
    overall.className = "alert-state alert-good";
  }

  renderAlertHealthCard(
    "worker",
    processRunning ? capacityDegraded ? "degraded" : "running" : "stopped",
    capacityDegraded
      ? `Capacity limits refused ${refused} observations or deliveries. Inspect history and receiver load.`
      : `Configuration is ${formatAlertState(configurationState).toLowerCase()}.`
  );
  renderAlertHealthCard(
    "source",
    sourceState,
    sourceState === "quiet"
      ? "The worker is healthy, but no recent local aircraft messages are arriving."
      : sourceState === "no_radio"
        ? "No receiver radios are detected; no aircraft can trigger alerts."
        : "Local 1090 and 978 MHz source coverage is tracked separately."
  );

  renderAlertChannel("pushover", channels.pushover);
  renderAlertChannel("email", channels.email);

  const bands = alertObject(status.bands);
  renderAlertBand("1090", bands["1090"]);
  renderAlertBand("978", bands["978"]);
  element("alerts-applied-revision").textContent = Number.isInteger(status.applied_revision)
    ? String(status.applied_revision)
    : "—";
  element("alerts-status-sampled").textContent = `Sampled ${formatAlertTimestamp(status.sampled_at)}`;

  const catalog = alertObject(status.catalog);
  element("alerts-catalog-version").textContent = typeof catalog.version === "string" && catalog.version
    ? catalog.version
    : "Unknown";
  element("alerts-catalog-detail").textContent = typeof catalog.state === "string"
    ? `Catalog ${formatAlertState(catalog.state).toLowerCase()}`
    : "Coverage unavailable";
  renderAlertTest(status.test);
}

// update a configured marker without exposing its value
function renderAlertSecret(fieldName, configured) {
  const inputId = ALERT_SECRET_FIELDS[fieldName];
  const input = element(inputId);
  input.value = "";
  input.disabled = false;
  input.dataset.configured = String(configured === true);
  alertSecretActions.set(fieldName, "unchanged");
  element(`${inputId}-state`).textContent = configured === true ? "Configured" : "Not configured";
  const clearButton = element(`${inputId}-clear`);
  clearButton.hidden = configured !== true;
  clearButton.textContent = `Clear saved ${fieldName === "pushover.app_token" ? "application token" : fieldName === "pushover.user_key" ? "user key" : fieldName === "smtp.username" ? "username" : "password"}`;
}

// unlock alert edits only after canonical hydration and outside saves
function updateAlertConfigControls() {
  element("alerts-config-controls").disabled = !alertConfigHydrated || alertConfigSaving;
}

// apply canonical alert configuration unless a draft is active
function renderAlertConfig(configValue, force = false) {
  // preserve unsaved settings and secret fields during polling
  if (alertConfigDirty && !force) {
    return;
  }

  const config = alertObject(configValue);
  const pushover = alertObject(config.pushover);
  const smtp = alertObject(config.smtp);
  const categories = Array.isArray(config.categories) ? config.categories : ALERT_CATEGORIES;
  alertRevision = Number.isInteger(config.revision) ? config.revision : 0;
  element("alerts-revision-label").textContent = `Revision ${alertRevision}`;
  element("alerts-enabled").checked = config.enabled === true;

  // restore every fixed category with an all-selected default
  for (const category of ALERT_CATEGORIES) {
    element(`alerts-category-${category}`).checked = categories.includes(category);
  }

  renderAlertSecret("pushover.app_token", pushover.app_token_configured === true);
  renderAlertSecret("pushover.user_key", pushover.user_key_configured === true);
  renderAlertSecret("smtp.username", smtp.username_configured === true);
  renderAlertSecret("smtp.password", smtp.password_configured === true);
  element("alerts-smtp-host").value = typeof smtp.host === "string" ? smtp.host : "";
  element("alerts-smtp-port").value = [465, 587].includes(Number(smtp.port)) ? String(smtp.port) : "465";
  element("alerts-smtp-from").value = typeof smtp.from_address === "string" ? smtp.from_address : "";
  element("alerts-smtp-to").value = typeof smtp.to_address === "string" ? smtp.to_address : "";
  renderAlertOverrides(Array.isArray(config.overrides) ? config.overrides : []);
  clearAlertFieldErrors();
  showAlertSaveMessage("", "");
  alertConfigDirty = false;
  alertConfigHydrated = true;
  updateAlertConfigControls();
  updateAlertTestButton();
}

// load canonical alert configuration
async function loadAlertConfig(force = false) {
  const sessionGeneration = alertSessionGeneration;
  const config = await requestJson("/api/admin/alerts/config");
  // discard responses from a session that has since ended
  if (sessionGeneration !== alertSessionGeneration) {
    return;
  }
  renderAlertConfig(config, force);
}

// create a text label bound to a control
function createAlertLabel(controlId, text) {
  const label = document.createElement("label");
  label.htmlFor = controlId;
  label.textContent = text;
  return label;
}

// create one editable exact-aircraft override row
function createAlertOverrideRow(value, index) {
  const override = alertObject(value);
  const controlKey = alertOverrideSequence;
  alertOverrideSequence += 1;
  const row = document.createElement("article");
  row.className = "override-row";

  const header = document.createElement("div");
  header.className = "override-row-heading";
  const title = document.createElement("strong");
  title.textContent = `Aircraft ${index + 1}`;
  const remove = document.createElement("button");
  remove.className = "text-button override-remove";
  remove.type = "button";
  remove.textContent = "Remove";
  remove.setAttribute("aria-label", `Remove aircraft ${index + 1}`);
  // remove only the selected draft row
  remove.addEventListener("click", () => {
    row.remove();
    renumberAlertOverrides();
    markAlertConfigDirty();
  });
  header.append(title, remove);

  const grid = document.createElement("div");
  grid.className = "override-grid";
  const hexField = document.createElement("div");
  hexField.className = "field";
  const hexId = `alerts-override-${controlKey}-hex`;
  const hexInput = document.createElement("input");
  hexInput.id = hexId;
  hexInput.className = "override-hex";
  hexInput.type = "text";
  hexInput.maxLength = 6;
  hexInput.pattern = "[A-Fa-f0-9]{6}";
  hexInput.autocomplete = "off";
  hexInput.spellcheck = false;
  hexInput.placeholder = "A1B2C3";
  hexInput.value = typeof override.hex === "string" ? override.hex.toUpperCase() : "";
  hexField.append(createAlertLabel(hexId, "ICAO hex"), hexInput);

  const modeField = document.createElement("div");
  modeField.className = "field";
  const modeId = `alerts-override-${controlKey}-mode`;
  const modeSelect = document.createElement("select");
  modeSelect.id = modeId;
  modeSelect.className = "override-mode";
  // add only fixed safe override actions
  for (const [mode, label] of [["include", "Include"], ["exclude", "Exclude"]]) {
    const option = document.createElement("option");
    option.value = mode;
    option.textContent = label;
    option.selected = override.mode === mode;
    modeSelect.append(option);
  }
  modeField.append(createAlertLabel(modeId, "Action"), modeSelect);

  const labelField = document.createElement("div");
  labelField.className = "field override-label-field";
  const labelId = `alerts-override-${controlKey}-label`;
  const labelInput = document.createElement("input");
  labelInput.id = labelId;
  labelInput.className = "override-label";
  labelInput.type = "text";
  labelInput.maxLength = 100;
  labelInput.placeholder = "Optional private label";
  labelInput.value = typeof override.label === "string" ? override.label : "";
  labelField.append(createAlertLabel(labelId, "Label"), labelInput);
  grid.append(hexField, modeField, labelField);

  const categoryGroup = document.createElement("fieldset");
  categoryGroup.className = "override-categories";
  const categoryLegend = document.createElement("legend");
  categoryLegend.textContent = "Categories";
  categoryGroup.append(categoryLegend);
  const selectedCategories = Array.isArray(override.categories) ? override.categories : ["military"];
  // add only fixed category checkboxes
  for (const category of ALERT_CATEGORIES) {
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "override-category";
    checkbox.value = category;
    checkbox.checked = selectedCategories.includes(category);
    const text = document.createElement("span");
    text.textContent = formatAlertState(category);
    label.append(checkbox, text);
    categoryGroup.append(label);
  }

  row.append(header, grid, categoryGroup);
  // mark any row edit without rebuilding other drafts
  row.addEventListener("input", markAlertConfigDirty);
  row.addEventListener("change", markAlertConfigDirty);
  return row;
}

// redraw all exact-aircraft override rows
function renderAlertOverrides(overrides) {
  const list = element("alerts-override-list");
  list.replaceChildren();
  alertOverrideSequence = 0;

  // append each bounded server-provided row safely
  for (let index = 0; index < overrides.length; index += 1) {
    list.append(createAlertOverrideRow(overrides[index], index));
  }

  element("alerts-overrides-empty").hidden = overrides.length > 0;
  updateAlertOverrideControls();
}

// keep the add control within the server's bounded watchlist
function updateAlertOverrideControls() {
  const count = element("alerts-override-list").querySelectorAll(".override-row").length;
  element("alerts-add-override").disabled = count >= MAX_ALERT_OVERRIDES;
}

// keep override headings and input ids aligned after removal
function renumberAlertOverrides() {
  const rows = element("alerts-override-list").querySelectorAll(".override-row");

  // update visible row positions without changing entered values
  for (let index = 0; index < rows.length; index += 1) {
    rows[index].querySelector(".override-row-heading strong").textContent = `Aircraft ${index + 1}`;
    rows[index].querySelector(".override-remove").setAttribute("aria-label", `Remove aircraft ${index + 1}`);
  }

  element("alerts-overrides-empty").hidden = rows.length > 0;
  updateAlertOverrideControls();
}

// add one blank exact-aircraft override
function handleAddAlertOverride() {
  const list = element("alerts-override-list");
  const index = list.querySelectorAll(".override-row").length;
  // refuse rows beyond the validated backend limit
  if (index >= MAX_ALERT_OVERRIDES) {
    return;
  }

  list.append(createAlertOverrideRow({ mode: "include", categories: ["military"] }, index));
  element("alerts-overrides-empty").hidden = true;
  updateAlertOverrideControls();
  markAlertConfigDirty();
  list.lastElementChild.querySelector(".override-hex").focus();
}

// refresh one secret marker from its draft action
function refreshAlertSecretDraft(fieldName) {
  const inputId = ALERT_SECRET_FIELDS[fieldName];
  const input = element(inputId);
  const state = element(`${inputId}-state`);
  const clearButton = element(`${inputId}-clear`);
  const action = alertSecretActions.get(fieldName) || "unchanged";
  const configured = input.dataset.configured === "true";

  // explain each explicit secret action without echoing a value
  if (action === "replace") {
    state.textContent = "Replacement entered";
    clearButton.hidden = false;
    clearButton.textContent = "Discard replacement";
    input.disabled = false;
  } else if (action === "clear") {
    state.textContent = "Will be cleared";
    clearButton.hidden = false;
    clearButton.textContent = "Undo clear";
    input.value = "";
    input.disabled = true;
  } else {
    state.textContent = configured ? "Configured" : "Not configured";
    clearButton.hidden = !configured;
    input.disabled = false;
  }
}

// capture an explicit secret replacement without retaining it elsewhere
function handleAlertSecretInput(event) {
  const fieldName = event.currentTarget.dataset.secretField;
  alertSecretActions.set(fieldName, event.currentTarget.value ? "replace" : "unchanged");
  refreshAlertSecretDraft(fieldName);
  markAlertConfigDirty();
}

// toggle an explicit secret clear or discard a replacement
function handleAlertSecretClear(event) {
  const fieldName = event.currentTarget.dataset.secretField;
  const input = element(ALERT_SECRET_FIELDS[fieldName]);
  const action = alertSecretActions.get(fieldName) || "unchanged";

  // undo clears and replacements before offering a new clear
  if (action === "clear" || action === "replace") {
    alertSecretActions.set(fieldName, "unchanged");
    input.value = "";
  } else {
    alertSecretActions.set(fieldName, "clear");
  }

  refreshAlertSecretDraft(fieldName);
  markAlertConfigDirty();
}

// clear alert form feedback and mark an unsaved draft
function markAlertConfigDirty() {
  alertConfigDirty = true;
  clearAlertFieldErrors();
  showAlertSaveMessage("", "");
  updateAlertTestButton();
}

// clear backend validation from fixed alert fields
function clearAlertFieldErrors() {
  const inputIds = new Set(Object.values(ALERT_FIELD_ERROR_IDS));

  // clear each unique mapped output
  for (const inputId of inputIds) {
    const input = element(inputId);
    const output = element(`${inputId}-error`);
    // inputs exist for every mapping except grouped outputs
    if (input) {
      input.removeAttribute("aria-invalid");
    }
    // clear the matching inline message
    if (output) {
      output.textContent = "";
      output.hidden = true;
    }
  }

  element("alerts-form-error").textContent = "";
  element("alerts-form-error").hidden = true;
}

// render safe server validation beside known alert fields
function renderAlertFieldErrors(fields) {
  const summary = [];
  clearAlertFieldErrors();

  // render each response field with text content only
  for (const [fieldName, rawMessage] of Object.entries(fields || {})) {
    const message = fieldMessage(rawMessage);
    const normalizedName = fieldName.replace(/^alerts\./, "");
    const inputId = ALERT_FIELD_ERROR_IDS[normalizedName];
    summary.push(message);

    // attach known errors to their controls
    if (inputId) {
      const input = element(inputId);
      const output = element(`${inputId}-error`);
      // mark only actual controls
      if (input) {
        input.setAttribute("aria-invalid", "true");
      }
      // display the matched error safely
      if (output) {
        output.textContent = message;
        output.hidden = false;
      }
    }
  }

  const message = summary.join(" ");
  element("alerts-form-error").textContent = message;
  element("alerts-form-error").hidden = !message;
  return message;
}

// display alert-save feedback
function showAlertSaveMessage(message, kind) {
  const output = element("alerts-save-message");
  output.textContent = message;
  output.className = kind ? `save-message save-message-${kind}` : "save-message";
}

// determine whether a secret will exist after saving
function alertSecretWillBeConfigured(fieldName) {
  const input = element(ALERT_SECRET_FIELDS[fieldName]);
  const action = alertSecretActions.get(fieldName) || "unchanged";

  // explicit clears always remove the value
  if (action === "clear") {
    return false;
  }

  // replacements require an entered value
  if (action === "replace") {
    return Boolean(input.value);
  }

  return input.dataset.configured === "true";
}

// validate and collect the alert settings payload
function collectAlertConfig() {
  const form = element("alerts-form");

  // run native email and exact-hex validation first
  if (!form.checkValidity()) {
    form.reportValidity();
    throw new Error("Correct the highlighted alert fields before saving.");
  }

  const categories = ALERT_CATEGORIES.filter((category) => element(`alerts-category-${category}`).checked);
  // keep at least one enabled classification role
  if (categories.length === 0) {
    element("alerts-categories-error").textContent = "Select at least one aircraft category.";
    element("alerts-categories-error").hidden = false;
    throw new Error("Select at least one aircraft category.");
  }

  const overrides = [];
  const seenHexes = new Set();
  const rows = element("alerts-override-list").querySelectorAll(".override-row");
  // collect every bounded exact-aircraft rule
  for (const row of rows) {
    const hex = row.querySelector(".override-hex").value.trim().toUpperCase();
    const mode = row.querySelector(".override-mode").value;
    const label = row.querySelector(".override-label").value.trim();
    const rowCategories = Array.from(row.querySelectorAll(".override-category:checked"), (input) => input.value);

    // enforce exact six-character ICAO identities
    if (!/^[0-9A-F]{6}$/.test(hex)) {
      throw new Error("Every override needs an exact six-character hexadecimal ICAO address.");
    }

    // prevent ambiguous duplicate override rows
    if (seenHexes.has(hex)) {
      throw new Error(`ICAO ${hex} appears more than once in the override list.`);
    }

    // keep override categories explicit
    if (rowCategories.length === 0) {
      throw new Error(`Select at least one category for ICAO ${hex}.`);
    }

    seenHexes.add(hex);
    overrides.push({ hex, mode, categories: rowCategories, label });
  }

  const enabled = element("alerts-enabled").checked;
  const smtp = {
    host: element("alerts-smtp-host").value.trim(),
    port: Number(element("alerts-smtp-port").value),
    from_address: element("alerts-smtp-from").value.trim(),
    to_address: element("alerts-smtp-to").value.trim(),
    clear_username: alertSecretActions.get("smtp.username") === "clear",
    clear_password: alertSecretActions.get("smtp.password") === "clear"
  };
  const pushover = {
    clear_app_token: alertSecretActions.get("pushover.app_token") === "clear",
    clear_user_key: alertSecretActions.get("pushover.user_key") === "clear"
  };

  // send replacements only when the operator entered them
  if (alertSecretActions.get("pushover.app_token") === "replace") {
    pushover.app_token = element("alerts-pushover-token").value;
  }
  // send replacements only when the operator entered them
  if (alertSecretActions.get("pushover.user_key") === "replace") {
    pushover.user_key = element("alerts-pushover-user-key").value;
  }
  // send replacements only when the operator entered them
  if (alertSecretActions.get("smtp.username") === "replace") {
    smtp.username = element("alerts-smtp-username").value;
  }
  // send replacements only when the operator entered them
  if (alertSecretActions.get("smtp.password") === "replace") {
    smtp.password = element("alerts-smtp-password").value;
  }

  // explain incomplete dual-channel setup before a round trip
  if (enabled && (!alertSecretWillBeConfigured("pushover.app_token") || !alertSecretWillBeConfigured("pushover.user_key"))) {
    throw new Error("Configure both Pushover credentials before enabling alerts.");
  }
  // require the protected smtp destination and credentials together
  if (enabled && (!smtp.host || !smtp.from_address || !smtp.to_address || !alertSecretWillBeConfigured("smtp.username") || !alertSecretWillBeConfigured("smtp.password"))) {
    throw new Error("Configure the SMTP host, credentials, sender and recipient before enabling alerts.");
  }

  return { revision: alertRevision, enabled, categories, pushover, smtp, overrides };
}

// save isolated alert configuration without touching station settings
async function handleAlertSave(event) {
  event.preventDefault();
  const button = element("alerts-save-button");
  const sessionGeneration = alertSessionGeneration;
  let payload;

  // ignore synthetic or repeated submissions while controls are unavailable
  if (!alertConfigHydrated || alertConfigSaving) {
    return;
  }

  // validate before changing progress state
  try {
    clearAlertFieldErrors();
    payload = collectAlertConfig();
  } catch (error) {
    element("alerts-form-error").textContent = error.message;
    element("alerts-form-error").hidden = false;
    showAlertSaveMessage(error.message, "error");
    return;
  }

  alertConfigSaving = true;
  updateAlertConfigControls();
  button.textContent = "Saving…";
  showAlertSaveMessage("Saving private alert settings…", "progress");

  // persist and apply the accepted redacted canonical state
  try {
    const config = await requestJson("/api/admin/alerts/config", {
      method: "PUT",
      headers: { "X-CSRF-Token": csrfToken },
      body: JSON.stringify(payload)
    });
    // discard a response from an expired or replaced session
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    renderAlertConfig(config, true);
    showAlertSaveMessage(`Alert settings saved as revision ${alertRevision}.`, "success");
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    // keep conflicts distinct from validation failures
    if (error.status === 409) {
      showAlertSaveMessage("Alert settings changed in another session. Reload this page before saving again.", "error");
    } else if (error.data && error.data.fields) {
      const summary = renderAlertFieldErrors(error.data.fields);
      showAlertSaveMessage(summary || "The server rejected one or more alert settings.", "error");
    } else {
      showAlertSaveMessage(error.message || "Unable to save alert settings.", "error");
    }
    return;
  } finally {
    // avoid unlocking controls owned by a newer session
    if (sessionGeneration === alertSessionGeneration) {
      alertConfigSaving = false;
      updateAlertConfigControls();
      button.textContent = "Save alert settings";
    }
  }

  // stop an old save before starting optional health work
  if (sessionGeneration !== alertSessionGeneration) {
    return;
  }
  // refresh optional health without changing the accepted save result
  try {
    await loadStatus();
  } catch {
    // avoid changing status rendered for a newer session
    if (sessionGeneration === alertSessionGeneration) {
      renderAlertStatusUnavailable("Alert status is unavailable.");
    }
  }
}

// format a channel result without claiming end-device delivery
function formatHistoryChannel(name, value) {
  const channel = alertObject(value);
  const state = typeof channel.state === "string" ? channel.state : "unknown";

  // distinguish provider acceptance from final receipt
  if (state === "accepted") {
    return name === "Pushover" ? "Accepted by Pushover" : "Accepted by SMTP server";
  }

  // label ambiguous final-send outcomes honestly
  if (["unknown", "acceptance_unknown"].includes(state)) {
    return "Acceptance unknown";
  }

  return formatAlertState(state);
}

// create one independent channel history line
function createHistoryChannel(name, value) {
  const channel = alertObject(value);
  const row = document.createElement("div");
  row.className = "history-channel";
  const heading = document.createElement("strong");
  heading.textContent = name;
  const state = document.createElement("span");
  state.className = alertStateClass(channel.state);
  state.textContent = formatHistoryChannel(name, channel);
  row.append(heading, state);

  const details = [];
  // show bounded attempt counts when provided
  if (Number.isInteger(channel.attempts) && channel.attempts >= 0) {
    details.push(`${channel.attempts} attempt${channel.attempts === 1 ? "" : "s"}`);
  }
  // show provider-acceptance time without implying receipt
  if (channel.accepted_at) {
    details.push(`accepted ${formatAlertTimestamp(channel.accepted_at)}`);
  }
  // include sanitized private errors as text
  if (typeof channel.error === "string" && channel.error) {
    details.push(channel.error);
  }

  // append details only when present
  if (details.length > 0) {
    const detail = document.createElement("small");
    detail.textContent = details.join(" · ");
    row.append(detail);
  }

  return row;
}

// create one safe history card
function createAlertHistoryEvent(value) {
  const event = alertObject(value);
  const card = document.createElement("article");
  card.className = "history-event";
  const header = document.createElement("div");
  header.className = "history-event-heading";
  const identity = document.createElement("div");
  const kind = event.kind === "test" ? "test" : "aircraft";
  const title = document.createElement("h4");
  title.textContent = kind === "test"
    ? "Notification test"
    : typeof event.label === "string" && event.label
      ? event.label
      : "Known aircraft";
  identity.append(title);

  const normalizedHex = typeof event.hex === "string" ? event.hex.trim().toUpperCase() : "";
  // link only genuine aircraft events with an exact validated hex
  if (kind === "aircraft" && /^[0-9A-F]{6}$/.test(normalizedHex)) {
    const link = document.createElement("a");
    link.href = `/map/?icao=${encodeURIComponent(normalizedHex.toLowerCase())}`;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = normalizedHex;
    link.setAttribute("aria-label", `View aircraft ${normalizedHex} on the map`);
    identity.append(link);
  }

  const time = document.createElement("time");
  const rawTime = event.observed_at || event.created_at;
  time.textContent = formatAlertTimestamp(rawTime);
  header.append(identity, time);

  const tags = document.createElement("div");
  tags.className = "history-tags";
  const categories = Array.isArray(event.categories) ? event.categories : [];
  // show only known category labels
  for (const category of categories) {
    // ignore unexpected categories from older records
    if (!ALERT_CATEGORIES.includes(category)) {
      continue;
    }
    const tag = document.createElement("span");
    tag.textContent = formatAlertState(category);
    tags.append(tag);
  }
  const bands = Array.isArray(event.bands) ? event.bands : [];
  // show only supported local receiver bands
  for (const band of bands) {
    // ignore unexpected band labels
    if (!["1090", "978"].includes(String(band))) {
      continue;
    }
    const tag = document.createElement("span");
    tag.textContent = `${band} MHz${event.receptions?.[band] === "rebroadcast" ? " (rebroadcast)" : ""}`;
    tags.append(tag);
  }

  const channelGrid = document.createElement("div");
  channelGrid.className = "history-channels";
  const channels = alertObject(event.channels);
  channelGrid.append(
    createHistoryChannel("Pushover", channels.pushover),
    createHistoryChannel("Email", channels.email)
  );
  card.append(header, tags, channelGrid);
  return card;
}

// load a bounded private history page
async function loadAlertHistory(reset = false, background = false) {
  const sessionGeneration = alertSessionGeneration;
  // prevent overlapping pagination and polling requests
  if (alertHistoryLoading) {
    return;
  }

  alertHistoryLoading = true;
  const list = element("alerts-history-list");
  const loading = element("alerts-history-loading");
  const errorOutput = element("alerts-history-error");
  const button = element("alerts-history-more");

  // expose loading only for foreground operations
  if (!background) {
    loading.hidden = false;
  }
  errorOutput.hidden = true;
  button.disabled = true;

  let path = "/api/admin/alerts/history?limit=50";
  // use the server cursor only for older-page requests
  if (!reset && alertHistoryCursor) {
    path += `&before=${encodeURIComponent(alertHistoryCursor)}`;
  }

  // replace or extend history only after a successful response
  try {
    const result = await requestJson(path);
    // discard a response from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    const events = Array.isArray(result.events) ? result.events : [];
    // replace the newest page during reset and background refreshes
    if (reset) {
      list.replaceChildren();
    }
    // append every event with safe DOM construction
    for (const event of events) {
      list.append(createAlertHistoryEvent(event));
    }

    alertHistoryCursor = typeof result.next_cursor === "string" && result.next_cursor
      ? result.next_cursor
      : null;
    element("alerts-history-empty").hidden = list.childElementCount > 0;
    button.hidden = !alertHistoryCursor;
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    errorOutput.textContent = error.message || "Unable to load notification history.";
    errorOutput.hidden = false;
  } finally {
    // avoid changing controls owned by a newer session
    if (sessionGeneration === alertSessionGeneration) {
      alertHistoryLoading = false;
      loading.hidden = true;
      button.disabled = false;
    }
  }
}

// queue one clearly labeled non-aircraft delivery test
async function handleAlertTest() {
  const sessionGeneration = alertSessionGeneration;
  const button = element("alerts-test-button");
  const output = element("alerts-test-message");
  button.disabled = true;
  output.textContent = "Queueing a non-aircraft test for both channels…";
  output.className = "save-message save-message-progress";

  // request server-side dispatch without exposing providers to the browser
  try {
    const result = await requestJson("/api/admin/alerts/test", {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ revision: alertRevision })
    });
    // discard a response from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    alertTestPending = true;
    alertTestCooldownUntil = Date.now() + 60000;
    output.textContent = typeof result.request_id === "string"
      ? `Test ${result.request_id} is queued. This does not confirm provider acceptance or receipt.`
      : "Test is queued. This does not confirm provider acceptance or receipt.";
    output.className = "save-message save-message-success";
    renderAlertTest({ request_id: result.request_id, state: result.status || "queued" });
    window.setTimeout(() => {
      // keep an old cooldown from changing newer controls
      if (sessionGeneration === alertSessionGeneration) {
        updateAlertTestButton();
      }
    }, 60000);
    await loadAlertHistory(true, true);
  } catch (error) {
    // ignore a failure from a session that has since ended
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    output.textContent = error.status === 429
      ? "A test was recently queued. Wait at least one minute before trying again."
      : error.message || "Unable to queue the test notification.";
    output.className = "save-message save-message-error";
  } finally {
    // avoid changing controls owned by a newer session
    if (sessionGeneration === alertSessionGeneration) {
      updateAlertTestButton();
    }
  }
}

// restore an existing browser session
async function initialize() {
  let sessionGeneration = alertSessionGeneration;
  // inspect the current session before showing a view
  try {
    const session = await requestJson("/api/session");
    // discard a response after another session transition
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }

    // open authenticated views only with csrf protection
    if (session.authenticated === true && typeof session.csrf_token === "string") {
      alertSessionGeneration += 1;
      sessionGeneration = alertSessionGeneration;
      csrfToken = session.csrf_token;
      await loadAdmin();
    } else {
      showLogin();
    }
  } catch (error) {
    // ignore a failure from an older initialization
    if (sessionGeneration !== alertSessionGeneration) {
      return;
    }
    // treat unauthorized as signed out
    if (error.status === 401) {
      showLogin();
    } else {
      showLogin("Unable to contact the admin service. Try again shortly.");
    }
  }
}

// bind static page controls
function bindEvents() {
  element("login-form").addEventListener("submit", handleLogin);
  element("logout-button").addEventListener("click", handleLogout);
  element("settings-form").addEventListener("submit", handleSave);
  element("settings-form").addEventListener("input", handleSettingsInput);
  element("alerts-form").addEventListener("submit", handleAlertSave);
  element("alerts-form").addEventListener("input", markAlertConfigDirty);
  element("alerts-form").addEventListener("change", markAlertConfigDirty);
  element("alerts-add-override").addEventListener("click", handleAddAlertOverride);
  element("alerts-test-button").addEventListener("click", handleAlertTest);
  element("alerts-history-refresh").addEventListener("click", () => loadAlertHistory(true, false));
  element("alerts-history-more").addEventListener("click", () => loadAlertHistory(false, false));

  // bind redacted credential actions
  for (const [fieldName, inputId] of Object.entries(ALERT_SECRET_FIELDS)) {
    const input = element(inputId);
    const clearButton = element(`${inputId}-clear`);
    input.dataset.secretField = fieldName;
    clearButton.dataset.secretField = fieldName;
    input.addEventListener("input", handleAlertSecretInput);
    clearButton.addEventListener("click", handleAlertSecretClear);
  }

  // bind per-network controls
  for (const networkId of NETWORK_IDS) {
    const enabledInput = element(`${networkId}-enabled`);
    const feederInput = element(`${networkId}-feeder-id`);
    const clearButton = element(`${networkId}-clear`);
    enabledInput.dataset.networkId = networkId;
    feederInput.dataset.networkId = networkId;
    clearButton.dataset.networkId = networkId;
    enabledInput.addEventListener("change", handleNetworkToggle);
    feederInput.addEventListener("input", handleFeederInput);
    clearButton.addEventListener("click", handleClearFeeder);
    // bind local UUID generation only for compatible providers
    if (networkId !== "flightaware") {
      const generateButton = element(`${networkId}-generate`);
      generateButton.dataset.networkId = networkId;
      generateButton.addEventListener("click", handleGenerateFeeder);
    }
  }
}

bindEvents();
initialize();
