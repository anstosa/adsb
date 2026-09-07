"use strict";

const NETWORK_IDS = ["adsbexchange", "flightaware", "adsblol", "airplaneslive"];
const PHASE_LABELS = {
  starting: "Applying configuration",
  ready: "Software ready",
  error: "Controller error",
  waiting: "Awaiting radios"
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
const feederActions = new Map();

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

  // render all supported runtimes
  for (const networkId of NETWORK_IDS) {
    renderNetworkRuntime(networkId, status.networks && status.networks[networkId]);
  }
}

// load current configuration
async function loadConfig() {
  const config = await requestJson("/api/admin/config");
  renderConfig(config);
}

// refresh current controller status
async function loadStatus() {
  // keep polling failures nonfatal
  try {
    const status = await requestJson("/api/admin/status");
    renderStatus(status);
  } catch (error) {
    // hand off expired sessions
    if (handleAuthenticationError(error)) {
      return;
    }

    element("phase-badge").className = "phase-badge phase-error";
    element("phase-label").textContent = "Status unavailable";
  }
}

// begin periodic status refreshes
function startStatusPolling() {
  stopStatusPolling();
  statusPollId = window.setInterval(loadStatus, 10000);
}

// load authenticated views
async function loadAdmin() {
  showAdmin();

  // load config before polling
  try {
    await loadConfig();
    await loadStatus();
    startStatusPolling();
  } catch (error) {
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

    // require the expected session contract
    if (session.authenticated !== true || typeof session.csrf_token !== "string") {
      throw new Error("The server did not establish an admin session.");
    }

    csrfToken = session.csrf_token;
    passwordInput.value = "";
    await loadAdmin();
  } catch (error) {
    passwordInput.value = "";
    element("login-error").textContent = error.message || "Sign-in failed.";
    element("login-error").hidden = false;
    passwordInput.focus();
  } finally {
    loginButton.disabled = false;
    loginButton.textContent = "Sign in";
  }
}

// end the current session
async function handleLogout() {
  element("logout-button").disabled = true;

  // attempt server logout before clearing local state
  try {
    await requestJson("/api/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
      body: JSON.stringify({})
    });
  } catch (error) {
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
    await loadConfig();
    await loadStatus();
    showSaveMessage(`Settings saved as revision ${currentRevision}. Controller status is shown below.`, "success");
  } catch (error) {
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
    saveButton.disabled = false;
    saveButton.textContent = "Save settings";
  }
}

// restore an existing browser session
async function initialize() {
  // inspect the current session before showing a view
  try {
    const session = await requestJson("/api/session");

    // open authenticated views only with csrf protection
    if (session.authenticated === true && typeof session.csrf_token === "string") {
      csrfToken = session.csrf_token;
      await loadAdmin();
    } else {
      showLogin();
    }
  } catch (error) {
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
