import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const playwrightModule = process.env.ADSB_PLAYWRIGHT_MODULE;

// require an explicit reusable playwright installation
if (!playwrightModule) {
  throw new Error("Set ADSB_PLAYWRIGHT_MODULE to an installed Playwright package directory.");
}

const { chromium } = require(playwrightModule);
const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WEB_ROOT = path.join(PROJECT_ROOT, "web");
const TEST_TIMEOUT_MS = 7000;
const NETWORK_IDS = ["adsbexchange", "flightaware", "adsblol", "airplaneslive"];
const REPORT_GENERATION = "a".repeat(64);
const AVAILABLE_CANDIDATE_ID = "b".repeat(64);
const HELD_CANDIDATE_ID = "c".repeat(64);
const BLOCKED_CANDIDATE_ID = "d".repeat(64);

// create one externally controlled promise
function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

// hold one response at a deterministic request barrier
function responseBarrier(body, status = 200) {
  return {
    body,
    status,
    seen: deferred(),
    release: deferred()
  };
}

// bound one scenario without retaining a completed timer
async function withTimeout(promise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs}ms`)), timeoutMs);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// build one complete station configuration
function stationConfig() {
  return {
    revision: 1,
    station: { name: "Browser test receiver", latitude: null, longitude: null, altitude_m: null },
    networks: Object.fromEntries(NETWORK_IDS.map((networkId) => [networkId, {
      enabled: false,
      mlat: false,
      feeder_id_configured: false
    }]))
  };
}

// build one redacted alert configuration
function alertConfig(revision = 7, overrides = []) {
  return {
    revision,
    enabled: false,
    categories: ["military", "medical", "news"],
    category_channels: { military: ["pushover", "email"], medical: ["pushover", "email"], news: ["pushover", "email"] },
    pushover: {
      app_token_configured: false,
      user_key_configured: false
    },
    smtp: {
      host: "saved.example",
      port: 465,
      username_configured: false,
      password_configured: false,
      from_address: "receiver@example.com",
      to_address: "operator@example.com"
    },
    overrides
  };
}

// derive the redacted accepted response from one put payload
function acceptedAlertConfig(payload, previous) {
  return {
    revision: previous.revision + 1,
    enabled: payload.enabled === true,
    categories: payload.categories,
    category_channels: payload.category_channels,
    pushover: {
      app_token_configured: Boolean(payload.pushover.app_token) || previous.pushover.app_token_configured,
      user_key_configured: Boolean(payload.pushover.user_key) || previous.pushover.user_key_configured
    },
    smtp: {
      host: payload.smtp.host,
      port: payload.smtp.port,
      username_configured: Boolean(payload.smtp.username) || previous.smtp.username_configured,
      password_configured: Boolean(payload.smtp.password) || previous.smtp.password_configured,
      from_address: payload.smtp.from_address,
      to_address: payload.smtp.to_address
    },
    overrides: payload.overrides
  };
}

// build current controller status without claiming live reception
function controllerStatus() {
  return {
    phase: "ready",
    applied_revision: 1,
    updated_at: "2026-10-05T12:00:00Z",
    hardware: { connected: false, message: "No test radio" },
    reception: {
      "1090": { telemetry_state: "quiet", messages_per_minute: 0, sample_at: "2026-10-05T12:00:00Z" },
      "978": { telemetry_state: "quiet", messages_per_minute: 0, sample_at: "2026-10-05T12:00:00Z" }
    },
    networks: Object.fromEntries(NETWORK_IDS.map((networkId) => [networkId, {
      enabled: false,
      running: false,
      connected: false,
      message: "Disabled in browser test"
    }]))
  };
}

// build isolated alert worker status
function alertStatus(revision = 7) {
  return {
    process_running: true,
    enabled: false,
    configuration_state: "ready",
    source_state: "quiet",
    capacity_state: "ready",
    capacity_rejections: 0,
    channels: {
      pushover: { state: "not_configured" },
      email: { state: "not_configured" }
    },
    bands: {
      "1090": { state: "quiet", last_message_at: null },
      "978": { state: "quiet", last_message_at: null }
    },
    applied_revision: revision,
    sampled_at: 1791230400,
    catalog: { state: "ready", version: "browser-test" },
    test: {}
  };
}

// build one safe maintenance response
function maintenanceReport(emailNotifications = { state: "waiting" }, overrides = {}) {
  return {
    status: "ok",
    updated_at: "2026-10-05T12:00:00Z",
    os_schedule: "Tuesdays 04:00 America/Los_Angeles",
    application_policy: "Clearly compatible updates install automatically; breaking or unknown updates are held for your Install action",
    disk_free_percent: 51.2,
    reboot_required: false,
    images: [],
    map_status: "current",
    email_notifications: emailNotifications,
    generation: REPORT_GENERATION,
    updates: [],
    installation: {
      state: "idle",
      candidate_id: "",
      candidate_ids: [],
      request_id: "",
      message: "",
      updated_at: "2026-10-05T12:00:00Z"
    },
    ...overrides
  };
}

// build one bounded maintenance candidate
function maintenanceCandidate(overrides = {}) {
  return {
    id: AVAILABLE_CANDIDATE_ID,
    name: "map-ui",
    label: "Tar1090 map",
    current_version: "v1.0.0",
    candidate_version: "v1.1.0",
    compatibility: "compatible",
    state: "available",
    reason: "The reviewed compatibility contract is unchanged.",
    changelog: "Improves map rendering.",
    changelog_url: "https://github.com/example/project/releases/tag/v1.1.0",
    ...overrides
  };
}

// read one bounded request body
async function readRequestBody(request) {
  const chunks = [];
  // collect the local test request only
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

// send one same-origin json response
function sendJson(response, status, body) {
  const content = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": String(content.length),
    "Content-Type": "application/json; charset=utf-8"
  });
  response.end(content);
}

// serve one fixed public asset
async function sendAsset(response, pathname) {
  const allowed = new Map([
    ["/admin", "admin.html"],
    ["/admin.html", "admin.html"],
    ["/admin.js", "admin.js"],
    ["/styles.css", "styles.css"],
    ["/favicon.svg", "favicon.svg"]
  ]);
  const filename = allowed.get(pathname);
  // reject every path outside the fixed asset set
  if (!filename) {
    response.writeHead(404, { "Content-Length": "0" });
    response.end();
    return;
  }
  const content = await fs.readFile(path.join(WEB_ROOT, filename));
  const contentType = filename.endsWith(".js")
    ? "text/javascript; charset=utf-8"
    : filename.endsWith(".css")
      ? "text/css; charset=utf-8"
      : filename.endsWith(".svg")
        ? "image/svg+xml"
        : "text/html; charset=utf-8";
  response.writeHead(200, {
    "Content-Length": String(content.length),
    "Content-Type": contentType
  });
  response.end(content);
}

// provide deterministic same-origin api responses
class FakeAdminServer {
  // initialize isolated response state
  constructor() {
    this.sessionAuthenticated = true;
    this.alertConfig = alertConfig();
    this.maintenance = maintenanceReport();
    this.loginQueue = [];
    this.logoutQueue = [];
    this.stationGetQueue = [];
    this.stationPutQueue = [];
    this.alertGetQueue = [];
    this.alertPutQueue = [];
    this.controllerStatusQueue = [];
    this.historyQueue = [];
    this.alertTestQueue = [];
    this.maintenanceQueue = [];
    this.installQueue = [];
    this.installRequests = [];
    this.requests = [];
    this.server = http.createServer((request, response) => {
      this.handle(request, response).catch((error) => {
        response.destroy(error);
      });
    });
  }

  // start on one unused loopback port
  async start() {
    await new Promise((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    const address = this.server.address();
    this.origin = `http://127.0.0.1:${address.port}`;
  }

  // stop the isolated loopback server
  async close() {
    await new Promise((resolve, reject) => {
      this.server.close((error) => {
        // surface cleanup failures
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }

  // release one queued response after recording the request
  async sendQueued(response, queued, fallback) {
    const item = queued.shift();
    // send the current state without a configured barrier
    if (!item) {
      sendJson(response, 200, fallback);
      return;
    }
    item.seen.resolve();
    await item.release.promise;
    sendJson(response, item.status, item.body);
  }

  // route the fixed browser-test surface
  async handle(request, response) {
    const requestUrl = new URL(request.url, this.origin || "http://127.0.0.1");
    const pathname = requestUrl.pathname;
    this.requests.push(`${request.method} ${pathname}`);
    // expose one authenticated local browser session
    if (request.method === "GET" && pathname === "/api/session") {
      sendJson(response, 200, this.sessionAuthenticated
        ? { authenticated: true, csrf_token: "browser-test-csrf" }
        : { authenticated: false });
      return;
    }
    // authenticate only inside the fake browser boundary
    if (request.method === "POST" && pathname === "/api/login") {
      await readRequestBody(request);
      this.sessionAuthenticated = true;
      await this.sendQueued(response, this.loginQueue, {
        authenticated: true,
        csrf_token: "browser-test-csrf"
      });
      return;
    }
    // gate logout without touching a real session
    if (request.method === "POST" && pathname === "/api/logout") {
      await readRequestBody(request);
      await this.sendQueued(response, this.logoutQueue, { authenticated: false });
      return;
    }
    // return fixed station settings
    if (request.method === "GET" && pathname === "/api/admin/config") {
      await this.sendQueued(response, this.stationGetQueue, stationConfig());
      return;
    }
    // gate station saves independently from alert settings
    if (request.method === "PUT" && pathname === "/api/admin/config") {
      await readRequestBody(request);
      await this.sendQueued(response, this.stationPutQueue, stationConfig());
      return;
    }
    // gate alert hydration when requested by a test
    if (request.method === "GET" && pathname === "/api/admin/alerts/config") {
      await this.sendQueued(response, this.alertGetQueue, this.alertConfig);
      return;
    }
    // gate alert saves without any provider dispatch
    if (request.method === "PUT" && pathname === "/api/admin/alerts/config") {
      const rawBody = await readRequestBody(request);
      const payload = JSON.parse(rawBody);
      const queued = this.alertPutQueue.shift();
      // return the queued deterministic failure or acceptance
      if (queued) {
        queued.payload = payload;
        queued.seen.resolve();
        await queued.release.promise;
        // advance only accepted writes
        if (queued.status >= 200 && queued.status < 300) {
          this.alertConfig = acceptedAlertConfig(payload, this.alertConfig);
          queued.body = this.alertConfig;
        }
        sendJson(response, queued.status, queued.body);
        return;
      }
      this.alertConfig = acceptedAlertConfig(payload, this.alertConfig);
      sendJson(response, 200, this.alertConfig);
      return;
    }
    // return an empty private history page
    if (request.method === "GET" && pathname === "/api/admin/alerts/history") {
      await this.sendQueued(response, this.historyQueue, { events: [], next_cursor: null });
      return;
    }
    // return fixed receiver health
    if (request.method === "GET" && pathname === "/api/admin/status") {
      await this.sendQueued(response, this.controllerStatusQueue, controllerStatus());
      return;
    }
    // return the currently selected maintenance projection
    if (request.method === "GET" && pathname === "/api/admin/maintenance") {
      await this.sendQueued(response, this.maintenanceQueue, this.maintenance);
      return;
    }
    // isolate exact update authorization without installing anything
    if (request.method === "POST" && pathname === "/api/admin/maintenance/install") {
      const rawBody = await readRequestBody(request);
      const payload = JSON.parse(rawBody);
      const queued = this.installQueue.shift();
      this.installRequests.push({ payload, csrf: request.headers["x-csrf-token"] || "" });
      // release a configured deterministic install outcome
      if (queued) {
        queued.payload = payload;
        queued.csrf = request.headers["x-csrf-token"] || "";
        queued.seen.resolve();
        await queued.release.promise;
        sendJson(response, queued.status, queued.body);
        return;
      }
      sendJson(response, 202, {
        state: "queued",
        request_id: "browser-install-request",
        candidate_ids: payload.candidate_ids
      });
      return;
    }
    // return isolated notifier health
    if (request.method === "GET" && pathname === "/api/admin/alerts/status") {
      sendJson(response, 200, alertStatus(this.alertConfig.revision));
      return;
    }
    // isolate intentional test requests from every provider
    if (request.method === "POST" && pathname === "/api/admin/alerts/test") {
      await readRequestBody(request);
      await this.sendQueued(response, this.alertTestQueue, {
        request_id: "fallback-browser-test",
        status: "queued"
      });
      return;
    }
    await sendAsset(response, pathname);
  }
}

// open one authenticated page and capture script failures
async function openPage(browser, server, viewport = { width: 1280, height: 900 }) {
  const page = await browser.newPage({ viewport });
  const pageErrors = [];
  const consoleErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("console", (message) => {
    // record only browser error output
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });
  await page.goto(`${server.origin}/admin`, { waitUntil: "load" });
  return { page, pageErrors, consoleErrors };
}

// wait for one alert revision to finish hydration
async function waitForRevision(page, revision) {
  await page.locator("#alerts-revision-label").getByText(`Revision ${revision}`, { exact: true }).waitFor();
}

// wait until the alert fieldset accepts another edit
async function waitForAlertControls(page) {
  await page.waitForFunction(() => !document.getElementById("alerts-config-controls").disabled);
}

// close one page and its local server
async function closeScenario(page, server) {
  await page.close();
  await server.close();
}

// apply one complete category-channel selection
async function setCategoryChannels(page, categoryChannels) {
  // set every fixed role and route explicitly
  for (const category of ["military", "medical", "news"]) {
    // set both supported delivery routes
    for (const channel of ["pushover", "email"]) {
      const checkbox = page.locator(`#alerts-category-${category}-${channel}`);
      const shouldBeChecked = (categoryChannels[category] || []).includes(channel);
      await checkbox.setChecked(shouldBeChecked);
    }
  }
}

// return the checked routes for one category
async function selectedCategoryChannels(page, category) {
  const selected = [];
  // read both supported delivery routes
  for (const channel of ["pushover", "email"]) {
    // collect checked route names only
    if (await page.locator(`#alerts-category-${category}-${channel}`).isChecked()) {
      selected.push(channel);
    }
  }
  return selected;
}

// verify legacy categories hydrate to both routes with accessible names
async function testLegacyCategoryRouteHydration(browser) {
  const server = new FakeAdminServer();
  server.alertConfig.categories = ["military", "news"];
  // exercise the supported older-backend rollback boundary explicitly
  delete server.alertConfig.category_channels;
  await server.start();
  const { page, pageErrors, consoleErrors } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    assert.deepEqual(await selectedCategoryChannels(page, "military"), ["pushover", "email"]);
    assert.deepEqual(await selectedCategoryChannels(page, "medical"), []);
    assert.deepEqual(await selectedCategoryChannels(page, "news"), ["pushover", "email"]);
    // expose one unique accessible name for each route control
    for (const [name, id] of [
      ["Military push", "alerts-category-military-pushover"],
      ["Military email", "alerts-category-military-email"],
      ["Medical push", "alerts-category-medical-pushover"],
      ["Medical email", "alerts-category-medical-email"],
      ["News push", "alerts-category-news-pushover"],
      ["News email", "alerts-category-news-email"]
    ]) {
      const checkbox = page.getByRole("checkbox", { name, exact: true });
      assert.equal(await checkbox.count(), 1);
      assert.equal(await checkbox.getAttribute("id"), id);
    }
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(consoleErrors, []);
  } finally {
    await closeScenario(page, server);
  }
}

// verify explicit route combinations persist through save and reload
async function testCategoryRouteSaveAndReload(browser) {
  const server = new FakeAdminServer();
  server.alertConfig = {
    ...alertConfig(),
    category_channels: {
      military: ["pushover"],
      medical: ["email"],
      news: ["pushover", "email"]
    },
    pushover: {
      app_token_configured: true,
      user_key_configured: true
    },
    smtp: {
      ...alertConfig().smtp,
      username_configured: true,
      password_configured: true
    }
  };
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    assert.deepEqual(await selectedCategoryChannels(page, "military"), ["pushover"]);
    assert.deepEqual(await selectedCategoryChannels(page, "medical"), ["email"]);
    assert.deepEqual(await selectedCategoryChannels(page, "news"), ["pushover", "email"]);
    const savedRoutes = {
      military: [],
      medical: ["pushover", "email"],
      news: ["pushover"]
    };
    await setCategoryChannels(page, savedRoutes);
    await page.locator("#alerts-save-button").click();
    await waitForRevision(page, 8);
    const putRequest = server.requests.filter((request) => request === "PUT /api/admin/alerts/config");
    assert.equal(putRequest.length, 1);
    assert.deepEqual(server.alertConfig.category_channels, savedRoutes);
    assert.deepEqual(server.alertConfig.categories, ["medical", "news"]);
    assert.equal(server.alertConfig.pushover.app_token_configured, true);
    assert.equal(server.alertConfig.pushover.user_key_configured, true);
    assert.equal(server.alertConfig.smtp.username_configured, true);
    assert.equal(server.alertConfig.smtp.password_configured, true);
    await page.evaluate(async () => window.loadAlertConfig(true));
    assert.deepEqual(await selectedCategoryChannels(page, "military"), []);
    assert.deepEqual(await selectedCategoryChannels(page, "medical"), ["pushover", "email"]);
    assert.deepEqual(await selectedCategoryChannels(page, "news"), ["pushover"]);
  } finally {
    await closeScenario(page, server);
  }
}

// verify polling cannot overwrite a route or credential draft
async function testCategoryRouteDraftPreservation(browser) {
  const server = new FakeAdminServer();
  server.alertConfig = {
    ...alertConfig(),
    category_channels: {
      military: ["pushover"],
      medical: ["email"],
      news: ["pushover", "email"]
    }
  };
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    const draftRoutes = {
      military: ["email"],
      medical: [],
      news: ["pushover"]
    };
    await setCategoryChannels(page, draftRoutes);
    await page.locator("#alerts-smtp-host").fill("draft-route.example");
    await page.locator("#alerts-add-model-override").click();
    await page.getByLabel("ICAO model code", { exact: true }).fill("H60");
    server.alertConfig = {
      ...alertConfig(8),
      category_channels: {
        military: ["pushover", "email"],
        medical: ["pushover", "email"],
        news: ["pushover", "email"]
      }
    };
    await page.evaluate(async () => window.loadAlertConfig());
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 7");
    assert.deepEqual(await selectedCategoryChannels(page, "military"), ["email"]);
    assert.deepEqual(await selectedCategoryChannels(page, "medical"), []);
    assert.deepEqual(await selectedCategoryChannels(page, "news"), ["pushover"]);
    assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "draft-route.example");
    assert.equal(await page.getByLabel("ICAO model code", { exact: true }).inputValue(), "H60");
  } finally {
    await closeScenario(page, server);
  }
}

// verify empty routing is saveable only while alerts remain disabled
async function testEmptyRouteDraftAndEnabledValidation(browser) {
  const server = new FakeAdminServer();
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    const noRoutes = { military: [], medical: [], news: [] };
    await setCategoryChannels(page, noRoutes);
    await page.locator("#alerts-save-button").click();
    await waitForRevision(page, 8);
    assert.deepEqual(server.alertConfig.category_channels, noRoutes);
    assert.deepEqual(server.alertConfig.categories, []);
    await waitForAlertControls(page);
    await page.getByText("Alerts enabled", { exact: true }).click();
    assert.equal(await page.locator("#alerts-enabled").isChecked(), true);
    await page.locator("#alerts-save-button").click();
    await page.locator("#alerts-form-error:not([hidden])").waitFor();
    assert.match(await page.locator("#alerts-form-error").textContent(), /push|email|route|notification|delivery/i);
    assert.equal(server.requests.filter((request) => request === "PUT /api/admin/alerts/config").length, 1);
  } finally {
    await closeScenario(page, server);
  }
}

// verify only credentials for selected routes are required
async function testSelectedRouteCredentialValidation(browser) {
  const cases = [
    {
      name: "pushover",
      routes: { military: ["pushover"], medical: [], news: [] },
      // enter only push credentials
      prepare: async (page) => {
        await page.locator("#alerts-pushover-token").fill("test-token");
        await page.locator("#alerts-pushover-user-key").fill("test-user");
      }
    },
    {
      name: "email",
      routes: { military: [], medical: ["email"], news: [] },
      // enter only email credentials
      prepare: async (page) => {
        await page.locator("#alerts-smtp-username").fill("test-user");
        await page.locator("#alerts-smtp-password").fill("test-password");
      }
    }
  ];
  // isolate each credential route from saved provider state
  for (const testCase of cases) {
    const server = new FakeAdminServer();
    await server.start();
    const { page } = await openPage(browser, server);
    try {
      await waitForRevision(page, 7);
      await setCategoryChannels(page, testCase.routes);
      await page.getByText("Alerts enabled", { exact: true }).click();
      assert.equal(await page.locator("#alerts-enabled").isChecked(), true);
      await testCase.prepare(page);
      await page.locator("#alerts-save-button").click();
      await waitForRevision(page, 8);
      await waitForAlertControls(page);
      assert.equal(server.requests.filter((request) => request === "PUT /api/admin/alerts/config").length, 1, `${testCase.name} route did not save`);
      assert.deepEqual(server.alertConfig.category_channels, testCase.routes);
    } finally {
      await closeScenario(page, server);
    }
  }
}

// verify initial edits cannot race the first canonical response
async function testInitialHydration(browser) {
  const server = new FakeAdminServer();
  const barrier = responseBarrier(server.alertConfig);
  server.alertGetQueue.push(barrier);
  await server.start();
  const { page, pageErrors, consoleErrors } = await openPage(browser, server);
  try {
    await barrier.seen.promise;
    assert.equal(await page.locator("#alerts-smtp-host").isEditable(), false);
    assert.equal(await page.locator("#alerts-save-button").isDisabled(), true);
    barrier.release.resolve();
    await waitForRevision(page, 7);
    assert.equal(await page.locator("#alerts-smtp-host").isEditable(), true);
    assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "saved.example");
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(consoleErrors, []);
  } finally {
    barrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify accepted saves scrub secrets before optional reloads
async function testAcceptedSaveAndStatusFailure(browser) {
  const server = new FakeAdminServer();
  const putBarrier = responseBarrier({}, 200);
  const statusFailure = responseBarrier({ error: "status_unavailable" }, 503);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.locator("#alerts-smtp-host").fill("new.example");
    await page.locator("#alerts-smtp-password").fill("replacement-secret");
    server.alertPutQueue.push(putBarrier);
    server.controllerStatusQueue.push(statusFailure);
    await page.locator("#alerts-save-button").click();
    await putBarrier.seen.promise;
    assert.equal(await page.locator("#alerts-smtp-host").isEditable(), false);
    assert.equal(await page.locator("#alerts-smtp-password").isEditable(), false);
    putBarrier.release.resolve();
    await statusFailure.seen.promise;
    statusFailure.release.resolve();
    await page.locator("#alerts-save-button:not([disabled])").waitFor();
    assert.equal(await page.locator("#alerts-smtp-password").inputValue(), "");
    assert.equal(await page.locator("#alerts-smtp-password-state").textContent(), "Configured");
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 8");
    assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "new.example");
    assert.equal(server.requests.filter((request) => request === "GET /api/admin/alerts/config").length, 1);
  } finally {
    putBarrier.release.resolve();
    statusFailure.release.resolve();
    await closeScenario(page, server);
  }
}

// verify failed saves retain a retryable private draft
async function testFailedSaveRetainsDraft(browser) {
  const server = new FakeAdminServer();
  const putBarrier = responseBarrier({ error: "settings_unavailable" }, 503);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.locator("#alerts-smtp-host").fill("retry.example");
    await page.locator("#alerts-smtp-password").fill("retry-secret");
    server.alertPutQueue.push(putBarrier);
    await page.locator("#alerts-save-button").click();
    await putBarrier.seen.promise;
    assert.equal(await page.locator("#alerts-smtp-host").isEditable(), false);
    putBarrier.release.resolve();
    await page.locator("#alerts-save-button:not([disabled])").waitFor();
    assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "retry.example");
    assert.equal(await page.locator("#alerts-smtp-password").inputValue(), "retry-secret");
    assert.equal(await page.locator("#alerts-smtp-password-state").textContent(), "Replacement entered");
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 7");
  } finally {
    putBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old unauthorized response cannot clear a replacement session
async function testStaleSaveResponseIsFenced(browser) {
  const server = new FakeAdminServer();
  await server.start();
  const { page } = await openPage(browser, server);
  const putBarrier = responseBarrier({ error: "unauthorized" }, 401);
  try {
    await waitForRevision(page, 7);
    await page.locator("#alerts-smtp-password").fill("old-session-secret");
    server.alertPutQueue.push(putBarrier);
    await page.locator("#alerts-save-button").click();
    await putBarrier.seen.promise;
    const replacementConfig = alertConfig(20);
    await page.evaluate((config) => {
      window.showLogin();
      window.showAdmin();
      window.renderAlertConfig(config, true);
    }, replacementConfig);
    await page.locator("#alerts-smtp-password").fill("new-session-draft");
    await page.evaluate(() => window.showAlertSaveMessage("New session draft", "progress"));
    const responsePromise = page.waitForResponse((response) =>
      response.request().method() === "PUT" && new URL(response.url()).pathname === "/api/admin/alerts/config");
    putBarrier.release.resolve();
    const staleResponse = await responsePromise;
    await staleResponse.finished();
    await page.evaluate(() => Promise.resolve());
    assert.equal(await page.locator("#admin-view").isVisible(), true);
    assert.equal(await page.locator("#login-view").isVisible(), false);
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 20");
    assert.equal(await page.locator("#alerts-smtp-password").inputValue(), "new-session-draft");
    assert.equal(await page.locator("#alerts-smtp-password-state").textContent(), "Replacement entered");
    assert.equal(await page.locator("#alerts-save-message").textContent(), "New session draft");
  } finally {
    putBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old status rejection cannot clear a replacement session
async function testStaleStatusRejectionIsFenced(browser) {
  const server = new FakeAdminServer();
  const statusBarrier = responseBarrier({ error: "unauthorized" }, 401);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    server.controllerStatusQueue.push(statusBarrier);
    await page.evaluate(() => {
      window.__staleStatusPromise = window.loadStatus();
    });
    await statusBarrier.seen.promise;
    const replacementConfig = alertConfig(30);
    await page.evaluate((config) => {
      window.showLogin();
      window.showAdmin();
      window.renderAlertConfig(config, true);
    }, replacementConfig);
    await page.locator("#alerts-smtp-password").fill("replacement-session-draft");
    await page.evaluate(() => window.showAlertSaveMessage("Replacement status session", "progress"));
    statusBarrier.release.resolve();
    await page.evaluate(() => window.__staleStatusPromise);
    assert.equal(await page.locator("#admin-view").isVisible(), true);
    assert.equal(await page.locator("#login-view").isVisible(), false);
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 30");
    assert.equal(await page.locator("#alerts-smtp-password").inputValue(), "replacement-session-draft");
    assert.equal(await page.locator("#alerts-save-message").textContent(), "Replacement status session");
  } finally {
    statusBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old status success cannot overwrite replacement status
async function testStaleStatusSuccessIsFenced(browser) {
  const server = new FakeAdminServer();
  const staleStatus = { ...controllerStatus(), phase: "error", updated_at: "2020-01-01T00:00:00Z" };
  const statusBarrier = responseBarrier(staleStatus, 200);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    server.controllerStatusQueue.push(statusBarrier);
    await page.evaluate(() => {
      window.__staleStatusPromise = window.loadStatus();
    });
    await statusBarrier.seen.promise;
    const replacementConfig = alertConfig(31);
    await page.evaluate((config) => {
      window.showLogin();
      window.showAdmin();
      window.renderAlertConfig(config, true);
      document.getElementById("phase-label").textContent = "Replacement session status";
      document.getElementById("phase-badge").className = "phase-badge phase-ready";
    }, replacementConfig);
    await page.locator("#alerts-smtp-password").fill("replacement-status-draft");
    statusBarrier.release.resolve();
    await page.evaluate(() => window.__staleStatusPromise);
    assert.equal(await page.locator("#phase-label").textContent(), "Replacement session status");
    assert.equal(await page.locator("#phase-badge").getAttribute("class"), "phase-badge phase-ready");
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 31");
    assert.equal(await page.locator("#alerts-smtp-password").inputValue(), "replacement-status-draft");
  } finally {
    statusBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// exercise one stale history outcome against a replacement session
async function exerciseStaleHistory(browser, status, body) {
  const server = new FakeAdminServer();
  const historyBarrier = responseBarrier(body, status);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    server.historyQueue.push(historyBarrier);
    await page.evaluate(() => {
      window.__staleHistoryPromise = window.loadAlertHistory(true, false);
    });
    await historyBarrier.seen.promise;
    const replacementConfig = alertConfig(40);
    await page.evaluate((config) => {
      window.showLogin();
      window.showAdmin();
      window.renderAlertConfig(config, true);
      const marker = document.createElement("p");
      marker.id = "replacement-history-marker";
      marker.textContent = "Replacement session history";
      document.getElementById("alerts-history-list").replaceChildren(marker);
      document.getElementById("alerts-history-loading").hidden = false;
      document.getElementById("alerts-history-more").disabled = true;
      document.getElementById("alerts-history-error").textContent = "Replacement history state";
      document.getElementById("alerts-history-error").hidden = false;
    }, replacementConfig);
    historyBarrier.release.resolve();
    await page.evaluate(() => window.__staleHistoryPromise);
    assert.equal(await page.locator("#admin-view").isVisible(), true);
    assert.equal(await page.locator("#login-view").isVisible(), false);
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 40");
    assert.equal(await page.locator("#replacement-history-marker").textContent(), "Replacement session history");
    assert.equal(await page.locator("#alerts-history-list .history-event").count(), 0);
    assert.equal(await page.locator("#alerts-history-loading").isHidden(), false);
    assert.equal(await page.locator("#alerts-history-more").isDisabled(), true);
    assert.equal(await page.locator("#alerts-history-error").textContent(), "Replacement history state");
  } finally {
    historyBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old history success is ignored
async function testStaleHistorySuccessIsFenced(browser) {
  await exerciseStaleHistory(browser, 200, {
    events: [{ kind: "test", request_id: "old-session-test", created_at: 1791230400, channels: {} }],
    next_cursor: "old-session-cursor"
  });
}

// verify an old history rejection is ignored
async function testStaleHistoryRejectionIsFenced(browser) {
  await exerciseStaleHistory(browser, 401, { error: "unauthorized" });
}

// exercise one stale delivery-test outcome against a replacement session
async function exerciseStaleDeliveryTest(browser, status, body) {
  const server = new FakeAdminServer();
  const testBarrier = responseBarrier(body, status);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    server.alertTestQueue.push(testBarrier);
    await page.evaluate(() => {
      window.__staleDeliveryTestPromise = window.handleAlertTest();
    });
    await testBarrier.seen.promise;
    const replacementConfig = alertConfig(50);
    await page.evaluate((config) => {
      window.showLogin();
      window.showAdmin();
      window.renderAlertConfig(config, true);
      const marker = document.createElement("p");
      marker.id = "replacement-test-marker";
      marker.textContent = "Replacement session test result";
      document.getElementById("alerts-test-results").replaceChildren(marker);
      document.getElementById("alerts-test-message").textContent = "Replacement test state";
      document.getElementById("alerts-test-button").textContent = "Replacement test action";
      document.getElementById("alerts-test-button").disabled = true;
    }, replacementConfig);
    testBarrier.release.resolve();
    await page.evaluate(() => window.__staleDeliveryTestPromise);
    assert.equal(await page.locator("#admin-view").isVisible(), true);
    assert.equal(await page.locator("#login-view").isVisible(), false);
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 50");
    assert.equal(await page.locator("#replacement-test-marker").textContent(), "Replacement session test result");
    assert.equal(await page.locator("#alerts-test-results .channel-result").count(), 0);
    assert.equal(await page.locator("#alerts-test-message").textContent(), "Replacement test state");
    assert.equal(await page.locator("#alerts-test-button").textContent(), "Replacement test action");
    assert.equal(await page.locator("#alerts-test-button").isDisabled(), true);
  } finally {
    testBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old delivery-test success is ignored
async function testStaleDeliveryTestSuccessIsFenced(browser) {
  await exerciseStaleDeliveryTest(browser, 200, {
    request_id: "old-session-request",
    status: "queued"
  });
}

// verify an old delivery-test rejection is ignored
async function testStaleDeliveryTestRejectionIsFenced(browser) {
  await exerciseStaleDeliveryTest(browser, 401, { error: "unauthorized" });
}

// verify a post-login configuration rejection restores the sign-in control
async function testLoginConfigRejectionRestoresControl(browser) {
  const server = new FakeAdminServer();
  server.sessionAuthenticated = false;
  const configBarrier = responseBarrier({ error: "unauthorized" }, 401);
  server.stationGetQueue.push(configBarrier);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await page.locator("#login-view:not([hidden])").waitFor();
    await page.locator("#password").fill("browser-test-password");
    await page.locator("#login-button").click();
    await configBarrier.seen.promise;
    assert.equal(await page.locator("#login-button").isDisabled(), true);
    assert.equal(await page.locator("#login-button").textContent(), "Signing in…");
    configBarrier.release.resolve();
    await page.locator("#login-button:not([disabled])").waitFor();
    assert.equal(await page.locator("#login-button").textContent(), "Sign in");
    assert.equal(await page.locator("#login-view").isVisible(), true);
    assert.equal(await page.locator("#admin-view").isVisible(), false);
    assert.equal(await page.locator("#login-error").textContent(), "Your session expired. Sign in again.");
  } finally {
    configBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// exercise one stale logout outcome against a replacement session
async function exerciseStaleLogout(browser, status, body) {
  const server = new FakeAdminServer();
  const logoutBarrier = responseBarrier(body, status);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    server.logoutQueue.push(logoutBarrier);
    await page.locator("#logout-button").click();
    await logoutBarrier.seen.promise;
    assert.equal(await page.locator("#logout-button").isDisabled(), true);
    const replacementConfig = alertConfig(60);
    await page.evaluate((config) => {
      window.showLogin();
      window.showAdmin();
      window.renderAlertConfig(config, true);
      window.showAlertSaveMessage("Replacement logout session", "progress");
    }, replacementConfig);
    const responsePromise = page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/api/logout");
    logoutBarrier.release.resolve();
    const staleResponse = await responsePromise;
    await staleResponse.finished();
    await page.evaluate(() => Promise.resolve());
    assert.equal(await page.locator("#admin-view").isVisible(), true);
    assert.equal(await page.locator("#login-view").isVisible(), false);
    assert.equal(await page.locator("#logout-button").isVisible(), true);
    assert.equal(await page.locator("#logout-button").isDisabled(), false);
    assert.equal(await page.locator("#logout-button").textContent(), "Log out");
    assert.equal(await page.locator("#alerts-revision-label").textContent(), "Revision 60");
    assert.equal(await page.locator("#alerts-save-message").textContent(), "Replacement logout session");
  } finally {
    logoutBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old accepted logout leaves replacement controls usable
async function testStaleLogoutSuccessRestoresControl(browser) {
  await exerciseStaleLogout(browser, 200, { authenticated: false });
}

// verify an old rejected logout leaves replacement controls usable
async function testStaleLogoutRejectionRestoresControl(browser) {
  await exerciseStaleLogout(browser, 401, { error: "unauthorized" });
}

// exercise one stale station-save outcome against a replacement session
async function exerciseStaleStationSave(browser, status, body) {
  const server = new FakeAdminServer();
  const saveBarrier = responseBarrier(body, status);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.locator("#station-name").fill("Old session edit");
    server.stationPutQueue.push(saveBarrier);
    await page.locator("#save-button").click();
    await saveBarrier.seen.promise;
    assert.equal(await page.locator("#save-button").isDisabled(), true);
    assert.equal(await page.locator("#save-button").textContent(), "Saving…");
    const replacementStation = stationConfig();
    replacementStation.revision = 61;
    replacementStation.station.name = "Replacement station";
    const replacementAlerts = alertConfig(61);
    await page.evaluate(({ station, alerts }) => {
      window.showLogin();
      window.showAdmin();
      window.renderConfig(station);
      window.renderAlertConfig(alerts, true);
      window.showSaveMessage("Replacement station state", "progress");
    }, { station: replacementStation, alerts: replacementAlerts });
    const responsePromise = page.waitForResponse((response) =>
      response.request().method() === "PUT" && new URL(response.url()).pathname === "/api/admin/config");
    saveBarrier.release.resolve();
    const staleResponse = await responsePromise;
    await staleResponse.finished();
    await page.evaluate(() => Promise.resolve());
    assert.equal(await page.locator("#admin-view").isVisible(), true);
    assert.equal(await page.locator("#save-button").isDisabled(), false);
    assert.equal(await page.locator("#save-button").textContent(), "Save settings");
    assert.equal(await page.locator("#station-name").inputValue(), "Replacement station");
    assert.equal(await page.locator("#revision-label").textContent(), "Revision 61");
    assert.equal(await page.locator("#save-message").textContent(), "Replacement station state");
  } finally {
    saveBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old accepted station save leaves replacement controls usable
async function testStaleStationSaveSuccessRestoresControl(browser) {
  await exerciseStaleStationSave(browser, 200, stationConfig());
}

// verify an old rejected station save leaves replacement controls usable
async function testStaleStationSaveRejectionRestoresControl(browser) {
  await exerciseStaleStationSave(browser, 409, { error: "revision_conflict" });
}

// verify exact-aircraft and model rules save and reload together
async function testModelOverrideSaveAndReload(browser) {
  const server = new FakeAdminServer();
  server.alertConfig = alertConfig(7, [
    { hex: "A00001", mode: "include", categories: ["military"], label: "Exact aircraft" },
    { model: "C17", mode: "include", categories: ["news"], label: "Airlifter type" }
  ]);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    assert.deepEqual(
      await page.getByLabel("ICAO hex", { exact: true }).evaluateAll((inputs) => inputs.map((input) => input.value)),
      ["A00001"]
    );
    assert.deepEqual(
      await page.getByLabel("ICAO model code", { exact: true }).evaluateAll((inputs) => inputs.map((input) => input.value)),
      ["C17"]
    );
    assert.deepEqual(await page.locator(".override-row-heading strong").allTextContents(), ["Aircraft 1", "Model 2"]);
    const modelRow = page.locator(".override-row").nth(1);
    await modelRow.getByLabel("ICAO model code", { exact: true }).fill("h60");
    await modelRow.getByLabel("Action", { exact: true }).selectOption("exclude");
    await modelRow.getByLabel("Label", { exact: true }).fill("Rescue type");
    await page.locator("#alerts-save-button").click();
    await waitForRevision(page, 8);
    assert.deepEqual(server.alertConfig.overrides, [
      { hex: "A00001", mode: "include", categories: ["military"], label: "Exact aircraft" },
      { model: "H60", mode: "exclude", categories: ["news"], label: "Rescue type" }
    ]);
    await page.evaluate(async () => window.loadAlertConfig(true));
    assert.deepEqual(
      await page.getByLabel("ICAO hex", { exact: true }).evaluateAll((inputs) => inputs.map((input) => input.value)),
      ["A00001"]
    );
    assert.deepEqual(
      await page.getByLabel("ICAO model code", { exact: true }).evaluateAll((inputs) => inputs.map((input) => input.value)),
      ["H60"]
    );
    assert.equal(await modelRow.getByLabel("Action", { exact: true }).inputValue(), "exclude");
  } finally {
    await closeScenario(page, server);
  }
}

// verify invalid and duplicate model codes stay client-side
async function testModelOverrideClientValidation(browser) {
  const server = new FakeAdminServer();
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.locator("#alerts-add-model-override").click();
    await page.getByLabel("ICAO model code", { exact: true }).fill("A");
    await page.locator("#alerts-save-button").click();
    assert.equal(server.requests.filter((request) => request === "PUT /api/admin/alerts/config").length, 0);
    await page.getByLabel("ICAO model code", { exact: true }).fill("C17");
    await page.locator("#alerts-add-model-override").click();
    await page.getByLabel("ICAO model code", { exact: true }).nth(1).fill("c17");
    await page.locator("#alerts-save-button").click();
    await page.locator("#alerts-form-error:not([hidden])").waitFor();
    assert.match(await page.locator("#alerts-form-error").textContent(), /Model C17 appears more than once/);
    assert.equal(server.requests.filter((request) => request === "PUT /api/admin/alerts/config").length, 0);
  } finally {
    await closeScenario(page, server);
  }
}

// verify indexed server validation points to the rejected model code
async function testModelOverrideServerValidation(browser) {
  const server = new FakeAdminServer();
  server.alertConfig = alertConfig(7, [
    { model: "C17", mode: "include", categories: ["military"], label: "Airlifter type" }
  ]);
  const rejected = responseBarrier({
    error: "validation_failed",
    fields: { "overrides.0.model": "must be a 2-4 character ICAO model code" }
  }, 422);
  server.alertPutQueue.push(rejected);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.locator("#alerts-save-button").click();
    await rejected.seen.promise;
    rejected.release.resolve();
    await page.getByLabel("ICAO model code", { exact: true }).and(page.locator("[aria-invalid='true']")).waitFor();
    assert.equal(
      await page.getByLabel("ICAO model code", { exact: true }).getAttribute("aria-describedby"),
      await page.locator(".override-field-error:not([hidden])").getAttribute("id")
    );
    assert.match(await page.locator(".override-field-error:not([hidden])").textContent(), /ICAO model code/);
  } finally {
    rejected.release.resolve();
    await closeScenario(page, server);
  }
}

// verify remove controls and inputs stay unique after mixed row changes
async function testOverrideAccessibleNames(browser) {
  const server = new FakeAdminServer();
  server.alertConfig = alertConfig(7, [
    { hex: "A00001", mode: "include", categories: ["military"], label: "One" },
    { model: "C17", mode: "include", categories: ["medical"], label: "Two" },
    { hex: "A00003", mode: "exclude", categories: ["news"], label: "Three" }
  ]);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    const removeButtons = page.locator(".override-remove");
    const initialNames = await removeButtons.evaluateAll((buttons) => buttons.map((button) => button.getAttribute("aria-label") || button.textContent));
    assert.equal(new Set(initialNames).size, 3);
    assert.match(initialNames[0], /aircraft 1/i);
    assert.match(initialNames[1], /model 2/i);
    assert.match(initialNames[2], /aircraft 3/i);
    await removeButtons.nth(1).click();
    const remainingNames = await removeButtons.evaluateAll((buttons) => buttons.map((button) => button.getAttribute("aria-label") || button.textContent));
    assert.equal(new Set(remainingNames).size, 2);
    assert.match(remainingNames[0], /aircraft 1/i);
    assert.match(remainingNames[1], /aircraft 2/i);
    const remainingHexes = await page.getByLabel("ICAO hex", { exact: true }).evaluateAll((inputs) => inputs.map((input) => input.value));
    assert.deepEqual(remainingHexes, ["A00001", "A00003"]);
    assert.deepEqual(await page.locator(".override-row-heading strong").allTextContents(), ["Aircraft 1", "Aircraft 2"]);
    await page.locator("#alerts-add-model-override").click();
    await page.getByLabel("ICAO model code", { exact: true }).fill("H60");
    assert.deepEqual(await page.locator(".override-row-heading strong").allTextContents(), ["Aircraft 1", "Aircraft 2", "Model 3"]);
    const identityIds = await page.locator(".override-hex, .override-model").evaluateAll((inputs) => inputs.map((input) => input.id));
    assert.equal(new Set(identityIds).size, 3);
    const labelledIds = await page.locator(".override-grid .field:first-child label").evaluateAll((labels) => labels.map((label) => label.htmlFor));
    assert.deepEqual(labelledIds, identityIds);
  } finally {
    await closeScenario(page, server);
  }
}

// verify history identifies a route omitted from one notification
async function testHistoryShowsUnselectedChannel(browser) {
  const server = new FakeAdminServer();
  const historyResponse = responseBarrier({
    events: [{
      kind: "aircraft",
      hex: "A00001",
      label: "Single-route aircraft",
      categories: ["military"],
      bands: ["1090"],
      observed_at: 1791230400,
      channels: {
        pushover: { state: "accepted", attempts: 1 }
      }
    }],
    next_cursor: null
  });
  historyResponse.release.resolve();
  server.historyQueue.push(historyResponse);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await page.locator(".history-event").waitFor();
    assert.deepEqual(await page.locator(".history-channel > strong").allTextContents(), ["Pushover", "Email"]);
    assert.deepEqual(await page.locator(".history-channel > span").allTextContents(), ["Accepted by Pushover", "Not selected"]);
  } finally {
    await closeScenario(page, server);
  }
}

// keep every card's selection above its details without individual install buttons
async function testMaintenanceHeaderCheckboxLayout(browser) {
  const states = ["available", "held", "blocked", "queued", "installing", "installed", "failed"];
  // verify both two-column desktop cards and narrow mobile cards
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 360, height: 800 }]) {
    const server = new FakeAdminServer();
    // cover selectable and read-only card states with unique identities
    const updates = states.map((state, index) => maintenanceCandidate({
      id: (index + 1).toString(16).repeat(64),
      label: `${state} application package`,
      name: "package-with-a-long-component-name",
      state
    }));
    server.maintenance = maintenanceReport({ state: "waiting" }, { updates });
    await server.start();
    const { page, pageErrors, consoleErrors } = await openPage(browser, server, viewport);
    try {
      await waitForRevision(page, 7);
      // wait for optional maintenance hydration before measuring cards
      await page.locator(".maintenance-update-card").first().waitFor();
      assert.equal(await page.locator(".maintenance-update-card").count(), states.length);
      assert.equal(await page.locator(".maintenance-update-heading input[type=checkbox]").count(), states.length);
      assert.equal(await page.locator(".maintenance-update-actions input[type=checkbox], .maintenance-update-card button").count(), 0);
      assert.equal(await page.locator("#maintenance-update-list input:checked").count(), 0);
      // measure every checkbox and both identity lines in the rendered header
      const layouts = await page.locator(".maintenance-update-card").evaluateAll((cards) => cards.map((card) => {
        const cardBounds = card.getBoundingClientRect();
        const checkbox = card.querySelector('input[type="checkbox"]').getBoundingClientRect();
        const name = card.querySelector("h4").getBoundingClientRect();
        const component = card.querySelector(".maintenance-update-heading small").getBoundingClientRect();
        return {
          cardLeft: cardBounds.left, cardRight: cardBounds.right, cardTop: cardBounds.top,
          checkboxLeft: checkbox.left, checkboxRight: checkbox.right, checkboxTop: checkbox.top,
          nameLeft: name.left, nameRight: name.right, nameTop: name.top,
          componentLeft: component.left, componentRight: component.right
        };
      }));
      // reserve the upper-left space while keeping text within each card
      for (const layout of layouts) {
        assert.ok(layout.checkboxLeft - layout.cardLeft <= 36);
        assert.ok(layout.checkboxTop - layout.cardTop <= 24);
        assert.ok(Math.abs(layout.checkboxTop - layout.nameTop) <= 6);
        assert.ok(layout.nameLeft > layout.checkboxRight);
        assert.ok(layout.componentLeft > layout.checkboxRight);
        assert.ok(layout.nameRight <= layout.cardRight);
        assert.ok(layout.componentRight <= layout.cardRight);
      }
      // reject horizontal page overflow
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
      // preserve explicit keyboard selection and the shared batch action
      const available = page.getByRole("checkbox", { name: "Select available application package for installation", exact: true });
      await available.focus();
      await available.press("Space");
      assert.equal(await available.isChecked(), true);
      assert.equal(await page.locator("#maintenance-install-selected").isEnabled(), true);
      await page.locator(".maintenance-update-selection").nth(1).click();
      assert.equal(await page.locator("#maintenance-selection-count").textContent(), "2 updates selected");
      // prevent selection of blocked or completed and in-flight updates
      for (const state of ["blocked", "queued", "installing", "installed"]) {
        assert.equal(await page.getByRole("checkbox", { name: `Select ${state} application package for installation`, exact: true }).isDisabled(), true);
      }
      // keep every card read-only while a batch is queued
      server.maintenance.installation = { state: "queued", candidate_ids: [updates[0].id, updates[1].id], request_id: "layout-batch" };
      await page.evaluate(async () => window.loadMaintenance());
      assert.equal(await page.locator(".maintenance-update-heading input[type=checkbox]:disabled").count(), states.length);
      assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
      assert.equal(server.installRequests.length, 0);
      assert.deepEqual(pageErrors, []);
      assert.deepEqual(consoleErrors, []);
    } finally {
      await closeScenario(page, server);
    }
  }
}

// build hostile text and links for observable maintenance rendering
function maintenanceRenderingCandidates() {
  return [
    maintenanceCandidate({ changelog: "<img src=x onerror=alert(1)>\n**not markdown**" }),
    maintenanceCandidate({ id: HELD_CANDIDATE_ID, name: "reverse-proxy", label: "Nginx proxy", compatibility: "breaking", state: "held", reason: "Configuration syntax changed and needs review.", changelog: "Breaking configuration change.", changelog_url: "javascript:alert(1)" }),
    maintenanceCandidate({ id: BLOCKED_CANDIDATE_ID, name: "tunnel-agent", label: "Cloudflare tunnel", compatibility: "unknown", state: "blocked", reason: "Candidate metadata could not be verified.", changelog: "Verification unavailable.", changelog_url: "https://example.com/not-official" })
  ];
}

// isolate each maintenance contract with its own fake server and browser page
async function withMaintenancePage(browser, verify) {
  const server = new FakeAdminServer();
  server.maintenance = maintenanceReport({ state: "waiting" }, { updates: maintenanceRenderingCandidates() });
  await server.start();
  const { page, pageErrors, consoleErrors } = await openPage(browser, server, { width: 360, height: 800 });
  try {
    await waitForRevision(page, 7);
    // wait for observable maintenance hydration before testing its public controls
    await page.getByRole("checkbox", { name: "Select Tar1090 map for installation", exact: true }).waitFor();
    await page.locator("#alerts-smtp-host").fill("draft.example");
    await verify(page, server);
    assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "draft.example");
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(consoleErrors, []);
  } finally {
    await closeScenario(page, server);
  }
}

// map every bounded email notification state without mutating alert drafts
async function testMaintenanceEmailStates(browser) {
  await withMaintenancePage(browser, async (page, server) => {
    const cases = [
      [{ state: "not_configured" }, "SMTP not configured"],
      [{ state: "waiting" }, "Watching for changes"],
      [{ state: "pending" }, "Queued"],
      [{ state: "in_flight" }, "Sending"],
      [{ state: "retry", retry_at: 1791230400 }, "Retrying"],
      [{ state: "accepted", accepted_at: 1791230400 }, "Accepted by SMTP server"],
      [{ state: "failed" }, "Failed"],
      [{ state: "expired" }, "Failed"],
      [{ state: "suppressed" }, "Suppressed"],
      [{ state: "unexpected", error: "<img src=x onerror=alert(1)>" }, "Unknown"]
    ];
    // inspect each externally visible email state
    for (const [notification, expected] of cases) {
      server.maintenance = maintenanceReport(notification);
      await page.evaluate(async () => window.loadMaintenance());
      assert.match(await page.locator("#maintenance-email-notification").textContent(), new RegExp(`^${expected}`));
    }
  });
}

// reject unsafe changelog links through their rendered public controls
async function testMaintenanceSafeRendering(browser) {
  await withMaintenancePage(browser, async (page, server) => {
    assert.equal(await page.getByRole("checkbox", { name: "Select Tar1090 map for installation", exact: true }).count(), 1);
    assert.equal(await page.getByRole("checkbox", { name: "Select Nginx proxy for installation", exact: true }).count(), 1);
    assert.equal(await page.getByRole("checkbox", { name: "Select Cloudflare tunnel for installation", exact: true }).isDisabled(), true);
    assert.equal(await page.locator(".maintenance-panel img, .maintenance-panel script").count(), 0);
    assert.equal(await page.locator(".maintenance-changelog pre").first().textContent(), "<img src=x onerror=alert(1)>\n**not markdown**");
    assert.deepEqual(await page.getByRole("link", { name: /Official release notes/ }).evaluateAll((links) => links.map((link) => link.href)), ["https://github.com/example/project/releases/tag/v1.1.0"]);
    assert.equal(await page.getByRole("link", { name: /Official release notes/ }).getAttribute("rel"), "noopener noreferrer");
    assert.match(await page.locator("#maintenance-policy").textContent(), /compatible updates install automatically/i);
    assert.match(await page.locator("#maintenance-policy").textContent(), /held for your install action/i);
    assert.match(await page.locator(".maintenance-note").last().textContent(), /newly held updates and terminal installation failures/i);
    assert.match(await page.locator(".maintenance-note").last().textContent(), /unchanged held candidates are not emailed again/i);
    assert.doesNotMatch(await page.locator(".maintenance-panel").textContent(), /pinned releases|review current/i);
    // render each rejected URL rather than invoking a private utility
    for (const changelog_url of ["https://user:password@github.com/project/releases", "https://github.com:444/project/releases", "https:\\github.com\\project\\releases", "https://github.com/project/releases\u0000"]) {
      server.maintenance = maintenanceReport({ state: "waiting" }, { updates: [maintenanceCandidate({ changelog_url })] });
      await page.evaluate(async () => window.loadMaintenance());
      assert.equal(await page.getByRole("link", { name: /Official release notes/ }).count(), 0);
    }
  });
}

// preserve explicit selections expanded changelogs and keyboard focus across polls
async function testMaintenanceSelectionPreservation(browser) {
  await withMaintenancePage(browser, async (page) => {
    assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
    const selection = page.getByRole("checkbox", { name: "Select Nginx proxy for installation", exact: true });
    assert.equal(await selection.isChecked(), false);
    await selection.check();
    assert.equal(await page.locator("#maintenance-install-selected").isEnabled(), true);
    const changelog = page.locator(".maintenance-changelog").first();
    const summary = changelog.locator("summary");
    await summary.focus();
    await summary.press("Enter");
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await selection.isChecked(), true);
    assert.equal(await changelog.getAttribute("open"), "");
    assert.equal(await summary.evaluate((value) => document.activeElement === value), true);
  });
}

// distinguish unavailable failed and refreshed terminal maintenance outcomes
async function testMaintenanceReportFailureStates(browser) {
  await withMaintenancePage(browser, async (page, server) => {
    server.maintenance = maintenanceReport({ state: "waiting" }, { status: "attention", updates: [], images: [{ name: "proxy", review_ref: "nginx:stable-alpine", status: "unknown" }], map_status: "unknown" });
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.locator("#maintenance-state").textContent(), "Check needs attention");
    assert.equal(await page.locator("#maintenance-releases").textContent(), "Update details unavailable");
    assert.match(await page.locator("#maintenance-summary").textContent(), /details are unavailable/i);
    assert.equal(await page.locator("#maintenance-update-list .empty-state").textContent(), "Update information is unavailable.");
    server.maintenance = { ...maintenanceReport({ state: "unknown" }), status: "failed", os_schedule: "<img src=x onerror=alert(1)>", application_policy: "<script>alert(1)</script>", disk_free_percent: null, reboot_required: null, images: [], map_status: "unknown" };
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.locator("#maintenance-state").textContent(), "Maintenance failed");
    assert.match(await page.locator("#maintenance-summary").textContent(), /failed and needs operator attention/i);
    assert.equal(await page.locator(".maintenance-panel img, .maintenance-panel script").count(), 0);
    assert.equal(await page.locator("#maintenance-schedule").textContent(), "<img src=x onerror=alert(1)>");
    server.maintenance = maintenanceReport({ state: "waiting" }, { generation: "e".repeat(64), updates: [], installation: { state: "installed", candidate_id: HELD_CANDIDATE_ID, candidate_ids: [HELD_CANDIDATE_ID], request_id: "f".repeat(64), message: "The verified immutable release was installed." } });
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.locator("#maintenance-installation").textContent(), "The verified immutable release was installed.");
    assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
  });
}

// keep cards and notification routes within the narrow viewport
async function testMaintenanceMobileLayout(browser) {
  await withMaintenancePage(browser, async (page) => {
    const cards = await page.locator(".maintenance-update-card").evaluateAll((values) => values.map((value) => ({ left: value.getBoundingClientRect().left, right: value.getBoundingClientRect().right })));
    assert.equal(cards.length, 3);
    // require visible cards without horizontal clipping
    for (const bounds of cards) {
      assert.ok(bounds.left >= 0);
      assert.ok(bounds.right <= 360);
    }
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth) <= 1);
    const rows = await page.locator(".category-row").evaluateAll((values) => values.map((value) => ({ left: value.getBoundingClientRect().left, right: value.getBoundingClientRect().right, width: value.getBoundingClientRect().width })));
    assert.equal(rows.length, 3);
    // require visible notification rows without horizontal clipping
    for (const bounds of rows) {
      assert.ok(bounds.left >= 0);
      assert.ok(bounds.right <= 360);
      assert.ok(bounds.width > 0);
    }
    // retain all six independently selectable notification routes
    for (const category of ["military", "medical", "news"]) {
      // verify both controls for each aircraft category
      for (const channel of ["pushover", "email"]) {
        assert.equal(await page.locator(`#alerts-category-${category}-${channel}`).isVisible(), true);
      }
    }
    // capture an opt-in browser review artifact
    if (process.env.ADSB_UI_SCREENSHOT_PATH) {
      await page.screenshot({ path: process.env.ADSB_UI_SCREENSHOT_PATH, fullPage: true });
    }
  });
}

// verify exact update authorization and preserve drafts during stale polls
async function testMaintenanceInstallQueuesExactCandidate(browser) {
  const server = new FakeAdminServer();
  server.maintenance = maintenanceReport({ state: "waiting" }, {
    updates: [maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Held proxy", compatibility: "breaking", state: "held" })]
  });
  const installBarrier = responseBarrier({
    state: "queued",
    request_id: "queued-browser-request",
    candidate_ids: [HELD_CANDIDATE_ID]
  }, 202);
  server.installQueue.push(installBarrier);
  await server.start();
  const { page, pageErrors, consoleErrors } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.locator("#station-name").fill("Station draft during install");
    await page.locator("#alerts-smtp-host").fill("smtp-draft.example");
    await page.getByRole("checkbox", { name: "Select Held proxy for installation", exact: true }).check();
    await page.locator("#maintenance-install-selected").click();
    await installBarrier.seen.promise;
    assert.deepEqual(installBarrier.payload, {
      candidate_ids: [HELD_CANDIDATE_ID],
      generation: REPORT_GENERATION
    });
    assert.equal(installBarrier.csrf, "browser-test-csrf");
    assert.equal(await page.getByRole("checkbox", { name: "Select Held proxy for installation", exact: true }).isDisabled(), true);
    assert.equal(await page.getByRole("checkbox", { name: "Select Held proxy for installation", exact: true }).isChecked(), true);
    assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
    assert.match(await page.locator("#maintenance-installation").textContent(), /requesting installation/i);
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.getByRole("checkbox", { name: "Select Held proxy for installation", exact: true }).isDisabled(), true);
    assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
    assert.equal(await page.locator("#station-name").inputValue(), "Station draft during install");
    assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "smtp-draft.example");
    installBarrier.release.resolve();
    await page.locator("#maintenance-installation").getByText(/queued.*not been reported complete/i).waitFor();
    assert.doesNotMatch(await page.locator("#maintenance-installation").textContent(), /installed successfully/i);
    assert.equal(server.installRequests.length, 1);
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(consoleErrors, []);
  } finally {
    installBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify failed queue requests restore one retryable action
async function testMaintenanceInstallFailureCanRetry(browser) {
  const server = new FakeAdminServer();
  server.maintenance = maintenanceReport({ state: "waiting" }, {
    updates: [maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Retry proxy", compatibility: "unknown", state: "failed" })]
  });
  const conflictBarrier = responseBarrier({ error: "candidate changed" }, 409);
  const failureBarrier = responseBarrier({ error: "installer unavailable" }, 503);
  server.installQueue.push(conflictBarrier, failureBarrier);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.getByRole("checkbox", { name: "Select Retry proxy for installation", exact: true }).check();
    await page.locator("#maintenance-install-selected").click();
    await conflictBarrier.seen.promise;
    conflictBarrier.release.resolve();
    const retry = page.locator("#maintenance-install-selected");
    // wait for the asynchronous retry control rather than its existing visibility
    await retry.and(page.locator(":enabled")).waitFor();
    assert.equal(await retry.isEnabled(), true);
    assert.match(await page.locator("#maintenance-installation").textContent(), /information changed.*next maintenance refresh/i);
    await retry.click();
    await failureBarrier.seen.promise;
    failureBarrier.release.resolve();
    // wait for the asynchronous retry control rather than its existing visibility
    await retry.and(page.locator(":enabled")).waitFor();
    assert.equal(await retry.isEnabled(), true);
    assert.match(await page.locator("#maintenance-installation").textContent(), /service is unavailable.*nothing was reported installed/i);
    await retry.click();
    await page.locator("#maintenance-installation").getByText(/queued.*not been reported complete/i).waitFor();
    assert.equal(server.installRequests.length, 3);
  } finally {
    conflictBarrier.release.resolve();
    failureBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// verify an old install completion cannot overwrite a replacement session
async function testStaleMaintenanceInstallIsFenced(browser) {
  const server = new FakeAdminServer();
  server.maintenance = maintenanceReport({ state: "waiting" }, {
    updates: [maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Old session update", compatibility: "breaking", state: "held" })]
  });
  const installBarrier = responseBarrier({
    state: "queued",
    request_id: "old-session-request",
    candidate_ids: [HELD_CANDIDATE_ID]
  }, 202);
  server.installQueue.push(installBarrier);
  await server.start();
  const { page } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.getByRole("checkbox", { name: "Select Old session update for installation", exact: true }).check();
    await page.locator("#maintenance-install-selected").click();
    await installBarrier.seen.promise;
    const replacementReport = maintenanceReport({ state: "waiting" });
    await page.evaluate((report) => {
      window.showLogin();
      window.showAdmin();
      window.renderMaintenance(report);
      document.getElementById("maintenance-summary").textContent = "Replacement session maintenance";
    }, replacementReport);
    const responsePromise = page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/api/admin/maintenance/install");
    installBarrier.release.resolve();
    const staleResponse = await responsePromise;
    await staleResponse.finished();
    await page.evaluate(() => Promise.resolve());
    assert.equal(await page.locator("#admin-view").isVisible(), true);
    assert.equal(await page.locator("#maintenance-summary").textContent(), "Replacement session maintenance");
    assert.equal(await page.locator(".maintenance-update-card").count(), 0);
    assert.equal(await page.locator("#maintenance-installation").isHidden(), true);
  } finally {
    installBarrier.release.resolve();
    await closeScenario(page, server);
  }
}

// keep refreshed candidates usable after an older queued request loses its report binding
async function testMaintenanceGenerationChangeReleasesOldAction(browser) {
  // cover both acknowledged queues and delayed acknowledgements
  for (const phase of ["queued", "requesting"]) {
    const server = new FakeAdminServer();
    server.maintenance = maintenanceReport({ state: "waiting" }, {
      updates: [maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Original proxy", compatibility: "unknown", state: "held" })]
    });
    const installBarrier = responseBarrier({ state: "queued", request_id: "old-generation-request", candidate_ids: [HELD_CANDIDATE_ID] }, 202);
    server.installQueue.push(installBarrier);
    await server.start();
    const { page, pageErrors } = await openPage(browser, server);
    try {
      await waitForRevision(page, 7);
      await page.getByRole("checkbox", { name: "Select Original proxy for installation", exact: true }).check();
    await page.locator("#maintenance-install-selected").click();
      await installBarrier.seen.promise;
      // acknowledge one queue before the replacement snapshot arrives
      if (phase === "queued") {
        installBarrier.release.resolve();
        await page.locator("#maintenance-installation").getByText(/queued.*not been reported complete/i).waitFor();
      }
      server.maintenance = maintenanceReport({ state: "waiting" }, {
        generation: "f".repeat(64),
        updates: [maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Refreshed proxy", compatibility: "unknown", state: "held" })]
      });
      await page.evaluate(async () => window.loadMaintenance());
      const refreshed = page.getByRole("checkbox", { name: "Select Refreshed proxy for installation", exact: true });
      assert.equal(await refreshed.isEnabled(), true);
      assert.match(await page.locator("#maintenance-installation").textContent(), /earlier.*not confirmed/i);
      // a delayed acknowledgement must not restore the older snapshot or action
      if (phase === "requesting") {
        const response = page.waitForResponse((value) => value.request().method() === "POST" && new URL(value.url()).pathname === "/api/admin/maintenance/install");
        installBarrier.release.resolve();
        await (await response).finished();
        await page.evaluate(() => Promise.resolve());
      }
      assert.equal(await refreshed.isEnabled(), true);
      assert.equal(await page.getByRole("checkbox", { name: "Select Original proxy for installation", exact: true }).count(), 0);
      assert.equal(await page.locator("#maintenance-state").textContent(), "Updates held");
      assert.equal(server.installRequests.length, 1);
      assert.deepEqual(pageErrors, []);
    } finally {
      installBarrier.release.resolve();
      await closeScenario(page, server);
    }
  }
}

// verify multiple choices become one exact transaction with progress on every card
async function testMaintenanceBatchSelectionAndProgress(browser) {
  const server = new FakeAdminServer();
  const updates = [
    maintenanceCandidate({ id: AVAILABLE_CANDIDATE_ID, label: "Batch map", compatibility: "breaking", state: "held" }),
    maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Batch proxy", compatibility: "unknown", state: "held" }),
    maintenanceCandidate({ id: BLOCKED_CANDIDATE_ID, label: "Blocked radio", state: "blocked" })
  ];
  server.maintenance = maintenanceReport({ state: "waiting" }, { updates });
  const batch = [AVAILABLE_CANDIDATE_ID, HELD_CANDIDATE_ID];
  const barrier = responseBarrier({ state: "queued", request_id: "batch-request", candidate_ids: batch }, 202);
  server.installQueue.push(barrier);
  await server.start();
  const { page, pageErrors } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    const install = page.locator("#maintenance-install-selected");
    assert.equal(await install.isDisabled(), true);
    assert.equal(await page.locator("#maintenance-update-list button").count(), 0);
    assert.equal(await page.getByRole("checkbox", { name: "Select Blocked radio for installation" }).isDisabled(), true);
    await page.getByRole("checkbox", { name: "Select Batch proxy for installation" }).check();
    await page.getByRole("checkbox", { name: "Select Batch map for installation" }).check();
    assert.equal(await page.locator("#maintenance-selection-count").textContent(), "2 updates selected");
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.locator("#maintenance-update-list input:checked").count(), 2);
    await install.click();
    await barrier.seen.promise;
    assert.deepEqual(barrier.payload, { candidate_ids: batch, generation: REPORT_GENERATION });
    assert.equal(barrier.csrf, "browser-test-csrf");
    assert.equal(await install.isDisabled(), true);
    assert.equal(await page.getByRole("checkbox", { name: "Select Batch map for installation" }).isDisabled(), true);
    assert.equal(await page.getByRole("checkbox", { name: "Select Batch proxy for installation" }).isDisabled(), true);
    assert.match(await page.locator("#maintenance-installation").textContent(), /2 selected updates/);
    // an older completed attempt must not erase a new in-flight request
    server.maintenance.installation = { state: "failed", candidate_id: batch[0], candidate_ids: batch, request_id: "older-request" };
    await page.evaluate(async () => window.loadMaintenance());
    assert.match(await page.locator("#maintenance-installation").textContent(), /requesting installation/i);
    assert.equal(await install.isDisabled(), true);
    barrier.release.resolve();
    await page.locator("#maintenance-installation").getByText(/queued.*not been reported complete/i).waitFor();
    // apply acknowledged root progress to all selected members
    for (const state of ["installing", "installed"]) {
      server.maintenance.installation = { state, candidate_id: batch[0], candidate_ids: batch, request_id: "batch-request" };
      await page.evaluate(async () => window.loadMaintenance());
      assert.match(await page.locator("#maintenance-installation").textContent(), state === "installed" ? /installed successfully/i : /installing/i);
      assert.equal(await page.getByRole("checkbox", { name: "Select Batch map for installation" }).isDisabled(), true);
      assert.equal(await page.getByRole("checkbox", { name: "Select Batch proxy for installation" }).isDisabled(), true);
    }
    assert.equal(await page.locator("#maintenance-selection-count").textContent(), "No updates selected");
    assert.equal(await install.isDisabled(), true);
    assert.equal(server.installRequests.length, 1);
    assert.deepEqual(pageErrors, []);
  } finally {
    barrier.release.resolve();
    await closeScenario(page, server);
  }
}

// reject partial acknowledgements and clear selections when authorization changes
async function testMaintenanceBatchSelectionSafety(browser) {
  const server = new FakeAdminServer();
  const updates = [
    maintenanceCandidate({ id: AVAILABLE_CANDIDATE_ID, label: "Map choice", state: "held" }),
    maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Proxy choice", state: "held" })
  ];
  server.maintenance = maintenanceReport({ state: "waiting" }, { updates });
  const partial = responseBarrier({ state: "queued", request_id: "partial-request", candidate_ids: [HELD_CANDIDATE_ID] }, 202);
  server.installQueue.push(partial);
  await server.start();
  const { page, pageErrors } = await openPage(browser, server);
  try {
    await waitForRevision(page, 7);
    await page.getByRole("checkbox", { name: "Select Map choice for installation" }).check();
    await page.getByRole("checkbox", { name: "Select Proxy choice for installation" }).check();
    await page.locator("#maintenance-install-selected").click();
    await partial.seen.promise;
    partial.release.resolve();
    await page.locator("#maintenance-installation").getByText(/did not acknowledge all selected updates/i).waitFor();
    assert.equal(await page.locator("#maintenance-install-selected").isEnabled(), true);
    assert.equal(await page.locator("#maintenance-update-list input:checked").count(), 2);
    // remove technical authorization without silently selecting another update
    updates[0].state = "blocked";
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.locator("#maintenance-update-list input:checked").count(), 1);
    server.maintenance.generation = "e".repeat(64);
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.locator("#maintenance-update-list input:checked").count(), 0);
    assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
    assert.equal(server.installRequests.length, 1);
    assert.deepEqual(pageErrors, []);
  } finally {
    partial.release.resolve();
    await closeScenario(page, server);
  }
}

// fence delayed older responses from a newer batch for the same candidate
async function testMaintenanceReplacementBatchIsFenced(browser) {
  // exercise both older acknowledgement and older queue failure
  for (const outcome of [202, 503]) {
    const server = new FakeAdminServer();
    const updates = [maintenanceCandidate({ id: HELD_CANDIDATE_ID, label: "Shared proxy", state: "held" })];
    server.maintenance = maintenanceReport({ state: "waiting" }, { updates });
    const old = responseBarrier(outcome === 202
      ? { state: "queued", request_id: "old-request", candidate_ids: [HELD_CANDIDATE_ID] }
      : { error: "old installer failure" }, outcome);
    const newer = responseBarrier({ state: "queued", request_id: "new-request", candidate_ids: [HELD_CANDIDATE_ID] }, 202);
    server.installQueue.push(old, newer);
    await server.start();
    const { page, pageErrors } = await openPage(browser, server);
    try {
      await waitForRevision(page, 7);
      await page.getByRole("checkbox", { name: "Select Shared proxy for installation" }).check();
      await page.locator("#maintenance-install-selected").click();
      await old.seen.promise;
      server.maintenance.generation = "f".repeat(64);
      await page.evaluate(async () => window.loadMaintenance());
      assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
      await page.getByRole("checkbox", { name: "Select Shared proxy for installation" }).check();
      await page.locator("#maintenance-install-selected").click();
      await newer.seen.promise;
      const response = page.waitForResponse((value) => value.request().method() === "POST" && value.status() === outcome);
      old.release.resolve();
      await (await response).finished();
      await page.evaluate(() => Promise.resolve());
      assert.equal(await page.locator("#maintenance-install-selected").isDisabled(), true);
      assert.match(await page.locator("#maintenance-installation").textContent(), /requesting installation/i);
      assert.equal(await page.getByRole("checkbox", { name: "Select Shared proxy for installation" }).isDisabled(), true);
      newer.release.resolve();
      await page.locator("#maintenance-installation").getByText(/queued.*not been reported complete/i).waitFor();
      assert.deepEqual(newer.payload, { candidate_ids: [HELD_CANDIDATE_ID], generation: "f".repeat(64) });
      assert.equal(server.installRequests.length, 2);
      assert.deepEqual(pageErrors, []);
    } finally {
      old.release.resolve();
      newer.release.resolve();
      await closeScenario(page, server);
    }
  }
}

const tests = [
  ["legacy categories hydrate both routes accessibly", testLegacyCategoryRouteHydration],
  ["category routes save and reload independently", testCategoryRouteSaveAndReload],
  ["category route drafts survive background hydration", testCategoryRouteDraftPreservation],
  ["disabled alerts preserve an empty route draft", testEmptyRouteDraftAndEnabledValidation],
  ["selected routes require only matching credentials", testSelectedRouteCredentialValidation],
  ["initial hydration locks alert edits", testInitialHydration],
  ["accepted save survives optional status failure", testAcceptedSaveAndStatusFailure],
  ["failed save retains retryable draft", testFailedSaveRetainsDraft],
  ["stale save response is session fenced", testStaleSaveResponseIsFenced],
  ["stale status rejection is session fenced", testStaleStatusRejectionIsFenced],
  ["stale status success is session fenced", testStaleStatusSuccessIsFenced],
  ["stale history success is session fenced", testStaleHistorySuccessIsFenced],
  ["stale history rejection is session fenced", testStaleHistoryRejectionIsFenced],
  ["stale delivery-test success is session fenced", testStaleDeliveryTestSuccessIsFenced],
  ["stale delivery-test rejection is session fenced", testStaleDeliveryTestRejectionIsFenced],
  ["login config rejection restores sign-in control", testLoginConfigRejectionRestoresControl],
  ["stale logout success restores control", testStaleLogoutSuccessRestoresControl],
  ["stale logout rejection restores control", testStaleLogoutRejectionRestoresControl],
  ["stale station-save success restores control", testStaleStationSaveSuccessRestoresControl],
  ["stale station-save rejection restores control", testStaleStationSaveRejectionRestoresControl],
  ["model and exact-aircraft overrides save together", testModelOverrideSaveAndReload],
  ["model override validation blocks invalid drafts", testModelOverrideClientValidation],
  ["model override server errors map to their input", testModelOverrideServerValidation],
  ["mixed override controls remain unique", testOverrideAccessibleNames],
  ["history labels unselected delivery channels", testHistoryShowsUnselectedChannel],
  ["maintenance checkboxes occupy each card's upper-left header", testMaintenanceHeaderCheckboxLayout],
  ["maintenance email states preserve alert drafts", testMaintenanceEmailStates],
  ["maintenance changelogs render safely", testMaintenanceSafeRendering],
  ["maintenance selection and focus survive polling", testMaintenanceSelectionPreservation],
  ["maintenance failure and refreshed terminal results stay truthful", testMaintenanceReportFailureStates],
  ["maintenance cards and routes fit mobile", testMaintenanceMobileLayout],
  ["maintenance selections install one batch with shared progress", testMaintenanceBatchSelectionAndProgress],
  ["maintenance selection rejects partial or stale authorization", testMaintenanceBatchSelectionSafety],
  ["maintenance install queues the exact candidate", testMaintenanceInstallQueuesExactCandidate],
  ["maintenance install failure can retry", testMaintenanceInstallFailureCanRetry],
  ["stale maintenance install is session fenced", testStaleMaintenanceInstallIsFenced],
  ["maintenance generation changes release old actions", testMaintenanceGenerationChangeReleasesOldAction],
  ["older batch responses cannot release a newer batch", testMaintenanceReplacementBatchIsFenced]
];

const browser = await chromium.launch({ headless: true });
let failures = 0;
try {
  // run each isolated browser scenario
  for (const [name, test] of tests) {
    try {
      await withTimeout(test(browser), TEST_TIMEOUT_MS);
      console.log(`PASS ${name}`);
    } catch (error) {
      failures += 1;
      console.error(`FAIL ${name}: ${error.stack || error.message}`);
    }
  }
} finally {
  await browser.close();
}

// return one failing process status to the unittest wrapper
if (failures > 0) {
  process.exitCode = 1;
}
