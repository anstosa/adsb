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
function maintenanceReport(emailNotifications = { state: "waiting" }) {
  return {
    status: "ok",
    updated_at: "2026-10-05T12:00:00Z",
    os_schedule: "Tuesdays 04:00 America/Los_Angeles",
    application_policy: "Pinned releases; updates require review",
    disk_free_percent: 51.2,
    reboot_required: false,
    images: [],
    map_status: "current",
    email_notifications: emailNotifications
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
      sendJson(response, 200, this.maintenance);
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

// close one page and its local server
async function closeScenario(page, server) {
  await page.close();
  await server.close();
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

// verify remove controls stay unique after row renumbering
async function testOverrideAccessibleNames(browser) {
  const server = new FakeAdminServer();
  server.alertConfig = alertConfig(7, [
    { hex: "A00001", mode: "include", categories: ["military"], label: "One" },
    { hex: "A00002", mode: "include", categories: ["medical"], label: "Two" },
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
    assert.match(initialNames[1], /aircraft 2/i);
    assert.match(initialNames[2], /aircraft 3/i);
    await removeButtons.nth(1).click();
    const remainingNames = await removeButtons.evaluateAll((buttons) => buttons.map((button) => button.getAttribute("aria-label") || button.textContent));
    assert.equal(new Set(remainingNames).size, 2);
    assert.match(remainingNames[0], /aircraft 1/i);
    assert.match(remainingNames[1], /aircraft 2/i);
    const remainingHexes = await page.locator(".override-hex").evaluateAll((inputs) => inputs.map((input) => input.value));
    assert.deepEqual(remainingHexes, ["A00001", "A00003"]);
    assert.deepEqual(await page.locator(".override-row-heading strong").allTextContents(), ["Aircraft 1", "Aircraft 2"]);
  } finally {
    await closeScenario(page, server);
  }
}

// verify maintenance states render safely without touching drafts
async function testMaintenanceRenderingAndMobile(browser) {
  const server = new FakeAdminServer();
  await server.start();
  const { page, pageErrors, consoleErrors } = await openPage(browser, server, { width: 360, height: 800 });
  try {
    await waitForRevision(page, 7);
    await page.locator("#alerts-smtp-host").fill("draft.example");
    const cases = [
      [{ state: "not_configured" }, "SMTP not configured"],
      [{ state: "waiting" }, "Waiting for next review"],
      [{ state: "pending" }, "Queued"],
      [{ state: "in_flight" }, "Sending"],
      [{ state: "retry", retry_at: 1791230400 }, "Retrying"],
      [{ state: "accepted", accepted_at: 1791230400 }, "Accepted by SMTP server"],
      [{ state: "failed" }, "Failed"],
      [{ state: "expired" }, "Failed"],
      [{ state: "suppressed" }, "Suppressed"],
      [{ state: "unexpected", error: "<img src=x onerror=alert(1)>" }, "Unknown"]
    ];
    // exercise every bounded maintenance email state
    for (const [notification, expected] of cases) {
      server.maintenance = maintenanceReport(notification);
      await page.evaluate(async () => window.loadMaintenance());
      assert.match(await page.locator("#maintenance-email-notification").textContent(), new RegExp(`^${expected}`));
      assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "draft.example");
    }
    server.maintenance = {
      ...maintenanceReport({ state: "unknown" }),
      status: "failed",
      os_schedule: "<img src=x onerror=alert(1)>",
      application_policy: "<script>alert(1)</script>",
      disk_free_percent: null,
      reboot_required: null,
      images: [],
      map_status: "unknown"
    };
    await page.evaluate(async () => window.loadMaintenance());
    assert.equal(await page.locator("#maintenance-state").textContent(), "Review failed");
    assert.match(await page.locator("#maintenance-summary").textContent(), /failed and needs operator attention/i);
    assert.equal(await page.locator(".maintenance-panel img, .maintenance-panel script").count(), 0);
    assert.equal(await page.locator("#maintenance-schedule").textContent(), "<img src=x onerror=alert(1)>");
    assert.equal(await page.locator("#alerts-smtp-host").inputValue(), "draft.example");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 1, `mobile page overflows by ${overflow}px`);
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(consoleErrors, []);
    // capture an opt-in review artifact
    if (process.env.ADSB_UI_SCREENSHOT_PATH) {
      await page.screenshot({ path: process.env.ADSB_UI_SCREENSHOT_PATH, fullPage: true });
    }
  } finally {
    await closeScenario(page, server);
  }
}

const tests = [
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
  ["override remove names remain unique", testOverrideAccessibleNames],
  ["maintenance rendering is safe and mobile", testMaintenanceRenderingAndMobile]
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
