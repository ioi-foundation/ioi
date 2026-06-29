#!/usr/bin/env node
// Behavioral contract test — source-owned Add connection surface (/connections/add).
// Asserts the native daemon connector contract (protocol-native: no upstream wire), the typed
// add forms (MCP = name+url; bearer = name+base_url+tool+token), an honest daemon-backed register
// (POST body shapes + the /oauth/discover and /credential follow-ups), the success receipt from
// the daemon's own record, and the error state. Deterministic via route mocking — no state mutated.
//
// Requires the vite dev server on :1420 with /connections/add wired to ConnectionAddView.
// Run: node apps/hypervisor/tests/connection-add.contract.mjs
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://127.0.0.1:1420";
const fails = [];
const ok = (name) => console.log(`  ✓ ${name}`);
const bad = (name, detail) => { fails.push(name); console.error(`  ✗ ${name}${detail ? " — " + detail : ""}`); };

const browser = await chromium.launch();

// `regFail` makes the connector register fail (to exercise the error path).
async function withPage({ regFail } = {}, fn) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark" });
  const page = await ctx.newPage();
  const seen = [];
  const calls = []; // { path, body }
  await page.route("**/v1/**", (route) => {
    const req = route.request();
    const path = req.url().replace(/^https?:\/\/[^/]+/, "");
    seen.push(path);
    if (req.method() === "POST") {
      let body = {};
      try { body = JSON.parse(req.postData() || "{}"); } catch { /* */ }
      calls.push({ path, body });
      // /credential and /oauth/discover are sub-paths of /connectors — match those first.
      if (path.includes("/credential")) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, auth_posture: "token-lease:bound" }) });
      if (path.includes("/oauth/discover")) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) });
      if (path.includes("/hypervisor/connectors")) {
        if (regFail) return route.fulfill({ status: 502, contentType: "application/json", body: JSON.stringify({ ok: false, reason: "daemon unavailable" }) });
        const bound = body.kind === "http"; // bearer connectors are then sealed; mcp stay unbound until connect
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, connector: { connector_id: "conn_test", name: body.name, service: body.service, kind: body.kind, base_url: body.base_url, auth_posture: bound ? "token-lease:bound" : "token-lease:unbound" } }) });
      }
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/api/**", (route) => { seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, "")); route.fulfill({ status: 404, body: "" }); });
  await fn(page, seen, calls);
  await ctx.close();
}

// --- Test A: MCP form landmarks (default type) + no upstream-wire bridge ---
await withPage({}, async (page, seen) => {
  await page.goto(`${BASE}/connections/add?type=mcp`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  const m = await page.evaluate(() => ({
    pageL: !!document.querySelector("[data-testid=connection-add-page]"),
    back: !!document.querySelector("[data-testid=connection-add-back]"),
    tabs: document.querySelectorAll("[data-testid^=connection-add-tab-]").length,
    mcpForm: !!document.querySelector("[data-testid=connection-add-form-mcp]"),
    name: !!document.querySelector("[data-testid=mcp-name]"),
    url: !!document.querySelector("[data-testid=mcp-url]"),
  }));
  m.pageL ? ok("renders connection-add-page landmark") : bad("connection-add-page landmark");
  m.back ? ok("back link present") : bad("back link");
  m.tabs === 2 ? ok("2 type tabs (mcp/bearer)") : bad("type tabs", `got ${m.tabs}`);
  m.mcpForm && m.name && m.url ? ok("MCP form fields (name + url)") : bad("MCP form fields");
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: bearer form via ?type=bearer ---
await withPage({}, async (page) => {
  await page.goto(`${BASE}/connections/add?type=bearer`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  const m = await page.evaluate(() => ({
    bearerForm: !!document.querySelector("[data-testid=connection-add-form-bearer]"),
    name: !!document.querySelector("[data-testid=bearer-name]"),
    baseUrl: !!document.querySelector("[data-testid=bearer-base-url]"),
    tool: !!document.querySelector("[data-testid=bearer-tool]"),
    token: !!document.querySelector("[data-testid=bearer-token]"),
  }));
  m.bearerForm && m.name && m.baseUrl && m.tool && m.token ? ok("bearer form fields (name + base_url + tool + token)") : bad("bearer form fields", JSON.stringify(m));
});

// --- Test C: MCP submit → register + oauth/discover, success receipt ---
await withPage({}, async (page, seen, calls) => {
  await page.goto(`${BASE}/connections/add?type=mcp`, { waitUntil: "networkidle" });
  await page.waitForTimeout(300);
  await page.fill("[data-testid=mcp-name]", "Linear");
  await page.fill("[data-testid=mcp-url]", "https://mcp.linear.app/mcp");
  await page.click("[data-testid=connection-add-submit]");
  await page.waitForTimeout(500);
  const reg = calls.find((c) => c.path.includes("/hypervisor/connectors") && !c.path.includes("/oauth") && !c.path.includes("/credential"));
  reg ? ok("POSTs /v1/hypervisor/connectors") : bad("POST connectors", "not requested");
  reg && reg.body.kind === "mcp" && reg.body.name === "Linear" && reg.body.base_url === "https://mcp.linear.app/mcp" ? ok("MCP register body shape (kind=mcp, name, base_url)") : bad("MCP register body", JSON.stringify(reg?.body));
  calls.some((c) => c.path.includes("/oauth/discover")) ? ok("follows up with /oauth/discover") : bad("oauth discover follow-up");
  (await page.locator("[data-testid=connection-add-success]").count()) ? ok("renders success receipt") : bad("success receipt");
});

// --- Test D: bearer submit → register + /credential seal ---
await withPage({}, async (page, seen, calls) => {
  await page.goto(`${BASE}/connections/add?type=bearer`, { waitUntil: "networkidle" });
  await page.waitForTimeout(300);
  await page.fill("[data-testid=bearer-name]", "Linear API");
  await page.fill("[data-testid=bearer-base-url]", "https://api.linear.app");
  await page.fill("[data-testid=bearer-tool]", "create_issue");
  await page.fill("[data-testid=bearer-token]", "secret-token");
  await page.click("[data-testid=connection-add-submit]");
  await page.waitForTimeout(500);
  const reg = calls.find((c) => c.path.endsWith("/hypervisor/connectors"));
  reg && reg.body.kind === "http" && Array.isArray(reg.body.allowed_tools) && reg.body.allowed_tools[0]?.name === "create_issue" ? ok("bearer register body shape (kind=http, allowed_tools)") : bad("bearer register body", JSON.stringify(reg?.body));
  const cred = calls.find((c) => c.path.includes("/credential"));
  cred && cred.body.token === "secret-token" ? ok("seals token via /credential") : bad("credential seal");
  (await page.locator("[data-testid=connection-add-success]").count()) ? ok("renders success receipt (connected)") : bad("success receipt");
});

// --- Test E: register failure → honest error state (no fabricated success) ---
await withPage({ regFail: true }, async (page) => {
  await page.goto(`${BASE}/connections/add?type=mcp`, { waitUntil: "networkidle" });
  await page.waitForTimeout(300);
  await page.fill("[data-testid=mcp-name]", "X");
  await page.fill("[data-testid=mcp-url]", "https://mcp.x/mcp");
  await page.click("[data-testid=connection-add-submit]");
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=connection-add-error]").count()) ? ok("daemon error surfaces (no fabricated success)") : bad("error state");
  (await page.locator("[data-testid=connection-add-success]").count()) === 0 ? ok("no success receipt on failure") : bad("false success on failure");
});

await browser.close();
if (fails.length) { console.error(`\nconnection-add contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\nconnection-add contract PASSED.");
