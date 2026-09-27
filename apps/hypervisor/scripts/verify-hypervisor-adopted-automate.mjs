#!/usr/bin/env node
// THE ADOPTED AUTOMATE WIZARD CREATES A HYPERVISOR AUTOMATION (R-241 seed depth, ADR 0056 P3 cut 3b).
//
// The reference Automate app is the seed: it boots from the LOCAL reference mirror (never vendored — the
// repository is public) through the /__apps/monitors lane, and the serve answers its reads and writes
// from the Hypervisor's planes. This proves, against an ISOLATED daemon + serve, that a person can walk
// the adopted wizard end to end over daemon truth: a function released through Ontology / Functions' own
// forms is offered by the wizard's Function effect with its typed inputs; the Save dialog offers the
// caller's project, validates the name against their automations and reports no issue; Save admits ONE
// automation through the automations plane — a cron schedule in its named zone, one function step pinned
// to the released revision's content hash — and lands on its detail page; Run now on the product's own
// automation page runs that exact revision and the step records Passed; and no operation the app sent
// went unanswered.
//
// Browser writes are the adopted app's own controls; product writes submit the forms the surface
// rendered. Exit: 0 pass · 1 fail · 2 blocked (no daemon binary, no local reference mirror, or the
// mirror server is not reachable — the seed cannot boot, which is not a pass).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   IOI_HARVEST_CAPTURE_URL       default http://127.0.0.1:9225 (the local mirror server)
//   node apps/hypervisor/scripts/verify-hypervisor-adopted-automate.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
    await sleep(400);
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-automate-"));
let daemon = null, serve = null, DAEMON = "", SERVE = "", COOKIE = "";

// The form the page RENDERED that posts to `action`: its fields with the values a browser would send
// untouched (a checkbox only when checked, each select's selected option), and what each choice offers.
// The form the page RENDERED that posts to `action` — when `id` is given, the one whose hidden `id` is
// that check (every row renders its own Evaluate / Pause / Archive form to the same action).
const unesc = (s) => String(s).replace(/&quot;/gu, '"').replace(/&#39;/gu, "'").replace(/&gt;/gu, ">").replace(/&lt;/gu, "<").replace(/&amp;/gu, "&");
const attrOf = (tag, name) => { const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`, "u")); return m ? unesc(m[1]) : null; };
function renderedForm(html, action, id = null) {
  let at = -1, inner = null;
  for (;;) {
    at = html.indexOf(`action="${action}"`, at + 1);
    if (at < 0) break;
    const candidate = html.slice(html.lastIndexOf("<form", at), html.indexOf("</form>", at));
    if (id === null || candidate.includes(`name="id" value="${id}"`)) inner = candidate;
    if (inner && id !== null) break;
  }
  if (inner === null) return null;
  const names = new Set([...inner.matchAll(/\bname="([^"]+)"/gu)].map((m) => m[1]));
  const values = [];
  const options = {};
  for (const [tag] of inner.matchAll(/<input\b[^>]*>/gu)) {
    const name = attrOf(tag, "name");
    const type = (attrOf(tag, "type") || "text").toLowerCase();
    if (!name || ["submit", "button", "file", "image", "reset"].includes(type)) continue;
    if (type === "checkbox" || type === "radio") {
      (options[name] ||= new Set()).add(attrOf(tag, "value") ?? "on");
      if (!/\bchecked\b/u.test(tag)) continue;
    }
    values.push([name, attrOf(tag, "value") ?? (type === "checkbox" ? "on" : "")]);
  }
  for (const m of inner.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/gu)) {
    const name = attrOf(m[1], "name");
    const offered = [...m[2].matchAll(/<option\b([^>]*)>/gu)].map((o) => o[1]);
    const chosen = offered.find((o) => /\bselected\b/u.test(o)) ?? offered[0];
    if (name) options[name] = new Set(offered.map((o) => attrOf(o, "value") ?? ""));
    if (name && chosen !== undefined) values.push([name, attrOf(chosen, "value") ?? ""]);
  }
  for (const m of inner.matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gu)) {
    const name = attrOf(m[1], "name");
    if (name) values.push([name, unesc(m[2])]);
  }
  return { names, values, options };
}

const page = async (route, { anonymous = false } = {}) => {
  const r = await fetch(`${SERVE}${route}`, { headers: { accept: "text/html", ...(anonymous ? {} : { cookie: COOKIE }) }, redirect: "manual" }).catch(() => null);
  return { status: r?.status ?? 0, text: r ? await r.text() : "", location: r?.headers.get("location") || "", headers: r?.headers };
};
const daemonRead = async (route) => fetch(`${DAEMON}${route}`, { headers: { cookie: COOKIE } })
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));

/**
 * Submit the rendered form with only what a person would fill in. A form that is not on the page, a
 * field it does not render, or a choice it does not offer is a FAILED STEP, never a hand-built post.
 */
async function submit(route, action, fields, { id = null, postAnonymously = false } = {}) {
  const from = await page(route);
  const form = renderedForm(from.text, action, id);
  if (!form) return { error: `no form posting to ${action}${id ? ` for ${id}` : ""} is rendered at ${route} (HTTP ${from.status})` };
  const missing = Object.keys(fields).filter((n) => !form.names.has(n));
  if (missing.length) return { error: `the form at ${route} renders no field ${missing.join(", ")}` };
  const unoffered = Object.entries(fields).filter(([n, v]) => form.options[n] && !form.options[n].has(String(v)));
  if (unoffered.length) return { error: `the form at ${route} offers no option ${unoffered.map(([n, v]) => `${n}=${v}`).join(", ")}` };
  const body = new URLSearchParams();
  for (const [n, v] of form.values) if (!(n in fields)) body.append(n, v);
  for (const [n, v] of Object.entries(fields)) body.append(n, v);
  const r = await fetch(`${SERVE}${action}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "text/html", ...(postAnonymously ? {} : { cookie: COOKIE }) },
    body: body.toString(), redirect: "manual",
  }).catch(() => null);
  const location = r?.headers.get("location") || "";
  return { status: r?.status ?? 0, location, q: new URLSearchParams(location.split("?")[1]?.split("#")[0] || ""), text: r ? await r.text() : "" };
}
const MIRROR_PAGE = path.join(ROOT, "internal-docs", "reverse-engineering", "palantir", "public", "workspace", "object-monitoring", "index.html");
const CAPTURE = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
if (!fs.existsSync(MIRROR_PAGE)) { console.error(`BLOCKED: no local reference mirror at ${MIRROR_PAGE}`); process.exit(2); }
if (!(await fetch(`${CAPTURE}/workspace/object-monitoring/`).then((r) => r.ok).catch(() => false))) { console.error(`BLOCKED: the local mirror server is not reachable at ${CAPTURE}`); process.exit(2); }
const SOURCE = "import json, sys\nprint(json.dumps(json.load(sys.stdin)['amount'] * 2))\n";

async function run() {
  const daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = token ? await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, password: "adopted-automate-bootstrap-v1", email: "adopted@ioi.local" }),
  }).then((r) => r.json()).catch(() => ({})) : {};
  COOKIE = boot.session_token ? `ioi_session=${boot.session_token}` : "";
  ok("operator bootstrap yields an authenticated session", COOKIE.startsWith("ioi_session=ioi_sess_"), COOKIE.slice(0, 24));

  const servePort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_HARVEST_CAPTURE_URL: CAPTURE },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/__apps/monitors`, 30000);
  const tag = `aa${Date.now().toString(36).slice(-5)}`;

  // ---- 1. a released function and a project, through the product's own surfaces --------------------
  const project = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ name: `proj-${tag}`, initializer: { specs: [{ git: { remoteUri: "https://example.invalid/adopted/run.git" } }] } }) }).then((r) => r.json()).catch(() => ({}));
  const declared = await submit("/ontology/functions", "/__ioi/ontology/functions/new", { display_name: `Double ${tag}`, api_name: "doubleAmount", version: "1.0.0", input_name_0: "amount", input_type_0: "integer", input_required_0: "on", output_type: "integer", runtime: "python3", source: SOURCE });
  const fnId = declared.q?.get("function") || "";
  const released = fnId ? await submit(`/ontology/functions?function=${fnId}`, "/__ioi/ontology/functions/release", {}) : { error: "no function" };
  ok("a function is declared and released through Ontology / Functions' own forms, and a project exists",
    released.q?.get("ok") === "1" && !!project.project?.id, `${fnId || declared.q?.get("note")} · ${released.q?.get("note") || released.error} · project ${project.project?.id || "none"}`);

  // ---- 2. the adopted wizard, in a browser --------------------------------------------------------------
  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const pg = await ctx.newPage();
    await pg.goto(`${SERVE}/__apps/monitors`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(8000);
    let opened = false;
    try { await pg.getByText("New automation", { exact: true }).first().click({ timeout: 8000 }); opened = true; } catch { /* named below */ }
    await pg.waitForTimeout(5000);
    try { await pg.getByText("Time", { exact: true }).first().click({ timeout: 6000 }); } catch { /* the condition step names it */ }
    await pg.waitForTimeout(2000);
    await pg.getByText("Effects", { exact: true }).first().click({ timeout: 6000 }).catch(() => {});
    await pg.waitForTimeout(2000);
    const fnRow = pg.locator("div", { has: pg.getByText("Function", { exact: true }) }).filter({ has: pg.getByRole("button", { name: "Add" }) }).last();
    await fnRow.getByRole("button", { name: "Add" }).click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(3000);
    await pg.getByText("Select a function", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(4000);
    const options = pg.locator('[role="option"], [role="menuitem"], .bp5-menu-item, .bp4-menu-item');
    const offered = (await options.allInnerTexts().catch(() => [])).map((t) => t.replace(/\s+/g, " "));
    await options.filter({ hasText: `Double ${tag}` }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(5000);
    const panel = ((await pg.evaluate(() => document.body.innerText)).split("Configure Function effect")[1] || "").replace(/\s+/g, " ");
    ok("the adopted wizard's Function effect offers the released function and shows its typed input and version",
      opened && offered.some((t) => t.includes(`Double ${tag}`)) && /amount\s*• integer/u.test(panel) && /1\.0\.0/u.test(panel),
      `wizard ${opened} · offered ${offered.length}: ${offered.slice(0, 3).join(" | ")} · panel ${panel.slice(0, 120)}`);
    for (let step = 0; step < 4; step++) {
      const text = await pg.evaluate(() => document.body.innerText);
      if (/Create automation/.test(text) && /\bSummary\b[\s\S]*\bCondition\b/.test(text) && step > 0) break;
      await pg.getByRole("button", { name: "Next" }).first().click({ timeout: 4000 }).catch(() => {});
      await pg.waitForTimeout(2500);
    }
    await pg.getByRole("button", { name: "Create automation", exact: true }).last().click({ timeout: 5000 }).catch(() => {});
    await pg.waitForTimeout(4000);
    await pg.getByPlaceholder("Enter a name…").first().fill(`auto-${tag}`, { timeout: 5000 }).catch(() => {});
    await pg.waitForTimeout(7000);
    const dialog = (await pg.locator(".bp5-dialog, .bp4-dialog, [role=dialog]").last().innerText().catch(() => "")).replace(/\s+/g, " ");
    ok("the Save dialog offers the caller's project as the location, reports no issue, and enables Save",
      dialog.includes(`proj-${tag}`) && /No action required/u.test(dialog) && await pg.getByRole("button", { name: "Save", exact: true }).last().isEnabled().catch(() => false),
      dialog.slice(0, 220));
    await pg.getByRole("button", { name: "Save", exact: true }).last().click({ timeout: 5000 }).catch(() => {});
    await pg.waitForTimeout(8000);
    const landed = pg.url().replace(SERVE, "");
    const autos = (await daemonRead("/v1/hypervisor/automations")).body?.automations ?? [];
    const made = autos.find((a) => a.name === `auto-${tag}`) || {};
    const fnDetail = (await daemonRead(`/v1/hypervisor/functions/${fnId}`)).body || {};
    const r1 = (fnDetail.revisions || []).find((r) => r.ordinal === 1) || {};
    ok("Save admits ONE automation in the project: a cron schedule in its named zone and one function step pinned to the released revision's content hash",
      autos.filter((a) => a.name === `auto-${tag}`).length === 1 && made.project_id === project.project?.id && made.schedule_spec?.type === "cron"
        && /\//u.test(made.schedule_spec?.timezone || "") && made.steps?.length === 1 && made.steps[0].kind === "function"
        && made.steps[0].function_revision_ref === r1.revision_ref && made.steps[0].content_hash === r1.content_hash,
      `${made.automation_id || "no automation"} · ${JSON.stringify(made.schedule_spec || {})} · ${JSON.stringify(made.steps?.[0] || {}).slice(0, 200)}`);
    ok("the adopted app lands on the new automation's own detail page, which names it",
      landed.includes("/automation/ri.object-sentinel.main.monitor.") && (await pg.evaluate(() => document.body.innerText)).includes(`auto-${tag}`),
      landed.slice(0, 120));
    const unbound = (await fetch(`${SERVE}/__ioi/adopted-seeds/unbound`, { headers: { cookie: COOKIE } }).then((r) => r.json()).catch(() => ({}))).automate || {};
    ok("no operation the adopted app sent went unanswered", Object.keys(unbound).length === 0, JSON.stringify(unbound).slice(0, 200));

    // ---- 3. Run now on the product's own automation page --------------------------------------------------
    const ran = made.automation_id ? await submit(`/__ioi/automations/${made.automation_id}`, `/__ioi/automations/${made.automation_id}/run`, {}) : { error: "no automation" };
    const exec = ((await daemonRead(`/v1/hypervisor/automations/${made.automation_id}/runs`)).body?.runs ?? [])[0] || {};
    const step = exec.step_results?.[0] || {};
    ok("Run now on the product's automation page runs that exact revision and the step records Passed",
      [302, 303].includes(ran.status) && exec.status === "done" && step.kind === "function" && step.output?.outcome === "passed" && step.output?.function_revision_ref === r1.revision_ref,
      `run ${ran.status ?? ran.error} · ${exec.status || "no execution"} ${step.output?.outcome || step.output?.error || ""}`);
  } finally {
    await browser.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "adopted-automate", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
