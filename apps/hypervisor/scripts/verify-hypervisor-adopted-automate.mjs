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
// to the released revision's content hash — and lands on its detail page, which shows that Function effect;
// /automations opens the adopted app under our rail; the app reaches the local mirror only for the
// reference's chrome reads (never its recorded directory or data); Run now on the product's own automation
// page runs that exact revision and the step records Passed; the adopted editor renames the automation and
// changes its function input in one Save; a manual command-step automation's page renders with its step
// shown and its owner named, and the editor does not save it; and no operation the app sent went unanswered.
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
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_HARVEST_CAPTURE_URL: CAPTURE, IOI_ADOPTED_SURFACES: "1" },
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
    // Every response the serve did NOT answer from Hypervisor truth carries x-ioi-mirror-passthrough.
    const passthroughs = new Set();
    pg.on("response", (resp) => {
      if (resp.headers()["x-ioi-mirror-passthrough"] !== "1") return;
      passthroughs.add(`${resp.request().method()} ${new URL(resp.url()).pathname.replace(/ri\.[a-z-]+\.main\.[a-z-]+\.[0-9a-f-]{36}/gu, "<rid>")}`);
    });
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
    await pg.waitForTimeout(3000);
    if (process.env.IOI_VERIFIER_SHOTS) await pg.screenshot({ path: path.join(process.env.IOI_VERIFIER_SHOTS, "adopted-detail.png"), fullPage: true });
    const detailText = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/g, " ");
    ok("the adopted app lands on the new automation's own detail page, which names it and shows its Function effect: the released function, its version and its one input",
      landed.includes("/automation/ri.object-sentinel.main.monitor.") && detailText.includes(`auto-${tag}`) && detailText.includes(`Double ${tag}`) && /1\.0\.0/u.test(detailText) && /\(1 input\)/u.test(detailText),
      `${landed.slice(0, 90)} · effect ${detailText.includes(`Double ${tag}`)} · version ${/1\.0\.0/u.test(detailText)} · inputs ${/\(1 input\)/u.test(detailText)}`);
    const unbound = (await fetch(`${SERVE}/__ioi/adopted-seeds/unbound`, { headers: { cookie: COOKIE } }).then((r) => r.json()).catch(() => ({}))).automate || {};
    ok("no operation the adopted app sent went unanswered", Object.keys(unbound).length === 0, JSON.stringify(unbound).slice(0, 200));

    // ---- Automations opens the adopted app: its canonical route, a deep link, and its own URLs on reload
    const top = await fetch(`${SERVE}/automations`, { headers: { accept: "text/html", cookie: COOKIE }, redirect: "manual" });
    const deep = await fetch(`${SERVE}/automations?automation=${made.automation_id}`, { headers: { accept: "text/html", cookie: COOKIE }, redirect: "manual" });
    await pg.goto(`${SERVE}/workspace/object-monitoring/automations`, { waitUntil: "domcontentloaded" });
    await pg.waitForTimeout(8000);
    const listed = (await pg.evaluate(() => document.body.innerText)).includes(`auto-${tag}`);
    const referenceSidebar = await pg.evaluate(() => { const el = document.getElementById("workspace-sidebar"); return !!el && el.getBoundingClientRect().width > 0; });
    const ourRail = await pg.evaluate(() => !!document.querySelector(".og-grail a[href='/ai']"));
    ok("/automations opens the adopted app (a deep link opens that automation), its own URLs reload in place, and our rail stands where the reference's sidebar was",
      top.status === 302 && top.headers.get("location") === "/workspace/object-monitoring/" && (deep.headers.get("location") || "").includes(`/automation/ri.object-sentinel.main.monitor.`)
        && listed && !referenceSidebar && ourRail,
      `${top.status} ${top.headers.get("location")} · deep ${deep.headers.get("location")} · reload lists ours ${listed} · reference sidebar ${referenceSidebar} · our rail ${ourRail}`);

    // ---- a MANUAL automation (a command step, no schedule) has no condition in the reference's
    // vocabulary: its detail must render, say so ("Unknown condition", never "Running on schedule" or a
    // cron the app cannot describe), and name its owner from the Hypervisor's principal. The fixture is
    // posted to the daemon: the adopted wizard cannot make one, and this assertion is about the READ.
    const manual = await fetch(`${DAEMON}/v1/hypervisor/automations`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ project_ref: project.project?.id, name: `manual-${tag}`, steps: [{ kind: "command", command: "echo manual" }] }) }).then((r) => r.json()).catch(() => ({}));
    const operator = (await daemonRead("/v1/hypervisor/auth/whoami")).body?.principal?.name || "";
    await pg.goto(`${SERVE}/automations?automation=${manual.automation?.automation_id}`, { waitUntil: "domcontentloaded" });
    await pg.waitForTimeout(8000);
    const manualText = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/g, " ");
    const ownerRow = (manualText.match(/Owner (?:[A-Z]{1,2} )?(.{0,40}?) Created by/u) || [])[1] || "";
    ok("a manual automation's adopted detail renders, reads \"Unknown condition\" rather than a schedule, shows its command step as an effect (never \"no effects\"), and names its owner from the Hypervisor's principal",
      manualText.includes(`manual-${tag}`) && !/An error has occurred/u.test(manualText) && /Unknown condition/u.test(manualText) && !/Running on schedule|Automation runs/u.test(manualText)
        && /Unknown effect/u.test(manualText) && !/There are no effects configured/u.test(manualText) && !!operator && ownerRow.includes(operator),
      `error card ${/An error has occurred/u.test(manualText)} · unknown condition ${/Unknown condition/u.test(manualText)} · step shown ${/Unknown effect/u.test(manualText)} · owner "${ownerRow}" (operator "${operator}")`);

    // The mirror still answers the reference's CHROME reads (sessions, beacons, release notes, favorites,
    // registry actions, lifecycle status, assist availability, view events) and nothing else: a new
    // passthrough is a new lane reaching recorded tenant answers, and fails here until it is bound.
    const CHROME_PASSTHROUGHS = new Set([
      "GET /aip-assist/api/chat/checkAvailability", "GET /compass/api/registry/actions", "GET /multipass/api/sessions/definitions/current",
      "GET /multipass/api/sessions/selection", "GET /workspace/api/lifecycleStatusByApplication", "POST /documentation/api/v2/release-notes/pagination",
      "POST /log-receiver/api/beacon", "POST /people/api/eventsink/create-events", "POST /people/api/personal/get-favorites",
    ]);
    const unexpected = [...passthroughs].filter((p) => !CHROME_PASSTHROUGHS.has(p));
    ok("the adopted app reaches the local mirror only for the reference's chrome reads — its user directory, functions, projects, automations, create and validation answer from the Hypervisor",
      unexpected.length === 0 && passthroughs.size > 0, unexpected.length ? `unexpected: ${unexpected.join(" · ")}` : `${passthroughs.size} chrome reads`);

    // ---- 3. Run now on the product's own automation page --------------------------------------------------
    const ran = made.automation_id ? await submit(`/__ioi/automations/${made.automation_id}`, `/__ioi/automations/${made.automation_id}/run`, {}) : { error: "no automation" };
    const exec = ((await daemonRead(`/v1/hypervisor/automations/${made.automation_id}/runs`)).body?.runs ?? [])[0] || {};
    const step = exec.step_results?.[0] || {};
    ok("Run now on the product's automation page runs that exact revision and the step records Passed",
      [302, 303].includes(ran.status) && exec.status === "done" && step.kind === "function" && step.output?.outcome === "passed" && step.output?.function_revision_ref === r1.revision_ref,
      `run ${ran.status ?? ran.error} · ${exec.status || "no execution"} ${step.output?.outcome || step.output?.error || ""}`);

    // ---- 4. Edit in the adopted wizard: rename (compass) and a new input value (updateMonitor) in ONE Save
    await pg.goto(`${SERVE}/automations?automation=${made.automation_id}`, { waitUntil: "domcontentloaded" });
    await pg.waitForTimeout(8000);
    const editSteps = [];
    try {
      await pg.getByRole("button", { name: /^Edit/u }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(7000);
      await pg.getByText(`Double ${tag}`, { exact: true }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(4000);
      await pg.getByText(/^amount/u).first().locator("xpath=following::input[1]").fill("21", { timeout: 8000 });
      await pg.keyboard.press("Tab");
      await pg.waitForTimeout(1500);
      editSteps.push("input");
      await pg.getByText("Summary", { exact: true }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(3000);
      await pg.locator(`input[value="auto-${tag}"]`).first().fill(`auto-${tag}-edited`, { timeout: 8000 });
      await pg.keyboard.press("Tab");
      await pg.waitForTimeout(2500);
      editSteps.push("name");
      await pg.getByRole("button", { name: "Save automation" }).last().click({ timeout: 8000 });
      await pg.waitForTimeout(8000);
      editSteps.push("saved");
    } catch (e) { editSteps.push(`stopped: ${String(e.message).split("\n")[0].slice(0, 120)}`); }
    const edited = (await daemonRead("/v1/hypervisor/automations")).body?.automations?.find((a) => a.automation_id === made.automation_id) || {};
    ok("Edit in the adopted wizard renames the automation and changes its function input in one Save — same project, same pinned revision — and lands back on its page",
      edited.name === `auto-${tag}-edited` && edited.steps?.length === 1 && edited.steps[0].inputs?.amount === 21 && edited.steps[0].function_revision_ref === r1.revision_ref
        && edited.steps[0].content_hash === r1.content_hash && edited.project_id === project.project?.id && /\/main\/view\//u.test(pg.url()),
      `${editSteps.join(" → ")} · name ${edited.name} · amount ${edited.steps?.[0]?.inputs?.amount} · ${pg.url().replace(SERVE, "").slice(0, 90)}`);

    // An automation the editor cannot fully show (a command step, no schedule) is never saved from it. The
    // app already disables Save for it (no effect, no schedule); the translation's own refusal of hidden
    // steps is pinned by test:adopted-seeds, since this walk cannot tell the two apart.
    await pg.goto(`${SERVE}/automations?automation=${manual.automation?.automation_id}`, { waitUntil: "domcontentloaded" });
    await pg.waitForTimeout(8000);
    let saveDisabled = null;
    try {
      await pg.getByRole("button", { name: /^Edit/u }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(7000);
      await pg.getByText("Summary", { exact: true }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(4000);
      saveDisabled = await pg.evaluate(() => { const b = [...document.querySelectorAll("button")].find((x) => /Save automation/u.test(x.innerText)); return b ? b.disabled : null; });
    } catch { /* recorded as null */ }
    const manualAfter = (await daemonRead("/v1/hypervisor/automations")).body?.automations?.find((a) => a.automation_id === manual.automation?.automation_id) || {};
    ok("the adopted editor does not save a manual command-step automation — Save stays disabled and the record is untouched",
      saveDisabled === true && manualAfter.steps?.length === 1 && manualAfter.steps[0].kind === "command" && manualAfter.updated_at === manual.automation?.updated_at,
      `save disabled ${saveDisabled} · steps ${JSON.stringify(manualAfter.steps || []).slice(0, 80)} · updated ${manualAfter.updated_at === manual.automation?.updated_at ? "no" : "YES"}`);

    // ---- 5. The detail page's own writes: its description, and Pause — whose popover promises that
    // in-flight executions are canceled mid-run — then Resume. The slow fixture and its run are posted to
    // the daemon (the run is the thing being paused, not the lane under test).
    const slow = await fetch(`${DAEMON}/v1/hypervisor/automations`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ project_ref: project.project?.id, name: `slow-${tag}`, steps: [{ kind: "command", command: "sleep 8; echo SLOW_FIRST" }, { kind: "command", command: "echo SLOW_SECOND" }] }) }).then((r) => r.json()).catch(() => ({}));
    const slowId = slow.automation?.automation_id || "";
    const writes = [];
    await pg.goto(`${SERVE}/automations?automation=${slowId}`, { waitUntil: "domcontentloaded" });
    await pg.waitForTimeout(8000);
    let inFlight = null;
    let slowRun = null;
    try {
      await pg.getByText("Edit description", { exact: true }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(800);
      await pg.keyboard.type(`Paused by the verifier ${tag}`);
      await pg.getByText("Automation flow", { exact: true }).first().click({ timeout: 5000 });
      await pg.waitForTimeout(3000);
      writes.push("description");
      slowRun = fetch(`${DAEMON}/v1/hypervisor/automations/${slowId}/runs`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: "{}" }).catch(() => null);
      for (let attempt = 0; attempt < 60 && !inFlight; attempt++) {
        await sleep(500);
        inFlight = ((await daemonRead(`/v1/hypervisor/automations/${slowId}/runs`)).body?.runs || []).find((r) => r.status === "running") || null;
      }
      await pg.getByRole("button", { name: /^Active/u }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(1200);
      await pg.locator(".bp6-popover-content").getByRole("button", { name: /Pause/u }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(4000);
      writes.push("paused");
    } catch (e) { writes.push(`stopped: ${String(e.message).split("\n")[0].slice(0, 120)}`); }
    await slowRun;
    const pausedSpec = (await daemonRead("/v1/hypervisor/automations")).body?.automations?.find((a) => a.automation_id === slowId) || {};
    const pausedExec = inFlight ? ((await daemonRead(`/v1/hypervisor/automation-executions/${inFlight.execution_id}`)).body?.execution || {}) : {};
    let resumedEnabled = null;
    try {
      await pg.getByRole("button", { name: /^Paused/u }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(1200);
      await pg.locator(".bp6-popover-content").getByRole("button", { name: /Resume/u }).first().click({ timeout: 8000 });
      await pg.waitForTimeout(4000);
      resumedEnabled = ((await daemonRead("/v1/hypervisor/automations")).body?.automations?.find((a) => a.automation_id === slowId) || {}).enabled;
    } catch (e) { writes.push(`resume: ${String(e.message).split("\n")[0].slice(0, 120)}`); }
    ok("the adopted page's own writes land: the description is the automation's, Pause disables it and stops its in-flight run before the next step (as its popover promises), and Resume enables it again",
      pausedSpec.description === `Paused by the verifier ${tag}` && pausedSpec.enabled === false && !!inFlight && pausedExec.status === "stopped"
        && pausedExec.step_results?.[1]?.status === "skipped" && resumedEnabled === true,
      `${writes.join(" → ")} · description ${JSON.stringify(pausedSpec.description)} · paused ${pausedSpec.enabled === false} · run ${inFlight ? pausedExec.status : "never running"} ${JSON.stringify((pausedExec.step_results || []).map((s) => s.status))} · resumed ${resumedEnabled}`);
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
