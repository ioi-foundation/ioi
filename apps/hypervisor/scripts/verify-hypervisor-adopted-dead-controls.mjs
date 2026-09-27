#!/usr/bin/env node
// A LIVE-LOOKING CONTROL ON AN ADOPTED APP MUST DO SOMETHING (R-240 Arm A, R-241 seed depth).
//
// check:dead-controls clicks every control on the OWNED surfaces, and counts `/__apps/*` apart as reference
// lanes: its own serve runs without IOI_ADOPTED_SURFACES, so the adopted apps the owner actually opens —
// Automate at /automations, Pipeline Builder at /data/recipes — were clicked by nothing. The first sweep of
// the adopted Pipeline Builder found what that blind spot hid: its reference sidebar's Home, Files and
// Ontology links landed on our not-found page (fixed: our rail stands in the sidebar's place).
//
// This gate is the same census over the adopted apps, on an ISOLATED daemon + serve with seeded truth: each
// live-looking control (check:dead-controls' own enumerator and classifier, lib/dead-control-page.mjs and
// lib/dead-control-census.mjs) is exercised the way a person would — chosen, typed into, toggled, clicked —
// and judged by the single-page-app rules (signals against the page AT REST, a route a click opened must
// render). Two refinements the adopted apps need, each measured: a skip link off the viewport is exercised
// by keyboard FOCUS (it appears on focus; a click cannot reach it), and a link to the page you are on is
// "self" whether or not a trailing slash differs.
//
// THE DEFECT LIST IS PINNED EXACTLY. A control that is not alive must be one of NAMED below, each with the
// reason that survives reading; a new one is red, and a named one that becomes alive must be unpinned.
// Writes are allowed — the stack is disposable — so a control that writes is judged by what it did.
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon binary, no local reference mirror, or the mirror server is
// not reachable — the apps cannot boot, which is not a pass).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   IOI_HARVEST_CAPTURE_URL       default http://127.0.0.1:9225 (the local mirror server)
//   node apps/hypervisor/scripts/verify-hypervisor-adopted-dead-controls.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import * as LIB from "./lib/dead-control-census.mjs";
import { ENUMERATE } from "./lib/dead-control-page.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

// Each control that is NOT alive, by surface and what it is, with the reason it may stay so.
export const NAMED = Object.freeze([
  { surface: "pipeline:editor", tag: "OL", text: /^intake-normalise$/u, verdict: "dead",
    reason: "the pipeline title renames only once the editor's writes (drafts to a change set) are bound — ADR 0056 P4 cut 2d; the editor opens read-only until then" },
  { surface: "automate:detail", tag: "SPAN", text: /^Add to favorites$/u, verdict: "dead",
    reason: "the Hypervisor keeps no favorites: the favorite mutation is refused by name, and the reference app shows no message (seed-depth detail.favorite, open)" },
  { surface: "pipeline:create", tag: "INPUT", text: /^$/u, verdict: "dead",
    reason: "the name field is consumed by Create pipeline, which the form enables once a location is chosen (check:adopted-pipeline proves the typed name reaches the founding change set)" },
]);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const freePort = () => new Promise((resolve, reject) => { const srv = net.createServer(); srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); }); srv.on("error", reject); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up */ } await sleep(400); } throw new Error(`timeout waiting for ${url}`); };

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch { console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`); process.exit(2); }
const CAPTURE = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
for (const seed of ["builder", "object-monitoring"]) {
  if (!fs.existsSync(path.join(ROOT, "internal-docs", "reverse-engineering", "palantir", "public", "workspace", seed, "index.html"))) { console.error(`BLOCKED: no local reference mirror for ${seed}`); process.exit(2); }
}
if (!(await fetch(`${CAPTURE}/workspace/builder/`).then((r) => r.ok).catch(() => false))) { console.error(`BLOCKED: the local mirror server is not reachable at ${CAPTURE}`); process.exit(2); }

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-dead-"));
let daemon = null, serve = null, DAEMON = "", SERVE = "", COOKIE = "";
const daemonReq = async (method, route, body) => { const r = await fetch(`${DAEMON}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).catch(() => null); return { status: r?.status ?? 0, body: r ? await r.json().catch(() => ({})) : {} }; };

// Measured per exercise, in the page.
const PAGE = () => {
  const vis = (e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none"; };
  return { url: location.pathname + location.search + location.hash, text: document.body.innerText, overlays: [...document.querySelectorAll('[role="dialog"],[role="alertdialog"],[role="menu"],[role="listbox"],[class*="popover"]')].filter(vis).length };
};
const STATES = () => JSON.stringify([...document.querySelectorAll("*")].flatMap((e) => [...e.attributes].filter((a) => /^data-.*state$/u.test(a.name)).map((a) => `${a.name}=${a.value}`)));
const trim = (p) => String(p || "").replace(/\/+$/u, "") || "/";

async function run() {
  const daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(daemonBinary, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = token ? await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "adopted-dead-bootstrap-v1", email: "dead@ioi.local" }) }).then((r) => r.json()).catch(() => ({})) : {};
  COOKIE = boot.session_token ? `ioi_session=${boot.session_token}` : "";
  ok("operator bootstrap yields an authenticated session", COOKIE.startsWith("ioi_session=ioi_sess_"), COOKIE.slice(0, 24));
  const servePort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], { cwd: APP, env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_HARVEST_CAPTURE_URL: CAPTURE, IOI_ADOPTED_SURFACES: "1" }, stdio: ["ignore", "pipe", "pipe"] });
  await waitFor(`${SERVE}/__ioi/login`, 30000);

  // ---- seeded truth: a merged recipe family with an open successor, a founding change set; a project and
  // an automation with a command step ------------------------------------------------------------------------
  const who = (await daemonReq("GET", "/v1/hypervisor/auth/whoami")).body;
  const OWNER = (who.principal?.tenant_refs || []).find((t) => String(t).startsWith("org://"));
  const POLICY = `sha256:${"3c".repeat(32)}`;
  const ont = await daemonReq("POST", "/v1/hypervisor/ontology-versions", { owner_ref: OWNER, idempotency_key: "ad-ont", namespace: "acme-clinic", name: "patient-intake", governing_scope_ref: "domain://acme-clinic/intake", policy_hash: POLICY, entity_types: [{ term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" }], valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null } });
  const ONT1 = ont.body?.ontology_version?.ontology_id;
  const map = await daemonReq("POST", "/v1/hypervisor/connector-mapping-revisions", { owner_ref: OWNER, idempotency_key: "ad-map", family: "acme.intake-form", name: "intake-form", connector_id: "connector://google-drive", ontology_revision_ref: ONT1, source_schema_ref: "artifact://acme/intake-form/provider-schema/2026-09", target_object_model_refs: ["object-model://om_patient_intake"], field_mappings: [{ role: "key", source_field: "record_id", target_property_ref: "object-model://om_patient_intake#intake_id", source_type: "string", source_cardinality: "one" }], action_mappings: [], authority_scopes_required: ["scope:connector.google_drive.read"], redaction_policy_ref: "policy://acme-clinic/intake-redaction", evidence_required: ["evidence-contract://acme-clinic/intake-consent"], effective_policy_hash: POLICY, registry_status: "active" });
  const MAP1 = map.body?.connector_mapping?.revision_ref;
  const draft = (extra = {}) => ({ name: "intake-normalise", ontology_revision_refs: [ONT1], input_source_types: ["connector", "document"], connector_mapping_revision_refs: [MAP1], output_object_model_refs: ["object-model://om_patient_intake"], output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"], transformation_steps: ["extract", "redact", "normalize", "validate", "map"], policy_bound_data_view_refs: [], receipt_obligations: ["data_recipe_run", "transformation"], effective_policy_hash: POLICY, registry_status: "active", ...extra });
  const w = (key, extra = {}) => ({ owner_ref: OWNER, idempotency_key: key, ...extra });
  const opened = await daemonReq("POST", "/v1/hypervisor/change-sets", w("ad-open-1", { subject: { kind: "data_recipe", family: "acme.intake-normalise" }, title: "Normalise intake", draft: draft() }));
  const cs1 = String(opened.body?.change_set?.change_set_ref || "").replace("change://", "");
  for (const step of ["validate", "propose", "merge"]) await daemonReq("POST", `/v1/hypervisor/change-sets/${cs1}/${step}`, w(`ad-${step}-1`));
  await daemonReq("POST", "/v1/hypervisor/change-sets", w("ad-open-2", { subject: { kind: "data_recipe", family: "acme.intake-normalise" }, title: "Add a dedupe step", draft: draft({ transformation_steps: ["extract", "redact", "normalize", "validate", "map", "dedupe"], succession_reason: "transformation_step_change" }) }));
  await daemonReq("POST", "/v1/hypervisor/change-sets", w("ad-open-3", { subject: { kind: "data_recipe", family: "acme.claims-triage" }, title: "Claims triage", draft: { name: "claims-triage" } }));
  const project = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ name: "dead-control-project", initializer: { specs: [{ git: { remoteUri: "https://example.invalid/adopted/dead.git" } }] } }) }).then((r) => r.json()).catch(() => ({}));
  const auto = await daemonReq("POST", "/v1/hypervisor/automations", { project_ref: project.project?.id, name: "nightly-digest", steps: [{ kind: "command", command: "echo digest" }] });
  const autoId = auto.body?.automation?.automation_id || auto.body?.automation_id || null;
  const search = await fetch(`${SERVE}/graphql-gateway/api/bulk?q=PipelineLandingSearchQuery`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ operations: { 0: "query PipelineLandingSearchQuery($text: String, $pageSize: Int!) { searchResourcesV2(pageSize: $pageSize, filter: {text: $text, types: [EDDIE_PIPELINE]}) { results { resource { rid } } } }" }, requests: [{ hash: "0", name: "PipelineLandingSearchQuery", variables: { text: "intake", pageSize: 5 } }] }) }).then((r) => r.text()).catch(() => "");
  const rid = (search.match(/ri\.eddie\.main\.pipeline\.[0-9a-f-]{36}/u) || [])[0] || null;
  const main = rid ? (await fetch(`${SERVE}/eddie/api/pipelines-v2/${rid}`, { headers: { cookie: COOKIE } }).then((r) => r.json()).catch(() => ({}))).pipeline?.publishedSandboxes?.[0] : null;
  ok("PRECONDITION: a recipe pipeline (merged, with an open successor), a founding-only pipeline, a project and an automation exist",
    !!rid && !!main && !!project.project?.id && !!autoId, `pipeline ${rid} main ${main} · project ${project.project?.id} · automation ${autoId} ${auto.status}`);

  const TARGETS = [
    { key: "pipeline:landing", route: "/workspace/builder/" },
    { key: "pipeline:editor", route: `/workspace/builder/${rid}/sandbox/${main}` },
    { key: "pipeline:create", route: "/workspace/builder/create-pipeline" },
    { key: "automate:overview", route: "/workspace/object-monitoring/" },
    { key: "automate:automations", route: "/workspace/object-monitoring/automations" },
  ];

  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  const rows = [];
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const pg = await ctx.newPage();
    const keys = []; let other = 0;
    pg.on("request", (q) => keys.push(LIB.requestKey(q.method(), q.url())));
    pg.on("dialog", (d) => { if (d.type() === "beforeunload") { d.accept().catch(() => {}); return; } other += 1; d.dismiss().catch(() => {}); });
    ctx.on("page", (p) => { other += 1; p.close().catch(() => {}); });
    pg.on("download", () => { other += 1; });
    // identity by what a control IS: time-varying text ("Created 2 seconds ago") and classes are not it
    // a control with no words of its own (a facet checkbox) is known by the words of its row
    const ident = (el) => `${el.tag}|${el.role}|${String(el.text || `@${el.contextText || ""}`).split(" Created ")[0].replace(/\d+/gu, "#")}|${el.href || ""}`;
    const withOcc = (els) => { const n = new Map(); return els.map((el) => { const k = ident(el); const i = n.get(k) || 0; n.set(k, i + 1); return { ...el, ident: k, occ: i }; }); };
    // a readonly field is a display (a rid to copy), not a control
    const enumerate = async () => withOcc((await pg.evaluate(ENUMERATE)).filter((el) => LIB.isLiveLooking(el) && !el.readOnly));
    // the automation's own page, at the address the adopted list links (read from the list, never derived)
    await pg.goto(`${SERVE}/workspace/object-monitoring/automations`, { waitUntil: "domcontentloaded", timeout: 90000 });
    await pg.waitForTimeout(9000);
    const detail = await pg.evaluate(() => [...document.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")).find((h) => /\/automation\/ri\.object-sentinel\.main\.monitor\.[0-9a-f-]{36}/u.test(h)) || null);
    if (detail) TARGETS.push({ key: "automate:detail", route: new URL(detail, SERVE).pathname });
    ok("the adopted Automate list links the seeded automation's own page", !!detail, detail || "no automation link on the list");

    for (const t of TARGETS) {
      const open = async () => {
        // EACH EXERCISE STARTS FROM A CLEAN CLIENT (check:dead-controls' shell rule): the adopted apps keep
        // filters and choices in browser storage, so one exercise's click would reshape the next page load
        await pg.evaluate(() => { try { localStorage.clear(); sessionStorage.clear(); } catch { /* no origin yet */ } }).catch(() => {});
        await pg.goto(`${SERVE}${t.route}`, { waitUntil: "domcontentloaded", timeout: 90000 });
        await pg.waitForTimeout(6000);
        await pg.getByText("Close", { exact: true }).first().click({ timeout: 1500 }).catch(() => { /* no announcement */ });
        // settled: the live-looking population holds its size across three reads a second apart
        const counts = [];
        for (let i = 0; i < 15; i++) { counts.push((await enumerate()).length); if (counts.length >= 3 && counts.slice(-3).every((n) => n === counts.at(-1) && n > 0)) break; await pg.waitForTimeout(1000); }
      };
      await open();
      const r0 = keys.length; await pg.waitForTimeout(2500); const rest = keys.slice(r0);
      const population = (await enumerate()).filter((el) => !el.inMenu);
      let dirty = false;
      for (const target of population) {
        if (dirty) { await open(); dirty = false; }
        let now = null;
        for (let a = 0; a < 5 && !now; a++) { now = (await enumerate()).find((el) => el.ident === target.ident && el.occ === target.occ); if (!now) await pg.waitForTimeout(500); }
        // a control a late-loading part of the page renders (a facet filled from data) gets one fresh load more
        if (!now) { await open(); for (let a = 0; a < 8 && !now; a++) { now = (await enumerate()).find((el) => el.ident === target.ident && el.occ === target.occ); if (!now) await pg.waitForTimeout(750); } }
        if (!now) { rows.push({ surface: t.key, tag: target.tag, text: target.text, verdict: "click_failed", why: "not found again after two fresh loads" }); dirty = true; continue; }
        const before = await pg.evaluate(PAGE); const st0 = await pg.evaluate(STATES);
        const k0 = keys.length; other = 0; let error = null;
        const how = LIB.exerciseFor(now);
        const loc = pg.locator(now.css).first();
        const box = await loc.boundingBox().catch(() => null);
        const offViewport = !!box && (box.y + box.height <= 0 || box.x + box.width <= 0 || box.y >= 1000 || box.x >= 1600);
        try {
          if (offViewport && /^Skip to/u.test(now.text)) {
            // a skip link appears on keyboard focus; alive if focusing it brings it into view
            await loc.focus({ timeout: 3000 });
            await pg.waitForTimeout(300);
            const b2 = await loc.boundingBox().catch(() => null);
            if (b2 && b2.y + b2.height > 0 && b2.x + b2.width > 0 && b2.y < 1000) other += 1;
          } else if (how === "select") { const o = await loc.evaluate((x) => ({ cur: x.value, vals: [...x.options].filter((q) => !q.disabled).map((q) => q.value) })); const nx = o.vals.find((v) => v !== o.cur); if (nx === undefined) error = "select offers no alternative option"; else await loc.selectOption(nx, { timeout: 3000 }); }
          else if (how === "type") { await loc.fill("zq", { timeout: 3000 }); await pg.waitForTimeout(500); await loc.press("Enter", { timeout: 3000, noWaitAfter: true }); }
          else if (how === "date") { await loc.fill(LIB.dateValueFor(now.type), { timeout: 3000 }); await loc.dispatchEvent("change").catch(() => {}); }
          else if (!["A", "BUTTON", "SELECT", "TEXTAREA", "SUMMARY", "INPUT"].includes(now.tag) && !now.role && !now.onclick) {
            // live-looking only by its pointer cursor (a breadcrumb list, a card): a person clicks its words,
            // not its geometric centre (which can fall on a chevron or a spacer)
            const at = await loc.evaluate((x) => { const leaf = [...x.querySelectorAll("*")].find((k) => k.children.length === 0 && (k.textContent || "").trim() && k.getBoundingClientRect().width > 0); const r = (leaf || x).getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; });
            await pg.mouse.click(at.x, at.y);
          } else { await loc.click({ timeout: 3000, noWaitAfter: true }); }
        } catch (e) { error = String(e.message).split("\n")[0].slice(0, 140); }
        await pg.waitForTimeout(1800);
        const after = await pg.evaluate(PAGE).catch(() => ({ url: "(navigated)", text: "", overlays: 0 }));
        const st1 = await pg.evaluate(STATES).catch(() => st0);
        const signals = LIB.spaSignals({ urlBefore: before.url, urlAfter: after.url, textBefore: before.text, textAfter: after.text, overlaysBefore: before.overlays, overlaysAfter: after.overlays, requestKeys: keys.slice(k0), restKeys: rest, stateMoved: st0 !== st1, other });
        // a link to the page you are on is "self" whatever its trailing slash
        const self = !!now.href && (() => { try { const u = new URL(now.href, `${SERVE}${before.url}`); return u.origin === SERVE && trim(u.pathname) === trim(before.url.split(/[?#]/u)[0]); } catch { return false; } })();
        let judged = LIB.exerciseVerdict({ ...now, selfLink: now.selfLink || self }, { signals, error });
        const landed = LIB.spaLandingVerdict({ urlChanged: signals.url, text: after.text });
        if (landed) judged = landed;
        rows.push({ surface: t.key, tag: now.tag, text: now.text, how, signals: Object.entries(signals).filter(([, v]) => v).map(([k]) => k).join(","), ...judged, url: after.url.slice(0, 120) });
        dirty = true;
      }
    }
  } finally {
    await browser.close();
  }

  const GOOD = new Set(["alive", "alive_by_form", "self"]);
  const bad = rows.filter((r) => !GOOD.has(r.verdict));
  const namedFor = (r) => NAMED.find((n) => n.surface === r.surface && n.tag === r.tag && n.text.test(r.text) && n.verdict === r.verdict);
  const unnamed = bad.filter((r) => !namedFor(r));
  const stale = NAMED.filter((n) => !bad.some((r) => n.surface === r.surface && n.tag === r.tag && n.text.test(r.text) && n.verdict === r.verdict));
  for (const t of TARGETS) {
    const mine = rows.filter((r) => r.surface === t.key);
    ok(`every live-looking control on ${t.key} does something, points where you already are, or is named with its reason`,
      mine.length > 0 && mine.filter((r) => !GOOD.has(r.verdict)).every((r) => namedFor(r)),
      `${mine.length} exercised · ${mine.filter((r) => r.verdict === "alive").length} alive · ${mine.filter((r) => !GOOD.has(r.verdict)).map((r) => `${r.verdict} ${r.tag} "${r.text}"${namedFor(r) ? " (named)" : ` — ${r.why || ""}`}`).join(" · ") || "none other"}`);
  }
  ok("the named list is exact: every named control is still not alive (one that works now must be unpinned)", stale.length === 0,
    stale.length ? `now alive or gone: ${stale.map((n) => `${n.surface} ${n.tag}`).join(", ")}` : `${NAMED.length} named, all still measured`);
  ok("no control outside the named list is dead, failed to click, or landed badly", unnamed.length === 0,
    unnamed.map((r) => `${r.surface} ${r.verdict} ${r.tag} "${r.text}" — ${r.why || ""} ${r.url || ""}`).join(" | ").slice(0, 900) || `${rows.length} exercised`);
  fs.mkdirSync(path.join(ROOT, ".artifacts", "mvp-finish-line"), { recursive: true });
  fs.writeFileSync(path.join(ROOT, ".artifacts", "mvp-finish-line", `adopted-dead-controls-${new Date().toISOString().replace(/[:.]/gu, "-")}.json`), JSON.stringify(rows, null, 1));
}

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "adopted-dead-controls", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); cleanup(); process.exit(1); });
