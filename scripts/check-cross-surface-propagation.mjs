#!/usr/bin/env node
// check:cross-surface-propagation — a value written on one surface must appear on every surface that
// reads it (apps/hypervisor/AGENTS.md; R-240).
//
// WHY THIS EXISTS. Every per-page check is right about its own page. None of them can see a value
// that lands in one place and not another — an ontology admitted in the Ontology Manager that the
// Pipeline's picker never offers, a source declared in Data sources that no mapping can reach. That
// is a projection defect, invisible to every per-page gate. R-240 found the second one by hand: three
// surfaces pointed at each other for "declare a mapping" and none could.
//
// WHAT IT DOES. It starts its OWN daemon on a fresh data directory and its own serve, bootstraps its
// own operator with the daemon's one-boot token, then makes every write through the form its owning
// surface renders — an ontology, an object type and its properties, a declared source, a backing
// datasource — and reads every consumer back BY THE WRITTEN VALUE'S OWN NAME. The owner's data is
// never touched.
//
//   PURE   — the matrix: every write is an action its module declares, every read follows a write and
//            is judged by a needle carrying the run's tag.
//   SOURCE — the live leg owns its daemon, its serve and its operator, and writes only through forms.
//   LIVE   — the drive itself.
//
//   --drills     CI-bound, seconds: PURE, SOURCE, BINDING, the verdict rules. No daemon, no browser.
//   --mutation   planted defects against the matrix rules — each must go red.
//   (default)    the drills, then LIVE. Exit 0 pass, 2 named failure, 1 fail.

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/propagation-matrix.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = path.join(ROOT, "apps", "hypervisor");
const FLOORS = path.join(APP, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP, "scripts", "lib", "propagation-matrix.mjs");
const SELF_PATH = fileURLToPath(import.meta.url);
const SERVE_SRC = path.join(APP, "scripts", "serve-product-ui.mjs");
const DAEMON_BIN = path.join(ROOT, "target", "debug", "hypervisor-daemon");

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";

const self = (n) => ({ kind: "self", script: `${n} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const LIVE = self("live");

export const CLAUSES = [
  { n: 1, demand: "A VALUE WRITTEN ON ONE SURFACE APPEARS ON EVERY SURFACE THAT READS IT. An ontology admitted in the Ontology Manager is offered by Object Explorer, the Solution Designer (and its Open Diagram · Recent), the Pipeline's picker and the ODK; a declared source is listed by Data sources; a backing datasource shows on its object type, in the Designer's composition, on the Pipeline's mapping node and under its source; a data recipe and a manifest authored on the ODK are listed there and name each other, an edited recipe shows its new name, and a saved set is listed by Object Explorer and named with its type by Insight", executed_by: [PURE, LIVE] },
  { n: 2, demand: "EVERY WRITE GOES THROUGH THE FORM ITS OWNING SURFACE RENDERS — never the daemon API — so the write path a person uses is the one measured. Each write names an action its module declares, or the exact /__ioi/ form action a serve-rendered surface posts to", executed_by: [PURE, SOURCE, LIVE] },
  { n: 3, demand: "A CONSUMER IS JUDGED BY THE WRITTEN VALUE'S OWN NAME. Every needle carries the run's tag: \"backing datasource\" alone is printed by the very notes that say no mapping exists, so a check on it passes on the absence it is testing (measured, R-240). A consumer that did not render is UNRENDERED, never read as missing or present", executed_by: [PURE, LIVE] },
  { n: 4, demand: "THE GATE OWNS ITS DAEMON AND ITS OPERATOR: a fresh data directory, its own serve on free ports, an operator bootstrapped with the daemon's one-boot token. The owner's data is never read or written, and no shared serve can answer for it", executed_by: [SOURCE, LIVE] },
  { n: 5, demand: "EVERY WRITE IS RECEIPTED OR REFUSED BY NAME. A write whose landing carries `refused` fails the leg with the daemon's own code; a write that lands nowhere fails it too", executed_by: [LIVE] },
];

const results = [];
const evidence = { schema: "ioi.cross-surface-propagation-evidence.v1", mode: MODE, started_at: new Date().toISOString(), pure: null, source: null, live: null, verdict: null, mutation: null };
function ok(name, cond, detail) {
  results.push({ name, pass: !!cond, detail: detail || "" });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail && !cond ? ` — ${detail}` : ""}`);
}
function writeEvidence() {
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `cross-surface-propagation-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(readText(p));

// ---- PURE -----------------------------------------------------------------------------------
// THE CONSUMERS THE GOAL NAMES, pinned here and not in the matrix: an ontology admitted in the
// Ontology Manager must appear in Explorer, Designer Recents, Pipeline's picker and ODK; a registered
// source must reach Pipeline. A matrix that quietly drops one of them still reads clean against its
// own rules, so the set it must cover is held by the gate (measured: mutation 8 survived without it).
export const REQUIRED_CONSUMERS = Object.freeze([
  "Ontology Manager lists the object type",
  "Object Explorer offers the object type",
  "Solution Designer lists the ontology",
  "Open Diagram · Recent has the ontology",
  "Pipeline's picker offers the ontology",
  "ODK lists the ontology",
  "Data sources lists the source",
  "Ontology Manager shows the backing datasource",
  "Solution Designer composes the mapping",
  "Pipeline's mapping node shows it",
  "Pipeline's datasource node carries the source",
  "Data sources shows the source's mapping",
  // R-240's second pass: the ODK write lanes and a saved set's type.
  "ODK lists the data recipe",
  "The recipe's page shows its edited name",
  "ODK lists the manifest",
  "The recipe's page names the manifest that bundles it",
  "Object Explorer lists the saved set",
  "Object Explorer names the saved set's type",
  // R-240's third pass: the lanes that replaced disabled "New…" buttons.
  "Model Catalog lists the registered model",
  "Inference offers the registered model",
  "Designer Recents lists the saved diagram",
  "Studio's blueprints list the saved diagram",
  "Machinery lists the saved process graph",
  "Issues lists the filed issue in its open lane",
  "Issues at its Operations route lists the filed issue",
  "Work / Incidents points at the filed issue",
]);

// The editors whose script submits their own form — driven through their UI by the LIVE leg.
export const DRIVERS = Object.freeze(["diagram-editor", "machinery-editor"]);

async function actionsOfModules() {
  const out = {};
  for (const m of ["ontology-manager", "sources", "object-explorer"]) {
    const mod = await import(pathToFileURL(path.join(APP, "surfaces", m, "index.mjs")).href);
    out[m] = (mod.actions || []).map((a) => a.id);
  }
  return out;
}
export function pureFindings(lib, actions) {
  const f = [];
  const expect = (what, got, want) => { if (got !== want) f.push(`${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); };
  // The matrix as shipped.
  for (const x of lib.matrixFindings({ writes: lib.WRITES, reads: lib.READS, actionsOf: (m) => actions[m], drivers: DRIVERS })) f.push(`matrix: ${x}`);
  const named = new Set(lib.READS.map((r) => r.consumer));
  for (const c of REQUIRED_CONSUMERS) if (!named.has(c)) f.push(`matrix: the required consumer '${c}' is not read`);
  // THE NEEDLE THAT PASSED ON ABSENCE: the no-mapping notes print "backing datasource".
  expect("needle/generic", lib.isSpecificNeedle("backing datasource"), false);
  expect("needle/tagged", lib.isSpecificNeedle("Loan {tag} backing datasource"), true);
  expect("needle/tag-only", lib.isSpecificNeedle("{tag}"), false);
  expect("matrix/generic-needle-refused", lib.matrixFindings({ writes: [{ id: "w", module: "m", action: "a", route: "/r" }], reads: [{ after: "w", consumer: "c", route: "/x", needle: "backing datasource" }], actionsOf: () => ["a"] }).length > 0, true);
  expect("matrix/undeclared-action-refused", lib.matrixFindings({ writes: [{ id: "w", module: "m", action: "nope", route: "/r" }], reads: [{ after: "w", consumer: "c", route: "/x", needle: "{tag}-v" }], actionsOf: () => ["a"] }).length > 0, true);
  expect("matrix/orphan-read-refused", lib.matrixFindings({ writes: [{ id: "w", module: "m", action: "a", route: "/r" }], reads: [{ after: "nothing", consumer: "c", route: "/x", needle: "{tag}-v" }], actionsOf: () => ["a"] }).length > 0, true);
  expect("matrix/empty-reads-refused", lib.matrixFindings({ writes: [{ id: "w", module: "m", action: "a", route: "/r" }], reads: [], actionsOf: () => ["a"] }).length > 0, true);
  expect("matrix/undriven-drive-refused", lib.matrixFindings({ writes: [{ id: "w", drive: "no-such-editor", route: "/r" }], reads: [{ after: "w", consumer: "c", route: "/x", needle: "{tag}-v" }], actionsOf: () => [], drivers: ["diagram-editor"] }).length > 0, true);
  expect("matrix/clean", lib.matrixFindings({ writes: [{ id: "w", module: "m", action: "a", route: "/r" }], reads: [{ after: "w", consumer: "c", route: "/x", needle: "{tag}-v" }], actionsOf: () => ["a"] }).length, 0);
  // Reads, judged.
  expect("read/shown", lib.readVerdict({ status: 200, html: "<b>Loan xs1 backing datasource</b>", needle: "Loan xs1 backing datasource" }).verdict, "shown");
  expect("read/missing", lib.readVerdict({ status: 200, html: "Add new backing datasource", needle: "Loan xs1 backing datasource" }).verdict, "missing");
  expect("read/unrendered-503", lib.readVerdict({ status: 503, html: "Loan xs1 backing datasource", needle: "Loan xs1 backing datasource" }).verdict, "unrendered");
  expect("read/unrendered-empty", lib.readVerdict({ status: 200, html: "", needle: "x" }).verdict, "unrendered");
  expect("fill", lib.fill("/p?ontology={ontology}&n={tag}", { ontology: "ont_1", tag: "xs1" }), "/p?ontology=ont_1&n=xs1");
  return f;
}

// ---- SOURCE ---------------------------------------------------------------------------------
export function sourceFindings({ gate, lib }) {
  const f = [];
  if (!/IOI_HYPERVISOR_DATA_DIR: dataDir/u.test(gate) || !/fs\.mkdtempSync\(/u.test(gate)) f.push("the LIVE leg no longer runs its daemon on a FRESH data directory of its own");
  if (/127\.0\.0\.1:8765|\.ioi\/hypervisor\/data/u.test(gate.replace(/\/\/[^\n]*/gu, ""))) f.push("the LIVE leg names the owner's daemon or data directory");
  if (!/spawn\(process\.execPath, \[SERVE_SRC\]/u.test(gate)) f.push("the LIVE leg no longer starts its own serve");
  if (!/IOI_PRODUCT_SIGNIN_REQUIRED: "1"/u.test(gate)) f.push("the LIVE leg no longer measures the product with its sign-in gate on");
  if (!/\/__ioi\/bootstrap/u.test(gate) || !/ioi_bootstrap_/u.test(gate)) f.push("the LIVE leg no longer bootstraps its own operator from the daemon's one-boot token");
  if (/fetch\([^)]*\/v1\/hypervisor\/(odk|data-sources)[^)]*method:\s*"POST"/u.test(gate)) f.push("the LIVE leg writes through the daemon API instead of the surface's form");
  if (/fetch\(|readFileSync|Date\.now\(|new Date\(|document\.|window\./u.test(lib)) f.push("the matrix rules reach a browser, a file, a clock or a network");
  for (const name of ["TAG", "WRITES", "READS"]) if (!lib.includes(`export const ${name}`)) f.push(`the matrix no longer names \`${name}\``);
  return f;
}

// ---- BINDING --------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const s of ["check:cross-surface-propagation", "mutate:cross-surface-propagation"]) if (!rootPkg.scripts?.[s]) f.push(`root_script_missing:${s}`);
  if (!appPkg.scripts?.["check:cross-surface-propagation"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "cross-surface-propagation");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  if (!/npm run check:cross-surface-propagation --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("ci_not_bound_in_the_recognised_form");
  if (!/mutate:cross-surface-propagation/u.test(ci)) f.push("ci_mutation_not_bound");
  if (!floorsGate.includes("check-cross-surface-propagation")) f.push("floors_gate_does_not_recognise_this_runner");
  for (const c of CLAUSES) {
    if (!c.executed_by?.length && !c.absence) f.push(`clause_${c.n}_neither_executed_nor_named`);
    if (c.absence && !c.absence.owner) f.push(`clause_${c.n}_absence_without_owner`);
  }
  if (CLAUSES.length !== 5) f.push(`clause_count:${CLAUSES.length}`);
  return f;
}

export function verdict(rows) {
  const failures = [];
  const absences = [];
  for (const c of CLAUSES) {
    const row = rows.find((r) => r.n === c.n);
    if (!row) { failures.push(`row_missing:${c.n}`); continue; }
    if (row.fabricated) { failures.push(`clause_${c.n}_fabricated: ${row.fabricated}`); continue; }
    if (row.red) { failures.push(`clause_${c.n}_red: ${row.red}`); continue; }
    if (row.absent) absences.push({ n: c.n, ...c.absence });
  }
  if (failures.length) return { kind: "fail", failures, absences };
  if (absences.length) return { kind: "named_failure", failures, absences };
  return { kind: "pass", failures, absences };
}

// ---- LIVE -----------------------------------------------------------------------------------
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.on("error", reject);
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
});
const waitFor = async (url, ms, label) => {
  const deadline = Date.now() + ms;
  for (;;) {
    if (Date.now() > deadline) throw new Error(`${label} did not come up in ${ms / 1000}s`);
    try { const r = await fetch(url); if (r.status) return; } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 500));
  }
};

async function liveLeg() {
  const started = Date.now();
  const findings = [];
  const writes = [];
  const reads = [];
  let daemon = null, serve = null, browser = null, dataDir = null;
  try {
    if (!fs.existsSync(DAEMON_BIN)) throw new Error(`no daemon binary at ${path.relative(ROOT, DAEMON_BIN)} — build it (cargo build -p ioi-node --bin hypervisor-daemon)`);
    const { chromium } = await import("playwright");
    // THIS GATE OWNS ITS DAEMON: a fresh data directory, its own port, its own operator.
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "cross-surface-propagation-"));
    const daemonPort = await freePort();
    let daemonOut = "";
    daemon = spawn(DAEMON_BIN, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}` }, stdio: ["ignore", "pipe", "pipe"] });
    daemon.stdout.on("data", (d) => { daemonOut += d; });
    daemon.stderr.on("data", (d) => { daemonOut += d; });
    await waitFor(`http://127.0.0.1:${daemonPort}/v1/hypervisor/auth/bootstrap-status`, 120000, "this gate's own daemon");
    const port = await freePort();
    const uiPort = await freePort();
    const base = `http://127.0.0.1:${port}`;
    serve = spawn(process.execPath, [SERVE_SRC], {
      cwd: APP,
      env: { ...process.env, PORT: String(port), PRODUCT_UI_PORT: String(uiPort), IOI_HYPERVISOR_DAEMON_URL: `http://127.0.0.1:${daemonPort}`, IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_PRODUCT_SIGNIN_REQUIRED: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    await waitFor(`${base}/`, 60000, "this gate's own serve");
    // The product is measured WITH its sign-in gate on: before anyone exists, a page navigation is
    // sent to first-run setup, never served to a stranger (R-240).
    const gated = await fetch(`${base}/projects`, { redirect: "manual", headers: { accept: "text/html" } }).catch(() => null);
    const gatedTo = gated ? gated.headers.get("location") || "" : "";
    if (!gated || gated.status !== 302 || !gatedTo.startsWith("/__ioi/bootstrap")) findings.push({ on: "setup", text: `sign-in gate: a signed-out navigation to /projects answered ${gated ? gated.status : "nothing"}${gatedTo ? ` → ${gatedTo}` : ""}, not first-run setup` });
    const token = (daemonOut.match(/ioi_bootstrap_[A-Za-z0-9_-]+/u) || [])[0];
    if (!token) throw new Error("the daemon printed no one-boot bootstrap token");

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    const page = await context.newPage();
    // THE OPERATOR, bootstrapped through the serve's own first-run form.
    await page.goto(`${base}/__ioi/bootstrap`);
    await page.fill('input[name="token"]', token); await page.fill('input[name="name"]', "Propagation Gate");
    await page.fill('input[name="email"]', "gate@propagation.invalid"); await page.fill('input[name="password"]', "propagation-gate-pass-1");
    await Promise.all([page.waitForNavigation(), page.click('button[type="submit"]')]);
    const who = await page.request.get(`${base}/v1/hypervisor/auth/whoami`).then((r) => r.json()).catch(() => ({}));
    if (who.authenticated !== true) throw new Error("the bootstrapped operator is not signed in");

    const vars = { tag: `xs${Date.now().toString(36).slice(-6)}`, ontology: null, source: null, recipe: null, manifest: null };
    const W = Object.fromEntries(LIB.WRITES.map((w) => [w.id, w]));
    const submit = async (w, fillForm) => {
      await page.goto(base + LIB.fill(w.route, vars), { waitUntil: "networkidle" });
      const form = page.locator(w.form ? `form[action="${LIB.fill(w.form, vars)}"]` : `form[action$="/actions/${w.action}"]`).first();
      if (!(await form.count())) throw new Error(`write ${w.id}: no '${w.form ? LIB.fill(w.form, vars) : w.action}' form rendered at ${LIB.fill(w.route, vars)}`);
      await fillForm(form);
      await Promise.all([page.waitForNavigation({ timeout: 30000 }), form.locator('button[type="submit"]').first().click()]);
      const u = new URL(page.url());
      // A module action lands with `refused=`; the ODK form handler answers its failure page instead.
      const failed = w.form ? ((await page.locator("body").innerText()).match(/(?:(?:Create|Save) failed|Not registered|Not filed): ([^\n]{0,200})/u) || [])[1] : null;
      const row = { id: w.id, action: w.action || w.form, refused: u.searchParams.get("refused") || (failed ? "odk_form_refused" : null), reason: u.searchParams.get("reason") || failed, landed: u.pathname + u.search.slice(0, 120) };
      writes.push(row);
      if (row.refused) throw new Error(`write ${w.id} REFUSED ${row.refused}: ${row.reason}`);
      if (w.capture) vars[w.capture] = decodeURIComponent(u.pathname.split("/").filter(Boolean).pop() || "");
      return u;
    };
    const u1 = await submit(W.ontology, async (f) => { await f.locator('[name="domain"]').fill(`${vars.tag}-lending`); });
    vars.ontology = u1.searchParams.get("ontology") || u1.searchParams.get("record");
    if (!vars.ontology) throw new Error("the ontology write landed without naming its ontology");
    await submit(W["object-type"], async (f) => { await f.locator('[name="def_id"]').fill("loan"); await f.locator('[name="name"]').fill(`Loan ${vars.tag}`); });
    for (const [id, name] of [["loan_id", "Loan ID"], ["title", "Title"], ["amount", "Amount"]]) {
      await submit(W.properties, async (f) => { await f.locator('[name="def_id"]').fill(id); await f.locator('[name="name"]').fill(name); });
    }
    await submit(W["title-property"], async (f) => { await f.locator('[name="title_property"]').selectOption("title"); });
    const u5 = await submit(W.source, async (f) => {
      // As a person fills it: the name, then the kind (which reloads the form), then the endpoint.
      await f.locator('[name="name"]').fill(`${vars.tag}-src`);
      await Promise.all([page.waitForNavigation(), f.locator('[name="kind"]').selectOption("rest_api")]);
      await f.locator('[name="endpoint"]').fill("https://example.invalid/loans");
      await f.locator('[name="confirm"]').check();
    });
    vars.source = u5.searchParams.get("dataSource") || u5.searchParams.get("record");
    await submit(W.mapping, async (f) => {
      await page.locator(".og-adddsrc summary").click();
      await f.locator('select[name="data_source_id"]').selectOption(vars.source);
      const rows = await f.locator("tbody tr").evaluateAll((trs) => trs.map((tr) => tr.querySelector("input[type=hidden]").value));
      for (const [i, prop] of rows.entries()) await f.locator(`input[name="src_${i}"]`).fill({ loan_id: "id", title: "title", amount: "amt" }[prop] || "");
      await f.locator('input[name="key_property"][value="loan_id"]').check();
    });
    // The ODK's own forms: a recipe bound to the ontology, edited once; a manifest bundling both.
    await submit(W.recipe, async (f) => { await f.locator('[name="name"]').fill(`recipe-${vars.tag}`); await f.locator('select[name="ontology_ref"]').selectOption(`ontology://${vars.ontology}`); });
    await submit(W["recipe-edit"], async (f) => { await f.locator('[name="name"]').fill(`recipe-${vars.tag}-v2`); });
    await submit(W.manifest, async (f) => {
      await f.locator('[name="name"]').fill(`manifest-${vars.tag}`);
      await f.locator(`input[name="ontology_refs"][value="ontology://${vars.ontology}"]`).check();
      await f.locator(`input[name="data_recipe_refs"][value="recipe://${vars.recipe}"]`).check();
    });
    // A saved exploration in Object Explorer, over the object type the matrix made.
    await submit(W["saved-set"], async (f) => { await f.locator('[name="name"]').fill(`saved-${vars.tag}`); });
    // A model route registered on the Model Catalog (the provider need not answer: the registration is
    // what must reach the surfaces that list routes).
    await submit(W.model, async (f) => { await page.locator(".mc-register > summary").click(); await f.locator('[name="model_id"]').fill(`probe-${vars.tag}:1b`); });
    // An issue filed from Issues' New dialog, against an object named by reference (the gate's own
    // daemon has no projects to pick from).
    await submit(W.issue, async (f) => { await f.locator('[name="title"]').fill(`issue-${vars.tag}`); await f.locator('[name="affected"]').selectOption("__other"); await f.locator('[name="affected_ref"]').fill(`env://propagation-${vars.tag}`); });
    // The two editors, driven as a person draws: one node, a name, Save.
    const drive = async (w, draw) => {
      await page.goto(base + w.route, { waitUntil: "networkidle" });
      await draw();
      await Promise.all([page.waitForNavigation({ timeout: 30000 }), page.locator("#dg-save").click()]);
      const u = new URL(page.url());
      const err = await page.locator(".dg-toast.err").first().innerText().catch(() => "");
      const row = { id: w.id, action: w.drive, refused: err ? "editor_save_refused" : null, reason: err || null, landed: u.pathname + u.search.slice(0, 120) };
      writes.push(row);
      if (row.refused) throw new Error(`write ${w.id} REFUSED: ${err}`);
    };
    await drive(W.diagram, async () => { await page.click("#dg-t-concept"); await page.locator('#dg-pop [data-pick="0"]').click(); await page.fill("#dg-name", `diagram-${vars.tag}`); });
    await drive(W.graph, async () => { await page.locator('[data-welcome="initial"]').click(); await page.fill("#dg-name", `process-${vars.tag}`); });

    for (const r of LIB.READS) {
      const route = LIB.fill(r.route, vars);
      const needle = LIB.fill(r.needle, vars);
      let status = 0, html = "";
      try { const resp = await page.goto(base + route, { waitUntil: "networkidle", timeout: 60000 }); status = resp ? resp.status() : 0; html = await page.content(); } catch (e) { html = ""; }
      const judged = LIB.readVerdict({ status, html, needle });
      reads.push({ consumer: r.consumer, route, needle, status, ...judged });
      if (judged.verdict !== "shown") findings.push({ on: "read", text: `${judged.verdict}: ${r.consumer} (${route}) — ${judged.why}` });
    }
    return { findings, writes, reads, vars, seconds: Math.round((Date.now() - started) / 1000) };
  } catch (error) {
    // A write that is refused or lands nowhere is the write's failure; anything before the first
    // write is the leg's ownership of its daemon, serve and operator failing.
    findings.push({ on: writes.length || /^write /u.test(error.message) ? "write" : "setup", text: `live leg: ${String(error.message).split("\n")[0].slice(0, 220)}` });
    return { findings, writes, reads, seconds: Math.round((Date.now() - started) / 1000) };
  } finally {
    try { await browser?.close(); } catch { /* gone */ }
    try { serve?.kill("SIGTERM"); } catch { /* gone */ }
    try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
    await new Promise((r) => setTimeout(r, 1000));
    try { if (dataDir) fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

// ---- run ------------------------------------------------------------------------------------
async function drills() {
  const actions = await actionsOfModules();
  const pure = pureFindings(LIB, actions);
  evidence.pure = pure;
  ok("PURE — every write is an action its owning surface declares, every read follows a write and is judged by a needle carrying the run's tag (the generic one that passed on absence is refused), and a consumer that did not render is neither shown nor missing", pure.length === 0, pure.slice(0, 4).join(" ; "));
  const src = sourceFindings({ gate: readText(SELF_PATH), lib: readText(LIB_PATH) });
  evidence.source = src;
  ok("SOURCE — the LIVE leg runs its own daemon on a fresh data directory and its own serve, bootstraps its own operator, writes only through forms, and the matrix reaches no browser, file, clock or network", src.length === 0, src.slice(0, 4).join(" ; "));
  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP, "package.json")),
    floors: readJson(FLOORS),
    ci: readText(path.join(ROOT, ".github", "workflows", "ci.yml")),
    floorsGate: readText(path.join(APP, "scripts", "check-verifier-floors.mjs")),
  });
  ok("BINDING — floored with an existing source, CI-bound in the form the floors gate recognises, and every clause executed or named with an owner", binding.length === 0, binding.slice(0, 4).join(" ; "));
  const all = CLAUSES.map((c) => ({ n: c.n }));
  ok("VERDICT — a table missing four of its five rows is a FAIL", verdict([{ n: 1 }]).kind === "fail");
  ok("VERDICT — five green rows with no absence is a PASS", verdict(all).kind === "pass");
  ok("VERDICT — a gate reporting success without evidence is fabricated", verdict(all.map((r) => (r.n === 1 ? { ...r, fabricated: "x" } : r))).kind === "fail");
  return { pure, src, binding };
}

async function mutation() {
  const original = readText(LIB_PATH);
  const actions = await actionsOfModules();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "propagation-mutation-"));
  let planted = 0, caught = 0;
  const mutate = async (what, transform) => {
    planted += 1;
    const text = transform(original);
    if (text === original) { console.log(`FAIL  mutation ${planted} (${what}) — the planted defect changed nothing`); return; }
    const file = path.join(dir, `m${planted}.mjs`);
    fs.writeFileSync(file, text);
    let f = [];
    try { f = pureFindings(await import(pathToFileURL(file).href), actions); } catch (e) { f = [`threw:${e.message}`]; }
    if (f.length) caught += 1;
    console.log(`${f.length ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${f.length ? "" : " SURVIVED"}`);
  };
  await mutate("NEEDLE — any string is specific", (t) => t.replace('return typeof needle === "string" && needle.includes(TAG) && needle.replace(TAG, "").trim().length > 0;', "return true;"));
  await mutate("NEEDLE — the tag alone is specific", (t) => t.replace(' && needle.replace(TAG, "").trim().length > 0', ""));
  await mutate("MATRIX — an undeclared action passes", (t) => t.replace("else if (!(actionsOf(w.module) || []).includes(w.action))", "else if (false)"));
  await mutate("MATRIX — a read may follow no write", (t) => t.replace("if (!writeIds.has(r.after))", "if (false)"));
  await mutate("MATRIX — reading nothing proves something", (t) => t.replace("if (!reads.length)", "if (false)"));
  await mutate("READ — an error page counts as shown", (t) => t.replace("if (!(status >= 200 && status < 400))", "if (false)"));
  await mutate("READ — a page without the value counts as shown", (t) => t.replace('return html.includes(needle) ? { verdict: "shown"', 'return true ? { verdict: "shown"'));
  await mutate("MATRIX — a consumer drops out of the reads", (t) => t.replace(/  \{ after: "mapping", consumer: "Data sources shows the source's mapping"[^\n]*\n/u, ""));
  console.log(`\n${caught}/${planted} planted defects caught`);
  evidence.mutation = { planted, caught };
  return caught === planted;
}

async function main() {
  if (MODE === "mutation") {
    const green = await mutation();
    console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
    process.exit(green ? 0 : 1);
  }
  const { pure, src, binding } = await drills();
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} drills passed`);
  emitVerifierCensus({ verifierId: "cross-surface-propagation", sourceUrl: import.meta.url, results });
  if (MODE === "drills") {
    console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
    process.exit(passed === results.length ? 0 : 1);
  }
  const live = await liveLeg();
  evidence.live = live;
  console.log(`\n# LIVE — ${live.findings.length === 0 ? "green" : live.findings.map((x) => x.text).join("; ")} in ${live.seconds}s`);
  for (const w of live.writes) console.log(`#   write ${w.id.padEnd(15)} ${w.refused ? `REFUSED ${w.refused}` : "landed"} ${w.landed || ""}`);
  for (const r of live.reads) console.log(`#   ${r.verdict.padEnd(10)} ${r.consumer.padEnd(46)} ${r.route.slice(0, 80)}`);
  const rows = CLAUSES.map((c) => {
    const row = { n: c.n };
    const red = [];
    if (c.executed_by.some((e) => e.script.startsWith("pure")) && pure.length) red.push("PURE");
    if (c.executed_by.some((e) => e.script.startsWith("source")) && src.length) red.push("SOURCE");
    // Each live finding reds only the clauses it measures: a read 1 and 3, a write 2 and 5, the setup 4.
    const liveOn = { 1: ["read"], 2: ["write"], 3: ["read"], 4: ["setup"], 5: ["write"] }[c.n] || [];
    if (c.executed_by.some((e) => e.script.startsWith("live")) && live.findings.some((x) => liveOn.includes(x.on))) red.push("LIVE");
    // A leg that never reached its reads has measured none of them.
    if (c.executed_by.some((e) => e.script.startsWith("live")) && !live.findings.length && live.reads.length !== LIB.READS.length) red.push(`LIVE read ${live.reads.length}/${LIB.READS.length}`);
    if (red.length) row.red = `${red.join("+")} (this runner)`;
    if (c.absence) row.absent = true;
    return row;
  });
  if (binding.length) rows.find((r) => r.n === 4).red = `BINDING: ${binding.join("; ")}`;
  const result = verdict(rows);
  evidence.verdict = result;
  console.log(`\n=== VERDICT: ${result.kind.toUpperCase()}${result.failures.length ? ` — ${result.failures.join(" ; ")}` : ""}`);
  for (const a of result.absences) console.log(`NAMED  clause ${a.n}: ${a.what}`);
  console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
  process.exit(result.kind === "pass" ? 0 : result.kind === "named_failure" ? 2 : 1);
}

main().catch((e) => { console.error(e); writeEvidence(); process.exit(1); });
