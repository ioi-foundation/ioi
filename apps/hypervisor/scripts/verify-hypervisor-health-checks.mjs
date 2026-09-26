#!/usr/bin/env node
// OPERATIONS / HEALTH, THROUGH THE PRODUCT'S OWN FORMS (ADR 0056 P2, R-240).
//
// Proves, against an ISOLATED real daemon + serve lane (never the shared dev processes), that a person
// can declare what to observe and read how it came out without leaving the product: Operations links
// the Health lane; its New check form offers the caller's environments and automations; a check over an
// automation's latest run is declared and evaluated (Passed, citing the execution and the canonical
// run); a command probe that exits 3 is Failed with its exit code and files an issue through the
// incident plane's own admission, which Issues then lists; the check's history holds that one result;
// Pause takes Evaluate now away and says why, Resume gives it back, Archive moves the check aside; and
// a refused declaration, a signed-out post and a signed-out page each say so and write nothing.
//
// Every write submits the form the surface RENDERED — its action, its hidden values, and only options
// it offers — and every outcome is read back from the daemon.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-health-checks.mjs

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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-health-checks-"));
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
const said = (res) => res.error || res.q?.get("note") || (res.text || "").match(/data-health-new-error="1">[\s\S]*?<\/div>/u)?.[0]?.replace(/<[^>]+>/gu, " ").trim() || `${res.status} ${res.location}`.slice(0, 160);
const HEALTH = "/operations/health";

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
    body: JSON.stringify({ token, password: "health-checks-bootstrap-v1", email: "health-checks@ioi.local" }),
  }).then((r) => r.json()).catch(() => ({})) : {};
  COOKIE = boot.session_token ? `ioi_session=${boot.session_token}` : "";
  ok("operator bootstrap yields an authenticated session", COOKIE.startsWith("ioi_session=ioi_sess_"), COOKIE.slice(0, 24));

  const servePort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}${HEALTH}`, 30000);
  const tag = `hc${Date.now().toString(36).slice(-5)}`;

  // ---- 1. Operations links the lane; the canonical route serves it ------------------------------
  const operations = await page("/__ioi/operations");
  const canonical = await page(HEALTH);
  ok("Operations links Operations / Health, and /operations/health serves the Health lane at its canonical route",
    operations.text.includes('href="/operations/health" data-ops-health-link="1"') && canonical.status === 200
      && canonical.headers?.get("x-ioi-surface-lane") === "/__ioi/operations/health" && canonical.text.includes("data-health-empty"),
    `Operations ${operations.status} · ${HEALTH} ${canonical.status} lane ${canonical.headers?.get("x-ioi-surface-lane")}`);

  // ---- 2. something real to observe: an automation that has run in an environment ---------------
  const project = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ name: `proj-${tag}`, initializer: { specs: [{ git: { remoteUri: "https://example.invalid/health/run.git" } }] } }) }).then((r) => r.json()).catch(() => ({}));
  const automation = await submit("/__ioi/automations/new", "/__ioi/automations", { project_ref: project.project?.id || "", name: `auto-${tag}`, step_kind: "command", step_body: "echo health" });
  const autoId = (automation.location || "").match(/auto_[0-9a-f]+/u)?.[0] || "";
  const ranNow = autoId ? await submit(`/__ioi/automations/${autoId}`, `/__ioi/automations/${autoId}/run`, {}) : { error: "no automation" };
  const execution = ((await daemonRead(`/v1/hypervisor/automations/${autoId}/runs`)).body?.runs ?? [])[0] || {};
  const envRef = execution.environment_id ? `environment://${execution.environment_id}` : "";
  ok("an automation created through its form and Run now finishes in an environment (the thing to observe)",
    !!autoId && [302, 303].includes(ranNow.status) && execution.status === "done" && !!envRef,
    `${said(automation)} · run ${ranNow.status ?? ranNow.error} · ${execution.execution_id || "no execution"} ${execution.status || ""}`);
  const blank = await page(HEALTH);
  const newForm = renderedForm(blank.text, "/__ioi/operations/health/new");
  ok("the New check form offers the caller's environment and automation as targets, and the environment as a probe's place",
    !!newForm && newForm.options.target?.has(envRef) && newForm.options.target?.has(`automation://${autoId}`) && newForm.options.environment_ref?.has(envRef),
    `target ${newForm?.options.target ? [...newForm.options.target].length : 0} options · environment ${newForm?.options.environment_ref ? [...newForm.options.environment_ref].length : 0}`);

  // ---- 3. a declaration the plane cannot admit is refused on the page -----------------------------
  const refused = await submit(HEALTH, "/__ioi/operations/health/new", { display_name: `broken-${tag}`, target: envRef, check_kind: "command_exit", environment_ref: envRef, command: "" });
  const afterRefusal = (await daemonRead("/v1/hypervisor/health-checks")).body?.health_checks ?? [];
  ok("a command check with no command is refused on the page, keeps what the person typed, and declares nothing",
    !refused.error && refused.status === 200 && refused.text.includes("data-health-new-error") && refused.text.includes(`value="broken-${tag}"`) && afterRefusal.length === 0,
    `${said(refused)} · ${afterRefusal.length} checks`);

  // ---- 4. a check over the automation's latest run, declared and evaluated ------------------------
  const declaredA = await submit(HEALTH, "/__ioi/operations/health/new", { display_name: `run succeeds ${tag}`, target: `automation://${autoId}`, check_kind: "automation_run_outcome", severity: "minor", file_on: "failed" });
  const idA = declaredA.q?.get("check") || "";
  const evaluatedA = idA ? await submit(HEALTH, "/__ioi/operations/health/evaluate", {}, { id: idA }) : { error: "no check" };
  const resultA = ((await daemonRead(`/v1/hypervisor/health-check-results?health_check=${idA}`)).body?.health_check_results ?? [])[0] || {};
  ok("an automation-outcome check is declared through New check, and Evaluate now records Passed citing the execution and its canonical run",
    declaredA.status === 303 && declaredA.q?.get("ok") === "1" && /^hc_[0-9a-f]+$/u.test(idA) && evaluatedA.q?.get("ok") === "1"
      && resultA.outcome === "passed" && (resultA.evidence_refs ?? []).includes(`automation-execution://${execution.execution_id}`) && (resultA.evidence_refs ?? []).some((r) => r.startsWith("automation-run://")),
    `${said(declaredA)} · ${said(evaluatedA)} · ${resultA.outcome || "no result"} ${JSON.stringify(resultA.evidence_refs ?? [])}`);

  // ---- 5. a failing command probe files an issue ----------------------------------------------------
  const declaredB = await submit(HEALTH, "/__ioi/operations/health/new", { display_name: `probe fails ${tag}`, target: envRef, check_kind: "command_exit", environment_ref: envRef, command: "exit 3", severity: "major", file_on: "failed" });
  const idB = declaredB.q?.get("check") || "";
  const evaluatedB = idB ? await submit(HEALTH, "/__ioi/operations/health/evaluate", {}, { id: idB }) : { error: "no check" };
  const resultsB = (await daemonRead(`/v1/hypervisor/health-check-results?health_check=${idB}`)).body?.health_check_results ?? [];
  const incident = resultsB[0]?.support_incident_ref || "";
  const issues = await page("/operations/issues?lane=open");
  ok("a command probe that exits 3 is Failed with its exit code, files an issue through the incident plane, and Issues lists it open",
    declaredB.q?.get("ok") === "1" && /^Failed/u.test(evaluatedB.q?.get("note") || "") && resultsB[0]?.outcome === "failed" && resultsB[0]?.exit_code === 3
      && incident.startsWith("support-incident://") && issues.text.includes(`Health check failed: probe fails ${tag}`),
    `${said(evaluatedB)} · ${resultsB[0]?.outcome || "no result"} exit ${resultsB[0]?.exit_code ?? "—"} · ${incident || "no incident"}`);
  const history = await page(`${HEALTH}?check=${idB}`);
  ok("the check's history renders the one admitted result with its outcome and a link to the issue it filed",
    history.text.includes(`data-health-detail="health-check://${idB}"`) && history.text.includes(`data-health-result="${resultsB[0]?.result_id}"`)
      && history.text.includes('data-health-outcome="failed"') && history.text.includes(`data-health-incident="${incident}"`) && resultsB.length === 1,
    `${resultsB.length} result(s) · detail ${history.text.includes(`data-health-detail="health-check://${idB}"`)}`);

  // ---- 6. a signed-out post of a rendered form records nothing ---------------------------------------
  const anon = idB ? await submit(HEALTH, "/__ioi/operations/health/evaluate", {}, { id: idB, postAnonymously: true }) : { error: "no check" };
  const afterAnon = (await daemonRead(`/v1/hypervisor/health-check-results?health_check=${idB}`)).body?.health_check_results ?? [];
  ok("an Evaluate now posted with no session is refused as signed out and records no result",
    anon.status === 303 && anon.q?.get("ok") === "0" && /signed out/u.test(anon.q?.get("note") || "") && afterAnon.length === resultsB.length,
    `${said(anon)} · ${resultsB.length} → ${afterAnon.length}`);

  // ---- 7. pause, resume, archive ----------------------------------------------------------------------
  const paused = idB ? await submit(HEALTH, "/__ioi/operations/health/enablement", { enablement: "paused" }, { id: idB }) : { error: "no check" };
  const pausedPage = await page(HEALTH);
  ok("Pause takes Evaluate now away from the check and says why beside it",
    /now paused/u.test(paused.q?.get("note") || "") && pausedPage.text.includes(`data-health-disabled-reason="${idB}"`) && !renderedForm(pausedPage.text, "/__ioi/operations/health/evaluate", idB),
    said(paused));
  const resumed = idB ? await submit(HEALTH, "/__ioi/operations/health/enablement", { enablement: "enabled" }, { id: idB }) : { error: "no check" };
  const resumedPage = await page(HEALTH);
  ok("Resume gives Evaluate now back", /now enabled/u.test(resumed.q?.get("note") || "") && !!renderedForm(resumedPage.text, "/__ioi/operations/health/evaluate", idB), said(resumed));
  const archivedBody = new URLSearchParams();
  const archiveAt = resumedPage.text.indexOf(`data-health-archive="${idB}"`);
  for (const m of resumedPage.text.slice(resumedPage.text.lastIndexOf("<form", archiveAt), archiveAt).matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/gu)) archivedBody.append(m[1], unesc(m[2]));
  const archived = archiveAt >= 0 && archivedBody.get("enablement") === "archived"
    ? await fetch(`${SERVE}/__ioi/operations/health/enablement`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/x-www-form-urlencoded" }, body: archivedBody.toString(), redirect: "manual" }).catch(() => null)
    : null;
  const archivedPage = await page(HEALTH);
  const checkB = ((await daemonRead(`/v1/hypervisor/health-checks/${idB}`)).body?.health_check) || {};
  ok("Archive (the row's own Archive form) moves the check to the archived list and the daemon holds it archived",
    archived?.status === 303 && archivedPage.text.includes('data-health-archived="1"') && archivedPage.text.includes('data-health-checks="1"') && checkB.enablement === "archived",
    `${archived?.status ?? "no Archive form"} · ${checkB.enablement || "—"}`);

  // ---- 8. signed out, the page names the refusal and shows nothing in its place -----------------------
  const anonPage = await page(HEALTH, { anonymous: true });
  ok("signed out, the Health page names the daemon's refusal and renders no check",
    anonPage.text.includes('data-health-read-error="request_principal_required"') && !anonPage.text.includes("data-health-checks") && !anonPage.text.includes(`probe fails ${tag}`),
    `${anonPage.status} ${anonPage.text.match(/data-health-read-error="([^"]*)"/u)?.[1] || "no refusal"}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "health-checks", sourceUrl: import.meta.url, results });
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
