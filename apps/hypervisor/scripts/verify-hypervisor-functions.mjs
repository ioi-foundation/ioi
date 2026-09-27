#!/usr/bin/env node
// ONTOLOGY / FUNCTIONS, THROUGH THE PRODUCT'S OWN FORMS (ADR 0056 P3, R-240).
//
// Proves, against an ISOLATED real daemon + serve lane (never the shared dev processes), that a person
// can declare a typed function, run it, release it into the runtime tool-contract registry, revise it
// and deprecate it without leaving the product: Ontology links the Functions lane; a declaration missing
// its API name is refused on the page and writes nothing; a declared function is a draft whose detail
// shows its typed inputs and output; a test run in the caller's environment Passes with the value the
// code printed, and an input of the wrong type is refused on the page before anything runs; Release
// admits an exact tool revision the daemon reports operable; a successor must carry a greater version;
// a successor that prints a log line before its value Fails its test run; Deprecate revokes the released
// tool revision; an automation's function step pins the released revision's content hash and Run now
// runs exactly it (Passed, its output), and after Deprecate the same step fails naming why; and a
// signed-out post and a signed-out page each say so and change nothing.
//
// Every write submits the form the surface RENDERED — its action, its hidden values, and only options
// it offers — and every outcome is read back from the daemon.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-functions.mjs

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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-functions-"));
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
const said = (res) => res.error || res.q?.get("note") || (res.text || "").match(/data-fn-(?:new|test|revise)-error="1">[\s\S]*?<\/div>/u)?.[0]?.replace(/<[^>]+>/gu, " ").replace(/\s+/gu, " ").trim() || `${res.status} ${res.location}`.slice(0, 160);
const FUNCTIONS = "/ontology/functions";
const SOURCE = "import json, sys\nprint(json.dumps(json.load(sys.stdin)['amount'] * 2))\n";
const NOISY = "import json, sys\nprint('computing')\nprint(json.dumps(json.load(sys.stdin)['amount'] * 2))\n";

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
    body: JSON.stringify({ token, password: "functions-bootstrap-v1", email: "functions@ioi.local" }),
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
  await waitFor(`${SERVE}${FUNCTIONS}`, 30000);
  const tag = `fn${Date.now().toString(36).slice(-5)}`;

  // ---- 1. Ontology links the lane; the canonical route serves it --------------------------------
  const ontology = await page("/ontology");
  const canonical = await page(FUNCTIONS);
  ok("Ontology links Ontology / Functions, and /ontology/functions serves the Functions lane at its canonical route",
    ontology.text.includes('href="/ontology/functions"') && canonical.status === 200
      && canonical.headers?.get("x-ioi-surface-lane") === "/__ioi/ontology/functions" && canonical.text.includes("data-fn-empty"),
    `Ontology ${ontology.status} · ${FUNCTIONS} ${canonical.status} lane ${canonical.headers?.get("x-ioi-surface-lane")}`);

  // ---- 2. somewhere to run: an automation run through its form leaves a running environment ------
  const project = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ name: `proj-${tag}`, initializer: { specs: [{ git: { remoteUri: "https://example.invalid/functions/run.git" } }] } }) }).then((r) => r.json()).catch(() => ({}));
  const automation = await submit("/__ioi/automations/new", "/__ioi/automations", { project_ref: project.project?.id || "", name: `auto-${tag}`, step_kind: "command", step_body: "echo ready" });
  const autoId = (automation.location || "").match(/auto_[0-9a-f]+/u)?.[0] || "";
  const ranNow = autoId ? await submit(`/__ioi/automations/${autoId}`, `/__ioi/automations/${autoId}/run`, {}) : { error: "no automation" };
  const execution = ((await daemonRead(`/v1/hypervisor/automations/${autoId}/runs`)).body?.runs ?? [])[0] || {};
  const envRef = execution.environment_id ? `environment://${execution.environment_id}` : "";
  ok("an automation run through its form leaves a running environment to test functions in",
    !!autoId && [302, 303].includes(ranNow.status) && execution.status === "done" && !!envRef,
    `${said(automation)} · run ${ranNow.status ?? ranNow.error} · ${execution.execution_id || "no execution"} ${execution.status || ""}`);

  // ---- 3. a declaration the plane cannot admit is refused on the page -----------------------------
  const refused = await submit(FUNCTIONS, "/__ioi/ontology/functions/new", { display_name: `Double ${tag}`, api_name: "", version: "1.0.0", input_name_0: "amount", input_type_0: "integer", output_type: "integer", runtime: "python3", source: SOURCE });
  const afterRefusal = (await daemonRead("/v1/hypervisor/functions")).body?.functions ?? [];
  ok("a declaration with no API name is refused on the page, keeps what the person typed, and declares nothing",
    !refused.error && refused.status === 200 && refused.text.includes("data-fn-new-error") && refused.text.includes(`value="Double ${tag}"`) && afterRefusal.length === 0,
    `${said(refused)} · ${afterRefusal.length} functions`);

  // ---- 4. a typed function, declared through New function ------------------------------------------
  const declared = await submit(FUNCTIONS, "/__ioi/ontology/functions/new", { display_name: `Double ${tag}`, api_name: "doubleAmount", version: "1.0.0", documentation: "Doubles the amount it is given.", input_name_0: "amount", input_type_0: "integer", input_required_0: "on", input_description_0: "what to double", output_type: "integer", output_description: "twice the amount", runtime: "python3", source: SOURCE });
  const fnId = declared.q?.get("function") || "";
  const detail1 = (await daemonRead(`/v1/hypervisor/functions/${fnId}`)).body || {};
  const r1 = (detail1.revisions ?? []).find((r) => r.ordinal === 1) || {};
  const detailPage = await page(`${FUNCTIONS}?function=${fnId}`);
  ok("New function declares a draft revision 1.0.0 whose integer input and output the daemon holds and the detail renders",
    declared.status === 303 && declared.q?.get("ok") === "1" && /^fn_[0-9a-f]{16}$/u.test(fnId) && r1.status === "draft" && r1.version === "1.0.0"
      && r1.inputs?.[0]?.data_type?.type === "integer" && r1.inputs?.[0]?.required === true && r1.output?.data_type?.type === "integer"
      && detailPage.text.includes(`data-fn-detail="function://${fnId}"`) && detailPage.text.includes('data-fn-output-type="integer"') && detailPage.text.includes('data-fn-status="draft"'),
    `${said(declared)} · ${r1.revision_ref || "no revision"} ${r1.status || ""}`);

  // ---- 5. a test run in the caller's environment -----------------------------------------------------
  const testForm = renderedForm(detailPage.text, "/__ioi/ontology/functions/test");
  ok("the Run a test form offers the caller's running environment and one typed field per declared input",
    !!testForm && testForm.options.environment_ref?.has(envRef) && testForm.names.has("in_amount"),
    `environment options ${testForm?.options.environment_ref ? [...testForm.options.environment_ref].length : 0} · fields ${testForm ? [...testForm.names].join(",") : "no form"}`);
  const wrongType = await submit(`${FUNCTIONS}?function=${fnId}`, "/__ioi/ontology/functions/test", { environment_ref: envRef, in_amount: "twenty" });
  const runsAfterWrong = (await daemonRead(`/v1/hypervisor/function-test-runs?function=${fnId}`)).body?.test_runs ?? [];
  ok("an input of the wrong type is refused on the page before anything runs",
    wrongType.status === 200 && wrongType.text.includes("data-fn-test-error") && /whole number/u.test(said(wrongType)) && runsAfterWrong.length === 0,
    `${said(wrongType)} · ${runsAfterWrong.length} runs`);
  const tested = await submit(`${FUNCTIONS}?function=${fnId}`, "/__ioi/ontology/functions/test", { environment_ref: envRef, in_amount: "21" });
  const run1 = ((await daemonRead(`/v1/hypervisor/function-test-runs?function=${fnId}`)).body?.test_runs ?? [])[0] || {};
  ok("a test run Passes with the value the code printed, recorded against the exact revision and its content hash",
    tested.status === 303 && /^Passed/u.test(tested.q?.get("note") || "") && run1.outcome === "passed" && run1.output === 42
      && run1.revision_ref === r1.revision_ref && run1.revision_content_hash === r1.content_hash && run1.environment_ref === envRef,
    `${said(tested)} · ${run1.outcome || "no run"} output ${JSON.stringify(run1.output)}`);

  // ---- 6. release into the runtime tool-contract registry ---------------------------------------------
  const released = await submit(`${FUNCTIONS}?function=${fnId}`, "/__ioi/ontology/functions/release", {});
  const r1r = ((await daemonRead(`/v1/hypervisor/functions/${fnId}`)).body?.revisions ?? []).find((r) => r.ordinal === 1) || {};
  ok("Release admits an exact tool revision tool://function/<id>/revision/1 that the daemon reports operable",
    released.q?.get("ok") === "1" && r1r.status === "released" && r1r.runtime_tool_contract?.revision_ref === `tool://function/${fnId}/revision/1` && r1r.tool_operable === true,
    `${said(released)} · ${r1r.status || ""} ${r1r.runtime_tool_contract?.revision_ref || "no tool"} operable ${r1r.tool_operable}`);

  // ---- 6b. an automation consumes the released revision by exact pin (ADR 0056 P3, cut 3) --------------
  const newAuto = await page("/__ioi/automations/new");
  const autoForm = renderedForm(newAuto.text, "/__ioi/automations");
  ok("New automation offers a function step and the released revision — only released ones — to pin",
    !!autoForm && autoForm.options.step_kind?.has("function") && autoForm.options.step_function?.has(r1r.revision_ref) && autoForm.options.step_function?.size === 2,
    `step kinds ${autoForm?.options.step_kind ? [...autoForm.options.step_kind].join(",") : "no form"} · functions offered ${autoForm?.options.step_function ? [...autoForm.options.step_function].filter(Boolean).join(",") : "none"}`);
  const fnAuto = await submit("/__ioi/automations/new", "/__ioi/automations", { project_ref: project.project?.id || "", name: `fnauto-${tag}`, step_kind: "function", step_function: r1r.revision_ref, step_body: '{"amount": 20}' });
  const fnAutoId = (fnAuto.location || "").match(/auto_[0-9a-f]+/u)?.[0] || "";
  const fnAutoRecord = ((await daemonRead(`/v1/hypervisor/automations/${fnAutoId}`)).body?.automation) || {};
  const fnRan = fnAutoId ? await submit(`/__ioi/automations/${fnAutoId}`, `/__ioi/automations/${fnAutoId}/run`, {}) : { error: "no automation" };
  const fnRuns = (await daemonRead(`/v1/hypervisor/automations/${fnAutoId}/runs`)).body?.runs ?? [];
  const fnExec = fnRuns[0] || {};
  const fnStep = fnExec.step_results?.[0] || {};
  ok("an automation's function step pins the revision's content hash, and Run now runs that exact revision: the execution is done and the step recorded Passed with output 40 and its tool revision",
    !!fnAutoId && fnAutoRecord.steps?.[0]?.content_hash === r1r.content_hash && [302, 303].includes(fnRan.status)
      && fnExec.status === "done" && fnStep.kind === "function" && fnStep.output?.outcome === "passed" && fnStep.output?.output === 40
      && fnStep.output?.tool_revision_ref === `tool://function/${fnId}/revision/1`,
    `${said(fnAuto)} · pin ${fnAutoRecord.steps?.[0]?.content_hash === r1r.content_hash} · run ${fnRan.status ?? fnRan.error} · ${fnExec.status || "no execution"} ${fnStep.output?.outcome || fnStep.output?.error || ""} output ${JSON.stringify(fnStep.output?.output)}`);
  // The daemon's OWN dispatch runs the same step: an accepted webhook fire (as a scheduled tick would)
  // carries the internal token and the executor, not a session. It failed with "an authenticated session
  // or API token is required" until the function step honoured the dispatch identity (R-241).
  const rotated = fnAutoId ? await fetch(`${DAEMON}/v1/hypervisor/automations/${fnAutoId}/webhook-rotate`, { method: "POST", headers: { cookie: COOKIE } }).then((r) => r.json()).catch(() => ({})) : {};
  const fire = rotated.webhook_token ? await fetch(`${DAEMON}/v1/hypervisor/automations/${fnAutoId}/webhook`, { method: "POST", headers: { "content-type": "application/json", "X-IOI-Trigger-Token": rotated.webhook_token }, body: "{}" }).then((r) => r.status).catch(() => 0) : 0;
  let fired = null;
  for (let attempt = 0; attempt < 40 && !fired; attempt++) {
    await sleep(1000);
    fired = ((await daemonRead(`/v1/hypervisor/automations/${fnAutoId}/runs`)).body?.runs ?? []).find((r) => r.activation_kind === "webhook" && r.status !== "running") || null;
  }
  const firedStep = fired?.step_results?.[0] || {};
  ok("the daemon's own dispatch runs a function step: an accepted webhook fire of the same automation is done, its step Passed with output 40",
    fire === 202 && fired?.status === "done" && firedStep.output?.outcome === "passed" && firedStep.output?.output === 40,
    `fire ${fire} · ${fired ? `${fired.status} ${firedStep.output?.outcome || firedStep.output?.error || ""}` : "no webhook execution"}`);

  // ---- 7. successors carry a greater version ------------------------------------------------------------
  const sameVersion = await submit(`${FUNCTIONS}?function=${fnId}`, "/__ioi/ontology/functions/revise", { version: "1.0.0", source: NOISY });
  const countAfterSame = ((await daemonRead(`/v1/hypervisor/functions/${fnId}`)).body?.revisions ?? []).length;
  ok("a successor that does not raise the version is refused on the page and adds nothing",
    sameVersion.status === 200 && sameVersion.text.includes("data-fn-revise-error") && /not greater/u.test(said(sameVersion)) && countAfterSame === 1,
    `${said(sameVersion)} · ${countAfterSame} revisions`);
  const revised = await submit(`${FUNCTIONS}?function=${fnId}`, "/__ioi/ontology/functions/revise", { version: "1.1.0", source: NOISY });
  const r2 = ((await daemonRead(`/v1/hypervisor/functions/${fnId}`)).body?.revisions ?? []).find((r) => r.ordinal === 2) || {};
  ok("Add revision records revision 2 (1.1.0) as a draft that names revision 1 as its predecessor",
    revised.q?.get("ok") === "1" && r2.status === "draft" && r2.version === "1.1.0" && r2.predecessor_revision_ref === r1.revision_ref && r2.api_name === "doubleAmount",
    `${said(revised)} · ${r2.revision_ref || "no revision"}`);
  const noisy = await submit(`${FUNCTIONS}?function=${fnId}&revision=2`, "/__ioi/ontology/functions/test", { environment_ref: envRef, in_amount: "2" });
  const run2 = ((await daemonRead(`/v1/hypervisor/function-test-runs?function=${fnId}`)).body?.test_runs ?? []).find((r) => r.revision_ref === r2.revision_ref) || {};
  ok("a revision that prints a log line before its value Fails its test run and says why",
    noisy.status === 303 && /^Failed/u.test(noisy.q?.get("note") || "") && run2.outcome === "failed" && /one JSON value/u.test(run2.redacted_summary || ""),
    `${said(noisy)} · ${run2.outcome || "no run"}`);

  // ---- 8. a signed-out post of a rendered form changes nothing -------------------------------------------
  const anon = await submit(`${FUNCTIONS}?function=${fnId}&revision=1`, "/__ioi/ontology/functions/deprecate", { reason: "signed out" }, { postAnonymously: true });
  const r1Anon = ((await daemonRead(`/v1/hypervisor/functions/${fnId}`)).body?.revisions ?? []).find((r) => r.ordinal === 1) || {};
  ok("a Deprecate posted with no session is refused as signed out and leaves the revision released",
    anon.status === 303 && anon.q?.get("ok") === "0" && /signed out/u.test(anon.q?.get("note") || "") && r1Anon.status === "released",
    `${said(anon)} · ${r1Anon.status || ""}`);

  // ---- 9. deprecate revokes the tool revision --------------------------------------------------------------
  const deprecated = await submit(`${FUNCTIONS}?function=${fnId}&revision=1`, "/__ioi/ontology/functions/deprecate", { reason: `superseded ${tag}` });
  const after = (await daemonRead(`/v1/hypervisor/functions/${fnId}`)).body || {};
  const r1d = (after.revisions ?? []).find((r) => r.ordinal === 1) || {};
  ok("Deprecate records the reason and revokes the released tool revision; the function then has no released revision",
    deprecated.q?.get("ok") === "1" && r1d.status === "deprecated" && r1d.deprecation?.reason === `superseded ${tag}` && r1d.tool_operable === false && after.function?.released_revision === null,
    `${said(deprecated)} · ${r1d.status || ""} operable ${r1d.tool_operable}`);

  const depRan = fnAutoId ? await submit(`/__ioi/automations/${fnAutoId}`, `/__ioi/automations/${fnAutoId}/run`, {}) : { error: "no automation" };
  const depExec = ((await daemonRead(`/v1/hypervisor/automations/${fnAutoId}/runs`)).body?.runs ?? []).find((r) => r.execution_id !== fnExec.execution_id) || {};
  const depStep = depExec.step_results?.[0] || {};
  ok("after Deprecate, the same automation's function step fails and says the pinned revision is deprecated — a pinned step never silently runs something else",
    [302, 303].includes(depRan.status) && depExec.status === "failed" && /deprecated/u.test(depStep.output?.error || ""),
    `run ${depRan.status ?? depRan.error} · ${depExec.status || "no execution"} ${depStep.output?.error || ""}`);

  // ---- 10. signed out, the page names the refusal and shows nothing in its place ----------------------------
  const anonPage = await page(FUNCTIONS, { anonymous: true });
  ok("signed out, the Functions page names the daemon's refusal and renders no function",
    anonPage.text.includes('data-fn-read-error="request_principal_required"') && !anonPage.text.includes("data-fn-list") && !anonPage.text.includes(`Double ${tag}`),
    `${anonPage.status} ${anonPage.text.match(/data-fn-read-error="([^"]*)"/u)?.[1] || "no refusal"}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "functions", sourceUrl: import.meta.url, results });
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
