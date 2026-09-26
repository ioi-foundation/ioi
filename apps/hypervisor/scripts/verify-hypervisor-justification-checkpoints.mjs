#!/usr/bin/env node
// GOVERNANCE / LEASES & LIMITS CHECKPOINTS, THROUGH THE PRODUCT'S OWN FORMS (ADR 0056 P5, R-240).
//
// Proves, against an ISOLATED real daemon + serve lane (never the shared dev processes), that a person
// can put a justification in front of an action and read what people answered, without leaving the
// product: /governance/limits serves Leases & Limits (Checkpoints, a Leases hand-off to Connections,
// Limits as the authority-node named gap); Configuration's form configures a checkpoint on Run now that
// asks for a written answer of a given form; authority evaluation reports the obligation; the
// automation's Run now is then PAUSED behind the prompt (nothing runs, nothing is recorded), a wrong
// answer is refused on the prompt, a right one records the justification — with the wording exactly as
// shown — and only then runs, naming the record on the execution; Review lists it and opens it; pausing
// the checkpoint lets Run now through untouched, resuming brings the prompt back, archiving leaves the
// record's wording intact; a second checkpoint on filing an issue asks for an acknowledgment; and a
// refused configuration and a signed-out page each say so and write nothing.
//
// Every write submits the form the surface RENDERED — its action, its hidden values, and only options
// it offers — and every outcome is read back from the daemon.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-justification-checkpoints.mjs


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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-justification-checkpoints-"));
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
const LIMITS = "/governance/limits";
// Submit a form found on HTML already in hand (a prompt page is the answer to a POST, not a GET).
async function submitFrom(html, action, fields) {
  const form = renderedForm(html, action);
  if (!form) return { error: `no form posting to ${action} is on the page` };
  const missing = Object.keys(fields).filter((n) => !form.names.has(n));
  if (missing.length) return { error: `the page renders no field ${missing.join(", ")}` };
  const body = new URLSearchParams();
  for (const [n, v] of form.values) if (!(n in fields)) body.append(n, v);
  for (const [n, v] of Object.entries(fields)) body.append(n, v);
  const r = await fetch(`${SERVE}${action}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "text/html", cookie: COOKIE }, body: body.toString(), redirect: "manual" }).catch(() => null);
  const location = r?.headers.get("location") || "";
  return { status: r?.status ?? 0, location, q: new URLSearchParams(location.split("?")[1]?.split("#")[0] || ""), text: r ? await r.text() : "" };
}
const executionsOf = async (autoId) => (await daemonRead(`/v1/hypervisor/automations/${autoId}/runs`)).body?.runs ?? [];
const recordsOf = async (q = "") => (await daemonRead(`/v1/hypervisor/justification-records${q}`)).body?.justification_records ?? [];

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
    body: JSON.stringify({ token, password: "justification-checkpoints-bootstrap-v1", email: "justification-checkpoints@ioi.local" }),
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
  await waitFor(`${SERVE}${LIMITS}`, 30000);
  const tag = `jc${Date.now().toString(36).slice(-5)}`;
  const who = await daemonRead("/v1/hypervisor/auth/whoami");
  const tenants = who.body?.principal?.tenant_refs ?? [];
  const org = tenants.find((t) => t === "org://local") || tenants.find((t) => String(t).startsWith("org://")) || "";

  // ---- 1. the lane at its canonical route ---------------------------------------------------------
  const landing = await page(LIMITS);
  const leases = await page(`${LIMITS}?tab=leases`);
  const limits = await page(`${LIMITS}?tab=limits`);
  ok("/governance/limits serves Leases & Limits at its canonical route: Checkpoints' Review is empty, Leases hands off to Connections, Limits names the authority-node gap",
    landing.status === 200 && landing.headers?.get("x-ioi-surface-lane") === "/__ioi/governance/limits" && landing.text.includes("data-limits-records-empty")
      && leases.text.includes('data-limits-leases="1"') && leases.text.includes('href="/__ioi/connections"') && limits.text.includes('data-named-gap="system_limits_authority_node_absent"'),
    `${landing.status} lane ${landing.headers?.get("x-ioi-surface-lane")}`);

  // ---- 2. a configuration the plane cannot admit is refused on the page -------------------------------
  const CONFIG = `${LIMITS}?tab=checkpoints&view=configuration`;
  const refused = await submit(CONFIG, "/__ioi/governance/limits/checkpoints/new", { display_name: `broken-${tag}`, prompt_title: "Why?", prompt_body: "Say why." });
  const noneYet = (await daemonRead("/v1/hypervisor/justification-checkpoints")).body?.checkpoints ?? [];
  ok("a checkpoint with no interaction is refused on the page, keeps what the person typed, and configures nothing",
    !refused.error && refused.status === 200 && refused.text.includes("data-limits-new-error") && refused.text.includes(`value="broken-${tag}"`) && noneYet.length === 0,
    `${refused.error || refused.status} · ${noneYet.length} checkpoints`);

  // ---- 3. a checkpoint on Run now ---------------------------------------------------------------------
  const configured = await submit(CONFIG, "/__ioi/governance/limits/checkpoints/new", {
    display_name: `Run now needs a ticket ${tag}`, interaction_kinds: "automation.run_now", prompt_title: "Why run this now?",
    prompt_body: "Automations run on their schedule. Name the ticket this manual run serves.", justification_kind: "response", response_pattern: "^TICKET-[0-9]+",
  });
  const checkpoints = (await daemonRead("/v1/hypervisor/justification-checkpoints")).body?.checkpoints ?? [];
  const cp = checkpoints[0] || {};
  const cpId = String(cp.checkpoint_id || "").replace("justification-checkpoint://", "");
  ok("Configuration's form configures a checkpoint on Run now, owned by and scoped to the caller's organization, with an admitted head",
    configured.status === 303 && configured.q?.get("ok") === "1" && checkpoints.length === 1 && cp.owner_ref === org && cp.scope_ref === org
      && JSON.stringify(cp.interaction_kinds) === '["automation.run_now"]' && /^sha256:[0-9a-f]{64}$/u.test(cp.admitted_head || ""),
    `${configured.status} ${configured.q?.get("note") || configured.error || ""} · ${cp.checkpoint_id || "none"} ${cp.owner_ref || ""}`);
  const evaluated = await fetch(`${DAEMON}/v1/hypervisor/authority/evaluate`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ effect: "automation.run_now" }) }).then((r) => r.json()).catch(() => ({}));
  ok("authority evaluation reports the justification obligation for Run now, naming the checkpoint (an obligation adds; it allows nothing)",
    (evaluated.obligations || []).some((o) => o.kind === "justification" && (o.checkpoint_refs || []).includes(cp.checkpoint_id)),
    JSON.stringify(evaluated.obligations || []).slice(0, 200));

  // ---- 4. Run now is paused behind the prompt -----------------------------------------------------------
  const project = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ name: `proj-${tag}`, initializer: { specs: [{ git: { remoteUri: "https://example.invalid/checkpoints/run.git" } }] } }) }).then((r) => r.json()).catch(() => ({}));
  const automation = await submit("/__ioi/automations/new", "/__ioi/automations", { project_ref: project.project?.id || "", name: `auto-${tag}`, step_kind: "command", step_body: "echo checkpoint" });
  const autoId = (automation.location || "").match(/auto_[0-9a-f]+/u)?.[0] || "";
  const RUN = `/__ioi/automations/${autoId}/run`;
  const prompted = autoId ? await submit(`/__ioi/automations/${autoId}`, RUN, {}) : { error: "no automation" };
  ok("Run now on the automation's page is PAUSED behind the prompt: the checkpoint's title and wording are shown, and nothing ran or was recorded",
    prompted.status === 200 && prompted.text.includes('data-justification-prompt="1"') && prompted.text.includes("Why run this now?") && prompted.text.includes(`data-justify-checkpoint="${cp.checkpoint_id}"`)
      && (await executionsOf(autoId)).length === 0 && (await recordsOf()).length === 0,
    `${prompted.error || prompted.status} · prompt ${prompted.text?.includes("data-justification-prompt") ?? false}`);
  const wrong = await submitFrom(prompted.text || "", RUN, { justify__0__text: "because I said so" });
  ok("an answer that does not take the checkpoint's form is refused ON THE PROMPT, and still nothing ran or was recorded",
    wrong.status === 200 && wrong.text.includes("data-justify-error") && (await executionsOf(autoId)).length === 0 && (await recordsOf()).length === 0,
    `${wrong.error || wrong.status}`);
  const right = await submitFrom(wrong.text || "", RUN, { justify__0__text: `TICKET-42 rerun after the feed fix ${tag}` });
  const executions = await executionsOf(autoId);
  const records = await recordsOf();
  const rec = records[0] || {};
  ok("the right answer records the justification with the wording exactly as shown, then runs — the execution names the record",
    [302, 303].includes(right.status) && executions.length === 1 && records.length === 1 && rec.language?.title === "Why run this now?"
      && rec.justification?.text === `TICKET-42 rerun after the feed fix ${tag}` && JSON.stringify(rec.checkpointed_item_refs) === JSON.stringify([`automation://${autoId}`])
      && rec.checkpoint_head === cp.admitted_head && (executions[0].justification_record_refs || []).includes(rec.record_id),
    `${right.error || right.status} · ${executions.length} execution(s) · ${records.length} record(s) ${rec.record_id || ""}`);
  const reviewed = await page(`${LIMITS}?tab=checkpoints&view=review`);
  const recTail = String(rec.record_id || "").replace("justification-record://", "");
  const detail = await page(`${LIMITS}?tab=checkpoints&view=review&record=${recTail}`);
  ok("Review lists the record (who, the checkpoint as shown, the automation, the answer) and opens it with its interaction and version",
    reviewed.text.includes(`data-limits-record="${rec.record_id}"`) && reviewed.text.includes(`TICKET-42 rerun after the feed fix ${tag}`) && reviewed.text.includes(`automation://${autoId}`)
      && detail.text.includes(`data-limits-record-detail="${rec.record_id}"`) && detail.text.includes(rec.interaction_ref || "@@") && detail.text.includes(cp.admitted_head || "@@"),
    `review ${reviewed.status} · detail ${detail.status}`);

  // ---- 5. pause, resume, archive --------------------------------------------------------------------------
  const paused = await submit(CONFIG, "/__ioi/governance/limits/checkpoints/enablement", { enablement: "paused" }, { id: cpId });
  const through = autoId ? await submit(`/__ioi/automations/${autoId}`, RUN, {}) : { error: "no automation" };
  ok("a paused checkpoint lets Run now through untouched: no prompt, a second execution, no new record",
    /now paused/u.test(paused.q?.get("note") || "") && [302, 303].includes(through.status) && (await executionsOf(autoId)).length === 2 && (await recordsOf()).length === 1,
    `${said(paused)} · run ${through.status}`);
  const resumed = await submit(CONFIG, "/__ioi/governance/limits/checkpoints/enablement", { enablement: "enabled" }, { id: cpId });
  const again = autoId ? await submit(`/__ioi/automations/${autoId}`, RUN, {}) : { error: "no automation" };
  ok("resuming brings the prompt back", /now enabled/u.test(resumed.q?.get("note") || "") && again.status === 200 && again.text.includes('data-justification-prompt="1"'), `${said(resumed)} · run ${again.status}`);
  const archived = await submit(CONFIG, "/__ioi/governance/limits/checkpoints/enablement", { enablement: "archived" }, { id: cpId });
  const afterArchive = await page(`${LIMITS}?tab=checkpoints&view=review&record=${recTail}`);
  ok("archiving the checkpoint leaves the record's wording exactly as it was shown",
    /now archived/u.test(archived.q?.get("note") || "") && afterArchive.text.includes(`data-limits-record-detail="${rec.record_id}"`) && afterArchive.text.includes("Name the ticket this manual run serves."),
    said(archived));

  // ---- 6. a second interaction: filing an issue asks for an acknowledgment --------------------------------
  const ackConfigured = await submit(CONFIG, "/__ioi/governance/limits/checkpoints/new", {
    display_name: `Issues are acknowledged ${tag}`, interaction_kinds: "support_incident.file", prompt_title: "Before you file",
    prompt_body: "Issues are read by the on-call rota.", justification_kind: "acknowledgment", acknowledgment_text: "I have checked this is not already filed",
  });
  const issueTitle = `issue-${tag}`;
  const issuePrompt = await submit("/__ioi/missions/incidents?new=1", "/__ioi/missions/incidents/new", { title: issueTitle, affected: "__other", affected_ref: `automation://${autoId}` });
  const unticked = await submitFrom(issuePrompt.text || "", "/__ioi/missions/incidents/new", {});
  const ticked = await submitFrom(unticked.text || "", "/__ioi/missions/incidents/new", { justify__0__ack: "on" });
  const openIssues = await page("/operations/issues?lane=open");
  const ackRecord = (await recordsOf("?kind=support_incident.file"))[0] || {};
  ok("a checkpoint on filing an issue asks for an acknowledgment: unticked is refused on the prompt, ticked files the issue and records the acknowledgment naming what it affects",
    ackConfigured.q?.get("ok") === "1" && issuePrompt.text?.includes("Before you file") && unticked.text?.includes("data-justify-error") && [302, 303].includes(ticked.status)
      && openIssues.text.includes(issueTitle) && ackRecord.justification?.acknowledged === true && (ackRecord.checkpointed_item_refs || []).includes(`automation://${autoId}`),
    `${said(ackConfigured)} · prompt ${issuePrompt.status} · ticked ${ticked.status} · record ${ackRecord.record_id || "none"}`);

  // ---- 7. signed out -----------------------------------------------------------------------------------------
  const anonPage = await page(`${LIMITS}?tab=checkpoints&view=review`, { anonymous: true });
  ok("signed out, Leases & Limits names the daemon's refusal and shows no checkpoint or record",
    anonPage.text.includes('data-limits-read-error="request_principal_required"') && !anonPage.text.includes("data-limits-record=") && !anonPage.text.includes(tag),
    `${anonPage.status} ${anonPage.text.match(/data-limits-read-error="([^"]*)"/u)?.[1] || "no refusal"}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "justification-checkpoints", sourceUrl: import.meta.url, results });
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
