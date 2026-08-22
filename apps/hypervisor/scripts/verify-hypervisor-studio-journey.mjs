#!/usr/bin/env node
// Studio primary journey verifier (next-legs II Leg 1b).
//
// Proves, against an ISOLATED real daemon + serve lane, the Studio surface packet end to end:
// the canonical /studio mount renders the rehomed agent-estate lens grammar (with authoring
// controls disabled-with-reason and NO machinery content — OQ-2 held); blueprint create/update/
// promote and descriptor create/update cross the module action lane speaking the shared
// owner-scoped admission contract (owner_ref + idempotency_key + expected_head CAS); a stale
// head and an unauthenticated write refuse TYPED and render verbatim; promotion COMPOSES a real
// governance ApprovalRequest visible on the governance plane AND the canonical approvals page;
// everything survives a daemon restart. Plus the 3-posture browser matrix.
//
// The owner scope is the daemon's own answer about this session (whoami tenant_refs), never a
// constant the verifier picked: hardcoding an owner would keep passing against a deployment
// where this session owns nothing.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

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
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-studio-journey-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

// Daemon JSON with the operator session (the admission contract is identity-first).
const jd = (p, init) => fetch(`${DAEMON}${p}`, {
  headers: {
    "content-type": "application/json",
    ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  ...init,
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const pageText = (p) => fetch(`${SERVE}${p}`)
  .then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }))
  .catch(() => ({ status: 0, text: "", headers: new Headers() }));

// A module action POST on the legacy lane: form-encoded, PRG 303, result in the redirect query.
async function act(tail, fields, { authenticated = true } = {}) {
  const r = await fetch(`${SERVE}/__ioi/studio/workbench${tail}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  const q = new URLSearchParams(location.split("?")[1]?.split("#")[0] ?? "");
  return { status: r?.status ?? 0, location, q };
}

const bpGet = async (id) => (await jd(`/v1/hypervisor/studio/blueprints/${id}`)).body;
const sdGet = async (id) => (await jd(`/v1/hypervisor/odk/surface-descriptors/${id}`)).body;

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "studio-journey-bootstrap-v1", email: "studio-journey@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // WHO this walk is: the owner scope comes from the daemon's own whoami, never a constant.
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  const OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  ok("the session authenticates a principal with an owner tenant to admit writes under", !!OWNER, OWNER || "no owner tenant");

  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: {
      ...process.env,
      PORT: String(servePort),
      PRODUCT_UI_PORT: String(productUiPort),
      IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"),
      IOI_HYPERVISOR_DAEMON_URL: DAEMON,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/studio`, 30000);

  // -- canonical mount renders the rehomed lens grammar ----------------------
  // GRE-2 STU-3 (owner go 2026-08-20): canonical /studio is the FAMILY LANDING (Designer-grammar
  // splash; every row a live surface incl. the Agent Studio estate). The module's agent-estate
  // lens keeps serving on its legacy workbench mount, asserted below.
  const stuLanding = await pageText("/studio");
  ok("canonical /studio serves the STU-3 family landing (ownership headers + splash grammar + live family rows)",
    stuLanding.status === 200 && stuLanding.headers.get("x-ioi-surface-route") === "/studio" && stuLanding.headers.get("x-ioi-surface-owner") === "Studio"
      && stuLanding.text.includes("Solution Designer") && stuLanding.text.includes("Agent Studio") && stuLanding.text.includes('class="spl-row"'),
    `status ${stuLanding.status}`);
  const landing = await pageText("/__ioi/studio/workbench");
  ok("the landing renders the agent-estate lens grammar (panes + labels)",
    landing.text.includes("the agent estate") && landing.text.includes("Agent estate")
      && landing.text.includes("System designs") && landing.text.includes("Composition pattern library")
      && landing.text.includes("Model routes") && landing.text.includes("Launch policies") && landing.text.includes("Intelligence"),
    "");
  ok("vendor-authoring controls are disabled WITH a machine-readable reason",
    landing.text.includes('data-ioi-disabled-reason='), "");
  ok("NO machinery content on /studio (OQ-2 held)", !/machinery/iu.test(landing.text), "");
  const legacyMount = await pageText("/__ioi/studio/workbench");
  ok("the fresh legacy lane serves the same module (its own truthful marker)",
    legacyMount.status === 200 && legacyMount.headers.get("x-ioi-surface-route") === "/__ioi/studio/workbench", "");
  const agentStudioSeed = await pageText("/__ioi/agent-studio");
  ok("the /__ioi/agent-studio seed readout keeps serving untouched (seed preservation)",
    agentStudioSeed.status === 200 && agentStudioSeed.text.includes("Studio"), `status ${agentStudioSeed.status}`);

  // -- composer: intent-frame projection --------------------------------------
  const composer = await pageText(`/__ioi/studio/workbench?view=composer&prompt=${encodeURIComponent("summarize provider spend weekly")}`);
  ok("the composer compiles an intent frame and says it is a projection only",
    composer.status === 200 && composer.text.includes("Projection only")
      && (composer.text.includes('data-testid="intent-frame"') || composer.text.includes("intent-frame projection did not answer")),
    "");
  ok("the compiled frame actually rendered (kernel projection answered)",
    composer.text.includes('data-testid="intent-frame"'), "");

  // -- unauthenticated mutation refuses typed ---------------------------------
  const anon = await act("/actions/create-blueprint", {
    owner_ref: OWNER, idempotency_key: "studio-journey-anon-1", name: "anon blueprint",
    return: "/__ioi/studio/workbench?view=blueprints",
  }, { authenticated: false });
  ok("an unauthenticated blueprint create refuses typed (401 surfaced, no record)",
    anon.status === 303 && (anon.q.get("refused") || "").includes("principal"), `${anon.q.get("refused")}`);

  // -- blueprint create through the module action lane ------------------------
  const created = await act("/actions/create-blueprint", {
    owner_ref: OWNER,
    idempotency_key: "studio-journey-create-1",
    name: "journey blueprint alpha",
    description: "spend summarizer composition",
    graph_json: JSON.stringify({ nodes: [{ id: "a", kind: "concept" }], edges: [] }),
    return: "/__ioi/studio/workbench?view=blueprints",
  });
  const bpId = created.q.get("record") || "";
  ok("blueprint create crosses with admission evidence (303 acted + receipt + record)",
    created.status === 303 && created.q.get("acted") === "create-blueprint" && (created.q.get("receipt") || "").length > 0 && bpId.startsWith("bp_"),
    created.location.slice(0, 140));
  let bp = await bpGet(bpId);
  const headV1 = bp.admitted_head || "";
  const hashV1 = bp.blueprint?.content_hash || "";
  ok("the created record reads back content-addressed with a live admitted head",
    bp.ok === true && bp.blueprint?.status === "draft" && hashV1.startsWith("sha256:") && !!headV1,
    `${hashV1.slice(0, 18)}… head ${String(headV1).slice(0, 12)}…`);
  const bpPage = await pageText(`/__ioi/studio/workbench?view=blueprints&bp=${encodeURIComponent(bpId)}`);
  ok("the canonical blueprints view renders the record (hash + head seeded into the CAS forms)",
    bpPage.status === 200 && bpPage.text.includes("journey blueprint alpha")
      && bpPage.text.includes(hashV1) && bpPage.text.includes(`name="expected_head" value="${headV1}"`),
    "");

  // -- update with the fresh head → revised; content identity moves -----------
  const updated = await act(`/${encodeURIComponent(bpId)}/update`, {
    idempotency_key: "studio-journey-update-1",
    expected_head: headV1,
    name: "journey blueprint alpha",
    description: "spend summarizer composition — revised",
    return: `/__ioi/studio/workbench?view=blueprints&bp=${encodeURIComponent(bpId)}`,
  });
  ok("update with the exact admitted head crosses receipted",
    updated.status === 303 && updated.q.get("acted") === "update-blueprint" && (updated.q.get("receipt") || "").length > 0,
    updated.location.slice(0, 140));
  bp = await bpGet(bpId);
  const headV2 = bp.admitted_head || "";
  ok("the revision recomputed content identity and advanced the head",
    bp.blueprint?.content_hash !== hashV1 && !!headV2 && headV2 !== headV1,
    `hash moved ${bp.blueprint?.content_hash !== hashV1}, head moved ${headV2 !== headV1}`);

  // -- stale head → typed CAS refusal, rendered verbatim ----------------------
  const stale = await act(`/${encodeURIComponent(bpId)}/update`, {
    idempotency_key: "studio-journey-update-stale-1",
    expected_head: headV1,
    description: "must not apply",
    return: `/__ioi/studio/workbench?view=blueprints&bp=${encodeURIComponent(bpId)}`,
  });
  ok("a stale expected_head refuses typed (event_stream_expected_head_conflict)",
    stale.status === 303 && stale.q.get("refused") === "event_stream_expected_head_conflict",
    stale.q.get("refused") || "");
  const stalePage = await pageText(`${stale.location.split("#")[0]}`);
  ok("the CAS refusal renders verbatim with the fresh-head remedy, state unchanged",
    stalePage.status === 200 && stalePage.text.includes("event_stream_expected_head_conflict")
      && stalePage.text.includes("re-open") && stalePage.text.includes("state unchanged")
      && (await bpGet(bpId)).blueprint?.description !== "must not apply",
    "");

  // -- promote composes a real governance ApprovalRequest ---------------------
  const promoted = await act(`/${encodeURIComponent(bpId)}/promote`, {
    idempotency_key: "studio-journey-promote-1",
    expected_head: headV2,
    reason: "journey promotion fixture",
    return: `/__ioi/studio/workbench?view=blueprints&bp=${encodeURIComponent(bpId)}`,
  });
  ok("promote crosses receipted (approval_requested)",
    promoted.status === 303 && promoted.q.get("acted") === "promote-blueprint"
      && (promoted.q.get("receipt") || "").length > 0 && promoted.q.get("result") === "approval_requested",
    promoted.location.slice(0, 140));
  bp = await bpGet(bpId);
  const approvalRef = bp.blueprint?.approval_request_ref || "";
  ok("the blueprint records the composed approval and STAYS a draft (nothing auto-applies)",
    bp.blueprint?.promote_state === "approval_requested" && bp.blueprint?.status === "draft" && !!approvalRef,
    approvalRef);
  const approvals = await jd("/v1/hypervisor/governance/approval-requests");
  const approval = (approvals.body?.approval_requests || []).find((a) => a.subject_ref === `blueprint://${bpId}`);
  ok("governance lists the composed ApprovalRequest (subject blueprint://, kind studio_blueprint_promotion, pending)",
    !!approval && approval.request_kind === "studio_blueprint_promotion" && approval.status === "pending",
    approval?.id || "not listed");
  const approvalsPage = await pageText("/governance/approvals");
  ok("the canonical /governance/approvals page shows the promotion request (cross-surface readback)",
    approvalsPage.status === 200 && approvalsPage.text.includes("studio_blueprint_promotion") && approvalsPage.text.includes(`blueprint://${bpId}`.slice(0, 46)),
    "");

  // -- descriptor authoring over the SAME admission contract ------------------
  const ont = await jd("/v1/hypervisor/odk/domain-ontologies", {
    method: "POST",
    body: JSON.stringify({ domain: "studio-journey", owner_ref: OWNER, idempotency_key: "studio-journey-ont-1" }),
  });
  const ontRef = ont.body?.ontology?.ref || "";
  ok("an ODK ontology fixture admits for the descriptor to reference", ont.status === 201 && !!ontRef, ontRef);
  const sdCreated = await act("/actions/create-descriptor", {
    owner_ref: OWNER,
    idempotency_key: "studio-journey-sd-1",
    name: "journey descriptor",
    description: "list/detail over the journey ontology",
    composition_pattern: "list_detail",
    ontology_ref: ontRef,
    return: "/__ioi/studio/workbench?view=descriptors",
  });
  const sdId = sdCreated.q.get("record") || "";
  ok("descriptor create crosses with admission evidence (303 acted + receipt + record)",
    sdCreated.status === 303 && sdCreated.q.get("acted") === "create-descriptor" && (sdCreated.q.get("receipt") || "").length > 0 && sdId.startsWith("sd_"),
    sdCreated.location.slice(0, 140));
  let sd = await sdGet(sdId);
  const sdHead = sd.admitted_head || "";
  ok("the descriptor reads back admitted (schema + head) and the authoring view renders it",
    sd.ok === true && sd.surface_descriptor?.schema_version === "ioi.hypervisor.odk.surface-descriptor.v1" && !!sdHead
      && (await pageText(`/__ioi/studio/workbench?view=descriptors&sd=${encodeURIComponent(sdId)}`)).text.includes("journey descriptor"),
    "");
  const sdUpdated = await act(`/${encodeURIComponent(sdId)}/update-descriptor`, {
    idempotency_key: "studio-journey-sd-update-1",
    expected_head: sdHead,
    description: "list/detail over the journey ontology — revised",
    return: `/__ioi/studio/workbench?view=descriptors&sd=${encodeURIComponent(sdId)}`,
  });
  ok("descriptor update with the exact head crosses receipted",
    sdUpdated.status === 303 && sdUpdated.q.get("acted") === "update-descriptor" && (sdUpdated.q.get("receipt") || "").length > 0,
    sdUpdated.location.slice(0, 140));
  const sdStale = await act(`/${encodeURIComponent(sdId)}/update-descriptor`, {
    idempotency_key: "studio-journey-sd-stale-1",
    expected_head: sdHead,
    description: "must not apply",
    return: `/__ioi/studio/workbench?view=descriptors&sd=${encodeURIComponent(sdId)}`,
  });
  ok("a stale descriptor head refuses typed on the same contract",
    sdStale.status === 303 && sdStale.q.get("refused") === "event_stream_expected_head_conflict",
    sdStale.q.get("refused") || "");

  // -- restart survival -------------------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  bp = await bpGet(bpId);
  sd = await sdGet(sdId);
  ok("blueprint + promotion state + descriptor survive a daemon restart",
    bp.ok === true && bp.blueprint?.promote_state === "approval_requested" && !!bp.admitted_head
      && sd.ok === true && sd.surface_descriptor?.description?.includes("revised"),
    "");
  const survivors = await jd("/v1/hypervisor/governance/approval-requests");
  ok("the composed ApprovalRequest survives the restart",
    (survivors.body?.approval_requests || []).some((a) => a.subject_ref === `blueprint://${bpId}`), "");
  let reload = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    await new Promise((r) => setTimeout(r, 1500));
    reload = await pageText(`/__ioi/studio/workbench?view=blueprints&bp=${encodeURIComponent(bpId)}`);
    if (reload.status === 200 && reload.text.includes("journey blueprint alpha")) break;
  }
  ok("the canonical blueprints view re-renders admitted state after restart",
    reload.status === 200 && reload.text.includes("journey blueprint alpha") && reload.text.includes("approval_requested"),
    `status ${reload.status}`);

  // -- 3-posture matrix -------------------------------------------------------
  let pw = null;
  try { pw = await import("playwright"); } catch { pw = null; }
  if (!pw) {
    ok("posture matrix skipped — playwright unavailable", false, "install playwright to run the browser matrix");
  } else {
    const browser = await pw.chromium.launch();
    for (const [name, opts] of [
      ["light-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "light" }],
      ["dark-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "dark" }],
      ["narrow-reduced-motion", { viewport: { width: 390, height: 844 }, colorScheme: "light", reducedMotion: "reduce" }],
    ]) {
      const ctx = await browser.newContext(opts);
      const page = await ctx.newPage();
      const errors = [];
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      const resp = await page.goto(`${SERVE}/studio`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.length > 0 && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
    await browser.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "studio-journey", sourceUrl: import.meta.url, results });
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
