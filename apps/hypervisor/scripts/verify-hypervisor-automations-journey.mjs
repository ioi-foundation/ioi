#!/usr/bin/env node
// Automations journey verifier (W2.1 §5 PR 1, next-legs II Leg 4).
//
// Proves, against an ISOLATED real daemon + serve lane, that the canonical /automations mount
// rehomes the T2 cockpit grammar READ-FIRST over the daemon automations family, and that every
// rendered verb is a verb the daemon ACTUALLY owns — journeyed with readback where the route
// exists, asserted as a TYPED ABSENCE (404 at the daemon, disabled-with-reason in the UI) where
// it does not. Named gaps, never simulation:
//   - the family's route inventory is pinned EXACTLY (list/create · get/patch/delete ·
//     start/runs · webhook/rotate/events · execution get/cancel) — no versions/revisions route,
//     no separate activate route (pause/resume IS `PATCH {enabled}`), no binding plane;
//   - spec mutations cross UNRECEIPTED ({ok, automation}, no admission envelope) — the brief's
//     named W2 defect stays current truth; the IDENTITY finding is CLOSED (#237 → next-legs III
//     Leg 1): every write verb is identity-first (rule E — anonymous callers answer a typed 401
//     request_principal_required BEFORE any record load or field validation, on the daemon lane
//     AND through the serve action lanes), and the stored spec/execution bind the RESOLVED
//     acting principal (INV-37) with executor_identity defaulting to it, never "operator";
//   - scheduler HEALTH is Operations-owned: the pages must render NO scheduler-health rows
//     (liveness/heartbeat/tick data) while the per-spec schedule fields stay;
//   - monitors stays a LINK to the protected seed route; machinery stays OUT (OQ-2 unruled).
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const SCHEMA_DIR = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validateWorkflowTemplate = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "workflow-template.v1.schema.json"), "utf8")));
const validateAutomationSpec = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "automation-spec.v1.schema.json"), "utf8")));
const validateAutomationInstallation = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "automation-installation-binding.v1.schema.json"), "utf8")));
const validateAutomationRun = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "automation-run.v1.schema.json"), "utf8")));

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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-automations-journey-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const SEED_LANE = "/__ioi/automations"; // the T2 cockpit's own wired action lanes (seed truth)
const FRESH_LANE = "/__ioi/automations-cockpit"; // E7-RETIRED lane — probed only to prove it serves no surface

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

// Daemon JSON — cookie=true carries the operator session (the probe rows judge the difference).
const jd = (p, init, cookie = true) => fetch(`${DAEMON}${p}`, {
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  ...init,
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

// A served page, optionally with the operator session.
const pageText = (p, { authenticated = true } = {}) => fetch(`${SERVE}${p}`, {
  headers: authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
}).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }))
  .catch(() => ({ status: 0, text: "", headers: new Headers() }));

// A form POST on a seed cockpit lane (the wiring the rendered verbs use) — redirect captured.
async function seedPost(tail, fields, { authenticated = true, json = null } = {}) {
  const r = await fetch(`${SERVE}${SEED_LANE}${tail}`, {
    method: "POST",
    headers: {
      "content-type": json ? "application/json" : "application/x-www-form-urlencoded",
      ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    },
    body: json ? JSON.stringify(json) : new URLSearchParams(fields).toString(),
    redirect: "manual",
  }).catch(() => null);
  return { status: r?.status ?? 0, location: r?.headers?.get("location") || "" };
}

const specGet = async (id) => (await jd(`/v1/hypervisor/automations/${encodeURIComponent(id)}`)).body;

function automationFamilyRoutes(index) {
  return (index.families ?? [])
    .flatMap((family) => family.paths ?? [])
    .filter((row) => [
      "/v1/hypervisor/automations",
      "/v1/hypervisor/automation-executions",
      "/v1/hypervisor/workflow-templates",
      "/v1/hypervisor/automation-specs",
      "/v1/hypervisor/automation-installations",
      "/v1/hypervisor/automation-runs",
    ].some((prefix) => row.path.startsWith(prefix)))
    .map((row) => ({ path: row.path, methods: [...row.methods].sort() }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

// Scheduler-health data markers that must NEVER render on this surface (Operations owns them).
const SCHEDULER_HEALTH_TOKENS = ["tick_seq", "last_tick_at", "no_heartbeat_recorded", "liveness", "misfire", "scheduler-heartbeat"];
const rendersNoSchedulerHealth = (text) => SCHEDULER_HEALTH_TOKENS.every((t) => !text.includes(t));

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "automations-journey-bootstrap-v1", email: "automations-journey@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // -- TYPED ABSENCE (mechanical): the owned verb set is pinned EXACTLY -------
  const index = await jd("/v1");
  const familyRoutes = automationFamilyRoutes(index.body);
  const expectedRoutes = [
    { path: "/v1/hypervisor/automation-executions/:id", methods: ["GET"] },
    { path: "/v1/hypervisor/automation-executions/:id/cancel", methods: ["POST"] },
    { path: "/v1/hypervisor/automations", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/automations/:id", methods: ["DELETE", "GET", "PATCH"] },
    { path: "/v1/hypervisor/automations/:id/runs", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/automations/:id/start", methods: ["POST"] },
    { path: "/v1/hypervisor/automations/:id/webhook", methods: ["POST"] },
    { path: "/v1/hypervisor/automations/:id/webhook-events", methods: ["GET"] },
    { path: "/v1/hypervisor/automations/:id/webhook-rotate", methods: ["POST"] },
    { path: "/v1/hypervisor/workflow-templates", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/workflow-templates/:id/revisions", methods: ["POST"] },
    { path: "/v1/hypervisor/automation-specs", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/automation-specs/:id/revisions", methods: ["POST"] },
    { path: "/v1/hypervisor/automation-installations", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/automation-installations/:id/revisions", methods: ["POST"] },
    { path: "/v1/hypervisor/automation-runs", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/automation-runs/:id", methods: ["GET"] },
  ].sort((left, right) => left.path.localeCompare(right.path));
  ok("owned-verb inventory pinned: the mutable predecessor executor remains explicit while the canonical family separately owns immutable template/spec revisions, successor-only installations, and frozen runs",
    JSON.stringify(familyRoutes) === JSON.stringify(expectedRoutes)
      && !JSON.stringify(index.body).includes("/v1/hypervisor/automations/:id/versions")
      && !JSON.stringify(index.body).includes("/v1/hypervisor/automations/:id/activate"),
    JSON.stringify(familyRoutes.map((r) => r.path)));

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
  await waitFor(`${SERVE}/automations`, 30000);

  // -- canonical mount: rehomed grammar, honest-empty, boundaries held --------
  // GRE-2 AUT-3 (owner go 2026-08-20): canonical /automations is a TRANSFER — nav lands on the
  // designated Automate shell (E1/E7); the redirect is asserted both raw (302 + transfer header)
  // and followed (the Automate shell renders). E7 (2026-08-20): the cockpit module that used to
  // serve the rehomed grammar on FRESH_LANE was retired — that lane is now asserted EMPTY below.
  const rawT = await fetch(`${SERVE}/automations`, { redirect: "manual" }).then((r) => ({ status: r.status, loc: r.headers.get("location"), tag: r.headers.get("x-ioi-gre2-transfer") })).catch(() => ({ status: 0 }));
  ok("canonical /automations is the GRE-2 transfer: 302 → the designated Automate landing, transfer-tagged",
    rawT.status === 302 && rawT.loc === "/__ioi/automations/monitors" && rawT.tag === "/automations",
    `status ${rawT.status} loc ${rawT.loc}`);
  const landingFollowed = await pageText("/automations");
  ok("followed, the canonical click lands on the Automate shell (the modified seed — E7)",
    landingFollowed.status === 200 && landingFollowed.text.includes("Automate") && landingFollowed.text.includes("mon-tabs"),
    String(landingFollowed.status));
  // E7 COCKPIT RETIREMENT (2026-08-20): the bound Automations cockpit module and its
  // /__ioi/automations-cockpit lane were removed with their registry row, so the five assertions
  // that read THAT MODULE'S rendered page are gone with it. Every assertion that survives here has
  // a LIVE subject: the designated Automate landing (above), the T2 cockpit at /__ioi/automations
  // which owns the family's real action lanes (below, and every crossing in this file already
  // posts to it), and the daemon automations family itself.
  const seedReadout = await pageText(SEED_LANE);
  const seedMonitors = await pageText("/__ioi/automations/monitors");
  ok("the LIVE Automations lanes serve: the T2 cockpit (the family's own action-lane owner) and the protected monitors seed",
    seedReadout.status === 200 && seedReadout.text.includes("Automations") && seedMonitors.status === 200,
    `statuses ${seedReadout.status}/${seedMonitors.status}`);
  // The Operations boundary, asserted of the LIVE surface as the live surface actually holds it:
  // the T2 cockpit renders NO scheduler-health data at all. (The retired module additionally named
  // the boundary with a link to /__ioi/operations; the seed never carried that affordance, so the
  // link half is NOT asserted here — asserting it would be inventing a claim about a live surface
  // rather than checking one. Operations owns scheduler health and check:operational-depth-era
  // coverage of that surface lives with Operations, not here.)
  ok("the LIVE T2 cockpit renders NO scheduler-health data — the Operations-owned boundary holds by absence, never by a duplicated read",
    rendersNoSchedulerHealth(seedReadout.text),
    "");
  ok("the retired /__ioi/automations-cockpit lane serves NO surface — it carries no registry ownership marker, so it is not a registered surface any more",
    await (async () => {
      const gone = await pageText(FRESH_LANE);
      return !gone.headers.get("x-ioi-surface-owner") && !gone.headers.get("x-ioi-surface-route");
    })(),
    FRESH_LANE);

  // -- a real project (the automation's REQUIRED durable container) -----------
  const created = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}) },
    body: JSON.stringify({ name: "automations-journey", initializer: { specs: [{ git: { remoteUri: "https://example.invalid/automations/journey.git" } }] } }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  const projectId = created.body?.project?.id || created.body?.project?.projectId || "";
  ok("a real project admits as the durable container", created.status === 200 && projectId.length > 0, projectId || `status ${created.status}`);
  const noProject = await jd("/v1/hypervisor/automations", { method: "POST", body: JSON.stringify({ name: "orphan" }) });
  ok("a container-less create refuses TYPED (automation_project_ref_required — the project linkage is the family's own rule)",
    noProject.status === 400 && noProject.body?.error?.code === "automation_project_ref_required",
    `${noProject.status}/${noProject.body?.error?.code}`);

  // -- identity gate (#237 finding CLOSED — next-legs III Leg 1): writes are identity-first ---
  const anonCreate = await jd("/v1/hypervisor/automations", {
    method: "POST",
    body: JSON.stringify({ project_ref: projectId, name: "anon-posture-probe", steps: [] }),
  }, false);
  const listAfterAnon = await jd("/v1/hypervisor/automations");
  ok("GATE: an anonymous direct daemon create refuses TYPED (401 request_principal_required) — never a silent success — and state is proven unchanged (no spec admitted)",
    anonCreate.status === 401 && anonCreate.body?.code === "request_principal_required"
      && (listAfterAnon.body?.automations || []).length === 0,
    `${anonCreate.status}/${anonCreate.body?.code} · ${(listAfterAnon.body?.automations || []).length} specs`);
  const anonNoProject = await jd("/v1/hypervisor/automations", {
    method: "POST",
    body: JSON.stringify({ name: "orphan-anon" }),
  }, false);
  ok("GATE rule E: identity is owed FIRST — an anonymous container-less create answers the 401, never the 400 project_ref field error (no field-shape probe exists for anonymous callers)",
    anonNoProject.status === 401 && anonNoProject.body?.code === "request_principal_required",
    `${anonNoProject.status}/${anonNoProject.body?.code}`);
  const anonPatch = await jd("/v1/hypervisor/automations/auto_absent", { method: "PATCH", body: JSON.stringify({ enabled: false }) }, false);
  const anonDelete = await jd("/v1/hypervisor/automations/auto_absent", { method: "DELETE" }, false);
  const anonRotate = await jd("/v1/hypervisor/automations/auto_absent/webhook-rotate", { method: "POST" }, false);
  const anonRun = await jd("/v1/hypervisor/automations/auto_absent/runs", { method: "POST", body: "{}" }, false);
  const anonCancel = await jd("/v1/hypervisor/automation-executions/aex_absent/cancel", { method: "POST" }, false);
  ok("GATE: every anonymous write verb refuses 401 request_principal_required BEFORE the record load (patch/delete/webhook-rotate/run-now/cancel) — the not-found reply is never an anonymous existence oracle",
    [anonPatch, anonDelete, anonRotate, anonRun, anonCancel].every((r) => r.status === 401 && r.body?.code === "request_principal_required"),
    JSON.stringify([anonPatch.status, anonDelete.status, anonRotate.status, anonRun.status, anonCancel.status]));
  const who = await jd("/v1/hypervisor/auth/whoami");
  const principalRef = who.body?.principal?.principal_ref
    || (who.body?.principal?.principal_id ? `user://${who.body.principal.principal_id}` : "");
  ok("the bootstrap session resolves a canonical principal ref (the binding subject for every INV-37 row below)",
    who.body?.authenticated === true && principalRef.startsWith("user://"),
    principalRef);

  // -- M04.2 canonical four-lifetime family ---------------------------------
  const graphHashV1 = `sha256:${"a".repeat(64)}`;
  const graphHashV2 = `sha256:${"b".repeat(64)}`;
  const forbiddenTemplateIdentity = await jd("/v1/hypervisor/workflow-templates", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: "forged identity",
      graph_ref: "workflow://graph/forged",
      graph_hash: graphHashV1,
      content_hash: graphHashV2,
    }),
  });
  ok("GATE: WorkflowTemplate identity and content hash are daemon-owned — a client-supplied content_hash refuses typed",
    forbiddenTemplateIdentity.status === 400
      && forbiddenTemplateIdentity.body?.error?.code === "automation_contract_unknown_field",
    `${forbiddenTemplateIdentity.status}/${forbiddenTemplateIdentity.body?.error?.code}`);
  const templateCreate = await jd("/v1/hypervisor/workflow-templates", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: "Journey directed work",
      version: "1.0.0",
      graph_ref: "workflow://graph/journey-v1",
      graph_hash: graphHashV1,
      required_primitive_capabilities: ["prim:process.execute"],
      registry_status: "released",
    }),
  });
  const templateV1 = templateCreate.body?.workflow_template || {};
  const templateTail = String(templateV1.workflow_template_id || "").replace("workflow-template://", "");
  ok("WorkflowTemplate admits as an immutable content-addressed directed-work revision with no trigger, grant, or run state",
    templateCreate.status === 201
      && /^workflow-template:\/\/[^/]+\/revision\/sha256:[a-f0-9]{64}$/.test(templateV1.revision_ref || "")
      && templateV1.content_hash?.startsWith("sha256:")
      && !["trigger", "authority_grant_ref", "status", "run_id"].some((key) => Object.hasOwn(templateV1, key)),
    templateV1.revision_ref || `status ${templateCreate.status}`);
  const specCreate = await jd("/v1/hypervisor/automation-specs", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: "Journey standing activation",
      workflow_template_revision_ref: templateV1.revision_ref,
      workflow_template_content_hash: templateV1.content_hash,
      activation_kind: "manual",
      concurrency_policy_ref: "policy://automation/concurrency/serial",
      idempotency_policy_ref: "policy://automation/idempotency/exact",
      authority_requirement_refs: ["scope:process.execute"],
      receipt_policy_ref: "policy://receipts/automation",
      registry_status: "released",
    }),
  });
  const specV1 = specCreate.body?.automation_spec || {};
  ok("AutomationSpec is a distinct immutable standing-activation revision bound to the exact template tuple",
    specCreate.status === 201
      && specV1.workflow_template_revision_ref === templateV1.revision_ref
      && specV1.workflow_template_content_hash === templateV1.content_hash
      && /^automation:\/\/[^/]+\/revision\/sha256:[a-f0-9]{64}$/.test(specV1.revision_ref || "")
      && !["enabled", "scope_ref", "status", "run_id"].some((key) => Object.hasOwn(specV1, key)),
    specV1.revision_ref || `status ${specCreate.status}`);
  const bindingCreate = await jd("/v1/hypervisor/automation-installations", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      scope_ref: principalRef,
      automation_spec_revision_ref: specV1.revision_ref,
      automation_spec_content_hash: specV1.content_hash,
      enabled: true,
      narrowed_activation_kinds: ["manual"],
      narrowed_authority_requirement_refs: ["scope:process.execute"],
      admission_receipt_ref: "receipt://automation-installation/journey-v1",
      registry_status: "released",
    }),
  });
  const bindingV1 = bindingCreate.body?.automation_installation_binding || {};
  const bindingTail = String(bindingV1.binding_id || "").split("/").at(-1) || "";
  ok("AutomationInstallationBinding is a third immutable lifetime: exact spec tuple plus local enablement and narrowing, never graph or trigger ownership",
    bindingCreate.status === 201
      && bindingV1.automation_spec_revision_ref === specV1.revision_ref
      && bindingV1.enabled === true
      && /^install:\/\/automation\/[^/]+\/revision\/sha256:[a-f0-9]{64}$/.test(bindingV1.revision_ref || "")
      && !["graph_ref", "trigger_contract_ref", "run_history"].some((key) => Object.hasOwn(bindingV1, key)),
    bindingV1.revision_ref || `status ${bindingCreate.status}`);
  const forgedRun = await jd("/v1/hypervisor/automation-runs", {
    method: "POST",
    body: JSON.stringify({
      automation_spec_revision_ref: specV1.revision_ref,
      automation_spec_content_hash: graphHashV2,
      automation_installation_binding_revision_ref: bindingV1.revision_ref,
      automation_installation_binding_hash: bindingV1.binding_hash,
      activation_kind: "manual",
    }),
  });
  ok("GATE: an AutomationRun refuses a mismatched exact spec hash before minting a run identity",
    forgedRun.status === 409 && forgedRun.body?.error?.code === "automation_run_resolution_hash_mismatch",
    `${forgedRun.status}/${forgedRun.body?.error?.code}`);
  const runCreate = await jd("/v1/hypervisor/automation-runs", {
    method: "POST",
    body: JSON.stringify({
      automation_spec_revision_ref: specV1.revision_ref,
      automation_spec_content_hash: specV1.content_hash,
      automation_installation_binding_revision_ref: bindingV1.revision_ref,
      automation_installation_binding_hash: bindingV1.binding_hash,
      activation_kind: "manual",
      activation_event_ref: "event://automation/journey-manual",
    }),
  });
  const canonicalRun = runCreate.body?.automation_run || {};
  const canonicalRunTail = String(canonicalRun.automation_run_ref || "").replace("automation-run://", "");
  const frozenTuple = JSON.stringify({
    template: [canonicalRun.workflow_template_revision_ref, canonicalRun.workflow_template_content_hash],
    spec: [canonicalRun.automation_spec_revision_ref, canonicalRun.automation_spec_content_hash],
    binding: [canonicalRun.automation_installation_binding_revision_ref, canonicalRun.automation_installation_binding_hash],
    receipt: canonicalRun.resolution_receipt,
  });
  ok("AutomationRun is the fourth lifetime: admission freezes the exact template, spec, and binding tuple in one resolution receipt",
    runCreate.status === 201
      && canonicalRun.status === "queued"
      && canonicalRun.workflow_template_revision_ref === templateV1.revision_ref
      && canonicalRun.automation_spec_revision_ref === specV1.revision_ref
      && canonicalRun.automation_installation_binding_revision_ref === bindingV1.revision_ref
      && canonicalRun.resolution_receipt?.receipt_type === "automation_run_resolution"
      && canonicalRun.resolution_receipt?.material?.automation_run_ref === canonicalRun.automation_run_ref,
    canonicalRun.automation_run_ref || `status ${runCreate.status}`);
  const anonymousCanonicalReads = await Promise.all([
    jd("/v1/hypervisor/workflow-templates", undefined, false),
    jd("/v1/hypervisor/automation-specs", undefined, false),
    jd("/v1/hypervisor/automation-installations", undefined, false),
    jd("/v1/hypervisor/automation-runs", undefined, false),
    jd(`/v1/hypervisor/automation-runs/${encodeURIComponent(canonicalRunTail)}`, undefined, false),
  ]);
  ok("GATE: canonical definition, installation, and run reads are identity-first — anonymous callers receive no list or exact-run existence oracle",
    anonymousCanonicalReads.every((response) => response.status === 401
      && response.body?.error?.code === "request_principal_required"),
    JSON.stringify(anonymousCanonicalReads.map((response) => [response.status, response.body?.error?.code])));
  const contractValidations = [
    ["WorkflowTemplate", validateWorkflowTemplate, templateV1],
    ["AutomationSpec", validateAutomationSpec, specV1],
    ["AutomationInstallationBinding", validateAutomationInstallation, bindingV1],
    ["AutomationRun", validateAutomationRun, canonicalRun],
  ];
  ok("all four live runtime records validate against their registered generated architecture contracts",
    contractValidations.every(([, validate, value]) => validate(value)),
    contractValidations.flatMap(([name, validate]) => (validate.errors || []).map((error) => `${name}${error.instancePath} ${error.message}`)).join("; "));
  ok("receipt honesty: the admitted run carries no fabricated Agentgres operation or concrete grant/lease",
    Array.isArray(canonicalRun.agentgres_operation_refs) && canonicalRun.agentgres_operation_refs.length === 0
      && Array.isArray(canonicalRun.authority_lease_refs) && canonicalRun.authority_lease_refs.length === 0
      && !JSON.stringify(canonicalRun).includes("authority_grant_ref"));

  const templateSuccessor = await jd(`/v1/hypervisor/workflow-templates/${encodeURIComponent(templateTail)}/revisions`, {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: "Journey directed work",
      version: "2.0.0",
      graph_ref: "workflow://graph/journey-v2",
      graph_hash: graphHashV2,
      required_primitive_capabilities: ["prim:process.execute"],
      registry_status: "released",
    }),
  });
  const templateV2 = templateSuccessor.body?.workflow_template || {};
  const runAfterTemplateEdit = await jd(`/v1/hypervisor/automation-runs/${encodeURIComponent(canonicalRunTail)}`);
  ok("editing a template creates a successor revision and cannot rewrite the already-admitted run tuple",
    templateSuccessor.status === 201
      && templateV2.predecessor_revision_ref === templateV1.revision_ref
      && templateV2.revision_ref !== templateV1.revision_ref
      && JSON.stringify({
        template: [runAfterTemplateEdit.body?.automation_run?.workflow_template_revision_ref, runAfterTemplateEdit.body?.automation_run?.workflow_template_content_hash],
        spec: [runAfterTemplateEdit.body?.automation_run?.automation_spec_revision_ref, runAfterTemplateEdit.body?.automation_run?.automation_spec_content_hash],
        binding: [runAfterTemplateEdit.body?.automation_run?.automation_installation_binding_revision_ref, runAfterTemplateEdit.body?.automation_run?.automation_installation_binding_hash],
        receipt: runAfterTemplateEdit.body?.automation_run?.resolution_receipt,
      }) === frozenTuple,
    `${templateV1.revision_ref} -> ${templateV2.revision_ref}`);

  const bindingSuccessor = await jd(`/v1/hypervisor/automation-installations/${encodeURIComponent(bindingTail)}/revisions`, {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      scope_ref: principalRef,
      automation_spec_revision_ref: specV1.revision_ref,
      automation_spec_content_hash: specV1.content_hash,
      enabled: false,
      narrowed_activation_kinds: ["manual"],
      narrowed_authority_requirement_refs: ["scope:process.execute"],
      admission_receipt_ref: "receipt://automation-installation/journey-disabled",
      registry_status: "released",
    }),
  });
  const bindingV2 = bindingSuccessor.body?.automation_installation_binding || {};
  const oldBindingRun = await jd("/v1/hypervisor/automation-runs", {
    method: "POST",
    body: JSON.stringify({
      automation_spec_revision_ref: specV1.revision_ref,
      automation_spec_content_hash: specV1.content_hash,
      automation_installation_binding_revision_ref: bindingV1.revision_ref,
      automation_installation_binding_hash: bindingV1.binding_hash,
      activation_kind: "manual",
    }),
  });
  const disabledBindingRun = await jd("/v1/hypervisor/automation-runs", {
    method: "POST",
    body: JSON.stringify({
      automation_spec_revision_ref: specV1.revision_ref,
      automation_spec_content_hash: specV1.content_hash,
      automation_installation_binding_revision_ref: bindingV2.revision_ref,
      automation_installation_binding_hash: bindingV2.binding_hash,
      activation_kind: "manual",
    }),
  });
  ok("successor-only local disablement is effective: the superseded enabled binding and its disabled successor both refuse new runs",
    bindingSuccessor.status === 201
      && bindingV2.predecessor_revision_ref === bindingV1.revision_ref
      && oldBindingRun.status === 409 && oldBindingRun.body?.error?.code === "automation_run_installation_superseded"
      && disabledBindingRun.status === 409 && disabledBindingRun.body?.error?.code === "automation_run_installation_ineligible",
    `${oldBindingRun.body?.error?.code}/${disabledBindingRun.body?.error?.code}`);

  // -- create through the served grammar (session-carried), round-trip readback
  const createRes = await seedPost("", {
    project_ref: projectId,
    name: "journey-nightly",
    description: "journey spec",
    schedule_type: "interval",
    interval_n: "5",
    interval_unit: "minutes",
    step_kind: "command",
    step_body: "echo journey-effect",
    max_concurrency: "1",
    failure_policy: "continue",
  });
  const automationId = decodeURIComponent((createRes.location.split("/").at(-1) || "").split("?")[0]);
  ok("create crosses through the seed cockpit lane with the session cookie (302 → the new spec)",
    createRes.status === 302 && automationId.startsWith("auto_"),
    createRes.location.slice(0, 100));
  let spec = await specGet(automationId);
  ok("trigger/condition/effect ROUND-TRIP exactly as the family stores them: trigger_kind time + schedule_spec {every_minutes:5} (the condition) + steps [{kind:command}] (the effect) + project linkage",
    spec.ok === true
      && spec.automation?.trigger_kind === "time"
      && JSON.stringify(spec.automation?.schedule_spec) === JSON.stringify({ every_minutes: 5 })
      && Array.isArray(spec.automation?.steps) && spec.automation.steps.length === 1
      && spec.automation.steps[0].kind === "command" && spec.automation.steps[0].command === "echo journey-effect"
      && spec.automation?.enabled === true
      && (spec.automation?.project_ref === projectId || spec.automation?.project_id === projectId),
    JSON.stringify({ trigger: spec.automation?.trigger_kind, sched: spec.automation?.schedule_spec }));
  ok("spec mutations answer WITHOUT an admission receipt — the named W2 defect is current daemon truth (asserted, not styled around)",
    spec.ok === true && !JSON.stringify(spec).includes("receipt_ref") && !JSON.stringify(spec).includes("agentgres"),
    "");
  ok("INV-37: the stored spec binds the RESOLVED creating principal — acting_principal_ref names the bootstrap principal and executor_identity defaults to it (never the operator literal)",
    spec.automation?.acting_principal_ref === principalRef
      && spec.automation?.executor_identity?.kind === "user"
      && spec.automation?.executor_identity?.ref === principalRef,
    JSON.stringify({ acting: spec.automation?.acting_principal_ref, executor: spec.automation?.executor_identity }));

  // -- anonymous serve-lane action: the typed refusal SURFACES (no blind 302) --
  const anonServeRun = await fetch(`${SERVE}${SEED_LANE}/${encodeURIComponent(automationId)}/run`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "",
    redirect: "manual",
  }).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const runsAfterAnonServe = (await jd(`/v1/hypervisor/automations/${encodeURIComponent(automationId)}/runs`)).body?.runs || [];
  ok("GATE: an anonymous serve-lane action (Run now with no session) surfaces the daemon's typed refusal — 401 with the machine-readable request_principal_required marker, and NO run was recorded",
    anonServeRun.status === 401
      && anonServeRun.text.includes('data-ioi-refusal-code="request_principal_required"')
      && runsAfterAnonServe.length === 0,
    `status ${anonServeRun.status} · ${runsAfterAnonServe.length} runs`);

  // E7 (2026-08-20): the three render assertions that read the RETIRED cockpit module's list and
  // detail pages went with the module. The crossings below are unchanged — every one of them
  // already posted to the LIVE seed cockpit's own action lanes (SEED_LANE), and every one is
  // proven by a DAEMON readback, which is the load-bearing half.

  // -- daemon typed absences probed directly ----------------------------------
  const versions = await jd(`/v1/hypervisor/automations/${encodeURIComponent(automationId)}/versions`);
  const activate = await jd(`/v1/hypervisor/automations/${encodeURIComponent(automationId)}/activate`, { method: "POST", body: "{}" });
  ok("version/revision family ABSENT at the daemon — typed 404, never simulated", versions.status === 404, `status ${versions.status}`);
  ok("no separate activate route — typed 404 (activation IS `PATCH {enabled}`, the family's own lane)", activate.status === 404, `status ${activate.status}`);

  // -- pause / resume journey (the PATCH {enabled} lane) ----------------------
  const paused = await seedPost(`/${encodeURIComponent(automationId)}/pause`, {});
  spec = await specGet(automationId);
  ok("pause crosses (302) and reads back: enabled false + next_run_at reset (the scheduler skips disabled specs)",
    paused.status === 302 && spec.automation?.enabled === false && spec.automation?.next_run_at === null,
    `enabled ${spec.automation?.enabled}`);
  const resumed = await seedPost(`/${encodeURIComponent(automationId)}/resume`, {});
  spec = await specGet(automationId);
  ok("resume crosses (302) and reads back enabled true", resumed.status === 302 && spec.automation?.enabled === true, "");

  // -- run now: a REAL execution over a REAL environment ----------------------
  const ran = await seedPost(`/${encodeURIComponent(automationId)}/run`, {});
  let runs = [];
  for (let attempt = 0; attempt < 20; attempt++) {
    runs = (await jd(`/v1/hypervisor/automations/${encodeURIComponent(automationId)}/runs`)).body?.runs || [];
    if (runs.length && ["done", "failed", "stopped"].includes(runs[0]?.status)) break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  const exec = runs[0] || {};
  ok("run-now crosses through the seed lane and run HISTORY records the execution: terminal `done`, 1 step done, a real environment_id",
    ran.status === 302 && exec.status === "done" && exec.counts?.done === 1 && String(exec.environment_id || "").length > 0,
    JSON.stringify({ status: exec.status, counts: exec.counts }));
  ok("INV-37: the recorded execution binds the acting principal — the manual run's acting_principal_ref is the resolved session principal and executor_identity rides the spec's principal-bound identity (never the operator literal)",
    exec.acting_principal_ref === principalRef && exec.executor_identity?.ref === principalRef,
    JSON.stringify({ acting: exec.acting_principal_ref, executor: exec.executor_identity }));
  const execRead = await jd(`/v1/hypervisor/automation-executions/${encodeURIComponent(exec.execution_id || "")}`);
  ok("the execution readback route answers the same record (the run drawer's read)",
    execRead.body?.ok === true && execRead.body?.execution?.status === "done",
    "");
  const ledger = await jd("/v1/hypervisor/work-ledger");
  const ledgerEntries = Array.isArray(ledger.body) ? ledger.body : (ledger.body?.entries || ledger.body?.work_ledger || []);
  const ledgerHit = ledgerEntries.find((e) => JSON.stringify(e).includes(exec.execution_id || "@"));
  ok("the unified proof stream carries the run with its transcript state_root (readback proof — the family's real evidence lane)",
    !!ledgerHit && JSON.stringify(ledgerHit).includes("state_root"),
    "");

  // -- webhook: rotate (hash-at-rest) + rejected trigger is a RECEIPTED event -
  const rotated = await jd(`/v1/hypervisor/automations/${encodeURIComponent(automationId)}/webhook-rotate`, { method: "POST" });
  const webhookToken = rotated.body?.webhook_token || "";
  spec = await specGet(automationId);
  ok("webhook-rotate mints a show-once token: plaintext returned exactly once, only its hash persists on the spec",
    webhookToken.length > 20 && !!spec.automation?.webhook_token_hash
      && !!spec.automation?.webhook_url && !JSON.stringify(spec).includes(webhookToken),
    "");
  const badTrigger = await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(automationId)}/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "X-IOI-Trigger-Token": "bogus-token" },
    body: JSON.stringify({ event: "ping" }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  const events = await jd(`/v1/hypervisor/automations/${encodeURIComponent(automationId)}/webhook-events`);
  const rejectedEvent = (events.body?.events || []).find((e) => e.accepted === false);
  ok("a bad-token webhook trigger refuses TYPED (401 invalid_token) and the refusal is a RECEIPTED audit event",
    badTrigger.status === 401 && badTrigger.body?.reason === "invalid_token"
      && !!rejectedEvent && !!rejectedEvent.receipt_id && events.body?.rejected_count === 1,
    JSON.stringify({ status: badTrigger.status, receipt: rejectedEvent?.receipt_id }));

  // -- delete journey (throwaway spec — the canonical page stays honest after)
  const throwaway = await jd("/v1/hypervisor/automations", {
    method: "POST",
    body: JSON.stringify({ project_ref: projectId, name: "journey-throwaway", steps: [] }),
  });
  const throwawayId = throwaway.body?.automation?.automation_id || "";
  const deleted = await seedPost(`/${encodeURIComponent(throwawayId)}/delete`, {});
  const deletedGet = await specGet(throwawayId);
  ok("delete crosses through the seed lane and the record is GONE — daemon readback ok:false (nothing inferred)",
    throwaway.status === 201 && deleted.status === 302 && deletedGet.ok === false,
    `create ${throwaway.status} · delete ${deleted.status} · readback ok=${deletedGet.ok}`);

  // -- restart: the spec + its history survive and the mount re-renders -------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  spec = await specGet(automationId);
  const runsAfter = (await jd(`/v1/hypervisor/automations/${encodeURIComponent(automationId)}/runs`)).body?.runs || [];
  ok("the spec survives a daemon restart with its exact fields (schedule, steps, webhook posture) and its run history intact",
    spec.ok === true && JSON.stringify(spec.automation?.schedule_spec) === JSON.stringify({ every_minutes: 5 })
      && spec.automation?.steps?.[0]?.command === "echo journey-effect"
      && !!spec.automation?.webhook_token_hash
      && runsAfter.some((r) => r.execution_id === exec.execution_id),
    "");
  const canonicalRunAfterRestart = await jd(`/v1/hypervisor/automation-runs/${encodeURIComponent(canonicalRunTail)}`);
  ok("the canonical AutomationRun and its exact four-lifetime resolution receipt survive daemon restart byte-for-byte",
    canonicalRunAfterRestart.status === 200
      && JSON.stringify({
        template: [canonicalRunAfterRestart.body?.automation_run?.workflow_template_revision_ref, canonicalRunAfterRestart.body?.automation_run?.workflow_template_content_hash],
        spec: [canonicalRunAfterRestart.body?.automation_run?.automation_spec_revision_ref, canonicalRunAfterRestart.body?.automation_run?.automation_spec_content_hash],
        binding: [canonicalRunAfterRestart.body?.automation_run?.automation_installation_binding_revision_ref, canonicalRunAfterRestart.body?.automation_run?.automation_installation_binding_hash],
        receipt: canonicalRunAfterRestart.body?.automation_run?.resolution_receipt,
      }) === frozenTuple,
    `status ${canonicalRunAfterRestart.status}`);
  // Re-aimed at the LIVE surface (E7): the retired module's mount is gone, so the render half of
  // restart survival is asserted where the family actually serves today — the T2 cockpit's own
  // detail lane, which is where every crossing above redirects back to.
  let reload = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    await new Promise((r) => setTimeout(r, 1500));
    reload = await pageText(`${SEED_LANE}/${encodeURIComponent(automationId)}`);
    if (reload.status === 200 && reload.text.includes("journey-nightly")) break;
  }
  ok("the LIVE Automations cockpit re-renders the surviving spec after restart",
    reload.status === 200 && reload.text.includes("journey-nightly"),
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
      const resp = await page.goto(`${SERVE}/automations`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
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
  emitVerifierCensus({ verifierId: "automations-journey", sourceUrl: import.meta.url, results });
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
