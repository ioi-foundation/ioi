#!/usr/bin/env node
// check:context-lease-handoff-lifecycle — M04.11, against an ISOLATED real daemon.
//
// The unit's claim is that context is a LEASED resource rather than a copied one, so almost every
// clause here is a refusal: a lease narrows and never widens, a revoked lease resolves nothing, a
// handoff moves a packet and never authority, and the privacy dimensions the unit's own check text
// names are INHERITED from the bound PolicyBoundDataView revision and the InformationFlowLabel
// rather than declared on the lease. Canon: goal-run-execution.md § ContextLeaseEnvelope /
// § ContextHandoffEnvelope; execution-context-and-step-resolution.md § InformationFlowLabel and
// DeclassificationApproval, whose owner forbids parallel privacy objects at this seam.
//
// THE ORACLE IS INDEPENDENT. `receipt_root` is re-derived HERE, in JavaScript, as canon defines it —
// SHA-256 over JCS of every field except `receipt_root` — and compared with the daemon's own number.
// Reading the daemon's hash back and calling it verified would be asking the committer whether it
// committed. The self-drill plants a change in the re-derived copy and requires this verifier's own
// oracle to notice, because an oracle that cannot fail is not one.
//
// "NO EFFECT ANYWHERE" IS MEASURED, NOT ASSERTED. Every other observable family is read before and
// after an admission and required to be byte-identical, and the self-drill plants a real record
// between the two reads so a comparison of two empty sets cannot pass for the wrong reason.
//
// WHAT THIS VERIFIER DOES NOT CLAIM, and says so as an executed assertion rather than in a comment:
// the unit's check text asks for the negative matrix "across native and MCP paths". The daemon's MCP
// surface is a CLOSED TOOL SET (`/v1/hypervisor/mcp-gateway/tools`), and no tool reaches the context
// families — so there is no MCP path to these routes to refuse anything on. Asserting MCP refusals
// by probing a path the family never used is the defect `check:named-gap-truth` polices, so this
// verifier asserts the structural fact instead and names M01.10/M01.11 as the owners of the MCP
// half. The producer clause is the same kind of honesty: a GoalRun cannot be created without the
// activation crossing (a direct create refuses `goal_run_activation_required_for_origin`), so the
// lane that MINTS a lease is driven by `check:m4-goalrun-activation-plane`, which the unit's check
// text runs beside this one.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   --mutation  run the planted defects instead of trusting the assertions above.
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const DRILL = process.argv.includes("--mutation");

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });

const LEASE_SCHEMA_VERSION = "ioi.context-lease.v1";
const HANDOFF_SCHEMA_VERSION = "ioi.context-handoff.v1";

/** RFC 8785 JCS for the JSON subset these records use: sorted keys, minimal separators. */
const jcs = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
};

/**
 * The receipt root, computed HERE and never read back from the record that carries it: canon says
 * "SHA-256 over JCS of every field above except `receipt_root`", so the field is removed and the
 * remainder hashed. A verifier that imported the daemon's own sealing helper would agree with it by
 * construction.
 */
const deriveReceiptRoot = (record) => {
  const material = { ...record };
  delete material.receipt_root;
  return `sha256:${createHash("sha256").update(jcs(material)).digest("hex")}`;
};

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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-context-lease-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let SESSION = "";
let OWNER = "";
let daemonLog = "";

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
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
}

const stopDaemon = async () => {
  if (!daemon) return;
  daemon.kill("SIGTERM");
  await new Promise((resolve) => {
    const done = setTimeout(() => { daemon.kill("SIGKILL"); resolve(); }, 8000);
    daemon.on("exit", () => { clearTimeout(done); resolve(); });
  });
  daemon = null;
};

const jd = (p, init = {}, { authenticated = true } = {}) => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: {
    "content-type": "application/json",
    ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    ...(init.headers || {}),
  },
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const code = (body) => body?.error ?? body?.code ?? body?.error?.code ?? "";

const GOAL_RUN = "gr_ctx_lease_1";
const base = `/v1/goal-orchestration/goal-runs/${GOAL_RUN}`;
const CELL = `context-cell://cc_${GOAL_RUN}_implementer`;
const REVIEWER_CELL = `context-cell://cc_${GOAL_RUN}_reviewer`;

const leaseBody = (key, overrides = {}) => ({
  context_lease_id: `context-lease://cl_${GOAL_RUN}_${key}`,
  context_cell_ref: CELL,
  issued_to_ref: CELL,
  lease_kind: "worktree",
  allowed_ref_patterns: [`workspace://goal-run/${GOAL_RUN}/implementer`],
  denied_ref_patterns: ["secret://", "unsafe_plaintext://"],
  authority_scope_refs: ["policy://ioi/least-context/1"],
  budget_ref: `budget://goal-run/${GOAL_RUN}/invocation`,
  ttl_seconds: 3600,
  receipt_required: true,
  leased_refs: [`workspace://goal-run/${GOAL_RUN}/implementer`],
  information_flow_label_refs: ["ifc-label://ioi/internal-untrusted/1"],
  permitted_recipient_roles: ["implementer"],
  owner_ref: OWNER,
  idempotency_key: `ctx-lease-${key}`,
  ...overrides,
});

const handoffBody = (key, overrides = {}) => ({
  handoff_id: `handoff://ho_${GOAL_RUN}_${key}`,
  from_context_cell_ref: CELL,
  to_context_cell_ref: REVIEWER_CELL,
  handoff_kind: "review_request",
  payload_ref: `implementation-result://ir_${GOAL_RUN}_${key}`,
  context_lease_refs: [],
  acceptance_refs: ["rubric://ioi/review/1"],
  receipt_refs: [],
  owner_ref: OWNER,
  idempotency_key: `ctx-handoff-${key}`,
  ...overrides,
});

// Families read before and after an admission: the unit's scope says payload bytes, views,
// artifacts, memory projections, Sessions, HarnessInvocations and authority stay with their owners,
// so a lease admission must leave every one of them untouched.
const OBSERVED = [
  "/v1/hypervisor/sessions",
  "/v1/hypervisor/policy-bound-data-views",
  "/v1/hypervisor/model-routes",
  "/v1/hypervisor/connectors",
  "/v1/goal-orchestration/goal-runs",
];
const snapshot = async () => {
  const out = {};
  for (const route of OBSERVED) {
    const r = await jd(route);
    // The top-level envelope stamp is generation time, not state (a recorded trap): strip it.
    const body = r.body && typeof r.body === "object" ? { ...r.body } : r.body;
    if (body && typeof body === "object") delete body.at;
    out[route] = `${r.status}:${jcs(body ?? null)}`;
  }
  return out;
};
const drifted = (before, after) => OBSERVED.filter((route) => before[route] !== after[route]);

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();

  // -- identity ----------------------------------------------------------------------------------
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "context-lease-bootstrap-v1", email: "context-lease@ioi.local" }),
    }, { authenticated: false });
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  ok("the session authenticates a principal with an owner tenant to admit under", !!OWNER, OWNER || "no owner tenant");

  // -- identity is the first gate, before any content complaint -----------------------------------
  const anon = await jd(`${base}/context-leases`, { method: "POST", body: JSON.stringify(leaseBody("anon")) }, { authenticated: false });
  ok("an unauthenticated lease admission refuses BEFORE any field complaint (401, not a shape error)",
    anon.status === 401 && !/leased_refs|issued_to_ref|schema_version/iu.test(JSON.stringify(anon.body)),
    `${anon.status} ${code(anon.body)}`);

  // -- create, and the INDEPENDENT oracle ---------------------------------------------------------
  const beforeAdmit = await snapshot();
  const admitted = await jd(`${base}/context-leases`, { method: "POST", body: JSON.stringify(leaseBody("a")) });
  const lease = admitted.body?.context_lease ?? {};
  ok("a well-formed lease admits as a registered record", admitted.status === 201 && lease.schema_version === LEASE_SCHEMA_VERSION,
    `${admitted.status} ${code(admitted.body)}`);
  const derived = deriveReceiptRoot(lease);
  ok("the lease's receipt_root RE-DERIVES here from its own fields — canon's SHA-256 over JCS of everything except the root itself",
    typeof lease.receipt_root === "string" && lease.receipt_root === derived,
    `${String(lease.receipt_root).slice(0, 24)} vs ${derived.slice(0, 24)}`);
  ok("the lease's subject and lineage are the DAEMON's, never the caller's (INV-37)",
    lease.work_subject_ref === `goal://${GOAL_RUN}` && lease.successor_of === null
      && lease.predecessor_remains_valid === false && lease.status === "active");
  ok("the lease is issued to a concrete CELL, which is what canon permits as a lease subject",
    lease.issued_to_ref === CELL, String(lease.issued_to_ref));
  const afterAdmit = await snapshot();
  ok("admitting a lease leaves every other observable family byte-identical — payload bytes, views, routes, connectors and runs stay with their owners",
    drifted(beforeAdmit, afterAdmit).length === 0, drifted(beforeAdmit, afterAdmit).join(", ") || "no drift");

  // -- the subject canon forbids, and the identity spellings it refuses ---------------------------
  const profileSubject = await jd(`${base}/context-leases`, {
    method: "POST",
    body: JSON.stringify(leaseBody("profile", { issued_to_ref: "harness-profile://ioi/claude-code" })),
  });
  ok("a lease issued to a reusable HarnessProfile is REFUSED — canon says only a concrete ContextCell or HarnessInvocation is a lease subject",
    profileSubject.status === 400 && code(profileSubject.body) === "context_lease_contract_invalid",
    `${profileSubject.status} ${code(profileSubject.body)}`);
  const legacyId = await jd(`${base}/context-leases`, {
    method: "POST",
    body: JSON.stringify(leaseBody("legacy", { context_lease_id: `context_lease://cl_${GOAL_RUN}_legacy` })),
  });
  ok("the legacy underscore identity is refused — the ref-scheme registry forbids emitting it",
    legacyId.status === 400 && code(legacyId.body) === "context_lease_id_not_canonical",
    `${legacyId.status} ${code(legacyId.body)}`);

  // -- the dimensions the lease INHERITS cannot be declared on it ---------------------------------
  for (const [field, value] of [["data_class", "confidential"], ["purpose", "hosted_training"], ["redaction_policy_ref", "policy://ioi/redact/1"]]) {
    const declared = await jd(`${base}/context-leases`, {
      method: "POST",
      body: JSON.stringify(leaseBody(`declares-${field}`, { [field]: value })),
    });
    ok(`a lease DECLARING \`${field}\` is refused by name — purpose, data class and redaction belong to the bound view revision and the label, and a lease that restated one could claim it WIDER than the view it leases`,
      declared.status === 400 && code(declared.body) === "context_request_unknown_field",
      `${declared.status} ${code(declared.body)}`);
  }

  // -- a view binding must name a REVISION --------------------------------------------------------
  const familyHead = await jd(`${base}/context-leases`, {
    method: "POST",
    body: JSON.stringify(leaseBody("head", { leased_refs: ["view://ioi/contacts"] })),
  });
  ok("a lease naming a view FAMILY HEAD is refused — a lease resolving through a moving head cannot reproduce the same least-context result after a restart",
    familyHead.status === 400 && code(familyHead.body) === "context_lease_contract_invalid",
    `${familyHead.status} ${code(familyHead.body)}`);
  const legacyView = await jd(`${base}/context-leases`, {
    method: "POST",
    body: JSON.stringify(leaseBody("legacy-view", { leased_refs: ["policy-bound-data-view://ioi/contacts/3"] })),
  });
  ok("a lease naming the predecessor's policy-bound-data-view:// spelling is refused where a revision is required",
    legacyView.status === 400 && code(legacyView.body) === "context_lease_contract_invalid",
    `${legacyView.status} ${code(legacyView.body)}`);

  // -- narrowing is SUBTRACTION ------------------------------------------------------------------
  const leaseId = String(lease.context_lease_id).replace("context-lease://", "");
  const narrowed = await jd(`${base}/context-leases/${leaseId}/narrow`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, permitted_recipient_roles: [], idempotency_key: "ctx-narrow-1" }),
  });
  const narrowedLease = narrowed.body?.context_lease ?? {};
  ok("narrowing admits a SUCCESSOR that names its predecessor and re-seals itself",
    narrowed.status === 200 && narrowedLease.successor_of === lease.context_lease_id
      && narrowedLease.receipt_root === deriveReceiptRoot(narrowedLease)
      && (narrowedLease.permitted_recipient_roles || []).length === 0,
    `${narrowed.status} ${code(narrowed.body)}`);

  for (const [member, widened] of [
    ["leased_refs", [`workspace://goal-run/${GOAL_RUN}/implementer`, "workspace://elsewhere"]],
    ["allowed_ref_patterns", [`workspace://goal-run/${GOAL_RUN}/implementer`, "workspace://elsewhere"]],
    ["authority_scope_refs", ["policy://ioi/least-context/1", "authority://ioi/extra"]],
    ["information_flow_label_refs", ["ifc-label://ioi/internal-untrusted/1", "ifc-label://ioi/public/1"]],
    ["permitted_recipient_roles", ["implementer", "reviewer"]],
  ]) {
    const attempt = await jd(`${base}/context-leases/${leaseId}/narrow`, {
      method: "POST",
      body: JSON.stringify({ owner_ref: OWNER, [member]: widened, idempotency_key: `ctx-widen-${member}` }),
    });
    ok(`widening \`${member}\` through a narrowing is refused by name — widening is a NEW binding on record, never a successor of this one`,
      attempt.status === 409 && code(attempt.body) === "context_lease_widened",
      `${attempt.status} ${code(attempt.body)}`);
  }
  const droppedDenial = await jd(`${base}/context-leases/${leaseId}/narrow`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, denied_ref_patterns: [], idempotency_key: "ctx-drop-denial" }),
  });
  ok("dropping a DENIAL is a widening too — reach grows by removal, not only by addition",
    droppedDenial.status === 409 && code(droppedDenial.body) === "context_lease_denial_dropped",
    `${droppedDenial.status} ${code(droppedDenial.body)}`);
  const extended = await jd(`${base}/context-leases/${leaseId}/narrow`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, ttl_seconds: 7200, idempotency_key: "ctx-ttl-extend" }),
  });
  ok("a narrowing cannot EXTEND the lease's ttl", extended.status === 409 && code(extended.body) === "context_lease_ttl_extended",
    `${extended.status} ${code(extended.body)}`);
  const unbounded = await jd(`${base}/context-leases/${leaseId}/narrow`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, ttl_seconds: null, idempotency_key: "ctx-ttl-unbound" }),
  });
  ok("a bounded lease cannot become UNBOUNDED through a narrowing",
    unbounded.status === 409 && code(unbounded.body) === "context_lease_ttl_removed",
    `${unbounded.status} ${code(unbounded.body)}`);

  // -- the least-context RESOLUTION, and what it says it inherits ---------------------------------
  const resolution = await jd(`${base}/context-leases/${leaseId}/resolution`);
  const view = resolution.body?.resolution ?? {};
  ok("the resolution is a READ MODEL that states its own nature and never persists",
    resolution.status === 200 && view.read_model_only === true, `${resolution.status} ${code(resolution.body)}`);
  ok("a lease binding NO view resolves with a typed reason rather than implying a policy nobody asserted",
    view.permitted_uses_source === "no_view_bound_to_this_lease" && (view.permitted_uses || []).length === 0,
    String(view.permitted_uses_source));
  ok("the resolution NAMES the dimensions it inherits and that it restates none of them",
    view.inherited_dimensions?.restated_here === false
      && (view.inherited_dimensions?.members || []).includes("purpose")
      && (view.inherited_dimensions?.members || []).includes("data_classes"),
    JSON.stringify(view.inherited_dimensions?.members || []));

  // -- restart reproduces the same least-context result -------------------------------------------
  const beforeRestart = JSON.stringify((await jd(`${base}/context-leases/${leaseId}/resolution`)).body?.resolution ?? {});
  await stopDaemon();
  await startDaemon();
  const afterRestart = JSON.stringify((await jd(`${base}/context-leases/${leaseId}/resolution`)).body?.resolution ?? {});
  ok("a daemon restart reproduces the SAME least-context resolution — it is re-derived from the admitted stream, not remembered",
    beforeRestart === afterRestart && afterRestart.includes("read_model_only"),
    `${beforeRestart.length} vs ${afterRestart.length} bytes`);

  // -- revoke, and what a revoked lease resolves --------------------------------------------------
  const revoked = await jd(`${base}/context-leases/${leaseId}/revoke`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "ctx-revoke-1" }),
  });
  ok("revocation admits a successor whose status is revoked",
    revoked.status === 200 && revoked.body?.context_lease?.status === "revoked",
    `${revoked.status} ${code(revoked.body)}`);
  const afterRevoke = await jd(`${base}/context-leases/${leaseId}/resolution`);
  ok("a REVOKED lease resolves nothing — the fence is on the read, not only on the write",
    afterRevoke.status === 409 && code(afterRevoke.body) === "context_lease_not_active",
    `${afterRevoke.status} ${code(afterRevoke.body)}`);
  const afterTerminal = await jd(`${base}/context-leases/${leaseId}/narrow`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, permitted_recipient_roles: [], idempotency_key: "ctx-post-revoke" }),
  });
  ok("a terminal lease admits no further successor",
    afterTerminal.status === 409 && code(afterTerminal.body) === "context_lease_terminal",
    `${afterTerminal.status} ${code(afterTerminal.body)}`);

  // -- a lease is reached through its OWN work subject --------------------------------------------
  const otherSubject = await jd(`/v1/goal-orchestration/goal-runs/gr_someone_else/context-leases/${leaseId}/revoke`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "ctx-wrong-subject" }),
  });
  ok("a lease cannot be reached through another GoalRun's path — the subject is checked, not assumed from the ref",
    otherSubject.status === 404 && code(otherSubject.body) === "context_lease_subject_mismatch",
    `${otherSubject.status} ${code(otherSubject.body)}`);

  // -- handoffs: a packet, never authority --------------------------------------------------------
  const handoff = await jd(`${base}/context-handoffs`, { method: "POST", body: JSON.stringify(handoffBody("a")) });
  const packet = handoff.body?.context_handoff ?? {};
  ok("a handoff admits as a registered record whose receipt_root re-derives here",
    handoff.status === 201 && packet.schema_version === HANDOFF_SCHEMA_VERSION
      && packet.receipt_root === deriveReceiptRoot(packet),
    `${handoff.status} ${code(handoff.body)}`);
  ok("its non_grants block is CONSTANT — authority widening, context declassification, executable state transfer, budget creation and receiver-policy bypass are each `none`",
    packet.non_grants && Object.values(packet.non_grants).every((v) => v === "none")
      && Object.keys(packet.non_grants).length === 5,
    JSON.stringify(packet.non_grants || {}));
  const suppliedNonGrant = await jd(`${base}/context-handoffs`, {
    method: "POST",
    body: JSON.stringify(handoffBody("weak", { non_grants: { authority_widening: "scoped" } })),
  });
  ok("a caller cannot SUPPLY or weaken a non-grant: the block is the daemon's, so the request field is refused",
    suppliedNonGrant.status === 400 && code(suppliedNonGrant.body) === "context_request_unknown_field",
    `${suppliedNonGrant.status} ${code(suppliedNonGrant.body)}`);
  const selfDirected = await jd(`${base}/context-handoffs`, {
    method: "POST",
    body: JSON.stringify(handoffBody("self", { to_context_cell_ref: CELL })),
  });
  ok("a cell handing off to ITSELF is refused — that is a summarisation, not a handoff between cells",
    selfDirected.status === 400 && code(selfDirected.body) === "context_handoff_self_directed",
    `${selfDirected.status} ${code(selfDirected.body)}`);
  const inventedPayload = await jd(`${base}/context-handoffs`, {
    method: "POST",
    body: JSON.stringify(handoffBody("payload", { payload_ref: "payload://ir_1" })),
  });
  ok("a handoff payload in an invented scheme is refused by the registered contract",
    inventedPayload.status === 400 && code(inventedPayload.body) === "context_handoff_contract_invalid",
    `${inventedPayload.status} ${code(inventedPayload.body)}`);

  const handoffId = String(packet.handoff_id).replace("handoff://", "");
  const accepted = await jd(`${base}/context-handoffs/${handoffId}/accept`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "ctx-accept-1" }),
  });
  ok("acceptance mints a successor that is a CANDIDATE under the receiver's policy and re-asserts the non-grants at the moment the claim matters most",
    accepted.status === 200 && accepted.body?.context_handoff?.status === "accepted"
      && accepted.body?.candidate_under_receiver_policy === true
      && Object.values(accepted.body?.context_handoff?.non_grants || {}).every((v) => v === "none"),
    `${accepted.status} ${code(accepted.body)}`);
  const reAccept = await jd(`${base}/context-handoffs/${handoffId}/accept`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "ctx-accept-2" }),
  });
  ok("only a SENT handoff can be decided: an accepted one cannot be accepted again",
    reAccept.status === 409 && code(reAccept.body) === "context_handoff_not_pending",
    `${reAccept.status} ${code(reAccept.body)}`);
  const rejectable = await jd(`${base}/context-handoffs`, { method: "POST", body: JSON.stringify(handoffBody("b")) });
  const rejectId = String(rejectable.body?.context_handoff?.handoff_id).replace("handoff://", "");
  const rejected = await jd(`${base}/context-handoffs/${rejectId}/reject`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "ctx-reject-1" }),
  });
  ok("rejection is equally a successor, so a refused handoff is on the record rather than absent",
    rejected.status === 200 && rejected.body?.context_handoff?.status === "rejected"
      && rejected.body?.candidate_under_receiver_policy === false,
    `${rejected.status} ${code(rejected.body)}`);

  // -- the MCP half, asserted as the structural fact it is ----------------------------------------
  const tools = await jd("/v1/hypervisor/mcp-gateway/tools");
  const toolText = JSON.stringify(tools.body ?? {});
  ok("NO MCP tool reaches the context families, so the refusals above are proven on the ONLY path that reaches them; the MCP half of this unit's matrix is a typed absence owned by M01.10/M01.11, not a probe at a path the family never used",
    !/context-lease|context_lease|context-handoff|context_handoff/u.test(toolText),
    `mcp-gateway/tools ${tools.status}, ${toolText.length} bytes, no context family named`);

  // -- replay ------------------------------------------------------------------------------------
  const replay = await jd(`${base}/context-leases`, { method: "POST", body: JSON.stringify(leaseBody("a")) });
  ok("the same idempotency key replays the same lease rather than minting a second for one cell",
    replay.status === 200 && replay.body?.replayed === true
      && replay.body?.context_lease?.receipt_root === lease.receipt_root,
    `${replay.status} replayed=${replay.body?.replayed}`);
  const diverged = await jd(`${base}/context-leases`, {
    method: "POST",
    body: JSON.stringify(leaseBody("a", { lease_kind: "repo_slice" })),
  });
  ok("the same key with a CHANGED lease is refused rather than silently replacing what was admitted",
    diverged.status === 409 && code(diverged.body) === "context_lease_replay_diverged",
    `${diverged.status} ${code(diverged.body)}`);
}

async function drill() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "context-lease-bootstrap-v1", email: "context-lease@ioi.local" }),
    }, { authenticated: false });
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
  }
  // The drill writes too, so it needs the same owner tenant the run path resolves — without it every
  // write refuses `mutation_owner_ref_required` and D4 would report the shrink as refused for the
  // wrong reason, which is the failure mode this drill exists to rule out.
  const whoDrill = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (whoDrill.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  const admitted = await jd(`${base}/context-leases`, { method: "POST", body: JSON.stringify(leaseBody("drill")) });
  const lease = admitted.body?.context_lease ?? {};

  // D1 — the receipt-root oracle must NOTICE a changed field. An oracle that cannot fail is not one.
  const tampered = { ...lease, lease_kind: "canon" };
  ok("DRILL D1 — the independent receipt_root oracle rejects a record whose field was changed after sealing",
    deriveReceiptRoot(tampered) !== lease.receipt_root);

  // D2 — the oracle must also notice a REMOVED field, not just a changed one.
  const shortened = { ...lease };
  delete shortened.budget_ref;
  ok("DRILL D2 — and it rejects a record with a field removed", deriveReceiptRoot(shortened) !== lease.receipt_root);

  // D3 — the no-effect comparison must be able to go RED, or it passes for the wrong reason.
  const before = await snapshot();
  await jd(`${base}/context-handoffs`, { method: "POST", body: JSON.stringify(handoffBody("drill")) });
  const afterHandoff = await snapshot();
  const sameAfterUnrelated = drifted(before, afterHandoff).length === 0;
  const beforeGoalRun = await snapshot();
  await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ title: "drill session" }) });
  const afterGoalRun = await snapshot();
  ok("DRILL D3 — the byte-identity comparison goes RED when a real record IS written, so its green is not two empty sets agreeing",
    sameAfterUnrelated && drifted(beforeGoalRun, afterGoalRun).length > 0,
    `handoff drift=${drifted(before, afterHandoff).length} session drift=${drifted(beforeGoalRun, afterGoalRun).length}`);

  // D4 — the widening refusal must be keyed on the MEMBER, not on any narrow attempt failing.
  const leaseId = String(lease.context_lease_id).replace("context-lease://", "");
  const shrink = await jd(`${base}/context-leases/${leaseId}/narrow`, {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, permitted_recipient_roles: [], idempotency_key: "drill-shrink" }),
  });
  ok("DRILL D4 — a narrowing that SHRINKS is admitted, so the widening refusals are not a blanket refusal of every successor",
    shrink.status === 200, `${shrink.status} ${code(shrink.body)}`);
}

const finish = async () => {
  await stopDaemon();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({
    verifierId: "context-lease-handoff-lifecycle",
    sourceUrl: import.meta.url,
    results: results.map((r) => ({ name: r.name, pass: r.pass })),
  });
  console.log(`\ncontext lease and handoff lifecycle: ${failed.length === 0 ? "PASS" : "FAIL"} (${results.length - failed.length}/${results.length})`);
  if (failed.length) console.log(daemonLog.split("\n").slice(-30).join("\n"));
  process.exit(failed.length === 0 ? 0 : 1);
};

(DRILL ? drill() : run())
  .then(finish)
  .catch(async (error) => {
    console.error(`FAIL  the verifier itself did not complete: ${error?.message ?? error}`);
    results.push({ name: "the verifier completed", pass: false, detail: String(error?.message ?? error) });
    await finish();
  });
