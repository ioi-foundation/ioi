#!/usr/bin/env node
// check:project-discovery-proposal — M09.1, against an ISOLATED real daemon.
//
// The unit's claim is a BOUNDARY, so almost every clause here is a negative: a policy-bound source
// snapshot plus a detector revision produce an immutable proposal, a human or policy accepts ONE
// exact candidate and ONE admitted override set, and discovery reads, proposes and STOPS. Canon:
// providers-and-environments.md § Evidenced Project Discovery.
//
// THE ORACLE IS INDEPENDENT. `proposal_hash` is re-derived HERE, in JavaScript, from the record the
// daemon returned — JCS bytes of a flat domain-separated material map — and compared with the
// daemon's own number. Reading the daemon's hash back and calling it verified would be asking the
// committer whether it committed. The self-drill then plants a change in the re-derived copy and
// requires this verifier's own oracle to notice, because an oracle that cannot fail is not one.
//
// "NO EFFECT ANYWHERE" IS MEASURED, NOT ASSERTED. Every other observable family the daemon serves
// is read before and after an admission and required to be byte-identical. The self-drill plants a
// real project between the two reads and requires that comparison to go red, because a comparison
// of two empty sets passes for the wrong reason.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   --mutation  run the three planted defects instead of trusting the assertions above.
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const DRILL = process.argv.includes("--mutation");

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });

const PROPOSAL_SCHEMA_VERSION = "ioi.hypervisor.project-discovery-proposal.v1";
const PROPOSAL_HASH_DOMAIN = "ioi.hypervisor-project-discovery-proposal-jcs-sha256.v1";
const OVERRIDE_SCHEMA_V1 = "override-schema://ioi/hypervisor/project-discovery/v1";
// The commitment's material, transcribed from canon rather than from the daemon's constant: a
// verifier that imported the producer's own field list would agree with it by construction.
const MATERIAL = [
  "schema_version",
  "project_discovery_proposal_ref",
  "source_ref",
  "source_snapshot_ref",
  "source_snapshot_hash",
  "discovery_engine_revision_ref",
  "discovery_engine_hash",
  "discovery_policy_ref",
  "observed_marker_refs",
  "evidence_refs",
  "candidate_roots",
  "information_flow_label_ref",
  "custody_posture_ref",
  "permitted_override_schema_ref",
];

/** RFC 8785 JCS for the JSON subset these records use: sorted keys, minimal separators. */
const jcs = (value) => {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
};

/** The commitment, computed here and never read back from the record that carries it. */
const deriveProposalHash = (record) => {
  const material = { domain: PROPOSAL_HASH_DOMAIN };
  for (const field of MATERIAL) material[field] = record[field] ?? null;
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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-project-discovery-"));
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

const jd = (p, init = {}, { authenticated = true } = {}) => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: {
    "content-type": "application/json",
    ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    ...(init.headers || {}),
  },
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const PROPOSALS = "/v1/hypervisor/project-discovery-proposals";
const code = (body) => body?.code ?? body?.error?.code ?? "";
const idOf = (ref) => (ref || "").replace("project-discovery-proposal://", "").replace("/revision/1", "");

const candidate = (id, confidence, extra = {}) => ({
  candidate_id: id,
  root_ref: `root://repo/${id}`,
  proposed_project_kind: "service",
  proposed_stack_or_runtime: "node20",
  proposed_initializer_inputs: [],
  proposed_task_inputs: [],
  proposed_service_inputs: [],
  proposed_port_inputs: [],
  proposed_dependency_inputs: [],
  confidence,
  uncertainty: "two lockfiles for one root",
  conflict_refs: [],
  alternative_candidate_refs: [],
  missing_requirement_refs: [],
  reason_codes: ["package_json_present"],
  ...extra,
});

const proposalBody = (key, overrides = {}) => ({
  schema_version: PROPOSAL_SCHEMA_VERSION,
  owner_ref: OWNER,
  idempotency_key: key,
  source_ref: "source://repo/example",
  source_snapshot_ref: "source-snapshot://repo/example/1",
  source_snapshot_hash: `sha256:${"a".repeat(64)}`,
  discovery_engine_revision_ref: "discovery-engine://ioi/static/revision/3",
  discovery_engine_hash: `sha256:${"b".repeat(64)}`,
  discovery_policy_ref: "policy://ioi/discovery/read-only",
  observed_marker_refs: ["marker://package.json", "marker://Dockerfile"],
  evidence_refs: ["evidence://package.json#1"],
  // Deliberately NOT in confidence order: the low-confidence candidate is the one accepted below,
  // so "confidence ranks, it does not select" is exercised rather than only stated.
  candidate_roots: [candidate("high", 0.97), candidate("low", 0.08, {
    conflict_refs: ["conflict://two-package-managers"],
    missing_requirement_refs: ["requirement://python-runtime"],
  })],
  information_flow_label_ref: "information-flow-label://ioi/internal",
  custody_posture_ref: "custody-posture://ioi/local",
  permitted_override_schema_ref: OVERRIDE_SCHEMA_V1,
  ...overrides,
});

/// Every family this daemon serves that discovery must not touch, read as one comparable snapshot.
const OBSERVED_FAMILIES = [
  "/v1/hypervisor/projects",
  "/v1/hypervisor/environments",
  "/v1/hypervisor/environment-classes",
  "/v1/hypervisor/recipes",
  "/v1/hypervisor/governance/approval-requests",
  "/v1/hypervisor/connectors",
  "/v1/hypervisor/model-routes",
];

/// A response's own generation time is not state.
///
/// MEASURED, not assumed: two reads of `/v1/hypervisor/model-routes` four seconds apart with NO
/// request in between differ in exactly one place — a top-level `at` stamped with the moment the
/// projection was built (the single route underneath is byte-identical). Comparing that would make
/// every "nothing moved" clause fail for the clock rather than for a write, the same way the
/// sequence-zero journey's byte-exact daemon-tree clauses went red on a liveness heartbeat. Only
/// the TOP-LEVEL envelope stamp is dropped; an `at` inside any record stays, because a record that
/// re-timestamped itself IS a write. DRILL 2 exists to prove this normalisation did not blind the
/// comparison: it plants a real project and requires it to be seen.
const withoutResponseStamp = (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const { at: _responseGeneratedAt, ...state } = body;
  return state;
};

const snapshotEstate = async () => {
  const snapshot = {};
  for (const route of OBSERVED_FAMILIES) {
    const { status, body } = await jd(route);
    snapshot[route] = `${status}:${jcs(withoutResponseStamp(body) ?? null)}`;
  }
  return snapshot;
};

const estateDelta = (before, after) =>
  OBSERVED_FAMILIES.filter((route) => before[route] !== after[route]);

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();

  // -- identity ---------------------------------------------------------------
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "project-discovery-bootstrap-v1", email: "project-discovery@ioi.local" }),
    }, { authenticated: false });
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  ok("the session authenticates a principal with an owner tenant to admit under", !!OWNER, OWNER || "no owner tenant");

  // -- identity is the first gate ---------------------------------------------
  const anon = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("anon-1")) }, { authenticated: false });
  ok("an unauthenticated admission refuses BEFORE any content complaint (401, not a field error)",
    anon.status === 401 && !/field|candidate|schema_version/iu.test(JSON.stringify(anon.body)),
    `${anon.status} ${code(anon.body)}`);

  // -- the estate before anything is proposed ---------------------------------
  const before = await snapshotEstate();

  // -- admission ---------------------------------------------------------------
  const created = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("pdp-1")) });
  const proposal = created.body?.proposal || {};
  const proposalRef = created.body?.project_discovery_proposal_ref || "";
  const id = idOf(proposalRef);
  ok("a proposal admits with an allocated ref and a live head",
    created.status === 201 && proposalRef.startsWith("project-discovery-proposal://pdp_") && !!created.body?.admitted_head,
    `${created.status} ${proposalRef}`);

  // THE INDEPENDENT ORACLE. Re-derived here from the returned record; the daemon's own number is
  // compared TO it, never trusted as it.
  const derived = deriveProposalHash(proposal);
  ok("the commitment re-derives independently, over the allocated ref and the exact ordered candidate set",
    derived === proposal.proposal_hash,
    `${derived.slice(0, 22)}… vs ${String(proposal.proposal_hash).slice(0, 22)}…`);
  ok("the record carries the ref INSIDE its own commitment material",
    MATERIAL.includes("project_discovery_proposal_ref") && proposal.project_discovery_proposal_ref === proposalRef,
    proposal.project_discovery_proposal_ref || "");

  // -- an unaccepted proposal has no effect ANYWHERE --------------------------
  const afterProposal = await snapshotEstate();
  const untouched = estateDelta(before, afterProposal);
  ok("an unaccepted proposal changes NO other family (projects, environments, classes, recipes, approvals, connectors, model routes)",
    untouched.length === 0,
    untouched.length ? `changed: ${untouched.join(", ")}` : `${OBSERVED_FAMILIES.length} families byte-identical`);

  // -- ambiguity stays visible -------------------------------------------------
  const read = await jd(`${PROPOSALS}/${id}`);
  const low = (read.body?.proposal?.candidate_roots || []).find((c) => c.candidate_id === "low") || {};
  ok("conflicts, uncertainty and missing requirements read back VERBATIM, never normalised away",
    low.uncertainty === "two lockfiles for one root"
      && jcs(low.conflict_refs) === jcs(["conflict://two-package-managers"])
      && jcs(low.missing_requirement_refs) === jcs(["requirement://python-runtime"]),
    jcs(low.conflict_refs || null));
  ok("the read projection re-derives the commitment rather than echoing it, and reports it unaccepted",
    read.body?.commitment_verified === true && read.body?.accepted === false,
    `verified ${read.body?.commitment_verified} · accepted ${read.body?.accepted}`);

  // -- the boundary, by its own cause -----------------------------------------
  const boundary = {};
  for (const field of ["project_id", "development_environment_recipe_ref", "placement_ref", "capability_lease_ref", "environment_startup_plan_ref"]) {
    const refused = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody(`boundary-${field}`, { [field]: "x" })) });
    boundary[field] = `${refused.status}:${code(refused.body)}`;
  }
  ok("a proposal naming Project, recipe, placement, lease or startup lineage refuses by the BOUNDARY code, not as an unknown field",
    Object.values(boundary).every((value) => value.endsWith(":project_discovery_proposal_boundary_field")),
    jcs(boundary));
  const authored = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("authored-hash", { proposal_hash: `sha256:${"c".repeat(64)}` })) });
  ok("a caller cannot author its own commitment or its own ref",
    code(authored.body) === "project_discovery_proposal_field_not_caller_authored",
    code(authored.body));
  const unknown = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("unknown-field", { favourite_colour: "blue" })) });
  ok("an unrecognised field is refused rather than ignored",
    code(unknown.body) === "project_discovery_request_field_unknown", code(unknown.body));

  // -- visibility members are required PRESENT --------------------------------
  const blind = candidate("blind", 0.5);
  delete blind.conflict_refs;
  const blindReply = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("blind-1", { candidate_roots: [blind] })) });
  ok("a candidate that omits its conflict set is refused: 'none found' and 'never looked' stay distinguishable",
    code(blindReply.body) === "project_discovery_candidate_visibility_member_missing", code(blindReply.body));

  // -- immutability ------------------------------------------------------------
  const replay = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("pdp-1")) });
  ok("the same key with identical content REPLAYS the same commitment (no second proposal)",
    replay.status === 200 && replay.body?.replayed === true && replay.body?.proposal?.proposal_hash === proposal.proposal_hash,
    `${replay.status} replayed=${replay.body?.replayed}`);
  const amended = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("pdp-1", { evidence_refs: ["evidence://package.json#2"] })) });
  const afterAmend = await jd(`${PROPOSALS}/${id}`);
  ok("the same key with CHANGED content is refused as a different proposal, and the stored bytes do not move",
    amended.status === 409 && code(amended.body) === "project_discovery_proposal_immutable"
      && afterAmend.body?.proposal?.proposal_hash === proposal.proposal_hash,
    `${amended.status} ${code(amended.body)}`);
  // Reordering the candidate set is a content change, not a presentation one.
  const reordered = proposalBody("pdp-reordered");
  reordered.candidate_roots = [...reordered.candidate_roots].reverse();
  const reorderedReply = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(reordered) });
  ok("a reordered candidate set is a DIFFERENT proposal (the commitment covers the exact order)",
    reorderedReply.status === 201 && reorderedReply.body?.proposal?.proposal_hash !== proposal.proposal_hash,
    `${String(reorderedReply.body?.proposal?.proposal_hash).slice(0, 22)}…`);

  // -- acceptance negatives ----------------------------------------------------
  const accept = (body) => jd(`${PROPOSALS}/${id}/acceptances`, { method: "POST", body: JSON.stringify({ owner_ref: OWNER, ...body }) });
  const noCandidate = await accept({ idempotency_key: "acc-no-candidate", expected_proposal_hash: proposal.proposal_hash });
  ok("acceptance with no named candidate refuses: confidence ranks, it does not select",
    code(noCandidate.body) === "project_discovery_acceptance_candidate_required", code(noCandidate.body));
  const noHash = await accept({ idempotency_key: "acc-no-hash", selected_candidate_id: "low" });
  ok("acceptance that does not name the exact proposal it read refuses",
    code(noHash.body) === "project_discovery_acceptance_proposal_hash_required", code(noHash.body));
  const wrongHash = await accept({ idempotency_key: "acc-wrong-hash", expected_proposal_hash: `sha256:${"d".repeat(64)}`, selected_candidate_id: "low" });
  ok("acceptance naming a DIFFERENT commitment refuses typed",
    wrongHash.status === 409 && code(wrongHash.body) === "project_discovery_acceptance_proposal_hash_mismatch",
    `${wrongHash.status} ${code(wrongHash.body)}`);
  const ghost = await accept({ idempotency_key: "acc-ghost", expected_proposal_hash: proposal.proposal_hash, selected_candidate_id: "never-proposed" });
  ok("acceptance of a candidate the proposal never proposed refuses typed",
    code(ghost.body) === "project_discovery_acceptance_candidate_unknown", code(ghost.body));
  const badOverride = await accept({
    idempotency_key: "acc-bad-override",
    expected_proposal_hash: proposal.proposal_hash,
    selected_candidate_id: "low",
    admitted_override_set: { grant_ref: "grant://anything" },
  });
  ok("an override outside the proposal's own permitted schema refuses typed",
    code(badOverride.body) === "project_discovery_override_not_permitted", code(badOverride.body));

  // An override set can only be checked against a schema this build resolves; fail closed.
  const otherSchema = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("pdp-other-schema", { permitted_override_schema_ref: "override-schema://vendor/unknown/v9" })) });
  const otherId = idOf(otherSchema.body?.project_discovery_proposal_ref || "");
  const unresolvable = await jd(`${PROPOSALS}/${otherId}/acceptances`, {
    method: "POST",
    body: JSON.stringify({
      owner_ref: OWNER,
      idempotency_key: "acc-unresolvable",
      expected_proposal_hash: otherSchema.body?.proposal?.proposal_hash,
      selected_candidate_id: "low",
      admitted_override_set: { project_kind: "library" },
    }),
  });
  ok("an override presented against a schema this build cannot resolve refuses rather than being waved through",
    code(unresolvable.body) === "project_discovery_override_schema_unresolvable", code(unresolvable.body));

  // -- acceptance, explicit, of the LEAST confident candidate ------------------
  const beforeAccept = await snapshotEstate();
  const accepted = await accept({
    idempotency_key: "acc-1",
    expected_proposal_hash: proposal.proposal_hash,
    selected_candidate_id: "low",
    admitted_override_set: { stack_or_runtime: "python3.12" },
  });
  ok("an explicit acceptance of the LEAST confident candidate is admitted exactly like any other",
    accepted.status === 201 && accepted.body?.acceptance?.selected_discovery_candidate_id === "low"
      && !!accepted.body?.acceptance?.admitted_discovery_override_set_hash,
    `${accepted.status} ${accepted.body?.acceptance?.selected_discovery_candidate_id || ""}`);
  ok("the acceptance binds the exact proposal ref AND its exact commitment",
    accepted.body?.acceptance?.project_discovery_proposal_ref === proposalRef
      && accepted.body?.acceptance?.project_discovery_proposal_hash === proposal.proposal_hash,
    "");
  ok("the acceptance is attributed to the daemon's resolved principal, never to the body",
    typeof accepted.body?.acceptance?.accepted_by === "string" && accepted.body.acceptance.accepted_by.startsWith("user://"),
    accepted.body?.acceptance?.accepted_by || "");

  // ACCEPTANCE STILL CREATES NO LINEAGE. M09.2 owns what is built from a freeze; the freeze itself
  // is a decision on the record and nothing more.
  const afterAccept = await snapshotEstate();
  const acceptDelta = estateDelta(beforeAccept, afterAccept);
  ok("acceptance freezes a decision and still creates NO project, recipe, environment or lease",
    acceptDelta.length === 0,
    acceptDelta.length ? `changed: ${acceptDelta.join(", ")}` : "no other family moved");

  const second = await accept({
    idempotency_key: "acc-2",
    expected_proposal_hash: proposal.proposal_hash,
    selected_candidate_id: "high",
  });
  ok("a second, different acceptance refuses: the freeze happens ONCE",
    second.status === 409 && code(second.body) === "project_discovery_proposal_already_accepted",
    `${second.status} ${code(second.body)}`);

  // -- restart survival --------------------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const survived = await jd(`${PROPOSALS}/${id}`);
  ok("the proposal and its acceptance survive a daemon restart with the commitment still re-deriving",
    survived.body?.proposal?.proposal_hash === proposal.proposal_hash
      && survived.body?.commitment_verified === true
      && survived.body?.acceptance?.selected_discovery_candidate_id === "low"
      && deriveProposalHash(survived.body.proposal) === proposal.proposal_hash,
    `accepted=${survived.body?.accepted}`);

  // ------------------------------------------------------------------- self-drill
  if (DRILL) {
    // P1 — the independent oracle must NOTICE a change. If it cannot, every commitment assertion
    // above passed because the two numbers came from the same place.
    const tampered = JSON.parse(JSON.stringify(proposal));
    tampered.candidate_roots = [...tampered.candidate_roots].reverse();
    const orderDetected = deriveProposalHash(tampered) !== proposal.proposal_hash;
    const fieldTampered = JSON.parse(JSON.stringify(proposal));
    fieldTampered.discovery_policy_ref = "policy://ioi/discovery/anything-goes";
    const fieldDetected = deriveProposalHash(fieldTampered) !== proposal.proposal_hash;
    ok("DRILL 1: this verifier's own hash oracle detects a reordered candidate set and a swapped discovery policy",
      orderDetected && fieldDetected,
      `order ${orderDetected} · policy ${fieldDetected}`);

    // P2 — the "no effect anywhere" comparison must be able to go RED. A real project is created
    // through the daemon's own route between two snapshots; if the comparison still reports "no
    // family moved", it was never observing them.
    const drillBefore = await snapshotEstate();
    const planted = await jd("/v1/hypervisor/projects", {
      method: "POST",
      body: JSON.stringify({ repository_url: "https://example.invalid/discovery-drill.git", project_name: "discovery-drill" }),
    });
    const drillAfter = await snapshotEstate();
    const noticed = estateDelta(drillBefore, drillAfter);
    ok("DRILL 2: a project created between two snapshots turns the no-effect-anywhere comparison RED",
      noticed.includes("/v1/hypervisor/projects"),
      `project create ${planted.status} · noticed [${noticed.join(", ")}]`);

    // P3 — the positive control for the negative. The acceptance that refused for want of an
    // explicit candidate must SUCCEED when the only thing added is the explicit candidate;
    // otherwise that refusal proved the route is broken, not that selection is explicit.
    const control = await jd(PROPOSALS, { method: "POST", body: JSON.stringify(proposalBody("drill-control")) });
    const controlId = idOf(control.body?.project_discovery_proposal_ref || "");
    const withoutCandidate = await jd(`${PROPOSALS}/${controlId}/acceptances`, {
      method: "POST",
      body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "drill-control-a", expected_proposal_hash: control.body?.proposal?.proposal_hash }),
    });
    const withCandidate = await jd(`${PROPOSALS}/${controlId}/acceptances`, {
      method: "POST",
      body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "drill-control-b", expected_proposal_hash: control.body?.proposal?.proposal_hash, selected_candidate_id: "high" }),
    });
    ok("DRILL 3: the SAME acceptance refuses without an explicit candidate and is admitted with one — the only difference is the explicit choice",
      code(withoutCandidate.body) === "project_discovery_acceptance_candidate_required" && withCandidate.status === 201,
      `${code(withoutCandidate.body)} → ${withCandidate.status}`);
  }
}

const stop = () => {
  try { daemon?.kill("SIGKILL"); } catch { /* already gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
};
process.on("SIGINT", () => { stop(); process.exit(130); });
process.on("SIGTERM", () => { stop(); process.exit(143); });

run()
  .catch((error) => ok("the journey ran to completion", false, String(error?.message || error)))
  .finally(() => {
    stop();
    for (const result of results) {
      console.log(`${result.pass ? "PASS" : "FAIL"} ${result.name}${result.detail ? ` — ${result.detail}` : ""}`);
    }
    const failed = results.filter((result) => !result.pass).length;
    console.log(`${failed ? "FAIL" : "PASS"} check:project-discovery-proposal — ${results.length - failed}/${results.length} assertions${DRILL ? " (with the three planted defects)" : ""} · M09.1 · discovery proposes and stops`);
    process.exit(failed ? 1 : 0);
  });
