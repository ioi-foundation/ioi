#!/usr/bin/env node
// M05.3 — `ProvenanceAssertion` as a queryable plane, driven end to end against a live daemon and its
// durable Agentgres chain.
//
// WHAT THIS GATE IS FOR. Provenance stops being a rendering of logs when a claim is an OBJECT: one
// that names its sources, records which side each piece of evidence bears on, says how uncertain it
// is in a way another estimator can read, keeps the contradictions that argue against it, and can be
// challenged without its bytes moving. The claims here are exactly those, plus the succession rule
// that makes v2 a successor rather than a reinterpretation of v1.
//
// THE DEFECTS THE REGISTERED CORPUS STRUCTURALLY CANNOT CATCH. Every negative fixture beside this
// gate is decidable from bytes alone. These are not:
//   * "is this predicate a term the BOUND revision actually declares" — a fact about another chain,
//     and a well-formed correctly-namespaced term the revision never declared passes every fixture;
//   * "does admitting a challenge leave the challenged claim's content hash where it was" — a fact
//     about two reads separated by a durable write of a different operation kind;
//   * "does the folded standing survive a restart with the process-local index gone";
//   * "does an idempotency key replay across that restart without appending".
//
// HOW IT AVOIDS GRADING ITSELF: content hashes are recomputed HERE from the material list read out
// of the REGISTERED invariant profile; every binding is a real admitted record minted through its
// own owner's route in this same run; durable truth is read across a restart with the index rebuild
// positively detected; every refusal re-reads the lineage and requires head and count to be
// unchanged; and `--mutate` plants named defects that must redden the exact assertion they target.
//
// NONCLAIMS. This gate proves the assertion plane only. It makes no claim that any admitted
// assertion is TRUE — admission records that this domain holds it as operational truth, which is
// what the record says. It asserts no authority plane is consulted here, which is not the same as
// proving those planes elsewhere.

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const ROUTE_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/provenance_assertion_routes.rs",
);
const OWNER_SEAM_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/ontology_version_routes.rs",
);
const INVARIANTS = path.join(ROOT, "docs/architecture/_meta/schemas/invariants");
const RECEIPT_OWNER_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/assurance_transition_routes.rs",
);
const REGISTRY = path.join(
  ROOT,
  "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json",
);

const MUTATE = process.argv.includes("--mutate");
const SUMMARIZE = process.argv.includes("--summarize");
/// Pre-flight the battery anchors without planting or rebuilding anything.
const ANCHORS = process.argv.includes("--anchors");
const ONLY = (process.argv.find((argument) => argument.startsWith("--only=")) ?? "")
  .slice("--only=".length)
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);
const LEDGER = path.join(os.tmpdir(), "ioi-m053-mutation-ledger.json");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.error?.code ?? j?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------- canonical JSON + content hash

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;

/** Read the commitment material out of the REGISTERED invariant profile, never out of this file. */
function commitmentRule(profileFile, ruleSuffix) {
  const profile = JSON.parse(fs.readFileSync(path.join(INVARIANTS, profileFile), "utf8"));
  const rule = profile.rules.find((entry) => entry.rule_id.endsWith(ruleSuffix));
  if (!rule) throw new Error(`no commitment rule ${ruleSuffix} in ${profileFile}`);
  return rule.expression;
}

function recomputeCommitment(record, expression) {
  const material = {};
  for (const [field, descriptor] of Object.entries(expression.material_fields)) {
    if (Object.hasOwn(descriptor, "value")) {
      material[field] = descriptor.value;
      continue;
    }
    let cursor = record;
    for (const part of descriptor.path.slice(2).split(".")) cursor = cursor?.[part];
    material[field] = cursor === undefined ? null : cursor;
  }
  return sha256(canonicalJson(material));
}

// -------------------------------------------------------------------------------- daemon lifecycle

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-m053-"));
const dataDir = path.join(scratch, "data");
fs.mkdirSync(dataDir, { recursive: true });
let daemon = null;
let daemonLog = "";
let DAEMON = "";

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

function daemonBinary() {
  if (process.env.IOI_HYPERVISOR_DAEMON_BINARY) return process.env.IOI_HYPERVISOR_DAEMON_BINARY;
  if (process.env.CARGO_TARGET_DIR) {
    return path.join(process.env.CARGO_TARGET_DIR, "debug", "hypervisor-daemon");
  }
  return path.join(ROOT, "target", "debug", "hypervisor-daemon");
}

async function waitFor(url, timeoutMs = 90000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.status < 500) return true;
    } catch {
      /* not listening yet */
    }
    await sleep(120);
  }
  return false;
}

async function startDaemon() {
  const port = await freePort();
  DAEMON = `http://127.0.0.1:${port}`;
  daemon = spawn(daemonBinary(), [], {
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
      IOI_WALLET_SECRET_PASS: "ioi-provenance-assertion-verifier",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  daemon.stderr.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  if (!(await waitFor(`${DAEMON}/healthz`))) throw new Error("the isolated daemon never became healthy");
}

// SIGTERM the tracked child. Never pgrep/pkill a daemon path — that kills this process's own shell.
async function stopDaemon() {
  if (!daemon) return;
  const child = daemon;
  daemon = null;
  try {
    child.kill("SIGTERM");
  } catch {
    /* already gone */
  }
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    sleep(4000).then(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }),
  ]);
  await sleep(150);
}

function cleanup() {
  try {
    daemon?.kill("SIGKILL");
  } catch {
    /* already gone */
  }
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

// ---------------------------------------------------------------------------------- request helpers

const SESSIONS = { A: "", B: "" };

async function req(method, route, body, { as = "A" } = {}) {
  const headers = {};
  if (body !== undefined && body !== null) headers["content-type"] = "application/json";
  const session = as ? SESSIONS[as] : "";
  if (session) headers.cookie = `ioi_session=${session}`;
  try {
    const response = await fetch(`${DAEMON}${route}`, {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
      body: body === undefined || body === null ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* non-json */
    }
    return { status: response.status, j: json, text };
  } catch (error) {
    return { status: 0, j: { transport_error: String(error) }, text: String(error) };
  }
}

const OV = "/v1/hypervisor/ontology-versions";
const PA = "/v1/hypervisor/provenance-assertions";
const PAC = "/v1/hypervisor/provenance-assertions/challenges";
const AT = "/v1/hypervisor/assurance-transitions";

/// Climb the canonical ladder over one subject and return the ADJUDICATION receipt.
///
/// A challenge resolution IS an adjudication, so the subject really climbs attested -> evidenced ->
/// verified -> accepted before it can be adjudicated. The receipt this returns is a record the
/// daemon admitted, which is the whole point: a `receipt://`-shaped string the gate invented would
/// prove nothing about the resolution it is handed to.
async function climbLadderToAdjudication(subject, challengeId, resolution, keyPrefix, outcome) {
  const stages = [
    ["attested", ["correctness", "acceptance", "settlement", "authority"]],
    ["evidenced", ["correctness", "acceptance", "settlement", "authority"]],
    ["verified", ["correctness", "acceptance", "settlement", "authority"]],
    ["accepted", ["correctness", "settlement", "authority"]],
  ];
  let head = null;
  let ordinaryReceipt = null;
  for (const [stage, nonclaims] of stages) {
    const body = {
      owner_ref: "org://local",
      idempotency_key: `${keyPrefix}-${stage}`,
      subject_ref: subject,
      outcome_class: "positive",
      evidence_refs: [`evidence://${NS}/${keyPrefix}-${stage}`],
      does_not_assert: nonclaims,
      valid_time: { starts_at: "2026-09-01T00:00:00Z", ends_at: null },
    };
    if (head !== null) body.expected_head = head;
    const step = await req("POST", AT, body);
    if (step.status !== 201) return { failedAt: stage, response: step };
    // A REAL admitted receipt from an ORDINARY rung: it exists, and it adjudicates nothing.
    if (stage === "attested") {
      ordinaryReceipt = step.j?.assurance_transition?.admission?.agentgres_receipt_ref ?? null;
    }
    head = step.j?.expected_head_for_successor ?? null;
  }
  const adjudication = await req("POST", AT, {
    owner_ref: "org://local",
    idempotency_key: `${keyPrefix}-adjudicated`,
    subject_ref: subject,
    outcome_class: outcome,
    evidence_refs: [`evidence://${NS}/${keyPrefix}-adjudication`],
    does_not_assert: ["correctness", "settlement", "authority"],
    valid_time: { starts_at: "2026-09-01T00:00:00Z", ends_at: null },
    expected_head: head,
    challenge_resolution: {
      verifier_challenge_id: challengeId,
      resolution,
      adjudicator_ref: "org://local",
      adjudicator_policy_ref: `policy://${NS}/assertion-adjudication`,
      reviewer_lineage: [
        {
          reviewer_ref: `user://${NS}/charge-nurse`,
          reviewed_at: "2026-09-05T10:00:00Z",
          review_decision: resolution,
        },
      ],
    },
  });
  return {
    receipt: adjudication.j?.assurance_transition?.admission?.agentgres_receipt_ref ?? null,
    record: adjudication.j?.assurance_transition ?? null,
    response: adjudication,
    ordinaryReceipt,
  };
}

const NS = "acme-clinic";
const FOREIGN_NS = "harbor-labs";
const NAME = "patient-intake";
const term = (ns, name, slug) => `ontology://${ns}/${name}/term/${slug}`;
const termsOf = (ns, name, slugs) =>
  slugs.map((slug) => ({ term_id: term(ns, name, slug), label: slug }));

function ontologyProposal({ ns = NS, name = NAME, key, expectedHead = null, entities, actions = [] }) {
  const body = {
    owner_ref: "org://local",
    idempotency_key: key,
    namespace: ns,
    name,
    governing_scope_ref: `domain://${ns}/clinical`,
    policy_hash: sha256(`ontology-policy-${ns}-${name}`),
    entity_types: termsOf(ns, name, entities),
    action_types: termsOf(ns, name, actions),
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  };
  if (expectedHead !== null) {
    body.expected_head = expectedHead;
    body.compatibility = "additive";
    body.term_mappings = [
      {
        from_term_id: term(ns, name, entities[0]),
        to_term_id: term(ns, name, entities[0]),
        disposition: "retained",
      },
    ];
  }
  return body;
}

/** Head + revision count for one family, read straight off the chain. */
async function chainState(route, query) {
  const response = await req("GET", `${route}?${query}`);
  return {
    head: response.j?.current_head ?? null,
    count: response.j?.lineage_revision_count ?? -1,
    status: response.status,
    j: response.j,
  };
}

/** Assert a refusal AND that it moved nothing. A route answering 4xx proves nothing on its own. */
async function refusesWithoutEffect(name, response, expectedCode, route, query) {
  const after = await chainState(route, query);
  ok(
    name,
    response.status >= 400 && code(response.j) === expectedCode,
    `status ${response.status} code ${code(response.j)}`,
  );
  return after;
}

// ------------------------------------------------------------------------------------------- the run

const PA_RULE = commitmentRule(
  "ontology-assertion.v2.invariants.json",
  ".content_hash.commits_claim_sources_evidence_uncertainty_and_valid_time",
);

let BASE_R1 = null;
let BASE_HASH = null;
const SUBJECT = `object://${NS}/encounter/2026-08-30-0114`;

const assertionBody = (overrides = {}) => ({
  owner_ref: "org://local",
  idempotency_key: "m053-assert-1",
  namespace: NS,
  name: "encounter-0114-triage",
  governing_scope_ref: `domain://${NS}/clinical`,
  policy_hash: sha256("assertion-policy"),
  ontology_version_ref: BASE_R1,
  predicate_ref: term(NS, NAME, "triage-level"),
  subject_ref: SUBJECT,
  object_or_value_ref: "urgent",
  polarity: "affirmative",
  valid_time: { starts_at: "2026-08-30T02:10:00Z", ends_at: "2026-08-30T06:00:00Z" },
  source_attribution: [
    {
      source_ref: `observation://${NS}/triage-station-3`,
      source_class: "observation",
      observed_at: "2026-08-30T02:11:00Z",
    },
  ],
  evidence_lineage: [
    {
      evidence_ref: `evidence://${NS}/triage-form-0114`,
      evidence_class: "direct",
      supports: "affirmative",
    },
  ],
  uncertainty: {
    uncertainty_kind: "point_confidence",
    confidence: 0.75,
    estimator_ref: `worker://${NS}/triage-scorer`,
  },
  applicability_scope_ref: `policy://${NS}/night-shift-triage`,
  permitted_consequence_scope_refs: [`policy://${NS}/triage-queue-ordering`],
  ...overrides,
});

const paQuery = `namespace=${NS}&name=encounter-0114-triage`;

async function run() {
  await startDaemon();
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "provenance-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "provenance-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "provenance-b-v1",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "provenance-b@ioi.local", password: "provenance-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  ok(
    "PRECONDITION: two REAL authenticated principals exist, and B holds no scope on this plane",
    SESSIONS.A.length > 0 && SESSIONS.B.length > 0,
    `A ${SESSIONS.A.length > 0} B ${SESSIONS.B.length > 0}`,
  );

  const genesis = await req(
    "POST",
    OV,
    ontologyProposal({ key: "m053-ontology-1", entities: ["triage-level", "acuity-band"] }),
  );
  BASE_R1 = genesis.j?.ontology_version?.ontology_id ?? null;
  BASE_HASH = genesis.j?.ontology_version?.content_hash ?? null;
  ok(
    "PRECONDITION: a REAL ontology revision declaring REAL terms is admitted through M05.1's OWN route in this same run",
    BASE_R1 === `ontology://${NS}/${NAME}/revision/1` && BASE_HASH?.startsWith("sha256:"),
    `${BASE_R1}`,
  );

  // ------------------------------------------------------------------ the claim becomes an object
  const admitted = await req("POST", PA, assertionBody());
  const record = admitted.j?.provenance_assertion ?? {};
  ok(
    "ASSERTION: a claim is admitted as an immutable revision on its own owner-qualified chain",
    admitted.status === 201 &&
      record.assertion_id === `ontology-assertion://${NS}/encounter-0114-triage/revision/1` &&
      record.assertion_profile === "provenance_assertion",
    `${admitted.status} ${record.assertion_id}`,
  );
  ok(
    "ASSERTION: the ontology binding carries the ONTOLOGY OWNER's committed hash, resolved through its published term reader rather than asserted here",
    record.ontology_binding?.ontology_version_ref === BASE_R1 &&
      record.ontology_binding?.content_hash === BASE_HASH &&
      record.ontology_resolved_by === "ontology_version_routes::resolve_admitted_term",
    JSON.stringify(record.ontology_binding ?? null),
  );
  ok(
    "ASSERTION: the served content hash is exactly the REGISTERED invariant's own material, recomputed here rather than read back",
    record.content_hash === recomputeCommitment(record, PA_RULE),
    `${record.content_hash}`,
  );
  ok(
    "ASSERTION: the record states both nonclaims — admission is operational truth, not universal truth, and it grants nothing",
    record.universality_nonclaim === "provenance_assertion_admission_is_not_universal_truth" &&
      record.authority_nonclaim === "provenance_assertion_grants_no_authority" &&
      !/"(?:capability|lease|grant|scope):/u.test(JSON.stringify(record)),
    record.universality_nonclaim ?? "",
  );
  ok(
    "SUCCESSION: the record names its predecessor CONTRACT and disclaims reinterpreting it, so the succession is auditable from the bytes alone",
    record.predecessor_contract_ref === "schema://ioi/foundations/ontology-assertion/v1" &&
      record.reinterpretation_nonclaim ===
        "provenance_assertion_v2_does_not_reinterpret_v1_records" &&
      record.schema_version === "ioi.ontology-assertion.v2",
    record.predecessor_contract_ref ?? "",
  );

  let before = await chainState(PA, paQuery);
  const v1Request = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-v1",
      schema_version: "ioi.ontology-assertion.v1",
      expected_head: before.head,
      compatibility: "additive",
    }),
  );
  await refusesWithoutEffect(
    "SUCCESSION REFUSES: a caller naming the PREDECESSOR contract is refused by name rather than read as v2 — reading a v1 request as a v2 record is the exact reinterpretation this version exists to avoid",
    v1Request,
    "provenance_assertion_schema_version_unsupported",
    PA,
    paQuery,
  );

  const undeclaredTerm = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-undeclared",
      expected_head: before.head,
      compatibility: "additive",
      predicate_ref: term(NS, NAME, "never-declared"),
    }),
  );
  let after = await refusesWithoutEffect(
    "ASSERTION REFUSES: a well-formed, correctly-namespaced, canonical predicate the bound revision NEVER DECLARED — the one claim no byte-level fixture can decide",
    undeclaredTerm,
    "ontology_version_term_absent",
    PA,
    paQuery,
  );
  ok(
    "ASSERTION REFUSES BY EFFECT: the undeclared-predicate attempt left head and revision count exactly where they were",
    after.head === before.head && after.count === before.count,
    `${before.head}/${before.count} -> ${after.head}/${after.count}`,
  );

  const foreignTerm = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-foreign",
      expected_head: before.head,
      compatibility: "additive",
      predicate_ref: term(FOREIGN_NS, "intake", "severity"),
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: a predicate of another domain's namespace is a category error, not an absent term of this one",
    foreignTerm,
    "ontology_version_term_foreign_family",
    PA,
    paQuery,
  );

  const unattributed = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-unattributed",
      expected_head: before.head,
      compatibility: "additive",
      source_attribution: [],
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: an unattributed claim is a rendering of a log, which is the thing this object exists instead of",
    unattributed,
    "provenance_assertion_source_required",
    PA,
    paQuery,
  );

  const doubleCounted = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-double-evidence",
      expected_head: before.head,
      compatibility: "additive",
      evidence_lineage: [
        {
          evidence_ref: `evidence://${NS}/triage-form-0114`,
          evidence_class: "direct",
          supports: "affirmative",
        },
        {
          evidence_ref: `evidence://${NS}/triage-form-0114`,
          evidence_class: "corroborating",
          supports: "affirmative",
        },
      ],
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: counting one artifact twice is how a thin evidence set looks thick",
    doubleCounted,
    "provenance_assertion_evidence_counted_twice",
    PA,
    paQuery,
  );

  const misfiled = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-misfiled",
      expected_head: before.head,
      compatibility: "additive",
      evidence_lineage: [
        {
          evidence_ref: `evidence://${NS}/lab-panel`,
          evidence_class: "contradicting",
          supports: "affirmative",
        },
      ],
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: evidence declared contradicting cannot also be filed as support — that pair is how a bundle looks unanimous",
    misfiled,
    "provenance_assertion_contradicting_evidence_filed_as_support",
    PA,
    paQuery,
  );

  const bareConfidence = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-bare-confidence",
      expected_head: before.head,
      compatibility: "additive",
      uncertainty: { uncertainty_kind: "point_confidence", confidence: 0.5, estimator_ref: null },
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: a confidence with no estimator cannot be compared across estimators",
    bareConfidence,
    "provenance_assertion_point_confidence_incomplete",
    PA,
    paQuery,
  );

  const unknownWithNumber = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-unknown-number",
      expected_head: before.head,
      compatibility: "additive",
      uncertainty: {
        uncertainty_kind: "unknown",
        confidence: 0,
        estimator_ref: null,
      },
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: declining to claim is NOT claiming zero — an 'unknown' posture carries no confidence",
    unknownWithNumber,
    "provenance_assertion_unknown_carries_a_confidence",
    PA,
    paQuery,
  );

  const unknownWithConsequence = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-unknown-consequence",
      expected_head: before.head,
      compatibility: "additive",
      uncertainty: { uncertainty_kind: "unknown", confidence: null, estimator_ref: null },
      permitted_consequence_scope_refs: [`policy://${NS}/triage-queue-ordering`],
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: a domain that declines to claim also declines to license acting on the claim",
    unknownWithConsequence,
    "provenance_assertion_unknown_licenses_a_consequence",
    PA,
    paQuery,
  );

  const cleanButNaming = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-clean-but-naming",
      expected_head: before.head,
      compatibility: "additive",
      contradiction_state: {
        contradiction_class: "none",
        contradicting_assertion_refs: [`ontology-assertion://${NS}/other/revision/1`],
        retained: true,
      },
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: calling the record clean while naming what disputes it is the same defect from the other side",
    cleanButNaming,
    "provenance_assertion_contradiction_class_understates_the_refs",
    PA,
    paQuery,
  );

  const dropped = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-dropped-contradiction",
      expected_head: before.head,
      compatibility: "additive",
      contradiction_state: {
        contradiction_class: "value_conflict",
        contradicting_assertion_refs: [`ontology-assertion://${NS}/other/revision/1`],
        retained: false,
      },
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: a record that drops a contradiction has not resolved it — retention is not optional",
    dropped,
    "provenance_assertion_contradiction_not_retained",
    PA,
    paQuery,
  );

  const orphanSupersession = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-orphan-supersession",
      expected_head: before.head,
      compatibility: "additive",
      supersession: {
        supersedes_ref: `ontology-assertion://${NS}/encounter-0114-triage/revision/1`,
        supersession_reason: "none",
      },
    }),
  );
  await refusesWithoutEffect(
    "ASSERTION REFUSES: supersession without a stated reason is a deletion with extra steps",
    orphanSupersession,
    "provenance_assertion_supersession_incomplete",
    PA,
    paQuery,
  );
  return { record };
}

// -------------------------- polarity, contradiction, supersession, and the challenge/resolution graph
async function runGraph(ctx) {
  const { record } = ctx;

  const negative = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-negative",
      name: "encounter-0115-not-sepsis",
      polarity: "negative",
      object_or_value_ref: "sepsis-alert",
      evidence_lineage: [
        {
          evidence_ref: `evidence://${NS}/lab-panel-0115`,
          evidence_class: "direct",
          supports: "negative",
        },
      ],
    }),
  );
  ok(
    "POLARITY: a NEGATIVE assertion is a recorded claim with its own sources and evidence — not the absence of a record",
    negative.status === 201 &&
      negative.j?.provenance_assertion?.polarity === "negative" &&
      negative.j?.provenance_assertion?.status === "admitted",
    `${negative.status} ${negative.j?.provenance_assertion?.polarity}`,
  );

  const unknown = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-unknown",
      name: "encounter-0116-triage",
      uncertainty: { uncertainty_kind: "unknown", confidence: null, estimator_ref: null },
      permitted_consequence_scope_refs: [],
      evidence_lineage: [
        {
          evidence_ref: `evidence://${NS}/partial-form-0116`,
          evidence_class: "inconclusive",
          supports: "neither",
        },
      ],
    }),
  );
  ok(
    "UNCERTAINTY: 'held_unknown' is a distinct epistemic state the plane can hold and project — the domain declines to claim, and licenses no consequence",
    unknown.status === 201 &&
      unknown.j?.provenance_assertion?.status === "held_unknown" &&
      unknown.j?.provenance_assertion?.permitted_consequence_scope_refs.length === 0,
    `${unknown.status} ${unknown.j?.provenance_assertion?.status}`,
  );

  const before = await chainState(PA, paQuery);
  const corrected = await req(
    "POST",
    PA,
    assertionBody({
      idempotency_key: "m053-assert-corrected",
      expected_head: before.head,
      compatibility: "additive",
      object_or_value_ref: "standard",
      contradiction_state: {
        contradiction_class: "value_conflict",
        contradicting_assertion_refs: [record.assertion_id],
        retained: true,
      },
      supersession: { supersedes_ref: record.assertion_id, supersession_reason: "corrected" },
      evidence_lineage: [
        {
          evidence_ref: `evidence://${NS}/triage-form-0114`,
          evidence_class: "contradicting",
          supports: "negative",
        },
        {
          evidence_ref: `evidence://${NS}/nurse-correction-0114`,
          evidence_class: "direct",
          supports: "affirmative",
        },
      ],
      source_attribution: [
        {
          source_ref: `observation://${NS}/triage-station-3`,
          source_class: "observation",
          observed_at: "2026-08-30T02:11:00Z",
        },
        {
          source_ref: `user://${NS}/charge-nurse`,
          source_class: "human_reviewer",
          observed_at: "2026-08-30T03:40:00Z",
        },
      ],
    }),
  );
  const successor = corrected.j?.provenance_assertion ?? {};
  ok(
    "CONTRADICTION: a correcting successor is admitted, names what it contradicts, and projects CONTRADICTED rather than quietly replacing its predecessor",
    corrected.status === 201 &&
      successor.status === "contradicted" &&
      successor.contradiction_state?.contradicting_assertion_refs?.includes(record.assertion_id) &&
      successor.contradiction_state?.retained === true,
    `${corrected.status} ${successor.status}`,
  );
  ok(
    "CONTRADICTION: the contradicting evidence is RETAINED beside the corroborating evidence, each recording which side it bears on",
    successor.evidence_lineage?.length === 2 &&
      successor.evidence_lineage.some(
        (row) => row.evidence_class === "contradicting" && row.supports === "negative",
      ),
    JSON.stringify(successor.evidence_lineage ?? null),
  );

  const predecessorNow = await req("GET", `${PA}?${paQuery}&revision=1`);
  const preserved = predecessorNow.j?.records?.[0] ?? {};
  ok(
    "SUPERSESSION: the predecessor stays ADDRESSABLE, its transaction interval closes, and its CONTENT HASH does not move — supersession is a fact about the chain, not an edit",
    preserved.status === "superseded" &&
      preserved.content_hash === record.content_hash &&
      typeof preserved.transaction_time?.superseded_at === "string" &&
      preserved.content_hash === recomputeCommitment(preserved, PA_RULE),
    `${preserved.status} ${preserved.content_hash === record.content_hash}`,
  );

  // ------------------------------------------------------------------- the challenge/resolution graph
  const CHALLENGE = `verifier-challenge://${NS}/triage-scorer-is-miscalibrated`;
  const target = successor.assertion_id;
  const v1Envelope = await req("POST", PAC, {
    owner_ref: "org://local",
    idempotency_key: "m053-challenge-v1",
    challenged_ref: target,
    verifier_challenge_id: CHALLENGE,
    challenger_ref: `user://${NS}/charge-nurse`,
    challenge_kind: "evidence",
    adjudicator_policy_ref: `policy://${NS}/assertion-adjudication`,
    challenge_contract_ref: "schema://ioi/foundations/objects/verifier-challenge-envelope/v1",
  });
  ok(
    "CHALLENGE REFUSES: a v1 envelope is refused BY NAME — its challenged_ref pattern cannot address a semantic-plane subject at all",
    v1Envelope.status >= 400 &&
      code(v1Envelope.j) === "provenance_assertion_challenge_contract_unsupported",
    `status ${v1Envelope.status} code ${code(v1Envelope.j)}`,
  );

  const opened = await req("POST", PAC, {
    owner_ref: "org://local",
    idempotency_key: "m053-challenge-open",
    challenged_ref: target,
    verifier_challenge_id: CHALLENGE,
    challenger_ref: `user://${NS}/charge-nurse`,
    challenge_kind: "evidence",
    adjudicator_policy_ref: `policy://${NS}/assertion-adjudication`,
    challenge_evidence_refs: [`evidence://${NS}/scorer-calibration-report`],
  });
  const disputed = opened.j?.provenance_assertion ?? {};
  ok(
    "CHALLENGE: an admitted challenge moves the assertion's STANDING to challenged and its status to disputed",
    opened.status === 201 &&
      disputed.challenge_state?.standing === "challenged" &&
      disputed.status === "disputed",
    `${opened.status} ${disputed.status}`,
  );
  ok(
    "CHALLENGE: the challenged claim's CONTENT HASH did not move, across a durable write of a different operation kind",
    disputed.content_hash === successor.content_hash &&
      disputed.content_hash === recomputeCommitment(disputed, PA_RULE),
    `${successor.content_hash} -> ${disputed.content_hash}`,
  );
  ok(
    "CHALLENGE: the record pins BOTH registered contracts — the v2 challenge envelope it admits and the AssuranceTransitionReceipt v2 successor a resolution is receipted under",
    disputed.challenge_state?.challenge_contract_ref ===
      "schema://ioi/foundations/objects/verifier-challenge-envelope/v2" &&
      disputed.challenge_state?.resolution_contract_ref ===
        "schema://ioi/foundations/assurance-transition-receipt/v2",
    JSON.stringify(disputed.challenge_state ?? null),
  );
  ok(
    "CHALLENGE: admitting a challenge is not an adjudication, and the response says so",
    opened.j?.verdict_nonclaim ===
      "provenance_assertion_challenge_admission_is_not_an_adjudication",
    opened.j?.verdict_nonclaim ?? "",
  );

  const resolveWith = (key, overrides) =>
    req("POST", PAC, {
      owner_ref: "org://local",
      idempotency_key: key,
      challenged_ref: target,
      verifier_challenge_id: CHALLENGE,
      challenger_ref: `user://${NS}/charge-nurse`,
      challenge_kind: "evidence",
      adjudicator_policy_ref: `policy://${NS}/assertion-adjudication`,
      resolution: "upheld",
      ...overrides,
    });

  const unreceipted = await resolveWith("m053-challenge-unreceipted", {});
  ok(
    "RESOLUTION REFUSES: a standing that changed with no assurance receipt is a verdict nobody stands behind",
    unreceipted.status >= 400 && code(unreceipted.j) === "provenance_assertion_ref_not_canonical",
    `status ${unreceipted.status} code ${code(unreceipted.j)}`,
  );

  const noLadder = await resolveWith("m053-challenge-no-ladder", {
    resolution_receipt_ref: `receipt://${NS}/assurance/batch/11`,
  });
  ok(
    "RESOLUTION REFUSES: a subject with NO assurance ladder at all cannot be resolved — the refusal is the M06 owner scope's, reached before any receipt comparison",
    noLadder.status >= 400 && noLadder.status !== 201,
    `status ${noLadder.status} code ${code(noLadder.j)}`,
  );

  // The REAL ladder over this exact assertion revision, through M06's own route.
  const ladder = await climbLadderToAdjudication(
    target,
    CHALLENGE,
    "upheld",
    "m053-assertion",
    "disputed",
  );
  ok(
    "M06 LADDER: the challenged assertion revision really climbs to adjudication through M06's own route, and the adjudication binds this exact challenge and this subject's owner-resolved bytes",
    ladder.response?.status === 201 &&
      ladder.record?.to_stage === "adjudicated" &&
      ladder.record?.challenge_resolution?.verifier_challenge_id === CHALLENGE &&
      ladder.record?.challenge_resolution?.challenged_subject_ref === target &&
      ladder.record?.challenge_resolution?.challenged_subject_content_hash ===
        ladder.record?.subject_content_hash &&
      ladder.record?.subject_resolved_by ===
        "provenance_assertion_routes::resolve_admitted_assertion",
    `status ${ladder.response?.status} stage ${ladder.record?.to_stage}`,
  );
  ok(
    "M06 OUTCOME COUPLING: an UPHELD challenge cannot be recorded as a clean pass — the ladder carries a disputed outcome class beside the sustained finding",
    ladder.record?.outcome_class === "disputed" &&
      ladder.record?.challenge_resolution?.resolution === "upheld",
    `${ladder.record?.outcome_class}`,
  );

  const forged = await resolveWith("m053-challenge-forged", {
    resolution_receipt_ref: `receipt://${NS}/assurance/batch/11`,
  });
  ok(
    "RESOLUTION REFUSES: with a REAL ladder present, a receipt-SHAPED string this daemon never admitted is still not on it — caller-authored evidence is not evidence (INV-37)",
    forged.status === 404 && code(forged.j) === "assurance_transition_receipt_absent",
    `status ${forged.status} code ${code(forged.j)}`,
  );

  const ordinaryStep = await resolveWith("m053-challenge-ordinary-step", {
    resolution_receipt_ref: ladder.ordinaryReceipt,
  });
  ok(
    "RESOLUTION REFUSES: a REAL admitted receipt from an ORDINARY rung of this subject's own ladder adjudicates no challenge — existing is not the same as resolving",
    ordinaryStep.status >= 400 &&
      code(ordinaryStep.j) === "assurance_transition_receipt_resolves_no_challenge",
    `status ${ordinaryStep.status} code ${code(ordinaryStep.j)}`,
  );

  const wrongSubjectLadder = await climbLadderToAdjudication(
    record.assertion_id,
    CHALLENGE,
    "upheld",
    "m053-other-subject",
    "disputed",
  );
  const wrongSubject = await resolveWith("m053-challenge-wrong-subject", {
    resolution_receipt_ref: wrongSubjectLadder.receipt,
  });
  // WHAT THIS ACTUALLY PROVES, stated exactly. The lookup is SCOPED to the subject whose standing is
  // changing, so a receipt admitted over a neighbouring revision is not compared and rejected — it is
  // unreachable, and the refusal is absence. That scoping is the real fence; the subject and
  // subject-hash equalities inside the resolver are defence in depth against a future reader that
  // widened it, and no live path reaches them today. Recorded as such rather than dressed up as a
  // comparison this build performs.
  ok(
    "RESOLUTION REFUSES: a REAL admitted receipt adjudicating a DIFFERENT subject is not reachable from this subject's ladder at all — cross-subject substitution is refused by stream SCOPING, not by comparison",
    wrongSubject.status === 404 && code(wrongSubject.j) === "assurance_transition_receipt_absent",
    `status ${wrongSubject.status} code ${code(wrongSubject.j)}`,
  );

  const wrongChallenge = await resolveWith("m053-challenge-wrong-challenge", {
    verifier_challenge_id: `verifier-challenge://${NS}/a-different-dispute`,
    resolution_receipt_ref: ladder.receipt,
  });
  ok(
    "RESOLUTION REFUSES: a REAL admitted receipt that resolves a DIFFERENT challenge — the binding v1 could not carry",
    wrongChallenge.status >= 400 &&
      [
        "assurance_transition_receipt_challenge_mismatch",
        "provenance_assertion_challenge_not_open",
      ].includes(code(wrongChallenge.j)),
    `status ${wrongChallenge.status} code ${code(wrongChallenge.j)}`,
  );

  const wrongOutcome = await resolveWith("m053-challenge-wrong-outcome", {
    resolution: "rejected",
    resolution_receipt_ref: ladder.receipt,
  });
  ok(
    "RESOLUTION REFUSES: the request cannot claim an outcome the LADDER did not record",
    wrongOutcome.status >= 400 &&
      code(wrongOutcome.j) === "provenance_assertion_resolution_disagrees_with_its_receipt",
    `status ${wrongOutcome.status} code ${code(wrongOutcome.j)}`,
  );

  const upheld = await resolveWith("m053-challenge-upheld", {
    resolution_receipt_ref: ladder.receipt,
  });
  const rejectedClaim = upheld.j?.provenance_assertion ?? {};
  ok(
    "RESOLUTION: an UPHELD challenge rejects the claim it upheld, and the resolution and its receipt stay addressable",
    upheld.status === 201 &&
      rejectedClaim.challenge_state?.standing === "upheld" &&
      rejectedClaim.status === "rejected" &&
      rejectedClaim.challenge_state.resolution_receipt_refs.length === 1 &&
      rejectedClaim.challenge_state.open_challenge_refs.length === 0,
    JSON.stringify(rejectedClaim.challenge_state ?? null),
  );
  ok(
    "RESOLUTION: the rejected claim's content hash STILL did not move, across two durable writes — a rejected claim is retained, not deleted",
    rejectedClaim.content_hash === successor.content_hash,
    `${rejectedClaim.content_hash}`,
  );
  return { target };
}

// ------------------------------------------- the query IS the plane: censuses, bitemporal, durability
async function runQueryAndDurability(ctx) {
  const graph = await req("GET", `${PA}?${paQuery}`);
  ok(
    "QUERY: the plane reports a census of what argued against it — negative, contradicted, disputed, rejected, held-unknown and superseded counts travel with the records",
    graph.status === 200 &&
      graph.j?.rejected_count === 1 &&
      graph.j?.superseded_count === 1 &&
      typeof graph.j?.contradicted_count === "number" &&
      typeof graph.j?.held_unknown_count === "number",
    JSON.stringify({
      rejected: graph.j?.rejected_count,
      superseded: graph.j?.superseded_count,
      contradicted: graph.j?.contradicted_count,
    }),
  );
  const byPredicate = await req(
    "GET",
    `${PA}?${paQuery}&predicate_ref=${encodeURIComponent(term(NS, NAME, "triage-level"))}`,
  );
  ok(
    "QUERY: the graph is queryable by subject/predicate/polarity/status rather than only by identity — provenance is a plane, not a rendering of logs",
    byPredicate.status === 200 && byPredicate.j?.revision_count === graph.j?.revision_count,
    `${byPredicate.j?.revision_count}`,
  );

  const beforeRestart = await chainState(PA, paQuery);
  const asOfTx = await req("GET", `${PA}?${paQuery}&as_of_transaction_time=2020-01-01T00:00:00Z`);
  ok(
    "BITEMPORAL: transaction-time travel to before this family existed returns an empty answer rather than the current head",
    asOfTx.status === 200 && asOfTx.j?.revision_count === 0,
    `count ${asOfTx.j?.revision_count}`,
  );
  const asOfValid = await req("GET", `${PA}?${paQuery}&as_of_valid_time=2026-08-30T04:00:00Z`);
  ok(
    "BITEMPORAL: valid-time travel narrows INDEPENDENTLY — the claims held true at 04:00 are a different set from the claims recorded by then",
    asOfValid.status === 200 &&
      asOfValid.j?.revision_count > 0 &&
      asOfValid.j?.lineage_revision_count === beforeRestart.count,
    `valid ${asOfValid.j?.revision_count} lineage ${asOfValid.j?.lineage_revision_count}`,
  );

  const foreignRead = await req("GET", `${PA}?${paQuery}`, undefined, { as: "B" });
  ok(
    "ACCESS: a principal with no scope cannot read this family's assertions, and cannot use the route as an existence oracle",
    foreignRead.status >= 400 && foreignRead.status !== 200,
    `status ${foreignRead.status} code ${code(foreignRead.j)}`,
  );

  await stopDaemon();
  await startDaemon();
  const bootAfter = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    {
      token: daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null,
      password: "provenance-a-v1",
    },
    { as: null },
  );
  if (bootAfter.j?.session_token) SESSIONS.A = bootAfter.j.session_token;

  const afterRestart = await chainState(PA, paQuery);
  ok(
    "RESTART: head and revision count survive a full daemon restart — durable truth is the chain, not the process",
    afterRestart.head === beforeRestart.head && afterRestart.count === beforeRestart.count,
    `${beforeRestart.head}/${beforeRestart.count} -> ${afterRestart.head}/${afterRestart.count}`,
  );
  ok(
    "INDEX REBUILD, POSITIVELY DETECTED: the first read after restart reports the process-local cache REBUILT, so an unchanged answer is not mistaken for a cache that was never dropped",
    afterRestart.j?.projection_index_state === "rebuilt_from_agentgres" &&
      afterRestart.j?.projection_source === "agentgres_owner_scoped_chain",
    afterRestart.j?.projection_index_state ?? "",
  );
  const second = await chainState(PA, paQuery);
  ok(
    "INDEX IS NEVER AN ANSWER SOURCE: the second read reports agreement and returns the same answer",
    second.j?.projection_index_state === "agreed_with_agentgres" && second.head === afterRestart.head,
    second.j?.projection_index_state ?? "",
  );
  const survived = await req("GET", `${PA}?${paQuery}&revision=2`);
  const survivor = survived.j?.records?.[0] ?? {};
  ok(
    "RESTART: the folded standing, the retained contradiction and the resolution receipt all survive — none of it was a process-local memory",
    survivor.challenge_state?.standing === "upheld" &&
      survivor.status === "rejected" &&
      survivor.contradiction_state?.contradicting_assertion_refs?.length === 1 &&
      survivor.content_hash === recomputeCommitment(survivor, PA_RULE),
    JSON.stringify(survivor.challenge_state ?? null),
  );

  const replay = await req("POST", PA, assertionBody({ idempotency_key: "m053-assert-1" }));
  const afterReplay = await chainState(PA, paQuery);
  ok(
    "REPLAY: the same idempotency key across a RESTART replays the original admitted revision and appends nothing",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.provenance_assertion?.revision_ordinal === 1 &&
      afterReplay.count === afterRestart.count,
    `status ${replay.status} replayed ${replay.j?.replayed} count ${afterReplay.count}`,
  );
}

function runSourceClaims() {
  const source = fs.readFileSync(ROUTE_SOURCE, "utf8");
  ok(
    "NO AUTHORITY PLANE: the module consults, mints, widens and redeems no capability, lease, grant, approval or effect admission",
    !/CapabilityLease|capability_lease|mint_grant|authority_grant|approval_ceremony|effect_admission|redeem/u.test(
      source,
    ),
    "source-text absence over the module that owns the assertion family",
  );
  ok(
    "OWNER SEAM, NOT A SECOND READER: the predicate is resolved through M05.1's published term reader, and this module opens no storage reader of its own",
    /resolve_admitted_term/u.test(source) &&
      !/read_record|write_record|remove_record|fs::(?:read|write)/u.test(source),
    "source-text absence of a second store",
  );
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const v1 = registry.contracts.find(
    (entry) => entry.contract_id === "schema://ioi/foundations/ontology-assertion/v1",
  );
  const v2 = registry.contracts.find(
    (entry) => entry.contract_id === "schema://ioi/foundations/ontology-assertion/v2",
  );
  ok(
    "REGISTERED SUCCESSION: v2 declares v1 as its predecessor, v1 points forward to v2, and v1 records REMAIN VALID — the succession is recorded, not implied",
    v2?.evolution?.successor_of === "schema://ioi/foundations/ontology-assertion/v1" &&
      v2?.evolution?.predecessor_remains_valid === true &&
      v2?.evolution?.migration_policy === "explicit_adapter_required" &&
      v1?.evolution?.successor_contract_id === "schema://ioi/foundations/ontology-assertion/v2",
    JSON.stringify(v2?.evolution ?? null),
  );
  ok(
    "REGISTERED: the v2 family carries a generated projection pair, a cross-field invariant profile, and both positive and negative fixture corpora",
    v2?.generated_targets?.length === 2 &&
      v2?.cross_field_invariant_refs?.length === 1 &&
      v2?.positive_fixture_refs?.length >= 9 &&
      v2?.negative_fixture_refs?.length >= 20,
    `${v2?.positive_fixture_refs?.length} positive / ${v2?.negative_fixture_refs?.length} negative`,
  );
}

// -------------------------------------------------------------------------------- planted mutations

/// Each mutant names the EXACT assertion it must redden. An off-target kill proves the harness, not
/// the gate, so a mutant that reddens something else — or nothing — fails the battery.
const MUTANTS = [
  {
    id: "any-receipt-shaped-string-resolves",
    file: RECEIPT_OWNER_SOURCE,
    // A GENUINE BYPASS: absent receipt falls back to the newest adjudication, so the forged request
    // reaches a real resolution path and succeeds.
    find: '    let matched = ladder.iter().find(|entry| {\n        entry\n            .pointer("/admission/agentgres_receipt_ref")\n            .and_then(Value::as_str)\n            == Some(receipt_ref)\n    });',
    replace: '    let matched = ladder.iter().find(|entry| {\n        entry\n            .pointer("/admission/agentgres_receipt_ref")\n            .and_then(Value::as_str)\n            == Some(receipt_ref)\n    }).or_else(|| ladder.iter().rev().find(|entry| entry.get("to_stage").and_then(Value::as_str) == Some("adjudicated")));',
    target:
      "RESOLUTION REFUSES: with a REAL ladder present, a receipt-SHAPED string this daemon never admitted is still not on it — caller-authored evidence is not evidence (INV-37)",
  },
  {
    id: "an-ordinary-ladder-step-resolves-a-challenge",
    file: RECEIPT_OWNER_SOURCE,
    find: "    if resolution.is_empty() {",
    replace: "    if false && resolution.is_empty() {",
    target:
      "RESOLUTION REFUSES: a REAL admitted receipt from an ORDINARY rung of this subject's own ladder adjudicates no challenge — existing is not the same as resolving",
  },
  {
    id: "a-receipt-may-resolve-another-challenge",
    file: RECEIPT_OWNER_SOURCE,
    find: "    if challenge_id != expected_challenge_id {",
    replace: "    if false && challenge_id != expected_challenge_id {",
    target:
      "RESOLUTION REFUSES: a REAL admitted receipt that resolves a DIFFERENT challenge — the binding v1 could not carry",
  },
  {
    id: "the-receipt-lookup-stops-being-subject-scoped",
    file: RECEIPT_OWNER_SOURCE,
    // The cross-subject fence in this build is the SCOPING of the lookup, not a comparison. Dropping
    // receipt identity from the match is the smallest change that makes SOME other adjudication
    // reachable through this subject's own ladder read.
    find: '    let matched = ladder.iter().find(|entry| {\n        entry\n            .pointer("/admission/agentgres_receipt_ref")\n            .and_then(Value::as_str)\n            == Some(receipt_ref)\n    });',
    replace: '    let matched = ladder.iter().rev().find(|entry| entry.get("to_stage").and_then(Value::as_str) == Some("adjudicated"));',
    target:
      "RESOLUTION REFUSES: a REAL admitted receipt adjudicating a DIFFERENT subject is not reachable from this subject's ladder at all — cross-subject substitution is refused by stream SCOPING, not by comparison",
  },
  {
    id: "the-request-may-outvote-its-receipt",
    file: ROUTE_SOURCE,
    find: "        if resolved.resolution != resolution {",
    replace: "        if false && resolved.resolution != resolution {",
    target: "RESOLUTION REFUSES: the request cannot claim an outcome the LADDER did not record",
  },
  {
    id: "an-upheld-challenge-may-be-a-clean-pass",
    file: RECEIPT_OWNER_SOURCE,
    find: "    if !permitted_outcomes.contains(&outcome_class) {",
    replace: "    if false && !permitted_outcomes.contains(&outcome_class) {",
    target:
      "M06 OUTCOME COUPLING: an UPHELD challenge cannot be recorded as a clean pass — the ladder carries a disputed outcome class beside the sustained finding",
  },
  {
    id: "an-undeclared-predicate-resolves",
    file: OWNER_SEAM_SOURCE,
    // A GENUINE BYPASS: a term no set of the bound revision declares resolves anyway, as an entity
    // type. The assertion is then ADMITTED over a predicate the revision never declared — a real
    // false record, not a different refusal code.
    find: "    }) else {\n        return Err(bad(\n            StatusCode::NOT_FOUND,\n            \"ontology_version_term_absent\",",
    replace: "    }).or(Some(\"entity_types\")) else {\n        return Err(bad(\n            StatusCode::NOT_FOUND,\n            \"ontology_version_term_absent\",",
    target:
      "ASSERTION REFUSES: a well-formed, correctly-namespaced, canonical predicate the bound revision NEVER DECLARED — the one claim no byte-level fixture can decide",
  },
  {
    id: "v1-schema-version-is-read-as-v2",
    file: ROUTE_SOURCE,
    find: '    if !declared.is_empty() && declared != SCHEMA_VERSION {',
    replace: '    if false && declared != SCHEMA_VERSION {',
    target:
      "SUCCESSION REFUSES: a caller naming the PREDECESSOR contract is refused by name rather than read as v2 — reading a v1 request as a v2 record is the exact reinterpretation this version exists to avoid",
  },
  {
    id: "challenge-state-enters-the-content-commitment",
    file: ROUTE_SOURCE,
    find: '    "universality_nonclaim",\n    "authority_nonclaim",\n];',
    replace: '    "universality_nonclaim",\n    "authority_nonclaim",\n    "challenge_state",\n];',
    target:
      "CHALLENGE: the challenged claim's CONTENT HASH did not move, across a durable write of a different operation kind",
  },
  {
    id: "unknown-may-carry-a-confidence",
    file: ROUTE_SOURCE,
    find: '    if kind == "unknown" && (!confidence.is_null() || !estimator_ref.is_null()) {',
    replace: '    if false && kind == "unknown" {',
    target:
      "ASSERTION REFUSES: declining to claim is NOT claiming zero — an 'unknown' posture carries no confidence",
  },
  {
    id: "unknown-may-license-a-consequence",
    file: ROUTE_SOURCE,
    find: '        && consequence_scopes.as_array().map_or(0, Vec::len) > 0\n    {',
    replace: '        && false\n    {',
    target:
      "ASSERTION REFUSES: a domain that declines to claim also declines to license acting on the claim",
  },
  {
    id: "contradictions-need-not-be-retained",
    file: ROUTE_SOURCE,
    find: '    if block\n        .get("retained")\n        .is_some_and(|value| value != &json!(true))\n    {',
    replace: '    if false\n    {',
    target:
      "ASSERTION REFUSES: a record that drops a contradiction has not resolved it — retention is not optional",
  },
  {
    id: "contradiction-class-may-understate-the-refs",
    file: ROUTE_SOURCE,
    find: '    if class == "none" && count > 0 {',
    replace: '    if false && count > 0 {',
    target:
      "ASSERTION REFUSES: calling the record clean while naming what disputes it is the same defect from the other side",
  },
  {
    id: "contradicting-evidence-may-be-filed-as-support",
    file: ROUTE_SOURCE,
    find: '        if evidence_class == "contradicting" && supports == "affirmative" {',
    replace: '        if false && evidence_class == "contradicting" {',
    target:
      "ASSERTION REFUSES: evidence declared contradicting cannot also be filed as support — that pair is how a bundle looks unanimous",
  },
  {
    id: "one-artifact-may-be-counted-twice",
    file: ROUTE_SOURCE,
    find: '        if seen.iter().any(|previous| previous == &evidence_ref) {',
    replace: '        if false && seen.iter().any(|previous| previous == &evidence_ref) {',
    target: "ASSERTION REFUSES: counting one artifact twice is how a thin evidence set looks thick",
  },
  {
    id: "an-unattributed-claim-is-admitted",
    file: ROUTE_SOURCE,
    find: '    if entries.is_empty() {\n        return Err(refuse(\n            "provenance_assertion_source_required",',
    replace: '    if false {\n        return Err(refuse(\n            "provenance_assertion_source_required",',
    target:
      "ASSERTION REFUSES: an unattributed claim is a rendering of a log, which is the thing this object exists instead of",
  },
  {
    id: "supersession-needs-no-reason",
    file: ROUTE_SOURCE,
    find: '    if supersedes_ref.is_null() != (reason == "none") {',
    replace: '    if false {',
    target: "ASSERTION REFUSES: supersession without a stated reason is a deletion with extra steps",
  },
  {
    id: "point-confidence-needs-no-estimator",
    file: ROUTE_SOURCE,
    find: '    if kind == "point_confidence" && (confidence.is_null() || estimator_ref.is_null()) {',
    replace: '    if kind == "point_confidence" && confidence.is_null() {',
    target: "ASSERTION REFUSES: a confidence with no estimator cannot be compared across estimators",
  },
  {
    id: "index-reports-agreement-it-did-not-have",
    file: ROUTE_SOURCE,
    find: '        None => "rebuilt_from_agentgres",',
    replace: '        None => "agreed_with_agentgres",',
    target:
      "INDEX REBUILD, POSITIVELY DETECTED: the first read after restart reports the process-local cache REBUILT, so an unchanged answer is not mistaken for a cache that was never dropped",
  },
  {
    id: "upheld-challenge-leaves-the-claim-admitted",
    file: ROUTE_SOURCE,
    find: '        "upheld" => return "rejected",',
    replace: '        "upheld" => return "admitted",',
    target:
      "RESOLUTION: an UPHELD challenge rejects the claim it upheld, and the resolution and its receipt stay addressable",
  },
  {
    id: "v1-challenge-envelope-is-downgraded-into",
    file: ROUTE_SOURCE,
    find: '    if !declared_contract.is_empty() && declared_contract != CHALLENGE_CONTRACT {',
    replace: '    if false && declared_contract != CHALLENGE_CONTRACT {',
    target:
      "CHALLENGE REFUSES: a v1 envelope is refused BY NAME — its challenged_ref pattern cannot address a semantic-plane subject at all",
  },

];

/// The digest one complete ledger is allowed to speak for.
///
/// It covers this verifier's own bytes AND every source its mutants plant into. A ledger row proves
/// a fence held in the tree that produced it; carried onto an edited tree it proves nothing, and a
/// stale row that still reads RED_ON_TARGET is worse than a missing one. So the digest travels with
/// the ledger and `--summarize` refuses any ledger that does not match the tree in front of it.
function harnessDigest() {
  const files = [fileURLToPath(import.meta.url), ...new Set(MUTANTS.map((m) => m.file))].sort();
  const hash = crypto.createHash("sha256");
  for (const file of files) {
    hash.update(file.slice(ROOT.length));
    hash.update(fs.readFileSync(file));
  }
  return `sha256:${hash.digest("hex")}`;
}

function rebuild() {
  const build = spawnSync(
    "cargo",
    ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 28 },
  );
  return build.status === 0;
}

async function runMutationBattery() {
  const originals = new Map();
  for (const mutant of MUTANTS) {
    if (!originals.has(mutant.file)) originals.set(mutant.file, fs.readFileSync(mutant.file, "utf8"));
  }
  const restore = () => {
    for (const [file, text] of originals) fs.writeFileSync(file, text);
  };
  process.on("exit", restore);
  process.on("SIGINT", () => {
    restore();
    process.exit(130);
  });

  const selected = ONLY.length > 0 ? MUTANTS.filter((m) => ONLY.includes(m.id)) : MUTANTS;
  const rows = [];
  for (const mutant of selected) {
    restore();
    const original = originals.get(mutant.file);
    if (!original.includes(mutant.find)) {
      rows.push({ id: mutant.id, verdict: "STALE", detail: "anchor absent from current source" });
      continue;
    }
    const mutated = original.replace(mutant.find, mutant.replace);
    fs.writeFileSync(mutant.file, mutated);
    if (!rebuild()) {
      rows.push({ id: mutant.id, verdict: "NO_BUILD", detail: "mutant did not compile" });
      continue;
    }
    results.length = 0;
    let crashed = "";
    try {
      await runAll();
    } catch (error) {
      crashed = String(error);
    }
    await stopDaemon();
    const hit = results.find((entry) => entry.name === mutant.target);
    const otherFailures = results.filter((entry) => !entry.pass && entry.name !== mutant.target);
    rows.push({
      id: mutant.id,
      verdict: hit && !hit.pass ? "RED_ON_TARGET" : crashed ? "CRASHED" : "SURVIVED",
      collateral: otherFailures.length,
      detail: crashed || (hit ? hit.detail : "target assertion did not execute"),
    });
    process.stdout.write(`  ${rows.at(-1).verdict.padEnd(14)} ${mutant.id}\n`);
  }
  restore();
  const restored = MUTANTS.every((mutant) =>
    fs.readFileSync(mutant.file, "utf8") === originals.get(mutant.file),
  );
  const digest = harnessDigest();
  const previous = fs.existsSync(LEDGER) ? JSON.parse(fs.readFileSync(LEDGER, "utf8")) : {};
  // A ledger speaks for ONE tree. If the harness or any mutated source moved since the last chunk,
  // the older rows are about a tree that no longer exists and are dropped rather than merged.
  const ledger = previous.harness_digest === digest ? previous : { harness_digest: digest, rows: {} };
  ledger.harness_digest = digest;
  ledger.rows = ledger.rows ?? {};
  for (const row of rows) ledger.rows[row.id] = row;
  fs.writeFileSync(LEDGER, JSON.stringify(ledger, null, 2));
  rebuild();
  const reds = rows.filter((row) => row.verdict === "RED_ON_TARGET").length;
  const collateral = rows.reduce((total, row) => total + (row.collateral ?? 0), 0);
  process.stdout.write(
    `\nM05.3 mutation battery: ${reds}/${rows.length} RED ON TARGET; collateral failures ${collateral}; source restored ${restored}\n`,
  );
  process.stdout.write(`harness digest ${digest}\n`);
  process.exit(reds === rows.length && restored ? 0 : 1);
}

function summarize() {
  const digest = harnessDigest();
  const stored = fs.existsSync(LEDGER) ? JSON.parse(fs.readFileSync(LEDGER, "utf8")) : {};
  const current = stored.harness_digest === digest;
  const ledger = current ? (stored.rows ?? {}) : {};
  const missing = MUTANTS.filter((mutant) => !ledger[mutant.id]).map((mutant) => mutant.id);
  const notRed = Object.values(ledger).filter((row) => row.verdict !== "RED_ON_TARGET");
  for (const mutant of MUTANTS) {
    const row = ledger[mutant.id];
    process.stdout.write(`  ${(row?.verdict ?? "NOT_RUN").padEnd(14)} ${mutant.id}\n`);
  }
  process.stdout.write(
    `\nharness digest ${digest}\nledger digest  ${stored.harness_digest ?? "(none)"}${current ? "" : "  <- STALE: rows are about a different tree"}\n`,
  );
  process.stdout.write(
    `\nM05.3 mutation summary: ${MUTANTS.length - missing.length - notRed.length}/${MUTANTS.length} RED ON TARGET\n`,
  );
  // A chunk that never ran is a MISSING ROW, not a silent pass; and a ledger for another tree is
  // treated as no ledger at all.
  process.exit(current && missing.length === 0 && notRed.length === 0 ? 0 : 1);
}


// ------------------------------------------------------------------------------------------- driver

async function runAll() {
  const ctx = await run();
  const graph = await runGraph(ctx);
  await runQueryAndDurability(graph);
  runSourceClaims();
}

/// Pre-flight the battery's own anchors WITHOUT running it.
///
/// A stale anchor is a mutant that silently tests nothing, and discovering one costs a full rebuild
/// per mutant if the battery finds it. This reads the SAME array the battery plants from — no
/// parsing, no second copy — and reports any anchor that does not appear exactly once in its target.
/// Exactly once matters: `String.replace` plants at the first match, so an ambiguous anchor may
/// mutate a site other than the one its target names.
function checkAnchors() {
  const seen = new Map();
  let problems = 0;
  for (const mutant of MUTANTS) {
    if (!seen.has(mutant.file)) seen.set(mutant.file, fs.readFileSync(mutant.file, "utf8"));
    const text = seen.get(mutant.file);
    const count = text.split(mutant.find).length - 1;
    if (count !== 1) {
      problems += 1;
      process.stdout.write(
        `  ${count === 0 ? "STALE" : `AMBIGUOUS(${count})`}  ${mutant.id}\n`,
      );
    }
  }
  process.stdout.write(`\n${MUTANTS.length} mutants, ${problems} anchor problems\n`);
  process.exit(problems === 0 ? 0 : 1);
}

async function main() {
  if (ANCHORS) return checkAnchors();
  if (SUMMARIZE) return summarize();
  if (MUTATE) return runMutationBattery();
  try {
    await runAll();
  } finally {
    await stopDaemon();
    cleanup();
  }
  const failed = results.filter((entry) => !entry.pass);
  for (const entry of results) {
    process.stdout.write(`${entry.pass ? "PASS" : "FAIL"}  ${entry.name}${entry.detail ? `  [${entry.detail}]` : ""}\n`);
  }
  emitVerifierCensus({
    verifierId: "provenance-assertion-graph",
    sourceUrl: import.meta.url,
    results,
  });
  process.stdout.write(
    `\ncheck:provenance-assertion-graph — ${results.length - failed.length}/${results.length} assertions\n`,
  );
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((error) => {
  cleanup();
  process.stderr.write(`${error}\n`);
  process.exit(1);
});
