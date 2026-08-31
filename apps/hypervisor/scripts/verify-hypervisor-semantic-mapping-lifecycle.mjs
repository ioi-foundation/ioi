#!/usr/bin/env node
// M05.2 — overlays, crosswalks and mapping decisions, driven end to end against a live daemon and
// its durable Agentgres chains.
//
// WHAT THIS GATE IS FOR. Three canonical objects share two base envelopes, so the whole value of the
// unit is that they are SEPARATE — separate identities, separate streams, separate lifetimes — and
// that a mapping is a receipted challengeable decision rather than a config row. The claims here are:
// an overlay diverges from an exact base without forking it; a crosswalk declares a correspondence
// between two exact resolved endpoints with its loss and ambiguity stated; a decision APPLIES one
// exact crosswalk revision under named reviewer lineage and must dispose of every ambiguity the map
// named; a challenge changes standing without moving the bytes it challenged; and cross-domain
// APPLICATION refuses by name because its terms-acceptance owner has not landed.
//
// THE DEFECTS THE REGISTERED CORPUS STRUCTURALLY CANNOT CATCH. Every negative fixture beside this
// gate is decidable from bytes alone. These are not:
//   * "is this endpoint a revision THIS chain admitted" — a fact about the ontology owner's chain;
//   * "is this ambiguity one the APPLIED crosswalk actually named" — a fact about another chain;
//   * "does a challenge leave the challenged revision's content hash where it was" — a fact about
//     two reads separated by a durable write;
//   * "does the answer survive a restart with the process-local index gone".
// All four are refused or proved HERE, live, and the mutation battery plants each as a named target.
//
// HOW IT AVOIDS GRADING ITSELF:
//   * CONTENT HASHES ARE RECOMPUTED FROM CANON, not from the response. The material field list is
//     read out of the REGISTERED invariant profile and the digest is taken here in JavaScript.
//   * EVERY BINDING IS A REAL ADMITTED RECORD, minted through its own owner's route in this same run.
//   * DURABLE TRUTH IS READ ACROSS A RESTART, with the index rebuild positively detected.
//   * REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the lineage afterwards and
//     requires head and revision count to be exactly what they were.
//   * A GREEN RUN CERTIFIES NOTHING UNTIL THE HARNESS PROVES IT RED. `--mutate` plants named defects
//     in this module's own source, rebuilds, re-runs, and requires each to redden the exact assertion
//     it targets; the source is restored and byte-verified before exit.
//
// NONCLAIMS. This gate proves the mapping plane only. It makes no claim that a mapping is
// semantically correct, that a reviewer was qualified, that a declared loss is the real loss, or that
// cross-domain application would be safe once M11.1 lands. It asserts that no authority plane is
// consulted here — which is not the same as proving those planes elsewhere.

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
  "crates/node/src/bin/hypervisor_daemon_routes/semantic_mapping_routes.rs",
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
const LEDGER = path.join(os.tmpdir(), "ioi-m052-mutation-ledger.json");

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

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-m052-"));
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
      IOI_WALLET_SECRET_PASS: "ioi-semantic-mapping-verifier",
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
const OVL = "/v1/hypervisor/ontology-overlays";
const XW = "/v1/hypervisor/ontology-crosswalks";
const XWC = "/v1/hypervisor/ontology-crosswalks/challenges";
const DEC = "/v1/hypervisor/semantic-mapping-decisions";
const DECC = "/v1/hypervisor/semantic-mapping-decisions/challenges";
const AT = "/v1/hypervisor/assurance-transitions";

/// Climb the canonical ladder over one subject and return the ADJUDICATION receipt.
///
/// A challenge resolution IS an adjudication, and adjudication is rung five, so the subject must
/// really have been attested, evidenced, verified and accepted first. Driving the whole ladder here
/// is what makes the receipt the gate hands to M05.2 a record this daemon actually admitted rather
/// than a string this file invented.
async function climbLadderToAdjudication(subject, challengeId, resolution, keyPrefix, outcome) {
  const stages = [
    ["attested", "positive", ["correctness", "acceptance", "settlement", "authority"]],
    ["evidenced", "positive", ["correctness", "acceptance", "settlement", "authority"]],
    ["verified", "positive", ["correctness", "acceptance", "settlement", "authority"]],
    ["accepted", "positive", ["correctness", "settlement", "authority"]],
  ];
  let head = null;
  let ordinaryReceipt = null;
  for (const [stage, outcomeClass, nonclaims] of stages) {
    const body = {
      owner_ref: "org://local",
      idempotency_key: `${keyPrefix}-${stage}`,
      subject_ref: subject,
      outcome_class: outcomeClass,
      evidence_refs: [`evidence://acme-clinic/${keyPrefix}-${stage}`],
      does_not_assert: nonclaims,
      valid_time: { starts_at: "2026-09-01T00:00:00Z", ends_at: null },
    };
    if (head !== null) body.expected_head = head;
    const step = await req("POST", AT, body);
    if (step.status !== 201) return { failedAt: stage, response: step };
    // Keep an ORDINARY rung's receipt: it is a real admitted receipt that adjudicates no challenge,
    // which is a different refusal from a receipt that does not exist at all.
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
    evidence_refs: [`evidence://acme-clinic/${keyPrefix}-adjudication`],
    does_not_assert: ["correctness", "settlement", "authority"],
    valid_time: { starts_at: "2026-09-01T00:00:00Z", ends_at: null },
    expected_head: head,
    challenge_resolution: {
      verifier_challenge_id: challengeId,
      resolution,
      adjudicator_ref: "org://local",
      adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
      reviewer_lineage: [
        {
          reviewer_ref: `user://${NS}/informatics-lead`,
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

/// Climb one subject only as far as `accepted` and hand back the head.
///
/// The M06 admission fences below are all REFUSALS, so they append nothing and can share one subject
/// parked at the rung an adjudication advances from. Parking it here — rather than reusing a subject
/// that already adjudicated — is what keeps each probe a test of the fence rather than of the
/// no-skip rule that would refuse it anyway.
async function climbLadderToAccepted(subject, keyPrefix) {
  const stages = [
    ["attested", ["correctness", "acceptance", "settlement", "authority"]],
    ["evidenced", ["correctness", "acceptance", "settlement", "authority"]],
    ["verified", ["correctness", "acceptance", "settlement", "authority"]],
    ["accepted", ["correctness", "settlement", "authority"]],
  ];
  let head = null;
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
    if (step.status !== 201) return { failedAt: stage, response: step, head: null };
    head = step.j?.expected_head_for_successor ?? null;
  }
  return { head };
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

const OVERLAY_RULE = commitmentRule(
  "ontology-overlay.v1.invariants.json",
  ".content_hash.commits_bases_divergence_and_valid_time",
);
const XW_RULE = commitmentRule(
  "ontology-crosswalk.v1.invariants.json",
  ".content_hash.commits_endpoints_mappings_risk_and_valid_time",
);
const DEC_RULE = commitmentRule(
  "semantic-mapping-decision.v1.invariants.json",
  ".content_hash.commits_crosswalk_reviewers_dispositions_and_valid_time",
);

let BASE_R1 = null;
let BASE_R2 = null;
let FOREIGN_R1 = null;
let OVERLAY_R1 = null;
let XW_R1 = null;

async function run() {
  await startDaemon();

  // ------------------------------------------------------------------------------------ principals
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "semantic-mapping-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "semantic-mapping-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "semantic-mapping-b-v1",
    },
    { as: "A" },
  );
  const principalB = created.j?.principal?.principal_id ?? "";
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "semantic-mapping-b@ioi.local", password: "semantic-mapping-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  ok(
    "PRECONDITION: two REAL authenticated principals exist, and B holds no tenant membership",
    SESSIONS.A.length > 0 && SESSIONS.B.length > 0 && principalB.length > 0,
    `A ${SESSIONS.A.length > 0} B ${SESSIONS.B.length > 0}`,
  );

  // ------------------------------------------------- REAL ontology revisions, through M05.1's route
  const genesis = await req(
    "POST",
    OV,
    ontologyProposal({ key: "m052-ontology-1", entities: ["triage-level", "legacy-note"] }),
  );
  BASE_R1 = genesis.j?.ontology_version?.ontology_id ?? null;
  const baseHead = genesis.j?.expected_head_for_successor ?? null;
  const successor = await req(
    "POST",
    OV,
    ontologyProposal({
      key: "m052-ontology-2",
      expectedHead: baseHead,
      entities: ["triage-level", "legacy-note", "acuity-band"],
    }),
  );
  BASE_R2 = successor.j?.ontology_version?.ontology_id ?? null;
  const foreign = await req(
    "POST",
    OV,
    ontologyProposal({
      ns: FOREIGN_NS,
      name: "intake",
      key: "m052-foreign-1",
      entities: ["severity"],
    }),
  );
  FOREIGN_R1 = foreign.j?.ontology_version?.ontology_id ?? null;
  ok(
    "PRECONDITION: three REAL ontology revisions in two owner-qualified namespaces are admitted through M05.1's OWN route in this same run — every binding below names something a chain actually holds",
    BASE_R1 === `ontology://${NS}/${NAME}/revision/1` &&
      BASE_R2 === `ontology://${NS}/${NAME}/revision/2` &&
      FOREIGN_R1 === `ontology://${FOREIGN_NS}/intake/revision/1`,
    `${BASE_R1} ${BASE_R2} ${FOREIGN_R1}`,
  );

  // --------------------------------------------------------------- an overlay diverges without forking
  const overlayBody = (overrides = {}) => ({
    owner_ref: "org://local",
    idempotency_key: "m052-overlay-1",
    namespace: NS,
    name: NAME,
    overlay_name: "night-clinic",
    governing_scope_ref: `domain://${NS}/clinical`,
    policy_hash: sha256("overlay-policy"),
    base_ontology_version_refs: [BASE_R1],
    added_terms: [
      {
        term_id: `ontology://${NS}/${NAME}/overlay/night-clinic/term/night-triage-band`,
        label: "Night triage band",
        term_kind: "entity",
      },
    ],
    overlaid_terms: [
      {
        base_term_id: term(NS, NAME, "triage-level"),
        overlay_disposition: "narrowed",
        overlay_label: "Triage level (night clinic subset)",
      },
    ],
    valid_time: { starts_at: "2026-06-01T00:00:00Z", ends_at: null },
    ...overrides,
  });

  const overlay = await req("POST", OVL, overlayBody());
  const overlayRecord = overlay.j?.ontology_overlay ?? {};
  OVERLAY_R1 = overlayRecord.overlay_id ?? null;
  ok(
    "OVERLAY: an overlay is admitted under its BASE family's own path, so it can never be addressed as the version it overlays",
    overlay.status === 201 &&
      OVERLAY_R1 === `ontology://${NS}/${NAME}/overlay/night-clinic/revision/1` &&
      overlayRecord.ontology_family_ref === `ontology://${NS}/${NAME}`,
    `${overlay.status} ${OVERLAY_R1}`,
  );
  ok(
    "OVERLAY: the base binding carries the BASE OWNER's committed content hash, resolved through M05.1's reader rather than asserted here",
    overlayRecord.base_ontology_bindings?.[0]?.ontology_version_ref === BASE_R1 &&
      overlayRecord.base_ontology_bindings?.[0]?.content_hash ===
        genesis.j?.ontology_version?.content_hash &&
      overlayRecord.base_resolved_by === "ontology_version_routes::resolve_admitted_revision",
    JSON.stringify(overlayRecord.base_ontology_bindings ?? null),
  );
  ok(
    "OVERLAY: the served content hash is exactly the one the REGISTERED invariant's own material list commits — recomputed here, not read back",
    overlayRecord.content_hash === recomputeCommitment(overlayRecord, OVERLAY_RULE),
    `${overlayRecord.content_hash} vs ${recomputeCommitment(overlayRecord, OVERLAY_RULE)}`,
  );
  ok(
    "OVERLAY: the record carries its fork and authority nonclaims, and no capability, lease or policy decision appears anywhere in it",
    overlayRecord.fork_nonclaim === "ontology_overlay_does_not_fork_or_redefine_its_base" &&
      overlayRecord.authority_nonclaim === "ontology_overlay_grants_no_authority" &&
      !/"(?:capability|lease|grant|scope):/u.test(JSON.stringify(overlayRecord)),
    overlayRecord.authority_nonclaim ?? "",
  );

  const overlayQuery = `namespace=${NS}&name=${NAME}&overlay_name=night-clinic`;
  let before = await chainState(OVL, overlayQuery);
  const mintsBaseTerm = await req(
    "POST",
    OVL,
    overlayBody({
      idempotency_key: "m052-overlay-mints-base",
      expected_head: before.head,
      compatibility: "additive",
      added_terms: [
        { term_id: term(NS, NAME, "smuggled"), label: "Smuggled", term_kind: "entity" },
      ],
    }),
  );
  let after = await refusesWithoutEffect(
    "OVERLAY REFUSES: minting a term inside the BASE family's namespace is an edit of the base, which is a fork",
    mintsBaseTerm,
    "ontology_overlay_added_term_in_foreign_namespace",
    OVL,
    overlayQuery,
  );
  ok(
    "OVERLAY REFUSES BY EFFECT: the fork attempt left the overlay's head and revision count exactly where they were",
    after.head === before.head && after.count === before.count,
    `${before.head}/${before.count} -> ${after.head}/${after.count}`,
  );

  const foreignBase = await req(
    "POST",
    OVL,
    overlayBody({
      idempotency_key: "m052-overlay-foreign-base",
      expected_head: before.head,
      compatibility: "additive",
      base_ontology_version_refs: [FOREIGN_R1],
    }),
  );
  after = await refusesWithoutEffect(
    "OVERLAY REFUSES: relocating itself onto another domain's lineage — the base must belong to the family the overlay lives under",
    foreignBase,
    "ontology_overlay_base_is_of_another_family",
    OVL,
    overlayQuery,
  );
  ok(
    "OVERLAY REFUSES BY EFFECT: the relocation attempt moved nothing",
    after.head === before.head && after.count === before.count,
    `${after.head}/${after.count}`,
  );

  const noDivergence = await req(
    "POST",
    OVL,
    overlayBody({
      idempotency_key: "m052-overlay-empty",
      expected_head: before.head,
      compatibility: "additive",
      added_terms: [],
      overlaid_terms: [],
    }),
  );
  await refusesWithoutEffect(
    "OVERLAY REFUSES: an overlay that adds nothing and overlays nothing is a second name for its base",
    noDivergence,
    "ontology_overlay_declares_no_divergence",
    OVL,
    overlayQuery,
  );

  const mutableBase = await req(
    "POST",
    OVL,
    overlayBody({
      idempotency_key: "m052-overlay-mutable-base",
      expected_head: before.head,
      compatibility: "additive",
      base_ontology_version_refs: [`ontology://${NS}/${NAME}`],
    }),
  );
  await refusesWithoutEffect(
    "OVERLAY REFUSES: a family ref names a lineage rather than a revision, so an overlay whose base can move is refused",
    mutableBase,
    "semantic_mapping_endpoint_not_canonical",
    OVL,
    overlayQuery,
  );

  const absentBase = await req(
    "POST",
    OVL,
    overlayBody({
      idempotency_key: "m052-overlay-absent-base",
      expected_head: before.head,
      compatibility: "additive",
      base_ontology_version_refs: [`ontology://${NS}/${NAME}/revision/9`],
    }),
  );
  await refusesWithoutEffect(
    "OVERLAY REFUSES: a well-formed base revision this chain never admitted is a typed absence, not an empty success — the defect no byte-level fixture can catch",
    absentBase,
    "ontology_version_revision_absent",
    OVL,
    overlayQuery,
  );
}

// --------------------------------------------------------------------- crosswalks and decisions
async function runMappings() {
  const xwQuery = `namespace=${NS}&name=intake-v1-to-v2`;
  const crosswalkBody = (overrides = {}) => ({
    owner_ref: "org://local",
    idempotency_key: "m052-crosswalk-1",
    namespace: NS,
    name: "intake-v1-to-v2",
    governing_scope_ref: `domain://${NS}/clinical`,
    policy_hash: sha256("crosswalk-policy"),
    source_ontology_version_ref: BASE_R1,
    target_ontology_version_ref: BASE_R2,
    term_mappings: [
      {
        source_term_id: term(NS, NAME, "triage-level"),
        target_term_id: term(NS, NAME, "acuity-band"),
        relation: "narrower",
        loss: "lossy_precision",
      },
      {
        source_term_id: term(NS, NAME, "legacy-note"),
        target_term_id: null,
        relation: "unmapped",
        loss: "unmapped",
      },
    ],
    compatibility_result: "lossy",
    risk_class: "moderate",
    declared_loss: "lossy_precision",
    residual_risk_refs: [`policy://${NS}/unmapped-legacy-note-is-escalated`],
    valid_time: { starts_at: "2026-07-01T00:00:00Z", ends_at: null },
    ...overrides,
  });

  const crosswalk = await req("POST", XW, crosswalkBody());
  const xwRecord = crosswalk.j?.ontology_crosswalk ?? {};
  XW_R1 = xwRecord.ontology_mapping_id ?? null;
  ok(
    "CROSSWALK: a declaration is admitted on its OWN family path, distinct from both endpoints' lineages and from the decision family that applies it",
    crosswalk.status === 201 &&
      XW_R1 === `ontology-mapping://${NS}/intake-v1-to-v2/crosswalk/revision/1` &&
      xwRecord.mapping_record_profile === "ontology_crosswalk",
    `${crosswalk.status} ${XW_R1}`,
  );
  ok(
    "CROSSWALK: both endpoints carry their OWN owners' committed hashes, and the declared endpoint list is exactly those two revisions",
    xwRecord.source_binding?.content_hash?.startsWith("sha256:") &&
      xwRecord.target_binding?.content_hash?.startsWith("sha256:") &&
      xwRecord.source_binding.content_hash !== xwRecord.target_binding.content_hash &&
      JSON.stringify(xwRecord.source_and_target_version_refs) ===
        JSON.stringify([BASE_R1, BASE_R2]),
    JSON.stringify(xwRecord.source_and_target_version_refs ?? null),
  );
  ok(
    "CROSSWALK: domain_relationship is SERVER-DERIVED from the two owner-qualified namespaces — same namespace reads in_domain",
    xwRecord.domain_relationship === "in_domain",
    xwRecord.domain_relationship ?? "",
  );
  ok(
    "CROSSWALK: an unmapped source term is RECORDED as unmapped and counted, rather than omitted; silent field equivalence is unrepresentable",
    xwRecord.mapping_risk?.unmapped_source_term_count === 1 &&
      xwRecord.term_mappings?.some((row) => row.relation === "unmapped" && row.loss === "unmapped"),
    JSON.stringify(xwRecord.mapping_risk ?? null),
  );
  ok(
    "CROSSWALK: the served content hash is exactly the REGISTERED invariant's own material, recomputed here",
    xwRecord.content_hash === recomputeCommitment(xwRecord, XW_RULE),
    `${xwRecord.content_hash}`,
  );
  ok(
    "CROSSWALK: an unchallenged declaration projects a v2-pinned challenge state with no open, resolved or receipted challenge",
    xwRecord.challenge_state?.standing === "unchallenged" &&
      xwRecord.challenge_state?.challenge_contract_ref ===
        "schema://ioi/foundations/objects/verifier-challenge-envelope/v2" &&
      xwRecord.challenge_state.open_challenge_refs.length === 0,
    JSON.stringify(xwRecord.challenge_state ?? null),
  );

  let before = await chainState(XW, xwQuery);
  const relabelled = await req(
    "POST",
    XW,
    crosswalkBody({
      idempotency_key: "m052-crosswalk-relabelled",
      expected_head: before.head,
      compatibility: "additive",
      expected_domain_relationship: "cross_domain",
    }),
  );
  await refusesWithoutEffect(
    "CROSSWALK REFUSES: the caller cannot assert a domain relationship the endpoints do not have; the discriminator the terms fence keys on is derived, never believed",
    relabelled,
    "ontology_crosswalk_domain_relationship_substituted",
    XW,
    xwQuery,
  );

  const understated = await req(
    "POST",
    XW,
    crosswalkBody({
      idempotency_key: "m052-crosswalk-understated",
      expected_head: before.head,
      compatibility: "additive",
      declared_loss: "none",
      compatibility_result: "exact",
    }),
  );
  await refusesWithoutEffect(
    "CROSSWALK REFUSES: declaring no loss while the declared rows leave a term unmapped — the posture must cover what the map actually does",
    understated,
    "ontology_crosswalk_declared_loss_understates_the_rows",
    XW,
    xwQuery,
  );

  const foreignTerm = await req(
    "POST",
    XW,
    crosswalkBody({
      idempotency_key: "m052-crosswalk-foreign-term",
      expected_head: before.head,
      compatibility: "additive",
      term_mappings: [
        {
          source_term_id: term(FOREIGN_NS, "intake", "severity"),
          target_term_id: term(NS, NAME, "acuity-band"),
          relation: "exact",
          loss: "none",
        },
      ],
      declared_loss: "none",
      compatibility_result: "exact",
    }),
  );
  await refusesWithoutEffect(
    "CROSSWALK REFUSES: a source term of a family this map did not bind — mapping FROM a term the bound source never declared",
    foreignTerm,
    "ontology_crosswalk_source_term_is_of_another_family",
    XW,
    xwQuery,
  );

  // ------------------------------------------------------- the ambiguous crosswalk, and its decision
  const ambiguous = await req(
    "POST",
    XW,
    crosswalkBody({
      idempotency_key: "m052-crosswalk-ambiguous",
      name: "intake-ambiguous",
      term_mappings: [
        {
          source_term_id: term(NS, NAME, "triage-level"),
          target_term_id: term(NS, NAME, "acuity-band"),
          relation: "narrower",
          loss: "lossy_precision",
        },
        {
          source_term_id: term(NS, NAME, "triage-level"),
          target_term_id: term(NS, NAME, "legacy-note"),
          relation: "related",
          loss: "lossy_scope",
        },
      ],
      compatibility_result: "requires_adapter",
      risk_class: "high",
      declared_loss: "lossy_scope",
    }),
  );
  const ambiguousRecord = ambiguous.j?.ontology_crosswalk ?? {};
  ok(
    "CROSSWALK: the ambiguity set is DERIVED from the rows — a source term with two targets IS ambiguous, so a caller cannot understate the set by omitting a name",
    ambiguous.status === 201 &&
      ambiguousRecord.ambiguous_term_refs?.length === 1 &&
      ambiguousRecord.ambiguous_term_refs[0] === term(NS, NAME, "triage-level") &&
      ambiguousRecord.mapping_risk?.ambiguous_term_count === 1,
    JSON.stringify(ambiguousRecord.ambiguous_term_refs ?? null),
  );

  const decisionBody = (overrides = {}) => ({
    owner_ref: "org://local",
    idempotency_key: "m052-decision-1",
    namespace: NS,
    name: "intake-v1-to-v2",
    governing_scope_ref: `domain://${NS}/clinical`,
    policy_hash: sha256("decision-policy"),
    applied_crosswalk_ref: XW_R1,
    application_target_refs: [`handoff://${NS}/night-intake-2026-08`],
    accepted_by_ref: `user://${NS}/informatics-lead`,
    residual_risk_refs: [`policy://${NS}/unmapped-legacy-note-is-escalated`],
    reviewer_lineage: [
      {
        reviewer_ref: `user://${NS}/informatics-lead`,
        review_role: "mapping_owner",
        reviewed_at: "2026-08-30T10:30:00Z",
        review_decision: "approved",
      },
      {
        reviewer_ref: `user://${NS}/intake-clinician`,
        review_role: "source_domain_reviewer",
        reviewed_at: "2026-08-30T10:45:00Z",
        review_decision: "approved_with_conditions",
      },
    ],
    ambiguity_dispositions: [],
    unmapped_term_dispositions: [
      { source_term_id: term(NS, NAME, "legacy-note"), disposition: "escalated" },
    ],
    valid_time: { starts_at: "2026-08-30T11:00:00Z", ends_at: null },
    ...overrides,
  });

  const decision = await req("POST", DEC, decisionBody());
  const decRecord = decision.j?.semantic_mapping_decision ?? {};
  ok(
    "DECISION: an application is admitted on its OWN family path and binds the EXACT crosswalk revision and hash it applied",
    decision.status === 201 &&
      decRecord.ontology_mapping_id ===
        `ontology-mapping://${NS}/intake-v1-to-v2/decision/revision/1` &&
      decRecord.applied_crosswalk_binding?.ontology_mapping_id === XW_R1 &&
      decRecord.applied_crosswalk_binding?.content_hash === xwRecord.content_hash,
    JSON.stringify(decRecord.applied_crosswalk_binding ?? null),
  );
  ok(
    "DECISION: compatibility, risk class and declared loss are carried VERBATIM from the applied crosswalk rather than re-asserted by the decider",
    decRecord.compatibility_result === xwRecord.compatibility_result &&
      decRecord.mapping_risk_acceptance?.accepted_risk_class ===
        xwRecord.mapping_risk?.risk_class &&
      decRecord.mapping_risk_acceptance?.accepted_loss === xwRecord.mapping_risk?.declared_loss,
    JSON.stringify(decRecord.mapping_risk_acceptance ?? null),
  );
  ok(
    "DECISION: the crosswalk's standing AS OF THIS DECISION is sealed inside the content commitment, so 'we applied a mapping nobody had challenged' is checkable later",
    decRecord.applied_crosswalk_binding?.challenge_standing === "unchallenged" &&
      decRecord.content_hash === recomputeCommitment(decRecord, DEC_RULE),
    decRecord.applied_crosswalk_binding?.challenge_standing ?? "",
  );
  ok(
    "DECISION: the canonical decision receipt IS the admitting batch's own Agentgres receipt, not a second receipt minted beside it",
    decRecord.mapping_decision_receipt_ref === decRecord.admission?.agentgres_receipt_ref &&
      decRecord.mapping_decision_receipt_ref?.startsWith("receipt://"),
    decRecord.mapping_decision_receipt_ref ?? "",
  );
  ok(
    "DECISION: reviewer lineage is retained with each reviewer's own decision, and the record asserts neither correctness nor legal conformity",
    decRecord.reviewer_lineage?.length === 2 &&
      decRecord.reviewer_lineage[1].review_decision === "approved_with_conditions" &&
      decRecord.legal_conformity_claim === "not_determined" &&
      decRecord.correctness_nonclaim === "semantic_mapping_decision_is_not_a_correctness_claim",
    JSON.stringify(decRecord.reviewer_lineage ?? null),
  );

  const decQuery = `namespace=${NS}&name=intake-v1-to-v2`;
  let decBefore = await chainState(DEC, decQuery);
  const undisposed = await req(
    "POST",
    DEC,
    decisionBody({
      idempotency_key: "m052-decision-undisposed",
      name: "intake-ambiguous-application",
      applied_crosswalk_ref: ambiguousRecord.ontology_mapping_id,
      ambiguity_dispositions: [],
      unmapped_term_dispositions: [],
    }),
  );
  ok(
    "DECISION REFUSES: an ambiguity the APPLIED crosswalk named and this decision disposes of in no way — a fact about another chain that no byte-level fixture can decide",
    undisposed.status >= 400 &&
      code(undisposed.j) === "semantic_mapping_decision_ambiguity_undisposed",
    `status ${undisposed.status} code ${code(undisposed.j)}`,
  );

  const unnamed = await req(
    "POST",
    DEC,
    decisionBody({
      idempotency_key: "m052-decision-unnamed-ambiguity",
      name: "intake-unnamed-ambiguity",
      ambiguity_dispositions: [
        {
          source_term_id: term(NS, NAME, "triage-level"),
          disposition: "adjudicated_exact",
          adjudicated_by_ref: `user://${NS}/informatics-lead`,
        },
      ],
    }),
  );
  ok(
    "DECISION REFUSES: adjudicating a term the applied map never called ambiguous decides something the map never asked",
    unnamed.status >= 400 &&
      code(unnamed.j) === "semantic_mapping_decision_disposes_of_an_unnamed_ambiguity",
    `status ${unnamed.status} code ${code(unnamed.j)}`,
  );

  const refusedAmbiguity = await req(
    "POST",
    DEC,
    decisionBody({
      idempotency_key: "m052-decision-refused-ambiguity",
      name: "intake-ambiguous-application",
      applied_crosswalk_ref: ambiguousRecord.ontology_mapping_id,
      ambiguity_dispositions: [
        {
          source_term_id: term(NS, NAME, "triage-level"),
          disposition: "refused_ambiguous",
          adjudicated_by_ref: `user://${NS}/informatics-lead`,
        },
      ],
      unmapped_term_dispositions: [],
    }),
  );
  ok(
    "DECISION: 'refused_ambiguous' is a REAL disposition — the ambiguity is adjudicated by keeping the term out of the application rather than by guessing it",
    refusedAmbiguity.status === 201 &&
      refusedAmbiguity.j?.semantic_mapping_decision?.ambiguity_dispositions?.[0]?.disposition ===
        "refused_ambiguous",
    `status ${refusedAmbiguity.status}`,
  );

  const twiceReviewed = await req(
    "POST",
    DEC,
    decisionBody({
      idempotency_key: "m052-decision-twice-reviewed",
      expected_head: decBefore.head,
      compatibility: "additive",
      reviewer_lineage: [
        {
          reviewer_ref: `user://${NS}/informatics-lead`,
          review_role: "mapping_owner",
          reviewed_at: "2026-08-30T10:30:00Z",
          review_decision: "approved",
        },
        {
          reviewer_ref: `user://${NS}/informatics-lead`,
          review_role: "mapping_owner",
          reviewed_at: "2026-08-30T10:50:00Z",
          review_decision: "approved",
        },
      ],
    }),
  );
  await refusesWithoutEffect(
    "DECISION REFUSES: one reviewer standing in for a quorum of itself in one role",
    twiceReviewed,
    "semantic_mapping_decision_reviewer_counted_twice",
    DEC,
    decQuery,
  );

  const substitutedDecider = await req(
    "POST",
    DEC,
    decisionBody({
      idempotency_key: "m052-decision-substituted-decider",
      expected_head: decBefore.head,
      compatibility: "additive",
      expected_decided_by_ref: `user://${NS}/somebody-else`,
    }),
  );
  await refusesWithoutEffect(
    "DECISION REFUSES: the decider is the authenticated owner and is never accepted from the body (INV-37)",
    substitutedDecider,
    "semantic_mapping_decision_decider_substituted",
    DEC,
    decQuery,
  );
  return {
    xwRecord,
    decRecord,
    xwQuery,
    decQuery,
    ambiguousMappingRef: ambiguousRecord.ontology_mapping_id,
  };
}

// ------------------------------------------- a challenge changes standing without moving the bytes
async function runChallenges(ctx) {
  const { xwRecord, xwQuery, ambiguousMappingRef } = ctx;
  const CHALLENGE = `verifier-challenge://${NS}/triage-band-is-not-narrower`;
  const v1Envelope = await req("POST", XWC, {
    owner_ref: "org://local",
    idempotency_key: "m052-challenge-v1-envelope",
    challenged_ref: XW_R1,
    verifier_challenge_id: CHALLENGE,
    challenger_ref: `user://${NS}/intake-clinician`,
    challenge_kind: "mapping",
    adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
    challenge_contract_ref: "schema://ioi/foundations/objects/verifier-challenge-envelope/v1",
  });
  ok(
    "CHALLENGE REFUSES: a v1 envelope is refused BY NAME rather than downgraded into — its challenged_ref pattern cannot address a semantic-plane subject at all",
    v1Envelope.status >= 400 &&
      code(v1Envelope.j) === "ontology_mapping_challenge_contract_unsupported",
    `status ${v1Envelope.status} code ${code(v1Envelope.j)}`,
  );

  const orphan = await req("POST", XWC, {
    owner_ref: "org://local",
    idempotency_key: "m052-challenge-orphan",
    challenged_ref: `ontology-mapping://${NS}/intake-v1-to-v2/crosswalk/revision/9`,
    verifier_challenge_id: `verifier-challenge://${NS}/orphan`,
    challenger_ref: `user://${NS}/intake-clinician`,
    challenge_kind: "mapping",
    adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
  });
  ok(
    "CHALLENGE REFUSES: a challenge against a revision this family never admitted would leave a permanently dangling standing nobody can resolve",
    orphan.status === 404 &&
      code(orphan.j) === "ontology_mapping_challenged_revision_absent",
    `status ${orphan.status} code ${code(orphan.j)}`,
  );

  const prematureResolve = await req("POST", XWC, {
    owner_ref: "org://local",
    idempotency_key: "m052-challenge-premature-resolve",
    challenged_ref: XW_R1,
    verifier_challenge_id: CHALLENGE,
    challenger_ref: `user://${NS}/intake-clinician`,
    challenge_kind: "mapping",
    adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
    resolution: "upheld",
    resolution_receipt_ref: `receipt://${NS}/fabricated`,
  });
  ok(
    "CHALLENGE REFUSES: resolving a challenge that was never admitted would change a standing nobody contested",
    prematureResolve.status >= 400 &&
      code(prematureResolve.j) === "ontology_mapping_challenge_not_open",
    `status ${prematureResolve.status} code ${code(prematureResolve.j)}`,
  );

  const opened = await req("POST", XWC, {
    owner_ref: "org://local",
    idempotency_key: "m052-challenge-open",
    challenged_ref: XW_R1,
    verifier_challenge_id: CHALLENGE,
    challenger_ref: `user://${NS}/intake-clinician`,
    challenge_kind: "mapping",
    adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
    challenge_evidence_refs: [`evidence://${NS}/band-round-trip-fails`],
  });
  const challenged = opened.j?.ontology_crosswalk ?? {};
  ok(
    "CHALLENGE: an admitted challenge moves the mapping's STANDING to challenged and its status with it",
    opened.status === 201 &&
      challenged.challenge_state?.standing === "challenged" &&
      challenged.challenge_state.open_challenge_refs.includes(CHALLENGE) &&
      challenged.status === "challenged",
    `${opened.status} ${challenged.status}`,
  );
  ok(
    "CHALLENGE: the challenged revision's CONTENT HASH did not move — standing is a fact about the chain and lives outside the content commitment. This is the two-reads-across-a-durable-write claim no fixture can make.",
    challenged.content_hash === xwRecord.content_hash &&
      challenged.content_hash === recomputeCommitment(challenged, XW_RULE),
    `${xwRecord.content_hash} -> ${challenged.content_hash}`,
  );
  ok(
    "CHALLENGE: admitting a challenge is not an adjudication, and the response says so",
    opened.j?.verdict_nonclaim === "ontology_mapping_challenge_admission_is_not_an_adjudication",
    opened.j?.verdict_nonclaim ?? "",
  );

  const duplicate = await req("POST", XWC, {
    owner_ref: "org://local",
    idempotency_key: "m052-challenge-duplicate",
    challenged_ref: XW_R1,
    verifier_challenge_id: CHALLENGE,
    challenger_ref: `user://${NS}/intake-clinician`,
    challenge_kind: "mapping",
    adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
  });
  ok(
    "CHALLENGE REFUSES: the same challenge admitted twice against one revision",
    duplicate.status >= 400 &&
      code(duplicate.j) === "ontology_mapping_challenge_already_admitted",
    `status ${duplicate.status} code ${code(duplicate.j)}`,
  );

  const appliedUnderChallenge = await req("POST", DEC, {
    owner_ref: "org://local",
    idempotency_key: "m052-decision-under-challenge",
    namespace: NS,
    name: "intake-under-challenge",
    governing_scope_ref: `domain://${NS}/clinical`,
    policy_hash: sha256("decision-policy"),
    applied_crosswalk_ref: XW_R1,
    application_target_refs: [`handoff://${NS}/disputed`],
    accepted_by_ref: `user://${NS}/informatics-lead`,
    reviewer_lineage: [
      {
        reviewer_ref: `user://${NS}/informatics-lead`,
        review_role: "mapping_owner",
        reviewed_at: "2026-08-30T12:00:00Z",
        review_decision: "approved",
      },
    ],
    unmapped_term_dispositions: [
      { source_term_id: term(NS, NAME, "legacy-note"), disposition: "escalated" },
    ],
    valid_time: { starts_at: "2026-08-30T12:00:00Z", ends_at: null },
  });
  ok(
    "DECISION: applying a mapping that is UNDER CHALLENGE is recorded, and cannot project active — the standing it sealed is the standing it lives with",
    appliedUnderChallenge.status === 201 &&
      appliedUnderChallenge.j?.semantic_mapping_decision?.applied_crosswalk_binding
        ?.challenge_standing === "challenged" &&
      appliedUnderChallenge.j?.semantic_mapping_decision?.status === "validated",
    `${appliedUnderChallenge.status} ${appliedUnderChallenge.j?.semantic_mapping_decision?.status}`,
  );

  // ------------------------------------------- the receipt is a record, or the resolution refuses
  //
  // The gate no longer hands this route a `receipt://`-shaped string it invented. It climbs the REAL
  // canonical ladder over this exact crosswalk revision — attested, evidenced, verified, accepted,
  // adjudicated — through M06's own route, and resolves with the adjudication receipt that produced.
  const ladder = await climbLadderToAdjudication(
    XW_R1,
    CHALLENGE,
    "rejected",
    "m052-xwalk",
    "no_fault",
  );
  ok(
    "M06 LADDER: the challenged crosswalk revision really climbs attested -> evidenced -> verified -> accepted -> adjudicated through M06's own route, and the adjudication binds this exact challenge",
    ladder.response?.status === 201 &&
      ladder.record?.to_stage === "adjudicated" &&
      ladder.record?.challenge_resolution?.verifier_challenge_id === CHALLENGE &&
      ladder.record?.challenge_resolution?.resolution === "rejected" &&
      ladder.receipt?.startsWith("receipt://"),
    `status ${ladder.response?.status} stage ${ladder.record?.to_stage}`,
  );
  ok(
    "M06 LADDER: the receipt binds the SUBJECT and the exact bytes the mapping owner resolved, filled in from the owner-resolved subject rather than from the request",
    ladder.record?.challenge_resolution?.challenged_subject_ref === XW_R1 &&
      ladder.record?.challenge_resolution?.challenged_subject_content_hash ===
        ladder.record?.subject_content_hash &&
      ladder.record?.subject_resolved_by ===
        "semantic_mapping_routes::resolve_admitted_mapping_revision",
    `${ladder.record?.challenge_resolution?.challenged_subject_ref}`,
  );
  ok(
    "M06 SUCCESSION: the adjudication is admitted under the v2 successor and names v1 as its predecessor contract, so the succession is auditable from the receipt's own bytes",
    ladder.record?.schema_version === "ioi.assurance-transition-receipt.v2" &&
      ladder.record?.receipt_profile_ref ===
        "schema://ioi/foundations/assurance-transition-receipt/v2" &&
      ladder.record?.predecessor_contract_ref ===
        "schema://ioi/foundations/assurance-transition-receipt/v1",
    ladder.record?.schema_version ?? "",
  );

  const resolveWith = (key, overrides) =>
    req("POST", XWC, {
      owner_ref: "org://local",
      idempotency_key: key,
      challenged_ref: XW_R1,
      verifier_challenge_id: CHALLENGE,
      challenger_ref: `user://${NS}/intake-clinician`,
      challenge_kind: "mapping",
      adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
      resolution: "rejected",
      resolution_receipt_ref: ladder.receipt,
      ...overrides,
    });

  const forged = await resolveWith("m052-resolve-forged", {
    resolution_receipt_ref: `receipt://${NS}/assurance/batch/7`,
  });
  ok(
    "RESOLUTION REFUSES: a receipt-SHAPED string this daemon never admitted resolves nothing — the defect this seam exists to close, and the exact shape the gate itself used to hand in",
    forged.status === 404 && code(forged.j) === "assurance_transition_receipt_absent",
    `status ${forged.status} code ${code(forged.j)}`,
  );

  const wrongChallenge = await resolveWith("m052-resolve-wrong-challenge", {
    verifier_challenge_id: `verifier-challenge://${NS}/some-other-dispute`,
  });
  ok(
    "RESOLUTION REFUSES: a REAL admitted receipt that resolves a DIFFERENT challenge — the binding v1 structurally could not carry, and the reason the v2 successor exists",
    wrongChallenge.status >= 400 &&
      ["assurance_transition_receipt_challenge_mismatch", "ontology_mapping_challenge_not_open"].includes(
        code(wrongChallenge.j),
      ),
    `status ${wrongChallenge.status} code ${code(wrongChallenge.j)}`,
  );

  const wrongOutcome = await resolveWith("m052-resolve-wrong-outcome", { resolution: "upheld" });
  ok(
    "RESOLUTION REFUSES: the request cannot claim an outcome the LADDER did not record — the receipt is the evidence, not the request",
    wrongOutcome.status >= 400 &&
      code(wrongOutcome.j) === "ontology_mapping_resolution_disagrees_with_its_receipt",
    `status ${wrongOutcome.status} code ${code(wrongOutcome.j)}`,
  );

  const foreignResolve = await req(
    "POST",
    XWC,
    {
      owner_ref: "org://local",
      idempotency_key: "m052-resolve-cross-tenant",
      challenged_ref: XW_R1,
      verifier_challenge_id: CHALLENGE,
      challenger_ref: `user://${NS}/intake-clinician`,
      challenge_kind: "mapping",
      adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
      resolution: "rejected",
      resolution_receipt_ref: ladder.receipt,
    },
    { as: "B" },
  );
  ok(
    "RESOLUTION REFUSES: a principal outside this tenant cannot resolve with a receipt it cannot reach — the refusal is the owner scope's, so the route is no existence oracle for another tenant's receipts",
    foreignResolve.status >= 400 && foreignResolve.status !== 201,
    `status ${foreignResolve.status} code ${code(foreignResolve.j)}`,
  );

  const ordinaryStep = await resolveWith("m052-resolve-ordinary-step", {
    resolution_receipt_ref: ladder.ordinaryReceipt,
  });
  ok(
    "RESOLUTION REFUSES: a REAL admitted receipt from an ORDINARY rung of this subject's own ladder adjudicates no challenge — existing is not the same as resolving",
    ordinaryStep.status >= 400 &&
      code(ordinaryStep.j) === "assurance_transition_receipt_resolves_no_challenge",
    `status ${ordinaryStep.status} code ${code(ordinaryStep.j)}`,
  );

  // ------------------------------------------------- the M06 ADMISSION fences, probed at their route
  //
  // Everything above tests the CONSUMPTION seam. These test the fences that stop a defective
  // resolution reaching the ladder at all, and every one of them is a refusal, so they share one
  // subject parked at `accepted` and leave it there.
  const parked = ambiguousMappingRef;
  const park = await climbLadderToAccepted(parked, "m052-parked");
  const adjudicate = (key, overrides, resolutionOverrides) =>
    req("POST", AT, {
      owner_ref: "org://local",
      idempotency_key: key,
      subject_ref: parked,
      outcome_class: "disputed",
      evidence_refs: [`evidence://${NS}/${key}`],
      does_not_assert: ["correctness", "settlement", "authority"],
      valid_time: { starts_at: "2026-09-01T00:00:00Z", ends_at: null },
      expected_head: park.head,
      challenge_resolution: {
        verifier_challenge_id: `verifier-challenge://${NS}/parked-dispute`,
        resolution: "upheld",
        adjudicator_ref: "org://local",
        adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
        reviewer_lineage: [
          {
            reviewer_ref: `user://${NS}/informatics-lead`,
            reviewed_at: "2026-09-05T10:00:00Z",
            review_decision: "upheld",
          },
        ],
        ...resolutionOverrides,
      },
      ...overrides,
    });
  ok(
    "M06 PRECONDITION: one subject really is parked at 'accepted', so each fence below is tested on its own terms rather than by the no-skip rule refusing everything",
    park.head !== null,
    park.failedAt ? `failed at ${park.failedAt}` : "accepted",
  );

  const hashSubstituted = await adjudicate("m052-fence-hash", {}, {
    challenged_subject_content_hash: sha256("some-other-revisions-bytes"),
  });
  ok(
    "M06 ADMISSION REFUSES: a resolution asserting a subject content hash the subject owner did not resolve — the receipt cannot be re-pointed at another revision's bytes",
    hashSubstituted.status >= 400 &&
      code(hashSubstituted.j) === "assurance_transition_resolution_subject_hash_substituted",
    `status ${hashSubstituted.status} code ${code(hashSubstituted.j)}`,
  );

  const subjectSubstituted = await adjudicate("m052-fence-subject", {}, {
    challenged_subject_ref: XW_R1,
  });
  ok(
    "M06 ADMISSION REFUSES: a resolution naming a subject other than the one this transition is about",
    subjectSubstituted.status >= 400 &&
      code(subjectSubstituted.j) === "assurance_transition_resolution_subject_substituted",
    `status ${subjectSubstituted.status} code ${code(subjectSubstituted.j)}`,
  );

  const cleanPass = await adjudicate("m052-fence-outcome", { outcome_class: "positive" }, {});
  ok(
    "M06 ADMISSION REFUSES: an UPHELD challenge recorded as a positive outcome — a sustained finding cannot be filed as a clean pass",
    cleanPass.status >= 400 &&
      code(cleanPass.j) === "assurance_transition_resolution_outcome_disagreement",
    `status ${cleanPass.status} code ${code(cleanPass.j)}`,
  );

  const noReviewer = await adjudicate("m052-fence-reviewer", {}, { reviewer_lineage: [] });
  ok(
    "M06 ADMISSION REFUSES: an adjudication with no reviewer at all is a verdict nobody stands behind",
    noReviewer.status >= 400 &&
      code(noReviewer.j) === "assurance_transition_resolution_reviewer_required",
    `status ${noReviewer.status} code ${code(noReviewer.j)}`,
  );

  const twiceReviewedResolution = await adjudicate("m052-fence-twice", {}, {
    reviewer_lineage: [
      {
        reviewer_ref: `user://${NS}/informatics-lead`,
        reviewed_at: "2026-09-05T10:00:00Z",
        review_decision: "upheld",
      },
      {
        reviewer_ref: `user://${NS}/informatics-lead`,
        reviewed_at: "2026-09-05T11:00:00Z",
        review_decision: "abstained",
      },
    ],
  });
  ok(
    "M06 ADMISSION REFUSES: one reviewer standing in for a quorum of itself in an adjudication",
    twiceReviewedResolution.status >= 400 &&
      code(twiceReviewedResolution.j) ===
        "assurance_transition_resolution_reviewer_counted_twice",
    `status ${twiceReviewedResolution.status} code ${code(twiceReviewedResolution.j)}`,
  );

  const badPolicy = await adjudicate("m052-fence-policy", {}, {
    adjudicator_policy_ref: `receipt://${NS}/not-a-policy`,
  });
  ok(
    "M06 ADMISSION REFUSES: an adjudicator policy that is not a policy ref",
    badPolicy.status >= 400 &&
      code(badPolicy.j) === "assurance_transition_adjudicator_policy_not_canonical",
    `status ${badPolicy.status} code ${code(badPolicy.j)}`,
  );

  const badAdjudicator = await adjudicate("m052-fence-adjudicator", {}, {
    adjudicator_ref: "not-a-principal",
  });
  ok(
    "M06 ADMISSION REFUSES: an adjudicator that is not a canonical principal",
    badAdjudicator.status >= 400 &&
      code(badAdjudicator.j) === "assurance_transition_adjudicator_not_canonical",
    `status ${badAdjudicator.status} code ${code(badAdjudicator.j)}`,
  );

  const v1Envelope2 = await adjudicate("m052-fence-envelope", {}, {
    challenge_contract_ref: "schema://ioi/foundations/objects/verifier-challenge-envelope/v1",
  });
  ok(
    "M06 ADMISSION REFUSES: a resolution citing the v1 challenge envelope, which cannot address a semantic-plane subject at all",
    v1Envelope2.status >= 400 &&
      code(v1Envelope2.j) === "assurance_transition_challenge_contract_unsupported",
    `status ${v1Envelope2.status} code ${code(v1Envelope2.j)}`,
  );

  const wrongRung = await req("POST", AT, {
    owner_ref: "org://local",
    idempotency_key: "m052-fence-rung",
    subject_ref: XW_R1,
    outcome_class: "disputed",
    evidence_refs: [`evidence://${NS}/m052-fence-rung`],
    does_not_assert: ["correctness", "settlement", "authority"],
    valid_time: { starts_at: "2026-09-01T00:00:00Z", ends_at: null },
    challenge_resolution: {
      verifier_challenge_id: CHALLENGE,
      resolution: "upheld",
      adjudicator_ref: "org://local",
      adjudicator_policy_ref: `policy://${NS}/mapping-adjudication`,
      reviewer_lineage: [
        {
          reviewer_ref: `user://${NS}/informatics-lead`,
          reviewed_at: "2026-09-05T10:00:00Z",
          review_decision: "upheld",
        },
      ],
    },
  });
  ok(
    "M06 ADMISSION REFUSES: a challenge resolution claimed at a rung that is not adjudication — 'resolved' is not claimable anywhere on the ladder",
    wrongRung.status >= 400 &&
      ["assurance_transition_challenge_resolution_outside_adjudication",
       "assurance_transition_expected_head_conflict"].includes(code(wrongRung.j)),
    `status ${wrongRung.status} code ${code(wrongRung.j)}`,
  );

  const parkedAfter = await req("GET", `${AT}?subject_ref=${encodeURIComponent(parked)}`);
  ok(
    "M06 ADMISSION REFUSES BY EFFECT: every fence above left the parked subject exactly at 'accepted' — nine refusals appended nothing",
    parkedAfter.j?.transition_count === 4 || parkedAfter.j?.ladder_transition_count === 4,
    JSON.stringify({
      count: parkedAfter.j?.transition_count ?? parkedAfter.j?.ladder_transition_count,
    }),
  );

  const resolved = await resolveWith("m052-challenge-resolve", {});
  const settled = resolved.j?.ontology_crosswalk ?? {};
  ok(
    "CHALLENGE: a REJECTED challenge is RETAINED beside the mapping it failed to unseat — the resolved set and its receipt stay addressable, and the mapping returns to standing",
    resolved.status === 201 &&
      settled.challenge_state?.standing === "rejected" &&
      settled.challenge_state.resolved_challenge_refs.includes(CHALLENGE) &&
      settled.challenge_state.resolution_receipt_refs.length === 1 &&
      settled.status === "active",
    JSON.stringify(settled.challenge_state ?? null),
  );
  ok(
    "CHALLENGE: resolution left the content hash where it was, across TWO durable writes",
    settled.content_hash === xwRecord.content_hash,
    `${settled.content_hash}`,
  );
  return { xwQuery };
}

// ------------------------------------------------------- INV-30: cross-domain application refuses
async function runCrossDomain() {
  const crossWalk = await req("POST", XW, {
    owner_ref: "org://local",
    idempotency_key: "m052-crosswalk-cross-domain",
    namespace: NS,
    name: "acme-to-harbor",
    governing_scope_ref: `domain://${NS}/clinical`,
    policy_hash: sha256("cross-domain-policy"),
    source_ontology_version_ref: BASE_R1,
    target_ontology_version_ref: FOREIGN_R1,
    term_mappings: [
      {
        source_term_id: term(NS, NAME, "triage-level"),
        target_term_id: term(FOREIGN_NS, "intake", "severity"),
        relation: "broader",
        loss: "lossy_scope",
      },
    ],
    compatibility_result: "requires_adapter",
    risk_class: "high",
    declared_loss: "lossy_scope",
    valid_time: { starts_at: "2026-07-01T00:00:00Z", ends_at: null },
  });
  const crossRecord = crossWalk.j?.ontology_crosswalk ?? {};
  ok(
    "CROSS-DOMAIN: a cross-domain crosswalk may be DECLARED — declaring a map is how domains negotiate at all, and the record says declaration is not application",
    crossWalk.status === 201 &&
      crossRecord.domain_relationship === "cross_domain" &&
      crossRecord.cross_domain_application_nonclaim ===
        "ontology_crosswalk_declaration_is_not_cross_domain_application",
    `${crossWalk.status} ${crossRecord.domain_relationship}`,
  );
  ok(
    "CROSS-DOMAIN: it can never project ACTIVE, because activation is application and application waits on accepted terms (INV-30)",
    crossRecord.status === "validated",
    crossRecord.status ?? "",
  );

  const crossApply = await req("POST", DEC, {
    owner_ref: "org://local",
    idempotency_key: "m052-decision-cross-domain",
    namespace: NS,
    name: "acme-to-harbor",
    governing_scope_ref: `domain://${NS}/clinical`,
    policy_hash: sha256("decision-policy"),
    applied_crosswalk_ref: crossRecord.ontology_mapping_id,
    application_target_refs: [`handoff://${NS}/harbor-referral`],
    accepted_by_ref: `user://${NS}/informatics-lead`,
    reviewer_lineage: [
      {
        reviewer_ref: `user://${NS}/informatics-lead`,
        review_role: "mapping_owner",
        reviewed_at: "2026-08-30T13:00:00Z",
        review_decision: "approved",
      },
    ],
    valid_time: { starts_at: "2026-08-30T13:00:00Z", ends_at: null },
  });
  ok(
    "CROSS-DOMAIN REFUSES BY NAME: application across a boundary is 501 with the exact unit that owns the terms-acceptance resolver named, never admitted on a caller-supplied acceptance",
    crossApply.status === 501 &&
      code(crossApply.j) === "semantic_mapping_terms_acceptance_unresolvable" &&
      /M11\.1/u.test(crossApply.j?.error?.message ?? ""),
    `status ${crossApply.status} code ${code(crossApply.j)}`,
  );
  const decisionFamilies = await req("GET", DEC);
  ok(
    "CROSS-DOMAIN REFUSES BY EFFECT: the refused application minted no decision family at all",
    !JSON.stringify(decisionFamilies.j?.families ?? []).includes("acme-to-harbor"),
    JSON.stringify(decisionFamilies.j?.families ?? []),
  );
}

// -------------------------------------------- bitemporal reads, cross-owner refusal, restart, replay
async function runDurability(ctx) {
  const { xwQuery } = ctx;
  const beforeRestart = await chainState(XW, xwQuery);
  const bitemporal = await req(
    "GET",
    `${XW}?${xwQuery}&as_of_transaction_time=2020-01-01T00:00:00Z`,
  );
  ok(
    "BITEMPORAL: transaction-time travel to before this family existed returns an EMPTY lineage rather than the current head — 'as the record stood then' is a real axis",
    bitemporal.status === 200 && bitemporal.j?.revision_count === 0,
    `count ${bitemporal.j?.revision_count}`,
  );
  const validTime = await req(
    "GET",
    `${XW}?${xwQuery}&as_of_valid_time=2020-01-01T00:00:00Z`,
  );
  ok(
    "BITEMPORAL: valid-time travel narrows INDEPENDENTLY of transaction time — the record was recorded, and was not yet held true",
    validTime.status === 200 &&
      validTime.j?.revision_count === 0 &&
      validTime.j?.lineage_revision_count === beforeRestart.count,
    `valid ${validTime.j?.revision_count} lineage ${validTime.j?.lineage_revision_count}`,
  );

  const foreignRead = await req("GET", `${XW}?${xwQuery}`, undefined, { as: "B" });
  ok(
    "ACCESS: a principal with no scope on this family cannot read its lineage, and receives the same refusal an absent family would give — no existence oracle",
    foreignRead.status >= 400 && foreignRead.status !== 200,
    `status ${foreignRead.status} code ${code(foreignRead.j)}`,
  );
  const foreignWrite = await req(
    "POST",
    XW,
    {
      owner_ref: "org://local",
      idempotency_key: "m052-crosswalk-foreign-owner",
      namespace: NS,
      name: "intake-v1-to-v2",
      governing_scope_ref: `domain://${NS}/clinical`,
      policy_hash: sha256("crosswalk-policy"),
      source_ontology_version_ref: BASE_R1,
      target_ontology_version_ref: BASE_R2,
      term_mappings: [
        {
          source_term_id: term(NS, NAME, "triage-level"),
          target_term_id: term(NS, NAME, "acuity-band"),
          relation: "exact",
          loss: "none",
        },
      ],
      compatibility_result: "exact",
      risk_class: "low",
      declared_loss: "none",
      valid_time: { starts_at: "2026-07-01T00:00:00Z", ends_at: null },
    },
    { as: "B" },
  );
  const afterForeign = await chainState(XW, xwQuery);
  ok(
    "ACCESS BY EFFECT: a cross-owner write is refused AND left the head and revision count exactly where they were",
    foreignWrite.status >= 400 &&
      afterForeign.head === beforeRestart.head &&
      afterForeign.count === beforeRestart.count,
    `status ${foreignWrite.status} ${afterForeign.head}/${afterForeign.count}`,
  );

  // ------------------------------------------------------------------- restart and index rebuild
  await stopDaemon();
  await startDaemon();
  const bootAfter = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    {
      token: daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null,
      password: "semantic-mapping-a-v1",
    },
    { as: null },
  );
  if (bootAfter.j?.session_token) SESSIONS.A = bootAfter.j.session_token;
  const relogin = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "semantic-mapping-b@ioi.local", password: "semantic-mapping-b-v1" },
    { as: null },
  );
  SESSIONS.B = relogin.j?.session_token ?? SESSIONS.B;

  const afterRestart = await chainState(XW, xwQuery);
  ok(
    "RESTART: the head and revision count survive a full daemon restart — durable truth is the chain, not the process",
    afterRestart.head === beforeRestart.head && afterRestart.count === beforeRestart.count,
    `${beforeRestart.head}/${beforeRestart.count} -> ${afterRestart.head}/${afterRestart.count}`,
  );
  ok(
    "INDEX REBUILD, POSITIVELY DETECTED: the first read after restart reports the process-local cache as REBUILT rather than agreed, so an unchanged answer is not mistaken for a cache that was never dropped",
    afterRestart.j?.projection_index_state === "rebuilt_from_agentgres" &&
      afterRestart.j?.projection_source === "agentgres_owner_scoped_chain",
    afterRestart.j?.projection_index_state ?? "",
  );
  const secondRead = await chainState(XW, xwQuery);
  ok(
    "INDEX IS NEVER AN ANSWER SOURCE: the second read reports agreement, and returns the same answer the rebuilt read did",
    secondRead.j?.projection_index_state === "agreed_with_agentgres" &&
      secondRead.head === afterRestart.head,
    secondRead.j?.projection_index_state ?? "",
  );
  const challengeSurvived = await req("GET", `${XW}?${xwQuery}&revision=1`);
  const survivor = challengeSurvived.j?.records?.[0] ?? {};
  ok(
    "RESTART: the folded challenge standing and its retained resolution survive too — a resolved challenge is not a process-local memory",
    survivor.challenge_state?.standing === "rejected" &&
      survivor.challenge_state.resolved_challenge_refs.length === 1 &&
      survivor.content_hash === recomputeCommitment(survivor, XW_RULE),
    JSON.stringify(survivor.challenge_state ?? null),
  );

  // ------------------------------------------------------------------------------ idempotent replay
  const replay = await req("POST", XW, {
    owner_ref: "org://local",
    idempotency_key: "m052-crosswalk-1",
    namespace: NS,
    name: "intake-v1-to-v2",
    governing_scope_ref: `domain://${NS}/clinical`,
    policy_hash: sha256("crosswalk-policy"),
    source_ontology_version_ref: BASE_R1,
    target_ontology_version_ref: BASE_R2,
    term_mappings: [
      {
        source_term_id: term(NS, NAME, "triage-level"),
        target_term_id: term(NS, NAME, "acuity-band"),
        relation: "narrower",
        loss: "lossy_precision",
      },
      {
        source_term_id: term(NS, NAME, "legacy-note"),
        target_term_id: null,
        relation: "unmapped",
        loss: "unmapped",
      },
    ],
    compatibility_result: "lossy",
    risk_class: "moderate",
    declared_loss: "lossy_precision",
    residual_risk_refs: [`policy://${NS}/unmapped-legacy-note-is-escalated`],
    valid_time: { starts_at: "2026-07-01T00:00:00Z", ends_at: null },
  });
  const afterReplay = await chainState(XW, xwQuery);
  ok(
    "REPLAY: the same idempotency key across a RESTART replays the original admitted revision and appends nothing",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.ontology_crosswalk?.ontology_mapping_id === XW_R1 &&
      afterReplay.count === afterRestart.count,
    `status ${replay.status} replayed ${replay.j?.replayed} count ${afterReplay.count}`,
  );
}

// ----------------------------------------------------------------------- authority-plane nonclaims
function runSourceClaims() {
  const source = fs.readFileSync(ROUTE_SOURCE, "utf8");
  ok(
    "NO AUTHORITY PLANE: the module consults, mints, widens and redeems no capability, lease, grant, approval or effect admission",
    !/CapabilityLease|capability_lease|mint_grant|authority_grant|approval_ceremony|effect_admission|redeem/u.test(
      source,
    ),
    "source-text absence over the module that owns the three families",
  );
  ok(
    "OWNER SEAMS, NOT SECOND READERS: every endpoint, crosswalk and term is resolved through a published owner reader, and this module opens no storage reader of its own",
    /resolve_admitted_revision/u.test(source) &&
      !/read_record|write_record|remove_record|fs::(?:read|write)/u.test(source),
    "source-text absence of a second store",
  );
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const registered = registry.contracts.filter((entry) =>
    [
      "schema://ioi/foundations/ontology-overlay/v1",
      "schema://ioi/foundations/ontology-crosswalk/v1",
      "schema://ioi/foundations/semantic-mapping-decision/v1",
    ].includes(entry.contract_id),
  );
  ok(
    "REGISTERED: all three families are registered contracts with generated projections and a cross-field invariant profile each",
    registered.length === 3 &&
      registered.every(
        (entry) =>
          entry.cross_field_invariant_refs.length === 1 &&
          entry.generated_targets.length === 2 &&
          entry.positive_fixture_refs.length > 0 &&
          entry.negative_fixture_refs.length > 0,
      ),
    `${registered.length} registered`,
  );
}

// -------------------------------------------------------------------------------- planted mutations

/// Each mutant names the EXACT assertion it must redden. A mutant that reddens something else, or
/// nothing, is a failure of the battery — an off-target kill proves the harness, not the gate.
const MUTANTS = [
  {
    id: "any-receipt-shaped-string-resolves",
    file: RECEIPT_OWNER_SOURCE,
    // A GENUINE BYPASS, not a renamed error: when the exact receipt is absent, fall back to the
    // newest adjudication on this ladder. The forged request then reaches a real resolution path and
    // SUCCEEDS, which is the semantic failure this id names.
    find: '    let matched = ladder.iter().find(|entry| {\n        entry\n            .pointer("/admission/agentgres_receipt_ref")\n            .and_then(Value::as_str)\n            == Some(receipt_ref)\n    });',
    replace: '    let matched = ladder.iter().find(|entry| {\n        entry\n            .pointer("/admission/agentgres_receipt_ref")\n            .and_then(Value::as_str)\n            == Some(receipt_ref)\n    }).or_else(|| ladder.iter().rev().find(|entry| entry.get("to_stage").and_then(Value::as_str) == Some("adjudicated")));',
    target:
      "RESOLUTION REFUSES: a receipt-SHAPED string this daemon never admitted resolves nothing — the defect this seam exists to close, and the exact shape the gate itself used to hand in",
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
      "RESOLUTION REFUSES: a REAL admitted receipt that resolves a DIFFERENT challenge — the binding v1 structurally could not carry, and the reason the v2 successor exists",
  },
  {
    id: "the-request-may-outvote-its-receipt",
    file: ROUTE_SOURCE,
    find: "        if resolved.resolution != resolution {",
    replace: "        if false && resolved.resolution != resolution {",
    target:
      "RESOLUTION REFUSES: the request cannot claim an outcome the LADDER did not record — the receipt is the evidence, not the request",
  },
  {
    id: "the-resolution-subject-hash-is-taken-from-the-request",
    file: RECEIPT_OWNER_SOURCE,
    find: "            if asserted != subject.content_hash {",
    replace: "            if false && asserted != subject.content_hash {",
    target:
      "M06 ADMISSION REFUSES: a resolution asserting a subject content hash the subject owner did not resolve — the receipt cannot be re-pointed at another revision's bytes",
  },
  {
    id: "the-resolution-subject-is-taken-from-the-request",
    file: RECEIPT_OWNER_SOURCE,
    find: "            if asserted != proposal.subject_ref {",
    replace: "            if false && asserted != proposal.subject_ref {",
    target:
      "M06 ADMISSION REFUSES: a resolution naming a subject other than the one this transition is about",
  },
  {
    id: "an-upheld-challenge-may-be-a-clean-pass",
    file: RECEIPT_OWNER_SOURCE,
    find: "    if !permitted_outcomes.contains(&outcome_class) {",
    replace: "    if false && !permitted_outcomes.contains(&outcome_class) {",
    target:
      "M06 ADMISSION REFUSES: an UPHELD challenge recorded as a positive outcome — a sustained finding cannot be filed as a clean pass",
  },
  {
    id: "an-adjudication-needs-no-reviewer",
    file: RECEIPT_OWNER_SOURCE,
    find: "    if rows.is_empty() || rows.len() > MAX_REVIEWERS {",
    replace: "    if rows.len() > MAX_REVIEWERS {",
    target:
      "M06 ADMISSION REFUSES: an adjudication with no reviewer at all is a verdict nobody stands behind",
  },
  {
    id: "one-reviewer-may-be-a-quorum",
    file: RECEIPT_OWNER_SOURCE,
    find: "        if seen.iter().any(|previous| previous == &reviewer_ref) {",
    replace: "        if false && seen.iter().any(|previous| previous == &reviewer_ref) {",
    target:
      "M06 ADMISSION REFUSES: one reviewer standing in for a quorum of itself in an adjudication",
  },
  {
    id: "the-adjudicator-policy-need-not-be-a-policy",
    file: RECEIPT_OWNER_SOURCE,
    find: '    if !policy_ref.starts_with("policy://") || policy_ref.len() > 480 {',
    replace: "    if policy_ref.len() > 480 {",
    target: "M06 ADMISSION REFUSES: an adjudicator policy that is not a policy ref",
  },
  {
    id: "the-adjudicator-need-not-be-a-principal",
    file: RECEIPT_OWNER_SOURCE,
    find: "    if !PRINCIPAL_SCHEMES\n        .iter()\n        .any(|scheme| adjudicator_ref.starts_with(scheme))\n    {",
    replace: "    if false\n    {",
    target: "M06 ADMISSION REFUSES: an adjudicator that is not a canonical principal",
  },
  {
    id: "a-resolution-is-claimable-at-any-rung",
    file: RECEIPT_OWNER_SOURCE,
    find: "    if to_stage != ADJUDICATED_STAGE {",
    replace: "    if false && to_stage != ADJUDICATED_STAGE {",
    target:
      "M06 ADMISSION REFUSES: a challenge resolution claimed at a rung that is not adjudication — 'resolved' is not claimable anywhere on the ladder",
  },
  {
    id: "the-owner-emits-the-v1-predecessor-contract",
    file: RECEIPT_OWNER_SOURCE,
    find: 'const SCHEMA_VERSION: &str = "ioi.assurance-transition-receipt.v2";',
    replace: 'const SCHEMA_VERSION: &str = "ioi.assurance-transition-receipt.v1";',
    target:
      "M06 SUCCESSION: the adjudication is admitted under the v2 successor and names v1 as its predecessor contract, so the succession is auditable from the receipt's own bytes",
  },
  {
    id: "overlay-accepts-a-base-term",
    file: ROUTE_SOURCE,
    // The fence is a `let ... else` whose refusal names the fork; weakening the prefix it strips is
    // what lets a base-namespace term through, so the mutant edits the prefix rather than the arm.
    find: '    let prefix = format!("{overlay_family}/term/");',
    replace: '    let prefix = String::new();',
    target:
      "OVERLAY REFUSES: minting a term inside the BASE family's namespace is an edit of the base, which is a fork",
  },
  {
    id: "ambiguity-need-not-be-disposed-of",
    file: ROUTE_SOURCE,
    find: '    if let Some(missing) = required.difference(&disposed).next() {\n        return Err(refuse(\n            "semantic_mapping_decision_ambiguity_undisposed",',
    replace: '    if let Some(missing) = required.difference(&disposed).next().filter(|_| false) {\n        return Err(refuse(\n            "semantic_mapping_decision_ambiguity_undisposed",',
    target:
      "DECISION REFUSES: an ambiguity the APPLIED crosswalk named and this decision disposes of in no way — a fact about another chain that no byte-level fixture can decide",
  },
  {
    id: "cross-domain-application-is-admitted",
    file: ROUTE_SOURCE,
    find: '    if domain_relationship == "cross_domain" {\n        return bad(\n            StatusCode::NOT_IMPLEMENTED,',
    replace: '    if false && domain_relationship == "cross_domain" {\n        return bad(\n            StatusCode::NOT_IMPLEMENTED,',
    target:
      "CROSS-DOMAIN REFUSES BY NAME: application across a boundary is 501 with the exact unit that owns the terms-acceptance resolver named, never admitted on a caller-supplied acceptance",
  },
  {
    id: "domain-relationship-is-believed",
    file: ROUTE_SOURCE,
    find: '    let domain_relationship = if source.namespace == target.namespace {',
    replace: '    let domain_relationship = if true || source.namespace == target.namespace {',
    target:
      "CROSS-DOMAIN: a cross-domain crosswalk may be DECLARED — declaring a map is how domains negotiate at all, and the record says declaration is not application",
  },
  {
    id: "ambiguity-is-declared-not-derived",
    file: ROUTE_SOURCE,
    find: "        .filter(|(_, count)| *count > 1)",
    replace: "        .filter(|(_, count)| *count > 2)",
    target:
      "CROSSWALK: the ambiguity set is DERIVED from the rows — a source term with two targets IS ambiguous, so a caller cannot understate the set by omitting a name",
  },
  {
    id: "challenge-state-enters-the-content-commitment",
    file: ROUTE_SOURCE,
    find: '    "cross_domain_application_nonclaim",\n    "correctness_nonclaim",\n    "authority_nonclaim",\n    "global_canonicality_nonclaim",\n];',
    replace: '    "cross_domain_application_nonclaim",\n    "correctness_nonclaim",\n    "authority_nonclaim",\n    "global_canonicality_nonclaim",\n    "challenge_state",\n];',
    target:
      "CHALLENGE: the challenged revision's CONTENT HASH did not move — standing is a fact about the chain and lives outside the content commitment. This is the two-reads-across-a-durable-write claim no fixture can make.",
  },
  {
    id: "decision-mints-its-own-receipt",
    file: ROUTE_SOURCE,
    find: '        document["mapping_decision_receipt_ref"] =\n            document["admission"]["agentgres_receipt_ref"].clone();',
    replace: '        document["mapping_decision_receipt_ref"] = json!("receipt://minted/beside-the-admission");',
    target:
      "DECISION: the canonical decision receipt IS the admitting batch's own Agentgres receipt, not a second receipt minted beside it",
  },
  {
    id: "index-reports-agreement-it-did-not-have",
    file: ROUTE_SOURCE,
    find: '        None => "rebuilt_from_agentgres",',
    replace: '        None => "agreed_with_agentgres",',
    target:
      "INDEX REBUILD, POSITIVELY DETECTED: the first read after restart reports the process-local cache as REBUILT rather than agreed, so an unchanged answer is not mistaken for a cache that was never dropped",
  },
  {
    id: "reviewer-may-hold-a-role-twice",
    file: ROUTE_SOURCE,
    find: "        if seen.contains(&key) {",
    replace: "        if false && seen.contains(&key) {",
    target: "DECISION REFUSES: one reviewer standing in for a quorum of itself in one role",
  },
  {
    id: "decider-is-taken-from-the-body",
    file: ROUTE_SOURCE,
    find: '    let decided_by_ref = caller.owner_ref.clone();',
    replace: '    let decided_by_ref = if str_field(&body, "expected_decided_by_ref").is_empty() {\n        caller.owner_ref.clone()\n    } else {\n        str_field(&body, "expected_decided_by_ref").to_owned()\n    };',
    target:
      "DECISION REFUSES: the decider is the authenticated owner and is never accepted from the body (INV-37)",
  },
  {
    id: "v1-challenge-envelope-is-downgraded-into",
    file: ROUTE_SOURCE,
    find: '    if !declared_contract.is_empty() && declared_contract != CHALLENGE_CONTRACT {\n        return refuse(\n            "ontology_mapping_challenge_contract_unsupported",',
    replace: '    if false && declared_contract != CHALLENGE_CONTRACT {\n        return refuse(\n            "ontology_mapping_challenge_contract_unsupported",',
    target:
      "CHALLENGE REFUSES: a v1 envelope is refused BY NAME rather than downgraded into — its challenged_ref pattern cannot address a semantic-plane subject at all",
  },
  {
    id: "declared-loss-may-understate-the-rows",
    file: ROUTE_SOURCE,
    find: '    if declared_loss == "none" && (mappings.unmapped > 0 || !mappings.ambiguous.is_empty()) {',
    replace: '    if false && declared_loss == "none" {',
    target:
      "CROSSWALK REFUSES: declaring no loss while the declared rows leave a term unmapped — the posture must cover what the map actually does",
  },
  {
    id: "an-absent-base-revision-resolves",
    file: OWNER_SEAM_SOURCE,
    // A GENUINE BYPASS, not a renamed label. The exact-revision resolver becomes a NEAREST-revision
    // resolver AND loses the identity fence behind it, so an overlay naming a revision the chain
    // never admitted binds the newest one instead and is ADMITTED. The span covers both fences
    // deliberately: defeating only the first yields a 502, which is still a refusal.
    find: "    let Some(document) = lineage\n        .iter()\n        .find(|document| ordinal_of(document) == coordinates.ordinal)\n    else {\n        return Err(bad(\n            StatusCode::NOT_FOUND,\n            \"ontology_version_revision_absent\",\n            format!(\n                \"this family has no revision {} \u2014 an absent revision is a typed absence, never an empty success\",\n                coordinates.ordinal\n            ),\n        ));\n    };\n    let field = |key: &str| {\n        document\n            .get(key)\n            .and_then(Value::as_str)\n            .unwrap_or_default()\n            .to_owned()\n    };\n    let resolved = ResolvedOntologyRevision {\n        ontology_id: field(\"ontology_id\"),\n        ontology_family_ref: field(\"ontology_family_ref\"),\n        namespace: field(\"namespace\"),\n        name: field(\"name\"),\n        revision_ordinal: coordinates.ordinal,\n        content_hash: field(\"content_hash\"),\n        status: field(\"status\"),\n    };\n    // The projection is already contract-validated, so a disagreement here means the chain answered\n    // with a revision other than the one addressed. That is not something to hand a consumer with a\n    // caveat; it is an unreadable chain.\n    if resolved.ontology_id != ontology_id\n        || resolved.ontology_family_ref != family\n        || resolved.namespace != coordinates.namespace\n        || resolved.name != coordinates.name\n        || !is_sha256(&resolved.content_hash)\n        || resolved.status.is_empty()\n    {\n        return Err(bad(\n            StatusCode::BAD_GATEWAY,\n            \"ontology_version_projection_failed\",\n            format!(\n                \"the chain resolved '{ontology_id}' to a revision that does not bind that identity\"\n            ),\n        ));\n    }\n",
    replace: "    // MUTANT: the exact-revision resolver becomes a NEAREST-revision resolver. An absent ordinal\n    // binds the newest admitted revision, and the identity fence that would have caught the\n    // substitution is gone with it, so the consumer receives a real revision's coordinates under an\n    // identity nobody admitted and its own admission SUCCEEDS.\n    let Some(document) = lineage\n        .iter()\n        .find(|document| ordinal_of(document) == coordinates.ordinal)\n        .or_else(|| lineage.last())\n    else {\n        return Err(bad(\n            StatusCode::NOT_FOUND,\n            \"ontology_version_revision_absent\",\n            format!(\n                \"this family has no revision {} \u2014 an absent revision is a typed absence, never an empty success\",\n                coordinates.ordinal\n            ),\n        ));\n    };\n    let field = |key: &str| {\n        document\n            .get(key)\n            .and_then(Value::as_str)\n            .unwrap_or_default()\n            .to_owned()\n    };\n    let resolved = ResolvedOntologyRevision {\n        ontology_id: field(\"ontology_id\"),\n        ontology_family_ref: field(\"ontology_family_ref\"),\n        namespace: field(\"namespace\"),\n        name: field(\"name\"),\n        revision_ordinal: coordinates.ordinal,\n        content_hash: field(\"content_hash\"),\n        status: field(\"status\"),\n    };\n",
    target:
      "OVERLAY REFUSES: a well-formed base revision this chain never admitted is a typed absence, not an empty success — the defect no byte-level fixture can catch",
  },
  {
    id: "a-challenge-may-name-an-absent-subject",
    file: ROUTE_SOURCE,
    // A GENUINE BYPASS: a challenge against a revision this family never admitted falls back to the
    // newest revision and is DURABLY APPENDED. The forbidden operation is accepted at the chain; the
    // 502 the route answers afterwards is the damage surfacing, not a fence catching it, and the
    // stream is left carrying a challenge whose subject does not exist.
    find: "    let Some(subject) = lineage\n        .iter()\n        .find(|document| ordinal_of(document) == coordinates.ordinal)\n        .cloned()\n    else {\n        return bad(\n            StatusCode::NOT_FOUND,\n            \"ontology_mapping_challenged_revision_absent\",",
    replace: "    let Some(subject) = lineage\n        .iter()\n        .find(|document| ordinal_of(document) == coordinates.ordinal)\n        .cloned()\n        .or_else(|| lineage.last().cloned())\n    else {\n        return bad(\n            StatusCode::NOT_FOUND,\n            \"ontology_mapping_challenged_revision_absent\",",
    target:
      "CHALLENGE REFUSES: a challenge against a revision this family never admitted would leave a permanently dangling standing nobody can resolve",
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
    `\nM05.2 mutation battery: ${reds}/${rows.length} RED ON TARGET; collateral failures ${collateral}; source restored ${restored}\n`,
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
    `\nM05.2 mutation summary: ${MUTANTS.length - missing.length - notRed.length}/${MUTANTS.length} RED ON TARGET\n`,
  );
  // A chunk that never ran is a MISSING ROW, not a silent pass; and a ledger for another tree is
  // treated as no ledger at all.
  process.exit(current && missing.length === 0 && notRed.length === 0 ? 0 : 1);
}

// ------------------------------------------------------------------------------------------- driver

async function runAll() {
  await run();
  const ctx = await runMappings();
  const challenged = await runChallenges(ctx);
  await runCrossDomain();
  await runDurability({ ...ctx, ...challenged });
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
    verifierId: "semantic-mapping-lifecycle",
    sourceUrl: import.meta.url,
    results,
  });
  process.stdout.write(
    `\ncheck:semantic-mapping-lifecycle — ${results.length - failed.length}/${results.length} assertions\n`,
  );
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((error) => {
  cleanup();
  process.stderr.write(`${error}\n`);
  process.exit(1);
});
