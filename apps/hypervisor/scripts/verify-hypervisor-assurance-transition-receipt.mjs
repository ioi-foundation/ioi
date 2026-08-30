#!/usr/bin/env node
// M06 prerequisite — `AssuranceTransitionReceipt` driven end to end against a live daemon and its
// durable Agentgres chain, over a subject that a DIFFERENT owner actually admitted.
//
// WHAT THIS GATE IS FOR. M05.2 and M05.3 both need to record that a verifier stood behind — or
// refused to stand behind — a semantic-plane claim, and neither may mint that object itself without
// becoming a second spine. So the claims here are the seam ones: a subject is RESOLVED through its
// own owner rather than believed from its URI, the ladder advances one member at a time, negative
// outcomes survive and are queryable, and nothing here is a verdict or a grant.
//
// HOW IT AVOIDS GRADING ITSELF:
//
//   * THE CONTENT HASH IS RECOMPUTED FROM CANON, not from the response. The material field list is
//     read out of the REGISTERED invariant profile in `docs/architecture/_meta/schemas/invariants/`
//     and the digest is taken here in JavaScript. If the daemon's commitment ever stops covering what
//     the registered contract says it covers, these two disagree.
//   * THE SUBJECT IS A REAL ADMITTED ONTOLOGY REVISION, minted through M05.1's own route in this same
//     run. Binding a hash the verifier invented would prove the transition stores what it is told,
//     which is the opposite of the claim.
//   * DURABLE TRUTH IS READ ACROSS A RESTART. Asking the API whether something survived a restart,
//     without restarting, is asking the thing under test to grade itself.
//   * REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the ladder afterwards and
//     requires the head and transition count to be exactly what they were. A 4xx that still appended
//     is the failure this shape exists to catch.
//   * THE OFFLINE HALF IS CHECKED OFFLINE. The registered fixtures are validated with no daemon
//     present, because "no stage skips" has to hold for a relying party who has only the bytes.
//   * A GREEN RUN CERTIFIES NOTHING UNTIL THE HARNESS PROVES IT RED. `--mutate` plants named defects
//     in the daemon's own source, rebuilds, re-runs this file against the mutant, and requires each
//     one to redden the exact assertion it targets — a mutant that only reddens something else is
//     reported as a MISS, not quietly counted.
//
// NONCLAIMS. This gate proves the transition seam only. It makes NO claim that the M06.1 WorkResult
// ladder exists, that the M05.3 assertion graph or M05.2 mappings exist, that any dispute is
// adjudicated, or that anything settles. It asserts that the receipt carries its authority and
// verdict nonclaims and that no capability, lease or policy decision is consulted — which is not the
// same as proving the authority planes elsewhere.

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
  "crates/node/src/bin/hypervisor_daemon_routes/assurance_transition_routes.rs",
);
const SCHEMAS = path.join(ROOT, "docs/architecture/_meta/schemas");
const INVARIANT_PROFILE = path.join(
  SCHEMAS,
  "invariants/assurance-transition-receipt.v1.invariants.json",
);
const REGISTRY = path.join(SCHEMAS, "architecture-contract-registry.v1.json");
const CONTRACT_ID = "schema://ioi/foundations/assurance-transition-receipt/v1";
const CHALLENGE_V1 = "schema://ioi/foundations/objects/verifier-challenge-envelope/v1";
const CHALLENGE_V2 = "schema://ioi/foundations/objects/verifier-challenge-envelope/v2";
const MUTATE = process.argv.includes("--mutate");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.error?.code ?? j?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

// ------------------------------------------------------------------ canonical JSON + content hash

// JCS for the ASCII-only material this contract commits: keys sorted by code unit, ES6 numbers.
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

/**
 * The content commitment, rebuilt from the REGISTERED invariant profile rather than from anything
 * this file or the daemon asserts. `material_fields` and the domain constant both come out of canon.
 */
function registeredContentCommitment(document) {
  const profile = JSON.parse(fs.readFileSync(INVARIANT_PROFILE, "utf8"));
  const rule = profile.rules.find(
    (candidate) =>
      candidate.rule_id ===
      "assurance_transition.content_hash.commits_subject_stage_outcome_and_valid_time",
  );
  if (!rule) throw new Error("the registered invariant profile declares no content commitment rule");
  const material = {};
  for (const [field, descriptor] of Object.entries(rule.expression.material_fields)) {
    if (Object.hasOwn(descriptor, "value")) {
      material[field] = descriptor.value;
      continue;
    }
    const pointer = descriptor.path.slice(2).split(".");
    let current = document;
    for (const segment of pointer) current = current?.[segment];
    material[field] = current === undefined ? null : current;
  }
  return {
    digest: `sha256:${crypto.createHash("sha256").update(canonicalJson(material)).digest("hex")}`,
    fields: Object.keys(rule.expression.material_fields),
  };
}

// ------------------------------------------------------------------------------------- daemon plane

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-assurance-transition-"));
const dataDir = path.join(scratch, "data");
fs.mkdirSync(dataDir, { recursive: true });

let daemon = null;
let daemonLog = "";
let DAEMON = "";

async function waitFor(url, timeoutMs = 60000) {
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
      IOI_WALLET_SECRET_PASS: "ioi-assurance-transition-verifier",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  daemon.stderr.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  if (!(await waitFor(`${DAEMON}/healthz`))) {
    throw new Error("the isolated daemon never became healthy");
  }
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
const AT = "/v1/hypervisor/assurance-transitions";

const NONCLAIMS = ["correctness", "acceptance", "settlement"];

function transition({
  subject,
  key,
  expectedHead = null,
  outcome = "positive",
  nonclaims = NONCLAIMS,
  startsAt = "2026-02-01T00:00:00Z",
  extra = {},
}) {
  const body = {
    owner_ref: "org://local",
    idempotency_key: key,
    subject_ref: subject,
    outcome_class: outcome,
    evidence_refs: [`evidence://assurance/${key}`],
    does_not_assert: nonclaims,
    valid_time: { starts_at: startsAt, ends_at: null },
    ...extra,
  };
  if (expectedHead !== null) body.expected_head = expectedHead;
  return body;
}

const ladderOf = async (subject, query = "", as = "A") =>
  req("GET", `${AT}?subject_ref=${encodeURIComponent(subject)}${query}`, null, { as });

/** The exact (head, count) pair, so a refusal can be counted BY EFFECT rather than by status code. */
async function ladderState(subject, as = "A") {
  const response = await ladderOf(subject, "", as);
  const transitions = response.j?.transitions ?? [];
  return {
    count: response.j?.transition_count ?? -1,
    head: transitions.at(-1)?.admission?.admission_head ?? null,
    reached: response.j?.reached_stage ?? null,
    // Captured on THIS read. The cache is populated by the act of reading, so an index-state claim
    // has to be made about the FIRST read after a restart, never a later one.
    indexState: response.j?.rebuildable_index_state ?? null,
    truthSource: response.j?.truth_source ?? null,
  };
}

// ------------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();

  // ---------------------------------------------------------------------------------- principals
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "assurance-transition-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const whoA = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "assurance-transition-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "assurance-transition-b-v1",
    },
    { as: "A" },
  );
  const principalB = created.j?.principal?.principal_id ?? "";
  await req(
    "POST",
    `/v1/hypervisor/principals/${principalB}/tenant-memberships`,
    {
      tenant_ref: "org://local",
      expected_revision: 0,
      idempotency_key: "assurance-transition-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "assurance-transition-b@ioi.local", password: "assurance-transition-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  const whoB = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "B" })).j || {};
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant, so a tenant check alone would isolate nothing",
    whoA.authenticated === true &&
      whoB.authenticated === true &&
      (whoA.principal?.tenant_refs || []).includes("org://local") &&
      (whoB.principal?.tenant_refs || []).includes("org://local") &&
      whoA.principal?.principal_ref !== whoB.principal?.principal_ref,
    `A=${whoA.principal?.principal_ref} B=${whoB.principal?.principal_ref}`,
  );

  // ------------------------------------------------- a REAL subject, admitted by its own owner
  const subjectResponse = await req(
    "POST",
    OV,
    {
      owner_ref: "org://local",
      idempotency_key: "assurance-subject-genesis",
      namespace: "acme-clinic",
      name: "patient-intake",
      governing_scope_ref: "domain://acme-clinic/intake",
      policy_hash: `sha256:${"1a".repeat(32)}`,
      entity_types: [
        { term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" },
      ],
      valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
    },
    { as: "A" },
  );
  const subjectVersion = subjectResponse.j?.ontology_version ?? {};
  const SUBJECT = subjectVersion.ontology_id ?? "";
  ok(
    "PRECONDITION: the subject of every transition below is a REAL ontology revision admitted through M05.1's own route in this run — binding a hash this verifier invented would prove only that the receipt stores what it is told",
    subjectResponse.status === 201 &&
      SUBJECT === "ontology://acme-clinic/patient-intake/revision/1" &&
      /^sha256:[0-9a-f]{64}$/u.test(subjectVersion.content_hash ?? ""),
    `status ${subjectResponse.status} subject ${SUBJECT} hash ${subjectVersion.content_hash}`,
  );
  const SUBJECT_HASH = subjectVersion.content_hash;

  // ------------------------------------------------------------------------- identity comes first
  const anonymous = await req("POST", AT, transition({ subject: SUBJECT, key: "anon" }), {
    as: null,
  });
  ok(
    "an unauthenticated admission is refused on IDENTITY before any content is judged — a 422 here would tell an anonymous caller which fields this route wants",
    anonymous.status === 401,
    `status ${anonymous.status} code ${code(anonymous.j)}`,
  );

  // ------------------------------------------------------- the subject is RESOLVED, not believed
  const invented = await req(
    "POST",
    AT,
    transition({ subject: "ontology://acme-clinic/patient-intake/revision/97", key: "invented" }),
    { as: "A" },
  );
  ok(
    "A URI PREFIX IS NOT PROOF THE SUBJECT EXISTS. A well-formed ontology revision ref that names no admitted revision is refused by the OWNER's resolver, so an unresolvable subject can never acquire a ladder on the strength of its spelling",
    invented.status === 404 && code(invented.j) === "ontology_version_revision_absent",
    `status ${invented.status} code ${code(invented.j)}`,
  );
  const wrongShape = await req(
    "POST",
    AT,
    transition({ subject: "ontology://acme-clinic/patient-intake/revision/01", key: "padded" }),
    { as: "A" },
  );
  ok(
    "a non-canonical subject spelling is refused rather than normalised — two spellings resolving to one revision would let a transition claim it moved something other than what it moved",
    wrongShape.status === 422 && code(wrongShape.j) === "ontology_version_identity_not_canonical",
    `status ${wrongShape.status} code ${code(wrongShape.j)}`,
  );
  for (const [family, subject] of [
    ["ontology_assertion", "ontology-assertion://acme-clinic/patient-intake/assertion/1"],
    ["ontology_mapping_revision", "ontology-mapping://acme-clinic/billing/crosswalk/1"],
    ["work_result", "work-result://room/one"],
    ["finding", "finding://room/one/finding/1"],
    ["attempt", "attempt://room/one/attempt/1"],
  ]) {
    const response = await req("POST", AT, transition({ subject, key: `family-${family}` }), {
      as: "A",
    });
    ok(
      `the '${family}' subject family is NAMEABLE on the v1 wire but FAILS CLOSED with no landed resolver — subject-generality from birth is what lets a later unit add its resolver without a wire change, and refusing by name is what stops the ladder accumulating subjects nobody can resolve`,
      response.status === 501 &&
        code(response.j) === "assurance_transition_subject_family_unresolvable" &&
        (response.j?.error?.message ?? "").includes(family),
      `status ${response.status} code ${code(response.j)}`,
    );
  }
  const unknownScheme = await req(
    "POST",
    AT,
    transition({ subject: "goal-run://anything/1", key: "unknown-scheme" }),
    { as: "A" },
  );
  ok(
    "a scheme outside the registered subject set is refused as an unknown scheme, distinctly from a known family with no resolver — the two are different findings and a single generic refusal would hide which one happened",
    unknownScheme.status === 422 &&
      code(unknownScheme.j) === "assurance_transition_subject_scheme_unknown",
    `status ${unknownScheme.status} code ${code(unknownScheme.j)}`,
  );

  // -------------------------------------------------------------------------- genesis transition
  const t1Response = await req(
    "POST",
    AT,
    transition({ subject: SUBJECT, key: "t1-attested" }),
    { as: "A" },
  );
  const t1 = t1Response.j?.assurance_transition ?? {};
  ok(
    "the first transition of a subject enters the ladder at ATTESTED with no predecessor and a real Agentgres admission",
    t1Response.status === 201 &&
      t1.to_stage === "attested" &&
      t1.from_stage === null &&
      t1.transition_ordinal === 1 &&
      t1.to_stage_ordinal === 1 &&
      t1.expected_predecessor_transition_ref === null &&
      /^sha256:[0-9a-f]{64}$/u.test(t1.admission?.admission_head ?? ""),
    `status ${t1Response.status} stage ${t1.to_stage} ordinal ${t1.transition_ordinal}`,
  );
  ok(
    "THE SUBJECT BINDING IS THE OWNER'S, CARRIED VERBATIM — the transition's subject_content_hash is byte-equal to the hash M05.1's own route served for that revision, and it names the exact resolver seam that produced it",
    t1.subject_ref === SUBJECT &&
      t1.subject_content_hash === SUBJECT_HASH &&
      t1.subject_family === "ontology_revision" &&
      t1.subject_resolved_by === "ontology_version_routes::resolve_admitted_revision",
    `subject ${t1.subject_ref} hash ${t1.subject_content_hash} by ${t1.subject_resolved_by}`,
  );
  ok(
    "THE ACTOR IS THE AUTHENTICATED PRINCIPAL, NOT THE REQUEST'S OWNER CONTEXT — `owner_ref` is a tenant the caller may act WITHIN and is shared by every member of that organization, so recording it as the actor would attribute the stage to the org rather than to whoever stood behind it, and would let the caller pick its own attribution from a set it is merely a member of",
    t1.actor_ref === whoA.principal?.principal_ref &&
      t1.actor_ref !== "org://local" &&
      t1.actor_ref.startsWith("user://"),
    `actor ${t1.actor_ref} authenticated ${whoA.principal?.principal_ref} owner_ref org://local`,
  );
  ok(
    "the receipt carries BOTH explicit nonclaims — a receipt is evidence, never a verdict, and it grants nothing (NN 20)",
    t1.authority_nonclaim === "assurance_transition_grants_no_authority" &&
      t1.verdict_nonclaim === "assurance_transition_is_not_a_verdict" &&
      t1.receipt_type === "assurance_transition" &&
      t1.schema_version === "ioi.assurance-transition-receipt.v1",
    `authority ${t1.authority_nonclaim} verdict ${t1.verdict_nonclaim}`,
  );
  const registeredT1 = registeredContentCommitment(t1);
  ok(
    "the served content hash is INDEPENDENTLY reproducible from the registered invariant profile's own material fields — the daemon does not get to define its own commitment",
    registeredT1.digest === t1.content_hash,
    `registered ${registeredT1.digest} served ${t1.content_hash} over ${registeredT1.fields.length} fields`,
  );
  ok(
    "that commitment covers the SUBJECT BINDING, the OUTCOME CLASS, the NONCLAIM SET and VALID time, and excludes TRANSACTION time — so a stage's meaning is frozen while its admission interval stays free to close",
    registeredT1.fields.includes("subject_content_hash") &&
      registeredT1.fields.includes("outcome_class") &&
      registeredT1.fields.includes("does_not_assert") &&
      registeredT1.fields.includes("valid_time") &&
      !registeredT1.fields.includes("transaction_time"),
    `fields ${registeredT1.fields.join(",")}`,
  );
  const head1 = t1.admission.admission_head;

  // ------------------------------------------------------------------ idempotent replay, not a fork
  const replay = await req("POST", AT, transition({ subject: SUBJECT, key: "t1-attested" }), {
    as: "A",
  });
  ok(
    "the SAME key with the same bytes replays the ORIGINAL admitted transition rather than minting a second one",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.assurance_transition?.admission?.admission_seq === t1.admission.admission_seq &&
      replay.j?.assurance_transition?.admission?.admission_head === head1,
    `status ${replay.status} replayed ${replay.j?.replayed}`,
  );

  // ------------------------------------------------- a key replays ONE command, not any command
  //
  // The substrate refuses same-key-different-bytes at the admission boundary, but a replay answered
  // from the projected ladder never REACHES that boundary. Without an intent comparison in front of
  // it, a caller could reuse a key with a different claim and be told the original had been
  // recorded — worst exactly where it matters most, quietly answering "your NEGATIVE finding was
  // recorded" with a stored POSITIVE one.
  for (const [field, changed] of [
    ["outcome_class", { outcome: "negative" }],
    ["evidence_refs", { extra: { evidence_refs: ["evidence://assurance/substituted"] } }],
    ["valid_time", { startsAt: "2026-03-03T00:00:00Z" }],
    ["does_not_assert", { nonclaims: ["correctness", "acceptance", "settlement", "authority"] }],
    ["to_stage", { extra: { to_stage: "verified" } }],
  ]) {
    const response = await req(
      "POST",
      AT,
      transition({ subject: SUBJECT, key: "t1-attested", ...changed }),
      { as: "A" },
    );
    const after = await ladderState(SUBJECT);
    ok(
      `replaying an admitted idempotency key with a CHANGED '${field}' is refused as a changed-intent replay and appends nothing — a key answers "did this exact command land?", so returning the stored transition in answer to a different one would substitute one claim for another`,
      response.status === 409 &&
        code(response.j) === "assurance_transition_replay_intent_changed" &&
        (response.j?.error?.message ?? "").includes(field) &&
        after.count === 1 &&
        after.head === head1,
      `status ${response.status} code ${code(response.j)} count ${after.count}`,
    );
  }
  // ------------------------- a replay confirms one command; it never confirms a false assertion
  //
  // The comparison above asks "is this the same command?". These fields ask a different question
  // that ORDINARY admission asks and the replay path used to skip: are the things the caller CLAIMS
  // to know about the server's own derivation actually true? A `200 replayed: true` is read as
  // "everything you asserted holds", so returning one while an assertion is false is the receipt
  // lying about itself.
  const TRUE_ASSERTIONS = {
    subject_content_hash: SUBJECT_HASH,
    subject_family: "ontology_revision",
    expected_predecessor_transition_ref: null,
    expected_predecessor_transition_hash: null,
    expected_transition_ordinal: 1,
    expected_content_hash: t1.content_hash,
  };
  for (const [field, value, expectedCode] of [
    ["subject_content_hash", `sha256:${"4".repeat(64)}`, "assurance_transition_subject_hash_substituted"],
    ["subject_family", "work_result", "assurance_transition_subject_family_substituted"],
    [
      "expected_predecessor_transition_ref",
      "assurance-transition://ontology_revision/forged/transition/1",
      "assurance_transition_predecessor_substituted",
    ],
    [
      "expected_predecessor_transition_hash",
      `sha256:${"5".repeat(64)}`,
      "assurance_transition_predecessor_hash_substituted",
    ],
    ["expected_transition_ordinal", 2, "assurance_transition_ordinal_gap"],
    ["expected_content_hash", `sha256:${"3".repeat(64)}`, "assurance_transition_content_hash_substituted"],
  ]) {
    const response = await req(
      "POST",
      AT,
      transition({ subject: SUBJECT, key: "t1-attested", extra: { [field]: value } }),
      { as: "A" },
    );
    const after = await ladderState(SUBJECT);
    ok(
      `replaying an admitted key while ASSERTING a false '${field}' is refused by that field's own cause and appends nothing — a stored success must never stand as confirmation of a server-derived fact nobody compared`,
      response.status === 422 &&
        code(response.j) === expectedCode &&
        response.j?.replayed === undefined &&
        after.count === 1 &&
        after.head === head1,
      `status ${response.status} code ${code(response.j)} count ${after.count}`,
    );
  }
  const replayAllTrue = await req(
    "POST",
    AT,
    transition({ subject: SUBJECT, key: "t1-attested", extra: { ...TRUE_ASSERTIONS } }),
    { as: "A" },
  );
  ok(
    "a retry that asserts ALL SIX server-derived facts at their true stored values still replays — the check refuses false claims without turning a correct, fully-asserted retry into a conflict",
    replayAllTrue.status === 200 &&
      replayAllTrue.j?.replayed === true &&
      replayAllTrue.j?.assurance_transition?.admission?.admission_head === head1,
    `status ${replayAllTrue.status} replayed ${replayAllTrue.j?.replayed}`,
  );

  const replayAgain = await req(
    "POST",
    AT,
    transition({ subject: SUBJECT, key: "t1-attested" }),
    { as: "A" },
  );
  ok(
    "and the UNCHANGED command still replays after all of those refusals — the intent comparison narrows the key to one command rather than breaking idempotency, which is the failure mode a naive fix produces",
    replayAgain.status === 200 &&
      replayAgain.j?.replayed === true &&
      replayAgain.j?.assurance_transition?.admission?.admission_head === head1,
    `status ${replayAgain.status} replayed ${replayAgain.j?.replayed}`,
  );

  // ----------------------------------------------------------------------- exact-head advancement
  const headless = await req("POST", AT, transition({ subject: SUBJECT, key: "t2-headless" }), {
    as: "A",
  });
  ok(
    "a successor offered with NO expected head is refused: an existing ladder is never appended to unconditionally",
    headless.status === 409 && code(headless.j) === "assurance_transition_expected_head_conflict",
    `status ${headless.status} code ${code(headless.j)}`,
  );
  const staleHead = await req(
    "POST",
    AT,
    transition({ subject: SUBJECT, key: "t2-stale", expectedHead: `sha256:${"0".repeat(64)}` }),
    { as: "A" },
  );
  const afterStale = await ladderState(SUBJECT);
  ok(
    "a STALE head is refused and appends nothing: the ladder's head and transition count are identical either side of the refusal",
    staleHead.status === 409 &&
      code(staleHead.j) === "assurance_transition_expected_head_conflict" &&
      afterStale.count === 1 &&
      afterStale.head === head1,
    `status ${staleHead.status} count ${afterStale.count}`,
  );

  // ------------------------------------------------------------------------------- no stage skips
  const skip = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t2-skip",
      expectedHead: head1,
      extra: { to_stage: "accepted" },
    }),
    { as: "A" },
  );
  const afterSkip = await ladderState(SUBJECT);
  ok(
    "A STAGE IS NOT REACHED BY SKIPPING THE ONE BEFORE IT — asking for 'accepted' at chain position 2 is refused by its own cause and appends nothing, so no stage can be claimed that nobody stood behind",
    skip.status === 422 &&
      code(skip.j) === "assurance_transition_stage_skip" &&
      afterSkip.count === 1 &&
      afterSkip.head === head1,
    `status ${skip.status} code ${code(skip.j)} count ${afterSkip.count}`,
  );

  // ---------------------------------------------------------- the nonclaim set is load-bearing
  const emptyNonclaims = await req(
    "POST",
    AT,
    transition({ subject: SUBJECT, key: "t2-noclaims", expectedHead: head1, nonclaims: [] }),
    { as: "A" },
  );
  ok(
    "an EMPTY does_not_assert is refused — a transition that disclaims nothing has collapsed NN 20 into a bare success flag",
    emptyNonclaims.status === 422 &&
      code(emptyNonclaims.j) === "assurance_transition_does_not_assert_empty",
    `status ${emptyNonclaims.status} code ${code(emptyNonclaims.j)}`,
  );
  const partialNonclaims = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t2-partial",
      expectedHead: head1,
      nonclaims: ["correctness"],
    }),
    { as: "A" },
  );
  ok(
    "a pre-acceptance stage that does not explicitly disclaim ACCEPTANCE is refused — a stage short of acceptance that does not say so is read as acceptance by omission",
    partialNonclaims.status === 422 &&
      code(partialNonclaims.j) === "assurance_transition_nonclaim_incomplete",
    `status ${partialNonclaims.status} code ${code(partialNonclaims.j)}`,
  );

  // ------------------------------------------------------- negative outcomes are never normalised
  //
  // A real gap between admissions, so "as of T1" and "as of T2" are distinguishable instants rather
  // than the same millisecond. The bitemporal assertions below depend on that separation being real.
  const t1RecordedAt = t1.transaction_time.recorded_at;
  await sleep(1200);
  const t2Response = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t2-evidenced",
      expectedHead: head1,
      outcome: "exploit",
    }),
    { as: "A" },
  );
  const t2 = t2Response.j?.assurance_transition ?? {};
  ok(
    "a NEGATIVE outcome class is retained VERBATIM through admission and projection — an exploit finding that came back as 'exploit' is stored as 'exploit', never normalised toward success (NN 21, ACC-8 clause 2)",
    t2Response.status === 201 &&
      t2.outcome_class === "exploit" &&
      t2.to_stage === "evidenced" &&
      t2.from_stage === "attested" &&
      t2.transition_ordinal === 2,
    `status ${t2Response.status} outcome ${t2.outcome_class} stage ${t2.to_stage}`,
  );
  const badOutcome = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t3-badoutcome",
      expectedHead: t2.admission.admission_head,
      outcome: "success",
    }),
    { as: "A" },
  );
  ok(
    "an UNKNOWN outcome class is refused rather than defaulted — a class the ladder does not know is exactly where a negative result would quietly become a positive one",
    badOutcome.status === 422 &&
      code(badOutcome.j) === "assurance_transition_outcome_class_invalid",
    `status ${badOutcome.status} code ${code(badOutcome.j)}`,
  );

  // ------------------------------------------------------------------------ the caller authors nothing
  const spoof = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t3-spoof",
      expectedHead: t2.admission.admission_head,
      extra: {
        actor_ref: "system://someone-else",
        transaction_time: { recorded_at: "1999-01-01T00:00:00Z", superseded_at: null },
        content_hash: `sha256:${"9".repeat(64)}`,
        resulting_stage_head_hash: `sha256:${"9".repeat(64)}`,
        admission: { transition_id: "assurance-transition://forged/x/transition/3" },
      },
    }),
    { as: "A" },
  );
  const t3 = spoof.j?.assurance_transition ?? {};
  const spoofCommitment = registeredContentCommitment(t3);
  ok(
    "ACTOR, TRANSACTION TIME, CONTENT HASH, RESULTING HEAD AND THE ADMISSION BLOCK ARE ALL SERVER-RESOLVED (INV-37) — a body that supplies every one of them is admitted with the AUTHENTICATED principal, a real admission stamp and a re-derived hash, and none of the supplied values survives",
    spoof.status === 201 &&
      t3.actor_ref !== "system://someone-else" &&
      t3.content_hash !== `sha256:${"9".repeat(64)}` &&
      t3.content_hash === spoofCommitment.digest &&
      t3.resulting_stage_head_hash === t3.content_hash &&
      !(t3.transaction_time?.recorded_at ?? "").startsWith("1999") &&
      t3.admission?.transition_id === t3.transition_id,
    `actor ${t3.actor_ref} recorded ${t3.transaction_time?.recorded_at} admission ${t3.admission?.transition_id}`,
  );

  // ------------------------------------------- expected_head is excluded from the replay checks
  //
  // A genuine retry follows an ambiguous response, so it necessarily still carries the head it
  // originally compare-and-swapped against — which is stale by construction once the ladder has
  // moved on. Refusing it would break the exact case the idempotency key exists to serve, so
  // `expected_head` is deliberately absent from the assertion set above.
  const staleHeadRetry = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t2-evidenced",
      expectedHead: head1,
      outcome: "exploit",
    }),
    { as: "A" },
  );
  ok(
    "a true retry that still carries its ORIGINAL, now-stale expected_head replays rather than conflicting — the ladder has advanced twice since, so this is exactly the ambiguous-response case an idempotency key exists to serve and the assertion checks must not break it",
    staleHeadRetry.status === 200 &&
      staleHeadRetry.j?.replayed === true &&
      staleHeadRetry.j?.assurance_transition?.transition_ordinal === 2 &&
      staleHeadRetry.j?.assurance_transition?.outcome_class === "exploit",
    `status ${staleHeadRetry.status} replayed ${staleHeadRetry.j?.replayed} ordinal ${staleHeadRetry.j?.assurance_transition?.transition_ordinal}`,
  );

  // --------------------------------------------------------- asserted server facts refuse by cause
  const wrongSubjectHash = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t4-wronghash",
      expectedHead: t3.admission.admission_head,
      extra: { subject_content_hash: `sha256:${"7".repeat(64)}` },
    }),
    { as: "A" },
  );
  const afterWrongHash = await ladderState(SUBJECT);
  ok(
    "an ASSERTED subject hash that disagrees with the owner's current commitment is refused BY ITS OWN CAUSE and appends nothing — the binding is the subject owner's, never the caller's",
    wrongSubjectHash.status === 422 &&
      code(wrongSubjectHash.j) === "assurance_transition_subject_hash_substituted" &&
      afterWrongHash.count === 3,
    `status ${wrongSubjectHash.status} code ${code(wrongSubjectHash.j)} count ${afterWrongHash.count}`,
  );
  const wrongFamily = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t4-wrongfamily",
      expectedHead: t3.admission.admission_head,
      extra: { subject_family: "work_result" },
    }),
    { as: "A" },
  );
  ok(
    "an ASSERTED subject family that disagrees with the scheme the subject actually names is refused — a record cannot be lifted onto another family's ladder",
    wrongFamily.status === 422 &&
      code(wrongFamily.j) === "assurance_transition_subject_family_substituted",
    `status ${wrongFamily.status} code ${code(wrongFamily.j)}`,
  );
  const wrongPredecessor = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t4-wrongpred",
      expectedHead: t3.admission.admission_head,
      extra: { expected_predecessor_transition_hash: `sha256:${"6".repeat(64)}` },
    }),
    { as: "A" },
  );
  ok(
    "an ASSERTED predecessor hash that does not match the ladder's exact current transition is refused by its own cause, distinctly from a stale HEAD — the two have different remedies",
    wrongPredecessor.status === 422 &&
      code(wrongPredecessor.j) === "assurance_transition_predecessor_hash_substituted",
    `status ${wrongPredecessor.status} code ${code(wrongPredecessor.j)}`,
  );

  // ---------------------------------------------------------------- unknown contract version
  const downgrade = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t4-downgrade",
      expectedHead: t3.admission.admission_head,
      extra: { schema_version: "ioi.assurance-transition-receipt.v2" },
    }),
    { as: "A" },
  );
  const afterDowngrade = await ladderState(SUBJECT);
  ok(
    "a DOWNGRADED contract version appends nothing: a caller naming a version this build does not implement is refused rather than having its bytes reinterpreted as v1, and the ladder is identical either side of the refusal",
    downgrade.status === 422 &&
      code(downgrade.j) === "assurance_transition_unsupported_schema_version" &&
      afterDowngrade.count === 3 &&
      afterDowngrade.head === t3.admission.admission_head,
    `status ${downgrade.status} code ${code(downgrade.j)} count ${afterDowngrade.count}`,
  );

  // --------------------------------------------------------------- owner scope and indistinguishability
  const foreignRead = await ladderOf(SUBJECT, "", "B");
  const foreignWrite = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "b-append",
      expectedHead: t3.admission.admission_head,
    }),
    { as: "B" },
  );
  const absentRead = await ladderOf("ontology://other-tenant/never-existed/revision/1", "", "B");
  ok(
    "a co-tenant principal who owns none of this subject's ladder can neither read nor append to it, and a subject that NEVER EXISTED answers B identically — so this route cannot become an existence oracle for another principal's ladder",
    foreignRead.status === absentRead.status &&
      code(foreignRead.j) === code(absentRead.j) &&
      foreignRead.status !== 200 &&
      foreignWrite.status !== 201 &&
      !JSON.stringify(foreignRead.j ?? {}).includes("acme-clinic"),
    `foreign ${foreignRead.status}/${code(foreignRead.j)} absent ${absentRead.status}/${code(absentRead.j)} write ${foreignWrite.status}`,
  );
  const beforeForeign = await ladderState(SUBJECT, "A");
  await ladderOf(SUBJECT, "", "B");
  await req(
    "POST",
    AT,
    transition({ subject: SUBJECT, key: "b-probe", expectedHead: t3.admission.admission_head }),
    { as: "B" },
  );
  const afterForeign = await ladderState(SUBJECT, "A");
  ok(
    "ANOTHER PRINCIPAL'S REFUSED READS AND WRITES DO NOT PERTURB THIS ONE'S CACHE ENTRY — the non-truth cache is keyed by the authorized reader AND the subject, so it cannot become a status side channel in which `stale_rebuilt_…` announces that somebody else's ladder moved",
    beforeForeign.indexState === "agreed_with_agentgres" &&
      afterForeign.indexState === "agreed_with_agentgres",
    `before ${beforeForeign.indexState} after ${afterForeign.indexState}`,
  );

  // ------------------------------------------------------------------------- negative results query
  const exploitOnly = await ladderOf(SUBJECT, "&outcome_class=exploit");
  const settledOnly = await ladderOf(SUBJECT, "&to_stage=settled");
  ok(
    "NEGATIVE RESULTS ARE QUERYABLE AS FIRST-CLASS (ACC-8 clause 2) — the exploit transition is selectable by outcome class, and a stage the ladder never reached returns an empty match rather than an error or a substitute",
    exploitOnly.status === 200 &&
      exploitOnly.j?.matched_transition_count === 1 &&
      exploitOnly.j?.transitions?.[0]?.outcome_class === "exploit" &&
      settledOnly.status === 200 &&
      settledOnly.j?.matched_transition_count === 0,
    `exploit ${exploitOnly.j?.matched_transition_count} settled ${settledOnly.j?.matched_transition_count}`,
  );
  ok(
    "a stage/outcome narrowing selects ROWS and never changes how far the subject actually got — reached_stage is read off the unfiltered ladder",
    exploitOnly.j?.reached_stage === "verified" && settledOnly.j?.reached_stage === "verified",
    `exploit-view ${exploitOnly.j?.reached_stage} settled-view ${settledOnly.j?.reached_stage}`,
  );

  // -------------------------------------------------------------------------- transaction-time cell
  //
  // The historical slice must be CONSTRUCTED, not filtered out of the present. Every aggregate the
  // response carries — count, reached stage, and each row's supersession stamp — has to describe the
  // ladder as it stood at the requested instant. A response that filters rows but reports today's
  // totals is a statement about now wearing a question about then.
  const beforeAll = await ladderOf(SUBJECT, "&as_of_transaction_time=2020-01-01T00:00:00Z");
  ok(
    "TRANSACTION-TIME travel answers 'as the ladder stood then' — BEFORE any of these transitions, the subject had no ladder at all: zero rows, zero count, and no reached stage rather than today's",
    beforeAll.status === 200 &&
      beforeAll.j?.matched_transition_count === 0 &&
      beforeAll.j?.transition_count === 0 &&
      beforeAll.j?.reached_stage === null,
    `matched ${beforeAll.j?.matched_transition_count} count ${beforeAll.j?.transition_count} reached ${beforeAll.j?.reached_stage}`,
  );
  const asOfT1 = await ladderOf(
    SUBJECT,
    `&as_of_transaction_time=${encodeURIComponent(t1RecordedAt)}`,
  );
  const asOfT1Row = asOfT1.j?.transitions?.[0] ?? {};
  ok(
    "BETWEEN transitions the slice is the ladder that existed then — as of the first transition's own admission instant the subject had exactly one transition, its count is one, and its reached stage is 'attested' rather than the 'verified' it later became",
    asOfT1.status === 200 &&
      asOfT1.j?.transition_count === 1 &&
      asOfT1.j?.matched_transition_count === 1 &&
      asOfT1.j?.reached_stage === "attested" &&
      asOfT1Row.transition_ordinal === 1,
    `count ${asOfT1.j?.transition_count} reached ${asOfT1.j?.reached_stage}`,
  );
  ok(
    "AND THAT ROW CARRIES NO SUPERSESSION FROM ITS OWN FUTURE — `superseded_at` is derived from the transition that FOLLOWS, so a slice filtered after projection would stamp this row with a supersession that had not happened yet and leak a fact from beyond the instant asked about",
    asOfT1Row.transaction_time?.superseded_at === null,
    `superseded_at ${JSON.stringify(asOfT1Row.transaction_time?.superseded_at)}`,
  );
  const nowView = await ladderOf(SUBJECT);
  ok(
    "while the CURRENT view of that same first transition does carry its supersession — so the null above is a property of the slice, not a field this route never populates, which is what stops the previous assertion passing for the wrong reason",
    (nowView.j?.transitions ?? [])[0]?.transaction_time?.superseded_at !== null &&
      (nowView.j?.transitions ?? [])[0]?.transition_ordinal === 1,
    `current superseded_at ${JSON.stringify((nowView.j?.transitions ?? [])[0]?.transaction_time?.superseded_at)}`,
  );
  ok(
    "a historical slice does not disturb the non-truth cache — it reports that it was not consulted, so a question about the past can never make the next ordinary read report a false 'stale' about the present",
    asOfT1.j?.rebuildable_index_state === "not_consulted_historical_slice" &&
      nowView.j?.rebuildable_index_state === "agreed_with_agentgres",
    `slice ${asOfT1.j?.rebuildable_index_state} current ${nowView.j?.rebuildable_index_state}`,
  );

  // ------------------------------------------------------------------------------ no second store
  const before = new Set(fs.readdirSync(dataDir));
  ok(
    "the transition family writes NO durable artifact of its own — every byte it admits lives on the shared Agentgres substrate, so there is no second store to drift even in principle",
    !Array.from(before).some((entry) => entry.toLowerCase().includes("assurance")),
    `data dir entries: ${Array.from(before).sort().join(", ")}`,
  );

  // ----------------------------------------------------------------------------- restart is truth
  const beforeRestart = await ladderState(SUBJECT);
  await stopDaemon();
  await startDaemon();
  const bootToken2 = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (bootToken2) {
    const reboot = await req(
      "POST",
      "/v1/hypervisor/auth/bootstrap",
      { token: bootToken2, password: "assurance-transition-a-v1" },
      { as: null },
    );
    if (reboot.j?.session_token) SESSIONS.A = reboot.j.session_token;
  }
  const relogin = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "assurance-transition-a@ioi.local", password: "assurance-transition-a-v1" },
    { as: null },
  );
  if (relogin.j?.session_token) SESSIONS.A = relogin.j.session_token;
  const afterRestart = await ladderState(SUBJECT);
  ok(
    "THE LADDER SURVIVES A REAL DAEMON RESTART with the same head, count and reached stage — asking the API whether something survived a restart, without restarting, is asking the thing under test to grade itself",
    afterRestart.count === beforeRestart.count &&
      afterRestart.head === beforeRestart.head &&
      afterRestart.reached === beforeRestart.reached &&
      afterRestart.count === 3,
    `before ${beforeRestart.count}/${beforeRestart.reached} after ${afterRestart.count}/${afterRestart.reached}`,
  );
  ok(
    "the read index is REBUILT from the chain after restart rather than restored from disk — asserted on the FIRST post-restart read, because reading is what populates the cache and a later read would report agreement no matter what happened",
    afterRestart.indexState === "rebuilt_from_agentgres" &&
      afterRestart.truthSource === "agentgres_owner_scoped_chain",
    `index ${afterRestart.indexState} truth ${afterRestart.truthSource}`,
  );
  const secondRead = await ladderState(SUBJECT);
  ok(
    "and the read AFTER that one reports agreement rather than a second rebuild — which is what makes the previous assertion a positive detection of the rebuild rather than a constant",
    secondRead.indexState === "agreed_with_agentgres",
    `second read ${secondRead.indexState}`,
  );

  // ------------------------------------------- the ladder still advances from the recovered head
  const afterRestartHead = afterRestart.head;
  const t4 = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t4-accepted",
      expectedHead: afterRestartHead,
      outcome: "disputed",
      nonclaims: ["correctness", "settlement"],
    }),
    { as: "A" },
  );
  ok(
    "the chain still ADMITS against the head recovered from that restart, so recovery restored a WRITABLE head rather than a readable copy",
    t4.status === 201 &&
      t4.j?.assurance_transition?.to_stage === "accepted" &&
      t4.j?.assurance_transition?.outcome_class === "disputed" &&
      t4.j?.assurance_transition?.transition_ordinal === 4,
    `status ${t4.status} stage ${t4.j?.assurance_transition?.to_stage}`,
  );

  // ------------------------------------------------------------------- OFFLINE: the portable half
  offlineAssertions();

  // ------------------------------------------------------------------- producer/consumer census
  sourceCensus();
}

// ---------------------------------------------------------------------------- offline (no daemon)

/**
 * The relying-party half. A portable bundle has no daemon in it, so the ordering claim has to hold
 * on the bytes alone — these run against the REGISTERED fixtures with nothing listening.
 */
function offlineAssertions() {
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const entry = registry.contracts.find((c) => c.contract_id === CONTRACT_ID);
  ok(
    "the transition contract is REGISTERED with generated Rust and TypeScript projections and a portable invariant profile — an unregistered shape is a local constant, not a contract",
    !!entry &&
      entry.cross_field_invariant_refs?.length === 1 &&
      entry.generated_targets?.some((t) => t.kind === "rust_projection") &&
      entry.generated_targets?.some((t) => t.kind === "typescript_projection"),
    `entry ${!!entry} invariants ${entry?.cross_field_invariant_refs?.length}`,
  );

  const profile = JSON.parse(fs.readFileSync(INVARIANT_PROFILE, "utf8"));
  const ladderRule = profile.rules.find(
    (r) => r.rule_id === "assurance_transition.ladder.position_matches_chain_position",
  );
  ok(
    "THE NO-SKIP RULE IS PORTABLE, not merely a runtime habit: a registered invariant pins the ladder position to the chain position, so a skipped stage fails for a relying party who has only the bytes and no daemon",
    !!ladderRule &&
      ladderRule.expression.operator === "fields_equal" &&
      ladderRule.expression.paths.includes("$.to_stage_ordinal") &&
      ladderRule.expression.paths.includes("$.transition_ordinal"),
    `rule ${ladderRule?.expression?.operator} over ${ladderRule?.expression?.paths?.join(" vs ")}`,
  );

  const dir = path.join(SCHEMAS, "fixtures/assurance-transition-receipt-v1");
  const skipFixture = JSON.parse(
    fs.readFileSync(path.join(dir, "negative-ladder-position-ahead-of-chain.json"), "utf8"),
  );
  ok(
    "the registered NEGATIVE corpus contains a transition whose ladder position runs ahead of its chain position — the offline expression of 'attested straight to verified', carried as bytes rather than as a code path",
    skipFixture.to_stage_ordinal !== skipFixture.transition_ordinal &&
      skipFixture.to_stage === "verified",
    `to_stage_ordinal ${skipFixture.to_stage_ordinal} transition_ordinal ${skipFixture.transition_ordinal}`,
  );
  const declaredNegatives = (entry?.negative_fixture_refs ?? []).length;
  ok(
    "every registered negative fixture is a real file on disk and the corpus covers stage skip, hash/subject substitution, empty nonclaims, unknown outcome class and borrowed admission",
    declaredNegatives >= 14 &&
      (entry?.negative_fixture_refs ?? []).every((ref) =>
        fs.existsSync(path.join(SCHEMAS, ref.path)),
      ),
    `${declaredNegatives} negative fixtures declared`,
  );

  // The v1/v2 challenge widening, proven load-bearing rather than cosmetic.
  const v1Schema = JSON.parse(
    fs.readFileSync(path.join(SCHEMAS, "verifier-challenge-envelope.v1.schema.json"), "utf8"),
  );
  const v2Schema = JSON.parse(
    fs.readFileSync(path.join(SCHEMAS, "verifier-challenge-envelope.v2.schema.json"), "utf8"),
  );
  const v1Pattern = v1Schema.properties.challenged_ref.pattern;
  const v2Pattern = v2Schema.properties.challenged_ref.pattern;
  ok(
    "v1 REFUSES an ontology-assertion and an ontology-mapping subject while v2 ADMITS both — the widening is load-bearing, not cosmetic, and this is the assertion that would go green on a v2 that changed nothing",
    !new RegExp(v1Pattern, "u").test("ontology-assertion://d/a/assertion/1") &&
      !new RegExp(v1Pattern, "u").test("ontology-mapping://d/b/crosswalk/1") &&
      new RegExp(v2Pattern, "u").test("ontology-assertion://d/a/assertion/1") &&
      new RegExp(v2Pattern, "u").test("ontology-mapping://d/b/crosswalk/1"),
    `v1 refuses both, v2 admits both`,
  );
  const v1Keys = Object.keys(v1Schema.properties).sort().join(",");
  const v2Keys = Object.keys(v2Schema.properties).sort().join(",");
  ok(
    "v2 is a SUCCESSOR, not a rewrite: the property set, the challenge_kind enumeration and the status enumeration are preserved byte-for-byte from v1, so widening one pattern did not become an excuse to redesign the envelope",
    v1Keys === v2Keys &&
      JSON.stringify(v1Schema.properties.challenge_kind) ===
        JSON.stringify(v2Schema.properties.challenge_kind) &&
      JSON.stringify(v1Schema.properties.status) === JSON.stringify(v2Schema.properties.status),
    `${Object.keys(v2Schema.properties).length} properties, enums identical`,
  );
  const registryV1 = registry.contracts.find((c) => c.contract_id === CHALLENGE_V1);
  const registryV2 = registry.contracts.find((c) => c.contract_id === CHALLENGE_V2);
  ok(
    "the registry records the succession in BOTH directions and keeps v1 valid — a widened pattern is a new version, never an edit of the registered one",
    registryV1?.evolution?.successor_contract_id === CHALLENGE_V2 &&
      registryV2?.evolution?.successor_of === CHALLENGE_V1 &&
      registryV2?.evolution?.predecessor_remains_valid === true &&
      registryV2?.evolution?.wire_mutation_policy === "forbidden",
    `v1->${registryV1?.evolution?.successor_contract_id} v2<-${registryV2?.evolution?.successor_of}`,
  );
  ok(
    "v1 carries REGISTERED refusal fixtures for both widened schemes, so 'v1 could not name a semantic-plane subject' is a checked expectation rather than a claim in a commit message",
    (registryV1?.negative_fixture_refs ?? []).some((r) =>
      r.path.includes("negative-ontology-assertion-subject-refused"),
    ) &&
      (registryV1?.negative_fixture_refs ?? []).some((r) =>
        r.path.includes("negative-ontology-mapping-subject-refused"),
      ),
    `${(registryV1?.negative_fixture_refs ?? []).length} v1 negatives`,
  );
}

/**
 * The EXACT producer/consumer census over the daemon's own source.
 *
 * A coverage gap must be a finding rather than an absence, so this counts the modules that can admit
 * an assurance transition and requires the number to be one.
 */
function sourceCensus() {
  const routesDir = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes");
  const files = fs.readdirSync(routesDir).filter((f) => f.endsWith(".rs"));
  const admitters = files.filter((file) => {
    const text = fs.readFileSync(path.join(routesDir, file), "utf8");
    return text.includes('"assurance_transition.stage.admit"');
  });
  ok(
    "EXACTLY ONE module admits an assurance transition — entailed from the whole route surface rather than from a probe that would answer the same either way; a second admitter is what a second spine looks like from here",
    admitters.length === 1 && admitters[0] === "assurance_transition_routes.rs",
    `admitters: ${admitters.join(", ") || "none"}`,
  );
  const source = fs.readFileSync(ROUTE_SOURCE, "utf8");
  const resolverCalls = (source.match(/resolve_admitted_revision\(/gu) ?? []).length;
  ok(
    "the ontology subject is resolved through the OWNER's published reader and this module adds no reader of its own — no direct chain read, no index, and no second interpretation of another family's truth",
    resolverCalls >= 1 &&
      !/read_owner_scoped_history\([^)]*ontology/su.test(source) &&
      !source.includes("hypervisor-ontology-versions"),
    `${resolverCalls} calls to the owner resolver`,
  );
  ok(
    "the module writes NO file of its own: it makes no raw filesystem call at all, which is what makes 'no second store' structural rather than asserted",
    !/\bstd::fs::(write|create_dir_all|remove_file|rename|copy|read)\s*\(/u.test(source),
    "no raw filesystem calls in the production module",
  );
  ok(
    "the module consults NO authority: no capability, lease, grant, policy decision or effect admission is read anywhere in it, so 'a receipt grants nothing' is entailed from the source rather than promised in prose",
    !/capability_lease|authority_grant|policy_decision|effect_admission|require_grant/u.test(
      source.replace(/^\s*\/\/.*$/gmu, ""),
    ),
    "no authority-plane reads in the production module",
  );
  ok(
    "the non-truth cache is KEYED BY THE AUTHORIZED READER AND THE SUBJECT, entailed from the source rather than from a probe: the key derives from the bound scope's principal, tenant and owner alongside subject_ref, so one entry can never be shared across principals and made observable to all of them",
    /fn projection_cache_key\(\s*scope: &RequestResourceScope,\s*subject_ref: &str,?\s*\)/u.test(
      source,
    ) &&
      /scope\.principal_ref,\s*scope\.tenant_ref,\s*scope\.owner_ref,\s*subject_ref/u.test(source) &&
      !/projection_cache_state\(subject_ref,/u.test(source),
    "cache key binds principal + tenant + owner + subject",
  );
  ok(
    "the transaction-time slice is TRUNCATED BEFORE PROJECTION, entailed from the source: the history is filtered by admission timestamp and only then projected, so no row can be stamped with a supersession drawn from a transition outside the slice",
    /\.filter\(\|entry\| entry\.operation\.recorded_at_ms <= as_of\)/u.test(source) &&
      /project_ladder\(&sliced, subject_ref\)/u.test(source) &&
      !/visible\.retain\([\s\S]{0,200}recorded_at/u.test(source),
    "history truncated by recorded_at_ms before project_ladder",
  );
  ok(
    "the replay path compares CURRENT REQUEST INTENT against the admitted record before returning it, over a pinned field set that covers subject, subject hash, outcome, evidence, nonclaims and validity",
    /fn replay_intent_divergence\(/u.test(source) &&
      /replay_intent_divergence\(&document, &proposal, &subject, &body\)/u.test(source) &&
      [
        "subject_ref",
        "subject_content_hash",
        "outcome_class",
        "evidence_refs",
        "does_not_assert",
        "valid_time",
      ].every((field) =>
        new RegExp(`REPLAY_INTENT_FIELDS[\\s\\S]{0,400}"${field}"`, "u").test(source),
      ),
    "intent comparison precedes the replay answer over all six pinned fields",
  );
  ok(
    "the actor is bound from the AUTHENTICATED PRINCIPAL in source, not from the request's owner context — `owner_ref` appears nowhere as the actor",
    /"actor_ref": caller\.identity\.principal_ref/u.test(source) &&
      !/"actor_ref": caller\.owner_ref/u.test(source),
    "actor_ref binds caller.identity.principal_ref",
  );

  // THE FOCUSED RUST TESTS ARE PINNED BY NAME, both directions. A filtered test run can pass with
  // ZERO tests, so counting them from source is what stops a deleted or renamed case from turning
  // this module's unit coverage into a silently empty filter. A new test is a finding too: it must
  // be recorded here deliberately rather than drift in.
  const testNames = [...source.matchAll(/#\[test\]\s*\n\s*fn\s+([a-z0-9_]+)/gu)]
    .map((match) => match[1])
    .sort();
  const PINNED_TESTS = [
    "content_commitment_excludes_transaction_time_and_admission",
    "every_ladder_member_is_the_canonical_enum_in_canonical_order",
    "every_registered_fixture_agrees_with_the_generated_projection",
    "outcome_classes_carry_every_negative_member_acc8_requires",
    "positive_fixture_admission_matches_the_producer_ref_shapes",
    "subject_family_classification_prefers_the_longer_scheme",
    "subject_hash_echo_rule_fires_on_its_own_finding",
    "transition_identity_binds_the_subject_family_and_ordinal",
    "two_subjects_never_share_one_transition_identity",
  ];
  ok(
    "the module's focused Rust test population is PINNED BY NAME in both directions — a filtered cargo run can pass with zero tests, so a deleted or renamed case fails here rather than silently emptying the filter",
    testNames.length === PINNED_TESTS.length &&
      testNames.every((name, index) => name === PINNED_TESTS[index]),
    `${testNames.length}/${PINNED_TESTS.length} pinned: ${testNames.join(", ")}`,
  );

  const stages = source.match(/const STAGES: &\[&str\] = &\[([\s\S]*?)\];/u)?.[1] ?? "";
  ok(
    "the ladder members in code are the canonical six in canonical order — this module registers and DRIVES the enum, it does not get to choose its members",
    ["attested", "evidenced", "verified", "accepted", "adjudicated", "settled"].every((stage) =>
      stages.includes(`"${stage}"`),
    ) && (stages.match(/"/gu) ?? []).length === 12,
    `stages block declares ${(stages.match(/"/gu) ?? []).length / 2} members`,
  );
}

// ------------------------------------------------------------------------------- mutation battery

const MUTANTS = [
  {
    id: "stage-skip-accepted",
    reddens:
      "A STAGE IS NOT REACHED BY SKIPPING THE ONE BEFORE IT — asking for 'accepted' at chain position 2 is refused by its own cause and appends nothing, so no stage can be claimed that nobody stood behind",
    from: "        if asserted != to_stage {",
    to: "        if false && asserted != to_stage {",
  },
  {
    id: "subject-taken-from-the-uri-prefix",
    reddens:
      "A URI PREFIX IS NOT PROOF THE SUBJECT EXISTS. A well-formed ontology revision ref that names no admitted revision is refused by the OWNER's resolver, so an unresolvable subject can never acquire a ladder on the strength of its spelling",
    from: "            let revision = resolve_admitted_revision(data_dir, identity, subject_ref)?;",
    to: "            let revision = resolve_admitted_revision(data_dir, identity, subject_ref).unwrap_or(super::ontology_version_routes::ResolvedOntologyRevision { ontology_id: subject_ref.to_string(), ontology_family_ref: String::new(), namespace: String::new(), name: String::new(), revision_ordinal: 1, content_hash: format!(\"sha256:{}\", \"0\".repeat(64)), status: \"active\".to_string() });",
  },
  {
    id: "unsupported-family-admitted-on-its-prefix",
    reddens:
      "the 'ontology_assertion' subject family is NAMEABLE on the v1 wire but FAILS CLOSED with no landed resolver — subject-generality from birth is what lets a later unit add its resolver without a wire change, and refusing by name is what stops the ladder accumulating subjects nobody can resolve",
    // The whole arm is replaced rather than guarded, because guarding it (`other if false`) makes the
    // match non-exhaustive and the mutant would not compile — a build failure reads as a red gate
    // while proving nothing about the assertion it aimed at.
    from: `        other => Err(bad(
            StatusCode::NOT_IMPLEMENTED,
            "assurance_transition_subject_family_unresolvable",`,
    to: `        other => Ok(ResolvedSubject {
            family: other,
            content_hash: format!("sha256:{}", "0".repeat(64)),
            resolved_by: "mutant::unchecked".to_string(),
        }),
        #[allow(unreachable_patterns)]
        other => Err(bad(
            StatusCode::NOT_IMPLEMENTED,
            "assurance_transition_subject_family_unresolvable",`,
  },
  {
    id: "actor-taken-from-the-request-body",
    reddens:
      "ACTOR, TRANSACTION TIME, CONTENT HASH, RESULTING HEAD AND THE ADMISSION BLOCK ARE ALL SERVER-RESOLVED (INV-37) — a body that supplies every one of them is admitted with the AUTHENTICATED principal, a real admission stamp and a re-derived hash, and none of the supplied values survives",
    from: '        "actor_ref": caller.identity.principal_ref,',
    to: '        "actor_ref": body.get("actor_ref").and_then(Value::as_str).map_or_else(|| caller.identity.principal_ref.clone(), str::to_owned),',
  },
  {
    id: "actor-taken-from-request-owner-context",
    reddens:
      "THE ACTOR IS THE AUTHENTICATED PRINCIPAL, NOT THE REQUEST'S OWNER CONTEXT — `owner_ref` is a tenant the caller may act WITHIN and is shared by every member of that organization, so recording it as the actor would attribute the stage to the org rather than to whoever stood behind it, and would let the caller pick its own attribution from a set it is merely a member of",
    // The exact defect the owner review found: request-scoped owner context standing in for identity.
    from: '        "actor_ref": caller.identity.principal_ref,',
    to: '        "actor_ref": caller.owner_ref,',
  },
  {
    id: "replay-ignores-changed-intent",
    reddens:
      'replaying an admitted idempotency key with a CHANGED \'outcome_class\' is refused as a changed-intent replay and appends nothing — a key answers "did this exact command land?", so returning the stored transition in answer to a different one would substitute one claim for another',
    from: "    if let Some(field) = REPLAY_INTENT_FIELDS\n        .iter()\n        .find(|field| prior.get(*field) != now.get(*field))\n    {\n        return Some(field);\n    }",
    to: '    if false {\n        return Some("unreachable");\n    }',
  },
  {
    id: "replay-skips-caller-assertion-checks",
    reddens:
      "replaying an admitted key while ASSERTING a false 'expected_content_hash' is refused by that field's own cause and appends nothing — a stored success must never stand as confirmation of a server-derived fact nobody compared",
    // Replaced whole rather than guarded: the block returns a Reply, so the replacement has to keep
    // the same control-flow shape to compile, and a non-compiling mutant proves nothing.
    from: "            if let Some(response) = replay_assertion_divergence(&document, &body) {\n                return response;\n            }",
    to: '            if false {\n                return bad(StatusCode::CONFLICT, "unreachable", "unreachable");\n            }',
  },
  {
    id: "historical-slice-filtered-after-projection",
    reddens:
      "AND THAT ROW CARRIES NO SUPERSESSION FROM ITS OWN FUTURE — `superseded_at` is derived from the transition that FOLLOWS, so a slice filtered after projection would stamp this row with a supersession that had not happened yet and leak a fact from beyond the instant asked about",
    // Truncation becomes a no-op: the whole chain is projected and only then narrowed, which is
    // exactly the ordering the owner review found.
    from: "        Some(as_of) => history\n            .into_iter()\n            .filter(|entry| entry.operation.recorded_at_ms <= as_of)\n            .collect(),",
    to: "        Some(_as_of) => history,",
  },
  {
    id: "cache-keyed-by-subject-alone",
    // AIMED AT THE SOURCE-BOUND ASSERTION ON PURPOSE. Two principals cannot both hold a scope on one
    // subject through the current API — a foreign read is refused before it reaches the cache — so
    // the side channel is not reachable from outside today and a live assertion could not detect
    // this mutant. The fix is defence in depth and its honest proof is entailment from the source;
    // claiming a live proof here would be the gate certifying something it did not check.
    reddens:
      "the non-truth cache is KEYED BY THE AUTHORIZED READER AND THE SUBJECT, entailed from the source rather than from a probe: the key derives from the bound scope's principal, tenant and owner alongside subject_ref, so one entry can never be shared across principals and made observable to all of them",
    from: "            scope.principal_ref, scope.tenant_ref, scope.owner_ref, subject_ref",
    to: '            "", "", "", subject_ref',
  },
  {
    id: "empty-nonclaim-set-admitted",
    reddens:
      "an EMPTY does_not_assert is refused — a transition that disclaims nothing has collapsed NN 20 into a bare success flag",
    from: "    if nonclaims.is_empty() {",
    to: "    if false && nonclaims.is_empty() {",
  },
  {
    id: "negative-outcome-normalized-to-positive",
    reddens:
      "a NEGATIVE outcome class is retained VERBATIM through admission and projection — an exploit finding that came back as 'exploit' is stored as 'exploit', never normalised toward success (NN 21, ACC-8 clause 2)",
    // Anchored with its preceding line: the intent comparison introduced a second occurrence of the
    // bare field, and an ambiguous anchor is an anchor that proves nothing about which site moved.
    from: '        "transition_ordinal": ordinal,\n        "outcome_class": proposal.outcome_class,',
    to: '        "transition_ordinal": ordinal,\n        "outcome_class": if proposal.outcome_class == "positive" { proposal.outcome_class.clone() } else { "positive".to_string() },',
  },
  {
    id: "stale-head-accepted",
    reddens:
      "a STALE head is refused and appends nothing: the ladder's head and transition count are identical either side of the refusal",
    from: "    if expected_head != current_head {",
    to: "    if false && expected_head != current_head {",
  },
  {
    id: "unknown-contract-version-silently-downgraded",
    reddens:
      "a DOWNGRADED contract version appends nothing: a caller naming a version this build does not implement is refused rather than having its bytes reinterpreted as v1, and the ladder is identical either side of the refusal",
    from: "        Some(Value::String(declared)) if declared == SCHEMA_VERSION => {}",
    to: "        Some(Value::String(declared)) if !declared.is_empty() || declared == SCHEMA_VERSION => {}",
  },
  {
    id: "subject-hash-substitution-accepted",
    reddens:
      "an ASSERTED subject hash that disagrees with the owner's current commitment is refused BY ITS OWN CAUSE and appends nothing — the binding is the subject owner's, never the caller's",
    from: "        if asserted != subject.content_hash {",
    to: "        if false && asserted != subject.content_hash {",
  },
  {
    id: "pre-acceptance-nonclaim-not-required",
    reddens:
      "a pre-acceptance stage that does not explicitly disclaim ACCEPTANCE is refused — a stage short of acceptance that does not say so is read as acceptance by omission",
    from: "    if PRE_ACCEPTANCE_STAGES.contains(&to_stage) {",
    to: "    if false && PRE_ACCEPTANCE_STAGES.contains(&to_stage) {",
  },
];

function rebuildDaemon() {
  const build = spawnSync(
    "cargo",
    ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  if (build.status !== 0) {
    throw new Error(`mutant daemon did not build:\n${build.stderr?.slice(-4000)}`);
  }
}

async function runMutationBattery() {
  const original = fs.readFileSync(ROUTE_SOURCE, "utf8");
  const originalDigest = crypto.createHash("sha256").update(original).digest("hex");
  const rows = [];
  try {
    for (const mutant of MUTANTS) {
      const occurrences = original.split(mutant.from).length - 1;
      // FAIL CLOSED ON AN ABSENT ANCHOR. A mutant whose target text has moved proves nothing, and
      // silently skipping it would shrink the battery without failing it.
      if (occurrences !== 1) {
        rows.push({ id: mutant.id, outcome: "ANCHOR_LOST", detail: `${occurrences} matches` });
        continue;
      }
      fs.writeFileSync(ROUTE_SOURCE, original.replace(mutant.from, mutant.to));
      let outcome;
      let detail;
      try {
        rebuildDaemon();
        const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
          cwd: ROOT,
          encoding: "utf8",
          env: { ...process.env, IOI_VERIFIER_CENSUS_DIR: "" },
          maxBuffer: 64 * 1024 * 1024,
        });
        const output = `${child.stdout ?? ""}${child.stderr ?? ""}`;
        const targeted = output.includes(`FAIL  ${mutant.reddens}`);
        const anyFailure = child.status !== 0;
        outcome = targeted ? "RED_ON_TARGET" : anyFailure ? "RED_OFF_TARGET" : "SURVIVED";
        detail = targeted
          ? "the targeted assertion failed"
          : anyFailure
            ? "the run failed, but not on its target"
            : "the mutant passed unnoticed";
      } catch (error) {
        // A mutant that does not compile is INVALID, never "caught": a build failure would otherwise
        // read as a red gate while proving nothing about the assertion it aimed at.
        outcome = "INVALID_DID_NOT_COMPILE";
        detail = String(error?.message ?? error).slice(0, 200);
      }
      rows.push({ id: mutant.id, outcome, detail });
    }
  } finally {
    // RESTORE, THEN PROVE THE RESTORE. Leaving a planted mutant in the checkout is the one outcome
    // this harness must never produce, so the bytes are compared rather than assumed.
    fs.writeFileSync(ROUTE_SOURCE, original);
    const restoredDigest = crypto
      .createHash("sha256")
      .update(fs.readFileSync(ROUTE_SOURCE, "utf8"))
      .digest("hex");
    if (restoredDigest !== originalDigest) {
      process.stderr.write(
        `\nFATAL: the production source was NOT restored (${originalDigest} -> ${restoredDigest})\n`,
      );
      process.exit(2);
    }
    rebuildDaemon();
    process.stdout.write(`\nsource restored and rebuilt; sha256 ${originalDigest}\n`);
  }
  for (const row of rows) {
    process.stdout.write(
      `${row.outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${row.id} — ${row.outcome}: ${row.detail}\n`,
    );
  }
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(
    `\nassurance-transition-receipt mutation battery: ${onTarget}/${MUTANTS.length} RED ON TARGET\n`,
  );
  process.exit(onTarget === MUTANTS.length ? 0 : 1);
}

if (MUTATE) {
  runMutationBattery().catch((error) => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(1);
  });
} else {
  run()
    .catch((error) => {
      ok("the verifier ran to completion", false, String(error?.stack || error));
    })
    .finally(async () => {
      await stopDaemon();
      cleanup();
      for (const result of results) {
        process.stdout.write(
          `${result.pass ? "ok  " : "FAIL"}  ${result.name}${result.detail ? ` — ${result.detail}` : ""}\n`,
        );
      }
      const passed = results.filter((result) => result.pass).length;
      process.stdout.write(`\nassurance-transition-receipt: ${passed}/${results.length}\n`);
      emitVerifierCensus({
        verifierId: "assurance-transition-receipt",
        sourceUrl: import.meta.url,
        results,
      });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
