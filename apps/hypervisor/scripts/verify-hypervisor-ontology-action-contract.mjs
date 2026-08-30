#!/usr/bin/env node
// M05.4 — `OntologyActionContract`: the binding that compiles meaning and grants nothing, driven end
// to end against a live daemon and its durable Agentgres chain.
//
// WHAT THIS GATE IS FOR. Typed action definitions and tool contracts existed separately; this unit
// binds them, and the whole value of the binding is that it is EXACT on both sides and confers
// nothing on either. So the claims here are: the ontology side resolves an exact admitted revision
// AND an action that revision actually declares; the tool side resolves an exact released
// RuntimeToolContract revision by revision-ref-and-hash together; the typed IO contract is pinned to
// the tool's own schema BYTES; and the compiled contract still names every gate the action must pass
// while minting, widening, consulting and redeeming nothing.
//
// THE ONE DEFECT THE REGISTERED CORPUS STRUCTURALLY CANNOT CATCH. Every negative fixture beside this
// gate is decidable from bytes alone. "Is this term a member of THAT admitted revision's
// action_types" is not — it is a fact about the ontology owner's chain. A well-formed, correctly
// namespaced, canonical term the revision never declared passes every schema and every portable
// invariant. It is refused HERE, live, and the mutation battery plants its removal as an explicit
// target. `fixtures/ontology-action-contract/request-unknown-same-family-action-term.json` is the
// tracked body that drives it.
//
// HOW IT AVOIDS GRADING ITSELF:
//
//   * THE CONTENT HASH IS RECOMPUTED FROM CANON, not from the response. The material field list is
//     read out of the REGISTERED invariant profile and the digest is taken here in JavaScript.
//   * THE BOUND TOOL IS A REAL SEEDED REVISION, discovered from the daemon's own tool projection
//     rather than invented, so "the owner resolved it" is not a fixture agreeing with itself.
//   * DURABLE TRUTH IS READ ACROSS A RESTART.
//   * REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the lineage afterwards and
//     requires head and revision count to be exactly what they were.
//   * A GREEN RUN CERTIFIES NOTHING UNTIL THE HARNESS PROVES IT RED. `--mutate` plants named defects
//     in this module's own source, rebuilds, re-runs, and requires each to redden the exact
//     assertion it targets; the source is restored and byte-verified before exit.
//
// NONCLAIMS. This gate proves the action-contract binding only. It makes no claim that the compiled
// action can be invoked, that any gate it names is implemented, that the bound tool will succeed, or
// that the declared risk/recovery semantics are correct for the domain. It asserts that no authority
// plane is consulted here — which is not the same as proving those planes elsewhere.

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
  "crates/node/src/bin/hypervisor_daemon_routes/ontology_action_contract_routes.rs",
);
const OWNER_SEAM_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/ontology_version_routes.rs",
);
const INVARIANT_PROFILE = path.join(
  ROOT,
  "docs/architecture/_meta/schemas/invariants/ontology-action-contract.v1.invariants.json",
);
const REGISTRY = path.join(
  ROOT,
  "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json",
);
const UNKNOWN_TERM_FIXTURE = path.join(
  APP,
  "fixtures/ontology-action-contract/request-unknown-same-family-action-term.json",
);
const CONTRACT_ID = "schema://ioi/foundations/objects/ontology-action-contract/v1";
const MUTATE = process.argv.includes("--mutate");
/// Plant the first mutant, start a real rebuild, then interrupt this process — proving the restore
/// path before the real battery is trusted with the tree.
const INTERRUPT_SELF_TEST = process.argv.includes("--interrupt-self-test");
/// Run a named subset, appending to the ledger. One full battery costs roughly three quarters of an
/// hour, which is longer than a single attached invocation can hold; running it as detached work is
/// how the previous two attempts were killed mid-flight and left mutated source behind. So the
/// battery is CHUNKABLE and its outcomes are DURABLE: each chunk plants, runs and restores
/// completely, records its rows, and `--summarize` adjudicates the union against the declared mutant
/// set. A chunk that never ran is a missing row, not a silent pass.
const ONLY = (process.argv.find((argument) => argument.startsWith("--only=")) ?? "")
  .slice("--only=".length)
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);
const SUMMARIZE = process.argv.includes("--summarize");

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

// ------------------------------------------------------------------- canonical JSON + content hash

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

/** The content commitment, rebuilt from the REGISTERED invariant profile rather than from the daemon. */
function registeredContentCommitment(document) {
  const profile = JSON.parse(fs.readFileSync(INVARIANT_PROFILE, "utf8"));
  const rule = profile.rules.find(
    (candidate) =>
      candidate.rule_id ===
      "ontology_action_contract.content_hash.commits_both_bindings_effect_semantics_and_valid_time",
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

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ontology-action-"));
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
      IOI_WALLET_SECRET_PASS: "ioi-ontology-action-verifier",
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
const OAC = "/v1/hypervisor/ontology-action-contracts";
const NS = "acme-clinic";
const NAME = "patient-intake";
const SLUG = "schedule-followup";
const ACTION = `ontology://${NS}/${NAME}/term/${SLUG}`;

const termsOf = (terms) =>
  terms.map((term) => ({ term_id: `ontology://${NS}/${NAME}/term/${term}`, label: term }));

/** A real M05.1 revision, admitted through M05.1's OWN route, declaring real action types. */
function ontologyProposal({ key, expectedHead = null, actions = [SLUG], entities = ["patient"] }) {
  const body = {
    owner_ref: "org://local",
    idempotency_key: key,
    namespace: NS,
    name: NAME,
    governing_scope_ref: `domain://${NS}/intake`,
    policy_hash: `sha256:${"1a".repeat(32)}`,
    entity_types: termsOf(entities),
    action_types: termsOf(actions),
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  };
  if (expectedHead !== null) {
    body.expected_head = expectedHead;
    body.compatibility = "breaking";
    body.term_mappings = [
      {
        from_term_id: `ontology://${NS}/${NAME}/term/patient`,
        to_term_id: `ontology://${NS}/${NAME}/term/patient`,
        disposition: "retained",
      },
    ];
  }
  return body;
}

let TOOL = null;
const toolSchemaDigest = (schema) =>
  `sha256:${crypto.createHash("sha256").update(canonicalJson(schema)).digest("hex")}`;

function contractProposal(overrides = {}) {
  return {
    owner_ref: "org://local",
    namespace: NS,
    name: NAME,
    action_slug: SLUG,
    governing_scope_ref: `domain://${NS}/intake`,
    policy_hash: `sha256:${"2b".repeat(32)}`,
    action_type_ref: ACTION,
    runtime_tool_contract_revision_ref: TOOL?.revision_ref,
    runtime_tool_contract_content_hash: TOOL?.content_hash,
    typed_input_schema_ref: `schema://runtime-tool-contract/input/${TOOL?.input_schema_hash}`,
    typed_output_schema_ref: `schema://runtime-tool-contract/output/${TOOL?.output_schema_hash}`,
    target_object_model_refs: [`object-model://${NS}/${NAME}/appointment`],
    precondition_refs: [`state://${NS}/${NAME}/appointment/unscheduled`],
    postcondition_and_invariant_refs: [`invariant://${NS}/${NAME}/one-open-followup`],
    expected_state_transition_ref: `transition://${NS}/${NAME}/appointment/unscheduled-to-scheduled`,
    risk_class: "external_message",
    effect_recovery_class: "reconciliation_required",
    idempotency_and_retry_profile_ref: `policy://${NS}/intake/idempotency/v1`,
    ambiguous_effect_and_reconciliation_profile_ref: `policy://${NS}/intake/reconciliation/v1`,
    compensation_profile_ref: `policy://${NS}/intake/compensation/v1`,
    preview_and_dry_run_profile_ref: null,
    approval_and_revocation_refs: [`approval-policy://${NS}/intake/outbound`],
    local_policy_and_authority_scope_refs: [`policy://${NS}/intake/outbound`, "scope:mail.send"],
    verifier_and_evidence_refs: [`verifier-path://${NS}/intake/scheduled`, `evidence://${NS}/intake/response`],
    physical_safety_profile_ref: null,
    receipt_obligations: [`receipt://${NS}/intake/action-admission`],
    does_not_assert: [
      "authority",
      "capability_grant",
      "lease",
      "policy_decision",
      "effect_admission",
      "invocation",
    ],
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
    ...overrides,
  };
}

const lineageOf = async (as = "A") =>
  req("GET", `${OAC}?namespace=${NS}&name=${NAME}&action_slug=${SLUG}`, null, { as });

/** Head + revision count, so a refusal can be counted BY EFFECT rather than by its status code. */
async function chainState() {
  const { j } = await lineageOf();
  const rows = j?.revisions ?? [];
  return {
    count: rows.length,
    head: rows.at(-1)?.admission?.admission_head ?? null,
  };
}

async function refusesWithoutTouchingTheChain(name, body, expectedCode) {
  const before = await chainState();
  const response = await req("POST", OAC, body);
  const after = await chainState();
  ok(
    name,
    response.status >= 400 &&
      code(response.j) === expectedCode &&
      after.count === before.count &&
      after.head === before.head,
    `status ${response.status} code ${code(response.j) || "(none)"} chain ${before.count}->${after.count}`,
  );
  return response;
}

const durableTopLevelEntries = () =>
  fs
    .readdirSync(dataDir, { withFileTypes: true })
    .map((entry) => entry.name)
    .sort();

// ------------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();

  // ---------------------------------------------------------------------------------- principals
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "ontology-action-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "ontology-action-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "ontology-action-b-v1",
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
      idempotency_key: "ontology-action-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "ontology-action-b@ioi.local", password: "ontology-action-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant",
    SESSIONS.A.length > 0 && SESSIONS.B.length > 0 && principalB.length > 0,
    `A ${SESSIONS.A.length > 0} B ${SESSIONS.B.length > 0}`,
  );

  // ------------------------------------------------------- a REAL ontology revision, M05.1's own route
  const genesisOntology = await req("POST", OV, ontologyProposal({ key: "oac-ontology-1" }));
  const ontologyHead = genesisOntology.j?.expected_head_for_successor ?? null;
  const ontologyRevision = genesisOntology.j?.ontology_version ?? {};
  ok(
    "PRECONDITION: a REAL ontology revision declaring a REAL action type is admitted through M05.1's own route in this same run — the binding is never made against a fixture that agrees with itself",
    genesisOntology.status === 201 &&
      ontologyRevision.ontology_id === `ontology://${NS}/${NAME}/revision/1` &&
      (ontologyRevision.action_types ?? []).some((term) => term.term_id === ACTION),
    `status ${genesisOntology.status} id ${ontologyRevision.ontology_id ?? "(none)"}`,
  );
  const ontologyContentHash = ontologyRevision.content_hash;

  // -------------------------------------------------- a REAL released tool revision, its owner's own
  // `/v1/tools` projects the seeded immutable registry as a bare array of admitted contracts.
  const tools = await req("GET", "/v1/tools", null, { as: "A" });
  const catalog = Array.isArray(tools.j) ? tools.j : [];
  const candidate = catalog.find(
    (entry) =>
      typeof entry?.revision_ref === "string" &&
      typeof entry?.content_hash === "string" &&
      entry.registry_status === "released",
  );
  TOOL = candidate
    ? {
        revision_ref: candidate.revision_ref,
        content_hash: candidate.content_hash,
        tool_id: candidate.tool_id,
        input_schema_hash: toolSchemaDigest(candidate.input_schema),
        output_schema_hash: toolSchemaDigest(candidate.output_schema),
      }
    : null;
  ok(
    "PRECONDITION: the bound RuntimeToolContract revision is a REAL released revision discovered from the daemon's own tool projection, not one this file invented",
    TOOL !== null && TOOL.revision_ref.includes("/revision/"),
    TOOL ? `${TOOL.revision_ref}` : `no released revision in a catalog of ${catalog.length}`,
  );

  // ------------------------------------------------------------------------------- the genesis binding
  const genesis = await req(
    "POST",
    OAC,
    contractProposal({
      idempotency_key: "oac-genesis",
      ontology_revision_ref: ontologyRevision.ontology_id,
    }),
  );
  const v1 = genesis.j?.ontology_action_contract ?? {};
  ok(
    "a compiled action contract is admitted as revision 1 of its own owner-qualified family",
    genesis.status === 201 &&
      v1.ontology_action_id === `ontology-action://${NS}/${NAME}/${SLUG}/revision/1` &&
      v1.action_family_ref === `ontology-action://${NS}/${NAME}/${SLUG}` &&
      v1.version === "v1" &&
      v1.status === "active",
    `status ${genesis.status} id ${v1.ontology_action_id ?? "(none)"} ${code(genesis.j)} ${genesis.j?.error?.message ?? ""}`,
  );
  ok(
    "it binds the EXACT admitted ontology revision and carries that owner's committed hash VERBATIM — the semantic side is resolved, never asserted",
    v1.ontology_revision_ref === ontologyRevision.ontology_id &&
      v1.ontology_content_hash === ontologyContentHash &&
      v1.ontology_resolved_by === "ontology_version_routes::resolve_admitted_action_type",
    `${v1.ontology_revision_ref ?? "(none)"} hash-matches-owner ${v1.ontology_content_hash === ontologyContentHash}`,
  );
  ok(
    "and it binds the EXACT released RuntimeToolContract revision AND hash together, through that owner's own exact resolver",
    v1.runtime_tool_contract_revision_ref === TOOL?.revision_ref &&
      v1.runtime_tool_contract_content_hash === TOOL?.content_hash &&
      v1.runtime_tool_resolved_by === "runtime_tool_contract_registry::resolve_exact" &&
      v1.bound_tool_id === TOOL?.tool_id,
    `${v1.runtime_tool_contract_revision_ref ?? "(none)"}`,
  );
  // Recomputed HERE from the tool owner's own projected schemas. Asserting only that the two hashes
  // differ would prove nothing about a tool whose input and output shapes are legitimately identical
  // — and several seeded native tools are exactly that — so the claim is checked the only way that
  // is true of every tool: by hashing that tool's declared bytes independently and comparing.
  ok(
    "the typed IO contract is pinned to the tool's own SCHEMA BYTES: both commitments are reproduced here by hashing the tool projection's own declared input and output schemas, so binding the tool ref alone could not leave the typed contract free to move underneath an admitted action",
    candidate !== undefined &&
      v1.bound_tool_input_schema_hash === toolSchemaDigest(candidate.input_schema) &&
      v1.bound_tool_output_schema_hash === toolSchemaDigest(candidate.output_schema) &&
      v1.typed_input_schema_ref === `schema://runtime-tool-contract/input/${v1.bound_tool_input_schema_hash}` &&
      v1.typed_output_schema_ref === `schema://runtime-tool-contract/output/${v1.bound_tool_output_schema_hash}`,
    `in ${(v1.bound_tool_input_schema_hash ?? "").slice(0, 22)} out ${(v1.bound_tool_output_schema_hash ?? "").slice(0, 22)}`,
  );
  ok(
    "the tool's declared risk/effect strings are carried VERBATIM under an explicit vocabulary label, and this record's own canonical assessment is a separate field — no legacy string is laundered into the canonical ladder",
    v1.bound_tool_class_vocabulary === "runtime_tool_declared_verbatim" &&
      typeof v1.bound_tool_risk_class === "string" &&
      v1.risk_class === "external_message",
    `bound ${v1.bound_tool_risk_class ?? "(none)"} / own ${v1.risk_class ?? "(none)"}`,
  );

  const commitment = registeredContentCommitment(v1);
  ok(
    "the served content hash is INDEPENDENTLY reproducible from the registered invariant profile's own material fields — the daemon does not get to define its own commitment",
    commitment.digest === v1.content_hash,
    `${commitment.fields.length} registered material fields; derived ${commitment.digest.slice(0, 24)} served ${(v1.content_hash ?? "").slice(0, 24)}`,
  );

  // ------------------------------------------------------------------------ ACC-6 clause 5, as a field
  ok(
    "ACC-6 CLAUSE 5 IS A FIELD, NOT A PARAGRAPH: the compiled contract names the exact six gates the action must still pass, and its declared count agrees with the ladder it carries",
    JSON.stringify(v1.required_gates) ===
      JSON.stringify([
        "capability",
        "policy",
        "authority",
        "daemon_admission",
        "evidence",
        "verification",
      ]) && v1.required_gate_count === 6,
    `${JSON.stringify(v1.required_gates)}`,
  );
  ok(
    "MEANING GRANTS NOTHING (NN 9): the record disclaims authority, capability grants, leases, policy decisions, effect admission and invocation explicitly, and the reply repeats both nonclaims",
    ["authority", "capability_grant", "lease", "policy_decision", "effect_admission", "invocation"].every(
      (token) => (v1.does_not_assert ?? []).includes(token),
    ) &&
      v1.authority_nonclaim === "ontology_action_contract_grants_no_authority" &&
      v1.invocation_nonclaim === "ontology_action_contract_does_not_invoke_or_dispatch" &&
      genesis.j?.authority_nonclaim === "ontology_action_contract_grants_no_authority" &&
      genesis.j?.invocation_nonclaim === "ontology_action_contract_does_not_invoke_or_dispatch",
    `${JSON.stringify(v1.does_not_assert)}`,
  );
  ok(
    "and the retired `action_term_membership` nonclaim is GONE: membership is checked now, so a record disclaiming it would understate a binding this path enforces",
    !(v1.does_not_assert ?? []).includes("action_term_membership"),
    "nonclaim set carries no membership disclaimer",
  );
  // Checked over the reply's KEY SET, not over a text blob. Scanning the serialized reply for the
  // word "grant" would be satisfied — and defeated — by this module's own nonclaim strings, which
  // contain "grants_no_authority" and "does_not_invoke_or_dispatch". A check about the absence of a
  // thing must not be answerable by prose asserting that absence.
  const replyKeys = Object.keys({ ...genesis.j, ontology_action_contract: undefined });
  ok(
    "the admission mints NO lease, grant, connection, credential or effect admission, and dispatches nothing: the reply's key set carries a receipt and an operation ref and no authority artifact of any kind",
    typeof genesis.j?.receipt_ref === "string" &&
      typeof genesis.j?.operation_ref === "string" &&
      !replyKeys.some((key) =>
        /lease|grant|credential|connection|invocation_result|dispatch|executed/iu.test(key),
      ),
    `keys: ${replyKeys.filter((key) => key !== "ontology_action_contract").join(", ")}`,
  );

  // ------------------------------------------ THE DEFECT THE OFFLINE CORPUS CANNOT CATCH
  const unknownTermFixture = JSON.parse(fs.readFileSync(UNKNOWN_TERM_FIXTURE, "utf8"));
  const unknownTermBody = {
    ...contractProposal({
      ...unknownTermFixture.request,
      ontology_revision_ref: ontologyRevision.ontology_id,
    }),
  };
  await refusesWithoutTouchingTheChain(
    "an UNKNOWN SAME-FAMILY action term is refused: a term that is well formed, correctly namespaced and canonical is still not an admitted action, and a contract is never compiled over meaning the bound revision never declared",
    unknownTermBody,
    "ontology_version_action_type_absent",
  );
  await refusesWithoutTouchingTheChain(
    "an entity term is not an action term — the revision declares 'patient', but not as an action, and resolving it as one is the same typed absence",
    contractProposal({
      idempotency_key: "oac-entity-as-action",
      ontology_revision_ref: ontologyRevision.ontology_id,
      action_type_ref: `ontology://${NS}/${NAME}/term/patient`,
    }),
    "ontology_version_action_type_absent",
  );
  await refusesWithoutTouchingTheChain(
    "a FOREIGN-FAMILY action term is refused as the category error it is — a contract never compiles one domain's action while binding another domain's meaning",
    contractProposal({
      idempotency_key: "oac-foreign-term",
      ontology_revision_ref: ontologyRevision.ontology_id,
      action_type_ref: `ontology://other-clinic/${NAME}/term/${SLUG}`,
    }),
    "ontology_version_action_type_foreign_family",
  );
  await refusesWithoutTouchingTheChain(
    "a MUTABLE-LATEST ontology binding is refused: a contract that named the family head would silently re-mean itself whenever the family advanced",
    contractProposal({
      idempotency_key: "oac-mutable-latest",
      ontology_revision_ref: `ontology://${NS}/${NAME}`,
      action_type_ref: ACTION,
    }),
    "ontology_version_identity_not_canonical",
  );
  await refusesWithoutTouchingTheChain(
    "a tool revision offered with a hash that does not identify it is refused — the tool binding is revision AND hash together, never a mutable family id",
    contractProposal({
      idempotency_key: "oac-tool-hash-mismatch",
      ontology_revision_ref: ontologyRevision.ontology_id,
      runtime_tool_contract_content_hash: `sha256:${"0".repeat(64)}`,
    }),
    "ontology_action_contract_tool_unresolved",
  );
  await refusesWithoutTouchingTheChain(
    "the OntologyActionContract family slug must name the EXACT resolved ontology action term — a local alias is not invented without an admitted mapping decision",
    contractProposal({
      idempotency_key: "oac-action-slug-substitution",
      ontology_revision_ref: ontologyRevision.ontology_id,
      action_slug: "cancel-followup",
    }),
    "ontology_action_contract_action_identity_substituted",
  );
  await refusesWithoutTouchingTheChain(
    "caller-authored typed schema names cannot float above the tool bytes — both refs are exact content-addressed projections of the bound RuntimeToolContract schemas",
    contractProposal({
      idempotency_key: "oac-typed-schema-substitution",
      ontology_revision_ref: ontologyRevision.ontology_id,
      typed_input_schema_ref: `schema://runtime-tool-contract/input/sha256:${"0".repeat(64)}`,
    }),
    "ontology_action_contract_typed_schema_binding_substituted",
  );
  await refusesWithoutTouchingTheChain(
    "an UNKNOWN CONTRACT VERSION is refused rather than downgraded — serving an unknown version as v1 is how a contract silently loses a field",
    contractProposal({
      idempotency_key: "oac-downgrade",
      ontology_revision_ref: ontologyRevision.ontology_id,
      schema_version: "ioi.ontology-action-contract.v0",
    }),
    "ontology_action_contract_schema_version_unsupported",
  );
  await refusesWithoutTouchingTheChain(
    "a contract that omits a mandatory nonclaim is refused: silence about what it does not confer is read as claiming it",
    contractProposal({
      idempotency_key: "oac-missing-nonclaim",
      ontology_revision_ref: ontologyRevision.ontology_id,
      does_not_assert: ["capability_grant", "lease", "policy_decision", "effect_admission", "invocation"],
    }),
    "ontology_action_contract_nonclaim_incomplete",
  );
  await refusesWithoutTouchingTheChain(
    "a PHYSICAL-ACTION contract with no bound safety profile is refused before admission, as well as offline by its registered invariant",
    contractProposal({
      idempotency_key: "oac-physical-no-safety",
      ontology_revision_ref: ontologyRevision.ontology_id,
      risk_class: "physical_action",
      physical_safety_profile_ref: null,
    }),
    "ontology_action_contract_physical_safety_profile_required",
  );

  // ------------------------------------------------------------------------------ replay and successor
  const replay = await req(
    "POST",
    OAC,
    contractProposal({
      idempotency_key: "oac-genesis",
      ontology_revision_ref: ontologyRevision.ontology_id,
    }),
  );
  const afterReplay = await chainState();
  ok(
    "the SAME key with the same bytes REPLAYS the original admitted fact rather than minting a second revision",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.ontology_action_contract?.content_hash === v1.content_hash &&
      afterReplay.count === 1,
    `status ${replay.status} replayed ${replay.j?.replayed} hash-match ${replay.j?.ontology_action_contract?.content_hash === v1.content_hash} revisions ${afterReplay.count}`,
  );
  await refusesWithoutTouchingTheChain(
    "the same key with a CHANGED INTENT is refused — an idempotency key replays one exact command and is never a way to receive a stored contract in answer to a different one",
    contractProposal({
      idempotency_key: "oac-genesis",
      ontology_revision_ref: ontologyRevision.ontology_id,
      risk_class: "funds",
    }),
    "ontology_action_contract_replay_intent_changed",
  );

  // EVERY caller-authored material input, not a remembered subset. The first cut of this module
  // compared twelve of twenty-eight, so each field below could be changed under an already-admitted
  // key and receive `200 replayed: true` for the ORIGINAL contract — a caller could compile one
  // meaning and then answer a different question with the first one's receipt. These four were all
  // in the omitted sixteen.
  for (const [field, changed] of [
    ["receipt_obligations", { receipt_obligations: [`receipt://${NS}/intake/effect-execution`] }],
    [
      "target_object_model_refs",
      { target_object_model_refs: [`object-model://${NS}/${NAME}/prescription`] },
    ],
    [
      "local_policy_and_authority_scope_refs",
      { local_policy_and_authority_scope_refs: [`policy://${NS}/intake/outbound`, "scope:funds.move"] },
    ],
    [
      "compensation_profile_ref",
      { compensation_profile_ref: `policy://${NS}/intake/compensation/v9` },
    ],
  ]) {
    await refusesWithoutTouchingTheChain(
      `changing '${field}' under the admitted key is a typed conflict and appends nothing — replay compares EVERY caller-authored material input, not a remembered subset of them`,
      contractProposal({
        idempotency_key: "oac-genesis",
        ontology_revision_ref: ontologyRevision.ontology_id,
        ...changed,
      }),
      "ontology_action_contract_replay_intent_changed",
    );
  }
  const fullRetry = await req(
    "POST",
    OAC,
    contractProposal({
      idempotency_key: "oac-genesis",
      ontology_revision_ref: ontologyRevision.ontology_id,
    }),
  );
  const afterFullRetry = await chainState();
  ok(
    "and the CORRECT FULL RETRY still replays after all of those refusals — a stricter comparison that broke ordinary idempotency would have replaced one defect with another",
    fullRetry.status === 200 &&
      fullRetry.j?.replayed === true &&
      fullRetry.j?.ontology_action_contract?.content_hash === v1.content_hash &&
      afterFullRetry.count === 1,
    `status ${fullRetry.status} replayed ${fullRetry.j?.replayed} hash-match ${fullRetry.j?.ontology_action_contract?.content_hash === v1.content_hash} revisions ${afterFullRetry.count}`,
  );

  // A REUSED KEY IS NOT A WAY TO HAVE A CLAIM GO UNEXAMINED. Each of these `expected_*` fields is
  // the caller asserting a server-derived fact. On the fresh-admission path each is checked where
  // its fact is derived; the replay path returns before most of those points, so before this was
  // closed a caller could reuse an admitted key, assert a false ordinal, predecessor or content
  // hash, and receive 200 with the stored contract and its assertion silently skipped.
  for (const [field, assertion, expectedCode] of [
    [
      "expected_revision_ordinal",
      { expected_revision_ordinal: 7 },
      "ontology_action_contract_ordinal_gap",
    ],
    [
      "expected_predecessor_revision_ref",
      {
        expected_predecessor_revision_ref: `ontology-action://${NS}/${NAME}/${SLUG}/revision/9`,
      },
      "ontology_action_contract_predecessor_substituted",
    ],
    [
      "expected_predecessor_content_hash",
      { expected_predecessor_content_hash: `sha256:${"9".repeat(64)}` },
      "ontology_action_contract_predecessor_hash_substituted",
    ],
    [
      "expected_content_hash",
      { expected_content_hash: `sha256:${"8".repeat(64)}` },
      "ontology_action_contract_content_hash_substituted",
    ],
  ]) {
    await refusesWithoutTouchingTheChain(
      `a reused key asserting a false '${field}' is refused by its ORDINARY cause and appends nothing — replaying a stored contract never means the caller's claims about it go unchecked`,
      contractProposal({
        idempotency_key: "oac-genesis",
        ontology_revision_ref: ontologyRevision.ontology_id,
        ...assertion,
      }),
      expectedCode,
    );
  }
  // AN ASSERTION THE ROUTE CANNOT READ IS NOT ONE IT MAY IGNORE. `Value::as_str` and `as_u64` answer
  // None for "absent" and for "present but the wrong type" alike, so reading an assertion through
  // them SKIPS it whenever the caller sends a number where a hash belongs. The caller then appears to
  // have checked a server-derived fact it never checked. Both paths must refuse instead — the fresh
  // one before it derives anything, the replay one before it answers from the stored revision.
  for (const [path, extra] of [
    ["FRESH", { idempotency_key: "oac-malformed-fresh" }],
    ["REPLAY", { idempotency_key: "oac-genesis" }],
  ]) {
    for (const [field, malformed] of [
      ["expected_ontology_content_hash", { expected_ontology_content_hash: 12345 }],
      ["expected_bound_tool_id", { expected_bound_tool_id: ["tool://ioi/runtime/mail.send"] }],
      ["expected_revision_ordinal", { expected_revision_ordinal: "1" }],
      ["expected_content_hash", { expected_content_hash: { sha256: "..." } }],
    ]) {
      await refusesWithoutTouchingTheChain(
        `on the ${path} path a malformed '${field}' is refused as unreadable and appends nothing — a wrong-typed assertion must never be mistaken for an absent one`,
        contractProposal({
          ontology_revision_ref: ontologyRevision.ontology_id,
          ...extra,
          ...malformed,
        }),
        "ontology_action_contract_assertion_not_canonical",
      );
    }
  }

  const allTrueRetry = await req(
    "POST",
    OAC,
    contractProposal({
      idempotency_key: "oac-genesis",
      ontology_revision_ref: ontologyRevision.ontology_id,
      expected_revision_ordinal: 1,
      expected_predecessor_revision_ref: null,
      expected_predecessor_content_hash: null,
      expected_content_hash: v1.content_hash,
      expected_ontology_content_hash: ontologyContentHash,
      expected_bound_tool_id: TOOL?.tool_id,
    }),
  );
  ok(
    "a retry whose assertions are ALL TRUE of the stored revision replays it — the checker refuses false claims without refusing correct ones, which is the difference between a fence and an obstacle",
    allTrueRetry.status === 200 &&
      allTrueRetry.j?.replayed === true &&
      allTrueRetry.j?.ontology_action_contract?.content_hash === v1.content_hash,
    `status ${allTrueRetry.status} replayed ${allTrueRetry.j?.replayed} ${code(allTrueRetry.j)}`,
  );

  const successorOntology = await req(
    "POST",
    OV,
    ontologyProposal({
      key: "oac-ontology-2",
      expectedHead: ontologyHead,
      actions: [SLUG],
      entities: ["patient", "guardian"],
    }),
  );
  const revision2 = successorOntology.j?.ontology_version ?? {};
  const successor = await req(
    "POST",
    OAC,
    contractProposal({
      idempotency_key: "oac-successor",
      ontology_revision_ref: revision2.ontology_id,
      expected_head: genesis.j?.expected_head_for_successor,
      compatibility: "breaking",
      risk_class: "commerce",
    }),
  );
  const v2 = successor.j?.ontology_action_contract ?? {};
  ok(
    "a successor is admitted against the EXACT current head, mints revision 2, and names its predecessor by ref and by hash",
    successor.status === 201 &&
      v2.revision_ordinal === 2 &&
      v2.predecessor_revision_ref === v1.ontology_action_id &&
      v2.predecessor_content_hash === v1.content_hash &&
      v2.migration?.from_content_hash === v1.content_hash &&
      v2.migration?.reinterprets_predecessor === false,
    `status ${successor.status} ordinal ${v2.revision_ordinal} ${code(successor.j)}`,
  );
  await refusesWithoutTouchingTheChain(
    "changing successor migration compatibility under its admitted key is a typed conflict — compatibility is replay intent and immutable content, not uncommitted commentary",
    contractProposal({
      idempotency_key: "oac-successor",
      ontology_revision_ref: revision2.ontology_id,
      expected_head: genesis.j?.expected_head_for_successor,
      compatibility: "additive",
      risk_class: "commerce",
    }),
    "ontology_action_contract_replay_intent_changed",
  );
  await refusesWithoutTouchingTheChain(
    "a successor offered against a head this family never had is refused — a fork does not become a lineage by asserting one",
    contractProposal({
      idempotency_key: "oac-fork",
      ontology_revision_ref: revision2.ontology_id,
      expected_head: `forged-head-${"0".repeat(32)}`,
      compatibility: "breaking",
    }),
    "ontology_action_contract_expected_head_conflict",
  );

  // THE REASON `expected_head` IS NOT IN THAT CHECKER. A genuine retry after an ambiguous response
  // carries the head it originally compare-and-swapped against, which the successor has since made
  // stale. Requiring it to match would turn every real duplicate into a conflict and make the
  // idempotency key unusable — so the stale head is carried here deliberately and must still replay.
  const staleHeadRetry = await req(
    "POST",
    OAC,
    contractProposal({
      idempotency_key: "oac-genesis",
      ontology_revision_ref: ontologyRevision.ontology_id,
      expected_head: null,
    }),
  );
  ok(
    "a true ambiguous-response retry carrying its ORIGINAL, NOW-STALE head still replays after the lineage advanced — `expected_head` is excluded from the replay assertion checker on purpose, and this is the assertion that would go red if it were added",
    staleHeadRetry.status === 200 &&
      staleHeadRetry.j?.replayed === true &&
      staleHeadRetry.j?.ontology_action_contract?.revision_ordinal === 1,
    `status ${staleHeadRetry.status} replayed ${staleHeadRetry.j?.replayed} ${code(staleHeadRetry.j)}`,
  );

  const afterSuccessor = await lineageOf();
  const projectedV1 = (afterSuccessor.j?.revisions ?? []).find(
    (row) => row.revision_ordinal === 1,
  );
  ok(
    "the predecessor stays ADDRESSABLE and UNREINTERPRETED: its content hash and both bindings are byte-identical, and only its TRANSACTION interval closed",
    projectedV1 !== undefined &&
      projectedV1.content_hash === v1.content_hash &&
      projectedV1.ontology_content_hash === v1.ontology_content_hash &&
      projectedV1.runtime_tool_contract_content_hash === v1.runtime_tool_contract_content_hash &&
      projectedV1.status === "deprecated" &&
      typeof projectedV1.transaction_time?.superseded_at === "string",
    `hash-stable ${projectedV1?.content_hash === v1.content_hash} superseded ${projectedV1?.transaction_time?.superseded_at ?? "(null)"}`,
  );

  // ------------------------------------------------------------------------------- restart and rebuild
  const beforeRestart = await lineageOf();
  await stopDaemon();
  await startDaemon();
  const relogin = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "ontology-action-b@ioi.local", password: "ontology-action-b-v1" },
    { as: null },
  );
  SESSIONS.B = relogin.j?.session_token ?? SESSIONS.B;
  const bootAfter = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null, password: "ontology-action-a-v1" },
    { as: null },
  );
  if (bootAfter.j?.session_token) SESSIONS.A = bootAfter.j.session_token;
  const afterRestart = await lineageOf();
  ok(
    "the whole lineage SURVIVES A RESTART and is rebuilt from the Agentgres chain — durable truth is read across a restart rather than asked of the process that wrote it",
    JSON.stringify(afterRestart.j?.revisions) ===
      JSON.stringify(beforeRestart.j?.revisions),
    `${(afterRestart.j?.revisions ?? []).length} revisions identical across restart`,
  );
  ok(
    "the process-local read index was DISCARDED by that restart and rebuilt from the chain — positively detected, not inferred from the answer being unchanged",
    afterRestart.j?.index_state === "rebuilt_from_agentgres",
    `index reported ${afterRestart.j?.index_state ?? "(none)"}`,
  );
  const replayAfterRestart = await req(
    "POST",
    OAC,
    contractProposal({
      idempotency_key: "oac-genesis",
      ontology_revision_ref: ontologyRevision.ontology_id,
    }),
  );
  ok(
    "the original command REPLAYS AFTER RESTART from immutable admitted bytes before mutable current tool resolution — revocation or loss of a process-local registry snapshot cannot rewrite historical idempotency",
    replayAfterRestart.status === 200 &&
      replayAfterRestart.j?.replayed === true &&
      replayAfterRestart.j?.ontology_action_contract?.content_hash === v1.content_hash,
    `status ${replayAfterRestart.status} replayed ${replayAfterRestart.j?.replayed} ${code(replayAfterRestart.j)}`,
  );

  // ------------------------------------------------------------------------------------- query plane
  const exact = await req(
    "GET",
    `${OAC}?namespace=${NS}&name=${NAME}&action_slug=${SLUG}&revision=1`,
  );
  ok(
    "an EXACT revision lookup answers the predecessor, unchanged, after the successor landed",
    (exact.j?.revisions ?? []).length === 1 &&
      exact.j.revisions[0].content_hash === v1.content_hash,
    `${(exact.j?.revisions ?? []).length} row(s)`,
  );
  const byRisk = await req(
    "GET",
    `${OAC}?namespace=${NS}&name=${NAME}&action_slug=${SLUG}&risk_class=commerce`,
  );
  ok(
    "the query plane narrows by declared risk class, so a reviewer can ask for the consequential contracts as a first-class question",
    (byRisk.j?.revisions ?? []).length === 1 &&
      byRisk.j.revisions[0].revision_ordinal === 2,
    `${(byRisk.j?.revisions ?? []).length} row(s)`,
  );
  const stranger = await req("GET", `${OAC}?namespace=${NS}&name=${NAME}&action_slug=${SLUG}`, null, {
    as: "B",
  });
  ok(
    "a co-tenant member with no scope on this family sees nothing — a shared tenant is not a shared lineage",
    (stranger.j?.revisions ?? []).length === 0,
    `${(stranger.j?.revisions ?? []).length} row(s) for the other principal`,
  );

  // --------------------------------------------------------------------------------- source boundaries
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const contract = registry.contracts.find((entry) => entry.contract_id === CONTRACT_ID);
  ok(
    "the wire contract is REGISTERED with generated Rust and TypeScript projections and a negative fixture corpus — no surface claims this family from a local constant",
    contract !== undefined &&
      contract.schema_version === "ioi.ontology-action-contract.v1" &&
      contract.generated_targets.some((target) => target.kind === "rust_projection") &&
      contract.generated_targets.some((target) => target.kind === "typescript_projection") &&
      contract.negative_fixture_refs.length >= 8,
    `registered ${contract !== undefined} negatives ${contract?.negative_fixture_refs?.length ?? 0}`,
  );
  const routeSource = fs.readFileSync(ROUTE_SOURCE, "utf8");
  ok(
    "the producer consults NO authority plane: no capability lease, policy decision, effect admission or approval grant is read, minted or widened anywhere in this module",
    !/capability_lease|approval_grant|policy_decision\(|authority_gateway|effect_admission\(|CapabilityLease|AuthorityGrant/u.test(
      routeSource,
    ),
    "module source carries no authority-plane call",
  );
  const productionSource = routeSource.slice(0, routeSource.indexOf("#[cfg(test)]"));
  ok(
    "historical replay is ordered before mutable ontology/tool resolution in the producer source, while fresh admission still resolves both owners",
    productionSource.indexOf("match replay_existing_admission(") >= 0 &&
      productionSource.indexOf("match replay_existing_admission(") <
        productionSource.indexOf("let semantics = match resolve_semantics("),
    "replay lookup precedes current owner resolution",
  );
  ok(
    "the COMPLETE registered contract is validated before the shared mutation admission — producer/schema drift cannot append an operation that every later projection must refuse",
    productionSource.indexOf("if let Err(reason) = validate_contract_before_admission(&record, &family)") >= 0 &&
      productionSource.indexOf("if let Err(reason) = validate_contract_before_admission(&record, &family)") <
        productionSource.indexOf("let commit = match admit_owner_scoped_mutation("),
    "registered validation precedes the shared admission boundary",
  );
  ok(
    "and it INVOKES NOTHING: no runtime host, no final invoker and no tool call appears in this module's production path at all — the patterns are CALL-SHAPED so the module's own prose about not invoking cannot satisfy the check that it does not",
    !/runtime_host::|handle_action_execution\s*\(|handle_runtime_host_session\s*\(|"mcp_tool_call"|RuntimeAgentService/u.test(
      productionSource,
    ),
    "module source carries no invocation call",
  );
  ok(
    "it mints no second store at all: admission crosses the SHARED owner-scoped mutation boundary, and the production path calls no record writer and writes no file of its own",
    productionSource.includes("admit_owner_scoped_mutation(") &&
      !/\b(persist_record|persist_record_durable|persist_promoted|remove_record|admit_required)\s*\(/u.test(
        productionSource,
      ) &&
      !/\bstd::fs::(write|create_dir_all|remove_file|rename|copy)\s*\(/u.test(productionSource),
    "shared admission boundary; zero record writers and zero durable writes in the production path",
  );
  ok(
    "the semantic binding goes through the ONTOLOGY OWNER'S OWN action seam and this module opens no second reader over that family",
    productionSource.includes("resolve_admitted_action_type(") &&
      !productionSource.includes("read_owner_scoped_history(\n        data_dir,\n        identity,\n        scope,\n        \"ontology-version-family\""),
    "one owner seam, no duplicate ontology reader",
  );
  const seamSource = fs.readFileSync(OWNER_SEAM_SOURCE, "utf8");
  ok(
    "and that seam PROJECTS FROM THE CHAIN rather than from an index or a copy: it shares one projection with the exact-revision resolver and reads `action_types` out of the contract-validated document",
    seamSource.includes("fn resolve_admitted_revision_projection(") &&
      seamSource.includes("document\n        .get(\"action_types\")"),
    "membership read from the shared contract-validated projection",
  );
  ok(
    "the durable footprint is the SHARED substrate directory alone — this family adds no store of its own",
    durableTopLevelEntries().every((entry) => entry !== "odk-ontology-action-contracts"),
    `top-level durable entries: ${durableTopLevelEntries().join(", ")}`,
  );
}

// ------------------------------------------------------------------------------- mutation harness

const MUTANTS = [
  {
    id: "action-term-membership-check-skipped",
    reddens:
      "an UNKNOWN SAME-FAMILY action term is refused: a term that is well formed, correctly namespaced and canonical is still not an admitted action, and a contract is never compiled over meaning the bound revision never declared",
    source: OWNER_SEAM_SOURCE,
    from: `        .and_then(|terms| {
            terms
                .iter()
                .find(|term| term.get("term_id").and_then(Value::as_str) == Some(action_type_ref))
        })`,
    to: `        .and_then(|terms| {
            terms
                .iter()
                .find(|term| term.get("term_id").and_then(Value::as_str) == Some(action_type_ref))
                .or_else(|| terms.first())
        })`,
  },
  {
    id: "action-term-family-check-skipped",
    reddens:
      "a FOREIGN-FAMILY action term is refused as the category error it is — a contract never compiles one domain's action while binding another domain's meaning",
    source: OWNER_SEAM_SOURCE,
    from: `    let Some(term_slug) = action_type_ref.strip_prefix(&term_prefix) else {`,
    to: `    let Some(term_slug) = action_type_ref.strip_prefix(&term_prefix).or(Some("placeholder")) else {`,
  },
  {
    id: "tool-resolved-by-family-id-not-exact-revision",
    reddens:
      "a tool revision offered with a hash that does not identify it is refused — the tool binding is revision AND hash together, never a mutable family id",
    source: ROUTE_SOURCE,
    // The defect this denies is resolving by the MUTABLE TOOL FAMILY and ignoring the caller's
    // content hash — not failing to resolve at all. An earlier version of this mutant passed a
    // revision id to a by-name resolver, which simply resolved nothing: everything went red and the
    // targeted assertion stayed green, because a hash mismatch was still refused, just for the wrong
    // reason. This one extracts the real tool name, resolves that family's current head, and drops
    // the hash on the floor — so a mismatched hash is ACCEPTED, which is exactly what the assertion
    // denies.
    from: "        .resolve_exact(revision_ref, content_hash)",
    to: "        .resolve_current_for_name(revision_ref.split(\"/revision/\").next().unwrap_or_default().rsplit('/').next().unwrap_or_default())",
  },
  {
    id: "typed-io-binds-one-schema-twice",
    reddens:
      "the typed IO contract is pinned to the tool's own SCHEMA BYTES: both commitments are reproduced here by hashing the tool projection's own declared input and output schemas, so binding the tool ref alone could not leave the typed contract free to move underneath an admitted action",
    source: ROUTE_SOURCE,
    from: "    let output_schema_hash = serde_jcs::to_vec(&contract.output_schema)",
    to: "    let output_schema_hash = serde_jcs::to_vec(&json!({\"type\": \"object\", \"mutant\": true}))",
  },
  {
    id: "gate-ladder-drops-authority",
    reddens:
      "ACC-6 CLAUSE 5 IS A FIELD, NOT A PARAGRAPH: the compiled contract names the exact six gates the action must still pass, and its declared count agrees with the ladder it carries",
    source: ROUTE_SOURCE,
    from: `const REQUIRED_GATES: &[&str] = &[
    "capability",
    "policy",
    "authority",`,
    to: `const REQUIRED_GATES: &[&str] = &[
    "capability",
    "policy",`,
  },
  {
    id: "mandatory-nonclaims-not-enforced",
    reddens:
      "a contract that omits a mandatory nonclaim is refused: silence about what it does not confer is read as claiming it",
    source: ROUTE_SOURCE,
    from: "        .find(|required| !declared.iter().any(|token| token == *required))",
    to: "        .find(|required| !declared.iter().any(|token| token == *required) && false)",
  },
  {
    id: "physical-action-admits-without-a-safety-profile",
    reddens:
      "a PHYSICAL-ACTION contract with no bound safety profile is refused before admission, as well as offline by its registered invariant",
    source: ROUTE_SOURCE,
    from: "    if risk_class == PHYSICAL_ACTION_RISK_CLASS && physical_safety_profile_ref.is_null() {",
    to: "    if false && risk_class == PHYSICAL_ACTION_RISK_CLASS && physical_safety_profile_ref.is_null() {",
  },
  {
    id: "assertion-shape-check-deferred-behind-the-lineage",
    // The ORDERING claim, certified on its own. Removing the pre-lineage shape gate leaves the
    // per-field `Asserted::Malformed` arms in place, so a malformed assertion is still eventually
    // refused — but only AFTER the exact-head precondition, so on a family that already has
    // revisions the caller is answered `expected_head_conflict` while its unreadable claim goes
    // unexamined. That is precisely the defect this gate exists to deny, and no other mutant in this
    // battery can distinguish it: every one of them leaves the ordering intact.
    reddens:
      "on the FRESH path a malformed 'expected_revision_ordinal' is refused as unreadable and appends nothing — a wrong-typed assertion must never be mistaken for an absent one",
    source: ROUTE_SOURCE,
    from: "    if let Err(response) = validate_assertion_shapes(&body) {\n        return response;\n    }",
    to: "    if let Err(response) = Ok::<(), Reply>(()).or(validate_assertion_shapes(&body)) {\n        return response;\n    }",
  },
  {
    id: "replay-path-skips-the-caller-assertion-checker",
    reddens:
      "a reused key asserting a false 'expected_content_hash' is refused by its ORDINARY cause and appends nothing — replaying a stored contract never means the caller's claims about it go unchecked",
    source: ROUTE_SOURCE,
    from: "    if let Some(response) = replay_assertion_divergence(document, body) {\n        return Err(response);\n    }",
    to: "    if let Some(response) = replay_assertion_divergence(document, body).filter(|_| false) {\n        return Err(response);\n    }",
  },
  {
    id: "replay-intent-narrowed-to-the-old-twelve-field-subset",
    reddens:
      "changing 'receipt_obligations' under the admitted key is a typed conflict and appends nothing — replay compares EVERY caller-authored material input, not a remembered subset of them",
    source: ROUTE_SOURCE,
    from: '        ("receipt_obligations", receipt_obligations.clone()),',
    to: '        // MUTANT: receipt obligations omitted from replay intent.',
  },
  {
    id: "replay-lookup-never-compares-intent",
    reddens:
      "the same key with a CHANGED INTENT is refused — an idempotency key replays one exact command and is never a way to receive a stored contract in answer to a different one",
    source: ROUTE_SOURCE,
    from: "    match replay_intent_divergence(document, proposal)? {",
    to: "    match None::<&str> {",
  },
  {
    id: "migration-omitted-from-content-commitment",
    reddens:
      "the served content hash is INDEPENDENTLY reproducible from the registered invariant profile's own material fields — the daemon does not get to define its own commitment",
    source: ROUTE_SOURCE,
    from: '    "migration",\n];',
    to: '    // MUTANT: migration is not committed.\n];',
  },
  {
    id: "compatibility-omitted-from-replay-intent",
    reddens:
      "changing successor migration compatibility under its admitted key is a typed conflict — compatibility is replay intent and immutable content, not uncommitted commentary",
    source: ROUTE_SOURCE,
    from: '        ("compatibility", json!(compatibility)),',
    to: '        // MUTANT: compatibility omitted from replay intent.',
  },
  {
    id: "action-slug-not-bound-to-resolved-term",
    reddens:
      "the OntologyActionContract family slug must name the EXACT resolved ontology action term — a local alias is not invented without an admitted mapping decision",
    source: ROUTE_SOURCE,
    from: "    if proposal.action_type_ref != expected_action_type_ref {",
    to: "    if false && proposal.action_type_ref != expected_action_type_ref {",
  },
  {
    id: "typed-schema-refs-not-bound-to-tool-bytes",
    reddens:
      "caller-authored typed schema names cannot float above the tool bytes — both refs are exact content-addressed projections of the bound RuntimeToolContract schemas",
    source: ROUTE_SOURCE,
    from: "    if proposal.typed_input_schema_ref != expected_input_schema_ref\n        || proposal.typed_output_schema_ref != expected_output_schema_ref",
    to: "    if false\n        && (proposal.typed_input_schema_ref != expected_input_schema_ref\n            || proposal.typed_output_schema_ref != expected_output_schema_ref)",
  },
  {
    id: "registered-validation-skipped-before-admission",
    reddens:
      "the COMPLETE registered contract is validated before the shared mutation admission — producer/schema drift cannot append an operation that every later projection must refuse",
    source: ROUTE_SOURCE,
    from: "    if let Err(reason) = validate_contract_before_admission(&record, &family) {",
    to: "    if let Err(reason) = Ok::<(), String>(()) {",
  },
  {
    id: "historical-replay-not-returned-before-owner-resolution",
    reddens:
      "the original command REPLAYS AFTER RESTART from immutable admitted bytes before mutable current tool resolution — revocation or loss of a process-local registry snapshot cannot rewrite historical idempotency",
    source: ROUTE_SOURCE,
    from: "                Ok(Some(response)) => return response,",
    to: "                Ok(Some(_response)) => None,",
  },
  {
    id: "exact-head-check-removed",
    reddens:
      "a successor offered against a head this family never had is refused — a fork does not become a lineage by asserting one",
    source: ROUTE_SOURCE,
    from: "    if expected_head != current_head {",
    to: "    if false && expected_head != current_head {",
  },
  {
    id: "unknown-contract-version-silently-downgraded",
    reddens:
      "an UNKNOWN CONTRACT VERSION is refused rather than downgraded — serving an unknown version as v1 is how a contract silently loses a field",
    source: ROUTE_SOURCE,
    from: "        Some(Value::String(declared)) if declared == SCHEMA_VERSION => {}",
    to: "        Some(Value::String(declared)) if !declared.is_empty() || declared == SCHEMA_VERSION => {}",
  },
  {
    id: "index-always-reports-agreement",
    reddens:
      "the process-local read index was DISCARDED by that restart and rebuilt from the chain — positively detected, not inferred from the answer being unchanged",
    source: ROUTE_SOURCE,
    from: `        None => "rebuilt_from_agentgres",`,
    to: `        None => "agreed_with_agentgres",`,
  },
  {
    id: "predecessor-interval-never-closes",
    reddens:
      "the predecessor stays ADDRESSABLE and UNREINTERPRETED: its content hash and both bindings are byte-identical, and only its TRANSACTION interval closed",
    source: ROUTE_SOURCE,
    from: "        let superseded_at = revisions\n            .get(index + 1)\n            .map(|next| admitted_stamp(next.recorded_at_ms));",
    to: "        let superseded_at = revisions\n            .get(index + 1)\n            .and_then(|next| Some(admitted_stamp(next.recorded_at_ms)).filter(|_| false));",
  },
  {
    id: "bindings-may-collapse-into-one-commitment",
    reddens:
      "it binds the EXACT admitted ontology revision and carries that owner's committed hash VERBATIM — the semantic side is resolved, never asserted",
    source: ROUTE_SOURCE,
    from: "        ontology_content_hash: action.content_hash,",
    to: "        ontology_content_hash: format!(\"sha256:{}\", \"0\".repeat(64)),",
  },
];

/// The battery's currently-running child, so a signal can reach it.
///
/// WHY THIS IS NOT `spawnSync`. `spawnSync` blocks the Node event loop for the whole life of the
/// child, and a JavaScript signal handler is a callback on that loop. So a battery built on
/// `spawnSync` cannot be interrupted: SIGINT and SIGTERM are queued, the handler never runs, and the
/// harness keeps marching from mutant to mutant with production source rewritten. That is exactly
/// what happened here — an interrupt left a planted mutant in the tree and the run had to be SIGKILLed
/// and repaired from the disk snapshot. Every child is now asynchronous and tracked, so a signal can
/// kill it, restore every source, drop the snapshot and exit.
let activeChild = null;

function runChild(command, args, { env } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: ROOT,
      env: env ? { ...process.env, ...env } : process.env,
      stdio: ["ignore", "pipe", "pipe"],
      // Its own process group, so an interrupt can kill the whole tree. `cargo` spawns `rustc`, and
      // killing only the direct child would leave the compiler running against a mutated source.
      detached: true,
    });
    activeChild = child;
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout = `${stdout}${chunk}`;
    });
    child.stderr.on("data", (chunk) => {
      stderr = `${stderr}${chunk}`;
    });
    child.on("close", (status) => {
      activeChild = null;
      resolve({ status, stdout, stderr });
    });
    child.on("error", (error) => {
      activeChild = null;
      resolve({ status: -1, stdout, stderr: String(error) });
    });
  });
}

async function rebuildDaemon() {
  const build = await runChild("cargo", [
    "build",
    "--locked",
    "-p",
    "ioi-node",
    "--bin",
    "hypervisor-daemon",
  ]);
  if (build.status !== 0) {
    throw new Error(`mutant daemon did not build:\n${build.stderr?.slice(-4000)}`);
  }
}

/// Where the pristine sources are parked for the duration of a battery.
///
/// A `finally` block does not run when the process is killed. An earlier interrupted run of this
/// harness left a planted mutant — a fallback that made an UNDECLARED action resolve — sitting in
/// production source, and the next command to touch the tree would have built and tested it as
/// though it were the real thing. So the snapshot goes to DISK before the first mutation, the signal
/// handlers restore from it, and a later run refuses to start while one is still lying around.
const SNAPSHOT_DIR = path.join(ROOT, "target", "ontology-action-contract-mutation-snapshot");

function snapshotPathFor(source) {
  return path.join(SNAPSHOT_DIR, `${path.basename(source)}.pristine`);
}

function restoreFromDiskSnapshot() {
  if (!fs.existsSync(SNAPSHOT_DIR)) return [];
  const restored = [];
  for (const entry of fs.readdirSync(SNAPSHOT_DIR)) {
    if (!entry.endsWith(".pristine")) continue;
    const pristine = path.join(SNAPSHOT_DIR, entry);
    const target = MUTANTS.map((mutant) => mutant.source).find(
      (source) => path.basename(source) === entry.slice(0, -".pristine".length),
    );
    if (!target) continue;
    const body = fs.readFileSync(pristine, "utf8");
    if (fs.readFileSync(target, "utf8") !== body) {
      fs.writeFileSync(target, body);
      restored.push(target);
    }
  }
  fs.rmSync(SNAPSHOT_DIR, { recursive: true, force: true });
  return restored;
}

/// The durable per-mutant outcome ledger, so chunks compose into one adjudicated battery.
const LEDGER = path.join(ROOT, "target", "ontology-action-contract-mutation-ledger.json");

/// THIS FILE'S OWN BYTES, BOUND INTO EVERY ROW.
///
/// A chunked battery composes evidence produced at different times, and the thing that decides what
/// each chunk MEANS is not only the source under test — it is the harness: which defects are
/// declared, what each one's `from`/`to` are, and which live assertion each claims to redden. Two
/// mutant definitions in this file were corrected after earlier chunks had already recorded rows, so
/// a summary binding only the two Rust digests would have aggregated rows made under a DIFFERENT set
/// of claims into one green total. That is the falsified-claim shape this whole program exists to
/// refuse, applied to the evidence for the gates themselves.
///
/// So the verifier's bytes are a digest in every row and in the comparison `--summarize` makes. It is
/// NOT a mutatable source and never appears in the snapshot or the restore set: nothing plants into
/// it and nothing restores it. It is bound, not managed. Editing this file — even a comment — stales
/// every row, which is correct: a battery is only ever evidence about the harness that produced it.
const HARNESS_DIGEST = crypto
  .createHash("sha256")
  .update(fs.readFileSync(fileURLToPath(import.meta.url)))
  .digest("hex");

function readLedger() {
  try {
    return JSON.parse(fs.readFileSync(LEDGER, "utf8"));
  } catch {
    return {};
  }
}

function recordLedger(rows, sourceDigests) {
  const ledger = readLedger();
  for (const row of rows) {
    ledger[row.id] = { ...row, sources: sourceDigests };
  }
  fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
  fs.writeFileSync(LEDGER, `${JSON.stringify(ledger, null, 2)}\n`);
}

/// Adjudicate the union of every recorded chunk against the DECLARED mutant set.
///
/// The declared set is the authority: a mutant that was never run has no row, and a missing row is
/// a failure rather than an absence nobody notices. The pristine source digests each chunk recorded
/// are compared too, so rows produced against different source than the tree now holds cannot be
/// aggregated into a green summary.
function evidenceDigests() {
  return {
    ...Object.fromEntries(
      [...new Set(MUTANTS.map((mutant) => mutant.source))].map((file) => [
        path.relative(ROOT, file),
        crypto.createHash("sha256").update(fs.readFileSync(file, "utf8")).digest("hex"),
      ]),
    ),
    // Bound, never restored — see HARNESS_DIGEST.
    harness: HARNESS_DIGEST,
  };
}

function summarizeBattery() {
  const ledger = readLedger();
  const current = evidenceDigests();
  let onTarget = 0;
  let stale = 0;
  for (const mutant of MUTANTS) {
    const row = ledger[mutant.id];
    if (!row) {
      process.stdout.write(`MISS  ${mutant.id} — never run in any recorded chunk\n`);
      continue;
    }
    const sameSource = JSON.stringify(row.sources) === JSON.stringify(current);
    if (!sameSource) stale += 1;
    if (row.outcome === "RED_ON_TARGET" && sameSource) onTarget += 1;
    process.stdout.write(
      `${row.outcome === "RED_ON_TARGET" && sameSource ? "RED " : "MISS"}  ${mutant.id} — ${row.detail}${sameSource ? "" : " (RECORDED AGAINST DIFFERENT SOURCE)"}\n`,
    );
  }
  const missing = MUTANTS.filter((mutant) => !ledger[mutant.id]).length;
  process.stdout.write(
    `\nontology-action-contract mutation battery: ${onTarget}/${MUTANTS.length} RED ON TARGET; ${stale} stale row(s); ${missing} missing row(s)\n`,
  );
  for (const [file, digest] of Object.entries(current)) {
    if (file === "harness") continue;
    process.stdout.write(`RESTORED  ${file} sha256:${digest}\n`);
  }
  process.stdout.write(`HARNESS   apps/hypervisor/scripts/verify-hypervisor-ontology-action-contract.mjs sha256:${HARNESS_DIGEST}\n`);
  process.exit(onTarget === MUTANTS.length && stale === 0 && missing === 0 ? 0 : 1);
}

async function runMutationBattery() {
  // SELECTION IS VALIDATED FIRST, BEFORE ANY STATE EXISTS. A typo in `--only` used to throw after the
  // snapshot directory had been created and the signal handlers installed, leaving an orphaned
  // snapshot that the NEXT battery would then "recover" from — repairing a tree that was never
  // broken and reporting a recovery that never happened. Nothing is created until the selection is
  // known to be real.
  const unknown = ONLY.filter((id) => !MUTANTS.some((mutant) => mutant.id === id));
  if (unknown.length > 0) {
    throw new Error(`--only names mutants this battery does not declare: ${unknown.join(", ")}`);
  }
  const selected = ONLY.length > 0 ? MUTANTS.filter((mutant) => ONLY.includes(mutant.id)) : MUTANTS;

  // A snapshot left over from a previous run means that run did not finish restoring. Repair before
  // planting anything, so a battery can never compound an earlier interruption.
  const inherited = restoreFromDiskSnapshot();
  if (inherited.length > 0) {
    process.stdout.write(
      `RECOVERED  a previous interrupted battery had left ${inherited.length} source(s) mutated; restored before starting\n`,
    );
  }
  const originals = new Map();
  for (const mutant of MUTANTS) {
    if (!originals.has(mutant.source)) {
      originals.set(mutant.source, fs.readFileSync(mutant.source, "utf8"));
    }
  }
  const digests = new Map(
    [...originals].map(([file, body]) => [
      file,
      crypto.createHash("sha256").update(body).digest("hex"),
    ]),
  );
  // THE PRE-RUN SNAPSHOT, ON DISK AND HASHED, BEFORE THE FIRST PLANT.
  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  for (const [file, body] of originals) fs.writeFileSync(snapshotPathFor(file), body);
  for (const [file, digest] of digests) {
    process.stdout.write(`PRISTINE  ${path.relative(ROOT, file)} sha256:${digest}\n`);
  }
  // The child is killed FIRST. Restoring sources under a running `cargo build` would let it observe
  // a half-written file, and the point of this path is to leave the tree exactly as it was found.
  let interrupting = false;
  const restoreAndExit = (signal) => {
    if (interrupting) return;
    interrupting = true;
    if (activeChild) {
      try {
        process.kill(-activeChild.pid, "SIGKILL");
      } catch {
        try {
          activeChild.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }
    }
    for (const [file, body] of originals) fs.writeFileSync(file, body);
    fs.rmSync(SNAPSHOT_DIR, { recursive: true, force: true });
    const restored = [...digests].every(
      ([file, digest]) =>
        crypto.createHash("sha256").update(fs.readFileSync(file, "utf8")).digest("hex") === digest,
    );
    process.stdout.write(
      `\nINTERRUPTED by ${signal} — child terminated, every source restored from the pre-run snapshot and byte-verified: ${restored}\n`,
    );
    process.exit(restored ? 130 : 1);
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(signal, () => restoreAndExit(signal));
  }
  process.stdout.write(
    `CHUNK  ${selected.length}/${MUTANTS.length} mutant(s) under harness sha256:${HARNESS_DIGEST}: ${selected.map((m) => m.id).join(", ")}\n`,
  );
  const rows = [];
  try {
    for (const mutant of selected) {
      const original = originals.get(mutant.source);
      const occurrences = original.split(mutant.from).length - 1;
      if (occurrences !== 1) {
        rows.push({ id: mutant.id, outcome: "ANCHOR_LOST", detail: `${occurrences} matches` });
        continue;
      }
      fs.writeFileSync(mutant.source, original.replace(mutant.from, mutant.to));
      // THE INTERRUPT SELF-TEST. With the first mutant planted and a real rebuild in flight, send
      // this process the signal that previously could not be handled. Everything after this point is
      // the production interrupt path — same handler, same child kill, same restore, same byte
      // verification — so a green self-test is evidence about the battery rather than about a mock.
      if (INTERRUPT_SELF_TEST) {
        setTimeout(() => process.kill(process.pid, "SIGINT"), 1500);
      }
      let built = true;
      try {
        await rebuildDaemon();
      } catch (error) {
        built = false;
        rows.push({
          id: mutant.id,
          outcome: "DID_NOT_COMPILE",
          detail: String(error).slice(0, 200),
        });
      }
      if (built) {
        const child = await runChild(process.execPath, [fileURLToPath(import.meta.url)], {
          env: { IOI_VERIFIER_CENSUS_DIR: "" },
        });
        const output = `${child.stdout ?? ""}${child.stderr ?? ""}`;
        const targeted = output.includes(`FAIL  ${mutant.reddens}`);
        const anyFailure = child.status !== 0;
        rows.push({
          id: mutant.id,
          outcome: targeted ? "RED_ON_TARGET" : anyFailure ? "RED_OFF_TARGET" : "SURVIVED",
          detail: targeted
            ? "the targeted assertion failed"
            : anyFailure
              ? "the run failed, but not on its target"
              : "the mutant passed unnoticed",
        });
      }
      fs.writeFileSync(mutant.source, original);
    }
  } finally {
    for (const [file, body] of originals) fs.writeFileSync(file, body);
    fs.rmSync(SNAPSHOT_DIR, { recursive: true, force: true });
    await rebuildDaemon();
  }
  let restored = true;
  for (const [file, digest] of digests) {
    const now = crypto.createHash("sha256").update(fs.readFileSync(file, "utf8")).digest("hex");
    const same = now === digest;
    restored = restored && same;
    process.stdout.write(
      `${same ? "RESTORED" : "DIRTY   "}  ${path.relative(ROOT, file)} sha256:${digest.slice(0, 16)}\n`,
    );
  }
  // Rows are recorded only when the sources came back byte-identical. A chunk that could not restore
  // the tree has no business contributing evidence to a battery summary.
  // A row is recorded ONLY after the Rust sources came back byte-identical, and it carries the full
  // evidence set — both restored sources plus the harness that defined the mutant. A chunk that could
  // not restore the tree has no business contributing evidence to a battery summary, and a row whose
  // digests are captured before restoration would attest to a state that never existed.
  if (restored) {
    recordLedger(rows, evidenceDigests());
  }
  for (const row of rows) {
    process.stdout.write(
      `${row.outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${row.id} — ${row.detail}\n`,
    );
  }
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(
    `\nontology-action-contract mutation chunk: ${onTarget}/${rows.length} RED ON TARGET; sources ${restored ? "restored and byte-verified" : "NOT RESTORED"}\n`,
  );
  process.exit(onTarget === rows.length && restored ? 0 : 1);
}

if (SUMMARIZE) {
  summarizeBattery();
} else if (MUTATE || INTERRUPT_SELF_TEST) {
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
      process.stdout.write(`\nontology-action-contract: ${passed}/${results.length}\n`);
      emitVerifierCensus({
        verifierId: "ontology-action-contract",
        sourceUrl: import.meta.url,
        results,
      });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
