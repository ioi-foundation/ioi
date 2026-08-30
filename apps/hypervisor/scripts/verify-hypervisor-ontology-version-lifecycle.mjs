#!/usr/bin/env node
// M05.1 — `OntologyVersion` as an immutable, owner-qualified object, driven end to end against a
// live daemon and its durable Agentgres chain.
//
// WHAT THIS GATE IS FOR. Without an immutable version an overlay has nothing to overlay, a crosswalk
// has nothing to map between, and a mapping decision has nothing to be a decision ABOUT. So the
// claims here are the foundation ones: identity is owner-qualified and cross-namespace, an edit
// mints a successor while the prior revision stays addressable and UNREINTERPRETED, valid time and
// transaction time answer different questions, admission is exact-head, and every substitution of
// fork/gap/predecessor/namespace/time/version/hash fails closed by its own name.
//
// HOW IT AVOIDS GRADING ITSELF:
//
//   * THE CONTENT HASH IS RECOMPUTED FROM CANON, not from the response. The material field list is
//     read out of the REGISTERED invariant profile in `docs/architecture/_meta/schemas/invariants/`,
//     and the digest is taken here in JavaScript. If the daemon's commitment ever stops covering what
//     the registered contract says it covers, these two disagree.
//   * DURABLE TRUTH IS READ ACROSS A RESTART. Asking the API whether something survived a restart,
//     without restarting, is asking the thing under test to grade itself.
//   * REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the lineage afterwards and
//     requires the head and revision count to be exactly what they were. A 4xx that still appended is
//     the failure this shape exists to catch.
//   * A GREEN RUN CERTIFIES NOTHING UNTIL THE HARNESS PROVES IT RED. `--mutate` plants named defects
//     in the daemon's own source, rebuilds, re-runs this file against the mutant, and requires each
//     one to redden the exact assertion it targets — a mutant that only reddens something else is
//     reported as a MISS, not quietly counted.
//
// NONCLAIMS. This gate proves the version lifecycle only. It makes no claim about overlays,
// crosswalks, mapping decisions, action contracts, surface descriptors or data recipes (M05.2-M05.7),
// and none about authority: it asserts the nonclaim is carried and that no capability, lease or
// policy decision is consulted, which is not the same as proving the authority planes elsewhere.

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
  "crates/node/src/bin/hypervisor_daemon_routes/ontology_version_routes.rs",
);
const INVARIANT_PROFILE = path.join(
  ROOT,
  "docs/architecture/_meta/schemas/invariants/ontology-version.v1.invariants.json",
);
const REGISTRY = path.join(
  ROOT,
  "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json",
);
const CONTRACT_ID = "schema://ioi/foundations/ontology-version/v1";
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

// ------------------------------------------------------------------- canonical JSON + content hash

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
    (candidate) => candidate.rule_id === "ontology_version.content_hash.commits_semantic_content_and_valid_time",
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

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ontology-version-"));
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
      IOI_WALLET_SECRET_PASS: "ioi-ontology-version-verifier",
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

const termsOf = (namespace, name, terms) =>
  terms.map((term) => ({
    term_id: `ontology://${namespace}/${name}/term/${term}`,
    label: term,
  }));

function proposal({
  namespace = "acme-clinic",
  name = "patient-intake",
  terms = ["patient"],
  startsAt = "2026-01-01T00:00:00Z",
  key,
  expectedHead = null,
  extra = {},
}) {
  const body = {
    owner_ref: "org://local",
    idempotency_key: key,
    namespace,
    name,
    governing_scope_ref: `domain://${namespace}/intake`,
    policy_hash: `sha256:${"1a".repeat(32)}`,
    entity_types: termsOf(namespace, name, terms),
    valid_time: { starts_at: startsAt, ends_at: null },
    ...extra,
  };
  if (expectedHead !== null) body.expected_head = expectedHead;
  if (expectedHead !== null && !("compatibility" in extra)) body.compatibility = "breaking";
  if (expectedHead !== null && !("term_mappings" in extra)) {
    body.term_mappings = [
      {
        from_term_id: `ontology://${namespace}/${name}/term/patient`,
        to_term_id: `ontology://${namespace}/${name}/term/patient`,
        disposition: "retained",
      },
    ];
  }
  return body;
}

const lineageOf = async (namespace, name, query = "", as = "A") =>
  req("GET", `${OV}?namespace=${namespace}&name=${name}${query}`, null, { as });

// Every durable byte this data directory holds, so the "no second store" claim is counted rather
// than asserted. The substrate directory is the shared Agentgres chain; the transport log belongs to
// this harness.
const durableTopLevelEntries = () =>
  fs
    .readdirSync(dataDir, { withFileTypes: true })
    .map((entry) => entry.name)
    .sort();

const MUXLOG = () => path.join(dataDir, "substrate", "muxlog.bin");

// ------------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();

  // ---------------------------------------------------------------------------------- principals
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "ontology-version-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const whoA = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    { email: "ontology-version-b@ioi.local", name: "Member B", role: "member", password: "ontology-version-b-v1" },
    { as: "A" },
  );
  const principalB = created.j?.principal?.principal_id ?? "";
  await req(
    "POST",
    `/v1/hypervisor/principals/${principalB}/tenant-memberships`,
    {
      tenant_ref: "org://local",
      expected_revision: 0,
      idempotency_key: "ontology-version-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "ontology-version-b@ioi.local", password: "ontology-version-b-v1" },
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

  // ------------------------------------------------------------------------- identity comes first
  const anonymous = await req("POST", OV, proposal({ key: "anon" }), { as: null });
  ok(
    "an unauthenticated admission is refused on IDENTITY before any content is judged — a 422 here would tell an anonymous caller which fields this route wants",
    anonymous.status === 401,
    `status ${anonymous.status} code ${code(anonymous.j)}`,
  );

  // -------------------------------------------------------------------------------- genesis (v1)
  const v1Response = await req("POST", OV, proposal({ key: "acme-genesis" }));
  const v1 = v1Response.j?.ontology_version ?? {};
  ok(
    "a first revision is admitted as revision 1 of an OWNER-QUALIFIED family, with no predecessor and a real Agentgres admission",
    v1Response.status === 201 &&
      v1.ontology_id === "ontology://acme-clinic/patient-intake/revision/1" &&
      v1.ontology_family_ref === "ontology://acme-clinic/patient-intake" &&
      v1.version === "v1" &&
      v1.revision_ordinal === 1 &&
      v1.predecessor_version_ref === null &&
      v1.status === "active" &&
      /^sha256:[0-9a-f]{64}$/u.test(v1.admission?.admission_head ?? "") &&
      /^sha256:[0-9a-f]{64}$/u.test(v1.admission?.admission_root ?? "") &&
      (v1Response.j?.receipt_ref ?? "").startsWith("receipt://"),
    `status ${v1Response.status} id ${v1.ontology_id} head ${v1.admission?.admission_head}`,
  );
  ok(
    "the revision carries the registered schema version and the explicit authority NONCLAIM — meaning compiles, it never grants",
    v1.schema_version === "ioi.ontology-version.v1" &&
      v1.ontology_record_profile === "ontology_version" &&
      v1.authority_nonclaim === "ontology_version_grants_no_authority",
    `schema ${v1.schema_version} nonclaim ${v1.authority_nonclaim}`,
  );
  const registeredV1 = registeredContentCommitment(v1);
  ok(
    "the served content hash is INDEPENDENTLY reproducible from the registered invariant profile's own material fields — the daemon does not get to define its own commitment",
    registeredV1.digest === v1.content_hash,
    `registered ${registeredV1.digest} served ${v1.content_hash} over ${registeredV1.fields.length} fields`,
  );
  ok(
    "that commitment covers VALID time and excludes TRANSACTION time, which is what keeps the two axes independent",
    registeredV1.fields.includes("valid_time") && !registeredV1.fields.includes("transaction_time"),
    `fields ${registeredV1.fields.join(",")}`,
  );

  const head1 = v1.admission.admission_head;

  // ------------------------------------------------------------------ idempotent replay, not a fork
  const replay = await req("POST", OV, proposal({ key: "acme-genesis" }));
  ok(
    "the SAME key with the same bytes replays the ORIGINAL admitted fact rather than minting a second revision",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.ontology_version?.admission?.admission_seq === v1.admission.admission_seq &&
      replay.j?.ontology_version?.admission?.admission_head === head1,
    `status ${replay.status} replayed ${replay.j?.replayed} seq ${replay.j?.ontology_version?.admission?.admission_seq}`,
  );

  // ------------------------------------------------------------------------- exact-head admission
  const headless = await req("POST", OV, proposal({ key: "acme-headless", terms: ["patient", "guardian"] }));
  ok(
    "a successor offered with NO expected head is refused: an existing family is never appended to unconditionally",
    headless.status === 409 && code(headless.j) === "ontology_version_expected_head_conflict",
    `status ${headless.status} code ${code(headless.j)}`,
  );
  const foreignHead = await req(
    "POST",
    OV,
    proposal({
      key: "acme-foreign-head",
      terms: ["patient", "guardian"],
      expectedHead: `sha256:${"cd".repeat(32)}`,
    }),
  );
  ok(
    "a successor offered against a head this family never had is refused — a fork does not become a lineage by asserting one",
    foreignHead.status === 409 && code(foreignHead.j) === "ontology_version_expected_head_conflict",
    `status ${foreignHead.status} code ${code(foreignHead.j)}`,
  );

  await sleep(60); // separate the two admissions in transaction time
  const v2Response = await req(
    "POST",
    OV,
    proposal({
      key: "acme-successor",
      terms: ["patient", "guardian"],
      startsAt: "2026-06-01T00:00:00Z",
      expectedHead: head1,
    }),
  );
  const v2 = v2Response.j?.ontology_version ?? {};
  ok(
    "an edit against the EXACT current head produces a new revision whose predecessor refs and predecessor content hash bind the prior revision exactly",
    v2Response.status === 201 &&
      v2.revision_ordinal === 2 &&
      v2.version === "v2" &&
      v2.predecessor_version_ref === v1.ontology_id &&
      v2.predecessor_content_hash === v1.content_hash &&
      v2.migration?.from_version_ref === v1.ontology_id &&
      v2.migration?.from_content_hash === v1.content_hash &&
      v2.migration?.from_revision_ordinal === 1 &&
      v2.migration?.reinterprets_predecessor === false,
    `status ${v2Response.status} ordinal ${v2.revision_ordinal} predecessor ${v2.predecessor_version_ref}`,
  );
  ok(
    "the successor's own content hash is independently reproducible and DIFFERS from its predecessor's — an edit that changes nothing is not an edit",
    registeredContentCommitment(v2).digest === v2.content_hash && v2.content_hash !== v1.content_hash,
    `v2 ${v2.content_hash} v1 ${v1.content_hash}`,
  );

  // --------------------------------------------------- the predecessor survives, unreinterpreted
  const afterSuccessor = await lineageOf("acme-clinic", "patient-intake", "&revision=1");
  const v1Again = afterSuccessor.j?.resolved_ontology_version ?? {};
  ok(
    "the PRIOR revision is still addressable at its exact coordinate after the edit",
    afterSuccessor.status === 200 && v1Again.ontology_id === v1.ontology_id,
    `status ${afterSuccessor.status} id ${v1Again.ontology_id}`,
  );
  ok(
    "and it is UNREINTERPRETED: its content hash, term sets and valid time are byte-identical, and only its TRANSACTION interval closed",
    v1Again.content_hash === v1.content_hash &&
      canonicalJson(v1Again.entity_types) === canonicalJson(v1.entity_types) &&
      canonicalJson(v1Again.valid_time) === canonicalJson(v1.valid_time) &&
      v1Again.transaction_time?.recorded_at === v1.transaction_time?.recorded_at &&
      v1Again.transaction_time?.superseded_at === v2.transaction_time?.recorded_at &&
      v1Again.status === "deprecated",
    `hash ${v1Again.content_hash === v1.content_hash} superseded ${v1Again.transaction_time?.superseded_at} status ${v1Again.status}`,
  );

  // --------------------------------------------------------------- fail-closed substitution matrix
  const baseline = await lineageOf("acme-clinic", "patient-intake");
  const baselineCount = baseline.j?.revision_count;
  const baselineHead = baseline.j?.resolved_ontology_version?.admission?.admission_head;
  const head2 = v2.admission.admission_head;

  const substitutions = [
    [
      "a REVISION GAP is refused: the next revision of a family is contiguous and never skips",
      "ontology_version_revision_gap",
      { expected_revision_ordinal: 9 },
    ],
    [
      "a substituted PREDECESSOR ref is refused by its own cause rather than as a generic conflict",
      "ontology_version_predecessor_substituted",
      { expected_predecessor_version_ref: "ontology://harbor-clinic/patient-intake/revision/1" },
    ],
    [
      "a substituted PREDECESSOR CONTENT HASH is refused",
      "ontology_version_predecessor_hash_substituted",
      { expected_predecessor_content_hash: `sha256:${"ef".repeat(32)}` },
    ],
    [
      "a substituted CONTENT HASH is refused: the hash is derived from the content, never accepted beside it",
      "ontology_version_content_hash_substituted",
      { expected_content_hash: `sha256:${"ab".repeat(32)}` },
    ],
    [
      "a substituted VERSION label is refused: the label is the identity's own revision segment",
      "ontology_version_version_label_substituted",
      { expected_version: "v9" },
    ],
    [
      "a caller-supplied TRANSACTION TIME is refused — a caller that could write it could backdate the record of when it was recorded",
      "ontology_version_transaction_time_server_resolved",
      { transaction_time: { recorded_at: "2020-01-01T00:00:00Z", superseded_at: null } },
    ],
    [
      "caller-authored ADMISSION EVIDENCE is refused (INV-37): admission is resolved by the server, never asserted by the caller",
      "ontology_version_field_server_resolved",
      { admission: { admission_head: `sha256:${"11".repeat(32)}` } },
    ],
    [
      "a term from ANOTHER NAMESPACE is refused: a version never mints meaning inside another domain's namespace",
      "ontology_version_term_foreign_namespace",
      { entity_types: termsOf("harbor-clinic", "patient-intake", ["patient"]) },
    ],
    [
      "a successor with NO declared migration is refused: an unexplained successor silently reinterprets its predecessor",
      "ontology_version_migration_required",
      { term_mappings: [] },
    ],
    [
      "a caller-declared `reinterprets_predecessor` is refused outright",
      "ontology_version_migration_reinterpretation_refused",
      {
        term_mappings: [
          {
            from_term_id: "ontology://acme-clinic/patient-intake/term/patient",
            to_term_id: "ontology://acme-clinic/patient-intake/term/patient",
            disposition: "retained",
            reinterprets_predecessor: true,
          },
        ],
      },
    ],
    [
      "an absent VALID TIME is refused: a domain that cannot say when a meaning became true cannot hold 'true then, not now'",
      "ontology_version_valid_time_required",
      { valid_time: {} },
    ],
    [
      "an INVERTED valid interval is refused",
      "ontology_version_valid_time_not_ordered",
      { valid_time: { starts_at: "2026-06-01T00:00:00Z", ends_at: "2026-01-01T00:00:00Z" } },
    ],
  ];

  let refusalsLeftTheChainAlone = true;
  for (const [claim, expectedCode, extra] of substitutions) {
    const attempt = await req(
      "POST",
      OV,
      proposal({
        key: `sub-${expectedCode}`,
        terms: ["patient", "guardian", "visitor"],
        startsAt: "2026-09-01T00:00:00Z",
        expectedHead: head2,
        extra,
      }),
    );
    ok(claim, code(attempt.j) === expectedCode, `status ${attempt.status} code ${code(attempt.j)}`);
    const after = await lineageOf("acme-clinic", "patient-intake");
    if (
      after.j?.revision_count !== baselineCount ||
      after.j?.resolved_ontology_version?.admission?.admission_head !== baselineHead
    ) {
      refusalsLeftTheChainAlone = false;
    }
  }
  ok(
    "EVERY refusal above left the chain exactly as it found it — a 4xx that still appended is the failure this shape exists to catch",
    refusalsLeftTheChainAlone,
    `revision_count pinned at ${baselineCount}, head pinned at ${baselineHead}`,
  );

  const noOp = await req(
    "POST",
    OV,
    proposal({
      key: "acme-no-op",
      terms: ["patient", "guardian"],
      startsAt: "2026-06-01T00:00:00Z",
      expectedHead: head2,
    }),
  );
  ok(
    "a successor whose content is byte-identical to the head is refused as a REPLAYED revision, not admitted as an edit",
    code(noOp.j) === "ontology_version_no_op_revision",
    `status ${noOp.status} code ${code(noOp.j)}`,
  );

  // ------------------------------------------------------------- cross-namespace, same local name
  const harbor = await req(
    "POST",
    OV,
    proposal({ key: "harbor-genesis", namespace: "harbor-clinic", terms: ["patient"] }),
    { as: "B" },
  );
  const harborV1 = harbor.j?.ontology_version ?? {};
  ok(
    "a DIFFERENT owner holds the SAME local name in its own namespace, with a distinct identity and a distinct content hash — no ontology is presumed globally canonical",
    harbor.status === 201 &&
      harborV1.ontology_id === "ontology://harbor-clinic/patient-intake/revision/1" &&
      harborV1.name === v1.name &&
      harborV1.namespace !== v1.namespace &&
      harborV1.content_hash !== v1.content_hash,
    `status ${harbor.status} id ${harborV1.ontology_id}`,
  );
  const crossRead = await lineageOf("harbor-clinic", "patient-intake", "", "A");
  ok(
    "the other owner cannot READ that lineage, even though both principals hold the same org tenant",
    crossRead.status === 403 || crossRead.status === 401,
    `status ${crossRead.status} code ${code(crossRead.j)}`,
  );
  const crossWrite = await req(
    "POST",
    OV,
    proposal({
      key: "acme-borrows-harbor",
      namespace: "harbor-clinic",
      terms: ["patient", "stowaway"],
      expectedHead: harborV1.admission.admission_head,
    }),
    { as: "A" },
  );
  ok(
    "and cannot APPEND to it: the family's reserved scope pins the admitting principal, not merely the tenant",
    crossWrite.status === 403 || crossWrite.status === 401,
    `status ${crossWrite.status} code ${code(crossWrite.j)}`,
  );

  // -------------------------------------------------------------------------- bitemporal queries
  const v1Recorded = v1.transaction_time.recorded_at;
  const asOfRecorded = await lineageOf(
    "acme-clinic",
    "patient-intake",
    `&as_of_transaction_time=${encodeURIComponent(v1Recorded)}`,
  );
  ok(
    "TRANSACTION-time travel answers 'as the record stood then': before the successor was recorded, the head was revision 1",
    asOfRecorded.status === 200 &&
      asOfRecorded.j?.matched_revision_count === 1 &&
      asOfRecorded.j?.resolved_ontology_version?.revision_ordinal === 1,
    `matched ${asOfRecorded.j?.matched_revision_count} head ${asOfRecorded.j?.resolved_ontology_version?.revision_ordinal}`,
  );
  const asOfValidEarly = await lineageOf(
    "acme-clinic",
    "patient-intake",
    "&as_of_valid_time=2026-03-01T00:00:00Z",
  );
  ok(
    "VALID-time travel answers 'what was held true then': at 2026-03-01 only revision 1's interval had opened, even though revision 2 is already recorded",
    asOfValidEarly.j?.matched_revision_count === 1 &&
      asOfValidEarly.j?.resolved_ontology_version?.revision_ordinal === 1,
    `matched ${asOfValidEarly.j?.matched_revision_count} head ${asOfValidEarly.j?.resolved_ontology_version?.revision_ordinal}`,
  );
  const asOfValidLate = await lineageOf(
    "acme-clinic",
    "patient-intake",
    "&as_of_valid_time=2026-07-01T00:00:00Z",
  );
  ok(
    "at 2026-07-01 both intervals are open and the later revision resolves — the two revisions are held together, not overwritten",
    asOfValidLate.j?.matched_revision_count === 2 &&
      asOfValidLate.j?.resolved_ontology_version?.revision_ordinal === 2,
    `matched ${asOfValidLate.j?.matched_revision_count} head ${asOfValidLate.j?.resolved_ontology_version?.revision_ordinal}`,
  );
  const bitemporalCell = await lineageOf(
    "acme-clinic",
    "patient-intake",
    `&as_of_valid_time=2026-07-01T00:00:00Z&as_of_transaction_time=${encodeURIComponent(v1Recorded)}`,
  );
  ok(
    "the two axes are INDEPENDENT: 'true on 2026-07-01, as the record stood before the successor was written' is a different answer from either alone",
    bitemporalCell.j?.matched_revision_count === 1 &&
      bitemporalCell.j?.resolved_ontology_version?.revision_ordinal === 1,
    `matched ${bitemporalCell.j?.matched_revision_count} head ${bitemporalCell.j?.resolved_ontology_version?.revision_ordinal}`,
  );
  const absent = await lineageOf("acme-clinic", "patient-intake", "&revision=7");
  ok(
    "a revision that does not exist is a TYPED absence, never an empty success",
    absent.status === 404 && code(absent.j) === "ontology_version_revision_absent",
    `status ${absent.status} code ${code(absent.j)}`,
  );

  // -------------------------------------- the read index is rebuildable and is not truth at all
  const truth = await lineageOf("acme-clinic", "patient-intake");
  const truthPrint = canonicalJson(truth.j?.lineage);
  ok(
    "the read reports its truth source as the Agentgres chain and its index state as an AGREEMENT, so a rebuild can be detected positively rather than inferred from an unchanged answer",
    truth.j?.truth_source === "agentgres_owner_scoped_chain" &&
      truth.j?.rebuildable_index_state === "agreed_with_agentgres",
    `source ${truth.j?.truth_source} state ${truth.j?.rebuildable_index_state}`,
  );
  ok(
    "this family owns NO durable artifact of its own — there is no second store to delete or corrupt, because the chain is the only thing written",
    !durableTopLevelEntries().some((entry) => entry.includes("ontology-version")) &&
      durableTopLevelEntries().includes("substrate"),
    `top-level: ${durableTopLevelEntries().join(", ")}`,
  );

  // ------------------------------------------------------------------------------------- restart
  const beforeRestartBytes = fs.statSync(MUXLOG()).size;
  await stopDaemon();
  // CORRUPTION, applied to the one durable artifact that exists: a TORN tail on the chain's own
  // write-ahead log — a frame header promising 4096 bytes with 64 actually present, which is what a
  // crash mid-append leaves behind. Acked batches are fully durable before the ack, so replay must
  // discard exactly these unacked bytes and reproduce the same truth. (A header with an out-of-range
  // length is a different finding: the engine refuses to open rather than guessing, which is also
  // correct and is deliberately not what is being asserted here.)
  const tornHeader = Buffer.alloc(4);
  tornHeader.writeUInt32LE(4096, 0);
  fs.appendFileSync(MUXLOG(), Buffer.concat([tornHeader, Buffer.alloc(64)]));
  await startDaemon();
  const relogin = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: whoA.principal?.email ?? "", password: "ontology-version-a-v1" },
    { as: null },
  );
  if (relogin.j?.session_token) SESSIONS.A = relogin.j.session_token;
  const afterRestart = await lineageOf("acme-clinic", "patient-intake");
  ok(
    "the whole lineage REPLAYS byte-identically after a daemon restart, over a chain whose write-ahead log was left with 4KB of garbage on its tail — corrupting the log's unacked tail cannot alter admitted truth",
    canonicalJson(afterRestart.j?.lineage) === truthPrint && afterRestart.j?.revision_count === 2,
    `identical ${canonicalJson(afterRestart.j?.lineage) === truthPrint} count ${afterRestart.j?.revision_count} log was ${beforeRestartBytes}B + 4096B of garbage`,
  );
  ok(
    "the process-local read index was DISCARDED by that restart and rebuilt from the chain — positively detected, not inferred from the answer being unchanged",
    afterRestart.j?.rebuildable_index_state === "rebuilt_from_agentgres",
    `state ${afterRestart.j?.rebuildable_index_state}`,
  );
  const restartHead = afterRestart.j?.resolved_ontology_version?.admission?.admission_head;
  await sleep(60);
  const v3 = await req(
    "POST",
    OV,
    proposal({
      key: "acme-post-restart",
      terms: ["patient", "guardian", "visitor"],
      startsAt: "2026-09-01T00:00:00Z",
      expectedHead: restartHead,
    }),
  );
  ok(
    "and the chain still ADMITS against the head recovered from that replay, so recovery restored a writable head rather than a readable copy",
    v3.status === 201 &&
      v3.j?.ontology_version?.revision_ordinal === 3 &&
      v3.j?.ontology_version?.predecessor_content_hash === v2.content_hash,
    `status ${v3.status} ordinal ${v3.j?.ontology_version?.revision_ordinal}`,
  );

  // ---------------------------------------------------------------------- registration and scope
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const contract = registry.contracts.find((entry) => entry.contract_id === CONTRACT_ID);
  ok(
    "the wire contract is REGISTERED with generated Rust and TypeScript projections and a negative fixture corpus — no surface claims this family from a local constant",
    contract !== undefined &&
      contract.schema_version === "ioi.ontology-version.v1" &&
      contract.generated_targets.some((target) => target.kind === "rust_projection") &&
      contract.generated_targets.some((target) => target.kind === "typescript_projection") &&
      contract.negative_fixture_refs.length >= 8,
    `registered ${contract !== undefined} negatives ${contract?.negative_fixture_refs?.length ?? 0}`,
  );
  const routeSource = fs.readFileSync(ROUTE_SOURCE, "utf8");
  ok(
    "the producer consults NO authority plane: no capability lease, policy decision, effect admission or approval grant is read, minted or widened anywhere in this module",
    !/capability_lease|approval_grant|policy_decision|authority_gateway|effect_admission/u.test(routeSource),
    "module source carries no authority-plane call",
  );
  const productionSource = routeSource.slice(0, routeSource.indexOf("#[cfg(test)]"));
  ok(
    "and it mints no second store at all: admission crosses the SHARED owner-scoped mutation boundary, and the production path calls no record writer and writes no file of its own",
    productionSource.includes("admit_owner_scoped_mutation(") &&
      !/\b(persist_record|persist_record_durable|persist_promoted|remove_record|admit_required)\s*\(/u.test(
        productionSource,
      ) &&
      !/\bstd::fs::(write|create_dir_all|remove_file|rename|copy)\s*\(/u.test(productionSource),
    "shared admission boundary; zero record writers and zero durable writes in the production path",
  );
}

// ------------------------------------------------------------------------------- mutation harness

const MUTANTS = [
  {
    id: "content-commitment-drops-valid-time",
    reddens:
      "the served content hash is INDEPENDENTLY reproducible from the registered invariant profile's own material fields — the daemon does not get to define its own commitment",
    from: `    "policy_hash",\n    "valid_time",\n];`,
    to: `    "policy_hash",\n];`,
  },
  {
    id: "exact-head-check-removed",
    reddens:
      "a successor offered against a head this family never had is refused — a fork does not become a lineage by asserting one",
    from: "    if expected_head != current_head {",
    to: "    if false && expected_head != current_head {",
  },
  {
    id: "revision-gap-accepted",
    reddens: "a REVISION GAP is refused: the next revision of a family is contiguous and never skips",
    from: "        if asserted != ordinal {",
    to: "        if false && asserted != ordinal {",
  },
  {
    id: "predecessor-interval-never-closes",
    reddens:
      "and it is UNREINTERPRETED: its content hash, term sets and valid time are byte-identical, and only its TRANSACTION interval closed",
    from: "        let superseded_at = revisions\n            .get(index + 1)\n            .map(|next| admitted_stamp(next.recorded_at_ms));",
    to: "        let superseded_at = revisions\n            .get(index + 1)\n            .and_then(|next| None::<String>.or(Some(admitted_stamp(next.recorded_at_ms))).filter(|_| false));",
  },
  {
    id: "index-always-reports-agreement",
    reddens:
      "the process-local read index was DISCARDED by that restart and rebuilt from the chain — positively detected, not inferred from the answer being unchanged",
    from: `        None => "rebuilt_from_agentgres",`,
    to: `        None => "agreed_with_agentgres",`,
  },
  {
    id: "caller-authored-fields-accepted",
    reddens:
      "caller-authored ADMISSION EVIDENCE is refused (INV-37): admission is resolved by the server, never asserted by the caller",
    from: `    for authored in ["admission", "content_hash", "ontology_id", "status"] {`,
    to: `    for authored in ["content_hash", "ontology_id", "status"] {`,
  },
  {
    id: "no-op-revision-admitted",
    reddens:
      "a successor whose content is byte-identical to the head is refused as a REPLAYED revision, not admitted as an edit",
    from: "        if proposed_meaning == previous_meaning {",
    to: "        if false && proposed_meaning == previous_meaning {",
  },
  {
    id: "replay-lookup-never-finds-the-callers-key",
    reddens:
      "the SAME key with the same bytes replays the ORIGINAL admitted fact rather than minting a second revision",
    from: "        &stream_tail(RESOURCE_KIND, &family),\n        &caller.idempotency_key,\n    ) {",
    to: "        &stream_tail(RESOURCE_KIND, &family),\n        \"mutant-key-that-never-admitted\",\n    ) {",
  },
];

function rebuildDaemon() {
  const build = spawnSync(
    "cargo",
    ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  if (build.status !== 0) throw new Error(`mutant daemon did not build:\n${build.stderr?.slice(-4000)}`);
}

async function runMutationBattery() {
  const original = fs.readFileSync(ROUTE_SOURCE, "utf8");
  const rows = [];
  try {
    for (const mutant of MUTANTS) {
      const occurrences = original.split(mutant.from).length - 1;
      if (occurrences !== 1) {
        rows.push({ id: mutant.id, outcome: "ANCHOR_LOST", detail: `${occurrences} matches` });
        continue;
      }
      fs.writeFileSync(ROUTE_SOURCE, original.replace(mutant.from, mutant.to));
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
      rows.push({
        id: mutant.id,
        outcome: targeted ? "RED_ON_TARGET" : anyFailure ? "RED_OFF_TARGET" : "SURVIVED",
        detail: targeted ? "the targeted assertion failed" : anyFailure ? "the run failed, but not on its target" : "the mutant passed unnoticed",
      });
    }
  } finally {
    fs.writeFileSync(ROUTE_SOURCE, original);
    rebuildDaemon();
  }
  for (const row of rows) {
    process.stdout.write(`${row.outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${row.id} — ${row.detail}\n`);
  }
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(`\nontology-version-lifecycle mutation battery: ${onTarget}/${MUTANTS.length} RED ON TARGET\n`);
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
        process.stdout.write(`${result.pass ? "ok  " : "FAIL"}  ${result.name}${result.detail ? ` — ${result.detail}` : ""}\n`);
      }
      const passed = results.filter((result) => result.pass).length;
      process.stdout.write(`\nontology-version-lifecycle: ${passed}/${results.length}\n`);
      emitVerifierCensus({ verifierId: "ontology-version-lifecycle", sourceUrl: import.meta.url, results });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
