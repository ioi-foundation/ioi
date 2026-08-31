#!/usr/bin/env node
// M05.5 — `OntologySurfaceDescriptor`: the invariant-11 binding set, driven end to end against a
// live daemon and its durable Agentgres chain.
//
// WHAT THIS GATE IS FOR. Non-negotiable 11 requires every ODK-generated surface to declare owning
// ontology refs, object-model refs, data-recipe refs where applicable, policy-bound data view refs,
// authority requirements, daemon/API dependencies, receipt obligations and conformance expectations
// BEFORE it becomes durable product inventory. v1 carried NONE of them, so no stored descriptor
// could be checked against invariant 11 even in principle. The claims driven here are: the eight
// members are carried and checkable from the bytes; the ontology binding is an EXACT admitted
// revision resolved through its owner with that owner's committed hash; authoring is an ORDINARY
// GOVERNED MUTATION that crosses no lease and no grant; the chain — not the rebuildable row — is the
// answer; and both downstream consumers read the canonical names rather than the ones v1 had.
//
// HOW IT AVOIDS GRADING ITSELF:
//
//   * THE CONTENT COMMITMENT IS RECOMPUTED FROM CANON. The material field list is read out of the
//     REGISTERED invariant profile and the digest is taken here in JavaScript, so a daemon that
//     hashed something else disagrees with the profile rather than with a copy of its own code.
//   * THE ONTOLOGY REVISION IS REAL AND ADMITTED IN THIS SAME RUN through M05.1's own route, so
//     "the owner resolved it" is never a fixture agreeing with itself.
//   * REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the chain afterwards and
//     requires the head and the revision count to be exactly what they were.
//   * THE INDEX IS DESTROYED AND CORRUPTED ON PURPOSE, and the answer must not move.
//   * DURABLE TRUTH IS READ ACROSS A RESTART.
//   * A GREEN RUN CERTIFIES NOTHING UNTIL THE HARNESS PROVES IT RED. `--mutate` plants named defects
//     in this module's own source, rebuilds, re-runs, and requires each to redden the exact
//     assertion it targets; the source is restored and byte-verified before exit.
//
// THE HISTORICAL v1 UPGRADE IS EXECUTED, NOT DISCLAIMED. A convergence needs a stored v1
// predecessor, and this build refuses to author one — that refusal IS the unit, so the upgrade
// cannot be driven over HTTP without inventing the bypass the unit exists to close. It is therefore
// driven where it legitimately can be: `the_historical_v1_upgrade_converges_restarts_and_replays`
// seeds a contract-valid v1 through the same owner-scoped admission foundation the legacy lane used,
// seeds its M05.1 prerequisite through THAT owner's own admission helper, and runs the full
// production `build_descriptor_v2` — so `resolve_admitted_revision` and every request validation
// actually execute — then closes and reopens state, admits, restarts, advances the source, replays
// the convergence key exactly, and proves the downgrade, cross-owner and changed-source refusals.
// This gate INVOKES that test, so a green gate cannot mean the upgrade went unexercised.
//
// RUNTIME SCOPE. This gate proves the descriptor binding and its two consumers. It makes no claim
// that a described surface can be mounted, served, registered or launched, that any authority
// requirement it names is implemented, or that the bound ontology's meaning is correct for the
// domain.

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
const ROUTE_SOURCE = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/odk_routes.rs");
const DOMAIN_APP_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/domain_apps_routes.rs",
);
const PACKAGE_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/package_registry_routes.rs",
);
const SCHEMAS = path.join(ROOT, "docs/architecture/_meta/schemas");
const INVARIANT_PROFILE = path.join(
  SCHEMAS,
  "invariants/ontology-surface-descriptor.v2.invariants.json",
);
const REGISTRY = path.join(SCHEMAS, "architecture-contract-registry.v1.json");
const V2 = "schema://ioi/foundations/objects/ontology-surface-descriptor/v2";
const V1 = "schema://ioi/foundations/objects/ontology-surface-descriptor/v1";

const MUTATE = process.argv.includes("--mutate");
const SUMMARIZE = process.argv.includes("--summarize");
const ONLY = (process.argv.find((argument) => argument.startsWith("--only=")) ?? "")
  .slice("--only=".length)
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);

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

// ------------------------------------------------------------------- canonical JSON + commitment

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

const profile = () => JSON.parse(fs.readFileSync(INVARIANT_PROFILE, "utf8"));
const registry = () => JSON.parse(fs.readFileSync(REGISTRY, "utf8"));

/** The content commitment, rebuilt from the REGISTERED invariant profile rather than from the daemon. */
function registeredContentCommitment(document) {
  const rule = profile().rules.find(
    (candidate) =>
      candidate.rule_id === "ontology_surface_descriptor.content_hash.commits_the_whole_descriptor",
  );
  if (!rule) throw new Error("the registered profile declares no content commitment rule");
  const material = {};
  for (const [field, descriptor] of Object.entries(rule.expression.material_fields)) {
    if (Object.hasOwn(descriptor, "value")) {
      material[field] = descriptor.value;
      continue;
    }
    const key = descriptor.path.slice(2);
    material[field] = Object.hasOwn(document ?? {}, key) ? document[key] : null;
  }
  return {
    digest: `sha256:${crypto.createHash("sha256").update(canonicalJson(material)).digest("hex")}`,
    fields: Object.keys(rule.expression.material_fields).filter((name) => name !== "domain"),
  };
}

// ------------------------------------------------------------------------------------- daemon plane

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-surface-descriptor-"));
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
      IOI_WALLET_SECRET_PASS: "ioi-surface-descriptor-verifier",
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

async function req(method, route, body, { as = "A", headers: extra = {} } = {}) {
  const headers = { ...extra };
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
const SD = "/v1/hypervisor/odk/surface-descriptors";
const NS = "acme-clinic";
const NAME = "patient-intake";
const OWNER = "org://local";
const REVISION_1 = `ontology://${NS}/${NAME}/revision/1`;
const REVISION_2 = `ontology://${NS}/${NAME}/revision/2`;

const termsOf = (terms) =>
  terms.map((term) => ({ term_id: `ontology://${NS}/${NAME}/term/${term}`, label: term }));

/** A real M05.1 revision, admitted through M05.1's OWN route. */
function ontologyProposal({ key, expectedHead = null, entities = ["patient"] }) {
  const body = {
    owner_ref: OWNER,
    idempotency_key: key,
    namespace: NS,
    name: NAME,
    governing_scope_ref: `domain://${NS}/intake`,
    policy_hash: `sha256:${"1a".repeat(32)}`,
    entity_types: termsOf(entities),
    action_types: termsOf(["schedule-followup"]),
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  };
  if (expectedHead !== null) {
    body.expected_head = expectedHead;
    body.compatibility = "additive";
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

const NONCLAIMS = [
  "authority",
  "capability_lease_crossing",
  "runtime_truth",
  "semantic_truth",
  "permission_truth",
  "marketplace_truth",
];

/** One complete v2 authoring request: all eight members, canonical names, exact revisions. */
function descriptorProposal(overrides = {}) {
  return {
    owner_ref: OWNER,
    schema_version: "ioi.ontology-surface-descriptor.v2",
    display_name: "Intake review inbox",
    surface_ref: `surface://${NS}/intake-review`,
    composition_pattern: "domain_app",
    ontology_refs: [REVISION_1],
    canonical_object_model_refs: [`object-model://${NS}/${NAME}/appointment`],
    data_recipe_refs: [`data-recipe://${NS}/intake-normalise/revision/1`],
    policy_bound_data_view_refs: [`view://${NS}/intake/reviewer`],
    authority_requirement_refs: ["scope:intake.review", `policy://${NS}/intake/reviewer`],
    daemon_api_refs: ["api://v1/hypervisor/ontology-versions"],
    receipt_obligations: [`receipt://${NS}/intake/review-decision`],
    conformance_profile_refs: [`profile://${NS}/intake/review-inbox/v1`],
    connector_mapping_refs: [`mapping://${NS}/intake-form`],
    ontology_projection_refs: [`projection://${NS}/intake/by-status`],
    allowed_action_refs: [`ontology-action://${NS}/${NAME}/schedule-followup`],
    operator_contract_refs: [`contract://${NS}/intake-reviewer`],
    mcp_contract_refs: [`mcp-profile://${NS}/intake`],
    generated_artifact_refs: [],
    does_not_assert: [...NONCLAIMS],
    ...overrides,
  };
}

/** Head + revision count, so a refusal can be counted BY EFFECT rather than by its status code. */
async function chainState(id, as = "A") {
  const { j, status } = await req("GET", `${SD}/${id}`, null, { as });
  return {
    status,
    head: j?.admitted_head ?? null,
    count: j?.revision_count ?? null,
    record: j?.surface_descriptor ?? null,
    indexState: j?.index_state ?? null,
  };
}

async function refusesWithoutTouchingTheChain(name, id, method, route, body, expectedCode) {
  const before = await chainState(id);
  const response = await req(method, route, body);
  const after = await chainState(id);
  ok(
    name,
    response.status >= 400 &&
      code(response.j) === expectedCode &&
      after.head === before.head &&
      after.count === before.count,
    `status ${response.status} code ${code(response.j) || "(none)"} chain ${before.count}->${after.count}`,
  );
  return response;
}

const rowPath = (id) => path.join(dataDir, "records", "odk-surface-descriptors", `${id}.json`);

function findRow(id) {
  const direct = rowPath(id);
  if (fs.existsSync(direct)) return direct;
  const found = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name === `${id}.json`) found.push(full);
    }
  };
  try {
    walk(dataDir);
  } catch {
    /* best effort */
  }
  return found[0] ?? null;
}

// ------------------------------------------------------------------------------------------- the run

async function run() {
  // =============================================================== OFFLINE: the registered corpus
  //
  // Read before a daemon exists, so a census failure is about canon rather than about a runtime.
  const reg = registry();
  const entryV2 = reg.contracts.find((c) => c.contract_id === V2);
  const entryV1 = reg.contracts.find((c) => c.contract_id === V1);
  ok(
    "the registry records the succession in BOTH directions over a REAL registered predecessor — `successor_of` names a contract that exists, with its own schema and its own fixtures, rather than a version string in a comment",
    entryV2?.evolution?.successor_of === V1 &&
      entryV1?.evolution?.successor_contract_id === V2 &&
      entryV1?.evolution?.predecessor_remains_valid === true &&
      entryV1?.evolution?.wire_mutation_policy === "forbidden" &&
      fs.existsSync(path.join(SCHEMAS, entryV1?.schema_ref ?? "missing")),
    `v2<-${entryV2?.evolution?.successor_of ?? "(none)"} v1->${entryV1?.evolution?.successor_contract_id ?? "(none)"}`,
  );

  const v1Schema = JSON.parse(
    fs.readFileSync(path.join(SCHEMAS, entryV1?.schema_ref ?? "ontology-surface-descriptor.v1.schema.json"), "utf8"),
  );
  const v2Schema = JSON.parse(
    fs.readFileSync(path.join(SCHEMAS, "ontology-surface-descriptor.v2.schema.json"), "utf8"),
  );
  const MEMBERS = v2Schema.properties.invariant_11_binding_set.items.enum;
  ok(
    "v1 CARRIES NONE OF THE EIGHT and v2 requires all eight — the widening is load-bearing, and this is the assertion that would go green on a successor that changed nothing",
    MEMBERS.length === 8 &&
      MEMBERS.every((member) => !Object.hasOwn(v1Schema.properties, member)) &&
      MEMBERS.every((member) => v2Schema.required.includes(member)) &&
      Object.hasOwn(v1Schema.properties, "ontology_ref") &&
      Object.hasOwn(v1Schema.properties, "recipe_refs"),
    `${MEMBERS.length} members, none on v1`,
  );

  const negatives = entryV2.negative_fixture_refs ?? [];
  const ruleIds = profile().rules.map((rule) => rule.rule_id);
  const declaredRules = negatives.map((n) => n.expected_rule_id).filter(Boolean);
  ok(
    "OFFLINE FIXTURE CENSUS: every registered fixture file exists, every declared `expected_rule_id` names a rule the profile actually carries, and no rule id is declared twice",
    entryV2.positive_fixture_refs.every((p) => fs.existsSync(path.join(SCHEMAS, p))) &&
      negatives.every((n) => fs.existsSync(path.join(SCHEMAS, n.path))) &&
      declaredRules.every((id) => ruleIds.includes(id)) &&
      new Set(ruleIds).size === ruleIds.length,
    `${entryV2.positive_fixture_refs.length} positive + ${negatives.length} negative over ${ruleIds.length} rules`,
  );

  const positives = entryV2.positive_fixture_refs.map((p) =>
    JSON.parse(fs.readFileSync(path.join(SCHEMAS, p), "utf8")),
  );
  ok(
    "every POSITIVE fixture's committed hash is reproducible from the REGISTERED material list alone — a relying party holding only the bytes can verify the commitment, which is what makes it a commitment rather than a number the record carries",
    positives.length === 2 &&
      positives.every((doc) => registeredContentCommitment(doc).digest === doc.content_hash),
    positives.map((doc) => `${doc.surface_descriptor_id}: ${registeredContentCommitment(doc).digest === doc.content_hash}`).join("; "),
  );

  const substitution = JSON.parse(
    fs.readFileSync(
      path.join(SCHEMAS, "fixtures/ontology-surface-descriptor-v2/negative-binding-set-equal-count-substitution.json"),
      "utf8",
    ),
  );
  const owned = substitution.ontology_refs;
  const boundIdentities = substitution.bound_ontology_revisions.map((r) => r.ontology_revision_ref);
  ok(
    "THE EQUAL-COUNT SUBSTITUTION IS A REAL CASE THE ARITHMETIC CANNOT SEE: its two counts agree, its entries are unique, its commitment is current — and the owning set and the bound set are DIFFERENT SETS, which only exact set equality refuses",
    owned.length === boundIdentities.length &&
      new Set(boundIdentities).size === boundIdentities.length &&
      registeredContentCommitment(substitution).digest === substitution.content_hash &&
      canonicalJson([...owned].sort()) !== canonicalJson([...boundIdentities].sort()),
    `${owned.length} named, ${boundIdentities.length} bound, sets differ`,
  );

  // EXACT PRODUCER / CONSUMER CENSUS. The producer is one route module; the consumers are exactly
  // two. Naming them here means a THIRD consumer added later without an owner-resolved read is a
  // failure rather than something nobody notices.
  const domainAppSource = fs.readFileSync(DOMAIN_APP_SOURCE, "utf8");
  const packageSource = fs.readFileSync(PACKAGE_SOURCE, "utf8");
  const routeSource = fs.readFileSync(ROUTE_SOURCE, "utf8");
  const routeDir = path.dirname(ROUTE_SOURCE);
  const others = fs
    .readdirSync(routeDir)
    .filter((file) => file.endsWith(".rs") && file !== "odk_routes.rs")
    .map((file) => [file, fs.readFileSync(path.join(routeDir, file), "utf8")]);
  const touching = others
    .filter(
      ([, body]) =>
        body.includes("odk-surface-descriptors") ||
        body.includes("resolve_admitted_surface_descriptor"),
    )
    .map(([file]) => file)
    .sort();
  const contentConsumers = touching
    .filter((file) =>
      others
        .find(([name]) => name === file)[1]
        .includes("odk_routes::resolve_admitted_surface_descriptor"),
    )
    .sort();
  ok(
    "EXACT PRODUCER AND CONTENT-CONSUMER CENSUS: one producer module, and exactly two modules that read a descriptor's CONTENT — both of which resolve through the descriptor OWNER rather than loading the record directory",
    routeSource.includes("pub(crate) fn resolve_admitted_surface_descriptor") &&
      canonicalJson(contentConsumers) ===
        canonicalJson(["domain_apps_routes.rs", "package_registry_routes.rs"]),
    `content consumers: ${contentConsumers.join(", ") || "(none)"}`,
  );
  // THE REST OF THE CENSUS, NAMED RATHER THAN OMITTED. Two further modules mention the descriptor
  // record kind, and both do exactly one thing with it: confirm that a NAMED evidence or subject ref
  // resolves to some local record. They read no descriptor field, so no contract-version divergence
  // can reach them — which is why they are not owner-resolved consumers and why this gate says so
  // instead of leaving them out of a count that claims to be exact.
  const existenceOnly = touching.filter((file) => !contentConsumers.includes(file)).sort();
  const DESCRIPTOR_FIELDS = [...MEMBERS, "composition_pattern", "content_hash", "bound_ontology_revisions"];
  ok(
    "and the only other modules naming the descriptor record kind are EXISTENCE-ONLY ref checkers that read no descriptor field, so the exact set of modules that could diverge on contract version is the two above",
    canonicalJson(existenceOnly) ===
      canonicalJson(["governance_routes.rs", "marketplace_routes.rs"]) &&
      existenceOnly.every((file) => {
        const body = others.find(([name]) => name === file)[1];
        const [, after] = body.split('"surface-descriptor" => Some("odk-surface-descriptors")');
        return DESCRIPTOR_FIELDS.every(
          (field) => !(after ?? "").slice(0, 600).includes(`"${field}"`),
        );
      }),
    `existence-only: ${existenceOnly.join(", ") || "(none)"}`,
  );
  ok(
    "THE DOMAIN APP READS THE CANONICAL PLURAL NAMES. It read `ontology_ref`/`recipe_refs` only — neither of which a v2 has — so a DomainApp over a v2 descriptor derived an EMPTY lineage and recorded it as its provenance, silently",
    domainAppSource.includes('arr_strs(descriptor, "ontology_refs")') &&
      domainAppSource.includes('arr_strs(descriptor, "data_recipe_refs")'),
    "canonical names present in derive_snapshot",
  );

  // ============================================ THE HISTORICAL UPGRADE, BOUND INTO THIS GATE
  //
  // The one path no HTTP request can reach, because this build refuses to author the v1 a
  // convergence needs. Running it HERE is what stops a green gate from meaning it went unexercised:
  // the focused test seeds a contract-valid v1 and its real M05.1 prerequisite through their owners'
  // own admission code, drives the full production builder, restarts, advances the source and
  // replays the convergence key exactly.
  const upgrade = spawnSync(
    "cargo",
    [
      "test",
      "--locked",
      "-p",
      "ioi-node",
      "--bin",
      "hypervisor-daemon",
      // Substring filter, not `--exact`: the exact form needs the full module path, and a filter
      // that matches NOTHING reports `0 passed` and exits 0 — a green that proves nothing. The
      // assertion below requires exactly one test to have passed for that reason.
      "the_historical_v1_upgrade_converges_restarts_and_replays",
      "--",
      "--nocapture",
    ],
    { cwd: ROOT, encoding: "utf8" },
  );
  const upgradeOutput = `${upgrade.stdout ?? ""}${upgrade.stderr ?? ""}`;
  ok(
    "THE HISTORICAL v1 UPGRADE IS EXECUTED: a contract-valid stored v1 and its real M05.1 prerequisite are seeded through their owners' own admission code, the full production builder converges them, and the record survives a restart and replays its key exactly after the source moves — the one path no HTTP request can reach, because authoring a v1 is closed by design",
    upgrade.status === 0 && /test result: ok\. 1 passed; 0 failed/u.test(upgradeOutput),
    upgrade.status === 0
      ? `cargo test ok: ${(upgradeOutput.match(/test result: ok\.[^\n]*/u) ?? ["(no summary line)"])[0]}`
      : `cargo test exited ${upgrade.status}: ${upgradeOutput.slice(-400)}`,
  );

  // THE OTHER v1 MUTATION AN OPERATOR ACTUALLY PERFORMS, bound in the same way and for the same
  // reason: a stored v1 cannot be authored over HTTP, so WITHDRAWING one is only reachable from a
  // focused test over the production withdrawal function. It is a separate `cargo test` rather than
  // more assertions inside the upgrade test because the two prove different things and a reader of
  // this gate's output should be able to see which one went red.
  const withdrawal = spawnSync(
    "cargo",
    [
      "test",
      "--locked",
      "-p",
      "ioi-node",
      "--bin",
      "hypervisor-daemon",
      "a_stored_v1_withdrawal_is_version_correct_and_repairs_to_the_same_bytes",
      "--",
      "--nocapture",
    ],
    { cwd: ROOT, encoding: "utf8" },
  );
  const withdrawalOutput = `${withdrawal.stdout ?? ""}${withdrawal.stderr ?? ""}`;
  ok(
    "A STORED v1 IS WITHDRAWN IN ITS OWN VERSION'S SHAPE, AND THE ROW IS REPAIRED TO THE SAME BYTES: the delete path built a valid v1 tombstone and then persisted it through an envelope hard-coded to the v2 contract, so the row on disk announced `…/ontology-surface-descriptor/v2` over a record admitted as v1 — while the documented repair wrote that same descriptor in a different shape. Two shapes for one admitted state, invisible because every read answers from the chain",
    withdrawal.status === 0 && /test result: ok\. 1 passed; 0 failed/u.test(withdrawalOutput),
    withdrawal.status === 0
      ? `cargo test ok: ${(withdrawalOutput.match(/test result: ok\.[^\n]*/u) ?? ["(no summary line)"])[0]}`
      : `cargo test exited ${withdrawal.status}: ${withdrawalOutput.slice(-400)}`,
  );

  // =========================================================================== LIVE: the daemon
  await startDaemon();

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "surface-descriptor-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "surface-descriptor-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "surface-descriptor-b-v1",
    },
    { as: "A" },
  );
  const principalB = created.j?.principal?.principal_id ?? "";
  await req(
    "POST",
    `/v1/hypervisor/principals/${principalB}/tenant-memberships`,
    {
      tenant_ref: OWNER,
      expected_revision: 0,
      idempotency_key: "surface-descriptor-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "surface-descriptor-b@ioi.local", password: "surface-descriptor-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant",
    SESSIONS.A.length > 0 && SESSIONS.B.length > 0 && principalB.length > 0,
    `A ${SESSIONS.A.length > 0} B ${SESSIONS.B.length > 0}`,
  );

  const genesisOntology = await req("POST", OV, ontologyProposal({ key: "sd-ontology-1" }));
  const ontologyRevision = genesisOntology.j?.ontology_version ?? {};
  const ontologyHead = genesisOntology.j?.expected_head_for_successor ?? null;
  ok(
    "PRECONDITION: a REAL ontology revision is admitted through M05.1's own route in this same run — the binding is never made against a fixture that agrees with itself",
    genesisOntology.status === 201 && ontologyRevision.ontology_id === REVISION_1,
    `status ${genesisOntology.status} id ${ontologyRevision.ontology_id ?? "(none)"}`,
  );
  const ontologyContentHash = ontologyRevision.content_hash;

  // --------------------------------------------------------------- the descriptor is authored
  const recordKinds = () => {
    try {
      return fs.readdirSync(path.join(dataDir, "records")).sort();
    } catch {
      return [];
    }
  };
  const durableBefore = recordKinds();
  const create = await req("POST", SD, {
    ...descriptorProposal(),
    idempotency_key: "sd-create-1",
  });
  const record = create.j?.surface_descriptor ?? {};
  const descriptorRef = record.surface_descriptor_id ?? "";
  const descriptorId = descriptorRef.replace("surface-descriptor://", "");
  ok(
    "the eight invariant-11 members are CARRIED, not described: a stored descriptor declares the exact set non-negotiable 11 requires, its declared count agrees with it, and the record names the field names canon uses",
    create.status === 201 &&
      canonicalJson(record.invariant_11_binding_set) === canonicalJson(MEMBERS) &&
      record.invariant_11_member_count === 8 &&
      MEMBERS.every((member) => Object.hasOwn(record, member)),
    `status ${create.status} members ${record.invariant_11_member_count}`,
  );
  ok(
    "the ontology binding is an EXACT ADMITTED REVISION carrying its OWNER'S committed hash verbatim, resolved through that owner's own published seam — naming a revision is not binding one",
    canonicalJson(record.ontology_refs) === canonicalJson([REVISION_1]) &&
      record.bound_ontology_revisions?.[0]?.ontology_revision_ref === REVISION_1 &&
      record.bound_ontology_revisions?.[0]?.ontology_content_hash === ontologyContentHash &&
      record.bound_ontology_revision_count === 1 &&
      record.ontology_resolved_by === "ontology_version_routes::resolve_admitted_revision",
    `bound ${record.bound_ontology_revisions?.[0]?.ontology_content_hash === ontologyContentHash}`,
  );
  ok(
    "the committed content hash is REPRODUCIBLE FROM CANON: recomputed here from the registered material list over the daemon's own returned bytes, it is the number the daemon committed",
    registeredContentCommitment(record).digest === record.content_hash &&
      registeredContentCommitment(record).fields.length === 32,
    `${record.content_hash ?? "(none)"}`,
  );
  ok(
    "AUTHORING IS AN ORDINARY GOVERNED MUTATION: it returns a receipt and an operation ref from the shared owner-scoped admission boundary, carries `capability_lease_crossing` as an explicit nonclaim, and mints no lease, grant or approval record anywhere in the data directory",
    typeof create.j?.receipt_ref === "string" &&
      create.j.receipt_ref.length > 0 &&
      typeof create.j?.operation_ref === "string" &&
      NONCLAIMS.every((token) => (record.does_not_assert ?? []).includes(token)) &&
      record.authority_nonclaim === "ontology_surface_descriptor_grants_no_authority" &&
      !recordKinds().some(
        (entry) => /lease|grant|approval/u.test(entry) && !durableBefore.includes(entry),
      ),
    `receipt ${String(create.j?.receipt_ref ?? "").slice(0, 24)}`,
  );

  await refusesWithoutTouchingTheChain(
    "an UNKNOWN REQUEST FIELD is refused by name, not ignored. Both routes read what they wanted and dropped the rest, so a misspelled binding member was answered 'the correctly-spelled one is absent', and an AUTHORITY-LOOKING field was answered 201 with a record containing no such thing — indistinguishable from one where something had been granted",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({ authority_grant_ref: "grant://acme-clinic/forged" }),
      idempotency_key: "sd-forged-grant",
    },
    "odk_descriptor_request_field_unknown",
  );
  await refusesWithoutTouchingTheChain(
    "a NON-STRING nonclaim member is refused rather than filtered out: `filter_map` silently DISCARDED it and admitted a record whose nonclaim set was not the one the caller sent, and quietly editing what a record says it does not confer is the one edit that must never be silent",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({ does_not_assert: [...NONCLAIMS, 7] }),
      idempotency_key: "sd-nonclaim-nonstring",
    },
    "odk_descriptor_nonclaim_not_canonical",
  );
  await refusesWithoutTouchingTheChain(
    "a DUPLICATED nonclaim member is refused by its own cause, rather than surfacing later as a `uniqueItems` shape complaint about a record the caller cannot map back to its mistake",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({ does_not_assert: [...NONCLAIMS, "authority"] }),
      idempotency_key: "sd-nonclaim-duplicate",
    },
    "odk_descriptor_nonclaim_duplicated",
  );

  const afterCreate = await chainState(descriptorId);
  ok(
    "THE CREATE REPLY IS THE BARE REGISTERED RECORD, byte-identical to what the exact-descriptor read returns. It briefly returned the storage ENVELOPE under the same `surface_descriptor` key, so a consumer validating the create reply against the registered contract saw an object with two unknown fields and none of the known ones — every field it wanted reading as absent rather than as an error",
    canonicalJson(record) === canonicalJson(afterCreate.record) &&
      record.schema_version === "ioi.ontology-surface-descriptor.v2" &&
      record.descriptor === undefined,
    `create reply and chain read agree: ${canonicalJson(record) === canonicalJson(afterCreate.record)}`,
  );
  ok(
    "the exact-descriptor read answers from the AGENTGRES CHAIN and reports what the row said, so a rebuild can be positively detected rather than inferred from an unchanged answer",
    afterCreate.status === 200 &&
      afterCreate.count === 1 &&
      typeof afterCreate.head === "string" &&
      afterCreate.indexState === "agreed_with_agentgres",
    `count ${afterCreate.count} index ${afterCreate.indexState}`,
  );

  // ------------------------------------------------------------------------------- owner scope
  const bRead = await req("GET", `${SD}/${descriptorId}`, null, { as: "B" });
  const bPatch = await req(
    "PATCH",
    `${SD}/${descriptorId}`,
    { idempotency_key: "b-patch", expected_head: afterCreate.head, display_name: "stolen" },
    { as: "B" },
  );
  const bDelete = await req("DELETE", `${SD}/${descriptorId}`, null, {
    as: "B",
    headers: { "x-ioi-idempotency-key": "b-delete", "x-ioi-expected-head": afterCreate.head },
  });
  const afterB = await chainState(descriptorId);
  ok(
    "ANOTHER PRINCIPAL IN THE SAME TENANT CANNOT READ, PATCH OR DELETE THIS DESCRIPTOR, and its attempts leave the chain exactly where they found it — the scope is per-resource and per-principal, not per-tenant",
    bRead.status >= 400 &&
      bPatch.status >= 400 &&
      bDelete.status >= 400 &&
      afterB.count === 1 &&
      afterB.head === afterCreate.head,
    `read ${bRead.status} patch ${bPatch.status} delete ${bDelete.status}`,
  );

  const anonymousList = await req("GET", SD, null, { as: null });
  const bList = await req("GET", SD, null, { as: "B" });
  ok(
    "THE LIST IS AUTHENTICATED AND TENANT-SAFE. It previously took no identity at all and returned every descriptor in the process — every owner, every binding, every surface ref — to any caller who asked. An anonymous caller is now refused, and a different principal sees none of this one's descriptors",
    anonymousList.status === 401 &&
      bList.status === 200 &&
      (bList.j?.surface_descriptors ?? []).length === 0,
    `anonymous ${anonymousList.status} B sees ${(bList.j?.surface_descriptors ?? []).length}`,
  );
  ok(
    "THE CENSUS LEAKS NO CROSS-TENANT COUNT. It briefly carried the global descriptor-stream total and the number this caller was NOT authorized for — facts about other tenants, answered to anyone authenticated, so polling the endpoint would tell you when a competitor created a descriptor and how many they hold. Every number is now scoped to the caller, and B's own view is honestly empty",
    bList.j?.census?.census_scope === "this_caller_only" &&
      bList.j?.census?.authorized_for_this_caller === 0 &&
      bList.j?.census?.resolved_from_chain === 0 &&
      bList.j?.census?.descriptor_streams_in_namespace === undefined &&
      bList.j?.census?.not_authorized_for_this_caller === undefined &&
      bList.j?.census?.read_model_rows_present === undefined &&
      bList.j?.projection_source === "agentgres_owner_chain",
    `scope ${bList.j?.census?.census_scope} authorized ${bList.j?.census?.authorized_for_this_caller}`,
  );

  const aList = await req("GET", SD, null, { as: "A" });
  ok(
    "the owner's own list resolves each descriptor FROM THE CHAIN and reports index agreement per row, so a short list can never be read as an authoritative absence",
    aList.status === 200 &&
      (aList.j?.surface_descriptors ?? []).length === 1 &&
      aList.j.surface_descriptors[0].surface_descriptor_id === descriptorRef &&
      aList.j?.census?.resolved_from_chain === 1 &&
      aList.j?.census?.index_agreed_with_chain === 1 &&
      (aList.j?.census?.unreadable ?? []).length === 0,
    `${(aList.j?.surface_descriptors ?? []).length} listed`,
  );

  // ------------------------------------------------------------- refusals that touch nothing
  await refusesWithoutTouchingTheChain(
    "a MUTABLE FAMILY HEAD is refused as an ontology binding — durable product inventory may not silently re-mean itself when the family advances",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({ ontology_refs: [`ontology://${NS}/${NAME}`] }),
      idempotency_key: "sd-family-head",
    },
    "odk_descriptor_ontology_ref_unresolved",
  );
  await refusesWithoutTouchingTheChain(
    "the LEGACY SINGULAR NAME is refused rather than translated: silently mapping `ontology_ref` onto `ontology_refs` would keep two spellings alive for one canonical field and make the convergence invisible",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal(),
      ontology_ref: REVISION_1,
      idempotency_key: "sd-legacy-name",
    },
    "odk_descriptor_legacy_field_name",
  );
  await refusesWithoutTouchingTheChain(
    "an ABSENT binding-set member is refused: an absent member and a declared empty one are different findings, and a surface that declares neither cannot be checked against invariant 11",
    descriptorId,
    "POST",
    SD,
    (() => {
      const body = descriptorProposal({ idempotency_key: "sd-missing-member" });
      delete body.receipt_obligations;
      return body;
    })(),
    "odk_descriptor_binding_member_absent",
  );
  await refusesWithoutTouchingTheChain(
    "a MISSING MANDATORY NONCLAIM is refused: a descriptor that does not say it crosses no CapabilityLease is read as crossing one, and that wording was withdrawn by ruling",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({
        does_not_assert: NONCLAIMS.filter((token) => token !== "capability_lease_crossing"),
      }),
      idempotency_key: "sd-nonclaim-short",
    },
    "odk_descriptor_nonclaim_incomplete",
  );

  // ---------------------------------------------------- migration and downgrade, all fail closed
  await refusesWithoutTouchingTheChain(
    "AUTHORING AT v1 IS CLOSED: the predecessor carries none of the binding set, so it is refused rather than downgraded, and the refusal names the successor",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({ schema_version: "ioi.hypervisor.odk.surface-descriptor.v1" }),
      idempotency_key: "sd-v1-author",
    },
    "odk_descriptor_version_superseded",
  );
  await refusesWithoutTouchingTheChain(
    "an UNKNOWN CONTRACT VERSION is refused rather than downgraded — serving an unknown version as v2 is how a contract silently loses a field",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({ schema_version: "ioi.ontology-surface-descriptor.v3" }),
      idempotency_key: "sd-v3-author",
    },
    "odk_descriptor_version_unsupported",
  );
  await refusesWithoutTouchingTheChain(
    "a CONVERGENCE FROM A v2 is refused: only the registered, deprecated v1 is a legitimate source, and a record is only ever hashed under the contract it was admitted under",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({ migrated_from_descriptor_ref: descriptorRef }),
      idempotency_key: "sd-converge-v2",
    },
    "odk_descriptor_migration_source_not_v1",
  );
  await refusesWithoutTouchingTheChain(
    "a CONVERGENCE FROM A REF THIS CALLER MAY NOT SEE is refused by the descriptor owner's own scope, so a migration is never a way to read another tenant's exact record bytes out of the successor's own commitment",
    descriptorId,
    "POST",
    SD,
    {
      ...descriptorProposal({
        migrated_from_descriptor_ref: "surface-descriptor://sd_00000000000000000",
      }),
      idempotency_key: "sd-converge-foreign",
    },
    "odk_descriptor_migration_source_unresolved",
  );

  // ------------------------------------------------------------- patch: allowlist and transitions
  const head1 = (await chainState(descriptorId)).head;
  await refusesWithoutTouchingTheChain(
    "a BINDING IS NOT PATCHABLE, and the refusal NAMES THE FIELD rather than reporting a registered-validity failure: a descriptor binds exact admitted revisions, so moving one describes a different surface",
    descriptorId,
    "PATCH",
    `${SD}/${descriptorId}`,
    {
      idempotency_key: "sd-patch-binding",
      expected_head: head1,
      ontology_refs: [REVISION_1],
    },
    "odk_descriptor_field_not_patchable",
  );
  await refusesWithoutTouchingTheChain(
    "a FIELD THE v2 CONTRACT DOES NOT HAVE is refused as unknown — `view_config` was on the inherited v1 allowlist, so a patch carrying it was written onto the record and then failed closed at revalidation with a message about registered validity rather than about the field the caller actually sent",
    descriptorId,
    "PATCH",
    `${SD}/${descriptorId}`,
    { idempotency_key: "sd-patch-viewconfig", expected_head: head1, view_config: {} },
    "odk_descriptor_request_field_unknown",
  );
  await refusesWithoutTouchingTheChain(
    "a STALE EXACT HEAD is refused: a patch compare-and-swaps against the exact admitted head, and a fork does not become a lineage by asserting one",
    descriptorId,
    "PATCH",
    `${SD}/${descriptorId}`,
    {
      idempotency_key: "sd-patch-stalehead",
      expected_head: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      display_name: "Renamed",
    },
    "event_stream_expected_head_conflict",
  );
  await refusesWithoutTouchingTheChain(
    "an UNDECLARED STATUS TRANSITION is refused: `draft` never jumps to `deprecated`, because the ladder is the closed set of moves canon's four names allow",
    descriptorId,
    "PATCH",
    `${SD}/${descriptorId}`,
    { idempotency_key: "sd-patch-badstatus", expected_head: head1, status: "deprecated" },
    "odk_descriptor_status_transition_refused",
  );

  const patchA = await req("PATCH", `${SD}/${descriptorId}`, {
    idempotency_key: "sd-patch-A",
    expected_head: head1,
    display_name: "Intake review inbox (A)",
  });
  const head2 = (await chainState(descriptorId)).head;
  const patchB = await req("PATCH", `${SD}/${descriptorId}`, {
    idempotency_key: "sd-patch-B",
    expected_head: head2,
    status: "active",
  });
  ok(
    "an ordinary governed patch moves a declared field, RECOMPUTES the commitment so it follows the bytes, and admits a status transition the ladder allows",
    patchA.status === 200 &&
      patchA.j?.surface_descriptor?.display_name === "Intake review inbox (A)" &&
      registeredContentCommitment(patchA.j.surface_descriptor).digest ===
        patchA.j.surface_descriptor.content_hash &&
      patchB.status === 200 &&
      patchB.j?.surface_descriptor?.status === "active" &&
      registeredContentCommitment(patchB.j.surface_descriptor).digest ===
        patchB.j.surface_descriptor.content_hash,
    `A ${patchA.status} B ${patchB.status}`,
  );

  // -------------------------------------------------------------------------- historical retry
  const beforeRetry = await chainState(descriptorId);
  const retryA = await req("PATCH", `${SD}/${descriptorId}`, {
    idempotency_key: "sd-patch-A",
    expected_head: head1,
    display_name: "Intake review inbox (A)",
  });
  const afterRetry = await chainState(descriptorId);
  ok(
    "PATCH A RETRIED AFTER PATCH B LANDED REPLAYS ITS OWN ADMITTED FACT. Rebuilding A's payload on top of B's record made the bytes B-plus-A rather than the A this key admitted, so the substrate answered `same key, different bytes` — a refusal for a caller doing exactly what an ambiguous response requires. The key is resolved against history first, and the chain does not grow",
    retryA.status === 200 &&
      retryA.j?.replayed === true &&
      retryA.j?.surface_descriptor?.display_name === "Intake review inbox (A)" &&
      retryA.j?.surface_descriptor?.status === "draft" &&
      afterRetry.count === beforeRetry.count &&
      afterRetry.head === beforeRetry.head,
    `status ${retryA.status} replayed ${retryA.j?.replayed} chain ${beforeRetry.count}->${afterRetry.count}`,
  );
  const changedIntent = await req("PATCH", `${SD}/${descriptorId}`, {
    idempotency_key: "sd-patch-A",
    expected_head: head1,
    display_name: "A COMPLETELY DIFFERENT NAME",
  });
  const afterChanged = await chainState(descriptorId);
  ok(
    "the SAME KEY WITH A CHANGED INTENT is a typed conflict and appends nothing — a key replays one exact command and is never a way to receive a stored descriptor in answer to a different one",
    changedIntent.status === 409 &&
      code(changedIntent.j) === "odk_descriptor_replay_intent_changed" &&
      afterChanged.count === beforeRetry.count,
    `status ${changedIntent.status} code ${code(changedIntent.j)}`,
  );
  ok(
    "AND THE REPLAY REPLY IS BYTE-IDENTICAL TO PATCH A'S ORIGINAL REPLY — the same bare registered record, so a caller cannot tell a first admission from its own retry by the shape of what comes back",
    canonicalJson(retryA.j?.surface_descriptor) ===
      canonicalJson(patchA.j?.surface_descriptor) &&
      retryA.j?.surface_descriptor?.descriptor === undefined,
    `identical: ${canonicalJson(retryA.j?.surface_descriptor) === canonicalJson(patchA.j?.surface_descriptor)}`,
  );
  const falseAssertion = await req("PATCH", `${SD}/${descriptorId}`, {
    idempotency_key: "sd-patch-A",
    expected_head: head1,
    display_name: "Intake review inbox (A)",
    expected_content_hash: `sha256:${"0".repeat(64)}`,
  });
  ok(
    "a reused key asserting a FALSE `expected_content_hash` is refused by its own cause and appends nothing — replaying a stored descriptor never means the caller's claims about it go unexamined",
    falseAssertion.status >= 400 &&
      code(falseAssertion.j) === "odk_descriptor_content_hash_substituted" &&
      (await chainState(descriptorId)).count === beforeRetry.count,
    `status ${falseAssertion.status} code ${code(falseAssertion.j)}`,
  );
  const malformed = await req("PATCH", `${SD}/${descriptorId}`, {
    idempotency_key: "sd-patch-A",
    expected_head: head1,
    expected_content_hash: 12345,
  });
  ok(
    "a WRONG-TYPED assertion is refused as UNREADABLE rather than silently skipped — `Value::as_str` answers None for 'absent' and for 'present but a number', and reading a claim through it drops the second on the floor",
    malformed.status >= 400 && code(malformed.j) === "odk_descriptor_assertion_not_canonical",
    `status ${malformed.status} code ${code(malformed.j)}`,
  );

  // A CREATE RETRY AFTER ITS DEPENDENCY MOVED. The convergence source cannot be exercised live, but
  // the same ordering claim is: the ontology family advances, and the original create key still
  // replays its own admitted bytes rather than re-resolving a world that has moved.
  const successor = await req(
    "POST",
    OV,
    // A real successor declares NEW meaning: an edit that changes nothing is a replayed head rather
    // than a revision, by that owner's own rule.
    ontologyProposal({
      key: "sd-ontology-2",
      expectedHead: ontologyHead,
      entities: ["patient", "visit"],
    }),
  );
  const retryCreate = await req("POST", SD, {
    ...descriptorProposal(),
    idempotency_key: "sd-create-1",
  });
  ok(
    "THE CREATE KEY REPLAYS AFTER ITS BOUND FAMILY ADVANCED: a second ontology revision is admitted, and the original create returns its own frozen record bound to revision 1 — a retry does not re-resolve a world that moved underneath an already-admitted command",
    successor.status === 201 &&
      successor.j?.ontology_version?.ontology_id === REVISION_2 &&
      retryCreate.status === 200 &&
      retryCreate.j?.replayed === true &&
      canonicalJson(retryCreate.j?.surface_descriptor?.ontology_refs) ===
        canonicalJson([REVISION_1]),
    `successor ${successor.status} ${code(successor.j) || ""} ${String(successor.j?.error?.message ?? "").slice(0, 140)} retry ${retryCreate.status} replayed ${retryCreate.j?.replayed}`,
  );

  // ------------------------------------------------------- the index is destroyed, then corrupted
  const stateBeforeIndexDamage = await chainState(descriptorId);
  const row = findRow(descriptorId);
  ok(
    "PRECONDITION: the read-model row for this descriptor exists on disk, so destroying it is a real experiment rather than a no-op",
    row !== null && fs.existsSync(row),
    `row ${row ? path.relative(dataDir, row) : "(not found)"}`,
  );
  const rowBytes = row ? fs.readFileSync(row, "utf8") : "";
  const rowAsWritten = row ? JSON.parse(rowBytes) : null;
  // THE PROJECTION METADATA THE WRITE PATH LEFT BEHIND. This descriptor has been created and
  // patched, so its row is the product of a SUCCESSOR write — which is exactly where the metadata
  // used to be lost. A successor composed its row from `previous["created_at"]`, and a v2 record
  // does not carry `created_at` at all (the envelope does), so that read was JSON null and every
  // patched descriptor's row said it had never been created. Asserting it here fences the write
  // half; the rebuild assertions below fence the repair half against the same bytes.
  ok(
    "THE ROW A SUCCESSOR WRITE LEAVES CARRIES DERIVED, NON-NULL PROJECTION METADATA, and names the contract its contents were actually admitted under — a patched descriptor's row used to claim creation time `null`, because the successor read `created_at` off a record that has no such field",
    rowAsWritten?.schema_version === "ioi.hypervisor.odk.surface-descriptor-projection.v2" &&
      rowAsWritten?.descriptor_contract_id === V2 &&
      /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/u.test(rowAsWritten?.created_at ?? "") &&
      /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/u.test(rowAsWritten?.updated_at ?? "") &&
      rowAsWritten.created_at <= rowAsWritten.updated_at &&
      stateBeforeIndexDamage.count > 1,
    `created_at ${rowAsWritten?.created_at ?? "(none)"} updated_at ${rowAsWritten?.updated_at ?? "(none)"} revisions ${stateBeforeIndexDamage.count}`,
  );
  if (row) fs.rmSync(row);
  const afterDelete = await chainState(descriptorId);
  ok(
    "DELETING THE READ-MODEL ROW DOES NOT CHANGE THE ANSWER. A projection whose loss changes the answer is not a projection: the record, the head and the revision count are identical, and the reply reports the row's absence positively",
    afterDelete.status === 200 &&
      canonicalJson(afterDelete.record) === canonicalJson(stateBeforeIndexDamage.record) &&
      afterDelete.head === stateBeforeIndexDamage.head &&
      afterDelete.count === stateBeforeIndexDamage.count &&
      afterDelete.indexState === "absent_rebuilt_from_agentgres",
    `index ${afterDelete.indexState}`,
  );
  // THE REPAIR OF A DESTROYED ROW IS BYTE-IDENTICAL TO THE WRITE, metadata included. This is the
  // case the old repair could not do at all: with the row gone there was nothing left to copy the
  // timestamps from, so it wrote `created_at: null` / `updated_at: null` and called that a recovery.
  // A rebuilt row differing from the written one in ANY field means the projection is not a function
  // of the chain, whatever the record inside it says.
  const rebuildFromAbsent = await req("POST", `${SD}/${descriptorId}/rebuild-index`, {});
  const restoredRow = row && fs.existsSync(row) ? JSON.parse(fs.readFileSync(row, "utf8")) : null;
  ok(
    "REPAIRING A DESTROYED ROW RESTORES THE EXACT BYTES THE WRITE PATH PRODUCED, TIMESTAMPS INCLUDED: the projection metadata is DERIVED from the admitted history — the genesis admission and the latest one — so there is nothing left to lose when the row is. It used to be copied out of the row being repaired, which meant a destroyed row was rebuilt with `created_at: null` and a corrupted one was rebuilt with the corruption",
    rebuildFromAbsent.status === 200 &&
      rebuildFromAbsent.j?.index_state_before_rebuild === "absent_rebuilt_from_agentgres" &&
      restoredRow !== null &&
      canonicalJson(restoredRow) === canonicalJson(rowAsWritten),
    `before ${rebuildFromAbsent.j?.index_state_before_rebuild} created_at ${restoredRow?.created_at ?? "(none)"}`,
  );
  // NOW CORRUPT THE METADATA ALONE, leaving the canonical record inside the envelope untouched. A
  // comparison that only looked at the record would report this row as agreeing with the chain and
  // leave the damage in place; the row is compared WHOLE against the row a rebuild would write.
  if (row) {
    const metadataOnly = JSON.parse(JSON.stringify(rowAsWritten));
    metadataOnly.created_at = "1999-01-01T00:00:00Z";
    metadataOnly.updated_at = "1999-01-01T00:00:00Z";
    fs.writeFileSync(row, JSON.stringify(metadataOnly));
  }
  const afterMetadataCorrupt = await chainState(descriptorId);
  const rebuildFromMetadata = await req("POST", `${SD}/${descriptorId}/rebuild-index`, {});
  const afterMetadataRepair =
    row && fs.existsSync(row) ? JSON.parse(fs.readFileSync(row, "utf8")) : null;
  ok(
    "A ROW WHOSE METADATA ALONE DRIFTED IS STALE, NOT AGREEING: `agreed_with_agentgres` means byte-identical to what a repair would write, not merely carrying the right record. The corrupted stamps are reported as a disagreement and then DISCARDED by the repair rather than carried forward",
    afterMetadataCorrupt.indexState === "stale_rebuilt_from_agentgres" &&
      canonicalJson(afterMetadataCorrupt.record) === canonicalJson(stateBeforeIndexDamage.record) &&
      rebuildFromMetadata.status === 200 &&
      canonicalJson(afterMetadataRepair) === canonicalJson(rowAsWritten) &&
      afterMetadataRepair?.created_at !== "1999-01-01T00:00:00Z",
    `index ${afterMetadataCorrupt.indexState} repaired created_at ${afterMetadataRepair?.created_at ?? "(none)"}`,
  );
  if (row) {
    fs.mkdirSync(path.dirname(row), { recursive: true });
    const corrupted = JSON.parse(rowBytes);
    if (corrupted.descriptor) corrupted.descriptor.display_name = "CORRUPTED BY THE VERIFIER";
    fs.writeFileSync(row, JSON.stringify(corrupted));
  }
  const afterCorrupt = await chainState(descriptorId);
  ok(
    "A CORRUPTED ROW IS NEVER AUTHORITATIVE: the answer still comes from the chain, the corruption does not appear in it, and the disagreement is reported rather than served",
    afterCorrupt.status === 200 &&
      canonicalJson(afterCorrupt.record) === canonicalJson(stateBeforeIndexDamage.record) &&
      afterCorrupt.record?.display_name !== "CORRUPTED BY THE VERIFIER" &&
      afterCorrupt.indexState === "stale_rebuilt_from_agentgres",
    `index ${afterCorrupt.indexState}`,
  );
  const rebuild = await req("POST", `${SD}/${descriptorId}/rebuild-index`, {});
  const afterRebuild = await chainState(descriptorId);
  ok(
    "REBUILDING THE INDEX IS DETERMINISTIC AND REPORTS WHAT IT REPAIRED: the row is restored to exactly the bytes the chain implies, the reply names the state it found, and a second read now agrees",
    rebuild.status === 200 &&
      rebuild.j?.index_state_before_rebuild === "stale_rebuilt_from_agentgres" &&
      afterRebuild.indexState === "agreed_with_agentgres" &&
      canonicalJson(afterRebuild.record) === canonicalJson(stateBeforeIndexDamage.record),
    `before ${rebuild.j?.index_state_before_rebuild} after ${afterRebuild.indexState}`,
  );
  // AND IT IS IDEMPOTENT AND HONEST ABOUT A NO-OP. Repairing a healthy row must change nothing and
  // must SAY it found nothing to repair, or an operator cannot tell a recovery from a no-op — which
  // is the exact confusion the v1 silent no-op created.
  const rebuildAgain = await req("POST", `${SD}/${descriptorId}/rebuild-index`, {});
  const afterSecondRebuild =
    row && fs.existsSync(row) ? JSON.parse(fs.readFileSync(row, "utf8")) : null;
  ok(
    "REPAIRING AN ALREADY-HEALTHY ROW IS AN IDEMPOTENT NO-OP THAT SAYS SO: three repairs from three different starting states — absent, metadata-corrupt, record-corrupt — all converge on ONE byte-string, and a fourth changes nothing",
    rebuildAgain.status === 200 &&
      rebuildAgain.j?.index_state_before_rebuild === "agreed_with_agentgres" &&
      canonicalJson(afterSecondRebuild) === canonicalJson(rowAsWritten),
    `before ${rebuildAgain.j?.index_state_before_rebuild}`,
  );

  // ------------------------------------------------------------------------------------ restart
  await stopDaemon();
  await startDaemon();
  const afterRestart = await chainState(descriptorId);
  const rowAfterRestart =
    row && fs.existsSync(row) ? JSON.parse(fs.readFileSync(row, "utf8")) : null;
  ok(
    "DURABLE TRUTH SURVIVES A RESTART: after the process is stopped and started over the same data directory, the descriptor projects byte-identically from its own admitted history",
    afterRestart.status === 200 &&
      canonicalJson(afterRestart.record) === canonicalJson(stateBeforeIndexDamage.record) &&
      afterRestart.head === stateBeforeIndexDamage.head &&
      afterRestart.count === stateBeforeIndexDamage.count,
    `count ${afterRestart.count}`,
  );
  ok(
    "AND SO DOES THE PROJECTION METADATA: the derived stamps are a function of the admitted history, not of the process that happened to be running, so a restart neither moves them nor makes the row disagree with the chain",
    afterRestart.indexState === "agreed_with_agentgres" &&
      canonicalJson(rowAfterRestart) === canonicalJson(rowAsWritten),
    `index ${afterRestart.indexState} created_at ${rowAfterRestart?.created_at ?? "(none)"}`,
  );

  // --------------------------------------------------------------------------- the two consumers
  // The manifest is admitted FIRST, because the packaging lane requires the DomainApp to bind one
  // that already includes this descriptor — the app-shape contract and the kit that ships it. The
  // manifest's own `ontology_refs` are the ODK DomainOntology family, which is a DIFFERENT family
  // from the M05.1 revisions the descriptor binds; one is the dev kit's authoring object and the
  // other is the admitted semantic revision, and this gate does not conflate them.
  const odkOntology = await req("POST", "/v1/hypervisor/odk/domain-ontologies", {
    owner_ref: OWNER,
    idempotency_key: "sd-odk-ontology-1",
    domain: "acme-clinic intake",
  });
  const odkOntologyRef = odkOntology.j?.domain_ontology?.ref ?? odkOntology.j?.ontology?.ref ?? "";
  const manifest = await req("POST", "/v1/hypervisor/odk/manifests", {
    owner_ref: OWNER,
    idempotency_key: "sd-manifest-1",
    name: "intake-kit",
    ontology_refs: [odkOntologyRef],
    surface_descriptor_refs: [descriptorRef],
  });
  // The same version-aware mechanic as the DomainApp's: M05.6's manifest successor names itself
  // `odk_manifest_id` once, where the predecessor carried a bare `id` and a `ref` beside it.
  const manifestRecord =
    manifest.j?.odk_manifest ?? manifest.j?.manifest ?? manifest.j?.odk ?? {};
  const manifestRef = manifestRecord.odk_manifest_id ?? manifestRecord.ref ?? "";
  ok(
    "PRECONDITION: an ODK manifest including this descriptor is admitted, so the packaging lane has the complete source mesh it requires",
    manifest.status === 201 && manifestRef.startsWith("odk://"),
    `status ${manifest.status} ref ${manifestRef || "(none)"} ${code(manifest.j) || ""} ${String(manifest.j?.error?.message ?? manifest.j?.message ?? "").slice(0, 200)}`,
  );
  const domainApp = await req("POST", "/v1/hypervisor/domain-apps", {
    owner_ref: OWNER,
    idempotency_key: "sd-dapp-1",
    name: "Intake review app",
    surface_descriptor_ref: descriptorRef,
    odk_manifest_ref: manifestRef,
  });
  const app = domainApp.j?.domain_app ?? {};
  // VERSION-AWARE MECHANICS ONLY. M05.6 registered the DomainApp family and its successor carries
  // identity ONCE, as canon's scheme-prefixed `domain_app_id`; the stored predecessor carried it
  // twice, as a bare id plus a `domain_app_ref` that could disagree. Reading both here keeps this
  // gate's claims and their names exactly as they were while it drives whichever contract the build
  // under test authors.
  const appRef = app.domain_app_id ?? app.domain_app_ref;
  ok(
    "THE DOMAIN APP PRESERVES THE CANONICAL LINEAGE. Reading v1's names only, a DomainApp over a v2 descriptor derived an EMPTY provenance snapshot and recorded it — nothing failed, and the app said this surface binds no ontology and no data recipe",
    domainApp.status === 201 &&
      (app.ontology_refs ?? []).includes(REVISION_1) &&
      (app.data_recipe_refs ?? []).includes(`data-recipe://${NS}/intake-normalise/revision/1`),
    `status ${domainApp.status} ontology_refs ${canonicalJson(app.ontology_refs ?? [])}`,
  );
  ok(
    "and what the DESCRIPTOR contributed to that lineage is an EXACT ADMITTED REVISION, never a family head that would re-mean itself after the snapshot was taken — the ODK dev-kit ontology the MANIFEST contributes is a different family and is not counted as one",
    (app.ontology_refs ?? [])
      .filter((ref) => ref.startsWith(`ontology://${NS}/`))
      .every((ref) => ref.includes("/revision/")) &&
      (app.ontology_refs ?? []).filter((ref) => ref.includes("/revision/")).length === 1,
    canonicalJson(app.ontology_refs ?? []),
  );

  const pkg = await req("POST", "/v1/hypervisor/packages", {
    package_id: "intake-review",
    owner_ref: OWNER,
    domain_app_ref: appRef,
    idempotency_key: "sd-package-1",
  });
  const candidate = pkg.j?.package?.record ?? {};
  ok(
    "THE PACKAGE REGISTRY CAN SEE A v2 DESCRIPTOR AT ALL. It looked the source up by a `ref` field a v2 does not have, so every correctly-bound descriptor was unresolvable in the one lane where a surface becomes durable product inventory — and the refusal read as 'you have not created it yet'. It now names the descriptor by its canonical identity",
    pkg.status === 201 && candidate.surface_descriptor_ref === descriptorRef,
    `status ${pkg.status} ref ${candidate.surface_descriptor_ref ?? "(none)"} ${code(pkg.j) || ""} ${String(pkg.j?.error?.message ?? "").slice(0, 160)}`,
  );
  ok(
    "and it freezes the DESCRIPTOR OWNER'S OWN COMMITMENT rather than minting a second number beside it, saying in the record whose number it carries and which contract the source was admitted under",
    candidate?.source_snapshots?.surface_descriptor_content_hash ===
      (await chainState(descriptorId)).record?.content_hash &&
      candidate?.source_snapshots?.surface_descriptor_content_hash_source ===
        "descriptor_owner_committed" &&
      candidate?.source_snapshots?.surface_descriptor_schema_version ===
        "ioi.ontology-surface-descriptor.v2",
    `${candidate?.source_snapshots?.surface_descriptor_content_hash_source ?? "(none)"} hash ${candidate?.source_snapshots?.surface_descriptor_content_hash ?? "(none)"}`,
  );

  // ------------------------------------------------------------------- withdrawal, and its retry
  const headBeforeDelete = (await chainState(descriptorId)).head;
  const withdraw = await req("DELETE", `${SD}/${descriptorId}`, null, {
    headers: {
      "x-ioi-idempotency-key": "sd-delete-1",
      "x-ioi-expected-head": headBeforeDelete,
    },
  });
  const afterWithdraw = await chainState(descriptorId);
  ok(
    "A WITHDRAWAL IS A REGISTERED-VALID SUCCESSOR IN CANON'S OWN VOCABULARY: v1 wrote a `deleted` tombstone, which is a fifth status the canonical envelope does not define, and v2 converges it onto `revoked` with the commitment recomputed so it follows the bytes",
    withdraw.status === 200 &&
      afterWithdraw.record?.status === "revoked" &&
      registeredContentCommitment(afterWithdraw.record).digest ===
        afterWithdraw.record?.content_hash &&
      afterWithdraw.count === headBeforeDelete !== null,
    `status ${withdraw.status} -> ${afterWithdraw.record?.status}`,
  );
  const countAfterWithdraw = afterWithdraw.count;
  const retryWithdraw = await req("DELETE", `${SD}/${descriptorId}`, null, {
    headers: {
      "x-ioi-idempotency-key": "sd-delete-1",
      "x-ioi-expected-head": headBeforeDelete,
    },
  });
  const afterRetryWithdraw = await chainState(descriptorId);
  ok(
    "AN EXACT DELETE RETRY REPLAYS ITS OWN WITHDRAWAL. The tombstone was derived from the CURRENT record, so a delete retried after any other successor produced different bytes under the same key and was refused; the key is now resolved against history first",
    retryWithdraw.status === 200 &&
      retryWithdraw.j?.replayed === true &&
      afterRetryWithdraw.count === countAfterWithdraw &&
      afterRetryWithdraw.head === afterWithdraw.head,
    `status ${retryWithdraw.status} replayed ${retryWithdraw.j?.replayed} chain ${countAfterWithdraw}->${afterRetryWithdraw.count}`,
  );
  const listAfterWithdraw = await req("GET", SD, null, { as: "A" });
  ok(
    "a withdrawn descriptor LEAVES THE LIST BUT IS COUNTED, so a corpus that shrank to nothing is distinguishable from one that was never populated — and the row is KEPT carrying the withdrawal rather than removed",
    listAfterWithdraw.status === 200 &&
      (listAfterWithdraw.j?.surface_descriptors ?? []).length === 0 &&
      listAfterWithdraw.j?.census?.withdrawn_and_hidden === 1 &&
      listAfterWithdraw.j?.census?.authorized_for_this_caller === 1,
    `listed ${(listAfterWithdraw.j?.surface_descriptors ?? []).length} withdrawn ${listAfterWithdraw.j?.census?.withdrawn_and_hidden}`,
  );
  // THE COMPLETE INVENTORY IS ADMINISTRATIVE EVIDENCE, taken from the data directory this verifier
  // holds rather than from a tenant-scoped reply. That is the whole reason the global counts left
  // the list: an operator with the substrate can enumerate the corpus, and an ordinary authenticated
  // caller may not — so the withdrawn descriptor the tenant view correctly hides is still fully
  // accounted for here, by someone entitled to see it.
  const withdrawnRow = findRow(descriptorId);
  const withdrawnOnDisk = withdrawnRow
    ? JSON.parse(fs.readFileSync(withdrawnRow, "utf8"))
    : null;
  ok(
    "OFFLINE ADMINISTRATIVE INVENTORY: the descriptor the tenant-scoped list correctly hides is still fully accounted for by direct substrate enumeration, carrying its withdrawn status — so removing the global counts from the reply narrowed WHO may count the corpus, not whether it can be counted",
    withdrawnRow !== null &&
      (withdrawnOnDisk?.descriptor ?? withdrawnOnDisk)?.status === "revoked" &&
      (listAfterWithdraw.j?.surface_descriptors ?? []).length === 0,
    `on disk: ${(withdrawnOnDisk?.descriptor ?? withdrawnOnDisk)?.status ?? "(absent)"}, tenant view: ${(listAfterWithdraw.j?.surface_descriptors ?? []).length}`,
  );
  ok(
    "A WITHDRAWAL MOVES THE LAST-UPDATE STAMP AND LEAVES THE CREATION STAMP EXACTLY WHERE IT WAS. Both are derived from the admitted history — genesis and latest — so a successor cannot rewrite when this descriptor came into existence, and it cannot lose the fact either: the withdrawal used to write BOTH as null",
    withdrawnOnDisk?.created_at === rowAsWritten?.created_at &&
      withdrawnOnDisk?.updated_at >= rowAsWritten?.updated_at &&
      typeof withdrawnOnDisk?.updated_at === "string" &&
      (await chainState(descriptorId)).indexState === "agreed_with_agentgres",
    `created_at ${withdrawnOnDisk?.created_at ?? "(none)"} (was ${rowAsWritten?.created_at ?? "(none)"}) updated_at ${withdrawnOnDisk?.updated_at ?? "(none)"}`,
  );
  const packageWithdrawn = await req("POST", "/v1/hypervisor/packages", {
    package_id: "intake-review-2",
    owner_ref: OWNER,
    domain_app_ref: appRef,
    idempotency_key: "sd-package-withdrawn",
  });
  ok(
    "A WITHDRAWN DESCRIPTOR DOES NOT BECOME DURABLE PRODUCT INVENTORY: the packaging lane refuses it. The record-directory sweep it replaces could not see status at all, so a revoked descriptor packaged exactly like a live one",
    packageWithdrawn.status >= 400 &&
      code(packageWithdrawn.j) === "package_surface_descriptor_withdrawn",
    `status ${packageWithdrawn.status} code ${code(packageWithdrawn.j)}`,
  );
}

// ------------------------------------------------------------------------------- mutation harness

const MUTANTS = [
  {
    id: "binding-set-equality-degraded-to-counting",
    reddens:
      "THE EQUAL-COUNT SUBSTITUTION IS A REAL CASE THE ARITHMETIC CANNOT SEE: its two counts agree, its entries are unique, its commitment is current — and the owning set and the bound set are DIFFERENT SETS, which only exact set equality refuses",
    source: path.join(SCHEMAS, "fixtures/ontology-surface-descriptor-v2/negative-binding-set-equal-count-substitution.json"),
    from: '"ontology_revision_ref": "ontology://acme-clinic/billing-codes/revision/9"',
    to: '"ontology_revision_ref": "ontology://acme-clinic/patient-intake/revision/4"',
  },
  {
    id: "list-takes-no-identity",
    reddens:
      "THE LIST IS AUTHENTICATED AND TENANT-SAFE. It previously took no identity at all and returned every descriptor in the process — every owner, every binding, every surface ref — to any caller who asked. An anonymous caller is now refused, and a different principal sees none of this one's descriptors",
    source: ROUTE_SOURCE,
    // RESTORE THE ORIGINAL DEFECT: an unauthenticated caller is served instead of refused.
    //
    // An earlier draft swapped the identity passed to `authorized_request_resource_refs` for the
    // local-development operator. That went red OFF TARGET: A's own list emptied, so the
    // owner's-list assertion failed while the anonymous caller was still correctly refused — the
    // targeted claim was never perturbed. A mutant must break the sentence it is filed under, not
    // merely break something.
    from: "    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {\n        Ok(identity) => identity,\n        Err(error) => return odk_scope_refusal(error),\n    };\n    let authorized = match super::substrate_store::authorized_request_resource_refs(",
    to: "    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {\n        Ok(identity) => identity,\n        Err(_) => super::substrate_store::RequestIdentity::local_development_operator(\"operator\"),\n    };\n    let authorized = match super::substrate_store::authorized_request_resource_refs(",
  },
  {
    id: "patch-replay-never-resolved-from-history",
    reddens:
      "PATCH A RETRIED AFTER PATCH B LANDED REPLAYS ITS OWN ADMITTED FACT. Rebuilding A's payload on top of B's record made the bytes B-plus-A rather than the A this key admitted, so the substrate answered `same key, different bytes` — a refusal for a caller doing exactly what an ambiguous response requires. The key is resolved against history first, and the chain does not grow",
    source: ROUTE_SOURCE,
    from: "    if !idempotency_key.is_empty() {\n        if let Some(prior) = history\n            .iter()\n            .find(|entry| entry.operation.idem_key == idempotency_key)\n        {\n            if let Some(field) = descriptor_patch_intent_divergence(&prior.operation.payload, &body)",
    to: "    if false && !idempotency_key.is_empty() {\n        if let Some(prior) = history\n            .iter()\n            .find(|entry| entry.operation.idem_key == idempotency_key)\n        {\n            if let Some(field) = descriptor_patch_intent_divergence(&prior.operation.payload, &body)",
  },
  {
    id: "replay-never-compares-intent",
    reddens:
      "the SAME KEY WITH A CHANGED INTENT is a typed conflict and appends nothing — a key replays one exact command and is never a way to receive a stored descriptor in answer to a different one",
    source: ROUTE_SOURCE,
    from: "fn descriptor_patch_intent_divergence(record: &Value, body: &Value) -> Option<&'static str> {",
    to: "fn descriptor_patch_intent_divergence(record: &Value, body: &Value) -> Option<&'static str> {\n    if record.is_object() && body.is_object() {\n        return None;\n    }",
  },
  {
    id: "replay-path-skips-the-caller-assertion-checker",
    reddens:
      "a reused key asserting a FALSE `expected_content_hash` is refused by its own cause and appends nothing — replaying a stored descriptor never means the caller's claims about it go unexamined",
    source: ROUTE_SOURCE,
    from: "            if let Some(response) = descriptor_assertion_divergence(&prior.operation.payload, &body)\n            {\n                return response;\n            }\n            return descriptor_replay_reply(&descriptor_ref, prior);\n        }\n    }\n\n    let previous = latest.operation.payload.clone();",
    to: "            if let Some(response) = descriptor_assertion_divergence(&prior.operation.payload, &body)\n                .filter(|_| false)\n            {\n                return response;\n            }\n            return descriptor_replay_reply(&descriptor_ref, prior);\n        }\n    }\n\n    let previous = latest.operation.payload.clone();",
  },
  {
    id: "wrong-typed-assertion-reads-as-absent",
    reddens:
      "a WRONG-TYPED assertion is refused as UNREADABLE rather than silently skipped — `Value::as_str` answers None for 'absent' and for 'present but a number', and reading a claim through it drops the second on the floor",
    source: ROUTE_SOURCE,
    from: "        Some(_) => Asserted::Malformed,\n    }\n}",
    to: "        Some(_) => Asserted::Absent,\n    }\n}",
  },
  {
    id: "ontology-binding-accepts-a-family-head",
    reddens:
      "a MUTABLE FAMILY HEAD is refused as an ontology binding — durable product inventory may not silently re-mean itself when the family advances",
    source: ROUTE_SOURCE,
    from: "            data_dir, identity, reference,\n        )",
    to: "            data_dir,\n            identity,\n            &format!(\"{reference}/revision/1\").replace(\"/revision/1/revision/1\", \"/revision/1\"),\n        )",
  },
  {
    id: "the-row-is-consulted-for-the-answer",
    reddens:
      "A CORRUPTED ROW IS NEVER AUTHORITATIVE: the answer still comes from the chain, the corruption does not appear in it, and the disagreement is reported rather than served",
    source: ROUTE_SOURCE,
    from: "    let row = load(data_dir, KIND_SD, id);\n    let index_state = match row.as_ref() {",
    to: '    let row = load(data_dir, KIND_SD, id);\n    let record = row.as_ref().and_then(|row| row.get("descriptor").cloned()).unwrap_or(record);\n    let index_state = match row.as_ref() {',
  },
  {
    id: "projection-metadata-copied-from-the-row-it-repairs",
    reddens:
      "THE ROW A SUCCESSOR WRITE LEAVES CARRIES DERIVED, NON-NULL PROJECTION METADATA, and names the contract its contents were actually admitted under — a patched descriptor's row used to claim creation time `null`, because the successor read `created_at` off a record that has no such field",
    source: ROUTE_SOURCE,
    // The exact historical defect: recover the creation stamp FROM the row instead of deriving it
    // from the genesis admission. A repair then carries forward whatever the damage said, and a
    // destroyed row rebuilds with nothing at all — which is what "deterministic" has to exclude.
    from: "    let projected_created_at = history\n        .first()\n        .map(|entry| admitted_stamp_ms(entry.operation.recorded_at_ms))\n        .unwrap_or_default();",
    to: '    let projected_created_at = load(data_dir, KIND_SD, id)\n        .and_then(|row| row.get("created_at").and_then(Value::as_str).map(str::to_string))\n        .unwrap_or_default();',
  },
  {
    id: "index-agreement-ignores-projection-metadata",
    reddens:
      "A ROW WHOSE METADATA ALONE DRIFTED IS STALE, NOT AGREEING: `agreed_with_agentgres` means byte-identical to what a repair would write, not merely carrying the right record. The corrupted stamps are reported as a disagreement and then DISCARDED by the repair rather than carried forward",
    source: ROUTE_SOURCE,
    // Compare only the canonical record inside the row, which is what this did before: a row whose
    // metadata was damaged then reported agreement and the damage was never repaired.
    from: '        Some(row) if *row == expected => "agreed_with_agentgres",',
    to: '        Some(row)\n            if row.get("descriptor").unwrap_or(row) == expected.get("descriptor").unwrap_or(&expected) =>\n        {\n            "agreed_with_agentgres"\n        }',
  },
  {
    id: "v1-row-stored-under-the-v2-contract-id",
    reddens:
      "A STORED v1 IS WITHDRAWN IN ITS OWN VERSION'S SHAPE, AND THE ROW IS REPAIRED TO THE SAME BYTES: the delete path built a valid v1 tombstone and then persisted it through an envelope hard-coded to the v2 contract, so the row on disk announced `…/ontology-surface-descriptor/v2` over a record admitted as v1 — while the documented repair wrote that same descriptor in a different shape. Two shapes for one admitted state, invisible because every read answers from the chain",
    source: ROUTE_SOURCE,
    // Reinstate the hard-coded v2 envelope for a v1 record: the projection announces a contract the
    // bytes inside it were never admitted under.
    from: '        Some(DESCRIPTOR_V1_SCHEMA_VERSION) => {\n            let mut inlined = record.clone();\n            inlined["created_at"] = json!(created_at);\n            inlined["updated_at"] = json!(updated_at);\n            Ok(inlined)\n        }',
    to: '        Some(DESCRIPTOR_V1_SCHEMA_VERSION) => Ok(json!({\n            "schema_version": DESCRIPTOR_PROJECTION_SCHEMA,\n            "descriptor_contract_id": DESCRIPTOR_V2_CONTRACT_ID,\n            "descriptor": record,\n            "created_at": created_at,\n            "updated_at": updated_at,\n        })),',
  },
  {
    id: "patch-allowlist-reopened-to-every-field",
    reddens:
      "a BINDING IS NOT PATCHABLE, and the refusal NAMES THE FIELD rather than reporting a registered-validity failure: a descriptor binds exact admitted revisions, so moving one describes a different surface",
    source: ROUTE_SOURCE,
    // Reopen the closed request set: every field is accepted, so a binding reaches the patch body.
    from: "        if allowed.contains(&name) {\n            continue;\n        }",
    to: "        if allowed.contains(&name) || true {\n            continue;\n        }",
  },
  {
    id: "unknown-request-field-silently-ignored",
    reddens:
      "an UNKNOWN REQUEST FIELD is refused by name, not ignored. Both routes read what they wanted and dropped the rest, so a misspelled binding member was answered 'the correctly-spelled one is absent', and an AUTHORITY-LOOKING field was answered 201 with a record containing no such thing — indistinguishable from one where something had been granted",
    source: ROUTE_SOURCE,
    // SILENTLY ACCEPT the unrecognised field, which is the defect itself. An earlier draft wrapped
    // the same refusal as `Ok(()).and(Err(...))` — which evaluates to that identical `Err`, so the
    // mutant changed nothing and could only have SURVIVED, reporting a fence as proven when nothing
    // had been perturbed. A mutant that does not alter behaviour is not evidence about a gate; it is
    // evidence about the harness, and the wrong kind.
    from: '        return Err(descriptor_refuse(\n            "odk_descriptor_request_field_unknown",',
    to: '        if true {\n            continue;\n        }\n        return Err(descriptor_refuse(\n            "odk_descriptor_request_field_unknown",',
  },
  {
    id: "nonclaim-members-filtered-instead-of-refused",
    reddens:
      "a NON-STRING nonclaim member is refused rather than filtered out: `filter_map` silently DISCARDED it and admitted a record whose nonclaim set was not the one the caller sent, and quietly editing what a record says it does not confer is the one edit that must never be silent",
    source: ROUTE_SOURCE,
    from: "                let Some(token) = entry.as_str() else {",
    to: "                let Some(token) = entry.as_str().or(Some(\"authority\")) else {",
  },
  {
    id: "v1-reads-are-never-validated",
    reddens:
      "THE HISTORICAL v1 UPGRADE IS EXECUTED: a contract-valid stored v1 and its real M05.1 prerequisite are seeded through their owners' own admission code, the full production builder converges them, and the record survives a restart and replays its key exactly after the source moves — the one path no HTTP request can reach, because authoring a v1 is closed by design",
    source: ROUTE_SOURCE,
    // Reinstate the old asymmetry: only v2 is validated on the read path, and a stored v1 is served
    // unexamined — which the upgrade test's registered-v1 assertion catches.
    from: "        DESCRIPTOR_V1_SCHEMA_VERSION => DESCRIPTOR_V1_CONTRACT_ID,",
    to: "        DESCRIPTOR_V1_SCHEMA_VERSION => DESCRIPTOR_V2_CONTRACT_ID,",
  },
  {
    id: "rebuild-index-no-ops-on-v1",
    reddens:
      "THE HISTORICAL v1 UPGRADE IS EXECUTED: a contract-valid stored v1 and its real M05.1 prerequisite are seeded through their owners' own admission code, the full production builder converges them, and the record survives a restart and replays its key exactly after the source moves — the one path no HTTP request can reach, because authoring a v1 is closed by design",
    source: ROUTE_SOURCE,
    // The silent no-op this repaired: answer 200 and write nothing for a non-v2 row.
    from: "    persist_required(\n        data_dir,\n        KIND_SD,\n        id,\n        &row,\n        \"odk_surface_descriptor_persistence_failed\",\n    )?;\n    Ok(resolved)",
    to: "    if resolved.schema_version == DESCRIPTOR_V2_SCHEMA_VERSION {\n        persist_required(\n            data_dir,\n            KIND_SD,\n            id,\n            &row,\n            \"odk_surface_descriptor_persistence_failed\",\n        )?;\n    }\n    Ok(resolved)",
  },
  {
    id: "list-census-leaks-the-global-corpus",
    reddens:
      "THE CENSUS LEAKS NO CROSS-TENANT COUNT. It briefly carried the global descriptor-stream total and the number this caller was NOT authorized for — facts about other tenants, answered to anyone authenticated, so polling the endpoint would tell you when a competitor created a descriptor and how many they hold. Every number is now scoped to the caller, and B's own view is honestly empty",
    source: ROUTE_SOURCE,
    from: '                "census_scope": "this_caller_only",',
    to: '                "census_scope": "this_caller_only",\n                "read_model_rows_present": read_record_dir(&st.data_dir, KIND_SD).len(),',
  },
  {
    id: "status-transitions-unfenced",
    reddens:
      "an UNDECLARED STATUS TRANSITION is refused: `draft` never jumps to `deprecated`, because the ladder is the closed set of moves canon's four names allow",
    source: ROUTE_SOURCE,
    from: "        if requested != current && !DESCRIPTOR_STATUS_TRANSITIONS.contains(&(current, requested)) {",
    to: "        if false && requested != current && !DESCRIPTOR_STATUS_TRANSITIONS.contains(&(current, requested)) {",
  },
  {
    id: "convergence-accepts-a-v2-source",
    reddens:
      "a CONVERGENCE FROM A v2 is refused: only the registered, deprecated v1 is a legitimate source, and a record is only ever hashed under the contract it was admitted under",
    source: ROUTE_SOURCE,
    from: "            if predecessor.schema_version != DESCRIPTOR_V1_SCHEMA_VERSION {",
    to: "            if false && predecessor.schema_version != DESCRIPTOR_V1_SCHEMA_VERSION {",
  },
  {
    id: "v1-authoring-silently-downgraded",
    reddens:
      "AUTHORING AT v1 IS CLOSED: the predecessor carries none of the binding set, so it is refused rather than downgraded, and the refusal names the successor",
    source: ROUTE_SOURCE,
    from: "        Some(Value::String(declared)) if declared == DESCRIPTOR_V2_SCHEMA_VERSION => {}",
    to: "        Some(Value::String(declared)) if !declared.is_empty() => {}",
  },
  {
    id: "domain-app-lineage-reads-only-v1-names",
    reddens:
      "THE DOMAIN APP PRESERVES THE CANONICAL LINEAGE. Reading v1's names only, a DomainApp over a v2 descriptor derived an EMPTY provenance snapshot and recorded it — nothing failed, and the app said this surface binds no ontology and no data recipe",
    source: DOMAIN_APP_SOURCE,
    from: '    for r in arr_strs(descriptor, "ontology_refs") {\n        push_unique(&mut ontology_refs, &r);\n    }',
    to: '    for r in arr_strs(descriptor, "ontology_refs").into_iter().take(0) {\n        push_unique(&mut ontology_refs, &r);\n    }',
  },
  {
    id: "package-mints-a-second-commitment",
    reddens:
      "and it freezes the DESCRIPTOR OWNER'S OWN COMMITMENT rather than minting a second number beside it, saying in the record whose number it carries and which contract the source was admitted under",
    source: PACKAGE_SOURCE,
    from: "        Some(committed) => (json!(committed), \"descriptor_owner_committed\"),",
    to: "        Some(_) => (json!(digest(&source.descriptor)?), \"descriptor_owner_committed\"),",
  },
  {
    id: "package-does-not-see-a-withdrawal",
    reddens:
      "A WITHDRAWN DESCRIPTOR DOES NOT BECOME DURABLE PRODUCT INVENTORY: the packaging lane refuses it. The record-directory sweep it replaces could not see status at all, so a revoked descriptor packaged exactly like a live one",
    source: PACKAGE_SOURCE,
    from: '    if matches!(resolved.status.as_str(), "revoked" | "deleted") {',
    to: '    if false && matches!(resolved.status.as_str(), "revoked" | "deleted") {',
  },
];

let activeChild = null;

function runChild(command, args, { env } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: ROOT,
      env: env ? { ...process.env, ...env } : process.env,
      stdio: ["ignore", "pipe", "pipe"],
      // Its own process group, so an interrupt can kill the whole tree: `cargo` spawns `rustc`, and
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

const RUST_SOURCES = new Set([ROUTE_SOURCE, DOMAIN_APP_SOURCE, PACKAGE_SOURCE]);

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
/// A `finally` block does not run when the process is killed, so the snapshot goes to DISK before
/// the first mutation, the signal handlers restore from it, and a later run repairs an inherited one
/// before planting anything.
const SNAPSHOT_DIR = path.join(ROOT, "target", "ontology-surface-descriptor-mutation-snapshot");
const LEDGER = path.join(ROOT, "target", "ontology-surface-descriptor-mutation-ledger.json");

const snapshotPathFor = (source) =>
  path.join(SNAPSHOT_DIR, `${path.basename(source)}.pristine`);

function restoreFromDiskSnapshot() {
  if (!fs.existsSync(SNAPSHOT_DIR)) return [];
  const restored = [];
  for (const entry of fs.readdirSync(SNAPSHOT_DIR)) {
    if (!entry.endsWith(".pristine")) continue;
    const target = [...new Set(MUTANTS.map((m) => m.source))].find(
      (source) => path.basename(source) === entry.slice(0, -".pristine".length),
    );
    if (!target) continue;
    const body = fs.readFileSync(path.join(SNAPSHOT_DIR, entry), "utf8");
    if (fs.readFileSync(target, "utf8") !== body) {
      fs.writeFileSync(target, body);
      restored.push(target);
    }
  }
  fs.rmSync(SNAPSHOT_DIR, { recursive: true, force: true });
  return restored;
}

/// THIS FILE'S OWN BYTES, BOUND INTO EVERY ROW. A battery is only ever evidence about the harness
/// that produced it: which defects are declared, and which live assertion each claims to redden.
/// Editing this file stales every row, which is correct. It is bound, never managed — nothing plants
/// into it and nothing restores it.
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

function evidenceDigests() {
  return {
    ...Object.fromEntries(
      [...new Set(MUTANTS.map((mutant) => mutant.source))].map((file) => [
        path.relative(ROOT, file),
        crypto.createHash("sha256").update(fs.readFileSync(file, "utf8")).digest("hex"),
      ]),
    ),
    harness: HARNESS_DIGEST,
  };
}

function recordLedger(rows, digests) {
  const ledger = readLedger();
  for (const row of rows) ledger[row.id] = { ...row, sources: digests };
  fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
  fs.writeFileSync(LEDGER, `${JSON.stringify(ledger, null, 2)}\n`);
}

/// Adjudicate the union of every recorded chunk against the DECLARED mutant set. The declared set is
/// the authority: a mutant that was never run has no row, and a missing row is a failure rather than
/// an absence nobody notices.
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
    `\nontology-surface-invariant-11 mutation battery: ${onTarget}/${MUTANTS.length} RED ON TARGET; ${stale} stale row(s); ${missing} missing row(s)\n`,
  );
  process.exit(onTarget === MUTANTS.length && stale === 0 && missing === 0 ? 0 : 1);
}

async function runMutationBattery() {
  const unknown = ONLY.filter((id) => !MUTANTS.some((mutant) => mutant.id === id));
  if (unknown.length > 0) {
    throw new Error(`--only names mutants this battery does not declare: ${unknown.join(", ")}`);
  }
  const selected = ONLY.length > 0 ? MUTANTS.filter((mutant) => ONLY.includes(mutant.id)) : MUTANTS;

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
  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  for (const [file, body] of originals) fs.writeFileSync(snapshotPathFor(file), body);
  for (const [file, digest] of digests) {
    process.stdout.write(`PRISTINE  ${path.relative(ROOT, file)} sha256:${digest}\n`);
  }

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
    `CHUNK  ${selected.length}/${MUTANTS.length} mutant(s) under harness sha256:${HARNESS_DIGEST}\n`,
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
      let built = true;
      // A fixture mutant needs no rebuild: the corpus is read from disk by this verifier.
      if (RUST_SOURCES.has(mutant.source)) {
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
  // A row is recorded ONLY after every source came back byte-identical. A chunk that could not
  // restore the tree has no business contributing evidence to a battery summary.
  if (restored) recordLedger(rows, evidenceDigests());
  for (const row of rows) {
    process.stdout.write(
      `${row.outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${row.id} — ${row.detail}\n`,
    );
  }
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(
    `\nontology-surface-invariant-11 mutation chunk: ${onTarget}/${rows.length} RED ON TARGET; sources ${restored ? "restored and byte-verified" : "NOT RESTORED"}\n`,
  );
  process.exit(onTarget === rows.length && restored ? 0 : 1);
}

if (SUMMARIZE) {
  summarizeBattery();
} else if (MUTATE) {
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
      process.stdout.write(`\nontology-surface-invariant-11: ${passed}/${results.length}\n`);
      emitVerifierCensus({
        verifierId: "ontology-surface-invariant-11",
        sourceUrl: import.meta.url,
        results,
      });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
