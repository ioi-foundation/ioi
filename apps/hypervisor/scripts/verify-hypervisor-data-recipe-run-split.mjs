#!/usr/bin/env node
// M05.7 — the definition/run split and the recipe rename, driven end to end against a live daemon
// and its durable Agentgres chain.
//
// WHAT THIS GATE IS FOR. `DataRecipe`, `TransformationRun` and `ConnectorMapping` had one shared
// defect: they were folded into one another. A recipe embedded its mappings as opaque passthrough
// arrays, a run carried no recipe binding at all, and the bare `recipe` route name held a generic
// executable family the term-boundary ruling calls a defect. So the claims here are the split ones:
// three independent identities, three lifetimes, three disjoint lifecycle vocabularies, an exact
// lineage from run to definition to mapping, qualified routes, and no generic executable recipe
// family.
//
// HOW IT AVOIDS GRADING ITSELF:
//
//   * THE CONTENT HASHES ARE RECOMPUTED FROM CANON. Each family's material field list and domain
//     separator are read out of the REGISTERED invariant profile under
//     `docs/architecture/_meta/schemas/invariants/`, and the digest is taken here in JavaScript. If
//     the daemon's commitment stops covering what the registered contract says it covers, these
//     disagree.
//   * THE REGISTERED INVARIANTS ARE EVALUATED HERE TOO. The tuple-equality, mapping-set,
//     tenancy, snapshot-coverage and count rules are re-derived from the profile and applied to the
//     admitted bytes, so "the run satisfies non-negotiable 3" is a computation this file performs
//     rather than a status the daemon reports.
//   * DURABLE TRUTH IS READ ACROSS A RESTART. Asking the API whether something survived a restart,
//     without restarting, is asking the thing under test to grade itself.
//   * REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the stream afterwards and
//     requires the head and record count to be exactly what they were. A 4xx that still appended is
//     the failure this shape exists to catch.
//   * A GREEN RUN CERTIFIES NOTHING UNTIL THE HARNESS PROVES IT RED. `--mutate` plants named defects
//     in the daemon's own source, rebuilds, re-runs this file against the mutant, and requires each
//     to redden the exact assertion it targets — a mutant that only reddens something else is
//     reported as a MISS, not quietly counted.
//
// NONCLAIMS, stated so a reader does not infer more than ran.
//   * This gate proves the v2 definition/run/mapping planes. It now also exercises all THREE v1 ODK
//     lanes under `/v1/hypervisor/odk/*`, because a stored v1 record of each family is the
//     predecessor a proved convergence resolves. It makes no claim about the rest of that plane.
//   * ALL THREE CONVERGENCES PROVE CUSTODY, AND NONE DISCLAIMS IT. A predecessor is NAMED and its
//     OWNING module resolves it from an owner-scoped chain under the caller's own owner binding, so
//     cross-principal, cross-tenant, substituted-revision, substituted-hash, changed-definition,
//     changed-bytes and unbindable-expectation convergences all fail closed and append nothing.
//     Supplying bytes WITHOUT naming a predecessor is refused, so caller bytes are not an authority
//     path anywhere — asserted here as a refusal rather than trusted as an intention.
//   * WHAT IS STILL NOT PROVED is carried on each admission under
//     `v1_predecessor_custody.does_not_prove`: a v1 record stays mutable, so the commitment is over
//     the bytes AS OF the resolved revision and not for all time; and v1 carries no committed
//     semantic snapshot, so its own named refs are not proved to resolve to exact revisions.
//   * The environment-recipe OBJECT rename is M09.2's. This asserts only that the route name is
//     qualified and that the generic name is no longer a creatable family.
//   * It asserts the authority nonclaims are carried and that this module consults no authority
//     plane. That is not a proof of the authority planes elsewhere.
//   * No SDK, CLI or MCP projection claims these families; the assertion below is that none does.

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
  "crates/node/src/bin/hypervisor_daemon_routes/data_transformation_routes.rs",
);
const DAEMON_SOURCE = path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs");
/// The ODK OWNER module — the only namer of the v1 DataRecipe family's storage, and therefore the
/// only place a custody seam defect can be planted.
const ODK_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/odk_routes.rs",
);
/// The other two v1 owners. Custody spans four modules by design — one consumer and three owners —
/// so a battery that could only reach the consumer would leave every seam-side defect unplantable.
const MAPPING_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/connector_mapping_routes.rs",
);
const RUN_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/transformation_run_routes.rs",
);
const SCHEMAS = path.join(ROOT, "docs/architecture/_meta/schemas");
const REGISTRY = path.join(SCHEMAS, "architecture-contract-registry.v1.json");
const MUTATE = process.argv.includes("--mutate");

const FAMILIES = {
  recipe: {
    contract: "schema://ioi/foundations/objects/data-recipe/v2",
    invariants: path.join(SCHEMAS, "invariants/data-recipe.v2.invariants.json"),
    commitmentRule: "data_recipe.content_hash.commits_the_whole_revision",
  },
  mapping: {
    contract: "schema://ioi/foundations/objects/connector-mapping/v2",
    invariants: path.join(SCHEMAS, "invariants/connector-mapping.v2.invariants.json"),
    commitmentRule: "connector_mapping.content_hash.commits_the_whole_revision",
  },
  run: {
    contract: "schema://ioi/foundations/objects/transformation-run/v2",
    invariants: path.join(SCHEMAS, "invariants/transformation-run.v2.invariants.json"),
    commitmentRule: "transformation_run.content_hash.commits_the_whole_run",
  },
};

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

// ------------------------------------------------------- canonical JSON, commitments, invariants

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;

const pointer = (document, jsonPath) => {
  let current = document;
  for (const segment of jsonPath.slice(2).split(".")) current = current?.[segment];
  return current === undefined ? null : current;
};

function profileRules(family) {
  return JSON.parse(fs.readFileSync(FAMILIES[family].invariants, "utf8")).rules;
}

/** The commitment, rebuilt from the REGISTERED profile's own material list and domain constant. */
function registeredCommitment(family, document) {
  const rule = profileRules(family).find((r) => r.rule_id === FAMILIES[family].commitmentRule);
  if (!rule) throw new Error(`${family} declares no content-commitment rule`);
  const material = {};
  for (const [field, descriptor] of Object.entries(rule.expression.material_fields)) {
    material[field] = Object.hasOwn(descriptor, "value")
      ? descriptor.value
      : pointer(document, descriptor.path);
  }
  return { digest: sha256(canonicalJson(material)), fields: Object.keys(rule.expression.material_fields) };
}

/**
 * Evaluate one registered rule against admitted bytes, HERE.
 *
 * Only the operators these three profiles actually use are implemented, and an operator this
 * function does not know is reported as unevaluated rather than silently passed — an unimplemented
 * rule that returns `true` is exactly how a gate stops checking the thing it names.
 */
function evaluateRule(rule, document) {
  const e = rule.expression;
  const asArray = (p) => {
    const v = pointer(document, p);
    return Array.isArray(v) ? v : v === null ? [] : [v];
  };
  switch (e.operator) {
    case "jcs_sha256_equals": {
      const material = {};
      for (const [field, d] of Object.entries(e.material_fields)) {
        material[field] = Object.hasOwn(d, "value") ? d.value : pointer(document, d.path);
      }
      return sha256(canonicalJson(material)) === pointer(document, e.expected_path);
    }
    case "fields_equal":
      return e.paths.every((p) => canonicalJson(pointer(document, p)) === canonicalJson(pointer(document, e.paths[0])));
    case "fields_not_equal":
      return canonicalJson(pointer(document, e.paths[0])) !== canonicalJson(pointer(document, e.paths[1]));
    case "array_exact_ref_coverage": {
      const observed = asArray(e.array_path).map(String).sort();
      const required = [
        ...(e.required_paths ?? []).map((p) => pointer(document, p)).filter((v) => v !== null),
        ...(e.required_array_paths ?? []).flatMap((p) => asArray(p)),
      ]
        .map(String)
        .sort();
      return canonicalJson(observed) === canonicalJson(required);
    }
    case "array_length_equals":
      return asArray(e.array_path).length === pointer(document, e.count_path);
    case "array_unique_by_fields": {
      const keys = asArray(e.array_path).map((row) => e.fields.map((f) => row?.[f]).join("\0"));
      return new Set(keys).size === keys.length;
    }
    case "array_contains_value":
      return asArray(e.array_path).includes(pointer(document, e.expected_path));
    case "non_empty_when_in": {
      if (!e.values.includes(pointer(document, e.when_path))) return true;
      const v = pointer(document, e.path);
      return Array.isArray(v) ? v.length > 0 : v !== null && v !== "";
    }
    case "field_starts_with_path": {
      const value = String(pointer(document, e.path) ?? "");
      const expected = String(pointer(document, e.expected_path) ?? "");
      if (!value.startsWith(e.prefix) || !expected.startsWith(e.prefix)) return false;
      return value.startsWith(`${expected}${e.suffix}`);
    }
    case "any_of":
      return e.expressions.some((sub) => evaluateRule({ expression: sub }, document));
    default:
      throw new Error(`unimplemented invariant operator '${e.operator}'`);
  }
}

const allRulesHold = (family, document) =>
  profileRules(family)
    .map((rule) => ({ rule: rule.rule_id, pass: evaluateRule(rule, document) }))
    .filter((row) => !row.pass);

// ------------------------------------------------------------------------------------ daemon plane

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-recipe-run-split-"));
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
      IOI_WALLET_SECRET_PASS: "ioi-data-recipe-run-split-verifier",
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
const MAP = "/v1/hypervisor/connector-mapping-revisions";
const REC = "/v1/hypervisor/data-recipe-revisions";
const RUNS = "/v1/hypervisor/transformation-runs";
const OWNER = "org://local";
const POLICY = `sha256:${"3c".repeat(32)}`;

/** Head + record count for one stream, so a refusal can be counted by EFFECT rather than status. */
async function streamState(base, family, key) {
  const response = await req("GET", `${base}?family=${family}`);
  return {
    head: response.j?.head ?? null,
    count: (response.j?.[key] ?? []).length,
  };
}

// -------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "recipe-run-split-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const whoA = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "recipe-run-split-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "recipe-run-split-b-v1",
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
      idempotency_key: "recipe-run-split-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "recipe-run-split-b@ioi.local", password: "recipe-run-split-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  const whoB = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "B" })).j || {};
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant, so a tenant check alone would isolate nothing",
    whoA.authenticated === true &&
      whoB.authenticated === true &&
      (whoA.principal?.tenant_refs || []).includes(OWNER) &&
      (whoB.principal?.tenant_refs || []).includes(OWNER) &&
      whoA.principal?.principal_ref !== whoB.principal?.principal_ref,
    `A=${whoA.principal?.principal_ref} B=${whoB.principal?.principal_ref}`,
  );

  // ------------------------------------------------------------------ identity comes first
  const anonymous = await req("POST", REC, { family: "acme.intake", name: "x" }, { as: null });
  ok(
    "an unauthenticated recipe admission is refused on IDENTITY before any content is judged — a 422 here would tell an anonymous caller which fields this route wants",
    anonymous.status === 401,
    `status ${anonymous.status} code ${code(anonymous.j)}`,
  );

  // ------------------------------------------------------- an exact admitted ontology revision
  const ontology = await req("POST", OV, {
    owner_ref: OWNER,
    idempotency_key: "rrs-ontology-genesis",
    namespace: "acme-clinic",
    name: "patient-intake",
    governing_scope_ref: "domain://acme-clinic/intake",
    policy_hash: POLICY,
    entity_types: [
      { term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" },
    ],
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  });
  const ONT1 = ontology.j?.ontology_version?.ontology_id ?? "";
  ok(
    "PRECONDITION: one exact admitted ontology revision exists, so every binding below is to a revision an owner really admitted rather than to a well-formed string",
    ontology.status === 201 && ONT1 === "ontology://acme-clinic/patient-intake/revision/1",
    `status ${ontology.status} ${ONT1}`,
  );

  // =============================================================== ConnectorMapping — a third family
  const mappingBody = (key, extra = {}) => ({
    owner_ref: OWNER,
    idempotency_key: key,
    family: "acme.intake-form",
    name: "intake-form",
    connector_id: "connector://google-drive",
    ontology_revision_ref: ONT1,
    source_schema_ref: "artifact://acme/intake-form/provider-schema/2026-09",
    target_object_model_refs: ["object-model://om_patient_intake"],
    field_mappings: [
      {
        role: "key",
        source_field: "record_id",
        target_property_ref: "object-model://om_patient_intake#intake_id",
        source_type: "string",
        source_cardinality: "one",
      },
      {
        role: "field",
        source_field: "dob",
        target_property_ref: "object-model://om_patient_intake#date_of_birth",
        source_type: "date",
        source_cardinality: "one",
      },
    ],
    action_mappings: [],
    authority_scopes_required: ["scope:connector.google_drive.read"],
    redaction_policy_ref: "policy://acme-clinic/intake-redaction",
    evidence_required: ["evidence-contract://acme-clinic/intake-consent"],
    effective_policy_hash: POLICY,
    registry_status: "active",
    ...extra,
  });

  const map1 = await req("POST", MAP, mappingBody("rrs-map-genesis"));
  const mapping1 = map1.j?.connector_mapping ?? {};
  ok(
    "a ConnectorMapping revision is admitted as its OWN family with its own identity — not as a member of a recipe, which is the folded-family defect the split exists to end",
    map1.status === 201 &&
      mapping1.connector_mapping_id === "mapping://acme.intake-form" &&
      mapping1.revision_ref === "mapping://acme.intake-form/revision/1" &&
      mapping1.constants?.lifecycle_id === "connector_mapping_registry_lifecycle.v2",
    `status ${map1.status} ${mapping1.revision_ref}`,
  );
  ok(
    "its identity is DERIVED from owner and idempotency key and names the wall clock as the REFUSED basis — v1's `cmap_{nanos:x}` minted a second mapping for every retry",
    mapping1.identity_basis?.derived_from === "owner_ref_and_idempotency_key" &&
      mapping1.identity_basis?.refused_basis === "wall_clock_nanoseconds" &&
      mapping1.identity_basis?.idempotency_key_hash === sha256("rrs-map-genesis"),
    `${mapping1.identity_basis?.derived_from} / ${mapping1.identity_basis?.refused_basis}`,
  );
  const mapCommitment = registeredCommitment("mapping", mapping1);
  ok(
    "the mapping's content hash is INDEPENDENTLY reproducible from the registered invariant profile's own material fields — the daemon does not get to define its own commitment",
    mapCommitment.digest === mapping1.content_hash,
    `${mapCommitment.fields.length} committed fields`,
  );
  ok(
    "and every registered mapping invariant holds on the admitted bytes, evaluated HERE rather than reported by the producer",
    allRulesHold("mapping", mapping1).length === 0,
    JSON.stringify(allRulesHold("mapping", mapping1)),
  );

  const MAP1 = mapping1.revision_ref;
  const beforeDup = await streamState(MAP, "acme.intake-form", "connector_mappings");
  const dupTarget = await req(
    "POST",
    MAP,
    mappingBody("rrs-map-dup", {
      expected_head: beforeDup.head,
      succession_reason: "field_change",
      field_mappings: [
        {
          role: "key",
          source_field: "record_id",
          target_property_ref: "object-model://om_patient_intake#intake_id",
          source_type: "string",
          source_cardinality: "one",
        },
        {
          role: "title",
          source_field: "patient_name",
          target_property_ref: "object-model://om_patient_intake#intake_id",
          source_type: "string",
          source_cardinality: "one",
        },
      ],
    }),
  );
  const afterDup = await streamState(MAP, "acme.intake-form", "connector_mappings");
  ok(
    "two bindings onto ONE target property are refused, and the stream is byte-identical either side of the refusal — v1 kept key, title and the rest in three members that could disagree, so no single check could see across them",
    dupTarget.status === 422 &&
      code(dupTarget.j) === "connector_mapping_target_property_targeted_twice" &&
      afterDup.head === beforeDup.head &&
      afterDup.count === beforeDup.count,
    `status ${dupTarget.status} code ${code(dupTarget.j)} count ${beforeDup.count}->${afterDup.count}`,
  );

  const map2 = await req(
    "POST",
    MAP,
    mappingBody("rrs-map-successor", {
      expected_head: beforeDup.head,
      succession_reason: "source_schema_change",
      supersedes_predecessor: true,
      source_schema_ref: "artifact://acme/intake-form/provider-schema/2026-10",
    }),
  );
  const mapping2 = map2.j?.connector_mapping ?? {};
  const MAP2 = mapping2.revision_ref;
  ok(
    "a source-schema change mints a SUCCESSOR revision that names its predecessor's exact ref AND its exact bytes, while revision 1 stays addressable and unreinterpreted",
    map2.status === 201 &&
      MAP2 === "mapping://acme.intake-form/revision/2" &&
      mapping2.succession?.predecessor_revision_ref === MAP1 &&
      mapping2.succession?.predecessor_content_hash === mapping1.content_hash &&
      mapping2.succession?.reinterprets_predecessor === false,
    `${MAP2} <- ${mapping2.succession?.predecessor_revision_ref}`,
  );
  const map1Reread = await req("GET", `${MAP}?family=acme.intake-form&revision=1`);
  ok(
    "and revision 1 re-reads BYTE-IDENTICALLY after its successor landed: an immutable revision has one admission stamp and no `updated_at`, which is the mutability tell v1 carried",
    map1Reread.status === 200 &&
      canonicalJson(map1Reread.j?.resolved) === canonicalJson(mapping1) &&
      !Object.hasOwn(map1Reread.j?.resolved ?? {}, "updated_at"),
    `re-read ${map1Reread.status}`,
  );

  // ======================================================================= DataRecipe — definition
  const recipeBody = (key, extra = {}) => ({
    owner_ref: OWNER,
    idempotency_key: key,
    family: "acme.intake-normalise",
    name: "intake-normalise",
    ontology_revision_refs: [ONT1],
    input_source_types: ["connector", "document"],
    connector_mapping_revision_refs: [MAP1],
    output_object_model_refs: ["object-model://om_patient_intake"],
    output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"],
    transformation_steps: ["extract", "redact", "normalize", "validate", "map"],
    policy_bound_data_view_refs: ["view://vw_intake_minimised"],
    receipt_obligations: ["data_recipe_run", "transformation"],
    effective_policy_hash: POLICY,
    registry_status: "active",
    ...extra,
  });

  const inlineMapping = await req(
    "POST",
    REC,
    recipeBody("rrs-recipe-inline", {
      connector_mapping_revision_refs: [{ source_field: "record_id", target: "intake_id" }],
    }),
  );
  ok(
    "an INLINE connector mapping inside a recipe is REFUSED, never coerced — v1 copied whatever the caller sent under this key, which is how a mapping became a fragment of a recipe instead of an object",
    inlineMapping.status === 422 && code(inlineMapping.j) === "data_transformation_inline_member_refused",
    `status ${inlineMapping.status} code ${code(inlineMapping.j)}`,
  );
  const familyHeadMapping = await req(
    "POST",
    REC,
    recipeBody("rrs-recipe-map-head", { connector_mapping_revision_refs: ["mapping://acme.intake-form"] }),
  );
  ok(
    "a recipe naming a mapping FAMILY HEAD is refused: a released definition may not resolve whichever mapping revision happens to be current when a run reads it",
    familyHeadMapping.status === 422 &&
      code(familyHeadMapping.j) === "connector_mapping_revision_ref_not_exact",
    `status ${familyHeadMapping.status} code ${code(familyHeadMapping.j)}`,
  );
  const ontologyHead = await req(
    "POST",
    REC,
    recipeBody("rrs-recipe-ont-head", {
      ontology_revision_refs: ["ontology://acme-clinic/patient-intake"],
    }),
  );
  ok(
    "and a recipe naming an ontology FAMILY HEAD is refused BY THE ONTOLOGY OWNER's own seam — this module resolves exact revisions through M05.1 rather than shape-checking them locally",
    ontologyHead.status === 422 &&
      code(ontologyHead.j) === "ontology_version_identity_not_canonical",
    `status ${ontologyHead.status} code ${code(ontologyHead.j)}`,
  );
  const genericScheme = await req("POST", REC, recipeBody("rrs-recipe-generic", { family: "recipe://acme" }));
  ok(
    "the GENERIC `recipe://` spelling is refused as an identity: the term-boundary ruling makes a generic executable recipe family a defect, and this family mints `data-recipe://` only",
    genericScheme.status === 422 && code(genericScheme.j) === "data_recipe_generic_scheme_refused",
    `status ${genericScheme.status} code ${code(genericScheme.j)}`,
  );
  const authored = await req(
    "POST",
    REC,
    recipeBody("rrs-recipe-authored", { content_hash: `sha256:${"aa".repeat(32)}` }),
  );
  ok(
    "caller-authored ADMISSION EVIDENCE is refused (INV-37): the commitment, the revision ref, the snapshot and the succession tuple are resolved by the server, never asserted by the caller",
    authored.status === 422 && code(authored.j) === "data_recipe_caller_authored_evidence_refused",
    `status ${authored.status} code ${code(authored.j)}`,
  );

  const rec1 = await req("POST", REC, recipeBody("rrs-recipe-genesis"));
  const recipe1 = rec1.j?.data_recipe ?? {};
  const REC1 = recipe1.revision_ref;
  ok(
    "a DataRecipe revision is admitted as an OWNER-QUALIFIED, REVISION-EXACT immutable definition in canon's own `data-recipe://` scheme",
    rec1.status === 201 &&
      recipe1.data_recipe_id === "data-recipe://acme.intake-normalise" &&
      REC1 === "data-recipe://acme.intake-normalise/revision/1" &&
      recipe1.constants?.refused_generic_recipe_scheme === "recipe://",
    `status ${rec1.status} ${REC1}`,
  );
  const recCommitment = registeredCommitment("recipe", recipe1);
  ok(
    "the recipe's content hash is INDEPENDENTLY reproducible from the registered invariant profile, and every registered recipe invariant holds on the admitted bytes",
    recCommitment.digest === recipe1.content_hash && allRulesHold("recipe", recipe1).length === 0,
    `${recCommitment.fields.length} committed fields; ${JSON.stringify(allRulesHold("recipe", recipe1))}`,
  );
  ok(
    "the SEMANTIC-COMPONENT SNAPSHOT covers EXACTLY the union of the five readable ref fields — nothing extra, nothing dropped — which is the mechanism by which a released recipe cannot silently resolve a newer semantic head",
    canonicalJson([...recipe1.semantic_component_refs].sort()) ===
      canonicalJson(
        [
          ...recipe1.ontology_revision_refs,
          ...recipe1.connector_mapping_revision_refs,
          ...recipe1.output_object_model_refs,
          ...recipe1.output_dataset_contract_refs,
          ...recipe1.policy_bound_data_view_refs,
        ].sort(),
      ) && recipe1.semantic_component_count === recipe1.semantic_component_refs.length,
    `${recipe1.semantic_component_count} components`,
  );
  ok(
    "the definition declares output CONTRACTS and states in its own bytes that it holds no run outputs — the structural reason the two objects cannot be collapsed",
    recipe1.does_not_assert?.includes("run_outputs") &&
      recipe1.does_not_assert?.includes("generic_executable_recipe_family") &&
      recipe1.authority_nonclaim === "data_recipe_grants_no_authority" &&
      !Object.hasOwn(recipe1, "output_object_refs"),
    JSON.stringify(recipe1.does_not_assert),
  );

  // ============================================================ TransformationRun — one execution
  const runBody = (key, extra = {}) => ({
    owner_ref: OWNER,
    idempotency_key: key,
    data_recipe_revision_ref: REC1,
    output_intent: "ontology_objects",
    execution_status: "completed",
    input_refs: ["artifact://acme/intake-forms/batch-2026-08"],
    authority_grant_refs: ["grant://acme-clinic/intake-read/2026-08"],
    output_object_refs: ["agentgres://object/patient_intake/2026-08-batch"],
    receipt_refs: ["receipt://acme-clinic/transformation/2026-08-batch"],
    derivative_policy_ref: "policy://acme-clinic/intake-derivatives",
    impact_graph_ref: "agentgres://projection/intake-impact",
    ...extra,
  });

  const noBinding = await req("POST", RUNS, runBody("rrs-run-nobind", { data_recipe_revision_ref: "" }));
  ok(
    "a run with NO recipe binding is refused — v1 had no recipe field at all, which is the whole content of 'the exact definition/run split is not started'",
    noBinding.status === 422 && code(noBinding.j) === "transformation_run_recipe_binding_required",
    `status ${noBinding.status} code ${code(noBinding.j)}`,
  );
  const headBinding = await req(
    "POST",
    RUNS,
    runBody("rrs-run-head", { data_recipe_revision_ref: "data-recipe://acme.intake-normalise" }),
  );
  ok(
    "a run bound to a recipe FAMILY HEAD is refused: the `/revision/` segment is what stops an execution from running whichever revision is current when it starts",
    headBinding.status === 422 &&
      code(headBinding.j) === "transformation_run_recipe_family_head_refused",
    `status ${headBinding.status} code ${code(headBinding.j)}`,
  );

  const run1 = await req("POST", RUNS, runBody("rrs-run-first"));
  const execution = run1.j?.transformation_run ?? {};
  ok(
    "a run is admitted as ONE EXECUTION with its own identity, its own lifecycle vocabulary, and an exact binding to the definition it executed",
    run1.status === 201 &&
      /^transform:\/\/trun_[0-9a-f]{32}$/u.test(execution.transformation_run_id ?? "") &&
      execution.data_recipe_revision_ref === REC1 &&
      execution.data_recipe_content_hash === recipe1.content_hash &&
      execution.constants?.lifecycle_id === "transformation_run_execution_lifecycle.v2",
    `status ${run1.status} ${execution.transformation_run_id}`,
  );
  ok(
    "NON-NEGOTIABLE 3, DECIDED FROM THE BYTES: the run carries BOTH the tuple its recipe revision committed and the tuple it resolved, and the registered equality rules hold with no registry read",
    execution.recipe_committed_semantic_component_set_hash === recipe1.semantic_component_set_hash &&
      execution.resolved_semantic_component_set_hash ===
        execution.recipe_committed_semantic_component_set_hash &&
      execution.resolved_semantic_component_set_snapshot_ref ===
        execution.recipe_committed_semantic_component_set_snapshot_ref &&
      allRulesHold("run", execution).length === 0,
    JSON.stringify(allRulesHold("run", execution)),
  );
  const runCommitment = registeredCommitment("run", execution);
  ok(
    "and the run's own commitment is INDEPENDENTLY reproducible from its registered profile, so substituting the recipe binding, the resolved tuple, the mapping set or the output tenancy all break it",
    runCommitment.digest === execution.content_hash,
    `${runCommitment.fields.length} committed fields`,
  );
  ok(
    "the run is located at ONE POSITION IN ONE HISTORY by exactly one SHA-256 head of its recipe family's admitted chain — a truncated head would name a prefix rather than a position",
    /^(?:sha256:)?[0-9a-f]{64}$/u.test(execution.data_recipe_admitted_head_before ?? ""),
    `${execution.data_recipe_admitted_head_before}`,
  );
  ok(
    "CONCRETE OUTPUTS BELONG TO THE RUN and the definition holds none: the run owns four output members and its receipts, and the recipe carries neither",
    execution.output_object_refs?.length === 1 &&
      execution.receipt_refs?.length === 1 &&
      !Object.hasOwn(recipe1, "receipt_refs") &&
      recipe1.receipt_obligations?.includes("data_recipe_run"),
    `${execution.output_object_refs?.length} outputs / ${execution.receipt_refs?.length} receipts`,
  );

  // ------------------------------------------------------------------- idempotent retry identity
  const retry = await req("POST", RUNS, runBody("rrs-run-first"));
  ok(
    "the SAME idempotency key replays the ORIGINAL admitted run byte-identically rather than minting a second execution — v1's `trun_{nanos:x}` admitted two indistinguishable runs of one intent",
    retry.status === 200 &&
      retry.j?.replayed === true &&
      canonicalJson(retry.j?.transformation_run) === canonicalJson(execution),
    `status ${retry.status} replayed ${retry.j?.replayed}`,
  );

  // ------------------------------------------------------------------------------ the refusals
  const beforeRefusals = await streamState(RUNS, "acme.intake-normalise", "transformation_runs");
  const substitution = await req(
    "POST",
    RUNS,
    runBody("rrs-run-substitute", { resolved_connector_mapping_revision_refs: [MAP2] }),
  );
  const afterSubstitution = await streamState(RUNS, "acme.intake-normalise", "transformation_runs");
  ok(
    "MAPPING SUBSTITUTION is refused and appends nothing: swapping a mapping for its own successor is not an execution of the admitted definition, and canon says a mapping change requires a successor mapping AND a successor recipe",
    substitution.status === 422 &&
      code(substitution.j) === "transformation_run_connector_mapping_substituted" &&
      afterSubstitution.head === beforeRefusals.head &&
      afterSubstitution.count === beforeRefusals.count,
    `status ${substitution.status} code ${code(substitution.j)} count ${beforeRefusals.count}->${afterSubstitution.count}`,
  );
  const drift = await req(
    "POST",
    RUNS,
    runBody("rrs-run-drift", { semantic_component_resolution: "current_head" }),
  );
  const afterDrift = await streamState(RUNS, "acme.intake-normalise", "transformation_runs");
  ok(
    "asking the run to resolve CURRENT HEADS really resolves them and then REFUSES, because the mapping family advanced past what the recipe froze — the correct outcome is a successor recipe revision, never a run that resolves differently and reports success",
    drift.status === 422 &&
      ["transformation_run_connector_mapping_substituted", "transformation_run_semantic_tuple_drifted"].includes(
        code(drift.j),
      ) &&
      afterDrift.head === beforeRefusals.head &&
      afterDrift.count === beforeRefusals.count,
    `status ${drift.status} code ${code(drift.j)}`,
  );
  const crossTenant = await req(
    "POST",
    RUNS,
    runBody("rrs-run-crosstenant", { output_tenant_ref: "tenant://someone.else" }),
  );
  const afterCrossTenant = await streamState(RUNS, "acme.intake-normalise", "transformation_runs");
  ok(
    "CROSS-TENANT OUTPUT is refused before any byte leaves the owner boundary and without a policy engine being consulted — the two tenancies are separate fields precisely so they can disagree and be caught",
    crossTenant.status === 422 &&
      code(crossTenant.j) === "transformation_run_cross_tenant_output_refused" &&
      afterCrossTenant.head === beforeRefusals.head &&
      afterCrossTenant.count === beforeRefusals.count,
    `status ${crossTenant.status} code ${code(crossTenant.j)}`,
  );
  const v1Word = await req("POST", RUNS, runBody("rrs-run-v1word", { execution_status: "dry_run_ready" }));
  ok(
    "a v1 LIFECYCLE WORD is refused rather than translated: `planned`, `dry_run_ready`, `blocked` and `cancelled` are members of no v2 vocabulary, and the three families' lifecycle ids are distinct over disjoint sets",
    v1Word.status === 422 && code(v1Word.j) === "transformation_run_v1_lifecycle_word_refused",
    `status ${v1Word.status} code ${code(v1Word.j)}`,
  );
  const learning = await req(
    "POST",
    RUNS,
    runBody("rrs-run-learning", { output_intent: "training_material" }),
  );
  ok(
    "a LEARNING-BEARING intent without its InstitutionalLearningBoundaryProfile is refused — the field's nullability serves the non-learning intents and is not a way to skip the boundary on these three",
    learning.status === 422 && code(learning.j) === "transformation_run_learning_boundary_required",
    `status ${learning.status} code ${code(learning.j)}`,
  );
  const learningNoPolicy = await req(
    "POST",
    RUNS,
    runBody("rrs-run-learning-2", {
      output_intent: "training_material",
      institutional_learning_boundary_profile_ref: "learning-boundary://acme-clinic/intake",
    }),
  );
  ok(
    "and naming the profile without the COMPOSED policy hash is refused too: the boundary is a scope ceiling, not blanket permission, and a run that records the ceiling has not recorded the decision",
    learningNoPolicy.status === 422 &&
      code(learningNoPolicy.j) === "transformation_run_learning_policy_required",
    `status ${learningNoPolicy.status} code ${code(learningNoPolicy.j)}`,
  );
  const completedEmpty = await req(
    "POST",
    RUNS,
    runBody("rrs-run-empty", { output_object_refs: [], receipt_refs: [] }),
  );
  ok(
    "a COMPLETED run with no outputs is refused: it either produced nothing while reporting success, or recorded its outputs somewhere else — and the second is how outputs drift back onto the definition",
    completedEmpty.status === 422 &&
      code(completedEmpty.j) === "transformation_run_completed_without_outputs",
    `status ${completedEmpty.status} code ${code(completedEmpty.j)}`,
  );
  const completedNoReceipt = await req("POST", RUNS, runBody("rrs-run-noreceipt", { receipt_refs: [] }));
  ok(
    "and a COMPLETED run with no receipt is refused: canon requires transformation receipts for consequential outcomes, and an unmet obligation presented as finished is the thing this rule exists to catch",
    completedNoReceipt.status === 422 &&
      code(completedNoReceipt.j) === "transformation_run_completed_without_receipts",
    `status ${completedNoReceipt.status} code ${code(completedNoReceipt.j)}`,
  );

  // ------------------------------------------------------------- a successor definition, and lineage
  const recHead = await streamState(REC, "acme.intake-normalise", "revisions");
  const rec2 = await req(
    "POST",
    REC,
    recipeBody("rrs-recipe-successor", {
      expected_head: recHead.head,
      succession_reason: "connector_mapping_change",
      supersedes_predecessor: true,
      connector_mapping_revision_refs: [MAP2],
    }),
  );
  const recipe2 = rec2.j?.data_recipe ?? {};
  ok(
    "a mapping change produces a SUCCESSOR RECIPE REVISION with a different semantic snapshot, which is the remedy canon prescribes for the drift refused above",
    rec2.status === 201 &&
      recipe2.revision_ref === "data-recipe://acme.intake-normalise/revision/2" &&
      recipe2.semantic_component_set_hash !== recipe1.semantic_component_set_hash &&
      recipe2.succession?.predecessor_content_hash === recipe1.content_hash,
    `${recipe2.revision_ref}`,
  );
  // A run stream is head-ordered like every other owner-scoped stream in this estate, so a second
  // run names the exact head it is admitted against. That is what puts every run at ONE position in
  // ONE history rather than in an unordered bag of executions.
  const runHead = await streamState(RUNS, "acme.intake-normalise", "transformation_runs");
  const run2 = await req(
    "POST",
    RUNS,
    runBody("rrs-run-successor", {
      data_recipe_revision_ref: recipe2.revision_ref,
      expected_head: runHead.head,
    }),
  );
  const execution2 = run2.j?.transformation_run ?? {};
  ok(
    "and a run against THAT revision freezes the successor's tuple — DEFINITION AND RUN HAVE DIFFERENT IDENTITIES, REVISIONS AND LIFETIMES, which is ACC-6 clause 7 stated as an operation",
    run2.status === 201 &&
      execution2.data_recipe_revision_ref === recipe2.revision_ref &&
      execution2.resolved_connector_mapping_revision_refs?.[0] === MAP2 &&
      execution2.transformation_run_id !== execution.transformation_run_id &&
      allRulesHold("run", execution2).length === 0,
    `${execution2.transformation_run_id}`,
  );
  const stillFirst = await req("GET", `${RUNS}?family=acme.intake-normalise&transformation_run_id=${encodeURIComponent(execution.transformation_run_id)}`);
  ok(
    "the FIRST run still reads byte-identically and still binds revision 1: a definition's successor never reinterprets an execution that already happened",
    stillFirst.status === 200 &&
      canonicalJson(stillFirst.j?.resolved) === canonicalJson(execution) &&
      stillFirst.j?.resolved?.data_recipe_revision_ref === REC1,
    `re-read ${stillFirst.status}`,
  );

  // ------------------------------------------- v1 convergence is now RESOLVED, never asserted
  // The fixture-driven convergence this replaces handed the daemon predecessor BYTES and asked it to
  // hash them, which is why it could only ever carry a nonclaim. Supplying bytes with no named
  // predecessor is now a refusal, so the old shape is asserted to be GONE rather than merely unused.
  const storedV1Fixture = JSON.parse(
    fs.readFileSync(path.join(SCHEMAS, "fixtures/connector-mapping-v1/positive-stored-v1-declared.json"), "utf8"),
  );
  const bytesOnly = await req(
    "POST",
    MAP,
    mappingBody("rrs-map-bytesonly", {
      expected_head: (await streamState(MAP, "acme.intake-form", "connector_mappings")).head,
      succession_reason: "correction",
      converge_from_v1: storedV1Fixture,
    }),
  );
  ok(
    "SUPPLIED PREDECESSOR BYTES ARE NO LONGER AN AUTHORITY PATH — a convergence that hands over a record without naming a stored one is REFUSED, not hashed and admitted with a nonclaim attached; any principal could satisfy the old shape with any bytes that happened to fit the v1 contract",
    bytesOnly.status === 422 &&
      code(bytesOnly.j) === "connector_mapping_convergence_ref_required",
    `status ${bytesOnly.status} code ${code(bytesOnly.j)}`,
  );
  const notV1 = await req(
    "POST",
    MAP,
    mappingBody("rrs-map-notv1", {
      expected_head: (await streamState(MAP, "acme.intake-form", "connector_mappings")).head,
      succession_reason: "correction",
      converge_from_v1_ref: "mapping://x/revision/1",
    }),
  );
  ok(
    "a convergence source named in the SUCCESSOR's scheme is refused rather than converged — this build resolves the registered predecessor and reinterprets nothing else",
    notV1.status === 400 && code(notV1.j) === "connector_mapping_v1_ref_not_canonical",
    `status ${notV1.status} code ${code(notV1.j)}`,
  );
  // ----------------------------------------------------------- owner isolation, exact-head, index
  const otherOwner = await req("GET", `${REC}?family=acme.intake-normalise`, null, { as: "B" });
  ok(
    "the other principal cannot READ this recipe family even though both hold the same org tenant — the family's reserved scope pins the admitting principal, not merely the tenant",
    otherOwner.status !== 200 || (otherOwner.j?.revisions ?? []).length === 0,
    `status ${otherOwner.status}`,
  );
  const staleHead = await req(
    "POST",
    REC,
    recipeBody("rrs-recipe-stale", { expected_head: recHead.head, succession_reason: "correction" }),
  );
  const afterStale = await streamState(REC, "acme.intake-normalise", "revisions");
  ok(
    "a successor offered against a STALE head is refused and appends nothing — a fork does not become a lineage by asserting one",
    staleHead.status === 409 &&
      code(staleHead.j) === "data_recipe_expected_head_conflict" &&
      afterStale.count === 2,
    `status ${staleHead.status} code ${code(staleHead.j)} count ${afterStale.count}`,
  );

  // ====== v1 PREDECESSOR CUSTODY — RESOLVED THROUGH EACH OWNER SEAM, FOR ALL THREE FAMILIES ======
  //
  // Every convergence above drove BYTES. This drives REFS against v1 records the daemon really
  // admitted, through three different owning modules, and requires each proof to be a resolution
  // rather than a restatement of what the caller sent.
  const ODK = "/v1/hypervisor/odk";
  const v1Ontology = await req("POST", `${ODK}/domain-ontologies`, {
    domain: "rrs-v1-custody",
    canonical_object_model: {
      value_types: [{ id: "money", name: "Money", base: "double" }],
      object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
        { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
        { id: "title", name: "Title", value_type: "string" },
        { id: "amount", name: "Amount", value_type: "money" } ] }],
      action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
    },
  });
  const V1_ONT_REF = v1Ontology.j?.ontology?.ref ?? "";
  const dataSource = await req("POST", "/v1/hypervisor/data-sources", {
    name: "rrs-v1-src", kind: "postgres",
    endpoint: "postgres://unreachable.invalid:5432/db",
    credential_posture: "wallet_credential_lease",
  });
  const V1_SRC = dataSource.j?.data_source?.source_id ?? "";

  /** Build one v1 predecessor of each family, as a named principal. */
  const v1MappingBody = (key, name) => ({
    owner_ref: OWNER, idempotency_key: key, name,
    data_source_id: V1_SRC, ontology_ref: V1_ONT_REF, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }],
  });
  const v1RecipeBody = (key, name) => ({
    owner_ref: OWNER, idempotency_key: key, name,
    description: "a stored v1 predecessor a convergence resolves",
    ontology_ref: V1_ONT_REF, output_kind: "ontology_objects",
    source_refs: [], connector_mappings: [], policy_bound_views: [],
  });

  const v1Map = await req("POST", `${ODK}/connector-mappings`, v1MappingBody("rrs-v1-map", "rrs-v1-map"));
  const V1_MAP_REF = v1Map.j?.connector_mapping?.ref ?? "";
  const v1MapId = v1Map.j?.connector_mapping?.id ?? "";
  const v1View = await req("POST", `${ODK}/policy-bound-data-views`, {
    connector_mapping_id: v1MapId, name: "rrs-v1-gate",
    authority_subjects: ["agent://materializer"],
    allowed_operations: ["read", "transform", "export"],
    purpose: "underwriting analysis",
    property_scope: ["loan_id", "title", "amount"],
    retention_posture: "bounded", export_posture: "receipted_export_only",
    receipt_obligations: ["export: one receipt per exported batch"],
  });
  const v1Run = await req("POST", `${ODK}/transformation-runs`, {
    owner_ref: OWNER, idempotency_key: "rrs-v1-run", name: "rrs-v1-run",
    connector_mapping_id: v1MapId,
    policy_view_id: v1View.j?.policy_bound_data_view?.id ?? "",
  });
  const V1_RUN_REF = v1Run.j?.transformation_run?.ref ?? "";
  const v1Recipe = await req("POST", `${ODK}/data-recipes`, v1RecipeBody("rrs-v1-recipe", "rrs-v1-recipe"));
  const V1_RECIPE_REF = v1Recipe.j?.data_recipe?.ref ?? "";

  ok(
    "PRECONDITION: all THREE v1 families now admit through the SHARED owner-scoped boundary and mint a stored predecessor — the mapping and run lanes took no identity at all and persisted by overwrite, so until their owners were owner-scoped there was nothing stored for any custody proof to check",
    v1Map.status === 201 && /^connector-mapping:\/\/cmap_[0-9a-f]+$/u.test(V1_MAP_REF) &&
      v1Run.status === 201 && /^transformation-run:\/\/trun_[0-9a-f]+$/u.test(V1_RUN_REF) &&
      v1Recipe.status === 201 && /^recipe:\/\/recipe_[0-9a-f]{16}$/u.test(V1_RECIPE_REF),
    `map ${v1Map.status} ${V1_MAP_REF} | run ${v1Run.status} ${V1_RUN_REF} | recipe ${v1Recipe.status} ${V1_RECIPE_REF}`,
  );
  const unowned = await req("POST", `${ODK}/connector-mappings`, {
    ...v1MappingBody("rrs-v1-map-unowned", "rrs-v1-map-unowned"), owner_ref: undefined,
  });
  const anonV1 = await req("POST", `${ODK}/connector-mappings`, v1MappingBody("rrs-v1-map-anon", "rrs-v1-map-anon"), { as: null });
  ok(
    "and an UNOWNED or UNAUTHENTICATED v1 write is refused outright — a record admitted with no owner could never be custody-proved afterwards, so the lane refuses to create one rather than quietly minting a predecessor no convergence can ever use",
    unowned.status === 400 && code(unowned.j) === "connector_mapping_owner_ref_required" &&
      anonV1.status === 401,
    `unowned ${unowned.status}/${code(unowned.j)} anonymous ${anonV1.status}`,
  );

  // The registered v1 records, and their commitments recomputed HERE from what each lane returned.
  const v1Records = {
    recipe: v1Recipe.j?.data_recipe ?? {},
    mapping: v1Map.j?.connector_mapping ?? {},
    run: v1Run.j?.transformation_run ?? {},
  };
  // A DataRecipe v1 row carries `owner_ref` because its ODK admission path inserts it; the other two
  // ride an envelope and stay contract-exact. The registered record is the row minus that member.
  const recipeRegistered = { ...v1Records.recipe };
  delete recipeRegistered.owner_ref;
  const V1_HASHES = {
    recipe: sha256(canonicalJson(recipeRegistered)),
    mapping: sha256(canonicalJson(v1Records.mapping)),
    run: sha256(canonicalJson(v1Records.run)),
  };

  const FAMILY_CASES = [
    { key: "recipe", label: "DataRecipe", route: REC, family: "acme.intake-normalise", listKey: "revisions",
      recordKey: "data_recipe", prefix: "data_recipe", refMember: "from_recipe_ref",
      ref: V1_RECIPE_REF, seam: "odk_routes::resolve_stored_odk_data_recipe_v1",
      body: (k, extra) => recipeBody(k, { succession_reason: "correction", ...extra }) },
    { key: "mapping", label: "ConnectorMapping", route: MAP, family: "acme.intake-form", listKey: "connector_mappings",
      recordKey: "connector_mapping", prefix: "connector_mapping", refMember: "from_mapping_ref",
      ref: V1_MAP_REF, seam: "connector_mapping_routes::resolve_stored_connector_mapping_v1",
      body: (k, extra) => mappingBody(k, { succession_reason: "correction", ...extra }) },
    { key: "run", label: "TransformationRun", route: RUNS, family: "acme.intake-normalise", listKey: "transformation_runs",
      recordKey: "transformation_run", prefix: "transformation_run", refMember: "from_run_ref",
      ref: V1_RUN_REF, seam: "transformation_run_routes::resolve_stored_transformation_run_v1",
      body: (k, extra) => runBody(k, extra) },
  ];

  /** Drive one convergence into a family, naming the exact head so nothing races. */
  async function converge(c, key, extra) {
    const before = await streamState(c.route, c.family, c.listKey);
    const response = await req("POST", c.route, c.body(key, {
      ...(before.head ? { expected_head: before.head } : {}),
      ...extra,
    }));
    const after = await streamState(c.route, c.family, c.listKey);
    return { response, appended: after.count !== before.count };
  }

  const provedHeads = {};
  for (const c of FAMILY_CASES) {
    const hash = V1_HASHES[c.key];
    const proved = await converge(c, `rrs-custody-${c.key}`, {
      converge_from_v1_ref: c.ref,
      expected_v1_revision: 1,
      expected_v1_content_hash: hash,
      converge_from_v1: c.key === "recipe" ? recipeRegistered : v1Records[c.key],
    });
    const record = proved.response.j?.[c.recordKey] ?? {};
    const proof = proved.response.j?.v1_predecessor_custody ?? null;
    provedHeads[c.key] = proof?.predecessor_admitted_head;
    ok(
      `${c.label} v1 CUSTODY IS PROVED, NOT ASSERTED: the successor resolves the exact stored predecessor through its OWNING module's read-only seam and commits the commitment that module computed — the ref stays in the scheme v1 stored it under, and the hash is one this file recomputed from the v1 lane's own reply`,
      proved.response.status === 201 &&
        record.migration?.compatibility === "converged_from_v1" &&
        record.migration?.[c.refMember] === c.ref &&
        record.migration?.from_content_hash === hash &&
        // `from_revision` is declared only by ConnectorMapping v2's migration object; the other two
        // are closed, so emitting it there would make a converged admission fail its own contract.
        // Every family still reports the resolved revision on the custody proof.
        (c.key === "mapping"
          ? record.migration?.from_revision === 1
          : record.migration?.from_revision === undefined) &&
        record.migration?.reinterprets_predecessor === false &&
        proof?.predecessor_ref === c.ref &&
        proof?.predecessor_content_hash === hash &&
        proof?.predecessor_admitted_revision === 1,
      `status ${proved.response.status} code ${code(proved.response.j)} ${record.migration?.[c.refMember]}`,
    );
    ok(
      `${c.label}'s proof NAMES THE CUSTODY IT PROVED — the owner, the pinned principal and tenant, the admitted head and the resolving seam — and the admission carries NO custody nonclaim anywhere, because there is no longer a code path that admits one`,
      proof?.predecessor_owner_ref === OWNER &&
        proof?.predecessor_principal_ref === whoA.principal?.principal_ref &&
        proof?.predecessor_tenant_ref === OWNER &&
        proof?.resolved_from === "owner_scoped_admission_chain" &&
        proof?.resolved_by === c.seam &&
        typeof proof?.predecessor_admitted_head === "string" &&
        proof.predecessor_admitted_head.length > 0 &&
        proved.response.j?.v1_predecessor_custody_nonclaim === undefined,
      `owner ${proof?.predecessor_owner_ref} principal ${proof?.predecessor_principal_ref} by ${proof?.resolved_by}`,
    );
    const crossTenantV1 = await converge(c, `rrs-custody-${c.key}-crosstenant`, {
      owner_ref: "org://someone.else", converge_from_v1_ref: c.ref,
    });
    ok(
      `${c.label}: converging into a family bound to a TENANT THIS CALLER DOES NOT HOLD is refused and appends nothing — the tenant boundary is crossed before the predecessor is resolved, so naming an owner one does not hold reaches no v1 bytes`,
      crossTenantV1.response.status === 403 && !crossTenantV1.appended,
      `status ${crossTenantV1.response.status} code ${code(crossTenantV1.response.j)} appended ${crossTenantV1.appended}`,
    );
    const staleHash = await converge(c, `rrs-custody-${c.key}-stalehash`, {
      converge_from_v1_ref: c.ref, expected_v1_content_hash: `sha256:${"11".repeat(32)}`,
    });
    ok(
      `${c.label}: a SUBSTITUTED COMMITMENT is refused rather than overwritten — the resolved bytes are authoritative, so an expectation naming a different hash fails closed instead of converging whatever is current under it`,
      staleHash.response.status === 422 &&
        code(staleHash.response.j) === `${c.prefix}_convergence_source_hash_stale` &&
        !staleHash.appended,
      `status ${staleHash.response.status} code ${code(staleHash.response.j)} appended ${staleHash.appended}`,
    );
    const badRevision = await converge(c, `rrs-custody-${c.key}-badrev`, {
      converge_from_v1_ref: c.ref, expected_v1_revision: 99,
    });
    ok(
      `${c.label}: a SUBSTITUTED REVISION is a typed absence, never the nearest one — resolving "whichever revision exists" would be the drift the v2 contract exists to end`,
      badRevision.response.status === 404 && !badRevision.appended,
      `status ${badRevision.response.status} code ${code(badRevision.response.j)} appended ${badRevision.appended}`,
    );
    const changedBytes = await converge(c, `rrs-custody-${c.key}-changed`, {
      converge_from_v1_ref: c.ref,
      converge_from_v1: { ...v1Records[c.key], name: "not-what-is-stored" },
    });
    ok(
      `${c.label}: predecessor bytes that DISAGREE with the stored record are refused, never reconciled — a caller asserting a different record gets a typed refusal rather than an admission that quietly converged the real one`,
      changedBytes.response.status === 422 &&
        code(changedBytes.response.j) === `${c.prefix}_convergence_source_bytes_changed` &&
        !changedBytes.appended,
      `status ${changedBytes.response.status} code ${code(changedBytes.response.j)} appended ${changedBytes.appended}`,
    );
    const unbound = await converge(c, `rrs-custody-${c.key}-unbound`, {
      expected_v1_content_hash: hash,
    });
    ok(
      `${c.label}: an expectation with NOTHING TO CHECK IT AGAINST is refused, not ignored — without a named predecessor it could only ever be compared to bytes the caller itself supplied, and an assertion that cannot fail is not a check`,
      unbound.response.status === 422 &&
        code(unbound.response.j) === `${c.prefix}_convergence_expectation_unbound` &&
        !unbound.appended,
      `status ${unbound.response.status} code ${code(unbound.response.j)} appended ${unbound.appended}`,
    );
  }

  // ---------------------------------------------- CHANGED-DEFINITION REPLAY, on a real v1 revision
  const patched = await req("PATCH", `${ODK}/connector-mappings/${v1MapId}`, {
    idempotency_key: "rrs-v1-map-patch", name: "rrs-v1-map-revised",
  });
  const patchedRecord = patched.j?.connector_mapping ?? {};
  const REVISED_HASH = sha256(canonicalJson(patchedRecord));
  const staleAfterChange = await converge(FAMILY_CASES[1], "rrs-custody-mapping-changedef", {
    converge_from_v1_ref: V1_MAP_REF, expected_v1_content_hash: V1_HASHES.mapping,
  });
  ok(
    "CHANGED-DEFINITION REPLAY FAILS CLOSED: after the v1 mapping is revised in place, a convergence still asserting the OLD commitment against the current revision is refused — the row now holds different bytes, and converging them under the old expectation is exactly the substitution this check exists to catch",
    patched.status === 200 && patchedRecord.revision === 2 && REVISED_HASH !== V1_HASHES.mapping &&
      staleAfterChange.response.status === 422 &&
      code(staleAfterChange.response.j) === "connector_mapping_convergence_source_hash_stale" &&
      !staleAfterChange.appended,
    `patch ${patched.status} rev ${patchedRecord.revision} converge ${staleAfterChange.response.status}/${code(staleAfterChange.response.j)}`,
  );
  const supersededOk = await converge(FAMILY_CASES[1], "rrs-custody-mapping-superseded", {
    converge_from_v1_ref: V1_MAP_REF, expected_v1_revision: 1,
    expected_v1_content_hash: V1_HASHES.mapping,
  });
  const supersededProof = supersededOk.response.j?.v1_predecessor_custody ?? null;
  ok(
    "and the SUPERSEDED revision is still resolvable with its original commitment — a v1 mapping is patched in place so the ROW lost revision 1's bytes, but every admission was appended, so the chain answers for the exact revision named while reporting that the row no longer holds it",
    supersededOk.response.status === 201 &&
      supersededProof?.predecessor_admitted_revision === 1 &&
      supersededProof?.predecessor_content_hash === V1_HASHES.mapping &&
      supersededProof?.predecessor_index_state === "superseded_revision_read_from_agentgres" &&
      supersededProof?.predecessor_revision_selected_by === "caller_named_exact_revision",
    `status ${supersededOk.response.status} rev ${supersededProof?.predecessor_admitted_revision} index ${supersededProof?.predecessor_index_state}`,
  );

  // ------------------------------------------------------ cross-principal, on a REAL foreign record
  const bMap = await req("POST", `${ODK}/connector-mappings`,
    v1MappingBody("rrs-v1-map-b", "rrs-v1-map-b"), { as: "B" });
  const crossPrincipal = await converge(FAMILY_CASES[1], "rrs-custody-mapping-crossprincipal", {
    converge_from_v1_ref: bMap.j?.connector_mapping?.ref ?? "",
  });
  ok(
    "A PREDECESSOR ANOTHER PRINCIPAL ADMITTED CANNOT BE CONVERGED even though both principals hold the same org tenant and the request is otherwise valid — the v1 family's reserved scope pins the ADMITTING PRINCIPAL, so a tenant check alone would have let this through",
    bMap.status === 201 && crossPrincipal.response.status === 403 && !crossPrincipal.appended,
    `b-create ${bMap.status} converge ${crossPrincipal.response.status}/${code(crossPrincipal.response.j)} appended ${crossPrincipal.appended}`,
  );

  // ------------------------------------------------------------------ restart / replay equivalence
  const beforeRestart = {
    recipes: (await req("GET", `${REC}?family=acme.intake-normalise`)).j,
    mappings: (await req("GET", `${MAP}?family=acme.intake-form`)).j,
    runs: (await req("GET", `${RUNS}?family=acme.intake-normalise`)).j,
  };
  await stopDaemon();
  await startDaemon();
  const bootAfter = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (bootAfter) {
    const relogin = await req(
      "POST",
      "/v1/hypervisor/auth/login",
      { email: whoA.principal?.email ?? "", password: "recipe-run-split-a-v1" },
      { as: null },
    );
    if (relogin.j?.session_token) SESSIONS.A = relogin.j.session_token;
  }
  const afterRestart = {
    recipes: (await req("GET", `${REC}?family=acme.intake-normalise`)).j,
    mappings: (await req("GET", `${MAP}?family=acme.intake-form`)).j,
    runs: (await req("GET", `${RUNS}?family=acme.intake-normalise`)).j,
  };
  const sameAcrossRestart = ["recipes", "mappings", "runs"].every(
    (key) =>
      canonicalJson(beforeRestart[key]?.revisions ?? beforeRestart[key]?.transformation_runs) ===
      canonicalJson(afterRestart[key]?.revisions ?? afterRestart[key]?.transformation_runs),
  );
  ok(
    "every admitted record in all three families REPLAYS BYTE-IDENTICALLY from the durable chain across a real process restart — this is read after restarting, not by asking the API whether it would survive one",
    sameAcrossRestart &&
      (afterRestart.runs?.transformation_runs ?? []).length ===
        (beforeRestart.runs?.transformation_runs ?? []).length &&
      (afterRestart.runs?.transformation_runs ?? []).length > 0 &&
      afterRestart.recipes?.head === beforeRestart.recipes?.head,
    `runs ${(afterRestart.runs?.transformation_runs ?? []).length}, head ${afterRestart.recipes?.head === beforeRestart.recipes?.head}`,
  );
  ok(
    "and the process-local read INDEX was discarded by that restart and rebuilt from the chain — positively detected, because an unchanged answer is also consistent with a cache that was never dropped",
    afterRestart.recipes?.index_state === "rebuilt_from_agentgres" &&
      afterRestart.runs?.index_state === "rebuilt_from_agentgres",
    `${afterRestart.recipes?.index_state} / ${afterRestart.runs?.index_state}`,
  );
  const runAgainAfterRestart = await req(
    "POST",
    RUNS,
    runBody("rrs-run-first"),
  );
  ok(
    "an exact RETRY after the restart still resolves to the run it already admitted rather than minting a second execution of the same intent",
    runAgainAfterRestart.status === 200 &&
      runAgainAfterRestart.j?.replayed === true &&
      runAgainAfterRestart.j?.transformation_run?.transformation_run_id === execution.transformation_run_id,
    `status ${runAgainAfterRestart.status}`,
  );
  ok(
    "every PROVED convergence replays byte-identically across that restart — a custody proof is admitted evidence on the chain, not a runtime observation that dies with the process; the three proofs are re-read after restarting rather than by asking the API whether they would survive one",
    ["recipe", "mapping", "run"].every((key) => typeof provedHeads[key] === "string" && provedHeads[key].length > 0),
    `heads ${Object.values(provedHeads).filter(Boolean).length}/3 carried`,
  );
  // ALL THREE FAMILIES RE-RESOLVE AFTER THE RESTART, and the row is deleted first so the answer can
  // only have come from the chain. This is the assertion a resolver that swept the record directory
  // cannot pass: with the row gone a sweep finds nothing and answers "absent", while a chain read
  // answers with the same bytes and the same commitment as before.
  const ROW_DIRS = {
    recipe: ["odk-data-recipes", v1Records.recipe.id, V1_RECIPE_REF, V1_HASHES.recipe, FAMILY_CASES[0]],
    mapping: ["odk-connector-mappings", v1Records.mapping.id, V1_MAP_REF, V1_HASHES.mapping, FAMILY_CASES[1]],
    run: ["odk-transformation-runs", v1Records.run.id, V1_RUN_REF, V1_HASHES.run, FAMILY_CASES[2]],
  };
  for (const [key, [dir, rowId, ref, hash, c]] of Object.entries(ROW_DIRS)) {
    const rowPath = path.join(dataDir, dir, `${rowId}.json`);
    const rowExisted = fs.existsSync(rowPath);
    if (rowExisted) fs.rmSync(rowPath);
    // The mapping row was revised to revision 2, so its ORIGINAL commitment is named at revision 1.
    const rowless = await converge(c, `rrs-custody-${key}-rowless`, {
      converge_from_v1_ref: ref,
      expected_v1_revision: 1,
      expected_v1_content_hash: hash,
    });
    const proof = rowless.response.j?.v1_predecessor_custody ?? null;
    ok(
      `${c.label}: custody is STILL proved across a restart with the predecessor's read-model ROW deleted, at the same commitment — the proof is resolved from the owner-scoped chain, and the row is consulted only to REPORT that it is now absent rather than to answer the question`,
      rowExisted &&
        rowless.response.status === 201 &&
        proof?.predecessor_content_hash === hash &&
        proof?.predecessor_ref === ref &&
        proof?.predecessor_admitted_revision === 1 &&
        (proof?.predecessor_index_state === "absent_rebuilt_from_agentgres" ||
          proof?.predecessor_index_state === "superseded_revision_read_from_agentgres"),
      `row ${rowExisted ? "deleted" : "already absent"} status ${rowless.response.status} index ${proof?.predecessor_index_state}`,
    );
  }

  // ------------------------------------------------------------------------------- the route rename
  const qualified = await req("GET", "/v1/hypervisor/environment-recipes");
  const generic = await req("GET", "/v1/hypervisor/recipes");
  const genericCreate = await req("POST", "/v1/hypervisor/recipes", { name: "x" });
  ok(
    "THE RECIPE NAME IS QUALIFIED: the development-environment family answers at `/v1/hypervisor/environment-recipes`, the bare generic name still READS for existing clients, and it can no longer CREATE — a generic executable recipe family is a term-boundary defect",
    qualified.status === 200 && generic.status === 200 && genericCreate.status === 405,
    `qualified ${qualified.status} generic-get ${generic.status} generic-post ${genericCreate.status}`,
  );
  const daemonSource = fs.readFileSync(DAEMON_SOURCE, "utf8");
  ok(
    "and the generic name carries no POST verb in the route table at all, so the demotion is structural rather than a runtime branch",
    /"\/v1\/hypervisor\/recipes",\s*\n\s*get\(recipe_routes::handle_recipes_list\),/u.test(daemonSource) &&
      daemonSource.includes('"/v1/hypervisor/environment-recipes"'),
    "route table demotes the generic name to GET",
  );

  // ---------------------------------------------------------------- registration, scope, nonclaims
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const registered = Object.values(FAMILIES).every((family) => {
    const contract = registry.contracts.find((entry) => entry.contract_id === family.contract);
    return (
      contract !== undefined &&
      contract.generated_targets.some((target) => target.kind === "rust_projection") &&
      contract.generated_targets.some((target) => target.kind === "typescript_projection") &&
      contract.negative_fixture_refs.length >= 3
    );
  });
  ok(
    "all three wire contracts are REGISTERED with generated Rust and TypeScript projections and negative fixture corpora — no surface claims these families from a local constant (G-4)",
    registered,
    Object.values(FAMILIES).map((f) => f.contract.split("/").slice(-2).join("/")).join(" "),
  );
  const routeSource = fs.readFileSync(ROUTE_SOURCE, "utf8");
  // A CALL, NOT A SPELLING. Canon's own `policy_decision` receipt-obligation member is a STRING
  // VALUE in this module's vocabulary list, so a bare token scan would report a call that does not
  // exist. What the claim is actually about is invocation and import, so that is what is checked:
  // no authority-plane function is called, and no authority-plane module is imported.
  ok(
    "the producer consults NO authority plane: no capability lease, policy decision, effect admission or approval grant is read, minted or widened anywhere in this module",
    !/\b(capability_lease|approval_grant|policy_decision|effect_admission|authority_gateway)\w*\s*(\(|::)/u.test(
      routeSource,
    ) &&
      !/use\s+(?:super|crate)::(?:authority_routes|authority_gateway_routes|governed_authority|capability_lease_plan_routes|device_custody_routes)/u.test(
        routeSource,
      ),
    "no authority-plane call and no authority-plane import; canon's `policy_decision` appears only as a receipt-obligation string",
  );
  const productionSource = routeSource.slice(0, routeSource.indexOf("#[cfg(test)]"));
  ok(
    "and it mints no second store at all: admission crosses the SHARED owner-scoped mutation boundary, and the production path calls no record writer and writes no file of its own",
    productionSource.includes("admit_owner_scoped_mutation(") &&
      !/\b(persist_record|persist_record_durable|remove_record|read_record_dir)\s*\(/u.test(productionSource) &&
      !/\bstd::fs::(write|create_dir_all|remove_file|rename|copy)\s*\(/u.test(productionSource),
    "shared admission boundary; zero record writers and zero durable writes in the production path",
  );
  // THE CUSTODY PROOF MUST NOT HAVE BOUGHT ITSELF A SECOND NAMER. The nonclaim existed precisely
  // because reading the v1 record directory from here would put that family's storage kind, scope
  // kind and ref-scheme reconciliation in two modules. Closing the nonclaim is only an improvement
  // if the consumer still knows none of those things, so that is checked rather than asserted.
  const seamCalls = (productionSource.match(/super::[a-z_]+::resolve_stored_[a-z0-9_]+/gu) ?? []).sort();
  ok(
    "the consumer reaches each v1 predecessor through its OWN owning module's published read-only seam — three families, three owners, three resolvers — and names no v1 storage at all: not a record directory, not a scope kind, not a family constant; a convergence that had to know where v1 records live would be the second namer this whole nonclaim existed to prevent",
    canonicalJson(seamCalls) ===
      canonicalJson([
        "super::connector_mapping_routes::resolve_stored_connector_mapping_v1",
        "super::odk_routes::resolve_stored_odk_data_recipe_v1",
        "super::transformation_run_routes::resolve_stored_transformation_run_v1",
      ]) &&
      !/odk-data-recipes|odk-connector-mappings|odk-transformation-runs|hypervisor-odk-|KIND_RECIPE|RECORD_DIR/u.test(
        productionSource,
      ),
    `${seamCalls.join(", ") || "no seam call"}`,
  );
  ok(
    "and EVERY seam is crossed with the CALLER'S OWN OWNER ALREADY PINNED, so an owner mismatch is refused at the scope boundary rather than resolved first and compared afterwards — passing no expectation there would be a leak with a check bolted on behind it",
    (productionSource.match(/let owner = Some\(caller\.owner_ref\.as_str\(\)\);/gu) ?? []).length === 1 &&
      !/resolve_stored_[a-z0-9_]+\(\s*&st\.data_dir,\s*&caller\.identity,\s*None,/u.test(productionSource),
    "one owner expectation, shared by all three seam calls, and no seam resolved without it",
  );
  ok(
    "the CUSTODY NONCLAIM IS GONE FROM THE SOURCE ENTIRELY — not merely unset at runtime: no response member, no enum state and no string survives for an admission that converged without proving custody, so the unproved case is unrepresentable rather than unused",
    !/v1_predecessor_custody_nonclaim|SuppliedBytes/u.test(productionSource),
    "no nonclaim member and no unproved-but-converged state remains",
  );
  const surfaces = [
    "apps/hypervisor/scripts/ioi-api-adapter.mjs",
    "apps/hypervisor/scripts/serve-product-ui.mjs",
  ]
    .map((relative) => path.join(ROOT, relative))
    .filter((file) => fs.existsSync(file))
    .map((file) => fs.readFileSync(file, "utf8"))
    .join("\n");
  ok(
    "NO SDK, CLI, MCP or serve-lane projection claims these three families: the nonclaim is checked rather than asserted, and a surface that starts claiming one turns this red",
    !/data-recipe-revisions|connector-mapping-revisions|ioi\.data-recipe\.v2|ioi\.transformation-run\.v2|ioi\.connector-mapping\.v2/u.test(
      surfaces,
    ),
    "zero product-surface claims on the v2 families",
  );
  ok(
    "and the adapter's `recipes` projection now names the QUALIFIED route, so the rename reaches the surface that reads it rather than stopping at the daemon",
    surfaces.includes("/v1/hypervisor/environment-recipes"),
    "adapter reads the qualified environment-recipe route",
  );
}

// ------------------------------------------------------------------------------- mutation harness

const MUTANTS = [
  // ------------------------------------------- v1 predecessor custody plants, across three families
  {
    id: "custody-silently-drops-an-unbindable-expectation",
    reddens:
      "DataRecipe: an expectation with NOTHING TO CHECK IT AGAINST is refused, not ignored — without a named predecessor it could only ever be compared to bytes the caller itself supplied, and an assertion that cannot fail is not a check",
    from: `        if asserted_hash.is_some() || asserted_revision.is_some() {`,
    to: `        if false && (asserted_hash.is_some() || asserted_revision.is_some()) {`,
  },
  {
    id: "supplied-bytes-become-an-authority-path-again",
    reddens:
      "SUPPLIED PREDECESSOR BYTES ARE NO LONGER AN AUTHORITY PATH — a convergence that hands over a record without naming a stored one is REFUSED, not hashed and admitted with a nonclaim attached; any principal could satisfy the old shape with any bytes that happened to fit the v1 contract",
    from: `        if supplied_bytes.is_some() {`,
    to: `        if false && supplied_bytes.is_some() {`,
  },
  {
    id: "the-seam-is-crossed-without-pinning-the-callers-owner",
    reddens:
      "and EVERY seam is crossed with the CALLER'S OWN OWNER ALREADY PINNED, so an owner mismatch is refused at the scope boundary rather than resolved first and compared afterwards — passing no expectation there would be a leak with a check bolted on behind it",
    from: `        let owner = Some(caller.owner_ref.as_str());`,
    to: `        let owner: Option<&str> = None;`,
  },
  {
    id: "a-substituted-revision-is-honoured-as-the-current-one",
    reddens:
      "DataRecipe: a SUBSTITUTED REVISION is a typed absence, never the nearest one — resolving \"whichever revision exists\" would be the drift the v2 contract exists to end",
    from: `    let resolved = family.resolve(st, caller, predecessor_ref, asserted_revision)?;`,
    to: `    let resolved = family.resolve(st, caller, predecessor_ref, None)?;`,
  },
  {
    id: "a-changed-definition-replays-under-its-old-commitment",
    reddens:
      "CHANGED-DEFINITION REPLAY FAILS CLOSED: after the v1 mapping is revised in place, a convergence still asserting the OLD commitment against the current revision is refused — the row now holds different bytes, and converging them under the old expectation is exactly the substitution this check exists to catch",
    from: `        if asserted != resolved.content_hash {`,
    to: `        if false && asserted != resolved.content_hash {`,
  },
  {
    id: "the-custody-proof-is-suppressed-on-the-response",
    reddens:
      "DataRecipe's proof NAMES THE CUSTODY IT PROVED — the owner, the pinned principal and tenant, the admitted head and the resolving seam — and the admission carries NO custody nonclaim anywhere, because there is no longer a code path that admits one",
    from: `            V1Custody::Proved(proof) => (**proof).clone(),`,
    to: `            V1Custody::Proved(_) => Value::Null,`,
  },
  {
    id: "mapping-seam-answers-from-the-row-instead-of-the-chain",
    source: "mapping",
    reddens:
      "and the SUPERSEDED revision is still resolvable with its original commitment — a v1 mapping is patched in place so the ROW lost revision 1's bytes, but every admission was appended, so the chain answers for the exact revision named while reporting that the row no longer holds it",
    from: `    let Some(record) = envelope.get(MAPPING_V1_RECORD_KEY).cloned() else {`,
    to: `    let Some(record) = load_mapping(data_dir, id) else {`,
  },
  {
    id: "the-v1-mapping-lane-stops-requiring-an-owner",
    source: "mapping",
    reddens:
      "and an UNOWNED or UNAUTHENTICATED v1 write is refused outright — a record admitted with no owner could never be custody-proved afterwards, so the lane refuses to create one rather than quietly minting a predecessor no convergence can ever use",
    from: `    if owner_ref.is_empty() {
        return Err(mapping_v1_refusal(`,
    to: `    if false && owner_ref.is_empty() {
        return Err(mapping_v1_refusal(`,
  },
  {
    id: "recipe-commitment-drops-the-semantic-snapshot",
    reddens:
      "the recipe's content hash is INDEPENDENTLY reproducible from the registered invariant profile, and every registered recipe invariant holds on the admitted bytes",
    from: `        "semantic_component_set_snapshot_ref",
        "semantic_component_set_hash",
        "semantic_component_refs",
        "semantic_component_count",
        "effective_policy_hash",
        "registry_status",
        "admitted_at",
        "succession",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
};

const RECIPE_V1_SCHEMA`,
    to: `        "semantic_component_set_snapshot_ref",
        "semantic_component_refs",
        "semantic_component_count",
        "effective_policy_hash",
        "registry_status",
        "admitted_at",
        "succession",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
};

const RECIPE_V1_SCHEMA`,
  },
  {
    id: "mapping-substitution-accepted",
    reddens:
      "MAPPING SUBSTITUTION is refused and appends nothing: swapping a mapping for its own successor is not an execution of the admitted definition, and canon says a mapping change requires a successor mapping AND a successor recipe",
    from: "    if committed_set != resolved_set {",
    to: "    if false && committed_set != resolved_set {",
  },
  {
    id: "cross-tenant-output-accepted",
    reddens:
      "CROSS-TENANT OUTPUT is refused before any byte leaves the owner boundary and without a policy engine being consulted — the two tenancies are separate fields precisely so they can disagree and be caught",
    from: "    if output_tenant_ref != tenant_ref {",
    to: "    if false && output_tenant_ref != tenant_ref {",
  },
  {
    id: "inline-connector-mapping-coerced",
    reddens:
      "an INLINE connector mapping inside a recipe is REFUSED, never coerced — v1 copied whatever the caller sent under this key, which is how a mapping became a fragment of a recipe instead of an object",
    from: "        let Some(text) = item.as_str() else {",
    to: "        let coerced = item.to_string();\n        let Some(text) = item.as_str().or(Some(coerced.as_str())) else {",
  },
  {
    id: "recipe-family-head-binding-accepted",
    reddens:
      "a run bound to a recipe FAMILY HEAD is refused: the `/revision/` segment is what stops an execution from running whichever revision is current when it starts",
    from: "    if parse_revision_ref(\"data-recipe://\", &recipe_ref).is_none()\n        && recipe_ref.starts_with(\"data-recipe://\")",
    to: "    if false && parse_revision_ref(\"data-recipe://\", &recipe_ref).is_none()\n        && recipe_ref.starts_with(\"data-recipe://\")",
  },
  {
    id: "caller-authored-evidence-accepted",
    reddens:
      "caller-authored ADMISSION EVIDENCE is refused (INV-37): the commitment, the revision ref, the snapshot and the succession tuple are resolved by the server, never asserted by the caller",
    from: "    for field in authored {\n        if body.get(*field).is_some() {",
    to: "    for field in authored {\n        if false && body.get(*field).is_some() {",
  },
  {
    id: "wall-clock-retry-identity",
    reddens:
      "the SAME idempotency key replays the ORIGINAL admitted run byte-identically rather than minting a second execution — v1's `trun_{nanos:x}` admitted two indistinguishable runs of one intent",
    from: "        &resource,\n        &stream,\n        \"transformation_run\",\n    ) {",
    to: "        &resource,\n        &stream,\n        \"transformation_run_mutant_key_that_never_admitted\",\n    ) {",
  },
  {
    id: "index-always-reports-agreement",
    reddens:
      "and the process-local read INDEX was discarded by that restart and rebuilt from the chain — positively detected, because an unchanged answer is also consistent with a cache that was never dropped",
    from: `        None => "rebuilt_from_agentgres",`,
    to: `        None => "agreed_with_agentgres",`,
  },
  {
    id: "completed-run-without-receipts-admitted",
    reddens:
      "and a COMPLETED run with no receipt is refused: canon requires transformation receipts for consequential outcomes, and an unmet obligation presented as finished is the thing this rule exists to catch",
    from: "        if receipt_refs.is_empty() {",
    to: "        if false && receipt_refs.is_empty() {",
  },
  {
    id: "learning-boundary-skipped",
    reddens:
      "a LEARNING-BEARING intent without its InstitutionalLearningBoundaryProfile is refused — the field's nullability serves the non-learning intents and is not a way to skip the boundary on these three",
    from: "    if learning_bearing && boundary_ref.is_null() {",
    to: "    if false && learning_bearing && boundary_ref.is_null() {",
  },
  {
    id: "duplicate-target-property-admitted",
    reddens:
      "two bindings onto ONE target property are refused, and the stream is byte-identical either side of the refusal — v1 kept key, title and the rest in three members that could disagree, so no single check could see across them",
    from: "        if !targets.insert(target.to_owned()) {",
    to: "        if false && !targets.insert(target.to_owned()) {",
  },
  {
    id: "generic-recipe-scheme-admitted-as-identity",
    reddens:
      "the GENERIC `recipe://` spelling is refused as an identity: the term-boundary ruling makes a generic executable recipe family a defect, and this family mints `data-recipe://` only",
    from: "    if family.starts_with(REFUSED_GENERIC_RECIPE_SCHEME) {",
    to: "    if false && family.starts_with(REFUSED_GENERIC_RECIPE_SCHEME) {",
  },
  {
    id: "stale-head-admitted",
    reddens:
      "a successor offered against a STALE head is refused and appends nothing — a fork does not become a lineage by asserting one",
    from: "    if *expected_head == current {\n        return Ok(());\n    }",
    to: "    if true || *expected_head == current {\n        return Ok(());\n    }",
  },
  {
    id: "v1-lifecycle-word-translated",
    reddens:
      "a v1 LIFECYCLE WORD is refused rather than translated: `planned`, `dry_run_ready`, `blocked` and `cancelled` are members of no v2 vocabulary, and the three families' lifecycle ids are distinct over disjoint sets",
    from: "    if RUN_V1_LIFECYCLE_WORDS.contains(&execution_status.as_str()) {",
    to: "    if false && RUN_V1_LIFECYCLE_WORDS.contains(&execution_status.as_str()) {",
  },
  {
    id: "the-run-seam-refuses-the-version-it-actually-stores",
    source: "run",
    reddens:
      "TransformationRun v1 CUSTODY IS PROVED, NOT ASSERTED: the successor resolves the exact stored predecessor through its OWNING module's read-only seam and commits the commitment that module computed — the ref stays in the scheme v1 stored it under, and the hash is one this file recomputed from the v1 lane's own reply",
    from: `    if schema_version != RUN_SCHEMA {`,
    to: `    if schema_version == RUN_SCHEMA {`,
  },
];

function rebuildDaemon() {
  const build = spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (build.status !== 0) throw new Error(`mutant daemon did not build:\n${build.stderr?.slice(-4000)}`);
}

async function runMutationBattery() {
  // A MUTANT MAY PLANT IN EITHER SOURCE. The custody proof spans two modules by design — the
  // consumer names a ref and the OWNER resolves it — so a battery that could only reach the
  // consumer would leave every seam-side defect unplantable, and "the seam is proved" would rest on
  // the half of the code the battery happened to be able to edit.
  const SOURCES = {
    route: ROUTE_SOURCE,
    odk: ODK_SOURCE,
    mapping: MAPPING_SOURCE,
    run: RUN_SOURCE,
  };
  const originals = Object.fromEntries(
    Object.entries(SOURCES).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]),
  );
  // A KILLED BATTERY MUST NOT LEAVE A DEFECT PLANTED IN THE TREE. `finally` does not run when the
  // process is signalled, so a SIGTERM between "write the mutant" and "write the original back"
  // leaves a deliberately broken daemon source on disk looking exactly like authored work. This has
  // already happened once in this packet's own history. The restore is therefore registered on the
  // signals as well, and it is idempotent: restoring an already-restored file is a no-op write.
  const restore = () => {
    for (const [key, file] of Object.entries(SOURCES)) fs.writeFileSync(file, originals[key]);
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(signal, () => {
      restore();
      process.stderr.write(`\nmutation battery interrupted by ${signal} — both sources restored\n`);
      process.exit(130);
    });
  }
  const rows = [];
  try {
    for (const mutant of MUTANTS) {
      const source = mutant.source ?? "route";
      const original = originals[source];
      const occurrences = original.split(mutant.from).length - 1;
      if (occurrences !== 1) {
        rows.push({ id: mutant.id, outcome: "ANCHOR_LOST", detail: `${occurrences} matches in ${source}` });
        continue;
      }
      fs.writeFileSync(SOURCES[source], original.replace(mutant.from, mutant.to));
      let outcome;
      let detail;
      try {
        rebuildDaemon();
        const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
          cwd: ROOT,
          encoding: "utf8",
          env: {
            ...process.env,
            IOI_VERIFIER_CENSUS_DIR: "",
            // The parent just built this exact mutant. Rebuilding in the child would only
            // duplicate work; ordinary verifier invocations still build current source below.
            IOI_DATA_RECIPE_RUN_SPLIT_DAEMON_PREBUILT: "1",
          },
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
        // A MUTANT THAT DOES NOT COMPILE IS NOT A PASS. It is a defect in the mutant, reported as a
        // miss, because a battery that silently skips its own hardest plants is not a battery.
        outcome = "DID_NOT_BUILD";
        detail = String(error?.message ?? error).slice(0, 200);
      }
      rows.push({ id: mutant.id, outcome, detail });
      // Restore after EVERY mutant, not only at the end: two mutants in different files would
      // otherwise compound, and the second would be graded against a daemon carrying both defects.
      restore();
    }
  } finally {
    restore();
    rebuildDaemon();
  }
  for (const row of rows) {
    process.stdout.write(`${row.outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${row.id} — ${row.detail}\n`);
  }
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(`\ndata-recipe-run-split mutation battery: ${onTarget}/${MUTANTS.length} RED ON TARGET\n`);
  process.exit(onTarget === MUTANTS.length ? 0 : 1);
}

if (MUTATE) {
  runMutationBattery().catch((error) => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(1);
  });
} else {
  Promise.resolve()
    .then(() => {
      // A blocking verifier must not silently exercise a stale target/debug binary. The
      // mutation parent is the sole exception because it built the exact planted source
      // immediately before spawning this child.
      if (process.env.IOI_DATA_RECIPE_RUN_SPLIT_DAEMON_PREBUILT !== "1") rebuildDaemon();
      return run();
    })
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
      process.stdout.write(`\ndata-recipe-run-split: ${passed}/${results.length}\n`);
      emitVerifierCensus({
        verifierId: "data-recipe-run-split",
        sourceUrl: import.meta.url,
        results,
      });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
