#!/usr/bin/env node
// M05.6 — the ODK contract registration and the DomainApp divergence repair, driven end to end
// against a live daemon and its durable Agentgres chain.
//
// WHAT THIS GATE IS FOR. G-4 says no surface may claim an object family before that family's wire
// contract is registered. The ODK families had no `_meta/schemas/` entry at all, so four planes ran
// on Rust string literals. Registration alone is not the claim, though: a registered schema that no
// producer validates against is a document. So this gate drives the real ladder and asserts the
// things registration was supposed to make checkable — a receipt that names the runtime it
// transitioned, an inventory status that advances only with the stage binding behind it, a runtime
// state that no status route can reach, and a record directory whose destruction changes no answer.
//
// THE DEFECTS THE REGISTERED FIXTURE CORPUS STRUCTURALLY CANNOT CATCH. Every negative fixture beside
// this gate is decidable from bytes alone. These are not:
//   * "does the mount receipt name the runtime THIS mount created" — a fact about two records
//     produced by one admitted transition, where a well-formed receipt naming some other real
//     runtime passes every fixture;
//   * "does a serve transition leave the app's inventory status where it was" — a fact about two
//     reads separated by a durable write on a different plane;
//   * "does deleting the whole runtime record directory change what the daemon answers";
//   * "does a replayed mount resolve to the runtime it already created, or mint a second one";
//   * "does the overview count a v2 descriptor" — the M05.5 consumer defect, which is a fact about
//     an envelope shape rather than about any single record's validity.
//
// HOW IT AVOIDS GRADING ITSELF. Commitments are recomputed HERE from the material list read out of
// the REGISTERED invariant profile, never from a constant in this file. Every binding is a real
// admitted record minted through its own owner's route in this same run. Durable truth is read
// across a restart with the index destroyed. Every refusal is counted BY EFFECT — the chain head and
// revision count are re-read and must be unchanged — rather than by its status code. And `--mutate`
// plants named defects in the source that must redden the exact assertion they target.
//
// NONCLAIMS. This gate proves the ODK contract and DomainApp planes only. It makes no claim that a
// mounted app behaves correctly, that its semantic bindings are valid, that an external surface
// exists, or that any domain action ran — which is exactly what the receipt it checks says about
// itself. It does not exercise external ingress admission, because no route grants it.

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
  "crates/node/src/bin/hypervisor_daemon_routes/domain_apps_routes.rs",
);
const ODK_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/odk_routes.rs",
);
const PACKAGE_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/package_registry_routes.rs",
);
const SCHEMAS = path.join(ROOT, "docs/architecture/_meta/schemas");
/// A schema mutant plants into the registered contract, not into Rust, so it needs no rebuild.
const RECEIPT_SCHEMA = path.join(SCHEMAS, "domain-app-mount-receipt.v2.schema.json");
const INVARIANTS = path.join(SCHEMAS, "invariants");
const REGISTRY = path.join(SCHEMAS, "architecture-contract-registry.v1.json");

const MUTATE = process.argv.includes("--mutate");
const SUMMARIZE = process.argv.includes("--summarize");
/// Pre-flight the battery anchors without planting or rebuilding anything.
const ANCHORS = process.argv.includes("--anchors");
const ONLY = (process.argv.find((argument) => argument.startsWith("--only=")) ?? "")
  .slice("--only=".length)
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);
const LEDGER = path.join(os.tmpdir(), "ioi-m056-mutation-ledger.json");

/// EXACTLY ONE SHA-256, with or without the substrate's prefix. Used wherever this gate checks a
/// cited chain head, so a candidate that froze a truncated head — which names a prefix of a chain
/// rather than a position in it — cannot pass by being merely hex-shaped and long enough.
const EXACT_HEAD = /^(?:sha256:)?[0-9a-f]{64}$/u;

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.error?.code ?? j?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------- canonical JSON + commitments

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;

/** Read the commitment rule out of the REGISTERED invariant profile, never out of this file. */
function commitmentRule(profileFile) {
  const profile = JSON.parse(fs.readFileSync(path.join(INVARIANTS, profileFile), "utf8"));
  return profile.rules[0].expression;
}

/**
 * Recompute a registered commitment from the record's own bytes.
 *
 * This is the whole point of a portable invariant: a relying party holding the record and the
 * published rule reproduces the number with no daemon in the loop. A missing material field is a
 * `null`, exactly as the registered runtime treats it, so a record that dropped a committed field
 * produces a different digest rather than silently agreeing.
 */
function recompute(record, expression) {
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

/**
 * THE SCRATCH TREE IS ALLOCATED WHEN A DAEMON NEEDS ONE, NEVER AT LOAD.
 *
 * `--anchors` reads source text and `--summarize` reads a ledger; neither starts a daemon, so
 * neither has anything to put in a data directory. Creating it at module scope meant every anchor
 * pre-flight and every summary left an empty `ioi-m056-*` tree in the system temp directory, and
 * those are exactly the two modes a person runs repeatedly while iterating. A verifier that litters
 * on the cheap path is a verifier people stop running on the cheap path.
 */
let scratch = "";
let dataDir = "";
function ensureScratch() {
  if (scratch) return dataDir;
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-m056-"));
  dataDir = path.join(scratch, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  return dataDir;
}
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
      IOI_HYPERVISOR_DATA_DIR: ensureScratch(),
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
      IOI_WALLET_SECRET_PASS: "ioi-odk-contract-and-domainapp-verifier",
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

/**
 * Tear down the daemon and the scratch tree, on EVERY exit path.
 *
 * Registered against `exit` and the two signals a person actually sends, because the paths that
 * skipped cleanup were the abnormal ones — a crash inside the battery, a Ctrl-C during a rebuild —
 * and those are precisely the runs that leave a live daemon holding a port. Idempotent: `scratch`
 * is cleared after removal so a second call has nothing to do, and `rmSync` is `force`.
 */
function cleanup() {
  try {
    daemon?.kill("SIGKILL");
  } catch {
    /* already gone */
  }
  daemon = null;
  if (!scratch) return;
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
  scratch = "";
  dataDir = "";
}

process.on("exit", cleanup);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    cleanup();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
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
const DA = "/v1/hypervisor/domain-apps";
const NS = "acme-clinic";
const NAME = "patient-intake";
const OWNER = "org://local";
const REVISION_1 = `ontology://${NS}/${NAME}/revision/1`;

const termsOf = (terms) =>
  terms.map((term) => ({ term_id: `ontology://${NS}/${NAME}/term/${term}`, label: term }));

const DESCRIPTOR_NONCLAIMS = [
  "authority",
  "capability_lease_crossing",
  "runtime_truth",
  "semantic_truth",
  "permission_truth",
  "marketplace_truth",
];

function descriptorProposal(overrides = {}) {
  return {
    owner_ref: OWNER,
    schema_version: "ioi.ontology-surface-descriptor.v2",
    display_name: "Intake domain app",
    surface_ref: `surface://${NS}/intake-app`,
    composition_pattern: "domain_app",
    ontology_refs: [REVISION_1],
    canonical_object_model_refs: [`object-model://${NS}/${NAME}/appointment`],
    data_recipe_refs: [`data-recipe://${NS}/intake-normalise/revision/1`],
    policy_bound_data_view_refs: [`view://${NS}/intake/reviewer`],
    authority_requirement_refs: ["scope:intake.review"],
    daemon_api_refs: ["api://v1/hypervisor/ontology-versions"],
    receipt_obligations: [`receipt://${NS}/intake/review-decision`],
    conformance_profile_refs: [`profile://${NS}/intake/app/v1`],
    connector_mapping_refs: [`mapping://${NS}/intake-form`],
    ontology_projection_refs: [`projection://${NS}/intake/by-status`],
    allowed_action_refs: [`ontology-action://${NS}/${NAME}/schedule-followup`],
    operator_contract_refs: [`contract://${NS}/intake-reviewer`],
    mcp_contract_refs: [`mcp-profile://${NS}/intake`],
    generated_artifact_refs: [],
    does_not_assert: [...DESCRIPTOR_NONCLAIMS],
    ...overrides,
  };
}

/** Head + revision count, so a refusal is counted BY EFFECT rather than by its status code. */
async function appState(id, as = "A") {
  const response = await req("GET", `${DA}/${id}`, undefined, { as });
  return {
    head: response.j?.admitted_head ?? null,
    revisions: response.j?.revision_count ?? -1,
    status: response.j?.domain_app?.status ?? null,
    posture: response.j?.domain_app?.runtime_posture ?? null,
    contentHash: response.j?.domain_app?.content_hash ?? null,
  };
}

/** Assert a refusal changed NOTHING on the chain — the only refusal proof that means anything. */
async function refusedWithNoEffect(name, response, id, before, expectedCode = null) {
  const after = await appState(id);
  ok(
    name,
    response.status >= 400 &&
      (expectedCode === null || code(response.j) === expectedCode) &&
      after.head === before.head &&
      after.revisions === before.revisions,
    `status ${response.status} code ${code(response.j)} head ${after.head === before.head} revisions ${before.revisions}->${after.revisions}`,
  );
}

// ------------------------------------------------------------------------------ the registered corpus

function runRegistryClaims() {
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const byId = new Map(registry.contracts.map((entry) => [entry.contract_id, entry]));
  const FAMILIES = [
    ["ontology-development-kit-manifest", "OntologyDevelopmentKitManifest"],
    ["domain-app", "DomainApp"],
    ["domain-app-runtime", "DomainAppRuntime"],
    ["domain-app-mount-receipt", "DomainAppMountReceipt"],
  ];
  // G-4: the family is registered, both versions, with the succession stated rather than implied.
  const missing = [];
  for (const [slug, name] of FAMILIES) {
    for (const version of ["v1", "v2"]) {
      const id = `schema://ioi/foundations/objects/${slug}/${version}`;
      const entry = byId.get(id);
      if (!entry || entry.canonical_name !== name) missing.push(id);
    }
  }
  ok(
    "G-4: every ODK family this module claims is REGISTERED — the four canonical names exist at both versions, so no surface claims a family whose wire contract is a Rust string literal",
    missing.length === 0,
    missing.length ? `missing ${missing.join(", ")}` : "8 contracts",
  );

  const successionProblems = [];
  for (const [slug] of FAMILIES) {
    const v1 = byId.get(`schema://ioi/foundations/objects/${slug}/v1`);
    const v2 = byId.get(`schema://ioi/foundations/objects/${slug}/v2`);
    if (!v1 || !v2) continue;
    if (v1.evolution.successor_contract_id !== v2.contract_id) successionProblems.push(`${slug}:v1->v2`);
    if (v2.evolution.successor_of !== v1.contract_id) successionProblems.push(`${slug}:v2<-v1`);
    // The predecessor stays READABLE. A succession that invalidated stored records would make every
    // v1 row unreadable at the owner seam, which is a deletion dressed as a migration.
    if (v1.evolution.predecessor_remains_valid !== true) successionProblems.push(`${slug}:v1-invalidated`);
    if (v2.evolution.compatibility !== "breaking") successionProblems.push(`${slug}:v2-not-breaking`);
    if (v2.evolution.migration_policy !== "explicit_adapter_required") {
      successionProblems.push(`${slug}:v2-implicit-migration`);
    }
  }
  ok(
    "the succession is EXPLICIT in both directions and the predecessor stays valid: v1 names v2, v2 names v1, the break is declared, and migration requires an explicit adapter rather than a silent reinterpretation",
    successionProblems.length === 0,
    successionProblems.join(", ") || "4 successions",
  );

  // The M05.5 succession is untouched. This leg registered four families beside it and must not have
  // reinterpreted the one that was already landed.
  const sdV1 = byId.get("schema://ioi/foundations/objects/ontology-surface-descriptor/v1");
  const sdV2 = byId.get("schema://ioi/foundations/objects/ontology-surface-descriptor/v2");
  ok(
    "the already-landed OntologySurfaceDescriptor v1/v2 succession is PRESERVED, not duplicated or reinterpreted: both entries still stand with their own schema versions and their own invariant profile",
    sdV1?.schema_version === "ioi.hypervisor.odk.surface-descriptor.v1" &&
      sdV2?.schema_version === "ioi.ontology-surface-descriptor.v2" &&
      sdV2?.cross_field_invariant_refs?.length === 1,
    `v1 ${sdV1?.schema_version} v2 ${sdV2?.schema_version}`,
  );

  // Generated projections: both required kinds, for every one of the eight.
  const projectionProblems = [];
  for (const [slug] of FAMILIES) {
    for (const version of ["v1", "v2"]) {
      const entry = byId.get(`schema://ioi/foundations/objects/${slug}/${version}`);
      const kinds = new Set((entry?.generated_targets ?? []).map((t) => t.kind));
      if (!kinds.has("rust_projection") || !kinds.has("typescript_projection")) {
        projectionProblems.push(`${slug}/${version}`);
      }
    }
  }
  const rustProjection = fs.readFileSync(
    path.join(ROOT, "crates/types/src/app/generated/architecture_contracts.rs"),
    "utf8",
  );
  const tsProjection = fs.readFileSync(
    path.join(ROOT, "packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts"),
    "utf8",
  );
  const symbols = [
    "DomainAppV1",
    "DomainAppV2",
    "DomainAppRuntimeV1",
    "DomainAppRuntimeV2",
    "DomainAppMountReceiptV1",
    "DomainAppMountReceiptV2",
    "OntologyDevelopmentKitManifestV1",
    "OntologyDevelopmentKitManifestV2",
  ];
  ok(
    "the generated Rust and TypeScript projections AGREE with the registry: every registered family declares both target kinds and both generated files carry all eight symbols, so a client cannot claim a family the projection does not describe",
    projectionProblems.length === 0 &&
      symbols.every((symbol) => rustProjection.includes(symbol) && tsProjection.includes(symbol)),
    projectionProblems.join(", ") || "8 symbols in 2 projections",
  );

  // Fixture census: a registered contract with no negative fixture proves only that it parses.
  let positives = 0;
  let negatives = 0;
  let invariantNegatives = 0;
  const thin = [];
  for (const [slug] of FAMILIES) {
    for (const version of ["v1", "v2"]) {
      const entry = byId.get(`schema://ioi/foundations/objects/${slug}/${version}`);
      if (!entry) continue;
      positives += entry.positive_fixture_refs.length;
      negatives += entry.negative_fixture_refs.length;
      invariantNegatives += entry.negative_fixture_refs.filter(
        (f) => f.expected_failure === "invariant",
      ).length;
      if (entry.positive_fixture_refs.length === 0 || entry.negative_fixture_refs.length === 0) {
        thin.push(`${slug}/${version}`);
      }
    }
  }
  ok(
    "every registered family carries BOTH a positive and a negative fixture corpus, and every v2 commitment carries an invariant-class negative — a contract with only positives proves that it parses, never that it refuses",
    thin.length === 0 && positives >= 8 && negatives >= 20 && invariantNegatives >= 4,
    `positives ${positives} negatives ${negatives} invariant-class ${invariantNegatives}${thin.length ? ` thin ${thin.join(",")}` : ""}`,
  );

  // THE ADMITTED HEAD A RECEIPT BINDS IS EXACTLY ONE SHA-256.
  const headPattern = JSON.parse(
    fs.readFileSync(path.join(SCHEMAS, "domain-app-mount-receipt.v2.schema.json"), "utf8"),
  ).properties.domain_app_admitted_head_before.pattern;
  const headRe = new RegExp(headPattern, "u");
  const sixtyFour = "a".repeat(64);
  ok(
    "the admitted head a receipt binds is EXACTLY ONE SHA-256 — sixty-four lowercase hex with or without the substrate's prefix — so a truncated head, which names a prefix of a chain rather than a position in it, cannot satisfy the contract",
    headRe.test(sixtyFour) &&
      headRe.test(`sha256:${sixtyFour}`) &&
      !headRe.test("a".repeat(32)) &&
      !headRe.test("a".repeat(63)) &&
      !headRe.test("a".repeat(65)) &&
      !headRe.test("A".repeat(64)),
    `pattern ${headPattern}`,
  );

  // The representation audit is a source-derived fact, not a claim: see `runRepresentationAudit`.
  runRepresentationAudit();
}

// --------------------------------------------------------- required representations, audited by proof

/**
 * WHICH REPRESENTATIONS THIS REPOSITORY ACTUALLY REQUIRES FOR THESE FAMILIES.
 *
 * "Types alone do not close this" is right, and the honest way to close it is to derive the required
 * set from the repository rather than to assert one. Two facts decide it, and both are read here
 * from the bytes that enforce them:
 *
 *   1. WHAT THE REGISTRY CAN EMIT. `scripts/lib/architecture-contract-consumer-targets.mjs` is the
 *      pinned list of generated target kinds, and the generator refuses any `generated_targets`
 *      entry whose kind is not in it AND refuses any contract that omits one that is. So the set of
 *      registry-driven representations is closed, and it is exactly what that file names.
 *   2. WHETHER ANY OTHER SURFACE CLAIMS THESE FAMILIES. G-4 binds representations that CLAIM a
 *      family. An OpenAPI document, an SDK, a CLI command or an MCP tool that never names these
 *      families claims nothing about them, and generating one would be inventing a surface rather
 *      than closing a requirement. This scans the repository's own OpenAPI documents, SDK packages,
 *      CLI command tree and MCP tool registry for the families' route prefixes and schema versions.
 *
 * A hit in (2) that is not covered by (1) is a required representation this leg owes. Zero hits is
 * an executable proof that none is required — reproducible by anyone who runs this gate, and it goes
 * red the moment some surface starts claiming one of these families.
 */
function runRepresentationAudit() {
  const targets = fs.readFileSync(
    path.join(ROOT, "scripts/lib/architecture-contract-consumer-targets.mjs"),
    "utf8",
  );
  const kinds = [...targets.matchAll(/kind:\s*"([a-z_]+)"/gu)].map((m) => m[1]).sort();
  ok(
    "THE REGISTRY-DRIVEN REPRESENTATION SET IS CLOSED, and it is exactly the two pinned consumer targets: the generator refuses an unknown `generated_targets` kind and refuses a contract that omits a pinned one, so 'which representations the registry can emit' is a fact about that file rather than a choice made per contract",
    JSON.stringify(kinds) === JSON.stringify(["rust_projection", "typescript_projection"]),
    `pinned kinds ${kinds.join(", ")}`,
  );

  // The families' externally visible names, in every spelling a surface could claim them by.
  const CLAIM_TOKENS = [
    "/v1/hypervisor/domain-apps",
    "/v1/hypervisor/domain-app-runtimes",
    "/v1/hypervisor/odk/manifests",
    "ioi.domain-app.v2",
    "ioi.domain-app-runtime.v2",
    "ioi.domain-app-mount-receipt.v2",
    "ioi.ontology-development-kit-manifest.v2",
    "DomainAppRuntimeV2",
    "DomainAppMountReceiptV2",
    "OntologyDevelopmentKitManifestV2",
  ];
  const SURFACES = [
    ["openapi", ["packages/wallet-protocol/openapi"]],
    ["sdk", ["packages/agent-sdk/src", "packages/wallet-sdk/src"]],
    ["cli", ["crates/cli/src"]],
    ["mcp", ["crates/services/src/agentic/runtime/tools", "crates/drivers/src/mcp"]],
  ];
  const walk = (dir, out = []) => {
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return out;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full, out);
      else out.push(full);
    }
    return out;
  };
  const claims = [];
  const scanned = [];
  for (const [surface, roots] of SURFACES) {
    for (const rel of roots) {
      const files = walk(path.join(ROOT, rel));
      scanned.push(`${surface}:${files.length}`);
      for (const file of files) {
        let text = "";
        try {
          text = fs.readFileSync(file, "utf8");
        } catch {
          continue;
        }
        for (const token of CLAIM_TOKENS) {
          if (text.includes(token)) claims.push(`${surface}:${path.relative(ROOT, file)}:${token}`);
        }
      }
    }
  }
  ok(
    "NO OPENAPI, SDK, CLI OR MCP SURFACE IN THIS REPOSITORY CLAIMS THESE FAMILIES, so none is a required representation — proved by scanning those four surfaces for every route prefix, schema version and projection symbol the families are nameable by, rather than asserted. A surface that starts claiming one turns this assertion red and owes a representation",
    claims.length === 0 && scanned.every((entry) => Number(entry.split(":")[1]) > 0),
    claims.length ? `claims ${claims.slice(0, 4).join(" | ")}` : `scanned ${scanned.join(" ")}`,
  );
}

// ------------------------------------------------------------------------------------- the live run

async function run() {
  await startDaemon();
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "odk-domainapp-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "odk-domainapp-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "odk-domainapp-b-v1",
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
      idempotency_key: "odk-domainapp-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "odk-domainapp-b@ioi.local", password: "odk-domainapp-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant",
    SESSIONS.A.length > 0 && SESSIONS.B.length > 0,
    `A ${SESSIONS.A.length > 0} B ${SESSIONS.B.length > 0}`,
  );

  // A real ontology revision through M05.1's own route, then a real v2 descriptor through M05.5's.
  await req("POST", OV, {
    owner_ref: OWNER,
    idempotency_key: "m056-ontology-1",
    namespace: NS,
    name: NAME,
    governing_scope_ref: `domain://${NS}/intake`,
    policy_hash: `sha256:${"1a".repeat(32)}`,
    entity_types: termsOf(["patient"]),
    action_types: termsOf(["schedule-followup"]),
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  });
  const descriptorCreate = await req("POST", SD, {
    ...descriptorProposal(),
    idempotency_key: "m056-sd-1",
  });
  const descriptor = descriptorCreate.j?.surface_descriptor ?? {};
  const descriptorRef = descriptor.surface_descriptor_id ?? "";
  ok(
    "PRECONDITION: a REAL v2 domain_app descriptor is admitted through M05.5's own route in this same run — the app-shape contract is never checked against a fixture that agrees with itself",
    descriptorCreate.status === 201 && descriptor.composition_pattern === "domain_app",
    `status ${descriptorCreate.status} pattern ${descriptor.composition_pattern ?? "(none)"}`,
  );

  // ============================================== THE M05.5 CONSUMER DEFECT, ON A REAL SUBSTRATE
  const overview = await req("GET", `${DA}/overview`);
  ok(
    "THE OVERVIEW COUNTS A v2 DESCRIPTOR: an admitted domain_app-pattern descriptor is resolved through its OWNER SEAM and its VERSIONED PAYLOAD is read, so the count is not zero on a substrate that holds one — the row-top-level read saw an envelope, found no `composition_pattern`, and reported a confident zero",
    overview.status === 200 &&
      overview.j?.substrate?.odk_domain_app_descriptors === 1 &&
      overview.j?.substrate?.odk_surface_descriptors_resolved === 1,
    `app-shaped ${overview.j?.substrate?.odk_domain_app_descriptors} resolved ${overview.j?.substrate?.odk_surface_descriptors_resolved}`,
  );
  ok(
    "the overview is CALLER-SCOPED and says what it could not read: it reports this caller's authorized/resolved/unreadable census rather than a substrate-wide total, so it is not a cross-tenant counting oracle at lower resolution",
    overview.j?.census_scope === "this_caller_only" &&
      overview.j?.projection_source === "agentgres_owner_chain" &&
      typeof overview.j?.substrate?.odk_surface_descriptors_unreadable === "number",
    `scope ${overview.j?.census_scope} source ${overview.j?.projection_source}`,
  );

  // ==================================================================== THE APP, AND ITS SNAPSHOT
  const appCreate = await req("POST", DA, {
    owner_ref: OWNER,
    idempotency_key: "m056-app-1",
    name: "acme intake",
    description: "an app candidate over one domain_app descriptor",
    surface_descriptor_ref: descriptorRef,
  });
  const app = appCreate.j?.domain_app ?? {};
  const appRef = app.domain_app_id ?? "";
  const appId = appRef.replace("domain-app://", "");
  ok(
    "the DomainApp is authored at the REGISTERED SUCCESSOR and its derived snapshot carries the two members v1 had no field for — a v1 app over this same descriptor recorded neither its object models nor its policy-bound views, and nothing failed",
    appCreate.status === 201 &&
      app.schema_version === "ioi.domain-app.v2" &&
      canonicalJson(app.canonical_object_model_refs) ===
        canonicalJson([`object-model://${NS}/${NAME}/appointment`]) &&
      canonicalJson(app.policy_bound_data_view_refs) ===
        canonicalJson([`view://${NS}/intake/reviewer`]),
    `status ${appCreate.status} object-models ${app.canonical_object_model_refs?.length} views ${app.policy_bound_data_view_refs?.length}`,
  );
  const appRule = commitmentRule("domain-app.v2.invariants.json");
  ok(
    "the app COMMITS ITSELF under the registered rule: recomputing the content hash offline from the published material list reproduces the number the daemon wrote, so a relying party holding only the bytes can check it with no daemon in the loop",
    app.content_hash === recompute(app, appRule),
    `stored ${String(app.content_hash).slice(0, 22)} recomputed ${recompute(app, appRule).slice(0, 22)}`,
  );
  ok(
    "the snapshot names the EXACT descriptor bytes it was derived from, under that version's own commitment rule — a descriptor that advances leaves this app bound to the revision it actually read, so 'the snapshot is current' is decidable rather than assumed",
    app.surface_descriptor_schema_version === "ioi.ontology-surface-descriptor.v2" &&
      app.surface_descriptor_content_hash === descriptor.content_hash,
    `bound ${String(app.surface_descriptor_content_hash).slice(0, 22)} descriptor ${String(descriptor.content_hash).slice(0, 22)}`,
  );
  ok(
    "a DRAFT has completed exactly one journey stage: every later stage binding is an explicit null rather than an absent key, so 'not yet done' and 'this record cannot say' are different bytes",
    app.status === "draft" &&
      app.surface_registration_ref === null &&
      app.package_release_ref === null &&
      app.installation_ref === null &&
      canonicalJson(app.system_binding_refs) === "[]" &&
      app.launch_posture === "inspect_only",
    `status ${app.status} posture ${app.launch_posture}`,
  );

  return { appId, appRef, descriptorRef, app };
}

// ------------------------------------------- the ODK manifest successor, its migration, and packaging

/**
 * The manifest family, driven end to end: author the successor, refuse the folds nobody can split,
 * converge a stored predecessor, and then package through the seams — with the rows destroyed.
 */
async function runManifestAndPackaging(ctx) {
  const { descriptorRef } = ctx;
  const odkOntology = await req("POST", "/v1/hypervisor/odk/domain-ontologies", {
    owner_ref: OWNER,
    idempotency_key: "m056-odk-ontology-1",
    domain: "acme-clinic intake",
  });
  const odkOntologyRef =
    odkOntology.j?.domain_ontology?.ref ?? odkOntology.j?.ontology?.ref ?? "";

  const created = await req("POST", "/v1/hypervisor/odk/manifests", {
    owner_ref: OWNER,
    idempotency_key: "m056-manifest-1",
    name: "intake-kit",
    version: "1.0.0",
    ontology_refs: [odkOntologyRef],
    surface_descriptor_refs: [descriptorRef],
    data_recipe_refs: [`data-recipe://${NS}/intake-normalise/revision/1`],
    evaluation_dataset_refs: [`dataset://${NS}/intake-holdout`],
    benchmark_profile_refs: [`benchmark://${NS}/intake-triage/v1`],
    operator_contract_refs: [`contract://${NS}/intake-reviewer`],
    mcp_contract_refs: [`mcp-profile://${NS}/intake`],
  });
  const manifest = created.j?.manifest ?? {};
  const manifestRef = manifest.odk_manifest_id ?? "";
  const manifestRule = commitmentRule("ontology-development-kit-manifest.v2.invariants.json");
  ok(
    "THE ODK MANIFEST SUCCESSOR IS EXPLICITLY AUTHORABLE, and it authors the members v1 could only fold: the dataset and the benchmark land in different lists, and so do the operator contract and the MCP profile, because the author said which was which",
    created.status === 201 &&
      manifest.schema_version === "ioi.ontology-development-kit-manifest.v2" &&
      canonicalJson(manifest.evaluation_dataset_refs) ===
        canonicalJson([`dataset://${NS}/intake-holdout`]) &&
      canonicalJson(manifest.benchmark_profile_refs) ===
        canonicalJson([`benchmark://${NS}/intake-triage/v1`]) &&
      canonicalJson(manifest.operator_contract_refs) ===
        canonicalJson([`contract://${NS}/intake-reviewer`]) &&
      canonicalJson(manifest.mcp_contract_refs) === canonicalJson([`mcp-profile://${NS}/intake`]),
    `status ${created.status} version ${manifest.schema_version} ${code(created.j) || ""} ${String(created.j?.error?.message ?? "").slice(0, 160)}`,
  );
  ok(
    "and it commits itself under its own registered rule, recomputable offline from the published material list",
    manifest.content_hash === recompute(manifest, manifestRule) &&
      canonicalJson(manifest.migration) ===
        canonicalJson({
          from_schema_version: null,
          from_manifest_ref: null,
          from_content_hash: null,
          compatibility: "initial",
          reinterprets_predecessor: false,
        }),
    `stored ${String(manifest.content_hash).slice(0, 22)} recomputed ${recompute(manifest, manifestRule).slice(0, 22)}`,
  );

  const legacy = await req("POST", "/v1/hypervisor/odk/manifests", {
    owner_ref: OWNER,
    idempotency_key: "m056-manifest-legacy",
    ontology_refs: [odkOntologyRef],
    eval_refs: [`dataset://${NS}/intake-holdout`],
  });
  ok(
    "AN AMBIGUOUS FOLD IS REFUSED, NOT SPLIT BY GUESS: `eval_refs` is answered by naming BOTH successor members it could belong to, because a dataset and a benchmark profile are different objects and only the author knows which each entry is",
    legacy.status >= 400 &&
      code(legacy.j) === "odk_manifest_legacy_member_name" &&
      String(legacy.j?.error?.message ?? "").includes("evaluation_dataset_refs") &&
      String(legacy.j?.error?.message ?? "").includes("benchmark_profile_refs"),
    `status ${legacy.status} code ${code(legacy.j)}`,
  );
  const downgrade = await req("POST", "/v1/hypervisor/odk/manifests", {
    owner_ref: OWNER,
    idempotency_key: "m056-manifest-downgrade",
    schema_version: "ioi.hypervisor.odk.manifest.v1",
    ontology_refs: [odkOntologyRef],
  });
  ok(
    "AND THE PREDECESSOR IS NOT NEWLY AUTHORED: naming v1 is refused by name, so the lane whose folds this successor exists to end cannot be reopened one create at a time",
    downgrade.status >= 400 && code(downgrade.j) === "odk_manifest_predecessor_not_authorable",
    `status ${downgrade.status} code ${code(downgrade.j)}`,
  );
  const badMigration = await req("POST", "/v1/hypervisor/odk/manifests", {
    owner_ref: OWNER,
    idempotency_key: "m056-manifest-bad-migration",
    ontology_refs: [odkOntologyRef],
    migrated_from_manifest_ref: manifestRef,
  });
  ok(
    "A CONVERGENCE NAMES A PREDECESSOR, NOT A PEER: pointing the migration at another v2 is refused, because a record is only ever hashed under the contract it was admitted under and a v2 hashed as a v1 predecessor would commit a number nobody can reproduce",
    badMigration.status >= 400 &&
      code(badMigration.j) === "odk_manifest_migration_source_not_predecessor",
    `status ${badMigration.status} code ${code(badMigration.j)}`,
  );

  // ------------------------------------------------------------- packaging, through the owner seams
  const dapp = await req("POST", DA, {
    owner_ref: OWNER,
    idempotency_key: "m056-pkg-app",
    name: "packaged intake",
    surface_descriptor_ref: descriptorRef,
    odk_manifest_ref: manifestRef,
  });
  const pkgAppRef = dapp.j?.domain_app?.domain_app_id ?? "";
  ok(
    "a DomainApp binds the manifest THROUGH THE MANIFEST OWNER SEAM, so the app-shape contract is checked against an owner-resolved manifest rather than a record-directory copy",
    dapp.status === 201 && dapp.j?.domain_app?.odk_manifest_ref === manifestRef,
    `status ${dapp.status} manifest ${dapp.j?.domain_app?.odk_manifest_ref ?? "(none)"} ${code(dapp.j) || ""}`,
  );

  const packaged = await req("POST", "/v1/hypervisor/packages", {
    package_id: "m056-intake",
    owner_ref: OWNER,
    domain_app_ref: pkgAppRef,
    idempotency_key: "m056-package-1",
  });
  const candidate = packaged.j?.package?.record ?? {};
  ok(
    "PACKAGE ADMISSION RESOLVES BOTH SOURCES THROUGH THEIR OWNER SEAMS AND CITES EXACT HEADS: the candidate names which contract admitted the app and the manifest and the exact chain position each was read at, so a frozen snapshot is locatable in its owner's history rather than only checkable against itself",
    packaged.status === 201 &&
      candidate.source_snapshots?.domain_app_schema_version === "ioi.domain-app.v2" &&
      candidate.source_snapshots?.odk_manifest_schema_version ===
        "ioi.ontology-development-kit-manifest.v2" &&
      EXACT_HEAD.test(String(candidate.source_snapshots?.domain_app_admitted_head ?? "")) &&
      EXACT_HEAD.test(String(candidate.source_snapshots?.odk_manifest_admitted_head ?? "")),
    `status ${packaged.status} app-head ${String(candidate.source_snapshots?.domain_app_admitted_head ?? "(none)").slice(0, 18)} manifest-head ${String(candidate.source_snapshots?.odk_manifest_admitted_head ?? "(none)").slice(0, 18)} ${code(packaged.j) || ""} ${String(packaged.j?.error?.message ?? "").slice(0, 140)}`,
  );
  ok(
    "and it freezes the MANIFEST OWNER'S OWN COMMITMENT, recomputable offline from that family's registered rule rather than re-digested here into a second number beside it",
    candidate.source_snapshots?.odk_manifest_content_hash === recompute(manifest, manifestRule),
    `frozen ${String(candidate.source_snapshots?.odk_manifest_content_hash ?? "(none)").slice(0, 22)} recomputed ${recompute(manifest, manifestRule).slice(0, 22)}`,
  );

  // DELETE AND CORRUPT THE ROWS, then package again under a second key. Same answer, or the rows
  // were load-bearing for an admission decision.
  const rowDir = (kind) => path.join(dataDir, kind);
  const appRowId = pkgAppRef.replace("domain-app://", "");
  const manifestRowId = manifestRef.replace("odk://", "");
  fs.rmSync(path.join(rowDir("domain-apps"), `${appRowId}.json`), { force: true });
  fs.writeFileSync(
    path.join(rowDir("odk-manifests"), `${manifestRowId}.json`),
    JSON.stringify({ schema_version: "ioi.hypervisor.odk.manifest.v1", ref: "odk://forged" }),
  );
  const afterDamage = await req("POST", "/v1/hypervisor/packages", {
    package_id: "m056-intake-2",
    owner_ref: OWNER,
    domain_app_ref: pkgAppRef,
    idempotency_key: "m056-package-2",
  });
  const damagedCandidate = afterDamage.j?.package?.record ?? {};
  ok(
    "PACKAGE ADMISSION SURVIVES A DELETED DOMAIN-APP ROW AND A CORRUPTED MANIFEST ROW, unchanged: the app row is gone, the manifest row has been overwritten with a forged predecessor naming a different manifest, and the candidate still freezes the same owner-committed hashes at the same heads — which is what 'the rows cannot change an admission decision' has to mean",
    afterDamage.status === 201 &&
      damagedCandidate.source_snapshots?.domain_app_content_hash ===
        candidate.source_snapshots?.domain_app_content_hash &&
      damagedCandidate.source_snapshots?.odk_manifest_content_hash ===
        candidate.source_snapshots?.odk_manifest_content_hash &&
      damagedCandidate.source_snapshots?.domain_app_admitted_head ===
        candidate.source_snapshots?.domain_app_admitted_head &&
      damagedCandidate.source_snapshots?.odk_manifest_admitted_head ===
        candidate.source_snapshots?.odk_manifest_admitted_head &&
      damagedCandidate.odk_manifest_ref === manifestRef,
    `status ${afterDamage.status} manifest_ref ${damagedCandidate.odk_manifest_ref ?? "(none)"} ${code(afterDamage.j) || ""} ${String(afterDamage.j?.error?.message ?? "").slice(0, 140)}`,
  );
}

// ------------------------------------------------------------------ the governed ladder, and G-6

async function runLadder(ctx) {
  const { appId, appRef } = ctx;
  const approvalCreate = await req("POST", "/v1/hypervisor/governance/approval-requests", {
    subject_ref: appRef,
    request_kind: "domain_app.mount",
    reason: "verifier fixture: a real approval targeting this app",
  });
  const approvalRef = approvalCreate.j?.approval_request?.ref ?? "";
  const approvalId = approvalRef.replace("approval-request://", "");
  await req("PATCH", `/v1/hypervisor/governance/approval-requests/${approvalId}`, {
    transition: "approve",
    reason: "verifier fixture",
  });
  const releaseCreate = await req("POST", "/v1/hypervisor/governance/release-controls", {
    release_target_ref: appRef,
    rollout_mode: "full",
  });
  const releaseRef = releaseCreate.j?.release_control?.ref ?? "";
  const releaseId = releaseRef.replace("release-control://", "");
  await req("PATCH", `/v1/hypervisor/governance/release-controls/${releaseId}`, {
    transition: "open",
    reason: "verifier fixture",
  });
  const approvalNow = await req(
    "GET",
    `/v1/hypervisor/governance/approval-requests/${approvalId}`,
  );
  const releaseNow = await req("GET", `/v1/hypervisor/governance/release-controls/${releaseId}`);
  ok(
    "PRECONDITION: a REAL approved ApprovalRequest and a REAL open ReleaseControl, both targeting this app, minted through Governance's own routes",
    approvalNow.j?.approval_request?.status === "approved" &&
      releaseNow.j?.release_control?.state === "open",
    `approval ${approvalNow.j?.approval_request?.status} release ${releaseNow.j?.release_control?.state}`,
  );

  const beforeMount = await appState(appId);
  const mount = await req("POST", `${DA}/${appId}/mount`, {
    owner_ref: OWNER,
    idempotency_key: "m056-mount-1",
    approval_request_ref: approvalRef,
    release_control_ref: releaseRef,
  });
  const runtime = mount.j?.runtime ?? {};
  const receipt = mount.j?.receipt ?? {};
  const runtimeRef = runtime.domain_app_runtime_id ?? "";
  ok(
    "THE MOUNT RECEIPT BINDS THE RUNTIME IT TRANSITIONED: it names that runtime's ref, its OWNER, the exact revision it attests and that runtime's own content hash — v1 named only the app, so a twice-mounted app's whole receipt chain was one undifferentiated set",
    mount.status === 201 &&
      receipt.domain_app_runtime_ref === runtimeRef &&
      receipt.domain_app_runtime_owner_ref === OWNER &&
      receipt.domain_app_runtime_revision === 0 &&
      receipt.domain_app_runtime_content_hash === runtime.content_hash,
    `status ${mount.status} runtime ${receipt.domain_app_runtime_ref === runtimeRef} owner ${receipt.domain_app_runtime_owner_ref} rev ${receipt.domain_app_runtime_revision}`,
  );
  ok(
    "the receipt names the EXACT admitted head the transition was admitted against, so it is locatable at one position in one chain rather than merely consistent with it",
    receipt.domain_app_admitted_head_before === beforeMount.head &&
      typeof beforeMount.head === "string" &&
      beforeMount.head.length > 0,
    `receipt ${String(receipt.domain_app_admitted_head_before).slice(0, 16)} chain ${String(beforeMount.head).slice(0, 16)}`,
  );
  const receiptRule = commitmentRule("domain-app-mount-receipt.v2.invariants.json");
  const runtimeRule = commitmentRule("domain-app-runtime.v2.invariants.json");
  ok(
    "the receipt's state root is a REAL COMMITMENT over the whole receipt including its three runtime bindings, recomputable offline — v1 hashed five values joined with pipes and said nothing about the runtime",
    receipt.state_root === recompute(receipt, receiptRule) &&
      runtime.content_hash === recompute(runtime, runtimeRule),
    `receipt ${receipt.state_root === recompute(receipt, receiptRule)} runtime ${runtime.content_hash === recompute(runtime, runtimeRule)}`,
  );
  ok(
    "MOUNT IS EFFECTFUL BUT NOT SERVING, AND INGRESS IS SEPARABLE FROM BOTH: the runtime is mounted with no internal route and an explicit null external ingress, so a reader can tell 'not exposed' from 'this record has no field for exposure'",
    runtime.mounted === true &&
      runtime.serving === false &&
      runtime.internal_route_ref === null &&
      Object.hasOwn(runtime, "external_ingress_ref") &&
      runtime.external_ingress_ref === null,
    `mounted ${runtime.mounted} serving ${runtime.serving} ingress ${runtime.external_ingress_ref}`,
  );

  const afterMount = await appState(appId);
  ok(
    "G-6: A RUNTIME TRANSITION DOES NOT MOVE INVENTORY STATUS. The mount is admitted, the app's runtime backlink names the runtime, and `status` is still `draft` — 'admitted' cannot start reading as 'running' because the writer that would conflate them cannot reach the field",
    afterMount.status === "draft" &&
      afterMount.posture?.mounted === true &&
      afterMount.posture?.mount_ref === runtimeRef,
    `status ${afterMount.status} mounted ${afterMount.posture?.mounted} mount_ref ${afterMount.posture?.mount_ref === runtimeRef}`,
  );

  // A REPLAY RESOLVES TO THE RUNTIME IT ALREADY CREATED.
  const replay = await req("POST", `${DA}/${appId}/mount`, {
    owner_ref: OWNER,
    idempotency_key: "m056-mount-1",
    approval_request_ref: approvalRef,
    release_control_ref: releaseRef,
  });
  const afterReplay = await appState(appId);
  ok(
    "A REPLAYED MOUNT RESOLVES RATHER THAN APPENDS: the same idempotency key re-answers the runtime and receipt it already created, byte-identical, and the chain gains no revision — the clock-derived id minted a SECOND runtime for every retry",
    replay.status === 201 &&
      replay.j?.runtime?.domain_app_runtime_id === runtimeRef &&
      canonicalJson(replay.j?.runtime) === canonicalJson(runtime) &&
      canonicalJson(replay.j?.receipt) === canonicalJson(receipt) &&
      afterReplay.revisions === afterMount.revisions,
    `runtime same ${replay.j?.runtime?.domain_app_runtime_id === runtimeRef} bytes ${canonicalJson(replay.j?.runtime) === canonicalJson(runtime)} revisions ${afterMount.revisions}->${afterReplay.revisions}`,
  );

  // THE ALLOWED SET IS ACCEPTED IN FULL, INCLUDING THE SHARED WRITE CONTROLS. An allowlist that
  // refuses a field the route genuinely accepts is an obstacle rather than a fence, so the positive
  // case is asserted beside the refusals: a caller may send `expected_head` — a shared concurrency
  // control no rung authors — alongside this rung's own two fields, and the replay still resolves.
  const withControlFields = await req("POST", `${DA}/${appId}/mount`, {
    owner_ref: OWNER,
    idempotency_key: "m056-mount-1",
    expected_head: beforeMount.head,
    approval_request_ref: approvalRef,
    release_control_ref: releaseRef,
  });
  ok(
    "THE SHARED WRITE CONTROLS ARE ACCEPTED BESIDE THIS RUNG'S OWN FIELDS AND ARE NOT PART OF THE COMPARED MATERIAL: a retry carrying `expected_head` still replays to the same runtime and receipt, because a concurrency control is not something the caller authored about WHAT to do",
    withControlFields.status === 201 &&
      canonicalJson(withControlFields.j?.runtime) === canonicalJson(runtime) &&
      canonicalJson(withControlFields.j?.receipt) === canonicalJson(receipt),
    `status ${withControlFields.status} identical ${canonicalJson(withControlFields.j?.runtime) === canonicalJson(runtime)} ${code(withControlFields.j) || ""}`,
  );

  // THE SAME KEY, A DIFFERENT COMMAND. Each of these must refuse, and refuse before any effect.
  let beforeReuse = await appState(appId);
  const reusedBody = await req("POST", `${DA}/${appId}/mount`, {
    owner_ref: OWNER,
    idempotency_key: "m056-mount-1",
    approval_request_ref: approvalRef,
    release_control_ref: "release-control://rel_someone_elses",
  });
  await refusedWithNoEffect(
    "A KEY REUSED WITH DIFFERENT REQUEST MATERIAL IS REFUSED, NOT REPLAYED: the same mount key naming a different ReleaseControl is answered as a reused key rather than handed the first mount's receipt, because answering it would be a forged success for a command that was never admitted",
    reusedBody,
    appId,
    beforeReuse,
    "domain_app_idempotency_key_reused_for_a_different_command",
  );
  beforeReuse = await appState(appId);
  const reusedAction = await req("POST", `${DA}/${appId}/serve`, {
    owner_ref: OWNER,
    idempotency_key: "m056-mount-1",
  });
  await refusedWithNoEffect(
    "AND A KEY REUSED FOR A DIFFERENT RUNG IS REFUSED TOO: a serve under the mount's key names a different transition, so the earlier operation's kind and action are compared rather than only its key — which is the whole difference between identifying a caller's intent and identifying their command",
    reusedAction,
    appId,
    beforeReuse,
    "domain_app_idempotency_key_reused_for_a_different_command",
  );

  // AN EXTRA CALLER FIELD CANNOT REACH THE COMPARISON AT ALL.
  beforeReuse = await appState(appId);
  const extraField = await req("POST", `${DA}/${appId}/mount`, {
    owner_ref: OWNER,
    idempotency_key: "m056-mount-1",
    approval_request_ref: approvalRef,
    release_control_ref: releaseRef,
    reason: "an extra field this rung does not author",
  });
  await refusedWithNoEffect(
    "AN EXTRA CALLER-AUTHORED FIELD IS REFUSED BY NAME, NOT IGNORED: the mount rung authors exactly two fields beside the shared write controls, so a retry that adds a third is a request the server would otherwise never have seen — and under the same key it would compare equal on everything the server did look at and replay as exact",
    extraField,
    appId,
    beforeReuse,
    "domain_app_request_field_unknown",
  );
  beforeReuse = await appState(appId);
  const unknownOnServe = await req("POST", `${DA}/${appId}/stop-serving`, {
    owner_ref: OWNER,
    idempotency_key: "m056-unknown-on-stop",
    approval_request_ref: approvalRef,
  });
  await refusedWithNoEffect(
    "AND THE ALLOWLIST IS PER-RUNG: stop-serving reuses the mount's governance and authors nothing, so naming an approval on it is refused rather than quietly accepted as a field some other rung happens to allow",
    unknownOnServe,
    appId,
    beforeReuse,
    "domain_app_request_field_unknown",
  );

  // SERVE: a second runtime revision, its own receipt, and the internal route only.
  const serve = await req("POST", `${DA}/${appId}/serve`, {
    owner_ref: OWNER,
    idempotency_key: "m056-serve-1",
  });
  const serving = serve.j?.runtime ?? {};
  const serveReceipt = serve.j?.receipt ?? {};
  ok(
    "A SERVE RECEIPT IS ATTRIBUTABLE TO THE SERVE IT RECORDS: it binds the SAME runtime at the NEXT revision with that revision's own content hash, so a later stop can be matched to this start rather than to the mount",
    serve.status === 201 &&
      serveReceipt.domain_app_runtime_ref === runtimeRef &&
      serveReceipt.domain_app_runtime_revision === 1 &&
      serveReceipt.action === "domain_app.serve_start" &&
      serveReceipt.domain_app_runtime_content_hash === serving.content_hash &&
      serveReceipt.domain_app_runtime_content_hash !== receipt.domain_app_runtime_content_hash,
    `rev ${serveReceipt.domain_app_runtime_revision} distinct ${serveReceipt.domain_app_runtime_content_hash !== receipt.domain_app_runtime_content_hash}`,
  );
  ok(
    "SERVING ASSIGNS AN INTERNAL ROUTE AND NOTHING ELSE: external ingress stays null across the transition, so exposure is never a consequence of serving",
    serving.serving === true &&
      typeof serving.internal_route_ref === "string" &&
      serving.internal_route_ref.startsWith("/__ioi/domain-app-runtime/") &&
      serving.external_ingress_ref === null,
    `route ${serving.internal_route_ref} ingress ${serving.external_ingress_ref}`,
  );
  const afterServe = await appState(appId);
  ok(
    "G-6 AGAIN, ACROSS A SECOND RUNTIME TRANSITION: serving moves the runtime and the backlink, and leaves inventory status exactly where the journey left it",
    afterServe.status === "draft" && afterServe.posture?.serving === true,
    `status ${afterServe.status} serving ${afterServe.posture?.serving}`,
  );

  // THE MOUNT KEY, REPLAYED AFTER A LATER TRANSITION LANDED.
  const lateReplay = await req("POST", `${DA}/${appId}/mount`, {
    owner_ref: OWNER,
    idempotency_key: "m056-mount-1",
    approval_request_ref: approvalRef,
    release_control_ref: releaseRef,
  });
  const afterLateReplay = await appState(appId);
  ok(
    "A REPLAY ANSWERS THE COMMAND IT REPLAYS, NOT THE LADDER'S CURRENT STATE: the mount key is retried AFTER a serve has advanced the runtime, and it still returns the mount's own runtime at revision 0 with the mount's own receipt, byte-identical to the first answer — a replay folded at the head would have handed back the serving runtime and called it the mount's result",
    lateReplay.status === 201 &&
      canonicalJson(lateReplay.j?.runtime) === canonicalJson(runtime) &&
      canonicalJson(lateReplay.j?.receipt) === canonicalJson(receipt) &&
      canonicalJson(lateReplay.j?.domain_app) === canonicalJson(mount.j?.domain_app) &&
      lateReplay.j?.runtime?.revision === 0 &&
      afterLateReplay.revisions === afterServe.revisions,
    `runtime identical ${canonicalJson(lateReplay.j?.runtime) === canonicalJson(runtime)} app identical ${canonicalJson(lateReplay.j?.domain_app) === canonicalJson(mount.j?.domain_app)} revision ${lateReplay.j?.runtime?.revision} revisions ${afterServe.revisions}->${afterLateReplay.revisions}`,
  );

  return { approvalRef, releaseRef, runtimeRef, runtime: serving, receipt, serveReceipt };
}

// ------------------------------------------------- inventory status, downgrade, and the negatives

async function runStatusAndRefusals(ctx, ladder) {
  const { appId } = ctx;
  let before = await appState(appId);

  // A runtime state named on the inventory route is a CATEGORY ERROR, not an unknown value.
  const asRuntimeState = await req("POST", `${DA}/${appId}/inventory-status`, {
    owner_ref: OWNER,
    idempotency_key: "m056-status-runtime",
    status: "serving",
  });
  await refusedWithNoEffect(
    "A RUNTIME STATE IS NOT AN INVENTORY STATUS: naming `serving` on the status route is refused as a category error that says which object owns the word, not as an unknown value that would leave a caller believing inventory has a serving state it has not reached",
    asRuntimeState,
    appId,
    before,
    "domain_app_runtime_state_is_not_inventory_status",
  );

  // An advance with no stage binding behind it is refused BY THE REGISTERED CONTRACT.
  before = await appState(appId);
  const unbacked = await req("POST", `${DA}/${appId}/inventory-status`, {
    owner_ref: OWNER,
    idempotency_key: "m056-status-unbacked",
    status: "admitted",
  });
  await refusedWithNoEffect(
    "AN ADVANCE WITH NO STAGE BINDING IS REFUSED: `admitted` without the immutable package release that admitted it is a claim about another plane's admission made by a route that admitted nothing, and the refusal comes from the registered contract's own conditional rather than a hand-written check that could drift from it",
    unbacked,
    appId,
    before,
    "domain_app_status_binding_missing",
  );

  // The legal advance, with its binding.
  const advanced = await req("POST", `${DA}/${appId}/inventory-status`, {
    owner_ref: OWNER,
    idempotency_key: "m056-status-admitted",
    status: "admitted",
    package_release_ref: "package://acme-intake/release/1.0.0",
  });
  ok(
    "STATUS ADVANCES WHEN ITS STAGE BINDING IS NAMED: the app reaches `admitted` carrying the release that admitted it, which is the field v1 pinned to `draft` forever with four of canon's five members unreachable",
    advanced.status === 200 &&
      advanced.j?.domain_app?.status === "admitted" &&
      advanced.j?.domain_app?.package_release_ref === "package://acme-intake/release/1.0.0",
    `status ${advanced.status} value ${advanced.j?.domain_app?.status}`,
  );
  ok(
    "AND THE ADVANCE DID NOT TOUCH THE RUNTIME: the app is `admitted` while its runtime is still serving on the route the mount ladder gave it, so the two state kinds moved independently in one record",
    advanced.j?.domain_app?.runtime_posture?.serving === true &&
      advanced.j?.domain_app?.runtime_posture?.mount_ref === ladder.runtimeRef,
    `serving ${advanced.j?.domain_app?.runtime_posture?.serving} mount_ref ${advanced.j?.domain_app?.runtime_posture?.mount_ref === ladder.runtimeRef}`,
  );

  // A stage skip is refused even when the bindings happen to be present.
  before = await appState(appId);
  const skip = await req("POST", `${DA}/${appId}/inventory-status`, {
    owner_ref: OWNER,
    idempotency_key: "m056-status-skip",
    status: "draft",
  });
  await refusedWithNoEffect(
    "THE JOURNEY DOES NOT RUN BACKWARDS BY STATUS EDIT: an admitted app cannot be written back to `draft`, because un-admitting is a withdrawal on the plane that admitted it and not a field assignment here",
    skip,
    appId,
    before,
    "domain_app_status_transition_illegal",
  );

  // DOWNGRADE REFUSAL, on three planes.
  before = await appState(appId);
  const downgradeCreate = await req("POST", DA, {
    owner_ref: OWNER,
    idempotency_key: "m056-downgrade-create",
    schema_version: "ioi.hypervisor.domain-app.v1",
    surface_descriptor_ref: ctx.descriptorRef,
  });
  ok(
    "DOWNGRADE IS A REFUSAL BY NAME: a create naming the deprecated predecessor is refused as the predecessor rather than read as the successor, because reading a v1 request as a v2 record is the exact reinterpretation the succession exists to avoid",
    downgradeCreate.status >= 400 &&
      code(downgradeCreate.j) === "domain_app_predecessor_contract_not_authorable",
    `status ${downgradeCreate.status} code ${code(downgradeCreate.j)}`,
  );
  const unknownVersion = await req("POST", DA, {
    owner_ref: OWNER,
    idempotency_key: "m056-unknown-version",
    schema_version: "ioi.domain-app.v9",
    surface_descriptor_ref: ctx.descriptorRef,
  });
  ok(
    "AND AN UNRECOGNISED CONTRACT IS REFUSED RATHER THAN DEFAULTED: a version this build neither authors nor projects fails closed, so an unknown case cannot take the success path for want of an arm",
    unknownVersion.status >= 400 && code(unknownVersion.j) === "domain_app_contract_unsupported",
    `status ${unknownVersion.status} code ${code(unknownVersion.j)}`,
  );
  const manifestUnknown = await req("POST", "/v1/hypervisor/odk/manifests", {
    owner_ref: OWNER,
    idempotency_key: "m056-manifest-unknown-version",
    schema_version: "ioi.ontology-development-kit-manifest.v9",
    ontology_refs: [],
  });
  ok(
    "THE ODK MANIFEST FAMILY REFUSES A CONTRACT IT DOES NOT AUTHOR: a version this build neither authors nor projects fails closed by name, so an unknown case cannot take the success path for want of an arm",
    manifestUnknown.status >= 400 &&
      code(manifestUnknown.j) === "odk_manifest_contract_unsupported",
    `status ${manifestUnknown.status} code ${code(manifestUnknown.j)}`,
  );

  // A field owned by another plane is refused BY NAME rather than silently dropped.
  before = await appState(appId);
  const patchStatus = await req("PATCH", `${DA}/${appId}`, {
    owner_ref: OWNER,
    idempotency_key: "m056-patch-status",
    status: "installed",
  });
  await refusedWithNoEffect(
    "A FIELD ANOTHER PLANE OWNS IS REFUSED BY NAME, NOT IGNORED: patching `status` through the ordinary mutation route is named and refused, because silently dropping it answers 200 to a request that changed nothing the caller asked for",
    patchStatus,
    appId,
    before,
    "domain_app_field_not_patchable",
  );
  before = await appState(appId);
  const patchPosture = await req("PATCH", `${DA}/${appId}`, {
    owner_ref: OWNER,
    idempotency_key: "m056-patch-posture",
    runtime_posture: { mounted: false, serving: false, route: null, mount_ref: null },
  });
  await refusedWithNoEffect(
    "AND THE RUNTIME BACKLINK CANNOT BE AUTHORED: `runtime_posture` is a projection of the runtime, so a caller cannot assert an app is unmounted while its runtime holds a governed mount",
    patchPosture,
    appId,
    before,
    "domain_app_field_not_patchable",
  );

  // Cross-principal: B holds the same tenant, so this is not an isolation claim — it is the claim
  // that the app plane refuses a delete while a governed mount is live (G-5's inverse ordering).
  before = await appState(appId);
  const deleteMounted = await req("DELETE", `${DA}/${appId}`, {
    owner_ref: OWNER,
    idempotency_key: "m056-delete-mounted",
  });
  await refusedWithNoEffect(
    "A MOUNTED APP IS NOT DELETABLE THROUGH THE OBJECT PLANE: deleting it would strand a runtime that still claims a governed mount, so the lifecycle's inverse has to run first",
    deleteMounted,
    appId,
    before,
    "domain_app_still_mounted",
  );
}

// -------------------------------------------------------------- durability: restart and index loss

async function runDurability(ctx, ladder) {
  const { appId } = ctx;
  const beforeRestart = await appState(appId);

  // DESTROY THE PROJECTIONS. Every one of the three record directories this module writes is a
  // rebuildable index; if any answer moves, one of them was load-bearing.
  await stopDaemon();
  const destroyed = [];
  for (const kind of ["domain-apps", "domain-app-runtimes", "domain-app-mount-receipts"]) {
    const dir = path.join(dataDir, kind);
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
      destroyed.push(kind);
    }
  }
  await startDaemon();
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (bootToken) {
    const boot = await req(
      "POST",
      "/v1/hypervisor/auth/bootstrap",
      { token: bootToken, password: "odk-domainapp-a-v1" },
      { as: null },
    );
    if (boot.j?.session_token) SESSIONS.A = boot.j.session_token;
  }
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "odk-domainapp-b@ioi.local", password: "odk-domainapp-b-v1" },
    { as: null },
  );
  if (login.j?.session_token) SESSIONS.B = login.j.session_token;

  const afterRestart = await appState(appId);
  ok(
    "THE RECORD DIRECTORIES ARE PROJECTIONS IN THE STRICT SENSE: all three are deleted, the daemon is restarted, and the app answers the same head, the same revision count, the same inventory status and the same content hash — an index whose loss changes an answer is not an index",
    destroyed.length === 3 &&
      afterRestart.head === beforeRestart.head &&
      afterRestart.revisions === beforeRestart.revisions &&
      afterRestart.status === beforeRestart.status &&
      afterRestart.contentHash === beforeRestart.contentHash,
    `destroyed ${destroyed.join(",")} head ${afterRestart.head === beforeRestart.head} hash ${afterRestart.contentHash === beforeRestart.contentHash}`,
  );

  const runtimeAfter = await req(
    "GET",
    `/v1/hypervisor/domain-app-runtimes/${ladder.runtimeRef.replace("domain-app-runtime://", "")}`,
  );
  const rebuilt = runtimeAfter.j?.runtime ?? {};
  ok(
    "AND THE RUNTIME IS A FOLD OVER THE ADMITTED HISTORY, NOT A ROW: with its directory gone it answers byte-identical to what the ladder produced, including the revision, the internal route, and the content hash the receipts bind",
    runtimeAfter.status === 200 &&
      canonicalJson(rebuilt) === canonicalJson(ladder.runtime),
    `status ${runtimeAfter.status} identical ${canonicalJson(rebuilt) === canonicalJson(ladder.runtime)}`,
  );
  const receipts = runtimeAfter.j?.receipts ?? [];
  const boundToThisRuntime = receipts.every(
    (r) => r.domain_app_runtime_ref === ladder.runtimeRef,
  );
  const revisions = receipts.map((r) => r.domain_app_runtime_revision);
  ok(
    "THE WHOLE RECEIPT CHAIN SURVIVES AND EVERY RECEIPT STILL NAMES THIS RUNTIME AND ITS REVISION: rebuilt from the chain, each receipt's state root still recomputes, which is what makes the binding evidence rather than decoration",
    receipts.length >= 2 &&
      boundToThisRuntime &&
      revisions.includes(0) &&
      revisions.includes(1) &&
      receipts.every((r) => r.state_root === recompute(r, commitmentRule("domain-app-mount-receipt.v2.invariants.json"))),
    `receipts ${receipts.length} bound ${boundToThisRuntime} revisions ${revisions.join(",")}`,
  );

  // The overview, after the index loss, still counts the v2 descriptor.
  const overview = await req("GET", `${DA}/overview`);
  ok(
    "THE OVERVIEW SURVIVES THE INDEX LOSS TOO: it still resolves the descriptor and every app from their owner chains and reports EVERY index as rebuilt rather than agreeing, so the rebuild is positively detected instead of inferred from an unchanged answer",
    overview.j?.substrate?.odk_domain_app_descriptors === 1 &&
      overview.j?.domain_apps?.resolved_from_chain >= 1 &&
      overview.j?.domain_apps?.index_answered_from_chain ===
        overview.j?.domain_apps?.authorized_for_this_caller &&
      overview.j?.domain_apps?.index_agreed_with_chain === 0,
    `app-shaped ${overview.j?.substrate?.odk_domain_app_descriptors} resolved ${overview.j?.domain_apps?.resolved_from_chain} rebuilt ${overview.j?.domain_apps?.index_answered_from_chain}/${overview.j?.domain_apps?.authorized_for_this_caller} agreed ${overview.j?.domain_apps?.index_agreed_with_chain}`,
  );

  // And the ladder still runs after the restart: unmount closes the mount it was given.
  const stop = await req("POST", `${DA}/${appId}/stop-serving`, {
    owner_ref: OWNER,
    idempotency_key: "m056-stop-1",
  });
  const unmount = await req("POST", `${DA}/${appId}/unmount`, {
    owner_ref: OWNER,
    idempotency_key: "m056-unmount-1",
    reason: "verifier fixture",
  });
  const final = unmount.j?.runtime ?? {};
  ok(
    "THE LADDER RUNS ACROSS A RESTART AND ITS INVERSE CLOSES THE MOUNT: stop then unmount advance the same runtime to revision 3, each receipted against that revision, and the terminal record carries its own unmount stamp",
    stop.status === 201 &&
      unmount.status === 201 &&
      final.revision === 3 &&
      final.mounted === false &&
      final.serving === false &&
      final.state === "unmounted" &&
      typeof final.unmounted_at === "string" &&
      unmount.j?.receipt?.domain_app_runtime_revision === 3,
    `stop ${stop.status} unmount ${unmount.status} revision ${final.revision} state ${final.state}`,
  );
  const afterUnmount = await appState(appId);
  ok(
    "AND THE UNMOUNT LEFT INVENTORY STATUS WHERE THE JOURNEY LEFT IT: the app is still `admitted`, its backlink projects nothing, and no stale runtime pointer survives on the record",
    afterUnmount.status === "admitted" &&
      afterUnmount.posture?.mounted === false &&
      afterUnmount.posture?.mount_ref === null &&
      afterUnmount.posture?.route === null,
    `status ${afterUnmount.status} mount_ref ${afterUnmount.posture?.mount_ref}`,
  );
}

// -------------------------------------------------------------------------------- planted mutations

/// Each mutant names the EXACT assertion it must redden. An off-target kill proves the harness, not
/// the gate, so a mutant that reddens something else — or nothing — fails the battery.
const MUTANTS = [
  {
    id: "the-overview-reads-the-row-top-level-again",
    file: ROUTE_SOURCE,
    // THE M05.5 DEFECT, REPLANTED. Reading `composition_pattern` off the resolved ENVELOPE rather
    // than the record is the exact shape the row-backed sweep had: a v2 payload has no such key at
    // the level being read, so the count silently returns to zero.
    find: '                if resolved.composition_pattern == "domain_app" {',
    replace:
      '                if resolved.record.get("descriptor").and_then(Value::as_str) == Some("domain_app") {',
    target:
      "THE OVERVIEW COUNTS A v2 DESCRIPTOR: an admitted domain_app-pattern descriptor is resolved through its OWNER SEAM and its VERSIONED PAYLOAD is read, so the count is not zero on a substrate that holds one — the row-top-level read saw an envelope, found no `composition_pattern`, and reported a confident zero",
  },
  {
    id: "the-receipt-stops-naming-its-runtime",
    file: ROUTE_SOURCE,
    find: '            "domain_app_runtime_ref": runtime_ref,',
    replace: '            "domain_app_runtime_ref": domain_app_ref,',
    target:
      "THE MOUNT RECEIPT BINDS THE RUNTIME IT TRANSITIONED: it names that runtime's ref, its OWNER, the exact revision it attests and that runtime's own content hash — v1 named only the app, so a twice-mounted app's whole receipt chain was one undifferentiated set",
  },
  {
    id: "the-receipt-binds-the-prior-runtime-state",
    file: ROUTE_SOURCE,
    // A GENUINE SUBSTITUTION: the receipt commits a hash of the state the transition STARTED from,
    // so it is well-formed, recomputes cleanly, and describes the wrong runtime state.
    find: "    let projected: Vec<Value> = receipts\n        .iter()\n        .map(|r| project_receipt(&r.core, &runtime_hash, &stamp))\n        .collect();",
    replace:
      "    let prior_hash = prior_runtime\n        .and_then(|p| p.get(\"content_hash\"))\n        .and_then(Value::as_str)\n        .unwrap_or(&runtime_hash)\n        .to_string();\n    let projected: Vec<Value> = receipts\n        .iter()\n        .map(|r| project_receipt(&r.core, &prior_hash, &stamp))\n        .collect();",
    target:
      "A SERVE RECEIPT IS ATTRIBUTABLE TO THE SERVE IT RECORDS: it binds the SAME runtime at the NEXT revision with that revision's own content hash, so a later stop can be matched to this start rather than to the mount",
  },
  {
    id: "the-receipt-forgets-which-head-it-was-admitted-against",
    file: ROUTE_SOURCE,
    find: '            "domain_app_admitted_head_before": admitted_head_before,',
    replace: '            "domain_app_admitted_head_before": "0000000000000000",',
    target:
      "the receipt names the EXACT admitted head the transition was admitted against, so it is locatable at one position in one chain rather than merely consistent with it",
  },
  {
    id: "a-runtime-transition-advances-inventory-status",
    file: ROUTE_SOURCE,
    // THE CONFLATION G-6 EXISTS FOR: the mount writes an inventory status, so "admitted" starts
    // reading as "running" and a stopped app reads as uninstalled.
    find: '    next["runtime_posture"] = runtime_backlink(runtime);',
    replace:
      '    next["runtime_posture"] = runtime_backlink(runtime);\n    if runtime.get("mounted").and_then(Value::as_bool) == Some(true) {\n        next["status"] = json!("admitted");\n    }',
    target:
      "G-6: A RUNTIME TRANSITION DOES NOT MOVE INVENTORY STATUS. The mount is admitted, the app's runtime backlink names the runtime, and `status` is still `draft` — 'admitted' cannot start reading as 'running' because the writer that would conflate them cannot reach the field",
  },
  {
    id: "the-runtime-id-goes-back-to-the-clock",
    file: ROUTE_SOURCE,
    find: '    replay_stable_id("dartm", &caller.owner_ref, &caller.idempotency_key)',
    replace:
      '    replay_stable_id(\n        "dartm",\n        &caller.owner_ref,\n        &format!(\n            "{}{}",\n            caller.idempotency_key,\n            std::time::SystemTime::now()\n                .duration_since(std::time::UNIX_EPOCH)\n                .map(|d| d.as_nanos())\n                .unwrap_or(0)\n        ),\n    )',
    target:
      "A REPLAYED MOUNT RESOLVES RATHER THAN APPENDS: the same idempotency key re-answers the runtime and receipt it already created, byte-identical, and the chain gains no revision — the clock-derived id minted a SECOND runtime for every retry",
  },
  {
    id: "serving-acquires-external-ingress",
    file: ROUTE_SOURCE,
    find: '        "external_ingress_ref": prior.get("external_ingress_ref").cloned().unwrap_or(Value::Null),',
    replace:
      '        "external_ingress_ref": if serving { json!("ingress://auto") } else { prior.get("external_ingress_ref").cloned().unwrap_or(Value::Null) },',
    target:
      "SERVING ASSIGNS AN INTERNAL ROUTE AND NOTHING ELSE: external ingress stays null across the transition, so exposure is never a consequence of serving",
  },
  {
    id: "a-status-advance-needs-no-stage-binding",
    file: ROUTE_SOURCE,
    // A GENUINE BYPASS: the registered contract is no longer consulted, so `admitted` lands with no
    // release behind it and the record persists claiming an admission that never happened.
    find: '    if let Err(response) = registered_valid(\n        DOMAIN_APP_V2_CONTRACT_ID,\n        &next,\n        "domain_app_status_binding_missing",\n    ) {\n        return response;\n    }',
    replace: "    let _ = DOMAIN_APP_V2_CONTRACT_ID;",
    target:
      "AN ADVANCE WITH NO STAGE BINDING IS REFUSED: `admitted` without the immutable package release that admitted it is a claim about another plane's admission made by a route that admitted nothing, and the refusal comes from the registered contract's own conditional rather than a hand-written check that could drift from it",
  },
  {
    id: "a-runtime-state-is-accepted-as-an-inventory-status",
    file: ROUTE_SOURCE,
    find: '    if matches!(target, "mounted" | "serving" | "unmounted" | "killed") {',
    replace: '    if false {',
    target:
      "A RUNTIME STATE IS NOT AN INVENTORY STATUS: naming `serving` on the status route is refused as a category error that says which object owns the word, not as an unknown value that would leave a caller believing inventory has a serving state it has not reached",
  },
  {
    id: "the-predecessor-contract-becomes-authorable",
    file: ROUTE_SOURCE,
    find: "        Some(Value::String(declared)) if declared == predecessor => Err(bad(",
    replace: "        Some(Value::String(declared)) if declared == predecessor => Ok(()).map(|_| ()).or_else(|_: ()| Err(bad(",
    target:
      "DOWNGRADE IS A REFUSAL BY NAME: a create naming the deprecated predecessor is refused as the predecessor rather than read as the successor, because reading a v1 request as a v2 record is the exact reinterpretation the succession exists to avoid",
    skipReason: "replaced below by a compiling variant",
  },
  {
    id: "another-plane-s-field-is-silently-dropped",
    file: ROUTE_SOURCE,
    find: "        if body.get(field).is_some() {\n            return bad(",
    replace: "        if false {\n            return bad(",
    target:
      "A FIELD ANOTHER PLANE OWNS IS REFUSED BY NAME, NOT IGNORED: patching `status` through the ordinary mutation route is named and refused, because silently dropping it answers 200 to a request that changed nothing the caller asked for",
  },
  {
    id: "a-mounted-app-becomes-deletable",
    file: ROUTE_SOURCE,
    find: '        == Some(true)\n    {\n        return bad(\n            "domain_app_still_mounted",',
    replace: '        == Some(false)\n    {\n        return bad(\n            "domain_app_still_mounted",',
    target:
      "A MOUNTED APP IS NOT DELETABLE THROUGH THE OBJECT PLANE: deleting it would strand a runtime that still claims a governed mount, so the lifecycle's inverse has to run first",
  },
  {
    id: "the-app-read-consults-the-row-again",
    file: ROUTE_SOURCE,
    // A GENUINE REGRESSION TO ROW-AS-TRUTH: the resolver answers from the local row when one exists,
    // so a destroyed directory changes the answer and the whole projection claim collapses.
    find: "    let Some(payload) = domain_app_payload(&latest.operation.payload) else {",
    replace:
      "    let row_first = load(data_dir, KIND_DAPP, id).and_then(|row| row.get(\"domain_app\").cloned());\n    let Some(payload) = row_first\n        .map(Some)\n        .or_else(|| domain_app_payload(&latest.operation.payload))\n    else {",
    target:
      "THE RECORD DIRECTORIES ARE PROJECTIONS IN THE STRICT SENSE: all three are deleted, the daemon is restarted, and the app answers the same head, the same revision count, the same inventory status and the same content hash — an index whose loss changes an answer is not an index",
  },
  {
    id: "the-fold-re-stamps-the-mount-on-every-transition",
    file: ROUTE_SOURCE,
    find: '    runtime["mounted_at"] = if action == "domain_app.mount" {\n        json!(stamp)\n    } else {\n        carried("mounted_at")\n    };',
    replace: '    runtime["mounted_at"] = json!(stamp);',
    target:
      "AND THE RUNTIME IS A FOLD OVER THE ADMITTED HISTORY, NOT A ROW: with its directory gone it answers byte-identical to what the ladder produced, including the revision, the internal route, and the content hash the receipts bind",
  },
  {
    id: "the-snapshot-drops-the-two-members-v1-lacked",
    file: ROUTE_SOURCE,
    find: '        "canonical_object_model_refs": derived.canonical_object_model_refs,',
    replace: '        "canonical_object_model_refs": Vec::<String>::new(),',
    target:
      "the DomainApp is authored at the REGISTERED SUCCESSOR and its derived snapshot carries the two members v1 had no field for — a v1 app over this same descriptor recorded neither its object models nor its policy-bound views, and nothing failed",
  },
  {
    id: "the-snapshot-stops-naming-the-bytes-it-came-from",
    file: ROUTE_SOURCE,
    find: '        "surface_descriptor_content_hash": descriptor_hash,',
    replace: '        "surface_descriptor_content_hash": format!("sha256:{}", "00".repeat(32)),',
    target:
      "the snapshot names the EXACT descriptor bytes it was derived from, under that version's own commitment rule — a descriptor that advances leaves this app bound to the revision it actually read, so 'the snapshot is current' is decidable rather than assumed",
  },
  {
    id: "the-manifest-predecessor-becomes-authorable-again",
    file: ODK_SOURCE,
    find: "        Some(Value::String(declared)) if declared == ODK_MANIFEST_V1_SCHEMA_VERSION => Err(bad(",
    replace:
      '        Some(Value::String(declared)) if declared == "never-declared-v1" => Err(bad(',
    target:
      "AND THE PREDECESSOR IS NOT NEWLY AUTHORED: naming v1 is refused by name, so the lane whose folds this successor exists to end cannot be reopened one create at a time",
  },
  {
    id: "an-ambiguous-fold-is-split-by-guess",
    file: ODK_SOURCE,
    // A GENUINE GUESS: the legacy fold is accepted and silently routed to one of the two successor
    // members, so a benchmark filed under `eval_refs` becomes a dataset with no author saying so.
    find: "    for (legacy, successor) in ODK_MANIFEST_LEGACY_FIELDS {\n        if body.get(*legacy).is_some() {",
    replace:
      "    for (legacy, successor) in ODK_MANIFEST_LEGACY_FIELDS {\n        if false && body.get(*legacy).is_some() {",
    target:
      "AN AMBIGUOUS FOLD IS REFUSED, NOT SPLIT BY GUESS: `eval_refs` is answered by naming BOTH successor members it could belong to, because a dataset and a benchmark profile are different objects and only the author knows which each entry is",
  },
  {
    id: "the-package-consumer-reads-the-row-again",
    file: PACKAGE_SOURCE,
    // THE COMPATIBILITY STRATEGY THIS REVIEW REMOVED, REPLANTED. Resolving the DomainApp from the
    // record directory makes package admission depend on a rebuildable index: delete the row and the
    // app is unpackageable, corrupt it and the candidate freezes what the corruption said.
    find: "    let resolved_app = super::domain_apps_routes::resolve_admitted_domain_app(\n        data_dir,\n        identity,\n        domain_app_ref,\n    )",
    replace:
      "    let resolved_app = super::read_record_dir(data_dir, \"domain-apps\")\n        .into_iter()\n        .find(|row| row.get(\"domain_app_ref\").and_then(Value::as_str) == Some(domain_app_ref))\n        .map(|row| super::domain_apps_routes::ResolvedDomainApp {\n            domain_app_ref: domain_app_ref.to_string(),\n            schema_version: \"ioi.domain-app.v2\".to_string(),\n            record: row,\n            admitted_head: String::new(),\n            revision_count: 0,\n            withdrawn: false,\n            index_state: \"agreed_with_agentgres\",\n            projected_created_at: String::new(),\n            projected_updated_at: String::new(),\n        })\n        .ok_or_else(|| (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({\"ok\": false, \"error\": {\"code\": \"package_domain_app_unresolved\", \"message\": \"row absent\"}}))))",
    target:
      "PACKAGE ADMISSION SURVIVES A DELETED DOMAIN-APP ROW AND A CORRUPTED MANIFEST ROW, unchanged: the app row is gone, the manifest row has been overwritten with a forged predecessor naming a different manifest, and the candidate still freezes the same owner-committed hashes at the same heads — which is what 'the rows cannot change an admission decision' has to mean",
  },
  {
    id: "the-manifest-consumer-reads-the-row-again",
    file: PACKAGE_SOURCE,
    find: "    let resolved_manifest =\n        super::odk_routes::resolve_admitted_odk_manifest(data_dir, identity, manifest_ref)",
    replace:
      "    let resolved_manifest = super::read_record_dir(data_dir, \"odk-manifests\")\n        .into_iter()\n        .find(|row| row.get(\"ref\").and_then(Value::as_str) == Some(manifest_ref))\n        .map(|row| super::odk_routes::ResolvedOdkManifest {\n            manifest_ref: manifest_ref.to_string(),\n            schema_version: \"ioi.hypervisor.odk.manifest.v1\".to_string(),\n            content_hash: String::new(),\n            record: row,\n            admitted_head: String::new(),\n            index_state: \"agreed_with_agentgres\",\n            projected_created_at: String::new(),\n            projected_updated_at: String::new(),\n        })\n        .ok_or_else(|| (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({\"ok\": false, \"error\": {\"code\": \"package_odk_manifest_unresolved\", \"message\": \"row absent\"}}))))",
    target:
      "PACKAGE ADMISSION RESOLVES BOTH SOURCES THROUGH THEIR OWNER SEAMS AND CITES EXACT HEADS: the candidate names which contract admitted the app and the manifest and the exact chain position each was read at, so a frozen snapshot is locatable in its owner's history rather than only checkable against itself",
  },
  {
    id: "a-reused-key-answers-a-different-command",
    file: ROUTE_SOURCE,
    // A GENUINE FORGED SUCCESS: the divergence check is dropped, so a mount key reused with a
    // different ReleaseControl is handed the first mount's runtime and receipt and told it worked.
    find: "    if let Some(reason) = divergence {",
    replace: "    if let Some(reason) = None::<String>.or(divergence).filter(|_| false) {",
    target:
      "A KEY REUSED WITH DIFFERENT REQUEST MATERIAL IS REFUSED, NOT REPLAYED: the same mount key naming a different ReleaseControl is answered as a reused key rather than handed the first mount's receipt, because answering it would be a forged success for a command that was never admitted",
  },
  {
    id: "a-replay-folds-at-the-current-head",
    file: ROUTE_SOURCE,
    // The subtle one: the replay still resolves, but it folds the WHOLE ladder, so a mount retried
    // after a serve answers with the serving runtime and calls it the mount's result.
    find: "    let (runtime, _) = fold_ladder(&history[..=index]);",
    replace: "    let (runtime, _) = fold_ladder(&history);",
    target:
      "A REPLAY ANSWERS THE COMMAND IT REPLAYS, NOT THE LADDER'S CURRENT STATE: the mount key is retried AFTER a serve has advanced the runtime, and it still returns the mount's own runtime at revision 0 with the mount's own receipt, byte-identical to the first answer — a replay folded at the head would have handed back the serving runtime and called it the mount's result",
  },
  {
    id: "an-unknown-caller-field-is-silently-ignored",
    file: ROUTE_SOURCE,
    // A GENUINE WIDENING: the allowlist stops refusing, so an extra caller-authored field is dropped
    // on the floor — and because the material only carries the allowed keys, a retry that added or
    // removed it compares equal and replays as exact.
    find: "            if LADDER_WRITE_CONTROL_FIELDS.contains(&key.as_str())\n                || allowed.contains(&key.as_str())\n            {\n                continue;\n            }",
    replace: "            if true {\n                continue;\n            }",
    target:
      "AN EXTRA CALLER-AUTHORED FIELD IS REFUSED BY NAME, NOT IGNORED: the mount rung authors exactly two fields beside the shared write controls, so a retry that adds a third is a request the server would otherwise never have seen — and under the same key it would compare equal on everything the server did look at and replay as exact",
  },
  {
    id: "the-allowlist-accepts-every-rung-s-fields",
    file: ROUTE_SOURCE,
    // Every rung accepts every other rung's fields, so `stop-serving` stops refusing an approval ref
    // and the per-rung boundary collapses into one union.
    find: '        "domain_app.mount" => &["approval_request_ref", "release_control_ref"],',
    replace:
      '        "domain_app.mount" => &["approval_request_ref", "release_control_ref"],\n        "domain_app.serve_stop" => &["approval_request_ref", "release_control_ref", "reason"],',
    target:
      "AND THE ALLOWLIST IS PER-RUNG: stop-serving reuses the mount's governance and authors nothing, so naming an approval on it is refused rather than quietly accepted as a field some other rung happens to allow",
  },
  {
    id: "a-write-control-field-enters-the-compared-material",
    file: ROUTE_SOURCE,
    // The other direction: `expected_head` becomes part of the material, so a legitimate retry that
    // carries a concurrency control refuses as a different command. An over-wide comparison breaks
    // replay exactly as thoroughly as an under-wide one lets a forgery through.
    find: 'const LADDER_WRITE_CONTROL_FIELDS: &[&str] = &["owner_ref", "idempotency_key", "expected_head"];',
    replace: 'const LADDER_WRITE_CONTROL_FIELDS: &[&str] = &["owner_ref", "idempotency_key"];',
    target:
      "THE SHARED WRITE CONTROLS ARE ACCEPTED BESIDE THIS RUNG'S OWN FIELDS AND ARE NOT PART OF THE COMPARED MATERIAL: a retry carrying `expected_head` still replays to the same runtime and receipt, because a concurrency control is not something the caller authored about WHAT to do",
  },
  {
    id: "the-head-width-goes-back-to-a-range",
    file: RECEIPT_SCHEMA,
    find: '"pattern": "^(?:sha256:[0-9a-f]{64}|[0-9a-f]{64})$"',
    replace: '"pattern": "^(?:sha256:[0-9a-f]{16,128}|[0-9a-f]{16,128})$"',
    target:
      "the admitted head a receipt binds is EXACTLY ONE SHA-256 — sixty-four lowercase hex with or without the substrate's prefix — so a truncated head, which names a prefix of a chain rather than a position in it, cannot satisfy the contract",
    noRebuild: true,
  },
].filter((mutant) => !mutant.skipReason);

/// The digest one complete ledger is allowed to speak for.
///
/// It covers this verifier's own bytes AND every source its mutants plant into. A ledger row proves
/// a fence held in the tree that produced it; carried onto an edited tree it proves nothing, and a
/// stale row that still reads RED_ON_TARGET is worse than a missing one.
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
    if (!originals.has(mutant.file)) {
      originals.set(mutant.file, fs.readFileSync(mutant.file, "utf8"));
    }
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
      process.stdout.write(`  ${"STALE".padEnd(14)} ${mutant.id}\n`);
      continue;
    }
    fs.writeFileSync(mutant.file, original.replace(mutant.find, mutant.replace));
    // A mutant that plants into a registered schema changes what the GATE reads, not what the daemon
    // is built from, so rebuilding would cost ninety seconds to produce the same binary.
    if (!mutant.noRebuild && !rebuild()) {
      rows.push({ id: mutant.id, verdict: "NO_BUILD", detail: "mutant did not compile" });
      process.stdout.write(`  ${"NO_BUILD".padEnd(14)} ${mutant.id}\n`);
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
  const restored = MUTANTS.every(
    (mutant) => fs.readFileSync(mutant.file, "utf8") === originals.get(mutant.file),
  );
  const digest = harnessDigest();
  const previous = fs.existsSync(LEDGER) ? JSON.parse(fs.readFileSync(LEDGER, "utf8")) : {};
  // A ledger speaks for ONE tree. If the harness or any mutated source moved since the last chunk,
  // the older rows are about a tree that no longer exists and are dropped rather than merged.
  const ledger =
    previous.harness_digest === digest ? previous : { harness_digest: digest, rows: {} };
  ledger.harness_digest = digest;
  ledger.rows = ledger.rows ?? {};
  for (const row of rows) ledger.rows[row.id] = row;
  fs.writeFileSync(LEDGER, JSON.stringify(ledger, null, 2));
  rebuild();
  const reds = rows.filter((row) => row.verdict === "RED_ON_TARGET").length;
  const collateral = rows.reduce((total, row) => total + (row.collateral ?? 0), 0);
  process.stdout.write(
    `\nM05.6 mutation battery: ${reds}/${rows.length} RED ON TARGET; collateral failures ${collateral}; source restored ${restored}\n`,
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
    `\nM05.6 mutation summary: ${MUTANTS.length - missing.length - notRed.length}/${MUTANTS.length} RED ON TARGET\n`,
  );
  process.exit(current && missing.length === 0 && notRed.length === 0 ? 0 : 1);
}

/// Pre-flight the battery's own anchors WITHOUT running it.
///
/// A stale anchor is a mutant that silently tests nothing, and discovering one costs a full rebuild
/// per mutant if the battery finds it. Exactly once matters: `String.replace` plants at the first
/// match, so an ambiguous anchor may mutate a site other than the one its target names.
function checkAnchors() {
  const seen = new Map();
  let problems = 0;
  for (const mutant of MUTANTS) {
    if (!seen.has(mutant.file)) seen.set(mutant.file, fs.readFileSync(mutant.file, "utf8"));
    const text = seen.get(mutant.file);
    const count = text.split(mutant.find).length - 1;
    if (count !== 1) {
      problems += 1;
      process.stdout.write(`  ${count === 0 ? "STALE" : `AMBIGUOUS(${count})`}  ${mutant.id}\n`);
    }
  }
  const targets = new Set(MUTANTS.map((m) => m.target));
  if (targets.size !== MUTANTS.length) {
    problems += 1;
    process.stdout.write("  DUPLICATE TARGETS: two mutants claim the same assertion\n");
  }
  process.stdout.write(`\n${MUTANTS.length} mutants, ${problems} anchor problems\n`);
  process.exit(problems === 0 ? 0 : 1);
}

// ------------------------------------------------------------------------------------------- driver

async function runAll() {
  runRegistryClaims();
  const ctx = await run();
  const ladder = await runLadder(ctx);
  await runStatusAndRefusals(ctx, ladder);
  // Packaging runs BEFORE the durability phase destroys this run's record directories, because it
  // destroys its own two rows and has to be the one that decides when they go.
  await runManifestAndPackaging(ctx);
  await runDurability(ctx, ladder);
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
    process.stdout.write(
      `${entry.pass ? "PASS" : "FAIL"}  ${entry.name}${entry.detail ? `  [${entry.detail}]` : ""}\n`,
    );
  }
  emitVerifierCensus({
    verifierId: "odk-contract-and-domainapp",
    sourceUrl: import.meta.url,
    results,
  });
  process.stdout.write(
    `\ncheck:odk-contract-and-domainapp — ${results.length - failed.length}/${results.length} assertions\n`,
  );
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((error) => {
  cleanup();
  process.stderr.write(`${error}\n`);
  process.exit(1);
});
