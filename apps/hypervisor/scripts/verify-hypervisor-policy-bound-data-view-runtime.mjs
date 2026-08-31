#!/usr/bin/env node
// M05.8 — the runtime-enforced PolicyBoundDataView, verified against a LIVE daemon.
//
// WHAT THIS GATE CLAIMS. That a policy-bound view is an immutable owner-qualified revision whose
// permitted-use set is a SUBTRACTION over inputs resolved through their owners' seams; that the
// materialization route is the only place a bounded row/field/time projection is granted; that it
// revalidates the policy at the READ instant so a consent window, a claim validity window or a
// boundary window that closed after admission refuses; that an excess field, an excess row count, a
// substituted row predicate, a wrong timebase, an out-of-scope window, a refused destination,
// representation, region or jurisdiction each refuse by name; and that every one of those facts
// REPLAYS from the durable chain across a real process restart with the read index destroyed.
//
// WHAT IT DOES NOT CLAIM. No provider-connection fact. `ProviderConnectionBinding` is
// wallet.network's (M03.16) and is deliberately outside this contract's closed eight-fact
// vocabulary; this gate asserts that the daemon models no stand-in for it and instead refuses a
// brokered destination no live route-rights contract admits. No protected data, provider or network
// egress is exercised. A granted projection is a DESCRIPTOR; this gate asserts it carries no payload
// bytes and is narrower than the view that permitted it.
//
// DURABLE TRUTH IS READ ACROSS A RESTART. Asking the API whether something survived a restart,
// without restarting, is asking the thing under test to grade itself.
//
// Exit: 0 all assertions pass · 1 any assertion fails · 2 BLOCKED (daemon binary missing).

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const MUTATE = process.argv.includes("--mutate");
const ANCHORS = process.argv.includes("--anchors");
const SUMMARIZE = process.argv.includes("--summarize");
const RESTORE = process.argv.includes("--restore");
// `--only=id,id` scores a SUBSET. An interrupted whole-battery run produced no result at all, so
// scoring in bounded batches makes each batch its own evidence. The ledger line always reports the
// denominator it actually ran, never the full population.
const ONLY = (process.argv.find((arg) => arg.startsWith("--only=")) ?? "")
  .replace("--only=", "")
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.error?.code ?? j?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const canonicalJson = (value) => {
  if (value === null || value === undefined || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
};
const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;
const pointer = (document, jsonPath) => {
  let current = document;
  for (const segment of jsonPath.slice(2).split(".")) current = current?.[segment];
  return current === undefined ? null : current;
};

const INVARIANTS = path.join(
  ROOT,
  "docs/architecture/_meta/schemas/invariants/policy-bound-data-view.v2.invariants.json",
);

/** The commitment, rebuilt from the REGISTERED profile's own material list and domain constant. */
function registeredCommitment(document) {
  const rules = JSON.parse(fs.readFileSync(INVARIANTS, "utf8")).rules;
  const rule = rules.find((r) => r.rule_id === "policy_bound_data_view.content_hash.commits_the_whole_revision");
  const material = {};
  for (const [field, descriptor] of Object.entries(rule.expression.material_fields)) {
    material[field] = Object.hasOwn(descriptor, "value") ? descriptor.value : pointer(document, descriptor.path);
  }
  return { digest: sha256(canonicalJson(material)), fields: Object.keys(rule.expression.material_fields).length };
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-pbdv-"));
const dataDir = path.join(scratch, "data");
let daemon = null;
let daemonLog = "";
let DAEMON = "";
const SESSIONS = { A: "", B: "" };

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
  if (process.env.CARGO_TARGET_DIR) return path.join(process.env.CARGO_TARGET_DIR, "debug", "hypervisor-daemon");
  return path.join(ROOT, "target", "debug", "hypervisor-daemon");
}

function rebuildDaemon() {
  const build = spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (build.status !== 0) throw new Error(`daemon did not build:\n${build.stderr?.slice(-4000)}`);
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
      IOI_WALLET_SECRET_PASS: "ioi-policy-bound-data-view-verifier",
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

process.on("exit", cleanup);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    cleanup();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}

async function req(method, url, body, opts = {}) {
  const as = "as" in opts ? opts.as : "A";
  const headers = { "content-type": "application/json" };
  if (as && SESSIONS[as]) headers.cookie = `ioi_session=${SESSIONS[as]}`;
  try {
    const response = await fetch(`${DAEMON}${url}`, {
      method,
      headers,
      body: body === null || body === undefined ? undefined : JSON.stringify(body),
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
const ROUTES = "/v1/hypervisor/model-route-rights-contracts";
const CLAIMS = "/v1/hypervisor/learning-source-rights-claims";
const PROFILES = "/v1/hypervisor/institutional-learning-boundary-profiles";
const APPROVALS = "/v1/hypervisor/governance/approval-requests";
const VIEWS = "/v1/hypervisor/policy-bound-data-views";
const MATS = "/v1/hypervisor/policy-bound-data-view-materializations";
const OWNER = "org://local";
// The runtime derives tenant identity from the owner-qualified namespace; keep the fixture on that
// same owner seam instead of inventing the legacy shorthand `tenant://local`.
const TENANT = "tenant://org.local";
const POLICY = `sha256:${"77".repeat(32)}`;

// ---------------------------------------------------------------------------------- the instants
//
// EVERY EXPIRY BELOW IS MEASURED AGAINST A CALLER-DECLARED INSTANT, so this gate is deterministic:
// the same fixtures produce the same decisions on any machine at any wall-clock time. ADMIT is when
// the view is compiled; READ is later, and the windows that close between them are what the
// read-time revalidation exists to find.
const T_ADMIT = "2026-09-01T08:00:00Z";
const T_READ = "2026-12-01T08:00:00Z";

// --------------------------------------------------------------------------------- fixture bodies
//
// THE SOURCE ROWS ARE REAL ADMITTED REVISIONS, not well-formed strings. `seedOwners` fills these in
// from what each owner actually served, because a view whose sources cannot be resolved is exactly
// what this build now refuses — so a fixture with invented source refs would test the refusal path
// and never reach the positive one.
let SOURCE_ROWS = [];
let OBSERVED_ROWS = [];

/// The consent this view binds. It must also be a rights basis on the bound claim, because that
/// claim is the only thing that can revalidate its revocation and expiry at the read.
const CONSENT_REF = "grant://acme-clinic/intake-consent/v3";

const viewBody = (key, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family: "acme.intake-minimised",
  effective_at: T_ADMIT,
  purpose: "evaluation",
  source_bindings: SOURCE_ROWS,
  object_model_refs: ["object-model://om_patient_intake"],
  row_scope: {
    row_predicate_ref: "predicate://acme/intake/consented-and-in-window",
    row_predicate_hash: `sha256:${"aa".repeat(32)}`,
    max_row_count: 50000,
  },
  allowed_field_refs: ["field://acme/intake/intake_id", "field://acme/intake/visit_date"],
  field_minimization_decisions: [
    {
      field_ref: "field://acme/intake/intake_id",
      source_ref: SOURCE_ROWS[0]?.source_ref ?? "",
      necessity_basis: "required_by_join_key",
      data_class: "quasi_identifier",
    },
    {
      field_ref: "field://acme/intake/visit_date",
      source_ref: SOURCE_ROWS[0]?.source_ref ?? "",
      necessity_basis: "required_by_purpose",
      data_class: "operational_metadata",
    },
  ],
  time_scope: { timebase: "source_event_time", from: "2026-01-01T00:00:00Z", until: "2026-09-01T00:00:00Z" },
  data_classes: ["source_data"],
  privacy_class: "restricted",
  consent_bindings: [
    {
      consent_ref: CONSENT_REF,
      consent_state: "active",
      consent_subject_ref: OWNER,
      valid_until: "2027-06-01T00:00:00Z",
    },
  ],
  jurisdiction_refs: ["jurisdiction://us-ca"],
  residency_refs: ["region://us-west"],
  retention_and_hold: {
    retention_policy_ref: "policy://acme/retention/intake/v3",
    retention_state: "within_retention",
    hold_state: "none",
    expires_at: "2027-01-01T00:00:00Z",
    deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2",
  },
  destination_and_egress: {
    permitted_destination_classes: ["in_boundary_only", "model_provider"],
    egress_ceiling: "redacted_only",
    permitted_region_refs: ["region://us-west"],
    cross_tenant_read_permitted: false,
    declassification_permitted_without_approval: false,
  },
  ...over,
});

const readBody = (key, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family: "acme.intake-read",
  effective_at: T_READ,
  requested_use: "evaluate",
  requested_field_refs: ["field://acme/intake/intake_id"],
  requested_row_predicate_ref: "predicate://acme/intake/consented-and-in-window",
  requested_row_predicate_hash: `sha256:${"aa".repeat(32)}`,
  requested_max_row_count: 100,
  requested_timebase: "source_event_time",
  requested_from: "2026-02-01T00:00:00Z",
  requested_until: "2026-08-01T00:00:00Z",
  requested_destination_class: "in_boundary_only",
  requested_representation: "redacted",
  requested_region_ref: "region://us-west",
  requested_jurisdiction_ref: "jurisdiction://us-ca",
  observed_source_revisions: OBSERVED_ROWS,
  ...over,
});

/// The eight facts the registered precondition names. This build revalidates all eight, so a
/// materialization that conforms genuinely grants a bounded descriptor.
const REVALIDATED_FACTS = [
  "current_authority",
  "current_rights",
  "revocation_state",
  "expiry",
  "retention_and_hold",
  "residency",
  "destination_class",
  "consent_state",
];

const refusals = (response) => response.j?.policy_bound_data_view_materialization?.refusal_codes ?? [];
const decision = (response) => response.j?.policy_bound_data_view_materialization?.decision ?? "";
const hasCode = (response, suffix) => refusals(response).some((c) => c.endsWith(suffix));

// ============================================================ the four surfaces, one owner route
//
// THE CENTRAL CLAIM OF THIS SECTION. Native, SDK, CLI and MCP are FOUR TRANSPORTS TO ONE DECISION.
// Each carries the caller's own bearer PAT to the same daemon owner route, and the daemon — the only
// place admission/materialization logic exists — returns the same typed body. So the same negative
// class produces the same refusal `code` on every path, no path materializes a negative, and the one
// positive yields the identical bounded descriptor. A client that started deciding for itself would
// break equivalence, and the static no-second-admitter grep below refuses one that even names a
// refusal string.
//
// AUTH IS A TOKEN, NEVER A PRINCIPAL. Every cell authenticates with a `pat_*` minted through the
// daemon's own /v1/hypervisor/api-tokens route; the token IS the principal binding, so no client can
// name a tenant or author a server-resolved field. Unauthenticated is 401 and principal B is 403 on
// every path.

const PATHS = ["native", "sdk", "cli", "mcp"];
const PAT = { A: "", B: "" };

// Runner availability. The daemon binary is always required; the SDK dist and the CLI binary are
// built by the same lane. When a runner is genuinely absent its cell is a TYPED non-pass
// (`unavailable`), never a silent skip — absent evidence is red, not green.
const SDK_ENTRY =
  process.env.IOI_AGENT_SDK_ENTRY ||
  path.join(ROOT, "packages", "agent-sdk", "dist", "index.js");
// The `ioi-cli` crate builds a binary named `cli` (per crates/cli/Cargo.toml), not `ioi-cli`.
const CLI_BINARY =
  process.env.IOI_CLI_BINARY ||
  (process.env.CARGO_TARGET_DIR
    ? path.join(process.env.CARGO_TARGET_DIR, "debug", "cli")
    : path.join(ROOT, "target", "debug", "cli"));
const MCP_SERVER = path.join(APP, "scripts", "mcp", "policy-bound-data-view-stdio.mjs");

let sdkModule = null;
async function loadSdk() {
  if (sdkModule) return sdkModule;
  if (!fs.existsSync(SDK_ENTRY)) return null;
  sdkModule = await import(pathToFileURL(SDK_ENTRY).href);
  return sdkModule;
}

// The route table each path resolves a `kind` to, so no client hardcodes a decision — only a route.
const KIND_ROUTE = {
  admit: { method: "POST", route: VIEWS },
  query: { method: "GET", route: VIEWS },
  materialize: { method: "POST", route: MATS },
};

/** NATIVE: a bearer fetch, the same wire every other path speaks. Distinct from `req()`, which uses
 *  a cookie session for setup; the matrix is bearer-only so all four carry the exact same credential
 *  shape. */
async function callNative(kind, { body, family, revision } = {}, token) {
  const { method, route } = KIND_ROUTE[kind];
  let url = `${DAEMON}${route}`;
  if (kind === "query") {
    const params = new URLSearchParams();
    if (family !== undefined) params.set("family", family);
    if (revision !== undefined) params.set("revision", String(revision));
    const suffix = params.toString();
    if (suffix) url = `${url}?${suffix}`;
  }
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers.authorization = `Bearer ${token}`;
  try {
    const response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let json = null;
    try {
      json = text.length ? JSON.parse(text) : null;
    } catch {
      json = text;
    }
    return { available: true, status: response.status, body: json };
  } catch (error) {
    return { available: true, status: 0, body: { transport_error: String(error) } };
  }
}

/** SDK: construct the exported client and call its method. A refusal is thrown as
 *  `PolicyBoundDataViewRefusal`, whose `.status` and `.body` carry the daemon envelope UNCHANGED. */
async function callSdk(kind, { body, family, revision } = {}, token) {
  const mod = await loadSdk();
  if (!mod) return { available: false, reason: "agent-sdk dist not built" };
  const client = new mod.PolicyBoundDataViewClient({ endpoint: DAEMON, apiKey: token });
  try {
    let result;
    if (kind === "admit") result = await client.admit(body);
    else if (kind === "materialize") result = await client.materialize(body);
    else result = await client.query({ family, revision });
    // The SDK returns only the parsed body on success; a created record answers 201, a query 200.
    const status = kind === "query" ? 200 : 201;
    return { available: true, status, body: result };
  } catch (error) {
    if (error && error.name === "PolicyBoundDataViewRefusal") {
      return { available: true, status: error.status, body: error.body };
    }
    return { available: true, status: 0, body: { transport_error: String(error) } };
  }
}

/** CLI: spawn the built `ioi-cli` binary with the token in the environment and the body on stdin. It
 *  prints the daemon JSON verbatim and exits nonzero on a non-2xx; we read the body from stdout and
 *  the status class from the exit code. */
function callCli(kind, { body, family, revision } = {}, token) {
  if (!fs.existsSync(CLI_BINARY)) return { available: false, reason: "ioi-cli binary not built" };
  const args = ["policy-bound-data-view", kind];
  if (kind === "query") {
    if (family !== undefined) args.push("--family", family);
    if (revision !== undefined) args.push("--revision", String(revision));
  } else {
    args.push("--file", "-");
  }
  const child = spawnSync(CLI_BINARY, args, {
    encoding: "utf8",
    input: kind === "query" ? undefined : JSON.stringify(body ?? {}),
    env: { ...process.env, IOI_DAEMON_ENDPOINT: DAEMON, IOI_DAEMON_TOKEN: token || "" },
    maxBuffer: 16 * 1024 * 1024,
  });
  let parsed = null;
  try {
    parsed = child.stdout && child.stdout.trim().length ? JSON.parse(child.stdout) : null;
  } catch {
    parsed = child.stdout;
  }
  // The refusal JSON is on stdout; the EXACT http status is in the CLI's stderr line
  // ("daemon responded <status> — …"). Derive it from there rather than mapping every nonzero exit
  // to one code, so a 401/403/409 is not flattened into a 422.
  let status;
  if (child.status === 0) {
    status = kind === "query" ? 200 : 201;
  } else {
    const match = /daemon responded (\d+)/u.exec(child.stderr || "");
    status = match ? Number(match[1]) : 0;
  }
  return { available: true, status, body: parsed };
}

/** MCP: spawn the bounded stdio server with the token in the environment, drive one `tools/call`, and
 *  read the daemon body back out of `structuredContent`. The bearer never appears in the arguments. */
function callMcp(kind, { body, family, revision } = {}, token) {
  if (!fs.existsSync(MCP_SERVER)) return { available: false, reason: "mcp stdio server missing" };
  const toolName = `policy_bound_data_view.${kind}`;
  const args =
    kind === "query"
      ? { ...(family !== undefined ? { family } : {}), ...(revision !== undefined ? { revision } : {}) }
      : { body: body ?? {} };
  const requests = [
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } }),
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: toolName, arguments: args } }),
    "",
  ].join("\n");
  const child = spawnSync(process.execPath, [MCP_SERVER], {
    encoding: "utf8",
    input: requests,
    env: { ...process.env, IOI_DAEMON_ENDPOINT: DAEMON, IOI_DAEMON_TOKEN: token || "" },
    maxBuffer: 16 * 1024 * 1024,
  });
  const lines = (child.stdout || "").split("\n").map((l) => l.trim()).filter(Boolean);
  let call = null;
  for (const line of lines) {
    try {
      const message = JSON.parse(line);
      if (message.id === 2) call = message;
    } catch {
      /* ignore non-json noise */
    }
  }
  if (!call) return { available: true, status: 0, body: { transport_error: "no tools/call response", stderr: child.stderr } };
  if (call.error) return { available: true, status: -32000, body: { mcp_error: call.error } };
  const structured = call.result?.structuredContent ?? {};
  return { available: true, status: structured.http_status ?? 0, body: structured.daemon_response ?? null };
}

async function callPath(pathName, kind, input, token) {
  if (pathName === "native") return callNative(kind, input, token);
  if (pathName === "sdk") return callSdk(kind, input, token);
  if (pathName === "cli") return callCli(kind, input, token);
  if (pathName === "mcp") return callMcp(kind, input, token);
  throw new Error(`unknown path ${pathName}`);
}

/** The refusal code a body carries, wherever the family put it, or "" for a 2xx body. */
function bodyRefusalCodes(body) {
  if (!body || typeof body !== "object") return [];
  if (body.error && typeof body.error === "object" && typeof body.error.code === "string") return [body.error.code];
  if (typeof body.code === "string") return [body.code];
  const mat = body.policy_bound_data_view_materialization;
  return mat && Array.isArray(mat.refusal_codes) ? mat.refusal_codes : [];
}

const bodyRefusalCode = (body) => bodyRefusalCodes(body)[0] ?? "";

/** True when a body records a granted materialization — the thing NO negative may produce. */
function bodyMaterialized(body) {
  if (!body || typeof body !== "object") return false;
  if (body.materialized === true) return true;
  return body.policy_bound_data_view_materialization?.decision === "materialized";
}

const pathSummary = (cells) =>
  cells.map((c) => `${c.path}:${c.available === false ? "unavailable" : `${c.status}/${c.code || "-"}`}`).join(" ");

// ------------------------------------------------------------------------------- the prerequisites

/** Every owner seam this unit binds, admitted through its OWNER's own route. */
async function seedOwners() {
  const ontology = await req("POST", OV, {
    owner_ref: OWNER,
    idempotency_key: "pbdv-ontology",
    namespace: "acme-clinic",
    name: "patient-intake",
    governing_scope_ref: "domain://acme-clinic/intake",
    policy_hash: POLICY,
    entity_types: [{ term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" }],
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  });
  const ONT = ontology.j?.ontology_version?.ontology_id ?? "";

  const mapping = async (key, family, status) =>
    (
      await req("POST", MAP, {
        owner_ref: OWNER,
        idempotency_key: key,
        family,
        name: family,
        connector_id: "connector://google-drive",
        ontology_revision_ref: ONT,
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
        ],
        action_mappings: [],
        authority_scopes_required: ["scope:connector.google_drive.read"],
        redaction_policy_ref: "policy://acme-clinic/intake-redaction",
        evidence_required: ["evidence-contract://acme-clinic/intake-consent"],
        effective_policy_hash: POLICY,
        registry_status: status,
      })
    ).j?.connector_mapping ?? {};
  const liveMap = await mapping("pbdv-map-live", "acme.intake-form", "active");
  const deadMap = await mapping("pbdv-map-dead", "acme.intake-form-old", "deprecated");

  const recipe = (
    await req("POST", REC, {
      owner_ref: OWNER,
      idempotency_key: "pbdv-recipe",
      family: "acme.intake-redact",
      name: "intake-redact",
      ontology_revision_refs: [ONT],
      input_source_types: ["connector"],
      connector_mapping_revision_refs: [liveMap.revision_ref],
      output_object_model_refs: ["object-model://om_patient_intake"],
      output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"],
      transformation_steps: ["extract", "redact", "normalize"],
      policy_bound_data_view_refs: [],
      receipt_obligations: ["data_recipe_run", "transformation"],
      effective_policy_hash: POLICY,
      registry_status: "active",
    })
  ).j?.data_recipe ?? {};

  const route = (
    await req("POST", ROUTES, {
      owner_ref: OWNER,
      idempotency_key: "pbdv-route",
      family: "acme.primary-inference",
      effective_at: "2026-05-01T10:00:00Z",
      route_binding: {
        route_ref: "route://acme-clinic/primary-inference",
        provider_ref: "provider://acme-clinic/external-inference-a",
        model_ref: "model://external-inference-a/general",
        model_revision_ref: "model://external-inference-a/general/revision/11",
        intermediary_ref: null,
        upstream_terms_ref: null,
        intermediary_is_supply_adapter_not_trust_boundary: true,
      },
      purposes: ["inference_service_delivery"],
      data_classes: ["prompts_and_completions"],
      declared_prohibited_route_uses: ["publication", "downstream_use", "oem_or_reseller_use"],
      unresolved_rights_findings: [],
      destination_and_egress: {
        permitted_destination_classes: ["model_provider"],
        egress_ceiling: "redacted_only",
        region_refs: ["region://us-west"],
        residency_refs: ["region://us-west"],
        cross_border_transfer_basis_ref: null,
      },
      customer_output_rights: {
        intended_customer_output_uses: ["retain", "internal_evaluation"],
        effective_customer_output_rights_hash: `sha256:${"44".repeat(32)}`,
        competing_model_training_permitted: false,
      },
      provider_use_of_customer_material: {
        request_or_prompt_logging: "prohibited",
        human_review: "prohibited",
        abuse_and_security_processing: "transient_only",
        service_improvement: "prohibited",
        provider_model_training: "prohibited",
        provider_model_training_basis_ref: null,
        cross_customer_aggregation: "prohibited",
        cross_customer_aggregation_basis_ref: null,
        publication: "prohibited",
      },
      retention_posture: "zero_retention",
      retention_policy_ref: "policy://acme/retention/route/v1",
      commercial_terms_refs: ["contract://acme/provider-a-order-form/v3"],
      technical_terms_refs: ["terms://acme/provider-a/v7"],
      fallback_substitution: { fallback_is_semantic_substitution: true, fallback_route_rights_revision_ref: null },
      validity: { valid_from: "2026-05-01T00:00:00Z", valid_until: "2027-05-01T00:00:00Z" },
      revocation: { revocation_state: "live", revoked_at: null, revocation_reason: null, revocation_authority_ref: null },
      status: "active",
      resolved_principal_ref: "worker://acme-clinic/intake-assistant",
      credential_principal_ref: "service://acme-clinic/inference-credential-a",
    })
  ).j?.model_route_rights_contract ?? {};

  const claim = async (key, family, validUntil) =>
    (
      await req("POST", CLAIMS, {
        owner_ref: OWNER,
        idempotency_key: key,
        family,
        effective_at: "2026-06-01T09:14:03Z",
        asserted_by_ref: OWNER,
        asserted_rights_holder_refs: [OWNER],
        source_class: "customer",
        subject_refs: ["dataset://acme/intake-rows/v3"],
        // THE CONSENT RIDES HERE, as canon carries it: a rights basis on the claim, never a family
        // of its own. This is what lets the view bind that consent and lets the read revalidate it.
        rights_basis_refs: ["contract://acme/customer-msa/v4", CONSENT_REF],
        declared_prohibited_uses: ["competing_model_training", "publish"],
        unresolved_rights_findings: [],
        derivative_disposition: "inherit_intersection",
        beneficiary_scope_refs: [OWNER],
        jurisdiction_refs: ["jurisdiction://us-ca"],
        residency_refs: ["region://us-west"],
        retention_policy_ref: "policy://acme/retention/intake/v3",
        deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2",
        legal_or_audit_hold_state: "none",
        validity: { valid_from: "2026-06-01T00:00:00Z", valid_until: validUntil },
        evidence_refs: ["evidence://acme/msa-countersigned/v4"],
        claim_commitment: `sha256:${"aa".repeat(32)}`,
        status: "admitted",
        route_rights_contract_refs: [route.revision_ref],
      })
    ).j?.learning_source_rights_claim ?? {};
  // The LIVE claim outlives the read. The LAPSING claim is still `admitted` and its own bytes carry
  // every permission — only a check against the READ instant can find that its window closed.
  const liveClaim = await claim("pbdv-claim-live", "acme.intake-records", null);
  const lapsingClaim = await claim("pbdv-claim-lapsing", "acme.lapsing-records", "2026-10-01T00:00:00Z");

  const profile = async (key, family, expiresAt) =>
    (
      await req("POST", PROFILES, {
        owner_ref: OWNER,
        idempotency_key: key,
        family,
        effective_at: "2026-06-01T09:20:11Z",
        scope_level: "organization",
        applies_to_refs: [OWNER],
        protected_material_classes: ["source_data"],
        custody: {
          product_mode: "private",
          runtime_operator: "customer_managed",
          permitted_provider_trust_postures: ["no_provider_plaintext", "redacted_only"],
          permitted_custody_postures: ["customer_boundary"],
          private_claim_requires_current_proof: true,
        },
        external_recipient_permissions: {
          transient_inference: "allow",
          service_logging: "policy_qualified",
          abuse_or_security_review: "policy_qualified",
          human_support_review: "deny",
          retention: "deny",
          service_improvement: "deny",
          provider_model_training: "deny",
          provider_model_training_basis_ref: null,
          cross_customer_aggregation: "deny",
          cross_customer_aggregation_basis_ref: null,
          publication: "deny",
        },
        cross_tenant_learning: {
          default: "deny",
          permitted_cohort_refs: [],
          aggregation_policy_ref: null,
          contribution_and_benefit_terms_ref: null,
          non_reconstruction_control_refs: [],
        },
        bound_target_refs: ["worker://acme-clinic/intake-assistant"],
        jurisdiction_refs: ["jurisdiction://us-ca"],
        residency_refs: ["region://us-west"],
        retention_policy_ref: "policy://acme/retention/intake/v3",
        deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2",
        derivative_policy_ref: "policy://acme/derivative/v1",
        export_policy_ref: "policy://acme/export/v1",
        revocation_policy_ref: "policy://acme/revocation/v1",
        declassification_policy_ref: "policy://acme/declassification/v1",
        learning_source_rights_claim_revision_refs: [liveClaim.revision_ref],
        route_rights_contract_refs: [route.revision_ref],
        status: "active",
        expires_at: expiresAt,
      })
    ).j?.institutional_learning_boundary_profile ?? {};
  const liveProfile = await profile("pbdv-profile-live", "acme.organization-default", null);
  const lapsingProfile = await profile("pbdv-profile-lapsing", "acme.lapsing-policy", "2026-10-01T00:00:00Z");
  // THE GOVERNANCE DECISION THAT BINDS THE PURPOSE. `authority-action://` is a scheme Governance
  // treats as a named ref, so the approval record itself is creatable here; what matters for this
  // unit is that the resulting `approval-request://appr_…` is a Governance-owned record its own
  // resolver can open — which is the difference between a bound purpose and a purpose-shaped label.
  const approval =
    (
      await req("POST", APPROVALS, {
        subject_ref: "authority-action://acme-clinic/intake-purpose",
        request_kind: "purpose_binding",
        reason: "verifier fixture: the Governance decision that bound this view's purpose",
      })
    ).j?.approval_request ?? {};

  // ONE COMPLETED EXECUTION, so the new M05.7 seam has something exact to resolve. A run is the
  // object that PRODUCED the ontology-bound material a view projects over, and it is the seam this
  // unit was missing before the audit.
const completedRunReply = await req("POST", "/v1/hypervisor/transformation-runs", {
    owner_ref: OWNER,
    idempotency_key: "pbdv-run-completed",
    data_recipe_revision_ref: recipe.revision_ref,
    output_intent: "ontology_objects",
    execution_status: "completed",
    input_refs: ["artifact://acme/intake-forms/batch-2026-08"],
    authority_grant_refs: ["grant://acme-clinic/intake-read/2026-08"],
    output_object_refs: ["agentgres://object/patient_intake/2026-08-batch"],
    receipt_refs: ["receipt://acme-clinic/transformation/2026-08-batch"],
    derivative_policy_ref: "policy://acme-clinic/intake-derivatives",
    impact_graph_ref: "agentgres://projection/intake-impact",
  });
  const completedRun = completedRunReply.j?.transformation_run ?? {};
  const queuedRunReply = await req("POST", "/v1/hypervisor/transformation-runs", {
    owner_ref: OWNER,
    idempotency_key: "pbdv-run-queued",
    data_recipe_revision_ref: recipe.revision_ref,
    output_intent: "ontology_objects",
    execution_status: "queued",
    input_refs: ["artifact://acme/intake-forms/batch-2026-09"],
    authority_grant_refs: ["grant://acme-clinic/intake-read/2026-09"],
    output_object_refs: [],
    receipt_refs: [],
    derivative_policy_ref: "policy://acme-clinic/intake-derivatives",
    impact_graph_ref: "agentgres://projection/intake-impact",
    expected_head: completedRunReply.j?.expected_head_for_successor,
  });
  const queuedRun = queuedRunReply.j?.transformation_run ?? {};

  // The bound source set: an ontology revision (M05.1), a mapping revision and a completed run
  // (M05.7). Every hash is what its OWNER served, never a constant this fixture invented.
  const row = (ref, hash, cls) => ({
    source_ref: ref,
    source_revision_ref: ref,
    source_content_hash: hash,
    source_tenant_ref: TENANT,
    source_owner_ref: OWNER,
    source_class: cls,
  });
  SOURCE_ROWS = [
    row(ONT, ontology.j?.ontology_version?.content_hash ?? "", "machine_generated"),
    row(liveMap.revision_ref, liveMap.content_hash, "customer"),
    row(completedRun.transformation_run_id, completedRun.content_hash, "machine_generated"),
  ];
  OBSERVED_ROWS = SOURCE_ROWS.map(({ source_ref, source_revision_ref, source_content_hash }) => ({
    source_ref,
    source_revision_ref,
    source_content_hash,
  }));

  return {
    ONT,
    liveMap,
    deadMap,
    recipe,
    route,
    liveClaim,
    lapsingClaim,
    liveProfile,
    lapsingProfile,
    approval,
    completedRun,
    queuedRun,
    completedRunReply,
    queuedRunReply,
  };
}

// ---------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken, password: "pbdv-a-v1" }, { as: null });
  SESSIONS.A = boot.j?.session_token ?? "";
  const whoA = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    { email: "pbdv-b@ioi.local", name: "Member B", role: "member", password: "pbdv-b-v1" },
    { as: "A" },
  );
  const principalB = created.j?.principal?.principal_id ?? "";
  await req(
    "POST",
    `/v1/hypervisor/principals/${principalB}/tenant-memberships`,
    {
      tenant_ref: OWNER,
      expected_revision: 0,
      idempotency_key: "pbdv-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req("POST", "/v1/hypervisor/auth/login", { email: "pbdv-b@ioi.local", password: "pbdv-b-v1" }, { as: null });
  SESSIONS.B = login.j?.session_token ?? "";
  const whoB = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "B" })).j || {};
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant, so a tenant check alone would isolate nothing and every isolation assertion below is about the PRINCIPAL",
    whoA.authenticated === true &&
      whoB.authenticated === true &&
      (whoA.principal?.tenant_refs || []).includes(OWNER) &&
      (whoB.principal?.tenant_refs || []).includes(OWNER) &&
      whoA.principal?.principal_ref !== whoB.principal?.principal_ref,
    `A=${whoA.principal?.principal_ref} B=${whoB.principal?.principal_ref}`,
  );

  // HEADLESS AUTH FOR THE CROSS-PATH MATRIX. The CLI and MCP shims cannot carry a browser cookie, so
  // each principal mints a `pat_*` API token through the daemon's OWN route. The token IS the
  // principal binding — a client holds it and asserts nothing — which is what lets SDK/CLI/MCP reach
  // the owner route without a second auth plane.
  const patA = await req(
    "POST",
    "/v1/hypervisor/api-tokens",
    { description: "pbdv cross-path matrix — principal A", validFor: 3600 },
    { as: "A" },
  );
  PAT.A = patA.j?.token?.value ?? "";
  const patB = await req(
    "POST",
    "/v1/hypervisor/api-tokens",
    { description: "pbdv cross-path matrix — principal B", validFor: 3600 },
    { as: "B" },
  );
  PAT.B = patB.j?.token?.value ?? "";
  ok(
    "PRECONDITION: each principal minted a headless API token through the daemon's own api-tokens route, so the SDK/CLI/MCP paths authenticate by a token that IS the principal binding rather than by a cookie or an asserted principal",
    /^ioi_pat_[0-9a-f]/u.test(PAT.A) && /^ioi_pat_[0-9a-f]/u.test(PAT.B) && PAT.A !== PAT.B,
    `A=${PAT.A.slice(0, 16)}… B=${PAT.B.slice(0, 16)}…`,
  );

  const owners = await seedOwners();
  ok(
    "PRECONDITION: every owner seam this unit binds has a real admitted revision — an ontology (M05.1), two connector mappings, a redaction recipe and two transformation runs (M05.7), a route contract (M07.2), two source-rights claims and two boundary profiles (M10.3), and a Governance approval",
    owners.ONT.endsWith("/revision/1") &&
      owners.liveMap.revision_ref === "mapping://acme.intake-form/revision/1" &&
      owners.deadMap.registry_status === "deprecated" &&
      owners.recipe.revision_ref === "data-recipe://acme.intake-redact/revision/1" &&
      /^transform:\/\/trun_[0-9a-f]{32}$/u.test(owners.completedRun.transformation_run_id ?? "") &&
      owners.queuedRun.execution_status === "queued" &&
      owners.route.revision_ref === "model-route-rights://acme.primary-inference/revision/1" &&
      owners.liveClaim.revision_ref === "learning-source-rights://acme.intake-records/revision/1" &&
      owners.liveProfile.revision_ref === "learning-boundary://acme.organization-default/revision/1" &&
      String(owners.approval.ref || "").startsWith("approval-request://"),
    `ont=${owners.ONT} map=${owners.liveMap.revision_ref} run=${owners.completedRun.transformation_run_id} ` +
      `run_status=${owners.completedRunReply.status}/${code(owners.completedRunReply.j)} ` +
      `queued_status=${owners.queuedRunReply.status}/${code(owners.queuedRunReply.j)} approval=${owners.approval.ref}`,
  );
  ok(
    "PRECONDITION: the bound source set is three REAL admitted revisions across two owner modules, each carrying the content hash its own owner served — a fixture of well-formed strings would exercise only the refusal path and never reach a grant",
    SOURCE_ROWS.length === 3 &&
      SOURCE_ROWS.every((r) => String(r.source_content_hash || "").startsWith("sha256:")) &&
      SOURCE_ROWS.some((r) => r.source_revision_ref.startsWith("ontology://")) &&
      SOURCE_ROWS.some((r) => r.source_revision_ref.startsWith("mapping://")) &&
      SOURCE_ROWS.some((r) => r.source_revision_ref.startsWith("transform://")),
    SOURCE_ROWS.map((r) => r.source_revision_ref).join(" "),
  );

  const base = (over = {}) => ({
    purpose_binding_ref: owners.approval.ref,
    ontology_revision_refs: [owners.ONT],
    connector_mapping_revision_refs: [owners.liveMap.revision_ref],
    source_rights_claim_revision_refs: [owners.liveClaim.revision_ref],
    route_rights_revision_refs: [owners.route.revision_ref],
    boundary_profile_revision_ref: owners.liveProfile.revision_ref,
    redaction: {
      recipe_revision_ref: owners.recipe.revision_ref,
      recipe_content_hash: owners.recipe.content_hash,
      techniques: ["field_suppression", "generalization"],
      findings: [],
      output_privacy_class: "restricted",
      creates_permission: false,
      severs_lineage: false,
      reidentification_risk_assessed: true,
    },
    ...over,
  });

  return { owners, base, principalA: whoA.principal?.principal_ref ?? "" };
}

// ------------------------------------------------------------------------------ admission clauses

async function runAdmission(state) {
  const { owners, base } = state;
  const view = await req("POST", VIEWS, viewBody("pbdv-view-1", base()));
  const record = view.j?.policy_bound_data_view ?? {};
  ok(
    "M05.8: a view is admitted as an IMMUTABLE OWNER-QUALIFIED REVISION in canon's own view:// scheme, with the predecessor's mutable policy-bound-data-view:// spelling named as the refused form in its own constants",
    view.status === 201 &&
      record.revision_ref === "view://acme.intake-minimised/revision/1" &&
      record.policy_bound_data_view_id === "view://acme.intake-minimised" &&
      record.constants?.refused_legacy_view_scheme === "policy-bound-data-view://" &&
      record.constants?.lifecycle_id === "policy_bound_data_view_registry_lifecycle.v2",
    `status ${view.status} ${record.revision_ref} :: ${code(view.j)}`,
  );
  const commitment = registeredCommitment(record);
  ok(
    "M05.8: the view's content hash is INDEPENDENTLY reproducible from the registered invariant profile's own material fields — the daemon does not get to define its own commitment",
    commitment.digest === record.content_hash,
    `${commitment.fields} committed fields :: ${record.content_hash}`,
  );
  ok(
    "M05.8: THE PERMISSION IS A SUBTRACTION — the bound purpose `evaluation` supports read/transform/evaluate and nothing else, `allowed_uses` equals the rights-derived set exactly, and `redaction_derived_allowed_uses` is emitted EMPTY so no use can enter by way of a transformation",
    canonicalJson(record.allowed_uses) === canonicalJson(["read", "transform", "evaluate"]) &&
      canonicalJson(record.rights_derived_allowed_uses) === canonicalJson(record.allowed_uses) &&
      canonicalJson(record.redaction_derived_allowed_uses) === "[]",
    `allowed ${canonicalJson(record.allowed_uses)}`,
  );
  ok(
    "M05.8: every denied use is ATTRIBUTED to the input that denied it, so an operator learns WHICH resolved input removed a use rather than only that the set is smaller than the vocabulary",
    (view.j?.denied_uses || []).length === 5 &&
      (view.j?.denied_uses || []).every((row) => row.use && row.denied_by && row.governing_ref && row.reason) &&
      (view.j?.denied_uses || []).some((row) => row.use === "train" && row.denied_by === "bound_purpose"),
    `${(view.j?.denied_uses || []).length} attributed denials`,
  );
  // The body deliberately tries to name a DIFFERENT principal. The record must carry the
  // authenticated one, which is the whole difference between `server_resolved` as a pin and
  // `server_resolved` as a label sitting beside whatever the caller typed.
  const impersonating = await req(
    "POST",
    VIEWS,
    viewBody("pbdv-view-impersonate", base({ family: "acme.impersonate", resolved_principal_ref: "worker://someone-else" })),
  );
  ok(
    "INV-37: the principal is RESOLVED from the authenticated request — a body naming a different principal is refused by name, and the admitted record carries this caller's own resolved ref beside the server_resolved pin",
    impersonating.status === 422 &&
      code(impersonating.j) === "policy_bound_data_view_caller_authored_evidence_refused" &&
      record.principal_resolution === "server_resolved" &&
      record.resolved_principal_ref === state.principalA &&
      String(record.resolved_principal_ref || "").startsWith("user://"),
    `refused ${code(impersonating.j)} :: ${record.principal_resolution} / ${record.resolved_principal_ref}`,
  );
  ok(
    "M05.8: the effective learning-boundary binding is SERVER-RESOLVED from one resolution of M10.3's profile, so the compiled-policy hash the view was bound under and the hash it requires of a materialization cannot be moved independently",
    record.effective_boundary_binding?.effective_learning_boundary_hash ===
      record.materialization_precondition?.required_effective_learning_boundary_hash &&
      record.effective_boundary_binding?.boundary_profile_content_hash === owners.liveProfile.content_hash &&
      record.effective_boundary_binding?.boundary_status_at_binding === "active",
    `${record.effective_boundary_binding?.effective_learning_boundary_hash}`,
  );
  ok(
    "M05.8: the precondition names ONLY the EIGHT facts this build rechecks — including `consent_state`, which is resolved through the covering LearningSourceRightsClaim rather than trusted from the caller",
    canonicalJson(record.materialization_precondition?.revalidated_facts) ===
      canonicalJson([
        "current_authority",
        "current_rights",
        "revocation_state",
        "expiry",
        "retention_and_hold",
        "residency",
        "destination_class",
        "consent_state",
      ]) && record.materialization_precondition?.fails_closed_on_missing_or_conflicting_policy === true,
    canonicalJson(record.materialization_precondition?.revalidated_facts),
  );
  ok(
    "M05.8: the admission record carries the registered seven explicit NONCLAIMS and invents no `unenforced_preconditions` or provider-connection stand-in — every fact it claims to revalidate has an owner seam",
    canonicalJson(record.does_not_assert) ===
      canonicalJson([
        "authority",
        "consent",
        "redaction_creates_permission",
        "declassification",
        "source_rights",
        "semantic_truth",
        "cross_tenant_reuse",
      ]) &&
      !Object.hasOwn(record, "unenforced_preconditions") &&
      !canonicalJson(record).includes("provider_connection_state"),
    canonicalJson(record.does_not_assert),
  );

  const authored = await req("POST", VIEWS, viewBody("pbdv-view-authored", base({ allowed_uses: ["train"] })));
  ok(
    "INV-37: a caller that AUTHORS the permission its own admission checks is refused BY NAME, rather than having its value quietly overwritten",
    authored.status === 422 && code(authored.j) === "policy_bound_data_view_caller_authored_evidence_refused",
    `status ${authored.status} code ${code(authored.j)}`,
  );
  const crossTenant = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-cross-tenant",
      base({
        family: "acme.cross-tenant",
        source_bindings: [
          {
            source_ref: "dataset://other/rows",
            source_revision_ref: "dataset://other/rows/revision/1",
            source_content_hash: `sha256:${"88".repeat(32)}`,
            source_tenant_ref: "tenant://other-org",
            source_owner_ref: "org://other-org",
            source_class: "customer",
          },
        ],
      }),
    ),
  );
  ok(
    "M05.8: a source belonging to ANOTHER TENANT is inadmissible at admission and named as such — a discovery at materialization would come after the protected bytes were already moving",
    crossTenant.status === 422 && code(crossTenant.j) === "policy_bound_data_view_cross_tenant_source_refused",
    `status ${crossTenant.status} code ${code(crossTenant.j)}`,
  );
  const excessField = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-excess-field",
      base({ family: "acme.excess-field", allowed_field_refs: ["field://acme/intake/intake_id", "field://acme/intake/ssn"] }),
    ),
  );
  ok(
    "M05.8: a field allowed WITHOUT its own minimization decision is refused by name — minimization stops being a claim the record makes about itself and becomes a property checkable one field at a time",
    excessField.status === 422 && code(excessField.j) === "policy_bound_data_view_excess_field_without_a_decision",
    `status ${excessField.status} code ${code(excessField.j)}`,
  );
  const staleConsent = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-stale-consent",
      base({
        family: "acme.stale-consent",
        consent_bindings: [
          {
            consent_ref: "grant://acme-clinic/withdrawn/v1",
            consent_state: "revoked",
            consent_subject_ref: OWNER,
            valid_until: null,
          },
        ],
      }),
    ),
  );
  ok(
    "M05.8: a view carrying an EXPIRED, REVOKED, WITHDRAWN or UNKNOWN consent cannot be admitted at all — the non-active states exist so a state can be recorded on the way to a successor, never so a live projection can carry one",
    staleConsent.status === 422 && code(staleConsent.j) === "policy_bound_data_view_consent_binding_not_active",
    `status ${staleConsent.status} code ${code(staleConsent.j)}`,
  );
  const declassify = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-declassify",
      base({
        family: "acme.declassify",
        redaction: { ...base().redaction, output_privacy_class: "internal" },
      }),
    ),
  );
  ok(
    "M05.8: redaction that LOWERS the privacy class is refused by name — reclassification is a governed act with its own approval, rights and receipts, never a side effect of masking a column",
    declassify.status === 422 && code(declassify.j) === "policy_bound_data_view_redaction_declassifies",
    `status ${declassify.status} code ${code(declassify.j)}`,
  );
  const redactionPermission = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-redaction-permission",
      base({ family: "acme.redaction-permission", redaction: { ...base().redaction, creates_permission: true } }),
    ),
  );
  ok(
    "M05.8: a redaction that CLAIMS IT CREATES PERMISSION is refused rather than silently corrected — a repaired claim is a claim that was made and not recorded",
    redactionPermission.status === 422 &&
      code(redactionPermission.j) === "policy_bound_data_view_redaction_claims_permission_or_severed_lineage",
    `status ${redactionPermission.status} code ${code(redactionPermission.j)}`,
  );
  const substitutedRecipe = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-recipe-substituted",
      base({
        family: "acme.recipe-substituted",
        redaction: { ...base().redaction, recipe_content_hash: `sha256:${"bb".repeat(32)}` },
      }),
    ),
  );
  ok(
    "M05.8: a redaction recipe whose committed bytes disagree with what the view commits is refused through M05.7's OWNER SEAM — an unreproducible transformation cannot carry a reproducible-looking record",
    substitutedRecipe.status === 422 && code(substitutedRecipe.j) === "policy_bound_data_view_redaction_recipe_substituted",
    `status ${substitutedRecipe.status} code ${code(substitutedRecipe.j)}`,
  );
  const opaqueRecipe = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-recipe-opaque",
      base({
        family: "acme.recipe-opaque",
        redaction: { ...base().redaction, recipe_revision_ref: "policy://acme/redaction/v1" },
      }),
    ),
  );
  ok(
    "M05.8: an OPAQUE redaction recipe ref is refused with no fallback path — a recipe nobody can resolve names a transformation nobody can reproduce",
    opaqueRecipe.status === 422 && code(opaqueRecipe.j) === "policy_bound_data_view_redaction_recipe_not_owner_resolvable",
    `status ${opaqueRecipe.status} code ${code(opaqueRecipe.j)}`,
  );
  const labelPurpose = await req(
    "POST",
    VIEWS,
    viewBody("pbdv-view-purpose-label", base({ family: "acme.purpose-label", purpose_binding_ref: "because we need it" })),
  );
  ok(
    "M05.8: a purpose bound by a free-text LABEL is refused — the binding must name a Governance-owned decision its own resolver can open, because a purpose nobody can check narrows nothing",
    labelPurpose.status === 422 && code(labelPurpose.j) === "policy_bound_data_view_purpose_binding_not_owner_resolvable",
    `status ${labelPurpose.status} code ${code(labelPurpose.j)}`,
  );
  const ontologyHead = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-ontology-head",
      base({ family: "acme.ontology-head", ontology_revision_refs: ["ontology://acme-clinic/patient-intake"] }),
    ),
  );
  ok(
    "M05.8: a view naming an ontology FAMILY HEAD is refused BY M05.1's own seam — this module resolves exact revisions rather than shape-checking them, so a view cannot project whatever the ontology becomes",
    ontologyHead.status === 422 && code(ontologyHead.j) === "ontology_version_identity_not_canonical",
    `status ${ontologyHead.status} code ${code(ontologyHead.j)}`,
  );
  const mappingHead = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-mapping-head",
      base({ family: "acme.mapping-head", connector_mapping_revision_refs: ["mapping://acme.intake-form"] }),
    ),
  );
  ok(
    "M05.8: a view naming a mapping FAMILY HEAD is refused BY M05.7's own seam, so the shape the view claims to scope cannot change underneath it without the view changing",
    mappingHead.status === 422 && code(mappingHead.j) === "connector_mapping_revision_ref_not_exact",
    `status ${mappingHead.status} code ${code(mappingHead.j)}`,
  );
  const stalePolicy = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-stale-policy",
      base({ family: "acme.stale-policy", expected_effective_learning_boundary_hash: `sha256:${"cc".repeat(32)}` }),
    ),
  );
  ok(
    "M05.8: a caller may ASSERT which compiled policy it believes it is binding and is refused by name when the boundary has moved — it may never AUTHOR the hash, which is what makes the assertion a check rather than a value",
    stalePolicy.status === 422 && code(stalePolicy.j) === "policy_bound_data_view_stale_policy_binding",
    `status ${stalePolicy.status} code ${code(stalePolicy.j)}`,
  );
  const noReason = await req(
    "POST",
    VIEWS,
    viewBody("pbdv-view-successor-no-reason", base({ expected_head: view.j?.expected_head_for_successor })),
  );
  ok(
    "M05.8: a SUCCESSOR revision must name why it exists, from the contract's closed reason vocabulary — a restatement with no reason is a lineage nobody can review",
    noReason.status === 422 && code(noReason.j) === "policy_bound_data_view_succession_reason_required",
    `status ${noReason.status} code ${code(noReason.j)}`,
  );
  const unownedScheme = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-unowned-source",
      base({
        family: "acme.unowned-source",
        source_bindings: [
          {
            source_ref: "dataset://acme/intake-rows",
            source_revision_ref: "dataset://acme/intake-rows/revision/3",
            source_content_hash: `sha256:${"88".repeat(32)}`,
            source_tenant_ref: TENANT,
            source_owner_ref: OWNER,
            source_class: "customer",
          },
        ],
      }),
    ),
  );
  ok(
    "M05.8: a source whose SCHEME HAS NO REGISTERED OWNER SEAM is refused by name — an accepted free-form source ref is silence, and silence about a protected source is inadmissible. This is also the fence that stops M05.9's dataset families from being invented in here",
    unownedScheme.status === 422 &&
      code(unownedScheme.j) === "policy_bound_data_view_source_scheme_has_no_owner_seam",
    `status ${unownedScheme.status} code ${code(unownedScheme.j)}`,
  );
  const movedHash = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-moved-hash",
      base({
        family: "acme.moved-hash",
        source_bindings: [{ ...SOURCE_ROWS[0], source_content_hash: `sha256:${"11".repeat(32)}` }],
      }),
    ),
  );
  ok(
    "M05.8: a source whose committed hash is NOT what its owner currently serves is refused — a ref names a location that may since have been re-admitted, and the hash is what names what was actually bound",
    movedHash.status === 422 &&
      code(movedHash.j) === "policy_bound_data_view_source_content_hash_moved",
    `status ${movedHash.status} code ${code(movedHash.j)}`,
  );
  const incompleteRun = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-queued-run",
      base({
        family: "acme.queued-run",
        source_bindings: [
          {
            source_ref: owners.queuedRun.transformation_run_id,
            source_revision_ref: owners.queuedRun.transformation_run_id,
            source_content_hash: owners.queuedRun.content_hash,
            source_tenant_ref: TENANT,
            source_owner_ref: OWNER,
            source_class: "machine_generated",
          },
        ],
      }),
    ),
  );
  ok(
    "M05.8: a TRANSFORMATION RUN that did not complete is refused as a source through M05.7's new owner seam — a run that produced nothing is not a source a projection can be over",
    incompleteRun.status === 422 &&
      code(incompleteRun.j) === "policy_bound_data_view_source_run_not_completed",
    `status ${incompleteRun.status} code ${code(incompleteRun.j)}`,
  );
  const uncoveredConsent = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-uncovered-consent",
      base({
        family: "acme.uncovered-consent",
        consent_bindings: [
          {
            consent_ref: "grant://acme-clinic/external-subject-consent/v9",
            consent_state: "active",
            consent_subject_ref: OWNER,
            valid_until: null,
          },
        ],
      }),
    ),
  );
  ok(
    "M05.8: a consent that is NOT a rights basis on any bound claim is refused — canon mints no consent family, so a consent nothing can revalidate is refused rather than trusted from the `consent_state` the caller attested",
    uncoveredConsent.status === 422 &&
      code(uncoveredConsent.j) === "policy_bound_data_view_consent_not_covered_by_a_bound_claim",
    `status ${uncoveredConsent.status} code ${code(uncoveredConsent.j)}`,
  );
  const uncoveredDestination = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-uncovered-destination",
      base({
        family: "acme.uncovered-destination",
        destination_and_egress: {
          permitted_destination_classes: ["in_boundary_only", "external_processor"],
          egress_ceiling: "redacted_only",
          permitted_region_refs: ["region://us-west"],
          cross_tenant_read_permitted: false,
          declassification_permitted_without_approval: false,
        },
      }),
    ),
  );
  ok(
    "M05.8: a BROKERED destination no bound route contract admits is refused by name — this module models no provider connection and mints no stand-in for one; the route-rights ceiling is the coverage it can resolve, and the refusal is the correct output",
    uncoveredDestination.status === 422 &&
      code(uncoveredDestination.j) ===
        "policy_bound_data_view_brokered_destination_without_admitted_authority",
    `status ${uncoveredDestination.status} code ${code(uncoveredDestination.j)}`,
  );
  const isolated = await req("GET", `${VIEWS}?family=acme.intake-minimised`, null, { as: "B" });
  ok(
    "M05.8: a SECOND REAL PRINCIPAL in the same tenant cannot read this view family — the isolation is about the principal, and a tenant check alone would have isolated nothing",
    isolated.status === 403,
    `status ${isolated.status}`,
  );

  return { ...state, view: record, viewRef: record.revision_ref };
}

// ------------------------------------------------------------------- materialization: the enforcement

async function runMaterialization(state) {
  const { owners, base, viewRef } = state;
  const read = (key, over = {}) =>
    req("POST", MATS, readBody(key, { family: `acme.${key}`, policy_bound_data_view_revision_ref: viewRef, ...over }));

  // THE POSITIVE CASE, AND IT GENUINELY GRANTS. Everything about this request conforms: the use is
  // allowed, the fields are in scope, the predicate matches by ref and bytes, the row ceiling holds,
  // the timebase and window are contained, the destination/representation/region/jurisdiction are
  // within the view's ceilings, and every owner-resolved input — sources, claims, routes, boundary,
  // mapping — is current at the read instant. The decision materializes a BOUNDED DESCRIPTOR.
  const conforming = await read("pbdv-read-conforming");
  const granted = conforming.j?.policy_bound_data_view_materialization?.granted_projection ?? null;
  ok(
    "M05.8: a fully conforming read MATERIALIZES — every one of the eight named facts was revalidated against its owner at the read instant, nothing denied it, and the decision is `materialized` with an empty refusal set",
    conforming.status === 201 &&
      decision(conforming) === "materialized" &&
      conforming.j?.materialized === true &&
      canonicalJson(refusals(conforming)) === "[]",
    `status ${conforming.status} decision ${decision(conforming)} codes ${canonicalJson(refusals(conforming))}`,
  );
  ok(
    "M05.8: the grant is a DESCRIPTOR, not a copy — it names the permitted fields, the committed row predicate and its ceiling, the timebase and window, and it pins `payload_bytes_included: false`; no protected byte is in the record",
    granted !== null &&
      canonicalJson(granted.granted_field_refs) === canonicalJson(["field://acme/intake/intake_id"]) &&
      granted.granted_field_count === 1 &&
      granted.row_predicate_hash === `sha256:${"aa".repeat(32)}` &&
      granted.max_row_count === 100 &&
      granted.timebase === "source_event_time" &&
      granted.payload_bytes_included === false &&
      !JSON.stringify(granted).includes("field://acme/intake/visit_date"),
    canonicalJson(granted),
  );
  ok(
    "M05.8: the grant is NARROWER than the view — the view allows two fields and a 50000-row ceiling, and the descriptor carries only the one field this read asked for under the lower of the two ceilings",
    granted?.granted_field_count === 1 &&
      (state.view?.field_scope?.allowed_field_count ?? 0) === 2 &&
      granted?.max_row_count < (state.view?.row_scope?.max_row_count ?? 0),
    `granted ${granted?.granted_field_count}/${state.view?.field_scope?.allowed_field_count} fields, ${granted?.max_row_count}/${state.view?.row_scope?.max_row_count} rows`,
  );
  ok(
    "M05.8: the decision is durable EVIDENCE — admitted to the chain with its own commitment, its per-fact revalidation findings, and the owner that answered each one",
    String(conforming.j?.policy_bound_data_view_materialization?.materialization_ref || "").startsWith("materialization://") &&
      String(conforming.j?.policy_bound_data_view_materialization?.content_hash || "").startsWith("sha256:") &&
      (conforming.j?.policy_bound_data_view_materialization?.revalidation_findings || []).length > 5 &&
      (conforming.j?.policy_bound_data_view_materialization?.revalidation_findings || []).some(
        (f) => f.fact === "consent_state" && f.outcome === "covered_by_a_live_claim",
      ),
    `${conforming.j?.policy_bound_data_view_materialization?.materialization_ref}`,
  );
  ok(
    "M05.8: ALL EIGHT named facts are claimed as revalidated, `consent_state` among them — a consent is a rights basis on a claim, so the claim's own liveness and window are what recheck it",
    canonicalJson(conforming.j?.policy_bound_data_view_materialization?.revalidated_facts) ===
      canonicalJson(REVALIDATED_FACTS),
    canonicalJson(conforming.j?.policy_bound_data_view_materialization?.revalidated_facts),
  );
  ok(
    "M05.8: the decision asserts no provider-connection fact and says so — `ProviderConnectionBinding` is wallet.network's and outside this contract's closed vocabulary, so a brokered destination is covered by a live route contract or refused, never by a stand-in modelled here",
    (conforming.j?.policy_bound_data_view_materialization?.does_not_assert || []).includes("materialized_payload_custody") &&
      (conforming.j?.policy_bound_data_view_materialization?.does_not_assert || []).includes("provider_connection_state") &&
      !canonicalJson(conforming.j?.policy_bound_data_view_materialization).includes("connection_epoch"),
    canonicalJson(conforming.j?.policy_bound_data_view_materialization?.does_not_assert),
  );

  // ---------------------------------------------------- every negative denies the read by its name
  const excessField = await read("pbdv-read-excess-field", {
    requested_field_refs: ["field://acme/intake/intake_id", "field://acme/intake/ssn"],
  });
  ok(
    "M05.8: an OUT-OF-SCOPE FIELD is refused at read time rather than silently trimmed — a quietly narrowed answer is indistinguishable from a permitted one",
    hasCode(excessField, "_excess_field") && decision(excessField) === "refused",
    canonicalJson(refusals(excessField)),
  );
  const wrongUse = await read("pbdv-read-wrong-use", { requested_use: "train" });
  ok(
    "M05.8: a use OUTSIDE the view's permitted set refuses — the set is itself the vocabulary minus every denial its resolved inputs contributed, so this is the subtraction being enforced at the read",
    hasCode(wrongUse, "_use_not_allowed"),
    canonicalJson(refusals(wrongUse)),
  );
  const excessRows = await read("pbdv-read-excess-rows", { requested_max_row_count: 999999 });
  ok(
    "M05.8: a read asking for MORE ROWS than the view's committed ceiling refuses",
    hasCode(excessRows, "_excess_rows"),
    canonicalJson(refusals(excessRows)),
  );
  const substitutedPredicate = await read("pbdv-read-predicate", {
    requested_row_predicate_hash: `sha256:${"ff".repeat(32)}`,
  });
  ok(
    "M05.8: a row predicate named at DIFFERENT BYTES refuses — a predicate editable after admission is a scope that widens silently",
    hasCode(substitutedPredicate, "_row_predicate_substituted"),
    canonicalJson(refusals(substitutedPredicate)),
  );
  const wrongTimebase = await read("pbdv-read-timebase", { requested_timebase: "ingest_time" });
  ok(
    "M05.8: a read on the WRONG CLOCK refuses — event time and ingest time disagree, and a range read on the wrong one silently widens or narrows the projection",
    hasCode(wrongTimebase, "_timebase_mismatch"),
    canonicalJson(refusals(wrongTimebase)),
  );
  const outsideWindow = await read("pbdv-read-window", { requested_until: "2027-01-01T00:00:00Z" });
  ok(
    "M05.8: a window reaching OUTSIDE the view's committed time scope refuses — a view over all of history is not minimized no matter how few fields it names",
    hasCode(outsideWindow, "_time_window_outside_scope"),
    canonicalJson(refusals(outsideWindow)),
  );
  const wrongDestination = await read("pbdv-read-destination", { requested_destination_class: "public_export" });
  ok(
    "M05.8: a destination class OUTSIDE the view's ceiling refuses — a materialization may carry less than the ceiling permits and never more",
    hasCode(wrongDestination, "_destination_class_refused"),
    canonicalJson(refusals(wrongDestination)),
  );
  const wrongRepresentation = await read("pbdv-read-representation", { requested_representation: "synthetic" });
  ok(
    "M05.8: the egress ceilings are a TABLE, NOT AN ORDERING — `synthetic` is refused under `redacted_only` rather than admitted as a near neighbour",
    hasCode(wrongRepresentation, "_egress_ceiling_exceeded"),
    canonicalJson(refusals(wrongRepresentation)),
  );
  const declassifying = await read("pbdv-read-declassify", {
    requested_representation: "protected_plaintext",
  });
  ok(
    "M05.8: moving DECLASSIFIED or protected-plaintext material without its own approval refuses — the view pins that it is never the approval",
    hasCode(declassifying, "_declassification_refused"),
    canonicalJson(refusals(declassifying)),
  );
  const wrongRegion = await read("pbdv-read-region", { requested_region_ref: "region://eu-west" });
  ok(
    "M05.8: a region outside BOTH the permitted destination regions and the declared residency refuses — they are separate axes, and conflating them is how a compliant-looking view permits a move neither would allow",
    hasCode(wrongRegion, "_residency_refused"),
    canonicalJson(refusals(wrongRegion)),
  );
  const wrongJurisdiction = await read("pbdv-read-jurisdiction", { requested_jurisdiction_ref: "jurisdiction://eu" });
  ok(
    "M05.8: a jurisdiction this projection never declared refuses — an unstated jurisdiction is not an absent obligation",
    hasCode(wrongJurisdiction, "_jurisdiction_refused"),
    canonicalJson(refusals(wrongJurisdiction)),
  );
  const foreignSource = await read("pbdv-read-foreign-source", {
    observed_source_revisions: [
      {
        source_ref: "dataset://acme/other-rows",
        source_revision_ref: "dataset://acme/other-rows/revision/1",
        source_content_hash: `sha256:${"99".repeat(32)}`,
      },
    ],
  });
  ok(
    "M05.8: a read naming a source OUTSIDE the bound set refuses, and a bound source ABSENT from the observed set refuses too — containment is exact in both directions, and it is named as containment because neither side was resolved against a source-revision owner",
    hasCode(foreignSource, "_source_outside_the_bound_set") &&
      hasCode(foreignSource, "_bound_source_absent_from_the_observed_set"),
    canonicalJson(refusals(foreignSource)),
  );

  const authoredDecision = await read("pbdv-read-authored", { decision: "materialized" });
  ok(
    "INV-37: a caller that AUTHORS the decision or the projection its own read would be granted is refused by name — a decision taken over self-supplied constants is void for conformance purposes",
    authoredDecision.status === 422 &&
      code(authoredDecision.j) === "policy_bound_data_view_materialization_caller_authored_evidence_refused",
    `status ${authoredDecision.status} code ${code(authoredDecision.j)}`,
  );

  // ------------------------------------------------ windows that closed BETWEEN admission and read
  const lapsedConsentView = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-lapsing-consent",
      base({
        family: "acme.lapsing-consent",
        // The consent rides on the LAPSING claim, whose validity window closes between admission and
        // the read. Nothing about the consent binding itself changes — which is the point: the only
        // thing that can revalidate it is the claim that carries it as a rights basis.
        source_rights_claim_revision_refs: [owners.lapsingClaim.revision_ref],
      }),
    ),
  );
  const lapsedConsentRead = await req(
    "POST",
    MATS,
    readBody("pbdv-read-lapsed-consent", {
      family: "acme.lapsed-consent-read",
      policy_bound_data_view_revision_ref: lapsedConsentView.j?.policy_bound_data_view?.revision_ref,
    }),
  );
  ok(
    "M05.8: a consent whose covering claim's validity window closed before the read is denied AT READ TIME by name — the consent rides on the claim, so the claim's own window is the consent's",
    lapsedConsentView.status === 201 && hasCode(lapsedConsentRead, "_consent_not_current"),
    `admitted ${lapsedConsentView.status} :: ${canonicalJson(refusals(lapsedConsentRead))}`,
  );

  const lapsedClaimView = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-lapsing-claim",
      base({
        family: "acme.lapsing-claim",
        source_rights_claim_revision_refs: [owners.lapsingClaim.revision_ref],
      }),
    ),
  );
  const lapsedClaimRead = await req(
    "POST",
    MATS,
    readBody("pbdv-read-lapsed-claim", {
      family: "acme.lapsed-claim-read",
      policy_bound_data_view_revision_ref: lapsedClaimView.j?.policy_bound_data_view?.revision_ref,
    }),
  );
  ok(
    "M05.8: a source-rights claim that is still `admitted` and carries every permission in its own bytes, but whose validity window closed before the read, is re-resolved through M10.3's seam and denied `source_right_expired`",
    lapsedClaimView.status === 201 && hasCode(lapsedClaimRead, "_source_right_expired"),
    `admitted ${lapsedClaimView.status} :: ${canonicalJson(refusals(lapsedClaimRead))}`,
  );

  const lapsedPolicyView = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-lapsing-policy",
      base({ family: "acme.lapsing-policy-view", boundary_profile_revision_ref: owners.lapsingProfile.revision_ref }),
    ),
  );
  const lapsedPolicyRead = await req(
    "POST",
    MATS,
    readBody("pbdv-read-lapsed-policy", {
      family: "acme.lapsed-policy-read",
      policy_bound_data_view_revision_ref: lapsedPolicyView.j?.policy_bound_data_view?.revision_ref,
    }),
  );
  ok(
    "M05.8: a compiled boundary whose own effective window closed before the read is STALE POLICY at the read — the view still names a live-looking revision, and only a read-time recheck against that instant finds it",
    lapsedPolicyView.status === 201 && hasCode(lapsedPolicyRead, "_stale_policy_binding"),
    `admitted ${lapsedPolicyView.status} :: ${canonicalJson(refusals(lapsedPolicyRead))}`,
  );

  const deprecatedMappingView = await req(
    "POST",
    VIEWS,
    viewBody(
      "pbdv-view-deprecated-mapping",
      base({ family: "acme.deprecated-mapping", connector_mapping_revision_refs: [owners.deadMap.revision_ref] }),
    ),
  );
  const deprecatedMappingRead = await req(
    "POST",
    MATS,
    readBody("pbdv-read-deprecated-mapping", {
      family: "acme.deprecated-mapping-read",
      policy_bound_data_view_revision_ref: deprecatedMappingView.j?.policy_bound_data_view?.revision_ref,
    }),
  );
  ok(
    "M05.8: a mapping that is no longer active blocks the READ rather than unmaking the admitted view — `reinterprets_predecessor` is pinned false, so a later narrowing stops future materialization and leaves the historical record exactly as admitted. This is a MAPPING fact and is named as one; it is not evidence about a provider connection",
    deprecatedMappingView.status === 201 && hasCode(deprecatedMappingRead, "_connector_mapping_not_active"),
    `admitted ${deprecatedMappingView.status} :: ${canonicalJson(refusals(deprecatedMappingRead))}`,
  );

  const isolatedRead = await req(
    "POST",
    MATS,
    readBody("pbdv-read-isolated", { family: "acme.isolated-read", policy_bound_data_view_revision_ref: viewRef }),
    { as: "B" },
  );
  ok(
    "M05.8: a second real principal cannot materialize against another principal's view — the read is refused at the OWNER SEAM before any policy is evaluated, not resolved first and compared afterwards",
    isolatedRead.status === 403,
    `status ${isolatedRead.status} code ${code(isolatedRead.j)}`,
  );

  const replay = await read("pbdv-read-conforming");
  ok(
    "M05.8: a retried read with the SAME key resolves to the decision it already took rather than taking a second one against a moved world",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.policy_bound_data_view_materialization?.materialization_ref ===
        conforming.j?.policy_bound_data_view_materialization?.materialization_ref,
    `status ${replay.status} replayed ${replay.j?.replayed}`,
  );

  return { ...state, conforming };
}

// ============================================== cross-path matrix: native · sdk · cli · mcp

// Give each path its own idempotency key (and, where the family names the record, its own family) so
// every path INDEPENDENTLY reaches the daemon's decision rather than replaying the first path's.
function perPath(body, pathName, { family = true } = {}) {
  const clone = JSON.parse(JSON.stringify(body ?? {}));
  if (clone.idempotency_key) clone.idempotency_key = `${clone.idempotency_key}:${pathName}`;
  if (family && clone.family) clone.family = `${clone.family}-${pathName}`;
  return clone;
}

async function runCrossPath(state) {
  const { owners, base, viewRef } = state;

  // Two dedicated views for the read-time negative classes, admitted once through the native path.
  const lapsedConsentView = await req(
    "POST",
    VIEWS,
    viewBody("xpath-lapsed-consent-view", base({
      family: "acme.xpath-lapsed-consent",
      source_rights_claim_revision_refs: [owners.lapsingClaim.revision_ref],
    })),
  );
  const lapsedConsentRef = lapsedConsentView.j?.policy_bound_data_view?.revision_ref;
  const deprecatedMappingView = await req(
    "POST",
    VIEWS,
    viewBody("xpath-deprecated-mapping-view", base({
      family: "acme.xpath-deprecated-mapping",
      connector_mapping_revision_refs: [owners.deadMap.revision_ref],
    })),
  );
  const deprecatedMappingRef = deprecatedMappingView.j?.policy_bound_data_view?.revision_ref;
  ok(
    "CROSS-PATH SETUP: the read-time negative views (a lapsed-consent view and a deprecated-mapping view) admitted through the native path, ready to be materialized through all four",
    lapsedConsentView.status === 201 &&
      deprecatedMappingView.status === 201 &&
      typeof lapsedConsentRef === "string" &&
      typeof deprecatedMappingRef === "string",
    `${lapsedConsentRef} ${deprecatedMappingRef}`,
  );

  // The core equivalence assertion. `bodyFor(pathName)` builds the per-path request; every AVAILABLE
  // path must return the SAME refusal code, none may materialize, and native must always run.
  async function equiv(label, kind, expectSuffix, bodyFor, queryFor) {
    const cells = [];
    for (const pathName of PATHS) {
      const input =
        kind === "query"
          ? queryFor(pathName)
          : { body: bodyFor(pathName) };
      const r = await callPath(pathName, kind, input, PAT.A);
      cells.push({
        path: pathName,
        available: r.available,
        status: r.status,
        code: r.available === false ? "" : bodyRefusalCode(r.body),
        codes: r.available === false ? [] : bodyRefusalCodes(r.body),
        materialized: r.available === false ? false : bodyMaterialized(r.body),
      });
    }
    const live = cells.filter((c) => c.available !== false);
    const nativeCell = cells.find((c) => c.path === "native");
    const codesMatch = live.every((c) => c.codes.some((held) => held.endsWith(expectSuffix)));
    const oneCode = new Set(live.map((c) => canonicalJson(c.codes))).size === 1;
    const noneMaterialized = live.every((c) => !c.materialized);
    ok(
      `CROSS-PATH ${label}: every available surface returns the SAME refusal set containing …${expectSuffix}, no surface materializes, and native always runs — the decision is the daemon's, identical across transports`,
      nativeCell &&
        nativeCell.available !== false &&
        nativeCell.codes.some((held) => held.endsWith(expectSuffix)) &&
        codesMatch &&
        oneCode &&
        noneMaterialized,
      pathSummary(cells),
    );
    return cells;
  }

  // ---- admission negatives (the request is refused before any decision is committed) ----
  await equiv("cross-tenant source", "admit", "_cross_tenant_source_refused", (p) =>
    perPath(
      viewBody("xpath-cross-tenant", base({
        family: "acme.xpath-cross-tenant",
        source_bindings: [
          {
            source_ref: "dataset://acme/intake-rows",
            source_revision_ref: "dataset://acme/intake-rows/revision/3",
            source_content_hash: `sha256:${"88".repeat(32)}`,
            source_tenant_ref: "tenant://other-org",
            source_owner_ref: "org://other-org",
            source_class: "customer",
          },
        ],
      })),
      p,
    ),
  );
  await equiv("excess field", "admit", "_excess_field_without_a_decision", (p) =>
    perPath(
      viewBody("xpath-excess-field", base({
        family: "acme.xpath-excess-field",
        allowed_field_refs: ["field://acme/intake/intake_id", "field://acme/intake/ssn"],
      })),
      p,
    ),
  );
  await equiv("stale policy", "admit", "_stale_policy_binding", (p) =>
    perPath(
      viewBody("xpath-stale-policy", base({
        family: "acme.xpath-stale-policy",
        expected_effective_learning_boundary_hash: `sha256:${"cc".repeat(32)}`,
      })),
      p,
    ),
  );
  await equiv("declassification", "admit", "_redaction_declassifies", (p) =>
    perPath(
      viewBody("xpath-declassify", base({
        family: "acme.xpath-declassify",
        redaction: { ...base().redaction, output_privacy_class: "internal" },
      })),
      p,
    ),
  );
  await equiv("redaction-as-permission", "admit", "_redaction_claims_permission_or_severed_lineage", (p) =>
    perPath(
      viewBody("xpath-redaction-permission", base({
        family: "acme.xpath-redaction-permission",
        redaction: { ...base().redaction, creates_permission: true },
      })),
      p,
    ),
  );
  await equiv("missing source", "admit", "_source_scheme_has_no_owner_seam", (p) =>
    perPath(
      viewBody("xpath-missing-source", base({
        family: "acme.xpath-missing-source",
        source_bindings: [
          {
            source_ref: "dataset://acme/intake-rows",
            source_revision_ref: "dataset://acme/intake-rows/revision/3",
            source_content_hash: `sha256:${"88".repeat(32)}`,
            source_tenant_ref: TENANT,
            source_owner_ref: OWNER,
            source_class: "customer",
          },
        ],
      })),
      p,
    ),
  );
  await equiv("destination without authority", "admit", "_brokered_destination_without_admitted_authority", (p) =>
    perPath(
      viewBody("xpath-destination", base({
        family: "acme.xpath-destination",
        destination_and_egress: {
          permitted_destination_classes: ["in_boundary_only", "external_processor"],
          egress_ceiling: "redacted_only",
          permitted_region_refs: ["region://us-west"],
          cross_tenant_read_permitted: false,
          declassification_permitted_without_approval: false,
        },
      })),
      p,
    ),
  );

  // ---- materialization negatives (the decision is committed as a refusal) ----
  await equiv("excess row", "materialize", "_excess_rows", (p) =>
    perPath(
      readBody("xpath-excess-rows", {
        family: "acme.xpath-excess-rows",
        policy_bound_data_view_revision_ref: viewRef,
        requested_max_row_count: 999999,
      }),
      p,
    ),
  );
  await equiv("residency", "materialize", "_residency_refused", (p) =>
    perPath(
      readBody("xpath-residency", {
        family: "acme.xpath-residency",
        policy_bound_data_view_revision_ref: viewRef,
        requested_region_ref: "region://eu-west",
      }),
      p,
    ),
  );
  await equiv("expired consent", "materialize", "_consent_not_current", (p) =>
    perPath(
      readBody("xpath-expired-consent", {
        family: "acme.xpath-expired-consent",
        policy_bound_data_view_revision_ref: lapsedConsentRef,
      }),
      p,
    ),
  );
  await equiv("revocation", "materialize", "_connector_mapping_not_active", (p) =>
    perPath(
      readBody("xpath-revocation", {
        family: "acme.xpath-revocation",
        policy_bound_data_view_revision_ref: deprecatedMappingRef,
      }),
      p,
    ),
  );

  // ---- the ONE positive: an identical bounded descriptor on every path ----
  const posCells = [];
  for (const pathName of PATHS) {
    const body = perPath(
      readBody("xpath-positive", {
        family: "acme.xpath-positive",
        policy_bound_data_view_revision_ref: viewRef,
      }),
      pathName,
    );
    const r = await callPath(pathName, "materialize", { body }, PAT.A);
    const mat = r.available === false ? null : r.body?.policy_bound_data_view_materialization;
    posCells.push({
      path: pathName,
      available: r.available,
      status: r.status,
      decision: mat?.decision,
      granted: mat?.granted_projection,
    });
  }
  const livePos = posCells.filter((c) => c.available !== false);
  const nativePos = posCells.find((c) => c.path === "native");
  const descriptorOf = (c) =>
    canonicalJson({
      fields: c.granted?.granted_field_refs,
      count: c.granted?.granted_field_count,
      rows: c.granted?.max_row_count,
      timebase: c.granted?.timebase,
      payload: c.granted?.payload_bytes_included,
    });
  ok(
    "CROSS-PATH positive: a conforming read MATERIALIZES on every available surface and returns the IDENTICAL bounded descriptor — one field, the committed ceiling, payload_bytes_included:false — proving no surface widens or narrows the grant",
    nativePos &&
      nativePos.decision === "materialized" &&
      nativePos.granted?.payload_bytes_included === false &&
      livePos.every((c) => c.decision === "materialized") &&
      livePos.every((c) => c.granted?.payload_bytes_included === false) &&
      new Set(livePos.map(descriptorOf)).size === 1,
    posCells.map((c) => `${c.path}:${c.available === false ? "unavailable" : c.decision}`).join(" "),
  );

  // ---- positive admit reaches the daemon on every path (distinct families, no cross-mint) ----
  const admitCells = [];
  for (const pathName of PATHS) {
    const body = perPath(
      viewBody(`xpath-admit-${pathName}`, base({ family: "acme.xpath-admit" })),
      pathName,
    );
    const r = await callPath(pathName, "admit", { body }, PAT.A);
    admitCells.push({
      path: pathName,
      available: r.available,
      status: r.status,
      ref: r.available === false ? "" : r.body?.policy_bound_data_view?.revision_ref ?? "",
    });
  }
  const liveAdmit = admitCells.filter((c) => c.available !== false);
  ok(
    "CROSS-PATH admit: every available surface admits its own view revision through the one owner route, each returning a real view:// revision ref — the mutation path works identically, not only the refusals",
    admitCells.find((c) => c.path === "native")?.status === 201 &&
      liveAdmit.every((c) => /^view:\/\//u.test(c.ref)),
    admitCells.map((c) => `${c.path}:${c.available === false ? "unavailable" : c.ref}`).join(" "),
  );

  // ---- authority: unauthenticated is 401, principal B is 403, on every path ----
  const unauthCells = [];
  for (const pathName of PATHS) {
    const r = await callPath(pathName, "query", { family: "acme.intake-minimised" }, "");
    unauthCells.push({ path: pathName, available: r.available, status: r.status });
  }
  const liveUnauth = unauthCells.filter((c) => c.available !== false);
  ok(
    "CROSS-PATH auth: an UNAUTHENTICATED call is refused 401 on every available surface — a client with no token asserts no principal and reaches no record",
    unauthCells.find((c) => c.path === "native")?.status === 401 &&
      liveUnauth.every((c) => c.status === 401),
    unauthCells.map((c) => `${c.path}:${c.available === false ? "unavailable" : c.status}`).join(" "),
  );
  const isoCells = [];
  for (const pathName of PATHS) {
    const r = await callPath(pathName, "query", { family: "acme.intake-minimised" }, PAT.B);
    isoCells.push({ path: pathName, available: r.available, status: r.status });
  }
  const liveIso = isoCells.filter((c) => c.available !== false);
  ok(
    "CROSS-PATH isolation: principal B, holding its OWN pat_*, is refused 403 reading principal A's view family on every available surface — the isolation is about the principal, enforced once at the owner seam and identical across transports",
    isoCells.find((c) => c.path === "native")?.status === 403 &&
      liveIso.every((c) => c.status === 403),
    isoCells.map((c) => `${c.path}:${c.available === false ? "unavailable" : c.status}`).join(" "),
  );

  // ---- static no-second-admitter: no client file re-derives a decision ----
  const clientFiles = {
    cli: path.join(ROOT, "crates/cli/src/commands/policy_bound_data_view.rs"),
    sdk: path.join(ROOT, "packages/agent-sdk/src/policy-bound-data-view.ts"),
    mcp: MCP_SERVER,
  };
  // Refusal fragments and policy tokens that must live ONLY in the daemon module. A client that
  // named any of them would be deciding for itself.
  const FORBIDDEN_FRAGMENTS = [
    "cross_tenant_source",
    "excess_field",
    "redaction_declassifies",
    "stale_policy_binding",
    "brokered_destination",
    "consent_not_current",
    "allowed_uses",
    "rights_derived",
    "revalidated_facts",
    "source_scheme_has_no_owner_seam",
    "content_hash",
  ];
  const leaks = [];
  for (const [name, file] of Object.entries(clientFiles)) {
    const src = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
    for (const fragment of FORBIDDEN_FRAGMENTS) {
      if (src.includes(fragment)) leaks.push(`${name}:${fragment}`);
    }
    // and no client imports the owner implementation module
    if (/policy_bound_data_view_revision_routes|revision_routes::/u.test(src)) {
      leaks.push(`${name}:imports-owner-module`);
    }
  }
  ok(
    "NO SECOND ADMITTER: the CLI, SDK and MCP client files contain NO refusal string, policy field, or import of the owner module — every decision is the daemon's, and a client that started deciding would turn this red",
    leaks.length === 0,
    leaks.length ? leaks.join(", ") : "zero policy fragments in any client",
  );
  // the MCP shim explicitly nonclaims the general outward gateway
  const mcpSrc = fs.existsSync(MCP_SERVER) ? fs.readFileSync(MCP_SERVER, "utf8") : "";
  ok(
    "NONCLAIM: the MCP shim names M01.11 as NOT its role, guards a fixed forbidden-argument set so no credential/principal/tenant rides in tool arguments, and exposes exactly three tools — it is a bounded local touchpoint, not the outward gateway",
    /M01\.11/u.test(mcpSrc) &&
      /FORBIDDEN_ARG_KEYS/u.test(mcpSrc) &&
      (mcpSrc.match(/policy_bound_data_view\.(admit|query|materialize)/gu) || []).length >= 3 &&
      !/normalizes every primitive|master tool/u.test(mcpSrc.replace(/exposes no master tool/gu, "")),
    "mcp shim is bounded and nonclaims M01.11",
  );

  return state;
}

// ------------------------------------------------------------------------------------ durability

async function runDurability(state) {
  const before = {
    views: (await req("GET", `${VIEWS}?family=acme.intake-minimised`)).j,
    reads: (await req("GET", `${MATS}?family=acme.pbdv-read-conforming`)).j,
  };
  await stopDaemon();
  // DELETE THE READ INDEX. If a per-family record directory exists, deleting it proves the answer is
  // rebuilt from the chain; if none exists, that is itself the finding — the chain is the only copy.
  const familyDirs = ["policy-bound-data-views", "policy-bound-data-view-materializations"];
  const present = familyDirs.filter((kind) => fs.existsSync(path.join(dataDir, kind)));
  for (const kind of present) fs.rmSync(path.join(dataDir, kind), { recursive: true, force: true });
  await startDaemon();
  const reloginA = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "admin@ioi.local", password: "pbdv-a-v1" },
    { as: null },
  );
  if (reloginA.j?.session_token) SESSIONS.A = reloginA.j.session_token;
  const reloginB = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "pbdv-b@ioi.local", password: "pbdv-b-v1" },
    { as: null },
  );
  if (reloginB.j?.session_token) SESSIONS.B = reloginB.j.session_token;

  const after = {
    views: (await req("GET", `${VIEWS}?family=acme.intake-minimised`)).j,
    reads: (await req("GET", `${MATS}?family=acme.pbdv-read-conforming`)).j,
  };
  ok(
    "DURABILITY: both families REPLAY BYTE-IDENTICALLY from the durable chain across a real process restart — this is read AFTER restarting, not by asking the API whether it would survive one",
    canonicalJson(before.views?.revisions) === canonicalJson(after.views?.revisions) &&
      canonicalJson(before.reads?.revisions) === canonicalJson(after.reads?.revisions) &&
      before.views?.head === after.views?.head,
    `views ${(after.views?.revisions || []).length} reads ${(after.reads?.revisions || []).length}`,
  );
  ok(
    "DURABILITY: NO SECOND COPY EXISTS — neither family materializes a per-family record directory, so the Agentgres chain is the only copy and there is no row a sweep could read instead of the log",
    present.length === 0,
    `materialized directories: ${present.length === 0 ? "none" : present.join(",")}`,
  );
  ok(
    "DURABILITY: the projection cache reports REBUILT-FROM-AGENTGRES by positive detection — an unchanged answer alone is also consistent with a cache that was never dropped, which would prove nothing",
    after.views?.index_state === "rebuilt_from_agentgres" && after.reads?.index_state === "rebuilt_from_agentgres",
    `${after.views?.index_state} / ${after.reads?.index_state}`,
  );
  ok(
    "DURABILITY: the view's commitment and its bound compiled-policy hash both survive the restart unchanged, so a consumer that bound this projection still binds the same policy",
    (after.views?.revisions || [])[0]?.content_hash === state.view?.content_hash &&
      (after.views?.revisions || [])[0]?.materialization_precondition?.required_effective_learning_boundary_hash ===
        state.view?.materialization_precondition?.required_effective_learning_boundary_hash,
    `${(after.views?.revisions || [])[0]?.content_hash}`,
  );
  const grantedAfterRestart = (after.reads?.revisions || []).find(
    (r) => r.materialization_ref === state.conforming?.j?.policy_bound_data_view_materialization?.materialization_ref,
  );
  ok(
    "DURABILITY: the granted decision replays with its DESCRIPTOR intact and still carries no payload bytes — a restart neither widens the grant nor turns the descriptor into a copy",
    grantedAfterRestart?.decision === "materialized" &&
      canonicalJson(grantedAfterRestart?.refusal_codes) === "[]" &&
      grantedAfterRestart?.granted_projection?.payload_bytes_included === false &&
      canonicalJson(grantedAfterRestart?.granted_projection?.granted_field_refs) ===
        canonicalJson(["field://acme/intake/intake_id"]),
    canonicalJson(grantedAfterRestart?.granted_projection?.granted_field_refs),
  );
  const isolationAfterRestart = await req("GET", `${VIEWS}?family=acme.intake-minimised`, null, { as: "B" });
  ok(
    "DURABILITY: cross-principal isolation is REBUILT too — the second principal is still refused after the restart and the index deletion, so the scope binding is durable rather than cached",
    isolationAfterRestart.status === 403,
    `status ${isolationAfterRestart.status}`,
  );
}

// -------------------------------------------------------------------------------- mutation battery

const PBDV_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/policy_bound_data_view_revision_routes.rs",
);
const SOURCES = { pbdv: PBDV_SOURCE };

const MUTANTS = [
  {
    id: "a-granted-decision-returns-no-descriptor",
    source: "pbdv",
    reddens:
      "M05.8: the grant is a DESCRIPTOR, not a copy — it names the permitted fields, the committed row predicate and its ceiling, the timebase and window, and it pins `payload_bytes_included: false`; no protected byte is in the record",
    from: `    let granted = if materialized {`,
    to: `    let granted = if false {`,
  },
  {
    id: "an-unowned-source-scheme-is-accepted",
    source: "pbdv",
    reddens:
      "M05.8: a source whose SCHEME HAS NO REGISTERED OWNER SEAM is refused by name — an accepted free-form source ref is silence, and silence about a protected source is inadmissible. This is also the fence that stops M05.9's dataset families from being invented in here",
    from: `        &VIEW.code("source_scheme_has_no_owner_seam"),`,
    to: `        &VIEW.code("source_scheme_has_no_owner_seam_renamed"),`,
  },
  {
    id: "the-source-content-hash-is-not-compared",
    source: "pbdv",
    reddens:
      "M05.8: a source whose committed hash is NOT what its owner currently serves is refused — a ref names a location that may since have been re-admitted, and the hash is what names what was actually bound",
    from: `        if live != committed {`,
    to: `        if false {`,
  },
  {
    id: "an-incomplete-run-is-accepted-as-a-source",
    source: "pbdv",
    reddens:
      "M05.8: a TRANSFORMATION RUN that did not complete is refused as a source through M05.7's new owner seam — a run that produced nothing is not a source a projection can be over",
    from: `        if !run.is_completed() {`,
    to: `        if false {`,
  },
  {
    id: "a-consent-need-not-be-covered-by-a-claim",
    source: "pbdv",
    reddens:
      "M05.8: a consent that is NOT a rights basis on any bound claim is refused — canon mints no consent family, so a consent nothing can revalidate is refused rather than trusted from the `consent_state` the caller attested",
    from: `        if !claim_bases.contains(&consent_ref) {`,
    to: `        if false {`,
  },
  {
    id: "a-brokered-destination-needs-no-admitted-authority",
    source: "pbdv",
    reddens:
      "M05.8: a BROKERED destination no bound route contract admits is refused by name — this module models no provider connection and mints no stand-in for one; the route-rights ceiling is the coverage it can resolve, and the refusal is the correct output",
    from: `        if BROKERED_DESTINATION_CLASSES.contains(&class.as_str())
            && !route_destinations.contains(class)
        {`,
    to: `        if false {`,
  },
  {
    id: "consent-is-not-revalidated-through-its-claim-at-the-read",
    source: "pbdv",
    reddens:
      "M05.8: a consent whose covering claim's validity window closed before the read is denied AT READ TIME by name — the consent rides on the claim, so the claim's own window is the consent's",
    from: `        if live_bases.contains(&consent_ref) {`,
    to: `        if true {`,
  },
  {
    id: "the-bound-purpose-narrows-nothing",
    source: "pbdv",
    reddens:
      "M05.8: THE PERMISSION IS A SUBTRACTION — the bound purpose `evaluation` supports read/transform/evaluate and nothing else, `allowed_uses` equals the rights-derived set exactly, and `redaction_derived_allowed_uses` is emitted EMPTY so no use can enter by way of a transformation",
    from: `        if !supported.contains(token) {`,
    to: `        if false {`,
  },
  {
    id: "the-caller-may-author-the-permission-it-checks",
    source: "pbdv",
    reddens:
      "INV-37: a caller that AUTHORS the permission its own admission checks is refused BY NAME, rather than having its value quietly overwritten",
    from: `    "allowed_uses",
    "rights_derived_allowed_uses",
    "redaction_derived_allowed_uses",
    "admitted_at",`,
    to: `    "rights_derived_allowed_uses",
    "redaction_derived_allowed_uses",
    "admitted_at",`,
  },
  {
    id: "the-caller-may-name-its-own-principal",
    source: "pbdv",
    reddens:
      "INV-37: the principal is RESOLVED from the authenticated request — a body naming a different principal is refused by name, and the admitted record carries this caller's own resolved ref beside the server_resolved pin",
    from: `    "resolved_principal_ref",
    "source_binding_count",`,
    to: `    "source_binding_count",`,
  },
  {
    id: "a-cross-tenant-source-is-admitted",
    source: "pbdv",
    reddens:
      "M05.8: a source belonging to ANOTHER TENANT is inadmissible at admission and named as such — a discovery at materialization would come after the protected bytes were already moving",
    from: `        if source_tenant != tenant_ref {`,
    to: `        if false {`,
  },
  {
    id: "a-field-needs-no-minimization-decision",
    source: "pbdv",
    reddens:
      "M05.8: a field allowed WITHOUT its own minimization decision is refused by name — minimization stops being a claim the record makes about itself and becomes a property checkable one field at a time",
    from: `        .find(|field_ref| !decided.contains(*field_ref))`,
    to: `        .find(|_field_ref| false)`,
  },
  {
    id: "a-non-active-consent-is-admitted",
    source: "pbdv",
    reddens:
      "M05.8: a view carrying an EXPIRED, REVOKED, WITHDRAWN or UNKNOWN consent cannot be admitted at all — the non-active states exist so a state can be recorded on the way to a successor, never so a live projection can carry one",
    from: `        .find(|binding| item_str(binding, "consent_state") != "active")`,
    to: `        .find(|_binding| false)`,
  },
  {
    id: "redaction-may-lower-the-privacy-class",
    source: "pbdv",
    reddens:
      "M05.8: redaction that LOWERS the privacy class is refused by name — reclassification is a governed act with its own approval, rights and receipts, never a side effect of masking a column",
    from: `    if output_class != privacy_class {`,
    to: `    if false {`,
  },
  {
    id: "redaction-may-claim-it-creates-permission",
    source: "pbdv",
    reddens:
      "M05.8: a redaction that CLAIMS IT CREATES PERMISSION is refused rather than silently corrected — a repaired claim is a claim that was made and not recorded",
    from: `    if redaction.get("creates_permission").and_then(Value::as_bool) != Some(false)
        || redaction.get("severs_lineage").and_then(Value::as_bool) != Some(false)
    {`,
    to: `    if false {`,
  },
  {
    id: "the-redaction-recipe-may-be-substituted",
    source: "pbdv",
    reddens:
      "M05.8: a redaction recipe whose committed bytes disagree with what the view commits is refused through M05.7's OWNER SEAM — an unreproducible transformation cannot carry a reproducible-looking record",
    from: `    if recipe.content_hash != recipe_hash {`,
    to: `    if false && recipe.content_hash != recipe_hash {`,
  },
  {
    id: "the-redaction-recipe-may-be-opaque",
    source: "pbdv",
    reddens:
      "M05.8: an OPAQUE redaction recipe ref is refused with no fallback path — a recipe nobody can resolve names a transformation nobody can reproduce",
    from: `    if !recipe_ref.starts_with("data-recipe://") {`,
    to: `    if false {`,
  },
  {
    id: "the-purpose-binding-may-be-a-label",
    source: "pbdv",
    reddens:
      "M05.8: a purpose bound by a free-text LABEL is refused — the binding must name a Governance-owned decision its own resolver can open, because a purpose nobody can check narrows nothing",
    from: `    if !purpose_binding_ref.starts_with("approval-request://") {`,
    to: `    if false {`,
  },
  {
    id: "an-ontology-family-head-is-accepted",
    source: "pbdv",
    reddens:
      "M05.8: a view naming an ontology FAMILY HEAD is refused BY M05.1's own seam — this module resolves exact revisions rather than shape-checking them, so a view cannot project whatever the ontology becomes",
    from: `    for ontology_ref in &ontology_refs {
        if let Err(response) = super::ontology_version_routes::resolve_admitted_revision(`,
    to: `    for ontology_ref in ontology_refs.iter().take(0) {
        if let Err(response) = super::ontology_version_routes::resolve_admitted_revision(`,
  },
  {
    id: "a-mapping-family-head-is-accepted",
    source: "pbdv",
    reddens:
      "M05.8: a view naming a mapping FAMILY HEAD is refused BY M05.7's own seam, so the shape the view claims to scope cannot change underneath it without the view changing",
    from: `    for mapping_ref in &mapping_refs {
        if let Err(response) = super::data_transformation_routes::resolve_admitted_connector_mapping(`,
    to: `    for mapping_ref in mapping_refs.iter().take(0) {
        if let Err(response) = super::data_transformation_routes::resolve_admitted_connector_mapping(`,
  },
  {
    id: "the-stale-policy-assertion-is-ignored",
    source: "pbdv",
    reddens:
      "M05.8: a caller may ASSERT which compiled policy it believes it is binding and is refused by name when the boundary has moved — it may never AUTHOR the hash, which is what makes the assertion a check rather than a value",
    from: `        if asserted != boundary.compiled_policy_hash {`,
    to: `        if false {`,
  },
  {
    id: "a-successor-needs-no-reason",
    source: "pbdv",
    reddens:
      "M05.8: a SUCCESSOR revision must name why it exists, from the contract's closed reason vocabulary — a restatement with no reason is a lineage nobody can review",
    from: `            if !SUCCESSION_REASONS.contains(&reason.as_str()) || reason == "genesis" {`,
    to: `            if false {`,
  },
  {
    id: "an-out-of-scope-field-is-trimmed-instead-of-refused",
    source: "pbdv",
    reddens:
      "M05.8: an OUT-OF-SCOPE FIELD is refused at read time rather than silently trimmed — a quietly narrowed answer is indistinguishable from a permitted one",
    from: `        if !allowed_fields.iter().any(|held| held == field_ref) {`,
    to: `        if false {`,
  },
  {
    id: "a-use-outside-the-permitted-set-is-allowed",
    source: "pbdv",
    reddens:
      "M05.8: a use OUTSIDE the view's permitted set refuses — the set is itself the vocabulary minus every denial its resolved inputs contributed, so this is the subtraction being enforced at the read",
    from: `    if !view
        .allowed_uses()
        .iter()
        .any(|held| *held == requested_use)
    {`,
    to: `    if false {`,
  },
  {
    id: "the-row-ceiling-is-ignored",
    source: "pbdv",
    reddens: "M05.8: a read asking for MORE ROWS than the view's committed ceiling refuses",
    from: `        if requested > ceiling {`,
    to: `        if false {`,
  },
  {
    id: "the-row-predicate-may-be-substituted",
    source: "pbdv",
    reddens:
      "M05.8: a row predicate named at DIFFERENT BYTES refuses — a predicate editable after admission is a scope that widens silently",
    from: `    if body_str(&body, "requested_row_predicate_ref") != row_predicate_ref
        || body_str(&body, "requested_row_predicate_hash") != row_predicate_hash
    {`,
    to: `    if false {`,
  },
  {
    id: "the-timebase-may-disagree",
    source: "pbdv",
    reddens:
      "M05.8: a read on the WRONG CLOCK refuses — event time and ingest time disagree, and a range read on the wrong one silently widens or narrows the projection",
    from: `    if body_str(&body, "requested_timebase") != timebase {`,
    to: `    if false {`,
  },
  {
    id: "the-time-window-need-not-be-contained",
    source: "pbdv",
    reddens:
      "M05.8: a window reaching OUTSIDE the view's committed time scope refuses — a view over all of history is not minimized no matter how few fields it names",
    from: `    if !window_ok {`,
    to: `    if false {`,
  },
  {
    id: "the-destination-ceiling-is-ignored",
    source: "pbdv",
    reddens:
      "M05.8: a destination class OUTSIDE the view's ceiling refuses — a materialization may carry less than the ceiling permits and never more",
    from: `    if !permitted_classes
        .iter()
        .any(|held| *held == requested_destination)
    {`,
    to: `    if false {`,
  },
  {
    id: "the-egress-ceiling-is-read-as-an-ordering",
    source: "pbdv",
    reddens:
      "M05.8: the egress ceilings are a TABLE, NOT AN ORDERING — `synthetic` is refused under `redacted_only` rather than admitted as a near neighbour",
    from: `    ("redacted_only", &["redacted"]),`,
    to: `    ("redacted_only", &["redacted", "synthetic"]),`,
  },
  {
    id: "declassified-egress-needs-no-approval",
    source: "pbdv",
    reddens:
      "M05.8: moving DECLASSIFIED or protected-plaintext material without its own approval refuses — the view pins that it is never the approval",
    from: `    if DECLASSIFYING_REPRESENTATIONS.contains(&requested_representation.as_str())
        && body_str(&body, "declassification_approval_ref").is_empty()
    {`,
    to: `    if false {`,
  },
  {
    id: "residency-and-destination-region-are-conflated",
    source: "pbdv",
    reddens:
      "M05.8: a region outside BOTH the permitted destination regions and the declared residency refuses — they are separate axes, and conflating them is how a compliant-looking view permits a move neither would allow",
    from: `    if !permitted_regions
        .iter()
        .any(|held| *held == requested_region)
        || !residency_refs.iter().any(|held| *held == requested_region)
    {`,
    to: `    if false {`,
  },
  {
    id: "the-jurisdiction-is-not-checked",
    source: "pbdv",
    reddens:
      "M05.8: a jurisdiction this projection never declared refuses — an unstated jurisdiction is not an absent obligation",
    from: `    if !view
        .list("/jurisdiction_refs")
        .iter()
        .any(|held| *held == requested_jurisdiction)
    {`,
    to: `    if false {`,
  },
  {
    id: "source-containment-is-not-checked",
    source: "pbdv",
    reddens:
      "M05.8: a read naming a source OUTSIDE the bound set refuses, and a bound source ABSENT from the observed set refuses too — containment is exact in both directions, and it is named as containment because neither side was resolved against a source-revision owner",
    from: `        if !matched {`,
    to: `        if false {`,
  },
  {
    id: "the-claim-validity-window-is-not-rechecked",
    source: "pbdv",
    reddens:
      "M05.8: a source-rights claim that is still `admitted` and carries every permission in its own bytes, but whose validity window closed before the read, is re-resolved through M10.3's seam and denied `source_right_expired`",
    from: `                } else if claim.expires_before(at_ms) {`,
    to: `                } else if false {`,
  },
  {
    id: "the-boundary-window-is-not-rechecked",
    source: "pbdv",
    reddens:
      "M05.8: a compiled boundary whose own effective window closed before the read is STALE POLICY at the read — the view still names a live-looking revision, and only a read-time recheck against that instant finds it",
    from: `            if expired_at(
                boundary.record.get("expires_at").and_then(Value::as_str),
                at_ms,
            ) {`,
    to: `            if false {`,
  },
  {
    id: "a-deprecated-mapping-still-materializes",
    source: "pbdv",
    reddens:
      "M05.8: a mapping that is no longer active blocks the READ rather than unmaking the admitted view — `reinterprets_predecessor` is pinned false, so a later narrowing stops future materialization and leaves the historical record exactly as admitted. This is a MAPPING fact and is named as one; it is not evidence about a provider connection",
    from: `            Ok(mapping) if mapping.registry_status != "active" => check.deny(`,
    to: `            Ok(mapping) if false && mapping.registry_status != "active" => check.deny(`,
  },
  {
    id: "the-caller-may-author-the-decision-it-receives",
    source: "pbdv",
    reddens:
      "INV-37: a caller that AUTHORS the decision or the projection its own read would be granted is refused by name — a decision taken over self-supplied constants is void for conformance purposes",
    from: `    "granted_projection",
    "decision",
    "refusal_codes",
    "emitted_at",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];`,
    to: `    "granted_projection",
    "refusal_codes",
    "emitted_at",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];`,
  },
];

/// Mutations CONSIDERED AND REJECTED. A rejected mutant is a finding about the gate, and deleting it
/// silently would let the same idea be re-proposed as new. Neither is counted in the population: the
/// census denominator is `MUTANTS.length`.
const REJECTED_MUTANTS = [
  {
    id: "the-projection-cache-always-reports-agreement",
    replacedBy: null,
    rejectedBecause:
      "NOT THIS UNIT'S CODE. `projection_cache_state` lives in model_route_rights_routes.rs, which M07.2 owns and this packet may not edit. The index-rebuild assertion here is real but its anchor belongs to the M10.3/M07.2 battery, which already carries `the-index-always-reports-agreement`. Duplicating the mutant would mean editing another unit's file to score this one.",
  },
  {
    id: "a-successor-need-not-name-the-exact-head",
    replacedBy: null,
    rejectedBecause:
      "SHARED ANCHOR IN ANOTHER OWNER'S FILE. `require_exact_head` is M07.2's shared chain machinery; the M10.3 battery already plants and scores it. This gate still asserts exact-head behaviour, but scoring it here would require mutating a file outside this unit's writable set.",
  },
];

// ================================================================= crash-safe byte restoration
//
// SIGKILL CANNOT BE TRAPPED, so in-process restore handlers are not a guarantee — a hard kill
// between planting and restoring leaves a defect in the tree, and a pattern grep cannot even find it
// when the mutant DELETED a line rather than adding one. The journal makes restoration a property of
// the FILESYSTEM rather than of the dying process: pristine bytes are copied aside and their digests
// recorded BEFORE the first plant, so any later invocation — the next battery, the anchor pre-flight,
// or an explicit `--restore` — can byte-restore without knowing what was planted or whether anything
// was. Recovery is idempotent and content-addressed.

const JOURNAL = path.join(os.tmpdir(), "ioi-pbdv-mutation-journal.json");
const LEDGER = path.join(os.tmpdir(), "ioi-pbdv-mutation-ledger.json");

const sha256File = (file) => `sha256:${crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")}`;

function openJournal() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-pbdv-pristine-"));
  const sources = Object.entries(SOURCES).map(([key, file]) => {
    const backup = path.join(dir, `${key}.rs`);
    fs.copyFileSync(file, backup);
    return { key, path: file, backup, sha256: sha256File(file) };
  });
  fs.writeFileSync(JOURNAL, JSON.stringify({ openedFor: "mutation-battery", dir, sources }, null, 2));
  return sources;
}

/**
 * Byte-restore anything a previous run left planted.
 *
 * An EMPTY repaired list is the interesting answer: every source already matched its pristine
 * digest, which is positive proof the tree is byte-clean rather than merely "looks fine".
 */
function recoverFromJournal({ quiet = false } = {}) {
  if (!fs.existsSync(JOURNAL)) return { present: false, repaired: [] };
  let journal;
  try {
    journal = JSON.parse(fs.readFileSync(JOURNAL, "utf8"));
  } catch {
    return { present: false, repaired: [] };
  }
  const repaired = [];
  for (const entry of journal.sources ?? []) {
    if (!fs.existsSync(entry.backup)) continue;
    if (sha256File(entry.path) !== entry.sha256) {
      fs.writeFileSync(entry.path, fs.readFileSync(entry.backup));
      repaired.push(entry.key);
    }
  }
  if (repaired.length && !quiet) {
    process.stderr.write(`RECOVERED  a previous run left ${repaired.join(", ")} planted; byte-restored from the journal\n`);
  }
  return { present: true, repaired, journal };
}

function closeJournal(sources) {
  for (const entry of sources) {
    const current = sha256File(entry.path);
    if (current !== entry.sha256) {
      throw new Error(
        `${entry.key} did not byte-restore: ${current} != ${entry.sha256}; refusing to report a census over a mutated tree`,
      );
    }
  }
  try {
    const journal = JSON.parse(fs.readFileSync(JOURNAL, "utf8"));
    fs.rmSync(journal.dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
  fs.rmSync(JOURNAL, { force: true });
}

/**
 * The population identity this ledger's rows belong to.
 *
 * Digested over the verifier PLUS the pristine source, so any edit to the harness or to the code
 * under test invalidates every stored row. That is what stops a batched census from accumulating
 * rows scored against different bytes and reporting them as one sweep.
 */
function harnessDigest(sources) {
  const hash = crypto.createHash("sha256");
  const self = fileURLToPath(import.meta.url);
  hash.update(path.relative(ROOT, self));
  hash.update(fs.readFileSync(self));
  for (const entry of [...sources].sort((a, b) => a.path.localeCompare(b.path))) {
    hash.update(path.relative(ROOT, entry.path));
    hash.update(fs.readFileSync(entry.backup));
  }
  return `sha256:${hash.digest("hex")}`;
}

function readLedger(digest) {
  try {
    const held = JSON.parse(fs.readFileSync(LEDGER, "utf8"));
    if (held.harness === digest) return held;
  } catch {
    /* absent or unreadable */
  }
  return { harness: digest, rows: {} };
}

function summarize() {
  const sources = Object.entries(SOURCES).map(([key, file]) => ({
    key,
    path: file,
    backup: file,
    sha256: sha256File(file),
  }));
  const digest = harnessDigest(sources);
  const ledger = readLedger(digest);
  const scored = MUTANTS.map((mutant) => ({ id: mutant.id, ...(ledger.rows[mutant.id] ?? {}) }));
  for (const row of scored) {
    const outcome = row.outcome ?? "NOT_RUN";
    process.stdout.write(
      `${outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${row.id} — ${row.detail ?? "not scored against this harness"}\n`,
    );
  }
  const onTarget = scored.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(`\nharness digest ${digest}\n`);
  process.stdout.write(
    `policy-bound-data-view mutation battery: ${onTarget}/${MUTANTS.length} RED ON TARGET (union over batches)\n`,
  );
  process.exit(onTarget === MUTANTS.length ? 0 : 1);
}

/** Zero-build pre-flight: every anchor must occur EXACTLY once, and no two mutants share a target. */
function checkAnchors() {
  const originals = Object.fromEntries(Object.entries(SOURCES).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]));
  const targets = new Map();
  let bad = 0;
  for (const mutant of MUTANTS) {
    const occurrences = originals[mutant.source].split(mutant.from).length - 1;
    if (occurrences !== 1) {
      bad += 1;
      process.stdout.write(`ANCHOR_LOST  ${mutant.id} — ${occurrences} matches in ${mutant.source}\n`);
    }
    if (targets.has(mutant.reddens)) {
      bad += 1;
      process.stdout.write(`SHARED_TARGET  ${mutant.id} shares its target with ${targets.get(mutant.reddens)}\n`);
    }
    targets.set(mutant.reddens, mutant.id);
  }
  // A target naming an assertion this gate never emits would score forever as RED_OFF_TARGET, and
  // the battery would read as "the mutant did not redden" when the truth is "nothing was watching".
  // Checked STATICALLY against this file's own source so the pre-flight stays zero-build: the target
  // text must occur at least twice — once as the mutant's `reddens`, once as the `ok(...)` name.
  const self = fs.readFileSync(fileURLToPath(import.meta.url), "utf8");
  for (const mutant of MUTANTS) {
    if (self.split(mutant.reddens).length - 1 < 2) {
      bad += 1;
      process.stdout.write(`UNKNOWN_TARGET  ${mutant.id} names an assertion this gate never emits\n`);
    }
  }
  process.stdout.write(`\nanchors: ${MUTANTS.length - bad}/${MUTANTS.length} resolve exactly once with distinct targets\n`);
  process.exit(bad === 0 ? 0 : 1);
}

async function runMutationBattery() {
  const originals = Object.fromEntries(Object.entries(SOURCES).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]));
  const journalled = openJournal();
  const digest = harnessDigest(journalled);
  // `finally` does not run when the process is signalled, so the restore is registered on the
  // signals too, and it is idempotent. SIGKILL is covered by the on-disk journal above.
  const restore = () => {
    for (const [key, file] of Object.entries(SOURCES)) fs.writeFileSync(file, originals[key]);
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(signal, () => {
      restore();
      process.stderr.write(`\nmutation battery interrupted by ${signal} — the source was restored\n`);
      process.exit(130);
    });
  }
  const selected = ONLY.length ? MUTANTS.filter((mutant) => ONLY.includes(mutant.id)) : MUTANTS;
  const unknown = ONLY.filter((id) => !MUTANTS.some((mutant) => mutant.id === id));
  if (unknown.length) {
    process.stderr.write(`no such mutant: ${unknown.join(", ")}\n`);
    process.exit(1);
  }
  const rows = [];
  try {
    for (const mutant of selected) {
      const original = originals[mutant.source];
      const occurrences = original.split(mutant.from).length - 1;
      if (occurrences !== 1) {
        rows.push({ id: mutant.id, outcome: "ANCHOR_LOST", detail: `${occurrences} matches in ${mutant.source}` });
        continue;
      }
      // The REPLACER FUNCTION form is deliberate: String.replace interprets `$&`, `` $` ``, `$'` and
      // `$1` in a string replacement, which would silently corrupt a Rust body containing them.
      fs.writeFileSync(SOURCES[mutant.source], original.replace(mutant.from, () => mutant.to));
      let outcome;
      let detail;
      try {
        rebuildDaemon();
        const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
          cwd: ROOT,
          encoding: "utf8",
          env: { ...process.env, IOI_VERIFIER_CENSUS_DIR: "", IOI_PBDV_DAEMON_PREBUILT: "1" },
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
      // EMIT EACH ROW AS IT LANDS. A killed run that reports nothing is indistinguishable from one
      // that found nothing; each row written immediately makes a partial battery partial EVIDENCE.
      process.stdout.write(`${outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${mutant.id} — ${detail}\n`);
      restore();
      // AND PROVE IT, per child: a restore that silently failed would grade every later mutant
      // against a tree still carrying this one.
      for (const entry of journalled) {
        const current = sha256File(entry.path);
        if (current !== entry.sha256) {
          throw new Error(`${entry.key} did not byte-restore after ${mutant.id}: ${current} != ${entry.sha256}`);
        }
      }
      const ledger = readLedger(digest);
      ledger.rows[mutant.id] = { outcome, detail };
      fs.writeFileSync(LEDGER, JSON.stringify(ledger, null, 2));
    }
  } finally {
    restore();
    rebuildDaemon();
  }
  closeJournal(journalled);
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(`\nharness digest ${digest}\n`);
  process.stdout.write(
    `policy-bound-data-view mutation battery: ${onTarget}/${selected.length} RED ON TARGET${
      ONLY.length ? ` (subset of ${MUTANTS.length}; run --summarize for the union)` : ""
    }\n`,
  );
  process.exit(onTarget === selected.length ? 0 : 1);
}

// ------------------------------------------------------------------------------------- the driver

const startupRecovery = recoverFromJournal();
if (startupRecovery.present) closeJournal(startupRecovery.journal?.sources ?? []);

if (RESTORE) {
  process.stdout.write(
    startupRecovery.present
      ? `restore: ${startupRecovery.repaired.length ? `byte-restored ${startupRecovery.repaired.join(", ")}` : "every source already matched its pristine digest"}\n`
      : "restore: no journal present; nothing was left planted\n",
  );
  process.exit(0);
}

// THE ZERO-BUILD MODES DISPATCH FIRST, BEFORE THE BINARY GATE. `--anchors` and `--summarize` read
// source and a ledger; neither starts a daemon. Gating them behind an executable check would make
// the cheapest pre-flight in this gate — "does every mutant still resolve exactly once?" — the one
// that needs a ten-minute build to answer, which is exactly backwards.
if (SUMMARIZE) {
  summarize();
} else if (ANCHORS) {
  checkAnchors();
}

try {
  fs.accessSync(daemonBinary(), fs.constants.X_OK);
} catch {
  process.stderr.write(`BLOCKED: daemon binary not executable at ${daemonBinary()}\n`);
  process.exit(2);
}

if (MUTATE) {
  runMutationBattery().catch((error) => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(1);
  });
} else {
  Promise.resolve()
    .then(() => {
      // A blocking verifier must not silently exercise a stale target/debug binary. The mutation
      // parent is the sole exception: it built the exact planted source immediately before spawning.
      if (process.env.IOI_PBDV_DAEMON_PREBUILT !== "1") rebuildDaemon();
      return run();
    })
    .then((state) => runAdmission(state))
    .then((state) => runMaterialization(state))
    .then((state) => runCrossPath(state))
    .then((state) => runDurability(state))
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
      process.stdout.write(`\npolicy-bound-data-view: ${passed}/${results.length}\n`);
      process.stdout.write(
        `\nCROSS-PATH — the ten mandated negative classes plus one positive run through native, SDK, CLI\nand MCP against the same live daemon; every surface returns the daemon's decision unchanged, and a\ntyped 'unavailable' (never a silent skip) marks any client whose build artifact is absent. The\nclients hold a token, decide nothing, and a static grep refuses one that names a refusal string.\n`,
      );
      process.stdout.write(
        `\nNOT CLAIMED BY THIS GATE — no provider-connection fact. ProviderConnectionBinding is\nwallet.network's (M03.16) and is deliberately outside this contract's closed eight-fact\nvocabulary; a brokered destination is covered by a live route-rights contract or refused, and no\nstand-in is modelled here. No protected data, provider or network egress is exercised, and a\ngranted projection is a descriptor rather than a copy. ${REJECTED_MUTANTS.length} mutants were considered and\nrejected; see REJECTED_MUTANTS.\n`,
      );
      emitVerifierCensus({ verifierId: "policy-bound-data-view", sourceUrl: import.meta.url, results });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
