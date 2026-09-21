#!/usr/bin/env node
//
// M09.11 — ONE MACHINE LIFECYCLE, TWO BACKENDS, AND A CAPABILITY MATRIX THAT IS CONSULTED.
//
// ACC-20 clause 1 is "contracts precede surfaces", so this gate starts by proving the eleven-member
// machine-control family is registered and that its projections agree. Clause 3 is "one operation
// vocabulary": the sixteen verbs resolve to the same versioned daemon operation and a backend alias
// never becomes a canonical verb. Clause 4 is "capability truth is current and explicit": the exact
// declaration decides, and unsupported, absent and DRIFTED cells refuse before effect.
//
// WHAT IS DRIVEN LIVE AND WHAT IS NOT. The lifecycle runs against a REAL daemon over its real route,
// with two deterministic reference backends — one hosted, one attached — whose matrices are
// deliberately asymmetric so that "runs on both" and "refuses honestly on the other" are different
// observations rather than the same one twice. What this gate does NOT claim is profile
// qualification: both reference declarations carry `evidence_mode: simulated`, and ACC-20 says in
// as many words that simulated-only evidence may validate the contract and may never qualify a
// public host or attached-estate matrix. The reference executor enforces that from the other side —
// it refuses to execute any backend that is not simulated — and this gate proves that refusal.
//
// WHAT IS STILL OUTSTANDING FOR THE UNIT. Attachments, console scope, crash/restart reconstruction
// and cleanup are clauses 6 and 7, and their surfaces do not exist yet: there is one route here,
// not a machine plane. Those are named at the end of the run rather than implied to be covered.
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const RESULTS = [];
const ok = (label, pass, detail = "") => {
  RESULTS.push({ label, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${label}${detail ? `  · ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf8"));
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});

const SCHEMA_DIR = "docs/architecture/_meta/schemas";
const FAMILY = [
  "hypervisor-machine-host", "hypervisor-machine-image", "hypervisor-machine-volume-attachment",
  "hypervisor-machine-network-attachment", "hypervisor-machine-device-assignment",
  "hypervisor-machine-console-session", "hypervisor-machine-snapshot",
  "hypervisor-machine-migration-plan", "hypervisor-host-maintenance-plan",
  "hypervisor-machine-operation", "hypervisor-machine-operation-receipt",
];
const VOCABULARY = [
  "discover", "define", "import", "create", "start", "stop", "pause", "resume", "reboot",
  "open_console", "close_console", "snapshot", "clone", "restore", "migrate", "delete",
];

// ---- 1. contracts precede surfaces ---------------------------------------------------------------
const registry = readJson(`${SCHEMA_DIR}/architecture-contract-registry.v1.json`);
const registered = FAMILY.filter((key) =>
  registry.contracts.some((c) => c.contract_id === `schema://ioi/components/hypervisor/${key}/v1`));
ok("all ELEVEN machine-control contracts are registered before any surface claims them",
  registered.length === 11, `${registered.length}/11`);

const operationSchema = readJson(`${SCHEMA_DIR}/hypervisor-machine-operation.v1.schema.json`);
ok("the operation vocabulary is canon's sixteen verbs, closed, and in canon's order",
  JSON.stringify(operationSchema.properties.operation.enum) === JSON.stringify(VOCABULARY));

const kernel = fs.readFileSync(path.join(ROOT, "crates/types/src/app/hypervisor_machine_lifecycle.rs"), "utf8");
const kernelVocab = /MACHINE_OPERATION_VOCABULARY: \[&str; 16\] = \[([\s\S]*?)\];/.exec(kernel)?.[1] ?? "";
ok("the KERNEL's copy of the vocabulary agrees with the contract's — a drift between them would let a verb through one and not the other",
  VOCABULARY.every((verb) => kernelVocab.includes(`"${verb}"`))
  && (kernelVocab.match(/"/g) ?? []).length === VOCABULARY.length * 2);

ok("the capability declaration is bound by ref AND hash, because a ref alone cannot see a drifted cell",
  operationSchema.required.includes("capability_declaration_ref")
  && operationSchema.required.includes("capability_declaration_hash"));

const receiptSchema = readJson(`${SCHEMA_DIR}/hypervisor-machine-operation-receipt.v1.schema.json`);
ok("the receipt's result vocabulary has THREE members, so an unconfirmable outcome can be stated rather than guessed",
  JSON.stringify(receiptSchema.properties.result.enum) === JSON.stringify(["succeeded", "refused", "ambiguous"]));
ok("the receipt records FOUR generations, so desired and observed never collapse at the moment of recording",
  ["desired_generation_before", "desired_generation_after", "observed_generation_before", "observed_generation_after"]
    .every((f) => receiptSchema.required.includes(f)));

// ---- 2. live: two asymmetric reference backends --------------------------------------------------
const HOSTED_HASH = `sha256:${"a".repeat(64)}`;
const ATTACHED_HASH = `sha256:${"b".repeat(64)}`;
const GENESIS = `sha256:${"0".repeat(64)}`;
const PORTABLE = VOCABULARY.filter((v) => !["clone", "restore", "migrate"].includes(v));

function declaration(reference, hash, supported, unsupported) {
  return {
    schema_version: "ioi.components.hypervisor.backend-capability-declaration.v1",
    declaration_ref: `capability://backend/${reference}/1`,
    declaration_hash: hash,
    producer_ref: "runtime://daemon/node-1",
    producer_release_ref: "release://hypervisor/0.1.0",
    backend_registration_ref: `backend://reference/${reference}`,
    adapter_release_ref: `release://adapter/${reference}/0.1.0`,
    scope_ref: "runtime-node://local/node-1",
    observed_backend_version: "1.0.0",
    // SIMULATED, and said out loud. The executor refuses anything else, and a public matrix is a
    // claim this evidence may never make.
    evidence_mode: "simulated",
    discovery_method_ref: "evaluator://backend-preflight/v1",
    supported_machine_architectures: ["x86_64"],
    supported_operations: supported,
    unsupported_operations: unsupported,
    limitations: [],
    evaluator_ref: "evaluator://backend-capability/v1",
    signature_or_attestation_ref: "evidence://signature/backend-capability-1",
    temporal_verification_evidence_ref: "evidence://temporal/backend-capability-1",
    currentness_evaluation_ref: "evaluation://currentness/backend-capability-1",
    provenance_evidence_refs: ["evidence://preflight/backend-capability-1"],
  };
}

const HOSTED = declaration("workstation-hosted", HOSTED_HASH,
  [...PORTABLE, "clone", "restore"], [{ operation: "migrate", reason_code: "backend_is_single_host" }]);
const ATTACHED = declaration("infrastructure-attached", ATTACHED_HASH,
  [...PORTABLE.filter((v) => !v.endsWith("_console")), "migrate"],
  [{ operation: "open_console", reason_code: "attached_estate_withholds_console" },
   { operation: "close_console", reason_code: "attached_estate_withholds_console" }]);
// A real backend, to prove the executor's fence rather than assert it.
const LIVE_BACKEND = { ...declaration("live-estate", `sha256:${"c".repeat(64)}`, [...PORTABLE], []),
  evidence_mode: "live" };

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-machine-conformance-"));
fs.mkdirSync(path.join(dataDir, "machine-capability-declarations"), { recursive: true });
for (const [name, decl] of [["hosted", HOSTED], ["attached", ATTACHED], ["live", LIVE_BACKEND]]) {
  fs.writeFileSync(path.join(dataDir, "machine-capability-declarations", `${name}.json`),
    JSON.stringify(decl));
}

let daemon = null;
let BASE = "";
let daemonLog = "";
// The operator session. M08.15 made the submit identity-first (an anonymous proposal is refused 401
// request_principal_required), so this gate bootstraps the isolated daemon's first operator and
// submits as that principal — exactly as a client would.
let SESSION = "";
const daemonBinary = path.join(ROOT, "target/debug/hypervisor-daemon");

async function startDaemon(port) {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  BASE = `http://127.0.0.1:${port}`;
  const until = Date.now() + 40000;
  while (Date.now() < until) {
    try { const r = await fetch(`${BASE}/healthz`); if (r.status < 500) return daemon.pid; } catch { /* not yet */ }
    await sleep(300);
  }
  return 0;
}

function cleanup() {
  if (daemon && !daemon.killed) { try { daemon.kill("SIGTERM"); } catch { /* gone */ } }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* gone */ }
}
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

let nonce = 0;
function proposal(verb, decl, { head = GENESIS, generation = 1, hash = null } = {}) {
  nonce += 1;
  return {
    schema_version: "ioi.hypervisor.machine-operation.v1",
    operation_ref: "machine-operation://caller-chose-this",
    operation: verb,
    workload_ref: "virtual-machine-workload://vm_conformance",
    desired_generation: generation,
    expected_head: head,
    owner_ref: "principal://owner_01",
    environment_ref: "environment://env_01",
    backend_registration_ref: decl.backend_registration_ref,
    capability_declaration_ref: decl.declaration_ref,
    capability_declaration_hash: hash ?? decl.declaration_hash,
    affected_image_bindings: [],
    affected_volume_bindings: [],
    affected_network_bindings: [],
    affected_device_bindings: [],
    authority_refs: ["authority://wallet_network_01"],
    policy_refs: [],
    idempotency_key_hash: `sha256:${String(nonce).padStart(64, "d")}`,
    cleanup_obligation_ref: null,
    durability_boundary_ref: "durability-boundary://declared_01",
    observation_boundary_ref: "observation-boundary://declared_01",
  };
}

/// The workload's current head, asked of the daemon rather than tracked here. A gate that kept its
/// own copy would be asserting its own bookkeeping, and the first version of this file did exactly
/// that — it used `.at(-1)` over an unordered record listing and produced three false failures. The
/// second version re-derived the head from the operation list (the hash no successor cites), which
/// is the daemon's rule copied into a client; M08.15 (R-215) gave the daemon a read model, and this
/// gate now asks it: `GET /v1/hypervisor/machines/:workload` answers `head`, or 404 before the first
/// admitted operation, which is the genesis head by the plane's own definition.
async function currentHead() {
  const res = await fetch(`${BASE}/v1/hypervisor/machines/vm_conformance`);
  if (res.status === 404) return GENESIS;
  const spine = await res.json();
  return typeof spine.machine?.head === "string" ? spine.machine.head : GENESIS;
}

async function submit(body, { authenticated = true } = {}) {
  const res = await fetch(`${BASE}/v1/hypervisor/machines/vm_conformance/operations`, {
    method: "POST", headers: { "content-type": "application/json", ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}) }, body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text };
}

async function main() {
  if (!fs.existsSync(daemonBinary)) {
    ok("the daemon binary exists (cargo build -p ioi-node --bin hypervisor-daemon)", false, daemonBinary);
    return;
  }
  const pid = await startDaemon(await freePort());
  ok("a real daemon is serving the machine-operation route", pid > 0, `pid ${pid}`);
  if (!pid) return;
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await fetch(`${BASE}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "machine-conformance-bootstrap-v1", email: "machine-conformance@ioi.local" }) });
    SESSION = (await boot.json().catch(() => ({}))).session_token ?? "";
  }
  ok("the operator bootstrap yields the session the proposals are submitted under (the route is identity-first)", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));
  const anonymous = await submit(proposal("create", HOSTED, { head: GENESIS, generation: 1 }), { authenticated: false });
  ok("an ANONYMOUS proposal is refused 401 request_principal_required before the contract is even validated — a mutation is admitted under a resolved principal or not at all",
    anonymous.status === 401 && anonymous.json?.reason === "request_principal_required", `${anonymous.status} ${anonymous.json?.reason ?? ""}`);

  // THE PORTABLE SUBSET, ON BOTH. The attached estate withholds the console, so "portable" means
  // portable where declared — which is the honest reading of a capability matrix.
  let admitted = 0;
  let head = GENESIS;
  let generation = 0;
  for (const verb of PORTABLE) {
    generation += 1;
    const r = await submit(proposal(verb, HOSTED, { head, generation }));
    if (r.json?.ok !== true || r.json?.state !== "succeeded") {
      ok(`the hosted backend runs '${verb}'`, false, JSON.stringify(r.json ?? r.text).slice(0, 200));
      break;
    }
    admitted += 1;
    head = await currentHead();
  }
  ok("the hosted reference backend runs the whole portable subset over the real route",
    admitted === PORTABLE.length, `${admitted}/${PORTABLE.length} verbs`);

  // THE IDENTITY IS THE DAEMON'S. Every proposal above sent `machine-operation://caller-chose-this`.
  const all = await (await fetch(`${BASE}/v1/hypervisor/machines/vm_conformance/operations`)).json();
  ok("the caller's proposed identity is discarded and the daemon's is minted",
    all.operations.length > 0
    && all.operations.every((o) => o.operation_ref.startsWith("machine-operation://hypervisor/vm_conformance/")),
    `${all.operations.length} record(s)`);
  ok("every record carries the submitter AS THE DAEMON RESOLVED IT from the session — a `user://` principal, never a member of the proposal",
    all.operations.every((o) => typeof o.submitted_by === "string" && o.submitted_by.startsWith("user://") && typeof o.submitted_at === "string"),
    all.operations[0]?.submitted_by ?? "—");

  // AN EXTENSION CELL RUNS ONLY WHERE DECLARED, and the other refuses with the DECLARATION's reason.
  const migrateOnHosted = await submit(proposal("migrate", HOSTED, { head: await currentHead(), generation: generation + 1 }));
  ok("migration is refused on the hosted backend, with the declaration's own reason_code",
    migrateOnHosted.json?.ok === false
    && migrateOnHosted.json?.reason === "capability_cell_unsupported"
    && String(migrateOnHosted.json?.detail ?? "").includes("backend_is_single_host"),
    String(migrateOnHosted.json?.detail ?? "").slice(0, 120));
  ok("a refusal still produces a RECEIPT — a refusal is an outcome, not an absence",
    typeof migrateOnHosted.json?.receipt_ref === "string");

  const consoleOnAttached = await submit(proposal("open_console", ATTACHED, { head: await currentHead(), generation: generation + 1 }));
  ok("the mirror image holds: the attached estate refuses the console it withholds",
    consoleOnAttached.json?.ok === false
    && String(consoleOnAttached.json?.detail ?? "").includes("attached_estate_withholds_console"));

  // A DRIFTED DECLARATION. Same ref, a hash the declaration no longer carries.
  const drifted = await submit(proposal("start", HOSTED, { head: await currentHead(), generation: generation + 1, hash: `sha256:${"e".repeat(64)}` }));
  ok("a declaration that drifted under the operation refuses BEFORE effect",
    drifted.json?.reason === "capability_declaration_drifted", String(drifted.json?.detail ?? "").slice(0, 120));

  // A STALE HEAD.
  const stale = await submit(proposal("stop", HOSTED, { head: GENESIS, generation: generation + 1 }));
  ok("a stale head refuses rather than acting on a view the caller no longer has",
    stale.json?.reason === "expected_head_stale", String(stale.json?.detail ?? "").slice(0, 120));

  // A DUPLICATE. Same idempotency key as an operation already applied.
  const first = proposal("reboot", HOSTED, { head: await currentHead(), generation: generation + 1 });
  const firstResult = await submit(first);
  const replay = { ...first, expected_head: await currentHead() };
  const replayResult = await submit(replay);
  ok("a replayed idempotency key refuses rather than taking effect twice",
    firstResult.json?.ok === true && replayResult.json?.reason === "operation_already_applied",
    `${firstResult.json?.state} then ${replayResult.json?.reason}`);

  // AN AMBIGUOUS EXTERNAL OUTCOME, on the backend that declares migration.
  const ambiguous = await submit(proposal("migrate", ATTACHED, { head: await currentHead(), generation: generation + 2 }));
  ok("an unconfirmable external completion is recorded as AMBIGUOUS rather than guessed either way",
    ambiguous.json?.ok === true && ambiguous.json?.state === "ambiguous",
    JSON.stringify(ambiguous.json ?? {}).slice(0, 160));

  // THE EXECUTOR'S FENCE. A live backend is admitted and NOT executed.
  const live = await submit(proposal("start", LIVE_BACKEND, { head: await currentHead(), generation: generation + 3 }));
  ok("a NON-SIMULATED backend is admitted and left awaiting effect — the reference executor refuses to answer for a real one",
    live.json?.ok === true && live.json?.state === "admitted_awaiting_effect"
    && live.json?.receipt_ref === null
    && String(live.json?.detail ?? "").includes("reference_executor_refuses_non_simulated_backend"),
    String(live.json?.detail ?? "").slice(0, 140));

  // EVERY RECEIPT WRITTEN IS A VALID RECEIPT.
  const receiptDir = path.join(dataDir, "machine-operation-receipts");
  const receipts = fs.existsSync(receiptDir)
    ? fs.readdirSync(receiptDir).filter((f) => f.endsWith(".json"))
        .map((f) => JSON.parse(fs.readFileSync(path.join(receiptDir, f), "utf8")))
    : [];
  ok("every receipt the plane wrote carries a typed reason whenever it is not a success",
    receipts.length > 0 && receipts.every((r) =>
      r.result === "succeeded" ? true : typeof r.result_reason === "string" && r.result_reason.length > 0),
    `${receipts.length} receipt(s)`);
  ok("a refusal names no backend operation, because it never reached one",
    receipts.filter((r) => r.result === "refused").length > 0
    && receipts.filter((r) => r.result === "refused").every((r) => r.backend_native_operation_id === null));
  ok("an ambiguous receipt advances NEITHER generation",
    receipts.filter((r) => r.result === "ambiguous").every((r) =>
      r.desired_generation_after === r.desired_generation_before
      && r.observed_generation_after === r.observed_generation_before));
}

main()
  .catch((error) => { ok("conformance run completed", false, String(error?.message || error)); })
  .finally(() => {
    cleanup();
    const failed = RESULTS.filter((r) => !r.pass);
    console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"} check:machine-lifecycle-backend-conformance — ${RESULTS.length - failed.length}/${RESULTS.length} assertion(s)`
      + (failed.length ? ` · failing: ${failed.map((r) => r.label).join(" | ")}` : ""));
    console.log("OUTSTANDING for M09.11, and NOT claimed by this run: attachments, console scope, "
      + "crash/restart reconstruction and cleanup (ACC-20 clauses 6 and 7) have no surfaces yet — "
      + "there is one route here, not a machine plane. Profile qualification is a separate claim "
      + "this evidence may never make: both reference backends declare `evidence_mode: simulated`.");
    process.exit(failed.length === 0 ? 0 : 1);
  });
