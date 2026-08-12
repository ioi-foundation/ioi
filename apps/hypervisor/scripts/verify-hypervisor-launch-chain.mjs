// verify-hypervisor-launch-chain — W3.1 the shared harness-session launch chain
// (check:launch-chain). Proves, live against an ISOLATED daemon + serve pair, that the typed
// Launch producer composes §6.1 steps 4-11 into ONE identity-first, receipted, idempotent,
// recoverable chain over exactly one owned Session — and that denial and missing authority
// fabricate no launch, record, receipt, or subject attachment.
//
// Named `-chain` (not `-journey`): the chain owns admission → thread/event → managed-session +
// subject attachment → launch-recipe → harness-binding → readiness → spawn/terminal-attach →
// stop/archive → daemon kill/restart → recovery/replay. Live model-driven execution (streamed
// tokens) is the W3.2 provider-runtime dependency behind POST /v1/hypervisor/sessions/:id/execute
// and is asserted here only as the honest readiness boundary, never fabricated.
//
// What it proves:
//   - the typed HarnessSessionLaunch producer family is LIVE at /v1 (the flipped absence);
//   - exactly ONE admitted Session, then exactly ONE launch composing every step's canonical ref
//     + receipt; the real kernel planners (launch-recipe / harness-binding / terminal-attach) admit;
//   - the REAL typed daemon-resolved subject attachment is materialized onto the Session record
//     (anti-masquerade: subject_kind/subject_ref/attachment_role resolved by the daemon);
//   - identity-first negatives (rule E): anon produce/stop/archive answer 401 before any record
//     load; a launch on an unknown/unowned Session 404s and fabricates nothing;
//   - idempotent replay-to-stored-record; expected-head CAS on stop/archive (stale refuses typed);
//   - stop then archive terminalize visibly with principal-bound receipts (INV-37) + lineage;
//   - daemon kill/restart → recovery/replay converges byte-identical on refs + receipts + the
//     materialized subject attachment.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-launch-chain-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const LAUNCHES = "/v1/hypervisor/harness-session-launches";

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

// Daemon JSON — cookie=true carries the operator session; cookie=false is the anonymous lane.
const jd = (p, init, cookie = true, extraHeaders = {}) => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    ...extraHeaders,
  },
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const sessGet = async (ref) => (await jd(`/v1/hypervisor/sessions/${encodeURIComponent(ref)}`)).body?.session || null;

// Durable receipt on disk by kind + launch/session ref (INV-37 reads the DURABLE receipt, not the
// response projection).
const readReceiptByKind = (kind, launchRef) => {
  try {
    for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8"));
        if (j.kind === kind && (!launchRef || j.launch_ref === launchRef)) return j;
      } catch { /* not JSON */ }
    }
  } catch { /* no receipts yet */ }
  return null;
};

const countSessionRecords = () => {
  try {
    return fs.readdirSync(path.join(dataDir, "sessions")).filter((f) => f.endsWith(".json")).length;
  } catch { return 0; }
};

// Read every durable record persisted under a daemon family directory (the receipt-census pattern):
// returns [{ file, text, json }] so an assertion can scan the PERSISTED bytes, not just an HTTP body.
const readFamilyRecords = (family) => {
  const out = [];
  try {
    for (const f of fs.readdirSync(path.join(dataDir, family))) {
      if (!f.endsWith(".json")) continue;
      const text = fs.readFileSync(path.join(dataDir, family, f), "utf8");
      let json = null; try { json = JSON.parse(text); } catch { /* keep raw */ }
      out.push({ file: f, text, json });
    }
  } catch { /* no such family yet */ }
  return out;
};

// Canonical JSON with recursively SORTED object keys + compact separators — byte-matches Rust
// serde_json::to_vec over a serde_json::Value (BTreeMap-backed: keys serialize sorted), so the
// frozen-revision sha256 can be INDEPENDENTLY recomputed here and compared for EXACTNESS.
// LATENT FRAGILITY (not reachable today, one schema change from silently breaking):
//  - number encoding: JSON.stringify(1) === "1" but serde_json encodes an integer-valued f64 as
//    "1.0"; the hashed material is currently all strings / bools / string-arrays, so no numbers
//    reach this path. A numeric field entering the material would diverge.
//  - key ordering: Object.keys().sort() orders by UTF-16 code units; Rust BTreeMap orders by UTF-8
//    bytes. They agree across the BMP but diverge for keys above U+FFFF — none exist here.
// The material shape below is HAND-DUPLICATED from the daemon's harness_profile_frozen_revision();
// both sides must be edited together, and LAUNCH_SCHEMA_ALLOWLIST updated, when the shape changes.
const canonicalJson = (v) => {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
};
const sha256Hex = (s) => crypto.createHash("sha256").update(s).digest("hex");

// Recompute the daemon's frozen harness-profile revision from a profile record's ACTUAL content,
// mirroring harness_profile_frozen_revision(): material = the exact fields + jcs-sha256 idiom.
const recomputeFrozenRevision = (prof) => {
  const harness = (typeof prof.harness === "string" && prof.harness) ? prof.harness : "hypervisor_worker";
  const material = {
    schema_version: "ioi.hypervisor.harness-profile-frozen-revision-jcs-sha256.v1",
    profile_ref: prof.profile_ref ?? null,
    profile_id: prof.profile_id ?? null,
    harness,
    adapter: prof.adapter ?? null,
    capabilities: prof.capabilities ?? null,
    model_binding: prof.model_binding ?? null,
    lifecycle_status: prof.lifecycle?.status ?? null,
  };
  const contentHash = `sha256:${sha256Hex(canonicalJson(material))}`;
  const harnessSlug = harness.replace(/[^A-Za-z0-9]/gu, "-");
  return { revisionRef: `harness-profile://daemon-resolved/${harnessSlug}/revision/${contentHash}`, contentHash };
};

// VALUE allowlists — defence in depth BEHIND the M5b key-set close (chain additionalProperties:false
// below). These prove approved vocab appears only on approved key names; they are NOT the security
// boundary (a shadow built from only-allowlisted values on a NEW key is stopped by the key-set close,
// not here). A denylist would be defeated by any rename (into ioi.hypervisor.*, a `_v2` suffix, a
// renamed event_kind); the allowlist instead pins the exact set of values a correct launch RECORD
// emits. Every entry is verified per-entry as actually emitted into the durable record/response;
// LAUNCH_SCHEMA_ALLOWLIST and the daemon-side material shape must be edited together when a schema
// legitimately changes (see the recomputeFrozenRevision note).
const LAUNCH_SCHEMA_ALLOWLIST = new Set([
  // launch-family wrapper tags (this PR)
  "ioi.hypervisor.harness_session_launch.v1",
  "ioi.hypervisor.harness_session_launch_plan.v1",
  "ioi.hypervisor.harness_session_launch_thread.v1",
  "ioi.hypervisor.harness_session_launch_event_ref.v1",
  "ioi.hypervisor.harness_session_launch_fork_step.v1",
  "ioi.hypervisor.harness_session_launch_managed_session_step.v1",
  "ioi.hypervisor.harness_session_launch_projection.v1",
  // (harness_session_launch_events.v1 dropped: it is only the /events ENVELOPE schema — it appears in
  // neither the durable record nor the produce response that this allowlist scans, so per "every entry
  // must be demonstrably emitted into a scanned surface" it is not carried here.)
  // real composed kernel admissions / records the launch legitimately embeds (NOT second spine),
  // verified per-entry as actually emitted into the durable launch record (the recipe/binding REQUEST
  // schemas were dropped as dead — they exist only in the in-memory planner requests, never persisted)
  "ioi.runtime.harness_session_binding_admission.v1",
  "ioi.runtime.harness_session_readiness.v1",
  "ioi.runtime.harness_session_spawn.v1",
  "ioi.runtime.harness_session_terminal_attach.v1",
  "ioi.runtime.harness_terminal_transcript_projection.v1",
  "ioi.runtime.hypervisor_session_launch_recipe_admission.v1",
]);
// Kernel-NATIVE schema(s) the launch's admitted thread events carry ON THE STREAM (distinct from the
// record's launch-family wrapper tags): runtime thread events are kernel event metadata under the
// kernel's own generic runtime-event schema, never a launch-family mint.
const STREAM_SCHEMA_ALLOWLIST = new Set(["ioi.runtime.event.v1"]);
// control_state / event_kind values a REAL kernel planner can legitimately emit. These are kept even
// though a clean no-delegation launch does not exercise them: a delegation-SUCCESS fork emits
// thread.forked, and a launch on a thread with a real managed session emits managed_session.controlled
// with an observe|take_over|return_agent control_state. Dropping them would false-positive real
// planner output the first time those paths run. (Value-allowlisting is no longer the security
// boundary — chain KEY-SET closure below is — so keeping the legitimate set is safe.)
const CONTROL_STATE_ALLOWLIST = new Set(["observe", "take_over", "return_agent"]);
const EVENT_KIND_ALLOWLIST = new Set(["thread.started", "harness_session.spawned", "thread.forked", "managed_session.controlled"]);
// The EXACT key sets (additionalProperties:false, sorted) a correct launch record carries at every
// level a second spine could hide — top-level record, chain, and the two provenance-bearing steps.
// A fabricated sibling fails on mere PRESENCE of an unexpected KEY, whatever allowlisted values it
// hides inside. Pinned from a clean run's DURABLE record (the assertions flag any drift).
// The top-level key set is PATH-DEPENDENT: launch_terminalize (stop/archive) MUTATES it, adding
// `lineage` + `{state}_at`. So the pin is STATE-AWARE — a strict-equality pin per lifecycle stage,
// checked against the durable record at each stage. A top-level shadow at ANY stage → RED.
const EXPECTED_LAUNCH_RECORD_KEYS_PRODUCED = ["acting_principal_ref", "chain", "created_at", "environment_ref", "head", "idempotency_key", "launch_id", "launch_ref", "lifecycle_state", "owner_ref", "receipt_refs", "request_hash", "revision", "runtimeTruthSource", "schema_version", "session_harness_binding", "session_model_route_binding", "session_ref", "workspace_root"];
const EXPECTED_LAUNCH_RECORD_KEYS_STOPPED = [...EXPECTED_LAUNCH_RECORD_KEYS_PRODUCED, "lineage", "stopped_at"].sort();
const EXPECTED_LAUNCH_RECORD_KEYS_ARCHIVED = [...EXPECTED_LAUNCH_RECORD_KEYS_STOPPED, "archived_at"].sort();
const EXPECTED_CHAIN_KEYS = ["first_runtime_event", "fork", "harness_binding_admission", "harness_binding_evidence", "launch_recipe_admission", "managed_session", "plan_admission", "readiness", "spawn", "subject_attachments", "terminal_attach", "thread"];
const EXPECTED_FORK_KEYS = ["decision", "fork_planner", "note", "schema_version"];
const EXPECTED_MANAGED_SESSION_KEYS = ["available_control_states", "control_planner", "decision", "note", "schema_version"];
// Structural walk of a parsed value → offending typed values, against a supplied schema allowlist.
const structuralViolations = (v, schemaAllow, out = []) => {
  if (v === null || typeof v !== "object") return out;
  if (Array.isArray(v)) { for (const x of v) structuralViolations(x, schemaAllow, out); return out; }
  for (const [k, val] of Object.entries(v)) {
    if ((k === "schema_version" || k === "payload_schema_version") && typeof val === "string" && !schemaAllow.has(val)) out.push(`${k}=${val}`);
    if (k === "control_state" && typeof val === "string" && !CONTROL_STATE_ALLOWLIST.has(val)) out.push(`control_state=${val}`);
    if ((k === "event_kind" || k === "kind") && typeof val === "string" && !EVENT_KIND_ALLOWLIST.has(val)) out.push(`${k}=${val}`);
    structuralViolations(val, schemaAllow, out);
  }
  return out;
};
// Raw-bytes backstop (V1c): a record corrupted-unparseable while still carrying kernel tokens in its
// bytes would parse to null and slip the parsed walk. Extract the same typed values by regex from the
// raw text and apply the SAME allowlists, so a token in the bytes fails regardless of parseability.
// M6b: JSON-unescape the bytes first (\" and ") so an ESCAPED key `\"schema_version\"` cannot
// slip the literal-keyed regex.
const rawViolations = (text) => {
  const norm = text.replace(/\\u0022/giu, '"').replace(/\\"/gu, '"');
  const out = [];
  for (const m of norm.matchAll(/"(?:payload_)?schema_version"\s*:\s*"([^"]*)"/gu)) if (!LAUNCH_SCHEMA_ALLOWLIST.has(m[1])) out.push(`raw schema=${m[1]}`);
  for (const m of norm.matchAll(/"control_state"\s*:\s*"([^"]*)"/gu)) if (!CONTROL_STATE_ALLOWLIST.has(m[1])) out.push(`raw control_state=${m[1]}`);
  for (const m of norm.matchAll(/"(?:event_kind|kind)"\s*:\s*"([^"]*)"/gu)) if (!EVENT_KIND_ALLOWLIST.has(m[1])) out.push(`raw ${m[1]}`);
  return out;
};

// Test-window time anchor: a real recheck timestamp lands inside the run, not merely "not 1970".
const runStartMs = Date.now();
const withinTestWindow = (iso) => {
  const t = Date.parse(iso);
  return Number.isFinite(t) && t >= runStartMs - 300000 && t <= Date.now() + 300000;
};

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "launch-chain-bootstrap-v1", email: "launch-chain@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // -- the typed Launch producer family is now LIVE at /v1 (the flipped absence) ----------------
  const index = await jd("/v1");
  const idxStr = JSON.stringify(index.body);
  const launchPaths = (index.body.families ?? [])
    .flatMap((family) => family.paths ?? []).map((row) => row.path)
    .filter((p) => p.startsWith("/v1/hypervisor/harness-session-launches"))
    .sort();
  ok("the typed HarnessSessionLaunch producer family is LIVE: produce + get + events + stop + archive routes exist (the W3.1 flip of the typed-absence pin)",
    JSON.stringify(launchPaths) === JSON.stringify([
      "/v1/hypervisor/harness-session-launches",
      "/v1/hypervisor/harness-session-launches/:id",
      "/v1/hypervisor/harness-session-launches/:id/archive",
      "/v1/hypervisor/harness-session-launches/:id/events",
      "/v1/hypervisor/harness-session-launches/:id/stop",
    ]),
    launchPaths.join(" "));
  ok("the composed admission planners it consumes remain their canonical owners (recipe/binding/terminal-attach)",
    idxStr.includes("/v1/hypervisor/session-launch-recipe-admissions")
      && idxStr.includes("/v1/hypervisor/harness-session-binding-admissions")
      && idxStr.includes("/v1/hypervisor/harness-session-terminal-attachments"));

  // -- identity-first negatives (rule E): anon writes refuse BEFORE any record load -------------
  const anonProduce = await jd(LAUNCHES, { method: "POST", body: JSON.stringify({ session_ref: "session:does-not-exist" }) }, false);
  ok("anonymous produce answers typed 401 request_principal_required before any record load (rule E — no existence oracle)",
    anonProduce.status === 401 && anonProduce.body?.error?.code === "request_principal_required",
    `${anonProduce.status} ${anonProduce.body?.error?.code}`);
  const anonStop = await jd(`${LAUNCHES}/whatever/stop`, { method: "POST", body: JSON.stringify({ expected_head: "x" }) }, false);
  ok("anonymous stop answers typed 401 before the record load", anonStop.status === 401 && anonStop.body?.error?.code === "request_principal_required", `${anonStop.status}`);
  const anonArchive = await jd(`${LAUNCHES}/whatever/archive`, { method: "POST", body: JSON.stringify({ expected_head: "x" }) }, false);
  ok("anonymous archive answers typed 401 before the record load", anonArchive.status === 401 && anonArchive.body?.error?.code === "request_principal_required", `${anonArchive.status}`);

  // -- create EXACTLY ONE admitted Session ------------------------------------------------------
  const create = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: "project:ioi", initial_input: "launch chain proof" }) });
  const sessionRef = create.body?.session_ref;
  ok("exactly one admitted Session is created (202 + provision receipt + daemon-resolved owner)",
    create.status === 202 && typeof sessionRef === "string" && sessionRef.startsWith("session:")
      && String(create.body?.receipt_ref || "").startsWith("receipt://hypervisor/session-provision/"),
    `${create.status} ${sessionRef}`);
  const sessionsBeforeLaunch = countSessionRecords();
  ok("the Session's subject_attachments are EXACTLY [] at create (attachment materializes only at launch — no masquerade at create)",
    Array.isArray(create.body?.subject_attachments) && create.body.subject_attachments.length === 0);

  // -- a launch on an UNOWNED/unknown Session fabricates nothing ---------------------------------
  const missing = await jd(LAUNCHES, { method: "POST", body: JSON.stringify({ session_ref: "session:not-mine-abcdef" }) });
  ok("a launch on an unknown/unowned Session answers typed 404 and fabricates no launch",
    missing.status === 404 && missing.body?.error?.code === "session_not_found",
    `${missing.status} ${missing.body?.error?.code}`);

  // -- produce the launch: compose §6.1 steps 4-11 ----------------------------------------------
  const produce = await jd(LAUNCHES, { method: "POST", body: JSON.stringify({ session_ref: sessionRef }) });
  const launch = produce.body;
  const launchRef = launch?.launch_ref;
  const launchId = launch?.launch_id;
  ok("produce returns 200 with the launch ref, launched lifecycle, and a principal-bound receipt",
    produce.status === 200 && typeof launchRef === "string" && launchRef.startsWith("harness-session-launch:")
      && launch?.lifecycle_state === "launched"
      && String(launch?.receipt_ref || "").startsWith("receipt://hypervisor/harness-session-launch/produced/"),
    `${produce.status} ${launch?.lifecycle_state}`);
  const steps = launch?.chain_step_refs || {};
  ok("every §6.1 step names a canonical ref: plan · thread · initial thread event · launch-recipe · harness-binding · readiness · spawn · terminal-attach · first runtime event",
    typeof steps.plan_ref === "string" && steps.plan_ref.startsWith("harness-session-launch-plan:")
      && typeof steps.thread_ref === "string" && steps.thread_ref.startsWith("thread:launch-")
      && typeof steps.thread_event_ref === "string" && steps.thread_event_ref.includes("/opened")
      && typeof steps.launch_recipe_ref === "string" && steps.launch_recipe_ref.startsWith("target-binding:")
      && typeof steps.harness_binding_ref === "string" && steps.harness_binding_ref.startsWith("harness-session-binding:")
      && typeof steps.readiness_ref === "string" && steps.readiness_ref.startsWith("readiness:")
      && typeof steps.spawn_ref === "string" && steps.spawn_ref.startsWith("spawn:")
      // Assert the ACTUAL terminal-attach ref shape, not the launch_step_ref schema_version fallback
      // (a kernel rename would otherwise leave this passing on a schema-version string).
      && typeof steps.terminal_attach_ref === "string" && steps.terminal_attach_ref.startsWith("harness-session-terminal-attach:")
      && typeof steps.first_runtime_event_ref === "string" && steps.first_runtime_event_ref.includes("/spawned"),
    JSON.stringify(steps));

  // Load the DURABLE launch record ONCE, early — it is RECOVERY TRUTH (what the daemon serves after
  // restart). The provenance and key-set assertions below read from it, so a durable-only forgery
  // (response sanitized, disk fabricated) cannot pass.
  const persistedLaunches = readFamilyRecords("harness-session-launches");
  const mainRecord = persistedLaunches.map((r) => r.json).find((j) => j && j.launch_id === launchId);

  // -- Finding 1: the thread / fork / managed-session facts are the REAL kernel planners' output or
  //    an honest typed absence. The gate catches #252's second spine two independent ways: (i) the
  //    composed launch-family SHAPE no longer wears a kernel schema name (positive presence-and-value
  //    assertions), and (ii) the substrate is read back INDEPENDENTLY — the initial event is proven
  //    on the real agentgres stream at its substrate-stamped seq, and the durable record is scanned
  //    structurally — so a well-formed literal cannot masquerade as a real admission. --------------
  ok("Finding 1 (step 5): the initial thread event is the kernel `thread.started` event with a substrate-stamped seq (0-indexed), a substrate_head field, and an agentgres operation ref — NOT a launch-family `runtime.thread.opened` vocabulary (that seq/head/op-ref are the SUBSTRATE's real values, not literals, is PROVEN by the /events cross-check below)",
    steps.thread_event_kind === "thread.started"
      && Number.isInteger(steps.thread_event_seq) && steps.thread_event_seq >= 0
      && typeof steps.thread_event_substrate_head === "string" && steps.thread_event_substrate_head.length > 0
      && typeof steps.thread_event_operation_ref === "string" && steps.thread_event_operation_ref.length > 0,
    `${steps.thread_event_kind} seq=${steps.thread_event_seq} head=${steps.thread_event_substrate_head}`);

  // -- Hardening (Finding A): those admission fields are SELF-REPORTED by the launch record. Read the
  //    event BACK from the substrate via /events (which replays agentgres, not the launch record) and
  //    prove the produced event_id is on the stream at the substrate-stamped seq the launch reported,
  //    carrying an agentgres operation ref. The substrate `seq` — not the kernel content-hash
  //    `resulting_head` — is admission truth; a literal in the launch record cannot conjure it. -----
  const streamAfterProduce = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}/events`);
  const streamEvents = streamAfterProduce.body?.events || [];
  const openedOnStream = streamEvents.find((e) => e.event_id === steps.thread_event_ref);
  const spawnedOnStream = streamEvents.find((e) => e.event_id === steps.first_runtime_event_ref);
  ok("Finding 1 (step 5) INDEPENDENT READBACK: the event named by thread_event_ref is actually on the real kernel stream, and the launch record's self-reported seq, substrate_head, AND agentgres_operation_ref each EQUAL the substrate's own values read back from /events; the spawned event follows at a higher seq — a fabricated head/op-ref or a constant literal in the launch record goes RED here",
    streamAfterProduce.status === 200
      && openedOnStream != null
      && openedOnStream.event_kind === "thread.started"
      && openedOnStream.seq === steps.thread_event_seq
      && typeof openedOnStream.agentgres_operation_ref === "string" && openedOnStream.agentgres_operation_ref.length > 0
      && openedOnStream.agentgres_operation_ref === steps.thread_event_operation_ref
      && typeof openedOnStream.substrate_head === "string" && openedOnStream.substrate_head.length > 0
      && openedOnStream.substrate_head === steps.thread_event_substrate_head
      && spawnedOnStream != null && spawnedOnStream.event_kind === "harness_session.spawned" && spawnedOnStream.seq > openedOnStream.seq,
    openedOnStream ? `opened seq=${openedOnStream.seq} head=${openedOnStream.substrate_head} op=${openedOnStream.agentgres_operation_ref}` : "event NOT found on stream");

  // -- Negative isolation (a): the kernel stream carries KERNEL-NATIVE events only, and no launch
  //    record. The launch's thread events are admitted under the kernel's own runtime-event schema
  //    (ioi.runtime.event.v1) — NOT a launch-family payload_schema_version — and no chain record
  //    reaches the stream. The stream events are themselves ALLOWLIST-SCANNED (payload schema ∈ the
  //    kernel-native stream allowlist; event_kind ∈ the composed kinds), closing the gap where the
  //    old launch-family `harness-session-launch-thread-event.v1` name evaded a record-only scan. --
  const streamShadow = streamEvents.flatMap((e) => structuralViolations(e, STREAM_SCHEMA_ALLOWLIST));
  ok("negative isolation (a): every event on the real kernel stream is a kernel-native runtime event (payload_schema_version ioi.runtime.event.v1, a kernel schema NOT a launch-family mint), event_kind ∈ {thread.started, harness_session.spawned}, and no launch record (chain/plan_admission/subject_attachments/harness_binding_admission or ioi.hypervisor.harness_session_launch* schema) reaches the stream",
    streamEvents.length >= 1
      && streamEvents.every((e) => ["thread.started", "harness_session.spawned"].includes(e.event_kind))
      && streamEvents.every((e) => e.payload_schema_version === "ioi.runtime.event.v1")
      && streamShadow.length === 0
      && !streamEvents.some((e) => e.chain != null || e.plan_admission != null || e.subject_attachments != null || e.harness_binding_admission != null || String(e.schema_version || "").startsWith("ioi.hypervisor.harness_session_launch")),
    streamShadow.length ? streamShadow.join(" | ") : `${streamEvents.length} kernel-native event(s): ${streamEvents.map((e) => e.event_kind).join(",")}`);

  // -- Negative isolation (b): the REAL managed-session control route refuses a launch thread ref. --
  const shadowControl = await jd(`/v1/threads/${encodeURIComponent(steps.thread_ref)}/managed-sessions/control`, { method: "POST", body: JSON.stringify({ managed_session_id: `managed-session:${launchId}`, control_state: "observe" }) });
  ok("negative isolation (b): the REAL managed-session control route (POST /v1/threads/<launch-thread>/managed-sessions/control) REFUSES for the launch thread ref — read_agent_for_thread 404s first, so a crafted POST cannot ride the launch shadow into the kernel control planner",
    shadowControl.status === 404, `${shadowControl.status}`);
  // K2D — the provenance (decision + control_planner + schema) is read from the DURABLE record (the
  // recovery truth the daemon serves after restart), NOT just the produce-time response; a durable-only
  // substitution (response reads no_managed_session_at_launch while disk reads decision:"admitted",
  // control_planner:"none_no_planner_ran") goes RED. The response is separately asserted to EQUAL the
  // durable provenance, so a divergence in either direction fails.
  const durFork = mainRecord?.chain?.fork || {};
  const durManaged = mainRecord?.chain?.managed_session || {};
  ok("Finding 1 (step 6) — DURABLE provenance: the on-disk fork step is the typed launch-family absence (schema_version=…_fork_step.v1, decision=not_requested), and the response fork EQUALS the durable fork — a durable-only forgery fails",
    durFork.schema_version === "ioi.hypervisor.harness_session_launch_fork_step.v1"
      && durFork.decision === "not_requested"
      && JSON.stringify(launch?.fork) === JSON.stringify(durFork),
    JSON.stringify(durFork));
  ok("Finding 1 (step 7) — DURABLE provenance: the on-disk managed-session step is the typed absence naming the REAL control planner (decision=no_managed_session_at_launch, control_planner=plan_runtime_managed_session_control_from_replayed_events), and the response managed_session EQUALS the durable one — a durable-only substitution (decision:\"admitted\" on disk) goes RED",
    durManaged.schema_version === "ioi.hypervisor.harness_session_launch_managed_session_step.v1"
      && durManaged.decision === "no_managed_session_at_launch"
      && durManaged.control_planner === "plan_runtime_managed_session_control_from_replayed_events"
      && JSON.stringify(launch?.managed_session) === JSON.stringify(durManaged),
    JSON.stringify(durManaged));
  // CLOSED-WORLD OVER KEYS at every level a second spine can hide (all read from the DURABLE record):
  //   M5b — chain siblings;  K3 — top-level siblings (outside chain);  K1 — nested siblings inside the
  //   two provenance-bearing steps (fork / managed_session). Value allowlists prove approved vocab on
  //   approved key NAMES; only the KEY-SET equality proves the key SET is expected, so a shadow built
  //   from ONLY allowlisted values fails on mere PRESENCE of any unexpected key, whatever it hides.
  const keysOf = (o) => (o && typeof o === "object" && !Array.isArray(o)) ? Object.keys(o).sort() : null;
  const eqKeys = (o, expected) => { const k = keysOf(o); return k != null && JSON.stringify(k) === JSON.stringify(expected); };
  ok("K3 (top-level closed-world, AT PRODUCE): the durable launch record's TOP-LEVEL key set EQUALS the pinned produced set (additionalProperties:false) — a sibling OUTSIDE chain (launch_record.shadow_*) fails on PRESENCE (the stopped/archived stages are pinned separately after terminalization)",
    eqKeys(mainRecord, EXPECTED_LAUNCH_RECORD_KEYS_PRODUCED),
    keysOf(mainRecord)?.join(",") || "no durable record");
  ok("M5b (chain closed-world): the durable record's `chain` key set EQUALS the pinned expected set — a chain sibling (chain.shadow_managed_session) fails on PRESENCE, whatever allowlisted values it hides",
    eqKeys(mainRecord?.chain, EXPECTED_CHAIN_KEYS),
    keysOf(mainRecord?.chain)?.join(",") || "no chain");
  ok("K1 (nested closed-world): the durable `chain.fork` and `chain.managed_session` key sets — the two steps carrying planner provenance — EQUAL their pinned expected sets, so a nested shadow (chain.managed_session.shadow_control) fails on PRESENCE",
    eqKeys(mainRecord?.chain?.fork, EXPECTED_FORK_KEYS) && eqKeys(mainRecord?.chain?.managed_session, EXPECTED_MANAGED_SESSION_KEYS),
    `fork=[${keysOf(mainRecord?.chain?.fork)}] managed=[${keysOf(mainRecord?.chain?.managed_session)}]`);

  // SAFETY — STRUCTURAL value scan (defence in depth behind the key-set close): every schema_version /
  // payload_schema_version / control_state / event_kind must be an allowlisted value (a rename into
  // ioi.hypervisor.*, a _v2 suffix, control_state:"admitted", a bad event_kind → shadow). Run over the
  // HTTP response AND the durable on-disk record (parsed walk + raw-bytes backstop with M6b unescape,
  // so a corrupt-unparseable record — even one with ESCAPED keys — still FAILS).
  const responseShadow = structuralViolations(launch, LAUNCH_SCHEMA_ALLOWLIST);
  ok("SAFETY (response, value allowlist): every schema_version is a legit launch-family/composed-admission tag, every control_state ∈ {observe,take_over,return_agent}, every event_kind is a composed thread lifecycle kind — anything else is a second-spine shadow",
    responseShadow.length === 0,
    responseShadow.length ? responseShadow.join(" | ") : "clean");
  const persistedShadow = persistedLaunches.flatMap((r) => [...structuralViolations(r.json, LAUNCH_SCHEMA_ALLOWLIST), ...rawViolations(r.text || "")]);
  ok("SAFETY (durable, value allowlist + raw backstop): the same value scan over the PERSISTED launch record(s) on disk — parsed walk AND a raw-bytes regex backstop (JSON-unescaped first) — finds NO out-of-allowlist value; a response that sanitizes while the durable record still wears a kernel token, or a corrupt-unparseable/escaped-key record carrying tokens, FAILS here",
    persistedLaunches.length >= 1
      && persistedLaunches.some((r) => (r.text || "").includes(launchId))
      && persistedShadow.length === 0,
    persistedShadow.length ? persistedShadow.join(" | ") : `${persistedLaunches.length} record(s) clean`);

  // -- Finding 2: the harness binding names a REAL seeded hp_* profile + its EXACT frozen revision,
  //    and model-route availability was RECHECKED at the launch boundary (not a static literal). ----
  const profiles = await jd("/v1/hypervisor/harness-profiles");
  const profilesStr = JSON.stringify(profiles.body);
  ok("Finding 2: the bound profile `hp_hypervisor_worker` is a REAL registry hp_* profile (it resolves), while the #252 `default_harness_profile` is ABSENT from the registry",
    profilesStr.includes("hp_hypervisor_worker") && !profilesStr.includes("default_harness_profile"),
    `hp_hypervisor_worker present=${profilesStr.includes("hp_hypervisor_worker")}`);
  const bindingEvidence = launch?.harness_binding_evidence || {};
  const workerProfile = readFamilyRecords("harness-profile-registry")
    .map((r) => r.json)
    .find((p) => p && p.profile_id === "hp_hypervisor_worker");
  // Hardening (Finding B.2/B.3): prove the launch RESOLVED the real registry record (the fallback
  // stub path was NOT taken) and named THAT record's own profile_id — not a compile-time constant.
  ok("Finding 2 (resolved, not stub): the launch resolved a real registry hp_* record (harness_profile_resolved=true) and its harness_profile_ref equals the RESOLVED record's own profile_id — the #23115 fallback-stub path was NOT taken; `default_harness_profile` is absent from the registry",
    bindingEvidence.harness_profile_resolved === true
      && workerProfile != null
      && bindingEvidence.harness_profile_ref === workerProfile.profile_id
      && steps.harness_profile_resolved === true,
    `resolved=${bindingEvidence.harness_profile_resolved} ref=${bindingEvidence.harness_profile_ref}`);
  // Hardening (Finding B.1): prove EXACTNESS, not well-formedness. Recompute the frozen revision from
  // the profile's ACTUAL on-disk content (the exact record the daemon froze) and compare — a stale,
  // fabricated, hard-coded, or stub-derived revision FAILS this, where a `startsWith`/`includes` shape
  // check would pass.
  const recomputed = workerProfile ? recomputeFrozenRevision(workerProfile) : null;
  ok("Finding 2 EXACTNESS: the frozen revision RECOMPUTED from hp_hypervisor_worker's actual on-disk content (jcs-sha256 over adapter/capabilities/model_binding/lifecycle) EQUALS the launch's revision ref AND content hash — a stale/fabricated/hard-coded/stub-derived revision fails this independent recomputation",
    recomputed != null
      && steps.harness_profile_revision_ref === recomputed.revisionRef
      && bindingEvidence.harness_profile_content_hash === recomputed.contentHash,
    recomputed ? `recomputed ${recomputed.contentHash} vs record ${bindingEvidence.harness_profile_content_hash}` : "profile not on disk");
  const recheck = bindingEvidence.model_route_recheck || {};
  ok("Finding 2: model-route availability was RECHECKED at the launch boundary with a real registry read (route resolved + admitted lifecycle read + a recheck timestamp INSIDE the test window) and the binding availability was DERIVED from it — not a static `daemon_verified` literal",
    recheck.recheck_source === "daemon-model-route-registry"
      && recheck.route_resolved === true
      && typeof recheck.registry_lifecycle_status === "string"
      && withinTestWindow(recheck.rechecked_at)
      && recheck.derived_binding_availability_state === "daemon_verified",
    JSON.stringify(recheck));
  ok("Finding 2 (availability CORRELATED, not hard-coded): the recheck actually READ registry_lifecycle_status=active AND DERIVED daemon_verified from it (asserted as the real values, not a biconditional that passes vacuously when both sides are false) — a mount read as non-active with a hard-coded daemon_verified fails the first conjunct",
    recheck.registry_lifecycle_status === "active" && recheck.derived_binding_availability_state === "daemon_verified",
    `${recheck.registry_lifecycle_status} => ${recheck.derived_binding_availability_state}`);
  ok("Finding 2: the recheck honestly carries live token reachability as FALSE (the mount is daemon-verified; live serving is the W3.2 execute dependency) — the binding never over-claims what the readiness admits",
    recheck.model_route_reachable === false && launch?.readiness?.observed_substrate?.model_route_reachable === false,
    `recheck=${recheck.model_route_reachable} readiness=${launch?.readiness?.observed_substrate?.model_route_reachable}`);

  ok("readiness is the honest client-PTY-attach gate: ready, and it carries the observed substrate probe rather than over-claiming a live model",
    launch?.readiness?.decision === "ready"
      && launch?.readiness?.readiness_state === "ready_for_harness_pty_attach"
      && launch?.readiness?.observed_substrate?.model_route_reachable === false,
    JSON.stringify(launch?.readiness?.decision));

  // -- the REAL typed daemon-resolved subject attachment materialized onto the Session -----------
  const attachments = launch?.subject_attachments || [];
  const primary = attachments.find((a) => a.attachment_role === "primary_execution");
  ok("the launch materializes a REAL typed daemon-resolved subject attachment (anti-masquerade: subject_kind/ref/role resolved by the daemon, never a caller-named app field)",
    Array.isArray(attachments) && attachments.length >= 1
      && primary && primary.subject_kind === "harness_session_launch"
      && primary.subject_ref === launchRef && primary.resolved_by === "daemon-runtime",
    JSON.stringify(attachments));
  const sessionAfter = await sessGet(sessionRef);
  ok("the owned Session record now carries the materialized subject attachment (subject_attachments flipped from [] to the daemon-resolved set)",
    Array.isArray(sessionAfter?.subject_attachments) && sessionAfter.subject_attachments.length >= 1
      && sessionAfter.subject_attachments.some((a) => a.subject_ref === launchRef),
    `${sessionAfter?.subject_attachments?.length} attachment(s)`);
  ok("no NEW session record was minted by the launch: the on-disk session count is UNCHANGED from before the launch (the launch hangs off the kernel-owned Session spine, not a second session family)",
    countSessionRecords() === sessionsBeforeLaunch, `delta 0 (before=${sessionsBeforeLaunch}, after=${countSessionRecords()})`);

  // -- Finding 1 (step 6), delegation REQUESTED: the fork routes the REAL kernel planner ---------
  // A delegation-requested launch routes plan_runtime_thread_fork_control; the launch thread has no
  // forkable source agent, so the planner's own refusal ladder answers with the SPECIFIC code
  // runtime_thread_fork_control_agent_replay_required and fabricates no admitted fork.
  const delegated = await jd(LAUNCHES, { method: "POST", body: JSON.stringify({
    session_ref: sessionRef,
    idempotency_key: "delegation-probe",
    delegation: { reason: "verifier delegation probe", bounds: { budget: "parent_bounded" } },
  }) });
  const delegatedFork = delegated.body?.fork || {};
  ok("Finding 1 (step 6) REAL PLANNER EXERCISE: a delegation-requested launch routes plan_runtime_thread_fork_control; with no forkable source agent on the launch thread the planner answers the SPECIFIC refusal runtime_thread_fork_control_agent_replay_required (not either-outcome), fabricates no admitted fork, and the response carries no second-spine token",
    delegated.status === 200
      && delegatedFork.fork_planner === "plan_runtime_thread_fork_control"
      && delegatedFork.decision === "refused"
      && delegatedFork.code === "runtime_thread_fork_control_agent_replay_required"
      && structuralViolations(delegated.body, LAUNCH_SCHEMA_ALLOWLIST).length === 0,
    `${delegatedFork.decision} · ${delegatedFork.code}`);

  // -- INV-37 durable receipt binds the acting principal ----------------------------------------
  const producedReceipt = readReceiptByKind("hypervisor.harness_session_launch.produced", launchRef);
  ok("the durable produced receipt binds acting_principal_ref to the real operator principal (INV-37), never user://local-operator, and its created_at lands inside the test window (a pinned anchor, not merely !1970)",
    producedReceipt && String(producedReceipt.acting_principal_ref || "").startsWith("user://")
      && producedReceipt.acting_principal_ref !== "user://local-operator"
      && withinTestWindow(producedReceipt.created_at),
    producedReceipt?.acting_principal_ref);

  // -- idempotent replay-to-stored-record -------------------------------------------------------
  const replay = await jd(LAUNCHES, { method: "POST", body: JSON.stringify({ session_ref: sessionRef }) });
  ok("re-producing the same launch replays the stored record (replayed=true) with byte-identical refs + receipts — no second effect",
    replay.status === 200 && replay.body?.replayed === true
      && replay.body?.launch_ref === launchRef && replay.body?.head === launch?.head
      && JSON.stringify(replay.body?.latest_receipt_refs) === JSON.stringify(launch?.latest_receipt_refs),
    `replayed=${replay.body?.replayed}`);

  // -- expected-head CAS on stop ----------------------------------------------------------------
  const getForHead = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}`);
  const head = getForHead.body?.head;
  ok("GET launch reads back the current head for compare-and-swap", typeof head === "string" && head.startsWith("sha256:"), head);
  const stopNoHead = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}/stop`, { method: "POST", body: JSON.stringify({}) });
  ok("stop without expected_head refuses typed (a terminalization must compare-and-swap)",
    stopNoHead.status === 400 && stopNoHead.body?.error?.code === "session_launch_expected_head_required", `${stopNoHead.status}`);
  const stopStale = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}/stop`, { method: "POST", body: JSON.stringify({ expected_head: "sha256:stale" }) });
  ok("stop with a stale expected_head refuses typed (session_launch_stale_head names the current head)",
    stopStale.status === 409 && stopStale.body?.error?.code === "session_launch_stale_head", `${stopStale.status}`);

  // -- stop terminalizes visibly with a principal-bound receipt ---------------------------------
  const stop = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}/stop`, { method: "POST", body: JSON.stringify({ expected_head: head }) });
  ok("stop with the correct head terminalizes to stopped, advances the head, and records a stop receipt",
    stop.status === 200 && stop.body?.lifecycle_state === "stopped" && stop.body?.head !== head
      && (stop.body?.latest_receipt_refs || []).some((r) => String(r).includes("/stopped/")),
    `${stop.status} ${stop.body?.lifecycle_state}`);
  const stopReceipt = readReceiptByKind("hypervisor.harness_session_launch.stopped", launchRef);
  ok("the durable stop receipt binds acting_principal_ref (INV-37)",
    stopReceipt && stopReceipt.acting_principal_ref === producedReceipt?.acting_principal_ref);
  const stopReplay = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}/stop`, { method: "POST", body: JSON.stringify({ expected_head: head }) });
  ok("re-stopping is idempotent (already-stopped replays without a second effect)",
    stopReplay.status === 200 && stopReplay.body?.lifecycle_state === "stopped" && stopReplay.body?.replayed === true, `${stopReplay.status}`);
  // K3 (state-aware, AFTER STOP): terminalize legitimately adds {lineage, stopped_at}; the durable
  // top-level key set must equal the STOPPED pin exactly — a shadow injected during terminalization
  // (also recovery truth) fails, and a legit stopped record passes.
  const stoppedRecord = readFamilyRecords("harness-session-launches").map((r) => r.json).find((j) => j && j.launch_id === launchId);
  ok("K3 (top-level closed-world, AFTER STOP): the durable record's top-level key set EQUALS the pinned STOPPED set (produced ∪ {lineage, stopped_at}) — a legit stopped record passes; a top-level shadow at this stage fails",
    eqKeys(stoppedRecord, EXPECTED_LAUNCH_RECORD_KEYS_STOPPED),
    keysOf(stoppedRecord)?.join(",") || "no stopped record");

  // -- archive terminalizes with lineage --------------------------------------------------------
  const stoppedHead = stop.body?.head;
  const archive = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}/archive`, { method: "POST", body: JSON.stringify({ expected_head: stoppedHead }) });
  ok("archive with the current head terminalizes to archived with a principal-bound receipt + lineage",
    archive.status === 200 && archive.body?.lifecycle_state === "archived"
      && (archive.body?.latest_receipt_refs || []).some((r) => String(r).includes("/archived/")),
    `${archive.status} ${archive.body?.lifecycle_state}`);
  const archiveReceipt = readReceiptByKind("hypervisor.harness_session_launch.archived", launchRef);
  ok("the durable archive receipt binds acting_principal_ref and names the previous head as lineage (INV-37 + terminal lineage)",
    archiveReceipt && archiveReceipt.acting_principal_ref === producedReceipt?.acting_principal_ref
      && archiveReceipt.previous_head === stoppedHead);
  // K3 (state-aware, AFTER ARCHIVE): archive adds {archived_at} on top of the stopped set.
  const archivedRecord = readFamilyRecords("harness-session-launches").map((r) => r.json).find((j) => j && j.launch_id === launchId);
  ok("K3 (top-level closed-world, AFTER ARCHIVE): the durable record's top-level key set EQUALS the pinned ARCHIVED set (stopped ∪ {archived_at}) — a legit archived record passes; a top-level shadow at this stage fails",
    eqKeys(archivedRecord, EXPECTED_LAUNCH_RECORD_KEYS_ARCHIVED),
    keysOf(archivedRecord)?.join(",") || "no archived record");
  // Also pin chain/fork/managed-session key sets on the TERMINALIZED record — terminalize must not
  // mutate the chain, so the same pins that held at produce hold after archive (recovery truth).
  ok("K1/M5b (closed-world, AFTER ARCHIVE): the terminalized record's chain / chain.fork / chain.managed_session key sets are UNCHANGED from produce — terminalization added no nested shadow",
    eqKeys(archivedRecord?.chain, EXPECTED_CHAIN_KEYS)
      && eqKeys(archivedRecord?.chain?.fork, EXPECTED_FORK_KEYS)
      && eqKeys(archivedRecord?.chain?.managed_session, EXPECTED_MANAGED_SESSION_KEYS),
    `chain=[${keysOf(archivedRecord?.chain)}]`);

  // -- daemon kill / restart → recovery/replay converges byte-identical --------------------------
  const preRestart = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}`);
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const postRestart = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}`);
  ok("after daemon kill/restart the launch projection is byte-identical (recovery/replay converges on the same refs, head, receipts, subject attachment)",
    postRestart.status === 200 && JSON.stringify(postRestart.body) === JSON.stringify(preRestart.body),
    postRestart.status === 200 ? "identical" : `status ${postRestart.status}`);
  const sessionPost = await sessGet(sessionRef);
  ok("after restart the owned Session still carries the materialized subject attachment (durable, not a process-memory fact)",
    Array.isArray(sessionPost?.subject_attachments) && sessionPost.subject_attachments.some((a) => a.subject_ref === launchRef));
  const eventsPost = await jd(`${LAUNCHES}/${encodeURIComponent(launchId)}/events`);
  const replayedEvents = eventsPost.body?.events || [];
  ok("Finding 1: /events REPLAYS the launch thread from the REAL kernel event stream after restart — the durable events read back are the kernel `thread.started` + `harness_session.spawned` facts (each carrying a substrate seq + resulting_head), NOT a launch-family `runtime.thread.opened` vocabulary",
    eventsPost.status === 200 && eventsPost.body?.reconstructed === true
      && replayedEvents.some((e) => e.event_kind === "thread.started" && typeof e.seq === "number" && typeof e.resulting_head === "string")
      && replayedEvents.some((e) => e.event_kind === "harness_session.spawned")
      && !replayedEvents.some((e) => e.kind === "runtime.thread.opened" || e.event_kind === "runtime.thread.opened"),
    `${replayedEvents.length} event(s): ${replayedEvents.map((e) => e.event_kind).join(",")}`);

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "launch-chain", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* already gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}

run().catch((error) => {
  console.error(`FAIL launch-chain — ${error?.stack || error}`);
  cleanup();
  process.exit(1);
});
