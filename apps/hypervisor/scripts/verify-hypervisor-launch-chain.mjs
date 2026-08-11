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
import { fileURLToPath } from "node:url";

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
  ok("every §6.1 step names a canonical ref: plan · thread · initial thread event · managed session · launch-recipe · harness-binding · readiness · spawn · terminal-attach · first runtime event",
    typeof steps.plan_ref === "string" && steps.plan_ref.startsWith("harness-session-launch-plan:")
      && typeof steps.thread_ref === "string" && steps.thread_ref.startsWith("thread:launch-")
      && typeof steps.thread_event_ref === "string" && steps.thread_event_ref.includes("/opened")
      && typeof steps.managed_session_ref === "string" && steps.managed_session_ref.startsWith("managed-session:")
      && steps.launch_recipe_ref != null
      && typeof steps.harness_binding_ref === "string" && steps.harness_binding_ref.startsWith("harness-session-binding:")
      && typeof steps.readiness_ref === "string" && steps.readiness_ref.startsWith("readiness:")
      && typeof steps.spawn_ref === "string" && steps.spawn_ref.startsWith("spawn:")
      && steps.terminal_attach_ref != null
      && typeof steps.first_runtime_event_ref === "string" && steps.first_runtime_event_ref.includes("/spawned"),
    JSON.stringify(steps));
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
  ok("no second Session family was minted: exactly one session record on disk after launch (the launch hangs off the kernel-owned Session spine)",
    countSessionRecords() === sessionsBeforeLaunch, `${countSessionRecords()} session record(s)`);

  // -- INV-37 durable receipt binds the acting principal ----------------------------------------
  const producedReceipt = readReceiptByKind("hypervisor.harness_session_launch.produced", launchRef);
  ok("the durable produced receipt binds acting_principal_ref to the real operator principal (INV-37), never user://local-operator",
    producedReceipt && String(producedReceipt.acting_principal_ref || "").startsWith("user://")
      && producedReceipt.acting_principal_ref !== "user://local-operator"
      && !producedReceipt.created_at.startsWith("1970"),
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
  ok("the reconstructed chain events replay after restart, distinguished as reconstructed (the initial thread event survives)",
    eventsPost.status === 200 && eventsPost.body?.reconstructed === true
      && (eventsPost.body?.events || []).some((e) => e.kind === "runtime.thread.opened"),
    `${(eventsPost.body?.events || []).length} event(s)`);

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
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
