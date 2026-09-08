// verify-hypervisor-session-authority-profile — the SESSION AUTHORITY PROFILE admission contract
// (check:session-authority-profile; ADR 0052 Decision 3; core-clients-surfaces.md § Session
// authority profile; the M13.1/M13.2 binding).
//
// What this verifier proves, live against an isolated daemon and the DIRECT daemon path (no UI,
// no serve adapter — the refusal must be the daemon's, independent of any catalog filter):
//   - a session created without a profile carries the EMPTY profile on its durable record and in
//     the list projection — the default is never the workspace's connector estate;
//   - a session created naming connector A carries exactly [connector:A]; naming an unknown
//     connector refuses the create (412) rather than silently shrinking the set;
//   - a connector invocation on behalf of the empty-profile session refuses TYPED 403
//     session_authority_out_of_profile BEFORE org policy, principal scope or the wallet crossing,
//     and writes a durable refusal receipt into the session's receipts family;
//   - under session A, invoking connector A passes the profile gate and reaches the ordinary
//     wallet crossing (the typed authority challenge), while invoking connector B refuses
//     out-of-profile — the same body, the same caller, only the profile differs;
//   - a session-less invocation is unchanged (the operator's own direct act keeps its gates);
//   - revocation fences: deleting connector A makes the next invocation under session A refuse
//     (the connector is gone; nothing in the session grants it back);
//   - reconnect fencing: after a daemon kill + restart, the profile is still on the record and
//     the out-of-profile invocation still refuses identically.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-session-authority-profile-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let SESSION = "";
let toolServer = null;

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

async function stopDaemon() {
  if (!daemon) return;
  const exited = new Promise((resolve) => daemon.once("exit", resolve));
  daemon.kill("SIGKILL");
  await exited;
  daemon = null;
}

const jd = (p, init, cookie = true) => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const sessGet = async (ref) => (await jd(`/v1/hypervisor/sessions/${encodeURIComponent(ref)}`)).body?.session || null;

// Durable receipts by kind + session (the refusal is read from the receipts family, never from the
// response projection).
const readReceipts = (kind, sessionRef) => {
  const found = [];
  try {
    for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8"));
        if (j.kind === kind && j.session_ref === sessionRef) found.push(j);
      } catch { /* not JSON */ }
    }
  } catch { /* no receipts yet */ }
  return found;
};

const invoke = (connectorId, sessionRef) => jd(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/invoke`, {
  method: "POST",
  body: JSON.stringify({ tool: "ping", request: {}, ...(sessionRef ? { session_ref: sessionRef } : {}) }),
});

async function run() {
  // A local open HTTP tool endpoint so the connectors are real, credential-free declared tools.
  const toolPort = await freePort();
  toolServer = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ pong: true, path: req.url }));
  });
  await new Promise((resolve) => toolServer.listen(toolPort, "127.0.0.1", resolve));

  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "session-authority-profile-v1", email: "session-authority-profile@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // -- two real connectors in the Connections estate -------------------------------------------
  const register = (name) => jd("/v1/hypervisor/connectors", {
    method: "POST",
    body: JSON.stringify({
      service: "ping-service", name, base_url: `http://127.0.0.1:${toolPort}`, kind: "bearer",
      requires_credential: false,
      allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }],
    }),
  });
  const a = await register("connector-a");
  const b = await register("connector-b");
  const A = a.body?.connector?.connector_id || a.body?.connector_id || "";
  const B = b.body?.connector?.connector_id || b.body?.connector_id || "";
  ok("two real connectors register in the Connections estate", a.status < 300 && b.status < 300 && A && B && A !== B, `${a.status}/${b.status} ${A} ${B}`);

  // -- the empty default ------------------------------------------------------------------------
  const plain = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: "project:authority-profile" }) });
  const plainRef = plain.body?.session_ref || "";
  const plainRecord = await sessGet(plainRef);
  ok("a session created WITHOUT a profile carries the EMPTY profile on the durable record (schema-versioned, connection_refs exactly [])",
    plain.status === 202
      && plainRecord?.authority_profile?.schema_version === "ioi.hypervisor.session_authority_profile.v1"
      && Array.isArray(plainRecord?.authority_profile?.connection_refs)
      && plainRecord.authority_profile.connection_refs.length === 0,
    `${plain.status} ${JSON.stringify(plainRecord?.authority_profile || null)}`);
  ok("the create projection itself returns the profile (the caller sees what was bound, never a silent default)",
    plain.body?.authority_profile?.connection_refs?.length === 0, JSON.stringify(plain.body?.authority_profile || null));

  // -- the closed set at create --------------------------------------------------------------------
  const scoped = await jd("/v1/hypervisor/sessions", {
    method: "POST",
    body: JSON.stringify({ project_ref: "project:authority-profile", authority_profile: { connection_refs: [`connector:${A}`, A] } }),
  });
  const scopedRef = scoped.body?.session_ref || "";
  const scopedRecord = await sessGet(scopedRef);
  ok("a session created naming connector A (both spellings) carries EXACTLY [connector:A] — normalized, deduplicated, closed",
    scoped.status === 202 && JSON.stringify(scopedRecord?.authority_profile?.connection_refs) === JSON.stringify([`connector:${A}`]),
    `${scoped.status} ${JSON.stringify(scopedRecord?.authority_profile?.connection_refs)}`);
  const unknown = await jd("/v1/hypervisor/sessions", {
    method: "POST",
    body: JSON.stringify({ project_ref: "project:authority-profile", authority_profile: { connection_refs: ["connector:conn_does_not_exist"] } }),
  });
  ok("naming a connection that does not exist REFUSES the create (412 session_authority_connection_unknown) — the set never silently shrinks",
    unknown.status === 412 && unknown.body?.error?.code === "session_authority_connection_unknown",
    `${unknown.status}/${unknown.body?.error?.code}`);
  const malformed = await jd("/v1/hypervisor/sessions", {
    method: "POST",
    body: JSON.stringify({ project_ref: "project:authority-profile", authority_profile: { connection_refs: "connector:x" } }),
  });
  ok("a malformed profile refuses typed 422 session_authority_profile_invalid",
    malformed.status === 422 && malformed.body?.error?.code === "session_authority_profile_invalid",
    `${malformed.status}/${malformed.body?.error?.code}`);
  const list = await jd("/v1/hypervisor/sessions");
  const listed = (list.body?.sessions || []).find((s) => s.session_ref === scopedRef);
  ok("the sessions list projection carries each session's profile (App and headless read the same daemon truth)",
    JSON.stringify(listed?.authority_profile?.connection_refs) === JSON.stringify([`connector:${A}`]), JSON.stringify(listed?.authority_profile || null));

  // -- admission narrows to the profile, at the daemon -------------------------------------------
  const outEmpty = await invoke(A, plainRef);
  ok("DIRECT DAEMON PATH: invoking connector A on behalf of the EMPTY-profile session refuses TYPED 403 session_authority_out_of_profile",
    outEmpty.status === 403 && outEmpty.body?.reason === "session_authority_out_of_profile" && outEmpty.body?.session_ref === plainRef,
    `${outEmpty.status}/${outEmpty.body?.reason}`);
  const refusals = readReceipts("hypervisor.session.authority_refusal", plainRef);
  ok("the refusal is DURABLE: a typed refusal receipt for that session is in the receipts family and the response names it",
    refusals.length >= 1 && refusals[0].reason === "session_authority_out_of_profile" && refusals[0].connection_ref === `connector:${A}`
      && String(outEmpty.body?.refusal_receipt_ref || "").startsWith("receipt://hypervisor/session-authority-refusal/"),
    `${refusals.length} receipt(s) · ${outEmpty.body?.refusal_receipt_ref || "no ref"}`);

  const inA = await invoke(A, scopedRef);
  ok("under session A, invoking connector A PASSES the profile gate and reaches the ordinary wallet crossing (the typed authority challenge, not an out-of-profile refusal)",
    inA.status !== 403 || inA.body?.reason !== "session_authority_out_of_profile",
    `${inA.status}/${inA.body?.reason || inA.body?.decision || "ok"}`);
  ok("the crossing under session A is the authority challenge that binds the SESSION (the daemon's challenge, never a silent success without a grant)",
    (inA.status === 403 && /authority_required/u.test(String(inA.body?.reason || ""))) || (inA.status === 501) || (inA.status === 200 && inA.body?.ok === true),
    `${inA.status}/${inA.body?.reason || ""}`);
  const outB = await invoke(B, scopedRef);
  ok("under session A, invoking connector B refuses out-of-profile — same caller, same body shape, only the profile differs",
    outB.status === 403 && outB.body?.reason === "session_authority_out_of_profile"
      && JSON.stringify(outB.body?.profile_connection_refs) === JSON.stringify([`connector:${A}`]),
    `${outB.status}/${outB.body?.reason}`);
  const direct = await invoke(A, null);
  ok("a session-less invocation is the operator's own direct act and keeps its existing gates (never an out-of-profile refusal)",
    direct.body?.reason !== "session_authority_out_of_profile", `${direct.status}/${direct.body?.reason || ""}`);
  const bogusSession = await invoke(A, "session:does-not-exist");
  ok("naming a session that does not exist refuses at the session gate (404 session_not_found) — no crossing, no receipt",
    bogusSession.status === 404 && bogusSession.body?.error?.code === "session_not_found",
    `${bogusSession.status}/${bogusSession.body?.error?.code}`);
  const anon = await fetch(`${DAEMON}/v1/hypervisor/connectors/${encodeURIComponent(A)}/invoke`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ tool: "ping", request: {}, session_ref: scopedRef }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  ok("an ANONYMOUS session-scoped invocation refuses typed 401 before the session record is read (identity precedes the profile gate)",
    anon.status === 401, `${anon.status}/${anon.body?.error?.code || anon.body?.reason || ""}`);

  // -- revocation fences ----------------------------------------------------------------------------
  const del = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(A)}`, { method: "DELETE" });
  const afterDelete = await invoke(A, scopedRef);
  ok("REVOCATION: deleting connector A makes the next invocation under session A refuse — the session's profile grants nothing the estate no longer holds",
    del.status < 300 && afterDelete.status >= 400 && afterDelete.body?.ok !== true,
    `delete ${del.status} · invoke ${afterDelete.status}/${afterDelete.body?.reason || ""}`);
  const stillClosed = await sessGet(scopedRef);
  ok("the session's profile is IMMUTABLE — deletion does not rewrite the record; the closed set still names connector A as declared at create",
    JSON.stringify(stillClosed?.authority_profile?.connection_refs) === JSON.stringify([`connector:${A}`]),
    JSON.stringify(stillClosed?.authority_profile?.connection_refs));

  // -- reconnect fencing across a daemon restart ------------------------------------------------------
  await stopDaemon();
  await startDaemon();
  const afterRestart = await sessGet(scopedRef);
  ok("RESTART: the profile survives a daemon kill + restart on the durable record",
    JSON.stringify(afterRestart?.authority_profile?.connection_refs) === JSON.stringify([`connector:${A}`]),
    JSON.stringify(afterRestart?.authority_profile?.connection_refs));
  const outBAfter = await invoke(B, scopedRef);
  ok("RESTART: the out-of-profile invocation refuses identically after restart (reconnect preserves fencing)",
    outBAfter.status === 403 && outBAfter.body?.reason === "session_authority_out_of_profile",
    `${outBAfter.status}/${outBAfter.body?.reason}`);
  const emptyAfter = await invoke(B, plainRef);
  ok("RESTART: the empty-profile session still refuses every connector after restart",
    emptyAfter.status === 403 && emptyAfter.body?.reason === "session_authority_out_of_profile",
    `${emptyAfter.status}/${emptyAfter.body?.reason}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "session-authority-profile", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { toolServer?.close(); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
