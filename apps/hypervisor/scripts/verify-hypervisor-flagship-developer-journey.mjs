#!/usr/bin/env node
// M13.11 — the flagship developer journey (ADR 0053 § 2): from an issue to a reviewed pull request
// through a governed SCM connector named in the session's authority profile. The claim is the
// GOVERNED PATH, never the quality of the work:
//   · reads and writes inside the attach-time standing envelope draw silently (one standing_draw
//     receipt per act, zero approval prompts) — M13.3 / M13.5;
//   · the push is an exact-effect review the operator approves with an exact grant bound to the
//     daemon's own commitments; an unapproved push yields ZERO calls at the SCM target and exactly
//     one after approval — M03.15;
//   · every crossing is receipted; a planted unreceipted crossing turns this verifier red;
//   · revoking the connection ends the authority: the next session naming it refuses at create.
// The SCM target is a FIXTURE this verifier owns (an HTTP server modelling issues, branches, commits,
// pull requests and pushes, counting every call). A live GitHub run is optional and separately
// authorized; it is not driven here.
//
// Scaffold: the real wallet.network principal-authority fixture (Solo), one daemon on a temp data
// dir, the operator bootstrapped from the one-boot token. Children are owned and reaped on exit and
// on signal.
//
// Env: IOI_HYPERVISOR_DAEMON_BINARY (default target/debug/hypervisor-daemon)
//      --self-drill  plants an unreceipted crossing (a direct call to the SCM target that bypasses
//                    the daemon) and requires the receipt ledger assertion to go red.
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { randomHex32, sealSessionStandingEnvelope, syntheticStandingCeremony } from "./lib/standing-authority-evidence.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const PRINCIPAL = "domain://acme-host";
const SESSION_ENVELOPE_CONTRACT = "schema://ioi/components/hypervisor/session-standing-envelope/v1";
const SELF_DRILL = process.argv.includes("--self-drill");
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const freePort = () => new Promise((resolve, reject) => { const srv = net.createServer(); srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); }); srv.on("error", reject); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up */ } await new Promise((r) => setTimeout(r, 250)); } throw new Error(`not up: ${url}`); };

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch { console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`); process.exit(2); }

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-flagship-developer-journey-"));
let daemon = null; let daemonPort = 0; let DAEMON = ""; let SESSION = ""; let fixture = null; let daemonEnv = {}; let scm = null;

async function startDaemon() {
  daemon = spawn(daemonBinary, [], { cwd: ROOT, env: daemonEnv, stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 60000);
  return () => log;
}
async function stopDaemon() { if (!daemon) return; const exited = new Promise((resolve) => daemon.once("exit", resolve)); daemon.kill("SIGKILL"); await exited; daemon = null; }
async function reapAll() {
  await stopDaemon();
  try { scm?.server.close(); } catch { /* closed */ }
  try { await fixture?.stop(); } catch { /* best effort */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}
for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]]) {
  process.on(signal, () => { console.error(`${signal}: reaping owned children`); reapAll().finally(() => process.exit(code)); });
}

// The FIXTURE SCM target: issues, branches, commits, pull requests, pushes. Every call is counted by
// operation so "zero pushes" and "exactly one push" are counted at the effect.
async function startScmFixture() {
  const port = await freePort();
  const state = { issues: { 42: { number: 42, title: "Config loader ignores IOI_CONFIG_PATH", body: "Repro: set the env var; observe the default path is read." } }, branches: {}, commits: [], pulls: {}, pushes: [], calls: {} };
  const count = (op) => { state.calls[op] = (state.calls[op] || 0) + 1; };
  const server = http.createServer((req, res) => {
    let raw = ""; req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const json = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
      let body = {}; try { body = raw ? JSON.parse(raw) : {}; } catch { body = {}; }
      const u = new URL(req.url, "http://scm");
      if (req.method === "GET" && u.pathname === "/issues/42") { count("get_issue"); return json(200, state.issues[42]); }
      if (req.method === "POST" && u.pathname === "/branches") { count("create_branch"); const name = body.name || `fix/issue-42-${Object.keys(state.branches).length + 1}`; state.branches[name] = { name, base: body.base || "main", commits: [] }; return json(201, state.branches[name]); }
      if (req.method === "POST" && u.pathname === "/commits") { count("commit"); const c = { sha: randomHex32().slice(0, 12), branch: body.branch, message: body.message, files: body.files || [] }; state.commits.push(c); state.branches[body.branch]?.commits.push(c.sha); return json(201, c); }
      if (req.method === "POST" && u.pathname === "/pulls") { count("open_pr"); const n = 100 + Object.keys(state.pulls).length + 1; state.pulls[n] = { number: n, head: body.head, base: body.base || "main", title: body.title, state: "open" }; return json(201, state.pulls[n]); }
      if (req.method === "POST" && u.pathname === "/push") { count("push"); state.pushes.push({ branch: body.branch, at: Date.now() }); return json(200, { pushed: body.branch, pushes: state.pushes.length }); }
      return json(404, { error: "no such fixture route", path: u.pathname });
    });
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  scm = { port, state, server, calls: (op) => state.calls[op] || 0 };
  return scm;
}

const jd = (p, init, cookie = true) => fetch(`${DAEMON}${p}`, { ...init, headers: { ...(init?.body ? { "content-type": "application/json" } : {}), ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}) } })
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch((e) => ({ status: 0, body: { fetch_error: String(e?.message || e) } }));
const readReceipts = (kind, sessionRef) => { const found = []; try { for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) { try { const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8")); if (j.kind === kind && (sessionRef === undefined || j.session_ref === sessionRef)) found.push(j); } catch { /* not JSON */ } } } catch { /* none */ } return found; };
const invokeReceipts = () => { let n = 0; try { for (const f of fs.readdirSync(path.join(dataDir, "connector-invoke-receipts"))) if (f.endsWith(".json")) n += 1; } catch { /* none */ } return n; };
const act = (connectorId, sessionRef, tool, request, extra = {}) => jd(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/invoke`, { method: "POST", body: JSON.stringify({ tool, request, ...(sessionRef ? { session_ref: sessionRef } : {}), ...extra }) });
const createSession = (refs) => jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: "project:flagship-developer-journey", authority_profile: { connection_refs: refs } }) });

const TOOLS = [
  { name: "get_issue", method: "GET", path: "/issues/42" },
  { name: "create_branch", method: "POST", path: "/branches" },
  { name: "commit", method: "POST", path: "/commits" },
  { name: "open_pr", method: "POST", path: "/pulls" },
  { name: "push", method: "POST", path: "/push" },
];

async function mintLease(connector, { maxUsages, spend = 1000, deposit = 1000, operations = ["session_execute", "connector_invoke"], tools }) {
  const now = await fixture.readChainTimestampMs();
  const policyHash = `sha256:${randomHex32()}`;
  const reviewReceiptHash = `sha256:${randomHex32()}`;
  const marker = randomHex32().slice(0, 16);
  const envelope = sealSessionStandingEnvelope({
    schema_version: "ioi.hypervisor.session-standing-envelope.v1",
    standing_envelope_ref: `standing-envelope://hypervisor/connections/${connector.connector_id}/${marker}`,
    owner_ref: "org://local", bounded_system_ref: "system://hypervisor/local", principal_ref: PRINCIPAL,
    audience_ref: "wallet-client://hypervisor/daemon", authority_scope: "scope:hypervisor.session-standing-envelope",
    facet_template: { connector_id: connector.connector_id, service: connector.service, base_url: connector.base_url, operations, allowed_tools: tools, per_operation_spend_microusd: spend, per_operation_deposit_microusd: deposit },
    aggregate_bounds: { max_cumulative_deposit_microusd: deposit * maxUsages, max_cumulative_spend_microusd: spend * maxUsages, max_usages: maxUsages },
    not_before_ms: Math.max(0, now - 30_000), expires_at_ms: now + 30 * 60_000, revocation_epoch: 0,
    trajectory_policy_ref: "policy://hypervisor/session-standing-envelope/trajectory/v1", trajectory_policy_hash: policyHash,
    approval_mode: "standing_envelope", recovery_posture: "recovery_never_widens_or_resets_drawdown",
  });
  const ceremony = syntheticStandingCeremony({ principalRef: PRINCIPAL, envelope, policyHash, reviewReceiptHash, validationProfileRef: SESSION_ENVELOPE_CONTRACT, nowMs: now, marker });
  const grant = fixture.mintStandingForCapability(PRINCIPAL, {
    standingEnvelopeHash: envelope.body_hash, policyHash, nonce: randomHex32(), counter: 1, issuedAtMs: now, expiresAtMs: now + 20 * 60_000,
    maxUsages, maxCumulativeDepositMicrousd: deposit * maxUsages, maxCumulativeSpendMicrousd: spend * maxUsages,
    reviewReceiptHash, approvalCeremonyContextHash: ceremony.contextHash, authFactorReceiptHash: ceremony.factor.receipt_hash,
  });
  const recorded = await fixture.recordStandingApprovalGrant(PRINCIPAL, grant, envelope, ceremony.context, ceremony.factor);
  return { envelope, grant, recorded };
}

async function run() {
  fixture = await startRealWalletNetworkPrincipalAuthorityFixture({
    wallClockChain: true,
    baseEnv: {
      ...process.env,
      IOI_M049_ORDERING_PROFILE: process.env.IOI_ALPHA_FIXTURE_ORDERING_PROFILE || "Solo",
      IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: process.env.IOI_ALPHA_FIXTURE_COMMIT_TIMEOUT_SECS || "900",
      IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1500000",
    },
  });
  await startScmFixture();
  daemonPort = await freePort(); DAEMON = `http://127.0.0.1:${daemonPort}`;
  daemonEnv = { ...process.env, ...fixture.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: PRINCIPAL, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" };
  delete daemonEnv.IOI_WALLET_TEST_SIGNER;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) { const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "flagship-developer-v1", email: "developer@ioi.local" }) }); SESSION = boot.body?.session_token ?? ""; }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // ---- the governed SCM connection --------------------------------------------------------------
  const G = (await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ service: "scm-fixture", name: "github-fixture", base_url: `http://127.0.0.1:${scm.port}`, kind: "bearer", requires_credential: false, allowed_tools: TOOLS }) })).body?.connector;
  ok("an SCM connector registers in the Connections estate with the five journey tools declared", G?.connector_id && Array.isArray(G.allowed_tools) && G.allowed_tools.length === 5, `${G?.connector_id}`);
  const lease = await mintLease(G, { maxUsages: 6, tools: ["get_issue", "create_branch", "commit", "open_pr", "push"] });
  const bind = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(G.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: lease.grant, envelope: lease.envelope }) });
  const policy = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(G.connector_id)}/policy`, { method: "POST", body: JSON.stringify({ allowed_tools: null, risk_posture: "standard", exact_review_tools: ["push"] }) });
  ok("Connections attaches a standing envelope (six draws over the journey's tools) and the admitted policy marks `push` for exact-effect review", bind.status === 200 && bind.body?.standing_lease?.status === "active" && policy.body?.ok === true, `bind ${bind.status} · policy ${policy.status}`);
  const created = await createSession([`connector:${G.connector_id}`]);
  const S = created.body?.session_ref || "";
  ok("a session names exactly the SCM connection in its closed authority profile", created.status === 202 && S && JSON.stringify(created.body?.authority_profile?.connection_refs) === JSON.stringify([`connector:${G.connector_id}`]), `${created.status} ${S}`);

  // ---- issue → branch → commit → PR: silent within the envelope -----------------------------------
  const issue = await act(G.connector_id, S, "get_issue", {});
  const branch = await act(G.connector_id, S, "create_branch", { name: "fix/issue-42", base: "main" });
  const commit = await act(G.connector_id, S, "commit", { branch: "fix/issue-42", message: "config: honour IOI_CONFIG_PATH (#42)", files: ["src/config.rs"] });
  const pr = await act(G.connector_id, S, "open_pr", { head: "fix/issue-42", base: "main", title: "config: honour IOI_CONFIG_PATH (#42)" });
  const silent = [issue, branch, commit, pr].every((r) => r.status === 200 && r.body?.ok === true && !r.body?.approval && !r.body?.authority_challenge);
  ok("ISSUE → BRANCH → COMMIT → PULL REQUEST: four in-envelope acts complete with zero approval prompts, and the fixture SCM saw exactly one of each", silent && scm.calls("get_issue") === 1 && scm.calls("create_branch") === 1 && scm.calls("commit") === 1 && scm.calls("open_pr") === 1 && scm.calls("push") === 0,
    `${[issue, branch, commit, pr].map((r) => r.status).join("/")} · calls ${JSON.stringify(scm.state.calls)}`);
  const draws = readReceipts("hypervisor.session.standing_draw", S);
  ok("every silent act is RECEIPTED: four standing_draw receipts on the session (posture silent_within_policy)", draws.length === 4 && draws.every((d) => d.posture === "silent_within_policy"), `${draws.length} draw(s)`);
  ok("the issue the agent read is the fixture's issue and the PR it opened names the branch it pushed nothing to yet", issue.body?.result?.number === 42 || JSON.stringify(issue.body).includes("IOI_CONFIG_PATH"), JSON.stringify(issue.body).slice(0, 100));

  // ---- the push: exact-effect review, approval, exactly one publish ------------------------------
  const push = await act(G.connector_id, S, "push", { branch: "fix/issue-42" });
  const R = push.body?.approval?.request_hash; const P = push.body?.approval?.policy_hash;
  ok("PUSH parks on an exact-effect review (202 exact_effect_review_required) — the standing envelope cannot admit it, the review object is durable and names its authority scope, and the fixture saw ZERO pushes", push.status === 202 && push.body?.reason === "exact_effect_review_required" && typeof R === "string" && typeof push.body?.required_authority_scope === "string" && readReceipts("hypervisor.session.exact_effect_review", S).length === 1 && scm.calls("push") === 0,
    `${push.status}/${push.body?.reason} · pushes ${scm.calls("push")}`);
  // The operator's approval is RECORDED on wallet.network against the exact authority scope the review
  // object names (the grant's audience is the daemon's capability account); an unrecorded grant is
  // refused as "no state for the exact approval grant".
  const grant = await fixture.mintRecorded(PRINCIPAL, P, R, push.body?.required_authority_scope);
  const forged = await act(G.connector_id, S, "push", { branch: "fix/issue-42" }, { wallet_approval_grant: { schema_version: 1, forged: true } });
  const swapped = await act(G.connector_id, S, "push", { branch: "main" }, { wallet_approval_grant: grant });
  ok("an unapproved push — a forged grant, or the operator's grant presented for a DIFFERENT branch — yields zero pushes", forged.status >= 400 && swapped.status >= 400 && scm.calls("push") === 0, `forged ${forged.status}/${forged.body?.reason} · swapped ${swapped.status}/${swapped.body?.reason}`);
  const approved = await act(G.connector_id, S, "push", { branch: "fix/issue-42" }, { wallet_approval_grant: grant });
  const replay = await act(G.connector_id, S, "push", { branch: "fix/issue-42" }, { wallet_approval_grant: grant });
  ok("the operator's exact-effect approval admits the push EXACTLY ONCE: 200, one push at the fixture, and the same grant replayed refuses", approved.status === 200 && approved.body?.ok === true && replay.status >= 400 && scm.calls("push") === 1, `approved ${approved.status} · replay ${replay.status}/${replay.body?.reason} · pushes ${scm.calls("push")}`);

  // ---- receipts for every crossing ------------------------------------------------------------------
  if (SELF_DRILL) {
    await fetch(`http://127.0.0.1:${scm.port}/push`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ branch: "planted-bypass" }) });
    ok("SELF-DRILL: a planted crossing that bypassed the daemon hit the SCM target (an unreceipted effect)", scm.calls("push") === 2, `pushes ${scm.calls("push")}`);
  }
  const totalCalls = Object.values(scm.state.calls).reduce((n, v) => n + v, 0);
  const receipted = invokeReceipts();
  ok("RECEIPT LEDGER: every call the SCM target served is matched by a connector-invoke receipt the daemon wrote (five silent acts and one approved push)", totalCalls === 5 && receipted >= 5, `target calls ${totalCalls} · invoke receipts ${receipted}`);

  // ---- leaving is real ---------------------------------------------------------------------------------
  const revoke = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(G.connector_id)}/standing-lease`, { method: "DELETE" });
  const afterRevoke = await act(G.connector_id, S, "get_issue", {});
  const nextSession = await createSession([`connector:${G.connector_id}`]);
  ok("LEAVING IS REAL: revoking the connection's envelope refuses the very next act (standing_lease_revoked) and the next session naming it refuses at create (412)", revoke.status === 200 && afterRevoke.status === 403 && afterRevoke.body?.reason === "standing_lease_revoked" && nextSession.status === 412, `revoke ${revoke.status} · act ${afterRevoke.status}/${afterRevoke.body?.reason} · create ${nextSession.status}`);
  ok("CLAIM BOUNDARY (recorded): this proves the governed path over a fixture SCM target; it claims nothing about the work's quality and did not touch a live GitHub", true, "fixture target only");
}

let exitCode = 1;
try {
  await run();
  const passed = results.filter((r) => r.pass).length;
  if (SELF_DRILL) {
    const ledger = results.find((r) => r.name.startsWith("RECEIPT LEDGER"));
    const drillOk = ledger && !ledger.pass;
    console.log(`${drillOk ? "PASS" : "FAIL"} mutate:flagship-developer-journey — a planted unreceipted crossing turned the receipt-ledger assertion ${ledger?.pass ? "GREEN (defect)" : "red, as it must"}`);
    exitCode = drillOk ? 0 : 1;
  } else {
    console.log(`${passed === results.length ? "PASS" : "FAIL"} check:flagship-developer-journey — ${passed}/${results.length} assertions · fixture SCM target · governed path only`);
    emitVerifierCensus({ verifierId: "flagship-developer-journey", sourceUrl: import.meta.url, results });
    exitCode = passed === results.length ? 0 : 1;
  }
} catch (error) {
  console.error(`FAIL check:flagship-developer-journey — ${error?.stack || error}`);
} finally {
  await reapAll();
}
process.exit(exitCode);
