// verify-hypervisor-worker-secret-non-possession — M03.13 at the supported profile's depth;
// ACC-15 N3 ("no credential is present in the session's environment at any point a probe can
// observe"). A HARNESS THAT ONLY LOOKS (packages/hypervisor-harness-shims/non-possession-drill.mjs)
// is spawned by the daemon's real host_spawn lane, on a real session drawing a real standing
// envelope on the wallet.network fixture, and probes from inside the session's own process:
//
//   env      — the names it was given carry no secret; planted needle values are absent;
//   parent   — /proc/<daemon>/environ is readable by a same-uid child (the supported profile's
//              honest posture) and carries NO secret-shaped assignment and NO planted needle: the
//              daemon scrubs its secret variables from its environment block at boot;
//   tree     — a bounded walk from the workspace up to the daemon's data dir finds no planted
//              needle in plaintext (the route credential is sealed; the sealing pass is nowhere);
//   broker   — the daemon's brokered surfaces refuse a bare request and leak no secret shape;
//   ptrace   — the host's yama ptrace_scope is recorded as a measured precondition (≥ 1: a
//              same-uid child cannot read its parent's memory; 0 would be a named gap).
//
// Needles are planted THREE ways: as the daemon's sealing pass (IOI_WALLET_SECRET_PASS), as a
// process-environment provider key the daemon refuses by default (OPENAI_API_KEY), and as a
// provider key SEALED to a model route through the custody crossing. The harness learns the needle
// values only from a file the verifier writes into the session workspace (excluded from the walk).
// Exit: 0 pass · 1 fail · 2 blocked.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
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
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const freePort = () => new Promise((resolve, reject) => { const srv = net.createServer(); srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); }); srv.on("error", reject); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up */ } await sleep(400); } throw new Error(`timeout waiting for ${url}`); };

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch { console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`); process.exit(2); }
const DRILL = path.join(ROOT, "packages", "hypervisor-harness-shims", "non-possession-drill.mjs");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-non-possession-"));
let daemon = null; let daemonPort = 0; let DAEMON = ""; let SESSION = ""; let fixture = null; let upstream = null; let daemonLog = "";

const NEEDLES = { sealing_pass: `np-pass-${crypto.randomBytes(12).toString("hex")}`, env_provider_key: `sk-np-env-${crypto.randomBytes(16).toString("hex")}`, sealed_route_key: `sk-np-sealed-${crypto.randomBytes(16).toString("hex")}` };

async function startDaemon(env) {
  daemon = spawn(daemonBinary, [], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 60000);
}
async function stopDaemon() { if (!daemon) return; const exited = new Promise((resolve) => daemon.once("exit", resolve)); daemon.kill("SIGTERM"); await Promise.race([exited, sleep(5000)]); if (daemon.exitCode === null) { daemon.kill("SIGKILL"); await exited; } daemon = null; }
const jd = (p, init, cookie = true) => fetch(`${DAEMON}${p}`, { ...init, headers: { ...(init?.body ? { "content-type": "application/json" } : {}), ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}), ...(init?.headers || {}) } })
  .then(async (r) => { const text = await r.text(); let body = {}; try { body = text ? JSON.parse(text) : {}; } catch { body = { _raw: text }; } return { status: r.status, body, text }; }).catch((e) => ({ status: 0, body: { fetch_error: String(e?.message || e) }, text: "" }));

async function mintLease(connector, { maxUsages, spend = 1000, deposit = 1000, operations = ["session_execute", "connector_invoke"], tools = ["ping"] }) {
  const now = await fixture.readChainTimestampMs();
  const policyHash = `sha256:${randomHex32()}`; const reviewReceiptHash = `sha256:${randomHex32()}`; const marker = randomHex32().slice(0, 16);
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
  const grant = fixture.mintStandingForCapability(PRINCIPAL, { standingEnvelopeHash: envelope.body_hash, policyHash, nonce: randomHex32(), counter: 1, issuedAtMs: now, expiresAtMs: now + 20 * 60_000, maxUsages, maxCumulativeDepositMicrousd: deposit * maxUsages, maxCumulativeSpendMicrousd: spend * maxUsages, reviewReceiptHash, approvalCeremonyContextHash: ceremony.contextHash, authFactorReceiptHash: ceremony.factor.receipt_hash });
  const recorded = await fixture.recordStandingApprovalGrant(PRINCIPAL, grant, envelope, ceremony.context, ceremony.factor);
  return { envelope, grant, recorded };
}

async function run() {
  fixture = await startRealWalletNetworkPrincipalAuthorityFixture({ wallClockChain: true, baseEnv: { ...process.env, IOI_M049_ORDERING_PROFILE: process.env.IOI_ALPHA_FIXTURE_ORDERING_PROFILE || "Solo", IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: process.env.IOI_ALPHA_FIXTURE_COMMIT_TIMEOUT_SECS || "900", IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1500000" } });
  // A reachable "model upstream" that answers nothing useful: the execute preflight only asks
  // whether the env-default upstream accepts a connection; the drill never calls a model.
  const upstreamPort = await freePort();
  upstream = http.createServer((req, res) => { res.writeHead(404, { "content-type": "application/json" }); res.end("{}"); });
  await new Promise((resolve) => upstream.listen(upstreamPort, "127.0.0.1", resolve));
  const toolPort = await freePort();
  const tool = http.createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ pong: true })); });
  await new Promise((resolve) => tool.listen(toolPort, "127.0.0.1", resolve));
  daemonPort = await freePort(); DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonEnv = { ...process.env, ...fixture.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: PRINCIPAL, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: `http://127.0.0.1:${upstreamPort}/v1`, IOI_HYPERVISOR_MODEL: "drill", IOI_HYPERVISOR_HARNESS_SHIM: DRILL,
    // The three planted secrets: the sealing pass, a process-environment provider key (refused by
    // default), and — bound below — a provider key sealed to a route through the custody crossing.
    IOI_WALLET_SECRET_PASS: NEEDLES.sealing_pass, OPENAI_API_KEY: NEEDLES.env_provider_key };
  delete daemonEnv.IOI_WALLET_TEST_SIGNER;
  await startDaemon(daemonEnv);
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = token ? await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "non-possession-v1", email: "np@ioi.local" }) }) : { status: 0, body: {} };
  SESSION = boot.body?.session_token || "";
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));
  const who = await jd("/v1/hypervisor/auth/whoami");
  const ownerRef = (who.body?.principal?.tenant_refs || []).find((t) => t === "org://local") || "org://local";
  const mut = (idem, extra = {}) => ({ owner_ref: ownerRef, idempotency_key: `np-${idem}`, ...extra });

  // ---- plant the sealed route key through the custody crossing --------------------------------
  const route = await jd("/v1/hypervisor/model-routes", { method: "POST", body: JSON.stringify(mut("route", { model_id: "np-remote", transport: "openai_compatible", base_url: "https://non-possession.invalid/v1", display_name: "non-possession drill route", credential_posture: "provider_vault_token" })) });
  const routeId = route.body?.route?.route_id || "";
  const challenge = await jd(`/v1/hypervisor/model-routes/${encodeURIComponent(routeId)}/credential`, { method: "POST", body: JSON.stringify(mut("cred", { token: NEEDLES.sealed_route_key })) });
  const scope = challenge.body?.required_authority_scope || challenge.body?.authority_challenge?.required_authority_scope || "";
  let sealed = challenge;
  if (challenge.status === 403 && challenge.body?.approval?.policy_hash && scope) {
    const grant = await fixture.mintRecorded(PRINCIPAL, challenge.body.approval.policy_hash, challenge.body.approval.request_hash, scope);
    sealed = await jd(`/v1/hypervisor/model-routes/${encodeURIComponent(routeId)}/credential`, { method: "POST", body: JSON.stringify(mut("cred", { token: NEEDLES.sealed_route_key, wallet_approval_grant: grant })) });
  }
  const routeAfter = await jd(`/v1/hypervisor/model-routes/${encodeURIComponent(routeId)}`);
  ok("a provider key is SEALED to a route through the custody crossing (the third planted needle); the route's read projection carries no secret", route.status < 300 && sealed.status < 300 && routeAfter.body?.route?.credential_binding?.kind === "sealed_capability_lease" && !routeAfter.text.includes(NEEDLES.sealed_route_key), `${route.status} → ${challenge.status} → ${sealed.status}`);

  // ---- a real session on a real standing envelope, executed by the drill harness ----------------
  const conn = (await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ service: "ping-service", name: "np-conn", base_url: `http://127.0.0.1:${toolPort}`, kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }] }) })).body?.connector;
  const lease = await mintLease(conn, { maxUsages: 2 });
  const bind = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(conn.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: lease.grant, envelope: lease.envelope }) });
  const env = await jd("/v1/hypervisor/environments", { method: "POST", body: JSON.stringify({ spec: { environment_class_id: "local-workspace-v0", project_id: "non-possession" } }) });
  const envId = env.body?.environment?.id || "";
  const started = await jd(`/v1/hypervisor/environments/${encodeURIComponent(envId)}/start`, { method: "POST" });
  const workspaceRoot = started.body?.environment?.status?.workspace_root || env.body?.environment?.status?.workspace_root || "";
  ok("a real environment provisions a workspace inside the daemon's data dir (the supported profile's posture — the walk starts there)", bind.status < 300 && envId && workspaceRoot && workspaceRoot.startsWith(dataDir), `${workspaceRoot}`);
  // The harness learns the needle VALUES only from this file, in its own workspace; the file is
  // excluded from the tree walk by name (it is the verifier's plant, not the daemon's leak).
  fs.writeFileSync(path.join(workspaceRoot, "non-possession-needles.txt"), Object.values(NEEDLES).join(","));
  const sessionRef = `session:np-${crypto.randomBytes(6).toString("hex")}`;
  const session = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ session_ref: sessionRef, project_ref: "project:non-possession", environment_id: envId, authority_profile: { connection_refs: [`connector:${conn.connector_id}`] } }) });
  const exec = await jd(`/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`, { method: "POST", body: JSON.stringify({ intent: "probe" }) });
  const probesFile = path.join(workspaceRoot, "non-possession-probes.json");
  let probes = null; try { probes = JSON.parse(fs.readFileSync(probesFile, "utf8")); } catch { /* absent */ }
  ok("the drill harness ran on the real host_spawn lane under the session's standing envelope and wrote its probes into the workspace", session.status < 300 && exec.status === 200 && exec.body?.exit_status === "success" && probes?.schema === "ioi.hypervisor.non-possession-probes.v1", `${session.status}/${exec.status} ${exec.body?.exit_status || exec.body?.reason || exec.body?.message || ""}`);

  // ---- the findings ------------------------------------------------------------------------------
  const p = probes || {};
  ok("ENVIRONMENT: the harness was given exactly PATH, HOME and the model upstream — no secret-shaped name, none of the three planted values", p.needles_known_to_harness === 3 && Array.isArray(p.env?.names) && p.env.names.every((n) => ["PATH", "HOME", "IOI_HYPERVISOR_MODEL_UPSTREAM"].includes(n)) && p.env.secret_shaped.length === 0 && p.env.needle_values_present === false, `${JSON.stringify(p.env?.names)} · needles known ${p.needles_known_to_harness}`);
  ok("PARENT PROCESS: the daemon's environment block is readable by its same-uid child (the profile's honest posture) and carries NO secret-shaped assignment and NO planted needle — the daemon scrubbed its secrets at boot", p.parent?.readable === true && p.parent?.needle_present === false && Array.isArray(p.parent?.secret_shaped_assignments) && p.parent.secret_shaped_assignments.length === 0, `readable ${p.parent?.readable} · ${p.parent?.assignments} assignments · secret-shaped ${JSON.stringify(p.parent?.secret_shaped_assignments)} · needle ${p.parent?.needle_present}`);
  const needleFiles = (p.tree?.needle_files || []).filter((f) => !f.endsWith("non-possession-needles.txt"));
  ok("STATE TREE: a bounded walk from the workspace up to the daemon's data dir finds no planted needle in plaintext (the route key is sealed; the sealing pass and the env key are nowhere)", p.tree && p.tree.files > 0 && !p.tree.capped && needleFiles.length === 0, `${p.tree?.files} files · ${needleFiles.length} needle file(s) ${JSON.stringify(needleFiles).slice(0, 160)}`);
  ok("BROKER: the harness found the daemon's address (a non-secret in the parent's environ) and the daemon's chat surface refuses its bare request (401) while the route and receipt listings expose no secret shape", Boolean(p.broker?.daemon) && p.broker?.chat_without_token?.status === 401 && p.broker?.routes_read?.status < 500 && p.broker?.routes_read?.has_secret_shape === false && p.broker?.receipts_list?.status < 500 && p.broker?.receipts_list?.has_secret_shape === false, JSON.stringify(p.broker).slice(0, 220));
  ok("PTRACE SCOPE (measured precondition): yama ptrace_scope ≥ 1 on this host — a same-uid child cannot read its parent's memory; 0 is a named gap", Number(p.ptrace_scope) >= 1, `ptrace_scope ${p.ptrace_scope}`);
  const execReceipts = (() => { const found = []; try { for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) { try { const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8")); if (j.kind === "hypervisor.session.execute" && j.session_ref === sessionRef) found.push(j); } catch { /* not JSON */ } } } catch { /* none */ } return found; })();
  const receiptKeys = [...(execReceipts[0]?.harness_environment_keys || [])].sort();
  ok("the execute receipt lists exactly the names the harness was given (harness_environment_keys) — the receipt agrees with the harness's own observation", execReceipts.length === 1 && JSON.stringify(receiptKeys) === JSON.stringify([...(p.env?.names || [])].sort()), JSON.stringify(receiptKeys));

  // ---- revoke the planted route key so no key material outlives the drill ----------------------
  const revoke = await jd(`/v1/hypervisor/model-routes/${encodeURIComponent(routeId)}/credential`, { method: "DELETE", body: JSON.stringify(mut("revoke")) });
  ok("the planted route key is revoked at the end (no key material outlives the drill)", revoke.status < 300, `${revoke.status}`);
  upstream.close(); tool.close();
}

let exitCode = 1;
try {
  await run();
  const failed = results.filter((r) => !r.pass).length;
  exitCode = failed ? 1 : 0;
  console.log(`${failed ? "FAIL" : "PASS"} check:worker-secret-non-possession — ${results.length - failed}/${results.length} assertions · M03.13 at the supported profile's depth (host_spawn, same uid, daemon environment scrubbed)`);
  emitVerifierCensus({ verifierId: "worker-secret-non-possession", sourceUrl: import.meta.url, results });
} catch (error) {
  console.error(`verifier crashed: ${error?.stack || error}`);
  exitCode = 1;
} finally {
  await stopDaemon();
  try { await fixture?.stop(); } catch { /* best effort */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
process.exit(exitCode);
