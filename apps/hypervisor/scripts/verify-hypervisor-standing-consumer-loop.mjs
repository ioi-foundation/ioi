// verify-hypervisor-standing-consumer-loop — M13.3 (attach-time envelope) and M13.5
// (policy-derived posture) proven live against an isolated daemon and the REAL wallet.network
// principal-authority fixture, on the DIRECT daemon path (no UI, no serve adapter):
//
//   ACC-15 clause 4 (silent within policy): a session naming a bounded connection draws N acts
//     inside the envelope with ZERO approval prompts; the draw-down receipts exist on the session
//     and the wallet consumed exactly N usages; marking the act interactive_exact_effect produces
//     the exact-effect review instead of silence.
//   ACC-15 clause 5 (out of bounds refuses, typed): draw N+1 refuses naming the bound with
//     widening pointed at Connections; a second direct probe refuses identically (UI bypass).
//   ACC-15 clause 8 (leaving is real): revoking the attach-time lease refuses the very next act
//     and the next session create; a wallet-side revocation fences at the next draw.
//   ACC-18 (exact review cannot be bypassed): a policy-marked tool produces the review object
//     even with authority and budget present; presenting the standing lease, a bogus exact grant,
//     or the same bytes again never admits it silently and consumes nothing.
//   M13.3: a profile naming an UNBOUNDED attach refuses at create (412); a bounded attach renders
//     its bounds on the connector record (the card's source); a mismatched lease refuses typed.
//   The execute lane: a session whose lease is exhausted fails execution CLOSED, typed, before
//     any harness runs.
//
// The ceremony evidence is the SYNTHETIC contract fixture the broker-contract verifier uses; it
// claims no physical passkey (recorded in the census). Exit: 0 pass · 1 fail · 2 blocked.
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

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
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const freePort = () => new Promise((resolve, reject) => { const srv = net.createServer(); srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); }); srv.on("error", reject); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up */ } await new Promise((r) => setTimeout(r, 400)); } throw new Error(`timeout waiting for ${url}`); };

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch { console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`); process.exit(2); }

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-standing-consumer-loop-"));
let daemon = null; let daemonPort = 0; let DAEMON = ""; let SESSION = ""; let toolServer = null; let fixture = null; let daemonEnv = {};

async function startDaemon() {
  daemon = spawn(daemonBinary, [], { cwd: ROOT, env: daemonEnv, stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 60000);
  return () => log;
}
async function stopDaemon() { if (!daemon) return; const exited = new Promise((resolve) => daemon.once("exit", resolve)); daemon.kill("SIGKILL"); await exited; daemon = null; }

const jd = (p, init, cookie = true) => fetch(`${DAEMON}${p}`, { ...init, headers: { ...(init?.body ? { "content-type": "application/json" } : {}), ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}) } })
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch((e) => ({ status: 0, body: { fetch_error: String(e?.message || e) } }));
const readReceipts = (kind, sessionRef) => { const found = []; try { for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) { try { const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8")); if (j.kind === kind && (sessionRef === undefined || j.session_ref === sessionRef)) found.push(j); } catch { /* not JSON */ } } } catch { /* none */ } return found; };
const consumedIntents = () => { let n = 0; try { for (const f of fs.readdirSync(path.join(dataDir, "authority-admission-intents"))) { try { const j = JSON.parse(fs.readFileSync(path.join(dataDir, "authority-admission-intents", f), "utf8")); if (j.authority_mode === "standing_envelope" && j.status === "consumed") n += 1; } catch { /* skip */ } } } catch { /* none */ } return n; };
const invoke = (connectorId, sessionRef, extra = {}) => jd(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/invoke`, { method: "POST", body: JSON.stringify({ tool: "ping", request: { n: 1 }, ...(sessionRef ? { session_ref: sessionRef } : {}), ...extra }) });
const createSession = (refs) => jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: "project:standing-loop", authority_profile: { connection_refs: refs } }) });

async function mintLease(connector, { maxUsages, spend = 1000, deposit = 1000, operations = ["session_execute", "connector_invoke"], tools = ["ping"] }) {
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
  // The fixture's default four-validator AFT profile does not commit reliably on a loaded host
  // (the 2026-09-07 alpha closure's first root cause); the standing loop needs ONE authority
  // node, so pin the deterministic single-node ordering profile exactly as the alpha journey does.
  fixture = await startRealWalletNetworkPrincipalAuthorityFixture({
    wallClockChain: true,
    baseEnv: {
      ...process.env,
      IOI_M049_ORDERING_PROFILE: process.env.IOI_ALPHA_FIXTURE_ORDERING_PROFILE || "Solo",
      IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: process.env.IOI_ALPHA_FIXTURE_COMMIT_TIMEOUT_SECS || "900",
      IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1500000",
    },
  });
  const toolPort = await freePort();
  toolServer = http.createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ pong: true, path: req.url })); });
  await new Promise((resolve) => toolServer.listen(toolPort, "127.0.0.1", resolve));
  daemonPort = await freePort(); DAEMON = `http://127.0.0.1:${daemonPort}`;
  daemonEnv = { ...process.env, ...fixture.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: PRINCIPAL, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" };
  delete daemonEnv.IOI_WALLET_TEST_SIGNER;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) { const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "standing-consumer-loop-v1", email: "standing-loop@ioi.local" }) }); SESSION = boot.body?.session_token ?? ""; }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  const register = (name) => jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ service: "ping-service", name, base_url: `http://127.0.0.1:${toolPort}`, kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }, { name: "wipe", method: "POST", path: "/wipe" }] }) });
  const A = (await register("bounded-a")).body?.connector; const B = (await register("unbounded-b")).body?.connector;
  const C = (await register("review-c")).body?.connector; const D = (await register("wallet-revoke-d")).body?.connector;
  ok("four real connectors register in the Connections estate", A?.connector_id && B?.connector_id && C?.connector_id && D?.connector_id, `${A?.connector_id} ${B?.connector_id} ${C?.connector_id} ${D?.connector_id}`);

  // ---- M13.3: attach-time envelope ------------------------------------------------------------
  const N = 3;
  const leaseA = await mintLease(A, { maxUsages: N });
  const bindA = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(A.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseA.grant, envelope: leaseA.envelope }) });
  ok("M13.3: attaching a standing lease (wallet-recorded grant + registered SessionStandingEnvelope) binds it to the connection and returns its bounds", bindA.status === 200 && bindA.body?.standing_lease?.status === "active" && bindA.body.standing_lease.bounds?.max_usages === N && bindA.body.standing_lease.envelope_hash_ref === leaseA.envelope.body_hash, `${bindA.status} ${JSON.stringify(bindA.body?.standing_lease?.bounds || bindA.body).slice(0, 200)}`);
  const listed = (await jd("/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === A.connector_id);
  ok("the connector record (the card's source) carries the lease bounds, hashes and status — never a client-side number", listed?.standing_lease?.status === "active" && listed.standing_lease.bounds?.max_cumulative_spend_microusd === 1000 * N && listed.standing_lease.grant_hash_ref?.startsWith("sha256:"), JSON.stringify(listed?.standing_lease?.bounds || null).slice(0, 160));
  const mismatched = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(B.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseA.grant, envelope: leaseA.envelope }) });
  ok("a lease whose envelope names another connector refuses typed at attach (422 standing_lease_connector_mismatch)", mismatched.status === 422 && mismatched.body?.error?.code === "standing_lease_connector_mismatch", `${mismatched.status}/${mismatched.body?.error?.code}`);
  const rebind = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(A.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseA.grant, envelope: leaseA.envelope }) });
  ok("an active lease is never edited in place: a second bind conflicts (409) — widening is a successor binding", rebind.status === 409 && rebind.body?.error?.code === "standing_lease_already_bound", `${rebind.status}`);
  const unbounded = await createSession([`connector:${B.connector_id}`]);
  ok("M13.3: a session profile naming an UNBOUNDED attach refuses at create (412 session_authority_connection_unbounded) and points widening at Connections", unbounded.status === 412 && unbounded.body?.error?.code === "session_authority_connection_unbounded" && unbounded.body.error.widening_path === "/__ioi/connections", `${unbounded.status}/${unbounded.body?.error?.code}`);
  const scoped = await createSession([`connector:${A.connector_id}`]);
  const sRef = scoped.body?.session_ref || "";
  ok("a session naming the BOUNDED attach creates (202) with the closed profile", scoped.status === 202 && sRef && JSON.stringify(scoped.body?.authority_profile?.connection_refs) === JSON.stringify([`connector:${A.connector_id}`]), `${scoped.status} ${sRef}`);

  // ---- ACC-15 clause 4: silent within policy --------------------------------------------------
  const first = await invoke(A.connector_id, sRef);
  const second = await invoke(A.connector_id, sRef);
  const silent = [first, second].every((r) => r.status === 200 && r.body?.ok === true && !r.body?.approval && !r.body?.authority_challenge);
  ok("ACC-15 §4: two in-envelope acts complete with ZERO approval prompts — no challenge, no card, the tool ran", silent, `${first.status}/${second.status} ${JSON.stringify(first.body).slice(0, 120)}`);
  const draws = readReceipts("hypervisor.session.standing_draw", sRef);
  ok("the silence is attributable: a standing_draw receipt per act is on the session (posture silent_within_policy, envelope hash, admission intent) and the wallet consumed exactly that many usages", draws.length === 2 && draws.every((d) => d.posture === "silent_within_policy" && d.standing_envelope_hash === leaseA.envelope.body_hash && String(d.admission_intent_ref || "").startsWith("authority-admission-intents/")) && consumedIntents() === 2, `${draws.length} draw receipt(s) · ${consumedIntents()} consumed intent(s)`);
  // mutation: mark the act interactive_exact_effect → the review appears instead of silence
  const mark = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(A.connector_id)}/policy`, { method: "POST", body: JSON.stringify({ allowed_tools: null, risk_posture: "standard", exact_review_tools: ["ping"] }) });
  const reviewed = await invoke(A.connector_id, sRef);
  ok("MUTATION (ACC-15 §4 / ACC-18): marking the act interactive_exact_effect in the admitted policy yields the exact-effect REVIEW (202 exact_effect_review_required with the daemon's commitments) instead of silence, and draws nothing", mark.body?.ok === true && reviewed.status === 202 && reviewed.body?.reason === "exact_effect_review_required" && reviewed.body.posture === "interactive_exact_effect" && reviewed.body.approval?.request_hash && consumedIntents() === 2, `${reviewed.status}/${reviewed.body?.reason} · consumed ${consumedIntents()}`);
  const reviews = readReceipts("hypervisor.session.exact_effect_review", sRef);
  ok("the review object is DURABLE: payload hash, destination, policy/request commitments and expiry are on the session's receipts", reviews.length === 1 && reviews[0].request_hash === reviewed.body?.approval?.request_hash && reviews[0].payload_hash?.startsWith("sha256:") && reviews[0].destination?.includes("ping-service") && reviews[0].standing_envelope_present === true, JSON.stringify(reviews[0] || null).slice(0, 160));
  const bogus = await invoke(A.connector_id, sRef, { wallet_approval_grant: { schema_version: 1, forged: true } });
  ok("ACC-18: a bogus exact grant against the review refuses at the exact lane (never silently admitted, nothing consumed)", bogus.status >= 400 && bogus.body?.ok !== true && consumedIntents() === 2, `${bogus.status}/${bogus.body?.reason}`);
  await jd(`/v1/hypervisor/connectors/${encodeURIComponent(A.connector_id)}/policy`, { method: "POST", body: JSON.stringify({ allowed_tools: null, risk_posture: "standard" }) });
  const third = await invoke(A.connector_id, sRef);
  ok("with the policy mark removed the act is silent again — silence is a policy outcome, not a UI choice", third.status === 200 && third.body?.ok === true && consumedIntents() === 3, `${third.status} · consumed ${consumedIntents()}`);

  // ---- ACC-15 clause 5: out of bounds refuses, typed -----------------------------------------
  const over = await invoke(A.connector_id, sRef);
  ok("ACC-15 §5: draw N+1 refuses TYPED at the daemon naming the bound (standing_envelope_exceeded / max_usages) with widening pointed at Connections; nothing ran", over.status === 403 && over.body?.reason === "standing_envelope_exceeded" && over.body.refused_bound === "max_usages" && over.body.widening_path === "/__ioi/connections" && over.body.bounds?.max_usages === N, `${over.status}/${over.body?.reason}/${over.body?.refused_bound}`);
  const refusals = readReceipts("hypervisor.session.standing_refusal", sRef);
  ok("the refusal is DURABLE: a standing_refusal receipt naming the bound is on the session and the response cites it", refusals.length >= 1 && refusals.at(-1).refused_bound === "max_usages" && over.body?.refusal_receipt_ref === refusals.at(-1).id, `${refusals.length} refusal receipt(s)`);
  const again = await invoke(A.connector_id, sRef);
  ok("UI-BYPASS DRILL: a second direct daemon probe refuses IDENTICALLY (same reason, same bound) — the refusal is admission's, not a surface's", again.status === over.status && again.body?.reason === over.body?.reason && again.body?.refused_bound === over.body?.refused_bound, `${again.status}/${again.body?.reason}`);
  const outsideTool = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(A.connector_id)}/invoke`, { method: "POST", body: JSON.stringify({ tool: "wipe", request: {}, session_ref: sRef }) });
  ok("a tool the template does not name refuses typed (standing_envelope_tool_outside_template) before any wallet call", outsideTool.status === 403 && outsideTool.body?.reason === "standing_envelope_tool_outside_template", `${outsideTool.status}/${outsideTool.body?.reason}`);
  // The execute lane needs a qualified model route and launch chain before its authority gate;
  // it is proven by check:alpha-journey (fixture authority mode), not re-driven here.
  const noSession = await invoke(A.connector_id, null);
  ok("a session-less invocation is the operator's own direct act: it keeps the exact authority challenge and never draws the envelope", noSession.status === 403 && noSession.body?.approval?.request_hash && !noSession.body?.refused_bound, `${noSession.status}/${noSession.body?.reason}`);

  // ---- ACC-18: the review cannot be bypassed on a review-marked connection ---------------------
  const leaseC = await mintLease(C, { maxUsages: 2 });
  await jd(`/v1/hypervisor/connectors/${encodeURIComponent(C.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseC.grant, envelope: leaseC.envelope }) });
  await jd(`/v1/hypervisor/connectors/${encodeURIComponent(C.connector_id)}/policy`, { method: "POST", body: JSON.stringify({ allowed_tools: null, risk_posture: "standard", exact_review_tools: ["ping"] }) });
  const cRef = (await createSession([`connector:${C.connector_id}`])).body?.session_ref || "";
  const r1 = await invoke(C.connector_id, cRef); const r2 = await invoke(C.connector_id, cRef);
  ok("ACC-18: a policy-marked tool with a FULL standing envelope produces the review object every time; the same bytes twice never admit and the envelope is never drawn", r1.status === 202 && r2.status === 202 && r1.body?.approval?.request_hash === r2.body?.approval?.request_hash && consumedIntents() === 3, `${r1.status}/${r2.status} · consumed ${consumedIntents()}`);

  // ---- ACC-15 clause 8: leaving is real ---------------------------------------------------------
  const leaseD = await mintLease(D, { maxUsages: 2 });
  await jd(`/v1/hypervisor/connectors/${encodeURIComponent(D.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseD.grant, envelope: leaseD.envelope }) });
  const dRef = (await createSession([`connector:${D.connector_id}`])).body?.session_ref || "";
  const d1 = await invoke(D.connector_id, dRef);
  await fixture.revokeStandingApprovalGrant(PRINCIPAL, leaseD.recorded.standing_grant_hash);
  const d2 = await invoke(D.connector_id, dRef);
  ok("ACC-15 §8 (wallet side): after the wallet revokes the grant, the very next draw refuses (standing_lease_revoked) — the daemon record still says active, the wallet is the truth", d1.status === 200 && d2.status === 403 && d2.body?.reason === "standing_lease_revoked", `${d1.status} ${JSON.stringify(d1.body).slice(0, 100)} → ${d2.status} ${JSON.stringify(d2.body).slice(0, 220)}`);
  const revokeA = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(A.connector_id)}/standing-lease`, { method: "DELETE" });
  const afterRevoke = await invoke(A.connector_id, sRef);
  const createAfterRevoke = await createSession([`connector:${A.connector_id}`]);
  ok("ACC-15 §8 (attach side): revoking the attach-time lease refuses the very next act (standing_lease_revoked, before any wallet call) and the next session create (412, lease_status revoked)", revokeA.status === 200 && afterRevoke.status === 403 && afterRevoke.body?.reason === "standing_lease_revoked" && createAfterRevoke.status === 412 && createAfterRevoke.body?.error?.lease_status === "standing_lease_revoked", `${revokeA.status} ${JSON.stringify(revokeA.body).slice(0, 120)} → ${afterRevoke.status}/${afterRevoke.body?.reason} · create ${createAfterRevoke.status}/${createAfterRevoke.body?.error?.code}/${createAfterRevoke.body?.error?.lease_status}`);
  const revocations = readReceipts("hypervisor.session.standing_revocation");
  ok("the revocation is receipted", revocations.length === 1 && revocations[0].connector_id === A.connector_id, `${revocations.length}`);

  // ---- restart -----------------------------------------------------------------------------------
  await stopDaemon();
  await startDaemon();
  const listedAfter = (await jd("/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === C.connector_id);
  const overAfter = await invoke(A.connector_id, sRef);
  const reviewAfter = await invoke(C.connector_id, cRef);
  ok("RESTART: the bounded lease still renders its bounds, the revoked lease still refuses, and the review-marked tool still reviews — all from durable records", listedAfter?.standing_lease?.status === "active" && overAfter.status === 403 && overAfter.body?.reason === "standing_lease_revoked" && reviewAfter.status === 202, `${listedAfter?.standing_lease?.status} · ${overAfter.status}/${overAfter.body?.reason} · ${reviewAfter.status}`);
}

let exitCode = 1;
try {
  await run();
  const passed = results.filter((r) => r.pass).length;
  console.log(`${passed === results.length ? "PASS" : "FAIL"} check:standing-consumer-loop — ${passed}/${results.length} assertions · factor_origin synthetic_contract_fixture_not_physical_passkey`);
  emitVerifierCensus({ verifierId: "standing-consumer-loop", sourceUrl: import.meta.url, results });
  exitCode = passed === results.length ? 0 : 1;
} catch (error) {
  console.error(`FAIL check:standing-consumer-loop — ${error?.stack || error}`);
} finally {
  await stopDaemon();
  toolServer?.close();
  try { await fixture?.stop(); } catch { /* best effort */ }
  fs.rmSync(dataDir, { recursive: true, force: true });
}
process.exit(exitCode);
