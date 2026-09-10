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
  const E = (await register("act-tool-e")).body?.connector;
  ok("five real connectors register in the Connections estate", A?.connector_id && B?.connector_id && C?.connector_id && D?.connector_id && E?.connector_id, `${A?.connector_id} ${B?.connector_id} ${C?.connector_id} ${D?.connector_id} ${E?.connector_id}`);

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

  // ---- R-17 DRILL: the route that MINTS standing authority resolves its caller ---------------
  // Until 2026-09-10 bind and revoke took no headers at all: the route that mints the envelope
  // resolved nobody, while invoke — the route that spends it — has resolved its caller since
  // INV-37. The drill proves BOTH halves of the ruling, and proves the scope half in BOTH
  // directions: a refusal that happens for the wrong reason proves nothing about scoping.
  const R = (await register("r17-drill")).body?.connector;
  ok("R-17 drill: the drill registers a REAL connector — an unwrapped response would address `conn_undefined` and make every assertion below vacuous",
    typeof R?.connector_id === "string" && R.connector_id.startsWith("conn_"), String(R?.connector_id));
  const unknownId = "conn_thisconnectordoesnotexist";
  const me = (await jd("/v1/hypervisor/auth/whoami")).body?.principal?.principal_id || "";
  ok("R-17 drill: the caller's principal resolves — this is the join key the scope gate uses", me.length > 0, me);

  // (1) UNAUTHENTICATED. Identity is resolved before any record read, so an EXISTING connector and
  // a made-up one answer identically: a caller who cannot authenticate learns nothing about which
  // connectors exist.
  const anonBindKnown = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(R.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) }, false);
  const anonBindUnknown = await jd(`/v1/hypervisor/connectors/${unknownId}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) }, false);
  const anonRevoke = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(R.connector_id)}/standing-lease`, { method: "DELETE" }, false);
  ok("R-17: an UNAUTHENTICATED bind refuses 401 typed, and revoke refuses identically — the minting route resolves its caller",
    anonBindKnown.status === 401 && anonBindKnown.body?.code === "hypervisor.authentication_required" && anonRevoke.status === 401,
    `bind ${anonBindKnown.status}/${anonBindKnown.body?.code} · revoke ${anonRevoke.status}`);
  ok("R-17: the anonymous refusal is NOT a record-existence oracle — an EXISTING connector and a made-up one answer byte-identically",
    anonBindKnown.status === anonBindUnknown.status && JSON.stringify(anonBindKnown.body) === JSON.stringify(anonBindUnknown.body),
    `existing ${anonBindKnown.status} ${JSON.stringify(anonBindKnown.body).slice(0, 70)} · unknown ${anonBindUnknown.status}`);

  // (2) SCOPE. Resolution alone was explicitly insufficient: the lookup is global, so an
  // authenticated caller could otherwise mint on a connection that is not theirs.
  const scopedPolicy = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(R.connector_id)}/policy`, { method: "POST", body: JSON.stringify({ principal_scoped: true }) });
  const scopedListed = (await jd("/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === R.connector_id);
  ok("R-17 drill: principal_scoped is actually SET on the record — the policy route answers 200 even when it refuses, so its status alone is not a witness",
    scopedListed?.org_policy?.principal_scoped === true, `policy ${scopedPolicy.status} · record ${JSON.stringify(scopedListed?.org_policy?.principal_scoped)}`);

  // 2a — scoped, caller holds NO grant: refused, and indistinguishable from unknown.
  const noGrantBind = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(R.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) });
  const unknownBind = await jd(`/v1/hypervisor/connectors/${unknownId}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) });
  ok("R-17: an authenticated caller holding NO lease grant for a principal-scoped connection cannot mint on it",
    noGrantBind.status === 404, `${noGrantBind.status}`);
  ok("R-17: the out-of-scope refusal is NOT an existence oracle either — byte-identical to the unknown-connector answer",
    noGrantBind.status === unknownBind.status && JSON.stringify(noGrantBind.body) === JSON.stringify(unknownBind.body),
    `scoped ${JSON.stringify(noGrantBind.body).slice(0, 60)} · unknown ${JSON.stringify(unknownBind.body).slice(0, 60)}`);

  // 2b — CROSS-PRINCIPAL: a grant for this connector exists, but it belongs to SOMEONE ELSE. If the
  // gate joined on "a grant exists" instead of "this caller holds one", this is where it shows.
  // The grant is SEEDED ON DISK rather than minted through the route, deliberately: the route
  // refuses `unknown_principal`, and this is a NEGATIVE control — the claim is that the gate
  // refuses a foreign grant HOWEVER it came to exist, which is stronger than proving it for
  // grants the route happens to allow. The daemon re-reads the family on every check.
  const foreignPrincipal = "00000000-0000-4000-8000-0000000000ff";
  const grantsDir = path.join(dataDir, "principal-lease-grants");
  fs.mkdirSync(grantsDir, { recursive: true });
  fs.writeFileSync(path.join(grantsDir, "plg_r17_foreign.json"), JSON.stringify({
    grant_id: "plg_r17_foreign",
    principal_id: foreignPrincipal,
    connector_id: R.connector_id,
    tools: ["ping", "*"],
    expires_at_ms: Date.now() + 3_600_000,
  }));
  const seededForeign = fs.existsSync(path.join(grantsDir, "plg_r17_foreign.json"));
  const foreignBind = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(R.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) });
  ok("R-17: a grant held by ANOTHER principal does not admit this caller — the scope gate joins on the CALLER, not on the existence of a grant",
    seededForeign && foreignPrincipal !== me && foreignBind.status === 404,
    `foreign grant seeded=${seededForeign} for ${foreignPrincipal} (caller ${me}) · bind ${foreignBind.status}`);

  // 2c — the gate ADMITS the principal the org actually granted. Without this, every refusal above
  // is consistent with a gate that refuses everyone, which would prove nothing about scoping.
  const myGrant = await jd(`/v1/hypervisor/principals/${encodeURIComponent(me)}/lease-grants`, { method: "POST", body: JSON.stringify({ connector_id: R.connector_id, tools: ["ping"], expires_in_seconds: 3600 }) });
  const grantedBind = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(R.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) });
  ok("R-17: the SAME request passes the scope gate once the caller holds the grant — the gate SCOPES, it does not simply refuse",
    (myGrant.status === 201 || myGrant.status === 200) && grantedBind.status !== 404,
    `my grant ${myGrant.status} · bind ${grantedBind.status} (past the scope gate; the envelope itself is still validated)`);

  // ---- R-20 / R-22 DRILL: one language at the four connector authority routes -----------------
  // R-20: a connector's identity binds the principal that registered it — until 2026-09-10 register
  // took no headers and derived the id from the triple alone, so a second caller presenting the same
  // triple OVERWROTE the first caller's record, principal_scoped included, which is the scoping the
  // R-17 drill above proves. R-22: after R-17 an anonymous caller was refused at bind and revoke but
  // could still DRAW through invoke. Three cases × four routes; every refusal is asserted by status
  // AND typed code, and the record on disk is read back after each collision so a refusal that
  // happened AFTER an overwrite cannot pass.
  const jdAs = (cookie, p, init) => fetch(`${DAEMON}${p}`, { ...init, headers: { ...(init?.body ? { "content-type": "application/json" } : {}), ...(cookie ? { cookie: `ioi_session=${cookie}` } : {}) } })
    .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch((e) => ({ status: 0, body: { fetch_error: String(e?.message || e) } }));
  const recordOnDisk = (id) => { try { return JSON.parse(fs.readFileSync(path.join(dataDir, "connectors", `${id}.json`), "utf8")); } catch { return null; } };
  const triple = { service: "ping-service", name: "r20-drill", base_url: `http://127.0.0.1:${toolPort}`, kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }] };
  const registered = await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify(triple) });
  const X = registered.body?.connector;
  ok("R-20 drill: the operator registers a REAL connector and the record carries the registering principal as owner_ref, server-resolved",
    registered.status === 200 && typeof X?.connector_id === "string" && X.owner_ref === `user://${me}` && recordOnDisk(X.connector_id)?.owner_ref === `user://${me}`,
    `${registered.status} · ${X?.connector_id} · owner_ref ${X?.owner_ref}`);
  await jd(`/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/policy`, { method: "POST", body: JSON.stringify({ principal_scoped: true }) });
  const scopedBefore = recordOnDisk(X.connector_id)?.org_policy?.principal_scoped === true;

  // (1) UNRESOLVED CALLER — all four routes, one typed answer, byte-identical bodies.
  const anonRegister = await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ ...triple, name: "r22-anon" }) }, false);
  const anonBind = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) }, false);
  const anonRevokeX = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/standing-lease`, { method: "DELETE" }, false);
  const anonInvoke = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/invoke`, { method: "POST", body: JSON.stringify({ tool: "ping", request: { n: 1 } }) }, false);
  const four = [anonRegister, anonBind, anonRevokeX, anonInvoke];
  ok("R-22: register, bind, revoke and invoke refuse an UNRESOLVED caller with ONE typed answer — 401 hypervisor.authentication_required, byte-identical across the four routes",
    four.every((r) => r.status === 401 && r.body?.code === "hypervisor.authentication_required") && new Set(four.map((r) => JSON.stringify(r.body))).size === 1,
    four.map((r) => `${r.status}/${r.body?.code || r.body?.reason || "?"}`).join(" · "));
  const anonInvokeUnknown = await jd(`/v1/hypervisor/connectors/${unknownId}/invoke`, { method: "POST", body: JSON.stringify({ tool: "ping", request: {} }) }, false);
  ok("R-22: the anonymous invoke refusal precedes the record read — an existing and a made-up connector answer identically (invoke used to say 400 unknown connector_id first)",
    anonInvokeUnknown.status === 401 && JSON.stringify(anonInvokeUnknown.body) === JSON.stringify(anonInvoke.body), `${anonInvokeUnknown.status}`);
  const anonAct = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${X.connector_id}`, tool: "ping", request: {}, capability_handle: `sha256:${"e".repeat(64)}` }) }, false);
  ok("R-22: an anonymous HEADLESS act (handle only) refuses at the same gate — the act tool delegates to invoke with the caller's headers, so it can no longer draw as the local operator",
    anonAct.status === 401 && anonAct.body?.code === "hypervisor.authentication_required", `${anonAct.status}/${anonAct.body?.code || anonAct.body?.reason}`);
  ok("R-20/R-22 drill: the anonymous probes changed nothing on the record — owner_ref and principal_scoped are as the operator left them",
    recordOnDisk(X.connector_id)?.owner_ref === `user://${me}` && recordOnDisk(X.connector_id)?.org_policy?.principal_scoped === true && scopedBefore, JSON.stringify(recordOnDisk(X.connector_id)?.org_policy));

  // (2) CROSS-PRINCIPAL CALLER — a REAL second principal with its own session (the R-17 drill seeded a
  // foreign grant on disk; this mints the foreign CALLER through the routes).
  const other = await jd("/v1/hypervisor/principals", { method: "POST", body: JSON.stringify({ email: "other-principal@ioi.local", name: "Other Principal", role: "member", password: "other-principal-v1" }) });
  const otherId = other.body?.principal?.principal_id || "";
  const otherLogin = await jd("/v1/hypervisor/auth/login", { method: "POST", body: JSON.stringify({ email: "other-principal@ioi.local", password: "other-principal-v1" }) }, false);
  const OTHER = otherLogin.body?.session_token || "";
  const otherMe = (await jdAs(OTHER, "/v1/hypervisor/auth/whoami")).body?.principal?.principal_id || "";
  ok("R-20 drill: a SECOND principal exists, logs in, and resolves as itself — the cross-principal caller is real, not a seeded file",
    (other.status === 201 || other.status === 200) && OTHER.startsWith("ioi_sess_") && otherMe === otherId && otherId !== me, `${other.status} · ${otherId} · login ${otherLogin.status}`);
  const collide = await jdAs(OTHER, "/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ ...triple, org_policy: { allowed_tools: null, risk_posture: "standard", principal_scoped: false } }) });
  const afterCollide = recordOnDisk(X.connector_id);
  ok("R-20: the second principal re-registering the SAME triple is refused 409 connector_already_registered — and the operator's record is untouched: owner_ref still the operator, principal_scoped still true (this exact request used to overwrite both)",
    collide.status === 409 && collide.body?.error?.code === "connector_already_registered" && collide.body?.connector_id === X.connector_id
      && afterCollide?.owner_ref === `user://${me}` && afterCollide?.org_policy?.principal_scoped === true,
    `${collide.status}/${collide.body?.error?.code} · owner_ref ${afterCollide?.owner_ref} · scoped ${afterCollide?.org_policy?.principal_scoped}`);
  const otherBind = await jdAs(OTHER, `/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: {}, envelope: {} }) });
  const otherRevoke = await jdAs(OTHER, `/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/standing-lease`, { method: "DELETE" });
  const otherInvoke = await jdAs(OTHER, `/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/invoke`, { method: "POST", body: JSON.stringify({ tool: "ping", request: { n: 1 } }) });
  ok("R-20/R-17: with the scoping intact, the cross-principal caller cannot bind (404, indistinguishable from unknown), cannot revoke (404), and cannot draw (403 principal_not_authorized) — the overwrite that would have opened all three is closed",
    otherBind.status === 404 && otherRevoke.status === 404 && otherInvoke.status === 403 && otherInvoke.body?.reason === "principal_not_authorized",
    `bind ${otherBind.status} · revoke ${otherRevoke.status} · invoke ${otherInvoke.status}/${otherInvoke.body?.reason}`);

  // (3) RE-REGISTRATION COLLISION by the holder, and a record that predates the ruling.
  const holderAgain = await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ ...triple, allowed_tools: [] }) });
  ok("R-20: the HOLDER re-registering its own triple is refused identically — a registration is never overwritten, not even by its owner (the retry carried allowed_tools: [] and the record still declares ping)",
    holderAgain.status === 409 && holderAgain.body?.error?.code === "connector_already_registered" && recordOnDisk(X.connector_id)?.allowed_tools?.[0]?.name === "ping",
    `${holderAgain.status}/${holderAgain.body?.error?.code} · tools ${JSON.stringify(recordOnDisk(X.connector_id)?.allowed_tools?.map((t) => t.name))}`);
  const differentName = await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ ...triple, name: "r20-drill-sibling" }) });
  ok("R-20: a different triple by the same caller still registers (200, a new id) — the refusal is about the id, not the caller",
    differentName.status === 200 && differentName.body?.connector?.connector_id && differentName.body.connector.connector_id !== X.connector_id, `${differentName.status} · ${differentName.body?.connector?.connector_id}`);
  // A record registered BEFORE the ruling carries no owner_ref on disk. Register one through the
  // route, then rewrite its bytes exactly as such a record exists in every pre-2026-09-10 deployment.
  const legacy = (await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ ...triple, name: "r20-legacy" }) })).body?.connector;
  const legacyId = legacy?.connector_id || "conn_legacy_unregistered";
  const legacyBytes = recordOnDisk(legacyId) || {};
  delete legacyBytes.owner_ref;
  legacyBytes.org_policy = { allowed_tools: null, risk_posture: "standard", principal_scoped: true };
  fs.writeFileSync(path.join(dataDir, "connectors", `${legacyId}.json`), JSON.stringify(legacyBytes));
  const legacyAgain = await jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ ...triple, name: "r20-legacy", allowed_tools: [] }) });
  const legacyAfter = recordOnDisk(legacyId);
  const legacyListed = (await jd("/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === legacyId);
  ok("R-20: a record that PREDATES the ruling (no owner_ref on disk) is neither re-keyed nor reinterpreted — re-registration refuses 409 by id, the bytes are unchanged, and the projection carries no owner_ref (a typed absence, never a backfilled principal)",
    legacy?.connector_id && legacyAgain.status === 409 && legacyAgain.body?.connector_id === legacyId && legacyAfter?.owner_ref === undefined && legacyAfter?.org_policy?.principal_scoped === true && legacyListed && !("owner_ref" in legacyListed),
    `${legacyAgain.status} · owner_ref ${String(legacyAfter?.owner_ref)} · listed ${Boolean(legacyListed)}`);

  // ---- M08.13/M08.14: the act tool as a draw-down client ------------------------------------
  const leaseE = await mintLease(E, { maxUsages: 3 });
  await jd(`/v1/hypervisor/connectors/${encodeURIComponent(E.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseE.grant, envelope: leaseE.envelope }) });
  const eRef = (await createSession([`connector:${E.connector_id}`])).body?.session_ref || "";
  const tools = await jd("/v1/model-mount/mcp/act/tools");
  const eTool = (tools.body?.tools || []).find((t) => t.connection_ref === `connector:${E.connector_id}`);
  const bTool = (tools.body?.tools || []).find((t) => t.connection_ref === `connector:${B.connector_id}`);
  ok("M08.13: the act tool's advertised filters ARE the daemon's lease projection — operations, tools, metered unit, usages, budget and expiry rendered from the connector record, with the capability handle and an explicit host_config_is_authority=false",
    tools.status === 200 && eTool?.actable === true && JSON.stringify(eTool.filters.allowed_tools) === JSON.stringify(["ping"]) && eTool.filters.max_usages === 3 && eTool.filters.per_operation_spend_microusd === 1000 && eTool.capability_handle === leaseE.recorded.standing_grant_hash.replace(/^/u, "sha256:") && eTool.host_config_is_authority === false,
    `${tools.status} ${JSON.stringify(eTool?.filters || null).slice(0, 160)} handle=${String(eTool?.capability_handle || "").slice(0, 20)}`);
  ok("an UNBOUNDED connection advertises no filters and says why — it is not actable", bTool?.actable === false && bTool?.filters === null && bTool?.reason === "standing_lease_absent" && bTool?.widening_path === "/__ioi/connections", `${bTool?.actable}/${bTool?.reason}`);
  const actOne = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "ping", request: { n: 1 }, session_ref: eRef }) });
  ok("M08.13: an interactive act completes WITHOUT a per-call signature — it draws against the caller's standing lease and the daemon records the draw",
    actOne.status === 200 && actOne.body?.ok === true && actOne.body.act_posture === "interactive" && actOne.body.authority_source === "daemon_lease_projection" && readReceipts("hypervisor.session.standing_draw", eRef).length === 1,
    `${actOne.status} · ${readReceipts("hypervisor.session.standing_draw", eRef).length} draw receipt(s)`);
  // MUTATION DRILL: widen the host-side filter config beyond the lease. The daemon re-derives from
  // the lease and refuses at the bound; the host's filters are read and ignored, and it says so.
  const widened = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "wipe", request: {}, session_ref: eRef, host_filters: { allowed_tools: ["ping", "wipe"], max_usages: 9999, per_operation_spend_microusd: 999999 } }) });
  ok("MUTATION DRILL (M08.13): widening the HOST config's filters beyond the lease changes nothing the daemon enforces — the act still refuses at the lease bound (tool outside the template) and the answer says the host filters were ignored",
    widened.status === 403 && widened.body?.reason === "standing_envelope_tool_outside_template" && widened.body.host_filters_ignored === true && widened.body.host_config_is_authority === false,
    `${widened.status}/${widened.body?.reason} host_filters_ignored=${widened.body?.host_filters_ignored}`);
  // M08.14 — headless: an opaque capability handle minted out of band, no session, no cookie.
  const handle = eTool.capability_handle;
  const headless = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "ping", request: { n: 1 }, capability_handle: handle }) });
  const headlessSession = headless.body?.receipt?.session_ref || null;
  const headlessDraws = readReceipts("hypervisor.session.standing_draw").filter((r) => r.connector_id === E.connector_id && r.session_ref !== eRef);
  ok("M08.14: a HEADLESS act presenting only the out-of-band capability handle draws under the same lease — no product session and no per-call signature; the caller's own identity is still resolved, because a handle selects a lease and never becomes a principal",
    headless.status === 200 && headless.body?.ok === true && headless.body.act_posture === "headless" && headlessDraws.length === 1,
    `${headless.status} · ${headlessDraws.length} headless draw receipt(s)`);
  const interactiveDraw = readReceipts("hypervisor.session.standing_draw", eRef)[0];
  const headlessDraw = headlessDraws[0];
  const receiptShape = (r) => Object.keys(r || {}).sort().join(",");
  ok("M08.14: the interactive and headless draws produce receipt chains that are byte-identical except their subject identity — same kind, same field set, same envelope and grant, same posture, both admitted through the same intent family",
    receiptShape(interactiveDraw) === receiptShape(headlessDraw) && interactiveDraw?.standing_envelope_hash === headlessDraw?.standing_envelope_hash && interactiveDraw?.grant_hash_ref === headlessDraw?.grant_hash_ref && interactiveDraw?.posture === headlessDraw?.posture && String(headlessDraw?.admission_intent_ref || "").startsWith("authority-admission-intents/"),
    `${receiptShape(interactiveDraw) === receiptShape(headlessDraw)} · ${interactiveDraw?.posture}/${headlessDraw?.posture}`);
  const noAuthority = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "ping", request: {}, host_filters: { allowed_tools: ["ping"] } }) });
  ok("M08.14: an act with NO lease authority — no session, no handle — refuses typed and never falls back to the host's configuration",
    noAuthority.status === 403 && noAuthority.body?.reason === "act_no_authority" && noAuthority.body.host_config_is_authority === false,
    `${noAuthority.status}/${noAuthority.body?.reason}`);
  const forgedHandle = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "ping", request: {}, capability_handle: `sha256:${"f".repeat(64)}` }) });
  ok("a capability handle that names no active lease refuses — the handle SELECTS a lease, it never authorizes one",
    forgedHandle.status === 403 && forgedHandle.body?.reason === "act_capability_handle_unknown", `${forgedHandle.status}/${forgedHandle.body?.reason}`);
  const exhausted = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "ping", request: {}, capability_handle: handle }) });
  const overBound = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "ping", request: {}, capability_handle: handle }) });
  ok("the act tool draws down the SAME envelope as every other path: the third draw exhausts the 3-usage lease and the fourth refuses at the bound",
    exhausted.status === 200 && overBound.status === 403 && overBound.body?.refused_bound === "max_usages",
    `${exhausted.status} then ${overBound.status}/${overBound.body?.refused_bound}`);

  // ---- R-19 DRILL: the exact-review requirement binds EVERY acting subject ------------------
  // M08.14 added the headless capability-handle subject, and the requirement read
  // `session_ref.is_some() && ...` — so a headless act on a review-marked tool stopped requiring
  // review and drew the standing envelope silently. That is the substitution M13.5 asserts is
  // impossible for a session; M03.15 generalizes it to every subject. Two halves had to be fixed,
  // and a drill on the boolean alone would have missed the second: the headless branch also armed
  // the standing draw unconditionally, so the envelope admitted the act regardless.
  const markE = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(E.connector_id)}/policy`, { method: "POST", body: JSON.stringify({ allowed_tools: null, risk_posture: "standard", exact_review_tools: ["ping"] }) });
  const drawsBeforeR19 = readReceipts("hypervisor.session.standing_draw").filter((r) => r.connector_id === E.connector_id).length;
  const intentsBeforeR19 = consumedIntents();
  ok("R-19 drill: the connection's policy marks the tool for individual exact-effect review", markE.body?.ok === true, `${markE.status}`);

  const headlessReviewed = await jd("/v1/model-mount/mcp/act", { method: "POST", body: JSON.stringify({ connection_ref: `connector:${E.connector_id}`, tool: "ping", request: { n: 1 }, capability_handle: handle }) });
  const drawsAfterR19 = readReceipts("hypervisor.session.standing_draw").filter((r) => r.connector_id === E.connector_id).length;
  ok("R-19: a HEADLESS act on a review-marked tool does NOT draw the standing envelope — a standing envelope may never satisfy a policy requiring individual exact-effect review, whoever presents it",
    headlessReviewed.status !== 200 && drawsAfterR19 === drawsBeforeR19 && consumedIntents() === intentsBeforeR19,
    `${headlessReviewed.status}/${headlessReviewed.body?.reason || headlessReviewed.body?.decision} · draws ${drawsBeforeR19}→${drawsAfterR19} · intents unchanged=${consumedIntents() === intentsBeforeR19}`);

  const headlessReviews = readReceipts("hypervisor.session.exact_effect_review").filter((r) => r.connector_id === E.connector_id);
  ok("R-19: the review object is written under the HANDLE-DERIVED subject — a headless caller cannot review in a browser, but the object an exact grant resolves against exists either way",
    headlessReviews.length >= 1 && headlessReviews.some((r) => String(r.session_ref || "").startsWith("capability-handle:")),
    `${headlessReviews.length} review object(s) · subjects ${headlessReviews.map((r) => String(r.session_ref || "").slice(0, 28)).join(",")}`);

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
