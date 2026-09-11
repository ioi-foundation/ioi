#!/usr/bin/env node
// M03.15 — generic exact-effect review for every acting subject (ACC-18; ADR 0052 § 3, R-19,
// ADR 0053 § 3). The claim: when the admitted policy marks an effect for individual exact-effect
// review, NO acting subject can cause that effect without an exact grant bound to the daemon's own
// commitments for that exact act — and substituting any of payload, destination, subject, reviewer,
// policy revision or expiry after the review, or revoking the connection, yields ZERO final-invoker
// calls and consumes no authority. The final invoker is a tool server this verifier owns, so "zero
// calls" is counted at the effect, not inferred from a status code.
//
// Source-neutral: the SESSION subject (review object + exact grant) and the OPERATOR'S DIRECT ACT
// (authority challenge + exact grant) are both driven here. The HEADLESS capability-handle subject's
// review OBJECT is proven by check:standing-consumer-loop (R-19); its approved path is a typed
// absence of this verifier, recorded in the summary, until a headless approval lane exists.
//
// Scaffold: the real wallet.network principal-authority fixture (Solo profile), one daemon on a
// temp data dir, two tool servers (two destinations), the operator bootstrapped from the daemon's
// one-boot token. Every child is owned and reaped on exit AND on signal (leg 3 of the correctness
// program: a wrapper's SIGTERM must never strand a daemon).
//
// Env:
//   IOI_HYPERVISOR_DAEMON_BINARY   default target/debug/hypervisor-daemon
//   --self-drill                   plants "the tool is NOT marked for review" and requires the
//                                  review-issuance assertion to go red (the verifier cannot pass
//                                  on a policy that requires nothing).
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
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const PRINCIPAL = "domain://acme-host";
const SESSION_ENVELOPE_CONTRACT = "schema://ioi/components/hypervisor/session-standing-envelope/v1";
// The fixture registers this deterministic public seed as the approver for PRINCIPAL; the expiry
// case mints with it directly so it can set --expires-at in the past.
const FIXTURE_APPROVER_SEED_HEX = "07".repeat(32);
const SELF_DRILL = process.argv.includes("--self-drill");
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const freePort = () => new Promise((resolve, reject) => { const srv = net.createServer(); srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); }); srv.on("error", reject); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up */ } await new Promise((r) => setTimeout(r, 250)); } throw new Error(`not up: ${url}`); };

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch { console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`); process.exit(2); }

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-exact-effect-review-"));
let daemon = null; let daemonPort = 0; let DAEMON = ""; let SESSION = ""; let fixture = null; let daemonEnv = {};
const toolServers = [];

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
  for (const s of toolServers) { try { s.server.close(); } catch { /* closed */ } }
  try { await fixture?.stop(); } catch { /* best effort */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}
for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]]) {
  process.on(signal, () => { console.error(`${signal}: reaping owned children`); reapAll().finally(() => process.exit(code)); });
}

// A tool server that COUNTS every call it serves: the final invoker.
async function startToolServer(label) {
  const port = await freePort();
  const entry = { label, port, hits: 0, server: null };
  entry.server = http.createServer((req, res) => { entry.hits += 1; res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ pong: true, label, path: req.url })); });
  await new Promise((resolve) => entry.server.listen(port, "127.0.0.1", resolve));
  toolServers.push(entry);
  return entry;
}

const jd = (p, init, cookie = true) => fetch(`${DAEMON}${p}`, { ...init, headers: { ...(init?.body ? { "content-type": "application/json" } : {}), ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}) } })
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch((e) => ({ status: 0, body: { fetch_error: String(e?.message || e) } }));
const readReceipts = (kind, sessionRef) => { const found = []; try { for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) { try { const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8")); if (j.kind === kind && (sessionRef === undefined || j.session_ref === sessionRef)) found.push(j); } catch { /* not JSON */ } } } catch { /* none */ } return found; };
const invoke = (connectorId, sessionRef, n, extra = {}) => jd(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/invoke`, { method: "POST", body: JSON.stringify({ tool: "ping", request: { n }, ...(sessionRef ? { session_ref: sessionRef } : {}), ...extra }) });
const createSession = (refs) => jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: "project:exact-effect-review", authority_profile: { connection_refs: refs } }) });
const markForReview = (connectorId, tools = ["ping"]) => jd(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/policy`, { method: "POST", body: JSON.stringify({ allowed_tools: null, risk_posture: "standard", exact_review_tools: tools }) });
const refused = (r) => r.status >= 400 && r.body?.ok !== true;
// The challenge names the exact target scope the approval must be RECORDED against on wallet.network
// (an unrecorded grant is refused as "no state for the exact approval grant"); read it the way the
// estate's other verifiers do, from wherever the response carries it.
let SCOPE = "";
const scopeOf = (r) => r.body?.required_authority_scope ?? r.body?.authority_challenge?.required_authority_scope ?? SCOPE;
const recorded = (r) => fixture.mintRecorded(PRINCIPAL, r.body?.approval?.policy_hash, r.body?.approval?.request_hash, scopeOf(r));
const recordOrNote = async (r, grant) => { try { await fixture.recordApproval(PRINCIPAL, r.body?.approval?.policy_hash, r.body?.approval?.request_hash, grant, scopeOf(r)); return "recorded"; } catch (error) { return `record refused: ${String(error?.message || error).slice(0, 80)}`; } };

// A session may name only a BOUNDED connection (M13.3: an unbounded attach refuses at create, 412),
// so each destination carries an attach-time standing envelope. Every act under test is
// review-marked and therefore never draws it; the envelope is the attach, not the authority.
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
  fixture = await startRealWalletNetworkPrincipalAuthorityFixture({
    wallClockChain: true,
    baseEnv: {
      ...process.env,
      IOI_M049_ORDERING_PROFILE: process.env.IOI_ALPHA_FIXTURE_ORDERING_PROFILE || "Solo",
      IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: process.env.IOI_ALPHA_FIXTURE_COMMIT_TIMEOUT_SECS || "900",
      IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1500000",
    },
  });
  const toolX = await startToolServer("X");
  const toolY = await startToolServer("Y");
  daemonPort = await freePort(); DAEMON = `http://127.0.0.1:${daemonPort}`;
  daemonEnv = { ...process.env, ...fixture.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: PRINCIPAL, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" };
  delete daemonEnv.IOI_WALLET_TEST_SIGNER;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) { const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "exact-effect-review-v1", email: "exact-review@ioi.local" }) }); SESSION = boot.body?.session_token ?? ""; }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  const register = (name, port) => jd("/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ service: "ping-service", name, base_url: `http://127.0.0.1:${port}`, kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }] }) });
  const X = (await register("review-x", toolX.port)).body?.connector;
  const Y = (await register("review-y", toolY.port)).body?.connector;
  ok("two real connectors register: the same service and tool names, two destinations", X?.connector_id && Y?.connector_id && X.connector_id !== Y.connector_id, `${X?.connector_id} ${Y?.connector_id}`);
  const leaseX = await mintLease(X, { maxUsages: 20 }); const leaseY = await mintLease(Y, { maxUsages: 20 });
  const bindX = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseX.grant, envelope: leaseX.envelope }) });
  const bindY = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(Y.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant: leaseY.grant, envelope: leaseY.envelope }) });
  ok("both destinations carry an attach-time standing envelope (a session may name only a bounded connection); the review-marked acts below never draw it", bindX.status === 200 && bindY.status === 200, `${bindX.status}/${bindY.status}`);
  if (!SELF_DRILL) {
    const mx = await markForReview(X.connector_id); const my = await markForReview(Y.connector_id);
    ok("the admitted policy marks `ping` for individual exact-effect review on both destinations", mx.body?.ok === true && my.body?.ok === true, `${mx.status}/${my.status}`);
  } else {
    ok("SELF-DRILL: the tool is deliberately NOT marked for review (planted)", true, "the review-issuance assertion below must go red");
  }

  const S = (await createSession([`connector:${X.connector_id}`])).body?.session_ref || "";
  const S2 = (await createSession([`connector:${X.connector_id}`])).body?.session_ref || "";
  const SXY = (await createSession([`connector:${X.connector_id}`, `connector:${Y.connector_id}`])).body?.session_ref || "";
  ok("three sessions exist: S and S2 naming X, SXY naming X and Y (closed profiles)", S && S2 && SXY && S !== S2, `${S} ${S2} ${SXY}`);

  // The wallet records an approval against the crossing's exact authority scope. The operator's
  // direct act names it on its 403 (`required_authority_scope`); it is the same scope for every
  // subject on this connection, so it is learned once here and the review bodies are checked for it.
  const scopeProbe = await invoke(X.connector_id, null, 0);
  SCOPE = scopeProbe.body?.required_authority_scope || "";
  ok("the crossing's exact authority scope is named by the daemon (required_authority_scope on the operator's direct-act challenge)", scopeProbe.status === 403 && SCOPE.length > 0 && toolX.hits === 0, `${scopeProbe.status} · ${SCOPE}`);

  // ---- (0) REVIEW ISSUANCE — the effect is marked, so the session act parks on a review object ----
  const review = await invoke(X.connector_id, S, 1);
  const R = review.body?.approval?.request_hash; const P = review.body?.approval?.policy_hash;
  ok("a session act on a review-marked tool yields 202 exact_effect_review_required with the daemon's commitments (request_hash, policy_hash) and NO final-invoker call",
    review.status === 202 && review.body?.reason === "exact_effect_review_required" && typeof R === "string" && typeof P === "string" && review.body?.required_authority_scope === SCOPE && toolX.hits === 0,
    `${review.status}/${review.body?.reason} · scope ${review.body?.required_authority_scope} · hits ${toolX.hits}`);
  const reviews = readReceipts("hypervisor.session.exact_effect_review", S);
  ok("the review object is DURABLE and commits to payload hash, destination, policy/request hashes and an expiry",
    reviews.length === 1 && reviews[0].request_hash === R && String(reviews[0].payload_hash || "").startsWith("sha256:") && String(reviews[0].destination || "").includes(`127.0.0.1:${toolX.port}`) && Number.isFinite(reviews[0].expires_at_ms),
    `${reviews.length} review(s) · ${reviews[0]?.destination}`);
  if (SELF_DRILL) return;

  // ---- (1) POSITIVE CONTROL — the exact grant bound to the review's commitments admits the act ONCE ----
  // The grant's AUDIENCE is the daemon's wallet capability account — wallet.network consumes a grant
  // only when its audience is the consuming signer — so every exact grant here is minted for it.
  const grant = await recorded(review);
  const approved = await invoke(X.connector_id, S, 1, { wallet_approval_grant: grant });
  ok("an exact grant bound to the review's policy and request hashes admits the SAME act: 200, exactly ONE final-invoker call",
    approved.status === 200 && approved.body?.ok === true && toolX.hits === 1, `${approved.status}/${approved.body?.reason || "ok"} · hits ${toolX.hits} · scope ${scopeOf(review) || "(none on the challenge)"} · grant error ${JSON.stringify(approved.body?.authority_challenge?.error || approved.body?.error || approved.body?.message || "").slice(0, 160)}`);
  const replay = await invoke(X.connector_id, S, 1, { wallet_approval_grant: grant });
  const replay2 = await invoke(X.connector_id, S, 1, { wallet_approval_grant: grant });
  ok("REPLAY / UI-BYPASS: the consumed grant refuses on a direct daemon replay, twice, identically — exactly-once is admission's, not a surface's",
    refused(replay) && refused(replay2) && replay.status === replay2.status && replay.body?.reason === replay2.body?.reason && toolX.hits === 1,
    `${replay.status}/${replay.body?.reason} · ${replay2.status}/${replay2.body?.reason} · hits ${toolX.hits}`);
  const forged = await invoke(X.connector_id, S, 1, { wallet_approval_grant: { schema_version: 1, forged: true } });
  ok("a forged grant refuses with zero calls", refused(forged) && toolX.hits === 1, `${forged.status}/${forged.body?.reason}`);

  // ---- (2) PAYLOAD SUBSTITUTION ---------------------------------------------------------------------
  const rv2 = await invoke(X.connector_id, S, 2); const grant2 = await recorded(rv2);
  const swapped = await invoke(X.connector_id, S, 3, { wallet_approval_grant: grant2 });
  const honest2 = await invoke(X.connector_id, S, 2, { wallet_approval_grant: grant2 });
  ok("PAYLOAD: a grant reviewed for payload {n:2} refuses payload {n:3} with zero calls, and admits {n:2} once — the refusal was the substitution, not the grant",
    rv2.status === 202 && refused(swapped) && honest2.status === 200 && toolX.hits === 2, `swap ${swapped.status}/${swapped.body?.reason} · honest ${honest2.status} · hits ${toolX.hits}`);

  // ---- (3) DESTINATION SUBSTITUTION — same service, same tool, same bytes, another host ------------
  const rv4 = await invoke(X.connector_id, SXY, 4); const grant4 = await recorded(rv4);
  const otherDest = await invoke(Y.connector_id, SXY, 4, { wallet_approval_grant: grant4 });
  ok("DESTINATION: a grant reviewed for destination X refuses on destination Y (same service, tool and bytes; only the host differs) with zero calls on Y",
    rv4.status === 202 && refused(otherDest) && toolY.hits === 0, `${otherDest.status}/${otherDest.body?.reason} · hitsY ${toolY.hits}`);
  const honest4 = await invoke(X.connector_id, SXY, 4, { wallet_approval_grant: grant4 });
  ok("…and still admits the reviewed destination once", honest4.status === 200 && toolX.hits === 3, `${honest4.status} · hitsX ${toolX.hits}`);

  // ---- (4) SUBJECT SUBSTITUTION — another session, and the operator's direct act -------------------
  const rv5 = await invoke(X.connector_id, S, 5); const grant5 = await recorded(rv5);
  const otherSession = await invoke(X.connector_id, S2, 5, { wallet_approval_grant: grant5 });
  const asOperator = await invoke(X.connector_id, null, 5, { wallet_approval_grant: grant5 });
  ok("SUBJECT: a grant reviewed under session S refuses under session S2 and as the operator's direct act, zero calls",
    refused(otherSession) && refused(asOperator) && toolX.hits === 3, `S2 ${otherSession.status}/${otherSession.body?.reason} · direct ${asOperator.status}/${asOperator.body?.reason} · hits ${toolX.hits}`);

  // ---- (5) REVIEWER SUBSTITUTION — a signer that is not the bound approver ----------------------------
  const rv6 = await invoke(X.connector_id, S, 6);
  const stranger = mintApprovalGrant({ seed: crypto.randomBytes(32).toString("hex"), policyHash: rv6.body?.approval?.policy_hash, requestHash: rv6.body?.approval?.request_hash, audience: fixture.capabilityAccountId });
  const strangerRecord = await recordOrNote(rv6, stranger);
  const strangerAct = await invoke(X.connector_id, S, 6, { wallet_approval_grant: stranger });
  const grant6 = await recorded(rv6);
  const honest6 = await invoke(X.connector_id, S, 6, { wallet_approval_grant: grant6 });
  ok("REVIEWER: a grant signed by a key that is not the bound approver refuses with zero calls; the bound approver's grant for the same review admits once",
    refused(strangerAct) && honest6.status === 200 && toolX.hits === 4, `stranger ${strangerAct.status}/${strangerAct.body?.reason} (${strangerRecord}) · honest ${honest6.status} · hits ${toolX.hits}`);

  // ---- (6) POLICY SUBSTITUTION — a grant bound to another policy revision ----------------------------
  const rv7 = await invoke(X.connector_id, S, 7);
  const otherPolicyHash = `sha256:${crypto.randomBytes(32).toString("hex")}`;
  const otherPolicy = fixture.mintForCapability(PRINCIPAL, otherPolicyHash, rv7.body?.approval?.request_hash);
  let otherPolicyRecord; try { await fixture.recordApproval(PRINCIPAL, otherPolicyHash, rv7.body?.approval?.request_hash, otherPolicy, scopeOf(rv7)); otherPolicyRecord = "recorded"; } catch (error) { otherPolicyRecord = `record refused: ${String(error?.message || error).slice(0, 80)}`; }
  const otherPolicyAct = await invoke(X.connector_id, S, 7, { wallet_approval_grant: otherPolicy });
  ok("POLICY: a grant bound to another policy revision (right request, wrong policy hash) refuses with zero calls",
    rv7.status === 202 && refused(otherPolicyAct) && toolX.hits === 4, `${otherPolicyAct.status}/${otherPolicyAct.body?.reason} (${otherPolicyRecord}) · hits ${toolX.hits}`);

  // ---- (7) EXPIRY — an expired grant for a live review ----------------------------------------------
  const rv8 = await invoke(X.connector_id, S, 8);
  const expired = mintApprovalGrant({ seed: FIXTURE_APPROVER_SEED_HEX, policyHash: rv8.body?.approval?.policy_hash, requestHash: rv8.body?.approval?.request_hash, audience: fixture.capabilityAccountId, expiresAt: Date.now() - 60_000 });
  const expiredRecord = await recordOrNote(rv8, expired);
  const expiredAct = await invoke(X.connector_id, S, 8, { wallet_approval_grant: expired });
  ok("EXPIRY: an expired grant for a live review refuses with zero calls", refused(expiredAct) && toolX.hits === 4, `${expiredAct.status}/${expiredAct.body?.reason} (${expiredRecord}) · hits ${toolX.hits}`);

  // ---- (8) SOURCE-NEUTRAL: the operator's DIRECT act is an exact-effect approval too ---------------
  const direct = await invoke(X.connector_id, null, 10);
  const dR = direct.body?.approval?.request_hash; const dP = direct.body?.approval?.policy_hash;
  const dGrant = await recorded(direct);
  const directSwapped = await invoke(X.connector_id, null, 11, { wallet_approval_grant: dGrant });
  const directHonest = await invoke(X.connector_id, null, 10, { wallet_approval_grant: dGrant });
  ok("DIRECT ACT: the operator's session-less act parks on the exact authority challenge (403 with commitments), a payload substitution against its grant refuses, and the reviewed bytes admit once",
    direct.status === 403 && typeof dR === "string" && refused(directSwapped) && directHonest.status === 200 && toolX.hits === 5,
    `${direct.status} · swap ${directSwapped.status}/${directSwapped.body?.reason} · honest ${directHonest.status} · hits ${toolX.hits}`);

  // ---- (9) REVOCATION — the connection is revoked after review; the grant is dead ---------------------
  const rv9 = await invoke(X.connector_id, S, 9); const grant9 = await recorded(rv9);
  const del = await jd(`/v1/hypervisor/connectors/${encodeURIComponent(X.connector_id)}`, { method: "DELETE" });
  const afterRevoke = await invoke(X.connector_id, S, 9, { wallet_approval_grant: grant9 });
  ok("REVOCATION: after the connection is revoked, a grant reviewed before the revocation refuses with zero calls",
    rv9.status === 202 && del.status < 300 && refused(afterRevoke) && toolX.hits === 5, `delete ${del.status} · ${afterRevoke.status}/${afterRevoke.body?.reason} · hits ${toolX.hits}`);

  // ---- ledger of what ran -----------------------------------------------------------------------------
  ok("FINAL-INVOKER LEDGER: exactly the five approved acts reached destination X and none reached Y", toolX.hits === 5 && toolY.hits === 0, `X ${toolX.hits} · Y ${toolY.hits}`);
  ok("TYPED ABSENCE (recorded, not a pass): the HEADLESS capability-handle subject's APPROVED path is not driven here — its review object is proven by check:standing-consumer-loop (R-19); an approval lane for a headless review is owed by M03.15's successor", true, "absence recorded");
}

let exitCode = 1;
try {
  await run();
  const passed = results.filter((r) => r.pass).length;
  if (SELF_DRILL) {
    const issuance = results.find((r) => r.name.startsWith("a session act on a review-marked tool yields 202"));
    const drillOk = issuance && !issuance.pass;
    console.log(`${drillOk ? "PASS" : "FAIL"} mutate:exact-effect-review — planted 'not marked for review' turned the review-issuance assertion ${issuance?.pass ? "GREEN (defect: the verifier would pass on a policy that requires nothing)" : "red, as it must"}`);
    exitCode = drillOk ? 0 : 1;
  } else {
    console.log(`${passed === results.length ? "PASS" : "FAIL"} check:exact-effect-review — ${passed}/${results.length} assertions · subjects: session, operator-direct · headless approval: typed absence`);
    emitVerifierCensus({ verifierId: "exact-effect-review", sourceUrl: import.meta.url, results });
    exitCode = passed === results.length ? 0 : 1;
  }
} catch (error) {
  console.error(`FAIL check:exact-effect-review — ${error?.stack || error}`);
} finally {
  await reapAll();
}
process.exit(exitCode);
