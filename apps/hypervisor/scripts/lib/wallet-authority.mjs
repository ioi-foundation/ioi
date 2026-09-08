// The ONE wallet-authority seam for the serve (#67 mandatory authority preflight).
//
// The fixture signer (repo scripts/lib/mint-approval-grant.mjs — a deterministic PUBLIC-seed
// Ed25519 test wallet) is test/fixture-only: production serve/module code must never import or
// invoke it. This adapter is the only place the serve touches wallet grants:
//
//   - PRODUCTION (no flag): mintTestGrant() returns null — a lane needing a grant parks in the
//     honest `awaiting_wallet_authority` state and surfaces the daemon's challenge verbatim so an
//     EXTERNAL wallet holder can sign it. The governed Build workflow's paste handoff
//     (challenge out → opaque signed grant back, held in memory only for the one forward POST)
//     is the production transport.
//   - DEV/TEST (IOI_WALLET_TEST_SIGNER=1): mintTestGrant() dynamically imports the fixture signer
//     and mints against the given challenge hashes — the explicit verifier/dev flag the mandate
//     allows. The import happens ONLY inside the flag check; no static edge to the signer exists.
export const TEST_SIGNER_FLAG = "IOI_WALLET_TEST_SIGNER";

export function testSignerEnabled() {
  return process.env[TEST_SIGNER_FLAG] === "1";
}

// Returns a signed grant under the test flag, null when no signer is attached (production).
// Throws only for a REAL mint failure under the flag — callers distinguish "no signer" (park
// awaiting authority) from "signer broke" (a 5xx-class fault).
export async function mintTestGrant({ policyHash, requestHash }) {
  if (!testSignerEnabled()) return null;
  const { mintApprovalGrant } = await import("../../../../scripts/lib/mint-approval-grant.mjs");
  return mintApprovalGrant({ policyHash, requestHash });
}

// ---- The deployment-local approver (ADR 0052; the bounded-alpha single-operator profile) ------
//
// The alpha profile's authority is a deployment-local wallet.network node whose approval key the
// OPERATOR holds. IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH names that key: a file the operator
// custodies (32-byte seed as 64 hex chars, or the raw 32 bytes), readable only by the serve's
// user. Unlike the test signer, this key NEVER signs automatically: a lane that needs a grant
// parks in `awaiting_operator_approval` with the exact effect, and only an explicit operator
// approval action (the Sessions surface / the approve endpoint, under the operator's own session)
// calls mintLocalApproverGrant for that one challenge. Deny mints nothing. The daemon still
// resolves the deployment authority independently and refuses a grant from any other signer.
export const LOCAL_APPROVER_KEY_PATH = "IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH";

export function localApproverEnabled() {
  return typeof process.env[LOCAL_APPROVER_KEY_PATH] === "string" && process.env[LOCAL_APPROVER_KEY_PATH].length > 0;
}

async function readLocalApproverSeedHex() {
  const keyPath = process.env[LOCAL_APPROVER_KEY_PATH];
  const { readFileSync, statSync } = await import("node:fs");
  const stat = statSync(keyPath);
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`local approver key ${keyPath} is readable by group/other (mode ${(stat.mode & 0o777).toString(8)}); refusing to sign with a shared key`);
  }
  const raw = readFileSync(keyPath);
  const text = raw.toString("utf8").trim();
  if (/^[0-9a-fA-F]{64}$/u.test(text)) return text.toLowerCase();
  if (raw.length === 32) return raw.toString("hex");
  throw new Error(`local approver key ${keyPath} is neither 64 hex characters nor 32 raw bytes`);
}

// Mint ONE grant for ONE exact challenge with the deployment-held approver key. Only an operator
// approval action may call this; nothing else in the serve imports it.
export async function mintLocalApproverGrant({ policyHash, requestHash, audience }) {
  if (!localApproverEnabled()) return null;
  if (!policyHash || !requestHash) throw new Error("local approver refuses to sign without both policy_hash and request_hash");
  // The grant's audience is the daemon's wallet capability account, carried on the challenge the
  // run parked on. wallet.network consumes a grant only when its audience is the consuming signer,
  // so a grant without it can never be consumed; refuse to mint a dead grant.
  if (!/^[0-9a-f]{64}$/u.test(String(audience || ""))) {
    throw new Error("local approver refuses to sign without the daemon's capability audience (the challenge carried none — is the daemon's wallet client configured?)");
  }
  const seed = await readLocalApproverSeedHex();
  const { mintApprovalGrant } = await import("../../../../scripts/lib/mint-approval-grant.mjs");
  // Exactly one use: the grant authorizes THIS challenge once and can never be replayed.
  return mintApprovalGrant({ seed, policyHash, requestHash, audience, maxUsages: 1 });
}

// The operator's approval is ALSO an act against the deployment's authority node: the one-use
// grant is recorded on wallet.network as the approval decision for the challenge's scope. Two
// recorders exist, both the estate's own protocols: the deployment node's control binary
// (IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR names the node; the binary transacts from the daemon's
// capability account under the daemon's transaction lock) and the cargo test fixture's command
// directory (IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR, qualification only). Neither configured
// → the approval refuses, because an unrecorded grant can never be consumed.
export const LOCAL_AUTHORITY_STATE_DIR = "IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR";
export const FIXTURE_COMMANDS_DIR = "IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR";

export async function recordLocalApproverGrant({ grant, targetScope }) {
  if (!grant || !targetScope) throw new Error("approval recording needs the grant and the challenge's target scope");
  const stateDir = process.env[LOCAL_AUTHORITY_STATE_DIR];
  if (stateDir) {
    const { spawnSync } = await import("node:child_process");
    const { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
    const path = await import("node:path");
    const os = await import("node:os");
    const binary = process.env.IOI_WALLET_AUTHORITY_BINARY || path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../../target/debug/wallet-network-local-authority");
    if (!existsSync(binary)) throw new Error(`authority control binary is absent at ${binary}`);
    const passFile = path.join(stateDir, "keys", "guardian.pass");
    const env = { ...process.env, ...(process.env.IOI_GUARDIAN_KEY_PASS ? {} : existsSync(passFile) ? { IOI_GUARDIAN_KEY_PASS: readFileSync(passFile, "utf8").trim() } : {}) };
    const tmp = mkdtempSync(path.join(os.tmpdir(), "ioi-approval-"));
    const grantFile = path.join(tmp, "grant.json");
    try {
      writeFileSync(grantFile, JSON.stringify(grant), { mode: 0o600 });
      const result = spawnSync(binary, ["record-approval", "--state-dir", stateDir, "--grant-file", grantFile, "--target-scope", targetScope], { encoding: "utf8", env });
      if (result.status !== 0) throw new Error(`record-approval failed: ${(result.stderr || result.stdout || "").trim().slice(-400)}`);
      const line = (result.stdout || "").trim().split("\n").reverse().find((l) => l.startsWith("{"));
      return { recorder: "deployment-node", ...(line ? JSON.parse(line) : {}) };
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  const commandsDir = process.env[FIXTURE_COMMANDS_DIR];
  if (commandsDir) {
    const { mkdirSync, writeFileSync, renameSync, existsSync, readFileSync, rmSync } = await import("node:fs");
    const { randomUUID } = await import("node:crypto");
    const path = await import("node:path");
    const principalRef = process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF || "";
    if (!principalRef) throw new Error("fixture recording needs IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF");
    const commandId = randomUUID();
    const dir = path.join(commandsDir, commandId);
    mkdirSync(dir, { mode: 0o700 });
    const hex = (v) => String(v || "").replace(/^sha256:/u, "");
    const payload = { schema_version: 1, operation: "record_approval", principal_ref: principalRef, policy_hash: hex(grant.policy_hash_hex || Buffer.from(grant.policy_hash || []).toString("hex")), request_hash: hex(grant.request_hash_hex || Buffer.from(grant.request_hash || []).toString("hex")), approval_grant: grant, target_scope: targetScope };
    writeFileSync(path.join(dir, "request.json.tmp"), JSON.stringify(payload), { mode: 0o600 });
    renameSync(path.join(dir, "request.json.tmp"), path.join(dir, "request.json"));
    const responsePath = path.join(dir, "response.json");
    const deadline = Date.now() + 900_000;
    while (!existsSync(responsePath)) {
      if (Date.now() > deadline) throw new Error("fixture record_approval timed out");
      await new Promise((r) => setTimeout(r, 50));
    }
    const response = JSON.parse(readFileSync(responsePath, "utf8"));
    rmSync(dir, { recursive: true, force: true });
    if (!response.ok) throw new Error(`fixture record_approval refused: ${response.error || "unknown"}`);
    return { recorder: "fixture", request_hash: response.request_hash };
  }
  throw new Error("no approval recorder is configured (set IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR to the deployment authority node); an unrecorded grant can never be consumed");
}

// The typed parked state when the deployment-local approver holds the key: the run waits for the
// operator's explicit decision on the exact effect. Hashes are public commitments, never secrets.
export function awaitingOperatorApproval(approval) {
  return {
    ok: false,
    status: "awaiting_operator_approval",
    error: {
      code: "operator_approval_required",
      message: "this crossing needs the operator's approval of the exact effect — review it on Work / Sessions and approve or deny",
    },
    approval: approval || null,
  };
}

// The typed parked state for lanes that need a grant and have no signer: the challenge rides
// verbatim (hashes only name WHAT to sign — they are public commitments, never secrets).
export function awaitingWalletAuthority(approval) {
  return {
    ok: false,
    status: "awaiting_wallet_authority",
    error: {
      code: "wallet_authority_required",
      message: "this crossing requires an externally signed wallet grant — no signer is attached to the serve (the dev test signer mounts only under IOI_WALLET_TEST_SIGNER=1)",
    },
    approval: approval || null,
  };
}

// ---- M13.3 — the attach-time standing envelope --------------------------------------------------
//
// The Connections attach flow mints the scoped standing bound in the same pass: a registered
// SessionStandingEnvelope for ONE connector (operations, tools, metered unit, usages, budget,
// window) bound by a StandingApprovalGrant the deployment approver signs, recorded on the
// authority node, then bound to the connector on the daemon. Recording needs the wallet's
// standing-grant evidence rule: an interactive step-up ceremony with a PASSKEY factor receipt.
//   · fixture authority mode (IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR): the qualification
//     fixture records the tuple with the SYNTHETIC contract ceremony the broker-contract verifier
//     uses (labelled; no physical passkey claimed);
//   · deployment mode (IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR): the deployment-local operator
//     key has NO admitted posture for standing envelopes (the auth-factor receipt contract is
//     passkey-only), so this refuses TYPED — `standing_lease_custody_tier_unruled` — until the
//     owner rules the alpha's custody tier for standing authority. Nothing is fabricated.
export const STANDING_LEASE_CUSTODY_TIER_UNRULED = "standing_lease_custody_tier_unruled";
const SESSION_ENVELOPE_CONTRACT = "schema://ioi/components/hypervisor/session-standing-envelope/v1";

function parseBounds(raw = {}) {
  const maxUsages = Number(raw.max_usages ?? raw.maxUsages);
  const budgetUsd = Number(raw.budget_usd ?? raw.budgetUsd ?? 0);
  const expiresHours = Number(raw.expires_hours ?? raw.expiresHours ?? 24);
  const perOpUsd = Number(raw.per_operation_usd ?? raw.perOperationUsd ?? 0);
  if (!Number.isInteger(maxUsages) || maxUsages < 1 || maxUsages > 1_000_000) throw new Error("standing envelope needs an integer max_usages between 1 and 1000000");
  if (!(expiresHours > 0 && expiresHours <= 24 * 90)) throw new Error("standing envelope needs expires_hours between 0 and 2160");
  const perOperationSpend = Math.max(1, Math.round((perOpUsd > 0 ? perOpUsd : (budgetUsd > 0 ? budgetUsd / maxUsages : 0.001)) * 1_000_000));
  const budgetMicro = budgetUsd > 0 ? Math.round(budgetUsd * 1_000_000) : perOperationSpend * maxUsages;
  if (perOperationSpend > budgetMicro) throw new Error("the metered unit per operation exceeds the whole budget");
  const tools = Array.isArray(raw.tools) ? raw.tools.map(String).filter(Boolean) : String(raw.tools || "").split(",").map((t) => t.trim()).filter(Boolean);
  const operations = Array.isArray(raw.operations) && raw.operations.length ? raw.operations.map(String) : ["session_execute", "connector_invoke"];
  return { maxUsages, expiresHours, perOperationSpend, budgetMicro, tools, operations };
}

export function standingLeaseRecorderMode() {
  if (process.env[FIXTURE_COMMANDS_DIR]) return "fixture";
  if (process.env[LOCAL_AUTHORITY_STATE_DIR]) return "deployment";
  return "none";
}

// Returns { ok:true, standing_lease } or { ok:false, code, message } — never throws for a typed
// custody refusal, so the attach surface can render the reason and the journey can record it.
export async function bindStandingLease({ connector, bounds: rawBounds, daemonFetch }) {
  const mode = standingLeaseRecorderMode();
  if (mode === "deployment") {
    return { ok: false, status: 501, code: STANDING_LEASE_CUSTODY_TIER_UNRULED, message: "Standing envelopes are recorded on wallet.network only through an interactive step-up ceremony with a passkey factor receipt; the bounded alpha's deployment-local operator key has no admitted posture for standing authority. An owner ruling on the alpha's custody tier for standing envelopes is pending; nothing was fabricated." };
  }
  if (mode === "none") {
    return { ok: false, status: 501, code: "standing_lease_recorder_not_configured", message: "no authority node is configured to record a standing grant; an unrecorded grant can never be drawn" };
  }
  if (!localApproverEnabled()) return { ok: false, status: 501, code: "local_approver_not_configured", message: "no deployment-local approver key is configured" };
  const principalRef = process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF || "";
  if (!principalRef) return { ok: false, status: 501, code: "authority_principal_not_configured", message: "IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF is required" };
  const bounds = parseBounds(rawBounds);
  const account = await daemonFetch("/v1/hypervisor/authority/capability-account").then((r) => r.json()).catch(() => null);
  const audience = account?.audience;
  if (!/^[0-9a-f]{64}$/u.test(String(audience || ""))) return { ok: false, status: 502, code: "capability_audience_unavailable", message: "the daemon did not report its wallet capability account; a grant without the audience can never be consumed" };
  const { sealSessionStandingEnvelope, syntheticStandingCeremony, randomHex32 } = await import("./standing-authority-evidence.mjs");
  const { mintStandingApprovalGrant } = await import("../../../../scripts/lib/mint-standing-approval-grant.mjs");
  const { mkdirSync, writeFileSync, renameSync, existsSync, readFileSync, rmSync } = await import("node:fs");
  const { randomUUID } = await import("node:crypto");
  const path = await import("node:path");
  const commandsDir = process.env[FIXTURE_COMMANDS_DIR];
  const fixtureCommand = async (payload) => {
    const dir = path.join(commandsDir, randomUUID());
    mkdirSync(dir, { mode: 0o700 });
    writeFileSync(path.join(dir, "request.json.tmp"), JSON.stringify(payload), { mode: 0o600 });
    renameSync(path.join(dir, "request.json.tmp"), path.join(dir, "request.json"));
    const responsePath = path.join(dir, "response.json");
    const deadline = Date.now() + 900_000;
    while (!existsSync(responsePath)) { if (Date.now() > deadline) throw new Error(`fixture ${payload.operation} timed out`); await new Promise((r) => setTimeout(r, 50)); }
    const response = JSON.parse(readFileSync(responsePath, "utf8"));
    rmSync(dir, { recursive: true, force: true });
    return response;
  };
  // The envelope's and ceremony's windows are judged against the authority node's committed
  // chain clock, so the attach pass reads that clock rather than assuming the host's.
  const clock = await fixtureCommand({ schema_version: 1, operation: "read_chain_timestamp", principal_ref: "fixture://wallet-network/chain-clock" });
  const nowMs = Number.isSafeInteger(clock?.chain_timestamp_ms) && clock.chain_timestamp_ms > 0 ? clock.chain_timestamp_ms : Date.now();
  const marker = randomHex32().slice(0, 16);
  const policyHash = `sha256:${randomHex32()}`;
  const reviewReceiptHash = `sha256:${randomHex32()}`;
  const declaredTools = (connector.allowed_tools || []).map((t) => t.name).filter(Boolean);
  const envelope = sealSessionStandingEnvelope({
    schema_version: "ioi.hypervisor.session-standing-envelope.v1",
    standing_envelope_ref: `standing-envelope://hypervisor/connections/${connector.connector_id}/${marker}`,
    owner_ref: "org://local", bounded_system_ref: "system://hypervisor/local", principal_ref: principalRef,
    audience_ref: "wallet-client://hypervisor/daemon", authority_scope: "scope:hypervisor.session-standing-envelope",
    facet_template: { connector_id: connector.connector_id, service: connector.service, base_url: connector.base_url, operations: bounds.operations, allowed_tools: bounds.tools.length ? bounds.tools : declaredTools, per_operation_spend_microusd: bounds.perOperationSpend, per_operation_deposit_microusd: bounds.perOperationSpend },
    aggregate_bounds: { max_cumulative_deposit_microusd: bounds.budgetMicro, max_cumulative_spend_microusd: bounds.budgetMicro, max_usages: bounds.maxUsages },
    not_before_ms: Math.max(0, nowMs - 60_000), expires_at_ms: nowMs + Math.round(bounds.expiresHours * 3_600_000), revocation_epoch: 0,
    trajectory_policy_ref: "policy://hypervisor/session-standing-envelope/trajectory/v1", trajectory_policy_hash: policyHash,
    approval_mode: "standing_envelope", recovery_posture: "recovery_never_widens_or_resets_drawdown",
  });
  const ceremony = syntheticStandingCeremony({ principalRef, envelope, policyHash, reviewReceiptHash, validationProfileRef: SESSION_ENVELOPE_CONTRACT, nowMs, marker });
  const seed = await readLocalApproverSeedHex();
  const grant = mintStandingApprovalGrant({ seed, standingEnvelopeHash: envelope.body_hash, policyHash, audience, nonce: randomHex32(), counter: 1, issuedAtMs: nowMs, expiresAtMs: envelope.expires_at_ms, maxUsages: bounds.maxUsages, maxCumulativeDepositMicrousd: bounds.budgetMicro, maxCumulativeSpendMicrousd: bounds.budgetMicro, reviewReceiptHash, approvalCeremonyContextHash: ceremony.contextHash, authFactorReceiptHash: ceremony.factor.receipt_hash });
  // Record on the fixture authority node through its command directory (the same protocol the
  // exact-approval act uses), then bind on the daemon.
  const response = await fixtureCommand({ schema_version: 1, operation: "record_standing_approval_grant", principal_ref: principalRef, standing_approval_grant: grant, standing_authority_envelope: envelope, approval_ceremony_context: ceremony.context, auth_factor_receipt: ceremony.factor });
  if (!response.ok) return { ok: false, status: 502, code: "standing_grant_record_refused", message: `the authority node refused to record the standing grant: ${response.error || JSON.stringify(response).slice(0, 300)}` };
  const bind = await daemonFetch(`/v1/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/standing-lease`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant, envelope }) });
  const bound = await bind.json().catch(() => ({}));
  if (bind.status !== 200 || !bound.ok) return { ok: false, status: bind.status, code: bound.error?.code || "standing_lease_bind_refused", message: bound.error?.message || "the daemon refused to bind the standing lease" };
  return { ok: true, recorder: "fixture", factor_origin: ceremony.factor_origin, standing_grant_hash: response.standing_grant_hash || null, standing_lease: bound.standing_lease };
}

export async function revokeStandingLease({ connectorId, daemonFetch }) {
  const res = await daemonFetch(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/standing-lease`, { method: "DELETE" });
  const body = await res.json().catch(() => ({}));
  return { ok: res.status === 200 && body.ok === true, status: res.status, ...body };
}
