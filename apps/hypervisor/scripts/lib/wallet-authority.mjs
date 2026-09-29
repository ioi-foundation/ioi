// The ONE wallet-authority seam for the serve (#67 mandatory authority preflight).
//
// The fixture signer (repo scripts/lib/mint-approval-grant.mjs — a deterministic PUBLIC-seed
// Ed25519 test wallet) is test/fixture-only: production serve/module code must never import or
// invoke it. This adapter is the only place the serve touches wallet grants, and the serve holds
// NO signing key and reads no key path in any mode (master guide §0.5.2, G5, N9):
//
//   - PRODUCTION (no flag): the serve signs nothing. A lane needing a grant parks on the daemon's
//     challenge. When the daemon parked it (`approval_challenge`) and can decide it, the operator's
//     decision is RELAYED to the daemon with the passphrase they typed (relayChallengeDecision),
//     and the run resumes with the returned `approval_ref`. Otherwise the run parks in
//     `awaiting_wallet_authority` with the challenge verbatim for an EXTERNAL wallet holder (the
//     governed Build workflow's paste handoff).
//   - DEV/TEST (IOI_WALLET_TEST_SIGNER=1): mintTestGrant() dynamically imports the fixture signer
//     and mints against the given challenge hashes — the explicit verifier/dev flag the mandate
//     allows. The import happens ONLY inside the flag check; no static edge to the signer exists.
//   - FIXTURE QUALIFICATION (IOI_WALLET_FIXTURE_APPROVER=1): the operator's decision mints with the
//     cargo wallet fixture's PUBLIC approver seed and records through the fixture (see below).
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

// ---- The operator's decision goes THROUGH THE DAEMON (master guide G5 / W0.2 part 2, N9) --------
//
// The serve holds NO signing key and reads no key path (master guide §0.5.2). The deployment's
// approver key is sealed under the operator passphrase inside the deployment authority node
// (ADR 0052, commit f3b869df2), and only that node's `approve` act can mint. When a gate refuses an
// effect for want of a grant, the DAEMON parks the challenge (`approval_challenge.challenge_id` on
// its 403) and decides it on `POST /v1/hypervisor/authority/challenges/:id/decision`: it runs the
// authority's `approve` for the coordinates in its OWN record, with the passphrase the operator
// typed in that child's environment only, stores the one-use grant and answers `approval_ref`.
// The serve relays the operator's decision (the passphrase rides the one request body and is never
// logged, persisted or put on a run) and resumes the run with `approval_ref`; the daemon presents
// the stored grant only when its hashes equal the ones it derives from the retried request.
export const CHALLENGE_DECISION_ROUTE = (challengeId) => `/v1/hypervisor/authority/challenges/${encodeURIComponent(challengeId)}/decision`;

/** The daemon's parked challenge on a gate's 403 body, or null when the refusal is not an ask. */
export function parkedChallengeOf(body) {
  const parked = body?.approval_challenge;
  return parked && typeof parked === "object" && typeof parked.challenge_id === "string" && parked.challenge_id ? parked : null;
}

/**
 * The operator's decision as an approval form posts it to the serve: a browser form (urlencoded) or a JSON call, carrying
 * `reason`, `operator_passphrase` and, on a form, a same-origin `return_to` path. Every approval surface reads it here (the
 * run card and a parked effect's own page), so the passphrase is taken from exactly one place. The request buffer is
 * zeroed once read: the passphrase then lives only in the returned value, which the caller hands to
 * relayChallengeDecision and drops. Nothing here logs or keeps it.
 */
export function operatorDecisionFrom(body, contentType = "") {
  const isForm = String(contentType || "").includes("application/x-www-form-urlencoded");
  const text = Buffer.isBuffer(body) ? body.toString("utf8") : String(body ?? "");
  let reason = "", operatorPassphrase = "", returnTo = "";
  if (isForm) {
    const form = new URLSearchParams(text);
    reason = form.get("reason") || "";
    operatorPassphrase = form.get("operator_passphrase") || "";
    const wanted = form.get("return_to") || "";
    if (/^\/[a-zA-Z0-9_\-./]*$/u.test(wanted)) returnTo = wanted;
  } else {
    try { const parsed = JSON.parse(text || "{}"); reason = typeof parsed.reason === "string" ? parsed.reason : ""; operatorPassphrase = typeof parsed.operator_passphrase === "string" ? parsed.operator_passphrase : ""; } catch { /* no reason */ }
  }
  if (Buffer.isBuffer(body)) body.fill(0);
  return { isForm, reason, operatorPassphrase, returnTo };
}

/**
 * Relay the operator's decision on one parked challenge to the daemon. `transport(method, path,
 * payload, headers)` answers `{ status, body }`; `headers` are the caller's bounded daemon identity
 * headers. Returns `{ ok, status, approval_ref, grant_ref, expires_at_ms }` or `{ ok:false, status,
 * error }`. The passphrase is sent once, in this request body, and nothing here keeps it.
 */
export async function relayChallengeDecision({ challengeId, decision, reason = "", operatorPassphrase = "", headers = {}, transport }) {
  if (!challengeId) return { ok: false, status: 409, error: { code: "challenge_not_parked", message: "the daemon parked no challenge for this effect" } };
  if (decision === "approve" && !operatorPassphrase) {
    return { ok: false, status: 400, error: { code: "operator_passphrase_required", message: "approving needs the operator passphrase: the daemon's deployment authority opens the sealed approver key with it for this one grant" } };
  }
  const payload = decision === "approve"
    ? { decision, reason: String(reason || "").slice(0, 400), operator_passphrase: String(operatorPassphrase) }
    : { decision, reason: String(reason || "").slice(0, 400) };
  let reply;
  try {
    reply = await transport("POST", CHALLENGE_DECISION_ROUTE(challengeId), payload, headers);
  } catch (error) {
    return { ok: false, status: 502, error: { code: "challenge_decision_unreachable", message: String(error?.message || error) } };
  }
  const body = reply?.body && typeof reply.body === "object" ? reply.body : {};
  if (Number(reply?.status) === 200 && body.ok === true) {
    return { ok: true, status: 200, state: body.state || null, approval_ref: body.approval_ref || null, grant_ref: body.grant_ref || null, expires_at_ms: body.expires_at_ms ?? null, decided_by: body.decided_by || null };
  }
  return {
    ok: false,
    status: Number(reply?.status) || 502,
    error: body.error && typeof body.error === "object" ? body.error : { code: body.code || body.reason || `daemon_${reply?.status}`, message: body.message || "the daemon refused the decision" },
    approval_ref: body.approval_ref || null,
  };
}

// ---- TEST-ONLY: the cargo wallet fixture's approver (explicit flag) ------------------------------
//
// The qualification fixture (crates/cli/tests/hypervisor_wallet_network_fixture.rs) registers the
// PUBLIC `07…` seed as the approver for its principal, and records approvals through its command
// directory; it is not a deployment authority the daemon can run `approve` against. Lanes that
// qualify the approval card against that fixture set IOI_WALLET_FIXTURE_APPROVER=1 (with the
// fixture's command directory): the operator's decision then mints with that public test seed
// and records through the fixture. The seed is a published constant — no key file is read — and
// without the flag nothing here signs. A deployment never sets it.
export const FIXTURE_APPROVER_FLAG = "IOI_WALLET_FIXTURE_APPROVER";
export const FIXTURE_COMMANDS_DIR = "IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR";
const FIXTURE_PUBLIC_APPROVER_SEED_HEX = "07".repeat(32);

export function fixtureApproverEnabled() {
  return process.env[FIXTURE_APPROVER_FLAG] === "1" && typeof process.env[FIXTURE_COMMANDS_DIR] === "string" && process.env[FIXTURE_COMMANDS_DIR].length > 0;
}

async function fixtureCommand(payload) {
  const commandsDir = process.env[FIXTURE_COMMANDS_DIR];
  if (!commandsDir) throw new Error("no fixture command directory is configured");
  const { mkdirSync, writeFileSync, renameSync, existsSync, readFileSync, rmSync } = await import("node:fs");
  const { randomUUID } = await import("node:crypto");
  const path = await import("node:path");
  const dir = path.join(commandsDir, randomUUID());
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(path.join(dir, "request.json.tmp"), JSON.stringify(payload), { mode: 0o600 });
  renameSync(path.join(dir, "request.json.tmp"), path.join(dir, "request.json"));
  const responsePath = path.join(dir, "response.json");
  const deadline = Date.now() + 900_000;
  while (!existsSync(responsePath)) {
    if (Date.now() > deadline) throw new Error(`fixture ${payload.operation} timed out`);
    await new Promise((r) => setTimeout(r, 50));
  }
  const response = JSON.parse(readFileSync(responsePath, "utf8"));
  rmSync(dir, { recursive: true, force: true });
  return response;
}

/**
 * TEST-ONLY (IOI_WALLET_FIXTURE_APPROVER=1): the operator's approval against the cargo wallet
 * fixture — mint ONE one-use grant for exactly the card's hashes and audience with the fixture's
 * public seed, record it through the fixture's command directory, and return it. Returns null
 * without the flag.
 */
export async function approveWithFixtureApprover({ policyHash, requestHash, audience, targetScope }) {
  if (!fixtureApproverEnabled()) return null;
  if (!policyHash || !requestHash || !targetScope) throw new Error("the fixture approver needs the challenge's policy_hash, request_hash and target_scope");
  if (!/^[0-9a-f]{64}$/u.test(String(audience || ""))) throw new Error("the fixture approver refuses to sign without the daemon's capability audience (the challenge carried none)");
  const principalRef = process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF || "";
  if (!principalRef) throw new Error("fixture recording needs IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF");
  const { mintApprovalGrant } = await import("../../../../scripts/lib/mint-approval-grant.mjs");
  const grant = mintApprovalGrant({ seed: FIXTURE_PUBLIC_APPROVER_SEED_HEX, policyHash, requestHash, audience, maxUsages: 1 });
  const hex = (v) => String(v || "").replace(/^sha256:/u, "");
  const response = await fixtureCommand({ schema_version: 1, operation: "record_approval", principal_ref: principalRef, policy_hash: hex(policyHash), request_hash: hex(requestHash), approval_grant: grant, target_scope: targetScope });
  if (!response.ok) throw new Error(`fixture record_approval refused: ${response.error || "unknown"}`);
  return grant;
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
// The Connections attach flow sets the scoped standing bound for ONE connector (operations, tools,
// metered unit, usages, budget, window): a registered SessionStandingEnvelope bound by a
// StandingApprovalGrant the deployment approver signs, recorded on the authority node, then bound
// to the connector on the daemon.
//   · deployment (no flag): the serve holds no key and no path to one (master guide §0.5.2). It
//     RELAYS the operator's standing decision to the daemon —
//     `POST /v1/hypervisor/authority/standing-envelopes` with the bounds and the passphrase the
//     operator typed — and the daemon derives every coordinate, runs the sealed authority's
//     `record-standing-approval` (mint mode) with the passphrase in that child's environment only,
//     and binds the grant. The passphrase rides the one request body; nothing here keeps it.
//   · fixture authority mode (TEST-ONLY: IOI_WALLET_FIXTURE_APPROVER=1 with the fixture's command
//     directory): the qualification fixture's public approver seed signs (a published constant, no
//     key file is read), and the fixture records the tuple with the SYNTHETIC contract ceremony the
//     broker-contract verifier uses (labelled; no physical passkey claimed).
export const STANDING_LEASE_CUSTODY_TIER_UNRULED = "standing_lease_custody_tier_unruled";
export const STANDING_ENVELOPE_ROUTE = "/v1/hypervisor/authority/standing-envelopes";
export const STANDING_ENVELOPE_REVOKE_ROUTE = (id) => `${STANDING_ENVELOPE_ROUTE}/${encodeURIComponent(id)}/revoke`;
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

// "fixture" only under the explicit test flag; "daemon" when this deployment names an authority
// principal (the daemon decides, with the operator's passphrase); "none" otherwise.
export function standingLeaseRecorderMode() {
  if (fixtureApproverEnabled()) return "fixture";
  return process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF ? "daemon" : "none";
}

// The bounds a caller may send the daemon. Anything else (an envelope, a grant, a hash, a window)
// the daemon derives itself and refuses by name.
const RELAYED_BOUNDS = ["max_usages", "budget_usd", "expires_hours", "per_operation_usd", "tools", "operations", "reason"];

async function readDaemonReply(res) {
  const text = await res.text().catch(() => "");
  try { return text ? JSON.parse(text) : {}; } catch { return { _raw: text.slice(0, 300) }; }
}

// The daemon refuses in three shapes: `{error:{code,message}}` (its typed refusals), `{code,message}`
// (the identity gate's 401) and `{reason}` (unknown connector). Read all three.
function typedRefusal(status, body, fallback) {
  return {
    ok: false,
    status: status || 502,
    code: body?.error?.code || body?.code || body?.reason || fallback,
    message: body?.error?.message || body?.message || body?.reason || "the daemon refused the standing decision",
  };
}

/**
 * Relay the operator's standing decision for one connection to the daemon: the bounds plus the
 * passphrase, once, in this request body. Returns `{ ok:true, standing_lease, standing_envelope_id,
 * ... }` or `{ ok:false, status, code, message }` — never throws for a typed refusal.
 */
export async function relayStandingEnvelope({ connectorId, bounds = {}, operatorPassphrase = "", daemonFetch }) {
  const payload = { connector_id: connectorId };
  for (const key of RELAYED_BOUNDS) {
    const value = bounds[key];
    if (value === undefined || value === null || value === "") continue;
    payload[key] = value;
  }
  payload.operator_passphrase = String(operatorPassphrase || "");
  let res;
  try {
    res = await daemonFetch(STANDING_ENVELOPE_ROUTE, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  } catch (error) {
    return { ok: false, status: 502, code: "standing_envelope_relay_failed", message: String(error?.message || error) };
  } finally {
    payload.operator_passphrase = "";
  }
  const body = await readDaemonReply(res);
  if (res.status !== 200 || body.ok !== true) return typedRefusal(res.status, body, "standing_envelope_refused");
  return {
    ok: true,
    recorder: "daemon",
    standing_envelope_id: body.standing_envelope_id || null,
    standing_envelope_ref: body.standing_envelope_ref || null,
    grant_hash_ref: body.grant_hash_ref || null,
    recorded_on_authority: body.recorded_on_authority || null,
    standing_lease: body.standing_lease || { status: "active", bounds: body.bounds || null },
  };
}

// Returns { ok:true, standing_lease } or { ok:false, code, message } — never throws for a typed
// refusal, so the attach surface can render the reason and the journey can record it.
export async function bindStandingLease({ connector, bounds: rawBounds, operatorPassphrase = "", daemonFetch }) {
  if (standingLeaseRecorderMode() !== "fixture") {
    // The daemon decides; the serve signs nothing. The daemon resolves the caller before anything
    // else, so an unauthenticated press records nothing.
    return relayStandingEnvelope({ connectorId: connector.connector_id, bounds: rawBounds || {}, operatorPassphrase, daemonFetch });
  }
  // R-17 — PRE-FLIGHT THE CALLER before anything is minted or recorded. The daemon's bind route now
  // resolves the caller and refuses an unresolved one (401). Everything below this line has side
  // effects that outlive a refusal: the ceremony is stamped, the grant is minted, and the grant is
  // RECORDED on the authority node. Discovering the 401 only at the bind would leave a recorded
  // standing grant with no lease bound to it, once per press. So the identity question is asked
  // first, and the answer is the daemon's own.
  const who = await daemonFetch("/v1/hypervisor/auth/whoami").catch(() => null);
  if (!who || who.status === 401 || who.status === 403) {
    return {
      ok: false,
      status: who?.status ?? 401,
      code: "hypervisor.authentication_required",
      message: "an authenticated session is required to bind a standing envelope — sign in and try again; nothing was minted or recorded",
    };
  }
  const principalRef = process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF || "";
  if (!principalRef) return { ok: false, status: 501, code: "authority_principal_not_configured", message: "IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF is required" };
  const bounds = parseBounds(rawBounds);
  const account = await daemonFetch("/v1/hypervisor/authority/capability-account").then((r) => r.json()).catch(() => null);
  const audience = account?.audience;
  if (!/^[0-9a-f]{64}$/u.test(String(audience || ""))) return { ok: false, status: 502, code: "capability_audience_unavailable", message: "the daemon did not report its wallet capability account; a grant without the audience can never be consumed" };
  const { sealSessionStandingEnvelope, syntheticStandingCeremony, randomHex32 } = await import("./standing-authority-evidence.mjs");
  const { mintStandingApprovalGrant } = await import("../../../../scripts/lib/mint-standing-approval-grant.mjs");
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
  // The labelled synthetic contract ceremony (fixture qualification only).
  const ceremony = syntheticStandingCeremony({ principalRef, envelope, policyHash, reviewReceiptHash, validationProfileRef: SESSION_ENVELOPE_CONTRACT, nowMs, marker });
  const grant = mintStandingApprovalGrant({ seed: FIXTURE_PUBLIC_APPROVER_SEED_HEX, standingEnvelopeHash: envelope.body_hash, policyHash, audience, nonce: randomHex32(), counter: 1, issuedAtMs: nowMs, expiresAtMs: envelope.expires_at_ms, maxUsages: bounds.maxUsages, maxCumulativeDepositMicrousd: bounds.budgetMicro, maxCumulativeSpendMicrousd: bounds.budgetMicro, reviewReceiptHash, approvalCeremonyContextHash: ceremony.contextHash, authFactorReceiptHash: ceremony.factor.receipt_hash });
  // Record through the fixture's command directory, then bind on the daemon.
  const response = await fixtureCommand({ schema_version: 1, operation: "record_standing_approval_grant", principal_ref: principalRef, standing_approval_grant: grant, standing_authority_envelope: envelope, approval_ceremony_context: ceremony.context, auth_factor_receipt: ceremony.factor });
  if (!response.ok) return { ok: false, status: 502, code: "standing_grant_record_refused", message: `the authority node refused to record the standing grant: ${response.error || JSON.stringify(response).slice(0, 300)}` };
  const bind = await daemonFetch(`/v1/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/standing-lease`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant, envelope }) });
  const bound = await bind.json().catch(() => ({}));
  if (bind.status !== 200 || !bound.ok) return typedRefusal(bind.status, bound, "standing_lease_bind_refused");
  return { ok: true, recorder: "fixture", factor_origin: ceremony.factor_origin, standing_grant_hash: response.standing_grant_hash || null, standing_lease: bound.standing_lease };
}

/**
 * Remove a connection's limits. An envelope the daemon's standing decision issued is revoked on
 * the authority node with the operator's passphrase (then fenced); any other lease (the fixture's)
 * is fenced on the daemon.
 */
export async function revokeStandingLease({ connectorId, operatorPassphrase = "", reason = "", daemonFetch }) {
  const estate = await daemonFetch("/v1/hypervisor/connectors").then((r) => r.json()).catch(() => ({}));
  const lease = (estate.connectors || []).find((c) => c.connector_id === connectorId)?.standing_lease || null;
  const envelopeId = typeof lease?.standing_envelope_id === "string" ? lease.standing_envelope_id : "";
  if (envelopeId) {
    const payload = { reason: String(reason || "").slice(0, 400), operator_passphrase: String(operatorPassphrase || "") };
    let res;
    try {
      res = await daemonFetch(STANDING_ENVELOPE_REVOKE_ROUTE(envelopeId), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    } catch (error) {
      return { ok: false, status: 502, code: "standing_envelope_relay_failed", message: String(error?.message || error) };
    } finally {
      payload.operator_passphrase = "";
    }
    const body = await readDaemonReply(res);
    if (res.status !== 200 || body.ok !== true) return typedRefusal(res.status, body, "standing_envelope_revoke_refused");
    return { ok: true, status: 200, connector_id: connectorId, standing_envelope_id: envelopeId, standing_lease: { status: "revoked" }, revocation: body.revocation || null };
  }
  const res = await daemonFetch(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/standing-lease`, { method: "DELETE" });
  const body = await res.json().catch(() => ({}));
  return { ok: res.status === 200 && body.ok === true, status: res.status, ...body };
}
