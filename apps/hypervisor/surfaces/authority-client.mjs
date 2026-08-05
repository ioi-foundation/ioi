// W0.3 — the authority client. ONE encoding of the CapabilityLease authority-crossing
// flow, exactly as the daemon gateway behaves at the bytes (`authorize_capability_lease`,
// crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs:11899-11942):
//
//   1) 428 PRECONDITION_REQUIRED — the sealed backing credential did not resolve
//      (body: { ok:false, decision:"blocked", reason, message, backing_provider }).
//   2) 403 FORBIDDEN — owner wallet authority required (body carries the challenge:
//      required_authority_scope, required_scopes, approval:{policy_hash, request_hash},
//      authority_challenge — public commitments only; sign externally, resubmit the
//      one-use grant as `wallet_approval_grant`).
//   3) Success — the gateway issues + persists the lease (ioi.hypervisor.capability-lease.v1)
//      and the route receipts the transition on the record's own history (`receipt_ref`).
//
// The invariant this client enforces: NO SILENT NO-OP. Every call resolves to exactly one
// typed result — crossed-with-receipt, refusal, or failure — that a pane can render as a
// named state. A 2xx WITHOUT a discoverable receipt ref fails CLOSED (`receipt_missing`),
// matching the estate's governed-build idiom. The wallet grant is forwarded to the daemon
// exactly once and is never retained, logged, or echoed by this module.
//
// Usable from BOTH lanes (serve-side readout + browser augmentation): no node: imports;
// fetch and the daemon base are injectable.
import { defaultDaemonBase } from "./read-client.mjs";

const DEFAULT_TIMEOUT_MS = 15000; // crossings can mint fresh tokens server-side (network)
const HASH_RE = /^sha256:[0-9a-f]{64}$/;

const iso = () => new Date().toISOString();
const trim = (value, max = 300) => String(value == null ? "" : value).slice(0, max);

const failure = (code, message) => ({
  ok: false,
  kind: "failure",
  code,
  message: trim(message),
  receipt_ref: "",
  at: iso(),
});

const refusal = (stage, status, code, message, extra = {}) => ({
  ok: false,
  kind: "refusal",
  stage,
  status,
  code,
  message: trim(message),
  receipt_ref: "",
  at: iso(),
  ...extra,
});

// Grant intake mirrors the governed-build pane: accept an object, or parse a pasted JSON
// string; anything else is a typed refusal BEFORE the network — never a mangled forward.
function normalizeGrant(grant) {
  if (grant === undefined || grant === null || grant === "") return { grant: undefined };
  if (typeof grant === "object" && !Array.isArray(grant)) return { grant };
  if (typeof grant === "string") {
    try {
      const parsed = JSON.parse(grant);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { err: "the grant is not a JSON object" };
      }
      return { grant: parsed };
    } catch {
      return { err: "the grant is not valid JSON (was it truncated?)" };
    }
  }
  return { err: "the grant must be a JSON object" };
}

// The 403 challenge, surfaced with its public commitments VERBATIM (hash-shape-checked,
// like the governed-build pane) so a pane can name exactly what to sign. Never a secret.
function walletChallenge(payload) {
  const approval = payload?.approval || {};
  return {
    required_authority_scope: trim(payload?.required_authority_scope || "", 200),
    required_scopes: Array.isArray(payload?.required_scopes) ? payload.required_scopes : [],
    policy_hash: HASH_RE.test(approval.policy_hash || "") ? approval.policy_hash : "",
    request_hash: HASH_RE.test(approval.request_hash || "") ? approval.request_hash : "",
    authority_challenge: payload?.authority_challenge ?? null,
  };
}

// Receipt discovery over the daemon's real success shapes: a top-level receipt_ref, a
// nested record's `history[]` (latest entry carrying receipt_ref — how lifecycle records
// receipt every transition), or a nested record's receipt_ref. Deterministic scan, no
// guessing beyond these shapes — an undiscoverable receipt is receipt_missing, not "ok".
function findReceiptRef(payload, extractReceiptRef) {
  if (typeof extractReceiptRef === "function") {
    const ref = extractReceiptRef(payload);
    return typeof ref === "string" && ref.length > 0 ? ref : "";
  }
  if (!payload || typeof payload !== "object") return "";
  if (typeof payload.receipt_ref === "string" && payload.receipt_ref) return payload.receipt_ref;
  for (const value of Object.values(payload)) {
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    if (typeof value.receipt_ref === "string" && value.receipt_ref) return value.receipt_ref;
    const history = Array.isArray(value.history) ? value.history : [];
    for (let i = history.length - 1; i >= 0; i--) {
      const ref = history[i]?.receipt_ref;
      if (typeof ref === "string" && ref.length > 0) return ref;
    }
  }
  return "";
}

// Non-secret lease coordinates when the success payload carries them (descriptor fields /
// the sealed-session labels). Labels only — the gateway never exports credential material.
function leaseFacets(payload) {
  if (!payload || typeof payload !== "object") return null;
  const nodes = [payload, ...Object.values(payload).filter((v) => v && typeof v === "object" && !Array.isArray(v))];
  for (const node of nodes) {
    const candidates = [node, node.session, node.lease].filter((v) => v && typeof v === "object");
    for (const c of candidates) {
      const lease_id = c.lease_id || c.gateway_lease_id || "";
      const grant_ref = c.grant_ref || "";
      const policy_hash = c.policy_hash || "";
      const request_hash = c.request_hash || "";
      if (lease_id || grant_ref || policy_hash || request_hash) {
        return {
          lease_id: trim(lease_id, 120),
          grant_ref: trim(grant_ref, 200),
          policy_hash: HASH_RE.test(policy_hash) ? policy_hash : "",
          request_hash: HASH_RE.test(request_hash) ? request_hash : "",
        };
      }
    }
  }
  return null;
}

/// The crossing. POSTs to a gateway-guarded daemon route; `grant` (optional) rides the
/// request exactly once as `wallet_approval_grant`. Result kinds:
///   { ok:true,  kind:"crossed", status, receipt_ref, lease, payload, at }
///   { ok:false, kind:"refusal", stage:"grant"|"credential"|"wallet_challenge"|"gateway",
///     status?, code, message, challenge?, refusal?, at }
///   { ok:false, kind:"failure", code ("daemon_unavailable"|"crossing_timeout"|"receipt_missing"), message, at }
export async function crossWithLease(
  { daemon = defaultDaemonBase(), fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {},
  path,
  { method = "POST", body = {}, grant, extractReceiptRef } = {},
) {
  const { grant: normalized, err } = normalizeGrant(grant);
  if (err) return refusal("grant", 0, "grant_invalid_json", err);
  const request = { ...body };
  if (normalized !== undefined) request.wallet_approval_grant = normalized;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  let payload = {};
  try {
    response = await fetchImpl(`${daemon}${path}`, {
      method,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    const text = await response.text();
    try { payload = text ? JSON.parse(text) : {}; } catch { payload = {}; }
  } catch (error) {
    const timedOut = error?.name === "AbortError";
    return failure(
      timedOut ? "crossing_timeout" : "daemon_unavailable",
      timedOut
        ? `the daemon did not answer the crossing within ${timeoutMs}ms — treat state as unknown and re-read the record`
        : "the daemon did not answer — no crossing occurred",
    );
  } finally {
    clearTimeout(timer);
  }

  const status = response.status;
  // Gateway step 1 — sealed credential unresolved. Fix the credential, then retry.
  if (status === 428) {
    return refusal("credential", status,
      payload?.reason || "credential_unresolved",
      payload?.message || "this crossing needs a resolvable sealed backing credential",
      { refusal: payload });
  }
  // Gateway step 2 — owner wallet authority required; surface the challenge to sign.
  if (status === 403) {
    return refusal("wallet_challenge", status,
      payload?.reason || "wallet_authority_required",
      payload?.message || "this crossing requires independently resolved, atomically consumed owner authority",
      { challenge: walletChallenge(payload), refusal: payload });
  }
  if (status >= 400) {
    return refusal("gateway", status,
      payload?.error?.code || payload?.reason || payload?.code || `http_${status}`,
      payload?.error?.message || payload?.message || payload?.reason || "the gateway refused the crossing",
      { refusal: payload });
  }
  // Gateway step 3 — the crossing happened iff a receipt names it. Fail closed otherwise.
  const receipt_ref = findReceiptRef(payload, extractReceiptRef);
  if (!receipt_ref) {
    return failure("receipt_missing", "the crossing returned success without a receipt ref — failing closed");
  }
  return { ok: true, kind: "crossed", status, receipt_ref, lease: leaseFacets(payload), payload, at: iso() };
}

/// Bound-client convenience mirroring createReadClient.
export function createAuthorityClient(options = {}) {
  const client = {
    daemon: options.daemon ?? defaultDaemonBase(),
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
  return {
    ...client,
    cross: (path, opts) => crossWithLease(client, path, opts),
  };
}
