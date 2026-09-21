// The editor-side challenge relay (M08.12, register R-214; ADR 0008's relay-only contract).
//
// An effect initiated from an ATTACHED editor is relayed to the daemon under the user's own identity;
// the daemon's refusal is parked through the App's spend-approval lane (M08.11) as the byte-derived
// card, and the editor receives a typed NOTIFICATION that carries the challenge's coordinates and the
// deep links to the operator's decision — and nothing else. The relay holds no key, mints nothing,
// caches no grant and adds no decision path: it imports neither the wallet authority module nor the
// grant minter, it reads no key path and no test-signer flag, and every record it touches is the
// lane's own. The editor access lease AUTHENTICATES the attach (an active `environment.editor.open`
// lease naming the editor service); it never authorizes the effect — the user's session does, at the
// daemon, exactly as for the App path, which is what makes the daemon's receipts identical.
import crypto from "node:crypto";
import { PROVIDER_OPERATION_KIND, getRun, persistRun, submitProviderOperation } from "../ioi-agent-runs.mjs";

export const NOTIFICATION_SCHEMA = "ioi.editor-challenge-notification.v1";
export const EDITOR_ACCESS_ACTION = "environment.editor.open";
export const ADAPTER_KIND = "ide_extension";
// Members a notification may NEVER carry: the card is byte-derived on the App (R-212); a notification
// that re-states a facet is the paraphrase defect, and one that carries a grant or a key is a second spine.
export const FORBIDDEN_NOTIFICATION_MEMBERS = ["facets", "lease_request_facets", "request_preimage", "policy_preimage", "wallet_approval_grant", "grant", "approver_sig", "key", "seed", "session_token", "api_key"];
const HASH = /^sha256:[0-9a-f]{64}$/u;
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text, "utf8").digest("hex")}`;

/** The attach tuple an editor host carries (the refs the daemon injects into its hosted editor). */
export function attachRefs(input) {
  const a = input && typeof input === "object" ? input : {};
  const refs = { editor_service_ref: String(a.editor_service_ref ?? ""), access_lease_ref: String(a.access_lease_ref ?? ""), session_ref: a.session_ref == null ? null : String(a.session_ref), environment_ref: String(a.environment_ref ?? "") };
  return refs.editor_service_ref && refs.access_lease_ref && refs.environment_ref ? refs : null;
}

/**
 * Verify the attach against the daemon's own grant projection: the access lease must be ACTIVE, carry
 * the editor-open action and name this editor service. Nothing here is authority for the effect.
 */
export function verifyAttach(refs, grants) {
  const list = Array.isArray(grants) ? grants : [];
  const serviceId = refs.editor_service_ref.replace(/^environment_service:editor_/u, "");
  const match = list.find((g) => [g?.lease_id, g?.grant_id, g?.id, g?.lease_ref, g?.grant_ref].some((v) => typeof v === "string" && (v === refs.access_lease_ref || refs.access_lease_ref.endsWith(v) || v.endsWith(refs.access_lease_ref))));
  if (!match) return { ok: false, code: "editor_attach_lease_unknown" };
  const status = String(match.status ?? match.state ?? "");
  if (status !== "active") return { ok: false, code: `editor_attach_lease_${status || "inactive"}` };
  const actions = [match.action, ...(Array.isArray(match.allowed_actions) ? match.allowed_actions : []), ...(Array.isArray(match.allowed_tools) ? match.allowed_tools : [])].filter(Boolean);
  if (!actions.includes(EDITOR_ACCESS_ACTION)) return { ok: false, code: "editor_attach_lease_wrong_action" };
  const resources = Array.isArray(match.resources) ? match.resources : (Array.isArray(match.resource_refs) ? match.resource_refs : []);
  if (!resources.some((r) => String(r) === `editor_service:${serviceId}` || String(r) === `editor_service:${refs.editor_service_ref}`)) return { ok: false, code: "editor_attach_lease_foreign_service" };
  return { ok: true, code: null, lease: { status, action: EDITOR_ACCESS_ACTION, service_id: serviceId } };
}

/** The typed notification: coordinates and links only. */
export function buildEditorChallengeNotification(run, { refs, serveBase = "" } = {}) {
  const p = run?.pendingApproval ?? {};
  const id = encodeURIComponent(run?.id ?? "");
  const preimage = p.challenge?.approval?.request_preimage;
  return {
    schema_version: NOTIFICATION_SCHEMA,
    run_id: run?.id ?? null,
    kind: p.kind ?? PROVIDER_OPERATION_KIND,
    state: p.byte_derived === false ? "refused_not_byte_derived" : (run?.status === "awaiting_operator_approval" ? "awaiting_operator_decision" : String(run?.status ?? "unknown")),
    byte_derived: p.byte_derived === true,
    policy_hash: p.policy_hash ?? null,
    request_hash: p.request_hash ?? null,
    audience: p.audience ?? null,
    target_scope: p.target_scope ?? null,
    required_scopes: Array.isArray(p.required_scopes) ? [...p.required_scopes] : [],
    receipt_ref: p.receipt_ref ?? null,
    preimage_sha256: typeof preimage === "string" ? sha256(preimage) : null,
    operation: { op: p.request?.op ?? null, environment_ref: p.request?.environment_ref ?? null, provider_id: p.request?.provider_id ?? null },
    source_adapter: { adapter_kind: ADAPTER_KIND, editor_service_ref: refs?.editor_service_ref ?? null, access_lease_ref: refs?.access_lease_ref ?? null, session_ref: refs?.session_ref ?? null },
    decision: p.byte_derived === true
      ? { card_url: `${serveBase}/work/sessions`, approve_url: `${serveBase}/__ioi/runs/${id}/approve`, deny_url: `${serveBase}/__ioi/runs/${id}/deny`, timeline_url: `${serveBase}/__ioi/agent-runs/${id}/timeline` }
      : { card_url: `${serveBase}/work/sessions`, approve_url: null, deny_url: `${serveBase}/__ioi/runs/${id}/deny`, timeline_url: `${serveBase}/__ioi/agent-runs/${id}/timeline` },
    message: p.byte_derived === true
      ? `Hypervisor blocked ${p.request?.op ?? "an operation"} on ${p.request?.environment_ref ?? "an environment"} pending your approval — decide on the App's approval card`
      : "Hypervisor blocked an operation whose challenge cannot be shown as the bytes that would execute — it can only be denied on the App",
  };
}

/** The grammar oracle: the notification against the run's challenge. */
export function verifyNotificationGrammar(notification, challenge, { runId = null } = {}) {
  const f = [];
  const n = notification ?? {};
  if (n.schema_version !== NOTIFICATION_SCHEMA) f.push("schema_invalid");
  const a = challenge?.approval ?? {};
  if (n.request_hash !== a.request_hash || !HASH.test(String(n.request_hash ?? ""))) f.push("request_hash_not_the_challenges");
  if (n.policy_hash !== a.policy_hash || !HASH.test(String(n.policy_hash ?? ""))) f.push("policy_hash_not_the_challenges");
  if ((a.audience ?? null) !== (n.audience ?? null)) f.push("audience_not_the_challenges");
  if ((challenge?.receipt_ref ?? null) !== (n.receipt_ref ?? null)) f.push("receipt_ref_not_the_challenges");
  if (typeof a.request_preimage === "string" && n.preimage_sha256 !== sha256(a.request_preimage)) f.push("preimage_sha_not_the_challenges");
  if (runId && n.run_id !== runId) f.push("run_id_mismatch");
  const serialized = JSON.stringify(n);
  for (const m of FORBIDDEN_NOTIFICATION_MEMBERS) if (new RegExp(`"${m}"\\s*:`, "u").test(serialized)) f.push(`forbidden_member:${m}`);
  if (/ioi_sess_[A-Za-z0-9_-]+|ioi_bootstrap_[A-Za-z0-9_-]+/u.test(serialized)) f.push("bearer_material");
  const d = n.decision ?? {};
  const id = encodeURIComponent(String(n.run_id ?? ""));
  if (n.byte_derived === true) { if (!(typeof d.approve_url === "string" && d.approve_url.endsWith(`/__ioi/runs/${id}/approve`))) f.push("approve_link_not_run_bound"); }
  else if (d.approve_url !== null) f.push("approve_link_on_refusal");
  if (!(typeof d.deny_url === "string" && d.deny_url.endsWith(`/__ioi/runs/${id}/deny`))) f.push("deny_link_not_run_bound");
  if (!(typeof d.timeline_url === "string" && d.timeline_url.endsWith(`/__ioi/agent-runs/${id}/timeline`))) f.push("timeline_link_not_run_bound");
  if (!(typeof d.card_url === "string" && d.card_url.endsWith("/work/sessions"))) f.push("card_link_missing");
  if (n.source_adapter?.adapter_kind !== ADAPTER_KIND) f.push("adapter_kind_not_ide_extension");
  if (typeof n.message !== "string" || n.message.length < 20) f.push("message_missing");
  return f;
}

/**
 * Relay an editor-initiated effect: authenticate the attach, submit through the App's lane under the
 * user's own identity, and return the run id and the notification. `grants` is the daemon's grant
 * projection (the caller reads it under the same identity); `transport` is the lane's daemon transport.
 */
export async function relayEditorEffect({ body, attach, grants, daemonHeaders = {}, transport, serveBase = "" }) {
  const refs = attachRefs(attach);
  if (!refs) return { ok: false, status: 400, error: { code: "editor_attach_refs_required", message: "editor_service_ref, access_lease_ref and environment_ref are required" } };
  const attached = verifyAttach(refs, grants);
  if (!attached.ok) return { ok: false, status: 403, error: { code: attached.code, message: "the editor attach is not an active editor-open lease for this service; nothing was submitted" } };
  if (body && typeof body === "object" && String(body.environment_ref ?? "") !== refs.environment_ref) return { ok: false, status: 403, error: { code: "editor_attach_environment_mismatch", message: "an attached editor may only relay an effect on the environment it is attached to" } };
  const submitted = await submitProviderOperation({ body, daemonHeaders, ...(transport ? { transport } : {}) });
  if (!submitted.ok || !submitted.run_id) return { ...submitted, relayed: true };
  const run = getRun(submitted.run_id);
  const notification = submitted.parked ? buildEditorChallengeNotification(run, { refs, serveBase }) : null;
  // The lane's write-through ran before the notification existed: attach it and write the record again
  // (ordered per run), so the durable record carries the notification the editor was handed.
  if (run && notification) { run.editorNotification = notification; run.relayedFrom = refs; persistRun(run); }
  return { ok: true, status: submitted.parked ? 202 : submitted.status, run_id: submitted.run_id, parked: submitted.parked === true, byte_derived: submitted.byte_derived ?? null, request_hash: submitted.request_hash ?? null, receipt_ref: submitted.receipt_ref ?? null, outcome: submitted.outcome ?? null, reason: submitted.reason ?? null, relayed: true, notification };
}

/**
 * Receipt parity across attach surfaces: two daemon receipts (or records) for the SAME operation must
 * carry the same member set and the same values, modulo the members that are identities or times.
 */
export const PARITY_VOLATILE = ["receipt_id", "receipt_ref", "at", "recorded_at", "operation_id", "grant_ref", "state_root", "environment_ref", "account_ref", "candidate_ref", "quote_ref", "idempotency_key", "created_at", "updated_at", "decided_at", "requested_at", "run_id", "id"];
function strip(value, volatile) {
  if (Array.isArray(value)) return value.map((v) => strip(v, volatile));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (volatile.includes(k)) { out[k] = v == null ? null : `<${typeof v}>`; continue; }
      out[k] = strip(v, volatile);
    }
    return out;
  }
  return value;
}
export function receiptParity(a, b, { volatile = PARITY_VOLATILE } = {}) {
  const f = [];
  const ka = Object.keys(a ?? {}).sort(); const kb = Object.keys(b ?? {}).sort();
  for (const k of ka) if (!kb.includes(k)) f.push(`member_only_in_first:${k}`);
  for (const k of kb) if (!ka.includes(k)) f.push(`member_only_in_second:${k}`);
  const sa = strip(a ?? {}, volatile); const sb = strip(b ?? {}, volatile);
  for (const k of ka) if (kb.includes(k) && stable(sa[k]) !== stable(sb[k])) f.push(`value_differs:${k}`);
  return f;
}
