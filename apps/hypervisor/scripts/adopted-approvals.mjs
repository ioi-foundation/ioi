// The adopted Approvals app's answers over Hypervisor truth (R-241, Approvals cut A1).
//
// The reference Approvals app (booted by the local mirror, routed at /workspace/approvals-app) is an inbox of task requests
// and a request's page with its reviewer tasks. Here a request is one of the daemon's own asks:
//   - a WALLET APPROVAL CHALLENGE — an exact effect a gate refused for want of a grant, parked by the daemon and waiting on
//     the operator (`/v1/hypervisor/authority/challenges`); approving it mints ONE one-use grant for exactly its hashes;
//   - a GOVERNANCE APPROVAL REQUEST — a record-only ask over a subject (`/v1/hypervisor/governance/approval-requests`);
//   - a THREAD APPROVAL — a tool call inside a run waiting on the operator (the approvals inbox's pending rows).
// Each is answered under the reference's one request type that asks for authority ("Access requests"); every other
// reference type (Ontology proposals, Workshop proposals, deletions, CDM publish, retention changes, user intake, add
// reference) has no Hypervisor counterpart and lists none. A request's page is its record: what it asks, who asked, its
// policy trail and hashes, and its reviewer — the operator. The recorded tenant's requests are never served: the recorded
// answers lend STRUCTURE only.
//
// Decisions stay with the daemon, and the UI server never signs. The reference app has no passphrase field, so it cannot
// approve a wallet challenge (the daemon's decision route opens the sealed approver key only with the operator passphrase):
// Approve there is refused by name, naming the Hypervisor's own approval page for that very challenge
// (/__ioi/authority/challenges/<id>, authority-challenge-page.mjs), which takes the passphrase and relays it to the daemon —
// whoever parked the effect, the Hypervisor or a direct session execute. A rejection needs no key — the
// daemon's decision route denies a challenge on the operator's session alone and mints nothing — so Reject is the daemon's
// deny, with the reason the person typed. A governance request's Approve is the governance plane's own transition (the
// daemon names the reviewer from the session and writes the receipt); its Reject is refused by name, because the plane's
// rejection carries no reason and the typed one would be lost. Close, invited reviewers and comments are refused by name.
import crypto from "node:crypto";
import { uuidOf } from "./adopted-pipeline.mjs";
import { principalUserId } from "./adopted-automate.mjs";
import { challengePagePath } from "./authority-challenge-page.mjs";

const cid = (s) => crypto.createHash("sha256").update(String(s)).digest("base64");

// The reference type every Hypervisor request is listed under, and the ones it has no counterpart for.
export const TASK_TYPE = "compass:request-access-to-resource";
export const KINDS = Object.freeze({
  wallet_approval_challenge: { subtaskType: "hypervisor:approve-exact-effect", label: "An effect waiting on the operator" },
  governance_approval_request: { subtaskType: "hypervisor:governance-decision", label: "A governance approval" },
  thread_approval: { subtaskType: "hypervisor:approve-tool-call", label: "A tool call waiting on the operator" },
});
export const requestRidOf = (kind, id) => `ri.approvals.main.task-request.${uuidOf(`approvals:${kind}:${id}`)}`;
const subRequestRidOf = (kind, id) => `ri.approvals.main.task-subrequest.${uuidOf(`approvals-subtask:${kind}:${id}`)}`;
const policyRidOf = (kind) => `ri.approvals.main.task-policy.${uuidOf(`approvals-policy:${kind}`)}`;
const userOf = (ref) => (ref ? principalUserId(ref) : null);

// ---- the principals the adopted layer can name: the caller and the daemon's directory (read when the caller may read it)
// dir: Map principal_ref → { ref, name, email }
export function directoryOf(principal, principals = []) {
  const dir = new Map();
  for (const p of principals || []) if (p?.principal_ref) dir.set(p.principal_ref, { ref: p.principal_ref, name: p.name || null, email: p.email || null });
  if (principal?.ref) dir.set(principal.ref, { ref: principal.ref, name: principal.name || null, email: principal.email || null });
  return dir;
}
const nameOf = (dir, ref) => (ref ? dir?.get(ref)?.name || dir?.get(ref)?.email || ref : null);

// ---- statuses: the reference's hierarchy is Open {Approved, Changes requested, Action required, Pending approval}, Draft,
// Closed {Closed, Rejected and closed, Completed}.
// A challenge approved but not yet run is Approved (open: the requester's retry runs it once); consumed, it is Completed;
// denied, Rejected and closed; a pending challenge past its expiry is Closed (re-running the effect parks it again); an
// approval whose one-use grant expired unused is Closed (the authority keeps one decision per request, so it is never
// decided again: the requester's retry asks the effect again as a new challenge). A decision being recorded (the record's
// `deciding` marker) and one whose outcome an interruption left unknown are still Pending approval — nothing is decided —
// and are named in the request's description (R-240, challenge states + re-ask); the daemon's words decide what may move.
export function challengeStatusOf(c, nowMs = Date.now()) {
  switch (c?.state) {
    case "pending":
      if (c.deciding && typeof c.deciding === "object") return "PENDING_APPROVAL";
      return Number(c.expires_at_ms) && Number(c.expires_at_ms) <= nowMs ? "CLOSED" : "PENDING_APPROVAL";
    case "approved": return grantExpiredUnused(c, nowMs) ? "CLOSED" : "APPROVED";
    case "consuming": return "APPROVED";
    case "consumed": return "APPROVED_AND_COMPLETED";
    case "denied": return "DISAPPROVED_AND_CLOSED";
    default: return "CLOSED";
  }
}
const grantExpiredUnused = (c, nowMs) => c?.state === "approved" && Number(c.grant_expires_at_ms) > 0 && Number(c.grant_expires_at_ms) <= nowMs;
// What a challenge's record says beyond its state: an approve being recorded (who, since when), an interrupted approve whose
// outcome is unknown (the daemon's named reason), an expired grant and the successor its re-ask parked, the ask a successor
// supersedes, and approves a stopped daemon left interrupted with nothing recorded.
export function challengeFacetsOf(c, nowMs = Date.now()) {
  const deciding = c?.state === "pending" && c.deciding && typeof c.deciding === "object" ? c.deciding : null;
  const unknown = c?.state === "pending" && !deciding && c.outcome_unknown && typeof c.outcome_unknown === "object" ? c.outcome_unknown : null;
  return {
    deciding: deciding ? { startedAt: deciding.started_at || null, decidedBy: deciding.decided_by || null } : null,
    outcomeUnknown: unknown ? { reason: unknown.reason || null, message: unknown.message || null, since: unknown.since || null } : null,
    grantExpired: grantExpiredUnused(c, nowMs),
    supersededBy: typeof c?.superseded_by === "string" ? c.superseded_by : null,
    supersedes: typeof c?.supersedes === "string" ? c.supersedes : null,
    interrupted: (Array.isArray(c?.history) ? c.history : []).filter((h) => h?.state === "interrupted"),
  };
}
// A governance approval is record-only — the decision is the whole of it — so an approved request is Completed; a rejected
// one Rejected and closed; a revoked approval Closed.
export function governanceStatusOf(a) {
  switch (a?.status) {
    case "pending": return "PENDING_APPROVAL";
    case "approved": return "APPROVED_AND_COMPLETED";
    case "rejected": case "denied": return "DISAPPROVED_AND_CLOSED";
    default: return "CLOSED";
  }
}
// the reviewer task's own status
const subStatusOf = (status) => (status === "PENDING_APPROVAL" ? "PENDING" : status === "DISAPPROVED_AND_CLOSED" ? "REJECTED" : status === "CLOSED" ? "CLOSED" : "APPROVED");
export const OPEN_STATUSES = ["APPROVED", "DISAPPROVED", "INVOCATION_BLOCKED", "PENDING_APPROVAL"];

const lines = (rows) => rows.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => `${k}: ${v}`).join("\n");
const when = (ms) => (Number(ms) ? new Date(Number(ms)).toISOString() : null);

// ---- one request per daemon item. ctx: { governance, challenges, inboxItems, principal: {ref, name, email, role}, principals }
// Who may decide (the request's reviewers): a challenge or a tool call — the deployment's operator (an administrator; the
// daemon refuses anyone else); a governance request — any signed-in principal (the plane's own posture). The reviewers a
// request names are the caller when they may decide it. The requester is not excluded: an operator's own parked effect
// waits on that operator (the reference leaves a requester out of their own inbox; here that would hide what waits on them).
export function requestsOf({ governance = [], challenges = [], inboxItems = [], principal = {}, principals = [], nowMs = Date.now() } = {}) {
  const me = principal?.ref || null;
  if (!me) return [];
  const meId = userOf(me);
  const operator = principal.role === "admin";
  const dir = directoryOf(principal, principals);
  const out = [];
  for (const c of challenges || []) {
    if (!c || !c.challenge_id) continue;
    const status = challengeStatusOf(c, nowMs);
    const facets = challengeFacetsOf(c, nowMs);
    const pre = c.published_preimage || {};
    const intent = pre.request_preimage?.intent || pre.effect?.intent || null;
    const scopes = pre.request_preimage?.scopes || pre.effect?.scopes || [];
    const decided = c.decision && typeof c.decision === "object" ? c.decision : null;
    out.push({
      kind: "wallet_approval_challenge", id: c.challenge_id, rid: requestRidOf("wallet_approval_challenge", c.challenge_id),
      title: `Approve ${c.operation || "an effect"} on ${c.subject_ref || "a subject"}`,
      description: lines([
        ["Asks", `the operator's approval of one exact effect the daemon parked for want of a grant: ${c.operation || "an effect"} on ${c.subject_ref || "—"}. Approving mints one one-use grant for exactly these hashes; the requester's retry then runs it once.`],
        ["Requested by", nameOf(dir, c.requester_ref)], ["Intent", intent], ["Scopes", scopes.join(", ")], ["Target scope", c.target_scope],
        ["Policy", pre.policy_preimage?.domain], ["Policy hash", c.policy_hash], ["Request hash", c.request_hash], ["Audience", c.audience],
        ["Approval ref", c.approval_ref], ["Expires", when(c.expires_at_ms)],
        ["Asks again", facets.supersedes ? `this effect's earlier approval expired unused, and the authority never decides one request twice, so this ask binds the same effect under a fresh single-use nonce (a new request hash): ${challengePagePath(facets.supersedes)}` : null],
        ["Deciding", facets.deciding ? `started ${facets.deciding.startedAt || "earlier"} by ${nameOf(dir, facets.deciding.decidedBy) || "an operator"} — the deployment authority is recording the operator's approval now; nothing else can be decided until it settles (${challengePagePath(c.challenge_id)})` : null],
        ["Outcome unknown", facets.outcomeUnknown ? `${facets.outcomeUnknown.reason || "no reason named"} — ${facets.outcomeUnknown.message || ""}. Approving is refused until the daemon reconciles it from the authority's record; rejecting stays open` : null],
        ["Closed", status === "CLOSED" && c.state === "pending" ? `expired at ${when(c.expires_at_ms)} with no decision; re-running the effect parks it again` : null],
        ["Grant expired", facets.grantExpired ? `approved, but its one-use grant expired unused at ${when(c.grant_expires_at_ms)}; the authority keeps one decision per request, so the action must be asked again — ${facets.supersededBy ? `asked again: ${challengePagePath(facets.supersededBy)}` : "the requester's retry parks a new challenge"}` : null],
        ["Decided", decided ? `${decided.decision} by ${nameOf(dir, decided.decided_by) || "—"} at ${decided.decided_at || "—"}${decided.reason ? ` — ${decided.reason}` : ""}` : null],
        ["Interrupted", facets.interrupted.length ? facets.interrupted.map((h) => `${h.closed_at || "—"}: the daemon stopped mid-approve${h.reconciliation?.attempt?.decided_by ? ` (started by ${nameOf(dir, h.reconciliation.attempt.decided_by)})` : ""}; the authority recorded nothing, so it was decided afresh`).join("; ") : null],
        ["Grant", c.grant_ref], ["Consumed", c.consumed_at], ["Consumed by", c.consumed_by],
      ]),
      status, creatorRef: c.requester_ref || null, created_at: c.created_at || null, updated_at: c.last_parked_at || c.created_at || null,
      reviewers: operator ? [meId] : [], reviewedBy: decided?.decided_by ? [userOf(decided.decided_by)] : [],
      decidedBy: decided?.decided_by || null, decidedAt: decided?.decided_at || null, decision: decided?.decision || null,
      // an approved effect completes when its one-use grant is consumed (the requester's retry ran it once)
      completedAt: status === "APPROVED_AND_COMPLETED" ? c.consumed_at || decided?.decided_at || null : null,
      policy: { met: status === "APPROVED" || status === "APPROVED_AND_COMPLETED" }, dir, record: c, facets,
      // while an approve is being recorded nobody can decide it (the daemon answers any decision 409)
      decisionOpen: !facets.deciding,
    });
  }
  for (const a of governance || []) {
    if (!a || !a.id) continue;
    const status = governanceStatusOf(a);
    out.push({
      kind: "governance_approval_request", id: a.id, rid: requestRidOf("governance_approval_request", a.id),
      title: `${a.request_kind || "Approval"} — ${a.subject_ref || "a subject"}`,
      description: lines([
        ["Asks", a.reason || null], ["Requested by", nameOf(dir, a.created_by_principal_ref)], ["Subject", a.subject_ref], ["Kind", a.request_kind],
        ["Required authority", (a.required_authority_refs || []).join(", ")], ["Would call", (a.would_call || []).join(", ")],
        ["Enforcement preview", a.enforcement_preview && typeof a.enforcement_preview === "object" ? JSON.stringify(a.enforcement_preview) : a.enforcement_preview],
        ["Decided", a.reviewer_ref ? `${a.status} by ${nameOf(dir, a.reviewer_ref)} at ${a.decided_at || "—"}` : null],
        ["Receipts", (a.receipt_refs || []).join(", ")], ["Record", a.ref],
      ]),
      status, creatorRef: a.created_by_principal_ref || null, created_at: a.created_at || null, updated_at: a.updated_at || a.created_at || null,
      reviewers: [meId], reviewedBy: a.reviewer_ref ? [userOf(a.reviewer_ref)] : [],
      decidedBy: a.reviewer_ref || null, decidedAt: a.decided_at || null, decision: a.status === "pending" ? null : a.status,
      completedAt: status === "APPROVED_AND_COMPLETED" ? a.decided_at || null : null,
      policy: { met: status === "APPROVED_AND_COMPLETED" }, dir, record: a,
    });
  }
  // (the daemon's inbox lists only PENDING tool calls: a decided one leaves the inbox, so no other status is shown here)
  for (const t of inboxItems || []) {
    if (t?.source_plane !== "thread_approval" || !t.approval_id) continue;
    const id = `${t.thread_id}/${t.approval_id}`;
    out.push({
      kind: "thread_approval", id, rid: requestRidOf("thread_approval", id),
      title: `Approve a tool call in ${t.subject_ref || t.thread_id || "a run"}`,
      description: lines([["Asks", t.reason || "the operator's approval of a tool call inside a run"], ["Requested by", nameOf(dir, t.requester_ref)], ["Run", t.run_id], ["Thread", t.thread_id],
        ["Approval", t.approval_id], ["Lease", t.lease_status], ["Receipts", (t.receipt_refs || []).join(", ")], ["Decided with", t.decide?.route ? `${t.decide.method || "POST"} ${t.decide.route}, under a wallet grant for this lease` : null]]),
      status: "PENDING_APPROVAL", creatorRef: t.requester_ref || null, created_at: t.created_at || null, updated_at: t.updated_at || t.created_at || null,
      reviewers: operator ? [meId] : [], reviewedBy: [], decidedBy: null, decidedAt: null, decision: null, completedAt: null, policy: { met: false }, dir, record: t,
    });
  }
  return out;
}

// ---- the search: PUT /approvals/api/search/task-requests {filters, sort, pageSizeLimit} and /counts {globalFilters, subFilters}
// Every filter the app sends is honored as a real server would; one the adopted layer does not know matches nothing (never
// silently ignored).
export function matchesFilter(row, f) {
  if (!f || !f.type) return true;
  switch (f.type) {
    case "taskType": return (f.taskType?.taskTypes || []).includes(TASK_TYPE);
    case "status": return (f.status?.statuses || []).includes(row.status);
    case "createdBy": return !!row.creatorRef && (f.createdBy?.userIds || []).includes(userOf(row.creatorRef));
    case "reviewers": return (f.reviewers?.userIds || []).some((u) => row.reviewers.includes(u));
    case "notReviewedBy": return !(f.notReviewedBy?.userIds || []).some((u) => row.reviewedBy.includes(u));
    case "title": return row.title.toLowerCase().includes(String(f.title?.contains || "").toLowerCase());
    case "notTitle": return !row.title.includes(String(f.notTitle?.contains || "\u0000"));
    // the access-request facets (project requested to, users or groups in the request, groups requested to): no Hypervisor
    // request names a project or a principal group, so a facet with values matches none
    case "customIndexedData": return !(f.customIndexedData?.values || []).length;
    default: return false;
  }
}
const all = (rows, filters) => rows.filter((r) => (filters || []).every((f) => matchesFilter(r, f)));
function searchRowOf(r) {
  return { taskType: TASK_TYPE, taskRid: r.rid, title: r.title, creator: userOf(r.creatorRef), creationTime: r.created_at, status: r.status, customIndexedData: {},
    subtasks: [{ type: KINDS[r.kind].subtaskType, id: subRequestRidOf(r.kind, r.id), version: String(r.record?.revision || 1), approvalStatus: subStatusOf(r.status) }] };
}
export function searchOf(request, rows) {
  const asc = request?.sort?.order === "ASC";
  const found = all(rows, request?.filters).sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")) * (asc ? 1 : -1));
  const size = Math.max(1, Number(request?.pageSizeLimit) || 100);
  const from = Math.max(0, Number(request?.pageToken) || 0);
  return { requests: found.slice(from, from + size).map(searchRowOf), totalCount: found.length, ...(from + size < found.length ? { nextPageToken: String(from + size) } : {}) };
}
export function countsOf(request, rows) {
  const global = request?.globalFilters || [];
  const subCounts = Object.fromEntries(Object.entries(request?.subFilters || {}).map(([k, v]) => [k, all(rows, [...global, ...(v || [])]).length]));
  return { totalCount: all(rows, global).length, subCounts };
}

// ---- a request by its rid: GET /approvals/api/task-requests/<rid>/minimal and GET …/<rid>
export const rowByRid = (rows, rid) => (rows || []).find((r) => r.rid === rid) || null;
export function minimalOf(r) {
  return { taskRid: r.rid, taskType: TASK_TYPE, latestVersion: 0, title: r.title, creationTime: r.created_at, invokeAsync: false, lastUpdatedAt: r.updated_at, reviewers: [], status: r.status, customIndexedData: {} };
}
export function fullOf(r) {
  const creator = userOf(r.creatorRef);
  const history = [{ type: "creationEntry", creationEntry: { time: r.created_at, creator } }];
  // an approval not yet run is a review, not a completion (the reference's history marks only creation and the end)
  if (r.status === "DISAPPROVED_AND_CLOSED" && r.decidedAt) history.push({ type: "rejectedEntry", rejectedEntry: { time: r.decidedAt, user: userOf(r.decidedBy) } });
  if (r.status === "APPROVED_AND_COMPLETED" && r.completedAt) history.push({ type: "completedEntry", completedEntry: { time: r.completedAt, user: userOf(r.decidedBy) } });
  return { ...minimalOf(r), taskRequestRid: r.rid, description: r.description, creator, contributors: creator ? [creator] : [], history,
    versionMetadata: [{ version: 0, createdBy: creator, createdAt: r.created_at }],
    subtasks: [{ type: KINDS[r.kind].subtaskType, id: subRequestRidOf(r.kind, r.id), version: String(r.record?.revision || 1), policies: [{ rid: policyRidOf(r.kind), version: 1 }], reviews: [], approvalStatus: subStatusOf(r.status) }] };
}
export const NOT_FOUND = (rid) => ({ errorCode: "NOT_FOUND", errorName: "Approvals:TaskRequestNotFound", errorInstanceId: "", parameters: { taskRid: rid } });

// ---- principals as the reference names them
function principalNode(ref, principal, dir) {
  if (!ref) return null;
  const id = userOf(ref);
  const known = dir?.get(ref) || (principal?.ref === ref ? { name: principal.name, email: principal.email } : null);
  const name = known?.name || known?.email || ref;
  const initials = String(name).split(/\s+/u).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("") || "?";
  return { __typename: "User", __implements: ["Principal"], _id: cid(`User:${id}`), id, fullName: name, displayName: name, username: known?.email || ref, initials, imageUrl: null,
    permissions: { __typename: "UserPermissions", isCurrentUser: principal?.ref === ref }, guestOrganizations: [], organization: null };
}
// POST /multipass/api/administration/principals — each asked id that names a principal the adopted layer knows
export function principalsOf(ids, dir) {
  const byId = new Map([...(dir || new Map()).values()].map((p) => [userOf(p.ref), p]));
  return (Array.isArray(ids) ? ids : []).filter((id) => byId.has(id)).map((id) => {
    const p = byId.get(id); const name = p.name || p.email || p.ref; const [given, ...rest] = String(name).split(" ");
    return { id, username: p.email || p.ref, realm: "hypervisor", type: "USER", attributes: { "multipass:given-name": [given || name], "multipass:family-name": [rest.join(" ")], ...(p.email ? { "multipass:email:primary": [p.email] } : {}) } };
  });
}

// POST /multipass/api/search/v2/search — the invite-reviewers picker: users the adopted layer can name, matched by the typed
// text (no group is named here)
export function principalSearchOf(request, dir) {
  const text = String(request?.query || "").trim().toLowerCase();
  const types = request?.principalTypes || ["USER"];
  if (!types.includes("USER")) return { values: [], nextPageToken: null };
  const found = principalsOf([...(dir || new Map()).values()].map((p) => userOf(p.ref)), dir)
    .filter((p) => !text || `${p.attributes["multipass:given-name"]?.[0] || ""} ${p.attributes["multipass:family-name"]?.[0] || ""} ${p.username}`.toLowerCase().includes(text));
  return { values: found.slice(0, Math.max(1, Number(request?.pageSize) || 100)).map((principal) => ({ principal })), nextPageToken: null };
}

// ---- a request's page (GraphQL): the request header, its reviewer task, the decision as a review, the policy trail
function subRequestOf(r, principal) {
  const me = principal?.ref || null;
  const may = !!me && r.reviewers.includes(userOf(me)) && r.status === "PENDING_APPROVAL" && r.decisionOpen !== false;
  const review = r.decidedBy ? [{ __typename: "ApprovalSubRequestReview", _id: cid(`Review:${r.rid}`), active: true, reviewType: r.status === "DISAPPROVED_AND_CLOSED" ? "DISAPPROVE" : "APPROVE",
    created: { __typename: "Attribution", user: principalNode(r.decidedBy, principal, r.dir), time: r.decidedAt } }] : [];
  return {
    __typename: "HypervisorApprovalSubRequest", __implements: ["ApprovalSubRequest"], _id: cid(`SubRequest:${r.rid}`), id: subRequestRidOf(r.kind, r.id), version: String(r.record?.revision || 1),
    status: subStatusOf(r.status), reviews: review, checkpointInteraction: null, passesCheckpointsValidation: true, hasCheckpointInteraction: false,
    permissions: { __typename: "ApprovalSubRequestPermissions", canFullyApprove: may, canPartiallyApprove: may },
    // the policy trail: the one policy this ask is decided under (a challenge's hash is in its record)
    applicablePolicies: [{ __typename: "ApprovalSubRequestResolvedPolicy", policyApprovalRequirementsMet: r.policy.met, approvingReviews: [],
      policy: { __typename: "SubRequestApprovalPolicyVersion", _id: cid(`Policy:${r.kind}`), rid: policyRidOf(r.kind), isDefault: true, requirements: { __typename: "OrApprovalRequirements" } } }],
    isCurrentlyApplied: r.status === "APPROVED_AND_COMPLETED",
  };
}
export function requestNodeOf(r, principal) {
  return {
    __typename: "HypervisorApprovalRequest", __implements: ["ApprovalRequest"], _id: cid(`ApprovalRequest:${r.rid}`), rid: r.rid, title: r.title, description: r.description, status: r.status,
    created: { __typename: "Attribution", user: principalNode(r.creatorRef, principal, r.dir), time: r.created_at },
    // nothing about a request is edited here, and no checkpoint interaction exists
    permissions: { __typename: "ApprovalRequestPermissions", canEditMetadata: false, canUpdateCheckpointInteractions: false },
    permissionsForCreator: { __typename: "ApprovalRequestPermissions", canView: true },
    latestVersion: { __typename: "ApprovalRequestVersion", _id: cid(`Version:${r.rid}`), version: 0, subRequests: [subRequestOf(r, principal)] },
    invokeWhenReady: false, invocationBlockers: r.status === "PENDING_APPROVAL" ? ["NOT_APPROVED"] : [], reviewers: [], lastInvokedAt: null,
  };
}
export const APPROVALS_GRAPHQL_OPERATIONS = new Set(["ApprovalRequestDetails", "AccessRequestMetadataQuery", "RequestQuery", "GetUserSuggestionList", "CustomIndexedDataPrincipalsFilterSearchQuery",
  "EditAccessRequestDialogQuery", "PrincipalAnchorPopoverPrincipalQuery", "ProjectSearchQuery"]);
// ctx: { rows, principal, dir }
export function approvalsGraphqlFacts(name, variables, ctx) {
  const root = { __typename: "Query" };
  switch (name) {
    case "ApprovalRequestDetails": case "AccessRequestMetadataQuery": case "RequestQuery": case "EditAccessRequestDialogQuery": {
      const r = rowByRid(ctx.rows, variables?.rid);
      return { ...root, approvalRequest: r ? requestNodeOf(r, ctx.principal) : null };
    }
    // the users a person may invite or mention: the principals the adopted layer can name, matched by the typed text
    // (inviting is refused by name when sent)
    case "GetUserSuggestionList": {
      const text = String(variables?.query || "").trim().toLowerCase();
      const users = [...(ctx.dir || new Map()).values()].map((p) => principalNode(p.ref, ctx.principal, ctx.dir))
        .filter((u) => !text || `${u.fullName} ${u.username}`.toLowerCase().includes(text)).slice(0, Math.max(1, Number(variables?.pageSize) || 10));
      return { ...root, principals: { __typename: "PrincipalPage", values: users } };
    }
    // the access-request facets' principal search: the caller belongs to no group the reference names
    case "CustomIndexedDataPrincipalsFilterSearchQuery": {
      const me = principalNode(ctx.principal?.ref, ctx.principal, ctx.dir);
      return { ...root, me: me ? { ...me, groupsIncludingTransitive: [] } : null };
    }
    // a principal's popover (the creator's name on a row or a request's page)
    case "PrincipalAnchorPopoverPrincipalQuery": {
      const p = [...(ctx.dir || new Map()).values()].find((x) => userOf(x.ref) === variables?.principalId);
      return { ...root, principal: p ? principalNode(p.ref, ctx.principal, ctx.dir) : null };
    }
    // the "Project requested to" facet's project search: no Hypervisor request names a project, so none is offered
    case "ProjectSearchQuery": return { ...root, searchResourcesV2: { __typename: "SearchResourcesPage", results: [] } };
    default: return null;
  }
}

// ---- writes: every decision and edit the reference app sends. Refused by name where the daemon holds no counterpart the
// UI server may call without a key (409 on REST, never 403: the app words a 403 as a missing permission, a false reason, and
// prints a 409's message; a GraphQL error's message is the app's toast). Nothing is written by a refusal.
export const WRITE_REFUSALS = {
  // (the message names the challenge's own approval page: approveChallengeRefusal below fills it in)
  approveChallenge: { status: 409, code: "Hypervisor:ApprovalsApproveNeedsPassphrase", message: "Approving mints a grant, and only the operator passphrase opens the sealed approver key that signs it. This page has no passphrase field and holds no key. Approve it on the Hypervisor's approval page for this parked effect, which takes the passphrase and hands it to the daemon: /__ioi/authority/challenges/<its id> (open it in the Hypervisor). Nothing was approved." },
  toolCall: { status: 409, code: "Hypervisor:ApprovalsToolCallNeedsGrant", message: "Deciding a tool call waiting inside a run takes a wallet-signed grant for exactly its approval lease — the daemon's decision on a run's approval admits nothing else — and this page has no passphrase field and holds no key. The run's own client decides it with that grant. Nothing was decided here." },
  rejectGovernance: { status: 409, code: "Hypervisor:ApprovalsRejectionReasonNotKept", message: "The governance plane's rejection records no reason, so the reason typed here would be lost: reject this request on the Hypervisor's governance approvals page. Nothing was rejected." },
  changesRequested: { status: 409, code: "Hypervisor:ApprovalsNoChangesRequested", message: "A Hypervisor request is approved or rejected; it has no changes-requested state. Nothing was changed." },
  decided: { status: 409, code: "Hypervisor:ApprovalsAlreadyDecided", message: "This request is already decided. Nothing was changed." },
  close: { status: 409, code: "Hypervisor:ApprovalsCloseNotBound", message: "A request here is closed by its decision: an open request has no close without one (reject it instead). Nothing was changed." },
  write: { status: 409, code: "Hypervisor:ApprovalsWriteNotBound", message: "A Hypervisor request is the daemon's own record: editing it or inviting reviewers is not bound here. Nothing was changed." },
  comment: { status: 409, code: "Hypervisor:ApprovalsCommentsNotKept", message: "The Hypervisor keeps no comment threads on a request. Nothing was posted." },
  notFound: { status: 404, code: "Hypervisor:ApprovalsRequestNotFound", message: "No request of yours has this id. Nothing was changed." },
  // (the two below are filled in with the record's own words: decisionRunningRefusal and approveOutcomeUnknownRefusal)
  decisionRunning: { status: 409, code: "Hypervisor:ApprovalsDecisionRunning", message: "A decision on this parked effect is already running: the deployment authority is recording it now, and the daemon refuses another decision until it settles. Nothing was sent; re-open the request for the outcome." },
  approveOutcomeUnknown: { status: 409, code: "Hypervisor:ApprovalsApproveOutcomeUnknown", message: "An earlier approval of this parked effect was interrupted and its outcome is not known. The daemon refuses a new approve until it reconciles it from the authority's record, and runs nothing on a guess; rejecting stays open. Nothing was approved." },
};
// Approve on a parked effect, refused toward that effect's own approval page (the app prints the message as its toast)
export const approveChallengeRefusal = (id) => ({ ...WRITE_REFUSALS.approveChallenge, message: WRITE_REFUSALS.approveChallenge.message.replace("/__ioi/authority/challenges/<its id>", challengePagePath(id)) });
// A decision on a parked effect while an approve is being recorded: refused by name, saying who started it and when
export const decisionRunningRefusal = (row) => {
  const d = row?.facets?.deciding;
  return d ? { ...WRITE_REFUSALS.decisionRunning, message: WRITE_REFUSALS.decisionRunning.message.replace("already running:", `already running (started ${d.startedAt || "earlier"} by ${nameOf(row.dir, d.decidedBy) || "an operator"}):`) } : WRITE_REFUSALS.decisionRunning;
};
// Approve on a parked effect whose interrupted approve's outcome is unknown: refused by the daemon's named reason
export const approveOutcomeUnknownRefusal = (row) => {
  const u = row?.facets?.outcomeUnknown;
  return u ? { ...WRITE_REFUSALS.approveOutcomeUnknown, message: WRITE_REFUSALS.approveOutcomeUnknown.message.replace("outcome is not known.", `outcome is not known (${u.reason || "no reason named"}: ${u.message || ""}).`) } : WRITE_REFUSALS.approveOutcomeUnknown;
};
export const refusalBodyOf = (refusal) => ({ errorCode: refusal.status === 404 ? "NOT_FOUND" : "CONFLICT", errorName: refusal.code, errorInstanceId: "", parameters: { message: refusal.message }, message: refusal.message });
// the GraphQL mutations the app's own buttons send
export const APPROVALS_MUTATIONS = new Set(["ReviewSubRequests", "CloseTask", "UpdateReviewers"]);
// the request a mutation names (UpdateReviewers names it taskRid)
export const mutationRidOf = (variables) => variables?.rid || variables?.taskRid || null;
// One mutation → one daemon step or one refusal. A step names the daemon route, method and body the serve sends on the
// caller's session; the serve then answers from the request re-read.
export function mutationStepOf(name, row, variables) {
  if (!row) return { refusal: WRITE_REFUSALS.notFound };
  if (name === "ReviewSubRequests") {
    const type = variables?.reviewType;
    if (row.status !== "PENDING_APPROVAL") return { refusal: WRITE_REFUSALS.decided };
    if (row.kind === "thread_approval") return { refusal: WRITE_REFUSALS.toolCall };
    if (row.kind === "wallet_approval_challenge") {
      if (row.facets?.deciding) return { refusal: decisionRunningRefusal(row) };
      if (type === "APPROVE" && row.facets?.outcomeUnknown) return { refusal: approveOutcomeUnknownRefusal(row) };
      if (type === "APPROVE") return { refusal: approveChallengeRefusal(row.id) };
      // a denial mints nothing: the daemon's decision route takes it on the operator's session, with the typed reason
      if (type === "DISAPPROVE" || type === "REJECT") return { daemon: { method: "POST", route: `/v1/hypervisor/authority/challenges/${encodeURIComponent(row.id)}/decision`, body: { decision: "deny", reason: String(variables?.reason || "").slice(0, 400) } } };
      return { refusal: WRITE_REFUSALS.changesRequested };
    }
    if (type === "APPROVE") return { daemon: { method: "PATCH", route: `/v1/hypervisor/governance/approval-requests/${encodeURIComponent(row.id)}`, body: { transition: "approve" } } };
    if (type === "DISAPPROVE" || type === "REJECT") return { refusal: WRITE_REFUSALS.rejectGovernance };
    return { refusal: WRITE_REFUSALS.changesRequested };
  }
  // "Reject and close" sends the review, then Close: a request its decision already closed answers closed, writing nothing
  if (name === "CloseTask") return row.status === "PENDING_APPROVAL" || row.status === "APPROVED" ? { refusal: WRITE_REFUSALS.close } : { answer: true };
  return { refusal: WRITE_REFUSALS.write };
}
// the mutation's answer, walked by its own document: the request re-read after the step
export function mutationFacts(name, row, principal) {
  const node = row ? requestNodeOf(row, principal) : null;
  if (name === "ReviewSubRequests") return { __typename: "Mutation", reviewApprovalSubRequests: node };
  if (name === "CloseTask") return { __typename: "Mutation", closeApprovalRequest: node };
  return { __typename: "Mutation" };
}
// any REST write the app sends under the approvals service: refused as not bound (the app's decisions are GraphQL)
export function writeRefusalOf(method, path) {
  if (!/^\/approvals\/api\//u.test(String(path)) || method === "GET" || method === "HEAD") return null;
  return WRITE_REFUSALS.write;
}
// POST /comments/api/comments/counts — every asked resource (and locator) has no comment
export function commentCountsOf(request) {
  return { responses: Object.fromEntries(((request && request.resources) || []).map((x) => [x.rid, { rid: x.rid, locatorCounts: x.locator ? { [x.locator]: 0 } : {}, totalCount: null }])) };
}
