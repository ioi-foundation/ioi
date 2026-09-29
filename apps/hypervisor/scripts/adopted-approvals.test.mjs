// The adopted Approvals app's pure answers (R-241, Approvals A1): the daemon's own asks — parked wallet challenges,
// governance approval requests and pending tool calls — as the reference app's task requests; the inbox's search and
// counts over them; a request's record as its page; and every write refused by name.
import test from "node:test";
import assert from "node:assert/strict";
import { answerDocument } from "./adopted-graphql.mjs";
import { principalUserId } from "./adopted-automate.mjs";
import * as AX from "./adopted-approvals.mjs";

const NOW = Date.parse("2026-09-28T12:00:00Z");
const operator = { ref: "user://op", name: "Ada Operator", email: "ada@ioi.local", role: "admin" };
const member = { ref: "user://member", name: "Mo Member", email: "mo@ioi.local", role: "member" };
const OP = principalUserId("user://op"), MEMBER = principalUserId("user://member");
const challenge = (id, state, extra = {}) => ({
  challenge_id: id, approval_ref: `wallet-approval-challenge://${id}`, state, operation: "session-execute", subject_ref: "session:s1",
  target_scope: "scope:hypervisor.live-route.session-execute", policy_hash: "sha256:" + "a".repeat(64), request_hash: "sha256:" + "b".repeat(64), audience: "c".repeat(64),
  published_preimage: { request_preimage: { intent: "create a file", scopes: ["workspace_write"] }, policy_preimage: { domain: "hypervisor.session.execute.policy.v1", scopes: ["workspace_write"] } },
  requester_ref: "user://op", created_at: "2026-09-28T10:00:00Z", last_parked_at: "2026-09-28T10:00:00Z", expires_at_ms: NOW + 3600_000, decision: null, grant_ref: null, ...extra,
});
const gov = (id, status, extra = {}) => ({ id, ref: `approval-request://${id}`, subject_ref: "authority-action://spend", request_kind: "spend_increase", reason: "raise the ceiling", status,
  created_by_principal_ref: "user://op", reviewer_ref: status === "pending" ? null : "user://op", decided_at: status === "pending" ? null : "2026-09-28T11:30:00Z",
  created_at: "2026-09-28T09:00:00Z", updated_at: "2026-09-28T09:00:00Z", receipt_refs: status === "pending" ? [] : ["agentgres://governance-approval-transition-receipt/atr_1"], ...extra });
const fixture = () => ({
  challenges: [challenge("wac_pending", "pending"), challenge("wac_denied", "denied", { decision: { decision: "deny", decided_by: "user://op", decided_at: "2026-09-28T10:30:00Z", reason: "not now" }, created_at: "2026-09-28T08:00:00Z" }),
    challenge("wac_expired", "pending", { expires_at_ms: NOW - 1, created_at: "2026-09-27T08:00:00Z" }), challenge("wac_consumed", "consumed", { decision: { decision: "approve", decided_by: "user://op", decided_at: "2026-09-28T07:00:00Z" }, consumed_by: "authority-admission-intents/x", consumed_at: "2026-09-28T07:30:00Z", created_at: "2026-09-28T06:00:00Z" })],
  governance: [gov("appr_pending", "pending"), gov("appr_approved", "approved"), gov("appr_rejected", "rejected"), gov("appr_theirs", "pending", { created_by_principal_ref: "user://member", created_at: "2026-09-28T11:00:00Z" })],
  inboxItems: [{ source_plane: "thread_approval", thread_id: "th_1", approval_id: "ap_1", run_id: "run_1", subject_ref: "run_1", reason: "write to /etc", status: "pending", requester_ref: "user://op", created_at: "2026-09-28T11:45:00Z",
    lease_status: "pending", decide: { route: "/v1/threads/th_1/approvals/ap_1/decision", method: "POST" } },
    { source_plane: "wallet_approval_challenge", challenge_id: "wac_pending" }, { source_plane: "improvement_proposal", item_ref: "imp://x" }],
  nowMs: NOW,
});

test("each daemon ask is one request: challenges and governance requests in every status, and the inbox's pending tool calls — nothing else, and nothing twice", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  assert.deepEqual(rows.map((r) => `${r.kind}:${r.id}`).sort(), [
    "governance_approval_request:appr_approved", "governance_approval_request:appr_pending", "governance_approval_request:appr_rejected", "governance_approval_request:appr_theirs",
    "thread_approval:th_1/ap_1", "wallet_approval_challenge:wac_consumed", "wallet_approval_challenge:wac_denied", "wallet_approval_challenge:wac_expired", "wallet_approval_challenge:wac_pending"]);
  assert.equal(new Set(rows.map((r) => r.rid)).size, rows.length, "rids are distinct");
  assert.ok(rows.every((r) => /^ri\.approvals\.main\.task-request\.[0-9a-f-]{36}$/u.test(r.rid)), "rids are derived, uuid-shaped");
  assert.deepEqual(AX.requestsOf({ ...fixture(), principal: {} }), [], "signed out: no request is anyone's");
});

test("statuses map onto the reference's hierarchy from daemon truth", () => {
  assert.equal(AX.challengeStatusOf(challenge("a", "pending"), NOW), "PENDING_APPROVAL");
  assert.equal(AX.challengeStatusOf(challenge("a", "pending", { expires_at_ms: NOW - 1 }), NOW), "CLOSED", "an expired ask is closed (re-running the effect parks it again)");
  assert.equal(AX.challengeStatusOf(challenge("a", "approved"), NOW), "APPROVED", "approved, not yet run: open");
  assert.equal(AX.challengeStatusOf(challenge("a", "consuming"), NOW), "APPROVED");
  assert.equal(AX.challengeStatusOf(challenge("a", "consumed"), NOW), "APPROVED_AND_COMPLETED");
  assert.equal(AX.challengeStatusOf(challenge("a", "denied"), NOW), "DISAPPROVED_AND_CLOSED");
  assert.equal(AX.governanceStatusOf(gov("g", "pending")), "PENDING_APPROVAL");
  assert.equal(AX.governanceStatusOf(gov("g", "approved")), "APPROVED_AND_COMPLETED", "record-only: the decision is the whole of it");
  assert.equal(AX.governanceStatusOf(gov("g", "rejected")), "DISAPPROVED_AND_CLOSED");
  assert.equal(AX.governanceStatusOf(gov("g", "revoked")), "CLOSED");
});

test("the reviewers are who the daemon lets decide: the operator for challenges and tool calls, any signed-in principal for governance", () => {
  const byId = (p) => Object.fromEntries(AX.requestsOf({ ...fixture(), principal: p }).map((r) => [r.id, r]));
  const asOp = byId(operator), asMember = byId(member);
  assert.deepEqual(asOp.wac_pending.reviewers, [OP]);
  assert.deepEqual(asMember.wac_pending.reviewers, [], "a member cannot decide a challenge (the daemon refuses anyone but an administrator)");
  assert.deepEqual(asMember["th_1/ap_1"].reviewers, []);
  assert.deepEqual(asMember.appr_pending.reviewers, [MEMBER], "any signed-in principal may decide a governance request");
  assert.deepEqual(asOp.wac_denied.reviewedBy, [OP], "the decider is who reviewed it");
  assert.deepEqual(asOp.appr_approved.reviewedBy, [OP]);
});

// the app's own requests (as recorded): Your inbox is the reviewRequests sub-filter; Created by you is myRequests
const TYPES = { type: "taskType", taskType: { taskTypes: [AX.TASK_TYPE, "ontology-metadata:approvals-v2", "cdm:publish-request-approval-task", "foundry-retention:policy-v2-change-request"] } };
const NOT_PIPELINE = { type: "notTitle", notTitle: { type: "contains", contains: "ri.eddie.main.pipeline" } };
const countsRequest = (me) => ({ globalFilters: [TYPES, NOT_PIPELINE], subFilters: {
  all: [NOT_PIPELINE], myRequests: [{ type: "createdBy", createdBy: { userIds: [me] } }, NOT_PIPELINE],
  reviewRequests: [{ type: "status", status: { statuses: AX.OPEN_STATUSES } }, NOT_PIPELINE, { type: "reviewers", reviewers: { userIds: [me] } }, { type: "notReviewedBy", notReviewedBy: { userIds: [me] } }] } });

test("the counts: Your inbox is what waits on the caller, Created by you what they asked, All requests everything", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  assert.deepEqual(AX.countsOf(countsRequest(OP), rows), { totalCount: 9, subCounts: { all: 9, myRequests: 8, reviewRequests: 4 } }, "the tool call the operator's run asked for is theirs");
  const asMember = AX.requestsOf({ ...fixture(), principal: member });
  assert.deepEqual(AX.countsOf(countsRequest(MEMBER), asMember).subCounts, { all: 9, myRequests: 1, reviewRequests: 2 }, "a member's inbox holds only the governance requests they may decide");
});

test("the search sifts: request type, status, creator, text, and sort order — and an unknown filter matches nothing", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const search = (filters, order = "DESC") => AX.searchOf({ filters, sort: { field: "CREATION_TIME", order }, pageSizeLimit: 100 }, rows);
  const inbox = search([TYPES, NOT_PIPELINE, { type: "status", status: { statuses: AX.OPEN_STATUSES } }, { type: "reviewers", reviewers: { userIds: [OP] } }, { type: "notReviewedBy", notReviewedBy: { userIds: [OP] } }]);
  assert.deepEqual(inbox.requests.map((r) => r.title), ["Approve a tool call in run_1", "spend_increase — authority-action://spend", "Approve session-execute on session:s1", "spend_increase — authority-action://spend"]);
  assert.ok(inbox.requests.every((r) => r.taskType === AX.TASK_TYPE && r.status === "PENDING_APPROVAL" && r.subtasks.length === 1));
  const ontologyOnly = search([{ type: "taskType", taskType: { taskTypes: ["ontology-metadata:approvals-v2", "ontology-metadata:approvals"] } }]);
  assert.equal(ontologyOnly.totalCount, 0, "the reference types with no Hypervisor counterpart list none");
  const closed = search([{ type: "status", status: { statuses: ["CLOSED", "DISAPPROVED_AND_CLOSED", "APPROVED_AND_COMPLETED"] } }]);
  assert.deepEqual(closed.requests.map((r) => r.status).sort(), ["APPROVED_AND_COMPLETED", "APPROVED_AND_COMPLETED", "CLOSED", "DISAPPROVED_AND_CLOSED", "DISAPPROVED_AND_CLOSED"]);
  const mine = search([{ type: "createdBy", createdBy: { userIds: [MEMBER] } }]);
  assert.deepEqual(mine.requests.map((r) => r.creator), [MEMBER]);
  assert.equal(search([{ type: "title", title: { type: "contains", contains: "SESSION-EXECUTE" } }]).totalCount, 4, "search is case-insensitive over the title");
  const oldest = search([], "ASC").requests.map((r) => r.creationTime);
  assert.deepEqual(oldest, [...oldest].sort(), "Oldest created sorts ascending");
  assert.equal(search([{ type: "customIndexedData", customIndexedData: { key: "compass:projectRid", values: ["ri.compass.main.folder.x"] } }]).totalCount, 0, "no request names a project");
  assert.equal(search([{ type: "somethingNew" }]).totalCount, 0, "an unknown filter is never silently ignored");
  assert.equal(AX.searchOf({ filters: [], pageSizeLimit: 2 }, rows).nextPageToken, "2");
});

test("a request by its rid: minimal and full reads over its record, and an unknown rid is the reference's not-found", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const r = rows.find((x) => x.id === "wac_denied");
  assert.equal(AX.rowByRid(rows, r.rid), r);
  assert.deepEqual(AX.minimalOf(r), { taskRid: r.rid, taskType: AX.TASK_TYPE, latestVersion: 0, title: "Approve session-execute on session:s1", creationTime: "2026-09-28T08:00:00Z", invokeAsync: false, lastUpdatedAt: "2026-09-28T10:00:00Z", reviewers: [], status: "DISAPPROVED_AND_CLOSED", customIndexedData: {} });
  const full = AX.fullOf(r);
  assert.equal(full.creator, OP);
  assert.deepEqual(full.history.map((h) => h.type), ["creationEntry", "rejectedEntry"]);
  const consumed = AX.fullOf(rows.find((x) => x.id === "wac_consumed"));
  assert.deepEqual(consumed.history.map((h) => [h.type, h.completedEntry?.time || h.creationEntry?.time]), [["creationEntry", "2026-09-28T06:00:00Z"], ["completedEntry", "2026-09-28T07:30:00Z"]], "an effect completes when its grant is consumed");
  const approvedOnly = AX.requestsOf({ ...fixture(), challenges: [challenge("wac_approved", "approved", { decision: { decision: "approve", decided_by: "user://op", decided_at: "2026-09-28T11:00:00Z" }, grant_ref: "grant://g1" })], principal: operator })
    .find((x) => x.id === "wac_approved");
  assert.deepEqual(AX.fullOf(approvedOnly).history.map((h) => h.type), ["creationEntry"], "an approval not yet run is a review, not a completion");
  assert.match(approvedOnly.description, /Decided: approve by Ada Operator at 2026-09-28T11:00:00Z/u);
  assert.match(approvedOnly.description, /Grant: grant:\/\/g1/u);
  assert.equal(AX.rowByRid(rows, "ri.approvals.main.task-request.00000000-0000-0000-0000-000000000000"), null);
  assert.equal(AX.NOT_FOUND("x").errorName, "Approvals:TaskRequestNotFound");
});

test("a challenge's page is its record: what it asks, who asked, its hashes and policy, and the operator as its reviewer", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const r = rows.find((x) => x.id === "wac_pending");
  const q = "query RequestQuery($rid: RID!) { approvalRequest(rid: $rid) { rid title description status created { user { id ... on User { fullName username } __typename } time } permissions { canEditMetadata } latestVersion { subRequests { id status permissions { canFullyApprove canPartiallyApprove } reviews { reviewType } applicablePolicies { policyApprovalRequirementsMet policy { rid isDefault } } __typename } } invocationBlockers __typename } }";
  const a = answerDocument(q, AX.approvalsGraphqlFacts("RequestQuery", { rid: r.rid }, { rows, principal: operator }), null, "RequestQuery").approvalRequest;
  assert.equal(a.title, "Approve session-execute on session:s1");
  assert.equal(a.status, "PENDING_APPROVAL");
  assert.match(a.description, /Policy hash: sha256:a{64}/u);
  assert.match(a.description, /Request hash: sha256:b{64}/u);
  assert.match(a.description, /Audience: c{64}/u);
  assert.match(a.description, /Intent: create a file/u);
  assert.match(a.description, /Target scope: scope:hypervisor\.live-route\.session-execute/u);
  assert.deepEqual([a.created.user.id, a.created.user.fullName], [OP, "Ada Operator"]);
  assert.equal(a.permissions.canEditMetadata, false, "nothing about a request is edited here");
  const sub = a.latestVersion.subRequests[0];
  assert.deepEqual([sub.status, sub.permissions.canFullyApprove, sub.reviews.length], ["PENDING", true, 0], "the operator may decide it (approving itself is the effect's own approval page's)");
  assert.equal(sub.applicablePolicies[0].policyApprovalRequirementsMet, false);
  assert.deepEqual(a.invocationBlockers, ["NOT_APPROVED"]);
  const asMember = AX.requestsOf({ ...fixture(), principal: member });
  const theirs = answerDocument(q, AX.approvalsGraphqlFacts("RequestQuery", { rid: r.rid }, { rows: asMember, principal: member }), null, "RequestQuery").approvalRequest;
  assert.equal(theirs.latestVersion.subRequests[0].permissions.canFullyApprove, false, "a member may not decide a challenge");
  assert.equal(AX.approvalsGraphqlFacts("RequestQuery", { rid: "ri.approvals.main.task-request.nope" }, { rows, principal: operator }).approvalRequest, null);
});

test("a decided request shows its decision as the reviewer's review", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const q = "query RequestQuery($rid: RID!) { approvalRequest(rid: $rid) { status latestVersion { subRequests { status reviews { active reviewType created { user { id } time } } permissions { canFullyApprove } __typename } } } }";
  const denied = answerDocument(q, AX.approvalsGraphqlFacts("RequestQuery", { rid: rows.find((x) => x.id === "wac_denied").rid }, { rows, principal: operator }), null, "RequestQuery").approvalRequest;
  assert.equal(denied.status, "DISAPPROVED_AND_CLOSED");
  assert.deepEqual(denied.latestVersion.subRequests[0].reviews.map((v) => [v.reviewType, v.created.user.id, v.created.time]), [["DISAPPROVE", OP, "2026-09-28T10:30:00Z"]]);
  assert.equal(denied.latestVersion.subRequests[0].permissions.canFullyApprove, false, "a decided request cannot be decided again");
  const approved = answerDocument(q, AX.approvalsGraphqlFacts("RequestQuery", { rid: rows.find((x) => x.id === "appr_approved").rid }, { rows, principal: operator }), null, "RequestQuery").approvalRequest;
  assert.deepEqual(approved.latestVersion.subRequests[0].reviews.map((v) => v.reviewType), ["APPROVE"]);
});

test("a decision is the daemon's own step or a refusal by name: Approve on a parked effect needs the passphrase (refused toward that effect's own approval page); its Reject is the daemon's deny with the typed reason; a governance Approve is the plane's transition and its Reject is refused (no reason kept)", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const row = (id) => rows.find((x) => x.id === id);
  const review = (id, reviewType, reason) => AX.mutationStepOf("ReviewSubRequests", row(id), { rid: row(id).rid, reviewType, reason });
  const approve = review("wac_pending", "APPROVE").refusal;
  assert.deepEqual([approve.status, approve.code], [409, AX.WRITE_REFUSALS.approveChallenge.code], "refused by name, as a 409 whose message the app prints");
  assert.match(approve.message, /operator passphrase/u);
  assert.match(approve.message, /Nothing was approved/u);
  // whoever parked the effect, its own approval page takes the passphrase: the refusal names that page for THIS challenge
  assert.match(approve.message, /Approve it on the Hypervisor's approval page for this parked effect, which takes the passphrase and hands it to the daemon: \/__ioi\/authority\/challenges\/wac_pending \(open it in the Hypervisor\)/u);
  assert.doesNotMatch(approve.message, /<its id>|no Hypervisor page approves/u, "the link is filled in, and the retired gap is not claimed");
  assert.equal(review("wac_expired", "APPROVE").refusal, AX.WRITE_REFUSALS.decided, "an expired ask is not approved anywhere: it is closed");
  assert.deepEqual(review("wac_pending", "DISAPPROVE", "not this effect").daemon, { method: "POST", route: "/v1/hypervisor/authority/challenges/wac_pending/decision", body: { decision: "deny", reason: "not this effect" } });
  assert.ok(!("operator_passphrase" in review("wac_pending", "DISAPPROVE", "x").daemon.body), "a denial carries no passphrase: the UI server holds none");
  assert.equal(review("wac_pending", "DISAPPROVE", "y".repeat(900)).daemon.body.reason.length, 400, "the reason is bounded as the daemon bounds it");
  assert.deepEqual(review("appr_pending", "APPROVE").daemon, { method: "PATCH", route: "/v1/hypervisor/governance/approval-requests/appr_pending", body: { transition: "approve" } });
  assert.ok(!("reviewer_ref" in review("appr_pending", "APPROVE").daemon.body), "the reviewer is the daemon's to name, never the body's");
  assert.equal(review("appr_pending", "DISAPPROVE", "why").refusal, AX.WRITE_REFUSALS.rejectGovernance);
  assert.equal(review("th_1/ap_1", "APPROVE").refusal, AX.WRITE_REFUSALS.toolCall);
  assert.equal(review("wac_denied", "DISAPPROVE", "again").refusal, AX.WRITE_REFUSALS.decided, "a decided request is not decided again");
  assert.equal(review("appr_approved", "APPROVE").refusal, AX.WRITE_REFUSALS.decided);
  assert.equal(AX.mutationStepOf("ReviewSubRequests", null, {}).refusal, AX.WRITE_REFUSALS.notFound);
});

test("Close, reviewers and comments: Close on an open request is refused, on one its decision closed it answers closed; inviting is refused; a comment is refused; REST writes are refused and reads are not writes", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const row = (id) => rows.find((x) => x.id === id);
  assert.equal(AX.mutationStepOf("CloseTask", row("wac_pending"), { rid: row("wac_pending").rid }).refusal, AX.WRITE_REFUSALS.close);
  assert.deepEqual(AX.mutationStepOf("CloseTask", row("wac_denied"), { rid: row("wac_denied").rid }), { answer: true }, "Reject and close: the close after a denial writes nothing");
  assert.equal(AX.mutationRidOf({ taskRid: "ri.x" }), "ri.x");
  assert.equal(AX.mutationStepOf("UpdateReviewers", row("wac_pending"), { taskRid: row("wac_pending").rid, principalIdsToAdd: [MEMBER] }).refusal, AX.WRITE_REFUSALS.write);
  const closed = answerDocument("mutation CloseTask($rid: RID!) { closeApprovalRequest(rid: $rid) { status __typename } }", AX.mutationFacts("CloseTask", row("wac_denied"), operator), null, "CloseTask");
  assert.equal(closed.closeApprovalRequest.status, "DISAPPROVED_AND_CLOSED");
  assert.equal(AX.writeRefusalOf("GET", "/approvals/api/task-requests/ri.x"), null);
  assert.equal(AX.writeRefusalOf("PUT", "/approvals/api/task-requests/ri.x/reviewers"), AX.WRITE_REFUSALS.write);
  assert.equal(AX.writeRefusalOf("POST", "/compass/api/anything"), null, "only the approvals service's writes are answered here (the fence names the rest)");
  const body = AX.refusalBodyOf(AX.WRITE_REFUSALS.comment);
  assert.deepEqual([body.errorCode, body.errorName], ["CONFLICT", "Hypervisor:ApprovalsCommentsNotKept"]);
  assert.deepEqual(AX.commentCountsOf({ resources: [{ rid: "ri.a", locator: "ri.b" }] }), { responses: { "ri.a": { rid: "ri.a", locatorCounts: { "ri.b": 0 }, totalCount: null } } });
});

test("an expired ask says so in its record, and a tool call's page names who asked, its run and the route that decides it under a grant", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const expired = rows.find((x) => x.id === "wac_expired");
  assert.equal(expired.status, "CLOSED");
  assert.match(expired.description, new RegExp(`Closed: expired at ${new Date(NOW - 1).toISOString()} with no decision; re-running the effect parks it again`, "u"));
  assert.doesNotMatch(rows.find((x) => x.id === "wac_pending").description, /Closed:/u, "an open ask is not closed");
  const tool = rows.find((x) => x.kind === "thread_approval");
  assert.deepEqual([tool.creatorRef, tool.created_at, tool.status], ["user://op", "2026-09-28T11:45:00Z", "PENDING_APPROVAL"]);
  assert.match(tool.description, /Requested by: Ada Operator/u);
  assert.match(tool.description, /Run: run_1\nThread: th_1\nApproval: ap_1\nLease: pending/u);
  assert.match(tool.description, /Decided with: POST \/v1\/threads\/th_1\/approvals\/ap_1\/decision, under a wallet grant for this lease/u);
  assert.equal(AX.searchOf({ filters: [{ type: "createdBy", createdBy: { userIds: [OP] } }, { type: "title", title: { contains: "tool call" } }] }, rows).totalCount, 1, "Created by names the tool call's requester");
  const unknownAsker = AX.requestsOf({ ...fixture(), inboxItems: [{ source_plane: "thread_approval", thread_id: "th_2", approval_id: "ap_2" }], principal: operator }).find((x) => x.kind === "thread_approval");
  assert.equal(unknownAsker.creatorRef, null, "a row the daemon names no requester for names none");
  assert.match(AX.WRITE_REFUSALS.toolCall.message, /wallet-signed grant for exactly its approval lease/u);
  assert.match(AX.WRITE_REFUSALS.toolCall.message, /Nothing was decided here/u);
  assert.doesNotMatch(AX.WRITE_REFUSALS.toolCall.message, /approval card/u, "no card decides a tool call: the refusal points nowhere false");
});

test("principals: the directory names requesters and deciders; the picker and the lookup offer only principals the daemon knows", () => {
  const principals = [{ principal_ref: "user://member", name: "Mo Member", email: "mo@ioi.local" }];
  const rows = AX.requestsOf({ ...fixture(), principal: operator, principals });
  assert.match(rows.find((x) => x.id === "appr_theirs").description, /Requested by: Mo Member/u);
  assert.match(rows.find((x) => x.id === "wac_denied").description, /Decided: deny by Ada Operator at 2026-09-28T10:30:00Z — not now/u);
  const dir = AX.directoryOf(operator, principals);
  assert.deepEqual(AX.principalsOf([MEMBER, OP, "00000000-0000-5000-8000-000000000000"], dir).map((p) => p.username), ["mo@ioi.local", "ada@ioi.local"], "an id nobody names is left out");
  assert.deepEqual(AX.principalSearchOf({ query: "mo", principalTypes: ["USER"] }, dir).values.map((v) => v.principal.id), [MEMBER]);
  assert.deepEqual(AX.principalSearchOf({ query: "", principalTypes: ["GROUP"] }, dir).values, [], "no group is named");
  const q = "query P($principalId: String!) { principal(id: $principalId) { id ... on User { displayName username permissions { isCurrentUser } } __typename } }";
  const pop = answerDocument(q, AX.approvalsGraphqlFacts("PrincipalAnchorPopoverPrincipalQuery", { principalId: MEMBER }, { rows, principal: operator, dir }), null, "P").principal;
  assert.deepEqual([pop.displayName, pop.username, pop.permissions.isCurrentUser], ["Mo Member", "mo@ioi.local", false]);
  const me = AX.approvalsGraphqlFacts("CustomIndexedDataPrincipalsFilterSearchQuery", {}, { rows, principal: operator, dir }).me;
  assert.deepEqual(me.groupsIncludingTransitive, [], "the caller belongs to no group the reference names");
});

test("the access facets offer nothing to pick where nothing is named: the project search answers none, and an unknown operation is not answered here", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const q = "query ProjectSearchQuery($query: String) { searchResourcesV2(filter: {text: $query}) { results { resource { rid name } } } }";
  assert.deepEqual(answerDocument(q, AX.approvalsGraphqlFacts("ProjectSearchQuery", { query: "pay" }, { rows, principal: operator }), null, "ProjectSearchQuery").searchResourcesV2.results, []);
  assert.equal(AX.approvalsGraphqlFacts("SomethingElseQuery", {}, { rows, principal: operator }), null, "the serve names it as an unbound operation");
});

// ---- R-240, challenge states + re-ask: a decision being recorded, an unknown outcome, an expired grant and its re-ask -----

const DECIDING = { attempt_id: "dec_1", process: "dp_live", decided_by: "user://op", started_at: "2026-09-28T11:58:00Z", child_pid: 4242 };
const UNKNOWN = { reason: "authority_record_unreadable", message: "the authority's record for this request hash could not be read (offline)", since: "2026-09-28T11:50:00Z" };
const REQ_Q = "query RequestQuery($rid: RID!) { approvalRequest(rid: $rid) { status description latestVersion { subRequests { status permissions { canFullyApprove } __typename } } } }";
const reviewOf = (rows, id, reviewType, reason) => { const r = rows.find((x) => x.id === id); return AX.mutationStepOf("ReviewSubRequests", r, { rid: r.rid, reviewType, reason }); };

test("Deciding: still Pending approval (nothing is decided) and named with who started it and when; nobody may decide it while it runs, and a decision sent anyway is refused by name without reaching the daemon", () => {
  const rows = AX.requestsOf({ ...fixture(), challenges: [challenge("wac_deciding", "pending", { deciding: DECIDING, expires_at_ms: NOW - 1 })], principal: operator });
  const r = rows.find((x) => x.id === "wac_deciding");
  assert.equal(AX.challengeStatusOf(r.record, NOW), "PENDING_APPROVAL", "an approve being recorded settles whatever the ask's window");
  assert.match(r.description, /Deciding: started 2026-09-28T11:58:00Z by Ada Operator — the deployment authority is recording the operator's approval now; nothing else can be decided until it settles \(\/__ioi\/authority\/challenges\/wac_deciding\)/u);
  const a = answerDocument(REQ_Q, AX.approvalsGraphqlFacts("RequestQuery", { rid: r.rid }, { rows, principal: operator }), null, "RequestQuery").approvalRequest;
  assert.equal(a.latestVersion.subRequests[0].permissions.canFullyApprove, false, "no decision control while it runs");
  for (const type of ["APPROVE", "DISAPPROVE"]) {
    const step = reviewOf(rows, "wac_deciding", type, "no");
    assert.ok(!step.daemon, `${type}: nothing is sent to the daemon`);
    assert.equal(step.refusal.code, "Hypervisor:ApprovalsDecisionRunning", type);
    assert.match(step.refusal.message, /already running \(started 2026-09-28T11:58:00Z by Ada Operator\)/u);
    assert.equal(step.refusal.status, 409);
  }
});

test("Outcome unknown: still Pending approval, the daemon's named reason in the description; Approve refused by that name, Reject still the daemon's deny", () => {
  const rows = AX.requestsOf({ ...fixture(), challenges: [challenge("wac_unknown", "pending", { outcome_unknown: UNKNOWN })], principal: operator });
  const r = rows.find((x) => x.id === "wac_unknown");
  assert.equal(r.status, "PENDING_APPROVAL");
  assert.match(r.description, /Outcome unknown: authority_record_unreadable — the authority's record for this request hash could not be read \(offline\)\. Approving is refused until the daemon reconciles it from the authority's record; rejecting stays open/u);
  const approve = reviewOf(rows, "wac_unknown", "APPROVE").refusal;
  assert.deepEqual([approve.status, approve.code], [409, "Hypervisor:ApprovalsApproveOutcomeUnknown"]);
  assert.match(approve.message, /outcome is not known \(authority_record_unreadable: the authority's record for this request hash could not be read \(offline\)\)/u);
  assert.deepEqual(reviewOf(rows, "wac_unknown", "DISAPPROVE", "stop").daemon, { method: "POST", route: "/v1/hypervisor/authority/challenges/wac_unknown/decision", body: { decision: "deny", reason: "stop" } }, "deny stays open");
  const a = answerDocument(REQ_Q, AX.approvalsGraphqlFacts("RequestQuery", { rid: r.rid }, { rows, principal: operator }), null, "RequestQuery").approvalRequest;
  assert.equal(a.latestVersion.subRequests[0].permissions.canFullyApprove, true, "the operator can still reject it");
});

test("an approval whose grant expired unused is Closed and says the action must be asked again, linking the successor its re-ask parked; the successor names what it supersedes; an interrupted attempt is named in the history line", () => {
  const rows = AX.requestsOf({ ...fixture(), challenges: [
    challenge("wac_old", "approved", { grant_ref: "grant://g1", grant_expires_at_ms: NOW - 1, superseded_by: "wac_new", decision: { decision: "approve", decided_by: "user://op", decided_at: "2026-09-28T09:00:00Z" } }),
    challenge("wac_lone", "approved", { grant_ref: "grant://g2", grant_expires_at_ms: NOW - 1, decision: { decision: "approve", decided_by: "user://op", decided_at: "2026-09-28T09:00:00Z" } }),
    challenge("wac_new", "pending", { supersedes: "wac_old", ask_nonce: "0f".repeat(16), history: [{ state: "interrupted", closed_at: "2026-09-28T11:40:00Z", decision: null, reconciliation: { authority_record: "absent", attempt: { decided_by: "user://op" } } }] }),
  ], principal: operator });
  const old = rows.find((x) => x.id === "wac_old"), lone = rows.find((x) => x.id === "wac_lone"), next = rows.find((x) => x.id === "wac_new");
  assert.equal(old.status, "CLOSED", "never decided again, never open");
  assert.match(old.description, new RegExp(`Grant expired: approved, but its one-use grant expired unused at ${new Date(NOW - 1).toISOString()}; the authority keeps one decision per request, so the action must be asked again — asked again: /__ioi/authority/challenges/wac_new`, "u"));
  assert.match(lone.description, /so the action must be asked again — the requester's retry parks a new challenge/u);
  assert.equal(reviewOf(rows, "wac_old", "APPROVE").refusal, AX.WRITE_REFUSALS.decided, "an expired approval is decided");
  assert.equal(next.status, "PENDING_APPROVAL");
  assert.match(next.description, /Asks again: this effect's earlier approval expired unused, and the authority never decides one request twice, so this ask binds the same effect under a fresh single-use nonce \(a new request hash\): \/__ioi\/authority\/challenges\/wac_old/u);
  assert.match(next.description, /Interrupted: 2026-09-28T11:40:00Z: the daemon stopped mid-approve \(started by Ada Operator\); the authority recorded nothing, so it was decided afresh/u);
  assert.equal(AX.challengeStatusOf(challenge("x", "approved", { grant_expires_at_ms: NOW + 1 }), NOW), "APPROVED", "a live grant stays open");
});
