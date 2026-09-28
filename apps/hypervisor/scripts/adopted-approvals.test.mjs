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
    challenge("wac_expired", "pending", { expires_at_ms: NOW - 1, created_at: "2026-09-27T08:00:00Z" }), challenge("wac_consumed", "consumed", { decision: { decision: "approve", decided_by: "user://op", decided_at: "2026-09-28T07:00:00Z" }, consumed_by: "authority-admission-intents/x", created_at: "2026-09-28T06:00:00Z" })],
  governance: [gov("appr_pending", "pending"), gov("appr_approved", "approved"), gov("appr_rejected", "rejected"), gov("appr_theirs", "pending", { created_by_principal_ref: "user://member", created_at: "2026-09-28T11:00:00Z" })],
  inboxItems: [{ source_plane: "thread_approval", thread_id: "th_1", approval_id: "ap_1", run_id: "run_1", subject_ref: "run_1", reason: "write to /etc", status: "pending", created_at: "2026-09-28T11:45:00Z" },
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
  assert.deepEqual(AX.countsOf(countsRequest(OP), rows), { totalCount: 9, subCounts: { all: 9, myRequests: 7, reviewRequests: 4 } });
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
  assert.deepEqual([sub.status, sub.permissions.canFullyApprove, sub.reviews.length], ["PENDING", true, 0], "the operator may decide it (the decision itself is the approval card's)");
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

test("a decision is the daemon's own step or a refusal by name: Approve on a parked effect needs the passphrase (refused toward the approval card); its Reject is the daemon's deny with the typed reason; a governance Approve is the plane's transition and its Reject is refused (no reason kept)", () => {
  const rows = AX.requestsOf({ ...fixture(), principal: operator });
  const row = (id) => rows.find((x) => x.id === id);
  const review = (id, reviewType, reason) => AX.mutationStepOf("ReviewSubRequests", row(id), { rid: row(id).rid, reviewType, reason });
  assert.equal(review("wac_pending", "APPROVE").refusal, AX.WRITE_REFUSALS.approveChallenge);
  assert.match(AX.WRITE_REFUSALS.approveChallenge.message, /operator passphrase/u);
  assert.match(AX.WRITE_REFUSALS.approveChallenge.message, /Nothing was approved/u);
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
