// Existing-agent Authority Gateway acceptance journey over the Rust workflow-edit route:
// audit-only adapter attach + exact proposal attribution -> exact-action review -> retained,
// expiring, revocable, one-shot sovereign-local AuthorityGrant -> final invoker -> effect receipt
// -> WorkResult -> OutcomeDelta. Coverage remains route-scoped and explicitly disclaims opaque
// direct filesystem writes; this test never treats the journey as universal interception.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let workspaceDir;
let workflowPath;

const initialWorkflow = {
  version: "1",
  metadata: { id: "workflow.react-flow.edit-proposal-proof", name: "Proposal proof" },
  nodes: [{ id: "model", type: "model_call", name: "Model" }],
  edges: [],
};

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-wfe-appr-state-"));
  workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-wfe-appr-ws-"));
  workflowPath = path.join(workspaceDir, "proposal-proof.workflow.json");
  fs.writeFileSync(workflowPath, `${JSON.stringify(initialWorkflow, null, 2)}\n`);
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  for (const dir of [stateDir, workspaceDir]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
});

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return { status: response.status, body: await response.json() };
}

async function createThread() {
  const r = await post(`${daemon.endpoint}/v1/threads`, { options: { local: { cwd: workspaceDir } } });
  assert.equal(r.status, 200);
  return r.body.thread_id || r.body.id;
}

function workflowName() {
  return JSON.parse(fs.readFileSync(workflowPath, "utf8")).metadata.name;
}

function records(family) {
  const directory = path.join(stateDir, family);
  if (!fs.existsSync(directory)) return [];
  return fs
    .readdirSync(directory)
    .filter((entry) => entry.endsWith(".json"))
    .map((entry) => JSON.parse(fs.readFileSync(path.join(directory, entry), "utf8")));
}

async function propose(threadId, proposalId, name) {
  return post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    source: "existing_agent_adapter",
    goal_ref: `goal://authority-gateway-${proposalId}`,
    authority_gateway: {
      adapter_ref: "agent-harness-adapter://external/coding-agent/workflow-edit/v1",
      adapter_version: "1.0.0",
      profile_ref: "authority-gateway-profile://hypervisor/workflow-edit/v1",
      profile_version: "1.0.0",
    },
    workflow_graph_id: initialWorkflow.metadata.id,
    workflow_node_id: "runtime.workflow-edit-proposal.model",
    proposal_id: proposalId,
    workflow_path: workflowPath,
    workflow_patch: { ...initialWorkflow, metadata: { ...initialWorkflow.metadata, name } },
  });
}

function exactApplyBody(proposed, approved) {
  return {
    expected_effect_hash: proposed.body.exact_action_review.effect_hash,
    authority_grant_ref: approved.body.authority_grant_ref,
  };
}

test("Rust workflow-edit rejected proposal stays blocked and never mutates the file", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-rejected", "Rejected edit");
  assert.equal(proposed.body.status, "waiting_for_approval", JSON.stringify(proposed));
  assert.equal(proposed.body.enforcement_coverage.operating_mode, "audit_only");
  assert.equal(proposed.body.enforcement_coverage.claims.attributable, true);
  assert.equal(proposed.body.enforcement_coverage.claims.mediated, false);
  assert.equal(proposed.body.enforcement_coverage.claims.preventable, false);
  assert.equal(proposed.body.enforcement_coverage.custom_os_kernel_module_required_for_claim, false);
  assert.equal(
    proposed.body.enforcement_coverage_retention.operability.currentness,
    "unverified",
  );
  assert.equal(
    proposed.body.enforcement_coverage_retention.registry_durability,
    "boot_scoped_not_restored",
  );
  assert.match(
    proposed.body.observation_receipt.receipt_ref,
    /^receipt:\/\/hypervisor\/authority-gateway-observation\//,
  );
  assert.equal(
    proposed.body.enforcement_coverage_artifact_ref,
    `artifact://hypervisor/enforcement-coverage/${proposed.body.enforcement_coverage_hash.slice("sha256:".length)}`,
  );
  assert.ok(
    records("authority-receipts").some(
      (receipt) => receipt.receipt_ref === proposed.body.observation_receipt.receipt_ref,
    ),
    "audit observation receipt is retained, not merely projected",
  );
  const approvalId = proposed.body.approval_id;

  // Apply before any decision is recorded -> blocked, even with client-asserted approval flags.
  const directApply = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-rejected/apply`,
    { approved: true, approvalGranted: true, approvalMode: "never_prompt" },
  );
  assert.equal(directApply.body.status, "blocked");
  assert.equal(directApply.body.mutation_executed, false);
  assert.equal(workflowName(), "Proposal proof");

  // Reject the proposal, then apply -> blocked with reason approval_rejected, still no mutation.
  const rejected = await post(`${daemon.endpoint}/v1/threads/${threadId}/approvals/${approvalId}/reject`, {
    reason: "Reject the proposal to prove no workflow mutation occurs.",
  });
  assert.equal(rejected.body.decision, "reject");
  const rejectedApply = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-rejected/apply`,
    { approvalId },
  );
  assert.equal(rejectedApply.body.status, "blocked");
  assert.equal(rejectedApply.body.reason, "approval_rejected");
  assert.equal(rejectedApply.body.mutation_executed, false);
  assert.equal(workflowName(), "Proposal proof");
});

test("Rust workflow-edit approved proposal mutates the file and replays idempotently", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-approved", "Approved edit");
  assert.equal(proposed.body.status, "waiting_for_approval", JSON.stringify(proposed));
  const approvalId = proposed.body.approval_id;

  const approved = await post(`${daemon.endpoint}/v1/threads/${threadId}/approvals/${approvalId}/approve`, {
    reason: "Approve bounded workflow metadata edit.",
    expected_effect_hash: proposed.body.exact_action_review.effect_hash,
    expiry_seconds: 120,
  });
  assert.equal(approved.body.decision, "approve");
  assert.equal(approved.body.authority_lane, "sovereign_local");
  assert.match(approved.body.authority_grant_ref, /^grant:\/\/authority\.local\//);
  assert.equal(approved.body.authority_grant.max_usages, 1);
  assert.equal(approved.body.portable_authority_alternative.kind, "CapabilityLease");
  assert.equal(approved.body.portable_authority_alternative.selected, false);
  assert.equal(workflowName(), "Proposal proof", "approval alone does not mutate");

  const applyUrl = `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-approved/apply`;
  const applyBody = exactApplyBody(proposed, approved);
  const applied = await post(applyUrl, applyBody);
  assert.equal(applied.body.status, "completed");
  assert.equal(applied.body.mutation_executed, true);
  assert.equal(applied.body.idempotent_replay, false);
  assert.equal(applied.body.event.event_kind, "workflow.edit.apply");
  assert.equal(applied.body.final_invoker_calls, 1);
  assert.equal(applied.body.effect_receipt.effect_hash, proposed.body.exact_action_review.effect_hash);
  assert.equal(
    applied.body.effect_receipt.final_invoker_ref,
    "runtime://hypervisor-daemon/workflow-edit-final-invoker",
  );
  assert.equal(applied.body.effect_receipt.authority_grant_ref, approved.body.authority_grant_ref);
  assert.match(applied.body.work_result.work_result_id, /^work-result:\/\//);
  assert.match(applied.body.outcome_delta.outcome_delta_id, /^outcome-delta:\/\//);
  assert.equal(applied.body.outcome_delta.proposed_by_ref, applied.body.work_result.work_result_id);
  assert.equal(applied.body.lineage.effect_receipt_ref, applied.body.effect_receipt.receipt_ref);
  assert.equal(applied.body.lineage.work_result_ref, applied.body.work_result.work_result_id);
  assert.equal(applied.body.lineage.outcome_delta_ref, applied.body.outcome_delta.outcome_delta_id);
  assert.equal(applied.body.enforcement_coverage.operating_mode, "active_enforcement");
  assert.equal(applied.body.enforcement_coverage.claims.mediated, true);
  assert.equal(applied.body.enforcement_coverage.claims.preventable, true);
  assert.equal(applied.body.enforcement_coverage.bypass.resistance, "cooperative");
  assert.equal(
    applied.body.enforcement_coverage_retention.operability.currentness,
    "unverified",
  );
  assert.equal(
    applied.body.enforcement_coverage_retention.registry_durability,
    "boot_scoped_not_restored",
  );
  assert.equal(
    applied.body.enforcement_coverage_artifact_ref,
    `artifact://hypervisor/enforcement-coverage/${applied.body.enforcement_coverage_hash.slice("sha256:".length)}`,
  );
  assert.ok(
    applied.body.enforcement_coverage.limitations.some((line) => line.includes("no endpoint-wide or universal")),
  );
  assert.equal(workflowName(), "Approved edit", "apply mutates the workflow file");
  const retainedGrant = records("authority-grants").find(
    (grant) => grant.grant_ref === approved.body.authority_grant_ref,
  );
  assert.equal(retainedGrant.consumption_state, "consumed");
  assert.equal(retainedGrant.uses, 1);
  assert.ok(
    records("authority-receipts").some(
      (receipt) => receipt.receipt_ref === applied.body.effect_receipt.receipt_ref,
    ),
  );
  assert.ok(
    records("work-result-registry").some(
      (result) => result.work_result_id === applied.body.work_result.work_result_id,
    ),
  );
  assert.ok(
    records("outcome-delta-registry").some(
      (delta) => delta.outcome_delta_id === applied.body.outcome_delta.outcome_delta_id,
    ),
  );

  // Re-apply -> idempotent replay (same admitted event, no re-mutation).
  const replay = await post(applyUrl, applyBody);
  assert.equal(replay.body.status, "completed");
  assert.equal(replay.body.idempotent_replay, true);
  assert.equal(replay.body.final_invoker_calls, 0);
  assert.equal(replay.body.event.event_id, applied.body.event.event_id);
  assert.equal(workflowName(), "Approved edit");

  // Both lifecycle events are on the thread stream.
  const events = await (
    await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events`, { headers: { accept: "text/event-stream" } })
  ).text();
  assert.ok(events.includes("workflow.edit_proposed"));
  assert.ok(events.includes("workflow.edit.apply"));
});

test("Rust workflow-edit concurrent approvals converge on one exact-action grant", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-concurrent-approval", "Concurrent edit");
  const approvalUrl = `${daemon.endpoint}/v1/threads/${threadId}/approvals/${proposed.body.approval_id}/approve`;
  const approvalBody = {
    reason: "Concurrent exact-action review convergence proof.",
    expected_effect_hash: proposed.body.exact_action_review.effect_hash,
    expiry_seconds: 120,
  };

  const approvals = await Promise.all(
    Array.from({ length: 8 }, () => post(approvalUrl, approvalBody)),
  );
  assert.ok(
    approvals.every((approval) => approval.status === 200),
    JSON.stringify(approvals),
  );
  assert.ok(approvals.every((approval) => approval.body.decision === "approve"));
  const grantRefs = new Set(
    approvals.map((approval) => approval.body.authority_grant_ref),
  );
  assert.equal(grantRefs.size, 1, "all concurrent clients receive the same grant identity");
  const [grantRef] = grantRefs;
  assert.equal(
    records("authority-grants").filter((grant) => grant.grant_ref === grantRef).length,
    1,
    "one proposal retains exactly one exact-action grant",
  );
  assert.equal(workflowName(), "Proposal proof", "approval convergence never invokes the effect");
});

test("Rust workflow-edit refuses effect body and target substitution before the final invoker", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-substitution", "Reviewed edit");
  const approved = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/approvals/${proposed.body.approval_id}/approve`,
    {
      expected_effect_hash: proposed.body.exact_action_review.effect_hash,
      expiry_seconds: 120,
    },
  );
  const applyUrl = `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-substitution/apply`;
  const exact = exactApplyBody(proposed, approved);

  const effectSwap = await post(applyUrl, {
    ...exact,
    expected_effect_hash: `sha256:${"0".repeat(64)}`,
  });
  assert.equal(effectSwap.status, 400);
  assert.match(effectSwap.body.error.message, /body_substitution_refused/);

  const bodySwap = await post(applyUrl, {
    ...exact,
    workflow_patch: { ...initialWorkflow, metadata: { ...initialWorkflow.metadata, name: "Injected edit" } },
  });
  assert.equal(bodySwap.status, 400);
  assert.match(bodySwap.body.error.message, /body_substitution_refused/);

  const otherPath = path.join(workspaceDir, "other.workflow.json");
  fs.writeFileSync(otherPath, `${JSON.stringify(initialWorkflow, null, 2)}\n`);
  const targetSwap = await post(applyUrl, { ...exact, workflow_path: otherPath });
  assert.equal(targetSwap.status, 400);
  assert.match(targetSwap.body.error.message, /target_substitution_refused/);
  assert.equal(workflowName(), "Proposal proof");
  assert.deepEqual(JSON.parse(fs.readFileSync(otherPath, "utf8")), initialWorkflow);
});

test("Rust workflow-edit final invoker refuses an expired exact-action grant", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-expired", "Expired edit");
  const approved = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/approvals/${proposed.body.approval_id}/approve`,
    { expected_effect_hash: proposed.body.exact_action_review.effect_hash, expiry_seconds: 1 },
  );
  await new Promise((resolve) => setTimeout(resolve, 1_200));
  const applied = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-expired/apply`,
    exactApplyBody(proposed, approved),
  );
  assert.equal(applied.body.status, "blocked");
  assert.equal(applied.body.reason, "authority_grant_expired");
  assert.equal(applied.body.final_invoker_calls, 0);
  assert.equal(workflowName(), "Proposal proof");
});

test("Rust workflow-edit final invoker refuses a revoked exact-action grant", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-revoked", "Revoked edit");
  const approved = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/approvals/${proposed.body.approval_id}/approve`,
    { expected_effect_hash: proposed.body.exact_action_review.effect_hash, expiry_seconds: 120 },
  );
  const revoked = await post(`${daemon.endpoint}/v1/hypervisor/authority/revoke`, {
    grant_ref: approved.body.authority_grant_ref,
    reason: "acceptance-test revoke before final invocation",
  });
  assert.equal(revoked.body.status, "revoked");
  const applied = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-revoked/apply`,
    exactApplyBody(proposed, approved),
  );
  assert.equal(applied.body.status, "blocked");
  assert.equal(applied.body.reason, "authority_grant_revoked");
  assert.equal(applied.body.final_invoker_calls, 0);
  assert.equal(workflowName(), "Proposal proof");
});

test("Rust workflow-edit apply fails closed for an unknown thread (404)", async () => {
  const r = await post(
    `${daemon.endpoint}/v1/threads/thread_missing/workflow-edit-proposals/proposal-x/apply`,
    { approvalId: "approval_x" },
  );
  assert.equal(r.status, 404);
});
