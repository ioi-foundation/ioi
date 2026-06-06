import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createRuntimeWorkflowEditSurface } from "./runtime-workflow-edit-surface.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

function policyError(message, details) {
  return runtimeError({ status: 403, code: "policy", message, details });
}

function createStore() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-workflow-edit-surface-"));
  const events = [];
  const calls = [];
  const agent = {
    id: "agent_alpha",
    cwd,
    runtimeControls: { mode: "agent" },
    fixtureProfile: "fixture.local",
    runtimeSessionId: "session_alpha",
  };
  const run = {
    id: "run_alpha",
    agentId: agent.id,
    status: "running",
  };

  return {
    cwd,
    events,
    calls,
    agent,
    run,
    agentForThread(threadId) {
      assert.equal(threadId, "thread_alpha");
      return agent;
    },
    listRuns(agentId) {
      return agentId === agent.id ? [run] : [];
    },
    getRun(runId) {
      if (runId !== run.id) throw notFound(`Run not found: ${runId}`, { runId });
      return run;
    },
    appendRuntimeEvent(record) {
      const event = {
        ...record,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        payload_summary: record.payload,
      };
      events.push(event);
      return event;
    },
    requestThreadApproval(threadId, request = {}) {
      calls.push({ name: "requestThreadApproval", threadId, request });
      const event = this.appendRuntimeEvent({
        event_stream_id: `${threadId}:events`,
        thread_id: threadId,
        turn_id: request.turn_id,
        event_kind: "approval.required",
        status: "waiting_for_approval",
        approval_id: request.approval_id,
        payload: {
          approval_id: request.approval_id,
          approval_manifest: request.approval_manifest,
        },
        receipt_refs: ["receipt_approval_required"],
        policy_decision_refs: request.policy_decision_refs ?? [],
      });
      return {
        approval_id: request.approval_id,
        event_id: event.event_id,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    },
    latestApprovalRequestEvent(threadId, approvalId) {
      return events
        .filter(
          (event) =>
            event.thread_id === threadId &&
            event.approval_id === approvalId &&
            event.event_kind === "approval.required",
        )
        .at(-1) ?? null;
    },
    runtimeEventStream() {
      return { events };
    },
    approve(approvalId) {
      return this.appendRuntimeEvent({
        event_stream_id: "thread_alpha:events",
        thread_id: "thread_alpha",
        turn_id: "turn_alpha",
        event_kind: "approval.approved",
        status: "approved",
        approval_id: approvalId,
        payload: {
          reason: "approved",
        },
        receipt_refs: ["receipt_approval_approved"],
        policy_decision_refs: ["policy_approval_approved"],
      });
    },
  };
}

function createSurface() {
  return createRuntimeWorkflowEditSurface({
    approvalReasonForDecisionEvent(event) {
      return event?.payload_summary?.reason ?? "approval_not_satisfied";
    },
    notFound,
    policyError,
    runtimeError,
  });
}

test("workflow-edit surface proposes workflow edits with approval manifest aliases", () => {
  const store = createStore();
  const surface = createSurface();

  const result = surface.proposeWorkflowEdit(store, "thread_alpha", {
    source: "agent_studio",
    proposal_id: "proposal_one",
    edit_intent_id: "intent_one",
    approval_id: "approval_one",
    title: "Change workflow",
    summary: "Update workflow step",
    workflow_path: "workflows/demo.json",
    workflow_patch: { nodes: [{ id: "node_1" }] },
    target_workflow_node_ids: ["node_1"],
    bounded_targets: ["node_2", "node_1"],
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
  });
  const proposalEvent = store.events[0];
  const approvalRequest = store.calls[0].request;

  assert.equal(result.status, "waiting_for_approval");
  assert.equal(result.proposal_id, "proposal_one");
  assert.equal(result.approval_id, "approval_one");
  assert.equal(result.workflow_relative_path, "workflows/demo.json");
  assert.equal(result.event_id, "event_1");
  assert.equal(result.approval_event_id, "event_2");
  assert.deepEqual(result.receipt_refs, [
    "receipt_request",
    "receipt_run_alpha_workflow_edit_proposed_proposal_one",
    "receipt_approval_required",
  ]);
  assert.equal(proposalEvent.event_kind, "workflow.edit_proposed");
  assert.equal(proposalEvent.source_event_kind, "WorkflowEdit.Proposed");
  assert.equal(proposalEvent.fixture_profile, "fixture.local");
  assert.equal(proposalEvent.payload_summary.session_id, "session_alpha");
  assert.deepEqual(proposalEvent.payload_summary.targetWorkflowNodeIds, ["node_1", "node_2"]);
  assert.equal(approvalRequest.action, "workflow.edit.apply");
  assert.equal(approvalRequest.approval_manifest.proposalId, "proposal_one");
  assert.equal(approvalRequest.approval_manifest.mutationAllowed, false);
  assert.deepEqual(approvalRequest.authority_scope_requirements, ["workflow.edit.apply"]);
  assert.equal(surface.latestWorkflowEditProposalEvent(store, "thread_alpha", "proposal_one"), proposalEvent);
});

test("workflow-edit surface ignores retired request identity aliases", () => {
  const store = createStore();
  const surface = createSurface();

  const proposal = surface.proposeWorkflowEdit(store, "thread_alpha", {
    proposal_id: "proposal_retired_aliases",
    approval_id: "approval_retired_aliases",
    workflow_path: "workflows/canonical.json",
    workflow_patch: { ok: "canonical" },
    requestedBy: "operator_retired",
    workflowPath: "workflows/retired.json",
    workflowPatch: { ok: true },
    codeDiff: "diff_retired",
    editIntentId: "intent_retired",
    proposalId: "proposal_retired",
    approvalId: "approval_retired",
    turnId: "turn_retired",
    workflowGraphId: "graph_retired",
    workflowNodeId: "node_retired",
    targetWorkflowNodeIds: ["node_target_retired"],
    boundedTargets: ["node_bound_retired"],
    idempotencyKey: "workflow_edit_idempotency_retired",
    receiptRefs: ["receipt_retired"],
    policyDecisionRefs: ["policy_retired"],
  });
  const proposalEvent = store.events[0];
  const approvalRequest = store.calls[0].request;

  assert.equal(proposalEvent.turn_id, "turn_alpha");
  assert.equal(proposalEvent.workflow_graph_id, null);
  assert.equal(proposalEvent.workflow_node_id, "runtime.workflow-edit-proposal.proposal_retired_aliases");
  assert.equal(
    proposalEvent.idempotency_key,
    "thread:thread_alpha:workflow.edit.proposed:proposal_retired_aliases",
  );
  assert.deepEqual(proposalEvent.payload_summary.target_workflow_node_ids, []);
  assert.equal(proposalEvent.payload_summary.requested_by, "workflow-author");
  assert.equal(proposalEvent.payload_summary.workflow_relative_path, "workflows/canonical.json");
  assert.deepEqual(proposalEvent.payload_summary.workflow_patch, { ok: "canonical" });
  assert.equal(proposalEvent.payload_summary.code_diff, null);
  assert.equal(proposalEvent.payload_summary.edit_intent_id, proposal.edit_intent_id);
  assert.notEqual(proposalEvent.payload_summary.edit_intent_id, "intent_retired");
  assert.equal(proposal.proposal_id, "proposal_retired_aliases");
  assert.equal(proposal.approval_id, "approval_retired_aliases");
  assert.equal(proposal.receipt_refs.includes("receipt_retired"), false);
  assert.equal(proposal.policy_decision_refs.includes("policy_retired"), false);
  assert.equal(approvalRequest.turn_id, "turn_alpha");
  assert.equal(approvalRequest.workflow_graph_id, null);
  assert.equal(approvalRequest.workflow_node_id, "runtime.workflow-edit-proposal.proposal_retired_aliases");
  assert.equal(approvalRequest.receipt_refs.includes("receipt_retired"), false);
  assert.equal(approvalRequest.policy_decision_refs.includes("policy_retired"), false);
  assert.equal(approvalRequest.approval_id, "approval_retired_aliases");
  for (const field of ["turnId", "workflowGraphId", "workflowNodeId", "receiptRefs", "policyDecisionRefs"]) {
    assert.equal(Object.hasOwn(approvalRequest, field), false);
  }

  store.approve(proposal.approval_id);
  const applied = surface.applyWorkflowEditProposal(store, "thread_alpha", proposal.proposal_id, {
    requestedBy: "operator_apply_retired",
    proposalId: "proposal_apply_retired",
    approvalId: "approval_apply_retired",
    workflowGraphId: "graph_apply_retired",
    workflowNodeId: "node_apply_retired",
    idempotencyKey: "workflow_edit_apply_idempotency_retired",
  });

  assert.equal(applied.event.workflow_graph_id, null);
  assert.equal(applied.event.workflow_node_id, "runtime.workflow-edit-proposal.proposal_retired_aliases");
  assert.equal(
    applied.event.idempotency_key,
    "thread:thread_alpha:workflow.edit.applied:proposal_retired_aliases:approval_retired_aliases",
  );
  assert.equal(applied.event.payload_summary.requested_by, "workflow-author");
  assert.equal(applied.event.payload_summary.approval_id, "approval_retired_aliases");
});

test("workflow-edit surface accepts canonical idempotency keys", () => {
  const store = createStore();
  const surface = createSurface();

  const proposal = surface.proposeWorkflowEdit(store, "thread_alpha", {
    proposal_id: "proposal_canonical_idempotency",
    approval_id: "approval_canonical_idempotency",
    workflow_path: "workflows/canonical.json",
    workflow_patch: { ok: true },
    idempotency_key: "workflow_edit_idempotency_canonical",
  });
  store.approve(proposal.approval_id);
  const applied = surface.applyWorkflowEditProposal(store, "thread_alpha", proposal.proposal_id, {
    idempotency_key: "workflow_edit_apply_idempotency_canonical",
  });

  assert.equal(store.events[0].idempotency_key, "workflow_edit_idempotency_canonical");
  assert.equal(applied.event.idempotency_key, "workflow_edit_apply_idempotency_canonical");
});

test("workflow-edit surface blocks apply until proposal approval is satisfied", () => {
  const store = createStore();
  const surface = createSurface();
  const proposal = surface.proposeWorkflowEdit(store, "thread_alpha", {
    proposal_id: "proposal_blocked",
    approval_id: "approval_blocked",
    workflow_path: "workflows/blocked.json",
    workflow_patch: { ok: true },
  });

  const result = surface.applyWorkflowEditProposal(store, "thread_alpha", proposal.proposal_id, {});

  assert.equal(result.status, "blocked");
  assert.equal(result.approval_required, true);
  assert.equal(result.approval_satisfied, false);
  assert.equal(result.mutation_executed, false);
  assert.equal(result.reason, "approval_decision_missing");
  assert.equal(result.error.code, "workflow_edit_approval_required");
});

test("workflow-edit surface applies approved proposals and replays idempotently", () => {
  const store = createStore();
  const surface = createSurface();
  const proposal = surface.proposeWorkflowEdit(store, "thread_alpha", {
    proposal_id: "proposal_apply",
    approval_id: "approval_apply",
    workflow_path: "workflows/apply.json",
    workflow_patch: { name: "applied", nodes: [{ id: "node_apply" }] },
  });
  store.approve(proposal.approval_id);

  const result = surface.applyWorkflowEditProposal(store, "thread_alpha", proposal.proposal_id, {
    source: "agent_studio",
    actor: "operator_one",
  });
  const replay = surface.applyWorkflowEditProposal(store, "thread_alpha", proposal.proposal_id, {});
  const written = JSON.parse(fs.readFileSync(path.join(store.cwd, "workflows/apply.json"), "utf8"));

  assert.equal(result.status, "completed");
  assert.equal(result.approval_satisfied, true);
  assert.equal(result.mutation_allowed, true);
  assert.equal(result.mutation_executed, true);
  assert.equal(result.idempotent_replay, false);
  assert.equal(result.event.event_kind, "workflow.edit_applied");
  assert.equal(result.event.payload_summary.approvalDecisionEventId, "event_3");
  assert.equal(result.event.payload_summary.workflowRelativePath, "workflows/apply.json");
  assert.deepEqual(written, { name: "applied", nodes: [{ id: "node_apply" }] });
  assert.equal(replay.status, "completed");
  assert.equal(replay.idempotent_replay, true);
  assert.equal(replay.event, result.event);
  assert.equal(store.events.filter((event) => event.event_kind === "workflow.edit_applied").length, 1);
});

test("workflow-edit surface enforces workspace boundaries and required proposal ids", () => {
  const store = createStore();
  const surface = createSurface();

  assert.throws(
    () => surface.proposeWorkflowEdit(store, "thread_alpha", { workflow_path: "../outside.json" }),
    (error) =>
      error.status === 403 &&
      error.code === "policy" &&
      error.details.workspaceRoot === store.cwd,
  );
  assert.throws(
    () => surface.applyWorkflowEditProposal(store, "thread_alpha", null, {}),
    (error) =>
      error.status === 400 &&
      error.code === "workflow_edit_proposal_id_required" &&
      error.details.threadId === "thread_alpha",
  );
  assert.throws(
    () => surface.applyWorkflowEditProposal(store, "thread_alpha", "missing", {}),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.proposalId === "missing",
  );
});
