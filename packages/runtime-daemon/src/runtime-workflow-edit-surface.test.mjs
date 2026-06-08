import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeWorkflowEditSurface } from "./runtime-workflow-edit-surface.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function createStore() {
  const events = [];
  const calls = [];
  return {
    events,
    calls,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      throw new Error("agentForThread must not be called by the retired workflow-edit JS facade");
    },
    listRuns(agentId) {
      calls.push({ name: "listRuns", agentId });
      throw new Error("listRuns must not be called by the retired workflow-edit JS facade");
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      throw new Error("getRun must not be called by the retired workflow-edit JS facade");
    },
    appendRuntimeEvent(event) {
      calls.push({ name: "appendRuntimeEvent", event });
      throw new Error(`appendRuntimeEvent must not be called by the retired workflow-edit JS facade: ${event?.event_kind}`);
    },
    requestThreadApproval(threadId, request) {
      calls.push({ name: "requestThreadApproval", threadId, request });
      throw new Error("requestThreadApproval must not be called by the retired workflow-edit JS facade");
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
  };
}

function createSurface() {
  return createRuntimeWorkflowEditSurface({
    runtimeError,
  });
}

function assertNoRetiredWorkflowEditDetailAliases(details) {
  for (const field of [
    "threadId",
    "turnId",
    "proposalId",
    "editIntentId",
    "approvalId",
    "workflowGraphId",
    "workflowNodeId",
    "workflowPath",
    "agentId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details, field), false, `${field} detail alias must be absent`);
  }
}

test("workflow-edit proposal facade fails closed before JS event append or approval persistence", () => {
  const store = createStore();
  const surface = createSurface();

  assert.throws(
    () => surface.proposeWorkflowEdit(store, "thread_alpha", {
      source: "agent_studio",
      turn_id: "turn_alpha",
      proposal_id: "proposal_one",
      edit_intent_id: "intent_one",
      approval_id: "approval_one",
      workflow_graph_id: "graph_one",
      workflow_node_id: "node_one",
      workflow_path: "workflows/demo.json",
      workflow_patch: { nodes: [{ id: "node_1" }] },
      target_workflow_node_ids: ["node_1"],
      receipt_refs: ["receipt_request"],
      policy_decision_refs: ["policy_request"],
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workflow_edit_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workflow_edit");
      assert.equal(error.details.operation, "workflow_edit_proposal");
      assert.equal(error.details.operation_kind, "workflow.edit_proposed");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.turn_id, "turn_alpha");
      assert.equal(error.details.proposal_id, "proposal_one");
      assert.equal(error.details.edit_intent_id, "intent_one");
      assert.equal(error.details.approval_id, "approval_one");
      assert.equal(error.details.workflow_graph_id, "graph_one");
      assert.equal(error.details.workflow_node_id, "node_one");
      assert.equal(error.details.workflow_path, "workflows/demo.json");
      assert.equal(error.details.source, "agent_studio");
      assert.deepEqual(error.details.evidence_refs, [
        "workflow_edit_proposal_js_facade_retired",
        "rust_daemon_core_workflow_edit_proposal_required",
        "agentgres_workflow_edit_proposal_truth_required",
      ]);
      assertNoRetiredWorkflowEditDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.calls, []);
});

test("workflow-edit apply facade fails closed before JS proposal lookup or mutation replay", () => {
  const store = createStore();
  const surface = createSurface();

  assert.throws(
    () => surface.applyWorkflowEditProposal(store, "thread_alpha", "proposal_one", {
      source: "agent_studio",
      approval_id: "approval_one",
      workflow_graph_id: "graph_one",
      workflow_node_id: "node_one",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workflow_edit_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workflow_edit");
      assert.equal(error.details.operation, "workflow_edit_apply");
      assert.equal(error.details.operation_kind, "workflow.edit.apply");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.proposal_id, "proposal_one");
      assert.equal(error.details.approval_id, "approval_one");
      assert.equal(error.details.workflow_graph_id, "graph_one");
      assert.equal(error.details.workflow_node_id, "node_one");
      assert.equal(error.details.source, "agent_studio");
      assert.deepEqual(error.details.evidence_refs, [
        "workflow_edit_apply_js_facade_retired",
        "rust_daemon_core_workflow_edit_apply_required",
        "agentgres_workflow_edit_apply_truth_required",
      ]);
      assertNoRetiredWorkflowEditDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.calls, []);
});

test("workflow-edit target/context facades fail closed before JS agent or workspace resolution", () => {
  const store = createStore();
  const surface = createSurface();

  assert.throws(
    () => surface.workflowEditThreadContext(store, "thread_alpha", { turn_id: "turn_alpha" }),
    (error) => {
      assert.equal(error.code, "runtime_workflow_edit_rust_core_required");
      assert.equal(error.details.operation, "workflow_edit_thread_context");
      assert.equal(error.details.operation_kind, "workflow.edit.context");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.turn_id, "turn_alpha");
      assertNoRetiredWorkflowEditDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () => surface.resolveWorkflowEditTarget({ id: "agent_alpha", cwd: "/workspace" }, { workflow_path: "workflow.json" }),
    (error) => {
      assert.equal(error.code, "runtime_workflow_edit_rust_core_required");
      assert.equal(error.details.operation, "workflow_edit_target_resolution");
      assert.equal(error.details.operation_kind, "workflow.edit.target.resolve");
      assert.equal(error.details.agent_id, "agent_alpha");
      assert.equal(error.details.workflow_path, "workflow.json");
      assertNoRetiredWorkflowEditDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.calls, []);
});

test("workflow-edit apply still validates canonical proposal id before the Rust-core boundary", () => {
  const surface = createSurface();

  assert.throws(
    () => surface.applyWorkflowEditProposal(createStore(), "thread_alpha", null, {}),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "workflow_edit_proposal_id_required");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(Object.hasOwn(error.details, "threadId"), false);
      return true;
    },
  );
});

test("workflow-edit read helper facades are retired with the JS apply path", () => {
  const surface = createSurface();

  assert.equal(Object.hasOwn(surface, "latestWorkflowEditProposalEvent"), false);
  assert.equal(Object.hasOwn(surface, "workflowEditApprovalSatisfaction"), false);
});
