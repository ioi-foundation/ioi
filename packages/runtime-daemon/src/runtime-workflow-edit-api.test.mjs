import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeWorkflowEditApi } from "./runtime-workflow-edit-api.mjs";

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
      throw new Error("agentForThread must not be called by the Rust-owned workflow-edit API");
    },
    listRuns(agentId) {
      calls.push({ name: "listRuns", agentId });
      throw new Error("listRuns must not be called by the Rust-owned workflow-edit API");
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      throw new Error("getRun must not be called by the Rust-owned workflow-edit API");
    },
    appendRuntimeEvent(event) {
      calls.push({ name: "appendRuntimeEvent", event });
      const admitted = {
        ...event,
        admitted: true,
        seq: events.length + 1,
      };
      events.push(admitted);
      return admitted;
    },
    requestThreadApproval(threadId, request) {
      calls.push({ name: "requestThreadApproval", threadId, request });
      throw new Error("requestThreadApproval must not be called by the Rust-owned workflow-edit API");
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

function createWorkflowEditCore(calls = []) {
  return {
    planRuntimeWorkflowEditControl(request) {
      calls.push({ name: "planRuntimeWorkflowEditControl", request });
      const isApply = request.operation_kind === "workflow.edit.apply";
      const proposalId = request.proposal_id ?? "proposal_planned";
      return {
        source: "rust_runtime_workflow_edit_control_api",
        backend: "rust_policy",
        object: "ioi.runtime_workflow_edit_control",
        status: "planned",
        operation: request.operation,
        operation_kind: request.operation_kind,
        thread_id: request.thread_id,
        proposal_id: proposalId,
        control_status: isApply ? "applied" : "pending_approval",
        event: {
          event_stream_id: request.event_stream_id,
          thread_id: request.thread_id,
          turn_id: request.turn_id ?? "",
          item_id: `${request.thread_id}:item:workflow_edit:${proposalId}`,
          idempotency_key: `thread:${request.thread_id}:${request.operation_kind}:${proposalId}`,
          source: request.source ?? "agent_studio",
          source_event_kind: isApply ? "WorkflowEdit.Apply" : "WorkflowEdit.Proposed",
          event_kind: request.operation_kind,
          status: isApply ? "applied" : "pending_approval",
          component_kind: "workflow_edit",
          workflow_graph_id: request.workflow_graph_id ?? null,
          workflow_node_id: request.workflow_node_id ?? "runtime.workflow_edit",
          payload_schema_version: "ioi.runtime.workflow-edit-control.v1",
          payload: {
            proposal_id: proposalId,
            workflow_path: request.workflow_path ?? null,
          },
          receipt_refs: ["receipt_workflow_edit"],
          policy_decision_refs: ["policy_workflow_edit"],
          evidence_refs: request.evidence_refs,
        },
        receipt_refs: ["receipt_workflow_edit"],
        policy_decision_refs: ["policy_workflow_edit"],
        evidence_refs: request.evidence_refs,
      };
    },
  };
}

function createSurface({ contextPolicyCore = null } = {}) {
  return createRuntimeWorkflowEditApi({
    contextPolicyCore,
    eventStreamIdForThread: (threadId) => `event_stream_${threadId}`,
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

test("workflow-edit proposal uses Rust planning and runtime event admission", () => {
  const runnerCalls = [];
  const store = createStore();
  const surface = createSurface({
    contextPolicyCore: createWorkflowEditCore(runnerCalls),
  });

  const result = surface.proposeWorkflowEdit(store, "thread_alpha", {
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
  });

  assert.equal(result.admitted, true);
  assert.equal(result.event_kind, "workflow.edit_proposed");
  assert.equal(result.source_event_kind, "WorkflowEdit.Proposed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].request.operation, "workflow_edit_proposal");
  assert.equal(runnerCalls[0].request.operation_kind, "workflow.edit_proposed");
  assert.equal(runnerCalls[0].request.event_stream_id, "event_stream_thread_alpha");
  assert.equal(runnerCalls[0].request.request.workflow_patch.nodes[0].id, "node_1");
  assert.deepEqual(runnerCalls[0].request.evidence_refs, [
    "runtime_workflow_edit_proposal_control_rust_owned",
    "runtime_workflow_edit_control_event_rust_owned",
    "agentgres_runtime_thread_event_truth_required",
  ]);
  assert.deepEqual(store.calls.map((call) => call.name), ["appendRuntimeEvent"]);
  assert.equal(store.calls[0].event.event_kind, "workflow.edit_proposed");
});

test("workflow-edit apply uses Rust planning and runtime event admission", () => {
  const runnerCalls = [];
  const store = createStore();
  const surface = createSurface({
    contextPolicyCore: createWorkflowEditCore(runnerCalls),
  });

  const result = surface.applyWorkflowEditProposal(store, "thread_alpha", "proposal_one", {
    source: "agent_studio",
    approval_id: "approval_one",
    workflow_graph_id: "graph_one",
    workflow_node_id: "node_one",
  });

  assert.equal(result.admitted, true);
  assert.equal(result.event_kind, "workflow.edit.apply");
  assert.equal(result.source_event_kind, "WorkflowEdit.Apply");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].request.operation, "workflow_edit_apply");
  assert.equal(runnerCalls[0].request.operation_kind, "workflow.edit.apply");
  assert.equal(runnerCalls[0].request.proposal_id, "proposal_one");
  assert.deepEqual(runnerCalls[0].request.evidence_refs, [
    "runtime_workflow_edit_apply_control_rust_owned",
    "runtime_workflow_edit_control_event_rust_owned",
    "agentgres_runtime_thread_event_truth_required",
  ]);
  assert.deepEqual(store.calls.map((call) => call.name), ["appendRuntimeEvent"]);
  assert.equal(store.calls[0].event.event_kind, "workflow.edit.apply");
});

test("workflow-edit controls fail closed before event append without Rust planning", () => {
  const store = createStore();
  const surface = createRuntimeWorkflowEditApi({
    eventStreamIdForThread: (threadId) => `event_stream_${threadId}`,
    runtimeError,
  });

  assert.throws(
    () => surface.proposeWorkflowEdit(store, "thread_alpha", {
      proposal_id: "proposal_one",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workflow_edit_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workflow_edit");
      assert.equal(error.details.operation, "workflow_edit_proposal");
      assert.equal(error.details.operation_kind, "workflow.edit_proposed");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.proposal_id, "proposal_one");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_workflow_edit_proposal_control_rust_owned",
        "runtime_workflow_edit_control_event_rust_owned",
        "agentgres_runtime_thread_event_truth_required",
      ]);
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

test("workflow-edit helper facades are retired with the JS apply path", () => {
  const surface = createSurface();

  assert.equal(Object.hasOwn(surface, "latestWorkflowEditProposalEvent"), false);
  assert.equal(Object.hasOwn(surface, "workflowEditApprovalSatisfaction"), false);
  assert.equal(Object.hasOwn(surface, "workflowEditThreadContext"), false);
  assert.equal(Object.hasOwn(surface, "resolveWorkflowEditTarget"), false);
});
