import { runtimeError } from "./runtime-http-utils.mjs";
import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import { normalizeArray, objectRecord, optionalString } from "./runtime-value-helpers.mjs";

const WORKFLOW_EDIT_CONTROL_EVENT_EVIDENCE_REFS = [
  "runtime_workflow_edit_control_event_rust_owned",
  "agentgres_runtime_thread_event_truth_required",
];

export function createRuntimeWorkflowEditSurface(deps = {}) {
  const {
    eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
    runtimeError: runtimeErrorDep = runtimeError,
    workflowEditRunner = null,
  } = deps;

  function workflowEditControlEvidenceRefs(operationKind) {
    const refs = [...WORKFLOW_EDIT_CONTROL_EVENT_EVIDENCE_REFS];
    if (operationKind === "workflow.edit.apply") {
      refs.unshift("runtime_workflow_edit_apply_control_rust_owned");
    } else {
      refs.unshift("runtime_workflow_edit_proposal_control_rust_owned");
    }
    return refs;
  }

  function throwWorkflowEditControlRustCoreRequired({ operation, operation_kind, thread_id, proposal_id = null }) {
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_workflow_edit_control_rust_core_required",
      message: "Runtime workflow edit control requires Rust daemon-core planning and runtime-event admission.",
      details: {
        rust_core_boundary: "runtime.workflow_edit",
        operation,
        operation_kind,
        thread_id: thread_id ?? null,
        proposal_id: proposal_id ?? null,
        evidence_refs: workflowEditControlEvidenceRefs(operation_kind),
      },
    });
  }

  function workflowEditControlRunner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? workflowEditRunner;
    if (
      runner?.planRuntimeWorkflowEditControl &&
      typeof store?.appendRuntimeEvent === "function"
    ) {
      return runner;
    }
    throwWorkflowEditControlRustCoreRequired({
      operation: request.operation,
      operation_kind: request.operation_kind,
      thread_id: request.thread_id,
      proposal_id: request.proposal_id,
    });
  }

  function workflowEditControlRequestPayload(request = {}) {
    const payload = {};
    for (const key of [
      "source",
      "status",
      "event_id",
      "turn_id",
      "proposal_id",
      "edit_intent_id",
      "approval_id",
      "workflow_graph_id",
      "workflow_node_id",
      "workflow_path",
      "workspace_root",
      "workflow_patch",
      "code_diff",
      "target_workflow_node_ids",
      "bounded_targets",
      "artifact_refs",
      "rollback_refs",
      "receipt_refs",
      "policy_decision_refs",
      "idempotency_key",
    ]) {
      if (Object.hasOwn(request, key)) payload[key] = request[key];
    }
    return payload;
  }

  function stringRefs(values) {
    return normalizeArray(values).map((value) => String(value)).filter(Boolean);
  }

  function planWorkflowEditControlEvent(store, threadId, request = {}, {
    operation,
    operationKind,
    proposal_id = null,
  }) {
    const normalizedRequest = objectRecord(request) ?? {};
    const normalizedProposalId =
      optionalString(proposal_id) ??
      optionalString(normalizedRequest.proposal_id) ??
      null;
    const runner = workflowEditControlRunner(store, {
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      proposal_id: normalizedProposalId,
    });
    return runner.planRuntimeWorkflowEditControl({
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      event_stream_id: eventStreamIdForThreadDep(threadId),
      turn_id: optionalString(normalizedRequest.turn_id) ?? null,
      proposal_id: normalizedProposalId,
      edit_intent_id: optionalString(normalizedRequest.edit_intent_id) ?? null,
      approval_id: optionalString(normalizedRequest.approval_id) ?? null,
      workflow_graph_id: optionalString(normalizedRequest.workflow_graph_id) ?? null,
      workflow_node_id: optionalString(normalizedRequest.workflow_node_id) ?? null,
      workflow_path: optionalString(normalizedRequest.workflow_path) ?? null,
      workspace_root: optionalString(normalizedRequest.workspace_root) ?? null,
      source: optionalString(normalizedRequest.source) ?? null,
      status: optionalString(normalizedRequest.status) ?? null,
      request: workflowEditControlRequestPayload(normalizedRequest),
      receipt_refs: stringRefs(normalizedRequest.receipt_refs),
      policy_decision_refs: stringRefs(normalizedRequest.policy_decision_refs),
      evidence_refs: workflowEditControlEvidenceRefs(operationKind),
    });
  }

  function appendPlannedWorkflowEditControlEvent(store, plannedControl) {
    const event = objectRecord(plannedControl?.event);
    if (!event) {
      throw runtimeErrorDep({
        status: 502,
        code: "runtime_workflow_edit_control_event_missing",
        message: "Rust workflow-edit control planning did not return a runtime event.",
        details: { operation_kind: plannedControl?.operation_kind ?? null },
      });
    }
    return store.appendRuntimeEvent(event);
  }

  function proposeWorkflowEdit(store, threadId, request = {}) {
    const plannedControl = planWorkflowEditControlEvent(store, threadId, request, {
      operation: "workflow_edit_proposal",
      operationKind: "workflow.edit_proposed",
    });
    return appendPlannedWorkflowEditControlEvent(store, plannedControl);
  }

  function applyWorkflowEditProposal(store, threadId, proposalId, request = {}) {
    const normalizedProposalId = optionalString(proposalId ?? request.proposal_id);
    if (!normalizedProposalId) {
      throw runtimeErrorDep({
        status: 400,
        code: "workflow_edit_proposal_id_required",
        message: "Workflow edit proposal apply requires a proposal id.",
        details: { thread_id: threadId },
      });
    }
    const plannedControl = planWorkflowEditControlEvent(store, threadId, request, {
      operation: "workflow_edit_apply",
      operationKind: "workflow.edit.apply",
      proposal_id: normalizedProposalId,
    });
    return appendPlannedWorkflowEditControlEvent(store, plannedControl);
  }

  return {
    proposeWorkflowEdit,
    applyWorkflowEditProposal,
  };
}
