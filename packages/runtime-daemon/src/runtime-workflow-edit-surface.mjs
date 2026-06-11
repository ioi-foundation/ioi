import { runtimeError } from "./runtime-http-utils.mjs";
import { optionalString } from "./runtime-value-helpers.mjs";

export function createRuntimeWorkflowEditSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
    workflowEditRunner = null,
  } = deps;

  function throwWorkflowEditRustCoreRequired(operation, operationKind, details = {}) {
    if (workflowEditRunner?.planWorkflowEditAdmissionRequired) {
      const record = workflowEditRunner.planWorkflowEditAdmissionRequired({
        operation,
        operation_kind: operationKind,
        thread_id: details.thread_id,
        turn_id: details.turn_id,
        proposal_id: details.proposal_id,
        edit_intent_id: details.edit_intent_id,
        approval_id: details.approval_id,
        workflow_graph_id: details.workflow_graph_id,
        workflow_node_id: details.workflow_node_id,
        workflow_path: details.workflow_path,
        source: details.source,
        evidence_refs: details.evidence_refs,
      });
      const planned = record?.record ?? record;
      throw runtimeErrorDep({
        status: Number(planned?.status_code ?? record?.status_code ?? 501),
        code: optionalString(planned?.code ?? record?.code) ?? "runtime_workflow_edit_rust_core_required",
        message:
          optionalString(planned?.message ?? record?.message) ??
          "Runtime workflow edit control requires direct Rust daemon-core admission and persistence.",
        details: planned?.details ?? record?.details ?? {
          rust_core_boundary: "runtime.workflow_edit",
          operation,
          operation_kind: operationKind,
          ...details,
        },
      });
    }
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_workflow_edit_rust_core_required",
      message: "Runtime workflow edit control requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.workflow_edit",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  function proposeWorkflowEdit(store, threadId, request = {}) {
    throwWorkflowEditRustCoreRequired("workflow_edit_proposal", "workflow.edit_proposed", {
      thread_id: threadId,
      turn_id: optionalString(request.turn_id) ?? null,
      proposal_id: optionalString(request.proposal_id) ?? null,
      edit_intent_id: optionalString(request.edit_intent_id) ?? null,
      approval_id: optionalString(request.approval_id) ?? null,
      workflow_graph_id: optionalString(request.workflow_graph_id) ?? null,
      workflow_node_id: optionalString(request.workflow_node_id) ?? null,
      workflow_path: optionalString(request.workflow_path) ?? null,
      source: optionalString(request.source) ?? null,
      evidence_refs: [
        "workflow_edit_proposal_js_facade_retired",
        "rust_daemon_core_workflow_edit_proposal_required",
        "agentgres_workflow_edit_proposal_truth_required",
      ],
    });
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
    throwWorkflowEditRustCoreRequired("workflow_edit_apply", "workflow.edit.apply", {
      thread_id: threadId,
      proposal_id: normalizedProposalId,
      approval_id: optionalString(request.approval_id) ?? null,
      workflow_graph_id: optionalString(request.workflow_graph_id) ?? null,
      workflow_node_id: optionalString(request.workflow_node_id) ?? null,
      source: optionalString(request.source) ?? null,
      evidence_refs: [
        "workflow_edit_apply_js_facade_retired",
        "rust_daemon_core_workflow_edit_apply_required",
        "agentgres_workflow_edit_apply_truth_required",
      ],
    });
  }

  return {
    proposeWorkflowEdit,
    applyWorkflowEditProposal,
  };
}
