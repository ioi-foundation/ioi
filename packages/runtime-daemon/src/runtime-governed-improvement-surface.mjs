import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.governed_improvement_admission.v1";

export function createRuntimeGovernedImprovementSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function proposalForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    const nested = objectRecord(body.proposal ?? body.proposal_payload ?? body.proposalPayload) ?? {};
    const proposal = Object.keys(nested).length > 0 ? nested : body;
    if (Object.keys(proposal).length === 0) {
      throw runtimeErrorDep({
        status: 400,
        code: "governed_improvement_proposal_required",
        message: "Governed improvement admission requires a proposal payload.",
      });
    }
    return proposal;
  }

  function admitGovernedImprovementProposal(store, threadId, request = {}) {
    const agent = store.agentForThread(threadId);
    const proposal = proposalForRequest(request);
    const admission = store.governedImprovementRunner.admitProposal(proposal);
    const record = objectRecord(admission.record) ?? {};
    return {
      schema_version: GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
      schemaVersion: GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_governed_improvement_admission",
      status: "admitted",
      proposal_admitted: true,
      proposalAdmitted: true,
      mutation_executed: false,
      mutationExecuted: false,
      thread_id: threadId,
      threadId,
      agent_id: agent.id,
      agentId: agent.id,
      proposal_id: admission.proposal_id ?? record.proposal_id ?? optionalString(proposal.proposal_id ?? proposal.proposalId),
      proposalId: admission.proposal_id ?? record.proposal_id ?? optionalString(proposal.proposal_id ?? proposal.proposalId),
      admission_hash: admission.admission_hash ?? record.admission_hash ?? null,
      admissionHash: admission.admission_hash ?? record.admission_hash ?? null,
      agentgres_operation_ref:
        admission.agentgres_operation_ref ?? record.agentgres_operation_ref ?? null,
      agentgresOperationRef:
        admission.agentgres_operation_ref ?? record.agentgres_operation_ref ?? null,
      state_root_before: admission.state_root_before ?? record.state_root_before ?? null,
      stateRootBefore: admission.state_root_before ?? record.state_root_before ?? null,
      state_root_after: admission.state_root_after ?? record.state_root_after ?? null,
      stateRootAfter: admission.state_root_after ?? record.state_root_after ?? null,
      resulting_head: admission.resulting_head ?? record.resulting_head ?? null,
      resultingHead: admission.resulting_head ?? record.resulting_head ?? null,
      approval_ref: admission.approval_ref ?? record.approval_ref ?? null,
      approvalRef: admission.approval_ref ?? record.approval_ref ?? null,
      rollback_ref: admission.rollback_ref ?? record.rollback_ref ?? null,
      rollbackRef: admission.rollback_ref ?? record.rollback_ref ?? null,
      admission,
      record,
    };
  }

  return {
    admitGovernedImprovementProposal,
    proposalForRequest,
  };
}
