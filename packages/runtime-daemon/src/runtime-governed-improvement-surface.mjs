import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.governed_improvement_admission.v1";

const RETIRED_GOVERNED_IMPROVEMENT_REQUEST_ALIASES = [
  "proposalPayload",
  "proposal_payload",
];

const CANONICAL_GOVERNED_IMPROVEMENT_REQUEST_FIELDS = [
  "proposal",
];

export function createRuntimeGovernedImprovementSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function proposalForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    assertCanonicalGovernedImprovementRequestBody(body);
    const nested = objectRecord(body.proposal) ?? {};
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

  function assertCanonicalGovernedImprovementRequestBody(body = {}) {
    const retiredAliases = RETIRED_GOVERNED_IMPROVEMENT_REQUEST_ALIASES.filter((field) =>
      Object.hasOwn(body, field),
    );
    if (retiredAliases.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "governed_improvement_proposal_request_aliases_retired",
      message: "Governed improvement proposal request aliases are retired; use proposal.",
      details: {
        retired_aliases: retiredAliases,
        canonical_fields: CANONICAL_GOVERNED_IMPROVEMENT_REQUEST_FIELDS,
      },
    });
  }

  function admitGovernedImprovementProposal(store, threadId, request = {}) {
    const proposal = proposalForRequest(request);
    const agent = store.agentForThread(threadId);
    const admission = store.governedImprovementRunner.admitProposal(proposal);
    const record = objectRecord(admission.record) ?? {};
    return {
      schema_version: GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_governed_improvement_admission",
      status: "admitted",
      proposal_admitted: true,
      mutation_executed: false,
      thread_id: threadId,
      agent_id: agent.id,
      proposal_id: admission.proposal_id ?? record.proposal_id ?? optionalString(proposal.proposal_id ?? proposal.proposalId),
      admission_hash: admission.admission_hash ?? record.admission_hash ?? null,
      agentgres_operation_ref:
        admission.agentgres_operation_ref ?? record.agentgres_operation_ref ?? null,
      state_root_before: admission.state_root_before ?? record.state_root_before ?? null,
      state_root_after: admission.state_root_after ?? record.state_root_after ?? null,
      resulting_head: admission.resulting_head ?? record.resulting_head ?? null,
      approval_ref: admission.approval_ref ?? record.approval_ref ?? null,
      rollback_ref: admission.rollback_ref ?? record.rollback_ref ?? null,
      admission,
      record,
    };
  }

  return {
    admitGovernedImprovementProposal,
    proposalForRequest,
  };
}
