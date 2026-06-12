import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord } from "./runtime-value-helpers.mjs";

const RETIRED_GOVERNED_IMPROVEMENT_REQUEST_ALIASES = [
  "proposalPayload",
  "proposal_payload",
];

const RETIRED_GOVERNED_IMPROVEMENT_TRUTH_FIELDS = [
  "agentgres_operation_ref",
  "expected_heads",
  "state_root_before",
  "state_root_after",
  "resulting_head",
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
    assertNoClientSuppliedGovernedImprovementTruth(proposal);
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

  function assertNoClientSuppliedGovernedImprovementTruth(proposal = {}) {
    const retiredTruthFields = RETIRED_GOVERNED_IMPROVEMENT_TRUTH_FIELDS.filter((field) =>
      Object.hasOwn(proposal, field),
    );
    if (retiredTruthFields.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "governed_improvement_agentgres_truth_fields_retired",
      message: "Governed improvement Agentgres truth fields are Rust-derived and cannot be supplied by clients.",
      details: {
        retired_fields: retiredTruthFields,
        derived_by: "rust_governed_evolution",
      },
    });
  }

  function admitGovernedImprovementProposal(store, threadId, request = {}) {
    const proposal = proposalForRequest(request);
    const agent = store.agentForThread(threadId);
    return store.governedImprovementRunner.admitProposal(proposal, {
      thread_id: threadId,
      agent_id: agent.id,
    });
  }

  return {
    admitGovernedImprovementProposal,
    proposalForRequest,
  };
}
