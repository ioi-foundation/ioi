export const RUNTIME_GOVERNED_IMPROVEMENT_BACKEND = "rust_governed_evolution";
export const GOVERNED_IMPROVEMENT_CORE_API_METHOD =
  "admitGovernedRuntimeImprovementProposal";

const RETIRED_GOVERNED_IMPROVEMENT_CORE_PROPOSAL_ALIASES = [
  "schemaVersion",
  "proposalId",
  "targetRef",
  "candidateRef",
  "sourceTraceRef",
  "evalReceiptRefs",
  "verifierReceiptRefs",
  "approvalRef",
  "rollbackRef",
  "agentgresOperationRef",
  "expectedHeads",
  "stateRootBefore",
  "stateRootAfter",
  "resultingHead",
];

const RETIRED_GOVERNED_IMPROVEMENT_CORE_TRUTH_FIELDS = [
  "agentgres_operation_ref",
  "expected_heads",
  "state_root_before",
  "state_root_after",
  "resulting_head",
];

export function createRuntimeGovernedImprovementCore(options = {}) {
  return new RuntimeGovernedImprovementCore(options);
}

export class RuntimeGovernedImprovementCore {
  constructor(options = {}) {
    assertNoRetiredGovernedImprovementCoreOption("command", options.command);
    assertNoRetiredGovernedImprovementCoreOption("args", options.args);
    assertNoRetiredGovernedImprovementCoreOption(
      "daemonCoreInvoker",
      options.daemonCoreInvoker,
    );
    this.daemonCoreGovernedAdmissionApi = governedAdmissionApi(
      options.daemonCoreGovernedAdmissionApi ??
        options.daemonCoreApi?.governed_admission ??
        options.daemonCoreApi?.governedAdmission ??
        options.daemonCoreApi,
      GOVERNED_IMPROVEMENT_CORE_API_METHOD,
    );
  }

  admitProposal(proposal, context = {}) {
    assertCanonicalGovernedImprovementCoreProposal(proposal);
    const routeContext = {
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
    };
    return this.invokeRustGovernedAdmissionApi(proposal, routeContext);
  }

  invokeRustGovernedAdmissionApi(proposal, context = {}) {
    if (!this.daemonCoreGovernedAdmissionApi) {
      throw new RuntimeGovernedImprovementCoreError(
        "Governed improvement admission requires daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal for Rust daemon-core proposal admission.",
        "governed_improvement_core_direct_governed_admission_api_unconfigured",
        {
          boundary:
            "daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal",
          backend: RUNTIME_GOVERNED_IMPROVEMENT_BACKEND,
        },
      );
    }
    const response = this.daemonCoreGovernedAdmissionApi[
      GOVERNED_IMPROVEMENT_CORE_API_METHOD
    ](proposal, context);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeGovernedImprovementCoreError(
        error.message ?? "Rust governed improvement core rejected the proposal.",
        error.code ?? "governed_improvement_core_direct_governed_admission_api_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

function assertCanonicalGovernedImprovementCoreProposal(proposal = {}) {
  const record = objectRecord(proposal) ?? {};
  const retiredAliases = RETIRED_GOVERNED_IMPROVEMENT_CORE_PROPOSAL_ALIASES.filter((field) =>
    Object.hasOwn(record, field),
  );
  const retiredTruthFields = RETIRED_GOVERNED_IMPROVEMENT_CORE_TRUTH_FIELDS.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0 && retiredTruthFields.length === 0) return;
  throw new RuntimeGovernedImprovementCoreError(
    "Governed improvement core proposal aliases and Agentgres truth fields are retired; use canonical snake_case proposal fields and Rust-derived truth.",
    "governed_improvement_core_proposal_fields_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
      retired_truth_fields: retiredTruthFields,
      canonical_fields: ["proposal"],
      derived_by: RUNTIME_GOVERNED_IMPROVEMENT_BACKEND,
    },
  );
}

function assertNoRetiredGovernedImprovementCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeGovernedImprovementCoreError(
    "Governed improvement command compatibility options are retired; use daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal for Rust daemon-core proposal admission.",
    "governed_improvement_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

export class RuntimeGovernedImprovementCoreError extends Error {
  constructor(message, code = "governed_improvement_core_error", details = {}) {
    super(message);
    this.name = "RuntimeGovernedImprovementCoreError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function governedAdmissionApi(value, method) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return typeof value[method] === "function" ? value : null;
}
