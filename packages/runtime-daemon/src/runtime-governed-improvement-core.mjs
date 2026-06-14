export const GOVERNED_IMPROVEMENT_CORE_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUNTIME_GOVERNED_IMPROVEMENT_BACKEND = "rust_governed_evolution";

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
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitProposal(proposal, context = {}) {
    assertCanonicalGovernedImprovementCoreProposal(proposal);
    const daemonCoreRequest = {
      schema_version: GOVERNED_IMPROVEMENT_CORE_SCHEMA_VERSION,
      operation: "admit_governed_runtime_improvement_proposal",
      backend: RUNTIME_GOVERNED_IMPROVEMENT_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      proposal,
    };
    return this.invokeDaemonCore(daemonCoreRequest);
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeGovernedImprovementCoreError(
        "Governed improvement admission requires daemonCoreInvoker for direct Rust daemon-core proposal admission.",
        "governed_improvement_core_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeGovernedImprovementCoreError(
        error.message ?? "Rust governed improvement core rejected the proposal.",
        error.code ?? "governed_improvement_core_direct_invoker_rejected",
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
    "Governed improvement command compatibility options are retired; use daemonCoreInvoker for direct Rust daemon-core proposal admission.",
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

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}
