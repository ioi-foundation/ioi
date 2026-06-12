import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

export const GOVERNED_IMPROVEMENT_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const GOVERNED_IMPROVEMENT_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_GOVERNED_IMPROVEMENT_BACKEND = "rust_governed_evolution";

export function createGovernedImprovementRunnerFromEnv(env = process.env, options = {}) {
  assertNoGovernedImprovementCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustGovernedImprovementRunner({
    command: options.command ?? env[GOVERNED_IMPROVEMENT_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function assertNoGovernedImprovementCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new GovernedImprovementRunnerError(
    "Governed improvement command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "governed_improvement_command_args_retired",
    { retired_args: value },
  );
}

export class RustGovernedImprovementRunner {
  constructor(options = {}) {
    assertNoGovernedImprovementCommandArgs(options.args);
    this.command = optionalString(options.command);
    this.invokeBridge = createDaemonCoreCommandInvoker({
      command: this.command,
      spawnSyncImpl: options.spawnSyncImpl,
      mockResult: options.mockResult,
      mockSource: "rust_governed_improvement_mock",
      defaultBackend: RUST_GOVERNED_IMPROVEMENT_BACKEND,
      ErrorClass: GovernedImprovementRunnerError,
      env: GOVERNED_IMPROVEMENT_COMMAND_ENV,
      unconfiguredMessage:
        "Governed improvement admission requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core proposal admission.",
      unconfiguredCode: "governed_improvement_bridge_unconfigured",
      spawnFailedMessage: "Failed to spawn Rust governed improvement admission bridge command.",
      spawnFailedCode: "governed_improvement_bridge_spawn_failed",
      commandFailedMessage: "Rust governed improvement admission bridge command failed.",
      commandFailedCode: "governed_improvement_bridge_failed",
      invalidJsonMessage: "Rust governed improvement admission bridge command returned invalid JSON.",
      invalidJsonCode: "governed_improvement_bridge_invalid_json",
      rejectedMessage: "Rust governed improvement core rejected the proposal.",
      rejectedCode: "governed_improvement_bridge_rejected",
    });
  }

  admitProposal(proposal, context = {}) {
    const bridgeRequest = {
      schema_version: GOVERNED_IMPROVEMENT_COMMAND_SCHEMA_VERSION,
      operation: "admit_governed_runtime_improvement_proposal",
      backend: RUST_GOVERNED_IMPROVEMENT_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      proposal,
    };
    return normalizeGovernedImprovementBridgeResult(this.invokeBridge(bridgeRequest));
  }

}

export class GovernedImprovementRunnerError extends Error {
  constructor(message, code = "governed_improvement_runner_error", details = {}) {
    super(message);
    this.name = "GovernedImprovementRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeGovernedImprovementBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    schema_version: result.schema_version ?? null,
    object: result.object ?? null,
    status: result.status ?? null,
    proposal_admitted: result.proposal_admitted ?? null,
    mutation_executed: result.mutation_executed ?? null,
    source: result.source ?? "rust_governed_meta_improvement_command",
    backend: result.backend ?? RUST_GOVERNED_IMPROVEMENT_BACKEND,
    thread_id: result.thread_id ?? null,
    agent_id: result.agent_id ?? null,
    record,
    proposal_id: result.proposal_id ?? record.proposal_id ?? null,
    target_ref: result.target_ref ?? record.target_ref ?? null,
    candidate_ref: result.candidate_ref ?? record.candidate_ref ?? null,
    admission_hash: result.admission_hash ?? record.admission_hash ?? null,
    agentgres_operation_ref: result.agentgres_operation_ref ?? record.agentgres_operation_ref ?? null,
    expected_heads: Array.isArray(result.expected_heads) ? result.expected_heads : record.expected_heads ?? [],
    state_root_before: result.state_root_before ?? record.state_root_before ?? null,
    state_root_after: result.state_root_after ?? record.state_root_after ?? null,
    resulting_head: result.resulting_head ?? record.resulting_head ?? null,
    eval_receipt_refs: Array.isArray(result.eval_receipt_refs) ? result.eval_receipt_refs : record.eval_receipt_refs ?? [],
    verifier_receipt_refs: Array.isArray(result.verifier_receipt_refs)
      ? result.verifier_receipt_refs
      : record.verifier_receipt_refs ?? [],
    approval_ref: result.approval_ref ?? record.approval_ref ?? null,
    rollback_ref: result.rollback_ref ?? record.rollback_ref ?? null,
  };
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
