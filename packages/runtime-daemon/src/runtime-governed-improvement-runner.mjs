import { spawnSync } from "node:child_process";

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
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  admitProposal(proposal) {
    const bridgeRequest = {
      schema_version: GOVERNED_IMPROVEMENT_COMMAND_SCHEMA_VERSION,
      operation: "admit_governed_runtime_improvement_proposal",
      backend: RUST_GOVERNED_IMPROVEMENT_BACKEND,
      proposal,
    };
    return normalizeGovernedImprovementBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_governed_improvement_mock",
        backend: request.backend ?? RUST_GOVERNED_IMPROVEMENT_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new GovernedImprovementRunnerError(
        "Governed improvement admission requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core proposal admission.",
        "governed_improvement_bridge_unconfigured",
        {
          env: GOVERNED_IMPROVEMENT_COMMAND_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, [], {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new GovernedImprovementRunnerError(
        "Failed to spawn Rust governed improvement admission bridge command.",
        "governed_improvement_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new GovernedImprovementRunnerError(
        "Rust governed improvement admission bridge command failed.",
        "governed_improvement_bridge_failed",
        {
          status: output.status,
          stderr: String(output.stderr ?? "").slice(0, 4096),
        },
      );
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new GovernedImprovementRunnerError(
        "Rust governed improvement admission bridge command returned invalid JSON.",
        "governed_improvement_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new GovernedImprovementRunnerError(
        parsed.error?.message ?? "Rust governed improvement core rejected the proposal.",
        parsed.error?.code ?? "governed_improvement_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
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
    source: result.source ?? "rust_governed_meta_improvement_command",
    backend: result.backend ?? RUST_GOVERNED_IMPROVEMENT_BACKEND,
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
