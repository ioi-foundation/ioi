import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

export const L1_SETTLEMENT_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const L1_SETTLEMENT_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_L1_SETTLEMENT_BACKEND = "l1_settlement_guard";

export function createL1SettlementRunnerFromEnv(env = process.env, options = {}) {
  assertNoL1SettlementCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustL1SettlementRunner({
    command: options.command ?? env[L1_SETTLEMENT_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function assertNoL1SettlementCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new L1SettlementRunnerError(
    "L1 settlement command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "l1_settlement_command_args_retired",
    { retired_args: value },
  );
}

export class RustL1SettlementRunner {
  constructor(options = {}) {
    assertNoL1SettlementCommandArgs(options.args);
    this.command = optionalString(options.command);
    this.invokeBridge = createDaemonCoreCommandInvoker({
      command: this.command,
      spawnSyncImpl: options.spawnSyncImpl,
      mockResult: options.mockResult,
      mockSource: "rust_l1_settlement_guard_mock",
      defaultBackend: RUST_L1_SETTLEMENT_BACKEND,
      ErrorClass: L1SettlementRunnerError,
      env: L1_SETTLEMENT_COMMAND_ENV,
      unconfiguredMessage:
        "L1 settlement admission requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core trigger admission.",
      unconfiguredCode: "l1_settlement_bridge_unconfigured",
      spawnFailedMessage: "Failed to spawn Rust L1 settlement admission bridge command.",
      spawnFailedCode: "l1_settlement_bridge_spawn_failed",
      commandFailedMessage: "Rust L1 settlement admission bridge command failed.",
      commandFailedCode: "l1_settlement_bridge_failed",
      invalidJsonMessage: "Rust L1 settlement admission bridge command returned invalid JSON.",
      invalidJsonCode: "l1_settlement_bridge_invalid_json",
      rejectedMessage: "Rust L1 settlement guard rejected the attempt.",
      rejectedCode: "l1_settlement_bridge_rejected",
    });
  }

  admitAttempt(attempt) {
    const bridgeRequest = {
      schema_version: L1_SETTLEMENT_COMMAND_SCHEMA_VERSION,
      operation: "admit_l1_settlement_attempt",
      backend: RUST_L1_SETTLEMENT_BACKEND,
      attempt,
    };
    return normalizeL1SettlementBridgeResult(this.invokeBridge(bridgeRequest));
  }

}

export class L1SettlementRunnerError extends Error {
  constructor(message, code = "l1_settlement_runner_error", details = {}) {
    super(message);
    this.name = "L1SettlementRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeL1SettlementBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? {};
  return {
    source: result.source ?? "rust_l1_settlement_guard_command",
    backend: result.backend ?? RUST_L1_SETTLEMENT_BACKEND,
    record,
    settlement_ref: result.settlement_ref ?? record.settlement_ref ?? null,
    domain_ref: result.domain_ref ?? record.domain_ref ?? null,
    state_root_ref: result.state_root_ref ?? record.state_root_ref ?? null,
    trigger_refs: stringArray(result.trigger_refs) ?? stringArray(record.trigger_refs) ?? [],
    receipt_refs: stringArray(result.receipt_refs) ?? stringArray(record.receipt_refs) ?? [],
    admission_hash: result.admission_hash ?? record.admission_hash ?? null,
  };
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function stringArray(value) {
  if (!Array.isArray(value)) return null;
  return value.filter((entry) => typeof entry === "string" && entry.trim()).map((entry) => entry.trim());
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
