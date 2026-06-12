export const L1_SETTLEMENT_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_L1_SETTLEMENT_BACKEND = "l1_settlement_guard";

export function createL1SettlementRunnerFromEnv(env = process.env, options = {}) {
  assertNoL1SettlementCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  assertNoL1SettlementCommandSelection(
    options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND ?? env.IOI_L1_SETTLEMENT_COMMAND,
  );
  return new RustL1SettlementRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
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

export function assertNoL1SettlementCommandSelection(value) {
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new L1SettlementRunnerError(
    "L1 settlement binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core admission.",
    "l1_settlement_command_selection_retired",
    { retired_command: value },
  );
}

export class RustL1SettlementRunner {
  constructor(options = {}) {
    assertNoL1SettlementCommandArgs(options.args);
    assertNoL1SettlementCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitAttempt(attempt, context = {}) {
    const bridgeRequest = {
      schema_version: L1_SETTLEMENT_COMMAND_SCHEMA_VERSION,
      operation: "admit_l1_settlement_attempt",
      backend: RUST_L1_SETTLEMENT_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      attempt,
    };
    return normalizeL1SettlementBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new L1SettlementRunnerError(
        "L1 settlement admission requires daemonCoreInvoker for direct Rust daemon-core trigger admission.",
        "l1_settlement_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new L1SettlementRunnerError(
        error.message ?? "Rust L1 settlement guard rejected the attempt.",
        error.code ?? "l1_settlement_direct_invoker_rejected",
        { error },
      );
    }
    return response?.result ?? response;
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
    schema_version: result.schema_version ?? null,
    object: result.object ?? null,
    status: result.status ?? null,
    settlement_admitted: result.settlement_admitted ?? null,
    thread_id: result.thread_id ?? null,
    agent_id: result.agent_id ?? null,
    record,
    settlement_ref: result.settlement_ref ?? record.settlement_ref ?? null,
    domain_ref: result.domain_ref ?? record.domain_ref ?? null,
    state_root_ref: result.state_root_ref ?? record.state_root_ref ?? null,
    trigger_refs: stringArray(result.trigger_refs) ?? stringArray(record.trigger_refs) ?? null,
    receipt_refs: stringArray(result.receipt_refs) ?? stringArray(record.receipt_refs) ?? null,
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

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}
