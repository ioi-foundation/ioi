export const L1_SETTLEMENT_CORE_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUNTIME_L1_SETTLEMENT_BACKEND = "l1_settlement_guard";

const RETIRED_L1_SETTLEMENT_CORE_REQUEST_ALIASES = [
  "settlementAttempt",
  "settlement_attempt",
  "stateRootRef",
  "state_root_ref",
];

export function createRuntimeL1SettlementCore(options = {}) {
  return new RuntimeL1SettlementCore(options);
}

export class RuntimeL1SettlementCore {
  constructor(options = {}) {
    assertNoRetiredL1SettlementCoreOption("command", options.command);
    assertNoRetiredL1SettlementCoreOption("args", options.args);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitAttempt(attempt, context = {}) {
    assertCanonicalL1SettlementCoreRequest(attempt);
    const daemonCoreRequest = {
      schema_version: L1_SETTLEMENT_CORE_SCHEMA_VERSION,
      operation: "admit_l1_settlement_attempt",
      backend: RUNTIME_L1_SETTLEMENT_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      attempt,
    };
    return this.invokeDaemonCore(daemonCoreRequest);
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeL1SettlementCoreError(
        "L1 settlement admission requires daemonCoreInvoker for direct Rust daemon-core trigger admission.",
        "l1_settlement_core_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeL1SettlementCoreError(
        error.message ?? "Rust L1 settlement core rejected the attempt.",
        error.code ?? "l1_settlement_core_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

function assertCanonicalL1SettlementCoreRequest(attempt = {}) {
  const record = objectRecord(attempt) ?? {};
  const retiredAliases = RETIRED_L1_SETTLEMENT_CORE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new RuntimeL1SettlementCoreError(
    "L1 settlement core request aliases and state-root truth fields are retired; use canonical snake_case Rust daemon-core fields and Rust-derived state roots.",
    "l1_settlement_core_request_aliases_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
      canonical_fields: ["attempt"],
      derived_fields: ["state_root_ref"],
    },
  );
}

function assertNoRetiredL1SettlementCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeL1SettlementCoreError(
    "L1 settlement command compatibility options are retired; use daemonCoreInvoker for direct Rust daemon-core trigger admission.",
    "l1_settlement_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

export class RuntimeL1SettlementCoreError extends Error {
  constructor(message, code = "l1_settlement_core_error", details = {}) {
    super(message);
    this.name = "RuntimeL1SettlementCoreError";
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
