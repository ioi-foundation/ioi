import { spawnSync } from "node:child_process";

export const CONTEXT_BUDGET_POLICY_COMMAND_ENV = "IOI_STEP_MODULE_COMMAND";
export const CONTEXT_BUDGET_POLICY_COMMAND_ARGS_ENV = "IOI_STEP_MODULE_COMMAND_ARGS";
export const CONTEXT_BUDGET_POLICY_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
export const CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.context-budget-policy-request.v1";
export const CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-budget-policy-request.v1";
export const RUST_CONTEXT_BUDGET_POLICY_BACKEND = "rust_policy";

export function createContextBudgetPolicyRunnerFromEnv(env = process.env, options = {}) {
  return new RustContextBudgetPolicyRunner({
    command: options.command ?? env[CONTEXT_BUDGET_POLICY_COMMAND_ENV] ?? null,
    args:
      options.args ??
      parseCommandArgs(env[CONTEXT_BUDGET_POLICY_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustContextBudgetPolicyRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  evaluateContextBudgetPolicy(request = {}) {
    return this.evaluatePolicy({
      operation: "evaluate_context_budget_policy",
      schemaVersion: CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
      request,
    });
  }

  evaluateCodingToolBudgetPolicy(request = {}) {
    return this.evaluatePolicy({
      operation: "evaluate_coding_tool_budget_policy",
      schemaVersion: CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
      request,
    });
  }

  evaluatePolicy({ operation, schemaVersion, request }) {
    const bridgeRequest = {
      schema_version: CONTEXT_BUDGET_POLICY_COMMAND_SCHEMA_VERSION,
      operation,
      backend: RUST_CONTEXT_BUDGET_POLICY_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: schemaVersion,
      },
    };
    return normalizeContextBudgetPolicyBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_context_budget_policy_mock",
        backend: request.backend ?? RUST_CONTEXT_BUDGET_POLICY_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new ContextBudgetPolicyRunnerError(
        "Context budget policy requires IOI_STEP_MODULE_COMMAND for Rust policy evaluation.",
        "context_budget_policy_bridge_unconfigured",
        {
          env: CONTEXT_BUDGET_POLICY_COMMAND_ENV,
          argsEnv: CONTEXT_BUDGET_POLICY_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ContextBudgetPolicyRunnerError(
        "Failed to spawn Rust context budget policy bridge command.",
        "context_budget_policy_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new ContextBudgetPolicyRunnerError(
        "Rust context budget policy bridge command failed.",
        "context_budget_policy_bridge_failed",
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
      throw new ContextBudgetPolicyRunnerError(
        "Rust context budget policy bridge command returned invalid JSON.",
        "context_budget_policy_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new ContextBudgetPolicyRunnerError(
        parsed.error?.message ?? "Rust context budget policy rejected the request.",
        parsed.error?.code ?? "context_budget_policy_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class ContextBudgetPolicyRunnerError extends Error {
  constructor(message, code = "context_budget_policy_runner_error", details = {}) {
    super(message);
    this.name = "ContextBudgetPolicyRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeContextBudgetPolicyBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_context_budget_policy_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_BUDGET_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "ok",
    mode: optionalString(result.mode ?? record.mode) ?? "simulate",
    usage_telemetry: objectRecord(result.usage_telemetry) ?? objectRecord(record.usage_telemetry) ?? {},
    usage_summary: objectRecord(result.usage_summary) ?? objectRecord(record.usage_summary) ?? {},
    policy_decision_id: optionalString(result.policy_decision_id ?? record.policy_decision_id),
    policy_decision: objectRecord(result.policy_decision) ?? objectRecord(record.policy_decision) ?? null,
    receipt_refs: stringArray(result.receipt_refs ?? record.receipt_refs),
    policy_decision_refs: stringArray(result.policy_decision_refs ?? record.policy_decision_refs),
    warnings: arrayValue(result.warnings ?? record.warnings),
    violations: arrayValue(result.violations ?? record.violations),
    would_block: Boolean(result.would_block ?? record.would_block),
    summary: optionalString(result.summary ?? record.summary) ?? null,
  };
}

function parseCommandArgs(value) {
  if (!value) return [];
  if (Array.isArray(value)) return normalizeArgs(value);
  return String(value)
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeArgs(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry)).filter((entry) => entry.length > 0);
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function stringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => optionalString(entry)).filter(Boolean);
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}
