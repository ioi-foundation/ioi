import { spawnSync } from "node:child_process";

export const MODEL_MOUNT_ROUTE_DECISION_COMMAND_ENV = "IOI_MODEL_MOUNT_ROUTE_DECISION_COMMAND";
export const MODEL_MOUNT_ROUTE_DECISION_COMMAND_ARGS_ENV = "IOI_MODEL_MOUNT_ROUTE_DECISION_COMMAND_ARGS";
export const MODEL_MOUNT_ROUTE_DECISION_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
export const RUST_MODEL_MOUNT_ROUTE_DECISION_BACKEND = "rust_model_mount_live";

export function createModelMountRouteDecisionRunnerFromEnv(env = process.env, options = {}) {
  return new RustModelMountRouteDecisionRunner({
    command: options.command ?? env[MODEL_MOUNT_ROUTE_DECISION_COMMAND_ENV] ?? null,
    args: options.args ?? parseCommandArgs(env[MODEL_MOUNT_ROUTE_DECISION_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustModelMountRouteDecisionRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  admitRouteDecision(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ROUTE_DECISION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_route_decision",
      backend: RUST_MODEL_MOUNT_ROUTE_DECISION_BACKEND,
      request,
    };
    return normalizeBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_model_mount_mock",
        backend: RUST_MODEL_MOUNT_ROUTE_DECISION_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new ModelMountRouteDecisionRunnerError(
        "Model mount route decisions require IOI_MODEL_MOUNT_ROUTE_DECISION_COMMAND for Rust core admission.",
        "model_mount_route_decision_bridge_unconfigured",
        {
          env: MODEL_MOUNT_ROUTE_DECISION_COMMAND_ENV,
          argsEnv: MODEL_MOUNT_ROUTE_DECISION_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ModelMountRouteDecisionRunnerError(
        "Failed to spawn Rust model_mount route-decision bridge command.",
        "model_mount_route_decision_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new ModelMountRouteDecisionRunnerError(
        "Rust model_mount route-decision bridge command failed.",
        "model_mount_route_decision_bridge_failed",
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
      throw new ModelMountRouteDecisionRunnerError(
        "Rust model_mount route-decision bridge command returned invalid JSON.",
        "model_mount_route_decision_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new ModelMountRouteDecisionRunnerError(
        parsed.error?.message ?? "Rust model_mount core rejected the route decision.",
        parsed.error?.code ?? "model_mount_route_decision_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class ModelMountRouteDecisionRunnerError extends Error {
  constructor(message, code = "model_mount_route_decision_runner_error", details = {}) {
    super(message);
    this.name = "ModelMountRouteDecisionRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function normalizeBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ROUTE_DECISION_BACKEND,
    record,
    route_decision_ref: result.route_decision_ref ?? record.route_decision_ref ?? null,
    route_decision_hash: result.route_decision_hash ?? record.route_decision_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
  return trimmed ? trimmed : null;
}
