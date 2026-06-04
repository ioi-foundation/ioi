import { spawnSync } from "node:child_process";

export const MODEL_MOUNT_ADMISSION_COMMAND_ENV = "IOI_MODEL_MOUNT_ADMISSION_COMMAND";
export const MODEL_MOUNT_ADMISSION_COMMAND_ARGS_ENV = "IOI_MODEL_MOUNT_ADMISSION_COMMAND_ARGS";
export const MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
export const RUST_MODEL_MOUNT_ADMISSION_BACKEND = "rust_model_mount_live";

export function createModelMountAdmissionRunnerFromEnv(env = process.env, options = {}) {
  return new RustModelMountAdmissionRunner({
    command: options.command ?? env[MODEL_MOUNT_ADMISSION_COMMAND_ENV] ?? null,
    args: options.args ?? parseCommandArgs(env[MODEL_MOUNT_ADMISSION_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustModelMountAdmissionRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  admitRouteDecision(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_route_decision",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeRouteDecisionBridgeResult(this.invokeBridge(bridgeRequest));
  }

  admitInvocation(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_invocation",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeInvocationBridgeResult(this.invokeBridge(bridgeRequest));
  }

  bindInvocationReceipt({ invocation, result, expectedHeads = [], receiptRef = null } = {}) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "bind_model_mount_invocation_receipt",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      invocation,
      result,
      expected_heads: Array.isArray(expectedHeads) ? expectedHeads : [],
      receipt_ref: receiptRef,
    };
    return normalizeInvocationReceiptBindingBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_model_mount_mock",
        backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new ModelMountAdmissionRunnerError(
        "Model mount admission requires IOI_MODEL_MOUNT_ADMISSION_COMMAND for Rust core admission.",
        "model_mount_admission_bridge_unconfigured",
        {
          env: MODEL_MOUNT_ADMISSION_COMMAND_ENV,
          argsEnv: MODEL_MOUNT_ADMISSION_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ModelMountAdmissionRunnerError(
        "Failed to spawn Rust model_mount admission bridge command.",
        "model_mount_admission_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new ModelMountAdmissionRunnerError(
        "Rust model_mount admission bridge command failed.",
        "model_mount_admission_bridge_failed",
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
      throw new ModelMountAdmissionRunnerError(
        "Rust model_mount admission bridge command returned invalid JSON.",
        "model_mount_admission_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new ModelMountAdmissionRunnerError(
        parsed.error?.message ?? "Rust model_mount core rejected the admission request.",
        parsed.error?.code ?? "model_mount_admission_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class ModelMountAdmissionRunnerError extends Error {
  constructor(message, code = "model_mount_admission_runner_error", details = {}) {
    super(message);
    this.name = "ModelMountAdmissionRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function normalizeRouteDecisionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
    record,
    route_decision_ref: result.route_decision_ref ?? record.route_decision_ref ?? null,
    route_decision_hash: result.route_decision_hash ?? record.route_decision_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
  };
}

function normalizeInvocationBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_invocation_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
    record,
    invocation_admission_ref: result.invocation_admission_ref ?? record.invocation_admission_ref ?? null,
    invocation_admission_hash: result.invocation_admission_hash ?? record.invocation_admission_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
  };
}

function normalizeInvocationReceiptBindingBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    source: result.source ?? "rust_model_mount_receipt_binding_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
    invocation: result.invocation ?? null,
    result: result.result ?? null,
    router_admission: result.router_admission ?? null,
    receipt_binding: result.receipt_binding ?? null,
    accepted_receipt_append: result.accepted_receipt_append ?? null,
    agentgres_admission: result.agentgres_admission ?? null,
    projection_record: result.projection_record ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : [],
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
