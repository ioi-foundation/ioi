import { spawnSync } from "node:child_process";

import {
  createCodingToolStepModuleProjection,
} from "./step-module-abi.mjs";

export const STEP_MODULE_BACKEND_ENV = "IOI_STEP_MODULE_BACKEND";
export const WORKLOAD_GRPC_ADDR_ENV = "IOI_WORKLOAD_GRPC_ADDR";
export const WORKLOAD_SHMEM_ID_ENV = "IOI_SHMEM_ID";
export const STEP_MODULE_COMMAND_ENV = "IOI_STEP_MODULE_COMMAND";
export const STEP_MODULE_COMMAND_ARGS_ENV = "IOI_STEP_MODULE_COMMAND_ARGS";

export const STEP_MODULE_BACKENDS = new Set([
  "rust_workload_shadow",
  "rust_workload_gated",
  "rust_workload_live",
]);

const COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";

export function createStepModuleRunnerFromEnv(env = process.env, options = {}) {
  const backend = normalizeStepModuleBackend(
    options.backend ?? env[STEP_MODULE_BACKEND_ENV] ?? "rust_workload_live",
  );
  return new RustWorkloadStepModuleRunner({
    backend,
    command: options.command ?? env[STEP_MODULE_COMMAND_ENV] ?? null,
    args: options.args ?? parseCommandArgs(env[STEP_MODULE_COMMAND_ARGS_ENV]),
    grpcAddr: options.grpcAddr ?? env[WORKLOAD_GRPC_ADDR_ENV] ?? null,
    shmemId: options.shmemId ?? env[WORKLOAD_SHMEM_ID_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function normalizeStepModuleBackend(value) {
  const normalized = String(value ?? "").trim().toLowerCase() || "rust_workload_live";
  if (!STEP_MODULE_BACKENDS.has(normalized)) {
    throw new StepModuleRunnerError(
      `Unknown StepModule backend "${value}".`,
      "step_module_backend_invalid",
      { backend: value },
    );
  }
  return normalized;
}

export class StepModuleRunner {
  constructor({ backend = "rust_workload_live" } = {}) {
    this.backend = normalizeStepModuleBackend(backend);
  }

  get blocksDaemonJsExecution() {
    return false;
  }

  runCodingTool() {
    throw new StepModuleRunnerError(
      "StepModuleRunner subclasses must implement runCodingTool.",
      "step_module_runner_not_implemented",
      { backend: this.backend },
    );
  }
}

export class RustWorkloadStepModuleRunner extends StepModuleRunner {
  constructor(options = {}) {
    super({ backend: options.backend ?? "rust_workload_shadow" });
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.grpcAddr = optionalString(options.grpcAddr);
    this.shmemId = optionalString(options.shmemId);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  get blocksDaemonJsExecution() {
    return this.backend === "rust_workload_gated" || this.backend === "rust_workload_live";
  }

  runCodingTool({ contract, toolId, input = {}, result = {}, context = {} } = {}) {
    const projection = createCodingToolStepModuleProjection({
      contract,
      toolId,
      input,
      result,
      ...context,
      module_kind: "workload_job",
      execution_backend: "workload_grpc",
      workflow_projection_status:
        context.workflow_projection_status ??
        (this.backend === "rust_workload_shadow" ? "shadow" : "gated"),
    });
    const request = {
      schema_version: COMMAND_SCHEMA_VERSION,
      operation: "run_coding_tool_step_module",
      backend: this.backend,
      workload_grpc_addr: this.grpcAddr,
      shmem_id: this.shmemId,
      invocation: projection.invocation,
      workspace_root: context.workspace_root ?? null,
      input,
    };
    const bridgeResult = this.invokeBridge(request);
    return {
      backend: this.backend,
      mode: this.backend.replace("rust_workload_", ""),
      blocking: this.blocksDaemonJsExecution,
      source: bridgeResult.source,
      bridge_result: bridgeResult,
      invocation: bridgeResult.invocation ?? projection.invocation,
      result: bridgeResult.result ?? projection.result,
    };
  }

  invokeBridge(request) {
    if (this.mockResult) {
      return normalizeBridgeResult(this.mockResult, {
        source: "rust_workload_mock",
        invocation: request.invocation,
      });
    }
    if (!this.command) {
      throw new StepModuleRunnerError(
        "Rust workload StepModule runner requires IOI_STEP_MODULE_COMMAND for command-bridge execution.",
        "rust_workload_bridge_unconfigured",
        {
          backend: this.backend,
          env: STEP_MODULE_COMMAND_ENV,
          workloadGrpcAddrEnv: WORKLOAD_GRPC_ADDR_ENV,
          shmemIdEnv: WORKLOAD_SHMEM_ID_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new StepModuleRunnerError(
        "Failed to spawn Rust workload StepModule bridge command.",
        "rust_workload_bridge_spawn_failed",
        { backend: this.backend, error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new StepModuleRunnerError(
        "Rust workload StepModule bridge command failed.",
        "rust_workload_bridge_failed",
        {
          backend: this.backend,
          status: output.status,
          stderr: String(output.stderr ?? "").slice(0, 4096),
        },
      );
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new StepModuleRunnerError(
        "Rust workload StepModule bridge command returned invalid JSON.",
        "rust_workload_bridge_invalid_json",
        { backend: this.backend, error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new StepModuleRunnerError(
        parsed.error?.message ?? "Rust workload StepModule bridge rejected the invocation.",
        parsed.error?.code ?? "rust_workload_bridge_rejected",
        { backend: this.backend, error: parsed.error },
      );
    }
    return normalizeBridgeResult(parsed.result ?? parsed, {
      source: "rust_workload_command",
      invocation: request.invocation,
    });
  }
}

export class StepModuleRunnerError extends Error {
  constructor(message, code = "step_module_runner_error", details = {}) {
    super(message);
    this.name = "StepModuleRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function normalizeBridgeResult(value, defaults = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    ...result,
    source: result.source ?? defaults.source ?? "rust_workload",
    invocation: result.invocation ?? defaults.invocation ?? null,
    result: result.result ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : [],
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
