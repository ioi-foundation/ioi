import { spawnSync } from "node:child_process";

import {
  createCodingToolStepModuleProjection,
} from "./step-module-abi.mjs";

export const WORKLOAD_GRPC_ADDR_ENV = "IOI_WORKLOAD_GRPC_ADDR";
export const WORKLOAD_SHMEM_ID_ENV = "IOI_SHMEM_ID";
export const STEP_MODULE_COMMAND_ENV = "IOI_STEP_MODULE_COMMAND";

const COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";

export function createStepModuleRunnerFromEnv(env = process.env, options = {}) {
  assertNoStepModuleBackendSelection(options.backend ?? env.IOI_STEP_MODULE_BACKEND);
  assertNoStepModuleCommandArgs(options.args ?? env.IOI_STEP_MODULE_COMMAND_ARGS);
  return new RustWorkloadStepModuleRunner({
    command: options.command ?? env[STEP_MODULE_COMMAND_ENV] ?? null,
    grpcAddr: options.grpcAddr ?? env[WORKLOAD_GRPC_ADDR_ENV] ?? null,
    shmemId: options.shmemId ?? env[WORKLOAD_SHMEM_ID_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function assertNoStepModuleBackendSelection(value) {
  if (typeof value !== "string" || value.trim().length === 0) return;
  throw new StepModuleRunnerError(
    "StepModule backend selection is retired; runtime-daemon StepModule execution is rust_workload_live.",
    "step_module_backend_selection_retired",
    { retired_backend: value, backend: "rust_workload_live" },
  );
}

export function assertNoStepModuleCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new StepModuleRunnerError(
    "StepModule command argument selection is retired; command-bridge argv is fixed migration transport.",
    "step_module_command_args_retired",
    { retired_args: value },
  );
}

export class StepModuleRunner {
  constructor() {
    this.backend = "rust_workload_live";
  }

  get blocksDaemonJsExecution() {
    return true;
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
    assertNoStepModuleBackendSelection(options.backend);
    assertNoStepModuleCommandArgs(options.args);
    super();
    this.command = optionalString(options.command);
    this.grpcAddr = optionalString(options.grpcAddr);
    this.shmemId = optionalString(options.shmemId);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  get blocksDaemonJsExecution() {
    return true;
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
        "live",
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
      mode: "live",
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
    const output = this.spawnSyncImpl(this.command, [], {
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

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
