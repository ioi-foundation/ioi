import {
  createStepModuleInvocationForCodingTool,
} from "./step-module-abi.mjs";
import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

export const WORKLOAD_GRPC_ADDR_ENV = "IOI_WORKLOAD_GRPC_ADDR";
export const WORKLOAD_SHMEM_ID_ENV = "IOI_SHMEM_ID";
export const DAEMON_CORE_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";

const COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";

export function createStepModuleRunnerFromEnv(env = process.env, options = {}) {
  assertNoStepModuleBackendSelection(options.backend ?? env.IOI_STEP_MODULE_BACKEND);
  assertNoStepModuleCommandArgs(options.args ?? env.IOI_STEP_MODULE_COMMAND_ARGS);
  assertNoStepModuleCommandSelection(env.IOI_STEP_MODULE_COMMAND);
  return new RustWorkloadStepModuleRunner({
    command: options.command ?? env[DAEMON_CORE_COMMAND_ENV] ?? null,
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

export function assertNoStepModuleCommandSelection(value) {
  if (typeof value !== "string" || value.trim().length === 0) return;
  throw new StepModuleRunnerError(
    "IOI_STEP_MODULE_COMMAND is retired; StepModule execution uses IOI_RUNTIME_DAEMON_CORE_COMMAND until direct Rust daemon-core APIs replace command transport.",
    "step_module_command_env_retired",
    { retired_env: "IOI_STEP_MODULE_COMMAND", env: DAEMON_CORE_COMMAND_ENV },
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
    this.grpcAddr = optionalString(options.grpcAddr);
    this.shmemId = optionalString(options.shmemId);
    this.invokeCommand = createDaemonCoreCommandInvoker({
      command: options.command,
      spawnSyncImpl: options.spawnSyncImpl,
      mockResult: options.mockResult,
      mockSource: "rust_workload_mock",
      defaultBackend: this.backend,
      ErrorClass: StepModuleRunnerError,
      env: DAEMON_CORE_COMMAND_ENV,
      unconfiguredMessage:
        "Rust workload StepModule runner requires IOI_RUNTIME_DAEMON_CORE_COMMAND for daemon-core command transport.",
      unconfiguredCode: "rust_workload_bridge_unconfigured",
      spawnFailedMessage: "Failed to spawn Rust workload StepModule bridge command.",
      spawnFailedCode: "rust_workload_bridge_spawn_failed",
      commandFailedMessage: "Rust workload StepModule bridge command failed.",
      commandFailedCode: "rust_workload_bridge_failed",
      invalidJsonMessage: "Rust workload StepModule bridge command returned invalid JSON.",
      invalidJsonCode: "rust_workload_bridge_invalid_json",
      rejectedMessage: "Rust workload StepModule bridge rejected the invocation.",
      rejectedCode: "rust_workload_bridge_rejected",
    });
  }

  get blocksDaemonJsExecution() {
    return true;
  }

  runCodingTool({ contract, toolId, input = {}, result = {}, context = {} } = {}) {
    const invocation = createStepModuleInvocationForCodingTool({
      contract,
      toolId,
      input,
      ...context,
      module_kind: "workload_job",
      execution_backend: "workload_grpc",
    });
    const request = {
      schema_version: COMMAND_SCHEMA_VERSION,
      operation: "run_coding_tool_step_module",
      backend: this.backend,
      workload_grpc_addr: this.grpcAddr,
      shmem_id: this.shmemId,
      invocation,
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
      invocation: bridgeResult.invocation ?? invocation,
      result: bridgeResult.result ?? null,
    };
  }

  invokeBridge(request) {
    return normalizeBridgeResult(this.invokeCommand(request), {
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
