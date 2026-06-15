export const WORKLOAD_GRPC_ADDR_ENV = "IOI_WORKLOAD_GRPC_ADDR";
export const WORKLOAD_SHMEM_ID_ENV = "IOI_SHMEM_ID";

export const WORKLOAD_STEP_MODULE_API_METHOD = "runCodingToolStepModule";
const CODING_TOOL_STEP_MODULE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-step-module-request.v1";

export function createStepModuleRunnerFromEnv(env = process.env, options = {}) {
  assertNoStepModuleBackendSelection(options.backend ?? env.IOI_STEP_MODULE_BACKEND);
  assertNoStepModuleCommandArgs(
    options.args ?? env.IOI_STEP_MODULE_COMMAND_ARGS ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS,
  );
  assertNoStepModuleCommandSelection(
    options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND ?? env.IOI_STEP_MODULE_COMMAND,
  );
  assertNoStepModuleCommandInvoker("daemonCoreInvoker", options.daemonCoreInvoker);
  return new RustWorkloadStepModuleRunner({
    daemonCoreWorkloadApi: options.daemonCoreWorkloadApi,
    grpcAddr: options.grpcAddr ?? env[WORKLOAD_GRPC_ADDR_ENV] ?? null,
    shmemId: options.shmemId ?? env[WORKLOAD_SHMEM_ID_ENV] ?? null,
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
    "StepModule binary command selection is retired; use daemonCoreWorkloadApi.runCodingToolStepModule for direct Rust daemon-core StepModule execution.",
    "step_module_command_selection_retired",
    { retired_command: value },
  );
}

export function assertNoStepModuleCommandInvoker(field, value) {
  if (value == null) return;
  throw new StepModuleRunnerError(
    "StepModule generic daemon-core invokers are retired; use daemonCoreWorkloadApi.runCodingToolStepModule.",
    "step_module_daemon_core_invoker_retired",
    { retired_option: field },
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
    assertNoStepModuleCommandSelection(options.command);
    assertNoStepModuleCommandInvoker("daemonCoreInvoker", options.daemonCoreInvoker);
    this.daemonCoreWorkloadApi = workloadApi(options.daemonCoreWorkloadApi);
  }

  get blocksDaemonJsExecution() {
    return true;
  }

  runCodingTool({ toolId, input = {}, context = {} } = {}) {
    const request = {
      schema_version: CODING_TOOL_STEP_MODULE_REQUEST_SCHEMA_VERSION,
      workload_grpc_addr: this.grpcAddr,
      shmem_id: this.shmemId,
      tool_id: optionalString(toolId),
      workspace_root: context.workspace_root ?? null,
      run_id: context.run_id ?? null,
      task_id: context.task_id ?? null,
      thread_id: context.thread_id ?? null,
      workflow_graph_id: context.workflow_graph_id ?? null,
      workflow_node_id: context.workflow_node_id ?? null,
      context_chamber_ref: context.context_chamber_ref ?? null,
      action_proposal_ref: context.action_proposal_ref ?? null,
      gate_result_ref: context.gate_result_ref ?? null,
      authority_grant_refs: normalizeStringArray(context.authority_grant_refs),
      approval_ref: context.approval_ref ?? null,
      state_root_before: context.state_root_before ?? null,
      projection_watermark: context.projection_watermark ?? null,
      artifact_refs: normalizeStringArray(context.artifact_refs),
      payload_refs: normalizeStringArray(context.payload_refs),
      data_plane_handle: context.data_plane_handle ?? null,
      idempotency_key: context.idempotency_key ?? null,
      deadline_ms: context.deadline_ms ?? null,
      manifest_ref: context.manifest_ref ?? null,
      input,
    };
    const workloadApiResult = this.invokeWorkloadApi(request);
    return {
      backend: this.backend,
      mode: "live",
      blocking: this.blocksDaemonJsExecution,
      source: workloadApiResult.source,
      workload_result: workloadApiResult,
      invocation: workloadApiResult.invocation ?? null,
      result: workloadApiResult.result ?? null,
    };
  }

  invokeWorkloadApi(request) {
    const invoke = this.daemonCoreWorkloadApi?.[WORKLOAD_STEP_MODULE_API_METHOD];
    if (typeof invoke !== "function") {
      throw new StepModuleRunnerError(
        "Rust workload StepModule runner requires daemonCoreWorkloadApi.runCodingToolStepModule for direct Rust daemon-core StepModule execution.",
        "rust_workload_api_unconfigured",
        { boundary: "daemonCoreWorkloadApi.runCodingToolStepModule" },
      );
    }
    const response = invoke.call(this.daemonCoreWorkloadApi, request);
    const responseError = objectRecord(response?.error);
    if (response?.ok === false && responseError) {
      throw new StepModuleRunnerError(
        responseError.message ?? "Rust workload StepModule core rejected the invocation.",
        responseError.code ?? "rust_workload_api_rejected",
        { error: responseError },
      );
    }
    const result = response?.ok === true ? response.result : response;
    return normalizeWorkloadApiResult(result, {
      source: "rust_workload_api",
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

function normalizeWorkloadApiResult(value, defaults = {}) {
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

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function workloadApi(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return typeof value[WORKLOAD_STEP_MODULE_API_METHOD] === "function" ? value : null;
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((entry) => typeof entry === "string" && entry.trim()).map((entry) => entry.trim());
}
