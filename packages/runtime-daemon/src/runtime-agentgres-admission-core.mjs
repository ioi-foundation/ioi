export const RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_RUNTIME_AGENTGRES_BACKEND = "rust_runtime_agentgres";
export const RUST_AGENTGRES_STORAGE_BACKEND = "rust_agentgres_storage";
export const CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-result-event-admission-request.v1";
export const CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-command-stream-admission-request.v1";
export const RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.thread-event-admission-request.v1";
export const RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.thread-event-projection-request.v1";
export const RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.thread-event-replay-request.v1";
export const RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.thread-turn-projection-request.v1";

export function createRuntimeAgentgresAdmissionCore(options = {}) {
  return new RuntimeAgentgresAdmissionCore(options);
}

export class RuntimeAgentgresAdmissionCore {
  constructor(options = {}) {
    assertNoRetiredRuntimeAgentgresCoreOption("command", options.command);
    assertNoRetiredRuntimeAgentgresCoreOption("args", options.args);
    assertNoRetiredRuntimeAgentgresCoreOption("env", options.env);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitStorageBackendWrite(request = {}) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "admit_storage_backend_write",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      request,
    });
  }

  admitCodingToolResultEvent(request = {}) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "admit_coding_tool_result_event",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  admitCodingToolCommandStreamEvents(request = {}) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "admit_coding_tool_command_stream_events",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  admitRuntimeThreadEvent(request = {}) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "admit_runtime_thread_event",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectRuntimeThreadEvents(request = {}) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "project_runtime_thread_events",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectRuntimeThreadEventReplay(request = {}) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "project_runtime_thread_event_replay",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectRuntimeThreadTurnProjection(request = {}) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "project_runtime_thread_turn_projection",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  commitRuntimeRunState(stateDir, request) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "commit_runtime_run_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeAgentState(stateDir, request) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "commit_runtime_agent_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeMemoryState(stateDir, request) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "commit_runtime_memory_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeSubagentState(stateDir, request) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "commit_runtime_subagent_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeArtifactState(stateDir, request) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "commit_runtime_artifact_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeModelMountRecordState(stateDir, request) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "commit_runtime_model_mount_record_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeModelMountReceiptState(stateDir, request) {
    return this.invokeDaemonCore({
      schema_version: RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
      operation: "commit_runtime_model_mount_receipt_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    });
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeAgentgresAdmissionCoreError(
        "Runtime Agentgres admission requires daemonCoreInvoker for direct Rust daemon-core Agentgres admission, receipt/state-root binding, storage writes, and replay/projection.",
        "runtime_agentgres_admission_core_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeAgentgresAdmissionCoreError(
        error.message ?? "Rust runtime Agentgres core rejected the transition request.",
        error.code ?? "runtime_agentgres_admission_core_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class RuntimeAgentgresAdmissionCoreError extends Error {
  constructor(message, code = "runtime_agentgres_admission_core_error", details = {}) {
    super(message);
    this.name = "RuntimeAgentgresAdmissionCoreError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function assertNoRetiredRuntimeAgentgresCoreOption(name, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeAgentgresAdmissionCoreError(
    "Runtime Agentgres compatibility options are retired; use the mounted daemonCoreInvoker-backed core API.",
    "runtime_agentgres_admission_core_compatibility_option_retired",
    {
      status: 400,
      option: name,
    },
  );
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}
