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
export const AGENTGRES_STORAGE_BACKEND_WRITE_API_METHOD = "admitStorageBackendWrite";
export const AGENTGRES_CODING_TOOL_RESULT_EVENT_API_METHOD = "admitCodingToolResultEvent";
export const AGENTGRES_CODING_TOOL_COMMAND_STREAM_API_METHOD =
  "admitCodingToolCommandStreamEvents";
export const AGENTGRES_RUNTIME_THREAD_EVENT_API_METHOD = "admitRuntimeThreadEvent";
export const AGENTGRES_RUNTIME_THREAD_EVENTS_PROJECTION_API_METHOD = "projectRuntimeThreadEvents";
export const AGENTGRES_RUNTIME_THREAD_EVENT_REPLAY_API_METHOD =
  "projectRuntimeThreadEventReplay";
export const AGENTGRES_RUNTIME_THREAD_TURN_PROJECTION_API_METHOD = "projectRuntimeThreadTurnProjection";
export const AGENTGRES_RUNTIME_RUN_STATE_COMMIT_API_METHOD = "commitRuntimeRunState";
export const AGENTGRES_RUNTIME_AGENT_STATE_COMMIT_API_METHOD = "commitRuntimeAgentState";
export const AGENTGRES_RUNTIME_MEMORY_STATE_COMMIT_API_METHOD = "commitRuntimeMemoryState";
export const AGENTGRES_RUNTIME_SUBAGENT_STATE_COMMIT_API_METHOD = "commitRuntimeSubagentState";
export const AGENTGRES_RUNTIME_ARTIFACT_STATE_COMMIT_API_METHOD = "commitRuntimeArtifactState";
export const AGENTGRES_RUNTIME_RECEIPT_STATE_COMMIT_API_METHOD = "commitRuntimeReceiptState";
export const AGENTGRES_RUNTIME_MCP_LIVE_RESULT_STATE_COMMIT_API_METHOD =
  "commitRuntimeMcpLiveResultState";
export const AGENTGRES_RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_API_METHOD =
  "commitRuntimeModelMountRecordState";
export const AGENTGRES_RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_API_METHOD =
  "commitRuntimeModelMountReceiptState";

export function createRuntimeAgentgresAdmissionCore(options = {}) {
  return new RuntimeAgentgresAdmissionCore(options);
}

export class RuntimeAgentgresAdmissionCore {
  constructor(options = {}) {
    assertNoRetiredRuntimeAgentgresCoreOption("command", options.command);
    assertNoRetiredRuntimeAgentgresCoreOption("args", options.args);
    assertNoRetiredRuntimeAgentgresCoreOption("env", options.env);
    assertNoRetiredRuntimeAgentgresCoreOption("daemonCoreInvoker", options.daemonCoreInvoker);
    this.daemonCoreAgentgresApi = agentgresApi(
      options.daemonCoreAgentgresApi ??
        options.daemonCoreApi?.agentgres ??
        options.daemonCoreApi?.runtimeAgentgres ??
        options.daemonCoreApi?.runtime_agentgres ??
        options.daemonCoreApi,
    );
  }

  admitStorageBackendWrite(request = {}) {
    return this.invokeRustAgentgresApi(AGENTGRES_STORAGE_BACKEND_WRITE_API_METHOD, {
      request,
    });
  }

  admitCodingToolResultEvent(request = {}) {
    return this.invokeRustAgentgresApi(AGENTGRES_CODING_TOOL_RESULT_EVENT_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  admitCodingToolCommandStreamEvents(request = {}) {
    return this.invokeRustAgentgresApi(AGENTGRES_CODING_TOOL_COMMAND_STREAM_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  admitRuntimeThreadEvent(request = {}) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_THREAD_EVENT_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectRuntimeThreadEvents(request = {}) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_THREAD_EVENTS_PROJECTION_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectRuntimeThreadEventReplay(request = {}) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_THREAD_EVENT_REPLAY_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectRuntimeThreadTurnProjection(request = {}) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_THREAD_TURN_PROJECTION_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  commitRuntimeRunState(stateDir, request) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_RUN_STATE_COMMIT_API_METHOD, {
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeAgentState(stateDir, request) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_AGENT_STATE_COMMIT_API_METHOD, {
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeMemoryState(stateDir, request) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_MEMORY_STATE_COMMIT_API_METHOD, {
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeSubagentState(stateDir, request) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_SUBAGENT_STATE_COMMIT_API_METHOD, {
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeArtifactState(stateDir, request) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_ARTIFACT_STATE_COMMIT_API_METHOD, {
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeReceiptState(stateDir, request) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_RECEIPT_STATE_COMMIT_API_METHOD, {
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeMcpLiveResultState(stateDir, request) {
    return this.invokeRustAgentgresApi(AGENTGRES_RUNTIME_MCP_LIVE_RESULT_STATE_COMMIT_API_METHOD, {
      state_dir: stateDir,
      request,
    });
  }

  commitRuntimeModelMountRecordState(stateDir, request) {
    return this.invokeRustAgentgresApi(
      AGENTGRES_RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_API_METHOD,
      {
        state_dir: stateDir,
        request,
      },
    );
  }

  commitRuntimeModelMountReceiptState(stateDir, request) {
    return this.invokeRustAgentgresApi(
      AGENTGRES_RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_API_METHOD,
      {
        state_dir: stateDir,
        request,
      },
    );
  }

  invokeRustAgentgresApi(method, request) {
    const invoke = this.daemonCoreAgentgresApi?.[method];
    if (typeof invoke !== "function") {
      throw new RuntimeAgentgresAdmissionCoreError(
        `Runtime Agentgres admission requires daemonCoreAgentgresApi.${method} for Rust daemon-core Agentgres admission, receipt/state-root binding, storage writes, and replay/projection.`,
        "runtime_agentgres_admission_core_direct_agentgres_api_unconfigured",
        {
          boundary: `daemonCoreAgentgresApi.${method}`,
          backend: RUST_RUNTIME_AGENTGRES_BACKEND,
        },
      );
    }
    const response = invoke.call(this.daemonCoreAgentgresApi, request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeAgentgresAdmissionCoreError(
        error.message ?? "Rust runtime Agentgres core rejected the transition request.",
        error.code ?? "runtime_agentgres_admission_core_direct_agentgres_api_rejected",
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
    "Runtime Agentgres compatibility options are retired; use daemonCoreAgentgresApi for direct Rust daemon-core Agentgres APIs.",
    "runtime_agentgres_admission_core_compatibility_option_retired",
    {
      status: 400,
      option: name,
    },
  );
}

function agentgresApi(value) {
  return objectRecord(value);
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}
