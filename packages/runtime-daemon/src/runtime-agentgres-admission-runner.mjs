export const RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
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

export function createRuntimeAgentgresAdmissionRunnerFromEnv(env = process.env, options = {}) {
  assertNoRuntimeAgentgresCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  assertNoRuntimeAgentgresCommandSelection(
    options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND ?? env.IOI_RUNTIME_AGENTGRES_COMMAND,
  );
  return new RustRuntimeAgentgresAdmissionRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
  });
}

export function assertNoRuntimeAgentgresCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeAgentgresAdmissionRunnerError(
    "Runtime Agentgres command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "runtime_agentgres_command_args_retired",
    { retired_args: value },
  );
}

export function assertNoRuntimeAgentgresCommandSelection(value) {
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeAgentgresAdmissionRunnerError(
    "Runtime Agentgres binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core Agentgres admission.",
    "runtime_agentgres_command_selection_retired",
    { retired_command: value },
  );
}

export class RustRuntimeAgentgresAdmissionRunner {
  constructor(options = {}) {
    assertNoRuntimeAgentgresCommandArgs(options.args);
    assertNoRuntimeAgentgresCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitStorageBackendWrite(request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "admit_storage_backend_write",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      request,
    };
    return normalizeStorageBackendWriteBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  admitCodingToolResultEvent(request = {}) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "admit_coding_tool_result_event",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...request,
        schema_version: CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeCodingToolResultEventAdmissionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  admitCodingToolCommandStreamEvents(request = {}) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "admit_coding_tool_command_stream_events",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...request,
        schema_version: CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeCodingToolCommandStreamAdmissionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  admitRuntimeThreadEvent(request = {}) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "admit_runtime_thread_event",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...request,
        schema_version: RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeRuntimeThreadEventAdmissionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  projectRuntimeThreadEvents(request = {}) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "project_runtime_thread_events",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...request,
        schema_version: RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeRuntimeThreadEventProjectionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  projectRuntimeThreadEventReplay(request = {}) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "project_runtime_thread_event_replay",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...request,
        schema_version: RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeRuntimeThreadEventReplayBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  projectRuntimeThreadTurnProjection(request = {}) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "project_runtime_thread_turn_projection",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request: {
        ...request,
        schema_version: RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeRuntimeThreadTurnProjectionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  commitRuntimeRunState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_run_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeRunStateCommitBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  commitRuntimeAgentState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_agent_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeAgentStateCommitBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  commitRuntimeMemoryState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_memory_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeMemoryStateCommitBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  commitRuntimeSubagentState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_subagent_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeSubagentStateCommitBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  commitRuntimeArtifactState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_artifact_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeArtifactStateCommitBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  commitRuntimeModelMountRecordState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_model_mount_record_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeModelMountRecordStateCommitBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  commitRuntimeModelMountReceiptState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_model_mount_receipt_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeModelMountReceiptStateCommitBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeAgentgresAdmissionRunnerError(
        "Runtime Agentgres admission requires daemonCoreInvoker for direct Rust daemon-core Agentgres admission.",
        "runtime_agentgres_admission_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeAgentgresAdmissionRunnerError(
        error.message ?? "Rust runtime Agentgres core rejected the transition request.",
        error.code ?? "runtime_agentgres_admission_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class RuntimeAgentgresAdmissionRunnerError extends Error {
  constructor(message, code = "runtime_agentgres_admission_runner_error", details = {}) {
    super(message);
    this.name = "RuntimeAgentgresAdmissionRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeStorageBackendWriteBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_agentgres_storage_write_admission_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    admission_hash: result.admission_hash ?? record.admission_hash ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    object_ref: result.object_ref ?? record.object_ref ?? null,
    content_hash: result.content_hash ?? record.content_hash ?? null,
    artifact_refs: Array.isArray(result.artifact_refs) ? result.artifact_refs : record.artifact_refs ?? null,
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : record.payload_refs ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeCodingToolResultEventAdmissionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const event = result.event && typeof result.event === "object" && !Array.isArray(result.event)
    ? result.event
    : record.event && typeof record.event === "object" && !Array.isArray(record.event)
      ? record.event
      : null;
  return {
    source: result.source ?? "rust_coding_tool_result_event_admission_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: result.admitted ?? record.status === "admitted",
    record,
    event,
    event_id: result.event_id ?? record.event_id ?? event?.event_id ?? null,
    seq: result.seq ?? record.seq ?? event?.seq ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    operation_ref: result.operation_ref ?? record.operation_ref ?? event?.agentgres_operation_ref ?? null,
    state_root_before: result.state_root_before ?? record.state_root_before ?? event?.state_root_before ?? null,
    state_root_after: result.state_root_after ?? record.state_root_after ?? event?.state_root_after ?? null,
    resulting_head: result.resulting_head ?? record.resulting_head ?? event?.resulting_head ?? null,
    projection_watermark: result.projection_watermark ?? record.projection_watermark ?? event?.projection_watermark ?? null,
    payload_refs: arrayOrNull(result.payload_refs) ?? arrayOrNull(record.payload_refs) ?? arrayOrNull(event?.payload_refs),
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(record.receipt_refs) ?? arrayOrNull(event?.receipt_refs),
    artifact_refs: arrayOrNull(result.artifact_refs) ?? arrayOrNull(record.artifact_refs) ?? arrayOrNull(event?.artifact_refs),
    rollback_refs: arrayOrNull(result.rollback_refs) ?? arrayOrNull(record.rollback_refs) ?? arrayOrNull(event?.rollback_refs),
    storage_admission: result.storage_admission ?? record.storage_admission ?? null,
    admission_hash: result.admission_hash ?? record.admission_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeCodingToolCommandStreamAdmissionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const events = arrayOrNull(result.events) ?? arrayOrNull(record.events) ?? [];
  return {
    source: result.source ?? "rust_coding_tool_command_stream_admission_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: result.admitted ?? record.status === "admitted",
    record,
    events,
    event_count: result.event_count ?? record.event_count ?? events.length,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    state_root_before: result.state_root_before ?? record.state_root_before ?? null,
    state_root_after: result.state_root_after ?? record.state_root_after ?? null,
    resulting_head: result.resulting_head ?? record.resulting_head ?? null,
    projection_watermark: result.projection_watermark ?? record.projection_watermark ?? null,
    payload_refs: arrayOrNull(result.payload_refs) ?? arrayOrNull(record.payload_refs),
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(record.receipt_refs),
    artifact_refs: arrayOrNull(result.artifact_refs) ?? arrayOrNull(record.artifact_refs),
    storage_admissions: arrayOrNull(result.storage_admissions) ?? arrayOrNull(record.storage_admissions),
    admission_hash: result.admission_hash ?? record.admission_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeThreadEventAdmissionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const event = result.event && typeof result.event === "object" && !Array.isArray(result.event)
    ? result.event
    : record.event && typeof record.event === "object" && !Array.isArray(record.event)
      ? record.event
      : null;
  return {
    source: result.source ?? "rust_runtime_thread_event_admission_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: result.admitted ?? record.status === "admitted",
    record,
    event,
    event_id: result.event_id ?? record.event_id ?? event?.event_id ?? null,
    seq: result.seq ?? record.seq ?? event?.seq ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    operation_ref: result.operation_ref ?? record.operation_ref ?? event?.agentgres_operation_ref ?? null,
    state_root_before: result.state_root_before ?? record.state_root_before ?? event?.state_root_before ?? null,
    state_root_after: result.state_root_after ?? record.state_root_after ?? event?.state_root_after ?? null,
    resulting_head: result.resulting_head ?? record.resulting_head ?? event?.resulting_head ?? null,
    projection_watermark: result.projection_watermark ?? record.projection_watermark ?? event?.projection_watermark ?? null,
    payload_refs: arrayOrNull(result.payload_refs) ?? arrayOrNull(record.payload_refs) ?? arrayOrNull(event?.payload_refs),
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(record.receipt_refs) ?? arrayOrNull(event?.receipt_refs),
    artifact_refs: arrayOrNull(result.artifact_refs) ?? arrayOrNull(record.artifact_refs) ?? arrayOrNull(event?.artifact_refs),
    rollback_refs: arrayOrNull(result.rollback_refs) ?? arrayOrNull(record.rollback_refs) ?? arrayOrNull(event?.rollback_refs),
    storage_admission: result.storage_admission ?? record.storage_admission ?? null,
    admission_hash: result.admission_hash ?? record.admission_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeThreadEventProjectionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const events = arrayOrNull(result.events) ?? arrayOrNull(record.events) ?? [];
  const admissions = arrayOrNull(result.admissions) ?? arrayOrNull(record.admissions) ?? [];
  return {
    source: result.source ?? "rust_runtime_thread_event_projection_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: result.projected ?? record.status === "projected",
    record,
    events,
    admissions,
    event_count: result.event_count ?? record.event_count ?? events.length,
    skipped_count: result.skipped_count ?? record.skipped_count ?? 0,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    projection_kind: result.projection_kind ?? record.projection_kind ?? null,
    resulting_seq: result.resulting_seq ?? record.resulting_seq ?? null,
    resulting_head: result.resulting_head ?? record.resulting_head ?? null,
    state_root_after: result.state_root_after ?? record.state_root_after ?? null,
    projection_watermark: result.projection_watermark ?? record.projection_watermark ?? null,
    payload_refs: arrayOrNull(result.payload_refs) ?? arrayOrNull(record.payload_refs),
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(record.receipt_refs),
    artifact_refs: arrayOrNull(result.artifact_refs) ?? arrayOrNull(record.artifact_refs),
    projection_hash: result.projection_hash ?? record.projection_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeThreadEventReplayBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const events = arrayOrNull(result.events) ?? arrayOrNull(record.events) ?? [];
  return {
    source: result.source ?? "rust_runtime_thread_event_replay_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: result.projected ?? record.status === "projected",
    record,
    events,
    event_count: result.event_count ?? record.event_count ?? events.length,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    replay_kind: result.replay_kind ?? record.replay_kind ?? null,
    latest_seq: result.latest_seq ?? record.latest_seq ?? null,
    cursor_seq: result.cursor_seq ?? record.cursor_seq ?? null,
    resulting_seq: result.resulting_seq ?? record.resulting_seq ?? null,
    resulting_head: result.resulting_head ?? record.resulting_head ?? null,
    state_root_after: result.state_root_after ?? record.state_root_after ?? null,
    projection_watermark: result.projection_watermark ?? record.projection_watermark ?? null,
    payload_refs: arrayOrNull(result.payload_refs) ?? arrayOrNull(record.payload_refs),
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(record.receipt_refs),
    artifact_refs: arrayOrNull(result.artifact_refs) ?? arrayOrNull(record.artifact_refs),
    replay_hash: result.replay_hash ?? record.replay_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeThreadTurnProjectionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const projection = result.projection && typeof result.projection === "object" ? result.projection : {};
  const record = result.record && typeof result.record === "object"
    ? result.record
    : projection.record && typeof projection.record === "object"
      ? projection.record
      : {};
  return {
    source: result.source ?? "rust_runtime_thread_turn_projection_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: result.projected ?? projection.status === "projected",
    projection,
    record,
    event_count: result.event_count ?? projection.event_count ?? null,
    operation_kind: result.operation_kind ?? projection.operation_kind ?? null,
    projection_kind: result.projection_kind ?? projection.projection_kind ?? null,
    thread_id: result.thread_id ?? projection.thread_id ?? record.thread_id ?? null,
    turn_id: result.turn_id ?? projection.turn_id ?? record.turn_id ?? null,
    latest_seq: result.latest_seq ?? projection.latest_seq ?? record.latest_seq ?? null,
    projection_hash: result.projection_hash ?? projection.projection_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeRunStateCommitBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const transition = result.transition && typeof result.transition === "object"
    ? result.transition
    : record.transition ?? {};
  const persistence = result.persistence && typeof result.persistence === "object"
    ? result.persistence
    : record.persistence ?? {};
  const materialization = persistence.materialization && typeof persistence.materialization === "object"
    ? persistence.materialization
    : {};
  const storageWriteSet = persistence.storage_write_set && typeof persistence.storage_write_set === "object"
    ? persistence.storage_write_set
    : {};
  return {
    source: result.source ?? "rust_agentgres_runtime_run_state_commit_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    transition,
    persistence,
    operation_ref: result.operation_ref ?? transition.operation_ref ?? null,
    state_root_after: result.state_root_after ?? transition.state_root_after ?? null,
    resulting_head: result.resulting_head ?? transition.resulting_head ?? null,
    transition_hash: result.transition_hash ?? transition.transition_hash ?? null,
    materialization,
    storage_write_set: storageWriteSet,
    records: arrayOrNull(result.records) ?? arrayOrNull(storageWriteSet.records),
    written_records: Array.isArray(result.written_records) ? result.written_records : null,
    materialization_hash:
      result.materialization_hash ?? materialization.materialization_hash ?? null,
    write_set_hash: result.write_set_hash ?? storageWriteSet.write_set_hash ?? null,
    persistence_hash: result.persistence_hash ?? persistence.persistence_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeAgentStateCommitBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const storageRecord = result.storage_record && typeof result.storage_record === "object"
    ? result.storage_record
    : record.record ?? {};
  return {
    source: result.source ?? "rust_agentgres_runtime_agent_state_commit_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    storage_record: storageRecord,
    agent_id: result.agent_id ?? record.agent_id ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    object_ref: result.object_ref ?? storageRecord.object_ref ?? null,
    content_hash: result.content_hash ?? storageRecord.content_hash ?? null,
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? null,
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeMemoryStateCommitBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const storageRecord = result.storage_record && typeof result.storage_record === "object"
    ? result.storage_record
    : record.record ?? {};
  return {
    source: result.source ?? "rust_agentgres_runtime_memory_state_commit_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    storage_record: storageRecord,
    memory_state_kind: result.memory_state_kind ?? record.memory_state_kind ?? null,
    state_id: result.state_id ?? record.state_id ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    object_ref: result.object_ref ?? storageRecord.object_ref ?? null,
    content_hash: result.content_hash ?? storageRecord.content_hash ?? null,
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? null,
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeSubagentStateCommitBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const storageRecord = result.storage_record && typeof result.storage_record === "object"
    ? result.storage_record
    : record.record ?? {};
  return {
    source: result.source ?? "rust_agentgres_runtime_subagent_state_commit_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    storage_record: storageRecord,
    subagent_id: result.subagent_id ?? record.subagent_id ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    object_ref: result.object_ref ?? storageRecord.object_ref ?? null,
    content_hash: result.content_hash ?? storageRecord.content_hash ?? null,
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? null,
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeArtifactStateCommitBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const storageRecord = result.storage_record && typeof result.storage_record === "object"
    ? result.storage_record
    : record.record ?? {};
  return {
    source: result.source ?? "rust_agentgres_runtime_artifact_state_commit_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    storage_record: storageRecord,
    artifact_id: result.artifact_id ?? record.artifact_id ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    object_ref: result.object_ref ?? storageRecord.object_ref ?? null,
    content_hash: result.content_hash ?? storageRecord.content_hash ?? null,
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? null,
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeModelMountRecordStateCommitBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const storageRecord = result.storage_record && typeof result.storage_record === "object"
    ? result.storage_record
    : record.record ?? {};
  return {
    source: result.source ?? "rust_agentgres_runtime_model_mount_record_state_commit_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    storage_record: storageRecord,
    record_dir: result.record_dir ?? record.record_dir ?? null,
    record_id: result.record_id ?? record.record_id ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    object_ref: result.object_ref ?? storageRecord.object_ref ?? null,
    content_hash: result.content_hash ?? storageRecord.content_hash ?? null,
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? null,
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

export function normalizeRuntimeModelMountReceiptStateCommitBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  const storageRecord = result.storage_record && typeof result.storage_record === "object"
    ? result.storage_record
    : record.record ?? {};
  return {
    source: result.source ?? "rust_agentgres_runtime_model_mount_receipt_state_commit_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    storage_record: storageRecord,
    receipt_id: result.receipt_id ?? record.receipt_id ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    object_ref: result.object_ref ?? storageRecord.object_ref ?? null,
    content_hash: result.content_hash ?? storageRecord.content_hash ?? null,
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? null,
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
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
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function arrayOrNull(value) {
  return Array.isArray(value) ? value : null;
}
