import { spawnSync } from "node:child_process";

export const RUNTIME_AGENTGRES_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const RUNTIME_AGENTGRES_COMMAND_ARGS_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS";
export const RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_RUNTIME_AGENTGRES_BACKEND = "rust_runtime_agentgres";
export const RUST_AGENTGRES_STORAGE_BACKEND = "rust_agentgres_storage";

export function createRuntimeAgentgresAdmissionRunnerFromEnv(env = process.env, options = {}) {
  return new RustRuntimeAgentgresAdmissionRunner({
    command: options.command ?? env[RUNTIME_AGENTGRES_COMMAND_ENV] ?? null,
    args:
      options.args ??
      parseCommandArgs(env[RUNTIME_AGENTGRES_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustRuntimeAgentgresAdmissionRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  admitStorageBackendWrite(request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "admit_storage_backend_write",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      request,
    };
    return normalizeStorageBackendWriteBridgeResult(this.invokeBridge(bridgeRequest));
  }

  commitRuntimeRunState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_run_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeRunStateCommitBridgeResult(this.invokeBridge(bridgeRequest));
  }

  commitRuntimeAgentState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_agent_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeAgentStateCommitBridgeResult(this.invokeBridge(bridgeRequest));
  }

  commitRuntimeMemoryState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_memory_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeMemoryStateCommitBridgeResult(this.invokeBridge(bridgeRequest));
  }

  commitRuntimeSubagentState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_subagent_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeSubagentStateCommitBridgeResult(this.invokeBridge(bridgeRequest));
  }

  commitRuntimeArtifactState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_artifact_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeArtifactStateCommitBridgeResult(this.invokeBridge(bridgeRequest));
  }

  commitRuntimeModelMountRecordState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_model_mount_record_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeModelMountRecordStateCommitBridgeResult(this.invokeBridge(bridgeRequest));
  }

  commitRuntimeModelMountReceiptState(stateDir, request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "commit_runtime_model_mount_receipt_state",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      state_dir: stateDir,
      request,
    };
    return normalizeRuntimeModelMountReceiptStateCommitBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_runtime_agentgres_mock",
        backend: request.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new RuntimeAgentgresAdmissionRunnerError(
        "Runtime Agentgres admission requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core admission.",
        "runtime_agentgres_admission_bridge_unconfigured",
        {
          env: RUNTIME_AGENTGRES_COMMAND_ENV,
          argsEnv: RUNTIME_AGENTGRES_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new RuntimeAgentgresAdmissionRunnerError(
        "Failed to spawn Rust runtime Agentgres admission bridge command.",
        "runtime_agentgres_admission_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new RuntimeAgentgresAdmissionRunnerError(
        "Rust runtime Agentgres admission bridge command failed.",
        "runtime_agentgres_admission_bridge_failed",
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
      throw new RuntimeAgentgresAdmissionRunnerError(
        "Rust runtime Agentgres admission bridge command returned invalid JSON.",
        "runtime_agentgres_admission_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new RuntimeAgentgresAdmissionRunnerError(
        parsed.error?.message ?? "Rust runtime Agentgres core rejected the transition request.",
        parsed.error?.code ?? "runtime_agentgres_admission_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
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
    artifact_refs: Array.isArray(result.artifact_refs) ? result.artifact_refs : record.artifact_refs ?? [],
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : record.payload_refs ?? [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    records: Array.isArray(result.records) ? result.records : storageWriteSet.records ?? [],
    written_records: Array.isArray(result.written_records) ? result.written_records : [],
    materialization_hash:
      result.materialization_hash ?? materialization.materialization_hash ?? null,
    write_set_hash: result.write_set_hash ?? storageWriteSet.write_set_hash ?? null,
    persistence_hash: result.persistence_hash ?? persistence.persistence_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? [],
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? [],
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? [],
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? [],
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? [],
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : storageRecord.payload_refs ?? [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : storageRecord.receipt_refs ?? [],
    admission_hash: result.admission_hash ?? storageRecord.admission?.admission_hash ?? null,
    commit_hash: result.commit_hash ?? record.commit_hash ?? null,
    written_record: result.written_record ?? null,
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
