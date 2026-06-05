import { spawnSync } from "node:child_process";

export const RUNTIME_AGENTGRES_COMMAND_ENV = "IOI_RUNTIME_AGENTGRES_COMMAND";
export const RUNTIME_AGENTGRES_COMMAND_ARGS_ENV = "IOI_RUNTIME_AGENTGRES_COMMAND_ARGS";
export const RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
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

  planRunStateTransition(request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "plan_runtime_run_state_transition",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request,
    };
    return normalizeRunStateTransitionBridgeResult(this.invokeBridge(bridgeRequest));
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

  planRuntimeStateStorageWrites(request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "plan_runtime_state_storage_writes",
      backend: RUST_AGENTGRES_STORAGE_BACKEND,
      request,
    };
    return normalizeRuntimeStateStorageWriteSetBridgeResult(this.invokeBridge(bridgeRequest));
  }

  materializeRuntimeStateRecords(request) {
    const bridgeRequest = {
      schema_version: RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
      operation: "materialize_runtime_state_records",
      backend: RUST_RUNTIME_AGENTGRES_BACKEND,
      request,
    };
    return normalizeRuntimeStateRecordMaterializationBridgeResult(this.invokeBridge(bridgeRequest));
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
        "Runtime Agentgres admission requires IOI_RUNTIME_AGENTGRES_COMMAND for Rust core transition planning.",
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

export function normalizeRunStateTransitionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_runtime_agentgres_transition_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    record,
    operation_ref: result.operation_ref ?? record.operation_ref ?? null,
    expected_heads: Array.isArray(result.expected_heads) ? result.expected_heads : record.expected_heads ?? [],
    state_root_before: result.state_root_before ?? record.state_root_before ?? null,
    state_root_after: result.state_root_after ?? record.state_root_after ?? null,
    resulting_head: result.resulting_head ?? record.resulting_head ?? null,
    projection_watermark: result.projection_watermark ?? record.projection_watermark ?? null,
    transition_hash: result.transition_hash ?? record.transition_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    artifact_refs: Array.isArray(result.artifact_refs) ? result.artifact_refs : record.artifact_refs ?? [],
    payload_refs: Array.isArray(result.payload_refs) ? result.payload_refs : record.payload_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
  };
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

export function normalizeRuntimeStateStorageWriteSetBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_agentgres_runtime_state_storage_write_set_command",
    backend: result.backend ?? RUST_AGENTGRES_STORAGE_BACKEND,
    record,
    write_set_hash: result.write_set_hash ?? record.write_set_hash ?? null,
    storage_backend_ref: result.storage_backend_ref ?? record.storage_backend_ref ?? null,
    records: Array.isArray(result.records) ? result.records : record.records ?? [],
    storage_admissions: Array.isArray(result.storage_admissions) ? result.storage_admissions : [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
  };
}

export function normalizeRuntimeStateRecordMaterializationBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_agentgres_runtime_state_record_materialization_command",
    backend: result.backend ?? RUST_RUNTIME_AGENTGRES_BACKEND,
    record,
    records: Array.isArray(result.records) ? result.records : record.records ?? [],
    materialization_hash: result.materialization_hash ?? record.materialization_hash ?? null,
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
