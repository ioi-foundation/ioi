import {
  RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
} from "./model-mount-core.mjs";
import { commitModelMountRecordState } from "./record-state-commits.mjs";

const MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION = "ioi.model_mount.instance_lifecycle.v1";

export function loadedInstanceForEndpoint(state, endpointId, failIfMissing = true, deps = {}) {
  const { notFound } = deps;
  const instance = projectionRecords(state, "listInstances").find(
    (candidate) => (candidate.endpointId ?? candidate.endpoint_id) === endpointId && candidate.status === "loaded",
  );
  if (!instance && failIfMissing) {
    throw notFound(`No loaded model instance for endpoint: ${endpointId}`, { endpoint_id: endpointId });
  }
  return instance ?? null;
}

export function evictExpiredInstances(state) {
  const nowMs = state.now().getTime();
  let changed = false;
  for (const instance of projectionRecords(state, "listInstances")) {
    if (instance.status !== "loaded" || !instance.expiresAt || Date.parse(instance.expiresAt) > nowMs) {
      continue;
    }
    commitInstanceMaintenanceTransition(state, instance, {
      action: "evict",
      targetStatus: "evicted",
      operation: "model_idle_evict",
      operation_kind: "model_mount.instance.evict",
      reason: "idle_ttl",
      evidenceRefs: ["model_mount_instance_eviction_rust_positive_api"],
    });
    changed = true;
  }
  return changed;
}

export function coalesceLoadedInstances(state) {
  const instances = projectionRecords(state, "listInstances");
  const loadedByEndpoint = new Map();
  for (const instance of instances) {
    const endpointId = instance.endpointId ?? instance.endpoint_id;
    if (instance.status !== "loaded" || !endpointId) continue;
    const current = loadedByEndpoint.get(endpointId);
    if (!current || String(instance.loadedAt ?? "") > String(current.loadedAt ?? "")) {
      loadedByEndpoint.set(endpointId, instance);
    }
  }
  let changed = false;
  for (const instance of instances) {
    const endpointId = instance.endpointId ?? instance.endpoint_id;
    if (instance.status !== "loaded" || !endpointId) continue;
    const keeper = loadedByEndpoint.get(endpointId);
    if (!keeper || keeper.id === instance.id) continue;
    commitInstanceMaintenanceTransition(state, instance, {
      action: "supersede",
      targetStatus: "superseded",
      operation: "model_supersede",
      operation_kind: "model_mount.instance.supersede",
      reason: "endpoint_reload",
      superseded_by: keeper.id,
      evidenceRefs: ["model_mount_instance_supersede_rust_positive_api"],
    });
    changed = true;
  }
  return changed;
}

export function supersedeLoadedInstances(state, endpointId, keepInstanceId) {
  let changed = false;
  for (const instance of projectionRecords(state, "listInstances")) {
    if (instance.id === keepInstanceId || (instance.endpointId ?? instance.endpoint_id) !== endpointId || instance.status !== "loaded") continue;
    commitInstanceMaintenanceTransition(state, instance, {
      action: "supersede",
      targetStatus: "superseded",
      operation: "model_supersede",
      operation_kind: "model_mount.instance.supersede",
      reason: "endpoint_reload",
      superseded_by: keepInstanceId,
      evidenceRefs: ["model_mount_instance_supersede_rust_positive_api"],
    });
    changed = true;
  }
  return changed;
}

function commitInstanceMaintenanceTransition(state, instance, options = {}) {
  const lifecycle = planInstanceMaintenanceLifecycle(state, instance, options);
  const record = lifecycle.result;
  const commit = commitModelMountRecordState(state, {
    recordDir: "model-instances",
    record,
    operation_kind: options.operation_kind,
    receipt_refs: [],
    unconfiguredCode: "model_mount_instance_lifecycle_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Model instance lifecycle maintenance requires Rust Agentgres record-state commit before instance truth can change.",
    invalidCode: "model_mount_instance_lifecycle_record_state_commit_invalid",
  });
  return {
    ...record,
    object: "ioi.model_mount_instance",
    record_dir: "model-instances",
    record_id: record.id,
    record,
    commit,
    instance_lifecycle_hash: lifecycle.instance_lifecycle_hash ?? record.instance_lifecycle_hash ?? null,
    evidence_refs: lifecycle.evidence_refs ?? record.evidence_refs ?? [],
  };
}

function planInstanceMaintenanceLifecycle(state, instance, options = {}) {
  const request = modelMountInstanceMaintenanceRequest(state, instance, options);
  if (typeof state.planModelMountInstanceLifecycle !== "function") {
    throwInstanceMaintenanceRustCoreRequired(options.operation, instance, {
      operation_kind: options.operation_kind,
      reason: options.reason ?? null,
      superseded_by: options.superseded_by ?? null,
      rust_core_api: "plan_model_mount_instance_lifecycle",
    });
  }
  const result = state.planModelMountInstanceLifecycle(request);
  assertRustAuthoredInstanceMaintenanceResult(result, options);
  return result;
}

function modelMountInstanceMaintenanceRequest(state, instance = {}, options = {}) {
  const superseded_by = options.action === "supersede"
    ? requiredMaintenanceString(options.superseded_by, "superseded_by", instance, options)
    : null;
  return {
    schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
    instance_ref: requiredMaintenanceString(instance.id, "instance_id", instance, options),
    endpoint_ref: "",
    model_ref: "",
    provider_ref: "",
    action: options.action,
    target_status: options.targetStatus,
    execution_backend: RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
    backend_ref: "",
    driver: "",
    provider_lifecycle_hash: "",
    reason: options.reason ?? null,
    superseded_by: superseded_by,
    evidence_refs: [
      ...new Set([
        "public_model_instance_maintenance_rust_facade",
        options.operation,
        ...(options.evidenceRefs ?? []),
      ].filter(Boolean)),
    ],
    state_dir: requireInstanceLifecycleMountedStateDir(state, options.operation_kind),
  };
}

function assertRustAuthoredInstanceMaintenanceResult(result = {}, options = {}) {
  const record = result.result && typeof result.result === "object" && !Array.isArray(result.result)
    ? result.result
    : {};
  const evidenceRefs = Array.isArray(result.evidence_refs)
    ? result.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [];
  const missing = [];
  const mismatches = [];
  for (const field of ["id", "endpoint_id", "model_id", "provider_id", "instance_lifecycle_hash"]) {
    if (!record[field]) missing.push(`result.${field}`);
  }
  if (!result.executionBackend && !record.execution_backend) missing.push("execution_backend");
  if (!result.status && !record.status) missing.push("status");
  if (!evidenceRefs.includes("rust_model_mount_instance_lifecycle")) {
    missing.push("evidence_refs.rust_model_mount_instance_lifecycle");
  }
  if (options.action && record.action !== options.action) mismatches.push("result.action");
  if (options.targetStatus && record.status !== options.targetStatus) mismatches.push("result.status");
  if (options.action === "supersede" && record.superseded_by !== options.superseded_by) {
    mismatches.push("result.superseded_by");
  }
  if (missing.length === 0 && mismatches.length === 0) return;
  const error = new Error("Model instance lifecycle maintenance requires a Rust-authored transition record.");
  error.status = 502;
  error.code = "model_mount_instance_lifecycle_rust_result_required";
  error.details = {
    operation: options.operation ?? null,
    operation_kind: options.operation_kind ?? null,
    target_status: options.targetStatus ?? null,
    missing,
    mismatches,
  };
  throw error;
}

function requiredMaintenanceString(value, field, instance, options = {}) {
  const normalized = value == null ? "" : String(value).trim();
  if (normalized) return normalized;
  throwInstanceMaintenanceRustCoreRequired(options.operation, instance, {
    operation_kind: options.operation_kind,
    reason: options.reason ?? null,
    superseded_by: options.superseded_by ?? null,
    missing: [field],
  });
}

function projectionRecords(state, methodName) {
  const reader = state?.[methodName];
  if (typeof reader !== "function") return [];
  const records = reader.call(state);
  return Array.isArray(records) ? records : [];
}

function throwInstanceMaintenanceRustCoreRequired(operation, instance, details = {}) {
  const error = new Error("Model instance lifecycle maintenance requires Rust daemon-core ownership.");
  error.status = 501;
  error.code = "model_mount_instance_lifecycle_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.instance_lifecycle",
    operation,
    ...details,
    instance_id: instance?.id ?? null,
    endpoint_id: instance?.endpointId ?? instance?.endpoint_id ?? null,
    model_id: instance?.modelId ?? instance?.model_id ?? null,
    provider_id: instance?.providerId ?? instance?.provider_id ?? null,
    evidence_refs: [
      "model_mount_instance_lifecycle_maintenance_positive_rust_api",
      "rust_daemon_core_instance_lifecycle_required",
      "agentgres_model_instance_record_truth_required",
    ],
  };
  throw error;
}

function requireInstanceLifecycleMountedStateDir(state, operation_kind) {
  const stateDir = typeof state?.stateDir === "string" && state.stateDir.trim()
    ? state.stateDir.trim()
    : null;
  if (stateDir) return stateDir;
  throwInstanceMaintenanceRustCoreRequired("model_instance_maintenance", {}, {
    operation_kind,
    missing: ["state_dir"],
    evidence_refs: [
      "rust_model_mount_instance_lifecycle",
      "agentgres_instance_lifecycle_topology_replay_required",
      "model_mount_instance_lifecycle_candidate_transport_retired",
    ],
  });
}
