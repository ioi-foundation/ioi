export function loadedInstanceForEndpoint(state, endpointId, failIfMissing = true, deps = {}) {
  const { notFound } = deps;
  const instance = [...state.instances.values()].find(
    (candidate) => candidate.endpointId === endpointId && candidate.status === "loaded",
  );
  if (!instance && failIfMissing) {
    throw notFound(`No loaded model instance for endpoint: ${endpointId}`, { endpoint_id: endpointId });
  }
  return instance ?? null;
}

export function evictExpiredInstances(state) {
  const nowMs = state.now().getTime();
  for (const instance of state.instances.values()) {
    if (instance.status !== "loaded" || !instance.expiresAt || Date.parse(instance.expiresAt) > nowMs) {
      continue;
    }
    throwInstanceMaintenanceRustCoreRequired("model_idle_evict", instance, {
      operation_kind: "model_mount.instance.evict",
      reason: "idle_ttl",
    });
  }
  return false;
}

export function coalesceLoadedInstances(state) {
  const loadedByEndpoint = new Map();
  for (const instance of state.instances.values()) {
    if (instance.status !== "loaded" || !instance.endpointId) continue;
    const current = loadedByEndpoint.get(instance.endpointId);
    if (!current || String(instance.loadedAt ?? "") > String(current.loadedAt ?? "")) {
      loadedByEndpoint.set(instance.endpointId, instance);
    }
  }
  for (const instance of state.instances.values()) {
    if (instance.status !== "loaded" || !instance.endpointId) continue;
    const keeper = loadedByEndpoint.get(instance.endpointId);
    if (!keeper || keeper.id === instance.id) continue;
    throwInstanceMaintenanceRustCoreRequired("model_supersede", instance, {
      operation_kind: "model_mount.instance.supersede",
      superseded_by: keeper.id,
      reason: "endpoint_reload",
    });
  }
  return false;
}

export function supersedeLoadedInstances(state, endpointId, keepInstanceId) {
  for (const instance of state.instances.values()) {
    if (instance.id === keepInstanceId || instance.endpointId !== endpointId || instance.status !== "loaded") continue;
    throwInstanceMaintenanceRustCoreRequired("model_supersede", instance, {
      operation_kind: "model_mount.instance.supersede",
      superseded_by: keepInstanceId,
      reason: "endpoint_reload",
    });
  }
  return false;
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
    endpoint_id: instance?.endpointId ?? null,
    model_id: instance?.modelId ?? null,
    provider_id: instance?.providerId ?? null,
    evidence_refs: [
      "model_mount_instance_lifecycle_js_maintenance_retired",
      "rust_daemon_core_instance_lifecycle_required",
      "agentgres_model_instance_record_truth_required",
    ],
  };
  throw error;
}
