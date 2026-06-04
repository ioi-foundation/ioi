export function loadedInstanceForEndpoint(state, endpointId, failIfMissing = true, deps = {}) {
  const { notFound } = deps;
  const instance = [...state.instances.values()].find(
    (candidate) => candidate.endpointId === endpointId && candidate.status === "loaded",
  );
  if (!instance && failIfMissing) {
    throw notFound(`No loaded model instance for endpoint: ${endpointId}`, { endpointId });
  }
  return instance ?? null;
}

export function evictExpiredInstances(state) {
  const nowMs = state.now().getTime();
  let changed = false;
  for (const instance of state.instances.values()) {
    if (instance.status !== "loaded" || !instance.expiresAt || Date.parse(instance.expiresAt) > nowMs) {
      continue;
    }
    const evicted = {
      ...instance,
      status: "evicted",
      evictedAt: state.nowIso(),
      evictionReason: "idle_ttl",
    };
    state.instances.set(instance.id, evicted);
    changed = true;
    state.lifecycleReceipt("model_idle_evict", {
      instanceId: instance.id,
      endpointId: instance.endpointId,
      modelId: instance.modelId,
      providerId: instance.providerId,
    });
  }
  if (changed) {
    state.writeMap("model-instances", state.instances);
  }
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
  let changed = false;
  for (const instance of state.instances.values()) {
    if (instance.status !== "loaded" || !instance.endpointId) continue;
    const keeper = loadedByEndpoint.get(instance.endpointId);
    if (!keeper || keeper.id === instance.id) continue;
    state.instances.set(instance.id, {
      ...instance,
      status: "superseded",
      supersededAt: state.nowIso(),
      supersededBy: keeper.id,
      supersededReason: "endpoint_reload",
    });
    changed = true;
  }
  if (changed) {
    state.writeMap("model-instances", state.instances);
  }
}

export function supersedeLoadedInstances(state, endpointId, keepInstanceId) {
  let changed = false;
  for (const instance of state.instances.values()) {
    if (instance.id === keepInstanceId || instance.endpointId !== endpointId || instance.status !== "loaded") continue;
    state.instances.set(instance.id, {
      ...instance,
      status: "superseded",
      supersededAt: state.nowIso(),
      supersededBy: keepInstanceId,
      supersededReason: "endpoint_reload",
    });
    changed = true;
  }
  return changed;
}
