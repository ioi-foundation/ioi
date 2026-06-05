import {
  modelMountInstanceLifecycleFields,
  modelMountInstanceLifecycleRequiresRust,
  planModelMountInstanceLifecycleForMigratedProvider,
} from "./model-instance-lifecycle.mjs";

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
    const instanceLifecycle = planStateInstanceLifecycle(state, instance, {
      action: "evict",
      targetStatus: "evicted",
      evidenceRefs: ["model_idle_evict"],
    });
    const evicted = {
      ...instance,
      status: "evicted",
      evictedAt: state.nowIso(),
      evictionReason: "idle_ttl",
      ...modelMountInstanceLifecycleFields(instanceLifecycle),
    };
    state.instances.set(instance.id, evicted);
    changed = true;
    state.lifecycleReceipt("model_idle_evict", {
      instanceId: instance.id,
      endpointId: instance.endpointId,
      modelId: instance.modelId,
      providerId: instance.providerId,
      ...lifecycleReceiptFields(state, evicted, instanceLifecycle),
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
    const instanceLifecycle = planStateInstanceLifecycle(state, instance, {
      action: "supersede",
      targetStatus: "superseded",
      evidenceRefs: ["model_supersede", keeper.id],
    });
    const superseded = {
      ...instance,
      status: "superseded",
      supersededAt: state.nowIso(),
      supersededBy: keeper.id,
      supersededReason: "endpoint_reload",
      ...modelMountInstanceLifecycleFields(instanceLifecycle),
    };
    state.instances.set(instance.id, superseded);
    state.lifecycleReceipt("model_supersede", {
      instanceId: instance.id,
      endpointId: instance.endpointId,
      modelId: instance.modelId,
      providerId: instance.providerId,
      supersededBy: keeper.id,
      ...lifecycleReceiptFields(state, superseded, instanceLifecycle),
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
    const instanceLifecycle = planStateInstanceLifecycle(state, instance, {
      action: "supersede",
      targetStatus: "superseded",
      evidenceRefs: ["model_supersede", keepInstanceId],
    });
    const superseded = {
      ...instance,
      status: "superseded",
      supersededAt: state.nowIso(),
      supersededBy: keepInstanceId,
      supersededReason: "endpoint_reload",
      ...modelMountInstanceLifecycleFields(instanceLifecycle),
    };
    state.instances.set(instance.id, superseded);
    state.lifecycleReceipt("model_supersede", {
      instanceId: instance.id,
      endpointId: instance.endpointId,
      modelId: instance.modelId,
      providerId: instance.providerId,
      supersededBy: keepInstanceId,
      ...lifecycleReceiptFields(state, superseded, instanceLifecycle),
    });
    changed = true;
  }
  return changed;
}

function planStateInstanceLifecycle(state, instance, { action, targetStatus, evidenceRefs = [] }) {
  const provider = providerForInstance(state, instance);
  if (!modelMountInstanceLifecycleRequiresRust(provider)) return null;
  const endpoint = endpointForInstance(state, instance);
  return planModelMountInstanceLifecycleForMigratedProvider({
    state,
    action,
    targetStatus,
    instanceId: instance.id,
    endpoint,
    provider,
    backendId: instance.backendId ?? endpoint.backendId ?? null,
    driver: instance.driver ?? provider.driver ?? "fixture",
    model_mount_provider_lifecycle_hash: instance.model_mount_provider_lifecycle_hash,
    evidenceRefs: [
      ...(Array.isArray(instance.providerEvidenceRefs) ? instance.providerEvidenceRefs : []),
      ...(Array.isArray(instance.model_mount_instance_lifecycle_evidence_refs)
        ? instance.model_mount_instance_lifecycle_evidence_refs
        : []),
      ...evidenceRefs,
    ],
  });
}

function providerForInstance(state, instance) {
  const provider = state.providers?.get?.(instance.providerId);
  if (provider) return provider;
  if (typeof state.provider === "function" && instance.providerId) {
    return state.provider(instance.providerId);
  }
  return null;
}

function endpointForInstance(state, instance) {
  if (typeof state.endpoint === "function" && instance.endpointId) {
    return state.endpoint(instance.endpointId);
  }
  return {
    id: instance.endpointId,
    modelId: instance.modelId,
    backendId: instance.backendId ?? null,
  };
}

function lifecycleReceiptFields(state, instance, instanceLifecycle) {
  if (!instanceLifecycle) return {};
  return {
    providerKind: providerForInstance(state, instance)?.kind ?? null,
    model_mount_provider_lifecycle_hash: instance.model_mount_provider_lifecycle_hash ?? null,
    ...modelMountInstanceLifecycleFields(instanceLifecycle),
  };
}
