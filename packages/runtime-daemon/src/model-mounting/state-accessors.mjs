export function provider(state, providerId, deps = {}) {
  const { notFound } = deps;
  const record = state.providers.get(providerId);
  if (!record) throw notFound(`Provider not found: ${providerId}`, { providerId });
  return record;
}

export function endpoint(state, endpointId, deps = {}) {
  const { notFound } = deps;
  const record = state.endpoints.get(endpointId);
  if (!record || record.status === "unmounted") {
    throw notFound(`Endpoint not found: ${endpointId}`, { endpointId });
  }
  return record;
}

export function instance(state, instanceId, deps = {}) {
  const { notFound } = deps;
  const record = state.instances.get(instanceId);
  if (!record) throw notFound(`Model instance not found: ${instanceId}`, { instanceId });
  return record;
}

export function route(state, routeId, deps = {}) {
  const { notFound } = deps;
  const record = state.routes.get(routeId);
  if (!record) throw notFound(`Route not found: ${routeId}`, { routeId });
  return record;
}

export function resolveEndpoint(state, endpointId, modelId, deps = {}) {
  const { runtimeError } = deps;
  if (endpointId) return state.endpoint(endpointId);
  if (modelId) {
    const record = [...state.endpoints.values()].find(
      (candidate) => candidate.status !== "unmounted" && candidate.modelId === modelId,
    );
    if (record) return record;
    return state.mountEndpoint({ model_id: modelId });
  }
  throw runtimeError({
    status: 424,
    code: "product_model_unavailable",
    message: "No model endpoint was specified and no product model route fallback is configured.",
    details: { required: "endpoint_id_or_model_id" },
  });
}

export async function ensureLoaded(state, endpointRecord, deps = {}) {
  const { expiresAt } = deps;
  state.evictExpiredInstances();
  const existing = state.loadedInstanceForEndpoint(endpointRecord.id, false);
  if (existing) {
    const updated = {
      ...existing,
      lastUsedAt: state.nowIso(),
      expiresAt: expiresAt(state.nowIso(), existing.loadPolicy),
    };
    state.instances.set(updated.id, updated);
    state.writeMap("model-instances", state.instances);
    return updated;
  }
  return state.loadModel({ endpoint_id: endpointRecord.id, load_policy: endpointRecord.loadPolicy });
}
