export function provider(state, providerId, deps = {}) {
  const { notFound } = deps;
  const record = state.providers.get(providerId);
  if (!record) throw notFound(`Provider not found: ${providerId}`, { provider_id: providerId });
  return record;
}

export function endpoint(state, endpointId, deps = {}) {
  const { notFound } = deps;
  const record = state.endpoints.get(endpointId);
  if (!record || record.status === "unmounted") {
    throw notFound(`Endpoint not found: ${endpointId}`, { endpoint_id: endpointId });
  }
  return record;
}

export function instance(state, instanceId, deps = {}) {
  const { notFound } = deps;
  const record = state.instances.get(instanceId);
  if (!record) throw notFound(`Model instance not found: ${instanceId}`, { instance_id: instanceId });
  return record;
}

export function route(state, routeId, deps = {}) {
  const { notFound } = deps;
  const record = state.routes.get(routeId);
  if (!record) throw notFound(`Route not found: ${routeId}`, { route_id: routeId });
  return record;
}

export function getModel(state, id, deps = {}) {
  const { notFound } = deps;
  const artifact = [...state.artifacts.values()].find((item) => item.id === id || item.modelId === id);
  if (!artifact) {
    throw notFound(`Model not found: ${id}`, { model_id: id });
  }
  return artifact;
}

export function modelForProviderMount(state, modelId, providerRecord, body = {}, now = state.nowIso(), deps = {}) {
  const {
    driverNameForProvider,
    normalizeScopes,
    safeId,
  } = deps;
  const artifact = [...state.artifacts.values()].find(
    (item) => item.id === modelId || (item.modelId === modelId && item.providerId === providerRecord.id),
  );
  if (artifact) return artifact;
  const mounted = {
    id: `${safeId(providerRecord.id)}.${safeId(modelId)}`,
    providerId: providerRecord.id,
    modelId,
    displayName: body.display_name ?? body.displayName ?? modelId,
    family: body.family ?? providerRecord.kind,
    quantization: body.quantization ?? null,
    sizeBytes: Number.isFinite(Number(body.size_bytes ?? body.sizeBytes)) ? Number(body.size_bytes ?? body.sizeBytes) : null,
    contextWindow: Number.isFinite(Number(body.context_window ?? body.contextWindow)) ? Number(body.context_window ?? body.contextWindow) : null,
    capabilities: normalizeScopes(body.capabilities, providerRecord.capabilities ?? ["chat", "responses", "embeddings"]),
    privacyClass: body.privacy_class ?? body.privacyClass ?? providerRecord.privacyClass,
    source: `${driverNameForProvider(providerRecord)}_provider_direct_mount`,
    state: "available",
    discoveredAt: now,
  };
  state.artifacts.set(mounted.id, mounted);
  state.writeMap("model-artifacts", state.artifacts);
  return mounted;
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
