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
    safeId,
  } = deps;
  const artifact = [...state.artifacts.values()].find(
    (item) => item.id === modelId || (item.modelId === modelId && item.providerId === providerRecord.id),
  );
  if (artifact) return artifact;
  throwStateAccessorRustCoreRequired("model_mount.artifact.provider_direct_mount", {
    artifact_id: `${safeId(providerRecord.id)}.${safeId(modelId)}`,
    provider_id: providerRecord?.id ?? null,
    provider_kind: providerRecord?.kind ?? null,
    model_id: modelId,
  });
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
  const existing = state.loadedInstanceForEndpoint(endpointRecord.id, false);
  if (existing) return existing;
  return state.loadModel({
    endpoint_id: endpointRecord.id,
    load_policy: endpointRecord.load_policy,
  });
}

export function throwStateAccessorRustCoreRequired(operation_kind, details = {}) {
  const error = new Error("Model-mount state accessor mutation requires Rust daemon-core ownership.");
  error.status = 501;
  error.code = "model_mount_state_accessor_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.projection",
    operation_kind,
    ...details,
    evidence_refs: [
      "model_mount_state_accessor_js_mutation_retired",
      "rust_daemon_core_model_mount_projection_required",
      "agentgres_model_mount_record_truth_required",
    ],
  };
  throw error;
}
