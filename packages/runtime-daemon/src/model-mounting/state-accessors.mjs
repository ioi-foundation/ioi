export function provider(state, providerId, deps = {}) {
  const { notFound } = deps;
  const record = providerProjectionRecord(state, providerId);
  if (!record) throw notFound(`Provider not found: ${providerId}`, { provider_id: providerId });
  return record;
}

export function optionalProvider(state, providerId) {
  return providerProjectionRecord(state, providerId);
}

function providerProjectionRecord(state, providerId) {
  const requested = String(providerId ?? "").trim();
  if (!requested) return null;
  const requestedRef = requested.startsWith("provider://") ? requested : `provider://${requested}`;
  const records = typeof state?.listProviders === "function" ? state.listProviders() : [];
  if (!Array.isArray(records)) return null;
  return records.find((record) =>
    record?.id === requested ||
    record?.provider_id === requested ||
    record?.provider_ref === requested ||
    record?.provider_ref === requestedRef) ?? null;
}

export function endpoint(state, endpointId, deps = {}) {
  const { notFound } = deps;
  const record = endpointProjectionRecord(state, endpointId);
  if (!record || record.status === "unmounted") {
    throw notFound(`Endpoint not found: ${endpointId}`, { endpoint_id: endpointId });
  }
  return record;
}

export function instance(state, instanceId, deps = {}) {
  const { notFound } = deps;
  const record = instanceProjectionRecord(state, instanceId);
  if (!record) throw notFound(`Model instance not found: ${instanceId}`, { instance_id: instanceId });
  return record;
}

export function route(state, routeId, deps = {}) {
  const { notFound } = deps;
  const record = routeProjectionRecord(state, routeId);
  if (!record) throw notFound(`Route not found: ${routeId}`, { route_id: routeId });
  return record;
}

export function getModel(state, id, deps = {}) {
  const { notFound } = deps;
  const artifact = artifactProjectionRecord(state, id);
  if (!artifact) {
    throw notFound(`Model not found: ${id}`, { model_id: id });
  }
  return artifact;
}

export function modelForProviderMount(state, modelId, providerRecord, body = {}, now = state.nowIso(), deps = {}) {
  const {
    safeId,
  } = deps;
  const artifact = projectionRecords(state, "listArtifacts").find(
    (item) => artifactMatchesModel(item, modelId) && artifactProviderMatches(item, providerRecord),
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
    const record = projectionRecords(state, "listEndpoints").find(
      (candidate) =>
        candidate.status !== "unmounted" &&
        (candidate.model_id === modelId || candidate.modelId === modelId || candidate.model_ref === modelId),
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
  const endpointId = endpointRecordId(endpointRecord);
  const existing = state.loadedInstanceForEndpoint(endpointId, false);
  if (existing) return existing;
  return state.loadModel({
    endpoint_id: endpointId,
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

function endpointProjectionRecord(state, endpointId) {
  const requested = String(endpointId ?? "").trim();
  if (!requested) return null;
  return projectionRecords(state, "listEndpoints").find(
    (record) =>
      record?.id === requested ||
      record?.endpoint_id === requested ||
      record?.endpoint_ref === requested,
  ) ?? null;
}

function instanceProjectionRecord(state, instanceId) {
  const requested = String(instanceId ?? "").trim();
  if (!requested) return null;
  return projectionRecords(state, "listInstances").find(
    (record) =>
      record?.id === requested ||
      record?.instance_id === requested ||
      record?.instance_ref === requested,
  ) ?? null;
}

function routeProjectionRecord(state, routeId) {
  const requested = String(routeId ?? "").trim();
  if (!requested) return null;
  return projectionRecords(state, "listRoutes").find(
    (record) =>
      record?.id === requested ||
      record?.route_id === requested ||
      record?.route_ref === requested,
  ) ?? null;
}

function artifactProjectionRecord(state, id) {
  const requested = String(id ?? "").trim();
  if (!requested) return null;
  return projectionRecords(state, "listArtifacts").find(
    (record) =>
      record?.id === requested ||
      record?.artifact_id === requested ||
      record?.artifact_ref === requested ||
      record?.model_id === requested ||
      record?.modelId === requested ||
      record?.model_ref === requested,
  ) ?? null;
}

function artifactMatchesModel(record, modelId) {
  return [
    record?.id,
    record?.artifact_id,
    record?.artifact_ref,
    record?.model_id,
    record?.modelId,
    record?.model_ref,
  ].includes(modelId);
}

function artifactProviderMatches(record, providerRecord) {
  const refs = providerRefs(providerRecord);
  if (refs.size === 0) return true;
  return [
    record?.provider_id,
    record?.providerId,
    record?.provider_ref,
  ].some((value) => refs.has(value));
}

function providerRefs(providerRecord) {
  const values = new Set();
  for (const value of [
    providerRecord?.id,
    providerRecord?.provider_id,
    providerRecord?.provider_ref,
  ]) {
    const normalized = String(value ?? "").trim();
    if (!normalized) continue;
    values.add(normalized);
    if (normalized.startsWith("provider://")) values.add(normalized.slice("provider://".length));
    else values.add(`provider://${normalized}`);
  }
  return values;
}

function endpointRecordId(endpointRecord) {
  return endpointRecord?.id ?? endpointRecord?.endpoint_id ?? endpointRecord?.endpoint_ref;
}

function projectionRecords(state, methodName) {
  const reader = state?.[methodName];
  if (typeof reader !== "function") return [];
  const records = reader.call(state);
  return Array.isArray(records) ? records : [];
}
