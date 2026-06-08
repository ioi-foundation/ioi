const RETIRED_MODEL_LOADING_REQUEST_ALIASES = [
  "endpointId",
  "modelId",
  "loadPolicy",
  "loadOptions",
  "workflowScope",
  "agentScope",
  "instanceId",
];

const CANONICAL_MODEL_LOADING_REQUEST_FIELDS = [
  "endpoint_id",
  "model_id",
  "load_policy",
  "load_options",
  "workflow_scope",
  "agent_scope",
  "instance_id",
];

export async function loadModel(state, body = {}, deps = {}) {
  const {
    defaultBackendForProvider,
    hasExplicitTtlOption,
    normalizeLoadOptions,
    normalizeLoadPolicy,
    schemaVersion,
  } = deps;
  assertCanonicalModelLoadingRequestBody(body);
  const endpoint = state.resolveEndpoint(body.endpoint_id, body.model_id);
  const provider = state.provider(endpoint.providerId);
  const loadPolicy = normalizeLoadPolicy(body.load_policy ?? endpoint.loadPolicy);
  const runtimePreference = state.runtimePreferenceForEndpoint(endpoint);
  const requestLoadOptions = body.load_options ?? {};
  const runtimeDefaults = { ...state.runtimeDefaultLoadOptions(runtimePreference.selectedEngineId) };
  if (body.load_policy && !hasExplicitTtlOption(body) && !hasExplicitTtlOption(requestLoadOptions)) {
    delete runtimeDefaults.ttlSeconds;
  }
  const loadOptions = normalizeLoadOptions(
    { ...runtimeDefaults, ...body, ...requestLoadOptions },
    loadPolicy,
  );
  if (loadOptions.ttlSeconds !== null) loadPolicy.idleTtlSeconds = loadOptions.ttlSeconds;
  const estimate = state.loadEstimate(endpoint, loadOptions, runtimePreference);
  const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
  const runtimeEngineProfile = state.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null;
  if (loadOptions.estimateOnly) {
    return {
      schemaVersion,
      status: "estimate_only",
      endpoint_id: endpoint.id,
      model_id: endpoint.modelId,
      provider_id: endpoint.providerId,
      provider_kind: provider.kind,
      backend_id: backendId,
      runtime_engine_id: runtimePreference.selectedEngineId,
      runtime_engine_profile: runtimeEngineProfile,
      load_policy: loadPolicy,
      load_options: loadOptions,
      estimate,
      receipt_id: null,
      evidence_refs: [
        "model_mount_model_loading_js_facade_retired",
        "model_load_estimate_projection_only",
      ],
    };
  }
  throwModelLoadingRustCoreRequired("model_load", provider, {
    operation_kind: "model_mount.instance.load",
    endpoint_id: endpoint.id,
    model_id: endpoint.modelId,
    backend_id: backendId,
  });
}

export function loadEstimate(state, endpoint, loadOptions = {}, runtimePreference = state.runtimePreference(), deps = {}) {
  const {
    defaultBackendForProvider,
    estimateNativeLocalResources,
  } = deps;
  const provider = state.provider(endpoint.providerId);
  const artifact = state.getModel(endpoint.modelId);
  const nativeEstimate = estimateNativeLocalResources({
    ...artifact,
    contextWindow: loadOptions.contextLength ?? artifact.contextWindow,
  });
  return {
    endpointId: endpoint.id,
    modelId: endpoint.modelId,
    providerId: endpoint.providerId,
    backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
    runtimeEngineId: runtimePreference.selectedEngineId,
    contextLength: loadOptions.contextLength ?? nativeEstimate.contextWindow,
    parallelism: loadOptions.parallel ?? 1,
    gpuOffload: loadOptions.gpu ?? "auto",
    identifier: loadOptions.identifier ?? null,
    estimatedVramBytes: nativeEstimate.estimatedVramBytes,
    estimatedSizeBytes: nativeEstimate.sizeBytes,
    realInference: provider.kind !== "ioi_native_local" ? null : nativeEstimate.realInference,
    evidenceRefs: ["model_load_option_estimate", "runtime_engine_preference"],
  };
}

export async function unloadModel(state, body = {}, deps = {}) {
  assertCanonicalModelLoadingRequestBody(body);
  const instanceId = body.instance_id ?? body.id;
  const instance = instanceId
    ? state.instance(instanceId)
    : state.loadedInstanceForEndpoint(state.resolveEndpoint(body.endpoint_id, body.model_id).id);
  const endpoint = state.endpoint(instance.endpointId);
  const provider = state.provider(instance.providerId);
  throwModelLoadingRustCoreRequired("model_unload", provider, {
    operation_kind: "model_mount.instance.unload",
    instance_id: instance.id,
    endpoint_id: endpoint.id,
    model_id: instance.modelId,
    backend_id: instance.backendId ?? endpoint.backendId ?? null,
  });
}

function throwModelLoadingRustCoreRequired(operation, provider = {}, details = {}) {
  const error = new Error("Model load/unload requires a Rust model_mount provider lifecycle backend.");
  error.status = 501;
  error.code = "model_mount_model_loading_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.instance_lifecycle",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
    evidence_refs: [
      "model_mount_model_loading_js_facade_retired",
      "rust_daemon_core_instance_lifecycle_required",
      "agentgres_model_instance_record_truth_required",
    ],
  };
  throw error;
}

function assertCanonicalModelLoadingRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_LOADING_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model loading request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_loading_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MODEL_LOADING_REQUEST_FIELDS,
  };
  throw error;
}
