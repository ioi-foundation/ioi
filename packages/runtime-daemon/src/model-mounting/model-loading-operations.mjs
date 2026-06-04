export async function loadModel(state, body = {}, deps = {}) {
  const {
    defaultBackendForProvider,
    driverNameForProvider,
    expiresAt,
    hasExplicitTtlOption,
    normalizeLoadOptions,
    normalizeLoadPolicy,
    safeId,
    schemaVersion,
  } = deps;
  const endpoint = state.resolveEndpoint(body.endpoint_id ?? body.endpointId, body.model_id ?? body.modelId);
  const provider = state.provider(endpoint.providerId);
  const loadPolicy = normalizeLoadPolicy(body.load_policy ?? body.loadPolicy ?? endpoint.loadPolicy);
  const runtimePreference = state.runtimePreferenceForEndpoint(endpoint);
  const requestLoadOptions = body.load_options ?? body.loadOptions ?? {};
  const runtimeDefaults = { ...state.runtimeDefaultLoadOptions(runtimePreference.selectedEngineId) };
  if ((body.load_policy ?? body.loadPolicy) && !hasExplicitTtlOption(body) && !hasExplicitTtlOption(requestLoadOptions)) {
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
    const receipt = state.lifecycleReceipt("model_load_estimate", {
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      backendId,
      runtimeEngineId: runtimePreference.selectedEngineId,
      runtimeEngineProfile,
      loadPolicy,
      loadOptions,
      estimate,
    });
    return {
      schemaVersion,
      status: "estimate_only",
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      backendId,
      runtimeEngineId: runtimePreference.selectedEngineId,
      runtimeEngineProfile,
      loadPolicy,
      loadOptions,
      estimate,
      receiptId: receipt.id,
    };
  }
  const driverResult = await state.driverForProvider(provider).load({
    state,
    provider,
    endpoint,
    body: { ...body, loadOptions, load_policy: loadPolicy },
  });
  const now = state.nowIso();
  const instance = {
    id: body.id ?? `instance.${safeId(endpoint.id)}.${Date.now()}`,
    endpointId: endpoint.id,
    providerId: endpoint.providerId,
    modelId: endpoint.modelId,
    status: "loaded",
    backend: driverResult.backend ?? endpoint.apiFormat,
    backendId: driverResult.backendId ?? backendId,
    driver: driverNameForProvider(provider),
    loadPolicy,
    loadOptions,
    runtimeEngineId: runtimePreference.selectedEngineId,
    runtimeEngineProfile,
    identifier: loadOptions.identifier ?? null,
    contextLength: loadOptions.contextLength ?? endpoint.contextWindow ?? null,
    parallelism: loadOptions.parallel ?? null,
    gpuOffload: loadOptions.gpu ?? null,
    estimate: driverResult.estimate ?? estimate,
    backendProcess: driverResult.process ?? null,
    backendProcessId: driverResult.process?.id ?? null,
    backendProcessPidHash: driverResult.process?.pidHash ?? null,
    loadedAt: now,
    lastUsedAt: now,
    expiresAt: expiresAt(now, loadPolicy),
    workflowScope: body.workflow_scope ?? body.workflowScope ?? null,
    agentScope: body.agent_scope ?? body.agentScope ?? null,
    providerEvidenceRefs: driverResult.evidenceRefs ?? [],
  };
  state.instances.set(instance.id, instance);
  state.supersedeLoadedInstances(endpoint.id, instance.id);
  state.writeMap("model-instances", state.instances);
  state.lifecycleReceipt("model_load", {
    instanceId: instance.id,
    endpointId: endpoint.id,
    modelId: endpoint.modelId,
    providerId: endpoint.providerId,
    backendId: instance.backendId,
    runtimeEngineId: runtimePreference.selectedEngineId,
    loadPolicy,
    loadOptions,
    estimate: instance.estimate,
    providerEvidenceRefs: driverResult.evidenceRefs ?? [],
    backendProcess: driverResult.process ?? null,
    commandArgsHash: driverResult.commandArgsHash ?? null,
  });
  return instance;
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
  const instanceId = body.instance_id ?? body.instanceId ?? body.id;
  const instance = instanceId
    ? state.instance(instanceId)
    : state.loadedInstanceForEndpoint(state.resolveEndpoint(body.endpoint_id ?? body.endpointId, body.model_id ?? body.modelId).id);
  const endpoint = state.endpoint(instance.endpointId);
  const provider = state.provider(instance.providerId);
  const driverResult = await state.driverForProvider(provider).unload({ state, provider, endpoint, instance, body });
  const updated = {
    ...instance,
    status: "unloaded",
    unloadedAt: state.nowIso(),
    providerEvidenceRefs: driverResult.evidenceRefs ?? instance.providerEvidenceRefs ?? [],
  };
  state.instances.set(instance.id, updated);
  state.writeMap("model-instances", state.instances);
  state.lifecycleReceipt("model_unload", {
    instanceId: instance.id,
    endpointId: instance.endpointId,
    modelId: instance.modelId,
    providerId: instance.providerId,
    providerEvidenceRefs: driverResult.evidenceRefs ?? [],
    backendProcess: driverResult.process ?? null,
  });
  return updated;
}
