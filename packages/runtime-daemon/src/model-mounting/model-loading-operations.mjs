import {
  modelMountInstanceLifecycleFields,
  planModelMountInstanceLifecycleForMigratedProvider,
} from "./model-instance-lifecycle.mjs";
import { commitModelInstanceRecordState } from "./model-instance-record-state.mjs";

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
    driverNameForProvider,
    expiresAt,
    hasExplicitTtlOption,
    normalizeLoadOptions,
    normalizeLoadPolicy,
    safeId,
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
  const instanceId = body.id ?? `instance.${safeId(endpoint.id)}.${Date.now()}`;
  const instanceLifecycle = planModelMountInstanceLifecycleForMigratedProvider({
    state,
    action: "load",
    targetStatus: "loaded",
    instanceId,
    endpoint,
    provider,
    backendId: driverResult.backendId ?? backendId,
    driver: driverNameForProvider(provider),
    model_mount_provider_lifecycle_hash: driverResult.lifecycleHash,
    evidenceRefs: driverResult.evidenceRefs ?? [],
  });
  const instance = {
    id: instanceId,
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
    workflowScope: body.workflow_scope ?? null,
    agentScope: body.agent_scope ?? null,
    providerEvidenceRefs: driverResult.evidenceRefs ?? [],
    ...modelMountInstanceLifecycleFields(instanceLifecycle),
  };
  const receipt = state.lifecycleReceipt("model_load", {
    instance_id: instance.id,
    endpoint_id: endpoint.id,
    model_id: endpoint.modelId,
    provider_id: endpoint.providerId,
    provider_kind: provider.kind,
    backend_id: instance.backendId,
    runtime_engine_id: runtimePreference.selectedEngineId,
    load_policy: loadPolicy,
    load_options: loadOptions,
    estimate: instance.estimate,
    provider_evidence_refs: driverResult.evidenceRefs ?? [],
    ...modelMountInstanceLifecycleFields(instanceLifecycle),
    backend_process: driverResult.process ?? null,
    command_args_hash: driverResult.commandArgsHash ?? null,
  });
  const stored = { ...instance, receiptId: receipt.id };
  commitModelInstanceRecordState(state, stored, "model_mount.instance.load", [receipt.id]);
  state.instances.set(stored.id, stored);
  state.supersedeLoadedInstances(endpoint.id, stored.id);
  return stored;
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
  const driverResult = await state.driverForProvider(provider).unload({ state, provider, endpoint, instance, body });
  const instanceLifecycle = planModelMountInstanceLifecycleForMigratedProvider({
    state,
    action: "unload",
    targetStatus: "unloaded",
    instanceId: instance.id,
    endpoint,
    provider,
    backendId: driverResult.backendId ?? instance.backendId ?? endpoint.backendId,
    driver: driverResult.driver ?? instance.driver ?? deps.driverNameForProvider?.(provider) ?? provider.driver ?? "fixture",
    model_mount_provider_lifecycle_hash: driverResult.lifecycleHash,
    evidenceRefs: driverResult.evidenceRefs ?? [],
  });
  const updated = {
    ...instance,
    status: "unloaded",
    unloadedAt: state.nowIso(),
    providerEvidenceRefs: driverResult.evidenceRefs ?? instance.providerEvidenceRefs ?? [],
    ...modelMountInstanceLifecycleFields(instanceLifecycle),
  };
  const receipt = state.lifecycleReceipt("model_unload", {
    instance_id: instance.id,
    endpoint_id: instance.endpointId,
    model_id: instance.modelId,
    provider_id: instance.providerId,
    provider_kind: provider.kind,
    provider_evidence_refs: driverResult.evidenceRefs ?? [],
    ...modelMountInstanceLifecycleFields(instanceLifecycle),
    backend_process: driverResult.process ?? null,
  });
  const stored = { ...updated, receiptId: receipt.id };
  commitModelInstanceRecordState(state, stored, "model_mount.instance.unload", [receipt.id]);
  state.instances.set(instance.id, stored);
  return stored;
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
