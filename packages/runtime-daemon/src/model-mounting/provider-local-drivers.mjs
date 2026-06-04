import { estimateNativeLocalResources } from "./local-system-probes.mjs";
import { normalizeLoadOptions } from "./load-policy.mjs";
import { normalizeScopes } from "./io.mjs";
import {
  RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND,
  RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND,
} from "./model-mount-admission-runner.mjs";

export class NativeLocalModelProviderDriver {
  async health(provider, { state } = {}) {
    const lifecycle = requireNativeLocalLifecycleResult(state?.planModelMountProviderLifecycle(nativeLocalLifecycleRequest({
      action: "health",
      provider,
      endpoint: {
        id: provider.defaultEndpointId ?? provider.endpointId ?? `${provider.id}.health`,
        providerId: provider.id,
        modelId: provider.defaultModelId ?? provider.modelId ?? provider.id,
        apiFormat: provider.apiFormat ?? "ioi_native",
        backendId: provider.backendId ?? "backend.autopilot.native-local.fixture",
      },
      backendId: provider.backendId ?? "backend.autopilot.native-local.fixture",
      evidenceRefs: ["daemon_native_local_health_request"],
    })), "health");
    return {
      status: lifecycle.status,
      evidenceRefs: lifecycle.evidence_refs ?? [],
      lifecycleHash: lifecycle.lifecycle_hash ?? null,
    };
  }

  async listModels({ state, provider }) {
    return state.listArtifacts().filter((artifact) => artifact.providerId === provider.id);
  }

  async listLoaded({ state, provider }) {
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backendEvidenceRefs: ["autopilot_native_local_process_supervisor", "deterministic_native_local_fixture"],
      }));
  }

  async load({ state, provider = null, endpoint, body = {} }) {
    const artifact = state.getModel(endpoint.modelId);
    const estimate = estimateNativeLocalResources(artifact);
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? body, endpoint.loadPolicy);
    const processRecord = state.ensureBackendProcess(backendId, {
      endpoint,
      loadOptions,
      reason: "model_load",
    });
    const processSnapshot = state.backendProcessSnapshot(processRecord);
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "load",
      modelId: endpoint.modelId,
      estimate,
      loadOptions,
      backend: "autopilot.native_local.fixture",
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
      argsHash: processRecord?.argsHash ?? null,
    });
    const lifecycle = requireNativeLocalLifecycleResult(state.planModelMountProviderLifecycle(nativeLocalLifecycleRequest({
      action: "load",
      provider,
      endpoint,
      backendId,
      processSnapshot,
      evidenceRefs: ["daemon_native_local_load_request"],
    })), "load");
    return {
      backend: lifecycle.providerBackend,
      backendId: lifecycle.backendId,
      driver: lifecycle.driver,
      status: lifecycle.status,
      estimate,
      process: processSnapshot,
      evidenceRefs: lifecycle.evidence_refs ?? [],
      lifecycleHash: lifecycle.lifecycle_hash ?? null,
    };
  }

  async unload({ state, provider = null, endpoint }) {
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const processRecord = state.backendProcessForBackend(backendId);
    const processSnapshot = state.backendProcessSnapshot(processRecord);
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "unload",
      modelId: endpoint.modelId,
      backend: "autopilot.native_local.fixture",
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    const lifecycle = requireNativeLocalLifecycleResult(state.planModelMountProviderLifecycle(nativeLocalLifecycleRequest({
      action: "unload",
      provider,
      endpoint,
      backendId,
      processSnapshot,
      evidenceRefs: ["daemon_native_local_unload_request"],
    })), "unload");
    return {
      driver: lifecycle.driver,
      status: lifecycle.status,
      backend: lifecycle.providerBackend,
      backendId: lifecycle.backendId,
      process: processSnapshot,
      evidenceRefs: lifecycle.evidence_refs ?? [],
      lifecycleHash: lifecycle.lifecycle_hash ?? null,
    };
  }

  supportsStream(kind) {
    return kind === "chat.completions" || kind === "chat" || kind === "responses";
  }

  async streamInvoke() {
    throw retiredLocalProviderStreamError("Native-local stream provider invocation");
  }

  async invoke() {
    throw retiredLocalProviderInvokeError("Native-local non-stream provider invocation");
  }
}

export class FixtureModelProviderDriver {
  async health(provider, { state } = {}) {
    const lifecycle = requireFixtureLifecycleResult(state?.planModelMountProviderLifecycle(fixtureLifecycleRequest({
      action: "health",
      provider,
      endpoint: {
        id: provider.defaultEndpointId ?? provider.endpointId ?? `${provider.id}.health`,
        providerId: provider.id,
        modelId: provider.defaultModelId ?? provider.modelId ?? provider.id,
        apiFormat: provider.apiFormat ?? "ioi_fixture",
        backendId: provider.backendId ?? "backend.fixture",
      },
      backendId: provider.backendId ?? "backend.fixture",
      evidenceRefs: ["daemon_fixture_health_request"],
    })), "health");
    return {
      status: lifecycle.status,
      evidenceRefs: lifecycle.evidence_refs ?? [],
      lifecycleHash: lifecycle.lifecycle_hash ?? null,
    };
  }

  async listModels({ state, provider }) {
    return state.listArtifacts().filter((artifact) => artifact.providerId === provider.id);
  }

  async listLoaded({ state, provider }) {
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded");
  }

  async load({ state, provider = null, endpoint }) {
    const lifecycle = requireFixtureLifecycleResult(state?.planModelMountProviderLifecycle(fixtureLifecycleRequest({
      action: "load",
      provider,
      endpoint,
      backendId: endpoint.backendId ?? "backend.fixture",
      evidenceRefs: ["daemon_fixture_load_request"],
    })), "load");
    return {
      backend: lifecycle.providerBackend,
      backendId: lifecycle.backendId,
      driver: lifecycle.driver,
      status: lifecycle.status,
      evidenceRefs: lifecycle.evidence_refs ?? [],
      lifecycleHash: lifecycle.lifecycle_hash ?? null,
    };
  }

  async unload({ state, provider = null, endpoint }) {
    const lifecycle = requireFixtureLifecycleResult(state?.planModelMountProviderLifecycle(fixtureLifecycleRequest({
      action: "unload",
      provider,
      endpoint,
      backendId: endpoint?.backendId ?? "backend.fixture",
      evidenceRefs: ["daemon_fixture_unload_request"],
    })), "unload");
    return {
      driver: lifecycle.driver,
      status: lifecycle.status,
      backend: lifecycle.providerBackend,
      backendId: lifecycle.backendId,
      evidenceRefs: lifecycle.evidence_refs ?? [],
      lifecycleHash: lifecycle.lifecycle_hash ?? null,
    };
  }

  async invoke() {
    throw retiredLocalProviderInvokeError("Fixture provider invocation");
  }
}

function retiredLocalProviderInvokeError(label) {
  const error = new Error(`${label} is retired; execute migrated local provider invocations through Rust model_mount.`);
  error.status = 500;
  error.code = "model_mount_local_provider_direct_invoke_retired";
  return error;
}

function retiredLocalProviderStreamError(label) {
  const error = new Error(`${label} is retired; execute native-local stream frames through Rust model_mount.`);
  error.status = 500;
  error.code = "model_mount_local_provider_direct_stream_retired";
  return error;
}

function nativeLocalLifecycleRequest({
  action,
  provider = null,
  endpoint,
  backendId,
  processSnapshot = null,
  evidenceRefs = [],
}) {
  return {
    schema_version: "ioi.model_mount.provider_lifecycle.v1",
    provider_ref: provider?.id ?? endpoint.providerId ?? "provider.autopilot.local",
    provider_kind: provider?.kind ?? "ioi_native_local",
    endpoint_ref: endpoint.id,
    model_ref: endpoint.modelId,
    action,
    execution_backend: RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND,
    api_format: endpoint.apiFormat ?? provider?.apiFormat ?? "ioi_native",
    driver: provider?.driver ?? "native_local",
    backend_ref: backendId,
    provider_status: provider?.status ?? null,
    evidence_refs: normalizeScopes(evidenceRefs, []),
    process_evidence_refs: normalizeScopes(processSnapshot?.evidenceRefs, []),
  };
}

function fixtureLifecycleRequest({
  action,
  provider = null,
  endpoint,
  backendId,
  evidenceRefs = [],
}) {
  return {
    schema_version: "ioi.model_mount.provider_lifecycle.v1",
    provider_ref: provider?.id ?? endpoint?.providerId ?? "provider.fixture",
    provider_kind: provider?.kind ?? "local_folder",
    endpoint_ref: endpoint?.id ?? `${provider?.id ?? "provider.fixture"}.health`,
    model_ref: endpoint?.modelId ?? provider?.defaultModelId ?? provider?.modelId ?? provider?.id ?? "model.fixture",
    action,
    execution_backend: RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND,
    api_format: endpoint?.apiFormat ?? provider?.apiFormat ?? "ioi_fixture",
    driver: provider?.driver ?? "fixture",
    backend_ref: backendId,
    provider_status: provider?.status ?? null,
    evidence_refs: normalizeScopes(evidenceRefs, []),
    process_evidence_refs: [],
  };
}

function requireNativeLocalLifecycleResult(value, action) {
  const expectedStatus =
    action === "health"
      ? null
      : action === "load"
        ? "loaded"
        : "unloaded";
  if (
    !value ||
    (expectedStatus ? value.status !== expectedStatus : !["available", "blocked"].includes(value.status)) ||
    !value.providerBackend ||
    !value.backendId ||
    value.driver !== "native_local" ||
    value.executionBackend !== RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND ||
    !value.lifecycle_hash
  ) {
    const error = new Error("Native-local provider lifecycle planning requires a Rust model_mount lifecycle result.");
    error.status = 502;
    error.code = "model_mount_provider_lifecycle_planning_required";
    error.details = { action, expectedStatus };
    throw error;
  }
  return value;
}

function requireFixtureLifecycleResult(value, action) {
  const expectedStatus =
    action === "health"
      ? null
      : action === "load"
        ? "loaded"
        : "unloaded";
  if (
    !value ||
    (expectedStatus ? value.status !== expectedStatus : !["available", "blocked"].includes(value.status)) ||
    !value.providerBackend ||
    !value.backendId ||
    value.driver !== "fixture" ||
    value.executionBackend !== RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND ||
    !value.lifecycle_hash
  ) {
    const error = new Error("Fixture provider lifecycle planning requires a Rust model_mount lifecycle result.");
    error.status = 502;
    error.code = "model_mount_fixture_provider_lifecycle_planning_required";
    error.details = { action, expectedStatus };
    throw error;
  }
  return value;
}
