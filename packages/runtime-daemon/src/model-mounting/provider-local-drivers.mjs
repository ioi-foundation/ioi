import { estimateNativeLocalResources } from "./local-system-probes.mjs";
import { normalizeLoadOptions } from "./load-policy.mjs";
import { normalizeScopes } from "./io.mjs";

export class NativeLocalModelProviderDriver {
  async health(provider) {
    return {
      status: provider.status === "blocked" ? "blocked" : "available",
      evidenceRefs: ["autopilot_native_local_backend_registry", "deterministic_native_local_fixture"],
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

  async load({ state, endpoint, body = {} }) {
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
    return {
      backend: "autopilot.native_local.fixture",
      backendId,
      driver: "native_local",
      status: "loaded",
      estimate,
      process: processSnapshot,
      evidenceRefs: [
        "autopilot_native_local_backend_registry",
        "autopilot_native_local_process_supervisor",
        "deterministic_native_local_fixture",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
      ],
    };
  }

  async unload({ state, endpoint }) {
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const processRecord = state.backendProcessForBackend(backendId);
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "unload",
      modelId: endpoint.modelId,
      backend: "autopilot.native_local.fixture",
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    return {
      driver: "native_local",
      status: "unloaded",
      backend: "autopilot.native_local.fixture",
      backendId,
      process: state.backendProcessSnapshot(processRecord),
      evidenceRefs: ["autopilot_native_local_process_supervisor", "deterministic_native_local_fixture"],
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
  async health(provider) {
    return {
      status: provider.status === "blocked" ? "blocked" : "available",
      evidenceRefs: ["agentgres_model_registry_fixture"],
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

  async load({ endpoint }) {
    return { backend: endpoint.apiFormat, backendId: endpoint.backendId ?? "backend.fixture", driver: "fixture", status: "loaded" };
  }

  async unload() {
    return { driver: "fixture", status: "unloaded" };
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
