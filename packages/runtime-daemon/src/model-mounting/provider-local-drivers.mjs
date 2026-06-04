import {
  jsonLineReadableStream,
  nativeLocalOutput,
  nativeLocalStreamRecords,
  providerStreamFrameDelayMs,
} from "./native-local-fixture.mjs";
import { estimateTokens } from "./provider-protocol.mjs";
import { estimateNativeLocalResources } from "./local-system-probes.mjs";
import { normalizeLoadOptions } from "./load-policy.mjs";
import { normalizeScopes, stableHash } from "./io.mjs";

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

  async streamInvoke({ kind, input, endpoint, state }) {
    if (!this.supportsStream(kind)) return null;
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const processRecord = state.ensureBackendProcess(backendId, {
      endpoint,
      loadOptions: state.loadedInstanceForEndpoint(endpoint.id, false)?.loadOptions ?? {},
      reason: "model_stream",
    });
    const processSnapshot = state.backendProcessSnapshot(processRecord);
    const outputText = nativeLocalOutput({ kind, input, modelId: endpoint.modelId });
    const tokenCount = estimateTokens(input, outputText);
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "stream",
      modelId: endpoint.modelId,
      kind,
      inputHash: stableHash(input),
      outputHash: stableHash(outputText),
      backend: "autopilot.native_local.fixture",
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    const streamHandle = jsonLineReadableStream(nativeLocalStreamRecords(outputText, tokenCount), {
      delayMs: providerStreamFrameDelayMs(),
      onAbort: (reason) => {
        state.writeBackendLog(endpoint.id, {
          backendId,
          event: "stream_abort",
          modelId: endpoint.modelId,
          kind,
          reason,
          inputHash: stableHash(input),
          outputHash: stableHash(outputText),
          backend: "autopilot.native_local.fixture",
          processId: processRecord?.id ?? null,
          pidHash: processRecord?.pidHash ?? null,
        });
      },
    });
    return {
      stream: streamHandle.stream,
      abort: () => streamHandle.abort("client_disconnect"),
      status: 200,
      streamFormat: "ioi_jsonl",
      streamKind: kind === "responses" ? "openai_responses_native_local" : "openai_chat_completions_native_local",
      providerResponseKind: kind === "responses" ? "native_local.responses.stream" : "native_local.chat.stream",
      backend: "autopilot.native_local.fixture",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "autopilot_native_local_provider_native_stream",
        "autopilot_native_local_openai_compatible_serving",
        "deterministic_native_local_fixture",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
      ],
    };
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
