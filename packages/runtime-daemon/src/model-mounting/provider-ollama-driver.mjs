import { defaultBackendForProvider } from "./provider-driver-helpers.mjs";
import { canonicalLoadOptionsInput, normalizeLoadOptions } from "./load-policy.mjs";
import { fetchProviderJson } from "./provider-transport.mjs";
import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";
import { safeId } from "./io.mjs";

export class OllamaModelProviderDriver {
  async health(provider, { state } = {}) {
    const result = await fetchProviderJson(provider, "/api/tags", { method: "GET", tolerateHttpError: true, state });
    return {
      status: result.ok ? "available" : "degraded",
      evidenceRefs: ["ollama_api_tags_probe"],
      httpStatus: result.status,
    };
  }

  async listModels({ provider, state }) {
    const result = await fetchProviderJson(provider, "/api/tags", { method: "GET", tolerateHttpError: true, state });
    if (!result.ok) return [];
    const models = Array.isArray(result.body?.models) ? result.body.models : [];
    return models
      .map((model) => String(model.name ?? model.model ?? ""))
      .filter(Boolean)
      .map((modelId) => ({
        id: `ollama.${safeId(modelId)}`,
        providerId: provider.id,
        modelId,
        displayName: modelId,
        family: "ollama",
        quantization: null,
        sizeBytes: null,
        contextWindow: null,
        capabilities: ["chat", "responses", "embeddings"],
        privacyClass: "local_private",
        source: "ollama_api_tags",
        state: "available",
        discoveredAt: new Date().toISOString(),
      }));
  }

  async listLoaded({ provider, state }) {
    const result = await fetchProviderJson(provider, "/api/ps", { method: "GET", tolerateHttpError: true, state });
    const backendId = defaultBackendForProvider(provider);
    if (result.ok) {
      const models = Array.isArray(result.body?.models) ? result.body.models : [];
      return models
        .map((model) => ({
          modelId: String(model.name ?? model.model ?? ""),
          sizeBytes: Number(model.size ?? 0) || null,
          processor: model.processor ?? null,
          until: model.expires_at ?? null,
        }))
        .filter((model) => model.modelId)
        .map((model) => ({
          id: `ollama.loaded.${safeId(model.modelId)}`,
          providerId: provider.id,
          modelId: model.modelId,
          displayName: model.modelId,
          backend: "ollama",
          backendId,
          sizeBytes: model.sizeBytes,
          processor: model.processor,
          until: model.until,
          backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
          evidenceRefs: ["ollama_api_ps_loaded_projection"],
        }));
    }
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backend: "ollama",
        backendId,
        backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
        evidenceRefs: ["ollama_agentgres_loaded_instance_projection"],
      }));
  }

  async load({ state, provider, endpoint, body = {} }) {
    const loadOptions = normalizeLoadOptions(canonicalLoadOptionsInput(body), endpoint.loadPolicy);
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    const processRecord =
      provider.id === "provider.ollama" && backend.binaryPath
        ? state.ensureBackendProcess(backendId, { endpoint, loadOptions, reason: "ollama_model_load" })
        : null;
    const generate = await fetchProviderJson(provider, "/api/generate", {
      method: "POST",
      body: {
        model: endpoint.modelId,
        prompt: "",
        stream: false,
        keep_alive: loadOptions.ttlSeconds ? `${loadOptions.ttlSeconds}s` : "5m",
      },
      tolerateHttpError: true,
      state,
    });
    return {
      status: "loaded",
      backend: "ollama",
      backendId,
      process: state.backendProcessSnapshot(processRecord),
      providerStatus: generate.ok ? "warmed" : "load_probe_degraded",
      evidenceRefs: [
        "ollama_generate_keep_alive_load",
        ...(processRecord ? ["ollama_process_supervisor"] : ["ollama_http_provider_load"]),
      ],
    };
  }

  async unload({ state, provider, endpoint }) {
    const backendId = endpoint?.backendId ?? defaultBackendForProvider(provider);
    const result = endpoint
      ? await fetchProviderJson(provider, "/api/generate", {
          method: "POST",
          body: { model: endpoint.modelId, prompt: "", stream: false, keep_alive: 0 },
          tolerateHttpError: true,
          state,
        })
      : { ok: false };
    return {
      status: "unloaded",
      backend: "ollama",
      backendId,
      providerStatus: result.ok ? "evicted" : "unload_probe_degraded",
      evidenceRefs: ["ollama_generate_keep_alive_zero_unload"],
    };
  }

  supportsStream(kind) {
    return false;
  }

  async streamInvoke({ provider } = {}) {
    throw retiredJsProviderInvocationError(provider, { label: "ollama", stream: true });
  }

  async invoke({ provider } = {}) {
    throw retiredJsProviderInvocationError(provider, { label: "ollama", stream: false });
  }
}
