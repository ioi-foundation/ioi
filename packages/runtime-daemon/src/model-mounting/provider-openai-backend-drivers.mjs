import { defaultBackendForProvider } from "./provider-driver-helpers.mjs";
import { canonicalLoadOptionsInput, normalizeLoadOptions } from "./load-policy.mjs";
import { normalizeScopes, stableHash } from "./io.mjs";
import { OpenAICompatibleModelProviderDriver } from "./provider-openai-compatible-driver.mjs";

export class VllmModelProviderDriver {
  constructor({ state }) {
    this.state = state;
    this.openAi = new OpenAICompatibleModelProviderDriver({ label: "vllm" });
  }

  providerWithBackendBaseUrl(provider) {
    const backend = this.state.backend(defaultBackendForProvider(provider));
    return {
      ...provider,
      baseUrl: provider.baseUrl ?? backend.baseUrl,
      status: provider.status === "blocked" && (backend.binaryPath || backend.baseUrl) ? "configured" : provider.status,
    };
  }

  async health(provider, { state } = {}) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const result = await this.openAi.health(effectiveProvider, { state });
    const backend = state.backend(defaultBackendForProvider(provider));
    return {
      ...result,
      status: result.status === "available" ? "available" : backend.binaryPath ? "degraded" : result.status,
      evidenceRefs: [
        "vllm_openai_compatible_models_probe",
        ...(result.evidenceRefs ?? []),
        ...(backend.binaryPath ? ["vllm_binary_configured"] : []),
      ],
      binaryPathHash: backend.binaryPath ? stableHash(backend.binaryPath) : null,
    };
  }

  async listModels({ state, provider }) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const models = await this.openAi.listModels({ state, provider: effectiveProvider });
    return models.map((model) => ({
      ...model,
      providerId: provider.id,
      family: "vllm",
      source: "vllm_openai_compatible_models_endpoint",
      compatibility: ["vllm", "safetensors", "hf_repository"],
    }));
  }

  async listLoaded({ state, provider }) {
    const backendId = defaultBackendForProvider(provider);
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backend: "vllm",
        backendId,
        backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
        evidenceRefs: ["vllm_agentgres_loaded_instance_projection"],
      }));
  }

  async load({ state, provider, endpoint, body = {} }) {
    const loadOptions = normalizeLoadOptions(canonicalLoadOptionsInput(body), endpoint.loadPolicy);
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    const processRecord =
      provider.id === "provider.vllm" && backend.binaryPath
        ? state.ensureBackendProcess(backendId, { endpoint, loadOptions, reason: "vllm_model_load" })
        : null;
    return {
      status: "loaded",
      backend: "vllm",
      backendId,
      process: state.backendProcessSnapshot(processRecord),
      evidenceRefs: [
        ...(processRecord ? ["vllm_process_supervisor", "vllm_openai_compatible_server"] : ["vllm_stateless_http_load"]),
      ],
    };
  }

  async unload({ state, provider, endpoint }) {
    const backendId = endpoint?.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    const stopped = provider.id === "provider.vllm" && backend.binaryPath ? state.stopBackendProcess(backend, { reason: "vllm_model_unload" }) : null;
    const processSnapshot = state.backendProcessSnapshot(stopped);
    return {
      status: "unloaded",
      backend: "vllm",
      backendId,
      process: processSnapshot,
      evidenceRefs: [
        ...(stopped ? ["vllm_process_supervisor", "clean_backend_stop", ...normalizeScopes(processSnapshot.evidenceRefs, [])] : ["vllm_stateless_http_unload"]),
      ],
    };
  }

  supportsStream(kind) {
    return this.openAi.supportsStream(kind);
  }

  async streamInvoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const backend = args.state.backend(backendId);
    const processRecord =
      provider.id === "provider.vllm" && backend.binaryPath
        ? args.state.ensureBackendProcess(backendId, {
            endpoint: args.endpoint,
            loadOptions: args.instance?.loadOptions ?? {},
            reason: "vllm_model_stream",
          })
        : null;
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.streamInvoke({ ...args, provider });
    if (!result) return null;
    return {
      ...result,
      backend: "vllm",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "vllm_openai_compatible_server",
        ...(processRecord ? ["vllm_process_supervisor", ...normalizeScopes(processSnapshot.evidenceRefs, [])] : []),
        ...(result.backendEvidenceRefs ?? []),
      ],
    };
  }

  async invoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const backend = args.state.backend(backendId);
    const processRecord =
      provider.id === "provider.vllm" && backend.binaryPath
        ? args.state.ensureBackendProcess(backendId, {
            endpoint: args.endpoint,
            loadOptions: args.instance?.loadOptions ?? {},
            reason: "vllm_model_invoke",
          })
        : null;
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.invoke({ ...args, provider });
    return {
      ...result,
      backend: "vllm",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "vllm_openai_compatible_server",
        ...(processRecord ? ["vllm_process_supervisor", ...normalizeScopes(processSnapshot.evidenceRefs, [])] : []),
        ...(result.backendEvidenceRefs ?? []),
      ],
    };
  }
}

export class LlamaCppModelProviderDriver {
  constructor({ state }) {
    this.state = state;
    this.openAi = new OpenAICompatibleModelProviderDriver({ label: "llama_cpp" });
  }

  providerWithBackendBaseUrl(provider) {
    const backend = this.state.backend(defaultBackendForProvider(provider));
    return {
      ...provider,
      baseUrl: provider.baseUrl ?? backend.baseUrl,
      status: provider.status === "blocked" && (backend.binaryPath || backend.baseUrl) ? "configured" : provider.status,
    };
  }

  async health(provider, { state } = {}) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const backend = state.backend(defaultBackendForProvider(provider));
    if (!effectiveProvider.baseUrl) {
      return {
        status: backend.binaryPath ? "configured" : "blocked",
        evidenceRefs: ["llama_cpp_binary_configured_without_server_probe"],
      };
    }
    const result = await this.openAi.health(effectiveProvider, { state });
    return {
      ...result,
      status: result.status === "available" ? "available" : backend.binaryPath ? "degraded" : result.status,
      evidenceRefs: [
        "llama_cpp_openai_compatible_models_probe",
        ...(result.evidenceRefs ?? []),
        ...(backend.binaryPath ? ["llama_cpp_binary_configured"] : []),
      ],
      binaryPathHash: backend.binaryPath ? stableHash(backend.binaryPath) : null,
    };
  }

  async listModels({ state, provider }) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const models = await this.openAi.listModels({ state, provider: effectiveProvider });
    return models.map((model) => ({
      ...model,
      providerId: provider.id,
      family: "llama_cpp",
      source: "llama_cpp_openai_compatible_models_endpoint",
      compatibility: ["llama_cpp", "gguf"],
    }));
  }

  async listLoaded({ state, provider }) {
    const backendId = defaultBackendForProvider(provider);
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backend: "llama_cpp",
        backendId,
        backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
        evidenceRefs: ["llama_cpp_agentgres_loaded_instance_projection"],
      }));
  }

  async load({ state, provider, endpoint, body = {} }) {
    const loadOptions = normalizeLoadOptions(canonicalLoadOptionsInput(body), endpoint.loadPolicy);
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const processRecord = state.ensureBackendProcess(backendId, {
      endpoint,
      loadOptions,
      reason: "llama_cpp_model_load",
    });
    const processSnapshot = state.backendProcessSnapshot(processRecord);
    return {
      status: "loaded",
      backend: "llama_cpp",
      backendId,
      process: processSnapshot,
      evidenceRefs: [
        "llama_cpp_process_supervisor",
        "llama_cpp_openai_compatible_server",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
      ],
    };
  }

  async unload({ state, provider, endpoint }) {
    const backend = state.backend(endpoint?.backendId ?? defaultBackendForProvider(provider));
    const stopped = state.stopBackendProcess(backend, { reason: "llama_cpp_model_unload" });
    const processSnapshot = state.backendProcessSnapshot(stopped);
    return {
      status: "unloaded",
      backend: "llama_cpp",
      backendId: backend.id,
      process: processSnapshot,
      evidenceRefs: ["llama_cpp_process_supervisor", "clean_backend_stop", ...normalizeScopes(processSnapshot.evidenceRefs, [])],
    };
  }

  supportsStream(kind) {
    return this.openAi.supportsStream(kind);
  }

  async streamInvoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const processRecord = args.state.ensureBackendProcess(backendId, {
      endpoint: args.endpoint,
      loadOptions: args.instance?.loadOptions ?? {},
      reason: "llama_cpp_model_stream",
    });
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.streamInvoke({ ...args, provider });
    if (!result) return null;
    return {
      ...result,
      backend: "llama_cpp",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "llama_cpp_openai_compatible_server",
        "llama_cpp_process_supervisor",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
        ...(result.backendEvidenceRefs ?? []),
      ],
    };
  }

  async invoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const processRecord = args.state.ensureBackendProcess(backendId, {
      endpoint: args.endpoint,
      loadOptions: args.instance?.loadOptions ?? {},
      reason: "llama_cpp_model_invoke",
    });
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.invoke({ ...args, provider });
    return {
      ...result,
      backend: "llama_cpp",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "llama_cpp_openai_compatible_server",
        "llama_cpp_process_supervisor",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
        ...(result.backendEvidenceRefs ?? []),
      ],
    };
  }
}
