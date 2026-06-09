import { throwBackendProcessSupervisorRetired } from "./backend-lifecycle.mjs";
import { defaultBackendForProvider } from "./provider-driver-helpers.mjs";
import { canonicalLoadOptionsInput, normalizeLoadOptions } from "./load-policy.mjs";
import { stableHash } from "./io.mjs";
import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";
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
    if (provider.id === "provider.vllm" && backend.binaryPath) {
      throwBackendProcessSupervisorRetired("model_mount.provider_lifecycle.vllm_load", backend, {
        provider_id: provider.id,
        endpoint_id: endpoint.id,
      });
    }
    return {
      status: "loaded",
      backend: "vllm",
      backendId,
      process: null,
      evidenceRefs: ["vllm_stateless_http_load"],
    };
  }

  async unload({ state, provider, endpoint }) {
    const backendId = endpoint?.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    if (provider.id === "provider.vllm" && backend.binaryPath) {
      throwBackendProcessSupervisorRetired("model_mount.provider_lifecycle.vllm_unload", backend, {
        provider_id: provider.id,
        endpoint_id: endpoint?.id ?? null,
      });
    }
    return {
      status: "unloaded",
      backend: "vllm",
      backendId,
      process: null,
      evidenceRefs: ["vllm_stateless_http_unload"],
    };
  }

  supportsStream(kind) {
    return false;
  }

  async streamInvoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    throw retiredJsProviderInvocationError(provider, { label: "vllm", stream: true });
  }

  async invoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    throw retiredJsProviderInvocationError(provider, { label: "vllm", stream: false });
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
    const backend = state.backend(backendId);
    void loadOptions;
    throwBackendProcessSupervisorRetired("model_mount.provider_lifecycle.llama_cpp_load", backend, {
      provider_id: provider.id,
      endpoint_id: endpoint.id,
    });
  }

  async unload({ state, provider, endpoint }) {
    const backend = state.backend(endpoint?.backendId ?? defaultBackendForProvider(provider));
    throwBackendProcessSupervisorRetired("model_mount.provider_lifecycle.llama_cpp_unload", backend, {
      provider_id: provider.id,
      endpoint_id: endpoint?.id ?? null,
    });
  }

  supportsStream(kind) {
    return false;
  }

  async streamInvoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    throw retiredJsProviderInvocationError(provider, { label: "llama_cpp", stream: true });
  }

  async invoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    throw retiredJsProviderInvocationError(provider, { label: "llama_cpp", stream: false });
  }
}
