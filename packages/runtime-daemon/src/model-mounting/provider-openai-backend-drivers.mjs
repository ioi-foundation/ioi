import { throwBackendProcessSupervisorRetired } from "./backend-lifecycle.mjs";
import { defaultBackendForProvider } from "./provider-driver-helpers.mjs";
import { canonicalLoadOptionsInput, normalizeLoadOptions } from "./load-policy.mjs";
import { providerHttpTransportRetiredError } from "./provider-transport.mjs";
import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";

export class VllmModelProviderDriver {
  constructor({ state }) {
    this.state = state;
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
    const backend = state.backend(defaultBackendForProvider(provider));
    throw providerHttpTransportRetiredError(this.providerWithBackendBaseUrl(provider), {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_health.vllm",
      backend_id: backend.id,
    });
  }

  async listModels({ state, provider }) {
    void state;
    throw providerHttpTransportRetiredError(this.providerWithBackendBaseUrl(provider), {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.vllm",
    });
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
    throw providerHttpTransportRetiredError(provider, {
      route: null,
      method: "LOAD",
      operation_kind: "model_mount.provider_lifecycle.vllm_load",
    });
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
    throw providerHttpTransportRetiredError(provider, {
      route: null,
      method: "UNLOAD",
      operation_kind: "model_mount.provider_lifecycle.vllm_unload",
    });
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
    throw providerHttpTransportRetiredError(effectiveProvider, {
      route: effectiveProvider.baseUrl ? "/models" : null,
      method: "GET",
      operation_kind: "model_mount.provider_health.llama_cpp",
      backend_id: backend.id,
    });
  }

  async listModels({ state, provider }) {
    void state;
    throw providerHttpTransportRetiredError(this.providerWithBackendBaseUrl(provider), {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.llama_cpp",
    });
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
