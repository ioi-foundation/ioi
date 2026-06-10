import { defaultBackendForProvider } from "./provider-driver-helpers.mjs";
import { providerHttpTransportRetiredError } from "./provider-transport.mjs";
import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";

export class VllmModelProviderDriver {
  async health(provider, { state } = {}) {
    const backend = state.backend(defaultBackendForProvider(provider));
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_health.vllm",
      backend_id: backend.id,
    });
  }

  async listModels({ state, provider }) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.vllm",
    });
  }

  async listLoaded({ state, provider }) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.vllm_loaded",
    });
  }

  async load({ state, provider, endpoint, body = {} }) {
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    void body;
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
    throw retiredJsProviderInvocationError(args.provider, { label: "vllm", stream: true });
  }

  async invoke(args) {
    throw retiredJsProviderInvocationError(args.provider, { label: "vllm", stream: false });
  }
}

export class LlamaCppModelProviderDriver {
  async health(provider, { state } = {}) {
    const backend = state.backend(defaultBackendForProvider(provider));
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_health.llama_cpp",
      backend_id: backend.id,
    });
  }

  async listModels({ state, provider }) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.llama_cpp",
    });
  }

  async listLoaded({ state, provider }) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.llama_cpp_loaded",
    });
  }

  async load({ state, provider, endpoint, body = {} }) {
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    void body;
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
    throw retiredJsProviderInvocationError(args.provider, { label: "llama_cpp", stream: true });
  }

  async invoke(args) {
    throw retiredJsProviderInvocationError(args.provider, { label: "llama_cpp", stream: false });
  }
}

function throwBackendProcessSupervisorRetired(operation_kind, backend = {}, details = {}) {
  const error = new Error("Backend process supervision requires Rust daemon-core model_mount lifecycle ownership.");
  error.status = 501;
  error.code = "model_mount_backend_process_supervisor_retired";
  error.details = {
    backend_id: backend?.id ?? null,
    backend_kind: backend?.kind ?? null,
    operation_kind,
    rust_core_boundary: "model_mount.backend_lifecycle",
    ...details,
    evidence_refs: [
      "js_backend_process_supervisor_retired",
      "rust_daemon_core_backend_process_required",
      "agentgres_backend_process_truth_required",
    ],
  };
  throw error;
}
