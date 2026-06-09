import { throwBackendProcessSupervisorRetired } from "./backend-lifecycle.mjs";
import { defaultBackendForProvider } from "./provider-driver-helpers.mjs";
import { providerHttpTransportRetiredError } from "./provider-transport.mjs";
import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";

export class OllamaModelProviderDriver {
  async health(provider, { state } = {}) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/api/tags",
      method: "GET",
      operation_kind: "model_mount.provider_health.ollama",
    });
  }

  async listModels({ provider, state }) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/api/tags",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.ollama_models",
    });
  }

  async listLoaded({ provider, state }) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/api/ps",
      method: "GET",
      operation_kind: "model_mount.provider_inventory.ollama_loaded",
    });
  }

  async load({ state, provider, endpoint, body = {} }) {
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    void body;
    if (provider.id === "provider.ollama" && backend.binaryPath) {
      throwBackendProcessSupervisorRetired("model_mount.provider_lifecycle.ollama_load", backend, {
        provider_id: provider.id,
        endpoint_id: endpoint.id,
      });
    }
    throw providerHttpTransportRetiredError(provider, {
      route: "/api/generate",
      method: "POST",
      operation_kind: "model_mount.provider_lifecycle.ollama_load",
    });
  }

  async unload({ state, provider, endpoint }) {
    void state;
    void endpoint;
    throw providerHttpTransportRetiredError(provider, {
      route: "/api/generate",
      method: "POST",
      operation_kind: "model_mount.provider_lifecycle.ollama_unload",
    });
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
