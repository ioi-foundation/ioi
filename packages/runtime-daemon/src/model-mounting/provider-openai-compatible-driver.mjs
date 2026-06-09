import { providerHttpTransportRetiredError } from "./provider-transport.mjs";
import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";

export class OpenAICompatibleModelProviderDriver {
  constructor({ label = "openai_compatible" } = {}) {
    this.label = label;
  }

  async health(provider, { state } = {}) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: `model_mount.provider_health.${this.label}`,
    });
  }

  async listModels({ state, provider }) {
    void state;
    throw providerHttpTransportRetiredError(provider, {
      route: "/models",
      method: "GET",
      operation_kind: `model_mount.provider_inventory.${this.label}`,
    });
  }

  async listLoaded() {
    return [];
  }

  async load({ endpoint }) {
    throw providerHttpTransportRetiredError({ id: endpoint?.providerId ?? null, kind: endpoint?.apiFormat ?? this.label }, {
      route: null,
      method: "LOAD",
      operation_kind: `model_mount.provider_lifecycle.${this.label}_load`,
    });
  }

  async unload({ endpoint }) {
    throw providerHttpTransportRetiredError({ id: endpoint?.providerId ?? null, kind: endpoint?.apiFormat ?? this.label }, {
      route: null,
      method: "UNLOAD",
      operation_kind: `model_mount.provider_lifecycle.${this.label}_unload`,
    });
  }

  supportsStream(kind) {
    return false;
  }

  async streamInvoke({ provider } = {}) {
    throw retiredJsProviderInvocationError(provider, { label: this.label, stream: true });
  }

  async invoke({ provider } = {}) {
    throw retiredJsProviderInvocationError(provider, { label: this.label, stream: false });
  }
}
