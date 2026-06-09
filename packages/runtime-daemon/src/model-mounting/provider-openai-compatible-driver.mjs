import { fetchProviderJson } from "./provider-transport.mjs";
import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";
import { safeId } from "./io.mjs";

export class OpenAICompatibleModelProviderDriver {
  constructor({ label = "openai_compatible" } = {}) {
    this.label = label;
  }

  async health(provider, { state } = {}) {
    const result = await fetchProviderJson(provider, "/models", { method: "GET", tolerateHttpError: true, state });
    return {
      status: result.ok ? "available" : "degraded",
      evidenceRefs: [`${this.label}_models_probe`],
      httpStatus: result.status,
      authEvidence: result.authEvidence ?? null,
    };
  }

  async listModels({ state, provider }) {
    const result = await fetchProviderJson(provider, "/models", { method: "GET", tolerateHttpError: true, state });
    if (!result.ok) return [];
    const models = Array.isArray(result.body?.data) ? result.body.data : Array.isArray(result.body) ? result.body : [];
    return models
      .map((model) => String(model.id ?? model.model ?? ""))
      .filter(Boolean)
      .map((modelId) => ({
        id: `${safeId(provider.id)}.${safeId(modelId)}`,
        providerId: provider.id,
        modelId,
        displayName: modelId,
        family: this.label,
        quantization: null,
        sizeBytes: null,
        contextWindow: null,
        capabilities: provider.capabilities ?? ["chat", "responses", "embeddings"],
        privacyClass: provider.privacyClass,
        source: `${this.label}_models_endpoint`,
        state: "available",
        discoveredAt: new Date().toISOString(),
      }));
  }

  async listLoaded() {
    return [];
  }

  async load({ endpoint }) {
    return { status: "loaded", backend: endpoint.apiFormat, evidenceRefs: [`${this.label}_stateless_load`] };
  }

  async unload({ endpoint }) {
    return { status: "unloaded", backend: endpoint.apiFormat, evidenceRefs: [`${this.label}_stateless_unload`] };
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
