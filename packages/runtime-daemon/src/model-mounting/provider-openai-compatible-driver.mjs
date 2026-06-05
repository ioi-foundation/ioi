import { defaultBackendForProvider } from "./provider-driver-helpers.mjs";
import {
  chatCompletionRequestBody,
  estimateTokens,
  normalizeUsage,
  outputTextFromChat,
  outputTextFromResponse,
} from "./provider-protocol.mjs";
import {
  fetchProviderJson,
  fetchProviderStream,
  providerHttpError,
} from "./provider-transport.mjs";
import { safeId, stableHash } from "./io.mjs";

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
    return kind === "chat.completions" || kind === "chat" || kind === "responses";
  }

  async streamInvoke({ state, provider, endpoint, kind, body }) {
    if (!this.supportsStream(kind)) return null;
    if (kind === "responses") {
      const responseBody = { ...body, model: body.model ?? endpoint.modelId, stream: true };
      const result = await fetchProviderStream(provider, "/responses", {
        method: "POST",
        body: responseBody,
        state,
      });
      return {
        stream: result.stream,
        abort: result.abort,
        status: result.status,
        providerResponseKind: "responses.stream",
        backend: endpoint.apiFormat,
        backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
        authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
        providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
        providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
        backendEvidenceRefs: [`${this.label}_responses_provider_native_stream`],
      };
    }
    const requestBody = chatCompletionRequestBody({ ...body, stream: true }, endpoint.modelId);
    const result = await fetchProviderStream(provider, "/chat/completions", {
      method: "POST",
      body: requestBody,
      state,
    });
    return {
      stream: result.stream,
      abort: result.abort,
      status: result.status,
      providerResponseKind: "chat.completions.stream",
      backend: endpoint.apiFormat,
      backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
      authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
      providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
      providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
      backendEvidenceRefs: [`${this.label}_provider_native_stream`],
    };
  }

  async invoke({ state, provider, endpoint, kind, body, input }) {
    if (kind === "embeddings") {
      const requestBody = { ...body, model: body.model ?? endpoint.modelId };
      const result = await fetchProviderJson(provider, "/embeddings", { method: "POST", body: requestBody, state });
      const outputText = `embedding:${endpoint.modelId}:${stableHash(result.body?.data ?? input).slice(0, 12)}`;
      return {
        outputText,
        tokenCount: normalizeUsage(result.body?.usage, estimateTokens(input, outputText)),
        providerResponse: result.body,
        providerResponseKind: "embeddings",
        backend: endpoint.apiFormat,
        backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
        authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
        providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
        providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
      };
    }

    if (kind === "responses") {
      const responseBody = { ...body, model: body.model ?? endpoint.modelId };
      const result = await fetchProviderJson(provider, "/responses", {
        method: "POST",
        body: responseBody,
        tolerateHttpError: true,
        state,
      });
      if (result.ok) {
        const outputText = outputTextFromResponse(result.body);
        return {
          outputText,
          tokenCount: normalizeUsage(result.body?.usage, estimateTokens(input, outputText)),
          providerResponse: result.body,
          providerResponseKind: "responses",
          backend: endpoint.apiFormat,
          backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
          authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
          providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
          providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
        };
      }
      throw providerHttpError(provider, "OpenAI-compatible responses call failed.", result);
    }

    const requestBody = chatCompletionRequestBody(body, endpoint.modelId);
    const result = await fetchProviderJson(provider, "/chat/completions", {
      method: "POST",
      body: requestBody,
      state,
    });
    const outputText = outputTextFromChat(result.body);
    return {
      outputText,
      tokenCount: normalizeUsage(result.body?.usage, estimateTokens(input, outputText)),
      providerResponse: result.body,
      providerResponseKind: "chat.completions",
      backend: endpoint.apiFormat,
      backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
      authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
      providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
      providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
    };
  }
}
