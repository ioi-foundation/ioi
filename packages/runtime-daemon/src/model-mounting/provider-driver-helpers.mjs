import {
  stableHash,
  stableStringify,
} from "./io.mjs";

export function driverForProviderKind(kind) {
  if (kind === "ioi_native_local") return "native_local";
  if (kind === "lm_studio") return "lm_studio";
  if (kind === "llama_cpp") return "llama_cpp";
  if (kind === "ollama") return "ollama";
  if (kind === "vllm") return "vllm";
  if (["openai_compatible", "custom_http", "openai", "anthropic", "gemini"].includes(kind)) {
    return "openai_compatible";
  }
  return "fixture";
}

export function driverNameForProvider(provider) {
  return provider.driver ?? driverForProviderKind(provider.kind);
}

export function defaultBackendForProvider(provider) {
  if (provider.kind === "ioi_native_local") return "backend.autopilot.native-local.fixture";
  if (provider.kind === "lm_studio") return "backend.lmstudio";
  if (provider.kind === "ollama") return "backend.ollama";
  if (provider.kind === "vllm") return "backend.vllm";
  if (provider.kind === "llama_cpp") return "backend.llama-cpp";
  if (["openai_compatible", "custom_http", "openai", "anthropic", "gemini"].includes(provider.kind)) {
    return "backend.openai-compatible";
  }
  return "backend.fixture";
}

export function supportsResponseState(kind) {
  return ["chat", "chat.completions", "responses", "messages", "completions"].includes(kind);
}

export function modelInvocationCoalesceKey({
  kind,
  body = {},
  providerBody = {},
  input = "",
  token,
  selection,
  previousResponseId = null,
}) {
  if (body.stream === true || providerBody.stream === true) return null;
  if (previousResponseId) return null;
  if (kind === "embeddings" || kind === "rerank") return null;
  if (!modelInvocationIsLowVariance(body, providerBody)) return null;
  const toolCount =
    Array.isArray(providerBody.tools)
      ? providerBody.tools.length
      : Array.isArray(body.tools)
        ? body.tools.length
        : 0;
  if (toolCount > 0) return null;
  return stableStringify({
    kind,
    grantId: token?.grantId ?? null,
    routeId: selection?.route?.id ?? null,
    endpointId: selection?.endpoint?.id ?? null,
    providerId: selection?.provider?.id ?? selection?.endpoint?.providerId ?? null,
    selectedModel: selection?.endpoint?.modelId ?? body.model ?? null,
    inputHash: stableHash(input),
    providerBodyHash: stableHash(providerBodyWithoutGeneratedResponseIds(providerBody)),
    policyHash: stableHash(body.model_policy ?? {}),
  });
}

export function modelInvocationIsLowVariance(body = {}, providerBody = {}) {
  const temperature = firstFiniteNumber([
    providerBody.temperature,
    body.temperature,
    body.options?.temperature,
    body.send_options?.temperature,
    body.sendOptions?.temperature,
  ]);
  if (temperature !== null && temperature > 0.2) return false;
  const topP = firstFiniteNumber([
    providerBody.top_p,
    providerBody.topP,
    body.top_p,
    body.topP,
  ]);
  if (topP !== null && topP < 0.95) return false;
  return true;
}

export function firstFiniteNumber(values) {
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

export function providerBodyWithoutGeneratedResponseIds(providerBody = {}) {
  if (!providerBody || typeof providerBody !== "object" || Array.isArray(providerBody)) {
    return providerBody;
  }
  const copy = { ...providerBody };
  delete copy.response_id;
  delete copy.responseId;
  return copy;
}
