const RETIRED_MODEL_TOKENIZER_REQUEST_ALIASES = [
  "routeId",
  "modelPolicy",
  "contextLength",
  "contextWindow",
  "maxOutputTokens",
  "reserveOutputTokens",
  "reserve_output_tokens",
];

export function modelTokenizerUtility(state, { authorization, requiredScope, body = {}, operation }, deps = {}) {
  const {
    deterministicTokenizeText,
    inputText,
    stableHash,
  } = deps;
  assertCanonicalModelTokenizerRequestBody(body);
  const token = state.authorize(authorization, requiredScope);
  const input = inputText(body);
  const selection = state.selectRoute({
    modelId: body.model,
    routeId: body.route_id,
    capability: "chat",
    policy: body.model_policy ?? {},
  });
  const routeReceipt = state.routeSelectionReceipt(selection, {
    body,
    capability: "tokenize",
    evidenceRefs: ["tokenizer_utility"],
  });
  const tokens = deterministicTokenizeText(input);
  const promptTokens = Math.max(1, tokens.length);
  const contextWindow = state.contextWindowForEndpoint(selection.endpoint, body);
  const receipt = state.receipt(operation === "context_fit" ? "model_context_fit" : "model_tokenization", {
    summary: `${operation} evaluated ${promptTokens} prompt tokens for ${selection.endpoint.modelId}.`,
    redaction: "redacted",
    evidenceRefs: ["tokenizer_estimator", routeReceipt.id, selection.route.id, selection.endpoint.id, token.grantId],
    details: {
      operation,
      route_id: selection.route.id,
      route_receipt_id: routeReceipt.id,
      selected_model: selection.endpoint.modelId,
      endpoint_id: selection.endpoint.id,
      provider_id: selection.endpoint.providerId,
      backend_id: selection.endpoint.backendId ?? null,
      selected_backend: selection.endpoint.backendId ?? null,
      grant_id: token.grantId,
      estimator: "deterministic_context_estimator",
      tokenizer_source: "deterministic_estimator",
      input_hash: stableHash(input),
      token_count: {
        prompt_tokens: promptTokens,
        completion_tokens: 0,
        total_tokens: promptTokens,
      },
      context_window: contextWindow,
    },
  });
  return { token, input, tokens, promptTokens, contextWindow, selection, routeReceipt, receipt };
}

export function tokenizeModel(state, { authorization, requiredScope = "model.tokenize:*", body = {} }, deps = {}) {
  const { schemaVersion } = deps;
  const utility = state.modelTokenizerUtility({ authorization, requiredScope, body, operation: "tokenize" });
  return {
    schemaVersion,
    model: utility.selection.endpoint.modelId,
    route_id: utility.selection.route.id,
    endpoint_id: utility.selection.endpoint.id,
    provider_id: utility.selection.endpoint.providerId,
    backend_id: utility.selection.endpoint.backendId ?? null,
    tokenizer: "deterministic_context_estimator",
    tokens: utility.tokens,
    token_count: utility.promptTokens,
    usage: {
      prompt_tokens: utility.promptTokens,
      completion_tokens: 0,
      total_tokens: utility.promptTokens,
    },
    receipt_id: utility.receipt.id,
    route_receipt_id: utility.routeReceipt.id,
  };
}

export function countModelTokens(state, { authorization, requiredScope = "model.tokenize:*", body = {} }, deps = {}) {
  const {
    schemaVersion,
    stableHash,
  } = deps;
  const utility = state.modelTokenizerUtility({ authorization, requiredScope, body, operation: "count_tokens" });
  return {
    schemaVersion,
    model: utility.selection.endpoint.modelId,
    route_id: utility.selection.route.id,
    endpoint_id: utility.selection.endpoint.id,
    provider_id: utility.selection.endpoint.providerId,
    backend_id: utility.selection.endpoint.backendId ?? null,
    tokenizer: "deterministic_context_estimator",
    input_hash: stableHash(utility.input),
    token_count: utility.promptTokens,
    usage: {
      prompt_tokens: utility.promptTokens,
      completion_tokens: 0,
      total_tokens: utility.promptTokens,
    },
    receipt_id: utility.receipt.id,
    route_receipt_id: utility.routeReceipt.id,
  };
}

export function fitModelContext(state, { authorization, requiredScope = "model.context:*", body = {} }, deps = {}) {
  const {
    normalizeNonNegativeInteger,
    schemaVersion,
    stableHash,
    truncateToEstimatedTokens,
  } = deps;
  const utility = state.modelTokenizerUtility({ authorization, requiredScope, body, operation: "context_fit" });
  const reservedOutputTokens = normalizeNonNegativeInteger(
    body.max_output_tokens,
    0,
  );
  const contextWindow = utility.contextWindow;
  const availableInputTokens = Math.max(0, contextWindow - reservedOutputTokens);
  const fits = utility.promptTokens <= availableInputTokens;
  const omittedTokenEstimate = fits ? 0 : utility.promptTokens - availableInputTokens;
  const fittedInput = fits ? utility.input : truncateToEstimatedTokens(utility.input, availableInputTokens);
  return {
    schemaVersion,
    model: utility.selection.endpoint.modelId,
    route_id: utility.selection.route.id,
    endpoint_id: utility.selection.endpoint.id,
    provider_id: utility.selection.endpoint.providerId,
    backend_id: utility.selection.endpoint.backendId ?? null,
    tokenizer: "deterministic_context_estimator",
    context_window: contextWindow,
    reserved_output_tokens: reservedOutputTokens,
    available_input_tokens: availableInputTokens,
    prompt_tokens: utility.promptTokens,
    fits,
    overflow_tokens: omittedTokenEstimate,
    truncation: {
      applied: !fits,
      strategy: "keep_tail",
      omitted_token_estimate: omittedTokenEstimate,
    },
    fitted_input: fittedInput,
    fitted_input_hash: stableHash(fittedInput),
    receipt_id: utility.receipt.id,
    route_receipt_id: utility.routeReceipt.id,
  };
}

export function contextWindowForEndpoint(state, endpoint, body = {}) {
  const explicit = Number(body.context_length);
  if (Number.isFinite(explicit) && explicit > 0) return Math.floor(explicit);
  const artifact =
    (endpoint.artifactId ? state.artifacts.get(endpoint.artifactId) : null) ??
    [...state.artifacts.values()].find((candidate) => candidate.modelId === endpoint.modelId);
  const artifactContext = Number(artifact?.contextWindow ?? artifact?.metadata?.contextWindow ?? artifact?.metadata?.context);
  if (Number.isFinite(artifactContext) && artifactContext > 0) return Math.floor(artifactContext);
  return 4096;
}

function assertCanonicalModelTokenizerRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_TOKENIZER_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model tokenizer request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_tokenizer_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: ["route_id", "model_policy", "context_length", "max_output_tokens"],
  };
  throw error;
}
