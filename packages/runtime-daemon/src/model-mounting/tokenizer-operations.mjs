const RETIRED_MODEL_TOKENIZER_REQUEST_ALIASES = [
  "routeId",
  "modelPolicy",
  "contextLength",
  "contextWindow",
  "maxOutputTokens",
  "reserveOutputTokens",
  "reserve_output_tokens",
];

const MODEL_TOKENIZER_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_tokenizer_js_facade_retired",
  "model_mount_context_fit_js_facade_retired",
  "rust_daemon_core_model_tokenizer_required",
  "rust_daemon_core_model_context_fit_required",
  "agentgres_model_tokenizer_truth_required",
];

export function modelTokenizerUtility(state, { authorization, requiredScope, body = {}, operation }, deps = {}) {
  assertCanonicalModelTokenizerRequestBody(body);
  throw modelTokenizerRustCoreRequiredError({
    operation,
    model: body.model ?? null,
    route_id: body.route_id ?? null,
    requested_scope: requiredScope ?? null,
  });
}

export function tokenizeModel(state, { authorization, requiredScope = "model.tokenize:*", body = {} }, deps = {}) {
  return modelTokenizerUtility(state, { authorization, requiredScope, body, operation: "tokenize" }, deps);
}

export function countModelTokens(state, { authorization, requiredScope = "model.tokenize:*", body = {} }, deps = {}) {
  return modelTokenizerUtility(state, { authorization, requiredScope, body, operation: "count_tokens" }, deps);
}

export function fitModelContext(state, { authorization, requiredScope = "model.context:*", body = {} }, deps = {}) {
  return modelTokenizerUtility(state, { authorization, requiredScope, body, operation: "context_fit" }, deps);
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

export function modelTokenizerRustCoreRequiredError(details = {}) {
  const error = new Error(
    "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
  );
  error.status = 501;
  error.code = "model_mount_tokenizer_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.tokenizer",
    ...details,
    evidence_refs: MODEL_TOKENIZER_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}
