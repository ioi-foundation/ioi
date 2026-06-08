const MODEL_CONVERSATION_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_conversation_state_js_facade_retired",
  "model_mount_stream_completion_js_facade_retired",
  "rust_daemon_core_model_conversation_required",
  "rust_daemon_core_model_stream_completion_required",
  "agentgres_model_conversation_truth_required",
];

export function nextResponseId(state, requested, deps = {}) {
  const {
    optionalString,
    randomUUID,
    runtimeError,
  } = deps;
  const responseId = optionalString(requested) ?? `resp_${randomUUID()}`;
  if (state.conversations.has(responseId)) {
    throw runtimeError({
      status: 409,
      code: "continuation",
      message: "response_id already exists.",
      details: { response_id: responseId },
    });
  }
  return responseId;
}

export function conversationState(state, responseId, deps = {}) {
  const { runtimeError } = deps;
  const record = state.conversations.get(responseId);
  if (!record) {
    throw runtimeError({
      status: 404,
      code: "continuation",
      message: "previous_response_id was not found.",
      details: { previous_response_id: responseId },
    });
  }
  return record;
}

export function recordConversationState(state, {
  responseId,
  previousState,
  kind,
  input,
  outputText,
  selection,
  instance,
  receipt,
  routeReceipt,
  tokenCount,
  streamReceiptId = null,
  status = "completed",
  continuationSafety = null,
}, deps = {}) {
  throw modelConversationRustCoreRequiredError({
    operation: "model_conversation_state_write",
    response_id: responseId ?? null,
    previous_response_id: previousState?.id ?? null,
    receipt_id: receipt?.id ?? null,
    route_receipt_id: routeReceipt?.id ?? null,
    stream_receipt_id: streamReceiptId,
    kind,
    status,
  });
}

export function recordModelStreamCompleted(state, {
  invocation,
  streamKind,
  outputText = "",
  providerUsage = null,
  chunksForwarded = 0,
  finishReason = null,
  providerResult = {},
  providerStreamShapeSummary = null,
}, deps = {}) {
  throw modelConversationRustCoreRequiredError({
    operation: "model_stream_completion",
    stream_kind: streamKind,
    invocation_receipt_id: invocation?.receipt?.id ?? null,
    response_id: invocation?.responseId ?? null,
    previous_response_id: invocation?.previousResponseId ?? null,
    chunks_forwarded: chunksForwarded,
    finish_reason: finishReason,
    provider_response_kind: providerResult?.providerResponseKind ?? invocation?.providerResponseKind ?? null,
    has_provider_stream_shape_summary: Boolean(providerStreamShapeSummary),
  });
}

export function listConversations(state) {
  return [...state.conversations.values()].sort((left, right) => String(left.created_at ?? "").localeCompare(String(right.created_at ?? "")));
}

export function modelConversationRustCoreRequiredError(details = {}) {
  const error = new Error(
    "Model conversation state and stream completion finalization require direct Rust daemon-core admission and projection.",
  );
  error.status = 501;
  error.code = "model_mount_conversation_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.conversation",
    ...details,
    evidence_refs: MODEL_CONVERSATION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}
