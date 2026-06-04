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
  const { stableHash } = deps;
  const now = state.nowIso();
  const record = {
    id: responseId,
    object: "ioi.model_response_state",
    status,
    redaction: "redacted",
    createdAt: now,
    previousResponseId: previousState?.id ?? null,
    rootResponseId: previousState?.rootResponseId ?? previousState?.id ?? responseId,
    kind,
    routeId: selection.route.id,
    endpointId: selection.endpoint.id,
    selectedModel: selection.endpoint.modelId,
    providerId: selection.endpoint.providerId,
    backendId: instance?.backendId ?? selection.endpoint.backendId ?? null,
    instanceId: instance?.id ?? null,
    receiptId: receipt.id,
    routeReceiptId: routeReceipt?.id ?? null,
    streamReceiptId,
    inputHash: stableHash(input),
    outputHash: stableHash(outputText),
    tokenCount,
    messageCount: Number(previousState?.messageCount ?? 0) + 2,
    continuation: continuationSafety,
    replay: {
      source: "redacted_conversation_state",
      plaintextPersisted: false,
      previousResponseId: previousState?.id ?? null,
    },
  };
  state.conversations.set(record.id, record);
  state.writeMap("model-conversations", state.conversations);
  return record;
}

export function recordModelStreamCompleted(state, {
  invocation,
  streamKind,
  outputText = "",
  providerUsage = null,
  chunksForwarded = 0,
  finishReason = null,
  providerResult = {},
}, deps = {}) {
  const {
    estimateTokens,
    normalizeUsage,
    stableHash,
  } = deps;
  const tokenCount = normalizeUsage(providerUsage, estimateTokens(invocation.input ?? "", outputText));
  const receipt = state.receipt("model_invocation_stream_completed", {
    summary: `${streamKind} stream completed for ${invocation.model}.`,
    redaction: "redacted",
    evidenceRefs: ["model_stream", streamKind, invocation.receipt.id, invocation.route.id, invocation.endpoint.id],
    details: {
      streamKind,
      streamSource: "provider_native",
      invocationReceiptId: invocation.receipt.id,
      routeId: invocation.route.id,
      selectedModel: invocation.model,
      endpointId: invocation.endpoint.id,
      providerId: invocation.endpoint.providerId,
      instanceId: invocation.instance.id,
      backendId: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
      selectedBackend: invocation.receipt.details?.selectedBackend ?? null,
      providerResponseKind: providerResult.providerResponseKind ?? invocation.providerResponseKind ?? null,
      backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
      toolReceiptIds: invocation.toolReceiptIds ?? [],
      tokenCount,
      outputHash: stableHash(outputText),
      chunksForwarded,
      finishReason,
      responseId: invocation.responseId ?? null,
      previousResponseId: invocation.previousResponseId ?? null,
    },
  });
  if (invocation.responseId) {
    invocation.conversationState = state.recordConversationState({
      responseId: invocation.responseId,
      previousState: invocation.previousConversationState ?? null,
      kind: invocation.kind,
      input: invocation.input ?? "",
      outputText,
      selection: {
        route: invocation.route,
        endpoint: invocation.endpoint,
        provider: null,
      },
      instance: invocation.instance,
      receipt: invocation.receipt,
      routeReceipt: invocation.routeReceipt,
      tokenCount,
      streamReceiptId: receipt.id,
      status: "completed",
      continuationSafety: invocation.continuationSafety ?? null,
    });
  }
  return receipt;
}

export function listConversations(state) {
  return [...state.conversations.values()].sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")));
}
