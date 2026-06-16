import crypto from "node:crypto";

function invocationProtocolMetadata(invocation, extra = {}) {
  const details = invocation.receipt?.details && typeof invocation.receipt.details === "object"
    ? invocation.receipt.details
    : {};
  const routeDecision = invocation.routeReceipt?.details?.model_route_decision ?? details.model_route_decision ?? null;
  const endpointId = invocation.endpoint?.id ?? details.endpoint_id ?? details.endpointId ?? null;
  const instanceId = invocation.instance?.id ?? details.instance_id ?? details.instanceId ?? null;
  const backendId =
    invocation.instance?.backendId ??
    invocation.instance?.backend_id ??
    invocation.backendId ??
    invocation.backend_id ??
    details.backend_id ??
    details.backendId ??
    null;
  return {
    receipt_id: invocation.receipt?.id ?? null,
    route_id: invocation.route?.id ?? null,
    endpoint_id: endpointId,
    instance_id: instanceId,
    backend_id: backendId,
    route_receipt_id: invocation.routeReceipt?.id ?? details.route_receipt_id ?? details.routeReceiptId ?? null,
    route_decision: routeDecision,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
    output_text: invocation.outputText ?? "",
    ...extra,
  };
}

export function openAiChatCompletion(invocation, body = {}) {
  if (invocation.providerResponseKind === "chat.completions" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      ...invocationProtocolMetadata(invocation, { request_model: body.model ?? null }),
    };
  }
  return {
    id: `chatcmpl_${crypto.randomUUID()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: invocation.model,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: invocation.outputText },
        finish_reason: "stop",
      },
    ],
    usage: invocation.tokenCount,
    ...invocationProtocolMetadata(invocation, { request_model: body.model ?? null }),
  };
}

export function openAiResponse(invocation) {
  if (invocation.providerResponseKind === "responses" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      id: invocation.responseId ?? invocation.providerResponse.id,
      ...invocationProtocolMetadata(invocation),
    };
  }
  return {
    id: invocation.responseId ?? `resp_${crypto.randomUUID()}`,
    object: "response",
    created_at: Math.floor(Date.now() / 1000),
    model: invocation.model,
    output_text: invocation.outputText,
    output: [
      {
        id: `msg_${crypto.randomUUID()}`,
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text: invocation.outputText }],
      },
    ],
    usage: invocation.tokenCount,
    ...invocationProtocolMetadata(invocation),
  };
}

export function openAiEmbedding(invocation, body = {}) {
  if (invocation.providerResponseKind === "embeddings" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      ...invocationProtocolMetadata(invocation),
    };
  }
  void body;
  throwProviderEmbeddingResponseRequired(invocation);
}

export function openAiCompletion(invocation) {
  return {
    id: `cmpl_${crypto.randomUUID()}`,
    object: "text_completion",
    created: Math.floor(Date.now() / 1000),
    model: invocation.model,
    choices: [{ text: invocation.outputText, index: 0, finish_reason: "stop" }],
    usage: invocation.tokenCount,
    ...invocationProtocolMetadata(invocation),
  };
}

export function anthropicMessage(invocation) {
  return {
    id: `msg_${crypto.randomUUID().replace(/-/g, "").slice(0, 24)}`,
    type: "message",
    role: "assistant",
    content: [{ type: "text", text: invocation.outputText }],
    model: invocation.model,
    stop_reason: "end_turn",
    stop_sequence: null,
    usage: {
      input_tokens: Number(invocation.tokenCount?.prompt_tokens ?? 0),
      output_tokens: Number(invocation.tokenCount?.completion_tokens ?? 0),
      cache_read_input_tokens: 0,
    },
    ...invocationProtocolMetadata(invocation),
  };
}

function throwProviderEmbeddingResponseRequired(invocation = {}) {
  const error = new Error("Embedding responses require Rust/provider-authored embedding vectors.");
  error.status = 501;
  error.code = "model_mount_embedding_provider_response_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_invocation",
    operation_kind: "model_mount.provider_result.embeddings",
    provider_response_kind: invocation.providerResponseKind ?? null,
    receipt_id: invocation.receipt?.id ?? null,
    route_id: invocation.route?.id ?? null,
    response_id: invocation.responseId ?? null,
    evidence_refs: [
      "model_mount_embedding_js_vector_fallback_retired",
      "rust_daemon_core_provider_embedding_required",
    ],
  };
  throw error;
}
