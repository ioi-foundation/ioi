import crypto from "node:crypto";

export function openAiChatCompletion(invocation, body = {}) {
  if (invocation.providerResponseKind === "chat.completions" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      receipt_id: invocation.receipt.id,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      response_id: invocation.responseId ?? null,
      previous_response_id: invocation.previousResponseId ?? null,
      request_model: body.model ?? null,
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
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
    request_model: body.model ?? null,
  };
}

export function openAiResponse(invocation) {
  if (invocation.providerResponseKind === "responses" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      id: invocation.responseId ?? invocation.providerResponse.id,
      receipt_id: invocation.receipt.id,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      previous_response_id: invocation.previousResponseId ?? null,
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
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    previous_response_id: invocation.previousResponseId ?? null,
  };
}

export function openAiEmbedding(invocation, body = {}) {
  if (invocation.providerResponseKind === "embeddings" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      receipt_id: invocation.receipt.id,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      response_id: invocation.responseId ?? null,
      previous_response_id: invocation.previousResponseId ?? null,
    };
  }
  const inputs = Array.isArray(body.input) ? body.input : [body.input ?? ""];
  return {
    object: "list",
    model: invocation.model,
    data: inputs.map((item, index) => ({
      object: "embedding",
      index,
      embedding: deterministicVector(String(item)),
    })),
    usage: invocation.tokenCount,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
  };
}

export function openAiCompletion(invocation) {
  return {
    id: `cmpl_${crypto.randomUUID()}`,
    object: "text_completion",
    created: Math.floor(Date.now() / 1000),
    model: invocation.model,
    choices: [{ text: invocation.outputText, index: 0, finish_reason: "stop" }],
    usage: invocation.tokenCount,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
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
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
  };
}

export function deterministicVector(input) {
  const digest = crypto.createHash("sha256").update(input).digest();
  return Array.from({ length: 8 }, (_, index) => Number(((digest[index] / 255) * 2 - 1).toFixed(6)));
}
