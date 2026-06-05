export function capabilityForWorkflowNode(node) {
  if (node === "Embedding") return "embeddings";
  if (node === "Reranker") return "rerank";
  if (node === "Vision") return "vision";
  if (node === "Structured Output") return "responses";
  if (node === "Local Tool/MCP" || node === "Local Tool / MCP") return "mcp";
  if (node === "Receipt Gate") return "receipt_gate";
  return "chat";
}

export function workflowKindForNode(node) {
  if (node === "Embedding") return "embeddings";
  if (node === "Reranker") return "rerank";
  if (node === "Structured Output") return "responses";
  return "chat";
}

export function nativeInvocationResponseShape(invocation) {
  return {
    model: invocation.model,
    route_id: invocation.route.id,
    endpoint_id: invocation.endpoint.id,
    instance_id: invocation.instance.id,
    backend_id: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
    receipt_id: invocation.receipt.id,
    route_receipt_id: invocation.routeReceipt.id,
    route_decision: invocation.routeReceipt?.details?.model_route_decision ?? null,
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    send_options: invocation.receipt.details?.sendOptions ?? null,
    memory_policy: invocation.receipt.details?.memory ?? null,
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
}
