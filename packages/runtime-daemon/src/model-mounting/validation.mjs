export function validateContinuationSafety({
  body = {},
  previousState,
  runtimeError,
  selection,
  truthy,
} = {}) {
  if (!previousState) {
    return { mode: "new", previousResponseId: null, fallbackAllowed: false, mismatchFields: [] };
  }
  const allowFallback = truthy(
    body.allow_continuation_fallback ??
      body.allowContinuationFallback ??
      body.allow_route_fallback ??
      body.allowRouteFallback,
  );
  const mismatchFields = [];
  if (previousState.routeId !== selection.route.id) mismatchFields.push("route_id");
  if (previousState.endpointId !== selection.endpoint.id) mismatchFields.push("endpoint_id");
  if (previousState.selectedModel !== selection.endpoint.modelId) mismatchFields.push("model");
  if (mismatchFields.length > 0 && !allowFallback) {
    throw runtimeError({
      status: 409,
      code: "continuation_route_mismatch",
      message: "Continuation would change the selected route, endpoint, or model without explicit fallback consent.",
      details: {
        previous_response_id: previousState.id,
        mismatch_fields: mismatchFields,
        required: "allow_continuation_fallback",
      },
    });
  }
  return {
    mode: mismatchFields.length > 0 ? "fallback_allowed" : "matched",
    previousResponseId: previousState.id,
    fallbackAllowed: allowFallback,
    mismatchFields,
  };
}

export function validateReceiptGate({
  body = {},
  getReceipt,
  normalizeScopes,
  receipt: createReceipt,
  requiredString,
  runtimeError,
} = {}) {
  const receiptId = requiredString(body.receipt_id ?? body.receiptId, "receipt_id");
  const receipt = getReceipt(receiptId);
  const requiredRedaction = body.redaction ?? body.redaction_class ?? body.redactionClass;
  const requiredRouteId = body.route_id ?? body.routeId;
  const requiredSelectedModel = body.selected_model ?? body.selectedModel;
  const requiredSelectedEndpoint = body.selected_endpoint ?? body.selectedEndpoint ?? body.endpoint_id ?? body.endpointId;
  const requiredSelectedBackend = body.selected_backend ?? body.selectedBackend ?? body.backend_id ?? body.backendId;
  const requiredToolReceiptIds = normalizeScopes(
    body.required_tool_receipt_ids ?? body.requiredToolReceiptIds,
    [],
  );
  const failures = [];
  if (requiredRedaction && receipt.redaction !== requiredRedaction) {
    failures.push(`redaction:${receipt.redaction}`);
  }
  if (requiredRouteId && receipt.details?.routeId !== requiredRouteId) {
    failures.push(`route:${receipt.details?.routeId ?? "missing"}`);
  }
  if (requiredSelectedModel && receipt.details?.selectedModel !== requiredSelectedModel) {
    failures.push(`selected_model:${receipt.details?.selectedModel ?? "missing"}`);
  }
  if (requiredSelectedEndpoint && receipt.details?.endpointId !== requiredSelectedEndpoint) {
    failures.push(`endpoint:${receipt.details?.endpointId ?? "missing"}`);
  }
  if (requiredSelectedBackend && receipt.details?.backendId !== requiredSelectedBackend && receipt.details?.selectedBackend !== requiredSelectedBackend) {
    failures.push(`backend:${receipt.details?.backendId ?? receipt.details?.selectedBackend ?? "missing"}`);
  }
  const linkedToolReceiptIds = new Set(normalizeScopes(receipt.details?.toolReceiptIds, []));
  for (const toolReceiptId of requiredToolReceiptIds) {
    const toolReceipt = getReceipt(toolReceiptId);
    if (toolReceipt.kind !== "mcp_tool_invocation") {
      failures.push(`tool_receipt_kind:${toolReceiptId}`);
    }
    if (!linkedToolReceiptIds.has(toolReceiptId)) {
      failures.push(`tool_receipt_link:${toolReceiptId}`);
    }
  }
  if (failures.length > 0) {
    const blockedReceipt = createReceipt("workflow_receipt_gate_blocked", {
      summary: `Receipt Gate blocked ${receiptId}.`,
      redaction: "redacted",
      evidenceRefs: ["workflow_canvas", "Receipt Gate", receiptId, ...requiredToolReceiptIds],
      details: {
        receiptId,
        failures,
        routeId: receipt.details?.routeId ?? null,
        selectedModel: receipt.details?.selectedModel ?? null,
        endpointId: receipt.details?.endpointId ?? null,
        backendId: receipt.details?.backendId ?? receipt.details?.selectedBackend ?? null,
        requiredToolReceiptIds,
      },
    });
    throw runtimeError({
      status: 412,
      code: "policy",
      message: "Receipt Gate blocked downstream workflow execution.",
      details: { receiptId, failures, gateReceiptId: blockedReceipt.id },
    });
  }
  const gateReceipt = createReceipt("workflow_receipt_gate", {
    summary: `Receipt Gate accepted ${receiptId}.`,
    redaction: "redacted",
    evidenceRefs: ["workflow_canvas", "Receipt Gate", receiptId, ...requiredToolReceiptIds],
    details: {
      receiptId,
      routeId: receipt.details?.routeId ?? null,
      selectedModel: receipt.details?.selectedModel ?? null,
      endpointId: receipt.details?.endpointId ?? null,
      backendId: receipt.details?.backendId ?? receipt.details?.selectedBackend ?? null,
      requiredToolReceiptIds,
    },
  });
  return {
    node: "Receipt Gate",
    status: "passed",
    receipt,
    gateReceipt,
  };
}
