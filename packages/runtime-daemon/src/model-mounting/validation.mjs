export function validateContinuationSafety({
  body = {},
  previousState,
  runtimeError,
  selection,
  truthy,
} = {}) {
  if (!previousState) {
    return { mode: "new", previous_response_id: null, fallback_allowed: false, mismatch_fields: [] };
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
    previous_response_id: previousState.id,
    fallback_allowed: allowFallback,
    mismatch_fields: mismatchFields,
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
  const receiptId = requiredString(body.receipt_id, "receipt_id");
  const receipt = getReceipt(receiptId);
  const requiredRedaction = body.redaction ?? body.redaction_class;
  const requiredRouteId = body.route_id;
  const requiredSelectedModel = body.selected_model;
  const requiredSelectedEndpoint = body.selected_endpoint ?? body.endpoint_id;
  const requiredSelectedBackend = body.selected_backend ?? body.backend_id;
  const requiredToolReceiptIds = normalizeScopes(
    body.required_tool_receipt_ids,
    [],
  );
  const failures = [];
  if (requiredRedaction && receipt.redaction !== requiredRedaction) {
    failures.push(`redaction:${receipt.redaction}`);
  }
  if (requiredRouteId && receipt.details?.route_id !== requiredRouteId) {
    failures.push(`route:${receipt.details?.route_id ?? "missing"}`);
  }
  if (requiredSelectedModel && receipt.details?.selected_model !== requiredSelectedModel) {
    failures.push(`selected_model:${receipt.details?.selected_model ?? "missing"}`);
  }
  if (requiredSelectedEndpoint && receipt.details?.endpoint_id !== requiredSelectedEndpoint) {
    failures.push(`endpoint:${receipt.details?.endpoint_id ?? "missing"}`);
  }
  if (requiredSelectedBackend && receipt.details?.backend_id !== requiredSelectedBackend && receipt.details?.selected_backend !== requiredSelectedBackend) {
    failures.push(`backend:${receipt.details?.backend_id ?? receipt.details?.selected_backend ?? "missing"}`);
  }
  const linkedToolReceiptIds = new Set(normalizeScopes(receipt.details?.tool_receipt_ids, []));
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
        receipt_id: receiptId,
        failures,
        route_id: receipt.details?.route_id ?? null,
        selected_model: receipt.details?.selected_model ?? null,
        endpoint_id: receipt.details?.endpoint_id ?? null,
        backend_id: receipt.details?.backend_id ?? receipt.details?.selected_backend ?? null,
        required_tool_receipt_ids: requiredToolReceiptIds,
      },
    });
    throw runtimeError({
      status: 412,
      code: "policy",
      message: "Receipt Gate blocked downstream workflow execution.",
      details: { receipt_id: receiptId, failures, gate_receipt_id: blockedReceipt.id },
    });
  }
  const gateReceipt = createReceipt("workflow_receipt_gate", {
    summary: `Receipt Gate accepted ${receiptId}.`,
    redaction: "redacted",
    evidenceRefs: ["workflow_canvas", "Receipt Gate", receiptId, ...requiredToolReceiptIds],
    details: {
      receipt_id: receiptId,
      route_id: receipt.details?.route_id ?? null,
      selected_model: receipt.details?.selected_model ?? null,
      endpoint_id: receipt.details?.endpoint_id ?? null,
      backend_id: receipt.details?.backend_id ?? receipt.details?.selected_backend ?? null,
      required_tool_receipt_ids: requiredToolReceiptIds,
    },
  });
  return {
    node: "Receipt Gate",
    status: "passed",
    receipt,
    gateReceipt,
  };
}
