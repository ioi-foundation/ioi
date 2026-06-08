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
  const allowFallback = truthy(body.allow_continuation_fallback);
  const mismatchFields = [];
  if (previousState.route_id !== selection.route.id) mismatchFields.push("route_id");
  if (previousState.endpoint_id !== selection.endpoint.id) mismatchFields.push("endpoint_id");
  if (previousState.selected_model !== selection.endpoint.modelId) mismatchFields.push("model");
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

export const MODEL_RECEIPT_GATE_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_receipt_gate_js_facade_retired",
  "rust_daemon_core_model_receipt_gate_required",
  "agentgres_model_receipt_gate_truth_required",
];

export function modelReceiptGateRustCoreRequiredError({ receiptId, receipt, requiredToolReceiptIds, failures }) {
  const error = new Error("Receipt Gate validation requires Rust model_mount receipt-gate admission.");
  error.code = "model_mount_receipt_gate_rust_core_required";
  error.status = 409;
  error.details = {
    boundary: "model_mount.receipt_gate",
    operation_kind: "workflow_receipt_gate",
    evidence_refs: MODEL_RECEIPT_GATE_RUST_CORE_REQUIRED_EVIDENCE_REFS,
    receipt_id: receiptId,
    gate_status: failures.length > 0 ? "blocked" : "passed",
    failures,
    route_id: receipt.details?.route_id ?? null,
    selected_model: receipt.details?.selected_model ?? null,
    endpoint_id: receipt.details?.endpoint_id ?? null,
    backend_id: receipt.details?.backend_id ?? receipt.details?.selected_backend ?? null,
    required_tool_receipt_ids: requiredToolReceiptIds,
  };
  return error;
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
  void createReceipt;
  throw modelReceiptGateRustCoreRequiredError({
    receiptId,
    receipt,
    requiredToolReceiptIds,
    failures,
  });
}
