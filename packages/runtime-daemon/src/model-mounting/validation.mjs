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
  "model_mount_receipt_gate_rust_owned",
  "rust_receipt_binder_core",
  "agentgres_model_receipt_gate_truth_required",
];

export function modelReceiptGateRustCoreRequiredError({ receiptId, requiredToolReceiptIds }) {
  const error = new Error("Receipt Gate validation requires Rust model_mount receipt-gate admission.");
  error.code = "model_mount_receipt_gate_rust_core_required";
  error.status = 409;
  error.details = {
    rust_core_boundary: "model_mount.receipt_gate",
    operation_kind: "workflow_receipt_gate",
    evidence_refs: MODEL_RECEIPT_GATE_RUST_CORE_REQUIRED_EVIDENCE_REFS,
    receipt_id: receiptId,
    required_tool_receipt_ids: requiredToolReceiptIds,
  };
  return error;
}

export function validateReceiptGate({
  body = {},
  getReceipt,
  normalizeScopes,
  persistRustAuthoredReceipt,
  planReceiptGate,
  requiredString,
  runtimeError,
  nowIso,
} = {}) {
  const receiptId = requiredString(body.receipt_id, "receipt_id");
  const receipt = getReceipt(receiptId);
  const requiredToolReceiptIds = normalizeScopes(
    body.required_tool_receipt_ids,
    [],
  ).filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim());
  const toolReceipts = requiredToolReceiptIds.map((toolReceiptId) => getReceipt(toolReceiptId));
  if (typeof planReceiptGate !== "function") {
    throw modelReceiptGateRustCoreRequiredError({
      receiptId,
      requiredToolReceiptIds,
    });
  }
  if (typeof persistRustAuthoredReceipt !== "function") {
    throw runtimeError({
      status: 500,
      code: "model_mount_receipt_gate_receipt_state_commit_unconfigured",
      message: "Receipt Gate validation requires Rust-authored receipt-state persistence.",
      details: {
        receipt_id: receiptId,
        rust_core_boundary: "model_mount.receipt_gate",
      },
    });
  }
  const plan = planReceiptGate({
    schema_version: "ioi.model_mount.receipt_gate.v1",
    operation_kind: "workflow_receipt_gate",
    receipt_id: receiptId,
    receipt,
    required_tool_receipt_ids: requiredToolReceiptIds,
    tool_receipts: toolReceipts,
    required_redaction: optionalString(body.redaction ?? body.redaction_class),
    required_route_id: optionalString(body.route_id),
    required_selected_model: optionalString(body.selected_model),
    required_endpoint_id: optionalString(body.selected_endpoint ?? body.endpoint_id),
    required_backend_id: optionalString(body.selected_backend ?? body.backend_id),
    source: "runtime-daemon.model_mounting.receipt_gate",
    generated_at: typeof nowIso === "function" ? nowIso() : null,
  });
  const persistedReceipt = persistRustAuthoredReceipt(plan.receipt);
  return {
    ...(plan.public_response ?? {}),
    status: plan.public_response?.status ?? plan.gate_status,
    receipt_id: receiptId,
    gate_status: plan.gate_status,
    failures: Array.isArray(plan.plan?.failures) ? plan.plan.failures : [],
    receipt: persistedReceipt,
    plan,
    receipt_refs: plan.receipt_refs ?? [],
    evidence_refs: plan.evidence_refs ?? [],
    gate_hash: plan.gate_hash ?? null,
    rust_core_boundary: plan.rust_core_boundary ?? "model_mount.receipt_gate",
  };
}

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
