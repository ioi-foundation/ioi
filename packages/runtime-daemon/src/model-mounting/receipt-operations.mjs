const MODEL_LIFECYCLE_RECEIPT_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_lifecycle_receipt_js_facade_retired",
  "rust_daemon_core_model_lifecycle_receipt_required",
  "agentgres_model_lifecycle_receipt_truth_required",
];

export function listReceipts(state) {
  return state.store.listReceipts();
}

export function getReceipt(state, receiptId) {
  return state.store.getReceipt(receiptId);
}

export function lifecycleReceipt(state, operation, details = {}) {
  assertNoRetiredLifecycleSubjectAliases(details);
  throw modelLifecycleReceiptRustCoreRequiredError({
    operation,
    model_id: details.model_id ?? null,
    endpoint_id: details.endpoint_id ?? null,
    provider_id: details.provider_id ?? null,
    backend_id: details.backend_id ?? null,
  });
}

function assertNoRetiredLifecycleSubjectAliases(details = {}) {
  const retiredAliases = ["modelId", "endpointId"].filter((field) => Object.hasOwn(details, field));
  if (retiredAliases.length === 0) return;
  const error = new Error("Model lifecycle receipt details must use canonical snake_case subject fields.");
  error.status = 409;
  error.code = "model_lifecycle_receipt_detail_aliases_retired";
  error.details = { retired_aliases: retiredAliases };
  throw error;
}

export function receipt(state, kind, { id, summary, redaction, evidenceRefs, details }, deps = {}) {
  const {
    randomUUID,
    redact,
    schemaVersion,
  } = deps;
  const record = {
    id: id ?? `receipt_${kind}_${randomUUID()}`,
    runId: null,
    kind,
    summary,
    redaction,
    evidenceRefs,
    createdAt: state.nowIso(),
    details: redact(details),
    schemaVersion,
  };
  state.store.writeReceipt(record);
  state.writeProjection();
  return record;
}

export function modelLifecycleReceiptRustCoreRequiredError(details = {}) {
  const error = new Error(
    "Model lifecycle receipts require direct Rust daemon-core admission, binding, and projection.",
  );
  error.status = 501;
  error.code = "model_mount_lifecycle_receipt_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.lifecycle_receipt",
    ...details,
    evidence_refs: MODEL_LIFECYCLE_RECEIPT_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}
