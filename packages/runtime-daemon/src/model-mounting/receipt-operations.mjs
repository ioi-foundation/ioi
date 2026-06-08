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

export function persistRustAuthoredReceipt(state, record = {}) {
  assertRustAuthoredReceiptRecord(record);
  state.store.writeReceipt(record);
  state.writeProjection();
  return record;
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
  void state;
  void kind;
  void id;
  void summary;
  void redaction;
  void evidenceRefs;
  void details;
  void deps;
  throw modelMountJsReceiptCreationRetiredError();
}

function assertRustAuthoredReceiptRecord(record = {}) {
  const evidenceRefs = Array.isArray(record.evidenceRefs) ? record.evidenceRefs : [];
  const details = record.details && typeof record.details === "object" ? record.details : {};
  const missing = [];
  if (!record.id) missing.push("id");
  if (!record.kind) missing.push("kind");
  if (!record.createdAt) missing.push("createdAt");
  if (!record.schemaVersion) missing.push("schemaVersion");
  if (!evidenceRefs.includes("rust_model_mount_core")) missing.push("evidenceRefs.rust_model_mount_core");
  if (!details.rust_daemon_core_receipt_author) missing.push("details.rust_daemon_core_receipt_author");
  if (!details.model_mount_route_decision_ref) missing.push("details.model_mount_route_decision_ref");
  if (missing.length === 0) return;
  const error = new Error("Model-mount receipt persistence requires a Rust-authored receipt record.");
  error.status = 502;
  error.code = "model_mount_rust_authored_receipt_required";
  error.details = { missing };
  throw error;
}

export function modelMountJsReceiptCreationRetiredError() {
  const error = new Error("Model-mount receipt creation in JS is retired; Rust daemon core must author receipt records.");
  error.status = 501;
  error.code = "model_mount_js_receipt_creation_retired";
  error.details = {
    rust_core_boundary: "model_mount.receipt_authoring",
    evidence_refs: [
      "model_mount_js_receipt_creation_retired",
      "rust_daemon_core_model_mount_receipt_authoring_required",
      "agentgres_model_mount_receipt_truth_required",
    ],
  };
  return error;
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
