export function listReceipts(state) {
  return state.store.listReceipts();
}

export function getReceipt(state, receiptId) {
  return state.store.getReceipt(receiptId);
}

export function lifecycleReceipt(state, operation, details) {
  return state.receipt("model_lifecycle", {
    summary: `${operation} recorded for ${details.modelId ?? details.endpointId ?? "model registry"}.`,
    redaction: "redacted",
    evidenceRefs: ["model_registry", "agentgres_canonical_operation_log", operation],
    details: { operation, ...details },
  });
}

export function receipt(state, kind, { summary, redaction, evidenceRefs, details }, deps = {}) {
  const {
    randomUUID,
    redact,
    schemaVersion,
  } = deps;
  const record = {
    id: `receipt_${kind}_${randomUUID()}`,
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
