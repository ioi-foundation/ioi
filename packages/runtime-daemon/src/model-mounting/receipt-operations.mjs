import {
  modelMountInstanceLifecycleBindingIssues,
  modelMountInstanceLifecycleRequiresRust,
} from "./model-instance-lifecycle.mjs";

const MODEL_INSTANCE_LIFECYCLE_RECEIPT_STATUSES = new Map([
  ["model_load", "loaded"],
  ["model_unload", "unloaded"],
  ["model_idle_evict", "evicted"],
  ["model_supersede", "superseded"],
]);

export function listReceipts(state) {
  return state.store.listReceipts();
}

export function getReceipt(state, receiptId) {
  return state.store.getReceipt(receiptId);
}

export function lifecycleReceipt(state, operation, details = {}) {
  assertModelInstanceLifecycleReceiptRustBound(state, operation, details);
  const subject = details.model_id ?? details.modelId ?? details.endpoint_id ?? details.endpointId ?? "model registry";
  return state.receipt("model_lifecycle", {
    summary: `${operation} recorded for ${subject}.`,
    redaction: "redacted",
    evidenceRefs: ["model_registry", "agentgres_receipt_projection_boundary", operation],
    details: { operation, ...details },
  });
}

function assertModelInstanceLifecycleReceiptRustBound(state, operation, details = {}) {
  const status = MODEL_INSTANCE_LIFECYCLE_RECEIPT_STATUSES.get(operation);
  if (!status) return;
  const provider = state.providers?.get?.(details.providerId);
  if (!modelMountInstanceLifecycleRequiresRust(provider)) return;
  const issues = modelMountInstanceLifecycleBindingIssues(details, {
    prefix: details.instanceId ?? operation,
    status,
  });
  if (issues.missing.length > 0 || issues.mismatches.length > 0) {
    const error = new Error("Model instance lifecycle receipts for migrated local providers require Rust model_mount lifecycle bindings.");
    error.status = 409;
    error.code = "model_mount_instance_lifecycle_receipt_direct_write_forbidden";
    error.details = {
      operation,
      providerId: details.providerId ?? null,
      missing: issues.missing,
      mismatches: issues.mismatches,
    };
    throw error;
  }
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
