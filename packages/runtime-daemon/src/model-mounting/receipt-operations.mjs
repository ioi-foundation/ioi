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
  assertNoRetiredLifecycleSubjectAliases(details);
  assertModelInstanceLifecycleReceiptRustBound(state, operation, details);
  const subject = details.model_id ?? details.endpoint_id ?? "model registry";
  return state.receipt("model_lifecycle", {
    summary: `${operation} recorded for ${subject}.`,
    redaction: "redacted",
    evidenceRefs: ["model_registry", "agentgres_receipt_projection_boundary", operation],
    details: { operation, ...details },
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

function assertModelInstanceLifecycleReceiptRustBound(state, operation, details = {}) {
  const status = MODEL_INSTANCE_LIFECYCLE_RECEIPT_STATUSES.get(operation);
  if (!status) return;
  const providerId = details.provider_id;
  const provider = state.providers?.get?.(providerId);
  if (!modelMountInstanceLifecycleRequiresRust(provider)) return;
  const issues = modelMountInstanceLifecycleBindingIssues(details, {
    prefix: details.instance_id ?? operation,
    status,
  });
  if (issues.missing.length > 0 || issues.mismatches.length > 0) {
    const error = new Error("Model instance lifecycle receipts for migrated local providers require Rust model_mount lifecycle bindings.");
    error.status = 409;
    error.code = "model_mount_instance_lifecycle_receipt_direct_write_forbidden";
    error.details = {
      operation,
      provider_id: providerId ?? null,
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
