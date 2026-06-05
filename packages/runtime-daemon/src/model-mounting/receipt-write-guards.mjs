import {
  modelMountInstanceLifecycleBindingIssues,
  modelMountProviderKindRequiresRustInstanceLifecycle,
} from "./model-instance-lifecycle.mjs";

const ACCEPTED_MODEL_INVOCATION_RECEIPT_KINDS = new Set([
  "model_invocation",
  "model_invocation_coalesced",
  "model_invocation_stream_completed",
]);

const MODEL_INSTANCE_LIFECYCLE_RECEIPT_STATUSES = new Map([
  ["model_load", "loaded"],
  ["model_unload", "unloaded"],
  ["model_idle_evict", "evicted"],
  ["model_supersede", "superseded"],
]);

const PROVIDER_INVENTORY_RECEIPT_ACTIONS = new Map([
  ["provider_models_list", "list_models"],
  ["provider_loaded_list", "list_loaded"],
]);

const PROVIDER_CONTROL_RECEIPT_ACTIONS = new Map([
  ["provider_start", "start"],
  ["provider_stop", "stop"],
]);

const PROVIDER_HEALTH_LIFECYCLE_STATUSES = new Set(["available", "blocked"]);

export function assertModelMountingReceiptWriteBound(receipt) {
  assertAcceptedModelInvocationReceiptBound(receipt);
  assertModelInstanceLifecycleReceiptBound(receipt);
  assertProviderInventoryReceiptBound(receipt);
  assertProviderControlReceiptBound(receipt);
  assertProviderHealthReceiptBound(receipt);
}

function assertAcceptedModelInvocationReceiptBound(receipt) {
  if (!ACCEPTED_MODEL_INVOCATION_RECEIPT_KINDS.has(receipt?.kind)) return;
  const details = receipt?.details && typeof receipt.details === "object" ? receipt.details : {};
  const operationRef = optionalNonEmptyString(details.model_mount_agentgres_operation_ref);
  const missing = [];
  if (!optionalNonEmptyString(details.model_mount_receipt_binding_ref)) {
    missing.push("model_mount_receipt_binding_ref");
  }
  if (!optionalNonEmptyString(details.model_mount_accepted_receipt_append_hash)) {
    missing.push("model_mount_accepted_receipt_append_hash");
  }
  if (!operationRef) missing.push("model_mount_agentgres_operation_ref");
  if (!optionalNonEmptyString(details.model_mount_agentgres_admission_hash)) {
    missing.push("model_mount_agentgres_admission_hash");
  }
  if (!optionalNonEmptyString(details.model_mount_step_module_invocation?.input?.state_root_before)) {
    missing.push("model_mount_step_module_invocation.input.state_root_before");
  }
  if (!Array.isArray(details.model_mount_step_module_result?.agentgres_operation_refs)) {
    missing.push("model_mount_step_module_result.agentgres_operation_refs");
  }
  if (!optionalNonEmptyString(details.model_mount_step_module_result?.state_root_after)) {
    missing.push("model_mount_step_module_result.state_root_after");
  }
  if (!optionalNonEmptyString(details.model_mount_step_module_result?.resulting_head)) {
    missing.push("model_mount_step_module_result.resulting_head");
  }

  const mismatches = [];
  if (
    operationRef &&
    !details.model_mount_step_module_result?.agentgres_operation_refs?.includes(operationRef)
  ) {
    mismatches.push("model_mount_agentgres_operation_ref");
  }
  if (
    operationRef &&
    optionalNonEmptyString(details.model_mount_agentgres_admission?.operation_ref) !== operationRef
  ) {
    mismatches.push("model_mount_agentgres_admission.operation_ref");
  }
  if (
    optionalNonEmptyString(details.model_mount_agentgres_state_root_before) !==
    optionalNonEmptyString(details.model_mount_step_module_invocation?.input?.state_root_before)
  ) {
    mismatches.push("model_mount_agentgres_state_root_before");
  }
  if (
    optionalNonEmptyString(details.model_mount_agentgres_state_root_after) !==
    optionalNonEmptyString(details.model_mount_step_module_result?.state_root_after)
  ) {
    mismatches.push("model_mount_agentgres_state_root_after");
  }
  if (
    optionalNonEmptyString(details.model_mount_agentgres_resulting_head) !==
    optionalNonEmptyString(details.model_mount_step_module_result?.resulting_head)
  ) {
    mismatches.push("model_mount_agentgres_resulting_head");
  }

  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_invocation_receipt_direct_append_forbidden",
      message: "Model invocation receipts require Rust receipt_binder and Agentgres admission before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        missing,
        mismatches,
      },
    });
  }
}

function assertModelInstanceLifecycleReceiptBound(receipt) {
  if (receipt?.kind !== "model_lifecycle") return;
  const details = receipt?.details && typeof receipt.details === "object" ? receipt.details : {};
  const status = MODEL_INSTANCE_LIFECYCLE_RECEIPT_STATUSES.get(details.operation);
  if (!status) return;
  const providerKind = optionalNonEmptyString(details.provider_kind);
  const missing = [];
  const mismatches = [];
  if (!providerKind && optionalNonEmptyString(details.providerId ?? details.provider_id)) {
    missing.push("provider_kind");
  }
  if (!providerKind || !modelMountProviderKindRequiresRustInstanceLifecycle(providerKind)) {
    if (missing.length > 0) {
      throw runtimeError({
        status: 409,
        code: "model_mount_instance_lifecycle_receipt_direct_append_forbidden",
        message: "Model instance lifecycle receipts require provider kind before JS store persistence.",
        details: {
          receiptId: receipt?.id ?? null,
          receiptKind: receipt?.kind ?? null,
          operation: details.operation ?? null,
          missing,
          mismatches,
        },
      });
    }
    return;
  }
  const issues = modelMountInstanceLifecycleBindingIssues(details, {
    prefix: details.instance_id ?? details.operation ?? "model_lifecycle",
    status,
  });
  missing.push(...issues.missing);
  mismatches.push(...issues.mismatches);
  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_instance_lifecycle_receipt_direct_append_forbidden",
      message: "Model instance lifecycle receipts for migrated local providers require Rust model_mount lifecycle bindings before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        operation: details.operation ?? null,
        provider_kind: providerKind,
        missing,
        mismatches,
      },
    });
  }
}

function assertProviderInventoryReceiptBound(receipt) {
  if (receipt?.kind !== "model_lifecycle") return;
  const details = receipt?.details && typeof receipt.details === "object" ? receipt.details : {};
  const expectedAction = PROVIDER_INVENTORY_RECEIPT_ACTIONS.get(details.operation);
  if (!expectedAction) return;
  const providerKind = optionalNonEmptyString(details.providerKind ?? details.provider_kind);
  const missing = [];
  const mismatches = [];
  if (!providerKind && optionalNonEmptyString(details.providerId ?? details.provider_id)) {
    missing.push("provider_kind");
  }
  if (!providerKind || !modelMountProviderKindRequiresRustInstanceLifecycle(providerKind)) {
    if (missing.length > 0) {
      throw runtimeError({
        status: 409,
        code: "model_mount_provider_inventory_receipt_direct_append_forbidden",
        message: "Provider inventory receipts require provider kind before JS store persistence.",
        details: {
          receiptId: receipt?.id ?? null,
          receiptKind: receipt?.kind ?? null,
          operation: details.operation ?? null,
          missing,
          mismatches,
        },
      });
    }
    return;
  }
  if (!optionalNonEmptyString(details.model_mount_provider_inventory_hash)) {
    missing.push("model_mount_provider_inventory_hash");
  }
  if (!Array.isArray(details.model_mount_provider_inventory_evidence_refs) ||
    !details.model_mount_provider_inventory_evidence_refs.includes("rust_model_mount_provider_inventory")) {
    missing.push("model_mount_provider_inventory_evidence_refs");
  }
  if (!optionalNonEmptyString(details.model_mount_provider_inventory_action)) {
    missing.push("model_mount_provider_inventory_action");
  } else if (details.model_mount_provider_inventory_action !== expectedAction) {
    mismatches.push("model_mount_provider_inventory_action");
  }
  if (!optionalNonEmptyString(details.model_mount_provider_inventory_status)) {
    missing.push("model_mount_provider_inventory_status");
  } else if (details.model_mount_provider_inventory_status !== "listed") {
    mismatches.push("model_mount_provider_inventory_status");
  }
  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_provider_inventory_receipt_direct_append_forbidden",
      message: "Provider inventory receipts for migrated local providers require Rust model_mount inventory bindings before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        operation: details.operation ?? null,
        provider_kind: providerKind,
        missing,
        mismatches,
      },
    });
  }
}

function assertProviderControlReceiptBound(receipt) {
  if (receipt?.kind !== "model_lifecycle") return;
  const details = receipt?.details && typeof receipt.details === "object" ? receipt.details : {};
  const expectedAction = PROVIDER_CONTROL_RECEIPT_ACTIONS.get(details.operation);
  if (!expectedAction) return;
  const providerKind = optionalNonEmptyString(details.providerKind ?? details.provider_kind);
  const missing = [];
  const mismatches = [];
  if (!providerKind && optionalNonEmptyString(details.providerId ?? details.provider_id)) {
    missing.push("provider_kind");
  }
  if (!providerKind || !modelMountProviderKindRequiresRustInstanceLifecycle(providerKind)) {
    if (missing.length > 0) {
      throw runtimeError({
        status: 409,
        code: "model_mount_provider_control_receipt_direct_append_forbidden",
        message: "Provider control receipts require provider kind before JS store persistence.",
        details: {
          receiptId: receipt?.id ?? null,
          receiptKind: receipt?.kind ?? null,
          operation: details.operation ?? null,
          missing,
          mismatches,
        },
      });
    }
    return;
  }
  if (!optionalNonEmptyString(details.model_mount_provider_lifecycle_hash)) {
    missing.push("model_mount_provider_lifecycle_hash");
  }
  if (!Array.isArray(details.model_mount_provider_lifecycle_evidence_refs) ||
    !details.model_mount_provider_lifecycle_evidence_refs.includes("rust_model_mount_provider_lifecycle")) {
    missing.push("model_mount_provider_lifecycle_evidence_refs");
  }
  if (!optionalNonEmptyString(details.model_mount_provider_lifecycle_action)) {
    missing.push("model_mount_provider_lifecycle_action");
  } else if (details.model_mount_provider_lifecycle_action !== expectedAction) {
    mismatches.push("model_mount_provider_lifecycle_action");
  }
  const expectedStatus = optionalNonEmptyString(details.state);
  if (!expectedStatus) {
    missing.push("state");
  }
  if (!optionalNonEmptyString(details.model_mount_provider_lifecycle_status)) {
    missing.push("model_mount_provider_lifecycle_status");
  } else if (details.model_mount_provider_lifecycle_status !== expectedStatus) {
    mismatches.push("model_mount_provider_lifecycle_status");
  }
  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_provider_control_receipt_direct_append_forbidden",
      message: "Provider control receipts for migrated local providers require Rust model_mount lifecycle bindings before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        operation: details.operation ?? null,
        provider_kind: providerKind,
        missing,
        mismatches,
      },
    });
  }
}

function assertProviderHealthReceiptBound(receipt) {
  if (receipt?.kind !== "provider_health") return;
  const details = receipt?.details && typeof receipt.details === "object" ? receipt.details : {};
  const providerKind = optionalNonEmptyString(details.providerKind ?? details.provider_kind);
  const missing = [];
  const mismatches = [];
  if (!providerKind && optionalNonEmptyString(details.providerId ?? details.provider_id)) {
    missing.push("provider_kind");
  }
  if (!providerKind || !modelMountProviderKindRequiresRustInstanceLifecycle(providerKind)) {
    if (missing.length > 0) {
      throw runtimeError({
        status: 409,
        code: "model_mount_provider_health_receipt_direct_append_forbidden",
        message: "Provider health receipts require provider kind before JS store persistence.",
        details: {
          receiptId: receipt?.id ?? null,
          receiptKind: receipt?.kind ?? null,
          missing,
          mismatches,
        },
      });
    }
    return;
  }
  const expectedStatus = optionalNonEmptyString(details.status);
  if (!expectedStatus) {
    missing.push("status");
  } else if (!PROVIDER_HEALTH_LIFECYCLE_STATUSES.has(expectedStatus)) {
    mismatches.push("status");
  }
  if (!optionalNonEmptyString(details.model_mount_provider_lifecycle_hash)) {
    missing.push("model_mount_provider_lifecycle_hash");
  }
  if (!Array.isArray(details.model_mount_provider_lifecycle_evidence_refs) ||
    !details.model_mount_provider_lifecycle_evidence_refs.includes("rust_model_mount_provider_lifecycle")) {
    missing.push("model_mount_provider_lifecycle_evidence_refs");
  }
  if (!optionalNonEmptyString(details.model_mount_provider_lifecycle_action)) {
    missing.push("model_mount_provider_lifecycle_action");
  } else if (details.model_mount_provider_lifecycle_action !== "health") {
    mismatches.push("model_mount_provider_lifecycle_action");
  }
  if (!optionalNonEmptyString(details.model_mount_provider_lifecycle_status)) {
    missing.push("model_mount_provider_lifecycle_status");
  } else if (details.model_mount_provider_lifecycle_status !== expectedStatus) {
    mismatches.push("model_mount_provider_lifecycle_status");
  }
  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_provider_health_receipt_direct_append_forbidden",
      message: "Provider health receipts for migrated local providers require Rust model_mount lifecycle bindings before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        provider_kind: providerKind,
        missing,
        mismatches,
      },
    });
  }
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function optionalNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
