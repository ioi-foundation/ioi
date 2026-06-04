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
  const operationRef = optionalNonEmptyString(details.modelMountAgentgresOperationRef);
  const missing = [];
  if (!optionalNonEmptyString(details.modelMountReceiptBindingRef)) missing.push("modelMountReceiptBindingRef");
  if (!optionalNonEmptyString(details.modelMountAcceptedReceiptAppendHash)) {
    missing.push("modelMountAcceptedReceiptAppendHash");
  }
  if (!operationRef) missing.push("modelMountAgentgresOperationRef");
  if (!optionalNonEmptyString(details.modelMountAgentgresAdmissionHash)) {
    missing.push("modelMountAgentgresAdmissionHash");
  }
  if (!optionalNonEmptyString(details.modelMountStepModuleInvocation?.input?.state_root_before)) {
    missing.push("modelMountStepModuleInvocation.input.state_root_before");
  }
  if (!Array.isArray(details.modelMountStepModuleResult?.agentgres_operation_refs)) {
    missing.push("modelMountStepModuleResult.agentgres_operation_refs");
  }
  if (!optionalNonEmptyString(details.modelMountStepModuleResult?.state_root_after)) {
    missing.push("modelMountStepModuleResult.state_root_after");
  }
  if (!optionalNonEmptyString(details.modelMountStepModuleResult?.resulting_head)) {
    missing.push("modelMountStepModuleResult.resulting_head");
  }

  const mismatches = [];
  if (
    operationRef &&
    !details.modelMountStepModuleResult?.agentgres_operation_refs?.includes(operationRef)
  ) {
    mismatches.push("modelMountAgentgresOperationRef");
  }
  if (
    operationRef &&
    optionalNonEmptyString(details.modelMountAgentgresAdmission?.operation_ref) !== operationRef
  ) {
    mismatches.push("modelMountAgentgresAdmission.operation_ref");
  }
  if (
    optionalNonEmptyString(details.modelMountAgentgresStateRootBefore) !==
    optionalNonEmptyString(details.modelMountStepModuleInvocation?.input?.state_root_before)
  ) {
    mismatches.push("modelMountAgentgresStateRootBefore");
  }
  if (
    optionalNonEmptyString(details.modelMountAgentgresStateRootAfter) !==
    optionalNonEmptyString(details.modelMountStepModuleResult?.state_root_after)
  ) {
    mismatches.push("modelMountAgentgresStateRootAfter");
  }
  if (
    optionalNonEmptyString(details.modelMountAgentgresResultingHead) !==
    optionalNonEmptyString(details.modelMountStepModuleResult?.resulting_head)
  ) {
    mismatches.push("modelMountAgentgresResultingHead");
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
  const providerKind = optionalNonEmptyString(details.providerKind ?? details.provider_kind);
  const missing = [];
  const mismatches = [];
  if (!providerKind && optionalNonEmptyString(details.providerId)) {
    missing.push("providerKind");
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
    prefix: details.instanceId ?? details.operation ?? "model_lifecycle",
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
        providerKind,
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
  if (!providerKind && optionalNonEmptyString(details.providerId)) {
    missing.push("providerKind");
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
  if (!optionalNonEmptyString(details.modelMountProviderInventoryHash)) {
    missing.push("modelMountProviderInventoryHash");
  }
  if (!Array.isArray(details.modelMountProviderInventoryEvidenceRefs) ||
    !details.modelMountProviderInventoryEvidenceRefs.includes("rust_model_mount_provider_inventory")) {
    missing.push("modelMountProviderInventoryEvidenceRefs");
  }
  if (!optionalNonEmptyString(details.modelMountProviderInventoryAction)) {
    missing.push("modelMountProviderInventoryAction");
  } else if (details.modelMountProviderInventoryAction !== expectedAction) {
    mismatches.push("modelMountProviderInventoryAction");
  }
  if (!optionalNonEmptyString(details.modelMountProviderInventoryStatus)) {
    missing.push("modelMountProviderInventoryStatus");
  } else if (details.modelMountProviderInventoryStatus !== "listed") {
    mismatches.push("modelMountProviderInventoryStatus");
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
        providerKind,
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
  if (!providerKind && optionalNonEmptyString(details.providerId)) {
    missing.push("providerKind");
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
  if (!optionalNonEmptyString(details.providerLifecycleHash)) {
    missing.push("providerLifecycleHash");
  }
  if (!Array.isArray(details.modelMountProviderLifecycleEvidenceRefs) ||
    !details.modelMountProviderLifecycleEvidenceRefs.includes("rust_model_mount_provider_lifecycle")) {
    missing.push("modelMountProviderLifecycleEvidenceRefs");
  }
  if (!optionalNonEmptyString(details.modelMountProviderLifecycleAction)) {
    missing.push("modelMountProviderLifecycleAction");
  } else if (details.modelMountProviderLifecycleAction !== expectedAction) {
    mismatches.push("modelMountProviderLifecycleAction");
  }
  const expectedStatus = optionalNonEmptyString(details.state);
  if (!expectedStatus) {
    missing.push("state");
  }
  if (!optionalNonEmptyString(details.modelMountProviderLifecycleStatus)) {
    missing.push("modelMountProviderLifecycleStatus");
  } else if (details.modelMountProviderLifecycleStatus !== expectedStatus) {
    mismatches.push("modelMountProviderLifecycleStatus");
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
        providerKind,
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
  if (!providerKind && optionalNonEmptyString(details.providerId)) {
    missing.push("providerKind");
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
  if (!optionalNonEmptyString(details.providerLifecycleHash)) {
    missing.push("providerLifecycleHash");
  }
  if (!Array.isArray(details.modelMountProviderLifecycleEvidenceRefs) ||
    !details.modelMountProviderLifecycleEvidenceRefs.includes("rust_model_mount_provider_lifecycle")) {
    missing.push("modelMountProviderLifecycleEvidenceRefs");
  }
  if (!optionalNonEmptyString(details.modelMountProviderLifecycleAction)) {
    missing.push("modelMountProviderLifecycleAction");
  } else if (details.modelMountProviderLifecycleAction !== "health") {
    mismatches.push("modelMountProviderLifecycleAction");
  }
  if (!optionalNonEmptyString(details.modelMountProviderLifecycleStatus)) {
    missing.push("modelMountProviderLifecycleStatus");
  } else if (details.modelMountProviderLifecycleStatus !== expectedStatus) {
    mismatches.push("modelMountProviderLifecycleStatus");
  }
  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_provider_health_receipt_direct_append_forbidden",
      message: "Provider health receipts for migrated local providers require Rust model_mount lifecycle bindings before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        providerKind,
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
