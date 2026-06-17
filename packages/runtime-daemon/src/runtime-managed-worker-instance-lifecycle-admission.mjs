import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const MANAGED_WORKER_INSTANCE_LIFECYCLE_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.managed_worker_instance_lifecycle_admission.v1";

const LIFECYCLE_STATES = new Set([
  "discover",
  "installed",
  "initializing",
  "active",
  "idle",
  "zero_to_idle",
  "suspended",
  "payment_past_due",
  "archived",
  "restoring",
  "migrated",
  "exported",
  "deleted",
  "forgotten",
]);

const PERSISTENCE_PROFILES = new Set([
  "ephemeral",
  "session",
  "zero_to_idle",
  "persistent",
]);

const PAYMENT_STATUSES = new Set([
  "current",
  "past_due",
  "canceled",
  "settled",
  "not_applicable",
]);

const ALLOWED_TRANSITIONS = new Map([
  ["discover", new Set(["installed"])],
  ["installed", new Set(["initializing", "deleted"])],
  ["initializing", new Set(["active", "suspended", "deleted"])],
  [
    "active",
    new Set([
      "idle",
      "suspended",
      "payment_past_due",
      "archived",
      "migrated",
      "exported",
      "deleted",
    ]),
  ],
  [
    "idle",
    new Set([
      "active",
      "zero_to_idle",
      "suspended",
      "payment_past_due",
      "archived",
      "migrated",
      "exported",
      "deleted",
    ]),
  ],
  [
    "zero_to_idle",
    new Set([
      "active",
      "suspended",
      "payment_past_due",
      "archived",
      "migrated",
      "exported",
      "deleted",
    ]),
  ],
  [
    "suspended",
    new Set([
      "active",
      "payment_past_due",
      "archived",
      "exported",
      "deleted",
    ]),
  ],
  [
    "payment_past_due",
    new Set([
      "active",
      "suspended",
      "zero_to_idle",
      "archived",
      "exported",
      "deleted",
    ]),
  ],
  ["archived", new Set(["restoring", "exported", "deleted", "forgotten"])],
  ["restoring", new Set(["active", "archived"])],
  ["migrated", new Set(["active", "archived", "exported", "deleted"])],
  ["exported", new Set(["active", "archived", "deleted", "forgotten"])],
  ["deleted", new Set(["forgotten"])],
  ["forgotten", new Set([])],
]);

const RETIRED_ALIASES = [
  "lifecycleId",
  "workerInstanceId",
  "ownerRef",
  "fromState",
  "toState",
  "archiveRefs",
  "receiptRefs",
  "agentgresOperationRefs",
];

export function admitManagedWorkerInstanceLifecycleTransition(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const lifecycleId = requiredString(request.lifecycle_id, "lifecycle_id");
  const workerInstanceId = requiredString(
    request.worker_instance_id,
    "worker_instance_id",
  );
  const workerPackageRef = optionalString(request.worker_package_ref) ?? null;
  const ownerRef = requiredString(request.owner_ref, "owner_ref");
  const fromState = enumValue(request.from_state, "from_state", LIFECYCLE_STATES);
  const toState = enumValue(request.to_state, "to_state", LIFECYCLE_STATES);
  const persistenceProfile = enumValue(
    request.persistence_profile,
    "persistence_profile",
    PERSISTENCE_PROFILES,
  );
  const paymentStatus = enumValue(
    request.payment_status ?? "not_applicable",
    "payment_status",
    PAYMENT_STATUSES,
  );
  const transitionReason = optionalString(request.transition_reason) ?? "operator_request";
  const authorityScopeRefs = uniqueScopeRefs(request.authority_scope_refs);
  const authorityGrantRefs = uniqueStrings(normalizeArray(request.authority_grant_refs));
  const policyRefs = uniqueStrings(normalizeArray(request.policy_refs));
  const archiveRefs = uniqueStrings(normalizeArray(request.archive_refs));
  const artifactRefs = uniqueStrings(normalizeArray(request.artifact_refs));
  const receiptRefs = uniqueStrings(normalizeArray(request.receipt_refs));
  const agentgresOperationRefs = uniqueStrings(
    normalizeArray(request.agentgres_operation_refs),
  );
  const requiredControls = uniqueStrings(normalizeArray(request.required_controls));
  const latestStateRoot = optionalString(request.latest_state_root) ?? null;
  const walletApprovalRef = optionalString(request.wallet_approval_ref) ?? null;
  const restoreImportRef = optionalString(request.restore_import_ref) ?? null;
  const migrationTargetRef = optionalString(request.migration_target_ref) ?? null;
  const archivePolicy = objectRecord(request.archive_policy);
  const restorePolicy = objectRecord(request.restore_policy);
  const exportPolicy = objectRecord(request.export_policy);
  const deletionPolicy = objectRecord(request.deletion_policy);
  const highRiskOrdersPaused =
    booleanValue(request.high_risk_orders_paused) ?? false;
  const newBillableWorkBlocked =
    booleanValue(request.new_billable_work_blocked) ?? false;

  assertLifecycleTransition({
    lifecycleId,
    workerInstanceId,
    ownerRef,
    fromState,
    toState,
    persistenceProfile,
    paymentStatus,
    transitionReason,
    authorityScopeRefs,
    archiveRefs,
    artifactRefs,
    receiptRefs,
    agentgresOperationRefs,
    requiredControls,
    latestStateRoot,
    walletApprovalRef,
    restoreImportRef,
    migrationTargetRef,
    archivePolicy,
    restorePolicy,
    exportPolicy,
    deletionPolicy,
    highRiskOrdersPaused,
    newBillableWorkBlocked,
  });

  const transitionId =
    optionalString(request.transition_id) ??
    `managed-worker-lifecycle:${safeId(lifecycleId)}:${safeId(fromState)}-${safeId(toState)}`;

  return {
    schema_version: MANAGED_WORKER_INSTANCE_LIFECYCLE_ADMISSION_SCHEMA_VERSION,
    transition_id: transitionId,
    lifecycle_id: lifecycleId,
    worker_instance_id: workerInstanceId,
    worker_package_ref: workerPackageRef,
    owner_ref: ownerRef,
    from_state: fromState,
    to_state: toState,
    state: toState,
    persistence_profile: persistenceProfile,
    payment_status: paymentStatus,
    transition_reason: transitionReason,
    freezes_new_billable_work:
      toState === "payment_past_due" || newBillableWorkBlocked,
    pauses_high_risk_standing_orders:
      toState === "payment_past_due" || highRiskOrdersPaused,
    latest_state_root: latestStateRoot,
    archive_policy: archivePolicy ?? null,
    restore_policy: restorePolicy ?? null,
    export_policy: exportPolicy ?? null,
    deletion_policy: deletionPolicy ?? null,
    archive_refs: archiveRefs,
    artifact_refs: artifactRefs,
    authority_scope_refs: authorityScopeRefs,
    authority_grant_refs: authorityGrantRefs,
    policy_refs: policyRefs,
    wallet_approval_ref: walletApprovalRef,
    restore_import_ref: restoreImportRef,
    migration_target_ref: migrationTargetRef,
    agentgres_operation_refs: agentgresOperationRefs,
    receipt_refs: receiptRefs,
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    runtimeTruthSource: "daemon-runtime",
  };
}

function assertLifecycleTransition({
  lifecycleId,
  workerInstanceId,
  ownerRef,
  fromState,
  toState,
  persistenceProfile,
  paymentStatus,
  transitionReason,
  authorityScopeRefs,
  archiveRefs,
  artifactRefs,
  receiptRefs,
  agentgresOperationRefs,
  requiredControls,
  latestStateRoot,
  walletApprovalRef,
  restoreImportRef,
  migrationTargetRef,
  archivePolicy,
  restorePolicy,
  exportPolicy,
  deletionPolicy,
  highRiskOrdersPaused,
  newBillableWorkBlocked,
}) {
  const allowed = ALLOWED_TRANSITIONS.get(fromState);
  if (!allowed?.has(toState)) {
    throw admissionError({
      code: "managed_worker_lifecycle_transition_invalid",
      message:
        "Managed worker lifecycle transition is not permitted by the canonical state machine.",
      details: { from_state: fromState, to_state: toState },
    });
  }
  requirePrefix(lifecycleId, "lifecycle:", "lifecycle_id");
  requirePrefix(workerInstanceId, "agent://", "worker_instance_id");
  requirePrefix(ownerRef, "wallet://", "owner_ref");
  requireAgentgresAndReceipt(agentgresOperationRefs, receiptRefs, toState);

  if (toState === "payment_past_due") {
    if (paymentStatus !== "past_due") {
      throw admissionError({
        code: "managed_worker_lifecycle_payment_status_invalid",
        message: "Payment-past-due transitions must carry payment_status=past_due.",
        details: { payment_status: paymentStatus },
      });
    }
    requireControl(requiredControls, "freeze_new_billable_work", toState);
    requireControl(requiredControls, "pause_high_risk_standing_orders", toState);
    if (!newBillableWorkBlocked || !highRiskOrdersPaused) {
      throw admissionError({
        code: "managed_worker_lifecycle_lapse_freeze_required",
        message:
          "Payment lapse must freeze new billable work and pause high-risk standing orders.",
        details: {
          new_billable_work_blocked: newBillableWorkBlocked,
          high_risk_orders_paused: highRiskOrdersPaused,
        },
      });
    }
  }

  if (transitionReason === "payment_lapse" && ["deleted", "forgotten"].includes(toState)) {
    throw admissionError({
      code: "managed_worker_lifecycle_lapse_delete_blocked",
      message:
        "Payment lapse cannot silently delete or forget user-owned worker context.",
      details: { from_state: fromState, to_state: toState },
    });
  }

  if (toState === "zero_to_idle") {
    if (persistenceProfile !== "zero_to_idle" && persistenceProfile !== "persistent") {
      throw admissionError({
        code: "managed_worker_lifecycle_zero_to_idle_profile_invalid",
        message:
          "Zero-to-idle transitions require zero_to_idle or persistent persistence profile.",
        details: { persistence_profile: persistenceProfile },
      });
    }
    requireStateRoot(latestStateRoot, toState);
  }

  if (toState === "archived") {
    requireArchiveMaterial({ archiveRefs, artifactRefs, latestStateRoot, archivePolicy, toState });
    requireControl(requiredControls, "agentgres_archive_ref", toState);
  }

  if (toState === "restoring") {
    requireArchiveRefs(archiveRefs, toState);
    requireScope(authorityScopeRefs, "scope:worker.restore", toState);
    requireWalletApproval(walletApprovalRef, toState);
    if (!restoreImportRef) {
      throw admissionError({
        code: "managed_worker_lifecycle_restore_import_ref_required",
        message: "Restore transitions require an Agentgres-backed restore import ref.",
        details: { to_state: toState },
      });
    }
    if (restorePolicy?.restore_receipt_required !== true) {
      throw admissionError({
        code: "managed_worker_lifecycle_restore_receipt_policy_required",
        message: "Restore policy must require restore receipts.",
        details: { restore_policy: restorePolicy ?? null },
      });
    }
  }

  if (toState === "migrated") {
    requireArchiveRefs(archiveRefs, toState);
    requireScope(authorityScopeRefs, "scope:worker.migrate", toState);
    if (!migrationTargetRef) {
      throw admissionError({
        code: "managed_worker_lifecycle_migration_target_required",
        message: "Migration transitions require a migration target ref.",
        details: { to_state: toState },
      });
    }
  }

  if (toState === "exported") {
    requireScope(authorityScopeRefs, "scope:worker.export", toState);
    requireWalletApproval(walletApprovalRef, toState);
    if (!exportPolicy?.export_requires) {
      throw admissionError({
        code: "managed_worker_lifecycle_export_policy_required",
        message: "Export transitions require an explicit export policy.",
        details: { export_policy: exportPolicy ?? null },
      });
    }
  }

  if (toState === "deleted") {
    requireScope(authorityScopeRefs, "scope:worker.delete", toState);
    requireWalletApproval(walletApprovalRef, toState);
    if (!deletionPolicy) {
      throw admissionError({
        code: "managed_worker_lifecycle_deletion_policy_required",
        message: "Delete transitions require explicit deletion policy.",
        details: { to_state: toState },
      });
    }
  }

  if (toState === "forgotten") {
    requireScope(authorityScopeRefs, "scope:worker.forget", toState);
    requireWalletApproval(walletApprovalRef, toState);
    if (deletionPolicy?.forget_semantic_memory !== true) {
      throw admissionError({
        code: "managed_worker_lifecycle_forget_policy_required",
        message:
          "Forget transitions require deletion_policy.forget_semantic_memory=true.",
        details: { deletion_policy: deletionPolicy ?? null },
      });
    }
  }
}

function requireArchiveMaterial({
  archiveRefs,
  artifactRefs,
  latestStateRoot,
  archivePolicy,
  toState,
}) {
  requireArchiveRefs(archiveRefs, toState);
  if (artifactRefs.length === 0) {
    throw admissionError({
      code: "managed_worker_lifecycle_artifact_ref_required",
      message: "Archive transitions require Agentgres artifact refs.",
      details: { to_state: toState },
    });
  }
  requireStateRoot(latestStateRoot, toState);
  if (!archivePolicy?.storage_policy_ref) {
    throw admissionError({
      code: "managed_worker_lifecycle_archive_policy_required",
      message: "Archive transitions require archive_policy.storage_policy_ref.",
      details: { archive_policy: archivePolicy ?? null },
    });
  }
}

function requireAgentgresAndReceipt(agentgresOperationRefs, receiptRefs, toState) {
  if (agentgresOperationRefs.length === 0) {
    throw admissionError({
      code: "managed_worker_lifecycle_agentgres_operation_required",
      message:
        "Managed worker lifecycle transitions require Agentgres operation refs.",
      details: { to_state: toState },
    });
  }
  if (receiptRefs.length === 0) {
    throw admissionError({
      code: "managed_worker_lifecycle_receipt_required",
      message: "Managed worker lifecycle transitions require receipts.",
      details: { to_state: toState },
    });
  }
}

function requireArchiveRefs(archiveRefs, toState) {
  if (archiveRefs.length > 0) return;
  throw admissionError({
    code: "managed_worker_lifecycle_archive_ref_required",
    message: "Managed worker lifecycle transition requires archive refs.",
    details: { to_state: toState },
  });
}

function requireStateRoot(latestStateRoot, toState) {
  if (latestStateRoot) return;
  throw admissionError({
    code: "managed_worker_lifecycle_state_root_required",
    message: "Managed worker lifecycle transition requires a latest state root.",
    details: { to_state: toState },
  });
}

function requireWalletApproval(walletApprovalRef, toState) {
  if (walletApprovalRef) return;
  throw admissionError({
    code: "managed_worker_lifecycle_wallet_approval_required",
    message: "Managed worker lifecycle transition requires wallet approval.",
    details: { to_state: toState },
  });
}

function requireControl(requiredControls, control, toState) {
  if (requiredControls.includes(control)) return;
  throw admissionError({
    code: "managed_worker_lifecycle_required_control_missing",
    message: "Managed worker lifecycle transition is missing a required control.",
    details: { to_state: toState, required_control: control },
  });
}

function requireScope(authorityScopeRefs, scope, toState) {
  if (authorityScopeRefs.includes(scope)) return;
  throw admissionError({
    code: "managed_worker_lifecycle_required_scope_missing",
    message:
      "Managed worker lifecycle transition is missing a required authority scope.",
    details: { to_state: toState, required_scope: scope },
  });
}

function requirePrefix(value, prefix, field) {
  if (value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `managed_worker_lifecycle_${field}_invalid`,
    message: `Managed worker lifecycle ${field} must start with ${prefix}.`,
    details: { [field]: value },
  });
}

function uniqueScopeRefs(value) {
  return uniqueStrings(normalizeArray(value)).map((scope) => {
    if (!scope.startsWith("scope:")) {
      throw runtimeError({
        status: 400,
        code: "managed_worker_lifecycle_scope_invalid",
        message: "Managed worker lifecycle authority scopes must use scope:* refs.",
        details: { scope },
      });
    }
    return scope;
  });
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value).trim()).filter(Boolean))];
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = RETIRED_ALIASES.filter((field) => Object.hasOwn(body, field));
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "managed_worker_lifecycle_request_aliases_retired",
    message:
      "Managed worker lifecycle admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `managed_worker_lifecycle_${field}_invalid`,
      message: `Managed worker lifecycle admission requires a valid ${field}.`,
      details: {
        [field]: normalized ?? null,
        allowed_values: [...allowedValues],
      },
    });
  }
  return normalized;
}

function requiredString(value, field) {
  const normalized = optionalString(value);
  if (!normalized) {
    throw runtimeError({
      status: 400,
      code: `managed_worker_lifecycle_${field}_required`,
      message: `Managed worker lifecycle admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function admissionError({ code, message, details }) {
  return runtimeError({
    status: 403,
    code,
    message,
    details,
  });
}
