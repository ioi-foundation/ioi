import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const WORKBENCH_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.workbench_adapter_launch_plan_admission.v1";

const LAUNCH_MODES = new Set(["embedded", "external", "remote_url", "headless"]);

const CONNECTION_KINDS = new Set([
  "embedded_host",
  "desktop_bridge",
  "browser_workspace_url",
  "terminal_session",
  "provider_workspace",
  "hypervisor_node_session",
]);

const CUSTODY_POSTURES = new Set([
  "local_projection",
  "redacted_projection",
  "provider_session",
  "headless_session",
]);

const RESTORE_ARCHIVE_POLICIES = new Set([
  "not_required",
  "required_for_remote_persistence",
]);

const RETIRED_ALIASES = [
  "launchPlanRef",
  "adapterRef",
  "targetRef",
  "launchMode",
  "connectionKind",
  "connectionContractRef",
  "requiredAccessLeaseRefs",
  "requiredAuthorityScopeRefs",
  "requiredReceiptRefs",
  "secretReleasePolicy",
  "restoreArchivePolicy",
  "providerPostureRequired",
  "agentgresOperationRefs",
];

export function admitWorkbenchAdapterLaunchPlan(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const launchPlanRef = requiredString(request.launch_plan_ref, "launch_plan_ref");
  const adapterRef = requiredString(request.adapter_ref, "adapter_ref");
  const targetRef = requiredString(request.target_ref, "target_ref");
  const launchMode = enumValue(request.launch_mode, "launch_mode", LAUNCH_MODES);
  const connectionKind = enumValue(
    request.connection_kind,
    "connection_kind",
    CONNECTION_KINDS,
  );
  const connectionContractRef = requiredString(
    request.connection_contract_ref,
    "connection_contract_ref",
  );
  const requiredAccessLeaseRefs = prefixedRefs(
    request.required_access_lease_refs,
    "required_access_lease_refs",
    "lease:",
  );
  const requiredAuthorityScopeRefs = prefixedRefs(
    request.required_authority_scope_refs,
    "required_authority_scope_refs",
    "scope:",
  );
  const requiredReceiptRefs = prefixedRefs(
    request.required_receipt_refs,
    "required_receipt_refs",
    "receipt-policy:",
  );
  const custodyPosture = enumValue(
    request.custody_posture,
    "custody_posture",
    CUSTODY_POSTURES,
  );
  const secretReleasePolicy =
    optionalString(request.secret_release_policy) ?? "no_durable_secret_release";
  const restoreArchivePolicy = enumValue(
    request.restore_archive_policy,
    "restore_archive_policy",
    RESTORE_ARCHIVE_POLICIES,
  );
  const providerPostureRequired =
    booleanValue(request.provider_posture_required) ?? false;
  const providerPostureRef = optionalString(request.provider_posture_ref) ?? null;
  const walletApprovalRef = optionalString(request.wallet_approval_ref) ?? null;
  const archiveRef = optionalString(request.archive_ref) ?? null;
  const restoreRef = optionalString(request.restore_ref) ?? null;
  const agentgresOperationRefs = prefixedRefs(
    request.agentgres_operation_refs,
    "agentgres_operation_refs",
    "agentgres://operation/",
    { allowEmpty: true },
  );
  const receiptRefs = prefixedRefs(request.receipt_refs, "receipt_refs", "receipt://", {
    allowEmpty: true,
  });
  const stateRoot = optionalString(request.state_root) ?? null;
  const adapterRuntimeTruthClaimed =
    booleanValue(request.adapter_runtime_truth_claimed) ?? false;

  assertWorkbenchAdapterLaunchPlan({
    launchPlanRef,
    adapterRef,
    targetRef,
    launchMode,
    connectionKind,
    connectionContractRef,
    requiredAccessLeaseRefs,
    requiredAuthorityScopeRefs,
    requiredReceiptRefs,
    custodyPosture,
    secretReleasePolicy,
    restoreArchivePolicy,
    providerPostureRequired,
    providerPostureRef,
    archiveRef,
    restoreRef,
    adapterRuntimeTruthClaimed,
  });

  const admissionId =
    optionalString(request.admission_id) ??
    `workbench-adapter-launch:${safeId(launchPlanRef)}:${safeId(connectionKind)}`;

  return {
    schema_version: WORKBENCH_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    launch_plan_ref: launchPlanRef,
    adapter_ref: adapterRef,
    target_ref: targetRef,
    launch_mode: launchMode,
    connection_kind: connectionKind,
    connection_contract_ref: connectionContractRef,
    required_access_lease_refs: requiredAccessLeaseRefs,
    required_authority_scope_refs: requiredAuthorityScopeRefs,
    required_receipt_refs: requiredReceiptRefs,
    custody_posture: custodyPosture,
    secret_release_policy: secretReleasePolicy,
    restore_archive_policy: restoreArchivePolicy,
    provider_posture_required: providerPostureRequired,
    provider_posture_ref: providerPostureRef,
    wallet_approval_ref: walletApprovalRef,
    archive_ref: archiveRef,
    restore_ref: restoreRef,
    agentgres_operation_refs: agentgresOperationRefs,
    receipt_refs: receiptRefs,
    state_root: stateRoot,
    adapter_runtime_truth_claimed: false,
    decision: "admitted",
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
  };
}

function assertWorkbenchAdapterLaunchPlan({
  launchPlanRef,
  adapterRef,
  targetRef,
  launchMode,
  connectionKind,
  connectionContractRef,
  requiredAccessLeaseRefs,
  requiredAuthorityScopeRefs,
  requiredReceiptRefs,
  custodyPosture,
  secretReleasePolicy,
  restoreArchivePolicy,
  providerPostureRequired,
  providerPostureRef,
  archiveRef,
  restoreRef,
  adapterRuntimeTruthClaimed,
}) {
  requirePrefix(launchPlanRef, "workbench-adapter:", "launch_plan_ref");
  requirePrefix(adapterRef, "workbench-adapter:", "adapter_ref");
  requirePrefix(targetRef, "adapter-target:", "target_ref");
  requirePrefix(
    connectionContractRef,
    "connection-contract:workbench-adapter/",
    "connection_contract_ref",
  );
  requireNonEmpty(requiredAccessLeaseRefs, "required_access_lease_refs");
  requireNonEmpty(requiredAuthorityScopeRefs, "required_authority_scope_refs");
  requireNonEmpty(requiredReceiptRefs, "required_receipt_refs");

  if (secretReleasePolicy !== "no_durable_secret_release") {
    throw admissionError({
      code: "workbench_adapter_launch_durable_secret_release_blocked",
      message:
        "Workbench adapter launch plans must not release durable secrets to adapter targets.",
      details: { secret_release_policy: secretReleasePolicy },
    });
  }

  if (adapterRuntimeTruthClaimed) {
    throw admissionError({
      code: "workbench_adapter_runtime_truth_claim_blocked",
      message:
        "Workbench adapter targets cannot claim Hypervisor runtime truth.",
      details: { adapter_runtime_truth_claimed: adapterRuntimeTruthClaimed },
    });
  }

  if (
    providerBackedConnection(connectionKind, custodyPosture) &&
    !providerPostureRequired
  ) {
    throw admissionError({
      code: "workbench_adapter_provider_posture_required",
      message:
        "Provider-backed adapter sessions require explicit provider posture.",
      details: { connection_kind: connectionKind, custody_posture: custodyPosture },
    });
  }

  if (providerPostureRequired && !providerPostureRef) {
    throw admissionError({
      code: "workbench_adapter_provider_posture_ref_required",
      message:
        "Provider-backed adapter launch plans require provider_posture_ref.",
      details: { provider_posture_required: providerPostureRequired },
    });
  }

  if (restoreArchivePolicy === "required_for_remote_persistence") {
    if (!archiveRef || !restoreRef) {
      throw admissionError({
        code: "workbench_adapter_restore_refs_required",
        message:
          "Persistent remote adapter sessions require archive_ref and restore_ref.",
        details: { archive_ref: archiveRef, restore_ref: restoreRef },
      });
    }
    requirePrefix(archiveRef, "artifact://", "archive_ref");
    requirePrefix(restoreRef, "agentgres://restore/", "restore_ref");
  }

  if (launchMode === "headless" && connectionKind !== "terminal_session") {
    throw admissionError({
      code: "workbench_adapter_headless_connection_invalid",
      message:
        "Headless workbench adapter launch mode must use terminal_session connection kind.",
      details: { launch_mode: launchMode, connection_kind: connectionKind },
    });
  }
}

function providerBackedConnection(connectionKind, custodyPosture) {
  return (
    custodyPosture === "provider_session" ||
    ["browser_workspace_url", "provider_workspace", "hypervisor_node_session"].includes(
      connectionKind,
    )
  );
}

function prefixedRefs(value, field, prefix, { allowEmpty = false } = {}) {
  const refs = uniqueStrings(normalizeArray(value));
  if (!allowEmpty) requireNonEmpty(refs, field);
  for (const ref of refs) requirePrefix(ref, prefix, field);
  return refs;
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `workbench_adapter_launch_${field}_invalid`,
      message: `Workbench adapter launch admission requires a valid ${field}.`,
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
      code: `workbench_adapter_launch_${field}_required`,
      message: `Workbench adapter launch admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function requireNonEmpty(value, field) {
  if (value.length > 0) return;
  throw runtimeError({
    status: 400,
    code: `workbench_adapter_launch_${field}_required`,
    message: `Workbench adapter launch admission requires ${field}.`,
    details: { field },
  });
}

function requirePrefix(value, prefix, field) {
  if (typeof value === "string" && value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `workbench_adapter_launch_${field}_prefix_invalid`,
    message: `Workbench adapter launch admission requires ${field} to start with ${prefix}.`,
    details: { field, value },
  });
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value).trim()).filter(Boolean))];
}

function assertNoRetiredAliases(request) {
  const present = RETIRED_ALIASES.filter((alias) =>
    Object.prototype.hasOwnProperty.call(objectRecord(request), alias),
  );
  if (present.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "workbench_adapter_launch_request_aliases_retired",
    message:
      "Workbench adapter launch admission uses canonical snake_case request fields.",
    details: { retired_aliases: present },
  });
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function admissionError({ code, message, details }) {
  return runtimeError({
    status: 403,
    code,
    message,
    details,
  });
}
