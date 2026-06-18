import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.code_editor_adapter_launch_plan_admission.v1";

const LAUNCH_MODES = new Set(["embedded", "external", "remote_url"]);

const CONNECTION_KINDS = new Set([
  "embedded_host",
  "desktop_editor",
  "browser_editor_url",
]);

const EXECUTOR_LANES = new Set([
  "embedded_workbench_host",
  "desktop_editor",
  "browser_code_editor",
]);

const CONTROL_ACTIONS = new Set([
  "open_embedded_workbench",
  "open_desktop_editor",
  "open_browser_editor",
]);

const CUSTODY_POSTURES = new Set([
  "local_projection",
  "redacted_projection",
]);

const RETIRED_ALIASES = [
  "launchPlanRef",
  "adapterRef",
  "targetRef",
  "launchMode",
  "connectionKind",
  "connectionContractRef",
  "executorLane",
  "controlAction",
  "controlChannelRef",
  "requiredAccessLeaseRefs",
  "requiredAuthorityScopeRefs",
  "requiredReceiptRefs",
  "secretReleasePolicy",
  "restoreArchivePolicy",
  "providerPostureRequired",
  "agentgresOperationRefs",
];

export function admitCodeEditorAdapterLaunchPlan(request = {}, deps = {}) {
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
  const executorLane = enumValue(
    request.executor_lane,
    "executor_lane",
    EXECUTOR_LANES,
  );
  const controlAction = enumValue(
    request.control_action,
    "control_action",
    CONTROL_ACTIONS,
  );
  const controlChannelRef = requiredString(
    request.control_channel_ref,
    "control_channel_ref",
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
  const walletApprovalRef = optionalString(request.wallet_approval_ref) ?? null;
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

  assertCodeEditorAdapterLaunchPlan({
    launchPlanRef,
    adapterRef,
    targetRef,
    connectionKind,
    connectionContractRef,
    executorLane,
    controlAction,
    controlChannelRef,
    requiredAccessLeaseRefs,
    requiredAuthorityScopeRefs,
    requiredReceiptRefs,
    custodyPosture,
    secretReleasePolicy,
    adapterRuntimeTruthClaimed,
  });

  const admissionId =
    optionalString(request.admission_id) ??
    `code-editor-adapter-launch:${safeId(launchPlanRef)}:${safeId(connectionKind)}`;

  return {
    schema_version: CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    launch_plan_ref: launchPlanRef,
    adapter_ref: adapterRef,
    target_ref: targetRef,
    launch_mode: launchMode,
    connection_kind: connectionKind,
    connection_contract_ref: connectionContractRef,
    executor_lane: executorLane,
    control_action: controlAction,
    control_channel_ref: controlChannelRef,
    required_access_lease_refs: requiredAccessLeaseRefs,
    required_authority_scope_refs: requiredAuthorityScopeRefs,
    required_receipt_refs: requiredReceiptRefs,
    custody_posture: custodyPosture,
    secret_release_policy: secretReleasePolicy,
    wallet_approval_ref: walletApprovalRef,
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

function assertCodeEditorAdapterLaunchPlan({
  launchPlanRef,
  adapterRef,
  targetRef,
  connectionKind,
  connectionContractRef,
  executorLane,
  controlAction,
  controlChannelRef,
  requiredAccessLeaseRefs,
  requiredAuthorityScopeRefs,
  requiredReceiptRefs,
  custodyPosture,
  secretReleasePolicy,
  adapterRuntimeTruthClaimed,
}) {
  requirePrefix(launchPlanRef, "code-editor-adapter:", "launch_plan_ref");
  requirePrefix(adapterRef, "code-editor-adapter:", "adapter_ref");
  requirePrefix(targetRef, "adapter-target:", "target_ref");
  requirePrefix(
    connectionContractRef,
    "connection-contract:code-editor-adapter/",
    "connection_contract_ref",
  );
  requirePrefix(
    controlChannelRef,
    "control-channel:code-editor-adapter/",
    "control_channel_ref",
  );
  requireNonEmpty(requiredAccessLeaseRefs, "required_access_lease_refs");
  requireNonEmpty(requiredAuthorityScopeRefs, "required_authority_scope_refs");
  requireNonEmpty(requiredReceiptRefs, "required_receipt_refs");

  assertConnectionControlPair({
    connectionKind,
    executorLane,
    controlAction,
  });

  if (secretReleasePolicy !== "no_durable_secret_release") {
    throw admissionError({
      code: "code_editor_adapter_launch_durable_secret_release_blocked",
      message:
        "code editor adapter launch plans must not release durable secrets to adapter targets.",
      details: { secret_release_policy: secretReleasePolicy },
    });
  }

  if (adapterRuntimeTruthClaimed) {
    throw admissionError({
      code: "code_editor_adapter_runtime_truth_claim_blocked",
      message:
        "code editor adapter targets cannot claim Hypervisor runtime truth.",
      details: { adapter_runtime_truth_claimed: adapterRuntimeTruthClaimed },
    });
  }

}

function assertConnectionControlPair({
  connectionKind,
  executorLane,
  controlAction,
}) {
  const expectedByConnection = {
    embedded_host: {
      executorLane: "embedded_workbench_host",
      controlAction: "open_embedded_workbench",
    },
    desktop_editor: {
      executorLane: "desktop_editor",
      controlAction: "open_desktop_editor",
    },
    browser_editor_url: {
      executorLane: "browser_code_editor",
      controlAction: "open_browser_editor",
    },
  }[connectionKind];

  if (
    expectedByConnection &&
    (executorLane !== expectedByConnection.executorLane ||
      controlAction !== expectedByConnection.controlAction)
  ) {
    throw admissionError({
      code: "code_editor_adapter_control_contract_mismatch",
      message:
        "code editor adapter control metadata must match its connection kind.",
      details: {
        connection_kind: connectionKind,
        executor_lane: executorLane,
        control_action: controlAction,
      },
    });
  }
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
      code: `code_editor_adapter_launch_${field}_invalid`,
      message: `code editor adapter launch admission requires a valid ${field}.`,
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
      code: `code_editor_adapter_launch_${field}_required`,
      message: `code editor adapter launch admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function requireNonEmpty(value, field) {
  if (value.length > 0) return;
  throw runtimeError({
    status: 400,
    code: `code_editor_adapter_launch_${field}_required`,
    message: `code editor adapter launch admission requires ${field}.`,
    details: { field },
  });
}

function requirePrefix(value, prefix, field) {
  if (typeof value === "string" && value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `code_editor_adapter_launch_${field}_prefix_invalid`,
    message: `code editor adapter launch admission requires ${field} to start with ${prefix}.`,
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
    code: "code_editor_adapter_launch_request_aliases_retired",
    message:
      "code editor adapter launch admission uses canonical snake_case request fields.",
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
