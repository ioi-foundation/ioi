import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const HARNESS_SESSION_BINDING_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.harness_session_binding_admission.v1";

const BINDING_SCHEMA_VERSION = "ioi.hypervisor.harness_session_binding.v1";

const SELECTION_KINDS = new Set(["harness_profile", "agent_harness_adapter"]);
const TRUTH_BOUNDARIES = new Set(["daemon-owned", "proposal_source_only"]);
const MODEL_ROUTE_POLICIES = new Set([
  "hypervisor_model_mount",
  "adapter_builtin",
  "provider_trust",
  "forbidden",
]);
const MODEL_ROUTE_STATES = new Set([
  "daemon_verified",
  "fixture_available",
  "missing",
  "unavailable",
]);
const WORKSPACE_MOUNT_POLICIES = new Set([
  "public_trunk",
  "redacted_projection",
  "plain_workspace",
  "ctee_private_workspace",
]);

const RETIRED_ALIASES = [
  "sessionBindingRef",
  "sessionRouteRef",
  "harnessSelectionRef",
  "harnessLaunchRouteRef",
  "modelConfigurationRef",
  "modelRouteRef",
  "workspaceMountPolicy",
  "privacyPostureRef",
  "authorityScopeRefs",
  "receiptPolicyRef",
  "receiptPreviewRef",
  "expectedReceiptRefs",
  "agentgresOperationRefs",
  "receiptRefs",
  "stateRoot",
];

export function admitHarnessSessionBinding(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const schemaVersion = requiredString(request.schema_version, "schema_version");
  const sessionBindingRef = prefixedString(
    request.session_binding_ref,
    "session_binding_ref",
    "harness-session-binding:",
  );
  const sessionRouteRef = prefixedString(
    request.session_route_ref,
    "session_route_ref",
    "session-route:",
  );
  const harnessSelectionRef = requiredString(
    request.harness_selection_ref,
    "harness_selection_ref",
  );
  const harnessSelectionKind = enumValue(
    request.harness_selection_kind,
    "harness_selection_kind",
    SELECTION_KINDS,
  );
  const harnessTruthBoundary = enumValue(
    request.harness_truth_boundary,
    "harness_truth_boundary",
    TRUTH_BOUNDARIES,
  );
  const harnessLaunchRouteRef = prefixedString(
    request.harness_launch_route_ref,
    "harness_launch_route_ref",
    "harness-route:",
  );
  const agentHarnessAdapterId =
    optionalString(request.agent_harness_adapter_id) ?? null;
  const harnessProfileRef = optionalString(request.harness_profile_ref) ?? null;
  const modelConfigurationRef = prefixedString(
    request.model_configuration_ref,
    "model_configuration_ref",
    "model-config:",
  );
  const modelRouteRef = prefixedString(
    request.model_route_ref,
    "model_route_ref",
    "model-route:",
  );
  const modelRoutePolicy = enumValue(
    request.model_route_policy,
    "model_route_policy",
    MODEL_ROUTE_POLICIES,
  );
  const modelRouteAvailabilityState = enumValue(
    request.model_route_availability_state,
    "model_route_availability_state",
    MODEL_ROUTE_STATES,
  );
  const modelRouteEndpointRefs = prefixedRefs(
    request.model_route_endpoint_refs,
    "model_route_endpoint_refs",
    "model-endpoint:",
    { allowEmpty: true },
  );
  const modelRouteLoadedInstanceRefs = prefixedRefs(
    request.model_route_loaded_instance_refs,
    "model_route_loaded_instance_refs",
    "model-instance:",
    { allowEmpty: true },
  );
  const workspaceMountPolicy = enumValue(
    request.workspace_mount_policy,
    "workspace_mount_policy",
    WORKSPACE_MOUNT_POLICIES,
  );
  const privacyPostureRef = prefixedString(
    request.privacy_posture_ref,
    "privacy_posture_ref",
    "privacy:",
  );
  const authorityScopeRefs = prefixedRefs(
    request.authority_scope_refs,
    "authority_scope_refs",
    "scope:",
  );
  const receiptPolicyRef = prefixedString(
    request.receipt_policy_ref,
    "receipt_policy_ref",
    "receipt-policy:",
  );
  const receiptPreviewRef = prefixedString(
    request.receipt_preview_ref,
    "receipt_preview_ref",
    "receipt-preview:",
  );
  const expectedReceiptRefs = prefixedRefs(
    request.expected_receipt_refs,
    "expected_receipt_refs",
    "receipt",
  );
  const requiresDaemonGate =
    booleanValue(request.requires_daemon_gate) ?? false;
  const runtimeTruthSource = optionalString(request.runtimeTruthSource) ?? null;
  const agentgresOperationRefs = prefixedRefs(
    request.agentgres_operation_refs,
    "agentgres_operation_refs",
    "agentgres://operation/",
    { allowEmpty: true },
  );
  const receiptRefs = prefixedRefs(
    request.receipt_refs,
    "receipt_refs",
    "receipt://",
    { allowEmpty: true },
  );
  const stateRoot = optionalString(request.state_root) ?? null;
  const harnessRuntimeTruthClaimed =
    booleanValue(request.harness_runtime_truth_claimed) ?? false;

  assertHarnessSessionBinding({
    schemaVersion,
    sessionBindingRef,
    sessionRouteRef,
    harnessSelectionRef,
    harnessSelectionKind,
    harnessTruthBoundary,
    harnessLaunchRouteRef,
    agentHarnessAdapterId,
    harnessProfileRef,
    modelConfigurationRef,
    modelRouteRef,
    modelRoutePolicy,
    modelRouteAvailabilityState,
    modelRouteEndpointRefs,
    modelRouteLoadedInstanceRefs,
    workspaceMountPolicy,
    privacyPostureRef,
    authorityScopeRefs,
    receiptPolicyRef,
    receiptPreviewRef,
    expectedReceiptRefs,
    requiresDaemonGate,
    runtimeTruthSource,
    harnessRuntimeTruthClaimed,
  });

  const admissionId =
    optionalString(request.admission_id) ??
    `harness-session-binding-admission:${safeId(sessionBindingRef)}`;
  const admissionReceiptRef =
    optionalString(request.admission_receipt_ref) ??
    `receipt://harness-session-binding/${safeId(sessionBindingRef)}/admitted`;

  return {
    schema_version: HARNESS_SESSION_BINDING_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    decision: "admitted",
    admission_state: "admitted_for_harness_launch",
    session_binding_ref: sessionBindingRef,
    session_route_ref: sessionRouteRef,
    harness_selection_ref: harnessSelectionRef,
    harness_selection_kind: harnessSelectionKind,
    harness_truth_boundary: harnessTruthBoundary,
    harness_launch_route_ref: harnessLaunchRouteRef,
    agent_harness_adapter_id: agentHarnessAdapterId,
    harness_profile_ref: harnessProfileRef,
    model_configuration_ref: modelConfigurationRef,
    model_route_ref: modelRouteRef,
    model_route_policy: modelRoutePolicy,
    model_route_availability_state: modelRouteAvailabilityState,
    model_route_endpoint_refs: modelRouteEndpointRefs,
    model_route_loaded_instance_refs: modelRouteLoadedInstanceRefs,
    workspace_mount_policy: workspaceMountPolicy,
    privacy_posture_ref: privacyPostureRef,
    authority_scope_refs: authorityScopeRefs,
    receipt_policy_ref: receiptPolicyRef,
    receipt_preview_ref: receiptPreviewRef,
    expected_receipt_refs: expectedReceiptRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    receipt_refs: uniqueStrings([...receiptRefs, admissionReceiptRef]),
    state_root: stateRoot,
    harness_runtime_truth_claimed: false,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    binding_invariant:
      "Harness session launch is admitted only after harness, model route, workspace mount policy, privacy posture, authority scopes, receipts, and daemon runtime truth boundary are bound.",
  };
}

function assertHarnessSessionBinding({
  schemaVersion,
  sessionBindingRef,
  sessionRouteRef,
  harnessSelectionRef,
  harnessSelectionKind,
  harnessTruthBoundary,
  harnessLaunchRouteRef,
  agentHarnessAdapterId,
  harnessProfileRef,
  modelConfigurationRef,
  modelRouteRef,
  modelRoutePolicy,
  modelRouteAvailabilityState,
  modelRouteEndpointRefs,
  modelRouteLoadedInstanceRefs,
  workspaceMountPolicy,
  privacyPostureRef,
  authorityScopeRefs,
  receiptPolicyRef,
  receiptPreviewRef,
  expectedReceiptRefs,
  requiresDaemonGate,
  runtimeTruthSource,
  harnessRuntimeTruthClaimed,
}) {
  if (schemaVersion !== BINDING_SCHEMA_VERSION) {
    throw admissionError({
      code: "harness_session_binding_schema_invalid",
      message: "Harness session binding admission requires the canonical binding schema.",
      details: { schema_version: schemaVersion },
    });
  }
  if (!requiresDaemonGate || runtimeTruthSource !== "daemon-runtime") {
    throw admissionError({
      code: "harness_session_binding_daemon_gate_required",
      message: "Harness session bindings must require daemon gates and daemon runtime truth.",
      details: { requires_daemon_gate: requiresDaemonGate, runtimeTruthSource },
    });
  }
  if (harnessRuntimeTruthClaimed) {
    throw admissionError({
      code: "harness_session_binding_runtime_truth_claim_blocked",
      message: "Harness adapters may propose actions but cannot claim runtime truth.",
      details: { harness_runtime_truth_claimed: harnessRuntimeTruthClaimed },
    });
  }
  requireScope(authorityScopeRefs, "scope:workspace.read");
  if (!expectedReceiptRefs.includes(receiptPreviewRef)) {
    throw admissionError({
      code: "harness_session_binding_receipt_preview_unbound",
      message: "Harness session binding must include the launch receipt preview in expected receipt refs.",
      details: { receipt_preview_ref: receiptPreviewRef },
    });
  }
  if (!expectedReceiptRefs.includes(receiptPolicyRef)) {
    throw admissionError({
      code: "harness_session_binding_receipt_policy_unbound",
      message: "Harness session binding must include its receipt policy in expected receipt refs.",
      details: { receipt_policy_ref: receiptPolicyRef },
    });
  }
  if (!sessionBindingRef.includes(safeBindingId(sessionRouteRef))) {
    throw admissionError({
      code: "harness_session_binding_route_unbound",
      message: "Harness session binding ref must bind the session route.",
      details: { session_binding_ref: sessionBindingRef, session_route_ref: sessionRouteRef },
    });
  }

  if (harnessSelectionKind === "harness_profile") {
    requirePrefix(harnessSelectionRef, "harness-profile:", "harness_selection_ref");
    if (!harnessProfileRef) {
      throw admissionError({
        code: "harness_session_binding_profile_ref_required",
        message: "Harness profile bindings require harness_profile_ref.",
        details: { harness_selection_kind: harnessSelectionKind },
      });
    }
    if (agentHarnessAdapterId) {
      throw admissionError({
        code: "harness_session_binding_adapter_ref_for_profile_blocked",
        message: "Harness profile bindings must not carry agent harness adapter ids.",
        details: { agent_harness_adapter_id: agentHarnessAdapterId },
      });
    }
    if (harnessTruthBoundary !== "daemon-owned") {
      throw admissionError({
        code: "harness_session_binding_profile_truth_boundary_invalid",
        message: "Harness profile bindings must remain daemon-owned.",
        details: { harness_truth_boundary: harnessTruthBoundary },
      });
    }
  } else {
    requirePrefix(
      harnessSelectionRef,
      "agent-harness-adapter:",
      "harness_selection_ref",
    );
    if (!agentHarnessAdapterId) {
      throw admissionError({
        code: "harness_session_binding_adapter_id_required",
        message: "Agent harness adapter bindings require agent_harness_adapter_id.",
        details: { harness_selection_kind: harnessSelectionKind },
      });
    }
    if (harnessProfileRef) {
      throw admissionError({
        code: "harness_session_binding_profile_ref_for_adapter_blocked",
        message: "Agent harness adapter bindings must not carry harness profile refs.",
        details: { harness_profile_ref: harnessProfileRef },
      });
    }
    if (harnessTruthBoundary !== "proposal_source_only") {
      throw admissionError({
        code: "harness_session_binding_adapter_truth_boundary_invalid",
        message: "Agent harness adapters are proposal sources only.",
        details: { harness_truth_boundary: harnessTruthBoundary },
      });
    }
    if (
      workspaceMountPolicy === "ctee_private_workspace" ||
      privacyPostureRef === "privacy:ctee-private-workspace"
    ) {
      throw admissionError({
        code: "harness_session_binding_external_ctee_custody_blocked",
        message:
          "External harness adapters cannot mount or claim cTEE private workspace custody.",
        details: { harness_selection_ref: harnessSelectionRef },
      });
    }
  }

  if (modelRoutePolicy === "hypervisor_model_mount") {
    if (
      !["daemon_verified", "fixture_available"].includes(
        modelRouteAvailabilityState,
      )
    ) {
      throw admissionError({
        code: "harness_session_binding_model_route_unavailable",
        message:
          "Hypervisor model mount bindings require a verified or fixture-available local model route.",
        details: { model_route_availability_state: modelRouteAvailabilityState },
      });
    }
    requireNonEmpty(modelRouteEndpointRefs, "model_route_endpoint_refs");
    requireNonEmpty(modelRouteLoadedInstanceRefs, "model_route_loaded_instance_refs");
    if (!modelConfigurationRef.startsWith("model-config:local/")) {
      throw admissionError({
        code: "harness_session_binding_local_model_config_required",
        message:
          "Hypervisor model mount bindings require a local model configuration.",
        details: { model_configuration_ref: modelConfigurationRef },
      });
    }
  }

  if (modelRoutePolicy === "provider_trust") {
    throw admissionError({
      code: "harness_session_binding_provider_trust_requires_future_lease",
      message:
        "Provider-trust harness routes require an explicit provider-trust lease and are not admitted by the local-first session binding gate.",
      details: { model_route_ref: modelRouteRef },
    });
  }

  if (
    modelRoutePolicy === "forbidden" &&
    modelRouteRef !== "model-route:none"
  ) {
    throw admissionError({
      code: "harness_session_binding_forbidden_model_route_invalid",
      message:
        "Harnesses with forbidden model routes must bind model-route:none.",
      details: { model_route_ref: modelRouteRef },
    });
  }
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `harness_session_binding_${field}_invalid`,
      message: `Harness session binding admission requires a valid ${field}.`,
      details: { [field]: normalized ?? null, allowed_values: [...allowedValues] },
    });
  }
  return normalized;
}

function safeBindingId(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96) || "binding";
}

function prefixedRefs(value, field, prefix, { allowEmpty = false } = {}) {
  const refs = uniqueStrings(normalizeArray(value));
  if (!allowEmpty) requireNonEmpty(refs, field);
  for (const ref of refs) requirePrefix(ref, prefix, field);
  return refs;
}

function prefixedString(value, field, prefix) {
  const normalized = requiredString(value, field);
  requirePrefix(normalized, prefix, field);
  return normalized;
}

function requiredString(value, field) {
  const normalized = optionalString(value);
  if (!normalized) {
    throw runtimeError({
      status: 400,
      code: `harness_session_binding_${field}_required`,
      message: `Harness session binding admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function requireNonEmpty(value, field) {
  if (value.length > 0) return;
  throw runtimeError({
    status: 400,
    code: `harness_session_binding_${field}_required`,
    message: `Harness session binding admission requires ${field}.`,
    details: { field },
  });
}

function requirePrefix(value, prefix, field) {
  if (typeof value === "string" && value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `harness_session_binding_${field}_prefix_invalid`,
    message: `Harness session binding admission requires ${field} to start with ${prefix}.`,
    details: { field, value, expected_prefix: prefix },
  });
}

function requireScope(scopeRefs, scope) {
  if (scopeRefs.includes(scope)) return;
  throw admissionError({
    code: "harness_session_binding_required_scope_missing",
    message: `Harness session binding admission requires ${scope}.`,
    details: { required_scope: scope },
  });
}

function assertNoRetiredAliases(request) {
  const present = RETIRED_ALIASES.filter((alias) =>
    Object.prototype.hasOwnProperty.call(objectRecord(request), alias),
  );
  if (present.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "harness_session_binding_request_aliases_retired",
    message:
      "Harness session binding admission uses canonical snake_case request fields.",
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
