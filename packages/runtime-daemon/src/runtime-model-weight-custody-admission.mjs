import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const MODEL_WEIGHT_CUSTODY_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.model_weight_custody_admission.v1";

const WEIGHT_CLASSES = new Set([
  "public_open_weight",
  "user_local_private_weight",
  "remote_api_private_weight",
  "provider_trust_remote_mount",
  "tee_or_customer_cloud_mount",
  "forbidden_plaintext_mount",
]);

const MOUNT_TARGETS = new Set([
  "local_device",
  "user_owned_node",
  "rented_gpu",
  "customer_cloud",
  "provider_api",
  "tee_session",
  "none",
]);

const EXECUTION_PRIVACY_POSTURES = new Set([
  "private_native",
  "ctee_split",
  "encrypted_storage_only",
  "confidential_compute",
  "remote_api_provider_trust",
  "unsafe_plaintext_mount",
]);

export function admitModelWeightCustodyRoute(request = {}, deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const routeRef = requiredString(request.route_ref, "route_ref");
  const modelRef = requiredString(request.model_ref, "model_ref");
  const providerRef = optionalString(request.provider_ref) ?? "provider:unspecified";
  const weightClass = enumValue(
    request.weight_class,
    "weight_class",
    WEIGHT_CLASSES,
  );
  const mountTarget = enumValue(
    request.mount_target,
    "mount_target",
    MOUNT_TARGETS,
  );
  const executionPrivacyPosture = enumValue(
    request.execution_privacy_posture,
    "execution_privacy_posture",
    EXECUTION_PRIVACY_POSTURES,
  );
  const remoteProviderCanReadWeights =
    booleanValue(request.remote_provider_can_read_weights) ?? false;
  const authorityScopeRefs = uniqueScopeRefs(request.authority_scope_refs);
  const requiredControls = normalizeControls(request.required_controls);
  const disclosureRef = optionalString(request.user_disclosure_ref);
  const providerTrustAcceptanceRef = optionalString(
    request.provider_trust_acceptance_ref,
  );
  const teeAttestationRef = optionalString(request.tee_attestation_ref);
  const customerBoundaryRef = optionalString(request.customer_boundary_ref);

  assertNoRetiredAliases(request);
  assertWeightLaneAdmission({
    weightClass,
    mountTarget,
    executionPrivacyPosture,
    remoteProviderCanReadWeights,
    authorityScopeRefs,
    requiredControls,
    disclosureRef,
    providerTrustAcceptanceRef,
    teeAttestationRef,
    customerBoundaryRef,
  });

  const decision =
    weightClass === "provider_trust_remote_mount"
      ? "admitted_provider_trust"
      : "admitted";

  const admissionId =
    optionalString(request.admission_id) ??
    `model-weight-custody-admission:${safeId(routeRef)}:${safeId(weightClass)}`;
  const receiptRef =
    optionalString(request.receipt_ref) ??
    `receipt://model-weight-custody/${safeId(routeRef)}/${safeId(weightClass)}`;

  return {
    schema_version: MODEL_WEIGHT_CUSTODY_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    route_ref: routeRef,
    model_ref: modelRef,
    provider_ref: providerRef,
    decision,
    weight_class: weightClass,
    mount_target: mountTarget,
    execution_privacy_posture: executionPrivacyPosture,
    remote_provider_can_read_weights: remoteProviderCanReadWeights,
    protects_model_weights_from_provider_root:
      protectsModelWeightsFromProviderRoot(weightClass),
    protects_workspace_state: protectsWorkspaceState(executionPrivacyPosture),
    required_controls: requiredControls,
    authority_scope_refs: authorityScopeRefs,
    user_disclosure_ref: disclosureRef ?? null,
    provider_trust_acceptance_ref: providerTrustAcceptanceRef ?? null,
    tee_attestation_ref: teeAttestationRef ?? null,
    customer_boundary_ref: customerBoundaryRef ?? null,
    agentgres_operation_refs: normalizeArray(request.agentgres_operation_refs),
    artifact_refs: normalizeArray(request.artifact_refs),
    receipt_ref: receiptRef,
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    runtimeTruthSource: "daemon-runtime",
  };
}

function assertWeightLaneAdmission({
  weightClass,
  mountTarget,
  executionPrivacyPosture,
  remoteProviderCanReadWeights,
  authorityScopeRefs,
  requiredControls,
  disclosureRef,
  providerTrustAcceptanceRef,
  teeAttestationRef,
  customerBoundaryRef,
}) {
  if (weightClass === "forbidden_plaintext_mount") {
    throw admissionError({
      code: "model_weight_custody_forbidden_plaintext_mount_blocked",
      message:
        "Model-weight custody admission blocks forbidden plaintext mounts by default.",
      details: { weight_class: weightClass, mount_target: mountTarget },
    });
  }

  if (
    remoteProviderCanReadWeights &&
    weightClass !== "public_open_weight" &&
    weightClass !== "provider_trust_remote_mount"
  ) {
    throw admissionError({
      code: "model_weight_custody_plaintext_private_weight_blocked",
      message:
        "Private model weights cannot be mounted where a remote provider can read them unless the route is explicit provider trust.",
      details: {
        weight_class: weightClass,
        mount_target: mountTarget,
      },
    });
  }

  if (
    executionPrivacyPosture === "private_native" &&
    (remoteProviderCanReadWeights || weightClass === "provider_trust_remote_mount")
  ) {
    throw admissionError({
      code: "model_weight_custody_private_native_claim_invalid",
      message:
        "Provider-readable or provider-trust model-weight routes cannot be presented as private-native.",
      details: {
        weight_class: weightClass,
        execution_privacy_posture: executionPrivacyPosture,
      },
    });
  }

  if (weightClass === "user_local_private_weight") {
    if (!["local_device", "user_owned_node"].includes(mountTarget)) {
      throw admissionError({
        code: "model_weight_custody_user_local_mount_target_invalid",
        message:
          "User-local private weights must stay on a local device or user-owned node.",
        details: { mount_target: mountTarget },
      });
    }
    requireControl(requiredControls, "local_only", weightClass);
  }

  if (weightClass === "remote_api_private_weight") {
    if (mountTarget !== "provider_api") {
      throw admissionError({
        code: "model_weight_custody_remote_api_target_invalid",
        message:
          "Remote API private-weight routes must use a provider_api mount target.",
        details: { mount_target: mountTarget },
      });
    }
    requireControl(requiredControls, "wallet_authorized_api_capability", weightClass);
    requireScope(authorityScopeRefs, "scope:model.invoke_remote", weightClass);
  }

  if (weightClass === "tee_or_customer_cloud_mount") {
    if (!["tee_session", "customer_cloud", "user_owned_node"].includes(mountTarget)) {
      throw admissionError({
        code: "model_weight_custody_confidential_target_invalid",
        message:
          "TEE/customer-cloud model-weight mounts require a TEE session, customer cloud, or user-owned node target.",
        details: { mount_target: mountTarget },
      });
    }
    if (!teeAttestationRef && !customerBoundaryRef) {
      throw admissionError({
        code: "model_weight_custody_attestation_or_customer_boundary_required",
        message:
          "TEE/customer-cloud model-weight mounts require attestation or a customer-boundary reference.",
        details: { required: ["tee_attestation_ref", "customer_boundary_ref"] },
      });
    }
    if (teeAttestationRef) requireControl(requiredControls, "tee_attestation", weightClass);
    if (customerBoundaryRef) {
      requireControl(requiredControls, "customer_account_boundary", weightClass);
    }
  }

  if (weightClass === "provider_trust_remote_mount") {
    if (!remoteProviderCanReadWeights) {
      throw admissionError({
        code: "model_weight_custody_provider_trust_requires_provider_readable",
        message:
          "Provider-trust model-weight mounts must explicitly disclose provider-readable weights.",
        details: { remote_provider_can_read_weights: false },
      });
    }
    if (!providerTrustAcceptanceRef || !disclosureRef) {
      throw admissionError({
        code: "model_weight_custody_provider_trust_acceptance_required",
        message:
          "Provider-trust model-weight mounts require explicit user disclosure and provider-trust acceptance.",
        details: {
          required: [
            "user_disclosure_ref",
            "provider_trust_acceptance_ref",
          ],
        },
      });
    }
    requireControl(requiredControls, "explicit_provider_trust_acceptance", weightClass);
    requireScope(authorityScopeRefs, "scope:provider.trust_override", weightClass);
  }
}

function protectsModelWeightsFromProviderRoot(weightClass) {
  return [
    "public_open_weight",
    "user_local_private_weight",
    "remote_api_private_weight",
    "tee_or_customer_cloud_mount",
  ].includes(weightClass);
}

function protectsWorkspaceState(posture) {
  return ["private_native", "ctee_split", "confidential_compute"].includes(posture);
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = ["modelWeightCustodyProfile", "remoteProviderCanReadWeights"].filter(
    (field) => Object.hasOwn(body, field),
  );
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "model_weight_custody_request_aliases_retired",
    message:
      "Model-weight custody admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function normalizeControls(value) {
  return uniqueStrings(normalizeArray(value));
}

function uniqueScopeRefs(value) {
  return uniqueStrings(normalizeArray(value)).map((scope) => {
    if (!scope.startsWith("scope:")) {
      throw runtimeError({
        status: 400,
        code: "model_weight_custody_scope_invalid",
        message: "Model-weight custody authority scopes must use scope:* refs.",
        details: { scope },
      });
    }
    return scope;
  });
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value).trim()).filter(Boolean))];
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `model_weight_custody_${field}_invalid`,
      message: `Model-weight custody admission requires a valid ${field}.`,
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
      code: `model_weight_custody_${field}_required`,
      message: `Model-weight custody admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function requireControl(requiredControls, control, weightClass) {
  if (requiredControls.includes(control)) return;
  throw admissionError({
    code: "model_weight_custody_required_control_missing",
    message: "Model-weight custody admission is missing a required control.",
    details: { weight_class: weightClass, required_control: control },
  });
}

function requireScope(authorityScopeRefs, scope, weightClass) {
  if (authorityScopeRefs.includes(scope)) return;
  throw admissionError({
    code: "model_weight_custody_required_scope_missing",
    message: "Model-weight custody admission is missing a required authority scope.",
    details: { weight_class: weightClass, required_scope: scope },
  });
}

function admissionError({ code, message, details }) {
  return runtimeError({
    status: 403,
    code,
    message,
    details,
  });
}
