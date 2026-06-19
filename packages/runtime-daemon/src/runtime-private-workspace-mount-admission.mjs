import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const PRIVATE_WORKSPACE_MOUNT_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.private_workspace_mount_admission.v1";

const CUSTODY_CLASSES = new Set([
  "public_trunk",
  "redacted_projection",
  "encrypted_blob_ref",
  "private_head",
  "capability_exit",
  "unsafe_plaintext_mount",
]);

const MOUNT_TARGETS = new Set([
  "local_device",
  "user_owned_node",
  "browser_client",
  "rented_gpu",
  "customer_cloud",
  "tee_session",
]);

const EXECUTION_PRIVACY_POSTURES = new Set([
  "private_native",
  "ctee_split",
  "encrypted_storage_only",
  "confidential_compute",
  "remote_api_provider_trust",
  "unsafe_plaintext_mount",
]);

export function admitPrivateWorkspaceMount(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const workspaceRef = prefixedString(
    request.workspace_ref,
    "workspace_ref",
    "workspace://",
  );
  const mountRef = requiredString(request.mount_ref, "mount_ref");
  const segmentRef = requiredString(request.segment_ref, "segment_ref");
  const providerRef = optionalString(request.provider_ref) ?? "provider:unspecified";
  const custodyClass = enumValue(
    request.custody_class,
    "custody_class",
    CUSTODY_CLASSES,
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
  const providerRootCanReadPlaintext =
    booleanValue(request.provider_root_can_read_plaintext) ?? false;
  const protectedPlaintextRequested =
    booleanValue(request.protected_plaintext_requested) ?? false;
  const requiredControls = uniqueStrings(normalizeArray(request.required_controls));
  const authorityScopeRefs = prefixedRefs(
    request.authority_scope_refs,
    "authority_scope_refs",
    "scope:",
    { allowEmpty: true },
  );
  const walletApprovalRef = optionalString(request.wallet_approval_ref) ?? null;
  const walletLeaseRef = optionalString(request.wallet_lease_ref) ?? null;
  const userDisclosureRef = optionalString(request.user_disclosure_ref) ?? null;
  const providerTrustAcceptanceRef =
    optionalString(request.provider_trust_acceptance_ref) ?? null;
  const teeAttestationRef = optionalString(request.tee_attestation_ref) ?? null;
  const customerBoundaryRef =
    optionalString(request.customer_boundary_ref) ?? null;
  const declassificationReceiptRefs = prefixedRefs(
    request.declassification_receipt_refs,
    "declassification_receipt_refs",
    "receipt://",
    { allowEmpty: true },
  );
  const agentgresOperationRefs = prefixedRefs(
    request.agentgres_operation_refs,
    "agentgres_operation_refs",
    "agentgres://operation/",
  );
  const artifactRefs = prefixedRefs(request.artifact_refs, "artifact_refs", "artifact://", {
    allowEmpty: custodyClass === "capability_exit",
  });
  const stateRootRef = prefixedString(
    request.state_root_ref,
    "state_root_ref",
    "agentgres://state-root/",
  );

  assertMountAdmission({
    custodyClass,
    mountTarget,
    executionPrivacyPosture,
    providerRootCanReadPlaintext,
    protectedPlaintextRequested,
    requiredControls,
    authorityScopeRefs,
    walletApprovalRef,
    walletLeaseRef,
    userDisclosureRef,
    providerTrustAcceptanceRef,
    teeAttestationRef,
    customerBoundaryRef,
    declassificationReceiptRefs,
    artifactRefs,
  });

  const decision = decisionFor({
    custodyClass,
    providerRootCanReadPlaintext,
    protectedPlaintextRequested,
  });
  const admissionId =
    optionalString(request.admission_id) ??
    `private-workspace-mount-admission:${safeId(workspaceRef)}:${safeId(segmentRef)}:${safeId(custodyClass)}`;
  const receiptRef =
    optionalString(request.receipt_ref) ??
    `receipt://private-workspace-mount/${safeId(workspaceRef)}/${safeId(segmentRef)}/${safeId(decision)}`;

  return {
    schema_version: PRIVATE_WORKSPACE_MOUNT_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    decision,
    workspace_ref: workspaceRef,
    mount_ref: mountRef,
    segment_ref: segmentRef,
    provider_ref: providerRef,
    custody_class: custodyClass,
    mount_target: mountTarget,
    execution_privacy_posture: executionPrivacyPosture,
    provider_root_can_read_plaintext: providerRootCanReadPlaintext,
    protected_plaintext_requested: protectedPlaintextRequested,
    protected_plaintext_exposed_to_provider_root:
      protectedPlaintextRequested && providerRootCanReadPlaintext,
    protects_workspace_plaintext_from_provider_root:
      !(protectedPlaintextRequested && providerRootCanReadPlaintext),
    required_controls: requiredControls,
    authority_scope_refs: authorityScopeRefs,
    wallet_approval_ref: walletApprovalRef,
    wallet_lease_ref: walletLeaseRef,
    user_disclosure_ref: userDisclosureRef,
    provider_trust_acceptance_ref: providerTrustAcceptanceRef,
    tee_attestation_ref: teeAttestationRef,
    customer_boundary_ref: customerBoundaryRef,
    declassification_receipt_refs: declassificationReceiptRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    artifact_refs: artifactRefs,
    state_root_ref: stateRootRef,
    receipt_ref: receiptRef,
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    runtimeTruthSource: "daemon-runtime",
  };
}

function assertMountAdmission({
  custodyClass,
  mountTarget,
  executionPrivacyPosture,
  providerRootCanReadPlaintext,
  protectedPlaintextRequested,
  requiredControls,
  authorityScopeRefs,
  walletApprovalRef,
  walletLeaseRef,
  userDisclosureRef,
  providerTrustAcceptanceRef,
  teeAttestationRef,
  customerBoundaryRef,
  declassificationReceiptRefs,
  artifactRefs,
}) {
  if (custodyClass === "public_trunk") {
    if (protectedPlaintextRequested) {
      throw admissionError({
        code: "private_workspace_mount_public_trunk_plaintext_claim_invalid",
        message:
          "Public-trunk mounts cannot request protected private workspace plaintext.",
        details: { custody_class: custodyClass },
      });
    }
    return;
  }

  if (custodyClass === "redacted_projection") {
    requireControl(requiredControls, "redaction_verified", custodyClass);
    if (protectedPlaintextRequested) {
      throw admissionError({
        code: "private_workspace_mount_redacted_plaintext_claim_invalid",
        message:
          "Redacted projection mounts cannot request protected private workspace plaintext.",
        details: { custody_class: custodyClass },
      });
    }
    return;
  }

  if (custodyClass === "encrypted_blob_ref") {
    requireControl(requiredControls, "encrypted_blob_refs_only", custodyClass);
    if (protectedPlaintextRequested || providerRootCanReadPlaintext) {
      throw admissionError({
        code: "private_workspace_mount_encrypted_blob_plaintext_blocked",
        message:
          "Encrypted private workspace blob refs cannot materialize provider-readable plaintext.",
        details: {
          protected_plaintext_requested: protectedPlaintextRequested,
          provider_root_can_read_plaintext: providerRootCanReadPlaintext,
        },
      });
    }
    return;
  }

  if (custodyClass === "capability_exit") {
    requireControl(requiredControls, "capability_exit_only", custodyClass);
    requireScope(authorityScopeRefs, "scope:capability.use", custodyClass);
    if (protectedPlaintextRequested || providerRootCanReadPlaintext) {
      throw admissionError({
        code: "private_workspace_mount_capability_exit_plaintext_blocked",
        message:
          "Capability-exit mounts expose operation handles, not private workspace plaintext.",
        details: { custody_class: custodyClass },
      });
    }
    return;
  }

  if (
    custodyClass === "private_head" &&
    ["tee_session", "customer_cloud"].includes(mountTarget)
  ) {
    if (teeAttestationRef) requireControl(requiredControls, "tee_attestation", custodyClass);
    if (customerBoundaryRef) {
      requireControl(requiredControls, "customer_account_boundary", custodyClass);
    }
    if (!teeAttestationRef && !customerBoundaryRef) {
      throw admissionError({
        code: "private_workspace_mount_attestation_or_customer_boundary_required",
        message:
          "Private-head mounts into TEE/customer-cloud targets require attestation or a customer-boundary ref.",
        details: { required: ["tee_attestation_ref", "customer_boundary_ref"] },
      });
    }
    if (providerRootCanReadPlaintext) {
      throw admissionError({
        code: "private_workspace_mount_confidential_provider_root_plaintext_invalid",
        message:
          "Confidential private-head mounts cannot claim provider-root plaintext visibility.",
        details: { mount_target: mountTarget },
      });
    }
    return;
  }

  if (
    custodyClass === "private_head" &&
    ["local_device", "user_owned_node", "browser_client"].includes(mountTarget)
  ) {
    requireControl(requiredControls, "wallet_decryption_lease", custodyClass);
    requireScope(authorityScopeRefs, "scope:artifact.decrypt", custodyClass);
    if (providerRootCanReadPlaintext) {
      throw admissionError({
        code: "private_workspace_mount_local_provider_root_plaintext_invalid",
        message:
          "Local/user-custody private-head mounts cannot expose plaintext to provider root.",
        details: { mount_target: mountTarget },
      });
    }
    return;
  }

  if (
    custodyClass === "private_head" &&
    mountTarget === "rented_gpu" &&
    !providerRootCanReadPlaintext &&
    !protectedPlaintextRequested
  ) {
    requireControl(requiredControls, "ctee_private_head_handle", custodyClass);
    requireScope(authorityScopeRefs, "scope:ctee.private-head.evaluate", custodyClass);
    if (executionPrivacyPosture !== "ctee_split") {
      throw admissionError({
        code: "private_workspace_mount_ctee_posture_required",
        message:
          "Rented-node private-head handles require cTEE split posture unless plaintext is explicitly declassified.",
        details: { execution_privacy_posture: executionPrivacyPosture },
      });
    }
    return;
  }

  if (
    custodyClass === "unsafe_plaintext_mount" ||
    (custodyClass === "private_head" &&
      mountTarget === "rented_gpu" &&
      providerRootCanReadPlaintext)
  ) {
    requireUnsafePlaintextException({
      requiredControls,
      authorityScopeRefs,
      walletApprovalRef,
      walletLeaseRef,
      userDisclosureRef,
      providerTrustAcceptanceRef,
      declassificationReceiptRefs,
      protectedPlaintextRequested,
      providerRootCanReadPlaintext,
    });
    return;
  }

  throw admissionError({
    code: "private_workspace_mount_custody_target_not_admissible",
    message:
      "Private workspace mount custody and target combination is not admissible.",
    details: { custody_class: custodyClass, mount_target: mountTarget },
  });
}

function requireUnsafePlaintextException({
  requiredControls,
  authorityScopeRefs,
  walletApprovalRef,
  walletLeaseRef,
  userDisclosureRef,
  providerTrustAcceptanceRef,
  declassificationReceiptRefs,
  protectedPlaintextRequested,
  providerRootCanReadPlaintext,
}) {
  if (!protectedPlaintextRequested || !providerRootCanReadPlaintext) {
    throw admissionError({
      code: "private_workspace_mount_unsafe_plaintext_shape_invalid",
      message:
        "Unsafe plaintext mount exceptions must explicitly request protected plaintext readable by provider root.",
      details: {
        protected_plaintext_requested: protectedPlaintextRequested,
        provider_root_can_read_plaintext: providerRootCanReadPlaintext,
      },
    });
  }
  requireControl(
    requiredControls,
    "explicit_unsafe_plaintext_acceptance",
    "unsafe_plaintext_mount",
  );
  requireScope(
    authorityScopeRefs,
    "scope:privacy.unsafe_plaintext_mount",
    "unsafe_plaintext_mount",
  );
  requirePrefixed(
    walletApprovalRef,
    "wallet_approval_ref",
    "approval://wallet/",
    "unsafe_plaintext_mount",
  );
  requirePrefixed(walletLeaseRef, "wallet_lease_ref", "lease:", "unsafe_plaintext_mount");
  requirePrefixed(
    userDisclosureRef,
    "user_disclosure_ref",
    "disclosure://",
    "unsafe_plaintext_mount",
  );
  requirePrefixed(
    providerTrustAcceptanceRef,
    "provider_trust_acceptance_ref",
    "approval://provider-trust/",
    "unsafe_plaintext_mount",
  );
  if (declassificationReceiptRefs.length === 0) {
    throw admissionError({
      code: "private_workspace_mount_declassification_receipt_required",
      message:
        "Unsafe private workspace plaintext mounts require declassification receipts.",
      details: { required: "declassification_receipt_refs" },
    });
  }
}

function decisionFor({
  custodyClass,
  providerRootCanReadPlaintext,
  protectedPlaintextRequested,
}) {
  if (protectedPlaintextRequested && providerRootCanReadPlaintext) {
    return "admitted_unsafe_exception";
  }
  if (custodyClass === "private_head") {
    return "admitted_declassification";
  }
  return "admitted";
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = [
    "workspaceMountProfile",
    "providerRootCanReadPlaintext",
    "protectedPlaintextRequested",
  ].filter((field) => Object.hasOwn(body, field));
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "private_workspace_mount_request_aliases_retired",
    message:
      "Private workspace mount admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `private_workspace_mount_${field}_invalid`,
      message: `Private workspace mount admission requires a valid ${field}.`,
      details: {
        [field]: normalized ?? null,
        allowed_values: [...allowedValues],
      },
    });
  }
  return normalized;
}

function prefixedString(value, field, prefix) {
  const normalized = requiredString(value, field);
  if (!normalized.startsWith(prefix)) {
    throw runtimeError({
      status: 400,
      code: "private_workspace_mount_ref_prefix_invalid",
      message: `${field} must use ${prefix} refs.`,
      details: { field, ref: normalized, expected_prefix: prefix },
    });
  }
  return normalized;
}

function prefixedRefs(value, field, prefix, { allowEmpty = false } = {}) {
  const refs = uniqueStrings(normalizeArray(value));
  if (!allowEmpty && refs.length === 0) {
    throw runtimeError({
      status: 400,
      code: "private_workspace_mount_required_refs_missing",
      message: `Private workspace mount admission requires ${field}.`,
      details: { field },
    });
  }
  for (const ref of refs) {
    if (!ref.startsWith(prefix)) {
      throw runtimeError({
        status: 400,
        code: "private_workspace_mount_ref_prefix_invalid",
        message: `${field} must use ${prefix} refs.`,
        details: { field, ref, expected_prefix: prefix },
      });
    }
  }
  return refs;
}

function requiredString(value, field) {
  const normalized = optionalString(value);
  if (!normalized) {
    throw runtimeError({
      status: 400,
      code: `private_workspace_mount_${field}_required`,
      message: `Private workspace mount admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function requireControl(requiredControls, control, custodyClass) {
  if (requiredControls.includes(control)) return;
  throw admissionError({
    code: "private_workspace_mount_required_control_missing",
    message: `Private workspace mount admission is missing required control ${control}.`,
    details: { custody_class: custodyClass, required_control: control },
  });
}

function requireScope(authorityScopeRefs, scope, custodyClass) {
  if (authorityScopeRefs.includes(scope)) return;
  throw admissionError({
    code: "private_workspace_mount_required_scope_missing",
    message:
      `Private workspace mount admission is missing required authority scope ${scope}.`,
    details: { custody_class: custodyClass, required_scope: scope },
  });
}

function requirePrefixed(value, field, prefix, custodyClass) {
  if (optionalString(value)?.startsWith(prefix)) return;
  throw admissionError({
    code: "private_workspace_mount_required_ref_missing",
    message: `Private workspace mount admission requires ${field}.`,
    details: {
      custody_class: custodyClass,
      field,
      expected_prefix: prefix,
    },
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
