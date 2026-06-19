import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const MODEL_ROUTE_MUTATION_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.model_route_mutation_admission.v1";

const MUTATION_KINDS = new Set([
  "select_route",
  "bind_session_route",
  "enable_route",
  "disable_route",
  "update_provider_credentials",
]);

const PROVIDER_KINDS = new Set([
  "local",
  "customer",
  "hosted_api",
  "tee",
  "provider_trust",
]);

const CREDENTIAL_POSTURES = new Set([
  "no_credentials_required",
  "wallet_credential_lease",
  "provider_vault_token",
  "customer_boundary",
  "unsafe_plaintext_secret",
]);

const RETIRED_ALIASES = [
  "routeRef",
  "sessionRef",
  "providerRef",
  "walletLeaseRef",
  "credentialLeaseRef",
  "agentgresOperationRefs",
  "receiptRefs",
  "stateRootRef",
];

export function admitModelRouteMutation(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const mutationKind = enumValue(
    request.mutation_kind,
    "mutation_kind",
    MUTATION_KINDS,
  );
  const routeRef = prefixedString(request.route_ref, "route_ref", "model-route:");
  const projectRef = prefixedString(request.project_ref, "project_ref", "project:");
  const sessionRef = optionalPrefixedString(
    request.session_ref,
    "session_ref",
    "session:",
  );
  const providerRef = prefixedString(
    request.provider_ref,
    "provider_ref",
    "provider:",
  );
  const providerKind = enumValue(
    request.provider_kind,
    "provider_kind",
    PROVIDER_KINDS,
  );
  const endpointRefs = prefixedRefs(
    request.endpoint_refs,
    "endpoint_refs",
    "model-endpoint:",
    { allowEmpty: mutationKind === "disable_route" },
  );
  const loadedInstanceRefs = prefixedRefs(
    request.loaded_instance_refs,
    "loaded_instance_refs",
    "model-instance:",
    { allowEmpty: true },
  );
  const credentialPosture = enumValue(
    request.credential_posture,
    "credential_posture",
    CREDENTIAL_POSTURES,
  );
  const providerRootReceivesPromptPlaintext =
    booleanValue(request.provider_root_receives_prompt_plaintext) ?? false;
  const providerRootReceivesCredentialPlaintext =
    booleanValue(request.provider_root_receives_credential_plaintext) ?? false;
  const authorityScopeRefs = prefixedRefs(
    request.authority_scope_refs,
    "authority_scope_refs",
    "scope:",
  );
  const credentialScopeRefs = prefixedRefs(
    request.credential_scope_refs,
    "credential_scope_refs",
    "scope:",
    { allowEmpty: true },
  );
  const walletApprovalRef = prefixedString(
    request.wallet_approval_ref,
    "wallet_approval_ref",
    "approval://wallet/",
    403,
  );
  const walletLeaseRef = prefixedString(
    request.wallet_lease_ref,
    "wallet_lease_ref",
    "lease:",
    403,
  );
  const providerCredentialLeaseRef = optionalPrefixedString(
    request.provider_credential_lease_ref,
    "provider_credential_lease_ref",
    "lease:",
  );
  const modelWeightCustodyAdmissionRef = optionalString(
    request.model_weight_custody_admission_ref,
  ) ?? null;
  const privacyPostureRef = optionalString(request.privacy_posture_ref) ?? null;
  const teeAttestationRef = optionalString(request.tee_attestation_ref) ?? null;
  const customerBoundaryRef =
    optionalString(request.customer_boundary_ref) ?? null;
  const providerTrustAcceptanceRef =
    optionalString(request.provider_trust_acceptance_ref) ?? null;
  const secretDisclosureReceiptRefs = prefixedRefs(
    request.secret_disclosure_receipt_refs,
    "secret_disclosure_receipt_refs",
    "receipt://",
    { allowEmpty: true },
  );
  const agentgresOperationRefs = prefixedRefs(
    request.agentgres_operation_refs,
    "agentgres_operation_refs",
    "agentgres://operation/",
  );
  const receiptRefs = prefixedRefs(
    request.receipt_refs,
    "receipt_refs",
    "receipt://",
  );
  const stateRootRef = prefixedString(
    request.state_root_ref,
    "state_root_ref",
    "agentgres://state-root/",
  );

  assertRouteMutation({
    mutationKind,
    providerKind,
    credentialPosture,
    authorityScopeRefs,
    credentialScopeRefs,
    providerCredentialLeaseRef,
    modelWeightCustodyAdmissionRef,
    privacyPostureRef,
    teeAttestationRef,
    customerBoundaryRef,
    providerTrustAcceptanceRef,
    secretDisclosureReceiptRefs,
    providerRootReceivesPromptPlaintext,
    providerRootReceivesCredentialPlaintext,
  });

  const admissionId =
    optionalString(request.admission_id) ??
    `model-route-mutation-admission:${safeId(routeRef)}:${safeId(mutationKind)}`;
  const mutationReceiptRef =
    optionalString(request.mutation_receipt_ref) ??
    `receipt://model-route-mutation/${safeId(routeRef)}/${safeId(mutationKind)}`;

  return {
    schema_version: MODEL_ROUTE_MUTATION_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    decision: "admitted",
    admission_state: "admitted_for_model_router",
    mutation_kind: mutationKind,
    route_ref: routeRef,
    project_ref: projectRef,
    session_ref: sessionRef,
    provider_ref: providerRef,
    provider_kind: providerKind,
    endpoint_refs: endpointRefs,
    loaded_instance_refs: loadedInstanceRefs,
    credential_posture: credentialPosture,
    provider_root_receives_prompt_plaintext: providerRootReceivesPromptPlaintext,
    provider_root_receives_credential_plaintext:
      providerRootReceivesCredentialPlaintext,
    authority_scope_refs: authorityScopeRefs,
    credential_scope_refs: credentialScopeRefs,
    wallet_approval_ref: walletApprovalRef,
    wallet_lease_ref: walletLeaseRef,
    provider_credential_lease_ref: providerCredentialLeaseRef,
    model_weight_custody_admission_ref: modelWeightCustodyAdmissionRef,
    privacy_posture_ref: privacyPostureRef,
    tee_attestation_ref: teeAttestationRef,
    customer_boundary_ref: customerBoundaryRef,
    provider_trust_acceptance_ref: providerTrustAcceptanceRef,
    secret_disclosure_receipt_refs: secretDisclosureReceiptRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    receipt_refs: uniqueStrings([...receiptRefs, mutationReceiptRef]),
    state_root_ref: stateRootRef,
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    route_mutation_invariant:
      "Model route mutation is daemon-admitted only after wallet authority, credential lease posture, model-weight custody admission, Agentgres operation refs, receipts, and state-root refs are bound.",
    runtimeTruthSource: "daemon-runtime",
  };
}

function assertRouteMutation({
  mutationKind,
  providerKind,
  credentialPosture,
  authorityScopeRefs,
  credentialScopeRefs,
  providerCredentialLeaseRef,
  modelWeightCustodyAdmissionRef,
  privacyPostureRef,
  teeAttestationRef,
  customerBoundaryRef,
  providerTrustAcceptanceRef,
  secretDisclosureReceiptRefs,
  providerRootReceivesPromptPlaintext,
  providerRootReceivesCredentialPlaintext,
}) {
  requireScope(authorityScopeRefs, "scope:model.route.mutate", mutationKind);
  if (
    mutationKind !== "disable_route" &&
    !modelWeightCustodyAdmissionRef?.startsWith(
      "model-weight-custody-admission:",
    )
  ) {
    throw admissionError({
      code: "model_route_mutation_custody_admission_required",
      message:
        "Model route mutation requires model-weight custody admission before enabling or binding routes.",
      details: { mutation_kind: mutationKind },
    });
  }
  if (mutationKind !== "disable_route" && !privacyPostureRef) {
    throw admissionError({
      code: "model_route_mutation_privacy_posture_required",
      message:
        "Model route mutation requires an execution privacy posture ref before enabling or binding routes.",
      details: { mutation_kind: mutationKind },
    });
  }
  if (["wallet_credential_lease", "provider_vault_token"].includes(credentialPosture)) {
    requireScope(credentialScopeRefs, "scope:secret.use", mutationKind);
    if (!providerCredentialLeaseRef) {
      throw admissionError({
        code: "model_route_mutation_provider_credential_lease_required",
        message:
          "Model route mutation requires a wallet/provider credential lease for credentialed provider routes.",
        details: { credential_posture: credentialPosture },
      });
    }
  }
  if (credentialPosture === "customer_boundary" && !customerBoundaryRef) {
    throw admissionError({
      code: "model_route_mutation_customer_boundary_required",
      message:
        "Customer-boundary model route mutation requires a customer boundary ref.",
      details: { credential_posture: credentialPosture },
    });
  }
  if (providerKind === "tee" && !teeAttestationRef) {
    throw admissionError({
      code: "model_route_mutation_tee_attestation_required",
      message: "TEE model route mutation requires attestation.",
      details: { provider_kind: providerKind },
    });
  }
  if (providerKind === "provider_trust" || providerRootReceivesPromptPlaintext) {
    if (!providerTrustAcceptanceRef?.startsWith("approval://provider-trust/")) {
      throw admissionError({
        code: "model_route_mutation_provider_trust_acceptance_required",
        message:
          "Provider-trust model route mutation requires provider-trust acceptance.",
        details: { provider_kind: providerKind },
      });
    }
  }
  if (credentialPosture === "unsafe_plaintext_secret") {
    requireScope(credentialScopeRefs, "scope:secret.export", mutationKind);
    if (!providerRootReceivesCredentialPlaintext) {
      throw admissionError({
        code: "model_route_mutation_unsafe_secret_shape_invalid",
        message:
          "Unsafe plaintext secret routes must explicitly disclose provider-root credential visibility.",
        details: { provider_root_receives_credential_plaintext: false },
      });
    }
    if (secretDisclosureReceiptRefs.length === 0) {
      throw admissionError({
        code: "model_route_mutation_secret_disclosure_receipt_required",
        message:
          "Unsafe plaintext secret routes require secret disclosure receipts.",
        details: { required: "secret_disclosure_receipt_refs" },
      });
    }
    if (!providerTrustAcceptanceRef?.startsWith("approval://provider-trust/")) {
      throw admissionError({
        code: "model_route_mutation_secret_provider_trust_acceptance_required",
        message:
          "Unsafe plaintext secret routes require provider-trust acceptance.",
        details: { credential_posture: credentialPosture },
      });
    }
  }
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = RETIRED_ALIASES.filter((field) => Object.hasOwn(body, field));
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "model_route_mutation_request_aliases_retired",
    message:
      "Model route mutation admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `model_route_mutation_${field}_invalid`,
      message: `Model route mutation admission requires a valid ${field}.`,
      details: {
        [field]: normalized ?? null,
        allowed_values: [...allowedValues],
      },
    });
  }
  return normalized;
}

function prefixedString(value, field, prefix, status = 400) {
  const normalized = requiredString(value, field, status);
  if (!normalized.startsWith(prefix)) {
    throw runtimeError({
      status,
      code: "model_route_mutation_ref_prefix_invalid",
      message: `${field} must use ${prefix} refs.`,
      details: { field, ref: normalized, expected_prefix: prefix },
    });
  }
  return normalized;
}

function optionalPrefixedString(value, field, prefix) {
  const normalized = optionalString(value);
  if (!normalized) return null;
  return prefixedString(normalized, field, prefix);
}

function prefixedRefs(value, field, prefix, { allowEmpty = false } = {}) {
  const refs = uniqueStrings(normalizeArray(value));
  if (!allowEmpty && refs.length === 0) {
    throw runtimeError({
      status: 400,
      code: "model_route_mutation_required_refs_missing",
      message: `Model route mutation admission requires ${field}.`,
      details: { field },
    });
  }
  for (const ref of refs) {
    if (!ref.startsWith(prefix)) {
      throw runtimeError({
        status: 400,
        code: "model_route_mutation_ref_prefix_invalid",
        message: `${field} must use ${prefix} refs.`,
        details: { field, ref, expected_prefix: prefix },
      });
    }
  }
  return refs;
}

function requiredString(value, field, status = 400) {
  const normalized = optionalString(value);
  if (!normalized) {
    throw runtimeError({
      status,
      code: `model_route_mutation_${field}_required`,
      message: `Model route mutation admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function requireScope(scopeRefs, scope, mutationKind) {
  if (scopeRefs.includes(scope)) return;
  throw admissionError({
    code: "model_route_mutation_required_scope_missing",
    message: `Model route mutation admission requires ${scope}.`,
    details: { mutation_kind: mutationKind, required_scope: scope },
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
