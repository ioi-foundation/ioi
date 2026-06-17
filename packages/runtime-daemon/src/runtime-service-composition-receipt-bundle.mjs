import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const SERVICE_COMPOSITION_RECEIPT_BUNDLE_SCHEMA_VERSION =
  "ioi.runtime.service_composition_receipt_bundle.v1";

const PRIVATE_DATA_POSTURES = new Set([
  "public_only",
  "ctee_private_workspace",
  "customer_plaintext",
  "provider_trust_plaintext",
  "unsafe_plaintext_exception",
]);

const DELIVERY_STATUSES = new Set([
  "delivered",
  "partial",
  "failed",
  "disputed",
]);

const RETIRED_ALIASES = [
  "compositionGraphRef",
  "contributionReceipts",
  "verifierReceipts",
  "policyReceipts",
  "routingReceipts",
  "privateDataPosture",
  "disputeEvidence",
  "agentgresOperationRefs",
  "stateRoot",
];

export function admitServiceCompositionReceiptBundle(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const serviceRef = requiredString(request.service_ref, "service_ref");
  const deliveryRef = requiredString(request.delivery_ref, "delivery_ref");
  const compositionGraphRef = requiredString(
    request.composition_graph_ref,
    "composition_graph_ref",
  );
  const privateDataPosture = enumValue(
    request.private_data_posture,
    "private_data_posture",
    PRIVATE_DATA_POSTURES,
  );
  const deliveryStatus = enumValue(
    request.delivery_status ?? "delivered",
    "delivery_status",
    DELIVERY_STATUSES,
  );
  const contributionReceiptRefs = uniqueRefs(request.contribution_receipt_refs);
  const verifierReceiptRefs = uniqueRefs(request.verifier_receipt_refs);
  const policyReceiptRefs = uniqueRefs(request.policy_receipt_refs);
  const routingReceiptRefs = uniqueRefs(request.routing_receipt_refs);
  const disputeEvidenceRefs = uniqueRefs(request.dispute_evidence_refs);
  const agentgresOperationRefs = uniqueRefs(request.agentgres_operation_refs);
  const artifactRefs = uniqueRefs(request.artifact_refs);
  const payloadRefs = uniqueRefs(request.payload_refs);
  const receiptRefs = uniqueRefs(request.receipt_refs);
  const providerLogRefs = uniqueRefs(request.provider_log_refs);
  const stateRoot = requiredString(request.state_root, "state_root");
  const walletApprovalRef = optionalString(request.wallet_approval_ref) ?? null;
  const unsafePlaintextExceptionRef =
    optionalString(request.unsafe_plaintext_exception_ref) ?? null;
  const settlementRequested =
    booleanValue(request.settlement_requested) ?? deliveryStatus === "delivered";

  assertServiceCompositionBundle({
    privateDataPosture,
    deliveryStatus,
    contributionReceiptRefs,
    verifierReceiptRefs,
    policyReceiptRefs,
    routingReceiptRefs,
    disputeEvidenceRefs,
    agentgresOperationRefs,
    artifactRefs,
    payloadRefs,
    receiptRefs,
    providerLogRefs,
    stateRoot,
    walletApprovalRef,
    unsafePlaintextExceptionRef,
    settlementRequested,
  });

  const bundleRef =
    optionalString(request.bundle_ref) ??
    `service-composition-bundle:${safeId(deliveryRef)}:${safeId(stateRoot)}`;

  return {
    schema_version: SERVICE_COMPOSITION_RECEIPT_BUNDLE_SCHEMA_VERSION,
    bundle_ref: bundleRef,
    service_ref: serviceRef,
    delivery_ref: deliveryRef,
    composition_graph_ref: compositionGraphRef,
    delivery_status: deliveryStatus,
    settlement_ready:
      settlementRequested &&
      deliveryStatus === "delivered" &&
      privateDataPosture !== "unsafe_plaintext_exception",
    contribution_receipt_refs: contributionReceiptRefs,
    verifier_receipt_refs: verifierReceiptRefs,
    policy_receipt_refs: policyReceiptRefs,
    routing_receipt_refs: routingReceiptRefs,
    private_data_posture: privateDataPosture,
    unsafe_plaintext_exception_ref: unsafePlaintextExceptionRef,
    dispute_evidence_refs: disputeEvidenceRefs,
    provider_log_refs: providerLogRefs,
    artifact_refs: artifactRefs,
    payload_refs: payloadRefs,
    receipt_refs: receiptRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    state_root: stateRoot,
    wallet_approval_ref: walletApprovalRef,
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    runtimeTruthSource: "daemon-runtime",
  };
}

function assertServiceCompositionBundle({
  privateDataPosture,
  deliveryStatus,
  contributionReceiptRefs,
  verifierReceiptRefs,
  policyReceiptRefs,
  routingReceiptRefs,
  disputeEvidenceRefs,
  agentgresOperationRefs,
  artifactRefs,
  payloadRefs,
  receiptRefs,
  providerLogRefs,
  stateRoot,
  walletApprovalRef,
  unsafePlaintextExceptionRef,
  settlementRequested,
}) {
  requireRefs(contributionReceiptRefs, "contribution_receipt_refs");
  requireRefs(verifierReceiptRefs, "verifier_receipt_refs");
  requireRefs(policyReceiptRefs, "policy_receipt_refs");
  requireRefs(routingReceiptRefs, "routing_receipt_refs");
  requireRefs(disputeEvidenceRefs, "dispute_evidence_refs");
  requireRefs(agentgresOperationRefs, "agentgres_operation_refs");
  requireRefs(receiptRefs, "receipt_refs");
  if (artifactRefs.length === 0 && payloadRefs.length === 0) {
    throw admissionError({
      code: "service_composition_delivery_payload_or_artifact_required",
      message:
        "Service composition bundles require artifact or payload refs for delivery evidence.",
      details: { artifact_refs: artifactRefs, payload_refs: payloadRefs },
    });
  }
  requirePrefix(stateRoot, "state_root:", "state_root");

  if (providerLogRefs.length > 0 && disputeEvidenceRefs.length === 0) {
    throw admissionError({
      code: "service_composition_provider_logs_not_dispute_truth",
      message:
        "Provider logs may support dispute evidence but cannot be the dispute truth by themselves.",
      details: { provider_log_refs: providerLogRefs },
    });
  }

  if (privateDataPosture === "unsafe_plaintext_exception") {
    if (!walletApprovalRef || !unsafePlaintextExceptionRef) {
      throw admissionError({
        code: "service_composition_unsafe_plaintext_exception_unapproved",
        message:
          "Unsafe plaintext service delivery exceptions require wallet approval and exception receipt refs.",
        details: {
          wallet_approval_ref: walletApprovalRef,
          unsafe_plaintext_exception_ref: unsafePlaintextExceptionRef,
        },
      });
    }
  }

  if (settlementRequested && deliveryStatus === "delivered") {
    if (privateDataPosture === "unsafe_plaintext_exception") {
      throw admissionError({
        code: "service_composition_unsafe_plaintext_settlement_blocked",
        message:
          "Unsafe plaintext exception deliveries cannot be marked settlement-ready by default.",
        details: { private_data_posture: privateDataPosture },
      });
    }
  }
}

function requireRefs(refs, field) {
  if (refs.length > 0) return;
  throw admissionError({
    code: `service_composition_${field}_required`,
    message: `Service composition bundle requires ${field}.`,
    details: { field },
  });
}

function requirePrefix(value, prefix, field) {
  if (value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `service_composition_${field}_invalid`,
    message: `Service composition ${field} must start with ${prefix}.`,
    details: { [field]: value },
  });
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = RETIRED_ALIASES.filter((field) => Object.hasOwn(body, field));
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "service_composition_request_aliases_retired",
    message:
      "Service composition receipt bundle admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `service_composition_${field}_invalid`,
      message: `Service composition receipt bundle requires a valid ${field}.`,
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
      code: `service_composition_${field}_required`,
      message: `Service composition receipt bundle requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function uniqueRefs(value) {
  return [...new Set(normalizeArray(value).map((item) => String(item).trim()).filter(Boolean))];
}

function admissionError({ code, message, details }) {
  return runtimeError({
    status: 403,
    code,
    message,
    details,
  });
}
