import crypto from "node:crypto";

import { stableStringify } from "./c7-c8-certificate.mjs";

export const sha256 = (bytes) =>
  `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

export const randomHex32 = () => crypto.randomBytes(32).toString("hex");

export function sealStandingAuthorityEnvelope(value) {
  const envelope = structuredClone(value);
  delete envelope.body_hash;
  const material = {
    ...envelope,
    domain: "ioi.standing-authority-envelope-jcs-sha256.v1",
  };
  envelope.body_hash = sha256(stableStringify(material));
  return envelope;
}

// M13.3 — the standing envelope a Connections attach declares for the Sessions naming that
// connection (schema://ioi/components/hypervisor/session-standing-envelope/v1); a sibling of
// the provider envelope under its own hash domain.
export function sealSessionStandingEnvelope(value) {
  const envelope = structuredClone(value);
  delete envelope.body_hash;
  const material = {
    ...envelope,
    domain: "ioi.session-standing-envelope-jcs-sha256.v1",
  };
  envelope.body_hash = sha256(stableStringify(material));
  return envelope;
}

export function approvalCeremonyContextHash(context) {
  return sha256(
    Buffer.concat([
      Buffer.from("IOI-APPROVAL-CEREMONY-CONTEXT-V1\0"),
      Buffer.from(stableStringify(context)),
    ]),
  );
}

export function sealAuthFactorReceipt(value) {
  const receipt = structuredClone(value);
  delete receipt.receipt_hash;
  receipt.receipt_hash = sha256(stableStringify(receipt));
  return receipt;
}

// A SYNTHETIC approval ceremony for a standing envelope, for verifiers that prove the broker,
// daemon and session planes without a physical passkey. The auth-factor receipt is explicitly
// labelled synthetic (`factor_origin`), exactly as the broker-contract verifier claims: it proves
// the registered contract tuple binds and is consumed, never that a person tapped a key. A
// deployment records real ceremonies through its own custody tier; this helper is test material.
// R-14 (ruled 2026-09-09): the DEPLOYMENT-LOCAL OPERATOR custody tier. The operator holds the
// approver key on the deployment host; the ceremony is their explicit act, receipted before the
// effect, and the factor receipt (auth-factor-receipt v2) attests CUSTODY — the host, the hash of
// the key's path, that it is readable by its owner alone, and when the operator performed it — and
// never a person. Same one-ceremony, non-widening rules as the passkey step-up.
export function deploymentLocalOperatorCeremony({
  principalRef,
  hostRef,
  keyPath,
  envelope,
  policyHash,
  reviewReceiptHash,
  validationProfileRef,
  nowMs,
  marker = randomHex32().slice(0, 16),
  productSessionRef = `session://deployment-local-operator/${marker}`,
}) {
  const built = syntheticStandingCeremony({
    principalRef,
    envelope,
    policyHash,
    reviewReceiptHash,
    validationProfileRef,
    nowMs,
    marker,
    productSessionRef,
    // The ceremony window, the grant's validity and the wallet's own comparison are all judged on
    // the AUTHORITY NODE's committed chain clock, which a deployment may run deterministically.
    // The operator's acknowledgement is stamped in that same frame; stamping it from the host
    // clock put the receipt outside its own consent window on every deterministic deployment.
    factorWallClockMs: nowMs,
    factorPostureRef: `auth_factor://deployment-local-operator/${encodeURIComponent(hostRef)}`,
    factorOverrides: {
      schema_version: "ioi.hypervisor.auth-factor-receipt.v2",
      factor_kind: "deployment_local_operator",
      user_verification: "deployment_local_key_custody",
      custody_tier_evidence: {
        host_ref: hostRef,
        key_path_hash: sha256(Buffer.from(String(keyPath), "utf8")),
        key_mode_octal: "600",
        operator_acknowledged_at: new Date(nowMs).toISOString(),
      },
    },
    factorOrigin: "deployment_local_operator_key_custody",
  });
  return built;
}

export function syntheticStandingCeremony({
  principalRef,
  operatorPrincipalRef = principalRef,
  envelope,
  policyHash,
  reviewReceiptHash,
  validationProfileRef,
  nowMs,
  factorWallClockMs = Date.now(),
  marker = randomHex32().slice(0, 16),
  productSessionRef = `session://standing-consumer-loop/${marker}`,
  factorPostureRef = "auth_factor://passkey/operator/device",
  factorOverrides = null,
  factorOrigin = "synthetic_contract_fixture_not_physical_passkey",
}) {
  const hash = () => `sha256:${randomHex32()}`;
  const authorizationSubject = {
    kind: "standing_envelope",
    subject_ref: envelope.standing_envelope_ref,
    subject_hash: envelope.body_hash,
    validation_profile_ref: validationProfileRef,
  };
  const context = {
    schema_version: "ioi.foundations.approval-ceremony-context.v1",
    approval_ceremony_context_ref: `approval-ceremony-context://standing-consumer-loop/${marker}`,
    authority_request_ref: `authority-request://standing-consumer-loop/${marker}`,
    authority_request_body_hash: hash(),
    authority_review_ref: `review://standing-consumer-loop/${marker}`,
    authority_review_body_hash: hash(),
    predecessor_authority_review_ref: null,
    predecessor_authority_review_body_hash: null,
    predecessor_authority_request_ref: null,
    predecessor_authority_request_body_hash: null,
    predecessor_authority_review_receipt_ref: null,
    predecessor_authority_review_receipt_hash: null,
    reviewed_representation_hash: hash(),
    principal_ref: operatorPrincipalRef,
    acting_subject_ref: "runtime://hypervisor/operator",
    product_session_ref: productSessionRef,
    origin_binding_ref: "origin://hypervisor/local",
    authorization_subject: authorizationSubject,
    presentation_surface_ref: "wallet-client://hypervisor/local",
    presentation_evidence_profile_ref: "policy://presentation/passkey/v1",
    principal_authority_resolution_ref: null,
    principal_authority_resolution_hash: null,
    required_auth_factor_posture_refs: [factorPostureRef],
    required_guardian_surface_refs: [],
    posture_satisfaction_profile_ref: "policy://auth-posture/step-up/v1",
    interaction_mode: "interactive",
    authentication_posture: "step_up",
    receipt_timing: "before_effect",
    policy_decision_receipt_ref: `receipt://standing-consumer-loop/review/${marker}`,
    policy_decision_receipt_hash: reviewReceiptHash,
    policy_hash: policyHash,
    risk_classes: ["external_spend", "standing_authority"],
    revocation_epoch: 0,
    nonce_b64url: randomHex32().replaceAll("+", "-").replaceAll("/", "_"),
    issued_at: new Date(Math.max(0, nowMs - 1_000)).toISOString(),
    expires_at: new Date(nowMs + 4 * 60_000).toISOString(),
    single_use: true,
  };
  const contextHash = approvalCeremonyContextHash(context);
  const factor = sealAuthFactorReceipt({
    schema_version: "ioi.hypervisor.auth-factor-receipt.v1",
    receipt_id: `afr_${marker}`,
    ceremony_id: `pkc_${marker}`,
    principal_id: "standing-consumer-loop",
    principal_ref: operatorPrincipalRef,
    factor_kind: "passkey",
    credential_id_hash: hash(),
    user_verification: "required_and_verified",
    purpose: "standing_effect_authority",
    approval_ceremony_context_ref: context.approval_ceremony_context_ref,
    approval_ceremony_context_hash: contextHash,
    authorization_subject: authorizationSubject,
    policy_hash: policyHash,
    effect_authority_created: false,
    created_at: new Date(factorWallClockMs).toISOString(),
    ...(factorOverrides ?? {}),
  });
  return { context, contextHash, factor, factor_origin: factorOrigin };
}
