#!/usr/bin/env node

// Real wallet.network chain/broker integration for the standing-authority evidence contract.
// The factor receipt here is deliberately synthetic: WebAuthn cryptography is tested at the
// device route, while this held bar proves the separate broker independently validates, records,
// and revokes the exact registered envelope/context/receipt tuple. It claims no physical passkey.

import {
  approvalCeremonyContextHash,
  randomHex32,
  sealAuthFactorReceipt,
  sealStandingAuthorityEnvelope,
} from "./lib/standing-authority-evidence.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const hash = () => `sha256:${randomHex32()}`;
const marker = randomHex32().slice(0, 16);
const principalRef = "org://acme/research";
const policyHash = hash();
const reviewReceiptHash = hash();

let fixture;
try {
  fixture = await startRealWalletNetworkPrincipalAuthorityFixture();
  const now = fixture.chainTimestampMs;
  const envelope = sealStandingAuthorityEnvelope({
    schema_version: "ioi.foundations.standing-authority-envelope.v1",
    standing_envelope_ref: `standing-envelope://wallet-broker/${marker}`,
    owner_ref: "org://acme/research",
    bounded_system_ref: "system://aft/u1",
    principal_ref: principalRef,
    audience_ref: "wallet-client://hypervisor/provider-ops",
    authority_scope: "scope:hypervisor.live-route.hypervisor-provider-op",
    facet_template: {
      provider_id: "pacc_18cd245812ad55b9",
      operations: ["create", "delete", "reconcile"],
      provider_selector: {
        mode: "exact",
        provider_addresses: ["akash1aaul837r7en7hpk9wv2svg8u78fdq0t2j2e82z"],
        selection: "only_qualified_bid_from_exact_provider",
      },
      per_operation_deposit_microusd: 1_000_000,
      pricing_ceiling: { amount: "1000", denom: "uact" },
      sdl_hashes: [hash()],
      image_digests: [hash()],
      registry_hosts: ["ghcr.io"],
      result_destination_refs: ["connector://result/aft-u1"],
      result_transport_certificate_hashes: [hash()],
      auto_topup: false,
      teardown_policy: "always_teardown_required",
      max_duration_seconds: 7200,
    },
    aggregate_bounds: {
      max_cumulative_deposit_microusd: 2_000_000,
      max_cumulative_spend_microusd: 2_000_000,
      max_usages: 2,
      max_concurrent_resources: 1,
      max_provider_fanout: 1,
      max_failures: 2,
    },
    not_before_ms: Math.max(0, now - 30_000),
    expires_at_ms: now + 30 * 60_000,
    revocation_epoch: 0,
    trajectory_policy_ref: "policy://aft/u1/trajectory/v1",
    trajectory_policy_hash: policyHash,
    approval_mode: "standing_envelope",
    recovery_posture: "recovery_never_widens_or_resets_drawdown",
  });
  const authorizationSubject = {
    kind: "standing_envelope",
    subject_ref: envelope.standing_envelope_ref,
    subject_hash: envelope.body_hash,
    validation_profile_ref: "schema://ioi/foundations/standing-authority-envelope/v1",
  };
  const context = {
    schema_version: "ioi.foundations.approval-ceremony-context.v1",
    approval_ceremony_context_ref: `approval-ceremony-context://wallet-broker/${marker}`,
    authority_request_ref: `authority-request://wallet-broker/${marker}`,
    authority_request_body_hash: hash(),
    authority_review_ref: `review://wallet-broker/${marker}`,
    authority_review_body_hash: hash(),
    predecessor_authority_review_ref: null,
    predecessor_authority_review_body_hash: null,
    predecessor_authority_request_ref: null,
    predecessor_authority_request_body_hash: null,
    predecessor_authority_review_receipt_ref: null,
    predecessor_authority_review_receipt_hash: null,
    reviewed_representation_hash: hash(),
    principal_ref: principalRef,
    acting_subject_ref: "runtime://hypervisor/operator",
    product_session_ref: `session://wallet-broker/${marker}`,
    origin_binding_ref: "origin://hypervisor/local",
    authorization_subject: authorizationSubject,
    presentation_surface_ref: "wallet-client://hypervisor/local",
    presentation_evidence_profile_ref: "policy://presentation/passkey/v1",
    principal_authority_resolution_ref: null,
    principal_authority_resolution_hash: null,
    required_auth_factor_posture_refs: ["auth_factor://passkey/operator/device"],
    required_guardian_surface_refs: [],
    posture_satisfaction_profile_ref: "policy://auth-posture/step-up/v1",
    interaction_mode: "interactive",
    authentication_posture: "step_up",
    receipt_timing: "before_effect",
    policy_decision_receipt_ref: `receipt://wallet-broker/review/${marker}`,
    policy_decision_receipt_hash: reviewReceiptHash,
    policy_hash: policyHash,
    risk_classes: ["external_spend", "standing_authority"],
    revocation_epoch: 0,
    nonce_b64url: randomHex32().replaceAll("+", "-").replaceAll("/", "_"),
    issued_at: new Date(Math.max(0, now - 1_000)).toISOString(),
    expires_at: new Date(now + 4 * 60_000).toISOString(),
    single_use: true,
  };
  const contextHash = approvalCeremonyContextHash(context);
  const factor = sealAuthFactorReceipt({
    schema_version: "ioi.hypervisor.auth-factor-receipt.v1",
    receipt_id: `afr_${marker}`,
    ceremony_id: `pkc_${marker}`,
    principal_id: "acme-research",
    principal_ref: principalRef,
    factor_kind: "passkey",
    credential_id_hash: hash(),
    user_verification: "required_and_verified",
    purpose: "standing_effect_authority",
    approval_ceremony_context_ref: context.approval_ceremony_context_ref,
    approval_ceremony_context_hash: contextHash,
    authorization_subject: authorizationSubject,
    policy_hash: policyHash,
    effect_authority_created: false,
    created_at: new Date(now).toISOString(),
  });
  const grant = fixture.mintStandingForCapability(principalRef, {
    standingEnvelopeHash: envelope.body_hash,
    policyHash,
    nonce: randomHex32(),
    counter: 1,
    issuedAtMs: now,
    expiresAtMs: now + 20 * 60_000,
    maxUsages: 2,
    maxCumulativeDepositMicrousd: 2_000_000,
    maxCumulativeSpendMicrousd: 2_000_000,
    reviewReceiptHash,
    approvalCeremonyContextHash: contextHash,
    authFactorReceiptHash: factor.receipt_hash,
  });
  const recorded = await fixture.recordStandingApprovalGrant(
    principalRef,
    grant,
    envelope,
    context,
    factor,
  );
  const revoked = await fixture.revokeStandingApprovalGrant(
    principalRef,
    recorded.standing_grant_hash,
  );
  console.log(JSON.stringify({
    check: "check:standing-authority-broker-contract",
    verdict: "PASS",
    factor_origin: "synthetic_contract_fixture_not_physical_passkey",
    standing_envelope_hash: recorded.standing_envelope_hash,
    standing_grant_status: revoked.standing_grant_status,
  }, null, 2));
} finally {
  await fixture?.stop();
}
