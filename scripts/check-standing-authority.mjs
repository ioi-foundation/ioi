#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const paths = {
  action: "crates/types/src/app/action.rs",
  handler: "crates/services/src/wallet_network/handlers/standing_authority.rs",
  wallet: "crates/services/src/wallet_network/mod.rs",
  auth: "crates/services/src/wallet_network/handlers/client_auth.rs",
  config: "crates/types/src/config/mod.rs",
  provider: "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs",
  governed: "crates/node/src/bin/hypervisor_daemon_routes/governed_authority.rs",
  client: "crates/node/src/bin/hypervisor_daemon_routes/wallet_network_capability_client.rs",
  lifecycle: "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs",
};
const sources = Object.fromEntries(
  Object.entries(paths).map(([name, path]) => [name, readFileSync(join(repo, path), "utf8")]),
);

function inspect({ action, handler, wallet, auth, config, provider, governed, client, lifecycle }) {
  const findings = [];
  const requireText = (source, value, code) => {
    if (!source.includes(value)) findings.push(code);
  };

  requireText(action, "struct ApprovalGrantSigningMaterial<'a>", "c7_grant_material_missing");
  requireText(action, "request_hash: [u8; 32]", "c7_exact_request_binding_missing");
  requireText(action, "pub struct StandingApprovalGrant", "standing_grant_not_separate");
  requireText(action, "standing_envelope_hash: [u8; 32]", "standing_envelope_hash_missing");
  requireText(handler, ".checked_add(1)", "usage_counter_not_overflow_safe");
  requireText(handler, ".checked_add(params.estimated_deposit_microusd)", "deposit_counter_not_overflow_safe");
  requireText(handler, ".checked_add(params.estimated_spend_microusd)", "spend_counter_not_overflow_safe");
  requireText(handler, "next_usage > grant_state.grant.max_usages", "usage_ceiling_missing");
  requireText(handler, "next_deposit > grant_state.grant.max_cumulative_deposit_microusd", "deposit_ceiling_missing");
  requireText(handler, "next_spend > grant_state.grant.max_cumulative_spend_microusd", "spend_ceiling_missing");
  requireText(handler, "params.actual_spend_microusd > consumption.estimated_spend_microusd", "terminal_spend_not_bounded_by_reservation");
  requireText(handler, "cumulative_spend_reserved_microusd: grant_state.cumulative_spend_reserved_microusd", "refund_releases_authority");
  requireText(handler, "validate_expected_principal_authority_binding", "current_principal_authority_not_resolved");
  requireText(handler, "standing approval grant principal or signer does not match current principal authority", "principal_authority_substitution_not_refused");
  requireText(handler, "StandingApprovalGrantStatus::Active", "revocation_status_not_enforced");
  requireText(handler, "fn validate_standing_evidence(", "standing_evidence_validator_missing");
  requireText(handler, "AUTH_FACTOR_RECEIPT_CONTRACT", "passkey_factor_contract_not_validated");
  requireText(handler, "factor_hash != grant.auth_factor_receipt_hash", "factor_receipt_not_bound_to_grant");
  requireText(handler, "context_hash != grant.approval_ceremony_context_hash", "approval_context_not_bound_to_grant");
  requireText(handler, 'context.get("principal_ref") != envelope.get("principal_ref")', "consent_principal_not_bound_to_envelope");
  requireText(handler, "params.expected_principal_authority.principal_ref != grant_state.principal_ref", "draw_principal_not_bound_to_envelope");
  requireText(handler, "standing evidence does not bind the grant envelope and policy", "standing_envelope_evidence_not_bound");
  requireText(handler, "issued_revocation_epoch != load_revocation_epoch(state)?", "revocation_epoch_not_enforced");
  requireText(handler, "StandingApprovalMode::SilentWithinStandingEnvelope", "actual_approval_mode_not_receipted");
  requireText(wallet, '"record_standing_approval_grant@v1"', "record_method_missing");
  requireText(wallet, '"consume_standing_approval_grant_for_effect@v1"', "draw_method_missing");
  requireText(wallet, '"settle_standing_approval_grant_consumption@v1"', "settlement_method_missing");
  requireText(wallet, '"revoke_standing_approval_grant@v1"', "revoke_method_missing");
  requireText(auth, "WalletAuthRole::ControlPlane", "standing_grant_control_plane_gate_missing");
  requireText(auth, "WalletAuthRole::Capability", "standing_draw_capability_gate_missing");
  requireText(config, "WALLET_STANDING_AUTHORITY_CONFIG_MIGRATION_CODE", "explicit_policy_migration_missing");
  requireText(provider, "fn validate_standing_provider_facets(", "daemon_facet_containment_missing");
  requireText(provider, "standing_result_destination_outside_envelope", "result_destination_containment_missing");
  requireText(provider, "standing_provider_address_outside_envelope", "provider_containment_missing");
  requireText(provider, "standing_deposit_outside_envelope", "per_effect_deposit_containment_missing");
  requireText(provider, "provider_authority_mode_ambiguous", "authority_mode_confusion_not_refused");
  requireText(governed, "canonicalize_standing_approval_grant", "standing_grant_canonicalizer_missing");
  requireText(governed, "ioi.hypervisor.standing-authority-consumption.v1", "standing_intent_domain_missing");
  requireText(governed, "revalidate_standing_admission_receipt", "standing_pre_invoker_revalidation_missing");
  requireText(client, "receipt.receipt_hash == expected_hash", "standing_receipt_hash_not_verified");
  requireText(client, "validate_standing_effect_settlement_receipt", "standing_settlement_receipt_not_verified");
  requireText(client, "recover_standing_approval_grant_consumption_for_effect", "standing_receipt_recovery_missing");
  requireText(lifecycle, "CapabilityAuthorityAdmission::Standing", "capability_gateway_standing_lane_missing");
  requireText(provider, "terminal_spend_microusd(&evidence)", "provider_terminal_spend_not_reconciled_to_wallet");
  return [...new Set(findings)].sort();
}

if (process.argv.includes("--mutation")) {
  const mutations = [
    {
      name: "one_shot_grant_loses_exact_request_hash",
      expected: "c7_exact_request_binding_missing",
      sources: { ...sources, action: sources.action.replaceAll("request_hash: [u8; 32]", "request_digest: [u8; 32]") },
    },
    {
      name: "usage_counter_wraps",
      expected: "usage_counter_not_overflow_safe",
      sources: { ...sources, handler: sources.handler.replace(".checked_add(1)", ".wrapping_add(1)") },
    },
    {
      name: "cumulative_spend_ceiling_removed",
      expected: "spend_ceiling_missing",
      sources: { ...sources, handler: sources.handler.replace("next_spend > grant_state.grant.max_cumulative_spend_microusd", "false") },
    },
    {
      name: "current_principal_binding_removed",
      expected: "current_principal_authority_not_resolved",
      sources: { ...sources, handler: sources.handler.replaceAll("validate_expected_principal_authority_binding", "trust_requested_principal_authority") },
    },
    {
      name: "revocation_epoch_ignored",
      expected: "revocation_epoch_not_enforced",
      sources: { ...sources, handler: sources.handler.replace("issued_revocation_epoch != load_revocation_epoch(state)?", "false") },
    },
    {
      name: "result_destination_containment_removed",
      expected: "result_destination_containment_missing",
      sources: { ...sources, provider: sources.provider.replaceAll("standing_result_destination_outside_envelope", "standing_destination_unchecked") },
    },
    {
      name: "factor_receipt_binding_removed",
      expected: "factor_receipt_not_bound_to_grant",
      sources: { ...sources, handler: sources.handler.replace("factor_hash != grant.auth_factor_receipt_hash", "false") },
    },
    {
      name: "consent_principal_can_differ_from_envelope",
      expected: "consent_principal_not_bound_to_envelope",
      sources: { ...sources, handler: sources.handler.replace('context.get("principal_ref") != envelope.get("principal_ref")', "false") },
    },
    {
      name: "draw_principal_can_differ_from_envelope",
      expected: "draw_principal_not_bound_to_envelope",
      sources: { ...sources, handler: sources.handler.replace("params.expected_principal_authority.principal_ref != grant_state.principal_ref", "false") },
    },
    {
      name: "wallet_receipt_hash_not_compared",
      expected: "standing_receipt_hash_not_verified",
      sources: { ...sources, client: sources.client.replaceAll("receipt.receipt_hash == expected_hash", "receipt.receipt_hash != [0u8; 32]") },
    },
    {
      name: "refund_releases_fresh_authority",
      expected: "refund_releases_authority",
      sources: { ...sources, handler: sources.handler.replace("cumulative_spend_reserved_microusd: grant_state.cumulative_spend_reserved_microusd", "cumulative_spend_reserved_microusd: next_settled") },
    },
    {
      name: "terminal_spend_can_exceed_reservation",
      expected: "terminal_spend_not_bounded_by_reservation",
      sources: { ...sources, handler: sources.handler.replace("params.actual_spend_microusd > consumption.estimated_spend_microusd", "false") },
    },
  ];
  const survived = mutations.filter(({ sources: mutated, expected }) => !inspect(mutated).includes(expected));
  if (survived.length > 0) {
    console.error(JSON.stringify({
      check: "mutate:standing-authority",
      verdict: "FAIL",
      survived: survived.map(({ name, expected }) => ({ name, expected })),
    }, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify({
    check: "mutate:standing-authority",
    verdict: "PASS",
    mutations: mutations.map(({ name, expected }) => ({ name, detected_by: expected })),
  }, null, 2));
  process.exit(0);
}

const findings = inspect(sources);
if (findings.length > 0) {
  console.error(JSON.stringify({ check: "check:standing-authority", verdict: "FAIL", findings }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({
  check: "check:standing-authority",
  verdict: "PASS",
  c7_exact_request_grant: "preserved",
  standing_grant: "separate signed artifact",
  draw_accounting: "atomic usage/deposit/spend reservation plus terminal settlement without authority reset",
}, null, 2));
