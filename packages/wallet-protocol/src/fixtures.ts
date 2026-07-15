import {
  type AuthorityReview,
  type CapabilityLease,
  type CapabilityLeaseRevocation,
  type ExchangeIntent,
  type LookupPrincipalAuthorityBindingParams,
  type LookupPrincipalAuthorityBindingReceipt,
  type IssuePrincipalAuthorityBindingParams,
  type PrincipalAuthorityBindingProofV1,
  type PrincipalAuthorityResolutionReceipt,
  type ResolvePrincipalAuthorityParams,
  type RevokePrincipalAuthorityBindingParams,
  type TradeIntent,
  type WalletReceipt,
  WALLET_PROTOCOL_SCHEMA_VERSION,
} from "./types.js";
import {
  exchangeRouteSourceAdapter,
  tradeVenueSourceAdapter,
} from "./candidate-source-adapters.js";

export const EXAMPLE_EXCHANGE_ROUTE_SOURCE_ADAPTER = exchangeRouteSourceAdapter({
  adapter_id: "adapter:direct-pool-v1",
  source: "decentralized.exchange",
});

export const EXAMPLE_TRADE_VENUE_SOURCE_ADAPTER = tradeVenueSourceAdapter({
  adapter_id: "adapter:paper-perps-v1",
  source: "decentralized.trade",
});

export const EXAMPLE_CANDIDATE_EVIDENCE = {
  candidate_id: "route:example-low-risk-usdc-eth",
  source: EXAMPLE_EXCHANGE_ROUTE_SOURCE_ADAPTER.source,
  adapter_id: EXAMPLE_EXCHANGE_ROUTE_SOURCE_ADAPTER.adapter_id,
  observed_at: "2026-06-17T00:00:00.000Z",
  expires_at: "2026-06-17T00:01:00.000Z",
  coverage_state: "assessed",
  evidence_refs: ["agentgres://evidence/wallet-route-example"],
  risk_labels: ["No Bridge", "Known Pool", "Route Risk Low"],
  claims: {
    venue: "direct-pool",
    simulation_hash: "hash:simulation-example",
  },
} as const;

export const EXAMPLE_TRADE_CANDIDATE_EVIDENCE = {
  candidate_id: "venue:paper-perps",
  source: EXAMPLE_TRADE_VENUE_SOURCE_ADAPTER.source,
  adapter_id: EXAMPLE_TRADE_VENUE_SOURCE_ADAPTER.adapter_id,
  observed_at: "2026-06-17T00:00:00.000Z",
  expires_at: "2026-06-17T00:10:00.000Z",
  coverage_state: "assessed",
  evidence_refs: ["agentgres://evidence/wallet-trade-example"],
  risk_labels: ["Leverage Risk", "Paper Only"],
  claims: {
    venue: "paper-perps",
    simulation_hash: "hash:trade-simulation-example",
  },
} as const;

export const EXAMPLE_AUTHORITY_REVIEW: AuthorityReview = {
  review_id: "review:example-exchange",
  schema_version: WALLET_PROTOCOL_SCHEMA_VERSION,
  initiator_id: "agent:research-assistant",
  account_id: "account:primary",
  intent_ref: "intent:exchange-example",
  action_summary: "Swap 25 USDC to ETH through a no-bridge route.",
  requested_scopes: ["scope:wallet.exchange"],
  approval_mode: "one_shot_review",
  allowed_approval_modes: ["one_shot_review", "step_up_review"],
  recommended_presentation_profile: "standard_wallet_review",
  risk_class: "funds",
  risk_labels: ["No Bridge", "Route Risk Low"],
  eligibility_labels: [],
  candidate_evidence: [EXAMPLE_CANDIDATE_EVIDENCE],
  policy_checks: [
    {
      check_id: "policy:max-single-swap",
      result: "passed",
      explanation: "Requested amount is below the policy cap.",
    },
  ],
  policy_result: "requires_human",
  simulation_ref: "simulation:exchange-example",
  receipt_preview_ref: "receipt-preview:exchange-example",
  expires_at: "2026-06-17T00:05:00.000Z",
};

export const EXAMPLE_CAPABILITY_LEASE: CapabilityLease = {
  lease_id: "lease:example-gmail-send",
  subject_id: "agent:assistant",
  holder_id: "account:primary",
  capability_scope: "scope:gmail.send",
  mode: "session_envelope",
  policy_hash: "hash:policy-example",
  grant_ref: "grant:example",
  revocation_epoch: 3,
  issued_at: "2026-06-17T00:00:00.000Z",
  expires_at: "2026-06-17T01:00:00.000Z",
  receipt_refs: ["receipt:lease-issued-example"],
};

export const EXAMPLE_CAPABILITY_LEASE_REVOCATION: CapabilityLeaseRevocation = {
  revocation_id: "revocation:example-gmail-send",
  schema_version: WALLET_PROTOCOL_SCHEMA_VERSION,
  lease_id: EXAMPLE_CAPABILITY_LEASE.lease_id,
  initiator_id: "user:primary",
  holder_id: EXAMPLE_CAPABILITY_LEASE.holder_id,
  capability_scope: EXAMPLE_CAPABILITY_LEASE.capability_scope,
  policy_hash: EXAMPLE_CAPABILITY_LEASE.policy_hash,
  revocation_epoch: EXAMPLE_CAPABILITY_LEASE.revocation_epoch + 1,
  revoked_at: "2026-06-17T00:30:00.000Z",
  reason: "User revoked the delegated Gmail send capability.",
  receipt_refs: ["receipt:lease-revoked-example"],
};

export const EXAMPLE_EXCHANGE_INTENT: ExchangeIntent = {
  intent_id: "intent:exchange-example",
  schema_version: WALLET_PROTOCOL_SCHEMA_VERSION,
  initiator_id: "agent:research-assistant",
  account_id: "account:primary",
  from_asset: { asset: "USDC", amount: "25", chain: "ethereum" },
  to_asset: "ETH",
  min_amount_out: { asset: "ETH", amount: "0.005", chain: "ethereum" },
  route_candidate_id: "route:example-low-risk-usdc-eth",
  candidate_evidence: [EXAMPLE_CANDIDATE_EVIDENCE],
  slippage_bps: 50,
  policy_hash: "hash:policy-example",
  risk_labels: ["No Bridge", "Route Risk Low"],
  simulation_hash: "hash:simulation-example",
  tx_intent_refs: ["tx:intent-example"],
};

export const EXAMPLE_TRADE_INTENT: TradeIntent = {
  intent_id: "intent:trade-example",
  schema_version: WALLET_PROTOCOL_SCHEMA_VERSION,
  initiator_id: "user:primary",
  account_id: "account:primary",
  venue_candidate_id: "venue:paper-perps",
  candidate_evidence: [EXAMPLE_TRADE_CANDIDATE_EVIDENCE],
  market: "ETH-PERP",
  side: "long",
  collateral: { asset: "USDC", amount: "100", chain: "arbitrum" },
  leverage: "1.5",
  margin_mode: "isolated",
  max_loss: { asset: "USDC", amount: "25", chain: "arbitrum" },
  policy_hash: "hash:policy-example",
  risk_labels: ["Leverage Risk", "Paper Only"],
  simulation_hash: "hash:trade-simulation-example",
};

export const EXAMPLE_WALLET_RECEIPT: WalletReceipt = {
  receipt_id: "receipt:exchange-example",
  receipt_type: "exchange",
  schema_version: WALLET_PROTOCOL_SCHEMA_VERSION,
  initiator_id: "agent:research-assistant",
  account_id: "account:primary",
  action_summary: "Exchange approved and executed.",
  request_hash: "hash:request-example",
  policy_hash: "hash:policy-example",
  lease_id: "lease:example-gmail-send",
  revocation_epoch: 3,
  risk_labels: ["No Bridge", "Route Risk Low"],
  policy_checks: EXAMPLE_AUTHORITY_REVIEW.policy_checks,
  candidate_evidence: [EXAMPLE_CANDIDATE_EVIDENCE],
  execution_refs: ["tx:0xexample"],
  agentgres_ref: "agentgres://operation/wallet-exchange-example",
  created_at: "2026-06-17T00:02:00.000Z",
  signatures: ["sig:hybrid-example"],
};

const exampleBytes32 = (byte: number) =>
  Array.from({ length: 32 }, () => byte);
const bytesFromHex = (hex: string) =>
  Array.from({ length: hex.length / 2 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );

const EXAMPLE_ROOT_PUBLIC_KEY = bytesFromHex(
  "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
);
const EXAMPLE_ROOT_ACCOUNT_ID = bytesFromHex(
  "6dfba71ea8318d9935bb13ae4ac945748a8a1d24aa7009e7f830b19ba01b1fe9",
);
const EXAMPLE_AUTHORITY_PUBLIC_KEY = bytesFromHex(
  "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
);
const EXAMPLE_AUTHORITY_ID = bytesFromHex(
  "db4f41937a0134a86113ca371f212e1671264ca30dc0f2957d44e21a51192cee",
);
const EXAMPLE_AUTHORITY_SNAPSHOT_HASH = bytesFromHex(
  "d009e819160193b7280e7b41952538faa500cdf63f471848db57754c2f424b1f",
);
const EXAMPLE_ACTIVE_BINDING_HASH = bytesFromHex(
  "09e239e362356cd33b08c2052e3c118a9be222aad9734d5f70e127062fe37734",
);
const EXAMPLE_ACTIVE_BINDING_REF =
  "wallet.network://principal-authority-binding/09e239e362356cd33b08c2052e3c118a9be222aad9734d5f70e127062fe37734";
const EXAMPLE_REVOKED_BINDING_HASH = bytesFromHex(
  "fe5aab67f8c918750eed91225c9081760df290c8294e89a09fcd03c6c5131ad7",
);
const EXAMPLE_REVOKED_BINDING_REF =
  "wallet.network://principal-authority-binding/fe5aab67f8c918750eed91225c9081760df290c8294e89a09fcd03c6c5131ad7";

export const EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF: PrincipalAuthorityBindingProofV1 = {
  schema_version: 1,
  statement: {
    schema_version: 1,
    principal_ref: "agentgres://domain/acme.example",
    authority_kind: "approval",
    binding_version: 1,
    status: "active",
    authority_id: EXAMPLE_AUTHORITY_ID,
    authority_public_key: EXAMPLE_AUTHORITY_PUBLIC_KEY,
    authority_signature_suite: -8,
    approval_authority_snapshot_hash: EXAMPLE_AUTHORITY_SNAPSHOT_HASH,
    signed_at_ms: 1_781_286_400_000,
    expires_at_ms: 1_812_822_400_000,
    issuer_root_account_id: EXAMPLE_ROOT_ACCOUNT_ID,
  },
  statement_hash: bytesFromHex(
    "0cd4768791b00098107022562059dc46329729b3e81ea5764bd64635ee07fdd8",
  ),
  issuer_signature_proof: {
    suite: -8,
    public_key: EXAMPLE_ROOT_PUBLIC_KEY,
    signature: bytesFromHex(
      "6f6a13185686751e8005152bf205bec04108efb32b923a5fed3bc7c1ffe510ad86731f05c77d77898574a119e1f623563a698b1968c83b2ad0a9f183ff23c105",
    ),
  },
  binding_ref: EXAMPLE_ACTIVE_BINDING_REF,
  binding_hash: EXAMPLE_ACTIVE_BINDING_HASH,
};

export const EXAMPLE_PRINCIPAL_AUTHORITY_REVOCATION_PROOF: PrincipalAuthorityBindingProofV1 = {
  schema_version: 1,
  statement: {
    ...EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF.statement,
    binding_version: 2,
    status: "revoked",
    previous_binding_ref: EXAMPLE_ACTIVE_BINDING_REF,
    previous_binding_hash: EXAMPLE_ACTIVE_BINDING_HASH,
    signed_at_ms: 1_781_372_800_000,
    expires_at_ms: undefined,
    reason: "Approval authority rotated by the wallet control root.",
  },
  statement_hash: bytesFromHex(
    "415fb07342e20ff3e54082915521fd9bc40eabdbb6b2920c4f5fd0e9c95ed3a0",
  ),
  issuer_signature_proof: {
    suite: -8,
    public_key: EXAMPLE_ROOT_PUBLIC_KEY,
    signature: bytesFromHex(
      "73f5a60b6610debb58c287b4427fd143b35962dd3ff3e3e446004f281a309c8c44d867ec424768f50a72cef3f1f5d9c5cec2a22c3a58c8f5a18c14504b791b0a",
    ),
  },
  binding_ref: EXAMPLE_REVOKED_BINDING_REF,
  binding_hash: EXAMPLE_REVOKED_BINDING_HASH,
};

export const EXAMPLE_ISSUE_PRINCIPAL_AUTHORITY_BINDING_PARAMS: IssuePrincipalAuthorityBindingParams = {
  proof: EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF,
};

export const EXAMPLE_REVOKE_PRINCIPAL_AUTHORITY_BINDING_PARAMS: RevokePrincipalAuthorityBindingParams = {
  predecessor_binding_ref: EXAMPLE_ACTIVE_BINDING_REF,
  proof: EXAMPLE_PRINCIPAL_AUTHORITY_REVOCATION_PROOF,
};

export const EXAMPLE_RESOLVE_PRINCIPAL_AUTHORITY_PARAMS: ResolvePrincipalAuthorityParams = {
  request_id: exampleBytes32(22),
  principal_ref: EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF.statement.principal_ref,
  authority_kind: "approval",
  required_scope: "room_participation.admit",
  expected_coordinates: {
    binding_ref: EXAMPLE_ACTIVE_BINDING_REF,
    binding_version: 1,
    binding_hash: EXAMPLE_ACTIVE_BINDING_HASH,
  },
};

export const EXAMPLE_PRINCIPAL_AUTHORITY_RESOLUTION_RECEIPT: PrincipalAuthorityResolutionReceipt = {
  request_id: EXAMPLE_RESOLVE_PRINCIPAL_AUTHORITY_PARAMS.request_id,
  resolved_at_ms: 1_781_286_400_100,
  resolution: {
    schema_version: 1,
    principal_ref: EXAMPLE_RESOLVE_PRINCIPAL_AUTHORITY_PARAMS.principal_ref,
    authority_kind: "approval",
    coordinates: EXAMPLE_RESOLVE_PRINCIPAL_AUTHORITY_PARAMS.expected_coordinates!,
    required_scope: EXAMPLE_RESOLVE_PRINCIPAL_AUTHORITY_PARAMS.required_scope,
    matched_scope: "room_participation.admit",
    approval_authority: {
      schema_version: 1,
      authority_id: EXAMPLE_AUTHORITY_ID,
      public_key: EXAMPLE_AUTHORITY_PUBLIC_KEY,
      signature_suite: -8,
      expires_at: 1_900_000_000_000,
      revoked: false,
      scope_allowlist: ["room_participation.admit"],
    },
    authority_id: EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF.statement.authority_id,
    authority_public_key:
      EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF.statement.authority_public_key,
    authority_signature_suite:
      EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF.statement.authority_signature_suite,
    approval_authority_snapshot_hash:
      EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF.statement
        .approval_authority_snapshot_hash,
    resolved_at_ms: 1_781_286_400_100,
    mutation_audit_event_id: exampleBytes32(23),
    mutation_audit_event_hash: exampleBytes32(24),
  },
};

export const EXAMPLE_LOOKUP_PRINCIPAL_AUTHORITY_BINDING_PARAMS: LookupPrincipalAuthorityBindingParams = {
  request_id: exampleBytes32(25),
  binding_ref: EXAMPLE_ACTIVE_BINDING_REF,
  expected_binding_hash: EXAMPLE_ACTIVE_BINDING_HASH,
};

export const EXAMPLE_LOOKUP_PRINCIPAL_AUTHORITY_BINDING_RECEIPT: LookupPrincipalAuthorityBindingReceipt = {
  request_id: EXAMPLE_LOOKUP_PRINCIPAL_AUTHORITY_BINDING_PARAMS.request_id,
  fetched_at_ms: 1_781_286_400_200,
  proof: EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF,
};
