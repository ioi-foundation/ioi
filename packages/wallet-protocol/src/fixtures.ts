import {
  type AuthorityReview,
  type CapabilityLease,
  type ExchangeIntent,
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
