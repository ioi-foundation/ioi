export const WALLET_PROTOCOL_SCHEMA_VERSION = "ioi.wallet.protocol.v1" as const;

export const APPROVAL_MODES = [
  "one_shot_review",
  "session_envelope",
  "batch_review",
  "silent_within_policy",
  "after_the_fact_receipt",
  "step_up_review",
  "denied",
] as const;

export type ApprovalMode = (typeof APPROVAL_MODES)[number];

export const AUTHORITY_RISK_CLASSES = [
  "read",
  "draft",
  "external_message",
  "commerce",
  "funds",
  "trade",
  "policy_widening",
  "secret_export",
  "declassification",
  "identity_change",
  "cloud_deploy",
  "physical_action",
] as const;

export type AuthorityRiskClass = (typeof AUTHORITY_RISK_CLASSES)[number];

export const RISK_COVERAGE_STATES = [
  "assessed",
  "unknown",
  "unassessed",
  "stale",
  "conflicting_sources",
] as const;

export type RiskCoverageState = (typeof RISK_COVERAGE_STATES)[number];

export type PolicyCheckResult =
  | "passed"
  | "failed"
  | "warning"
  | "not_applicable";

export type PolicyResult =
  | "approved"
  | "blocked"
  | "requires_step_up"
  | "requires_human"
  | "requires_policy_change";

export type ReceiptType =
  | "send"
  | "receive"
  | "exchange"
  | "trade"
  | "prediction"
  | "approval"
  | "delegation"
  | "revocation"
  | "agent_action"
  | "step_up"
  | "secret_execution"
  | "declassification"
  | "risk_event"
  | "protection"
  | "policy_change"
  | "cloud_execution";

export interface MoneyAmount {
  readonly asset: string;
  readonly amount: string;
  readonly chain?: string;
}

export interface BudgetEnvelope {
  readonly limit: MoneyAmount;
  readonly window: "single_action" | "hour" | "day" | "week" | "month";
}

export interface CandidateEvidence {
  readonly candidate_id: string;
  readonly source: string;
  readonly adapter_id: string;
  readonly observed_at: string;
  readonly expires_at?: string;
  readonly coverage_state: RiskCoverageState;
  readonly evidence_refs: readonly string[];
  readonly risk_labels: readonly string[];
  readonly claims: Readonly<Record<string, string>>;
}

export interface PolicyCheck {
  readonly check_id: string;
  readonly result: PolicyCheckResult;
  readonly explanation: string;
  readonly safer_alternative?: string;
}

export interface AuthorityReview {
  readonly review_id: string;
  readonly schema_version: typeof WALLET_PROTOCOL_SCHEMA_VERSION;
  readonly initiator_id: string;
  readonly account_id: string;
  readonly intent_ref: string;
  readonly action_summary: string;
  readonly requested_scopes: readonly string[];
  readonly approval_mode: ApprovalMode;
  readonly risk_class: AuthorityRiskClass;
  readonly risk_labels: readonly string[];
  readonly eligibility_labels: readonly string[];
  readonly candidate_evidence: readonly CandidateEvidence[];
  readonly policy_checks: readonly PolicyCheck[];
  readonly policy_result: PolicyResult;
  readonly simulation_ref?: string;
  readonly receipt_preview_ref: string;
  readonly expires_at: string;
}

export interface CapabilityLease {
  readonly lease_id: string;
  readonly subject_id: string;
  readonly holder_id: string;
  readonly capability_scope: string;
  readonly mode: ApprovalMode;
  readonly budget?: BudgetEnvelope;
  readonly policy_hash: string;
  readonly grant_ref?: string;
  readonly revocation_epoch: number;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly revoked_at?: string;
  readonly receipt_refs: readonly string[];
}

export interface ExchangeIntent {
  readonly intent_id: string;
  readonly schema_version: typeof WALLET_PROTOCOL_SCHEMA_VERSION;
  readonly initiator_id: string;
  readonly account_id: string;
  readonly from_asset: MoneyAmount;
  readonly to_asset: string;
  readonly min_amount_out: MoneyAmount;
  readonly route_candidate_id: string;
  readonly slippage_bps: number;
  readonly policy_hash: string;
  readonly risk_labels: readonly string[];
  readonly simulation_hash: string;
  readonly tx_intent_refs: readonly string[];
}

export interface TradeIntent {
  readonly intent_id: string;
  readonly schema_version: typeof WALLET_PROTOCOL_SCHEMA_VERSION;
  readonly initiator_id: string;
  readonly account_id: string;
  readonly venue_candidate_id: string;
  readonly market: string;
  readonly side: "buy" | "sell" | "long" | "short";
  readonly collateral: MoneyAmount;
  readonly leverage?: string;
  readonly margin_mode?: "isolated" | "cross";
  readonly max_loss?: MoneyAmount;
  readonly policy_hash: string;
  readonly risk_labels: readonly string[];
  readonly simulation_hash?: string;
}

export interface WalletReceipt {
  readonly receipt_id: string;
  readonly receipt_type: ReceiptType;
  readonly schema_version: typeof WALLET_PROTOCOL_SCHEMA_VERSION;
  readonly initiator_id: string;
  readonly account_id: string;
  readonly action_summary: string;
  readonly request_hash: string;
  readonly policy_hash: string;
  readonly grant_id?: string;
  readonly lease_id?: string;
  readonly revocation_epoch: number;
  readonly risk_labels: readonly string[];
  readonly policy_checks: readonly PolicyCheck[];
  readonly candidate_evidence: readonly CandidateEvidence[];
  readonly execution_refs: readonly string[];
  readonly agentgres_ref?: string;
  readonly ioi_commitment?: string;
  readonly created_at: string;
  readonly signatures: readonly string[];
}
