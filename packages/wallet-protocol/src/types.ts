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

export const WALLET_PRESENTATION_PROFILES = [
  "lite_approval_card",
  "standard_wallet_review",
  "advanced_authority_console",
  "cli_prompt",
  "mobile_approval_sheet",
] as const;

export type WalletPresentationProfile =
  (typeof WALLET_PRESENTATION_PROFILES)[number];

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
  readonly expires_at: string;
  readonly coverage_state: RiskCoverageState;
  readonly evidence_refs: readonly string[];
  readonly risk_labels: readonly string[];
  readonly claims: Readonly<Record<string, string>>;
}

export type CandidateSourceDomain = "exchange" | "trade";

export interface WalletCandidateSourceAdapter {
  readonly adapter_id: string;
  readonly source: string;
  readonly domain: CandidateSourceDomain;
  readonly candidate_kind:
    | "route_candidate"
    | "venue_candidate"
    | "market_candidate"
    | "prediction_candidate";
  readonly trust_boundary: "candidate_source_only";
  readonly evidence_policy: "claims_plus_refs_required";
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
  readonly allowed_approval_modes: readonly ApprovalMode[];
  readonly recommended_presentation_profile: WalletPresentationProfile;
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

export interface CapabilityLeaseRevocation {
  readonly revocation_id: string;
  readonly schema_version: typeof WALLET_PROTOCOL_SCHEMA_VERSION;
  readonly lease_id: string;
  readonly initiator_id: string;
  readonly holder_id: string;
  readonly capability_scope: string;
  readonly policy_hash: string;
  readonly revocation_epoch: number;
  readonly revoked_at: string;
  readonly reason?: string;
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
  readonly candidate_evidence: readonly CandidateEvidence[];
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
  readonly candidate_evidence: readonly CandidateEvidence[];
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

/** Canonical byte-array representation used by the Rust wallet.network ABI. */
export type WalletProtocolBytes = readonly number[];

/** The authority family currently bindable to a portable principal. */
export type PrincipalAuthorityKind = "approval";

/** Lifecycle state carried by each immutable binding version. */
export type PrincipalAuthorityBindingStatus = "active" | "revoked";

/** Root-signed immutable statement for one principal-authority binding version. */
export interface PrincipalAuthorityBindingStatementV1 {
  readonly schema_version: 1;
  readonly principal_ref: string;
  readonly authority_kind: PrincipalAuthorityKind;
  readonly binding_version: number;
  readonly status: PrincipalAuthorityBindingStatus;
  readonly authority_id: WalletProtocolBytes;
  readonly authority_public_key: WalletProtocolBytes;
  readonly authority_signature_suite: number;
  readonly approval_authority_snapshot_hash: WalletProtocolBytes;
  readonly previous_binding_ref?: string;
  readonly previous_binding_hash?: WalletProtocolBytes;
  readonly signed_at_ms: number;
  readonly expires_at_ms?: number;
  readonly issuer_root_account_id: WalletProtocolBytes;
  readonly reason?: string;
}

/** Cryptographic proof emitted by the wallet control root. */
export interface WalletSignatureProof {
  readonly suite: number;
  readonly public_key: WalletProtocolBytes;
  readonly signature: WalletProtocolBytes;
}

/** Complete immutable proof for one principal-authority binding version. */
export interface PrincipalAuthorityBindingProofV1 {
  readonly schema_version: 1;
  readonly statement: PrincipalAuthorityBindingStatementV1;
  readonly statement_hash: WalletProtocolBytes;
  readonly issuer_signature_proof: WalletSignatureProof;
  readonly binding_ref: string;
  readonly binding_hash: WalletProtocolBytes;
}

/** Stable coordinates retained by governed intents for exact boot-time replay. */
export interface PrincipalAuthorityBindingCoordinates {
  readonly binding_ref: string;
  readonly binding_version: number;
  readonly binding_hash: WalletProtocolBytes;
}

/** Mutable current-head pointer over append-only immutable binding proofs. */
export interface PrincipalAuthorityBindingHeadV1 {
  readonly schema_version: 1;
  readonly principal_ref: string;
  readonly authority_kind: PrincipalAuthorityKind;
  readonly coordinates: PrincipalAuthorityBindingCoordinates;
  readonly status: PrincipalAuthorityBindingStatus;
  readonly updated_at_ms: number;
  readonly mutation_audit_seq: number;
  readonly mutation_audit_event_id: WalletProtocolBytes;
  readonly mutation_audit_event_hash: WalletProtocolBytes;
}

/** Verified resolution result returned for a portable principal. */
export interface PrincipalAuthorityResolutionV1 {
  readonly schema_version: 1;
  readonly principal_ref: string;
  readonly authority_kind: PrincipalAuthorityKind;
  readonly coordinates: PrincipalAuthorityBindingCoordinates;
  readonly required_scope: string;
  readonly matched_scope: string;
  readonly approval_authority: ApprovalAuthoritySnapshot;
  readonly authority_id: WalletProtocolBytes;
  readonly authority_public_key: WalletProtocolBytes;
  readonly authority_signature_suite: number;
  readonly approval_authority_snapshot_hash: WalletProtocolBytes;
  readonly resolved_at_ms: number;
  readonly mutation_audit_event_id: WalletProtocolBytes;
  readonly mutation_audit_event_hash: WalletProtocolBytes;
}

export interface IssuePrincipalAuthorityBindingParams {
  readonly proof: PrincipalAuthorityBindingProofV1;
}

export interface RevokePrincipalAuthorityBindingParams {
  readonly predecessor_binding_ref: string;
  readonly proof: PrincipalAuthorityBindingProofV1;
}

export interface ResolvePrincipalAuthorityParams {
  readonly request_id: WalletProtocolBytes;
  readonly principal_ref: string;
  readonly authority_kind: PrincipalAuthorityKind;
  readonly required_scope: string;
  readonly expected_coordinates?: PrincipalAuthorityBindingCoordinates;
}

export interface PrincipalAuthorityResolutionReceipt {
  readonly request_id: WalletProtocolBytes;
  readonly resolved_at_ms: number;
  readonly resolution: PrincipalAuthorityResolutionV1;
}

export interface LookupPrincipalAuthorityBindingParams {
  readonly request_id: WalletProtocolBytes;
  readonly binding_ref: string;
  readonly expected_binding_hash?: WalletProtocolBytes;
}

export interface LookupPrincipalAuthorityBindingReceipt {
  readonly request_id: WalletProtocolBytes;
  readonly fetched_at_ms: number;
  readonly proof: PrincipalAuthorityBindingProofV1;
}

/** Complete ApprovalAuthority registry artifact frozen by the binding snapshot hash. */
export interface ApprovalAuthoritySnapshot {
  readonly schema_version: number;
  readonly authority_id: WalletProtocolBytes;
  readonly public_key: WalletProtocolBytes;
  readonly signature_suite: number;
  readonly expires_at: number;
  readonly revoked: boolean;
  readonly scope_allowlist: readonly string[];
}
