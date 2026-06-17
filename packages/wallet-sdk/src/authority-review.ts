import {
  APPROVAL_MODES,
  type ApprovalMode,
  type AuthorityReview,
  type AuthorityRiskClass,
  type CandidateEvidence,
  type PolicyCheck,
  type PolicyResult,
  WALLET_PROTOCOL_SCHEMA_VERSION,
} from "@ioi/wallet-protocol";

export interface BuildAuthorityReviewInput {
  readonly review_id: string;
  readonly initiator_id: string;
  readonly account_id: string;
  readonly intent_ref: string;
  readonly action_summary: string;
  readonly requested_scopes: readonly string[];
  readonly approval_mode?: ApprovalMode;
  readonly risk_class: AuthorityRiskClass;
  readonly risk_labels?: readonly string[];
  readonly eligibility_labels?: readonly string[];
  readonly candidate_evidence?: readonly CandidateEvidence[];
  readonly policy_checks?: readonly PolicyCheck[];
  readonly policy_result?: PolicyResult;
  readonly simulation_ref?: string;
  readonly receipt_preview_ref: string;
  readonly expires_at: string;
}

export function isApprovalMode(value: string): value is ApprovalMode {
  return APPROVAL_MODES.includes(value as ApprovalMode);
}

export function assertWalletScope(scope: string): string {
  if (!scope.startsWith("scope:")) {
    throw new Error(`wallet capability scopes must preserve the scope: prefix: ${scope}`);
  }

  return scope;
}

export function buildAuthorityReview(
  input: BuildAuthorityReviewInput,
): AuthorityReview {
  const requested_scopes = input.requested_scopes.map(assertWalletScope);

  return {
    review_id: input.review_id,
    schema_version: WALLET_PROTOCOL_SCHEMA_VERSION,
    initiator_id: input.initiator_id,
    account_id: input.account_id,
    intent_ref: input.intent_ref,
    action_summary: input.action_summary,
    requested_scopes,
    approval_mode: input.approval_mode ?? "one_shot_review",
    risk_class: input.risk_class,
    risk_labels: input.risk_labels ?? [],
    eligibility_labels: input.eligibility_labels ?? [],
    candidate_evidence: input.candidate_evidence ?? [],
    policy_checks: input.policy_checks ?? [],
    policy_result: input.policy_result ?? "requires_human",
    simulation_ref: input.simulation_ref,
    receipt_preview_ref: input.receipt_preview_ref,
    expires_at: input.expires_at,
  };
}

export function summarizeAuthorityReview(review: AuthorityReview): string {
  const labels =
    review.risk_labels.length > 0 ? review.risk_labels.join(", ") : "No labels";

  return `${review.action_summary} (${review.policy_result}; ${labels})`;
}
