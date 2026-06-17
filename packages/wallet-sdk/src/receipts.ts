import {
  type CandidateEvidence,
  type PolicyCheck,
  type ReceiptType,
  type WalletReceipt,
  WALLET_PROTOCOL_SCHEMA_VERSION,
} from "@ioi/wallet-protocol";

export interface BuildWalletReceiptInput {
  readonly receipt_id: string;
  readonly receipt_type: ReceiptType;
  readonly initiator_id: string;
  readonly account_id: string;
  readonly action_summary: string;
  readonly request_hash: string;
  readonly policy_hash: string;
  readonly grant_id?: string;
  readonly lease_id?: string;
  readonly revocation_epoch: number;
  readonly risk_labels?: readonly string[];
  readonly policy_checks?: readonly PolicyCheck[];
  readonly candidate_evidence?: readonly CandidateEvidence[];
  readonly execution_refs?: readonly string[];
  readonly agentgres_ref?: string;
  readonly ioi_commitment?: string;
  readonly created_at: string;
  readonly signatures?: readonly string[];
}

export function buildWalletReceipt(input: BuildWalletReceiptInput): WalletReceipt {
  return {
    receipt_id: input.receipt_id,
    receipt_type: input.receipt_type,
    schema_version: WALLET_PROTOCOL_SCHEMA_VERSION,
    initiator_id: input.initiator_id,
    account_id: input.account_id,
    action_summary: input.action_summary,
    request_hash: input.request_hash,
    policy_hash: input.policy_hash,
    grant_id: input.grant_id,
    lease_id: input.lease_id,
    revocation_epoch: input.revocation_epoch,
    risk_labels: input.risk_labels ?? [],
    policy_checks: input.policy_checks ?? [],
    candidate_evidence: input.candidate_evidence ?? [],
    execution_refs: input.execution_refs ?? [],
    agentgres_ref: input.agentgres_ref,
    ioi_commitment: input.ioi_commitment,
    created_at: input.created_at,
    signatures: input.signatures ?? [],
  };
}
