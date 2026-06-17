import {
  type ApprovalMode,
  type BudgetEnvelope,
  type CapabilityLease,
} from "@ioi/wallet-protocol";
import { assertWalletScope } from "./authority-review.js";

export interface BuildCapabilityLeaseInput {
  readonly lease_id: string;
  readonly subject_id: string;
  readonly holder_id: string;
  readonly capability_scope: string;
  readonly mode?: ApprovalMode;
  readonly budget?: BudgetEnvelope;
  readonly policy_hash: string;
  readonly grant_ref?: string;
  readonly revocation_epoch: number;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly receipt_refs?: readonly string[];
}

export function buildCapabilityLease(
  input: BuildCapabilityLeaseInput,
): CapabilityLease {
  return {
    lease_id: input.lease_id,
    subject_id: input.subject_id,
    holder_id: input.holder_id,
    capability_scope: assertWalletScope(input.capability_scope),
    mode: input.mode ?? "session_envelope",
    budget: input.budget,
    policy_hash: input.policy_hash,
    grant_ref: input.grant_ref,
    revocation_epoch: input.revocation_epoch,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    receipt_refs: input.receipt_refs ?? [],
  };
}
