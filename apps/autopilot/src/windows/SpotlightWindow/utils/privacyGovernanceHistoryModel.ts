import type {
  CapabilityGovernanceRequest,
  ShieldApprovalHookReceipt,
  ShieldRememberedApprovalSnapshot,
} from "../../StudioWindow/policyCenter";

export interface PrivacyGovernanceHistoryOverview {
  label: string;
  detail: string;
  recentReceipts: ShieldApprovalHookReceipt[];
}

export function buildPrivacyGovernanceHistoryOverview(input: {
  governanceRequest: CapabilityGovernanceRequest | null;
  rememberedApprovals: ShieldRememberedApprovalSnapshot | null;
}): PrivacyGovernanceHistoryOverview {
  const recentReceipts = input.rememberedApprovals?.recentReceipts.slice(0, 4) ?? [];

  if (input.governanceRequest) {
    return {
      label: "Governance change pending",
      detail:
        input.governanceRequest.detail ||
        input.governanceRequest.headline ||
        "A privacy-relevant governance request is still pending review.",
      recentReceipts,
    };
  }

  if (recentReceipts.length > 0) {
    return {
      label: "Recent governance review retained",
      detail:
        "Remembered approvals, scope misses, expiries, and revocations stay attached to the privacy surface so export decisions can be reviewed without leaving this drawer.",
      recentReceipts,
    };
  }

  return {
    label: "No recent governance review retained",
    detail:
      "Remembered approvals and privacy-relevant hook receipts will appear here once the runtime retains them for the current shell posture.",
    recentReceipts,
  };
}
