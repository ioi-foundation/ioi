import type { SessionHookSnapshot } from "../../../types";
import type {
  CapabilityGovernanceRequest,
  SessionPermissionProfileId,
  ShieldRememberedApprovalSnapshot,
} from "../../ChatWindow/chatPolicyCenter";

export type AuthorityAutomationTone = "ready" | "review" | "setup";
export type AuthorityAutomationActionKind =
  | "apply_profile"
  | "review_permissions"
  | "review_hooks"
  | "none";

export interface AuthorityAutomationPlan {
  tone: AuthorityAutomationTone;
  statusLabel: string;
  detail: string;
  actionKind: AuthorityAutomationActionKind;
  recommendedProfileId: SessionPermissionProfileId | null;
  recommendedView: "permissions" | "hooks" | null;
  primaryActionLabel: string | null;
  checklist: string[];
}

export interface BuildAuthorityAutomationPlanInput {
  currentProfileId: SessionPermissionProfileId | null;
  hookSnapshot: SessionHookSnapshot | null;
  rememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  governanceRequest: CapabilityGovernanceRequest | null;
  activeOverrideCount: number;
}

export function buildAuthorityAutomationPlan(
  input: BuildAuthorityAutomationPlanInput,
): AuthorityAutomationPlan {
  const activeHookCount = input.hookSnapshot?.activeHookCount ?? 0;
  const disabledHookCount = input.hookSnapshot?.disabledHookCount ?? 0;
  const runtimeReceiptCount = input.hookSnapshot?.runtimeReceiptCount ?? 0;
  const approvalReceiptCount = input.hookSnapshot?.approvalReceiptCount ?? 0;
  const rememberedDecisionCount =
    input.rememberedApprovals?.activeDecisionCount ?? 0;
  const recentApprovalReceiptCount =
    input.rememberedApprovals?.recentReceiptCount ?? 0;
  const checklist = [
    `${activeHookCount} active hooks`,
    `${approvalReceiptCount} approval receipts`,
    `${rememberedDecisionCount} remembered approvals`,
    `${input.activeOverrideCount} connector overrides`,
  ];

  if (!input.hookSnapshot && !input.rememberedApprovals && !input.governanceRequest) {
    return {
      tone: "setup",
      statusLabel: "Authority automation waiting on runtime posture",
      detail:
        "Load hook and approval-memory posture before the shell can recommend a profile change or authority review path.",
      actionKind: "none",
      recommendedProfileId: null,
      recommendedView: null,
      primaryActionLabel: null,
      checklist,
    };
  }

  if (input.governanceRequest || approvalReceiptCount > 0) {
    if (input.currentProfileId !== "safer_review") {
      return {
        tone: "review",
        statusLabel: "Safer review profile recommended",
        detail:
          "Live approval-sensitive automation is active, so tightening the session baseline to Safer review is the safest next authority move before widening anything else.",
        actionKind: "apply_profile",
        recommendedProfileId: "safer_review",
        recommendedView: "permissions",
        primaryActionLabel: "Apply Safer review",
        checklist,
      };
    }

    return {
      tone: "review",
      statusLabel: "Authority review should stay in focus",
      detail:
        "The session is already on Safer review while approval-sensitive automation is active, so the next step is to inspect permissions rather than widen the baseline.",
      actionKind: "review_permissions",
      recommendedProfileId: null,
      recommendedView: "permissions",
      primaryActionLabel: "Review session permissions",
      checklist,
    };
  }

  if (
    input.currentProfileId === "safer_review" &&
    activeHookCount > 0 &&
    runtimeReceiptCount > 0 &&
    rememberedDecisionCount > 0
  ) {
    return {
      tone: "ready",
      statusLabel: "Guided default can resume",
      detail:
        "Hooks are active, runtime receipts are flowing, and remembered approvals already cover repeated work, so the session can move from Safer review back to Guided default without losing governance.",
      actionKind: "apply_profile",
      recommendedProfileId: "guided_default",
      recommendedView: "permissions",
      primaryActionLabel: "Apply Guided default",
      checklist,
    };
  }

  if (
    input.currentProfileId === "guided_default" &&
    activeHookCount > 1 &&
    runtimeReceiptCount > 1 &&
    rememberedDecisionCount > 2 &&
    recentApprovalReceiptCount > 0 &&
    input.activeOverrideCount === 0 &&
    disabledHookCount === 0
  ) {
    return {
      tone: "ready",
      statusLabel: "Autonomous profile is now supportable",
      detail:
        "Multiple live hooks, repeated runtime receipts, and remembered approvals are aligned without connector-specific widening, so Autonomous is now a supportable baseline if the operator wants faster execution.",
      actionKind: "apply_profile",
      recommendedProfileId: "autonomous",
      recommendedView: "permissions",
      primaryActionLabel: "Apply Autonomous",
      checklist,
    };
  }

  if (disabledHookCount > 0) {
    return {
      tone: "review",
      statusLabel: "Hook coverage should be reviewed first",
      detail:
        "Some tracked hooks are disabled, so authority changes should stay conservative until the live automation surface is fully understood.",
      actionKind: "review_hooks",
      recommendedProfileId: null,
      recommendedView: "hooks",
      primaryActionLabel: "Review hooks",
      checklist,
    };
  }

  return {
    tone: "ready",
    statusLabel: "Authority automation has no pending change",
    detail:
      "Current hooks, approvals, and profile posture are aligned well enough that the shell does not need to push a profile change right now.",
    actionKind: "none",
    recommendedProfileId: null,
    recommendedView: null,
    primaryActionLabel: null,
    checklist,
  };
}
