import type { SessionHookSnapshot } from "../../../types";

export type HookControlTone = "ready" | "setup" | "attention";
export type HookControlRecommendedView = "permissions" | "plugins" | null;

export interface HookControlOverview {
  tone: HookControlTone;
  statusLabel: string;
  statusDetail: string;
  meta: string[];
  recommendedView: HookControlRecommendedView;
  recommendedActionLabel: string | null;
}

export function buildHookControlOverview(
  snapshot: SessionHookSnapshot | null,
): HookControlOverview {
  const activeHookCount = snapshot?.activeHookCount ?? 0;
  const disabledHookCount = snapshot?.disabledHookCount ?? 0;
  const runtimeReceiptCount = snapshot?.runtimeReceiptCount ?? 0;
  const approvalReceiptCount = snapshot?.approvalReceiptCount ?? 0;
  const trackedHookCount = snapshot?.hooks.length ?? 0;
  const meta = [
    `${activeHookCount} active`,
    `${disabledHookCount} disabled`,
    `${runtimeReceiptCount} runtime receipts`,
    `${approvalReceiptCount} approval receipts`,
  ];

  if (!snapshot || trackedHookCount === 0) {
    return {
      tone: "setup",
      statusLabel: "No hook sources retained",
      statusDetail:
        "Enable or install a hook-contributing source before expecting runtime automation or approval-aware hook receipts in this session.",
      meta,
      recommendedView: "plugins",
      recommendedActionLabel: "Manage Plugins",
    };
  }

  if (approvalReceiptCount > 0) {
    return {
      tone: "attention",
      statusLabel: "Approval-sensitive automation active",
      statusDetail:
        "Recent approval-memory receipts are actively shaping hook behavior, so permissions should be reviewed alongside the live hook surface.",
      meta,
      recommendedView: "permissions",
      recommendedActionLabel: "Review Permissions",
    };
  }

  if (disabledHookCount > 0) {
    return {
      tone: "setup",
      statusLabel: "Some hooks are disabled",
      statusDetail:
        "Tracked hook sources exist, but runtime automation coverage is partial until the disabled hook contributions are reviewed.",
      meta,
      recommendedView: "plugins",
      recommendedActionLabel: "Review disabled hooks",
    };
  }

  if (runtimeReceiptCount === 0) {
    return {
      tone: "setup",
      statusLabel: "Hooks loaded, awaiting live activity",
      statusDetail:
        "Runtime-visible hooks are present, but no recent runtime or approval receipts have been retained for this session yet.",
      meta,
      recommendedView: null,
      recommendedActionLabel: null,
    };
  }

  return {
    tone: "ready",
    statusLabel: "Hooks active and reporting",
    statusDetail:
      "Runtime-visible hooks and retained receipts are aligned for the active session context.",
    meta,
    recommendedView: null,
    recommendedActionLabel: null,
  };
}
