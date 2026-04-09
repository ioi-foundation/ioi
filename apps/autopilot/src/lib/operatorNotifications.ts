import { invoke } from "@tauri-apps/api/core";
import type {
  AssistantNotificationRecord,
  AssistantNotificationStatus,
  InterventionRecord,
  NotificationAction,
} from "../types";

export function humanizeOperatorNotificationValue(
  value: string | null | undefined,
): string {
  const normalized = (value || "").trim().replace(/[_:]+/g, " ");
  if (!normalized) return "Unknown";
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

export function isResolvedIntervention(
  status: InterventionRecord["status"],
): boolean {
  return status === "resolved" || status === "expired" || status === "cancelled";
}

export function isResolvedAssistant(
  status: AssistantNotificationRecord["status"],
): boolean {
  return (
    status === "resolved" ||
    status === "dismissed" ||
    status === "expired" ||
    status === "archived"
  );
}

export function isLocalEngineIntervention(item: InterventionRecord): boolean {
  if (item.approvalScope === "model::control") return true;
  const text = [
    item.title,
    item.summary,
    item.reason ?? "",
    item.sensitiveActionType ?? "",
    item.approvalScope ?? "",
    item.recoveryHint ?? "",
  ]
    .join(" ")
    .toLowerCase();
  return (
    text.includes("local engine") ||
    text.includes("model::control") ||
    text.includes("model_registry") ||
    text.includes("model control") ||
    text.includes("backend control") ||
    text.includes("gallery control")
  );
}

export function pickPrimaryAssistantAction(
  item: AssistantNotificationRecord,
): NotificationAction | null {
  return (
    item.actions.find((action) => action.style === "primary") ??
    item.actions.find((action) => action.id === "open_target") ??
    item.actions[0] ??
    null
  );
}

export function displayNotificationActionLabel(
  label: string | null | undefined,
): string {
  if (!label) return "Open";
  if (label === "Open Integrations") return "Open Capabilities";
  if (label === "Open Shield") return "Open Policy";
  return label;
}

type AssistantActionHandlers = {
  onOpenAutopilot: () => void;
  onOpenIntegrations: (connectorId?: string | null) => void;
  onOpenShield: (connectorId?: string | null) => void;
  onOpenSettings: () => void;
  onOpenTarget?: (item: AssistantNotificationRecord) => boolean | void;
};

type RunAssistantNotificationActionOptions = AssistantActionHandlers & {
  item: AssistantNotificationRecord;
  actionId: string;
  updateAssistantStatus: (
    itemId: string,
    status: AssistantNotificationStatus,
    snoozedUntilMs?: number | null,
  ) => Promise<void>;
};

async function markAssistantSeenIfNeeded(
  item: AssistantNotificationRecord,
  updateAssistantStatus: RunAssistantNotificationActionOptions["updateAssistantStatus"],
) {
  if (item.status === "new") {
    await updateAssistantStatus(item.itemId, "seen");
  }
}

export async function runAssistantNotificationAction({
  item,
  actionId,
  updateAssistantStatus,
  onOpenAutopilot,
  onOpenIntegrations,
  onOpenShield,
  onOpenSettings,
  onOpenTarget,
}: RunAssistantNotificationActionOptions): Promise<void> {
  const [action, connectorId, subscriptionId] = actionId.split(":");

  switch (action) {
    case "open_target":
      await markAssistantSeenIfNeeded(item, updateAssistantStatus);
      if (item.target) {
        const handled = onOpenTarget?.(item);
        if (handled !== false) {
          return;
        }
      }
      onOpenAutopilot();
      return;
    case "open_autopilot":
    case "open_task":
    case "view_result":
      await markAssistantSeenIfNeeded(item, updateAssistantStatus);
      onOpenAutopilot();
      return;
    case "open_integrations":
      await markAssistantSeenIfNeeded(item, updateAssistantStatus);
      onOpenIntegrations(connectorId ?? null);
      return;
    case "open_shield":
      await markAssistantSeenIfNeeded(item, updateAssistantStatus);
      onOpenShield(connectorId ?? null);
      return;
    case "open_settings":
      await markAssistantSeenIfNeeded(item, updateAssistantStatus);
      onOpenSettings();
      return;
    case "renew_subscription":
      if (!connectorId || !subscriptionId) {
        throw new Error("Missing subscription target.");
      }
      await invoke("connector_renew_subscription", {
        connectorId,
        connector_id: connectorId,
        subscriptionId,
        subscription_id: subscriptionId,
      });
      await updateAssistantStatus(item.itemId, "resolved");
      onOpenIntegrations(connectorId);
      return;
    case "resume_subscription":
      if (!connectorId || !subscriptionId) {
        throw new Error("Missing subscription target.");
      }
      await invoke("connector_resume_subscription", {
        connectorId,
        connector_id: connectorId,
        subscriptionId,
        subscription_id: subscriptionId,
      });
      await updateAssistantStatus(item.itemId, "resolved");
      onOpenIntegrations(connectorId);
      return;
    case "archive":
      await updateAssistantStatus(item.itemId, "archived");
      return;
    case "dismiss":
      await updateAssistantStatus(item.itemId, "dismissed");
      return;
    case "snooze":
      await updateAssistantStatus(
        item.itemId,
        "snoozed",
        Date.now() + 60 * 60 * 1000,
      );
      return;
    default:
      await markAssistantSeenIfNeeded(item, updateAssistantStatus);
      onOpenAutopilot();
  }
}
