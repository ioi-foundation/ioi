import {
  humanizeOperatorNotificationValue,
  isLocalEngineIntervention,
  isResolvedAssistant,
  isResolvedIntervention,
} from "./operatorNotifications";
import type {
  AssistantNotificationRecord,
  InterventionRecord,
  NotificationSeverity,
} from "../types";

export type InboxLane =
  | "all"
  | "needs_action"
  | "ready_for_review"
  | "monitor"
  | "digests"
  | "resolved";

type QueueItemType =
  | "Approval"
  | "Clarification"
  | "Result"
  | "Anomaly"
  | "Digest"
  | "Escalation";

export interface InboxQueueItem {
  key: string;
  lane: Exclude<InboxLane, "all">;
  kind: "assistant" | "intervention";
  typeLabel: QueueItemType;
  record: AssistantNotificationRecord | InterventionRecord;
  sourceLabel: string;
  statusLabel: string;
  meta: string[];
}

export interface InboxSummaryCounts {
  needsAction: number;
  localEngine: number;
  readyForReview: number;
  anomalies: number;
  resolvedToday: number;
}

export const INBOX_LANES: Array<{
  id: InboxLane;
  label: string;
  description: string;
}> = [
  { id: "all", label: "All", description: "Everything in the queue" },
  { id: "needs_action", label: "Needs action", description: "Blocked on you" },
  {
    id: "ready_for_review",
    label: "Ready for review",
    description: "Completed or prepared",
  },
  { id: "monitor", label: "Monitor", description: "Risk, drift, or anomalies" },
  {
    id: "digests",
    label: "Digests",
    description: "Summaries and batched updates",
  },
  { id: "resolved", label: "Resolved", description: "Handled or archived" },
];

const SEVERITY_ORDER: Record<NotificationSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

function compareRecords(
  left: {
    severity: NotificationSeverity;
    dueAtMs?: number | null;
    updatedAtMs: number;
  },
  right: {
    severity: NotificationSeverity;
    dueAtMs?: number | null;
    updatedAtMs: number;
  },
): number {
  const severityDelta =
    SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
  if (severityDelta !== 0) return severityDelta;

  const leftDue = left.dueAtMs ?? Number.MAX_SAFE_INTEGER;
  const rightDue = right.dueAtMs ?? Number.MAX_SAFE_INTEGER;
  if (leftDue !== rightDue) return leftDue - rightDue;

  return right.updatedAtMs - left.updatedAtMs;
}

function interventionTypeLabel(item: InterventionRecord): QueueItemType {
  switch (item.interventionType) {
    case "approval_gate":
    case "pii_review_gate":
      return "Approval";
    case "clarification_gate":
    case "credential_gate":
    case "decision_gate":
      return "Clarification";
    case "intervention_outcome":
      return "Result";
    case "reauth_gate":
      return "Escalation";
    default:
      return "Escalation";
  }
}

function interventionLane(item: InterventionRecord): Exclude<InboxLane, "all"> {
  if (isResolvedIntervention(item.status)) return "resolved";

  switch (item.interventionType) {
    case "intervention_outcome":
      return item.blocking ? "needs_action" : "ready_for_review";
    default:
      return "needs_action";
  }
}

function assistantTypeLabel(item: AssistantNotificationRecord): QueueItemType {
  switch (item.notificationClass) {
    case "digest":
      return "Digest";
    case "valuable_completion":
    case "meeting_prep":
    case "automation_opportunity":
      return "Result";
    case "auth_attention":
    case "stalled_workflow":
      return "Escalation";
    case "deadline_risk":
    case "follow_up_risk":
    case "habitual_friction":
    default:
      return "Anomaly";
  }
}

function assistantLane(
  item: AssistantNotificationRecord,
): Exclude<InboxLane, "all"> {
  if (isResolvedAssistant(item.status)) return "resolved";

  switch (item.notificationClass) {
    case "digest":
      return "digests";
    case "valuable_completion":
    case "meeting_prep":
    case "automation_opportunity":
      return "ready_for_review";
    case "auth_attention":
    case "stalled_workflow":
      return "needs_action";
    case "deadline_risk":
    case "follow_up_risk":
    case "habitual_friction":
    default:
      return "monitor";
  }
}

export function buildInterventionQueueItem(
  item: InterventionRecord,
): InboxQueueItem {
  const meta: string[] = [];

  if (item.blocking) meta.push("Blocking");
  if (isLocalEngineIntervention(item)) meta.push("Kernel-managed");
  if (item.approvalScope) {
    meta.push(humanizeOperatorNotificationValue(item.approvalScope));
  }
  if (item.workflowId) meta.push(`Workflow ${item.workflowId}`);
  if (item.runId) meta.push(`Run ${item.runId}`);

  return {
    key: `intervention:${item.itemId}`,
    kind: "intervention",
    lane: interventionLane(item),
    typeLabel: interventionTypeLabel(item),
    record: item,
    sourceLabel: isLocalEngineIntervention(item)
      ? "Local Engine"
      : item.source.serviceName,
    statusLabel: humanizeOperatorNotificationValue(item.status),
    meta,
  };
}

export function buildAssistantQueueItem(
  item: AssistantNotificationRecord,
): InboxQueueItem {
  const meta: string[] = [];

  meta.push(`Priority ${(item.priorityScore * 100).toFixed(0)}%`);
  meta.push(`Confidence ${(item.confidenceScore * 100).toFixed(0)}%`);
  if (item.workflowId) meta.push(`Workflow ${item.workflowId}`);
  if (item.runId) meta.push(`Run ${item.runId}`);

  return {
    key: `assistant:${item.itemId}`,
    kind: "assistant",
    lane: assistantLane(item),
    typeLabel: assistantTypeLabel(item),
    record: item,
    sourceLabel: item.source.serviceName,
    statusLabel: humanizeOperatorNotificationValue(item.status),
    meta,
  };
}

export function buildInboxQueueItems(
  interventions: InterventionRecord[],
  assistantNotifications: AssistantNotificationRecord[],
): InboxQueueItem[] {
  return [
    ...interventions.map(buildInterventionQueueItem),
    ...assistantNotifications.map(buildAssistantQueueItem),
  ].sort((left, right) => compareRecords(left.record, right.record));
}

export function getInboxLaneCounts(
  queueItems: InboxQueueItem[],
): Record<InboxLane, number> {
  return {
    all: queueItems.length,
    needs_action: queueItems.filter((item) => item.lane === "needs_action").length,
    ready_for_review: queueItems.filter((item) => item.lane === "ready_for_review")
      .length,
    monitor: queueItems.filter((item) => item.lane === "monitor").length,
    digests: queueItems.filter((item) => item.lane === "digests").length,
    resolved: queueItems.filter((item) => item.lane === "resolved").length,
  };
}

export function getInboxSummaryCounts(
  queueItems: InboxQueueItem[],
  now = new Date(),
): InboxSummaryCounts {
  const startOfToday = new Date(now);
  startOfToday.setHours(0, 0, 0, 0);
  const startOfTodayMs = startOfToday.getTime();

  return {
    needsAction: queueItems.filter((item) => item.lane === "needs_action")
      .length,
    localEngine: queueItems.filter(
      (item) =>
        item.kind === "intervention" &&
        isLocalEngineIntervention(item.record as InterventionRecord) &&
        item.lane !== "resolved",
    ).length,
    readyForReview: queueItems.filter(
      (item) => item.lane === "ready_for_review",
    ).length,
    anomalies: queueItems.filter((item) => item.lane === "monitor").length,
    resolvedToday: queueItems.filter(
      (item) =>
        item.lane === "resolved" && item.record.updatedAtMs >= startOfTodayMs,
    ).length,
  };
}

export function filterInboxQueueItems(
  queueItems: InboxQueueItem[],
  activeLane: InboxLane,
  searchDraft: string,
): InboxQueueItem[] {
  const query = searchDraft.trim().toLowerCase();

  return queueItems.filter((item) => {
    if (activeLane !== "all" && item.lane !== activeLane) {
      return false;
    }

    if (!query) return true;

    const haystack = [
      item.typeLabel,
      item.record.title,
      item.record.summary,
      item.record.reason ?? "",
      item.record.recommendedAction ?? "",
      item.record.source.serviceName,
      item.record.workflowId ?? "",
      item.record.runId ?? "",
    ]
      .join(" ")
      .toLowerCase();

    return haystack.includes(query);
  });
}
