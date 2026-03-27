import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useMemo, useState } from "react";
import { NotificationDetailPanel } from "./NotificationDetailPanel";
import type {
  AssistantNotificationRecord,
  AssistantNotificationStatus,
  AssistantWorkbenchSession,
  InterventionRecord,
  InterventionStatus,
  NotificationAction,
  NotificationSeverity,
} from "../../../types";

interface NotificationsViewProps {
  onOpenAutopilot: () => void;
  onOpenIntegrations: (connectorId?: string | null) => void;
  onOpenLocalEngine: () => void;
  onOpenShield: (connectorId?: string | null) => void;
  onOpenSettings: () => void;
  onOpenReplyComposer: (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => void;
  onOpenMeetingPrep: (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => void;
}

type InboxLane =
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

interface InboxQueueItem {
  key: string;
  lane: Exclude<InboxLane, "all">;
  kind: "assistant" | "intervention";
  typeLabel: QueueItemType;
  record: AssistantNotificationRecord | InterventionRecord;
  sourceLabel: string;
  statusLabel: string;
  meta: string[];
}

const SEVERITY_ORDER: Record<NotificationSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

const INBOX_LANES: Array<{
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

function humanize(value: string): string {
  return value.replace(/::/g, " ").replace(/_/g, " ");
}

function isResolvedIntervention(status: InterventionStatus): boolean {
  return (
    status === "resolved" || status === "expired" || status === "cancelled"
  );
}

function isResolvedAssistant(status: AssistantNotificationStatus): boolean {
  return (
    status === "resolved" ||
    status === "dismissed" ||
    status === "expired" ||
    status === "archived"
  );
}

function upsertById<T extends { itemId: string; updatedAtMs: number }>(
  items: T[],
  next: T,
): T[] {
  const existingIndex = items.findIndex((item) => item.itemId === next.itemId);
  if (existingIndex === -1) {
    return [next, ...items];
  }

  const updated = [...items];
  updated[existingIndex] = next;
  return updated;
}

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

function formatAbsoluteTime(timestampMs?: number | null): string {
  if (!timestampMs) return "No deadline";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestampMs));
}

function formatRelativeTime(timestampMs: number): string {
  const deltaMs = timestampMs - Date.now();
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const minuteMs = 60_000;
  const hourMs = 60 * minuteMs;
  const dayMs = 24 * hourMs;

  if (Math.abs(deltaMs) < hourMs) {
    return formatter.format(Math.round(deltaMs / minuteMs), "minute");
  }
  if (Math.abs(deltaMs) < dayMs) {
    return formatter.format(Math.round(deltaMs / hourMs), "hour");
  }
  return formatter.format(Math.round(deltaMs / dayMs), "day");
}

function dueCopy(dueAtMs?: number | null): string | null {
  if (!dueAtMs) return null;
  return `${formatRelativeTime(dueAtMs)} (${formatAbsoluteTime(dueAtMs)})`;
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

function buildInterventionQueueItem(item: InterventionRecord): InboxQueueItem {
  const meta: string[] = [];

  if (item.blocking) meta.push("Blocking");
  if (isLocalEngineIntervention(item)) meta.push("Kernel-managed");
  if (item.approvalScope) meta.push(humanize(item.approvalScope));
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
    statusLabel: humanize(item.status),
    meta,
  };
}

function buildAssistantQueueItem(
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
    statusLabel: humanize(item.status),
    meta,
  };
}

function pickPrimaryAssistantAction(
  item: AssistantNotificationRecord,
): NotificationAction | null {
  return (
    item.actions.find((action) => action.style === "primary") ??
    item.actions.find((action) => action.id === "open_target") ??
    item.actions[0] ??
    null
  );
}

function displayActionLabel(label: string | null | undefined): string {
  if (!label) return "Open";
  if (label === "Open Integrations") return "Open Capabilities";
  if (label === "Open Shield") return "Open Policy";
  return label;
}

function isLocalEngineIntervention(item: InterventionRecord): boolean {
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

export function NotificationsView({
  onOpenAutopilot,
  onOpenIntegrations,
  onOpenLocalEngine,
  onOpenShield,
  onOpenSettings,
  onOpenReplyComposer,
  onOpenMeetingPrep,
}: NotificationsViewProps) {
  const [interventions, setInterventions] = useState<InterventionRecord[]>([]);
  const [assistantNotifications, setAssistantNotifications] = useState<
    AssistantNotificationRecord[]
  >([]);
  const [searchDraft, setSearchDraft] = useState("");
  const [activeLane, setActiveLane] = useState<InboxLane>("needs_action");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selectedItemKey, setSelectedItemKey] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        setLoading(true);
        const [loadedInterventions, loadedAssistant] = await Promise.all([
          invoke<InterventionRecord[]>("notification_list_interventions"),
          invoke<AssistantNotificationRecord[]>("notification_list_assistant"),
        ]);
        if (cancelled) return;
        setInterventions(loadedInterventions);
        setAssistantNotifications(loadedAssistant);
        setError(null);
      } catch (nextError) {
        if (cancelled) return;
        setError(String(nextError));
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    const listeners = Promise.all([
      listen<InterventionRecord>("intervention-updated", (event) => {
        setInterventions((current) => upsertById(current, event.payload));
      }),
      listen<AssistantNotificationRecord>(
        "assistant-notification-updated",
        (event) => {
          setAssistantNotifications((current) =>
            upsertById(current, event.payload),
          );
        },
      ),
    ]);

    void load();

    return () => {
      cancelled = true;
      void listeners.then((unsubscribers) => {
        unsubscribers.forEach((unsubscribe) => unsubscribe());
      });
    };
  }, []);

  const updateInterventionStatus = async (
    itemId: string,
    status: InterventionStatus,
    snoozedUntilMs?: number | null,
  ) => {
    await invoke("notification_update_intervention_status", {
      itemId,
      item_id: itemId,
      status,
      snoozedUntilMs,
      snoozed_until_ms: snoozedUntilMs,
    });
  };

  const updateAssistantStatus = async (
    itemId: string,
    status: AssistantNotificationStatus,
    snoozedUntilMs?: number | null,
  ) => {
    await invoke("notification_update_assistant_status", {
      itemId,
      item_id: itemId,
      status,
      snoozedUntilMs,
      snoozed_until_ms: snoozedUntilMs,
    });
  };

  const markAssistantSeenIfNeeded = async (
    item: AssistantNotificationRecord,
  ) => {
    if (item.status === "new") {
      await updateAssistantStatus(item.itemId, "seen");
    }
  };

  const handleAssistantAction = async (
    item: AssistantNotificationRecord,
    actionId: string,
  ) => {
    setActionError(null);
    const [action, connectorId, subscriptionId] = actionId.split(":");

    try {
      switch (action) {
        case "open_target":
          await markAssistantSeenIfNeeded(item);
          if (item.target) {
            setSelectedItemKey(`assistant:${item.itemId}`);
            return;
          }
          onOpenAutopilot();
          return;
        case "open_autopilot":
        case "open_task":
        case "view_result":
          await markAssistantSeenIfNeeded(item);
          onOpenAutopilot();
          return;
        case "open_integrations":
          await markAssistantSeenIfNeeded(item);
          onOpenIntegrations(connectorId ?? null);
          return;
        case "open_shield":
          await markAssistantSeenIfNeeded(item);
          onOpenShield(connectorId ?? null);
          return;
        case "open_settings":
          await markAssistantSeenIfNeeded(item);
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
          await markAssistantSeenIfNeeded(item);
          onOpenAutopilot();
      }
    } catch (nextError) {
      setActionError(String(nextError));
    }
  };

  const queueItems = useMemo(
    () =>
      [
        ...interventions.map(buildInterventionQueueItem),
        ...assistantNotifications.map(buildAssistantQueueItem),
      ].sort((left, right) => compareRecords(left.record, right.record)),
    [assistantNotifications, interventions],
  );

  const summaryCounts = useMemo(() => {
    const startOfToday = new Date();
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
  }, [queueItems]);

  const laneCounts = useMemo(
    () => ({
      all: queueItems.length,
      needs_action: queueItems.filter((item) => item.lane === "needs_action")
        .length,
      ready_for_review: queueItems.filter(
        (item) => item.lane === "ready_for_review",
      ).length,
      monitor: queueItems.filter((item) => item.lane === "monitor").length,
      digests: queueItems.filter((item) => item.lane === "digests").length,
      resolved: queueItems.filter((item) => item.lane === "resolved").length,
    }),
    [queueItems],
  );

  const filteredQueueItems = useMemo(() => {
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
  }, [activeLane, queueItems, searchDraft]);

  useEffect(() => {
    if (filteredQueueItems.length === 0) {
      setSelectedItemKey(null);
      return;
    }

    if (
      selectedItemKey &&
      filteredQueueItems.some((item) => item.key === selectedItemKey)
    ) {
      return;
    }

    setSelectedItemKey(filteredQueueItems[0]?.key ?? null);
  }, [filteredQueueItems, selectedItemKey]);

  const selectedQueueItem = useMemo(
    () =>
      filteredQueueItems.find((item) => item.key === selectedItemKey) ?? null,
    [filteredQueueItems, selectedItemKey],
  );

  if (loading) {
    return (
      <div className="notifications-view">
        <div className="notifications-empty-state">Loading inbox…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="notifications-view">
        <div className="notifications-empty-state notifications-empty-state-error">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="notifications-view">
      <header className="notifications-header">
        <div className="notifications-header-copy">
          <span className="notifications-kicker">Approve</span>
          <h1>Inbox</h1>
          <p>
            Operations queue for approvals, reviews, anomalies, and durable
            follow-up.
          </p>
        </div>
        <div className="notifications-header-stats">
          <div className="notifications-stat-card">
            <span>Needs action</span>
            <strong>{summaryCounts.needsAction}</strong>
          </div>
          <div className="notifications-stat-card">
            <span>Local engine</span>
            <strong>{summaryCounts.localEngine}</strong>
          </div>
          <div className="notifications-stat-card">
            <span>Ready for review</span>
            <strong>{summaryCounts.readyForReview}</strong>
          </div>
          <div className="notifications-stat-card">
            <span>Monitor</span>
            <strong>{summaryCounts.anomalies}</strong>
          </div>
          <div className="notifications-stat-card">
            <span>Resolved today</span>
            <strong>{summaryCounts.resolvedToday}</strong>
          </div>
        </div>
      </header>

      {actionError ? (
        <p className="notifications-error">{actionError}</p>
      ) : null}

      <div className="notifications-shell">
        <aside className="notifications-sidebar">
          <div className="notifications-sidebar-head">
            <strong>Queues</strong>
            <span>Filter</span>
          </div>
          <div className="notifications-filter-list">
            {INBOX_LANES.map((lane) => (
              <button
                key={lane.id}
                type="button"
                className={`notifications-filter-button ${activeLane === lane.id ? "active" : ""}`}
                onClick={() => setActiveLane(lane.id)}
              >
                <div>
                  <strong>{lane.label}</strong>
                  <span>{lane.description}</span>
                </div>
                <em>{laneCounts[lane.id]}</em>
              </button>
            ))}
          </div>
        </aside>

        <section className="notifications-queue-pane">
          <div className="notifications-queue-toolbar">
            <input
              className="notifications-search-input"
              type="search"
              value={searchDraft}
              onChange={(event) => setSearchDraft(event.target.value)}
              placeholder="Search title, workflow, run, or action"
            />
            <button
              type="button"
              className="notifications-secondary-button"
              onClick={onOpenSettings}
            >
              Inbox settings
            </button>
          </div>

          <div className="notifications-queue-head">
            <div>
              <span className="notifications-card-eyebrow">
                Operations Queue
              </span>
              <h2>
                {INBOX_LANES.find((lane) => lane.id === activeLane)?.label ??
                  "All"}{" "}
                items
              </h2>
            </div>
            <span className="notifications-queue-count">
              {filteredQueueItems.length}
            </span>
          </div>

          <div className="notifications-list">
            {filteredQueueItems.length === 0 ? (
              <div className="notifications-empty-card">
                No inbox items match this queue.
              </div>
            ) : (
              filteredQueueItems.map((item) => {
                const relativeTime = formatRelativeTime(
                  item.record.updatedAtMs,
                );
                const dueLabel = dueCopy(item.record.dueAtMs);

                return (
                  <article
                    key={item.key}
                    className={`notifications-card notifications-card-${item.record.severity}${
                      item.kind === "intervention" &&
                      isLocalEngineIntervention(item.record as InterventionRecord)
                        ? " notifications-card-engine"
                        : ""
                    }${
                      selectedItemKey === item.key
                        ? " notifications-card-selected"
                        : ""
                    }`}
                    onClick={() => setSelectedItemKey(item.key)}
                  >
                    <div className="notifications-card-topline">
                      <div className="notifications-card-badges">
                        <span
                          className={`notifications-pill notifications-pill-type-${item.typeLabel.toLowerCase()}`}
                        >
                          {item.typeLabel}
                        </span>
                        <span className="notifications-pill">
                          {item.statusLabel}
                        </span>
                        <span className="notifications-pill">
                          {item.sourceLabel}
                        </span>
                      </div>
                      <span className="notifications-card-time">
                        {dueLabel ? `Due ${dueLabel}` : relativeTime}
                      </span>
                    </div>

                    <div className="notifications-card-main">
                      <h3>{item.record.title}</h3>
                      <p className="notifications-summary">
                        {item.record.summary}
                      </p>
                    </div>

                    {item.meta.length > 0 ? (
                      <div className="notifications-meta">
                        {item.meta.map((value) => (
                          <span key={`${item.key}:${value}`}>{value}</span>
                        ))}
                      </div>
                    ) : null}

                    {item.record.recommendedAction ? (
                      <p className="notifications-next-step">
                        Next: {item.record.recommendedAction}
                      </p>
                    ) : null}

                    <div className="notifications-card-actions">
                      {item.kind === "assistant" ? (
                        <>
                          {pickPrimaryAssistantAction(
                            item.record as AssistantNotificationRecord,
                          ) ? (
                            <button
                              type="button"
                              className="notifications-primary-button"
                              onClick={(event) => {
                                event.stopPropagation();
                                const primaryAction =
                                  pickPrimaryAssistantAction(
                                    item.record as AssistantNotificationRecord,
                                  );
                                if (!primaryAction) return;
                                void handleAssistantAction(
                                  item.record as AssistantNotificationRecord,
                                  primaryAction.id,
                                );
                              }}
                            >
                              {displayActionLabel(
                                pickPrimaryAssistantAction(
                                  item.record as AssistantNotificationRecord,
                                )?.label,
                              )}
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="notifications-primary-button"
                              onClick={(event) => {
                                event.stopPropagation();
                                void handleAssistantAction(
                                  item.record as AssistantNotificationRecord,
                                  "open_target",
                                );
                              }}
                            >
                              Open
                            </button>
                          )}
                          <button
                            type="button"
                            className="notifications-secondary-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              void handleAssistantAction(
                                item.record as AssistantNotificationRecord,
                                isResolvedAssistant(
                                  (item.record as AssistantNotificationRecord)
                                    .status,
                                )
                                  ? "archive"
                                  : "snooze",
                              );
                            }}
                          >
                            {isResolvedAssistant(
                              (item.record as AssistantNotificationRecord)
                                .status,
                            )
                              ? "Archive"
                              : "Snooze 1h"}
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            type="button"
                            className="notifications-primary-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              if (
                                isLocalEngineIntervention(
                                  item.record as InterventionRecord,
                                )
                              ) {
                                onOpenLocalEngine();
                                return;
                              }
                              void onOpenAutopilot();
                            }}
                          >
                            {isLocalEngineIntervention(
                              item.record as InterventionRecord,
                            )
                              ? "Open local engine"
                              : "Open chat"}
                          </button>
                          {!isResolvedIntervention(
                            (item.record as InterventionRecord).status,
                          ) ? (
                            <button
                              type="button"
                              className="notifications-secondary-button"
                              onClick={(event) => {
                                event.stopPropagation();
                                void updateInterventionStatus(
                                  (item.record as InterventionRecord).itemId,
                                  (item.record as InterventionRecord).status ===
                                    "new"
                                    ? "seen"
                                    : "pending",
                                  (item.record as InterventionRecord).status ===
                                    "new"
                                    ? undefined
                                    : Date.now() + 60 * 60 * 1000,
                                ).catch((nextError) => {
                                  setActionError(String(nextError));
                                });
                              }}
                            >
                              {(item.record as InterventionRecord).status ===
                              "new"
                                ? "Mark seen"
                                : "Snooze 1h"}
                            </button>
                          ) : null}
                        </>
                      )}
                    </div>
                  </article>
                );
              })
            )}
          </div>
        </section>

        <NotificationDetailPanel
          item={selectedQueueItem?.record ?? null}
          onClose={() => setSelectedItemKey(null)}
          onOpenAutopilot={onOpenAutopilot}
          onOpenLocalEngine={onOpenLocalEngine}
          onOpenReplyComposer={onOpenReplyComposer}
          onOpenMeetingPrep={onOpenMeetingPrep}
          onOpenIntegrations={onOpenIntegrations}
          onOpenShield={onOpenShield}
        />
      </div>
    </div>
  );
}
