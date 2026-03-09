import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useMemo, useState } from "react";
import { NotificationDetailPanel } from "./NotificationDetailPanel";
import type {
  AssistantAttentionPolicy,
  AssistantNotificationRecord,
  AssistantNotificationStatus,
  AssistantWorkbenchSession,
  InterventionRecord,
  InterventionStatus,
  NotificationSeverity,
} from "../../../types";

interface NotificationsViewProps {
  onOpenAutopilot: () => void;
  onOpenIntegrations: (connectorId?: string | null) => void;
  onOpenShield: (connectorId?: string | null) => void;
  onOpenSettings: () => void;
  onOpenReplyComposer: (session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>) => void;
  onOpenMeetingPrep: (session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>) => void;
}

const SEVERITY_ORDER: Record<NotificationSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

function isResolvedIntervention(status: InterventionStatus): boolean {
  return status === "resolved" || status === "expired" || status === "cancelled";
}

function isResolvedAssistant(status: AssistantNotificationStatus): boolean {
  return (
    status === "resolved" ||
    status === "dismissed" ||
    status === "expired" ||
    status === "archived"
  );
}

function upsertById<T extends { itemId: string; updatedAtMs: number }>(items: T[], next: T): T[] {
  const existingIndex = items.findIndex((item) => item.itemId === next.itemId);
  if (existingIndex === -1) {
    return [next, ...items];
  }

  const updated = [...items];
  updated[existingIndex] = next;
  return updated;
}

function compareRecords(
  left: { severity: NotificationSeverity; dueAtMs?: number | null; updatedAtMs: number },
  right: { severity: NotificationSeverity; dueAtMs?: number | null; updatedAtMs: number },
): number {
  const severityDelta = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
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

function observationLabel(value: string): string {
  return value.replace(/_/g, " ");
}

export function NotificationsView({
  onOpenAutopilot,
  onOpenIntegrations,
  onOpenShield,
  onOpenSettings,
  onOpenReplyComposer,
  onOpenMeetingPrep,
}: NotificationsViewProps) {
  const [interventions, setInterventions] = useState<InterventionRecord[]>([]);
  const [assistantNotifications, setAssistantNotifications] = useState<
    AssistantNotificationRecord[]
  >([]);
  const [policy, setPolicy] = useState<AssistantAttentionPolicy | null>(null);
  const [queryDraft, setQueryDraft] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selectedAssistantItemId, setSelectedAssistantItemId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        setLoading(true);
        const [loadedInterventions, loadedAssistant, loadedPolicy] = await Promise.all([
          invoke<InterventionRecord[]>("notification_list_interventions"),
          invoke<AssistantNotificationRecord[]>("notification_list_assistant"),
          invoke<AssistantAttentionPolicy>("assistant_attention_policy_get"),
        ]);
        if (cancelled) return;
        setInterventions(loadedInterventions);
        setAssistantNotifications(loadedAssistant);
        setPolicy(loadedPolicy);
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
      listen<AssistantNotificationRecord>("assistant-notification-updated", (event) => {
        setAssistantNotifications((current) => upsertById(current, event.payload));
      }),
      listen<AssistantAttentionPolicy>("assistant-attention-policy-updated", (event) => {
        setPolicy(event.payload);
      }),
    ]);

    void load();

    return () => {
      cancelled = true;
      void listeners.then((unsubscribers) => {
        unsubscribers.forEach((unsubscribe) => unsubscribe());
      });
    };
  }, []);

  const sortedInterventions = useMemo(
    () => [...interventions].sort(compareRecords),
    [interventions],
  );
  const sortedAssistant = useMemo(
    () => [...assistantNotifications].sort(compareRecords),
    [assistantNotifications],
  );

  const unresolvedInterventions = useMemo(
    () => sortedInterventions.filter((item) => !isResolvedIntervention(item.status)),
    [sortedInterventions],
  );
  const unresolvedAssistant = useMemo(
    () => sortedAssistant.filter((item) => !isResolvedAssistant(item.status)),
    [sortedAssistant],
  );
  const selectedAssistantItem = useMemo(
    () =>
      selectedAssistantItemId
        ? assistantNotifications.find((item) => item.itemId === selectedAssistantItemId) ?? null
        : null,
    [assistantNotifications, selectedAssistantItemId],
  );

  useEffect(() => {
    if (!selectedAssistantItemId) return;
    if (assistantNotifications.some((item) => item.itemId === selectedAssistantItemId)) {
      return;
    }
    setSelectedAssistantItemId(null);
  }, [assistantNotifications, selectedAssistantItemId]);

  const persistPolicy = async (nextPolicy: AssistantAttentionPolicy) => {
    setSavingPolicy(true);
    setPolicyError(null);
    try {
      const saved = await invoke<AssistantAttentionPolicy>("assistant_attention_policy_set", {
        policy: nextPolicy,
      });
      setPolicy(saved);
    } catch (nextError) {
      setPolicyError(String(nextError));
    } finally {
      setSavingPolicy(false);
    }
  };

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

  const applyQueryPolicy = async () => {
    if (!queryDraft.trim()) return;
    setSavingPolicy(true);
    setPolicyError(null);
    try {
      const nextPolicy = await invoke<AssistantAttentionPolicy>(
        "assistant_attention_policy_apply_query",
        {
          instruction: queryDraft,
        },
      );
      setPolicy(nextPolicy);
      setQueryDraft("");
    } catch (nextError) {
      setPolicyError(String(nextError));
    } finally {
      setSavingPolicy(false);
    }
  };

  const markAssistantSeenIfNeeded = async (item: AssistantNotificationRecord) => {
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
            setSelectedAssistantItemId(item.itemId);
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
          await updateAssistantStatus(item.itemId, "snoozed", Date.now() + 60 * 60 * 1000);
          return;
        default:
          await markAssistantSeenIfNeeded(item);
          onOpenAutopilot();
      }
    } catch (nextError) {
      setActionError(String(nextError));
    }
  };

  if (loading) {
    return (
      <div className="notifications-view">
        <div className="notifications-empty-state">Loading notifications…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="notifications-view">
        <div className="notifications-empty-state notifications-empty-state-error">{error}</div>
      </div>
    );
  }

  return (
    <div className="notifications-view">
      <header className="notifications-header">
        <div>
          <span className="notifications-kicker">Operator Console</span>
          <h1>Notifications</h1>
          <p>
            Interventions are control-plane workflow state. Assistant notifications are ranked,
            suppressible suggestions.
          </p>
        </div>
        <div className="notifications-header-stats">
          <div className="notifications-stat-card">
            <span>Interventions</span>
            <strong>{unresolvedInterventions.length}</strong>
          </div>
          <div className="notifications-stat-card">
            <span>Assistant</span>
            <strong>{unresolvedAssistant.length}</strong>
          </div>
        </div>
      </header>

      <section className="notifications-policy-card">
        <div className="notifications-policy-head">
          <div>
            <span className="notifications-card-eyebrow">Attention Policy</span>
            <h2>Adapt assistant behavior</h2>
          </div>
          <button
            type="button"
            className="notifications-secondary-button"
            onClick={onOpenAutopilot}
          >
            Open Autopilot
          </button>
        </div>

        <div className="notifications-policy-grid">
          <label className="notifications-toggle">
            <input
              type="checkbox"
              checked={policy?.global.toastsEnabled ?? false}
              onChange={(event) => {
                if (!policy) return;
                void persistPolicy({
                  ...policy,
                  global: {
                    ...policy.global,
                    toastsEnabled: event.target.checked,
                  },
                });
              }}
            />
            <span>System toasts</span>
          </label>
          <label className="notifications-toggle">
            <input
              type="checkbox"
              checked={policy?.global.badgeEnabled ?? false}
              onChange={(event) => {
                if (!policy) return;
                void persistPolicy({
                  ...policy,
                  global: {
                    ...policy.global,
                    badgeEnabled: event.target.checked,
                  },
                });
              }}
            />
            <span>Action badge</span>
          </label>
          <label className="notifications-toggle">
            <input
              type="checkbox"
              checked={policy?.global.digestEnabled ?? false}
              onChange={(event) => {
                if (!policy) return;
                void persistPolicy({
                  ...policy,
                  global: {
                    ...policy.global,
                    digestEnabled: event.target.checked,
                  },
                });
              }}
            />
            <span>Digest lane</span>
          </label>
          <label className="notifications-toggle">
            <input
              type="checkbox"
              checked={policy?.global.hostedInferenceAllowed ?? false}
              onChange={(event) => {
                if (!policy) return;
                void persistPolicy({
                  ...policy,
                  global: {
                    ...policy.global,
                    hostedInferenceAllowed: event.target.checked,
                  },
                });
              }}
            />
            <span>Hosted inference for assistant summaries</span>
          </label>
        </div>

        <div className="notifications-query-row">
          <input
            type="text"
            value={queryDraft}
            onChange={(event) => setQueryDraft(event.target.value)}
            placeholder='Try: "move build completion alerts to digest"'
          />
          <button
            type="button"
            className="notifications-primary-button"
            disabled={savingPolicy || !queryDraft.trim()}
            onClick={() => {
              void applyQueryPolicy();
            }}
          >
            {savingPolicy ? "Applying…" : "Apply"}
          </button>
        </div>
        {policyError ? <p className="notifications-error">{policyError}</p> : null}
        {actionError ? <p className="notifications-error">{actionError}</p> : null}
      </section>

      <div className="notifications-workspace">
        <section className="notifications-columns">
          <div className="notifications-column">
            <div className="notifications-column-head">
              <div>
                <span className="notifications-card-eyebrow">Control</span>
                <h2>Interventions</h2>
              </div>
              <span className="notifications-column-count">{sortedInterventions.length}</span>
            </div>
            <div className="notifications-list">
              {sortedInterventions.length === 0 ? (
                <div className="notifications-empty-card">No active interventions.</div>
              ) : (
                sortedInterventions.map((item) => (
                  <article
                    key={item.itemId}
                    className={`notifications-card notifications-card-${item.severity}`}
                  >
                    <div className="notifications-card-topline">
                      <span className="notifications-pill notifications-pill-control">
                        {item.interventionType.replace(/_/g, " ")}
                      </span>
                      <span className="notifications-pill">{item.status.replace(/_/g, " ")}</span>
                    </div>
                    <h3>{item.title}</h3>
                    <p className="notifications-summary">{item.summary}</p>
                    {item.reason ? <p className="notifications-reason">{item.reason}</p> : null}
                    <div className="notifications-meta">
                      <span>{item.source.serviceName}</span>
                      {item.sessionId ? <span>Session {item.sessionId.slice(0, 8)}</span> : null}
                      {item.dueAtMs ? <span>Due {dueCopy(item.dueAtMs)}</span> : null}
                    </div>
                    <div className="notifications-assistive-copy">
                      {item.recommendedAction ? <p>Next: {item.recommendedAction}</p> : null}
                      {item.consequenceIfIgnored ? (
                        <p>If ignored: {item.consequenceIfIgnored}</p>
                      ) : null}
                    </div>
                    <div className="notifications-card-actions">
                      {item.status === "new" ? (
                        <button
                          type="button"
                          className="notifications-primary-button"
                          onClick={() => {
                            void updateInterventionStatus(item.itemId, "seen");
                          }}
                        >
                          Mark seen
                        </button>
                      ) : null}
                      <button
                        type="button"
                        className="notifications-secondary-button"
                        onClick={onOpenAutopilot}
                      >
                        Open workflow
                      </button>
                    </div>
                  </article>
                ))
              )}
            </div>
          </div>

          <div className="notifications-column">
            <div className="notifications-column-head">
              <div>
                <span className="notifications-card-eyebrow">Assistant</span>
                <h2>Productivity prompts</h2>
              </div>
              <span className="notifications-column-count">{sortedAssistant.length}</span>
            </div>
            <div className="notifications-list">
              {sortedAssistant.length === 0 ? (
                <div className="notifications-empty-card">No assistant notifications yet.</div>
              ) : (
                sortedAssistant.map((item) => (
                  <article
                    key={item.itemId}
                    className={`notifications-card notifications-card-${item.severity}${
                      selectedAssistantItemId === item.itemId ? " notifications-card-selected" : ""
                    }`}
                  >
                    <div className="notifications-card-topline">
                      <span className="notifications-pill notifications-pill-assistant">
                        {item.notificationClass.replace(/_/g, " ")}
                      </span>
                      <span className="notifications-pill">{item.status.replace(/_/g, " ")}</span>
                    </div>
                    <h3>{item.title}</h3>
                    <p className="notifications-summary">{item.summary}</p>
                    {item.reason ? <p className="notifications-reason">{item.reason}</p> : null}
                    <div className="notifications-meta">
                      <span>Priority {(item.priorityScore * 100).toFixed(0)}%</span>
                      <span>Confidence {(item.confidenceScore * 100).toFixed(0)}%</span>
                      {item.dueAtMs ? <span>Due {dueCopy(item.dueAtMs)}</span> : null}
                    </div>
                    <div className="notifications-assistive-copy">
                      {item.recommendedAction ? <p>Next: {item.recommendedAction}</p> : null}
                      <p>
                        Why now:{" "}
                        {item.rankingReason.map(observationLabel).join(", ") || "user value"}
                      </p>
                      <p>Observation tier: {observationLabel(item.privacy.observationTier)}</p>
                    </div>
                    <div className="notifications-card-actions">
                      {item.actions.map((action) => (
                        <button
                          key={action.id}
                          type="button"
                          className={
                            action.style === "primary"
                              ? "notifications-primary-button"
                              : action.style === "secondary"
                                ? "notifications-secondary-button"
                                : action.style === "danger"
                                  ? "notifications-primary-button"
                                  : "notifications-quiet-button"
                          }
                          onClick={() => {
                            void handleAssistantAction(item, action.id);
                          }}
                        >
                          {action.label}
                        </button>
                      ))}
                      {!isResolvedAssistant(item.status) ? (
                        <button
                          type="button"
                          className="notifications-secondary-button"
                          onClick={() => {
                            void handleAssistantAction(item, "snooze");
                          }}
                        >
                          Snooze 1h
                        </button>
                      ) : null}
                      {!isResolvedAssistant(item.status) ? (
                        <button
                          type="button"
                          className="notifications-quiet-button"
                          onClick={() => {
                            void handleAssistantAction(item, "dismiss");
                          }}
                        >
                          Dismiss
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="notifications-quiet-button"
                          onClick={() => {
                            void handleAssistantAction(item, "archive");
                          }}
                        >
                          Archive
                        </button>
                      )}
                    </div>
                  </article>
                ))
              )}
            </div>
          </div>
        </section>

        <NotificationDetailPanel
          item={selectedAssistantItem}
          onClose={() => setSelectedAssistantItemId(null)}
          onOpenReplyComposer={onOpenReplyComposer}
          onOpenMeetingPrep={onOpenMeetingPrep}
          onOpenIntegrations={onOpenIntegrations}
          onOpenShield={onOpenShield}
        />
      </div>
    </div>
  );
}
