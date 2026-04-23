import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AssistantWorkbenchView,
  type AssistantWorkbenchActivity,
  useAssistantWorkbenchState,
  useSessionApprovalState,
  useSessionInterruptionActions,
} from "@ioi/agent-ide";
import { OperatorInboxQueueColumns } from "../../components/OperatorInboxQueueColumns";
import "../../components/OperatorInboxQueueColumns.css";
import { useNotificationTargetDetail } from "../../hooks/useNotificationTargetDetail";
import { useOperatorNotifications } from "../../hooks/useOperatorNotifications";
import { useRetainedWorkbenchTrace } from "../../hooks/useRetainedWorkbenchTrace";
import { buildOperatorWorkbenchSummary } from "../../lib/operatorWorkbenchSummary";
import {
  buildInboxQueueItems,
  filterInboxQueueItems,
  getInboxLaneCounts,
  getInboxSummaryCounts,
  type InboxLane,
} from "../../lib/operatorInboxQueue";
import {
  runAssistantNotificationAction,
} from "../../lib/operatorNotifications";
import { buildAssistantWorkbenchSummary } from "../../lib/assistantWorkbenchSummary";
import { bootstrapAgentSession, useAgentStore } from "../../session/autopilotSession";
import {
  openCompanionAutopilotIntent,
  openCompanionCapabilities,
  openCompanionCapabilityTarget,
  openCompanionNotifications,
  openCompanionPolicyTarget,
  openCompanionSettings,
  openCompanionChat,
} from "../../services/companionShellNavigation";
import { openAssistantWorkbenchReview } from "../../services/reviewNavigation";
import { getSessionWorkbenchRuntime } from "../../services/sessionRuntime";
import type {
  AssistantNotificationRecord,
  InterventionRecord,
} from "../../types";
import { ChatGateDock } from "../ChatShellWindow/components/ChatGateDock";
import { GateNotificationDetail } from "./GateNotificationDetail";

import "../ChatShellWindow/styles/Layout.css";
import "../ChatShellWindow/styles/Chat.css";
import "../ChatShellWindow/styles/Sidebar.css";
import "../ChatShellWindow/styles/Components.css";
import "../ChatShellWindow/styles/Visuals.css";
import "../ChatShellWindow/styles/ArtifactPanel.css";
import "../ChatShellWindow/styles/Overrides.css";
import "../ChatShellWindow/styles/MicroEventCard.css";
import "../ChatShellWindow/styles/ChatSurface.css";
import "../shared/AssistantWorkbench.css";
import "./GateWindow.css";

export function GateWindow() {
  const { task, continueTask } = useAgentStore();
  const {
    assistantWorkbench,
    activeAssistantWorkbenchActivities,
    openReplyComposer,
    openMeetingPrep,
  } = useAssistantWorkbenchState();
  const [activeLane, setActiveLane] = useState<InboxLane>("needs_action");
  const [searchDraft, setSearchDraft] = useState("");
  const [showWorkbench, setShowWorkbench] = useState(false);
  const [queueActionError, setQueueActionError] = useState<string | null>(null);
  const [selectedQueueItemKey, setSelectedQueueItemKey] = useState<string | null>(null);
  const {
    badgeCount,
    interventions,
    assistantNotifications,
    loading: notificationsLoading,
    error: notificationsError,
    updateInterventionStatus,
    updateAssistantStatus,
  } = useOperatorNotifications();

  useEffect(() => {
    void bootstrapAgentSession();
  }, []);

  useEffect(() => {
    if (assistantWorkbench) {
      setShowWorkbench(true);
      return;
    }
    setShowWorkbench(false);
  }, [assistantWorkbench]);

  const {
    setRuntimePasswordPending,
    setRuntimePasswordSessionId,
    gateActionError,
    credentialRequest,
    clarificationRequest,
    showPasswordPrompt,
    showClarificationPrompt,
    gateInfo,
    isPiiGate,
    isGated,
    gateDeadlineMs,
    handleApprove,
    handleDeny,
    handleGrantScopedException,
  } = useSessionApprovalState({
    task,
  });

  const {
    handleSubmitRuntimePassword,
    handleCancelRuntimePassword,
    handleSubmitClarification,
    handleCancelClarification,
  } = useSessionInterruptionActions({
    task,
    continueTask,
    setRuntimePasswordPending,
    setRuntimePasswordSessionId,
  });

  const hasGateSurface =
    isGated || showPasswordPrompt || (showClarificationPrompt && !!clarificationRequest);

  const queueItems = useMemo(
    () => buildInboxQueueItems(interventions, assistantNotifications),
    [assistantNotifications, interventions],
  );
  const summaryCounts = useMemo(
    () => getInboxSummaryCounts(queueItems),
    [queueItems],
  );
  const laneCounts = useMemo(() => getInboxLaneCounts(queueItems), [queueItems]);
  const filteredQueueItems = useMemo(
    () => filterInboxQueueItems(queueItems, activeLane, searchDraft),
    [activeLane, queueItems, searchDraft],
  );
  const recommendedWorkbenchQueueItem = useMemo(
    () =>
      queueItems.find(
        (item) =>
          item.kind === "assistant" &&
          item.lane !== "resolved" &&
          !!item.record.target &&
          (item.record.target.kind === "gmail_thread" ||
            item.record.target.kind === "calendar_event"),
      ) ?? null,
    [queueItems],
  );
  const activeWorkbenchSummary = useMemo(
    () => buildAssistantWorkbenchSummary(assistantWorkbench),
    [assistantWorkbench],
  );
  const {
    evidenceThreadId: retainedWorkbenchEvidenceThreadId,
    trace: retainedWorkbenchTrace,
    latestEvent: latestRetainedWorkbenchEvent,
    latestArtifact: latestRetainedWorkbenchArtifact,
  } = useRetainedWorkbenchTrace(activeAssistantWorkbenchActivities);
  const recommendedWorkbenchDetail = useNotificationTargetDetail(
    (recommendedWorkbenchQueueItem?.record as AssistantNotificationRecord | undefined) ??
      null,
  );
  const recommendedWorkbenchSummary = useMemo(
    () =>
      buildOperatorWorkbenchSummary(
        (recommendedWorkbenchQueueItem?.record as AssistantNotificationRecord | undefined) ??
          null,
        recommendedWorkbenchDetail.gmailThread,
        recommendedWorkbenchDetail.calendarEvent,
      ),
    [
      recommendedWorkbenchDetail.calendarEvent,
      recommendedWorkbenchDetail.gmailThread,
      recommendedWorkbenchQueueItem,
    ],
  );
  const recommendedWorkbenchFallback = useMemo(() => {
    const item =
      (recommendedWorkbenchQueueItem?.record as AssistantNotificationRecord | undefined) ??
      null;
    if (!item?.target || recommendedWorkbenchSummary) {
      return null;
    }

    if (item.target.kind === "gmail_thread") {
      const subject = item.title.replace(/^Reply may be overdue:\s*/i, "").trim();
      return {
        title: "Recommended next workbench",
        summary: `Open the reply composer for ${subject || "this Gmail thread"}. Gate will keep the queue item in focus while the thread context finishes loading.`,
        ctaLabel: recommendedWorkbenchDetail.loading
          ? "Loading thread context..."
          : "Retry thread detail",
        meta: [
          recommendedWorkbenchDetail.loading
            ? "Loading thread context"
            : "Thread detail unavailable",
        ],
      };
    }

    const subject = item.title.replace(/^Upcoming meeting:\s*/i, "").trim();
    return {
      title: "Recommended next workbench",
      summary: `Open meeting prep for ${subject || "this calendar event"}. Gate will keep the queue item in focus while the event context finishes loading.`,
      ctaLabel: recommendedWorkbenchDetail.loading
        ? "Loading event context..."
        : "Retry event detail",
      meta: [
        recommendedWorkbenchDetail.loading
          ? "Loading event context"
          : "Event detail unavailable",
      ],
    };
  }, [
    recommendedWorkbenchDetail.loading,
    recommendedWorkbenchQueueItem,
    recommendedWorkbenchSummary,
  ]);
  const workbenchRuntime = useMemo(
    () => getSessionWorkbenchRuntime(),
    [],
  );
  const selectedQueueItem = useMemo(
    () =>
      filteredQueueItems.find((item) => item.key === selectedQueueItemKey) ??
      filteredQueueItems[0] ??
      null,
    [filteredQueueItems, selectedQueueItemKey],
  );

  useEffect(() => {
    if (filteredQueueItems.length === 0) {
      if (selectedQueueItemKey !== null) {
        setSelectedQueueItemKey(null);
      }
      return;
    }

    if (
      selectedQueueItemKey === null ||
      !filteredQueueItems.some((item) => item.key === selectedQueueItemKey)
    ) {
      setSelectedQueueItemKey(filteredQueueItems[0]?.key ?? null);
    }
  }, [filteredQueueItems, selectedQueueItemKey]);

  const collapseWorkbench = useCallback(() => {
    setShowWorkbench(false);
  }, []);

  const focusWorkbenchSource = useCallback(() => {
    if (assistantWorkbench?.sourceNotificationId) {
      setSelectedQueueItemKey(`assistant:${assistantWorkbench.sourceNotificationId}`);
    }
    setShowWorkbench(false);
  }, [assistantWorkbench]);

  const handleDeferIntervention = useCallback(
    async (item: InterventionRecord) => {
      setQueueActionError(null);
      try {
        await updateInterventionStatus(
          item.itemId,
          item.status === "new" ? "seen" : "pending",
          item.status === "new" ? undefined : Date.now() + 60 * 60 * 1000,
        );
      } catch (error) {
        setQueueActionError(String(error));
      }
    },
    [updateInterventionStatus],
  );

  const handleDeferAssistantNotification = useCallback(
    async (item: AssistantNotificationRecord) => {
      setQueueActionError(null);
      try {
        await updateAssistantStatus(
          item.itemId,
          item.status === "new" ? "seen" : "snoozed",
          item.status === "new" ? undefined : Date.now() + 60 * 60 * 1000,
        );
      } catch (error) {
        setQueueActionError(String(error));
      }
    },
    [updateAssistantStatus],
  );

  const handleAssistantAction = useCallback(
    async (item: AssistantNotificationRecord, actionId: string) => {
      setQueueActionError(null);
      try {
        await runAssistantNotificationAction({
          item,
          actionId,
          updateAssistantStatus,
          onOpenAutopilot: () => {
            void openCompanionChat();
          },
          onOpenIntegrations: (connectorId) => {
            void openCompanionCapabilityTarget(
              connectorId,
              connectorId ? "setup" : null,
            );
          },
          onOpenShield: (connectorId) => {
            void openCompanionPolicyTarget(connectorId);
          },
          onOpenSettings: () => {
            void openCompanionSettings();
          },
          onOpenTarget: () => {
            setSelectedQueueItemKey(`assistant:${item.itemId}`);
          },
        });
      } catch (error) {
        setQueueActionError(String(error));
      }
    },
    [updateAssistantStatus],
  );

  const formatWorkbenchActivityTime = useCallback((timestampMs: number) => {
    return new Intl.DateTimeFormat(undefined, {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
    }).format(timestampMs);
  }, []);

  const activityToneLabel = useCallback(
    (activity: AssistantWorkbenchActivity) => {
      if (activity.status === "failed") return "Failed";
      if (activity.status === "requested") return "Approval";
      if (activity.status === "succeeded") return "Done";
      return "Running";
    },
    [],
  );

  return (
    <div className="gate-window-host">
      <section className="gate-window-shell">
        <header className="gate-window-header">
          <div>
            <span className="gate-window-kicker">Approval center</span>
            <h1>Governed operator review</h1>
            <p>
              Review live gates, privacy interventions, and assistant prompts from one shell.
            </p>
          </div>
          <div className="gate-window-header-meta">
            <span>{badgeCount} pending inbox item{badgeCount === 1 ? "" : "s"}</span>
            <button
              type="button"
              className="gate-window-header-action"
              onClick={() => {
                void openCompanionNotifications();
              }}
            >
              Open inbox
            </button>
          </div>
        </header>

        <section className="gate-window-summary">
          <div className="gate-window-summary-copy">
            <strong>Queue context</strong>
            <span>Shared inbox totals for approvals, reviews, anomalies, and resolved work.</span>
          </div>
          <div className="gate-window-summary-grid">
            {[
              { label: "Needs action", value: summaryCounts.needsAction },
              { label: "Local engine", value: summaryCounts.localEngine },
              { label: "Ready for review", value: summaryCounts.readyForReview },
              { label: "Monitor", value: summaryCounts.anomalies },
              { label: "Resolved today", value: summaryCounts.resolvedToday },
            ].map((entry) => (
              <div key={entry.label} className="gate-window-summary-card">
                <span>{entry.label}</span>
                <strong>{entry.value}</strong>
              </div>
            ))}
          </div>
        </section>

        {assistantWorkbench && activeWorkbenchSummary && !showWorkbench ? (
          <section className="gate-window-workbench">
            <div className="gate-window-summary-copy">
              <strong>{activeWorkbenchSummary.title}</strong>
              <span>{activeWorkbenchSummary.summary}</span>
            </div>
            <div className="gate-window-workbench-actions">
              <button
                type="button"
                className="gate-window-primary-button"
                onClick={() => {
                  setShowWorkbench(true);
                }}
              >
                Resume in Gate
              </button>
              <button
                type="button"
                className="gate-window-secondary-button"
                onClick={() => {
                  void openAssistantWorkbenchReview(assistantWorkbench);
                }}
              >
                {activeWorkbenchSummary.resumeLabel}
              </button>
            </div>
          </section>
        ) : null}

        {!assistantWorkbench &&
        recommendedWorkbenchQueueItem &&
        (recommendedWorkbenchSummary || recommendedWorkbenchFallback) ? (
          <section className="gate-window-workbench gate-window-workbench--suggested">
            <div className="gate-window-summary-copy">
              <strong>
                {(recommendedWorkbenchSummary ?? recommendedWorkbenchFallback)?.title}
              </strong>
              <span>
                {(recommendedWorkbenchSummary ?? recommendedWorkbenchFallback)?.summary}
              </span>
            </div>
            {(recommendedWorkbenchSummary ?? recommendedWorkbenchFallback)?.meta.length ? (
              <div className="gate-window-workbench-tags">
                {(recommendedWorkbenchSummary ?? recommendedWorkbenchFallback)?.meta.map(
                  (value) => (
                  <span key={value}>{value}</span>
                  ),
                )}
              </div>
            ) : null}
            <div className="gate-window-workbench-actions">
              {recommendedWorkbenchSummary ? (
                <button
                  type="button"
                  className="gate-window-primary-button"
                  onClick={() => {
                    if (recommendedWorkbenchSummary.kind === "gmail_reply") {
                      openReplyComposer(recommendedWorkbenchSummary.session);
                    } else {
                      openMeetingPrep(recommendedWorkbenchSummary.session);
                    }
                    setSelectedQueueItemKey(recommendedWorkbenchQueueItem.key);
                    setActiveLane(recommendedWorkbenchQueueItem.lane);
                    setShowWorkbench(true);
                  }}
                >
                  {recommendedWorkbenchSummary.ctaLabel}
                </button>
              ) : (
                <button
                  type="button"
                  className="gate-window-secondary-button"
                  disabled={recommendedWorkbenchDetail.loading}
                  onClick={() => {
                    recommendedWorkbenchDetail.refresh();
                  }}
                >
                  {recommendedWorkbenchFallback?.ctaLabel}
                </button>
              )}
              <button
                type="button"
                className="gate-window-secondary-button"
                onClick={() => {
                  setSelectedQueueItemKey(recommendedWorkbenchQueueItem.key);
                  setActiveLane(recommendedWorkbenchQueueItem.lane);
                }}
              >
                Focus queue item
              </button>
            </div>
          </section>
        ) : null}

        {assistantWorkbench && activeAssistantWorkbenchActivities.length > 0 ? (
          <section className="gate-window-workbench">
            <div className="gate-window-summary-copy">
              <strong>Workbench activity</strong>
              <span>
                Shared receipts for the current reply/prep handoff so the operator can
                verify progress without leaving Gate.
              </span>
            </div>
            <div className="gate-window-activity-list">
              {activeAssistantWorkbenchActivities.slice(0, 6).map((activity) => (
                <article
                  key={activity.activityId}
                  className={`gate-window-activity-card gate-window-activity-card--${activity.status}`}
                >
                  <div className="gate-window-activity-head">
                    <strong>{activity.message}</strong>
                    <span>{formatWorkbenchActivityTime(activity.timestampMs)}</span>
                  </div>
                  <div className="gate-window-activity-meta">
                    <span>{activityToneLabel(activity)}</span>
                    <span>{activity.surface === "reply-composer" ? "Reply" : "Prep"}</span>
                    <span>{activity.action.replace(/_/g, " ")}</span>
                    {activity.evidenceThreadId ? <span>Retained</span> : null}
                  </div>
                  {activity.detail ? (
                    <p className="gate-window-activity-detail">{activity.detail}</p>
                  ) : null}
                </article>
              ))}
            </div>
          </section>
        ) : null}

        {assistantWorkbench && retainedWorkbenchEvidenceThreadId ? (
          <section className="gate-window-workbench">
            <div className="gate-window-summary-copy">
              <strong>Retained trace</strong>
              <span>
                Kernel-backed events and report artifacts stored for this reply/prep thread.
              </span>
            </div>
            {retainedWorkbenchTrace.loading ? (
              <div className="capabilities-inline-note">
                Loading retained trace summary...
              </div>
            ) : retainedWorkbenchTrace.error ? (
              <div className="capabilities-inline-note">
                Retained trace unavailable: {retainedWorkbenchTrace.error}
              </div>
            ) : (
              <div className="gate-window-summary-grid">
                <div className="gate-window-summary-card">
                  <strong>{retainedWorkbenchTrace.events.length}</strong>
                  <span>Persisted events</span>
                </div>
                <div className="gate-window-summary-card">
                  <strong>{retainedWorkbenchTrace.artifacts.length}</strong>
                  <span>Report artifacts</span>
                </div>
                <div className="gate-window-summary-card">
                  <strong>{latestRetainedWorkbenchEvent?.title ?? "Awaiting event"}</strong>
                  <span>Latest event</span>
                </div>
                <div className="gate-window-summary-card">
                  <strong>{latestRetainedWorkbenchArtifact?.title ?? "No report yet"}</strong>
                  <span>Latest artifact</span>
                </div>
              </div>
            )}
          </section>
        ) : null}

        {assistantWorkbench && showWorkbench ? (
          <section className="gate-window-workbench-stage">
            <AssistantWorkbenchView
              session={assistantWorkbench}
              runtime={workbenchRuntime}
              onBack={collapseWorkbench}
              onOpenNotifications={focusWorkbenchSource}
              onOpenAutopilot={(intent) => {
                void openCompanionAutopilotIntent(intent);
              }}
            />
            <div className="gate-window-workbench-stage-actions">
              <button
                type="button"
              className="gate-window-secondary-button"
              onClick={() => {
                  void openAssistantWorkbenchReview(assistantWorkbench);
              }}
            >
              Open in Chat
              </button>
            </div>
          </section>
        ) : null}

        {hasGateSurface ? (
          <ChatGateDock
            isGated={isGated}
            gateInfo={gateInfo}
            isPiiGate={isPiiGate}
            gateDeadlineMs={gateDeadlineMs}
            gateActionError={gateActionError}
            onApprove={handleApprove}
            onGrantScopedException={handleGrantScopedException}
            onDeny={handleDeny}
            showPasswordPrompt={showPasswordPrompt}
            credentialRequest={credentialRequest}
            onSubmitRuntimePassword={handleSubmitRuntimePassword}
            onCancelRuntimePassword={handleCancelRuntimePassword}
            showClarificationPrompt={showClarificationPrompt}
            clarificationRequest={clarificationRequest}
            onSubmitClarification={handleSubmitClarification}
            onCancelClarification={handleCancelClarification}
          />
        ) : (
          <section className="gate-window-empty">
            <h2>No active gate</h2>
            <p>
              The queue below still tracks pending interventions and assistant prompts that may
              need review.
            </p>
          </section>
        )}

        <section className="gate-window-queue">
          <OperatorInboxQueueColumns
            activeLane={activeLane}
            laneCounts={laneCounts}
            searchDraft={searchDraft}
            filteredQueueItems={filteredQueueItems}
            selectedItemKey={selectedQueueItemKey}
            className="notifications-shell--compact notifications-shell--embedded"
            actionError={queueActionError}
            notificationsError={notificationsError}
            notificationsLoading={notificationsLoading}
            queueEyebrow="Approval queue"
            toolbarActionLabel="Open chat"
            onLaneChange={setActiveLane}
            onSearchDraftChange={setSearchDraft}
            onSelectItemKey={setSelectedQueueItemKey}
            onToolbarAction={() => {
              void openCompanionChat();
            }}
            onOpenAutopilot={() => {
              void openCompanionChat();
            }}
            onOpenLocalEngine={() => {
              void openCompanionCapabilities();
            }}
            onAssistantAction={handleAssistantAction}
            onDeferAssistant={handleDeferAssistantNotification}
            onDeferIntervention={handleDeferIntervention}
          />
        </section>

        <GateNotificationDetail
          item={selectedQueueItem?.record ?? null}
          onClose={() => {
            setSelectedQueueItemKey(null);
          }}
          onOpenChat={() => {
            void openCompanionChat();
          }}
          onOpenInbox={() => {
            void openCompanionNotifications();
          }}
          onOpenReplyComposer={(session) => {
            openReplyComposer(session);
            setShowWorkbench(true);
          }}
          onOpenMeetingPrep={(session) => {
            openMeetingPrep(session);
            setShowWorkbench(true);
          }}
          onOpenCapabilities={(connectorId) => {
            void openCompanionCapabilityTarget(
              connectorId,
              connectorId ? "setup" : null,
            );
          }}
          onOpenPolicy={(connectorId) => {
            void openCompanionPolicyTarget(connectorId);
          }}
          onOpenLocalEngine={() => {
            void openCompanionCapabilities();
          }}
        />
      </section>
    </div>
  );
}
