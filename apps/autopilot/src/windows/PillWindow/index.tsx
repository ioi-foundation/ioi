import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AssistantWorkbenchView,
  hidePillShell,
  openStudioAutopilotIntent,
  openStudioCapabilityTarget,
  openStudioPolicyTarget,
  openStudioShellView,
  showGateShell,
  showSpotlightShell,
  useAssistantWorkbenchState,
} from "@ioi/agent-ide";
import { useRetainedWorkbenchTrace } from "../../hooks/useRetainedWorkbenchTrace";
import { buildAssistantWorkbenchSummary } from "../../lib/assistantWorkbenchSummary";
import { useNotificationTargetDetail } from "../../hooks/useNotificationTargetDetail";
import { useOperatorNotifications } from "../../hooks/useOperatorNotifications";
import { notificationTargetConnectorId } from "../../lib/notificationTargets";
import { buildOperatorWorkbenchSummary } from "../../lib/operatorWorkbenchSummary";
import {
  displayNotificationActionLabel,
  humanizeOperatorNotificationValue,
  isLocalEngineIntervention,
  pickPrimaryAssistantAction,
  runAssistantNotificationAction,
} from "../../lib/operatorNotifications";
import { bootstrapAgentSession, useAgentStore } from "../../session/autopilotSession";
import { getSessionWorkbenchRuntime } from "../../services/sessionRuntime";
import "./PillWindow.css";
import "../shared/AssistantWorkbench.css";
import type {
  AgentTask,
  AssistantNotificationRecord,
  InterventionRecord,
} from "../../types";

function phaseLabel(task: AgentTask | null): string {
  if (!task) return "Ready";
  switch (task.phase) {
    case "Gate":
      return "Approval waiting";
    case "Running":
      return "Working";
    case "Complete":
      return "Complete";
    case "Failed":
      return "Needs review";
    default:
      return "Ready";
  }
}

function phaseTone(task: AgentTask | null): string {
  if (!task) return "idle";
  switch (task.phase) {
    case "Gate":
      return "gate";
    case "Running":
      return "running";
    case "Complete":
      return "complete";
    case "Failed":
      return "failed";
    default:
      return "idle";
  }
}

function isInterventionRecord(
  item: AssistantNotificationRecord | InterventionRecord,
): item is InterventionRecord {
  return "interventionType" in item;
}

export function PillWindow() {
  const { task } = useAgentStore();
  const {
    assistantWorkbench,
    activeAssistantWorkbenchActivities,
    openReplyComposer,
    openMeetingPrep,
  } = useAssistantWorkbenchState();
  const [focusActionError, setFocusActionError] = useState<string | null>(null);
  const [showWorkbench, setShowWorkbench] = useState(false);
  const {
    badgeCount,
    topQueueItem,
    updateInterventionStatus,
    updateAssistantStatus,
  } = useOperatorNotifications();
  const focusItem = topQueueItem?.record ?? null;
  const focusIntervention =
    focusItem && isInterventionRecord(focusItem) ? focusItem : null;
  const focusAssistantNotification =
    focusItem && !isInterventionRecord(focusItem) ? focusItem : null;
  const primaryAssistantAction = focusAssistantNotification
    ? pickPrimaryAssistantAction(focusAssistantNotification)
    : null;
  const {
    loading: focusDetailLoading,
    gmailThread,
    calendarEvent,
    authRecord,
    subscription,
  } = useNotificationTargetDetail(focusItem);

  useEffect(() => {
    void bootstrapAgentSession();
  }, []);

  useEffect(() => {
    if (!assistantWorkbench) {
      setShowWorkbench(false);
    }
  }, [assistantWorkbench]);

  const canOpenGate =
    task?.phase === "Gate" ||
    Boolean(task?.gate_info) ||
    Boolean(task?.credential_request) ||
    Boolean(task?.clarification_request);
  const replyWorkbenchSession =
    focusAssistantNotification?.target?.kind === "gmail_thread" && gmailThread
      ? {
          kind: "gmail_reply" as const,
          connectorId:
            notificationTargetConnectorId(focusAssistantNotification.target) ??
            "google.workspace",
          thread: gmailThread,
          sourceNotificationId: focusAssistantNotification.itemId,
        }
      : null;
  const meetingPrepWorkbenchSession =
    focusAssistantNotification?.target?.kind === "calendar_event" && calendarEvent
      ? {
          kind: "meeting_prep" as const,
          connectorId:
            notificationTargetConnectorId(focusAssistantNotification.target) ??
            "google.workspace",
          event: calendarEvent,
          sourceNotificationId: focusAssistantNotification.itemId,
        }
      : null;

  const headline = useMemo(() => {
    if (task?.intent?.trim()) {
      return task.intent.trim();
    }
    if (focusItem?.title?.trim()) {
      return focusItem.title.trim();
    }
    return "Autopilot ready";
  }, [focusItem, task]);

  const summary = useMemo(() => {
    if (task?.current_step?.trim()) {
      return task.current_step.trim();
    }
    if (focusItem?.summary?.trim()) {
      return focusItem.summary.trim();
    }
    if (badgeCount > 0) {
      return `${badgeCount} pending inbox item${badgeCount === 1 ? "" : "s"}.`;
    }
    return "Open Spotlight for a live run, or Studio for deeper inspection.";
  }, [badgeCount, focusItem, task]);

  const handleOpenSpotlight = useCallback(async () => {
    await showSpotlightShell();
  }, []);

  const handleOpenStudio = useCallback(async (view: string) => {
    await openStudioShellView(view);
  }, []);

  const openCapabilityTarget = useCallback(async (connectorId?: string | null) => {
    await openStudioCapabilityTarget(
      connectorId,
      connectorId ? "setup" : undefined,
    );
  }, []);

  const openPolicyTarget = useCallback(async (connectorId?: string | null) => {
    await openStudioPolicyTarget(connectorId);
  }, []);

  const handleOpenGate = useCallback(async () => {
    await showGateShell();
  }, []);

  const workbenchRuntime = useMemo(
    () => getSessionWorkbenchRuntime(),
    [],
  );

  const handleDeferTopIntervention = useCallback(async () => {
    if (!focusIntervention) return;
    setFocusActionError(null);
    try {
      await updateInterventionStatus(
        focusIntervention.itemId,
        focusIntervention.status === "new" ? "seen" : "pending",
        focusIntervention.status === "new" ? undefined : Date.now() + 60 * 60 * 1000,
      );
    } catch (error) {
      setFocusActionError(String(error));
    }
  }, [focusIntervention, updateInterventionStatus]);

  const handleDeferTopAssistant = useCallback(async () => {
    if (!focusAssistantNotification) return;
    setFocusActionError(null);
    try {
      await updateAssistantStatus(
        focusAssistantNotification.itemId,
        focusAssistantNotification.status === "new" ? "seen" : "snoozed",
        focusAssistantNotification.status === "new"
          ? undefined
          : Date.now() + 60 * 60 * 1000,
      );
    } catch (error) {
      setFocusActionError(String(error));
    }
  }, [focusAssistantNotification, updateAssistantStatus]);

  const handlePrimaryAssistantAction = useCallback(async () => {
    if (!focusAssistantNotification) return;
    setFocusActionError(null);
    try {
      await runAssistantNotificationAction({
        item: focusAssistantNotification,
        actionId: primaryAssistantAction?.id ?? "open_target",
        updateAssistantStatus,
        onOpenAutopilot: () => {
          void showSpotlightShell();
        },
        onOpenIntegrations: (connectorId) => {
          void openCapabilityTarget(connectorId);
        },
        onOpenShield: (connectorId) => {
          void openPolicyTarget(connectorId);
        },
        onOpenSettings: () => {
          void handleOpenStudio("settings");
        },
        onOpenTarget: (item) => {
          if (!item.target) {
            return false;
          }
          if (item.target.kind === "gmail_thread" && gmailThread) {
            openReplyComposer({
              kind: "gmail_reply",
              connectorId:
                notificationTargetConnectorId(item.target) ??
                "google.workspace",
              thread: gmailThread,
              sourceNotificationId: item.itemId,
            });
            setShowWorkbench(true);
            return true;
          }
          if (item.target.kind === "calendar_event" && calendarEvent) {
            openMeetingPrep({
              kind: "meeting_prep",
              connectorId:
                notificationTargetConnectorId(item.target) ??
                "google.workspace",
              event: calendarEvent,
              sourceNotificationId: item.itemId,
            });
            setShowWorkbench(true);
            return true;
          }
          void handleOpenGate();
          return true;
        },
      });
    } catch (error) {
      setFocusActionError(String(error));
    }
  }, [
    handleOpenGate,
    handleOpenStudio,
    calendarEvent,
    focusAssistantNotification,
    gmailThread,
    openCapabilityTarget,
    openMeetingPrep,
    openReplyComposer,
    openPolicyTarget,
    primaryAssistantAction?.id,
    updateAssistantStatus,
  ]);

  const focusTargetSummary = useMemo(() => {
    if (!focusItem?.target) return null;

    switch (focusItem.target.kind) {
      case "gmail_thread": {
        const latestMessage = gmailThread?.messages[0];
        return (
          gmailThread?.snippet ||
          latestMessage?.snippet ||
          latestMessage?.subject ||
          null
        );
      }
      case "calendar_event":
        return (
          calendarEvent?.summary ||
          calendarEvent?.location ||
          calendarEvent?.description ||
          null
        );
      case "connector_auth":
        return (
          authRecord?.record.accountLabel ||
          authRecord?.record.state ||
          null
        );
      case "connector_subscription":
        return (
          subscription?.accountEmail ||
          subscription?.status ||
          subscription?.kind ||
          null
        );
      default:
        return null;
    }
  }, [authRecord, calendarEvent, focusItem, gmailThread, subscription]);

  const focusWorkbenchSummary = useMemo(
    () =>
      buildOperatorWorkbenchSummary(
        focusItem,
        gmailThread,
        calendarEvent,
      ),
    [calendarEvent, focusItem, gmailThread],
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

  return (
    <div className="pill-window">
      <button
        type="button"
        className={`pill-shell pill-shell--${phaseTone(task)}`}
        onClick={() => {
          void handleOpenSpotlight();
        }}
      >
        <div className="pill-shell__row">
          <span className="pill-shell__status">
            <span className="pill-shell__status-dot" />
            {phaseLabel(task)}
          </span>
          {badgeCount > 0 ? (
            <span className="pill-shell__badge">{badgeCount}</span>
          ) : null}
        </div>

        <strong className="pill-shell__headline">{headline}</strong>
        <p className="pill-shell__summary">{summary}</p>
      </button>

      <div className="pill-actions">
        {assistantWorkbench && activeWorkbenchSummary ? (
          <button
            type="button"
            className="pill-action"
            onClick={() => {
              setShowWorkbench(true);
            }}
          >
            {activeWorkbenchSummary.resumeLabel}
          </button>
        ) : null}
        {canOpenGate ? (
          <button
            type="button"
            className="pill-action pill-action--gate"
            onClick={() => {
              void handleOpenGate();
            }}
          >
            Review gate
          </button>
        ) : null}
        {badgeCount > 0 ? (
          <button
            type="button"
            className="pill-action"
            onClick={() => {
              void handleOpenStudio("notifications");
            }}
          >
            Open inbox
          </button>
        ) : null}
        <button
          type="button"
          className="pill-action"
          onClick={() => {
            void handleOpenStudio("autopilot");
          }}
        >
          Studio
        </button>
        <button
          type="button"
          className="pill-action pill-action--quiet"
          onClick={() => {
            void hidePillShell();
          }}
        >
          Hide
        </button>
      </div>

      {focusActionError ? (
        <p className="pill-focus pill-focus--error">{focusActionError}</p>
      ) : null}

      {focusItem ? (
        <section className="pill-focus">
          <div className="pill-focus__head">
            <span className="pill-focus__eyebrow">
              {isInterventionRecord(focusItem) ? "Intervention" : "Assistant"}
            </span>
            <span className="pill-focus__badge">
              {humanizeOperatorNotificationValue(focusItem.severity)}
            </span>
          </div>

          <strong className="pill-focus__title">{focusItem.title}</strong>
          <p className="pill-focus__copy">{focusItem.summary}</p>

          <div className="pill-focus__meta">
            <span>{humanizeOperatorNotificationValue(focusItem.status)}</span>
            <span>{focusItem.source.serviceName}</span>
            {focusItem.target ? (
              <span>{humanizeOperatorNotificationValue(focusItem.target.kind)}</span>
            ) : null}
          </div>

          {focusDetailLoading && focusItem.target ? (
            <p className="pill-focus__snippet">Loading target detail…</p>
          ) : null}
          {!focusDetailLoading && focusTargetSummary ? (
            <p className="pill-focus__snippet">{focusTargetSummary}</p>
          ) : null}
          {focusWorkbenchSummary ? (
            <div className="pill-focus__workbench">
              <span className="pill-focus__workbench-eyebrow">
                {focusWorkbenchSummary.title}
              </span>
              <strong className="pill-focus__workbench-title">
                {focusWorkbenchSummary.ctaLabel}
              </strong>
              <p className="pill-focus__workbench-copy">
                {focusWorkbenchSummary.summary}
              </p>
              {focusWorkbenchSummary.meta.length > 0 ? (
                <div className="pill-focus__meta pill-focus__meta--workbench">
                  {focusWorkbenchSummary.meta.map((value) => (
                    <span key={value}>{value}</span>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}

          {isInterventionRecord(focusItem) ? (
            <div className="pill-focus__actions">
              <button
                type="button"
                className="pill-action pill-action--gate"
                onClick={() => {
                  void handleOpenGate();
                }}
              >
                Review in Gate
              </button>
              {isLocalEngineIntervention(focusItem) ? (
                <button
                  type="button"
                  className="pill-action"
                  onClick={() => {
                    void handleOpenStudio("capabilities");
                  }}
                >
                  Open capabilities
                </button>
              ) : null}
              <button
                type="button"
                className="pill-action pill-action--quiet"
                onClick={() => {
                  void handleDeferTopIntervention();
                }}
              >
                {focusItem.status === "new" ? "Mark seen" : "Snooze 1h"}
              </button>
            </div>
          ) : (
            <div className="pill-focus__actions">
              {replyWorkbenchSession ? (
                <button
                  type="button"
                  className="pill-action"
                  onClick={() => {
                    openReplyComposer(replyWorkbenchSession);
                    setShowWorkbench(true);
                  }}
                >
                  Reply workbench
                </button>
              ) : null}
              {meetingPrepWorkbenchSession ? (
                <button
                  type="button"
                  className="pill-action"
                  onClick={() => {
                    openMeetingPrep(meetingPrepWorkbenchSession);
                    setShowWorkbench(true);
                  }}
                >
                  Prep workbench
                </button>
              ) : null}
              <button
                type="button"
                className="pill-action pill-action--gate"
                onClick={() => {
                  void handlePrimaryAssistantAction();
                }}
              >
                {displayNotificationActionLabel(primaryAssistantAction?.label)}
              </button>
              <button
                type="button"
                className="pill-action"
                onClick={() => {
                  void handleOpenGate();
                }}
              >
                Review in Gate
              </button>
              <button
                type="button"
                className="pill-action pill-action--quiet"
                onClick={() => {
                  void handleDeferTopAssistant();
                }}
              >
              {focusAssistantNotification?.status === "new"
                ? "Mark seen"
                : "Snooze 1h"}
              </button>
            </div>
          )}
        </section>
      ) : null}

      {assistantWorkbench && showWorkbench ? (
        <section className="pill-workbench-stage">
          {retainedWorkbenchEvidenceThreadId ? (
            <div className="pill-workbench-trace">
              <div className="pill-workbench-trace__head">
                <strong>Retained trace</strong>
                <span>Kernel-backed workbench events</span>
              </div>
              {retainedWorkbenchTrace.loading ? (
                <p className="pill-workbench-trace__note">
                  Loading retained trace summary...
                </p>
              ) : retainedWorkbenchTrace.error ? (
                <p className="pill-workbench-trace__note pill-workbench-trace__note--error">
                  Retained trace unavailable: {retainedWorkbenchTrace.error}
                </p>
              ) : (
                <div className="pill-workbench-trace__grid">
                  <div className="pill-workbench-trace__card">
                    <strong>{retainedWorkbenchTrace.events.length}</strong>
                    <span>Persisted events</span>
                  </div>
                  <div className="pill-workbench-trace__card">
                    <strong>{retainedWorkbenchTrace.artifacts.length}</strong>
                    <span>Report artifacts</span>
                  </div>
                  <div className="pill-workbench-trace__card">
                    <strong>{latestRetainedWorkbenchEvent?.title ?? "Awaiting event"}</strong>
                    <span>Latest event</span>
                  </div>
                  <div className="pill-workbench-trace__card">
                    <strong>{latestRetainedWorkbenchArtifact?.title ?? "No report yet"}</strong>
                    <span>Latest artifact</span>
                  </div>
                </div>
              )}
            </div>
          ) : null}
          <AssistantWorkbenchView
            session={assistantWorkbench}
            runtime={workbenchRuntime}
            onBack={() => {
              setShowWorkbench(false);
            }}
            onOpenNotifications={() => {
              setShowWorkbench(false);
              void handleOpenStudio("notifications");
            }}
            onOpenAutopilot={(intent) => {
              setShowWorkbench(false);
              void openStudioAutopilotIntent(intent);
            }}
          />
        </section>
      ) : null}
    </div>
  );
}
