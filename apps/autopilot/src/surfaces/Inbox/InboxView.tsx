import { useEffect, useMemo, useState } from "react";
import { OperatorInboxQueueColumns } from "../../components/OperatorInboxQueueColumns";
import { useOperatorNotifications } from "../../hooks/useOperatorNotifications";
import {
  buildInboxQueueItems,
  filterInboxQueueItems,
  getInboxLaneCounts,
  getInboxSummaryCounts,
  type InboxLane,
} from "../../lib/operatorInboxQueue";
import { runAssistantNotificationAction } from "../../lib/operatorNotifications";
import { NotificationDetailPanel } from "./NotificationDetailPanel";
import type { AssistantNotificationRecord, AssistantWorkbenchSession } from "../../types";

interface InboxViewProps {
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

export function InboxView({
  onOpenAutopilot,
  onOpenIntegrations,
  onOpenLocalEngine,
  onOpenShield,
  onOpenSettings,
  onOpenReplyComposer,
  onOpenMeetingPrep,
}: InboxViewProps) {
  const {
    interventions,
    assistantNotifications,
    loading,
    error,
    updateInterventionStatus,
    updateAssistantStatus,
  } = useOperatorNotifications();
  const [searchDraft, setSearchDraft] = useState("");
  const [activeLane, setActiveLane] = useState<InboxLane>("needs_action");
  const [actionError, setActionError] = useState<string | null>(null);
  const [selectedItemKey, setSelectedItemKey] = useState<string | null>(null);

  const handleAssistantAction = async (
    item: AssistantNotificationRecord,
    actionId: string,
  ) => {
    setActionError(null);

    try {
      await runAssistantNotificationAction({
        item,
        actionId,
        updateAssistantStatus,
        onOpenAutopilot,
        onOpenIntegrations,
        onOpenShield,
        onOpenSettings,
        onOpenTarget: (nextItem) => {
          setSelectedItemKey(`assistant:${nextItem.itemId}`);
        },
      });
    } catch (nextError) {
      setActionError(String(nextError));
    }
  };

  const queueItems = useMemo(
    () => buildInboxQueueItems(interventions, assistantNotifications),
    [assistantNotifications, interventions],
  );

  const summaryCounts = useMemo(
    () => getInboxSummaryCounts(queueItems),
    [queueItems],
  );

  const laneCounts = useMemo(() => getInboxLaneCounts(queueItems), [queueItems]);

  const filteredQueueItems = useMemo(() => {
    return filterInboxQueueItems(queueItems, activeLane, searchDraft);
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
        <OperatorInboxQueueColumns
          activeLane={activeLane}
          laneCounts={laneCounts}
          searchDraft={searchDraft}
          filteredQueueItems={filteredQueueItems}
          selectedItemKey={selectedItemKey}
          embedded
          actionError={null}
          onLaneChange={setActiveLane}
          onSearchDraftChange={setSearchDraft}
          onSelectItemKey={setSelectedItemKey}
          onToolbarAction={onOpenSettings}
          onOpenAutopilot={onOpenAutopilot}
          onOpenLocalEngine={onOpenLocalEngine}
          onAssistantAction={handleAssistantAction}
          onDeferAssistant={(item) =>
            updateAssistantStatus(
              item.itemId,
              item.status === "new" ? "seen" : "snoozed",
              item.status === "new" ? undefined : Date.now() + 60 * 60 * 1000,
            ).catch((nextError) => {
              setActionError(String(nextError));
            })
          }
          onDeferIntervention={(item) =>
            updateInterventionStatus(
              item.itemId,
              item.status === "new" ? "seen" : "pending",
              item.status === "new" ? undefined : Date.now() + 60 * 60 * 1000,
            ).catch((nextError) => {
              setActionError(String(nextError));
            })
          }
        />

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

export const NotificationsView = InboxView;
