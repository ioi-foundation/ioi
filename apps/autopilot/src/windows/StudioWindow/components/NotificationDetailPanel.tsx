import { OperatorNotificationDetail } from "../../../components/OperatorNotificationDetail";
import type {
  AssistantWorkbenchSession,
  AssistantNotificationRecord,
  InterventionRecord,
} from "../../../types";

interface NotificationDetailPanelProps {
  item: AssistantNotificationRecord | InterventionRecord | null;
  onClose: () => void;
  onOpenAutopilot: () => void;
  onOpenLocalEngine: () => void;
  onOpenReplyComposer: (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => void;
  onOpenMeetingPrep: (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => void;
  onOpenIntegrations: (connectorId?: string | null) => void;
  onOpenShield: (connectorId?: string | null) => void;
}

export function NotificationDetailPanel({
  item,
  onClose,
  onOpenAutopilot,
  onOpenLocalEngine,
  onOpenReplyComposer,
  onOpenMeetingPrep,
  onOpenIntegrations,
  onOpenShield,
}: NotificationDetailPanelProps) {
  return (
    <OperatorNotificationDetail
      item={item}
      containerTag="aside"
      onClose={onClose}
      onOpenChat={onOpenAutopilot}
      onOpenReplyComposer={onOpenReplyComposer}
      onOpenMeetingPrep={onOpenMeetingPrep}
      onOpenCapabilities={onOpenIntegrations}
      onOpenPolicy={onOpenShield}
      onOpenLocalEngine={onOpenLocalEngine}
      emptyState={{
        eyebrow: "Detail",
        title: "Select an inbox item",
        description:
          "Select an inbox item to inspect context, risk, and the underlying record without leaving the queue.",
      }}
      copy={{
        close: "Close",
        openChat: "Open chat",
        openCapabilities: "Open Capabilities",
        openPolicy: "Open Shield",
        openLocalEngine: "Open local engine",
      }}
      classNames={{
        container: "notifications-detail-pane",
        emptyContainer: "notifications-detail-pane-empty",
        head: "notifications-detail-head",
        eyebrow: "notifications-card-eyebrow",
        quietButton: "notifications-quiet-button",
        meta: "notifications-detail-meta",
        section: "notifications-detail-section",
        card: "notifications-detail-card",
        engineCard: "notifications-detail-card notifications-detail-card-engine",
        cardHead: "notifications-detail-card-head",
        tags: "notifications-detail-tags",
        actions: "notifications-detail-actions",
        primaryButton: "notifications-primary-button",
        secondaryButton: "notifications-secondary-button",
        error: "notifications-error",
        loadingCard: "notifications-empty-card",
        target: {
          section: "notifications-detail-section",
          meta: "notifications-detail-meta",
          snippet: "notifications-detail-snippet",
          stack: "notifications-detail-stack",
          card: "notifications-detail-card",
          cardHead: "notifications-detail-card-head",
          tags: "notifications-detail-tags",
          actions: "notifications-detail-actions",
          primaryButton: "notifications-primary-button",
          secondaryButton: "notifications-secondary-button",
          quietButton: "notifications-quiet-button",
        },
      }}
    />
  );
}
