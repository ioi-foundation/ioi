import { OperatorNotificationDetail } from "../../components/OperatorNotificationDetail";
import type {
  AssistantNotificationRecord,
  AssistantWorkbenchSession,
  InterventionRecord,
} from "../../types";

type GateNotificationDetailProps = {
  item: AssistantNotificationRecord | InterventionRecord | null;
  onClose: () => void;
  onOpenChat: () => void;
  onOpenInbox: () => void;
  onOpenReplyComposer: (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => void;
  onOpenMeetingPrep: (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => void;
  onOpenCapabilities: (connectorId?: string | null) => void;
  onOpenPolicy: (connectorId?: string | null) => void;
  onOpenLocalEngine: () => void;
};

export function GateNotificationDetail({
  item,
  onClose,
  onOpenChat,
  onOpenInbox,
  onOpenReplyComposer,
  onOpenMeetingPrep,
  onOpenCapabilities,
  onOpenPolicy,
  onOpenLocalEngine,
}: GateNotificationDetailProps) {
  return (
    <OperatorNotificationDetail
      item={item}
      containerTag="section"
      onClose={onClose}
      onOpenChat={onOpenChat}
      onOpenInbox={onOpenInbox}
      onOpenReplyComposer={onOpenReplyComposer}
      onOpenMeetingPrep={onOpenMeetingPrep}
      onOpenCapabilities={onOpenCapabilities}
      onOpenPolicy={onOpenPolicy}
      onOpenLocalEngine={onOpenLocalEngine}
      emptyState={{
        eyebrow: "Inspection",
        title: "Select a queue item",
        description:
          "Pick an intervention or assistant prompt above to inspect its target and context without leaving Gate.",
      }}
      copy={{
        close: "Clear",
        openChat: "Open chat",
        openInbox: "Open inbox",
        openCapabilities: "Open capabilities",
        openPolicy: "Open policy",
        openLocalEngine: "Open local engine",
      }}
      classNames={{
        container: "gate-window-detail",
        emptyContainer: "gate-window-detail-empty",
        head: "gate-window-detail-head",
        eyebrow: "gate-window-kicker",
        quietButton: "gate-window-quiet-button",
        meta: "gate-window-detail-meta",
        section: "gate-window-detail-section",
        card: "gate-window-detail-card",
        engineCard: "gate-window-detail-card gate-window-detail-card-engine",
        cardHead: "gate-window-detail-card-head",
        tags: "gate-window-detail-tags",
        actions: "gate-window-detail-actions",
        primaryButton: "gate-window-primary-button",
        secondaryButton: "gate-window-secondary-button",
        error: "gate-window-error",
        loadingCard: "gate-window-detail-card",
        target: {
          section: "gate-window-detail-section",
          meta: "gate-window-detail-meta",
          snippet: "gate-window-detail-snippet",
          stack: "gate-window-detail-stack",
          card: "gate-window-detail-card",
          cardHead: "gate-window-detail-card-head",
          tags: "gate-window-detail-tags",
          actions: "gate-window-detail-actions",
          primaryButton: "gate-window-primary-button",
          secondaryButton: "gate-window-secondary-button",
          quietButton: "gate-window-quiet-button",
          secondaryLink: "gate-window-secondary-link",
        },
      }}
    />
  );
}
