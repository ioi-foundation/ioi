import type { ReactNode } from "react";
import type { AgentWorkbenchRuntime, AssistantSessionRuntime } from "@ioi/hypervisor-workbench";
import { ChatCopilotView } from "../../windows/HypervisorShellWindow/components/ChatCopilot";
import type { AssistantWorkbenchSession } from "../../types";
import { AssistantWorkbenchView } from "./components/AssistantWorkbenchView";

type SessionCapableRuntime = AgentWorkbenchRuntime & AssistantSessionRuntime;

interface ConversationSurfaceViewProps {
  surface: "chat" | "reply-composer" | "meeting-prep";
  session: AssistantWorkbenchSession | null;
  runtime: SessionCapableRuntime;
  embedded?: boolean;
  chatPresentation?: "standalone" | "embedded-pane";
  paneLeadingAction?: ReactNode;
  paneTrailingAction?: ReactNode;
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  onBackToInbox: () => void;
  onOpenInbox: () => void;
  onOpenHypervisor: (intent: string) => void;
}

function chatCopy(surface: ConversationSurfaceViewProps["surface"]): {
  title: string;
  description: string;
} {
  if (surface === "reply-composer") {
    return {
      title: "Reply composer",
      description: "Finish the draft in a tighter handoff surface, then return to conversation.",
    };
  }

  if (surface === "meeting-prep") {
    return {
      title: "Meeting brief",
      description: "Shape the brief in context, then hand control back to the main thread.",
    };
  }

  return {
    title: "Conversation",
    description: "Drive work from language first. Evidence and deep inspection open only when needed.",
  };
}

export function ConversationSurfaceView({
  surface,
  session,
  runtime,
  embedded = false,
  chatPresentation,
  paneLeadingAction,
  paneTrailingAction,
  seedIntent,
  onConsumeSeedIntent,
  onBackToInbox,
  onOpenInbox,
  onOpenHypervisor,
}: ConversationSurfaceViewProps) {
  const copy = chatCopy(surface);
  const isPrimaryConversation = surface === "chat";
  const showHeader = !isPrimaryConversation && !embedded;

  return (
    <div
      className={`hypervisor-surface-view ${
        isPrimaryConversation ? "hypervisor-surface-view--chat" : ""
      } ${embedded ? "hypervisor-surface-view--pane" : ""}`}
    >
      {showHeader ? (
        <header className="hypervisor-surface-header">
          <div className="hypervisor-surface-header-copy">
            <span className="hypervisor-surface-kicker">Talk</span>
            <h2>{copy.title}</h2>
            <p>{copy.description}</p>
          </div>
        </header>
      ) : null}

      <div className="hypervisor-surface-stage">
        <div
          className={`hypervisor-surface-stage-frame ${
            isPrimaryConversation || embedded
              ? "hypervisor-surface-stage-frame--chat"
              : ""
          }`}
        >
          {surface === "chat" ? (
            <ChatCopilotView
              presentation={
                chatPresentation ?? (embedded ? "embedded-pane" : "standalone")
              }
              paneLeadingAction={paneLeadingAction}
              paneTrailingAction={paneTrailingAction}
              seedIntent={seedIntent}
              onConsumeSeedIntent={onConsumeSeedIntent}
              sessionRuntime={runtime}
            />
          ) : (
            <AssistantWorkbenchView
              session={session}
              runtime={runtime}
              onBack={onBackToInbox}
              onOpenNotifications={onOpenInbox}
              onOpenHypervisor={onOpenHypervisor}
            />
          )}
        </div>
      </div>
    </div>
  );
}
