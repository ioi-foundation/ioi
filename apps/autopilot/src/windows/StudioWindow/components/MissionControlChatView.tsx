import type { AgentRuntime } from "@ioi/agent-ide";
import { AssistantWorkbenchView } from "./AssistantWorkbenchView";
import { StudioCopilotView } from "./StudioCopilot";
import type { AssistantWorkbenchSession } from "../../../types";

interface MissionControlChatViewProps {
  surface: "chat" | "reply-composer" | "meeting-prep";
  session: AssistantWorkbenchSession | null;
  runtime: AgentRuntime;
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  onBackToInbox: () => void;
  onOpenInbox: () => void;
  onOpenAutopilot: (intent: string) => void;
}

function chatCopy(surface: MissionControlChatViewProps["surface"]): {
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

export function MissionControlChatView({
  surface,
  session,
  runtime,
  seedIntent,
  onConsumeSeedIntent,
  onBackToInbox,
  onOpenInbox,
  onOpenAutopilot,
}: MissionControlChatViewProps) {
  const copy = chatCopy(surface);
  const isPrimaryConversation = surface === "chat";

  return (
    <div
      className={`mission-control-view ${isPrimaryConversation ? "mission-control-view--chat" : ""}`}
    >
      {!isPrimaryConversation ? (
        <header className="mission-control-header">
          <div className="mission-control-header-copy">
            <span className="mission-control-kicker">Talk</span>
            <h2>{copy.title}</h2>
            <p>{copy.description}</p>
          </div>
        </header>
      ) : null}

      <div className="mission-control-stage">
        <div
          className={`mission-control-stage-frame ${
            isPrimaryConversation ? "mission-control-stage-frame--chat" : ""
          }`}
        >
          {surface === "chat" ? (
            <StudioCopilotView
              seedIntent={seedIntent}
              onConsumeSeedIntent={onConsumeSeedIntent}
            />
          ) : (
            <AssistantWorkbenchView
              session={session}
              runtime={runtime}
              onBack={onBackToInbox}
              onOpenNotifications={onOpenInbox}
              onOpenAutopilot={onOpenAutopilot}
            />
          )}
        </div>
      </div>
    </div>
  );
}
