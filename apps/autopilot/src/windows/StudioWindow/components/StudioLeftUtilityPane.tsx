import type { AgentRuntime } from "@ioi/agent-ide";
import type { AssistantWorkbenchSession } from "../../../types";
import { MissionControlChatView } from "./MissionControlChatView";

interface StudioLeftUtilityPaneProps {
  surface: "chat" | "reply-composer" | "meeting-prep";
  session: AssistantWorkbenchSession | null;
  runtime: AgentRuntime;
  maximized: boolean;
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  onClose: () => void;
  onToggleMaximize: () => void;
  onBackToInbox: () => void;
  onOpenInbox: () => void;
  onOpenAutopilot: (intent: string) => void;
}

export function StudioLeftUtilityPane({
  surface,
  session,
  runtime,
  maximized,
  seedIntent,
  onConsumeSeedIntent,
  onClose,
  onToggleMaximize,
  onBackToInbox,
  onOpenInbox,
  onOpenAutopilot,
}: StudioLeftUtilityPaneProps) {
  return (
    <aside
      className={`studio-chat-pane ${maximized ? "is-maximized" : ""}`}
      aria-label="Operator chat"
    >
      <div className="studio-chat-pane-controls">
        <button
          type="button"
          className="studio-chat-pane-control"
          onClick={onToggleMaximize}
          aria-label={maximized ? "Restore chat layout" : "Full screen chat"}
          title={maximized ? "Restore chat layout" : "Full screen chat"}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            {maximized ? (
              <>
                <path d="M8 4H4v4" />
                <path d="M4 4l6 6" />
                <path d="M16 20h4v-4" />
                <path d="M20 20l-6-6" />
              </>
            ) : (
              <>
                <path d="M15 4h5v5" />
                <path d="M14 10l6-6" />
                <path d="M9 20H4v-5" />
                <path d="M10 14l-6 6" />
              </>
            )}
          </svg>
        </button>

        <button
          type="button"
          className="studio-chat-pane-control"
          onClick={onClose}
          aria-label="Close chat pane"
          title="Close chat pane"
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M18 6 6 18" />
            <path d="m6 6 12 12" />
          </svg>
        </button>
      </div>

      <div className="studio-chat-pane-body">
        <MissionControlChatView
          embedded
          surface={surface}
          session={session}
          runtime={runtime}
          seedIntent={seedIntent}
          onConsumeSeedIntent={onConsumeSeedIntent}
          onBackToInbox={onBackToInbox}
          onOpenInbox={onOpenInbox}
          onOpenAutopilot={onOpenAutopilot}
        />
      </div>
    </aside>
  );
}
