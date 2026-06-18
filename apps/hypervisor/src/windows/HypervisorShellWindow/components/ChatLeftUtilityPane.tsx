import type {
  AgentWorkbenchRuntime,
  AssistantSessionRuntime,
} from "@ioi/hypervisor-workbench";
import { Codicon } from "@ioi/workspace-substrate";
import type { AssistantWorkbenchSession } from "../../../types";
import { ConversationSurfaceView } from "../../../surfaces/Conversation";

type SessionCapableRuntime = AgentWorkbenchRuntime & AssistantSessionRuntime;

interface ChatLeftUtilityPaneProps {
  surface: "chat" | "reply-composer" | "meeting-prep";
  session: AssistantWorkbenchSession | null;
  runtime: SessionCapableRuntime;
  maximized: boolean;
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  onClose: () => void;
  onToggleMaximize: () => void;
  onBackToInbox: () => void;
  onOpenInbox: () => void;
  onOpenHypervisor: (intent: string) => void;
}

export function ChatLeftUtilityPane({
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
  onOpenHypervisor,
}: ChatLeftUtilityPaneProps) {
  const usesIntegratedChatChrome = surface === "chat";
  const layoutControlLabel = maximized
    ? "Restore Secondary Side Bar Size"
    : "Maximize Secondary Side Bar Size";
  const layoutControl = (
    <button
      type="button"
      className="chat-chat-pane-control"
      onClick={onToggleMaximize}
      aria-label={layoutControlLabel}
      title={layoutControlLabel}
    >
      <Codicon
        name={maximized ? "auxiliarybar-restore" : "auxiliarybar-maximize"}
      />
    </button>
  );
  const closeControl = (
    <button
      type="button"
      className="chat-chat-pane-control"
      onClick={onClose}
      aria-label="Hide Secondary Side Bar (Ctrl+Alt+B)"
      title="Hide Secondary Side Bar (Ctrl+Alt+B)"
    >
      <Codicon name="auxiliarybar-close" />
    </button>
  );

  return (
    <aside
      className={`operator-chat-pane-shell ${
        maximized ? "is-maximized" : ""
      }`}
      aria-label="Operator chat"
    >
      {usesIntegratedChatChrome ? null : (
        <div className="chat-chat-pane-utility-controls">
          {layoutControl}
          {closeControl}
        </div>
      )}
      <ConversationSurfaceView
        embedded
        chatPresentation={maximized ? "standalone" : "embedded-pane"}
        paneLeadingAction={usesIntegratedChatChrome ? layoutControl : undefined}
        paneTrailingAction={usesIntegratedChatChrome ? closeControl : undefined}
        surface={surface}
        session={session}
        runtime={runtime}
        seedIntent={seedIntent}
        onConsumeSeedIntent={onConsumeSeedIntent}
        onBackToInbox={onBackToInbox}
        onOpenInbox={onOpenInbox}
        onOpenHypervisor={onOpenHypervisor}
      />
    </aside>
  );
}
