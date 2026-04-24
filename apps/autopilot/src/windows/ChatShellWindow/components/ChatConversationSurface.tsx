import type { ReactNode } from "react";
import { icons } from "./Icons";

export function ChatConversationSurface({
  sidebar,
  artifactVisible,
  artifactMenuVisible,
  artifactDrawerVisible,
  artifactDrawerAvailable,
  conversationSurface,
  artifactDrawer,
  onNewSession,
  onOpenCommandPalette,
  onOpenSettings,
  onToggleArtifactDrawer,
}: {
  sidebar: ReactNode;
  artifactVisible: boolean;
  artifactMenuVisible: boolean;
  artifactDrawerVisible: boolean;
  artifactDrawerAvailable: boolean;
  conversationSurface: ReactNode;
  artifactDrawer: ReactNode;
  onNewSession: () => void;
  onOpenCommandPalette: () => void;
  onOpenSettings: () => void;
  onToggleArtifactDrawer: () => void;
}) {
  return (
    <div
      className={`spot-chat-shell ${
        artifactVisible ? "is-artifact-open" : "is-artifact-collapsed"
      } ${artifactMenuVisible ? "is-artifact-menu-open" : ""}`}
    >
      <div className="spot-chat-sidebar-shell-item">{sidebar}</div>
      <div className="spot-chat-conversation-shell-item">
        <div className="spot-workbench-chat-topbar" aria-label="Chat workbench toolbar">
          <div className="spot-workbench-chat-tab is-active">Chat</div>
          <div className="spot-workbench-chat-actions">
            <button type="button" onClick={onNewSession} title="New session">
              {icons.plus}
            </button>
            <button
              type="button"
              onClick={onOpenCommandPalette}
              title="Open Chat command palette"
            >
              {icons.search}
            </button>
            <button type="button" onClick={onOpenSettings} title="Open Chat settings">
              {icons.settings}
            </button>
            {artifactDrawerAvailable ? (
              <button
                type="button"
                className={artifactVisible ? "is-active" : ""}
                onClick={onToggleArtifactDrawer}
                title={artifactVisible ? "Hide artifacts" : "Show artifacts"}
              >
                {icons.expand}
              </button>
            ) : null}
          </div>
        </div>
        {conversationSurface}
      </div>
      {artifactDrawerVisible ? artifactDrawer : null}
    </div>
  );
}
