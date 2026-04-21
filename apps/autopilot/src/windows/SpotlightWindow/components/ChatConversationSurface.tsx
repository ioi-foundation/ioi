import type { ReactNode } from "react";

export function ChatConversationSurface({
  sidebar,
  artifactVisible,
  artifactMenuVisible,
  artifactDrawerVisible,
  conversationSurface,
  artifactDrawer,
}: {
  sidebar: ReactNode;
  artifactVisible: boolean;
  artifactMenuVisible: boolean;
  artifactDrawerVisible: boolean;
  conversationSurface: ReactNode;
  artifactDrawer: ReactNode;
}) {
  return (
    <div
      className={`spot-chat-shell ${
        artifactVisible ? "is-artifact-open" : "is-artifact-collapsed"
      } ${artifactMenuVisible ? "is-artifact-menu-open" : ""}`}
    >
      <div className="spot-chat-sidebar-shell-item">{sidebar}</div>
      <div className="spot-chat-conversation-shell-item">{conversationSurface}</div>
      {artifactDrawerVisible ? artifactDrawer : null}
    </div>
  );
}
