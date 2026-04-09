import type { ReactNode } from "react";

export function StudioConversationSurface({
  artifactVisible,
  artifactMenuVisible,
  artifactDrawerVisible,
  conversationSurface,
  artifactDrawer,
}: {
  artifactVisible: boolean;
  artifactMenuVisible: boolean;
  artifactDrawerVisible: boolean;
  conversationSurface: ReactNode;
  artifactDrawer: ReactNode;
}) {
  return (
    <div
      className={`spot-studio-shell ${
        artifactVisible ? "is-artifact-open" : "is-artifact-collapsed"
      } ${artifactMenuVisible ? "is-artifact-menu-open" : ""}`}
    >
      <div className="spot-studio-conversation-shell-item">{conversationSurface}</div>
      {artifactDrawerVisible ? artifactDrawer : null}
    </div>
  );
}
