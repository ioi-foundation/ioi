import type { ReactNode } from "react";
import {
  OperatorChatPane,
  type OperatorChatPaneAction,
  type OperatorChatPaneMode,
} from "@ioi/workspace-substrate";
import { icons } from "../../../components/ui/icons";

export function ChatConversationSurface({
  mode = "full",
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
  paneLeadingAction,
  paneTrailingAction,
}: {
  mode?: OperatorChatPaneMode;
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
  paneLeadingAction?: ReactNode;
  paneTrailingAction?: ReactNode;
}) {
  const primaryActions: OperatorChatPaneAction[] = [
    {
      id: "new",
      label: "New session",
      icon: icons.plus,
      onClick: onNewSession,
    },
    {
      id: "settings",
      label: "Open Chat settings",
      icon: icons.settings,
      onClick: onOpenSettings,
    },
    {
      id: "more",
      label: "More chat actions",
      icon: icons.more,
      onClick: onOpenCommandPalette,
    },
  ];
  const secondaryActions: OperatorChatPaneAction[] = artifactDrawerAvailable
    ? [
        {
          id: artifactVisible ? "collapse" : "expand",
          label: artifactVisible ? "Hide artifacts" : "Show artifacts",
          icon: icons.expand,
          active: artifactVisible,
          onClick: onToggleArtifactDrawer,
        },
      ]
    : [];

  return (
    <OperatorChatPane
      mode={mode}
      className={`spot-chat-shell ${
        artifactVisible ? "is-artifact-open" : "is-artifact-collapsed"
      } ${artifactMenuVisible ? "is-artifact-menu-open" : ""} ${
        sidebar ? "" : "is-sidebar-hidden"
      }`}
      label="Chat"
      sidebar={sidebar}
      artifactDrawer={artifactDrawer}
      artifactDrawerVisible={artifactDrawerVisible}
      artifactMenuVisible={artifactMenuVisible}
      leadingControls={paneLeadingAction}
      primaryActions={primaryActions}
      secondaryActions={secondaryActions}
      trailingControls={paneTrailingAction}
      dataOperatorChatPane={mode}
      dataInspectionTarget="operator-chat-pane"
    >
      {conversationSurface}
    </OperatorChatPane>
  );
}
