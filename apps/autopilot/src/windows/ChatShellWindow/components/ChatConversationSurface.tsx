import type { ReactNode } from "react";
import {
  Codicon,
  OperatorChatPane,
  type OperatorChatEmptyStateModel,
  type OperatorChatPaneAction,
  type OperatorChatPaneMode,
} from "@ioi/workspace-substrate";

export function ChatConversationSurface({
  mode = "full",
  sidebar,
  artifactVisible,
  artifactMenuVisible,
  artifactDrawerVisible,
  artifactDrawerAvailable,
  conversationSurface,
  composer,
  emptyState,
  suggestedActions,
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
  composer?: ReactNode;
  emptyState?: OperatorChatEmptyStateModel;
  suggestedActions?: ReactNode;
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
      label: "New Chat (Ctrl+N)",
      icon: <Codicon name="plus" />,
      onClick: onNewSession,
    },
    {
      id: "new-options",
      label: "New Chat",
      icon: <Codicon name="chevron-down" />,
      onClick: onOpenCommandPalette,
    },
    {
      id: "settings",
      label: "Configure Chat",
      icon: <Codicon name="gear" />,
      onClick: onOpenSettings,
    },
    {
      id: "more",
      label: "Views and More Actions...",
      icon: <Codicon name="toolbar-more" />,
      onClick: onOpenCommandPalette,
    },
  ];
  const secondaryActions: OperatorChatPaneAction[] = artifactDrawerAvailable
    ? [
        {
          id: artifactVisible ? "restore" : "maximize",
          label: artifactVisible
            ? "Restore Secondary Side Bar Size"
            : "Maximize Secondary Side Bar Size",
          icon: (
            <Codicon
              name={
                artifactVisible
                  ? "auxiliarybar-restore"
                  : "auxiliarybar-maximize"
              }
            />
          ),
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
      emptyState={emptyState}
      suggestedActions={suggestedActions}
      composer={composer}
      dataOperatorChatPane={mode}
      dataInspectionTarget="operator-chat-pane"
    >
      {conversationSurface}
    </OperatorChatPane>
  );
}
