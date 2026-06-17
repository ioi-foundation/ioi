import type { ReactNode } from "react";
import { ScrollToBottom } from "./ScrollToBottom";

export function OverlayConversationSurface({
  isChatVariant,
  conversationContent,
  showScrollButton,
  onScrollToBottom,
  artifactPanelVisible,
  artifactPanel,
}: {
  isChatVariant: boolean;
  conversationContent: ReactNode;
  showScrollButton: boolean;
  onScrollToBottom: () => void;
  artifactPanelVisible: boolean;
  artifactPanel: ReactNode;
}) {
  return (
    <>
      <div className={`spot-main ${isChatVariant ? "spot-main--chat" : ""}`}>
        {conversationContent}
      </div>
      <ScrollToBottom visible={showScrollButton} onClick={onScrollToBottom} />
      {artifactPanelVisible ? artifactPanel : null}
    </>
  );
}
