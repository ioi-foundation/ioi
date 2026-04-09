import type { ReactNode } from "react";
import { ScrollToBottom } from "./ScrollToBottom";

export function OverlayConversationSurface({
  isStudioVariant,
  conversationContent,
  showScrollButton,
  onScrollToBottom,
  artifactPanelVisible,
  artifactPanel,
}: {
  isStudioVariant: boolean;
  conversationContent: ReactNode;
  showScrollButton: boolean;
  onScrollToBottom: () => void;
  artifactPanelVisible: boolean;
  artifactPanel: ReactNode;
}) {
  return (
    <>
      <div className={`spot-main ${isStudioVariant ? "spot-main--studio" : ""}`}>
        {conversationContent}
      </div>
      <ScrollToBottom visible={showScrollButton} onClick={onScrollToBottom} />
      {artifactPanelVisible ? artifactPanel : null}
    </>
  );
}
