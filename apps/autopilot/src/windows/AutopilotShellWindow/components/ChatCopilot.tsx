// Compatibility aliases remain so the shared chat shell can re-export this view.
import type { ReactNode } from "react";
import type { AssistantSessionRuntime } from "@ioi/agent-ide";
import { ChatShellWindow } from "../../ChatShellWindow";

interface ChatCopilotViewProps {
  presentation?: "standalone" | "embedded-pane";
  paneLeadingAction?: ReactNode;
  paneTrailingAction?: ReactNode;
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  sessionRuntime: AssistantSessionRuntime;
  workspaceRootHint?: string | null;
  workspaceNameHint?: string | null;
}

export function ChatCopilotView({
  presentation = "standalone",
  paneLeadingAction,
  paneTrailingAction,
  seedIntent,
  onConsumeSeedIntent,
  sessionRuntime,
  workspaceRootHint,
  workspaceNameHint,
}: ChatCopilotViewProps) {
  return (
    <ChatShellWindow
      variant="chat"
      presentationMode={presentation}
      paneLeadingAction={paneLeadingAction}
      paneTrailingAction={paneTrailingAction}
      seedIntent={seedIntent}
      onConsumeSeedIntent={onConsumeSeedIntent}
      sessionRuntime={sessionRuntime}
      workspaceRootHint={workspaceRootHint}
      workspaceNameHint={workspaceNameHint}
    />
  );
}
