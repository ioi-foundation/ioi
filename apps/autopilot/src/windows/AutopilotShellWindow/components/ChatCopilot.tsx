// Compatibility aliases remain so the shared chat shell can re-export this view.
import type { AssistantSessionRuntime } from "@ioi/agent-ide";
import { ChatShellWindow } from "../../ChatShellWindow";

interface ChatCopilotViewProps {
  presentation?: "standalone" | "embedded-pane";
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  sessionRuntime: AssistantSessionRuntime;
  workspaceRootHint?: string | null;
  workspaceNameHint?: string | null;
}

export function ChatCopilotView({
  presentation = "standalone",
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
      seedIntent={seedIntent}
      onConsumeSeedIntent={onConsumeSeedIntent}
      sessionRuntime={sessionRuntime}
      workspaceRootHint={workspaceRootHint}
      workspaceNameHint={workspaceNameHint}
    />
  );
}
