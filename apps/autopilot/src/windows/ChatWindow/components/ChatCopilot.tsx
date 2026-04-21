// Compatibility aliases remain so the shared chat shell can re-export this view.
import type { AssistantSessionRuntime } from "@ioi/agent-ide";
import { SpotlightWindow } from "../../SpotlightWindow";

interface ChatCopilotViewProps {
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  sessionRuntime: AssistantSessionRuntime;
}

export function ChatCopilotView({
  seedIntent,
  onConsumeSeedIntent,
  sessionRuntime,
}: ChatCopilotViewProps) {
  return (
    <SpotlightWindow
      variant="chat"
      seedIntent={seedIntent}
      onConsumeSeedIntent={onConsumeSeedIntent}
      sessionRuntime={sessionRuntime}
    />
  );
}
