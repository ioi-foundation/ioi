// Compatibility aliases remain so the legacy Studio shell path can re-export this view.
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
      variant="studio"
      seedIntent={seedIntent}
      onConsumeSeedIntent={onConsumeSeedIntent}
      sessionRuntime={sessionRuntime}
    />
  );
}
