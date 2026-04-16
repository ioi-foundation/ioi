// apps/autopilot/src/windows/StudioWindow/components/StudioCopilot.tsx
import type { AssistantSessionRuntime } from "@ioi/agent-ide";
import { SpotlightWindow } from "../../SpotlightWindow";

interface StudioCopilotViewProps {
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  sessionRuntime: AssistantSessionRuntime;
}

export function StudioCopilotView({
  seedIntent,
  onConsumeSeedIntent,
  sessionRuntime,
}: StudioCopilotViewProps) {
  return (
    <SpotlightWindow
      variant="studio"
      seedIntent={seedIntent}
      onConsumeSeedIntent={onConsumeSeedIntent}
      sessionRuntime={sessionRuntime}
    />
  );
}
