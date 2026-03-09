// apps/autopilot/src/windows/StudioWindow/components/StudioCopilot.tsx
import { SpotlightWindow } from "../../SpotlightWindow";

interface StudioCopilotViewProps {
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
}

export function StudioCopilotView({ seedIntent, onConsumeSeedIntent }: StudioCopilotViewProps) {
  return (
    <SpotlightWindow
      variant="studio"
      seedIntent={seedIntent}
      onConsumeSeedIntent={onConsumeSeedIntent}
    />
  );
}
