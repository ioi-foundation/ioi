import { useMemo } from "react";
import {
  buildDefaultShellShortcutRecords,
  shellShortcutPlatformLabel,
} from "../../shared/shellShortcuts";

export interface SpotlightKeybindingRecord {
  id: string;
  command: string;
  binding: string;
  defaultBinding: string;
  scope: string;
  source: string;
  summary: string;
}

export interface SpotlightKeybindingSnapshot {
  generatedAtMs: number;
  platformLabel: string;
  records: SpotlightKeybindingRecord[];
}

export function useSpotlightKeybindings(): SpotlightKeybindingSnapshot {
  return useMemo(() => {
    const platformLabel = shellShortcutPlatformLabel();
    const records: SpotlightKeybindingRecord[] = buildDefaultShellShortcutRecords();

    return {
      generatedAtMs: Date.now(),
      platformLabel,
      records,
    };
  }, []);
}
