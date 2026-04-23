import { useMemo } from "react";
import {
  buildDefaultShellShortcutRecords,
  shellShortcutPlatformLabel,
} from "../../shared/shellShortcuts";

export interface ChatKeybindingRecord {
  id: string;
  command: string;
  binding: string;
  defaultBinding: string;
  scope: string;
  source: string;
  summary: string;
}

export interface ChatKeybindingSnapshot {
  generatedAtMs: number;
  platformLabel: string;
  records: ChatKeybindingRecord[];
}

export function useChatKeybindings(): ChatKeybindingSnapshot {
  return useMemo(() => {
    const platformLabel = shellShortcutPlatformLabel();
    const records: ChatKeybindingRecord[] = buildDefaultShellShortcutRecords();

    return {
      generatedAtMs: Date.now(),
      platformLabel,
      records,
    };
  }, []);
}
