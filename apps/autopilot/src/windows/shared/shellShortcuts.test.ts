import assert from "node:assert/strict";
import {
  buildDefaultShellShortcutRecords,
  shellShortcutPlatformLabel,
  spotlightCommandPaletteShortcutLabel,
  chatNavigationShortcutLabel,
} from "./shellShortcuts.ts";

const mac = { platform: "MacIntel", userAgent: "Mozilla/5.0 (Macintosh)" };
const windows = {
  platform: "Win32",
  userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
};

{
  assert.equal(shellShortcutPlatformLabel(mac), "macOS");
  assert.equal(spotlightCommandPaletteShortcutLabel(mac), "Cmd+K");
  assert.equal(chatNavigationShortcutLabel(3, mac), "⌘3");
}

{
  assert.equal(shellShortcutPlatformLabel(windows), "Windows/Linux");
  assert.equal(spotlightCommandPaletteShortcutLabel(windows), "Ctrl+K");
  assert.equal(chatNavigationShortcutLabel(3, windows), "Ctrl+3");
}

{
  const records = buildDefaultShellShortcutRecords(mac);
  assert.equal(
    records.find((record) => record.id === "chat-nav-4")?.binding,
    "⌘4",
  );
  assert.equal(
    records.find((record) => record.id === "spotlight-command-palette")?.binding,
    "Cmd+K",
  );
}
