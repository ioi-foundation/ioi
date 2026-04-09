export interface ShortcutPlatformInfo {
  platform?: string | null;
  userAgent?: string | null;
}

export interface ShellShortcutRecord {
  id: string;
  command: string;
  binding: string;
  defaultBinding: string;
  scope: string;
  source: string;
  summary: string;
}

function currentPlatformInfo(): ShortcutPlatformInfo {
  if (typeof navigator === "undefined") {
    return {};
  }

  return {
    platform: navigator.platform,
    userAgent: navigator.userAgent,
  };
}

function isApplePlatform(
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): boolean {
  const value =
    `${platformInfo.platform || ""} ${platformInfo.userAgent || ""}`.toLowerCase();
  return value.includes("mac") || value.includes("iphone") || value.includes("ipad");
}

export function shellShortcutPlatformLabel(
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): string {
  return isApplePlatform(platformInfo) ? "macOS" : "Windows/Linux";
}

export function shellShortcutModifierLabel(
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): string {
  return isApplePlatform(platformInfo) ? "Cmd" : "Ctrl";
}

export function shellShortcutModifierGlyph(
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): string {
  return isApplePlatform(platformInfo) ? "⌘" : "Ctrl+";
}

export function spotlightCommandPaletteShortcutLabel(
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): string {
  return `${shellShortcutModifierLabel(platformInfo)}+K`;
}

export function studioNavigationShortcutLabel(
  index: number,
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): string {
  return `${shellShortcutModifierGlyph(platformInfo)}${index}`;
}

export function buildDefaultShellShortcutRecords(
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): ShellShortcutRecord[] {
  const modifier = shellShortcutModifierLabel(platformInfo);
  return [
    {
      id: "global-spotlight",
      command: "Open Autopilot",
      binding: `${modifier}+Space`,
      defaultBinding: `${modifier}+Space`,
      scope: "Global shell",
      source: "Tauri global shortcut",
      summary: "Show or hide Spotlight from anywhere.",
    },
    {
      id: "spotlight-command-palette",
      command: "Toggle command palette",
      binding: spotlightCommandPaletteShortcutLabel(platformInfo),
      defaultBinding: spotlightCommandPaletteShortcutLabel(platformInfo),
      scope: "Spotlight shell",
      source: "Session shell shortcuts",
      summary: "Open the Spotlight command palette from the active shell.",
    },
    {
      id: "spotlight-new-session",
      command: "Start new session",
      binding: `${modifier}+N`,
      defaultBinding: `${modifier}+N`,
      scope: "Spotlight shell",
      source: "Session shell shortcuts",
      summary: "Reset the current shell and start a new session.",
    },
    {
      id: "spotlight-stop-run",
      command: "Stop active run",
      binding: "Esc",
      defaultBinding: "Esc",
      scope: "Spotlight shell",
      source: "Spotlight input controls",
      summary: "Stop the active task or close the current inspection surface.",
    },
    {
      id: "studio-command-palette",
      command: "Open Studio command palette",
      binding: spotlightCommandPaletteShortcutLabel(platformInfo),
      defaultBinding: spotlightCommandPaletteShortcutLabel(platformInfo),
      scope: "Studio shell",
      source: "Studio command header",
      summary: "Open Studio search for commands, sessions, tools, and projects.",
    },
    {
      id: "studio-utility-drawer",
      command: "Toggle Studio utility drawer",
      binding: `${shellShortcutModifierGlyph(platformInfo)}J`,
      defaultBinding: `${shellShortcutModifierGlyph(platformInfo)}J`,
      scope: "Studio shell",
      source: "Studio utility drawer",
      summary: "Expand or collapse the bottom utility drawer.",
    },
    {
      id: "studio-nav-1",
      command: "Open Studio",
      binding: studioNavigationShortcutLabel(1, platformInfo),
      defaultBinding: studioNavigationShortcutLabel(1, platformInfo),
      scope: "Studio navigation",
      source: "Studio activity bar",
      summary: "Jump to the Studio primary surface.",
    },
    {
      id: "studio-nav-2",
      command: "Open Runs",
      binding: studioNavigationShortcutLabel(2, platformInfo),
      defaultBinding: studioNavigationShortcutLabel(2, platformInfo),
      scope: "Studio navigation",
      source: "Studio activity bar",
      summary: "Jump to runtime runs and receipts.",
    },
    {
      id: "studio-nav-3",
      command: "Open Inbox",
      binding: studioNavigationShortcutLabel(3, platformInfo),
      defaultBinding: studioNavigationShortcutLabel(3, platformInfo),
      scope: "Studio navigation",
      source: "Studio activity bar",
      summary: "Jump to approvals, prompts, and interventions.",
    },
    {
      id: "studio-nav-4",
      command: "Open Capabilities",
      binding: studioNavigationShortcutLabel(4, platformInfo),
      defaultBinding: studioNavigationShortcutLabel(4, platformInfo),
      scope: "Studio navigation",
      source: "Studio activity bar",
      summary: "Jump to connections, skills, and extensions.",
    },
    {
      id: "studio-nav-5",
      command: "Open Policy",
      binding: studioNavigationShortcutLabel(5, platformInfo),
      defaultBinding: studioNavigationShortcutLabel(5, platformInfo),
      scope: "Studio navigation",
      source: "Studio activity bar",
      summary: "Jump to governance and policy posture.",
    },
    {
      id: "studio-nav-6",
      command: "Open Settings",
      binding: studioNavigationShortcutLabel(6, platformInfo),
      defaultBinding: studioNavigationShortcutLabel(6, platformInfo),
      scope: "Studio navigation",
      source: "Studio activity bar",
      summary: "Jump to Studio settings and local diagnostics.",
    },
  ];
}
