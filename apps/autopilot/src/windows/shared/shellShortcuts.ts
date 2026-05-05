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

export function chatCommandPaletteShortcutLabel(
  platformInfo: ShortcutPlatformInfo = currentPlatformInfo(),
): string {
  return `${shellShortcutModifierLabel(platformInfo)}+K`;
}

export function chatNavigationShortcutLabel(
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
      id: "global-chat-session",
      command: "Open Autopilot",
      binding: `${modifier}+Space`,
      defaultBinding: `${modifier}+Space`,
      scope: "Global shell",
      source: "Tauri global shortcut",
      summary: "Show or hide Chat from anywhere.",
    },
    {
      id: "chat-command-palette",
      command: "Toggle command palette",
      binding: chatCommandPaletteShortcutLabel(platformInfo),
      defaultBinding: chatCommandPaletteShortcutLabel(platformInfo),
      scope: "Chat shell",
      source: "Session shell shortcuts",
      summary: "Open the Chat command palette from the active shell.",
    },
    {
      id: "chat-new-session",
      command: "Start new session",
      binding: `${modifier}+N`,
      defaultBinding: `${modifier}+N`,
      scope: "Chat shell",
      source: "Session shell shortcuts",
      summary: "Reset the current shell and start a new session.",
    },
    {
      id: "chat-stop-run",
      command: "Stop active run",
      binding: "Esc",
      defaultBinding: "Esc",
      scope: "Chat shell",
      source: "Chat input controls",
      summary: "Stop the active task or close the current inspection surface.",
    },
    {
      id: "chat-command-palette",
      command: "Open Chat command palette",
      binding: chatCommandPaletteShortcutLabel(platformInfo),
      defaultBinding: chatCommandPaletteShortcutLabel(platformInfo),
      scope: "Chat shell",
      source: "Chat command header",
      summary: "Open Chat search for commands, sessions, tools, and projects.",
    },
    {
      id: "chat-utility-drawer",
      command: "Toggle Chat utility drawer",
      binding: `${shellShortcutModifierGlyph(platformInfo)}J`,
      defaultBinding: `${shellShortcutModifierGlyph(platformInfo)}J`,
      scope: "Chat shell",
      source: "Chat utility drawer",
      summary: "Expand or collapse the bottom utility drawer.",
    },
    {
      id: "chat-nav-1",
      command: "Open Chat",
      binding: chatNavigationShortcutLabel(1, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(1, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to the Chat primary surface.",
    },
    {
      id: "chat-nav-2",
      command: "Open Workspace",
      binding: chatNavigationShortcutLabel(2, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(2, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to the workspace execution surface.",
    },
    {
      id: "chat-nav-3",
      command: "Open Workflows",
      binding: chatNavigationShortcutLabel(3, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(3, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to the workflow composer.",
    },
    {
      id: "chat-nav-4",
      command: "Open Runs",
      binding: chatNavigationShortcutLabel(4, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(4, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to runtime runs and receipts.",
    },
    {
      id: "chat-nav-5",
      command: "Open Model Mounts",
      binding: chatNavigationShortcutLabel(5, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(5, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to the model mounting surface.",
    },
    {
      id: "chat-nav-6",
      command: "Open Inbox",
      binding: chatNavigationShortcutLabel(6, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(6, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to approvals, prompts, and interventions.",
    },
    {
      id: "chat-nav-7",
      command: "Open Capabilities",
      binding: chatNavigationShortcutLabel(7, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(7, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to connections, skills, and extensions.",
    },
    {
      id: "chat-nav-8",
      command: "Open Policy",
      binding: chatNavigationShortcutLabel(8, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(8, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to governance and policy posture.",
    },
    {
      id: "chat-nav-9",
      command: "Open Settings",
      binding: chatNavigationShortcutLabel(9, platformInfo),
      defaultBinding: chatNavigationShortcutLabel(9, platformInfo),
      scope: "Chat navigation",
      source: "Chat activity bar",
      summary: "Jump to Chat settings and local diagnostics.",
    },
  ];
}
