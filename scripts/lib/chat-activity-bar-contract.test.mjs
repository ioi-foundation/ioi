import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const activityBar = readFileSync(
  "apps/autopilot/src/windows/AutopilotShellWindow/components/ChatLocalActivityBar.tsx",
  "utf8",
);
const chatIdeHeader = readFileSync(
  "apps/autopilot/src/windows/AutopilotShellWindow/components/ChatIdeHeader.tsx",
  "utf8",
);
const shellBaseCss = readFileSync(
  "apps/autopilot/src/windows/AutopilotShellWindow/styles/autopilot-shell/shell-base.css",
  "utf8",
);
const traceAndWelcomeCss = readFileSync(
  "apps/autopilot/src/windows/AutopilotShellWindow/styles/autopilot-shell/trace-and-welcome.css",
  "utf8",
);

test("activity bar owns sidebar brand and can collapse without losing surface ids", () => {
  assert.match(activityBar, /CHAT_ACTIVITY_BAR_COLLAPSED_KEY/);
  assert.match(activityBar, /profile: AssistantUserProfile;/);
  assert.match(activityBar, /stored === null \? true : stored === "true"/);
  assert.match(activityBar, /className=\{`chat-activity-bar \$\{collapsed \? "is-collapsed" : ""\}`\}/);
  assert.match(activityBar, /data-collapsed=\{collapsed \? "true" : "false"\}/);
  assert.match(activityBar, /className="chat-activity-brand-row"[\s\S]*<ChatLogoIcon \/>/);
  assert.match(activityBar, /className="chat-activity-collapse-button"/);
  assert.match(activityBar, /data-window-surface=\{item\.id\}/);
  assert.match(activityBar, /data-window-surface="profile"/);
  assert.match(activityBar, /resolveProfileDisplayName\(profile\)/);
  assert.doesNotMatch(activityBar, /currentProject\.name/);
});

test("old header leading block is removed so the rail is the single sidebar identity", () => {
  assert.doesNotMatch(chatIdeHeader, /chat-ide-leading/);
  assert.doesNotMatch(chatIdeHeader, /chat-ide-brand/);
  assert.doesNotMatch(shellBaseCss, /\.chat-ide-leading/);
  assert.doesNotMatch(shellBaseCss, /\.chat-ide-brand/);
  assert.match(
    chatIdeHeader,
    /className="chat-ide-drag-surface"[\s\S]*data-tauri-drag-region/,
  );
});

test("activity bar styling matches the themeable collapsible rail contract", () => {
  assert.match(shellBaseCss, /\.chat-activity-bar\s*\{[\s\S]*width: 230px;/);
  assert.match(shellBaseCss, /--chat-activity-bg: #181818;/);
  assert.match(shellBaseCss, /background: var\(--chat-activity-bg\);/);
  assert.match(shellBaseCss, /\.chat-activity-brand\s*\{[\s\S]*color: var\(--chat-activity-text\);/);
  assert.match(shellBaseCss, /\.chat-activity-bar\.is-collapsed\s*\{\s*width: 48px;/);
  assert.match(shellBaseCss, /\.chat-activity-brand-row\s*\{[\s\S]*min-height: 48px;/);
  assert.match(shellBaseCss, /\.chat-activity-group\s*\{[\s\S]*border-bottom:/);
  assert.match(shellBaseCss, /\.chat-activity-button::before\s*\{[\s\S]*background: transparent;/);
  assert.match(shellBaseCss, /\.chat-activity-button\.is-active::before\s*\{\s*background: var\(--chat-accent\);/);
  assert.match(shellBaseCss, /\.chat-activity-button-label\s*\{[\s\S]*text-overflow: ellipsis;/);
  assert.match(shellBaseCss, /\.chat-activity-button-shortcut\s*\{/);
  assert.match(shellBaseCss, /\.chat-activity-apps\s*\{/);
  assert.match(shellBaseCss, /\.chat-activity-bar\.is-collapsed \.chat-activity-button-label,/);
  assert.match(shellBaseCss, /\.chat-activity-bar\.is-collapsed \.chat-activity-brand\s*\{\s*display: none;/);
  assert.match(shellBaseCss, /\.chat-activity-bar\.is-collapsed \.chat-activity-collapse-button\s*\{[\s\S]*width: 42px;[\s\S]*height: 42px;/);
});

test("light workbench mode restores the old theme-inherited activity rail colors", () => {
  assert.doesNotMatch(
    traceAndWelcomeCss,
    /:root\[data-autopilot-theme\^="light"\] \.chat-activity-button,/,
  );
  assert.match(
    traceAndWelcomeCss,
    /:root\[data-autopilot-theme\^="light"\] \.chat-activity-bar \{[\s\S]*--chat-activity-bg: #f3f3f3;[\s\S]*--chat-activity-text: #424242;/,
  );
});
