import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const activityBar = readFileSync(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLocalActivityBar.tsx",
  "utf8",
);
const hypervisorClientHeader = readFileSync(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorClientHeader.tsx",
  "utf8",
);
const shellBaseCss = readFileSync(
  "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/shell-base.css",
  "utf8",
);
const traceAndWelcomeCss = readFileSync(
  "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/trace-and-welcome.css",
  "utf8",
);

test("activity bar owns sidebar brand and can collapse without losing surface ids", () => {
  assert.match(activityBar, /CHAT_ACTIVITY_BAR_COLLAPSED_KEY/);
  assert.match(activityBar, /profile: AssistantUserProfile;/);
  assert.match(activityBar, /return stored === "true";/);
  assert.match(
    activityBar,
    /className=\{`chat-activity-bar \$\{collapsed \? "is-collapsed" : ""\}`\}/,
  );
  assert.match(activityBar, /data-collapsed=\{collapsed \? "true" : "false"\}/);
  assert.match(
    activityBar,
    /className="chat-activity-brand-row"[\s\S]*<ChatLogoIcon \/>/,
  );
  assert.match(activityBar, /className="chat-activity-collapse-button"/);
  assert.match(activityBar, /function CollapseIcon\(\{ collapsed \}/);
  assert.match(activityBar, /collapsed\s*\?/);
  assert.match(activityBar, /onOpenCommandPalette: \(\) => void;/);
  assert.match(activityBar, /HYPERVISOR_PRIMARY_ACTION/);
  assert.match(activityBar, /data-ioi-reference-primary-rail="true"/);
  assert.match(
    activityBar,
    /const activateRoute = \(route: OperatorSurfaceRoute\)/,
  );
  assert.match(activityBar, /route\.kind === "command-palette"/);
  assert.match(activityBar, /chat-activity-button--new-session/);
  assert.match(activityBar, /data-window-surface="new-session"/);
  assert.match(activityBar, /New Session/);
  assert.match(activityBar, /Organization settings/);
  assert.match(activityBar, /chat-activity-project-label/);
  assert.match(activityBar, /chat-activity-project-skeleton/);
  assert.match(activityBar, /data-ioi-reference-session-list="project-skeleton"/);
  assert.doesNotMatch(activityBar, /Search\.\.\./);
  assert.doesNotMatch(activityBar, /What's New/);
  assert.doesNotMatch(activityBar, /IOI Assist/);
  assert.doesNotMatch(activityBar, /Your favorite apps will appear here/);
  assert.match(activityBar, /data-window-surface=\{item\.dataWindowSurface\}/);
  assert.match(activityBar, /data-window-surface="account"/);
  assert.match(
    activityBar,
    /data-window-surface="account"[\s\S]*onClick=\{\(\) => \{[\s\S]*onViewChange\("settings"\);/,
  );
  assert.doesNotMatch(
    activityBar,
    /data-window-surface="account"[\s\S]*activateRoute\(profileItem\.route\)/,
  );
  assert.match(activityBar, /resolveProfileDisplayName\(profile\)/);
  assert.doesNotMatch(activityBar, /currentProject\.name/);
});

test("reference rail exposes new session and session context shortcut pills", () => {
  assert.doesNotMatch(activityBar, /title=\{`\$\{item\.label\}/);
  assert.match(activityBar, /: item\.label/);
  assert.match(activityBar, /chat-activity-button-shortcut">Ctrl/);
  assert.match(activityBar, /chat-activity-button-shortcut">O/);
  assert.match(activityBar, /shortcutKeys=\{\["Project"\]\}/);
  assert.match(activityBar, /shortcutKeys\.map\(\(key\) =>/);
  assert.match(activityBar, /className="chat-activity-button-shortcut"/);
});

test("old client header leading block is removed so the rail is the single sidebar identity", () => {
  assert.doesNotMatch(hypervisorClientHeader, /hypervisor-client-leading/);
  assert.doesNotMatch(hypervisorClientHeader, /hypervisor-client-brand/);
  assert.doesNotMatch(shellBaseCss, /\.hypervisor-client-leading/);
  assert.doesNotMatch(shellBaseCss, /\.hypervisor-client-brand/);
  assert.match(
    hypervisorClientHeader,
    /className="hypervisor-client-drag-surface"[\s\S]*data-host-drag-region/,
  );
});

test("activity bar styling matches the themeable collapsible rail contract", () => {
  assert.match(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*\.chat-activity-bar\s*\{[\s\S]*width: 300px;/,
  );
  assert.match(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*--chat-activity-bg: #ffffff;/,
  );
  assert.doesNotMatch(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*--chat-activity-bg: #252b33;[\s\S]*width: 230px;/,
  );
  assert.match(shellBaseCss, /background: var\(--chat-activity-bg\);/);
  assert.match(
    shellBaseCss,
    /\.chat-activity-brand\s*\{[\s\S]*color: var\(--chat-activity-text\);/,
  );
  assert.match(
    shellBaseCss,
    /\.chat-activity-bar\.is-collapsed\s*\{\s*width: 48px;/,
  );
  assert.match(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*\.chat-activity-brand-row\s*\{[\s\S]*min-height: 51px;/,
  );
  assert.match(shellBaseCss, /\.chat-activity-group\s*\{[\s\S]*border-bottom:/);
  assert.match(shellBaseCss, /\.chat-activity-button::before\s*\{[\s\S]*display: none;/);
  assert.match(shellBaseCss, /\.chat-activity-button\.is-active\s*\{[\s\S]*box-shadow: none;/);
  assert.match(
    shellBaseCss,
    /\.chat-activity-button-label\s*\{[\s\S]*text-overflow: ellipsis;/,
  );
  assert.match(shellBaseCss, /\.chat-activity-button-shortcut\s*\{/);
  assert.match(shellBaseCss, /\.chat-activity-apps\s*\{/);
  assert.match(
    shellBaseCss,
    /\.chat-activity-bar\.is-collapsed \.chat-activity-button-label,/,
  );
  assert.match(
    shellBaseCss,
    /\.chat-activity-bar\.is-collapsed \.chat-activity-brand\s*\{\s*display: none;/,
  );
  assert.match(
    shellBaseCss,
    /\.chat-activity-bar\.is-collapsed \.chat-activity-collapse-button\s*\{[\s\S]*width: 42px;[\s\S]*height: 42px;/,
  );
});

test("light workbench mode preserves the IOI reference light rail colors", () => {
  assert.doesNotMatch(
    traceAndWelcomeCss,
    /:root\[data-hypervisor-theme\^="light"\] \.chat-activity-button,/,
  );
  assert.match(
    traceAndWelcomeCss,
    /:root\[data-hypervisor-theme\^="light"\] \.chat-activity-bar \{[\s\S]*--chat-activity-bg: #ffffff;[\s\S]*--chat-activity-text: #6f737a;/,
  );
  assert.doesNotMatch(
    traceAndWelcomeCss,
    /:root\[data-hypervisor-theme\^="light"\] \.chat-activity-bar \{[\s\S]*--chat-activity-bg: #252b33;/,
  );
});
