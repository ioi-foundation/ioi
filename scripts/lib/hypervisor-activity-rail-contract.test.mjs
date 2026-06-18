import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const activityBar = readFileSync(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRail.tsx",
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

test("hypervisor activity rail owns sidebar brand and can collapse without losing surface ids", () => {
  assert.match(activityBar, /HYPERVISOR_ACTIVITY_RAIL_COLLAPSED_KEY/);
  assert.match(activityBar, /profile: AssistantUserProfile;/);
  assert.match(activityBar, /return stored === "true";/);
  assert.match(
    activityBar,
    /className=\{`hypervisor-activity-bar \$\{collapsed \? "is-collapsed" : ""\}`\}/,
  );
  assert.match(activityBar, /data-collapsed=\{collapsed \? "true" : "false"\}/);
  assert.match(
    activityBar,
    /className="hypervisor-activity-brand-row"[\s\S]*<HypervisorRailLogoIcon \/>/,
  );
  assert.match(activityBar, /className="hypervisor-activity-collapse-button"/);
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
  assert.match(activityBar, /data-hypervisor-quick-switcher-anchor=/);
  assert.match(activityBar, /hypervisor-activity-button--new-session/);
  assert.match(activityBar, /data-window-surface="new-session"/);
  assert.match(activityBar, /New Session/);
  assert.match(activityBar, /Organization settings/);
  assert.match(activityBar, /hypervisor-activity-project-label/);
  assert.match(activityBar, /hypervisor-activity-session-row/);
  assert.match(
    activityBar,
    /data-ioi-reference-session-list="from-launched-sessions"/,
  );
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
  assert.match(activityBar, /hypervisor-activity-button-shortcut">Ctrl/);
  assert.match(activityBar, /hypervisor-activity-button-shortcut">O/);
  assert.match(activityBar, /shortcutKeys=\{\["Project"\]\}/);
  assert.match(activityBar, /shortcutKeys\.map\(\(key\) =>/);
  assert.match(activityBar, /className="hypervisor-activity-button-shortcut"/);
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

test("hypervisor activity rail styling matches the themeable collapsible rail contract", () => {
  assert.match(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*\.hypervisor-activity-bar\s*\{[\s\S]*width: 300px;/,
  );
  assert.match(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*--hypervisor-activity-bg: #ffffff;/,
  );
  assert.doesNotMatch(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*--hypervisor-activity-bg: #252b33;[\s\S]*width: 230px;/,
  );
  assert.match(shellBaseCss, /background: var\(--hypervisor-activity-bg\);/);
  assert.match(
    shellBaseCss,
    /\.hypervisor-activity-brand\s*\{[\s\S]*color: var\(--hypervisor-activity-text\);/,
  );
  assert.match(
    shellBaseCss,
    /\.hypervisor-activity-bar\.is-collapsed\s*\{\s*width: 48px;/,
  );
  assert.match(
    shellBaseCss,
    /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*\.hypervisor-activity-brand-row\s*\{[\s\S]*min-height: 51px;/,
  );
  assert.match(shellBaseCss, /\.hypervisor-activity-group\s*\{[\s\S]*border-bottom:/);
  assert.match(shellBaseCss, /\.hypervisor-activity-button::before\s*\{[\s\S]*display: none;/);
  assert.match(shellBaseCss, /\.hypervisor-activity-button\.is-active\s*\{[\s\S]*box-shadow: none;/);
  assert.match(
    shellBaseCss,
    /\.hypervisor-activity-button-label\s*\{[\s\S]*text-overflow: ellipsis;/,
  );
  assert.match(shellBaseCss, /\.hypervisor-activity-button-shortcut\s*\{/);
  assert.match(shellBaseCss, /\.hypervisor-activity-apps\s*\{/);
  assert.match(
    shellBaseCss,
    /\.hypervisor-activity-bar\.is-collapsed \.hypervisor-activity-button-label,/,
  );
  assert.match(
    shellBaseCss,
    /\.hypervisor-activity-bar\.is-collapsed \.hypervisor-activity-brand\s*\{\s*display: none;/,
  );
  assert.match(
    shellBaseCss,
    /\.hypervisor-activity-bar\.is-collapsed \.hypervisor-activity-collapse-button\s*\{[\s\S]*width: 42px;[\s\S]*height: 42px;/,
  );
});

test("light workbench mode preserves the IOI reference light rail colors", () => {
  assert.doesNotMatch(
    traceAndWelcomeCss,
    /:root\[data-hypervisor-theme\^="light"\] \.hypervisor-activity-button,/,
  );
  assert.match(
    traceAndWelcomeCss,
    /:root\[data-hypervisor-theme\^="light"\] \.hypervisor-activity-bar \{[\s\S]*--hypervisor-activity-bg: #ffffff;[\s\S]*--hypervisor-activity-text: #6f737a;/,
  );
  assert.doesNotMatch(
    traceAndWelcomeCss,
    /:root\[data-hypervisor-theme\^="light"\] \.hypervisor-activity-bar \{[\s\S]*--hypervisor-activity-bg: #252b33;/,
  );
});
