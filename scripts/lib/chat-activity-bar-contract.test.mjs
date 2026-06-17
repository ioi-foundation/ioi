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
  "apps/hypervisor/src/windows/HypervisorShellWindow/styles/autopilot-shell/shell-base.css",
  "utf8",
);
const traceAndWelcomeCss = readFileSync(
  "apps/hypervisor/src/windows/HypervisorShellWindow/styles/autopilot-shell/trace-and-welcome.css",
  "utf8",
);

test("activity bar owns sidebar brand and can collapse without losing surface ids", () => {
  assert.match(activityBar, /CHAT_ACTIVITY_BAR_COLLAPSED_KEY/);
  assert.match(activityBar, /profile: AssistantUserProfile;/);
  assert.match(activityBar, /stored === null \? true : stored === "true"/);
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
  assert.match(
    activityBar,
    /<path d="M7 4h6" \/>[\s\S]*<path d="m2\.5 5\.5 2\.5 2\.5-2\.5 2\.5" \/>/,
  );
  assert.match(
    activityBar,
    /<path d="M6 4h7" \/>[\s\S]*<path d="m3\.5 5\.5-2\.5 2\.5 2\.5 2\.5" \/>/,
  );
  assert.match(activityBar, /onOpenCommandPalette: \(\) => void;/);
  assert.match(activityBar, /data-window-surface="search"/);
  assert.match(
    activityBar,
    /const activateRoute = \(route: OperatorSurfaceRoute\)/,
  );
  assert.match(activityBar, /route\.kind === "command-palette"/);
  assert.match(
    activityBar,
    /<SearchButton onClick=\{\(\) => activateRoute\(searchItem\.route\)\} \/>/,
  );
  assert.match(activityBar, /data-window-surface=\{item\.dataWindowSurface\}/);
  assert.match(
    activityBar,
    /data-window-surface=\{profileItem\.dataWindowSurface\}/,
  );
  assert.match(activityBar, /resolveProfileDisplayName\(profile\)/);
  assert.doesNotMatch(activityBar, /currentProject\.name/);
});

test("only the search rail item displays a keyboard shortcut", () => {
  assert.match(activityBar, /chatCommandPaletteShortcutLabel/);
  assert.equal(
    activityBar.match(/className="chat-activity-button-shortcut"/g)?.length,
    1,
  );
  assert.doesNotMatch(activityBar, /title=\{`\$\{item\.label\}/);
  assert.match(activityBar, /: item\.label/);
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
  assert.match(shellBaseCss, /\.chat-activity-bar\s*\{[\s\S]*width: 230px;/);
  assert.match(shellBaseCss, /--chat-activity-bg: #181818;/);
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
    /\.chat-activity-brand-row\s*\{[\s\S]*min-height: 48px;/,
  );
  assert.match(shellBaseCss, /\.chat-activity-group\s*\{[\s\S]*border-bottom:/);
  assert.match(
    shellBaseCss,
    /\.chat-activity-button::before\s*\{[\s\S]*background: transparent;/,
  );
  assert.match(
    shellBaseCss,
    /\.chat-activity-button\.is-active::before\s*\{\s*background: var\(--chat-accent\);/,
  );
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
