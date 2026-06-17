import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(
  new URL("./HypervisorShellContent.tsx", import.meta.url),
  "utf8",
);
const shellCss = fs.readFileSync(
  new URL("../styles/hypervisor-shell/shell-base.css", import.meta.url),
  "utf8",
);
const traceAndWelcomeCss = fs.readFileSync(
  new URL("../styles/hypervisor-shell/trace-and-welcome.css", import.meta.url),
  "utf8",
);
const homeViewSource = fs.readFileSync(
  new URL("../../../surfaces/Home/HomeView.tsx", import.meta.url),
  "utf8",
);
const homeCss = fs.readFileSync(
  new URL("../../../surfaces/Home/Home.css", import.meta.url),
  "utf8",
);

assert.match(
  source,
  /<ChatCopilotView[\s\S]*seedIntent=\{controller\.chat\.seedIntent\}[\s\S]*onConsumeSeedIntent=\{controller\.chat\.consumeSeedIntent\}/,
  "the primary chat copilot surface should remain the only seed-intent consumer",
);

assert.match(
  source,
  /<ChatLeftUtilityPane[\s\S]*seedIntent=\{null\}[\s\S]*onConsumeSeedIntent=\{undefined\}/,
  "the auxiliary chat pane should not auto-submit the same seed intent a second time",
);

const chatLeftUtilityPaneSource = fs.readFileSync(
  new URL("./ChatLeftUtilityPane.tsx", import.meta.url),
  "utf8",
);

assert.match(
  chatLeftUtilityPaneSource,
  /className=\{`operator-chat-pane-shell/,
  "the persistent chat pane should use only a layout shell around shared operator chat chrome",
);

assert.doesNotMatch(
  chatLeftUtilityPaneSource,
  /chat-chat-pane-body/,
  "the persistent chat pane should not wrap shared chat chrome in legacy pane body styling",
);

assert.match(
  chatLeftUtilityPaneSource,
  /chatPresentation=\{maximized \? "standalone" : "embedded-pane"\}/,
  "the persistent chat pane should use the compact embedded chat presentation until it is maximized",
);

assert.match(
  chatLeftUtilityPaneSource,
  /const usesIntegratedChatChrome = surface === "chat"[\s\S]*paneLeadingAction=\{[\s\S]*usesIntegratedChatChrome \? layoutControl : undefined[\s\S]*paneTrailingAction=\{[\s\S]*usesIntegratedChatChrome \? closeControl : undefined/,
  "the persistent chat pane should merge layout and close controls into the shared chat topbar",
);

assert.doesNotMatch(
  chatLeftUtilityPaneSource,
  /className="chat-chat-pane-controls"/,
  "the persistent chat pane should not render a second standalone control strip above the chat topbar",
);

const chatConversationSurfaceSource = fs.readFileSync(
  new URL(
    "../../ChatShellWindow/components/ChatConversationSurface.tsx",
    import.meta.url,
  ),
  "utf8",
);

assert.match(
  chatConversationSurfaceSource,
  /primaryActions=\{primaryActions\}[\s\S]*secondaryActions=\{secondaryActions\}[\s\S]*trailingControls=\{paneTrailingAction\}/,
  "pane chrome controls should stay on the shared operator chat topbar",
);

assert.match(
  chatConversationSurfaceSource,
  /id: "more"[\s\S]*label: "Views and More Actions\.\.\."[\s\S]*onClick: onOpenCommandPalette/,
  "sidebar chat should expose command actions through the substrate-style overflow control rather than a second search button",
);

assert.doesNotMatch(
  chatConversationSurfaceSource,
  /id: "search"/,
  "sidebar chat should not add a separate search control that competes with the Hypervisor command center",
);

assert.match(
  source,
  /className="hypervisor-automation-compositor hypervisor-automation-compositor--ioi-reference"/,
  "Automations should use the IOI-reference operator console shell",
);

assert.match(
  source,
  /className="hypervisor-automation-compositor__metrics"[\s\S]*className="hypervisor-automation-compositor__filters"[\s\S]*className="hypervisor-automation-compositor__table"[\s\S]*className="hypervisor-automation-compositor__suggested"/,
  "Automations should render metrics, filters, table rows, and the suggested-template rail",
);

assert.match(
  source,
  /data-workflow-compositor-editor-boundary="projection-client"[\s\S]*hidden/,
  "the legacy compositor child should remain mounted as a boundary artifact without becoming the default visible surface",
);

assert.match(
  source,
  /const settingsActive = activeView === "settings"/,
  "settings should have an explicit shell focus mode",
);

assert.match(
  source,
  /const utilityDrawerVisible =[\s\S]*!settingsActive[\s\S]*activeView !== "sessions"/,
  "settings should not render the utility drawer over the reference settings shell",
);

assert.match(
  source,
  /const auxiliaryChatVisible =[\s\S]*!settingsActive[\s\S]*!workspaceActive/,
  "settings should not render the auxiliary chat pane over the reference settings shell",
);

assert.match(
  source,
  /activeView === "authority" \?[\s\S]*<MissionControlControlView[\s\S]*surface="policy"/,
  "the authority route should keep the governance wrapper while settings is no longer wrapped as Mission Control",
);

assert.match(
  source,
  /settingsActive \?[\s\S]*<SettingsView[\s\S]*source: "settings"/,
  "the settings route should render SettingsView directly as a client preference surface",
);

assert.match(
  shellCss,
  /\.hypervisor-automation-compositor--ioi-reference\s*\{[\s\S]*background: #ffffff;[\s\S]*font-family:[\s\S]*"ABC Diatype"/,
  "Automations should share the IOI-reference light workplane and typography",
);

assert.match(
  shellCss,
  /\.hypervisor-automation-compositor__layout\s*\{[\s\S]*grid-template-columns: minmax\(0, 1fr\) 310px;[\s\S]*\.hypervisor-automation-compositor__table\s*\{[\s\S]*border-radius: 12px;/,
  "Automations should keep the reference main-column plus suggested-template rail layout",
);

assert.match(
  homeViewSource,
  /data-home-dashboard-variant="ioi-reference-portal"/,
  "Home should default to the IOI reference portal workplane",
);

assert.match(
  homeCss,
  /\.chat-home-zero--ioi-reference \.chat-home-zero-intent-composer,[\s\S]*display: none !important;/,
  "Home should not expose the chat prompt composer as the default workplane",
);

assert.doesNotMatch(
  homeViewSource,
  /What do you want to get done today\?/,
  "Home should not regress to the prompt-first zero-state copy",
);

assert.match(
  shellCss,
  /\.chat-activity-bar\s*\{[\s\S]*--chat-activity-bg: #17191f;[\s\S]*width: 208px;/,
  "The primary rail should use the IOI reference dark 208px shell",
);

assert.doesNotMatch(
  traceAndWelcomeCss,
  /:root\[data-hypervisor-theme\^="light"\] \.chat-activity-bar\s*\{[\s\S]*--chat-activity-bg: #f3f3f3;/,
  "Light theme must not turn the IOI reference rail pale",
);

console.log("HypervisorShellContent.seedIntent.test.ts: ok");
