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
const newSessionModalSource = fs.readFileSync(
  new URL("./HypervisorNewSessionModal.tsx", import.meta.url),
  "utf8",
);

assert.doesNotMatch(
  source,
  /<ChatCopilotView/,
  "Sessions should not mount the legacy chat pane underneath the IOI-reference cockpit",
);

assert.match(
  source,
  /<ChatLeftUtilityPane[\s\S]*seedIntent=\{null\}[\s\S]*onConsumeSeedIntent=\{undefined\}/,
  "the auxiliary chat pane should not auto-submit the same seed intent a second time",
);

assert.match(
  source,
  /const contentMainRef = useRef<HTMLDivElement \| null>\(null\);[\s\S]*useLayoutEffect\(\(\) => \{[\s\S]*const resetScroll = \(\) => \{[\s\S]*node\.scrollTop = 0;[\s\S]*window\.requestAnimationFrame\(resetScroll\)[\s\S]*window\.setTimeout\(resetScroll, 0\)[\s\S]*}, \[activeView\]\);[\s\S]*ref=\{contentMainRef\}/,
  "the main workplane should reset scroll during and after layout so reference cockpit surfaces open at the top",
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
  /className="hypervisor-session-operations--ioi-reference-session hypervisor-session-detail-shell"[\s\S]*data-ioi-reference-session-cockpit="true"/,
  "Sessions should use the IOI-reference session cockpit shell",
);

assert.doesNotMatch(
  source,
  /className="hypervisor-session-operations hypervisor-session-operations--ioi-reference-session/,
  "Sessions should not keep the stale dark cockpit root class that creates a card frame",
);

assert.match(
  source,
  /function SessionCodeIcon[\s\S]*function SessionOctagonIcon[\s\S]*function CompactEditorIcon[\s\S]*function SearchIcon[\s\S]*data-session-reference-page="environment-detail"[\s\S]*data-session-workspace-mode-list=\{HYPERVISOR_SESSION_WORKSPACE_MODES\.map[\s\S]*\.filter\(\s*\(mode\) => mode\.mode_id === "code"[\s\S]*className="hypervisor-session-operations__tab-icon"[\s\S]*<SessionCodeIcon \/>[\s\S]*className="hypervisor-session-operations__session-title"[\s\S]*<SessionOctagonIcon \/>[\s\S]*<strong>\{formatSessionDisplayTitle\(projection\.selected_session_ref\)\}<\/strong>[\s\S]*data-session-detail-tab-list=\{projection\.detail_tabs[\s\S]*\.filter\(\(tab\) => tab\.tab_id === "environment"\)[\s\S]*className="hypervisor-session-operations__detail-status-dot"[\s\S]*Environment \{formatSessionLifecycleLabel\(projection\.lifecycle_state\)\}/,
  "Sessions should render the IOI reference environment detail page with Code/title/Environment tab icons, status dot, human title, and lifecycle status",
);

assert.doesNotMatch(
  source,
  /aria-label="Request session access lease"[\s\S]*>\s*<span aria-hidden="true">\.\.\.<\/span>/,
  "Sessions should not keep a separate topbar ellipsis beside the reference editor control",
);

assert.match(
  source,
  /folder: "\.devcontainer\/"[\s\S]*name: "devcontainer\.json"[\s\S]*name: "Dockerfile"[\s\S]*folder: "docs\/"[\s\S]*name: "parent-harness-evidence-boundary\.md"[\s\S]*className="hypervisor-session-operations__search-icon"[\s\S]*<SearchIcon \/>[\s\S]*className="hypervisor-session-operations__file-status"[\s\S]*panel\.panel_id === "ports_services"[\s\S]*\? "Ports & Services"/,
  "Sessions should mirror the reference changed-file tree shape with search icon, folder rows, file icons, deltas, status pills, and dock label",
);

assert.doesNotMatch(
  source,
  /className="hypervisor-session-operations__(?:header|launches|rail|reference-detail|tabs|grid|actions|bottom|metadata)"/,
  "Sessions should hard-delete the stale dashboard rail/grid/actions/bottom DOM instead of hiding it behind CSS",
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
  /Phase 0A hard cut: Sessions uses the IOI reference environment detail view[\s\S]*\.hypervisor-session-detail-shell\s*\{[\s\S]*height: 100%;[\s\S]*overflow: hidden;[\s\S]*background: #ffffff;[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__reference-page\s*\{[\s\S]*grid-template-columns: minmax\(0, 1fr\) 340px;[\s\S]*grid-template-rows: 48px 48px minmax\(0, 1fr\);/,
  "Sessions should use the IOI-reference two-column environment detail page instead of the stale dashboard grid",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__right-pane\s*\{[\s\S]*grid-column: 2;[\s\S]*grid-row: 1 \/ -1;[\s\S]*grid-template-rows: 48px 56px minmax\(0, 1fr\) minmax\(224px, 32vh\);[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__change-filter-row\s*\{[\s\S]*grid-template-columns: minmax\(0, 1fr\) 140px;[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__bottom-dock\s*\{[\s\S]*border-top: 1px solid #e2e2df;/,
  "Sessions should keep the reference full-height Changes tree and Ports/Tasks/Terminal dock in the right inspector",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__bottom-content[\s\S]*> \.hypervisor-session-operations__panel:not\(:first-child\)\s*\{[\s\S]*display: none;[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__empty-state\s*\{/,
  "Sessions should render the active Ports pane as an IOI-reference empty state while retaining tabbed dock panels",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__inline-icon,[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__tab-icon,[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__editor-logo,[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__file-icon[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__search-icon/,
  "Sessions should use first-class reference icons for tabs, editor controls, chevrons, files, and inspector actions",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__top-actions\s*\{[\s\S]*display: flex;/,
  "Sessions should keep operation proposals in the reference top action strip without a stale action rail",
);

assert.doesNotMatch(
  shellCss,
  /\.hypervisor-session-detail-shell > \.hypervisor-session-operations__(?:header|rail|reference-detail|tabs|grid|actions|bottom|metadata)[\s\S]*display: none;/,
  "Sessions CSS should not keep hiding stale dashboard children after the DOM cut",
);

assert.match(
  shellCss,
  /\.hypervisor-automation-compositor__layout\s*\{[\s\S]*grid-template-columns: minmax\(0, 1fr\) 310px;[\s\S]*\.hypervisor-automation-compositor__table\s*\{[\s\S]*border-radius: 12px;/,
  "Automations should keep the reference main-column plus suggested-template rail layout",
);

assert.match(
  newSessionModalSource,
  /const \[harnessSelectionRef, setHarnessSelectionRef\] = useState[\s\S]*const \[modelRouteRef, setModelRouteRef\] = useState[\s\S]*const \[privacyPostureRef, setPrivacyPostureRef\] = useState/,
  "New Session should let the operator choose harness, model route, and privacy posture instead of freezing the default harness",
);

assert.match(
  newSessionModalSource,
  /data-new-session-harness-selection-ref=\{[\s\S]*launchSummary\.harness_selection_ref[\s\S]*data-new-session-harness-truth-boundary=\{[\s\S]*launchSummary\.harness_truth_boundary[\s\S]*data-new-session-requires-daemon-gate=\{String\([\s\S]*launchSummary\.requires_daemon_gate/,
  "New Session should bind selected harness truth boundary and daemon gate into launch-summary DOM evidence",
);

assert.match(
  newSessionModalSource,
  /data-new-session-governance="harness-model-privacy"[\s\S]*setHarnessSelectionRef\(event\.currentTarget\.value\)[\s\S]*setModelRouteRef\(event\.currentTarget\.value\)[\s\S]*setPrivacyPostureRef\(event\.currentTarget\.value\)[\s\S]*data-new-session-harness-verdict-card=\{harnessVerdict\.state\}/,
  "New Session should expose the governed harness/model/privacy testbed selectors and verdict before launch",
);

assert.match(
  shellCss,
  /\.hypervisor-new-session-modal__governance\s*\{[\s\S]*grid-template-columns: repeat\(3, minmax\(0, 1fr\)\);[\s\S]*\.hypervisor-new-session-modal__verdict\[data-new-session-harness-verdict-card="blocked"\]/,
  "New Session governance controls should be visible and warn on blocked harness/privacy combinations",
);

assert.match(
  homeViewSource,
  /data-home-dashboard-variant="ioi-reference-home"/,
  "Home should default to the IOI reference prompt workplane",
);

assert.match(
  homeCss,
  /Phase 0A hard cut: Home mirrors the IOI reference prompt surface[\s\S]*\.chat-home-zero--ioi-reference \.chat-home-zero-composer \{/,
  "Home should expose the IOI reference prompt composer as the default workplane",
);

assert.match(
  homeViewSource,
  /What do you want to get done today\?/,
  "Home should match the IOI reference prompt-first home copy",
);

assert.match(
  shellCss,
  /Phase 0A hard cut: mirror the IOI reference console rail[\s\S]*\.chat-activity-bar\s*\{[\s\S]*--chat-activity-bg: #f7f7f6;[\s\S]*width: 300px;/,
  "The primary rail should use the IOI reference light 300px console shell",
);

assert.match(
  traceAndWelcomeCss,
  /:root\[data-hypervisor-theme\^="light"\] \.chat-activity-bar\s*\{[\s\S]*--chat-activity-bg: #f7f7f6;/,
  "Light theme should preserve the IOI reference console rail palette",
);

assert.doesNotMatch(
  traceAndWelcomeCss,
  /:root\[data-hypervisor-theme\^="light"\] \.chat-activity-bar\s*\{[\s\S]*--chat-activity-bg: #17191f;/,
  "Light theme must not restore the deprecated dark IDE rail",
);

console.log("HypervisorShellContent.seedIntent.test.ts: ok");
