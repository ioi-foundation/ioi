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
const leftSidebarShellSource = fs.readFileSync(
  new URL("./HypervisorLeftSidebarShell.tsx", import.meta.url),
  "utf8",
);
const capabilitiesNavigationPaneSource = fs.readFileSync(
  new URL(
    "../../../surfaces/Capabilities/components/CapabilitiesNavigationPane.tsx",
    import.meta.url,
  ),
  "utf8",
);
const capabilitiesCss = fs.readFileSync(
  new URL("../../../surfaces/Capabilities/Capabilities.css", import.meta.url),
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
const projectSurfaceStart = source.indexOf(
  "function HypervisorProjectStateSurface",
);
const projectSurfaceEnd = source.indexOf(
  "function HypervisorProviderPlacementDashboard",
);
assert.ok(projectSurfaceStart >= 0, "Projects surface source should exist");
assert.ok(
  projectSurfaceEnd > projectSurfaceStart,
  "Projects surface source should be bounded",
);
const projectSurfaceSource = source.slice(
  projectSurfaceStart,
  projectSurfaceEnd,
);

assert.doesNotMatch(
  source,
  /<ChatCopilotView/,
  "Sessions cockpit should not mount a second chat pane underneath the workplane",
);

assert.doesNotMatch(
  source,
  /ChatLeftUtilityPane|ChatUtilityDrawer|ChatBenchmarkTraceDeck/,
  "Hypervisor reference shell should not import legacy auxiliary chat overlays",
);

assert.match(
  source,
  /const contentMainRef = useRef<HTMLDivElement \| null>\(null\);[\s\S]*useLayoutEffect\(\(\) => \{[\s\S]*const resetScroll = \(\) => \{[\s\S]*node\.scrollTop = 0;[\s\S]*window\.requestAnimationFrame\(resetScroll\)[\s\S]*window\.setTimeout\(resetScroll, 0\)[\s\S]*}, \[activeView\]\);[\s\S]*ref=\{contentMainRef\}/,
  "the main workplane should reset scroll during and after layout so reference cockpit surfaces open at the top",
);

assert.doesNotMatch(
  source,
  /chat-left-utility-pane|chat-utility-drawer|is-chat-fullscreen/,
  "Hypervisor reference shell should not keep legacy auxiliary pane class hooks",
);

assert.match(
  `${leftSidebarShellSource}\n${capabilitiesNavigationPaneSource}\n${capabilitiesCss}\n${shellCss}\n${traceAndWelcomeCss}`,
  /HypervisorLeftSidebarShell[\s\S]*hypervisor-left-sidebar[\s\S]*hypervisor-pane-control|hypervisor-pane-control[\s\S]*HypervisorLeftSidebarShell[\s\S]*hypervisor-left-sidebar/,
  "Capabilities should use the Hypervisor sidebar shell and pane control selectors",
);

assert.doesNotMatch(
  `${leftSidebarShellSource}\n${capabilitiesNavigationPaneSource}\n${capabilitiesCss}\n${shellCss}\n${traceAndWelcomeCss}`,
  /ChatLeftSidebarShell|chat-left-sidebar|chat-chat-pane-control|--chat-left-sidebar/,
  "Capabilities should not keep the Chat-named left sidebar seam",
);

assert.equal(
  fs.existsSync(new URL("../../ChatShellWindow", import.meta.url)),
  false,
  "Hypervisor shell should not retain the retired alternate ChatShellWindow UI tree",
);

assert.match(
  source,
  /className="hypervisor-automation-compositor hypervisor-automation-compositor--ioi-reference"/,
  "Automations should use the IOI-reference shell",
);

assert.match(
  projectSurfaceSource,
  /HYPERVISOR_PROJECT_STATE_CLEAN_BOOT_PROJECTION[\s\S]*<h2>Projects<\/h2>[\s\S]*placeholder="Search projects"[\s\S]*visibleProjects\.length > 0[\s\S]*data-project-state-records[\s\S]*data-project-state-record=\{project\.project_id\}[\s\S]*No projects[\s\S]*Projects bundle your repo, secrets, and other configuration[\s\S]*Learn more about projects in IOI\.[\s\S]*New project/,
  "Projects should clean boot to the IOI-reference searchable empty state and render daemon project rows only when records exist",
);

assert.match(
  source,
  /className="hypervisor-session-operations--ioi-reference-session hypervisor-session-detail-shell"[\s\S]*data-ioi-reference-session-cockpit="true"/,
  "Sessions should use the IOI-reference session cockpit shell",
);

assert.doesNotMatch(
  source,
  /className="hypervisor-session-operations hypervisor-session-operations--ioi-reference-session/,
  "Sessions should use only the reference cockpit root class",
);

assert.match(
  source,
  /function SessionCodeIcon[\s\S]*function SessionOctagonIcon[\s\S]*function CompactEditorIcon[\s\S]*function SearchIcon[\s\S]*data-session-reference-page="workspace-detail"[\s\S]*data-session-workspace-mode-list=\{HYPERVISOR_SESSION_WORKSPACE_MODES\.map[\s\S]*\.filter\(\s*\(mode\) => mode\.mode_id === "code"[\s\S]*className="hypervisor-session-operations__tab-icon"[\s\S]*<SessionCodeIcon \/>[\s\S]*className="hypervisor-session-operations__session-title"[\s\S]*data-session-detail-tab="agent"[\s\S]*<SessionOctagonIcon \/>[\s\S]*<strong>Agent<\/strong>[\s\S]*data-session-detail-tab="environment"[\s\S]*<strong>Environment<\/strong>[\s\S]*data-session-detail-tab-list=\{projection\.detail_tabs[\s\S]*data-session-lifecycle-state=\{projection\.lifecycle_state\}/,
  "Sessions should render the IOI reference workspace detail page with Code/Agent/Environment tabs and hidden lifecycle metadata",
);

assert.match(
  source,
  /data-session-workspace-cockpit=\{activeSessionRef\}[\s\S]*What do you want to get done today\?[\s\S]*label: "Automate env setup", tone: "blue"[\s\S]*label: "Fix a bug", tone: "red"[\s\S]*label: "Boost your test coverage", tone: "purple"[\s\S]*data-session-suggestion-tone=\{suggestion\.tone\}[\s\S]*Describe your task or type \/ for commands[\s\S]*data-session-environment-steps=\{projection\.environment_lifecycle_steps/,
  "Sessions should render the reference workspace prompt while preserving lifecycle refs as metadata",
);

assert.match(
  source,
  /<AgentModelSelector[\s\S]*options=\{agentOptions\}[\s\S]*selectedRef=\{agentSelectionRef\}[\s\S]*onSelect=\{onSelectAgent\}/,
  "Sessions composer should expose a working agent/model selector instead of a dead 5.5 Medium toggle",
);

assert.match(
  source,
  /sessionInitializing \?[\s\S]*hypervisor-session-operations__init"[\s\S]*Step \{initStepIndex \+ 1\} of[\s\S]*HYPERVISOR_SESSION_STARTUP_STEPS\.length[\s\S]*=== System logs ===/,
  "Sessions should initialize inline with a Step N of 5 build sequence and system logs instead of opening a separate window",
);

assert.match(
  source,
  /if \(!launchedHarnessSession\) \{[\s\S]*buildHypervisorNewSessionLaunchRequest\(\{[\s\S]*onLaunchSession\(request\)/,
  "Sessions composer submit should launch a governed session inline from the typed task",
);

assert.match(
  source,
  /launchedSessions: readonly HypervisorLaunchedSessionProjection\[\][\s\S]*const launchedHarnessSession[\s\S]*data-session-harness-drill-in=\{[\s\S]*data-session-harness-drill-in-spawn-state=\{[\s\S]*data-session-harness-drill-in-model-name=\{[\s\S]*data-session-harness-drill-in-pty-transport=\{[\s\S]*data-session-harness-drill-in-terminal-attach=\{[\s\S]*data-session-harness-drill-in-terminal-transcript=\{[\s\S]*data-session-harness-drill-in-terminal-transcript-cursor=\{[\s\S]*data-session-harness-drill-in-command=\{[\s\S]*launchedHarnessSession\.harness_session_binding[\s\S]*\.harness_label/,
  "Sessions should render launched harness readiness, attach, and transcript state from governed session projections instead of hiding Codex OSS/Qwen behind rail-only metadata",
);

assert.doesNotMatch(
  source,
  /className="hypervisor-session-operations__recent-launches"|data-launched-session-list="new-session-projection-cache"|className="hypervisor-session-operations__environment"|className="hypervisor-session-operations__startup-list"/,
  "Sessions should not reintroduce the launched-session strip or environment-first workplane",
);

assert.doesNotMatch(
  source,
  /aria-label="Request session access lease"[\s\S]*>\s*<span aria-hidden="true">\.\.\.<\/span>/,
  "Sessions should not keep a separate topbar ellipsis beside the reference editor control",
);

assert.match(
  source,
  /className="hypervisor-session-operations__search-icon"[\s\S]*<SearchIcon \/>[\s\S]*projection\.changed_file_groups\.map[\s\S]*data-session-changed-file-group=\{group\.group_ref\}[\s\S]*group\.files\.length[\s\S]*group\.files\.map[\s\S]*data-session-changed-file-status=\{file\.status\}[\s\S]*formatChangedFileStatus\(file\.status\)/,
  "Sessions should mirror the reference changed-file tree shape from the projection with search icon, folder rows, file icons, deltas, status pills, and dock label",
);

assert.match(
  source,
  /panel\.panel_id === "ports_services"[\s\S]*\? "Ports & Services"[\s\S]*projection\.ports_services\.map[\s\S]*data-session-port-service=\{service\.service_ref\}/,
  "Sessions should render Ports & Services from the session projection instead of hard-coded empty state copy",
);

assert.doesNotMatch(
  source,
  /className="hypervisor-session-operations__(?:header|launches|rail|reference-detail|tabs|grid|actions|bottom|metadata)"/,
  "Sessions should render only the reference cockpit DOM instead of hiding alternate dashboard branches",
);

assert.match(
  source,
  /className="hypervisor-automation-compositor__metrics"[\s\S]*value=\{referenceAutomationTotal\}[\s\S]*className="hypervisor-automation-compositor__filters"[\s\S]*Yours[\s\S]*All \(\{referenceAutomationTotal\}\)[\s\S]*className="hypervisor-automation-compositor__table"[\s\S]*No automations yet[\s\S]*className="hypervisor-automation-compositor__suggested"/,
  "Automations should render reference metrics, filters, clean empty state, and suggested-template rail",
);
assert.match(
  source,
  /projection\.source !== "daemon-automation-compositor-projection"[\s\S]*return \[\]/,
  "Automations should clean boot without fake automation rows unless daemon projection admits templates",
);
assert.match(
  source,
  /Scan recent commits for bugs[\s\S]*Draft weekly release notes[\s\S]*Add optimized AGENTS\.md[\s\S]*10x engineer[\s\S]*Daily standup generator[\s\S]*Tech spec from Linear issue[\s\S]*Automated dev environment setup[\s\S]*CVE mitigation & dependency updates/,
  "Automations should render the IOI-reference suggested template catalog",
);
assert.match(
  source,
  /className="hypervisor-automation-compositor__empty"/,
  "Automations should render the IOI-reference empty-state panel",
);

assert.match(
  source,
  /data-workflow-compositor-editor-boundary="projection-client"[\s\S]*hidden/,
  "the compositor projection client should stay hidden behind the Automations surface",
);

assert.match(
  source,
  /className="hypervisor-insights-reference"[\s\S]*Turn Insights into actionable intelligence[\s\S]*data-insights-runtime-projection-boundary="hidden-runs-client"/,
  "Insights should render the IOI-reference enterprise surface while keeping runtime analytics as a hidden boundary",
);

assert.doesNotMatch(
  source,
  /activeView === "insights" \? \(\s*<RuntimeInsightsView runtime=\{runtime\} \/>/,
  "Insights should not expose the raw runs client as the visible product route",
);

assert.match(
  source,
  /const settingsActive = activeView === "settings"/,
  "settings should have an explicit shell focus mode",
);

assert.doesNotMatch(
  source,
  /const conversationalSurfaceActive|const utilityDrawerVisible/,
  "top-level product surfaces should not render the utility drawer over the IOI reference shell",
);

assert.doesNotMatch(
  source,
  /const auxiliaryChatVisible|controller\.chat\.paneVisible/,
  "top-level product surfaces should not render the auxiliary chat pane over the IOI reference shell",
);

assert.match(
  source,
  /activeView === "authority" \?[\s\S]*<AuthoritySettingsSurfaceView[\s\S]*surface="policy"/,
  "the authority route should keep the governance wrapper while settings is no longer wrapped as Hypervisor governance",
);

assert.match(
  source,
  /settingsActive \?[\s\S]*<SettingsView[\s\S]*seedSection=\{controller\.settings\.seedSection\}/,
  "the settings route should render SettingsView directly as a client preference surface",
);

assert.match(
  shellCss,
  /\.hypervisor-automation-compositor--ioi-reference\s*\{[\s\S]*background: #ffffff;[\s\S]*font-family:[\s\S]*"ABC Diatype"/,
  "Automations should share the IOI-reference light workplane and typography",
);

assert.match(
  shellCss,
  /\.hypervisor-project-state\s*\{[\s\S]*background: #ffffff;[\s\S]*font-family: "ABC Diatype"[\s\S]*\.hypervisor-project-state__toolbar\s*\{[\s\S]*grid-template-columns: minmax\(240px,\s*1fr\) auto;[\s\S]*\.hypervisor-project-state__toolbar--empty\s*\{[\s\S]*grid-template-columns: minmax\(0,\s*1fr\);[\s\S]*\.hypervisor-project-state__table\s*\{[\s\S]*border: 1px solid #d8dee6;[\s\S]*\.hypervisor-project-state__inspector\s*\{/,
  "Projects should use the IOI-reference light workplane while preserving loaded-row and restore-inspector styling",
);

assert.doesNotMatch(
  shellCss,
  /\.hypervisor-project-state\s*\{[\s\S]*background: rgba\(15,\s*23,\s*42|hypervisor-project-state__sidebar|hypervisor-project-state__repositories|hypervisor-project-state__tabs/,
  "Projects should not regress into the old dark architecture-card or repository-sidebar treatment",
);

assert.match(
  shellCss,
  /Phase 0A hard cut: Sessions uses the IOI reference workspace cockpit[\s\S]*\.hypervisor-session-detail-shell\s*\{[\s\S]*height: 100%;[\s\S]*overflow: hidden;[\s\S]*background: #ffffff;[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__reference-page\s*\{[\s\S]*grid-template-columns: minmax\(0, 1fr\) clamp\(340px, 25vw, 488px\);[\s\S]*grid-template-rows: 48px 48px minmax\(0, 1fr\);[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__workspace\s*\{/,
  "Sessions should use the IOI-reference two-column workspace page",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__harness-drill-in\s*\{[\s\S]*width: min\(100%, 668px\);[\s\S]*border: 1px solid #d8dee6;[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__harness-drill-in code\s*\{[\s\S]*font-family: "ABC Diatype Mono"/,
  "Sessions should style launched harness readiness as a compact reference-cockpit drill-in card",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__right-pane\s*\{[\s\S]*grid-column: 2;[\s\S]*grid-row: 1 \/ -1;[\s\S]*grid-template-columns: minmax\(0, 1fr\);[\s\S]*grid-template-rows: 48px 56px minmax\(0, 1fr\) minmax\(224px, 32vh\);[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__change-filter-row\s*\{[\s\S]*grid-template-columns: minmax\(0, 1fr\) 140px;[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__bottom-dock\s*\{[\s\S]*border-top: 1px solid #e2e2df;/,
  "Sessions should keep the reference full-height Changes tree and Ports/Tasks/Terminal dock in the right inspector",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__bottom-content[\s\S]*> \.hypervisor-session-operations__panel:not\(:first-child\)\s*\{[\s\S]*display: none;[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__empty-state\s*\{[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__empty-state\.has-session-services/,
  "Sessions should render the active Ports pane as IOI-reference empty or populated projection rows while retaining tabbed dock panels",
);

assert.match(
  source,
  /data-session-detail-tab="agent"[\s\S]*<strong>Agent<\/strong>[\s\S]*data-session-detail-tab="environment"[\s\S]*<strong>Environment<\/strong>/,
  "Sessions should expose reference-style Agent and Environment tabs while binding them to session detail metadata",
);

assert.match(
  source,
  /className="hypervisor-session-operations__change-inspector"[\s\S]*HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES\.map[\s\S]*data-session-change-mode=\{mode\.mode_id\}[\s\S]*\{mode\.label\}/,
  "Sessions should render Changes, All Files, and Comments as visible right-inspector tabs",
);

assert.match(
  source,
  /hypervisor-session-operations__workspace-mark-symbol[\s\S]*label: "Create PR"[\s\S]*data-session-review-action=\{action\.label/,
  "Sessions should render the captured IOI reference mark and visible Create PR review action",
);

assert.doesNotMatch(
  source,
  /function WorkspaceIoiMark|<WorkspaceIoiMark \/>/,
  "Sessions should not use the old inline triangle mark that rendered as a warning-like glyph",
);

assert.doesNotMatch(
  `${source}\n${shellCss}`,
  /hypervisor-session-operations__activity-grid|hypervisor-session-operations__activity-signals|hypervisor-session-operations__lease-stack|data-session-activity-signal|data-session-lease=|data-session-archive-ref|data-session-restore-ref/,
  "Sessions should not reintroduce the non-reference center activity, lease, archive, or restore card grid",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__inline-icon,[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__tab-icon,[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__editor-logo,[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__file-icon[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__workspace-mark-symbol[\s\S]*clip-path: polygon\(50% 0, 95% 84%, 50% 66%, 5% 84%\);[\s\S]*data-session-suggestion-tone="blue"[\s\S]*data-session-suggestion-tone="red"[\s\S]*data-session-suggestion-tone="purple"[\s\S]*\.hypervisor-session-detail-shell \.hypervisor-session-operations__search-icon/,
  "Sessions should use first-class reference icons for tabs, editor controls, chevrons, files, and inspector actions",
);

assert.match(
  shellCss,
  /\.hypervisor-session-detail-shell \.hypervisor-session-operations__top-actions\s*\{[\s\S]*display: flex;/,
  "Sessions should keep operation proposals in the reference top action strip",
);

assert.doesNotMatch(
  shellCss,
  /\.hypervisor-session-detail-shell > \.hypervisor-session-operations__(?:header|rail|reference-detail|tabs|grid|actions|bottom|metadata)[\s\S]*display: none;/,
  "Sessions CSS should not hide alternate dashboard children after the DOM cut",
);

assert.match(
  shellCss,
  /\.hypervisor-automation-compositor__layout\s*\{[\s\S]*grid-template-columns: minmax\(0, 740px\) 293px;[\s\S]*gap: 42px;[\s\S]*\.hypervisor-automation-compositor__table\s*\{[\s\S]*min-height: 170px;[\s\S]*border-radius: 12px;[\s\S]*\.hypervisor-automation-compositor__empty\s*\{/,
  "Automations should keep the reference main-column, empty-state table, and suggested-template rail layout",
);

assert.match(
  newSessionModalSource,
  /const \[harnessSelectionRef, setHarnessSelectionRef\] = useState[\s\S]*const \[modelRouteRef, setModelRouteRef\] = useState[\s\S]*const \[privacyPostureRef, setPrivacyPostureRef\] = useState/,
  "New Session should let the operator choose harness, model route, and privacy posture instead of freezing the default harness",
);

assert.match(
  newSessionModalSource,
  /data-new-session-target-binding=\{[\s\S]*launchSummary\.target_binding\.schema_version[\s\S]*data-new-session-target-binding-ref=\{[\s\S]*launchSummary\.target_binding_ref[\s\S]*data-new-session-target-kind=\{[\s\S]*launchSummary\.target_binding\.target_kind[\s\S]*data-new-session-harness-selection-ref=\{[\s\S]*launchSummary\.harness_selection_ref[\s\S]*data-new-session-harness-truth-boundary=\{[\s\S]*launchSummary\.harness_truth_boundary[\s\S]*data-new-session-requires-daemon-gate=\{String\([\s\S]*launchSummary\.requires_daemon_gate/,
  "New Session should bind selected target, harness truth boundary, and daemon gate into launch-summary DOM evidence",
);

assert.match(
  newSessionModalSource,
  /data-new-session-governance="harness-model-privacy"[\s\S]*<span>Launch type<\/span>[\s\S]*setRecipeId\(event\.currentTarget\.value\)[\s\S]*setHarnessSelectionRef\(event\.currentTarget\.value\)[\s\S]*setModelRouteRef\(event\.currentTarget\.value\)[\s\S]*setPrivacyPostureRef\(event\.currentTarget\.value\)[\s\S]*data-new-session-harness-verdict-card=\{harnessVerdict\.state\}/,
  "New Session should expose the governed recipe/harness/model/privacy testbed selectors and verdict before launch",
);

assert.match(
  shellCss,
  /\.hypervisor-new-session-modal__governance\s*\{[\s\S]*grid-template-columns: repeat\(4, minmax\(0, 1fr\)\);[\s\S]*\.hypervisor-new-session-modal__verdict\[data-new-session-harness-verdict-card="blocked"\]/,
  "New Session governance controls should be visible and warn on blocked harness/privacy combinations",
);

assert.match(
  homeViewSource,
  /data-home-dashboard-variant="ioi-reference-home"/,
  "Home should default to the IOI reference prompt surface",
);

assert.match(
  homeCss,
  /\.hypervisor-home-prompt__shell\s*\{[\s\S]*\.hypervisor-home-prompt__stage\s*\{[\s\S]*\.hypervisor-home-prompt__composer\s*\{/,
  "Home should expose the IOI reference prompt surface as the default surface",
);

assert.match(
  homeViewSource,
  /What do you want to get done today\?[\s\S]*Describe your task or type \/ for commands[\s\S]*hypervisor-home-prompt__quickstarts/,
  "Home should match the IOI reference prompt-home copy",
);

assert.doesNotMatch(
  homeViewSource,
  /Welcome back, Operator|Recommended applications|HOME_REFERENCE_APPS|HOME_REFERENCE_ACTIONS|HOME_REFERENCE_SURFACES|Sessions and workspaces/,
  "Home should stay prompt-first instead of becoming an application-card portal",
);

assert.match(
  homeViewSource,
  /hypervisor-home-prompt__stage[\s\S]*What do you want to get done today\?[\s\S]*hypervisor-home-prompt__composer[\s\S]*hypervisor-home-prompt__quickstarts[\s\S]*hypervisor-home-prompt__sessions/,
  "Home should keep the prompt-first session launcher with the IOI-reference quick action chips and recent sessions list",
);
assert.match(
  homeViewSource,
  /recentSessions\.slice\(0, 3\)[\s\S]*data-home-reference-session-ref/,
  "Home should render recent sessions from launched-session projections instead of static Home shortcuts",
);
assert.doesNotMatch(
  homeViewSource,
  /data-home-recent-sessions|HOME_RECENT_SESSIONS/,
  "Home should not revive the old static recent-session shortcut model",
);

assert.match(
  source,
  /className="hypervisor-automation-compositor__webhooks"[\s\S]*Webhooks[\s\S]*className="hypervisor-automation-compositor__new"/,
  "Automations should expose the reference Webhooks and New actions in the topbar",
);

assert.doesNotMatch(
  source,
  /const conversationalSurfaceActive|const auxiliaryChatVisible/,
  "The right chat pane should stay off application surfaces such as Agents, Models, and Privacy",
);

assert.match(
  source,
  /<h2>Models<\/h2>[\s\S]*formatModelRouteRef\(route\.route_ref\)[\s\S]*formatProviderRef\(route\.provider_ref\)[\s\S]*formatCustodyLane\(route\.model_weight_custody_lane\)[\s\S]*Receipt recorded/,
  "Models should render product labels while retaining raw model refs only as data attributes",
);

assert.match(
  source,
  /<h2>Private workspace<\/h2>[\s\S]*formatPrivacyPostureRef\(projection\.selected_privacy_ref\)[\s\S]*formatModelRouteRef\(projection\.default_model_route_ref\)[\s\S]*formatPrivacyOwner\(control\.owner\)/,
  "Privacy should render custody as product language rather than daemon or Agentgres prose",
);

assert.match(
  source,
  /data-privacy-admission-control=\{control\.control_ref\}[\s\S]*Receipt recorded/,
  "Privacy controls should render receipt status as product text while keeping raw receipt refs in the projection",
);

assert.match(
  shellCss,
  /\.hypervisor-content-main:has\(\.hypervisor-privacy-posture\)[\s\S]*background: #ffffff/,
  "Privacy should live on the same light reference content plane as the other application surfaces",
);

assert.doesNotMatch(
  shellCss,
  /\.hypervisor-privacy-posture\s*\{[^}]*background:\s*rgba\(15,\s*23,\s*42/,
  "Privacy should not regress into the old dark architecture-card treatment",
);

assert.match(
  shellCss,
  /Phase 0A reference parity: primary rail follows the IOI captured shell[\s\S]*\.hypervisor-activity-bar\s*\{[\s\S]*--hypervisor-activity-bg: #ffffff;[\s\S]*width: 300px;/,
  "The primary rail should use the IOI reference light navigation shell",
);

assert.match(
  traceAndWelcomeCss,
  /:root\[data-hypervisor-theme\^="light"\] \.hypervisor-activity-bar\s*\{[\s\S]*--hypervisor-activity-bg: #ffffff;/,
  "Light content theme should preserve the IOI reference light rail palette",
);

assert.doesNotMatch(
  traceAndWelcomeCss,
  /:root\[data-hypervisor-theme\^="light"\] \.hypervisor-activity-bar\s*\{[\s\S]*--hypervisor-activity-bg: #252b33;/,
  "Light content theme should keep the reference light rail palette",
);

console.log("HypervisorShellContent.seedIntent.test.ts: ok");
