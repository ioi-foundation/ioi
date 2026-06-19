import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("./hypervisorShellNavigationModel.ts", import.meta.url),
  "utf8",
);
const codeEditorAdapterPreferences = readFileSync(
  new URL("./codeEditorAdapterPreferences.ts", import.meta.url),
  "utf8",
);
const operatorSubstrate = readFileSync(
  new URL("./operatorSubstrateModel.ts", import.meta.url),
  "utf8",
);
const activityBar = readFileSync(
  new URL("./components/HypervisorActivityRail.tsx", import.meta.url),
  "utf8",
);
const activityBarIcons = readFileSync(
  new URL("./components/HypervisorActivityRailIcons.tsx", import.meta.url),
  "utf8",
);
const newSessionModal = readFileSync(
  new URL("./components/HypervisorNewSessionModal.tsx", import.meta.url),
  "utf8",
);
const controller = readFileSync(
  new URL("./useHypervisorShellController.ts", import.meta.url),
  "utf8",
);
const shellWindow = readFileSync(
  new URL("./index.tsx", import.meta.url),
  "utf8",
);
const shellContent = readFileSync(
  new URL("./components/HypervisorShellContent.tsx", import.meta.url),
  "utf8",
);
const sessionOperationsModel = readFileSync(
  new URL("./hypervisorSessionOperationsModel.ts", import.meta.url),
  "utf8",
);
const providerPlacementModel = readFileSync(
  new URL("./hypervisorProviderPlacementModel.ts", import.meta.url),
  "utf8",
);
const privacyPostureModel = readFileSync(
  new URL("./hypervisorPrivacyPostureModel.ts", import.meta.url),
  "utf8",
);
const projectStateModel = readFileSync(
  new URL("./hypervisorProjectStateModel.ts", import.meta.url),
  "utf8",
);
const automationCompositorModel = readFileSync(
  new URL("./hypervisorAutomationCompositorModel.ts", import.meta.url),
  "utf8",
);
const agentsModel = readFileSync(
  new URL("./hypervisorAgentsModel.ts", import.meta.url),
  "utf8",
);
const modelInfrastructureModel = readFileSync(
  new URL("./hypervisorModelInfrastructureModel.ts", import.meta.url),
  "utf8",
);
const receiptEvidenceModel = readFileSync(
  new URL("./hypervisorReceiptEvidenceModel.ts", import.meta.url),
  "utf8",
);
const launchedSessionPersistence = readFileSync(
  new URL("./hypervisorLaunchedSessionPersistence.ts", import.meta.url),
  "utf8",
);
const shellBaseCss = readFileSync(
  new URL("./styles/hypervisor-shell/shell-base.css", import.meta.url),
  "utf8",
);

function sourceSlice(contents, startMarker, endMarker) {
  const start = contents.indexOf(startMarker);
  const end = contents.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return contents.slice(start, end);
}

test("hypervisor shell exposes the canonical core client and surface taxonomy", () => {
  assert.match(source, /export type HypervisorClientKind/);
  assert.match(source, /export type HypervisorSurfaceId/);
  assert.match(source, /export type HypervisorSessionDetailTab/);
  assert.match(source, /export type HypervisorInspectorPanelId/);
  assert.match(source, /"app"[\s\S]*"web"[\s\S]*"cli_headless"/);
  assert.match(source, /"workbench"[\s\S]*"automations"[\s\S]*"insights"/);
  assert.doesNotMatch(source, /"recipes"/);
});

test("hypervisor shell binds Phase 0A to the IOI reference cockpit contract", () => {
  assert.match(source, /HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS/);
  assert.match(
    source,
    /primaryReference: "internal-docs\/reverse-engineering\/ioi"/,
  );
  assert.doesNotMatch(source, /internal-docs\/reverse-engineering\/ona/);
  for (const referenceSurface of [
    "home",
    "workspaces",
    "automations",
    "insights",
    "ai",
    "projects",
    "settings",
    "logs",
    "session_detail",
    "editor",
  ]) {
    assert.match(source, new RegExp(`"${referenceSurface}"`));
  }
  for (const hypervisorSurface of [
    "home",
    "sessions",
    "projects",
    "missions",
    "workbench",
    "automations",
    "insights",
    "agents",
    "models",
    "privacy",
    "providers",
    "environments",
    "foundry",
    "authority",
    "receipts",
    "settings",
  ]) {
    assert.match(source, new RegExp(`"${hypervisorSurface}"`));
  }
  for (const shellRegion of [
    "left_nav",
    "new_session",
    "session_rail",
    "main_surface",
    "session_detail_tabs",
    "right_inspector",
    "bottom_inspector",
    "settings",
  ]) {
    assert.match(source, new RegExp(`"${shellRegion}"`));
  }
  for (const settingsSection of [
    "identity",
    "secrets",
    "git_auth",
    "personal_access_tokens",
    "integrations",
  ]) {
    assert.match(source, new RegExp(`"${settingsSection}"`));
  }
  assert.match(
    source,
    /Codex CLI[\s\S]*Claude Code[\s\S]*DeepSeek TUI[\s\S]*Grok Build/,
  );
  assert.match(source, /HYPERVISOR_REFERENCE_LEFT_NAV_SURFACE_IDS/);
  assert.match(
    source,
    /HYPERVISOR_REFERENCE_LEFT_NAV_SURFACE_IDS = \[[\s\S]*"home"[\s\S]*"projects"[\s\S]*"automations"[\s\S]*"insights"[\s\S]*"sessions"[\s\S]*\]/,
  );
  assert.doesNotMatch(
    sourceSlice(
      source,
      "export const HYPERVISOR_REFERENCE_LEFT_NAV_SURFACE_IDS",
      "export const HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS",
    ),
    /"workbench"|"agents"|"models"|"privacy"|"authority"/,
  );
  assert.match(
    source,
    /leftNavSurfaceIds: HYPERVISOR_REFERENCE_LEFT_NAV_SURFACE_IDS/,
  );
  assert.match(source, /HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES/);
  assert.match(codeEditorAdapterPreferences, /CodeEditorAdapterPreference/);
  assert.match(codeEditorAdapterPreferences, /CodeEditorAdapterLaunchPlan/);
  assert.match(codeEditorAdapterPreferences, /buildCodeEditorAdapterLaunchPlan/);
  assert.match(codeEditorAdapterPreferences, /executor_lane/);
  assert.match(codeEditorAdapterPreferences, /control_action/);
  assert.match(codeEditorAdapterPreferences, /control_channel_ref/);
  assert.match(
    codeEditorAdapterPreferences,
    /ioi\.hypervisor\.code_editor_adapter_launch_plan\.v1/,
  );
  assert.match(source, /DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF/);
  assert.match(source, /code_editor_adapter/);
  assert.match(
    codeEditorAdapterPreferences,
    /VS Code[\s\S]*VS Code Insiders[\s\S]*Cursor[\s\S]*Windsurf[\s\S]*IntelliJ IDEA Ultimate[\s\S]*CLion[\s\S]*RustRover[\s\S]*Rider/,
  );
  assert.match(activityBar, /HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS/);
  assert.match(
    activityBar,
    /\[\.\.\.HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS\.leftNavSurfaceIds\]/,
  );
  assert.match(activityBar, /hypervisor\.primaryRailCollapsed\.v2/);
  assert.doesNotMatch(activityBar, /hypervisor\.activityBarCollapsed/);
  assert.match(activityBar, /return stored === "true"/);
  assert.doesNotMatch(
    activityBar,
    /stored === null \? true : stored === "true"/,
  );
});

test("hypervisor shell keeps application surfaces separate from clients", () => {
  assert.match(source, /id: "workbench"[\s\S]*label: "Workbench"/);
  assert.match(
    source,
    /embedded, desktop, and browser code editors are adapter targets/,
  );
  assert.match(source, /id: "foundry"[\s\S]*label: "Foundry"/);
  assert.match(source, /id: "providers"[\s\S]*label: "Providers"/);
  assert.match(source, /id: "environments"[\s\S]*label: "Environments"/);
  assert.match(source, /Direct integrations for local, cloud, DePIN/);
  assert.doesNotMatch(source, /id: "fleet"[\s\S]*label: "Fleet"/);
  assert.doesNotMatch(source, /Hypervisor IDE|reverse-engineering\/ona/);
});

test("hypervisor shell models IOI-reference session detail and inspectors", () => {
  assert.match(source, /HYPERVISOR_PRIMARY_ACTION[\s\S]*New Session/);
  assert.match(source, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.match(source, /HYPERVISOR_SESSION_LAUNCH_RECIPES/);
  assert.match(source, /adapter_preference_ref/);
  assert.match(source, /code_editor_adapter_launch_plan_ref/);
  assert.match(source, /code_editor_adapter_connection_contract_ref/);
  assert.match(source, /code_editor_adapter_access_lease_refs/);
  assert.match(source, /"adapter_preference"/);
  for (const recipeId of [
    "mission.default",
    "workbench.default",
    "agent.default",
    "automation.default",
    "foundry.eval",
    "environment.provider",
    "privacy.workspace",
  ]) {
    assert.match(source, new RegExp(recipeId.replace(".", "\\.")));
  }
  assert.match(
    source,
    /Default Harness Profile or governed AgentHarnessAdapter/,
  );
  assert.match(source, /harnessOptions: HYPERVISOR_HARNESS_SELECTION_OPTIONS/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL/);
  assert.match(source, /HYPERVISOR_SESSION_DETAIL_TABS/);
  assert.match(source, /HypervisorSessionWorkspaceMode/);
  assert.match(source, /HypervisorSessionChangeInspectorMode/);
  assert.match(source, /HYPERVISOR_SESSION_WORKSPACE_MODES/);
  assert.match(
    source,
    /HYPERVISOR_SESSION_WORKSPACE_MODES = \[[\s\S]*mode_id: "code"[\s\S]*label: "Code"[\s\S]*\] as const/,
  );
  assert.doesNotMatch(source, /mode_id: "conversation"|label: "Conversation"/);
  assert.match(source, /HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES/);
  assert.match(
    source,
    /HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES = \[[\s\S]*mode_id: "changes"[\s\S]*label: "Changes"[\s\S]*mode_id: "all_files"[\s\S]*label: "All Files"[\s\S]*mode_id: "comments"[\s\S]*label: "Comments"/,
  );
  assert.match(
    source,
    /"agent"[\s\S]*"code"[\s\S]*"environment"[\s\S]*"changes"[\s\S]*"receipts"[\s\S]*"replay"/,
  );
  assert.match(source, /HYPERVISOR_RIGHT_INSPECTOR_PANELS/);
  assert.match(source, /HYPERVISOR_BOTTOM_INSPECTOR_PANELS/);
  assert.match(
    source,
    /"ports_services"[\s\S]*"tasks"[\s\S]*"terminal"[\s\S]*"logs"/,
  );
});

test("visible shell chrome uses Hypervisor labels over compatibility route keys", () => {
  assert.match(source, /id: "sessions"[\s\S]*label: "Sessions"/);
  assert.match(source, /id: "projects"[\s\S]*label: "Projects"/);
  assert.match(source, /id: "workbench"[\s\S]*label: "Workbench"/);
  assert.match(source, /id: "automations"[\s\S]*label: "Automations"/);
  assert.match(source, /id: "insights"[\s\S]*label: "Insights"/);
  assert.match(source, /id: "models"[\s\S]*label: "Models"/);
  assert.match(source, /id: "agents"[\s\S]*label: "Agents"/);
  assert.match(source, /id: "authority"[\s\S]*label: "Authority"/);
  assert.match(operatorSubstrate, /label: surface\.label/);
  assert.doesNotMatch(
    operatorSubstrate,
    /HYPERVISOR_SURFACE_PRIMARY_VIEW_ROUTES/,
  );
  assert.match(operatorSubstrate, /routeState: "active_route"/);
  assert.match(
    operatorSubstrate,
    /Search sessions, surfaces, commands, receipts, and workspace context/,
  );
  assert.match(activityBar, /aria-label="Hypervisor navigation"/);
  assert.match(activityBar, /data-ioi-reference-primary-rail="true"/);
  assert.match(
    activityBar,
    /data-left-nav-surfaces=\{referenceLeftNavSurfaceIds\.join\(" "\)\}/,
  );
  assert.match(activityBar, /referenceLeftNavSurfaceIds\.flatMap/);
  assert.match(activityBar, /const topNavItems = primaryNavItems\.filter/);
  assert.match(activityBar, /sessionsNavItem/);
  assert.match(activityBar, /hypervisor-activity-button--new-session/);
  assert.match(activityBar, /data-window-surface="new-session"/);
  assert.match(activityBar, /New Session/);
  assert.match(activityBar, /topNavItems\.map/);
  assert.match(activityBar, /label="Sessions"/);
  assert.match(activityBar, /icon=\{<SessionReferenceIcon \/>\}/);
  assert.match(activityBar, /shortcutKeys=\{\["Project"\]\}/);
  assert.match(activityBar, /shortcutVariant="label"/);
  assert.match(activityBar, /trailingIcon=\{<SessionsFilterIcon \/>\}/);
  assert.match(activityBar, /hypervisor-activity-project-label/);
  assert.match(activityBar, /From scratch/);
  assert.match(activityBar, /hypervisor-activity-session-list/);
  assert.match(activityBar, /launchedSessions: readonly HypervisorLaunchedSessionProjection\[\]/);
  assert.match(activityBar, /data-ioi-reference-session-list="from-launched-sessions"/);
  assert.match(activityBar, /data-launched-session-ref/);
  assert.match(activityBar, /data-launched-session-admission/);
  assert.match(activityBar, /GENERIC_HOME_NEW_SESSION_INTENT/);
  assert.match(activityBar, /HYPERVISOR_SESSION_LAUNCH_RECIPES\.find/);
  assert.match(activityBar, /return `\$\{recipe\.label\} for \$\{projectLabel\}`;/);
  assert.match(activityBar, /launchedSessionRailTitle/);
  assert.match(activityBar, /launchedSessionRailMeta/);
  assert.match(activityBar, /session\.branch_label/);
  assert.match(activityBar, /session\.relative_time_label/);
  assert.match(activityBar, /session\.activity_count/);
  assert.match(activityBar, /launchedSessionRailBadge/);
  assert.doesNotMatch(activityBar, /REFERENCE_SESSION_ROWS/);
  assert.doesNotMatch(activityBar, /Write Parent Harness Evidence Boundary Doc/);
  assert.doesNotMatch(activityBar, /Write Harness Tool Call Documentation/);
  assert.doesNotMatch(activityBar, /Design Postquantum Computers Website/);
  assert.doesNotMatch(activityBar, /hypervisor-activity-project-skeleton/);
  assert.doesNotMatch(
    activityBar,
    /data-ioi-reference-session-list="project-skeleton"/,
  );
  assert.doesNotMatch(activityBar, /Search\.\.\./);
  assert.doesNotMatch(activityBar, /What's New/);
  assert.doesNotMatch(activityBar, /label="Applications"/);
  assert.doesNotMatch(activityBar, /Your favorite apps will appear here/);
  assert.doesNotMatch(activityBar, /IOI Assist/);
  assert.doesNotMatch(activityBar, /REFERENCE_RECENT_SESSIONS/);
  assert.doesNotMatch(activityBar, /data-ioi-reference-session-list="true"/);
  assert.match(activityBar, /activateRoute\(sessionsNavItem\.route\)/);
  assert.match(activityBar, /Organization settings/);
  assert.match(activityBar, /WORKSPACE_NAME/);
  assert.match(activityBarIcons, /hypervisor-ioi-gem-vert/);
  assert.match(activityBarIcons, /<polygon points=/);
  assert.doesNotMatch(activityBarIcons, /strokeWidth="12"/);
  assert.match(activityBar, /hypervisor-activity-profile-indicator/);
  assert.match(activityBar, /hypervisor-activity-footer-profile-row/);
  assert.match(activityBar, /hypervisor-activity-profile-secondary/);
  assert.match(activityBar, /data-window-surface="workspace-notifications"/);
  assert.match(activityBar, /hypervisor-activity-profile-label/);
  assert.match(activityBar, /hypervisor-activity-profile-menu-indicator/);
  assert.doesNotMatch(activityBar, /hypervisor-activity-button--account/);
  assert.match(activityBar, /HYPERVISOR_PRIMARY_ACTION/);
  assert.match(activityBar, /aria-label="Session shortcuts"/);
  assert.doesNotMatch(activityBar, /aria-label="Projects"/);
  assert.doesNotMatch(
    activityBar,
    /aria-label="Governance and infrastructure"/,
  );
  assert.match(activityBar, /data-route-state=\{item\.routeState\}/);
  assert.doesNotMatch(shellContent, /HypervisorClientHeader/);
  assert.doesNotMatch(shellContent, /hypervisor-client-header/);
});

test("new session modal is a shell-level governed launch flow", () => {
  assert.match(newSessionModal, /HYPERVISOR_SESSION_LAUNCH_RECIPES/);
  assert.match(newSessionModal, /HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES/);
  assert.match(newSessionModal, /adapter_preference_ref: adapterPreferenceRef/);
  assert.match(newSessionModal, /buildHarnessCompatibilityVerdict/);
  assert.match(newSessionModal, /buildHypervisorNewSessionLaunchSummary/);
  assert.match(newSessionModal, /initialSeedIntent/);
  assert.match(newSessionModal, /initialRecipeId/);
  assert.match(newSessionModal, /initialRecipeSelectionRef/);
  assert.match(newSessionModal, /useEffect/);
  assert.match(
    newSessionModal,
    /setRecipeId\(initialRecipeSelectionRef\(initialRecipeId\)\)/,
  );
  assert.match(
    newSessionModal,
    /setSeedIntent\(initialSeedIntent\?\.trim\(\) \?\? ""\)/,
  );
  assert.match(newSessionModal, /seedIntent/);
  assert.match(newSessionModal, /seed_intent: nextLaunchSummary\.seed_intent/);
  assert.match(
    newSessionModal,
    /data-new-session-launch-cockpit="ioi-reference-governed-launch"/,
  );
  assert.match(newSessionModal, /hypervisor-new-session-modal__body--compact/);
  assert.match(newSessionModal, /compactLaunchChoices/);
  assert.match(newSessionModal, /HYPERVISOR_SESSION_LAUNCH_RECIPES\.map/);
  assert.match(newSessionModal, /launchRecipeTone/);
  assert.match(newSessionModal, /data-new-session-recipe-count/);
  assert.match(newSessionModal, /<span>Launch type<\/span>/);
  assert.match(newSessionModal, /data-new-session-start-selected="true"/);
  assert.match(
    newSessionModal,
    /data-new-session-recipe=\{choice\.recipe_id\}/,
  );
  assert.doesNotMatch(
    newSessionModal,
    /onLaunch\(buildLaunchRequest\(launchRecipe\)\)/,
  );
  assert.match(
    newSessionModal,
    /onClick=\{\(\) => \{\s*setRecipeId\(launchRecipe\.recipe_id\);\s*\}\}/s,
  );
  assert.match(
    newSessionModal,
    /onClick=\{\(\) => void onLaunch\(buildLaunchRequest\(recipe\)\)\}/,
  );
  for (const recipeId of [
    "mission.default",
    "workbench.default",
    "agent.default",
    "automation.default",
    "foundry.eval",
    "environment.provider",
    "privacy.workspace",
  ]) {
    assert.match(source, new RegExp(recipeId.replace(".", "\\.")));
  }
  assert.match(newSessionModal, /data-new-session-seed-intent/);
  assert.match(newSessionModal, /launch_summary: nextLaunchSummary/);
  assert.match(newSessionModal, /data-new-session-launch-summary/);
  assert.match(newSessionModal, /data-new-session-code-editor-adapter-ref/);
  assert.match(newSessionModal, /data-new-session-harness-selection-kind/);
  assert.match(newSessionModal, /selectedPrivacy\.ref/);
  assert.match(newSessionModal, /modelRouteSupportsHypervisorMount/);
  assert.match(
    newSessionModal,
    /modelRouteSupportsHypervisorMountFromInventory/,
  );
  assert.match(newSessionModal, /modelMountInventory/);
  assert.match(newSessionModal, /data-new-session-model-route-inventory-state/);
  assert.match(newSessionModal, /launchBlockedByHarnessVerdict/);
  assert.match(newSessionModal, /disabled=\{launchBlockedByHarnessVerdict\}/);
  assert.doesNotMatch(
    newSessionModal,
    /selectedModelRoute\.ref === "model-route:hypervisor\/default-local"/,
  );
  assert.doesNotMatch(newSessionModal, /modelRouteRef !== "model-route:none"/);
  assert.match(newSessionModal, /data-new-session-receipt-preview/);
  assert.match(newSessionModal, /data-new-session-project-ref/);
  assert.match(newSessionModal, /setProjectId/);
  assert.match(newSessionModal, /<span>Project<\/span>/);
  assert.match(newSessionModal, /projectOptions\.map/);
  assert.match(newSessionModal, /data-new-session-harness-verdict/);
  assert.match(newSessionModal, /cTEE private workspace/);
  assert.match(shellBaseCss, /hypervisor-new-session-modal__compact-choice strong/);
  assert.match(shellBaseCss, /grid-column: 2;/);
  assert.match(shellBaseCss, /hypervisor-new-session-modal__compact-choice b/);
  assert.match(shellBaseCss, /grid-column: 3;/);
  assert.doesNotMatch(newSessionModal, /Launch governed session/);
  assert.doesNotMatch(newSessionModal, /Code Editor Adapter/);
  assert.match(controller, /newSessionModalOpen/);
  assert.match(controller, /newSessionSeedIntent/);
  assert.match(controller, /newSessionRecipeId/);
  assert.match(controller, /type NewSessionModalSeed/);
  assert.match(
    controller,
    /openNewSessionModal: \(seed\?: NewSessionModalSeed\)/,
  );
  assert.match(controller, /typeof seed === "string"/);
  assert.match(controller, /recipeId/);
  assert.match(controller, /launchNewSession = async/);
  assert.match(controller, /requestCodeEditorAdapterLaunchPlanAdmission/);
  assert.match(controller, /buildHypervisorCodeEditorAdapterAdmissionFailure/);
  assert.match(controller, /buildCodeEditorAdapterLaunchPlan/);
  assert.match(controller, /codeEditorAdapterAdmission/);
  assert.match(source, /HypervisorLaunchedSessionProjection/);
  assert.match(source, /buildHypervisorLaunchedSessionProjection/);
  assert.match(source, /ioi\.hypervisor\.launched_session_projection\.v1/);
  assert.match(source, /code_editor_adapter_admission/);
  assert.match(source, /code_editor_adapter_executor_lane/);
  assert.match(source, /code_editor_adapter_control_action/);
  assert.match(source, /code_editor_adapter_control_channel_ref/);
  assert.match(source, /daemon_admitted/);
  assert.match(source, /daemon_blocked/);
  assert.match(source, /daemon_unavailable/);
  assert.match(source, /CodeEditorAdapterLaunchAdmissionError/);
  assert.match(controller, /launchedSessionProjections/);
  assert.match(controller, /loadHypervisorLaunchedSessionProjections/);
  assert.doesNotMatch(
    controller,
    /HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS|loaded\.length > 0[\s\S]*REFERENCE/,
  );
  assert.match(controller, /mergeHypervisorLaunchedSessionProjection/);
  assert.match(controller, /persistHypervisorLaunchedSessionProjections/);
  assert.match(controller, /hypervisorBrowserStorage/);
  assert.match(controller, /buildHypervisorLaunchedSessionProjection\(\{/);
  assert.match(controller, /setLaunchedSessionProjections\(\(current\) => \{/);
  assert.match(
    launchedSessionPersistence,
    /HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY/,
  );
  assert.match(
    launchedSessionPersistence,
    /ioi\.hypervisor\.launched_session_projections\.v1/,
  );
  assert.match(
    launchedSessionPersistence,
    /normalizeHypervisorLaunchedSessionProjection/,
  );
  assert.doesNotMatch(
    launchedSessionPersistence,
    /HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS|Write Parent Harness Evidence Boundary Doc|relative_time_label: "6h ago"|activity_count: 3/,
  );
  assert.match(
    launchedSessionPersistence,
    /runtimeTruthSource !== "daemon-runtime"/,
  );
  assert.match(controller, /buildHypervisorLaunchedSessionProjection\(\{[\s\S]*request,[\s\S]*recipe,[\s\S]*projectLabel: project\.name,[\s\S]*codeEditorAdapterAdmission/);
  assert.match(controller, /setCurrentProjectId\(project\.id\)/);
  assert.match(controller, /setActiveView\(recipe\.surface_id\)/);
  assert.match(shellWindow, /loadHypervisorModelMountInventorySnapshot/);
  assert.match(shellWindow, /setModelMountInventory/);
  assert.match(shellWindow, /<HypervisorNewSessionModal/);
  assert.match(
    shellWindow,
    /initialSeedIntent=\{controller\.modals\.newSessionSeedIntent\}/,
  );
  assert.match(
    shellWindow,
    /initialRecipeId=\{controller\.modals\.newSessionRecipeId\}/,
  );
  assert.match(shellWindow, /modelMountInventory=\{modelMountInventory\}/);
  assert.match(
    shellWindow,
    /onLaunch=\{controller\.modals\.launchNewSession\}/,
  );
});

test("Foundry exposes harness comparison as a governed runtime dashboard", () => {
  assert.match(shellContent, /HypervisorHarnessComparisonDashboard/);
  assert.match(shellContent, /HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE/);
  assert.match(shellContent, /requestHarnessPublicFixtureRun/);
  assert.match(shellContent, /data-hypervisor-harness-comparison-run/);
  assert.match(shellContent, /data-hypervisor-harness-comparison-state/);
  assert.match(shellContent, /data-harness-comparison-action="request-run"/);
  assert.match(shellContent, /setComparison\(nextComparison\)/);
  assert.match(shellContent, /unavailable/);
  assert.match(shellContent, /Harness comparison dashboard/);
  assert.match(
    shellContent,
    /output, cost, verification, receipts, and evidence/,
  );
  assert.match(shellContent, /candidate_reports\.map/);
  assert.match(shellContent, /data-harness-comparison-candidate/);
  assert.match(shellContent, /estimated_cost_usd/);
  assert.match(shellContent, /verification_status/);
  assert.match(shellContent, /receipt_ref/);
  assert.match(shellContent, /activeView === "foundry"/);
});

test("Sessions surface renders session tabs and operations inspectors from daemon projections", () => {
  assert.match(sessionOperationsModel, /HypervisorSessionOperationsProjection/);
  assert.match(
    sessionOperationsModel,
    /HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE/,
  );
  assert.match(
    sessionOperationsModel,
    /HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH/,
  );
  assert.match(
    sessionOperationsModel,
    /HYPERVISOR_SESSION_OPERATION_PROPOSAL_PATH/,
  );
  assert.match(sessionOperationsModel, /HypervisorSessionOperationProposal/);
  assert.match(
    sessionOperationsModel,
    /buildHypervisorSessionOperationProposal/,
  );
  assert.match(sessionOperationsModel, /proposeHypervisorSessionOperation/);
  assert.match(sessionOperationsModel, /wallet\.network grants/);
  assert.match(sessionOperationsModel, /Agentgres admits lifecycle/);
  assert.match(
    sessionOperationsModel,
    /loadHypervisorSessionOperationsProjection/,
  );
  assert.match(
    sessionOperationsModel,
    /normalizeHypervisorSessionOperationsProjection/,
  );
  assert.match(sessionOperationsModel, /HYPERVISOR_SESSION_DETAIL_TABS/);
  assert.match(sessionOperationsModel, /HYPERVISOR_RIGHT_INSPECTOR_PANELS/);
  assert.match(sessionOperationsModel, /HYPERVISOR_BOTTOM_INSPECTOR_PANELS/);
  assert.match(sessionOperationsModel, /access_lease_ref/);
  assert.match(sessionOperationsModel, /log_lease_ref/);
  assert.match(sessionOperationsModel, /archive_ref/);
  assert.match(sessionOperationsModel, /restore_ref/);
  assert.match(sessionOperationsModel, /ports_services/);
  assert.match(sessionOperationsModel, /terminal_events/);
  assert.match(sessionOperationsModel, /activity_signals/);
  assert.match(sessionOperationsModel, /access_log_leases/);
  assert.match(shellContent, /HypervisorSessionOperationsCockpit/);
  assert.match(
    shellContent,
    /controller\.sessions\.launchedSessionProjections/,
  );
  assert.match(
    shellContent,
    /workspaceActive \? \(\s*<WorkspaceShell\s+active\s+currentProject=\{currentProject\}/s,
  );
  assert.doesNotMatch(shellContent, /active=\{workspaceActive\}/);
  assert.doesNotMatch(shellContent, /launchedSessions: readonly HypervisorLaunchedSessionProjection\[\]/);
  assert.doesNotMatch(shellContent, /data-launched-session-list="new-session-projection-cache"/);
  assert.doesNotMatch(shellContent, /launchedSessionAdmissionLabel/);
  assert.doesNotMatch(shellContent, /launchedSessionAdmissionDetail/);
  assert.match(shellContent, /loadHypervisorSessionOperationsProjection/);
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Sessions\] operations projection unavailable/,
  );
  assert.match(shellContent, /data-hypervisor-session-operations/);
  assert.match(shellContent, /data-session-operations-source/);
  assert.match(shellContent, /data-runtime-truth-source/);
  assert.match(shellContent, /onOpenReceiptEvidence/);
  assert.match(shellContent, /data-session-open-receipts/);
  assert.match(shellContent, /data-session-open-receipts-session/);
  assert.match(shellContent, /HYPERVISOR_SESSION_WORKSPACE_MODES/);
  assert.match(shellContent, /HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES/);
  assert.match(
    shellContent,
    /data-session-reference-detail="code-workspace"/,
  );
  assert.match(shellContent, /aria-label="Session workspace modes"/);
  assert.match(shellContent, /data-session-workspace-mode-list/);
  assert.match(
    shellContent,
    /\.filter\(\s*\(mode\) => mode\.mode_id === "code"/,
  );
  assert.match(shellContent, /data-session-workspace-mode=\{mode\.mode_id\}/);
  assert.match(shellContent, /data-session-reference-page="workspace-detail"/);
  assert.match(shellContent, /data-session-workspace-cockpit/);
  assert.match(shellContent, /What do you want to get done today\?/);
  assert.match(shellContent, /Describe your task or type \/ for commands/);
  assert.match(
    shellContent,
    /aria-label="Changes, files, comments, and session inspectors"/,
  );
  assert.match(
    shellContent,
    /data-session-change-inspector="changes-files-comments"/,
  );
  assert.match(shellContent, /data-session-change-mode-list/);
  assert.match(
    shellContent,
    /className="hypervisor-session-operations__change-filter-row"/,
  );
  assert.match(
    shellContent,
    /className="hypervisor-session-operations__status-filter"/,
  );
  assert.match(shellContent, /data-session-changed-file/);
  assert.match(shellContent, /data-session-detail-tab-list/);
  assert.match(shellContent, /data-session-detail-tab="agent"[\s\S]*<strong>Agent<\/strong>/);
  assert.match(
    shellContent,
    /data-session-detail-tab="environment"[\s\S]*<strong>Environment<\/strong>/,
  );
  assert.match(shellContent, /data-session-lifecycle-state/);
  assert.doesNotMatch(shellContent, /\.filter\(\(tab\) => tab\.tab_id === "environment"\)/);
  assert.doesNotMatch(shellContent, /data-session-detail-tab=\{tab\.tab_id\}/);
  assert.match(shellContent, /data-session-port-services-count/);
  assert.doesNotMatch(shellContent, /hypervisor-session-operations__recent-launches/);
  assert.doesNotMatch(shellContent, /hypervisor-session-operations__environment/);
  assert.doesNotMatch(shellContent, /hypervisor-session-operations__startup-list/);
  assert.doesNotMatch(shellContent, /hypervisor-session-operations__activity-grid/);
  assert.doesNotMatch(shellContent, /data-session-activity-signal-list/);
  assert.doesNotMatch(shellContent, /data-session-activity-signal/);
  assert.doesNotMatch(shellContent, /data-session-lease=/);
  assert.doesNotMatch(shellContent, /data-session-archive-ref/);
  assert.doesNotMatch(shellContent, /data-session-restore-ref/);
  assert.doesNotMatch(shellContent, /formatSessionSignalKind/);
  assert.doesNotMatch(shellContent, /formatSessionLeaseStatus/);
  assert.match(shellContent, /data-session-task/);
  assert.match(shellContent, /data-session-terminal-event/);
  assert.doesNotMatch(shellContent, /HYPERVISOR_SESSION_OPERATION_KINDS/);
  assert.match(shellContent, /data-session-operation-kind/);
  assert.match(shellContent, /data-session-operation-proposal/);
  assert.match(shellContent, /data-session-operation-admission/);
  assert.match(shellContent, /data-session-operation-target/);
  assert.match(shellContent, /data-session-service-open-port/);
  assert.match(shellContent, /data-session-task-run/);
  assert.match(shellContent, /data-session-terminal-propose/);
  assert.match(shellContent, /proposeHypervisorSessionOperation/);
  assert.match(shellContent, /buildHypervisorSessionOperationProposal/);
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Sessions\] operation proposal unavailable/,
  );
  assert.doesNotMatch(shellContent, /operationProposal\.custody_invariant/);
  assert.match(shellContent, /activeView === "sessions"/);
});

test("Projects surface renders the reference Projects page over hidden project truth", () => {
  assert.match(projectStateModel, /HypervisorProjectStateProjection/);
  assert.match(
    projectStateModel,
    /HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE/,
  );
  assert.match(
    projectStateModel,
    /HYPERVISOR_PROJECT_STATE_CLEAN_BOOT_PROJECTION/,
  );
  assert.match(projectStateModel, /HYPERVISOR_PROJECT_STATE_PROJECTION_PATH/);
  assert.match(projectStateModel, /HYPERVISOR_PROJECT_OPERATION_PROPOSAL_PATH/);
  assert.match(projectStateModel, /loadHypervisorProjectStateProjection/);
  assert.match(projectStateModel, /proposeHypervisorProjectOperation/);
  assert.match(projectStateModel, /HypervisorProjectOperationProposal/);
  assert.match(projectStateModel, /normalizeHypervisorProjectStateProjection/);
  assert.match(projectStateModel, /agentgres_object_head_ref/);
  assert.match(projectStateModel, /state_root_ref/);
  assert.match(projectStateModel, /artifact_refs/);
  assert.match(projectStateModel, /archive_ref/);
  assert.match(projectStateModel, /restore_ref/);
  assert.match(projectStateModel, /Agentgres admits project truth/);
  assert.match(projectStateModel, /storage backends only hold bytes/);
  assert.match(shellContent, /HypervisorProjectStateSurface/);
  assert.match(shellContent, /loadHypervisorProjectStateProjection/);
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Projects\] state projection unavailable/,
  );
  assert.match(shellContent, /data-hypervisor-project-state/);
  assert.match(shellContent, /data-project-state-source/);
  assert.match(shellContent, /data-project-state-record-count/);
  assert.match(shellContent, /data-project-state-records/);
  assert.match(shellContent, /data-project-state-record/);
  assert.match(shellContent, /data-project-restore-state/);
  assert.match(shellContent, /data-project-custody-posture/);
  assert.match(shellContent, /data-project-workspace-ref/);
  assert.match(shellContent, /data-project-object-head-ref/);
  assert.match(shellContent, /data-project-state-root-ref/);
  assert.match(shellContent, /data-project-archive-ref/);
  assert.match(shellContent, /data-project-restore-ref/);
  assert.match(shellContent, /data-project-operation-kind/);
  assert.match(shellContent, /data-project-open-receipts/);
  assert.match(shellContent, /data-project-open-receipts-project/);
  assert.match(shellContent, /data-project-open-receipts-session/);
  assert.match(shellContent, /data-project-operation-proposal/);
  assert.match(shellContent, /data-project-operation-proposal-source/);
  assert.match(shellContent, /data-project-operation-admission-state/);
  assert.match(shellContent, /<h2>Projects<\/h2>/);
  assert.match(shellContent, /HYPERVISOR_PROJECT_STATE_CLEAN_BOOT_PROJECTION/);
  assert.match(shellContent, /<h3>No projects<\/h3>/);
  assert.match(shellContent, /Projects bundle your repo, secrets, and other configuration/);
  assert.match(shellContent, /Learn more about projects in IOI\./);
  assert.match(shellContent, /visibleProjects\.length > 0 \? \(/);
  assert.match(shellContent, /placeholder="Search projects"/);
  assert.match(shellContent, /aria-label="Project state records"/);
  assert.match(shellContent, /Restore ready/);
  assert.match(shellContent, /className="hypervisor-project-state__inspector"/);
  assert.match(shellContent, /aria-label="Selected project restore context"/);
  assert.match(shellContent, /Agentgres owns project truth/);
  assert.match(controller, /openReceiptEvidenceTarget/);
  assert.match(shellContent, /activeView === "projects"/);
});

test("Automations surface renders workflow compositor projection before editor", () => {
  assert.match(
    automationCompositorModel,
    /HypervisorAutomationCompositorProjection/,
  );
  assert.match(
    automationCompositorModel,
    /HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE/,
  );
  assert.match(
    automationCompositorModel,
    /HYPERVISOR_AUTOMATION_COMPOSITOR_CLEAN_BOOT_PROJECTION/,
  );
  assert.match(
    automationCompositorModel,
    /HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH/,
  );
  assert.match(
    automationCompositorModel,
    /HYPERVISOR_AUTOMATION_RUN_PROPOSAL_PATH/,
  );
  assert.match(
    automationCompositorModel,
    /loadHypervisorAutomationCompositorProjection/,
  );
  assert.match(
    automationCompositorModel,
    /proposeHypervisorAutomationRun/,
  );
  assert.match(
    automationCompositorModel,
    /HypervisorAutomationRunProposal/,
  );
  assert.match(
    automationCompositorModel,
    /ioi\.hypervisor\.automation_run_proposal\.v1/,
  );
  assert.match(
    automationCompositorModel,
    /normalizeHypervisorAutomationCompositorProjection/,
  );
  assert.match(automationCompositorModel, /workflow_template_refs/);
  assert.match(automationCompositorModel, /run_recipe_refs/);
  assert.match(automationCompositorModel, /graph_refs/);
  assert.match(automationCompositorModel, /action_proposal_ref/);
  assert.match(automationCompositorModel, /agentgres_operation_refs/);
  assert.match(automationCompositorModel, /state_root_ref/);
  assert.match(
    automationCompositorModel,
    /Workflow Compositor edits and proposes/,
  );
  assert.match(automationCompositorModel, /Hypervisor Core admits execution/);
  assert.match(
    automationCompositorModel,
    /Agentgres records operational truth/,
  );
  assert.match(shellContent, /HypervisorAutomationCompositorSurface/);
  assert.match(shellContent, /loadHypervisorAutomationCompositorProjection/);
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Automations\] compositor projection unavailable/,
  );
  assert.match(shellContent, /data-hypervisor-automation-compositor/);
  assert.match(shellContent, /data-automation-compositor-source/);
  assert.match(shellContent, /data-automation-run-proposal/);
  assert.match(shellContent, /data-automation-run-proposal-source/);
  assert.match(shellContent, /data-automation-run-admission-state/);
  assert.match(shellContent, /HYPERVISOR_AUTOMATION_COMPOSITOR_CLEAN_BOOT_PROJECTION/);
  assert.match(shellContent, /Total Automations/);
  assert.match(shellContent, /referenceAutomationTotal = 4/);
  assert.match(shellContent, /No automations yet/);
  assert.match(shellContent, /Automated dev environment setup/);
  assert.match(shellContent, /CVE mitigation & dependency updates/);
  assert.match(shellContent, /Draft weekly release notes/);
  assert.match(shellContent, /10x engineer/);
  assert.match(shellContent, /Scan recent commits for bugs/);
  assert.match(shellContent, /className="hypervisor-automation-compositor__empty"/);
  assert.match(shellContent, /automationRows\.length > 0/);
  assert.match(
    shellContent,
    /projection\.source !== "daemon-automation-compositor-projection"/,
  );
  assert.match(shellContent, /data-workflow-template-ref/);
  assert.match(shellContent, /data-workflow-run-recipe-ref/);
  assert.match(shellContent, /data-workflow-graph-ref/);
  assert.match(shellContent, /data-automation-run-proposal-template/);
  assert.match(shellContent, /data-workflow-template-suggestion/);
  assert.match(shellContent, /data-workflow-compositor-editor-boundary/);
  assert.match(shellContent, /activeView === "automations"/);
});

test("Agents surface renders workers as a cockpit list", () => {
  assert.match(agentsModel, /HypervisorAgentsProjection/);
  assert.match(agentsModel, /HYPERVISOR_AGENTS_PROJECTION_FIXTURE/);
  assert.match(agentsModel, /HYPERVISOR_AGENTS_PROJECTION_PATH/);
  assert.match(agentsModel, /loadHypervisorAgentsProjection/);
  assert.match(agentsModel, /normalizeHypervisorAgentsProjection/);
  assert.match(agentsModel, /ioi\.hypervisor\.agents_projection\.v1/);
  assert.match(agentsModel, /DEFAULT_HARNESS_PROFILE_OPTION/);
  assert.match(agentsModel, /defaultHarnessRef/);
  assert.match(agentsModel, /agent-harness-adapter:codex_cli/);
  assert.match(agentsModel, /proposal_source_only/);
  assert.match(agentsModel, /Agent Wiki \/ ioi-memory/);
  assert.match(agentsModel, /wallet.network capability leases/);
  assert.match(agentsModel, /agentgres_operation_refs/);
  assert.match(agentsModel, /state_root_ref/);
  assert.match(shellContent, /HypervisorAgentsSurface/);
  assert.match(shellContent, /loadHypervisorAgentsProjection/);
  assert.match(shellContent, /\[Hypervisor\]\[Agents\] projection unavailable/);
  assert.match(shellContent, /data-hypervisor-agents/);
  assert.match(shellContent, /data-hypervisor-agents-source/);
  assert.match(shellContent, /data-agent-harness-boundary/);
  assert.match(shellContent, /data-agent-capability-lease/);
  assert.match(shellContent, /data-agent-capability-management-boundary/);
  assert.match(shellContent, /<h2>Agents<\/h2>/);
  assert.match(shellContent, /className="hypervisor-agents__primary"/);
  assert.match(shellContent, /className="hypervisor-agents__filters"/);
  assert.match(shellContent, /placeholder="Search agents\.\.\."/);
  assert.match(shellContent, />Sort: Updated</);
  assert.match(shellContent, /className="hypervisor-agents__summary-strip"/);
  assert.match(shellContent, /className="hypervisor-agents__inline-inspector"/);
  assert.match(shellContent, /className="hypervisor-agents__detail-label"/);
  assert.match(shellContent, />Selected agent</);
  assert.match(shellContent, /className="hypervisor-agents__detail-column"/);
  assert.match(shellContent, /formatAgentHarnessLabel/);
  assert.match(shellContent, /formatCapabilityRef/);
  assert.match(shellContent, /formatModelRouteRef/);
  assert.match(shellContent, /formatPrivacyPostureRef/);
  assert.match(shellContent, /formatWorkspaceRef/);
  assert.match(shellContent, /formatLeaseExpiry/);
  assert.match(shellContent, />Interface</);
  assert.match(shellContent, />Access</);
  assert.match(shellContent, />Updated</);
  assert.match(shellContent, /className="hypervisor-agents__workplane"/);
  assert.match(shellContent, /className="hypervisor-agents__list"/);
  assert.match(shellContent, /className="hypervisor-agents__detail"/);
  assert.match(shellContent, /return "Built-in"/);
  assert.match(shellContent, /return "Terminal"/);
  assert.match(shellContent, /return "Code tool"/);
  assert.match(
    shellContent,
    /data-agent-state-root-ref=\{agent\.state_root_ref\}/,
  );
  assert.match(
    shellContent,
    /data-agent-latest-receipt-ref=\{agent\.latest_receipt_refs\[0\] \?\? ""\}/,
  );
  assert.match(shellContent, /activeView === "agents"/);
  assert.match(shellContent, /<CapabilitiesView/);
});

test("Insights surface renders the IOI reference product surface before runtime analytics", () => {
  assert.match(shellContent, /insightsDashboardPreviewUrl/);
  assert.match(shellContent, /HypervisorInsightsReferenceSurface/);
  assert.match(shellContent, /data-hypervisor-insights-reference/);
  assert.match(shellContent, /Turn Insights into actionable intelligence/);
  assert.match(shellContent, /Available on Enterprise/);
  assert.match(shellContent, /Request trial/);
  assert.match(shellContent, /Learn more/);
  assert.match(shellContent, /Use Insights to:/);
  assert.match(shellContent, /Analyze usage across your organization/);
  assert.match(shellContent, /Maximize ROI and manage costs/);
  assert.match(shellContent, /Drive team productivity through insights/);
  assert.match(shellContent, /data-insights-runtime-projection-boundary/);
  assert.match(
    shellContent,
    /activeView === "insights"[\s\S]*<HypervisorInsightsReferenceSurface>[\s\S]*<RuntimeInsightsView runtime=\{runtime\} \/>[\s\S]*<\/HypervisorInsightsReferenceSurface>/,
  );
  assert.doesNotMatch(
    shellContent,
    /activeView === "insights" \? \(\s*<RuntimeInsightsView runtime=\{runtime\} \/>/,
  );
});

test("Models surface renders model infrastructure projection before mount UI", () => {
  assert.match(
    modelInfrastructureModel,
    /HypervisorModelInfrastructureProjection/,
  );
  assert.match(
    modelInfrastructureModel,
    /HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE/,
  );
  assert.match(
    modelInfrastructureModel,
    /HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH/,
  );
  assert.match(
    modelInfrastructureModel,
    /buildHypervisorModelInfrastructureProjectionFromInventory/,
  );
  assert.match(
    modelInfrastructureModel,
    /loadHypervisorModelInfrastructureProjection/,
  );
  assert.match(
    modelInfrastructureModel,
    /normalizeHypervisorModelInfrastructureProjection/,
  );
  assert.match(modelInfrastructureModel, /model_route_refs/);
  assert.match(modelInfrastructureModel, /endpoint_refs/);
  assert.match(modelInfrastructureModel, /loaded_instance_refs/);
  assert.match(modelInfrastructureModel, /session_bindings/);
  assert.match(modelInfrastructureModel, /model_weight_custody_policy_refs/);
  assert.match(modelInfrastructureModel, /authority_scope_refs/);
  assert.match(
    modelInfrastructureModel,
    /Models is an infrastructure projection/,
  );
  assert.match(modelInfrastructureModel, /Hypervisor Core admits execution/);
  assert.match(modelInfrastructureModel, /Agentgres records model-route truth/);
  assert.match(shellContent, /HypervisorModelInfrastructureSurface/);
  assert.match(shellContent, /loadHypervisorModelInfrastructureProjection/);
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Models\] infrastructure projection unavailable/,
  );
  assert.match(shellContent, /data-hypervisor-model-infrastructure/);
  assert.match(shellContent, /data-model-infrastructure-source/);
  assert.match(shellContent, /data-model-route-ref/);
  assert.match(shellContent, /data-model-route-detail/);
  assert.match(shellContent, /data-model-provider-ref/);
  assert.match(shellContent, /data-model-session-binding/);
  assert.match(shellContent, /data-model-mounting-ui-boundary/);
  assert.match(
    shellContent,
    /className="hypervisor-model-infrastructure__workplane"/,
  );
  assert.match(
    shellContent,
    /className="hypervisor-model-infrastructure__list"/,
  );
  assert.match(
    shellContent,
    /className="hypervisor-model-infrastructure__detail"/,
  );
  assert.doesNotMatch(
    shellContent,
    /className="hypervisor-model-infrastructure__summary"/,
  );
  assert.doesNotMatch(
    shellContent,
    /className="hypervisor-model-infrastructure__grid"/,
  );
  assert.doesNotMatch(
    shellContent,
    /className="hypervisor-model-infrastructure__card"/,
  );
  assert.doesNotMatch(
    shellContent,
    /\{projection\.infrastructure_boundary_invariant\}/,
  );
  assert.match(shellContent, /activeView === "models"/);
});

test("Providers and Environments surfaces are direct integrations, not Fleet placeholders", () => {
  assert.match(providerPlacementModel, /HypervisorProviderPlacementProjection/);
  assert.match(
    providerPlacementModel,
    /HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE/,
  );
  assert.match(
    providerPlacementModel,
    /HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH/,
  );
  assert.match(
    providerPlacementModel,
    /HYPERVISOR_PROVIDER_OPERATION_PROPOSAL_PATH/,
  );
  assert.match(providerPlacementModel, /HypervisorProviderOperationProposal/);
  assert.match(
    providerPlacementModel,
    /loadHypervisorProviderPlacementProjection/,
  );
  assert.match(
    providerPlacementModel,
    /normalizeHypervisorProviderPlacementProjection/,
  );
  assert.match(providerPlacementModel, /proposeHypervisorProviderOperation/);
  assert.match(providerPlacementModel, /wallet_lease_ref/);
  assert.match(providerPlacementModel, /agentgres_operation_ref/);
  assert.match(providerPlacementModel, /anti_gateway_invariant/);
  assert.match(providerPlacementModel, /wallet\.network authorizes/);
  assert.match(providerPlacementModel, /Agentgres records admitted truth/);
  assert.match(providerPlacementModel, /provider-candidate:akash-gpu/);
  assert.match(providerPlacementModel, /provider-candidate:filecoin-archive/);
  assert.match(providerPlacementModel, /ctee_split_required/);
  assert.match(providerPlacementModel, /encrypted_storage_only/);
  assert.doesNotMatch(providerPlacementModel, /decentralized\.cloud/);
  assert.match(shellContent, /HypervisorProviderPlacementDashboard/);
  assert.match(shellContent, /loadHypervisorProviderPlacementProjection/);
  assert.match(shellContent, /proposeHypervisorProviderOperation/);
  assert.match(shellContent, /data-provider-operation-kind/);
  assert.match(shellContent, /data-provider-operation-proposal/);
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Providers\] operation proposal unavailable/,
  );
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Providers\] placement projection unavailable/,
  );
  assert.match(shellContent, /HypervisorEnvironmentEstateSurface/);
  assert.match(shellContent, /EnvironmentEstateView runtime=\{runtime\}/);
  assert.match(shellContent, /data-hypervisor-provider-placement/);
  assert.match(shellContent, /data-provider-placement-source/);
  assert.match(shellContent, /data-provider-placement-candidate/);
  assert.match(shellContent, /data-hypervisor-environment-estate/);
  assert.match(shellContent, /Choose where sessions can run/);
  assert.match(shellContent, /before attaching a workspace to infrastructure/);
  assert.match(
    shellContent,
    /\{candidate\.wallet_authority_scope_refs\.length\} controls/,
  );
  assert.match(
    shellContent,
    /candidate\.agentgres_receipt_ref \? "Available" : "Pending"/,
  );
  const providerSurface = sourceSlice(
    shellContent,
    "function HypervisorProviderPlacementDashboard",
    "function HypervisorEnvironmentEstateSurface",
  );
  assert.doesNotMatch(providerSurface, /governed sessions/);
  assert.doesNotMatch(
    providerSurface,
    /<dd>\{candidate\.agentgres_receipt_ref\}<\/dd>/,
  );
  assert.doesNotMatch(
    providerSurface,
    /<dd>\{candidate\.storage_policy_ref\}<\/dd>/,
  );
  assert.doesNotMatch(
    providerSurface,
    /<dd>\{candidate\.restore_policy_ref\}<\/dd>/,
  );
  assert.doesNotMatch(shellContent, /projection\.anti_gateway_invariant/);
  assert.doesNotMatch(
    shellContent,
    /This view reads the live environment estate through Hypervisor Core/,
  );
  assert.match(shellContent, /activeView === "providers"/);
  assert.match(shellContent, /activeView === "environments"/);
});

test("Hypervisor shell surfaces do not fall back to generic placeholder bodies", () => {
  assert.doesNotMatch(shellContent, /PLACEHOLDER_SURFACE_COPY/);
  assert.doesNotMatch(shellContent, /HypervisorSurfacePlaceholder/);
  assert.doesNotMatch(shellContent, /isPlaceholderSurface/);
  assert.doesNotMatch(shellContent, /hypervisor-surface-placeholder/);
});

test("Receipts surface renders Agentgres-bound evidence instead of a placeholder", () => {
  assert.match(receiptEvidenceModel, /HypervisorReceiptEvidenceProjection/);
  assert.match(
    receiptEvidenceModel,
    /HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE/,
  );
  assert.match(
    receiptEvidenceModel,
    /HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH/,
  );
  assert.match(receiptEvidenceModel, /loadHypervisorReceiptEvidenceProjection/);
  assert.match(receiptEvidenceModel, /daemon-receipt-evidence-projection/);
  assert.match(receiptEvidenceModel, /page_cursor/);
  assert.match(receiptEvidenceModel, /next_page_cursor/);
  assert.match(receiptEvidenceModel, /has_more/);
  assert.match(receiptEvidenceModel, /pageCursor/);
  assert.match(receiptEvidenceModel, /pageSize/);
  assert.match(receiptEvidenceModel, /receipt_boundary_invariant/);
  assert.match(receiptEvidenceModel, /Agentgres admits operational truth/);
  assert.match(receiptEvidenceModel, /artifact_refs/);
  assert.match(receiptEvidenceModel, /trace_refs/);
  assert.match(receiptEvidenceModel, /state_root_ref/);
  assert.match(receiptEvidenceModel, /replay_ref/);
  assert.match(receiptEvidenceModel, /harness_comparison/);
  assert.match(receiptEvidenceModel, /artifact_restore/);
  assert.match(shellContent, /HypervisorReceiptEvidenceSurface/);
  assert.match(shellContent, /loadHypervisorReceiptEvidenceProjection/);
  assert.match(shellContent, /data-hypervisor-receipt-evidence/);
  assert.match(shellContent, /data-receipt-evidence-source/);
  assert.match(shellContent, /data-receipt-evidence-record/);
  assert.match(shellContent, /data-receipt-evidence-kind/);
  assert.match(shellContent, /data-receipt-evidence-status/);
  assert.match(shellContent, /data-receipt-evidence-filter-controls/);
  assert.match(shellContent, /data-receipt-evidence-filtered-count/);
  assert.match(shellContent, /data-receipt-evidence-selected-ref/);
  assert.match(shellContent, /data-receipt-evidence-page-cursor/);
  assert.match(shellContent, /data-receipt-evidence-next-page-cursor/);
  assert.match(shellContent, /data-receipt-evidence-next-page/);
  assert.match(shellContent, /data-receipt-evidence-has-more/);
  assert.match(shellContent, /data-receipt-evidence-target-source/);
  assert.match(shellContent, /data-receipt-evidence-target-project/);
  assert.match(shellContent, /data-receipt-evidence-target-session/);
  assert.match(shellContent, /data-receipt-evidence-target-ref/);
  assert.match(shellContent, /data-receipt-evidence-detail/);
  assert.match(shellContent, /data-receipt-evidence-replay-ref/);
  assert.match(shellContent, /data-receipt-evidence-review/);
  assert.match(
    shellContent,
    /\[Hypervisor\]\[Receipts\] evidence projection unavailable/,
  );
  assert.doesNotMatch(shellContent, /projection\.receipt_boundary_invariant/);
  assert.match(shellContent, /activeView === "receipts"/);
});

test("Privacy surface renders cTEE and model-weight custody admission posture", () => {
  assert.match(privacyPostureModel, /HypervisorPrivacyPostureProjection/);
  assert.match(
    privacyPostureModel,
    /HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE/,
  );
  assert.match(
    privacyPostureModel,
    /Model-weight custody is a separate admission lane/,
  );
  assert.match(privacyPostureModel, /WorkspaceCustodySegment/);
  assert.match(privacyPostureModel, /ModelWeightCustodyPolicy/);
  assert.match(privacyPostureModel, /node_plaintext_allowed/);
  assert.match(privacyPostureModel, /forbidden_plaintext_mount/);
  assert.match(privacyPostureModel, /remote_api_capability/);
  assert.match(privacyPostureModel, /tee_or_customer_cloud_mount/);
  assert.match(privacyPostureModel, /modelWeightCustodyAdmissionAction/);
  assert.match(
    privacyPostureModel,
    /requestHypervisorModelWeightCustodyAdmission/,
  );
  assert.match(privacyPostureModel, /HYPERVISOR_MODEL_WEIGHT_CUSTODY_ADMISSION_PATH/);
  assert.match(privacyPostureModel, /ctee_split/);
  assert.match(privacyPostureModel, /encrypted_storage_only/);
  assert.match(privacyPostureModel, /wallet_network/);
  assert.match(privacyPostureModel, /hypervisor_daemon/);
  assert.match(privacyPostureModel, /agentgres/);
  assert.match(shellContent, /HypervisorPrivacyPostureSurface/);
  assert.match(shellContent, /data-hypervisor-privacy-posture/);
  assert.match(shellContent, /data-privacy-workspace-segment/);
  assert.match(shellContent, /data-model-weight-custody-lane/);
  assert.match(shellContent, /data-model-weight-custody-admission-action/);
  assert.match(shellContent, /data-model-weight-custody-admission-request/);
  assert.match(shellContent, /data-model-weight-custody-admission-runtime-truth/);
  assert.match(shellContent, /data-provider-privacy-candidate/);
  assert.match(shellContent, /data-privacy-admission-control/);
  assert.doesNotMatch(shellContent, /projection\.invariant/);
  assert.match(shellContent, /activeView === "privacy"/);
  assert.doesNotMatch(
    shellContent,
    /privacy: \{\s*eyebrow: "Private workspace"/,
  );
});

console.log("hypervisorShellNavigationModel.test.mjs: ok");
