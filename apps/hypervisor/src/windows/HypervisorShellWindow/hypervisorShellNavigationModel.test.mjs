import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("./hypervisorShellNavigationModel.ts", import.meta.url),
  "utf8",
);
const workbenchAdapterPreferences = readFileSync(
  new URL("./workbenchAdapterPreferences.ts", import.meta.url),
  "utf8",
);
const operatorSubstrate = readFileSync(
  new URL("./operatorSubstrateModel.ts", import.meta.url),
  "utf8",
);
const activityBar = readFileSync(
  new URL("./components/ChatLocalActivityBar.tsx", import.meta.url),
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
const header = readFileSync(
  new URL("./components/HypervisorClientHeader.tsx", import.meta.url),
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
  assert.match(source, /primaryReference: "internal-docs\/reverse-engineering\/ioi"/);
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
    "workbench_adapter",
    "secrets",
    "git_auth",
    "personal_access_tokens",
    "integrations",
  ]) {
    assert.match(source, new RegExp(`"${settingsSection}"`));
  }
  assert.match(source, /Codex CLI[\s\S]*Claude Code[\s\S]*DeepSeek TUI[\s\S]*Grok Build/);
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
  assert.match(source, /HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES/);
  assert.match(workbenchAdapterPreferences, /WorkbenchAdapterPreference/);
  assert.match(workbenchAdapterPreferences, /WorkbenchAdapterLaunchPlan/);
  assert.match(workbenchAdapterPreferences, /buildWorkbenchAdapterLaunchPlan/);
  assert.match(
    workbenchAdapterPreferences,
    /ioi\.hypervisor\.workbench_adapter_launch_plan\.v1/,
  );
  assert.match(source, /DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF/);
  assert.match(source, /workbench_adapter/);
  assert.match(
    workbenchAdapterPreferences,
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
  assert.doesNotMatch(activityBar, /stored === null \? true : stored === "true"/);
});

test("hypervisor shell keeps application surfaces separate from clients", () => {
  assert.match(source, /id: "workbench"[\s\S]*label: "Workbench"/);
  assert.match(
    source,
    /editors, terminals, browsers, and VMs are adapter targets/,
  );
  assert.match(source, /id: "foundry"[\s\S]*label: "Foundry"/);
  assert.match(source, /id: "providers"[\s\S]*label: "Providers"/);
  assert.match(source, /id: "environments"[\s\S]*label: "Environments"/);
  assert.match(source, /Direct integrations for local, cloud, DePIN/);
  assert.doesNotMatch(source, /id: "fleet"[\s\S]*label: "Fleet"/);
  assert.doesNotMatch(
    source,
    /Hypervisor IDE|reverse-engineering\/ona/,
  );
});

test("hypervisor shell models IOI-reference session detail and inspectors", () => {
  assert.match(source, /HYPERVISOR_PRIMARY_ACTION[\s\S]*New Session/);
  assert.match(source, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.match(source, /HYPERVISOR_SESSION_LAUNCH_RECIPES/);
  assert.match(source, /adapter_preference_ref/);
  assert.match(source, /workbench_adapter_launch_plan_ref/);
  assert.match(source, /workbench_adapter_connection_contract_ref/);
  assert.match(source, /workbench_adapter_access_lease_refs/);
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
    /HYPERVISOR_SESSION_WORKSPACE_MODES = \[[\s\S]*mode_id: "code"[\s\S]*label: "Code"[\s\S]*mode_id: "conversation"[\s\S]*label: "Conversation"/,
  );
  assert.match(source, /HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES/);
  assert.match(
    source,
    /HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES = \[[\s\S]*mode_id: "changes"[\s\S]*label: "Changes"[\s\S]*mode_id: "all_files"[\s\S]*label: "All Files"[\s\S]*mode_id: "comments"[\s\S]*label: "Comments"/,
  );
  assert.match(
    source,
    /"agent"[\s\S]*"workbench"[\s\S]*"environment"[\s\S]*"changes"[\s\S]*"receipts"[\s\S]*"replay"/,
  );
  assert.match(source, /HYPERVISOR_RIGHT_INSPECTOR_PANELS/);
  assert.match(source, /HYPERVISOR_BOTTOM_INSPECTOR_PANELS/);
  assert.match(
    source,
    /"ports_services"[\s\S]*"tasks"[\s\S]*"terminal"[\s\S]*"logs"/,
  );
});

test("visible shell chrome uses Hypervisor labels over compatibility route keys", () => {
  assert.match(operatorSubstrate, /sessions: "Sessions"/);
  assert.match(operatorSubstrate, /projects: "Projects"/);
  assert.match(operatorSubstrate, /workbench: "Workbench"/);
  assert.match(operatorSubstrate, /automations: "Automations"/);
  assert.match(operatorSubstrate, /insights: "Insights"/);
  assert.match(operatorSubstrate, /models: "Models"/);
  assert.match(operatorSubstrate, /agents: "Agents"/);
  assert.match(operatorSubstrate, /authority: "Authority"/);
  assert.doesNotMatch(operatorSubstrate, /HYPERVISOR_SURFACE_PRIMARY_VIEW_ROUTES/);
  assert.match(operatorSubstrate, /routeState: "active_route"/);
  assert.match(
    operatorSubstrate,
    /Search Hypervisor, projects, insights, sessions, and commands/,
  );
  assert.match(activityBar, /aria-label="Hypervisor navigation"/);
  assert.match(activityBar, /data-ioi-reference-primary-rail="true"/);
  assert.match(activityBar, /data-left-nav-surfaces=\{referenceLeftNavSurfaceIds\.join\(" "\)\}/);
  assert.match(activityBar, /referenceLeftNavSurfaceIds\.flatMap/);
  assert.match(activityBar, /topReferenceNavItems/);
  assert.match(activityBar, /sessionsNavItem/);
  assert.match(activityBar, /chat-activity-button--new-session/);
  assert.match(activityBar, /chat-activity-session-list/);
  assert.match(activityBar, /data-ioi-reference-session-list="empty"/);
  assert.doesNotMatch(activityBar, /REFERENCE_RECENT_SESSIONS/);
  assert.doesNotMatch(activityBar, /data-ioi-reference-session-list="true"/);
  assert.doesNotMatch(activityBar, /Write Parent Harness Evidence Boundary Doc/);
  assert.match(activityBar, /activateRoute\(sessionsNavItem\.route\)/);
  assert.doesNotMatch(activityBar, /chat-activity-project-skeleton/);
  assert.match(activityBar, /Organization settings/);
  assert.match(activityBar, /HYPERVISOR_PRIMARY_ACTION/);
  assert.doesNotMatch(activityBar, /aria-label="Applications"/);
  assert.doesNotMatch(activityBar, /aria-label="Governance and infrastructure"/);
  assert.match(activityBar, /data-route-state=\{item\.routeState\}/);
  assert.match(header, /`Hypervisor .*?\$\{windowSurfaceTitle/s);
  assert.doesNotMatch(header, /Autopilot Chat/);
});

test("new session modal is a shell-level governed launch flow", () => {
  assert.match(newSessionModal, /HYPERVISOR_SESSION_LAUNCH_RECIPES/);
  assert.match(newSessionModal, /HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES/);
  assert.match(newSessionModal, /adapter_preference_ref: adapterPreferenceRef/);
  assert.match(newSessionModal, /buildHarnessCompatibilityVerdict/);
  assert.match(newSessionModal, /buildHypervisorNewSessionLaunchSummary/);
  assert.match(newSessionModal, /initialSeedIntent/);
  assert.match(newSessionModal, /initialRecipeId/);
  assert.match(newSessionModal, /initialRecipeSelectionRef/);
  assert.match(newSessionModal, /useEffect/);
  assert.match(newSessionModal, /setRecipeId\(initialRecipeSelectionRef\(initialRecipeId\)\)/);
  assert.match(newSessionModal, /setSeedIntent\(initialSeedIntent\?\.trim\(\) \?\? ""\)/);
  assert.match(newSessionModal, /seedIntent/);
  assert.match(newSessionModal, /seed_intent: nextLaunchSummary\.seed_intent/);
  assert.match(newSessionModal, /data-new-session-launch-cockpit="ioi-reference-governed-launch"/);
  assert.match(newSessionModal, /hypervisor-new-session-modal__body--compact/);
  assert.match(newSessionModal, /compactLaunchChoices/);
  assert.match(newSessionModal, /Start from project/);
  assert.match(newSessionModal, /Start from URL/);
  assert.match(newSessionModal, /Start from scratch/);
  assert.match(newSessionModal, /data-new-session-recipe=\{choice\.recipe_id\}/);
  assert.match(newSessionModal, /data-new-session-seed-intent/);
  assert.match(newSessionModal, /launch_summary: nextLaunchSummary/);
  assert.match(newSessionModal, /data-new-session-launch-summary/);
  assert.match(newSessionModal, /data-new-session-workbench-adapter-ref/);
  assert.match(newSessionModal, /data-new-session-harness-selection-kind/);
  assert.match(newSessionModal, /selectedPrivacy\.ref/);
  assert.match(newSessionModal, /modelRouteSupportsHypervisorMount/);
  assert.match(newSessionModal, /modelRouteSupportsHypervisorMountFromInventory/);
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
  assert.match(newSessionModal, /data-new-session-harness-verdict/);
  assert.match(newSessionModal, /cTEE private workspace/);
  assert.doesNotMatch(newSessionModal, /Launch governed session/);
  assert.doesNotMatch(newSessionModal, /Workbench Adapter/);
  assert.match(controller, /newSessionModalOpen/);
  assert.match(controller, /newSessionSeedIntent/);
  assert.match(controller, /newSessionRecipeId/);
  assert.match(controller, /type NewSessionModalSeed/);
  assert.match(controller, /openNewSessionModal: \(seed\?: NewSessionModalSeed\)/);
  assert.match(controller, /typeof seed === "string"/);
  assert.match(controller, /recipeId/);
  assert.match(controller, /launchNewSession = async/);
  assert.match(controller, /requestWorkbenchAdapterLaunchPlanAdmission/);
  assert.match(controller, /buildHypervisorWorkbenchAdapterAdmissionFailure/);
  assert.match(controller, /buildWorkbenchAdapterLaunchPlan/);
  assert.match(controller, /workbenchAdapterAdmission/);
  assert.match(source, /HypervisorLaunchedSessionProjection/);
  assert.match(source, /buildHypervisorLaunchedSessionProjection/);
  assert.match(source, /ioi\.hypervisor\.launched_session_projection\.v1/);
  assert.match(source, /workbench_adapter_admission/);
  assert.match(source, /daemon_admitted/);
  assert.match(source, /daemon_blocked/);
  assert.match(source, /daemon_unavailable/);
  assert.match(source, /WorkbenchAdapterLaunchAdmissionError/);
  assert.match(controller, /launchedSessionProjections/);
  assert.match(controller, /buildHypervisorLaunchedSessionProjection\(\{/);
  assert.match(controller, /setLaunchedSessionProjections\(\(current\) => \[/);
  assert.match(controller, /const summary = request\.launch_summary/);
  assert.match(controller, /summary\.seed_intent/);
  assert.match(controller, /summary\.harness_label/);
  assert.match(controller, /summary\.model_route_availability_state/);
  assert.match(controller, /summary\.workbench_adapter_ref/);
  assert.match(controller, /setCurrentProjectId\(project\.id\)/);
  assert.match(controller, /setActiveView\(recipe\.surface_id\)/);
  assert.match(shellWindow, /loadHypervisorModelMountInventorySnapshot/);
  assert.match(shellWindow, /setModelMountInventory/);
  assert.match(shellWindow, /<HypervisorNewSessionModal/);
  assert.match(shellWindow, /initialSeedIntent=\{controller\.modals\.newSessionSeedIntent\}/);
  assert.match(shellWindow, /initialRecipeId=\{controller\.modals\.newSessionRecipeId\}/);
  assert.match(shellWindow, /modelMountInventory=\{modelMountInventory\}/);
  assert.match(shellWindow, /onLaunch=\{controller\.modals\.launchNewSession\}/);
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
  assert.match(shellContent, /output, cost, verification, receipts, and evidence/);
  assert.match(shellContent, /candidate_reports\.map/);
  assert.match(shellContent, /data-harness-comparison-candidate/);
  assert.match(shellContent, /estimated_cost_usd/);
  assert.match(shellContent, /verification_status/);
  assert.match(shellContent, /receipt_ref/);
  assert.match(shellContent, /activeView === "foundry"/);
});

test("Sessions surface renders session tabs and operations inspectors from daemon projections", () => {
  assert.match(sessionOperationsModel, /HypervisorSessionOperationsProjection/);
  assert.match(sessionOperationsModel, /HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE/);
  assert.match(sessionOperationsModel, /HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH/);
  assert.match(sessionOperationsModel, /HYPERVISOR_SESSION_OPERATION_PROPOSAL_PATH/);
  assert.match(sessionOperationsModel, /HypervisorSessionOperationProposal/);
  assert.match(sessionOperationsModel, /buildHypervisorSessionOperationProposal/);
  assert.match(sessionOperationsModel, /proposeHypervisorSessionOperation/);
  assert.match(sessionOperationsModel, /wallet\.network grants/);
  assert.match(sessionOperationsModel, /Agentgres admits lifecycle/);
  assert.match(sessionOperationsModel, /loadHypervisorSessionOperationsProjection/);
  assert.match(sessionOperationsModel, /normalizeHypervisorSessionOperationsProjection/);
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
  assert.match(shellContent, /<HypervisorSessionOperationsCockpit \/>/);
  assert.doesNotMatch(shellContent, /launchedSessions: HypervisorLaunchedSessionProjection\[\]/);
  assert.doesNotMatch(shellContent, /data-launched-session-/);
  assert.doesNotMatch(shellContent, /canOpenLaunchedSessionSurface/);
  assert.doesNotMatch(shellContent, /launchedSessionAdmissionLabel/);
  assert.doesNotMatch(shellContent, /launchedSessionAdmissionDetail/);
  assert.doesNotMatch(shellContent, /controller\.sessions\.launchedSessionProjections/);
  assert.match(shellContent, /loadHypervisorSessionOperationsProjection/);
  assert.match(shellContent, /\[Hypervisor\]\[Sessions\] operations projection unavailable/);
  assert.match(shellContent, /data-hypervisor-session-operations/);
  assert.match(shellContent, /data-session-operations-source/);
  assert.match(shellContent, /data-runtime-truth-source/);
  assert.match(shellContent, /HYPERVISOR_SESSION_WORKSPACE_MODES/);
  assert.match(shellContent, /HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES/);
  assert.match(shellContent, /data-session-reference-detail="code-conversation"/);
  assert.match(shellContent, /aria-label="Session workspace modes"/);
  assert.match(shellContent, /data-session-workspace-mode-list/);
  assert.match(shellContent, /\.filter\(\s*\(mode\) => mode\.mode_id === "code"/);
  assert.match(shellContent, /data-session-workspace-mode=\{mode\.mode_id\}/);
  assert.match(shellContent, /aria-label="Changes, files, comments, and session inspectors"/);
  assert.match(shellContent, /data-session-change-inspector="changes-files-comments"/);
  assert.match(shellContent, /data-session-change-mode-list/);
  assert.match(shellContent, /className="hypervisor-session-operations__change-filter-row"/);
  assert.match(shellContent, /className="hypervisor-session-operations__status-filter"/);
  assert.match(shellContent, /data-session-changed-file/);
  assert.match(shellContent, /data-session-detail-tab-list/);
  assert.match(shellContent, /\.filter\(\(tab\) => tab\.tab_id === "environment"\)/);
  assert.match(shellContent, /data-session-detail-tab/);
  assert.match(shellContent, /data-session-port-services-count/);
  assert.match(shellContent, /data-session-activity-signal-list/);
  assert.match(shellContent, /data-session-activity-signal/);
  assert.match(shellContent, /data-session-lease=/);
  assert.match(shellContent, /data-session-archive-ref/);
  assert.match(shellContent, /data-session-restore-ref/);
  assert.match(shellContent, /formatSessionSignalKind/);
  assert.match(shellContent, /formatSessionLeaseStatus/);
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
  assert.match(shellContent, /\[Hypervisor\]\[Sessions\] operation proposal unavailable/);
  assert.doesNotMatch(shellContent, /operationProposal\.custody_invariant/);
  assert.match(shellContent, /activeView === "sessions"/);
});

test("Projects surface renders the reference Projects page over hidden project truth", () => {
  assert.match(projectStateModel, /HypervisorProjectStateProjection/);
  assert.match(projectStateModel, /HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE/);
  assert.match(projectStateModel, /HYPERVISOR_PROJECT_STATE_PROJECTION_PATH/);
  assert.match(projectStateModel, /loadHypervisorProjectStateProjection/);
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
  assert.match(shellContent, /\[Hypervisor\]\[Projects\] state projection unavailable/);
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
  assert.match(shellContent, /<h2>Projects<\/h2>/);
  assert.match(shellContent, /placeholder="Search projects"/);
  assert.match(shellContent, /No projects/);
  assert.match(shellContent, /Projects bundle your repo/);
  assert.match(shellContent, /New project/);
  assert.doesNotMatch(shellContent, /Code repositories/);
  assert.doesNotMatch(shellContent, /No pull requests created by you/);
  assert.doesNotMatch(shellContent, /className="hypervisor-project-state__repositories"/);
  assert.doesNotMatch(shellContent, /"hypervisor-project-state__repo"/);
  assert.doesNotMatch(shellContent, /data-project-select-action/);
  assert.doesNotMatch(shellContent, /data-project-open-provider/);
  assert.doesNotMatch(shellContent, /data-project-open-restore/);
  assert.doesNotMatch(shellContent, /hypervisor-project-state__card/);
  assert.doesNotMatch(shellContent, /hypervisor-project-state__refs/);
  assert.match(shellContent, /activeView === "projects"/);
  assert.match(shellContent, /activeView !== "projects"/);
  assert.doesNotMatch(shellContent, /projects: \{\s*eyebrow: "Project state"/);
  assert.doesNotMatch(shellContent, /projection\.project_boundary_invariant/);
});

test("Automations surface renders workflow compositor projection before editor", () => {
  assert.match(automationCompositorModel, /HypervisorAutomationCompositorProjection/);
  assert.match(automationCompositorModel, /HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE/);
  assert.match(automationCompositorModel, /HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH/);
  assert.match(automationCompositorModel, /loadHypervisorAutomationCompositorProjection/);
  assert.match(automationCompositorModel, /normalizeHypervisorAutomationCompositorProjection/);
  assert.match(automationCompositorModel, /workflow_template_refs/);
  assert.match(automationCompositorModel, /run_recipe_refs/);
  assert.match(automationCompositorModel, /graph_refs/);
  assert.match(automationCompositorModel, /action_proposal_ref/);
  assert.match(automationCompositorModel, /agentgres_operation_refs/);
  assert.match(automationCompositorModel, /state_root_ref/);
  assert.match(automationCompositorModel, /Workflow Compositor edits and proposes/);
  assert.match(automationCompositorModel, /Hypervisor Core admits execution/);
  assert.match(automationCompositorModel, /Agentgres records operational truth/);
  assert.match(shellContent, /HypervisorAutomationCompositorSurface/);
  assert.match(shellContent, /loadHypervisorAutomationCompositorProjection/);
  assert.match(shellContent, /\[Hypervisor\]\[Automations\] compositor projection unavailable/);
  assert.match(shellContent, /data-hypervisor-automation-compositor/);
  assert.match(shellContent, /data-automation-compositor-source/);
  assert.match(shellContent, /No automations yet/);
  assert.match(shellContent, /data-workflow-template-suggestion/);
  assert.match(shellContent, /className="hypervisor-automation-compositor__empty"/);
  assert.doesNotMatch(shellContent, /data-workflow-template-ref/);
  assert.doesNotMatch(shellContent, /data-workflow-run-ref/);
  assert.match(shellContent, /data-workflow-compositor-editor-boundary/);
  assert.match(shellContent, /activeView === "automations"/);
});

test("Agents surface renders workers as a cockpit list without internal doctrine copy", () => {
  const agentsSurface = sourceSlice(
    shellContent,
    "function HypervisorAgentsSurface",
    "function HypervisorAutomationCompositorSurface",
  );
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
  assert.match(shellContent, />Sort: Recently updated</);
  assert.match(shellContent, /className="hypervisor-agents__detail-label"/);
  assert.match(shellContent, />Selected agent</);
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
  assert.doesNotMatch(shellContent, /Runtime actors/);
  assert.doesNotMatch(shellContent, /Configured workers/);
  assert.doesNotMatch(shellContent, /Configure workers/);
  assert.doesNotMatch(shellContent, />Leases</);
  assert.doesNotMatch(shellContent, /Manage authority/);
  assert.doesNotMatch(shellContent, /Review leases/);
  assert.doesNotMatch(shellContent, /Daemon Owned/);
  assert.doesNotMatch(shellContent, /Proposal Source Only/);
  assert.doesNotMatch(shellContent, /AgentHarnessAdapter proposal source/);
  assert.doesNotMatch(shellContent, /Reference HarnessProfile scaffold/);
  assert.doesNotMatch(shellContent, /Hypervisor Daemon remains runtime truth/);
  assert.doesNotMatch(agentsSurface, /data-runtime-truth-source/);
  assert.doesNotMatch(shellContent, /formatAgentRuntimeBoundary/);
  assert.doesNotMatch(shellContent, /AgentMetric/);
  assert.doesNotMatch(shellContent, /hypervisor-agents__metrics/);
  assert.doesNotMatch(agentsSurface, />Harness</);
  assert.doesNotMatch(agentsSurface, />Model route</);
  assert.doesNotMatch(agentsSurface, />Execution</);
  assert.doesNotMatch(agentsSurface, />Capability leases</);
  assert.doesNotMatch(shellContent, /<dt>Mode<\/dt>/);
  assert.doesNotMatch(shellContent, /<dd>\{agent\.state_root_ref\}<\/dd>/);
  assert.doesNotMatch(shellContent, /<dd>\{agent\.latest_receipt_refs\[0\]\}<\/dd>/);
  assert.match(shellContent, /data-agent-state-root-ref=\{agent\.state_root_ref\}/);
  assert.match(shellContent, /data-agent-latest-receipt-ref=\{agent\.latest_receipt_refs\[0\] \?\? ""\}/);
  assert.doesNotMatch(shellContent, /className="hypervisor-agents__grid"/);
  assert.doesNotMatch(shellContent, /className="hypervisor-agents__invariants"/);
  assert.doesNotMatch(shellContent, /className="hypervisor-agents__status"/);
  assert.match(shellContent, /activeView === "agents"/);
  assert.match(shellContent, /activeView !== "agents"/);
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
    /activeView === "insights"[\s\S]*<HypervisorInsightsReferenceSurface>[\s\S]*<MissionControlRunsView runtime=\{runtime\} \/>[\s\S]*<\/HypervisorInsightsReferenceSurface>/,
  );
  assert.doesNotMatch(
    shellContent,
    /activeView === "insights" \? \(\s*<MissionControlRunsView runtime=\{runtime\} \/>/,
  );
});

test("Models surface renders model infrastructure projection before mount UI", () => {
  assert.match(modelInfrastructureModel, /HypervisorModelInfrastructureProjection/);
  assert.match(modelInfrastructureModel, /HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE/);
  assert.match(modelInfrastructureModel, /HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH/);
  assert.match(modelInfrastructureModel, /buildHypervisorModelInfrastructureProjectionFromInventory/);
  assert.match(modelInfrastructureModel, /loadHypervisorModelInfrastructureProjection/);
  assert.match(modelInfrastructureModel, /normalizeHypervisorModelInfrastructureProjection/);
  assert.match(modelInfrastructureModel, /model_route_refs/);
  assert.match(modelInfrastructureModel, /endpoint_refs/);
  assert.match(modelInfrastructureModel, /loaded_instance_refs/);
  assert.match(modelInfrastructureModel, /session_bindings/);
  assert.match(modelInfrastructureModel, /model_weight_custody_policy_refs/);
  assert.match(modelInfrastructureModel, /authority_scope_refs/);
  assert.match(modelInfrastructureModel, /Models is an infrastructure projection/);
  assert.match(modelInfrastructureModel, /Hypervisor Core admits execution/);
  assert.match(modelInfrastructureModel, /Agentgres records model-route truth/);
  assert.match(shellContent, /HypervisorModelInfrastructureSurface/);
  assert.match(shellContent, /loadHypervisorModelInfrastructureProjection/);
  assert.match(shellContent, /\[Hypervisor\]\[Models\] infrastructure projection unavailable/);
  assert.match(shellContent, /data-hypervisor-model-infrastructure/);
  assert.match(shellContent, /data-model-infrastructure-source/);
  assert.match(shellContent, /data-model-route-ref/);
  assert.match(shellContent, /data-model-route-detail/);
  assert.match(shellContent, /data-model-provider-ref/);
  assert.match(shellContent, /data-model-session-binding/);
  assert.match(shellContent, /data-model-mounting-ui-boundary/);
  assert.match(shellContent, /className="hypervisor-model-infrastructure__workplane"/);
  assert.match(shellContent, /className="hypervisor-model-infrastructure__list"/);
  assert.match(shellContent, /className="hypervisor-model-infrastructure__detail"/);
  assert.doesNotMatch(shellContent, /className="hypervisor-model-infrastructure__summary"/);
  assert.doesNotMatch(shellContent, /className="hypervisor-model-infrastructure__grid"/);
  assert.doesNotMatch(shellContent, /className="hypervisor-model-infrastructure__card"/);
  assert.doesNotMatch(shellContent, /\{projection\.infrastructure_boundary_invariant\}/);
  assert.match(shellContent, /activeView === "models"/);
});

test("Providers and Environments surfaces are direct integrations, not Fleet placeholders", () => {
  assert.match(providerPlacementModel, /HypervisorProviderPlacementProjection/);
  assert.match(providerPlacementModel, /HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE/);
  assert.match(providerPlacementModel, /HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH/);
  assert.match(providerPlacementModel, /HYPERVISOR_PROVIDER_OPERATION_PROPOSAL_PATH/);
  assert.match(providerPlacementModel, /HypervisorProviderOperationProposal/);
  assert.match(providerPlacementModel, /loadHypervisorProviderPlacementProjection/);
  assert.match(providerPlacementModel, /normalizeHypervisorProviderPlacementProjection/);
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
  assert.match(shellContent, /\[Hypervisor\]\[Providers\] operation proposal unavailable/);
  assert.match(shellContent, /\[Hypervisor\]\[Providers\] placement projection unavailable/);
  assert.match(shellContent, /HypervisorEnvironmentEstateSurface/);
  assert.match(shellContent, /EnvironmentEstateView runtime=\{runtime\}/);
  assert.match(shellContent, /data-hypervisor-provider-placement/);
  assert.match(shellContent, /data-provider-placement-source/);
  assert.match(shellContent, /data-provider-placement-candidate/);
  assert.match(shellContent, /data-hypervisor-environment-estate/);
  assert.doesNotMatch(shellContent, /projection\.anti_gateway_invariant/);
  assert.doesNotMatch(
    shellContent,
    /This view reads the live environment estate through Hypervisor Core/,
  );
  assert.match(shellContent, /activeView === "providers"/);
  assert.match(shellContent, /activeView === "environments"/);
  assert.match(shellContent, /activeView !== "providers"/);
  assert.match(shellContent, /activeView !== "environments"/);
});

test("Receipts surface renders Agentgres-bound evidence instead of a placeholder", () => {
  assert.match(receiptEvidenceModel, /HypervisorReceiptEvidenceProjection/);
  assert.match(receiptEvidenceModel, /HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE/);
  assert.match(receiptEvidenceModel, /HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH/);
  assert.match(receiptEvidenceModel, /loadHypervisorReceiptEvidenceProjection/);
  assert.match(receiptEvidenceModel, /daemon-receipt-evidence-projection/);
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
  assert.match(shellContent, /\[Hypervisor\]\[Receipts\] evidence projection unavailable/);
  assert.doesNotMatch(shellContent, /projection\.receipt_boundary_invariant/);
  assert.match(shellContent, /activeView === "receipts"/);
  assert.match(shellContent, /activeView !== "receipts"/);
});

test("Privacy surface renders cTEE and model-weight custody admission posture", () => {
  assert.match(privacyPostureModel, /HypervisorPrivacyPostureProjection/);
  assert.match(privacyPostureModel, /HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE/);
  assert.match(privacyPostureModel, /Model-weight custody is a separate admission lane/);
  assert.match(privacyPostureModel, /WorkspaceCustodySegment/);
  assert.match(privacyPostureModel, /ModelWeightCustodyPolicy/);
  assert.match(privacyPostureModel, /node_plaintext_allowed/);
  assert.match(privacyPostureModel, /forbidden_plaintext_mount/);
  assert.match(privacyPostureModel, /remote_api_capability/);
  assert.match(privacyPostureModel, /tee_or_customer_cloud_mount/);
  assert.match(privacyPostureModel, /ctee_split/);
  assert.match(privacyPostureModel, /encrypted_storage_only/);
  assert.match(privacyPostureModel, /wallet_network/);
  assert.match(privacyPostureModel, /hypervisor_daemon/);
  assert.match(privacyPostureModel, /agentgres/);
  assert.match(shellContent, /HypervisorPrivacyPostureSurface/);
  assert.match(shellContent, /data-hypervisor-privacy-posture/);
  assert.match(shellContent, /data-privacy-workspace-segment/);
  assert.match(shellContent, /data-model-weight-custody-lane/);
  assert.match(shellContent, /data-provider-privacy-candidate/);
  assert.match(shellContent, /data-privacy-admission-control/);
  assert.doesNotMatch(shellContent, /projection\.invariant/);
  assert.match(shellContent, /activeView === "privacy"/);
  assert.match(shellContent, /activeView !== "privacy"/);
  assert.doesNotMatch(shellContent, /privacy: \{\s*eyebrow: "Private workspace"/);
});

console.log("hypervisorShellNavigationModel.test.mjs: ok");
