import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("./hypervisorShellNavigationModel.ts", import.meta.url),
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
const receiptEvidenceModel = readFileSync(
  new URL("./hypervisorReceiptEvidenceModel.ts", import.meta.url),
  "utf8",
);

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
  assert.match(source, /HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES/);
  assert.match(source, /WorkbenchAdapterPreference/);
  assert.match(source, /DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF/);
  assert.match(source, /workbench_adapter/);
  assert.match(source, /Embedded Workbench[\s\S]*External Editor[\s\S]*Browser Workspace/);
  assert.match(activityBar, /HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS/);
  assert.match(
    activityBar,
    /HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS\.leftNavSurfaceIds\.slice\(0, 9\)/,
  );
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
    /Default Harness Profile or daemon-mediated AgentHarnessAdapter/,
  );
  assert.match(source, /harnessOptions: HYPERVISOR_HARNESS_SELECTION_OPTIONS/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL/);
  assert.match(source, /HYPERVISOR_SESSION_DETAIL_TABS/);
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
    /Search Hypervisor, sessions, workbench, automations, and commands/,
  );
  assert.match(activityBar, /aria-label="Hypervisor navigation"/);
  assert.match(activityBar, /chat-activity-button--new-session/);
  assert.match(activityBar, /HYPERVISOR_PRIMARY_ACTION/);
  assert.match(activityBar, /aria-label="Applications"/);
  assert.match(activityBar, /aria-label="Governance and infrastructure"/);
  assert.match(activityBar, /data-route-state=\{item\.routeState\}/);
  assert.match(header, /`Hypervisor .*?\$\{windowSurfaceTitle/s);
  assert.doesNotMatch(header, /Autopilot Chat/);
});

test("new session modal is a shell-level governed launch flow", () => {
  assert.match(newSessionModal, /HYPERVISOR_SESSION_LAUNCH_RECIPES/);
  assert.match(newSessionModal, /HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES/);
  assert.match(newSessionModal, /Workbench Adapter/);
  assert.match(newSessionModal, /adapter_preference_ref: adapterPreferenceRef/);
  assert.match(newSessionModal, /buildHarnessCompatibilityVerdict/);
  assert.match(newSessionModal, /buildHypervisorNewSessionLaunchSummary/);
  assert.match(newSessionModal, /launch_summary: launchSummary/);
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
  assert.match(newSessionModal, /Launch governed session/);
  assert.match(controller, /newSessionModalOpen/);
  assert.match(controller, /launchNewSession/);
  assert.match(controller, /const summary = request\.launch_summary/);
  assert.match(controller, /summary\.harness_label/);
  assert.match(controller, /summary\.model_route_availability_state/);
  assert.match(controller, /summary\.workbench_adapter_ref/);
  assert.match(controller, /setCurrentProjectId\(project\.id\)/);
  assert.match(controller, /setActiveView\(recipe\.surface_id\)/);
  assert.match(shellWindow, /loadHypervisorModelMountInventorySnapshot/);
  assert.match(shellWindow, /setModelMountInventory/);
  assert.match(shellWindow, /<HypervisorNewSessionModal/);
  assert.match(shellWindow, /modelMountInventory=\{modelMountInventory\}/);
  assert.match(shellWindow, /onLaunch=\{controller\.modals\.launchNewSession\}/);
});

test("Foundry exposes harness comparison as a daemon-runtime dashboard", () => {
  assert.match(shellContent, /HypervisorHarnessComparisonDashboard/);
  assert.match(shellContent, /HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE/);
  assert.match(shellContent, /data-hypervisor-harness-comparison-run/);
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
  assert.match(shellContent, /HypervisorSessionOperationsCockpit/);
  assert.match(shellContent, /loadHypervisorSessionOperationsProjection/);
  assert.match(shellContent, /\[Hypervisor\]\[Sessions\] operations projection unavailable/);
  assert.match(shellContent, /data-hypervisor-session-operations/);
  assert.match(shellContent, /data-session-operations-source/);
  assert.match(shellContent, /data-runtime-truth-source/);
  assert.match(shellContent, /data-session-detail-tab/);
  assert.match(shellContent, /data-right-inspector-panel/);
  assert.match(shellContent, /data-session-port-service/);
  assert.match(shellContent, /data-session-task/);
  assert.match(shellContent, /data-session-terminal-event/);
  assert.match(shellContent, /activeView === "sessions"/);
});

test("Projects surface renders workspace, restore, artifact, and state-root projection", () => {
  assert.match(projectStateModel, /HypervisorProjectStateProjection/);
  assert.match(projectStateModel, /HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE/);
  assert.match(projectStateModel, /agentgres_object_head_ref/);
  assert.match(projectStateModel, /state_root_ref/);
  assert.match(projectStateModel, /artifact_refs/);
  assert.match(projectStateModel, /archive_ref/);
  assert.match(projectStateModel, /restore_ref/);
  assert.match(projectStateModel, /Agentgres admits project truth/);
  assert.match(projectStateModel, /storage backends only hold bytes/);
  assert.match(shellContent, /HypervisorProjectStateSurface/);
  assert.match(shellContent, /data-hypervisor-project-state/);
  assert.match(shellContent, /data-project-state-record/);
  assert.match(shellContent, /data-project-restore-state/);
  assert.match(shellContent, /data-project-custody-posture/);
  assert.match(shellContent, /activeView === "projects"/);
  assert.match(shellContent, /activeView !== "projects"/);
  assert.doesNotMatch(shellContent, /projects: \{\s*eyebrow: "Project state"/);
});

test("Providers and Environments surfaces are direct integrations, not Fleet placeholders", () => {
  assert.match(providerPlacementModel, /HypervisorProviderPlacementProjection/);
  assert.match(providerPlacementModel, /HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE/);
  assert.match(providerPlacementModel, /anti_gateway_invariant/);
  assert.match(providerPlacementModel, /wallet\.network authorizes/);
  assert.match(providerPlacementModel, /Agentgres records admitted truth/);
  assert.match(providerPlacementModel, /provider-candidate:akash-gpu/);
  assert.match(providerPlacementModel, /provider-candidate:filecoin-archive/);
  assert.match(providerPlacementModel, /ctee_split_required/);
  assert.match(providerPlacementModel, /encrypted_storage_only/);
  assert.doesNotMatch(providerPlacementModel, /decentralized\.cloud/);
  assert.match(shellContent, /HypervisorProviderPlacementDashboard/);
  assert.match(shellContent, /HypervisorEnvironmentEstateSurface/);
  assert.match(shellContent, /EnvironmentEstateView runtime=\{runtime\}/);
  assert.match(shellContent, /data-hypervisor-provider-placement/);
  assert.match(shellContent, /data-provider-placement-candidate/);
  assert.match(shellContent, /data-hypervisor-environment-estate/);
  assert.match(shellContent, /activeView === "providers"/);
  assert.match(shellContent, /activeView === "environments"/);
  assert.match(shellContent, /activeView !== "providers"/);
  assert.match(shellContent, /activeView !== "environments"/);
});

test("Receipts surface renders Agentgres-bound evidence instead of a placeholder", () => {
  assert.match(receiptEvidenceModel, /HypervisorReceiptEvidenceProjection/);
  assert.match(receiptEvidenceModel, /HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE/);
  assert.match(receiptEvidenceModel, /receipt_boundary_invariant/);
  assert.match(receiptEvidenceModel, /Agentgres admits operational truth/);
  assert.match(receiptEvidenceModel, /artifact_refs/);
  assert.match(receiptEvidenceModel, /trace_refs/);
  assert.match(receiptEvidenceModel, /state_root_ref/);
  assert.match(receiptEvidenceModel, /replay_ref/);
  assert.match(receiptEvidenceModel, /harness_comparison/);
  assert.match(receiptEvidenceModel, /artifact_restore/);
  assert.match(shellContent, /HypervisorReceiptEvidenceSurface/);
  assert.match(shellContent, /data-hypervisor-receipt-evidence/);
  assert.match(shellContent, /data-receipt-evidence-record/);
  assert.match(shellContent, /data-receipt-evidence-kind/);
  assert.match(shellContent, /data-receipt-evidence-status/);
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
  assert.match(shellContent, /activeView === "privacy"/);
  assert.match(shellContent, /activeView !== "privacy"/);
  assert.doesNotMatch(shellContent, /privacy: \{\s*eyebrow: "Private workspace"/);
});

console.log("hypervisorShellNavigationModel.test.mjs: ok");
