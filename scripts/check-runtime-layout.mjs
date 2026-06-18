#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const report = [];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function exists(relativePath) {
  return fs.existsSync(path.join(root, relativePath));
}

function allFiles(dir, predicate = () => true) {
  const absolute = path.join(root, dir);
  if (!fs.existsSync(absolute)) return [];
  return fs.readdirSync(absolute, { withFileTypes: true }).flatMap((entry) => {
    const relative = path.join(dir, entry.name);
    if (entry.isDirectory()) return allFiles(relative, predicate);
    return predicate(relative) ? [relative] : [];
  });
}

function assert(id, condition, evidence, message) {
  report.push({ id, status: condition ? "passed" : "failed", evidence, message });
  if (!condition) failures.push(`${id}: ${message}`);
}

const packageJson = JSON.parse(read("package.json"));
const readme = read("README.md");
const developersDocs = read("apps/developers-ioi-ai/src/content/docs.tsx");
const refineArchitectureGuide = read("internal-docs/implementation/refine-architecture.md");
const runtimePackageBoundaries = read("internal-docs/implementation/runtime-package-boundaries.md");
const runtimeModuleMap = read("internal-docs/implementation/runtime-module-map.md");
const hypervisorCoreClientsSurfacesDoc = read(
  "docs/architecture/components/hypervisor/core-clients-surfaces.md",
);
const retiredHypervisorFleetDoc = "docs/architecture/components/hypervisor/fleet.md";
const retiredAutopilotWorkflowCanvasFixtures = [
  "test.workflow",
  "scripts/lib/prompt-parser.ts",
  "scripts/custom-hypervisor-agenda.mjs",
];
const hypervisorProvidersEnvironmentsDoc = read(
  "docs/architecture/components/hypervisor/providers-and-environments.md",
);
const daemonRuntimeApiDoc = read("docs/architecture/components/daemon-runtime/api.md");
const architectureSourceOfTruthMap = read("docs/architecture/_meta/source-of-truth-map.md");
const architectureImplementationMatrix = read("docs/architecture/_meta/implementation-matrix.md");
const architectureVocabulary = read("docs/architecture/_meta/vocabulary.md");
const workbenchAdapterLauncher = read("scripts/launch-hypervisor-workbench-adapter-host.mjs");
const workbenchAdapterHostPaths = read("scripts/lib/hypervisor-workbench-adapter-host-paths.mjs");
const workbenchAdaptersReadme = read("workbench-adapters/README.md");
const workbenchShellManifest = read("workbench-adapters/shell.manifest.json");
const workbenchShellPatch = read("scripts/lib/hypervisor-workbench-shell-patch.mjs");
const rootGitignore = read(".gitignore");
const hypervisorInstallProductMetadataSource = read(
  "crates/services/src/agentic/runtime/resolver/software_install/product_metadata.rs",
);
const hypervisorRustProductFixtureSources = [
  "crates/services/src/agentic/runtime/service/decision_loop/cognition/final_reply_product_handoff.rs",
  "crates/services/src/agentic/runtime/service/decision_loop/cognition/tests_parts/root/final_reply_evidence.rs",
  "crates/services/src/agentic/runtime/execution/screen/semantics/tests.rs",
  "crates/services/src/agentic/runtime/execution/screen/tests.rs",
].map(read).join("\n");
const hypervisorShellNavigationSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts",
);
const workbenchAdapterPreferencesSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/workbenchAdapterPreferences.ts",
);
const workspaceEditorAdapterBridgeSource = read(
  "apps/hypervisor/src/services/workspaceEditorAdapterBridge.ts",
);
const hypervisorHarnessAdapterModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.ts",
);
const hypervisorModelMountInventoryModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/modelMountInventoryModel.ts",
);
const hypervisorAutomationCompositorModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAutomationCompositorModel.ts",
);
const hypervisorAgentsModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAgentsModel.ts",
);
const hypervisorModelInfrastructureModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorModelInfrastructureModel.ts",
);
const hypervisorReceiptEvidenceModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorReceiptEvidenceModel.ts",
);
const hypervisorShellWindowSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/index.tsx",
);
const hypervisorShellContentSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
);
const hypervisorShellBaseCssSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/shell-base.css",
);
const hypervisorNewSessionModalSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx",
);
const hypervisorShellControllerSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/useHypervisorShellController.ts",
);
const runtimeHarnessContainerLaneSource = read(
  "packages/runtime-daemon/src/runtime-harness-container-lane.mjs",
);
const runtimeWorkbenchAdapterLaunchPlanAdmissionSource = read(
  "packages/runtime-daemon/src/runtime-workbench-adapter-launch-plan-admission.mjs",
);
const runtimeHarnessContainerLaneTestSource = read(
  "packages/runtime-daemon/src/runtime-harness-container-lane.test.mjs",
);
const runtimeHarnessContainerExecutorSource = read(
  "packages/runtime-daemon/src/runtime-harness-container-executor.mjs",
);
const runtimeHarnessContainerExecutorTestSource = read(
  "packages/runtime-daemon/src/runtime-harness-container-executor.test.mjs",
);
const runtimeHarnessPublicFixtureRunSource = read(
  "packages/runtime-daemon/src/runtime-harness-public-fixture-run.mjs",
);
const runtimeHarnessPublicFixtureRunTestSource = read(
  "packages/runtime-daemon/src/runtime-harness-public-fixture-run.test.mjs",
);
const hypervisorAppShellContractSource = read(
  "scripts/hypervisor-app-shell-contract.mjs",
);
const publicRuntimeRoutesSource = read(
  "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
);
const publicRuntimeRoutesTestSource = read(
  "packages/runtime-daemon/src/http/public-runtime-routes.test.mjs",
);
const runtimeModelWeightCustodyAdmissionSource = read(
  "packages/runtime-daemon/src/runtime-model-weight-custody-admission.mjs",
);
const runtimeModelWeightCustodyAdmissionTestSource = read(
  "packages/runtime-daemon/src/runtime-model-weight-custody-admission.test.mjs",
);
const runtimeManagedWorkerLifecycleAdmissionSource = read(
  "packages/runtime-daemon/src/runtime-managed-worker-instance-lifecycle-admission.mjs",
);
const runtimeManagedWorkerLifecycleAdmissionTestSource = read(
  "packages/runtime-daemon/src/runtime-managed-worker-instance-lifecycle-admission.test.mjs",
);
const runtimePhysicalActionIntentAdmissionSource = read(
  "packages/runtime-daemon/src/runtime-physical-action-intent-admission.mjs",
);
const runtimePhysicalActionIntentAdmissionTestSource = read(
  "packages/runtime-daemon/src/runtime-physical-action-intent-admission.test.mjs",
);
const runtimeWorkerPackageInstallAdmissionSource = read(
  "packages/runtime-daemon/src/runtime-worker-package-install-admission.mjs",
);
const runtimeWorkerPackageInstallAdmissionTestSource = read(
  "packages/runtime-daemon/src/runtime-worker-package-install-admission.test.mjs",
);
const hypervisorActivityBarSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLocalActivityBar.tsx",
);
const hypervisorHomeSource = [
  "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
  "apps/hypervisor/src/surfaces/Home/HomeWalkthroughDocument.tsx",
  "apps/hypervisor/src/surfaces/Home/homeOnboardingModel.ts",
  "apps/hypervisor/scripts/home_onboarding_condition_matrix.ts",
  "apps/hypervisor/src/surfaces/Home/index.ts",
].map(read).join("\n");
const hypervisorHomeCockpitModelSource = read(
  "apps/hypervisor/src/surfaces/Home/homeCockpitModel.ts",
);
const hypervisorSessionOperationsModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts",
);
const hypervisorProjectStateModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorProjectStateModel.ts",
);
const hypervisorProviderPlacementModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorProviderPlacementModel.ts",
);
const workspaceRepositoryGateSource = read(
  "apps/hypervisor/src/surfaces/Workspace/WorkspaceRepositoryGate.tsx",
);
const authorityCenterTestSource = read(
  "apps/hypervisor/src/surfaces/Policy/authorityCenter.test.ts",
);
const activeHypervisorFixtureSources = [
  "apps/hypervisor/src/windows/ChatShellWindow/components/artifactHubPrCommentsModel.test.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/utils/assistantTurnProcessModel.test.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/utils/turnWindows.test.ts",
  "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.test.ts",
].map(read).join("\n");
const workspaceWorkbenchCopySources = [
  "apps/hypervisor/src/surfaces/Workspace/WorkspaceShell.tsx",
  "apps/hypervisor/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx",
  "apps/hypervisor/src/services/directWorkspaceWorkbenchHost.ts",
  "apps/hypervisor/src/services/openVsCodeWorkbenchHost.ts",
  "apps/hypervisor/src/services/openVsCodeWorkbenchSession.ts",
  "apps/hypervisor/src/services/workspaceRuntimeNavigation.ts",
  "apps/hypervisor/src/services/workflowCodeGenerationProposal.ts",
  "apps/hypervisor/src/services/hypervisorAppearance.ts",
].map(read).join("\n");
const agentModelMatrixScopeSources = [
  "scripts/run-agent-model-matrix.mjs",
  "scripts/lib/agent-model-matrix.mjs",
  "scripts/run-agent-model-matrix.test.mjs",
  "scripts/lib/agent-model-matrix.test.mjs",
  "apps/benchmarks/src/App.tsx",
  "apps/benchmarks/src/scorecardPreview.ts",
].map(read).join("\n");
const hypervisorVisibleSurfaceSources = [
  "apps/hypervisor/src/windows/ChatShellWindow/index.tsx",
  "apps/hypervisor/src/windows/ChatShellWindow/components/ArtifactHubTaskViews.tsx",
  "apps/hypervisor/src/windows/ChatShellWindow/components/views/ThoughtsView.tsx",
  "apps/hypervisor/src/surfaces/MissionControl/WelcomeView.tsx",
  "apps/hypervisor/src/surfaces/MissionControl/MissionControlMountsView.tsx",
  "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
  "packages/workspace-substrate/src/notebook.ts",
  "packages/hypervisor-workbench/src/features/Connectors/components/googleWorkspaceConnectorPanelConfig.ts",
  "packages/hypervisor-workbench/src/features/Connectors/components/GoogleWorkspaceConnectorPanelConnected.tsx",
  "packages/hypervisor-workbench/src/features/Connectors/components/GoogleWorkspaceConnectorPanel.tsx",
  "packages/hypervisor-workbench/src/features/Connectors/components/GoogleWorkspaceConnectorPanelBody.tsx",
  "packages/hypervisor-workbench/src/features/Connectors/components/GoogleWorkspaceConnectorPanelOnboarding.tsx",
  "packages/hypervisor-workbench/src/features/Connectors/components/GenericConnectorPanel.tsx",
  "packages/hypervisor-workbench/src/features/Connectors/components/MailConnectorPanel.tsx",
  "packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts",
].map(read).join("\n");
const hypervisorClientNamespaceSources = [
  "apps/hypervisor/index.html",
  "apps/hypervisor/src/services/workspaceShellState.ts",
  "apps/hypervisor/src/services/workspaceRuntimeNavigation.ts",
  "apps/hypervisor/src/services/chatLaunchState.ts",
  "apps/hypervisor/src/services/chatShellLaunchState.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/hooks/useChatVimMode.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts",
  "apps/hypervisor/src/windows/HypervisorShellWindow/HypervisorShellWindow.css",
  "packages/workspace-substrate/src/codeOss.ts",
  "packages/workspace-substrate/src/notebook.ts",
  "packages/workspace-substrate/src/types.ts",
  "packages/workspace-substrate/src/components/CodeOssEditor.tsx",
  "packages/workspace-substrate/src/components/WorkspaceEditorPane.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/components/model.ts",
  "packages/hypervisor-workbench/src/runtime/workflow-scratch-blueprints.ts",
].map(read).join("\n");
const hypervisorIndexHtmlSource = read("apps/hypervisor/index.html");
const hypervisorClientRuntimeSource = read(
  "apps/hypervisor/src/services/HypervisorClientRuntime.ts",
);
const companionShellNavigationSource = read(
  "apps/hypervisor/src/services/companionShellNavigation.ts",
);
const chatSessionHookSource = read(
  "apps/hypervisor/src/windows/ChatShellWindow/hooks/useChatSession.ts",
);
const hypervisorTypeWrapperSources = [
  "apps/hypervisor/src/types/generated.ts",
  "apps/hypervisor/src/types/events.ts",
  "apps/hypervisor/src/types/artifacts.ts",
  "apps/hypervisor/src/types/notifications.ts",
  "apps/hypervisor/src/types/atlas.ts",
].map(read).join("\n");
const hypervisorModelMountIdentitySources = [
  "packages/runtime-daemon/src/model-mounting/default-records.mjs",
  "packages/runtime-daemon/src/model-mounting/default-discovery.mjs",
  "packages/runtime-daemon/src/model-mounting.mjs",
  "apps/hypervisor/src/surfaces/MissionControl/MissionControlMountsView.tsx",
  "scripts/lib/model-mounting-daemon-contract.test.mjs",
  "scripts/validate-model-mounting-e2e.mjs",
  "scripts/launch-hypervisor-workbench-adapter-host.mjs",
  "scripts/live-model-mounting-gate.mjs",
  "apps/hypervisor/scripts/desktop_model_mounts_probe.py",
  "packages/runtime-daemon/src/runtime-daemon-core-direct-invoker-service.test.mjs",
  "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
  "packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs",
  "packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs",
  "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
  "packages/runtime-daemon/src/model-mounting/model-mount-core.test.mjs",
  "packages/runtime-daemon/src/model-mounting/read-projection-direct.test.mjs",
].map(read).join("\n") +
  "\n" +
  allFiles(
    "crates/services/src/agentic/runtime/kernel/model_mount",
    (relativePath) => relativePath.endsWith(".rs"),
  ).map(read).join("\n");
const packageScriptNames = Object.keys(packageJson.scripts ?? {});
const retiredAutopilotPackageScripts = packageScriptNames.filter((scriptName) =>
  /^(?:goal|validate|test):autopilot/.test(scriptName),
);
const retiredDesktopLaunchScripts = packageScriptNames.filter((scriptName) =>
  /^(?:dev|probe|dryrun):desktop(?::|$)/.test(scriptName),
);
const retiredHypervisorGoalScripts = packageScriptNames.filter((scriptName) =>
  scriptName.startsWith("goal:hypervisor-"),
);
const retiredHypervisorHarnessValidationScripts = packageScriptNames.filter((scriptName) =>
  scriptName.startsWith("validate:hypervisor-app-harness"),
);
const hypervisorAppHarnessContractSource = read("scripts/lib/hypervisor-app-harness-contract.mjs");
const daemonSource = read("packages/runtime-daemon/src/index.mjs");
const sdkSubstrate = read("packages/agent-sdk/src/substrate-client.ts");
const sdkIndex = read("packages/agent-sdk/src/index.ts");
const workbenchRuntimeFiles = allFiles("packages/hypervisor-workbench/src/runtime", (file) =>
  /\.(ts|tsx)$/.test(file),
);
const activeTauriSrc = "apps/hypervisor/src-tauri/src";
const activeTauriRuntimeService = "apps/hypervisor/src/services/TauriRuntime.ts";
const activeTauriDesktopLauncher = "apps/hypervisor/scripts/dev-desktop.sh";
const legacyTauriArchive = "internal-docs/legacy/autopilot-tauri-src";
const rootIdeDir = "ide";
const retiredAgentIdePath = "packages/agent-ide";
const retiredAutopilotShellWindow = "apps/hypervisor/src/windows/AutopilotShellWindow";
const builtinFiles = allFiles("crates/services/src/agentic/runtime/tools/builtins", (file) =>
  file.endsWith(".rs"),
);
const runtimeServiceFiles = allFiles("crates/services/src/agentic/runtime/service", (file) =>
  /\.(rs|md)$/.test(file),
);
const hypervisorDesktopProbeFiles = allFiles("apps/hypervisor/scripts", (file) =>
  /^apps\/hypervisor\/scripts\/(?:desktop_.*_probe|dev_.*_probe)\.py$/.test(file) ||
  file === "apps/hypervisor/scripts/home_onboarding_condition_matrix.ts",
);
const activeRuntimeSwarmFiles = [
  ...allFiles("apps/hypervisor/src", (file) => /\.(ts|tsx|css)$/.test(file)),
  ...allFiles("crates/api/src", (file) => file.endsWith(".rs")),
  ...allFiles("crates/services/src/agentic/runtime", (file) => file.endsWith(".rs")),
  "crates/types/src/app/chat.rs",
].filter((file) => exists(file));
const allowedSwarmCompatibilityFiles = new Set([
  "apps/hypervisor/src/types/work-graph-compat.ts",
  "crates/api/src/chat/types.rs",
  "crates/services/src/agentic/runtime/service/memory/context.rs",
  "crates/services/src/agentic/runtime/types.rs",
  "crates/types/src/app/chat.rs",
]);
const generatedTs = read("packages/hypervisor-workbench/src/runtime/generated/action-schema.ts");
const generatedRust = read("crates/types/src/app/generated/runtime_action_schema.rs");
const actionSchema = JSON.parse(read("internal-docs/implementation/runtime-action-schema.json"));

assert(
  "daemon-promoted",
  exists("packages/runtime-daemon/src/index.mjs") && !exists("scripts/lib/local-runtime-daemon.mjs"),
  ["packages/runtime-daemon/src/index.mjs"],
  "daemon implementation must live outside scripts/lib",
);
assert(
  "daemon-product-names",
  daemonSource.includes("startRuntimeDaemonService") &&
    daemonSource.includes("AgentgresRuntimeStateStore") &&
    !daemonSource.includes("startLocalRuntimeDaemon") &&
    !daemonSource.includes("AgentgresRuntimeStore"),
  ["packages/runtime-daemon/src/index.mjs"],
  "daemon implementation must use product runtime names",
);
assert(
  "focused-hypervisor-checks",
  retiredAutopilotPackageScripts.length === 0 &&
    retiredHypervisorGoalScripts.length === 0 &&
    retiredHypervisorHarnessValidationScripts.length === 0 &&
    packageJson.scripts["test:hypervisor-app-harness"] &&
    !packageJson.scripts["build:hypervisor-workbench-composer"] &&
    !packageJson.scripts["build:ioi-workbench-composer"],
  ["package.json"],
  "root package scripts must expose focused Hypervisor checks and keep adapter-local composer builds retired",
);
assert(
  "compact-app-harness-contract",
  hypervisorAppHarnessContractSource.includes("hypervisorGuiHarnessContract") &&
    hypervisorAppHarnessContractSource.includes("validateHypervisorGuiHarnessResult") &&
    hypervisorAppHarnessContractSource.includes("buildBlockedHypervisorGuiHarnessResult") &&
    hypervisorAppHarnessContractSource.includes("HYPERVISOR_RETAINED_QUERIES") &&
    !/autopilotGuiHarnessContract|validateAutopilotGuiHarnessResult|buildBlockedAutopilotGuiHarnessResult|AUTOPILOT_(?:GUI_HARNESS|REQUIRED|RETAINED|PROVIDER_GATED|READ_ONLY)/.test(
      hypervisorAppHarnessContractSource,
    ),
  [
    "scripts/lib/hypervisor-app-harness-contract.mjs",
  ],
  "keep the compact app harness contract as the app-harness authority",
);
assert(
  "hypervisor-client-runtime-command-names",
  hypervisorClientRuntimeSource.includes("runtime_open_hypervisor_intent_requested") &&
    hypervisorClientRuntimeSource.includes('invoke("reset_hypervisor_data")') &&
    !/runtime_open_autopilot_intent_requested|reset_autopilot_data/.test(
      hypervisorClientRuntimeSource,
    ),
  ["apps/hypervisor/src/services/HypervisorClientRuntime.ts"],
  "Hypervisor client runtime must emit Hypervisor-named host events and commands, not retired Autopilot bridge names.",
);
assert(
  "workbench-adapter-bridge-command-names",
  workspaceEditorAdapterBridgeSource.includes('"ensure_workbench_adapter_session"') &&
    workspaceEditorAdapterBridgeSource.includes('"stop_workbench_adapter_session"') &&
    workspaceEditorAdapterBridgeSource.includes(
      '"write_workbench_adapter_bridge_state"',
    ) &&
    workspaceEditorAdapterBridgeSource.includes(
      '"enqueue_workbench_adapter_bridge_command"',
    ) &&
    workspaceEditorAdapterBridgeSource.includes(
      '"take_workbench_adapter_bridge_requests"',
    ) &&
    !/workspace_ide|Workspace IDE/.test(workspaceEditorAdapterBridgeSource),
  ["apps/hypervisor/src/services/workspaceEditorAdapterBridge.ts"],
  "Workbench adapter bridge commands must use Workbench adapter protocol names, not retired workspace_ide command ids.",
);
assert(
  "chat-shell-hypervisor-route-names",
  companionShellNavigationSource.includes('openChatShellView("process")') &&
    chatSessionHookSource.includes('await openChat("process")') &&
    !/openChatShellView\("autopilot"\)|openChat\("autopilot"\)/.test(
      `${companionShellNavigationSource}\n${chatSessionHookSource}`,
    ),
  [
    "apps/hypervisor/src/services/companionShellNavigation.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/hooks/useChatSession.ts",
  ],
  "Chat shell entry points must route Hypervisor/work-graph shortcuts to the process view, not the retired autopilot view id.",
);
assert(
  "hypervisor-generated-contract-path",
  exists("apps/hypervisor/src/generated/hypervisor-contracts/index.ts") &&
    !exists("apps/hypervisor/src/generated/autopilot-contracts/index.ts") &&
    hypervisorTypeWrapperSources.includes("../generated/hypervisor-contracts") &&
    !hypervisorTypeWrapperSources.includes("../generated/autopilot-contracts"),
  [
    "apps/hypervisor/src/generated/hypervisor-contracts",
    "apps/hypervisor/src/types/generated.ts",
    "apps/hypervisor/src/types/events.ts",
    "apps/hypervisor/src/types/artifacts.ts",
    "apps/hypervisor/src/types/notifications.ts",
    "apps/hypervisor/src/types/atlas.ts",
  ],
  "Hypervisor frontend type wrappers must import generated Hypervisor contracts, not the retired generated/autopilot-contracts path.",
);
assert(
  "runtime-module-map",
  exists("internal-docs/implementation/runtime-module-map.md") &&
    runtimeModuleMap.includes("RuntimeSubstrate") &&
    runtimePackageBoundaries.includes("runtime-module-map.md") &&
    runtimeModuleMap.includes("WorkbenchAdapterHost") &&
    runtimeModuleMap.includes("root `ide/` product path") &&
    runtimeModuleMap.includes("not an active proof home"),
  [
    "internal-docs/implementation/runtime-module-map.md",
    "internal-docs/implementation/runtime-package-boundaries.md",
  ],
  "runtime module map must identify canonical homes and be linked from boundary docs",
);
assert(
  "hypervisor-internal-maps-fold-fleet-into-provider-environment-views",
  runtimePackageBoundaries.includes("Hypervisor Providers / Environments") &&
    runtimePackageBoundaries.includes("sessions, leases, and restore/archive refs") &&
    runtimeModuleMap.includes("provider/environment views") &&
    runtimeModuleMap.includes("provider-environment names") &&
    !/Foundry\s*\/\s*Fleet|Workbench,\s*Foundry,\s*Fleet|Foundry\/Fleet|Fleet names/.test(
      `${runtimePackageBoundaries}\n${runtimeModuleMap}`,
    ),
  [
    "internal-docs/implementation/runtime-package-boundaries.md",
    "internal-docs/implementation/runtime-module-map.md",
  ],
  "internal implementation maps must fold retired Fleet posture into Hypervisor provider/environment/session views",
);
assert(
  "refine-architecture-ioi-reference-target",
  refineArchitectureGuide.includes("internal-docs/reverse-engineering/ioi") &&
    refineArchitectureGuide.includes("Primary IOI reference mirror") &&
    !/internal-docs\/reverse-engineering\/ona|ONA-like/.test(refineArchitectureGuide),
  ["internal-docs/implementation/refine-architecture.md"],
  "refine-architecture Phase 0A must use the IOI reverse-engineering mirror as the primary UX target, not ONA-era wording.",
);
assert(
  "hypervisor-shell-ioi-reference-contract",
  hypervisorShellNavigationSource.includes("HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS") &&
    hypervisorShellNavigationSource.includes('primaryReference: "internal-docs/reverse-engineering/ioi"') &&
    [
      '"home"',
      '"sessions"',
      '"projects"',
      '"missions"',
      '"workbench"',
      '"automations"',
      '"insights"',
      '"agents"',
      '"models"',
      '"privacy"',
      '"providers"',
      '"environments"',
      '"foundry"',
      '"authority"',
      '"receipts"',
      '"settings"',
    ].every((surface) => hypervisorShellNavigationSource.includes(surface)) &&
    !/["']fleet["']|fleet_job|fleet\.provider|features\/Fleet/.test(
      hypervisorShellNavigationSource,
    ) &&
    !exists("packages/hypervisor-workbench/src/features/Fleet") &&
    [
      '"left_nav"',
      '"new_session"',
      '"session_rail"',
      '"session_detail_tabs"',
      '"right_inspector"',
      '"bottom_inspector"',
    ].every((region) => hypervisorShellNavigationSource.includes(region)) &&
    hypervisorShellNavigationSource.includes('"workbench_adapter"') &&
    hypervisorShellNavigationSource.includes('"git_auth"') &&
    hypervisorShellNavigationSource.includes("Codex CLI") &&
    hypervisorShellNavigationSource.includes("Claude Code") &&
    hypervisorShellNavigationSource.includes("DeepSeek TUI") &&
    hypervisorActivityBarSource.includes("HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS") &&
    hypervisorActivityBarSource.includes("referenceLeftNavSurfaceIds") &&
    hypervisorActivityBarSource.includes("primaryNavItems") &&
    !/internal-docs\/reverse-engineering\/ona|Hypervisor IDE/.test(
      hypervisorShellNavigationSource,
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLocalActivityBar.tsx",
  ],
  "Hypervisor shell must bind Phase 0A to the IOI reference cockpit contract and derive rail shortcuts from that contract.",
);
assert(
  "hypervisor-shell-light-reference-boot",
  hypervisorIndexHtmlSource.includes("background: #ffffff") &&
    hypervisorIndexHtmlSource.includes("color: #1f1f1f") &&
    hypervisorIndexHtmlSource.includes('font: 13px/1.45 "ABC Diatype"') &&
    hypervisorIndexHtmlSource.includes("background: #f7f7f6") &&
    hypervisorIndexHtmlSource.includes("border: 1px solid #e1e1e1") &&
    hypervisorIndexHtmlSource.includes("color: #6f6f76") &&
    !/background: #0d0c0a|color: #f2f0eb|rgba\(242, 240, 235/.test(
      hypervisorIndexHtmlSource,
    ),
  ["apps/hypervisor/index.html"],
  "Hypervisor pre-mount boot fallback must use the light IOI reference posture instead of a dark IDE-era card.",
);
assert(
  "repo-facing-hypervisor-client-map",
  readme.includes("[`apps/hypervisor`](apps/hypervisor)") &&
    readme.includes("[`packages/hypervisor-workbench`](packages/hypervisor-workbench)") &&
    readme.includes("[`workbench-adapters`](workbench-adapters)") &&
    readme.includes("Hypervisor Workbench") &&
    !readme.includes("packages/agent-ide") &&
    !readme.includes("Hypervisor IDE"),
  ["README.md"],
  "README must present Hypervisor App/Web, Workbench, and adapter targets instead of retired Hypervisor IDE or packages/agent-ide language.",
);
assert(
  "active-product-copy-hypervisor-taxonomy",
  developersDocs.includes("Hypervisor exists today as a native operator client over Hypervisor Core") &&
    developersDocs.includes("'apps/hypervisor/src/windows/HypervisorShellWindow'") &&
    developersDocs.includes("routePath: '/hypervisor'") &&
    !developersDocs.includes("Autopilot exists today as a local Tauri desktop product") &&
    !developersDocs.includes("'apps/hypervisor/src/windows/AutopilotShellWindow'") &&
    !developersDocs.includes("daemon and Autopilot surfaces") &&
    workbenchAdapterLauncher.includes("hypervisor-workbench-configured-llama-cpp") &&
    !workbenchAdapterLauncher.includes("autopilot-ide-configured-llama-cpp"),
  [
    "apps/developers-ioi-ai/src/content/docs.tsx",
    "scripts/launch-hypervisor-workbench-adapter-host.mjs",
  ],
  "Active product docs and model preload identifiers must use Hypervisor client/Workbench taxonomy, not Autopilot IDE or Tauri product language.",
);
assert(
  "install-resolver-current-product-hypervisor-named",
  hypervisorInstallProductMetadataSource.includes("IOI Hypervisor") &&
    hypervisorInstallProductMetadataSource.includes("ioi-hypervisor") &&
    hypervisorInstallProductMetadataSource.includes("hypervisor,ioi hypervisor") &&
    !/IOI Autopilot|ioi-autopilot|autopilot,ioi autopilot/.test(
      hypervisorInstallProductMetadataSource,
    ),
  ["crates/services/src/agentic/runtime/resolver/software_install/product_metadata.rs"],
  "Current-product install resolution must default to Hypervisor names and must not retain Autopilot aliases.",
);
assert(
  "rust-product-fixtures-hypervisor-named",
  hypervisorRustProductFixtureSources.includes("IOI Hypervisor") &&
    hypervisorRustProductFixtureSources.includes("Hypervisor Agent Studio") &&
    hypervisorRustProductFixtureSources.includes("/tmp/hypervisor-agent-studio-") &&
    !/IOI Autopilot|Autopilot Agent Studio|autopilot_agent_studio|autopilot-agent-studio|\/tmp\/autopilot|\.tmp\/autopilot/.test(
      hypervisorRustProductFixtureSources,
    ),
  [
    "crates/services/src/agentic/runtime/service/decision_loop/cognition/final_reply_product_handoff.rs",
    "crates/services/src/agentic/runtime/service/decision_loop/cognition/tests_parts/root/final_reply_evidence.rs",
    "crates/services/src/agentic/runtime/execution/screen/semantics/tests.rs",
    "crates/services/src/agentic/runtime/execution/screen/tests.rs",
  ],
  "Active Rust product fixtures and final-reply handoff canaries must use Hypervisor-era labels, not Autopilot labels.",
);
assert(
  "workbench-shell-patch-hypervisor-named",
  exists("scripts/lib/hypervisor-workbench-shell-patch.mjs") &&
    !exists("scripts/lib/autopilot-workbench-shell-patch.mjs") &&
    workbenchShellPatch.includes("applyHypervisorWorkbenchShellPatch") &&
    workbenchShellPatch.includes("ioi-hypervisor-native-shell") &&
    workbenchShellPatch.includes("ioi-hypervisor-workbench-quickinput") &&
    workbenchShellPatch.includes("ioi.hypervisor-workbench-shell-patch.v1") &&
    workbenchShellPatch.includes("ioi.hypervisor.shell.mode") &&
    workbenchShellPatch.includes("ioi.hypervisor.active.mode") &&
    workbenchShellPatch.includes("hypervisor-primary-rail") &&
    workbenchShellPatch.includes("code-rail-back-to-hypervisor") &&
    workbenchShellPatch.includes("secondaryHypervisorHeaderRemoved") &&
    workbenchShellPatch.includes("hypervisorModeMenuHiddenByCssAndSettings") &&
    !/applyAutopilotWorkbenchShellPatch|ioi-autopilot-native-shell|ioi-autopilot-fork-quickinput|ioi\.autopilot-workbench-shell-patch|ioi\.autopilot\.shell\.mode|ioi\.autopilot\.active\.mode|autopilot-primary-rail|code-rail-back-to-autopilot|activeAutopilotMode|secondaryAutopilotHeaderRemoved|autopilotModeMenuHiddenByCssAndSettings|Back to Autopilot/.test(
      workbenchShellPatch,
    ),
  [
    "scripts/lib/hypervisor-workbench-shell-patch.mjs",
    "scripts/lib/autopilot-workbench-shell-patch.mjs",
  ],
  "Workbench adapter shell patch helper must use Hypervisor naming; the retired Autopilot helper path/function/source ids must not return.",
);
assert(
  "workbench-adapter-fork-sync-target-only",
  /workbench-adapters\/vscode\/\n/.test(rootGitignore) &&
    /workbench-adapters\/builds\/\n/.test(rootGitignore) &&
    /"workbenchSource":\s*"workbench-adapters\/ioi-workbench"/.test(workbenchShellManifest) &&
    /"optionalForRuntimeLaunch":\s*true/.test(workbenchShellManifest) &&
    workbenchAdaptersReadme.includes("workbench-adapters/ioi-workbench") &&
    workbenchAdaptersReadme.includes("target optional local VS Code source") &&
    /const extensionSource = resolve\(\s*repoRoot,\s*"workbench-adapters\/ioi-workbench",\s*\);/.test(
      workbenchAdapterHostPaths,
    ) &&
    /const forkWorkbenchTarget = resolve\(forkRoot, "extensions\/ioi-workbench"\);/.test(
      workbenchAdapterHostPaths,
    ) &&
    /rmSync\(target\.path, \{ recursive: true, force: true \}\);\s*mkdirSync\(target\.path, \{ recursive: true \}\);\s*cpSync\(extensionSource, target\.path, \{ recursive: true, force: true \}\);/.test(
      workbenchAdapterHostPaths,
    ) &&
    !/const extensionSource = resolve\([\s\S]*workbench-adapters\/vscode/.test(
      workbenchAdapterHostPaths,
    ),
  [
    ".gitignore",
    "workbench-adapters/README.md",
    "workbench-adapters/shell.manifest.json",
    "scripts/lib/hypervisor-workbench-adapter-host-paths.mjs",
  ],
  "Ignored VS Code fork/build trees must stay sync targets copied from the canonical Workbench adapter source, not duplicate tracked JS truth paths.",
);
assert(
  "home-onboarding-hypervisor-taxonomy",
  hypervisorHomeSource.includes("HYPERVISOR_ONBOARDING_FAMILIES") &&
    hypervisorHomeSource.includes("HypervisorOnboardingStep") &&
    hypervisorHomeSource.includes("Get Started with Hypervisor") &&
    hypervisorHomeSource.includes("governed Workbench adapter") &&
    hypervisorHomeSource.includes("Workbench adapter") &&
    !/AUTOPILOT_ONBOARDING|AutopilotOnboarding|autopilot\.home\.onboarding|autopilot\.onboarding|OpenVSCode|contained OpenVSCode/.test(hypervisorHomeSource),
  [
    "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
    "apps/hypervisor/src/surfaces/Home/HomeWalkthroughDocument.tsx",
    "apps/hypervisor/src/surfaces/Home/homeOnboardingModel.ts",
    "apps/hypervisor/src/surfaces/Home/index.ts",
  ],
  "Home onboarding must use Hypervisor and Workbench adapter language instead of retired Autopilot/OpenVSCode product framing.",
);
assert(
  "active-visible-surfaces-hypervisor-named",
  !/\bAutopilot\b/.test(hypervisorVisibleSurfaceSources) &&
    hypervisorVisibleSurfaceSources.includes("Hypervisor workspace") &&
    hypervisorVisibleSurfaceSources.includes("Hypervisor native-local fixture") &&
    hypervisorVisibleSurfaceSources.includes("inside Hypervisor"),
  [
    "apps/hypervisor/src/windows/ChatShellWindow/index.tsx",
    "apps/hypervisor/src/windows/ChatShellWindow/components/ArtifactHubTaskViews.tsx",
    "apps/hypervisor/src/windows/ChatShellWindow/components/views/ThoughtsView.tsx",
    "apps/hypervisor/src/surfaces/MissionControl/WelcomeView.tsx",
    "apps/hypervisor/src/surfaces/MissionControl/MissionControlMountsView.tsx",
    "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
    "packages/workspace-substrate/src/notebook.ts",
    "packages/hypervisor-workbench/src/features/Connectors/components",
    "packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts",
  ],
  "Active visible app/workbench surfaces must use Hypervisor labels; Autopilot may remain only in protocol IDs, historical evidence, or explicit legacy fixtures.",
);
assert(
  "workflow-runtime-checkpoint-identities-hypervisor-named",
  hypervisorVisibleSurfaceSources.includes(
    "hypervisor.workflow_output_writer_transcript_staging.v1",
  ) &&
    !/autopilot\.workflow_output_writer/.test(hypervisorVisibleSurfaceSources),
  ["packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts"],
  "Workflow runtime checkpoint identities must use Hypervisor namespaces, not retired Autopilot checkpoint names.",
);
assert(
  "authority-center-model-route-fixtures-hypervisor-named",
  [
    "model-capability:route.hypervisor",
    "route.hypervisor",
    "model.route.hypervisor",
  ].every((token) => authorityCenterTestSource.includes(token)) &&
    !/model-capability:route\.autopilot|route_id:\s*["']route\.autopilot["']|model\.route\.autopilot/.test(
      authorityCenterTestSource,
    ),
  ["apps/hypervisor/src/surfaces/Policy/authorityCenter.test.ts"],
  "Authority Center model-route fixtures must use Hypervisor route identities, not retired Autopilot model-route namespaces.",
);
assert(
  "active-test-fixtures-hypervisor-named",
  activeHypervisorFixtureSources.includes("Hypervisor validation run") &&
    activeHypervisorFixtureSources.includes("install hypervisor") &&
    activeHypervisorFixtureSources.includes('"captureAppName"] = "Hypervisor"') &&
    activeHypervisorFixtureSources.includes(
      "internal-docs/implementation/refine-architecture.md:50",
    ) &&
    !/Autopilot validation run|install autopilot|captureAppName["'\]]+\s*=\s*["']Autopilot|autopilot-chat-agent-ux/.test(
      activeHypervisorFixtureSources,
    ),
  [
    "apps/hypervisor/src/windows/ChatShellWindow/components/artifactHubPrCommentsModel.test.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/utils/assistantTurnProcessModel.test.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/utils/turnWindows.test.ts",
    "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.test.ts",
  ],
  "Active chat/workflow fixture inputs must use Hypervisor labels unless they are explicit negative assertions.",
);
assert(
  "workspace-workbench-copy-adapter-named",
  workspaceWorkbenchCopySources.includes("Direct Workbench adapter") &&
    workspaceWorkbenchCopySources.includes("Workbench adapter session is ready") &&
    workspaceWorkbenchCopySources.includes("Direct Workbench adapter webview") &&
    workspaceWorkbenchCopySources.includes("Workbench adapter context") &&
    !/Direct OpenVSCode workbench|OpenVSCode session is ready|current OpenVSCode|available OpenVSCode|native OpenVSCode contribution|Code repositories<\/span>|Direct OpenVSCode workbench webview|OpenVSCode setup baseline/.test(
      workspaceWorkbenchCopySources,
    ),
  [
    "apps/hypervisor/src/surfaces/Workspace/WorkspaceShell.tsx",
    "apps/hypervisor/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx",
    "apps/hypervisor/src/services/directWorkspaceWorkbenchHost.ts",
    "apps/hypervisor/src/services/openVsCodeWorkbenchHost.ts",
    "apps/hypervisor/src/services/openVsCodeWorkbenchSession.ts",
    "apps/hypervisor/src/services/workspaceRuntimeNavigation.ts",
    "apps/hypervisor/src/services/workflowCodeGenerationProposal.ts",
    "apps/hypervisor/src/services/hypervisorAppearance.ts",
  ],
  "Visible Workbench copy must describe adapter targets, not present OpenVSCode as the parent product.",
);
assert(
  "agent-model-matrix-session-scope-named",
  agentModelMatrixScopeSources.includes("session_shared") &&
    !/fleet_shared/.test(agentModelMatrixScopeSources),
  [
    "scripts/run-agent-model-matrix.mjs",
    "scripts/lib/agent-model-matrix.mjs",
    "apps/benchmarks/src",
  ],
  "Agent/model benchmark execution scopes must use session_shared rather than the retired Fleet shared-scope label.",
);
assert(
  "active-client-namespaces-hypervisor-named",
  [
    "hypervisor.workspace-shell.v1",
    "hypervisor.pending_chat_launch.v1",
    "hypervisor.chat_launch_receipts.v1",
    "hypervisor.pending_chat_shell_launch.v1",
    "hypervisor.chat_session.vim_mode.v1",
    "hypervisor:chat-session-vim-mode-updated",
    "hypervisor-header.command-center",
    "hypervisor-share",
    "hypervisor-trace",
    "hypervisor-dark",
    "hypervisor-light",
    ".hypervisor",
    "hypervisor-cell",
    "hypervisor_replay",
    "hypervisor-replay",
    "defineHypervisorTheme",
    "hypervisor-shell",
    "hypervisor-boot-fallback",
    "data-hypervisor-boot-error",
    "hypervisor.capabilities.custom-connections",
    "route.hypervisor.local-first",
  ].every((token) => hypervisorClientNamespaceSources.includes(token)) &&
    !/autopilot-shell|autopilot-dark|autopilot-light|autopilot-share|autopilot-trace|autopilot\.pending|autopilot\.workspace-shell|autopilot\.chat_session|autopilot:chat-session|autopilot-header\.command-center|autopilot-boot-fallback|data-autopilot-boot-error|autopilot\.capabilities\.custom-connections|route\.autopilot\.local-first|["']\.autopilot["']|autopilot-cell|autopilot_replay|autopilot-replay|defineAutopilotTheme/.test(
      hypervisorClientNamespaceSources,
    ),
  [
    "apps/hypervisor/index.html",
    "apps/hypervisor/src/services/*LaunchState.ts",
    "apps/hypervisor/src/services/workspaceShellState.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/hooks/useChatVimMode.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell",
    "packages/workspace-substrate/src/codeOss.ts",
    "packages/workspace-substrate/src/types.ts",
    "packages/workspace-substrate/src/notebook.ts",
    "apps/hypervisor/src/surfaces/Capabilities/components/model.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-scratch-blueprints.ts",
  ],
  "Active client storage keys, events, export prefixes, editor themes, replay formats, and shell stylesheet paths must use Hypervisor namespaces.",
);
assert(
  "active-model-mount-identities-hypervisor-named",
  [
    "provider.hypervisor.local",
    "backend.hypervisor.native-local.fixture",
    "hypervisor.native_local.fixture",
    "endpoint.hypervisor.native-fixture",
    "hypervisor:native-fixture",
    "hypervisor:gui-lifecycle",
    "hypervisor:gui-download",
    "hypervisor:gui-failed-download",
    "endpoint.hypervisor.gui-lifecycle",
    "hypervisor-local-server",
    "hypervisor_native_local_openai_compatible_serving",
    "hypervisor_native_local_provider_native_stream",
    "hypervisor_native_local_backend_registry",
    "hypervisor_native_local_process_supervisor",
    "fixture://catalog/hypervisor-native-3b-q4",
    "hypervisor:map-only",
    "Hypervisor native local model response",
    "Hypervisor native fixture e2e",
    "Hypervisor native fixture tuned",
    "Hypervisor native-local route backed by configured llama.cpp runtime.",
    "Hypervisor received the catalog OAuth callback.",
    "governed Hypervisor model mounting path",
  ].every((token) => hypervisorModelMountIdentitySources.includes(token)) &&
    !/provider\.autopilot\.local|backend\.autopilot\.native-local\.fixture|autopilot\.native_local\.fixture|endpoint\.autopilot\.local|endpoint\.autopilot\.native-fixture|endpoint\.autopilot\.gui-lifecycle|model\.autopilot\.local|autopilot:native-fixture|autopilot:map-only|autopilot:gui-|autopilot-local-server|autopilot_native_local_openai_compatible_serving|autopilot_native_local_provider_native_stream|autopilot_native_local_backend_registry|autopilot_native_local_process_supervisor|autopilot_native_local_process_started|catalog\/search\?(?:q|query)=autopilot|lastSearch\.query,\s*["']autopilot["']|catalog-search["'\],\s]+--query["'\],\s]+autopilot|fixture:\/\/catalog\/autopilot-native-3b-q4|fixture:\/\/autopilot|Autopilot native local|Autopilot native fixture|Autopilot-native local route|Autopilot received the catalog OAuth callback|governed Autopilot model mounting path/.test(
      hypervisorModelMountIdentitySources,
    ),
  [
    "packages/runtime-daemon/src/model-mounting/default-records.mjs",
    "packages/runtime-daemon/src/model-mounting/default-discovery.mjs",
    "packages/runtime-daemon/src/model-mounting.mjs",
    "apps/hypervisor/src/surfaces/MissionControl/MissionControlMountsView.tsx",
    "scripts/lib/model-mounting-daemon-contract.test.mjs",
    "scripts/validate-model-mounting-e2e.mjs",
    "packages/runtime-daemon/src/model-mounting/*.test.mjs",
    "packages/runtime-daemon/src/runtime-daemon-core-direct-invoker-service.test.mjs",
  ],
  "Active native-local model mount providers, backends, endpoints, auth audiences, catalog fixtures, and stream evidence refs must use Hypervisor identities.",
);
assert(
  "workbench-landing-adapter-hub",
  workspaceRepositoryGateSource.includes('data-workbench-adapter-hub="true"') &&
    workspaceRepositoryGateSource.includes("<h1>Workbench</h1>") &&
    workspaceRepositoryGateSource.includes("Adapter targets") &&
    workspaceRepositoryGateSource.includes("Choose where Workbench opens") &&
    workspaceRepositoryGateSource.includes("local editors, browser workspaces") &&
    workspaceRepositoryGateSource.includes("workspace-repository-gate__adapter-list") &&
    workspaceRepositoryGateSource.includes("workspace-repository-gate__adapter-row") &&
    workspaceRepositoryGateSource.includes("What's new?") &&
    workspaceRepositoryGateSource.includes("HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES") &&
    workspaceRepositoryGateSource.includes("getWorkbenchAdapterPreferenceRef") &&
    workspaceRepositoryGateSource.includes("buildWorkbenchAdapterLaunchPlan") &&
    workspaceRepositoryGateSource.includes("data-workbench-adapter-preference") &&
    workspaceRepositoryGateSource.includes("data-workbench-adapter-executor-lane") &&
    workspaceRepositoryGateSource.includes("data-workbench-adapter-control-action") &&
    workspaceRepositoryGateSource.includes("data-workbench-adapter-control-channel-ref") &&
    workspaceRepositoryGateSource.includes("workspace-repository-gate__adapter-control") &&
    workspaceRepositoryGateSource.includes("persistWorkbenchAdapterPreferenceRef") &&
    !/Governance|Adapter policy|Review policy|governed adapter target|runtime truth|Hypervisor Core|Agentgres|wallet\.network/.test(
      workspaceRepositoryGateSource,
    ) &&
    !/<h1>Code repositories<\/h1>|>Pull requests<|No pull requests created by you|Find pull requests/.test(
      workspaceRepositoryGateSource,
    ),
  ["apps/hypervisor/src/surfaces/Workspace/WorkspaceRepositoryGate.tsx"],
  "Workbench must open as a product-facing adapter hub with reference-style activity copy, not a code-repository, pull-request, or architecture-doctrine console.",
);
assert(
  "workbench-adapter-launch-plan-contract",
  hypervisorShellNavigationSource.includes("workbenchAdapterPreferences.ts") &&
    workbenchAdapterPreferencesSource.includes("WorkbenchAdapterLaunchPlan") &&
    workbenchAdapterPreferencesSource.includes(
      "ioi.hypervisor.workbench_adapter_launch_plan.v1",
    ) &&
    workbenchAdapterPreferencesSource.includes(
      "buildWorkbenchAdapterLaunchPlan",
    ) &&
    workbenchAdapterPreferencesSource.includes(
      "requestWorkbenchAdapterLaunchPlanAdmission",
    ) &&
    workbenchAdapterPreferencesSource.includes(
      "HYPERVISOR_WORKBENCH_ADAPTER_LAUNCH_PLAN_ADMISSION_PATH",
    ) &&
    workbenchAdapterPreferencesSource.includes(
      "connection-contract:workbench-adapter/desktop-bridge",
    ) &&
    workbenchAdapterPreferencesSource.includes("executor_lane") &&
    workbenchAdapterPreferencesSource.includes("control_action") &&
    workbenchAdapterPreferencesSource.includes("control_channel_ref") &&
    workbenchAdapterPreferencesSource.includes(
      "control-channel:workbench-adapter/desktop-bridge",
    ) &&
    workbenchAdapterPreferencesSource.includes(
      "lease:provider/workspace-access",
    ) &&
    workbenchAdapterPreferencesSource.includes(
      "secret_release_policy: \"no_durable_secret_release\"",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-workbench-adapter-launch-plan-ref",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-workbench-adapter-connection-contract-ref",
    ) &&
    hypervisorShellNavigationSource.includes("workbench_adapter_admission") &&
    hypervisorShellNavigationSource.includes("workbench_adapter_executor_lane") &&
    hypervisorShellNavigationSource.includes("workbench_adapter_control_action") &&
    hypervisorShellNavigationSource.includes(
      "workbench_adapter_control_channel_ref",
    ) &&
    hypervisorShellNavigationSource.includes("daemon_admitted") &&
    hypervisorShellNavigationSource.includes("daemon_blocked") &&
    hypervisorShellNavigationSource.includes("daemon_unavailable") &&
    hypervisorShellControllerSource.includes(
      "requestWorkbenchAdapterLaunchPlanAdmission",
    ) &&
    hypervisorShellControllerSource.includes(
      "buildHypervisorWorkbenchAdapterAdmissionFailure",
    ) &&
    runtimeWorkbenchAdapterLaunchPlanAdmissionSource.includes(
      "ioi.runtime.workbench_adapter_launch_plan_admission.v1",
    ) &&
    runtimeWorkbenchAdapterLaunchPlanAdmissionSource.includes(
      "workbench_adapter_launch_durable_secret_release_blocked",
    ) &&
    runtimeWorkbenchAdapterLaunchPlanAdmissionSource.includes(
      "workbench_adapter_runtime_truth_claim_blocked",
    ) &&
    runtimeWorkbenchAdapterLaunchPlanAdmissionSource.includes(
      "workbench_adapter_provider_posture_ref_required",
    ) &&
    runtimeWorkbenchAdapterLaunchPlanAdmissionSource.includes(
      "workbench_adapter_control_contract_mismatch",
    ) &&
    hypervisorShellContentSource.includes(
      "data-session-open-surface-enabled",
    ) &&
    hypervisorShellContentSource.includes(
      "data-session-open-surface-admission-state",
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/workbench-adapter-launch-plans",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/workbenchAdapterPreferences.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/useHypervisorShellController.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx",
    "packages/runtime-daemon/src/runtime-workbench-adapter-launch-plan-admission.mjs",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
  ],
  "Workbench adapter preferences must compile into daemon-gated launch plans, call the public daemon admission route during New Session launch, preserve admission/block/offline state, and keep connection contracts, leases, receipts, and no durable secret release.",
);
assert(
  "hypervisor-environment-ops-model",
  refineArchitectureGuide.includes("HypervisorEnvironmentOpsProfile") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentLifecycleState") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentClass") &&
    refineArchitectureGuide.includes("HypervisorSessionAccessLease") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentService") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentTask") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentPort") &&
    refineArchitectureGuide.includes("HypervisorScmAuthRequirement") &&
    refineArchitectureGuide.includes("Environment-ops doctrine") &&
    refineArchitectureGuide.includes("create, create_from_project, start, stop, mark_active, archive,") &&
    refineArchitectureGuide.includes("access/log lease state, SCM auth requirements, ports/services, tasks, terminal/logs") &&
    !/\bGitpod\b|gitpod/i.test(refineArchitectureGuide),
  ["internal-docs/implementation/refine-architecture.md"],
  "Refine guide must model environment lifecycle, access/log leases, SCM auth, services, tasks, ports, and restore refs as Hypervisor-native objects without vendor-specific references.",
);
assert(
  "hypervisor-environment-ops-canon",
  [
    "HypervisorEnvironmentClass",
    "HypervisorEnvironmentOpsProfile",
    "HypervisorEnvironmentLifecycleState",
    "HypervisorEnvironmentActivitySignal",
    "HypervisorSessionAccessLease",
    "HypervisorEnvironmentService",
    "HypervisorEnvironmentTask",
    "HypervisorEnvironmentPort",
    "HypervisorScmAuthRequirement",
  ].every((term) =>
    [
      hypervisorCoreClientsSurfacesDoc,
      hypervisorProvidersEnvironmentsDoc,
      daemonRuntimeApiDoc,
      architectureSourceOfTruthMap,
      architectureImplementationMatrix,
      architectureVocabulary,
    ].every((doc) => doc.includes(term)),
  ) &&
    hypervisorCoreClientsSurfacesDoc.includes("encrypted blobs are restore material, not restore truth") &&
    hypervisorProvidersEnvironmentsDoc.includes("A blob can be necessary restore material without") &&
    daemonRuntimeApiDoc.includes("Provider lifecycle state may be evidence, but it is not") &&
    architectureVocabulary.includes("derived token material under a `HypervisorSessionAccessLease`") &&
    !exists(retiredHypervisorFleetDoc) &&
    (hypervisorProvidersEnvironmentsDoc.includes("There is no separate Fleet product") ||
      hypervisorProvidersEnvironmentsDoc.includes("They are not a separate product")) &&
    !/\bGitpod\b|gitpod/i.test(
      [
        hypervisorCoreClientsSurfacesDoc,
        hypervisorProvidersEnvironmentsDoc,
        daemonRuntimeApiDoc,
        architectureSourceOfTruthMap,
        architectureImplementationMatrix,
        architectureVocabulary,
      ].join("\n"),
    ),
  [
    "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    "docs/architecture/components/hypervisor/providers-and-environments.md",
    retiredHypervisorFleetDoc,
    "docs/architecture/components/daemon-runtime/api.md",
    "docs/architecture/_meta/source-of-truth-map.md",
    "docs/architecture/_meta/implementation-matrix.md",
    "docs/architecture/_meta/vocabulary.md",
  ],
  "Canon docs must model Hypervisor environment lifecycle, access/log leases, SCM auth, services, tasks, ports, and restore refs without vendor-specific references.",
);
assert(
  "hypervisor-agent-harness-adapter-testbed",
  [
    "codex_cli",
    "codex_desktop_linux",
    "claude_code_cli",
    "grok_build_cli",
    "deepseek_tui",
    "aider_cli",
    "openhands",
    "shell_tmux_agent",
    "generic_cli",
  ].every((adapterId) => hypervisorHarnessAdapterModelSource.includes(adapterId)) &&
    hypervisorHarnessAdapterModelSource.includes(
      "HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE",
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE",
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      'workspace_mount_policy: "public_trunk"',
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      'expected_receipt_schema: "ioi.hypervisor.harness_adapter_receipt.v1"',
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      'runtimeTruthSource: "daemon-runtime"',
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      'truth_boundary: "proposal_source_only"',
    ) &&
    !/Codex = Default Harness|Claude Code = Default Harness|external harness.*runtime truth/i.test(
      hypervisorHarnessAdapterModelSource,
    ),
  ["apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.ts"],
  "AgentHarnessAdapter fixtures must list external harnesses as daemon-gated proposal sources with public testbed custody, comparison receipts, and no runtime-truth shortcut.",
);
assert(
  "hypervisor-harness-container-lane-contract",
  runtimeHarnessContainerLaneSource.includes(
    "ioi.hypervisor.harness_container_lane_plan.v1",
  ) &&
    runtimeHarnessContainerLaneSource.includes(
      "ioi.hypervisor.harness_container_lane_receipt.v1",
    ) &&
    runtimeHarnessContainerLaneSource.includes("planHarnessAdapterContainerLane") &&
    runtimeHarnessContainerLaneSource.includes("buildHarnessContainerLaneReceipt") &&
    runtimeHarnessContainerLaneSource.includes("container_image_ref") &&
    runtimeHarnessContainerLaneSource.includes("command_argv_hash") &&
    runtimeHarnessContainerLaneSource.includes("network_policy") &&
    runtimeHarnessContainerLaneSource.includes("exit_status") &&
    runtimeHarnessContainerLaneSource.includes("ctee_private_workspace") &&
    runtimeHarnessContainerLaneSource.includes(
      "harness_container_lane_private_mount_blocked",
    ) &&
    runtimeHarnessContainerLaneSource.includes(
      "source refs, not raw host paths",
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/harness-container-lanes",
    ) &&
    publicRuntimeRoutesSource.includes("planHarnessAdapterContainerLane") &&
    publicRuntimeRoutesTestSource.includes(
      "expose daemon-planned harness container lane receipts",
    ) &&
    runtimeHarnessContainerLaneTestSource.includes(
      "container lane plan produces a not-executed receipt",
    ) &&
    runtimeHarnessContainerLaneTestSource.includes(
      "External container harnesses cannot mount plaintext or cTEE private workspace custody",
    ),
  [
    "packages/runtime-daemon/src/runtime-harness-container-lane.mjs",
    "packages/runtime-daemon/src/runtime-harness-container-lane.test.mjs",
  ],
  "Harness container lanes must be daemon-planned Docker/Podman contracts with image, argv hash, mounts, network policy, exit status, and private-mount/secret guards.",
);
assert(
  "hypervisor-harness-container-executor-contract",
  runtimeHarnessContainerExecutorSource.includes(
    "ioi.hypervisor.harness_container_invocation.v1",
  ) &&
    runtimeHarnessContainerExecutorSource.includes(
      "buildHarnessContainerInvocation",
    ) &&
    runtimeHarnessContainerExecutorSource.includes(
      "executeHarnessContainerLane",
    ) &&
    runtimeHarnessContainerExecutorSource.includes(
      "resolveMountSourceRef",
    ) &&
    runtimeHarnessContainerExecutorSource.includes(
      "resolveContainerImageRef",
    ) &&
    runtimeHarnessContainerExecutorSource.includes(
      "harness_container_executor_command_hash_mismatch",
    ) &&
    runtimeHarnessContainerExecutorSource.includes(
      "requires disabled networking",
    ) &&
    runtimeHarnessContainerExecutorTestSource.includes(
      "builds a docker invocation only from daemon-resolved source refs",
    ) &&
    runtimeHarnessContainerExecutorTestSource.includes(
      "returns daemon receipts with output hashes, not plaintext output",
    ),
  [
    "packages/runtime-daemon/src/runtime-harness-container-executor.mjs",
    "packages/runtime-daemon/src/runtime-harness-container-executor.test.mjs",
  ],
  "Harness container execution must be daemon-owned, command-hash verified, source-ref resolved, network-disabled by default, and receipt-only with output hashes.",
);
assert(
  "hypervisor-foundry-harness-comparison-daemon-run",
  hypervisorHarnessAdapterModelSource.includes(
    "buildHarnessPublicFixtureRunRequest",
  ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "requestHarnessPublicFixtureRun",
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "normalizeHarnessComparisonRunFromPublicFixtureRun",
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "hypervisor_foundry.harness_comparison_dashboard",
    ) &&
    hypervisorShellContentSource.includes("requestHarnessPublicFixtureRun") &&
    hypervisorShellContentSource.includes(
      'data-harness-comparison-action="request-run"',
    ) &&
    hypervisorShellContentSource.includes(
      "data-hypervisor-harness-comparison-state",
    ) &&
    hypervisorShellContentSource.includes("setComparison(nextComparison)") &&
    publicRuntimeRoutesTestSource.includes(
      "public runtime routes expose harness public fixture comparison under daemon gates",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.test.mjs",
  ],
  "Foundry harness comparison must request the daemon public-fixture route, normalize daemon attempts into comparison rows, and never execute external harnesses locally.",
);
assert(
  "hypervisor-model-weight-custody-admission",
  runtimeModelWeightCustodyAdmissionSource.includes(
    "ioi.runtime.model_weight_custody_admission.v1",
  ) &&
    runtimeModelWeightCustodyAdmissionSource.includes(
      "admitModelWeightCustodyRoute",
    ) &&
    runtimeModelWeightCustodyAdmissionSource.includes("public_open_weight") &&
    runtimeModelWeightCustodyAdmissionSource.includes("remote_api_private_weight") &&
    runtimeModelWeightCustodyAdmissionSource.includes(
      "tee_or_customer_cloud_mount",
    ) &&
    runtimeModelWeightCustodyAdmissionSource.includes(
      "provider_trust_remote_mount",
    ) &&
    runtimeModelWeightCustodyAdmissionSource.includes(
      "forbidden_plaintext_mount",
    ) &&
    runtimeModelWeightCustodyAdmissionSource.includes(
      "model_weight_custody_plaintext_private_weight_blocked",
    ) &&
    runtimeModelWeightCustodyAdmissionSource.includes(
      "model_weight_custody_private_native_claim_invalid",
    ) &&
    runtimeModelWeightCustodyAdmissionSource.includes(
      'runtimeTruthSource: "daemon-runtime"',
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/model-weight-custody-admissions",
    ) &&
    publicRuntimeRoutesSource.includes("admitModelWeightCustodyRoute") &&
    publicRuntimeRoutesTestSource.includes(
      "expose model-weight custody admissions",
    ) &&
    publicRuntimeRoutesTestSource.includes(
      "blocks provider-readable private weights",
    ) &&
    runtimeModelWeightCustodyAdmissionTestSource.includes(
      "blocks private weights readable by remote root",
    ) &&
    runtimeModelWeightCustodyAdmissionTestSource.includes(
      "provider-trust mounts require disclosure",
    ) &&
    runtimeModelWeightCustodyAdmissionTestSource.includes(
      "TEE or customer-cloud model-weight mounts require attestation",
    ),
  [
    "packages/runtime-daemon/src/runtime-model-weight-custody-admission.mjs",
    "packages/runtime-daemon/src/runtime-model-weight-custody-admission.test.mjs",
  ],
  "Model-weight custody admission must block unsafe private-weight plaintext mounts, separate remote API/TEE/provider-trust lanes, and keep daemon runtime truth.",
);
assert(
  "hypervisor-managed-worker-lifecycle-admission",
  runtimeManagedWorkerLifecycleAdmissionSource.includes(
    "ioi.runtime.managed_worker_instance_lifecycle_admission.v1",
  ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "admitManagedWorkerInstanceLifecycleTransition",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes("payment_past_due") &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes("zero_to_idle") &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "managed_worker_lifecycle_lapse_delete_blocked",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "managed_worker_lifecycle_restore_import_ref_required",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "managed_worker_lifecycle_archive_policy_required",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "scope:worker.restore",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "scope:worker.export",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "scope:worker.delete",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      "scope:worker.forget",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionSource.includes(
      'runtimeTruthSource: "daemon-runtime"',
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/managed-worker-lifecycle-admissions",
    ) &&
    publicRuntimeRoutesSource.includes(
      "admitManagedWorkerInstanceLifecycleTransition",
    ) &&
    publicRuntimeRoutesTestSource.includes(
      "expose managed worker lifecycle admissions",
    ) &&
    publicRuntimeRoutesTestSource.includes(
      "blocks payment-lapse deletion",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionTestSource.includes(
      "payment lapse freezes billable work and cannot silently delete context",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionTestSource.includes(
      "archive and restore transitions require Agentgres refs",
    ) &&
    runtimeManagedWorkerLifecycleAdmissionTestSource.includes(
      "export, delete, and forget transitions require explicit wallet authority",
    ),
  [
    "packages/runtime-daemon/src/runtime-managed-worker-instance-lifecycle-admission.mjs",
    "packages/runtime-daemon/src/runtime-managed-worker-instance-lifecycle-admission.test.mjs",
  ],
  "Managed worker lifecycle admission must bind lapse, archive, restore, export, delete, and forget transitions to Agentgres operations, wallet authority, receipts, and restore/archive refs.",
);
assert(
  "hypervisor-physical-action-intent-admission",
  runtimePhysicalActionIntentAdmissionSource.includes(
    "ioi.runtime.physical_action_intent_admission.v1",
  ) &&
    runtimePhysicalActionIntentAdmissionSource.includes(
      "admitPhysicalActionIntent",
    ) &&
    runtimePhysicalActionIntentAdmissionSource.includes(
      "physical_action_generic_tool_call_blocked",
    ) &&
    runtimePhysicalActionIntentAdmissionSource.includes(
      "physical_action_emergency_stop_test_required",
    ) &&
    runtimePhysicalActionIntentAdmissionSource.includes(
      "physical_action_simulation_not_execution_receipt",
    ) &&
    runtimePhysicalActionIntentAdmissionSource.includes(
      "physical_action_human_supervision_authority_required",
    ) &&
    runtimePhysicalActionIntentAdmissionSource.includes(
      'runtimeTruthSource: "daemon-runtime"',
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/physical-action-intent-admissions",
    ) &&
    publicRuntimeRoutesSource.includes("admitPhysicalActionIntent") &&
    publicRuntimeRoutesTestSource.includes(
      "expose physical action intent admissions",
    ) &&
    publicRuntimeRoutesTestSource.includes(
      "blocks generic actuator tool calls",
    ) &&
    runtimePhysicalActionIntentAdmissionTestSource.includes(
      "admits physical action only through daemon-owned safety",
    ) &&
    runtimePhysicalActionIntentAdmissionTestSource.includes(
      "blocks actuator-affecting work routed as a generic tool call",
    ) &&
    runtimePhysicalActionIntentAdmissionTestSource.includes(
      "requires tested emergency stop and current sensor evidence",
    ) &&
    runtimePhysicalActionIntentAdmissionTestSource.includes(
      "does not admit simulation-only evidence as actuator execution",
    ),
  [
    "packages/runtime-daemon/src/runtime-physical-action-intent-admission.mjs",
    "packages/runtime-daemon/src/runtime-physical-action-intent-admission.test.mjs",
  ],
  "Physical-action admission must bind actuator-affecting work to safety envelopes, emergency stop, sensor evidence, wallet authority, Agentgres receipts, and daemon runtime truth instead of generic tool calls.",
);
assert(
  "hypervisor-worker-package-install-admission",
  runtimeWorkerPackageInstallAdmissionSource.includes(
    "ioi.runtime.worker_package_install_admission.v1",
  ) &&
    runtimeWorkerPackageInstallAdmissionSource.includes(
      "admitWorkerPackageInstall",
    ) &&
    runtimeWorkerPackageInstallAdmissionSource.includes(
      "worker_package_install_primitive_scope_masquerade_blocked",
    ) &&
    runtimeWorkerPackageInstallAdmissionSource.includes(
      "worker_package_install_vertical_runtime_fork_blocked",
    ) &&
    runtimeWorkerPackageInstallAdmissionSource.includes(
      "worker_package_install_ctee_policy_required",
    ) &&
    runtimeWorkerPackageInstallAdmissionSource.includes(
      "physical_action_policy_refs",
    ) &&
    runtimeWorkerPackageInstallAdmissionSource.includes(
      'runtimeTruthSource: "daemon-runtime"',
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/worker-package-install-admissions",
    ) &&
    publicRuntimeRoutesSource.includes("admitWorkerPackageInstall") &&
    publicRuntimeRoutesTestSource.includes(
      "expose worker package install admissions",
    ) &&
    publicRuntimeRoutesTestSource.includes(
      "blocks physical packages without safety refs",
    ) &&
    runtimeWorkerPackageInstallAdmissionTestSource.includes(
      "admits ontology-bound worker package installs",
    ) &&
    runtimeWorkerPackageInstallAdmissionTestSource.includes(
      "blocks prim capabilities masquerading as authority scopes",
    ) &&
    runtimeWorkerPackageInstallAdmissionTestSource.includes(
      "physical-action worker packages require safety policy refs",
    ) &&
    runtimeWorkerPackageInstallAdmissionTestSource.includes(
      "blocks vertical packs from becoming bespoke runtime forks",
    ),
  [
    "packages/runtime-daemon/src/runtime-worker-package-install-admission.mjs",
    "packages/runtime-daemon/src/runtime-worker-package-install-admission.test.mjs",
  ],
  "Worker package install admission must bind aiagent ontology refs, vertical packs, integration surfaces, prim/scope separation, cTEE policy, physical safety refs, wallet approval, Agentgres refs, and daemon runtime truth.",
);
assert(
  "hypervisor-new-session-model-route-compatibility",
  hypervisorHarnessAdapterModelSource.includes(
    "modelRouteSupportsHypervisorMountFromInventory",
  ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "ioi.hypervisor.model_mount_inventory_snapshot.v1",
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE",
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF",
    ) &&
    hypervisorHarnessAdapterModelSource.includes(
      "External harness adapters cannot mount or claim cTEE private workspace custody",
    ) &&
    hypervisorModelMountInventoryModelSource.includes(
      "/v1/model-mount/snapshot",
    ) &&
    hypervisorModelMountInventoryModelSource.includes(
      "normalizeHypervisorModelMountInventorySnapshot",
    ) &&
    hypervisorModelMountInventoryModelSource.includes(
      "loadHypervisorModelMountInventorySnapshot",
    ) &&
    hypervisorShellWindowSource.includes(
      "loadHypervisorModelMountInventorySnapshot",
    ) &&
    hypervisorShellWindowSource.includes(
      "modelMountInventory={modelMountInventory}",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "modelRouteSupportsHypervisorMountFromInventory",
    ) &&
    hypervisorNewSessionModalSource.includes("selectedPrivacy.ref") &&
    hypervisorNewSessionModalSource.includes("modelMountInventory") &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-model-route-inventory-state",
    ) &&
    hypervisorNewSessionModalSource.includes("launchBlockedByHarnessVerdict") &&
    hypervisorNewSessionModalSource.includes(
      "disabled={launchBlockedByHarnessVerdict}",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-harness-verdict",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "buildHypervisorNewSessionLaunchSummary",
    ) &&
    hypervisorNewSessionModalSource.includes("const launchSummary") &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-launch-summary",
    ) &&
    hypervisorShellNavigationSource.includes(
      "HypervisorNewSessionTargetBinding",
    ) &&
    hypervisorShellNavigationSource.includes(
      "ioi.hypervisor.new_session_target_binding.v1",
    ) &&
    hypervisorShellNavigationSource.includes("target_binding_ref") &&
    hypervisorShellNavigationSource.includes("session_route_ref") &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-target-binding",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-target-binding-ref",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-target-kind",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-target-session-route",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-workbench-adapter-ref",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-harness-selection-kind",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-launch-cockpit",
    ) &&
    hypervisorNewSessionModalSource.includes("data-new-session-recipe") &&
    hypervisorNewSessionModalSource.includes(
      "onClick={() => onLaunch(buildLaunchRequest(launchRecipe))}",
    ) &&
    hypervisorShellControllerSource.includes(
      "const summary = request.launch_summary",
    ) &&
    hypervisorShellControllerSource.includes("summary.harness_label") &&
    hypervisorShellControllerSource.includes(
      "summary.target_binding.session_route_ref",
    ) &&
    hypervisorShellControllerSource.includes(
      "summary.model_route_availability_state",
    ) &&
    hypervisorShellControllerSource.includes(
      "summary.workbench_adapter_ref",
    ) &&
    !hypervisorNewSessionModalSource.includes(
      'selectedModelRoute.ref === "model-route:hypervisor/default-local"',
    ) &&
    !hypervisorNewSessionModalSource.includes(
      'modelRouteRef !== "model-route:none"',
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/index.tsx",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx",
    "apps/hypervisor/src/windows/HypervisorShellWindow/useHypervisorShellController.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/modelMountInventoryModel.ts",
  ],
  "New Session must emit a typed launch summary, treat only verified Hypervisor model mounts as local model routes, and block harness launches that would otherwise silently fall back.",
);
assert(
  "hypervisor-app-shell-contract",
  packageJson.scripts["check:hypervisor-app-shell"] ===
    "node scripts/hypervisor-app-shell-contract.mjs" &&
    hypervisorAppShellContractSource.includes("ioi.hypervisor.app_shell_contract.v1") &&
    hypervisorAppShellContractSource.includes(
      '[data-home-dashboard-variant="ioi-reference-home"]',
    ) &&
    hypervisorAppShellContractSource.includes(
      "Sessions and workspaces",
    ) &&
    hypervisorAppShellContractSource.includes(
      '[data-home-start-session="true"]',
    ) &&
    hypervisorAppShellContractSource.includes(
      "[data-new-session-seed-intent]",
    ) &&
    hypervisorAppShellContractSource.includes(
      '[data-new-session-target-binding="ioi.hypervisor.new_session_target_binding.v1"]',
    ) &&
    hypervisorAppShellContractSource.includes(
      "[data-new-session-target-binding-ref]",
    ) &&
    hypervisorAppShellContractSource.includes(
      "[data-new-session-target-session-route]",
    ) &&
    hypervisorAppShellContractSource.includes(
      'label:has-text("Harness") select',
    ) &&
    hypervisorAppShellContractSource.includes(
      "agent-harness-adapter:codex_cli",
    ) &&
    hypervisorAppShellContractSource.includes(
      "privacy:ctee-private-workspace",
    ) &&
    hypervisorAppShellContractSource.includes(
      "privacy:redacted-projection",
    ) &&
    hypervisorAppShellContractSource.includes(
      '[data-window-surface="projects"]',
    ) &&
    hypervisorAppShellContractSource.includes(
      "Projects page leaked repository-console or runtime-truth copy",
    ) &&
    hypervisorAppShellContractSource.includes("?view=workbench") &&
    hypervisorAppShellContractSource.includes(
      '[data-workbench-adapter-hub="true"]',
    ) &&
    hypervisorAppShellContractSource.includes(
      '[data-workbench-adapter-target="cursor"]',
    ) &&
    hypervisorAppShellContractSource.includes("?view=agents") &&
    hypervisorAppShellContractSource.includes(
      "Agents surface leaked implementation-truth copy into the visible product surface.",
    ) &&
    hypervisorAppShellContractSource.includes("?view=receipts") &&
    hypervisorAppShellContractSource.includes(
      '[data-receipt-evidence-filter-controls="true"]',
    ) &&
    hypervisorAppShellContractSource.includes(
      "[data-receipt-evidence-filtered-count]",
    ) &&
    hypervisorAppShellContractSource.includes(
      "[data-receipt-evidence-review]",
    ) &&
    hypervisorAppShellContractSource.includes(
      "[data-receipt-evidence-detail]",
    ) &&
    hypervisorAppShellContractSource.includes(
      "receipts_filter_and_drill_in_rendered",
    ) &&
    hypervisorAppShellContractSource.includes(
      "apps/hypervisor/dist/index.html is missing",
    ),
  [
    "package.json",
    "scripts/hypervisor-app-shell-contract.mjs",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx",
  ],
  "Phase 0A.10 must include a built-shell contract covering IOI-reference Home, New Session harness/privacy gating, Projects, Workbench adapter hub, and Agents product-surface copy.",
);
assert(
  "hypervisor-shell-no-generic-surface-placeholders",
  !/PLACEHOLDER_SURFACE_COPY|HypervisorSurfacePlaceholder|isPlaceholderSurface|hypervisor-surface-placeholder/.test(
    `${hypervisorShellContentSource}\n${hypervisorShellBaseCssSource}`,
  ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/shell-base.css",
  ],
  "Hypervisor App surfaces must render explicit IOI-reference bodies instead of generic placeholder fallback screens.",
);
assert(
  "retired-autopilot-workflow-canvas-fixtures-absent",
  retiredAutopilotWorkflowCanvasFixtures.every((fixturePath) => !exists(fixturePath)),
  retiredAutopilotWorkflowCanvasFixtures,
  "Retired Autopilot workflow-canvas fixtures and agenda scripts must stay deleted; current workflow/compositor proof paths live under Hypervisor surfaces and daemon gates.",
);
assert(
  "hypervisor-harness-public-fixture-runs-contract",
  runtimeHarnessPublicFixtureRunSource.includes(
    "ioi.hypervisor.harness_public_fixture_run.v1",
  ) &&
    runtimeHarnessPublicFixtureRunSource.includes(
      "runHarnessPublicFixtureRun",
    ) &&
    runtimeHarnessPublicFixtureRunSource.includes(
      "executeContainerLane",
    ) &&
    runtimeHarnessPublicFixtureRunSource.includes("command_argv: commandArgv") &&
    runtimeHarnessPublicFixtureRunSource.includes(
      "harness-testbed:public-code-edit-fixture",
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/harness-public-fixture-runs",
    ) &&
    publicRuntimeRoutesSource.includes("runHarnessPublicFixtureRun") &&
    publicRuntimeRoutesTestSource.includes(
      "expose harness public fixture comparison under daemon gates",
    ) &&
    runtimeHarnessPublicFixtureRunTestSource.includes(
      "executes the same fixture through two installed adapters",
    ) &&
    runtimeHarnessPublicFixtureRunTestSource.includes(
      "command_argv.slice",
    ) &&
    runtimeHarnessPublicFixtureRunTestSource.includes(
      "preserves container lane private-mount guard",
    ),
  [
    "packages/runtime-daemon/src/runtime-harness-public-fixture-run.mjs",
    "packages/runtime-daemon/src/runtime-harness-public-fixture-run.test.mjs",
  ],
  "Harness public fixture runs must compare installed adapters against the same public fixture through daemon-gated container receipts.",
);
assert(
  "hypervisor-home-harness-comparison-preview",
  !hypervisorHomeSource.includes("HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE") &&
    !hypervisorHomeSource.includes("data-home-harness-comparison-run") &&
    !hypervisorHomeSource.includes("Harness comparison preview") &&
    hypervisorHomeCockpitModelSource.includes(
      "HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE",
    ) &&
    hypervisorHomeCockpitModelSource.includes("Harness comparison") &&
    hypervisorHomeCockpitModelSource.includes(
      "HYPERVISOR_HOME_COCKPIT_PROJECTION_PATH",
    ) &&
    hypervisorHomeCockpitModelSource.includes(
      "normalizeHypervisorHomeCockpitProjection",
    ) &&
    hypervisorHomeCockpitModelSource.includes(
      "ioi.hypervisor.home_cockpit_projection.v1",
    ) &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/home-cockpit") &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_home_cockpit",
    ) &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor home cockpit through lifecycle projection",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/home-cockpit") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_home_cockpit",
    ),
  [
    "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
    "apps/hypervisor/src/surfaces/Home/homeCockpitModel.ts",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Home should keep the visual application shell clean while the cockpit projection model retains receipt-backed harness comparison evidence through the runtime route with fixture fallback.",
);
assert(
  "hypervisor-session-operations-live-projection",
  hypervisorSessionOperationsModelSource.includes(
    "HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH",
  ) &&
    hypervisorSessionOperationsModelSource.includes(
      "normalizeHypervisorSessionOperationsProjection",
    ) &&
    hypervisorSessionOperationsModelSource.includes(
      "loadHypervisorSessionOperationsProjection",
    ) &&
    hypervisorSessionOperationsModelSource.includes(
      "ioi.hypervisor.session_operations_projection.v1",
    ) &&
    hypervisorShellContentSource.includes(
      "loadHypervisorSessionOperationsProjection",
    ) &&
    hypervisorShellContentSource.includes("data-session-operations-source") &&
    hypervisorSessionOperationsModelSource.includes("display_title") &&
    hypervisorSessionOperationsModelSource.includes("branch_label") &&
    hypervisorSessionOperationsModelSource.includes("environment_lifecycle_steps") &&
    hypervisorSessionOperationsModelSource.includes("changed_file_groups") &&
    hypervisorSessionOperationsModelSource.includes("activity_signals") &&
    hypervisorSessionOperationsModelSource.includes("access_log_leases") &&
    hypervisorSessionOperationsModelSource.includes("resource_health_state") &&
    hypervisorSessionOperationsModelSource.includes("Workspace control service") &&
    hypervisorShellContentSource.includes("projection.display_title") &&
    hypervisorShellContentSource.includes("projection.branch_label") &&
    hypervisorShellContentSource.includes("projection.environment_lifecycle_steps.map") &&
    hypervisorShellContentSource.includes("projection.changed_file_groups.map") &&
    hypervisorShellContentSource.includes("projection.activity_signals.map") &&
    hypervisorShellContentSource.includes("projection.access_log_leases.map") &&
    hypervisorShellContentSource.includes("projection.ports_services.map") &&
    hypervisorShellContentSource.includes("data-session-port-service") &&
    hypervisorShellContentSource.includes("data-session-activity-signal") &&
    hypervisorShellContentSource.includes("data-session-lease") &&
    hypervisorShellContentSource.includes("data-session-archive-ref") &&
    hypervisorShellContentSource.includes("data-session-restore-ref") &&
    hypervisorShellContentSource.includes("data-session-lifecycle-step") &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/session-operations") &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_session_operations",
    ) &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor session operations through lifecycle projection",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/session-operations") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_session_operations",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Sessions should hydrate title, branch, session rails, detail tabs, inspectors, lifecycle steps, changed files, leases, services, tasks, terminal events, and restore refs through daemon/public runtime routes.",
);
assert(
  "hypervisor-project-state-live-projection",
  hypervisorProjectStateModelSource.includes(
    "HYPERVISOR_PROJECT_STATE_PROJECTION_PATH",
  ) &&
    hypervisorProjectStateModelSource.includes(
      "normalizeHypervisorProjectStateProjection",
    ) &&
    hypervisorProjectStateModelSource.includes(
      "loadHypervisorProjectStateProjection",
    ) &&
    hypervisorProjectStateModelSource.includes(
      "ioi.hypervisor.project_state_projection.v1",
    ) &&
    hypervisorProjectStateModelSource.includes("agentgres_object_head_ref") &&
    hypervisorProjectStateModelSource.includes("state_root_ref") &&
    hypervisorShellContentSource.includes(
      "loadHypervisorProjectStateProjection",
    ) &&
    hypervisorShellContentSource.includes("data-project-state-source") &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/project-state") &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_project_state",
    ) &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor project state through lifecycle projection",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/project-state") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_project_state",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorProjectStateModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Projects should hydrate workspace refs, adapter preferences, Agentgres object heads, state roots, artifact refs, archive refs, restore refs, and receipts through the daemon/public runtime route with fixture fallback.",
);
assert(
  "hypervisor-automation-compositor-live-projection",
  hypervisorAutomationCompositorModelSource.includes(
    "HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH",
  ) &&
    hypervisorAutomationCompositorModelSource.includes(
      "normalizeHypervisorAutomationCompositorProjection",
    ) &&
    hypervisorAutomationCompositorModelSource.includes(
      "loadHypervisorAutomationCompositorProjection",
    ) &&
    hypervisorAutomationCompositorModelSource.includes(
      "ioi.hypervisor.automation_compositor_projection.v1",
    ) &&
    hypervisorAutomationCompositorModelSource.includes(
      "workflow_template_refs",
    ) &&
    hypervisorAutomationCompositorModelSource.includes("run_recipe_refs") &&
    hypervisorAutomationCompositorModelSource.includes("graph_refs") &&
    hypervisorAutomationCompositorModelSource.includes(
      "agentgres_operation_refs",
    ) &&
    hypervisorAutomationCompositorModelSource.includes("state_root_ref") &&
    hypervisorShellContentSource.includes(
      "HypervisorAutomationCompositorSurface",
    ) &&
    hypervisorShellContentSource.includes(
      "loadHypervisorAutomationCompositorProjection",
    ) &&
    hypervisorShellContentSource.includes(
      "data-automation-compositor-source",
    ) &&
    hypervisorShellContentSource.includes(
      "data-workflow-compositor-editor-boundary",
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/automation-compositor",
    ) &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_automation_compositor",
    ) &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor automation compositor through lifecycle projection",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/automation-compositor") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_automation_compositor",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAutomationCompositorModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Automations should hydrate workflow templates, run recipes, compositor graphs, action proposals, Agentgres operation refs, state roots, and receipts through the daemon/public runtime route with fixture fallback.",
);
assert(
  "hypervisor-agents-live-projection",
  hypervisorAgentsModelSource.includes("HYPERVISOR_AGENTS_PROJECTION_PATH") &&
    hypervisorAgentsModelSource.includes(
      "normalizeHypervisorAgentsProjection",
    ) &&
    hypervisorAgentsModelSource.includes("loadHypervisorAgentsProjection") &&
    hypervisorAgentsModelSource.includes(
      "ioi.hypervisor.agents_projection.v1",
    ) &&
    hypervisorAgentsModelSource.includes("Agent Wiki / ioi-memory") &&
    hypervisorAgentsModelSource.includes("wallet.network capability leases") &&
    hypervisorAgentsModelSource.includes("state_root_ref") &&
    hypervisorShellContentSource.includes("HypervisorAgentsSurface") &&
    hypervisorShellContentSource.includes("loadHypervisorAgentsProjection") &&
    hypervisorShellContentSource.includes("data-hypervisor-agents-source") &&
    hypervisorShellContentSource.includes(
      "data-agent-capability-management-boundary",
    ) &&
    hypervisorShellContentSource.includes("data-agent-harness-boundary") &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/agents") &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_agents",
    ) &&
    publicRuntimeRoutesSource.includes('projection_kind: "agents"') &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor agents through lifecycle projection",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/agents") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_agents",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAgentsModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Agents should hydrate configured runtime actors, skills, semantic memory, wallet capability leases, Agentgres refs, state roots, and receipts through the daemon/public runtime route; Capabilities remains a subordinate wallet-governed boundary.",
);
assert(
  "hypervisor-model-infrastructure-live-projection",
  hypervisorModelInfrastructureModelSource.includes(
    "HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH",
  ) &&
    hypervisorModelInfrastructureModelSource.includes(
      "normalizeHypervisorModelInfrastructureProjection",
    ) &&
    hypervisorModelInfrastructureModelSource.includes(
      "loadHypervisorModelInfrastructureProjection",
    ) &&
    hypervisorModelInfrastructureModelSource.includes(
      "buildHypervisorModelInfrastructureProjectionFromInventory",
    ) &&
    hypervisorModelInfrastructureModelSource.includes(
      "ioi.hypervisor.model_infrastructure_projection.v1",
    ) &&
    hypervisorModelInfrastructureModelSource.includes("model_route_refs") &&
    hypervisorModelInfrastructureModelSource.includes("endpoint_refs") &&
    hypervisorModelInfrastructureModelSource.includes(
      "loaded_instance_refs",
    ) &&
    hypervisorModelInfrastructureModelSource.includes(
      "model_weight_custody_policy_refs",
    ) &&
    hypervisorModelInfrastructureModelSource.includes("session_bindings") &&
    hypervisorModelInfrastructureModelSource.includes(
      "authority_scope_refs",
    ) &&
    hypervisorShellContentSource.includes(
      "HypervisorModelInfrastructureSurface",
    ) &&
    hypervisorShellContentSource.includes(
      "loadHypervisorModelInfrastructureProjection",
    ) &&
    hypervisorShellContentSource.includes(
      "data-model-infrastructure-source",
    ) &&
    hypervisorShellContentSource.includes(
      "data-model-mounting-ui-boundary",
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/model-infrastructure",
    ) &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_model_infrastructure",
    ) &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor model infrastructure through lifecycle projection",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/model-infrastructure") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_model_infrastructure",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorModelInfrastructureModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Models should hydrate model routes, provider endpoints, loaded instances, session bindings, custody policy refs, authority scopes, and receipts through the daemon/public runtime route with fixture fallback.",
);
assert(
  "hypervisor-provider-placement-live-projection",
  hypervisorProviderPlacementModelSource.includes(
    "HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH",
  ) &&
    hypervisorProviderPlacementModelSource.includes(
      "normalizeHypervisorProviderPlacementProjection",
    ) &&
    hypervisorProviderPlacementModelSource.includes(
      "loadHypervisorProviderPlacementProjection",
    ) &&
    hypervisorProviderPlacementModelSource.includes(
      "HYPERVISOR_PROVIDER_OPERATION_PROPOSAL_PATH",
    ) &&
    hypervisorProviderPlacementModelSource.includes(
      "HypervisorProviderOperationProposal",
    ) &&
    hypervisorProviderPlacementModelSource.includes(
      "proposeHypervisorProviderOperation",
    ) &&
    hypervisorProviderPlacementModelSource.includes("wallet_lease_ref") &&
    hypervisorProviderPlacementModelSource.includes(
      "agentgres_operation_ref",
    ) &&
    hypervisorProviderPlacementModelSource.includes(
      "ioi.hypervisor.provider_placement_projection.v1",
    ) &&
    hypervisorProviderPlacementModelSource.includes(
      "ioi.hypervisor.provider_operation_proposal.v1",
    ) &&
    hypervisorProviderPlacementModelSource.includes("ctee_split_required") &&
    hypervisorProviderPlacementModelSource.includes("encrypted_storage_only") &&
    hypervisorProviderPlacementModelSource.includes(
      "wallet.network authorizes",
    ) &&
    hypervisorShellContentSource.includes(
      "loadHypervisorProviderPlacementProjection",
    ) &&
    hypervisorShellContentSource.includes(
      "proposeHypervisorProviderOperation",
    ) &&
    hypervisorShellContentSource.includes("data-provider-placement-source") &&
    hypervisorShellContentSource.includes("data-provider-operation-kind") &&
    hypervisorShellContentSource.includes("data-provider-operation-proposal") &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/provider-placement") &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/provider-operations") &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_provider_placement",
    ) &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_operation.hypervisor_provider_operation_proposal",
    ) &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor provider placement through lifecycle projection",
    ) &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor provider operations through lifecycle admission proposal",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/provider-placement") &&
    daemonRuntimeApiDoc.includes("POST /v1/hypervisor/provider-operations") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_provider_placement",
    ) &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_operation.hypervisor_provider_operation_proposal",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorProviderPlacementModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Providers should hydrate direct provider placement candidates through the daemon/public runtime route while preserving wallet authority, Agentgres truth, and storage-backend boundaries.",
);
assert(
  "hypervisor-receipt-evidence-live-projection",
  hypervisorReceiptEvidenceModelSource.includes(
    "HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH",
  ) &&
    hypervisorReceiptEvidenceModelSource.includes(
      "normalizeHypervisorReceiptEvidenceProjection",
    ) &&
    hypervisorReceiptEvidenceModelSource.includes(
      "loadHypervisorReceiptEvidenceProjection",
    ) &&
    hypervisorReceiptEvidenceModelSource.includes(
      "ioi.hypervisor.receipt_evidence_projection.v1",
    ) &&
    hypervisorReceiptEvidenceModelSource.includes(
      "daemon-receipt-evidence-projection",
    ) &&
    hypervisorReceiptEvidenceModelSource.includes(
      "Agentgres admits operational truth",
    ) &&
    hypervisorShellContentSource.includes(
      "loadHypervisorReceiptEvidenceProjection",
    ) &&
    hypervisorShellContentSource.includes("data-receipt-evidence-source") &&
    hypervisorShellContentSource.includes("data-receipt-evidence-record") &&
    hypervisorShellContentSource.includes(
      "data-receipt-evidence-filter-controls",
    ) &&
    hypervisorShellContentSource.includes(
      "data-receipt-evidence-filtered-count",
    ) &&
    hypervisorShellContentSource.includes(
      "data-receipt-evidence-selected-ref",
    ) &&
    hypervisorShellContentSource.includes("data-receipt-evidence-detail") &&
    hypervisorShellContentSource.includes(
      "data-receipt-evidence-replay-ref",
    ) &&
    hypervisorShellContentSource.includes("data-receipt-evidence-review") &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/receipt-evidence") &&
    publicRuntimeRoutesSource.includes(
      "runtime.lifecycle_projection.hypervisor_receipt_evidence",
    ) &&
    publicRuntimeRoutesSource.includes("projectRuntimeLifecycle") &&
    publicRuntimeRoutesTestSource.includes(
      "dispatch Hypervisor receipt evidence through lifecycle projection",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/receipt-evidence") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_receipt_evidence",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorReceiptEvidenceModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Receipts should hydrate receipt evidence, Agentgres operation refs, artifacts, traces, state roots, and replay refs through the daemon/public runtime route with fixture fallback.",
);
assert(
  "contract-family-modules",
  [
    "adapters",
    "agentgres",
    "authority",
    "cognition",
    "envelope",
    "events",
    "policy",
    "quality",
    "tools",
    "trace",
  ].every((name) => exists(`crates/types/src/app/runtime/${name}.rs`)) &&
    read("crates/types/src/app/mod.rs").includes("pub mod runtime;"),
  ["crates/types/src/app/runtime", "crates/types/src/app/mod.rs"],
  "runtime contract families must have concern-oriented module paths",
);
assert(
  "step-ownership-map",
  exists("crates/services/src/agentic/runtime/service/README.md") &&
    read("crates/services/src/agentic/runtime/service/README.md").includes("decision_loop") &&
    read("crates/services/src/agentic/runtime/service/README.md").includes("tool_execution") &&
    read("crates/services/src/agentic/runtime/service/decision_loop/README.md").includes("guarded service lane"),
  [
    "crates/services/src/agentic/runtime/service/README.md",
    "crates/services/src/agentic/runtime/service/decision_loop/README.md",
  ],
  "runtime service must have explicit lane ownership boundaries",
);
assert(
  "step-physical-split",
  !exists("crates/services/src/agentic/runtime/service/step") &&
    runtimeServiceFiles.every((file) => !read(file).includes("service::step")),
  ["crates/services/src/agentic/runtime/service"],
  "runtime service implementation must be physically split into named lanes with no service::step imports",
);
assert(
  "builtin-tool-family-names",
  builtinFiles.every((file) => {
    const base = path.basename(file);
    return (
      base === "tests.rs" ||
      /^[a-z][a-z0-9_]*\.rs$/.test(base) &&
        !base.includes("deterministic_system_tools_are_available") &&
        !base.includes("tier_1_deterministic") &&
        !base.includes("only_expose_screen")
    );
  }),
  builtinFiles,
  "built-in production tool files must use tool-family names",
);
assert(
  "proofs-isolated",
  !exists(activeTauriSrc) &&
  !exists(activeTauriRuntimeService) &&
  !exists(activeTauriDesktopLauncher) &&
  !exists(rootIdeDir) &&
    !exists(retiredAgentIdePath) &&
    !exists(retiredAutopilotShellWindow) &&
    !exists(legacyTauriArchive),
  [
    activeTauriSrc,
    activeTauriRuntimeService,
    activeTauriDesktopLauncher,
    rootIdeDir,
    retiredAgentIdePath,
    retiredAutopilotShellWindow,
    legacyTauriArchive,
  ],
  "Active Tauri Rust/launchers, root ide/, packages/agent-ide, old AutopilotShellWindow, and legacy Tauri archive paths must stay retired from active app paths.",
);
assert(
  "hypervisor-app-launcher-names",
  Boolean(packageJson.scripts?.["dev:hypervisor-app"]) &&
    Boolean(packageJson.scripts?.["dev:hypervisor-app:wayland"]) &&
    retiredDesktopLaunchScripts.length === 0,
  ["package.json", retiredDesktopLaunchScripts],
  "Active launch/probe scripts must use Hypervisor App naming; retired dev/probe/dryrun:desktop script keys must not return.",
);
assert(
  "desktop-probes-no-retired-tauri-workspace",
  hypervisorDesktopProbeFiles.every(
    (file) => !read(file).includes("apps/hypervisor/src-tauri"),
  ),
  hypervisorDesktopProbeFiles,
  "Active Hypervisor desktop probes must use temporary/current workspaces, not the retired Tauri app path.",
);
assert(
  "desktop-probes-no-tauri-product-language",
  hypervisorDesktopProbeFiles.every(
    (file) => !/\bTauri\b|@tauri|tauri:\/\//.test(read(file)),
  ),
  hypervisorDesktopProbeFiles,
  "Active Hypervisor desktop probes must target Hypervisor/App/Web/Workbench adapter hosts, not describe a Tauri app.",
);
assert(
  "desktop-probes-no-ide-product-marker",
  hypervisorDesktopProbeFiles.every(
    (file) => !/\[Workspace IDE\]|Workspace IDE/.test(read(file)),
  ),
  hypervisorDesktopProbeFiles,
  "Active Hypervisor desktop probes must target Workbench adapter hosts, not the retired Workspace IDE marker.",
);
assert(
  "sdk-no-gui-harness-imports",
  !/apps\/autopilot|hypervisor-workbench|scripts\/lib|benchmarks/.test(sdkSubstrate + sdkIndex),
  ["packages/agent-sdk/src"],
  "SDK must not import GUI, harness, benchmark, or script internals",
);
assert(
  "projection-adapter-names",
  exists("packages/hypervisor-workbench/src/runtime/runtime-projection-adapter.ts") &&
    !exists("packages/hypervisor-workbench/src/runtime/agent-execution-substrate.ts") &&
    !exists(`${activeTauriSrc}/runtime_projection.rs`) &&
    !exists(`${activeTauriSrc}/agent_runtime_substrate.rs`),
  [
    "packages/hypervisor-workbench/src/runtime/runtime-projection-adapter.ts",
    `${activeTauriSrc}/runtime_projection.rs`,
  ],
  "client projection adapters must not be named as canonical execution substrates, and Tauri Rust projection must stay retired",
);
assert(
  "workbench-projection-boundary",
  workbenchRuntimeFiles.every((file) => !read(file).includes("AgentgresRuntimeStateStore")) &&
    read("packages/hypervisor-workbench/src/runtime/workflow-composer-model.ts").includes("non-canonical"),
  ["packages/hypervisor-workbench/src/runtime"],
  "hypervisor-workbench runtime helpers must remain non-canonical projections",
);
assert(
  "capability-tiers",
  read("crates/types/src/app/runtime_contracts.rs").includes("primitive_capabilities: Vec<String>") &&
    read("crates/types/src/app/runtime_contracts.rs").includes("authority_scope_requirements: Vec<String>") &&
    read("crates/services/src/agentic/runtime/tools/contracts.rs").includes("authority_scopes_for") &&
    !read("crates/types/src/app/runtime_contracts.rs").includes("capability_lease_requirements"),
  ["crates/types/src/app/runtime_contracts.rs", "crates/services/src/agentic/runtime/tools/contracts.rs"],
  "primitive capabilities and authority scopes must stay separated",
);
assert(
  "action-schema-drift",
  actionSchema.actionKinds.every((kind) => generatedTs.includes(`"${kind}"`) && generatedRust.includes(`"${kind}"`)),
  [
    "internal-docs/implementation/runtime-action-schema.json",
    "packages/hypervisor-workbench/src/runtime/generated/action-schema.ts",
    "crates/types/src/app/generated/runtime_action_schema.rs",
  ],
  "generated action schema projections must match shared runtime-action-schema.json",
);
assert(
  "public-swarm-boundary",
  !read("crates/types/src/app/chat.rs").includes('alias = "swarm"') &&
    !read("crates/types/src/app/chat.rs").includes("MicroSwarm") &&
    read("docs/architecture/_meta/vocabulary.md").includes("adaptive_work_graph") &&
    activeRuntimeSwarmFiles.every((file) => !read(file).includes("SWARM:")) &&
    activeRuntimeSwarmFiles.every((file) => {
      const content = read(file);
      if (!/\bswarm\b|Swarm|swarm[A-Z_]/.test(content)) return true;
      return allowedSwarmCompatibilityFiles.has(file);
    }),
  ["crates/types/src/app/chat.rs", "apps/hypervisor/src", "crates/services/src/agentic/runtime"],
  "active public runtime vocabulary must use adaptive work graph terminology; retired SWARM: decoding must stay absent",
);
assert(
  "retired-ioi-swarm-product",
  !exists("ioi-swarm") &&
    !exists("docs/ioi-swarm-release.md") &&
    (!exists("pyrightconfig.json") || !read("pyrightconfig.json").includes("ioi-swarm")),
  ["ioi-swarm", "docs/ioi-swarm-release.md", "pyrightconfig.json"],
  "retired ioi-swarm product package and release surface must not return",
);
assert(
  "debt-ledger-closed",
  !exists("docs/evidence/runtime-layout-refactor/remaining-debt.md") ||
    read("docs/evidence/runtime-layout-refactor/remaining-debt.md").includes(
      "No remaining runtime-layout refactor debt",
    ),
  ["docs/evidence/runtime-layout-refactor/remaining-debt.md"],
  "runtime-layout debt ledger must be closed before claiming completion when generated evidence is present",
);

const evidenceDir = path.join(root, "docs/evidence/runtime-layout-refactor");
fs.mkdirSync(evidenceDir, { recursive: true });
const summary = {
  schemaVersion: "ioi.runtime-layout-refactor.check.v1",
  generatedAt: new Date().toISOString(),
  status: failures.length ? "failed" : "passed",
  report,
  failures,
};
fs.writeFileSync(path.join(evidenceDir, "guardrail-report.json"), `${JSON.stringify(summary, null, 2)}\n`);

if (failures.length) {
  console.error("Runtime layout check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Runtime layout check passed.");
console.log(`Evidence: ${path.relative(root, path.join(evidenceDir, "guardrail-report.json"))}`);
