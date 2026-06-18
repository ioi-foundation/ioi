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
  report.push({
    id,
    status: condition ? "passed" : "failed",
    evidence,
    message,
  });
  if (!condition) failures.push(`${id}: ${message}`);
}

const packageJson = JSON.parse(read("package.json"));
const readme = read("README.md");
const hypervisorAppReadme = read("apps/hypervisor/README.md");
const developersDocs = read("apps/developers-ioi-ai/src/content/docs.tsx");
const refineArchitectureGuide = read(
  "internal-docs/implementation/refine-architecture.md",
);
const runtimePackageBoundaries = read(
  "internal-docs/implementation/runtime-package-boundaries.md",
);
const runtimeModuleMap = read(
  "internal-docs/implementation/runtime-module-map.md",
);
const hypervisorCoreClientsSurfacesDoc = read(
  "docs/architecture/components/hypervisor/core-clients-surfaces.md",
);
const retiredHypervisorFleetDoc =
  "docs/architecture/components/hypervisor/fleet.md";
const retiredAutopilotWorkflowCanvasFixtures = [
  "test.workflow",
  "scripts/lib/prompt-parser.ts",
  "scripts/custom-hypervisor-agenda.mjs",
];
const retiredDirectOpenVsCodeDesktopProbes = [
  "apps/hypervisor/scripts/desktop_chat_codebase_probe.py",
  "apps/hypervisor/scripts/desktop_workspace_probe.py",
  "apps/hypervisor/scripts/desktop_home_menu_bar_bridge_probe.py",
  "apps/hypervisor/scripts/desktop_openvscode_bridge_routing_probe.py",
  "apps/hypervisor/scripts/desktop_openvscode_direct_probe.py",
  "apps/hypervisor/scripts/desktop_openvscode_fullscreen_first_load_probe.py",
  "apps/hypervisor/scripts/desktop_openvscode_hot_lifecycle_probe.py",
  "apps/hypervisor/scripts/desktop_openvscode_onboarding_pass.py",
];
const retiredHomeOnboardingSurfacePaths = [
  "apps/hypervisor/scripts/desktop_home_onboarding_probe.py",
  "apps/hypervisor/scripts/desktop_home_zero_state_probe.py",
  "apps/hypervisor/scripts/home_onboarding_condition_matrix.ts",
  "apps/hypervisor/src/surfaces/Home/HomeWalkthroughDocument.tsx",
  "apps/hypervisor/src/surfaces/Home/homeOnboardingModel.ts",
];
const retiredDirectWorkspaceSurfacePaths = [
  "apps/hypervisor/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx",
  "apps/hypervisor/src/services/directWorkspaceWorkbenchHost.ts",
  "apps/hypervisor/src/services/directWorkspaceSessionHost.ts",
  "apps/hypervisor/src/services/openVsCodeWorkbenchHost.ts",
  "apps/hypervisor/src/services/openVsCodeWorkbenchSession.ts",
  "apps/hypervisor/src/services/workspaceDirectWebview.ts",
];
const hypervisorConformanceSource = read(
  "scripts/conformance/hypervisor-conformance.mjs",
);
const hypervisorProvidersEnvironmentsDoc = read(
  "docs/architecture/components/hypervisor/providers-and-environments.md",
);
const daemonRuntimeApiDoc = read(
  "docs/architecture/components/daemon-runtime/api.md",
);
const architectureSourceOfTruthMap = read(
  "docs/architecture/_meta/source-of-truth-map.md",
);
const architectureImplementationMatrix = read(
  "docs/architecture/_meta/implementation-matrix.md",
);
const architectureVocabulary = read("docs/architecture/_meta/vocabulary.md");
const codeEditorAdapterLauncher = read(
  "scripts/launch-hypervisor-code-editor-adapter-host.mjs",
);
const codeEditorAdapterHostPaths = read(
  "scripts/lib/hypervisor-code-editor-adapter-host-paths.mjs",
);
const codeEditorAdaptersReadme = read("code-editor-adapters/README.md");
const codeEditorAdapterHostManifest = read(
  "code-editor-adapters/code-editor-adapter-host.manifest.json",
);
const codeEditorAdapterPackage = read(
  "code-editor-adapters/ioi-code-editor-adapter/package.json",
);
const codeEditorAdapterExtension = read(
  "code-editor-adapters/ioi-code-editor-adapter/extension.js",
);
const codeEditorAdapterTransport = read(
  "code-editor-adapters/ioi-code-editor-adapter/transport/context-transport.js",
);
const codeEditorAdapterTransportClient = read(
  "code-editor-adapters/ioi-code-editor-adapter/transport/client.js",
);
const codeEditorAdapterPublisher = read(
  "code-editor-adapters/ioi-code-editor-adapter/editor-context/context-publisher.js",
);
const codeEditorAdapterContextSnapshot = read(
  "code-editor-adapters/ioi-code-editor-adapter/editor-context/context-snapshot.js",
);
const hypervisorDevStartIntentProbe = read(
  "apps/hypervisor/scripts/dev_start_intent_probe.py",
);
const rootGitignore = read(".gitignore");
const hypervisorInstallProductMetadataSource = read(
  "crates/services/src/agentic/runtime/resolver/software_install/product_metadata.rs",
);
const hypervisorRustProductFixtureSources = [
  "crates/services/src/agentic/runtime/service/decision_loop/cognition/final_reply_product_handoff.rs",
  "crates/services/src/agentic/runtime/service/decision_loop/cognition/tests_parts/root/final_reply_evidence.rs",
  "crates/services/src/agentic/runtime/execution/screen/semantics/tests.rs",
  "crates/services/src/agentic/runtime/execution/screen/tests.rs",
]
  .map(read)
  .join("\n");
const hypervisorShellNavigationSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts",
);
const codeEditorAdapterPreferencesSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/codeEditorAdapterPreferences.ts",
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
const hypervisorAgentsModelTestSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAgentsModel.test.ts",
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
const runtimeCodeEditorAdapterLaunchPlanAdmissionSource = read(
  "packages/runtime-daemon/src/runtime-code-editor-adapter-launch-plan-admission.mjs",
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
const runtimeHypervisorApprovedOperationAdmissionSource = read(
  "packages/runtime-daemon/src/runtime-hypervisor-approved-operation-admission.mjs",
);
const runtimeHypervisorApprovedOperationAdmissionTestSource = read(
  "packages/runtime-daemon/src/runtime-hypervisor-approved-operation-admission.test.mjs",
);
const runtimeHypervisorCoreTaxonomySource = read(
  "packages/runtime-daemon/src/runtime-hypervisor-core-taxonomy.mjs",
);
const runtimeHypervisorCoreTaxonomyTestSource = read(
  "packages/runtime-daemon/src/runtime-hypervisor-core-taxonomy.test.mjs",
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
  "apps/hypervisor/src/surfaces/Home/index.ts",
]
  .map(read)
  .join("\n");
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
const authorityCenterTestSource = read(
  "apps/hypervisor/src/surfaces/Policy/authorityCenter.test.ts",
);
const activeHypervisorFixtureSources = [
  "apps/hypervisor/src/windows/ChatShellWindow/components/artifactHubPrCommentsModel.test.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/utils/assistantTurnProcessModel.test.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/utils/turnWindows.test.ts",
  "packages/agent-sdk/test/computer-use.test.mjs",
  "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.test.ts",
]
  .map(read)
  .join("\n");
const workspaceSessionCopySources = [
  "apps/hypervisor/src/surfaces/Workspace/WorkspaceShell.tsx",
  "apps/hypervisor/src/services/workspaceSubstratePreviewHost.ts",
  "apps/hypervisor/src/services/hypervisorAppearance.ts",
]
  .map(read)
  .join("\n");
const agentModelMatrixScopeSources = [
  "scripts/run-agent-model-matrix.mjs",
  "scripts/lib/agent-model-matrix.mjs",
  "scripts/run-agent-model-matrix.test.mjs",
  "scripts/lib/agent-model-matrix.test.mjs",
  "apps/benchmarks/src/App.tsx",
  "apps/benchmarks/src/scorecardPreview.ts",
]
  .map(read)
  .join("\n");
const hypervisorVisibleSurfaceSources = [
  "apps/hypervisor/src/windows/ChatShellWindow/index.tsx",
  "apps/hypervisor/src/windows/ChatShellWindow/components/ArtifactHubTaskViews.tsx",
  "apps/hypervisor/src/windows/ChatShellWindow/components/views/ThoughtsView.tsx",
  "apps/hypervisor/src/surfaces/Models/ModelMountsSurfaceView.tsx",
  "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
  "packages/workspace-substrate/src/notebook.ts",
  "apps/hypervisor/src/surfaces/Capabilities/connectors/components/googleWorkspaceConnectorPanelConfig.ts",
  "apps/hypervisor/src/surfaces/Capabilities/connectors/components/GoogleWorkspaceConnectorPanelConnected.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/connectors/components/GoogleWorkspaceConnectorPanel.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/connectors/components/GoogleWorkspaceConnectorPanelBody.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/connectors/components/GoogleWorkspaceConnectorPanelOnboarding.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/connectors/components/GenericConnectorPanel.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/connectors/components/MailConnectorPanel.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/components/EngineDetailPane.tsx",
  "apps/hypervisor/src/surfaces/Settings/SettingsEnvironmentSection.tsx",
  "apps/hypervisor/src/surfaces/Settings/SettingsMaintenanceSection.tsx",
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowComposerModals.tsx",
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
  "packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts",
]
  .map(read)
  .join("\n");
const hypervisorClientNamespaceSources = [
  "apps/hypervisor/index.html",
  "apps/hypervisor/src/services/workspaceShellState.ts",
  "apps/hypervisor/src/services/chatLaunchState.ts",
  "apps/hypervisor/src/services/chatShellLaunchState.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/hooks/useChatVimMode.ts",
  "apps/hypervisor/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts",
  "apps/hypervisor/src/windows/HypervisorShellWindow/HypervisorShellWindow.css",
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorClientHeader.tsx",
  "packages/workspace-substrate/src/codeOss.ts",
  "packages/workspace-substrate/src/notebook.ts",
  "packages/workspace-substrate/src/types.ts",
  "packages/workspace-substrate/src/components/CodeOssEditor.tsx",
  "packages/workspace-substrate/src/components/WorkspaceEditorPane.tsx",
  "apps/hypervisor/src/surfaces/Capabilities/components/model.ts",
  "packages/hypervisor-workbench/src/runtime/workflow-scratch-blueprints.ts",
]
  .map(read)
  .join("\n");
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
]
  .map(read)
  .join("\n");
const hypervisorModelMountIdentitySources =
  [
    "packages/runtime-daemon/src/model-mounting/default-records.mjs",
    "packages/runtime-daemon/src/model-mounting/default-discovery.mjs",
    "packages/runtime-daemon/src/model-mounting.mjs",
    "apps/hypervisor/src/surfaces/Models/ModelMountsSurfaceView.tsx",
    "scripts/lib/model-mounting-daemon-contract.test.mjs",
    "scripts/validate-model-mounting-e2e.mjs",
    "scripts/live-model-mounting-gate.mjs",
    "packages/runtime-daemon/src/runtime-daemon-core-direct-invoker-service.test.mjs",
    "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
    "packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs",
    "packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs",
    "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
    "packages/runtime-daemon/src/model-mounting/model-mount-core.test.mjs",
    "packages/runtime-daemon/src/model-mounting/read-projection-direct.test.mjs",
  ]
    .map(read)
    .join("\n") +
  "\n" +
  allFiles(
    "crates/services/src/agentic/runtime/kernel/model_mount",
    (relativePath) => relativePath.endsWith(".rs"),
  )
    .map(read)
    .join("\n");
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
const retiredHypervisorHarnessValidationScripts = packageScriptNames.filter(
  (scriptName) => scriptName.startsWith("validate:hypervisor-app-harness"),
);
const hypervisorAppHarnessContractSource = read(
  "scripts/lib/hypervisor-app-harness-contract.mjs",
);
const daemonSource = read("packages/runtime-daemon/src/index.mjs");
const sdkSubstrate = read("packages/agent-sdk/src/substrate-client.ts");
const sdkIndex = read("packages/agent-sdk/src/index.ts");
const workbenchRuntimeFiles = allFiles(
  "packages/hypervisor-workbench/src/runtime",
  (file) => /\.(ts|tsx)$/.test(file),
);
const activeTauriSrc = "apps/hypervisor/src-tauri/src";
const activeTauriRuntimeService =
  "apps/hypervisor/src/services/TauriRuntime.ts";
const activeTauriDesktopLauncher = "apps/hypervisor/scripts/dev-desktop.sh";
const legacyTauriArchive = "internal-docs/legacy/autopilot-tauri-src";
const rootIdeDir = "ide";
const retiredAgentIdePath = "packages/agent-ide";
const retiredAutopilotShellWindow =
  "apps/hypervisor/src/windows/AutopilotShellWindow";
const builtinFiles = allFiles(
  "crates/services/src/agentic/runtime/tools/builtins",
  (file) => file.endsWith(".rs"),
);
const runtimeServiceFiles = allFiles(
  "crates/services/src/agentic/runtime/service",
  (file) => /\.(rs|md)$/.test(file),
);
const hypervisorDesktopProbeFiles = allFiles(
  "apps/hypervisor/scripts",
  (file) =>
    /^apps\/hypervisor\/scripts\/(?:desktop_.*_probe|dev_.*_probe)\.py$/.test(
      file,
    ),
);
const activeHypervisorEnvFiles = [
  "scripts/validate-model-mounting-closeout.mjs",
  "scripts/lib/hypervisor-app-harness-contract.mjs",
  "scripts/lib/hypervisor-app-harness-contract.test.mjs",
  "apps/hypervisor/scripts/dev_start_intent_probe.py",
  "apps/hypervisor/scripts/dev_reuse_session_probe.py",
  "apps/hypervisor/scripts/desktop_prompt_probe.py",
  "apps/hypervisor/scripts/dry-run-desktop.sh",
  "packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts",
  "crates/api/src/chat.rs",
  "crates/node/src/bin/ioi-local.rs",
  "crates/types/src/app/runtime_contracts.rs",
  "crates/types/src/app/harness/activation.rs",
  "crates/types/src/app/harness/tests.rs",
  "crates/services/src/agentic/runtime/service/output/direct_inline.rs",
  "crates/services/src/agentic/runtime/service/tool_execution/processing/repair/core.rs",
  "crates/services/src/agentic/runtime/service/decision_loop/cognition/inference.rs",
  "crates/services/src/agentic/runtime/service/decision_loop/cognition/inference/tests.rs",
];
const activeHypervisorEnvSource = activeHypervisorEnvFiles.map(read).join("\n");
const activeRuntimeSwarmFiles = [
  ...allFiles("apps/hypervisor/src", (file) => /\.(ts|tsx|css)$/.test(file)),
  ...allFiles("crates/api/src", (file) => file.endsWith(".rs")),
  ...allFiles("crates/services/src/agentic/runtime", (file) =>
    file.endsWith(".rs"),
  ),
  "crates/types/src/app/chat.rs",
].filter((file) => exists(file));
const allowedSwarmCompatibilityFiles = new Set([
  "apps/hypervisor/src/types/work-graph-compat.ts",
  "crates/api/src/chat/types.rs",
  "crates/services/src/agentic/runtime/service/memory/context.rs",
  "crates/services/src/agentic/runtime/types.rs",
  "crates/types/src/app/chat.rs",
]);
const generatedTs = read(
  "packages/hypervisor-workbench/src/runtime/generated/action-schema.ts",
);
const generatedRust = read(
  "crates/types/src/app/generated/runtime_action_schema.rs",
);
const actionSchema = JSON.parse(
  read("internal-docs/implementation/runtime-action-schema.json"),
);

assert(
  "daemon-promoted",
  exists("packages/runtime-daemon/src/index.mjs") &&
    !exists("scripts/lib/local-runtime-daemon.mjs"),
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
    !packageJson.scripts["build:ioi-code-editor-adapter-composer"],
  ["package.json"],
  "root package scripts must expose focused Hypervisor checks and keep adapter-local composer builds retired",
);
assert(
  "compact-app-harness-contract",
  hypervisorAppHarnessContractSource.includes("hypervisorGuiHarnessContract") &&
    hypervisorAppHarnessContractSource.includes(
      "validateHypervisorGuiHarnessResult",
    ) &&
    hypervisorAppHarnessContractSource.includes(
      "buildBlockedHypervisorGuiHarnessResult",
    ) &&
    hypervisorAppHarnessContractSource.includes(
      "HYPERVISOR_RETAINED_QUERIES",
    ) &&
    hypervisorAppHarnessContractSource.includes("HYPERVISOR_LOCAL_GPU_DEV") &&
    !/autopilotGuiHarnessContract|validateAutopilotGuiHarnessResult|buildBlockedAutopilotGuiHarnessResult|AUTOPILOT_(?:GUI_HARNESS|REQUIRED|RETAINED|PROVIDER_GATED|READ_ONLY|LOCAL_GPU_DEV|HARNESS_DEFAULT_PROMOTION|WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT)/.test(
      hypervisorAppHarnessContractSource,
    ),
  ["scripts/lib/hypervisor-app-harness-contract.mjs"],
  "keep the compact app harness contract as the app-harness authority",
);
assert(
  "active-hypervisor-env-family-renamed",
  [
    "HYPERVISOR_LOCAL_GPU_DEV",
    "HYPERVISOR_RESET_DATA_ON_BOOT",
    "HYPERVISOR_DEV_START_INTENT",
    "HYPERVISOR_DATA_PROFILE",
    "HYPERVISOR_HARNESS_DEFAULT_PROMOTION",
    "HYPERVISOR_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT",
  ].every((token) => activeHypervisorEnvSource.includes(token)) &&
    !/AUTOPILOT_(?:LOCAL_GPU_DEV|RESET_DATA_ON_BOOT|DEV_START_|DATA_PROFILE|HARNESS_DEFAULT_PROMOTION|WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT|DESKTOP_CAPTURE_URL|DEV_CLEAN_INSTANCE)/.test(
      activeHypervisorEnvSource,
    ),
  activeHypervisorEnvFiles,
  "Active Hypervisor harness/dev environment names must use Hypervisor prefixes; retired AUTOPILOT_* env shims must not return.",
);
assert(
  "hypervisor-client-runtime-command-names",
  hypervisorClientRuntimeSource.includes(
    "runtime_open_hypervisor_intent_requested",
  ) &&
    hypervisorClientRuntimeSource.includes('invoke("reset_hypervisor_data")') &&
    !/runtime_open_autopilot_intent_requested|reset_autopilot_data/.test(
      hypervisorClientRuntimeSource,
    ),
  ["apps/hypervisor/src/services/HypervisorClientRuntime.ts"],
  "Hypervisor client runtime must emit Hypervisor-named host events and commands, not retired Autopilot bridge names.",
);
assert(
  "hypervisor-dev-start-probe-no-dual-product-log-prefix",
  hypervisorDevStartIntentProbe.includes("^\\[Hypervisor\\] Block #") &&
    hypervisorDevStartIntentProbe.includes("\\[Hypervisor\\]\\[ChatLaunch\\]") &&
    !/\(\?:Autopilot\|Hypervisor\)|\[Autopilot\]/.test(
      hypervisorDevStartIntentProbe,
    ),
  ["apps/hypervisor/scripts/dev_start_intent_probe.py"],
  "Active Hypervisor dev-start probes must not accept retired Autopilot log prefixes as a compatibility shim.",
);
assert(
  "code-editor-adapter-command-queue-retired",
  !exists("apps/hypervisor/src/services/workspaceEditorAdapterBridge.ts") &&
    !/ensure_code_editor_adapter_session|stop_code_editor_adapter_session|write_code_editor_adapter_bridge_state|enqueue_code_editor_adapter_bridge_command|take_code_editor_adapter_bridge_requests/.test(
      allFiles("apps/hypervisor/src", (relative) =>
        /\.(ts|tsx|js|jsx)$/.test(relative),
      )
        .map(read)
        .join("\n"),
    ),
  ["apps/hypervisor/src/services/workspaceEditorAdapterBridge.ts"],
  "Unused editor-adapter command queues must stay deleted; code editors provide context transport only and product controls live in Hypervisor Home/Sessions/Projects.",
);
assert(
  "chat-shell-hypervisor-route-names",
  companionShellNavigationSource.includes('window.location.assign("/home")') &&
    companionShellNavigationSource.includes('window.location.assign("/authority")') &&
    chatSessionHookSource.includes('await openChat("process")') &&
    !/openChatShellView\("autopilot"\)|openChat\("autopilot"\)/.test(
      `${companionShellNavigationSource}\n${chatSessionHookSource}`,
    ),
  [
    "apps/hypervisor/src/services/companionShellNavigation.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/hooks/useChatSession.ts",
  ],
  "Companion shell entry points must route Hypervisor shortcuts to canonical Hypervisor surfaces and block the retired autopilot view id.",
);
assert(
  "hypervisor-generated-contract-path",
  exists("apps/hypervisor/src/generated/hypervisor-contracts/index.ts") &&
    !exists("apps/hypervisor/src/generated/autopilot-contracts/index.ts") &&
    hypervisorTypeWrapperSources.includes(
      "../generated/hypervisor-contracts",
    ) &&
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
    runtimeModuleMap.includes("CodeEditorAdapterHost") &&
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
    runtimePackageBoundaries.includes(
      "sessions, leases, and restore/archive refs",
    ) &&
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
    !/internal-docs\/reverse-engineering\/ona|ONA-like/.test(
      refineArchitectureGuide,
    ),
  ["internal-docs/implementation/refine-architecture.md"],
  "refine-architecture Phase 0A must use the IOI reverse-engineering mirror as the primary UX target, not ONA-era wording.",
);
assert(
  "refine-architecture-hard-cut-editor-surface-drift",
  refineArchitectureGuide.includes("code-editor and workspace target choice") &&
    refineArchitectureGuide.includes("deleted onboarding walkthroughs") &&
    refineArchitectureGuide.includes("default code editor target"),
  ["internal-docs/implementation/refine-architecture.md"],
  "refine-architecture Phase 0A must describe code-editor adapters and deleted onboarding fat, not a direct editor product surface.",
);
assert(
  "hypervisor-shell-ioi-reference-contract",
  hypervisorShellNavigationSource.includes(
    "HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS",
  ) &&
    hypervisorShellNavigationSource.includes(
      'primaryReference: "internal-docs/reverse-engineering/ioi"',
    ) &&
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
    hypervisorShellNavigationSource.includes('"code_editor_adapter"') &&
    hypervisorShellNavigationSource.includes('"git_auth"') &&
    hypervisorShellNavigationSource.includes("Codex CLI") &&
    hypervisorShellNavigationSource.includes("Claude Code") &&
    hypervisorShellNavigationSource.includes("DeepSeek TUI") &&
    hypervisorActivityBarSource.includes(
      "HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS",
    ) &&
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
    readme.includes(
      "[`packages/hypervisor-workbench`](packages/hypervisor-workbench)",
    ) &&
    readme.includes("[`code-editor-adapters`](code-editor-adapters)") &&
    readme.includes("Hypervisor Workbench") &&
    !readme.includes("packages/agent-ide") &&
    !readme.includes("Hypervisor IDE"),
  ["README.md"],
  "README must present Hypervisor App/Web, Workbench, and adapter targets instead of retired Hypervisor IDE or packages/agent-ide language.",
);
assert(
  "active-product-copy-hypervisor-taxonomy",
  developersDocs.includes(
    "Hypervisor exists today as a native operator client over Hypervisor Core",
  ) &&
    developersDocs.includes(
      "'apps/hypervisor/src/windows/HypervisorShellWindow'",
    ) &&
    developersDocs.includes("routePath: '/hypervisor'") &&
    !developersDocs.includes(
      "Autopilot exists today as a local Tauri desktop product",
    ) &&
    !developersDocs.includes(
      "'apps/hypervisor/src/windows/AutopilotShellWindow'",
    ) &&
    !developersDocs.includes("daemon and Autopilot surfaces") &&
    !/configured-llama-cpp|IOI_DAEMON_ENDPOINT|IOI_DAEMON_TOKEN|IOI_MODEL_MOUNTING_API_URL/.test(
      codeEditorAdapterLauncher,
    ),
  [
    "apps/developers-ioi-ai/src/content/docs.tsx",
    "scripts/launch-hypervisor-code-editor-adapter-host.mjs",
  ],
  "Active product docs and model preload identifiers must use Hypervisor client/Workbench taxonomy, not Autopilot IDE or Tauri product language.",
);
assert(
  "install-resolver-current-product-hypervisor-named",
  hypervisorInstallProductMetadataSource.includes("IOI Hypervisor") &&
    hypervisorInstallProductMetadataSource.includes("ioi-hypervisor") &&
    hypervisorInstallProductMetadataSource.includes(
      "hypervisor,ioi hypervisor",
    ) &&
    !/IOI Autopilot|ioi-autopilot|autopilot,ioi autopilot/.test(
      hypervisorInstallProductMetadataSource,
    ),
  [
    "crates/services/src/agentic/runtime/resolver/software_install/product_metadata.rs",
  ],
  "Current-product install resolution must default to Hypervisor names and must not retain Autopilot aliases.",
);
assert(
  "rust-product-fixtures-hypervisor-named",
  hypervisorRustProductFixtureSources.includes("IOI Hypervisor") &&
    hypervisorRustProductFixtureSources.includes("Hypervisor Workbench") &&
    hypervisorRustProductFixtureSources.includes(
      "/tmp/hypervisor-workbench-",
    ) &&
    !/IOI Autopilot|autopilot_agent_studio|autopilot-agent-studio|\/tmp\/autopilot|\.tmp\/autopilot/.test(
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
  "code-editor-adapter-host-without-product-shell-patch",
  !exists("scripts/lib/hypervisor-workbench-shell-patch.mjs") &&
    !exists("scripts/lib/autopilot-workbench-shell-patch.mjs") &&
    !/applyHypervisorWorkbenchShellPatch|applyAutopilotWorkbenchShellPatch|IOI_WORKBENCH_NATIVE_SHELL|ioi-hypervisor-native-shell|ioi-hypervisor-workbench-quickinput|workbench-shell-patch|ioi\.quickInput/.test(
      codeEditorAdapterLauncher,
    ),
  [
    "scripts/lib/hypervisor-workbench-shell-patch.mjs",
    "scripts/lib/autopilot-workbench-shell-patch.mjs",
    "scripts/launch-hypervisor-code-editor-adapter-host.mjs",
  ],
  "Code editor adapter hosts must not patch editor chrome into a Hypervisor product shell; product UX stays in Hypervisor App/Web clients.",
);
assert(
  "code-editor-adapter-host-scope-stays-editor-only",
  hypervisorAppReadme.includes("code editor targets only") &&
    hypervisorAppReadme.includes(
      "context projection and daemon-admitted launch boundary",
    ) &&
    !/Code editor adapter hosts[\s\S]{0,220}(terminal|VM|hosted workspace)/.test(
      hypervisorAppReadme,
    ),
  ["apps/hypervisor/README.md"],
  "Code editor adapter host docs must stay limited to code-editor targets; terminal, VM, hosted workspace, and provider posture belong to sessions/environments.",
);
assert(
  "code-editor-adapter-extension-only",
  /"name":\s*"ioi-code-editor-adapter"/.test(codeEditorAdapterPackage) &&
    /"activationEvents":\s*\[\s*"onStartupFinished"\s*\]/.test(
      codeEditorAdapterPackage,
    ) &&
    !/"contributes"|ioi\.code\.open|viewsContainers|viewsWelcome|ioi\.hypervisor\.(home|studio|workflow|models|runs|policy|connectors)/.test(
      codeEditorAdapterPackage,
    ) &&
    codeEditorAdapterExtension.includes("createCodeEditorAdapterTransport") &&
    codeEditorAdapterExtension.includes("startCodeEditorContextPublisher") &&
    !/startBridgeCommandPolling|readDaemonModelSnapshot|createWorkbenchContextSnapshot|registerCommand|createStatusBarItem|createOutputChannel|code\.open|ioi\.code\.open/.test(
      codeEditorAdapterExtension,
    ) &&
    codeEditorAdapterTransport.includes("ioi.code_editor_adapter_request.v1") &&
    !/readBridgeState|readBridgeCommands|defaultBridgeState|commandRouteReceipt/.test(
      codeEditorAdapterTransport,
    ) &&
    codeEditorAdapterPublisher.includes("codeEditor.contextSnapshot") &&
    codeEditorAdapterPublisher.includes("codeEditor.inspectionTargetIndex") &&
    !/workbench\.contextSnapshot|workbench\.inspectionTargetIndex/.test(
      codeEditorAdapterPublisher,
    ) &&
    !/onDidOpenTerminal|onDidCloseTerminal|onDidStartTask|onDidEndTaskProcess/.test(
      codeEditorAdapterPublisher,
    ) &&
    codeEditorAdapterContextSnapshot.includes("activeEditorRef") &&
    codeEditorAdapterContextSnapshot.includes("buildCodeEditorScmState") &&
    codeEditorAdapterContextSnapshot.includes("diagnostics") &&
    !/taskState|terminalState|taskExecutions|terminals|activity\.(?:explorer|search|scm)|terminal\.panel|checks\.tasks|problems\.panel|surface:\s*"activity-rail"|surface:\s*"terminal"|surface:\s*"problems"|workbench\.action\.tasks|workbench\.action\.terminal|workbench\.actions\.view\.problems/.test(
      codeEditorAdapterContextSnapshot,
    ) &&
    !/daemonEndpoint|IOI_DAEMON_ENDPOINT|IOI_MODEL_MOUNTING_API_URL/.test(
      codeEditorAdapterTransportClient,
    ),
  [
    "code-editor-adapters/ioi-code-editor-adapter/package.json",
    "code-editor-adapters/ioi-code-editor-adapter/extension.js",
    "code-editor-adapters/ioi-code-editor-adapter/transport/context-transport.js",
    "code-editor-adapters/ioi-code-editor-adapter/editor-context/context-publisher.js",
    "code-editor-adapters/ioi-code-editor-adapter/editor-context/context-snapshot.js",
  ],
  "The editor-host extension must stay a code-editor adapter only; Hypervisor product routes, command queues, terminal/tasks/provider controls, and daemon model-mount state belong to the Hypervisor shell/daemon.",
);
assert(
  "code-editor-adapter-fork-sync-target-only",
  /code-editor-adapters\/vscode\/\n/.test(rootGitignore) &&
    /code-editor-adapters\/builds\/\n/.test(rootGitignore) &&
    /"adapterSource":\s*"code-editor-adapters\/ioi-code-editor-adapter"/.test(
      codeEditorAdapterHostManifest,
    ) &&
    /"optionalForRuntimeLaunch":\s*true/.test(codeEditorAdapterHostManifest) &&
    codeEditorAdaptersReadme.includes(
      "code-editor-adapters/ioi-code-editor-adapter",
    ) &&
    codeEditorAdaptersReadme.includes("target optional local VS Code source") &&
    /const extensionSource = resolve\(\s*repoRoot,\s*"code-editor-adapters\/ioi-code-editor-adapter",\s*\);/.test(
      codeEditorAdapterHostPaths,
    ) &&
    /const forkCodeEditorTarget = resolve\(forkRoot, "extensions\/ioi-code-editor-adapter"\);/.test(
      codeEditorAdapterHostPaths,
    ) &&
    /rmSync\(target\.path, \{ recursive: true, force: true \}\);\s*mkdirSync\(target\.path, \{ recursive: true \}\);\s*cpSync\(extensionSource, target\.path, \{ recursive: true, force: true \}\);/.test(
      codeEditorAdapterHostPaths,
    ) &&
    !/const extensionSource = resolve\([\s\S]*code-editor-adapters\/vscode/.test(
      codeEditorAdapterHostPaths,
    ),
  [
    ".gitignore",
    "code-editor-adapters/README.md",
    "code-editor-adapters/code-editor-adapter-host.manifest.json",
    "scripts/lib/hypervisor-code-editor-adapter-host-paths.mjs",
  ],
  "Ignored VS Code fork/build trees must stay sync targets copied from the canonical code editor adapter source, not duplicate tracked JS truth paths.",
);
assert(
  "home-prompt-shell-without-onboarding-fat",
  hypervisorHomeSource.includes(
    'data-home-dashboard-variant="ioi-reference-home"',
  ) &&
    hypervisorHomeSource.includes("What do you want to get done today?") &&
    hypervisorHomeSource.includes('data-home-start-session="true"') &&
    retiredHomeOnboardingSurfacePaths.every(
      (surfacePath) => !exists(surfacePath),
    ) &&
    !/AUTOPILOT_ONBOARDING|AutopilotOnboarding|autopilot\.home\.onboarding|autopilot\.onboarding|HYPERVISOR_ONBOARDING|HomeWalkthroughDocument|homeOnboardingModel|OpenVSCode|contained OpenVSCode/.test(
      hypervisorHomeSource,
    ),
  [
    "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
    "apps/hypervisor/src/surfaces/Home/index.ts",
    ...retiredHomeOnboardingSurfacePaths,
  ],
  "Hypervisor Home must be the IOI-reference prompt shell; retired onboarding/walkthrough source must stay deleted.",
);
assert(
  "active-visible-surfaces-hypervisor-named",
  !/\bAutopilot\b/.test(hypervisorVisibleSurfaceSources) &&
    !/Legacy environment credentials|Legacy model id|Legacy connector ref|Legacy tool ref|legacy local setup|No legacy upgrades|legacy-model-id/.test(
      hypervisorVisibleSurfaceSources,
    ) &&
    hypervisorVisibleSurfaceSources.includes("Hypervisor workspace") &&
    hypervisorVisibleSurfaceSources.includes(
      "Hypervisor native-local fixture",
    ) &&
    hypervisorVisibleSurfaceSources.includes("inside Hypervisor"),
  [
    "apps/hypervisor/src/windows/ChatShellWindow/index.tsx",
    "apps/hypervisor/src/windows/ChatShellWindow/components/ArtifactHubTaskViews.tsx",
    "apps/hypervisor/src/windows/ChatShellWindow/components/views/ThoughtsView.tsx",
    "apps/hypervisor/src/surfaces/Models/ModelMountsSurfaceView.tsx",
    "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
    "packages/workspace-substrate/src/notebook.ts",
    "apps/hypervisor/src/surfaces/Capabilities/connectors/components",
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
    activeHypervisorFixtureSources.includes(
      '"captureAppName"] = "Hypervisor"',
    ) &&
    activeHypervisorFixtureSources.includes('appName: "Hypervisor"') &&
    activeHypervisorFixtureSources.includes(
      "internal-docs/implementation/refine-architecture.md:50",
    ) &&
    !/Autopilot validation run|install autopilot|(?:appName|captureAppName)["'\]]*\s*[:=]\s*["']Autopilot|autopilot-chat-agent-ux/.test(
      activeHypervisorFixtureSources,
    ),
  [
    "apps/hypervisor/src/windows/ChatShellWindow/components/artifactHubPrCommentsModel.test.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/utils/assistantTurnProcessModel.test.ts",
    "apps/hypervisor/src/windows/ChatShellWindow/utils/turnWindows.test.ts",
    "packages/agent-sdk/test/computer-use.test.mjs",
    "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.test.ts",
  ],
  "Active chat/workflow fixture inputs must use Hypervisor labels unless they are explicit negative assertions.",
);
assert(
  "workspace-session-direct-code-editor-only",
  workspaceSessionCopySources.includes("useWorkspaceSession") &&
    workspaceSessionCopySources.includes("currentProject") &&
    workspaceSessionCopySources.includes("<WorkspaceHost") &&
    retiredDirectWorkspaceSurfacePaths.every(
      (surfacePath) => !exists(surfacePath),
    ) &&
    !workspaceSessionCopySources.includes("openvscode-direct"),
  [
    "apps/hypervisor/src/surfaces/Workspace/WorkspaceShell.tsx",
    "apps/hypervisor/src/services/workspaceSubstratePreviewHost.ts",
    "apps/hypervisor/src/services/hypervisorAppearance.ts",
    ...retiredDirectWorkspaceSurfacePaths,
  ],
  "Workspace must direct-mount the current project into the code-editor substrate.",
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
    "operator-command-center",
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
  "hypervisor-shell-responsive-styles-not-legacy-named",
  exists(
    "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/chat-responsive.css",
  ) &&
    !exists(
      "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/chat-legacy-and-responsive.css",
    ) &&
    hypervisorClientNamespaceSources.includes(
      '@import "./styles/hypervisor-shell/chat-responsive.css";',
    ) &&
    !hypervisorClientNamespaceSources.includes(
      "chat-legacy-and-responsive.css",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/HypervisorShellWindow.css",
    "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell",
  ],
  "Active Hypervisor shell responsive styles must not preserve legacy chat stylesheet naming.",
);
assert(
  "active-model-mount-identities-hypervisor-named",
  [
    "provider.hypervisor.local",
    "backend.hypervisor.native-local.fixture",
    "hypervisor.native_local.fixture",
    "endpoint.hypervisor.native-fixture",
    "hypervisor:native-fixture",
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
    "apps/hypervisor/src/surfaces/Models/ModelMountsSurfaceView.tsx",
    "scripts/lib/model-mounting-daemon-contract.test.mjs",
    "scripts/validate-model-mounting-e2e.mjs",
    "packages/runtime-daemon/src/model-mounting/*.test.mjs",
    "packages/runtime-daemon/src/runtime-daemon-core-direct-invoker-service.test.mjs",
  ],
  "Active native-local model mount providers, backends, endpoints, auth audiences, catalog fixtures, and stream evidence refs must use Hypervisor identities.",
);
assert(
  "code-editor-adapter-launch-plan-contract",
  hypervisorShellNavigationSource.includes("codeEditorAdapterPreferences.ts") &&
    codeEditorAdapterPreferencesSource.includes("CodeEditorAdapterLaunchPlan") &&
    codeEditorAdapterPreferencesSource.includes(
      "ioi.hypervisor.code_editor_adapter_launch_plan.v1",
    ) &&
    codeEditorAdapterPreferencesSource.includes(
      "buildCodeEditorAdapterLaunchPlan",
    ) &&
    codeEditorAdapterPreferencesSource.includes(
      "requestCodeEditorAdapterLaunchPlanAdmission",
    ) &&
    codeEditorAdapterPreferencesSource.includes(
      "HYPERVISOR_CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_PATH",
    ) &&
    codeEditorAdapterPreferencesSource.includes(
      "connection-contract:code-editor-adapter/desktop-context",
    ) &&
    codeEditorAdapterPreferencesSource.includes("executor_lane") &&
    codeEditorAdapterPreferencesSource.includes("control_action") &&
    codeEditorAdapterPreferencesSource.includes("control_channel_ref") &&
    codeEditorAdapterPreferencesSource.includes(
      "control-channel:code-editor-adapter/desktop-context",
    ) &&
    codeEditorAdapterPreferencesSource.includes(
      "connection-contract:code-editor-adapter/browser-editor",
    ) &&
    codeEditorAdapterPreferencesSource.includes("embedded_code_editor") &&
    codeEditorAdapterPreferencesSource.includes("embedded_code_editor_host") &&
    codeEditorAdapterPreferencesSource.includes("open_embedded_code_editor") &&
    !/embedded_workbench|embedded_workbench_host|open_embedded_workbench|workbench\.adapterPreferenceRef|packaged Workbench|Default Workbench target|Embedded Workbench/.test(
      codeEditorAdapterPreferencesSource,
    ) &&
    !/adapter_id:\s*"remote_vm"|adapter_id:\s*"hypervisor_node"|adapter_id:\s*"terminal_workspace"|adapter_id:\s*"browser_workspace"|adapter_id:\s*"devin"|attach_provider_workspace|attach_hypervisor_node|attach_terminal_session|provider_environment|hypervisor_node_session|terminal_session/.test(
      codeEditorAdapterPreferencesSource,
    ) &&
    codeEditorAdapterPreferencesSource.includes(
      'secret_release_policy: "no_durable_secret_release"',
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-code-editor-adapter-launch-plan-ref",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-code-editor-adapter-connection-contract-ref",
    ) &&
    hypervisorShellNavigationSource.includes("code_editor_adapter_admission") &&
    hypervisorShellNavigationSource.includes(
      "code_editor_adapter_executor_lane",
    ) &&
    hypervisorShellNavigationSource.includes(
      "code_editor_adapter_control_action",
    ) &&
    hypervisorShellNavigationSource.includes(
      "code_editor_adapter_control_channel_ref",
    ) &&
    hypervisorShellNavigationSource.includes("daemon_admitted") &&
    hypervisorShellNavigationSource.includes("daemon_blocked") &&
    hypervisorShellNavigationSource.includes("daemon_unavailable") &&
    hypervisorShellControllerSource.includes(
      "requestCodeEditorAdapterLaunchPlanAdmission",
    ) &&
    hypervisorShellControllerSource.includes(
      "buildHypervisorCodeEditorAdapterAdmissionFailure",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "ioi.runtime.code_editor_adapter_launch_plan_admission.v1",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "code_editor_adapter_launch_durable_secret_release_blocked",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "code_editor_adapter_runtime_truth_claim_blocked",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "browser_editor_url",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "browser_code_editor",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "embedded_code_editor_host",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "open_embedded_code_editor",
    ) &&
    !/embedded_workbench_host|open_embedded_workbench/.test(
      runtimeCodeEditorAdapterLaunchPlanAdmissionSource,
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "open_browser_editor",
    ) &&
    runtimeCodeEditorAdapterLaunchPlanAdmissionSource.includes(
      "code_editor_adapter_control_contract_mismatch",
    ) &&
    hypervisorShellContentSource.includes(
      "data-session-open-surface-enabled",
    ) &&
    hypervisorShellContentSource.includes(
      "data-session-open-surface-admission-state",
    ) &&
    publicRuntimeRoutesSource.includes(
      "/v1/hypervisor/code-editor-adapter-launch-plans",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/codeEditorAdapterPreferences.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/useHypervisorShellController.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx",
    "packages/runtime-daemon/src/runtime-code-editor-adapter-launch-plan-admission.mjs",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
  ],
  "code editor adapter preferences must compile into daemon-gated launch plans, call the public daemon admission route during New Session launch, preserve admission/block/offline state, and keep connection contracts, leases, receipts, and no durable secret release.",
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
    refineArchitectureGuide.includes(
      "create, create_from_project, start, stop, mark_active, archive,",
    ) &&
    refineArchitectureGuide.includes(
      "access/log lease state, SCM auth requirements, ports/services, tasks, terminal/logs",
    ) &&
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
    hypervisorCoreClientsSurfacesDoc.includes(
      "encrypted blobs are restore material, not restore truth",
    ) &&
    hypervisorProvidersEnvironmentsDoc.includes(
      "A blob can be necessary restore material without",
    ) &&
    daemonRuntimeApiDoc.includes(
      "Provider lifecycle state may be evidence, but it is not",
    ) &&
    architectureVocabulary.includes(
      "derived token material under a `HypervisorSessionAccessLease`",
    ) &&
    !exists(retiredHypervisorFleetDoc) &&
    (hypervisorProvidersEnvironmentsDoc.includes(
      "There is no separate Fleet product",
    ) ||
      hypervisorProvidersEnvironmentsDoc.includes(
        "They are not a separate product",
      )) &&
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
  ].every((adapterId) =>
    hypervisorHarnessAdapterModelSource.includes(adapterId),
  ) &&
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
    runtimeHarnessContainerLaneSource.includes(
      "planHarnessAdapterContainerLane",
    ) &&
    runtimeHarnessContainerLaneSource.includes(
      "buildHarnessContainerLaneReceipt",
    ) &&
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
    runtimeHarnessContainerExecutorSource.includes("resolveMountSourceRef") &&
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
    runtimeModelWeightCustodyAdmissionSource.includes(
      "remote_api_private_weight",
    ) &&
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
    publicRuntimeRoutesTestSource.includes("blocks payment-lapse deletion") &&
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
    hypervisorNewSessionModalSource.includes("data-new-session-target-kind") &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-target-session-route",
    ) &&
    hypervisorNewSessionModalSource.includes(
      "data-new-session-code-editor-adapter-ref",
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
    hypervisorShellControllerSource.includes("summary.code_editor_adapter_ref") &&
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
    hypervisorAppShellContractSource.includes(
      "ioi.hypervisor.app_shell_contract.v1",
    ) &&
    hypervisorAppShellContractSource.includes(
      '[data-home-dashboard-variant="ioi-reference-home"]',
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
    hypervisorAppShellContractSource.includes("privacy:redacted-projection") &&
    hypervisorAppShellContractSource.includes(
      '[data-window-surface="projects"]',
    ) &&
    hypervisorAppShellContractSource.includes("?view=workbench") &&
    hypervisorAppShellContractSource.includes(
      ".chat-workspace-oss-shell__workbench-surface",
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
  "Phase 0A.10 must include a built-shell contract covering IOI-reference Home, New Session harness/privacy gating, Projects, direct Workbench workspace session, and Agents product-surface copy.",
);
assert(
  "hypervisor-conformance-command-contract",
  packageJson.scripts["hypervisor-conformance"] ===
    "node scripts/conformance/hypervisor-conformance.mjs" &&
    packageJson.scripts["hypervisor-conformance:docs"] ===
      "node scripts/conformance/hypervisor-conformance.mjs docs" &&
    packageJson.scripts["hypervisor-conformance:abi"] ===
      "node scripts/conformance/hypervisor-conformance.mjs abi" &&
    packageJson.scripts["hypervisor-conformance:bridge"] ===
      "node scripts/conformance/hypervisor-conformance.mjs bridge" &&
    packageJson.scripts["hypervisor-conformance:receipts"] ===
      "node scripts/conformance/hypervisor-conformance.mjs receipts" &&
    packageJson.scripts["hypervisor-conformance:ctee"] ===
      "node scripts/conformance/hypervisor-conformance.mjs ctee" &&
    packageJson.scripts["hypervisor-conformance:app"] ===
      "node scripts/conformance/hypervisor-conformance.mjs app" &&
    packageJson.scripts["hypervisor-conformance:compositor"] ===
      "node scripts/conformance/hypervisor-conformance.mjs compositor" &&
    packageJson.scripts["hypervisor-conformance:negative"] ===
      "node scripts/conformance/hypervisor-conformance.mjs negative" &&
    packageJson.scripts["hypervisor-conformance:wallet"] ===
      "node scripts/conformance/hypervisor-conformance.mjs wallet" &&
    packageJson.scripts["hypervisor-conformance:candidates"] ===
      "node scripts/conformance/hypervisor-conformance.mjs candidates" &&
    hypervisorConformanceSource.includes("ioi.hypervisor.conformance_run.v1") &&
    hypervisorConformanceSource.includes("check:architecture-docs") &&
    hypervisorConformanceSource.includes("check:runtime-layout") &&
    hypervisorConformanceSource.includes(
      "check:hypervisor-code-editor-adapter-host-paths",
    ) &&
    hypervisorConformanceSource.includes("check:wallet-packaging") &&
    hypervisorConformanceSource.includes("check:candidate-evidence") &&
    hypervisorConformanceSource.includes("check:service-composition-evidence") &&
    hypervisorConformanceSource.includes("check:artifact-availability-incident") &&
    hypervisorConformanceSource.includes(
      "runtime-ctee-private-workspace-api.test.mjs",
    ) &&
    hypervisorConformanceSource.includes(
      "runtime-model-weight-custody-admission.test.mjs",
    ) &&
    hypervisorConformanceSource.includes(
      "runtime-harness-container-lane.test.mjs",
    ),
  [
    "package.json",
    "scripts/conformance/hypervisor-conformance.mjs",
  ],
  "The canon-named hypervisor-conformance command family must exist and delegate to the current docs, ABI, bridge, receipt, cTEE, app, compositor, wallet, candidate, and negative guards.",
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
  retiredAutopilotWorkflowCanvasFixtures.every(
    (fixturePath) => !exists(fixturePath),
  ),
  retiredAutopilotWorkflowCanvasFixtures,
  "Retired Autopilot workflow-canvas fixtures and agenda scripts must stay deleted; current workflow/compositor proof paths live under Hypervisor surfaces and daemon gates.",
);
assert(
  "retired-direct-openvscode-desktop-probes-absent",
  retiredDirectOpenVsCodeDesktopProbes.every((probePath) => !exists(probePath)),
  retiredDirectOpenVsCodeDesktopProbes,
  "Retired direct-OpenVSCode desktop probes must stay deleted; editor behavior is verified through Hypervisor code editor adapter preferences and shell contracts.",
);
assert(
  "retired-home-onboarding-surfaces-absent",
  retiredHomeOnboardingSurfacePaths.every(
    (surfacePath) => !exists(surfacePath),
  ),
  retiredHomeOnboardingSurfacePaths,
  "Retired Home onboarding walkthrough sources/probes must stay deleted; Home is the IOI-reference prompt shell.",
);
assert(
  "retired-direct-workspace-surfaces-absent",
  retiredDirectWorkspaceSurfacePaths.every(
    (surfacePath) => !exists(surfacePath),
  ),
  retiredDirectWorkspaceSurfacePaths,
  "Retired direct workspace webview hosts must stay deleted; Workbench resolves through the current project workspace session.",
);
assert(
  "hypervisor-harness-public-fixture-runs-contract",
  runtimeHarnessPublicFixtureRunSource.includes(
    "ioi.hypervisor.harness_public_fixture_run.v1",
  ) &&
    runtimeHarnessPublicFixtureRunSource.includes(
      "runHarnessPublicFixtureRun",
    ) &&
    runtimeHarnessPublicFixtureRunSource.includes("executeContainerLane") &&
    runtimeHarnessPublicFixtureRunSource.includes(
      "command_argv: commandArgv",
    ) &&
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
    runtimeHarnessPublicFixtureRunTestSource.includes("command_argv.slice") &&
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
    hypervisorSessionOperationsModelSource.includes(
      "environment_lifecycle_steps",
    ) &&
    hypervisorSessionOperationsModelSource.includes("changed_file_groups") &&
    hypervisorSessionOperationsModelSource.includes("activity_signals") &&
    hypervisorSessionOperationsModelSource.includes("access_log_leases") &&
    hypervisorSessionOperationsModelSource.includes("resource_health_state") &&
    hypervisorSessionOperationsModelSource.includes(
      "Workspace control service",
    ) &&
    hypervisorShellContentSource.includes("projection.display_title") &&
    hypervisorShellContentSource.includes("projection.branch_label") &&
    hypervisorShellContentSource.includes(
      "projection.environment_lifecycle_steps.map",
    ) &&
    hypervisorShellContentSource.includes(
      "projection.changed_file_groups.map",
    ) &&
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
  "hypervisor-approved-operation-admission",
  runtimeHypervisorApprovedOperationAdmissionSource.includes(
    "ioi.runtime.hypervisor_approved_operation_admission.v1",
  ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "admitHypervisorApprovedOperation",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "daemon-session-operation-proposal",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "daemon-provider-operation-proposal",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "hypervisor_approved_operation_proposal_source_not_admissible",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "wallet_approval_ref",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "wallet_lease_ref",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "agentgres_operation_refs",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      "state_root_ref",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionSource.includes(
      'runtimeTruthSource: "daemon-runtime"',
    ) &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/approved-operations") &&
    publicRuntimeRoutesSource.includes("admitHypervisorApprovedOperation") &&
    publicRuntimeRoutesTestSource.includes(
      "admit approved Hypervisor operations after wallet and Agentgres refs",
    ) &&
    publicRuntimeRoutesTestSource.includes(
      "reject fixture Hypervisor operation execution admission",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionTestSource.includes(
      "rejects fixture or unverified proposals",
    ) &&
    runtimeHypervisorApprovedOperationAdmissionTestSource.includes(
      "rejects approved operations without Agentgres operation, receipt, or state root",
    ) &&
    daemonRuntimeApiDoc.includes("POST /v1/hypervisor/approved-operations") &&
    daemonRuntimeApiDoc.includes(
      "ioi.runtime.hypervisor_approved_operation_admission.v1",
    ),
  [
    "packages/runtime-daemon/src/runtime-hypervisor-approved-operation-admission.mjs",
    "packages/runtime-daemon/src/runtime-hypervisor-approved-operation-admission.test.mjs",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Approved Hypervisor operation admission must only admit daemon-authored session/provider proposals after wallet approval, wallet lease, Agentgres operations, receipts, and state-root refs are bound.",
);
assert(
  "hypervisor-core-taxonomy-projection",
  runtimeHypervisorCoreTaxonomySource.includes(
    "ioi.runtime.hypervisor_core_taxonomy.v1",
  ) &&
    runtimeHypervisorCoreTaxonomySource.includes(
      "buildHypervisorCoreTaxonomy",
    ) &&
    runtimeHypervisorCoreTaxonomySource.includes("first_class_clients") &&
    runtimeHypervisorCoreTaxonomySource.includes("application_surfaces") &&
    runtimeHypervisorCoreTaxonomySource.includes("adapter_target_families") &&
    runtimeHypervisorCoreTaxonomySource.includes("agent_harness_adapters") &&
    runtimeHypervisorCoreTaxonomySource.includes("retired_surface_aliases") &&
    runtimeHypervisorCoreTaxonomySource.includes("fleet") &&
    runtimeHypervisorCoreTaxonomySource.includes("proposal_source_only") &&
    runtimeHypervisorCoreTaxonomySource.includes(
      'runtimeTruthSource: "daemon-runtime"',
    ) &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/core-taxonomy") &&
    publicRuntimeRoutesSource.includes("buildHypervisorCoreTaxonomy") &&
    publicRuntimeRoutesTestSource.includes("expose Hypervisor Core taxonomy") &&
    runtimeHypervisorCoreTaxonomyTestSource.includes(
      "classifies external harnesses as proposal-source adapters only",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/core-taxonomy") &&
    daemonRuntimeApiDoc.includes("ioi.runtime.hypervisor_core_taxonomy.v1"),
  [
    "packages/runtime-daemon/src/runtime-hypervisor-core-taxonomy.mjs",
    "packages/runtime-daemon/src/runtime-hypervisor-core-taxonomy.test.mjs",
    "packages/runtime-daemon/src/http/public-runtime-routes.mjs",
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Core taxonomy must be a daemon-visible projection that keeps clients, application surfaces, adapter targets, AgentHarnessAdapters, and retired Fleet posture distinct.",
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
      "HYPERVISOR_WORKER_PACKAGE_INSTALL_ADMISSION_PATH",
    ) &&
    hypervisorAgentsModelSource.includes(
      "normalizeHypervisorAgentsProjection",
    ) &&
    hypervisorAgentsModelSource.includes("loadHypervisorAgentsProjection") &&
    hypervisorAgentsModelSource.includes(
      "buildWorkerPackageInstallAdmissionRequest",
    ) &&
    hypervisorAgentsModelSource.includes(
      "requestWorkerPackageInstallAdmission",
    ) &&
    hypervisorAgentsModelSource.includes(
      "ioi.hypervisor.agents_projection.v1",
    ) &&
    hypervisorAgentsModelSource.includes("Agent Wiki / ioi-memory") &&
    hypervisorAgentsModelSource.includes("wallet.network capability leases") &&
    hypervisorAgentsModelSource.includes("state_root_ref") &&
    hypervisorShellContentSource.includes("HypervisorAgentsSurface") &&
    hypervisorShellContentSource.includes("loadHypervisorAgentsProjection") &&
    hypervisorShellContentSource.includes(
      "data-agent-worker-package-install-admission",
    ) &&
    hypervisorShellContentSource.includes("Admit package") &&
    hypervisorShellContentSource.includes(
      "requestWorkerPackageInstallAdmission",
    ) &&
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
    hypervisorAgentsModelTestSource.includes(
      "worker package install admission request preserves prim and scope boundaries",
    ) &&
    hypervisorAgentsModelTestSource.includes(
      "worker package install admission client posts to daemon route",
    ) &&
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/agents") &&
    daemonRuntimeApiDoc.includes(
      "runtime.lifecycle_projection.hypervisor_agents",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAgentsModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAgentsModel.test.ts",
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
    hypervisorModelInfrastructureModelSource.includes("loaded_instance_refs") &&
    hypervisorModelInfrastructureModelSource.includes(
      "model_weight_custody_policy_refs",
    ) &&
    hypervisorModelInfrastructureModelSource.includes("session_bindings") &&
    hypervisorModelInfrastructureModelSource.includes("authority_scope_refs") &&
    hypervisorShellContentSource.includes(
      "HypervisorModelInfrastructureSurface",
    ) &&
    hypervisorShellContentSource.includes(
      "loadHypervisorModelInfrastructureProjection",
    ) &&
    hypervisorShellContentSource.includes("data-model-infrastructure-source") &&
    hypervisorShellContentSource.includes("data-model-mounting-ui-boundary") &&
    publicRuntimeRoutesSource.includes("/v1/hypervisor/model-infrastructure") &&
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
    hypervisorShellContentSource.includes("data-receipt-evidence-replay-ref") &&
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
    read("crates/services/src/agentic/runtime/service/README.md").includes(
      "decision_loop",
    ) &&
    read("crates/services/src/agentic/runtime/service/README.md").includes(
      "tool_execution",
    ) &&
    read(
      "crates/services/src/agentic/runtime/service/decision_loop/README.md",
    ).includes("guarded service lane"),
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
      (/^[a-z][a-z0-9_]*\.rs$/.test(base) &&
        !base.includes("deterministic_system_tools_are_available") &&
        !base.includes("tier_1_deterministic") &&
        !base.includes("only_expose_screen"))
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
  packageJson.scripts?.["dev:hypervisor-app"] ===
    "npm run dev --workspace=@ioi/hypervisor-app" &&
    packageJson.scripts?.["dev:hypervisor-code-editor-adapter-host"] ===
      "node scripts/launch-hypervisor-code-editor-adapter-host.mjs" &&
    packageJson.scripts?.["dev:hypervisor-code-editor-adapter-host:wayland"] ===
      "node scripts/launch-hypervisor-code-editor-adapter-host.mjs --ozone-platform=wayland" &&
    packageJson.scripts?.["dryrun:hypervisor-code-editor-adapter-host"] ===
      "bash apps/hypervisor/scripts/dry-run-desktop.sh x11" &&
    packageJson.scripts?.["dryrun:hypervisor-code-editor-adapter-host:wayland"] ===
      "bash apps/hypervisor/scripts/dry-run-desktop.sh wayland" &&
    !packageJson.scripts?.["dev:hypervisor-app:wayland"] &&
    !packageJson.scripts?.["dryrun:hypervisor-app"] &&
    !packageJson.scripts?.["dryrun:hypervisor-app:wayland"] &&
    retiredDesktopLaunchScripts.length === 0,
  ["package.json", retiredDesktopLaunchScripts],
  "Active launch/probe scripts must keep Hypervisor App and code editor adapter-host commands separate; retired desktop/app aliases must not return.",
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
  "Active Hypervisor desktop probes must target Hypervisor/App/Web/Code editor adapter hosts, not describe a Tauri app.",
);
assert(
  "desktop-probes-no-ide-product-marker",
  hypervisorDesktopProbeFiles.every(
    (file) => !/\[Workspace IDE\]|Workspace IDE/.test(read(file)),
  ),
  hypervisorDesktopProbeFiles,
  "Active Hypervisor desktop probes must target Code editor adapter hosts, not the retired Workspace IDE marker.",
);
assert(
  "sdk-no-gui-harness-imports",
  !/apps\/autopilot|hypervisor-workbench|scripts\/lib|benchmarks/.test(
    sdkSubstrate + sdkIndex,
  ),
  ["packages/agent-sdk/src"],
  "SDK must not import GUI, harness, benchmark, or script internals",
);
assert(
  "projection-adapter-names",
  exists(
    "packages/hypervisor-workbench/src/runtime/runtime-projection-adapter.ts",
  ) &&
    !exists(
      "packages/hypervisor-workbench/src/runtime/agent-execution-substrate.ts",
    ) &&
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
  workbenchRuntimeFiles.every(
    (file) => !read(file).includes("AgentgresRuntimeStateStore"),
  ) &&
    read(
      "packages/hypervisor-workbench/src/runtime/workflow-composer-model.ts",
    ).includes("non-canonical"),
  ["packages/hypervisor-workbench/src/runtime"],
  "hypervisor-workbench runtime helpers must remain non-canonical projections",
);
assert(
  "capability-tiers",
  read("crates/types/src/app/runtime_contracts.rs").includes(
    "primitive_capabilities: Vec<String>",
  ) &&
    read("crates/types/src/app/runtime_contracts.rs").includes(
      "authority_scope_requirements: Vec<String>",
    ) &&
    read("crates/services/src/agentic/runtime/tools/contracts.rs").includes(
      "authority_scopes_for",
    ) &&
    !read("crates/types/src/app/runtime_contracts.rs").includes(
      "capability_lease_requirements",
    ),
  [
    "crates/types/src/app/runtime_contracts.rs",
    "crates/services/src/agentic/runtime/tools/contracts.rs",
  ],
  "primitive capabilities and authority scopes must stay separated",
);
assert(
  "action-schema-drift",
  actionSchema.actionKinds.every(
    (kind) =>
      generatedTs.includes(`"${kind}"`) && generatedRust.includes(`"${kind}"`),
  ),
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
    read("docs/architecture/_meta/vocabulary.md").includes(
      "adaptive_work_graph",
    ) &&
    activeRuntimeSwarmFiles.every((file) => !read(file).includes("SWARM:")) &&
    activeRuntimeSwarmFiles.every((file) => {
      const content = read(file);
      if (!/\bswarm\b|Swarm|swarm[A-Z_]/.test(content)) return true;
      return allowedSwarmCompatibilityFiles.has(file);
    }),
  [
    "crates/types/src/app/chat.rs",
    "apps/hypervisor/src",
    "crates/services/src/agentic/runtime",
  ],
  "active public runtime vocabulary must use adaptive work graph terminology; retired SWARM: decoding must stay absent",
);
assert(
  "retired-ioi-swarm-product",
  !exists("ioi-swarm") &&
    !exists("docs/ioi-swarm-release.md") &&
    (!exists("pyrightconfig.json") ||
      !read("pyrightconfig.json").includes("ioi-swarm")),
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
fs.writeFileSync(
  path.join(evidenceDir, "guardrail-report.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
);

if (failures.length) {
  console.error("Runtime layout check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Runtime layout check passed.");
console.log(
  `Evidence: ${path.relative(root, path.join(evidenceDir, "guardrail-report.json"))}`,
);
