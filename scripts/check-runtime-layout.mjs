#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const report = [];

function read(relativePath) {
  // Resilient: a removed file reads as empty rather than aborting the whole check.
  try {
    return fs.readFileSync(path.join(root, relativePath), "utf8");
  } catch {
    return "";
  }
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
  "code-editor-adapters/editor-targets.manifest.json",
);
const codeEditorAdapterPackage = read(
  "packages/hypervisor-adapter-targets/code-editors/vscode-extension/package.json",
);
const codeEditorAdapterPackageJson = JSON.parse(codeEditorAdapterPackage);
const codeEditorAdapterExtension = read(
  "packages/hypervisor-adapter-targets/code-editors/vscode-extension/extension.js",
);
const codeEditorAdapterTransport = read(
  "packages/hypervisor-adapter-targets/code-editors/vscode-extension/transport/context-transport.js",
);
const codeEditorAdapterPublisher = read(
  "packages/hypervisor-adapter-targets/code-editors/vscode-extension/editor-context/context-publisher.js",
);
const codeEditorAdapterContextSnapshot = read(
  "packages/hypervisor-adapter-targets/code-editors/vscode-extension/editor-context/context-snapshot.js",
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
  "apps/hypervisor/src/domain/harnessAdapterModel.ts",
);
const hypervisorModelMountInventoryModelSource = read(
  "apps/hypervisor/src/domain/modelMountInventoryModel.ts",
);
const hypervisorAutomationCompositorModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAutomationCompositorModel.ts",
);
const workflowComposerControllerSource = read(
  "packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
);
const workflowComposerSupportSource = read(
  "packages/hypervisor-workbench/src/WorkflowComposer/support.tsx",
);
const workflowComposerHarnessSource = `${workflowComposerControllerSource}\n${workflowComposerSupportSource}`;
const hypervisorAgentsModelSource = read(
  "apps/hypervisor/src/domain/hypervisorAgentsModel.ts",
);
const hypervisorAgentsModelTestSource = read(
  "apps/hypervisor/src/domain/hypervisorAgentsModel.test.ts",
);
const hypervisorModelInfrastructureModelSource = read(
  "apps/hypervisor/src/domain/hypervisorModelInfrastructureModel.ts",
);
const hypervisorModelInfrastructureModelTestSource = read(
  "apps/hypervisor/src/domain/hypervisorModelInfrastructureModel.test.ts",
);
const hypervisorPrivacyPostureModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorPrivacyPostureModel.ts",
);
const hypervisorReceiptEvidenceModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorReceiptEvidenceModel.ts",
);
const hypervisorReceiptEvidenceModelTestSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorReceiptEvidenceModel.test.ts",
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
const hypervisorTraceAndWelcomeCssSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/trace-and-welcome.css",
);
const hypervisorLeftSidebarShellSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorLeftSidebarShell.tsx",
);
const capabilitiesNavigationPaneSource = read(
  "apps/hypervisor/src/surfaces/Capabilities/components/CapabilitiesNavigationPane.tsx",
);
const capabilitiesCssSource = read(
  "apps/hypervisor/src/surfaces/Capabilities/Capabilities.css",
);
const hypervisorNewSessionModalSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx",
);
const hypervisorShellControllerSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/useHypervisorShellController.ts",
);
const hypervisorLaunchedSessionPersistenceSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorLaunchedSessionPersistence.ts",
);
const hypervisorAppShellContractSource = read(
  "scripts/hypervisor-app-shell-contract.mjs",
);
const hypervisorActivityBarSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRail.tsx",
);
const hypervisorActivityRailSource = hypervisorActivityBarSource;
const hypervisorActivityBarIconsSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRailIcons.tsx",
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
  "apps/hypervisor/src/domain/hypervisorSessionOperationsModel.ts",
);
const hypervisorProjectStateModelSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorProjectStateModel.ts",
);
const hypervisorProviderPlacementModelSource = read(
  "apps/hypervisor/src/domain/hypervisorProviderPlacementModel.ts",
);
const authorityCenterTestSource = read(
  "apps/hypervisor/src/surfaces/Policy/authorityCenter.test.ts",
);
const activeHypervisorFixtureSources = [
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
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowComposerModals.tsx",
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
  "packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts",
]
  .map(read)
  .join("\n");
const hypervisorSettingsSurfaceSources = [
  "apps/hypervisor/src/surfaces/Settings/SettingsView.tsx",
  "apps/hypervisor/src/surfaces/Settings/SettingsViewBody.tsx",
  "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/settings-and-panels.css",
]
  .map(read)
  .join("\n");
const hypervisorClientNamespaceSources = [
  "apps/hypervisor/index.html",
  "apps/hypervisor/src/services/workspaceShellState.ts",
  "apps/hypervisor/src/services/hypervisorLaunchState.ts",
  "apps/hypervisor/src/windows/HypervisorShellWindow/HypervisorShellWindow.css",
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRail.tsx",
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
const hypervisorTypeWrapperSources = [
  "apps/hypervisor/src/types/generated.ts",
  "apps/hypervisor/src/types/events.ts",
  "apps/hypervisor/src/types/artifacts.ts",
  "apps/hypervisor/src/types/notifications.ts",
  "apps/hypervisor/src/types/atlas.ts",
]
  .map(read)
  .join("\n");
// Model-mount identity is owned by the Rust substrate (the hypervisor daemon +
// the model-mount kernel) plus the app surface. The retired JS model-mount
// facade is no longer a source of truth, so it is not read here; the daemon
// carries a canonical identity manifest for the few literals that lived only in
// the JS path.
const hypervisorModelMountIdentitySources =
  [
    "apps/hypervisor/src/surfaces/Models/ModelMountsSurfaceView.tsx",
    "crates/node/src/bin/hypervisor-daemon.rs",
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
const sdkSubstrate = read("packages/agent-sdk/src/substrate-client.ts");
const sdkIndex = read("packages/agent-sdk/src/index.ts");
const workbenchRuntimeFiles = allFiles(
  "packages/hypervisor-workbench/src/runtime",
  (file) => /\.(ts|tsx)$/.test(file),
);
const activeTauriSrc = ["apps", "hypervisor", "src-" + "tauri", "src"].join("/");
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
  "packages/hypervisor-workbench/src/WorkflowComposer/support.tsx",
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
  read("docs/architecture/_meta/schemas/runtime-action-schema.json"),
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
  "workflow-composer-harness-globals-hypervisor-named",
  [
    "__HYPERVISOR_HARNESS_REPLAY_GATE_CLICK_RESULT",
    "__HYPERVISOR_HARNESS_ACTIVATION_DRY_RUN_CLICK_RESULT",
    "__HYPERVISOR_HARNESS_ACTIVATION_MINT_CLICK_RESULT",
    "__HYPERVISOR_HARNESS_ACTIVE_RUNTIME_ROLLBACK_DRY_RUN_RESULT",
    "__HYPERVISOR_HARNESS_ACTIVE_RUNTIME_ROLLBACK_APPLY_RESULT",
    "__HYPERVISOR_HARNESS_PROMOTION_LIVE_GUI_RESULT",
    "__HYPERVISOR_WORKFLOW_DOGFOOD_RESULT",
    "VITE_HYPERVISOR_WORKFLOW_DOGFOOD_SCRIPT",
    "VITE_HYPERVISOR_HARNESS_PROMOTION_LIVE_GUI",
  ].every((token) => workflowComposerHarnessSource.includes(token)) &&
    !/__AUTOPILOT_|VITE_AUTOPILOT_/.test(workflowComposerHarnessSource),
  [
    "packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/support.tsx",
  ],
  "Workflow Composer harness globals and env flags must use Hypervisor names, not retired Autopilot names.",
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
  "hypervisor-retired-client-header-absent",
  !exists(
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorClientHeader.tsx",
  ) &&
    !exists("apps/hypervisor/src/windows/shared/hostWindowDrag.ts") &&
    ![
      architectureImplementationMatrix,
      architectureSourceOfTruthMap,
      hypervisorCoreClientsSurfacesDoc,
    ]
      .join("\n")
      .includes(
        "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorClientHeader.tsx",
      ) &&
    ![
      architectureImplementationMatrix,
      architectureSourceOfTruthMap,
      hypervisorCoreClientsSurfacesDoc,
    ]
      .join("\n")
      .includes("apps/hypervisor/src/windows/shared/hostWindowDrag.ts") &&
    architectureImplementationMatrix.includes(
      "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRail.tsx",
    ) &&
    architectureImplementationMatrix.includes(
      "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorClientHeader.tsx",
    "apps/hypervisor/src/windows/shared/hostWindowDrag.ts",
    "docs/architecture/_meta/implementation-matrix.md",
    "docs/architecture/_meta/source-of-truth-map.md",
    "docs/architecture/components/hypervisor/core-clients-surfaces.md",
  ],
  "Hypervisor shell and secondary canon docs must not reintroduce a hidden client header or host drag helper above the IOI-reference left rail.",
);
assert(
  "hypervisor-dev-start-probe-no-dual-product-log-prefix",
  hypervisorDevStartIntentProbe.includes("^\\[Hypervisor\\] Block #") &&
    hypervisorDevStartIntentProbe.includes("\\[Hypervisor\\]\\[HypervisorLaunch\\]") &&
    !/\(\?:Autopilot\|Hypervisor\)|\[Autopilot\]/.test(
      hypervisorDevStartIntentProbe,
    ),
  ["apps/hypervisor/scripts/dev_start_intent_probe.py"],
  "Active Hypervisor dev-start probes must not accept retired Autopilot log prefixes as a compatibility shim.",
);
assert(
  "hypervisor-app-no-retired-chat-shell-window",
  !exists("apps/hypervisor/src/windows/ChatShellWindow") &&
    !exists("apps/hypervisor/src/services/chatShellNavigation.ts") &&
    !exists("apps/hypervisor/src/services/chatSessionNavigation.ts") &&
    !exists("apps/hypervisor/src/services/artifactHubNavigation.ts") &&
    !exists("apps/hypervisor/src/services/artifactNavigation.ts") &&
    !exists("apps/hypervisor/src/services/chatShellLaunchState.ts") &&
    !exists("apps/hypervisor/src/services/chatShellPendingLaunchNavigation.ts"),
  [
    "apps/hypervisor/src/windows/ChatShellWindow",
    "apps/hypervisor/src/services/chatShellNavigation.ts",
    "apps/hypervisor/src/services/chatSessionNavigation.ts",
    "apps/hypervisor/src/services/artifactHubNavigation.ts",
    "apps/hypervisor/src/services/artifactNavigation.ts",
    "apps/hypervisor/src/services/chatShellLaunchState.ts",
    "apps/hypervisor/src/services/chatShellPendingLaunchNavigation.ts",
  ],
  "Hypervisor App must not retain the retired alternate chat/artifact shell; Home, Sessions, Projects, Receipts, and Authority own those routes.",
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
  "tracked-runtime-boundary-map",
  architectureSourceOfTruthMap.includes("Hypervisor Core") &&
    architectureSourceOfTruthMap.includes("Hypervisor Daemon") &&
    architectureSourceOfTruthMap.includes("AdapterConnectionProfile") &&
    architectureSourceOfTruthMap.includes("adapter targets, not Hypervisor's product identity") &&
    architectureVocabulary.includes("HypervisorAdapterTarget") &&
    architectureVocabulary.includes("AdapterConnectionProfile"),
  [
    "docs/architecture/_meta/source-of-truth-map.md",
    "docs/architecture/_meta/vocabulary.md",
  ],
  "tracked canon must identify runtime/client boundaries and adapter targets without depending on ignored implementation maps",
);
assert(
  "hypervisor-canon-folds-fleet-into-provider-environment-views",
  architectureSourceOfTruthMap.includes("Hypervisor Providers / Environments") &&
    hypervisorProvidersEnvironmentsDoc.includes("cross-session environment inventory") &&
    hypervisorProvidersEnvironmentsDoc.includes("session access leases") &&
    hypervisorProvidersEnvironmentsDoc.includes("development environment recipes") &&
    hypervisorProvidersEnvironmentsDoc.includes("lifecycle observations") &&
    !/Foundry\s*\/\s*Fleet|Workbench,\s*Foundry,\s*Fleet|Foundry\/Fleet|Fleet names/.test(
      `${architectureSourceOfTruthMap}\n${hypervisorProvidersEnvironmentsDoc}`,
    ),
  [
    "docs/architecture/_meta/source-of-truth-map.md",
    "docs/architecture/components/hypervisor/providers-and-environments.md",
  ],
  "tracked canon must fold retired Fleet posture into Hypervisor provider/environment/session views",
);
assert(
  "ioi-reference-local-verifier-script",
  packageJson.scripts?.["check:ioi-reference"] ===
    "node internal-docs/reverse-engineering/ioi/verify.js",
  ["package.json"],
  "IOI reference verifier can remain a root local script, but tracked layout conformance must not read ignored local mirror guides.",
);
assert(
  "tracked-editor-surface-drift-guard",
  codeEditorAdaptersReadme.includes("not the Hypervisor product") &&
    codeEditorAdaptersReadme.includes("not runtime authority") &&
    hypervisorAppReadme.includes("Editor hosts = adapter targets") &&
    !readme.includes("Hypervisor IDE"),
  ["README.md", "apps/hypervisor/README.md", "code-editor-adapters/README.md"],
  "tracked docs must describe code-editor adapters as mediated targets, not direct editor product surfaces.",
);
assert(
  "hypervisor-reference-shell-no-auxiliary-chat-overlay",
  !exists(
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLeftUtilityPane.tsx",
  ) &&
    !exists(
      "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatUtilityDrawer.tsx",
    ) &&
    !exists(
      "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatBenchmarkTraceDeck.tsx",
    ) &&
    !/ChatLeftUtilityPane|ChatUtilityDrawer|ChatBenchmarkTraceDeck|controller\.chat\.paneVisible|const auxiliaryChatVisible|const utilityDrawerVisible|const conversationalSurfaceActive/.test(
      hypervisorShellContentSource,
    ) &&
    !/chat-left-utility-pane|chat-utility-drawer|is-chat-fullscreen|chat-trace-deck/.test(
      `${hypervisorShellBaseCssSource}\n${hypervisorTraceAndWelcomeCssSource}`,
    ) &&
    !/chat-utility-drawer|Toggle utility drawer/.test(
      read("apps/hypervisor/src/windows/shared/shellShortcuts.ts"),
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/shell-base.css",
    "apps/hypervisor/src/windows/HypervisorShellWindow/styles/hypervisor-shell/trace-and-welcome.css",
    "apps/hypervisor/src/windows/shared/shellShortcuts.ts",
  ],
  "Hypervisor reference shell must not keep the retired auxiliary chat overlay path.",
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
      "'apps/hypervisor/src/surfaces/Home/HypervisorReferenceShell.tsx'",
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
  codeEditorAdapterPackageJson.name === "hypervisor-vscode-extension" &&
    Array.isArray(codeEditorAdapterPackageJson.activationEvents) &&
    codeEditorAdapterPackageJson.activationEvents.length === 1 &&
    codeEditorAdapterPackageJson.activationEvents[0] === "onStartupFinished" &&
    !Object.hasOwn(codeEditorAdapterPackageJson, "contributes") &&
    codeEditorAdapterExtension.includes("createCodeEditorAdapterTransport") &&
    codeEditorAdapterExtension.includes("startCodeEditorContextPublisher") &&
    codeEditorAdapterTransport.includes("ioi.code_editor_adapter_request.v1") &&
    codeEditorAdapterPublisher.includes("codeEditor.contextSnapshot") &&
    codeEditorAdapterPublisher.includes("codeEditor.inspectionTargetIndex") &&
    codeEditorAdapterContextSnapshot.includes("activeEditorRef") &&
    codeEditorAdapterContextSnapshot.includes("buildCodeEditorScmState") &&
    codeEditorAdapterContextSnapshot.includes("diagnostics"),
  [
    "packages/hypervisor-adapter-targets/code-editors/vscode-extension/package.json",
    "packages/hypervisor-adapter-targets/code-editors/vscode-extension/extension.js",
    "packages/hypervisor-adapter-targets/code-editors/vscode-extension/transport/context-transport.js",
    "packages/hypervisor-adapter-targets/code-editors/vscode-extension/editor-context/context-publisher.js",
    "packages/hypervisor-adapter-targets/code-editors/vscode-extension/editor-context/context-snapshot.js",
  ],
  "The editor-host extension must stay a code-editor adapter only; Hypervisor product routes, terminal/tasks/provider controls, and daemon model-mount state belong to Hypervisor sessions and the daemon.",
);
assert(
  "code-editor-adapter-fork-sync-target-only",
  /code-editor-adapters\/vscode\/\n/.test(rootGitignore) &&
    /code-editor-adapters\/builds\/\n/.test(rootGitignore) &&
    /"defaultEditorId":\s*"vscode"/.test(codeEditorAdapterHostManifest) &&
    /"adapterModule":\s*"packages\/hypervisor-adapter-targets\/code-editors\/vscode-extension"/.test(
      codeEditorAdapterHostManifest,
    ) &&
    codeEditorAdapterHostManifest.includes('"jetbrains-gateway"') &&
    codeEditorAdapterHostManifest.includes('"vscode-browser"') &&
    /"optionalForRuntimeLaunch":\s*true/.test(codeEditorAdapterHostManifest) &&
    codeEditorAdaptersReadme.includes(
      "packages/hypervisor-adapter-targets/code-editors/vscode-extension",
    ) &&
    codeEditorAdaptersReadme.includes("target optional local VS Code source") &&
    /const extensionSource = resolve\(\s*repoRoot,\s*"packages\/hypervisor-adapter-targets\/code-editors\/vscode-extension",\s*\);/.test(
      codeEditorAdapterHostPaths,
    ) &&
    /const forkCodeEditorTarget = resolve\(forkRoot, "extensions\/hypervisor-vscode-extension"\);/.test(
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
    "code-editor-adapters/editor-targets.manifest.json",
    "scripts/lib/hypervisor-code-editor-adapter-host-paths.mjs",
  ],
  "Ignored VS Code fork/build trees must stay sync targets copied from the canonical code editor adapter source, not duplicate tracked JS truth paths.",
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
  "active-test-fixtures-hypervisor-named",
  activeHypervisorFixtureSources.includes('"captureAppName"] = "Hypervisor"') &&
    !/Autopilot validation run|install autopilot|(?:appName|captureAppName)["'\]]*\s*[:=]\s*["']Autopilot|autopilot-chat-agent-ux/.test(
      activeHypervisorFixtureSources,
    ),
  [
    "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.test.ts",
  ],
  "Active workflow fixture inputs must use Hypervisor labels unless they are explicit negative assertions.",
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
    "crates/node/src/bin/hypervisor-daemon.rs",
    "crates/services/src/agentic/runtime/kernel/model_mount",
    "apps/hypervisor/src/surfaces/Models/ModelMountsSurfaceView.tsx",
  ],
  "Active native-local model mount providers, backends, endpoints, auth audiences, catalog fixtures, and stream evidence refs must use Hypervisor identities (Rust substrate owned).",
);
assert(
  "hypervisor-environment-ops-model",
  hypervisorCoreClientsSurfacesDoc.includes("HypervisorEnvironmentOpsProfile") &&
    hypervisorCoreClientsSurfacesDoc.includes("HypervisorEnvironmentLifecycleState") &&
    hypervisorCoreClientsSurfacesDoc.includes("HypervisorEnvironmentClass") &&
    hypervisorCoreClientsSurfacesDoc.includes("HypervisorSessionAccessLease") &&
    hypervisorCoreClientsSurfacesDoc.includes("HypervisorEnvironmentService") &&
    hypervisorCoreClientsSurfacesDoc.includes("HypervisorEnvironmentTask") &&
    hypervisorCoreClientsSurfacesDoc.includes("HypervisorEnvironmentPort") &&
    hypervisorCoreClientsSurfacesDoc.includes("HypervisorScmAuthRequirement") &&
    hypervisorProvidersEnvironmentsDoc.includes("development environment recipes") &&
    hypervisorProvidersEnvironmentsDoc.includes("session access leases") &&
    hypervisorProvidersEnvironmentsDoc.includes("log access") &&
    hypervisorProvidersEnvironmentsDoc.includes("SCM auth requirements") &&
    !/\bGitpod\b|gitpod/i.test(
      `${hypervisorCoreClientsSurfacesDoc}\n${hypervisorProvidersEnvironmentsDoc}`,
    ),
  [
    "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    "docs/architecture/components/hypervisor/providers-and-environments.md",
  ],
  "Tracked canon must model environment lifecycle, access/log leases, SCM auth, services, tasks, ports, and restore refs as Hypervisor-native objects without vendor-specific references.",
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
  "hypervisor-private-workspace-mount-admission",
    daemonRuntimeApiDoc.includes(
      "POST /v1/hypervisor/private-workspace-mount-admissions",
    ) &&
    daemonRuntimeApiDoc.includes(
      "ioi.runtime.private_workspace_mount_admission.v1",
    ),
  [
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Private workspace mount admission must keep protected workspace plaintext out of provider-root custody by default, require cTEE/TEE/local/customer handles for private heads, and make unsafe plaintext mounts wallet-declassified and receipt-backed.",
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
    hypervisorConformanceSource.includes("check:artifact-availability-incident"),
  [
    "package.json",
    "scripts/conformance/hypervisor-conformance.mjs",
  ],
  "The canon-named hypervisor-conformance command family must exist and delegate to the current docs, ABI, bridge, receipt, app, compositor, wallet, candidate, and negative guards.",
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
  "hypervisor-approved-operation-admission",
    daemonRuntimeApiDoc.includes("POST /v1/hypervisor/approved-operations") &&
    daemonRuntimeApiDoc.includes(
      "ioi.runtime.hypervisor_approved_operation_admission.v1",
    ) &&
    daemonRuntimeApiDoc.includes(
      "ioi.runtime.hypervisor_approved_operation_execution_plan.v1",
    ),
  [
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Approved Hypervisor operation admission must only admit daemon-authored session/provider/project/automation proposals after wallet approval, wallet lease, Agentgres operations, receipts, and state-root refs are bound, then emit a daemon-owned execution plan awaiting a real executor.",
);
assert(
  "hypervisor-approved-operation-dispatch",
    daemonRuntimeApiDoc.includes(
      "POST /v1/hypervisor/approved-operation-dispatches",
    ) &&
    daemonRuntimeApiDoc.includes(
      "ioi.runtime.hypervisor_approved_operation_dispatch.v1",
    ) &&
    daemonRuntimeApiDoc.includes("awaiting_executor"),
  [
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Approved Hypervisor operation dispatch must consume daemon-owned execution plans through mounted executors only, mount the default daemon executor registry, fail closed without the mounted executor ref, and return execution receipts plus state-root refs instead of allowing client-local side effects.",
);
assert(
  "hypervisor-core-taxonomy-projection",
    daemonRuntimeApiDoc.includes("GET /v1/hypervisor/core-taxonomy") &&
    daemonRuntimeApiDoc.includes("ioi.runtime.hypervisor_core_taxonomy.v1"),
  [
    "docs/architecture/components/daemon-runtime/api.md",
  ],
  "Hypervisor Core taxonomy must be a daemon-visible projection that keeps clients, application surfaces, adapter targets, AgentHarnessAdapters, and retired Fleet posture distinct.",
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
    (file) =>
      !read(file).includes(
        ["apps", "hypervisor", "src-" + "tauri"].join("/"),
      ),
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
    "docs/architecture/_meta/schemas/runtime-action-schema.json",
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
