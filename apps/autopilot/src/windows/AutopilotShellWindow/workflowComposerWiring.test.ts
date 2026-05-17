import assert from "node:assert/strict";
import fs from "node:fs";

const activityBar = fs.readFileSync(
  new URL("./components/ChatLocalActivityBar.tsx", import.meta.url),
  "utf8",
);
const controller = fs.readFileSync(
  new URL("./useAutopilotShellController.ts", import.meta.url),
  "utf8",
);
const shellContent = fs.readFileSync(
  new URL("./components/AutopilotShellContent.tsx", import.meta.url),
  "utf8",
);
const engineDetailPane = fs.readFileSync(
  new URL(
    "../../surfaces/Capabilities/components/EngineDetailPane.tsx",
    import.meta.url,
  ),
  "utf8",
);
const localEngineSupport = fs.readFileSync(
  new URL(
    "../../../../../apps/autopilot/src-tauri/src/kernel/data/commands/local_engine_support.rs",
    import.meta.url,
  ),
  "utf8",
);
const workflowsView = fs.readFileSync(
  new URL(
    "../../surfaces/MissionControl/MissionControlWorkflowsView.tsx",
    import.meta.url,
  ),
  "utf8",
);
const composer = [
  "../../../../../packages/agent-ide/src/WorkflowComposer.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/content.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/support.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/controller.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/view.tsx",
]
  .map((path) => fs.readFileSync(new URL(path, import.meta.url), "utf8"))
  .join("\n");
const workflowBottomShelf = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowNodeConfigModal = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowNodeConfigModal.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowNodeConfigTypes = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowNodeConfigTypes.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowComposerModals = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowComposerModals.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowNodeBindingEditor = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowNodeBindingEditorSections = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowFunctionBindingEditor = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowFunctionBindingEditor.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowNodeDetailGrid = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowNodeDetailGrid.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowRailPanelDir = new URL(
  "../../../../../packages/agent-ide/src/features/Workflows/WorkflowRailPanel/",
  import.meta.url,
);
const workflowRailPanel = fs
  .readdirSync(workflowRailPanelDir, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".tsx"))
  .sort((left, right) => left.name.localeCompare(right.name))
  .map((entry) =>
    fs.readFileSync(new URL(entry.name, workflowRailPanelDir), "utf8"),
  )
  .join("\n");
const workflowRailRunsPanel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowRunCapabilityReceiptsProbe = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/workflow-run-capability-receipts-gui-probe.mjs",
    import.meta.url,
  ),
  "utf8",
);
const workflowRailReadinessPanel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowComposerTypes = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/WorkflowComposer/types.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowComposerCss = [
  "../../../../../packages/agent-ide/src/WorkflowComposer.css",
  "../../../../../packages/agent-ide/src/WorkflowComposer/styles/composer-shell.css",
  "../../../../../packages/agent-ide/src/WorkflowComposer/styles/composer-panels.css",
  "../../../../../packages/agent-ide/src/WorkflowComposer/styles/composer-modals.css",
]
  .map((path) => fs.readFileSync(new URL(path, import.meta.url), "utf8"))
  .join("\n");
const autopilotShellCss = fs.readFileSync(
  new URL("./styles/autopilot-shell/trace-and-welcome.css", import.meta.url),
  "utf8",
);
const autopilotShellBaseCss = fs.readFileSync(
  new URL("./styles/autopilot-shell/shell-base.css", import.meta.url),
  "utf8",
);
const chatIdeHeaderTsx = fs.readFileSync(
  new URL("./components/ChatIdeHeader.tsx", import.meta.url),
  "utf8",
);
const chatConversationSurfaceTsx = fs.readFileSync(
  new URL("../ChatShellWindow/components/ChatConversationSurface.tsx", import.meta.url),
  "utf8",
);
const tauriWindowDragTs = fs.readFileSync(
  new URL("../shared/tauriWindowDrag.ts", import.meta.url),
  "utf8",
);
const tauriDefaultCapabilityJson = fs.readFileSync(
  new URL("../../../src-tauri/capabilities/default.json", import.meta.url),
  "utf8",
);
const chatShellLayoutCss = fs.readFileSync(
  new URL("../ChatShellWindow/styles/Layout.css", import.meta.url),
  "utf8",
);
const chatShellOverridesCss = fs.readFileSync(
  new URL("../ChatShellWindow/styles/Overrides.css", import.meta.url),
  "utf8",
);
const chatArtifactWorkbenchCss = fs.readFileSync(
  new URL("../ChatShellWindow/styles/ChatSurface/artifact-workbench.css", import.meta.url),
  "utf8",
);
const autopilotMain = fs.readFileSync(
  new URL("../../main.tsx", import.meta.url),
  "utf8",
);
const workflowComposerUi = `${composer}\n${workflowComposerModals}\n${workflowNodeConfigModal}\n${workflowNodeBindingEditor}\n${workflowNodeBindingEditorSections}\n${workflowFunctionBindingEditor}\n${workflowNodeDetailGrid}\n${workflowRailPanel}\n${workflowRailRunsPanel}\n${workflowRailReadinessPanel}\n${workflowBottomShelf}`;
const templates = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/workflowTemplates.ts",
    import.meta.url,
  ),
  "utf8",
);
const harnessTools = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-harness-tools.ts",
    import.meta.url,
  ),
  "utf8",
);
const nodeRegistry = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-node-registry.ts",
    import.meta.url,
  ),
  "utf8",
);
const scratchBlueprints = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-scratch-blueprints.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowValidation = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-validation.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowRailModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-rail-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowSettingsModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-settings-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowEntrypointsModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-entrypoints-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowFileBundleModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-file-bundle-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowReadinessModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-readiness-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowRunHistoryModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-run-history-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowRunCapabilityReceipts = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-run-capability-receipts.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowModelInvocationTrace = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-model-invocation-trace.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowComposerModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-composer-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowBottomPanelModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-bottom-panel-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowSchema = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-schema.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowCodingRoutes = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-coding-routes.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowDefaults = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-defaults.ts",
    import.meta.url,
  ),
  "utf8",
);
const harnessWorkflow = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/harness-workflow/core.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowFixtureModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-fixture-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const graphTypes = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/types/graph.ts",
    import.meta.url,
  ),
  "utf8",
);
const graphRuntimeTypes = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/graph-runtime-types.ts",
    import.meta.url,
  ),
  "utf8",
);
const guiHarnessValidation = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/autopilot-gui-harness-validation/core.mjs",
    import.meta.url,
  ),
  "utf8",
);
const guiHarnessContract = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/autopilot-gui-harness-contract.mjs",
    import.meta.url,
  ),
  "utf8",
);
const workflowCapabilityCatalogBindingProbe = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/workflow-capability-catalog-binding-gui-probe.mjs",
    import.meta.url,
  ),
  "utf8",
);
const promotionTransitionGuiProbe = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/harness-promotion-transition-gui-probe.mjs",
    import.meta.url,
  ),
  "utf8",
);
const tauriRuntime = fs.readFileSync(
  new URL("../../services/TauriRuntime.ts", import.meta.url),
  "utf8",
);
const tauriLib = fs.readFileSync(
  new URL("../../../src-tauri/src/lib.rs", import.meta.url),
  "utf8",
);
const projectCommands = fs.readFileSync(
  new URL("../../../src-tauri/src/project/commands.rs", import.meta.url),
  "utf8",
);
const projectWorkflowPolicyLane = fs.readFileSync(
  new URL(
    "../../../src-tauri/src/project/workflow_run_policy_lane.rs",
    import.meta.url,
  ),
  "utf8",
);
const projectRuntime = [
  "../../../src-tauri/src/project/runtime.rs",
  "../../../src-tauri/src/project/workflow_coding_route_lane.rs",
]
  .map((path) => fs.readFileSync(new URL(path, import.meta.url), "utf8"))
  .join("\n");
const graphState = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/hooks/useGraphState.ts",
    import.meta.url,
  ),
  "utf8",
);
const executionSubstrate = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/runtime-projection-adapter.ts",
    import.meta.url,
  ),
  "utf8",
);
const canvasNode = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Editor/Canvas/Nodes/CanvasNode.tsx",
    import.meta.url,
  ),
  "utf8",
);
const canvasNodeCss = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Editor/Canvas/Nodes/CanvasNode.css",
    import.meta.url,
  ),
  "utf8",
);
const canvasEdge = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Editor/Canvas/Edges/CanvasEdge.tsx",
    import.meta.url,
  ),
  "utf8",
);
const canvasEdgeCss = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Editor/Canvas/Edges/CanvasEdge.css",
    import.meta.url,
  ),
  "utf8",
);
const graphExecution = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/hooks/useGraphExecution.ts",
    import.meta.url,
  ),
  "utf8",
);
const scratchProbe = fs.readFileSync(
  new URL(
    "../../../scripts/desktop_workflow_scratch_probe.py",
    import.meta.url,
  ),
  "utf8",
);
const usabilityProbe = fs.readFileSync(
  new URL(
    "../../../scripts/desktop_workflow_usability_probe.py",
    import.meta.url,
  ),
  "utf8",
);
const escapeRegExp = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

assert.match(
  activityBar,
  /id: "workspace"[\s\S]*id: "workflows"[\s\S]*id: "runs"/,
  "Workflows should sit after Workspace and before Runs in the activity bar",
);

assert.match(
  activityBar,
  /id: "workflows"[\s\S]*shortcut: chatNavigationShortcutLabel\(3\)/,
  "Workflows should receive the third numbered navigation shortcut",
);

assert.match(
  controller,
  /useState<WorkflowSurface>\("canvas"\)/,
  "Workflows should boot canvas-first",
);

assert.match(
  controller,
  /if \(view === "workflows"\) \{[\s\S]*setWorkflowSurface\("canvas"\);[\s\S]*\}/,
  "Opening Workflows from the shell should force the canvas surface",
);

assert.match(
  shellContent,
  /const workflowActive = activeView === "workflows";/,
  "The shell should treat Workflows as a dedicated workbench surface",
);

assert.match(
  shellContent,
  /!dedicatedWorkbenchActive[\s\S]*controller\.chat\.paneVisible/,
  "Workflows should suppress the auxiliary chat pane",
);

assert.match(
  `${shellContent}\n${autopilotShellCss}`,
  /is-dedicated-workbench[\s\S]*chat-content-main--dedicated-workbench[\s\S]*chat-content\.is-dedicated-workbench[\s\S]*height: 100%[\s\S]*chat-content-main--dedicated-workbench > \.mission-control-view--workflow-canvas[\s\S]*height: 100%/,
  "Dedicated workflow workbenches should stretch through the shell so the composer bottom shelf docks to the actual viewport bottom",
);

assert.match(
  autopilotMain,
  /applyAutopilotAppearance\(loadAutopilotAppearance\(\)\);/,
  "Autopilot should apply the saved appearance before the first shell render to avoid split light/dark startup surfaces",
);

assert.match(
  autopilotShellBaseCss,
  /workspace-repository-gate[\s\S]*--workspace-repo-bg: var\(--chat-bg\)[\s\S]*background: var\(--workspace-repo-bg\)[\s\S]*workspace-repository-gate__header[\s\S]*background: var\(--workspace-repo-header-bg\)/,
  "Repository selection should consume shell theme variables instead of pinning a permanent light workbench palette",
);

assert.match(
  chatShellLayoutCss,
  /spot-window\.spot-window--chat[\s\S]*justify-content: stretch[\s\S]*:root\[data-autopilot-theme\^="light"\] \.spot-window\.spot-window--chat[\s\S]*--spot-bg-primary: #ffffff/,
  "The fullscreen chat surface should only use light-specific tokens when the root appearance is light",
);

assert.match(
  chatShellLayoutCss,
  /spot-context-btn,\s*\n\.spot-input-selector\s*\{[\s\S]*background: var\(--spot-bg-tertiary\);[\s\S]*spot-context-btn:hover,[\s\S]*background: var\(--spot-bg-elevated\);/,
  "Chat input toolbar controls should use active theme tokens instead of hard-coded light pills",
);

assert.match(
  chatShellOverridesCss,
  /spot-container\.spot-container\.spot-container\s*\{\s*background: var\(--spot-bg-primary\) !important;/,
  "High-specificity chat shell overrides should still resolve through the active theme tokens",
);

assert.match(
  chatArtifactWorkbenchCss,
  /spot-window--chat \.spot-chat-shell\s*\{[\s\S]*background: var\(--spot-bg-primary\);[\s\S]*spot-window--chat \.spot-chat-sidebar-shell-item\s*\{[\s\S]*background: var\(--spot-bg-secondary\);[\s\S]*spot-workbench-chat-topbar[\s\S]*background: var\(--spot-bg-primary\);/,
  "Workbench-grade chat composition should use active theme tokens instead of hard-coded light surfaces",
);

assert.match(
  chatIdeHeaderTsx,
  /className="chat-ide-drag-surface"[\s\S]*data-tauri-drag-region[\s\S]*onMouseDown=\{startTauriWindowDrag\}/,
  "The frameless shell header should expose a broad native Tauri drag region outside the window-control buttons",
);

assert.match(
  autopilotShellBaseCss,
  /\.chat-ide-drag-surface\s*\{[\s\S]*flex: 1 1 auto;/,
  "The shell drag region should expand across available header space so users can move the frameless window",
);

assert.match(
  chatConversationSurfaceTsx,
  /className="spot-workbench-chat-drag-region"[\s\S]*data-tauri-drag-region[\s\S]*onMouseDown=\{startTauriWindowDrag\}/,
  "The chat workbench topbar should expose a native Tauri drag region without stealing toolbar button clicks",
);

assert.match(
  chatArtifactWorkbenchCss,
  /\.spot-workbench-chat-drag-region\s*\{[\s\S]*flex: 1 1 auto;/,
  "The chat workbench drag region should expand across available topbar space",
);

assert.match(
  tauriWindowDragTs,
  /setPosition\(new PhysicalPosition/,
  "The frameless drag helper should move the native Tauri window deterministically instead of relying on browser-only app-region CSS",
);

assert.match(
  tauriDefaultCapabilityJson,
  /"core:window:allow-set-position"/,
  "The Tauri chat window capability must allow deterministic manual movement for frameless drag lanes",
);

assert.match(
  shellContent,
  /const utilityDrawerVisible =[\s\S]*activeView !== "chat"[\s\S]*activeView !== "home"[\s\S]*!dedicatedWorkbenchActive[\s\S]*\{utilityDrawerVisible \? \(/,
  "Workflows should suppress the diagnostic utility drawer",
);

assert.match(
  workflowsView,
  /<WorkflowComposer[\s\S]*currentProject=\{currentProject\}[\s\S]*initialFile=\{composeSeedProject \?\? undefined\}/,
  "The Workflows canvas surface should render the dedicated workflow workbench",
);

assert.doesNotMatch(
  workflowsView,
  /<AgentEditor/,
  "The Workflows canvas should not fall back to the older generic AgentEditor scaffold",
);

assert.match(
  templates,
  /type: "model_call"/,
  "Workflow template graphs should serialize model nodes as model_call",
);

for (const [label, source] of [
  ["workflow node types", graphTypes],
  ["workflow node registry", nodeRegistry],
  ["workflow templates", templates],
  ["workflow composer", composer],
  ["workflow execution substrate", executionSubstrate],
] as const) {
  assert.doesNotMatch(
    source,
    /Artifact\/Output|artifact_output|ArtifactOutput|artifact_created|invalid_artifact_output_edge|type: "artifact"|case "artifact"/,
    `${label} should use output/renderer vocabulary instead of workflow artifact authority`,
  );
}

for (const outputType of [
  "WorkflowOutputBundle",
  "WorkflowMaterializedAsset",
  "WorkflowRendererRef",
  "WorkflowDeliveryTarget",
] as const) {
  assert.match(
    graphTypes,
    new RegExp(`interface ${outputType}`),
    `Workflow output typing should include ${outputType}`,
  );
}

assert.doesNotMatch(
  composer,
  /type: "model"[\s\S]*name:/,
  "Workflow seed graphs should not emit legacy model nodes",
);

assert.match(
  canvasNode,
  /source[\s\S]*function[\s\S]*model_binding[\s\S]*model_call[\s\S]*parser[\s\S]*adapter[\s\S]*plugin_tool[\s\S]*decision[\s\S]*human_gate[\s\S]*output[\s\S]*test_assertion/,
  "Every canonical workflow node family should be known to the canvas node renderer",
);

assert.match(
  canvasNodeCss,
  /\.canvas-node \{[\s\S]*width: 196px;[\s\S]*min-height: 86px;/,
  "Workflow nodes should keep stable fixed dimensions",
);

assert.match(
  composer,
  /rightRailCollapsed[\s\S]*rightRailWidth[\s\S]*leftDrawerOpen[\s\S]*canvasSearchOpen[\s\S]*canvasSearchQuery[\s\S]*workflow-composer-left-drawer/,
  "The workflow workbench should keep rail and drawer state local to the UI",
);

assert.match(
  workflowComposerUi,
  /handleAddNodeFromLibrary[\s\S]*handleConnectSelectedNodes[\s\S]*Blank canvas/,
  "GUI dogfood should support scratch workflow authoring without forcing templates",
);

assert.match(
  composer,
  /handleAddNodeFromLibrary[\s\S]*openConfig[\s\S]*handleNodeSelect\(nodeId\)[\s\S]*setBottomPanel\("selection"\)[\s\S]*setNodeConfigOpen\(true\)[\s\S]*data-testid=\{`workflow-component-\$\{itemId\}`\}[\s\S]*openConfig: true[\s\S]*closeDrawer: true/,
  "Scratch primitive creation should open node configuration immediately while preserving macro/test harness bulk creation paths",
);

assert.doesNotMatch(
  composer,
  /workflow-toolbar-add-source|workflow-toolbar-add-output/,
  "The canvas toolbar should not expose hard-coded Source/Output shortcuts outside the primitive picker",
);

assert.match(
  composer,
  /recentNodeTypes[\s\S]*setRecentNodeTypes[\s\S]*workflow-recent-primitives[\s\S]*workflow-recent-primitive-\$\{itemId\}/,
  "The primitive picker should keep a local recently-used section for scratch composition without adding templates",
);

assert.match(
  composer,
  /direction: "downstream"[\s\S]*direction: "attachment"[\s\S]*data-connection-direction/,
  "Compatible node creation should support downstream nodes and upstream attachment primitives",
);

assert.match(
  composer,
  /VITE_AUTOPILOT_WORKFLOW_DOGFOOD_SCRIPT[\s\S]*handleBuildRepoTestEngineerScratch[\s\S]*__AUTOPILOT_WORKFLOW_DOGFOOD_RESULT/,
  "The desktop dogfood probe should be able to trigger scratch-from-blank Repo Test Engineer authoring without template fixtures",
);

assert.match(
  `${composer}\n${workflowComposerCss}`,
  /lucide-react[\s\S]*WorkflowHeaderAction[\s\S]*workflow-action-tooltip[\s\S]*workflow-action-cluster[\s\S]*workflow-action-button:hover \.workflow-action-tooltip/,
  "Workflow header actions should use icon-first controls with readable hover/focus labels instead of a wall of text buttons",
);

assert.match(
  `${composer}\n${workflowComposerCss}`,
  /(?=[\s\S]*workflow-composer-banner)(?=[\s\S]*workflow-banner-configure-models)(?=[\s\S]*setModelBindingOpen\(true\))(?=[\s\S]*Configure models)(?=[\s\S]*\.workflow-composer-banner button)/,
  "Missing model-binding blockers should provide a direct action into model configuration",
);

assert.match(
  composer,
  /missingReasoningBinding = useMemo[\s\S]*nodeItem\.type !== "model_call"[\s\S]*hasInlineBinding[\s\S]*hasGlobalBinding[\s\S]*hasAttachedModelBinding[\s\S]*edge\.targetHandle === "model"[\s\S]*connectionClass === "model"/,
  "Model binding banners should not fire when model nodes already have explicit attached Model Binding primitives",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}\n${workflowRailReadinessPanel}\n${workflowBottomShelf}\n${workflowNodeDetailGrid}\n${workflowComposerModals}`,
  /(?=[\s\S]*WORKFLOW_ISSUE_TITLES)(?=[\s\S]*workflowIssueTitle)(?=[\s\S]*workflowIssueActionLabel)(?=[\s\S]*workflow-readiness-blocker-\$\{index\})(?=[\s\S]*onResolveIssue\(issue\))/,
  "Validation and readiness blockers should use product issue labels and resolve into an authoring action",
);

assert.match(
  composer,
  /const SCAFFOLD_GROUPS[\s\S]*"Start"[\s\S]*"Sources"[\s\S]*"Transform"[\s\S]*"AI"[\s\S]*"Tools"[\s\S]*"Connectors"[\s\S]*"Flow"[\s\S]*"State"[\s\S]*"Human"[\s\S]*"Outputs"/,
  "Canvas scaffold catalog groups should use professional primitive categories instead of scenario templates or internal type buckets",
);

assert.match(
  nodeRegistry,
  /type: "model_binding"[\s\S]*label: "Model Binding"[\s\S]*port\("model"[\s\S]*"model"\)/,
  "Model Binding should be a primitive node with a typed model attachment port",
);

assert.match(
  nodeRegistry,
  /type: "parser"[\s\S]*label: "Output Parser"[\s\S]*port\("parser"[\s\S]*"parser"\)/,
  "Output Parser should be a primitive node with a typed parser attachment port",
);

assert.match(
  scratchBlueprints,
  /scratch-model-binding[\s\S]*edge-model-binding-model[\s\S]*"model"[\s\S]*"model"[\s\S]*"model"/,
  "Scratch GUI dogfood should exercise model binding primitive attachment rather than only catalog presence",
);

assert.match(
  scratchBlueprints,
  /scratch-parser[\s\S]*edge-parser-model[\s\S]*"parser"[\s\S]*"parser"[\s\S]*"parser"/,
  "Scratch GUI dogfood should exercise parser primitive attachment rather than only catalog presence",
);

assert.match(
  scratchBlueprints,
  /edge-research-tool-attachment[\s\S]*"tool"[\s\S]*"tool"[\s\S]*"tool"[\s\S]*edge-state-memory-model[\s\S]*"memory"[\s\S]*"memory"[\s\S]*"memory"/,
  "Heavy scratch workflows should exercise tool and memory attachment ports, not only sequential data paths",
);

assert.match(
  scratchBlueprints,
  /bindingKind: "workflow_tool"[\s\S]*workflowTool:[\s\S]*workflowPath:[\s\S]*scratch-media-transform-agent\.workflow\.json[\s\S]*edge-workflow-tool-attachment[\s\S]*"tool"[\s\S]*"tool"[\s\S]*"tool"/,
  "Scratch subgraph orchestration should exercise workflow-as-tool attachment semantics",
);

for (const selector of [
  "workflow-model-binding-ref",
  "workflow-model-binding-result-schema",
  "workflow-parser-ref",
  "workflow-parser-kind",
  "workflow-parser-result-schema",
] as const) {
  assert.match(
    workflowComposerUi,
    new RegExp(`data-testid="${escapeRegExp(selector)}"`),
    `Parser node details should expose ${selector}`,
  );
}

assert.doesNotMatch(
  composer,
  /data-testid="workflow-build-repo-test-engineer"|data-testid="workflow-dogfood-button"|data-testid="workflow-toolbar-build-repo-test-engineer"/,
  "Dogfood and Repo Engineer automation must not be visible top-level product controls",
);

assert.doesNotMatch(
  composer,
  /SCAFFOLD_GROUPS[\s\S]*"AI Assist"|SCAFFOLD_GROUPS[\s\S]*"Edit"/,
  "The default canvas scaffold catalog should not render empty or debug-oriented groups",
);

assert.match(
  composer,
  /createWorkflowProject[\s\S]*saveWorkflowProject[\s\S]*saveWorkflowTests[\s\S]*validateWorkflowBundle[\s\S]*runWorkflowTests[\s\S]*runWorkflowProject[\s\S]*resumeWorkflowRun[\s\S]*exportWorkflowPackage/,
  "Scratch dogfood automation should exercise the typed workflow runtime APIs used by the GUI",
);

assert.match(
  scratchBlueprints,
  /buildRepoTestEngineerScratchWorkflow[\s\S]*scratch-source[\s\S]*scratch-function[\s\S]*scratch-model[\s\S]*scratch-gate[\s\S]*scratch-output/,
  "Scratch Repo Test Engineer authoring should stay in the dogfood blueprint module",
);

assert.doesNotMatch(
  nodeRegistry,
  /buildRepoTestEngineerScratchWorkflow|SCRATCH_WORKFLOW_BLUEPRINTS|Scratch-built JPG to SVG|scratch-media-transform-agent/,
  "The workflow node registry should remain primitive ontology, not dogfood blueprint storage",
);

assert.match(
  graphState,
  /workflowNodeDefaults[\s\S]*workflowNodeDefaultLogic[\s\S]*workflowNodeDefaultLaw/,
  "Canvas node creation should use the shared workflow node registry instead of local duplicated defaults",
);

assert.doesNotMatch(
  graphState,
  /function defaultMetricForType|function defaultLogicForType|function defaultLawForType/,
  "Workflow node defaults should not be duplicated in graph state hooks",
);

assert.match(
  scratchProbe,
  /VITE_AUTOPILOT_WORKFLOW_DOGFOOD_SCRIPT[\s\S]*scratch-heavy[\s\S]*wait_for_dogfood_sidecars/,
  "The desktop scratch probe should observe the scratch-heavy composer dogfood bridge instead of coordinate-authoring workflow JSON",
);

assert.doesNotMatch(
  scratchProbe,
  /CANVAS_NODE_STEPS|workflow-template-picker|Basic agent answer|createWorkflowFromTemplate/,
  "The scratch dogfood probe should not rely on templates or coordinate-click node creation",
);

assert.match(
  executionSubstrate,
  /AgentActionKind[\s\S]*source_input[\s\S]*model_binding[\s\S]*model_call[\s\S]*adapter_connector[\s\S]*plugin_tool[\s\S]*output/,
  "Workflow UI authoring should use shared action substrate vocabulary instead of node-local routing strings",
);

assert.match(
  executionSubstrate,
  /case "skill_context"[\s\S]*return "skill_context"/,
  "Skill Context nodes should be first-class workflow action kinds in the shared action substrate",
);

assert.match(
  graphTypes,
  /interface WorkflowSkillContextConfig[\s\S]*mode: "discover" \| "pinned"[\s\S]*goalSource\?: "workflow_goal" \| "node_input" \| "static"[\s\S]*pinnedSkills\?: WorkflowSkillContextPinnedSkill\[\]/,
  "Workflow schema should expose first-class skill context node config",
);

assert.match(
  nodeRegistry,
  /type: "skill_context"[\s\S]*token: "SK"[\s\S]*executorId: "workflow\.skill_context"[\s\S]*creatorId: "skill_context\.discover"[\s\S]*creatorId: "skill_context\.pinned"/,
  "Workflow node registry should expose discover and pinned Skill Context creator variants",
);

assert.match(
  workflowComposerUi,
  /data-testid="workflow-skill-context-mode"[\s\S]*data-testid="workflow-skill-context-pinned-skills"[\s\S]*data-testid="workflow-skill-context-include-markdown"/,
  "Workflow config UI should expose Skill Context mode, pinned lookup, and guidance controls",
);

assert.match(
  tauriRuntime,
  /listWorkflowSkillCatalog[\s\S]*getSkillCatalog\(\)[\s\S]*getSkillDetail\(skill\.skill_hash\)[\s\S]*workflowOptionsWithSkillCatalog/,
  "Workflow runtime should populate skill context from the runtime skill registry catalog/detail APIs",
);

assert.match(
  projectCommands,
  /WorkflowSkillResolver::from_options\(options\.as_ref\(\)\)[\s\S]*execute_workflow_project/,
  "Tauri workflow run commands should pass the runtime skill resolver into execution",
);

assert.match(
  projectRuntime,
  /struct WorkflowSkillResolver[\s\S]*resolve_skill_context[\s\S]*workflow\.skill-context\.v1[\s\S]*workflow\.skill_context\.discovery\.v1[\s\S]*workflow\.skill_context\.read\.v1/,
  "Workflow execution should emit receipt-backed skill context artifacts from a resolver abstraction",
);

assert.match(
  harnessTools,
  /"workflow\.catalog\.skills"[\s\S]*listWorkflowSkillCatalog[\s\S]*Workflow skill catalog loaded through runtime registry API/,
  "Workflow harness tools should expose the runtime skill catalog for scripted proof flows",
);

assert.match(
  graphTypes,
  /interface WorkflowCodingRouteContract[\s\S]*routeId: WorkflowCodingRouteId[\s\S]*phases: WorkflowCodingRoutePhaseId\[\][\s\S]*phaseDetails\?: WorkflowCodingRoutePhase\[\][\s\S]*gates: WorkflowCodingRouteGate\[\]/,
  "Workflow schema should expose typed coding route contracts and phase topology",
);

assert.match(
  graphTypes,
  /interface WorkflowCodingRouteGateResult[\s\S]*status: WorkflowCodingRouteGateStatus[\s\S]*blockingRequirements: string\[\][\s\S]*interface WorkflowCodingRouteBenchmarkResult[\s\S]*interface WorkflowCodingRoutePromotionDecision[\s\S]*interface WorkflowCodingRouteRunSummary/,
  "Workflow schema should expose typed gate, benchmark, promotion, and route run summary objects",
);

assert.match(
  workflowCodingRoutes,
  /(?=[\s\S]*WORKFLOW_CODING_ROUTE_CONTRACTS)(?=[\s\S]*coding\.template\.build)(?=[\s\S]*coding\.template\.debug)(?=[\s\S]*coding\.template\.review)(?=[\s\S]*coding\.route\.gate\.v1)(?=[\s\S]*coding\.route\.benchmark\.v1)(?=[\s\S]*coding\.route\.promotion\.v1)(?=[\s\S]*componentKind: "verifier")/,
  "Workflow route catalog should define build, debug, and review contracts with gate, benchmark, promotion, and phase evidence",
);

assert.match(
  templates,
  /coding\.template\.build[\s\S]*skill-context-route[\s\S]*edge-skill-context-model-context[\s\S]*coding\.template\.debug[\s\S]*coding\.template\.review/,
  "Workflow template catalog should expose build, debug, and review routes with explicit skill context edges",
);

assert.match(
  projectRuntime,
  /workflow_classify_coding_route[\s\S]*coding\.template\.review[\s\S]*coding\.template\.debug[\s\S]*coding\.template\.build[\s\S]*workflow_coding_route_evidence_from_run[\s\S]*workflow_coding_route_benchmark_results[\s\S]*workflow_coding_route_promotion_decisions[\s\S]*coding\.route\.promotion\.v1/,
  "Workflow runtime should classify coding routes and emit route, benchmark, and promotion evidence from execution",
);

assert.match(
  harnessTools,
  /"workflow\.catalog\.coding_routes"[\s\S]*listWorkflowCodingRoutes[\s\S]*"workflow\.skills\.import_pack"[\s\S]*importWorkflowSkillPack/,
  "Workflow harness tools should expose coding route contracts and thin Draft skill-pack import",
);

assert.match(
  tauriRuntime,
  /(?=[\s\S]*listWorkflowCodingRoutes)(?=[\s\S]*WORKFLOW_CODING_ROUTE_CONTRACTS)(?=[\s\S]*workflowDraftSkillsFromSources)(?=[\s\S]*importWorkflowSkillPack)(?=[\s\S]*addSkillSource)(?=[\s\S]*syncSkillSource)(?=[\s\S]*applyWorkflowPromotionDecisions)/,
  "Autopilot runtime should provide route catalog access, Draft skill-pack import, and promotion metadata updates through registry APIs",
);

assert.match(
  workflowBottomShelf,
  /data-testid="workflow-route-evidence"[\s\S]*routeRunSummary[\s\S]*workflow-route-promotion-summary[\s\S]*workflow-route-selected-skill[\s\S]*workflow-route-gate[\s\S]*workflow-route-promotion/,
  "Workflow run details should expose route preset, selected skills, gate status, promotion decisions, and evidence refs",
);

assert.match(
  executionSubstrate,
  /validateActionEdge[\s\S]*invalid_source_input_edge[\s\S]*invalid_output_edge/,
  "Workflow edge authoring should share substrate entry/terminal validation rules",
);

assert.match(
  graphTypes,
  /type WorkflowConnectionClass[\s\S]*"control"[\s\S]*"model"[\s\S]*"memory"[\s\S]*"tool"[\s\S]*"approval"[\s\S]*"delivery"[\s\S]*"subgraph"/,
  "Workflow schema should define production-grade typed connection categories",
);

assert.match(
  graphTypes,
  /interface WorkflowPortDefinition[\s\S]*connectionClass: WorkflowConnectionClass/,
  "Workflow ports should carry connection class authority",
);

assert.match(
  nodeRegistry,
  /port\([\s\S]*connectionClassForPort[\s\S]*portDefinitions[\s\S]*"model"[\s\S]*"tool"[\s\S]*"memory"/,
  "Node registry should define attachment ports for model, tool, and memory connections",
);

assert.match(
  executionSubstrate,
  /validateWorkflowConnection[\s\S]*invalid_connection_class[\s\S]*connectableNodeKinds/,
  "Runtime substrate should reject incompatible typed port connections",
);

assert.match(
  canvasNode,
  /data-connection-class=\{port\.connectionClass\}[\s\S]*port-\$\{port\.connectionClass\}/,
  "Canvas nodes should render typed attachment ports distinctly",
);

assert.match(
  `${canvasNode}\n${canvasNodeCss}`,
  /onRequestCompatibleNodes[\s\S]*workflow-port-add-compatible-\$\{nodeData\.id\}-\$\{port\.id\}[\s\S]*direction: "attachment"[\s\S]*direction: "downstream"[\s\S]*\.port-compatible-button/,
  "Canvas ports should expose port-level compatible-node creation for both attachments and downstream flow",
);

assert.match(
  canvasNodeCss,
  /canvas-node:hover \.port-compatible-button,[\s\S]*canvas-node\.selected \.port-compatible-button/,
  "Selecting a node should visibly expose port-local add-next affordances without requiring pixel-perfect hover",
);

assert.match(
  `${canvasEdge}\n${canvasEdgeCss}`,
  /(?=[\s\S]*sourceHandleId)(?=[\s\S]*targetHandleId)(?=[\s\S]*edgeSemanticLabel)(?=[\s\S]*SEMANTIC_HANDLE_LABELS\[semanticHandle\] \?\? null)(?=[\s\S]*edgeLabel \?)(?=[\s\S]*workflow-canvas-edge-label)(?=[\s\S]*canvas-edge-label-background)(?=[\s\S]*canvas-edge-label--model)(?=[\s\S]*canvas-edge-label--tool)(?=[\s\S]*canvas-edge-label--error)(?=[\s\S]*canvas-edge-label--retry)/,
  "Canvas edges should label meaningful typed lanes while suppressing default data/flow clutter",
);

assert.match(
  workflowComposerUi,
  /workflow-node-library-search[\s\S]*workflow-related-node-hints[\s\S]*visibleCompatibleNodeHints[\s\S]*workflow-compatible-port-path/,
  "Primitive creation should be searchable and port-aware without mixing recipes into the catalog",
);

assert.match(
  composer,
  /compatibleCreatorIds[\s\S]*workflowCreatorItemId\(hint\.definition\)[\s\S]*searchedCreatorIds[\s\S]*visibleCompatibleNodeHints/,
  "Compatible action search should operate on creator/action IDs so variants do not collapse into a coarse node kind",
);

assert.match(
  composer,
  /NODE_GROUP_FILTERS[\s\S]*nodeGroupFilter[\s\S]*workflow-node-group-filter[\s\S]*workflow-node-drawer-summary[\s\S]*workflow-node-library-empty/,
  "Primitive creation should provide grouped filtering, compatibility filtering, and an empty state without adding recipes",
);

assert.match(
  composer,
  /EMPTY_CANVAS_START_CREATOR_IDS[\s\S]*workflow-empty-start-overlay[\s\S]*What starts this workflow\?[\s\S]*workflow-empty-browse-primitives[\s\S]*workflow-empty-start-\$\{itemId\}/,
  "Blank workflows should guide users into start/source primitives before exposing the full registry",
);

assert.match(
  composer,
  /"trigger\.scheduled": "Run on a schedule\."[\s\S]*workflowStartCardDescription[\s\S]*workflowStartCardDescription\(item\)/,
  "Empty workflow starter cards should use concise overlay-specific descriptions instead of wrapping global registry copy",
);

assert.match(
  workflowComposerCss,
  /\.workflow-start-card\s*\{[\s\S]*grid-template-rows: auto auto auto 1fr;[\s\S]*min-height: 84px;/,
  "Empty workflow starter cards should reserve a stable row rhythm without wasting canvas space",
);

assert.match(
  workflowComposerCss,
  /\.workflow-start-card span\s*\{[\s\S]*text-overflow: ellipsis;[\s\S]*white-space: nowrap;/,
  "Empty workflow starter descriptions should stay on one line for scanability",
);

assert.match(
  nodeRegistry,
  /function\.javascript[\s\S]*function\.typescript[\s\S]*function\.python[\s\S]*function\.file_backed[\s\S]*output\.table[\s\S]*output\.patch[\s\S]*output\.deploy[\s\S]*state\.read[\s\S]*state\.write[\s\S]*state\.append[\s\S]*state\.reducer[\s\S]*state\.checkpoint/,
  "Primitive creator should expose concrete action variants while keeping media/output as generic ontology primitives",
);

assert.doesNotMatch(
  nodeRegistry,
  /Repo test engineer|JPG to SVG tracing|Software request triage agent|Product feedback router|Weekly metrics reporting agent|Month-end accounting close agent|Slack Q&A agent/,
  "Primitive/action registry must not contain scenario recipes or dogfood workflows",
);

assert.match(
  composer,
  /canvasSearchQuery[\s\S]*workflowCanvasSearchResults\([\s\S]*workflow-canvas-search-toggle[\s\S]*workflow-canvas-search-panel[\s\S]*workflow-canvas-search-input[\s\S]*workflow-canvas-search-result[\s\S]*workflow-canvas-search-compatible[\s\S]*openLeftDrawer\(\)[\s\S]*setNodeGroupFilter\("Compatible"\)[\s\S]*workflow-canvas-search-configure[\s\S]*closeCanvasSearch\(\)[\s\S]*setNodeConfigOpen\(true\)/,
  "Canvas search should navigate across node metadata, open compatible-node creation, and open node configuration directly",
);

assert.match(
  composer,
  /(?=[\s\S]*const openLeftDrawer = useCallback\([\s\S]*setCanvasSearchOpen\(false\)[\s\S]*setLeftDrawerOpen\(true\))(?=[\s\S]*const toggleLeftDrawer = useCallback\([\s\S]*setCanvasSearchOpen\(false\))(?=[\s\S]*const toggleCanvasSearch = useCallback\([\s\S]*setLeftDrawerOpen\(false\))(?=[\s\S]*workflow-open-node-library[\s\S]*onClick=\{openLeftDrawer\})(?=[\s\S]*workflow-canvas-search-toggle[\s\S]*onClick=\{toggleCanvasSearch\})/,
  "Canvas search and node creator should behave as mutually exclusive authoring overlays",
);

assert.match(
  workflowComposerModel,
  /workflowCanvasSearchResults[\s\S]*workflowConfiguredFieldNames[\s\S]*nodeRunStatusById[\s\S]*configuredFields[\s\S]*status/,
  "Canvas search indexing should live in the extracted composer model instead of JSX-local search heuristics",
);

assert.match(
  workflowComposerModel,
  /workflowNodeCreatorBadge[\s\S]*Needs capability[\s\S]*Needs connector/,
  "Primitive readiness badge rules should live outside the composer component",
);

assert.match(
  composer,
  /workflowNodeCreatorBadge\(\s*item,\s*globalConfig,\s*\)[\s\S]*workflow-component-readiness-\$\{itemId\}/,
  "Primitive creator should show operational readiness badges without hiding binding requirements",
);

assert.match(
  composer,
  /handleAddCompatibleNode[\s\S]*prospectiveNodeId[\s\S]*sourcePort[\s\S]*targetPort[\s\S]*compatible_node_picker[\s\S]*closeLeftDrawer\(\)[\s\S]*setBottomPanel\("selection"\)[\s\S]*setNodeConfigOpen\(true\)[\s\S]*workflow-add-compatible-\$\{itemId\}/,
  "Port-aware related-node creation should validate before creation, add, connect, and open configuration in one operation",
);

assert.match(
  composer,
  /compatiblePortFocus[\s\S]*sourcePort\.id === compatiblePortFocus\.portId[\s\S]*targetPort\.id === compatiblePortFocus\.portId[\s\S]*handleShowCompatibleNodesForPort[\s\S]*onRequestCompatibleNodes: handleShowCompatibleNodesForPort[\s\S]*workflow-clear-compatible-port-filter/,
  "Port-level compatible-node creation should scope the picker to the selected typed port and provide a way back to all ports",
);

assert.match(
  composer,
  /(?=[\s\S]*workflow-add-agent-loop-macro)(?=[\s\S]*handleInsertAgentLoopMacro)/,
  "Composer should offer a generic agent-loop macro without adding scenario templates to the primitive catalog",
);

assert.match(
  composer,
  /createdBy: "agent_loop_macro"[\s\S]*connectionClass: "memory"[\s\S]*connectionClass: "tool"/,
  "Agent-loop macro should expand into explicit typed memory/tool attachment edges rather than hidden execution",
);

assert.match(
  `${graphTypes}\n${composer}\n${canvasNode}\n${canvasNodeCss}\n${canvasEdge}\n${canvasEdgeCss}`,
  /interface WorkflowNodeViewMacro[\s\S]*viewMacro\?: WorkflowNodeViewMacro[\s\S]*viewMacro: \{[\s\S]*expandedFrom: "agent_loop_macro"[\s\S]*workflow-canvas-node-macro-badge[\s\S]*canvas-node--macro-member[\s\S]*canvas-edge--macro/,
  "Agent-loop macros should remain view metadata over explicit primitive nodes and visibly mark their expanded cluster on the canvas",
);

assert.match(
  `${graphTypes}\n${composer}\n${canvasNode}\n${canvasNodeCss}`,
  /(?=[\s\S]*interface WorkflowHarnessGroupView)(?=[\s\S]*harnessGroup\?: WorkflowHarnessGroupView)(?=[\s\S]*harnessGroupViews)(?=[\s\S]*selectedHarnessGroup)(?=[\s\S]*handleInspectHarnessGroupNode)(?=[\s\S]*collapsedHarnessGroupByNodeId)(?=[\s\S]*HARNESS_GROUP_BOUNDARY_PORTS)(?=[\s\S]*HARNESS_WORKBENCH_DEEP_LINK_PREFIX)(?=[\s\S]*encodeHarnessWorkbenchDeepLink)(?=[\s\S]*parseHarnessWorkbenchDeepLink)(?=[\s\S]*applyHarnessWorkbenchDeepLink)(?=[\s\S]*window\.history\.replaceState)(?=[\s\S]*navigator\.clipboard)(?=[\s\S]*selectorDecisionId)(?=[\s\S]*dispatchId)(?=[\s\S]*workerBindingId)(?=[\s\S]*rollbackTarget)(?=[\s\S]*collapsedGroupEdge)(?=[\s\S]*workflow-harness-group-controls)(?=[\s\S]*workflow-harness-collapse-groups)(?=[\s\S]*workflow-harness-expand-groups)(?=[\s\S]*workflow-harness-group-node-\$\{harnessGroup\.groupId\})(?=[\s\S]*workflow-harness-group-toggle)(?=[\s\S]*workflow-harness-group-boundary-ports)(?=[\s\S]*workflow-harness-group-deep-link)(?=[\s\S]*canvas-node--harness-group)/,
  "Harness promotion clusters and active runtime binding targets should collapse into typed boundary nodes with selection state, rollups, URL-restorable deep links, and explicit expand controls.",
);

assert.match(
	  workflowRailPanel,
	  /(?=[\s\S]*selectedHarnessGroup)(?=[\s\S]*workflow-harness-deep-link-state)(?=[\s\S]*workflow-copy-harness-deep-link)(?=[\s\S]*workflow-harness-group-inspector)(?=[\s\S]*workflow-harness-group-readiness-rollup)(?=[\s\S]*workflow-harness-group-components)(?=[\s\S]*workflow-harness-group-run-status)(?=[\s\S]*workflow-harness-group-gated-run)(?=[\s\S]*workflow-harness-group-receipt-refs)(?=[\s\S]*workflow-harness-group-receipt-ref-)(?=[\s\S]*workflow-harness-group-replay-fixtures)(?=[\s\S]*workflow-harness-group-replay-ref-)(?=[\s\S]*workflow-harness-group-activation-blockers)(?=[\s\S]*workflow-harness-group-shadow-comparison)(?=[\s\S]*workflow-harness-group-attempts)(?=[\s\S]*onInspectHarnessGroupNode)(?=[\s\S]*onSelectHarnessReceiptRef)(?=[\s\S]*onSelectHarnessReplayFixtureRef)(?=[\s\S]*workflow-harness-activation-wizard)(?=[\s\S]*workflow-harness-activation-candidate)(?=[\s\S]*workflow-harness-activation-candidate-decision)(?=[\s\S]*workflow-harness-fork-mutation-canary)(?=[\s\S]*workflow-harness-activation-candidate-worker-binding)(?=[\s\S]*workflow-harness-worker-binding-inspector)(?=[\s\S]*workflow-harness-worker-binding-picker)(?=[\s\S]*workflow-harness-worker-binding-option-current)(?=[\s\S]*workflow-harness-worker-binding-option-candidate)(?=[\s\S]*workflow-harness-worker-binding-option-rollback)(?=[\s\S]*workflow-harness-worker-binding-rollback-targets)(?=[\s\S]*workflow-harness-worker-binding-apply-candidate)(?=[\s\S]*workflow-harness-worker-binding-run-rollback-drill)(?=[\s\S]*workflow-harness-worker-binding-execute-rollback)(?=[\s\S]*workflow-harness-rollback-drill-proof)(?=[\s\S]*workflow-harness-rollback-execution-proof)(?=[\s\S]*workflow-harness-git-restore-proof)(?=[\s\S]*workflow-harness-git-restore-summary)(?=[\s\S]*workflow-harness-git-restore-paths)(?=[\s\S]*workflow-harness-git-restore-hashes)(?=[\s\S]*workflow-harness-git-restore-blockers)(?=[\s\S]*workflow-harness-activation-audit)(?=[\s\S]*workflow-harness-activation-audit-event-\$\{event\.eventId\})(?=[\s\S]*workflow-harness-worker-binding-version-set)(?=[\s\S]*workflow-harness-worker-binding-refresh-candidate)(?=[\s\S]*workflow-harness-worker-binding-check-readiness)(?=[\s\S]*workflow-harness-activation-candidate-gate-\$\{gate\.gateId\})(?=[\s\S]*workflow-harness-activation-dry-run)(?=[\s\S]*workflow-harness-activation-step-\$\{step\.id\})(?=[\s\S]*id: "slots")(?=[\s\S]*id: "tests")(?=[\s\S]*id: "replay-fixtures")(?=[\s\S]*id: "policy-posture")(?=[\s\S]*id: "mutation-canary")(?=[\s\S]*id: "receipt-coverage")(?=[\s\S]*id: "package-evidence")(?=[\s\S]*id: "canary")(?=[\s\S]*id: "rollback")(?=[\s\S]*id: "activation-id")(?=[\s\S]*id: "worker-binding")(?=[\s\S]*workflow-harness-activation-blocked-proof)(?=[\s\S]*workflow-harness-activation-minted-proof)(?=[\s\S]*workflow-harness-activation-run-readiness)(?=[\s\S]*workflow-harness-activation-review-proposal)(?=[\s\S]*workflow-harness-fork-component-diff)(?=[\s\S]*workflow-harness-fork-component-diff-summary)(?=[\s\S]*workflow-harness-fork-component-diff-row-\$\{row\.componentId\})(?=[\s\S]*onCheckActivationReadiness)(?=[\s\S]*onRunHarnessActivationDryRun)(?=[\s\S]*onApplyHarnessActivationCandidate)(?=[\s\S]*onRunHarnessRollbackDrill)(?=[\s\S]*onExecuteHarnessRollback)(?=[\s\S]*onSelectHarnessRollbackTarget)/,
  "Harness group rail inspection should expose readiness rollups, components, run/gate status, receipts, replay fixtures, blockers, shadow comparison, attempts, member deep links, copyable workbench state, dry-run activation candidates, rollback drill proof, activation audit history, and blessed-vs-fork component diffs.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-harness-rollback-restore-canary)(?=[\s\S]*data-restore-canary-status)(?=[\s\S]*id: "rollback-restore")(?=[\s\S]*rollbackRestoreCanaryReady)/,
  "Activation rail should surface the rollback restore canary and its dedicated wizard gate before minting.",
);

assert.match(
  workflowRailPanel,
  /workflow-harness-rollback-restore-canary[\s\S]*data-receipt-binding-ref[\s\S]*receiptBindingRef/,
  "Activation rail should surface rollback restore canary receipt bindings.",
);

assert.match(
  `${workflowRailPanel}\n${composer}\n${workflowValidation}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationWizardStep)(?=[\s\S]*WorkflowHarnessActivationGateAction)(?=[\s\S]*WorkflowHarnessActivationGateActionClickProof)(?=[\s\S]*gateAction)(?=[\s\S]*runHarnessActivationGateActionClickProbe)(?=[\s\S]*selectedHarnessActivationGateInspection)(?=[\s\S]*workflow-harness-activation-gate-inspector)(?=[\s\S]*workflow-harness-activation-gate-summary)(?=[\s\S]*workflow-harness-activation-gate-actions)(?=[\s\S]*workflow-harness-activation-gate-action)(?=[\s\S]*workflow-harness-activation-step-action-\$\{step\.id\})(?=[\s\S]*workflow-harness-activation-candidate-gate-action-\$\{gate\.gateId\})(?=[\s\S]*workflow-harness-activation-gate-evidence-refs)(?=[\s\S]*workflow-harness-activation-gate-node-attempt-refs)(?=[\s\S]*workflow-harness-activation-gate-node-timeline)(?=[\s\S]*workflow-harness-activation-gate-receipt-refs)(?=[\s\S]*workflow-harness-activation-gate-replay-refs)(?=[\s\S]*data-evidence-ref-count)(?=[\s\S]*data-node-attempt-ref-count)(?=[\s\S]*data-gate-action-id)(?=[\s\S]*data-gate-action-kind)(?=[\s\S]*data-gate-action-command)(?=[\s\S]*data-selected-activation-gate-evidence-ref)(?=[\s\S]*data-selected-activation-gate-node-attempt-id)(?=[\s\S]*data-activation-gate-evidence-ref)(?=[\s\S]*data-activation-gate-node-attempt-id)(?=[\s\S]*activationGateEvidenceRef)(?=[\s\S]*activationGateNodeAttemptId)(?=[\s\S]*activationGateReceiptRef)(?=[\s\S]*activationGateReplayFixtureRef)(?=[\s\S]*selectedRailTestId: "workflow-harness-activation-gate-inspector")(?=[\s\S]*gateResults:[\s\S]*evidenceRefs)(?=[\s\S]*activationGateEvidenceInspectable)(?=[\s\S]*activationGateActionWorkbench)(?=[\s\S]*activationGateActionClickProof)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)(?=[\s\S]*harness_activation_gate_evidence_inspector)(?=[\s\S]*harness_activation_gate_evidence_inspector_present)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_action_workbench)(?=[\s\S]*harness_activation_gate_action_workbench_present)(?=[\s\S]*harness_activation_gate_action_click_proof)(?=[\s\S]*harness_activation_gate_action_click_proof_present)/,
  "Activation gate deep links should restore into a selected gate evidence inspector with evidence, receipt, and replay refs.",
);

assert.match(
  `${workflowRailPanel}\n${composer}\n${guiHarnessValidation}`,
  /(?=[\s\S]*workflow-harness-canary-execution-boundaries)(?=[\s\S]*data-selected-canary-boundary-id)(?=[\s\S]*data-selected-rollback-drill-id)(?=[\s\S]*data-canary-boundary-id)(?=[\s\S]*data-rollback-drill-id)(?=[\s\S]*activation-gate-canary-boundary)(?=[\s\S]*activation-gate-canary-rollback-drill)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)/,
  "Canary boundary and rollback drill rows should be route-stateful activation gate deep-link targets.",
);

assert.match(
  `${graphTypes}\n${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationGateCollectEvidenceClickProof)(?=[\s\S]*runHarnessActivationGateCollectEvidenceClickProbe)(?=[\s\S]*activationGateCollectEvidenceClickProof)(?=[\s\S]*activationGateReplayFixtureRefs)(?=[\s\S]*selectedHarnessActivationGateId === "replay-fixtures")(?=[\s\S]*__AUTOPILOT_HARNESS_REPLAY_GATE_CLICK_RESULT)(?=[\s\S]*workflow-harness-gate-action-replay-fixtures)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof_present)/,
  "Activation replay fixture gate actions should have live click proof that collects persisted replay-gate evidence.",
);

assert.match(
  `${graphTypes}\n${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationGateRollbackRestoreClickProof)(?=[\s\S]*runHarnessActivationGateRollbackRestoreClickProbe)(?=[\s\S]*activationGateRollbackRestoreClickProof)(?=[\s\S]*__AUTOPILOT_HARNESS_ACTIVATION_DRY_RUN_CLICK_RESULT)(?=[\s\S]*workflow-harness-gate-action-rollback-restore)(?=[\s\S]*rollbackRestoreReceiptBindingRef)(?=[\s\S]*rollbackRestoreDeepLink)(?=[\s\S]*data-selected-rollback-restore-canary-id)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof_present)/,
  "Rollback restore activation gate actions should have live click proof that collects restore canary receipt evidence.",
);

assert.match(
  `${graphTypes}\n${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationIdGateClickProof)(?=[\s\S]*workflowHarnessActivationIdGateClickProofBlockers)(?=[\s\S]*activation_id_gate_click_proof_missing)(?=[\s\S]*runHarnessActivationIdGateClickProbe)(?=[\s\S]*activationIdGateClickProof)(?=[\s\S]*__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT)(?=[\s\S]*workflow-harness-gate-action-activation-id)(?=[\s\S]*workerHandoffDeepLink)(?=[\s\S]*workerHandoffTimelineVisible)(?=[\s\S]*activation_id_gate_mint_handoff_timeline_missing)(?=[\s\S]*activationIdBlockedDryRunDecision)(?=[\s\S]*activationIdMintedActivationId)(?=[\s\S]*harness_activation_id_gate_click_proof)(?=[\s\S]*harness_activation_id_gate_click_proof_present)/,
  "Activation id gate actions should have live click proof for both blocked dry-run and minting paths.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-harness-activation-audit[\s\S]*data-receipt-refs[\s\S]*data-audit-receipt-refs)(?=[\s\S]*workflow-harness-rollback-execution-proof[\s\S]*data-restore-receipt-binding-ref)/,
  "Activation rail should surface audit and rollback execution receipt refs.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-harness-active-runtime-binding)(?=[\s\S]*data-binding-matched)(?=[\s\S]*data-selector-decision-id)(?=[\s\S]*data-default-dispatch-id)(?=[\s\S]*data-worker-launch-reviewed-import-invariant-bound)(?=[\s\S]*data-worker-session-launch-authority-invariant-ids)(?=[\s\S]*data-worker-launch-envelope-invariant-ids)(?=[\s\S]*data-worker-handoff-receipt-invariant-ids)(?=[\s\S]*DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)(?=[\s\S]*data-selected-selector-decision-id)(?=[\s\S]*data-selected-default-dispatch-id)(?=[\s\S]*data-selected-worker-binding-id)(?=[\s\S]*data-selected-rollback-target)(?=[\s\S]*workflow-harness-active-runtime-binding-selector-link)(?=[\s\S]*selectorDecisionId)(?=[\s\S]*workflow-harness-active-runtime-binding-dispatch-link)(?=[\s\S]*dispatchId)(?=[\s\S]*workflow-harness-active-runtime-binding-worker-link)(?=[\s\S]*workerBindingId)(?=[\s\S]*workflow-harness-active-runtime-binding-rollback-link)(?=[\s\S]*rollbackTarget)(?=[\s\S]*workflow-harness-active-runtime-binding-receipt-\$\{index\})(?=[\s\S]*workflow-harness-active-runtime-binding-replay-\$\{index\})(?=[\s\S]*workflow-harness-active-runtime-binding-blockers)/,
  "The harness rail should surface route-restorable active runtime binding identity with selector, dispatch, worker, rollback, receipt, replay, and blocker deep links.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*id: "worker-invariant")(?=[\s\S]*workflow-harness-activation-step-\$\{step\.id\})(?=[\s\S]*data-required-invariant-ids)(?=[\s\S]*data-invariant-blockers)(?=[\s\S]*workflow-harness-activation-gate-inspector)(?=[\s\S]*data-invariant-blocker-count)(?=[\s\S]*DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)/,
  "The activation wizard should expose reviewed-import worker launch invariants as a selectable gate with GUI-visible blockers.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-selected-receipt-ref)(?=[\s\S]*workflow-harness-activation-audit-summary-receipt-\$\{index\})(?=[\s\S]*workflow-harness-activation-audit-receipt-\$\{event\.eventId\}-\$\{index\})(?=[\s\S]*workflow-harness-rollback-drill-receipt-\$\{index\})(?=[\s\S]*workflow-harness-rollback-execution-receipt-\$\{index\})(?=[\s\S]*selectedHarnessReceiptRef === receiptRef)(?=[\s\S]*onSelectHarnessReceiptRef\?\.\(receiptRef\))/,
  "Activation receipt refs should be clickable deep-link controls across audit, drill, and rollback execution panels.",
);

assert.match(
  composer,
  /(?=[\s\S]*handleSelectHarnessReceiptRef[\s\S]*setSelectedHarnessReceiptRef\(receiptRef\))(?=[\s\S]*receiptRef: selectedHarnessReceiptRef)(?=[\s\S]*selectorDecisionId: selectedHarnessSelectorDecisionId)(?=[\s\S]*dispatchId: selectedHarnessDefaultDispatchId)(?=[\s\S]*workerBindingId: selectedHarnessWorkerBindingId)(?=[\s\S]*rollbackTarget: selectedHarnessRollbackTarget)/,
  "Selecting harness receipts and active binding targets should update URL-restorable workbench state.",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*export function resolveWorkflowHarnessReceiptInspection)(?=[\s\S]*workflowHarnessReceiptKind)(?=[\s\S]*workflowRedactedReceiptPayload)(?=[\s\S]*selectedHarnessReceiptInspection)(?=[\s\S]*sourceKind: "node_attempt")(?=[\s\S]*sourceKind: "activation_audit")(?=[\s\S]*sourceKind: "activation_worker_handoff")(?=[\s\S]*sourceKind: "rollback_execution")(?=[\s\S]*sourceKind: "default_runtime_dispatch")(?=[\s\S]*workflow-harness-receipt-inspector)(?=[\s\S]*data-receipt-source-kind)(?=[\s\S]*data-producer-component)(?=[\s\S]*workflow-harness-receipt-inspector-metadata)(?=[\s\S]*workflow-harness-receipt-payload-preview)(?=[\s\S]*workflow-harness-receipt-evidence-refs)/,
  "Activation receipt refs should resolve into a redacted detail inspector with source, policy, attempt, replay, hashes, and evidence refs.",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*export interface WorkflowHarnessReplayInspection)(?=[\s\S]*export function resolveWorkflowHarnessReplayInspection)(?=[\s\S]*workflowUniqueReplayFixtureRefs)(?=[\s\S]*selectedHarnessReplayInspection)(?=[\s\S]*sourceKind: "node_attempt")(?=[\s\S]*sourceKind: "gated_cluster")(?=[\s\S]*sourceKind: "runtime_binding")(?=[\s\S]*sourceKind: "activation_worker_handoff")(?=[\s\S]*sourceKind: "default_runtime_dispatch")(?=[\s\S]*sourceKind: "read_only_routing_proof")(?=[\s\S]*sourceKind: "authority_gate_proof")(?=[\s\S]*sourceKind: "harness_group")(?=[\s\S]*workflow-harness-replay-inspector)(?=[\s\S]*data-replay-source-kind)(?=[\s\S]*data-determinism)(?=[\s\S]*workflow-harness-replay-inspector-metadata)(?=[\s\S]*workflow-harness-replay-capture-flags)(?=[\s\S]*workflow-harness-replay-payload-preview)(?=[\s\S]*workflow-harness-replay-evidence-refs)/,
  "Replay fixture refs should resolve into a redacted detail inspector with source, policy, attempt, receipt, determinism, capture flags, and evidence refs.",
);

assert.match(
  `${graphTypes}\n${harnessWorkflow}\n${composer}\n${workflowRailPanel}\n${workflowValidation}`,
  /(?=[\s\S]*WorkflowHarnessReplayDrillResult)(?=[\s\S]*WorkflowHarnessReplayGateResult)(?=[\s\S]*WorkflowHarnessPromotionClusterReplayGateProof)(?=[\s\S]*WorkflowHarnessReplayDrillDivergenceClass)(?=[\s\S]*replayGateProof\?: WorkflowHarnessPromotionClusterReplayGateProof)(?=[\s\S]*replayDrills\?: WorkflowHarnessReplayDrillResult\[\])(?=[\s\S]*replayGates\?: WorkflowHarnessReplayGateResult\[\])(?=[\s\S]*executeWorkflowHarnessReplayDrill)(?=[\s\S]*executeWorkflowHarnessReplayGate)(?=[\s\S]*workflowHarnessPromotionClustersWithReplayGateProof)(?=[\s\S]*replay_drill_passed)(?=[\s\S]*replay_gate_passed)(?=[\s\S]*replay_gate_blocked)(?=[\s\S]*handleRunHarnessReplayDrill)(?=[\s\S]*handleRunHarnessReplayGate)(?=[\s\S]*onRunHarnessReplayGate)(?=[\s\S]*workflow-harness-run-replay-drill)(?=[\s\S]*workflow-harness-run-replay-gate)(?=[\s\S]*workflow-harness-replay-gate-result)(?=[\s\S]*workflow-harness-promotion-cluster-replay-gate)(?=[\s\S]*workflow-harness-group-replay-gate-proof)(?=[\s\S]*data-replay-divergence-class)(?=[\s\S]*data-activation-gate-impact)(?=[\s\S]*replayDrillBlockers)(?=[\s\S]*replayGateBlockers)(?=[\s\S]*promotionClusterReplayGateBlockers)/,
  "Replay fixture refs should run replay drills and batch replay gates, classify divergence, persist cluster replay gate proofs, surface receipt refs, and feed activation readiness.",
);

assert.match(
  `${graphTypes}\n${harnessWorkflow}\n${composer}\n${workflowRailPanel}`,
  /(?=[\s\S]*WorkflowHarnessPromotionTransitionEligibility)(?=[\s\S]*WorkflowHarnessPromotionTransitionAttempt)(?=[\s\S]*promotionStatus\?: WorkflowHarnessClusterPromotionStatus)(?=[\s\S]*promotionTransitions\?: WorkflowHarnessPromotionTransitionAttempt\[\])(?=[\s\S]*workflowHarnessPromotionTransitionEligibility)(?=[\s\S]*executeWorkflowHarnessPromotionTransition)(?=[\s\S]*promotion_transition_blocked)(?=[\s\S]*promotion_transition_promoted)(?=[\s\S]*handleRunHarnessPromotionTransition)(?=[\s\S]*onRunHarnessPromotionTransition)(?=[\s\S]*workflow-harness-group-promotion-actions)(?=[\s\S]*workflow-harness-promote-cluster-gated)(?=[\s\S]*workflow-harness-promote-cluster-live)(?=[\s\S]*workflow-harness-group-promotion-eligibility)(?=[\s\S]*workflow-harness-group-promotion-attempt)/,
  "Promotion cluster controls should prove eligibility before gated/live transitions and persist audited transition attempts.",
);

assert.match(
  `${guiHarnessValidation}\n${guiHarnessContract}\n${promotionTransitionGuiProbe}`,
  /(?=[\s\S]*collectPromotionTransitionGuiBehaviorProof)(?=[\s\S]*harness-promotion-transition-gui-probe\.mjs)(?=[\s\S]*harness_promotion_transition_gui_behavior)(?=[\s\S]*harness_promotion_transition_gui_behavior_present)(?=[\s\S]*promotionTransitionBehavior)(?=[\s\S]*render WorkflowRailPanel markup)(?=[\s\S]*blockedGatedButtonDisabled)(?=[\s\S]*liveClickPromotesCluster)/,
  "Retained GUI validation should require behavioral promotion proof that renders the rail, drives the transition handler path, and proves blocked/gated/live control states.",
);

assert.match(
  `${harnessWorkflow}\n${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*VITE_AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI)(?=[\s\S]*HARNESS_PROMOTION_LIVE_GUI_SCRIPT)(?=[\s\S]*__AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI_RESULT)(?=[\s\S]*handleHarnessPromotionLiveGuiProbe)(?=[\s\S]*runHarnessDeepLinkReplayProbe)(?=[\s\S]*runHarnessLiveTurnNodeInspectorDeepLinkProbe)(?=[\s\S]*runHarnessLiveShadowComparisonDeepLinkProbe)(?=[\s\S]*runHarnessColdStartDeepLinkRestoreProbe)(?=[\s\S]*runHarnessActivationBlockerDeepLinkProbe)(?=[\s\S]*runHarnessActivationGateDeepLinkProbe)(?=[\s\S]*activation-gate-worker-invariant)(?=[\s\S]*liveActivationGateDeepLinkProof)(?=[\s\S]*liveTurnNodeInspectorDeepLinkProof)(?=[\s\S]*liveShadowComparisonDeepLinkProof)(?=[\s\S]*live-shadow-comparison)(?=[\s\S]*live-turn-node-inspector)(?=[\s\S]*runHarnessWorkerInvariantNegativeEnforcementProbe)(?=[\s\S]*workerInvariantNegativeEnforcementProof)(?=[\s\S]*workerInvariantNegativeEnforcement)(?=[\s\S]*HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS)(?=[\s\S]*workflowWithBlessedDefaultRuntimeActivationProof)(?=[\s\S]*makeHarnessRuntimeSelectorDecision)(?=[\s\S]*makeBlessedHarnessLiveHandoffProof)(?=[\s\S]*makeHarnessDefaultRuntimeDispatchProof)(?=[\s\S]*workflowHarnessPackageImportActivationApplyProofBlockers)(?=[\s\S]*package_import_activation_apply_proof_missing)(?=[\s\S]*defaultLivePromotionInvariantBlockers)(?=[\s\S]*reviewedImportActivationApplyProofPassed)(?=[\s\S]*reviewedImportActivationApplyGate)(?=[\s\S]*reviewed_import_activation_apply)(?=[\s\S]*default-agent-harness-live-gui-promotion-proof\.workflow\.json)(?=[\s\S]*runtimeSelectorDefaultPromoted)(?=[\s\S]*selectorReviewedImportActivationApplyInvariant)(?=[\s\S]*liveHandoffTransferred)(?=[\s\S]*liveHandoffReviewedImportActivationApplyInvariant)(?=[\s\S]*defaultDispatchBound)(?=[\s\S]*defaultDispatchReviewedImportActivationApplyInvariant)(?=[\s\S]*activeWorkerBinding)(?=[\s\S]*routeStatefulDeepLinks)(?=[\s\S]*routeStatefulActiveRuntimeBindingDeepLinks)(?=[\s\S]*routeStatefulRevisionBindingDeepLink)(?=[\s\S]*routeStatefulActivationBlockerDeepLink)(?=[\s\S]*routeStatefulActivationAuditDeepLink)(?=[\s\S]*routeStatefulActivationGateDeepLink)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)(?=[\s\S]*activationGateWorkerInvariantDeepLink)(?=[\s\S]*activationGateWorkerInvariantInspector)(?=[\s\S]*activationGateActionWorkbench)(?=[\s\S]*activationGateActionClickProof)(?=[\s\S]*revisionBindingKind)(?=[\s\S]*revisionBindingRef)(?=[\s\S]*activationBlockerRef)(?=[\s\S]*activationAuditEventId)(?=[\s\S]*activationGateId)(?=[\s\S]*activationGateEvidenceRef)(?=[\s\S]*activationGateReceiptRef)(?=[\s\S]*activationGateReplayFixtureRef)(?=[\s\S]*deepLinkReplayProof)(?=[\s\S]*coldStartDeepLinkRestoreProof)(?=[\s\S]*activationBlockerDeepLinkProof)(?=[\s\S]*activationGateDeepLinkProof)(?=[\s\S]*routeStatefulDeepLinkReplay)(?=[\s\S]*coldStartDeepLinkRestore)(?=[\s\S]*liveTurnNodeInspectorDeepLink)(?=[\s\S]*harness_route_stateful_deep_link_replay)(?=[\s\S]*harness_route_stateful_deep_link_replay_present)(?=[\s\S]*harness_cold_start_deep_link_restore)(?=[\s\S]*harness_cold_start_deep_link_restore_present)(?=[\s\S]*harness_revision_binding_deep_link_restore)(?=[\s\S]*harness_revision_binding_deep_link_restore_present)(?=[\s\S]*harness_activation_blocker_deep_link_restore)(?=[\s\S]*harness_activation_blocker_deep_link_restore_present)(?=[\s\S]*harness_activation_audit_deep_link_restore)(?=[\s\S]*harness_activation_audit_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_deep_link_restore)(?=[\s\S]*harness_activation_gate_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore_present)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_gate_deep_link)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_gate_deep_link_present)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_negative_enforcement)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_negative_enforcement_present)(?=[\s\S]*harness_activation_gate_action_workbench)(?=[\s\S]*harness_activation_gate_action_workbench_present)(?=[\s\S]*harness_activation_gate_action_click_proof)(?=[\s\S]*harness_activation_gate_action_click_proof_present)(?=[\s\S]*collectPromotionTransitionLiveGuiInteractionProof)(?=[\s\S]*promotion-transition-live-gui-interaction-proof\.json)(?=[\s\S]*harness_promotion_transition_live_gui_interaction)(?=[\s\S]*harness_promotion_transition_live_gui_interaction_present)(?=[\s\S]*harness_selector_reviewed_import_activation_apply_invariant)(?=[\s\S]*harness_selector_reviewed_import_activation_apply_invariant_present)(?=[\s\S]*harness_chat_runtime_binding)(?=[\s\S]*harness_chat_runtime_binding_matches_workflow_activation)(?=[\s\S]*harness_live_turn_node_timeline)(?=[\s\S]*harness_live_turn_node_timeline_present)(?=[\s\S]*harness_live_turn_node_inspector)(?=[\s\S]*harness_live_turn_node_inspector_present)(?=[\s\S]*harness_live_turn_node_inspector_deep_link)(?=[\s\S]*harness_live_turn_node_inspector_deep_link_present)(?=[\s\S]*harness_live_shadow_comparison)(?=[\s\S]*harness_live_shadow_comparison_present)(?=[\s\S]*harnessLiveTurnNodeTimelineCount)(?=[\s\S]*harnessLiveTurnNodeInspectorCount)(?=[\s\S]*harnessLiveShadowComparisonCount)(?=[\s\S]*HarnessDefaultRuntimeBinding)(?=[\s\S]*harnessDefaultRuntimeBindingMatchedCount)(?=[\s\S]*promotionTransitionLiveGui)/,
  "Retained GUI validation should require a live Workflows desktop promotion interaction that promotes every P0 cluster, saves blessed default selector state, captures screenshot proof, records route-stateful active binding links, and replays them into hydrated rail state.",
);

assert.match(
  `${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*activationGateCollectEvidenceClickProof)(?=[\s\S]*activationGateCollectEvidenceClickPassed)(?=[\s\S]*activationGateCollectEvidenceCommand)(?=[\s\S]*activationGateCollectEvidenceReplayGateId)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof_present)/,
  "Live promotion GUI validation should include replay-fixture collect-evidence gate click proof in the retained evidence contract.",
);

assert.match(
  `${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*activationGateRollbackRestoreClickProof)(?=[\s\S]*activationGateRollbackRestoreClickPassed)(?=[\s\S]*activationGateRollbackRestoreCommand)(?=[\s\S]*activationGateRollbackRestoreCanaryStatus)(?=[\s\S]*activationGateRollbackRestoreReceiptBindingRef)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof_present)/,
  "Live promotion GUI validation should include rollback restore gate click proof in the retained evidence contract.",
);

assert.match(
  `${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*activationIdGateClickProof)(?=[\s\S]*activationIdGateClickPassed)(?=[\s\S]*activationIdBlockedDryRunDecision)(?=[\s\S]*activationIdMintedActivationId)(?=[\s\S]*harness_activation_id_gate_click_proof)(?=[\s\S]*harness_activation_id_gate_click_proof_present)/,
  "Live promotion GUI validation should include activation-id blocked and mint gate click proof in the retained evidence contract.",
);

assert.match(
	  `${graphTypes}\n${workflowRailPanel}\n${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
	  /(?=[\s\S]*WorkflowHarnessPackageEvidenceGateClickProof)(?=[\s\S]*runHarnessPackageEvidenceGateClickProbe)(?=[\s\S]*packageEvidenceGateClickProof)(?=[\s\S]*packageEvidenceGateClickPassed)(?=[\s\S]*packageEvidenceGateReceiptRefCount)(?=[\s\S]*packageEvidenceGateDeepLinkCount)(?=[\s\S]*workflow-harness-package-evidence-review)(?=[\s\S]*workflow-harness-package-evidence-row-\$\{row\.id\})(?=[\s\S]*workflow-harness-package-evidence-row-ref-\$\{row\.id\}-\$\{index\})(?=[\s\S]*data-harness-package-evidence-ready)(?=[\s\S]*data-harness-package-fork-mutation-receipt-count)(?=[\s\S]*data-harness-package-receipt-ref-count)(?=[\s\S]*data-harness-package-replay-fixture-ref-count)(?=[\s\S]*data-harness-package-worker-handoff-attempt-count)(?=[\s\S]*workflowHarnessPackageDeepLinkTarget)(?=[\s\S]*harness_package_evidence_gate_click_proof)(?=[\s\S]*harness_package_evidence_gate_click_proof_present)/,
  "Live promotion GUI validation should include package-evidence gate click proof with inspectable manifest rows and route-restorable refs.",
);

assert.match(
  `${graphTypes}\n${workflowRailPanel}\n${composer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessPackageEvidenceImportRoundTripProof)(?=[\s\S]*WorkflowHarnessPackageImportReviewProof)(?=[\s\S]*WorkflowPackageImportReview)(?=[\s\S]*reviewedPackageSnapshotHash)(?=[\s\S]*runHarnessPackageEvidenceImportRoundTripProbe)(?=[\s\S]*packageEvidenceImportRoundTripProof)(?=[\s\S]*packageImportReviewProof)(?=[\s\S]*exportWorkflowPackage)(?=[\s\S]*importWorkflowPackage)(?=[\s\S]*workflow-harness-package-import-review)(?=[\s\S]*workflow-harness-package-import-activate)(?=[\s\S]*data-package-import-source-reviewed-package-snapshot-hash)(?=[\s\S]*data-package-import-source-workflow-path)(?=[\s\S]*data-package-import-imported-workflow-path)(?=[\s\S]*packageEvidenceImportRoundTripPassed)(?=[\s\S]*packageImportReviewPassed)(?=[\s\S]*harness_package_evidence_import_roundtrip)(?=[\s\S]*harness_package_import_review_mode)(?=[\s\S]*harness_package_import_review_mode_present)/,
  "Live promotion GUI validation should prove package-evidence export/import round-trip preservation and source/import review gating.",
);

assert.match(
  workflowComposerUi,
  /viewMacro[\s\S]*macroPeerNodes[\s\S]*workflow-node-macro-cluster[\s\S]*workflow-node-macro-peer-list[\s\S]*workflow-node-macro-peer/,
  "Node details should show the expanded agent-loop composition and peer roles without hiding runtime behavior inside a macro node",
);

assert.match(
  `${workflowNodeConfigTypes}\n${workflowNodeConfigModal}`,
  /Settings[\s\S]*Inputs[\s\S]*Outputs[\s\S]*Fixtures[\s\S]*Run data[\s\S]*workflow-node-port-summary/,
  "Node details should expose professional configuration sections and typed port summaries",
);

assert.match(
  workflowNodeConfigModal,
  /workflow-node-detail-workbench[\s\S]*workflow-node-detail-input-zone[\s\S]*Capture fixture[\s\S]*workflow-node-detail-config-zone[\s\S]*workflow-node-detail-output-zone[\s\S]*Dry run/,
  "Node details should center input, configuration, and output inspection in one workbench surface",
);

assert.match(
  workflowNodeConfigModal,
  /WORKFLOW_NODE_DETAIL_SECTIONS[\s\S]*workflow-config-nav-\$\{section\.id\}[\s\S]*scrollToConfigSection[\s\S]*data-config-section/,
  "Node detail section navigation should be operational, anchored, shared, and local to the modal",
);

assert.match(
  `${workflowNodeConfigModal}\n${workflowComposerCss}`,
  /event\.key !== "Escape"[\s\S]*onClose\(\)[\s\S]*workflow-config-dialog > header[\s\S]*position: sticky[\s\S]*workflow-config-dialog > footer[\s\S]*position: sticky/,
  "Node configuration should remain closable after jumping to a deep blocker section",
);

assert.match(
  workflowNodeConfigTypes,
  /WORKFLOW_NODE_DETAIL_SECTIONS[\s\S]*Settings[\s\S]*Inputs[\s\S]*Mapping[\s\S]*Outputs[\s\S]*Schema[\s\S]*Bindings[\s\S]*Policy[\s\S]*Fixtures[\s\S]*Run data[\s\S]*Tests[\s\S]*Advanced/,
  "Node detail section model should be shared instead of buried in one modal component",
);

assert.match(
  workflowComposerUi,
  /(?=[\s\S]*workflow-config-section-policy)(?=[\s\S]*workflow-config-section-bindings)(?=[\s\S]*workflow-config-section-tests)(?=[\s\S]*workflow-node-advanced-summary)/,
  "Node details should separate runtime bindings, contextual policy, tests, and advanced executor identity",
);

assert.match(
  workflowNodeConfigModal,
  /workflow-node-config-connections[\s\S]*workflow-node-config-incoming-edges[\s\S]*workflow-node-config-outgoing-edges[\s\S]*workflow-node-config-compatible-next/,
  "Node details should expose typed incoming/outgoing connections and compatible downstream primitives",
);

assert.match(
  `${workflowNodeConfigModal}\n${workflowComposerCss}`,
  /(?=[\s\S]*workflowConfigSectionForNodeIssue)(?=[\s\S]*workflow-node-repair-strip[\s\S]*workflow-node-repair-action-\$\{index\}[\s\S]*scrollToConfigSection)(?=[\s\S]*workflow-config-repair-strip)/,
  "Node details should promote repair actions that jump to the exact configuration section for the selected node",
);

assert.match(
  `${workflowNodeBindingEditor}\n${workflowNodeBindingEditorSections}`,
  /workflow-state-reducer[\s\S]*workflow-subgraph-output-mapping[\s\S]*workflow-subgraph-run-controls[\s\S]*workflow-output-asset-kind[\s\S]*workflow-output-delivery-target-ref[\s\S]*workflow-output-delivery-approval[\s\S]*workflow-proposal-summary[\s\S]*workflow-proposal-requires-approval[\s\S]*workflow-connector-operation[\s\S]*workflow-connector-capability-scope[\s\S]*workflow-connector-requires-approval/,
  "Node-specific editors should expose deeper state, subgraph, proposal, connector-write, and output delivery controls",
);

assert.match(
  workflowRailPanel,
  /workflow-selected-node-inspector[\s\S]*workflow-rail-configure-node[\s\S]*workflow-selected-node-status[\s\S]*workflow-selected-node-ports[\s\S]*workflow-selected-node-bindings/,
  "Selecting a node should populate a compact right-rail inspector with status, ports, bindings, and a configure action",
);

assert.match(
  workflowRailPanel,
  /workflow-selected-node-quick-actions[\s\S]*workflow-inspector-run-node[\s\S]*workflow-inspector-run-upstream[\s\S]*workflow-inspector-replay-fixture[\s\S]*workflow-inspector-capture-fixture[\s\S]*workflow-inspector-add-test-from-output/,
  "The everyday right inspector should expose node run, upstream run, fixture replay/capture, and test-from-output actions",
);

assert.match(
  workflowRailPanel,
  /workflow-selected-node-io-workbench[\s\S]*workflow-selected-node-input-zone[\s\S]*workflow-selected-node-config-zone[\s\S]*workflow-selected-node-output-zone/,
  "The right inspector should use input/config/output zones for everyday node reasoning",
);

assert.match(
  workflowRailPanel,
  /workflow-selected-node-ai-cluster[\s\S]*Model[\s\S]*Memory[\s\S]*Tools[\s\S]*Parser[\s\S]*workflow-selected-node-ai-attachment/,
  "Model and agent nodes should expose AI attachment posture in the right inspector",
);

assert.match(
  `${composer}\n${canvasNode}\n${canvasNodeCss}\n${canvasEdge}\n${canvasEdgeCss}`,
  /(?=[\s\S]*workflowCanvasIssuesByNodeId)(?=[\s\S]*canvasEdgeIssues)(?=[\s\S]*validationIssueSummary)(?=[\s\S]*workflow-canvas-node-issue-\$\{nodeData\.id\})(?=[\s\S]*node-issue-badge)(?=[\s\S]*workflow-canvas-edge-warning)(?=[\s\S]*canvas-edge-warning)/,
  "Canvas should surface validation/readiness issues directly on affected nodes and invalid typed edges",
);

assert.match(
  `${composer}\n${workflowComposerCss}`,
  /RIGHT_PANELS[\s\S]*description[\s\S]*rightPanelBadgeCounts[\s\S]*workflow-rail-active-header[\s\S]*workflow-rail-panel-badge[\s\S]*workflow-rail-panel-label[\s\S]*focus-visible \.workflow-rail-panel-label/,
  "Right-rail icon controls should expose descriptions, badges, and readable hover/focus labels without widening the workbench rail",
);

assert.match(
  `${workflowRailModel}\n${composer}\n${workflowComposerCss}`,
  /(?=[\s\S]*workflowLifecycleState)(?=[\s\S]*Draft)(?=[\s\S]*Runnable locally)(?=[\s\S]*Ready for sandbox)(?=[\s\S]*Ready for scheduled)(?=[\s\S]*Ready for production)(?=[\s\S]*workflow-lifecycle-state)(?=[\s\S]*workflow-action-cluster-label[\s\S]*Create[\s\S]*Bind[\s\S]*Run[\s\S]*Ship)/,
  "The header should show a product lifecycle state and grouped action clusters instead of a flat button wall",
);

assert.match(
  `${composer}\n${workflowComposerCss}`,
  /workflow-selection-actions[\s\S]*workflow-selection-action[\s\S]*workflow-configure-node[\s\S]*workflow-show-compatible-nodes[\s\S]*setNodeGroupFilter\("Compatible"\)[\s\S]*workflow-connect-from-node[\s\S]*workflow-connect-to-node[\s\S]*workflow-add-node-test[\s\S]*workflow-selection-action:hover \.workflow-action-tooltip/,
  "Selected-node canvas actions should stay compact and provide a direct compatible-node creator path",
);

assert.match(
  workflowComposerCss,
  /(?=[\s\S]*grid-template-rows: auto auto auto minmax\(0, 1fr\) minmax\(144px, 22vh\))(?=[\s\S]*workflow-composer-header[\s\S]*grid-row: 1)(?=[\s\S]*workflow-composer-tabs[\s\S]*grid-row: 2)(?=[\s\S]*workflow-composer-banner[\s\S]*grid-row: 3)(?=[\s\S]*workflow-composer-body[\s\S]*grid-row: 4)(?=[\s\S]*workflow-composer-bottom[\s\S]*grid-row: 5)(?=[\s\S]*workflow-composer-bottom\[data-testid="workflow-bottom-run_output"\][\s\S]*min-height: min\(320px, 36vh\))(?=[\s\S]*workflow-run-detail-grid[\s\S]*align-content: start)/,
  "Run Output should have enough default shelf height to show run details without clipping in a maximized workbench",
);

assert.match(
  workflowComposerCss,
  /workflow-composer-bottom[\s\S]*grid-row: 5[\s\S]*grid-template-rows: auto minmax\(0, 1fr\)[\s\S]*align-self: stretch[\s\S]*min-height: 0[\s\S]*overflow: hidden[\s\S]*workflow-bottom-grid[\s\S]*min-height: 0[\s\S]*overflow: auto/,
  "Bottom shelf should dock to the bottom grid row and scroll its contents instead of floating above unused workspace",
);

assert.doesNotMatch(
  workflowComposerCss,
  /workflow-composer-bottom[\s\S]*height: 100%/,
  "Bottom shelf should not use percentage height inside the composer grid because it can inflate the bottom row and steal canvas space",
);

assert.match(
  workflowRailPanel,
  /railSearchQuery[\s\S]*workflowRailSearchModel\([\s\S]*searchQuery: railSearchQuery[\s\S]*WorkflowSearchPanel[\s\S]*workflow-rail-search-input[\s\S]*workflow-rail-search-results[\s\S]*onInspectNode/,
  "Search rail should index nodes, tests, and outputs and let users jump to matching nodes",
);

assert.match(
  `${workflowRailModel}\n${fs.readFileSync(new URL("../../../../../packages/agent-ide/src/runtime/workflow-rail-search-model.ts", import.meta.url), "utf8")}`,
  /workflowRailSearchResults[\s\S]*workflowSelectedNodeBindingSummary[\s\S]*resultKind: "Node"[\s\S]*resultKind: "Test"[\s\S]*resultKind: "Output"[\s\S]*workflowRailSearchModel[\s\S]*actionable/,
  "Search rail indexing should live in the extracted rail model",
);

assert.match(
  workflowRailPanel,
  /outputNodes[\s\S]*workflow-output-node-list[\s\S]*workflow-output-node-\$\{nodeItem\.id\}[\s\S]*renderer-only until materialization or delivery is configured/,
  "Outputs rail should list workflow output nodes when no node is selected",
);

assert.match(
  workflowRailPanel,
  /workflow-settings-summary[\s\S]*workflow-settings-metadata[\s\S]*workflow-settings-model-bindings[\s\S]*workflow-settings-capabilities[\s\S]*workflow-settings-policy/,
  "Settings rail should summarize workflow metadata, bindings, capabilities, readiness, and run policy",
);

assert.match(
  graphTypes,
  /interface GraphEnvironmentProfile[\s\S]*target: GraphEnvironmentTarget[\s\S]*credentialScope\?: string[\s\S]*mockBindingPolicy\?: GraphMockBindingPolicy/,
  "Workflow global config should carry a typed environment profile instead of burying environment semantics in a raw string",
);

assert.match(
  workflowDefaults,
  /environmentProfile:[\s\S]*target: "local"[\s\S]*credentialScope: "local"[\s\S]*mockBindingPolicy: "block"[\s\S]*normalizeGlobalConfig[\s\S]*environmentProfile:/,
  "Workflow defaults should normalize environment target, credential scope, and mock-binding policy",
);

assert.match(
  composer,
  /handleUpdateEnvironmentProfile[\s\S]*setGlobalConfig[\s\S]*environmentProfile[\s\S]*markWorkflowDirty\(\)[\s\S]*Environment profile updated/,
  "Environment profile edits should update typed workflow config and dirty readiness state",
);

for (const selector of [
  "workflow-environment-profile",
  "workflow-environment-target",
  "workflow-environment-credential-scope",
  "workflow-environment-mock-policy",
  "workflow-settings-binding-registry",
  "workflow-binding-registry-summary",
  "workflow-binding-manifest",
  "workflow-generate-binding-manifest",
  "workflow-binding-manifest-summary",
] as const) {
  assert.match(
    workflowRailPanel,
    new RegExp(escapeRegExp(selector)),
    `Settings rail should expose ${selector}`,
  );
}

assert.match(
  `${workflowSettingsModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*workflowBindingRegistryRows\(workflow\))(?=[\s\S]*workflowBindingRegistrySummary\(bindingRegistryRows\))(?=[\s\S]*workflow-binding-registry-row-\$\{row\.nodeItem\.id\})(?=[\s\S]*workflow-binding-check-\$\{row\.id\})(?=[\s\S]*workflow-binding-check-result-\$\{row\.id\})/,
  "Settings rail should render binding registry rows from the extracted settings model",
);

assert.match(
  workflowRailModel,
  /workflowBindingRegistryRows[\s\S]*modelBinding[\s\S]*connectorBinding[\s\S]*toolBinding[\s\S]*parserBinding/,
  "Settings rail should summarize model, connector, tool, and parser bindings with click-through node inspection",
);

assert.match(
  workflowRailModel,
  /workflowBindingCheckResult[\s\S]*mockBindingPolicy[\s\S]*Live binding contract is ready[\s\S]*No hidden vendor connectivity probe was run[\s\S]*Workflow tool needs a child workflow/,
  "Binding checks should validate typed config honestly without faking external connector probes",
);

assert.match(
  graphRuntimeTypes,
  /checkWorkflowBinding\?\([\s\S]*nodeId[\s\S]*bindingId\?\:[\s\S]*Promise<WorkflowBindingCheckResult>[\s\S]*generateWorkflowBindingManifest\?\([\s\S]*Promise<WorkflowBindingManifest>[\s\S]*loadWorkflowBindingManifest\?\([\s\S]*Promise<WorkflowBindingManifest \| null>/,
  "Binding checks and binding manifests should be part of the typed workflow runtime API",
);

assert.match(
  tauriRuntime,
  /async checkWorkflowBinding[\s\S]*invoke\(\"check_workflow_binding\"[\s\S]*bindingId: bindingId \?\? null[\s\S]*async generateWorkflowBindingManifest[\s\S]*invoke\(\"generate_workflow_binding_manifest\"[\s\S]*async loadWorkflowBindingManifest[\s\S]*invoke\(\"load_workflow_binding_manifest\"/,
  "Desktop runtime should call typed binding commands instead of keeping checks UI-local",
);

assert.match(
  tauriLib,
  /project::check_workflow_binding[\s\S]*project::generate_workflow_binding_manifest[\s\S]*project::load_workflow_binding_manifest/,
  "Tauri command registry should expose binding checks and manifests to the GUI harness",
);

assert.match(
  projectCommands,
  /pub fn check_workflow_binding[\s\S]*kind: \"binding_check\"[\s\S]*path: None[\s\S]*pub fn generate_workflow_binding_manifest[\s\S]*save_workflow_binding_manifest[\s\S]*kind: \"binding_manifest\"[\s\S]*path: None/,
  "Binding checks and manifests should record hidden runtime evidence without surfacing sidecar paths in product UI",
);

assert.match(
  graphRuntimeTypes,
  /restoreWorkflowRevision\?\([\s\S]*WorkflowRevisionRestoreRequest[\s\S]*Promise<WorkflowRevisionRestoreResult>/,
  "Workflow runtime should expose a typed restore API for git-backed harness revision rollback",
);

assert.match(
  tauriRuntime,
  /async restoreWorkflowRevision[\s\S]*invoke\(\"restore_workflow_revision\"[\s\S]*request/,
  "Desktop runtime should call the git-backed workflow revision restore command",
);

assert.match(
  tauriLib,
  /project::save_workflow_project[\s\S]*project::restore_workflow_revision[\s\S]*project::save_workflow_tests/,
  "Tauri command registry should expose restore_workflow_revision beside workflow persistence",
);

assert.match(
  projectCommands,
  /pub fn restore_workflow_revision[\s\S]*unsupported_revision_source[\s\S]*git_show_file_bytes[\s\S]*workflow_project_content_hash[\s\S]*workflow_content_hash_mismatch[\s\S]*hash_verified[\s\S]*git_show_file_restore[\s\S]*load_workflow_bundle_from_path/,
  "Git-backed rollback should restore one workflow JSON file through git show and reload the typed workbench bundle",
);

assert.match(
  projectCommands,
  /workflow_restore_canary_receipt_binding_ref[\s\S]*workflow\.restore-canary\.receipt-binding\.v1[\s\S]*receipt_binding_ref[\s\S]*WorkflowRevisionRestoreResult/,
  "Git-backed rollback restore should return durable restore-canary receipt binding refs.",
);

assert.match(
  projectCommands,
  /if request\.dry_run[\s\S]*dry_run: true[\s\S]*WorkflowWorkbenchBundle[\s\S]*workflow: restored_workflow/,
  "Git-backed rollback should support a non-mutating dry-run restore canary with a parsed workflow bundle.",
);

assert.match(
  composer,
  /handleExecuteHarnessRollback[\s\S]*rollbackRevisionBinding[\s\S]*restoreResult[\s\S]*restoreBlockers[\s\S]*runtime\.restoreWorkflowRevision[\s\S]*executeWorkflowHarnessRevisionRollback[\s\S]*restoredWorkflow[\s\S]*restoreResult[\s\S]*restoreBlockers/,
  "Rollback execution should restore the selected git revision and preserve blocked restore proof before applying verified harness rollback metadata",
);

assert.match(
  composer,
  /handleRunHarnessActivationDryRun[\s\S]*rollbackRevisionBinding[\s\S]*runWorkflowHarnessRollbackRestoreCanaryProbe[\s\S]*runtime[\s\S]*workflowPath[\s\S]*rollbackRevisionBinding[\s\S]*rollbackRestoreResult[\s\S]*rollbackRestoreBlockers/,
  "Activation dry run should run a non-mutating restore canary for git-backed rollback revisions before minting.",
);

assert.match(
  harnessWorkflow,
  /(?=[\s\S]*runWorkflowHarnessRollbackRestoreCanaryProbe)(?=[\s\S]*revisionSource !== "git")(?=[\s\S]*dryRun: true)(?=[\s\S]*rollback_restore_api_unavailable)(?=[\s\S]*runtime\.restoreWorkflowRevision\(restoreRequest\))(?=[\s\S]*rollback_restore_canary_failed)/,
  "Git-backed rollback restore canary probes should execute through one reusable dry-run helper with explicit blocked paths.",
);

assert.match(
  composer,
  /generateWorkflowBindingManifest[\s\S]*setBindingManifest[\s\S]*bindingManifest=\{bindingManifest\}[\s\S]*onGenerateBindingManifest=\{handleGenerateBindingManifest\}/,
  "Workflow Settings should generate binding manifests through the runtime and render manifest state without writing UI state into the graph",
);

assert.match(
  workflowRailPanel,
  /workflow-readiness-summary[\s\S]*workflow-readiness-attention[\s\S]*workflow-readiness-attention-\$\{index\}[\s\S]*onResolveIssue\(issue\)[\s\S]*workflow-readiness-checklist[\s\S]*workflow-readiness-capability-preflight[\s\S]*workflow-readiness-capability-repair-\$\{action\.kind\}-\$\{row\.nodeId\}[\s\S]*onCapabilityRepairAction\?\.\(action\)[\s\S]*workflow-readiness-blockers[\s\S]*onResolveIssue\(issue\)[\s\S]*workflow-readiness-warnings[\s\S]*workflow-readiness-warning-\$\{index\}[\s\S]*onResolveIssue\(issue\)[\s\S]*workflow-readiness-policy-nodes[\s\S]*onInspectNode/,
  "Readiness rail should summarize launch checks and make blockers/policy-required nodes actionable",
);

assert.match(
  `${workflowComposerTypes}\n${controller}\n${shellContent}\n${workflowsView}\n${composer}\n${workflowRailPanel}`,
  /(?=[\s\S]*WorkflowComposerPreflightSeed)(?=[\s\S]*preflightSeed\?: WorkflowComposerPreflightSeed)(?=[\s\S]*workflowPreflightSeed)(?=[\s\S]*openWorkflowPreflight)(?=[\s\S]*controller\.workflow\.openPreflight)(?=[\s\S]*preflightSeed=\{workflowPreflightSeed\})(?=[\s\S]*workflowPreflightFocus)(?=[\s\S]*workflow-readiness-capability-preflight)(?=[\s\S]*data-focus-capability-ref)(?=[\s\S]*data-focused=\{focused\})/,
  "Authority Center workflow handoffs should open Workflows readiness with a focused capability preflight seed instead of creating shell-side workflow truth.",
);

assert.match(
  composer,
  /handleResolveWorkflowIssue[\s\S]*missing_output_node[\s\S]*setNodeGroupFilter\("Outputs"\)[\s\S]*openLeftDrawer\(\)[\s\S]*missing_start_node[\s\S]*setNodeGroupFilter\("Start"\)[\s\S]*missing_unit_tests[\s\S]*setTestEditorOpen\(true\)[\s\S]*missing_error_handling_path[\s\S]*setNodeGroupFilter\("Flow"\)[\s\S]*mock_binding_active[\s\S]*setRightPanel\("settings"\)/,
  "Readiness blocker actions should open the concrete authoring surface needed to resolve each workflow gap",
);

assert.match(
  composer,
  /(?=[\s\S]*workflowValidationStatusMessage[\s\S]*passed with[\s\S]*warning)(?=[\s\S]*setStatusMessage\(workflowValidationStatusMessage\("Validation", result\)\))(?=[\s\S]*setStatusMessage\(workflowValidationStatusMessage\("Readiness", result\)\))(?=[\s\S]*workflowChecksStatusMessage[\s\S]*Run checks passed)(?=[\s\S]*validationWarningCount)/,
  "Readiness and workflow-check status copy should distinguish clean passes from passes with warnings",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}`,
  /workflowReadinessStatusLabel[\s\S]*passed with warnings[\s\S]*workflowReadinessStatusLabel\(result\)/,
  "Readiness rail status should not summarize warning-bearing readiness as a clean pass",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}\n${workflowBottomShelf}`,
  /workflowWorkbenchCheckTitle[\s\S]*Run checks[\s\S]*workflowWorkbenchCheckSummary[\s\S]*checked through the workbench[\s\S]*workflowWorkbenchCheckTitle\(dogfoodRun\.status\)/,
  "Automation-backed validation summaries should use product run-check language rather than harness jargon",
);

assert.doesNotMatch(
  workflowComposerUi,
  /Workflow checks/,
  "Visible workflow surfaces should not expose generic workflow-check harness copy",
);

assert.match(
  `${workflowEntrypointsModel}\n${workflowRailPanel}`,
  /sourceRows[\s\S]*triggerRows[\s\S]*workflow-sources-list[\s\S]*workflow-source-node-\$\{row\.node\.id\}[\s\S]*onInspectNode/,
  "Sources rail should list source and trigger start points with click-through inspection",
);

assert.match(
  `${workflowFileBundleModel}\n${workflowRailPanel}`,
  /workflowFileBundleItems\([\s\S]*workflow,[\s\S]*tests,[\s\S]*proposals,[\s\S]*runs,[\s\S]*portablePackage,[\s\S]*bindingManifest,[\s\S]*\)[\s\S]*workflow-files-list/,
  "Files rail should show workflow bundle sidecars and portable package status",
);

assert.match(
  workflowRailModel,
  /workflowFileBundleItems[\s\S]*Workflow graph[\s\S]*Tests sidecar[\s\S]*Proposal sidecar[\s\S]*Run sidecar[\s\S]*Binding manifest[\s\S]*Portable package/,
  "Workflow bundle file rows should live in the extracted rail model",
);

assert.match(
  `${workflowEntrypointsModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*triggerRows)(?=[\s\S]*cronSchedule)(?=[\s\S]*eventSourceRef)(?=[\s\S]*workflow-schedules-list)(?=[\s\S]*workflow-schedule-node-\$\{row\.node\.id\})/,
  "Schedules rail should show trigger readiness for manual, scheduled, and event starts",
);

assert.match(
  workflowRailPanel,
  /onSelectProposal[\s\S]*workflow-changes-list[\s\S]*workflow-change-proposal-\$\{proposal\.id\}[\s\S]*boundedTargets/,
  "Changes rail should list bounded proposals and open the proposal preview without applying changes",
);

assert.match(
  workflowRailPanel,
  /unitTestSearchQuery[\s\S]*workflow-unit-test-search-input[\s\S]*workflow-unit-test-summary[\s\S]*workflow-unit-test-list[\s\S]*workflow-unit-test-target-\$\{test\.id\}[\s\S]*workflow-unit-test-uncovered/,
  "Unit Tests rail should search tests, summarize coverage, and jump to covered or uncovered nodes",
);

assert.match(
  workflowRailModel,
  /workflowSelectedNodeBindingSummary[\s\S]*model_call[\s\S]*connectorBinding[\s\S]*toolBinding[\s\S]*functionBinding[\s\S]*deliveryTarget/,
  "Selected-node inspector should summarize node-specific binding and output configuration",
);

assert.match(
  `${workflowNodeBindingEditor}\n${workflowNodeBindingEditorSections}`,
  /(?=[\s\S]*OUTPUT_FORMAT_OPTIONS)(?=[\s\S]*OUTPUT_RENDERER_OPTIONS)(?=[\s\S]*OUTPUT_DISPLAY_MODE_OPTIONS)(?=[\s\S]*<select[\s\S]*data-testid="workflow-output-format")(?=[\s\S]*<select[\s\S]*data-testid="workflow-output-renderer")(?=[\s\S]*<select[\s\S]*data-testid="workflow-output-display-mode")/,
  "Output node configuration should use typed format, renderer, and display choices instead of free-text runtime ontology fields",
);

assert.match(
  workflowComposerUi,
  /selectedUpstreamReferences[\s\S]*workflow-upstream-references[\s\S]*workflow-upstream-field-picker[\s\S]*workflow-map-upstream-field[\s\S]*workflow-insert-upstream-reference[\s\S]*workflow-config-section-mapping[\s\S]*workflow-field-mapping-workbench[\s\S]*workflow-upstream-schema-preview/,
  "Node details should expose upstream field references, schema field picking, and schema previews for mapping between connected nodes",
);

assert.match(
  workflowComposerUi,
  /\{\{nodes\.\$\{sourceData\.id\}\.\$\{portId\}\}\}[\s\S]*applyUpstreamFieldReference[\s\S]*source: reference\.expression[\s\S]*path: field\.path[\s\S]*inputMapping[\s\S]*fieldMappings/,
  "Upstream mapping should use explicit node/port expressions and structured field paths instead of lexical prompt shortcuts",
);

assert.match(
  workflowValidation,
  /workflowExpressionReferences[\s\S]*validateWorkflowExpressionReferences[\s\S]*fieldMappings[\s\S]*missing_expression_node[\s\S]*missing_expression_port[\s\S]*unconnected_expression_ref[\s\S]*invalid_expression_connection[\s\S]*missing_field_mapping_path/,
  "Workflow expression and field mapping references should be validated against typed graph nodes, ports, incoming edges, and upstream schemas",
);

assert.match(
  composer,
  /from "\.\.\/runtime\/workflow-defaults"[\s\S]*from "\.\.\/runtime\/workflow-schema"[\s\S]*from "\.\.\/runtime\/workflow-validation"/,
  "WorkflowComposer should consume extracted workflow defaults, schema, and validation modules instead of owning those runtime concerns",
);

assert.match(
  workflowDefaults,
  /DEFAULT_GLOBAL_CONFIG[\s\S]*normalizeGlobalConfig[\s\S]*makeDefaultWorkflow/,
  "Workflow defaults should live in the runtime defaults module",
);

assert.match(
  graphTypes,
  /(?=[\s\S]*WorkflowHarnessExecutionMode)(?=[\s\S]*WorkflowHarnessComponentReadiness)(?=[\s\S]*WorkflowHarnessReplayEnvelope)(?=[\s\S]*WorkflowHarnessActionFrame)(?=[\s\S]*WorkflowHarnessComponentInvocation)(?=[\s\S]*WorkflowHarnessComponentAdapterResult)(?=[\s\S]*WorkflowHarnessNodeAttemptRecord)(?=[\s\S]*WorkflowHarnessShadowComparison)(?=[\s\S]*WorkflowHarnessPromotionCluster)(?=[\s\S]*WorkflowHarnessGatedClusterRun)(?=[\s\S]*WorkflowRevisionBinding)(?=[\s\S]*WorkflowRevisionRestoreRequest)(?=[\s\S]*WorkflowRevisionRestoreResult)(?=[\s\S]*git_show_file_restore)(?=[\s\S]*workflowContentHash)(?=[\s\S]*actualWorkflowContentHash)(?=[\s\S]*hashVerified)(?=[\s\S]*rollbackRevision)(?=[\s\S]*WorkflowHarnessForkActivationCandidate)(?=[\s\S]*revisionBindingPreview: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationAuditEvent)(?=[\s\S]*previousRevisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationRollbackProof)(?=[\s\S]*activeRevisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationRollbackExecution)(?=[\s\S]*activationAudit\?: WorkflowHarnessActivationAuditEvent\[\])(?=[\s\S]*activationRollbackProof\?: WorkflowHarnessActivationRollbackProof)(?=[\s\S]*activationRollbackExecution\?: WorkflowHarnessActivationRollbackExecution)(?=[\s\S]*revisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessLiveHandoffProof)(?=[\s\S]*WorkflowHarnessRuntimeSelectorDecision)(?=[\s\S]*WorkflowHarnessCanaryExecutionBoundary)(?=[\s\S]*canaryExecutionBoundaries)(?=[\s\S]*WorkflowHarnessComponentSpec[\s\S]*readiness[\s\S]*inputSchema[\s\S]*outputSchema[\s\S]*errorSchema)(?=[\s\S]*WorkflowHarnessWorkerBinding[\s\S]*harnessWorkflowId[\s\S]*harnessActivationId[\s\S]*harnessHash)/,
  "Harness-as-workflow types should expose mode, readiness, replay, callable adapter envelopes, node attempts, shadow comparison, gated clusters, workflow revision binding, activation audit history, rollback drill proof, live handoff, selector routing, canary execution boundaries, durable component contracts, and worker harness identity fields",
);

assert.match(
  graphTypes,
  /(?=[\s\S]*WorkflowRevisionRestoreRequest[\s\S]*dryRun\?: boolean)(?=[\s\S]*WorkflowRevisionRestoreResult[\s\S]*dryRun\?: boolean)(?=[\s\S]*WorkflowHarnessRollbackRestoreCanary)(?=[\s\S]*rollbackRestoreCanary: WorkflowHarnessRollbackRestoreCanary)/,
  "Harness activation contract should carry dry-run restore requests and rollback restore canary proof.",
);

assert.match(
  graphTypes,
  /WorkflowRevisionRestoreResult[\s\S]*receiptBindingRef\?: string[\s\S]*WorkflowHarnessRollbackRestoreCanary[\s\S]*receiptBindingRef\?: string[\s\S]*evidenceRefs/,
  "Harness activation contract should carry backend restore-canary receipt refs through activation evidence.",
);

assert.match(
  graphTypes,
  /WorkflowHarnessActivationAuditEvent[\s\S]*receiptRefs: string\[\][\s\S]*WorkflowHarnessActivationRollbackExecution[\s\S]*receiptRefs: string\[\][\s\S]*restoreReceiptBindingRef\?: string/,
  "Harness activation contract should carry restore-canary receipt refs through audit and rollback execution evidence.",
);

assert.match(
  harnessWorkflow,
  /DEFAULT_HARNESS_EXECUTION_MODE[\s\S]*HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*cognition[\s\S]*DEFAULT_AGENT_HARNESS_COMPONENTS[\s\S]*kind: "planner"[\s\S]*kind: "prompt_assembler"[\s\S]*kind: "mcp_provider"[\s\S]*kind: "mcp_tool_call"[\s\S]*kind: "receipt_writer"[\s\S]*defaultHarnessPromotionClusters[\s\S]*requiredExecutionMode: "gated"[\s\S]*makeDefaultAgentHarnessWorkflow[\s\S]*readOnly: true/,
  "Default Agent Harness projection should componentize planner, prompt assembly, MCP providers/tools, receipts, gated clusters, and expose a read-only workflow graph",
);

assert.match(
  harnessWorkflow,
  /(?=[\s\S]*forkDefaultAgentHarnessWorkflow[\s\S]*proposal-\$\{slug\}-activation-gates[\s\S]*forkedFrom[\s\S]*activationState: "blocked"[\s\S]*activationRecord)(?=[\s\S]*workflowRevisionBindingFor)(?=[\s\S]*workflowSourceProjection)(?=[\s\S]*stableContentHash)(?=[\s\S]*recordWorkflowHarnessActivationDryRun)(?=[\s\S]*recordWorkflowHarnessRollbackTargetSelection)(?=[\s\S]*executeWorkflowHarnessRollbackDrill)(?=[\s\S]*rollback_drill_restored_previous_worker_binding)(?=[\s\S]*executeWorkflowHarnessRevisionRollback)(?=[\s\S]*restoredWorkflow)(?=[\s\S]*git_show_file_restore)(?=[\s\S]*rollback_execution_restored_verified_workflow_revision)(?=[\s\S]*rollback_executed)(?=[\s\S]*activationRollbackExecution)(?=[\s\S]*activeRevisionBinding)(?=[\s\S]*restoredRevisionBinding)(?=[\s\S]*applyWorkflowHarnessActivationCandidate)(?=[\s\S]*activation_mint_blocked)(?=[\s\S]*activation_minted)(?=[\s\S]*candidate_not_mintable)(?=[\s\S]*activationState: "validated")(?=[\s\S]*workerHarnessBinding: workerBinding)(?=[\s\S]*revisionBinding)(?=[\s\S]*rollbackRevisionBinding)(?=[\s\S]*componentVersionSet: candidate\.componentVersionSet)/,
  "Forking the Default Agent Harness should create editable lineage metadata, package proposal sidecars, workflow revision bindings, audited dry runs, guarded candidate activation minting, and rollback drill proof",
);

assert.match(
  harnessWorkflow,
  /(?=[\s\S]*activationCandidateReceiptRefs)(?=[\s\S]*recordWorkflowHarnessActivationDryRun[\s\S]*receiptRefs)(?=[\s\S]*activation_mint_blocked[\s\S]*receiptRefs)(?=[\s\S]*activation_minted[\s\S]*receiptRefs)(?=[\s\S]*workflowRollbackReceiptRefs)(?=[\s\S]*executeWorkflowHarnessRollbackDrill[\s\S]*receiptRefs)(?=[\s\S]*executeWorkflowHarnessRevisionRollback[\s\S]*restoreReceiptBindingRef)/,
  "Fork activation and rollback proof should preserve restore-canary receipt continuity.",
);

assert.match(
	  workflowValidation,
	  /(?=[\s\S]*workflowIsHarnessFork)(?=[\s\S]*harness_required_slot_unbound)(?=[\s\S]*harness_activation_not_validated)(?=[\s\S]*harness_self_mutation_not_proposal_only)(?=[\s\S]*harness_fork_mutation_canary_not_passed)(?=[\s\S]*harness_package_manifest_incomplete)(?=[\s\S]*workflowHarnessPackageEvidenceReview)(?=[\s\S]*gateId: "mutation-canary")(?=[\s\S]*gateId: "package-evidence")/,
  "Harness activation readiness should block invalid forks, unbound slots, missing activation ids, incomplete package manifests, and direct AI self-mutation",
);

assert.match(
  workflowValidation,
  /(?=[\s\S]*workflowHarnessRollbackRestoreCanaryFor)(?=[\s\S]*rollback_restore_canary_not_run)(?=[\s\S]*rollback_restore_canary_hash_mismatch)(?=[\s\S]*gateId: "rollback-restore")(?=[\s\S]*rollbackRestoreCanary)/,
  "Harness activation candidates should block git-backed forks until rollback restore canary proof passes.",
);

assert.match(
  workflowComposerUi,
  /(?=[\s\S]*workflow-open-default-harness)(?=[\s\S]*handleOpenDefaultHarness)(?=[\s\S]*workflow-fork-harness-button)(?=[\s\S]*handleForkDefaultHarness)(?=[\s\S]*handleRunHarnessActivationDryRun)(?=[\s\S]*recordWorkflowHarnessActivationDryRun)(?=[\s\S]*handleApplyHarnessActivationCandidate)(?=[\s\S]*handleRunHarnessRollbackDrill)(?=[\s\S]*executeWorkflowHarnessRollbackDrill)(?=[\s\S]*handleExecuteHarnessRollback)(?=[\s\S]*executeWorkflowHarnessRevisionRollback)(?=[\s\S]*handleSelectHarnessRollbackTarget)(?=[\s\S]*workflow-readonly-badge)(?=[\s\S]*workflow-harness-worker-binding)(?=[\s\S]*workflow-harness-authority-gate-badge)/,
  "Workflow GUI should expose a read-only Default Agent Harness view, an editable fork path, worker harness identity, audited dry runs, rollback target selection, activation minting, rollback drills, and authority gate live state",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-settings-harness-summary)(?=[\s\S]*Mode)(?=[\s\S]*Live-ready)(?=[\s\S]*Gated clusters)(?=[\s\S]*Authority gates)(?=[\s\S]*workflow-harness-authority-gate-status)(?=[\s\S]*Authority gate live)(?=[\s\S]*workflow-harness-worker-binding-inspector)(?=[\s\S]*workflow-harness-worker-binding-summary)(?=[\s\S]*workflow-harness-worker-binding-picker)(?=[\s\S]*workflow-harness-worker-binding-option-current)(?=[\s\S]*workflow-harness-worker-binding-option-candidate)(?=[\s\S]*workflow-harness-worker-binding-option-rollback)(?=[\s\S]*workflow-harness-worker-binding-rollback-targets)(?=[\s\S]*workflow-harness-worker-binding-rollback-target-\$\{index\})(?=[\s\S]*workflow-harness-worker-binding-apply-candidate)(?=[\s\S]*workflow-harness-worker-binding-run-rollback-drill)(?=[\s\S]*workflow-harness-worker-binding-execute-rollback)(?=[\s\S]*workflow-harness-rollback-drill-proof)(?=[\s\S]*workflow-harness-rollback-execution-proof)(?=[\s\S]*workflow-harness-git-restore-proof)(?=[\s\S]*workflow-harness-git-restore-summary)(?=[\s\S]*workflow-harness-git-restore-paths)(?=[\s\S]*workflow-harness-git-restore-hashes)(?=[\s\S]*workflow-harness-git-restore-blockers)(?=[\s\S]*workflow-harness-revision-binding)(?=[\s\S]*workflow-harness-revision-binding-current)(?=[\s\S]*workflow-harness-revision-binding-candidate)(?=[\s\S]*workflow-harness-revision-binding-rollback)(?=[\s\S]*harnessRevisionBinding)(?=[\s\S]*harnessCandidateRevisionBinding)(?=[\s\S]*harnessRollbackRevisionBinding)(?=[\s\S]*harnessActivationRollbackExecution)(?=[\s\S]*workflow-harness-activation-audit)(?=[\s\S]*workflow-harness-activation-audit-list)(?=[\s\S]*workflow-harness-activation-audit-event-\$\{event\.eventId\})(?=[\s\S]*workflow-harness-worker-binding-version-set)(?=[\s\S]*harnessBindingVersionSet)(?=[\s\S]*harnessBindingRollbackTarget)(?=[\s\S]*harnessSelectedRollbackTarget)(?=[\s\S]*harnessActivationAudit)(?=[\s\S]*harnessActivationRollbackProof)(?=[\s\S]*workflow-harness-activation-wizard)(?=[\s\S]*workflow-harness-activation-candidate)(?=[\s\S]*workflow-harness-activation-candidate-empty)(?=[\s\S]*workflow-harness-activation-candidate-gates)(?=[\s\S]*workflow-harness-activation-dry-run)(?=[\s\S]*workflow-harness-activation-step-\$\{step\.id\})(?=[\s\S]*id: "slots")(?=[\s\S]*id: "tests")(?=[\s\S]*id: "replay-fixtures")(?=[\s\S]*id: "policy-posture")(?=[\s\S]*id: "receipt-coverage")(?=[\s\S]*id: "package-evidence")(?=[\s\S]*id: "canary")(?=[\s\S]*id: "rollback")(?=[\s\S]*id: "activation-id")(?=[\s\S]*id: "worker-binding")(?=[\s\S]*workflow-harness-slots)(?=[\s\S]*workflow-harness-promotion-clusters)(?=[\s\S]*workflow-harness-fork-component-diff)(?=[\s\S]*workflow-harness-fork-component-diff-summary)(?=[\s\S]*workflow-harness-default-runtime-dispatch)(?=[\s\S]*workflow-harness-authority-gate-live)(?=[\s\S]*workflow-harness-authority-gate-summary)(?=[\s\S]*workflow-harness-authority-gate-rollup)(?=[\s\S]*workflow-harness-authority-gate-list)(?=[\s\S]*workflow-selected-node-authority-gate-live)(?=[\s\S]*workflow-selected-node-authority-gate-list)(?=[\s\S]*policy_gate)(?=[\s\S]*destructive-denial)(?=[\s\S]*approval_gate)(?=[\s\S]*workflow-harness-read-only-routing-proof)(?=[\s\S]*workflow-harness-read-only-routing-node-kinds)(?=[\s\S]*workflow-harness-read-only-routing-receipts)(?=[\s\S]*workflow-run-harness-timeline)(?=[\s\S]*workflow-run-harness-timeline-node-\$\{attempt\.attemptId\})(?=[\s\S]*workflow-run-harness-shadow-comparison)(?=[\s\S]*workflow-harness-node-attempt-inspector)(?=[\s\S]*workflow-harness-live-shadow-comparison-inspector)(?=[\s\S]*data-shadow-attempt-id)(?=[\s\S]*data-live-replay-fixture-ref)(?=[\s\S]*data-harness-workflow-id)(?=[\s\S]*data-replay-fixture-ref)(?=[\s\S]*workflow-selected-node-harness-component)(?=[\s\S]*workflow-selected-node-harness-receipts)(?=[\s\S]*workflow-selected-node-replay-binding)(?=[\s\S]*workflow-selected-node-harness-attempt)(?=[\s\S]*workflow-selected-node-read-only-routing-proof)(?=[\s\S]*workflow-selected-node-read-only-routing-receipts)(?=[\s\S]*workflow-selected-node-read-only-routing-no-mutation)(?=[\s\S]*replayEnvelope)/,
  "Workflow rail should render harness mode, readiness, activation wizard gates, activation candidates, rollback target selection, mint action, rollback drill proof, workflow revision binding posture, activation audit history, slots, promotion clusters, fork component diffs, default dispatch, authority gate live proof, read-only routing proof, component ids, receipt mappings, replay metadata, node attempts, no-mutation proof, and shadow comparison at node level",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-cognition-node-authority-mode)(?=[\s\S]*data-cognition-node-authority-authoritative)(?=[\s\S]*data-cognition-node-authority-policy-decision)(?=[\s\S]*data-cognition-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose node-authoritative cognition gate state, policy, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-routing-model-node-authority-mode)(?=[\s\S]*data-routing-model-node-authority-authoritative)(?=[\s\S]*data-routing-model-node-authority-policy-decision)(?=[\s\S]*data-routing-model-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose gated node-authoritative routing/model gate state, policy, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-verification-output-node-authority-mode)(?=[\s\S]*data-verification-output-node-authority-authoritative)(?=[\s\S]*data-verification-output-node-authority-policy-decision)(?=[\s\S]*data-verification-output-node-authority-visible-write-committed)(?=[\s\S]*data-verification-output-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose gated node-authoritative verification/output gate state, visible-write readiness, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-authority-tooling-node-authority-mode)(?=[\s\S]*data-authority-tooling-node-authority-authoritative)(?=[\s\S]*data-authority-tooling-node-authority-policy-decision)(?=[\s\S]*data-authority-tooling-node-authority-read-only-route-accepted)(?=[\s\S]*data-authority-tooling-node-authority-destructive-route-denied)(?=[\s\S]*data-authority-tooling-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose gated node-authoritative authority/tooling gate state, route decisions, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-harness-authority-gate-list)(?=[\s\S]*gateTestIdPrefix: "workflow-harness-authority-gate")(?=[\s\S]*gateTestIdPrefix: "workflow-selected-node-authority-gate")(?=[\s\S]*\$\{options\.gateTestIdPrefix\}-\$\{gate\.id\})(?=[\s\S]*\$\{options\.gateTestIdPrefix\}-component-\$\{gate\.id\})(?=[\s\S]*\$\{options\.gateTestIdPrefix\}-receipt-\$\{gate\.id\})(?=[\s\S]*\$\{options\.gateTestIdPrefix\}-replay-\$\{gate\.id\})(?=[\s\S]*policyDecision)(?=[\s\S]*componentId)(?=[\s\S]*runId)(?=[\s\S]*replayFixtureRefs)/,
  "Authority gate proof rows should expose component, run, policy decision, receipt, and replay deep links for global and selected-node inspectors",
);

assert.match(
  `${engineDetailPane}\n${localEngineSupport}`,
  /worker-harness-binding[\s\S]*harnessWorkflowId[\s\S]*harnessActivationId[\s\S]*harnessHash[\s\S]*DEFAULT_AGENT_HARNESS_WORKFLOW_ID[\s\S]*DEFAULT_AGENT_HARNESS_ACTIVATION_ID[\s\S]*DEFAULT_AGENT_HARNESS_HASH/,
  "Worker workflow records should expose harness workflow id, activation id, and harness hash in Autopilot inspection surfaces",
);

assert.match(
  workflowSchema,
  /schemaFromSample[\s\S]*workflowOutputBundleSchema[\s\S]*workflowNodeHasDeclaredOutputSchema[\s\S]*workflowNodeDeclaredOutputSchema[\s\S]*node\.type === "output"[\s\S]*workflowNodeDeclaredInputSchema[\s\S]*workflowSchemaFieldReferences/,
  "Workflow schema inference, output-bundle schema, declared-schema posture, and field references should live in the runtime schema module",
);

assert.match(
  workflowComposerUi,
  /workflow-tool-kind[\s\S]*workflow_tool[\s\S]*workflow-tool-child-path[\s\S]*workflow-tool-timeout-ms[\s\S]*workflow-tool-max-attempts[\s\S]*workflow-tool-argument-schema[\s\S]*workflow-tool-result-schema/,
  "Plugin tool configuration should support workflow-as-tool bindings with schema-bound arguments/results and retry settings",
);

assert.match(
  graphTypes,
  /WorkflowToolBindingKind =\s*\|\s*"plugin_tool"\s*\|\s*"mcp_tool"\s*\|\s*"native_tool"\s*\|\s*"workflow_tool"[\s\S]*workflowTool\?:/,
  "Workflow tool bindings should include a typed workflow_tool variant",
);

assert.match(
  workflowComposerUi,
  /nodeFixturesById[\s\S]*listWorkflowNodeFixtures[\s\S]*saveWorkflowNodeFixture[\s\S]*handlePinNodeFixture[\s\S]*workflow-capture-node-fixture[\s\S]*workflow-dry-run-node-fixture[\s\S]*workflow-fixture-list[\s\S]*workflow-fixture-pin[\s\S]*workflow-fixture-replay[\s\S]*workflow-bottom-capture-fixture[\s\S]*workflow-bottom-fixture-list[\s\S]*workflow-bottom-fixture-pin[\s\S]*workflow-bottom-fixture-replay/,
  "Node fixtures should be sidecar-backed authoring state with explicit capture, pin, selection, and replay controls",
);

assert.match(
  workflowFixtureModel,
  /workflowOutputBundleSchema[\s\S]*workflowFixtureHashesForNode[\s\S]*workflowFixtureValidationForNode[\s\S]*workflowFixtureWithFreshness[\s\S]*schemaHash[\s\S]*nodeConfigHash[\s\S]*validationStatus[\s\S]*workflowFixturesForNode[\s\S]*pinned[\s\S]*workflowFixtureSourceLabel/,
  "Node fixture staleness, output-bundle validation, schema validation, pin ordering, and grouping should live in the extracted fixture model",
);

assert.match(
  workflowBottomShelf,
  /workflowNodeHasDeclaredOutputSchema[\s\S]*hasDeclaredOutputSchema[\s\S]*workflow-bottom-fixture-stale[\s\S]*workflowFixtureSourceLabel[\s\S]*workflow-bottom-fixture-validation[\s\S]*workflow-bottom-fixture-input[\s\S]*workflow-bottom-fixture-output/,
  "Bottom fixture shelf should show declared-schema posture, deterministic staleness, validation status, source metadata, and separate input/output previews",
);

assert.match(
  workflowComposerUi,
  /handleImportNodeFixture[\s\S]*saveWorkflowNodeFixture[\s\S]*workflow-import-fixture-json[\s\S]*workflow-import-node-fixture/,
  "Node details should import typed fixture samples through the sidecar fixture API",
);

assert.match(
  scratchProbe,
  /(?=[\s\S]*FIXTURE_VALIDATION_STATUSES)(?=[\s\S]*freshFixtureInputCount)(?=[\s\S]*freshFixturePinnedCount)(?=[\s\S]*fixtureValidationStatuses)(?=[\s\S]*summary\.get\("freshFixtureInputCount", 0\) > 0)(?=[\s\S]*summary\.get\("fixtureValidationStatuses"\))/,
  "Desktop workflow dogfood should require fresh fixture input, pin, and validation evidence in the sidecar summary",
);

assert.match(
  workflowComposerUi,
  /handleCaptureNodeFixture[\s\S]*const run = nodeRunStatusById\[node\.id\][\s\S]*run\?\.input[\s\S]*logic\.functionBinding\?\.testInput[\s\S]*output: run\?\.output/,
  "Capture latest fixture should preserve the actual node-run input/output sample before falling back to configured test input",
);

assert.match(
  composer,
  /fixtureNodeRun\.input[\s\S]*fixtureNode\.config\?\.logic\.functionBinding\?\.testInput[\s\S]*output: fixtureNodeRun\.output/,
  "Scratch dogfood fixture capture should persist the real run input/output sample, not only configured node defaults",
);

assert.match(
  `${composer}\n${workflowRailReadinessPanel}\n${workflowValidation}\n${workflowReadinessModel}`,
  /(?=[\s\S]*id: "readiness")(?=[\s\S]*Readiness)(?=[\s\S]*handleCheckReadiness)(?=[\s\S]*validateWorkflowExecutionReadiness)(?=[\s\S]*Trigger or source)(?=[\s\S]*Model binding)(?=[\s\S]*Live bindings for activation)(?=[\s\S]*Outputs defined)(?=[\s\S]*Tests present)/,
  "The workbench should expose activation readiness as operational product state",
);

assert.match(
  workflowValidation,
  /evaluateWorkflowActivationReadiness[\s\S]*fixtures: WorkflowNodeFixture\[\] \| null[\s\S]*hasIncomingConnectionClass[\s\S]*"model"[\s\S]*unbound_model_ref[\s\S]*logic\.toolBinding \?\? logic\.connectorBinding \?\? logic\.modelBinding \?\? logic\.parserBinding[\s\S]*mock_binding_active/,
  "Activation readiness should understand attached model bindings, fixture posture, and explicit mock bindings for the right reason",
);

assert.match(
  workflowValidation,
  /(?=[\s\S]*workflowNodeNeedsReplayFixture)(?=[\s\S]*model_call)(?=[\s\S]*adapter)(?=[\s\S]*plugin_tool)(?=[\s\S]*function)(?=[\s\S]*workflowHasUsableReplayFixture)(?=[\s\S]*missing_replay_fixture)/,
  "Activation readiness should warn when expensive or external nodes lack replayable fixture samples",
);

assert.match(
  workflowValidation,
  /environmentProfile[\s\S]*mockBindingsBlockActivation[\s\S]*environmentProfile\.target === "production"[\s\S]*mockBindingPolicy === "block"[\s\S]*addAdvisoryWarning\(issue\)/,
  "Activation readiness should apply the workflow environment's mock-binding policy instead of treating environment config as display-only",
);

assert.match(
  workflowComposerUi,
  /workflow-activation-readiness[\s\S]*workflow-check-readiness[\s\S]*workflow-activate-submit[\s\S]*disabled=\{blocked\}/,
  "Deploy should behave as a readiness-gated activation flow instead of an unconditional save",
);

assert.match(
  workflowComposerUi,
  /workflow-activation-summary-stats[\s\S]*workflow-activation-checklist[\s\S]*workflow-activation-blockers[\s\S]*workflow-activation-policy-nodes[\s\S]*onInspectNode/,
  "Deploy activation modal should show actionable readiness details and click-through node blockers",
);

assert.match(
  workflowBottomShelf,
  /workflow-fixtures-panel[\s\S]*workflow-checkpoints-panel[\s\S]*workflow-checkpoint-history[\s\S]*workflow-checkpoint-card[\s\S]*workflow-proposal-diff-panel[\s\S]*workflow-bottom-proposal-card[\s\S]*workflow-bottom-proposal-impact[\s\S]*workflow-bottom-proposal-nodes/,
  "Bottom shelf should include fixture replay, readable checkpoint history, and readable proposal diff surfaces",
);

assert.match(
  workflowBottomShelf,
  /workflow-bottom-test-output[\s\S]*workflow-bottom-test-list[\s\S]*workflow-bottom-test-row[\s\S]*workflow-bottom-test-targets/,
  "Test Output shelf should render readable test results and covered-node navigation instead of raw JSON",
);

assert.match(
  workflowBottomShelf,
  /workflow-selection-preview[\s\S]*workflow-selection-summary[\s\S]*workflow-selection-config[\s\S]*workflow-selection-run-card[\s\S]*workflow-selection-output-preview/,
  "Selection Preview should render operator-oriented node configuration and run summaries instead of raw logic dumps",
);

assert.doesNotMatch(
  workflowBottomShelf,
  /logic: selectedNode\.config\?\.logic[\s\S]*recentRun:/,
  "Selection Preview should not expose raw node logic and recent-run JSON as the default product surface",
);

assert.match(
  `${workflowRailPanel}\n${workflowBottomShelf}`,
  /workflowValuePreview[\s\S]*workflow-selected-node-latest-output-preview[\s\S]*workflow-validation-suite-summary/,
  "Output rail and validation-suite surfaces should use readable previews rather than evidence-path or raw-payload dumps",
);

assert.match(
  workflowBottomShelf,
  /workflow-bottom-runtime-log-list[\s\S]*workflow-bottom-runtime-log-row[\s\S]*workflow-run-summary-fallback[\s\S]*workflow-run-event-snapshot/,
  "Run Output fallback states should render readable log and event summaries instead of raw runtime objects",
);

assert.match(
  composer,
  /validateActionEdge[\s\S]*actionKindForWorkflowNodeType/,
  "Workflow composer validation should call shared action substrate rules",
);

assert.match(
  graphTypes,
  /WorkflowNodeActionDefinition[\s\S]*requiredBinding[\s\S]*sideEffectClass[\s\S]*connectionClasses/,
  "Workflow graph types should expose action-aware creator metadata",
);

assert.match(
  nodeRegistry,
  /workflowNodeActionDefinitions[\s\S]*requiredBindingFor[\s\S]*supportsMockBinding[\s\S]*schemaRequiredFor/,
  "Workflow node registry should derive action definitions from primitive node contracts",
);

assert.match(
  composer,
  /workflowNodeActionDefinitions[\s\S]*ACTION_BY_NODE_TYPE[\s\S]*workflow-action-metadata/,
  "Workflow composer should consume action metadata for searchable professional node creation",
);

assert.match(
  workflowComposerUi,
  /NodeConfigModal[\s\S]*ModelBindingModal[\s\S]*ConnectorBindingModal[\s\S]*TestEditorModal[\s\S]*ProposalPreviewModal[\s\S]*DeployModal/,
  "Complex workflow editing should use focused modals instead of overcrowding the canvas",
);

assert.match(
  workflowComposerUi,
  /workflow-model-binding-modal[\s\S]*workflow-model-binding-summary[\s\S]*workflow-model-binding-list[\s\S]*workflow-model-binding-required-\$\{bindingKey\}/,
  "Model bindings modal should expose model readiness and activation-required controls",
);

assert.match(
  workflowComposerUi,
  /workflow-connector-binding-modal[\s\S]*workflow-connector-binding-summary[\s\S]*workflow-capability-catalog-summary[\s\S]*workflow-connector-binding-list[\s\S]*workflow-connector-binding-row-\$\{row\.nodeItem\.id\}[\s\S]*workflow-catalog-picker-\$\{row\.nodeItem\.id\}[\s\S]*workflow-catalog-apply-\$\{row\.nodeItem\.id\}[\s\S]*onInspectNode/,
  "Connector bindings modal should expose runtime catalog-backed binding choices and jump to per-node configuration",
);

assert.match(
  composer,
  /(?=[\s\S]*listWorkflowToolCatalog)(?=[\s\S]*normalizeWorkflowToolCatalog)(?=[\s\S]*listWorkflowConnectorCatalog)(?=[\s\S]*normalizeWorkflowConnectorCatalog)(?=[\s\S]*handleApplyWorkflowCatalogBinding)/,
  "Workflow composer should hydrate tool and connector capability catalogs before applying node bindings",
);

assert.match(
  `${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*collectWorkflowCapabilityCatalogBindingProof)(?=[\s\S]*workflow_capability_catalog_binding)(?=[\s\S]*workflow_capability_catalog_binding_proof_present)/,
  "Retained GUI validation should require canonical capability catalog binding proof.",
);

assert.match(
  workflowCapabilityCatalogBindingProbe,
  /(?=[\s\S]*workflow-catalog-picker)(?=[\s\S]*workflow-catalog-apply)(?=[\s\S]*workflowWithCatalogBinding)(?=[\s\S]*tool-capability:mcp\.tool\.catalog\.read)(?=[\s\S]*connector-capability:agent\.connector\.catalog)(?=[\s\S]*failClosedWhenReadinessMissing)/,
  "Catalog binding proof should exercise the modal picker path, canonical refs, and fail-closed readiness.",
);

assert.match(
  templates,
  /type: "model_call"/,
  "Internal workflow fixtures should continue to serialize model nodes as model_call",
);

for (const forbiddenProductLabel of [
  "Basic agent answer",
  "Repo function test",
  "Adapter connector check",
  "Plugin tool action",
  "Human gated change",
  "JPG to SVG tracing",
  "Software request triage agent",
  "Product feedback router",
  "Weekly metrics reporting agent",
  "Month-end accounting close agent",
  "Slack Q&A agent",
  "Repo test engineer",
  "MCP research operator",
]) {
  assert.doesNotMatch(
    composer,
    new RegExp(escapeRegExp(forbiddenProductLabel), "i"),
    `Dogfood/example workflow '${forbiddenProductLabel}' must not be product-visible in the canvas composer`,
  );
}

assert.doesNotMatch(
  composer,
  /workflowTemplates|WORKFLOW_TEMPLATES|getWorkflowTemplate|workflow-template-picker|workflow-template-button|Template catalog/,
  "The product composer must not wire dogfood templates into the visible create flow or node library",
);

assert.match(
  harnessTools,
  /createWorkflowProject[\s\S]*saveWorkflowProject[\s\S]*validateWorkflowBundle[\s\S]*createWorkflowFromTemplate[\s\S]*createWorkflowProposal[\s\S]*applyWorkflowProposal[\s\S]*runWorkflowProject[\s\S]*runWorkflowNode[\s\S]*dryRunWorkflowFunction[\s\S]*runWorkflowDogfoodSuite[\s\S]*resumeWorkflowRun[\s\S]*forkWorkflowCheckpoint[\s\S]*exportWorkflowPackage[\s\S]*importWorkflowPackage/,
  "Harness workflow tools should call typed workflow runtime APIs",
);

assert.match(
  graphTypes,
  /interface WorkflowPortablePackageManifest[\s\S]*harnessPackageManifest\?: WorkflowHarnessPackageEvidenceManifest[\s\S]*readinessStatus[\s\S]*portable[\s\S]*files: WorkflowPortablePackageFile\[\]/,
  "Portable workflow package manifests should carry harness package evidence, readiness, and file integrity metadata",
);

assert.match(
  `${graphTypes}\n${harnessWorkflow}\n${workflowRailPanel}\n${projectCommands}`,
  /(?=[\s\S]*WorkflowHarnessPackageEvidenceManifest)(?=[\s\S]*makeWorkflowHarnessPackageEvidenceManifest)(?=[\s\S]*workflow\.harness\.package-evidence-manifest\.v1)(?=[\s\S]*withWorkflowHarnessPackageManifest)(?=[\s\S]*harnessWorkbenchDeepLinkHash)(?=[\s\S]*harnessPackageManifest)(?=[\s\S]*data-harness-package-manifest-present)(?=[\s\S]*workflow-harness-package-evidence-review)(?=[\s\S]*workflow-harness-package-evidence-row-\$\{row\.id\})(?=[\s\S]*harness-package-evidence\.json)(?=[\s\S]*harness_package_manifest)(?=[\s\S]*packageManifest)/,
  "Harness fork portable packages should preserve evidence manifests, route-restorable deep links, GUI coverage counts, and Rust bundle sidecars across export/import.",
);

assert.match(
  graphRuntimeTypes,
  /exportWorkflowPackage\?\([\s\S]*WorkflowPortablePackage[\s\S]*importWorkflowPackage\?\([\s\S]*WorkflowWorkbenchBundle/,
  "Workflow runtime should expose portable package export/import APIs",
);

assert.match(
  workflowComposerUi,
  /handleExportPortablePackage[\s\S]*exportWorkflowPackage[\s\S]*workflow-portable-package[\s\S]*workflow-export-package[\s\S]*workflow-package-summary/,
  "Workflow readiness UI should export portable packages without exposing hidden evidence paths",
);

assert.match(
  workflowComposerUi,
  /handleImportPortablePackage[\s\S]*importWorkflowPackage[\s\S]*createWorkflowPackageImportReview[\s\S]*setSelectedHarnessActivationGateId\("package-evidence"\)/,
  "Workflow readiness UI should import portable packages into package-evidence review through the workflow runtime",
);

for (const importSelector of [
  "workflow-import-package-open",
  "workflow-import-package-modal",
  "workflow-import-package-path",
  "workflow-import-package-submit",
]) {
  assert.match(
    workflowComposerUi,
    new RegExp(escapeRegExp(importSelector)),
    `Workflow package import should expose ${importSelector}`,
  );
}

assert.match(
  workflowComposerUi,
  /(?=[\s\S]*const mutationCanaryGateLink = \{[\s\S]*panel: "settings" as WorkflowRightPanel[\s\S]*activationGateId: "mutation-canary"[\s\S]*activationGateNodeAttemptId: mutationCanaryNodeAttemptId[\s\S]*mutationCanaryState =[\s\S]*readHarnessRailSelectedState\(selectedRailTestId\)[\s\S]*workflow-harness-activation-gate-node-timeline)(?=[\s\S]*const mutationCanaryInspectorLink = \{[\s\S]*\.\.\.mutationCanaryGateLink[\s\S]*panel: "outputs" as WorkflowRightPanel[\s\S]*mutationCanaryNodeAttemptState = readHarnessRailSelectedState\([\s\S]*"workflow-harness-node-attempt-inspector")/,
  "Package import activation apply should restore mutation-canary gate/timeline on the settings rail and the same attempt in the outputs node inspector",
);

assert.match(
  graphTypes,
  /interface WorkflowNodeFixture[\s\S]*nodeId[\s\S]*nodeConfigHash[\s\S]*pinned\?:[\s\S]*validationStatus\?:[\s\S]*validationMessage\?:[\s\S]*createdAtMs/,
  "Workflow node fixtures should be typed sidecar records instead of workflow JSON fields",
);

assert.doesNotMatch(
  harnessTools,
  /\bwriteFile|fs\.|localStorage|indexedDB\b/,
  "Harness workflow tools should not bypass the workflow runtime with direct persistence",
);

assert.match(
  graphExecution,
  /model_call: "responses"/,
  "model_call nodes should dispatch to the model execution path",
);

assert.match(
  graphExecution,
  /workflowNodeType\(node\) === "model"/,
  "legacy model nodes should remain rejected before execution",
);

assert.doesNotMatch(
  composer,
  /\b(CIRC|CEC|ledger|completion gate)\b/i,
  "The workflow composer should not surface legacy audit vocabulary in product UI copy",
);

assert.match(
  composer,
  /WorkflowRunResult[\s\S]*WorkflowStreamEvent[\s\S]*WorkflowCheckpoint/,
  "The workflow workbench should consume durable run, stream, and checkpoint state",
);

assert.match(
  graphRuntimeTypes,
  /loadWorkflowRun\?\([\s\S]*WorkflowRunResult/,
  "Runtime should expose durable run detail loading for execution inspection",
);

assert.match(
  workflowComposerUi,
  /handleSelectRun[\s\S]*loadWorkflowRun[\s\S]*workflow-run-inspector[\s\S]*workflow-run-timeline[\s\S]*workflow-run-node-attempts[\s\S]*workflow-run-payload/,
  "Runs UI should load run sidecars and expose timeline, attempts, and node IO without trace vocabulary",
);

assert.match(
  composer,
  /useLayoutEffect\(\(\) => \{[\s\S]*runtime\.loadWorkflowRun[\s\S]*runs\.length === 0[\s\S]*runDetailLoading[\s\S]*selectedRunId[\s\S]*lastRunResult\?\.summary\.id[\s\S]*setRunDetailLoading\(true\)[\s\S]*applyRunResult\(result\)[\s\S]*setRunDetailLoading\(false\)/,
  "Workflow open should auto-load durable run details before painting a stale run-output fallback",
);

assert.match(
  `${workflowRunHistoryModel}\n${workflowRailRunsPanel}\n${workflowRailPanel}`,
  /(?=[\s\S]*runSearchQuery)(?=[\s\S]*setRunSearchQuery)(?=[\s\S]*runStatusFilter)(?=[\s\S]*setRunStatusFilter)(?=[\s\S]*filteredRuns)(?=[\s\S]*visibleRows)(?=[\s\S]*workflow-run-filters)(?=[\s\S]*workflow-run-search-input)(?=[\s\S]*workflow-run-status-filter)(?=[\s\S]*workflow-runs-empty-filtered)/,
  "Runs rail should filter high-volume execution history instead of dumping an overwhelming run count",
);

assert.match(
  `${composer}\n${workflowRunHistoryModel}\n${workflowRailRunsPanel}\n${workflowBottomShelf}`,
  /(?=[\s\S]*handleCompareRun)(?=[\s\S]*loadWorkflowRun)(?=[\s\S]*compareRunRecords)(?=[\s\S]*workflow-run-compare)(?=[\s\S]*input changed)(?=[\s\S]*workflow-bottom-run-compare)(?=[\s\S]*workflow-bottom-run-compare-nodes)(?=[\s\S]*workflow-bottom-run-compare-state)/,
  "Runs UI should compare two durable run sidecars without exposing hidden trace vocabulary",
);

assert.match(
  workflowComposerUi,
  /(?=[\s\S]*showRuntimeLogs = logs\.length > 0 && !latestRun)(?=[\s\S]*showWorkflowChecks = dogfoodRun && !latestRun && logs\.length === 0)(?=[\s\S]*workflow-run-detail)(?=[\s\S]*workflow-dogfood-bottom)/,
  "Run Output should prioritize real run details over workflow-check harness summaries",
);

assert.match(
  composer,
  /setLastRunResult\(finalRun\);\s*setSelectedRunId\(finalRun\.summary\.id\);/,
  "Scratch GUI-authored runs should become the selected run so run details stay inspectable",
);

assert.match(
  workflowBottomShelf,
  /Run details not loaded[\s\S]*Runs rail or Executions[\s\S]*attempts, timeline events, and outputs/,
  "Run Output empty state should guide users to the Runs rail or Executions instead of a dead end",
);

assert.match(
  workflowRailModel,
  /interface WorkflowRunComparison[\s\S]*inputChanged: boolean[\s\S]*workflowValueFingerprint\(before\?\.input\)[\s\S]*workflowValueFingerprint\(after\?\.input\)/,
  "Run comparison should detect node input deltas as well as output, status, and error changes",
);

assert.match(
  workflowRailModel,
  /interface WorkflowChildRunLineage[\s\S]*workflowNodeRunChildLineage[\s\S]*toolKind[\s\S]*workflow_tool[\s\S]*childRunId[\s\S]*childWorkflowPath/,
  "Workflow-as-tool child run lineage should be modeled once and reused by execution surfaces",
);

assert.match(
  `${graphTypes}\n${workflowRailModel}`,
  /child_run_completed[\s\S]*Child run completed/,
  "Workflow-as-tool child completions should be first-class run timeline events",
);

assert.match(
  `${workflowRunHistoryModel}\n${workflowRailRunsPanel}\n${workflowBottomShelf}`,
  /(?=[\s\S]*workflowInterruptPreview\(lastRunResult\))(?=[\s\S]*workflow-interrupt-preview)(?=[\s\S]*workflow-run-action-preview)(?=[\s\S]*Approve and resume)/,
  "Paused tool and connector actions should show an operational approval preview before resume",
);

assert.doesNotMatch(
  workflowComposerUi,
  /Dogfood suite|Scratch dogfood|Scratch heavy suite|Validation suite|Reasoning model binding|dogfoodRun\.suiteId|dogfoodRun\.outputDir|dogfoodRun\.gapLedgerPath/,
  "Automation harness status, suite ids, and evidence paths should not leak into visible workflow surfaces",
);

assert.match(
  composer,
  /clearRunState[\s\S]*setLastRunResult\(null\)[\s\S]*setRunEvents\(\[\]\)[\s\S]*setCheckpoints\(\[\]\)[\s\S]*setNodeRunStatusById\(\{\}\)/,
  "Switching workflow bundles should clear transient run/checkpoint UI state",
);

for (const selector of [
  "workflow-create-button",
  "workflow-create-name",
  "workflow-scratch-start",
  "workflow-open-node-drawer",
  "workflow-left-drawer",
  "workflow-component-library",
  "workflow-canvas-search-toggle",
  "workflow-canvas-search-panel",
  "workflow-canvas-search-input",
  "workflow-canvas-search-results",
  "workflow-canvas-search-result",
  "workflow-canvas-search-compatible",
  "workflow-canvas-search-configure",
  "workflow-canvas-search-empty",
  "workflow-configure-node",
  "workflow-show-compatible-nodes",
  "workflow-connect-from-node",
  "workflow-connect-to-node",
  "workflow-add-node-test",
  "workflow-run-button",
  "workflow-run-tests-button",
  "workflow-model-bindings-button",
  "workflow-connector-bindings-button",
  "workflow-validate-button",
  "workflow-propose-button",
  "workflow-deploy-button",
  "workflow-save-button",
  "workflow-node-config-modal",
  "workflow-node-name",
  "workflow-node-metric",
  "workflow-node-config-done",
  "workflow-node-run-report",
  "workflow-node-run-output",
  "workflow-node-run-error",
  "workflow-config-input-port-table",
  "workflow-config-input-schema-fields",
  "workflow-config-output-port-table",
  "workflow-config-output-schema-fields",
  "workflow-config-upstream-schema-fields",
  "workflow-model-attachment-summary",
  "workflow-model-tool-use-mode",
  "workflow-model-output-schema",
  "workflow-model-parser-ref",
  "workflow-model-memory-key",
  "workflow-model-structured-validation",
  "workflow-connector-binding-mode",
  "workflow-connector-credential-ready",
  "workflow-tool-credential-contract",
  "workflow-tool-binding-mode",
  "workflow-tool-credential-ready",
  "workflow-tool-contract",
  "workflow-tool-argument-schema",
  "workflow-tool-result-schema",
  "workflow-tool-timeout-ms",
  "workflow-tool-max-attempts",
  "workflow-tool-child-lineage",
  "workflow-run-child-lineage",
  "workflow-bottom-child-lineage",
  "workflow-executions-child-lineage",
  "workflow-node-test-summary",
  "workflow-node-related-test-row",
  "workflow-node-related-test-status",
  "workflow-source-kind",
  "workflow-source-path",
  "workflow-source-extension",
  "workflow-source-mime",
  "workflow-source-media-kind",
  "workflow-source-sanitize-input",
  "workflow-source-validate-mime",
  "workflow-source-strip-metadata",
  "workflow-source-payload",
  "workflow-test-assertion-kind",
  "workflow-test-name",
  "workflow-test-targets",
  "workflow-test-submit",
  "workflow-node-test-assertion-kind",
  "workflow-function-dry-run",
  "workflow-function-dry-run-result",
  "workflow-function-dry-run-payload",
  "workflow-function-dry-run-payload-preview",
  "workflow-function-dry-run-stdout",
  "workflow-function-dry-run-stderr",
  "workflow-bottom-dry-run-payload",
  "workflow-bottom-dry-run-payload-preview",
  "workflow-bottom-dry-run-stdout",
  "workflow-bottom-dry-run-stderr",
  "workflow-function-input-schema",
  "workflow-function-test-input",
  "workflow-approve-resume",
  "workflow-runs-list",
  "workflow-run-inspector",
  "workflow-run-detail",
  "workflow-run-node-attempts",
  "workflow-bottom-run-timeline",
  "workflow-run-payload",
  "workflow-interrupt-preview",
  "workflow-run-action-preview",
]) {
  assert.match(
    workflowComposerUi,
    new RegExp(`(?:data-testid|testId)="${selector}"`),
    `Workflow GUI should expose stable selector '${selector}' for dogfood automation`,
  );
}

assert.match(
  workflowComposerUi,
  /data-testid=\{`workflow-function-sandbox-\$\{field\}`\}[\s\S]*data-testid=\{`workflow-function-permission-\$\{permission\}`\}/,
  "Function editor should expose stable sandbox and permission controls for dogfood automation",
);

assert.match(
  workflowComposerModel,
  /workflowFunctionDryRunView[\s\S]*stdout[\s\S]*stderr[\s\S]*sandbox/,
  "Function dry-run presentation extraction should keep stdout, stderr, and sandbox details together",
);

assert.match(
  workflowComposerUi,
  /workflowFunctionDryRunView\(dryRunResult\)[\s\S]*workflow-function-dry-run-result[\s\S]*workflow-function-dry-run-payload[\s\S]*workflow-function-dry-run-payload-preview[\s\S]*Raw result payload[\s\S]*workflow-function-dry-run-stdout[\s\S]*workflow-function-dry-run-stderr[\s\S]*workflow-bottom-dry-run-payload[\s\S]*workflow-bottom-dry-run-payload-preview/,
  "Function dry-run should surface result, stdout, stderr, attempt, and sandbox details instead of raw JSON only",
);

assert.match(
  workflowComposerUi,
  /(?=[\s\S]*data-testid="workflow-open-node-library")(?=[\s\S]*data-testid=\{`workflow-component-\$\{itemId\}`\})(?=[\s\S]*data-testid="workflow-recent-primitives")/,
  "Workflow scaffold catalog should expose stable primitive-picker selectors for scratch dogfood automation",
);

assert.match(
  nodeRegistry,
  /workflowNodeCreatorDefinitions[\s\S]*creatorId: "source\.media"[\s\S]*label: "Media input"[\s\S]*sourceKind: "media"[\s\S]*fileExtension: "jpg"[\s\S]*stripMetadata: true/,
  "The primitive creator should expose media as a source action variant instead of inventing JPEG-specific node kinds",
);

assert.match(
  nodeRegistry,
  /creatorId: "output\.media"[\s\S]*label: "Media output"[\s\S]*format: "svg"[\s\S]*rendererId: "media"/,
  "The primitive creator should expose media output as an output action variant with renderer/materialization config",
);

assert.match(
  graphState,
  /const addNode = useCallback\(\(type: string, name: string, preferredId\?: string\): string[\s\S]*setSelectedNodeId\(nodeId\)[\s\S]*return nodeId/,
  "Adding a node from scratch should select and return the new node id for honest manual composition",
);

assert.match(
  composer,
  /handleAddNodeFromLibrary\(nodeItem\.type, nodeItem\.name, nodeItem\.id\)[\s\S]*compositionMode: "manual_canvas_primitives"/,
  "Repo Test Engineer dogfood should assemble nodes and edges through composer primitives instead of loading a complete graph in one step",
);

assert.doesNotMatch(
  composer,
  /loadWorkflowProject\(scratch\.workflow\)/,
  "Repo Test Engineer dogfood should not load the complete scratch graph as a template-equivalent shortcut",
);

assert.match(
  workflowComposerUi,
  /functionBinding[\s\S]*connectorBinding[\s\S]*toolBinding/,
  "Node configuration should expose typed function, connector, and tool bindings",
);

assert.match(
  workflowComposerUi,
  /Blank canvas[\s\S]*workflow-create-summary[\s\S]*Create an empty workflow and add nodes from the canvas/,
  "Create Workflow should default to blank-canvas authoring without exposing example-template shortcuts",
);

assert.doesNotMatch(
  workflowComposerUi,
  /workflow-create-template-summary|workflow-template-picker|workflow-template-button|Template catalog/,
  "Create/import workflow modals should not use template-catalog vocabulary in the primary authoring path",
);

assert.match(
  workflowBottomShelf,
  /latestPayloadSnapshot[\s\S]*input: selectedNodeRun\?\.input[\s\S]*workflow-bottom-data-preview[\s\S]*workflow-bottom-port-map[\s\S]*workflow-bottom-latest-payload[\s\S]*workflow-bottom-latest-input-preview[\s\S]*workflow-bottom-latest-output-preview[\s\S]*Raw payload snapshot/,
  "Bottom Data Preview should expose node ports, schemas, and summary-first latest payload previews rather than raw placeholder text",
);

assert.match(
  workflowBottomShelf,
  /workflow-bottom-warnings-detail[\s\S]*workflow-bottom-warnings-list[\s\S]*onInspectNode/,
  "Bottom Warnings should provide actionable validation rows that can navigate back to affected nodes",
);

assert.match(
  workflowBottomPanelModel,
  /workflowBottomSuggestions[\s\S]*Validate executable readiness[\s\S]*Add unit tests[\s\S]*Define workflow output/,
  "Bottom Suggestions should be derived from validation, tests, proposals, and output posture",
);

assert.match(
  workflowBottomShelf,
  /workflowBottomSuggestions\(\{[\s\S]*workflow-bottom-suggestions-detail[\s\S]*workflow-bottom-suggestions-list/,
  "Bottom Suggestions should render from the extracted bottom-panel model",
);

assert.match(
  composer,
  /workflow-proposals-workbench[\s\S]*workflow-proposals-summary[\s\S]*workflow-proposal-workbench-list[\s\S]*workflow-proposals-targets/,
  "Proposals tab should be a bounded-change workbench surface, not a placeholder list",
);

assert.match(
  workflowComposerModals,
  /workflow-proposal-bounds-check[\s\S]*workflow-proposal-graph-diff[\s\S]*workflow-proposal-config-diff[\s\S]*workflow-proposal-sidecar-diff[\s\S]*workflow-proposal-code-diff[\s\S]*workflow-proposal-patch-preview/,
  "Proposal preview should separate graph, config, sidecar, code, and patch changes instead of dumping an opaque JSON blob",
);

assert.match(
  workflowComposerModals,
  /workflow-proposal-review-summary[\s\S]*workflow-proposal-apply-status[\s\S]*Apply is blocked[\s\S]*Ready to apply declared bounded changes/,
  "Proposal preview should keep mutation review summary and apply posture visible while long diffs scroll",
);

assert.match(
  workflowComposerCss,
  /workflow-proposal-preview-dialog[\s\S]*grid-template-rows:[\s\S]*workflow-proposal-preview-footer[\s\S]*position: sticky[\s\S]*bottom: 0/,
  "Proposal preview should keep the review footer sticky so bounded apply is never buried below long diffs",
);

assert.match(
  workflowComposerModals,
  /const applyBlocked =[\s\S]*proposal\.status !== "open" \|\| proposalBoundsIssues\.length > 0[\s\S]*disabled=\{applyBlocked\}[\s\S]*workflowProposalBoundsIssues[\s\S]*workflow-config[\s\S]*workflow-metadata/,
  "Proposal preview should preflight declared bounds before enabling apply",
);

assert.match(
  graphTypes,
  /configDiff\?:[\s\S]*changedNodeIds\?:[\s\S]*changedGlobalKeys\?:[\s\S]*sidecarDiff\?:[\s\S]*changedRoles\?:/,
  "Workflow proposal payloads should carry typed config and sidecar diff metadata for bounded review",
);

assert.match(
  projectCommands,
  /validate_workflow_proposal_patch_bounds[\s\S]*exceeds declared bounds[\s\S]*apply_workflow_proposal/,
  "Applying a workflow proposal should enforce that workflow patches stay inside declared bounds",
);

assert.match(
  composer,
  /workflowPatchBoundedTargets[\s\S]*workflow-config[\s\S]*workflow-metadata[\s\S]*CreateWorkflowProposalRequest/,
  "Generated workflow proposals should declare node, config, and metadata bounds for the patch they are asking to review",
);

assert.match(
  composer,
  /workflow-executions-workbench[\s\S]*workflow-executions-summary[\s\S]*workflow-executions-run-list[\s\S]*workflow-executions-run-detail[\s\S]*workflow-executions-node-attempts[\s\S]*workflow-executions-timeline/,
  "Executions tab should expose run lifecycle, node attempts, and timeline inspection",
);

assert.match(
  composer,
  /setRightPanel\("runs"\)[\s\S]*runtime\.runWorkflowProject[\s\S]*applyRunResult\(result\)[\s\S]*setRightPanel\("runs"\)/,
  "Running a workflow should open the Runs rail so execution inspection is immediate",
);

assert.match(
  composer,
  /workflowCapabilityPreflight[\s\S]*workflowCapabilityRunLaunchAnnotation[\s\S]*capabilityPreflight[\s\S]*runtime\.runWorkflowProject/,
  "Workflow runs should pass canonical capability preflight annotations to the daemon before live execution",
);

assert.match(
  projectCommands,
  /workflow_capability_preflight_blocked_from_options[\s\S]*workflow_capability_preflight_blocked_result/,
  "Workflow run commands should fail closed through the canonical capability preflight lane",
);

assert.match(
  projectWorkflowPolicyLane,
  /WORKFLOW_CAPABILITY_PREFLIGHT_SCHEMA_VERSION[\s\S]*WorkflowRunCapabilityPreflightBlocked[\s\S]*capabilityRows[\s\S]*policyDecisionRefs/,
  "Capability preflight daemon results should emit schemaed policy-blocked evidence and receipt metadata",
);

assert.match(
  workflowRailPanel,
  /data-testid="workflow-open-executions"[\s\S]*Open Executions/,
  "Runs rail should provide a clear path into the full Executions workbench",
);

assert.match(
  composer,
  /onOpenExecutions=\{\(\) => setActiveTab\("executions"\)\}/,
  "Runs rail should navigate to the top-level Executions workbench",
);

assert.match(
  composer,
  /handleInspectExecutionNode[\s\S]*handleWorkflowNodeSelect\(nodeId\)[\s\S]*setActiveTab\("graph"\)[\s\S]*setRightPanel\("runs"\)[\s\S]*setBottomPanel\("selection"\)/,
  "Inspecting a node attempt from Executions should return to the canvas with the node selected",
);

assert.match(
  workflowComposerUi,
  /schema_matches[\s\S]*output_contains[\s\S]*custom/,
  "Workflow unit-test editor should expose executable assertion kinds for scratch-built workflows",
);

assert.match(
  workflowComposerUi,
  /workflow-test-editor-summary[\s\S]*workflow-test-target-summary[\s\S]*workflow-test-assertion-guidance[\s\S]*workflow-test-schema-preview/,
  "Unit-test editor should show target coverage, assertion guidance, and selected-node schema context",
);

assert.match(
  workflowComposerUi,
  /(?=[\s\S]*workflow-node-config-issues)(?=[\s\S]*workflow-node-config-related-tests)(?=[\s\S]*testResultById)/,
  "Node configuration should show node-local validation issues and related unit-test status",
);

assert.match(
  workflowComposerUi,
  /relatedTestStatusCounts[\s\S]*workflow-node-test-summary[\s\S]*workflow-node-related-test-row[\s\S]*workflow-node-related-test-status/,
  "Node configuration should summarize related test coverage and latest test status per node",
);

assert.match(
  workflowComposerUi,
  /workflow-config-section-run-data[\s\S]*workflow-node-run-report[\s\S]*workflowDurationLabel[\s\S]*workflow-node-run-input[\s\S]*workflow-node-run-output[\s\S]*workflow-node-run-error/,
  "Node configuration should expose structured per-node run inspection instead of raw execution JSON only",
);

assert.match(
  workflowComposerUi,
  /workflowValuePreview[\s\S]*workflow-node-input-preview[\s\S]*Raw input payload[\s\S]*workflow-node-output-preview[\s\S]*Raw output payload[\s\S]*workflow-node-run-input[\s\S]*Raw input[\s\S]*workflow-node-run-output[\s\S]*Raw output/,
  "Node configuration should summarize payloads first and keep raw JSON behind intentional details controls",
);

assert.match(
  graphTypes,
  /interface WorkflowNodeRun[\s\S]*attempt: number;[\s\S]*input\?: unknown;[\s\S]*output\?: unknown;[\s\S]*harnessAttempt\?: WorkflowHarnessNodeAttemptRecord;[\s\S]*interface WorkflowRunResult[\s\S]*harnessAttempts\?: WorkflowHarnessNodeAttemptRecord\[\];[\s\S]*harnessShadowComparisons\?: WorkflowHarnessShadowComparison\[\];/,
  "Workflow node run records should persist typed input, output, harness attempts, and shadow comparisons for execution inspection",
);

assert.match(
  workflowComposerUi,
  /workflow-config-section-inputs[\s\S]*workflow-config-input-port-table[\s\S]*workflow-config-input-schema-fields[\s\S]*workflow-node-input-preview[\s\S]*workflow-config-section-outputs[\s\S]*workflow-config-output-port-table[\s\S]*workflow-config-output-schema-fields[\s\S]*workflow-config-upstream-schema-fields/,
  "Node configuration should expose ports and schema fields as operator rows before falling back to raw JSON payloads",
);

assert.match(
  workflowComposerUi,
  /workflow-model-attachment-summary[\s\S]*workflow-model-tool-use-mode[\s\S]*workflow-model-output-schema[\s\S]*workflow-model-parser-ref[\s\S]*workflow-model-memory-key[\s\S]*workflow-model-structured-validation/,
  "Model nodes should configure tool mode, structured output, parser, and memory attachments explicitly",
);

assert.match(
  workflowValidation,
  /missing_model_tool_attachment[\s\S]*missing_model_parser_attachment[\s\S]*missing_model_memory_attachment[\s\S]*missing_model_output_schema/,
  "Model configuration should validate tool, parser, memory, and structured-output requirements through typed graph state",
);

assert.match(
  workflowValidation,
  /missing_workflow_tool_argument_schema[\s\S]*missing_workflow_tool_result_schema[\s\S]*invalid_workflow_tool_timeout[\s\S]*invalid_workflow_tool_attempts/,
  "Workflow tool configuration should validate child workflow schemas and retry bounds through typed graph state",
);

assert.match(
  workflowValidation,
  /missing_live_connector_credential[\s\S]*missing_live_tool_credential/,
  "Live connector and tool bindings should require explicit credential readiness",
);

assert.match(
  graphTypes,
  /interface GraphProductionProfile[\s\S]*errorWorkflowPath[\s\S]*evaluationSetPath[\s\S]*expectedTimeSavedMinutes[\s\S]*mcpAccessReviewed/,
  "Workflow bundles should carry a typed production profile for activation readiness",
);

assert.match(
  workflowValidation,
  /missing_error_handling_path[\s\S]*missing_ai_evaluation_coverage[\s\S]*mcp_access_not_reviewed[\s\S]*operational_value_not_estimated[\s\S]*missing_replay_fixture/,
  "Activation readiness should include production checklist concerns without exposing audit jargon",
);

assert.match(
  workflowRailPanel,
  /workflow-settings-production-profile[\s\S]*Production checklist[\s\S]*Error path[\s\S]*Evaluations[\s\S]*Value estimate[\s\S]*MCP access/,
  "Settings rail should expose production checklist state as product operations vocabulary",
);

assert.match(
  workflowRailPanel,
  /workflow-production-profile-editor[\s\S]*workflow-production-error-path[\s\S]*workflow-production-evaluation-path[\s\S]*workflow-production-time-saved[\s\S]*workflow-production-mcp-reviewed/,
  "Production checklist fields should be editable from the Workflows settings rail instead of requiring JSON edits",
);

assert.match(
  composer,
  /handleUpdateProductionProfile[\s\S]*normalizeGlobalConfig[\s\S]*production:[\s\S]*markWorkflowDirty/,
  "Production checklist edits should persist through the workflow global config and dirty the workflow bundle",
);

assert.match(
  workflowReadinessModel,
  /Error handling[\s\S]*Evaluation coverage[\s\S]*Replay samples[\s\S]*MCP access reviewed[\s\S]*Value estimate/,
  "Readiness checklist should make production blockers and replay-sample posture visible before activation",
);

assert.match(
  scratchProbe,
  /inputCapturedCount[\s\S]*bindingManifestFresh[\s\S]*freshFixtureInputCount[\s\S]*fixtureValidationStatuses[\s\S]*wait_for_dogfood_sidecars[\s\S]*initial_view="workflows"/,
  "Scratch GUI dogfood should launch Workflows and observe fresh binding manifests, fixture input/validation, and node-run input capture through the manual composer bridge",
);

assert.match(
  scratchProbe,
  /04-canvas-search-output[\s\S]*05-canvas-search-configure[\s\S]*05a-node-input-preview[\s\S]*05b-output-bindings-editor[\s\S]*05c-fixture-replay-shelf[\s\S]*06-compatible-node-picker/,
  "Scratch GUI dogfood should capture canvas search, node configuration, input preview, output bindings, fixture replay shelf, and compatible-node picker access from the native workflow surface",
);

assert.match(
  scratchProbe,
  /dismiss_create_workflow_modal[\s\S]*01b-create-blank-workflow-modal[\s\S]*dismiss_create_workflow_modal\(window_id\)[\s\S]*02-dogfood-running/,
  "Scratch GUI dogfood should capture and dismiss the blank Create Workflow modal before continuing primitive-node validation",
);

assert.doesNotMatch(
  scratchProbe,
  /create_workflow_from_template|createWorkflowFromTemplate|workflow\.template\.instantiate|Basic agent answer/,
  "Scratch GUI dogfood probe must not instantiate templates or route around the GUI",
);

assert.match(
  usabilityProbe,
  /DEFAULT_OUTPUT_ROOT = Path\("\/tmp\/autopilot-workflow-usability"\)[\s\S]*open_new_blank_workflow[\s\S]*choose_empty_start[\s\S]*open_add_picker_from_selected_node[\s\S]*search_creator/,
  "Usability probe should launch the real GUI and compose from visible blank-canvas and add-next controls",
);

assert.match(
  usabilityProbe,
  /exercise_manual_function_output[\s\S]*manual-input[\s\S]*javascript[\s\S]*inline output[\s\S]*run-workflow[\s\S]*exercise_chat_tool_decision[\s\S]*chat-trigger[\s\S]*model call[\s\S]*mcp[\s\S]*decision/,
  "Usability probe should cover the two canonical scratch exercises through visible controls",
);

assert.match(
  tauriRuntime,
  /run_workflow_project_live[\s\S]*run_workflow_node_live/,
  "Workflow composer runs should call the live daemon project/node runner so configured model nodes can use mounted inference",
);

assert.match(
  workflowBottomShelf,
  /workflow-model-invocation-trace[\s\S]*workflow-model-invocation-prompt[\s\S]*workflow-model-invocation-trace-step/,
  "Workflow run output should expose a glass-box model invocation trace with prompt and phase evidence",
);

assert.match(
  workflowRailRunsPanel,
  /workflow-run-model-invocation-trace[\s\S]*workflow-run-model-invocation-summary[\s\S]*workflow-run-model-invocation-step/,
  "Workflow run inspector should surface model prompt pipeline evidence in the primary Runs rail",
);

assert.match(
  `${workflowRunHistoryModel}\n${workflowRunCapabilityReceipts}\n${workflowRailRunsPanel}`,
  /(?=[\s\S]*WorkflowRunCapabilityReceiptProjection)(?=[\s\S]*workflowRunCapabilityReceiptProjection)(?=[\s\S]*workflow-run-capability-receipts)(?=[\s\S]*workflow-run-capability-receipt-\$\{row\.nodeId\})(?=[\s\S]*data-capability-ref)(?=[\s\S]*data-grant-status)(?=[\s\S]*data-policy-status)(?=[\s\S]*data-receipt-required)(?=[\s\S]*data-fail-closed)(?=[\s\S]*repairActions)(?=[\s\S]*workflow-run-capability-repair-\$\{action\.kind\}-\$\{rowNodeId\})(?=[\s\S]*data-target-surface)(?=[\s\S]*\/api\/v1\/authority)/,
  "Workflow run inspector should project canonical model/tool/connector capability refs with grant, policy, receipt, and fail-closed evidence.",
);

assert.match(
  composer,
  /handleCapabilityRepairAction[\s\S]*apply_approved_grant[\s\S]*runtime\.applyWorkflowCapabilityGrantRequest[\s\S]*workflowCapabilityGrantRequestFromRepairAction[\s\S]*runtime\.createWorkflowCapabilityGrantRequest[\s\S]*loadRuntimeSidecars/,
  "Capability repair actions should draft authority grant requests and apply approved grants through the daemon.",
);

assert.match(
  `${tauriRuntime}\n${tauriLib}\n${projectCommands}\n${workflowRailRunsPanel}`,
  /(?=[\s\S]*createWorkflowCapabilityGrantRequest)(?=[\s\S]*listWorkflowCapabilityGrantRequests)(?=[\s\S]*resolveWorkflowCapabilityGrantRequest)(?=[\s\S]*applyWorkflowCapabilityGrantRequest)(?=[\s\S]*create_workflow_capability_grant_request)(?=[\s\S]*resolve_workflow_capability_grant_request)(?=[\s\S]*apply_workflow_capability_grant_request)(?=[\s\S]*authority_grant_request)(?=[\s\S]*secretMaterialPresent)(?=[\s\S]*data-grant-request-status)(?=[\s\S]*workflow-run-capability-grant-\$\{decision\})(?=[\s\S]*apply_approved_grant)/,
  "Authority grant repair should have daemon lifecycle commands, redacted receipt results, and run-rail draft/resolve/apply projection.",
);

assert.match(
  workflowRunCapabilityReceiptsProbe,
  /(?=[\s\S]*workflow_run_capability_receipts_projection)(?=[\s\S]*renderToStaticMarkup)(?=[\s\S]*workflowRunHistoryModel)(?=[\s\S]*workflow-run-capability-receipts)(?=[\s\S]*model-capability:route\.local-first)(?=[\s\S]*tool-capability:file\.apply_patch)(?=[\s\S]*connector-capability:agent\.connector\.catalog)(?=[\s\S]*missing_credential_readiness)(?=[\s\S]*missing_receipt_behavior)/,
  "Retained GUI proof should render the Runs rail capability receipt projection with canonical refs and fail-closed blockers.",
);

assert.match(
  workflowModelInvocationTrace,
  /workflowModelInvocationTraces[\s\S]*workflowModelInvocationTraceSearchText/,
  "Model invocation traces should use a shared runtime view model for shelf, rail, and search projections",
);

assert.doesNotMatch(
  usabilityProbe,
  /createWorkflowProject|saveWorkflowProject|createWorkflowFromTemplate|workflow\.template\.instantiate|write_text\([^)]*workflow/i,
  "Usability probe must not create or mutate workflow files through direct APIs",
);

assert.doesNotMatch(
  composer,
  /includes\([^)]*(create|send|financial|approval)/i,
  "Policy validation should not infer privileged behavior from node names or lexical action fragments",
);

console.log("workflowComposerWiring.test.ts: ok");
