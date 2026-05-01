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
const workflowRailPanel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowRailPanel.tsx",
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
const workflowComposerUi = `${composer}\n${workflowComposerModals}\n${workflowNodeConfigModal}\n${workflowNodeBindingEditor}\n${workflowNodeBindingEditorSections}\n${workflowFunctionBindingEditor}\n${workflowNodeDetailGrid}\n${workflowRailPanel}\n${workflowBottomShelf}`;
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
const workflowDefaults = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-defaults.ts",
    import.meta.url,
  ),
  "utf8",
);
const harnessWorkflow = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/harness-workflow.ts",
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
  /!workflowActive[\s\S]*controller\.chat\.paneVisible/,
  "Workflows should suppress the auxiliary chat pane",
);

assert.match(
  shellContent,
  /const utilityDrawerVisible =[\s\S]*activeView !== "chat"[\s\S]*activeView !== "home"[\s\S]*!workflowActive[\s\S]*\{utilityDrawerVisible \? \(/,
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
  `${workflowRailModel}\n${workflowRailPanel}\n${workflowBottomShelf}\n${workflowNodeDetailGrid}\n${workflowComposerModals}`,
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
  /workflowNodeCreatorBadge[\s\S]*Needs model[\s\S]*Needs connector/,
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
  /workflow-add-agent-loop-macro[\s\S]*handleInsertAgentLoopMacro/,
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
  /(?=[\s\S]*grid-template-rows: auto auto auto minmax\(0, 1fr\) minmax\(220px, 31vh\))(?=[\s\S]*workflow-composer-bottom\[data-testid="workflow-bottom-run_output"\][\s\S]*min-height: min\(320px, 36vh\))(?=[\s\S]*workflow-run-detail-grid[\s\S]*align-content: start)/,
  "Run Output should have enough default shelf height to show run details without clipping in a maximized workbench",
);

assert.match(
  workflowRailPanel,
  /railSearchQuery[\s\S]*workflowRailSearchResults\(workflow, tests, normalizedRailSearch\)[\s\S]*workflow-rail-search-input[\s\S]*workflow-rail-search-results[\s\S]*onInspectNode/,
  "Search rail should index nodes, tests, and outputs and let users jump to matching nodes",
);

assert.match(
  workflowRailModel,
  /workflowRailSearchResults[\s\S]*workflowSelectedNodeBindingSummary[\s\S]*resultKind: "Node"[\s\S]*resultKind: "Test"[\s\S]*resultKind: "Output"/,
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
  workflowRailPanel,
  /workflowBindingRegistryRows\(workflow\)[\s\S]*workflowBindingRegistrySummary\(bindingRegistryRows\)[\s\S]*workflow-binding-registry-row-\$\{row\.nodeItem\.id\}[\s\S]*workflow-binding-check-\$\{row\.id\}[\s\S]*workflow-binding-check-result-\$\{row\.id\}/,
  "Settings rail should render binding registry rows from the extracted rail model",
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
  composer,
  /generateWorkflowBindingManifest[\s\S]*setBindingManifest[\s\S]*bindingManifest=\{bindingManifest\}[\s\S]*onGenerateBindingManifest=\{handleGenerateBindingManifest\}/,
  "Workflow Settings should generate binding manifests through the runtime and render manifest state without writing UI state into the graph",
);

assert.match(
  workflowRailPanel,
  /workflow-readiness-summary[\s\S]*workflow-readiness-attention[\s\S]*workflow-readiness-attention-\$\{index\}[\s\S]*onResolveIssue\(issue\)[\s\S]*workflow-readiness-checklist[\s\S]*workflow-readiness-blockers[\s\S]*onResolveIssue\(issue\)[\s\S]*workflow-readiness-warnings[\s\S]*workflow-readiness-warning-\$\{index\}[\s\S]*onResolveIssue\(issue\)[\s\S]*workflow-readiness-policy-nodes[\s\S]*onInspectNode/,
  "Readiness rail should summarize launch checks and make blockers/policy-required nodes actionable",
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
  workflowRailPanel,
  /sourceAndTriggerNodes[\s\S]*workflow-sources-list[\s\S]*workflow-source-node-\$\{nodeItem\.id\}[\s\S]*onInspectNode/,
  "Sources rail should list source and trigger start points with click-through inspection",
);

assert.match(
  workflowRailPanel,
  /workflowFileBundleItems\([\s\S]*workflow,[\s\S]*tests,[\s\S]*proposals,[\s\S]*runs,[\s\S]*portablePackage,[\s\S]*bindingManifest,[\s\S]*\)[\s\S]*workflow-files-list/,
  "Files rail should show workflow bundle sidecars and portable package status",
);

assert.match(
  workflowRailModel,
  /workflowFileBundleItems[\s\S]*Workflow graph[\s\S]*Tests sidecar[\s\S]*Proposal sidecar[\s\S]*Run sidecar[\s\S]*Binding manifest[\s\S]*Portable package/,
  "Workflow bundle file rows should live in the extracted rail model",
);

assert.match(
  workflowRailPanel,
  /triggerNodes[\s\S]*workflow-schedules-list[\s\S]*workflow-schedule-node-\$\{nodeItem\.id\}[\s\S]*cronSchedule[\s\S]*eventSourceRef/,
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
  /WorkflowHarnessComponentSpec[\s\S]*inputSchema[\s\S]*outputSchema[\s\S]*errorSchema[\s\S]*WorkflowHarnessWorkerBinding[\s\S]*harnessWorkflowId[\s\S]*harnessActivationId[\s\S]*harnessHash/,
  "Harness-as-workflow types should expose durable component contracts and worker harness identity fields",
);

assert.match(
  harnessWorkflow,
  /DEFAULT_AGENT_HARNESS_COMPONENTS[\s\S]*kind: "planner"[\s\S]*kind: "mcp_provider"[\s\S]*kind: "mcp_tool_call"[\s\S]*kind: "receipt_writer"[\s\S]*makeDefaultAgentHarnessWorkflow[\s\S]*readOnly: true/,
  "Default Agent Harness projection should componentize planner, MCP providers/tools, receipts, and expose a read-only workflow graph",
);

assert.match(
  harnessWorkflow,
  /forkDefaultAgentHarnessWorkflow[\s\S]*forkedFrom[\s\S]*activationState: "blocked"[\s\S]*proposal-[\s\S]*activation-gates/,
  "Forking the Default Agent Harness should create editable lineage metadata with activation blockers and package proposal sidecars",
);

assert.match(
  workflowValidation,
  /(?=[\s\S]*workflowIsHarnessFork)(?=[\s\S]*harness_required_slot_unbound)(?=[\s\S]*harness_activation_not_validated)(?=[\s\S]*harness_self_mutation_not_proposal_only)/,
  "Harness activation readiness should block invalid forks, unbound slots, missing activation ids, and direct AI self-mutation",
);

assert.match(
  workflowComposerUi,
  /(?=[\s\S]*workflow-open-default-harness)(?=[\s\S]*handleOpenDefaultHarness)(?=[\s\S]*workflow-fork-harness-button)(?=[\s\S]*handleForkDefaultHarness)(?=[\s\S]*workflow-readonly-badge)(?=[\s\S]*workflow-harness-worker-binding)/,
  "Workflow GUI should expose a read-only Default Agent Harness view and an editable fork path with worker harness identity",
);

assert.match(
  workflowRailPanel,
  /workflow-settings-harness-summary[\s\S]*workflow-harness-slots[\s\S]*workflow-selected-node-harness-component[\s\S]*workflow-selected-node-harness-receipts[\s\S]*workflow-selected-node-replay-binding/,
  "Workflow rail should render harness slots, component ids, receipt mappings, and replay metadata at node level",
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
  /WorkflowToolBindingKind = "plugin_tool" \| "mcp_tool" \| "workflow_tool"[\s\S]*workflowTool\?:/,
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
  workflowComposerUi,
  /id: "readiness"[\s\S]*Readiness[\s\S]*handleCheckReadiness[\s\S]*validateWorkflowExecutionReadiness[\s\S]*Trigger or source[\s\S]*Model binding[\s\S]*Live bindings for activation[\s\S]*Outputs defined[\s\S]*Tests present/,
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
  /workflow-connector-binding-modal[\s\S]*workflow-connector-binding-summary[\s\S]*workflow-connector-binding-list[\s\S]*workflow-connector-binding-row-\$\{row\.nodeItem\.id\}[\s\S]*onInspectNode/,
  "Connector bindings modal should expose binding readiness and jump to per-node configuration",
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
  /interface WorkflowPortablePackageManifest[\s\S]*readinessStatus[\s\S]*portable[\s\S]*files: WorkflowPortablePackageFile\[\]/,
  "Portable workflow package manifests should carry readiness and file integrity metadata",
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
  /handleImportPortablePackage[\s\S]*importWorkflowPackage/,
  "Workflow readiness UI should import portable packages through the workflow runtime",
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
  /\b(CIRC|CEC|ledger|receipt|completion gate)\b/i,
  "The workflow composer should not surface audit vocabulary in product UI copy",
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
  workflowRailPanel,
  /(?=[\s\S]*runSearchQuery)(?=[\s\S]*setRunSearchQuery)(?=[\s\S]*runStatusFilter)(?=[\s\S]*setRunStatusFilter)(?=[\s\S]*filteredRuns)(?=[\s\S]*visibleRuns)(?=[\s\S]*workflow-run-filters)(?=[\s\S]*workflow-run-search-input)(?=[\s\S]*workflow-run-status-filter)(?=[\s\S]*workflow-runs-empty-filtered)/,
  "Runs rail should filter high-volume execution history instead of dumping an overwhelming run count",
);

assert.match(
  workflowComposerUi,
  /handleCompareRun[\s\S]*loadWorkflowRun[\s\S]*compareRunRecords[\s\S]*workflow-run-compare[\s\S]*input changed[\s\S]*workflow-bottom-run-compare[\s\S]*workflow-bottom-run-compare-nodes[\s\S]*workflow-bottom-run-compare-state/,
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
  workflowComposerUi,
  /workflowInterruptPreview\(lastRunResult\)[\s\S]*workflow-interrupt-preview[\s\S]*workflow-run-action-preview[\s\S]*Approve and resume/,
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
  /interface WorkflowNodeRun[\s\S]*attempt: number;[\s\S]*input\?: unknown;[\s\S]*output\?: unknown;/,
  "Workflow node run records should persist typed input and output for execution inspection",
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
  workflowRailPanel,
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
