import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
} from "react";
import { ReactFlowProvider } from "@xyflow/react";
import {
  Activity,
  Brain,
  Cable,
  CalendarClock,
  CheckCircle2,
  Database,
  FileOutput,
  FlaskConical,
  FolderOpen,
  GitCompare,
  GitPullRequest,
  ListChecks,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Plus,
  Rocket,
  Save,
  Search,
  Settings,
  type LucideIcon,
} from "lucide-react";
import { AgentWorkbenchRuntime } from "./runtime/agent-runtime";
import { Canvas } from "./features/Editor/Canvas/Canvas";
import { WorkflowBottomShelf } from "./features/Workflows/WorkflowBottomShelf";
import { WorkflowRailPanel } from "./features/Workflows/WorkflowRailPanel";
import {
  WorkflowNodeConfigModal,
  type WorkflowCompatibleNodeHint,
  type WorkflowUpstreamReference,
} from "./features/Workflows/WorkflowNodeConfigModal";
import {
  ConnectorBindingModal,
  CreateWorkflowModal,
  DeployModal,
  ImportPackageModal,
  ModelBindingModal,
  ProposalPreviewModal,
  TestEditorModal,
} from "./features/Workflows/WorkflowComposerModals";
import type { WorkflowNodeConfigSectionId } from "./features/Workflows/WorkflowNodeConfigTypes";
import { useGraphExecution } from "./hooks/useGraphExecution";
import { useGraphState } from "./hooks/useGraphState";
import {
  CreateWorkflowProjectRequest,
  CreateWorkflowProposalRequest,
  FirewallPolicy,
  GraphGlobalConfig,
  ImportWorkflowPackageRequest,
  Node,
  NodeLogic,
  ProjectFile,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowBottomPanel,
  WorkflowConnectionClass,
  WorkflowExecutionMode,
  WorkflowKind,
  WorkflowNodeKind,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRightPanel,
  WorkflowCheckpoint,
  WorkflowDogfoodRun,
  WorkflowNodeFixture,
  WorkflowNodeRun,
  WorkflowPortablePackage,
  WorkflowResumeRequest,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowTestRunResult,
  WorkflowValidationIssue,
  WorkflowValidationResult,
  WorkflowWorkbenchTab,
} from "./types/graph";
import {
  actionKindForWorkflowNodeType,
  validateActionEdge,
  validateWorkflowConnection,
} from "./runtime/agent-execution-substrate";
import {
  WORKFLOW_NODE_DEFINITIONS,
  workflowNodeCreatorDefinitions,
  workflowNodeActionDefinitions,
  workflowScaffoldDefinitions,
  type WorkflowNodeCreatorDefinition,
  type WorkflowNodeDefinition,
} from "./runtime/workflow-node-registry";
import {
  SCRATCH_WORKFLOW_BLUEPRINTS,
  buildScratchWorkflow,
  type ScratchWorkflowBlueprintId,
} from "./runtime/workflow-scratch-blueprints";
import {
  makeDefaultWorkflow,
  normalizeGlobalConfig,
  slugify,
} from "./runtime/workflow-defaults";
import {
  defaultAgentHarnessTests,
  forkDefaultAgentHarnessWorkflow,
  makeDefaultAgentHarnessWorkflow,
  workflowHarnessWorkerBinding,
  workflowIsBlessedHarness,
  workflowIsHarness,
} from "./runtime/harness-workflow";
import {
  compatiblePortPair,
  createBlockedTestResult,
  createLocalProposal,
  createLocalRunSummary,
  createLocalTestResult,
  createWorkflowActionFailure,
  errorMessage,
  nodeFamilyCounts,
  nodeVisualStatus,
  preferredCompatiblePortPair,
  toWorkflowProject,
  workflowCanvasSearchResults,
  workflowNodeCreatorBadge,
} from "./runtime/workflow-composer-model";
import { workflowNodeDeclaredOutputSchema } from "./runtime/workflow-schema";
import {
  defaultTestsForWorkflow,
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "./runtime/workflow-validation";
import {
  groupFixturesByNodeId,
  workflowFixtureHashesForNode,
  workflowFixtureValidationForNode,
  workflowFixturesForNode,
} from "./runtime/workflow-fixture-model";
import {
  workflowBindingCheckResult,
  type WorkflowBindingRegistryRow,
  workflowDurationLabel,
  workflowEnvironmentProfile,
  workflowEventLabel,
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowLifecycleState,
  workflowNodeRunChildLineage,
  workflowNodeName,
  workflowTimeLabel,
} from "./runtime/workflow-rail-model";
import "./WorkflowComposer.css";
import "./styles/theme.css";

export interface WorkflowComposerProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

export interface WorkflowComposerProps {
  runtime: AgentWorkbenchRuntime;
  currentProject?: WorkflowComposerProjectScope;
  initialFile?: ProjectFile | null;
  onInitialFileLoaded?: () => void;
}

const NODE_LIBRARY = workflowNodeCreatorDefinitions();
const NODE_ACTIONS = workflowNodeActionDefinitions();
const ACTION_BY_NODE_TYPE = new Map(
  NODE_ACTIONS.map((action) => [action.nodeType, action]),
);

function workflowCreatorItemId(
  definition: WorkflowNodeDefinition | WorkflowNodeCreatorDefinition,
): string {
  return "creatorId" in definition ? definition.creatorId : definition.type;
}

function workflowActionMetadataLabel(
  definition: WorkflowNodeDefinition | WorkflowNodeCreatorDefinition,
): string {
  const action = ACTION_BY_NODE_TYPE.get(definition.type);
  if (!action) return "typed action";
  const binding =
    action.bindingMode === "required"
      ? `${action.requiredBinding} binding`
      : "no binding";
  const policy = action.requiresApproval
    ? "approval"
    : action.sandboxed
      ? "sandbox"
      : action.sideEffectClass;
  const schemas = action.schemaRequired ? "schema" : "no schema";
  return [binding, policy, schemas].filter(Boolean).join(" · ");
}

const RIGHT_PANELS: Array<{
  id: WorkflowRightPanel;
  label: string;
  description: string;
  icon: LucideIcon;
}> = [
  {
    id: "outputs",
    label: "Outputs",
    description: "Inspect selected nodes and workflow outputs.",
    icon: FileOutput,
  },
  {
    id: "unit_tests",
    label: "Unit tests",
    description: "Review coverage, assertions, and latest test results.",
    icon: ListChecks,
  },
  {
    id: "sources",
    label: "Sources",
    description: "Manage triggers, source nodes, and workflow entry points.",
    icon: Database,
  },
  {
    id: "search",
    label: "Search",
    description: "Jump across nodes, tests, outputs, and bindings.",
    icon: Search,
  },
  {
    id: "changes",
    label: "Changes",
    description: "Review bounded proposal changes.",
    icon: GitCompare,
  },
  {
    id: "runs",
    label: "Runs",
    description: "Inspect executions, attempts, checkpoints, and timeline.",
    icon: Activity,
  },
  {
    id: "readiness",
    label: "Readiness",
    description: "Resolve blockers before run, package, or deploy.",
    icon: CheckCircle2,
  },
  {
    id: "schedules",
    label: "Schedules",
    description: "Review manual, scheduled, and event starts.",
    icon: CalendarClock,
  },
  {
    id: "files",
    label: "Files",
    description: "Inspect git-backed bundle files and sidecars.",
    icon: FolderOpen,
  },
  {
    id: "settings",
    label: "Settings",
    description: "Edit environment, bindings, policy, and packaging posture.",
    icon: Settings,
  },
];

const SCAFFOLD_GROUPS: Array<WorkflowNodeDefinition["group"]> = [
  "Start",
  "Sources",
  "Transform",
  "AI",
  "Tools",
  "Connectors",
  "Flow",
  "State",
  "Human",
  "Outputs",
  "Tests",
  "Proposals",
];

type WorkflowNodeGroupFilter =
  | WorkflowNodeDefinition["group"]
  | "All"
  | "Compatible";

const NODE_GROUP_FILTERS: WorkflowNodeGroupFilter[] = [
  "All",
  "Compatible",
  ...SCAFFOLD_GROUPS,
];

const WORKFLOW_SCAFFOLDS = workflowScaffoldDefinitions();
const EMPTY_CANVAS_START_CREATOR_IDS = [
  "trigger.manual",
  "source.manual",
  "trigger.scheduled",
  "trigger.event",
  "trigger.chat",
  "source.api_payload",
  "source.file",
  "source.media",
  "source.dataset",
];

const WORKFLOW_ISSUE_SECTION_BY_CODE: Record<
  string,
  WorkflowNodeConfigSectionId
> = {
  invalid_expression_connection: "mapping",
  invalid_field_mapping_source: "mapping",
  invalid_workflow_tool_attempts: "bindings",
  invalid_workflow_tool_timeout: "bindings",
  live_connector_write_unavailable: "bindings",
  live_tool_side_effect_unavailable: "bindings",
  mcp_access_not_reviewed: "policy",
  missing_ai_evaluation_coverage: "tests",
  missing_connector_binding: "bindings",
  missing_edge_endpoint: "connections",
  missing_error_handling_path: "connections",
  missing_event_trigger: "settings",
  missing_expression_node: "mapping",
  missing_expression_port: "mapping",
  missing_field_mapping_path: "mapping",
  missing_function_binding: "bindings",
  missing_live_connector_credential: "bindings",
  missing_live_model_credential: "bindings",
  missing_live_tool_credential: "bindings",
  missing_model_binding: "bindings",
  missing_model_binding_result_schema: "schema",
  missing_model_memory_attachment: "connections",
  missing_model_output_schema: "schema",
  missing_model_parser_attachment: "connections",
  missing_model_tool_attachment: "connections",
  missing_output_node: "outputs",
  missing_output_schema: "schema",
  missing_parser_binding: "bindings",
  missing_parser_result_schema: "schema",
  missing_proposal_bounds: "advanced",
  missing_replay_fixture: "fixtures",
  missing_scheduled_trigger: "settings",
  missing_start_node: "settings",
  missing_state_key: "settings",
  missing_subgraph_ref: "bindings",
  missing_test_target: "tests",
  missing_tool_binding: "bindings",
  missing_trigger_event_source: "settings",
  missing_trigger_schedule: "settings",
  missing_unit_tests: "tests",
  missing_workflow_tool_argument_schema: "schema",
  missing_workflow_tool_ref: "bindings",
  missing_workflow_tool_result_schema: "schema",
  mock_binding_active: "bindings",
  open_proposal: "advanced",
  operational_value_not_estimated: "advanced",
  output_policy_required: "policy",
  policy_required: "policy",
  proposal_approval_required: "policy",
  self_edge: "connections",
  unbound_model_ref: "bindings",
  unconnected_expression_ref: "mapping",
  unsafe_function_permission: "policy",
  unsupported_function_dependency: "bindings",
  unsupported_function_runtime: "bindings",
  unsupported_live_trigger: "settings",
  unsupported_node_kind: "settings",
};

const BOTTOM_TABS: Array<{ id: WorkflowBottomPanel; label: string }> = [
  { id: "selection", label: "Selection Preview" },
  { id: "data", label: "Data Preview" },
  { id: "suggestions", label: "Suggestions" },
  { id: "warnings", label: "Warnings" },
  { id: "fixtures", label: "Fixtures" },
  { id: "checkpoints", label: "Checkpoints" },
  { id: "proposal_diff", label: "Proposal Diff" },
  { id: "test_output", label: "Test Output" },
  { id: "run_output", label: "Run Output" },
];

const SCRATCH_DOGFOOD_WORKFLOW_NAME = "Scratch GUI Node Composition";
const SCRATCH_HEAVY_BLUEPRINTS: ScratchWorkflowBlueprintId[] = [
  ...SCRATCH_WORKFLOW_BLUEPRINTS,
];
const SCRATCH_DOGFOOD_SCRIPT =
  typeof import.meta !== "undefined"
    ? ((import.meta as unknown as { env?: Record<string, string | undefined> })
        .env?.VITE_AUTOPILOT_WORKFLOW_DOGFOOD_SCRIPT as string | undefined)
    : undefined;

function WorkflowHeaderAction({
  label,
  icon: Icon,
  testId,
  onClick,
  variant = "secondary",
  showLabel = false,
  title,
  disabled = false,
}: {
  label: string;
  icon: LucideIcon;
  testId: string;
  onClick: () => void;
  variant?: "primary" | "secondary";
  showLabel?: boolean;
  title?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      className={`workflow-action-button is-${variant}`}
      data-testid={testId}
      aria-label={label}
      title={title ?? label}
      disabled={disabled}
      onClick={onClick}
    >
      <WorkflowInlineIcon icon={Icon} />
      {showLabel ? (
        <span className="workflow-action-label">{label}</span>
      ) : (
        <span className="workflow-action-tooltip">{label}</span>
      )}
    </button>
  );
}

function WorkflowInlineIcon({
  icon,
  size = 15,
}: {
  icon: LucideIcon;
  size?: number;
}) {
  const Icon = icon as unknown as (props: {
    size?: number;
    strokeWidth?: number;
    "aria-hidden"?: string;
  }) => JSX.Element;
  return <Icon size={size} strokeWidth={1.8} aria-hidden="true" />;
}

function workflowPatchBoundedTargets(
  workflow: WorkflowProject,
  options: { selectedNodeId?: string; includeWorkflowConfig?: boolean } = {},
): string[] {
  const targets = options.selectedNodeId
    ? [options.selectedNodeId]
    : workflow.nodes.map((node) => node.id);
  if (options.includeWorkflowConfig ?? true) {
    targets.push("workflow-config", "workflow-metadata");
  }
  return Array.from(new Set(targets.filter(Boolean)));
}

function workflowIssueCountLabel(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

function workflowValidationBlockingIssueCount(
  result: WorkflowValidationResult,
): number {
  return (
    result.errors.length +
    result.missingConfig.length +
    result.connectorBindingIssues.length +
    (result.executionReadinessIssues?.length ?? 0) +
    (result.verificationIssues?.length ?? 0) +
    result.unsupportedRuntimeNodes.length
  );
}

function workflowValidationIssueKey(
  issue: WorkflowValidationIssue,
): string {
  return `${issue.nodeId ?? "workflow"}:${issue.code}:${issue.message}`;
}

function workflowCanvasIssuesByNodeId(
  validationResult: WorkflowValidationResult | null,
  readinessResult: WorkflowValidationResult | null,
): Map<
  string,
  {
    blockers: WorkflowValidationIssue[];
    warnings: WorkflowValidationIssue[];
    primaryIssue: WorkflowValidationIssue;
  }
> {
  const byNode = new Map<
    string,
    {
      blockers: WorkflowValidationIssue[];
      warnings: WorkflowValidationIssue[];
      seen: Set<string>;
    }
  >();
  const addIssue = (
    issue: WorkflowValidationIssue,
    severity: "blocker" | "warning",
  ) => {
    if (!issue.nodeId) return;
    const existing =
      byNode.get(issue.nodeId) ??
      {
        blockers: [],
        warnings: [],
        seen: new Set<string>(),
      };
    const key = workflowValidationIssueKey(issue);
    if (existing.seen.has(key)) return;
    existing.seen.add(key);
    if (severity === "blocker") {
      existing.blockers.push(issue);
    } else {
      existing.warnings.push(issue);
    }
    byNode.set(issue.nodeId, existing);
  };
  const addResult = (result: WorkflowValidationResult | null) => {
    if (!result) return;
    result.errors.forEach((issue) => addIssue(issue, "blocker"));
    result.missingConfig.forEach((issue) => addIssue(issue, "blocker"));
    result.connectorBindingIssues.forEach((issue) =>
      addIssue(issue, "blocker"),
    );
    (result.executionReadinessIssues ?? []).forEach((issue) =>
      addIssue(issue, "blocker"),
    );
    (result.verificationIssues ?? []).forEach((issue) =>
      addIssue(issue, "blocker"),
    );
    result.warnings.forEach((issue) => addIssue(issue, "warning"));
  };
  addResult(validationResult);
  addResult(readinessResult);
  return new Map(
    Array.from(byNode.entries()).map(([nodeId, value]) => [
      nodeId,
      {
        blockers: value.blockers,
        warnings: value.warnings,
        primaryIssue: value.blockers[0] ?? value.warnings[0],
      },
    ]),
  );
}

function workflowValidationStatusMessage(
  label: string,
  result: WorkflowValidationResult,
): string {
  const blockingIssues = workflowValidationBlockingIssueCount(result);
  if (result.status === "blocked") {
    return `${label} blocked by ${workflowIssueCountLabel(
      Math.max(blockingIssues, 1),
      "issue",
    )}`;
  }
  if (result.status === "failed") {
    return blockingIssues > 0
      ? `${label} failed with ${workflowIssueCountLabel(blockingIssues, "issue")}`
      : `${label} failed`;
  }
  if (result.warnings.length > 0) {
    return `${label} passed with ${workflowIssueCountLabel(
      result.warnings.length,
      "warning",
    )}`;
  }
  return `${label} passed`;
}

function workflowChecksStatusMessage(
  status: "passed" | "failed" | "blocked",
  options: {
    warningCount?: number;
    blockedWorkflowCount?: number;
    readinessAttentionWorkflowCount?: number;
  } = {},
): string {
  if (
    status === "passed" &&
    (options.readinessAttentionWorkflowCount ?? 0) > 0
  ) {
    return `Run checks passed; ${workflowIssueCountLabel(
      options.readinessAttentionWorkflowCount ?? 0,
      "readiness review",
    )} need attention`;
  }
  if (status === "passed" && (options.warningCount ?? 0) > 0) {
    return `Run checks passed with ${workflowIssueCountLabel(
      options.warningCount ?? 0,
      "warning",
    )}`;
  }
  if (status !== "passed" && (options.blockedWorkflowCount ?? 0) > 0) {
    return `Run checks ${status} by ${workflowIssueCountLabel(
      options.blockedWorkflowCount ?? 0,
      "workflow",
    )}`;
  }
  return `Run checks ${status}`;
}

function workflowConfigSectionForNodeKind(
  kind: string,
): WorkflowNodeConfigSectionId {
  if (
    [
      "function",
      "model_call",
      "model_binding",
      "adapter",
      "plugin_tool",
      "parser",
      "state",
      "trigger",
      "source",
      "output",
      "proposal",
      "subgraph",
    ].includes(kind)
  ) {
    return "bindings";
  }
  if (kind === "test_assertion") return "tests";
  if (kind === "human_gate") return "policy";
  return "settings";
}

function workflowConfigSectionForIssue(
  issue: WorkflowValidationIssue,
): WorkflowNodeConfigSectionId {
  if (
    issue.configSection &&
    [
      "settings",
      "connections",
      "inputs",
      "mapping",
      "outputs",
      "schema",
      "bindings",
      "policy",
      "fixtures",
      "run-data",
      "tests",
      "advanced",
    ].includes(issue.configSection)
  ) {
    return issue.configSection as WorkflowNodeConfigSectionId;
  }
  return WORKFLOW_ISSUE_SECTION_BY_CODE[issue.code] ?? "settings";
}

function WorkflowComposerContent({
  runtime,
  currentProject,
  initialFile,
  onInitialFileLoaded,
}: WorkflowComposerProps) {
  const defaultWorkflow = useMemo(() => makeDefaultWorkflow(), []);
  const {
    nodes,
    edges,
    setNodes,
    setEdges,
    onNodesChange,
    onEdgesChange,
    onConnect,
    handleCanvasDrop,
    selectedNodeId,
    handleNodeSelect,
    fitView,
    zoomIn,
    zoomOut,
    replaceGraph,
    addNode,
  } = useGraphState(defaultWorkflow.nodes, defaultWorkflow.edges);
  const execution = useGraphExecution(
    runtime,
    nodes,
    edges,
    setNodes,
    setEdges,
  );
  const [workflow, setWorkflow] = useState<WorkflowProject>(defaultWorkflow);
  const [workflowPath, setWorkflowPath] = useState(
    currentProject?.rootPath
      ? `${currentProject.rootPath}/.agents/workflows/${defaultWorkflow.metadata.slug}.workflow.json`
      : defaultWorkflow.metadata.gitLocation ||
          ".agents/workflows/agent-workflow.workflow.json",
  );
  const [testsPath, setTestsPath] = useState(
    workflowPath.replace(/\.workflow\.json$/, ".tests.json"),
  );
  const [tests, setTests] = useState<WorkflowTestCase[]>([]);
  const [proposals, setProposals] = useState<WorkflowProposal[]>([]);
  const [runs, setRuns] = useState<WorkflowRunSummary[]>([]);
  const [activeTab, setActiveTab] = useState<WorkflowWorkbenchTab>("graph");
  const [rightPanel, setRightPanel] = useState<WorkflowRightPanel>("outputs");
  const [bottomPanel, setBottomPanel] =
    useState<WorkflowBottomPanel>("selection");
  const [rightRailCollapsed, setRightRailCollapsed] = useState(false);
  const [rightRailWidth, setRightRailWidth] = useState(336);
  const [leftDrawerOpen, setLeftDrawerOpen] = useState(false);
  const [nodeSearch, setNodeSearch] = useState("");
  const [canvasSearchOpen, setCanvasSearchOpen] = useState(false);
  const [canvasSearchQuery, setCanvasSearchQuery] = useState("");
  const [nodeConfigOpen, setNodeConfigOpen] = useState(false);
  const [nodeConfigInitialSection, setNodeConfigInitialSection] =
    useState<WorkflowNodeConfigSectionId>("settings");
  const [compatiblePortFocus, setCompatiblePortFocus] = useState<{
    nodeId: string;
    portId: string;
    direction: "downstream" | "attachment";
  } | null>(null);
  const [modelBindingOpen, setModelBindingOpen] = useState(false);
  const [connectorBindingOpen, setConnectorBindingOpen] = useState(false);
  const [testEditorOpen, setTestEditorOpen] = useState(false);
  const [deployOpen, setDeployOpen] = useState(false);
  const [proposalToReview, setProposalToReview] =
    useState<WorkflowProposal | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [nodeGroupFilter, setNodeGroupFilter] =
    useState<WorkflowNodeGroupFilter>("All");
  const [recentNodeTypes, setRecentNodeTypes] = useState<string[]>([]);
  const [createName, setCreateName] = useState("New blank workflow");
  const [createKind, setCreateKind] = useState<WorkflowKind>("agent_workflow");
  const [createMode, setCreateMode] = useState<WorkflowExecutionMode>("local");
  const [newTestName, setNewTestName] = useState("Selected node exists");
  const [newTestTargets, setNewTestTargets] = useState("");
  const [newTestKind, setNewTestKind] =
    useState<WorkflowTestCase["assertion"]["kind"]>("node_exists");
  const [newTestExpected, setNewTestExpected] = useState("");
  const [newTestExpression, setNewTestExpression] = useState("");
  const [statusMessage, setStatusMessage] = useState("Ready");
  const [testResult, setTestResult] = useState<WorkflowTestRunResult | null>(
    null,
  );
  const [validationResult, setValidationResult] =
    useState<WorkflowValidationResult | null>(null);
  const [readinessResult, setReadinessResult] =
    useState<WorkflowValidationResult | null>(null);
  const [lastRunResult, setLastRunResult] = useState<WorkflowRunResult | null>(
    null,
  );
  const [runDetailLoading, setRunDetailLoading] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [compareRunResult, setCompareRunResult] =
    useState<WorkflowRunResult | null>(null);
  const [compareRunId, setCompareRunId] = useState<string | null>(null);
  const [functionDryRunResult, setFunctionDryRunResult] =
    useState<WorkflowRunResult | null>(null);
  const [dogfoodRun, setDogfoodRun] = useState<WorkflowDogfoodRun | null>(null);
  const [portablePackage, setPortablePackage] =
    useState<WorkflowPortablePackage | null>(null);
  const [bindingManifest, setBindingManifest] =
    useState<WorkflowBindingManifest | null>(null);
  const [importPackageOpen, setImportPackageOpen] = useState(false);
  const [importPackagePath, setImportPackagePath] = useState("");
  const [importPackageName, setImportPackageName] = useState("");
  const [connectFromNodeId, setConnectFromNodeId] = useState<string | null>(
    null,
  );
  const [runEvents, setRunEvents] = useState<WorkflowStreamEvent[]>([]);
  const [checkpoints, setCheckpoints] = useState<WorkflowCheckpoint[]>([]);
  const [nodeRunStatusById, setNodeRunStatusById] = useState<
    Record<string, WorkflowNodeRun>
  >({});
  const [nodeFixturesById, setNodeFixturesById] = useState<
    Record<string, WorkflowNodeFixture[]>
  >({});
  const dogfoodAutomationStarted = useRef(false);
  const [globalConfig, setGlobalConfig] = useState<GraphGlobalConfig>(
    defaultWorkflow.global_config,
  );
  const openLeftDrawer = useCallback(() => {
    setCanvasSearchOpen(false);
    setLeftDrawerOpen(true);
  }, []);
  const closeLeftDrawer = useCallback(() => {
    setLeftDrawerOpen(false);
    setNodeSearch("");
    setNodeGroupFilter("All");
    setCompatiblePortFocus(null);
  }, []);
  const toggleLeftDrawer = useCallback(() => {
    setLeftDrawerOpen((open) => {
      const nextOpen = !open;
      if (nextOpen) {
        setCanvasSearchOpen(false);
      }
      return nextOpen;
    });
  }, []);
  const closeCanvasSearch = useCallback(() => {
    setCanvasSearchOpen(false);
  }, []);
  const toggleCanvasSearch = useCallback(() => {
    setCanvasSearchOpen((open) => {
      const nextOpen = !open;
      if (nextOpen) {
        setLeftDrawerOpen(false);
      }
      return nextOpen;
    });
  }, []);

  const selectedNode =
    (nodes.find((node) => node.id === selectedNodeId)?.data as
      | Node
      | undefined) ?? null;
  const selectedDefinition = selectedNode
    ? WORKFLOW_NODE_DEFINITIONS.find(
        (definition) => definition.type === selectedNode.type,
      )
    : null;
  const selectedOutputClasses = new Set(
    (selectedNode?.ports ?? [])
      .filter((port) => port.direction === "output")
      .map((port) => port.connectionClass),
  );
  const isSearchingNodeLibrary = nodeSearch.trim().length > 0;
  const searchedNodeLibrary = useMemo(() => {
    const query = nodeSearch.trim().toLowerCase();
    return NODE_LIBRARY.filter((item) => {
      const scaffold = WORKFLOW_SCAFFOLDS.find(
        (entry) => entry.nodeType === item.type,
      );
      const action = ACTION_BY_NODE_TYPE.get(item.type);
      const haystack = [
        item.label,
        item.group,
        item.familyLabel,
        item.metricLabel,
        "creatorDescription" in item ? item.creatorDescription : "",
        action?.description,
        action?.requiredBinding,
        action?.sideEffectClass,
        action?.requiresApproval ? "approval" : "",
        action?.supportsMockBinding ? "mock live credential" : "",
        action?.schemaRequired ? "schema typed contract" : "",
        ...(scaffold?.keywords ?? []),
        ...(scaffold?.connectionClasses ?? []),
        ...(action?.keywords ?? []),
        ...(action?.connectionClasses ?? []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return !query || haystack.includes(query);
    });
  }, [nodeSearch]);
  const compatibleNodeHints = useMemo<WorkflowCompatibleNodeHint[]>(() => {
    if (!selectedNode) return [];
    const selectedActionKind = actionKindForWorkflowNodeType(selectedNode.type);
    const selectedOutputPorts = (selectedNode.ports ?? []).filter(
      (port) => port.direction === "output",
    );
    const selectedInputPorts = (selectedNode.ports ?? []).filter(
      (port) => port.direction === "input",
    );
    const selectedScaffold = WORKFLOW_SCAFFOLDS.find(
      (entry) => entry.nodeType === selectedNode.type,
    );
    const hints = NODE_LIBRARY.flatMap((definition) => {
      const targetActionKind = actionKindForWorkflowNodeType(definition.type);
      const downstreamHints: WorkflowCompatibleNodeHint[] = [];
      for (const sourcePort of selectedOutputPorts) {
        for (const targetPort of definition.portDefinitions.filter(
          (port) => port.direction === "input",
        )) {
          const issue = validateWorkflowConnection(
            selectedActionKind,
            targetActionKind,
            sourcePort,
            targetPort,
          );
          if (!issue) {
            downstreamHints.push({
              definition,
              sourcePort,
              targetPort,
              connectionClass: sourcePort.connectionClass,
              direction: "downstream",
              recommended: Boolean(
                selectedScaffold?.relatedNodeTypes?.includes(
                  definition.type as WorkflowNodeKind,
                ),
              ),
            });
            break;
          }
        }
      }
      const sourceActionKind = targetActionKind;
      const attachmentHints: WorkflowCompatibleNodeHint[] = [];
      for (const sourcePort of definition.portDefinitions.filter(
        (port) => port.direction === "output",
      )) {
        for (const targetPort of selectedInputPorts) {
          const issue = validateWorkflowConnection(
            sourceActionKind,
            selectedActionKind,
            sourcePort,
            targetPort,
          );
          if (!issue) {
            attachmentHints.push({
              definition,
              sourcePort,
              targetPort,
              connectionClass: sourcePort.connectionClass,
              direction: "attachment",
              recommended:
                targetPort.semanticRole !== "input" ||
                Boolean(
                  selectedScaffold?.relatedNodeTypes?.includes(
                    definition.type as WorkflowNodeKind,
                  ),
                ),
            });
            break;
          }
        }
      }
      return [...downstreamHints, ...attachmentHints];
    });
    const scopedHints =
      compatiblePortFocus?.nodeId === selectedNode.id
        ? hints.filter((hint) =>
            compatiblePortFocus.direction === "downstream"
              ? hint.direction === "downstream" &&
                hint.sourcePort.id === compatiblePortFocus.portId
              : hint.direction === "attachment" &&
                hint.targetPort.id === compatiblePortFocus.portId,
          )
        : hints;
    return scopedHints.sort((left, right) => {
      if (left.direction !== right.direction)
        return left.direction === "attachment" ? -1 : 1;
      if (left.recommended !== right.recommended)
        return left.recommended ? -1 : 1;
      return (
        left.definition.group.localeCompare(right.definition.group) ||
        left.definition.label.localeCompare(right.definition.label)
      );
    });
  }, [compatiblePortFocus, selectedNode, selectedOutputClasses]);
  const compatiblePortFocusLabel = useMemo(() => {
    if (!selectedNode || compatiblePortFocus?.nodeId !== selectedNode.id)
      return null;
    const port = (selectedNode.ports ?? []).find(
      (candidate) => candidate.id === compatiblePortFocus.portId,
    );
    if (!port) return null;
    return `${selectedNode.name} · ${port.label}`;
  }, [compatiblePortFocus, selectedNode]);
  const compatibleCreatorIds = useMemo(
    () =>
      new Set(
        compatibleNodeHints.map((hint) =>
          workflowCreatorItemId(hint.definition),
        ),
      ),
    [compatibleNodeHints],
  );
  const searchedCreatorIds = useMemo(
    () => new Set(searchedNodeLibrary.map(workflowCreatorItemId)),
    [searchedNodeLibrary],
  );
  const filteredNodeLibrary = useMemo(
    () =>
      searchedNodeLibrary.filter((item) => {
        if (nodeGroupFilter === "All") return true;
        if (nodeGroupFilter === "Compatible")
          return compatibleCreatorIds.has(workflowCreatorItemId(item));
        return item.group === nodeGroupFilter;
      }),
    [compatibleCreatorIds, nodeGroupFilter, searchedNodeLibrary],
  );
  const visibleCompatibleNodeHints = useMemo(
    () =>
      compatibleNodeHints.filter((hint) => {
        const itemId = workflowCreatorItemId(hint.definition);
        if (!searchedCreatorIds.has(itemId)) return false;
        if (nodeGroupFilter === "All" || nodeGroupFilter === "Compatible")
          return true;
        return hint.definition.group === nodeGroupFilter;
      }),
    [compatibleNodeHints, nodeGroupFilter, searchedCreatorIds],
  );
  const recentNodeLibrary = useMemo(
    () =>
      recentNodeTypes
        .map((creatorId) =>
          filteredNodeLibrary.find(
            (item) => workflowCreatorItemId(item) === creatorId,
          ),
        )
        .filter((item): item is WorkflowNodeCreatorDefinition => Boolean(item)),
    [filteredNodeLibrary, recentNodeTypes],
  );
  const nodeGroupCounts = useMemo(() => {
    const counts = new Map<WorkflowNodeGroupFilter, number>();
    counts.set("All", searchedNodeLibrary.length);
    counts.set(
      "Compatible",
      searchedNodeLibrary.filter((item) =>
        compatibleCreatorIds.has(workflowCreatorItemId(item)),
      ).length,
    );
    for (const group of SCAFFOLD_GROUPS) {
      counts.set(
        group,
        searchedNodeLibrary.filter((item) => item.group === group).length,
      );
    }
    return counts;
  }, [compatibleCreatorIds, searchedNodeLibrary]);
  const emptyCanvasStartItems = useMemo(
    () =>
      EMPTY_CANVAS_START_CREATOR_IDS.map((creatorId) =>
        NODE_LIBRARY.find((item) => workflowCreatorItemId(item) === creatorId),
      ).filter((item): item is WorkflowNodeCreatorDefinition => Boolean(item)),
    [],
  );
  const selectedUpstreamReferences = useMemo<
    WorkflowUpstreamReference[]
  >(() => {
    if (!selectedNode) return [];
    return edges
      .filter((edge) => edge.target === selectedNode.id)
      .map((edge) => {
        const source = nodes.find((flowNode) => flowNode.id === edge.source);
        const sourceData = source?.data as Node | undefined;
        if (!sourceData) return null;
        const portId = edge.sourceHandle ?? "output";
        const sourcePort = sourceData.ports?.find(
          (port) => port.id === portId && port.direction === "output",
        );
        const latestOutput = nodeRunStatusById[sourceData.id]?.output;
        return {
          nodeId: sourceData.id,
          nodeName: sourceData.name,
          nodeType: sourceData.type,
          portId,
          connectionClass:
            sourcePort?.connectionClass ??
            (edge.data?.connectionClass as
              | WorkflowConnectionClass
              | undefined) ??
            "data",
          expression: `{{nodes.${sourceData.id}.${portId}}}`,
          schema: workflowNodeDeclaredOutputSchema(sourceData, latestOutput),
          latestOutput,
        };
      })
      .filter((item): item is WorkflowUpstreamReference => Boolean(item));
  }, [edges, nodeRunStatusById, nodes, selectedNode]);
  const selectedFixtures = useMemo(
    () => workflowFixturesForNode(selectedNode, nodeFixturesById),
    [nodeFixturesById, selectedNode],
  );
  const canvasSearchResults = useMemo(() => {
    return workflowCanvasSearchResults(
      nodes,
      nodeRunStatusById,
      canvasSearchQuery,
    );
  }, [canvasSearchQuery, nodeRunStatusById, nodes]);
  const counts = nodeFamilyCounts(nodes);
  const missingReasoningBinding = useMemo(
    () =>
      nodes.some((flowNode) => {
        const nodeItem = flowNode.data as Node | undefined;
        if (!nodeItem || nodeItem.type !== "model_call") return false;
        const logic = nodeItem.config?.logic ?? {};
        const modelRef = String(logic.modelRef ?? "reasoning");
        const hasInlineBinding = Boolean(logic.modelBinding?.modelRef);
        const hasGlobalBinding = Boolean(
          globalConfig.modelBindings[modelRef]?.modelId,
        );
        const hasAttachedModelBinding = edges.some((edge) => {
          if (edge.target !== nodeItem.id) return false;
          const connectionClass =
            (edge.data?.connectionClass as
              | WorkflowConnectionClass
              | undefined) ??
            (
              edge.data as
                | { connectionClass?: WorkflowConnectionClass }
                | undefined
            )?.connectionClass;
          return edge.targetHandle === "model" || connectionClass === "model";
        });
        return (
          !hasInlineBinding && !hasGlobalBinding && !hasAttachedModelBinding
        );
      }),
    [edges, globalConfig.modelBindings, nodes],
  );
  const canvasIssuesByNodeId = useMemo(
    () => workflowCanvasIssuesByNodeId(validationResult, readinessResult),
    [readinessResult, validationResult],
  );
  const canvasEdgeIssues = useMemo(() => {
    const nodeById = new Map(
      nodes.map((flowNode) => [flowNode.id, flowNode]),
    );
    const issueByEdge = new Map<
      string,
      Pick<WorkflowValidationIssue, "code" | "message">
    >();
    edges.forEach((edge) => {
      const sourceNode = nodeById.get(edge.source);
      const targetNode = nodeById.get(edge.target);
      if (!sourceNode || !targetNode) {
        issueByEdge.set(edge.id, {
          code: "missing_edge_endpoint",
          message: "This connection references a missing node.",
        });
        return;
      }
      const sourceData = sourceNode.data as Node | undefined;
      const targetData = targetNode.data as Node | undefined;
      const sourceType = String(sourceData?.type ?? sourceNode.type ?? "");
      const targetType = String(targetData?.type ?? targetNode.type ?? "");
      const sourcePort = sourceData?.ports?.find(
        (port) =>
          port.direction === "output" &&
          port.id === (edge.sourceHandle || "output"),
      );
      const targetPort = targetData?.ports?.find(
        (port) =>
          port.direction === "input" &&
          port.id === (edge.targetHandle || "input"),
      );
      const edgeIssue = validateActionEdge(
        edge.source,
        actionKindForWorkflowNodeType(sourceType),
        edge.target,
        actionKindForWorkflowNodeType(targetType),
        sourcePort ?? null,
        targetPort ?? null,
      );
      if (edgeIssue) {
        issueByEdge.set(edge.id, edgeIssue);
      }
    });
    return issueByEdge;
  }, [edges, nodes]);
  const handleShowCompatibleNodesForPort = useCallback(
    (request: {
      nodeId: string;
      portId: string;
      direction: "downstream" | "attachment";
    }) => {
      const nodeItem = nodes.find((flowNode) => flowNode.id === request.nodeId)
        ?.data as Node | undefined;
      const port = (nodeItem?.ports ?? []).find(
        (candidate) => candidate.id === request.portId,
      );
      handleNodeSelect(request.nodeId);
      setCompatiblePortFocus(request);
      setNodeGroupFilter("Compatible");
      setNodeSearch("");
      openLeftDrawer();
      setStatusMessage(
        port
          ? `Showing compatible nodes for ${nodeItem?.name ?? request.nodeId} · ${port.label}`
          : `Showing compatible nodes for ${nodeItem?.name ?? request.nodeId}`,
      );
    },
    [handleNodeSelect, nodes, openLeftDrawer],
  );
  const displayEdges = useMemo(
    () =>
      edges.map((edge) => {
        const issue = canvasEdgeIssues.get(edge.id);
        return {
          ...edge,
          data: {
            ...(edge.data ?? {}),
            ...(issue
              ? {
                  issueCount: 1,
                  issueStatus: "blocked",
                  issueTitle: workflowIssueTitle(issue),
                  issueMessage: issue.message,
                }
              : {
                  issueCount: 0,
                  issueStatus: null,
                  issueTitle: null,
                  issueMessage: null,
                }),
          },
        };
      }),
    [canvasEdgeIssues, edges],
  );

  const loadWorkflowProject = useCallback(
    (next: WorkflowProject) => {
      setWorkflow(next);
      setGlobalConfig(normalizeGlobalConfig(next.global_config));
      replaceGraph(next);
      requestAnimationFrame(() => fitView({ padding: 0.22 }));
    },
    [fitView, replaceGraph],
  );

  useEffect(() => {
    if (!initialFile) return;
    const next = {
      ...makeDefaultWorkflow(
        initialFile.global_config?.meta?.name || "Generated workflow",
      ),
      ...initialFile,
      metadata: initialFile.metadata ?? makeDefaultWorkflow().metadata,
      global_config: normalizeGlobalConfig(initialFile.global_config),
    } as WorkflowProject;
    loadWorkflowProject(next);
    onInitialFileLoaded?.();
  }, [initialFile, loadWorkflowProject, onInitialFileLoaded]);

  const currentProjectFile = useMemo(
    () => toWorkflowProject(nodes, edges, globalConfig, workflow),
    [nodes, edges, globalConfig, workflow],
  );
  const isReadOnlyWorkflow = currentProjectFile.metadata.readOnly === true;
  const isHarnessWorkflow = workflowIsHarness(currentProjectFile);
  const isBlessedHarnessWorkflow = workflowIsBlessedHarness(currentProjectFile);
  const harnessWorkerBinding = isHarnessWorkflow
    ? workflowHarnessWorkerBinding(currentProjectFile)
    : null;
  const activeRightPanelMeta =
    RIGHT_PANELS.find((panel) => panel.id === rightPanel) ?? {
      id: "outputs" as WorkflowRightPanel,
      label: "Outputs",
      description: "Inspect selected nodes and workflow outputs.",
      icon: FileOutput,
    };
  const rightPanelBadgeCounts = useMemo<Record<WorkflowRightPanel, number>>(
    () => {
      const activeValidation = readinessResult ?? validationResult;
      const readinessIssueCount = activeValidation
        ? workflowValidationBlockingIssueCount(activeValidation) +
          activeValidation.warnings.length
        : 0;
      return {
        outputs: currentProjectFile.nodes.filter(
          (nodeItem) => nodeItem.type === "output",
        ).length,
        unit_tests: tests.length,
        sources: currentProjectFile.nodes.filter(
          (nodeItem) =>
            nodeItem.type === "source" || nodeItem.type === "trigger",
        ).length,
        search: 0,
        changes: proposals.filter((proposal) => proposal.status === "open")
          .length,
        runs: runs.length,
        readiness: readinessIssueCount,
        schedules: currentProjectFile.nodes.filter(
          (nodeItem) => nodeItem.type === "trigger",
        ).length,
        files: 0,
        settings: 0,
      };
    },
    [currentProjectFile.nodes, proposals, readinessResult, runs, tests, validationResult],
  );

  const loadRuntimeSidecars = useCallback(
    async (path: string) => {
      if (runtime.listWorkflowRuns) {
        setRuns(await runtime.listWorkflowRuns(path));
      }
      if (runtime.listWorkflowNodeFixtures) {
        setNodeFixturesById(
          groupFixturesByNodeId(await runtime.listWorkflowNodeFixtures(path)),
        );
      }
      if (runtime.loadWorkflowBindingManifest) {
        setBindingManifest(await runtime.loadWorkflowBindingManifest(path));
      }
    },
    [runtime],
  );

  const handleCheckWorkflowBinding = useCallback(
    async (
      row: WorkflowBindingRegistryRow,
    ): Promise<WorkflowBindingCheckResult> => {
      const localResult = workflowBindingCheckResult(
        row,
        workflowEnvironmentProfile(currentProjectFile),
      );
      if (!runtime.checkWorkflowBinding) {
        return localResult;
      }
      try {
        const result = await runtime.checkWorkflowBinding(
          workflowPath,
          row.nodeItem.id,
          row.id,
        );
        await loadRuntimeSidecars(workflowPath);
        return result;
      } catch (error) {
        return {
          ...localResult,
          status: "blocked",
          summary: "Binding check could not run",
          detail: error instanceof Error ? error.message : String(error),
        };
      }
    },
    [currentProjectFile, loadRuntimeSidecars, runtime, workflowPath],
  );

  const clearRunState = useCallback(() => {
    setLastRunResult(null);
    setSelectedRunId(null);
    setCompareRunResult(null);
    setCompareRunId(null);
    setFunctionDryRunResult(null);
    setReadinessResult(null);
    setBindingManifest(null);
    setRunDetailLoading(false);
    setRunEvents([]);
    setCheckpoints([]);
    setNodeRunStatusById({});
    setNodeFixturesById({});
  }, []);

  const applyRunResult = useCallback(
    async (result: WorkflowRunResult) => {
      setLastRunResult(result);
      setSelectedRunId(result.summary.id);
      setRunEvents(result.events);
      setRuns((current) => [
        result.summary,
        ...current.filter((run) => run.id !== result.summary.id),
      ]);
      const runStatusEntries = new Map(
        result.nodeRuns.map((run) => [run.nodeId, run]),
      );
      result.finalState.completedNodeIds.forEach((nodeId) => {
        if (runStatusEntries.has(nodeId)) return;
        const nodeData = nodes.find((node) => node.id === nodeId)?.data as
          | Node
          | undefined;
        runStatusEntries.set(nodeId, {
          nodeId,
          nodeType: String(nodeData?.type ?? "function"),
          status: "success",
          startedAtMs: result.summary.startedAtMs,
          finishedAtMs: result.summary.finishedAtMs,
          attempt: 1,
        });
      });
      setNodeRunStatusById(Object.fromEntries(runStatusEntries));
      if (runtime.listWorkflowCheckpoints) {
        setCheckpoints(
          await runtime.listWorkflowCheckpoints(workflowPath, result.thread.id),
        );
      } else {
        setCheckpoints(result.checkpoints);
      }
      setRightPanel(
        result.summary.status === "interrupted" ? "runs" : rightPanel,
      );
      setStatusMessage(`Run ${result.summary.status}`);
    },
    [nodes, rightPanel, runtime, workflowPath],
  );

  const handleSelectRun = useCallback(
    async (run: WorkflowRunSummary) => {
      setSelectedRunId(run.id);
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (!runtime.loadWorkflowRun) {
        setStatusMessage(`Selected run ${run.status}`);
        return;
      }
      setRunDetailLoading(true);
      try {
        const result = await runtime.loadWorkflowRun(workflowPath, run.id);
        await applyRunResult(result);
        setStatusMessage(`Loaded run ${result.summary.status}`);
      } catch (error) {
        setStatusMessage(`Run detail unavailable: ${errorMessage(error)}`);
      } finally {
        setRunDetailLoading(false);
      }
    },
    [applyRunResult, runtime, workflowPath],
  );

  useLayoutEffect(() => {
    if (!runtime.loadWorkflowRun || runs.length === 0) return;
    if (runDetailLoading) return;
    const selectedRun = runs.find((run) => run.id === selectedRunId) ?? runs[0];
    if (lastRunResult?.summary.id === selectedRun.id) return;

    let cancelled = false;
    setRunDetailLoading(true);
    runtime
      .loadWorkflowRun(workflowPath, selectedRun.id)
      .then((result) => {
        if (!cancelled) {
          void applyRunResult(result);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedRunId(selectedRun.id);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setRunDetailLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [
    applyRunResult,
    lastRunResult?.summary.id,
    runtime,
    runDetailLoading,
    runs,
    selectedRunId,
    workflowPath,
  ]);

  const handleCompareRun = useCallback(
    async (run: WorkflowRunSummary) => {
      if (!lastRunResult || run.id === lastRunResult.summary.id) {
        setStatusMessage("Select a different run to compare.");
        return;
      }
      setCompareRunId(run.id);
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (!runtime.loadWorkflowRun) {
        setStatusMessage("Run comparison needs durable run detail loading.");
        return;
      }
      try {
        const result = await runtime.loadWorkflowRun(workflowPath, run.id);
        setCompareRunResult(result);
        setStatusMessage(`Comparing with ${result.summary.status} run`);
      } catch (error) {
        setStatusMessage(`Run comparison unavailable: ${errorMessage(error)}`);
      }
    },
    [lastRunResult, runtime, workflowPath],
  );

  const handleDragStart = (event: DragEvent, type: string, label: string) => {
    event.dataTransfer.setData("nodeType", type);
    event.dataTransfer.setData("nodeName", label);
  };

  const markWorkflowDirty = useCallback(() => {
    if (isReadOnlyWorkflow) {
      setStatusMessage("Read-only harness graph cannot be edited. Fork it first.");
      return;
    }
    setReadinessResult(null);
    setWorkflow((current) => ({
      ...current,
      metadata: { ...current.metadata, dirty: true },
    }));
  }, [isReadOnlyWorkflow]);

  const guardedOnNodesChange = useCallback(
    (...args: Parameters<typeof onNodesChange>) => {
      if (isReadOnlyWorkflow) return;
      onNodesChange(...args);
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, onNodesChange],
  );
  const guardedOnEdgesChange = useCallback(
    (...args: Parameters<typeof onEdgesChange>) => {
      if (isReadOnlyWorkflow) return;
      onEdgesChange(...args);
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, onEdgesChange],
  );
  const guardedOnConnect = useCallback(
    (...args: Parameters<typeof onConnect>) => {
      if (isReadOnlyWorkflow) return;
      onConnect(...args);
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, onConnect],
  );
  const guardedCanvasDrop = useCallback(
    (...args: Parameters<typeof handleCanvasDrop>) => {
      if (isReadOnlyWorkflow) return;
      handleCanvasDrop(...args);
      markWorkflowDirty();
    },
    [handleCanvasDrop, isReadOnlyWorkflow, markWorkflowDirty],
  );

  const handleUpdateProductionProfile = useCallback(
    (updates: NonNullable<GraphGlobalConfig["production"]>) => {
      if (isReadOnlyWorkflow) {
        setStatusMessage("Read-only harness graph cannot be edited. Fork it first.");
        return;
      }
      setGlobalConfig((current) =>
        normalizeGlobalConfig({
          ...current,
          production: {
            ...(current.production ?? {}),
            ...updates,
          },
        }),
      );
      markWorkflowDirty();
      setStatusMessage("Production checklist updated");
    },
    [isReadOnlyWorkflow, markWorkflowDirty],
  );

  const handleUpdateEnvironmentProfile = useCallback(
    (
      updates: Partial<NonNullable<GraphGlobalConfig["environmentProfile"]>>,
    ) => {
      if (isReadOnlyWorkflow) {
        setStatusMessage("Read-only harness graph cannot be edited. Fork it first.");
        return;
      }
      setGlobalConfig((current) =>
        normalizeGlobalConfig({
          ...current,
          environmentProfile: {
            ...(current.environmentProfile ?? {
              target: "local",
              credentialScope: "local",
              mockBindingPolicy: "block",
            }),
            ...updates,
          },
        }),
      );
      markWorkflowDirty();
      setStatusMessage("Environment profile updated");
    },
    [isReadOnlyWorkflow, markWorkflowDirty],
  );

  const handleAddNodeFromLibrary = useCallback(
    (
      type: string,
      label: string,
      preferredId?: string,
      options: {
        openConfig?: boolean;
        closeDrawer?: boolean;
        creatorId?: string;
        defaultLogic?: NodeLogic;
        defaultLaw?: FirewallPolicy;
        metricLabel?: string;
        metricValue?: string;
      } = {},
    ): string => {
      if (isReadOnlyWorkflow) {
        setStatusMessage("Read-only harness graph cannot be edited. Fork it first.");
        return selectedNodeId ?? "";
      }
      const nodeId = addNode(type, label, preferredId);
      const definition =
        (options.creatorId
          ? NODE_LIBRARY.find(
              (item) => workflowCreatorItemId(item) === options.creatorId,
            )
          : null) ?? NODE_LIBRARY.find((item) => item.type === type);
      if (definition) {
        const creatorId = workflowCreatorItemId(definition);
        setRecentNodeTypes((current) =>
          [creatorId, ...current.filter((item) => item !== creatorId)].slice(
            0,
            5,
          ),
        );
      }
      if (
        options.defaultLogic ||
        options.defaultLaw ||
        options.metricLabel ||
        options.metricValue
      ) {
        setNodes((currentNodes) =>
          currentNodes.map((flowNode) => {
            if (flowNode.id !== nodeId) return flowNode;
            const data = flowNode.data as Node;
            const currentConfig = data.config ?? {
              kind: type as WorkflowNodeKind,
              logic: {},
              law: {},
            };
            return {
              ...flowNode,
              data: {
                ...data,
                metricLabel: options.metricLabel ?? data.metricLabel,
                metricValue: options.metricValue ?? data.metricValue,
                config: {
                  ...currentConfig,
                  kind: type as WorkflowNodeKind,
                  logic: options.defaultLogic
                    ? { ...options.defaultLogic }
                    : currentConfig.logic,
                  law: options.defaultLaw
                    ? { ...options.defaultLaw }
                    : currentConfig.law,
                },
              },
            };
          }),
        );
      }
      markWorkflowDirty();
      if (options.openConfig) {
        handleNodeSelect(nodeId);
        setBottomPanel("selection");
        closeCanvasSearch();
        setNodeConfigInitialSection(workflowConfigSectionForNodeKind(type));
        setNodeConfigOpen(true);
      }
      if (options.closeDrawer) {
        closeLeftDrawer();
      }
      setStatusMessage(`${label} node added`);
      return nodeId;
    },
    [
      addNode,
      closeCanvasSearch,
      closeLeftDrawer,
      handleNodeSelect,
      isReadOnlyWorkflow,
      markWorkflowDirty,
      selectedNodeId,
      setNodes,
    ],
  );

  const connectWorkflowNodes = useCallback(
    (sourceNodeId: string, targetNodeId: string): boolean => {
      if (sourceNodeId === targetNodeId) return false;
      const sourceNode = nodes.find((flowNode) => flowNode.id === sourceNodeId);
      const targetNode = nodes.find((flowNode) => flowNode.id === targetNodeId);
      const sourceType = String(
        sourceNode?.type ?? (sourceNode?.data as Node | undefined)?.type ?? "",
      );
      const targetType = String(
        targetNode?.type ?? (targetNode?.data as Node | undefined)?.type ?? "",
      );
      const { sourcePort, targetPort, connectionClass } = compatiblePortPair(
        sourceNode,
        targetNode,
      );
      const edgeIssue = validateActionEdge(
        sourceNodeId,
        actionKindForWorkflowNodeType(sourceType),
        targetNodeId,
        actionKindForWorkflowNodeType(targetType),
        sourcePort,
        targetPort,
      );
      if (edgeIssue) {
        setStatusMessage(edgeIssue.message);
        return false;
      }
      const edgeId = `edge-${sourceNodeId}-${targetNodeId}-${Date.now()}`;
      setEdges((currentEdges) => {
        if (
          currentEdges.some(
            (edge) =>
              edge.source === sourceNodeId && edge.target === targetNodeId,
          )
        ) {
          return currentEdges;
        }
        return [
          ...currentEdges,
          {
            id: edgeId,
            source: sourceNodeId,
            target: targetNodeId,
            sourceHandle: sourcePort?.id ?? "output",
            targetHandle: targetPort?.id ?? "input",
            type: "semantic",
            animated: false,
            data: { status: "idle", active: false, connectionClass },
          },
        ];
      });
      markWorkflowDirty();
      setStatusMessage("Nodes connected");
      return true;
    },
    [markWorkflowDirty, nodes, setEdges],
  );

  const handleAddCompatibleNode = useCallback(
    (
      sourceNode: Node,
      item: WorkflowNodeDefinition | WorkflowNodeCreatorDefinition,
      portPath?: Pick<
        WorkflowCompatibleNodeHint,
        "sourcePort" | "targetPort" | "connectionClass" | "direction"
      >,
    ) => {
      const direction = portPath?.direction ?? "downstream";
      const fallbackPair =
        direction === "attachment"
          ? preferredCompatiblePortPair(
              item.portDefinitions.filter(
                (port) => port.direction === "output",
              ),
              (sourceNode.ports ?? []).filter(
                (port) => port.direction === "input",
              ),
            )
          : preferredCompatiblePortPair(
              (sourceNode.ports ?? []).filter(
                (port) => port.direction === "output",
              ),
              item.portDefinitions.filter((port) => port.direction === "input"),
            );
      const sourcePort = portPath?.sourcePort ?? fallbackPair.sourcePort;
      const targetPort = portPath?.targetPort ?? fallbackPair.targetPort;
      const connectionClass =
        portPath?.connectionClass ?? fallbackPair.connectionClass;
      const prospectiveNodeId = `new-${item.type}`;
      const prospectiveEdgeSourceId =
        direction === "attachment" ? prospectiveNodeId : sourceNode.id;
      const prospectiveEdgeTargetId =
        direction === "attachment" ? sourceNode.id : prospectiveNodeId;
      const edgeSourceType =
        direction === "attachment" ? item.type : sourceNode.type;
      const edgeTargetType =
        direction === "attachment" ? sourceNode.type : item.type;
      const edgeIssue = validateActionEdge(
        prospectiveEdgeSourceId,
        actionKindForWorkflowNodeType(edgeSourceType),
        prospectiveEdgeTargetId,
        actionKindForWorkflowNodeType(edgeTargetType),
        sourcePort,
        targetPort,
      );
      if (edgeIssue) {
        setStatusMessage(edgeIssue.message);
        return;
      }
      const nodeId = handleAddNodeFromLibrary(item.type, item.label, undefined, {
        creatorId: workflowCreatorItemId(item),
        defaultLogic: item.defaultLogic,
        defaultLaw: item.defaultLaw,
        metricLabel: item.metricLabel,
        metricValue: item.metricValue,
      });
      const edgeSourceId = direction === "attachment" ? nodeId : sourceNode.id;
      const edgeTargetId = direction === "attachment" ? sourceNode.id : nodeId;
      setEdges((currentEdges) => [
        ...currentEdges,
        {
          id: `edge-${edgeSourceId}-${edgeTargetId}-${Date.now()}`,
          source: edgeSourceId,
          target: edgeTargetId,
          sourceHandle: sourcePort?.id ?? "output",
          targetHandle: targetPort?.id ?? "input",
          type: "semantic",
          animated: false,
          data: {
            status: "idle",
            active: false,
            connectionClass,
            createdBy: "compatible_node_picker",
            direction,
          },
        },
      ]);
      markWorkflowDirty();
      handleNodeSelect(nodeId);
      closeLeftDrawer();
      closeCanvasSearch();
      setBottomPanel("selection");
      setNodeConfigInitialSection(workflowConfigSectionForNodeKind(item.type));
      setNodeConfigOpen(true);
      setStatusMessage(
        direction === "attachment"
          ? `${item.label} attached to ${sourceNode.name}`
          : `${item.label} added and connected after ${sourceNode.name}`,
      );
    },
    [
      handleAddNodeFromLibrary,
      handleNodeSelect,
      closeCanvasSearch,
      closeLeftDrawer,
      markWorkflowDirty,
      setEdges,
      setBottomPanel,
      setNodeConfigOpen,
    ],
  );

  const handleInsertAgentLoopMacro = useCallback(() => {
    const macroId = `agent-loop-${Date.now()}`;
    const selectedData = selectedNode;
    const baseX = Number(selectedData?.x ?? 120);
    const baseY = Number(selectedData?.y ?? 180);
    const selectedHasDataOutput = selectedData?.ports?.some(
      (port) =>
        port.direction === "output" &&
        port.connectionClass === "data" &&
        port.id === "output",
    );
    const shouldCreateInput = !selectedData || !selectedHasDataOutput;
    const inputId = shouldCreateInput
      ? handleAddNodeFromLibrary("source", "Agent input", `${macroId}-input`)
      : selectedData.id;
    const memoryId = handleAddNodeFromLibrary(
      "state",
      "Agent memory",
      `${macroId}-memory`,
    );
    const toolId = handleAddNodeFromLibrary(
      "plugin_tool",
      "Agent tool",
      `${macroId}-tool`,
    );
    const modelId = handleAddNodeFromLibrary(
      "model_call",
      "Agent reasoning",
      `${macroId}-model`,
    );
    const decisionId = handleAddNodeFromLibrary(
      "decision",
      "Route result",
      `${macroId}-decision`,
    );
    const outputId = handleAddNodeFromLibrary(
      "output",
      "Agent output",
      `${macroId}-output`,
    );
    const positions: Record<string, { x: number; y: number }> = {
      [memoryId]: { x: baseX + 280, y: baseY + 150 },
      [toolId]: { x: baseX + 280, y: baseY + 300 },
      [modelId]: { x: baseX + 280, y: baseY },
      [decisionId]: { x: baseX + 560, y: baseY },
      [outputId]: { x: baseX + 840, y: baseY },
    };
    const macroRoles: Record<
      string,
      NonNullable<NodeLogic["viewMacro"]>["role"]
    > = {
      [inputId]: "input",
      [memoryId]: "memory",
      [toolId]: "tool",
      [modelId]: "model",
      [decisionId]: "decision",
      [outputId]: "output",
    };
    if (shouldCreateInput) {
      positions[inputId] = { x: baseX, y: baseY };
    }

    setNodes((currentNodes) =>
      currentNodes.map((flowNode) => {
        const nodeData = flowNode.data as Node;
        const position = positions[flowNode.id];
        const macroRole = macroRoles[flowNode.id];
        if (!position && !macroRole) return flowNode;
        let logic = nodeData.config?.logic ?? {};
        let law = nodeData.config?.law ?? {};
        if (flowNode.id === inputId && shouldCreateInput) {
          logic = {
            payload: { message: "Describe the request for this agent run." },
          };
        } else if (flowNode.id === memoryId) {
          logic = {
            stateKey: "agent_memory",
            stateOperation: "merge",
            reducer: "merge",
            initialValue: {},
          };
        } else if (flowNode.id === toolId) {
          logic = {
            toolBinding: {
              toolRef: "codex_plugin",
              bindingKind: "plugin_tool",
              mockBinding: true,
              capabilityScope: ["read", "analyze"],
              sideEffectClass: "read",
              requiresApproval: false,
              arguments: {},
            },
          };
        } else if (flowNode.id === modelId) {
          logic = {
            modelRef: "reasoning",
            prompt:
              "Use the input, memory, and tool attachment to produce the next workflow result.",
          };
        } else if (flowNode.id === decisionId) {
          logic = {
            routes: ["left", "right"],
            defaultRoute: "left",
          };
        }
        if (macroRole) {
          logic = {
            ...logic,
            viewMacro: {
              macroId,
              macroLabel: "Agent loop",
              role: macroRole,
              expandedFrom: "agent_loop_macro",
            },
          };
        }
        return {
          ...flowNode,
          position: position ?? flowNode.position,
          data: {
            ...nodeData,
            x: position?.x ?? nodeData.x,
            y: position?.y ?? nodeData.y,
            config: {
              kind: nodeData.type,
              logic,
              law,
            },
          },
        };
      }),
    );
    setEdges((currentEdges) => {
      const macroEdges = [
        {
          id: `edge-${inputId}-${modelId}-${macroId}`,
          source: inputId,
          target: modelId,
          sourceHandle: "output",
          targetHandle: "input",
          data: {
            status: "idle",
            active: false,
            connectionClass: "data",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${memoryId}-${modelId}-${macroId}`,
          source: memoryId,
          target: modelId,
          sourceHandle: "memory",
          targetHandle: "memory",
          data: {
            status: "idle",
            active: false,
            connectionClass: "memory",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${toolId}-${modelId}-${macroId}`,
          source: toolId,
          target: modelId,
          sourceHandle: "tool",
          targetHandle: "tool",
          data: {
            status: "idle",
            active: false,
            connectionClass: "tool",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${modelId}-${decisionId}-${macroId}`,
          source: modelId,
          target: decisionId,
          sourceHandle: "output",
          targetHandle: "input",
          data: {
            status: "idle",
            active: false,
            connectionClass: "data",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${decisionId}-${outputId}-${macroId}`,
          source: decisionId,
          target: outputId,
          sourceHandle: "left",
          targetHandle: "input",
          data: {
            status: "idle",
            active: false,
            connectionClass: "data",
            createdBy: "agent_loop_macro",
          },
        },
      ];
      const dedupedEdges = macroEdges.filter(
        (edge) =>
          !currentEdges.some(
            (current) =>
              current.source === edge.source &&
              current.target === edge.target &&
              current.targetHandle === edge.targetHandle,
          ),
      );
      return [
        ...currentEdges,
        ...dedupedEdges.map((edge) => ({
          ...edge,
          type: "semantic",
          animated: false,
        })),
      ];
    });
    handleNodeSelect(modelId);
    markWorkflowDirty();
    setStatusMessage("Agent loop expanded into explicit workflow primitives");
  }, [
    handleAddNodeFromLibrary,
    handleNodeSelect,
    markWorkflowDirty,
    selectedNode,
    setEdges,
    setNodes,
  ]);

  const handleConnectSelectedNodes = useCallback(() => {
    if (!connectFromNodeId || !selectedNode) return;
    if (connectWorkflowNodes(connectFromNodeId, selectedNode.id)) {
      setConnectFromNodeId(null);
    }
  }, [connectFromNodeId, connectWorkflowNodes, selectedNode]);

  const handleWorkflowNodeSelect = useCallback(
    (nodeId: string | null) => {
      if (nodeId && connectFromNodeId && connectFromNodeId !== nodeId) {
        if (connectWorkflowNodes(connectFromNodeId, nodeId)) {
          setConnectFromNodeId(null);
        }
      }
      handleNodeSelect(nodeId);
    },
    [connectFromNodeId, connectWorkflowNodes, handleNodeSelect],
  );

  const handleInspectExecutionNode = useCallback(
    (nodeId: string) => {
      handleWorkflowNodeSelect(nodeId);
      setActiveTab("graph");
      setRightPanel("runs");
      setBottomPanel("selection");
    },
    [handleWorkflowNodeSelect],
  );

  const handleResolveWorkflowIssue = useCallback(
    (issue: WorkflowValidationIssue) => {
      if (issue.nodeId) {
        handleWorkflowNodeSelect(issue.nodeId);
        setNodeConfigInitialSection(workflowConfigSectionForIssue(issue));
        setBottomPanel(
          issue.code === "missing_replay_fixture" ? "fixtures" : "selection",
        );
        setNodeConfigOpen(true);
        setStatusMessage(workflowIssueActionLabel(issue));
        return;
      }

      setCompatiblePortFocus(null);
      setCanvasSearchOpen(false);
      setActiveTab("graph");

      if (issue.code === "missing_output_node") {
        setNodeGroupFilter("Outputs");
        setNodeSearch("");
        openLeftDrawer();
        setStatusMessage("Add an Output primitive");
        return;
      }

      if (
        issue.code === "missing_start_node" ||
        issue.code === "missing_scheduled_trigger" ||
        issue.code === "missing_event_trigger"
      ) {
        setNodeGroupFilter("Start");
        setNodeSearch(
          issue.code === "missing_scheduled_trigger"
            ? "scheduled"
            : issue.code === "missing_event_trigger"
              ? "event"
              : "",
        );
        openLeftDrawer();
        setStatusMessage("Add a start primitive");
        return;
      }

      if (issue.code === "missing_unit_tests") {
        const firstTarget =
          selectedNode?.id ??
          ((nodes[0]?.data as Node | undefined)?.id || nodes[0]?.id || "");
        setRightPanel("unit_tests");
        setBottomPanel("test_output");
        setNewTestName(
          firstTarget ? "Selected node exists" : "Workflow smoke test",
        );
        setNewTestTargets(firstTarget);
        setNewTestKind("node_exists");
        setNewTestExpected("");
        setNewTestExpression("");
        setTestEditorOpen(true);
        setStatusMessage("Create a unit test");
        return;
      }

      if (issue.code === "missing_error_handling_path") {
        setNodeGroupFilter("Flow");
        setNodeSearch("error");
        openLeftDrawer();
        setStatusMessage("Add an error or retry path");
        return;
      }

      if (issue.code === "mock_binding_active") {
        setRightPanel("settings");
        setStatusMessage("Review binding mode");
        return;
      }

      setRightPanel("settings");
      setStatusMessage(workflowIssueActionLabel(issue));
    },
    [handleWorkflowNodeSelect, nodes, openLeftDrawer, selectedNode],
  );
  const displayNodes = useMemo(
    () =>
      nodes.map((flowNode) => {
        const run = nodeRunStatusById[flowNode.id];
        const data = flowNode.data as Node;
        const issueSummary = canvasIssuesByNodeId.get(flowNode.id);
        return {
          ...flowNode,
          data: {
            ...data,
            onRequestCompatibleNodes: handleShowCompatibleNodesForPort,
            onResolveCanvasIssue: handleResolveWorkflowIssue,
            validationIssueSummary: issueSummary
              ? {
                  blockerCount: issueSummary.blockers.length,
                  warningCount: issueSummary.warnings.length,
                  issueCount:
                    issueSummary.blockers.length +
                    issueSummary.warnings.length,
                  title: workflowIssueTitle(issueSummary.primaryIssue),
                  message: issueSummary.primaryIssue.message,
                  actionLabel: workflowIssueActionLabel(
                    issueSummary.primaryIssue,
                  ),
                  primaryIssue: issueSummary.primaryIssue,
                }
              : null,
            ...(run
              ? {
                  status: nodeVisualStatus(run.status),
                  metricLabel: "Run",
                  metricValue: run.status,
                }
              : {}),
          },
        };
      }),
    [
      canvasIssuesByNodeId,
      handleResolveWorkflowIssue,
      handleShowCompatibleNodesForPort,
      nodeRunStatusById,
      nodes,
    ],
  );

  const updateNode = useCallback(
    (nodeId: string, updates: Partial<Node>) => {
      if (isReadOnlyWorkflow) {
        setStatusMessage("Read-only harness graph cannot be edited. Fork it first.");
        return;
      }
      setNodes((currentNodes) =>
        currentNodes.map((flowNode) =>
          flowNode.id === nodeId
            ? {
                ...flowNode,
                data: {
                  ...flowNode.data,
                  ...updates,
                  config: updates.config ?? (flowNode.data as Node).config,
                },
              }
            : flowNode,
        ),
      );
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, setNodes],
  );

  const handleCreateWorkflow = async () => {
    const request: CreateWorkflowProjectRequest = {
      projectRoot: currentProject?.rootPath || ".",
      name: createName,
      workflowKind: createKind,
      executionMode: createMode,
    };
    if (runtime.createWorkflowProject) {
      const bundle = await runtime.createWorkflowProject(request);
      setWorkflowPath(bundle.workflowPath);
      setTestsPath(bundle.testsPath);
      setTests(bundle.tests);
      setProposals(bundle.proposals);
      setRuns(bundle.runs);
      clearRunState();
      loadWorkflowProject(bundle.workflow);
      await loadRuntimeSidecars(bundle.workflowPath);
      setStatusMessage("Blank workflow created");
    } else {
      const next = makeDefaultWorkflow(createName);
      next.metadata.workflowKind = createKind;
      next.metadata.executionMode = createMode;
      setTests(defaultTestsForWorkflow(next));
      setRuns([]);
      clearRunState();
      loadWorkflowProject(next);
      setStatusMessage("Blank workflow initialized locally");
    }
    setCreateOpen(false);
  };

  const handleOpenDefaultHarness = useCallback(() => {
    const next = makeDefaultAgentHarnessWorkflow();
    const projectRoot = currentProject?.rootPath || ".";
    setWorkflowPath(
      `${projectRoot}/.agents/workflows/${next.metadata.slug}.workflow.json`,
    );
    setTestsPath(
      `${projectRoot}/.agents/workflows/${next.metadata.slug}.tests.json`,
    );
    setTests(defaultAgentHarnessTests(next));
    setProposals([]);
    setRuns([]);
    clearRunState();
    loadWorkflowProject(next);
    setValidationResult(validateWorkflowProject(next, defaultAgentHarnessTests(next)));
    setRightPanel("settings");
    setBottomPanel("selection");
    setStatusMessage("Default Agent Harness opened as a read-only graph");
  }, [clearRunState, currentProject?.rootPath, loadWorkflowProject]);

  const handleForkDefaultHarness = useCallback(() => {
    const fork = forkDefaultAgentHarnessWorkflow();
    const projectRoot = currentProject?.rootPath || ".";
    const nextPath = `${projectRoot}/.agents/workflows/${fork.workflow.metadata.slug}.workflow.json`;
    setWorkflowPath(nextPath);
    setTestsPath(nextPath.replace(/\.workflow\.json$/, ".tests.json"));
    setTests(fork.tests);
    setProposals(fork.proposals);
    setRuns([]);
    clearRunState();
    loadWorkflowProject(fork.workflow);
    const base = validateWorkflowProject(fork.workflow, fork.tests);
    setValidationResult(base);
    setReadinessResult(
      evaluateWorkflowActivationReadiness(fork.workflow, fork.tests, base, fork.proposals),
    );
    setRightPanel("readiness");
    setBottomPanel("selection");
    setStatusMessage("Harness fork created with lineage and activation blockers");
  }, [clearRunState, currentProject?.rootPath, loadWorkflowProject]);

  const handleSave = async () => {
    if (isReadOnlyWorkflow) {
      setStatusMessage("Read-only harness graph cannot be saved. Fork it first.");
      return;
    }
    const next = toWorkflowProject(nodes, edges, globalConfig, workflow);
    if (runtime.saveWorkflowProject) {
      await runtime.saveWorkflowProject(workflowPath, next);
    } else {
      await runtime.saveProject(workflowPath, next);
    }
    if (runtime.saveWorkflowTests) {
      await runtime.saveWorkflowTests(workflowPath, tests);
    }
    setWorkflow({ ...next, metadata: { ...next.metadata, dirty: false } });
    setValidationResult(validateWorkflowProject(next, tests));
    await loadRuntimeSidecars(workflowPath);
    setStatusMessage("Saved");
  };

  const handleGenerateBindingManifest = async () => {
    if (!runtime.generateWorkflowBindingManifest) {
      setStatusMessage("Binding manifest unavailable");
      return;
    }
    await handleSave();
    const manifest =
      await runtime.generateWorkflowBindingManifest(workflowPath);
    setBindingManifest(manifest);
    await loadRuntimeSidecars(workflowPath);
    setRightPanel("settings");
    setStatusMessage(
      `Binding manifest ready: ${manifest.summary.ready}/${manifest.summary.total}`,
    );
  };

  const handleValidate = async () => {
    let result: WorkflowValidationResult;
    try {
      result = runtime.validateWorkflowBundle
        ? await runtime.validateWorkflowBundle(workflowPath)
        : validateWorkflowProject(currentProjectFile, tests);
    } catch (error) {
      result = createWorkflowActionFailure(
        "workflow_bundle_unavailable",
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setValidationResult(result);
    setBottomPanel("warnings");
    setStatusMessage(workflowValidationStatusMessage("Validation", result));
  };

  const handleCheckReadiness = async (): Promise<WorkflowValidationResult> => {
    let result: WorkflowValidationResult;
    try {
      const runtimeReadinessAvailable = Boolean(
        runtime.validateWorkflowExecutionReadiness,
      );
      const runtimeResult = runtime.validateWorkflowExecutionReadiness
        ? await runtime.validateWorkflowExecutionReadiness(workflowPath)
        : validateWorkflowProject(currentProjectFile, tests);
      result = evaluateWorkflowActivationReadiness(
        currentProjectFile,
        tests,
        runtimeResult,
        proposals,
        runtimeReadinessAvailable
          ? null
          : Object.values(nodeFixturesById).flat(),
      );
    } catch (error) {
      result = createWorkflowActionFailure(
        "workflow_bundle_unavailable",
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setReadinessResult(result);
    setRightPanel("readiness");
    setStatusMessage(workflowValidationStatusMessage("Readiness", result));
    return result;
  };

  const handleOpenDeploy = async () => {
    await handleCheckReadiness();
    setDeployOpen(true);
  };

  const handleExportPortablePackage = async () => {
    await handleSave();
    const readiness = await handleCheckReadiness();
    if (!runtime.exportWorkflowPackage) {
      setStatusMessage("Package export unavailable");
      return;
    }
    const exported = await runtime.exportWorkflowPackage(workflowPath);
    setPortablePackage(exported);
    setRightPanel("readiness");
    setStatusMessage(
      exported.manifest.portable
        ? "Portable package exported"
        : `Package exported with ${readiness.status} blockers`,
    );
    await loadRuntimeSidecars(workflowPath);
  };

  const handleImportPortablePackage = async () => {
    const packagePath = importPackagePath.trim();
    if (!packagePath) {
      setStatusMessage("Choose a package directory to import");
      return;
    }
    if (!runtime.importWorkflowPackage) {
      setStatusMessage("Package import unavailable");
      return;
    }
    const request: ImportWorkflowPackageRequest = {
      packagePath,
      projectRoot: currentProject?.rootPath || ".",
      name: importPackageName.trim() || undefined,
    };
    try {
      const bundle = await runtime.importWorkflowPackage(request);
      setWorkflowPath(bundle.workflowPath);
      setTestsPath(bundle.testsPath);
      setTests(bundle.tests);
      setProposals(bundle.proposals);
      setRuns(bundle.runs);
      clearRunState();
      setValidationResult(null);
      setReadinessResult(null);
      setPortablePackage(null);
      loadWorkflowProject(bundle.workflow);
      await loadRuntimeSidecars(bundle.workflowPath);
      setRightPanel("files");
      setImportPackageOpen(false);
      setStatusMessage("Package imported");
    } catch (error) {
      setStatusMessage(`Package import failed: ${errorMessage(error)}`);
    }
  };

  const handleRunTests = async () => {
    let result: WorkflowTestRunResult;
    try {
      result = runtime.runWorkflowTests
        ? await runtime.runWorkflowTests(workflowPath)
        : createLocalTestResult(tests, nodes);
    } catch (error) {
      result = createBlockedTestResult(
        tests,
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setTestResult(result);
    setTests((current) =>
      current.map((test) => {
        const run = result.results.find((item) => item.testId === test.id);
        return run
          ? { ...test, status: run.status, lastMessage: run.message }
          : test;
      }),
    );
    setRightPanel(
      result.failed > 0 || result.blocked > 0 ? "unit_tests" : rightPanel,
    );
    setBottomPanel("test_output");
    setStatusMessage(
      `Tests: ${result.passed} passed, ${result.failed} failed, ${result.blocked} blocked`,
    );
  };

  const handleRun = async () => {
    let validation: WorkflowValidationResult;
    try {
      validation = runtime.validateWorkflowBundle
        ? await runtime.validateWorkflowBundle(workflowPath)
        : validateWorkflowProject(currentProjectFile, tests);
    } catch (error) {
      validation = createWorkflowActionFailure(
        "workflow_bundle_unavailable",
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setValidationResult(validation);
    setRightPanel("runs");
    setBottomPanel("run_output");
    if (runtime.runWorkflowProject) {
      try {
        const result = await runtime.runWorkflowProject(workflowPath);
        await applyRunResult(result);
        setRightPanel("runs");
      } catch (error) {
        const blocked = createLocalRunSummary(
          currentProjectFile,
          createWorkflowActionFailure(
            "workflow_bundle_unavailable",
            `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
          ),
        );
        setRuns((current) => [blocked, ...current]);
        setRightPanel("runs");
        setStatusMessage("Run blocked");
      }
    } else if (validation.status === "passed") {
      await execution.runGraph(globalConfig);
      setRuns((current) => [
        createLocalRunSummary(currentProjectFile, validation),
        ...current,
      ]);
      setStatusMessage("Run completed");
    } else {
      setRuns((current) => [
        createLocalRunSummary(currentProjectFile, validation),
        ...current,
      ]);
      setRightPanel("runs");
      setStatusMessage(`Run ${validation.status}`);
    }
    setBottomPanel("run_output");
  };

  const handleResumeRun = async (outcome: WorkflowResumeRequest["outcome"]) => {
    if (!lastRunResult?.interrupt || !runtime.resumeWorkflowRun) return;
    const result = await runtime.resumeWorkflowRun(workflowPath, {
      runId: lastRunResult.summary.id,
      threadId: lastRunResult.thread.id,
      interruptId: lastRunResult.interrupt.id,
      checkpointId: lastRunResult.thread.latestCheckpointId,
      outcome,
    });
    await applyRunResult(result);
    setRightPanel("runs");
    setBottomPanel("run_output");
  };

  const handleDryRunFunction = async (node: Node) => {
    if (node.type !== "function" || !runtime.dryRunWorkflowFunction) return;
    const result = await runtime.dryRunWorkflowFunction(
      workflowPath,
      node.id,
      node.config?.logic.functionBinding?.testInput ??
        node.config?.logic.testInput ?? { payload: "sample" },
    );
    setFunctionDryRunResult(result);
    setBottomPanel("run_output");
    setStatusMessage(`Function dry run ${result.summary.status}`);
  };

  const handleCaptureNodeFixture = useCallback(
    async (node: Node) => {
      const run = nodeRunStatusById[node.id];
      const logic = node.config?.logic ?? {};
      const input =
        run?.input ??
        logic.functionBinding?.testInput ??
        logic.testInput ??
        logic.payload ??
        null;
      const hashes = workflowFixtureHashesForNode(node);
      const fixture: WorkflowNodeFixture = {
        id: `fixture-${node.id}-${Date.now()}`,
        nodeId: node.id,
        name: `${node.name} fixture`,
        input,
        output: run?.output ?? null,
        schemaHash: hashes.schemaHash,
        nodeConfigHash: hashes.nodeConfigHash,
        ...workflowFixtureValidationForNode(node, run?.output ?? null),
        sourceRunId: lastRunResult?.summary.id,
        pinned: true,
        stale: false,
        createdAtMs: Date.now(),
      };
      if (runtime.saveWorkflowNodeFixture) {
        const savedFixtures = await runtime.saveWorkflowNodeFixture(
          workflowPath,
          fixture,
        );
        setNodeFixturesById(groupFixturesByNodeId(savedFixtures));
      } else {
        setNodeFixturesById((current) => ({
          ...current,
          [node.id]: [fixture, ...(current[node.id] ?? [])].slice(0, 8),
        }));
      }
      setBottomPanel("fixtures");
      setStatusMessage(`Fixture captured for ${node.name}`);
    },
    [lastRunResult?.summary.id, nodeRunStatusById, runtime, workflowPath],
  );

  const handleImportNodeFixture = useCallback(
    async (node: Node, rawText: string) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawText);
      } catch (error) {
        setStatusMessage(`Fixture import blocked: ${errorMessage(error)}`);
        return;
      }
      const record =
        parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? (parsed as Record<string, unknown>)
          : null;
      const logic = node.config?.logic ?? {};
      const hashes = workflowFixtureHashesForNode(node);
      const fixture: WorkflowNodeFixture = {
        id: `fixture-${node.id}-import-${Date.now()}`,
        nodeId: node.id,
        name: String(record?.name ?? `${node.name} imported sample`),
        input:
          record && "input" in record
            ? record.input
            : (logic.functionBinding?.testInput ??
              logic.testInput ??
              logic.payload ??
              null),
        output: record && "output" in record ? record.output : parsed,
        schemaHash: hashes.schemaHash,
        nodeConfigHash: hashes.nodeConfigHash,
        ...workflowFixtureValidationForNode(
          node,
          record && "output" in record ? record.output : parsed,
        ),
        pinned: true,
        stale: false,
        createdAtMs: Date.now(),
      };
      if (runtime.saveWorkflowNodeFixture) {
        const savedFixtures = await runtime.saveWorkflowNodeFixture(
          workflowPath,
          fixture,
        );
        setNodeFixturesById(groupFixturesByNodeId(savedFixtures));
      } else {
        setNodeFixturesById((current) => ({
          ...current,
          [node.id]: [fixture, ...(current[node.id] ?? [])].slice(0, 8),
        }));
      }
      setBottomPanel("fixtures");
      setStatusMessage(`Fixture imported for ${node.name}`);
    },
    [runtime, workflowPath],
  );

  const handlePinNodeFixture = useCallback(
    async (node: Node, fixture: WorkflowNodeFixture) => {
      const pinnedFixture: WorkflowNodeFixture = {
        ...fixture,
        pinned: true,
        stale: fixture.stale ?? false,
      };
      if (runtime.saveWorkflowNodeFixture) {
        const savedFixtures = await runtime.saveWorkflowNodeFixture(
          workflowPath,
          pinnedFixture,
        );
        setNodeFixturesById(groupFixturesByNodeId(savedFixtures));
      } else {
        setNodeFixturesById((current) => ({
          ...current,
          [node.id]: (current[node.id] ?? []).map((item) => ({
            ...item,
            pinned: item.id === fixture.id,
          })),
        }));
      }
      setBottomPanel("fixtures");
      setStatusMessage(`Fixture pinned for ${node.name}`);
    },
    [runtime, workflowPath],
  );

  const handleDryRunNodeFromFixture = useCallback(
    async (node: Node, fixture?: WorkflowNodeFixture) => {
      const input = fixture?.input ??
        node.config?.logic?.functionBinding?.testInput ??
        node.config?.logic?.testInput ??
        node.config?.logic?.payload ?? { payload: "sample" };
      if (runtime.dryRunWorkflowNode) {
        const result = await runtime.dryRunWorkflowNode(
          workflowPath,
          node.id,
          input,
        );
        if (node.type === "function") {
          setFunctionDryRunResult(result);
        }
        await applyRunResult(result);
        setBottomPanel("run_output");
        setStatusMessage(`Dry run ${result.summary.status}`);
        return;
      }
      if (node.type === "function" && runtime.dryRunWorkflowFunction) {
        const result = await runtime.dryRunWorkflowFunction(
          workflowPath,
          node.id,
          input,
        );
        setFunctionDryRunResult(result);
        setBottomPanel("run_output");
        setStatusMessage(`Function dry run ${result.summary.status}`);
        return;
      }
      setStatusMessage(
        "Dry run is unavailable for this node until the runtime binding is saved.",
      );
    },
    [applyRunResult, runtime, workflowPath],
  );

  const handleRunWorkflowNode = useCallback(
    async (node: Node, fixture?: WorkflowNodeFixture) => {
      const run = nodeRunStatusById[node.id];
      const logic = node.config?.logic ?? {};
      const input =
        fixture?.input ??
        run?.input ??
        logic.functionBinding?.testInput ??
        logic.testInput ??
        logic.payload ??
        { payload: "sample" };
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (runtime.runWorkflowNode) {
        try {
          const result = await runtime.runWorkflowNode(
            workflowPath,
            node.id,
            input,
            { source: "inspector" },
          );
          await applyRunResult(result);
          setStatusMessage(`Node run ${result.summary.status}`);
        } catch (error) {
          const blocked = createLocalRunSummary(
            currentProjectFile,
            createWorkflowActionFailure(
              "workflow_node_run_unavailable",
              `Node run is unavailable. ${errorMessage(error)}`,
            ),
          );
          setRuns((current) => [blocked, ...current]);
          setStatusMessage("Node run blocked");
        }
        return;
      }
      await handleDryRunNodeFromFixture(node, fixture);
    },
    [
      applyRunResult,
      currentProjectFile,
      handleDryRunNodeFromFixture,
      nodeRunStatusById,
      runtime,
      workflowPath,
    ],
  );

  const handleRunWorkflowUpstream = useCallback(
    async (node: Node) => {
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (runtime.runWorkflowProject) {
        try {
          const result = await runtime.runWorkflowProject(workflowPath, {
            stopAtNodeId: node.id,
            source: "inspector-upstream",
          });
          await applyRunResult(result);
          setStatusMessage(`Upstream run ${result.summary.status}`);
        } catch (error) {
          const blocked = createLocalRunSummary(
            currentProjectFile,
            createWorkflowActionFailure(
              "workflow_upstream_run_unavailable",
              `Upstream run is unavailable. ${errorMessage(error)}`,
            ),
          );
          setRuns((current) => [blocked, ...current]);
          setStatusMessage("Upstream run blocked");
        }
        return;
      }
      await handleRunWorkflowNode(node);
    },
    [
      applyRunResult,
      currentProjectFile,
      handleRunWorkflowNode,
      runtime,
      workflowPath,
    ],
  );

  const handleAddTestFromOutput = useCallback(
    (node: Node) => {
      const output = nodeRunStatusById[node.id]?.output;
      setNewTestName(`${node.name} output is valid`);
      setNewTestTargets(node.id);
      setNewTestKind("schema_matches");
      setNewTestExpression(`nodes.${node.id}.output`);
      setNewTestExpected(
        output === undefined ? "" : JSON.stringify(output, null, 2),
      );
      setTestEditorOpen(true);
      setRightPanel("unit_tests");
      setBottomPanel("test_output");
      setStatusMessage(`Adding test from ${node.name} output`);
    },
    [nodeRunStatusById],
  );

  const handleBuildScratchBlueprint = useCallback(
    async (blueprintId: ScratchWorkflowBlueprintId) => {
      setActiveTab("graph");
      setRightPanel("runs");
      setBottomPanel("run_output");
      setStatusMessage(`Building ${blueprintId}`);
      const projectRoot = currentProject?.rootPath || ".";
      const requestedName =
        blueprintId === "repo-test-engineer"
          ? SCRATCH_DOGFOOD_WORKFLOW_NAME
          : `Scratch ${blueprintId.replace(/-/g, " ")}`;
      const bundle = runtime.createWorkflowProject
        ? await runtime.createWorkflowProject({
            projectRoot,
            name: requestedName,
            workflowKind: "agent_workflow",
            executionMode: "local",
          })
        : {
            workflowPath: `${projectRoot}/.agents/workflows/${slugify(requestedName)}.workflow.json`,
            testsPath: `${projectRoot}/.agents/workflows/${slugify(requestedName)}.tests.json`,
            proposalsDir: `${projectRoot}/.agents/workflows/${slugify(requestedName)}.proposals`,
            workflow: makeDefaultWorkflow(requestedName),
            tests: [],
            proposals: [],
            runs: [],
          };
      const scratch = buildScratchWorkflow(bundle.workflow, blueprintId);

      const blankWorkflow = {
        ...bundle.workflow,
        metadata: {
          ...bundle.workflow.metadata,
          name: scratch.workflow.metadata.name,
          slug: scratch.workflow.metadata.slug,
          dirty: true,
          updatedAtMs: Date.now(),
        },
        global_config: scratch.workflow.global_config,
        nodes: [],
        edges: [],
      };
      setWorkflowPath(bundle.workflowPath);
      setTestsPath(bundle.testsPath);
      setTests([]);
      setProposals(bundle.proposals);
      setRuns(bundle.runs);
      clearRunState();
      loadWorkflowProject(blankWorkflow);
      setStatusMessage(
        `Composing ${scratch.workflow.metadata.name} from blank canvas`,
      );

      scratch.workflow.nodes.forEach((nodeItem) => {
        handleAddNodeFromLibrary(nodeItem.type, nodeItem.name, nodeItem.id);
        setNodes((currentNodes) =>
          currentNodes.map((flowNode) =>
            flowNode.id === nodeItem.id
              ? {
                  ...flowNode,
                  type: nodeItem.type,
                  position: { x: nodeItem.x, y: nodeItem.y },
                  data: { ...nodeItem },
                }
              : flowNode,
          ),
        );
      });
      const scratchNodeById = new Map(
        scratch.workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem]),
      );
      setEdges(() =>
        scratch.workflow.edges.flatMap((edge) => {
          const sourceNode = scratchNodeById.get(edge.from);
          const targetNode = scratchNodeById.get(edge.to);
          const edgeIssue = validateActionEdge(
            edge.from,
            actionKindForWorkflowNodeType(sourceNode?.type ?? ""),
            edge.to,
            actionKindForWorkflowNodeType(targetNode?.type ?? ""),
          );
          if (edgeIssue) return [];
          return [
            {
              id: edge.id,
              source: edge.from,
              target: edge.to,
              sourceHandle: edge.fromPort || "output",
              targetHandle: edge.toPort || "input",
              type: "semantic",
              animated: false,
              data: {
                status: "idle",
                active: false,
                compositionMode: "manual_canvas_primitives",
              },
            },
          ];
        }),
      );
      setWorkflow(scratch.workflow);
      setGlobalConfig(normalizeGlobalConfig(scratch.workflow.global_config));
      handleNodeSelect(scratch.workflow.nodes[0]?.id ?? null);
      await new Promise<void>((resolve) =>
        requestAnimationFrame(() => resolve()),
      );

      if (runtime.saveWorkflowProject) {
        await runtime.saveWorkflowProject(
          bundle.workflowPath,
          scratch.workflow,
        );
      }
      if (runtime.saveWorkflowTests) {
        await runtime.saveWorkflowTests(bundle.workflowPath, scratch.tests);
      }
      setTests(scratch.tests);
      await loadRuntimeSidecars(bundle.workflowPath);

      let bindingCheckCount = 0;
      if (runtime.checkWorkflowBinding) {
        const bindingNodeIds = scratch.workflow.nodes
          .filter((nodeItem) =>
            [
              "model_call",
              "model_binding",
              "adapter",
              "plugin_tool",
              "parser",
            ].includes(nodeItem.type),
          )
          .map((nodeItem) => nodeItem.id);
        for (const nodeId of bindingNodeIds) {
          try {
            await runtime.checkWorkflowBinding(bundle.workflowPath, nodeId);
            bindingCheckCount += 1;
          } catch {
            // The visible dogfood result is driven by validation/run status;
            // binding-check failures are still captured through readiness.
          }
        }
        await loadRuntimeSidecars(bundle.workflowPath);
      }
      if (runtime.generateWorkflowBindingManifest) {
        try {
          setBindingManifest(
            await runtime.generateWorkflowBindingManifest(bundle.workflowPath),
          );
          await loadRuntimeSidecars(bundle.workflowPath);
        } catch {
          // Validation/readiness will expose binding blockers; manifest refresh
          // stays a sidecar concern for dogfood evidence.
        }
      }

      const validation = runtime.validateWorkflowBundle
        ? await runtime.validateWorkflowBundle(bundle.workflowPath)
        : validateWorkflowProject(scratch.workflow, scratch.tests);
      setValidationResult(validation);
      const activationReadiness = runtime.validateWorkflowExecutionReadiness
        ? await runtime.validateWorkflowExecutionReadiness(bundle.workflowPath)
        : evaluateWorkflowActivationReadiness(
            scratch.workflow,
            scratch.tests,
            validation,
            [],
            Object.values(nodeFixturesById).flat(),
          );
      setReadinessResult(activationReadiness);

      const testsResult = runtime.runWorkflowTests
        ? await runtime.runWorkflowTests(bundle.workflowPath)
        : createLocalTestResult(
            scratch.tests,
            scratch.workflow.nodes.map((node) => ({
              id: node.id,
              type: node.type,
              data: node,
            })),
          );
      setTestResult(testsResult);
      setTests((current) =>
        current.map((test) => {
          const run = testsResult.results.find(
            (item) => item.testId === test.id,
          );
          return run
            ? { ...test, status: run.status, lastMessage: run.message }
            : test;
        }),
      );

      let finalRun: WorkflowRunResult | null = null;
      let checkpointResumePassed = false;
      if (runtime.runWorkflowProject) {
        finalRun = await runtime.runWorkflowProject(bundle.workflowPath);
        if (
          blueprintId === "failed-function-resume" &&
          finalRun.summary.status === "failed" &&
          runtime.saveWorkflowProject &&
          runtime.resumeWorkflowRun
        ) {
          const repairedWorkflow: WorkflowProject = {
            ...scratch.workflow,
            nodes: scratch.workflow.nodes.map((nodeItem) => {
              if (nodeItem.id !== "resume-function") return nodeItem;
              const logic = {
                ...(nodeItem.config?.logic ?? {}),
              } as Record<string, unknown>;
              const functionBinding = {
                ...((logic.functionBinding as Record<string, unknown>) ?? {}),
                code: "return { repaired: true, result: input };",
              };
              return {
                ...nodeItem,
                config: {
                  ...nodeItem.config,
                  logic: {
                    ...logic,
                    code: "return { repaired: true, result: input };",
                    functionBinding,
                  },
                },
              };
            }) as WorkflowProject["nodes"],
          };
          await runtime.saveWorkflowProject(bundle.workflowPath, repairedWorkflow);
          setWorkflow(repairedWorkflow);
          loadWorkflowProject(repairedWorkflow);
          finalRun = await runtime.resumeWorkflowRun(bundle.workflowPath, {
            runId: finalRun.summary.id,
            threadId: finalRun.thread.id,
            nodeId: "resume-function",
            checkpointId: finalRun.thread.latestCheckpointId,
            outcome: "repair",
          });
          checkpointResumePassed = finalRun.summary.status === "passed";
        }
        for (let approvals = 0; approvals < 8; approvals += 1) {
          if (
            finalRun.summary.status !== "interrupted" ||
            !finalRun.interrupt ||
            !runtime.resumeWorkflowRun
          ) {
            break;
          }
          finalRun = await runtime.resumeWorkflowRun(bundle.workflowPath, {
            runId: finalRun.summary.id,
            threadId: finalRun.thread.id,
            interruptId: finalRun.interrupt.id,
            checkpointId: finalRun.thread.latestCheckpointId,
            outcome: "approve",
          });
        }
      }

      if (finalRun) {
        setLastRunResult(finalRun);
        setSelectedRunId(finalRun.summary.id);
        setRunEvents(finalRun.events);
        setRuns((current) => [
          finalRun.summary,
          ...current.filter((run) => run.id !== finalRun?.summary.id),
        ]);
        setCheckpoints(finalRun.checkpoints);
        setNodeRunStatusById(
          Object.fromEntries(finalRun.nodeRuns.map((run) => [run.nodeId, run])),
        );
        if (runtime.saveWorkflowNodeFixture) {
          const nodeById = new Map(
            scratch.workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem]),
          );
          const fixtureNodeRun =
            finalRun.nodeRuns.find(
              (run) => nodeById.get(run.nodeId)?.type === "output" && run.output,
            ) ?? finalRun.nodeRuns.find((run) => run.output);
          const fixtureNode = fixtureNodeRun
            ? nodeById.get(fixtureNodeRun.nodeId)
            : null;
          if (fixtureNode && fixtureNodeRun) {
            const hashes = workflowFixtureHashesForNode(fixtureNode);
            const fixture: WorkflowNodeFixture = {
              id: `fixture-${fixtureNode.id}-${Date.now()}`,
              nodeId: fixtureNode.id,
              name: `${fixtureNode.name} fixture`,
              input:
                fixtureNodeRun.input ??
                fixtureNode.config?.logic.functionBinding?.testInput ??
                fixtureNode.config?.logic.testInput ??
                fixtureNode.config?.logic.payload ??
                null,
              output: fixtureNodeRun.output ?? null,
              schemaHash: hashes.schemaHash,
              nodeConfigHash: hashes.nodeConfigHash,
              ...workflowFixtureValidationForNode(
                fixtureNode,
                fixtureNodeRun.output ?? null,
              ),
              sourceRunId: finalRun.summary.id,
              pinned: true,
              stale: false,
              createdAtMs: Date.now(),
            };
            setNodeFixturesById(
              groupFixturesByNodeId(
                await runtime.saveWorkflowNodeFixture(
                  bundle.workflowPath,
                  fixture,
                ),
              ),
            );
          }
        }
      }

      const proposalRequest: CreateWorkflowProposalRequest = {
        title: `Bounded ${scratch.workflow.metadata.name} review`,
        summary:
          "Review the scratch-built workflow before applying any graph, code, or test mutations.",
        boundedTargets: workflowPatchBoundedTargets(scratch.workflow),
        workflowPatch: scratch.workflow,
        codeDiff:
          "No files are mutated by this workflow run. Future repair remains proposal-only.",
      };
      if (runtime.createWorkflowProposal) {
        try {
          const proposalBundle = await runtime.createWorkflowProposal(
            bundle.workflowPath,
            proposalRequest,
          );
          setProposals(proposalBundle.proposals);
          setProposalToReview(
            proposalBundle.proposals.find(
              (proposal) => proposal.status === "open",
            ) ?? null,
          );
        } catch {
          const proposal = createLocalProposal(proposalRequest);
          setProposals((current) => [proposal, ...current]);
          setProposalToReview(proposal);
        }
      } else {
        const proposal = createLocalProposal(proposalRequest);
        setProposals((current) => [proposal, ...current]);
        setProposalToReview(proposal);
      }

      let packagePath: string | null = null;
      if (runtime.exportWorkflowPackage) {
        const exported = await runtime.exportWorkflowPackage(
          bundle.workflowPath,
        );
        setPortablePackage(exported);
        packagePath = exported.packagePath;
      }

      const status =
        validation.status === "passed" &&
        testsResult.status === "passed" &&
        (!finalRun || finalRun.summary.status === "passed")
          ? "passed"
          : "blocked";
      const validationWarningCount =
        validation.warnings.length + activationReadiness.warnings.length;
      const validationBlockingIssueCount =
        workflowValidationBlockingIssueCount(validation) +
        workflowValidationBlockingIssueCount(activationReadiness);
      setRightPanel(status === "passed" ? "runs" : "unit_tests");
      setBottomPanel(status === "passed" ? "run_output" : "warnings");
      setStatusMessage(
        status === "passed" && validationWarningCount > 0
          ? `${scratch.workflow.metadata.name} passed with ${workflowIssueCountLabel(
              validationWarningCount,
              "warning",
            )}`
          : `${scratch.workflow.metadata.name} ${status}`,
      );
      return {
        blueprintId,
        status,
        workflowPath: bundle.workflowPath,
        testsPath: bundle.testsPath,
        packagePath,
        bindingCheckCount,
        validationStatus: validation.status,
        readinessStatus: activationReadiness.status,
        readinessNeedsAttention:
          activationReadiness.status !== "passed" ||
          activationReadiness.warnings.length > 0,
        validationWarningCount,
        validationBlockingIssueCount,
        testStatus: testsResult.status,
        runStatus: finalRun?.summary.status ?? "not-run",
        checkpointResumePassed,
      };
    },
    [
      clearRunState,
      currentProject?.rootPath,
      handleAddNodeFromLibrary,
      handleNodeSelect,
      loadRuntimeSidecars,
      loadWorkflowProject,
      runtime,
      setEdges,
      setNodes,
    ],
  );

  const handleBuildRepoTestEngineerScratch = useCallback(
    () => handleBuildScratchBlueprint("repo-test-engineer"),
    [handleBuildScratchBlueprint],
  );

  const handleBuildScratchHeavySuite = useCallback(async () => {
    const results = [];
    for (const blueprintId of SCRATCH_HEAVY_BLUEPRINTS) {
      results.push(await handleBuildScratchBlueprint(blueprintId));
    }
    const status = results.every((result) => result.status === "passed")
      ? "passed"
      : "blocked";
    setStatusMessage(
      workflowChecksStatusMessage(status, {
        warningCount: results.reduce(
          (count, result) => count + result.validationWarningCount,
          0,
        ),
        blockedWorkflowCount: results.filter(
          (result) => result.status !== "passed",
        ).length,
        readinessAttentionWorkflowCount: results.filter(
          (result) => result.readinessNeedsAttention,
        ).length,
      }),
    );
    return { status, results };
  }, [handleBuildScratchBlueprint]);

  const handleDogfoodSuite = useCallback(async () => {
    if (!runtime.runWorkflowDogfoodSuite) return;
    const result = await runtime.runWorkflowDogfoodSuite(
      currentProject?.rootPath || ".",
      "heavy-agent-workflows",
    );
    setDogfoodRun(result);
    setRightPanel("runs");
    setBottomPanel("run_output");
    setStatusMessage(workflowChecksStatusMessage(result.status));
  }, [currentProject?.rootPath, runtime]);

  const handleCreateProposal = async () => {
    const targetIds = selectedNode
      ? workflowPatchBoundedTargets(currentProjectFile, {
          selectedNodeId: selectedNode.id,
        })
      : workflowPatchBoundedTargets(currentProjectFile);
    const request: CreateWorkflowProposalRequest = {
      title: selectedNode
        ? `Review ${selectedNode.name}`
        : "Review workflow improvement",
      summary:
        "Bounded workflow change staged for explicit review before apply.",
      boundedTargets: targetIds,
      workflowPatch: currentProjectFile,
      codeDiff: "Workflow graph metadata and node configuration only.",
    };
    if (runtime.createWorkflowProposal) {
      try {
        const bundle = await runtime.createWorkflowProposal(
          workflowPath,
          request,
        );
        setProposals(bundle.proposals);
        setRuns(bundle.runs);
        setTests(bundle.tests);
        setProposalToReview(
          bundle.proposals.find((proposal) => proposal.status === "open") ??
            null,
        );
      } catch {
        const proposal = createLocalProposal(request);
        setProposals((current) => [proposal, ...current]);
        setProposalToReview(proposal);
      }
    } else {
      const proposal = createLocalProposal(request);
      setProposals((current) => [proposal, ...current]);
      setProposalToReview(proposal);
    }
    setActiveTab("proposals");
    setRightPanel("changes");
    setStatusMessage("Proposal staged");
  };

  const handleApplyProposal = async (proposalId: string) => {
    if (!runtime.applyWorkflowProposal) return;
    const bundle = await runtime.applyWorkflowProposal(
      workflowPath,
      proposalId,
    );
    setProposals(bundle.proposals);
    setRuns(bundle.runs);
    setTests(bundle.tests);
    loadWorkflowProject(bundle.workflow);
    await loadRuntimeSidecars(workflowPath);
    setProposalToReview(null);
    setStatusMessage("Proposal applied");
  };

  const handleAddTest = () => {
    const targets = newTestTargets
      .split(",")
      .map((target) => target.trim())
      .filter(Boolean);
    const fallbackTargets = selectedNode
      ? [selectedNode.id]
      : nodes.slice(0, 1).map((node) => node.id);
    const targetNodeIds = targets.length > 0 ? targets : fallbackTargets;
    const testId = `test-${slugify(newTestName)}-${Date.now()}`;
    let expected: unknown = undefined;
    if (newTestExpected.trim()) {
      try {
        expected = JSON.parse(newTestExpected);
      } catch {
        expected = newTestExpected;
      }
    }
    setTests((current) => [
      ...current,
      {
        id: testId,
        name: newTestName,
        targetNodeIds,
        assertion: {
          kind: newTestKind,
          expected,
          expression: newTestExpression.trim() || undefined,
        },
        status: "idle",
      },
    ]);
    setTestEditorOpen(false);
    setRightPanel("unit_tests");
    setStatusMessage("Unit test added");
  };

  useEffect(() => {
    if (
      SCRATCH_DOGFOOD_SCRIPT !== "scratch-heavy" &&
      SCRATCH_DOGFOOD_SCRIPT !== "manual-repo-test-engineer"
    )
      return;
    if (dogfoodAutomationStarted.current) return;
    dogfoodAutomationStarted.current = true;

    const publishDogfoodState = (payload: Record<string, unknown>) => {
      (window as any).__AUTOPILOT_WORKFLOW_DOGFOOD_RESULT = {
        ...(window as any).__AUTOPILOT_WORKFLOW_DOGFOOD_RESULT,
        ...payload,
        updatedAtMs: Date.now(),
      };
    };

    const runScratchDogfood = async () => {
      const isHeavySuite = SCRATCH_DOGFOOD_SCRIPT === "scratch-heavy";
      publishDogfoodState({
        status: "running",
        phase: isHeavySuite
          ? "build_scratch_heavy_suite"
          : "build_repo_test_engineer",
      });
      setActiveTab("graph");
      setBottomPanel("run_output");
      setStatusMessage("Run checks running");
      try {
        const result = isHeavySuite
          ? await handleBuildScratchHeavySuite()
          : await handleBuildRepoTestEngineerScratch();
        publishDogfoodState({
          ...result,
          phase: "complete",
        });
      } catch (error) {
        const message = errorMessage(error);
        setStatusMessage("Run checks blocked");
        setRightPanel("runs");
        setBottomPanel("run_output");
        publishDogfoodState({
          status: "blocked",
          phase: "error",
          error: message,
        });
      }
    };

    void runScratchDogfood();
  }, [handleBuildRepoTestEngineerScratch, handleBuildScratchHeavySuite]);

  useEffect(() => {
    if (SCRATCH_DOGFOOD_SCRIPT !== "heavy-agent-suite") return;
    if (dogfoodAutomationStarted.current) return;
    dogfoodAutomationStarted.current = true;
    void handleDogfoodSuite();
  }, [handleDogfoodSuite]);

  const proposalStatusCounts = proposals.reduce(
    (counts, proposal) => ({
      ...counts,
      [proposal.status]: counts[proposal.status] + 1,
    }),
    { open: 0, applied: 0, rejected: 0 },
  );
  const proposalBoundedTargetCount = proposals.reduce(
    (total, proposal) => total + proposal.boundedTargets.length,
    0,
  );
  const executionStatusCounts = runs.reduce<Record<string, number>>(
    (counts, run) => {
      counts[run.status] = (counts[run.status] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const selectedExecutionRun =
    runs.find((run) => run.id === selectedRunId) ??
    (lastRunResult ? lastRunResult.summary : null) ??
    runs[0] ??
    null;
  const selectedExecutionRunResult =
    lastRunResult && selectedExecutionRun?.id === lastRunResult.summary.id
      ? lastRunResult
      : null;
  const executionCheckpointCount = runs.reduce(
    (total, run) => total + (run.checkpointCount ?? 0),
    0,
  );
  const executionCompareRun = selectedExecutionRun
    ? (runs.find((run) => run.id !== selectedExecutionRun.id) ?? null)
    : null;
  const lifecycleState = workflowLifecycleState(
    currentProjectFile,
    readinessResult,
    validationResult,
  );

  return (
    <div
      className="workflow-composer"
      data-testid="workflow-composer"
      data-selected-node-id={selectedNodeId ?? ""}
    >
      <header
        className="workflow-composer-header"
        data-testid="workflow-header"
      >
        <div className="workflow-composer-breadcrumbs">
          <span>{currentProject?.name || "Workspace"}</span>
          <span>Workflows</span>
          <strong>{globalConfig.meta.name}</strong>
        </div>
        <div className="workflow-composer-title-row">
          <input
            aria-label="Workflow name"
            value={globalConfig.meta.name}
            disabled={isReadOnlyWorkflow}
            onChange={(event) =>
              setGlobalConfig((current) => ({
                ...current,
                meta: { ...current.meta, name: event.target.value },
              }))
            }
          />
          <span className="workflow-composer-path">{workflowPath}</span>
          <span className="workflow-composer-branch">
            {workflow.metadata.branch || "main"}
          </span>
          <span
            className={`workflow-composer-save-state ${workflow.metadata.dirty ? "is-dirty" : ""}`}
          >
            {workflow.metadata.dirty ? "Unsaved" : "Saved"}
          </span>
          {isReadOnlyWorkflow ? (
            <span
              className="workflow-composer-readonly-badge"
              data-testid="workflow-readonly-badge"
            >
              Read-only
            </span>
          ) : null}
          {harnessWorkerBinding ? (
            <span
              className="workflow-composer-harness-badge"
              data-testid="workflow-harness-worker-binding"
              title={`${harnessWorkerBinding.harnessWorkflowId} · ${harnessWorkerBinding.harnessHash}`}
            >
              Harness {harnessWorkerBinding.source} · {harnessWorkerBinding.harnessWorkflowId}
            </span>
          ) : null}
          <span
            className={`workflow-composer-lifecycle is-${lifecycleState.status}`}
            data-testid="workflow-lifecycle-state"
            data-lifecycle-state={lifecycleState.id}
            title={lifecycleState.detail}
          >
            {lifecycleState.label}
          </span>
        </div>
        <div className="workflow-composer-actions">
          <div
            className="workflow-action-cluster"
            aria-label="Workflow library"
          >
            <span className="workflow-action-cluster-label">Create</span>
            <WorkflowHeaderAction
              label="Add"
              icon={PanelLeftOpen}
              testId="workflow-open-node-drawer"
              onClick={toggleLeftDrawer}
              title="Add nodes"
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Harness"
              icon={GitCompare}
              testId="workflow-open-default-harness"
              onClick={handleOpenDefaultHarness}
              title="Open the read-only Default Agent Harness graph"
            />
            <WorkflowHeaderAction
              label="New"
              icon={Plus}
              testId="workflow-create-button"
              onClick={() => setCreateOpen(true)}
              variant="primary"
              showLabel
              title="Create workflow"
            />
          </div>
          <div
            className="workflow-action-cluster"
            aria-label="Workflow bindings"
          >
            <span className="workflow-action-cluster-label">Bind</span>
            <WorkflowHeaderAction
              label="Models"
              icon={Brain}
              testId="workflow-model-bindings-button"
              onClick={() => setModelBindingOpen(true)}
            />
            <WorkflowHeaderAction
              label="Connectors"
              icon={Cable}
              testId="workflow-connector-bindings-button"
              onClick={() => setConnectorBindingOpen(true)}
            />
          </div>
          <div
            className="workflow-action-cluster"
            aria-label="Workflow run controls"
          >
            <span className="workflow-action-cluster-label">Run</span>
            <WorkflowHeaderAction
              label="Validate"
              icon={CheckCircle2}
              testId="workflow-validate-button"
              onClick={handleValidate}
            />
            <WorkflowHeaderAction
              label="Run tests"
              icon={FlaskConical}
              testId="workflow-run-tests-button"
              onClick={handleRunTests}
              title={`Run tests: ${testsPath}`}
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Run"
              icon={Play}
              testId="workflow-run-button"
              onClick={handleRun}
              variant="primary"
              showLabel
              disabled={isReadOnlyWorkflow}
            />
          </div>
          <div
            className="workflow-action-cluster"
            aria-label="Workflow release controls"
          >
            <span className="workflow-action-cluster-label">Ship</span>
            <WorkflowHeaderAction
              label="Propose"
              icon={GitPullRequest}
              testId="workflow-propose-button"
              onClick={handleCreateProposal}
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Fork harness"
              icon={GitCompare}
              testId="workflow-fork-harness-button"
              onClick={handleForkDefaultHarness}
              disabled={!isBlessedHarnessWorkflow}
              title={
                isBlessedHarnessWorkflow
                  ? "Fork the Default Agent Harness into an editable package"
                  : "Open the Default Agent Harness first"
              }
            />
            <WorkflowHeaderAction
              label="Deploy"
              icon={Rocket}
              testId="workflow-deploy-button"
              onClick={() => {
                void handleOpenDeploy();
              }}
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Save"
              icon={Save}
              testId="workflow-save-button"
              onClick={handleSave}
              disabled={isReadOnlyWorkflow}
            />
          </div>
        </div>
      </header>

      <div
        className="workflow-composer-tabs"
        role="tablist"
        aria-label="Workflow views"
      >
        {(["graph", "proposals", "executions"] as WorkflowWorkbenchTab[]).map(
          (tab) => (
            <button
              key={tab}
              type="button"
              className={activeTab === tab ? "is-active" : ""}
              onClick={() => setActiveTab(tab)}
            >
              {tab === "graph"
                ? "Graph"
                : tab === "proposals"
                  ? "Proposals"
                  : "Executions"}
            </button>
          ),
        )}
      </div>

      {missingReasoningBinding ? (
        <div className="workflow-composer-banner">
          <span>
            A model node needs a model binding. Configure a default model or
            attach a Model Binding node.
          </span>
          <button
            type="button"
            data-testid="workflow-banner-configure-models"
            onClick={() => setModelBindingOpen(true)}
          >
            Configure models
          </button>
        </div>
      ) : null}

      <main className="workflow-composer-body">
        {activeTab === "graph" ? (
          <section
            className={`workflow-composer-graph ${leftDrawerOpen ? "has-left-drawer" : ""}`}
            style={{
              gridTemplateColumns: leftDrawerOpen
                ? `260px minmax(0, 1fr) ${rightRailCollapsed ? "48px" : `${rightRailWidth}px`}`
                : `minmax(0, 1fr) ${rightRailCollapsed ? "48px" : `${rightRailWidth}px`}`,
            }}
          >
            {leftDrawerOpen ? (
              <aside
                className="workflow-composer-left-drawer"
                aria-label="Workflow node library"
                data-testid="workflow-left-drawer"
              >
                <header>
                  <h3>Add node</h3>
                  <button type="button" onClick={closeLeftDrawer}>
                    Close
                  </button>
                </header>
                <label className="workflow-node-search">
                  <span>Search primitives</span>
                  <input
                    data-testid="workflow-node-library-search"
                    value={nodeSearch}
                    onChange={(event) => setNodeSearch(event.target.value)}
                    placeholder="Search sources, models, tools..."
                  />
                </label>
                <nav
                  className="workflow-node-group-filter"
                  data-testid="workflow-node-group-filter"
                  aria-label="Primitive groups"
                >
                  {NODE_GROUP_FILTERS.map((filter) => {
                    const count = nodeGroupCounts.get(filter) ?? 0;
                    const disabled = filter === "Compatible" && count === 0;
                    return (
                      <button
                        key={filter}
                        type="button"
                        className={
                          nodeGroupFilter === filter ? "is-active" : ""
                        }
                        data-testid={`workflow-node-group-filter-${slugify(filter)}`}
                        disabled={disabled}
                        title={
                          filter === "Compatible"
                            ? "Show primitives compatible with the selected node"
                            : `Show ${filter}`
                        }
                        onClick={() => {
                          setNodeGroupFilter(filter);
                          if (filter !== "Compatible") {
                            setCompatiblePortFocus(null);
                          }
                        }}
                      >
                        <span>{filter}</span>
                        <small>{count}</small>
                      </button>
                    );
                  })}
                </nav>
                <p
                  className="workflow-node-drawer-summary"
                  data-testid="workflow-node-drawer-summary"
                >
                  {filteredNodeLibrary.length} primitive
                  {filteredNodeLibrary.length === 1 ? "" : "s"}
                  {nodeGroupFilter === "Compatible" && selectedNode
                    ? ` compatible with ${compatiblePortFocusLabel ?? selectedNode.name}`
                    : ""}
                </p>
                {!isSearchingNodeLibrary && recentNodeLibrary.length > 0 ? (
                  <section
                    className="workflow-recent-primitives"
                    data-testid="workflow-recent-primitives"
                  >
                    <h5>Recently used</h5>
                    <div>
                      {recentNodeLibrary.map((item) => {
                        const badge = workflowNodeCreatorBadge(
                          item,
                          globalConfig,
                        );
                        const itemId = workflowCreatorItemId(item);
                        return (
                          <button
                            key={`recent-${itemId}`}
                            type="button"
                            data-testid={`workflow-recent-primitive-${itemId}`}
                            onClick={() =>
                              handleAddNodeFromLibrary(
                                item.type,
                                item.label,
                                undefined,
                                {
                                  openConfig: true,
                                  closeDrawer: true,
                                  creatorId: itemId,
                                  defaultLogic: item.defaultLogic,
                                  defaultLaw: item.defaultLaw,
                                  metricLabel: item.metricLabel,
                                  metricValue: item.metricValue,
                                },
                              )
                            }
                            title={`Add ${item.label}`}
                          >
                            <strong>{item.label}</strong>
                            <span>{item.group}</span>
                            <small
                              className="workflow-action-metadata"
                              data-testid={`workflow-recent-action-${itemId}`}
                            >
                              {workflowActionMetadataLabel(item)}
                            </small>
                            <em data-readiness={badge.status}>{badge.label}</em>
                          </button>
                        );
                      })}
                    </div>
                  </section>
                ) : null}
                {selectedNode &&
                visibleCompatibleNodeHints.length > 0 &&
                !isSearchingNodeLibrary ? (
                  <section
                    className="workflow-related-nodes"
                    data-testid="workflow-related-node-hints"
                  >
                    <div className="workflow-related-header">
                      <h5>
                        Works with{" "}
                        {compatiblePortFocusLabel ?? selectedNode.name}
                      </h5>
                      {compatiblePortFocusLabel ? (
                        <button
                          type="button"
                          data-testid="workflow-clear-compatible-port-filter"
                          onClick={() => setCompatiblePortFocus(null)}
                        >
                          All ports
                        </button>
                      ) : null}
                    </div>
                    <div>
                      {visibleCompatibleNodeHints.slice(0, 8).map((hint) => {
                        const item = hint.definition;
                        const badge = workflowNodeCreatorBadge(
                          item,
                          globalConfig,
                        );
                        const itemId = workflowCreatorItemId(item);
                        return (
                          <button
                            key={`related-${hint.direction}-${itemId}-${hint.sourcePort.id}-${hint.targetPort.id}`}
                            type="button"
                            data-testid={`workflow-add-compatible-${itemId}`}
                            data-connection-class={hint.connectionClass}
                            data-connection-direction={hint.direction}
                            className={hint.recommended ? "is-recommended" : ""}
                            onClick={() =>
                              handleAddCompatibleNode(selectedNode, item, hint)
                            }
                            title={`Add ${item.label}: ${hint.sourcePort.label} to ${hint.targetPort.label}`}
                          >
                            <strong>{item.label}</strong>
                            <span data-testid="workflow-compatible-port-path">
                              {hint.direction === "attachment"
                                ? "Attach"
                                : "After"}{" "}
                              · {hint.sourcePort.label}
                              {" -> "}
                              {hint.targetPort.label} · {hint.connectionClass}
                            </span>
                            <small
                              className="workflow-action-metadata"
                              data-testid={`workflow-compatible-action-${itemId}`}
                            >
                              {workflowActionMetadataLabel(item)}
                            </small>
                            <em data-readiness={badge.status}>{badge.label}</em>
                          </button>
                        );
                      })}
                    </div>
                  </section>
                ) : selectedDefinition ? (
                  <p className="workflow-related-empty">
                    {compatiblePortFocusLabel ? (
                      <>
                        No primitives match {compatiblePortFocusLabel}.{" "}
                        <button
                          type="button"
                          data-testid="workflow-clear-compatible-port-filter-empty"
                          onClick={() => setCompatiblePortFocus(null)}
                        >
                          Show all compatible ports
                        </button>
                      </>
                    ) : (
                      <>
                        Select a node with compatible ports to add downstream or
                        attached primitives.
                      </>
                    )}
                  </p>
                ) : null}
                {!isSearchingNodeLibrary ? (
                  <section
                    className="workflow-macro-library"
                    data-testid="workflow-macro-library"
                  >
                    <h5>Composition helpers</h5>
                    <button
                      type="button"
                      data-testid="workflow-add-agent-loop-macro"
                      onClick={handleInsertAgentLoopMacro}
                      title="Expand a generic agent loop into explicit source, model, memory, tool, decision, and output nodes"
                    >
                      <strong>Agent loop</strong>
                      <span>
                        Expands into typed primitives with visible tool and
                        memory attachments.
                      </span>
                    </button>
                  </section>
                ) : null}
                <section
                  className="workflow-component-library"
                  data-testid="workflow-component-library"
                >
                  {filteredNodeLibrary.length === 0 ? (
                    <p
                      className="workflow-node-library-empty"
                      data-testid="workflow-node-library-empty"
                    >
                      No primitives match the current search and group filter.
                    </p>
                  ) : null}
                  {SCAFFOLD_GROUPS.map((group) => {
                    const groupItems = filteredNodeLibrary.filter(
                      (item) => item.group === group,
                    );
                    if (groupItems.length === 0) return null;
                    return (
                      <div
                        className="workflow-scaffold-group"
                        key={group}
                        data-testid={`workflow-scaffold-group-${slugify(group)}`}
                      >
                        <h5>{group}</h5>
                        {groupItems.map((item) => {
                          const scaffold = WORKFLOW_SCAFFOLDS.find(
                            (entry) => entry.nodeType === item.type,
                          );
                          const classList =
                            scaffold?.connectionClasses?.join(", ") || "data";
                          const badge = workflowNodeCreatorBadge(
                            item,
                            globalConfig,
                          );
                          const itemId = workflowCreatorItemId(item);
                          const compatibleHint =
                            selectedNode && isSearchingNodeLibrary
                              ? compatibleNodeHints.find(
                                  (hint) =>
                                    workflowCreatorItemId(hint.definition) ===
                                    itemId,
                                )
                              : undefined;
                          return (
                            <button
                              key={`drawer-${itemId}`}
                              type="button"
                              data-testid={`workflow-component-${itemId}`}
                              data-node-type={item.type}
                              draggable
                              onDragStart={(event) =>
                                handleDragStart(event, item.type, item.label)
                              }
                              onClick={() =>
                                selectedNode && compatibleHint
                                  ? handleAddCompatibleNode(
                                      selectedNode,
                                      item,
                                      compatibleHint,
                                    )
                                  : handleAddNodeFromLibrary(
                                      item.type,
                                      item.label,
                                      undefined,
                                      {
                                        openConfig: true,
                                        closeDrawer: true,
                                        creatorId: itemId,
                                        defaultLogic: item.defaultLogic,
                                        defaultLaw: item.defaultLaw,
                                        metricLabel: item.metricLabel,
                                        metricValue: item.metricValue,
                                      },
                                    )
                              }
                              title={
                                ("creatorDescription" in item
                                  ? item.creatorDescription
                                  : undefined) ??
                                scaffold?.description ??
                                `Add ${item.label}`
                              }
                            >
                              <strong>{item.label}</strong>
                              <span>
                                {item.familyLabel} · {classList}
                              </span>
                              <small
                                className="workflow-action-metadata"
                                data-testid={`workflow-component-action-${itemId}`}
                              >
                                {workflowActionMetadataLabel(item)}
                              </small>
                              <em
                                data-testid={`workflow-component-readiness-${itemId}`}
                                data-readiness={badge.status}
                              >
                                {badge.label}
                              </em>
                            </button>
                          );
                        })}
                      </div>
                    );
                  })}
                </section>
              </aside>
            ) : null}
            <div className="workflow-composer-canvas-stage">
              <div
                className="workflow-composer-toolbar workflow-composer-toolbar--compact"
                aria-label="Workflow canvas tools"
              >
                <button
                  type="button"
                  className="workflow-toolbar-action"
                  data-testid="workflow-open-node-library"
                  onClick={openLeftDrawer}
                  title="Open node library"
                  aria-label="Open node library"
                >
                  <WorkflowInlineIcon icon={PanelLeftOpen} />
                  <span>Add</span>
                </button>
              </div>

              <div className="workflow-composer-canvas-controls">
                <button
                  type="button"
                  className={`workflow-icon-button ${canvasSearchOpen ? "is-active" : ""}`}
                  aria-label="Search workflow"
                  title="Search workflow"
                  data-testid="workflow-canvas-search-toggle"
                  onClick={toggleCanvasSearch}
                >
                  <WorkflowInlineIcon icon={Search} />
                </button>
                {canvasSearchOpen ? (
                  <section
                    className="workflow-canvas-search-panel"
                    data-testid="workflow-canvas-search-panel"
                    aria-label="Search workflow nodes"
                  >
                    <label>
                      <span>Find node</span>
                      <input
                        autoFocus
                        data-testid="workflow-canvas-search-input"
                        value={canvasSearchQuery}
                        onChange={(event) =>
                          setCanvasSearchQuery(event.target.value)
                        }
                        placeholder="Name, type, status, field..."
                      />
                    </label>
                    <div
                      className="workflow-canvas-search-results"
                      data-testid="workflow-canvas-search-results"
                    >
                      {canvasSearchResults.length > 0 ? (
                        canvasSearchResults.map((result) => {
                          const nodeItem = result.node;
                          return (
                            <article
                              key={nodeItem.id}
                              className={`workflow-canvas-search-result-row ${
                                selectedNodeId === nodeItem.id
                                  ? "is-selected"
                                  : ""
                              }`}
                              data-testid="workflow-canvas-search-result"
                            >
                              <button
                                type="button"
                                className="workflow-canvas-search-result-main"
                                onClick={() => {
                                  handleWorkflowNodeSelect(nodeItem.id);
                                  setBottomPanel("selection");
                                }}
                              >
                                <strong>{nodeItem.name}</strong>
                                <span>
                                  {nodeItem.type}
                                  {result.status ? ` · ${result.status}` : ""}
                                </span>
                                <small>
                                  {result.configuredFields.length > 0
                                    ? result.configuredFields
                                        .slice(0, 4)
                                        .join(", ")
                                    : nodeItem.id}
                                </small>
                              </button>
                              <button
                                type="button"
                                className="workflow-canvas-search-compatible"
                                data-testid="workflow-canvas-search-compatible"
                                title={`Show compatible nodes for ${nodeItem.name}`}
                                onClick={() => {
                                  handleWorkflowNodeSelect(nodeItem.id);
                                  setCompatiblePortFocus(null);
                                  openLeftDrawer();
                                  setNodeGroupFilter("Compatible");
                                  setNodeSearch("");
                                  setBottomPanel("selection");
                                }}
                              >
                                Add next
                              </button>
                              <button
                                type="button"
                                className="workflow-canvas-search-configure"
                                data-testid="workflow-canvas-search-configure"
                                title={`Configure ${nodeItem.name}`}
                                onClick={() => {
                                  handleWorkflowNodeSelect(nodeItem.id);
                                  closeCanvasSearch();
                                  setNodeConfigInitialSection(
                                    workflowConfigSectionForNodeKind(
                                      nodeItem.type,
                                    ),
                                  );
                                  setNodeConfigOpen(true);
                                }}
                              >
                                Configure
                              </button>
                            </article>
                          );
                        })
                      ) : (
                        <p data-testid="workflow-canvas-search-empty">
                          No nodes match this search.
                        </p>
                      )}
                    </div>
                  </section>
                ) : null}
                <div className="workflow-legend">
                  {counts.map((item) => (
                    <span key={item.family}>
                      <i data-family={item.family} />
                      {item.family} ({item.count})
                    </span>
                  ))}
                </div>
              </div>

              <Canvas
                nodes={displayNodes}
                edges={displayEdges}
                onNodesChange={guardedOnNodesChange}
                onEdgesChange={guardedOnEdgesChange}
                onConnect={guardedOnConnect}
                onNodeSelect={handleWorkflowNodeSelect}
                onNodeActivate={(nodeId) => {
                  if (isReadOnlyWorkflow) return;
                  const nodeItem = nodes.find((node) => node.id === nodeId)
                    ?.data as Node | undefined;
                  handleWorkflowNodeSelect(nodeId);
                  setNodeConfigInitialSection(
                    workflowConfigSectionForNodeKind(nodeItem?.type ?? ""),
                  );
                  setNodeConfigOpen(true);
                }}
                onDrop={guardedCanvasDrop}
                readOnly={isReadOnlyWorkflow}
              />

              {nodes.length === 0 ? (
                <section
                  className="workflow-start-overlay"
                  data-testid="workflow-empty-start-overlay"
                  aria-label="Choose what starts this workflow"
                >
                  <header>
                    <div>
                      <h3>What starts this workflow?</h3>
                      <p>
                        Start with a trigger or input, then grow the graph from
                        typed ports.
                      </p>
                    </div>
                    <button
                      type="button"
                      data-testid="workflow-empty-browse-primitives"
                      onClick={() => {
                        setNodeGroupFilter("All");
                        setNodeSearch("");
                        openLeftDrawer();
                      }}
                    >
                      Browse all primitives
                    </button>
                  </header>
                  <div className="workflow-start-card-grid">
                    {emptyCanvasStartItems.map((item) => {
                      const itemId = workflowCreatorItemId(item);
                      const badge = workflowNodeCreatorBadge(
                        item,
                        globalConfig,
                      );
                      return (
                        <button
                          key={itemId}
                          type="button"
                          className="workflow-start-card"
                          data-testid={`workflow-empty-start-${itemId}`}
                          onClick={() =>
                            handleAddNodeFromLibrary(
                              item.type,
                              item.label,
                              undefined,
                              {
                                openConfig: true,
                                closeDrawer: true,
                                creatorId: itemId,
                                defaultLogic: item.defaultLogic,
                                defaultLaw: item.defaultLaw,
                                metricLabel: item.metricLabel,
                                metricValue: item.metricValue,
                              },
                            )
                          }
                          title={item.creatorDescription}
                        >
                          <strong>{item.label}</strong>
                          <span>{item.creatorDescription}</span>
                          <small>
                            {item.group} · {workflowActionMetadataLabel(item)}
                          </small>
                          <em data-readiness={badge.status}>{badge.label}</em>
                        </button>
                      );
                    })}
                  </div>
                </section>
              ) : null}

              <div className="workflow-zoom-controls">
                <button type="button" onClick={() => zoomIn({ duration: 160 })}>
                  +
                </button>
                <button
                  type="button"
                  onClick={() => zoomOut({ duration: 160 })}
                >
                  -
                </button>
                <button type="button" onClick={() => fitView({ padding: 0.2 })}>
                  Fit
                </button>
              </div>
              {selectedNode ? (
                <div className="workflow-selection-actions">
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-configure-node"
                    aria-label="Configure node"
                    title="Configure node"
                    onClick={() => {
                      setNodeConfigInitialSection(
                        workflowConfigSectionForNodeKind(selectedNode.type),
                      );
                      setNodeConfigOpen(true);
                    }}
                  >
                    <WorkflowInlineIcon icon={Settings} />
                    <span className="workflow-action-tooltip">
                      Configure node
                    </span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-show-compatible-nodes"
                    aria-label="Show compatible nodes"
                    title="Show compatible nodes"
                    disabled={compatibleNodeHints.length === 0}
                    onClick={() => {
                      setCompatiblePortFocus(null);
                      openLeftDrawer();
                      setNodeGroupFilter("Compatible");
                      setNodeSearch("");
                      setStatusMessage(
                        compatibleNodeHints.length > 0
                          ? `${compatibleNodeHints.length} compatible node option${compatibleNodeHints.length === 1 ? "" : "s"} for ${selectedNode.name}`
                          : `No compatible nodes found for ${selectedNode.name}`,
                      );
                    }}
                  >
                    <WorkflowInlineIcon icon={Plus} />
                    <span className="workflow-action-tooltip">
                      Show compatible nodes
                    </span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-connect-from-node"
                    aria-label="Connect from"
                    title="Connect from"
                    onClick={() => {
                      setConnectFromNodeId(selectedNode.id);
                      setStatusMessage(`Connecting from ${selectedNode.name}`);
                    }}
                  >
                    <WorkflowInlineIcon icon={Cable} />
                    <span className="workflow-action-tooltip">
                      Connect from
                    </span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-connect-to-node"
                    aria-label="Connect to"
                    title="Connect to"
                    disabled={
                      !connectFromNodeId ||
                      connectFromNodeId === selectedNode.id
                    }
                    onClick={handleConnectSelectedNodes}
                  >
                    <WorkflowInlineIcon icon={GitPullRequest} />
                    <span className="workflow-action-tooltip">Connect to</span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-add-node-test"
                    aria-label="Add test"
                    title="Add test"
                    onClick={() => {
                      setNewTestTargets(selectedNode.id);
                      setNewTestKind("node_exists");
                      setNewTestExpected("");
                      setNewTestExpression("");
                      setTestEditorOpen(true);
                    }}
                  >
                    <WorkflowInlineIcon icon={FlaskConical} />
                    <span className="workflow-action-tooltip">Add test</span>
                  </button>
                </div>
              ) : null}
            </div>

            <aside
              className={`workflow-composer-rail ${rightRailCollapsed ? "is-collapsed" : ""}`}
              data-testid={`workflow-right-rail-${rightPanel}`}
            >
              {!rightRailCollapsed ? (
                <div className="workflow-composer-rail-panel">
                  <div className="workflow-rail-controls">
                    <div className="workflow-rail-active-header">
                      <button
                        type="button"
                        className="workflow-icon-button"
                        data-testid="workflow-rail-collapse"
                        aria-label="Collapse rail"
                        title="Collapse rail"
                        onClick={() => setRightRailCollapsed(true)}
                      >
                        <WorkflowInlineIcon icon={PanelRightClose} />
                      </button>
                      <div>
                        <strong>{activeRightPanelMeta.label}</strong>
                        <span>{activeRightPanelMeta.description}</span>
                      </div>
                    </div>
                    <label>
                      Width
                      <input
                        type="range"
                        min={280}
                        max={460}
                        value={rightRailWidth}
                        onChange={(event) =>
                          setRightRailWidth(Number(event.target.value))
                        }
                      />
                    </label>
                  </div>
                  <WorkflowRailPanel
                    panel={rightPanel}
                    selectedNode={selectedNode}
                    tests={tests}
                    proposals={proposals}
                    runs={runs}
                    validationResult={validationResult}
                    readinessResult={readinessResult}
                    testResult={testResult}
                    workflow={currentProjectFile}
                    lastRunResult={lastRunResult}
                    selectedRunId={selectedRunId}
                    compareRunResult={compareRunResult}
                    compareRunId={compareRunId}
                    runEvents={runEvents}
                    dogfoodRun={dogfoodRun}
                    portablePackage={portablePackage}
                    bindingManifest={bindingManifest}
                    selectedNodeFixtures={selectedFixtures}
                    checkpoints={checkpoints}
                    onSelectRun={handleSelectRun}
                    onCompareRun={handleCompareRun}
                    onOpenExecutions={() => setActiveTab("executions")}
                    onInspectNode={(nodeId) => handleWorkflowNodeSelect(nodeId)}
                    onConfigureNode={() => {
                      if (selectedNode) {
                        setNodeConfigInitialSection(
                          workflowConfigSectionForNodeKind(selectedNode.type),
                        );
                      }
                      setNodeConfigOpen(true);
                    }}
                    onSelectProposal={(proposal) =>
                      setProposalToReview(proposal)
                    }
                    onExportPackage={handleExportPortablePackage}
                    onOpenImportPackage={() => setImportPackageOpen(true)}
                    onGenerateBindingManifest={handleGenerateBindingManifest}
                    onUpdateEnvironmentProfile={handleUpdateEnvironmentProfile}
                    onUpdateProductionProfile={handleUpdateProductionProfile}
                    onCheckBinding={handleCheckWorkflowBinding}
                    onResolveIssue={handleResolveWorkflowIssue}
                    onRunNode={(node, fixture) => {
                      void handleRunWorkflowNode(node, fixture);
                    }}
                    onRunUpstream={(node) => {
                      void handleRunWorkflowUpstream(node);
                    }}
                    onCaptureFixtureForNode={(node) => {
                      void handleCaptureNodeFixture(node);
                    }}
                    onDryRunFixtureForNode={(node, fixture) => {
                      void handleDryRunNodeFromFixture(node, fixture);
                    }}
                    onPinFixtureForNode={(node, fixture) => {
                      void handlePinNodeFixture(node, fixture);
                    }}
                    onAddTestFromOutput={handleAddTestFromOutput}
                  />
                </div>
              ) : null}
              <nav
                className="workflow-composer-rail-strip"
                aria-label="Workflow panels"
              >
                <button
                  type="button"
                  data-testid="workflow-rail-toggle"
                  className={rightRailCollapsed ? "is-active" : ""}
                  title={rightRailCollapsed ? "Expand rail" : "Collapse rail"}
                  aria-label={
                    rightRailCollapsed ? "Expand rail" : "Collapse rail"
                  }
                  onClick={() =>
                    setRightRailCollapsed((collapsed) => !collapsed)
                  }
                >
                  {rightRailCollapsed ? (
                    <WorkflowInlineIcon icon={PanelRightOpen} />
                  ) : (
                    <WorkflowInlineIcon icon={PanelRightClose} />
                  )}
                </button>
                {RIGHT_PANELS.map((panel) => {
                  const PanelIcon = panel.icon;
                  const badgeCount = rightPanelBadgeCounts[panel.id];
                  return (
                    <button
                      key={panel.id}
                      type="button"
                      data-testid={`workflow-rail-panel-${panel.id}`}
                      className={rightPanel === panel.id ? "is-active" : ""}
                      title={`${panel.label}: ${panel.description}`}
                      aria-label={panel.label}
                      data-panel-badge={badgeCount > 0 ? badgeCount : undefined}
                      onClick={() => {
                        setRightPanel(panel.id);
                        setRightRailCollapsed(false);
                      }}
                    >
                      <WorkflowInlineIcon icon={PanelIcon} />
                      <span className="workflow-rail-panel-label">
                        <strong>{panel.label}</strong>
                        <small>{panel.description}</small>
                      </span>
                      {badgeCount > 0 ? (
                        <em
                          className="workflow-rail-panel-badge"
                          data-testid={`workflow-rail-panel-badge-${panel.id}`}
                        >
                          {badgeCount > 99 ? "99+" : badgeCount}
                        </em>
                      ) : null}
                    </button>
                  );
                })}
              </nav>
            </aside>
          </section>
        ) : null}

        {activeTab === "proposals" ? (
          <section
            className="workflow-composer-empty workflow-proposals-workbench"
            data-testid="workflow-proposals-workbench"
          >
            <header className="workflow-workbench-tab-header">
              <div>
                <h3>Proposals</h3>
                <p>
                  Review bounded graph, test, and code changes before anything
                  is applied.
                </p>
              </div>
              <button
                type="button"
                onClick={handleCreateProposal}
                data-testid="workflow-proposals-create"
              >
                Create proposal
              </button>
            </header>
            <dl
              className="workflow-tab-stats"
              data-testid="workflow-proposals-summary"
            >
              <div>
                <dt>Open</dt>
                <dd>{proposalStatusCounts.open}</dd>
              </div>
              <div>
                <dt>Applied</dt>
                <dd>{proposalStatusCounts.applied}</dd>
              </div>
              <div>
                <dt>Rejected</dt>
                <dd>{proposalStatusCounts.rejected}</dd>
              </div>
              <div>
                <dt>Bounded targets</dt>
                <dd>{proposalBoundedTargetCount}</dd>
              </div>
            </dl>
            {proposals.length === 0 ? (
              <section
                className="workflow-tab-empty"
                data-testid="workflow-proposals-empty"
              >
                <strong>No proposals</strong>
                <span>
                  Use proposals for self-mutation, generated repair, or
                  reviewable workflow changes.
                </span>
              </section>
            ) : (
              <div
                className="workflow-proposal-workbench-list"
                data-testid="workflow-proposal-workbench-list"
              >
                {proposals.map((proposal) => {
                  const changedNodeIds = [
                    ...(proposal.graphDiff?.addedNodeIds ?? []),
                    ...(proposal.graphDiff?.changedNodeIds ?? []),
                    ...(proposal.graphDiff?.removedNodeIds ?? []),
                  ];
                  return (
                    <article
                      key={proposal.id}
                      className={`workflow-proposal-review-card is-${proposal.status}`}
                      data-testid={`workflow-proposals-card-${proposal.id}`}
                    >
                      <header>
                        <div>
                          <strong>{proposal.title}</strong>
                          <span>{proposal.summary}</span>
                        </div>
                        <em>{proposal.status}</em>
                      </header>
                      <dl>
                        <div>
                          <dt>Targets</dt>
                          <dd>{proposal.boundedTargets.length}</dd>
                        </div>
                        <div>
                          <dt>Changed nodes</dt>
                          <dd>{changedNodeIds.length}</dd>
                        </div>
                        <div>
                          <dt>Created</dt>
                          <dd>{workflowTimeLabel(proposal.createdAtMs)}</dd>
                        </div>
                      </dl>
                      <div
                        className="workflow-proposal-targets"
                        data-testid={`workflow-proposals-targets-${proposal.id}`}
                      >
                        {proposal.boundedTargets.slice(0, 6).map((target) => (
                          <code key={target}>{target}</code>
                        ))}
                        {proposal.boundedTargets.length > 6 ? (
                          <code>+{proposal.boundedTargets.length - 6}</code>
                        ) : null}
                      </div>
                      <footer>
                        <span>
                          {changedNodeIds.length > 0
                            ? changedNodeIds
                                .map((nodeId) =>
                                  workflowNodeName(currentProjectFile, nodeId),
                                )
                                .join(", ")
                            : "No graph node changes recorded"}
                        </span>
                        <button
                          type="button"
                          onClick={() => setProposalToReview(proposal)}
                        >
                          Preview
                        </button>
                      </footer>
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        ) : null}

        {activeTab === "executions" ? (
          <section
            className="workflow-composer-empty workflow-executions-workbench"
            data-testid="workflow-executions-workbench"
          >
            <header className="workflow-workbench-tab-header">
              <div>
                <h3>Executions</h3>
                <p>
                  Inspect run lifecycle, attempts, checkpoints, interrupts, and
                  output status.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRun}
                data-testid="workflow-executions-run-now"
              >
                Run workflow
              </button>
            </header>
            <dl
              className="workflow-tab-stats"
              data-testid="workflow-executions-summary"
            >
              <div>
                <dt>Runs</dt>
                <dd>{runs.length}</dd>
              </div>
              <div>
                <dt>Passed</dt>
                <dd>{executionStatusCounts.passed ?? 0}</dd>
              </div>
              <div>
                <dt>Blocked</dt>
                <dd>
                  {(executionStatusCounts.blocked ?? 0) +
                    (executionStatusCounts.failed ?? 0)}
                </dd>
              </div>
              <div>
                <dt>Checkpoints</dt>
                <dd>{executionCheckpointCount}</dd>
              </div>
            </dl>
            {runs.length === 0 ? (
              <section
                className="workflow-tab-empty"
                data-testid="workflow-executions-empty"
              >
                <strong>No runs</strong>
                <span>
                  Run the workflow to create executions, node attempts, and
                  checkpoint records.
                </span>
              </section>
            ) : (
              <div className="workflow-executions-layout">
                <div
                  className="workflow-executions-run-list"
                  data-testid="workflow-executions-run-list"
                >
                  {runs.map((run) => (
                    <article
                      key={run.id}
                      className={`workflow-executions-run-card is-${run.status} ${selectedExecutionRun?.id === run.id ? "is-active" : ""}`}
                      data-testid={`workflow-executions-run-${run.id}`}
                    >
                      <button
                        type="button"
                        onClick={() => void handleSelectRun(run)}
                      >
                        <strong>{run.status}</strong>
                        <span>{run.summary}</span>
                        <small>
                          {workflowDurationLabel(
                            run.startedAtMs,
                            run.finishedAtMs,
                          )}{" "}
                          · {run.checkpointCount ?? 0} checkpoints
                        </small>
                      </button>
                      {lastRunResult && run.id !== lastRunResult.summary.id ? (
                        <button
                          type="button"
                          className="workflow-inline-link"
                          onClick={() => void handleCompareRun(run)}
                        >
                          Compare
                        </button>
                      ) : null}
                    </article>
                  ))}
                </div>
                <section
                  className="workflow-executions-detail"
                  data-testid="workflow-executions-run-detail"
                >
                  {selectedExecutionRun ? (
                    <>
                      <header>
                        <div>
                          <strong>{selectedExecutionRun.status}</strong>
                          <span>{selectedExecutionRun.summary}</span>
                        </div>
                        {executionCompareRun ? (
                          <button
                            type="button"
                            onClick={() =>
                              void handleCompareRun(executionCompareRun)
                            }
                          >
                            Compare latest
                          </button>
                        ) : null}
                      </header>
                      <dl className="workflow-tab-stats">
                        <div>
                          <dt>Nodes</dt>
                          <dd>{selectedExecutionRun.nodeCount}</dd>
                        </div>
                        <div>
                          <dt>Tests</dt>
                          <dd>{selectedExecutionRun.testCount}</dd>
                        </div>
                        <div>
                          <dt>Checkpoints</dt>
                          <dd>{selectedExecutionRun.checkpointCount ?? 0}</dd>
                        </div>
                        <div>
                          <dt>Duration</dt>
                          <dd>
                            {workflowDurationLabel(
                              selectedExecutionRun.startedAtMs,
                              selectedExecutionRun.finishedAtMs,
                            )}
                          </dd>
                        </div>
                      </dl>
                      {selectedExecutionRunResult ? (
                        <>
                          <div
                            className="workflow-run-attempt-grid"
                            data-testid="workflow-executions-node-attempts"
                          >
                            {selectedExecutionRunResult.nodeRuns.map(
                              (nodeRun) => {
                                const childLineage =
                                  workflowNodeRunChildLineage(nodeRun);
                                return (
                                  <button
                                    key={`${nodeRun.nodeId}-${nodeRun.attempt}-${nodeRun.startedAtMs}`}
                                    type="button"
                                    className={`workflow-run-attempt is-${nodeRun.status}`}
                                    onClick={() =>
                                      handleInspectExecutionNode(nodeRun.nodeId)
                                    }
                                  >
                                    <strong>
                                      {workflowNodeName(
                                        currentProjectFile,
                                        nodeRun.nodeId,
                                      )}
                                    </strong>
                                    <span>
                                      {nodeRun.status} · attempt{" "}
                                      {nodeRun.attempt}
                                    </span>
                                    <small>
                                      {nodeRun.error ??
                                        workflowDurationLabel(
                                          nodeRun.startedAtMs,
                                          nodeRun.finishedAtMs,
                                        )}
                                      {" · "}
                                      {nodeRun.input === undefined
                                        ? "input not captured"
                                        : "input captured"}
                                    </small>
                                    <small
                                      className="workflow-run-lifecycle"
                                      data-testid="workflow-executions-node-lifecycle"
                                    >
                                      {(nodeRun.lifecycle?.length ?? 0) > 0
                                        ? `${nodeRun.lifecycle?.length} run steps`
                                        : "run steps pending"}
                                      {nodeRun.checkpointId
                                        ? " · checkpoint saved"
                                        : ""}
                                    </small>
                                    {childLineage ? (
                                      <small
                                        className="workflow-run-child-lineage"
                                        data-testid="workflow-executions-child-lineage"
                                        data-node-id={nodeRun.nodeId}
                                      >
                                        Child run {childLineage.childRunStatus}{" "}
                                        · {childLineage.childRunId}
                                      </small>
                                    ) : null}
                                  </button>
                                );
                              },
                            )}
                          </div>
                          <ol
                            className="workflow-run-timeline"
                            data-testid="workflow-executions-timeline"
                          >
                            {selectedExecutionRunResult.events
                              .slice(0, 12)
                              .map((event) => (
                                <li
                                  key={event.id}
                                  className={`is-${event.status ?? event.kind}`}
                                >
                                  <strong>{workflowEventLabel(event)}</strong>
                                  <span>
                                    {event.message ??
                                      workflowNodeName(
                                        currentProjectFile,
                                        event.nodeId,
                                      )}
                                  </span>
                                  <small>
                                    {workflowTimeLabel(event.createdAtMs)}
                                  </small>
                                </li>
                              ))}
                          </ol>
                        </>
                      ) : (
                        <p>
                          Load a run to inspect node attempts and timeline
                          events.
                        </p>
                      )}
                    </>
                  ) : null}
                </section>
              </div>
            )}
          </section>
        ) : null}
      </main>

      <section
        className="workflow-composer-bottom"
        aria-label="Workflow details"
        data-testid={`workflow-bottom-${bottomPanel}`}
      >
        <div className="workflow-composer-bottom-tabs">
          {BOTTOM_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              data-testid={`workflow-bottom-tab-${tab.id}`}
              className={bottomPanel === tab.id ? "is-active" : ""}
              onClick={() => setBottomPanel(tab.id)}
            >
              {tab.label}
            </button>
          ))}
          <span>{statusMessage}</span>
        </div>
        <WorkflowBottomShelf
          panel={bottomPanel}
          selectedNode={selectedNode}
          selectedNodeRun={
            selectedNode ? (nodeRunStatusById[selectedNode.id] ?? null) : null
          }
          tests={tests}
          proposals={proposals}
          testResult={testResult}
          validationResult={validationResult}
          runs={runs}
          lastRunResult={lastRunResult}
          runDetailLoading={runDetailLoading}
          compareRunResult={compareRunResult}
          workflow={currentProjectFile}
          functionDryRunResult={functionDryRunResult}
          dogfoodRun={dogfoodRun}
          fixtures={selectedFixtures}
          runEvents={runEvents}
          checkpoints={checkpoints}
          logs={execution.logs}
          onCaptureFixture={() => {
            if (selectedNode) void handleCaptureNodeFixture(selectedNode);
          }}
          onPinFixture={(fixture) => {
            if (selectedNode) void handlePinNodeFixture(selectedNode, fixture);
          }}
          onDryRunFixture={(fixture) => {
            if (selectedNode)
              void handleDryRunNodeFromFixture(selectedNode, fixture);
          }}
          onResumeRun={handleResumeRun}
          onInspectNode={(nodeId) => handleWorkflowNodeSelect(nodeId)}
        />
      </section>

      {createOpen ? (
        <CreateWorkflowModal
          name={createName}
          projectRoot={currentProject?.rootPath || "."}
          workflowKind={createKind}
          executionMode={createMode}
          onNameChange={setCreateName}
          onWorkflowKindChange={setCreateKind}
          onExecutionModeChange={setCreateMode}
          onClose={() => setCreateOpen(false)}
          onCreate={() => {
            void handleCreateWorkflow();
          }}
        />
      ) : null}

      {nodeConfigOpen && selectedNode ? (
        <WorkflowNodeConfigModal
          node={selectedNode}
          workflow={currentProjectFile}
          dryRunResult={functionDryRunResult}
          fixtures={selectedFixtures}
          selectedNodeRun={nodeRunStatusById[selectedNode.id] ?? null}
          upstreamReferences={selectedUpstreamReferences}
          compatibleNodeHints={compatibleNodeHints}
          tests={tests}
          testResult={testResult}
          validationResult={validationResult}
          readinessResult={readinessResult}
          initialSection={nodeConfigInitialSection}
          onClose={() => setNodeConfigOpen(false)}
          onUpdate={(updates) => updateNode(selectedNode.id, updates)}
          onInspectNode={(nodeId) => {
            const nodeItem = nodes.find((node) => node.id === nodeId)
              ?.data as Node | undefined;
            handleWorkflowNodeSelect(nodeId);
            setNodeConfigInitialSection(
              workflowConfigSectionForNodeKind(nodeItem?.type ?? ""),
            );
            setNodeConfigOpen(true);
          }}
          onDryRun={() => {
            void handleDryRunFunction(selectedNode);
          }}
          onCaptureFixture={() => {
            void handleCaptureNodeFixture(selectedNode);
          }}
          onImportFixture={(rawText) => {
            void handleImportNodeFixture(selectedNode, rawText);
          }}
          onPinFixture={(fixture) => {
            void handlePinNodeFixture(selectedNode, fixture);
          }}
          onDryRunFixture={(fixture) => {
            void handleDryRunNodeFromFixture(selectedNode, fixture);
          }}
        />
      ) : null}

      {modelBindingOpen ? (
        <ModelBindingModal
          globalConfig={globalConfig}
          onClose={() => setModelBindingOpen(false)}
          onUpdate={setGlobalConfig}
        />
      ) : null}

      {connectorBindingOpen ? (
        <ConnectorBindingModal
          workflow={currentProjectFile}
          onClose={() => setConnectorBindingOpen(false)}
          onInspectNode={(nodeId) => {
            const nodeItem = nodes.find((node) => node.id === nodeId)
              ?.data as Node | undefined;
            handleWorkflowNodeSelect(nodeId);
            setNodeConfigInitialSection(
              workflowConfigSectionForNodeKind(nodeItem?.type ?? ""),
            );
            setNodeConfigOpen(true);
            setConnectorBindingOpen(false);
          }}
          onOpenNodeLibrary={() => {
            openLeftDrawer();
            setConnectorBindingOpen(false);
          }}
        />
      ) : null}

      {testEditorOpen ? (
        <TestEditorModal
          workflow={currentProjectFile}
          existingTests={tests}
          name={newTestName}
          targets={newTestTargets}
          selectedNode={selectedNode}
          onNameChange={setNewTestName}
          onTargetsChange={setNewTestTargets}
          kind={newTestKind}
          expected={newTestExpected}
          expression={newTestExpression}
          onKindChange={setNewTestKind}
          onExpectedChange={setNewTestExpected}
          onExpressionChange={setNewTestExpression}
          onClose={() => setTestEditorOpen(false)}
          onSubmit={handleAddTest}
        />
      ) : null}

      {proposalToReview ? (
        <ProposalPreviewModal
          proposal={proposalToReview}
          onClose={() => setProposalToReview(null)}
          onApply={() => handleApplyProposal(proposalToReview.id)}
        />
      ) : null}

      {deployOpen ? (
        <DeployModal
          workflow={currentProjectFile}
          validationResult={validationResult}
          readinessResult={readinessResult}
          onCheckReadiness={() => {
            void handleCheckReadiness();
          }}
          onInspectNode={(nodeId) => {
            handleWorkflowNodeSelect(nodeId);
            setRightPanel("readiness");
          }}
          onClose={() => setDeployOpen(false)}
          onDeploy={async () => {
            const readiness = readinessResult ?? (await handleCheckReadiness());
            if (readiness.status !== "passed") {
              setRightPanel("readiness");
              setStatusMessage("Activation blocked");
              return;
            }
            await handleSave();
            setDeployOpen(false);
            setStatusMessage("Activation checkpoint saved");
          }}
        />
      ) : null}

      {importPackageOpen ? (
        <ImportPackageModal
          projectRoot={currentProject?.rootPath || "."}
          packagePath={importPackagePath}
          packageName={importPackageName}
          onPackagePathChange={setImportPackagePath}
          onPackageNameChange={setImportPackageName}
          onClose={() => setImportPackageOpen(false)}
          onImport={handleImportPortablePackage}
        />
      ) : null}
    </div>
  );
}

export function WorkflowComposer(props: WorkflowComposerProps) {
  return (
    <ReactFlowProvider>
      <WorkflowComposerContent {...props} />
    </ReactFlowProvider>
  );
}
