import type {
  CreateWorkflowProposalRequest,
  GraphGlobalConfig,
  Node,
  WorkflowConnectionClass,
  WorkflowNodeRun,
  WorkflowPortDefinition,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowTestCase,
  WorkflowTestRunResult,
  WorkflowValidationResult,
} from "../types/graph";
import { connectionClassForPorts } from "./runtime-projection-adapter";
import { slugify } from "./workflow-defaults";
import {
  normalizeGraphModelBinding,
  workflowModelBindingIsReady,
} from "./workflow-model-capability-binding";
import type { WorkflowNodeDefinition } from "./workflow-node-registry";
import { workflowConfiguredFieldNames } from "./workflow-value-preview";

export interface WorkflowCanvasSearchResult {
  node: Node;
  configuredFields: string[];
  status: string;
}

export type WorkflowSelectedNodeRepairActionKind =
  | "bind_model_capability"
  | "bind_tool_capability"
  | "connect_to_agent"
  | "add_agent_step"
  | "add_output"
  | "add_evaluation"
  | "add_verifier"
  | "check_readiness";

export interface WorkflowSelectedNodeRepairAction {
  id: string;
  kind: WorkflowSelectedNodeRepairActionKind;
  label: string;
  description: string;
  priority: "primary" | "secondary";
  nodeId: string;
  searchHint?: string;
  bindingFocusKey?: string;
}

export interface WorkflowCompatibleSearchRecovery {
  query: string;
  selectedNodeId: string;
  selectedNodeName: string;
  globalMatchCount: number;
  title: string;
  message: string;
  recommendedBridgeLabel: string;
}

export interface WorkflowSelectedNodeLifecycleItem {
  label: string;
  value: string;
  status: "ready" | "blocked" | "warning" | "idle";
}

export interface WorkflowSelectedNodeLifecycleSummary {
  title: string;
  items: WorkflowSelectedNodeLifecycleItem[];
}

export function workflowCompatibleSearchRecovery({
  query,
  nodeGroupFilter,
  selectedNode,
  globalMatchCount,
  compatibleMatchCount,
}: {
  query: string;
  nodeGroupFilter: string;
  selectedNode: Node | null;
  globalMatchCount: number;
  compatibleMatchCount: number;
}): WorkflowCompatibleSearchRecovery | null {
  const normalizedQuery = query.trim();
  if (
    !selectedNode ||
    !normalizedQuery ||
    nodeGroupFilter !== "Compatible" ||
    compatibleMatchCount > 0 ||
    globalMatchCount === 0
  ) {
    return null;
  }

  return {
    query: normalizedQuery,
    selectedNodeId: selectedNode.id,
    selectedNodeName: selectedNode.name,
    globalMatchCount,
    title: `No ${normalizedQuery} primitives connect directly from ${selectedNode.name}.`,
    message:
      "Those primitives exist, but this selected node needs a bridge step or a different port path before they can attach.",
    recommendedBridgeLabel: "Add Agent Step",
  };
}

function workflowNodeHasConnection(
  workflow: WorkflowProject,
  nodeId: string,
  predicate: (node: Node) => boolean,
  direction: "incoming" | "outgoing",
): boolean {
  const targetIds = new Set(
    workflow.edges
      .filter((edge) =>
        direction === "incoming" ? edge.to === nodeId : edge.from === nodeId,
      )
      .map((edge) => (direction === "incoming" ? edge.from : edge.to)),
  );
  return workflow.nodes.some((node) => targetIds.has(node.id) && predicate(node));
}

function workflowIsAgentStepNode(node: Node): boolean {
  return node.type === "model_call";
}

function workflowIsToolCapabilityNode(node: Node): boolean {
  return node.type === "plugin_tool" || node.type === "adapter";
}

function workflowIsContextNode(node: Node): boolean {
  return (
    node.type === "repository_context" ||
    node.type === "github_context" ||
    node.type === "issue_context" ||
    node.type === "branch_policy" ||
    node.type.endsWith("_context") ||
    String(node.config?.kind ?? "").endsWith("_context")
  );
}

function workflowIsVerificationNode(node: Node): boolean {
  return (
    node.type === "review_gate" ||
    node.type === "quality_ledger" ||
    node.type === "semantic_impact" ||
    node.type === "postcondition_synthesis" ||
    node.type.endsWith("_gate") ||
    node.type.includes("verification")
  );
}

export function workflowModelBindingKeyForNode(node: Node | null): string {
  if (!node || node.type !== "model_call") return "reasoning";
  const logic = node.config?.logic ?? {};
  const rawKey = String(
    logic.modelRef ??
      logic.capability ??
      logic.modelCapabilityRef ??
      logic.routeId ??
      "reasoning",
  ).toLowerCase();
  if (rawKey.includes("vision")) return "vision";
  if (rawKey.includes("embed")) return "embedding";
  if (rawKey.includes("image")) return "image";
  return "reasoning";
}

export function workflowSelectedNodeRepairActions({
  workflow,
  selectedNode,
  validationResult,
  tests,
}: {
  workflow: WorkflowProject;
  selectedNode: Node | null;
  validationResult?: WorkflowValidationResult | null;
  tests: WorkflowTestCase[];
}): WorkflowSelectedNodeRepairAction[] {
  if (!selectedNode) return [];

  const actions: WorkflowSelectedNodeRepairAction[] = [];
  const selectedIssues = [
    ...(validationResult?.errors ?? []),
    ...(validationResult?.warnings ?? []),
  ].filter((issue) => issue.nodeId === selectedNode.id);
  const hasDirectOutput = workflowNodeHasConnection(
    workflow,
    selectedNode.id,
    (node) => node.type === "output",
    "outgoing",
  );
  const hasAnyOutput = workflow.nodes.some((node) => node.type === "output");
  const hasEvaluation = tests.some((test) =>
    test.targetNodeIds.includes(selectedNode.id),
  );
  const addAction = (
    kind: WorkflowSelectedNodeRepairActionKind,
    label: string,
    description: string,
    options: Partial<
      Pick<
        WorkflowSelectedNodeRepairAction,
        "priority" | "searchHint" | "bindingFocusKey"
      >
    > = {},
  ) => {
    if (actions.some((action) => action.kind === kind)) return;
    actions.push({
      id: `${selectedNode.id}:${kind}`,
      kind,
      label,
      description,
      priority: options.priority ?? "secondary",
      nodeId: selectedNode.id,
      searchHint: options.searchHint,
      bindingFocusKey: options.bindingFocusKey,
    });
  };

  if (workflowIsAgentStepNode(selectedNode)) {
    addAction(
      "bind_model_capability",
      "Bind model capability",
      "Choose the runtime model route and authority posture for this agent step.",
      {
        priority: "primary",
        bindingFocusKey: workflowModelBindingKeyForNode(selectedNode),
      },
    );
    if (!hasDirectOutput) {
      addAction(
        "add_output",
        "Add output",
        hasAnyOutput
          ? "Connect this agent step to an output primitive."
          : "Materialize the agent response through an output primitive.",
        { priority: "primary", searchHint: "output" },
      );
    }
    if (!hasEvaluation) {
      addAction(
        "add_evaluation",
        "Add evaluation",
        "Add a fixture or test so this step can be verified before promotion.",
        { searchHint: "evaluation" },
      );
    }
  } else if (workflowIsToolCapabilityNode(selectedNode)) {
    addAction(
      "bind_tool_capability",
      "Bind tool capability",
      "Choose the canonical tool or connector capability backing this node.",
      { priority: "primary" },
    );
    if (
      !workflowNodeHasConnection(
        workflow,
        selectedNode.id,
        workflowIsAgentStepNode,
        "outgoing",
      )
    ) {
      addAction(
        "connect_to_agent",
        "Connect to agent",
        "Attach this tool to an Agent Step before running.",
        { searchHint: "agent" },
      );
    }
    addAction(
      "add_verifier",
      "Add verifier",
      "Check tool results before they affect workflow output.",
      { searchHint: "verification" },
    );
  } else if (workflowIsContextNode(selectedNode)) {
    if (
      !workflowNodeHasConnection(
        workflow,
        selectedNode.id,
        workflowIsAgentStepNode,
        "outgoing",
      )
    ) {
      addAction(
        "connect_to_agent",
        "Connect to agent",
        "Feed this context into an Agent Step.",
        { priority: "primary", searchHint: "agent" },
      );
    }
    addAction(
      "add_agent_step",
      "Add Agent Step",
      "Create the agent that will use this context.",
      { searchHint: "model" },
    );
  } else if (selectedNode.type === "output") {
    if (!hasEvaluation) {
      addAction(
        "add_evaluation",
        "Add evaluation",
        "Verify this output contract with a fixture or test.",
        { priority: "primary", searchHint: "evaluation" },
      );
    }
  } else if (workflowIsVerificationNode(selectedNode)) {
    if (!hasDirectOutput) {
      addAction(
        "add_output",
        "Add output",
        "Route verified results into an output primitive.",
        { priority: "primary", searchHint: "output" },
      );
    }
  }

  addAction(
    "check_readiness",
    "Check readiness",
    selectedIssues.length > 0
      ? `Refresh readiness for ${selectedIssues.length} issue${selectedIssues.length === 1 ? "" : "s"} on this node.`
      : "Refresh run, authority, receipt, and manifest readiness for this workflow.",
    { priority: actions.length === 0 ? "primary" : "secondary" },
  );

  return actions.slice(0, 5);
}

export function workflowSelectedNodeLifecycleSummary({
  workflow,
  selectedNode,
  validationResult,
  tests,
}: {
  workflow: WorkflowProject;
  selectedNode: Node | null;
  validationResult?: WorkflowValidationResult | null;
  tests: WorkflowTestCase[];
}): WorkflowSelectedNodeLifecycleSummary | null {
  if (!selectedNode) return null;

  const incomingEdges = workflow.edges.filter((edge) => edge.to === selectedNode.id);
  const outgoingEdges = workflow.edges.filter((edge) => edge.from === selectedNode.id);
  const requiredInputCount = (selectedNode.ports ?? []).filter(
    (port) => port.direction === "input" && port.required,
  ).length;
  const selectedIssues = [
    ...(validationResult?.errors ?? []),
    ...(validationResult?.warnings ?? []),
  ].filter((issue) => issue.nodeId === selectedNode.id);
  const outputConnected =
    selectedNode.type === "output" ||
    outgoingEdges.some((edge) =>
      workflow.nodes.some((node) => node.id === edge.to && node.type === "output"),
    );
  const toolAttachmentCount = incomingEdges.filter(
    (edge) =>
      edge.toPort === "tool" ||
      edge.connectionClass === "tool" ||
      String(edge.data?.connectionClass ?? "") === "tool",
  ).length;
  const logic = selectedNode.config?.logic ?? {};
  const hasModelCapability = Boolean(
    logic.modelCapabilityRef || logic.routeId || logic.modelBinding,
  );
  const testCount = tests.filter((test) =>
    test.targetNodeIds.includes(selectedNode.id),
  ).length;

  const items: WorkflowSelectedNodeLifecycleItem[] = [];
  items.push({
    label: "Input",
    value:
      incomingEdges.length > 0
        ? "connected"
        : requiredInputCount > 0
          ? "missing"
          : "not required",
    status:
      incomingEdges.length > 0 || requiredInputCount === 0 ? "ready" : "blocked",
  });
  if (selectedNode.type === "model_call") {
    items.push({
      label: "Model capability",
      value: hasModelCapability ? "declared route" : "missing",
      status: hasModelCapability ? "ready" : "blocked",
    });
    items.push({
      label: "Tools",
      value: toolAttachmentCount > 0 ? `${toolAttachmentCount} attached` : "none",
      status: toolAttachmentCount > 0 ? "ready" : "idle",
    });
  }
  if (selectedNode.type === "plugin_tool" || selectedNode.type === "adapter") {
    const binding = logic.toolBinding ?? logic.connectorBinding;
    items.push({
      label: "Capability",
      value: binding ? "declared" : "missing",
      status: binding ? "ready" : "blocked",
    });
  }
  items.push({
    label: "Output",
    value: outputConnected ? "connected" : "missing",
    status: outputConnected ? "ready" : "warning",
  });
  items.push({
    label: "Receipts",
    value: logic.receiptRequired === false ? "optional" : "required",
    status: "ready",
  });
  items.push({
    label: "Tests",
    value: testCount > 0 ? `${testCount} linked` : "none",
    status: testCount > 0 ? "ready" : "warning",
  });
  items.push({
    label: "Ready",
    value:
      selectedIssues.length > 0
        ? `${selectedIssues.length} blocker${selectedIssues.length === 1 ? "" : "s"}`
        : "no node blockers",
    status: selectedIssues.length > 0 ? "blocked" : "ready",
  });

  return {
    title: "Lifecycle summary",
    items,
  };
}

export function workflowNodeCreatorBadge(
  definition: WorkflowNodeDefinition,
  globalConfig: GraphGlobalConfig,
): { label: string; status: "ready" | "needs_attention" | "sandboxed" | "approval" } {
  if (definition.type === "model_call") {
    const modelRef = String(definition.defaultLogic.modelRef ?? "reasoning");
    const binding = normalizeGraphModelBinding(modelRef, globalConfig.modelBindings?.[modelRef]);
    return workflowModelBindingIsReady(binding)
      ? { label: "Model bound", status: "ready" }
      : { label: "Needs capability", status: "needs_attention" };
  }
  if (definition.type === "adapter") {
    return { label: "Needs connector", status: "needs_attention" };
  }
  if (definition.type === "plugin_tool") {
    return { label: "Needs tool", status: "needs_attention" };
  }
  if (definition.executor.sandboxed) {
    return { label: "Sandboxed", status: "sandboxed" };
  }
  if (definition.policyProfile.requiresApproval || definition.type === "human_gate" || definition.type === "proposal") {
    return { label: "Approval path", status: "approval" };
  }
  return { label: "Ready", status: "ready" };
}

export type WorkflowNodeCreatorDefaultAddMode =
  | "configure"
  | "topology_first";

export function workflowNodeCreatorDefaultAddMode(
  definition: WorkflowNodeDefinition,
): WorkflowNodeCreatorDefaultAddMode {
  if (
    definition.type === "plugin_tool" ||
    definition.type === "adapter" ||
    definition.type === "output" ||
    definition.type === "repository_context" ||
    definition.type === "github_context" ||
    definition.type === "issue_context" ||
    definition.type === "branch_policy"
  ) {
    return "topology_first";
  }
  if (
    definition.group === "Tools" ||
    definition.group === "Connectors" ||
    definition.group === "State" ||
    definition.group === "Outputs"
  ) {
    return "topology_first";
  }
  return "configure";
}

// These helpers create UI-side projections when no runtime adapter is attached.
// They are intentionally non-canonical; daemon/Agentgres-backed substrate APIs
// own durable run, proposal, task, receipt, and quality state.
export function createSubstrateProjectionProposal(
  request: CreateWorkflowProposalRequest,
): WorkflowProposal {
  const createdAtMs = Date.now();
  const changedNodeIds = request.boundedTargets;
  return {
    id: `proposal-${createdAtMs}`,
    title: request.title,
    summary: request.summary,
    status: "open",
    createdAtMs,
    boundedTargets: request.boundedTargets,
    codeDiff: request.codeDiff,
    workflowPatch: request.workflowPatch,
    graphDiff: {
      changedNodeIds,
    },
    configDiff: {
      changedNodeIds,
      changedGlobalKeys: [],
      changedMetadataKeys: [],
    },
    sidecarDiff: {
      functionsChanged: Boolean(request.codeDiff),
      proposalsChanged: true,
      changedRoles: request.codeDiff ? ["proposal", "code"] : ["proposal"],
    },
  };
}

export function createSubstrateProjectionRunSummary(
  workflow: WorkflowProject,
  validation: WorkflowValidationResult,
): WorkflowRunSummary {
  const startedAtMs = Date.now();
  return {
    id: `workflow-run-${startedAtMs}`,
    status: validation.status === "passed" ? "passed" : validation.status,
    startedAtMs,
    finishedAtMs: Date.now(),
      nodeCount: workflow.nodes.length,
      summary:
        validation.status === "passed"
        ? "Workflow validation passed and a non-canonical substrate projection was recorded."
        : `Workflow blocked by ${validation.errors.length + validation.warnings.length} validation issue(s).`,
  };
}

export function nodeVisualStatus(status: WorkflowNodeRun["status"]): Node["status"] {
  if (status === "success") return "success";
  if (status === "running") return "running";
  if (status === "error") return "error";
  if (status === "blocked" || status === "interrupted") return "blocked";
  return "idle";
}

export function nodeFamilyCounts(nodes: any[]): Array<{ family: string; count: number }> {
  const counts = new Map<string, number>();
  nodes.forEach((node) => {
    const type = String(node?.data?.type || node?.type || "step");
    counts.set(type, (counts.get(type) ?? 0) + 1);
  });
  return Array.from(counts, ([family, count]) => ({ family, count }));
}

export function workflowCanvasSearchResults(
  nodes: any[],
  nodeRunStatusById: Record<string, WorkflowNodeRun>,
  query: string,
): WorkflowCanvasSearchResult[] {
  const normalizedQuery = query.trim().toLowerCase();
  return nodes
    .map((flowNode) => {
      const node = flowNode.data as Node;
      const configuredFields = workflowConfiguredFieldNames(node.config?.logic ?? {});
      const status = nodeRunStatusById[node.id]?.status ?? node.status ?? "idle";
      return {
        node,
        configuredFields,
        status,
        searchable: [
          node.id,
          node.name,
          node.type,
          node.family,
          node.metricLabel,
          node.metricValue,
          status,
          ...configuredFields,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase(),
      };
    })
    .filter((item) => !normalizedQuery || item.searchable.includes(normalizedQuery))
    .slice(0, 24)
    .map(({ searchable: _searchable, ...item }) => item);
}

export function nodePorts(flowNode: any, direction?: WorkflowPortDefinition["direction"]): WorkflowPortDefinition[] {
  const data = flowNode?.data as Node | undefined;
  const ports = Array.isArray(data?.ports) ? data.ports : [];
  return direction ? ports.filter((port) => port.direction === direction) : ports;
}

export function preferredCompatiblePortPair(
  sourcePorts: WorkflowPortDefinition[],
  targetPorts: WorkflowPortDefinition[],
): {
  sourcePort: WorkflowPortDefinition | null;
  targetPort: WorkflowPortDefinition | null;
  connectionClass: WorkflowConnectionClass;
} {
  const preferredSource = sourcePorts.find((port) => port.id === "output") ?? sourcePorts[0] ?? null;
  const preferredTarget =
    targetPorts.find((port) => port.id === "input" && port.connectionClass === preferredSource?.connectionClass) ??
    targetPorts.find((port) => port.connectionClass === preferredSource?.connectionClass) ??
    targetPorts.find((port) => port.id === "input") ??
    targetPorts[0] ??
    null;
  const exactSource =
    preferredTarget
      ? sourcePorts.find((port) => port.id === "output" && port.connectionClass === preferredTarget.connectionClass) ??
        sourcePorts.find((port) => port.connectionClass === preferredTarget.connectionClass) ??
        preferredSource
      : preferredSource;
  return {
    sourcePort: exactSource,
    targetPort: preferredTarget,
    connectionClass: connectionClassForPorts(exactSource, preferredTarget),
  };
}

export function compatiblePortPair(sourceNode: any, targetNode: any) {
  return preferredCompatiblePortPair(nodePorts(sourceNode, "output"), nodePorts(targetNode, "input"));
}

export function toWorkflowProject(
  nodes: any[],
  edges: any[],
  globalConfig: GraphGlobalConfig,
  previous: WorkflowProject,
): WorkflowProject {
  return {
    ...previous,
    version: previous.version || "workflow.v1",
    metadata: {
      ...previous.metadata,
      name: globalConfig.meta.name,
      slug: previous.metadata.slug || slugify(globalConfig.meta.name),
      dirty: previous.metadata.readOnly ? false : true,
      updatedAtMs: Date.now(),
    },
    nodes: nodes.map((flowNode) => {
      const data = flowNode.data as Node;
      const {
        status: _status,
        metrics: _metrics,
        attested: _attested,
        ...persistedData
      } = data;
      return {
        ...persistedData,
        id: flowNode.id,
        type: String(data.type || flowNode.type),
        x: flowNode.position?.x ?? data.x ?? 0,
        y: flowNode.position?.y ?? data.y ?? 0,
      };
    }),
    edges: edges.map((flowEdge) => {
      const connectionClass = String(flowEdge.data?.connectionClass || "data") as WorkflowConnectionClass;
      return {
        id: flowEdge.id,
        from: flowEdge.source,
        to: flowEdge.target,
        fromPort: flowEdge.sourceHandle || "output",
        toPort: flowEdge.targetHandle || "input",
        type: connectionClass === "control" ? "control" as const : "data" as const,
        connectionClass,
        data: { ...(flowEdge.data ?? {}), connectionClass },
      };
    }),
    global_config: globalConfig,
  };
}

export function createSubstrateProjectionTestResult(
  tests: WorkflowTestCase[],
  nodes: any[],
  selectedIds?: string[],
): WorkflowTestRunResult {
  const startedAtMs = Date.now();
  const nodeIds = new Set(nodes.map((node) => node.id));
  const selected = selectedIds?.length
    ? tests.filter((test) => selectedIds.includes(test.id))
    : tests;
  const results = selected.map((test) => {
    if (test.assertion.kind !== "node_exists") {
      return {
        testId: test.id,
        status: "blocked" as const,
        message: "No executable assertion runner is attached for this test kind.",
        coveredNodeIds: test.targetNodeIds,
      };
    }
    const missing = test.targetNodeIds.filter((nodeId) => !nodeIds.has(nodeId));
    return {
      testId: test.id,
      status: missing.length === 0 ? ("passed" as const) : ("failed" as const),
      message: missing.length === 0 ? "Targets are present." : `Missing targets: ${missing.join(", ")}`,
      coveredNodeIds: test.targetNodeIds,
    };
  });
  const passed = results.filter((result) => result.status === "passed").length;
  const failed = results.filter((result) => result.status === "failed").length;
  const blocked = results.filter((result) => result.status === "blocked").length;
  const skipped = selected.length === 0 ? tests.length : 0;
  return {
    runId: `local-test-${startedAtMs}`,
    status: failed > 0 ? "failed" : blocked > 0 ? "blocked" : "passed",
    startedAtMs,
    finishedAtMs: Date.now(),
    passed,
    failed,
    blocked,
    skipped,
    results,
  };
}

export function createBlockedTestResult(tests: WorkflowTestCase[], message: string): WorkflowTestRunResult {
  const startedAtMs = Date.now();
  const results = tests.map((test) => ({
    testId: test.id,
    status: "blocked" as const,
    message,
    coveredNodeIds: test.targetNodeIds,
  }));
  return {
    runId: `blocked-test-${startedAtMs}`,
    status: "blocked",
    startedAtMs,
    finishedAtMs: Date.now(),
    passed: 0,
    failed: 0,
    blocked: results.length,
    skipped: 0,
    results,
  };
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export type WorkflowRuntimeUnavailableSurface =
  | "saved_workflow_bundle"
  | "runtime_bridge"
  | "tool_catalog"
  | "connector_catalog"
  | "model_catalog";

export interface WorkflowRuntimeUnavailableCopy {
  code: string;
  title: string;
  message: string;
  repairLabel: string;
  technicalDetail: string;
}

const RUNTIME_BRIDGE_UNAVAILABLE_MESSAGE =
  "The composer could not reach the desktop/runtime bridge needed to read saved workflow bundles or live catalogs. Try saving the workflow, retrying the runtime bridge, or opening diagnostics. Offline presets are available for draft composition.";

function workflowRuntimeUnavailableSurfaceLabel(
  surface: WorkflowRuntimeUnavailableSurface,
): string {
  switch (surface) {
    case "saved_workflow_bundle":
      return "saved workflow bundle";
    case "tool_catalog":
      return "tool catalog";
    case "connector_catalog":
      return "connector catalog";
    case "model_catalog":
      return "model catalog";
    case "runtime_bridge":
    default:
      return "runtime bridge";
  }
}

export function workflowRuntimeUnavailableCopy(
  error: unknown,
  surface: WorkflowRuntimeUnavailableSurface = "runtime_bridge",
): WorkflowRuntimeUnavailableCopy {
  const detail = errorMessage(error);
  const normalizedDetail = detail.toLowerCase();
  const bridgeLike =
    normalizedDetail.includes("reading 'invoke'") ||
    normalizedDetail.includes('reading "invoke"') ||
    normalizedDetail.includes("invoke is not a function") ||
    normalizedDetail.includes("runtime bridge") ||
    normalizedDetail.includes("tauri") ||
    normalizedDetail.includes("ipc");
  const label = workflowRuntimeUnavailableSurfaceLabel(surface);
  if (bridgeLike) {
    return {
      code: "runtime_bridge_unavailable",
      title: "Runtime bridge unavailable",
      message: RUNTIME_BRIDGE_UNAVAILABLE_MESSAGE,
      repairLabel: "Open runtime diagnostics",
      technicalDetail: `${label}: ${detail}`,
    };
  }
  if (surface === "saved_workflow_bundle") {
    return {
      code: "workflow_bundle_unavailable",
      title: "Workflow bundle unavailable",
      message:
        "The saved workflow bundle could not be read. Save the workflow, retry validation, or open diagnostics if the runtime bridge is unavailable.",
      repairLabel: "Save workflow or open diagnostics",
      technicalDetail: `${label}: ${detail}`,
    };
  }
  return {
    code: `${surface}_unavailable`,
    title: `${workflowRuntimeUnavailableSurfaceLabel(surface)} unavailable`,
    message: `The ${label} could not be loaded. Continue with offline presets for draft composition, then retry when the runtime is available.`,
    repairLabel: "Retry runtime bridge",
    technicalDetail: `${label}: ${detail}`,
  };
}

export function createWorkflowRuntimeUnavailableFailure(
  surface: WorkflowRuntimeUnavailableSurface,
  error: unknown,
): WorkflowValidationResult {
  const copy = workflowRuntimeUnavailableCopy(error, surface);
  return {
    ...createWorkflowActionFailure(copy.code, copy.message),
    errors: [
      {
        code: copy.code,
        message: copy.message,
        repairLabel: copy.repairLabel,
        technicalDetail: copy.technicalDetail,
      },
    ],
  };
}

export function workflowRuntimeCatalogFallbackCopy(
  issues: WorkflowRuntimeUnavailableCopy[],
): { message: string; technicalDetail: string | null } | null {
  if (issues.length === 0) return null;
  const hasBridgeIssue = issues.some(
    (issue) => issue.code === "runtime_bridge_unavailable",
  );
  const message = hasBridgeIssue
    ? "Runtime bridge unavailable. Live capability catalogs could not be loaded; using offline presets for draft composition."
    : "Live capability catalogs could not be loaded; using offline presets for draft composition.";
  return {
    message,
    technicalDetail: issues
      .map((issue) => issue.technicalDetail)
      .filter(Boolean)
      .join("; ") || null,
  };
}

export function workflowRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function workflowFunctionDryRunView(result: WorkflowRunResult | null): {
  nodeRun: WorkflowNodeRun | null;
  status: string;
  resultPayload: unknown;
  stdout: string;
  stderr: string;
  error: string;
  sandbox: Record<string, unknown>;
} | null {
  if (!result) return null;
  const nodeRun = result.nodeRuns[0] ?? null;
  const outputRecord = workflowRecord(nodeRun?.output);
  const sandbox = workflowRecord(outputRecord.sandbox);
  return {
    nodeRun,
    status: nodeRun?.status ?? result.summary.status,
    resultPayload: "result" in outputRecord ? outputRecord.result : nodeRun?.output ?? result.summary,
    stdout: typeof outputRecord.stdout === "string" ? outputRecord.stdout : "",
    stderr: typeof outputRecord.stderr === "string" ? outputRecord.stderr : "",
    error: nodeRun?.error ?? "",
    sandbox,
  };
}

export function createWorkflowActionFailure(
  code: string,
  message: string,
): WorkflowValidationResult {
  return {
    status: "blocked",
    errors: [{ code, message }],
    warnings: [],
    blockedNodes: [],
    missingConfig: [],
    unsupportedRuntimeNodes: [],
    policyRequiredNodes: [],
    coverageByNodeId: {},
    connectorBindingIssues: [],
    executionReadinessIssues: [],
    verificationIssues: [],
  };
}
