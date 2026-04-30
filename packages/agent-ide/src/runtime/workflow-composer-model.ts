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
import { connectionClassForPorts } from "./agent-execution-substrate";
import { slugify } from "./workflow-defaults";
import type { WorkflowNodeDefinition } from "./workflow-node-registry";
import { workflowConfiguredFieldNames } from "./workflow-value-preview";

export interface WorkflowCanvasSearchResult {
  node: Node;
  configuredFields: string[];
  status: string;
}

export function workflowNodeCreatorBadge(
  definition: WorkflowNodeDefinition,
  globalConfig: GraphGlobalConfig,
): { label: string; status: "ready" | "needs_attention" | "sandboxed" | "approval" } {
  if (definition.type === "model_call") {
    const modelRef = String(definition.defaultLogic.modelRef ?? "reasoning");
    return globalConfig.modelBindings?.[modelRef]?.modelId
      ? { label: "Model bound", status: "ready" }
      : { label: "Needs model", status: "needs_attention" };
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

export function createLocalProposal(
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

export function createLocalRunSummary(
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
        ? "Workflow validation passed and local run path completed."
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

export function createLocalTestResult(
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
