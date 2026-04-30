import type {
  GraphEnvironmentProfile,
  Node,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowDogfoodRun,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";

export interface WorkflowBindingSummaryItem {
  label: string;
  value: string;
  ready: boolean;
}

export interface WorkflowBindingRegistryRow {
  id: string;
  nodeItem: Node;
  bindingKind: string;
  ref: string;
  mode: "mock" | "live" | "local";
  ready: boolean;
  scope: string;
  sideEffectClass: string;
  approval: string;
}

export interface WorkflowBindingRegistrySummary {
  total: number;
  ready: number;
  mock: number;
  approval: number;
}

export interface WorkflowLifecycleState {
  id:
    | "draft"
    | "local"
    | "sandbox"
    | "scheduled"
    | "production"
    | "blocked";
  label: string;
  detail: string;
  status: "idle" | "ready" | "warning" | "blocked";
}

export interface WorkflowRailSearchResult {
  id: string;
  resultKind: "Node" | "Test" | "Output";
  title: string;
  subtitle: string;
  detail?: string;
  nodeId: string | null;
  searchable: string;
}

export interface WorkflowFileBundleItem {
  label: string;
  path: string;
  status: string;
}

export interface WorkflowRunComparison {
  baselineRunId: string;
  targetRunId: string;
  baselineStatus: string;
  targetStatus: string;
  durationDeltaMs: number | null;
  checkpointDelta: number;
  eventDelta: number;
  changedNodes: Array<{
    nodeId: string;
    nodeName: string;
    before: string;
    after: string;
    inputChanged: boolean;
    outputChanged: boolean;
    errorChanged: boolean;
  }>;
  stateChanges: Array<{
    key: string;
    change: "added" | "removed" | "changed";
  }>;
}

export interface WorkflowChildRunLineage {
  childRunId: string;
  childRunStatus: string;
  childWorkflowPath: string;
  childThreadId: string;
}

function workflowUnknownRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function workflowNodeRunChildLineage(
  nodeRun?: WorkflowRunResult["nodeRuns"][number] | null,
): WorkflowChildRunLineage | null {
  const output = workflowUnknownRecord(nodeRun?.output);
  const toolKind = String(output.toolKind ?? "");
  const childRunId = String(output.childRunId ?? "");
  const childWorkflowPath = String(output.childWorkflowPath ?? "");
  if (toolKind !== "workflow_tool" && !childRunId && !childWorkflowPath) {
    return null;
  }
  return {
    childRunId: childRunId || "not run",
    childRunStatus: String(output.childRunStatus ?? "unknown"),
    childWorkflowPath: childWorkflowPath || "not selected",
    childThreadId: String(output.childThreadId ?? "unknown"),
  };
}

export function workflowEnvironmentProfile(workflow: WorkflowProject): GraphEnvironmentProfile {
  return {
    target: workflow.global_config.environmentProfile?.target ?? "local",
    credentialScope: workflow.global_config.environmentProfile?.credentialScope ?? "local",
    mockBindingPolicy: workflow.global_config.environmentProfile?.mockBindingPolicy ?? "block",
  };
}

export function workflowBindingRegistryRows(workflow: WorkflowProject): WorkflowBindingRegistryRow[] {
  return workflow.nodes.flatMap((nodeItem) => {
    const logic = nodeItem.config?.logic ?? {};
    const rows: WorkflowBindingRegistryRow[] = [];
    if (nodeItem.type === "model_call") {
      const modelBinding = logic.modelBinding;
      if (modelBinding) {
        rows.push({
          id: `${nodeItem.id}-model`,
          nodeItem,
          bindingKind: "Model",
          ref: modelBinding.modelRef || "model",
          mode: modelBinding.mockBinding ? "mock" : "live",
          ready: modelBinding.mockBinding || modelBinding.credentialReady === true,
          scope: modelBinding.capabilityScope?.join(", ") || "reasoning",
          sideEffectClass: modelBinding.sideEffectClass ?? "none",
          approval: modelBinding.requiresApproval ? "approval required" : "not required",
        });
      } else {
        const modelRef = String(logic.modelRef ?? "reasoning");
        const globalBinding = workflow.global_config.modelBindings?.[modelRef];
        rows.push({
          id: `${nodeItem.id}-global-model`,
          nodeItem,
          bindingKind: "Model",
          ref: globalBinding?.modelId || modelRef,
          mode: globalBinding?.modelId ? "live" : "local",
          ready:
            Boolean(globalBinding?.modelId) ||
            workflow.edges.some((edge) => {
              const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
              return edge.to === nodeItem.id && (edgeClass === "model" || edge.toPort === "model");
            }),
          scope: modelRef,
          sideEffectClass: "none",
          approval: "not required",
        });
      }
    }
    if (nodeItem.type === "model_binding" && logic.modelBinding) {
      rows.push({
        id: `${nodeItem.id}-model-binding`,
        nodeItem,
        bindingKind: "Model",
        ref: logic.modelBinding.modelRef || "model",
        mode: logic.modelBinding.mockBinding ? "mock" : "live",
        ready: logic.modelBinding.mockBinding || logic.modelBinding.credentialReady === true,
        scope: logic.modelBinding.capabilityScope?.join(", ") || "reasoning",
        sideEffectClass: logic.modelBinding.sideEffectClass ?? "none",
        approval: logic.modelBinding.requiresApproval ? "approval required" : "not required",
      });
    }
    if (nodeItem.type === "adapter" && logic.connectorBinding) {
      rows.push({
        id: `${nodeItem.id}-connector`,
        nodeItem,
        bindingKind: "Connector",
        ref: logic.connectorBinding.connectorRef,
        mode: logic.connectorBinding.mockBinding ? "mock" : "live",
        ready: logic.connectorBinding.mockBinding || logic.connectorBinding.credentialReady === true,
        scope: logic.connectorBinding.capabilityScope?.join(", ") || "read",
        sideEffectClass: logic.connectorBinding.sideEffectClass ?? "read",
        approval: logic.connectorBinding.requiresApproval ? "approval required" : "not required",
      });
    }
    if (nodeItem.type === "plugin_tool" && logic.toolBinding) {
      const isWorkflowTool = logic.toolBinding.bindingKind === "workflow_tool";
      const workflowToolPath = logic.toolBinding.workflowTool?.workflowPath?.trim();
      rows.push({
        id: `${nodeItem.id}-tool`,
        nodeItem,
        bindingKind: isWorkflowTool ? "Workflow tool" : "Tool",
        ref: isWorkflowTool
          ? workflowToolPath || logic.toolBinding.toolRef
          : logic.toolBinding.toolRef,
        mode: isWorkflowTool
          ? "local"
          : logic.toolBinding.mockBinding
            ? "mock"
            : "live",
        ready:
          isWorkflowTool
            ? Boolean(workflowToolPath)
            : logic.toolBinding.mockBinding ||
              logic.toolBinding.credentialReady === true,
        scope: logic.toolBinding.capabilityScope?.join(", ") || "tool",
        sideEffectClass: logic.toolBinding.sideEffectClass ?? "none",
        approval: logic.toolBinding.requiresApproval ? "approval required" : "not required",
      });
    }
    if (nodeItem.type === "parser" && logic.parserBinding) {
      rows.push({
        id: `${nodeItem.id}-parser`,
        nodeItem,
        bindingKind: "Parser",
        ref: logic.parserBinding.parserRef,
        mode: logic.parserBinding.mockBinding ? "mock" : "local",
        ready: true,
        scope: logic.parserBinding.parserKind ?? "structured_output",
        sideEffectClass: "none",
        approval: "not required",
      });
    }
    return rows;
  });
}

export function workflowBindingRegistrySummary(
  rows: WorkflowBindingRegistryRow[],
): WorkflowBindingRegistrySummary {
  return {
    total: rows.length,
    ready: rows.filter((row) => row.ready).length,
    mock: rows.filter((row) => row.mode === "mock").length,
    approval: rows.filter((row) => row.approval === "approval required").length,
  };
}

export function workflowBindingCheckResult(
  row: WorkflowBindingRegistryRow,
  environment: GraphEnvironmentProfile = {
    target: "local",
    credentialScope: "local",
    mockBindingPolicy: "block",
  },
): WorkflowBindingCheckResult {
  const createdAtMs = Date.now();
  const base = {
    id: `binding-check-${row.id}-${createdAtMs}`,
    rowId: row.id,
    nodeId: row.nodeItem.id,
    bindingKind: row.bindingKind,
    reference: row.ref,
    mode: row.mode,
    createdAtMs,
  } satisfies Pick<
    WorkflowBindingCheckResult,
    | "id"
    | "rowId"
    | "nodeId"
    | "bindingKind"
    | "reference"
    | "mode"
    | "createdAtMs"
  >;
  if (row.mode === "mock") {
    const strictEnvironment =
      environment.target === "production" ||
      environment.mockBindingPolicy === "block";
    return {
      ...base,
      status: strictEnvironment ? "blocked" : "warning",
      summary: strictEnvironment
        ? "Mock binding blocked for activation"
        : "Mock binding available for sandbox use",
      detail: strictEnvironment
        ? "This binding is explicitly mocked. Switch to live credentials or relax the environment mock policy before activation."
        : "This check validates the explicit mock contract locally. It does not call a live external service.",
    };
  }
  if (row.mode === "live") {
    return row.ready
      ? {
          ...base,
          status: "passed",
          summary: "Live binding contract is ready",
          detail: "Credentials are marked ready in workflow config. No hidden vendor connectivity probe was run.",
        }
      : {
          ...base,
          status: "blocked",
          summary: "Live credentials are not ready",
          detail: "Mark credentials ready from the node configuration after the connector or tool is configured.",
        };
  }
  if (row.bindingKind === "Workflow tool") {
    return row.ready
      ? {
          ...base,
          status: "passed",
          summary: "Workflow tool reference is configured",
          detail: "The child workflow path is present. Execution will validate the child workflow and record lineage at run time.",
        }
      : {
          ...base,
          status: "blocked",
          summary: "Workflow tool needs a child workflow",
          detail: "Select a child workflow path before this binding can run as a tool.",
        };
  }
  return row.ready
    ? {
        ...base,
        status: "passed",
        summary: "Local binding contract is ready",
        detail: "This local binding can be validated without external credentials.",
      }
    : {
        ...base,
        status: "blocked",
        summary: "Binding is incomplete",
        detail: "Open the node configuration and complete the binding fields.",
      };
}

export function workflowRailSearchResults(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  normalizedQuery: string,
): WorkflowRailSearchResult[] {
  const outputNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "output");
  return [
    ...workflow.nodes.map((nodeItem) => {
      const logic = nodeItem.config?.logic ?? {};
      const bindingSummary = workflowSelectedNodeBindingSummary(nodeItem, logic);
      return {
        id: `node-${nodeItem.id}`,
        resultKind: "Node" as const,
        title: nodeItem.name,
        subtitle: `${nodeItem.type} · ${nodeItem.status ?? "idle"}`,
        detail: bindingSummary.map((item) => `${item.label}: ${item.value}`).join(" · "),
        nodeId: nodeItem.id,
        searchable: [
          nodeItem.id,
          nodeItem.name,
          nodeItem.type,
          nodeItem.status,
          nodeItem.metricValue,
          ...bindingSummary.flatMap((item) => [item.label, item.value]),
        ].join(" ").toLowerCase(),
      };
    }),
    ...tests.map((test) => ({
      id: `test-${test.id}`,
      resultKind: "Test" as const,
      title: test.name,
      subtitle: `${test.status ?? "idle"} · ${test.targetNodeIds.length} target${test.targetNodeIds.length === 1 ? "" : "s"}`,
      detail: test.lastMessage ?? test.assertion.kind,
      nodeId: test.targetNodeIds[0] ?? null,
      searchable: [
        test.id,
        test.name,
        test.status,
        test.lastMessage,
        test.assertion.kind,
        ...test.targetNodeIds,
      ].join(" ").toLowerCase(),
    })),
    ...outputNodes.map((nodeItem) => ({
      id: `output-${nodeItem.id}`,
      resultKind: "Output" as const,
      title: nodeItem.name,
      subtitle: String(nodeItem.config?.logic?.format ?? "output"),
      detail: String(nodeItem.config?.logic?.deliveryTarget?.targetKind ?? "no delivery"),
      nodeId: nodeItem.id,
      searchable: [
        nodeItem.id,
        nodeItem.name,
        nodeItem.config?.logic?.format,
        nodeItem.config?.logic?.deliveryTarget?.targetKind,
      ].join(" ").toLowerCase(),
    })),
  ].filter((item) => normalizedQuery.length === 0 || item.searchable.includes(normalizedQuery));
}

export function workflowFileBundleItems(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  proposals: WorkflowProposal[],
  runs: WorkflowRunSummary[],
  portablePackage: WorkflowPortablePackage | null,
  bindingManifest: WorkflowBindingManifest | null = null,
): WorkflowFileBundleItem[] {
  return [
    {
      label: "Workflow graph",
      path: workflow.metadata.gitLocation || `.agents/workflows/${workflow.metadata.slug}.workflow.json`,
      status: workflow.metadata.dirty ? "modified" : "saved",
    },
    {
      label: "Tests sidecar",
      path: `.agents/workflows/${workflow.metadata.slug}.tests.json`,
      status: `${tests.length} test${tests.length === 1 ? "" : "s"}`,
    },
    {
      label: "Proposal sidecar",
      path: `.agents/workflows/${workflow.metadata.slug}.proposals/`,
      status: `${proposals.length} proposal${proposals.length === 1 ? "" : "s"}`,
    },
    {
      label: "Run sidecar",
      path: `.agents/workflows/${workflow.metadata.slug}.runs/`,
      status: `${runs.length} run${runs.length === 1 ? "" : "s"}`,
    },
    {
      label: "Binding manifest",
      path: `.agents/workflows/${workflow.metadata.slug}.bindings.json`,
      status: bindingManifest
        ? `${bindingManifest.summary.ready}/${bindingManifest.summary.total} ready`
        : "not generated",
    },
    {
      label: "Portable package",
      path: portablePackage?.packagePath ?? `.agents/workflows/${workflow.metadata.slug}.portable/`,
      status: portablePackage
        ? portablePackage.manifest.portable
          ? "portable"
          : `blocked: ${portablePackage.manifest.readinessStatus}`
        : "not exported",
    },
  ];
}

export function workflowTimeLabel(value?: number): string {
  return value ? new Date(value).toLocaleTimeString() : "pending";
}

export function workflowDurationLabel(startedAtMs?: number, finishedAtMs?: number): string {
  if (!startedAtMs || !finishedAtMs) return "running";
  const elapsed = Math.max(0, finishedAtMs - startedAtMs);
  if (elapsed < 1000) return `${elapsed} ms`;
  return `${(elapsed / 1000).toFixed(elapsed < 10_000 ? 1 : 0)} s`;
}

export function workflowEventLabel(event: WorkflowStreamEvent): string {
  switch (event.kind) {
    case "run_started":
      return "Run started";
    case "node_started":
      return "Node started";
    case "node_succeeded":
      return "Node finished";
    case "node_failed":
      return "Node failed";
    case "node_blocked":
      return "Node blocked";
    case "node_interrupted":
      return "Waiting for approval";
    case "state_updated":
      return "State updated";
    case "output_created":
      return "Output created";
    case "asset_materialized":
      return "Asset materialized";
    case "test_result":
      return "Test result";
    case "child_run_completed":
      return "Child run completed";
    case "run_completed":
      return "Run completed";
    default:
      return String(event.kind).replace(/_/g, " ");
  }
}

export function workflowNodeName(workflow: WorkflowProject, nodeId?: string): string {
  if (!nodeId) return "Workflow";
  return workflow.nodes.find((node) => node.id === nodeId)?.name ?? nodeId;
}

const WORKFLOW_ISSUE_TITLES: Record<string, string> = {
  missing_model_binding: "Model binding missing",
  missing_model_tool_attachment: "Tool attachment missing",
  missing_model_parser_attachment: "Parser attachment missing",
  missing_model_memory_attachment: "Memory attachment missing",
  missing_model_output_schema: "Structured output schema missing",
  missing_model_binding_result_schema: "Model result schema missing",
  missing_parser_binding: "Parser binding missing",
  missing_parser_result_schema: "Parser result schema missing",
  missing_function_binding: "Function binding missing",
  missing_output_schema: "Output schema missing",
  missing_connector_binding: "Connector binding missing",
  missing_live_connector_credential: "Connector credential missing",
  missing_tool_binding: "Tool binding missing",
  missing_live_tool_credential: "Tool credential missing",
  missing_workflow_tool_ref: "Workflow tool target missing",
  missing_workflow_tool_argument_schema: "Workflow tool input schema missing",
  missing_workflow_tool_result_schema: "Workflow tool output schema missing",
  missing_trigger_schedule: "Schedule missing",
  missing_trigger_event_source: "Event source missing",
  missing_state_key: "State key missing",
  missing_subgraph_ref: "Subgraph target missing",
  missing_proposal_bounds: "Proposal bounds missing",
  missing_start_node: "Start node missing",
  missing_output_node: "Output node missing",
  missing_unit_tests: "Unit tests missing",
  missing_error_handling_path: "Error handling path missing",
  missing_ai_evaluation_coverage: "AI evaluation coverage missing",
  missing_replay_fixture: "Replay fixture missing",
  missing_scheduled_trigger: "Scheduled trigger missing",
  missing_event_trigger: "Event trigger missing",
  mock_binding_active: "Mock binding active",
};

function titleCaseIssueCode(code: string): string {
  return code
    .split("_")
    .filter(Boolean)
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function workflowIssueTitle(issue: Pick<WorkflowValidationIssue, "code">): string {
  return WORKFLOW_ISSUE_TITLES[issue.code] ?? titleCaseIssueCode(issue.code);
}

export function workflowIssueActionLabel(
  issue: Pick<
    WorkflowValidationIssue,
    "code" | "nodeId" | "repairLabel"
  >,
): string {
  if (issue.repairLabel) return issue.repairLabel;
  if (issue.nodeId) return "Open configuration";
  if (issue.code === "missing_output_node") return "Add an output node";
  if (issue.code === "missing_start_node") return "Add a start or source node";
  if (issue.code === "missing_unit_tests") return "Add a unit test";
  if (issue.code === "missing_error_handling_path") return "Add an error or retry path";
  if (issue.code === "mock_binding_active") return "Review binding mode";
  return "Review workflow settings";
}

export function workflowReadinessStatusLabel(
  result: WorkflowValidationResult | null,
): string {
  if (!result) return "not run";
  if (result.status === "passed" && result.warnings.length > 0) {
    return "passed with warnings";
  }
  return result.status;
}

export function workflowLifecycleState(
  workflow: WorkflowProject,
  readinessResult: WorkflowValidationResult | null,
  validationResult: WorkflowValidationResult | null = null,
): WorkflowLifecycleState {
  const result = readinessResult ?? validationResult;
  const environment = workflowEnvironmentProfile(workflow);
  const hasStart = workflow.nodes.some(
    (nodeItem) => nodeItem.type === "trigger" || nodeItem.type === "source",
  );
  const hasOutput = workflow.nodes.some((nodeItem) => nodeItem.type === "output");
  const hasScheduledTrigger = workflow.nodes.some(
    (nodeItem) =>
      nodeItem.type === "trigger" &&
      nodeItem.config?.logic?.triggerKind === "scheduled",
  );

  if (result?.status === "blocked" || result?.status === "failed") {
    return {
      id: "blocked",
      label: "Blocked",
      detail: "Repair readiness blockers before activation.",
      status: "blocked",
    };
  }

  if (!hasStart || !hasOutput) {
    return {
      id: "draft",
      label: "Draft",
      detail: "Add a start and output to make this workflow runnable.",
      status: "idle",
    };
  }

  if (!result) {
    return {
      id: "local",
      label: "Runnable locally",
      detail: "Validate readiness before scheduling or production activation.",
      status: "warning",
    };
  }

  if (result.warnings.length > 0) {
    return {
      id: "sandbox",
      label: "Ready for sandbox",
      detail: "Warnings remain for production use.",
      status: "warning",
    };
  }

  if (environment.target === "production") {
    return {
      id: "production",
      label: "Ready for production",
      detail: "Readiness passed for the selected production profile.",
      status: "ready",
    };
  }

  if (hasScheduledTrigger) {
    return {
      id: "scheduled",
      label: "Ready for scheduled",
      detail: "Scheduled trigger and output are configured.",
      status: "ready",
    };
  }

  if (environment.target === "sandbox" || environment.mockBindingPolicy !== "block") {
    return {
      id: "sandbox",
      label: "Ready for sandbox",
      detail: "Readiness passed for sandbox execution.",
      status: "ready",
    };
  }

  return {
    id: "local",
    label: "Runnable locally",
    detail: "Ready for a local run.",
    status: "ready",
  };
}

export function workflowWorkbenchCheckTitle(
  status: WorkflowDogfoodRun["status"],
): string {
  return `Run checks ${status}`;
}

export function workflowWorkbenchCheckSummary(count: number): string {
  return `${count} workflow${count === 1 ? "" : "s"} checked through the workbench.`;
}

export function compareRunRecords(
  workflow: WorkflowProject,
  target: WorkflowRunResult,
  baseline: WorkflowRunResult,
): WorkflowRunComparison {
  const targetDuration = workflowRunDurationMs(target.summary);
  const baselineDuration = workflowRunDurationMs(baseline.summary);
  const baselineNodes = new Map(baseline.nodeRuns.map((run) => [run.nodeId, run]));
  const targetNodes = new Map(target.nodeRuns.map((run) => [run.nodeId, run]));
  const nodeIds = Array.from(new Set([...baselineNodes.keys(), ...targetNodes.keys()]));
  const changedNodes = nodeIds
    .map((nodeId) => {
      const before = baselineNodes.get(nodeId);
      const after = targetNodes.get(nodeId);
      const inputChanged = workflowValueFingerprint(before?.input) !== workflowValueFingerprint(after?.input);
      const outputChanged = workflowValueFingerprint(before?.output) !== workflowValueFingerprint(after?.output);
      const errorChanged = (before?.error ?? "") !== (after?.error ?? "");
      const statusChanged = (before?.status ?? "not run") !== (after?.status ?? "not run");
      if (!inputChanged && !outputChanged && !errorChanged && !statusChanged) return null;
      return {
        nodeId,
        nodeName: workflowNodeName(workflow, nodeId),
        before: before?.status ?? "not run",
        after: after?.status ?? "not run",
        inputChanged,
        outputChanged,
        errorChanged,
      };
    })
    .filter((item): item is WorkflowRunComparison["changedNodes"][number] => Boolean(item));
  const baselineState = baseline.finalState.values ?? {};
  const targetState = target.finalState.values ?? {};
  const stateKeys = Array.from(new Set([...Object.keys(baselineState), ...Object.keys(targetState)]));
  const stateChanges = stateKeys
    .map((key) => {
      if (!(key in baselineState)) return { key, change: "added" as const };
      if (!(key in targetState)) return { key, change: "removed" as const };
      return workflowValueFingerprint(baselineState[key]) === workflowValueFingerprint(targetState[key])
        ? null
        : { key, change: "changed" as const };
    })
    .filter((item): item is WorkflowRunComparison["stateChanges"][number] => Boolean(item));
  return {
    baselineRunId: baseline.summary.id,
    targetRunId: target.summary.id,
    baselineStatus: baseline.summary.status,
    targetStatus: target.summary.status,
    durationDeltaMs:
      targetDuration === null || baselineDuration === null
        ? null
        : targetDuration - baselineDuration,
    checkpointDelta: target.checkpoints.length - baseline.checkpoints.length,
    eventDelta: target.events.length - baseline.events.length,
    changedNodes,
    stateChanges,
  };
}

export function workflowSelectedNodeBindingSummary(
  node: Node,
  logic: Record<string, any>,
): WorkflowBindingSummaryItem[] {
  if (node.type === "model_call") {
    return [{ label: "Model", value: String(logic.modelRef || "not selected"), ready: Boolean(logic.modelRef) }];
  }
  if (node.type === "model_binding") {
    const binding = logic.modelBinding ?? {};
    return [
      { label: "Model", value: String(binding.modelRef || logic.modelRef || "not selected"), ready: Boolean(binding.modelRef || logic.modelRef) },
      { label: "Mode", value: binding.mockBinding === true ? "mock" : "live", ready: typeof binding.mockBinding === "boolean" },
      { label: "Result schema", value: binding.resultSchema || logic.outputSchema ? "configured" : "missing", ready: Boolean(binding.resultSchema || logic.outputSchema) },
    ];
  }
  if (node.type === "parser") {
    const binding = logic.parserBinding ?? {};
    return [
      { label: "Parser", value: String(binding.parserRef || logic.parserRef || "not selected"), ready: Boolean(binding.parserRef || logic.parserRef) },
      { label: "Kind", value: String(binding.parserKind || "json_schema"), ready: true },
      { label: "Result schema", value: binding.resultSchema || logic.outputSchema ? "configured" : "missing", ready: Boolean(binding.resultSchema || logic.outputSchema) },
    ];
  }
  if (node.type === "adapter") {
    const binding = logic.connectorBinding ?? {};
    return [
      { label: "Connector", value: String(binding.connectorRef || "not selected"), ready: Boolean(binding.connectorRef) },
      { label: "Mode", value: binding.mockBinding === true ? "mock" : "live", ready: typeof binding.mockBinding === "boolean" },
      { label: "Credentials", value: binding.mockBinding === true ? "mock" : binding.credentialReady ? "ready" : "missing", ready: binding.mockBinding === true || binding.credentialReady === true },
    ];
  }
  if (node.type === "plugin_tool") {
    const binding = logic.toolBinding ?? {};
    return [
      { label: "Tool", value: String(binding.toolRef || "not selected"), ready: Boolean(binding.toolRef) },
      { label: "Mode", value: binding.mockBinding === true ? "mock" : "live", ready: typeof binding.mockBinding === "boolean" },
      { label: "Credentials", value: binding.bindingKind === "workflow_tool" ? "local" : binding.mockBinding === true ? "mock" : binding.credentialReady ? "ready" : "missing", ready: binding.bindingKind === "workflow_tool" || binding.mockBinding === true || binding.credentialReady === true },
    ];
  }
  if (node.type === "function") {
    const binding = logic.functionBinding ?? {};
    return [
      { label: "Runtime", value: String(binding.language ?? logic.language ?? "javascript"), ready: true },
      { label: "Output schema", value: binding.outputSchema || logic.outputSchema ? "configured" : "missing", ready: Boolean(binding.outputSchema || logic.outputSchema) },
    ];
  }
  if (node.type === "trigger") {
    return [{ label: "Trigger", value: String(logic.triggerKind ?? "manual"), ready: true }];
  }
  if (node.type === "state") {
    return [{ label: "State key", value: String(logic.stateKey || "not set"), ready: Boolean(logic.stateKey) }];
  }
  if (node.type === "subgraph") {
    return [{ label: "Workflow", value: String(logic.subgraphRef?.workflowPath || "not selected"), ready: Boolean(logic.subgraphRef?.workflowPath) }];
  }
  if (node.type === "output") {
    const targetKind = logic.deliveryTarget?.targetKind ?? "none";
    return [
      { label: "Format", value: String(logic.format ?? "markdown"), ready: Boolean(logic.format) },
      { label: "Delivery", value: String(targetKind), ready: true },
    ];
  }
  if (node.type === "proposal") {
    const targetCount = logic.proposalAction?.boundedTargets?.length ?? 0;
    return [{ label: "Bounds", value: `${targetCount} target${targetCount === 1 ? "" : "s"}`, ready: targetCount > 0 }];
  }
  return [{ label: "Configuration", value: "basic settings", ready: true }];
}

function workflowRunDurationMs(run?: WorkflowRunSummary): number | null {
  if (!run?.startedAtMs || !run.finishedAtMs) return null;
  return Math.max(0, run.finishedAtMs - run.startedAtMs);
}

function workflowValueFingerprint(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? null);
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash * 31 + text.charCodeAt(index)) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}
