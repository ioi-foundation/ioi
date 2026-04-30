import type { JSX } from "react";
import {
  Activity,
  CalendarClock,
  CheckCircle2,
  Database,
  FileOutput,
  FolderOpen,
  GitCompare,
  ListChecks,
  Search,
  Settings,
  type LucideIcon,
} from "lucide-react";
import type {
  WorkflowBottomPanel,
  WorkflowProject,
  WorkflowRightPanel,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import type { WorkflowNodeConfigSectionId } from "../features/Workflows/WorkflowNodeConfigTypes";
import {
  workflowNodeActionDefinitions,
  workflowNodeCreatorDefinitions,
  workflowScaffoldDefinitions,
  type WorkflowNodeCreatorDefinition,
  type WorkflowNodeDefinition,
} from "../runtime/workflow-node-registry";
import {
  SCRATCH_WORKFLOW_BLUEPRINTS,
  type ScratchWorkflowBlueprintId,
} from "../runtime/workflow-scratch-blueprints";

export const NODE_LIBRARY = workflowNodeCreatorDefinitions();
export const NODE_ACTIONS = workflowNodeActionDefinitions();
export const ACTION_BY_NODE_TYPE = new Map(
  NODE_ACTIONS.map((action) => [action.nodeType, action]),
);

export function workflowCreatorItemId(
  definition: WorkflowNodeDefinition | WorkflowNodeCreatorDefinition,
): string {
  return "creatorId" in definition ? definition.creatorId : definition.type;
}

export function workflowActionMetadataLabel(
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

export const RIGHT_PANELS: Array<{
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

export const SCAFFOLD_GROUPS: Array<WorkflowNodeDefinition["group"]> = [
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

export type WorkflowNodeGroupFilter =
  | WorkflowNodeDefinition["group"]
  | "All"
  | "Compatible";

export const NODE_GROUP_FILTERS: WorkflowNodeGroupFilter[] = [
  "All",
  "Compatible",
  ...SCAFFOLD_GROUPS,
];

export const WORKFLOW_SCAFFOLDS = workflowScaffoldDefinitions();
export const EMPTY_CANVAS_START_CREATOR_IDS = [
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

export const WORKFLOW_ISSUE_SECTION_BY_CODE: Record<
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

export const BOTTOM_TABS: Array<{ id: WorkflowBottomPanel; label: string }> = [
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

export const SCRATCH_DOGFOOD_WORKFLOW_NAME = "Scratch GUI Node Composition";
export const SCRATCH_HEAVY_BLUEPRINTS: ScratchWorkflowBlueprintId[] = [
  ...SCRATCH_WORKFLOW_BLUEPRINTS,
];
export const SCRATCH_DOGFOOD_SCRIPT =
  typeof import.meta !== "undefined"
    ? ((import.meta as unknown as { env?: Record<string, string | undefined> })
        .env?.VITE_AUTOPILOT_WORKFLOW_DOGFOOD_SCRIPT as string | undefined)
    : undefined;

export function WorkflowHeaderAction({
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

export function WorkflowInlineIcon({
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

export function workflowPatchBoundedTargets(
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

export function workflowIssueCountLabel(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

export function workflowValidationBlockingIssueCount(
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

export function workflowValidationIssueKey(
  issue: WorkflowValidationIssue,
): string {
  return `${issue.nodeId ?? "workflow"}:${issue.code}:${issue.message}`;
}

export function workflowCanvasIssuesByNodeId(
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

export function workflowValidationStatusMessage(
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

export function workflowChecksStatusMessage(
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

export function workflowConfigSectionForNodeKind(
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

export function workflowConfigSectionForIssue(
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

