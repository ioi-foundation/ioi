import type { Edge, Node, NodeLogic } from "../types/graph";
import {
  workflowNodeDefaultLaw,
  workflowNodeDefaults,
} from "./workflow-node-registry";

export const WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION =
  "ioi.workflow.runtime-terminal-coding-loop-subflow.v1" as const;

export type WorkflowRuntimeTerminalCodingLoopStepId =
  | "workspace_status"
  | "git_diff"
  | "file_inspect"
  | "file_apply_patch_dry_run"
  | "file_apply_patch"
  | "test_run"
  | "lsp_diagnostics"
  | "artifact_read"
  | "tool_retrieve_result";

interface TerminalCodingLoopStepDefinition {
  stepId: WorkflowRuntimeTerminalCodingLoopStepId;
  nodeSuffix: string;
  label: string;
  command: string;
  toolId: string;
  capabilityScope: string[];
  sideEffectClass: "read" | "write";
  requiresApproval: boolean;
  arguments: Record<string, unknown>;
  toolPack: Record<string, unknown>;
}

type TerminalCodingLoopApprovalMode =
  | "suggest"
  | "auto_local"
  | "never_prompt"
  | "human_required"
  | "policy_required";

export interface WorkflowRuntimeTerminalCodingLoopSubflowOptions {
  idPrefix?: string;
  origin?: { x: number; y: number };
  workflowGraphId?: string | null;
  horizontalSpacing?: number;
  verticalSpacing?: number;
  allowedPaths?: string[];
  maxTotalTokens?: number;
  contextWarningRatio?: number;
  contextBlockRatio?: number;
  approvalMode?: TerminalCodingLoopApprovalMode;
  trustProfile?: string;
  nodeApprovalOverride?: string;
}

export interface WorkflowRuntimeTerminalCodingLoopSubflow {
  schemaVersion: typeof WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION;
  workflowGraphId: string | null;
  nodeIds: string[];
  stepNodeIds: Record<WorkflowRuntimeTerminalCodingLoopStepId, string>;
  nodes: Node[];
  edges: Edge[];
}

const DEFAULT_ORIGIN = { x: 160, y: 160 };

export const WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS: readonly TerminalCodingLoopStepDefinition[] =
  [
    {
      stepId: "workspace_status",
      nodeSuffix: "workspace-status",
      label: "Workspace status",
      command: "status",
      toolId: "workspace.status",
      capabilityScope: ["workspace.status"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {},
      toolPack: {
        workspaceStatusEnabled: true,
        gitEnabled: true,
      },
    },
    {
      stepId: "git_diff",
      nodeSuffix: "git-diff",
      label: "Git diff",
      command: "diff",
      toolId: "git.diff",
      capabilityScope: ["git.diff"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        path: "README.md",
        maxBytes: 32768,
      },
      toolPack: {
        gitEnabled: true,
      },
    },
    {
      stepId: "file_inspect",
      nodeSuffix: "file-inspect",
      label: "File inspect",
      command: "inspect",
      toolId: "file.inspect",
      capabilityScope: ["file.inspect"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        path: "README.md",
        previewLines: 120,
      },
      toolPack: {
        filesystemEnabled: true,
      },
    },
    {
      stepId: "file_apply_patch_dry_run",
      nodeSuffix: "patch-dry-run",
      label: "Patch dry run",
      command: "patch-dry-run",
      toolId: "file.apply_patch",
      capabilityScope: ["file.apply_patch"],
      sideEffectClass: "write",
      requiresApproval: false,
      arguments: {
        path: "README.md",
        oldText: "replace me",
        newText: "preview replacement",
        dryRun: true,
        diagnosticsMode: "advisory",
        diagnosticCommandId: "auto",
      },
      toolPack: {
        filesystemEnabled: true,
        writeEnabled: true,
        dryRun: true,
        diagnosticsEnabled: true,
      },
    },
    {
      stepId: "file_apply_patch",
      nodeSuffix: "apply-patch",
      label: "Apply patch",
      command: "patch",
      toolId: "file.apply_patch",
      capabilityScope: ["file.apply_patch"],
      sideEffectClass: "write",
      requiresApproval: true,
      arguments: {
        path: "README.md",
        oldText: "replace me",
        newText: "applied replacement",
        dryRun: false,
        diagnosticsMode: "blocking",
        diagnosticCommandId: "auto",
      },
      toolPack: {
        filesystemEnabled: true,
        writeEnabled: true,
        dryRun: false,
        diagnosticsEnabled: true,
      },
    },
    {
      stepId: "test_run",
      nodeSuffix: "test-run",
      label: "Run tests",
      command: "test",
      toolId: "test.run",
      capabilityScope: ["test.run"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        commandId: "node.test",
        path: "README.md",
        timeoutMs: 60000,
      },
      toolPack: {
        testEnabled: true,
      },
    },
    {
      stepId: "lsp_diagnostics",
      nodeSuffix: "lsp-diagnostics",
      label: "LSP diagnostics",
      command: "diagnostics",
      toolId: "lsp.diagnostics",
      capabilityScope: ["lsp.diagnostics"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        commandId: "auto",
        path: "README.md",
        timeoutMs: 30000,
      },
      toolPack: {
        diagnosticsEnabled: true,
      },
    },
    {
      stepId: "artifact_read",
      nodeSuffix: "artifact-read",
      label: "Read artifact",
      command: "artifact",
      toolId: "artifact.read",
      capabilityScope: ["artifact.read"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        artifactId: "{artifactId}",
        maxBytes: 32768,
      },
      toolPack: {
        artifactEnabled: true,
        resultRetrievalEnabled: true,
      },
    },
    {
      stepId: "tool_retrieve_result",
      nodeSuffix: "retrieve-result",
      label: "Retrieve result",
      command: "retrieve",
      toolId: "tool.retrieve_result",
      capabilityScope: ["tool.retrieve_result", "artifact.read"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        toolCallId: "{toolCallId}",
        maxBytes: 32768,
      },
      toolPack: {
        artifactEnabled: true,
        resultRetrievalEnabled: true,
      },
    },
  ];

export function createWorkflowRuntimeTerminalCodingLoopTemplateSubflow(
  options: WorkflowRuntimeTerminalCodingLoopSubflowOptions = {},
): WorkflowRuntimeTerminalCodingLoopSubflow {
  const idPrefix = cleanId(options.idPrefix) ??
    `runtime-terminal-coding-loop-${Date.now()}`;
  const origin = options.origin ?? DEFAULT_ORIGIN;
  const workflowGraphId = options.workflowGraphId ?? null;
  const horizontalSpacing = finiteNumber(options.horizontalSpacing, 300);
  const verticalSpacing = finiteNumber(options.verticalSpacing, 150);
  const stepNodeIds = Object.fromEntries(
    WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.map((step) => [
      step.stepId,
      `${idPrefix}-${step.nodeSuffix}`,
    ]),
  ) as Record<WorkflowRuntimeTerminalCodingLoopStepId, string>;
  const nodes = WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.map(
    (step, index) =>
      terminalCodingToolNode(step, {
        id: stepNodeIds[step.stepId],
        x: origin.x + (index % 3) * horizontalSpacing,
        y: origin.y + Math.floor(index / 3) * verticalSpacing,
        workflowGraphId,
        allowedPaths: options.allowedPaths ?? [],
        maxTotalTokens: finiteNumber(options.maxTotalTokens, 4096),
        contextWarningRatio: finiteNumber(options.contextWarningRatio, 0.75),
        contextBlockRatio: finiteNumber(options.contextBlockRatio, 0.9),
        approvalMode: options.approvalMode ?? "human_required",
        trustProfile: options.trustProfile ?? "local_private",
        nodeApprovalOverride: options.nodeApprovalOverride ?? "inherit",
      }),
  );
  const nodeIds = nodes.map((node) => node.id);

  return {
    schemaVersion: WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION,
    workflowGraphId,
    nodeIds,
    stepNodeIds,
    nodes,
    edges: nodeIds.slice(1).map((nodeId, index) =>
      terminalCodingLoopEdge(
        `${idPrefix}-edge-${index + 1}`,
        nodeIds[index]!,
        nodeId,
      ),
    ),
  };
}

function terminalCodingToolNode(
  step: TerminalCodingLoopStepDefinition,
  params: {
    id: string;
    x: number;
    y: number;
    workflowGraphId: string | null;
    allowedPaths: string[];
    maxTotalTokens: number;
    contextWarningRatio: number;
    contextBlockRatio: number;
    approvalMode: TerminalCodingLoopApprovalMode;
    trustProfile: string;
    nodeApprovalOverride: string;
  },
): Node {
  const writeStep = step.sideEffectClass === "write";
  const requiresApproval = step.requiresApproval;
  const logic: NodeLogic = {
    workflowNodeId: params.id,
    runtimeTerminalCodingLoopSchemaVersion:
      WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION,
    runtimeTerminalCodingLoopWorkflowNodeId: params.id,
    runtimeTerminalCodingLoopWorkflowGraphId: params.workflowGraphId,
    runtimeTerminalCodingLoopStepId: step.stepId,
    runtimeTerminalCodingLoopCommand: step.command,
    runtimeTerminalCodingLoopThreadIdField: "threadId",
    runtimeTerminalCodingLoopTurnIdField: "turnId",
    runtimeTerminalCodingLoopCursorField: "cursor",
    runtimeTerminalCodingLoopLastEventIdField: "lastEventId",
    runtimeTerminalCodingLoopToolCallIdField: "toolCallId",
    runtimeTerminalCodingLoopArtifactIdField: "artifactId",
    runtimeTerminalCodingLoopSource: "react_flow_template",
    runtimeTerminalCodingLoopActor: "operator",
    runtimeTerminalCodingLoopTuiReopen: {
      schemaVersion: "ioi.workflow.runtime-terminal-coding-loop-tui-reopen.v1",
      command: "ioi agent tui",
      args: ["agent", "tui", "--thread-id", "{threadId}", "--interactive"],
      reopenCommand: "ioi agent tui --thread-id {threadId} --interactive",
      threadIdField: "threadId",
      turnIdField: "turnId",
      sinceSeqField: "sequence",
      lastEventIdField: "lastEventId",
      cursorField: "cursor",
      rowKind: "coding_tool",
    },
    toolBinding: {
      toolRef: step.toolId,
      bindingKind: "coding_tool_pack",
      mockBinding: false,
      credentialReady: true,
      capabilityScope: step.capabilityScope,
      sideEffectClass: step.sideEffectClass,
      requiresApproval,
      arguments: step.arguments,
      toolPack: {
        pack: "coding",
        trustProfile: params.trustProfile,
        approvalMode: requiresApproval ? params.approvalMode : "suggest",
        nodeApprovalOverride: requiresApproval
          ? "require_approval"
          : params.nodeApprovalOverride,
        requiresApproval,
        allowedPaths: params.allowedPaths,
        allowedTestCommandIds: ["node.test", "npm.test", "cargo.test", "cargo.check"],
        allowedDiagnosticCommandIds: ["auto", "node.check", "typescript.check"],
        diagnosticsMode: writeStep ? "blocking" : "advisory",
        defaultDiagnosticCommandId: "auto",
        restorePolicy: "apply_with_approval",
        restoreConflictPolicy: "block",
        diagnosticsRepairDefault: "repair_retry",
        operatorOverrideRequiresApproval: true,
        timeoutMs: writeStep ? 60000 : 30000,
        dryRun:
          step.stepId === "file_apply_patch_dry_run"
            ? true
            : step.stepId === "file_apply_patch"
              ? false
              : undefined,
        budgetMode: "block",
        budgetUsageField: "runtimeTelemetrySummary",
        maxTotalTokens: params.maxTotalTokens,
        maxContextPressure: params.contextBlockRatio,
        warnAtRatio: params.contextWarningRatio,
        ...step.toolPack,
      },
    },
    inputMapping: {
      threadId: "runtime.threadId",
      turnId: "runtime.turnId",
      cursor: "runtime.cursor",
      lastEventId: "runtime.lastEventId",
      toolCallId: "runtime.toolCallId",
      artifactId: "runtime.artifactId",
      runtimeTelemetrySummary: "runtime.telemetrySummary",
    },
  };
  return {
    ...workflowNodeDefaults("plugin_tool"),
    id: params.id,
    type: "plugin_tool",
    name: step.label,
    x: params.x,
    y: params.y,
    config: {
      kind: "plugin_tool",
      logic,
      law: workflowNodeDefaultLaw("plugin_tool"),
    },
  };
}

function terminalCodingLoopEdge(id: string, from: string, to: string): Edge {
  return {
    id,
    from,
    to,
    fromPort: "output",
    toPort: "input",
    type: "control",
    connectionClass: "state",
    data: {
      createdBy: "runtime_terminal_coding_loop_template",
      status: "idle",
      active: false,
      fromPort: "output",
      toPort: "input",
    },
  };
}

function finiteNumber(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) ? Number(value) : fallback;
}

function cleanId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
