import type { Edge, Node } from "../types/graph";
import {
  workflowNodeDefaultLaw,
  workflowNodeDefaults,
} from "./workflow-node-registry";

export const WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_SUBFLOW_SCHEMA_VERSION =
  "ioi.workflow.runtime-telemetry-budget-chain-subflow.v1";

export interface WorkflowRuntimeTelemetryBudgetChainSubflowOptions {
  idPrefix?: string;
  origin?: { x: number; y: number };
  workflowGraphId?: string | null;
  maxTotalTokens?: number;
  contextWarningRatio?: number;
  contextBlockRatio?: number;
  executeCompaction?: boolean;
}

export interface WorkflowRuntimeTelemetryBudgetChainSubflow {
  schemaVersion: typeof WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_SUBFLOW_SCHEMA_VERSION;
  workflowGraphId: string | null;
  nodes: Node[];
  edges: Edge[];
  usageMeterNodeId: string;
  contextBudgetNodeId: string;
  compactionPolicyNodeId: string;
  budgetGateNodeId: string;
}

const DEFAULT_ORIGIN = { x: 160, y: 160 };

const finiteNumber = (
  value: number | undefined,
  fallback: number
): number => (Number.isFinite(value) ? Number(value) : fallback);

const makeTemplateEdge = (
  id: string,
  from: string,
  to: string,
  fromPort: string,
  toPort: string,
  connectionClass: Edge["connectionClass"]
): Edge => ({
  id,
  from,
  to,
  fromPort,
  toPort,
  type: connectionClass === "data" ? "data" : "control",
  connectionClass,
  data: {
    createdBy: "runtime_telemetry_budget_chain_template",
    fromPort,
    toPort,
  },
});

export function createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow(
  options: WorkflowRuntimeTelemetryBudgetChainSubflowOptions = {}
): WorkflowRuntimeTelemetryBudgetChainSubflow {
  const idPrefix = options.idPrefix ?? `runtime-telemetry-budget-chain-${Date.now()}`;
  const origin = options.origin ?? DEFAULT_ORIGIN;
  const workflowGraphId = options.workflowGraphId ?? null;

  const usageMeterNodeId = `${idPrefix}-usage-meter`;
  const contextBudgetNodeId = `${idPrefix}-context-budget`;
  const compactionPolicyNodeId = `${idPrefix}-compaction-policy`;
  const budgetGateNodeId = `${idPrefix}-coding-budget-gate`;

  const maxTotalTokens = finiteNumber(options.maxTotalTokens, 4096);
  const contextWarningRatio = finiteNumber(options.contextWarningRatio, 0.75);
  const contextBlockRatio = finiteNumber(options.contextBlockRatio, 0.9);
  const executeCompaction = options.executeCompaction ?? false;

  const usageMeterNode: Node = {
    ...workflowNodeDefaults("runtime_usage_meter"),
    id: usageMeterNodeId,
    type: "runtime_usage_meter",
    name: "Usage meter",
    x: origin.x,
    y: origin.y,
    config: {
      law: workflowNodeDefaultLaw("runtime_usage_meter"),
      logic: {
        workflowNodeId: usageMeterNodeId,
        runtimeUsageMeterWorkflowNodeId: usageMeterNodeId,
        runtimeUsageMeterEndpoint: "/v1/threads/{threadId}/usage",
        runtimeUsageMeterThreadIdField: "threadId",
        runtimeUsageMeterScope: "thread",
        runtimeUsageMeterScopeField: "usageScope",
        runtimeUsageMeterField: "runtimeUsageMeter",
        runtimeUsageMeterStatusField: "runtimeUsageMeter.contextPressureStatus",
        runtimeUsageMeterSource: "react_flow_template",
        runtimeUsageMeterActor: "operator",
        inputMapping: {
          threadId: "runtime.threadId",
          usageScope: "runtime.usageScope",
        },
      },
    },
  };

  const contextBudgetNode: Node = {
    ...workflowNodeDefaults("runtime_context_budget"),
    id: contextBudgetNodeId,
    type: "runtime_context_budget",
    name: "Context budget",
    x: origin.x + 320,
    y: origin.y,
    config: {
      law: workflowNodeDefaultLaw("runtime_context_budget"),
      logic: {
        workflowNodeId: contextBudgetNodeId,
        runtimeContextBudgetWorkflowNodeId: contextBudgetNodeId,
        runtimeContextBudgetEndpoint: "/v1/threads/{threadId}/context-budget",
        runtimeContextBudgetThreadIdField: "threadId",
        runtimeContextBudgetScope: "thread",
        runtimeContextBudgetScopeField: "budgetScope",
        runtimeContextBudgetUsageField: "usage_telemetry",
        runtimeContextBudgetMode: "block",
        runtimeContextBudgetMaxTotalTokens: maxTotalTokens,
        runtimeContextBudgetMaxContextPressure: contextBlockRatio,
        runtimeContextBudgetWarnAtRatio: contextWarningRatio,
        runtimeContextBudgetField: "runtimeContextBudget",
        runtimeContextBudgetStatusField: "runtimeContextBudget.status",
        inputMapping: {
          threadId: "runtime.threadId",
          usage_telemetry: `${usageMeterNodeId}.usage_telemetry`,
        },
      },
    },
  };

  const compactionPolicyNode: Node = {
    ...workflowNodeDefaults("runtime_compaction_policy"),
    id: compactionPolicyNodeId,
    type: "runtime_compaction_policy",
    name: "Compaction policy",
    x: origin.x + 640,
    y: origin.y,
    config: {
      law: workflowNodeDefaultLaw("runtime_compaction_policy"),
      logic: {
        workflowNodeId: compactionPolicyNodeId,
        runtimeCompactionPolicyWorkflowNodeId: compactionPolicyNodeId,
        runtimeCompactionPolicyEndpoint: "/v1/threads/{threadId}/compaction-policy",
        runtimeCompactionPolicyThreadIdField: "threadId",
        runtimeCompactionPolicyTurnIdField: "turnId",
        runtimeCompactionPolicyContextBudgetField: "runtimeContextBudget",
        runtimeCompactionPolicyContextBudgetStatusField:
          "runtimeContextBudget.status",
        runtimeCompactionPolicyOkAction: "noop",
        runtimeCompactionPolicyWarnAction: "warn",
        runtimeCompactionPolicyBlockedAction: "compact",
        runtimeCompactionPolicyExecuteCompaction: executeCompaction,
        runtimeCompactionPolicyExecuteCompactionField: "executeCompaction",
        runtimeCompactionPolicyCompactWorkflowNodeId: `${compactionPolicyNodeId}.compact`,
        runtimeCompactionPolicyField: "runtimeCompactionPolicy",
        runtimeCompactionPolicyStatusField: "runtimeCompactionPolicy.status",
        inputMapping: {
          threadId: "runtime.threadId",
          turnId: "runtime.turnId",
          runtimeContextBudget: `${contextBudgetNodeId}.runtimeContextBudget`,
        },
      },
    },
  };

  const budgetGateNode: Node = {
    ...workflowNodeDefaults("plugin_tool"),
    id: budgetGateNodeId,
    type: "plugin_tool",
    name: "Coding budget gate",
    x: origin.x + 960,
    y: origin.y,
    config: {
      law: workflowNodeDefaultLaw("plugin_tool"),
      logic: {
        workflowNodeId: budgetGateNodeId,
        toolBinding: {
          toolRef: "workspace.status",
          bindingKind: "coding_tool_pack",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["workspace.status"],
          sideEffectClass: "read",
          requiresApproval: false,
          arguments: {},
          toolPack: {
            pack: "coding",
            trustProfile: "local_private",
            approvalMode: "suggest",
            nodeApprovalOverride: "inherit",
            requiresApproval: false,
            writeEnabled: false,
            dryRun: true,
            budgetMode: "block",
            budgetUsageField: "runtimeTelemetrySummary",
            maxTotalTokens,
            maxContextPressure: contextBlockRatio,
            warnAtRatio: contextWarningRatio,
          },
        },
        inputMapping: {
          threadId: "runtime.threadId",
          runtimeTelemetrySummary: "runtime.telemetrySummary",
        },
      },
    },
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_SUBFLOW_SCHEMA_VERSION,
    workflowGraphId,
    nodes: [usageMeterNode, contextBudgetNode, compactionPolicyNode, budgetGateNode],
    edges: [
      makeTemplateEdge(
        `${idPrefix}-usage-to-context`,
        usageMeterNodeId,
        contextBudgetNodeId,
        "usage_telemetry",
        "usage_telemetry",
        "data"
      ),
      makeTemplateEdge(
        `${idPrefix}-context-to-compaction`,
        contextBudgetNodeId,
        compactionPolicyNodeId,
        "runtimeContextBudget",
        "runtimeContextBudget",
        "data"
      ),
      makeTemplateEdge(
        `${idPrefix}-compaction-to-budget-gate`,
        compactionPolicyNodeId,
        budgetGateNodeId,
        "runtimeCompactionPolicy",
        "runtimeTelemetrySummary",
        "state"
      ),
    ],
    usageMeterNodeId,
    contextBudgetNodeId,
    compactionPolicyNodeId,
    budgetGateNodeId,
  };
}
