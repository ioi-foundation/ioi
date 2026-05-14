import assert from "node:assert/strict";
import test from "node:test";

import type { Node, WorkflowProject } from "../types/graph";
import { makeDefaultWorkflow } from "./workflow-defaults";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "./workflow-validation";
import { createRuntimeCodingToolControlRequestFromWorkflowNode } from "./workflow-runtime-coding-tool-control-nodes";
import { createRuntimeCompactionPolicyControlRequestFromWorkflowNode } from "./workflow-runtime-compaction-policy-control-nodes";
import { createRuntimeContextBudgetControlRequestFromWorkflowNode } from "./workflow-runtime-context-budget-control-nodes";
import {
  WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_SUBFLOW_SCHEMA_VERSION,
  createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow,
} from "./workflow-runtime-telemetry-budget-chain-subflow";
import {
  bindWorkflowRuntimeTelemetrySourceToWorkflow,
  workflowRuntimeTelemetrySourceBindingIssue,
} from "./workflow-runtime-telemetry-source-binding";
import type { WorkflowRuntimeTelemetrySummary } from "./workflow-runtime-telemetry-summary";
import { createRuntimeUsageMeterControlRequestFromWorkflowNode } from "./workflow-runtime-usage-control-nodes";

function telemetrySummary(): WorkflowRuntimeTelemetrySummary {
  return {
    schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
    status: "blocked",
    sourceKinds: ["runtime_usage_events", "tui_context_rows"],
    threadIds: ["thread-template"],
    turnIds: ["turn-template"],
    workflowGraphIds: ["workflow.telemetry-budget-chain"],
    workflowNodeIds: ["runtime.usage-meter", "runtime.context-budget"],
    eventIds: ["event-usage-template", "event-context-template"],
    latestSeq: 2,
    latestCursor: "events_thread:2",
    latestEventId: "event-context-template",
    runtimeEventCount: 2,
    usageEventCount: 1,
    contextPressureEventCount: 1,
    contextPressureAlertCount: 1,
    tuiRowCount: 1,
    usageRowCount: 1,
    costRowCount: 1,
    contextRowCount: 1,
    subagentRowCount: 0,
    codingToolBudgetRowCount: 0,
    inputTokens: 1600,
    outputTokens: 900,
    totalTokens: 2500,
    costEstimateUsd: 0.0125,
    contextPressure: 0.91,
    contextPressureStatus: "blocked",
    runCount: 1,
    subagentCount: 0,
    receiptRefs: ["receipt-usage-template"],
    policyDecisionRefs: ["policy-context-template"],
  };
}

function workflowWithSubflow(nodes: Node[]): WorkflowProject {
  const workflow = makeDefaultWorkflow("Telemetry budget chain template");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.telemetry-budget-chain",
    },
    nodes,
  };
}

test("creates a reusable telemetry-governed budget chain template", () => {
  const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
    idPrefix: "telemetry-budget-chain-proof",
    workflowGraphId: "workflow.telemetry-budget-chain",
    origin: { x: 100, y: 120 },
  });

  assert.equal(
    subflow.schemaVersion,
    WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_SUBFLOW_SCHEMA_VERSION,
  );
  assert.equal(subflow.workflowGraphId, "workflow.telemetry-budget-chain");
  assert.deepEqual(
    subflow.nodes.map((node) => node.type),
    [
      "runtime_usage_meter",
      "runtime_context_budget",
      "runtime_compaction_policy",
      "plugin_tool",
    ],
  );
  assert.deepEqual(
    subflow.edges.map((edge) => [
      edge.from,
      edge.to,
      edge.fromPort,
      edge.toPort,
      edge.connectionClass,
    ]),
    [
      [
        subflow.usageMeterNodeId,
        subflow.contextBudgetNodeId,
        "runtimeUsageMeter",
        "runtimeUsageMeter",
        "data",
      ],
      [
        subflow.contextBudgetNodeId,
        subflow.compactionPolicyNodeId,
        "runtimeContextBudget",
        "runtimeContextBudget",
        "data",
      ],
      [
        subflow.compactionPolicyNodeId,
        subflow.budgetGateNodeId,
        "runtimeCompactionPolicy",
        "runtimeTelemetrySummary",
        "state",
      ],
    ],
  );
});

test("generated telemetry budget chain nodes compile into daemon requests", () => {
  const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
    idPrefix: "telemetry-budget-chain-executable",
    workflowGraphId: "workflow.telemetry-budget-chain",
    origin: { x: 100, y: 120 },
    maxTotalTokens: 3000,
    contextWarningRatio: 0.7,
    contextBlockRatio: 0.88,
  });
  const summary = telemetrySummary();
  const usageNode = subflow.nodes.find(
    (node) => node.id === subflow.usageMeterNodeId,
  )!;
  const contextNode = subflow.nodes.find(
    (node) => node.id === subflow.contextBudgetNodeId,
  )!;
  const compactionNode = subflow.nodes.find(
    (node) => node.id === subflow.compactionPolicyNodeId,
  )!;
  const codingNode = subflow.nodes.find(
    (node) => node.id === subflow.budgetGateNodeId,
  )!;

  const usageRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
    usageNode,
    { threadId: "thread-template" },
    { workflowGraphId: subflow.workflowGraphId },
  );
  assert.equal(usageRequest.threadId, "thread-template");
  assert.equal(usageRequest.metadata.workflowNodeId, subflow.usageMeterNodeId);

  const contextRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
    contextNode,
    {
      threadId: "thread-template",
      runtimeUsageMeter: {
        total_tokens: summary.totalTokens,
        estimated_cost_usd: summary.costEstimateUsd,
        context_pressure: summary.contextPressure,
      },
    },
    { workflowGraphId: subflow.workflowGraphId },
  );
  assert.equal(contextRequest.body.workflowNodeId, subflow.contextBudgetNodeId);
  assert.equal(contextRequest.body.mode, "block");
  assert.equal(contextRequest.body.thresholds.maxTotalTokens, 3000);
  assert.equal(contextRequest.body.thresholds.maxContextPressure, 0.88);
  assert.equal(contextRequest.body.thresholds.warnAtRatio, 0.7);

  const compactionRequest =
    createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
      compactionNode,
      {
        threadId: "thread-template",
        turnId: "turn-template",
        runtimeContextBudget: {
          status: "blocked",
          receiptRefs: summary.receiptRefs,
          policyDecisionRefs: summary.policyDecisionRefs,
        },
      },
      { workflowGraphId: subflow.workflowGraphId },
    );
  assert.equal(
    compactionRequest.body.workflowNodeId,
    subflow.compactionPolicyNodeId,
  );
  assert.equal(compactionRequest.body.contextBudgetStatus, "blocked");
  assert.equal(compactionRequest.body.policy.blockedAction, "compact");

  const codingRequest = createRuntimeCodingToolControlRequestFromWorkflowNode(
    codingNode,
    {
      threadId: "thread-template",
      runtimeTelemetrySummary: summary,
    },
    { workflowGraphId: subflow.workflowGraphId },
  );
  assert.equal(codingRequest.toolId, "workspace.status");
  assert.equal(codingRequest.body.workflowNodeId, subflow.budgetGateNodeId);
  assert.equal(codingRequest.body.budgetMode, "block");
  assert.equal(codingRequest.body.toolPack.coding.pack, "coding");
  assert.equal(codingRequest.body.toolPack.coding.budgetUsageField, "runtimeTelemetrySummary");
  assert.equal(
    (codingRequest.body.budgetUsageTelemetry as Record<string, unknown>)
      .total_tokens,
    2500,
  );
});

test("telemetry budget chain template is activation-ready and validates missing live bindings", () => {
  const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
    idPrefix: "telemetry-budget-chain-readiness",
    workflowGraphId: "workflow.telemetry-budget-chain",
  });
  const workflow = {
    ...workflowWithSubflow(subflow.nodes),
    edges: subflow.edges,
  };

  const readiness = evaluateWorkflowActivationReadiness(
    workflow,
    [],
    validateWorkflowProject(workflow, []),
  );
  assert.equal(
    (readiness.executionReadinessIssues ?? []).some((issue) =>
      workflowRuntimeTelemetrySourceBindingIssue(issue),
    ),
    false,
  );

  const missingUsageBindingNodes: Node[] = subflow.nodes.map((node): Node => {
    if (node.id !== subflow.contextBudgetNodeId) return node;
    if (!node.config) return node;
    return {
      ...node,
      config: {
        ...node.config,
        logic: {
          ...node.config?.logic,
          inputMapping: {
            threadId: "runtime.threadId",
          },
        },
      },
    };
  });
  const missingUsageWorkflow = {
    ...workflowWithSubflow(missingUsageBindingNodes),
    edges: subflow.edges,
  };
  const missingUsageReadiness = evaluateWorkflowActivationReadiness(
    missingUsageWorkflow,
    [],
    validateWorkflowProject(missingUsageWorkflow, []),
  );
  assert.equal(
    (missingUsageReadiness.executionReadinessIssues ?? []).some(
      (issue) =>
        issue.nodeId === subflow.contextBudgetNodeId &&
        issue.code === "missing_runtime_telemetry_source_usage_binding",
    ),
    true,
  );
});

test("telemetry budget chain template stays compatible with telemetry-source quick binding", () => {
  const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
    idPrefix: "telemetry-budget-chain-binding",
    workflowGraphId: "workflow.telemetry-budget-chain",
  });
  const workflow = {
    ...workflowWithSubflow(subflow.nodes),
    edges: subflow.edges,
  };

  const result = bindWorkflowRuntimeTelemetrySourceToWorkflow(
    workflow,
    telemetrySummary(),
  );

  assert.equal(result.status, "bound");
  assert.deepEqual(result.boundNodeIds, [
    subflow.usageMeterNodeId,
    subflow.contextBudgetNodeId,
    subflow.compactionPolicyNodeId,
    subflow.budgetGateNodeId,
  ]);

  const readiness = evaluateWorkflowActivationReadiness(
    result.workflow,
    [],
    validateWorkflowProject(result.workflow, []),
  );
  assert.equal(
    (readiness.executionReadinessIssues ?? []).some((issue) =>
      workflowRuntimeTelemetrySourceBindingIssue(issue),
    ),
    false,
  );
});
