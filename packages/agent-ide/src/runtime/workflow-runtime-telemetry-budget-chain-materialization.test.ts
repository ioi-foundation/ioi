import assert from "node:assert/strict";
import test from "node:test";

import type { Node, WorkflowProject } from "../types/graph";
import { makeDefaultWorkflow } from "./workflow-defaults";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "./workflow-validation";
import { createRuntimeCodingToolControlRequestFromWorkflowNode } from "./workflow-runtime-coding-tool-control-nodes";
import {
  createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow,
} from "./workflow-runtime-telemetry-budget-chain-subflow";
import {
  WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_MATERIALIZATION_SCHEMA_VERSION,
  materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry,
  workflowRuntimeTelemetryBudgetChainIdsFromWorkflow,
} from "./workflow-runtime-telemetry-budget-chain-materialization";
import {
  workflowRuntimeTelemetrySourceBindingIssue,
} from "./workflow-runtime-telemetry-source-binding";
import type { WorkflowRuntimeTelemetrySummary } from "./workflow-runtime-telemetry-summary";

function telemetrySummary(): WorkflowRuntimeTelemetrySummary {
  return {
    schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
    status: "blocked",
    sourceKinds: ["runtime_usage_events", "tui_context_rows"],
    threadIds: ["thread-run-inspector"],
    turnIds: ["turn-run-inspector"],
    workflowGraphIds: ["workflow.run-inspector-telemetry"],
    workflowNodeIds: ["runtime.usage-meter", "runtime.context-budget"],
    eventIds: ["event-usage-run-inspector", "event-context-run-inspector"],
    latestSeq: 4,
    latestCursor: "events_thread-run-inspector:4",
    latestEventId: "event-context-run-inspector",
    runtimeEventCount: 4,
    usageEventCount: 1,
    contextPressureEventCount: 1,
    contextPressureAlertCount: 1,
    tuiRowCount: 1,
    usageRowCount: 1,
    costRowCount: 1,
    contextRowCount: 1,
    subagentRowCount: 0,
    codingToolBudgetRowCount: 0,
    inputTokens: 2200,
    outputTokens: 1300,
    totalTokens: 3500,
    costEstimateUsd: 0.091,
    contextPressure: 0.94,
    contextPressureStatus: "blocked",
    runCount: 1,
    subagentCount: 0,
    receiptRefs: ["receipt-run-inspector-telemetry"],
    policyDecisionRefs: ["policy-run-inspector-context"],
  };
}

function workflowBase(): WorkflowProject {
  const workflow = makeDefaultWorkflow("Run inspector telemetry chain");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.run-inspector-telemetry",
    },
  };
}

function telemetryBindingIssues(workflow: WorkflowProject) {
  return (
    evaluateWorkflowActivationReadiness(
      workflow,
      [],
      validateWorkflowProject(workflow, []),
    ).executionReadinessIssues ?? []
  ).filter((issue) => workflowRuntimeTelemetrySourceBindingIssue(issue));
}

test("run-inspector telemetry evidence materializes and binds a budget chain", () => {
  const result = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
    workflowBase(),
    telemetrySummary(),
    {
      idPrefix: "run-inspector-telemetry-chain",
      origin: { x: 180, y: 240 },
    },
  );

  assert.equal(
    result.schemaVersion,
    WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_MATERIALIZATION_SCHEMA_VERSION,
  );
  assert.equal(result.status, "bound");
  assert.equal(result.mode, "materialized");
  assert.deepEqual(result.insertedNodeIds, [
    "run-inspector-telemetry-chain-usage-meter",
    "run-inspector-telemetry-chain-context-budget",
    "run-inspector-telemetry-chain-compaction-policy",
    "run-inspector-telemetry-chain-coding-budget-gate",
  ]);
  assert.equal(result.insertedEdgeIds.length, 3);
  assert.deepEqual(result.boundNodeIds, result.insertedNodeIds);
  assert.equal(result.evidenceBinding?.latestEventId, "event-context-run-inspector");
  assert.equal(telemetryBindingIssues(result.workflow).length, 0);

  const chainIds = workflowRuntimeTelemetryBudgetChainIdsFromWorkflow(
    result.workflow,
  );
  assert.deepEqual(chainIds, {
    usageMeterNodeId: "run-inspector-telemetry-chain-usage-meter",
    contextBudgetNodeId: "run-inspector-telemetry-chain-context-budget",
    compactionPolicyNodeId: "run-inspector-telemetry-chain-compaction-policy",
    budgetGateNodeId: "run-inspector-telemetry-chain-coding-budget-gate",
  });

  const budgetGate = result.workflow.nodes.find(
    (node) => node.id === chainIds?.budgetGateNodeId,
  )!;
  const codingRequest = createRuntimeCodingToolControlRequestFromWorkflowNode(
    budgetGate,
    budgetGate.config?.logic?.testInput ?? {},
    { workflowGraphId: result.workflow.metadata.id },
  );
  assert.equal(codingRequest.body.budgetMode, "block");
  assert.equal(
    (codingRequest.body.toolPack.coding.telemetrySourceBinding as any)
      .latestEventId,
    "event-context-run-inspector",
  );
  assert.equal(
    (codingRequest.body.budgetUsageTelemetry as any).total_tokens,
    3500,
  );
});

test("run-inspector telemetry evidence hydrates an existing compatible chain", () => {
  const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
    idPrefix: "existing-run-inspector-chain",
    workflowGraphId: "workflow.run-inspector-telemetry",
    origin: { x: 100, y: 100 },
  });
  const base = workflowBase();
  const workflow = {
    ...base,
    nodes: [...base.nodes, ...subflow.nodes],
    edges: [...base.edges, ...subflow.edges],
  };

  const result = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
    workflow,
    telemetrySummary(),
  );

  assert.equal(result.status, "bound");
  assert.equal(result.mode, "hydrated");
  assert.deepEqual(result.insertedNodeIds, []);
  assert.deepEqual(result.insertedEdgeIds, []);
  assert.deepEqual(result.boundNodeIds, [
    subflow.usageMeterNodeId,
    subflow.contextBudgetNodeId,
    subflow.compactionPolicyNodeId,
    subflow.budgetGateNodeId,
  ]);
  assert.equal(result.workflow.nodes.length, workflow.nodes.length);
  assert.equal(result.workflow.edges.length, workflow.edges.length);
  assert.equal(telemetryBindingIssues(result.workflow).length, 0);
});

test("run-inspector telemetry chain materialization blocks without evidence", () => {
  const result = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
    workflowBase(),
    { ...telemetrySummary(), sourceKinds: [] },
  );

  assert.equal(result.status, "blocked");
  assert.equal(result.mode, null);
  assert.deepEqual(result.insertedNodeIds, []);
  assert(result.blockers.includes("runtime_telemetry_source_evidence_missing"));
});

test("run-inspector telemetry chain readiness still catches broken upstream binding", () => {
  const result = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
    workflowBase(),
    telemetrySummary(),
    { idPrefix: "broken-run-inspector-chain" },
  );
  const brokenNodes: Node[] = result.workflow.nodes.map((node) => {
    if (node.id !== "broken-run-inspector-chain-context-budget" || !node.config) {
      return node;
    }
    return {
      ...node,
      config: {
        ...node.config,
        logic: {
          ...node.config.logic,
          runtimeContextBudget: undefined,
          runtimeTelemetrySummary: undefined,
          inputMapping: {
            threadId: "runtime.threadId",
          },
        },
      },
    };
  });
  const brokenWorkflow = { ...result.workflow, nodes: brokenNodes };

  assert(
    telemetryBindingIssues(brokenWorkflow).some(
      (issue) =>
        issue.nodeId === "broken-run-inspector-chain-context-budget" &&
        issue.code === "missing_runtime_telemetry_source_usage_binding",
    ),
  );
});
