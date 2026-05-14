import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowProject } from "../types/graph";
import { makeDefaultWorkflow } from "./workflow-defaults";
import { makeWorkflowNode } from "./workflow-node-registry";
import { createRuntimeCodingToolControlRequestFromWorkflowNode } from "./workflow-runtime-coding-tool-control-nodes";
import { createRuntimeCompactionPolicyControlRequestFromWorkflowNode } from "./workflow-runtime-compaction-policy-control-nodes";
import { createRuntimeContextBudgetControlRequestFromWorkflowNode } from "./workflow-runtime-context-budget-control-nodes";
import {
  bindWorkflowRuntimeTelemetrySourceToWorkflow,
  workflowRuntimeTelemetrySourceBindingIssue,
} from "./workflow-runtime-telemetry-source-binding";
import type { WorkflowRuntimeTelemetrySummary } from "./workflow-runtime-telemetry-summary";
import { createRuntimeUsageMeterControlRequestFromWorkflowNode } from "./workflow-runtime-usage-control-nodes";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "./workflow-validation";

function telemetrySummary(): WorkflowRuntimeTelemetrySummary {
  return {
    schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
    status: "elevated",
    sourceKinds: ["runtime_usage_events", "tui_context_rows"],
    threadIds: ["thread-telemetry-source"],
    turnIds: ["turn-telemetry-source"],
    workflowGraphIds: ["workflow.telemetry-source"],
    workflowNodeIds: ["runtime.usage-meter"],
    eventIds: ["event-usage", "event-context"],
    latestSeq: 2,
    latestCursor: "events_thread-telemetry-source:2",
    latestEventId: "event-context",
    runtimeEventCount: 2,
    usageEventCount: 1,
    contextPressureEventCount: 1,
    contextPressureAlertCount: 0,
    tuiRowCount: 1,
    usageRowCount: 1,
    costRowCount: 1,
    contextRowCount: 1,
    subagentRowCount: 0,
    codingToolBudgetRowCount: 0,
    totalTokens: 1800,
    inputTokens: 1200,
    outputTokens: 600,
    costEstimateUsd: 0.045,
    contextPressure: 0.72,
    contextPressureStatus: "elevated",
    runCount: 1,
    subagentCount: 0,
    receiptRefs: ["receipt-telemetry"],
    policyDecisionRefs: ["policy-telemetry"],
  };
}

function workflowWithTelemetryTargets(): WorkflowProject {
  const workflow = makeDefaultWorkflow();
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.telemetry-source",
    },
    nodes: [
      ...workflow.nodes,
      makeWorkflowNode("usage-meter", "runtime_usage_meter", "Usage", 100, 100),
      makeWorkflowNode(
        "context-budget",
        "runtime_context_budget",
        "Context budget",
        300,
        100,
      ),
      makeWorkflowNode(
        "compaction-policy",
        "runtime_compaction_policy",
        "Compaction",
        500,
        100,
      ),
      makeWorkflowNode("coding-tool", "plugin_tool", "Coding tool", 700, 100, {
        toolBinding: {
          toolRef: "workspace.status",
          bindingKind: "coding_tool_pack",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["workspace:read"],
          sideEffectClass: "read",
          requiresApproval: false,
          toolPack: {
            pack: "coding",
            budgetMode: "block",
            budgetUsageField: "runtimeTelemetrySummary",
          },
        },
      }),
    ],
  };
}

test("runtime telemetry source binding quick-fix wires selected summary into runtime budget nodes", () => {
  const workflow = workflowWithTelemetryTargets();
  const readiness = evaluateWorkflowActivationReadiness(
    workflow,
    [],
    validateWorkflowProject(workflow, []),
  );
  const issues = (readiness.executionReadinessIssues ?? []).filter((issue) =>
    workflowRuntimeTelemetrySourceBindingIssue(issue),
  );
  assert(issues.length >= 4);

  const result = bindWorkflowRuntimeTelemetrySourceToWorkflow(
    workflow,
    telemetrySummary(),
  );
  assert.equal(result.status, "bound");
  assert.deepEqual(
    result.boundNodeIds,
    ["usage-meter", "context-budget", "compaction-policy", "coding-tool"],
  );

  const usageNode = result.workflow.nodes.find((node) => node.id === "usage-meter")!;
  const contextNode = result.workflow.nodes.find(
    (node) => node.id === "context-budget",
  )!;
  const compactionNode = result.workflow.nodes.find(
    (node) => node.id === "compaction-policy",
  )!;
  const codingNode = result.workflow.nodes.find((node) => node.id === "coding-tool")!;

  const usageRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
    usageNode,
    {},
    { workflowGraphId: result.workflow.metadata.id },
  );
  assert.equal(usageRequest.threadId, "thread-telemetry-source");
  assert.match(usageRequest.endpoint, /^\/v1\/threads\/thread-telemetry-source\/usage\?/);

  const contextRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
    contextNode,
    {},
    { workflowGraphId: result.workflow.metadata.id },
  );
  assert.equal(contextRequest.threadId, "thread-telemetry-source");
  assert.equal(
    (contextRequest.body.usageTelemetry as any).runtimeTelemetrySummarySchemaVersion,
    "ioi.workflow.runtime-telemetry-summary.v1",
  );
  assert.equal((contextRequest.body.usageTelemetry as any).totalTokens, 1800);

  const compactionRequest =
    createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
      compactionNode,
      {},
      { workflowGraphId: result.workflow.metadata.id },
    );
  assert.equal(compactionRequest.threadId, "thread-telemetry-source");
  assert.equal(compactionRequest.turnId, "turn-telemetry-source");
  assert.equal(compactionRequest.body.contextBudgetStatus, "warn");

  const codingRequest = createRuntimeCodingToolControlRequestFromWorkflowNode(
    codingNode,
    codingNode.config?.logic?.testInput ?? {},
    { workflowGraphId: result.workflow.metadata.id },
  );
  assert.equal(
    (codingRequest.body.budgetUsageTelemetry as any)
      .runtimeTelemetrySummarySchemaVersion,
    "ioi.workflow.runtime-telemetry-summary.v1",
  );
  assert.equal(codingRequest.body.toolPack.coding.budgetUsageField, "runtimeTelemetrySummary");

  const nextReadiness = evaluateWorkflowActivationReadiness(
    result.workflow,
    [],
    validateWorkflowProject(result.workflow, []),
  );
  assert.equal(
    (nextReadiness.executionReadinessIssues ?? []).some((issue) =>
      workflowRuntimeTelemetrySourceBindingIssue(issue),
    ),
    false,
  );
});

test("runtime telemetry source binding blocks without telemetry evidence", () => {
  const result = bindWorkflowRuntimeTelemetrySourceToWorkflow(
    workflowWithTelemetryTargets(),
    {
      ...telemetrySummary(),
      sourceKinds: [],
    },
  );
  assert.equal(result.status, "blocked");
  assert.deepEqual(result.boundNodeIds, []);
  assert(result.blockers.includes("runtime_telemetry_source_evidence_missing"));
});
