import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

test("React Flow runtime event projection consumes canonical Thread.events shape", () => {
  const projection = read(
    "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts",
  );
  const exports = read("packages/agent-ide/src/index.ts");
  const typeTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts",
  );
  const controlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts",
  );
  const usageControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-usage-control-nodes.ts",
  );
  const contextBudgetControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts",
  );
  const codingToolControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts",
  );
  const compactionPolicyControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-compaction-policy-control-nodes.ts",
  );
  const controlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts",
  );
  const usageControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-usage-control-nodes.test.ts",
  );
  const contextBudgetControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.test.ts",
  );
  const codingToolControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.test.ts",
  );
  const compactionPolicyControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-compaction-policy-control-nodes.test.ts",
  );
  const runHistoryModel = read(
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
  );
  const telemetrySummary = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-summary.ts",
  );
  const telemetrySummaryTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-summary.test.ts",
  );
  const runHistoryModelTest = read(
    "packages/agent-ide/src/runtime/workflow-run-history-model.test.ts",
  );
  const runsPanel = read(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
  );
  const railPanel = read(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx",
  );
  const composerController = read(
    "packages/agent-ide/src/WorkflowComposer/controller.tsx",
  );
  const composerView = read("packages/agent-ide/src/WorkflowComposer/view.tsx");
  const graphRuntimeTypes = read(
    "packages/agent-ide/src/runtime/graph-runtime-types.ts",
  );
  const tauriRuntime = read("apps/autopilot/src/services/TauriRuntime.ts");

  assert.match(
    projection,
    /ioi\.workflow\.runtime-event-projection\.v1/,
  );
  assert.match(projection, /WorkflowRuntimeThreadEventLike/);
  for (const field of [
    "cursor",
    "seq",
    "threadId",
    "turnId",
    "eventKind",
    "sourceEventKind",
    "componentKind",
    "workflowNodeId",
    "workflowGraphId",
    "payloadSchemaVersion",
    "receiptRefs",
    "artifactRefs",
    "policyDecisionRefs",
    "rollbackRefs",
  ]) {
    assert.match(projection, new RegExp(`${field}:`));
  }
  for (const eventType of [
    "thread_forked",
    "reasoning_delta",
    "tool_completed",
    "tool_failed",
    "turn_interrupted",
    "turn_steered",
    "context_compacted",
    "approval_required",
    "compaction_policy_evaluated",
    "policy_blocked",
    "receipt_emitted",
    "model_route_decision",
    "tool_route_decision",
  ]) {
    assert.match(projection, new RegExp(`"${eventType}"`));
  }
  assert.match(projection, /projectRuntimeThreadEventsToWorkflowProjection/);
  assert.match(projection, /projectRuntimeThreadEventsToWorkflowNodes/);
  assert.match(projection, /reactFlowNodes/);
  assert.match(projection, /reactFlowEdges/);
  assert.match(projection, /runtimeEventProjection/);
  assert.match(projection, /runtimeEventTransition/);
  assert.match(projection, /WorkflowRuntimeSubagentChildSubflowDescriptor/);
  assert.match(projection, /subagentChildSubflowReactFlowNodes/);
  assert.match(projection, /subagentBudgetStatus/);
  assert.match(projection, /subagentCostEstimateUsd/);
  assert.match(projection, /subagentTokenEstimate/);
  assert.match(projection, /usage_status/);
  assert.match(projection, /usageTotalTokens/);
  assert.match(projection, /usageCostEstimateUsd/);
  assert.match(projection, /coding_tool_budget/);
  assert.match(projection, /codingToolBudgetRowCount/);
  assert.match(projection, /codingToolBudgetStatus/);
  assert.match(projection, /codingToolBudgetViolationCount/);
  assert.match(projection, /codingToolMutationBlocked/);
  assert.match(projection, /Coding tool budget/);
  assert.match(projection, /runtimeSubagentSubflow/);
  assert.match(projection, /runtimeSubagentRun/);
  assert.match(projection, /runtime_thread_fork/);
  assert.match(projection, /runtime_operator_interrupt/);
  assert.match(projection, /runtime_operator_steer/);
  assert.match(projection, /runtime_context_compact/);
  assert.match(projection, /runtime_context_budget/);
  assert.match(projection, /runtime_compaction_policy/);
  assert.match(controlNodes, /createRuntimeThreadForkControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeOperatorInterruptControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeOperatorSteerControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeContextCompactControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeRollbackSnapshotControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeRestoreGateControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /runtime_thread_fork/);
  assert.match(controlNodes, /runtime_operator_interrupt/);
  assert.match(controlNodes, /runtime_operator_steer/);
  assert.match(controlNodes, /runtime_context_compact/);
  assert.match(controlNodes, /runtime_rollback_snapshot/);
  assert.match(controlNodes, /runtime_restore_gate/);
  assert.match(controlNodes, /runtime\.thread-fork/);
  assert.match(controlNodes, /runtime\.operator-interrupt/);
  assert.match(controlNodes, /runtime\.operator-steer/);
  assert.match(controlNodes, /runtime\.context-compact/);
  assert.match(controlNodes, /runtime\.rollback-snapshot/);
  assert.match(controlNodes, /runtime\.restore-gate/);
  assert.match(controlNodes, /source: RUNTIME_THREAD_FORK_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_OPERATOR_INTERRUPT_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_OPERATOR_STEER_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_CONTEXT_COMPACT_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_ROLLBACK_SNAPSHOT_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_RESTORE_GATE_SOURCE/);
  assert.match(controlNodes, /workflowGraphId/);
  assert.match(controlNodes, /workflowNodeId/);
  assert.match(usageControlNodes, /createRuntimeUsageMeterControlRequestFromWorkflowNode/);
  assert.match(usageControlNodes, /runtime_usage_meter/);
  assert.match(usageControlNodes, /\/v1\/threads\/\{threadId\}\/usage/);
  assert.match(usageControlNodes, /RuntimeUsageTelemetry\.Read/);
  assert.match(usageControlNodes, /usage_meter_scope/);
  assert.match(contextBudgetControlNodes, /createRuntimeContextBudgetControlRequestFromWorkflowNode/);
  assert.match(contextBudgetControlNodes, /runtime_context_budget/);
  assert.match(contextBudgetControlNodes, /\/v1\/threads\/\{threadId\}\/context-budget/);
  assert.match(contextBudgetControlNodes, /RuntimeContextBudget\.Evaluate/);
  assert.match(codingToolControlNodes, /createRuntimeCodingToolControlRequestFromWorkflowNode/);
  assert.match(codingToolControlNodes, /runtimeTelemetrySummary/);
  assert.match(codingToolControlNodes, /budgetUsageTelemetry/);
  assert.match(codingToolControlNodes, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.match(compactionPolicyControlNodes, /createRuntimeCompactionPolicyControlRequestFromWorkflowNode/);
  assert.match(compactionPolicyControlNodes, /runtime_compaction_policy/);
  assert.match(compactionPolicyControlNodes, /\/v1\/threads\/\{threadId\}\/compaction-policy/);
  assert.match(compactionPolicyControlNodes, /RuntimeCompactionPolicy\.Evaluate/);
  assert.match(read("packages/agent-ide/src/runtime/workflow-node-registry.ts"), /creatorId: "usage\.meter"/);
  assert.match(read("packages/agent-ide/src/runtime/workflow-node-registry.ts"), /creatorId: "context\.budget"/);
  assert.match(read("packages/agent-ide/src/runtime/workflow-node-registry.ts"), /creatorId: "compaction\.policy"/);
  assert.match(controlNodesTest, /React Flow daemon request/);
  assert.match(usageControlNodesTest, /workflow\.react-flow\.usage-meter-proof/);
  assert.match(contextBudgetControlNodesTest, /workflow\.react-flow\.context-budget-proof/);
  assert.match(codingToolControlNodesTest, /runtime telemetry summary budget gates/);
  assert.match(typeTest, /projects coding tool budget blocks/);
  assert.match(typeTest, /projects TUI coding-tool budget rows/);
  assert.match(runHistoryModelTest, /componentKind: "coding_tool"/);
  assert.match(runsPanel, /data-coding-tool-budget-row-count/);
  assert.match(runsPanel, /data-coding-tool-budget-status/);
  assert.match(runsPanel, /data-coding-tool-mutation-blocked/);
  assert.match(compactionPolicyControlNodesTest, /workflow\.react-flow\.compaction-policy-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.thread-fork-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.operator-interrupt-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.operator-steer-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.context-compact-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.rollback-snapshot-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.restore-gate-proof/);
  assert.match(exports, /workflow-runtime-event-projection/);
  assert.match(exports, /workflow-runtime-telemetry-summary/);
  assert.match(exports, /workflow-runtime-control-nodes/);
  assert.match(exports, /workflow-runtime-usage-control-nodes/);
  assert.match(exports, /workflow-runtime-context-budget-control-nodes/);
  assert.match(exports, /workflow-runtime-compaction-policy-control-nodes/);
  assert.match(typeTest, /projects Thread\.events runtime events/);
  assert.match(typeTest, /runtime_thread_fork/);
  assert.match(typeTest, /runtime_operator_interrupt/);
  assert.match(typeTest, /runtime_operator_steer/);
  assert.match(typeTest, /runtime_context_compact/);
  assert.match(typeTest, /runtime_compaction_policy/);
  assert.match(typeTest, /approval_required/);
  assert.match(typeTest, /policy_blocked/);
  assert.match(runHistoryModel, /projectRuntimeThreadEventsToWorkflowProjection/);
  assert.match(runHistoryModel, /runtimeThreadEvents\?: WorkflowRuntimeThreadEventLike\[\]/);
  assert.match(runHistoryModel, /runtimeEventProjection: WorkflowRuntimeEventProjection/);
  assert.match(runHistoryModel, /runtimeTelemetrySummary: WorkflowRuntimeTelemetrySummary/);
  assert.match(runHistoryModel, /runtimeTelemetrySourceFilters/);
  assert.match(runHistoryModel, /runtimeCodingToolBudgetEvidence/);
  assert.match(runHistoryModel, /visibleTuiControlStateRows/);
  assert.match(runHistoryModel, /workflowRuntimeTelemetrySummaryFromProjection/);
  assert.match(runHistoryModel, /runtimeThreadEventsForRunResult/);
  assert.match(runHistoryModelTest, /projects canonical runtime thread events/);
  assert.match(runHistoryModelTest, /source-filtered TUI coding-tool budget evidence/);
  assert.match(telemetrySummary, /ioi\.workflow\.runtime-telemetry-summary\.v1/);
  assert.match(telemetrySummary, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.match(telemetrySummary, /estimated_cost_usd/);
  assert.match(telemetrySummary, /runtime_usage_events/);
  assert.match(telemetrySummary, /runtime_context_pressure_events/);
  assert.match(telemetrySummary, /runtime_context_pressure_alerts/);
  assert.match(telemetrySummary, /tui_usage_rows/);
  assert.match(telemetrySummary, /tui_context_rows/);
  assert.match(telemetrySummary, /tui_subagent_rows/);
  assert.match(telemetrySummary, /tui_coding_tool_rows/);
  assert.match(telemetrySummary, /codingToolBudgetRowCount/);
  assert.match(telemetrySummaryTest, /merges usage, context, TUI, and subagent rows/);
  assert.match(telemetrySummaryTest, /TUI coding-tool budget rows/);
  assert.match(telemetrySummaryTest, /converts to daemon budget usage telemetry/);
  assert.match(contextBudgetControlNodes, /runtimeTelemetrySummary/);
  assert.match(contextBudgetControlNodesTest, /runtime telemetry summary input/);
  assert.match(railPanel, /runtimeThreadEvents\?: WorkflowRuntimeThreadEventLike\[\]/);
  assert.match(railPanel, /runtimeThreadEvents,/);
  assert.match(composerController, /loadWorkflowRuntimeThreadEvents/);
  assert.match(composerController, /setRuntimeThreadEvents/);
  assert.match(composerView, /runtimeThreadEvents=\{runtimeThreadEvents\}/);
  assert.match(graphRuntimeTypes, /loadWorkflowRuntimeThreadEvents/);
  assert.match(tauriRuntime, /loadWorkflowRuntimeThreadEvents/);
  assert.match(runsPanel, /workflow-run-runtime-event-graph/);
  assert.match(runsPanel, /workflow-run-telemetry-summary/);
  assert.match(runsPanel, /workflow-run-source-filter/);
  assert.match(runsPanel, /workflow-run-coding-tool-budget-evidence/);
  assert.match(runsPanel, /workflow-run-telemetry-source-kinds/);
  assert.match(runsPanel, /data-telemetry-status/);
  assert.match(runsPanel, /data-context-pressure-event-count/);
  assert.match(runsPanel, /data-visible-row-count/);
  assert.match(runsPanel, /workflow-run-runtime-event-node-/);
  assert.match(runsPanel, /workflow-run-runtime-event-edge-/);
  assert.match(runsPanel, /data-event-id/);
  assert.match(runsPanel, /data-event-cursor/);
  assert.match(runsPanel, /data-receipt-refs/);
  assert.match(runsPanel, /data-artifact-refs/);
  assert.match(runsPanel, /data-policy-decision-refs/);
  assert.match(runsPanel, /data-rollback-refs/);
  assert.match(runsPanel, /workflow-run-subagent-subflows/);
  assert.match(runsPanel, /data-subagent-child-subflow-count/);
  assert.match(runsPanel, /data-subagent-budget-status/);
  assert.match(runsPanel, /data-subagent-cost-estimate-usd/);
  assert.match(runsPanel, /data-subagent-token-estimate/);
  assert.match(runsPanel, /data-usage-total-tokens/);
  assert.match(runsPanel, /data-usage-cost-estimate-usd/);
  assert.match(runsPanel, /data-usage-context-pressure-status/);
  assert.match(runsPanel, /data-child-thread-id/);
});
