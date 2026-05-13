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
  const controlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts",
  );
  const runHistoryModel = read(
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
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
  assert.match(projection, /runtime_thread_fork/);
  assert.match(projection, /runtime_operator_interrupt/);
  assert.match(projection, /runtime_operator_steer/);
  assert.match(projection, /runtime_context_compact/);
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
  assert.match(controlNodesTest, /React Flow daemon request/);
  assert.match(controlNodesTest, /workflow\.react-flow\.thread-fork-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.operator-interrupt-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.operator-steer-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.context-compact-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.rollback-snapshot-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.restore-gate-proof/);
  assert.match(exports, /workflow-runtime-event-projection/);
  assert.match(exports, /workflow-runtime-control-nodes/);
  assert.match(typeTest, /projects Thread\.events runtime events/);
  assert.match(typeTest, /runtime_thread_fork/);
  assert.match(typeTest, /runtime_operator_interrupt/);
  assert.match(typeTest, /runtime_operator_steer/);
  assert.match(typeTest, /runtime_context_compact/);
  assert.match(typeTest, /approval_required/);
  assert.match(typeTest, /policy_blocked/);
  assert.match(runHistoryModel, /projectRuntimeThreadEventsToWorkflowProjection/);
  assert.match(runHistoryModel, /runtimeThreadEvents\?: WorkflowRuntimeThreadEventLike\[\]/);
  assert.match(runHistoryModel, /runtimeEventProjection: WorkflowRuntimeEventProjection/);
  assert.match(runHistoryModel, /runtimeThreadEventsForRunResult/);
  assert.match(runHistoryModelTest, /projects canonical runtime thread events/);
  assert.match(railPanel, /runtimeThreadEvents\?: WorkflowRuntimeThreadEventLike\[\]/);
  assert.match(railPanel, /runtimeThreadEvents,/);
  assert.match(composerController, /loadWorkflowRuntimeThreadEvents/);
  assert.match(composerController, /setRuntimeThreadEvents/);
  assert.match(composerView, /runtimeThreadEvents=\{runtimeThreadEvents\}/);
  assert.match(graphRuntimeTypes, /loadWorkflowRuntimeThreadEvents/);
  assert.match(tauriRuntime, /loadWorkflowRuntimeThreadEvents/);
  assert.match(runsPanel, /workflow-run-runtime-event-graph/);
  assert.match(runsPanel, /workflow-run-runtime-event-node-/);
  assert.match(runsPanel, /workflow-run-runtime-event-edge-/);
  assert.match(runsPanel, /data-event-id/);
  assert.match(runsPanel, /data-event-cursor/);
  assert.match(runsPanel, /data-receipt-refs/);
  assert.match(runsPanel, /data-artifact-refs/);
  assert.match(runsPanel, /data-policy-decision-refs/);
  assert.match(runsPanel, /data-rollback-refs/);
});
