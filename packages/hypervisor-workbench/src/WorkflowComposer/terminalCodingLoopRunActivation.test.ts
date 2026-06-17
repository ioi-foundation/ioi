import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowProject } from "../types/graph";
import { createWorkflowRuntimeTerminalCodingLoopTemplateSubflow } from "../runtime/workflow-runtime-terminal-coding-loop-subflow";
import {
  runWorkflowComposerTerminalCodingLoopActivation,
  workflowComposerTerminalCodingLoopRunLaunchEligible,
  type WorkflowComposerTerminalCodingLoopControlRequest,
} from "./terminalCodingLoopRunActivation";

test("composer terminal coding-loop activation launches pure saved workflow", async () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "composer-terminal-loop",
    workflowGraphId: "workflow.composer-terminal-loop",
  });
  const workflow = {
    version: "workflow.v1",
    metadata: {
      id: "workflow.composer-terminal-loop",
      name: "Composer terminal loop",
      slug: "composer-terminal-loop",
      workflowKind: "agent_workflow",
      executionMode: "local",
      gitLocation: ".agents/workflows/composer-terminal-loop.workflow.json",
    },
    nodes: subflow.nodes,
    edges: subflow.edges,
    global_config: {},
  } as unknown as WorkflowProject;

  assert.equal(workflowComposerTerminalCodingLoopRunLaunchEligible(workflow), true);
  assert.equal(
    workflowComposerTerminalCodingLoopRunLaunchEligible({
      ...workflow,
      nodes: [
        ...workflow.nodes,
        {
          id: "extra-output",
          type: "output",
          name: "Output",
          config: { logic: {} },
        },
      ],
    } as unknown as WorkflowProject),
    false,
  );

  const requests: WorkflowComposerTerminalCodingLoopControlRequest[] = [];
  const stepIdByNodeId = new Map(
    Object.entries(subflow.stepNodeIds).map(([stepId, nodeId]) => [
      nodeId,
      stepId,
    ]),
  );
  let seq = 0;
  const completedResult = (
    stepId: string,
    nodeId: string,
    toolId: string,
    extras: Record<string, unknown> = {},
  ) => {
    seq += 1;
    return {
      status: "completed",
      tool_name: toolId,
      tool_call_id: `terminal_loop_thread-composer-terminal_${stepId}`,
      workflow_graph_id: "workflow.composer-terminal-loop",
      workflow_node_id: nodeId,
      receipt_refs: [`receipt-${stepId}`],
      ...extras,
      event: {
        event_id: `event-${stepId}`,
        event_stream_id: "events_thread-composer-terminal",
        seq,
        event_kind: "tool.completed",
        source_event_kind: "CodingTool.Invoke",
        status: "completed",
        thread_id: "thread-composer-terminal",
        workflow_graph_id: "workflow.composer-terminal-loop",
        workflow_node_id: nodeId,
        component_kind: "coding_tool",
        tool_name: toolId,
        tool_call_id: `terminal_loop_thread-composer-terminal_${stepId}`,
        payload_schema_version: "ioi.agent-sdk.thread-event.v1",
        receipt_refs: [`receipt-${stepId}`],
        artifact_refs:
          stepId === "test_run" ? ["artifact-composer-terminal-test"] : [],
        rollback_refs:
          stepId === "file_apply_patch" ? ["snapshot-composer-terminal"] : [],
        policy_decision_refs: [],
        payload_summary: { tool_name: toolId },
      },
    };
  };

  const launch = await runWorkflowComposerTerminalCodingLoopActivation({
    workflow,
    workflowPath:
      workflow.metadata.gitLocation ??
      ".agents/workflows/composer-terminal-loop.workflow.json",
    threadId: "thread-composer-terminal",
    actor: "workflow-author",
    startedAtMs: 1_700,
    executeRuntimeControlRequest: async (request) => {
      requests.push(request);
      if (request.nodeType === "runtime_approval_decision") {
        assert.match(request.endpoint, /\/approvals\/approval-composer-terminal\/decision$/);
        assert.equal(request.body.decision, "approve");
        assert.equal(request.body.workflowNodeId, subflow.stepNodeIds.file_apply_patch);
        return { decision: "approve" };
      }
      const stepId = stepIdByNodeId.get(request.body.workflowNodeId);
      const body = request.body as typeof request.body & Record<string, unknown>;
      assert.equal(request.body.workflowGraphId, "workflow.composer-terminal-loop");
      assert.equal(body.toolCallId, `terminal_loop_thread-composer-terminal_${stepId}`);
      if (stepId === "artifact_read") {
        assert.equal(request.body.arguments.artifactId, "artifact-composer-terminal-test");
      }
      if (stepId === "tool_retrieve_result") {
        assert.equal(request.body.arguments.toolCallId, "terminal_loop_thread-composer-terminal_test_run");
      }
      if (stepId === "file_apply_patch" && !body.approvalId) {
        return {
          status: "blocked",
          approval_required: true,
          approval_id: "approval-composer-terminal",
        };
      }
      if (stepId === "test_run") {
        return completedResult(stepId, request.body.workflowNodeId, request.toolId, {
          artifact_refs: ["artifact-composer-terminal-test"],
          result: {
            artifacts: [
              {
                artifactId: "artifact-composer-terminal-test",
                channel: "output",
              },
            ],
          },
        });
      }
      if (stepId === "file_apply_patch") {
        return completedResult(stepId, request.body.workflowNodeId, request.toolId, {
          rollback_refs: ["snapshot-composer-terminal"],
          workspace_snapshot: {
            schemaVersion: "ioi.runtime.workspace-snapshot.v1",
            snapshotId: "snapshot-composer-terminal",
          },
        });
      }
      return completedResult(stepId ?? "unknown", request.body.workflowNodeId, request.toolId);
    },
  });

  assert.equal(launch.runResult.summary.status, "passed");
  assert.equal(launch.runResult.thread.id, "thread-composer-terminal");
  assert.equal(launch.runResult.nodeRuns.length, 9);
  assert.equal(launch.runResult.runtimeThreadEvents?.length, 9);
  assert.deepEqual(launch.runResult.finalState.completedNodeIds, subflow.nodeIds);
  assert.equal(
    requests.filter((request) => request.nodeType === "runtime_approval_decision")
      .length,
    1,
  );
  assert.equal(launch.context.artifactId, "artifact-composer-terminal-test");
  assert.equal(
    launch.context.resultToolCallId,
    "terminal_loop_thread-composer-terminal_test_run",
  );
});
