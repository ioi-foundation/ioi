import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowProject } from "../types/graph";
import {
  createRuntimeTerminalCodingLoopRunLaunchPlan,
  runRuntimeTerminalCodingLoopWorkflowLaunch,
} from "./workflow-runtime-terminal-coding-loop-run-launch";
import {
  createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
} from "./workflow-runtime-terminal-coding-loop-subflow";

test("terminal coding-loop run launch dispatches saved workflow nodes in run-history order", async () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "terminal-loop-run-launch",
    workflowGraphId: "workflow.terminal-loop-run-launch",
  });
  const workflow = {
    version: "workflow.v1",
    metadata: {
      id: "workflow.terminal-loop-run-launch",
      name: "Terminal loop run launch",
      slug: "terminal-loop-run-launch",
      workflowKind: "agent_workflow",
      executionMode: "local",
      gitLocation: ".agents/workflows/terminal-loop-run-launch.workflow.json",
    },
    nodes: subflow.nodes,
    edges: subflow.edges,
    global_config: {},
  } as unknown as WorkflowProject;
  const plan = createRuntimeTerminalCodingLoopRunLaunchPlan(
    workflow,
    { threadId: "thread-terminal-loop-run-launch" },
    { workflowPath: workflow.metadata.gitLocation },
  );

  assert.equal(plan.status, "ready");
  assert.equal(plan.workflowGraphId, "workflow.terminal-loop-run-launch");
  assert.deepEqual(plan.nodeIds, subflow.nodeIds);
  assert.deepEqual(plan.stepIds, [
    "workspace_status",
    "git_diff",
    "file_inspect",
    "file_apply_patch_dry_run",
    "file_apply_patch",
    "test_run",
    "lsp_diagnostics",
    "artifact_read",
    "tool_retrieve_result",
  ]);

  const invoked: Array<{
    stepId: string;
    toolId: string;
    artifactId?: unknown;
    toolCallId?: unknown;
    approvedRetry: boolean;
  }> = [];
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
      tool_call_id: `tool-call-${stepId}`,
      workflow_graph_id: "workflow.terminal-loop-run-launch",
      workflow_node_id: nodeId,
      receipt_refs: [`receipt-${stepId}`],
      ...extras,
      event: {
        event_id: `event-${stepId}`,
        event_stream_id: "events_thread-terminal-loop-run-launch",
        seq,
        event_kind: "tool.completed",
        source_event_kind: "CodingTool.Invoke",
        status: "completed",
        thread_id: "thread-terminal-loop-run-launch",
        workflow_graph_id: "workflow.terminal-loop-run-launch",
        workflow_node_id: nodeId,
        component_kind: "coding_tool",
        tool_name: toolId,
        tool_call_id: `tool-call-${stepId}`,
        payload_schema_version: "ioi.agent-sdk.thread-event.v1",
        receipt_refs: [`receipt-${stepId}`],
        artifact_refs:
          stepId === "test_run" ? ["artifact-terminal-loop-test"] : [],
        rollback_refs:
          stepId === "file_apply_patch" ? ["snapshot-terminal-loop"] : [],
        policy_decision_refs: [],
        payload_summary: { tool_name: toolId },
      },
    };
  };

  const launch = await runRuntimeTerminalCodingLoopWorkflowLaunch(
    workflow,
    { threadId: "thread-terminal-loop-run-launch" },
    {
      workflowPath: workflow.metadata.gitLocation,
      runId: "run-terminal-loop-launch",
      startedAtMs: 1_000,
      actor: "workflow-author",
      toolCallIdForStep: (stepId) => `terminal-loop-run-launch-${stepId}`,
      invoke: async (request, body, context) => {
        invoked.push({
          stepId: context.stepId,
          toolId: request.toolId,
          artifactId: body.arguments.artifactId,
          toolCallId: body.arguments.toolCallId,
          approvedRetry: context.approvedRetry,
        });
        if (
          context.stepId === "file_apply_patch" &&
          !context.approvedRetry
        ) {
          return {
            status: "blocked",
            approval_required: true,
            approval_id: "approval-terminal-loop-apply",
          };
        }
        if (context.stepId === "test_run") {
          return completedResult(context.stepId, context.node.id, request.toolId, {
            artifact_refs: ["artifact-terminal-loop-test"],
            result: {
              artifacts: [
                {
                  artifactId: "artifact-terminal-loop-test",
                  channel: "output",
                },
              ],
            },
          });
        }
        if (context.stepId === "file_apply_patch") {
          return completedResult(context.stepId, context.node.id, request.toolId, {
            rollback_refs: ["snapshot-terminal-loop"],
            workspace_snapshot: {
              schemaVersion: "ioi.runtime.workspace-snapshot.v1",
              snapshotId: "snapshot-terminal-loop",
            },
          });
        }
        return completedResult(context.stepId, context.node.id, request.toolId);
      },
      approve: async (context) => {
        assert.equal(context.approvalId, "approval-terminal-loop-apply");
        assert.equal(context.stepId, "file_apply_patch");
        return { approvalId: context.approvalId };
      },
    },
  );

  assert.equal(launch.runResult.summary.status, "passed");
  assert.equal(launch.runResult.summary.threadId, "thread-terminal-loop-run-launch");
  assert.deepEqual(launch.runResult.finalState.completedNodeIds, subflow.nodeIds);
  assert.equal(launch.runResult.nodeRuns.length, 9);
  assert.equal(launch.runResult.runtimeThreadEvents?.length, 9);
  assert.equal(launch.context.resultToolCallId, "tool-call-test_run");
  assert.equal(launch.context.artifactId, "artifact-terminal-loop-test");
  assert.ok(launch.context.rollbackRefs?.includes("snapshot-terminal-loop"));
  assert.equal(
    invoked.find((entry) => entry.stepId === "artifact_read")?.artifactId,
    "artifact-terminal-loop-test",
  );
  assert.equal(
    invoked.find((entry) => entry.stepId === "tool_retrieve_result")?.toolCallId,
    "tool-call-test_run",
  );
  assert.equal(
    invoked.filter((entry) => entry.stepId === "file_apply_patch").length,
    2,
  );
  assert.equal(
    invoked.find(
      (entry) => entry.stepId === "file_apply_patch" && entry.approvedRetry,
    )?.approvedRetry,
    true,
  );
});

test("terminal coding-loop run launch ignores retired runtime event id aliases", async () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "terminal-loop-run-launch-alias",
    workflowGraphId: "workflow.terminal-loop-run-launch-alias",
  });
  const node = subflow.nodes.find(
    (candidate) => candidate.id === subflow.stepNodeIds.workspace_status,
  );
  if (!node) throw new Error("workspace status node missing");
  const workflow = {
    version: "workflow.v1",
    metadata: {
      id: "workflow.terminal-loop-run-launch-alias",
      name: "Terminal loop run launch alias",
      slug: "terminal-loop-run-launch-alias",
      workflowKind: "agent_workflow",
      executionMode: "local",
      gitLocation: ".agents/workflows/terminal-loop-run-launch-alias.workflow.json",
    },
    nodes: [node],
    edges: [],
    global_config: {},
  } as unknown as WorkflowProject;

  const launch = await runRuntimeTerminalCodingLoopWorkflowLaunch(
    workflow,
    { threadId: "thread-terminal-loop-run-launch-alias" },
    {
      workflowPath: workflow.metadata.gitLocation,
      runId: "run-terminal-loop-launch-alias",
      startedAtMs: 1_000,
      actor: "workflow-author",
      invoke: async (request, _body, context) => ({
        status: "completed",
        tool_name: request.toolId,
        tool_call_id: `tool-call-${context.stepId}`,
        eventId: "legacy-root-event-id",
        event: {
          id: "legacy-nested-event-id",
          seq: 1,
          event_kind: "tool.completed",
          source_event_kind: "CodingTool.Invoke",
          status: "completed",
          thread_id: "thread-terminal-loop-run-launch-alias",
          workflow_graph_id: "workflow.terminal-loop-run-launch-alias",
          workflow_node_id: context.node.id,
          component_kind: "coding_tool",
          tool_name: request.toolId,
          payload_schema_version: "ioi.agent-sdk.thread-event.v1",
          payload_summary: { tool_name: request.toolId },
        },
      }),
    },
  );

  assert.equal(launch.runResult.summary.status, "passed");
  assert.equal(launch.runResult.nodeRuns.length, 1);
  assert.equal(launch.runResult.runtimeThreadEvents?.length, 0);
});
