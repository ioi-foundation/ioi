import assert from "node:assert/strict";
import test from "node:test";

import {
  createRuntimeTerminalCodingLoopStepRequest,
  updateRuntimeTerminalCodingLoopExecutionContextFromToolResult,
  type WorkflowRuntimeTerminalCodingLoopExecutionContext,
  workflowRuntimeTerminalCodingLoopNodesInExecutionOrder,
} from "./workflow-runtime-terminal-coding-loop-execution";
import {
  createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
} from "./workflow-runtime-terminal-coding-loop-subflow";

test("terminal coding loop execution resolves upstream artifact and tool result placeholders", () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "terminal-loop-exec-context",
    workflowGraphId: "workflow.terminal-loop-exec-context",
  });
  const ordered = workflowRuntimeTerminalCodingLoopNodesInExecutionOrder([
    ...subflow.nodes.slice().reverse(),
  ]);

  assert.deepEqual(ordered.map((node) => node.id), subflow.nodeIds);

  let context: WorkflowRuntimeTerminalCodingLoopExecutionContext = {
    threadId: "thread-terminal-loop-exec",
  };
  const testNode = ordered.find(
    (node) => node.config?.logic.runtimeTerminalCodingLoopStepId === "test_run",
  )!;
  const testRequest = createRuntimeTerminalCodingLoopStepRequest(
    testNode,
    context,
    {
      workflowGraphId: subflow.workflowGraphId,
      actor: "workflow-author",
    },
  );

  assert.equal(testRequest.threadId, "thread-terminal-loop-exec");
  assert.equal(testRequest.body.actor, "workflow-author");
  assert.equal(testRequest.body.workflowGraphId, "workflow.terminal-loop-exec-context");
  assert.equal(testRequest.toolId, "test.run");

  context = updateRuntimeTerminalCodingLoopExecutionContextFromToolResult(
    context,
    {
      tool_name: "test.run",
      tool_call_id: "coding_tool_terminal_loop_test",
      receipt_refs: ["receipt_terminal_loop_test"],
      artifact_refs: ["artifact_terminal_loop_stdout"],
      event: {
        event_id: "event_terminal_loop_test",
        event_stream_id: "events_thread-terminal-loop-exec",
        seq: 6,
        turn_id: "turn-terminal-loop-exec",
      },
      result: {
        artifacts: [
          {
            artifactId: "artifact_terminal_loop_stdout",
            channel: "output",
          },
        ],
      },
    },
  );

  assert.equal(context.turnId, "turn-terminal-loop-exec");
  assert.equal(context.cursor, "events_thread-terminal-loop-exec:6");
  assert.equal(context.lastEventId, "event_terminal_loop_test");
  assert.equal(context.toolCallId, "coding_tool_terminal_loop_test");
  assert.equal(context.resultToolCallId, "coding_tool_terminal_loop_test");
  assert.equal(context.artifactId, "artifact_terminal_loop_stdout");
  assert.deepEqual(context.receiptRefs, ["receipt_terminal_loop_test"]);

  const artifactNode = ordered.find(
    (node) => node.config?.logic.runtimeTerminalCodingLoopStepId === "artifact_read",
  )!;
  const artifactRequest = createRuntimeTerminalCodingLoopStepRequest(
    artifactNode,
    context,
    { workflowGraphId: subflow.workflowGraphId },
  );
  assert.equal(artifactRequest.toolId, "artifact.read");
  assert.equal(
    artifactRequest.body.arguments.artifactId,
    "artifact_terminal_loop_stdout",
  );

  context = updateRuntimeTerminalCodingLoopExecutionContextFromToolResult(
    context,
    {
      tool_name: "artifact.read",
      tool_call_id: "coding_tool_terminal_loop_artifact_read",
      receipt_refs: ["receipt_terminal_loop_artifact_read"],
      event: {
        event_id: "event_terminal_loop_artifact_read",
        event_stream_id: "events_thread-terminal-loop-exec",
        seq: 8,
      },
      result: {
        content: "terminal loop output",
      },
    },
  );

  const retrieveNode = ordered.find(
    (node) =>
      node.config?.logic.runtimeTerminalCodingLoopStepId ===
      "tool_retrieve_result",
  )!;
  const retrieveRequest = createRuntimeTerminalCodingLoopStepRequest(
    retrieveNode,
    context,
    { workflowGraphId: subflow.workflowGraphId },
  );
  assert.equal(retrieveRequest.toolId, "tool.retrieve_result");
  assert.equal(
    retrieveRequest.body.arguments.toolCallId,
    "coding_tool_terminal_loop_test",
  );
  assert.equal(context.toolCallId, "coding_tool_terminal_loop_artifact_read");
  assert.equal(context.resultToolCallId, "coding_tool_terminal_loop_test");
});
