import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_THREAD_FORK_COMPONENT_KIND,
  RUNTIME_THREAD_FORK_SOURCE,
  RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND,
  RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
  WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION,
  createRuntimeThreadForkControlRequestFromWorkflowNode,
} from "./workflow-runtime-control-nodes";

test("runtime_thread_fork workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "fork-control",
    "runtime_thread_fork",
    "Fork control",
    100,
    120,
  );
  const request = createRuntimeThreadForkControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      reason: "branch for live React Flow validation",
    },
    { workflowGraphId: "workflow.react-flow.thread-fork-proof" },
  );

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION);
  assert.equal(request.nodeType, "runtime_thread_fork");
  assert.equal(request.nodeId, "fork-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/fork");
  assert.equal(request.body.reason, "branch for live React Flow validation");
  assert.equal(request.body.source, RUNTIME_THREAD_FORK_SOURCE);
  assert.equal(request.body.actor, "operator");
  assert.equal(request.body.workflowGraphId, "workflow.react-flow.thread-fork-proof");
  assert.equal(request.body.workflowNodeId, RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_THREAD_FORK_COMPONENT_KIND);
});

test("runtime_thread_fork helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "fork-control-configured",
    "runtime_thread_fork",
    "Fork control",
    100,
    120,
    {
      runtimeThreadForkEndpoint: "/runtime/{threadId}/fork",
      runtimeThreadForkThreadIdField: "runtime.threadId",
      runtimeThreadForkReasonField: "operator.reason",
      runtimeThreadForkWorkflowNodeId: "runtime.thread-fork",
      runtimeThreadForkActor: "workflow-author",
    },
  );
  const request = createRuntimeThreadForkControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space" },
      operator: { reason: "split the live branch" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.endpoint, "/runtime/thread%20with%20space/fork");
  assert.equal(request.body.reason, "split the live branch");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});
