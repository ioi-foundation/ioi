import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND,
  RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND,
  RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
  RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND,
  RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND,
  RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
  RUNTIME_OPERATOR_STEER_COMPONENT_KIND,
  RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND,
  RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
  RUNTIME_THREAD_FORK_COMPONENT_KIND,
  RUNTIME_THREAD_FORK_SOURCE,
  RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND,
  RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
  WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION,
  createRuntimeContextCompactControlRequestFromWorkflowNode,
  createRuntimeOperatorInterruptControlRequestFromWorkflowNode,
  createRuntimeOperatorSteerControlRequestFromWorkflowNode,
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

test("runtime control workflow helpers share graph identity envelope metadata", () => {
  const graphId = "workflow.react-flow.shared-control-envelope";
  const actor = "workflow-operator";
  const requests = [
    createRuntimeThreadForkControlRequestFromWorkflowNode(
      makeWorkflowNode("fork-shared", "runtime_thread_fork", "Fork", 0, 0),
      { threadId: "thread-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
      makeWorkflowNode(
        "interrupt-shared",
        "runtime_operator_interrupt",
        "Interrupt",
        0,
        0,
      ),
      { threadId: "thread-shared", turnId: "turn-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeOperatorSteerControlRequestFromWorkflowNode(
      makeWorkflowNode("steer-shared", "runtime_operator_steer", "Steer", 0, 0),
      { threadId: "thread-shared", turnId: "turn-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeContextCompactControlRequestFromWorkflowNode(
      makeWorkflowNode(
        "compact-shared",
        "runtime_context_compact",
        "Compact",
        0,
        0,
      ),
      { threadId: "thread-shared", turnId: "turn-shared" },
      { workflowGraphId: graphId, actor },
    ),
  ];

  assert.deepEqual(
    requests.map((request) => ({
      source: request.body.source,
      actor: request.body.actor,
      graphId: request.body.workflowGraphId,
      nodeId: request.body.workflowNodeId,
      threadId: request.threadId,
    })),
    [
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
    ],
  );
});

test("runtime_context_compact workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "compact-control",
    "runtime_context_compact",
    "Compact control",
    100,
    120,
  );
  const request = createRuntimeContextCompactControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      turnId: "turn-react-flow-1",
      reason: "reduce stale context",
      scope: "thread",
    },
    { workflowGraphId: "workflow.react-flow.context-compact-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_context_compact");
  assert.equal(request.nodeId, "compact-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.turnId, "turn-react-flow-1");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/compact");
  assert.equal(request.body.reason, "reduce stale context");
  assert.equal(request.body.scope, "thread");
  assert.equal(request.body.turnId, "turn-react-flow-1");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.context-compact-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND);
});

test("runtime_context_compact helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "compact-control-configured",
    "runtime_context_compact",
    "Compact control",
    100,
    120,
    {
      runtimeContextCompactEndpoint: "/runtime/{threadId}/compact/{turnId}",
      runtimeContextCompactThreadIdField: "runtime.threadId",
      runtimeContextCompactTurnIdField: "runtime.turnId",
      runtimeContextCompactReasonField: "operator.reason",
      runtimeContextCompactScopeField: "operator.scope",
      runtimeContextCompactWorkflowNodeId: "runtime.context-compact",
      runtimeContextCompactActor: "workflow-author",
    },
  );
  const request = createRuntimeContextCompactControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space", turnId: "turn/with/slash" },
      operator: { reason: "summarize stale context", scope: "thread" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn/with/slash");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/compact/turn%2Fwith%2Fslash",
  );
  assert.equal(request.body.reason, "summarize stale context");
  assert.equal(request.body.scope, "thread");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_operator_steer workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "steer-control",
    "runtime_operator_steer",
    "Steer control",
    100,
    120,
  );
  const request = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      turnId: "turn-react-flow-1",
      guidance: "focus on the failing assertion",
    },
    { workflowGraphId: "workflow.react-flow.operator-steer-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_operator_steer");
  assert.equal(request.nodeId, "steer-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.turnId, "turn-react-flow-1");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-react-flow-1/turns/turn-react-flow-1/steer",
  );
  assert.equal(request.body.guidance, "focus on the failing assertion");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.operator-steer-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_OPERATOR_STEER_COMPONENT_KIND);
});

test("runtime_operator_steer helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "steer-control-configured",
    "runtime_operator_steer",
    "Steer control",
    100,
    120,
    {
      runtimeOperatorSteerEndpoint: "/runtime/{threadId}/turns/{turnId}/steer",
      runtimeOperatorSteerThreadIdField: "runtime.threadId",
      runtimeOperatorSteerTurnIdField: "runtime.turnId",
      runtimeOperatorSteerGuidanceField: "operator.guidance",
      runtimeOperatorSteerWorkflowNodeId: "runtime.operator-steer",
      runtimeOperatorSteerActor: "workflow-author",
    },
  );
  const request = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space", turnId: "turn/with/slash" },
      operator: { guidance: "keep the proof scoped" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn/with/slash");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/turns/turn%2Fwith%2Fslash/steer",
  );
  assert.equal(request.body.guidance, "keep the proof scoped");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_operator_interrupt workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "interrupt-control",
    "runtime_operator_interrupt",
    "Interrupt control",
    100,
    120,
  );
  const request = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      turnId: "turn-react-flow-1",
      reason: "pause live validation from workflow",
    },
    { workflowGraphId: "workflow.react-flow.operator-interrupt-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_operator_interrupt");
  assert.equal(request.nodeId, "interrupt-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.turnId, "turn-react-flow-1");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-react-flow-1/turns/turn-react-flow-1/interrupt",
  );
  assert.equal(request.body.reason, "pause live validation from workflow");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.operator-interrupt-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND);
});

test("runtime_operator_interrupt helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "interrupt-control-configured",
    "runtime_operator_interrupt",
    "Interrupt control",
    100,
    120,
    {
      runtimeOperatorInterruptEndpoint:
        "/runtime/{threadId}/turns/{turnId}/interrupt",
      runtimeOperatorInterruptThreadIdField: "runtime.threadId",
      runtimeOperatorInterruptTurnIdField: "runtime.turnId",
      runtimeOperatorInterruptReasonField: "operator.reason",
      runtimeOperatorInterruptWorkflowNodeId: "runtime.operator-interrupt",
      runtimeOperatorInterruptActor: "workflow-author",
    },
  );
  const request = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space", turnId: "turn/with/slash" },
      operator: { reason: "pause the active turn" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn/with/slash");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/turns/turn%2Fwith%2Fslash/interrupt",
  );
  assert.equal(request.body.reason, "pause the active turn");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});
