import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_USAGE_METER_COMPONENT_KIND,
  RUNTIME_USAGE_METER_SOURCE,
  RUNTIME_USAGE_METER_SOURCE_EVENT_KIND,
  RUNTIME_USAGE_METER_WORKFLOW_NODE_ID,
  WORKFLOW_RUNTIME_USAGE_METER_CONTROL_SCHEMA_VERSION,
  createRuntimeUsageMeterControlRequestFromWorkflowNode,
} from "./workflow-runtime-usage-control-nodes";

test("runtime_usage_meter workflow node builds a React Flow daemon usage request", () => {
  const node = makeWorkflowNode(
    "usage-meter",
    "runtime_usage_meter",
    "Usage meter",
    100,
    120,
  );
  const request = createRuntimeUsageMeterControlRequestFromWorkflowNode(
    node,
    { threadId: "thread-react-flow-usage-1" },
    { workflowGraphId: "workflow.react-flow.usage-meter-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_USAGE_METER_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_usage_meter");
  assert.equal(request.nodeId, "usage-meter");
  assert.equal(request.scope, "thread");
  assert.equal(request.threadId, "thread-react-flow-usage-1");
  assert.equal(request.runId, null);
  assert.equal(request.method, "GET");
  assert.match(
    request.endpoint,
    /^\/v1\/threads\/thread-react-flow-usage-1\/usage\?/,
  );
  assert.match(request.endpoint, /source=react_flow/);
  assert.match(request.endpoint, /workflow_graph_id=workflow\.react-flow\.usage-meter-proof/);
  assert.match(request.endpoint, /workflow_node_id=runtime\.usage-meter/);
  assert.match(request.endpoint, /usage_meter_scope=thread/);
  assert.equal(request.body, null);
  assert.equal(request.metadata.source, RUNTIME_USAGE_METER_SOURCE);
  assert.equal(request.metadata.actor, "operator");
  assert.equal(
    request.metadata.workflowGraphId,
    "workflow.react-flow.usage-meter-proof",
  );
  assert.equal(request.metadata.workflowNodeId, RUNTIME_USAGE_METER_WORKFLOW_NODE_ID);
  assert.equal(request.metadata.eventKind, RUNTIME_USAGE_METER_SOURCE_EVENT_KIND);
  assert.equal(request.metadata.componentKind, RUNTIME_USAGE_METER_COMPONENT_KIND);
  assert.equal(request.metadata.simulationMode, true);
});

test("runtime_usage_meter helper supports run scope and configurable fields", () => {
  const node = makeWorkflowNode(
    "usage-meter-configured",
    "runtime_usage_meter",
    "Usage meter",
    100,
    120,
    {
      runtimeUsageMeterEndpoint: "/runtime/runs/{runId}/usage",
      runtimeUsageMeterRunIdField: "runtime.runId",
      runtimeUsageMeterScope: "run",
      runtimeUsageMeterWorkflowNodeId: "runtime.usage-meter.run",
      runtimeUsageMeterActor: "workflow-author",
      runtimeUsageMeterSimulationMode: false,
    },
  );
  const request = createRuntimeUsageMeterControlRequestFromWorkflowNode(node, {
    runtime: { runId: "run with space" },
  });

  assert.equal(request.scope, "run");
  assert.equal(request.runId, "run with space");
  assert.equal(request.threadId, null);
  assert.match(request.endpoint, /^\/runtime\/runs\/run%20with%20space\/usage\?/);
  assert.match(request.endpoint, /simulation_mode=false/);
  assert.equal(request.metadata.actor, "workflow-author");
  assert.equal(request.metadata.workflowNodeId, "runtime.usage-meter.run");
  assert.equal(request.metadata.simulationMode, false);
});

test("runtime_usage_meter helper builds workflow-scope list usage requests", () => {
  const node = makeWorkflowNode(
    "usage-meter-workflow",
    "runtime_usage_meter",
    "Usage meter",
    100,
    120,
    {
      runtimeUsageMeterScope: "workflow",
      runtimeUsageMeterGroupBy: "thread",
    },
  );
  const request = createRuntimeUsageMeterControlRequestFromWorkflowNode(
    node,
    {},
    { workflowGraphId: "workflow.react-flow.usage-meter-proof" },
  );

  assert.equal(request.scope, "workflow");
  assert.equal(request.endpoint, "/v1/usage?source=react_flow&actor=operator&event_kind=RuntimeUsageTelemetry.Read&component_kind=usage_telemetry&payload_schema_version=ioi.runtime.usage-telemetry.v1&workflow_graph_id=workflow.react-flow.usage-meter-proof&workflow_node_id=runtime.usage-meter&usage_meter_scope=workflow&simulation_mode=true&group_by=thread");
});
