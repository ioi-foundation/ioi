import assert from "node:assert/strict";
import test from "node:test";

import {
  runtimeEventCursorFromRequest,
  usageRequestMetadataFromUrl,
} from "./runtime-request-metadata.mjs";

const retiredUsageRequestMetadataAliasKeys = [
  "eventKind",
  "componentKind",
  "payloadSchemaVersion",
  "workflowGraphId",
  "workflowNodeId",
  "usageMeterScope",
  "simulationMode",
];

test("usage request metadata emits canonical fields only", () => {
  const metadata = usageRequestMetadataFromUrl(
    new URL(
      "http://daemon.test/v1/runs/run-1/usage?workflow_graph_id=graph-1&workflow_node_id=node-1&source=rail&payload_schema_version=usage.v1&event_kind=usage.read&component_kind=usage_meter&usage_meter_scope=thread&simulation_mode=false",
    ),
  );

  assert.deepEqual(metadata, {
    source: "rail",
    actor: "operator",
    event_kind: "usage.read",
    component_kind: "usage_meter",
    payload_schema_version: "usage.v1",
    workflow_graph_id: "graph-1",
    workflow_node_id: "node-1",
    usage_meter_scope: "thread",
    simulation_mode: false,
  });
  for (const alias of retiredUsageRequestMetadataAliasKeys) {
    assert.equal(Object.hasOwn(metadata, alias), false, `retired alias ${alias} must be absent`);
  }
});

test("usage request metadata ignores retired URL aliases", () => {
  const metadata = usageRequestMetadataFromUrl(
    new URL(
      "http://daemon.test/v1/runs/run-1/usage?workflowNodeId=node-retired&workflowGraphId=graph-retired&payloadSchemaVersion=retired.v1&eventKind=retired.event&componentKind=retired.component&usageMeterScope=retired&simulationMode=false",
    ),
    { runtimeUsageTelemetrySchemaVersion: "usage.default.v1" },
  );

  assert.equal(metadata, null);
});

test("runtime event cursor request metadata uses canonical query fields", () => {
  assert.deepEqual(
    runtimeEventCursorFromRequest({
      request: { headers: {} },
      url: new URL("http://daemon.test/v1/runs/run-1/events?since_seq=7"),
    }),
    { since_seq: 7 },
  );
  assert.deepEqual(
    runtimeEventCursorFromRequest({
      request: { headers: {} },
      url: new URL("http://daemon.test/v1/runs/run-1/events?last_event_id=event-canonical"),
    }),
    { last_event_id: "event-canonical" },
  );
});

test("runtime event cursor request metadata ignores retired lastEventId query alias", () => {
  assert.deepEqual(
    runtimeEventCursorFromRequest({
      request: { headers: {} },
      url: new URL("http://daemon.test/v1/runs/run-1/events?lastEventId=event-retired"),
    }),
    { last_event_id: "" },
  );
  assert.deepEqual(
    runtimeEventCursorFromRequest({
      request: { headers: { "last-event-id": "event-header" } },
      url: new URL(
        "http://daemon.test/v1/runs/run-1/events?lastEventId=event-retired",
      ),
    }),
    { last_event_id: "event-header" },
  );
});
