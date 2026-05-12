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
    "reasoning_delta",
    "tool_completed",
    "tool_failed",
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
  assert.match(exports, /workflow-runtime-event-projection/);
  assert.match(typeTest, /projects Thread\.events runtime events/);
  assert.match(typeTest, /approval_required/);
  assert.match(typeTest, /policy_blocked/);
});
