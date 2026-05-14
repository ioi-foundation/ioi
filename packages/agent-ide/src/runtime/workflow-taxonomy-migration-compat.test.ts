import assert from "node:assert/strict";
import test from "node:test";
import { makeDefaultWorkflow } from "./workflow-defaults";
import { workflowPrimitiveConfigProjection } from "./workflow-primitive-config-projection";
import type { Node } from "../types/graph";

function legacyStateNode(
  id: string,
  stateOperation: string,
): Node {
  return {
    id,
    type: "state",
    name: stateOperation,
    family: "state",
    status: "idle",
    x: 0,
    y: 0,
    inputs: [],
    outputs: [],
    ports: [],
    config: {
      kind: "state",
      logic: {
        stateKey: id,
        stateOperation: stateOperation as any,
      },
      law: {},
    },
  };
}

test("projection compatibility keeps legacy workflow node kinds and logic unchanged", () => {
  const workflow = makeDefaultWorkflow("Legacy projection compatibility");
  workflow.nodes = [
    legacyStateNode("legacy-memory-search", "memory_search"),
    legacyStateNode("legacy-subagent-spawn", "subagent_spawn"),
    legacyStateNode("legacy-mcp-invoke", "mcp_tool_invoke"),
  ];
  const before = JSON.stringify(workflow);

  const projections = workflow.nodes.map((node) =>
    workflowPrimitiveConfigProjection(
      node.type as any,
      node.config?.logic ?? {},
    ),
  );

  assert.equal(JSON.stringify(workflow), before);
  assert.deepEqual(
    projections.map((projection) => projection.canonicalPrimitive),
    ["memory", "worker", "tool_pack"],
  );
  assert.deepEqual(
    workflow.nodes.map((node) => node.type),
    ["state", "state", "state"],
  );
  assert.deepEqual(
    projections.map((projection) => projection.runtimeContract),
    ["workflow.node.state", "workflow.node.state", "workflow.node.state"],
  );
});
