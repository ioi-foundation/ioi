import assert from "node:assert/strict";
import test from "node:test";
import {
  WORKFLOW_NODE_DEFINITIONS,
  workflowNodeCreatorDefinitions,
} from "./workflow-node-registry";
import { WORKFLOW_CANVAS_NODE_TYPE_IDS } from "./workflow-canvas-node-types";

test("canvas custom node renderer covers every canonical workflow node type", () => {
  const canvasTypes = new Set(WORKFLOW_CANVAS_NODE_TYPE_IDS);

  for (const definition of WORKFLOW_NODE_DEFINITIONS) {
    assert.ok(
      canvasTypes.has(definition.type),
      `${definition.type} has a custom React Flow node renderer`,
    );
  }
});

test("creator presets never route to React Flow fallback nodes", () => {
  const canvasTypes = new Set(WORKFLOW_CANVAS_NODE_TYPE_IDS);

  for (const creator of workflowNodeCreatorDefinitions()) {
    assert.ok(
      canvasTypes.has(creator.type),
      `${creator.creatorId} (${creator.type}) has a custom React Flow node renderer`,
    );
  }
});
