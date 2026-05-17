import assert from "node:assert/strict";
import test from "node:test";
import { makeDefaultAgentHarnessWorkflow } from "./harness-workflow/core";
import type { WorkflowProject } from "../types/graph";
import {
  WORKFLOW_NODE_DEFINITIONS,
  workflowNodeCreatorDefinitions,
} from "./workflow-node-registry";
import {
  WORKFLOW_CANVAS_NODE_TYPE_IDS,
  WORKFLOW_CANVAS_RUNTIME_PROJECTION_NODE_TYPE_IDS,
} from "./workflow-canvas-node-types";

test("canvas custom node renderer covers every canonical workflow node type", () => {
  const canvasTypes = new Set<string>(WORKFLOW_CANVAS_NODE_TYPE_IDS);

  for (const definition of WORKFLOW_NODE_DEFINITIONS) {
    assert.ok(
      canvasTypes.has(definition.type),
      `${definition.type} has a custom React Flow node renderer`,
    );
  }
});

test("creator presets never route to React Flow fallback nodes", () => {
  const canvasTypes = new Set<string>(WORKFLOW_CANVAS_NODE_TYPE_IDS);

  for (const creator of workflowNodeCreatorDefinitions()) {
    assert.ok(
      canvasTypes.has(creator.type),
      `${creator.creatorId} (${creator.type}) has a custom React Flow node renderer`,
    );
  }
});

test("runtime projection node types use the custom canvas renderer", () => {
  const canvasTypes = new Set<string>(WORKFLOW_CANVAS_NODE_TYPE_IDS);

  for (const type of WORKFLOW_CANVAS_RUNTIME_PROJECTION_NODE_TYPE_IDS) {
    assert.ok(
      canvasTypes.has(type),
      `${type} has a custom React Flow node renderer`,
    );
  }
});

test("default agent harness never emits React Flow fallback nodes", () => {
  const canvasTypes = new Set<string>(WORKFLOW_CANVAS_NODE_TYPE_IDS);
  const workflow: WorkflowProject = makeDefaultAgentHarnessWorkflow(0);

  for (const node of workflow.nodes) {
    assert.ok(
      canvasTypes.has(node.type),
      `${node.id} (${node.type}) has a custom React Flow node renderer`,
    );
  }
});
