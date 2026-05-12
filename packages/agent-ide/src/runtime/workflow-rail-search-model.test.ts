import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject, WorkflowTestCase } from "../types/graph";
import { workflowRailSearchModel } from "./workflow-rail-search-model";

const workflow = {
  version: "1",
  nodes: [
    {
      id: "source",
      type: "source",
      name: "Source payload",
      x: 0,
      y: 0,
      status: "idle",
      config: {
        logic: {
          payload: "issue payload",
        },
      },
    },
    {
      id: "model",
      type: "model_call",
      name: "Model answer",
      x: 0,
      y: 0,
      status: "success",
      config: {
        logic: {
          model: "gpt-test",
          prompt: "summarize issue",
        },
      },
    },
    {
      id: "output",
      type: "output",
      name: "Markdown report",
      x: 0,
      y: 0,
      status: "blocked",
      config: {
        logic: {
          format: "markdown",
          deliveryTarget: {
            targetKind: "artifact",
          },
        },
      },
    },
  ],
  edges: [],
  global_config: {
    env: "test",
    modelBindings: {},
    requiredCapabilities: {},
    policy: {
      maxBudget: 1,
      maxSteps: 4,
      timeoutMs: 1_000,
    },
    contract: {
      developerBond: 1,
      adjudicationRubric: "test",
    },
    meta: {
      name: "Search workflow",
      description: "Search workflow",
    },
  },
  metadata: {
    id: "workflow",
    name: "Workflow",
    slug: "workflow",
    workflowKind: "agent_workflow",
    executionMode: "mock",
  },
} as unknown as WorkflowProject;

const tests = [
  {
    id: "test-model",
    name: "Model emits final answer",
    targetNodeIds: ["model"],
    assertion: { kind: "schema_matches" },
    status: "passed",
    lastMessage: "model matched schema",
  },
  {
    id: "test-output",
    name: "Report contains markdown summary",
    targetNodeIds: ["output"],
    assertion: { kind: "output_contains" },
    status: "failed",
    lastMessage: "summary missing",
  },
] as WorkflowTestCase[];

test("workflow rail search model summarizes indexed workflow content", () => {
  const model = workflowRailSearchModel({
    workflow,
    tests,
    searchQuery: "",
    visibleLimit: 3,
  });

  assert.equal(model.normalizedSearch, "");
  assert.equal(model.hasQuery, false);
  assert.equal(model.totalNodes, 3);
  assert.equal(model.totalTests, 2);
  assert.equal(model.outputCount, 1);
  assert.equal(model.totalIndexed, 6);
  assert.equal(model.results.length, 6);
  assert.equal(model.visibleResults.length, 3);
  assert.equal(model.hiddenResultCount, 3);
  assert.equal(model.actionableResultCount, 6);
  assert.deepEqual(model.resultKindCounts, {
    Node: 3,
    Test: 2,
    Output: 1,
  });
  assert.deepEqual(
    model.resultGroups.map((group) => [group.resultKind, group.count]),
    [
      ["Node", 3],
      ["Test", 2],
      ["Output", 1],
    ],
  );
});

test("workflow rail search model normalizes and filters by node, test, and output fields", () => {
  const model = workflowRailSearchModel({
    workflow,
    tests,
    searchQuery: "  MARKDOWN  ",
  });

  assert.equal(model.normalizedSearch, "markdown");
  assert.equal(model.hasQuery, true);
  assert.deepEqual(
    model.results.map((item) => item.id),
    ["node-output", "test-test-output", "output-output"],
  );
  assert.deepEqual(
    model.results.map((item) => item.nodeId),
    ["output", "output", "output"],
  );
});

test("workflow rail search model exposes test target nodes as actions", () => {
  const model = workflowRailSearchModel({
    workflow,
    tests,
    searchQuery: "schema_matches",
  });

  assert.equal(model.results.length, 1);
  assert.equal(model.results[0]?.id, "test-test-model");
  assert.equal(model.results[0]?.actionable, true);
  assert.equal(model.results[0]?.nodeId, "model");
});

test("workflow rail search model reports an empty filtered state", () => {
  const model = workflowRailSearchModel({
    workflow,
    tests,
    searchQuery: "does-not-exist",
  });

  assert.equal(model.results.length, 0);
  assert.equal(model.visibleResults.length, 0);
  assert.equal(model.hiddenResultCount, 0);
  assert.equal(model.emptyTitle, "No matches");
  assert.match(model.emptyDescription, /node name/);
});
