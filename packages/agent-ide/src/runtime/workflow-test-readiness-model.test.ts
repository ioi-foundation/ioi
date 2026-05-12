import assert from "node:assert/strict";
import test from "node:test";
import type {
  WorkflowProject,
  WorkflowTestCase,
  WorkflowTestRunResult,
} from "../types/graph";
import { workflowTestReadinessModel } from "./workflow-test-readiness-model";

const workflow = {
  version: "1",
  nodes: [
    {
      id: "trigger",
      type: "trigger",
      name: "Trigger",
      x: 0,
      y: 0,
      status: "idle",
    },
    {
      id: "model",
      type: "model_call",
      name: "Model",
      x: 0,
      y: 0,
      status: "success",
    },
    {
      id: "output",
      type: "output",
      name: "Output",
      x: 0,
      y: 0,
      status: "blocked",
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
      name: "Test workflow",
      description: "Test workflow",
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
    name: "Model emits structured answer",
    targetNodeIds: ["model"],
    assertion: { kind: "schema_matches" },
    status: "passed",
  },
  {
    id: "test-output",
    name: "Output contains summary",
    targetNodeIds: ["output"],
    assertion: { kind: "output_contains" },
    status: "failed",
    lastMessage: "summary missing",
  },
  {
    id: "test-trigger",
    name: "Trigger exists",
    targetNodeIds: ["trigger"],
    assertion: { kind: "node_exists" },
    status: "blocked",
  },
] as WorkflowTestCase[];

const testResult = {
  runId: "run",
  status: "failed",
  startedAtMs: 1,
  finishedAtMs: 2,
  passed: 1,
  failed: 1,
  blocked: 1,
  skipped: 0,
  results: [
    {
      testId: "test-output",
      status: "passed",
      message: "latest output passed",
      coveredNodeIds: ["output"],
    },
  ],
} as WorkflowTestRunResult;

test("workflow test readiness model summarizes coverage and status counts", () => {
  const model = workflowTestReadinessModel({
    workflow,
    tests,
    testResult,
    searchQuery: "",
  });

  assert.equal(model.totalTests, 3);
  assert.deepEqual([...model.coveredNodeIds].sort(), [
    "model",
    "output",
    "trigger",
  ]);
  assert.equal(model.uncoveredNodes.length, 0);
  assert.equal(model.statusCounts.passed, 1);
  assert.equal(model.statusCounts.failed, 1);
  assert.equal(model.statusCounts.blocked, 1);
});

test("workflow test readiness model filters by assertion, status, and target id", () => {
  assert.deepEqual(
    workflowTestReadinessModel({
      workflow,
      tests,
      testResult,
      searchQuery: "schema_matches",
    }).rows.map((row) => row.test.id),
    ["test-model"],
  );
  assert.deepEqual(
    workflowTestReadinessModel({
      workflow,
      tests,
      testResult,
      searchQuery: "blocked",
    }).rows.map((row) => row.test.id),
    ["test-trigger"],
  );
  assert.deepEqual(
    workflowTestReadinessModel({
      workflow,
      tests,
      testResult,
      searchQuery: "output",
    }).rows.map((row) => row.test.id),
    ["test-output"],
  );
});

test("workflow test readiness model binds latest results and target nodes to rows", () => {
  const model = workflowTestReadinessModel({
    workflow,
    tests,
    testResult,
    searchQuery: "summary",
  });

  assert.equal(model.rows.length, 1);
  assert.equal(model.rows[0]?.test.id, "test-output");
  assert.equal(model.rows[0]?.targetNode?.id, "output");
  assert.equal(model.rows[0]?.status, "passed");
  assert.equal(model.rows[0]?.message, "latest output passed");
  assert.equal(model.resultById.get("test-output")?.message, "latest output passed");
});

test("workflow test readiness model reports uncovered workflow nodes", () => {
  const model = workflowTestReadinessModel({
    workflow,
    tests: tests.slice(0, 1),
    testResult: null,
    searchQuery: "  MODEL  ",
  });

  assert.equal(model.normalizedSearch, "model");
  assert.deepEqual(
    model.uncoveredNodes.map((node) => node.id),
    ["trigger", "output"],
  );
  assert.equal(model.rows[0]?.message, "1 covered targets");
});
