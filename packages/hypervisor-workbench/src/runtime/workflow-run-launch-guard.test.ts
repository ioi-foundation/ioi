import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject, WorkflowValidationResult } from "../types/graph";
import { workflowRunLaunchGuard } from "./workflow-run-launch-guard.ts";

const passedValidation: WorkflowValidationResult = {
  status: "passed",
  errors: [],
  warnings: [],
  blockedNodes: [],
  missingConfig: [],
  unsupportedRuntimeNodes: [],
  policyRequiredNodes: [],
  coverageByNodeId: {},
  connectorBindingIssues: [],
  executionReadinessIssues: [],
  verificationIssues: [],
};

function workflow(
  nodes: WorkflowProject["nodes"],
): WorkflowProject {
  return {
    version: "1",
    nodes,
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
      executionMode: "local",
    },
  } as WorkflowProject;
}

test("blocks blank workflow runs before runtime activation", () => {
  const guard = workflowRunLaunchGuard(workflow([]), passedValidation);

  assert.equal(guard.status, "blocked");
  assert.equal(
    guard.message,
    "Run needs at least one workflow node before activation.",
  );
  assert.equal(guard.validation.status, "blocked");
  assert.deepEqual(
    guard.validation.errors.map((issue) => issue.code),
    [
      "empty_workflow_run_blocked",
      "missing_start_node",
      "missing_output_node",
    ],
  );
});

test("blocks validation failures before runtime activation", () => {
  const validation: WorkflowValidationResult = {
    ...passedValidation,
    status: "failed",
    errors: [
      {
        code: "invalid_edge",
        message: "An edge references a missing node.",
      },
    ],
  };
  const guard = workflowRunLaunchGuard(
    workflow([
      { id: "start", type: "trigger", name: "Start", x: 0, y: 0 },
      { id: "output", type: "output", name: "Output", x: 120, y: 0 },
    ]),
    validation,
  );

  assert.equal(guard.status, "blocked");
  assert.equal(guard.validation, validation);
  assert.equal(guard.message, "An edge references a missing node.");
});

test("allows runnable workflow topology after validation passes", () => {
  const guard = workflowRunLaunchGuard(
    workflow([
      { id: "start", type: "trigger", name: "Start", x: 0, y: 0 },
      { id: "output", type: "output", name: "Output", x: 120, y: 0 },
    ]),
    passedValidation,
  );

  assert.equal(guard.status, "ready");
  assert.equal(guard.validation, passedValidation);
  assert.equal(guard.message, null);
});
