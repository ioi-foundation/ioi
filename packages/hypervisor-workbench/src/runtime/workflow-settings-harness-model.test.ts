import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject } from "../types/graph";
import { workflowSettingsHarnessModel } from "./workflow-settings-harness-model";

function workflow(harness: WorkflowProject["metadata"]["harness"]): WorkflowProject {
  return {
    version: "1",
    nodes: [],
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
        name: "Harness settings workflow",
        description: "Harness settings workflow",
      },
    },
    metadata: {
      id: "harness-settings-workflow",
      name: "Harness settings workflow",
      slug: "harness-settings-workflow",
      workflowKind: "agent_workflow",
      executionMode: "hybrid",
      harness,
    },
  } as unknown as WorkflowProject;
}

test("workflow settings harness model summarizes blessed activation state", () => {
  const model = workflowSettingsHarnessModel({
    workflow: workflow({
      activationId: "activation-live",
      activationState: "validated",
      executionMode: "live",
      componentIds: ["planner", "worker", "verifier"],
    } as never),
    blessedHarnessWorkflow: true,
    harnessWorkerExecutionMode: "shadow",
    liveReadyHarnessComponents: 2,
    harnessComponentReadinessCount: 3,
    gatedHarnessClusterCount: 1,
    harnessPromotionClusterCount: 2,
  });

  assert.deepEqual(model, {
    templateLabel: "blessed",
    activationLabel: "activation-live",
    modeLabel: "live",
    componentCount: 3,
    liveReadyLabel: "2/3",
    gatedClustersLabel: "1/2",
  });
});

test("workflow settings harness model falls back to fork defaults", () => {
  const model = workflowSettingsHarnessModel({
    workflow: workflow({
      activationState: "blocked",
    } as never),
    blessedHarnessWorkflow: false,
    harnessWorkerExecutionMode: "gated",
    liveReadyHarnessComponents: 0,
    harnessComponentReadinessCount: 0,
    gatedHarnessClusterCount: 0,
    harnessPromotionClusterCount: 0,
  });

  assert.deepEqual(model, {
    templateLabel: "fork",
    activationLabel: "blocked",
    modeLabel: "gated",
    componentCount: 0,
    liveReadyLabel: "0/0",
    gatedClustersLabel: "0/0",
  });
});
