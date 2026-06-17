import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowPortablePackage, WorkflowProject } from "../types/graph";
import type { WorkflowBindingRegistryRow } from "./workflow-rail-model";
import { workflowSettingsModel } from "./workflow-settings-model";

function workflow(updates: Partial<WorkflowProject> = {}): WorkflowProject {
  return {
    version: "1",
    nodes: [],
    edges: [],
    global_config: {
      env: "test",
      workflowChromeLocale: "es-ES",
      environmentProfile: {
        target: "staging",
        credentialScope: "staging",
        mockBindingPolicy: "block",
      },
      modelBindings: {
        planner: {
          modelId: "openai/gpt-5.1",
          required: true,
        },
      },
      requiredCapabilities: {
        reasoning: {
          required: true,
          bindingKey: "planner",
        },
        vision: {
          required: false,
        },
      },
      policy: {
        maxBudget: 12,
        maxSteps: 40,
        timeoutMs: 30_000,
      },
      contract: {
        developerBond: 1,
        adjudicationRubric: "test",
      },
      meta: {
        name: "Settings workflow",
        description: "Settings workflow",
      },
      production: {
        evaluationSetPath: ".agents/workflows/settings.tests.json",
        expectedTimeSavedMinutes: 17,
        mcpAccessReviewed: true,
      },
    },
    metadata: {
      id: "settings-workflow",
      name: "Settings workflow",
      slug: "settings-workflow",
      workflowKind: "agent_workflow",
      executionMode: "hybrid",
      branch: "feature/settings",
      dirty: true,
      readOnly: true,
    },
    ...updates,
  } as unknown as WorkflowProject;
}

const portablePackage = {
  manifest: {
    readinessStatus: "passed",
  },
} as WorkflowPortablePackage;

const bindingRow = {
  id: "model:model",
  nodeItem: {
    id: "model",
    name: "Model",
  },
  bindingKind: "model",
  ref: "planner",
  mode: "live",
  ready: true,
  scope: "reasoning",
  sideEffectClass: "none",
  approval: "none",
} as WorkflowBindingRegistryRow;

test("workflow settings model centralizes summary, environment, and production state", () => {
  const model = workflowSettingsModel({
    workflow: workflow(),
    validationResult: { status: "passed" } as never,
    readinessResult: { status: "warning" } as never,
    bindingRegistryRows: [bindingRow],
    portablePackage,
    criticalAiNodeCount: 2,
    mcpToolNodeCount: 1,
    hasErrorOrRetryPath: true,
  });

  assert.equal(model.metadata.workflowPath, ".agents/workflows/settings-workflow.workflow.json");
  assert.equal(model.metadata.branch, "feature/settings");
  assert.equal(model.metadata.dirty, true);
  assert.equal(model.workflowReadOnly, true);
  assert.equal(model.chromeLocale, "es-ES");
  assert.equal(model.environmentProfile.target, "staging");
  assert.equal(model.bindingRegistrySummary.ready, 1);
  assert.equal(model.bindingRegistrySummary.total, 1);
  assert.deepEqual(model.modelBindingItems.map(([key]) => key), ["planner"]);
  assert.deepEqual(model.requiredCapabilityItems.map(([key]) => key), [
    "reasoning",
  ]);
  assert.equal(model.policy.maxSteps, 40);
  assert.equal(model.packageReadinessStatus, "passed");
  assert.deepEqual(model.productionSummary, {
    errorPath: "graph path",
    evaluations: ".agents/workflows/settings.tests.json",
    valueEstimate: "17 min/run",
    mcpAccess: "reviewed",
  });
});

test("workflow settings model reports defaults for editable local workflows", () => {
  const model = workflowSettingsModel({
    workflow: workflow({
      global_config: {
        ...workflow().global_config,
        workflowChromeLocale: "not-real",
        environmentProfile: undefined,
        production: undefined,
      },
      metadata: {
        ...workflow().metadata,
        gitLocation: ".agents/workflows/custom.workflow.json",
        dirty: false,
        readOnly: false,
      },
    }),
    validationResult: null,
    readinessResult: null,
    bindingRegistryRows: [],
    portablePackage: null,
    criticalAiNodeCount: 1,
    mcpToolNodeCount: 0,
    hasErrorOrRetryPath: false,
  });

  assert.equal(model.metadata.workflowPath, ".agents/workflows/custom.workflow.json");
  assert.equal(model.workflowReadOnly, false);
  assert.equal(model.chromeLocale, "en-US");
  assert.equal(model.environmentProfile.target, "local");
  assert.equal(model.bindingRegistrySummary.total, 0);
  assert.equal(model.packageReadinessStatus, "not exported");
  assert.deepEqual(model.productionSummary, {
    errorPath: "not set",
    evaluations: "1 model node",
    valueEstimate: "not set",
    mcpAccess: "not used",
  });
});
