import assert from "node:assert/strict";
import test from "node:test";
import type {
  WorkflowBindingManifest,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRunSummary,
  WorkflowTestCase,
} from "../types/graph";
import { workflowFileBundleModel } from "./workflow-file-bundle-model";

function workflow(
  updates: Partial<WorkflowProject["metadata"]> = {},
): WorkflowProject {
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
        name: "Files workflow",
        description: "Files workflow",
      },
    },
    metadata: {
      id: "workflow",
      name: "Workflow",
      slug: "workflow",
      workflowKind: "agent_workflow",
      executionMode: "mock",
      ...updates,
    },
  } as unknown as WorkflowProject;
}

const tests = [
  {
    id: "test-a",
    name: "Test A",
    targetNodeIds: [],
    assertion: { kind: "node_exists" },
  },
] as unknown as WorkflowTestCase[];

const proposals = [
  {
    id: "proposal-a",
    title: "Proposal A",
    summary: "Update workflow",
    status: "open",
    createdAtMs: 1,
    boundedTargets: [],
  },
] as WorkflowProposal[];

const runs = [
  {
    id: "run-a",
    status: "passed",
    startedAtMs: 1,
    finishedAtMs: 2,
    nodeCount: 1,
    summary: "ok",
  },
  {
    id: "run-b",
    status: "failed",
    startedAtMs: 3,
    finishedAtMs: 4,
    nodeCount: 1,
    summary: "failed",
  },
] as WorkflowRunSummary[];

const bindingManifest = {
  schemaVersion: "workflow.bindings.v1",
  workflowId: "workflow",
  workflowSlug: "workflow",
  generatedAtMs: 1,
  environmentProfile: {},
  bindings: [],
  summary: {
    total: 3,
    live: 1,
    mock: 1,
    local: 1,
    ready: 2,
    blocked: 1,
    approvalRequired: 0,
  },
} as unknown as WorkflowBindingManifest;

const portablePackage = {
  packagePath: ".agents/workflows/workflow.portable/package.zip",
  manifestPath: ".agents/workflows/workflow.portable/manifest.json",
  manifest: {
    schemaVersion: "workflow.portable-package.v1",
    exportedAtMs: 1,
    workflowName: "Workflow",
    workflowSlug: "workflow",
    sourceWorkflowPath: ".agents/workflows/workflow.workflow.json",
    workflowChromeLocale: "en-US",
    readinessStatus: "passed",
    portable: true,
    blockers: [],
    files: [],
  },
} as unknown as WorkflowPortablePackage;

test("workflow file bundle model reports default sidecar paths and pending exports", () => {
  const model = workflowFileBundleModel({
    workflow: workflow(),
    tests,
    proposals,
    runs,
    portablePackage: null,
    bindingManifest: null,
  });

  assert.equal(
    model.workflowPath,
    ".agents/workflows/workflow.workflow.json",
  );
  assert.equal(model.dirty, false);
  assert.equal(model.testCount, 1);
  assert.equal(model.proposalCount, 1);
  assert.equal(model.runCount, 2);
  assert.equal(model.bindingManifestReady, null);
  assert.equal(model.portablePackageExported, false);
  assert.equal(model.pendingItems, 2);
  assert.deepEqual(
    model.items.map((item) => [item.id, item.path, item.status, item.ready]),
    [
      [
        "workflow-graph",
        ".agents/workflows/workflow.workflow.json",
        "saved",
        true,
      ],
      ["tests-sidecar", ".agents/workflows/workflow.tests.json", "1 test", true],
      [
        "proposal-sidecar",
        ".agents/workflows/workflow.proposals/",
        "1 proposal",
        true,
      ],
      ["run-sidecar", ".agents/workflows/workflow.runs/", "2 runs", true],
      [
        "binding-manifest",
        ".agents/workflows/workflow.bindings.json",
        "not generated",
        false,
      ],
      [
        "portable-package",
        ".agents/workflows/workflow.portable/",
        "not exported",
        false,
      ],
    ],
  );
});

test("workflow file bundle model reports dirty graph, binding readiness, and portable package", () => {
  const model = workflowFileBundleModel({
    workflow: workflow({
      dirty: true,
      gitLocation: ".agents/workflows/custom.workflow.json",
    }),
    tests: [],
    proposals: [],
    runs: [],
    portablePackage,
    bindingManifest,
  });

  assert.equal(model.workflowPath, ".agents/workflows/custom.workflow.json");
  assert.equal(model.dirty, true);
  assert.equal(model.bindingManifestReady, 2);
  assert.equal(model.bindingManifestTotal, 3);
  assert.equal(
    model.portablePackagePath,
    ".agents/workflows/workflow.portable/package.zip",
  );
  assert.equal(model.portablePackageExported, true);
  assert.equal(model.pendingItems, 0);
  assert.equal(
    model.items.find((item) => item.id === "workflow-graph")?.status,
    "modified",
  );
  assert.equal(
    model.items.find((item) => item.id === "binding-manifest")?.status,
    "2/3 ready",
  );
  assert.equal(
    model.items.find((item) => item.id === "portable-package")?.status,
    "portable · en-US",
  );
});

test("workflow file bundle model marks blocked portable packages pending", () => {
  const model = workflowFileBundleModel({
    workflow: workflow(),
    tests: [],
    proposals: [],
    runs: [],
    bindingManifest,
    portablePackage: {
      ...portablePackage,
      manifest: {
        ...portablePackage.manifest,
        portable: false,
        readinessStatus: "failed",
      },
    },
  });

  const portable = model.items.find((item) => item.id === "portable-package");
  assert.equal(portable?.ready, false);
  assert.equal(portable?.exported, true);
  assert.equal(portable?.status, "blocked: failed");
});
