import assert from "node:assert/strict";
import test from "node:test";

import { createWorkflowProjectMaterializationPlan } from "./workflowProjectMaterializationPlan.ts";

test("workflow project materialization plan emits package, eval, and receipt artifacts", () => {
  const plan = createWorkflowProjectMaterializationPlan({
    workflowId: "workflow:repo-agent",
    workflowName: "Repo Agent",
    workflowPath: ".agents/workflows/repo-agent.workflow.json",
    projectRoot: ".",
    projectName: "Repo Agent!",
    dryRun: false,
    workflowSnapshot: {
      id: "workflow:repo-agent",
      nodes: [{ id: "manual-input", kind: "manual_input" }],
      edges: [],
    },
    testsSnapshot: {
      cases: [],
    },
    requestedAtMs: 1_763_000_000_000,
  });

  assert.equal(plan.rootPath, ".agents/materialized-projects/repo-agent");
  assert.equal(
    plan.manifestPath,
    ".agents/materialized-projects/repo-agent/autonomous-system.manifest.json",
  );
  assert.equal(
    plan.workflowPath,
    ".agents/materialized-projects/repo-agent/workflow.workflow.json",
  );
  assert.equal(
    plan.evalPath,
    ".agents/materialized-projects/repo-agent/evals/fixture.json",
  );
  assert.equal(
    plan.expectedReceiptsPath,
    ".agents/materialized-projects/repo-agent/receipts/expected-receipts.json",
  );

  const manifestFile = plan.files.find((file) => file.path === plan.manifestPath);
  const receiptFile = plan.files.find((file) => file.path === plan.expectedReceiptsPath);
  assert.ok(manifestFile);
  assert.ok(receiptFile);

  const manifest = JSON.parse(manifestFile.content);
  const receipts = JSON.parse(receiptFile.content);
  assert.equal(manifest.schemaVersion, "ioi.autonomous-system-package.v1");
  assert.equal(manifest.runtimeTruth, "daemon-runtime");
  assert.equal(manifest.lifecycle.packaged, true);
  assert.equal(manifest.lifecycle.bound, false);
  assert.equal(receipts.receipts[0].kind, "workflow_project_materialized");
  assert.equal(receipts.receipts[1].kind, "workspace_open");
});
