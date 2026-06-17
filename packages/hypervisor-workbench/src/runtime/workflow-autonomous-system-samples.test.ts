import assert from "node:assert/strict";
import test from "node:test";
import { makeDefaultWorkflow } from "./workflow-defaults";
import { buildScratchWorkflow } from "./workflow-scratch-blueprints";
import { workflowLifecycleReadinessProjection } from "./workflow-lifecycle-readiness";
import { validateWorkflowProject } from "./workflow-validation";

test("repo-maintenance package sample projects to full lifecycle readiness", () => {
  const sample = buildScratchWorkflow(
    makeDefaultWorkflow("Repo Maintenance Autonomous System"),
    "repo-maintenance-package",
  );
  const validation = validateWorkflowProject(sample.workflow, sample.tests);
  const lifecycle = workflowLifecycleReadinessProjection({
    workflow: sample.workflow,
    tests: sample.tests,
    validationResult: validation,
  });

  assert.equal(lifecycle.packageArtifact, "Autonomous System Package");
  assert.equal(lifecycle.compatibility.projectedFromLegacyWorkflow, false);
  assert.equal(lifecycle.manifest.systemId, "system://repo-maintenance");
  assert.equal(lifecycle.manifest.worker.workerRef, "worker://repo-maintenance");
  assert.deepEqual(lifecycle.categories.map((category) => category.kind), [
    "run",
    "authority",
    "package",
    "evaluation",
    "deployment",
    "promotion",
  ]);
  assert.equal(
    lifecycle.categories.find((category) => category.kind === "package")
      ?.status,
    "ready",
  );
  assert.equal(
    lifecycle.categories.find((category) => category.kind === "evaluation")
      ?.status,
    "ready",
  );
  assert.equal(
    lifecycle.categories.find((category) => category.kind === "deployment")
      ?.status,
    "ready",
  );
  assert.equal(
    lifecycle.categories.find((category) => category.kind === "promotion")
      ?.status,
    "ready",
  );
  assert.deepEqual(lifecycle.manifest.capabilities.modelCapabilityRefs, [
    "model-capability:autopilot.mounted.local-coder",
  ]);
  assert.deepEqual(lifecycle.manifest.capabilities.toolCapabilityRefs, [
    "tool-capability:file.apply_patch",
    "tool-capability:file.read",
  ]);
  assert.deepEqual(lifecycle.manifest.authority.authorityScopeRequirements, [
    "scope:git.diff",
    "scope:model.invoke.local",
    "scope:workspace.read",
    "scope:workspace.write",
  ]);
});
