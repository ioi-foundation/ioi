import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");

function fullPath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function read(relativePath) {
  return fs.readFileSync(fullPath(relativePath), "utf8");
}

function lineCount(relativePath) {
  return read(relativePath).split("\n").length;
}

function assertExists(relativePath) {
  assert.ok(fs.existsSync(fullPath(relativePath)), `${relativePath} should exist`);
}

function assertFacade(relativePath, maxLines) {
  assertExists(relativePath);
  assert.ok(
    lineCount(relativePath) <= maxLines,
    `${relativePath} should stay a small compatibility facade`,
  );
}

function assertOwnsImplementation(relativePath, pattern, minLines = 8) {
  assertExists(relativePath);
  const source = read(relativePath);
  assert.ok(
    lineCount(relativePath) >= minLines,
    `${relativePath} should contain extracted implementation, not just a placeholder`,
  );
  assert.match(source, pattern, `${relativePath} is missing its expected implementation surface`);
}

test("runtime and workflow harness compatibility facades stay thin", () => {
  for (const [relativePath, maxLines] of [
    ["crates/types/src/app/harness/mod.rs", 48],
    ["packages/agent-ide/src/runtime/harness-workflow.ts", 8],
    ["packages/agent-ide/src/features/Workflows/WorkflowRailPanel.tsx", 8],
    ["scripts/run-autopilot-gui-harness-validation.mjs", 12],
  ]) {
    assertFacade(relativePath, maxLines);
  }
});

test("workflow harness runtime modules remain split by concern", () => {
  for (const relativePath of [
    "packages/agent-ide/src/runtime/harness-workflow/constants.ts",
    "packages/agent-ide/src/runtime/harness-workflow/hashing.ts",
    "packages/agent-ide/src/runtime/harness-workflow/package-evidence.ts",
    "packages/agent-ide/src/runtime/harness-workflow/worker-binding.ts",
    "packages/agent-ide/src/runtime/harness-workflow/activation.ts",
    "packages/agent-ide/src/runtime/harness-workflow/rollback.ts",
    "packages/agent-ide/src/runtime/harness-workflow/replay.ts",
    "packages/agent-ide/src/runtime/harness-workflow/promotion.ts",
    "packages/agent-ide/src/runtime/harness-workflow/adapter-results.ts",
    "packages/agent-ide/src/runtime/harness-workflow/graph-builder.ts",
    "packages/agent-ide/src/runtime/harness-workflow/inspection.ts",
  ]) {
    assertExists(relativePath);
  }

  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/harness-workflow/constants.ts",
    /DEFAULT_AGENT_HARNESS_WORKFLOW_ID/,
    20,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/harness-workflow/hashing.ts",
    /stableContentHash/,
    20,
  );
});

test("workflow rail modules own extracted implementation", () => {
  for (const relativePath of [
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/activationWizard.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/evidencePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/packagePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/replayPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/timelinePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/rollbackPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/statusPrimitives.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/types.ts",
    "packages/agent-ide/src/runtime/workflow-rail-search-model.ts",
    "packages/agent-ide/src/runtime/workflow-entrypoints-model.ts",
    "packages/agent-ide/src/runtime/workflow-file-bundle-model.ts",
    "packages/agent-ide/src/runtime/workflow-settings-model.ts",
    "packages/agent-ide/src/runtime/workflow-readiness-model.ts",
    "packages/agent-ide/src/runtime/workflow-test-readiness-model.ts",
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
  ]) {
    assertExists(relativePath);
  }

  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/types.ts",
    /WorkflowHarnessActivationWizardStep/,
    40,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/statusPrimitives.tsx",
    /workflowHarnessPackageDeepLinkTarget/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx",
    /workflow-rail-search-results/,
    60,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-rail-search-model.ts",
    /workflowRailSearchModel/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx",
    /workflow-schedules-list/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-entrypoints-model.ts",
    /workflowEntrypointsModel/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx",
    /workflow-files-list/,
    30,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-file-bundle-model.ts",
    /workflowFileBundleModel/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx",
    /workflow-settings-production-profile/,
    200,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-settings-model.ts",
    /workflowSettingsModel/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
    /workflow-readiness-scheduler-lanes/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-readiness-model.ts",
    /workflowReadinessModel/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx",
    /workflow-unit-test-list/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-test-readiness-model.ts",
    /workflowTestReadinessModel/,
    80,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    /workflow-runs-list/,
    200,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
    /workflowRunHistoryModel/,
    80,
  );
});

test("GUI harness validation modules remain split by concern", () => {
  for (const relativePath of [
    "scripts/lib/autopilot-gui-harness-validation/args.mjs",
    "scripts/lib/autopilot-gui-harness-validation/desktop.mjs",
    "scripts/lib/autopilot-gui-harness-validation/retained-query-evidence.mjs",
    "scripts/lib/autopilot-gui-harness-validation/artifacts.mjs",
    "scripts/lib/autopilot-gui-harness-validation/promotion-proof.mjs",
    "scripts/lib/autopilot-gui-harness-validation/rollback-proof.mjs",
    "scripts/lib/autopilot-gui-harness-validation/assessment.mjs",
  ]) {
    assertExists(relativePath);
  }

  assertOwnsImplementation(
    "scripts/lib/autopilot-gui-harness-validation/args.mjs",
    /parseArgs/,
    30,
  );
  assertOwnsImplementation(
    "scripts/lib/autopilot-gui-harness-validation/artifacts.mjs",
    /writeBundle/,
    8,
  );
  assertOwnsImplementation(
    "scripts/lib/autopilot-gui-harness-validation/desktop.mjs",
    /typeQuery/,
    200,
  );
});

test("core files do not grow past the refactor checkpoint without updating the guard", () => {
  for (const [relativePath, maxLines] of [
    ["packages/agent-ide/src/runtime/harness-workflow/core.ts", 13_500],
    ["packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx", 10_350],
    ["scripts/lib/autopilot-gui-harness-validation/core.mjs", 11_750],
  ]) {
    assert.ok(
      lineCount(relativePath) <= maxLines,
      `${relativePath} exceeded its checkpoint size; extract into its domain modules before adding more behavior`,
    );
  }
});
