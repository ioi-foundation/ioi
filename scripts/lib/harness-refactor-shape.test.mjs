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

test("refactor facades stay thin and module directories exist", () => {
  for (const [relativePath, maxLines] of [
    ["crates/types/src/app/harness/mod.rs", 48],
    ["packages/agent-ide/src/runtime/harness-workflow.ts", 8],
    ["packages/agent-ide/src/features/Workflows/WorkflowRailPanel.tsx", 8],
    ["scripts/run-autopilot-gui-harness-validation.mjs", 8],
    ["apps/autopilot/src-tauri/src/orchestrator/store/mod.rs", 32],
  ]) {
    assertFacade(relativePath, maxLines);
  }

  for (const relativePath of [
    "crates/types/src/app/harness/core.rs",
    "crates/types/src/app/harness/components.rs",
    "crates/types/src/app/harness/slots.rs",
    "crates/types/src/app/harness/replay.rs",
    "crates/types/src/app/harness/receipts.rs",
    "crates/types/src/app/harness/worker_binding.rs",
    "crates/types/src/app/harness/activation.rs",
    "crates/types/src/app/harness/promotion.rs",
    "crates/types/src/app/harness/serde_bridge.rs",
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
    "apps/autopilot/src-tauri/src/orchestrator/store/events.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/artifacts.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/sessions.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/workbench_activity.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/local_engine.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/workflow_harness.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/knowledge.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/skills.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/attention.rs",
    "apps/autopilot/src-tauri/src/orchestrator/store/shared.rs",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/activationWizard.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/evidencePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/packagePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/replayPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/timelinePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/rollbackPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/statusPrimitives.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/types.ts",
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
});

test("core files do not grow past the refactor checkpoint without updating the guard", () => {
  for (const [relativePath, maxLines] of [
    ["packages/agent-ide/src/runtime/harness-workflow/core.ts", 12_200],
    ["packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx", 11_700],
    ["scripts/lib/autopilot-gui-harness-validation/core.mjs", 10_850],
    ["apps/autopilot/src-tauri/src/orchestrator/store/core.rs", 21_200],
  ]) {
    assert.ok(
      lineCount(relativePath) <= maxLines,
      `${relativePath} exceeded its checkpoint size; extract into its domain modules before adding more behavior`,
    );
  }
});
