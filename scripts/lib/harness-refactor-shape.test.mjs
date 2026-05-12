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
  assert.ok(
    fs.existsSync(fullPath(relativePath)),
    `${relativePath} should exist`,
  );
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
  assert.match(
    source,
    pattern,
    `${relativePath} is missing its expected implementation surface`,
  );
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
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/statusPrimitives.tsx",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/types.ts",
    "packages/agent-ide/src/runtime/workflow-rail-search-model.ts",
    "packages/agent-ide/src/runtime/workflow-entrypoints-model.ts",
    "packages/agent-ide/src/runtime/workflow-file-bundle-model.ts",
    "packages/agent-ide/src/runtime/workflow-settings-model.ts",
    "packages/agent-ide/src/runtime/workflow-settings-harness-model.ts",
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
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx",
    /workflow-settings-harness-summary/,
    400,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts",
    /WorkflowSettingsHarnessPanelProps/,
    300,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx",
    /workflow-harness-activation-wizard/,
    500,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx",
    /workflow-harness-activation-gate-inspector/,
    500,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx",
    /workflow-harness-package-evidence-review/,
    600,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx",
    /workflow-harness-worker-binding-inspector/,
    600,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx",
    /workflow-harness-active-runtime-rollback-proof/,
    300,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx",
    /workflow-harness-active-runtime-binding/,
    800,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx",
    /workflow-harness-git-restore-proof/,
    200,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx",
    /workflow-harness-promotion-clusters/,
    300,
  );
  assertOwnsImplementation(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx",
    /workflow-harness-selector-live-promotion-readiness/,
    800,
  );
  {
    const settingsHarnessPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx",
    );
    const settingsHarnessTypes = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts",
    );
    const settingsHarnessActivationPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx",
    );
    const settingsHarnessActivationGatePanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx",
    );
    const settingsHarnessPackageEvidencePanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx",
    );
    const settingsHarnessWorkerBindingPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx",
    );
    const settingsHarnessActiveRuntimeRollbackPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx",
    );
    const settingsHarnessActiveRuntimeBindingPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx",
    );
    const settingsHarnessRollbackRestoreProofPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx",
    );
    const settingsHarnessPromotionPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx",
    );
    const settingsHarnessPromotionReadinessPanel = read(
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx",
    );
    for (const expectedInterface of [
      "WorkflowSettingsHarnessActivationProps",
      "WorkflowSettingsHarnessPackageRestoreProps",
      "WorkflowSettingsHarnessRollbackProps",
      "WorkflowSettingsHarnessWorkerBindingProps",
      "WorkflowSettingsHarnessPromotionProps",
      "WorkflowSettingsHarnessCallbacks",
    ]) {
      assert.match(
        settingsHarnessTypes,
        new RegExp(`export interface ${expectedInterface}`),
        `settings harness types should expose ${expectedInterface}`,
      );
    }
    assert.match(
      settingsHarnessPanel,
      /WorkflowSettingsHarnessActivationPanel/,
      "settings harness panel should delegate activation UI to its extracted component",
    );
    assert.match(
      settingsHarnessPanel,
      /WorkflowSettingsHarnessWorkerBindingPanel/,
      "settings harness panel should delegate worker binding UI to its extracted component",
    );
    assert.match(
      settingsHarnessPanel,
      /WorkflowSettingsHarnessPromotionPanel/,
      "settings harness panel should delegate promotion UI to its extracted component",
    );
    assert.doesNotMatch(
      settingsHarnessPanel,
      /workflow-harness-activation-gate-inspector/,
      "settings harness panel should not keep the activation gate inspector implementation inline",
    );
    assert.doesNotMatch(
      settingsHarnessPanel,
      /workflow-harness-worker-binding-inspector/,
      "settings harness panel should not keep the worker binding inspector implementation inline",
    );
    assert.doesNotMatch(
      settingsHarnessPanel,
      /workflow-harness-promotion-clusters/,
      "settings harness panel should not keep the promotion cluster implementation inline",
    );
    assert.match(
      settingsHarnessActivationPanel,
      /WorkflowSettingsHarnessActivationPanelProps/,
      "settings harness activation panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessActivationPanel,
      /WorkflowSettingsHarnessActivationGatePanel/,
      "settings harness activation panel should delegate gate evidence UI to its extracted component",
    );
    assert.match(
      settingsHarnessActivationGatePanel,
      /WorkflowSettingsHarnessActivationGatePanelProps/,
      "settings harness activation gate panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessActivationGatePanel,
      /workflow-harness-activation-gate-inspector/,
      "settings harness activation gate panel should own gate evidence inspector UI",
    );
    assert.match(
      settingsHarnessActivationGatePanel,
      /WorkflowSettingsHarnessPackageEvidencePanel/,
      "settings harness activation gate panel should delegate package evidence UI to its extracted component",
    );
    assert.match(
      settingsHarnessPackageEvidencePanel,
      /WorkflowSettingsHarnessPackageEvidencePanelProps/,
      "settings harness package evidence panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessPackageEvidencePanel,
      /workflow-harness-package-evidence-review/,
      "settings harness package evidence panel should own package evidence review UI",
    );
    assert.match(
      settingsHarnessPackageEvidencePanel,
      /workflow-harness-package-import-review/,
      "settings harness package evidence panel should own import review UI",
    );
    assert.doesNotMatch(
      settingsHarnessActivationGatePanel,
      /data-testid="workflow-harness-package-evidence-review"/,
      "settings harness activation gate panel should not keep package evidence implementation inline",
    );
    assert.doesNotMatch(
      settingsHarnessActivationPanel,
      /data-testid="workflow-harness-activation-gate-inspector"/,
      "settings harness activation panel should not keep gate evidence inspector implementation inline",
    );
    assert.match(
      settingsHarnessWorkerBindingPanel,
      /WorkflowSettingsHarnessWorkerBindingPanelProps/,
      "settings harness worker binding panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessWorkerBindingPanel,
      /WorkflowSettingsHarnessActiveRuntimeRollbackPanel/,
      "settings harness worker binding panel should delegate active runtime rollback UI to its extracted component",
    );
    assert.match(
      settingsHarnessActiveRuntimeRollbackPanel,
      /WorkflowSettingsHarnessActiveRuntimeRollbackPanelProps/,
      "settings harness active runtime rollback panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessActiveRuntimeRollbackPanel,
      /WorkflowSettingsHarnessActiveRuntimeBindingPanel/,
      "settings harness active runtime rollback panel should delegate active binding UI to its extracted component",
    );
    assert.match(
      settingsHarnessActiveRuntimeBindingPanel,
      /WorkflowSettingsHarnessActiveRuntimeBindingPanelProps/,
      "settings harness active runtime binding panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessActiveRuntimeBindingPanel,
      /workflow-harness-active-runtime-binding-deep-links/,
      "settings harness active runtime binding panel should own active binding deep links",
    );
    assert.doesNotMatch(
      settingsHarnessActiveRuntimeRollbackPanel,
      /data-testid="workflow-harness-active-runtime-binding"/,
      "settings harness active runtime rollback panel should not keep active binding implementation inline",
    );
    assert.match(
      settingsHarnessActiveRuntimeRollbackPanel,
      /WorkflowSettingsHarnessRollbackRestoreProofPanel/,
      "settings harness active runtime rollback panel should delegate restore proof UI to its extracted component",
    );
    assert.match(
      settingsHarnessRollbackRestoreProofPanel,
      /WorkflowSettingsHarnessRollbackRestoreProofPanelProps/,
      "settings harness rollback restore proof panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessRollbackRestoreProofPanel,
      /workflow-harness-git-restore-proof/,
      "settings harness rollback restore proof panel should own restore proof UI",
    );
    assert.doesNotMatch(
      settingsHarnessActiveRuntimeRollbackPanel,
      /workflow-harness-git-restore-proof/,
      "settings harness active runtime rollback panel should not keep restore proof inline",
    );
    assert.doesNotMatch(
      settingsHarnessWorkerBindingPanel,
      /workflow-harness-active-runtime-rollback-proof/,
      "settings harness worker binding panel should not keep active runtime rollback proof inline",
    );
    assert.doesNotMatch(
      settingsHarnessWorkerBindingPanel,
      /workflow-harness-git-restore-proof/,
      "settings harness worker binding panel should not keep git restore proof inline",
    );
    assert.match(
      settingsHarnessPromotionPanel,
      /WorkflowSettingsHarnessPromotionPanelProps/,
      "settings harness promotion panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessPromotionPanel,
      /WorkflowSettingsHarnessPromotionReadinessPanel/,
      "settings harness promotion panel should delegate live readiness UI to its extracted component",
    );
    assert.match(
      settingsHarnessPromotionReadinessPanel,
      /WorkflowSettingsHarnessPromotionReadinessPanelProps/,
      "settings harness promotion readiness panel should expose a typed prop boundary",
    );
    assert.match(
      settingsHarnessPromotionReadinessPanel,
      /workflow-harness-authority-gate-live/,
      "settings harness promotion readiness panel should own authority gate live UI",
    );
    assert.doesNotMatch(
      settingsHarnessPromotionPanel,
      /data-testid="workflow-harness-selector-live-promotion-readiness"/,
      "settings harness promotion panel should not keep live readiness implementation inline",
    );
    assert.doesNotMatch(
      settingsHarnessPanel,
      /\bany\b/,
      "settings harness panel should keep its extracted prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessActivationPanel,
      /\bany\b/,
      "settings harness activation panel should keep its prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessActivationGatePanel,
      /\bany\b/,
      "settings harness activation gate panel should keep its prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessPackageEvidencePanel,
      /\bany\b/,
      "settings harness package evidence panel should keep its prop boundary typed",
    );
    for (const [source, label] of [
      [settingsHarnessActivationPanel, "activation"],
      [settingsHarnessActivationGatePanel, "activation gate"],
      [settingsHarnessPackageEvidencePanel, "package evidence"],
      [settingsHarnessWorkerBindingPanel, "worker binding"],
      [settingsHarnessActiveRuntimeRollbackPanel, "active runtime rollback"],
      [settingsHarnessActiveRuntimeBindingPanel, "active runtime binding"],
      [settingsHarnessRollbackRestoreProofPanel, "rollback restore proof"],
      [settingsHarnessPromotionPanel, "promotion"],
      [settingsHarnessPromotionReadinessPanel, "promotion readiness"],
    ]) {
      assert.doesNotMatch(
        source,
        /from "\.\/settingsHarnessPanel"/,
        `settings harness ${label} panel should import shared contracts from settingsHarnessTypes`,
      );
      assert.match(
        source,
        /from "\.\/settingsHarnessTypes"/,
        `settings harness ${label} panel should import shared contracts from settingsHarnessTypes`,
      );
    }
    assert.doesNotMatch(
      settingsHarnessWorkerBindingPanel,
      /\bany\b/,
      "settings harness worker binding panel should keep its prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessActiveRuntimeRollbackPanel,
      /\bany\b/,
      "settings harness active runtime rollback panel should keep its prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessActiveRuntimeBindingPanel,
      /\bany\b/,
      "settings harness active runtime binding panel should keep its prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessRollbackRestoreProofPanel,
      /\bany\b/,
      "settings harness rollback restore proof panel should keep its prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessPromotionPanel,
      /\bany\b/,
      "settings harness promotion panel should keep its prop boundary typed",
    );
    assert.doesNotMatch(
      settingsHarnessPromotionReadinessPanel,
      /\bany\b/,
      "settings harness promotion readiness panel should keep its prop boundary typed",
    );
  }
  assertOwnsImplementation(
    "packages/agent-ide/src/runtime/workflow-settings-harness-model.ts",
    /workflowSettingsHarnessModel/,
    40,
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
    [
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx",
      5_830,
    ],
    ["scripts/lib/autopilot-gui-harness-validation/core.mjs", 11_775],
  ]) {
    assert.ok(
      lineCount(relativePath) <= maxLines,
      `${relativePath} exceeded its checkpoint size; extract into its domain modules before adding more behavior`,
    );
  }
});
