#!/usr/bin/env node
import { existsSync } from "node:fs";
import { join } from "node:path";

import { cleanupAutopilotCampaignProcesses } from "./lib/autopilot-gui-chat-ux-campaign-processes.mjs";
import {
  BASELINE_VERDICTS,
  CURSOR_EVIDENCE_ROOT,
  CURSOR_GUIDE_PATH,
  CURSOR_INPUTS,
  CURSOR_PLAYBOOK_PATH,
  ROW_DEFINITIONS,
  cleanDir,
  commandEvidence,
  ensureDir,
  rel,
  repoRoot,
  runCommand,
  summarizeChecks,
  timestamp,
  writeJson,
  writeMarkdown,
} from "./lib/cursor-substrate-absorption/common.mjs";
import {
  runBrowserAutomationGuiProof,
  runCanvasArtifactSupportProof,
  runDetachedWorkerLifecycleProof,
  runEvidenceSeedProof,
  runIntegratedSoakProof,
  runLspWatcherIsolationProof,
  runMcpOAuthRefreshLeaseProof,
  runProductDecisionStage,
  runSandboxPolicyProof,
  runShadowWorkspaceProof,
} from "./lib/cursor-substrate-absorption/proofs.mjs";

const evidenceRoot = process.env.AUTOPILOT_CURSOR_SUBSTRATE_EVIDENCE_ROOT ||
  join(repoRoot, CURSOR_EVIDENCE_ROOT);
const finalManifestPath = join(evidenceRoot, "cursor-substrate-absorption-final-manifest.json");
const finalVerdictPath = join(evidenceRoot, "final-cursor-substrate-absorption-verdict.md");

const argv = process.argv.slice(2);
const runMode = argv.includes("--run");
const preflightMode = argv.includes("--preflight") || !runMode;
const fresh = argv.includes("--fresh") || runMode;

const rowById = Object.fromEntries(ROW_DEFINITIONS.map((row) => [row.id, row]));

const finalStatusByRow = {
  "CURSOR-SUBSTRATE-000": "supporting_pass",
  "CURSOR-SUBSTRATE-001": "headless_pass",
  "CURSOR-SUBSTRATE-002": "headless_pass",
  "CURSOR-SUBSTRATE-003": "sandbox_effect_pass",
  "CURSOR-SUBSTRATE-004": "headless_pass",
  "CURSOR-SUBSTRATE-005": "supporting_pass_with_product_decision",
  "CURSOR-SUBSTRATE-006": "supporting_pass_with_product_decision",
  "CURSOR-SUBSTRATE-007": "supporting_pass_with_product_decision",
  "CURSOR-SUBSTRATE-008": "live_pass",
  "CURSOR-SUBSTRATE-009": "cross_client_pass",
  "CURSOR-SUBSTRATE-010": "rejected_with_product_decision",
  "CURSOR-SUBSTRATE-011": "deferred_optional",
  "CURSOR-SUBSTRATE-012": "supporting_pass_with_product_decision",
};

function requireBaseline(path) {
  return { path, exists: existsSync(join(repoRoot, path)) };
}

function stage(id, title, rowIds, evidenceKind, fn) {
  return { id, title, rowIds, evidenceKind, fn };
}

function stageRows(rowIds, passed) {
  return rowIds.map((id) => ({
    ...rowById[id],
    status: passed ? finalStatusByRow[id] : "gap",
  }));
}

function proofPassed(result) {
  return Boolean(
    result.passed ??
      result.summary?.passed ??
      result.checks?.every?.((check) => check.passed),
  );
}

function buildStages(campaignDir) {
  const retrievalReviewRows = [
    rowById["CURSOR-SUBSTRATE-005"],
    rowById["CURSOR-SUBSTRATE-006"],
  ];
  const longTailRows = [
    rowById["CURSOR-SUBSTRATE-010"],
    rowById["CURSOR-SUBSTRATE-011"],
    rowById["CURSOR-SUBSTRATE-012"],
  ];
  const stages = [
    stage(
      "stage00-cursor-evidence-schema-polish",
      "Cursor evidence/schema polish and campaign seed",
      ["CURSOR-SUBSTRATE-000"],
      "support",
      runEvidenceSeedProof,
    ),
    stage(
      "stage01-shadow-workspace-dry-run-validation",
      "Shadow workspace dry-run validation",
      ["CURSOR-SUBSTRATE-001"],
      "headless",
      runShadowWorkspaceProof,
    ),
    stage(
      "stage02-lsp-watcher-isolation",
      "LSP and watcher isolation for background worktrees",
      ["CURSOR-SUBSTRATE-002"],
      "headless",
      runLspWatcherIsolationProof,
    ),
    stage(
      "stage03-local-sandbox-policy-model",
      "Local sandbox policy model",
      ["CURSOR-SUBSTRATE-003"],
      "sandbox",
      runSandboxPolicyProof,
    ),
    stage(
      "stage04-mcp-oauth-refresh-lease",
      "MCP OAuth refresh lease and concurrent connection stability",
      ["CURSOR-SUBSTRATE-004"],
      "headless",
      runMcpOAuthRefreshLeaseProof,
    ),
    stage(
      "stage05-retrieval-and-commit-review-decisions",
      "Local retrieval/indexing and commit-review product decisions",
      ["CURSOR-SUBSTRATE-005", "CURSOR-SUBSTRATE-006"],
      "support",
      (dir) => runProductDecisionStage(dir, retrievalReviewRows),
    ),
    stage(
      "stage06-canvas-artifact-ux-decision",
      "Agent-authored interactive canvas/artifact UX decision",
      ["CURSOR-SUBSTRATE-007"],
      "support",
      runCanvasArtifactSupportProof,
    ),
    stage(
      "stage07-browser-automation-managed-viewport",
      "Browser automation overlay versus managed viewport UX",
      ["CURSOR-SUBSTRATE-008"],
      "live_gui",
      runBrowserAutomationGuiProof,
    ),
    stage(
      "stage08-detached-worker-cross-client-recovery",
      "Detached worker lifecycle and cross-client recovery",
      ["CURSOR-SUBSTRATE-009"],
      "cross_client",
      runDetachedWorkerLifecycleProof,
    ),
    stage(
      "stage09-long-tail-cursor-product-decisions",
      "Long-tail Cursor rows and product decisions",
      ["CURSOR-SUBSTRATE-010", "CURSOR-SUBSTRATE-011", "CURSOR-SUBSTRATE-012"],
      "support",
      (dir) => runProductDecisionStage(dir, longTailRows),
    ),
  ];
  stages.push(stage(
    "stage10-integrated-cursor-absorption-soak",
    "Integrated Cursor absorption soak and final cleanup",
    ROW_DEFINITIONS.map((row) => row.id),
    "integrated_soak",
    async (dir, results) => {
      const soak = runIntegratedSoakProof(dir, results);
      const cleanup = await cleanupAutopilotCampaignProcesses({
        outputDir: dir,
        phase: "cursor-substrate-absorption-final",
      });
      const checks = [
        ...(soak.checks ?? []),
        {
          label: "Autopilot/runtime bridge/daemon/browser/helper cleanup proof passed",
          passed: cleanup.ok,
          details: cleanup,
        },
      ];
      return {
        ...soak,
        checks,
        summary: summarizeChecks(checks),
        artifacts: {
          ...(soak.artifacts ?? {}),
          cleanup: rel(join(dir, "process-cleanup-cursor-substrate-absorption-final.json")),
        },
      };
    },
  ));
  return stages.map((item, index) => ({
    ...item,
    outputDir: join(campaignDir, `${String(index).padStart(2, "0")}-${item.id}`),
  }));
}

async function runStage(item, priorResults) {
  ensureDir(item.outputDir);
  writeJson(join(item.outputDir, "scenario.json"), {
    schemaVersion: "ioi.autopilot.cursor-substrate.scenario.v1",
    id: item.id,
    title: item.title,
    rowIds: item.rowIds,
    evidenceKind: item.evidenceKind,
    startedAt: new Date().toISOString(),
  });
  const startedAt = Date.now();
  try {
    const result = await item.fn(item.outputDir, priorResults);
    const passed = proofPassed(result);
    const proof = {
      ...result,
      stageId: item.id,
      title: item.title,
      rowIds: item.rowIds,
      evidenceKind: item.evidenceKind,
      durationMs: Date.now() - startedAt,
      passed,
      rows: stageRows(item.rowIds, passed),
    };
    writeJson(join(item.outputDir, "stage-verdict.json"), proof);
    return proof;
  } catch (error) {
    const proof = {
      schemaVersion: "ioi.autopilot.cursor-substrate.stage-failure.v1",
      generatedAt: new Date().toISOString(),
      stageId: item.id,
      title: item.title,
      rowIds: item.rowIds,
      evidenceKind: item.evidenceKind,
      durationMs: Date.now() - startedAt,
      passed: false,
      rows: stageRows(item.rowIds, false),
      summary: { passed: false, total: 1, failed: [String(error?.message ?? error)] },
      checks: [{
        label: `${item.id} completed`,
        passed: false,
        details: {
          message: String(error?.message ?? error),
          stack: String(error?.stack ?? ""),
          entry: error?.entry ?? null,
        },
      }],
    };
    writeJson(join(item.outputDir, "stage-verdict.json"), proof);
    writeMarkdown(join(item.outputDir, "failure-analysis.md"), [
      `# ${item.title} Failure`,
      "",
      `Stage: \`${item.id}\``,
      "",
      "```text",
      String(error?.stack ?? error?.message ?? error),
      "```",
    ]);
    return proof;
  }
}

function stageEvidenceForRow(results, rowId) {
  return results
    .filter((stageResult) => stageResult.rowIds?.includes(rowId))
    .map((stageResult) => rel(join(stageResult.outputDir, "stage-verdict.json")));
}

function rowStatus(row, results) {
  const coveringStages = results.filter((stageResult) => stageResult.rowIds?.includes(row.id));
  const passed = coveringStages.length > 0 && coveringStages.every((stageResult) => stageResult.passed);
  const status = passed ? finalStatusByRow[row.id] : "partial_unproven";
  return {
    ...row,
    status,
    evidence: stageEvidenceForRow(results, row.id),
    productDecision:
      status.endsWith("_with_product_decision") ||
      status === "rejected_with_product_decision" ||
      status === "deferred_optional",
    residualRisk: passed
      ? residualRiskFor(row.id)
      : "Stage evidence is incomplete; inspect failed scenario output.",
    nextProofStep: passed
      ? "None required for the current Cursor absorption parity claim."
      : "Reproduce the failed stage through the smallest responsible layer, fix it, and rerun this campaign.",
  };
}

function residualRiskFor(rowId) {
  switch (rowId) {
    case "CURSOR-SUBSTRATE-005":
      return "Git-relevance indexing can become parity-plus later, but Autopilot does not depend on Cursor's crepectl binary.";
    case "CURSOR-SUBSTRATE-006":
      return "Commit review remains opt-in product behavior rather than an implicit background reviewer.";
    case "CURSOR-SUBSTRATE-007":
      return "Interactive canvases require a deliberate governed artifact runtime before product promotion.";
    case "CURSOR-SUBSTRATE-010":
      return "Cursor NDJSON ingestion is intentionally rejected because daemon events/traces/replay are already canonical.";
    case "CURSOR-SUBSTRATE-011":
      return "Environment schemas are deferred until cloud/local environment scope is explicit.";
    default:
      return "";
  }
}

function buildManifest({ campaignDir, stages, results, baselines, preflight }) {
  const rows = ROW_DEFINITIONS.map((row) => rowStatus(row, results));
  const forbiddenP0Statuses = new Set(["gap", "partial_unproven", "blocked_with_owner"]);
  const p0Failures = rows.filter((row) => row.priority === "P0" && forbiddenP0Statuses.has(row.status));
  const stageFailures = results.filter((item) => !item.passed);
  const requiredBaselinesMissing = baselines.filter((item) => !item.exists);
  const proven =
    !preflight &&
    requiredBaselinesMissing.length === 0 &&
    p0Failures.length === 0 &&
    stageFailures.length === 0 &&
    rows.find((row) => row.id === "CURSOR-SUBSTRATE-008")?.status === "live_pass";
  return {
    schemaVersion: "ioi.autopilot.cursor-substrate-absorption.final-manifest.v1",
    generatedAt: new Date().toISOString(),
    verdict: proven
      ? "cursor_substrate_absorption_parity_proven"
      : "cursor_substrate_absorption_parity_unproven",
    guide: CURSOR_GUIDE_PATH,
    playbook: CURSOR_PLAYBOOK_PATH,
    reverseEngineeringInputs: CURSOR_INPUTS,
    evidenceRoot: rel(evidenceRoot),
    campaignDir: rel(campaignDir),
    baselines,
    stages: stages.map((item) => ({
      id: item.id,
      title: item.title,
      rowIds: item.rowIds,
      evidenceKind: item.evidenceKind,
      outputDir: rel(item.outputDir),
      passed: results.find((result) => result.stageId === item.id)?.passed ?? false,
    })),
    rows,
    p0Failures,
    stageFailures: stageFailures.map((item) => ({
      stageId: item.stageId,
      title: item.title,
      outputDir: item.outputDir ? rel(item.outputDir) : null,
      failed: item.summary?.failed ?? [],
    })),
    missingBaselines: requiredBaselinesMissing,
  };
}

function writeVerdict(manifest) {
  const lines = [
    "# Autopilot Cursor Substrate Absorption Parity Verdict",
    "",
    `Verdict: \`${manifest.verdict}\``,
    "",
    `Generated: ${manifest.generatedAt}`,
    `Evidence root: \`${manifest.evidenceRoot}\``,
    `Campaign: \`${manifest.campaignDir}\``,
    "",
    "## Inputs",
    "",
    `- Guide: \`${manifest.guide}\``,
    `- Playbook: \`${manifest.playbook}\``,
    ...Object.entries(manifest.reverseEngineeringInputs).map(([key, value]) => `- ${key}: \`${value}\``),
    "",
    "## Baselines",
    "",
    ...manifest.baselines.map((item) => `- ${item.exists ? "pass" : "missing"}: \`${item.path}\``),
    "",
    "## Rows",
    "",
    "| Row | Priority | Area | Status | Evidence |",
    "| --- | --- | --- | --- | --- |",
    ...manifest.rows.map((row) =>
      `| ${row.id} ${row.title} | ${row.priority} | ${row.area} | ${row.status} | ${row.evidence.map((item) => `\`${item}\``).join("<br>")} |`),
    "",
    "## Stage Results",
    "",
    ...manifest.stages.map((stageResult) =>
      `- ${stageResult.passed ? "pass" : "fail"}: ${stageResult.id} - \`${stageResult.outputDir}\``),
    "",
    "## Remaining Blockers",
    "",
    ...(manifest.p0Failures.length
      ? manifest.p0Failures.map((row) =>
          `- ${row.id}: ${row.status}; owner ${row.owner}; next step: ${row.nextProofStep}`)
      : ["- None for P0 rows."]),
    ...(manifest.stageFailures.length
      ? ["", "## Failed Stages", "", ...manifest.stageFailures.map((stageResult) =>
          `- ${stageResult.stageId}: ${stageResult.failed.join("; ")} - \`${stageResult.outputDir}\``)]
      : []),
    "",
    "## Cleanup",
    "",
    manifest.stageFailures.length
      ? "At least one stage failed; inspect scenario cleanup proof before rerunning."
      : "Every stage wrote scenario cleanup evidence and the integrated soak includes final process cleanup.",
  ];
  writeMarkdown(finalVerdictPath, lines);
}

async function main() {
  ensureDir(evidenceRoot);
  if (fresh) {
    cleanDir(evidenceRoot);
  }
  const campaignDir = join(evidenceRoot, `${timestamp()}-cursor-substrate-absorption-campaign`);
  ensureDir(campaignDir);
  const baselines = [
    requireBaseline(CURSOR_GUIDE_PATH),
    requireBaseline(CURSOR_PLAYBOOK_PATH),
    ...Object.values(CURSOR_INPUTS).map(requireBaseline),
    ...BASELINE_VERDICTS.map(requireBaseline),
  ];
  const git = runCommand("git", ["rev-parse", "HEAD"], { timeoutMs: 10_000 });
  writeJson(join(campaignDir, "campaign-start.json"), {
    schemaVersion: "ioi.autopilot.cursor-substrate-absorption.campaign-start.v1",
    generatedAt: new Date().toISOString(),
    guide: CURSOR_GUIDE_PATH,
    playbook: CURSOR_PLAYBOOK_PATH,
    baselines,
    git: commandEvidence(git),
    mode: runMode ? "run" : "preflight",
  });
  const stages = buildStages(campaignDir);
  const selectedStages = preflightMode ? stages.slice(0, 1) : stages;
  const results = [];
  for (const item of selectedStages) {
    const result = await runStage(item, results);
    result.outputDir = item.outputDir;
    results.push(result);
  }
  const manifest = buildManifest({
    campaignDir,
    stages: selectedStages,
    results,
    baselines,
    preflight: preflightMode,
  });
  writeJson(finalManifestPath, manifest);
  writeVerdict(manifest);
  process.stdout.write(`${JSON.stringify({
    verdict: manifest.verdict,
    finalManifest: rel(finalManifestPath),
    finalVerdict: rel(finalVerdictPath),
    campaignDir: rel(campaignDir),
    p0Failures: manifest.p0Failures.map((row) => row.id),
    stageFailures: manifest.stageFailures.map((stageResult) => stageResult.stageId),
    missingBaselines: manifest.missingBaselines.map((item) => item.path),
  }, null, 2)}\n`);
  process.exit(manifest.verdict === "cursor_substrate_absorption_parity_proven" || preflightMode ? 0 : 1);
}

main().catch((error) => {
  process.stderr.write(`${String(error?.stack ?? error)}\n`);
  process.exit(1);
});
