#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const evidenceRoot =
  process.argv[3] ??
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus";

if (!outputPath) {
  throw new Error("usage: workflow-evidence-manifest-proof.mjs <output-path> [evidence-root]");
}

const recentStageRequirements = [
  {
    stage: "stage52",
    dirFragment: "stage52-imported-policy-draft",
    proofFile: "workflow-imported-policy-draft-proof.json",
  },
  {
    stage: "stage53",
    dirFragment: "stage53-imported-generation-metadata-redaction",
    proofFile: "workflow-imported-generation-metadata-redaction-proof.json",
  },
  {
    stage: "stage54",
    dirFragment: "stage54-imported-error-render-info",
    proofFile: "workflow-imported-error-render-info-proof.json",
  },
  {
    stage: "stage55",
    dirFragment: "stage55-imported-audit-panels-live-gui",
    proofFile: "workflow-recovery-panels-live-gui-proof.json",
  },
  {
    stage: "stage56",
    dirFragment: "stage56-sqlite-extended-import-projections",
    proofFile: "workflow-sqlite-extended-import-projections-proof.json",
  },
  {
    stage: "stage57",
    dirFragment: "stage57-imported-audit-replay-notebook",
    proofFile: "workflow-imported-audit-replay-notebook-proof.json",
  },
  {
    stage: "stage58",
    dirFragment: "stage58-chat-responsibility-negative-matrix",
    proofFile: "workflow-chat-responsibility-negative-matrix-proof.json",
  },
  {
    stage: "stage59",
    dirFragment: "stage59-agent-studio-mode-payload-contract",
    proofFile: "workflow-agent-studio-mode-payload-contract-proof.json",
  },
  {
    stage: "stage60",
    dirFragment: "stage60-live-mode-selection-boundary",
    proofFile: "workflow-recovery-panels-live-gui-proof.json",
  },
  {
    stage: "stage61",
    dirFragment: "stage61-evidence-manifest",
    proofFile: "workflow-evidence-manifest-proof.json",
  },
  {
    stage: "stage62",
    dirFragment: "stage62-live-ask-agent-submission",
    proofFile: "workflow-live-ask-agent-submission-summary-proof.json",
  },
  {
    stage: "stage63",
    dirFragment: "stage63-live-currentness-retrieval",
    proofFile: "workflow-live-currentness-retrieval-summary-proof.json",
  },
  {
    stage: "stage64",
    dirFragment: "stage64-live-repo-aware-read-search",
    proofFile: "workflow-live-repo-aware-read-search-summary-proof.json",
  },
  {
    stage: "stage65",
    dirFragment: "stage65-live-code-review-patch-proposal",
    proofFile: "workflow-live-code-review-patch-proposal-summary-proof.json",
  },
  {
    stage: "stage66",
    dirFragment: "stage66-live-shell-test-loop",
    proofFile: "workflow-live-shell-test-loop-summary-proof.json",
  },
  {
    stage: "stage67",
    dirFragment: "stage67-live-shell-approval-gate",
    proofFile: "workflow-live-shell-approval-gate-summary-proof.json",
  },
  {
    stage: "stage68",
    dirFragment: "stage68-live-approval-gate-ux",
    proofFile: "workflow-live-approval-gate-ux-summary-proof.json",
  },
  {
    stage: "stage69",
    dirFragment: "stage69-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage70",
    dirFragment: "stage70-reverse-engineering-sandbox-deltas",
    proofFile: "workflow-reverse-engineering-sandbox-delta-proof.json",
  },
  {
    stage: "stage71",
    dirFragment: "stage71-live-file-boundary-denial",
    proofFile: "workflow-live-file-boundary-denial-summary-proof.json",
  },
  {
    stage: "stage72",
    dirFragment: "stage72-live-sanitized-env",
    proofFile: "workflow-live-sanitized-env-summary-proof.json",
  },
  {
    stage: "stage73",
    dirFragment: "stage73-live-symlink-boundary-denial",
    proofFile: "workflow-live-symlink-boundary-denial-summary-proof.json",
  },
  {
    stage: "stage74",
    dirFragment: "stage74-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage75",
    dirFragment: "stage75-reverse-engineering-sandbox-refresh",
    proofFile: "workflow-reverse-engineering-sandbox-delta-refresh-proof.json",
  },
  {
    stage: "stage76",
    dirFragment: "stage76-late-progress-recap",
    proofFile: "workflow-live-late-progress-recap-summary-proof.json",
  },
  {
    stage: "stage77",
    dirFragment: "stage77-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage78",
    dirFragment: "stage78-native-fixture-intent-refactor",
    proofFile: "workflow-native-fixture-intent-refactor-proof.json",
  },
  {
    stage: "stage79",
    dirFragment: "stage79-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage80",
    dirFragment: "stage80-namespace-runner-host-smoke",
    proofFile: "workflow-namespace-runner-host-smoke-proof.json",
  },
  {
    stage: "stage81",
    dirFragment: "stage81-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage82",
    dirFragment: "stage82-post-refactor-repo-aware-live",
    proofFile: "workflow-post-refactor-repo-aware-live-summary-proof.json",
  },
  {
    stage: "stage83",
    dirFragment: "stage83-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage84",
    dirFragment: "stage84-drivers-lib-regression",
    proofFile: "workflow-drivers-lib-regression-proof.json",
  },
  {
    stage: "stage85",
    dirFragment: "stage85-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage86",
    dirFragment: "stage86-services-lib-regression",
    proofFile: "workflow-services-lib-regression-proof.json",
  },
  {
    stage: "stage87",
    dirFragment: "stage87-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage88",
    dirFragment: "stage88-services-env-mutation-hardening",
    proofFile: "workflow-services-env-mutation-hardening-proof.json",
  },
  {
    stage: "stage89",
    dirFragment: "stage89-evidence-manifest-refresh",
    proofFile: "workflow-evidence-manifest-refresh-proof.json",
  },
  {
    stage: "stage90",
    dirFragment: "stage90-isolated-computer-provider-gap",
    proofFile: "workflow-isolated-computer-provider-gap-proof.json",
  },
  {
    stage: "stage92",
    dirFragment: "stage92-computer-use-sdk-contract",
    proofFile: "workflow-computer-use-sdk-contract-proof.json",
  },
  {
    stage: "stage94",
    dirFragment: "stage94-computer-use-provider-registry",
    proofFile: "workflow-computer-use-provider-registry-proof.json",
  },
  {
    stage: "stage96",
    dirFragment: "stage96-computer-use-provider-discovery-api",
    proofFile: "workflow-computer-use-provider-discovery-api-proof.json",
  },
  {
    stage: "stage98",
    dirFragment: "stage98-computer-use-full-regression",
    proofFile: "workflow-computer-use-full-regression-proof.json",
  },
];

function listFilesRecursive(root) {
  const files = [];
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        stack.push(absolute);
      } else if (entry.isFile()) {
        files.push(absolute);
      }
    }
  }
  return files.sort();
}

function parseJsonFile(filePath) {
  try {
    return { ok: true, data: JSON.parse(fs.readFileSync(filePath, "utf8")) };
  } catch (error) {
    return { ok: false, error: String(error?.message ?? error) };
  }
}

function isAfterCleanup(cleanupFile) {
  const basename = path.basename(cleanupFile);
  const parsed = parseJsonFile(cleanupFile);
  const phase = parsed.ok ? String(parsed.data.phase ?? "") : "";
  return basename.includes("after") || phase.includes("after");
}

function summarizeStage(stageDir, allFiles) {
  const files = allFiles.filter((file) => file.startsWith(`${stageDir}${path.sep}`));
  const proofFiles = files.filter((file) => {
    const basename = path.basename(file);
    return /proof\.json$/.test(basename) && !/^process-cleanup/.test(basename);
  });
  const cleanupFiles = files.filter((file) => /^process-cleanup.*\.json$/.test(path.basename(file)));
  const screenshots = files.filter((file) => /\.(png|jpg|jpeg)$/i.test(file));
  const fixtureFiles = files.filter((file) => /\.(db|autopilot)$/i.test(file));
  const logFiles = files.filter((file) => /\.(log|zip)$/i.test(file));

  const proofSummaries = proofFiles.map((file) => {
    const parsed = parseJsonFile(file);
    return {
      file: path.relative(evidenceRoot, file),
      parsed: parsed.ok,
      passed: parsed.ok ? parsed.data.passed === true : false,
      schemaVersion: parsed.ok ? parsed.data.schemaVersion ?? null : null,
      error: parsed.ok ? null : parsed.error,
    };
  });
  const cleanupSummaries = cleanupFiles.map((file) => {
    const parsed = parseJsonFile(file);
    return {
      file: path.relative(evidenceRoot, file),
      parsed: parsed.ok,
      phase: parsed.ok ? parsed.data.phase ?? null : null,
      ok: parsed.ok ? parsed.data.ok === true : false,
      afterCount: parsed.ok && Array.isArray(parsed.data.after) ? parsed.data.after.length : null,
      cleaned: parsed.ok ? parsed.data.cleaned ?? null : null,
      error: parsed.ok ? null : parsed.error,
    };
  });

  return {
    directory: path.relative(evidenceRoot, stageDir),
    fileCount: files.length,
    proofCount: proofFiles.length,
    passedProofCount: proofSummaries.filter((proof) => proof.passed).length,
    cleanupCount: cleanupFiles.length,
    cleanupOkCount: cleanupSummaries.filter((cleanup) => cleanup.ok).length,
    afterCleanupCount: cleanupFiles.filter(isAfterCleanup).length,
    afterCleanupOkCount: cleanupSummaries.filter((cleanup) => {
      const file = path.join(evidenceRoot, cleanup.file);
      return cleanup.ok && isAfterCleanup(file);
    }).length,
    screenshotCount: screenshots.length,
    fixtureCount: fixtureFiles.length,
    logArtifactCount: logFiles.length,
    proofs: proofSummaries,
    cleanups: cleanupSummaries,
  };
}

const rootStat = fs.statSync(evidenceRoot);
assert.equal(rootStat.isDirectory(), true, `missing evidence root: ${evidenceRoot}`);

const allFiles = listFilesRecursive(evidenceRoot);
const stageDirs = fs
  .readdirSync(evidenceRoot, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => path.join(evidenceRoot, entry.name))
  .sort();

const stageSummaries = stageDirs.map((stageDir) => summarizeStage(stageDir, allFiles));
const recentStages = recentStageRequirements.map((requirement) => {
  const matchingStageDirs = stageDirs.filter((dir) => path.basename(dir).includes(requirement.dirFragment));
  const stageDir =
    matchingStageDirs.find((dir) => fs.existsSync(path.join(dir, requirement.proofFile))) ??
    matchingStageDirs[0];
  assert.ok(stageDir, `missing evidence directory for ${requirement.stage}`);
  const proofPath = path.join(stageDir, requirement.proofFile);
  assert.ok(fs.existsSync(proofPath), `missing proof for ${requirement.stage}: ${requirement.proofFile}`);
  const parsedProof = parseJsonFile(proofPath);
  assert.equal(parsedProof.ok, true, `invalid proof JSON for ${requirement.stage}`);
  assert.equal(parsedProof.data.passed, true, `proof did not pass for ${requirement.stage}`);

  const cleanupFiles = allFiles.filter(
    (file) => file.startsWith(`${stageDir}${path.sep}`) && /^process-cleanup.*\.json$/.test(path.basename(file)),
  );
  const afterCleanupFiles = cleanupFiles.filter(isAfterCleanup);
  assert.ok(afterCleanupFiles.length > 0, `missing after-cleanup for ${requirement.stage}`);
  const afterCleanups = afterCleanupFiles.map((file) => ({ file, parsed: parseJsonFile(file) }));
  assert.ok(
    afterCleanups.some((cleanup) => cleanup.parsed.ok && cleanup.parsed.data.ok === true),
    `missing successful after-cleanup for ${requirement.stage}`,
  );

  return {
    ...requirement,
    directory: path.relative(evidenceRoot, stageDir),
    proofSchemaVersion: parsedProof.data.schemaVersion,
    proofPassed: true,
    successfulAfterCleanupCount: afterCleanups.filter(
      (cleanup) => cleanup.parsed.ok && cleanup.parsed.data.ok === true,
    ).length,
  };
});

const totalProofs = stageSummaries.reduce((sum, stage) => sum + stage.proofCount, 0);
const passedProofs = stageSummaries.reduce((sum, stage) => sum + stage.passedProofCount, 0);
const totalCleanups = stageSummaries.reduce((sum, stage) => sum + stage.cleanupCount, 0);
const cleanupOkCount = stageSummaries.reduce((sum, stage) => sum + stage.cleanupOkCount, 0);
const afterCleanupCount = stageSummaries.reduce((sum, stage) => sum + stage.afterCleanupCount, 0);
const afterCleanupOkCount = stageSummaries.reduce((sum, stage) => sum + stage.afterCleanupOkCount, 0);
const screenshotCount = stageSummaries.reduce((sum, stage) => sum + stage.screenshotCount, 0);
const fixtureCount = stageSummaries.reduce((sum, stage) => sum + stage.fixtureCount, 0);
const logArtifactCount = stageSummaries.reduce((sum, stage) => sum + stage.logArtifactCount, 0);

const proof = {
  schemaVersion: "ioi.autopilot.stage61.evidence-manifest-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  evidenceRoot,
  checks: {
    evidenceRootExists: true,
    recentStagesHavePassingProofs: recentStages.every((stage) => stage.proofPassed),
    recentStagesHaveSuccessfulAfterCleanup: recentStages.every(
      (stage) => stage.successfulAfterCleanupCount > 0,
    ),
    manifestHasScreenshots: screenshotCount > 0,
    manifestHasReplayOrDatabaseFixtures: fixtureCount > 0,
    manifestHasCleanupArtifacts: totalCleanups > 0 && afterCleanupOkCount > 0,
  },
  totals: {
    stageDirectoryCount: stageSummaries.length,
    fileCount: allFiles.length,
    proofCount: totalProofs,
    passedProofCount: passedProofs,
    cleanupCount: totalCleanups,
    cleanupOkCount,
    afterCleanupCount,
    afterCleanupOkCount,
    screenshotCount,
    fixtureCount,
    logArtifactCount,
  },
  recentStages,
  stages: stageSummaries,
};

assert.equal(proof.checks.recentStagesHavePassingProofs, true);
assert.equal(proof.checks.recentStagesHaveSuccessfulAfterCleanup, true);
assert.equal(proof.checks.manifestHasScreenshots, true);
assert.equal(proof.checks.manifestHasReplayOrDatabaseFixtures, true);
assert.equal(proof.checks.manifestHasCleanupArtifacts, true);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
