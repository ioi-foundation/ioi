#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const evidenceRoot =
  process.argv[3] ??
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus";
const providerGuidePath =
  process.argv[4] ?? ".internal/plans/isolated-computer-providers-master-guide.md";
const sandboxReportPath =
  process.argv[5] ?? "internal-docs/reverse-engineering/antigravity-sandbox-boundary-report.md";

if (!outputPath) {
  throw new Error(
    "usage: workflow-isolated-computer-provider-gap-proof.mjs <output-path> [evidence-root] [provider-guide-path] [sandbox-report-path]",
  );
}

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function findStageProof(stageFragment, proofFile) {
  const dirs = fs
    .readdirSync(evidenceRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.includes(stageFragment))
    .map((entry) => path.join(evidenceRoot, entry.name))
    .sort();
  const dir = dirs.find((candidate) => fs.existsSync(path.join(candidate, proofFile)));
  assert.ok(dir, `missing stage proof directory for ${stageFragment}`);
  const proofPath = path.join(dir, proofFile);
  const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  assert.equal(proof.passed, true, `stage proof did not pass: ${proofPath}`);
  return { dir, proofPath, proof };
}

const providerGuide = readText(providerGuidePath);
const sandboxReport = readText(sandboxReportPath);

for (const pattern of [
  /task_scoped_browser_profile/,
  /task_scoped_playwright_context/,
  /ComputerUseLease/,
  /EnvironmentSelectionReceipt/,
  /CleanupReceipt/,
]) {
  assert.match(providerGuide, pattern);
}
for (const pattern of [/Browser Session Isolation/, /Containerized Linux Sandboxing/, /Env Var Filtering/]) {
  assert.match(sandboxReport, pattern);
}

const stage71 = findStageProof("stage71-live-file-boundary-denial", "workflow-live-file-boundary-denial-summary-proof.json");
const stage72 = findStageProof("stage72-live-sanitized-env", "workflow-live-sanitized-env-summary-proof.json");
const stage73 = findStageProof("stage73-live-symlink-boundary-denial", "workflow-live-symlink-boundary-denial-summary-proof.json");
const stage80 = findStageProof("stage80-namespace-runner-host-smoke", "workflow-namespace-runner-host-smoke-proof.json");
const stage82 = findStageProof("stage82-post-refactor-repo-aware-live", "workflow-post-refactor-repo-aware-live-summary-proof.json");
const stage89 = findStageProof("stage89-evidence-manifest-refresh", "workflow-evidence-manifest-refresh-proof.json");

const proof = {
  schemaVersion: "ioi.autopilot.stage90.isolated-computer-provider-gap-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    providerGuideContainsLeaseSpine: true,
    sandboxReportContainsBrowserAndLinuxIsolationSignals: true,
    liveBoundaryEvidencePresent: true,
    namespaceHostSmokePresent: true,
    latestManifestPresent: true,
  },
  coveredByCurrentCampaign: [
    {
      area: "live protected file boundary",
      evidence: path.relative(".", stage71.proofPath),
    },
    {
      area: "live sanitized subprocess env",
      evidence: path.relative(".", stage72.proofPath),
    },
    {
      area: "live symlink boundary",
      evidence: path.relative(".", stage73.proofPath),
    },
    {
      area: "host namespace smoke capability",
      evidence: path.relative(".", stage80.proofPath),
    },
    {
      area: "live GUI repo-aware harness with cleanup",
      evidence: path.relative(".", stage82.proofPath),
    },
    {
      area: "latest evidence manifest",
      evidence: path.relative(".", stage89.proofPath),
    },
  ],
  parityPlusOpenItems: [
    {
      id: "computer-provider-registry",
      status: "open",
      requirement:
        "Daemon-owned provider discovery, capability report, lease acquisition, observation, action, verification, trajectory export, and cleanup lifecycle.",
    },
    {
      id: "task-scoped-browser-profile-provider",
      status: "open",
      requirement:
        "Product-level provider that launches an isolated browser user-data-dir and emits EnvironmentSelectionReceipt, ComputerUseLease, ObservationBundle, ActionReceipt, VerificationReceipt, TrajectoryBundle, and CleanupReceipt.",
    },
    {
      id: "playwright-context-adapter",
      status: "open",
      requirement:
        "Optional Playwright adapter with isolated BrowserContext, locator/trace artifacts, fail-closed readiness, and IOI receipt mapping.",
    },
    {
      id: "profile-contamination-guard",
      status: "open",
      requirement:
        "Proof that everyday browser history, cookies, cache, and extensions are untouched by task-scoped computer-use runs.",
    },
  ],
  recommendation:
    "Treat task_scoped_browser_profile plus task_scoped_playwright_context as the next parity-plus implementation slice after the 12-hour campaign; the current live GUI harness proves the audit method but not the product-level provider registry.",
  artifacts: {
    providerGuidePath,
    sandboxReportPath,
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
