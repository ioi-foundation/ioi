#!/usr/bin/env node
import { existsSync } from "node:fs";
import { join } from "node:path";
import { cleanupHypervisorCampaignProcesses } from "./lib/hypervisor-campaign-processes.mjs";
import {
  cleanDir,
  commandEvidence,
  ensureDir,
  maybeReadJson,
  rel,
  repoRoot,
  runCommand,
  summarizeChecks,
  timestamp,
  writeJson,
  writeMarkdown,
} from "./lib/headless-runtime-unification/common.mjs";
import { inspectOwnership, REQUIRED_ROWS } from "./lib/headless-runtime-unification/ownership.mjs";
import {
  runCliTuiClientProof,
  runGuiScenarioProof,
  runHeadlessDaemonProof,
  runRustRetainedShellProof,
  runSdkClientProof,
} from "./lib/headless-runtime-unification/live-proofs.mjs";

const evidenceRoot = process.env.AUTOPILOT_HEADLESS_RUNTIME_UNIFICATION_EVIDENCE_ROOT ||
  join(repoRoot, "docs/evidence/autopilot-headless-runtime-unification-parity");
const guidePath = ".internal/plans/autopilot-headless-runtime-unification-parity-master-guide.md";
const playbookPath = ".internal/playbooks/substrate-absorption-rubric-playbook.md";
const finalManifestPath = join(evidenceRoot, "headless-runtime-unification-final-manifest.json");
const finalVerdictPath = join(evidenceRoot, "final-headless-runtime-unification-verdict.md");

const argv = process.argv.slice(2);
const runMode = argv.includes("--run");
const preflightMode = argv.includes("--preflight") || !runMode;
const skipGui = argv.includes("--skip-gui");
const fresh = argv.includes("--fresh") || runMode;

function stage(id, title, rowIds, kind, fn) {
  return { id, title, rowIds, kind, fn };
}

const guiScenarios = [
  {
    id: "stage62-live-ask-agent-boundary",
    rows: ["HRU-002", "HRU-005", "HRU-013", "HRU-017"],
    title: "Focused GUI Ask/Agent boundary and permission selector proof",
  },
  {
    id: "toolcat-stage4-retained-shell-threaded-controls",
    rows: ["HRU-009", "HRU-017"],
    title: "Focused GUI retained shell lifecycle proof",
  },
  {
    id: "browser-computer-live-viewport-ux-focused",
    rows: ["HRU-011", "HRU-017"],
    title: "Focused GUI browser/computer managed viewport proof",
  },
];

function requireBaseline(path) {
  return {
    path,
    exists: existsSync(join(repoRoot, path)),
  };
}

function buildStages(campaignDir) {
  const stages = [
    stage("stage0-ownership-matrix", "Ownership matrix and source audit", REQUIRED_ROWS.map((row) => row.id), "support", async (dir) =>
      inspectOwnership(join(dir, "ownership-evidence.json"))),
    stage("stage1-headless-daemon-contract", "Live headless daemon contract proof", [
      "HRU-001",
      "HRU-003",
      "HRU-004",
      "HRU-005",
      "HRU-006",
      "HRU-008",
      "HRU-010",
      "HRU-011",
      "HRU-012",
      "HRU-013",
      "HRU-017",
    ], "headless", runHeadlessDaemonProof),
    stage("stage2-sdk-client-contract", "SDK shared client adapter proof", [
      "HRU-001",
      "HRU-003",
      "HRU-004",
      "HRU-006",
      "HRU-010",
      "HRU-011",
      "HRU-012",
      "HRU-014",
      "HRU-017",
    ], "sdk", runSdkClientProof),
    stage("stage3-cli-tui-client-contract", "CLI and TUI daemon client proof", [
      "HRU-001",
      "HRU-003",
      "HRU-004",
      "HRU-006",
      "HRU-011",
      "HRU-012",
      "HRU-015",
      "HRU-016",
      "HRU-017",
    ], "cross_client", runCliTuiClientProof),
    stage("stage4-rust-retained-shell-headless", "Headless Rust retained shell proof", [
      "HRU-009",
      "HRU-017",
    ], "headless", runRustRetainedShellProof),
  ];
  if (!skipGui) {
    for (const scenario of guiScenarios) {
      stages.push(stage(
        `stage5-gui-${scenario.id}`,
        scenario.title,
        scenario.rows,
        "live_gui",
        (dir) => runGuiScenarioProof(dir, scenario.id),
      ));
    }
  }
  stages.push(stage("stage6-final-cleanup", "Final cleanup and process audit", REQUIRED_ROWS.map((row) => row.id), "cleanup", async (dir) => {
    const proof = await cleanupHypervisorCampaignProcesses({
      outputDir: dir,
      phase: "headless-runtime-unification-final",
    });
    return {
      schemaVersion: "ioi.autopilot.headless-runtime-unification.final-cleanup.v1",
      generatedAt: new Date().toISOString(),
      passed: proof.ok,
      summary: { passed: proof.ok, total: 1, failed: proof.ok ? [] : ["final cleanup process audit"] },
      checks: [{ label: "Autopilot/runtime bridge/daemon cleanup proof", passed: proof.ok, details: proof }],
      artifacts: { cleanup: rel(join(dir, "process-cleanup-headless-runtime-unification-final.json")) },
    };
  }));
  return stages.map((item, index) => ({
    ...item,
    outputDir: join(campaignDir, `${String(index).padStart(2, "0")}-${item.id}`),
  }));
}

async function runStage(item) {
  ensureDir(item.outputDir);
  writeJson(join(item.outputDir, "scenario.json"), {
    schemaVersion: "ioi.autopilot.headless-runtime-unification.scenario.v1",
    id: item.id,
    title: item.title,
    rowIds: item.rowIds,
    evidenceKind: item.kind,
    startedAt: new Date().toISOString(),
  });
  const startedAt = Date.now();
  try {
    const result = await item.fn(item.outputDir);
    const proof = {
      ...result,
      stageId: item.id,
      title: item.title,
      rowIds: item.rowIds,
      evidenceKind: item.kind,
      durationMs: Date.now() - startedAt,
      passed:
        result.passed ??
        result.summary?.passed ??
        result.checks?.every?.((check) => check.passed) ??
        false,
    };
    writeJson(join(item.outputDir, "stage-verdict.json"), proof);
    return proof;
  } catch (error) {
    const proof = {
      schemaVersion: "ioi.autopilot.headless-runtime-unification.stage-failure.v1",
      generatedAt: new Date().toISOString(),
      stageId: item.id,
      title: item.title,
      rowIds: item.rowIds,
      evidenceKind: item.kind,
      durationMs: Date.now() - startedAt,
      passed: false,
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

function stagePassed(results, id) {
  return Boolean(results.find((item) => item.stageId === id && item.passed));
}

function anyGuiPassed(results, scenarioId) {
  return Boolean(results.find((item) => item.stageId === `stage5-gui-${scenarioId}` && item.passed));
}

function rowStatus(row, results) {
  const ownership = results.find((item) => item.stageId === "stage0-ownership-matrix")?.rows
    ?.find((candidate) => candidate.id === row.id)?.ownership ?? "gap";
  const evidence = results
    .filter((item) => item.rowIds?.includes(row.id))
    .map((item) => item.artifacts?.proof ?? item.artifacts?.transcript ?? item.artifacts?.commandResult ?? rel(join(item.outputDir ?? "", "stage-verdict.json")))
    .filter(Boolean);

  const headless = stagePassed(results, "stage1-headless-daemon-contract");
  const sdk = stagePassed(results, "stage2-sdk-client-contract");
  const cliTui = stagePassed(results, "stage3-cli-tui-client-contract");
  const shell = stagePassed(results, "stage4-rust-retained-shell-headless");
  const askAgentGui = anyGuiPassed(results, "stage62-live-ask-agent-boundary");
  const shellGui = anyGuiPassed(results, "toolcat-stage4-retained-shell-threaded-controls");
  const browserGui = anyGuiPassed(results, "browser-computer-live-viewport-ux-focused");

  const closure = {
    "HRU-001": headless && sdk && cliTui,
    "HRU-002": headless && askAgentGui,
    "HRU-003": headless && sdk && cliTui,
    "HRU-004": headless && sdk && cliTui,
    "HRU-005": headless && askAgentGui,
    "HRU-006": headless && sdk && cliTui,
    "HRU-007": stagePassed(results, "stage0-ownership-matrix"),
    "HRU-008": headless,
    "HRU-009": shell && shellGui,
    "HRU-010": headless && sdk,
    "HRU-011": headless && sdk && cliTui && browserGui,
    "HRU-012": headless && sdk && cliTui,
    "HRU-013": headless && askAgentGui,
    "HRU-014": sdk,
    "HRU-015": cliTui,
    "HRU-016": cliTui,
    "HRU-017": headless && sdk && cliTui && shell && askAgentGui && shellGui && browserGui,
  };

  const clients = {
    "HRU-014": ["sdk"],
    "HRU-015": ["cli"],
    "HRU-016": ["tui"],
    "HRU-009": ["headless_rust_runtime", "gui"],
    "HRU-011": ["daemon", "sdk", "cli", "gui"],
  }[row.id] ?? ["daemon", "sdk", "cli", "tui", "gui"];

  const passed = Boolean(closure[row.id]);
  let status = passed ? "cross_client_pass" : "partial_unproven";
  if (row.id === "HRU-007" && passed) status = "supporting_pass_with_product_decision";
  if (row.id === "HRU-009" && passed) status = "headless_pass";
  if (row.id === "HRU-011" && passed && !skipGui) status = "live_pass";
  if (row.id === "HRU-014" && passed) status = "headless_pass";
  if (row.id === "HRU-015" && passed) status = "cross_client_pass";
  if (row.id === "HRU-016" && passed) status = "cross_client_pass";

  return {
    ...row,
    ownership,
    status,
    clients,
    evidence,
    proof_summary: passed
      ? `${row.capability} is proven against the headless runtime unification campaign evidence.`
      : `${row.capability} is not fully proven yet; inspect failed stage evidence.`,
    remaining_work: passed ? [] : ["Rerun failed stage after fixing the smallest responsible layer."],
  };
}

function buildManifest({ campaignDir, stages, results, baselines, preflight }) {
  const rows = REQUIRED_ROWS.map((row) => rowStatus(row, results));
  const forbiddenP0Statuses = new Set(["gap", "partial_unproven"]);
  const forbiddenP0Ownership = new Set(["gui_only_debt", "tui_missing"]);
  const p0Failures = rows.filter((row) =>
    row.priority === "P0" &&
    (forbiddenP0Statuses.has(row.status) || forbiddenP0Ownership.has(row.ownership))
  );
  const stageFailures = results.filter((item) => !item.passed);
  const proven = !preflight && !skipGui && p0Failures.length === 0 && stageFailures.length === 0 && baselines.every((item) => item.exists);
  return {
    schemaVersion: "ioi.autopilot.headless-runtime-unification.final-manifest.v1",
    generatedAt: new Date().toISOString(),
    verdict: proven
      ? "headless_runtime_unification_parity_proven"
      : "headless_runtime_unification_parity_unproven",
    guide: guidePath,
    playbook: playbookPath,
    evidenceRoot: rel(evidenceRoot),
    campaignDir: rel(campaignDir),
    baselines,
    stages: stages.map((item) => ({
      id: item.id,
      title: item.title,
      rowIds: item.rowIds,
      evidenceKind: item.kind,
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
  };
}

function writeVerdict(manifest) {
  const lines = [
    "# Autopilot Headless Runtime Unification Parity Verdict",
    "",
    `Verdict: \`${manifest.verdict}\``,
    "",
    `Generated: ${manifest.generatedAt}`,
    `Evidence root: \`${manifest.evidenceRoot}\``,
    `Campaign: \`${manifest.campaignDir}\``,
    "",
    "## Baselines",
    "",
    ...manifest.baselines.map((item) => `- ${item.exists ? "pass" : "missing"}: \`${item.path}\``),
    "",
    "## Rows",
    "",
    "| Row | Priority | Ownership | Status | Evidence |",
    "| --- | --- | --- | --- | --- |",
    ...manifest.rows.map((row) =>
      `| ${row.id} ${row.capability} | ${row.priority} | ${row.ownership} | ${row.status} | ${row.evidence.map((item) => `\`${item}\``).join("<br>")} |`),
    "",
    "## Stage Results",
    "",
    ...manifest.stages.map((stage) => `- ${stage.passed ? "pass" : "fail"}: ${stage.id} - \`${stage.outputDir}\``),
    "",
    "## Remaining Blockers",
    "",
    ...(manifest.p0Failures.length
      ? manifest.p0Failures.map((row) => `- ${row.id}: ${row.status}/${row.ownership}; owner ${row.owner}; next step: ${row.remaining_work.join("; ")}`)
      : ["- None for P0 rows."]),
    "",
    "## Cleanup",
    "",
    manifest.stageFailures.length
      ? "At least one stage failed; inspect the stage cleanup proof before rerunning."
      : "Final cleanup stage passed and scenario cleanup proofs are referenced from the manifest.",
  ];
  writeMarkdown(finalVerdictPath, lines);
}

async function main() {
  ensureDir(evidenceRoot);
  if (fresh) {
    cleanDir(evidenceRoot);
  }
  const campaignDir = join(evidenceRoot, `${timestamp()}-headless-runtime-unification-campaign`);
  ensureDir(campaignDir);
  const baselines = [
    requireBaseline("docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md"),
    requireBaseline("docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md"),
    requireBaseline("docs/evidence/autopilot-claude-code-substrate-absorption-parity/final-claude-code-substrate-absorption-verdict.md"),
    requireBaseline(guidePath),
    requireBaseline(playbookPath),
  ];
  const git = runCommand("git", ["rev-parse", "HEAD"], { timeoutMs: 10_000 });
  writeJson(join(campaignDir, "campaign-start.json"), {
    schemaVersion: "ioi.autopilot.headless-runtime-unification.campaign-start.v1",
    generatedAt: new Date().toISOString(),
    guide: guidePath,
    playbook: playbookPath,
    baselines,
    git: commandEvidence(git),
    mode: runMode ? "run" : "preflight",
    skipGui,
  });
  const stages = buildStages(campaignDir);
  const selectedStages = preflightMode ? stages.slice(0, 1) : stages;
  const results = [];
  for (const item of selectedStages) {
    const result = await runStage(item);
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
    stageFailures: manifest.stageFailures.map((stage) => stage.stageId),
  }, null, 2)}\n`);
  process.exit(manifest.verdict === "headless_runtime_unification_parity_proven" || preflightMode ? 0 : 1);
}

main().catch((error) => {
  process.stderr.write(`${String(error?.stack ?? error)}\n`);
  process.exit(1);
});
