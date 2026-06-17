#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { cleanupAutopilotCampaignProcesses } from "./lib/autopilot-gui-chat-ux-campaign-processes.mjs";

const repoRoot = resolve(process.cwd());
const evidenceRoot = process.env.AUTOPILOT_CLAUDE_CODE_SUBSTRATE_EVIDENCE_ROOT ||
  join(repoRoot, "docs/evidence/autopilot-claude-code-substrate-absorption-parity");
const finalManifestPath = join(evidenceRoot, "claude-code-substrate-absorption-final-manifest.json");
const finalVerdictPath = join(evidenceRoot, "final-claude-code-substrate-absorption-verdict.md");
const auditManifestPath = "docs/evidence/claude-code-agent-harness-gap-audit/2026-05-27-gap-manifest.json";
const guidePath = ".internal/plans/autopilot-claude-code-substrate-absorption-parity-master-guide.md";
const defaultHarnessVerdictPath = "docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md";
const antigravityVerdictPath = "docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md";

const argv = process.argv.slice(2);
const runMode = argv.includes("--run");
const preflightMode = argv.includes("--preflight") || !runMode;
const resumeFromFinalManifest = argv.includes("--resume");

function proof(id, stage, rowIds, evidenceKind, command, options = {}) {
  return { id, stage, rowIds, evidenceKind, command, ...options };
}

const support = (proofId) => [
  "node",
  [
    "scripts/lib/claude-code-substrate/support-proofs.mjs",
    "--proof",
    proofId,
    "--output",
    "$OUTPUT",
  ],
];

const proofPlan = [
  proof("stage0-campaign-harness-rubric", 0, [
    "CC-HARNESS-001",
    "CC-HARNESS-002",
    "CC-HARNESS-003",
    "CC-HARNESS-004",
    "CC-HARNESS-005",
    "CC-HARNESS-006",
    "CC-HARNESS-007",
    "CC-HARNESS-008",
    "CC-HARNESS-009",
    "CC-HARNESS-010",
    "CC-HARNESS-011",
    "CC-HARNESS-012",
  ], "support", support("campaign-harness-rubric")),
  proof("stage1-streaming-tool-execution", 1, ["CC-HARNESS-001"], "support", support("streaming-tool-execution")),
  proof("stage2-permission-grammar", 2, ["CC-HARNESS-002"], "support", support("permission-grammar")),
  proof("stage3-context-analyzer-compaction", 3, ["CC-HARNESS-003"], "support", support("context-analyzer-compaction")),
  proof("stage4-hook-lifecycle", 4, ["CC-HARNESS-004"], "support", support("hook-lifecycle")),
  proof("stage5-deferred-mcp-tool-search", 5, ["CC-HARNESS-005"], "support", support("deferred-mcp-tool-search")),
  proof("stage6-task-team-substrate", 6, ["CC-HARNESS-006"], "support", support("task-team-substrate")),
  proof("stage7-shell-background-stall", 7, ["CC-HARNESS-007"], "support", support("shell-background-stall")),
  proof("stage8-skills-plugins-decision", 8, ["CC-HARNESS-008"], "support", support("skills-plugins-decision")),
  proof("stage9-cli-longtail-decisions", 9, ["CC-HARNESS-009", "CC-HARNESS-010", "CC-HARNESS-012"], "support", support("cli-longtail-decisions")),
  proof("stage10-browser-computer-live-gui", 10, ["CC-HARNESS-011"], "live_gui", [
    "node",
    [
      "scripts/run-autopilot-agent-studio-live-gui-validation.mjs",
      "--run",
      "--scenario",
      "browser-computer-live-viewport-ux-focused",
    ],
  ], {
    outputStyle: "childEvidenceDir",
    env: (scenarioDir) => ({
      AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT: relative(repoRoot, scenarioDir),
    }),
  }),
  proof("stage11-integrated-soak", 11, [
    "CC-HARNESS-001",
    "CC-HARNESS-002",
    "CC-HARNESS-003",
    "CC-HARNESS-004",
    "CC-HARNESS-005",
    "CC-HARNESS-006",
    "CC-HARNESS-007",
    "CC-HARNESS-008",
    "CC-HARNESS-009",
    "CC-HARNESS-010",
    "CC-HARNESS-011",
    "CC-HARNESS-012",
  ], "support", support("integrated-soak")),
];

const rowClosurePolicy = {
  "CC-HARNESS-001": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage1-streaming-tool-execution", "stage11-integrated-soak"],
    owner: "Runtime tool executor",
    residualRisk:
      "Provider-native structured tool-call delta execution remains gated until providers expose complete arguments early enough to avoid duplicate side effects.",
  },
  "CC-HARNESS-002": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage2-permission-grammar", "stage11-integrated-soak"],
    owner: "Policy runtime / Agent Studio approval menu",
  },
  "CC-HARNESS-003": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage3-context-analyzer-compaction", "stage11-integrated-soak"],
    owner: "Context analyzer and compaction runtime",
  },
  "CC-HARNESS-004": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage4-hook-lifecycle", "stage11-integrated-soak"],
    owner: "Daemon hook lifecycle",
  },
  "CC-HARNESS-005": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage5-deferred-mcp-tool-search", "stage11-integrated-soak"],
    owner: "MCP runtime and deferred tool search",
  },
  "CC-HARNESS-006": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage6-task-team-substrate", "stage11-integrated-soak"],
    owner: "Subagent delegation manager",
  },
  "CC-HARNESS-007": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage7-shell-background-stall", "stage11-integrated-soak"],
    owner: "Retained shell runtime",
  },
  "CC-HARNESS-008": {
    finalStatus: "rejected_with_product_decision",
    required: ["stage8-skills-plugins-decision", "stage11-integrated-soak"],
    owner: "Runtime extension strategy",
    residualRisk:
      "Runtime skills/plugins remain a future trust and context-budget lane; operator-side Codex skills are intentionally separate.",
  },
  "CC-HARNESS-009": {
    finalStatus: "rejected_with_product_decision",
    required: ["stage9-cli-longtail-decisions", "stage11-integrated-soak"],
    owner: "CLI and SDK strategy",
    residualRisk:
      "Terminal-first SDK parity is outside the IDE default harness claim until a headless product is explicitly scoped.",
  },
  "CC-HARNESS-010": {
    finalStatus: "supporting_pass_with_product_decision",
    required: ["stage9-cli-longtail-decisions", "stage11-integrated-soak"],
    owner: "Tool registry strategy",
  },
  "CC-HARNESS-011": {
    finalStatus: "live_pass",
    required: ["stage10-browser-computer-live-gui", "stage11-integrated-soak"],
    owner: "Managed browser/computer automation UX",
  },
  "CC-HARNESS-012": {
    finalStatus: "deferred_optional",
    required: ["stage9-cli-longtail-decisions", "stage11-integrated-soak"],
    owner: "Provider/media/external lane strategy",
    residualRisk:
      "External provider account/install/media lanes require hermetic fixtures before promotion into default product scope.",
  },
};

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function maybeReadJson(path) {
  try {
    return readJson(path);
  } catch {
    return null;
  }
}

function listDirectories(path) {
  if (!existsSync(path)) return [];
  return readdirSync(path)
    .map((name) => {
      const fullPath = join(path, name);
      try {
        const stat = statSync(fullPath);
        return stat.isDirectory() ? { name, path: fullPath, mtimeMs: stat.mtimeMs } : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => a.mtimeMs - b.mtimeMs);
}

function newestChildDirectory(path, beforeNames) {
  return listDirectories(path)
    .filter((entry) => !beforeNames.has(entry.name))
    .at(-1)?.path ?? null;
}

function proofOutputPath(scenarioDir, scenario) {
  if (scenario.outputStyle === "directory" || scenario.outputStyle === "childEvidenceDir") {
    return scenarioDir;
  }
  return join(scenarioDir, `${scenario.id}.json`);
}

function resolveArgs(argsList, scenarioDir, outputPath) {
  return argsList.map((arg) => {
    if (arg === "$OUTPUT") return outputPath;
    if (arg === "$DIR") return scenarioDir;
    return arg;
  });
}

function runCommand(command, argsList, { env = {}, outputDir }) {
  const startedAtMs = Date.now();
  const result = spawnSync(command, argsList, {
    cwd: repoRoot,
    env: { ...process.env, ...env },
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 64,
  });
  const finishedAtMs = Date.now();
  const summary = {
    command,
    args: argsList,
    status: result.status,
    signal: result.signal,
    durationMs: finishedAtMs - startedAtMs,
    error: result.error ? String(result.error?.stack || result.error?.message || result.error) : null,
    stdoutTail: String(result.stdout || "").slice(-8000),
    stderrTail: String(result.stderr || "").slice(-8000),
  };
  writeFileSync(join(outputDir, "command-result.json"), `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(join(outputDir, "stdout.log"), result.stdout || "");
  writeFileSync(join(outputDir, "stderr.log"), result.stderr || "");
  return summary;
}

async function runProofScenario(campaignDir, scenario) {
  const scenarioDir = join(campaignDir, `stage${scenario.stage}-${scenario.id}`);
  ensureDir(scenarioDir);
  const [command, rawArgs] = scenario.command;
  const outputPath = proofOutputPath(scenarioDir, scenario);
  const beforeChildren = new Set(listDirectories(scenarioDir).map((entry) => entry.name));
  const scenarioJson = {
    id: scenario.id,
    stage: scenario.stage,
    rowIds: scenario.rowIds,
    evidenceKind: scenario.evidenceKind,
    command,
    args: resolveArgs(rawArgs, scenarioDir, outputPath),
    startedAt: new Date().toISOString(),
  };
  writeFileSync(join(scenarioDir, "scenario.json"), `${JSON.stringify(scenarioJson, null, 2)}\n`);
  writeFileSync(join(scenarioDir, "baseline-gap-ids.json"), `${JSON.stringify(scenario.rowIds, null, 2)}\n`);
  const env = typeof scenario.env === "function" ? scenario.env(scenarioDir) : scenario.env || {};
  const result = runCommand(command, scenarioJson.args, { env, outputDir: scenarioDir });
  const childEvidenceDir =
    scenario.outputStyle === "childEvidenceDir" ? newestChildDirectory(scenarioDir, beforeChildren) : null;
  const evidenceDir = childEvidenceDir || scenarioDir;
  const proofPath =
    scenario.outputStyle === "directory" || scenario.outputStyle === "childEvidenceDir"
      ? newestJsonProofPath(evidenceDir)
      : outputPath;
  const proofBody = proofPath ? maybeReadJson(proofPath) : null;
  const passed = result.status === 0 && (proofBody?.passed !== false);
  await cleanupAutopilotCampaignProcesses({
    outputDir: scenarioDir,
    phase: `after-${scenario.id}`,
  });
  const latency = {
    schemaVersion: "ioi.autopilot.claude-code-substrate-absorption.latency.v1",
    durationMs: result.durationMs,
    simpleTurnPipelineIssue: result.durationMs > 30_000 && scenario.evidenceKind !== "live_gui",
  };
  writeFileSync(join(scenarioDir, "latency.json"), `${JSON.stringify(latency, null, 2)}\n`);
  const verdict = {
    schemaVersion: "ioi.autopilot.claude-code-substrate-absorption.stage-verdict.v1",
    id: scenario.id,
    stage: scenario.stage,
    rowIds: scenario.rowIds,
    evidenceKind: scenario.evidenceKind,
    status: passed ? "passed" : "failed",
    evidenceDir: relative(repoRoot, evidenceDir),
    proofPath: proofPath ? relative(repoRoot, proofPath) : null,
    cleanupProof: relative(repoRoot, join(scenarioDir, `process-cleanup-after-${scenario.id}.json`)),
    commandResult: relative(repoRoot, join(scenarioDir, "command-result.json")),
    latency: relative(repoRoot, join(scenarioDir, "latency.json")),
    productDecision: proofBody?.productDecision || "",
    checks: proofBody?.checks || null,
    failure: passed ? null : failureSummary(result, proofBody),
  };
  writeFileSync(join(scenarioDir, "stage-verdict.json"), `${JSON.stringify(verdict, null, 2)}\n`);
  return verdict;
}

function newestJsonProofPath(evidenceDir) {
  if (!existsSync(evidenceDir)) return null;
  const files = [];
  const stack = [evidenceDir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".json")) {
        const body = maybeReadJson(fullPath);
        if (body && Object.hasOwn(body, "passed")) {
          files.push({ path: fullPath, mtimeMs: statSync(fullPath).mtimeMs });
        }
      }
    }
  }
  return files.sort((a, b) => a.mtimeMs - b.mtimeMs).at(-1)?.path ?? null;
}

function failureSummary(commandResult, proofBody) {
  return {
    commandStatus: commandResult.status,
    commandSignal: commandResult.signal,
    commandError: commandResult.error,
    proofPassed: proofBody?.passed ?? null,
    stderrTail: commandResult.stderrTail,
    stdoutTail: commandResult.stdoutTail,
  };
}

function proofIdsForRow(rowId) {
  return proofPlan.filter((scenario) => scenario.rowIds.includes(rowId)).map((scenario) => scenario.id);
}

function statusClosesPriority(row) {
  const closed = new Set([
    "live_pass",
    "fixed_then_pass",
    "supporting_pass",
    "supporting_pass_with_product_decision",
    "policy_gate_pass",
    "sandbox_effect_pass",
    "rejected_with_product_decision",
    "deferred_optional",
  ]);
  return closed.has(row.status);
}

function buildManifest(campaignDir, scenarioVerdicts) {
  const audit = readJson(auditManifestPath);
  const verdictById = new Map(scenarioVerdicts.map((verdict) => [verdict.id, verdict]));
  const rows = audit.rows.map((gap) => {
    const closure = rowClosurePolicy[gap.id] || {
      finalStatus: "gap",
      required: proofIdsForRow(gap.id),
      owner: gap.area,
    };
    const required = closure.required || [];
    const missing = required.filter((id) => verdictById.get(id)?.status !== "passed");
    const availableEvidence = proofIdsForRow(gap.id)
      .map((id) => verdictById.get(id))
      .filter(Boolean);
    const liveEvidence = availableEvidence.filter((verdict) => {
      const plan = proofPlan.find((candidate) => candidate.id === verdict.id);
      return plan?.evidenceKind === "live_gui";
    });
    const supportDecisions = availableEvidence
      .map((verdict) => verdict.productDecision)
      .filter(Boolean);
    const status = missing.length === 0 ? closure.finalStatus : "gap";
    return {
      id: gap.id,
      priority: gap.priority,
      area: gap.area,
      status,
      owner: closure.owner || gap.area,
      sourceRequirements: audit.sources?.claudeCode || [],
      baselineStatus: gap.status,
      baselineGap: gap.gap,
      productDecision: supportDecisions.join(" ") || productDecisionFallback(gap.id),
      implementationRefs: implementationRefsFor(gap.id),
      tests: availableEvidence.map((verdict) => verdict.proofPath || verdict.commandResult).filter(Boolean),
      liveEvidence: liveEvidence.map((verdict) => verdict.evidenceDir),
      screenshots: screenshotIndex(liveEvidence),
      cleanupProof: availableEvidence.map((verdict) => verdict.cleanupProof).filter(Boolean).at(-1) || "",
      residualRisk: missing.length > 0
        ? `Missing required proof scenarios: ${missing.join(", ")}`
        : closure.residualRisk || "",
      nextProofStep: missing.length > 0
        ? "Fix failing proof scenario, rerun this campaign, and update the manifest."
        : status === "deferred_optional"
          ? "Promote this lane only with a hermetic fixture and focused live product proof."
          : status === "rejected_with_product_decision"
            ? "Revisit only if product scope changes; keep the product decision in the absorption audit."
            : "Keep this row in the focused substrate regression suite.",
      evidence: availableEvidence,
    };
  });
  const openP0P1 = rows.filter((row) =>
    ["P0", "P1"].includes(row.priority) &&
    !statusClosesPriority(row),
  );
  const scenarioFailCount = scenarioVerdicts.filter((verdict) => verdict.status !== "passed").length;
  const summary = {
    verdict: openP0P1.length === 0 && scenarioFailCount === 0
      ? "claude_code_substrate_absorption_parity_proven"
      : "claude_code_substrate_absorption_parity_not_yet_proven",
    totalRows: rows.length,
    closedRows: rows.filter(statusClosesPriority).length,
    livePassRows: rows.filter((row) => row.status === "live_pass").length,
    productDecisionRows: rows.filter((row) => /product_decision|deferred_optional/.test(row.status)).length,
    openP0P1Rows: openP0P1.map((row) => row.id),
    scenarioPassCount: scenarioVerdicts.filter((verdict) => verdict.status === "passed").length,
    scenarioFailCount,
  };
  return {
    schemaVersion: "ioi.autopilot.claude-code-substrate-absorption.final-manifest.v1",
    generatedAt: new Date().toISOString(),
    campaignDir: relative(repoRoot, campaignDir),
    guidePath,
    baseline: {
      defaultHarnessVerdictPath,
      defaultHarnessVerdictExists: existsSync(defaultHarnessVerdictPath),
      antigravityVerdictPath,
      antigravityVerdictExists: existsSync(antigravityVerdictPath),
      auditManifestPath,
    },
    absorptionScope:
      "Claude Code substrate absorption parity, not exact terminal-first clone parity. Product-default rows need live proof; terminal/headless/optional rows need explicit product decisions.",
    summary,
    scenarioVerdicts,
    rows,
  };
}

function productDecisionFallback(rowId) {
  return {
    "CC-HARNESS-011": "Autopilot preserves its browser/computer managed live viewport UX as product parity-plus.",
    "CC-HARNESS-012": "Provider/media/external account lanes remain optional until promoted with hermetic fixtures.",
  }[rowId] || "";
}

function implementationRefsFor(rowId) {
  const refs = {
    "CC-HARNESS-001": [
      "scripts/lib/claude-code-substrate/support-proofs.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "CC-HARNESS-002": [
      "apps/autopilot/openvscode-extension/ioi-workbench/extension.js",
      "packages/hypervisor-workbench/src/runtime/workflow-runtime-control-nodes.test.ts",
    ],
    "CC-HARNESS-003": [
      "packages/runtime-daemon/src/usage-telemetry.mjs",
      "crates/services/src/agentic/runtime/service/lifecycle/compaction.rs",
    ],
    "CC-HARNESS-004": [
      "packages/runtime-daemon/src/index.mjs",
      "docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md",
    ],
    "CC-HARNESS-005": [
      "packages/runtime-daemon/src/index.mjs",
      "apps/autopilot/openvscode-extension/ioi-workbench/extension.js",
    ],
    "CC-HARNESS-006": [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "scripts/lib/workflow-delegation-matrix-proof.mjs",
    ],
    "CC-HARNESS-007": [
      "scripts/lib/autopilot-agent-studio-chat-scenarios.mjs",
      "scripts/run-autopilot-agent-studio-live-gui-validation.mjs",
    ],
    "CC-HARNESS-011": [
      "packages/runtime-daemon/src/computer-use-projection.mjs",
      "scripts/run-autopilot-agent-studio-live-gui-validation.mjs",
    ],
  };
  return refs[rowId] || [
    "scripts/lib/claude-code-substrate/support-proofs.mjs",
    "docs/evidence/claude-code-agent-harness-gap-audit/2026-05-27-gap-manifest.json",
  ];
}

function screenshotIndex(liveVerdicts) {
  const screenshots = [];
  for (const verdict of liveVerdicts) {
    const evidenceDir = join(repoRoot, verdict.evidenceDir);
    if (!existsSync(evidenceDir)) continue;
    const stack = [evidenceDir];
    while (stack.length) {
      const current = stack.pop();
      for (const entry of readdirSync(current, { withFileTypes: true })) {
        const fullPath = join(current, entry.name);
        if (entry.isDirectory()) {
          stack.push(fullPath);
        } else if (entry.isFile() && entry.name.endsWith(".png")) {
          screenshots.push(relative(repoRoot, fullPath));
        }
      }
    }
  }
  return screenshots.sort();
}

function writeVerdictMarkdown(manifest) {
  const byStage = new Map();
  for (const verdict of manifest.scenarioVerdicts) {
    const stageRows = byStage.get(verdict.stage) || [];
    stageRows.push(verdict);
    byStage.set(verdict.stage, stageRows);
  }
  const lines = [
    "# Autopilot Claude Code Substrate Absorption Final Verdict",
    "",
    `Verdict: \`${manifest.summary.verdict}\``,
    "",
    `Generated: ${manifest.generatedAt}`,
    "",
    "## Scope",
    "",
    manifest.absorptionScope,
    "",
    "## Baselines",
    "",
    `- Default harness baseline: \`${manifest.baseline.defaultHarnessVerdictPath}\``,
    `- Antigravity parity-plus baseline: \`${manifest.baseline.antigravityVerdictPath}\``,
    `- Claude Code gap audit: \`${manifest.baseline.auditManifestPath}\``,
    "",
    "## Final Counts",
    "",
    `- Total rows: ${manifest.summary.totalRows}`,
    `- Closed rows: ${manifest.summary.closedRows}`,
    `- Live-pass rows: ${manifest.summary.livePassRows}`,
    `- Product-decision rows: ${manifest.summary.productDecisionRows}`,
    `- Open P0/P1 rows: ${manifest.summary.openP0P1Rows.length ? manifest.summary.openP0P1Rows.join(", ") : "none"}`,
    `- Scenario pass/fail: ${manifest.summary.scenarioPassCount}/${manifest.summary.scenarioFailCount}`,
    "",
    "## Stage Evidence",
    "",
  ];
  for (const [stage, verdicts] of [...byStage.entries()].sort((a, b) => Number(a[0]) - Number(b[0]))) {
    lines.push(`### Stage ${stage}`);
    for (const verdict of verdicts) {
      lines.push(
        `- ${verdict.status === "passed" ? "PASS" : "FAIL"} \`${verdict.id}\` -> ${verdict.rowIds.join(", ")} (${verdict.evidenceDir})`,
      );
    }
    lines.push("");
  }
  lines.push("## Row Verdicts", "");
  for (const row of manifest.rows) {
    lines.push(`- \`${row.id}\` ${row.priority} ${row.status}: ${row.owner}`);
  }
  lines.push("", "## Product Decisions", "");
  for (const row of manifest.rows.filter((candidate) => candidate.productDecision)) {
    lines.push(`- \`${row.id}\`: ${row.productDecision}`);
  }
  lines.push("", "## Residual Risks", "");
  const risks = manifest.rows.filter((row) => row.residualRisk);
  if (risks.length === 0) {
    lines.push("- None for P0/P1 absorption-scope rows.");
  } else {
    for (const row of risks) {
      lines.push(`- \`${row.id}\`: ${row.residualRisk}`);
    }
  }
  lines.push("", "## Cleanup", "");
  lines.push("- Every scenario wrote a `process-cleanup-after-*.json` proof. Final manifest rows link their latest cleanup proof.");
  return `${lines.join("\n")}\n`;
}

function resumePassedScenarioVerdicts() {
  if (!resumeFromFinalManifest) return [];
  const previousManifest = maybeReadJson(finalManifestPath);
  if (!previousManifest || !Array.isArray(previousManifest.scenarioVerdicts)) return [];
  const knownScenarioIds = new Set(proofPlan.map((scenario) => scenario.id));
  const seen = new Set();
  return previousManifest.scenarioVerdicts
    .filter((verdict) => verdict?.status === "passed" && knownScenarioIds.has(verdict.id))
    .filter((verdict) => {
      if (seen.has(verdict.id)) return false;
      seen.add(verdict.id);
      return true;
    });
}

async function runCampaign() {
  ensureDir(evidenceRoot);
  const campaignDir = join(evidenceRoot, `${timestamp()}-claude-code-substrate-absorption-campaign`);
  ensureDir(campaignDir);
  const scenarioVerdicts = resumePassedScenarioVerdicts();
  const resumedScenarioIds = new Set(scenarioVerdicts.map((verdict) => verdict.id));
  if (scenarioVerdicts.length > 0) {
    writeFileSync(
      join(campaignDir, "resume-source.json"),
      `${JSON.stringify({ finalManifestPath, resumedScenarioIds: [...resumedScenarioIds] }, null, 2)}\n`,
    );
  }
  await cleanupAutopilotCampaignProcesses({ outputDir: campaignDir, phase: "before-campaign" });
  for (const scenario of proofPlan) {
    if (resumedScenarioIds.has(scenario.id)) continue;
    const verdict = await runProofScenario(campaignDir, scenario);
    scenarioVerdicts.push(verdict);
    writeFileSync(join(campaignDir, "campaign-progress.json"), `${JSON.stringify({ scenarioVerdicts }, null, 2)}\n`);
    if (verdict.status !== "passed") break;
  }
  await cleanupAutopilotCampaignProcesses({ outputDir: campaignDir, phase: "after-campaign" });
  const manifest = buildManifest(campaignDir, scenarioVerdicts);
  writeFileSync(join(campaignDir, "claude-code-substrate-absorption-final-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(finalManifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const markdown = writeVerdictMarkdown(manifest);
  writeFileSync(join(campaignDir, "final-claude-code-substrate-absorption-verdict.md"), markdown);
  writeFileSync(finalVerdictPath, markdown);
  return { campaignDir, manifest };
}

function preflight() {
  ensureDir(evidenceRoot);
  const checks = [
    { id: "guide", path: guidePath },
    { id: "audit_manifest", path: auditManifestPath },
    { id: "default_harness_verdict", path: defaultHarnessVerdictPath },
    { id: "antigravity_verdict", path: antigravityVerdictPath },
  ].map((check) => ({ ...check, exists: existsSync(check.path) }));
  const scriptChecks = [
    "scripts/lib/claude-code-substrate/common.mjs",
    "scripts/lib/claude-code-substrate/support-proofs.mjs",
    "scripts/run-autopilot-claude-code-substrate-absorption-parity-goal.mjs",
    "scripts/run-autopilot-agent-studio-live-gui-validation.mjs",
  ].map((script) => {
    const result = spawnSync("node", ["--check", script], { cwd: repoRoot, encoding: "utf8" });
    return {
      script,
      ok: result.status === 0,
      stderr: String(result.stderr || "").slice(-4000),
    };
  });
  const proofScriptsPresent = proofPlan.map((scenario) => {
    const script = scenario.command[1][0];
    return { id: scenario.id, script, exists: existsSync(script) };
  });
  const report = {
    schemaVersion: "ioi.autopilot.claude-code-substrate-absorption.preflight.v1",
    generatedAt: new Date().toISOString(),
    checks,
    scriptChecks,
    proofScriptsPresent,
    ok: checks.every((check) => check.exists) &&
      scriptChecks.every((check) => check.ok) &&
      proofScriptsPresent.every((check) => check.exists),
  };
  writeFileSync(join(evidenceRoot, "preflight.latest.json"), `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

if (preflightMode) {
  const report = preflight();
  console.log(JSON.stringify(report, null, 2));
  if (!report.ok) process.exitCode = 1;
}

if (runMode) {
  const { campaignDir, manifest } = await runCampaign();
  console.log(JSON.stringify({
    ok: manifest.summary.verdict === "claude_code_substrate_absorption_parity_proven",
    verdict: manifest.summary.verdict,
    campaignDir,
    finalManifestPath,
    finalVerdictPath,
  }, null, 2));
  if (manifest.summary.verdict !== "claude_code_substrate_absorption_parity_proven") {
    process.exitCode = 1;
  }
}
