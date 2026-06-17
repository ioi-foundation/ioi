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
import { dirname, join, relative } from "node:path";

import { cleanupHypervisorCampaignProcesses } from "./lib/hypervisor-campaign-processes.mjs";

const repoRoot = process.cwd();
const evidenceRoot = "docs/evidence/autopilot-antigravity-harness-parity-plus";
const auditManifestPath =
  "docs/evidence/antigravity-agent-harness-gap-audit/2026-05-27-gap-manifest.json";
const defaultHarnessVerdictPath =
  "docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md";
const finalManifestPath = join(evidenceRoot, "antigravity-harness-parity-plus-final-manifest.json");
const finalVerdictPath = join(evidenceRoot, "final-antigravity-harness-parity-plus-verdict.md");

const args = new Set(process.argv.slice(2));
const runMode = args.has("--run");
const preflightMode = args.has("--preflight") || !runMode;
const resumeFromFinalManifest = args.has("--resume-from-final-manifest");

const proofPlan = [
  proof("stage1-trajectory-sqlite", 1, ["AG-HARNESS-001", "AG-HARNESS-018"], "supporting", [
    "node",
    ["scripts/lib/workflow-trajectory-sqlite-blob-ingest-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage1-session-brain", 1, ["AG-HARNESS-006", "AG-HARNESS-016"], "supporting", [
    "node",
    ["scripts/lib/workflow-session-brain-panel-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage2-file-atomicity", 2, ["AG-HARNESS-005"], "supporting", [
    "node",
    ["scripts/lib/workflow-file-apply-patch-atomicity-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage2-hunk-decisions", 2, ["AG-HARNESS-004", "AG-HARNESS-005"], "supporting", [
    "node",
    ["scripts/lib/workflow-hunk-decision-receipt-panel-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage2-runtime-cockpit-live-gui", 2, [
    "AG-HARNESS-004",
    "AG-HARNESS-009",
    "AG-HARNESS-010",
  ], "live_gui", [
    "node",
    ["scripts/run-hypervisor-runtime-cockpit-parity-goal.mjs", "--run"],
  ], {
    outputStyle: "childEvidenceDir",
    env: (scenarioDir) => ({
      AUTOPILOT_AGENT_STUDIO_RUNTIME_COCKPIT_EVIDENCE_ROOT: scenarioDir,
    }),
  }),
  proof("stage3-sandbox-boundary", 3, ["AG-HARNESS-008", "AG-HARNESS-009"], "supporting", [
    "node",
    ["scripts/lib/workflow-sandbox-boundary-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage3-sandbox-resource-limits", 3, ["AG-HARNESS-008"], "supporting", [
    "node",
    ["scripts/lib/workflow-sandbox-resource-limits-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage3-policy-lease-revoke", 3, ["AG-HARNESS-009"], "supporting", [
    "node",
    ["scripts/lib/workflow-policy-lease-panel-revoke-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage3-terminal-stream-card", 3, ["AG-HARNESS-010"], "supporting", [
    "node",
    ["scripts/lib/workflow-terminal-stream-card-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage3-retained-shell-live-gui", 3, ["AG-HARNESS-003", "AG-HARNESS-010"], "live_gui", [
    "node",
    [
      "scripts/run-hypervisor-agent-chat-ux-hardening-goal.mjs",
      "--run",
      "--scenario",
      "toolcat-stage4-retained-shell-threaded-controls",
    ],
  ], {
    outputStyle: "childEvidenceDir",
    env: (scenarioDir) => ({
      AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT: scenarioDir,
    }),
  }),
  proof("stage4-crash-restart-resume", 4, ["AG-HARNESS-002"], "supporting", [
    "node",
    ["scripts/lib/workflow-crash-restart-timeline-resume-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage4-auth-stream-cancel", 4, ["AG-HARNESS-003", "AG-HARNESS-012", "AG-HARNESS-015"], "supporting", [
    "node",
    ["scripts/lib/workflow-auth-stream-failure-drill-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage4-goal-verification", 4, ["AG-HARNESS-007"], "supporting", [
    "node",
    ["scripts/lib/workflow-goal-verification-failing-to-green-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage5-context-lifecycle", 5, ["AG-HARNESS-011", "AG-HARNESS-015"], "supporting", [
    "node",
    ["scripts/lib/workflow-context-lifecycle-panel-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage5-gateway-token-hygiene", 5, ["AG-HARNESS-012"], "supporting", [
    "node",
    ["scripts/lib/workflow-gateway-token-hygiene-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage5-chat-trace-live-gui", 5, [
    "AG-HARNESS-002",
    "AG-HARNESS-011",
    "AG-HARNESS-012",
    "AG-HARNESS-015",
    "AG-HARNESS-016",
  ], "live_gui", [
    "node",
    ["scripts/lib/workflow-chat-trace-parity-plus-live-gui-proof.mjs", "$DIR"],
  ], { outputStyle: "directory" }),
  proof("stage6-delegation-matrix", 6, ["AG-HARNESS-003", "AG-HARNESS-013"], "supporting", [
    "node",
    ["scripts/lib/workflow-delegation-matrix-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage6-worker-contribution", 6, ["AG-HARNESS-013"], "supporting", [
    "node",
    ["scripts/lib/workflow-worker-contribution-trace-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage6-parent-trajectory-linkage", 6, ["AG-HARNESS-001", "AG-HARNESS-013"], "supporting", [
    "node",
    ["scripts/lib/workflow-parent-trajectory-linkage-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage7-computer-replay", 7, ["AG-HARNESS-014", "AG-HARNESS-018"], "supporting", [
    "node",
    ["scripts/lib/workflow-computer-use-replay-timeline-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage7-browser-computer-live-gui", 7, ["AG-HARNESS-014"], "live_gui", [
    "node",
    [
      "scripts/run-hypervisor-agent-chat-ux-hardening-goal.mjs",
      "--run",
      "--scenario",
      "browser-computer-live-viewport-ux-focused",
    ],
  ], {
    outputStyle: "childEvidenceDir",
    env: (scenarioDir) => ({
      AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT: scenarioDir,
    }),
  }),
  proof("stage7-computer-provider-registry", 7, ["AG-HARNESS-014", "AG-HARNESS-020"], "supporting", [
    "node",
    ["scripts/lib/workflow-computer-use-provider-registry-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage8-structured-policy-composer", 8, ["AG-HARNESS-017"], "supporting", [
    "node",
    ["scripts/lib/workflow-structured-policy-composer-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage8-recovery-panels-live-gui", 8, [
    "AG-HARNESS-006",
    "AG-HARNESS-007",
    "AG-HARNESS-008",
    "AG-HARNESS-012",
    "AG-HARNESS-016",
    "AG-HARNESS-017",
    "AG-HARNESS-019",
  ], "live_gui", [
    "node",
    ["scripts/lib/workflow-recovery-panels-live-gui-proof.mjs", "$DIR"],
  ], { outputStyle: "directory" }),
  proof("stage8-chat-output-renderer-live-gui", 8, ["AG-HARNESS-016"], "live_gui", [
    "node",
    ["scripts/lib/workflow-chat-output-renderer-live-gui-proof.mjs", "$DIR"],
  ], { outputStyle: "directory" }),
  proof("stage9-signed-replay-notebook", 9, ["AG-HARNESS-018"], "supporting", [
    "node",
    ["scripts/lib/workflow-signed-replay-notebook-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage9-onboarding-diagnostics", 9, ["AG-HARNESS-019"], "supporting", [
    "node",
    ["scripts/lib/workflow-onboarding-diagnostics-checklist-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage9-model-capability-selector", 9, ["AG-HARNESS-020"], "supporting", [
    "node",
    ["scripts/lib/workflow-model-capability-selector-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage9-computer-provider-discovery", 9, ["AG-HARNESS-020"], "supporting", [
    "node",
    ["scripts/lib/workflow-computer-use-provider-discovery-api-proof.mjs", "$OUTPUT"],
  ]),
  proof("stage9-computer-use-full-regression", 9, ["AG-HARNESS-014", "AG-HARNESS-020"], "supporting", [
    "node",
    ["scripts/lib/workflow-computer-use-full-regression-proof.mjs", "$OUTPUT"],
  ]),
];

const rowClosurePolicy = {
  "AG-HARNESS-001": {
    finalStatus: "fixed_then_pass",
    required: ["stage1-trajectory-sqlite", "stage6-parent-trajectory-linkage"],
    owner: "Runtime trajectory substrate / Agent Studio trace projections",
  },
  "AG-HARNESS-002": {
    finalStatus: "fixed_then_pass",
    required: ["stage4-crash-restart-resume", "stage5-chat-trace-live-gui"],
    owner: "Runtime daemon recovery / Agent Studio reconnect UX",
  },
  "AG-HARNESS-003": {
    finalStatus: "fixed_then_pass",
    required: ["stage4-auth-stream-cancel", "stage6-delegation-matrix", "stage3-retained-shell-live-gui"],
    owner: "Runtime cancellation / retained shell / delegated worker controls",
  },
  "AG-HARNESS-004": {
    finalStatus: "fixed_then_pass",
    required: ["stage2-hunk-decisions", "stage2-runtime-cockpit-live-gui"],
    owner: "Editor hunk workflow / Agent Studio runtime cockpit",
  },
  "AG-HARNESS-005": {
    finalStatus: "fixed_then_pass",
    required: ["stage2-file-atomicity", "stage2-hunk-decisions"],
    owner: "Runtime coding tools / atomic patch transaction layer",
  },
  "AG-HARNESS-006": {
    finalStatus: "fixed_then_pass",
    required: ["stage1-session-brain", "stage8-recovery-panels-live-gui"],
    owner: "Session brain lifecycle / evidence projections",
  },
  "AG-HARNESS-007": {
    finalStatus: "fixed_then_pass",
    required: ["stage4-goal-verification", "stage8-recovery-panels-live-gui"],
    owner: "Goal verification and stop-hook UX",
  },
  "AG-HARNESS-008": {
    finalStatus: "fixed_then_pass",
    required: ["stage3-sandbox-boundary", "stage3-sandbox-resource-limits", "stage8-recovery-panels-live-gui"],
    owner: "Sandbox runner / boundary policy projections",
  },
  "AG-HARNESS-009": {
    finalStatus: "fixed_then_pass",
    required: ["stage3-policy-lease-revoke", "stage8-structured-policy-composer", "stage2-runtime-cockpit-live-gui"],
    owner: "Policy lease model / active lease UX",
  },
  "AG-HARNESS-010": {
    finalStatus: "fixed_then_pass",
    required: ["stage3-terminal-stream-card", "stage3-retained-shell-live-gui", "stage2-runtime-cockpit-live-gui"],
    owner: "Terminal stream cards / retained process controls",
  },
  "AG-HARNESS-011": {
    finalStatus: "fixed_then_pass",
    required: ["stage5-context-lifecycle", "stage5-chat-trace-live-gui"],
    owner: "Context compiler / trace stream projections",
  },
  "AG-HARNESS-012": {
    finalStatus: "fixed_then_pass",
    required: ["stage5-gateway-token-hygiene", "stage4-auth-stream-cancel", "stage5-chat-trace-live-gui"],
    owner: "Loopback auth and gateway token hygiene",
  },
  "AG-HARNESS-013": {
    finalStatus: "fixed_then_pass",
    required: ["stage6-delegation-matrix", "stage6-worker-contribution", "stage6-parent-trajectory-linkage"],
    owner: "Subagent manager / delegation matrix",
  },
  "AG-HARNESS-014": {
    finalStatus: "fixed_then_pass",
    required: ["stage7-computer-replay", "stage7-browser-computer-live-gui", "stage9-computer-use-full-regression"],
    owner: "Managed browser/computer sessions",
  },
  "AG-HARNESS-015": {
    finalStatus: "fixed_then_pass",
    required: ["stage5-context-lifecycle", "stage4-auth-stream-cancel", "stage5-chat-trace-live-gui"],
    owner: "Typed model stream and product chat renderer",
  },
  "AG-HARNESS-016": {
    finalStatus: "fixed_then_pass",
    required: ["stage1-session-brain", "stage8-recovery-panels-live-gui", "stage8-chat-output-renderer-live-gui"],
    owner: "Evidence pane / artifact rendering",
  },
  "AG-HARNESS-017": {
    finalStatus: "fixed_then_pass",
    required: ["stage8-structured-policy-composer", "stage8-recovery-panels-live-gui"],
    owner: "Structured policy composer",
  },
  "AG-HARNESS-018": {
    finalStatus: "fixed_then_pass",
    required: ["stage1-trajectory-sqlite", "stage7-computer-replay", "stage9-signed-replay-notebook"],
    owner: "Signed receipts and replay notebook",
  },
  "AG-HARNESS-019": {
    finalStatus: "fixed_then_pass",
    required: ["stage9-onboarding-diagnostics", "stage8-recovery-panels-live-gui"],
    owner: "Onboarding readiness checklist",
  },
  "AG-HARNESS-020": {
    finalStatus: "deferred_optional",
    required: [
      "stage9-model-capability-selector",
      "stage7-computer-provider-registry",
      "stage9-computer-provider-discovery",
    ],
    owner: "Provider decisions / optional adapter registry",
    residualRisk:
      "Provider-specific external lanes remain outside the default parity-plus claim unless promoted to default with hermetic credentials-free fixtures.",
  },
};

function proof(id, stage, rowIds, evidenceKind, command, options = {}) {
  return { id, stage, rowIds, evidenceKind, command, ...options };
}

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
  const cleanup = await cleanupHypervisorCampaignProcesses({
    outputDir: scenarioDir,
    phase: `after-${scenario.id}`,
  });
  const latency = {
    schemaVersion: "ioi.autopilot.antigravity-harness-parity-plus.latency.v1",
    durationMs: result.durationMs,
    simpleTurnPipelineIssue: result.durationMs > 30_000 && scenario.evidenceKind !== "live_gui",
  };
  writeFileSync(join(scenarioDir, "latency.json"), `${JSON.stringify(latency, null, 2)}\n`);
  const verdict = {
    schemaVersion: "ioi.autopilot.antigravity-harness-parity-plus.stage-verdict.v1",
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

function buildManifest(campaignDir, scenarioVerdicts) {
  const audit = readJson(auditManifestPath);
  const verdictById = new Map(scenarioVerdicts.map((verdict) => [verdict.id, verdict]));
  const rows = audit.gaps.map((gap) => {
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
    const status = missing.length === 0 ? closure.finalStatus : "gap";
    return {
      id: gap.id,
      priority: gap.priority,
      area: gap.area,
      status,
      owner: closure.owner || gap.area,
      sourceRequirements: audit.sources,
      baselineStatus: gap.status,
      baselineGap: gap.gap,
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
          ? "Promote a provider lane to default only with a hermetic fixture and live GUI proof."
          : "Keep this row in the focused regression suite.",
      evidence: availableEvidence,
    };
  });
  const openP0P1 = rows.filter((row) =>
    ["P0", "P1"].includes(row.priority) &&
    ["gap", "partial_unproven", "blocked_with_owner"].includes(row.status),
  );
  const summary = {
    verdict: openP0P1.length === 0 ? "antigravity_harness_parity_plus_proven" : "antigravity_harness_parity_plus_not_proven",
    totalRows: rows.length,
    closedRows: rows.filter((row) => ["live_pass", "fixed_then_pass", "supporting_pass"].includes(row.status)).length,
    deferredOptionalRows: rows.filter((row) => row.status === "deferred_optional").length,
    openP0P1Rows: openP0P1.map((row) => row.id),
    scenarioPassCount: scenarioVerdicts.filter((verdict) => verdict.status === "passed").length,
    scenarioFailCount: scenarioVerdicts.filter((verdict) => verdict.status !== "passed").length,
  };
  return {
    schemaVersion: "ioi.autopilot.antigravity-harness-parity-plus.final-manifest.v1",
    generatedAt: new Date().toISOString(),
    campaignDir: relative(repoRoot, campaignDir),
    defaultHarnessBaseline: {
      verdictPath: defaultHarnessVerdictPath,
      verdictExists: existsSync(defaultHarnessVerdictPath),
    },
    auditBaseline: {
      manifestPath: auditManifestPath,
      verdict: audit.summary?.verdict,
      p0: audit.summary?.p0,
      p1: audit.summary?.p1,
      p2: audit.summary?.p2,
    },
    summary,
    scenarioVerdicts,
    rows,
  };
}

function implementationRefsFor(rowId) {
  const refs = {
    "AG-HARNESS-001": [
      "packages/hypervisor-workbench/src/runtime/workflow-trajectory-import-audit.ts",
      "scripts/lib/workflow-trajectory-sqlite-blob-ingest-proof.mjs",
    ],
    "AG-HARNESS-006": [
      "packages/hypervisor-workbench/src/runtime/workflow-session-brain-panel.ts",
      "scripts/lib/workflow-session-brain-panel-proof.mjs",
    ],
    "AG-HARNESS-014": [
      "packages/runtime-daemon/src/computer-use-projection.mjs",
      "scripts/run-hypervisor-agent-chat-ux-hardening-goal.mjs",
    ],
    "AG-HARNESS-017": [
      "packages/hypervisor-workbench/src/runtime/workflow-structured-policy-composer.ts",
      "scripts/lib/workflow-structured-policy-composer-proof.mjs",
    ],
    "AG-HARNESS-018": [
      "packages/hypervisor-workbench/src/runtime/workflow-signed-replay-notebook.ts",
      "scripts/lib/workflow-signed-replay-notebook-proof.mjs",
    ],
  };
  return refs[rowId] || [
    "workbench-adapters/ioi-workbench/extension.js",
    "packages/runtime-daemon/src/index.mjs",
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
    "# Autopilot Antigravity Harness Parity Plus Final Verdict",
    "",
    `Verdict: \`${manifest.summary.verdict}\``,
    "",
    `Generated: ${manifest.generatedAt}`,
    "",
    "## Baseline",
    "",
    `- Default harness baseline: \`${manifest.defaultHarnessBaseline.verdictPath}\``,
    `- Gap audit baseline: \`${manifest.auditBaseline.manifestPath}\``,
    `- Baseline counts: P0 ${manifest.auditBaseline.p0}, P1 ${manifest.auditBaseline.p1}, P2 ${manifest.auditBaseline.p2}`,
    "",
    "## Final Counts",
    "",
    `- Total rows: ${manifest.summary.totalRows}`,
    `- Closed rows: ${manifest.summary.closedRows}`,
    `- Deferred optional rows: ${manifest.summary.deferredOptionalRows}`,
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
  lines.push("", "## Residual Risks", "");
  const risks = manifest.rows.filter((row) => row.residualRisk);
  if (risks.length === 0) {
    lines.push("- None for P0/P1 parity-plus rows.");
  } else {
    for (const row of risks) {
      lines.push(`- \`${row.id}\`: ${row.residualRisk}`);
    }
  }
  lines.push("", "## Cleanup", "");
  lines.push("- Every scenario wrote a `process-cleanup-after-*.json` proof. Final manifest rows link their latest cleanup proof.");
  return `${lines.join("\n")}\n`;
}

async function runCampaign() {
  ensureDir(evidenceRoot);
  const campaignDir = join(evidenceRoot, `${timestamp()}-antigravity-harness-parity-plus-campaign`);
  ensureDir(campaignDir);
  const scenarioVerdicts = resumePassedScenarioVerdicts();
  const resumedScenarioIds = new Set(scenarioVerdicts.map((verdict) => verdict.id));
  if (scenarioVerdicts.length > 0) {
    writeFileSync(
      join(campaignDir, "resume-source.json"),
      `${JSON.stringify({ finalManifestPath, resumedScenarioIds: [...resumedScenarioIds] }, null, 2)}\n`,
    );
  }
  await cleanupHypervisorCampaignProcesses({ outputDir: campaignDir, phase: "before-campaign" });
  for (const scenario of proofPlan) {
    if (resumedScenarioIds.has(scenario.id)) {
      continue;
    }
    const verdict = await runProofScenario(campaignDir, scenario);
    scenarioVerdicts.push(verdict);
    writeFileSync(
      join(campaignDir, "campaign-progress.json"),
      `${JSON.stringify({ scenarioVerdicts }, null, 2)}\n`,
    );
    if (verdict.status !== "passed") {
      break;
    }
  }
  await cleanupHypervisorCampaignProcesses({ outputDir: campaignDir, phase: "after-campaign" });
  const manifest = buildManifest(campaignDir, scenarioVerdicts);
  writeFileSync(join(campaignDir, "antigravity-harness-parity-plus-final-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(finalManifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const markdown = writeVerdictMarkdown(manifest);
  writeFileSync(join(campaignDir, "final-antigravity-harness-parity-plus-verdict.md"), markdown);
  writeFileSync(finalVerdictPath, markdown);
  return { campaignDir, manifest };
}

function preflight() {
  ensureDir(evidenceRoot);
  const checks = [
    { id: "guide", path: ".internal/plans/autopilot-antigravity-harness-parity-plus-master-guide.md" },
    { id: "audit_manifest", path: auditManifestPath },
    { id: "default_harness_verdict", path: defaultHarnessVerdictPath },
  ].map((check) => ({ ...check, exists: existsSync(check.path) }));
  const scriptChecks = [
    "scripts/run-hypervisor-antigravity-harness-parity-plus-goal.mjs",
    "scripts/run-hypervisor-runtime-cockpit-parity-goal.mjs",
    "scripts/run-hypervisor-agent-chat-ux-hardening-goal.mjs",
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
    schemaVersion: "ioi.autopilot.antigravity-harness-parity-plus.preflight.v1",
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
    ok: manifest.summary.verdict === "antigravity_harness_parity_plus_proven",
    verdict: manifest.summary.verdict,
    campaignDir,
    finalManifestPath,
    finalVerdictPath,
  }, null, 2));
  if (manifest.summary.verdict !== "antigravity_harness_parity_plus_proven") {
    process.exitCode = 1;
  }
}
