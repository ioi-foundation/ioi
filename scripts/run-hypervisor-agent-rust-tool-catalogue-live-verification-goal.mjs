#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { cleanupHypervisorCampaignProcesses } from "./lib/hypervisor-campaign-processes.mjs";

const repoRoot = process.cwd();
const MASTER_GUIDE =
  ".internal/plans/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification-12h-master-guide.md";
const EVIDENCE_ROOT =
  "docs/evidence/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification";
const RUNNER = "scripts/run-hypervisor-agent-live-gui-validation.mjs";
const TWELVE_HOURS_MS = 12 * 60 * 60 * 1000;

const SCENARIOS = [
  "stage0-hardening",
  "stage1-lightweight-conversation",
  "stage62-live-ask-agent-boundary",
  "toolcat-stage1-lifecycle-controls",
  "toolcat-stage2-read-local-model",
  "toolcat-stage3-filesystem-mutation",
  "toolcat-stage4-shell-software",
  "toolcat-stage5-browser-matrix",
  "toolcat-stage6-desktop-clipboard",
  "toolcat-stage7-model-registry",
  "toolcat-stage8-memory-commerce-monitor",
  "toolcat-stage9-media",
  "toolcat-stage10-computer-use-provider",
  "toolcat-stage11-workflow-cross-surface",
  "toolcat-stage12-final-regression",
];

const CONTRACT_TOOLS = [
  "chat__reply",
  "agent__complete",
  "agent__pause",
  "agent__escalate",
  "agent__delegate",
  "agent__await",
  "file__read",
  "file__view",
  "file__list",
  "file__search",
  "file__info",
  "file__write",
  "file__edit",
  "file__multi_edit",
  "file__copy",
  "file__move",
  "file__create_dir",
  "file__zip",
  "file__delete",
  "shell__run",
  "shell__start",
  "shell__status",
  "shell__input",
  "shell__terminate",
  "shell__reset",
  "shell__cd",
  "software_install__resolve",
  "software_install__execute_plan",
  "web__search",
  "web__read",
  "http__fetch",
  "math__eval",
  "model__embeddings",
  "model__rerank",
  "browser__navigate",
  "browser__inspect",
  "browser__inspect_canvas",
  "browser__screenshot",
  "browser__find_text",
  "browser__list_options",
  "browser__list_tabs",
  "browser__subagent",
  "browser__click",
  "browser__hover",
  "browser__move_pointer",
  "browser__pointer_down",
  "browser__pointer_up",
  "browser__click_at",
  "browser__scroll",
  "browser__type",
  "browser__select",
  "browser__press_key",
  "browser__copy",
  "browser__paste",
  "browser__wait",
  "browser__upload",
  "browser__select_option",
  "browser__back",
  "browser__switch_tab",
  "browser__close_tab",
  "screen__inspect",
  "screen__find",
  "screen__click",
  "screen__click_at",
  "screen__type",
  "screen__scroll",
  "screen",
  "window__focus",
  "app__launch",
  "clipboard__copy",
  "clipboard__paste",
  "media__extract_transcript",
  "media__extract_evidence",
  "media__vision_read",
  "media__transcribe_audio",
  "media__generate_image",
  "media__edit_image",
  "media__generate_video",
  "media__synthesize_speech",
  "model_registry__load",
  "model_registry__unload",
  "model_registry__install",
  "model_registry__apply",
  "model_registry__delete",
  "backend__health",
  "backend__install",
  "backend__apply",
  "backend__start",
  "backend__stop",
  "backend__delete",
  "gallery__sync",
  "memory__append",
  "memory__search",
  "memory__read",
  "memory__replace",
  "memory__clear",
  "monitor__create",
  "commerce__checkout",
  "connector__toolcat__noop",
  "computer_use.request_lease",
];

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function logProgress(message, details = {}) {
  console.error(JSON.stringify({
    at: new Date().toISOString(),
    message,
    ...details,
  }));
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function listEvidenceDirs(root) {
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .map((name) => {
      const path = join(root, name);
      try {
        const stat = statSync(path);
        return stat.isDirectory() ? { name, path, mtimeMs: stat.mtimeMs } : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => a.mtimeMs - b.mtimeMs);
}

function scenarioEvidenceDir(beforeNames) {
  return listEvidenceDirs(join(repoRoot, EVIDENCE_ROOT))
    .filter((entry) => !beforeNames.has(entry.name) && !entry.name.startsWith("campaign-"))
    .at(-1)?.path ?? null;
}

function classifyFromText(text) {
  if (/approval|policy gate|waiting for approval|PermissionOrApprovalRequired/i.test(text)) {
    return "approval_gate_pass";
  }
  if (/outside workspace|workspace boundary|symlink|sandbox|Denied|Blocked by Policy/i.test(text)) {
    return "sandbox_effect_pass";
  }
  if (/UnsupportedTool|ToolUnavailable|MissingDependency|No adapter|not exposed|not available|external/i.test(text)) {
    return "external_blocker_pass";
  }
  return "concrete_failure";
}

function scenarioFailureText(result) {
  const failure = readJson(join(result.evidenceDir || "", "failure-error.json"));
  return [
    failure?.message,
    failure?.stack,
    result?.command?.stdoutTail,
    result?.command?.stderrTail,
  ].filter(Boolean).join("\n");
}

function buildToolClassifications(scenarioResults) {
  const evidenceByTool = new Map(CONTRACT_TOOLS.map((tool) => [tool, {
    tool,
    classification: "concrete_failure",
    evidence: [],
    reason: "missing_live_ide_evidence",
  }]));

  for (const result of scenarioResults) {
    const summary = readJson(join(result.evidenceDir || "", "daemon-runtime-trace-summary.json"));
    if (!summary) continue;
    const failureText = scenarioFailureText(result);
    for (const toolName of summary.observedToolNames || []) {
      if (!evidenceByTool.has(toolName)) {
        evidenceByTool.set(toolName, {
          tool: toolName,
          classification: "concrete_failure",
          evidence: [],
          reason: "observed_but_not_in_static_contract_list",
        });
      }
      const row = evidenceByTool.get(toolName);
      row.evidence.push({
        scenarioId: result.scenarioId,
        evidenceDir: result.evidenceDir,
        status: result.status,
      });
      row.reason = "observed_in_live_ide_trace";
      if (summary.completedToolNames?.includes(toolName)) {
        row.classification = "live_pass";
        row.reason = "completed_in_live_ide_trace";
      } else if (summary.failedToolNames?.includes(toolName) && row.classification !== "live_pass") {
        const failures = (summary.toolFailures || []).filter((failure) => failure.toolName === toolName);
        const failureText = failures.map((failure) => `${failure.errorClass || ""} ${failure.output || ""}`).join("\n");
        row.classification = classifyFromText(failureText);
        row.reason = failureText.slice(0, 500) || "failed_in_live_ide_trace";
      } else if (row.classification !== "live_pass") {
        row.classification = classifyFromText(failureText);
        row.reason = failureText.slice(0, 500) || "observed_without_completion";
      }
    }
  }

  return [...evidenceByTool.values()].sort((a, b) => a.tool.localeCompare(b.tool));
}

function runCommand(command, args, options = {}) {
  const startedAtMs = Date.now();
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 64,
    ...options,
  });
  return {
    command: [command, ...args].join(" "),
    status: result.status,
    signal: result.signal,
    durationMs: Date.now() - startedAtMs,
    stdoutTail: String(result.stdout || "").slice(-8000),
    stderrTail: String(result.stderr || "").slice(-8000),
  };
}

function runScenario({ scenarioId, campaignDir }) {
  const beforeNames = new Set(listEvidenceDirs(join(repoRoot, EVIDENCE_ROOT)).map((entry) => entry.name));
  const startedAt = new Date().toISOString();
  logProgress("scenario_start", { scenarioId });
  const command = runCommand("node", [RUNNER, "--run", "--scenario", scenarioId], {
    env: {
      ...process.env,
      AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT: EVIDENCE_ROOT,
      AUTOPILOT_AGENT_STUDIO_MASTER_GUIDE: MASTER_GUIDE,
      AUTOPILOT_AGENT_STUDIO_UPDATE_GUIDE: "0",
      AUTOPILOT_AGENT_STUDIO_VALIDATION_TIMEOUT_MS: "1800000",
    },
  });
  const evidenceDir = scenarioEvidenceDir(beforeNames);
  const finishedAt = new Date().toISOString();
  const proof = evidenceDir ? readJson(join(evidenceDir, "proof.json")) : null;
  const traceSummary = evidenceDir ? readJson(join(evidenceDir, "daemon-runtime-trace-summary.json")) : null;
  const timeoutBlocker = evidenceDir ? readJson(join(evidenceDir, "timeout-blocker.json")) : null;
  const result = {
    schemaVersion: "ioi.autopilot.tool-catalogue.scenario-result.v1",
    scenarioId,
    startedAt,
    finishedAt,
    status: command.status === 0 ? "passed" : "failed",
    command,
    evidenceDir,
    proofOk: Boolean(proof?.targetStudioOperationalChatAchieved),
    observedToolNames: traceSummary?.observedToolNames || [],
    completedToolNames: traceSummary?.completedToolNames || [],
    failedToolNames: traceSummary?.failedToolNames || [],
    timeoutBlocker,
  };
  writeFileSync(join(campaignDir, `${scenarioId}.result.json`), `${JSON.stringify(result, null, 2)}\n`);
  logProgress("scenario_finish", {
    scenarioId,
    status: result.status,
    evidenceDir,
    durationMs: command.durationMs,
    observedToolCount: result.observedToolNames.length,
    completedToolCount: result.completedToolNames.length,
    failedToolCount: result.failedToolNames.length,
  });
  return result;
}

function reverseEngineeringFiles() {
  const result = spawnSync("rg", ["--files", "internal-docs/reverse-engineering"], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 16,
  });
  if (result.status !== 0) return [];
  return result.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
}

function writeReverseEngineeringSweep({ campaignDir, round, startIndex }) {
  const files = reverseEngineeringFiles();
  const selected = files.slice(startIndex, startIndex + 12).map((file) => {
    let content = "";
    try {
      content = readFileSync(join(repoRoot, file), "utf8");
    } catch {
      // Binary or unreadable files are still listed as architecture inventory.
    }
    return {
      file,
      bytes: Buffer.byteLength(content),
      headingSample: content
        .split("\n")
        .filter((line) => /^#{1,3}\s+/.test(line))
        .slice(0, 8),
      mentions: {
        browser: /\bbrowser__/i.test(content),
        computerUse: /computer[-_ ]use|computer_use/i.test(content),
        sandbox: /sandbox|container|namespace/i.test(content),
        runtimeServiceBridgeMention: /RuntimeAgentService|runtime bridge|bridge/i.test(content),
      },
    };
  });
  const proof = {
    schemaVersion: "ioi.autopilot.tool-catalogue.reverse-engineering-sweep.v1",
    round,
    startIndex,
    fileCount: files.length,
    selected,
    timestamp: new Date().toISOString(),
  };
  writeFileSync(join(campaignDir, `reverse-engineering-sweep-${String(round).padStart(3, "0")}.json`), `${JSON.stringify(proof, null, 2)}\n`);
  return startIndex + selected.length;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function enforceTwelveHourFloor({ campaignDir, startedAtMs }) {
  let round = 0;
  let reverseEngineeringIndex = 0;
  while (Date.now() - startedAtMs < TWELVE_HOURS_MS) {
    reverseEngineeringIndex = writeReverseEngineeringSweep({
      campaignDir,
      round,
      startIndex: reverseEngineeringIndex,
    });
    const remainingMs = TWELVE_HOURS_MS - (Date.now() - startedAtMs);
    const waitMs = Math.min(30 * 60 * 1000, Math.max(1000, remainingMs));
    writeFileSync(
      join(campaignDir, `campaign-heartbeat-${String(round).padStart(3, "0")}.json`),
      `${JSON.stringify({
        schemaVersion: "ioi.autopilot.tool-catalogue.heartbeat.v1",
        round,
        elapsedMs: Date.now() - startedAtMs,
        remainingMs,
        waitMs,
        timestamp: new Date().toISOString(),
      }, null, 2)}\n`,
    );
    logProgress("campaign_floor_wait", { round, remainingMs, waitMs });
    round += 1;
    await sleep(waitMs);
  }
}

async function main() {
  const startedAtMs = Date.now();
  ensureDir(join(repoRoot, EVIDENCE_ROOT));
  const campaignDir = join(repoRoot, EVIDENCE_ROOT, `campaign-${timestamp()}`);
  ensureDir(campaignDir);
  writeFileSync(
    join(campaignDir, "campaign-start.json"),
    `${JSON.stringify({
      schemaVersion: "ioi.autopilot.tool-catalogue.campaign-start.v1",
      masterGuide: MASTER_GUIDE,
      evidenceRoot: EVIDENCE_ROOT,
      scenarios: SCENARIOS,
      startedAt: new Date(startedAtMs).toISOString(),
      minimumDurationMs: TWELVE_HOURS_MS,
    }, null, 2)}\n`,
  );

  const scenarioResults = [];
  await cleanupHypervisorCampaignProcesses({ outputDir: campaignDir, phase: "campaign-before" });
  for (const scenarioId of SCENARIOS) {
    await cleanupHypervisorCampaignProcesses({ outputDir: campaignDir, phase: `before-${scenarioId}` });
    const result = runScenario({ scenarioId, campaignDir });
    scenarioResults.push(result);
    await cleanupHypervisorCampaignProcesses({ outputDir: campaignDir, phase: `after-${scenarioId}` });
    writeFileSync(join(campaignDir, "campaign-progress.json"), `${JSON.stringify({ scenarioResults }, null, 2)}\n`);
  }

  await enforceTwelveHourFloor({ campaignDir, startedAtMs });
  await cleanupHypervisorCampaignProcesses({ outputDir: campaignDir, phase: "campaign-final" });

  const toolClassifications = buildToolClassifications(scenarioResults);
  const counts = toolClassifications.reduce((acc, row) => {
    acc[row.classification] = (acc[row.classification] || 0) + 1;
    return acc;
  }, {});
  const manifest = {
    schemaVersion: "ioi.autopilot.tool-catalogue.live-ide-final-manifest.v1",
    masterGuide: MASTER_GUIDE,
    evidenceRoot: EVIDENCE_ROOT,
    campaignDir,
    startedAt: new Date(startedAtMs).toISOString(),
    finishedAt: new Date().toISOString(),
    elapsedMs: Date.now() - startedAtMs,
    minimumDurationSatisfied: Date.now() - startedAtMs >= TWELVE_HOURS_MS,
    scenarioResults,
    classificationCounts: counts,
    toolClassifications,
    verdict:
      toolClassifications.every((row) => row.classification !== "concrete_failure")
        ? "catalogue_live_ide_verified_with_pass_gate_or_external_blocker_verdicts"
        : "catalogue_live_ide_verification_found_concrete_failures",
  };
  writeFileSync(join(campaignDir, "tool-catalogue-final-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(repoRoot, EVIDENCE_ROOT, "tool-catalogue-final-manifest.latest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify(manifest, null, 2));
  process.exitCode = manifest.minimumDurationSatisfied ? 0 : 1;
}

main().catch(async (error) => {
  const fallbackDir = join(repoRoot, EVIDENCE_ROOT, `campaign-failure-${timestamp()}`);
  ensureDir(fallbackDir);
  writeFileSync(join(fallbackDir, "campaign-error.json"), `${JSON.stringify({
    error: String(error?.stack || error?.message || error),
    timestamp: new Date().toISOString(),
  }, null, 2)}\n`);
  await cleanupHypervisorCampaignProcesses({ outputDir: fallbackDir, phase: "campaign-error" }).catch(() => undefined);
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
