import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";

import {
  agentModelMatrixPaths,
  loadAgentModelMatrixBenchmarkCatalog,
  loadAgentModelMatrixPresetCatalog,
  renderAgentModelMatrixMarkdown,
} from "./lib/agent-model-matrix.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const SCORECARD_SCHEMA = {
  version: 1,
  categories: [
    {
      id: "artifactQuality",
      label: "Artifact quality",
      requiredForPromotion: true,
      metrics: [
        "averageJudgeScore",
        "verifierPassRate",
        "averageRepairLoopIterations",
        "routeMatchRate",
      ],
    },
    {
      id: "codingCompletion",
      label: "Coding completion",
      requiredForPromotion: true,
      metrics: [
        "taskPassRate",
        "targetedTestPassRate",
        "verifierPassRate",
      ],
    },
    {
      id: "researchQuality",
      label: "Research quality",
      requiredForPromotion: true,
      metrics: [
        "citationVerifierPassRate",
        "sourceIndependenceRate",
        "synthesisCompleteness",
      ],
    },
    {
      id: "computerUseCompletion",
      label: "Computer-use completion",
      requiredForPromotion: true,
      metrics: [
        "rewardFloorPassRate",
        "postconditionPassRate",
        "meanStepCount",
      ],
    },
    {
      id: "latencyAndResourcePressure",
      label: "Latency and resource pressure",
      requiredForPromotion: true,
      metrics: [
        "meanWallClockMs",
        "p95WallClockMs",
        "residentModelBytes",
        "processorKind",
      ],
    },
    {
      id: "operationalDiscipline",
      label: "Operational discipline",
      requiredForPromotion: false,
      metrics: [
        "malformedToolCallRate",
        "noOpStallRate",
        "repairLoopIterations",
        "interruptionRecoveryQuality",
      ],
    },
  ],
};

const DEFAULT_ARTIFACT_TIMEOUT_MS = 120_000;
const DEFAULT_COMPUTER_USE_TIMEOUT_MS = 180_000;
const DEFAULT_CAPABILITIES_TIMEOUT_MS = 240_000;
const DEFAULT_CAPABILITIES_MIN_STACK_BYTES = "33554432";
const MINIWOB_SOURCE_REPO = "https://github.com/Farama-Foundation/miniwob-plusplus.git";
const RESEARCH_SOURCE_FLOOR = 2;
const RESEARCH_DOMAIN_FLOOR = 2;
const REQUIRED_PROMOTION_CATEGORY_IDS = SCORECARD_SCHEMA.categories
  .filter((category) => category.requiredForPromotion)
  .map((category) => category.id);

let cachedCliBinaryPath = null;
let cachedMiniwobSourceDir = null;

function nowIsoStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  const options = {
    presets: null,
    benchmarks: null,
    skipComputerUse: false,
  };
  for (const arg of argv.slice(2)) {
    if (arg.startsWith("--presets=")) {
      options.presets = arg
        .slice("--presets=".length)
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      continue;
    }
    if (arg.startsWith("--benchmarks=")) {
      options.benchmarks = arg
        .slice("--benchmarks=".length)
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      continue;
    }
    if (arg === "--skip-computer-use") {
      options.skipComputerUse = true;
      continue;
    }
    throw new Error(`Unknown argument '${arg}'`);
  }
  return options;
}

function readJsonIfExists(targetPath) {
  if (!targetPath || !fs.existsSync(targetPath)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(targetPath, "utf8"));
}

function ensureDir(targetPath) {
  fs.mkdirSync(targetPath, { recursive: true });
}

function writeJson(targetPath, value) {
  ensureDir(path.dirname(targetPath));
  fs.writeFileSync(targetPath, `${JSON.stringify(value, null, 2)}\n`);
}

function writeText(targetPath, value) {
  ensureDir(path.dirname(targetPath));
  fs.writeFileSync(targetPath, value);
}

function mean(values) {
  const numeric = values.filter(
    (value) => typeof value === "number" && Number.isFinite(value),
  );
  if (numeric.length === 0) {
    return null;
  }
  return numeric.reduce((sum, value) => sum + value, 0) / numeric.length;
}

function percentile(values, ratio) {
  const numeric = values
    .filter((value) => typeof value === "number" && Number.isFinite(value))
    .sort((left, right) => left - right);
  if (numeric.length === 0) {
    return null;
  }
  const index = Math.min(
    numeric.length - 1,
    Math.max(0, Math.ceil(numeric.length * ratio) - 1),
  );
  return numeric[index];
}

function round(value, digits = 3) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function rate(numerator, denominator) {
  if (
    typeof numerator !== "number" ||
    !Number.isFinite(numerator) ||
    typeof denominator !== "number" ||
    !Number.isFinite(denominator) ||
    denominator <= 0
  ) {
    return null;
  }
  return round(numerator / denominator);
}

function clampedRatio(value, floor) {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    typeof floor !== "number" ||
    !Number.isFinite(floor) ||
    floor <= 0
  ) {
    return null;
  }
  return round(Math.max(0, Math.min(value / floor, 1)));
}

function isPassedStatus(value) {
  return String(value || "").trim().toLowerCase() === "passed";
}

function judgeScore(judge) {
  if (!judge || typeof judge !== "object") {
    return null;
  }
  const fields = [
    "requestFaithfulness",
    "conceptCoverage",
    "interactionRelevance",
    "layoutCoherence",
    "visualHierarchy",
    "completeness",
  ];
  const values = fields
    .map((field) => judge[field])
    .filter((value) => typeof value === "number");
  if (values.length !== fields.length) {
    return null;
  }
  return round(values.reduce((sum, value) => sum + value, 0) / (fields.length * 5));
}

function benchmarkResultFromClassification(classification) {
  const normalized = String(classification || "").trim().toLowerCase();
  if (normalized === "pass" || normalized === "ready") {
    return "pass";
  }
  if (normalized === "repairable" || normalized === "partial") {
    return "near-miss";
  }
  if (normalized) {
    return "red";
  }
  return "unknown";
}

function stripAnsi(value) {
  return String(value || "").replace(
    // eslint-disable-next-line no-control-regex
    /\u001B\[[0-9;]*[A-Za-z]/g,
    "",
  );
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  return {
    status: result.status ?? 1,
    stdout: stripAnsi(result.stdout ?? ""),
    stderr: stripAnsi(result.stderr ?? ""),
    error: result.error ? String(result.error.message || result.error) : null,
    timedOut: result.error?.code === "ETIMEDOUT",
  };
}

function compactFailureSummary(result, fallbackMessage) {
  const merged = `${result?.stderr || ""}\n${result?.stdout || ""}`;
  const lines = merged
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const preferred =
    lines.find((line) => line.startsWith("Error:")) ||
    [...lines].reverse().find((line) => !line.startsWith("warning:")) ||
    lines[0];
  return preferred || fallbackMessage;
}

function compactText(value, limit = 280) {
  if (!value) {
    return "";
  }
  const text = String(value).replace(/\s+/g, " ").trim();
  if (text.length <= limit) {
    return text;
  }
  return `${text.slice(0, limit - 3)}...`;
}

function extractJsonMarkerValues(output, marker) {
  const values = [];
  const lines = String(output || "").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const prefix = `${marker}=`;
    if (!lines[index].startsWith(prefix)) {
      continue;
    }
    let candidate = lines[index].slice(prefix.length);
    while (true) {
      try {
        values.push(JSON.parse(candidate));
        break;
      } catch (error) {
        if (index + 1 >= lines.length) {
          throw new Error(
            `Failed to parse JSON marker '${marker}': ${error.message}`,
          );
        }
        index += 1;
        candidate = `${candidate}\n${lines[index]}`;
      }
    }
  }
  return values;
}

function lastJsonMarkerValue(output, marker) {
  const values = extractJsonMarkerValues(output, marker);
  return values.length > 0 ? values[values.length - 1] : null;
}

function latestCapabilitiesPlaybook(observation, benchmark) {
  const receipts = Array.isArray(observation?.parent_playbook_receipts)
    ? observation.parent_playbook_receipts
    : [];
  const normalizedPlaybookId = String(benchmark?.playbookId || "")
    .trim()
    .toLowerCase();
  const normalizedRouteFamily = String(benchmark?.routeFamily || "")
    .trim()
    .toLowerCase();

  if (normalizedPlaybookId) {
    const exact = [...receipts]
      .reverse()
      .find(
        (receipt) =>
          String(receipt?.playbook_id || "")
            .trim()
            .toLowerCase() === normalizedPlaybookId,
      );
    if (exact) {
      return exact;
    }
  }

  if (normalizedRouteFamily) {
    return (
      [...receipts]
        .reverse()
        .find(
          (receipt) =>
            String(receipt?.route_family || "")
              .trim()
              .toLowerCase() === normalizedRouteFamily,
        ) || null
    );
  }

  return receipts.length > 0 ? receipts[receipts.length - 1] : null;
}

function capabilitiesBenchmarkResult(outcome) {
  if (outcome?.observed_pass === true) {
    return "pass";
  }
  if (outcome?.local?.pass === true || outcome?.arbiter?.pass === true) {
    return "near-miss";
  }
  return "red";
}

function summarizeCapabilitiesBenchmark({
  benchmark,
  playbook,
  outcome,
  result,
}) {
  const localFailures = Array.isArray(outcome?.local?.failures)
    ? outcome.local.failures.filter((value) => typeof value === "string" && value.trim())
    : [];
  const arbiterFailures = Array.isArray(outcome?.arbiter?.failures)
    ? outcome.arbiter.failures.filter((value) => typeof value === "string" && value.trim())
    : [];
  const parts = [
    playbook?.summary,
    localFailures.length > 0 ? `local_failures=${localFailures.join(", ")}` : null,
    arbiterFailures.length > 0
      ? `arbiter_failures=${arbiterFailures.join(", ")}`
      : null,
    outcome?.arbiter?.rationale,
  ].filter(Boolean);

  return (
    compactText(parts[0] || parts.join(" | "), 360) ||
    compactFailureSummary(
      result,
      `${benchmark.title} did not retain parsed capabilities evidence.`,
    ) ||
    `${benchmark.title} did not retain parsed capabilities evidence.`
  );
}

function miniwobSourceLooksValid(candidate) {
  if (!candidate) {
    return false;
  }
  const resolved = path.resolve(candidate);
  const probePaths = [
    resolved,
    path.join(resolved, "html"),
    path.join(resolved, "miniwob", "html"),
  ];
  return probePaths.some((probe) =>
    fs.existsSync(path.join(probe, "core", "core.js")) &&
    fs.existsSync(path.join(probe, "miniwob")),
  );
}

function ensureCliBinary(runRoot) {
  if (cachedCliBinaryPath && fs.existsSync(cachedCliBinaryPath)) {
    return { ok: true, binaryPath: cachedCliBinaryPath };
  }
  const binaryName = process.platform === "win32" ? "cli.exe" : "cli";
  const binaryPath = path.join(repoRoot, "target", "debug", binaryName);
  if (fs.existsSync(binaryPath)) {
    cachedCliBinaryPath = binaryPath;
    return { ok: true, binaryPath };
  }
  const build = runCommand(
    "cargo",
    ["build", "-p", "ioi-cli", "--bin", "cli"],
    {
      env: {
        ...process.env,
        CARGO_TERM_COLOR: "never",
      },
      timeout: 180_000,
    },
  );
  writeText(path.join(runRoot, "cli-build.stdout.log"), build.stdout);
  writeText(path.join(runRoot, "cli-build.stderr.log"), build.stderr);
  if (build.status !== 0 || !fs.existsSync(binaryPath)) {
    return {
      ok: false,
      error:
        compactFailureSummary(build, "Failed to build the ioi-cli benchmark binary.") ||
        "Failed to build the ioi-cli benchmark binary.",
    };
  }
  cachedCliBinaryPath = binaryPath;
  return { ok: true, binaryPath };
}

function ensureMiniwobSourceDir(runRoot) {
  if (cachedMiniwobSourceDir && miniwobSourceLooksValid(cachedMiniwobSourceDir)) {
    return { ok: true, sourceDir: cachedMiniwobSourceDir };
  }

  for (const key of ["COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR", "MINIWOB_SOURCE_DIR"]) {
    const raw = process.env[key];
    if (raw && miniwobSourceLooksValid(raw)) {
      cachedMiniwobSourceDir = path.resolve(raw);
      return { ok: true, sourceDir: cachedMiniwobSourceDir };
    }
  }

  const cacheDir = path.join(repoRoot, "target", "benchmarks", "miniwob-plusplus");
  if (miniwobSourceLooksValid(cacheDir)) {
    cachedMiniwobSourceDir = cacheDir;
    return { ok: true, sourceDir: cacheDir };
  }

  fs.rmSync(cacheDir, { recursive: true, force: true });
  ensureDir(path.dirname(cacheDir));
  const clone = runCommand(
    "git",
    ["clone", "--depth", "1", MINIWOB_SOURCE_REPO, cacheDir],
    {
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: "0",
      },
      timeout: 180_000,
    },
  );
  writeText(path.join(runRoot, "miniwob-source-bootstrap.stdout.log"), clone.stdout);
  writeText(path.join(runRoot, "miniwob-source-bootstrap.stderr.log"), clone.stderr);
  if (clone.status !== 0 || !miniwobSourceLooksValid(cacheDir)) {
    return {
      ok: false,
      error:
        compactFailureSummary(
          clone,
          "Failed to clone or validate the MiniWoB source checkout.",
        ) || "Failed to clone or validate the MiniWoB source checkout.",
    };
  }
  cachedMiniwobSourceDir = cacheDir;
  return { ok: true, sourceDir: cacheDir };
}

function probeOllamaModel(preset) {
  const probe = {
    availabilityStatus: "blocked",
    availabilitySummary: "Local runtime health probe did not return the configured model.",
    processorKind: null,
    residentModelBytes: null,
    modelSizeBytes: null,
  };
  if (!preset.runtimeHealthUrl) {
    probe.availabilitySummary = "Preset does not declare a health endpoint.";
    return probe;
  }
  const health = runCommand("curl", ["-fsS", preset.runtimeHealthUrl]);
  if (health.status !== 0) {
    probe.availabilitySummary = `Health probe failed: ${health.stderr || health.error || "unknown error"}`;
    return probe;
  }
  let payload;
  try {
    payload = JSON.parse(health.stdout);
  } catch {
    probe.availabilitySummary = "Health probe returned invalid JSON.";
    return probe;
  }
  const models = Array.isArray(payload?.models) ? payload.models : [];
  const model = models.find((entry) => {
    const name = entry?.model ?? entry?.name ?? "";
    return name === preset.runtimeModel;
  });
  if (!model) {
    probe.availabilitySummary = `Configured model '${preset.runtimeModel}' is not loaded in the local runtime.`;
    return probe;
  }
  probe.availabilityStatus = "ready";
  probe.availabilitySummary = `Local runtime is healthy and exposes '${preset.runtimeModel}'.`;
  probe.modelSizeBytes = Number(model?.size ?? 0) || null;

  const ps = runCommand("ollama", ["ps"]);
  if (ps.status === 0) {
    const lines = ps.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const entry = lines.find((line) => line.startsWith(`${preset.runtimeModel} `));
    if (entry) {
      const parts = entry.split(/\s{2,}/).map((value) => value.trim());
      probe.processorKind = parts[3] ?? null;
    }
  }
  return probe;
}

function probeRemotePreset(preset) {
  const url = process.env[preset.runtimeUrlEnv || ""];
  const apiKey = process.env[preset.apiKeyEnv || ""];
  const runtimeModel =
    process.env[preset.runtimeModelEnv || ""] || preset.defaultRuntimeModel || null;
  if (!url || !apiKey) {
    return {
      availabilityStatus: "blocked",
      availabilitySummary:
        "Remote multimodal runtime credentials are not configured in this environment.",
      runtimeModel,
      processorKind: null,
      residentModelBytes: null,
      modelSizeBytes: null,
    };
  }
  return {
    availabilityStatus: "configured",
    availabilitySummary: "Remote runtime credentials are present but phase-0 did not execute this lane in the local pass.",
    runtimeModel,
    processorKind: null,
    residentModelBytes: null,
    modelSizeBytes: null,
  };
}

function availabilityForPreset(preset) {
  if (preset.runtimeKind === "local_http") {
    return probeOllamaModel(preset);
  }
  if (preset.runtimeKind === "remote_http") {
    return probeRemotePreset(preset);
  }
  return {
    availabilityStatus: "blocked",
    availabilitySummary: `Unsupported runtime kind '${preset.runtimeKind}'.`,
    processorKind: null,
    residentModelBytes: null,
    modelSizeBytes: null,
  };
}

function artifactAcceptanceModelForPreset(preset) {
  return preset.artifactAcceptanceModel || preset.runtimeModel;
}

function benchmarkAttempted(caseResult) {
  return caseResult?.status && caseResult.status !== "blocked";
}

function runArtifactBenchmark(preset, benchmark, benchmarkRoot) {
  const outputRoot = path.join(benchmarkRoot, "artifact");
  const startedAt = Date.now();
  const timeoutMs = Number(benchmark.timeoutMs || DEFAULT_ARTIFACT_TIMEOUT_MS);
  const cliBinary = ensureCliBinary(benchmarkRoot);
  if (!cliBinary.ok) {
    return {
      benchmarkId: benchmark.benchmarkId,
      title: benchmark.title,
      workload: benchmark.workload,
      runner: benchmark.runner,
      status: "blocked",
      result: "unknown",
      elapsedMs: null,
      summary: cliBinary.error,
      evidencePath: null,
      evidenceRoot: benchmarkRoot,
      stdoutPath: path.join(benchmarkRoot, "cli-build.stdout.log"),
      stderrPath: path.join(benchmarkRoot, "cli-build.stderr.log"),
    };
  }
  const command = [
    "artifact",
    "generate",
    benchmark.prompt,
    "--output",
    outputRoot,
    "--force",
    "--local",
    "--api-url",
    preset.runtimeUrl,
    "--api-key",
    "ollama",
    "--model-name",
    preset.runtimeModel,
    "--acceptance-api-url",
    preset.runtimeUrl,
    "--acceptance-api-key",
    "ollama",
    "--acceptance-model-name",
    artifactAcceptanceModelForPreset(preset),
    "--json",
  ];
  const result = runCommand(cliBinary.binaryPath, command, {
    env: {
      ...process.env,
      LOCAL_LLM_URL: preset.runtimeUrl,
      LOCAL_LLM_MODEL: preset.runtimeModel,
      AUTOPILOT_LOCAL_RUNTIME_URL: preset.runtimeUrl,
      AUTOPILOT_LOCAL_RUNTIME_MODEL: preset.runtimeModel,
      AUTOPILOT_ACCEPTANCE_RUNTIME_URL: preset.runtimeUrl,
      AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL: artifactAcceptanceModelForPreset(preset),
    },
    timeout: timeoutMs,
  });
  const elapsedMs = Date.now() - startedAt;
  writeText(path.join(benchmarkRoot, "command.stdout.log"), result.stdout);
  writeText(path.join(benchmarkRoot, "command.stderr.log"), result.stderr);
  writeJson(path.join(benchmarkRoot, "command.json"), {
    command: [cliBinary.binaryPath, ...command],
    exitStatus: result.status,
    elapsedMs,
    timedOut: result.timedOut === true,
    timeoutMs,
  });

  const generationPath = path.join(outputRoot, "generation.json");
  const generation = readJsonIfExists(generationPath);
  const judge = generation?.judge ?? null;
  const manifestVerification = generation?.manifest?.verification ?? {};
  const repairLoopIterations = Array.isArray(generation?.candidateSummaries)
    ? generation.candidateSummaries.filter((entry) => {
        const candidateId = String(entry?.candidateId || "");
        const strategy = String(entry?.strategy || "");
        return candidateId.includes("refine") || strategy.includes("refinement");
      }).length
    : 0;
  const caseResult =
    result.status === 0 && generation
      ? benchmarkResultFromClassification(judge?.classification)
      : "red";
  return {
    benchmarkId: benchmark.benchmarkId,
    title: benchmark.title,
    workload: benchmark.workload,
    runner: benchmark.runner,
    status: result.status === 0 && generation ? "completed" : result.timedOut ? "timed_out" : "failed",
    result: caseResult,
    elapsedMs,
    timedOut: result.timedOut === true,
    judgeScore: judgeScore(judge),
    verifierPass: manifestVerification?.status === "ready",
    repairLoopIterations,
    routeMatched:
      generation?.route?.artifact?.artifactClass === benchmark.expectedArtifactClass &&
      generation?.route?.artifact?.renderer === benchmark.expectedRenderer,
    summary:
      (result.timedOut
        ? `Artifact benchmark timed out after ${timeoutMs}ms.`
        : null) ||
      generation?.verifiedReply?.summary ||
      judge?.rationale ||
      compactFailureSummary(
        result,
        "Artifact benchmark did not produce retained evidence.",
      ) ||
      "Artifact benchmark did not produce retained evidence.",
    evidencePath: generationPath,
    evidenceRoot: outputRoot,
    stdoutPath: path.join(benchmarkRoot, "command.stdout.log"),
    stderrPath: path.join(benchmarkRoot, "command.stderr.log"),
  };
}

function runComputerUseBenchmark(preset, benchmark, benchmarkRoot) {
  const sourceDir = ensureMiniwobSourceDir(benchmarkRoot);
  if (!sourceDir.ok) {
    return {
      benchmarkId: benchmark.benchmarkId,
      title: benchmark.title,
      workload: benchmark.workload,
      runner: benchmark.runner,
      status: "blocked",
      result: "unknown",
      elapsedMs: null,
      summary: `MiniWoB source bootstrap failed: ${sourceDir.error || "unknown error"}`,
      evidencePath: null,
      evidenceRoot: benchmarkRoot,
      stdoutPath: path.join(benchmarkRoot, "miniwob-source-bootstrap.stdout.log"),
      stderrPath: path.join(benchmarkRoot, "miniwob-source-bootstrap.stderr.log"),
    };
  }

  const artifactRoot = path.join(benchmarkRoot, "artifacts");
  const startedAt = Date.now();
  const timeoutMs = Number(
    benchmark.timeoutMs || DEFAULT_COMPUTER_USE_TIMEOUT_MS,
  );
  const command = [
    "test",
    "-p",
    "ioi-cli",
    "--test",
    "computer_use_suite_e2e",
    "computer_use_suite_from_env",
    "--",
    "--ignored",
    "--exact",
    "--nocapture",
  ];
  const result = runCommand("cargo", command, {
    env: {
      ...process.env,
      OPENAI_API_URL: preset.runtimeUrl,
      OPENAI_API_KEY: "ollama",
      OPENAI_MODEL: preset.runtimeModel,
      COMPUTER_USE_SUITE_MODE: "agent",
      COMPUTER_USE_SUITE_TASK_SET: benchmark.taskSet || "smoke",
      COMPUTER_USE_SUITE_CASES: benchmark.caseId,
      COMPUTER_USE_SUITE_MAX_CASES: "1",
      COMPUTER_USE_SUITE_AGENT_BACKEND: "live_http",
      COMPUTER_USE_SUITE_FAIL_ON_FAILURE: "0",
      COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS: "1",
      COMPUTER_USE_SUITE_HEADLESS: "1",
      COMPUTER_USE_SUITE_ARTIFACT_DIR: artifactRoot,
      COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR: sourceDir.sourceDir,
      CARGO_TERM_COLOR: "never",
    },
    timeout: timeoutMs,
  });
  const elapsedMs = Date.now() - startedAt;
  writeText(path.join(benchmarkRoot, "command.stdout.log"), result.stdout);
  writeText(path.join(benchmarkRoot, "command.stderr.log"), result.stderr);
  writeJson(path.join(benchmarkRoot, "command.json"), {
    command: ["cargo", ...command],
    exitStatus: result.status,
    elapsedMs,
    timedOut: result.timedOut === true,
    timeoutMs,
  });

  const caseRoot = path.join(artifactRoot, "agent", benchmark.caseId);
  const benchmarkSummaryPath = path.join(caseRoot, "benchmark_summary.json");
  const diagnosticSummaryPath = path.join(caseRoot, "diagnostic_summary.json");
  const summaryPayload =
    readJsonIfExists(benchmarkSummaryPath) || readJsonIfExists(diagnosticSummaryPath);
  const summary = summaryPayload?.summary ?? {};
  const detailDiagnostic = readJsonIfExists(diagnosticSummaryPath);
  const stepCount = Array.isArray(detailDiagnostic?.timeline)
    ? detailDiagnostic.timeline.length
    : typeof summary?.episode_step === "number"
      ? summary.episode_step
      : null;
  const rewardFloorMet =
    typeof summary?.reward_floor_met === "boolean"
      ? summary.reward_floor_met
      : summary?.result_label === "pass";
  return {
    benchmarkId: benchmark.benchmarkId,
    title: benchmark.title,
    workload: benchmark.workload,
    runner: benchmark.runner,
    status:
      result.status === 0 && summaryPayload
        ? "completed"
        : result.timedOut
          ? "timed_out"
          : "failed",
    result:
      result.status === 0 && summaryPayload
        ? summary?.result_label || (rewardFloorMet ? "pass" : "red")
        : "red",
    elapsedMs,
    timedOut: result.timedOut === true,
    rewardFloorMet,
    stepCount,
    summary:
      (result.timedOut
        ? `Computer-use benchmark timed out after ${timeoutMs}ms.`
        : null) ||
      summaryPayload?.summary?.query_text ||
      detailDiagnostic?.summary?.query_text ||
      compactFailureSummary(
        result,
        "Computer-use benchmark did not retain summary evidence.",
      ) ||
      "Computer-use benchmark did not retain summary evidence.",
    evidencePath: benchmarkSummaryPath,
    evidenceRoot: caseRoot,
    stdoutPath: path.join(benchmarkRoot, "command.stdout.log"),
    stderrPath: path.join(benchmarkRoot, "command.stderr.log"),
  };
}

function runCapabilitiesBenchmark(preset, benchmark, benchmarkRoot) {
  const startedAt = Date.now();
  const timeoutMs = Number(
    benchmark.timeoutMs || DEFAULT_CAPABILITIES_TIMEOUT_MS,
  );
  const cognitionTimeoutSecs = Number(preset.cognitionInferenceTimeoutSecs || 0);
  const command = [
    "test",
    "-p",
    "ioi-cli",
    "--test",
    "capabilities_suite_e2e",
    "capabilities_query_suite_e2e",
    "--",
    "--ignored",
    "--exact",
    "--nocapture",
  ];
  const result = runCommand("cargo", command, {
    env: {
      ...process.env,
      OPENAI_API_URL: preset.runtimeUrl,
      OPENAI_API_KEY: "ollama",
      OPENAI_MODEL: preset.runtimeModel,
      RUST_MIN_STACK: DEFAULT_CAPABILITIES_MIN_STACK_BYTES,
      CAPABILITIES_E2E_ARBITER_MODEL: artifactAcceptanceModelForPreset(preset),
      CAPABILITIES_ONLY_CASE: benchmark.caseId,
      CAPABILITIES_PROFILE: benchmark.executionProfile || "hermetic",
      CAPABILITIES_MAX_ATTEMPTS: "1",
      CAPABILITIES_DEBUG_OBSERVATION: "1",
      CAPABILITIES_DUMP_KERNEL_LOGS: "failure",
      CARGO_TERM_COLOR: "never",
      ...(cognitionTimeoutSecs > 0
        ? {
            IOI_COGNITION_INFERENCE_TIMEOUT_SECS: String(cognitionTimeoutSecs),
          }
        : {}),
    },
    timeout: timeoutMs,
  });
  const elapsedMs = Date.now() - startedAt;
  writeText(path.join(benchmarkRoot, "command.stdout.log"), result.stdout);
  writeText(path.join(benchmarkRoot, "command.stderr.log"), result.stderr);
  writeJson(path.join(benchmarkRoot, "command.json"), {
    command: ["cargo", ...command],
    exitStatus: result.status,
    elapsedMs,
    timedOut: result.timedOut === true,
    timeoutMs,
    caseId: benchmark.caseId,
    cognitionInferenceTimeoutSecs:
      cognitionTimeoutSecs > 0 ? cognitionTimeoutSecs : null,
  });

  let outcome = null;
  let observation = null;
  let suiteSummary = null;
  let parseError = null;
  try {
    outcome = lastJsonMarkerValue(
      result.stdout,
      `CAPABILITIES_CASE_RESULT_${benchmark.caseId}`,
    );
    observation = lastJsonMarkerValue(
      result.stdout,
      `CAPABILITIES_CASE_OBSERVATION_${benchmark.caseId}_ATTEMPT_1`,
    );
    suiteSummary = lastJsonMarkerValue(result.stdout, "CAPABILITIES_SUITE_SUMMARY");
  } catch (error) {
    parseError = error;
  }

  const playbook = latestCapabilitiesPlaybook(observation, benchmark);
  const codingScorecard = playbook?.coding_scorecard ?? null;
  const researchScorecard = playbook?.research_scorecard ?? null;
  const patchSynthesis = playbook?.patch_synthesis ?? null;
  const retainedEvidencePath = path.join(benchmarkRoot, "retained-result.json");
  if (outcome || observation || suiteSummary || playbook) {
    writeJson(retainedEvidencePath, {
      benchmarkId: benchmark.benchmarkId,
      caseId: benchmark.caseId,
      title: benchmark.title,
      workload: benchmark.workload,
      presetId: preset.id,
      outcome,
      observation,
      suiteSummary,
      playbook,
    });
  }

  const targetedCommandCount = Number(codingScorecard?.targeted_command_count ?? 0);
  const targetedPassCount = Number(codingScorecard?.targeted_pass_count ?? 0);
  const sourceCount = Number(researchScorecard?.source_count ?? 0);
  const distinctDomainCount = Number(
    researchScorecard?.distinct_domain_count ?? 0,
  );
  const hasRetainedEvidence = Boolean(outcome && observation);

  return {
    benchmarkId: benchmark.benchmarkId,
    title: benchmark.title,
    workload: benchmark.workload,
    runner: benchmark.runner,
    caseId: benchmark.caseId,
    status: hasRetainedEvidence
      ? "completed"
      : result.timedOut
        ? "timed_out"
        : "failed",
    result: hasRetainedEvidence ? capabilitiesBenchmarkResult(outcome) : "red",
    elapsedMs,
    timedOut: result.timedOut === true,
    taskPassed: outcome?.observed_pass === true,
    localScore:
      typeof outcome?.local?.score === "number" ? round(outcome.local.score) : null,
    arbiterPass: outcome?.arbiter?.pass === true,
    playbookId: playbook?.playbook_id ?? null,
    routeFamily: playbook?.route_family ?? null,
    topology: playbook?.topology ?? null,
    verifierState: playbook?.verifier_state ?? null,
    verifierPass:
      benchmark.workload === "coding"
        ? isPassedStatus(codingScorecard?.verdict)
        : benchmark.workload === "research"
          ? isPassedStatus(researchScorecard?.verdict)
          : null,
    targetedCommandCount: targetedCommandCount || null,
    targetedPassCount: targetedPassCount || null,
    targetedTestPassRate: rate(targetedPassCount, targetedCommandCount),
    patchSynthesisReady: patchSynthesis?.verification_ready === true,
    citationVerifierPass: isPassedStatus(researchScorecard?.verdict),
    sourceCount: sourceCount || null,
    distinctDomainCount: distinctDomainCount || null,
    sourceCountFloorRate: clampedRatio(sourceCount, RESEARCH_SOURCE_FLOOR),
    sourceIndependenceRate: clampedRatio(
      distinctDomainCount,
      RESEARCH_DOMAIN_FLOOR,
    ),
    synthesisCompleteness:
      typeof outcome?.local?.score === "number" ? round(outcome.local.score) : null,
    freshnessPassed: isPassedStatus(researchScorecard?.freshness_status),
    quoteGroundingPassed: isPassedStatus(
      researchScorecard?.quote_grounding_status,
    ),
    summary:
      (result.timedOut
        ? `Capabilities benchmark timed out after ${timeoutMs}ms.`
        : null) ||
      (parseError ? parseError.message : null) ||
      summarizeCapabilitiesBenchmark({
        benchmark,
        playbook,
        outcome,
        result,
      }),
    evidencePath:
      hasRetainedEvidence || suiteSummary || playbook ? retainedEvidencePath : null,
    evidenceRoot: benchmarkRoot,
    stdoutPath: path.join(benchmarkRoot, "command.stdout.log"),
    stderrPath: path.join(benchmarkRoot, "command.stderr.log"),
  };
}

function summarizePreset(preset, availability, caseResults, presetRoot) {
  const artifactCases = caseResults.filter((entry) => entry.workload === "artifacts");
  const attemptedArtifactCases = artifactCases.filter(benchmarkAttempted);
  const artifactJudgeScores = attemptedArtifactCases.map((entry) => entry.judgeScore);
  const artifactVerifierPasses = attemptedArtifactCases.filter(
    (entry) => entry.verifierPass === true,
  ).length;
  const artifactRouteMatches = attemptedArtifactCases.filter(
    (entry) => entry.routeMatched === true,
  ).length;
  const artifactRepairLoops = attemptedArtifactCases.map(
    (entry) => entry.repairLoopIterations,
  );

  const computerUseCases = caseResults.filter(
    (entry) => entry.workload === "computer_use",
  );
  const attemptedComputerUseCases = computerUseCases.filter(benchmarkAttempted);
  const computerUseRewardPasses = attemptedComputerUseCases.filter(
    (entry) => entry.rewardFloorMet === true,
  ).length;
  const computerUseStepCounts = attemptedComputerUseCases.map((entry) => entry.stepCount);

  const codingCases = caseResults.filter((entry) => entry.workload === "coding");
  const attemptedCodingCases = codingCases.filter(benchmarkAttempted);
  const codingTaskPasses = attemptedCodingCases.filter(
    (entry) => entry.taskPassed === true,
  ).length;
  const codingVerifierPasses = attemptedCodingCases.filter(
    (entry) => entry.verifierPass === true,
  ).length;
  const codingTargetedTestRates = attemptedCodingCases.map(
    (entry) => entry.targetedTestPassRate,
  );
  const codingPatchSynthesisReady = attemptedCodingCases.filter(
    (entry) => entry.patchSynthesisReady === true,
  ).length;

  const researchCases = caseResults.filter((entry) => entry.workload === "research");
  const attemptedResearchCases = researchCases.filter(benchmarkAttempted);
  const researchTaskPasses = attemptedResearchCases.filter(
    (entry) => entry.taskPassed === true,
  ).length;
  const citationVerifierPasses = attemptedResearchCases.filter(
    (entry) => entry.citationVerifierPass === true,
  ).length;
  const researchSourceIndependenceRates = attemptedResearchCases.map(
    (entry) => entry.sourceIndependenceRate,
  );
  const researchSourceFloorRates = attemptedResearchCases.map(
    (entry) => entry.sourceCountFloorRate,
  );
  const researchSynthesisScores = attemptedResearchCases.map(
    (entry) => entry.synthesisCompleteness,
  );
  const researchFreshnessPasses = attemptedResearchCases.filter(
    (entry) => entry.freshnessPassed === true,
  ).length;
  const researchQuoteGroundingPasses = attemptedResearchCases.filter(
    (entry) => entry.quoteGroundingPassed === true,
  ).length;

  const attemptedCases = caseResults.filter(benchmarkAttempted);
  const wallClockValues = attemptedCases.map((entry) => entry.elapsedMs);
  const topFindings = [];
  for (const entry of caseResults) {
    if (entry.status !== "completed") {
      topFindings.push(`${entry.title}: ${entry.summary}`);
      continue;
    }
    if (entry.result === "red" || entry.result === "near-miss") {
      topFindings.push(`${entry.title}: ${entry.summary}`);
    }
  }

  return {
    presetId: preset.id,
    label: preset.label,
    role: preset.role,
    benchmarkTier: preset.benchmarkTier,
    experimental: preset.experimental === true,
    shippedDefault: preset.shippedDefault === true,
    runtimeModel: preset.runtimeModel || preset.defaultRuntimeModel || null,
    artifactAcceptanceModel: artifactAcceptanceModelForPreset(preset),
    availabilityStatus: availability.availabilityStatus,
    availabilitySummary: availability.availabilitySummary,
    caseCount: caseResults.length,
    availableWorkloadCount: [
      attemptedArtifactCases.length > 0,
      attemptedCodingCases.length > 0,
      attemptedResearchCases.length > 0,
      attemptedComputerUseCases.length > 0,
    ].filter(Boolean).length,
    topFindings: topFindings.slice(0, 4),
    scorecards: {
      artifactQuality: {
        available: attemptedArtifactCases.length > 0,
        reason:
          attemptedArtifactCases.length > 0
            ? ""
            : "No retained artifact benchmarks were executed for this preset in the current pass.",
        metrics: {
          benchmarkCount: attemptedArtifactCases.length,
          passRate:
            attemptedArtifactCases.length > 0
              ? round(
                  attemptedArtifactCases.filter((entry) => entry.result === "pass").length /
                    attemptedArtifactCases.length,
                )
              : null,
          averageJudgeScore: mean(artifactJudgeScores),
          verifierPassRate:
            attemptedArtifactCases.length > 0
              ? round(artifactVerifierPasses / attemptedArtifactCases.length)
              : null,
          averageRepairLoopIterations: mean(artifactRepairLoops),
          routeMatchRate:
            attemptedArtifactCases.length > 0
              ? round(artifactRouteMatches / attemptedArtifactCases.length)
              : null,
        },
      },
      codingCompletion: {
        available: attemptedCodingCases.length > 0,
        reason:
          attemptedCodingCases.length > 0
            ? ""
            : "No retained coding benchmark was executed for this preset in the current pass.",
        metrics: {
          benchmarkCount: attemptedCodingCases.length,
          taskPassRate: rate(codingTaskPasses, attemptedCodingCases.length),
          targetedTestPassRate: mean(codingTargetedTestRates),
          verifierPassRate: rate(codingVerifierPasses, attemptedCodingCases.length),
          patchSynthesisReadyRate: rate(
            codingPatchSynthesisReady,
            attemptedCodingCases.length,
          ),
        },
      },
      researchQuality: {
        available: attemptedResearchCases.length > 0,
        reason:
          attemptedResearchCases.length > 0
            ? ""
            : "No retained research benchmark was executed for this preset in the current pass.",
        metrics: {
          benchmarkCount: attemptedResearchCases.length,
          taskPassRate: rate(researchTaskPasses, attemptedResearchCases.length),
          citationVerifierPassRate: rate(
            citationVerifierPasses,
            attemptedResearchCases.length,
          ),
          sourceIndependenceRate: mean(researchSourceIndependenceRates),
          sourceCountFloorRate: mean(researchSourceFloorRates),
          synthesisCompleteness: mean(researchSynthesisScores),
          freshnessPassRate: rate(researchFreshnessPasses, attemptedResearchCases.length),
          quoteGroundingPassRate: rate(
            researchQuoteGroundingPasses,
            attemptedResearchCases.length,
          ),
        },
      },
      computerUseCompletion: {
        available: attemptedComputerUseCases.length > 0,
        reason:
          attemptedComputerUseCases.length > 0
            ? ""
            : "No retained computer-use benchmark was executed for this preset in the current pass.",
        metrics: {
          benchmarkCount: attemptedComputerUseCases.length,
          rewardFloorPassRate:
            attemptedComputerUseCases.length > 0
              ? round(computerUseRewardPasses / attemptedComputerUseCases.length)
              : null,
          postconditionPassRate:
            attemptedComputerUseCases.length > 0
              ? round(computerUseRewardPasses / attemptedComputerUseCases.length)
              : null,
          meanStepCount: mean(computerUseStepCounts),
        },
      },
      latencyAndResourcePressure: {
        available: attemptedCases.length > 0,
        reason:
          attemptedCases.length > 0
            ? ""
            : "No executed benchmarks were retained for this preset in the current pass.",
        metrics: {
          meanWallClockMs: round(mean(wallClockValues)),
          p95WallClockMs: round(percentile(wallClockValues, 0.95)),
          residentModelBytes: availability.modelSizeBytes,
          processorKind: availability.processorKind,
        },
      },
      operationalDiscipline: {
        available: attemptedCases.length > 0,
        reason:
          attemptedCases.length > 0
            ? ""
            : "No operational benchmark outputs were retained for this preset in the current pass.",
        metrics: {
          malformedToolCallRate: null,
          noOpStallRate: null,
          repairLoopIterations: mean(artifactRepairLoops),
          interruptionRecoveryQuality: null,
        },
      },
    },
    cases: caseResults,
    summaryPath: path.join(presetRoot, "summary.json"),
    runRootPath: presetRoot,
  };
}

function compareHigherBetter(left, right) {
  const leftValid = typeof left === "number" && Number.isFinite(left);
  const rightValid = typeof right === "number" && Number.isFinite(right);
  if (!leftValid && !rightValid) {
    return 0;
  }
  if (!leftValid) {
    return -1;
  }
  if (!rightValid) {
    return 1;
  }
  if (left === right) {
    return 0;
  }
  return left > right ? 1 : -1;
}

function compareLowerBetter(left, right) {
  return compareHigherBetter(
    typeof left === "number" ? -left : left,
    typeof right === "number" ? -right : right,
  );
}

function compareMetricSeries(series) {
  for (const [left, right, mode] of series) {
    const comparison =
      mode === "lower"
        ? compareLowerBetter(left, right)
        : compareHigherBetter(left, right);
    if (comparison !== 0) {
      return comparison;
    }
  }
  return 0;
}

function presetHasRequiredCoverage(preset) {
  return REQUIRED_PROMOTION_CATEGORY_IDS.every(
    (categoryId) => preset.scorecards[categoryId]?.available === true,
  );
}

function comparePresetCategory(leftPreset, rightPreset, categoryId) {
  const leftMetrics = leftPreset.scorecards[categoryId]?.metrics ?? {};
  const rightMetrics = rightPreset.scorecards[categoryId]?.metrics ?? {};
  switch (categoryId) {
    case "artifactQuality":
      return compareMetricSeries([
        [leftMetrics.passRate, rightMetrics.passRate, "higher"],
        [leftMetrics.averageJudgeScore, rightMetrics.averageJudgeScore, "higher"],
        [leftMetrics.verifierPassRate, rightMetrics.verifierPassRate, "higher"],
        [leftMetrics.routeMatchRate, rightMetrics.routeMatchRate, "higher"],
        [
          leftMetrics.averageRepairLoopIterations,
          rightMetrics.averageRepairLoopIterations,
          "lower",
        ],
      ]);
    case "codingCompletion":
      return compareMetricSeries([
        [leftMetrics.taskPassRate, rightMetrics.taskPassRate, "higher"],
        [leftMetrics.verifierPassRate, rightMetrics.verifierPassRate, "higher"],
        [leftMetrics.targetedTestPassRate, rightMetrics.targetedTestPassRate, "higher"],
        [
          leftMetrics.patchSynthesisReadyRate,
          rightMetrics.patchSynthesisReadyRate,
          "higher",
        ],
      ]);
    case "researchQuality":
      return compareMetricSeries([
        [
          leftMetrics.citationVerifierPassRate,
          rightMetrics.citationVerifierPassRate,
          "higher",
        ],
        [
          leftMetrics.sourceIndependenceRate,
          rightMetrics.sourceIndependenceRate,
          "higher",
        ],
        [
          leftMetrics.synthesisCompleteness,
          rightMetrics.synthesisCompleteness,
          "higher",
        ],
        [leftMetrics.freshnessPassRate, rightMetrics.freshnessPassRate, "higher"],
        [
          leftMetrics.quoteGroundingPassRate,
          rightMetrics.quoteGroundingPassRate,
          "higher",
        ],
      ]);
    case "computerUseCompletion":
      return compareMetricSeries([
        [
          leftMetrics.postconditionPassRate,
          rightMetrics.postconditionPassRate,
          "higher",
        ],
        [
          leftMetrics.rewardFloorPassRate,
          rightMetrics.rewardFloorPassRate,
          "higher",
        ],
        [leftMetrics.meanStepCount, rightMetrics.meanStepCount, "lower"],
      ]);
    case "latencyAndResourcePressure":
      return compareMetricSeries([
        [leftMetrics.meanWallClockMs, rightMetrics.meanWallClockMs, "lower"],
        [leftMetrics.p95WallClockMs, rightMetrics.p95WallClockMs, "lower"],
      ]);
    default:
      return 0;
  }
}

function compareChallengerAgainstDefault(leftPreset, rightPreset, defaultPreset) {
  const leftWins = REQUIRED_PROMOTION_CATEGORY_IDS.filter(
    (categoryId) => comparePresetCategory(leftPreset, defaultPreset, categoryId) > 0,
  ).length;
  const rightWins = REQUIRED_PROMOTION_CATEGORY_IDS.filter(
    (categoryId) => comparePresetCategory(rightPreset, defaultPreset, categoryId) > 0,
  ).length;
  if (leftWins !== rightWins) {
    return leftWins - rightWins;
  }

  const leftTies = REQUIRED_PROMOTION_CATEGORY_IDS.filter(
    (categoryId) => comparePresetCategory(leftPreset, defaultPreset, categoryId) >= 0,
  ).length;
  const rightTies = REQUIRED_PROMOTION_CATEGORY_IDS.filter(
    (categoryId) => comparePresetCategory(rightPreset, defaultPreset, categoryId) >= 0,
  ).length;
  if (leftTies !== rightTies) {
    return leftTies - rightTies;
  }

  return comparePresetCategory(
    leftPreset,
    rightPreset,
    "latencyAndResourcePressure",
  );
}

function decisionForRun(presets) {
  const defaultPreset = presets.find((preset) => preset.shippedDefault);
  const artifactLeader = [...presets]
    .filter((preset) => preset.scorecards.artifactQuality.available)
    .sort((left, right) => {
      const leftScore =
        left.scorecards.artifactQuality.metrics.averageJudgeScore ?? -Infinity;
      const rightScore =
        right.scorecards.artifactQuality.metrics.averageJudgeScore ?? -Infinity;
      if (leftScore !== rightScore) {
        return rightScore - leftScore;
      }
      return left.label.localeCompare(right.label);
    })[0];

  const missingCoverage = REQUIRED_PROMOTION_CATEGORY_IDS.filter(
    (categoryId) =>
      !presets.some(
        (preset) =>
          preset.experimental === true &&
          preset.scorecards[categoryId]?.available === true,
      ),
  );
  const experimentalWithCoverage = presets.filter(
    (preset) => preset.experimental === true && presetHasRequiredCoverage(preset),
  );
  const eligibleChallengers =
    defaultPreset && presetHasRequiredCoverage(defaultPreset)
      ? experimentalWithCoverage
          .filter((preset) => {
            const comparisons = REQUIRED_PROMOTION_CATEGORY_IDS.map((categoryId) =>
              comparePresetCategory(preset, defaultPreset, categoryId),
            );
            return comparisons.every((comparison) => comparison >= 0)
              && comparisons.some((comparison) => comparison > 0);
          })
          .sort((left, right) => {
            const comparison = compareChallengerAgainstDefault(
              right,
              left,
              defaultPreset,
            );
            if (comparison !== 0) {
              return comparison;
            }
            return left.label.localeCompare(right.label);
          })
      : [];
  const leadChallenger = eligibleChallengers[0] || null;

  if (!artifactLeader) {
    return {
      outcome: "keep_default",
      summary:
        "No challenger retained a completed benchmark slice, so the shipped default remains unchanged.",
      leaderPresetId: defaultPreset?.presetId ?? null,
      artifactLeaderPresetId: null,
      missingCoverage,
    };
  }

  if (missingCoverage.length > 0) {
    return {
      outcome: "keep_default",
      summary: `${artifactLeader.label} leads the retained artifact slice, but the matrix still lacks required workload coverage for ${missingCoverage.join(", ")}. Keep the shipped default unchanged.`,
      leaderPresetId: defaultPreset?.presetId ?? null,
      artifactLeaderPresetId: artifactLeader.presetId,
      missingCoverage,
    };
  }

  if (leadChallenger) {
    return {
      outcome: "keep_default",
      summary: `${leadChallenger.label} leads the fully covered scorecard on this comparison pass, but the shipped default stays in place until a challenger wins repeatedly across retained runs.`,
      leaderPresetId: leadChallenger.presetId,
      artifactLeaderPresetId: artifactLeader.presetId,
      missingCoverage,
    };
  }

  return {
    outcome: "keep_default",
    summary:
      defaultPreset && presetHasRequiredCoverage(defaultPreset)
        ? "The shipped default still holds the fully covered scorecard on this comparison pass."
        : "Retained coverage is present, but no experimental preset cleared the promotion gate over the shipped default on this pass.",
    leaderPresetId: defaultPreset?.presetId ?? artifactLeader.presetId,
    artifactLeaderPresetId: artifactLeader.presetId,
    missingCoverage,
  };
}

function main() {
  const options = parseArgs(process.argv);
  const paths = agentModelMatrixPaths({ repoRoot });
  const presetCatalog = loadAgentModelMatrixPresetCatalog({ repoRoot });
  const benchmarkCatalog = loadAgentModelMatrixBenchmarkCatalog({ repoRoot });
  if (!presetCatalog || !Array.isArray(presetCatalog.presets)) {
    throw new Error(`Preset catalog is missing or invalid at ${paths.presetCatalogPath}`);
  }
  if (!benchmarkCatalog || !Array.isArray(benchmarkCatalog.benchmarks)) {
    throw new Error(
      `Benchmark catalog is missing or invalid at ${paths.benchmarkCatalogPath}`,
    );
  }

  const runId = nowIsoStamp();
  const runRoot = path.join(paths.runsRoot, runId);
  ensureDir(runRoot);

  const selectedPresets = presetCatalog.presets.filter((preset) =>
    options.presets ? options.presets.includes(preset.id) : true,
  );
  const selectedBenchmarks = benchmarkCatalog.benchmarks.filter((benchmark) => {
    if (options.benchmarks && !options.benchmarks.includes(benchmark.benchmarkId)) {
      return false;
    }
    if (options.skipComputerUse && benchmark.workload === "computer_use") {
      return false;
    }
    return true;
  });

  const presetSummaries = [];
  for (const preset of selectedPresets) {
    const presetRoot = path.join(runRoot, preset.id);
    ensureDir(presetRoot);
    const availability = availabilityForPreset(preset);
    const caseResults = [];
    if (
      availability.availabilityStatus === "ready" &&
      preset.runtimeKind === "local_http"
    ) {
      for (const benchmark of selectedBenchmarks) {
        const benchmarkRoot = path.join(presetRoot, benchmark.benchmarkId);
        ensureDir(benchmarkRoot);
        let caseResult;
        if (benchmark.runner === "artifact_generate") {
          caseResult = runArtifactBenchmark(preset, benchmark, benchmarkRoot);
        } else if (benchmark.runner === "computer_use_suite") {
          caseResult = runComputerUseBenchmark(preset, benchmark, benchmarkRoot);
        } else if (benchmark.runner === "capabilities_suite") {
          caseResult = runCapabilitiesBenchmark(preset, benchmark, benchmarkRoot);
        } else {
          caseResult = {
            benchmarkId: benchmark.benchmarkId,
            title: benchmark.title,
            workload: benchmark.workload,
            runner: benchmark.runner,
            status: "blocked",
            result: "unknown",
            elapsedMs: null,
            summary: `Unsupported benchmark runner '${benchmark.runner}'.`,
            evidencePath: null,
            evidenceRoot: benchmarkRoot,
            stdoutPath: null,
            stderrPath: null,
          };
        }
        caseResults.push(caseResult);
      }
    }
    if (availability.availabilityStatus !== "ready") {
      caseResults.push(
        ...selectedBenchmarks.map((benchmark) => ({
          benchmarkId: benchmark.benchmarkId,
          title: benchmark.title,
          workload: benchmark.workload,
          runner: benchmark.runner,
          status: "blocked",
          result: "unknown",
          elapsedMs: null,
          summary: availability.availabilitySummary,
          evidencePath: null,
          evidenceRoot: path.join(presetRoot, benchmark.benchmarkId),
          stdoutPath: null,
          stderrPath: null,
        })),
      );
    }
    const summary = summarizePreset(preset, availability, caseResults, presetRoot);
    writeJson(summary.summaryPath, summary);
    presetSummaries.push(summary);
  }

  const decision = decisionForRun(presetSummaries);
  const latestSummary = {
    version: 1,
    status: "ready",
    runId,
    generatedAt: new Date().toISOString(),
    presetCatalogPath: paths.presetCatalogPath,
    benchmarkCatalogPath: paths.benchmarkCatalogPath,
    summaryPath: paths.latestSummaryPath,
    runRootPath: runRoot,
    executedPresetCount: presetSummaries.filter((preset) =>
      preset.cases.some(benchmarkAttempted),
    ).length,
    comparedPresetCount: presetSummaries.length,
    preservedDefault: decision.outcome !== "promote_challenger",
    scorecardSchema: SCORECARD_SCHEMA,
    decision,
    presets: presetSummaries,
  };

  writeJson(paths.latestSummaryPath, latestSummary);
  writeText(paths.latestSummaryMarkdownPath, renderAgentModelMatrixMarkdown(latestSummary));
  console.log(
    `Agent model matrix summary written to ${paths.latestSummaryPath} (${presetSummaries.length} presets, decision=${decision.outcome})`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}

export { decisionForRun };
