import fs from "fs";
import path from "path";
import { spawn, spawnSync } from "child_process";
import crypto from "crypto";
import { fileURLToPath } from "url";

import {
  agentModelMatrixPaths,
  loadAgentModelMatrixBenchmarkCatalog,
  loadAgentModelMatrixPresetCatalog,
  renderAgentModelMatrixMarkdown,
} from "./lib/agent-model-matrix.mjs";
import {
  DEFAULT_CONFORMANCE_POLICY_IDS,
  DEPLOYMENT_PROFILES,
  FAILURE_ONTOLOGY,
  REQUIRED_DECISION_CATEGORY_IDS,
  SCORECARD_CATEGORY_ID_BY_FAMILY,
  SCORECARD_SCHEMA,
  deploymentProfileForPresetLike,
  inferRoleAssignmentsForPreset,
  normalizeDeploymentProfileId,
  scorecardDecisionWeight,
} from "./lib/benchmark-matrix-contracts.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const DEFAULT_ARTIFACT_TIMEOUT_MS = 120_000;
const DEFAULT_COMPUTER_USE_TIMEOUT_MS = 180_000;
const DEFAULT_CAPABILITIES_TIMEOUT_MS = 240_000;
const DEFAULT_PRESET_WARMUP_TIMEOUT_MS = 60_000;
const DEFAULT_PRESET_TRANSITION_SETTLE_TIMEOUT_MS = 45_000;
const DEFAULT_PRESET_TRANSITION_POLL_INTERVAL_MS = 1_000;
const DEFAULT_EARLY_ABORT_TIMEOUT_COUNT = 2;
const DEFAULT_CAPABILITIES_MIN_STACK_BYTES = "33554432";
const REQUIRED_RETAINED_PROMOTION_WINS = 2;
const DEFAULT_OLLAMA_CONTEXT_LENGTH = "8192";
const LIVE_HTML_ARTIFACT_OLLAMA_CONTEXT_LENGTH = "4096";
const STUDIO_PROOF_TRACE_PREFIX = "[studio-proof-trace] ";
const MINIWOB_SOURCE_REPO = "https://github.com/Farama-Foundation/miniwob-plusplus.git";
const RESEARCH_SOURCE_FLOOR = 2;
const RESEARCH_DOMAIN_FLOOR = 2;
const CATEGORY_SHORT_LABELS = {
  baseModelQuality: "Base model",
  artifactQuality: "Artifact",
  codingCompletion: "Coding",
  researchQuality: "Research",
  computerUseCompletion: "Computer use",
  toolApiReliability: "Tool/API",
  generalAgentQuality: "General agent",
  latencyAndResourcePressure: "Latency",
  operationalDiscipline: "Conformance",
};
const INTERRUPT_SIGNALS = ["SIGINT", "SIGTERM"];
const COMMAND_TERMINATION_GRACE_MS = 5_000;
const TERMINAL_BENCHMARK_STATUSES = new Set([
  "completed",
  "failed",
  "timed_out",
  "blocked",
  "dependency_blocked",
  "not_run",
]);
const RUNNER_SCHEMA_VERSION = 2;
const RUNNER_VERSION = "benchmark-matrix-v2";

let cachedCliBinaryPath = null;
let cachedMiniwobSourceDir = null;
let interruptHandlersRegistered = false;
let pendingInterruptSignal = null;
let activeCommandState = null;

function nowIsoStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  const options = {
    presets: null,
    benchmarks: null,
    skipComputerUse: false,
    comparisonIntent: null,
    executionScope: "fleet_shared",
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
    if (arg.startsWith("--comparison-intent=")) {
      options.comparisonIntent = arg.slice("--comparison-intent=".length).trim() || null;
      continue;
    }
    if (arg.startsWith("--execution-scope=")) {
      options.executionScope = arg.slice("--execution-scope=".length).trim() || "fleet_shared";
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
  try {
    return JSON.parse(fs.readFileSync(targetPath, "utf8"));
  } catch {
    return null;
  }
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

function sleepMs(durationMs) {
  if (
    typeof durationMs !== "number" ||
    !Number.isFinite(durationMs) ||
    durationMs <= 0
  ) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, durationMs);
    if (typeof timer?.unref === "function") {
      timer.unref();
    }
  });
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

function sha256Text(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function stableJsonHash(value) {
  return sha256Text(JSON.stringify(value ?? null));
}

function gitCommand(args) {
  const result = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    return null;
  }
  return String(result.stdout || "").trim() || null;
}

function gitHeadSha() {
  return gitCommand(["rev-parse", "HEAD"]);
}

function gitDirtyWorktree() {
  const result = spawnSync("git", ["status", "--porcelain"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    return null;
  }
  return String(result.stdout || "").trim().length > 0;
}

function inferBenchmarkFamily(benchmark) {
  const explicit = String(benchmark?.family || "").trim();
  if (explicit) {
    return explicit;
  }
  switch (benchmark?.workload) {
    case "artifacts":
      return "artifacts";
    case "coding":
      return "coding";
    case "research":
      return "research";
    case "computer_use":
      return "computer_use";
    default:
      return "general_agent";
  }
}

function normalizeBenchmarkDefinition(benchmark, catalogVersion = 1) {
  const family = inferBenchmarkFamily(benchmark);
  const adapter = String(benchmark?.adapter || benchmark?.runner || "").trim() || "unknown";
  const splitClass = String(benchmark?.splitClass || "validation").trim();
  const splitVisibility = String(
    benchmark?.splitVisibility ||
      (splitClass === "holdout" ? "hidden" : splitClass === "challenge" ? "restricted" : "open"),
  ).trim();
  const labelExposurePolicy = String(
    benchmark?.labelExposurePolicy ||
      (splitVisibility === "open"
        ? "full_trace"
        : splitVisibility === "restricted"
          ? "bounded_summary"
          : "verdict_only"),
  ).trim();
  const benchmarkProgram = String(
    benchmark?.benchmarkProgram ||
      (String(benchmark?.packId || "").trim() === "repo_native_retained"
        ? "repo_native_retained"
        : "public_screening"),
  ).trim();
  return {
    ...benchmark,
    catalogVersion,
    benchmarkId: String(benchmark?.benchmarkId || "").trim(),
    title: String(benchmark?.title || benchmark?.benchmarkId || "").trim(),
    family,
    adapter,
    runner: String(benchmark?.runner || adapter).trim() || adapter,
    benchmarkProgram,
    packId: String(
      benchmark?.packId ||
        (benchmarkProgram === "repo_native_retained"
          ? "repo_native_retained"
          : `${family}_pack`),
    ).trim(),
    packVersion: Number(benchmark?.packVersion ?? catalogVersion ?? 1),
    splitClass,
    splitVisibility,
    labelExposurePolicy,
    seedPolicy: benchmark?.seedPolicy || "single_seed",
    repeatCount: Number(benchmark?.repeatCount ?? 1),
    conformancePolicyIds: Array.isArray(benchmark?.conformancePolicyIds)
      ? benchmark.conformancePolicyIds
      : DEFAULT_CONFORMANCE_POLICY_IDS,
    requiredModalities: Array.isArray(benchmark?.requiredModalities)
      ? benchmark.requiredModalities
      : ["text"],
    deploymentProfiles: Array.isArray(benchmark?.deploymentProfiles)
      ? benchmark.deploymentProfiles
      : DEPLOYMENT_PROFILES.map((profile) => profile.id),
    lifecycleState: String(
      benchmark?.lifecycleState || (benchmark?.enabledByDefault === false ? "shadow" : "active"),
    ).trim(),
    enabledByDefault: benchmark?.enabledByDefault !== false,
  };
}

function executionScopeIsValid(value) {
  return ["fleet_shared", "actor_family", "actor_local"].includes(String(value || ""));
}

function runtimeModelFingerprint(preset, availability) {
  return {
    modelId: preset?.runtimeModel || preset?.defaultRuntimeModel || null,
    artifactValidationModelId: artifactAcceptanceModelForPreset(preset),
    runtimeKind: preset?.runtimeKind || null,
    backendId: preset?.backendId || null,
    backendSource: preset?.backendSource || null,
    availabilityStatus: availability?.availabilityStatus || null,
    residentModelBytes: availability?.residentModelBytes ?? null,
    processorKind: availability?.processorKind ?? null,
  };
}

function comparisonIntentBetweenPresets(baselinePreset, preset, explicitIntent = null) {
  if (explicitIntent) {
    return explicitIntent;
  }
  const baselineId = baselinePreset?.presetId ?? baselinePreset?.id ?? null;
  const presetId = preset?.presetId ?? preset?.id ?? null;
  if (!baselinePreset || (baselineId && presetId && baselineId === presetId)) {
    return "baseline_anchor";
  }
  const roleChanged = String(baselinePreset?.role || "") !== String(preset?.role || "");
  const deploymentChanged =
    deploymentProfileForPreset(baselinePreset) !== deploymentProfileForPreset(preset);
  const modelChanged =
    String(baselinePreset?.runtimeModel || baselinePreset?.defaultRuntimeModel || "") !==
    String(preset?.runtimeModel || preset?.defaultRuntimeModel || "");
  if (roleChanged && modelChanged) {
    return "full_stack_change";
  }
  if (deploymentChanged && modelChanged) {
    return "full_stack_change";
  }
  if (roleChanged || deploymentChanged) {
    return "role_assignment_change";
  }
  if (modelChanged) {
    return "model_change";
  }
  return "harness_change";
}

function inferredRunComparisonIntent(selectedPresets, explicitIntent = null) {
  if (explicitIntent) {
    return explicitIntent;
  }
  if (!Array.isArray(selectedPresets) || selectedPresets.length <= 1) {
    return "harness_change";
  }
  const first = selectedPresets[0];
  const intents = new Set(
    selectedPresets.map((preset) => comparisonIntentBetweenPresets(first, preset)),
  );
  if (intents.size === 1) {
    return [...intents][0];
  }
  if (intents.has("full_stack_change") || intents.has("role_assignment_change")) {
    return "full_stack_change";
  }
  return "model_change";
}

function baseFailureClassForResult(caseResult) {
  if (FAILURE_ONTOLOGY.includes(caseResult?.primaryFailureClass)) {
    return caseResult.primaryFailureClass;
  }
  switch (caseResult?.status) {
    case "dependency_blocked":
      return "dependency";
    case "blocked":
      return "infra";
    case "timed_out":
      return "latency_or_budget";
    case "failed":
      return "quality";
    default:
      return "quality";
  }
}

function conformanceChecksForBenchmark(benchmark, preset, runContext, caseResult) {
  const checks = [
    {
      id: "comparison_intent_declared",
      status: runContext?.comparisonIntent ? "pass" : "fail",
      summary: runContext?.comparisonIntent
        ? `comparison intent '${runContext.comparisonIntent}' declared`
        : "comparison intent missing",
    },
    {
      id: "deployment_profile_declared",
      status: deploymentProfileForPreset(preset) ? "pass" : "fail",
      summary: deploymentProfileForPreset(preset)
        ? `deployment profile '${deploymentProfileForPreset(preset)}' declared`
        : "deployment profile missing",
    },
    {
      id: "split_visibility_respected",
      status:
        benchmark.splitVisibility === "hidden" &&
        benchmark.labelExposurePolicy === "full_trace"
          ? "fail"
          : "pass",
      summary:
        benchmark.splitVisibility === "hidden" &&
        benchmark.labelExposurePolicy === "full_trace"
          ? "protected split exposes full trace"
          : `split '${benchmark.splitClass}' uses '${benchmark.labelExposurePolicy}' exposure`,
    },
    {
      id: "no_implicit_cloud_promotion",
      status:
        deploymentProfileForPreset(preset).startsWith("blind_cloud") &&
        preset?.shippedDefault === true
          ? "warn"
          : "pass",
      summary:
        deploymentProfileForPreset(preset).startsWith("blind_cloud") &&
        preset?.shippedDefault === true
          ? "blind-cloud default must stay profile-scoped"
          : "no implicit cross-profile promotion detected",
    },
    {
      id: "adapter_contract_declared",
      status: benchmark.adapter && benchmark.family ? "pass" : "fail",
      summary:
        benchmark.adapter && benchmark.family
          ? `adapter '${benchmark.adapter}' mapped to family '${benchmark.family}'`
          : "adapter or family metadata missing",
    },
    {
      id: "adapter_execution_supported",
      status:
        caseResult?.status === "dependency_blocked"
          ? "warn"
          : caseResult?.status === "blocked"
            ? "warn"
            : "pass",
      summary:
        caseResult?.status === "dependency_blocked"
          ? "adapter declared but dependency wiring is incomplete"
          : caseResult?.status === "blocked"
            ? "benchmark was blocked before execution"
            : "adapter executed or remained eligible for execution",
    },
  ];
  const failCount = checks.filter((check) => check.status === "fail").length;
  const warnCount = checks.filter((check) => check.status === "warn").length;
  return {
    status: failCount > 0 ? "fail" : warnCount > 0 ? "warn" : "pass",
    failCount,
    warnCount,
    checkCount: checks.length,
    checks,
  };
}

function normalizeCaseResult(benchmark, preset, availability, caseResult, runContext) {
  const comparisonEligible =
    availability?.availabilityStatus === "ready" &&
    caseResult?.status !== "dependency_blocked" &&
    caseResult?.status !== "blocked" &&
    caseResult?.status !== "not_run";
  const conformanceReport = conformanceChecksForBenchmark(
    benchmark,
    preset,
    runContext,
    caseResult,
  );
  const normalizedScore =
    typeof caseResult?.validationScore === "number"
      ? round(caseResult.validationScore)
      : typeof caseResult?.localScore === "number"
        ? round(caseResult.localScore)
        : typeof caseResult?.rewardFloorMet === "boolean"
          ? (caseResult.rewardFloorMet ? 1 : 0)
          : caseResult?.result === "pass"
            ? 1
            : caseResult?.result === "near-miss"
              ? 0.5
              : caseResult?.result === "red"
                ? 0
                : null;
  return {
    ...caseResult,
    adapter: benchmark.adapter,
    benchmarkFamily: benchmark.family,
    benchmarkProgram: benchmark.benchmarkProgram,
    packId: benchmark.packId,
    packVersion: benchmark.packVersion,
    splitClass: benchmark.splitClass,
    splitVisibility: benchmark.splitVisibility,
    labelExposurePolicy: benchmark.labelExposurePolicy,
    requiredModalities: benchmark.requiredModalities,
    comparisonIntent: comparisonIntentBetweenPresets(
      runContext?.baselinePreset ?? null,
      preset,
      runContext?.comparisonIntent ?? null,
    ),
    validForComparison: comparisonEligible && conformanceReport.failCount === 0,
    invalidReason:
      comparisonEligible && conformanceReport.failCount === 0
        ? ""
        : availability?.availabilityStatus !== "ready"
          ? availability?.availabilitySummary || "preset unavailable"
          : caseResult?.status === "dependency_blocked"
            ? "adapter dependency blocked"
            : caseResult?.status === "blocked"
              ? "benchmark execution blocked"
              : conformanceReport.failCount > 0
                ? "conformance checks failed"
                : "comparison context incomplete",
    normalizedScore,
    primaryFailureClass: baseFailureClassForResult(caseResult),
    failureTags: Array.isArray(caseResult?.failureTags)
      ? caseResult.failureTags
      : caseResult?.status === "dependency_blocked"
        ? ["adapter_unavailable"]
        : caseResult?.timedOut === true
          ? ["timeout"]
          : [],
    conformanceReport,
    protectedEvidence: {
      splitClass: benchmark.splitClass,
      splitVisibility: benchmark.splitVisibility,
      labelExposurePolicy: benchmark.labelExposurePolicy,
    },
  };
}

function aggregateCategoryStatus(caseResults, categoryId) {
  const relevantResults = caseResults.filter(
    (entry) => SCORECARD_CATEGORY_ID_BY_FAMILY[entry?.benchmarkFamily] === categoryId,
  );
  const attemptedResults = relevantResults.filter(benchmarkAttempted);
  const comparisonValidCount = relevantResults.filter(
    (entry) => entry?.validForComparison === true,
  ).length;
  const conformancePassCount = relevantResults.filter(
    (entry) => entry?.conformanceReport?.status === "pass",
  ).length;
  return {
    benchmarkCount: attemptedResults.length,
    totalBenchmarkCount: relevantResults.length,
    comparisonStatus:
      attemptedResults.length === 0
        ? "not_comparable"
        : comparisonValidCount === attemptedResults.length
          ? "comparable"
          : "caution",
    confidenceClass:
      attemptedResults.length >= 3 ? "high" : attemptedResults.length >= 2 ? "medium" : "low",
    coverageClass:
      relevantResults.length === 0
        ? "none"
        : attemptedResults.length === relevantResults.length
          ? "full"
          : attemptedResults.length > 0
            ? "partial"
            : "none",
    benchmarkPrograms: [...new Set(relevantResults.map((entry) => entry?.benchmarkProgram).filter(Boolean))],
    conformancePassRate: attemptedResults.length > 0 ? round(conformancePassCount / attemptedResults.length) : null,
    comparisonValidityRate:
      attemptedResults.length > 0 ? round(comparisonValidCount / attemptedResults.length) : null,
  };
}

function deploymentProfileForPreset(preset) {
  return deploymentProfileForPresetLike(preset);
}

function validationScore(validation) {
  if (!validation || typeof validation !== "object") {
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
    .map((field) => validation[field])
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

function ollamaContextLengthForArtifactBenchmark(benchmark) {
  return benchmark?.expectedRenderer === "html_iframe"
    ? LIVE_HTML_ARTIFACT_OLLAMA_CONTEXT_LENGTH
    : DEFAULT_OLLAMA_CONTEXT_LENGTH;
}

function isManagedLocalOllamaPreset(preset) {
  return preset?.runtimeKind === "local_http" && preset?.family === "ollama_openai";
}

function ollamaManagedModelNamesForPreset(preset) {
  if (!isManagedLocalOllamaPreset(preset)) {
    return [];
  }
  return [...new Set(
    [preset.runtimeModel, artifactAcceptanceModelForPreset(preset)]
      .map((value) => String(value || "").trim())
      .filter(Boolean),
  )];
}

function ollamaResidentModelNamesFromPsOutput(output) {
  return [...new Set(
    ollamaResidentEntriesFromPsOutput(output).map((entry) => entry.name),
  )];
}

function ollamaResidentEntriesFromPsOutput(output) {
  return String(output || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^(\S+)\s+(.*)$/);
      if (!match) {
        return null;
      }
      const [, name, remainder] = match;
      const parts = remainder
        .split(/\s{2,}/)
        .map((value) => value.trim())
        .filter(Boolean);
      return {
        name,
        id: parts[0] || null,
        size: parts[1] || null,
        processor: parts[2] || null,
        context: parts[3] || null,
        until: parts[4] || null,
      };
    })
    .filter((entry) => entry && entry.name && entry.name !== "NAME");
}

function shouldIsolatePresetTransition(currentPreset, nextPreset) {
  return (
    isManagedLocalOllamaPreset(currentPreset) &&
    isManagedLocalOllamaPreset(nextPreset) &&
    currentPreset.family === nextPreset.family
  );
}

function ollamaModelsToStopForTransition(currentPreset, nextPreset, psOutput) {
  if (!shouldIsolatePresetTransition(currentPreset, nextPreset)) {
    return [];
  }
  const resident = ollamaResidentModelNamesFromPsOutput(psOutput);
  const keepResident = new Set(ollamaManagedModelNamesForPreset(nextPreset));
  return resident.filter((name) => !keepResident.has(name));
}

function stripAnsi(value) {
  return String(value || "").replace(
    // eslint-disable-next-line no-control-regex
    /\u001B\[[0-9;]*[A-Za-z]/g,
    "",
  );
}

function ollamaGenerateUrlForPreset(preset) {
  const base =
    preset?.runtimeHealthUrl ||
    preset?.runtimeUrl ||
    "http://127.0.0.1:11434/api/tags";
  try {
    return new URL("/api/generate", base).toString();
  } catch {
    return null;
  }
}

function ollamaWarmupPayloadForModel(model) {
  return JSON.stringify({
    model,
    prompt: "Reply with OK.",
    stream: false,
    keep_alive: "10m",
    options: {
      num_predict: 1,
      temperature: 0,
    },
  });
}

function ollamaTransitionStatusForPsOutput(nextPreset, psOutput) {
  const residentEntries = ollamaResidentEntriesFromPsOutput(psOutput);
  const warmModels = ollamaManagedModelNamesForPreset(nextPreset);
  const keepResident = new Set(warmModels);
  const blockingModels = residentEntries
    .filter((entry) => !keepResident.has(entry.name))
    .map((entry) => entry.name);
  const warmedEntries = residentEntries.filter((entry) => keepResident.has(entry.name));
  const missingWarmModels = warmModels.filter(
    (model) => !warmedEntries.some((entry) => entry.name === model),
  );
  const stoppingWarmModels = warmedEntries
    .filter((entry) => String(entry.until || "").toLowerCase().includes("stopping"))
    .map((entry) => entry.name);
  return {
    ready:
      blockingModels.length === 0 &&
      missingWarmModels.length === 0 &&
      stoppingWarmModels.length === 0,
    blockingModels,
    missingWarmModels,
    stoppingWarmModels,
  };
}

function signalExitCode(signal) {
  switch (signal) {
    case "SIGINT":
      return 130;
    case "SIGTERM":
      return 143;
    default:
      return 1;
  }
}

function interruptSignalRequested() {
  return pendingInterruptSignal;
}

function interruptAbortReason(signal = pendingInterruptSignal) {
  return signal ? `Run interrupted by ${signal}.` : null;
}

function registerInterruptHandlers() {
  if (interruptHandlersRegistered) {
    return;
  }
  interruptHandlersRegistered = true;
  for (const signal of INTERRUPT_SIGNALS) {
    process.on(signal, () => {
      if (!pendingInterruptSignal) {
        pendingInterruptSignal = signal;
      }
      activeCommandState?.requestInterrupt?.(signal);
    });
  }
}

function killChildProcessTree(child, signal = "SIGTERM") {
  if (!child?.pid) {
    return;
  }
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
      stdio: "ignore",
    });
    return;
  }
  try {
    process.kill(-child.pid, signal);
    return;
  } catch (error) {
    if (error?.code !== "ESRCH") {
      try {
        child.kill(signal);
      } catch {}
    }
  }
}

function beginEscalatingTermination(child, signal = "SIGTERM") {
  killChildProcessTree(child, signal);
  const timer = setTimeout(() => {
    killChildProcessTree(child, "SIGKILL");
  }, COMMAND_TERMINATION_GRACE_MS);
  if (typeof timer?.unref === "function") {
    timer.unref();
  }
  return timer;
}

async function runCommand(command, args, options = {}) {
  registerInterruptHandlers();
  const { timeout, maxBuffer: _maxBuffer, ...spawnOptions } = options;
  return await new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let errorMessage = null;
    let timedOut = false;
    let interrupted = false;
    let requestedSignal = null;
    let terminationTimer = null;
    let timeoutTimer = null;
    let settled = false;

    const child = spawn(command, args, {
      cwd: repoRoot,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
      ...spawnOptions,
    });

    const commandState = {
      requestInterrupt(signal) {
        interrupted = true;
        requestedSignal = requestedSignal || signal;
        errorMessage = errorMessage || `Interrupted by ${signal}.`;
        if (!settled && !terminationTimer) {
          terminationTimer = beginEscalatingTermination(child, signal);
        }
      },
    };
    activeCommandState = commandState;

    const clearTimers = () => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
      }
      if (terminationTimer) {
        clearTimeout(terminationTimer);
      }
    };

    timeoutTimer =
      typeof timeout === "number" && Number.isFinite(timeout) && timeout > 0
        ? setTimeout(() => {
            timedOut = true;
            errorMessage = errorMessage || `Command timed out after ${timeout}ms.`;
            if (!settled && !terminationTimer) {
              terminationTimer = beginEscalatingTermination(child, "SIGTERM");
            }
          }, timeout)
        : null;
    if (typeof timeoutTimer?.unref === "function") {
      timeoutTimer.unref();
    }

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr?.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      errorMessage = String(error?.message || error);
    });
    child.on("close", (code, signal) => {
      settled = true;
      clearTimers();
      if (activeCommandState === commandState) {
        activeCommandState = null;
      }
      resolve({
        status: typeof code === "number" ? code : 1,
        stdout: stripAnsi(stdout),
        stderr: stripAnsi(stderr),
        error:
          errorMessage ||
          (signal
            ? `Command terminated by ${signal}.`
            : timedOut
              ? `Command timed out after ${timeout}ms.`
              : interrupted
                ? `Interrupted by ${requestedSignal || "signal"}.`
                : null),
        timedOut,
        interrupted,
        signal: requestedSignal || signal || null,
      });
    });

    if (pendingInterruptSignal) {
      commandState.requestInterrupt(pendingInterruptSignal);
    }
  });
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

function studioProofTraceMessages(output) {
  return String(output || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith(STUDIO_PROOF_TRACE_PREFIX))
    .map((line) => line.slice(STUDIO_PROOF_TRACE_PREFIX.length).trim())
    .filter(Boolean);
}

function artifactCommandDiagnostics(result) {
  const merged = `${result?.stderr || ""}\n${result?.stdout || ""}`;
  const traceMessages = studioProofTraceMessages(merged);
  const lines = merged
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const lastProviderError =
    [...lines].reverse().find((line) => line.includes("Provider Error")) || null;
  const compactFailure = compactFailureSummary(result, "");
  return {
    timedOut: result?.timedOut === true,
    commandError: compactText(result?.error || "", 240) || null,
    studioProofTraceCount: traceMessages.length,
    lastStudioProofTrace:
      traceMessages.length > 0 ? traceMessages[traceMessages.length - 1] : null,
    lastProviderError: compactText(lastProviderError, 240) || null,
    compactFailure: compactText(compactFailure, 240) || null,
  };
}

function artifactTimeoutSummary(timeoutMs, diagnostics) {
  const summary = [`Artifact benchmark timed out after ${timeoutMs}ms.`];
  if (diagnostics?.lastStudioProofTrace) {
    summary.push(
      `Last trace: ${compactText(diagnostics.lastStudioProofTrace, 180)}.`,
    );
  }
  if (diagnostics?.lastProviderError) {
    summary.push(
      `Provider error: ${compactText(diagnostics.lastProviderError, 180)}.`,
    );
  } else if (
    diagnostics?.commandError
    && !diagnostics.commandError.toLowerCase().includes("etimedout")
  ) {
    summary.push(`Runner error: ${compactText(diagnostics.commandError, 180)}.`);
  }
  return summary.join(" ");
}

function interruptedBenchmarkSummary(label, result, diagnostics = null) {
  const summary = [`${label} interrupted by ${result?.signal || "signal"}.`];
  if (diagnostics?.lastStudioProofTrace) {
    summary.push(
      `Last trace: ${compactText(diagnostics.lastStudioProofTrace, 180)}.`,
    );
  }
  if (diagnostics?.lastProviderError) {
    summary.push(
      `Provider error: ${compactText(diagnostics.lastProviderError, 180)}.`,
    );
  } else {
    const failure = compactText(compactFailureSummary(result, ""), 180);
    if (failure && !failure.toLowerCase().includes("interrupted by")) {
      summary.push(`Last output: ${failure}.`);
    }
  }
  return summary.join(" ");
}

function benchmarkStatusFromCommandResult(result, success) {
  if (success) {
    return "completed";
  }
  if (result?.interrupted === true) {
    return "interrupted";
  }
  if (result?.timedOut === true) {
    return "timed_out";
  }
  return "failed";
}

function benchmarkResultForCommandResult(result, successResult) {
  if (result?.interrupted === true) {
    return "unknown";
  }
  return successResult;
}

function timeoutDiagnosticLabel(caseResult) {
  if (!caseResult || caseResult.timedOut !== true) {
    return null;
  }
  const label = caseResult.benchmarkId || caseResult.title || "unknown-benchmark";
  const details = [];
  if (caseResult.lastStudioProofTrace) {
    details.push(`last_trace=${compactText(caseResult.lastStudioProofTrace, 120)}`);
  }
  if (caseResult.lastProviderError) {
    details.push(`provider_error=${compactText(caseResult.lastProviderError, 120)}`);
  }
  if (details.length === 0) {
    return label;
  }
  return `${label} (${details.join(" | ")})`;
}

function appendText(targetPath, value) {
  ensureDir(path.dirname(targetPath));
  fs.appendFileSync(targetPath, value);
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

async function ensureCliBinary(runRoot) {
  if (cachedCliBinaryPath && fs.existsSync(cachedCliBinaryPath)) {
    return { ok: true, binaryPath: cachedCliBinaryPath };
  }
  const binaryName = process.platform === "win32" ? "cli.exe" : "cli";
  const binaryPath = path.join(repoRoot, "target", "debug", binaryName);
  if (fs.existsSync(binaryPath)) {
    cachedCliBinaryPath = binaryPath;
    return { ok: true, binaryPath };
  }
  const build = await runCommand(
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

async function ensureMiniwobSourceDir(runRoot) {
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
  const clone = await runCommand(
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

async function probeOllamaModel(preset) {
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
  const health = await runCommand("curl", ["-fsS", preset.runtimeHealthUrl]);
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

  const ps = await runCommand("ollama", ["ps"]);
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

async function isolateOllamaPresetTransition({
  currentPreset,
  nextPreset,
  runRoot,
}) {
  if (!shouldIsolatePresetTransition(currentPreset, nextPreset)) {
    return { ok: true };
  }
  const transitionRoot = path.join(runRoot, "_preset_transitions");
  const logPath = path.join(
    transitionRoot,
    `${currentPreset.id}--to--${nextPreset.id}.log`,
  );
  const ps = await runCommand("ollama", ["ps"], { timeout: 15_000 });
  appendText(
    logPath,
    [
      `from=${currentPreset.id}`,
      `to=${nextPreset.id}`,
      `ps_status=${ps.status}`,
      ps.error ? `ps_error=${ps.error}` : null,
      "resident_before:",
      ps.stdout || "(empty)",
      "",
    ]
      .filter(Boolean)
      .join("\n"),
  );
  if (ps.status !== 0) {
    return;
  }
  const modelsToStop = ollamaModelsToStopForTransition(
    currentPreset,
    nextPreset,
    ps.stdout,
  );
  appendText(
    logPath,
    `models_to_stop=${modelsToStop.length > 0 ? modelsToStop.join(",") : "(none)"}\n`,
  );
  for (const model of modelsToStop) {
    const stop = await runCommand("ollama", ["stop", model], { timeout: 30_000 });
    appendText(
      logPath,
      [
        `stop_model=${model}`,
        `stop_status=${stop.status}`,
        stop.error ? `stop_error=${stop.error}` : null,
        stop.stdout ? `stop_stdout=${compactText(stop.stdout, 400)}` : null,
        stop.stderr ? `stop_stderr=${compactText(stop.stderr, 400)}` : null,
        "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
  }
  const warmupUrl = ollamaGenerateUrlForPreset(nextPreset);
  const warmModels = ollamaManagedModelNamesForPreset(nextPreset);
  appendText(
    logPath,
    `warmup_url=${warmupUrl || "(invalid)"}\n` +
      `warm_models=${warmModels.length > 0 ? warmModels.join(",") : "(none)"}\n`,
  );
  if (!warmupUrl) {
    appendText(logPath, "warmup_skipped=invalid_url\n");
    return {
      ok: false,
      summary:
        `Ollama preset transition from '${currentPreset.id}' to '${nextPreset.id}' could not warm the target models because the runtime generate URL is invalid. See ${logPath}.`,
    };
  }
  for (const model of warmModels) {
    const warm = await runCommand(
      "curl",
      [
        "-fsS",
        warmupUrl,
        "-H",
        "Content-Type: application/json",
        "-d",
        ollamaWarmupPayloadForModel(model),
      ],
      { timeout: DEFAULT_PRESET_WARMUP_TIMEOUT_MS },
    );
    appendText(
      logPath,
      [
        `warm_model=${model}`,
        `warm_status=${warm.status}`,
        `warm_timed_out=${warm.timedOut === true}`,
        warm.error ? `warm_error=${warm.error}` : null,
        warm.stdout ? `warm_stdout=${compactText(warm.stdout, 400)}` : null,
        warm.stderr ? `warm_stderr=${compactText(warm.stderr, 400)}` : null,
        "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
  }
  const settleDeadline =
    Date.now() + DEFAULT_PRESET_TRANSITION_SETTLE_TIMEOUT_MS;
  let lastStatus = {
    ready: false,
    blockingModels: modelsToStop,
    missingWarmModels: warmModels,
    stoppingWarmModels: [],
  };
  let lastPs = null;
  let attempt = 0;
  while (Date.now() <= settleDeadline) {
    attempt += 1;
    const postWarmPs = await runCommand("ollama", ["ps"], { timeout: 15_000 });
    lastPs = postWarmPs;
    lastStatus =
      postWarmPs.status === 0
        ? ollamaTransitionStatusForPsOutput(nextPreset, postWarmPs.stdout)
        : {
            ready: false,
            blockingModels: [],
            missingWarmModels: warmModels,
            stoppingWarmModels: [],
          };
    appendText(
      logPath,
      [
        `settle_attempt=${attempt}`,
        `ps_after_warm_status=${postWarmPs.status}`,
        postWarmPs.error ? `ps_after_warm_error=${postWarmPs.error}` : null,
        "resident_after_warm:",
        postWarmPs.stdout || "(empty)",
        `blocking_models=${
          lastStatus.blockingModels.length > 0
            ? lastStatus.blockingModels.join(",")
            : "(none)"
        }`,
        `missing_warm_models=${
          lastStatus.missingWarmModels.length > 0
            ? lastStatus.missingWarmModels.join(",")
            : "(none)"
        }`,
        `stopping_warm_models=${
          lastStatus.stoppingWarmModels.length > 0
            ? lastStatus.stoppingWarmModels.join(",")
            : "(none)"
        }`,
        "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
    if (postWarmPs.status === 0 && lastStatus.ready) {
      appendText(logPath, "transition_ready=true\n");
      return { ok: true };
    }
    if (Date.now() < settleDeadline) {
      await sleepMs(DEFAULT_PRESET_TRANSITION_POLL_INTERVAL_MS);
    }
  }
  appendText(logPath, "transition_ready=false\n");
  const blockingSummaryParts = [];
  if (lastStatus.blockingModels.length > 0) {
    blockingSummaryParts.push(
      `non-target residents remained loaded (${lastStatus.blockingModels.join(", ")})`,
    );
  }
  if (lastStatus.missingWarmModels.length > 0) {
    blockingSummaryParts.push(
      `target warmup did not materialize (${lastStatus.missingWarmModels.join(", ")})`,
    );
  }
  if (lastStatus.stoppingWarmModels.length > 0) {
    blockingSummaryParts.push(
      `target models were still stopping (${lastStatus.stoppingWarmModels.join(", ")})`,
    );
  }
  return {
    ok: false,
    summary:
      `Ollama preset transition from '${currentPreset.id}' to '${nextPreset.id}' did not reach a clean resident state: ${
        blockingSummaryParts.join("; ") || "post-warm residency stayed unstable"
      }. See ${logPath}.`,
  };
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

async function availabilityForPreset(preset) {
  if (preset.runtimeKind === "local_http") {
    return await probeOllamaModel(preset);
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
  return (
    caseResult?.status &&
    !["blocked", "dependency_blocked", "not_run"].includes(caseResult.status)
  );
}

function benchmarkFullyCompleted(caseResult) {
  return TERMINAL_BENCHMARK_STATUSES.has(String(caseResult?.status || ""));
}

function presetFullyCompleted(presetSummary) {
  const cases = Array.isArray(presetSummary?.cases) ? presetSummary.cases : [];
  return cases.length > 0 && cases.every(benchmarkFullyCompleted);
}

function runAbortReasonForShippedDefaultTimeouts({
  options,
  selectedPresets,
  preset,
  caseResults,
}) {
  if (!preset?.shippedDefault || preset?.runtimeKind !== "local_http") {
    return null;
  }
  if (!Array.isArray(selectedPresets) || selectedPresets.length < 2) {
    return null;
  }
  if (Array.isArray(options?.benchmarks) || options?.skipComputerUse === true) {
    return null;
  }
  const attemptedCases = caseResults.filter(benchmarkAttempted);
  if (attemptedCases.length < DEFAULT_EARLY_ABORT_TIMEOUT_COUNT) {
    return null;
  }
  if (attemptedCases.some((entry) => entry.timedOut !== true)) {
    return null;
  }
  const diagnosticLabels = attemptedCases
    .map(timeoutDiagnosticLabel)
    .filter(Boolean)
    .slice(0, DEFAULT_EARLY_ABORT_TIMEOUT_COUNT);
  const diagnosticSuffix =
    diagnosticLabels.length > 0
      ? ` First timed-out slices: ${diagnosticLabels.join("; ")}.`
      : "";
  return `Shipped default preset '${preset.id}' timed out on the first ${attemptedCases.length} attempted benchmarks, so the local retained environment is unstable for a benchmark-honest comparison.${diagnosticSuffix}`;
}

async function runArtifactBenchmark(preset, benchmark, benchmarkRoot) {
  const outputRoot = path.join(benchmarkRoot, "artifact");
  const startedAt = Date.now();
  const timeoutMs = Number(benchmark.timeoutMs || DEFAULT_ARTIFACT_TIMEOUT_MS);
  const cliBinary = await ensureCliBinary(benchmarkRoot);
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
  const result = await runCommand(cliBinary.binaryPath, command, {
    env: {
      ...process.env,
      LOCAL_LLM_URL: preset.runtimeUrl,
      LOCAL_LLM_MODEL: preset.runtimeModel,
      AUTOPILOT_LOCAL_RUNTIME_URL: preset.runtimeUrl,
      AUTOPILOT_LOCAL_RUNTIME_MODEL: preset.runtimeModel,
      AUTOPILOT_ACCEPTANCE_RUNTIME_URL: preset.runtimeUrl,
      AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL: artifactAcceptanceModelForPreset(preset),
      OLLAMA_CONTEXT_LENGTH:
        process.env.OLLAMA_CONTEXT_LENGTH ||
        ollamaContextLengthForArtifactBenchmark(benchmark),
      IOI_STUDIO_PROOF_TRACE: "1",
    },
    timeout: timeoutMs,
  });
  const elapsedMs = Date.now() - startedAt;
  writeText(path.join(benchmarkRoot, "command.stdout.log"), result.stdout);
  writeText(path.join(benchmarkRoot, "command.stderr.log"), result.stderr);
  const diagnostics = artifactCommandDiagnostics(result);
  const diagnosticsPath = path.join(benchmarkRoot, "trace-diagnostics.json");
  writeJson(diagnosticsPath, diagnostics);
  writeJson(path.join(benchmarkRoot, "command.json"), {
    command: [cliBinary.binaryPath, ...command],
    exitStatus: result.status,
    elapsedMs,
    timedOut: result.timedOut === true,
    interrupted: result.interrupted === true,
    signal: result.signal || null,
    timeoutMs,
  });

  const generationPath = path.join(outputRoot, "generation.json");
  const generation = readJsonIfExists(generationPath);
  const validation = generation?.validation ?? null;
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
      ? benchmarkResultFromClassification(validation?.classification)
      : "red";
  return {
    benchmarkId: benchmark.benchmarkId,
    title: benchmark.title,
    workload: benchmark.workload,
    runner: benchmark.runner,
    status: benchmarkStatusFromCommandResult(
      result,
      result.status === 0 && generation,
    ),
    result: benchmarkResultForCommandResult(result, caseResult),
    elapsedMs,
    timedOut: result.timedOut === true,
    interrupted: result.interrupted === true,
    signal: result.signal || null,
    validationScore: validationScore(validation),
    verifierPass: manifestVerification?.status === "ready",
    repairLoopIterations,
    routeMatched:
      generation?.route?.artifact?.artifactClass === benchmark.expectedArtifactClass &&
      generation?.route?.artifact?.renderer === benchmark.expectedRenderer,
    summary:
      (result.interrupted
        ? interruptedBenchmarkSummary("Artifact benchmark", result, diagnostics)
        : null) ||
      (result.timedOut
        ? artifactTimeoutSummary(timeoutMs, diagnostics)
        : null) ||
      generation?.verifiedReply?.summary ||
      validation?.rationale ||
      compactFailureSummary(
        result,
        "Artifact benchmark did not produce retained evidence.",
      ) ||
      "Artifact benchmark did not produce retained evidence.",
    evidencePath: generationPath,
    evidenceRoot: outputRoot,
    stdoutPath: path.join(benchmarkRoot, "command.stdout.log"),
    stderrPath: path.join(benchmarkRoot, "command.stderr.log"),
    diagnosticsPath,
    lastStudioProofTrace: diagnostics.lastStudioProofTrace,
    lastProviderError: diagnostics.lastProviderError,
  };
}

async function runComputerUseBenchmark(preset, benchmark, benchmarkRoot) {
  const sourceDir = await ensureMiniwobSourceDir(benchmarkRoot);
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
  const result = await runCommand("cargo", command, {
    env: {
      ...process.env,
      OPENAI_API_URL: preset.runtimeUrl,
      OPENAI_API_KEY: "ollama",
      OPENAI_MODEL: preset.runtimeModel,
      COMPUTER_USE_SUITE_MODE: "agent",
      COMPUTER_USE_SUITE_TASK_SET: benchmark.taskSet || "baseline",
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
    interrupted: result.interrupted === true,
    signal: result.signal || null,
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
    status: benchmarkStatusFromCommandResult(
      result,
      result.status === 0 && summaryPayload,
    ),
    result: benchmarkResultForCommandResult(
      result,
      result.status === 0 && summaryPayload
        ? summary?.result_label || (rewardFloorMet ? "pass" : "red")
        : "red",
    ),
    elapsedMs,
    timedOut: result.timedOut === true,
    interrupted: result.interrupted === true,
    signal: result.signal || null,
    rewardFloorMet,
    stepCount,
    summary:
      (result.interrupted
        ? interruptedBenchmarkSummary("Computer-use benchmark", result)
        : null) ||
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

async function runCapabilitiesBenchmark(preset, benchmark, benchmarkRoot) {
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
  const result = await runCommand("cargo", command, {
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
    interrupted: result.interrupted === true,
    signal: result.signal || null,
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
    status: benchmarkStatusFromCommandResult(result, hasRetainedEvidence),
    result: benchmarkResultForCommandResult(
      result,
      hasRetainedEvidence ? capabilitiesBenchmarkResult(outcome) : "red",
    ),
    elapsedMs,
    timedOut: result.timedOut === true,
    interrupted: result.interrupted === true,
    signal: result.signal || null,
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
      (result.interrupted
        ? interruptedBenchmarkSummary("Capabilities benchmark", result)
        : null) ||
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

function dependencyBlockedBenchmarkResult(benchmark, benchmarkRoot, summary) {
  return {
    benchmarkId: benchmark.benchmarkId,
    title: benchmark.title,
    workload: benchmark.workload,
    runner: benchmark.runner,
    status: "dependency_blocked",
    result: "unknown",
    elapsedMs: null,
    summary,
    evidencePath: null,
    evidenceRoot: benchmarkRoot,
    stdoutPath: null,
    stderrPath: null,
  };
}

function summarizePreset(preset, availability, caseResults, presetRoot, runContext = {}) {
  const artifactCases = caseResults.filter((entry) => entry.benchmarkFamily === "artifacts");
  const attemptedArtifactCases = artifactCases.filter(benchmarkAttempted);
  const artifactValidationScores = attemptedArtifactCases.map((entry) => entry.validationScore);
  const artifactVerifierPasses = attemptedArtifactCases.filter(
    (entry) => entry.verifierPass === true,
  ).length;
  const artifactRouteMatches = attemptedArtifactCases.filter(
    (entry) => entry.routeMatched === true,
  ).length;
  const artifactRepairLoops = attemptedArtifactCases.map(
    (entry) => entry.repairLoopIterations,
  );

  const baseModelCases = caseResults.filter((entry) => entry.benchmarkFamily === "base_model");
  const attemptedBaseModelCases = baseModelCases.filter(benchmarkAttempted);
  const toolApiCases = caseResults.filter((entry) => entry.benchmarkFamily === "tool_api");
  const attemptedToolApiCases = toolApiCases.filter(benchmarkAttempted);
  const generalAgentCases = caseResults.filter(
    (entry) => entry.benchmarkFamily === "general_agent",
  );
  const attemptedGeneralAgentCases = generalAgentCases.filter(benchmarkAttempted);

  const computerUseCases = caseResults.filter(
    (entry) => entry.benchmarkFamily === "computer_use",
  );
  const attemptedComputerUseCases = computerUseCases.filter(benchmarkAttempted);
  const computerUseRewardPasses = attemptedComputerUseCases.filter(
    (entry) => entry.rewardFloorMet === true,
  ).length;
  const computerUseStepCounts = attemptedComputerUseCases.map((entry) => entry.stepCount);

  const codingCases = caseResults.filter((entry) => entry.benchmarkFamily === "coding");
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

  const researchCases = caseResults.filter((entry) => entry.benchmarkFamily === "research");
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

  const validComparisonCount = attemptedCases.filter(
    (entry) => entry.validForComparison === true,
  ).length;
  const conformancePassCount = attemptedCases.filter(
    (entry) => entry.conformanceReport?.status === "pass",
  ).length;
  const protectedSplitPassCount = attemptedCases.filter(
    (entry) =>
      entry.protectedEvidence?.splitVisibility !== "hidden" ||
      entry.protectedEvidence?.labelExposurePolicy !== "full_trace",
  ).length;

  function makeCategory({
    categoryId,
    attemptedCasesForCategory,
    metrics,
    unavailableReason,
  }) {
    const aggregate = aggregateCategoryStatus(caseResults, categoryId);
    return {
      available: attemptedCasesForCategory.length > 0,
      reason:
        attemptedCasesForCategory.length > 0
          ? ""
          : unavailableReason,
      decisionWeight: scorecardDecisionWeight(categoryId),
      comparisonStatus: aggregate.comparisonStatus,
      confidenceClass: aggregate.confidenceClass,
      coverageClass: aggregate.coverageClass,
      benchmarkPrograms: aggregate.benchmarkPrograms,
      metrics,
    };
  }

  return {
    presetId: preset.id,
    label: preset.label,
    role: preset.role,
    benchmarkTier: preset.benchmarkTier,
    deploymentProfile: deploymentProfileForPreset(preset),
    experimental: preset.experimental === true,
    shippedDefault: preset.shippedDefault === true,
    runtimeModel: preset.runtimeModel || preset.defaultRuntimeModel || null,
    artifactAcceptanceModel: artifactAcceptanceModelForPreset(preset),
    availabilityStatus: availability.availabilityStatus,
    availabilitySummary: availability.availabilitySummary,
    modelFingerprint: runtimeModelFingerprint(preset, availability),
    roleAssignments: inferRoleAssignmentsForPreset({
      ...preset,
      artifactAcceptanceModel: artifactAcceptanceModelForPreset(preset),
    }),
    comparisonContext: {
      comparisonIntent: comparisonIntentBetweenPresets(
        runContext.baselinePreset ?? null,
        preset,
        runContext.comparisonIntent ?? null,
      ),
      executionScope: runContext.executionScope ?? "fleet_shared",
      baselinePresetId: runContext.baselinePreset?.id ?? null,
      manifestPath: path.join(presetRoot, "run-manifest.json"),
    },
    conformanceSummary: {
      status:
        attemptedCases.length === 0
          ? "warn"
          : conformancePassCount === attemptedCases.length
            ? "pass"
            : validComparisonCount === 0
              ? "fail"
              : "warn",
      activePolicyIds: DEFAULT_CONFORMANCE_POLICY_IDS,
      comparisonValidityRate: rate(validComparisonCount, attemptedCases.length),
      conformancePassRate: rate(conformancePassCount, attemptedCases.length),
      protectedSplitPassRate: rate(protectedSplitPassCount, attemptedCases.length),
      rollbackReadinessRate: 1,
    },
    caseCount: caseResults.length,
    availableWorkloadCount: [
      attemptedBaseModelCases.length > 0,
      attemptedArtifactCases.length > 0,
      attemptedCodingCases.length > 0,
      attemptedResearchCases.length > 0,
      attemptedComputerUseCases.length > 0,
      attemptedToolApiCases.length > 0,
      attemptedGeneralAgentCases.length > 0,
    ].filter(Boolean).length,
    topFindings: topFindings.slice(0, 6),
    scorecards: {
      baseModelQuality: makeCategory({
        categoryId: "baseModelQuality",
        attemptedCasesForCategory: attemptedBaseModelCases,
        unavailableReason:
          "No public base-model screening lane has retained evidence for this preset yet.",
        metrics: {
          benchmarkCount: attemptedBaseModelCases.length,
          normalizedScore: mean(attemptedBaseModelCases.map((entry) => entry.normalizedScore)),
          passRate: rate(
            attemptedBaseModelCases.filter((entry) => entry.result === "pass").length,
            attemptedBaseModelCases.length,
          ),
        },
      }),
      artifactQuality: makeCategory({
        categoryId: "artifactQuality",
        attemptedCasesForCategory: attemptedArtifactCases,
        unavailableReason:
          "No retained artifact benchmarks were executed for this preset in the current pass.",
        metrics: {
          benchmarkCount: attemptedArtifactCases.length,
          passRate:
            attemptedArtifactCases.length > 0
              ? round(
                  attemptedArtifactCases.filter((entry) => entry.result === "pass").length /
                    attemptedArtifactCases.length,
                )
              : null,
          averageValidationScore: mean(artifactValidationScores),
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
      }),
      codingCompletion: makeCategory({
        categoryId: "codingCompletion",
        attemptedCasesForCategory: attemptedCodingCases,
        unavailableReason:
          "No retained coding benchmark was executed for this preset in the current pass.",
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
      }),
      researchQuality: makeCategory({
        categoryId: "researchQuality",
        attemptedCasesForCategory: attemptedResearchCases,
        unavailableReason:
          "No retained research benchmark was executed for this preset in the current pass.",
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
      }),
      computerUseCompletion: makeCategory({
        categoryId: "computerUseCompletion",
        attemptedCasesForCategory: attemptedComputerUseCases,
        unavailableReason:
          "No retained computer-use benchmark was executed for this preset in the current pass.",
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
      }),
      toolApiReliability: makeCategory({
        categoryId: "toolApiReliability",
        attemptedCasesForCategory: attemptedToolApiCases,
        unavailableReason:
          "No public or retained Tool/API benchmark evidence is available for this preset yet.",
        metrics: {
          benchmarkCount: attemptedToolApiCases.length,
          normalizedScore: mean(attemptedToolApiCases.map((entry) => entry.normalizedScore)),
          taskPassRate: rate(
            attemptedToolApiCases.filter((entry) => entry.result === "pass").length,
            attemptedToolApiCases.length,
          ),
          policyPassRate: rate(
            attemptedToolApiCases.filter(
              (entry) => entry.conformanceReport?.status === "pass",
            ).length,
            attemptedToolApiCases.length,
          ),
        },
      }),
      generalAgentQuality: makeCategory({
        categoryId: "generalAgentQuality",
        attemptedCasesForCategory: attemptedGeneralAgentCases,
        unavailableReason:
          "No general-agent screening lane has retained evidence for this preset yet.",
        metrics: {
          benchmarkCount: attemptedGeneralAgentCases.length,
          normalizedScore: mean(attemptedGeneralAgentCases.map((entry) => entry.normalizedScore)),
          taskPassRate: rate(
            attemptedGeneralAgentCases.filter((entry) => entry.result === "pass").length,
            attemptedGeneralAgentCases.length,
          ),
          reasoningPassRate: rate(
            attemptedGeneralAgentCases.filter(
              (entry) => entry.conformanceReport?.status === "pass",
            ).length,
            attemptedGeneralAgentCases.length,
          ),
        },
      }),
      latencyAndResourcePressure: makeCategory({
        categoryId: "latencyAndResourcePressure",
        attemptedCasesForCategory: attemptedCases,
        unavailableReason:
          "No executed benchmarks were retained for this preset in the current pass.",
        metrics: {
          benchmarkCount: attemptedCases.length,
          meanWallClockMs: round(mean(wallClockValues)),
          p95WallClockMs: round(percentile(wallClockValues, 0.95)),
          residentModelBytes: availability.modelSizeBytes,
          processorKind: availability.processorKind,
        },
      }),
      operationalDiscipline: makeCategory({
        categoryId: "operationalDiscipline",
        attemptedCasesForCategory: attemptedCases,
        unavailableReason:
          "No operational benchmark outputs were retained for this preset in the current pass.",
        metrics: {
          benchmarkCount: attemptedCases.length,
          conformancePassRate: rate(conformancePassCount, attemptedCases.length),
          comparisonValidityRate: rate(validComparisonCount, attemptedCases.length),
          protectedSplitPassRate: rate(protectedSplitPassCount, attemptedCases.length),
          rollbackReadinessRate: 1,
        },
      }),
    },
    cases: caseResults,
    summaryPath: path.join(presetRoot, "summary.json"),
    manifestPath: path.join(presetRoot, "run-manifest.json"),
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
  return REQUIRED_DECISION_CATEGORY_IDS.every(
    (categoryId) => preset.scorecards[categoryId]?.available === true,
  );
}

function loadPresetSummariesForHistoricalRun(runRoot) {
  if (!runRoot || !fs.existsSync(runRoot)) {
    return [];
  }
  return fs
    .readdirSync(runRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && !entry.name.startsWith("_"))
    .map((entry) =>
      readJsonIfExists(path.join(runRoot, entry.name, "summary.json")),
    )
    .filter(
      (summary) =>
        summary
        && typeof summary === "object"
        && typeof summary.presetId === "string"
        && summary.scorecards
        && typeof summary.scorecards === "object",
    );
}

function loadHistoricalPromotionRuns(runsRoot, currentRunId) {
  if (!runsRoot || !fs.existsSync(runsRoot)) {
    return [];
  }
  return fs
    .readdirSync(runsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name !== currentRunId)
    .map((entry) => ({
      runId: entry.name,
      presets: loadPresetSummariesForHistoricalRun(path.join(runsRoot, entry.name)),
    }))
    .filter((run) => run.presets.length > 0)
    .sort((left, right) => left.runId.localeCompare(right.runId));
}

function comparePresetCategory(leftPreset, rightPreset, categoryId) {
  const leftMetrics = leftPreset.scorecards[categoryId]?.metrics ?? {};
  const rightMetrics = rightPreset.scorecards[categoryId]?.metrics ?? {};
  switch (categoryId) {
    case "baseModelQuality":
      return compareMetricSeries([
        [leftMetrics.normalizedScore, rightMetrics.normalizedScore, "higher"],
        [leftMetrics.passRate, rightMetrics.passRate, "higher"],
      ]);
    case "artifactQuality":
      return compareMetricSeries([
        [leftMetrics.passRate, rightMetrics.passRate, "higher"],
        [leftMetrics.averageValidationScore, rightMetrics.averageValidationScore, "higher"],
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
    case "toolApiReliability":
      return compareMetricSeries([
        [leftMetrics.normalizedScore, rightMetrics.normalizedScore, "higher"],
        [leftMetrics.taskPassRate, rightMetrics.taskPassRate, "higher"],
        [leftMetrics.policyPassRate, rightMetrics.policyPassRate, "higher"],
      ]);
    case "generalAgentQuality":
      return compareMetricSeries([
        [leftMetrics.normalizedScore, rightMetrics.normalizedScore, "higher"],
        [leftMetrics.taskPassRate, rightMetrics.taskPassRate, "higher"],
        [leftMetrics.reasoningPassRate, rightMetrics.reasoningPassRate, "higher"],
      ]);
    case "latencyAndResourcePressure":
      return compareMetricSeries([
        [leftMetrics.meanWallClockMs, rightMetrics.meanWallClockMs, "lower"],
        [leftMetrics.p95WallClockMs, rightMetrics.p95WallClockMs, "lower"],
      ]);
    case "operationalDiscipline":
      return compareMetricSeries([
        [
          leftMetrics.conformancePassRate,
          rightMetrics.conformancePassRate,
          "higher",
        ],
        [
          leftMetrics.comparisonValidityRate,
          rightMetrics.comparisonValidityRate,
          "higher",
        ],
        [
          leftMetrics.protectedSplitPassRate,
          rightMetrics.protectedSplitPassRate,
          "higher",
        ],
      ]);
    default:
      return 0;
  }
}

function compareChallengerAgainstDefault(leftPreset, rightPreset, defaultPreset) {
  const leftWins = REQUIRED_DECISION_CATEGORY_IDS.filter(
    (categoryId) => comparePresetCategory(leftPreset, defaultPreset, categoryId) > 0,
  ).length;
  const rightWins = REQUIRED_DECISION_CATEGORY_IDS.filter(
    (categoryId) => comparePresetCategory(rightPreset, defaultPreset, categoryId) > 0,
  ).length;
  if (leftWins !== rightWins) {
    return leftWins - rightWins;
  }

  const leftTies = REQUIRED_DECISION_CATEGORY_IDS.filter(
    (categoryId) => comparePresetCategory(leftPreset, defaultPreset, categoryId) >= 0,
  ).length;
  const rightTies = REQUIRED_DECISION_CATEGORY_IDS.filter(
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

function targetFamilyForPreset(preset) {
  const coveredRequiredCategories = SCORECARD_SCHEMA.categories.filter(
    (category) =>
      category.requiredForPromotion && preset.scorecards?.[category.id]?.available === true,
  );
  if (coveredRequiredCategories.length === 0) {
    return "No retained required-family coverage yet";
  }
  return coveredRequiredCategories
    .map((category) => CATEGORY_SHORT_LABELS[category.id] ?? category.label)
    .join(" / ");
}

function bestPresetIdsByRequiredCategory(presets) {
  const bestByCategory = new Map();
  for (const categoryId of REQUIRED_DECISION_CATEGORY_IDS) {
    const bestPreset =
      [...presets].sort((left, right) => {
        const comparison = comparePresetCategory(right, left, categoryId);
        if (comparison !== 0) {
          return comparison;
        }
        return left.label.localeCompare(right.label);
      })[0] ?? null;
    bestByCategory.set(categoryId, bestPreset?.presetId ?? null);
  }
  return bestByCategory;
}

function candidateStatusForPreset({
  baselinePresetId,
  matrixLeaderPresetId,
  preset,
  requiredReadyCount,
  requiredCategoryCount,
}) {
  if (preset.shippedDefault) {
    return "retained_default";
  }
  if (
    String(preset.deploymentProfile || "").startsWith("blind_cloud") &&
    preset.presetId === matrixLeaderPresetId
  ) {
    return "shadow_winner";
  }
  if (preset.presetId === matrixLeaderPresetId) {
    return "leader";
  }
  if (
    preset.experimental === true &&
    requiredCategoryCount > 0 &&
    requiredReadyCount === requiredCategoryCount &&
    preset.presetId !== baselinePresetId
  ) {
    return "promotable";
  }
  if (preset.experimental === true) {
    return "candidate";
  }
  return "retained";
}

function candidateSummaryForStatus(status) {
  switch (status) {
    case "retained_default":
      return "Current default anchor kept in place while stronger candidates continue to be validated.";
    case "shadow_winner":
      return "Highest retained score overall, but intentionally held in shadow because blind-cloud posture cannot silently replace local defaults.";
    case "promotable":
      return "Strongest retained local candidate on richer hardware tiers with honest required-family coverage.";
    case "candidate":
      return "Experimental retained candidate that is visible for comparison but not yet promoted.";
    case "leader":
      return "Current retained leader on the visible matrix surface.";
    default:
      return "Retained preset snapshot carried forward for comparison.";
  }
}

function mutationIntentForProfile(deploymentProfile, preset) {
  if (preset.shippedDefault) {
    return "Stabilize low-footprint local behavior and hold the baseline until a cleaner successor exists.";
  }
  if (deploymentProfile === "local_workstation") {
    return "Raise cross-vertical completion on stronger local hardware without introducing fallback hacks.";
  }
  if (String(deploymentProfile || "").startsWith("blind_cloud")) {
    return "Use higher-tier remote model conscription while keeping trust posture and promotion boundaries explicit.";
  }
  if (deploymentProfile === "hybrid_privacy_preserving") {
    return "Keep the local-first privacy posture while validating bounded remote assists under explicit egress rules.";
  }
  return "Preserve baseline behavior while improving coverage and trustworthiness.";
}

function changedContractsForProfile(deploymentProfile) {
  if (String(deploymentProfile || "").startsWith("blind_cloud")) {
    return ["role-model assignment", "blind-cloud routing", "validation gates"];
  }
  if (deploymentProfile === "local_workstation") {
    return ["role-model assignment", "verification policy", "recovery loop"];
  }
  if (deploymentProfile === "hybrid_privacy_preserving") {
    return ["role-model assignment", "egress guard", "fallback policy"];
  }
  return ["default preservation", "coverage guard", "latency/resource fit"];
}

function candidateLedgerForRun(presets, decision) {
  const baselinePreset =
    presets.find((preset) => preset.shippedDefault) ?? presets[0] ?? null;
  const matrixLeaderPresetId =
    decision?.leaderPresetId ?? decision?.artifactLeaderPresetId ?? null;
  const bestPresetIds = bestPresetIdsByRequiredCategory(presets);

  return presets.map((preset) => {
    const requiredReadyCount = REQUIRED_DECISION_CATEGORY_IDS.filter(
      (categoryId) => preset.scorecards?.[categoryId]?.available === true,
    ).length;
    const bestRequiredCount = REQUIRED_DECISION_CATEGORY_IDS.filter(
      (categoryId) => bestPresetIds.get(categoryId) === preset.presetId,
    ).length;
    const requiredCategoryCount = REQUIRED_DECISION_CATEGORY_IDS.length;
    const status = candidateStatusForPreset({
      baselinePresetId: baselinePreset?.presetId ?? null,
      matrixLeaderPresetId,
      preset,
      requiredReadyCount,
      requiredCategoryCount,
    });

    return {
      candidateId: `candidate:${preset.presetId}`,
      candidateKind: "model",
      parentCandidateId:
        preset.shippedDefault || !baselinePreset || baselinePreset.presetId === preset.presetId
          ? null
          : `candidate:${baselinePreset.presetId}`,
      presetId: preset.presetId,
      deploymentProfile: preset.deploymentProfile,
      comparisonIntent: preset.comparisonContext?.comparisonIntent ?? "model_change",
      executionScope: preset.comparisonContext?.executionScope ?? "fleet_shared",
      status,
      summary: candidateSummaryForStatus(status),
      mutationIntent: mutationIntentForProfile(preset.deploymentProfile, preset),
      targetFamily: targetFamilyForPreset(preset),
      changedContracts: changedContractsForProfile(preset.deploymentProfile),
      roleAssignmentDelta: Array.isArray(preset.roleAssignments)
        ? preset.roleAssignments.map((assignment) => assignment.roleId)
        : [],
      validationSummary: {
        requiredReadyCount,
        requiredCategoryCount,
        bestRequiredCount,
        coverageStatus:
          requiredCategoryCount === 0
            ? "sparse"
            : requiredReadyCount === requiredCategoryCount
            ? "clear"
              : `${requiredCategoryCount - requiredReadyCount} blocked`,
      },
      evaluationLanes: {
        proxy: "not_run",
        validation: requiredReadyCount > 0 ? "retained" : "missing",
        challenge: "not_run",
        holdout: "protected_not_run",
      },
      conformanceStatus: preset.conformanceSummary?.status ?? "warn",
      paretoClass:
        status === "promotable" || status === "shadow_winner" || status === "leader"
          ? "pareto_improving"
          : status === "candidate"
            ? "targeted_tradeoff"
            : "retained",
      controlRunIds: [],
      rollbackTarget:
        baselinePreset?.presetId && baselinePreset.presetId !== preset.presetId
          ? `candidate:${baselinePreset.presetId}`
          : null,
      regressions:
        preset.topFindings.length > 0
          ? preset.topFindings.slice(0, 3)
          : Array.isArray(decision?.missingCoverage) && decision.missingCoverage.length > 0
            ? decision.missingCoverage.slice(0, 3)
            : [],
      evidenceLinks: [
        { label: "summary", path: preset.summaryPath },
        { label: "retained_run", path: preset.runRootPath },
      ],
    };
  });
}

function promotionContextForRun(presets) {
  const defaultPreset = presets.find((preset) => preset.shippedDefault);
  const artifactLeader = [...presets]
    .filter((preset) => preset.scorecards.artifactQuality.available)
    .sort((left, right) => {
      const leftScore =
        left.scorecards.artifactQuality.metrics.averageValidationScore ?? -Infinity;
      const rightScore =
        right.scorecards.artifactQuality.metrics.averageValidationScore ?? -Infinity;
      if (leftScore !== rightScore) {
        return rightScore - leftScore;
      }
      return left.label.localeCompare(right.label);
    })[0];

  const missingCoverage = REQUIRED_DECISION_CATEGORY_IDS.filter(
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
            const comparisons = REQUIRED_DECISION_CATEGORY_IDS.map((categoryId) =>
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

  return {
    defaultPreset,
    artifactLeader,
    missingCoverage,
    leadChallenger,
  };
}

function deploymentDecisionsForRun(presets) {
  const grouped = new Map(DEPLOYMENT_PROFILES.map((profile) => [profile.id, []]));
  for (const preset of presets) {
    const deploymentProfile = normalizeDeploymentProfileId(preset?.deploymentProfile);
    if (deploymentProfile && grouped.has(deploymentProfile)) {
      grouped.get(deploymentProfile).push(preset);
    }
  }

  return DEPLOYMENT_PROFILES.map((profile) => {
    const lanePresets = grouped.get(profile.id) ?? [];
    const context = lanePresets.length > 0 ? promotionContextForRun(lanePresets) : null;
    const defaultPreset = context?.defaultPreset ?? null;
    const leaderPreset =
      context?.leadChallenger ??
      context?.defaultPreset ??
      context?.artifactLeader ??
      lanePresets[0] ??
      null;
    const state =
      lanePresets.length === 0
        ? "empty"
        : leaderPreset?.shippedDefault
          ? "default"
          : profile.id.startsWith("blind_cloud")
            ? "shadow_only"
            : leaderPreset?.experimental
              ? "candidate"
              : "retained";
    const coverageGaps = context?.missingCoverage ?? REQUIRED_DECISION_CATEGORY_IDS;
    return {
      deploymentProfile: profile.id,
      label: profile.label,
      trustPosture: profile.trustPosture,
      state,
      defaultPresetId: defaultPreset?.presetId ?? null,
      leaderPresetId: leaderPreset?.presetId ?? null,
      challengerPresetId:
        leaderPreset && defaultPreset && leaderPreset.presetId !== defaultPreset.presetId
          ? leaderPreset.presetId
          : null,
      coverageGaps,
      requiredCategoryIds: REQUIRED_DECISION_CATEGORY_IDS,
      summary:
        lanePresets.length === 0
          ? "No retained preset has been benchmarked for this deployment profile yet."
          : profile.id.startsWith("blind_cloud") &&
              leaderPreset &&
              leaderPreset.presetId !== defaultPreset?.presetId
            ? "Blind-cloud leaders remain shadow-scoped and cannot silently replace local defaults."
            : leaderPreset?.shippedDefault
              ? "Current retained default for this deployment profile."
              : coverageGaps.length > 0
                ? `Coverage gaps still block a clean promotion path for ${coverageGaps.join(", ")}.`
                : "Current leading candidate for this deployment profile.",
    };
  });
}

function decisionForRun(
  presets,
  {
    previousRuns = [],
    currentRunId = null,
    requiredRetainedPromotionWins = REQUIRED_RETAINED_PROMOTION_WINS,
  } = {},
) {
  const { defaultPreset, artifactLeader, missingCoverage, leadChallenger } =
    promotionContextForRun(presets);

  const retainedPromotionRunIds = leadChallenger
    ? [
        ...previousRuns
          .filter(
            (run) =>
              promotionContextForRun(run.presets).leadChallenger?.presetId
                === leadChallenger.presetId,
          )
          .map((run) => run.runId),
        ...(currentRunId ? [currentRunId] : []),
      ]
    : [];
  const retainedPromotionWinCount = retainedPromotionRunIds.length;
  const promotionReady =
    leadChallenger != null
    && retainedPromotionWinCount >= requiredRetainedPromotionWins;

  if (!artifactLeader) {
    return {
      outcome: "keep_default",
      summary:
        "No challenger retained a completed benchmark slice, so the shipped default remains unchanged.",
      leaderPresetId: defaultPreset?.presetId ?? null,
      artifactLeaderPresetId: null,
      missingCoverage,
      requiredRetainedPromotionWins,
      retainedPromotionWinCount,
      retainedPromotionRunIds,
      promotionReady,
    };
  }

  if (missingCoverage.length > 0) {
    return {
      outcome: "keep_default",
      summary: `${artifactLeader.label} leads the retained artifact slice, but the matrix still lacks required workload coverage for ${missingCoverage.join(", ")}. Keep the shipped default unchanged.`,
      leaderPresetId: defaultPreset?.presetId ?? null,
      artifactLeaderPresetId: artifactLeader.presetId,
      missingCoverage,
      requiredRetainedPromotionWins,
      retainedPromotionWinCount,
      retainedPromotionRunIds,
      promotionReady,
    };
  }

  if (promotionReady) {
    return {
      outcome: "promote_challenger",
      summary: `${leadChallenger.label} has ${retainedPromotionWinCount} retained full-coverage wins (${retainedPromotionRunIds.join(", ")}), clearing the ${requiredRetainedPromotionWins}-run promotion gate over the shipped default.`,
      leaderPresetId: leadChallenger.presetId,
      artifactLeaderPresetId: artifactLeader.presetId,
      missingCoverage,
      requiredRetainedPromotionWins,
      retainedPromotionWinCount,
      retainedPromotionRunIds,
      promotionReady,
    };
  }

  if (leadChallenger) {
    return {
      outcome: "keep_default",
      summary: `${leadChallenger.label} leads the fully covered scorecard on this comparison pass and now has ${retainedPromotionWinCount}/${requiredRetainedPromotionWins} retained wins toward promotion, so the shipped default stays in place for now.`,
      leaderPresetId: leadChallenger.presetId,
      artifactLeaderPresetId: artifactLeader.presetId,
      missingCoverage,
      requiredRetainedPromotionWins,
      retainedPromotionWinCount,
      retainedPromotionRunIds,
      promotionReady,
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
    requiredRetainedPromotionWins,
    retainedPromotionWinCount,
    retainedPromotionRunIds,
    promotionReady,
  };
}

function appendBlockedBenchmarks(
  caseResults,
  selectedBenchmarks,
  presetRoot,
  summary,
  preset,
  availability,
  runContext,
) {
  const retainedIds = new Set(
    caseResults
      .map((entry) => entry?.benchmarkId)
      .filter((value) => typeof value === "string" && value.trim()),
  );
  for (const benchmark of selectedBenchmarks) {
    if (retainedIds.has(benchmark.benchmarkId)) {
      continue;
    }
    caseResults.push(
      normalizeCaseResult(benchmark, preset, availability, {
      benchmarkId: benchmark.benchmarkId,
      title: benchmark.title,
      workload: benchmark.workload,
      runner: benchmark.runner,
      status: "blocked",
      result: "unknown",
      elapsedMs: null,
      summary,
      evidencePath: null,
      evidenceRoot: path.join(presetRoot, benchmark.benchmarkId),
      stdoutPath: null,
      stderrPath: null,
      }, runContext),
    );
  }
}

function buildRunManifest({
  paths,
  runId,
  runRoot,
  selectedPresets,
  selectedBenchmarks,
  options,
}) {
  const comparisonIntent = inferredRunComparisonIntent(
    selectedPresets,
    options?.comparisonIntent ?? null,
  );
  return {
    version: RUNNER_SCHEMA_VERSION,
    runnerVersion: RUNNER_VERSION,
    runId,
    runRoot,
    generatedAt: new Date().toISOString(),
    comparisonIntent,
    executionScope: executionScopeIsValid(options?.executionScope)
      ? options.executionScope
      : "fleet_shared",
    repoCommitSha: gitHeadSha(),
    dirtyWorktree: gitDirtyWorktree(),
    benchmarkCatalogPath: paths.benchmarkCatalogPath,
    benchmarkCatalogHash: sha256Text(
      fs.existsSync(paths.benchmarkCatalogPath)
        ? fs.readFileSync(paths.benchmarkCatalogPath, "utf8")
        : "",
    ),
    presetCatalogPath: paths.presetCatalogPath,
    presetCatalogHash: sha256Text(
      fs.existsSync(paths.presetCatalogPath)
        ? fs.readFileSync(paths.presetCatalogPath, "utf8")
        : "",
    ),
    selectedPresetIds: selectedPresets.map((preset) => preset.id),
    selectedBenchmarkIds: selectedBenchmarks.map((benchmark) => benchmark.benchmarkId),
    conformancePolicyIds: DEFAULT_CONFORMANCE_POLICY_IDS,
    repeatCount: Math.max(
      1,
      ...selectedBenchmarks.map((benchmark) => Number(benchmark.repeatCount ?? 1)),
    ),
    deploymentProfiles: [...new Set(
      selectedPresets.map((preset) => deploymentProfileForPreset(preset)),
    )],
    modelRegistryPath: paths.modelRegistryPath,
    deploymentProfilesPath: paths.deploymentProfilesPath,
    latestCandidateLedgerPath: paths.latestCandidateLedgerPath,
    latestRunManifestPath: paths.latestRunManifestPath,
  };
}

function buildPresetRunManifest(runManifest, preset, availability, caseResults) {
  return {
    ...runManifest,
    presetId: preset.id,
    presetLabel: preset.label,
    deploymentProfile: deploymentProfileForPreset(preset),
    modelFingerprint: runtimeModelFingerprint(preset, availability),
    roleAssignments: inferRoleAssignmentsForPreset({
      ...preset,
      artifactAcceptanceModel: artifactAcceptanceModelForPreset(preset),
    }),
    attemptedBenchmarkIds: caseResults
      .filter(benchmarkAttempted)
      .map((entry) => entry.benchmarkId),
    caseResultHash: stableJsonHash(caseResults),
  };
}

function buildComparisonExportRows(summary) {
  const rows = [];
  for (const preset of summary?.presets ?? []) {
    for (const caseResult of preset?.cases ?? []) {
      rows.push({
        packId: caseResult.packId ?? null,
        packVersion: caseResult.packVersion ?? null,
        deploymentProfile: preset.deploymentProfile ?? null,
        trustPosture: DEPLOYMENT_PROFILES.find(
          (profile) => profile.id === preset.deploymentProfile,
        )?.trustPosture ?? null,
        comparisonIntent:
          caseResult.comparisonIntent ??
          preset?.comparisonContext?.comparisonIntent ??
          summary?.runManifest?.comparisonIntent ??
          null,
        presetOrTargetId: preset.presetId,
        roleScope: preset.role,
        modelId: preset.runtimeModel,
        servingAdapter: preset.modelFingerprint?.runtimeKind ?? null,
        quantization: null,
        hardwareProfile: preset.deploymentProfile,
        benchmarkFamily: caseResult.benchmarkFamily ?? null,
        benchmarkId: caseResult.benchmarkId ?? null,
        splitClass: caseResult.splitClass ?? null,
        score: caseResult.normalizedScore ?? null,
        normalizedScore: caseResult.normalizedScore ?? null,
        repeatCount: summary?.runManifest?.repeatCount ?? 1,
        confidenceClass:
          preset.scorecards?.[
            SCORECARD_CATEGORY_ID_BY_FAMILY[caseResult.benchmarkFamily] ?? ""
          ]?.confidenceClass ?? null,
        coverageClass:
          preset.scorecards?.[
            SCORECARD_CATEGORY_ID_BY_FAMILY[caseResult.benchmarkFamily] ?? ""
          ]?.coverageClass ?? null,
        runId: summary?.runId ?? null,
        manifestPath: preset.manifestPath ?? summary?.runManifestPath ?? null,
      });
    }
  }
  return rows;
}

function csvEscape(value) {
  if (value == null) {
    return "";
  }
  const text = String(value);
  return /[,"\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function persistComparisonArtifacts(paths, latestSummary) {
  const candidateLedger = latestSummary?.candidateLedger ?? [];
  writeJson(paths.latestCandidateLedgerPath, candidateLedger);
  if (latestSummary?.runManifest) {
    writeJson(paths.latestRunManifestPath, latestSummary.runManifest);
  }
  const exportRows = buildComparisonExportRows(latestSummary);
  writeJson(paths.latestComparisonExportJsonPath, exportRows);
  const csvHeaders = [
    "packId",
    "packVersion",
    "deploymentProfile",
    "trustPosture",
    "comparisonIntent",
    "presetOrTargetId",
    "roleScope",
    "modelId",
    "servingAdapter",
    "quantization",
    "hardwareProfile",
    "benchmarkFamily",
    "benchmarkId",
    "splitClass",
    "score",
    "normalizedScore",
    "repeatCount",
    "confidenceClass",
    "coverageClass",
    "runId",
    "manifestPath",
  ];
  const csvLines = [
    csvHeaders.join(","),
    ...exportRows.map((row) =>
      csvHeaders.map((header) => csvEscape(row[header])).join(","),
    ),
  ];
  writeText(paths.latestComparisonExportCsvPath, `${csvLines.join("\n")}\n`);
  return exportRows;
}

function latestSummaryForRun({
  paths,
  runId,
  runRoot,
  previousRuns,
  presetSummaries,
  runAbortReason,
  plannedPresetCount,
  runManifest,
}) {
  const baseDecision = decisionForRun(presetSummaries, {
    previousRuns,
    currentRunId: runId,
  });
  const deploymentDecisions = deploymentDecisionsForRun(presetSummaries);
  const decision = runAbortReason
    ? {
        ...baseDecision,
        summary: `${baseDecision.summary} Run blocked: ${runAbortReason}`,
      }
    : baseDecision;
  const summarizedPresetCount = presetSummaries.length;
  const completedPresetCount = presetSummaries.filter(presetFullyCompleted).length;
  return {
    version: RUNNER_SCHEMA_VERSION,
    status: runAbortReason
      ? "blocked"
      : summarizedPresetCount < plannedPresetCount
        ? "running"
        : "ready",
    runId,
    generatedAt: new Date().toISOString(),
    presetCatalogPath: paths.presetCatalogPath,
    benchmarkCatalogPath: paths.benchmarkCatalogPath,
    summaryPath: paths.latestSummaryPath,
    runRootPath: runRoot,
    plannedPresetCount,
    summarizedPresetCount,
    completedPresetCount,
    fullyCompletedPresetCount: completedPresetCount,
    executedPresetCount: presetSummaries.filter((preset) =>
      preset.cases.some(benchmarkAttempted),
    ).length,
    comparedPresetCount: summarizedPresetCount,
    preservedDefault: decision.outcome !== "promote_challenger",
    scorecardSchema: SCORECARD_SCHEMA,
    decision,
    deploymentDecisions,
    runAbortReason,
    runManifest,
    runManifestPath: paths.latestRunManifestPath,
    candidateLedgerPath: paths.latestCandidateLedgerPath,
    comparisonExportJsonPath: paths.latestComparisonExportJsonPath,
    comparisonExportCsvPath: paths.latestComparisonExportCsvPath,
    modelRegistryPath: paths.modelRegistryPath,
    deploymentProfilesPath: paths.deploymentProfilesPath,
    presets: presetSummaries,
    candidateLedger: candidateLedgerForRun(presetSummaries, decision),
  };
}

function persistLatestSummary({
  paths,
  runId,
  runRoot,
  previousRuns,
  presetSummaries,
  runAbortReason,
  plannedPresetCount,
  runManifest,
}) {
  const latestSummary = latestSummaryForRun({
    paths,
    runId,
    runRoot,
    previousRuns,
    presetSummaries,
    runAbortReason,
    plannedPresetCount,
    runManifest,
  });
  writeJson(paths.latestSummaryPath, latestSummary);
  writeText(
    paths.latestSummaryMarkdownPath,
    renderAgentModelMatrixMarkdown(latestSummary),
  );
  persistComparisonArtifacts(paths, latestSummary);
  return latestSummary;
}

async function main() {
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
  const selectedBenchmarks = benchmarkCatalog.benchmarks
    .map((benchmark) =>
      normalizeBenchmarkDefinition(benchmark, benchmarkCatalog.version ?? 1),
    )
    .filter((benchmark) => {
      if (options.benchmarks && !options.benchmarks.includes(benchmark.benchmarkId)) {
        return false;
      }
      if (!options.benchmarks && benchmark.enabledByDefault === false) {
        return false;
      }
      if (options.skipComputerUse && benchmark.workload === "computer_use") {
        return false;
      }
      if (benchmark.lifecycleState === "retired") {
        return false;
      }
      return true;
    });
  const runManifest = buildRunManifest({
    paths,
    runId,
    runRoot,
    selectedPresets,
    selectedBenchmarks,
    options,
  });
  const baselinePreset = selectedPresets.find((preset) => preset.shippedDefault) ??
    selectedPresets[0] ??
    null;
  const runContext = {
    comparisonIntent: runManifest.comparisonIntent,
    executionScope: runManifest.executionScope,
    baselinePreset,
  };

  const presetSummaries = [];
  const previousRuns = loadHistoricalPromotionRuns(paths.runsRoot, runId);
  const presetTransitionFailures = new Map();
  let runAbortReason = null;
  let fatalError = null;
  let latestSummary = null;
  try {
    for (let presetIndex = 0; presetIndex < selectedPresets.length; presetIndex += 1) {
      if (interruptSignalRequested() && !runAbortReason) {
        runAbortReason = interruptAbortReason();
      }
      if (runAbortReason) {
        break;
      }

      const preset = selectedPresets[presetIndex];
      const presetRoot = path.join(runRoot, preset.id);
      ensureDir(presetRoot);
      const transitionFailure = presetTransitionFailures.get(preset.id) || null;
      const availability = transitionFailure
        ? {
            availabilityStatus: "blocked",
            availabilitySummary: transitionFailure.summary,
            processorKind: null,
            residentModelBytes: null,
            modelSizeBytes: null,
          }
        : await availabilityForPreset(preset);
      if (interruptSignalRequested() && !runAbortReason) {
        runAbortReason = interruptAbortReason();
      }

      const caseResults = [];
      if (
        availability.availabilityStatus === "ready" &&
        preset.runtimeKind === "local_http" &&
        !runAbortReason
      ) {
        for (
          let benchmarkIndex = 0;
          benchmarkIndex < selectedBenchmarks.length;
          benchmarkIndex += 1
        ) {
          if (interruptSignalRequested() && !runAbortReason) {
            runAbortReason = interruptAbortReason();
          }
          if (runAbortReason) {
            break;
          }
          const benchmark = selectedBenchmarks[benchmarkIndex];
          const benchmarkRoot = path.join(presetRoot, benchmark.benchmarkId);
          ensureDir(benchmarkRoot);
          let rawCaseResult;
          if (benchmark.adapter === "artifact_generate") {
            rawCaseResult = await runArtifactBenchmark(preset, benchmark, benchmarkRoot);
          } else if (benchmark.adapter === "computer_use_suite") {
            rawCaseResult = await runComputerUseBenchmark(preset, benchmark, benchmarkRoot);
          } else if (benchmark.adapter === "capabilities_suite") {
            rawCaseResult = await runCapabilitiesBenchmark(preset, benchmark, benchmarkRoot);
          } else {
            rawCaseResult = dependencyBlockedBenchmarkResult(
              benchmark,
              benchmarkRoot,
              `Adapter '${benchmark.adapter}' is declared in the matrix registry but not yet wired in this local benchmark environment.`,
            );
          }
          const caseResult = normalizeCaseResult(
            benchmark,
            preset,
            availability,
            rawCaseResult,
            runContext,
          );
          caseResults.push(caseResult);
          if (
            (caseResult.interrupted === true || interruptSignalRequested()) &&
            !runAbortReason
          ) {
            runAbortReason = interruptAbortReason(
              caseResult.signal || interruptSignalRequested(),
            );
          }
          const earlyAbortReason =
            runAbortReason ||
            runAbortReasonForShippedDefaultTimeouts({
              options,
              selectedPresets,
              preset,
              caseResults,
            });
          if (earlyAbortReason) {
            runAbortReason = earlyAbortReason;
            break;
          }
        }
      }
      if (availability.availabilityStatus !== "ready") {
        appendBlockedBenchmarks(
          caseResults,
          selectedBenchmarks,
          presetRoot,
          availability.availabilitySummary,
          preset,
          availability,
          runContext,
        );
      } else if (runAbortReason) {
        appendBlockedBenchmarks(
          caseResults,
          selectedBenchmarks,
          presetRoot,
          runAbortReason,
          preset,
          availability,
          runContext,
        );
      }

      const presetRunManifest = buildPresetRunManifest(
        runManifest,
        preset,
        availability,
        caseResults,
      );
      writeJson(path.join(presetRoot, "run-manifest.json"), presetRunManifest);
      const summary = summarizePreset(
        preset,
        availability,
        caseResults,
        presetRoot,
        runContext,
      );
      writeJson(summary.summaryPath, summary);
      presetSummaries.push(summary);
      latestSummary = persistLatestSummary({
        paths,
        runId,
        runRoot,
        previousRuns,
        presetSummaries,
        runAbortReason,
        plannedPresetCount: selectedPresets.length,
        runManifest,
      });
      if (runAbortReason) {
        break;
      }
      const transitionResult = await isolateOllamaPresetTransition({
        currentPreset: preset,
        nextPreset: selectedPresets[presetIndex + 1] || null,
        runRoot,
      });
      if (interruptSignalRequested() && !runAbortReason) {
        runAbortReason = interruptAbortReason();
      }
      if (runAbortReason) {
        break;
      }
      if (
        transitionResult &&
        transitionResult.ok === false &&
        selectedPresets[presetIndex + 1]
      ) {
        presetTransitionFailures.set(
          selectedPresets[presetIndex + 1].id,
          transitionResult,
        );
      }
    }
  } catch (error) {
    fatalError = error;
    runAbortReason = runAbortReason || `Runner failed: ${error.message}`;
  } finally {
    latestSummary = persistLatestSummary({
      paths,
      runId,
      runRoot,
      previousRuns,
      presetSummaries,
      runAbortReason,
      plannedPresetCount: selectedPresets.length,
      runManifest,
    });
    if (interruptSignalRequested()) {
      process.exitCode = signalExitCode(interruptSignalRequested());
    }
  }
  if (fatalError) {
    throw fatalError;
  }
  console.log(
    `Agent model matrix summary written to ${paths.latestSummaryPath} (${presetSummaries.length} presets, decision=${latestSummary.decision.outcome})`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main().catch((error) => {
    console.error(error?.stack || String(error));
    process.exitCode = process.exitCode || 1;
  });
}

export {
  artifactCommandDiagnostics,
  candidateLedgerForRun,
  decisionForRun,
  deploymentProfileForPreset,
  latestSummaryForRun,
  ollamaManagedModelNamesForPreset,
  ollamaGenerateUrlForPreset,
  ollamaResidentEntriesFromPsOutput,
  ollamaModelsToStopForTransition,
  ollamaResidentModelNamesFromPsOutput,
  ollamaTransitionStatusForPsOutput,
  ollamaWarmupPayloadForModel,
  runAbortReasonForShippedDefaultTimeouts,
  shouldIsolatePresetTransition,
  studioProofTraceMessages,
  timeoutDiagnosticLabel,
};
