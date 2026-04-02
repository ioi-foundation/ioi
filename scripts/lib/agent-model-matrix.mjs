import fs from "fs";
import path from "path";

export function agentModelMatrixPaths({ repoRoot }) {
  const evidenceRoot = path.join(repoRoot, "docs", "evidence", "agent-model-matrix");
  return {
    repoRoot,
    evidenceRoot,
    runsRoot: path.join(evidenceRoot, "runs"),
    latestSummaryPath: path.join(evidenceRoot, "latest-summary.json"),
    latestSummaryMarkdownPath: path.join(evidenceRoot, "latest-summary.md"),
    benchmarkCatalogPath: path.join(evidenceRoot, "benchmark-suite.catalog.json"),
    presetCatalogPath: path.join(
      repoRoot,
      "apps",
      "autopilot",
      "src-tauri",
      "dev",
      "model-matrix-presets.json",
    ),
  };
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

function toDisplayPath(repoRoot, targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return "";
  }
  if (!path.isAbsolute(targetPath)) {
    return String(targetPath).replace(/\\/g, "/");
  }
  const relative = path.relative(repoRoot, targetPath);
  if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
    return relative.split(path.sep).join("/");
  }
  return targetPath.replace(/\\/g, "/");
}

function toFileHref(targetPath) {
  return targetPath && fs.existsSync(targetPath) ? `file://${targetPath}` : "";
}

function normalizeScorecardCategory(category) {
  const parsed = category && typeof category === "object" ? category : {};
  return {
    available: parsed.available === true,
    reason: typeof parsed.reason === "string" ? parsed.reason : "",
    metrics:
      parsed.metrics && typeof parsed.metrics === "object" ? parsed.metrics : {},
  };
}

function normalizePresetScorecard(preset) {
  const categories =
    preset?.scorecards && typeof preset.scorecards === "object"
      ? preset.scorecards
      : {};
  return {
    artifactQuality: normalizeScorecardCategory(categories.artifactQuality),
    codingCompletion: normalizeScorecardCategory(categories.codingCompletion),
    researchQuality: normalizeScorecardCategory(categories.researchQuality),
    computerUseCompletion: normalizeScorecardCategory(
      categories.computerUseCompletion,
    ),
    latencyAndResourcePressure: normalizeScorecardCategory(
      categories.latencyAndResourcePressure,
    ),
    operationalDiscipline: normalizeScorecardCategory(
      categories.operationalDiscipline,
    ),
  };
}

export function normalizeAgentModelMatrixView(summary, repoRoot) {
  const parsed = summary && typeof summary === "object" ? summary : {};
  const presets = Array.isArray(parsed.presets) ? parsed.presets : [];
  return {
    status:
      typeof parsed.status === "string" && parsed.status.trim()
        ? parsed.status
        : "not_run",
    generatedAt:
      typeof parsed.generatedAt === "string" ? parsed.generatedAt : null,
    runId: typeof parsed.runId === "string" ? parsed.runId : null,
    decision: {
      outcome:
        typeof parsed?.decision?.outcome === "string"
          ? parsed.decision.outcome
          : "keep_default",
      summary:
        typeof parsed?.decision?.summary === "string"
          ? parsed.decision.summary
          : "No matrix comparison has been retained yet.",
      leaderPresetId:
        typeof parsed?.decision?.leaderPresetId === "string"
          ? parsed.decision.leaderPresetId
          : null,
      artifactLeaderPresetId:
        typeof parsed?.decision?.artifactLeaderPresetId === "string"
          ? parsed.decision.artifactLeaderPresetId
          : null,
      missingCoverage: Array.isArray(parsed?.decision?.missingCoverage)
        ? parsed.decision.missingCoverage.filter(
            (value) => typeof value === "string",
          )
        : [],
    },
    scorecardSchema:
      parsed.scorecardSchema && typeof parsed.scorecardSchema === "object"
        ? parsed.scorecardSchema
        : { version: 1, categories: [] },
    presetCatalogPath: toDisplayPath(repoRoot, parsed.presetCatalogPath),
    presetCatalogHref: toFileHref(parsed.presetCatalogPath),
    benchmarkCatalogPath: toDisplayPath(repoRoot, parsed.benchmarkCatalogPath),
    benchmarkCatalogHref: toFileHref(parsed.benchmarkCatalogPath),
    summaryPath: toDisplayPath(repoRoot, parsed.summaryPath),
    summaryHref: toFileHref(parsed.summaryPath),
    runRootPath: toDisplayPath(repoRoot, parsed.runRootPath),
    runRootHref: toFileHref(parsed.runRootPath),
    executedPresetCount: Number(parsed.executedPresetCount ?? 0),
    comparedPresetCount: Number(parsed.comparedPresetCount ?? presets.length),
    preservedDefault: parsed.preservedDefault !== false,
    presets: presets.map((preset) => ({
      presetId: preset?.presetId ?? "",
      label: preset?.label ?? "",
      role: preset?.role ?? "",
      benchmarkTier: preset?.benchmarkTier ?? "",
      experimental: preset?.experimental === true,
      shippedDefault: preset?.shippedDefault === true,
      availabilityStatus: preset?.availabilityStatus ?? "unknown",
      availabilitySummary: preset?.availabilitySummary ?? "",
      runtimeModel: preset?.runtimeModel ?? null,
      artifactAcceptanceModel: preset?.artifactAcceptanceModel ?? null,
      scorecards: normalizePresetScorecard(preset),
      caseCount: Number(preset?.caseCount ?? 0),
      availableWorkloadCount: Number(preset?.availableWorkloadCount ?? 0),
      summaryPath: toDisplayPath(repoRoot, preset?.summaryPath),
      summaryHref: toFileHref(preset?.summaryPath),
      runRootPath: toDisplayPath(repoRoot, preset?.runRootPath),
      runRootHref: toFileHref(preset?.runRootPath),
      topFindings: Array.isArray(preset?.topFindings)
        ? preset.topFindings.filter((value) => typeof value === "string").slice(0, 5)
        : [],
    })),
  };
}

export function renderAgentModelMatrixMarkdown(summary) {
  const normalized = normalizeAgentModelMatrixView(summary, summary?.repoRoot ?? process.cwd());
  const lines = [
    "# Agent Model Matrix",
    "",
    `- status: \`${normalized.status}\``,
    `- run_id: \`${normalized.runId ?? "unavailable"}\``,
    `- generated_at: \`${normalized.generatedAt ?? "unavailable"}\``,
    `- decision: \`${normalized.decision.outcome}\``,
    `- summary: ${normalized.decision.summary}`,
  ];
  if (normalized.decision.missingCoverage.length > 0) {
    lines.push(
      `- missing_coverage: ${normalized.decision.missingCoverage.join(", ")}`,
    );
  }
  lines.push("");
  lines.push(
    "| preset | role | availability | artifact judge | artifact verifier | coding | research | computer use | latency |",
  );
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const preset of normalized.presets) {
    const artifactMetrics = preset.scorecards.artifactQuality.metrics;
    const codingMetrics = preset.scorecards.codingCompletion.metrics;
    const researchMetrics = preset.scorecards.researchQuality.metrics;
    const artifactJudge =
      typeof artifactMetrics.averageJudgeScore === "number"
        ? artifactMetrics.averageJudgeScore.toFixed(3)
        : "n/a";
    const artifactVerifier =
      typeof artifactMetrics.verifierPassRate === "number"
        ? `${Math.round(artifactMetrics.verifierPassRate * 100)}%`
        : "n/a";
    const coding =
      typeof codingMetrics.taskPassRate === "number"
        ? `${Math.round(codingMetrics.taskPassRate * 100)}%`
        : preset.scorecards.codingCompletion.available
          ? "run"
          : "pending";
    const research =
      typeof researchMetrics.citationVerifierPassRate === "number"
        ? `${Math.round(researchMetrics.citationVerifierPassRate * 100)}%`
        : preset.scorecards.researchQuality.available
          ? "run"
          : "pending";
    const computerUseMetrics = preset.scorecards.computerUseCompletion.metrics;
    const computerUse =
      typeof computerUseMetrics.rewardFloorPassRate === "number"
        ? `${Math.round(computerUseMetrics.rewardFloorPassRate * 100)}%`
        : preset.scorecards.computerUseCompletion.available
          ? "run"
          : "pending";
    const latencyMetrics = preset.scorecards.latencyAndResourcePressure.metrics;
    const latency =
      typeof latencyMetrics.meanWallClockMs === "number"
        ? `${Math.round(latencyMetrics.meanWallClockMs)} ms`
        : "n/a";
    lines.push(
      `| ${preset.label} | ${preset.role} | ${preset.availabilityStatus} | ${artifactJudge} | ${artifactVerifier} | ${coding} | ${research} | ${computerUse} | ${latency} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

export function loadAgentModelMatrixPresetCatalog({ repoRoot }) {
  const { presetCatalogPath } = agentModelMatrixPaths({ repoRoot });
  return readJsonIfExists(presetCatalogPath);
}

export function loadAgentModelMatrixBenchmarkCatalog({ repoRoot }) {
  const { benchmarkCatalogPath } = agentModelMatrixPaths({ repoRoot });
  return readJsonIfExists(benchmarkCatalogPath);
}

export function buildAgentModelMatrixView({ repoRoot }) {
  const { latestSummaryPath } = agentModelMatrixPaths({ repoRoot });
  const summary = readJsonIfExists(latestSummaryPath);
  if (!summary) {
    return null;
  }
  return normalizeAgentModelMatrixView(summary, repoRoot);
}
