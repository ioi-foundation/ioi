import fs from "fs";
import path from "path";

import {
  DEPLOYMENT_PROFILES,
  REQUIRED_DECISION_CATEGORY_IDS,
  SCORECARD_SCHEMA,
  deploymentProfileForPresetLike,
  normalizeDeploymentProfileId,
} from "./benchmark-matrix-contracts.mjs";

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

const LOWER_IS_BETTER_METRICS = new Set([
  "meanWallClockMs",
  "p95WallClockMs",
  "residentModelBytes",
  "averageRepairLoopIterations",
  "repairLoopIterations",
  "meanStepCount",
  "malformedToolCallRate",
  "noOpStallRate",
]);

export function agentModelMatrixPaths({ repoRoot }) {
  const evidenceRoot = path.join(repoRoot, "docs", "evidence", "agent-model-matrix");
  return {
    repoRoot,
    evidenceRoot,
    runsRoot: path.join(evidenceRoot, "runs"),
    latestSummaryPath: path.join(evidenceRoot, "latest-summary.json"),
    latestSummaryMarkdownPath: path.join(evidenceRoot, "latest-summary.md"),
    latestCandidateLedgerPath: path.join(evidenceRoot, "latest-candidate-ledger.json"),
    latestRunManifestPath: path.join(evidenceRoot, "latest-run-manifest.json"),
    latestComparisonExportJsonPath: path.join(
      evidenceRoot,
      "exports",
      "latest-comparison-export.json",
    ),
    latestComparisonExportCsvPath: path.join(
      evidenceRoot,
      "exports",
      "latest-comparison-export.csv",
    ),
    benchmarkCatalogPath: path.join(evidenceRoot, "benchmark-suite.catalog.json"),
    modelRegistryPath: path.join(evidenceRoot, "model-registry.json"),
    deploymentProfilesPath: path.join(evidenceRoot, "deployment-profiles.json"),
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
    decisionWeight:
      typeof parsed.decisionWeight === "string"
        ? parsed.decisionWeight
        : "supporting",
    comparisonStatus:
      typeof parsed.comparisonStatus === "string"
        ? parsed.comparisonStatus
        : parsed.available === true
          ? "comparable"
          : "not_comparable",
    confidenceClass:
      typeof parsed.confidenceClass === "string" ? parsed.confidenceClass : "low",
    coverageClass:
      typeof parsed.coverageClass === "string"
        ? parsed.coverageClass
        : parsed.available === true
          ? "full"
          : "none",
    benchmarkPrograms: Array.isArray(parsed.benchmarkPrograms)
      ? parsed.benchmarkPrograms.filter((value) => typeof value === "string")
      : [],
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
    baseModelQuality: normalizeScorecardCategory(categories.baseModelQuality),
    artifactQuality: normalizeScorecardCategory(categories.artifactQuality),
    codingCompletion: normalizeScorecardCategory(categories.codingCompletion),
    researchQuality: normalizeScorecardCategory(categories.researchQuality),
    computerUseCompletion: normalizeScorecardCategory(
      categories.computerUseCompletion,
    ),
    toolApiReliability: normalizeScorecardCategory(categories.toolApiReliability),
    generalAgentQuality: normalizeScorecardCategory(categories.generalAgentQuality),
    latencyAndResourcePressure: normalizeScorecardCategory(
      categories.latencyAndResourcePressure,
    ),
    operationalDiscipline: normalizeScorecardCategory(
      categories.operationalDiscipline,
    ),
  };
}

function inferDeploymentProfileId(preset, catalogPreset) {
  return (
    normalizeDeploymentProfileId(preset?.deploymentProfile) ??
    normalizeDeploymentProfileId(catalogPreset?.deploymentProfile) ??
    normalizeDeploymentProfileId(catalogPreset?.deploymentProfileId) ??
    deploymentProfileForPresetLike({
      ...catalogPreset,
      ...preset,
      deploymentProfile:
        preset?.deploymentProfile ??
        catalogPreset?.deploymentProfile ??
        catalogPreset?.deploymentProfileId,
    })
  );
}

function scorecardValue(category, metricId) {
  return category?.metrics?.[metricId] ?? null;
}

function preferredMetricId(categoryId, category, schemaMetrics) {
  const preferredByCategory = {
    artifactQuality: "averageValidationScore",
    codingCompletion: "taskPassRate",
    researchQuality: "citationVerifierPassRate",
    computerUseCompletion: "rewardFloorPassRate",
    latencyAndResourcePressure: "meanWallClockMs",
    operationalDiscipline: "interruptionRecoveryQuality",
  };
  const preferred = preferredByCategory[categoryId];
  if (preferred && schemaMetrics.includes(preferred)) {
    return preferred;
  }
  return (
    schemaMetrics.find((metricId) => {
      const value = scorecardValue(category, metricId);
      return value !== null && value !== undefined && value !== "";
    }) ?? null
  );
}

function bestPresetIdsByCategory(presets, scorecardSchema) {
  const bestByCategory = new Map();

  for (const category of scorecardSchema?.categories ?? []) {
    const metricId = preferredMetricId(category.id, null, category.metrics ?? []);
    if (!metricId) {
      bestByCategory.set(category.id, null);
      continue;
    }

    let bestPresetId = null;
    let bestValue = null;

    for (const preset of presets) {
      const categoryData = scorecardValue(preset.scorecards?.[category.id], metricId);
      if (typeof categoryData !== "number") {
        continue;
      }

      if (bestValue == null) {
        bestValue = categoryData;
        bestPresetId = preset.presetId;
        continue;
      }

      const lowerIsBetter = LOWER_IS_BETTER_METRICS.has(metricId);
      const wins = lowerIsBetter ? categoryData < bestValue : categoryData > bestValue;
      if (wins) {
        bestValue = categoryData;
        bestPresetId = preset.presetId;
      }
    }

    bestByCategory.set(category.id, bestPresetId);
  }

  return bestByCategory;
}

function targetFamilyLabel(requiredCategories, preset) {
  const covered = requiredCategories.filter(
    (category) => preset.scorecards?.[category.id]?.available === true,
  );
  if (covered.length === 0) {
    return "No retained required-family coverage yet";
  }
  return covered
    .map((category) => CATEGORY_SHORT_LABELS[category.id] ?? category.label)
    .join(" / ");
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

function buildCandidateLedger(normalizedPresets, decision, scorecardSchema) {
  const baselinePreset =
    normalizedPresets.find((preset) => preset.shippedDefault) ??
    normalizedPresets[0] ??
    null;
  const matrixLeaderPresetId =
    decision?.leaderPresetId ?? decision?.artifactLeaderPresetId ?? null;
  const requiredCategories = (scorecardSchema?.categories ?? []).filter(
    (category) => REQUIRED_DECISION_CATEGORY_IDS.includes(category.id),
  );
  const bestPresetIds = bestPresetIdsByCategory(normalizedPresets, scorecardSchema);

  return normalizedPresets.map((preset) => {
    const requiredReadyCount = requiredCategories.filter(
      (category) => preset.scorecards?.[category.id]?.available === true,
    ).length;
    const bestRequiredCount = requiredCategories.filter(
      (category) => bestPresetIds.get(category.id) === preset.presetId,
    ).length;
    const requiredCategoryCount = requiredCategories.length;
    const status = candidateStatusForPreset({
      baselinePresetId: baselinePreset?.presetId ?? null,
      matrixLeaderPresetId,
      preset,
      requiredReadyCount,
      requiredCategoryCount,
    });

    return {
      candidateId: `candidate:${preset.presetId}`,
      parentCandidateId:
        preset.shippedDefault || !baselinePreset || baselinePreset.presetId === preset.presetId
          ? null
          : `candidate:${baselinePreset.presetId}`,
      presetId: preset.presetId,
      deploymentProfile: preset.deploymentProfile,
      status,
      summary: candidateSummaryForStatus(status),
      mutationIntent: mutationIntentForProfile(preset.deploymentProfile, preset),
      targetFamily: targetFamilyLabel(requiredCategories, preset),
      changedContracts: changedContractsForProfile(preset.deploymentProfile),
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
      regressions:
        preset.topFindings.length > 0
          ? preset.topFindings.slice(0, 3)
          : decision?.missingCoverage?.length > 0
            ? decision.missingCoverage.slice(0, 3)
            : [],
      evidenceLinks: [
        { label: "summary", href: preset.summaryHref },
        { label: "retained_run", href: preset.runRootHref },
      ].filter((entry) => entry.href),
    };
  });
}

function normalizeCandidateLedgerEntry(entry, normalizedPresetMap) {
  const parsed = entry && typeof entry === "object" ? entry : {};
  const preset =
    typeof parsed.presetId === "string"
      ? normalizedPresetMap.get(parsed.presetId) ?? null
      : null;
  const deploymentProfile =
    normalizeDeploymentProfileId(parsed.deploymentProfile) ??
    preset?.deploymentProfile ??
    "local_gpu_8gb_class";

  const evidenceLinks = Array.isArray(parsed.evidenceLinks)
    ? parsed.evidenceLinks
        .map((link) => {
          const pathValue =
            typeof link?.path === "string"
              ? link.path
              : typeof link?.href === "string" && link.href.startsWith("file://")
                ? link.href.replace(/^file:\/\//, "")
                : null;
          const href =
            typeof link?.href === "string" && link.href
              ? link.href
              : toFileHref(pathValue);
          if (!href) {
            return null;
          }
          return {
            label:
              typeof link?.label === "string" && link.label.trim()
                ? link.label
                : "evidence",
            href,
          };
        })
        .filter(Boolean)
    : [];

  return {
    candidateId:
      typeof parsed.candidateId === "string"
        ? parsed.candidateId
        : `candidate:${preset?.presetId ?? "unknown"}`,
    candidateKind:
      typeof parsed.candidateKind === "string" ? parsed.candidateKind : "model",
    parentCandidateId:
      typeof parsed.parentCandidateId === "string" ? parsed.parentCandidateId : null,
    presetId: typeof parsed.presetId === "string" ? parsed.presetId : preset?.presetId ?? "",
    deploymentProfile,
    comparisonIntent:
      typeof parsed.comparisonIntent === "string"
        ? parsed.comparisonIntent
        : preset?.comparisonContext?.comparisonIntent ?? "model_change",
    executionScope:
      typeof parsed.executionScope === "string"
        ? parsed.executionScope
        : preset?.comparisonContext?.executionScope ?? "fleet_shared",
    status: typeof parsed.status === "string" ? parsed.status : "retained",
    summary: typeof parsed.summary === "string" ? parsed.summary : "",
    mutationIntent:
      typeof parsed.mutationIntent === "string" ? parsed.mutationIntent : "",
    targetFamily:
      typeof parsed.targetFamily === "string"
        ? parsed.targetFamily
        : "No retained required-family coverage yet",
    changedContracts: Array.isArray(parsed.changedContracts)
      ? parsed.changedContracts.filter((value) => typeof value === "string")
      : [],
    roleAssignmentDelta: Array.isArray(parsed.roleAssignmentDelta)
      ? parsed.roleAssignmentDelta.filter((value) => typeof value === "string")
      : [],
    validationSummary: {
      requiredReadyCount: Number(parsed?.validationSummary?.requiredReadyCount ?? 0),
      requiredCategoryCount: Number(parsed?.validationSummary?.requiredCategoryCount ?? 0),
      bestRequiredCount: Number(parsed?.validationSummary?.bestRequiredCount ?? 0),
      coverageStatus:
        typeof parsed?.validationSummary?.coverageStatus === "string"
          ? parsed.validationSummary.coverageStatus
          : "sparse",
    },
    evaluationLanes:
      parsed.evaluationLanes && typeof parsed.evaluationLanes === "object"
        ? {
            proxy: parsed.evaluationLanes.proxy ?? "not_run",
            validation: parsed.evaluationLanes.validation ?? "not_run",
            challenge: parsed.evaluationLanes.challenge ?? "not_run",
            holdout: parsed.evaluationLanes.holdout ?? "not_run",
          }
        : {
            proxy: "not_run",
            validation: "not_run",
            challenge: "not_run",
            holdout: "not_run",
          },
    conformanceStatus:
      typeof parsed.conformanceStatus === "string"
        ? parsed.conformanceStatus
        : preset?.conformanceSummary?.status ?? "warn",
    paretoClass:
      typeof parsed.paretoClass === "string" ? parsed.paretoClass : "retained",
    controlRunIds: Array.isArray(parsed.controlRunIds)
      ? parsed.controlRunIds.filter((value) => typeof value === "string")
      : [],
    rollbackTarget:
      typeof parsed.rollbackTarget === "string" ? parsed.rollbackTarget : null,
    regressions: Array.isArray(parsed.regressions)
      ? parsed.regressions.filter((value) => typeof value === "string")
      : [],
    evidenceLinks,
  };
}

function buildDeploymentDecisions(normalizedPresets, decision, scorecardSchema) {
  const grouped = new Map(DEPLOYMENT_PROFILES.map((profile) => [profile.id, []]));
  for (const preset of normalizedPresets) {
    if (grouped.has(preset.deploymentProfile)) {
      grouped.get(preset.deploymentProfile).push(preset);
    }
  }

  const matrixLeaderPresetId =
    decision?.leaderPresetId ?? decision?.artifactLeaderPresetId ?? null;
  const requiredCategoryIds = (scorecardSchema?.categories ?? SCORECARD_SCHEMA.categories)
    .filter((category) => REQUIRED_DECISION_CATEGORY_IDS.includes(category.id))
    .map((category) => category.id);

  return DEPLOYMENT_PROFILES.map((profile) => {
    const presets = grouped.get(profile.id) ?? [];
    const defaultPreset = presets.find((preset) => preset.shippedDefault) ?? null;
    const leaderPreset =
      presets.find((preset) => preset.presetId === matrixLeaderPresetId) ??
      defaultPreset ??
      presets.find((preset) => preset.experimental) ??
      presets[0] ??
      null;
    const coverageGaps = requiredCategoryIds.filter(
      (categoryId) =>
        !presets.some((preset) => preset.scorecards?.[categoryId]?.available === true),
    );
    const state =
      presets.length === 0
        ? "empty"
        : leaderPreset?.shippedDefault
          ? "default"
          : profile.id.startsWith("blind_cloud")
            ? "shadow_only"
            : leaderPreset?.experimental
              ? "candidate"
              : "retained";

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
          : leaderPreset && !defaultPreset && leaderPreset.experimental
            ? leaderPreset.presetId
            : null,
      coverageGaps,
      requiredCategoryIds,
      summary:
        presets.length === 0
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

export function normalizeAgentModelMatrixView(summary, repoRoot, options = {}) {
  const parsed = summary && typeof summary === "object" ? summary : {};
  const defaultPaths = agentModelMatrixPaths({ repoRoot });
  const presetCatalog = options.presetCatalog && typeof options.presetCatalog === "object"
    ? options.presetCatalog
    : null;
  const presetCatalogMap = new Map(
    Array.isArray(presetCatalog?.presets)
      ? presetCatalog.presets
          .filter((preset) => preset && typeof preset.id === "string")
          .map((preset) => [preset.id, preset])
      : [],
  );
  const presets = Array.isArray(parsed.presets) ? parsed.presets : [];
  const normalizedPresets = presets.map((preset) => {
    const catalogPreset = presetCatalogMap.get(preset?.presetId) ?? null;
    return {
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
      deploymentProfile: inferDeploymentProfileId(preset, catalogPreset),
      modelFingerprint:
        preset?.modelFingerprint && typeof preset.modelFingerprint === "object"
          ? preset.modelFingerprint
          : null,
      roleAssignments: Array.isArray(preset?.roleAssignments)
        ? preset.roleAssignments.filter((value) => value && typeof value === "object")
        : [],
      comparisonContext:
        preset?.comparisonContext && typeof preset.comparisonContext === "object"
          ? preset.comparisonContext
          : {
              comparisonIntent: "model_change",
              executionScope: "fleet_shared",
              baselinePresetId: null,
              manifestPath: null,
            },
      conformanceSummary:
        preset?.conformanceSummary && typeof preset.conformanceSummary === "object"
          ? preset.conformanceSummary
          : {
              status: "warn",
              activePolicyIds: [],
              comparisonValidityRate: null,
              conformancePassRate: null,
              protectedSplitPassRate: null,
              rollbackReadinessRate: null,
            },
      scorecards: normalizePresetScorecard(preset),
      caseCount: Number(preset?.caseCount ?? 0),
      availableWorkloadCount: Number(preset?.availableWorkloadCount ?? 0),
      summaryPath: toDisplayPath(repoRoot, preset?.summaryPath),
      summaryHref: toFileHref(preset?.summaryPath),
      manifestPath: toDisplayPath(repoRoot, preset?.manifestPath),
      manifestHref: toFileHref(preset?.manifestPath),
      runRootPath: toDisplayPath(repoRoot, preset?.runRootPath),
      runRootHref: toFileHref(preset?.runRootPath),
      topFindings: Array.isArray(preset?.topFindings)
        ? preset.topFindings.filter((value) => typeof value === "string").slice(0, 5)
        : [],
    };
  });
  const normalizedPresetMap = new Map(
    normalizedPresets.map((preset) => [preset.presetId, preset]),
  );
  const candidateLedger = Array.isArray(parsed.candidateLedger)
    ? parsed.candidateLedger
        .map((entry) => normalizeCandidateLedgerEntry(entry, normalizedPresetMap))
        .filter(
          (entry) =>
            typeof entry.presetId === "string" &&
            entry.presetId &&
            normalizedPresetMap.has(entry.presetId),
        )
    : buildCandidateLedger(
        normalizedPresets,
        parsed?.decision ?? {},
        parsed?.scorecardSchema ?? SCORECARD_SCHEMA,
      );

  return {
    status:
      typeof parsed.status === "string" && parsed.status.trim()
        ? parsed.status
        : "not_run",
    generatedAt:
      typeof parsed.generatedAt === "string" ? parsed.generatedAt : null,
    runId: typeof parsed.runId === "string" ? parsed.runId : null,
    runAbortReason:
      typeof parsed.runAbortReason === "string" ? parsed.runAbortReason : null,
    runManifest:
      parsed.runManifest && typeof parsed.runManifest === "object"
        ? parsed.runManifest
        : null,
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
        : SCORECARD_SCHEMA,
    deploymentDecisions:
      Array.isArray(parsed.deploymentDecisions) && parsed.deploymentDecisions.length > 0
        ? parsed.deploymentDecisions
        : buildDeploymentDecisions(
            normalizedPresets,
            parsed?.decision ?? {},
            parsed?.scorecardSchema ?? SCORECARD_SCHEMA,
          ),
    presetCatalogPath: toDisplayPath(
      repoRoot,
      parsed.presetCatalogPath ?? defaultPaths.presetCatalogPath,
    ),
    presetCatalogHref: toFileHref(parsed.presetCatalogPath ?? defaultPaths.presetCatalogPath),
    benchmarkCatalogPath: toDisplayPath(
      repoRoot,
      parsed.benchmarkCatalogPath ?? defaultPaths.benchmarkCatalogPath,
    ),
    benchmarkCatalogHref: toFileHref(
      parsed.benchmarkCatalogPath ?? defaultPaths.benchmarkCatalogPath,
    ),
    modelRegistryPath: toDisplayPath(
      repoRoot,
      parsed.modelRegistryPath ?? defaultPaths.modelRegistryPath,
    ),
    modelRegistryHref: toFileHref(parsed.modelRegistryPath ?? defaultPaths.modelRegistryPath),
    deploymentProfilesPath: toDisplayPath(
      repoRoot,
      parsed.deploymentProfilesPath ?? defaultPaths.deploymentProfilesPath,
    ),
    deploymentProfilesHref: toFileHref(
      parsed.deploymentProfilesPath ?? defaultPaths.deploymentProfilesPath,
    ),
    summaryPath: toDisplayPath(repoRoot, parsed.summaryPath ?? defaultPaths.latestSummaryPath),
    summaryHref: toFileHref(parsed.summaryPath ?? defaultPaths.latestSummaryPath),
    runRootPath: toDisplayPath(repoRoot, parsed.runRootPath ?? defaultPaths.evidenceRoot),
    runRootHref: toFileHref(parsed.runRootPath ?? defaultPaths.evidenceRoot),
    runManifestPath: toDisplayPath(
      repoRoot,
      parsed.runManifestPath ?? defaultPaths.latestRunManifestPath,
    ),
    runManifestHref: toFileHref(parsed.runManifestPath ?? defaultPaths.latestRunManifestPath),
    candidateLedgerPath: toDisplayPath(
      repoRoot,
      parsed.candidateLedgerPath ?? defaultPaths.latestCandidateLedgerPath,
    ),
    candidateLedgerHref: toFileHref(
      parsed.candidateLedgerPath ?? defaultPaths.latestCandidateLedgerPath,
    ),
    comparisonExportJsonPath: toDisplayPath(
      repoRoot,
      parsed.comparisonExportJsonPath ?? defaultPaths.latestComparisonExportJsonPath,
    ),
    comparisonExportJsonHref: toFileHref(
      parsed.comparisonExportJsonPath ?? defaultPaths.latestComparisonExportJsonPath,
    ),
    comparisonExportCsvPath: toDisplayPath(
      repoRoot,
      parsed.comparisonExportCsvPath ?? defaultPaths.latestComparisonExportCsvPath,
    ),
    comparisonExportCsvHref: toFileHref(
      parsed.comparisonExportCsvPath ?? defaultPaths.latestComparisonExportCsvPath,
    ),
    plannedPresetCount: Number(
      parsed.plannedPresetCount ?? parsed.comparedPresetCount ?? presets.length,
    ),
    summarizedPresetCount: Number(
      parsed.summarizedPresetCount ?? parsed.comparedPresetCount ?? presets.length,
    ),
    fullyCompletedPresetCount: Number(
      parsed.fullyCompletedPresetCount ??
        parsed.completedPresetCount ??
        parsed.comparedPresetCount ??
        presets.length,
    ),
    executedPresetCount: Number(parsed.executedPresetCount ?? 0),
    comparedPresetCount: Number(parsed.comparedPresetCount ?? presets.length),
    preservedDefault: parsed.preservedDefault !== false,
    presets: normalizedPresets,
    candidateLedger,
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
    `- comparison_intent: \`${normalized.runManifest?.comparisonIntent ?? "unavailable"}\``,
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
    "| preset | deployment | role | base model | artifacts | coding | research | computer use | tool/api | general agent | latency | conformance |",
  );
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const preset of normalized.presets) {
    const baseModelMetrics = preset.scorecards.baseModelQuality.metrics;
    const artifactMetrics = preset.scorecards.artifactQuality.metrics;
    const codingMetrics = preset.scorecards.codingCompletion.metrics;
    const researchMetrics = preset.scorecards.researchQuality.metrics;
    const toolApiMetrics = preset.scorecards.toolApiReliability.metrics;
    const generalAgentMetrics = preset.scorecards.generalAgentQuality.metrics;
    const artifactValidation =
      typeof artifactMetrics.averageValidationScore === "number"
        ? artifactMetrics.averageValidationScore.toFixed(3)
        : preset.scorecards.artifactQuality.available
          ? "run"
          : "pending";
    const baseModel =
      typeof baseModelMetrics.normalizedScore === "number"
        ? baseModelMetrics.normalizedScore.toFixed(2)
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
    const toolApi =
      typeof toolApiMetrics.normalizedScore === "number"
        ? toolApiMetrics.normalizedScore.toFixed(2)
        : preset.scorecards.toolApiReliability.available
          ? "run"
          : "pending";
    const generalAgent =
      typeof generalAgentMetrics.normalizedScore === "number"
        ? generalAgentMetrics.normalizedScore.toFixed(2)
        : preset.scorecards.generalAgentQuality.available
          ? "run"
          : "pending";
    const latencyMetrics = preset.scorecards.latencyAndResourcePressure.metrics;
    const latency =
      typeof latencyMetrics.meanWallClockMs === "number"
        ? `${Math.round(latencyMetrics.meanWallClockMs)} ms`
        : "n/a";
    const conformanceMetrics = preset.scorecards.operationalDiscipline.metrics;
    const conformance =
      typeof conformanceMetrics.conformancePassRate === "number"
        ? `${Math.round(conformanceMetrics.conformancePassRate * 100)}%`
        : preset.scorecards.operationalDiscipline.available
          ? "run"
          : "pending";
    lines.push(
      `| ${preset.label} | ${preset.deploymentProfile ?? "unknown"} | ${preset.role} | ${baseModel} | ${artifactValidation} | ${coding} | ${research} | ${computerUse} | ${toolApi} | ${generalAgent} | ${latency} | ${conformance} |`,
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
  return normalizeAgentModelMatrixView(summary, repoRoot, {
    presetCatalog: loadAgentModelMatrixPresetCatalog({ repoRoot }),
  });
}
