import fs from "fs";
import path from "path";

export const DEFAULT_PARITY_LOOP_LEDGER_PATH = path.join(
  "parity-loop",
  "ledger.json",
);

export const INTERVENTION_FAMILIES = [
  "blueprint",
  "skill_discovery",
  "scaffold",
  "component_pack",
  "static_audit",
  "validation",
  "repair_loop",
  "evidence_ux",
];

export const DEFAULT_PARITY_LOOP_BUDGETS = {
  maxInterventionCount: 12,
  maxWallClockMs: 4 * 60 * 60 * 1000,
  maxNoImprovementStreak: 3,
};

export const DEFAULT_PARITY_LOOP_THRESHOLDS = {
  maxBlockedCases: 0,
  maxRepairableCases: 0,
  maxTruthfulnessIssues: 0,
  requireAllParityChecks: true,
  requireFullBenchmarkCoverage: true,
};

function deepClone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
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

function mergedBudgets(budgets = {}) {
  return {
    ...DEFAULT_PARITY_LOOP_BUDGETS,
    ...(budgets ?? {}),
  };
}

function mergedThresholds(thresholds = {}) {
  return {
    ...DEFAULT_PARITY_LOOP_THRESHOLDS,
    ...(thresholds ?? {}),
  };
}

function normalizeHistoricalLabel(value) {
  if (typeof value !== "string") {
    return value ?? null;
  }
  return value.replace(/\bLive Chat Runtime lane\b/g, "Live Chat Runtime");
}

function normalizeInvariantFailure(failure) {
  if (!failure || typeof failure !== "object") {
    return failure;
  }
  const normalizedId = failure.id === "live_chat_runtime_lane" ? "live_chat_runtime" : failure.id;
  const normalizedLabel =
    failure.id === "live_chat_runtime_lane" || failure.label === "Live Chat Runtime lane"
      ? "Live Chat Runtime"
      : normalizeHistoricalLabel(failure.label);
  return {
    ...failure,
    id: normalizedId,
    label: normalizedLabel,
    summary: normalizeHistoricalLabel(failure.summary),
    caseIds: Array.isArray(failure.caseIds)
      ? failure.caseIds.filter((value) => typeof value === "string")
      : [],
  };
}

function normalizeWeakestTarget(target) {
  if (!target || typeof target !== "object") {
    return target;
  }
  return {
    ...target,
    id: target.id === "live_chat_runtime_lane" ? "live_chat_runtime" : target.id,
    label:
      target.id === "live_chat_runtime_lane" || target.label === "Live Chat Runtime lane"
        ? "Live Chat Runtime"
        : normalizeHistoricalLabel(target.label),
    summary: normalizeHistoricalLabel(target.summary),
    caseIds: Array.isArray(target.caseIds)
      ? target.caseIds.filter((value) => typeof value === "string")
      : [],
  };
}

function normalizeParitySnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") {
    return snapshot;
  }
  const invariantFailures = Array.isArray(snapshot.invariantFailures)
    ? snapshot.invariantFailures.map(normalizeInvariantFailure)
    : [];
  const weakestTarget = normalizeWeakestTarget(snapshot.weakestTarget);
  return {
    ...snapshot,
    invariantFailures,
    weakestTarget,
  };
}

function normalizeParityReceipt(receipt) {
  if (!receipt || typeof receipt !== "object") {
    return receipt;
  }
  return {
    ...receipt,
    snapshot: normalizeParitySnapshot(receipt.snapshot),
    weakestTarget: normalizeWeakestTarget(receipt.weakestTarget),
    decision:
      receipt.decision && typeof receipt.decision === "object"
        ? {
            ...receipt.decision,
            reason: normalizeHistoricalLabel(receipt.decision.reason),
          }
        : receipt.decision,
  };
}

function validationClassificationRank(classification) {
  switch (classification) {
    case "pass":
      return 3;
    case "repairable":
      return 2;
    default:
      return 1;
  }
}

function validationTotalScore(validation) {
  if (!validation || typeof validation !== "object") {
    return null;
  }
  const issueClassCount = Array.isArray(validation.issueClasses)
    ? validation.issueClasses.length
    : 0;
  const truthfulnessWarningCount = Array.isArray(validation.truthfulnessWarnings)
    ? validation.truthfulnessWarnings.length
    : 0;
  const blockedReasonCount = Array.isArray(validation.blockedReasons)
    ? validation.blockedReasons.length
    : 0;
  const strengthCount = Array.isArray(validation.strengths) ? validation.strengths.length : 0;
  return (
    validationClassificationRank(validation.classification) * 100 +
    Number(validation.requestFaithfulness ?? 0) * 12 +
    Number(validation.conceptCoverage ?? 0) * 10 +
    Number(validation.interactionRelevance ?? 0) * 8 +
    Number(validation.layoutCoherence ?? 0) * 7 +
    Number(validation.visualHierarchy ?? 0) * 7 +
    Number(validation.completeness ?? 0) * 9 +
    (validation.deservesPrimaryArtifactView ? 12 : -20) +
    (validation.genericShellDetected ? -28 : 0) +
    (validation.trivialShellDetected ? -36 : 0) -
    issueClassCount * 4 -
    truthfulnessWarningCount * 6 -
    blockedReasonCount * 8 +
    strengthCount * 3 +
    Number(validation.continuityRevisionUx ?? 0)
  );
}

function readyRateFromCorpus(corpusSummary) {
  const metric = corpusSummary?.benchmarkSuite?.metrics?.readyRate;
  if (metric?.available && typeof metric.value === "number") {
    return metric.value;
  }
  const totals = corpusSummary?.totals ?? {};
  const totalCases =
    Number(totals.pass ?? 0) +
    Number(totals.repairable ?? 0) +
    Number(totals.blocked ?? 0);
  return totalCases > 0 ? Number(totals.pass ?? 0) / totalCases : 0;
}

function averageValidationScoreFromCorpus(corpusSummary) {
  const metric = corpusSummary?.benchmarkSuite?.metrics?.averageValidationScore;
  if (metric?.available && typeof metric.value === "number") {
    return metric.value;
  }
  const scores = Array.isArray(corpusSummary?.cases)
    ? corpusSummary.cases
        .map((entry) => validationTotalScore(entry?.validation))
        .filter((value) => typeof value === "number")
    : [];
  if (scores.length === 0) {
    return null;
  }
  return scores.reduce((sum, value) => sum + value, 0) / scores.length;
}

function countTruthfulnessIssues(corpusSummary) {
  if (!Array.isArray(corpusSummary?.cases)) {
    return 0;
  }
  return corpusSummary.cases.reduce((count, entry) => {
    if (!entry || typeof entry !== "object") {
      return count + 1;
    }
    const classification = entry.classification ?? "blocked";
    const validation = entry.validation ?? null;
    const failure = entry.failure ?? null;
    const fallbackUsed = Boolean(entry.fallbackUsed);
    if (classification === "pass" && (!validation || failure || fallbackUsed)) {
      return count + 1;
    }
    if (validation && classification !== validation.classification) {
      return count + 1;
    }
    return count;
  }, 0);
}

function collectInvariantFailures(corpusSummary) {
  const parityChecks = corpusSummary?.parityChecks ?? {};
  const failures = [];

  if (corpusSummary?.lanes?.liveChatRuntime?.status !== "pass") {
    failures.push({
      id: "live_chat_runtime",
      label: "Live Chat Runtime",
      summary:
        corpusSummary?.lanes?.liveChatRuntime?.strongestContradiction ??
        "Live Chat Runtime is not yet passing.",
      family: "evidence_ux",
      caseIds: Array.isArray(corpusSummary?.lanes?.liveChatRuntime?.cases)
        ? corpusSummary.lanes.liveChatRuntime.cases.map((entry) => entry.id).filter(Boolean)
        : [],
    });
  }

  if (parityChecks?.htmlDistinctness?.allDistinct === false) {
    failures.push({
      id: "html_distinctness",
      label: "HTML distinctness",
      summary: "HTML retained outputs still collapse into visually similar shells.",
      family: "scaffold",
      caseIds: parityChecks.htmlDistinctness.failingCaseIds ?? [],
    });
  }

  if (parityChecks?.refinementPatchFlow?.allPatched === false) {
    failures.push({
      id: "refinement_patch_flow",
      label: "Refinement patch flow",
      summary: "Refinement passes are not consistently patching the intended structure.",
      family: "repair_loop",
      caseIds: parityChecks.refinementPatchFlow.failingCaseIds ?? [],
    });
  }

  if (parityChecks?.targetedEditFlow?.passed === false) {
    failures.push({
      id: "targeted_edit_flow",
      label: "Targeted edit flow",
      summary: "Targeted edits are not preserving the intended mutation boundary.",
      family: "component_pack",
      caseIds: [parityChecks.targetedEditFlow.caseId].filter(Boolean),
    });
  }

  if (parityChecks?.styleSteeringFlow?.passed === false) {
    failures.push({
      id: "style_steering_flow",
      label: "Style steering flow",
      summary: "Style steering is not reliably surfacing promoted design guidance.",
      family: "skill_discovery",
      caseIds: [parityChecks.styleSteeringFlow.caseId].filter(Boolean),
    });
  }

  for (const revisionStage of ["compare", "restore", "branch"]) {
    if (parityChecks?.revisionFlow?.[revisionStage]?.classification !== "pass") {
      failures.push({
        id: `revision_${revisionStage}`,
        label: `Revision ${revisionStage}`,
        summary: `Revision ${revisionStage} is not yet passing.`,
        family: "evidence_ux",
        caseIds: [
          parityChecks?.revisionFlow?.[revisionStage]?.caseId ??
            parityChecks?.revisionFlow?.[revisionStage]?.baseCaseId ??
            parityChecks?.revisionFlow?.[revisionStage]?.refinedCaseId,
        ].filter(Boolean),
      });
    }
  }

  if (parityChecks?.repeatedRunVariationFlow?.classification !== "pass") {
    failures.push({
      id: "repeated_run_variation",
      label: "Repeated run variation",
      summary:
        parityChecks?.repeatedRunVariationFlow?.strongestContradiction ??
        "Repeated runs are not yet stable enough.",
      family: "static_audit",
      caseIds: [
        parityChecks?.repeatedRunVariationFlow?.sourceCaseId,
        ...(parityChecks?.repeatedRunVariationFlow?.failingRunIds ?? []),
      ].filter(Boolean),
    });
  }

  return failures;
}

function collectWeakestCase(corpusSummary) {
  if (!Array.isArray(corpusSummary?.cases) || corpusSummary.cases.length === 0) {
    return null;
  }

  const ranked = corpusSummary.cases
    .map((entry) => ({
      id: entry.id,
      label: entry.id,
      summary:
        entry.strongestContradiction ??
        entry.validation?.strongestContradiction ??
        entry.validation?.rationale ??
        "Case needs additional work.",
      classification: entry.classification ?? "blocked",
      validationScore: validationTotalScore(entry.validation),
      blueprintPresent: Boolean(entry.blueprint),
      artifactIrPresent: Boolean(entry.artifactIr),
      selectedSkillCount: Array.isArray(entry.selectedSkills)
        ? entry.selectedSkills.length
        : 0,
      renderer:
        entry.manifest?.renderer ??
        entry.inspect?.renderer ??
        entry.route?.artifact?.renderer ??
        null,
      caseIds: [entry.id].filter(Boolean),
    }))
    .sort((left, right) => {
      const leftRank = validationClassificationRank(left.classification);
      const rightRank = validationClassificationRank(right.classification);
      if (leftRank !== rightRank) {
        return leftRank - rightRank;
      }
      const leftScore = left.validationScore ?? -Infinity;
      const rightScore = right.validationScore ?? -Infinity;
      if (leftScore !== rightScore) {
        return leftScore - rightScore;
      }
      return String(left.id).localeCompare(String(right.id));
    });

  return ranked[0] ?? null;
}

function weakestTargetForSnapshot(snapshot) {
  if (snapshot.invariantFailures.length > 0) {
    return snapshot.invariantFailures[0];
  }
  return snapshot.weakestCase;
}

function familyForWeakestCase(weakestCase) {
  if (!weakestCase) {
    return "validation";
  }
  if (!weakestCase.blueprintPresent || !weakestCase.artifactIrPresent) {
    return "blueprint";
  }
  if (
    ["html_iframe", "jsx_sandbox", "svg"].includes(weakestCase.renderer) &&
    weakestCase.selectedSkillCount === 0
  ) {
    return "skill_discovery";
  }
  if (weakestCase.classification === "blocked") {
    return "static_audit";
  }
  if (weakestCase.classification === "repairable") {
    return "repair_loop";
  }
  return "validation";
}

export function collectChatArtifactParitySnapshot(corpusSummary, options = {}) {
  const thresholds = mergedThresholds(options.thresholds);
  const totals = corpusSummary?.totals ?? { pass: 0, repairable: 0, blocked: 0 };
  const benchmarkSuite = corpusSummary?.benchmarkSuite ?? null;
  const invariantFailures = collectInvariantFailures(corpusSummary);
  const weakestCase = collectWeakestCase(corpusSummary);
  const truthfulnessIssues = countTruthfulnessIssues(corpusSummary);
  const benchmarkCoverage = benchmarkSuite
    ? {
        executed: Number(benchmarkSuite.executedBenchmarks ?? 0),
        total: Number(benchmarkSuite.totalBenchmarks ?? 0),
      }
    : null;

  return {
    generatedAt: corpusSummary?.generatedAt ?? new Date().toISOString(),
    thresholds,
    totals: {
      pass: Number(totals.pass ?? 0),
      repairable: Number(totals.repairable ?? 0),
      blocked: Number(totals.blocked ?? 0),
    },
    readyRate: readyRateFromCorpus(corpusSummary),
    averageValidationScore: averageValidationScoreFromCorpus(corpusSummary),
    firstPaintEvidenceScore:
      benchmarkSuite?.metrics?.firstPaintEvidenceScore?.available &&
      typeof benchmarkSuite.metrics.firstPaintEvidenceScore.value === "number"
        ? benchmarkSuite.metrics.firstPaintEvidenceScore.value
        : null,
    truthfulnessIssues,
    benchmarkCoverage,
    invariantFailures,
    weakestCase,
    weakestTarget: weakestTargetForSnapshot({
      invariantFailures,
      weakestCase,
    }),
  };
}

export function compareChatArtifactParitySnapshots(
  previousSnapshot,
  currentSnapshot,
) {
  if (!previousSnapshot || !currentSnapshot) {
    return null;
  }

  const improvedMetrics = [];
  const regressedMetrics = [];
  const unchangedMetrics = [];

  const compareMetric = (label, previousValue, currentValue, direction) => {
    if (
      typeof previousValue !== "number" ||
      Number.isNaN(previousValue) ||
      typeof currentValue !== "number" ||
      Number.isNaN(currentValue)
    ) {
      return;
    }
    if (currentValue === previousValue) {
      unchangedMetrics.push(label);
      return;
    }
    const improved =
      direction === "higher" ? currentValue > previousValue : currentValue < previousValue;
    if (improved) {
      improvedMetrics.push(label);
    } else {
      regressedMetrics.push(label);
    }
  };

  compareMetric(
    "pass_cases",
    previousSnapshot.totals.pass,
    currentSnapshot.totals.pass,
    "higher",
  );
  compareMetric(
    "repairable_cases",
    previousSnapshot.totals.repairable,
    currentSnapshot.totals.repairable,
    "lower",
  );
  compareMetric(
    "blocked_cases",
    previousSnapshot.totals.blocked,
    currentSnapshot.totals.blocked,
    "lower",
  );
  compareMetric(
    "ready_rate",
    previousSnapshot.readyRate,
    currentSnapshot.readyRate,
    "higher",
  );
  compareMetric(
    "average_validation_score",
    previousSnapshot.averageValidationScore,
    currentSnapshot.averageValidationScore,
    "higher",
  );
  compareMetric(
    "first_paint_evidence_score",
    previousSnapshot.firstPaintEvidenceScore,
    currentSnapshot.firstPaintEvidenceScore,
    "higher",
  );
  compareMetric(
    "truthfulness_issues",
    previousSnapshot.truthfulnessIssues,
    currentSnapshot.truthfulnessIssues,
    "lower",
  );
  compareMetric(
    "invariant_failures",
    previousSnapshot.invariantFailures.length,
    currentSnapshot.invariantFailures.length,
    "lower",
  );

  const keepChange =
    regressedMetrics.length === 0 &&
    (improvedMetrics.length > 0 ||
      currentSnapshot.truthfulnessIssues < previousSnapshot.truthfulnessIssues);

  return {
    improvedMetrics,
    regressedMetrics,
    unchangedMetrics,
    keepChange,
  };
}

function thresholdsSatisfied(snapshot, thresholds) {
  const benchmarkCoverageSatisfied =
    !thresholds.requireFullBenchmarkCoverage ||
    !snapshot.benchmarkCoverage ||
    snapshot.benchmarkCoverage.total === 0 ||
    snapshot.benchmarkCoverage.executed >= snapshot.benchmarkCoverage.total;
  const invariantsSatisfied =
    !thresholds.requireAllParityChecks || snapshot.invariantFailures.length === 0;

  return {
    met:
      snapshot.totals.blocked <= thresholds.maxBlockedCases &&
      snapshot.totals.repairable <= thresholds.maxRepairableCases &&
      snapshot.truthfulnessIssues <= thresholds.maxTruthfulnessIssues &&
      benchmarkCoverageSatisfied &&
      invariantsSatisfied,
    benchmarkCoverageSatisfied,
    invariantsSatisfied,
  };
}

function budgetStatus(ledger, budgets, nowIso) {
  const receiptCount = Array.isArray(ledger?.receipts) ? ledger.receipts.length : 0;
  const firstReceiptCreatedAt =
    receiptCount > 0 && ledger?.receipts?.[0]?.createdAt
      ? Date.parse(ledger.receipts[0].createdAt)
      : Number.NaN;
  const createdAt = Number.isFinite(firstReceiptCreatedAt)
    ? firstReceiptCreatedAt
    : Number.NaN;
  const nowMs = Date.parse(nowIso);
  const elapsedMs =
    Number.isFinite(createdAt) && Number.isFinite(nowMs) ? Math.max(nowMs - createdAt, 0) : 0;

  return {
    receiptCount,
    elapsedMs,
    maxInterventionsReached: receiptCount >= budgets.maxInterventionCount,
    maxWallClockReached: elapsedMs >= budgets.maxWallClockMs,
  };
}

export function selectChatArtifactInterventionFamily(snapshot) {
  if (snapshot?.weakestTarget?.family) {
    return snapshot.weakestTarget.family;
  }
  return familyForWeakestCase(snapshot?.weakestCase ?? null);
}

export function createEmptyChatArtifactParityLedger(options = {}) {
  return {
    version: 1,
    createdAt: options.createdAt ?? new Date().toISOString(),
    budgets: mergedBudgets(options.budgets),
    thresholds: mergedThresholds(options.thresholds),
    receipts: [],
  };
}

export function loadChatArtifactParityLoopLedger(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const ledgerPath =
    options.ledgerPath ??
    path.join(evidenceRoot, DEFAULT_PARITY_LOOP_LEDGER_PATH);
  const existing = readJsonIfExists(ledgerPath);
  if (existing && typeof existing === "object") {
    return {
      ledgerPath,
      ledger: {
        version: Number(existing.version ?? 1),
        createdAt: existing.createdAt ?? new Date().toISOString(),
        budgets: mergedBudgets(existing.budgets),
        thresholds: mergedThresholds(existing.thresholds),
        receipts: Array.isArray(existing.receipts)
          ? existing.receipts.map(normalizeParityReceipt)
          : [],
      },
    };
  }
  return {
    ledgerPath,
    ledger: createEmptyChatArtifactParityLedger({
      createdAt: options.createdAt,
      budgets: options.budgets,
      thresholds: options.thresholds,
    }),
  };
}

export function loadChatArtifactParityCorpusSummary(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const summaryPath =
    options.summaryPath ?? path.join(evidenceRoot, "corpus-summary.json");
  const summary = readJsonIfExists(summaryPath);
  return summary && typeof summary === "object"
    ? { summaryPath, corpusSummary: summary }
    : { summaryPath, corpusSummary: null };
}

export function planChatArtifactParityIteration(options = {}) {
  const nowIso =
    options.now instanceof Date
      ? options.now.toISOString()
      : options.now ?? new Date().toISOString();
  const budgets = mergedBudgets(options.budgets ?? options.ledger?.budgets);
  const thresholds = mergedThresholds(
    options.thresholds ?? options.ledger?.thresholds,
  );
  const snapshot = collectChatArtifactParitySnapshot(options.corpusSummary, {
    thresholds,
  });
  const previousReceipt =
    Array.isArray(options.ledger?.receipts) && options.ledger.receipts.length > 0
      ? options.ledger.receipts[options.ledger.receipts.length - 1]
      : null;
  const comparison = previousReceipt?.snapshot
    ? compareChatArtifactParitySnapshots(previousReceipt.snapshot, snapshot)
    : null;
  const noImprovementStreak = comparison
    ? comparison.keepChange
      ? 0
      : Number(previousReceipt?.noImprovementStreak ?? 0) + 1
    : 0;
  const thresholdState = thresholdsSatisfied(snapshot, thresholds);
  const budget = budgetStatus(options.ledger, budgets, nowIso);
  const interventionFamily = selectChatArtifactInterventionFamily(snapshot);

  let decision = {
    kind: "continue",
    reason: snapshot.weakestTarget
      ? `Address ${snapshot.weakestTarget.label}.`
      : "Advance the next artifact benchmark improvement.",
  };

  if (thresholdState.met) {
    decision = {
      kind: "stop_parity",
      reason: "Parity thresholds are satisfied across retained benchmarks and receipts.",
    };
  } else if (budget.maxInterventionsReached || budget.maxWallClockReached) {
    decision = {
      kind: "stop_budget",
      reason: budget.maxInterventionsReached
        ? "Intervention budget reached."
        : "Wall-clock budget reached.",
    };
  } else if (noImprovementStreak >= budgets.maxNoImprovementStreak) {
    decision = {
      kind: "stop_plateau",
      reason: "No-improvement streak reached the configured plateau threshold.",
    };
  }

  return {
    version: 1,
    createdAt: nowIso,
    budgets,
    thresholds,
    snapshot,
    comparison,
    keepChange: comparison ? comparison.keepChange : true,
    noImprovementStreak,
    selectedInterventionFamily:
      decision.kind === "continue" ? interventionFamily : null,
    allowedInterventionFamilies:
      decision.kind === "continue" ? [interventionFamily] : [],
    weakestTarget: deepClone(snapshot.weakestTarget),
    relevantCaseIds: Array.isArray(snapshot.weakestTarget?.caseIds)
      ? snapshot.weakestTarget.caseIds
      : [],
    requiredReceipts: ["corpus_summary", "parity_loop_receipt"],
    decision,
  };
}

export function writeChatArtifactParityLoopLedger(options = {}) {
  const { ledgerPath, ledger } = loadChatArtifactParityLoopLedger(options);
  const receipt = options.receipt
    ? normalizeParityReceipt(deepClone(options.receipt))
    : planChatArtifactParityIteration({
        corpusSummary: options.corpusSummary,
        ledger,
        now: options.now,
        budgets: options.budgets,
        thresholds: options.thresholds,
      });
  const nextLedger = {
    version: 1,
    createdAt: ledger.createdAt,
    updatedAt: receipt.createdAt,
    budgets: mergedBudgets(options.budgets ?? ledger.budgets),
    thresholds: mergedThresholds(options.thresholds ?? ledger.thresholds),
    receipts: [...(Array.isArray(ledger.receipts) ? ledger.receipts : []), receipt],
  };
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  fs.writeFileSync(ledgerPath, JSON.stringify(nextLedger, null, 2));
  return { ledgerPath, ledger: nextLedger, receipt };
}

export function collectChatArtifactParityLoopView(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const { corpusSummary, summaryPath } = loadChatArtifactParityCorpusSummary({
    repoRoot,
    evidenceRoot,
    summaryPath: options.summaryPath,
  });
  if (!corpusSummary) {
    return null;
  }
  const { ledgerPath, ledger } = loadChatArtifactParityLoopLedger({
    repoRoot,
    evidenceRoot,
    ledgerPath: options.ledgerPath,
  });
  const currentPlan = planChatArtifactParityIteration({
    corpusSummary,
    ledger,
    budgets: options.budgets,
    thresholds: options.thresholds,
    now: options.now,
  });
  const latestReceipt =
    Array.isArray(ledger.receipts) && ledger.receipts.length > 0
      ? ledger.receipts[ledger.receipts.length - 1]
      : null;

  return {
    status: currentPlan.decision.kind === "continue" ? "active" : currentPlan.decision.kind,
    summaryPath,
    ledgerPath,
    receiptCount: Array.isArray(ledger.receipts) ? ledger.receipts.length : 0,
    latestReceipt,
    currentPlan,
  };
}
