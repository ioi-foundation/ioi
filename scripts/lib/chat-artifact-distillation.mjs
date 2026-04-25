import fs from "fs";
import path from "path";

export const DEFAULT_DISTILLATION_LEDGER_PATH = path.join(
  "distillation",
  "ledger.json",
);

const DEFAULT_BENCHMARK_CATALOG_NAME = "benchmark-suite.catalog.json";
const MIN_MATERIAL_SCORE_DELTA = 0.05;

function relativeEvidenceDisplayPath(evidenceRoot, targetPath) {
  if (!targetPath || typeof targetPath !== "string" || !fs.existsSync(targetPath)) {
    return null;
  }
  const relative = path.relative(evidenceRoot, targetPath);
  return relative && !relative.startsWith("..")
    ? relative.split(path.sep).join("/")
    : targetPath;
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

function roundMetric(value, digits = 3) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function average(values) {
  const numeric = values.filter((value) => typeof value === "number" && Number.isFinite(value));
  if (numeric.length === 0) {
    return null;
  }
  return numeric.reduce((sum, value) => sum + value, 0) / numeric.length;
}

function classificationRank(classification) {
  switch (classification) {
    case "pass":
      return 3;
    case "repairable":
      return 2;
    default:
      return 1;
  }
}

function compareEntriesForWinner(left, right) {
  const leftClassification = classificationRank(left?.effectiveClassification ?? left?.classification);
  const rightClassification = classificationRank(
    right?.effectiveClassification ?? right?.classification,
  );
  if (leftClassification !== rightClassification) {
    return rightClassification - leftClassification;
  }
  const leftJudge = left?.validationScore ?? -Infinity;
  const rightJudge = right?.validationScore ?? -Infinity;
  if (leftJudge !== rightJudge) {
    return rightJudge - leftJudge;
  }
  const leftFirstPaint = left?.firstPaintEvidenceScore ?? -Infinity;
  const rightFirstPaint = right?.firstPaintEvidenceScore ?? -Infinity;
  if (leftFirstPaint !== rightFirstPaint) {
    return rightFirstPaint - leftFirstPaint;
  }
  if (Boolean(left?.shimDependent) !== Boolean(right?.shimDependent)) {
    return left?.shimDependent ? 1 : -1;
  }
  const leftSkills = Number(left?.selectedSkillCount ?? 0);
  const rightSkills = Number(right?.selectedSkillCount ?? 0);
  if (leftSkills !== rightSkills) {
    return rightSkills - leftSkills;
  }
  const leftExemplars = Number(left?.retrievedExemplarCount ?? 0);
  const rightExemplars = Number(right?.retrievedExemplarCount ?? 0);
  if (leftExemplars !== rightExemplars) {
    return rightExemplars - leftExemplars;
  }
  if (Boolean(left?.artifactIrPresent) !== Boolean(right?.artifactIrPresent)) {
    return left?.artifactIrPresent ? -1 : 1;
  }
  if (Boolean(left?.blueprintPresent) !== Boolean(right?.blueprintPresent)) {
    return left?.blueprintPresent ? -1 : 1;
  }
  const leftTime = Date.parse(`${left?.dateRoot ?? ""}T00:00:00.000Z`) || 0;
  const rightTime = Date.parse(`${right?.dateRoot ?? ""}T00:00:00.000Z`) || 0;
  if (leftTime !== rightTime) {
    return rightTime - leftTime;
  }
  return String(left?.id ?? "").localeCompare(String(right?.id ?? ""));
}

function entrySummary(entry) {
  return {
    caseId: entry?.id ?? null,
    dateRoot: entry?.dateRoot ?? null,
    renderer: entry?.renderer ?? null,
    classification: entry?.effectiveClassification ?? entry?.classification ?? "blocked",
    validationScore: entry?.validationScore ?? null,
    firstPaintEvidenceScore: entry?.firstPaintEvidenceScore ?? null,
    shimDependent: entry?.shimDependent === true,
    blueprintPresent: entry?.blueprintPresent === true,
    artifactIrPresent: entry?.artifactIrPresent === true,
    selectedSkillCount: Number(entry?.selectedSkillCount ?? 0),
    retrievedExemplarCount: Number(entry?.retrievedExemplarCount ?? 0),
    summaryPath: entry?.summaryPath ?? null,
    strongestContradiction: entry?.strongestContradiction ?? null,
  };
}

function buildStructuralDiff(winner, loser) {
  const reasons = [];
  const targetUpgrades = new Set();
  const classificationDelta =
    classificationRank(winner?.effectiveClassification ?? winner?.classification) -
    classificationRank(loser?.effectiveClassification ?? loser?.classification);
  const validationScoreDelta = roundMetric(
    Number(winner?.validationScore ?? 0) - Number(loser?.validationScore ?? 0),
  );
  const firstPaintEvidenceDelta = roundMetric(
    Number(winner?.firstPaintEvidenceScore ?? 0) -
      Number(loser?.firstPaintEvidenceScore ?? 0),
  );
  const selectedSkillDelta =
    Number(winner?.selectedSkillCount ?? 0) - Number(loser?.selectedSkillCount ?? 0);
  const retrievedExemplarDelta =
    Number(winner?.retrievedExemplarCount ?? 0) -
    Number(loser?.retrievedExemplarCount ?? 0);
  const shimRemoved = loser?.shimDependent === true && winner?.shimDependent === false;
  const blueprintAdded = loser?.blueprintPresent !== true && winner?.blueprintPresent === true;
  const artifactIrAdded =
    loser?.artifactIrPresent !== true && winner?.artifactIrPresent === true;

  if (classificationDelta > 0) {
    reasons.push("classification_improved");
    targetUpgrades.add("validation_calibration_example");
  }
  if (validationScoreDelta != null && validationScoreDelta >= MIN_MATERIAL_SCORE_DELTA) {
    reasons.push("validation_score_gain");
    targetUpgrades.add("validation_calibration_example");
  }
  if (
    firstPaintEvidenceDelta != null &&
    firstPaintEvidenceDelta >= MIN_MATERIAL_SCORE_DELTA
  ) {
    reasons.push("first_paint_evidence_gain");
    targetUpgrades.add("component_pack_upgrade");
  }
  if (shimRemoved) {
    reasons.push("shim_dependency_removed");
    targetUpgrades.add("scaffold_upgrade");
  }
  if (selectedSkillDelta > 0) {
    reasons.push("skill_support_increased");
    targetUpgrades.add("skill_guidance_upgrade");
  }
  if (retrievedExemplarDelta > 0) {
    reasons.push("exemplar_support_increased");
    targetUpgrades.add("taste_memory_default");
  }
  if (blueprintAdded || artifactIrAdded) {
    reasons.push("typed_contract_coverage_improved");
    targetUpgrades.add("ir_compiler_rule");
  }

  return {
    material:
      reasons.length > 0 ||
      classificationDelta > 0 ||
      (validationScoreDelta != null && validationScoreDelta >= MIN_MATERIAL_SCORE_DELTA) ||
      (firstPaintEvidenceDelta != null &&
        firstPaintEvidenceDelta >= MIN_MATERIAL_SCORE_DELTA),
    classificationDelta,
    validationScoreDelta,
    firstPaintEvidenceDelta,
    selectedSkillDelta,
    retrievedExemplarDelta,
    shimRemoved,
    blueprintAdded,
    artifactIrAdded,
    typedReasons: reasons,
    targetUpgrades: Array.from(targetUpgrades),
  };
}

function benchmarkLookup(catalog) {
  const byCaseId = new Map();
  const byBenchmarkId = new Map();
  for (const benchmark of Array.isArray(catalog?.cases) ? catalog.cases : []) {
    byBenchmarkId.set(benchmark.benchmarkId, benchmark);
    for (const caseId of Array.isArray(benchmark.caseBindings) ? benchmark.caseBindings : []) {
      if (!byCaseId.has(caseId)) {
        byCaseId.set(caseId, []);
      }
      byCaseId.get(caseId).push(benchmark);
    }
  }
  return { byCaseId, byBenchmarkId };
}

function groupByCaseHistory(cases) {
  const groups = new Map();
  for (const entry of Array.isArray(cases) ? cases : []) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const caseId = typeof entry.id === "string" ? entry.id : null;
    if (!caseId) {
      continue;
    }
    if (!groups.has(caseId)) {
      groups.set(caseId, []);
    }
    groups.get(caseId).push(entry);
  }
  return groups;
}

function buildProposal({
  sourceKind,
  groupId,
  benchmark,
  winner,
  loser,
  relatedEntries,
}) {
  const diff = buildStructuralDiff(winner, loser);
  if (!diff.material) {
    return null;
  }

  const benchmarkBindings = Array.isArray(benchmark?.caseBindings)
    ? benchmark.caseBindings
    : [];
  const relatedCaseIds = Array.from(
    new Set(
      Array.isArray(relatedEntries)
        ? relatedEntries
            .map((entry) => entry?.id)
            .filter((value) => typeof value === "string")
        : [],
    ),
  );
  const sameRendererPassCount = Array.isArray(relatedEntries)
    ? relatedEntries.filter(
        (entry) =>
          entry?.renderer === winner?.renderer &&
          classificationRank(entry?.effectiveClassification ?? entry?.classification) >= 3,
      ).length
    : 0;

  return {
    proposalId: `${sourceKind}:${groupId}:${winner.id}:${winner.dateRoot}:${loser.id}:${loser.dateRoot}`,
    sourceKind,
    groupId,
    benchmarkId: benchmark?.benchmarkId ?? null,
    benchmarkTitle: benchmark?.title ?? null,
    prompt: benchmark?.prompt ?? null,
    renderer: winner?.renderer ?? loser?.renderer ?? null,
    categories: Array.isArray(benchmark?.categories) ? benchmark.categories : [],
    trackedParityTarget: benchmark?.trackedParityTarget === true,
    targetUpgrades: diff.targetUpgrades,
    typedReasons: diff.typedReasons,
    structuralChanges: {
      classificationDelta: diff.classificationDelta,
      validationScoreDelta: diff.validationScoreDelta,
      firstPaintEvidenceDelta: diff.firstPaintEvidenceDelta,
      selectedSkillDelta: diff.selectedSkillDelta,
      retrievedExemplarDelta: diff.retrievedExemplarDelta,
      shimRemoved: diff.shimRemoved,
      blueprintAdded: diff.blueprintAdded,
      artifactIrAdded: diff.artifactIrAdded,
    },
    before: entrySummary(loser),
    after: entrySummary(winner),
    generalization: {
      relatedCaseIds,
      benchmarkCaseBindings: benchmarkBindings,
      relatedCaseCount: relatedCaseIds.length,
      benchmarkBindingCount: benchmarkBindings.length,
      sameRendererPassCount,
      generalizesAcrossRelatedPrompts:
        benchmarkBindings.length > 1 || relatedCaseIds.length > 1,
    },
    status: "proposed",
    measuredGain: null,
  };
}

export function collectChatArtifactDistillationLedger(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const corpusSummary = options.corpusSummary ?? null;
  const benchmarkCatalog = options.benchmarkCatalog ?? { version: 1, cases: [] };
  const cases = Array.isArray(corpusSummary?.cases) ? corpusSummary.cases : [];
  const { byCaseId } = benchmarkLookup(benchmarkCatalog);
  const proposals = [];
  const dedupe = new Set();

  const caseHistoryGroups = groupByCaseHistory(cases);
  for (const [caseId, entries] of caseHistoryGroups.entries()) {
    if (!Array.isArray(entries) || entries.length < 2) {
      continue;
    }
    const sorted = [...entries].sort(compareEntriesForWinner);
    const winner = sorted[0];
    const loser = sorted[sorted.length - 1];
    if (!winner || !loser || winner === loser) {
      continue;
    }
    const benchmark = byCaseId.get(caseId)?.[0] ?? null;
    const proposal = buildProposal({
      sourceKind: "case_history",
      groupId: caseId,
      benchmark,
      winner,
      loser,
      relatedEntries: entries,
    });
    if (!proposal || dedupe.has(proposal.proposalId)) {
      continue;
    }
    dedupe.add(proposal.proposalId);
    proposals.push(proposal);
  }

  for (const benchmark of Array.isArray(benchmarkCatalog?.cases) ? benchmarkCatalog.cases : []) {
    const benchmarkEntries = cases.filter((entry) =>
      Array.isArray(benchmark.caseBindings) && benchmark.caseBindings.includes(entry?.id),
    );
    const distinctCaseIds = Array.from(
      new Set(
        benchmarkEntries
          .map((entry) => entry?.id)
          .filter((value) => typeof value === "string"),
      ),
    );
    if (distinctCaseIds.length < 2) {
      continue;
    }
    const sorted = [...benchmarkEntries].sort(compareEntriesForWinner);
    const winner = sorted[0];
    const loser = sorted[sorted.length - 1];
    if (!winner || !loser || winner === loser) {
      continue;
    }
    const proposal = buildProposal({
      sourceKind: "benchmark_binding",
      groupId: benchmark.benchmarkId,
      benchmark,
      winner,
      loser,
      relatedEntries: benchmarkEntries,
    });
    if (!proposal || dedupe.has(proposal.proposalId)) {
      continue;
    }
    dedupe.add(proposal.proposalId);
    proposals.push(proposal);
  }

  proposals.sort((left, right) => {
    const leftClassification = Number(left.structuralChanges.classificationDelta ?? 0);
    const rightClassification = Number(right.structuralChanges.classificationDelta ?? 0);
    if (leftClassification !== rightClassification) {
      return rightClassification - leftClassification;
    }
    const leftJudge = Number(left.structuralChanges.validationScoreDelta ?? 0);
    const rightJudge = Number(right.structuralChanges.validationScoreDelta ?? 0);
    if (leftJudge !== rightJudge) {
      return rightJudge - leftJudge;
    }
    const leftFirstPaint = Number(left.structuralChanges.firstPaintEvidenceDelta ?? 0);
    const rightFirstPaint = Number(right.structuralChanges.firstPaintEvidenceDelta ?? 0);
    if (leftFirstPaint !== rightFirstPaint) {
      return rightFirstPaint - leftFirstPaint;
    }
    return String(left.proposalId).localeCompare(String(right.proposalId));
  });

  const applied = proposals.filter((proposal) => proposal.status === "applied");
  const measuredGain = roundMetric(
    average(
      applied
        .map((proposal) => proposal?.measuredGain?.validationScoreDelta)
        .filter((value) => typeof value === "number"),
    ),
  );

  return {
    version: 1,
    generatedAt: options.now ?? new Date().toISOString(),
    source: {
      summaryPath: relativeEvidenceDisplayPath(evidenceRoot, options.summaryPath ?? null),
      benchmarkCatalogPath: relativeEvidenceDisplayPath(
        evidenceRoot,
        options.benchmarkCatalogPath ?? null,
      ),
    },
    proposalCount: proposals.length,
    appliedCount: applied.length,
    measuredGain,
    proposals,
  };
}

export function loadChatArtifactDistillationLedger(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const ledgerPath =
    options.ledgerPath ??
    path.join(evidenceRoot, DEFAULT_DISTILLATION_LEDGER_PATH);
  const ledger = readJsonIfExists(ledgerPath);
  return {
    ledgerPath,
    ledger:
      ledger && typeof ledger === "object"
        ? ledger
        : {
            version: 1,
            generatedAt: null,
            proposalCount: 0,
            appliedCount: 0,
            measuredGain: null,
            proposals: [],
          },
  };
}

export function writeChatArtifactDistillationLedger(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const summaryPath =
    options.summaryPath ?? path.join(evidenceRoot, "corpus-summary.json");
  const benchmarkCatalogPath =
    options.benchmarkCatalogPath ??
    path.join(evidenceRoot, DEFAULT_BENCHMARK_CATALOG_NAME);
  const corpusSummary = options.corpusSummary ?? readJsonIfExists(summaryPath);
  const benchmarkCatalog =
    options.benchmarkCatalog ?? readJsonIfExists(benchmarkCatalogPath) ?? { version: 1, cases: [] };
  const ledger = collectChatArtifactDistillationLedger({
    corpusSummary,
    benchmarkCatalog,
    summaryPath,
    benchmarkCatalogPath,
    now: options.now,
  });
  const ledgerPath =
    options.ledgerPath ??
    path.join(evidenceRoot, DEFAULT_DISTILLATION_LEDGER_PATH);
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2));
  return { ledgerPath, ledger };
}

export function collectChatArtifactDistillationView(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const { ledgerPath, ledger } = loadChatArtifactDistillationLedger({
    repoRoot,
    evidenceRoot,
    ledgerPath: options.ledgerPath,
  });

  return {
    status: Number(ledger.proposalCount ?? 0) > 0 ? "ready_for_distillation" : "idle",
    ledgerPath,
    proposalCount: Number(ledger.proposalCount ?? 0),
    appliedCount: Number(ledger.appliedCount ?? 0),
    measuredGain: ledger.measuredGain ?? null,
    topProposals: Array.isArray(ledger.proposals) ? ledger.proposals.slice(0, 3) : [],
  };
}
