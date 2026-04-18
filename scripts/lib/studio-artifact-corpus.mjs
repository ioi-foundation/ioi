import fs from "fs";
import path from "path";

const AUXILIARY_SEGMENTS = new Set([
  "repeated-run-variation",
  "revision-branch",
  "revision-restore",
]);

const CASE_CLASSIFICATIONS = new Set(["pass", "repairable", "blocked"]);
const VERIFICATION_READY = new Set(["ready", "pass"]);
const VERIFICATION_PARTIAL = new Set(["partial", "repairable"]);
const SHIM_MARKERS = [
  "data-studio-normalized",
  "data-studio-view-switch-repair",
  "data-studio-rollover-repair",
];
const JUDGE_SCORE_DIMENSIONS = [
  "requestFaithfulness",
  "conceptCoverage",
  "interactionRelevance",
  "layoutCoherence",
  "visualHierarchy",
  "completeness",
];
const FIRST_PAINT_EVIDENCE_DIMENSIONS = [
  "interactionRelevance",
  "layoutCoherence",
  "visualHierarchy",
  "completeness",
];
const DEFAULT_BENCHMARK_CATALOG_NAME = "benchmark-suite.catalog.json";
const DEFAULT_PAIRWISE_MATCHES_PATH = ["arena", "pairwise-matches.json"];
const DEFAULT_EXTERNAL_REFERENCES_PATH = ["arena", "external-references.json"];
const DEFAULT_DISTILLATION_LEDGER_PATH = ["distillation", "ledger.json"];
const LANE_ALIASES = new Map([
  ["live-studio-lane", "live_studio"],
  ["contract-lane", "contract"],
  ["fixture-lane", "fixture"],
  ["root", "root"],
]);
const LANE_LABELS = new Map([
  ["live_studio", "Live Studio"],
  ["contract", "Contract"],
  ["fixture", "Fixture"],
  ["root", "Root"],
]);
const RUNTIME_ALIASES = new Map([
  ["fixture_runtime", "fixture"],
  ["real_local_runtime", "local_runtime"],
  ["real_remote_runtime", "remote_runtime"],
  ["studio_runtime", "studio_runtime"],
  ["validation_runtime", "validation_runtime"],
]);
const RUNTIME_LABELS = new Map([
  ["fixture", "Fixture"],
  ["local_runtime", "Local Runtime"],
  ["remote_runtime", "Remote Runtime"],
  ["studio_runtime", "Studio Runtime"],
  ["validation_runtime", "Validation Runtime"],
]);

function readJson(targetPath, fallback = null) {
  if (!targetPath || !fs.existsSync(targetPath)) {
    return fallback;
  }
  try {
    return JSON.parse(fs.readFileSync(targetPath, "utf8"));
  } catch {
    return fallback;
  }
}

function roundMetric(value, digits = 3) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function sanitizeSlug(value, fallback = "unknown") {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized || fallback;
}

function humanizeSlug(value, fallback = "Unknown") {
  const normalized = String(value ?? "")
    .trim()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!normalized) {
    return fallback;
  }
  return normalized.replace(/\b[a-z]/g, (char) => char.toUpperCase());
}

function sanitizeEvidenceLane(value) {
  const normalized = sanitizeSlug(value, "root");
  return LANE_ALIASES.get(String(value ?? "").trim()) ?? LANE_ALIASES.get(normalized) ?? normalized;
}

function labelEvidenceLane(value) {
  const normalized = sanitizeEvidenceLane(value);
  return LANE_LABELS.get(normalized) ?? humanizeSlug(normalized);
}

function sanitizeRuntimeKind(value) {
  const normalized = sanitizeSlug(value, "unknown");
  return RUNTIME_ALIASES.get(String(value ?? "").trim()) ?? RUNTIME_ALIASES.get(normalized) ?? normalized;
}

function labelRuntimeKind(value) {
  if (value == null) {
    return null;
  }
  const normalized = sanitizeRuntimeKind(value);
  return RUNTIME_LABELS.get(normalized) ?? humanizeSlug(normalized);
}

function joinRefSegments(...segments) {
  return segments
    .flatMap((segment) => String(segment ?? "").split(/[\\/]+/))
    .map((segment) => segment.trim())
    .filter(Boolean)
    .join("/");
}

function normalizeEvidenceRef(targetPath) {
  if (typeof targetPath !== "string" || !targetPath.trim()) {
    return null;
  }
  const segments = targetPath
    .split(/[\\/]+/)
    .map((segment) => segment.trim())
    .filter(Boolean);
  if (segments.length === 0) {
    return null;
  }
  if (/^\d{4}-\d{2}-\d{2}$/.test(segments[0]) && segments.length >= 2) {
    segments[1] = sanitizeEvidenceLane(segments[1]);
  }
  return joinRefSegments(...segments);
}

function evidenceRelativeRef(targetPath, evidenceRoot) {
  if (typeof targetPath !== "string" || !targetPath.trim()) {
    return null;
  }
  const relative = path.isAbsolute(targetPath)
    ? path.relative(evidenceRoot, targetPath)
    : targetPath;
  return normalizeEvidenceRef(relative);
}

function caseScopedRef(targetPath, { caseDir, caseRef, evidenceRoot }) {
  if (typeof targetPath !== "string" || !targetPath.trim()) {
    return null;
  }

  if (path.isAbsolute(targetPath)) {
    const relativeToCase = path.relative(caseDir, targetPath);
    if (
      relativeToCase &&
      !relativeToCase.startsWith("..") &&
      !path.isAbsolute(relativeToCase)
    ) {
      return joinRefSegments(caseRef, relativeToCase);
    }
    return evidenceRelativeRef(targetPath, evidenceRoot);
  }

  const normalized = normalizeEvidenceRef(targetPath);
  if (!normalized) {
    return null;
  }
  if (normalized === caseRef || normalized.startsWith(`${caseRef}/`)) {
    return normalized;
  }
  return joinRefSegments(caseRef, normalized);
}

function average(values) {
  const numeric = values.filter((value) => typeof value === "number" && Number.isFinite(value));
  if (numeric.length === 0) {
    return null;
  }
  return numeric.reduce((sum, value) => sum + value, 0) / numeric.length;
}

function normalizedValidationAverage(validation, keys) {
  if (!validation || typeof validation !== "object") {
    return null;
  }
  const score = average(
    keys
      .map((key) => validation?.[key])
      .filter((value) => typeof value === "number" && Number.isFinite(value))
      .map((value) => value / 5),
  );
  return roundMetric(score);
}

function resolveRenderEvaluation(summary) {
  if (summary?.renderEvaluation && typeof summary.renderEvaluation === "object") {
    return summary.renderEvaluation;
  }
  const winningCandidate = Array.isArray(summary?.candidateSetMetadata)
    ? summary.candidateSetMetadata.find((candidate) => candidate?.selected)
    : null;
  if (winningCandidate?.renderEvaluation && typeof winningCandidate.renderEvaluation === "object") {
    return winningCandidate.renderEvaluation;
  }
  return null;
}

function normalizedRenderOverallScore(renderEvaluation) {
  if (
    !renderEvaluation ||
    typeof renderEvaluation !== "object" ||
    renderEvaluation.supported !== true ||
    renderEvaluation.firstPaintCaptured !== true
  ) {
    return null;
  }
  const overallScore = renderEvaluation?.overallScore;
  if (typeof overallScore !== "number" || !Number.isFinite(overallScore)) {
    return null;
  }
  return roundMetric(overallScore / 25);
}

function preservationRatio(left, right) {
  if (!Number.isFinite(left) || !Number.isFinite(right)) {
    return null;
  }
  if (left <= 0 && right <= 0) {
    return 1;
  }
  if (left <= 0 || right <= 0) {
    return 0;
  }
  return Math.min(left, right) / Math.max(left, right);
}

function normalizedResponsivenessScore(renderEvaluation) {
  if (
    !renderEvaluation ||
    typeof renderEvaluation !== "object" ||
    renderEvaluation.supported !== true
  ) {
    return null;
  }
  const captures = Array.isArray(renderEvaluation.captures) ? renderEvaluation.captures : [];
  const desktop = captures.find((capture) => capture?.viewport === "desktop");
  const mobile = captures.find((capture) => capture?.viewport === "mobile");
  if (!desktop || !mobile) {
    return null;
  }

  return roundMetric(
    average([
      1,
      preservationRatio(desktop.visibleElementCount, mobile.visibleElementCount),
      preservationRatio(desktop.visibleTextChars, mobile.visibleTextChars),
      preservationRatio(desktop.interactiveElementCount, mobile.interactiveElementCount),
    ]),
  );
}

function walkCaseSummaryPaths(root) {
  if (!root || !fs.existsSync(root)) {
    return [];
  }

  const discovered = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        pending.push(entryPath);
        continue;
      }
      if (entry.isFile() && entry.name === "case-summary.json") {
        discovered.push(entryPath);
      }
    }
  }

  return discovered.sort();
}

function parseDateRootToTimestampMs(dateRoot) {
  const match = String(dateRoot || "").match(/^(\d{4}-\d{2}-\d{2})/);
  if (!match) {
    return 0;
  }
  const parsed = Date.parse(`${match[1]}T00:00:00.000Z`);
  return Number.isFinite(parsed) ? parsed : 0;
}

function mapVerificationToClassification(status) {
  const normalized = String(status || "").trim().toLowerCase();
  if (VERIFICATION_READY.has(normalized)) {
    return "pass";
  }
  if (VERIFICATION_PARTIAL.has(normalized)) {
    return "repairable";
  }
  if (normalized) {
    return "blocked";
  }
  return "blocked";
}

function normalizeClassification(value, fallback = "blocked") {
  const normalized = String(value || "").trim().toLowerCase();
  return CASE_CLASSIFICATIONS.has(normalized) ? normalized : fallback;
}

function resolveProvenance(summary, which) {
  return (
    summary?.[`${which}Provenance`] ??
    summary?.composeReply?.[`${which}Provenance`] ??
    summary?.verifiedReply?.[`${which}Provenance`] ??
    summary?.manifest?.verification?.[`${which}Provenance`] ??
    summary?.inspect?.inspection?.[`${which}_provenance`] ??
    summary?.inspect?.inspection?.[`${which}Provenance`] ??
    null
  );
}

function resolvePrimaryFile(summary) {
  if (typeof summary?.rendererOutput?.primaryFile === "string") {
    return summary.rendererOutput.primaryFile;
  }
  const manifestFiles = Array.isArray(summary?.manifest?.files) ? summary.manifest.files : [];
  return (
    manifestFiles.find((entry) => entry?.role === "primary")?.path ??
    manifestFiles.find((entry) => typeof entry?.path === "string")?.path ??
    null
  );
}

function hasShimDependency(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    return false;
  }
  try {
    const body = fs.readFileSync(filePath, "utf8");
    return SHIM_MARKERS.some((marker) => body.includes(marker));
  } catch {
    return false;
  }
}

function candidateClassificationCounts(candidateSetMetadata) {
  const counts = { pass: 0, repairable: 0, blocked: 0 };
  for (const candidate of Array.isArray(candidateSetMetadata) ? candidateSetMetadata : []) {
    const classification = normalizeClassification(candidate?.validation?.classification, "");
    if (classification) {
      counts[classification] += 1;
    }
  }
  return counts;
}

function normalizeMetricRate(numerator, denominator) {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) {
    return null;
  }
  return roundMetric(numerator / denominator);
}

function metricReading({
  label,
  value,
  unit = "ratio",
  method,
  available = value != null,
  numerator = null,
  denominator = null,
  supportingBenchmarkIds = [],
}) {
  return {
    label,
    value,
    unit,
    available,
    method,
    numerator,
    denominator,
    supportingBenchmarkIds,
  };
}

function readBenchmarkCatalog(targetPath) {
  const parsed = readJson(targetPath, null);
  if (!parsed || typeof parsed !== "object") {
    return { version: 1, cases: [] };
  }
  return {
    version:
      typeof parsed.version === "number" && Number.isFinite(parsed.version)
        ? parsed.version
        : 1,
    cases: Array.isArray(parsed.cases) ? parsed.cases : [],
  };
}

function normalizeExternalReferences(parsed) {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && typeof parsed === "object" && Array.isArray(parsed.references)) {
    return parsed.references;
  }
  return [];
}

function externalReferenceSummary(externalReferencesPath, evidenceRoot) {
  const parsed = readJson(externalReferencesPath, null);
  const references = normalizeExternalReferences(parsed)
    .filter((entry) => entry && typeof entry === "object")
    .map((entry) => ({
      benchmarkId:
        typeof entry.benchmarkId === "string" ? entry.benchmarkId : "unknown-benchmark",
      participant:
        typeof entry.participant === "string"
          ? entry.participant
          : typeof entry.referenceParticipant === "string"
            ? entry.referenceParticipant
            : "reference:external",
      label:
        typeof entry.label === "string"
          ? entry.label
          : typeof entry.title === "string"
            ? entry.title
            : null,
      artifactPath: evidenceRelativeRef(entry.artifactPath, evidenceRoot),
      summaryPath: evidenceRelativeRef(entry.summaryPath, evidenceRoot),
    }));
  const byBenchmarkId = new Map();
  for (const entry of references) {
    if (!byBenchmarkId.has(entry.benchmarkId)) {
      byBenchmarkId.set(entry.benchmarkId, []);
    }
    byBenchmarkId.get(entry.benchmarkId).push(entry);
  }

  return {
    available: references.length > 0,
    externalReferencesPath: fs.existsSync(externalReferencesPath)
      ? evidenceRelativeRef(externalReferencesPath, evidenceRoot)
      : null,
    count: references.length,
    byBenchmarkId,
  };
}

function normalizePairwiseMatches(parsed) {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && typeof parsed === "object" && Array.isArray(parsed.matches)) {
    return parsed.matches;
  }
  return [];
}

function walkRetainedCorpusSummaryPaths(evidenceRoot) {
  if (!evidenceRoot || !fs.existsSync(evidenceRoot)) {
    return [];
  }

  return fs
    .readdirSync(evidenceRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(evidenceRoot, entry.name, "corpus-summary.json"))
    .filter((targetPath) => fs.existsSync(targetPath))
    .sort();
}

function latestEntriesByCaseId(entries) {
  const byCaseId = new Map();
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (!entry || typeof entry !== "object" || typeof entry.id !== "string") {
      continue;
    }
    const current = byCaseId.get(entry.id);
    if (!current) {
      byCaseId.set(entry.id, entry);
      continue;
    }
    const currentTime = Number(current.sortTimestampMs ?? 0);
    const nextTime = Number(entry.sortTimestampMs ?? 0);
    if (nextTime > currentTime) {
      byCaseId.set(entry.id, entry);
    }
  }
  return byCaseId;
}

function repeatedRunVariationFlow(summary) {
  return (
    summary?.parityChecks?.repeatedRunVariationFlow ??
    summary?.lanes?.liveStudio?.repeatedRunVariationFlow ??
    summary?.repeatedRunVariationFlow ??
    null
  );
}

function classificationScore(classification) {
  switch (String(classification || "").trim().toLowerCase()) {
    case "pass":
      return 1;
    case "repairable":
    case "partial":
      return 0.5;
    case "blocked":
      return 0;
    default:
      return null;
  }
}

function spread(values) {
  const numeric = values.filter((value) => typeof value === "number" && Number.isFinite(value));
  if (numeric.length < 2) {
    return null;
  }
  return Math.max(...numeric) - Math.min(...numeric);
}

function repeatedRunVarianceSummary({
  evidenceRoot,
  entries,
  caseBindingToBenchmarkId,
}) {
  const retainedSummaryPaths = walkRetainedCorpusSummaryPaths(evidenceRoot);
  if (retainedSummaryPaths.length === 0) {
    return {
      available: false,
      value: null,
      supportingBenchmarkIds: [],
      flowCount: 0,
      measurementCount: 0,
      method:
        "requires retained repeated-run corpus summaries with repeatedRunVariationFlow receipts",
    };
  }

  const latestByCaseId = latestEntriesByCaseId(entries);
  const measurements = [];
  const supportingBenchmarkIds = new Set();

  for (const summaryPath of retainedSummaryPaths) {
    const summary = readJson(summaryPath, null);
    const flow = repeatedRunVariationFlow(summary);
    if (!flow || typeof flow !== "object") {
      continue;
    }

    const benchmarkId =
      caseBindingToBenchmarkId.get(flow.sourceCaseId) ??
      caseBindingToBenchmarkId.get(
        Array.isArray(flow.runs) ? flow.runs[0]?.caseId : null,
      ) ??
      null;
    if (benchmarkId) {
      supportingBenchmarkIds.add(benchmarkId);
    }

    const runIds = Array.from(
      new Set(
        [
          flow.sourceCaseId,
          ...(Array.isArray(flow.runs) ? flow.runs.map((run) => run?.caseId) : []),
        ].filter((value) => typeof value === "string" && value.trim()),
      ),
    );
    const runEntries = runIds
      .map((caseId) => latestByCaseId.get(caseId))
      .filter((entry) => entry && typeof entry === "object");
    if (runEntries.length < 2) {
      continue;
    }

    const variance = average(
      [
        spread(runEntries.map((entry) => entry.validationScore)),
        spread(runEntries.map((entry) => entry.firstPaintEvidenceScore)),
        spread(runEntries.map((entry) => entry.screenshotQualityScore)),
        spread(
          runEntries.map((entry) => classificationScore(entry.effectiveClassification)),
        ),
      ].filter((value) => typeof value === "number" && Number.isFinite(value)),
    );
    if (typeof variance === "number" && Number.isFinite(variance)) {
      measurements.push(variance);
    }
  }

  return {
    available: measurements.length > 0,
    value: roundMetric(average(measurements)),
    supportingBenchmarkIds: Array.from(supportingBenchmarkIds).sort(),
    flowCount: retainedSummaryPaths.length,
    measurementCount: measurements.length,
    method:
      "mean spread across validation, first-paint, render-eval, and classification scores for retained repeated-run variation receipts",
  };
}

function eloSummaryFromPairwiseMatches(pairwiseMatchesPath, evidenceRoot) {
  const parsed = readJson(pairwiseMatchesPath, null);
  const matches = normalizePairwiseMatches(parsed)
    .filter((match) => match && typeof match === "object")
    .map((match) => ({
      benchmarkId:
        typeof match.benchmarkId === "string" ? match.benchmarkId : "unknown",
      leftParticipant:
        typeof match.leftParticipant === "string" ? match.leftParticipant : null,
      rightParticipant:
        typeof match.rightParticipant === "string" ? match.rightParticipant : null,
      winner: typeof match.winner === "string" ? match.winner : "draw",
      externalReferenceParticipant:
        typeof match.externalReferenceParticipant === "string"
          ? match.externalReferenceParticipant
          : null,
      blind: match.blind !== false,
    }))
    .filter((match) => match.leftParticipant && match.rightParticipant);

  if (matches.length === 0) {
    return {
      available: false,
      pairwiseMatchesPath: fs.existsSync(pairwiseMatchesPath)
        ? evidenceRelativeRef(pairwiseMatchesPath, evidenceRoot)
        : null,
      matchCount: 0,
      participantCount: 0,
      ratings: [],
      blindMatchCount: 0,
      winRateVsExternalReference: null,
    };
  }

  const K_FACTOR = 24;
  const ratings = new Map();
  const records = new Map();
  const ensureParticipant = (participant) => {
    if (!ratings.has(participant)) {
      ratings.set(participant, 1500);
      records.set(participant, { participant, wins: 0, losses: 0, draws: 0, matches: 0 });
    }
    return records.get(participant);
  };

  let externalMatches = 0;
  let externalWins = 0;

  for (const match of matches) {
    const left = match.leftParticipant;
    const right = match.rightParticipant;
    const leftRecord = ensureParticipant(left);
    const rightRecord = ensureParticipant(right);
    const leftRating = ratings.get(left);
    const rightRating = ratings.get(right);
    const expectedLeft = 1 / (1 + 10 ** ((rightRating - leftRating) / 400));
    const expectedRight = 1 - expectedLeft;
    let actualLeft = 0.5;
    let actualRight = 0.5;
    if (match.winner === "left") {
      actualLeft = 1;
      actualRight = 0;
      leftRecord.wins += 1;
      rightRecord.losses += 1;
    } else if (match.winner === "right") {
      actualLeft = 0;
      actualRight = 1;
      leftRecord.losses += 1;
      rightRecord.wins += 1;
    } else {
      leftRecord.draws += 1;
      rightRecord.draws += 1;
    }
    leftRecord.matches += 1;
    rightRecord.matches += 1;
    ratings.set(left, leftRating + K_FACTOR * (actualLeft - expectedLeft));
    ratings.set(right, rightRating + K_FACTOR * (actualRight - expectedRight));

    if (match.externalReferenceParticipant) {
      externalMatches += 1;
      const winnerParticipant =
        match.winner === "left"
          ? left
          : match.winner === "right"
            ? right
            : null;
      if (
        winnerParticipant &&
        winnerParticipant !== match.externalReferenceParticipant
      ) {
        externalWins += 1;
      }
    }
  }

  return {
    available: true,
    pairwiseMatchesPath: evidenceRelativeRef(pairwiseMatchesPath, evidenceRoot),
    matchCount: matches.length,
    participantCount: ratings.size,
    blindMatchCount: matches.filter((match) => match.blind).length,
    winRateVsExternalReference:
      externalMatches > 0 ? roundMetric(externalWins / externalMatches) : null,
    ratings: Array.from(records.values())
      .map((record) => ({
        ...record,
        rating: roundMetric(ratings.get(record.participant), 1),
      }))
      .sort((left, right) => right.rating - left.rating || left.participant.localeCompare(right.participant)),
  };
}

function summarizeDistillationLedger(distillationLedgerPath, evidenceRoot) {
  const parsed = readJson(distillationLedgerPath, null);
  const proposals = Array.isArray(parsed?.proposals)
    ? parsed.proposals.filter((proposal) => proposal && typeof proposal === "object")
    : [];
  const applied = proposals.filter((proposal) => proposal.status === "applied");
  const measuredGains = applied
    .map((proposal) => proposal?.measuredGain?.validationScoreDelta)
    .filter((value) => typeof value === "number" && Number.isFinite(value));

  return {
    available: proposals.length > 0,
    ledgerPath: fs.existsSync(distillationLedgerPath)
      ? evidenceRelativeRef(distillationLedgerPath, evidenceRoot)
      : null,
    proposalCount: proposals.length,
    appliedCount: applied.length,
    measuredGain: roundMetric(average(measuredGains)),
    targetUpgrades: Array.from(
      proposals.reduce((acc, proposal) => {
        for (const target of Array.isArray(proposal.targetUpgrades)
          ? proposal.targetUpgrades
          : []) {
          if (typeof target === "string" && target.trim()) {
            acc.add(target);
          }
        }
        return acc;
      }, new Set()),
    ).sort(),
  };
}

function summarizeTotals(entries) {
  const totals = {
    caseCount: 0,
    passCount: 0,
    repairableCount: 0,
    blockedCount: 0,
    readyCount: 0,
    partialCount: 0,
    blockedVerificationCount: 0,
    shimDependentCount: 0,
    fixtureRuntimeCount: 0,
    fullStudioPathCount: 0,
    fallbackUsedCount: 0,
  };

  for (const entry of entries) {
    totals.caseCount += 1;
    totals[`${entry.effectiveClassification}Count`] += 1;
    if (VERIFICATION_READY.has(entry.verificationStatus)) {
      totals.readyCount += 1;
    } else if (VERIFICATION_PARTIAL.has(entry.verificationStatus)) {
      totals.partialCount += 1;
    } else {
      totals.blockedVerificationCount += 1;
    }
    if (entry.shimDependent) {
      totals.shimDependentCount += 1;
    }
    if (entry.productionProvenanceKind === "fixture") {
      totals.fixtureRuntimeCount += 1;
    }
    if (entry.fullStudioPath) {
      totals.fullStudioPathCount += 1;
    }
    if (entry.fallbackUsed) {
      totals.fallbackUsedCount += 1;
    }
  }

  return totals;
}

function buildIndexedEntry(caseSummaryPath, evidenceRoot) {
  const summary = readJson(caseSummaryPath, null);
  if (!summary || typeof summary !== "object") {
    return null;
  }

  const relativeSegments = path.relative(evidenceRoot, caseSummaryPath).split(path.sep);
  const dateRoot = relativeSegments[0] ?? "unknown";
  const caseId = relativeSegments[relativeSegments.length - 2] ?? summary.id ?? "unknown";
  const caseDir = path.dirname(caseSummaryPath);
  const rawLane = relativeSegments.length >= 4 ? relativeSegments[1] : "root";
  const lane = sanitizeEvidenceLane(rawLane);
  const laneLabel = labelEvidenceLane(lane);
  const intermediateSegments = relativeSegments.slice(2, -2);
  const auxiliarySegments = intermediateSegments.filter((segment) =>
    AUXILIARY_SEGMENTS.has(segment)
  );
  const isAuxiliary = auxiliarySegments.length > 0;
  const caseRef = joinRefSegments(dateRoot, lane, ...auxiliarySegments, caseId);
  const inspection = summary?.inspect?.inspection ?? summary?.inspect ?? {};
  const routeArtifact = summary?.route?.artifact ?? {};
  const manifest = summary?.manifest ?? {};
  const verificationStatus = String(
    inspection?.verification_status ??
      inspection?.verificationStatus ??
      manifest?.verification?.status ??
      summary?.verifiedReply?.status ??
      "",
  )
    .trim()
    .toLowerCase();
  const lifecycleState = String(
    inspection?.lifecycle_state ??
      inspection?.lifecycleState ??
      manifest?.verification?.lifecycleState ??
      summary?.verifiedReply?.lifecycleState ??
      "",
  )
    .trim()
    .toLowerCase();
  const primaryFile = resolvePrimaryFile(summary);
  const artifactDirPath =
    typeof summary?.artifactDir === "string" ? summary.artifactDir : path.join(caseDir, "artifact");
  const primaryArtifactFsPath = primaryFile ? path.join(artifactDirPath, primaryFile) : null;
  const materializedPrimaryFsPath = primaryFile
    ? path.join(caseDir, "materialized", primaryFile)
    : null;
  const shimDependent =
    hasShimDependency(primaryArtifactFsPath) || hasShimDependency(materializedPrimaryFsPath);
  const candidateCounts = candidateClassificationCounts(summary?.candidateSetMetadata);
  const validation = summary?.validation && typeof summary.validation === "object" ? summary.validation : null;
  const renderEvaluation = resolveRenderEvaluation(summary);
  const validationClassification = normalizeClassification(summary?.validation?.classification, "");
  const effectiveClassification = validationClassification
    ? validationClassification
    : normalizeClassification(
        summary?.classification,
        mapVerificationToClassification(verificationStatus),
      );
  const productionProvenance = resolveProvenance(summary, "production");
  const acceptanceProvenance = resolveProvenance(summary, "acceptance");
  const productionProvenanceKind =
    typeof productionProvenance?.kind === "string"
      ? sanitizeRuntimeKind(productionProvenance.kind)
      : null;
  const acceptanceProvenanceKind =
    typeof acceptanceProvenance?.kind === "string"
      ? sanitizeRuntimeKind(acceptanceProvenance.kind)
      : null;
  const outputOrigin =
    typeof summary?.outputOrigin === "string"
      ? sanitizeRuntimeKind(summary.outputOrigin)
      : null;
  const winningCandidate = Array.isArray(summary?.candidateSetMetadata)
    ? summary.candidateSetMetadata.find((candidate) => candidate?.selected)
    : null;
  const summaryStats = fs.statSync(caseSummaryPath);
  const sortTimestampMs = Math.max(parseDateRootToTimestampMs(dateRoot), summaryStats.mtimeMs || 0);

  return {
    id: typeof summary?.id === "string" ? summary.id : caseId,
    prompt: typeof summary?.prompt === "string" ? summary.prompt : "",
    dateRoot,
    lane,
    laneLabel,
    auxiliarySegments,
    isAuxiliary,
    caseDir: caseRef,
    summaryPath: caseScopedRef(caseSummaryPath, { caseDir, caseRef, evidenceRoot }),
    artifactDir: caseScopedRef(artifactDirPath, { caseDir, caseRef, evidenceRoot }),
    manifestPath: caseScopedRef(
      typeof summary?.manifestPath === "string"
        ? summary.manifestPath
        : path.join(artifactDirPath, "artifact-manifest.json"),
      { caseDir, caseRef, evidenceRoot },
    ),
    routePath: caseScopedRef(path.join(caseDir, "route.json"), {
      caseDir,
      caseRef,
      evidenceRoot,
    }),
    validationPath: caseScopedRef(path.join(caseDir, "validation.json"), {
      caseDir,
      caseRef,
      evidenceRoot,
    }),
    inspectPath: caseScopedRef(path.join(caseDir, "inspect.json"), {
      caseDir,
      caseRef,
      evidenceRoot,
    }),
    generationPath: caseScopedRef(path.join(artifactDirPath, "generation.json"), {
      caseDir,
      caseRef,
      evidenceRoot,
    }),
    materializedReadmePath: caseScopedRef(path.join(caseDir, "materialized", "README.md"), {
      caseDir,
      caseRef,
      evidenceRoot,
    }),
    capturePaths: Array.isArray(summary?.rendererOutput?.capturePaths)
      ? summary.rendererOutput.capturePaths
          .map((capturePath) => caseScopedRef(capturePath, { caseDir, caseRef, evidenceRoot }))
          .filter(Boolean)
      : [],
    renderer: String(
      inspection?.renderer ?? manifest?.renderer ?? routeArtifact?.renderer ?? "unknown",
    ).trim(),
    artifactClass: String(
      inspection?.artifact_class ??
        inspection?.artifactClass ??
        manifest?.artifactClass ??
        routeArtifact?.artifactClass ??
        "unknown",
    ).trim(),
    verificationStatus,
    lifecycleState,
    classification: normalizeClassification(summary?.classification, effectiveClassification),
    effectiveClassification,
    candidateCount: Array.isArray(summary?.candidateSetMetadata)
      ? summary.candidateSetMetadata.length
      : 0,
    passCandidateCount: candidateCounts.pass,
    repairableCandidateCount: candidateCounts.repairable,
    blockedCandidateCount: candidateCounts.blocked,
    briefPresent: Boolean(summary?.artifactBrief && typeof summary.artifactBrief === "object"),
    blueprintPresent: Boolean(summary?.blueprint && typeof summary.blueprint === "object"),
    artifactIrPresent: Boolean(summary?.artifactIr && typeof summary.artifactIr === "object"),
    scaffoldFamily:
      typeof summary?.blueprint?.scaffoldFamily === "string"
        ? summary.blueprint.scaffoldFamily
        : null,
    componentFamilies: Array.isArray(summary?.blueprint?.componentPlan)
      ? Array.from(
          new Set(
            summary.blueprint.componentPlan
              .map((component) => component?.componentFamily)
              .filter((value) => typeof value === "string" && value.trim()),
          ),
        )
      : [],
    selectedSkillCount: Array.isArray(summary?.selectedSkills) ? summary.selectedSkills.length : 0,
    selectedSkillNames: Array.isArray(summary?.selectedSkills)
      ? summary.selectedSkills
          .map((skill) => skill?.name)
          .filter((value) => typeof value === "string" && value.trim())
      : [],
    retrievedExemplarCount: Array.isArray(summary?.retrievedExemplars)
      ? summary.retrievedExemplars.length
      : 0,
    validationPresent: Boolean(validation),
    validationScore: normalizedValidationAverage(validation, JUDGE_SCORE_DIMENSIONS),
    firstPaintEvidenceScore: normalizedValidationAverage(validation, FIRST_PAINT_EVIDENCE_DIMENSIONS),
    renderEvaluationPresent: Boolean(renderEvaluation),
    screenshotQualityScore: normalizedRenderOverallScore(renderEvaluation),
    responsivenessScore: normalizedResponsivenessScore(renderEvaluation),
    winningCandidateId:
      typeof summary?.winningCandidateId === "string" ? summary.winningCandidateId : null,
    winningCandidateRationale:
      typeof summary?.winningCandidateRationale === "string"
        ? summary.winningCandidateRationale
        : null,
    winningModel: null,
    strongestContradiction:
      summary?.validation?.strongestContradiction ??
      summary?.strongestContradiction ??
      summary?.manifest?.verification?.failure?.message ??
      null,
    shimDependent,
    primaryFile,
    primaryArtifactPath: caseScopedRef(primaryArtifactFsPath, {
      caseDir,
      caseRef,
      evidenceRoot,
    }),
    materializedPrimaryPath: caseScopedRef(materializedPrimaryFsPath, {
      caseDir,
      caseRef,
      evidenceRoot,
    }),
    proofPath:
      typeof summary?.proofPath === "string"
        ? caseScopedRef(summary.proofPath, { caseDir, caseRef, evidenceRoot })
        : null,
    fullStudioPath: summary?.fullStudioPath === true,
    fallbackUsed: summary?.fallbackUsed === true,
    outputOrigin,
    outputOriginLabel: labelRuntimeKind(outputOrigin),
    productionProvenanceKind,
    productionRuntimeLabel: labelRuntimeKind(productionProvenanceKind),
    productionModel: null,
    acceptanceProvenanceKind,
    acceptanceRuntimeLabel: labelRuntimeKind(acceptanceProvenanceKind),
    acceptanceModel: null,
    sortTimestampMs,
  };
}

function resolveBenchmarkCaseExecution(benchmarkCase, cases) {
  const requestedBindings = Array.isArray(benchmarkCase?.caseBindings)
    ? benchmarkCase.caseBindings.filter((value) => typeof value === "string" && value.trim())
    : [];
  for (const caseId of requestedBindings) {
    const match = cases.find((entry) => entry.id === caseId);
    if (match) {
      return match;
    }
  }
  return null;
}

export function collectStudioArtifactBenchmarkSuite(options = {}) {
  const repoRoot =
    options.repoRoot ??
    path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "studio-artifact-surface");
  const cases =
    options.cases ??
    walkCaseSummaryPaths(evidenceRoot)
      .map((caseSummaryPath) => buildIndexedEntry(caseSummaryPath, evidenceRoot))
      .filter(Boolean)
      .sort(
        (left, right) =>
          right.sortTimestampMs - left.sortTimestampMs ||
          left.id.localeCompare(right.id),
      )
      .filter((entry) => !entry.isAuxiliary);
  const allEntries = Array.isArray(options.allEntries) ? options.allEntries : cases;
  const catalogPath =
    options.benchmarkCatalogPath ??
    path.join(evidenceRoot, DEFAULT_BENCHMARK_CATALOG_NAME);
  const pairwiseMatchesPath =
    options.pairwiseMatchesPath ??
    path.join(evidenceRoot, ...DEFAULT_PAIRWISE_MATCHES_PATH);
  const externalReferencesPath =
    options.externalReferencesPath ??
    path.join(evidenceRoot, ...DEFAULT_EXTERNAL_REFERENCES_PATH);
  const distillationLedgerPath =
    options.distillationLedgerPath ??
    path.join(evidenceRoot, ...DEFAULT_DISTILLATION_LEDGER_PATH);
  const catalog = readBenchmarkCatalog(catalogPath);
  const caseBindingToBenchmarkId = new Map();
  for (const benchmarkCase of catalog.cases) {
    if (
      !benchmarkCase ||
      typeof benchmarkCase !== "object" ||
      typeof benchmarkCase.benchmarkId !== "string"
    ) {
      continue;
    }
    for (const binding of Array.isArray(benchmarkCase.caseBindings)
      ? benchmarkCase.caseBindings
      : []) {
      if (typeof binding === "string" && binding.trim()) {
        caseBindingToBenchmarkId.set(binding, benchmarkCase.benchmarkId);
      }
    }
  }
  const externalReferences = externalReferenceSummary(externalReferencesPath, evidenceRoot);
  const benchmarkCases = catalog.cases.map((benchmarkCase) => {
    const executedCase = resolveBenchmarkCaseExecution(benchmarkCase, cases);
    const benchmarkId =
      typeof benchmarkCase.benchmarkId === "string"
        ? benchmarkCase.benchmarkId
        : "unknown-benchmark";
    const benchmarkExternalReferences =
      externalReferences.byBenchmarkId.get(benchmarkId) ?? [];
    return {
      benchmarkId,
      title:
        typeof benchmarkCase.title === "string"
          ? benchmarkCase.title
          : "Untitled benchmark case",
      prompt: typeof benchmarkCase.prompt === "string" ? benchmarkCase.prompt : "",
      outcomeRequest:
        benchmarkCase.outcomeRequest && typeof benchmarkCase.outcomeRequest === "object"
          ? benchmarkCase.outcomeRequest
          : null,
      categories: Array.isArray(benchmarkCase.categories)
        ? benchmarkCase.categories.filter((value) => typeof value === "string")
        : [],
      caseBindings: Array.isArray(benchmarkCase.caseBindings)
        ? benchmarkCase.caseBindings.filter((value) => typeof value === "string")
        : [],
      requiredInteractionContracts: Array.isArray(
        benchmarkCase.requiredInteractionContracts,
      )
        ? benchmarkCase.requiredInteractionContracts.filter(
            (value) => typeof value === "string",
          )
        : [],
      goldenEvaluationCriteria: Array.isArray(benchmarkCase.goldenEvaluationCriteria)
        ? benchmarkCase.goldenEvaluationCriteria.filter(
            (value) => typeof value === "string",
          )
        : [],
      trackedParityTarget: benchmarkCase.trackedParityTarget === true,
      externalReferenceCount: benchmarkExternalReferences.length,
      externalReferenceParticipants: benchmarkExternalReferences.map(
        (entry) => entry.participant,
      ),
      referenceMode:
        typeof benchmarkCase.referenceMode === "string"
          ? benchmarkCase.referenceMode
          : "none",
      caseAvailable: Boolean(executedCase),
      matchedCaseId: executedCase?.id ?? null,
      matchedRunId: executedCase ? `${executedCase.dateRoot}:${executedCase.lane}` : null,
      matchedSummaryPath: executedCase?.summaryPath ?? null,
      matchedCaseDir: executedCase?.caseDir ?? null,
      matchedRenderer: executedCase?.renderer ?? null,
      matchedArtifactClass: executedCase?.artifactClass ?? null,
      matchedVerificationStatus: executedCase?.verificationStatus ?? null,
      matchedLifecycleState: executedCase?.lifecycleState ?? null,
      matchedClassification: executedCase?.effectiveClassification ?? null,
      capturePaths: executedCase?.capturePaths ?? [],
      shimDependent:
        typeof executedCase?.shimDependent === "boolean" ? executedCase.shimDependent : null,
      validationScore: executedCase?.validationScore ?? null,
      firstPaintEvidenceScore: executedCase?.firstPaintEvidenceScore ?? null,
      iterationsToClear:
        typeof executedCase?.candidateCount === "number" ? executedCase.candidateCount : null,
      wallClockTimeToReadyMs: null,
      screenshotQualityScore: executedCase?.screenshotQualityScore ?? null,
      responsivenessScore: executedCase?.responsivenessScore ?? null,
      motionQualityScore: null,
      blueprintPresent: executedCase?.blueprintPresent === true,
      artifactIrPresent: executedCase?.artifactIrPresent === true,
      briefPresent: executedCase?.briefPresent === true,
      selectedSkillCount:
        typeof executedCase?.selectedSkillCount === "number"
          ? executedCase.selectedSkillCount
          : 0,
      retrievedExemplarCount:
        typeof executedCase?.retrievedExemplarCount === "number"
          ? executedCase.retrievedExemplarCount
          : 0,
    };
  });

  const executedBenchmarks = benchmarkCases.filter((entry) => entry.caseAvailable);
  const supportingBenchmarkIds = executedBenchmarks.map((entry) => entry.benchmarkId);
  const readyCount = executedBenchmarks.filter((entry) =>
    ["ready", "pass"].includes(String(entry.matchedVerificationStatus || "").toLowerCase()),
  ).length;
  const blockedCount = executedBenchmarks.filter((entry) => entry.matchedClassification === "blocked")
    .length;
  const shimRequiredCount = executedBenchmarks.filter((entry) => entry.shimDependent === true).length;
  const arena = eloSummaryFromPairwiseMatches(pairwiseMatchesPath, evidenceRoot);
  const distillation = summarizeDistillationLedger(distillationLedgerPath, evidenceRoot);
  const repeatedRunVariance = repeatedRunVarianceSummary({
    evidenceRoot,
    entries: allEntries,
    caseBindingToBenchmarkId,
  });

  return {
    catalogVersion: catalog.version,
    catalogPath: fs.existsSync(catalogPath) ? catalogPath : null,
    totalBenchmarks: benchmarkCases.length,
    executedBenchmarks: executedBenchmarks.length,
    missingBenchmarks: benchmarkCases.length - executedBenchmarks.length,
    parityTargets: benchmarkCases
      .filter((entry) => entry.trackedParityTarget)
      .map((entry) => entry.benchmarkId),
    metrics: {
      readyRate: metricReading({
        label: "Ready rate",
        value: normalizeMetricRate(readyCount, executedBenchmarks.length),
        method: "share of benchmark cases whose surfaced verification cleared to ready/pass",
        numerator: readyCount,
        denominator: executedBenchmarks.length,
        supportingBenchmarkIds,
      }),
      blockedRate: metricReading({
        label: "Blocked rate",
        value: normalizeMetricRate(blockedCount, executedBenchmarks.length),
        method: "share of benchmark cases whose effective classification remained blocked",
        numerator: blockedCount,
        denominator: executedBenchmarks.length,
        supportingBenchmarkIds,
      }),
      shimRequiredRate: metricReading({
        label: "Shim-required rate",
        value: normalizeMetricRate(shimRequiredCount, executedBenchmarks.length),
        method: "share of executed benchmark cases that still relied on Studio normalization repair shims",
        numerator: shimRequiredCount,
        denominator: executedBenchmarks.length,
        supportingBenchmarkIds: executedBenchmarks
          .filter((entry) => entry.shimDependent === true)
          .map((entry) => entry.benchmarkId),
      }),
      averageValidationScore: metricReading({
        label: "Average validation score",
        value: roundMetric(average(executedBenchmarks.map((entry) => entry.validationScore))),
        unit: "normalized_score",
        method: "mean of the six structured acceptance dimensions normalized to the 0-1 range",
        supportingBenchmarkIds: executedBenchmarks
          .filter((entry) => entry.validationScore != null)
          .map((entry) => entry.benchmarkId),
      }),
      firstPaintEvidenceScore: metricReading({
        label: "First-paint evidence score",
        value: roundMetric(
          average(executedBenchmarks.map((entry) => entry.firstPaintEvidenceScore)),
        ),
        unit: "normalized_score",
        method: "mean of interaction relevance, layout coherence, visual hierarchy, and completeness normalized to the 0-1 range",
        supportingBenchmarkIds: executedBenchmarks
          .filter((entry) => entry.firstPaintEvidenceScore != null)
          .map((entry) => entry.benchmarkId),
      }),
      iterationsToClear: metricReading({
        label: "Iterations to clear",
        value: roundMetric(average(executedBenchmarks.map((entry) => entry.iterationsToClear))),
        unit: "candidate_count",
        method: "mean candidate count observed in benchmark evidence as the current bounded search-depth proxy",
        supportingBenchmarkIds: executedBenchmarks
          .filter((entry) => entry.iterationsToClear != null)
          .map((entry) => entry.benchmarkId),
      }),
      wallClockTimeToReadyMs: metricReading({
        label: "Wall-clock time to ready",
        value: null,
        unit: "ms",
        method: "reserved for runtime timing receipts once artifact generation emits wall-clock timing directly",
        available: false,
      }),
      humanPreferenceScore: metricReading({
        label: "Human preference score",
        value: arena.winRateVsExternalReference,
        unit: "ratio",
        method: "blind pairwise win rate against externally supplied references when arena evidence is present",
        available: arena.available && arena.winRateVsExternalReference != null,
      }),
      screenshotQualityScore: metricReading({
        label: "Screenshot quality score",
        value: roundMetric(
          average(executedBenchmarks.map((entry) => entry.screenshotQualityScore)),
        ),
        unit: "normalized_score",
        method: "mean normalized overall render-evaluation score across executed benchmarks with first-paint screenshot receipts",
        available: executedBenchmarks.some((entry) => entry.screenshotQualityScore != null),
        supportingBenchmarkIds: executedBenchmarks
          .filter((entry) => entry.screenshotQualityScore != null)
          .map((entry) => entry.benchmarkId),
      }),
      responsivenessScore: metricReading({
        label: "Responsiveness score",
        value: roundMetric(
          average(executedBenchmarks.map((entry) => entry.responsivenessScore)),
        ),
        unit: "normalized_score",
        method: "mean desktop/mobile structural preservation ratio derived from render-evaluation capture receipts",
        available: executedBenchmarks.some((entry) => entry.responsivenessScore != null),
        supportingBenchmarkIds: executedBenchmarks
          .filter((entry) => entry.responsivenessScore != null)
          .map((entry) => entry.benchmarkId),
      }),
      motionQualityScore: metricReading({
        label: "Motion quality score",
        value: null,
        unit: "normalized_score",
        method: "reserved for motion-aware render evaluation once animation capture receipts are recorded",
        available: false,
      }),
      varianceAcrossRepeatedRuns: metricReading({
        label: "Variance across repeated runs",
        value: repeatedRunVariance.value,
        unit: "normalized_score",
        method: repeatedRunVariance.method,
        available: repeatedRunVariance.available,
        supportingBenchmarkIds: repeatedRunVariance.supportingBenchmarkIds,
      }),
      distillationGain: metricReading({
        label: "Distillation gain",
        value: distillation.measuredGain,
        unit: "delta",
        method: "mean retained validation-score delta across applied distillation upgrades once winning runs are folded back into the default stack",
        available: distillation.appliedCount > 0 && distillation.measuredGain != null,
      }),
    },
    arena,
    externalReferences: {
      available: externalReferences.available,
      path: externalReferences.externalReferencesPath,
      count: externalReferences.count,
      benchmarkCount: Array.from(externalReferences.byBenchmarkId.keys()).length,
    },
    distillation,
    cases: benchmarkCases,
  };
}

export function collectStudioArtifactCorpusIndex(options = {}) {
  const repoRoot =
    options.repoRoot ??
    path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "studio-artifact-surface");
  const entries = walkCaseSummaryPaths(evidenceRoot)
    .map((caseSummaryPath) => buildIndexedEntry(caseSummaryPath, evidenceRoot))
    .filter(Boolean)
    .sort(
      (left, right) =>
        right.sortTimestampMs - left.sortTimestampMs ||
        left.id.localeCompare(right.id),
    );
  const cases = entries.filter((entry) => !entry.isAuxiliary);
  const auxiliaryCases = entries.filter((entry) => entry.isAuxiliary);
  const dateRoots = Array.from(
    cases.reduce((acc, entry) => {
      const current = acc.get(entry.dateRoot) ?? [];
      current.push(entry);
      acc.set(entry.dateRoot, current);
      return acc;
    }, new Map()),
  )
    .map(([dateRoot, dateCases]) => ({
      dateRoot,
      totals: summarizeTotals(dateCases),
    }))
    .sort((left, right) => right.dateRoot.localeCompare(left.dateRoot));

  return {
    generatedAt: new Date().toISOString(),
    repoRoot,
    evidenceRoot,
    totals: summarizeTotals(cases),
    cases,
    auxiliaryCases,
    dateRoots,
    benchmarkSuite: collectStudioArtifactBenchmarkSuite({
      repoRoot,
      evidenceRoot,
      cases,
      allEntries: entries,
      benchmarkCatalogPath: options.benchmarkCatalogPath,
      pairwiseMatchesPath: options.pairwiseMatchesPath,
      distillationLedgerPath: options.distillationLedgerPath,
    }),
  };
}

export function writeStudioArtifactCorpusIndex(options = {}) {
  const summary = collectStudioArtifactCorpusIndex(options);
  const outputPath =
    options.outputPath ?? path.join(summary.evidenceRoot, "corpus-summary.json");
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(summary, null, 2));
  return { outputPath, summary };
}
