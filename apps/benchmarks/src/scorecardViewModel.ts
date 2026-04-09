export type MatrixBadgeTone = "neutral" | "accent" | "good" | "warn" | "danger";
export type ScorecardNoteTone = "up" | "down" | "flat";

export type DeploymentProfileId =
  | "local_cpu_consumer"
  | "local_gpu_8gb_class"
  | "local_gpu_16gb_class"
  | "local_workstation"
  | "hybrid_privacy_preserving"
  | "blind_cloud_standard"
  | "blind_cloud_premium";

export type ScorecardMatrixInput = {
  status: string;
  generatedAt: string | null;
  runAbortReason?: string | null;
  decision: {
    outcome: string;
    summary: string;
    leaderPresetId: string | null;
    artifactLeaderPresetId: string | null;
    missingCoverage: string[];
  };
  scorecardSchema: {
    version?: number;
    categories: Array<{
      id: string;
      label: string;
      decisionWeight?: string;
      requiredForPromotion: boolean;
      metrics: string[];
    }>;
  };
  deploymentDecisions?: Array<{
    deploymentProfile: DeploymentProfileId;
    label: string;
    trustPosture: string;
    state: string;
    defaultPresetId: string | null;
    leaderPresetId: string | null;
    challengerPresetId: string | null;
    coverageGaps: string[];
    requiredCategoryIds: string[];
    summary: string;
  }>;
  plannedPresetCount?: number;
  summarizedPresetCount?: number;
  fullyCompletedPresetCount?: number;
  comparedPresetCount: number;
  executedPresetCount: number;
  preservedDefault: boolean;
  summaryHref: string;
  runRootHref: string;
  runManifestHref?: string;
  candidateLedgerHref?: string;
  comparisonExportJsonHref?: string;
  comparisonExportCsvHref?: string;
  modelRegistryHref?: string;
  deploymentProfilesHref?: string;
  presetCatalogHref: string;
  benchmarkCatalogHref: string;
  runManifest?: {
    comparisonIntent?: string | null;
    executionScope?: string | null;
  } | null;
  presets: Array<{
    presetId: string;
    label: string;
    role: string;
    benchmarkTier: string;
    experimental: boolean;
    shippedDefault: boolean;
    deploymentProfile?: DeploymentProfileId | null;
    availabilityStatus: string;
    availabilitySummary: string;
    runtimeModel: string | null;
    artifactAcceptanceModel: string | null;
    modelFingerprint?: {
      runtimeKind?: string | null;
    } | null;
    roleAssignments?: Array<{
      roleId: string;
      modelId: string | null;
      modalityUse?: string | null;
    }>;
    comparisonContext?: {
      comparisonIntent?: string | null;
      executionScope?: string | null;
      baselinePresetId?: string | null;
      manifestPath?: string | null;
    };
    conformanceSummary?: {
      status?: string | null;
      comparisonValidityRate?: number | null;
      conformancePassRate?: number | null;
      protectedSplitPassRate?: number | null;
      rollbackReadinessRate?: number | null;
    };
    caseCount: number;
    availableWorkloadCount: number;
    summaryHref: string;
    manifestHref?: string;
    runRootHref: string;
    topFindings: string[];
    scorecards: Record<
      string,
      {
        available: boolean;
        reason: string;
        decisionWeight?: string;
        comparisonStatus?: string;
        confidenceClass?: string;
        coverageClass?: string;
        benchmarkPrograms?: string[];
        metrics: Record<string, number | string | null | undefined>;
      }
    >;
  }>;
  candidateLedger?: CandidateLedgerEntry[];
};

export type ScorecardViewModel = {
  previewMode: boolean;
  statusLabel: string;
  outcomeLabel: string;
  summary: string;
  freshnessLabel: string;
  interruptionLabel: string | null;
  preservedDefault: boolean;
  leaderLabel: string;
  baselineLabel: string;
  plannedPresetCount: number;
  summarizedPresetCount: number;
  fullyCompletedPresetCount: number;
  comparedPresetCount: number;
  executedPresetCount: number;
  coverageGapCount: number;
  coverageGaps: string[];
  sidebarSummary: {
    statusLabel: string;
    leaderLabel: string;
    outcomeLabel: string;
    gapCount: number;
  };
  schemaItems: Array<{
    id: string;
    label: string;
    qualifier: string;
  }>;
  evidenceLinks: Array<{
    label: string;
    href: string;
  }>;
  rows: ScorecardPresetViewModel[];
};

export type DeploymentsViewModel = {
  previewMode: boolean;
  summary: string;
  assignmentNote: string;
  stats: Array<{
    label: string;
    value: string;
  }>;
  profiles: DeploymentProfileViewModel[];
};

export type CandidatesViewModel = {
  previewMode: boolean;
  summary: string;
  assignmentNote: string;
  stats: Array<{
    label: string;
    value: string;
  }>;
  candidates: CandidateViewModel[];
};

export type CandidateLedgerEntry = {
  candidateId: string;
  candidateKind?: string;
  parentCandidateId: string | null;
  presetId: string;
  deploymentProfile: DeploymentProfileId;
  comparisonIntent?: string;
  executionScope?: string;
  status: string;
  summary: string;
  mutationIntent: string;
  targetFamily: string;
  changedContracts: string[];
  roleAssignmentDelta?: string[];
  validationSummary: {
    requiredReadyCount: number;
    requiredCategoryCount: number;
    bestRequiredCount: number;
    coverageStatus: string;
  };
  evaluationLanes?: {
    proxy: string;
    validation: string;
    challenge: string;
    holdout: string;
  };
  conformanceStatus?: string;
  paretoClass?: string;
  controlRunIds?: string[];
  rollbackTarget?: string | null;
  regressions: string[];
  evidenceLinks: Array<{
    label: string;
    href: string;
  }>;
};

export type DeploymentProfileViewModel = {
  id: DeploymentProfileId;
  label: string;
  sublabel: string;
  winnerLabel: string;
  summary: string;
  roleLabel: string | null;
  runtimeTags: string[];
  highlights: Array<{
    label: string;
    value: string;
  }>;
  blockers: string[];
  badges: Array<{
    label: string;
    tone: MatrixBadgeTone;
  }>;
};

export type CandidateViewModel = {
  id: string;
  label: string;
  status: {
    label: string;
    tone: MatrixBadgeTone;
  };
  deploymentLabel: string;
  roleLabel: string | null;
  targetFamily: string;
  summary: string;
  mutationIntent: string;
  lineage: string;
  runtimeTags: string[];
  touchedSurfaces: string[];
  validationReadings: Array<{
    label: string;
    value: string;
  }>;
  regressions: string[];
  evidenceLinks: Array<{
    label: string;
    href: string;
  }>;
};

export type ScorecardPresetViewModel = {
  presetId: string;
  label: string;
  roleLabel: string;
  availabilityLabel: string;
  runtimeTags: string[];
  findings: string | null;
  titleBadges: Array<{
    label: string;
    tone: MatrixBadgeTone;
  }>;
  cells: ScorecardCellViewModel[];
};

export type ScorecardCellViewModel = {
  categoryId: string;
  shortLabel: string;
  headingLabel: string;
  primaryValue: string;
  metricLabel: string;
  note: string;
  noteTone: ScorecardNoteTone;
  isBlocked: boolean;
  isBest: boolean;
  badges: Array<{
    label: string;
    tone: MatrixBadgeTone;
  }>;
};

const CATEGORY_PRIMARY_METRIC: Record<string, string> = {
  baseModelQuality: "normalizedScore",
  artifactQuality: "averageJudgeScore",
  codingCompletion: "taskPassRate",
  researchQuality: "citationVerifierPassRate",
  computerUseCompletion: "rewardFloorPassRate",
  toolApiReliability: "normalizedScore",
  generalAgentQuality: "normalizedScore",
  latencyAndResourcePressure: "meanWallClockMs",
  operationalDiscipline: "conformancePassRate",
};

const CATEGORY_SHORT_LABELS: Record<string, string> = {
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

const METRIC_LABELS: Record<string, string> = {
  normalizedScore: "score",
  passRate: "pass rate",
  averageJudgeScore: "judge",
  verifierPassRate: "verifier",
  averageRepairLoopIterations: "repair loops",
  routeMatchRate: "route match",
  taskPassRate: "task pass",
  policyPassRate: "policy",
  reasoningPassRate: "reasoning",
  targetedTestPassRate: "targeted tests",
  citationVerifierPassRate: "citations",
  sourceIndependenceRate: "independence",
  synthesisCompleteness: "synthesis",
  rewardFloorPassRate: "reward floor",
  postconditionPassRate: "postconditions",
  meanStepCount: "steps",
  meanWallClockMs: "mean wall time",
  p95WallClockMs: "p95 wall time",
  residentModelBytes: "resident bytes",
  processorKind: "processor",
  conformancePassRate: "conformance",
  comparisonValidityRate: "comparability",
  protectedSplitPassRate: "split guard",
  rollbackReadinessRate: "rollback",
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

const DEPLOYMENT_PROFILES: Array<{
  id: DeploymentProfileId;
  label: string;
  sublabel: string;
}> = [
  {
    id: "local_cpu_consumer",
    label: "CPU consumer",
    sublabel: "lowest-footprint local lane",
  },
  {
    id: "local_gpu_8gb_class",
    label: "8GB-class local",
    sublabel: "constrained local GPU default",
  },
  {
    id: "local_gpu_16gb_class",
    label: "16GB-class local",
    sublabel: "stronger local GPU lane",
  },
  {
    id: "local_workstation",
    label: "Workstation local",
    sublabel: "high-capacity local lane",
  },
  {
    id: "hybrid_privacy_preserving",
    label: "Hybrid private",
    sublabel: "local-first with bounded remote help",
  },
  {
    id: "blind_cloud_standard",
    label: "Blind cloud",
    sublabel: "standard approved blind-cloud posture",
  },
  {
    id: "blind_cloud_premium",
    label: "Blind cloud premium",
    sublabel: "highest approved blind-cloud tier",
  },
];

function relTime(iso: string) {
  const deltaMs = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(deltaMs / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function fmtPct(value: number | null | undefined) {
  return value == null ? "—" : `${Math.round(value * 100)}%`;
}

function fmtScore(value: number | null | undefined) {
  return value == null ? "—" : value.toFixed(2);
}

function fmtMs(value: number | null | undefined) {
  return value == null ? "—" : `${Math.round(value)}ms`;
}

function fmtAvailabilityStatus(value: string | null | undefined) {
  return value ? value.replace(/_/g, " ") : "unknown";
}

function fmtCount(value: number | null | undefined) {
  return value == null ? "—" : `${Math.round(value)}`;
}

function fmtCompactBytes(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const digits = size >= 10 || unitIndex === 0 ? 0 : 1;
  return `${size.toFixed(digits)}${units[unitIndex]}`;
}

function fmtLoopStatus(value: string | null | undefined) {
  switch (value) {
    case "active":
      return "active";
    case "stop_parity":
      return "parity met";
    case "stop_plateau":
      return "plateau";
    case "stop_budget":
      return "budget cap";
    default:
      return value ? value.replace(/_/g, " ") : "—";
  }
}

function interruptionLabelForMatrix(matrix: ScorecardMatrixInput) {
  const summarizedPresetCount =
    typeof matrix.summarizedPresetCount === "number"
      ? matrix.summarizedPresetCount
      : matrix.comparedPresetCount;
  const fullyCompletedPresetCount =
    typeof matrix.fullyCompletedPresetCount === "number"
      ? matrix.fullyCompletedPresetCount
      : summarizedPresetCount;
  if (typeof matrix.runAbortReason === "string" && matrix.runAbortReason.trim()) {
    const incompletePresetCount = Math.max(
      0,
      summarizedPresetCount - fullyCompletedPresetCount,
    );
    if (incompletePresetCount > 0) {
      return `${matrix.runAbortReason} ${incompletePresetCount} preset${
        incompletePresetCount === 1 ? "" : "s"
      } incomplete.`;
    }
    return matrix.runAbortReason;
  }
  if (summarizedPresetCount > fullyCompletedPresetCount) {
    const incompletePresetCount = summarizedPresetCount - fullyCompletedPresetCount;
    return `${incompletePresetCount} preset${
      incompletePresetCount === 1 ? "" : "s"
    } retained with interrupted or partial completion.`;
  }
  return null;
}

function scorecardValue(
  category:
    | {
        metrics: Record<string, number | string | null | undefined>;
      }
    | null
    | undefined,
  metricId: string,
) {
  return category?.metrics?.[metricId] ?? null;
}

function preferredMetricId(
  categoryId: string,
  category:
    | {
        metrics: Record<string, number | string | null | undefined>;
      }
    | null
    | undefined,
  schemaMetrics: string[],
) {
  const preferred = CATEGORY_PRIMARY_METRIC[categoryId];
  if (preferred && schemaMetrics.includes(preferred)) {
    return preferred;
  }
  const availableMetric = schemaMetrics.find((metricId) => {
    const value = scorecardValue(category, metricId);
    return value !== null && value !== undefined && value !== "";
  });
  return availableMetric ?? schemaMetrics[0] ?? null;
}

function secondaryMetricId(
  primaryMetricId: string | null,
  category:
    | {
        metrics: Record<string, number | string | null | undefined>;
      }
    | null
    | undefined,
  schemaMetrics: string[],
) {
  return (
    schemaMetrics.find((metricId) => {
      if (!metricId || metricId === primaryMetricId) {
        return false;
      }
      const value = scorecardValue(category, metricId);
      return value !== null && value !== undefined && value !== "";
    }) ?? null
  );
}

function formatMetricValue(metricId: string | null, value: string | number | null | undefined) {
  if (value == null || value === "") return "—";
  if (typeof value === "string") {
    return value.replace(/_/g, " ");
  }
  if (!metricId) return fmtScore(value);
  if (metricId === "residentModelBytes") return fmtCompactBytes(value);
  if (metricId.endsWith("Ms")) return fmtMs(value);
  if (
    metricId.includes("Rate") ||
    metricId.includes("Quality") ||
    metricId.includes("Completeness")
  ) {
    return fmtPct(value);
  }
  if (metricId.includes("Score")) return fmtScore(value);
  if (metricId.includes("Iterations") || metricId.includes("Count")) {
    return fmtCount(value);
  }
  return fmtScore(value);
}

function formatMetricDelta(metricId: string | null, delta: number | null) {
  if (delta == null || !metricId) return null;
  const sign = delta > 0 ? "+" : delta < 0 ? "−" : "±";
  const abs = Math.abs(delta);
  if (metricId === "residentModelBytes") {
    return `${sign}${fmtCompactBytes(abs)}`;
  }
  if (metricId.endsWith("Ms")) {
    return `${sign}${Math.round(abs)}ms`;
  }
  if (
    metricId.includes("Rate") ||
    metricId.includes("Quality") ||
    metricId.includes("Completeness")
  ) {
    return `${sign}${Math.round(abs * 100)} pts`;
  }
  if (metricId.includes("Score")) {
    return `${sign}${abs.toFixed(2)}`;
  }
  if (metricId.includes("Iterations") || metricId.includes("Count")) {
    return `${sign}${abs.toFixed(abs >= 10 ? 0 : 1)}`;
  }
  return `${sign}${abs.toFixed(2)}`;
}

function deltaTone(metricId: string | null, delta: number | null): ScorecardNoteTone {
  if (delta == null || !metricId || delta === 0) return "flat";
  const lowerIsBetter = LOWER_IS_BETTER_METRICS.has(metricId);
  const improved = lowerIsBetter ? delta < 0 : delta > 0;
  return improved ? "up" : "down";
}

function humanizeCoverageEntry(value: string) {
  return value.replace(/([A-Z])/g, " $1").replace(/_/g, " ").trim();
}

function normalizeDeploymentProfileId(
  value: string | null | undefined,
): DeploymentProfileId | null {
  switch (value) {
    case "consumerLocal":
    case "consumer_local":
      return "local_gpu_8gb_class";
    case "workstationLocal":
    case "workstation_local":
      return "local_workstation";
    case "blindCloud":
    case "blind_cloud":
      return "blind_cloud_standard";
    case "local_cpu_consumer":
    case "local_gpu_8gb_class":
    case "local_gpu_16gb_class":
    case "local_workstation":
    case "hybrid_privacy_preserving":
    case "blind_cloud_standard":
    case "blind_cloud_premium":
      return value;
    default:
      return null;
  }
}

function humanizeToken(value: string | null | undefined) {
  return value ? value.replace(/_/g, " ") : "—";
}

function deploymentProfileRecord(
  value: DeploymentProfileId | string | null | undefined,
) {
  const normalized = normalizeDeploymentProfileId(value);
  return DEPLOYMENT_PROFILES.find((profile) => profile.id === normalized) ?? null;
}

function deploymentTrustBadge(
  profileId: DeploymentProfileId,
): DeploymentProfileViewModel["badges"][number] {
  if (profileId.startsWith("blind_cloud")) {
    return { label: "blind cloud", tone: "neutral" };
  }
  if (profileId === "hybrid_privacy_preserving") {
    return { label: "hybrid", tone: "neutral" };
  }
  return { label: "local only", tone: "neutral" };
}

function deploymentStateBadgeLabel(state: string | null | undefined) {
  switch (state) {
    case "default":
      return "current default";
    case "candidate":
      return "active challenger";
    case "shadow_only":
      return "shadow scoped";
    case "retained":
      return "retained";
    case "empty":
      return "empty lane";
    default:
      return humanizeToken(state);
  }
}

function candidateLaneSummary(
  lanes: CandidateLedgerEntry["evaluationLanes"] | null | undefined,
) {
  if (!lanes) {
    return "proxy — · validation — · challenge — · holdout —";
  }
  return [
    `proxy ${humanizeToken(lanes.proxy)}`,
    `validation ${humanizeToken(lanes.validation)}`,
    `challenge ${humanizeToken(lanes.challenge)}`,
    `holdout ${humanizeToken(lanes.holdout)}`,
  ].join(" · ");
}

function candidateRollbackLabel(
  candidate: CandidateLedgerEntry,
  presetById: Map<string, ScorecardMatrixInput["presets"][number]>,
) {
  if (!candidate.rollbackTarget) {
    return "none";
  }
  const rollbackPresetId = candidate.rollbackTarget.replace(/^candidate:/, "");
  return presetById.get(rollbackPresetId)?.label ?? rollbackPresetId;
}

function bestPresetIdsByCategory(matrix: ScorecardMatrixInput) {
  const bestByCategory = new Map<string, string | null>();

  for (const category of matrix.scorecardSchema.categories) {
    const metricId = preferredMetricId(category.id, null, category.metrics);
    if (!metricId) {
      bestByCategory.set(category.id, null);
      continue;
    }

    let bestPresetId: string | null = null;
    let bestValue: number | null = null;

    for (const preset of matrix.presets) {
      const categoryData = scorecardValue(preset.scorecards[category.id], metricId);
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

function inferDeploymentProfileId(
  preset: ScorecardMatrixInput["presets"][number],
): DeploymentProfileId {
  const text = [
    preset.benchmarkTier,
    preset.role,
    preset.label,
    preset.runtimeModel ?? "",
  ]
    .join(" ")
    .toLowerCase();

  if (text.includes("premium cloud")) {
    return "blind_cloud_premium";
  }
  if (text.includes("cloud") || text.includes("remote") || text.includes("blind")) {
    return "blind_cloud_standard";
  }
  if (text.includes("hybrid")) {
    return "hybrid_privacy_preserving";
  }
  if (text.includes("workstation")) {
    return "local_workstation";
  }
  if (text.includes("16gb")) {
    return "local_gpu_16gb_class";
  }
  if (
    preset.benchmarkTier === "tier0" ||
    text.includes("baseline") ||
    text.includes("3b")
  ) {
    return "local_cpu_consumer";
  }
  if (preset.benchmarkTier === "tier1" || text.includes("8gb")) {
    return "local_gpu_8gb_class";
  }
  if (preset.benchmarkTier === "tier2") {
    return "local_gpu_8gb_class";
  }
  return "local_workstation";
}

function resolveDeploymentProfileId(
  preset: ScorecardMatrixInput["presets"][number],
): DeploymentProfileId {
  return normalizeDeploymentProfileId(preset.deploymentProfile) ?? inferDeploymentProfileId(preset);
}

function statusToneForCandidateStatus(status: string): MatrixBadgeTone {
  switch (status) {
    case "retained_default":
      return "accent";
    case "leader":
    case "promotable":
      return "good";
    case "shadow_winner":
    case "candidate":
      return "warn";
    default:
      return "neutral";
  }
}

function statusLabelForCandidateStatus(status: string) {
  return status.replace(/_/g, " ");
}

function fallbackCandidateLineage(
  candidate: CandidateLedgerEntry,
  presetById: Map<string, ScorecardMatrixInput["presets"][number]>,
) {
  if (!candidate.parentCandidateId) {
    return "root baseline";
  }
  const currentLabel = presetById.get(candidate.presetId)?.label ?? candidate.presetId;
  const parentPresetId = candidate.parentCandidateId.replace(/^candidate:/, "");
  const parentLabel = presetById.get(parentPresetId)?.label ?? parentPresetId;
  return `${parentLabel} → ${currentLabel}`;
}

function selectDeploymentWinner(
  presets: ScorecardMatrixInput["presets"],
  matrixLeaderPresetId: string | null,
) {
  const leader = presets.find((preset) => preset.presetId === matrixLeaderPresetId);
  if (leader) return leader;

  const shippedDefault = presets.find((preset) => preset.shippedDefault);
  if (shippedDefault) return shippedDefault;

  return [...presets].sort((left, right) => {
    if (left.experimental !== right.experimental) {
      return left.experimental ? 1 : -1;
    }
    if (left.availableWorkloadCount !== right.availableWorkloadCount) {
      return right.availableWorkloadCount - left.availableWorkloadCount;
    }
    return right.caseCount - left.caseCount;
  })[0] ?? null;
}

function qualifierForCategory(category: ScorecardMatrixInput["scorecardSchema"]["categories"][number]) {
  switch (category.decisionWeight) {
    case "required":
      return "required";
    case "screening":
      return "screening";
    default:
      return category.requiredForPromotion ? "required" : "supporting";
  }
}

function toneForComparisonStatus(status: string | null | undefined): MatrixBadgeTone {
  switch (status) {
    case "comparable":
      return "good";
    case "caution":
      return "warn";
    case "not_comparable":
      return "danger";
    default:
      return "neutral";
  }
}

function toneForConfidenceClass(value: string | null | undefined): MatrixBadgeTone {
  switch (value) {
    case "high":
      return "good";
    case "medium":
      return "accent";
    case "low":
      return "warn";
    default:
      return "neutral";
  }
}

export function buildScorecardViewModel(
  matrix: ScorecardMatrixInput | null | undefined,
  fallbackGeneratedAt: string,
  options?: {
    previewMode?: boolean;
  },
): ScorecardViewModel | null {
  if (!matrix) {
    return null;
  }

  const previewMode = Boolean(options?.previewMode);
  const matrixLeaderPresetId =
    matrix.decision.leaderPresetId ?? matrix.decision.artifactLeaderPresetId ?? null;
  const matrixLeaderPreset =
    matrix.presets.find((preset) => preset.presetId === matrixLeaderPresetId) ?? null;
  const baselinePreset =
    matrix.presets.find((preset) => preset.shippedDefault) ??
    matrixLeaderPreset ??
    matrix.presets[0] ??
    null;
  const bestPresetIds = bestPresetIdsByCategory(matrix);
  const generatedAt = matrix.generatedAt ?? fallbackGeneratedAt;

  const rows = matrix.presets.map((preset) => {
    const isLeader = preset.presetId === matrixLeaderPresetId;
    const isBaseline = preset.presetId === baselinePreset?.presetId;
    const titleBadges: ScorecardPresetViewModel["titleBadges"] = [];

    if (isLeader) titleBadges.push({ label: "leader", tone: "good" });
    if (preset.shippedDefault) titleBadges.push({ label: "default", tone: "accent" });
    if (preset.experimental) titleBadges.push({ label: "experimental", tone: "warn" });
    if (preset.conformanceSummary?.status === "fail") {
      titleBadges.push({ label: "conformance fail", tone: "danger" });
    }

    const cells = matrix.scorecardSchema.categories.map((category) => {
      const categoryData = preset.scorecards[category.id];
      const baselineCategory = baselinePreset?.scorecards?.[category.id];
      const primaryMetricId = preferredMetricId(category.id, categoryData, category.metrics);
      const supportingMetricId = secondaryMetricId(
        primaryMetricId,
        categoryData,
        category.metrics,
      );
      const primaryValue = primaryMetricId
        ? scorecardValue(categoryData, primaryMetricId)
        : null;
      const supportingValue = supportingMetricId
        ? scorecardValue(categoryData, supportingMetricId)
        : null;
      const baselineValue = primaryMetricId
        ? scorecardValue(baselineCategory, primaryMetricId)
        : null;
      const delta =
        typeof primaryValue === "number" && typeof baselineValue === "number"
          ? primaryValue - baselineValue
          : null;
      const deltaLabel = isBaseline ? "baseline" : formatMetricDelta(primaryMetricId, delta);
      const isBest = bestPresetIds.get(category.id) === preset.presetId;
      const note =
        deltaLabel != null
          ? `${deltaLabel}${isBaseline ? "" : " vs baseline"}`
          : categoryData?.available === false
            ? categoryData.reason
            : supportingMetricId
              ? `${
                  METRIC_LABELS[supportingMetricId] ?? supportingMetricId
                } ${formatMetricValue(supportingMetricId, supportingValue)}`
              : "No retained comparison yet.";

      const badges: ScorecardCellViewModel["badges"] = [
        {
          label: qualifierForCategory(category),
          tone:
            qualifierForCategory(category) === "required"
              ? "accent"
              : qualifierForCategory(category) === "screening"
                ? "neutral"
                : "neutral",
        },
      ];

      if (categoryData?.available === false) {
        badges.push({ label: "blocked", tone: "warn" });
      }
      if (categoryData?.comparisonStatus) {
        badges.push({
          label: categoryData.comparisonStatus.replace(/_/g, " "),
          tone: toneForComparisonStatus(categoryData.comparisonStatus),
        });
      }
      if (categoryData?.confidenceClass) {
        badges.push({
          label: `${categoryData.confidenceClass} confidence`,
          tone: toneForConfidenceClass(categoryData.confidenceClass),
        });
      }
      if (categoryData?.coverageClass) {
        badges.push({
          label: `${categoryData.coverageClass} coverage`,
          tone: categoryData.coverageClass === "full" ? "good" : "warn",
        });
      }

      return {
        categoryId: category.id,
        shortLabel: CATEGORY_SHORT_LABELS[category.id] ?? category.label,
        headingLabel: category.label,
        primaryValue: formatMetricValue(primaryMetricId, primaryValue),
        metricLabel: METRIC_LABELS[primaryMetricId ?? ""] ?? category.label.toLowerCase(),
        note,
        noteTone: deltaTone(primaryMetricId, delta),
        isBlocked: categoryData?.available === false,
        isBest: isBest && matrix.presets.length > 1,
        badges,
      };
    });

    const runtimeTags = [
      preset.runtimeModel,
      preset.artifactAcceptanceModel
        ? `judge ${preset.artifactAcceptanceModel}`
        : null,
      preset.comparisonContext?.comparisonIntent
        ? preset.comparisonContext.comparisonIntent.replace(/_/g, " ")
        : null,
      preset.roleAssignments?.length
        ? `${preset.roleAssignments.length} role assignments`
        : null,
      `${preset.caseCount} retained cases`,
    ].filter((value): value is string => Boolean(value));

    return {
      presetId: preset.presetId,
      label: preset.label,
      roleLabel: preset.role.replace(/_/g, " "),
      availabilityLabel: fmtAvailabilityStatus(preset.availabilityStatus),
      runtimeTags,
      findings: preset.topFindings.length > 0 ? preset.topFindings.slice(0, 2).join(" · ") : null,
      titleBadges,
      cells,
    };
  });

  const evidenceLinks = [
    { label: "latest_summary", href: matrix.summaryHref },
    { label: "retained_run", href: matrix.runRootHref },
    { label: "run_manifest", href: matrix.runManifestHref ?? "" },
    { label: "candidate_ledger", href: matrix.candidateLedgerHref ?? "" },
    { label: "comparison_export_json", href: matrix.comparisonExportJsonHref ?? "" },
    { label: "comparison_export_csv", href: matrix.comparisonExportCsvHref ?? "" },
    { label: "model_registry", href: matrix.modelRegistryHref ?? "" },
    { label: "deployment_profiles", href: matrix.deploymentProfilesHref ?? "" },
    { label: "preset_catalog", href: matrix.presetCatalogHref },
    { label: "benchmark_catalog", href: matrix.benchmarkCatalogHref },
  ].filter((entry) => Boolean(entry.href));

  const plannedPresetCount =
    typeof matrix.plannedPresetCount === "number"
      ? matrix.plannedPresetCount
      : matrix.comparedPresetCount;
  const summarizedPresetCount =
    typeof matrix.summarizedPresetCount === "number"
      ? matrix.summarizedPresetCount
      : matrix.comparedPresetCount;
  const fullyCompletedPresetCount =
    typeof matrix.fullyCompletedPresetCount === "number"
      ? matrix.fullyCompletedPresetCount
      : summarizedPresetCount;

  return {
    previewMode,
    statusLabel: fmtLoopStatus(matrix.status),
    outcomeLabel: matrix.decision.outcome.replace(/_/g, " "),
    summary: matrix.decision.summary,
    freshnessLabel: relTime(generatedAt),
    interruptionLabel: interruptionLabelForMatrix(matrix),
    preservedDefault: matrix.preservedDefault,
    leaderLabel: matrixLeaderPreset?.label ?? "Leader pending",
    baselineLabel: baselinePreset?.label ?? "Retained baseline",
    plannedPresetCount,
    summarizedPresetCount,
    fullyCompletedPresetCount,
    comparedPresetCount: matrix.comparedPresetCount,
    executedPresetCount: matrix.executedPresetCount,
    coverageGapCount: matrix.decision.missingCoverage.length,
    coverageGaps: matrix.decision.missingCoverage.map(humanizeCoverageEntry),
    sidebarSummary: {
      statusLabel: fmtLoopStatus(matrix.status),
      leaderLabel: matrixLeaderPreset?.label ?? "Leader pending",
      outcomeLabel: matrix.decision.outcome.replace(/_/g, " "),
      gapCount: matrix.decision.missingCoverage.length,
    },
    schemaItems: matrix.scorecardSchema.categories.map((category) => ({
      id: category.id,
      label: category.label,
      qualifier: qualifierForCategory(category),
    })),
    evidenceLinks,
    rows,
  };
}

export function buildDeploymentsViewModel(
  matrix: ScorecardMatrixInput | null | undefined,
  scorecard: ScorecardViewModel | null | undefined,
  options?: {
    previewMode?: boolean;
  },
): DeploymentsViewModel | null {
  if (!matrix || !scorecard) {
    return null;
  }

  const previewMode = Boolean(options?.previewMode);
  const matrixLeaderPresetId =
    matrix.decision.leaderPresetId ?? matrix.decision.artifactLeaderPresetId ?? null;
  const baselinePreset =
    matrix.presets.find((preset) => preset.shippedDefault) ??
    matrix.presets[0] ??
    null;
  const rowByPresetId = new Map(scorecard.rows.map((row) => [row.presetId, row]));
  const deploymentDecisionByProfile = new Map(
    (matrix.deploymentDecisions ?? []).map((entry) => [entry.deploymentProfile, entry]),
  );
  const hasExplicitDeploymentProfiles =
    matrix.presets.length > 0 &&
    matrix.presets.every((preset) => normalizeDeploymentProfileId(preset.deploymentProfile) != null);
  const groupedPresets = new Map<DeploymentProfileId, ScorecardMatrixInput["presets"]>(
    DEPLOYMENT_PROFILES.map((profile) => [profile.id, []]),
  );

  for (const preset of matrix.presets) {
    groupedPresets.get(resolveDeploymentProfileId(preset))?.push(preset);
  }

  const profiles = DEPLOYMENT_PROFILES.map((profile) => {
    const presets = groupedPresets.get(profile.id) ?? [];
    const retainedDecision = deploymentDecisionByProfile.get(profile.id);
    const winner =
      (retainedDecision?.leaderPresetId
        ? presets.find((preset) => preset.presetId === retainedDecision.leaderPresetId)
        : null) ?? selectDeploymentWinner(presets, matrixLeaderPresetId);
    const winnerRow = winner ? rowByPresetId.get(winner.presetId) ?? null : null;
    const badges: DeploymentProfileViewModel["badges"] = [];

    badges.push(deploymentTrustBadge(profile.id));

    if (winner?.presetId === matrixLeaderPresetId) {
      badges.push({ label: "overall leader", tone: "good" });
    }

    if (
      retainedDecision?.defaultPresetId &&
      winner?.presetId === retainedDecision.defaultPresetId
    ) {
      badges.push({ label: "current default", tone: "accent" });
    } else if (winner?.shippedDefault) {
      badges.push({ label: "current default", tone: "accent" });
    }

    if (
      retainedDecision?.challengerPresetId &&
      winner?.presetId === retainedDecision.challengerPresetId
    ) {
      badges.push({ label: "active challenger", tone: "warn" });
    }

    if (
      retainedDecision?.state &&
      !(
        retainedDecision.state === "default" &&
        (winner?.shippedDefault ||
          retainedDecision.defaultPresetId === winner?.presetId)
      ) &&
      !(
        retainedDecision.state === "candidate" &&
        retainedDecision.challengerPresetId === winner?.presetId
      )
    ) {
      badges.push({
        label: deploymentStateBadgeLabel(retainedDecision.state),
        tone:
          retainedDecision.state === "shadow_only"
            ? "warn"
            : retainedDecision.state === "retained"
              ? "neutral"
              : retainedDecision.state === "empty"
                ? "warn"
                : "neutral",
      });
    } else if (winner && !winner.shippedDefault) {
      badges.push({ label: "candidate", tone: "warn" });
    } else {
      badges.push({ label: "empty lane", tone: "warn" });
    }

    if ((retainedDecision?.coverageGaps?.length ?? 0) > 0) {
      badges.push({ label: "coverage gaps", tone: "warn" });
    }

    const runtimeTags = winner
      ? [
          winner.runtimeModel,
          winner.artifactAcceptanceModel
            ? `judge ${winner.artifactAcceptanceModel}`
            : null,
          winner.roleAssignments?.length
            ? `${winner.roleAssignments.length} roles`
            : null,
          retainedDecision?.trustPosture
            ? humanizeToken(retainedDecision.trustPosture)
            : null,
          `${winner.caseCount} retained cases`,
        ].filter((value): value is string => Boolean(value))
      : [];

    const highlights =
      winnerRow?.cells
        .filter((cell) => cell.badges.some((badge) => badge.label === "required"))
        .slice(0, 4)
        .map((cell) => ({
          label: cell.shortLabel,
          value: cell.primaryValue,
        })) ?? [];

    let summary = "No retained benchmarked preset currently maps to this deployment profile.";
    if (retainedDecision?.summary) {
      summary = retainedDecision.summary;
    } else if (winner) {
      summary = winner.shippedDefault
        ? "Current retained default for this deployment target."
        : winner.experimental
          ? "Read-only retained candidate for this deployment target."
          : "Current retained winner for this deployment target.";
    }

    const blockers = winner
      ? [
          ...(retainedDecision?.coverageGaps ?? []).map(humanizeCoverageEntry),
          ...winner.topFindings,
        ].slice(0, 3)
      : (retainedDecision?.coverageGaps?.length ?? 0) > 0
        ? (retainedDecision?.coverageGaps ?? []).map(humanizeCoverageEntry).slice(0, 3)
        : matrix.decision.missingCoverage.length > 0
          ? matrix.decision.missingCoverage.map(humanizeCoverageEntry).slice(0, 2)
        : ["No retained candidate observed for this deployment profile yet."];

    return {
      id: profile.id,
      label: profile.label,
      sublabel: profile.sublabel,
      winnerLabel: winner?.label ?? "No retained candidate",
      summary,
      roleLabel: winner ? winner.role.replace(/_/g, " ") : null,
      runtimeTags,
      highlights,
      blockers,
      badges,
    };
  });

  const populatedProfiles = profiles.filter(
    (profile) => profile.winnerLabel !== "No retained candidate",
  ).length;

  return {
    previewMode,
    summary:
      "Defaults stay separated by hardware tier and trust posture, so local, hybrid, and blind-cloud answers can all remain visible without pretending one global winner answers every deployment lane.",
    assignmentNote:
      matrix.deploymentDecisions && matrix.deploymentDecisions.length > 0
        ? "Deployment winners, defaults, challengers, and coverage gaps are sourced from retained deployment decisions in the matrix payload."
        : hasExplicitDeploymentProfiles
          ? "Deployment profile assignment is carried in the retained matrix payload so local and blind-cloud defaults read from explicit profile metadata."
          : "Deployment profile assignment is currently inferred from retained preset metadata until the benchmark payload carries an explicit deployment profile field.",
    stats: [
      {
        label: "Profiles covered",
        value: `${populatedProfiles}/${profiles.length}`,
      },
      {
        label: "Local default",
        value: baselinePreset?.label ?? "—",
      },
      {
        label: "Overall leader",
        value: scorecard.leaderLabel,
      },
    ],
    profiles,
  };
}

export function buildCandidatesViewModel(
  matrix: ScorecardMatrixInput | null | undefined,
  scorecard: ScorecardViewModel | null | undefined,
  options?: {
    previewMode?: boolean;
  },
): CandidatesViewModel | null {
  if (!matrix || !scorecard) {
    return null;
  }

  const previewMode = Boolean(options?.previewMode);
  const baselinePreset =
    matrix.presets.find((preset) => preset.shippedDefault) ??
    matrix.presets[0] ??
    null;
  const presetById = new Map(matrix.presets.map((preset) => [preset.presetId, preset]));
  const candidateLedger =
    Array.isArray(matrix.candidateLedger) && matrix.candidateLedger.length > 0
      ? matrix.candidateLedger
      : null;

  const candidates: CandidateViewModel[] = [];

  if (candidateLedger) {
    for (const entry of candidateLedger) {
      const preset = presetById.get(entry.presetId);
      if (!preset) {
        continue;
      }
      const deploymentProfile =
        deploymentProfileRecord(entry.deploymentProfile) ?? DEPLOYMENT_PROFILES[0];
      const touchedSurfaces = [
        ...entry.changedContracts,
        ...(entry.roleAssignmentDelta ?? []).map((roleId) => `role:${roleId}`),
      ];
      const runtimeTags = [
        preset.runtimeModel,
        preset.artifactAcceptanceModel
          ? `judge ${preset.artifactAcceptanceModel}`
          : null,
        entry.comparisonIntent ? humanizeToken(entry.comparisonIntent) : null,
        entry.executionScope ? humanizeToken(entry.executionScope) : null,
        entry.paretoClass ? humanizeToken(entry.paretoClass) : null,
        `${preset.caseCount} retained cases`,
      ].filter((value): value is string => Boolean(value));
      const regressions = [...entry.regressions];
      if (entry.conformanceStatus === "fail") {
        regressions.unshift("Conformance checks are currently failing.");
      }

      candidates.push({
        id: entry.candidateId,
        label: preset.label,
        status: {
          label: statusLabelForCandidateStatus(entry.status),
          tone: statusToneForCandidateStatus(entry.status),
        },
        deploymentLabel: deploymentProfile.label,
        roleLabel: preset.role.replace(/_/g, " "),
        targetFamily: entry.targetFamily,
        summary: entry.summary,
        mutationIntent: entry.mutationIntent,
        lineage: fallbackCandidateLineage(entry, presetById),
        runtimeTags,
        touchedSurfaces: touchedSurfaces.length > 0 ? touchedSurfaces : ["no contract delta recorded"],
        validationReadings: [
          {
            label: "Required ready",
            value: `${entry.validationSummary.requiredReadyCount}/${entry.validationSummary.requiredCategoryCount || 0}`,
          },
          {
            label: "Best on required",
            value: `${entry.validationSummary.bestRequiredCount}/${entry.validationSummary.requiredCategoryCount || 0}`,
          },
          {
            label: "Coverage",
            value: humanizeToken(entry.validationSummary.coverageStatus),
          },
          {
            label: "Compare intent",
            value: humanizeToken(entry.comparisonIntent),
          },
          {
            label: "Exec scope",
            value: humanizeToken(entry.executionScope),
          },
          {
            label: "Lane state",
            value: candidateLaneSummary(entry.evaluationLanes),
          },
          {
            label: "Conformance",
            value: humanizeToken(entry.conformanceStatus),
          },
          {
            label: "Rollback",
            value: candidateRollbackLabel(entry, presetById),
          },
          {
            label: "Deployment",
            value: deploymentProfile.label,
          },
        ],
        regressions:
          regressions.length > 0
            ? regressions
            : ["No retained regression callouts yet."],
        evidenceLinks: entry.evidenceLinks.filter((link) => Boolean(link.href)),
      });
    }
  } else {
    for (const preset of matrix.presets) {
      const deploymentProfileId = resolveDeploymentProfileId(preset);
      const deploymentProfile =
        deploymentProfileRecord(deploymentProfileId) ?? DEPLOYMENT_PROFILES[0];
      const runtimeTags = [
        preset.runtimeModel,
        preset.artifactAcceptanceModel
          ? `judge ${preset.artifactAcceptanceModel}`
          : null,
        `${preset.caseCount} retained cases`,
      ].filter((value): value is string => Boolean(value));

      candidates.push({
        id: preset.presetId,
        label: preset.label,
        status: {
          label: preset.shippedDefault ? "retained default" : "retained",
          tone: preset.shippedDefault ? "accent" : "neutral",
        },
        deploymentLabel: deploymentProfile.label,
        roleLabel: preset.role.replace(/_/g, " "),
        targetFamily: "No retained required-family coverage yet",
        summary: "Retained preset snapshot without an attached candidate ledger yet.",
        mutationIntent:
          "Preserve baseline behavior while improving coverage and trustworthiness.",
        lineage:
          preset.shippedDefault
            ? "root baseline"
            : `${baselinePreset?.label ?? "retained baseline"} → ${preset.label}`,
        runtimeTags,
        touchedSurfaces: ["default preservation", "coverage guard", "latency/resource fit"],
        validationReadings: [
          { label: "Required ready", value: "0/0" },
          { label: "Best on required", value: "0/0" },
          { label: "Coverage", value: "sparse" },
          { label: "Compare intent", value: humanizeToken(preset.comparisonContext?.comparisonIntent) },
          { label: "Exec scope", value: humanizeToken(preset.comparisonContext?.executionScope) },
          { label: "Lane state", value: "proxy — · validation — · challenge — · holdout —" },
          { label: "Conformance", value: humanizeToken(preset.conformanceSummary?.status) },
          { label: "Rollback", value: baselinePreset?.label ?? "none" },
          { label: "Deployment", value: deploymentProfile.label },
        ],
        regressions:
          preset.topFindings.slice(0, 2).length > 0
            ? preset.topFindings.slice(0, 2)
            : ["No retained regression callouts yet."],
        evidenceLinks: [
          { label: "summary", href: preset.summaryHref },
          { label: "retained_run", href: preset.runRootHref },
        ].filter((entry) => Boolean(entry.href)),
      });
    }
  }

  const candidateCount = candidates.filter(
    (candidate) => candidate.status.label !== "retained default",
  ).length;

  return {
    previewMode,
    summary:
      candidateLedger
        ? "Candidate review is backed by retained lineage, comparison intent, lane receipts, rollback targets, and conformance status carried in the benchmark payload."
        : "Candidate review stays read-only for now: lineage, mutation intent, validation shape, and regressions are surfaced without pretending a full ledger already exists.",
    assignmentNote:
      candidateLedger
        ? "Candidate cards are sourced from the retained candidate ledger in the benchmark payload."
        : "Candidate cards are inferred from retained preset metadata and scorecard outcomes until the benchmark payload carries a first-class candidate lineage ledger.",
    stats: [
      {
        label: "Candidates visible",
        value: `${candidateCount}`,
      },
      {
        label: "Current baseline",
        value: baselinePreset?.label ?? "—",
      },
      {
        label: "Overall leader",
        value: scorecard.leaderLabel,
      },
    ],
    candidates,
  };
}
