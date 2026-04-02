import fs from "fs";
import path from "path";

export const DEFAULT_RELEASE_GATE_CONFIG_PATH = "release-gates.config.json";
export const DEFAULT_RELEASE_GATE_REPORT_PATH = "release-gates.json";
const DEFAULT_CORPUS_SUMMARY_PATH = "corpus-summary.json";
const DEFAULT_CONFORMANCE_REPORT_PATH = "conformance-report.json";
const DEFAULT_ARENA_LEDGER_PATH = path.join("arena", "ledger.json");

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

function deepClone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function relativeEvidenceDisplayPath(evidenceRoot, targetPath) {
  if (!targetPath || typeof targetPath !== "string" || !fs.existsSync(targetPath)) {
    return null;
  }
  const relative = path.relative(evidenceRoot, targetPath);
  return relative && !relative.startsWith("..")
    ? relative.split(path.sep).join("/")
    : targetPath;
}

function defaultReleaseGateConfig() {
  return {
    version: 1,
    gates: [
      {
        id: "ready_rate",
        label: "Ready rate",
        source: { kind: "benchmark_metric", metricId: "readyRate" },
        operator: "minimum",
        shipThreshold: 0.95,
        ratchetFloor: 0.8,
        minImprovementDelta: 0.02,
        required: true,
      },
      {
        id: "average_judge_score",
        label: "Average judge score",
        source: { kind: "benchmark_metric", metricId: "averageJudgeScore" },
        operator: "minimum",
        shipThreshold: 0.85,
        ratchetFloor: 0.8,
        minImprovementDelta: 0.02,
        required: true,
      },
      {
        id: "screenshot_quality_score",
        label: "Screenshot quality score",
        source: { kind: "benchmark_metric", metricId: "screenshotQualityScore" },
        operator: "minimum",
        shipThreshold: 0.8,
        ratchetFloor: 0.75,
        minImprovementDelta: 0.02,
        required: true,
      },
      {
        id: "pairwise_win_rate",
        label: "Pairwise win rate",
        source: { kind: "benchmark_metric", metricId: "humanPreferenceScore" },
        operator: "minimum",
        shipThreshold: 0.55,
        ratchetFloor: 0.5,
        minImprovementDelta: 0.02,
        required: true,
      },
      {
        id: "shim_required_rate",
        label: "Shim-required rate",
        source: { kind: "benchmark_metric", metricId: "shimRequiredRate" },
        operator: "maximum",
        shipThreshold: 0.1,
        ratchetFloor: 0.7,
        minImprovementDelta: 0.02,
        required: true,
      },
      {
        id: "variance_across_repeats",
        label: "Variance across repeated runs",
        source: { kind: "benchmark_metric", metricId: "varianceAcrossRepeatedRuns" },
        operator: "maximum",
        shipThreshold: 0.15,
        ratchetFloor: 0.25,
        minImprovementDelta: 0.02,
        required: true,
      },
      {
        id: "lexical_routing_regressions",
        label: "Lexical routing regressions",
        source: {
          kind: "conformance_failed_checks",
          checkIds: ["benchmark_specific_routing", "skill_name_routing"],
        },
        operator: "maximum",
        shipThreshold: 0,
        ratchetFloor: 0,
        minImprovementDelta: 0,
        required: true,
      },
    ],
  };
}

function normalizeConfig(config) {
  const parsed = config && typeof config === "object" ? config : {};
  const gates = Array.isArray(parsed.gates) ? parsed.gates : defaultReleaseGateConfig().gates;
  return {
    version:
      typeof parsed.version === "number" && Number.isFinite(parsed.version)
        ? parsed.version
        : 1,
    gates: gates
      .filter((gate) => gate && typeof gate === "object" && typeof gate.id === "string")
      .map((gate) => ({
        id: gate.id,
        label: typeof gate.label === "string" ? gate.label : gate.id,
        source: gate.source && typeof gate.source === "object" ? gate.source : {},
        operator: gate.operator === "maximum" ? "maximum" : "minimum",
        shipThreshold:
          typeof gate.shipThreshold === "number" && Number.isFinite(gate.shipThreshold)
            ? gate.shipThreshold
            : null,
        ratchetFloor:
          typeof gate.ratchetFloor === "number" && Number.isFinite(gate.ratchetFloor)
            ? gate.ratchetFloor
            : null,
        minImprovementDelta:
          typeof gate.minImprovementDelta === "number" &&
          Number.isFinite(gate.minImprovementDelta)
            ? gate.minImprovementDelta
            : 0,
        required: gate.required !== false,
      })),
  };
}

function findBenchmarkMetric(corpusSummary, metricId) {
  return corpusSummary?.benchmarkSuite?.metrics?.[metricId] ?? null;
}

function evaluateConformanceFailures(conformanceReport, checkIds = null) {
  const checks = Array.isArray(conformanceReport?.checks) ? conformanceReport.checks : [];
  const relevant = Array.isArray(checkIds) && checkIds.length > 0
    ? checks.filter((check) => checkIds.includes(check?.id))
    : checks;
  const failed = relevant.filter((check) => check?.status !== "pass");
  return {
    value: failed.length,
    available: relevant.length > 0,
    method:
      Array.isArray(checkIds) && checkIds.length > 0
        ? `count of non-pass conformance checks across ${checkIds.join(", ")}`
        : "count of non-pass Studio artifact conformance checks",
    supportingCheckIds: relevant
      .map((check) => check?.id)
      .filter((value) => typeof value === "string"),
    failedCheckIds: failed
      .map((check) => check?.id)
      .filter((value) => typeof value === "string"),
  };
}

function resolveGateReading(gate, context) {
  const source = gate?.source ?? {};
  if (source.kind === "benchmark_metric") {
    const reading = findBenchmarkMetric(context.corpusSummary, source.metricId);
    if (!reading || typeof reading !== "object") {
      return {
        value: null,
        available: false,
        method: `benchmark metric '${source.metricId}' is missing from the retained corpus summary`,
        supportingBenchmarkIds: [],
      };
    }
    return {
      value: typeof reading.value === "number" ? reading.value : null,
      available: reading.available === true,
      method: typeof reading.method === "string" ? reading.method : null,
      supportingBenchmarkIds: Array.isArray(reading.supportingBenchmarkIds)
        ? reading.supportingBenchmarkIds.filter((value) => typeof value === "string")
        : [],
    };
  }
  if (source.kind === "conformance_failed_checks") {
    return evaluateConformanceFailures(context.conformanceReport, source.checkIds);
  }
  return {
    value: null,
    available: false,
    method: `unsupported gate source '${String(source.kind || "unknown")}'`,
    supportingBenchmarkIds: [],
  };
}

function passesThreshold(operator, value, threshold) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  if (typeof threshold !== "number" || !Number.isFinite(threshold)) {
    return null;
  }
  return operator === "maximum" ? value <= threshold : value >= threshold;
}

function ratchetAssessment(gate, reading) {
  const value = reading?.value;
  const floor = gate?.ratchetFloor;
  const delta = gate?.minImprovementDelta ?? 0;
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    typeof floor !== "number" ||
    !Number.isFinite(floor)
  ) {
    return {
      status: "pending",
      floor,
      deltaToFloor: null,
      candidateFloor: null,
    };
  }

  if (gate.operator === "maximum") {
    const deltaToFloor = roundMetric(floor - value);
    if (value > floor) {
      return {
        status: "regressed",
        floor,
        deltaToFloor,
        candidateFloor: null,
      };
    }
    if (value <= floor - delta) {
      return {
        status: "eligible_raise_floor",
        floor,
        deltaToFloor,
        candidateFloor: roundMetric(value),
      };
    }
    return {
      status: "holding_floor",
      floor,
      deltaToFloor,
      candidateFloor: null,
    };
  }

  const deltaToFloor = roundMetric(value - floor);
  if (value < floor) {
    return {
      status: "regressed",
      floor,
      deltaToFloor,
      candidateFloor: null,
    };
  }
  if (value >= floor + delta) {
    return {
      status: "eligible_raise_floor",
      floor,
      deltaToFloor,
      candidateFloor: roundMetric(value),
    };
  }
  return {
    status: "holding_floor",
    floor,
    deltaToFloor,
    candidateFloor: null,
  };
}

function evaluateGate(gate, context) {
  const reading = resolveGateReading(gate, context);
  const thresholdPass = passesThreshold(gate.operator, reading.value, gate.shipThreshold);
  const status =
    reading.available !== true
      ? "pending_measurement"
      : thresholdPass
        ? "pass"
        : "fail";
  const ratchet = ratchetAssessment(gate, reading);
  return {
    id: gate.id,
    label: gate.label,
    required: gate.required === true,
    status,
    operator: gate.operator,
    shipThreshold: gate.shipThreshold,
    reading: {
      value: typeof reading.value === "number" ? roundMetric(reading.value) : null,
      available: reading.available === true,
      method: reading.method ?? null,
      supportingBenchmarkIds: Array.isArray(reading.supportingBenchmarkIds)
        ? reading.supportingBenchmarkIds
        : [],
      supportingCheckIds: Array.isArray(reading.supportingCheckIds)
        ? reading.supportingCheckIds
        : [],
      failedCheckIds: Array.isArray(reading.failedCheckIds)
        ? reading.failedCheckIds
        : [],
    },
    ratchet,
  };
}

export function collectStudioArtifactReleaseGates(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "studio-artifact-surface");
  const configPath =
    options.configPath ?? path.join(evidenceRoot, DEFAULT_RELEASE_GATE_CONFIG_PATH);
  const summaryPath =
    options.summaryPath ?? path.join(evidenceRoot, DEFAULT_CORPUS_SUMMARY_PATH);
  const conformanceReportPath =
    options.conformanceReportPath ??
    path.join(evidenceRoot, DEFAULT_CONFORMANCE_REPORT_PATH);
  const arenaLedgerPath =
    options.arenaLedgerPath ?? path.join(evidenceRoot, DEFAULT_ARENA_LEDGER_PATH);
  const config = normalizeConfig(
    options.config ?? readJsonIfExists(configPath) ?? defaultReleaseGateConfig(),
  );
  const corpusSummary =
    options.corpusSummary ?? readJsonIfExists(summaryPath) ?? { benchmarkSuite: { metrics: {} } };
  const conformanceReport =
    options.conformanceReport ?? readJsonIfExists(conformanceReportPath) ?? { checks: [] };
  const arenaLedger =
    options.arenaLedger ?? readJsonIfExists(arenaLedgerPath) ?? { status: "unknown" };

  const gates = config.gates.map((gate) =>
    evaluateGate(gate, { corpusSummary, conformanceReport, arenaLedger }),
  );
  const requiredGates = gates.filter((gate) => gate.required);
  const blockingGates = requiredGates.filter((gate) => gate.status !== "pass");
  const ratchetCandidates = gates
    .filter((gate) => gate.ratchet?.status === "eligible_raise_floor")
    .map((gate) => ({
      id: gate.id,
      label: gate.label,
      operator: gate.operator,
      currentValue: gate.reading.value,
      currentFloor: gate.ratchet.floor,
      candidateFloor: gate.ratchet.candidateFloor,
    }));

  return {
    version: 1,
    generatedAt: options.now ?? new Date().toISOString(),
    configPath: relativeEvidenceDisplayPath(evidenceRoot, configPath),
    summaryPath: relativeEvidenceDisplayPath(evidenceRoot, summaryPath),
    conformanceReportPath: relativeEvidenceDisplayPath(evidenceRoot, conformanceReportPath),
    arenaLedgerPath: relativeEvidenceDisplayPath(evidenceRoot, arenaLedgerPath),
    passing: blockingGates.length === 0,
    status:
      blockingGates.length === 0
        ? "pass"
        : blockingGates.some((gate) => gate.status === "fail")
          ? "fail"
          : "pending_measurement",
    summary: {
      gateCount: gates.length,
      passCount: gates.filter((gate) => gate.status === "pass").length,
      failCount: gates.filter((gate) => gate.status === "fail").length,
      pendingCount: gates.filter((gate) => gate.status === "pending_measurement").length,
      blockingGateIds: blockingGates.map((gate) => gate.id),
      ratchetCandidateIds: ratchetCandidates.map((gate) => gate.id),
      changeRequirement:
        "Major artifact-lane changes should raise the floor, raise the ceiling, reduce variance, or reduce cost at the same quality; release gates make that obligation explicit.",
    },
    gates,
    ratchetCandidates,
  };
}

export function writeStudioArtifactReleaseGates(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "studio-artifact-surface");
  const report = collectStudioArtifactReleaseGates({
    ...options,
    repoRoot,
    evidenceRoot,
  });
  const reportPath =
    options.reportPath ?? path.join(evidenceRoot, DEFAULT_RELEASE_GATE_REPORT_PATH);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  return { reportPath, report };
}

function loadStudioArtifactReleaseGates(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "studio-artifact-surface");
  const reportPath =
    options.reportPath ?? path.join(evidenceRoot, DEFAULT_RELEASE_GATE_REPORT_PATH);
  const report = readJsonIfExists(reportPath) ?? collectStudioArtifactReleaseGates(options);
  return { reportPath, report: deepClone(report) };
}

export function collectStudioArtifactReleaseGatesView(options = {}) {
  const { reportPath, report } = loadStudioArtifactReleaseGates(options);
  return {
    status: report.status ?? "pending_measurement",
    passing: report.passing === true,
    reportPath,
    gateCount: Number(report?.summary?.gateCount ?? 0),
    passCount: Number(report?.summary?.passCount ?? 0),
    failCount: Number(report?.summary?.failCount ?? 0),
    pendingCount: Number(report?.summary?.pendingCount ?? 0),
    blockingGateIds: Array.isArray(report?.summary?.blockingGateIds)
      ? report.summary.blockingGateIds
      : [],
    ratchetCandidateIds: Array.isArray(report?.summary?.ratchetCandidateIds)
      ? report.summary.ratchetCandidateIds
      : [],
    topGates: Array.isArray(report.gates) ? report.gates.slice(0, 6) : [],
    ratchetCandidates: Array.isArray(report.ratchetCandidates)
      ? report.ratchetCandidates.slice(0, 6)
      : [],
  };
}
