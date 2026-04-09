import type { ScorecardMatrixInput } from "./scorecardViewModel";

type BenchmarkDataWithMatrix = {
  agentModelMatrix?: ScorecardMatrixInput | null;
};

type DeploymentDecision = NonNullable<ScorecardMatrixInput["deploymentDecisions"]>[number];

const REQUIRED_CATEGORY_IDS = [
  "artifactQuality",
  "codingCompletion",
  "researchQuality",
  "computerUseCompletion",
  "latencyAndResourcePressure",
  "operationalDiscipline",
];

function withMetrics(
  metrics: Record<string, number | string | null | undefined>,
  overrides: Record<string, number | string | null | undefined>,
) {
  return {
    ...metrics,
    ...overrides,
  };
}

function clonePreset(
  base: ScorecardMatrixInput["presets"][number],
  overrides: Partial<ScorecardMatrixInput["presets"][number]>,
) {
  return {
    ...base,
    ...overrides,
    scorecards: Object.fromEntries(
      Object.entries(base.scorecards).map(([categoryId, category]) => [
        categoryId,
        {
          ...category,
          metrics: { ...category.metrics },
        },
      ]),
    ) as ScorecardMatrixInput["presets"][number]["scorecards"],
  };
}

function deploymentDecision(
  profile: DeploymentDecision["deploymentProfile"],
  label: string,
  trustPosture: string,
  summary: string,
  overrides: Partial<DeploymentDecision> = {},
) {
  return {
    deploymentProfile: profile,
    label,
    trustPosture,
    state: "empty",
    defaultPresetId: null,
    leaderPresetId: null,
    challengerPresetId: null,
    coverageGaps: REQUIRED_CATEGORY_IDS,
    requiredCategoryIds: REQUIRED_CATEGORY_IDS,
    summary,
    ...overrides,
  };
}

export function withScorecardPreview<T extends BenchmarkDataWithMatrix>(data: T): T {
  const matrix = data.agentModelMatrix;
  const basePreset = matrix?.presets?.[0];
  if (!matrix || !basePreset) {
    return data;
  }

  const baselinePreset = clonePreset(basePreset, {
    deploymentProfile: "local_gpu_8gb_class",
    comparisonContext: {
      comparisonIntent: "baseline_anchor",
      executionScope: "fleet_shared",
      baselinePresetId: basePreset.presetId,
      manifestPath: "/tmp/retained/run-manifest.json",
    },
    conformanceSummary: {
      status: "warn",
      comparisonValidityRate: 0.91,
      conformancePassRate: 0.88,
      protectedSplitPassRate: 1,
      rollbackReadinessRate: 1,
    },
    topFindings: [
      "Local smoke baseline remains coverage-light and blocks promotion on missing families.",
      "Latency and resource pressure are acceptable for consumer hardware, but retained capability coverage is still sparse.",
    ],
  });

  baselinePreset.scorecards.baseModelQuality = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "medium",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(baselinePreset.scorecards.baseModelQuality.metrics, {
      benchmarkCount: 2,
      normalizedScore: 0.54,
      passRate: 0.57,
    }),
  };
  baselinePreset.scorecards.toolApiReliability = {
    available: false,
    reason: "Tool/API screening pack not yet wired for this retained local baseline.",
    comparisonStatus: "not_comparable",
    confidenceClass: "low",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(baselinePreset.scorecards.toolApiReliability.metrics, {
      benchmarkCount: 0,
    }),
  };
  baselinePreset.scorecards.generalAgentQuality = {
    available: false,
    reason: "General-agent public screening pack is not yet retained for this baseline.",
    comparisonStatus: "not_comparable",
    confidenceClass: "low",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(baselinePreset.scorecards.generalAgentQuality.metrics, {
      benchmarkCount: 0,
    }),
  };
  baselinePreset.scorecards.operationalDiscipline = {
    available: true,
    reason: "",
    comparisonStatus: "caution",
    confidenceClass: "medium",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(baselinePreset.scorecards.operationalDiscipline.metrics, {
      conformancePassRate: 0.88,
      comparisonValidityRate: 0.91,
      protectedSplitPassRate: 1,
      rollbackReadinessRate: 1,
    }),
  };

  const workstationPreset = clonePreset(basePreset, {
    presetId: "local-workstation-candidate",
    label: "Workstation local candidate",
    role: "local_candidate",
    experimental: true,
    shippedDefault: false,
    deploymentProfile: "local_workstation",
    availabilityStatus: "ready",
    runtimeModel: "local-32b-instruct",
    artifactAcceptanceModel: "local-14b-judge",
    caseCount: 24,
    comparisonContext: {
      comparisonIntent: "model_change",
      executionScope: "fleet_shared",
      baselinePresetId: baselinePreset.presetId,
      manifestPath: "/tmp/retained/run-manifest.json",
    },
    roleAssignments: [
      { roleId: "planner", modelId: "local-32b-instruct", modalityUse: "text_tools" },
      { roleId: "verifier", modelId: "local-14b-judge", modalityUse: "artifact_review" },
    ],
    conformanceSummary: {
      status: "pass",
      comparisonValidityRate: 1,
      conformancePassRate: 0.97,
      protectedSplitPassRate: 1,
      rollbackReadinessRate: 1,
    },
    topFindings: [
      "Best promotable local option across required families with complete retained coverage.",
      "Improves coding, research, and computer-use lanes without regressing operational discipline.",
    ],
  });

  workstationPreset.scorecards.baseModelQuality = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "medium",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(workstationPreset.scorecards.baseModelQuality.metrics, {
      benchmarkCount: 3,
      normalizedScore: 0.72,
      passRate: 0.74,
    }),
  };
  workstationPreset.scorecards.artifactQuality = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(workstationPreset.scorecards.artifactQuality.metrics, {
      benchmarkCount: 6,
      averageJudgeScore: 0.84,
      verifierPassRate: 0.79,
      averageRepairLoopIterations: 1.2,
      routeMatchRate: 0.91,
    }),
  };
  workstationPreset.scorecards.codingCompletion = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(workstationPreset.scorecards.codingCompletion.metrics, {
      benchmarkCount: 5,
      taskPassRate: 0.62,
      targetedTestPassRate: 0.71,
      verifierPassRate: 0.83,
    }),
  };
  workstationPreset.scorecards.researchQuality = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(workstationPreset.scorecards.researchQuality.metrics, {
      benchmarkCount: 4,
      citationVerifierPassRate: 0.74,
      sourceIndependenceRate: 0.81,
      synthesisCompleteness: 0.77,
    }),
  };
  workstationPreset.scorecards.computerUseCompletion = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(workstationPreset.scorecards.computerUseCompletion.metrics, {
      benchmarkCount: 4,
      rewardFloorPassRate: 0.66,
      postconditionPassRate: 0.72,
      meanStepCount: 19,
    }),
  };
  workstationPreset.scorecards.toolApiReliability = {
    available: true,
    reason: "",
    comparisonStatus: "caution",
    confidenceClass: "medium",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(workstationPreset.scorecards.toolApiReliability.metrics, {
      benchmarkCount: 2,
      normalizedScore: 0.67,
      taskPassRate: 0.69,
      policyPassRate: 0.94,
    }),
  };
  workstationPreset.scorecards.generalAgentQuality = {
    available: true,
    reason: "",
    comparisonStatus: "caution",
    confidenceClass: "medium",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(workstationPreset.scorecards.generalAgentQuality.metrics, {
      benchmarkCount: 2,
      normalizedScore: 0.7,
      taskPassRate: 0.71,
      reasoningPassRate: 0.73,
    }),
  };
  workstationPreset.scorecards.latencyAndResourcePressure = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(workstationPreset.scorecards.latencyAndResourcePressure.metrics, {
      meanWallClockMs: 18400,
      p95WallClockMs: 31200,
      residentModelBytes: 18400000000,
      processorKind: "consumer_gpu",
    }),
  };
  workstationPreset.scorecards.operationalDiscipline = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(workstationPreset.scorecards.operationalDiscipline.metrics, {
      conformancePassRate: 0.97,
      comparisonValidityRate: 1,
      protectedSplitPassRate: 1,
      rollbackReadinessRate: 1,
    }),
  };

  const cloudPreset = clonePreset(basePreset, {
    presetId: "blind-cloud-candidate",
    label: "Blind cloud candidate",
    role: "cloud_candidate",
    experimental: true,
    shippedDefault: false,
    deploymentProfile: "blind_cloud_standard",
    availabilityStatus: "ready",
    runtimeModel: "blind-cloud-max",
    artifactAcceptanceModel: "blind-cloud-judge",
    caseCount: 24,
    comparisonContext: {
      comparisonIntent: "full_stack_change",
      executionScope: "fleet_shared",
      baselinePresetId: baselinePreset.presetId,
      manifestPath: "/tmp/retained/run-manifest.json",
    },
    roleAssignments: [
      { roleId: "planner", modelId: "blind-cloud-max", modalityUse: "text_tools" },
      { roleId: "verifier", modelId: "blind-cloud-judge", modalityUse: "artifact_review" },
      { roleId: "researcher", modelId: "blind-cloud-max", modalityUse: "web_research" },
    ],
    conformanceSummary: {
      status: "pass",
      comparisonValidityRate: 0.98,
      conformancePassRate: 0.95,
      protectedSplitPassRate: 1,
      rollbackReadinessRate: 1,
    },
    topFindings: [
      "Current leader on required families, but not the local default because deployment-profile promotion is still separated.",
      "Highest retained artifact and research quality with strong computer-use recovery and lower wall-clock time.",
    ],
  });

  cloudPreset.scorecards.baseModelQuality = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(cloudPreset.scorecards.baseModelQuality.metrics, {
      benchmarkCount: 3,
      normalizedScore: 0.86,
      passRate: 0.87,
    }),
  };
  cloudPreset.scorecards.artifactQuality = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(cloudPreset.scorecards.artifactQuality.metrics, {
      benchmarkCount: 6,
      averageJudgeScore: 0.91,
      verifierPassRate: 0.88,
      averageRepairLoopIterations: 0.7,
      routeMatchRate: 0.95,
    }),
  };
  cloudPreset.scorecards.codingCompletion = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(cloudPreset.scorecards.codingCompletion.metrics, {
      benchmarkCount: 5,
      taskPassRate: 0.74,
      targetedTestPassRate: 0.82,
      verifierPassRate: 0.9,
    }),
  };
  cloudPreset.scorecards.researchQuality = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(cloudPreset.scorecards.researchQuality.metrics, {
      benchmarkCount: 4,
      citationVerifierPassRate: 0.86,
      sourceIndependenceRate: 0.9,
      synthesisCompleteness: 0.88,
    }),
  };
  cloudPreset.scorecards.computerUseCompletion = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(cloudPreset.scorecards.computerUseCompletion.metrics, {
      benchmarkCount: 4,
      rewardFloorPassRate: 0.79,
      postconditionPassRate: 0.83,
      meanStepCount: 15,
    }),
  };
  cloudPreset.scorecards.toolApiReliability = {
    available: true,
    reason: "",
    comparisonStatus: "caution",
    confidenceClass: "high",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(cloudPreset.scorecards.toolApiReliability.metrics, {
      benchmarkCount: 2,
      normalizedScore: 0.8,
      taskPassRate: 0.82,
      policyPassRate: 0.96,
    }),
  };
  cloudPreset.scorecards.generalAgentQuality = {
    available: true,
    reason: "",
    comparisonStatus: "caution",
    confidenceClass: "high",
    coverageClass: "partial",
    benchmarkPrograms: ["public_screening"],
    metrics: withMetrics(cloudPreset.scorecards.generalAgentQuality.metrics, {
      benchmarkCount: 2,
      normalizedScore: 0.83,
      taskPassRate: 0.84,
      reasoningPassRate: 0.88,
    }),
  };
  cloudPreset.scorecards.latencyAndResourcePressure = {
    available: true,
    reason: "",
    comparisonStatus: "comparable",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(cloudPreset.scorecards.latencyAndResourcePressure.metrics, {
      meanWallClockMs: 6200,
      p95WallClockMs: 14100,
      residentModelBytes: null,
      processorKind: "remote_service",
    }),
  };
  cloudPreset.scorecards.operationalDiscipline = {
    available: true,
    reason: "",
    comparisonStatus: "caution",
    confidenceClass: "high",
    coverageClass: "full",
    benchmarkPrograms: ["repo_native_retained"],
    metrics: withMetrics(cloudPreset.scorecards.operationalDiscipline.metrics, {
      conformancePassRate: 0.95,
      comparisonValidityRate: 0.98,
      protectedSplitPassRate: 1,
      rollbackReadinessRate: 1,
    }),
  };

  return {
    ...data,
    agentModelMatrix: {
      ...matrix,
      status: "active",
      decision: {
        ...matrix.decision,
        outcome: "leader_not_promotable",
        summary:
          "Blind cloud candidate leads on required benchmark families, while workstation local candidate is the top promotable local option and the shipped local default remains preserved by deployment profile.",
        leaderPresetId: cloudPreset.presetId,
        artifactLeaderPresetId: cloudPreset.presetId,
        missingCoverage: [],
      },
      runManifest: {
        comparisonIntent: "full_stack_change",
        executionScope: "fleet_shared",
      },
      plannedPresetCount: 3,
      summarizedPresetCount: 3,
      fullyCompletedPresetCount: 3,
      comparedPresetCount: 3,
      executedPresetCount: 3,
      preservedDefault: true,
      deploymentDecisions: [
        deploymentDecision(
          "local_cpu_consumer",
          "CPU consumer",
          "local_only",
          "No retained preset has been benchmarked for this deployment profile yet.",
        ),
        deploymentDecision(
          "local_gpu_8gb_class",
          "8GB-class local",
          "local_only",
          "Current retained default for this deployment profile.",
          {
            state: "default",
            defaultPresetId: baselinePreset.presetId,
            leaderPresetId: baselinePreset.presetId,
            coverageGaps: [
              "codingCompletion",
              "researchQuality",
              "computerUseCompletion",
              "operationalDiscipline",
            ],
          },
        ),
        deploymentDecision(
          "local_gpu_16gb_class",
          "16GB-class local",
          "local_only",
          "No retained preset has been benchmarked for this deployment profile yet.",
        ),
        deploymentDecision(
          "local_workstation",
          "Workstation local",
          "local_only",
          "Current leading candidate for this deployment profile.",
          {
            state: "candidate",
            leaderPresetId: workstationPreset.presetId,
            challengerPresetId: workstationPreset.presetId,
            coverageGaps: [],
          },
        ),
        deploymentDecision(
          "hybrid_privacy_preserving",
          "Hybrid private",
          "hybrid",
          "No retained preset has been benchmarked for this deployment profile yet.",
        ),
        deploymentDecision(
          "blind_cloud_standard",
          "Blind cloud",
          "blind_cloud",
          "Blind-cloud leaders remain shadow-scoped and cannot silently replace local defaults.",
          {
            state: "shadow_only",
            leaderPresetId: cloudPreset.presetId,
            challengerPresetId: cloudPreset.presetId,
            coverageGaps: [],
          },
        ),
        deploymentDecision(
          "blind_cloud_premium",
          "Blind cloud premium",
          "blind_cloud",
          "No retained preset has been benchmarked for this deployment profile yet.",
        ),
      ],
      candidateLedger: [
        {
          candidateId: `candidate:${baselinePreset.presetId}`,
          candidateKind: "model",
          parentCandidateId: null,
          presetId: baselinePreset.presetId,
          deploymentProfile: "local_gpu_8gb_class",
          comparisonIntent: "baseline_anchor",
          executionScope: "fleet_shared",
          status: "retained_default",
          summary:
            "Current default anchor kept in place while stronger candidates continue to be validated.",
          mutationIntent:
            "Stabilize low-footprint local behavior and hold the baseline until a cleaner successor exists.",
          targetFamily: "Artifact / Latency",
          changedContracts: [
            "default preservation",
            "coverage guard",
            "latency/resource fit",
          ],
          validationSummary: {
            requiredReadyCount: 2,
            requiredCategoryCount: 6,
            bestRequiredCount: 1,
            coverageStatus: "4 blocked",
          },
          evaluationLanes: {
            proxy: "retained",
            validation: "retained",
            challenge: "not_run",
            holdout: "protected_not_run",
          },
          conformanceStatus: "warn",
          paretoClass: "retained",
          controlRunIds: [],
          rollbackTarget: null,
          regressions: baselinePreset.topFindings.slice(0, 2),
          evidenceLinks: [
            { label: "summary", href: baselinePreset.summaryHref },
            { label: "retained_run", href: baselinePreset.runRootHref },
          ],
        },
        {
          candidateId: `candidate:${workstationPreset.presetId}`,
          candidateKind: "model",
          parentCandidateId: `candidate:${baselinePreset.presetId}`,
          presetId: workstationPreset.presetId,
          deploymentProfile: "local_workstation",
          comparisonIntent: "model_change",
          executionScope: "fleet_shared",
          status: "promotable",
          summary:
            "Strongest retained local candidate on richer hardware tiers with honest required-family coverage.",
          mutationIntent:
            "Raise cross-vertical completion on stronger local hardware without introducing fallback hacks.",
          targetFamily: "Artifact / Coding / Research / Computer use / Latency",
          changedContracts: [
            "role-model assignment",
            "verification policy",
            "recovery loop",
          ],
          roleAssignmentDelta: ["planner", "verifier"],
          validationSummary: {
            requiredReadyCount: 6,
            requiredCategoryCount: 6,
            bestRequiredCount: 3,
            coverageStatus: "clear",
          },
          evaluationLanes: {
            proxy: "retained",
            validation: "retained",
            challenge: "queued",
            holdout: "protected_not_run",
          },
          conformanceStatus: "pass",
          paretoClass: "pareto_improving",
          controlRunIds: ["control:local-baseline-anchor"],
          rollbackTarget: `candidate:${baselinePreset.presetId}`,
          regressions: workstationPreset.topFindings.slice(0, 2),
          evidenceLinks: [
            { label: "summary", href: workstationPreset.summaryHref },
            { label: "retained_run", href: workstationPreset.runRootHref },
          ],
        },
        {
          candidateId: `candidate:${cloudPreset.presetId}`,
          candidateKind: "model",
          parentCandidateId: `candidate:${baselinePreset.presetId}`,
          presetId: cloudPreset.presetId,
          deploymentProfile: "blind_cloud_standard",
          comparisonIntent: "full_stack_change",
          executionScope: "fleet_shared",
          status: "shadow_winner",
          summary:
            "Highest retained score overall, but intentionally held in shadow because blind-cloud posture cannot silently replace local defaults.",
          mutationIntent:
            "Use higher-tier remote model conscription while keeping trust posture and promotion boundaries explicit.",
          targetFamily: "Artifact / Coding / Research / Computer use / Latency",
          changedContracts: [
            "role-model assignment",
            "blind-cloud routing",
            "validation gates",
          ],
          roleAssignmentDelta: ["planner", "verifier", "researcher"],
          validationSummary: {
            requiredReadyCount: 6,
            requiredCategoryCount: 6,
            bestRequiredCount: 5,
            coverageStatus: "clear",
          },
          evaluationLanes: {
            proxy: "retained",
            validation: "retained",
            challenge: "queued",
            holdout: "protected_not_run",
          },
          conformanceStatus: "pass",
          paretoClass: "pareto_improving",
          controlRunIds: ["control:local-baseline-anchor"],
          rollbackTarget: `candidate:${baselinePreset.presetId}`,
          regressions: cloudPreset.topFindings.slice(0, 2),
          evidenceLinks: [
            { label: "summary", href: cloudPreset.summaryHref },
            { label: "retained_run", href: cloudPreset.runRootHref },
          ],
        },
      ],
      presets: [baselinePreset, workstationPreset, cloudPreset],
    },
  };
}
