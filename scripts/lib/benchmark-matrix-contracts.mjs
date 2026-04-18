const DEPLOYMENT_PROFILE_ALIAS_MAP = new Map([
  ["consumerLocal", "local_gpu_8gb_class"],
  ["consumer_local", "local_gpu_8gb_class"],
  ["workstationLocal", "local_workstation"],
  ["workstation_local", "local_workstation"],
  ["blindCloud", "blind_cloud_standard"],
  ["blind_cloud", "blind_cloud_standard"],
]);

export const DEPLOYMENT_PROFILES = [
  {
    id: "local_cpu_consumer",
    label: "CPU consumer",
    sublabel: "lowest-footprint local lane",
    trustPosture: "local_only",
    cloudEgressPosture: "forbidden",
    roleScope: "single-model local fallback",
  },
  {
    id: "local_gpu_8gb_class",
    label: "8GB-class local",
    sublabel: "constrained local GPU default",
    trustPosture: "local_only",
    cloudEgressPosture: "forbidden",
    roleScope: "single-model or compact split-role local",
  },
  {
    id: "local_gpu_16gb_class",
    label: "16GB-class local",
    sublabel: "stronger local GPU lane",
    trustPosture: "local_only",
    cloudEgressPosture: "forbidden",
    roleScope: "heavier local reasoning and tool loops",
  },
  {
    id: "local_workstation",
    label: "Workstation local",
    sublabel: "high-capacity local lane",
    trustPosture: "local_only",
    cloudEgressPosture: "forbidden",
    roleScope: "richer local role composition",
  },
  {
    id: "hybrid_privacy_preserving",
    label: "Hybrid private",
    sublabel: "mostly local with bounded remote help",
    trustPosture: "hybrid",
    cloudEgressPosture: "approved_bounded",
    roleScope: "local-first with explicit remote assists",
  },
  {
    id: "blind_cloud_standard",
    label: "Blind cloud",
    sublabel: "remote capacity with standard blind posture",
    trustPosture: "blind_cloud",
    cloudEgressPosture: "approved_blind",
    roleScope: "cloud-backed blind lane",
  },
  {
    id: "blind_cloud_premium",
    label: "Blind cloud premium",
    sublabel: "highest approved blind-cloud tier",
    trustPosture: "blind_cloud",
    cloudEgressPosture: "approved_blind",
    roleScope: "premium cloud-backed blind lane",
  },
];

export const DEPLOYMENT_PROFILE_IDS = DEPLOYMENT_PROFILES.map((profile) => profile.id);

export const SCORECARD_SCHEMA = {
  version: 2,
  categories: [
    {
      id: "baseModelQuality",
      label: "Base model",
      decisionWeight: "screening",
      requiredForPromotion: false,
      metrics: ["normalizedScore", "passRate", "benchmarkCount"],
    },
    {
      id: "artifactQuality",
      label: "Artifacts",
      decisionWeight: "required",
      requiredForPromotion: true,
      metrics: [
        "averageValidationScore",
        "verifierPassRate",
        "averageRepairLoopIterations",
        "routeMatchRate",
      ],
    },
    {
      id: "codingCompletion",
      label: "Coding",
      decisionWeight: "required",
      requiredForPromotion: true,
      metrics: [
        "taskPassRate",
        "targetedTestPassRate",
        "verifierPassRate",
      ],
    },
    {
      id: "researchQuality",
      label: "Research",
      decisionWeight: "required",
      requiredForPromotion: true,
      metrics: [
        "citationVerifierPassRate",
        "sourceIndependenceRate",
        "synthesisCompleteness",
      ],
    },
    {
      id: "computerUseCompletion",
      label: "Computer use",
      decisionWeight: "required",
      requiredForPromotion: true,
      metrics: [
        "rewardFloorPassRate",
        "postconditionPassRate",
        "meanStepCount",
      ],
    },
    {
      id: "toolApiReliability",
      label: "Tool/API",
      decisionWeight: "screening",
      requiredForPromotion: false,
      metrics: ["normalizedScore", "taskPassRate", "policyPassRate"],
    },
    {
      id: "generalAgentQuality",
      label: "General agent",
      decisionWeight: "screening",
      requiredForPromotion: false,
      metrics: ["normalizedScore", "taskPassRate", "reasoningPassRate"],
    },
    {
      id: "latencyAndResourcePressure",
      label: "Latency / resource",
      decisionWeight: "required",
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
      label: "Conformance / discipline",
      decisionWeight: "required",
      requiredForPromotion: true,
      metrics: [
        "conformancePassRate",
        "comparisonValidityRate",
        "protectedSplitPassRate",
        "rollbackReadinessRate",
      ],
    },
  ],
};

export const REQUIRED_DECISION_CATEGORY_IDS = SCORECARD_SCHEMA.categories
  .filter((category) => category.decisionWeight === "required")
  .map((category) => category.id);

export const SCORECARD_CATEGORY_ID_BY_FAMILY = {
  base_model: "baseModelQuality",
  artifacts: "artifactQuality",
  coding: "codingCompletion",
  research: "researchQuality",
  computer_use: "computerUseCompletion",
  tool_api: "toolApiReliability",
  general_agent: "generalAgentQuality",
};

export const FAILURE_ONTOLOGY = [
  "infra",
  "dependency",
  "routing",
  "observation",
  "tool_selection",
  "execution_contract",
  "recovery",
  "verification",
  "grounding",
  "quality",
  "latency_or_budget",
  "policy",
];

export const PUBLIC_BENCHMARK_PACKS = [
  {
    packId: "text_foundation_pack",
    label: "Text foundation",
    family: "base_model",
    decisionWeight: "screening",
  },
  {
    packId: "multimodal_foundation_pack",
    label: "Multimodal foundation",
    family: "base_model",
    decisionWeight: "screening",
  },
  {
    packId: "coding_agent_pack",
    label: "Coding agent",
    family: "coding",
    decisionWeight: "screening",
  },
  {
    packId: "computer_use_pack",
    label: "Computer use",
    family: "computer_use",
    decisionWeight: "screening",
  },
  {
    packId: "tool_api_pack",
    label: "Tool/API",
    family: "tool_api",
    decisionWeight: "screening",
  },
  {
    packId: "general_agent_pack",
    label: "General agent",
    family: "general_agent",
    decisionWeight: "screening",
  },
];

export const DEFAULT_CONFORMANCE_POLICY_IDS = [
  "comparison_intent_declared",
  "deployment_profile_declared",
  "split_visibility_respected",
  "no_implicit_cloud_promotion",
  "adapter_contract_declared",
];

export function normalizeDeploymentProfileId(value) {
  if (!value || typeof value !== "string") {
    return null;
  }
  if (DEPLOYMENT_PROFILE_IDS.includes(value)) {
    return value;
  }
  return DEPLOYMENT_PROFILE_ALIAS_MAP.get(value) ?? null;
}

export function deploymentProfileRecord(value) {
  const normalized = normalizeDeploymentProfileId(value);
  return DEPLOYMENT_PROFILES.find((profile) => profile.id === normalized) ?? null;
}

export function deploymentProfileLabel(value) {
  return deploymentProfileRecord(value)?.label ?? "Unknown deployment";
}

export function deploymentProfileSublabel(value) {
  return deploymentProfileRecord(value)?.sublabel ?? "undeclared deployment lane";
}

function parseModelSizeBillions(value) {
  const match = String(value ?? "").match(/(\d+(?:\.\d+)?)\s*b\b/i);
  if (!match) {
    return null;
  }
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) ? parsed : null;
}

export function deploymentProfileForPresetLike(preset) {
  const explicit = normalizeDeploymentProfileId(preset?.deploymentProfile);
  if (explicit) {
    return explicit;
  }

  const text = [
    preset?.benchmarkTier,
    preset?.role,
    preset?.label,
    preset?.runtimeModel,
    preset?.defaultRuntimeModel,
    preset?.routingIntent,
    ...(Array.isArray(preset?.workloadIntents) ? preset.workloadIntents : []),
    ...(Array.isArray(preset?.notes) ? preset.notes : []),
    ...(Array.isArray(preset?.autoHardwareProfiles)
      ? preset.autoHardwareProfiles
      : []),
  ]
    .filter((value) => typeof value === "string" && value.trim())
    .join(" ")
    .toLowerCase();

  if (
    preset?.runtimeKind === "remote_http" ||
    preset?.family === "remote_http" ||
    /\b(remote|cloud|blind)\b/.test(text)
  ) {
    return "blind_cloud_standard";
  }

  if (/\bhybrid\b/.test(text)) {
    return "hybrid_privacy_preserving";
  }

  if (/\b16gb-class\b/.test(text)) {
    return "local_gpu_16gb_class";
  }

  if (
    preset?.role === "baseline_local" ||
    preset?.benchmarkTier === "tier0" ||
    /\bcpu\b/.test(text)
  ) {
    return "local_cpu_consumer";
  }

  if (
    preset?.benchmarkTier === "tier1" ||
    /\b8gb-class\b/.test(text)
  ) {
    return "local_gpu_8gb_class";
  }

  const modelSize =
    parseModelSizeBillions(preset?.runtimeModel) ??
    parseModelSizeBillions(preset?.defaultRuntimeModel) ??
    parseModelSizeBillions(preset?.label);
  if (modelSize != null && modelSize <= 4) {
    return "local_cpu_consumer";
  }
  if (modelSize != null && modelSize <= 8) {
    return "local_gpu_8gb_class";
  }
  if (modelSize != null && modelSize <= 16) {
    return "local_gpu_16gb_class";
  }

  return "local_workstation";
}

export function scorecardCategoryRecord(categoryId) {
  return SCORECARD_SCHEMA.categories.find((category) => category.id === categoryId) ?? null;
}

export function scorecardDecisionWeight(categoryId) {
  return scorecardCategoryRecord(categoryId)?.decisionWeight ?? "supporting";
}

export function inferRoleAssignmentsForPreset(preset) {
  const runtimeModel = preset?.runtimeModel || preset?.defaultRuntimeModel || null;
  const validationModel = preset?.artifactAcceptanceModel || runtimeModel;
  const role = String(preset?.role || "").trim().toLowerCase();
  const assignments = [];

  function push(roleId, modelId, assignmentIntent, modalityUse = "text") {
    assignments.push({
      roleId,
      modelId,
      assignmentIntent,
      modalityUse,
      fallbackPolicy: "none_declared",
      simulationPolicy: "benchmark_only",
      validationPolicy: "retained_validation",
    });
  }

  if (role === "planner_verifier") {
    push("planner", runtimeModel, "shared planner lane");
    push("verifier", runtimeModel, "shared verifier lane");
    push("artifact_validation", validationModel, "artifact validation lane");
  } else if (role === "coding_executor") {
    push("coding_executor", runtimeModel, "repo-grounded patching lane");
    push("artifact_validation", validationModel, "artifact validation lane");
  } else if (role === "multimodal_realtime") {
    push("planner", runtimeModel, "remote planner lane");
    push("perception_worker", runtimeModel, "multimodal perception lane", "vision");
    push("speech_worker", runtimeModel, "realtime speech lane", "audio");
  } else {
    push("planner", runtimeModel, "baseline shared lane");
    push("artifact_validation", validationModel, "artifact validation lane");
  }

  return assignments;
}
