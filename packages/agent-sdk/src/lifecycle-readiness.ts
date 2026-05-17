export const AUTONOMOUS_SYSTEM_MANIFEST_SCHEMA_VERSION =
  "ioi.autonomous-system-manifest.v1" as const;

export const WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION =
  "ioi.workflow.lifecycle-readiness.v1" as const;

export const WORKFLOW_LIFECYCLE_LOOP = [
  "compose",
  "bind",
  "simulate",
  "authorize",
  "run",
  "verify",
  "inspect_receipts",
  "package",
  "deploy",
  "promote",
  "improve",
] as const;

export type WorkflowLifecycleReadinessKind =
  | "run"
  | "authority"
  | "package"
  | "evaluation"
  | "deployment"
  | "promotion";

export type WorkflowLifecycleReadinessStatus =
  | "ready"
  | "blocked"
  | "warning";

export interface AutonomousSystemManifestProfile {
  schemaVersion?: string;
  systemId?: string;
  manifestId?: string;
  displayName?: string;
  status?: string;
  worker?: {
    workerRef?: string | null;
    responsibility?: string | null;
    ownerRef?: string | null;
  };
  workflow?: {
    workflowManifestRef?: string | null;
    harnessRef?: string | null;
    topologyHash?: string | null;
  };
  capabilities?: {
    modelCapabilityRefs?: string[];
    toolCapabilityRefs?: string[];
    connectorRefs?: string[];
    primitiveCapabilitiesRequired?: string[];
  };
  authority?: {
    authorityScopeRequirements?: string[];
    grantRequirements?: string[];
    approvalProfileRef?: string | null;
    policyProfileRef?: string | null;
    revocationPosture?: string | null;
  };
  runtimeProfiles?: Array<{
    profileId?: string;
    kind?: string;
    readiness?: string;
    cleanupPolicyRef?: string | null;
  }>;
  evaluation?: {
    evalProfileRefs?: string[];
    benchmarkRefs?: string[];
    qualityGateRefs?: string[];
    replayProfileRef?: string | null;
  };
  promotion?: {
    promotionProfileRef?: string | null;
    marketplaceExposureEligibility?: string | null;
    foundryLineageRefs?: string[];
    workerCardPreviewRef?: string | null;
  };
  receipts?: {
    packageReadinessReceiptRef?: string | null;
    latestRunReceiptRefs?: string[];
    latestEvalReceiptRefs?: string[];
  };
}

export interface WorkflowLifecycleReadinessCategory {
  kind: WorkflowLifecycleReadinessKind;
  label: string;
  status: WorkflowLifecycleReadinessStatus;
  blockingScope: string;
  summary: string;
  blockers: string[];
  warnings: string[];
  evidenceRefs: string[];
}

export interface AutonomousSystemLifecycleReadinessProjection {
  schemaVersion: typeof WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION;
  packageArtifact: "Autonomous System Package";
  lifecycleLoop: typeof WORKFLOW_LIFECYCLE_LOOP;
  systemId: string;
  manifest: AutonomousSystemManifestProfile;
  categories: WorkflowLifecycleReadinessCategory[];
  status: WorkflowLifecycleReadinessStatus;
  promotionGate: {
    status: WorkflowLifecycleReadinessStatus;
    requiredEvidence: string[];
    evidenceRefs: string[];
    blockers: string[];
  };
}

export function inspectAutonomousSystemLifecycleReadiness({
  manifest,
  evalEvidenceRefs = [],
}: {
  manifest: AutonomousSystemManifestProfile;
  evalEvidenceRefs?: string[];
}): AutonomousSystemLifecycleReadinessProjection {
  const categories = [
    runCategory(manifest),
    authorityCategory(manifest),
    packageCategory(manifest),
    evaluationCategory(manifest),
    deploymentCategory(manifest),
    promotionCategory(manifest, evalEvidenceRefs),
  ];
  const status = categories.some((category) => category.status === "blocked")
    ? "blocked"
    : categories.some((category) => category.status === "warning")
      ? "warning"
      : "ready";
  const promotion = categories.find(
    (category) => category.kind === "promotion",
  );
  const promotionEvidence = [
    ...strings(manifest.receipts?.latestEvalReceiptRefs),
    ...evalEvidenceRefs,
  ];

  return {
    schemaVersion: WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION,
    packageArtifact: "Autonomous System Package",
    lifecycleLoop: WORKFLOW_LIFECYCLE_LOOP,
    systemId: text(manifest.systemId) ?? "system://unidentified",
    manifest,
    categories,
    status,
    promotionGate: {
      status: promotion?.status ?? "blocked",
      requiredEvidence: ["eval_receipt", "quality_gate"],
      evidenceRefs: unique(promotionEvidence),
      blockers: promotion?.blockers ?? ["promotion readiness was not evaluated"],
    },
  };
}

function runCategory(
  manifest: AutonomousSystemManifestProfile,
): WorkflowLifecycleReadinessCategory {
  return category({
    kind: "run",
    label: "Run readiness",
    blockingScope: "Blocks Run",
    blockers: [
      ...missing(manifest.workflow?.workflowManifestRef, "workflow manifest ref missing"),
      ...missing(
        strings(manifest.capabilities?.modelCapabilityRefs).length,
        "model capability ref missing",
      ),
    ],
    readySummary: "Workflow and model capability slots are present.",
    blockedSummary: "Workflow or model capability slots are missing.",
  });
}

function authorityCategory(
  manifest: AutonomousSystemManifestProfile,
): WorkflowLifecycleReadinessCategory {
  return category({
    kind: "authority",
    label: "Authority readiness",
    blockingScope: "Blocks live effects",
    blockers: [
      ...missing(
        strings(manifest.authority?.authorityScopeRequirements).length,
        "authority scope requirements missing",
      ),
      ...missing(
        manifest.authority?.revocationPosture === "fail_closed",
        "revocation posture must fail closed",
      ),
    ],
    readySummary: "Authority scopes and fail-closed revocation posture are present.",
    blockedSummary: "Authority scopes or fail-closed posture are missing.",
  });
}

function packageCategory(
  manifest: AutonomousSystemManifestProfile,
): WorkflowLifecycleReadinessCategory {
  const toolCount =
    strings(manifest.capabilities?.toolCapabilityRefs).length +
    strings(manifest.capabilities?.connectorRefs).length;
  return category({
    kind: "package",
    label: "Package readiness",
    blockingScope: "Blocks package/publish",
    blockers: [
      ...missing(manifest.worker?.workerRef, "worker ref missing"),
      ...missing(manifest.workflow?.workflowManifestRef, "workflow manifest ref missing"),
      ...missing(
        strings(manifest.capabilities?.modelCapabilityRefs).length,
        "model capability refs missing",
      ),
      ...missing(toolCount, "tool or connector capability refs missing"),
      ...missing(
        strings(manifest.authority?.authorityScopeRequirements).length,
        "authority scope requirements missing",
      ),
    ],
    readySummary: "Manifest has worker, workflow, capabilities, and authority.",
    blockedSummary: "Manifest is still a draft package.",
  });
}

function evaluationCategory(
  manifest: AutonomousSystemManifestProfile,
): WorkflowLifecycleReadinessCategory {
  return category({
    kind: "evaluation",
    label: "Evaluation readiness",
    blockingScope: "Blocks promotion",
    blockers: [
      ...missing(
        strings(manifest.evaluation?.evalProfileRefs).length,
        "eval profile refs missing",
      ),
    ],
    readySummary: "Eval profile refs are bound.",
    blockedSummary: "No eval profile refs are bound.",
  });
}

function deploymentCategory(
  manifest: AutonomousSystemManifestProfile,
): WorkflowLifecycleReadinessCategory {
  const readyProfile = (manifest.runtimeProfiles ?? []).some((profile) =>
    ["ready", "degraded", "external"].includes(String(profile.readiness)),
  );
  return category({
    kind: "deployment",
    label: "Deployment readiness",
    blockingScope: "Blocks deploy",
    blockers: [...missing(readyProfile, "runtime profile missing")],
    readySummary: "Runtime/deployment profile slot is present.",
    blockedSummary: "Runtime/deployment profile slot is missing.",
  });
}

function promotionCategory(
  manifest: AutonomousSystemManifestProfile,
  evalEvidenceRefs: string[],
): WorkflowLifecycleReadinessCategory {
  const evalEvidence = [
    ...strings(manifest.receipts?.latestEvalReceiptRefs),
    ...evalEvidenceRefs,
  ];
  return category({
    kind: "promotion",
    label: "Promotion readiness",
    blockingScope: "Blocks promotion",
    blockers: [
      ...missing(
        strings(manifest.evaluation?.evalProfileRefs).length,
        "eval profile refs missing",
      ),
      ...missing(evalEvidence.length, "eval receipt evidence missing"),
      ...missing(
        text(manifest.promotion?.promotionProfileRef) ||
          strings(manifest.evaluation?.qualityGateRefs).length,
        "promotion profile or quality gate missing",
      ),
    ],
    evidenceRefs: unique(evalEvidence),
    readySummary: "Eval evidence and promotion gates are present.",
    blockedSummary: "Promotion needs eval evidence and a promotion gate.",
  });
}

function category({
  kind,
  label,
  blockingScope,
  blockers,
  warnings = [],
  evidenceRefs = [],
  readySummary,
  blockedSummary,
}: {
  kind: WorkflowLifecycleReadinessKind;
  label: string;
  blockingScope: string;
  blockers: string[];
  warnings?: string[];
  evidenceRefs?: string[];
  readySummary: string;
  blockedSummary: string;
}): WorkflowLifecycleReadinessCategory {
  const status =
    blockers.length > 0 ? "blocked" : warnings.length > 0 ? "warning" : "ready";
  return {
    kind,
    label,
    status,
    blockingScope,
    summary: status === "ready" ? readySummary : blockedSummary,
    blockers,
    warnings,
    evidenceRefs,
  };
}

function missing(value: unknown, message: string): string[] {
  return value ? [] : [message];
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values)).sort();
}
