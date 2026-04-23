import type {
  ChatArtifactManifest,
  ChatArtifactRenderEvaluation,
  ChatArtifactSelectedSkill,
  ChatArtifactValidationResult,
} from "../types";

export type RuntimeInspectionTone =
  | "ready"
  | "attention"
  | "running"
  | "completed"
  | "unknown";

export type RuntimeUiTone = "pass" | "warn" | "fail" | "idle";
export type RuntimeValidationStatus =
  | "verified"
  | "running"
  | "waiting"
  | "missing"
  | "error";

export type ArtifactVerificationInspection = {
  headline: string;
  summary: string;
  productionLabel: string;
  acceptanceLabel: string;
  tone: RuntimeInspectionTone;
};

export type ArtifactValidationInspection = {
  headline: string;
  summary: string;
  scoreLine: string | null;
  nextPass: string | null;
  obligationLine: string;
  tone: RuntimeInspectionTone;
};

export type ArtifactDeliveryInspection = {
  headline: string;
  summary: string;
  revisionLine: string;
  repairLine: string | null;
  activeRoleLine: string | null;
  workspaceDetail: string | null;
  tone: RuntimeInspectionTone;
};

export type ArtifactContextInspection = {
  headline: string;
  summary: string;
};

export function normalizeRunInspectionStatus(status: string | null | undefined) {
  const normalized = (status ?? "unknown").toLowerCase();
  if (normalized === "running") {
    return "running" as const;
  }
  if (normalized === "failed" || normalized === "blocked") {
    return "attention" as const;
  }
  if (normalized === "completed") {
    return "completed" as const;
  }
  return "unknown" as const;
}

export function normalizeArtifactInspectionStatus(status: string | null | undefined) {
  const normalized = (status ?? "unknown").toLowerCase();
  if (
    normalized === "completed" ||
    normalized === "verified" ||
    normalized === "succeeded"
  ) {
    return "ready" as const;
  }
  if (normalized === "running" || normalized === "started") {
    return "running" as const;
  }
  if (normalized === "failed" || normalized === "blocked" || normalized === "error") {
    return "attention" as const;
  }
  return "unknown" as const;
}

export function toneForRuntimeStatus(status: string | null | undefined): RuntimeUiTone {
  const normalized = (status ?? "unknown").trim().toLowerCase();
  if (
    normalized === "pass" ||
    normalized === "completed" ||
    normalized === "success" ||
    normalized === "succeeded" ||
    normalized === "verified" ||
    normalized === "ready"
  ) {
    return "pass";
  }
  if (
    normalized === "red" ||
    normalized === "failure" ||
    normalized === "failed" ||
    normalized === "blocked" ||
    normalized === "error" ||
    normalized === "attention"
  ) {
    return "fail";
  }
  if (
    normalized === "active" ||
    normalized === "warning" ||
    normalized === "partial" ||
    normalized === "running" ||
    normalized === "repairable" ||
    normalized === "waiting"
  ) {
    return "warn";
  }
  return "idle";
}

export function formatRuntimeStatusLabel(status: string | null | undefined) {
  if (!status) {
    return "Unknown";
  }

  return status
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

export function formatInspectionCount(count: number, singular: string, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function buildArtifactVerificationInspection(
  manifest: ChatArtifactManifest,
  formatRuntimeProvenance: (value: ChatArtifactManifest["verification"]["productionProvenance"]) => string,
): ArtifactVerificationInspection {
  return {
    headline: manifest.verification.failure ? "Verification blocked" : "Verification retained",
    summary: manifest.verification.summary,
    productionLabel: formatRuntimeProvenance(manifest.verification.productionProvenance),
    acceptanceLabel: formatRuntimeProvenance(manifest.verification.acceptanceProvenance),
    tone: manifest.verification.failure ? "attention" : "ready",
  };
}

export function buildArtifactValidationInspection(
  validation: ChatArtifactValidationResult | null | undefined,
  evaluation: ChatArtifactRenderEvaluation | null | undefined,
  formatStatusLabel: (value: string | null | undefined) => string,
): ArtifactValidationInspection {
  const required =
    evaluation?.acceptanceObligations?.filter((obligation) => obligation.required) ?? [];
  const cleared = required.filter((obligation) => obligation.status === "passed").length;
  const failed = required.filter(
    (obligation) =>
      obligation.status === "failed" || obligation.status === "blocked",
  ).length;

  return {
    headline: validation ? formatStatusLabel(validation.classification) : "Validation pending",
    summary: validation?.rationale ?? "No validation result is attached yet.",
    scoreLine: validation
      ? `Faithfulness ${validation.requestFaithfulness}/5 · Layout ${validation.layoutCoherence}/5 · Completeness ${validation.completeness}/5`
      : null,
    nextPass: validation?.recommendedNextPass ?? null,
    obligationLine:
      required.length > 0
        ? `${cleared}/${required.length} required obligations cleared${failed > 0 ? ` · ${failed} unresolved` : ""}`
        : "Execution-witness obligation counts pending",
    tone:
      validation?.classification === "pass"
        ? "ready"
        : validation
          ? "attention"
          : "unknown",
  };
}

export function buildArtifactDeliveryInspection(input: {
  hasSwarmExecution: boolean;
  adapterLabel?: string | null;
  completedWorkItems?: number | null;
  totalWorkItems?: number | null;
  evidenceCount: number;
  receiptCount: number;
  revisionCount: number;
  winningCandidateId?: string | null;
  winningCandidateRationale?: string | null;
  obligationLine: string;
  repairPassCount: number;
  activeWorkerRole?: string | null;
  workspaceDetail?: string | null;
  formatStatusLabel: (value: string | null | undefined) => string;
}): ArtifactDeliveryInspection {
  const headline = input.hasSwarmExecution
    ? `${formatInspectionCount(input.completedWorkItems ?? 0, "worker receipt")} · ${formatInspectionCount(input.receiptCount, "receipt")}`
    : `${formatInspectionCount(input.evidenceCount, "file")} · ${formatInspectionCount(input.receiptCount, "receipt")}`;

  const summary = input.hasSwarmExecution
    ? `${input.adapterLabel ?? "Swarm"} · ${input.completedWorkItems ?? 0}/${input.totalWorkItems ?? 0} work items completed`
    : input.winningCandidateId
      ? `Winner ${input.winningCandidateId}${input.winningCandidateRationale ? ` · ${input.winningCandidateRationale}` : ""}`
      : "Winning candidate not recorded yet.";

  return {
    headline,
    summary,
    revisionLine: `${formatInspectionCount(input.revisionCount, "revision")} · ${input.obligationLine}`,
    repairLine:
      input.repairPassCount > 0
        ? `${input.repairPassCount} bounded repair attempt${input.repairPassCount === 1 ? "" : "s"} recorded separately from acceptance truth.`
        : null,
    activeRoleLine: input.activeWorkerRole
      ? `Active role: ${input.formatStatusLabel(input.activeWorkerRole)}`
      : null,
    workspaceDetail: input.workspaceDetail ?? null,
    tone: input.hasSwarmExecution ? "running" : "ready",
  };
}

export function buildArtifactContextInspection(input: {
  selectedSkills: ChatArtifactSelectedSkill[];
  subjectDomain?: string | null;
  artifactThesis?: string | null;
  tasteSummary?: string | null;
}): ArtifactContextInspection {
  const headline = input.selectedSkills.length
    ? `${formatInspectionCount(input.selectedSkills.length, "skill")} selected`
    : input.subjectDomain ?? "Context pending";

  return {
    headline,
    summary: input.artifactThesis ?? input.tasteSummary ?? "Artifact thesis pending.",
  };
}
