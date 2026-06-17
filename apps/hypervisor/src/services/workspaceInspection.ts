import {
  normalizeArtifactInspectionStatus,
  normalizeRunInspectionStatus,
} from "./runtimeInspection";

type ActivityLike = {
  activityId: string;
  sessionKind?: string | null;
  surface?: string | null;
  action?: string | null;
  status?: string | null;
  message?: string | null;
  timestampMs?: number | null;
  connectorId?: string | null;
  evidenceThreadId?: string | null;
};

type ParentPlaybookRunLike = {
  runId: string;
  parentSessionId: string;
  playbookLabel?: string | null;
  playbookId?: string | null;
  status?: string | null;
  currentStepLabel?: string | null;
  currentStepId?: string | null;
  activeChildSessionId?: string | null;
  startedAtMs?: number | null;
  summary?: string | null;
  steps?: Array<{
    stepId: string;
    receipts?: Array<{
      artifactIds: string[];
    }>;
  }>;
};

type CapabilitySummaryLike = {
  totalEntries: number;
  connectorCount: number;
  connectedConnectorCount: number;
  runtimeSkillCount: number;
  authoritativeSourceCount: number;
  activeIssueCount: number;
};

export type WorkspaceArtifactInspection = {
  artifactId: string;
  title: string;
  summary: string;
  status: "ready" | "attention" | "running" | "unknown";
  evidenceThreadId: string | null;
  connectorId: string | null;
  timestampMs: number | null;
};

export type WorkspaceRunInspection = {
  runId: string;
  title: string;
  summary: string;
  status: "completed" | "attention" | "running" | "unknown";
  currentStepLabel: string | null;
  parentSessionId: string;
  activeChildSessionId: string | null;
  reviewSessionId: string;
  artifactId: string | null;
  startedAtMs: number | null;
};

export type WorkspacePolicyInspection = {
  totalEntries: number;
  connectorCount: number;
  connectedConnectorCount: number;
  runtimeSkillCount: number;
  authoritativeSourceCount: number;
  activeIssueCount: number;
  overallStatus: "ready" | "attention";
};

export function buildWorkspaceArtifactInspections(
  activities: ActivityLike[],
): WorkspaceArtifactInspection[] {
  return activities.slice(0, 12).map((activity) => ({
    artifactId: activity.activityId,
    title: activity.action || activity.sessionKind || "Artifact",
    summary: activity.message || "Evidence-linked activity",
    status: normalizeArtifactInspectionStatus(activity.status),
    evidenceThreadId: activity.evidenceThreadId ?? null,
    connectorId: activity.connectorId ?? null,
    timestampMs: activity.timestampMs ?? null,
  }));
}

export function buildWorkspaceRunInspections(
  runs: ParentPlaybookRunLike[],
): WorkspaceRunInspection[] {
  return runs.slice(0, 10).map((run) => {
    const currentStep =
      run.steps?.find((step) => step.stepId === run.currentStepId) ?? null;
    const artifactId =
      currentStep?.receipts?.flatMap((receipt) => receipt.artifactIds).find(Boolean) ?? null;
    const reviewSessionId = run.activeChildSessionId?.trim() || run.parentSessionId;
    return {
      runId: run.runId,
      title: run.playbookLabel || run.playbookId || run.runId,
      summary: run.currentStepLabel?.trim() || run.summary?.trim() || run.playbookId || "Runtime run",
      status: normalizeRunInspectionStatus(run.status),
      currentStepLabel: run.currentStepLabel ?? null,
      parentSessionId: run.parentSessionId,
      activeChildSessionId: run.activeChildSessionId ?? null,
      reviewSessionId,
      artifactId,
      startedAtMs: run.startedAtMs ?? null,
    };
  });
}

export function buildWorkspacePolicyInspection(
  summary: CapabilitySummaryLike | null | undefined,
): WorkspacePolicyInspection | null {
  if (!summary) {
    return null;
  }

  return {
    totalEntries: summary.totalEntries,
    connectorCount: summary.connectorCount,
    connectedConnectorCount: summary.connectedConnectorCount,
    runtimeSkillCount: summary.runtimeSkillCount,
    authoritativeSourceCount: summary.authoritativeSourceCount,
    activeIssueCount: summary.activeIssueCount,
    overallStatus: summary.activeIssueCount > 0 ? "attention" : "ready",
  };
}
