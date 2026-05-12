import type { WorkflowProject } from "../types/graph";

export interface WorkflowSettingsHarnessModelInput {
  workflow: WorkflowProject;
  blessedHarnessWorkflow: boolean;
  harnessWorkerExecutionMode?: string | null;
  liveReadyHarnessComponents: number;
  harnessComponentReadinessCount: number;
  gatedHarnessClusterCount: number;
  harnessPromotionClusterCount: number;
}

export interface WorkflowSettingsHarnessModel {
  templateLabel: "blessed" | "fork";
  activationLabel: string;
  modeLabel: string;
  componentCount: number;
  liveReadyLabel: string;
  gatedClustersLabel: string;
}

export function workflowSettingsHarnessModel({
  workflow,
  blessedHarnessWorkflow,
  harnessWorkerExecutionMode,
  liveReadyHarnessComponents,
  harnessComponentReadinessCount,
  gatedHarnessClusterCount,
  harnessPromotionClusterCount,
}: WorkflowSettingsHarnessModelInput): WorkflowSettingsHarnessModel {
  const harnessMetadata = workflow.metadata.harness;

  return {
    templateLabel: blessedHarnessWorkflow ? "blessed" : "fork",
    activationLabel:
      harnessMetadata?.activationId ??
      harnessMetadata?.activationState ??
      "blocked",
    modeLabel:
      harnessMetadata?.executionMode ??
      harnessWorkerExecutionMode ??
      "projection",
    componentCount: harnessMetadata?.componentIds?.length ?? 0,
    liveReadyLabel: `${liveReadyHarnessComponents}/${harnessComponentReadinessCount}`,
    gatedClustersLabel: `${gatedHarnessClusterCount}/${harnessPromotionClusterCount}`,
  };
}
