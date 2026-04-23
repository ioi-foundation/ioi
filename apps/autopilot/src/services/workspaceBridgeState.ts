import type { TauriRuntime } from "./TauriRuntime";
import {
  buildWorkspaceArtifactInspections,
  buildWorkspacePolicyInspection,
  buildWorkspaceRunInspections,
} from "./workspaceInspection";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchProjectDescriptor,
  WorkspaceWorkbenchHostSession,
} from "./workspaceWorkbenchHost";

export async function buildWorkspaceBridgeState(
  runtime: TauriRuntime,
  host: WorkspaceWorkbenchHost,
  currentProject: WorkspaceWorkbenchProjectDescriptor,
  session: WorkspaceWorkbenchHostSession,
) {
  const [
    workflowsResult,
    connectorsResult,
    localEngineResult,
    capabilitySnapshotResult,
    activitiesResult,
  ] = await Promise.allSettled([
    runtime.listWorkspaceWorkflows(),
    runtime.getConnectors(),
    runtime.getLocalEngineSnapshot(),
    runtime.getCapabilityRegistrySnapshot(),
    runtime.getRecentAssistantWorkbenchActivities?.(12) ?? Promise.resolve([]),
  ]);

  const workflows =
    workflowsResult.status === "fulfilled" ? workflowsResult.value : [];
  const connectors =
    connectorsResult.status === "fulfilled" ? connectorsResult.value : [];
  const localEngine =
    localEngineResult.status === "fulfilled" ? localEngineResult.value : null;
  const capabilitySnapshot =
    capabilitySnapshotResult.status === "fulfilled"
      ? capabilitySnapshotResult.value
      : null;
  const activities =
    activitiesResult.status === "fulfilled" ? activitiesResult.value : [];
  const runInspections = buildWorkspaceRunInspections(
    localEngine?.parentPlaybookRuns ?? [],
  );
  const artifactInspections = buildWorkspaceArtifactInspections(activities);
  const policyInspection = buildWorkspacePolicyInspection(
    capabilitySnapshot?.summary ?? null,
  );

  return {
    schemaVersion: 1,
    generatedAtMs: Date.now(),
    authoritativeRuntime: true,
    workspace: {
      ...host.describeBridgeWorkspace(session, currentProject),
    },
    chat: {
      runtime: "ioi-runtime",
      authority: "bounded",
      helperText:
        "Workspace actions route back into the IOI runtime. Views here are projections only.",
    },
    workflows: workflows.map((workflow) => ({
      workflowId: workflow.workflowId,
      slashCommand: workflow.slashCommand,
      description: workflow.description,
      relativePath: workflow.relativePath,
      stepCount: workflow.stepCount,
      turboAll: workflow.turboAll,
    })),
    runs: runInspections.map((run) => ({
      runId: run.runId,
      label: run.title,
      status: run.status,
      currentStepLabel: run.currentStepLabel,
      startedAtMs: run.startedAtMs,
      summary: run.summary,
      parentSessionId: run.parentSessionId,
      activeChildSessionId: run.activeChildSessionId,
      reviewSessionId: run.reviewSessionId,
      artifactId: run.artifactId,
    })),
    artifacts: artifactInspections.map((artifact) => ({
      activityId: artifact.artifactId,
      action: artifact.title,
      status: artifact.status,
      message: artifact.summary,
      timestampMs: artifact.timestampMs,
      connectorId: artifact.connectorId,
      evidenceThreadId: artifact.evidenceThreadId,
    })),
    policy: policyInspection,
    connections: connectors.map((connector) => ({
      id: connector.id,
      name: connector.name,
      status: connector.status,
      summary: connector.notes ?? connector.description ?? "",
      kind: connector.category ?? null,
    })),
  };
}
