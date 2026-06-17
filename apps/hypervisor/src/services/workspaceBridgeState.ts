import type { HypervisorClientRuntime } from "./HypervisorClientRuntime";
import { buildHypervisorAppearanceBridgeState } from "./hypervisorAppearance";
import type { AgentTask, ChatMessage, SessionSummary } from "../types";
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

function rejectionMessage(result: PromiseSettledResult<unknown>, label: string) {
  if (result.status !== "rejected") {
    return null;
  }
  const reason = result.reason;
  return {
    label,
    message: reason instanceof Error ? reason.message : String(reason ?? "Unknown error"),
  };
}

function projectWorkspaceChatTurn(message: ChatMessage, index: number) {
  return {
    id: `turn:${index}:${message.timestamp}`,
    role: message.role,
    text: message.text,
    timestamp: message.timestamp,
  };
}

function projectWorkspaceChatState(
  projection: { task: AgentTask | null; sessions: SessionSummary[] } | null,
) {
  const task = projection?.task ?? null;
  const turns = (task?.history ?? [])
    .filter((message) => message.role !== "system")
    .slice(-12)
    .map(projectWorkspaceChatTurn);

  return {
    runtime: "ioi-runtime",
    authority: "bounded",
    helperText:
      "Workspace actions route back into the IOI runtime. Views here are projections only.",
    activeSessionId: task?.session_id ?? task?.id ?? null,
    phase: task?.phase ?? null,
    currentStep: task?.current_step ?? null,
    hasActiveConversation: turns.length > 0,
    turns,
    recentSessions: (projection?.sessions ?? []).slice(0, 6).map((session) => ({
      sessionId: session.session_id,
      title: session.title,
      phase: session.phase ?? null,
      currentStep: session.current_step ?? null,
      workspaceRoot: session.workspace_root ?? null,
      timestamp: session.timestamp,
    })),
  };
}

export async function buildWorkspaceBridgeState(
  runtime: HypervisorClientRuntime,
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
    sessionProjectionResult,
  ] = await Promise.allSettled([
    runtime.listWorkspaceWorkflows(),
    runtime.getConnectors(),
    runtime.getLocalEngineSnapshot(),
    runtime.getCapabilityRegistrySnapshot(),
    runtime.getRecentAssistantWorkbenchActivities?.(12) ?? Promise.resolve([]),
    runtime.getSessionProjection<AgentTask, SessionSummary>(),
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
  const sessionProjection =
    sessionProjectionResult.status === "fulfilled"
      ? sessionProjectionResult.value
      : null;
  const runInspections = buildWorkspaceRunInspections(
    localEngine?.parentPlaybookRuns ?? [],
  );
  const artifactInspections = buildWorkspaceArtifactInspections(activities);
  const policyInspection = buildWorkspacePolicyInspection(
    capabilitySnapshot?.summary ?? null,
  );
  const diagnostics = [
    rejectionMessage(workflowsResult, "workflows"),
    rejectionMessage(connectorsResult, "connections"),
    rejectionMessage(localEngineResult, "runs"),
    rejectionMessage(capabilitySnapshotResult, "policy"),
    rejectionMessage(activitiesResult, "artifacts"),
    rejectionMessage(sessionProjectionResult, "chat"),
  ].filter((item): item is { label: string; message: string } => item !== null);

  return {
    schemaVersion: 1,
    generatedAtMs: Date.now(),
    authoritativeRuntime: true,
    appearance: buildHypervisorAppearanceBridgeState(),
    workspace: {
      ...host.describeBridgeWorkspace(session, currentProject),
    },
    chat: projectWorkspaceChatState(sessionProjection),
    summary: {
      workflowCount: workflows.length,
      runCount: runInspections.length,
      artifactCount: artifactInspections.length,
      connectorCount: connectors.length,
      policyIssueCount: policyInspection?.activeIssueCount ?? 0,
      diagnosticCount: diagnostics.length,
    },
    diagnostics,
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
