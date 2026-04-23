import type {
  WorkspaceExtensionsModel,
  WorkspaceOperatorModel,
  WorkspaceOperatorSurface,
  WorkspaceRunDebugModel,
} from "@ioi/workspace-substrate";
import type { ExtensionManifestRecord } from "../types";
import type { TauriRuntime } from "./TauriRuntime";
import {
  openRuntimeArtifactReview,
  openRuntimeBrowserAutomation,
  openRuntimeConnectionsOverview,
  openRuntimeEvidenceSession,
  openRuntimeFileReview,
  openRuntimePolicyView,
  openRuntimeRunReview,
  openRuntimeRunsView,
  openRuntimeWorkflowView,
} from "./runtimeChatNavigation";
import { buildWorkspaceBridgeState } from "./workspaceBridgeState";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchHostSession,
  WorkspaceWorkbenchProjectDescriptor,
} from "./workspaceWorkbenchHost";

export type DirectWorkspaceBridgeState = Awaited<
  ReturnType<typeof buildWorkspaceBridgeState>
>;

export async function loadDirectWorkspaceWorkbenchData(params: {
  runtime: TauriRuntime;
  host: WorkspaceWorkbenchHost;
  currentProject: WorkspaceWorkbenchProjectDescriptor;
  session: WorkspaceWorkbenchHostSession;
}): Promise<{
  bridgeState: DirectWorkspaceBridgeState;
  extensionManifests: ExtensionManifestRecord[];
}> {
  const [bridgeState, extensionManifests] = await Promise.all([
    buildWorkspaceBridgeState(
      params.runtime,
      params.host,
      params.currentProject,
      params.session,
    ),
    params.runtime.getExtensionManifests().catch(() => []),
  ]);

  return {
    bridgeState,
    extensionManifests,
  };
}

function statusDetailLabel(timestampMs: number | null | undefined): string | null {
  if (!timestampMs) {
    return null;
  }

  const timestamp = new Date(timestampMs);
  return timestamp.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function createRunDebugModel(params: {
  bridgeState: DirectWorkspaceBridgeState | null;
  runtime: TauriRuntime;
  rootPath: string;
  activeFilePath: string | null;
}): WorkspaceRunDebugModel {
  const runs = params.bridgeState?.runs ?? [];

  return {
    entries: runs.slice(0, 8).map((run) => ({
      id: run.runId,
      title: run.label,
      summary: run.summary || "Runtime run",
      status: run.status,
      detail: run.currentStepLabel || statusDetailLabel(run.startedAtMs),
      onSelect: () =>
        openRuntimeRunReview(params.runtime, {
          workspaceRoot: params.rootPath,
          filePath: params.activeFilePath,
          runId: run.runId,
          artifactId: run.artifactId ?? null,
          evidenceThreadId: run.reviewSessionId,
          source: "workspace-runtime",
        }),
    })),
    onOpenRunsSurface: () => openRuntimeRunsView(params.runtime),
  };
}

export function createExtensionsModel(params: {
  bridgeState: DirectWorkspaceBridgeState | null;
  extensionManifests: ExtensionManifestRecord[];
  runtime: TauriRuntime;
}): WorkspaceExtensionsModel {
  const primaryConnectorId = params.bridgeState?.connections[0]?.id ?? null;
  const statusForExtension = (
    extension: ExtensionManifestRecord,
  ): "enabled" | "available" | "attention" => {
    if (!extension.enabled) {
      return "available";
    }
    if (extension.trustPosture === "attention") {
      return "attention";
    }
    return "enabled";
  };
  const entries = params.extensionManifests.slice(0, 10).map((extension) => ({
    id: extension.extensionId,
    name: extension.displayName?.trim() || extension.name || extension.extensionId,
    description:
      extension.description?.trim() ||
      "Extension metadata is available through the direct runtime.",
    detail:
      [extension.version, extension.sourceLabel, extension.manifestKind]
        .filter(Boolean)
        .join(" · ") || null,
    status: statusForExtension(extension),
  }));

  return {
    entries,
    onOpenConnections: () =>
      openRuntimeConnectionsOverview(params.runtime, primaryConnectorId),
    onOpenPolicies: () => openRuntimePolicyView(params.runtime, primaryConnectorId),
  };
}

export function createOperatorModel(params: {
  bridgeState: DirectWorkspaceBridgeState | null;
  activeSurface: WorkspaceOperatorSurface;
  onSelectSurface: (surface: WorkspaceOperatorSurface) => void;
  runtime: TauriRuntime;
  rootPath: string;
  activeFilePath: string | null;
}): WorkspaceOperatorModel {
  const bridgeState = params.bridgeState;
  const workflows = bridgeState?.workflows ?? [];
  const runs = bridgeState?.runs ?? [];
  const artifacts = bridgeState?.artifacts ?? [];
  const policy = bridgeState?.policy ?? null;
  const connections = bridgeState?.connections ?? [];
  const latestRun = runs[0] ?? null;
  const latestArtifact = artifacts[0] ?? null;
  const primaryConnectorId =
    latestArtifact?.connectorId ?? connections[0]?.id ?? null;

  return {
    activeSurface: params.activeSurface,
    onSelectSurface: params.onSelectSurface,
    views: [
      {
        id: "chat",
        title: "Chat",
        eyebrow: "Outcome control plane",
        description:
          "Use Chat as a native workbench surface for code-aware prompting, patch review, and outcome shaping.",
        summaryItems: [
          {
            label: "File",
            value: params.activeFilePath ?? "No active file",
          },
        ],
        actions: [
          {
            id: "chat-open",
            label: "Open Chat Surface",
            onSelect: () => params.runtime.openChatView("chat"),
          },
          {
            id: "chat-review-file",
            label: "Review Current File",
              onSelect: () =>
                openRuntimeFileReview(params.runtime, {
                  workspaceRoot: params.rootPath,
                  filePath: params.activeFilePath,
                  source: "workspace-runtime",
                }),
          },
          {
            id: "chat-browser",
            label: "Start Browser Validation",
              onSelect: () =>
                openRuntimeBrowserAutomation(params.runtime, {
                  workspaceRoot: params.rootPath,
                  filePath: params.activeFilePath,
                  source: "workspace-runtime",
                }),
          },
        ],
      },
      {
        id: "workflows",
        title: "Workflows",
        eyebrow: "Agent orchestration",
        description:
          "Launch, inspect, and sequence agent workflows without leaving the direct workbench shell.",
        summaryItems: [
          {
            label: "Installed",
            value: String(workflows.length),
          },
        ],
        actions: [
          {
            id: "workflow-open",
            label: "Open Workflow Surface",
            onSelect: () => openRuntimeWorkflowView(params.runtime),
          },
          {
            id: "workflow-browser",
            label: "Start Browser Validation",
              onSelect: () =>
                openRuntimeBrowserAutomation(params.runtime, {
                  workspaceRoot: params.rootPath,
                  filePath: params.activeFilePath,
                  source: "workspace-runtime",
                }),
          },
          {
            id: "workflow-runs",
            label: "Open Runs Surface",
            onSelect: () => openRuntimeRunsView(params.runtime),
          },
        ],
      },
      {
        id: "runs",
        title: "Runs",
        eyebrow: "Runtime evidence",
        description:
          "Track active runs, surface receipts, and jump back to impacted files and artifacts.",
        summaryItems: [
          { label: "Runs", value: String(runs.length) },
          {
            label: "Running",
            value: String(runs.filter((run) => run.status === "running").length),
            tone: runs.some((run) => run.status === "running") ? "success" : "default",
          },
        ],
        actions: [
          {
            id: "runs-open",
            label: "Open Runs Surface",
            onSelect: () => openRuntimeRunsView(params.runtime),
          },
          ...(latestRun
            ? [
                {
                  id: "runs-review-latest",
                  label: "Review Latest Run",
                  onSelect: () =>
                    openRuntimeRunReview(params.runtime, {
                      workspaceRoot: params.rootPath,
                      filePath: params.activeFilePath,
                      runId: latestRun.runId,
                      artifactId: latestRun.artifactId ?? null,
                      evidenceThreadId: latestRun.reviewSessionId,
                      source: "workspace-runtime",
                    }),
                },
              ]
            : []),
        ],
      },
      {
        id: "artifacts",
        title: "Artifacts",
        eyebrow: "Evidence and receipts",
        description:
          "Inspect generated artifacts, provenance, and receipt-linked surfaces as a first-class workbench concern.",
        summaryItems: [
          { label: "Artifacts", value: String(artifacts.length) },
          latestArtifact
            ? {
                label: "Latest",
                value: latestArtifact.action,
              }
            : {
                label: "Latest",
                value: "None",
              },
        ],
        actions: [
          ...(latestArtifact?.evidenceThreadId
            ? [
                {
                  id: "artifacts-open-evidence",
                  label: "Open Evidence Session",
                  onSelect: () =>
                    openRuntimeEvidenceSession(
                      params.runtime,
                      latestArtifact.evidenceThreadId as string,
                    ),
                },
              ]
            : []),
          ...(latestArtifact
            ? [
                {
                  id: "artifacts-review-latest",
                  label: "Review Latest Artifact",
                  onSelect: () =>
                    openRuntimeArtifactReview(params.runtime, {
                      workspaceRoot: params.rootPath,
                      filePath: params.activeFilePath,
                      artifactId: latestArtifact.activityId,
                      evidenceThreadId: latestArtifact.evidenceThreadId ?? null,
                      connectorId: latestArtifact.connectorId ?? null,
                      source: "workspace-runtime",
                    }),
                },
              ]
            : []),
          {
            id: "artifacts-policy",
            label: "Open Connector Policy",
            onSelect: () => openRuntimePolicyView(params.runtime, primaryConnectorId),
          },
        ],
      },
      {
        id: "policy",
        title: "Policy",
        eyebrow: "Governed execution",
        description:
          "Keep approvals, authority, and policy context visible while acting from the workspace.",
        summaryItems: policy
          ? [
              {
                label: "Issues",
                value: String(policy.activeIssueCount),
                tone: policy.activeIssueCount > 0 ? "attention" : "success",
              },
              {
                label: "Connectors",
                value: `${policy.connectedConnectorCount}/${policy.connectorCount}`,
              },
            ]
          : [],
        actions: [
          {
            id: "policy-open",
            label: "Open Policy Context",
            onSelect: () => openRuntimePolicyView(params.runtime, primaryConnectorId),
          },
          {
            id: "policy-connections",
            label: "Open Connections Surface",
            onSelect: () =>
              openRuntimeConnectionsOverview(params.runtime, primaryConnectorId),
          },
        ],
      },
      {
        id: "connections",
        title: "Connections",
        eyebrow: "Services and integrations",
        description:
          "Inspect available services, runtime bindings, and connection posture from inside the workspace.",
        summaryItems: [
          { label: "Connectors", value: String(connections.length) },
        ],
        actions: [
          {
            id: "connections-open",
            label: "Open Connections Surface",
            onSelect: () =>
              openRuntimeConnectionsOverview(params.runtime, primaryConnectorId),
          },
          {
            id: "connections-policy",
            label: "Open Policy Context",
            onSelect: () => openRuntimePolicyView(params.runtime, primaryConnectorId),
          },
        ],
      },
    ],
  };
}
