import type { TauriRuntime } from "./TauriRuntime";
import type { WorkspaceActionContext } from "./workspaceActionContext";
import type { WorkspaceBridgeRouteRequest } from "./workspaceBridgeTypes";
import { openArtifactReviewTarget } from "./reviewNavigation";
import {
  openRuntimeArtifactReview,
  openRuntimeBrowserAutomation,
  openRuntimeCodeSelectionReview,
  openRuntimeConnectionsOverview,
  openRuntimeEvidenceSession,
  openRuntimeFileReview,
  openRuntimePolicyView,
  openRuntimeRunsView,
  openRuntimeRunReview,
  openRuntimeWorkflowView,
} from "./runtimeChatNavigation";

type WorkspaceMetricRecorder = (
  name: string,
  detail?: Record<string, unknown>,
) => void;

function readString(
  source: Record<string, unknown> | undefined,
  key: string,
): string | null {
  const value = source?.[key];
  return typeof value === "string" ? value : null;
}

export function readWorkspaceActionContext(
  rawContext: Record<string, unknown> | undefined,
): WorkspaceActionContext | null {
  if (!rawContext) {
    return null;
  }

  const rawSelection =
    rawContext.selection && typeof rawContext.selection === "object"
      ? (rawContext.selection as Record<string, unknown>)
      : null;

  return {
    workspaceRoot: readString(rawContext, "workspaceRoot"),
    filePath: readString(rawContext, "filePath"),
    artifactId: readString(rawContext, "artifactId"),
    evidenceThreadId: readString(rawContext, "evidenceThreadId"),
    runId: readString(rawContext, "runId"),
    connectorId: readString(rawContext, "connectorId"),
    source:
      (readString(rawContext, "source") as WorkspaceActionContext["source"] | null) ??
      undefined,
    selection: rawSelection
      ? {
          startLineNumber:
            typeof rawSelection.startLineNumber === "number"
              ? rawSelection.startLineNumber
              : 0,
          startColumn:
            typeof rawSelection.startColumn === "number"
              ? rawSelection.startColumn
              : 0,
          endLineNumber:
            typeof rawSelection.endLineNumber === "number"
              ? rawSelection.endLineNumber
              : 0,
          endColumn:
            typeof rawSelection.endColumn === "number"
              ? rawSelection.endColumn
              : 0,
          selectedText: readString(rawSelection, "selectedText"),
        }
      : null,
  };
}

export async function routeWorkspaceBridgeRequest(
  runtime: TauriRuntime,
  request: WorkspaceBridgeRouteRequest,
  recordMetric?: WorkspaceMetricRecorder,
) {
  const context =
    request.context && typeof request.context === "object"
      ? readWorkspaceActionContext(request.context as Record<string, unknown>)
      : null;

  recordMetric?.("bridge_request_received", {
    requestId: request.requestId,
    requestType: request.requestType,
    source: context?.source ?? null,
    filePath: context?.filePath ?? null,
    runId: context?.runId ?? null,
    artifactId: context?.artifactId ?? null,
  });

  switch (request.requestType) {
    case "chat.explainSelection": {
      const filePath = readString(request.payload, "filePath") ?? context?.filePath ?? null;
      const selectedText =
        readString(request.payload, "selectedText") ??
        context?.selection?.selectedText ??
        null;
      await openRuntimeCodeSelectionReview(
        runtime,
        context ? { ...context, filePath } : { workspaceRoot: null, filePath },
        selectedText,
      );
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent",
      });
      return;
    }
    case "chat.reviewFile": {
      const filePath = readString(request.payload, "filePath") ?? context?.filePath ?? null;
      await openRuntimeFileReview(
        runtime,
        context ? { ...context, filePath } : { workspaceRoot: null, filePath },
      );
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent",
      });
      return;
    }
    case "chat.reviewArtifact":
      await openRuntimeArtifactReview(runtime, context);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: context?.evidenceThreadId ? "chat.session" : "chat.intent.artifact",
      });
      return;
    case "chat.reviewRun":
      await openRuntimeRunReview(runtime, context);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: context?.evidenceThreadId ? "chat.session" : "chat.intent.run",
      });
      return;
    case "workflow.open":
      await openRuntimeWorkflowView(runtime);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.workflows",
      });
      return;
    case "runs.open":
      await openRuntimeRunsView(runtime);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.runs",
      });
      return;
    case "policy.open": {
      const connectorId =
        readString(request.payload, "connectorId") ?? context?.connectorId ?? null;
      await openRuntimePolicyView(runtime, connectorId);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.policy",
        connectorId,
      });
      return;
    }
    case "evidence.open": {
      const sessionId =
        readString(request.payload, "sessionId") ?? context?.evidenceThreadId ?? null;
      if (!sessionId) {
        recordMetric?.("bridge_request_ignored", {
          requestId: request.requestId,
          requestType: request.requestType,
          reason: "missing_session_id",
        });
        return;
      }
      await openRuntimeEvidenceSession(runtime, sessionId);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.evidence",
        sessionId,
      });
      return;
    }
    case "chatSession.openArtifact": {
      const artifactId =
        readString(request.payload, "artifactId") ?? context?.artifactId ?? null;
      if (!artifactId) {
        recordMetric?.("bridge_request_ignored", {
          requestId: request.requestId,
          requestType: request.requestType,
          reason: "missing_artifact_id",
        });
        return;
      }
      await openArtifactReviewTarget(artifactId);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat-session.artifact",
        artifactId,
      });
      return;
    }
    case "connections.open":
      await openRuntimeConnectionsOverview(
        runtime,
        readString(request.payload, "connectorId") ?? context?.connectorId ?? null,
      );
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.capabilities",
      });
      return;
    case "automation.browser":
      await openRuntimeBrowserAutomation(runtime, context);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent.browser",
      });
      return;
    default:
      recordMetric?.("bridge_request_ignored", {
        requestId: request.requestId,
        requestType: request.requestType,
      });
      console.warn("[Workspace] Ignoring unknown bridge request:", request);
  }
}
