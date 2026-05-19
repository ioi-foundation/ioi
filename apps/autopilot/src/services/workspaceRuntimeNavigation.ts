import type { TauriRuntime } from "./TauriRuntime";
import type { WorkspaceActionContext } from "./workspaceActionContext";
import type { WorkspaceBridgeRouteRequest } from "./workspaceBridgeTypes";
import { openArtifactReviewTarget } from "./reviewNavigation";
import {
  openRuntimeArtifactReview,
  openRuntimeBrowserAutomation,
  openRuntimeChatPrompt,
  openRuntimeCodeSelectionReview,
  openRuntimeConnectionsOverview,
  openRuntimeEvidenceSession,
  openRuntimeFileReview,
  openRuntimePolicyView,
  openRuntimeRunsView,
  openRuntimeRunReview,
  openRuntimeWorkflowCodeGeneration,
  openRuntimeWorkflowView,
} from "./runtimeChatNavigation";
import { materializeWorkflowCodeGenerationProposal } from "./workflowCodeGenerationProposal";

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

function readBoolean(
  source: Record<string, unknown> | undefined,
  key: string,
): boolean | null {
  const value = source?.[key];
  return typeof value === "boolean" ? value : null;
}

function readStringArray(
  source: Record<string, unknown> | undefined,
  key: string,
): string[] {
  const value = source?.[key];
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
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
    case "workbench.contextSnapshot":
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "workbench.context-snapshot",
        workspaceRoot: readString(request.payload, "workspaceRoot"),
      });
      return;
    case "workbench.inspectionTargetIndex":
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "workbench.inspection-target-index",
        targetCount: Array.isArray(request.payload.targets)
          ? request.payload.targets.length
          : 0,
      });
      return;
    case "workbench.commandRouteReceipt":
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "workbench.command-route-receipt",
        commandId: readString(request.payload, "commandId"),
        route: readString(request.payload, "route"),
        status: readString(request.payload, "status"),
      });
      return;
    case "chat.submit": {
      const prompt = readString(request.payload, "prompt");
      if (!prompt) {
        recordMetric?.("bridge_request_ignored", {
          requestId: request.requestId,
          requestType: request.requestType,
          reason: "missing_prompt",
        });
        return;
      }
      await openRuntimeChatPrompt(runtime, prompt);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent.native-workbench-submit",
      });
      return;
    }
    case "chat.generateAgentInstructions":
      await openRuntimeChatPrompt(
        runtime,
        "Generate Agent Instructions for this workspace using the current OpenVSCode workbench context. Include repository context, setup assumptions, and safe proposal-first coding posture.",
      );
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent.generate-agent-instructions",
      });
      return;
    case "chat.showConfig":
      await openRuntimeChatPrompt(
        runtime,
        "Show the current Autopilot native workbench configuration, including active workspace, model/tool capability posture, authority scope, and receipt expectations.",
      );
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent.native-workbench-config",
      });
      return;
    case "chat.addContext":
    case "chat.attachEditorContext": {
      if (context?.selection?.selectedText || context?.filePath) {
        await openRuntimeCodeSelectionReview(
          runtime,
          context,
          context.selection?.selectedText ?? null,
        );
      } else {
        await openRuntimeChatPrompt(
          runtime,
          "Attach the most relevant OpenVSCode workspace context to the next Autopilot turn. Prefer active editor, selected text, diagnostics, SCM posture, and visible IOI workbench refs.",
        );
      }
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent.attach-native-context",
        filePath: context?.filePath ?? null,
        hasSelection: Boolean(context?.selection?.selectedText),
      });
      return;
    }
    case "chat.contextOptions":
      await openRuntimeChatPrompt(
        runtime,
        "List available OpenVSCode context options for this Autopilot turn, including active editor, selection, diagnostics, SCM state, terminal/task state, workflows, runs, and evidence refs.",
      );
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent.context-options",
      });
      return;
    case "chat.toolControls":
      await openRuntimeConnectionsOverview(runtime, context?.connectorId ?? null);
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.capabilities.tool-controls",
      });
      return;
    case "chat.focusComposer":
    case "chat.new":
    case "chat.newOptions":
    case "chat.moreActions":
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "native-chat-local-control",
      });
      return;
    case "settings.open":
      await runtime.openChatView("settings");
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.settings",
      });
      return;
    case "workflow.codeGenerationRequest":
      try {
        const proposal = await materializeWorkflowCodeGenerationProposal({
          requestId: readString(request.payload, "requestId"),
          requestedAtMs:
            typeof request.payload.requestedAtMs === "number"
              ? request.payload.requestedAtMs
              : null,
          workflowRef: readString(request.payload, "workflowRef"),
          packageRef: readString(request.payload, "packageRef"),
          goal: readString(request.payload, "goal"),
          targetWorkspace: readString(request.payload, "targetWorkspace"),
          modelCapabilityRef: readString(request.payload, "boundModelCapabilityRef"),
          toolCapabilityRefs: readStringArray(request.payload, "boundToolCapabilityRefs"),
          authorityScope: readString(request.payload, "authorityScope"),
          evalProfileRef: readString(request.payload, "evalProfileRef"),
          proposalOnly: readBoolean(request.payload, "proposalOnly") ?? true,
        });
        recordMetric?.("bridge_request_artifact_materialized", {
          requestId: request.requestId,
          requestType: request.requestType,
          proposalRootPath: proposal.proposalRootPath,
          receiptPath: proposal.receiptPath,
          status: proposal.status,
        });
      } catch (error) {
        recordMetric?.("bridge_request_artifact_materialization_failed", {
          requestId: request.requestId,
          requestType: request.requestType,
          message: error instanceof Error ? error.message : String(error),
        });
      }
      await openRuntimeWorkflowCodeGeneration(runtime, {
        workflowRef: readString(request.payload, "workflowRef"),
        packageRef: readString(request.payload, "packageRef"),
        goal: readString(request.payload, "goal"),
        targetWorkspace: readString(request.payload, "targetWorkspace"),
        modelCapabilityRef: readString(request.payload, "boundModelCapabilityRef"),
        toolCapabilityRefs: readStringArray(request.payload, "boundToolCapabilityRefs"),
        proposalOnly: readBoolean(request.payload, "proposalOnly") ?? true,
      });
      recordMetric?.("bridge_request_handled", {
        requestId: request.requestId,
        requestType: request.requestType,
        routedTo: "chat.intent.workflow-code-generation",
        workflowRef: readString(request.payload, "workflowRef"),
        packageRef: readString(request.payload, "packageRef"),
        proposalOnly: readBoolean(request.payload, "proposalOnly") ?? true,
      });
      return;
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
