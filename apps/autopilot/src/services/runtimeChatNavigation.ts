import type { TauriRuntime } from "./TauriRuntime";
import {
  buildArtifactReviewIntent,
  buildContextReviewIntent,
  buildBrowserAutomationIntent,
  buildExplainSelectionIntent,
  buildReviewFileIntent,
  buildRunReviewIntent,
  type CodeAwareActionContext,
} from "./codeAwareActionContext";

export async function openRuntimeCodeSelectionReview(
  runtime: TauriRuntime,
  context: CodeAwareActionContext | null | undefined,
  selectedText?: string | null,
) {
  await runtime.openChatAutopilotIntent(
    buildExplainSelectionIntent(context, selectedText),
  );
}

export async function openRuntimeFileReview(
  runtime: TauriRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  await runtime.openChatAutopilotIntent(buildReviewFileIntent(context));
}

export async function openRuntimeContextReview(
  runtime: TauriRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.evidenceThreadId) {
    await runtime.openChatSessionTarget(context.evidenceThreadId);
    return;
  }

  await runtime.openChatAutopilotIntent(buildContextReviewIntent(context));
}

export async function openRuntimeArtifactReview(
  runtime: TauriRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.evidenceThreadId) {
    await runtime.openChatSessionTarget(context.evidenceThreadId);
    return;
  }

  await runtime.openChatAutopilotIntent(buildArtifactReviewIntent(context));
}

export async function openRuntimeRunReview(
  runtime: TauriRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.evidenceThreadId) {
    await runtime.openChatSessionTarget(context.evidenceThreadId);
    return;
  }

  await runtime.openChatAutopilotIntent(buildRunReviewIntent(context));
}

export async function openRuntimeWorkflowView(runtime: TauriRuntime) {
  await runtime.openChatView("workflows");
}

export async function openRuntimeRunsView(runtime: TauriRuntime) {
  await runtime.openChatView("runs");
}

export async function openRuntimePolicyView(
  runtime: TauriRuntime,
  connectorId?: string | null,
) {
  await runtime.openChatPolicyTarget(connectorId);
}

export async function openRuntimeEvidenceSession(
  runtime: TauriRuntime,
  sessionId: string,
) {
  await runtime.openChatSessionTarget(sessionId);
}

export async function openRuntimeConnectionsOverview(
  runtime: TauriRuntime,
  connectorId?: string | null,
) {
  await runtime.openChatCapabilityTarget(connectorId ?? null, "overview");
}

export async function openRuntimeBrowserAutomation(
  runtime: TauriRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  await runtime.openChatAutopilotIntent(buildBrowserAutomationIntent(context));
}
