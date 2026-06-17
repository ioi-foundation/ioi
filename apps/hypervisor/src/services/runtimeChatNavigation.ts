import type { HypervisorClientRuntime } from "./HypervisorClientRuntime";
import {
  buildArtifactReviewIntent,
  buildContextReviewIntent,
  buildBrowserAutomationIntent,
  buildExplainSelectionIntent,
  buildReviewFileIntent,
  buildRunReviewIntent,
  buildWorkflowCodeGenerationIntent,
  type CodeAwareActionContext,
} from "./codeAwareActionContext";

export async function openRuntimeCodeSelectionReview(
  runtime: HypervisorClientRuntime,
  context: CodeAwareActionContext | null | undefined,
  selectedText?: string | null,
) {
  await runtime.openChatHypervisorIntent(
    buildExplainSelectionIntent(context, selectedText),
  );
}

export async function openRuntimeFileReview(
  runtime: HypervisorClientRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  await runtime.openChatHypervisorIntent(buildReviewFileIntent(context));
}

export async function openRuntimeContextReview(
  runtime: HypervisorClientRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.evidenceThreadId) {
    await runtime.openChatSessionTarget(context.evidenceThreadId);
    return;
  }

  await runtime.openChatHypervisorIntent(buildContextReviewIntent(context));
}

export async function openRuntimeArtifactReview(
  runtime: HypervisorClientRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.evidenceThreadId) {
    await runtime.openChatSessionTarget(context.evidenceThreadId);
    return;
  }

  await runtime.openChatHypervisorIntent(buildArtifactReviewIntent(context));
}

export async function openRuntimeRunReview(
  runtime: HypervisorClientRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.evidenceThreadId) {
    await runtime.openChatSessionTarget(context.evidenceThreadId);
    return;
  }

  await runtime.openChatHypervisorIntent(buildRunReviewIntent(context));
}

export async function openRuntimeWorkflowView(runtime: HypervisorClientRuntime) {
  await runtime.openChatView("workflows");
}

export async function openRuntimeRunsView(runtime: HypervisorClientRuntime) {
  await runtime.openChatView("runs");
}

export async function openRuntimePolicyView(
  runtime: HypervisorClientRuntime,
  connectorId?: string | null,
) {
  await runtime.openChatPolicyTarget(connectorId);
}

export async function openRuntimeEvidenceSession(
  runtime: HypervisorClientRuntime,
  sessionId: string,
) {
  await runtime.openChatSessionTarget(sessionId);
}

export async function openRuntimeConnectionsOverview(
  runtime: HypervisorClientRuntime,
  connectorId?: string | null,
) {
  await runtime.openChatCapabilityTarget(connectorId ?? null, "overview");
}

export async function openRuntimeBrowserAutomation(
  runtime: HypervisorClientRuntime,
  context: CodeAwareActionContext | null | undefined,
) {
  await runtime.openChatHypervisorIntent(buildBrowserAutomationIntent(context));
}

export async function openRuntimeChatPrompt(runtime: HypervisorClientRuntime, prompt: string) {
  await runtime.openChatHypervisorIntent(prompt);
}

export async function openRuntimeWorkflowCodeGeneration(
  runtime: HypervisorClientRuntime,
  params: {
    workflowRef?: string | null;
    packageRef?: string | null;
    goal?: string | null;
    targetWorkspace?: string | null;
    modelCapabilityRef?: string | null;
    toolCapabilityRefs?: string[];
    proposalOnly?: boolean;
  },
) {
  await runtime.openChatHypervisorIntent(buildWorkflowCodeGenerationIntent(params));
}
