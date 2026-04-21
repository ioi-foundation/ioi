import { useMemo } from "react";
import { hasOpenableArtifactSurface } from "../components/chatArtifactSurfaceModel";
import {
  ARTIFACT_PANEL_WIDTH,
  BASE_PANEL_WIDTH,
  COMPACT_ARTIFACT_PANEL_WIDTH,
  COMPACT_SIDEBAR_PANEL_WIDTH,
  CONTENT_PIPELINE_V2_ENABLED,
  SIDEBAR_PANEL_WIDTH,
} from "../constants";
import { buildRunPresentation } from "../viewmodels/contentPipeline";
import { useTurnContexts } from "./useTurnContexts";
import {
  deriveChatExecutionChrome as deriveChatExecutionChromeState,
  formatStudioStatusLabel,
  type ChatExecutionMetrics,
  type ChatExecutionProcess,
} from "../components/chatExecutionChrome";
import {
  defaultRunActivityDetail,
  defaultRunActivityTitle,
  operatorFacingCurrentStep,
} from "../viewmodels/runtimeStatusCopy";
import type {
  AgentEvent,
  Artifact,
  ChatMessage,
  RunPresentation,
  SessionSummary,
  ChatArtifactOperatorStep,
  ChatArtifactSelectedSkill,
  ChatArtifactSkillDiscoveryResolution,
} from "../../../types";

export type ChatStatusCardState = {
  tone?: "active" | "error";
  title: string;
  detail: string;
  metrics?: ChatExecutionMetrics;
  processes?: ChatExecutionProcess[];
  selectedSkills?: ChatArtifactSelectedSkill[];
  livePreview?: {
    label: string;
    content: string;
    status: string;
    kind?: string | null;
    language?: string | null;
    isFinal: boolean;
  } | null;
  codePreview?: {
    label: string;
    content: string;
    status: string;
    kind?: string | null;
    language?: string | null;
    isFinal: boolean;
  } | null;
} | null;

type ChatStatusPreview = NonNullable<ChatStatusCardState>["livePreview"];

function shouldDisplayArtifactStatusPreview(
  preview: ChatStatusPreview,
): boolean {
  if (!preview) {
    return false;
  }
  const normalizedKind = String(preview.kind || "").trim().toLowerCase();
  const normalizedStatus = String(preview.status || "").trim().toLowerCase();
  if (
    normalizedKind === "token_stream" &&
    preview.isFinal &&
    (normalizedStatus === "completed" || normalizedStatus === "recovered")
  ) {
    return false;
  }
  return true;
}

function selectArtifactStatusPreviews({
  artifactThinkingPreview,
  executionChromeLivePreview,
  executionChromeCodePreview,
}: {
  artifactThinkingPreview: ChatStatusPreview;
  executionChromeLivePreview: ChatStatusPreview;
  executionChromeCodePreview: ChatStatusPreview;
}): {
  livePreview: ChatStatusPreview;
  codePreview: ChatStatusPreview;
} {
  const filteredArtifactThinkingPreview = shouldDisplayArtifactStatusPreview(
    artifactThinkingPreview,
  )
    ? artifactThinkingPreview
    : null;
  const filteredExecutionChromeLivePreview = shouldDisplayArtifactStatusPreview(
    executionChromeLivePreview,
  )
    ? executionChromeLivePreview
    : null;
  const filteredExecutionChromeCodePreview = shouldDisplayArtifactStatusPreview(
    executionChromeCodePreview,
  )
    ? executionChromeCodePreview
    : null;
  const livePreview =
    filteredExecutionChromeLivePreview ??
    filteredExecutionChromeCodePreview ??
    filteredArtifactThinkingPreview;
  const codePreview =
    filteredExecutionChromeCodePreview?.content &&
    filteredExecutionChromeCodePreview.content !== livePreview?.content
      ? filteredExecutionChromeCodePreview
      : null;

  return { livePreview, codePreview };
}

function deriveTaskChatExecutionChrome(task: any) {
  const materialization = task?.chat_session?.materialization;
  const executionEnvelope = materialization?.executionEnvelope ?? null;
  return deriveChatExecutionChromeState({
    executionEnvelope,
    swarmExecution:
      materialization?.swarmExecution ?? executionEnvelope?.executionSummary ?? null,
    swarmPlan: materialization?.swarmPlan ?? executionEnvelope?.plan ?? null,
    workerReceipts:
      materialization?.swarmWorkerReceipts ?? executionEnvelope?.workerReceipts ?? [],
    changeReceipts:
      materialization?.swarmChangeReceipts ?? executionEnvelope?.changeReceipts ?? [],
  });
}

function isArtifactStudioRoute(task: any): boolean {
  return (
    task?.chat_session?.outcomeRequest?.outcomeKind === "artifact" ||
    task?.chat_outcome?.outcomeKind === "artifact"
  );
}

function formatArtifactThinkingStatus(status: string | null | undefined): string {
  switch ((status || "").trim().toLowerCase()) {
    case "complete":
      return "Done";
    case "active":
      return "Working";
    case "blocked":
      return "Blocked";
    case "failed":
      return "Failed";
    case "pending":
      return "Queued";
    default:
      return formatStudioStatusLabel(status) || "Queued";
  }
}

function resolveArtifactThinkingSubject(task: any): string {
  const subjectDomain =
    task?.chat_session?.materialization?.artifactBrief?.subjectDomain?.trim() || "";
  if (subjectDomain) {
    return subjectDomain;
  }

  const title = task?.chat_session?.title?.trim() || "";
  if (title) {
    return title.toLowerCase();
  }

  return "the artifact request";
}

function buildArtifactThinkingPreview(
  task: any,
): ChatStatusPreview {
  const operatorSteps = (
    (task?.chat_session?.materialization?.operatorSteps ?? []) as ChatArtifactOperatorStep[]
  )
    .filter((step) => step.preview?.content?.trim());
  if (operatorSteps.length === 0) {
    return null;
  }

  const matchingStep =
    [...operatorSteps].reverse().find((step) => {
      const status = String(step.status || "").trim().toLowerCase();
      return status === "active" || status === "pending";
    }) ??
    [...operatorSteps].reverse().find((step) => Boolean(step.preview?.isFinal)) ??
    [...operatorSteps].reverse()[0] ??
    null;
  const preview = matchingStep?.preview ?? null;
  if (!preview?.content?.trim()) {
    return null;
  }
  return {
    label: preview.label,
    content: preview.content,
    status: preview.status,
    kind: preview.kind || null,
    language: preview.language || null,
    isFinal: Boolean(preview.isFinal),
  };
}

function buildArtifactThinkingProcesses(task: any): ChatExecutionProcess[] {
  const materialization = task?.chat_session?.materialization;
  const operatorSteps = ((materialization?.operatorSteps ?? []) as ChatArtifactOperatorStep[])
    .filter((step) => step.label.trim().length > 0);
  const skillDiscoveryResolution = (materialization?.skillDiscoveryResolution ??
    null) as ChatArtifactSkillDiscoveryResolution | null;
  if (operatorSteps.length === 0) {
    return [];
  }

  const processes = operatorSteps.map((step) => ({
    id: step.stepId || `${String(step.phase || "other")}:${step.startedAtMs}`,
    label: step.label || "Chat artifact step",
    status: formatArtifactThinkingStatus(step.status || "pending"),
    summary:
      step.detail ||
      skillDiscoveryResolution?.rationale ||
      "Chat is working through the active artifact step.",
    isActive: String(step.status || "").trim().toLowerCase() === "active",
    iconKey: artifactThinkingIconKeyForStep(step),
  }));

  return processes;
}

function artifactThinkingIconKeyForStep(
  step: ChatArtifactOperatorStep,
): "search" | "cube" | "copy" | "code" | "retry" | "check" | "artifacts" | "sparkles" {
  switch (String(step.phase || "").trim().toLowerCase()) {
    case "understand_request":
      return "search";
    case "route_artifact":
      return "cube";
    case "search_sources":
    case "read_sources":
      return "search";
    case "author_artifact":
      return "code";
    case "repair_artifact":
      return "retry";
    case "verify_artifact":
    case "inspect_artifact":
      return "check";
    case "present_artifact":
      return "artifacts";
    default:
      return "sparkles";
  }
}

function summarizeStudioFailure(
  message: string | null | undefined,
): {
  title: string;
  detail: string;
} {
  const raw = (message || "").trim();
  const normalized = raw.toLowerCase();

  if (
    normalized.includes("did not commit within") ||
    normalized.includes("last tx status") ||
    normalized.includes("inmempool")
  ) {
    return {
      title: "Chat kept the request in conversation",
      detail:
        "The artifact route stalled before a stable surface was ready. Keep iterating in chat, or inspect the thinking trace if you need runtime detail.",
    };
  }

  if (
    normalized.includes("usable artifact") ||
    normalized.includes("artifact") ||
    normalized.includes("renderer")
  ) {
    return {
      title: "Chat did not open an artifact yet",
      detail:
        "The request is still here, but the artifact surface was not ready to open. Continue in chat, or inspect the trace if you need to see what happened.",
    };
  }

  return {
    title: "Chat kept the request in conversation",
    detail:
      "The request did not settle into a usable Chat surface yet. Continue in chat, or inspect the trace if you need the underlying runtime details.",
  };
}

export function selectRetainableDrawerSession(
  sessions: SessionSummary[],
): SessionSummary | null {
  const sorted = [...sessions].sort((left, right) => right.timestamp - left.timestamp);
  const candidate = sorted.find((session) => {
    const phase = (session.phase || "").trim().toLowerCase();
    const currentStep = (session.current_step || "").trim().toLowerCase();

    return (
      phase === "running" ||
      phase === "gate" ||
      currentStep.includes("waiting for") ||
      currentStep.includes("initializing") ||
      currentStep.includes("routing the request") ||
      currentStep.includes("sending message")
    );
  });

  return candidate || null;
}

export function useSpotlightSurfaceState({
  isStudioVariant,
  layout,
  activeHistory,
  activeEvents,
  activeArtifacts,
  selectedArtifact,
  selectedArtifactId,
  retainedArtifacts,
  task,
  chatEvents,
  inputLockedByCredential,
  seedIntent,
  intent,
  isRunning,
  submissionInFlight,
  submissionError,
  clarificationRequest,
  isGated,
  showPasswordPrompt,
}: {
  isStudioVariant: boolean;
  layout: {
    sidebarVisible: boolean;
    artifactPanelVisible: boolean;
  };
  activeHistory: ChatMessage[];
  activeEvents: AgentEvent[];
  activeArtifacts: Artifact[];
  selectedArtifact: Artifact | null;
  selectedArtifactId: string | null;
  retainedArtifacts: Artifact[];
  task: any;
  chatEvents: ChatMessage[];
  inputLockedByCredential: boolean;
  seedIntent: string | null;
  intent: string;
  isRunning: boolean;
  submissionInFlight: boolean;
  submissionError: string | null;
  clarificationRequest: unknown;
  isGated: boolean;
  showPasswordPrompt: boolean;
}) {
  const selectedInspectionArtifact = useMemo(() => {
    if (selectedArtifact) {
      return selectedArtifact;
    }

    if (!selectedArtifactId) {
      return null;
    }

    return (
      retainedArtifacts.find((artifact) => artifact.artifact_id === selectedArtifactId) ??
      null
    );
  }, [retainedArtifacts, selectedArtifact, selectedArtifactId]);

  const activeChatSessionId = task?.chat_session?.sessionId ?? null;
  const studioArtifactExpected = isArtifactStudioRoute(task);

  const studioArtifactAvailable = useMemo(() => {
    const manifest = task?.chat_session?.artifactManifest;
    if (!manifest) {
      return false;
    }

    return hasOpenableArtifactSurface(
      manifest,
      task?.renderer_session ?? null,
      task?.build_session?.workspaceRoot ?? null,
    );
  }, [
    task?.build_session?.workspaceRoot,
    task?.renderer_session,
    task?.chat_session,
  ]);

  const isDualPanelSpotlight =
    !isStudioVariant && layout.sidebarVisible && layout.artifactPanelVisible;
  const sidebarPanelWidth = layout.sidebarVisible
    ? isDualPanelSpotlight
      ? COMPACT_SIDEBAR_PANEL_WIDTH
      : SIDEBAR_PANEL_WIDTH
    : 0;
  const artifactPanelWidth = layout.artifactPanelVisible
    ? isDualPanelSpotlight
      ? COMPACT_ARTIFACT_PANEL_WIDTH
      : ARTIFACT_PANEL_WIDTH
    : 0;
  const panelWidth =
    BASE_PANEL_WIDTH + sidebarPanelWidth + artifactPanelWidth;
  const containerStyle = isStudioVariant
    ? undefined
    : { width: `${panelWidth}px` };

  const runPresentation: RunPresentation = useMemo(
    () => buildRunPresentation(activeHistory, activeEvents, activeArtifacts),
    [activeArtifacts, activeEvents, activeHistory],
  );

  const { conversationTurns, latestAnsweredTurnIndex, turnContexts } =
    useTurnContexts({
      activeHistory,
      activeEvents,
      activeChatSession: task?.chat_session ?? null,
      runPresentation,
    });

  const hasSessionContent =
    activeHistory.length > 0 ||
    chatEvents.length > 0 ||
    conversationTurns.length > 0 ||
    activeEvents.length > 0 ||
    activeArtifacts.length > 0 ||
    Boolean(task?.chat_session);
  const shouldAutoFocusStudioComposer =
    isStudioVariant &&
    !inputLockedByCredential &&
    !seedIntent?.trim() &&
    !hasSessionContent &&
    !intent.trim();

  const hasOperatorDecisionPrompt =
    isGated || showPasswordPrompt || Boolean(clarificationRequest);
  const inlineStudioDecisionPrompt = isStudioVariant && hasOperatorDecisionPrompt;
  const showOverlaySessionChrome =
    !hasOperatorDecisionPrompt &&
    hasSessionContent &&
    task?.phase === "Gate";

  const showInitialLoader = CONTENT_PIPELINE_V2_ENABLED
    ? isRunning && conversationTurns.length === 0
    : false;

  const chatStatusCard: ChatStatusCardState = useMemo(() => {
    if (!isStudioVariant) {
      return null;
    }
    if (task?.chat_session?.activeOperatorRun) {
      return null;
    }

    const submissionFailureSummary = summarizeStudioFailure(submissionError);
    const executionChrome = deriveTaskChatExecutionChrome(task);
    const artifactRouteActive = isArtifactStudioRoute(task);
    const artifactThinkingProcesses = artifactRouteActive
      ? buildArtifactThinkingProcesses(task)
      : executionChrome.processes;
    const artifactThinkingActiveProcess =
      artifactThinkingProcesses.find((process) => process.isActive) ?? null;
    const artifactThinkingLatestProcess =
      artifactThinkingProcesses[artifactThinkingProcesses.length - 1] ?? null;
    const artifactSelectedSkills = artifactRouteActive
      ? ((task?.chat_session?.materialization?.selectedSkills ??
          []) as ChatArtifactSelectedSkill[])
      : [];
    const artifactThinkingPreview = artifactRouteActive
      ? buildArtifactThinkingPreview(task)
      : null;
    const artifactStatusPreviews = selectArtifactStatusPreviews({
      artifactThinkingPreview,
      executionChromeLivePreview: executionChrome.livePreview,
      executionChromeCodePreview: executionChrome.codePreview,
    });
    const artifactThinkingTitle = artifactRouteActive
      ? `Thinking through ${resolveArtifactThinkingSubject(task)}`
      : "Routing the request";
    const artifactThinkingDetail =
      artifactThinkingActiveProcess?.summary ||
      artifactThinkingLatestProcess?.summary ||
      task?.current_step ||
      "Chat is moving through the current artifact run.";
    const routeActivityTitle = defaultRunActivityTitle(runPresentation.planSummary);
    const routeActivityDetail =
      operatorFacingCurrentStep(task, runPresentation.planSummary) ||
      defaultRunActivityDetail(runPresentation.planSummary);

    if (hasOperatorDecisionPrompt) {
      return null;
    }

    if (submissionError) {
      if (artifactRouteActive) {
        return {
          tone: "error",
          title: artifactThinkingTitle,
          detail: artifactThinkingDetail || submissionFailureSummary.detail,
          metrics: null,
          processes: artifactThinkingProcesses,
          selectedSkills: artifactSelectedSkills,
          livePreview: artifactStatusPreviews.livePreview,
          codePreview: artifactStatusPreviews.codePreview,
        };
      }

      return {
        tone: "error",
        title: submissionFailureSummary.title,
        detail: submissionFailureSummary.detail,
        ...executionChrome,
      };
    }

    if (submissionInFlight) {
      return {
        title: artifactRouteActive ? artifactThinkingTitle : routeActivityTitle,
        detail: artifactRouteActive
          ? artifactThinkingDetail
          : routeActivityDetail,
        metrics: artifactRouteActive ? null : executionChrome.metrics,
        processes: artifactRouteActive ? artifactThinkingProcesses : executionChrome.processes,
        selectedSkills: artifactRouteActive ? artifactSelectedSkills : [],
        livePreview: artifactRouteActive
          ? artifactStatusPreviews.livePreview
          : executionChrome.livePreview,
        codePreview: artifactRouteActive
          ? artifactStatusPreviews.codePreview
          : executionChrome.codePreview,
      };
    }

    if (
      task &&
      isRunning &&
      !activeChatSessionId &&
      !runPresentation.finalAnswer
    ) {
      return {
        title: studioArtifactExpected
          ? "Thinking through the artifact request"
          : routeActivityTitle,
        detail: routeActivityDetail,
        ...executionChrome,
      };
    }

    if (
      task?.clarification_request &&
      task.chat_session &&
      !studioArtifactAvailable
    ) {
      return {
        title: "Clarification needed",
        detail: task.clarification_request.question,
        ...deriveTaskChatExecutionChrome(task),
      };
    }

    if (
      task?.chat_session &&
      isRunning &&
      !runPresentation.finalAnswer &&
      task.chat_session.lifecycleState !== "blocked"
    ) {
      const outcomeLabel = formatStudioStatusLabel(
        task.chat_session.outcomeRequest?.outcomeKind,
      );
      return {
        title:
          studioArtifactExpected || task.chat_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactThinkingTitle
            : routeActivityTitle || outcomeLabel || "Preparing the reply",
        detail:
          studioArtifactExpected || task.chat_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactThinkingDetail
            : routeActivityDetail,
        metrics:
          studioArtifactExpected || task.chat_session.outcomeRequest?.outcomeKind === "artifact"
            ? null
            : executionChrome.metrics,
        processes:
          studioArtifactExpected || task.chat_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactThinkingProcesses
            : executionChrome.processes,
        selectedSkills:
          studioArtifactExpected || task.chat_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactSelectedSkills
            : [],
        livePreview:
          studioArtifactExpected || task.chat_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactStatusPreviews.livePreview
            : executionChrome.livePreview,
        codePreview:
          studioArtifactExpected || task.chat_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactStatusPreviews.codePreview
            : executionChrome.codePreview,
      };
    }

    if (
      task?.chat_session &&
      !studioArtifactAvailable &&
      task.chat_session.lifecycleState === "blocked"
    ) {
      const blockedSummary = summarizeStudioFailure(
        task.current_step ||
          task.chat_session.artifactManifest.verification.summary ||
          task.chat_session.verifiedReply.summary,
      );
      return {
        tone: "error",
        title: artifactRouteActive ? artifactThinkingTitle : blockedSummary.title,
        detail:
          artifactRouteActive && artifactThinkingDetail
            ? artifactThinkingDetail
            : blockedSummary.detail,
        metrics: artifactRouteActive ? null : deriveTaskChatExecutionChrome(task).metrics,
        processes: artifactRouteActive
          ? artifactThinkingProcesses
          : deriveTaskChatExecutionChrome(task).processes,
        selectedSkills: artifactRouteActive ? artifactSelectedSkills : [],
        livePreview:
          artifactRouteActive
            ? artifactStatusPreviews.livePreview
            : deriveTaskChatExecutionChrome(task).livePreview,
        codePreview: artifactRouteActive
          ? artifactStatusPreviews.codePreview
          : deriveTaskChatExecutionChrome(task).codePreview,
      };
    }

    return null;
  }, [
    activeChatSessionId,
    hasOperatorDecisionPrompt,
    isRunning,
    isStudioVariant,
    runPresentation.finalAnswer,
    studioArtifactAvailable,
    studioArtifactExpected,
    submissionError,
    submissionInFlight,
    task,
  ]);

  return {
    activeChatSessionId,
    containerStyle,
    conversationTurns,
    hasOperatorDecisionPrompt,
    hasSessionContent,
    inlineStudioDecisionPrompt,
    isDualPanelSpotlight,
    latestAnsweredTurnIndex,
    runPresentation,
    selectedInspectionArtifact,
    shouldAutoFocusStudioComposer,
    showInitialLoader,
    showOverlaySessionChrome,
    studioArtifactAvailable,
    studioArtifactExpected,
    chatStatusCard,
    suppressConversationPendingIndicators:
      hasOperatorDecisionPrompt || Boolean(chatStatusCard),
    turnContexts,
  };
}
