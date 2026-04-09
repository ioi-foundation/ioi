import { useMemo } from "react";
import { hasOpenableArtifactSurface } from "../components/studioArtifactSurfaceModel";
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
  deriveStudioExecutionChrome as deriveStudioExecutionChromeState,
  formatStudioStatusLabel,
  type StudioExecutionMetrics,
  type StudioExecutionProcess,
} from "../components/studioExecutionChrome";
import type {
  AgentEvent,
  Artifact,
  ChatMessage,
  RunPresentation,
  SessionSummary,
} from "../../../types";

export type StudioStatusCardState = {
  tone?: "active";
  title: string;
  detail: string;
  metrics?: StudioExecutionMetrics;
  processes?: StudioExecutionProcess[];
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

function deriveTaskStudioExecutionChrome(task: any) {
  const materialization = task?.studio_session?.materialization;
  const executionEnvelope = materialization?.executionEnvelope ?? null;
  return deriveStudioExecutionChromeState({
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
      title: "Studio kept the request in conversation",
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
      title: "Studio did not open an artifact yet",
      detail:
        "The request is still here, but the artifact surface was not ready to open. Continue in chat, or inspect the trace if you need to see what happened.",
    };
  }

  return {
    title: "Studio kept the request in conversation",
    detail:
      "The request did not settle into a usable Studio surface yet. Continue in chat, or inspect the trace if you need the underlying runtime details.",
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

  const hasSessionContent = activeHistory.length > 0 || chatEvents.length > 0;
  const activeStudioSessionId = task?.studio_session?.sessionId ?? null;
  const studioArtifactExpected =
    Boolean(task?.studio_session) &&
    task?.studio_session?.outcomeRequest?.outcomeKind === "artifact";
  const shouldAutoFocusStudioComposer =
    isStudioVariant &&
    !inputLockedByCredential &&
    !seedIntent?.trim() &&
    !hasSessionContent &&
    !intent.trim();

  const studioArtifactAvailable = useMemo(() => {
    const manifest = task?.studio_session?.artifactManifest;
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
    task?.studio_session,
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
      runPresentation,
    });

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

  const studioStatusCard: StudioStatusCardState = useMemo(() => {
    if (!isStudioVariant) {
      return null;
    }

    const submissionFailureSummary = summarizeStudioFailure(submissionError);

    if (hasOperatorDecisionPrompt) {
      return null;
    }

    if (submissionError) {
      const executionChrome = deriveTaskStudioExecutionChrome(task);
      return {
        tone: "active",
        title: submissionFailureSummary.title,
        detail: submissionFailureSummary.detail,
        ...executionChrome,
      };
    }

    if (submissionInFlight) {
      return {
        title: "Routing the request",
        detail:
          "Studio is choosing whether this should remain conversational, open a tool surface, render a visualizer, or materialize an artifact.",
        ...deriveTaskStudioExecutionChrome(task),
      };
    }

    if (
      task &&
      isRunning &&
      !activeStudioSessionId &&
      !runPresentation.finalAnswer
    ) {
      return {
        title: "Preparing the outcome surface",
        detail:
          task.current_step ||
          "Studio is materializing the right outcome type and waiting for verification evidence.",
        ...deriveTaskStudioExecutionChrome(task),
      };
    }

    if (
      task?.clarification_request &&
      task.studio_session &&
      !studioArtifactAvailable
    ) {
      return {
        title: "Studio needs clarification before it can open an artifact",
        detail: task.current_step || task.clarification_request.question,
        ...deriveTaskStudioExecutionChrome(task),
      };
    }

    if (
      task?.studio_session &&
      isRunning &&
      !runPresentation.finalAnswer &&
      task.studio_session.lifecycleState !== "blocked"
    ) {
      const outcomeLabel = formatStudioStatusLabel(
        task.studio_session.outcomeRequest?.outcomeKind,
      );
      return {
        title:
          studioArtifactExpected || task.studio_session.outcomeRequest?.outcomeKind === "artifact"
            ? "Building the artifact surface"
            : outcomeLabel
              ? `Working the ${outcomeLabel.toLowerCase()} route`
              : "Working the outcome surface",
        detail:
          task.current_step ||
          "Studio is routing the active work items, merging worker output, and verifying the next usable surface.",
        ...deriveTaskStudioExecutionChrome(task),
      };
    }

    if (
      task?.studio_session &&
      !studioArtifactAvailable &&
      task.studio_session.lifecycleState === "blocked"
    ) {
      const blockedSummary = summarizeStudioFailure(
        task.current_step ||
          task.studio_session.artifactManifest.verification.summary ||
          task.studio_session.verifiedReply.summary,
      );
      return {
        tone: "active",
        title: blockedSummary.title,
        detail: blockedSummary.detail,
        ...deriveTaskStudioExecutionChrome(task),
      };
    }

    return null;
  }, [
    activeStudioSessionId,
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
    activeStudioSessionId,
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
    studioStatusCard,
    suppressConversationPendingIndicators:
      hasOperatorDecisionPrompt || Boolean(studioStatusCard),
    turnContexts,
  };
}
