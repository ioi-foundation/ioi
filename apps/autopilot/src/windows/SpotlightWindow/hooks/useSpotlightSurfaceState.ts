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
  StudioArtifactRuntimeNarrationEvent,
  StudioArtifactRuntimePreviewSnapshot,
  StudioArtifactSelectedSkill,
  StudioArtifactSkillDiscoveryResolution,
} from "../../../types";

export type StudioStatusCardState = {
  tone?: "active" | "error";
  title: string;
  detail: string;
  metrics?: StudioExecutionMetrics;
  processes?: StudioExecutionProcess[];
  selectedSkills?: StudioArtifactSelectedSkill[];
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

type StudioStatusPreview = NonNullable<StudioStatusCardState>["livePreview"];

function shouldDisplayArtifactStatusPreview(
  preview: StudioStatusPreview,
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
  artifactThinkingPreview: StudioStatusPreview;
  executionChromeLivePreview: StudioStatusPreview;
  executionChromeCodePreview: StudioStatusPreview;
}): {
  livePreview: StudioStatusPreview;
  codePreview: StudioStatusPreview;
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

function isArtifactStudioRoute(task: any): boolean {
  return (
    task?.studio_session?.outcomeRequest?.outcomeKind === "artifact" ||
    task?.studio_outcome?.outcomeKind === "artifact"
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
    task?.studio_session?.materialization?.artifactBrief?.subjectDomain?.trim() || "";
  if (subjectDomain) {
    return subjectDomain;
  }

  const title = task?.studio_session?.title?.trim() || "";
  if (title) {
    return title.toLowerCase();
  }

  return "the artifact request";
}

function sortArtifactRuntimeNarrationEvents(
  events: StudioArtifactRuntimeNarrationEvent[],
): StudioArtifactRuntimeNarrationEvent[] {
  return [...events].sort((left, right) => {
    const timeDelta = (left.occurredAtMs || 0) - (right.occurredAtMs || 0);
    if (timeDelta !== 0) {
      return timeDelta;
    }
    return String(left.eventId || "").localeCompare(String(right.eventId || ""));
  });
}

function artifactRuntimeStepId(
  event: StudioArtifactRuntimeNarrationEvent,
): string {
  return String(event.stepKey || event.stepId || "").trim();
}

function artifactRuntimeStepKind(
  event: StudioArtifactRuntimeNarrationEvent,
): string {
  return String(event.stepKind || "").trim();
}

function artifactRuntimeEventKind(
  event: StudioArtifactRuntimeNarrationEvent,
): string {
  return String(event.eventKindKey || event.eventKind || "").trim().toLowerCase();
}

function artifactRuntimeStatus(
  event: StudioArtifactRuntimeNarrationEvent,
): string {
  return String(event.statusKind || event.status || "").trim().toLowerCase();
}

function artifactThinkingLabelForEvent(
  event: StudioArtifactRuntimeNarrationEvent,
): string {
  switch (artifactRuntimeStepId(event)) {
    case "understand_request":
      return "Understand request";
    case "artifact_route_committed":
      return "Route to artifact";
    case "skill_discovery":
      return "Check for guidance";
    case "skill_read":
      return event.title || "Read guidance";
    case "artifact_brief":
      return "Shape artifact brief";
    case "author_artifact":
      return "Write artifact";
    case "replan_execution":
      return "Switch execution strategy";
    case "verify_artifact":
      return "Verify artifact";
    case "present_artifact":
      return "Open artifact";
    default:
      switch (artifactRuntimeStepKind(event)) {
        case "intake":
          return "Understand request";
        case "routing":
          return "Route to artifact";
        case "guidance":
          return event.title || "Check for guidance";
        case "planning":
          return event.title || "Shape artifact brief";
        case "authoring":
          return event.title || "Write artifact";
        case "strategy":
          return event.title || "Switch execution strategy";
        case "verification":
          return event.title || "Verify artifact";
        case "presentation":
          return event.title || "Open artifact";
        default:
          return event.title || "Artifact step";
      }
  }
}

function artifactThinkingIconKeyForEvent(
  event: StudioArtifactRuntimeNarrationEvent,
): string {
  switch (artifactRuntimeStepId(event)) {
    case "understand_request":
      return "search";
    case "artifact_route_committed":
      return "cube";
    case "skill_discovery":
    case "skill_read":
      return "sparkles";
    case "artifact_brief":
      return "copy";
    case "author_artifact":
      return "code";
    case "replan_execution":
      return "retry";
    case "verify_artifact":
      return "check";
    case "present_artifact":
      return "artifacts";
    default:
      switch (artifactRuntimeStepKind(event)) {
        case "intake":
          return "search";
        case "routing":
          return "cube";
        case "planning":
          return "copy";
        case "authoring":
          return "code";
        case "strategy":
          return "retry";
        case "verification":
          return "check";
        case "presentation":
          return "artifacts";
        default:
          return "sparkles";
      }
  }
}

function buildArtifactThinkingPreview(
  task: any,
): StudioStatusPreview {
  const runtimeNarrationEvents = sortArtifactRuntimeNarrationEvents(
    ((task?.studio_session?.materialization?.runtimeNarrationEvents ??
      []) as StudioArtifactRuntimeNarrationEvent[]).filter(
      (event) => artifactRuntimeEventKind(event) === "preview",
    ),
  );
  if (runtimeNarrationEvents.length === 0) {
    return null;
  }

  const stepEvents = sortArtifactRuntimeNarrationEvents(
    ((task?.studio_session?.materialization?.runtimeNarrationEvents ??
      []) as StudioArtifactRuntimeNarrationEvent[]).filter(
      (event) => artifactRuntimeEventKind(event) !== "preview",
    ),
  );
  const activeAttemptId =
    [...stepEvents]
      .reverse()
        .find(
        (event) =>
          artifactRuntimeStatus(event) === "active" &&
          typeof event.attemptId === "string" &&
          event.attemptId.trim().length > 0,
      )
      ?.attemptId ?? null;
  const matchingPreview = activeAttemptId
    ? [...runtimeNarrationEvents]
        .reverse()
        .find((event) => event.attemptId === activeAttemptId && event.preview)
    : [...runtimeNarrationEvents]
        .reverse()
        .find(
          (event) =>
            event.preview &&
            (Boolean(event.preview.isFinal) ||
              ["complete", "completed", "blocked", "failed", "interrupted"].includes(
                String(event.preview.status || "").trim().toLowerCase(),
              )),
        ) ?? null;
  if (activeAttemptId && !matchingPreview) {
    return null;
  }
  const preview = matchingPreview?.preview as StudioArtifactRuntimePreviewSnapshot | null;
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

function buildArtifactThinkingProcesses(task: any): StudioExecutionProcess[] {
  const materialization = task?.studio_session?.materialization;
  const runtimeNarrationEvents = sortArtifactRuntimeNarrationEvents(
    ((materialization?.runtimeNarrationEvents ?? []) as StudioArtifactRuntimeNarrationEvent[])
      .filter((event) => artifactRuntimeEventKind(event) !== "preview"),
  );
  const skillDiscoveryResolution = (materialization?.skillDiscoveryResolution ??
    null) as StudioArtifactSkillDiscoveryResolution | null;
  if (runtimeNarrationEvents.length === 0) {
    return [];
  }

  const processes = runtimeNarrationEvents
    .filter((event) => artifactRuntimeStepId(event).length > 0)
    .map((event) => ({
      id: event.eventId || `${artifactRuntimeStepId(event)}:${event.occurredAtMs}`,
      label: artifactThinkingLabelForEvent(event),
      status: formatArtifactThinkingStatus(event.status),
      summary:
        event.detail ||
        skillDiscoveryResolution?.rationale ||
        "Studio is working through the active artifact step.",
      isActive: artifactRuntimeStatus(event) === "active",
      iconKey: artifactThinkingIconKeyForEvent(event),
    }));

  return processes;
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
  const studioArtifactExpected = isArtifactStudioRoute(task);
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
    const executionChrome = deriveTaskStudioExecutionChrome(task);
    const artifactRouteActive = isArtifactStudioRoute(task);
    const artifactThinkingProcesses = artifactRouteActive
      ? buildArtifactThinkingProcesses(task)
      : executionChrome.processes;
    const artifactThinkingActiveProcess =
      artifactThinkingProcesses.find((process) => process.isActive) ?? null;
    const artifactThinkingLatestProcess =
      artifactThinkingProcesses[artifactThinkingProcesses.length - 1] ?? null;
    const artifactSelectedSkills = artifactRouteActive
      ? ((task?.studio_session?.materialization?.selectedSkills ??
          []) as StudioArtifactSelectedSkill[])
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
      "Studio is moving through the current artifact run.";

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
        title: artifactRouteActive
          ? artifactThinkingTitle
          : "Routing the request",
        detail: artifactRouteActive
          ? artifactThinkingDetail
          : "Studio is choosing whether this should remain conversational, open a tool surface, render a visualizer, or materialize an artifact.",
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
      !activeStudioSessionId &&
      !runPresentation.finalAnswer
    ) {
      return {
        title: studioArtifactExpected
          ? "Thinking through the artifact request"
          : "Preparing the outcome surface",
        detail:
          task.current_step ||
          "Studio is materializing the right outcome type and waiting for verification evidence.",
        ...executionChrome,
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
            ? artifactThinkingTitle
            : outcomeLabel
              ? `Working the ${outcomeLabel.toLowerCase()} route`
              : "Working the outcome surface",
        detail:
          studioArtifactExpected || task.studio_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactThinkingDetail
            : task.current_step ||
              "Studio is routing the active work items, merging worker output, and verifying the next usable surface.",
        metrics:
          studioArtifactExpected || task.studio_session.outcomeRequest?.outcomeKind === "artifact"
            ? null
            : executionChrome.metrics,
        processes:
          studioArtifactExpected || task.studio_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactThinkingProcesses
            : executionChrome.processes,
        selectedSkills:
          studioArtifactExpected || task.studio_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactSelectedSkills
            : [],
        livePreview:
          studioArtifactExpected || task.studio_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactStatusPreviews.livePreview
            : executionChrome.livePreview,
        codePreview:
          studioArtifactExpected || task.studio_session.outcomeRequest?.outcomeKind === "artifact"
            ? artifactStatusPreviews.codePreview
            : executionChrome.codePreview,
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
        tone: "error",
        title: artifactRouteActive ? artifactThinkingTitle : blockedSummary.title,
        detail:
          artifactRouteActive && artifactThinkingDetail
            ? artifactThinkingDetail
            : blockedSummary.detail,
        metrics: artifactRouteActive ? null : deriveTaskStudioExecutionChrome(task).metrics,
        processes: artifactRouteActive
          ? artifactThinkingProcesses
          : deriveTaskStudioExecutionChrome(task).processes,
        selectedSkills: artifactRouteActive ? artifactSelectedSkills : [],
        livePreview:
          artifactRouteActive
            ? artifactStatusPreviews.livePreview
            : deriveTaskStudioExecutionChrome(task).livePreview,
        codePreview: artifactRouteActive
          ? artifactStatusPreviews.codePreview
          : deriveTaskStudioExecutionChrome(task).codePreview,
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
