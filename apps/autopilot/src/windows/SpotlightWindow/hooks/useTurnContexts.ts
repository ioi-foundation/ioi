import {
  useSessionTurnContexts,
  type SessionConversationTurn,
  type SessionTurnContext,
} from "@ioi/agent-ide";
import type {
  ActivityEventRef,
  AgentEvent,
  ArtifactHubViewKey,
  ChatMessage,
  ExecutionMoment,
  RunPresentation,
  SourceSummary,
  StudioArtifactSession,
  ThoughtSummary,
  ToolActivityGroupPresentation,
} from "../../../types";
import type { StudioConversationArtifactEntry } from "../components/studioArtifactConversationModel";
import {
  buildReasoningDurationLabel,
  buildTurnToolActivityGroup,
} from "../components/conversationTranscriptModel";
import {
  collectStudioConversationArtifactsForTurn,
  studioArtifactSessionIsPresentable,
} from "../components/studioArtifactConversationModel";
import { collectScreenshotReceipts } from "../utils/screenshotEvidence";
import {
  eventOutputText,
  eventToolName,
  toEventString,
} from "../utils/eventFields";
import {
  buildEventTurnWindows,
  eventBelongsToTurnWindow,
} from "../utils/turnWindows";
import {
  buildActivityGroups,
  buildExecutionMoments,
  buildPlanSummary,
  buildSourceSummary,
  buildThoughtSummary,
} from "../viewmodels/contentPipeline.summaries";

export type ConversationTurn = SessionConversationTurn<ChatMessage>;
export type TurnContext = SessionTurnContext<
  RunPresentation["planSummary"],
  ExecutionMoment,
  ArtifactHubViewKey
> & {
  studioSession: StudioArtifactSession | null;
  artifacts: StudioConversationArtifactEntry[];
  hasPendingStudioArtifact: boolean;
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  toolActivityGroup: ToolActivityGroupPresentation | null;
  reasoningDurationLabel: string | null;
};

type UseTurnContextsOptions = {
  activeHistory: ChatMessage[];
  activeEvents: AgentEvent[];
  activeStudioSession?: StudioArtifactSession | null;
  runPresentation: RunPresentation;
};

function isChatReplyTool(event: AgentEvent): boolean {
  const tool = eventToolName(event).toLowerCase();
  return tool === "chat__reply" || tool === "chat::reply";
}

function canonicalAnswerOutputForEvent(event: AgentEvent): string | null {
  if (!isChatReplyTool(event)) {
    return null;
  }

  const output = eventOutputText(event).trim();
  return output || null;
}

function streamMetadataForEvent(event: AgentEvent) {
  const digest = event.digest || {};
  return {
    streamId: toEventString(digest.stream_id as unknown).trim() || null,
    seq: Number((digest as Record<string, unknown>).seq ?? 0),
    channel: toEventString(digest.channel as unknown).trim() || null,
    isFinal: Boolean((digest as Record<string, unknown>).is_final),
  };
}

function toActivityEventRefs(events: AgentEvent[]): ActivityEventRef[] {
  return events.map((event) => ({
    key: event.event_id,
    kind:
      event.event_type === "RECEIPT"
        ? "receipt_event"
        : event.event_type === "INFO_NOTE"
          ? "reasoning_event"
          : "workload_event",
    event,
    toolName: eventToolName(event),
  }));
}

export function useTurnContexts({
  activeHistory,
  activeEvents,
  activeStudioSession = null,
  runPresentation,
}: UseTurnContextsOptions) {
  const base = useSessionTurnContexts({
    activeHistory,
    activeEvents,
    thoughtAgents: runPresentation.thoughtSummary?.agents || [],
    searches: runPresentation.sourceSummary?.searches || [],
    browses: runPresentation.sourceSummary?.browses || [],
    buildEventTurnWindows,
    eventBelongsToTurnWindow,
    collectScreenshotReceipts,
    buildPlanSummary: (events) => buildPlanSummary(toActivityEventRefs(events)),
    buildExecutionMoments: (events, planSummary) =>
      buildExecutionMoments(toActivityEventRefs(events), planSummary),
    getEventToolName: eventToolName,
    getEventOutputText: eventOutputText,
    getEventType: (event) => event.event_type,
    getEventTimestamp: (event) => event.timestamp,
    getEventStepIndex: (event) => event.step_index,
    getCanonicalAnswerOutput: canonicalAnswerOutputForEvent,
    getStreamMetadata: streamMetadataForEvent,
    views: {
      plan: "active_context",
      thoughts: "thoughts",
      sources: "sources",
      screenshots: "screenshots",
      fallback: "kernel_logs",
    },
  });

  const eventTurnWindows = buildEventTurnWindows(activeEvents);
  let promptOrdinal = 0;
  const latestTurnIndex = base.conversationTurns.length - 1;

  const turnContexts = base.turnContexts.map((context, index) => {
    const turn = base.conversationTurns[index] || null;
    const window = turn?.prompt
      ? eventTurnWindows[promptOrdinal++] || null
      : null;
    const windowEvents = window
      ? activeEvents.filter((event) => eventBelongsToTurnWindow(event, window))
      : [];
    const activityRefs = toActivityEventRefs(windowEvents);
    const thoughtSummary = buildThoughtSummary(
      buildActivityGroups(activityRefs),
    );
    const artifacts = collectStudioConversationArtifactsForTurn(
      activeEvents,
      windowEvents,
      window?.id ?? null,
      activeStudioSession,
    );
    const activeStudioSessionBelongsToTurn =
      (activeStudioSession?.originPromptEventId ?? null) === (window?.id ?? null)
      || (
        index === latestTurnIndex &&
        !!turn?.prompt &&
        !!activeStudioSession &&
        !activeStudioSession.originPromptEventId
      );
    const primaryStudioSession = activeStudioSessionBelongsToTurn
      ? activeStudioSession
      : artifacts[0]?.studioSession ?? null;
    const operatorSourceRefs =
      primaryStudioSession?.activeOperatorRun?.steps.flatMap(
        (step) => step.sourceRefs || [],
      ) || [];
    const sourceSummary = buildSourceSummary(activityRefs, operatorSourceRefs);
    const hasActiveArtifactSession =
      !!primaryStudioSession &&
      activeStudioSession?.sessionId === primaryStudioSession.sessionId;
    const hasPendingStudioArtifact =
      !!primaryStudioSession &&
      primaryStudioSession.outcomeRequest.outcomeKind === "artifact" &&
      !studioArtifactSessionIsPresentable(primaryStudioSession);

    return {
      ...context,
      studioSession: primaryStudioSession,
      artifacts,
      hasPendingStudioArtifact,
      sourceSummary,
      thoughtSummary,
      toolActivityGroup: buildTurnToolActivityGroup(
        activityRefs,
        context.planSummary,
        artifacts,
        {
          defaultOpen: hasActiveArtifactSession,
          studioSession: primaryStudioSession,
        },
      ),
      reasoningDurationLabel: turn?.prompt
        ? buildReasoningDurationLabel(activityRefs, turn.prompt.timestamp)
        : null,
    };
  });

  return {
    conversationTurns: base.conversationTurns,
    latestAnsweredTurnIndex: base.latestAnsweredTurnIndex,
    turnContexts,
  };
}
