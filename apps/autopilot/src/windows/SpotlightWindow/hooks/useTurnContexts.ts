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
  ThoughtSummary,
  ToolActivityGroupPresentation,
} from "../../../types";
import type { StudioConversationArtifactEntry } from "../components/studioArtifactConversationModel";
import {
  buildReasoningDurationLabel,
  buildTurnToolActivityGroup,
} from "../components/conversationTranscriptModel";
import { collectStudioConversationArtifacts } from "../components/studioArtifactConversationModel";
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
  artifacts: StudioConversationArtifactEntry[];
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  toolActivityGroup: ToolActivityGroupPresentation | null;
  reasoningDurationLabel: string | null;
};

type UseTurnContextsOptions = {
  activeHistory: ChatMessage[];
  activeEvents: AgentEvent[];
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

  const turnContexts = base.turnContexts.map((context, index) => {
    const turn = base.conversationTurns[index] || null;
    const window = turn?.prompt
      ? eventTurnWindows[promptOrdinal++] || null
      : null;
    const windowEvents = window
      ? activeEvents.filter((event) => eventBelongsToTurnWindow(event, window))
      : [];
    const activityRefs = toActivityEventRefs(windowEvents);
    const sourceSummary = buildSourceSummary(activityRefs);
    const thoughtSummary = buildThoughtSummary(
      buildActivityGroups(activityRefs),
    );
    const artifacts = collectStudioConversationArtifacts(windowEvents);

    return {
      ...context,
      artifacts,
      sourceSummary,
      thoughtSummary,
      toolActivityGroup: buildTurnToolActivityGroup(
        activityRefs,
        context.planSummary,
        artifacts,
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
