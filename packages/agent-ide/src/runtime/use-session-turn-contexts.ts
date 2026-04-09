import { useMemo } from "react";

export interface SessionConversationMessageLike {
  role: string;
  text: string;
  timestamp: number;
}

export interface SessionConversationTurn<TMessage> {
  key: string;
  prompt: TMessage | null;
  answer: TMessage | null;
}

export interface SessionThoughtAgentLike {
  stepIndex: number;
}

export interface SessionSourceSearchLike {
  stepIndex: number;
  resultCount: number;
}

export interface SessionSourceBrowseLike {
  stepIndex: number;
}

export interface SessionTurnWindowLike {
  id: string;
  index: number;
  prompt: string;
  startAtMs: number | null;
  endAtMs: number | null;
}

export interface SessionScreenshotReceiptLike {
  hash: string;
  hasBlob: boolean;
  timestamp: string;
  stepIndex: number;
  summary: string;
}

export interface SessionStreamMetadata {
  streamId?: string | null;
  seq?: number | null;
  channel?: string | null;
  isFinal?: boolean | null;
}

export interface SessionTurnContext<
  TPlanSummary,
  TExecutionMoment,
  TViewKey extends string,
> {
  turnId: string | null;
  planSummary: TPlanSummary | null;
  executionMoments: TExecutionMoment[];
  thoughtCount: number;
  sourceCount: number;
  kernelEventCount: number;
  visualReceiptCount: number;
  latestVisualHash: string | null;
  latestVisualTimestamp: string | null;
  latestVisualStepIndex: number | null;
  latestVisualHasBlob: boolean;
  latestVisualSummary: string | null;
  streamPreview: string | null;
  streamLabel: string | null;
  streamIsFinal: boolean;
  defaultView: TViewKey;
}

export interface UseSessionTurnContextsOptions<
  TMessage extends SessionConversationMessageLike,
  TEvent,
  TPlanSummary,
  TExecutionMoment,
  TViewKey extends string,
  TTurnWindow extends SessionTurnWindowLike,
  TScreenshotReceipt extends SessionScreenshotReceiptLike,
  TThoughtAgent extends SessionThoughtAgentLike,
  TSearch extends SessionSourceSearchLike,
  TBrowse extends SessionSourceBrowseLike,
> {
  activeHistory: TMessage[];
  activeEvents: TEvent[];
  thoughtAgents: TThoughtAgent[];
  searches: TSearch[];
  browses: TBrowse[];
  buildEventTurnWindows: (events: TEvent[]) => TTurnWindow[];
  eventBelongsToTurnWindow: (event: TEvent, turn: TTurnWindow) => boolean;
  collectScreenshotReceipts: (events: TEvent[]) => TScreenshotReceipt[];
  buildPlanSummary: (events: TEvent[]) => TPlanSummary | null;
  buildExecutionMoments: (
    events: TEvent[],
    planSummary: TPlanSummary | null,
  ) => TExecutionMoment[];
  getEventToolName: (event: TEvent) => string;
  getEventOutputText: (event: TEvent) => string;
  getEventType: (event: TEvent) => string;
  getEventTimestamp: (event: TEvent) => string;
  getEventStepIndex: (event: TEvent) => number;
  getCanonicalAnswerOutput: (event: TEvent) => string | null;
  getStreamMetadata: (event: TEvent) => SessionStreamMetadata | null;
  views: {
    plan: TViewKey;
    thoughts: TViewKey;
    sources: TViewKey;
    screenshots: TViewKey;
    fallback: TViewKey;
  };
}

function normalizeOutputForCompare(value: string): string {
  return value.replace(/\s+/g, " ").trim().toLowerCase();
}

const STREAM_PREVIEW_MAX_LINES = 12;
const STREAM_PREVIEW_MAX_CHARS = 1600;

function buildStreamPreview<TEvent>({
  events,
  getEventType,
  getEventTimestamp,
  getEventOutputText,
  getEventToolName,
  getStreamMetadata,
}: Pick<
  UseSessionTurnContextsOptions<
    SessionConversationMessageLike,
    TEvent,
    unknown,
    unknown,
    string,
    SessionTurnWindowLike,
    SessionScreenshotReceiptLike,
    SessionThoughtAgentLike,
    SessionSourceSearchLike,
    SessionSourceBrowseLike
  >,
  | "getEventType"
  | "getEventTimestamp"
  | "getEventOutputText"
  | "getEventToolName"
  | "getStreamMetadata"
> & { events: TEvent[] }): {
  streamPreview: string | null;
  streamLabel: string | null;
  streamIsFinal: boolean;
} {
  const streamEvents = events.filter(
    (event) => getEventType(event) === "COMMAND_STREAM",
  );
  if (streamEvents.length === 0) {
    return {
      streamPreview: null,
      streamLabel: null,
      streamIsFinal: false,
    };
  }

  const byTimestamp = [...streamEvents].sort((left, right) =>
    getEventTimestamp(left).localeCompare(getEventTimestamp(right)),
  );
  const latest = byTimestamp[byTimestamp.length - 1]!;
  const latestMetadata = getStreamMetadata(latest);
  const latestStreamId = (latestMetadata?.streamId || "").trim();
  const scoped = latestStreamId
    ? byTimestamp.filter((event) => {
        const metadata = getStreamMetadata(event);
        return (metadata?.streamId || "").trim() === latestStreamId;
      })
    : byTimestamp;
  const ordered = [...scoped].sort((left, right) => {
    const leftSeq = Number(getStreamMetadata(left)?.seq ?? 0);
    const rightSeq = Number(getStreamMetadata(right)?.seq ?? 0);
    if (leftSeq !== rightSeq) {
      return leftSeq - rightSeq;
    }
    return getEventTimestamp(left).localeCompare(getEventTimestamp(right));
  });

  const merged = ordered.map((event) => getEventOutputText(event)).join("");
  const lines = merged
    .split(/\r?\n/g)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0);
  let preview =
    lines.length > 0
      ? lines.slice(-STREAM_PREVIEW_MAX_LINES).join("\n")
      : merged.trim();
  if (preview.length > STREAM_PREVIEW_MAX_CHARS) {
    preview = preview.slice(preview.length - STREAM_PREVIEW_MAX_CHARS);
  }

  const tool = getEventToolName(latest).trim();
  const channel = (latestMetadata?.channel || "").trim();
  const streamLabel = [tool || "command", channel ? `(${channel})` : ""]
    .filter(Boolean)
    .join(" ");

  return {
    streamPreview: preview || null,
    streamLabel: streamLabel || null,
    streamIsFinal: Boolean(latestMetadata?.isFinal),
  };
}

export function useSessionTurnContexts<
  TMessage extends SessionConversationMessageLike,
  TEvent,
  TPlanSummary,
  TExecutionMoment,
  TViewKey extends string,
  TTurnWindow extends SessionTurnWindowLike,
  TScreenshotReceipt extends SessionScreenshotReceiptLike,
  TThoughtAgent extends SessionThoughtAgentLike,
  TSearch extends SessionSourceSearchLike,
  TBrowse extends SessionSourceBrowseLike,
>({
  activeHistory,
  activeEvents,
  thoughtAgents,
  searches,
  browses,
  buildEventTurnWindows,
  eventBelongsToTurnWindow,
  collectScreenshotReceipts,
  buildPlanSummary,
  buildExecutionMoments,
  getEventToolName,
  getEventOutputText,
  getEventType,
  getEventTimestamp,
  getEventStepIndex,
  getCanonicalAnswerOutput,
  getStreamMetadata,
  views,
}: UseSessionTurnContextsOptions<
  TMessage,
  TEvent,
  TPlanSummary,
  TExecutionMoment,
  TViewKey,
  TTurnWindow,
  TScreenshotReceipt,
  TThoughtAgent,
  TSearch,
  TBrowse
>) {
  const canonicalAnswerHashes = useMemo(() => {
    const hashes = new Set<string>();
    for (const event of activeEvents) {
      const output = (getCanonicalAnswerOutput(event) || "").trim();
      if (!output) {
        continue;
      }
      hashes.add(normalizeOutputForCompare(output));
    }
    return hashes;
  }, [activeEvents, getCanonicalAnswerOutput]);

  const fallbackConversation = useMemo(() => {
    const shouldMatchCanonical = canonicalAnswerHashes.size > 0;
    return activeHistory.filter((message) => {
      if (message.role === "user") return true;
      if (message.role !== "agent") return false;
      if (!shouldMatchCanonical) return true;
      return canonicalAnswerHashes.has(normalizeOutputForCompare(message.text));
    });
  }, [activeHistory, canonicalAnswerHashes]);

  const conversationTurns = useMemo<SessionConversationTurn<TMessage>[]>(() => {
    const turns: SessionConversationTurn<TMessage>[] = [];
    let pendingPrompt: TMessage | null = null;
    let index = 0;

    for (const message of fallbackConversation) {
      if (message.role === "user") {
        if (pendingPrompt) {
          turns.push({
            key: `turn-${index}-${pendingPrompt.timestamp}`,
            prompt: pendingPrompt,
            answer: null,
          });
          index += 1;
        }
        pendingPrompt = message;
        continue;
      }

      if (message.role !== "agent") {
        continue;
      }

      if (pendingPrompt) {
        turns.push({
          key: `turn-${index}-${pendingPrompt.timestamp}-${message.timestamp}`,
          prompt: pendingPrompt,
          answer: message,
        });
        index += 1;
        pendingPrompt = null;
        continue;
      }

      turns.push({
        key: `turn-${index}-agent-${message.timestamp}`,
        prompt: null,
        answer: message,
      });
      index += 1;
    }

    if (pendingPrompt) {
      turns.push({
        key: `turn-${index}-${pendingPrompt.timestamp}`,
        prompt: pendingPrompt,
        answer: null,
      });
    }

    return turns;
  }, [fallbackConversation]);

  const latestAnsweredTurnIndex = useMemo(() => {
    for (let index = conversationTurns.length - 1; index >= 0; index -= 1) {
      if (conversationTurns[index]?.answer) {
        return index;
      }
    }
    return -1;
  }, [conversationTurns]);

  const eventTurnWindows = useMemo(
    () => buildEventTurnWindows(activeEvents),
    [activeEvents, buildEventTurnWindows],
  );

  const turnContexts = useMemo<
    SessionTurnContext<TPlanSummary, TExecutionMoment, TViewKey>[]
  >(() => {
    let promptOrdinal = 0;

    return conversationTurns.map((turn) => {
      const window = turn.prompt
        ? eventTurnWindows[promptOrdinal++] || null
        : null;

      if (!window) {
        return {
          turnId: null,
          planSummary: null,
          executionMoments: [],
          thoughtCount: 0,
          sourceCount: 0,
          kernelEventCount: 0,
          visualReceiptCount: 0,
          latestVisualHash: null,
          latestVisualTimestamp: null,
          latestVisualStepIndex: null,
          latestVisualHasBlob: false,
          latestVisualSummary: null,
          streamPreview: null,
          streamLabel: null,
          streamIsFinal: false,
          defaultView: views.fallback,
        };
      }

      const windowEvents = activeEvents.filter((event) =>
        eventBelongsToTurnWindow(event, window),
      );
      const stepIndexes = new Set(
        windowEvents.map((event) => getEventStepIndex(event)),
      );
      const thoughtCount = thoughtAgents.filter((agent) =>
        stepIndexes.has(agent.stepIndex),
      ).length;
      const sourceCount = Math.max(
        searches
          .filter((row) => stepIndexes.has(row.stepIndex))
          .reduce((sum, row) => sum + Math.max(0, row.resultCount), 0),
        browses.filter((row) => stepIndexes.has(row.stepIndex)).length,
      );
      const kernelEventCount = windowEvents.filter(
        (event) => getEventType(event) !== "INFO_NOTE",
      ).length;
      const screenshotReceipts = collectScreenshotReceipts(windowEvents);
      const latestVisualReceipt = screenshotReceipts[0] || null;
      const streamPreview = buildStreamPreview({
        events: windowEvents,
        getEventType,
        getEventTimestamp,
        getEventOutputText,
        getEventToolName,
        getStreamMetadata,
      });
      const planSummary = buildPlanSummary(windowEvents);

      const defaultView = planSummary
        ? views.plan
        : thoughtCount > 0
          ? views.thoughts
          : sourceCount > 0
            ? views.sources
            : screenshotReceipts.length > 0
              ? views.screenshots
              : views.fallback;

      return {
        turnId: window.id,
        planSummary,
        executionMoments: buildExecutionMoments(windowEvents, planSummary),
        thoughtCount,
        sourceCount,
        kernelEventCount,
        visualReceiptCount: screenshotReceipts.length,
        latestVisualHash: latestVisualReceipt?.hash || null,
        latestVisualTimestamp: latestVisualReceipt?.timestamp || null,
        latestVisualStepIndex: latestVisualReceipt?.stepIndex ?? null,
        latestVisualHasBlob: latestVisualReceipt?.hasBlob || false,
        latestVisualSummary: latestVisualReceipt?.summary || null,
        streamPreview: streamPreview.streamPreview,
        streamLabel: streamPreview.streamLabel,
        streamIsFinal: streamPreview.streamIsFinal,
        defaultView,
      };
    });
  }, [
    activeEvents,
    browses,
    buildExecutionMoments,
    buildPlanSummary,
    collectScreenshotReceipts,
    conversationTurns,
    eventBelongsToTurnWindow,
    eventTurnWindows,
    getEventOutputText,
    getEventStepIndex,
    getEventTimestamp,
    getEventToolName,
    getEventType,
    getStreamMetadata,
    searches,
    thoughtAgents,
    views.fallback,
    views.plan,
    views.screenshots,
    views.sources,
    views.thoughts,
  ]);

  return {
    conversationTurns,
    latestAnsweredTurnIndex,
    turnContexts,
  };
}
