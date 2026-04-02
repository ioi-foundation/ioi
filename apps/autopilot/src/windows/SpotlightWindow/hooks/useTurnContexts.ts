import { useMemo } from "react";
import type {
  AgentEvent,
  ArtifactHubViewKey,
  ChatMessage,
  ExecutionMoment,
  RunPresentation,
} from "../../../types";
import { collectScreenshotReceipts } from "../utils/screenshotEvidence";
import {
  eventOutputText,
  eventToolName,
  toEventString,
} from "../utils/eventFields";
import {
  buildEventTurnWindows,
  eventBelongsToTurnWindow,
  type EventTurnWindow,
} from "../utils/turnWindows";
import {
  buildExecutionMoments,
  buildPlanSummary,
} from "../viewmodels/contentPipeline.summaries";

export type ConversationTurn = {
  key: string;
  prompt: ChatMessage | null;
  answer: ChatMessage | null;
};

export type TurnContext = {
  turnId: string | null;
  planSummary: RunPresentation["planSummary"];
  executionMoments: ExecutionMoment[];
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
  defaultView: ArtifactHubViewKey;
};

type UseTurnContextsOptions = {
  activeHistory: ChatMessage[];
  activeEvents: AgentEvent[];
  runPresentation: RunPresentation;
};

function normalizeOutputForCompare(value: string): string {
  return value.replace(/\s+/g, " ").trim().toLowerCase();
}

function isChatReplyTool(event: AgentEvent): boolean {
  const tool = eventToolName(event).toLowerCase();
  return tool === "chat__reply" || tool === "chat::reply";
}

function collectCanonicalAnswerHashes(events: AgentEvent[]): Set<string> {
  const hashes = new Set<string>();
  for (const event of events) {
    if (!isChatReplyTool(event)) continue;
    const output = eventOutputText(event).trim();
    if (!output) continue;
    hashes.add(normalizeOutputForCompare(output));
  }
  return hashes;
}

const STREAM_PREVIEW_MAX_LINES = 12;
const STREAM_PREVIEW_MAX_CHARS = 1600;

function buildStreamPreview(windowEvents: AgentEvent[]): {
  streamPreview: string | null;
  streamLabel: string | null;
  streamIsFinal: boolean;
} {
  const streamEvents = windowEvents.filter(
    (event) => event.event_type === "COMMAND_STREAM",
  );
  if (streamEvents.length === 0) {
    return {
      streamPreview: null,
      streamLabel: null,
      streamIsFinal: false,
    };
  }

  const byTimestamp = [...streamEvents].sort((a, b) =>
    a.timestamp.localeCompare(b.timestamp),
  );
  const latest = byTimestamp[byTimestamp.length - 1];
  const latestDigest = latest.digest || {};
  const latestStreamId = toEventString(
    latestDigest.stream_id as unknown,
  ).trim();
  const scoped = latestStreamId
    ? byTimestamp.filter((event) => {
        const digest = event.digest || {};
        return (
          toEventString(digest.stream_id as unknown).trim() === latestStreamId
        );
      })
    : byTimestamp;
  const ordered = [...scoped].sort((a, b) => {
    const seqA = Number((a.digest as any)?.seq ?? 0);
    const seqB = Number((b.digest as any)?.seq ?? 0);
    if (seqA !== seqB) {
      return seqA - seqB;
    }
    return a.timestamp.localeCompare(b.timestamp);
  });
  const merged = ordered.map((event) => eventOutputText(event)).join("");
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

  const tool = eventToolName(latest).trim();
  const channel = toEventString(
    (latest.digest || {}).channel as unknown,
  ).trim();
  const streamLabel = [tool || "command", channel ? `(${channel})` : ""]
    .filter(Boolean)
    .join(" ");

  return {
    streamPreview: preview || null,
    streamLabel: streamLabel || null,
    streamIsFinal: Boolean((latest.digest as any)?.is_final),
  };
}

export function useTurnContexts({
  activeHistory,
  activeEvents,
  runPresentation,
}: UseTurnContextsOptions) {
  const canonicalAnswerHashes = useMemo(
    () => collectCanonicalAnswerHashes(activeEvents),
    [activeEvents],
  );

  const fallbackConversation = useMemo(() => {
    const shouldMatchCanonical = canonicalAnswerHashes.size > 0;
    return activeHistory.filter((message) => {
      if (message.role === "user") return true;
      if (message.role !== "agent") return false;
      if (!shouldMatchCanonical) return true;
      return canonicalAnswerHashes.has(normalizeOutputForCompare(message.text));
    });
  }, [activeHistory, canonicalAnswerHashes]);

  const conversationTurns = useMemo<ConversationTurn[]>(() => {
    const turns: ConversationTurn[] = [];
    let pendingPrompt: ChatMessage | null = null;
    let idx = 0;

    for (const message of fallbackConversation) {
      if (message.role === "user") {
        if (pendingPrompt) {
          turns.push({
            key: `turn-${idx}-${pendingPrompt.timestamp}`,
            prompt: pendingPrompt,
            answer: null,
          });
          idx += 1;
        }
        pendingPrompt = message;
        continue;
      }

      if (message.role !== "agent") {
        continue;
      }

      if (pendingPrompt) {
        turns.push({
          key: `turn-${idx}-${pendingPrompt.timestamp}-${message.timestamp}`,
          prompt: pendingPrompt,
          answer: message,
        });
        idx += 1;
        pendingPrompt = null;
      } else {
        turns.push({
          key: `turn-${idx}-agent-${message.timestamp}`,
          prompt: null,
          answer: message,
        });
        idx += 1;
      }
    }

    if (pendingPrompt) {
      turns.push({
        key: `turn-${idx}-${pendingPrompt.timestamp}`,
        prompt: pendingPrompt,
        answer: null,
      });
    }

    return turns;
  }, [fallbackConversation]);

  const latestAnsweredTurnIndex = useMemo(() => {
    for (let i = conversationTurns.length - 1; i >= 0; i -= 1) {
      if (conversationTurns[i]?.answer) {
        return i;
      }
    }
    return -1;
  }, [conversationTurns]);

  const eventTurnWindows = useMemo<EventTurnWindow[]>(
    () => buildEventTurnWindows(activeEvents),
    [activeEvents],
  );

  const turnContexts = useMemo<TurnContext[]>(() => {
    let promptOrdinal = 0;
    const thoughtAgents = runPresentation.thoughtSummary?.agents || [];
    const searches = runPresentation.sourceSummary?.searches || [];
    const browses = runPresentation.sourceSummary?.browses || [];

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
          defaultView: "kernel_logs",
        };
      }

      const windowEvents = activeEvents.filter((event) =>
        eventBelongsToTurnWindow(event, window),
      );
      const stepIndexes = new Set(
        windowEvents.map((event) => event.step_index),
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
        (event) => event.event_type !== "INFO_NOTE",
      ).length;
      const screenshotReceipts = collectScreenshotReceipts(windowEvents);
      const latestVisualReceipt = screenshotReceipts[0] || null;
      const streamPreview = buildStreamPreview(windowEvents);
      const planSummary = buildPlanSummary(
        windowEvents.map((event) => ({
          key: event.event_id,
          kind:
            event.event_type === "RECEIPT"
              ? "receipt_event"
              : event.event_type === "INFO_NOTE"
                ? "reasoning_event"
                : "workload_event",
          event,
          toolName: eventToolName(event),
        })),
      );

      const defaultView: ArtifactHubViewKey = planSummary
        ? "active_context"
        : thoughtCount > 0
          ? "thoughts"
          : sourceCount > 0
            ? "sources"
            : screenshotReceipts.length > 0
              ? "screenshots"
              : "kernel_logs";

      return {
        turnId: window.id,
        planSummary,
        executionMoments: buildExecutionMoments(
          windowEvents.map((event) => ({
            key: event.event_id,
            kind:
              event.event_type === "RECEIPT"
                ? "receipt_event"
                : event.event_type === "INFO_NOTE"
                  ? "reasoning_event"
                  : "workload_event",
            event,
            toolName: eventToolName(event),
          })),
          planSummary,
        ),
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
  }, [activeEvents, conversationTurns, eventTurnWindows, runPresentation]);

  return {
    conversationTurns,
    latestAnsweredTurnIndex,
    turnContexts,
  };
}
