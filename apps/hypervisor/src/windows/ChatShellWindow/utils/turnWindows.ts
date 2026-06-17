import type { AgentEvent } from "../../../types";
import {
  eventPromptText,
  isUserRequestEvent,
  parseTimestampMs,
} from "./eventFields";

export type EventTurnWindow = {
  id: string;
  index: number;
  prompt: string;
  startAtMs: number | null;
  endAtMs: number | null;
};

export function buildEventTurnWindows(events: AgentEvent[]): EventTurnWindow[] {
  const ordered = events
    .slice()
    .sort((a, b) => {
      const aTimestamp = a.timestamp || "";
      const bTimestamp = b.timestamp || "";
      return (
        aTimestamp.localeCompare(bTimestamp) ||
        (a.step_index ?? 0) - (b.step_index ?? 0) ||
        (a.event_id || "").localeCompare(b.event_id || "")
      );
    });
  const userEvents = ordered.filter((event) => isUserRequestEvent(event));

  return userEvents.map((event, idx) => {
    const next = userEvents[idx + 1];
    return {
      id: event.event_id,
      index: idx + 1,
      prompt: eventPromptText(event),
      startAtMs: parseTimestampMs(event.timestamp),
      endAtMs: next ? parseTimestampMs(next.timestamp) : null,
    };
  });
}

export function eventBelongsToTurnWindow(
  event: AgentEvent,
  turn: EventTurnWindow,
): boolean {
  const eventAtMs = parseTimestampMs(event.timestamp);
  if (turn.startAtMs !== null && eventAtMs !== null && eventAtMs < turn.startAtMs) {
    return false;
  }
  if (turn.endAtMs !== null && eventAtMs !== null && eventAtMs >= turn.endAtMs) {
    return false;
  }
  return true;
}
