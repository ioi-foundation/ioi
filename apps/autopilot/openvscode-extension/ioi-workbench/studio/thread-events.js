"use strict";

function createStudioThreadEvents({
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  requestJson,
  requestSseJson,
  studioRuntimeEventKind,
} = {}) {
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const eventKind = typeof studioRuntimeEventKind === "function"
    ? studioRuntimeEventKind
    : (event = {}) => String(event?.kind || event?.type || "");

  function collectStudioAgentEventsFromResponse(turn = {}) {
    return [
      ...array(turn.events),
      ...array(turn.runtime_events),
      ...array(turn.runtimeEvents),
      ...array(turn.event_log),
      ...array(turn.eventLog),
    ];
  }

  function uniqueStudioRuntimeEvents(events = []) {
    const seen = new Set();
    const unique = [];
    for (const event of array(events)) {
      const key =
        event?.event_id ||
        event?.eventId ||
        event?.id ||
        (event?.event_stream_id && event?.seq ? `${event.event_stream_id}:${event.seq}` : "");
      if (key && seen.has(key)) {
        continue;
      }
      if (key) {
        seen.add(key);
      }
      unique.push(event);
    }
    return unique;
  }

  function studioMaxRuntimeEventSeq(events = []) {
    return array(events).reduce((max, event) => {
      const seq = Number(event?.seq || 0);
      return Number.isFinite(seq) && seq > max ? seq : max;
    }, 0);
  }

  async function fetchStudioThreadEvents(threadId, output, { timeoutMs = 1500, sinceSeq = 0, stopOnTerminal = false } = {}) {
    if (!threadId) {
      return [];
    }
    const events = [];
    try {
      await requestSseJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/events?since_seq=${encodeURIComponent(String(Math.max(0, Number(sinceSeq) || 0)))}`, {
        method: "GET",
        token: daemonRequestToken(),
        timeoutMs,
        onPayload: (payload) => {
          let event = null;
          if (payload && payload.event && typeof payload.event === "object") {
            event = payload.event;
            events.push(event);
          } else if (payload) {
            event = payload;
            events.push(event);
          }
          if (stopOnTerminal && event) {
            const kind = eventKind(event).toLowerCase();
            if (/turn\.(completed|failed|blocked)/.test(kind)) {
              return false;
            }
          }
        },
      });
    } catch (error) {
      output?.appendLine?.(`[ioi-studio] daemon thread event stream unavailable: ${error?.message || String(error)}`);
    }
    return events;
  }

  async function fetchStudioThreadTurns(threadId, output, { timeoutMs = 5000 } = {}) {
    if (!threadId) {
      return [];
    }
    try {
      const turns = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
        method: "GET",
        token: daemonRequestToken(),
        timeoutMs,
      });
      return array(turns);
    } catch (error) {
      output?.appendLine?.(`[ioi-studio] daemon turn refresh unavailable: ${error?.message || String(error)}`);
      return [];
    }
  }

  async function fetchStudioThreadTurnEvents(threadId, output, { turnId } = {}) {
    const turns = await fetchStudioThreadTurns(threadId, output, { timeoutMs: 5000 });
    const scopedTurns = turnId
      ? turns.filter((turn) => String(turn.turn_id || turn.turnId || "") === String(turnId))
      : turns;
    return scopedTurns.flatMap((turn) => collectStudioAgentEventsFromResponse(turn));
  }

  return {
    collectStudioAgentEventsFromResponse,
    fetchStudioThreadEvents,
    fetchStudioThreadTurnEvents,
    fetchStudioThreadTurns,
    studioMaxRuntimeEventSeq,
    uniqueStudioRuntimeEvents,
  };
}

module.exports = {
  createStudioThreadEvents,
};
