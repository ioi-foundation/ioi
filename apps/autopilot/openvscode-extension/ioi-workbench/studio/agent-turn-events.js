function createStudioAgentTurnEvents({
  fetchStudioThreadEvents,
  applyStudioAgentTurnEvents,
  studioMaxRuntimeEventSeq,
  studioAssistantTextFromRuntimeToolEvents,
  studioAgentTurnResultText,
  studioRuntimeEventKind,
  firstArray,
}) {
  function terminalEventHasVisibleText(event = {}) {
    if (!/turn\.(completed|failed|blocked)/.test(studioRuntimeEventKind(event).toLowerCase())) {
      return false;
    }
    return Boolean(
      studioAgentTurnResultText({ events: [event] }, [event]) ||
        event.payload_summary?.summary ||
        event.payload_summary?.result_summary ||
        event.payload_summary?.message ||
        event.payload_summary?.output ||
        event.payload_summary?.agent_status ||
        event.payload?.summary ||
        event.payload?.result ||
        event.payload?.message ||
        event.payload?.output ||
        event.payload?.agent_status ||
        event.summary,
    );
  }

  function studioRuntimeEventsHaveTerminalAssistantResult(events = []) {
    return firstArray(events).some(terminalEventHasVisibleText);
  }

  async function pollStudioThreadEventsDuringTurn(
    threadId,
    output,
    completionPromise,
    {
      sinceSeq = 0,
      resolveOnTerminal = false,
      projectAnswerStream = true,
      answerStreamPresentation = "agent_final_handoff",
      answerStreamFileName = "",
    } = {},
  ) {
    if (!threadId) {
      return [];
    }
    let settled = false;
    let latestSeq = Math.max(0, Number(sinceSeq) || 0);
    const collected = [];
    completionPromise.finally(() => {
      settled = true;
    }).catch(() => {
      settled = true;
    });
    while (!settled) {
      const events = await fetchStudioThreadEvents(threadId, output, {
        timeoutMs: 1000,
        sinceSeq: latestSeq,
        stopOnTerminal: resolveOnTerminal,
      });
      if (events.length) {
        latestSeq = Math.max(latestSeq, studioMaxRuntimeEventSeq(events));
        const terminalBatch = resolveOnTerminal && studioRuntimeEventsHaveTerminalAssistantResult(events);
        const applied = applyStudioAgentTurnEvents(events, {
          projectPending: true,
          projectAnswerStream,
          answerStreamPresentation,
          answerStreamFileName,
        });
        collected.push(...applied);
        if (terminalBatch) {
          return [...collected, ...events];
        }
        if (resolveOnTerminal && studioRuntimeEventsHaveTerminalAssistantResult(collected)) {
          return collected;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    const tailEvents = await fetchStudioThreadEvents(threadId, output, {
      timeoutMs: 1000,
      sinceSeq: latestSeq,
      stopOnTerminal: resolveOnTerminal,
    });
    if (tailEvents.length) {
      const terminalBatch = resolveOnTerminal && studioRuntimeEventsHaveTerminalAssistantResult(tailEvents);
      const applied = applyStudioAgentTurnEvents(tailEvents, {
        projectPending: true,
        projectAnswerStream,
        answerStreamPresentation,
        answerStreamFileName,
      });
      collected.push(...applied);
      if (terminalBatch) {
        return [...collected, ...tailEvents];
      }
    }
    return collected;
  }

  return {
    pollStudioThreadEventsDuringTurn,
    studioRuntimeEventsHaveTerminalAssistantResult,
  };
}

module.exports = {
  createStudioAgentTurnEvents,
};
