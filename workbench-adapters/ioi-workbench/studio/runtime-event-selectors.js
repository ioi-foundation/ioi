"use strict";

function createStudioRuntimeEventSelectors({
  firstArray,
  stringValue,
  studioRuntimeEventKind,
  studioRuntimeEventToolName,
}) {
  function studioRuntimeEventsIncludeTool(events = [], pattern) {
    return firstArray(events).some((event) =>
      pattern.test(String(studioRuntimeEventToolName(event)).toLowerCase()),
    );
  }

  function studioRuntimeEventsIncludeCompletedTool(events = [], pattern) {
    return firstArray(events).some((event) => {
      const kind = studioRuntimeEventKind(event).toLowerCase();
      return (
        /tool\.(completed|result)/.test(kind) &&
        pattern.test(String(studioRuntimeEventToolName(event)).toLowerCase())
      );
    });
  }

  function studioRuntimeToolEventCount(events = [], pattern) {
    return firstArray(events).filter((event) =>
      pattern.test(String(studioRuntimeEventToolName(event)).toLowerCase()),
    ).length;
  }

  function studioRuntimeEventTurnId(event = {}) {
    return stringValue(event.turn_id || event.turnId || event.payload?.turn_id || event.payload?.turnId);
  }

  function studioRuntimeEventsForTurn(events = [], turnId = "") {
    const normalizedTurnId = stringValue(turnId);
    const allEvents = firstArray(events);
    if (!normalizedTurnId) {
      return allEvents;
    }
    const matched = allEvents.filter((event) => studioRuntimeEventTurnId(event) === normalizedTurnId);
    return matched.length ? matched : allEvents;
  }

  return {
    studioRuntimeEventTurnId,
    studioRuntimeEventsForTurn,
    studioRuntimeEventsIncludeCompletedTool,
    studioRuntimeEventsIncludeTool,
    studioRuntimeToolEventCount,
  };
}

module.exports = {
  createStudioRuntimeEventSelectors,
};
