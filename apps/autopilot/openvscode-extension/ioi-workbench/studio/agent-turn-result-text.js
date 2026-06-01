function createStudioAgentTurnResultText({
  stringValue,
  firstArray,
  studioRuntimeEventKind,
  studioRuntimeEventToolName,
  extractHtmlDocument,
} = {}) {
  function normalizeStudioAssistantReplyText(value) {
    const text = stringValue(value);
    if (!text) {
      return "";
    }
    return text.replace(/^Replied:\s*/i, "").trim();
  }

  function decodeStudioRustOptionalText(value) {
    const text = stringValue(value).trim();
    const match = text.match(/^(?:Completed|Failed|Blocked|Paused)\(Some\("([\s\S]*)"\)\)$/);
    if (!match) {
      return "";
    }
    try {
      return JSON.parse(`"${match[1]}"`);
    } catch {
      return match[1]
        .replace(/\\"/g, "\"")
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\r")
        .replace(/\\t/g, "\t")
        .trim();
    }
  }

  function studioAssistantReplyTextIsDeferred(text = "") {
    return /\bdeferred\s+chat__reply\b|\bfresh\s+web__search\/web__read\s+evidence\b/i.test(stringValue(text));
  }

  function studioAgentResultTextIsRuntimePayload(text = "") {
    return /\b(?:Agent Failure:\s*)?ERROR_CLASS=|\bProvider Error\s+\d+|\bexternal_blocker\b|OpenAI-compatible provider stream failed/i.test(stringValue(text));
  }

  function normalizeStudioAgentResultText(value) {
    const text = normalizeStudioAssistantReplyText(decodeStudioRustOptionalText(value) || value);
    if (
      !text ||
      studioAssistantReplyTextIsDeferred(text) ||
      studioAgentResultTextIsRuntimePayload(text) ||
      /^Runtime step completed\.?$/i.test(text)
    ) {
      return "";
    }
    return text;
  }

  function studioAssistantTextFromRuntimeToolEvents(events = []) {
    for (const event of firstArray(events).slice().reverse()) {
      if (String(studioRuntimeEventToolName(event)).toLowerCase() !== "chat__reply") {
        continue;
      }
      const text = normalizeStudioAssistantReplyText(
        event.payload?.output ||
          event.payload?.message ||
          event.payload?.text ||
          event.payload_summary?.output ||
          event.payload_summary?.message ||
          event.payload_summary?.text ||
          event.payload_summary?.result_summary ||
          event.payload_summary?.summary ||
          event.summary,
      );
      if (studioAgentResultTextIsRuntimePayload(text)) {
        continue;
      }
      if (text && !studioAssistantReplyTextIsDeferred(text)) {
        return text;
      }
    }
    return "";
  }

  function completedRuntimeEvent(events = []) {
    return firstArray(events)
      .slice()
      .reverse()
      .find((event) => /turn\.(completed|failed|blocked)/.test(studioRuntimeEventKind(event).toLowerCase()));
  }

  function terminalEventText(completed) {
    return normalizeStudioAgentResultText(
      completed?.payload_summary?.summary ||
        completed?.payload_summary?.result_summary ||
        completed?.payload_summary?.message ||
        completed?.payload_summary?.output ||
        completed?.payload_summary?.agent_status ||
        completed?.payload?.summary ||
        completed?.payload?.result ||
        completed?.payload?.message ||
        completed?.payload?.output ||
        completed?.payload?.agent_status ||
        completed?.summary,
    );
  }

  function studioAgentTurnResultText(turn = {}, events = []) {
    const terminalText = terminalEventText(completedRuntimeEvent(events));
    if (terminalText) {
      return terminalText;
    }
    const toolReply = studioAssistantTextFromRuntimeToolEvents(events);
    if (toolReply) {
      return toolReply;
    }
    return normalizeStudioAgentResultText(
      turn.result ||
        turn.output ||
        turn.text ||
        turn.message ||
        turn.summary ||
        turn.payload_summary?.result_summary ||
        "",
    );
  }

  function studioArtifactSourceTextFromAgentTurn(agentTurn = {}) {
    const turn = agentTurn.turn || agentTurn;
    const events = firstArray(agentTurn.events);
    const completed = completedRuntimeEvent(events);
    const candidates = [
      agentTurn.text,
      studioAgentTurnResultText(turn, events),
      completed?.payload_summary?.agent_status,
      completed?.payload_summary?.summary,
      studioAssistantTextFromRuntimeToolEvents(events),
      completed?.payload?.summary,
      completed?.payload?.agent_status,
    ];
    for (const candidate of candidates) {
      const text = normalizeStudioAgentResultText(candidate);
      if (extractHtmlDocument(text)) {
        return text;
      }
    }
    return normalizeStudioAgentResultText(candidates.find(Boolean)) || "";
  }

  return {
    normalizeStudioAssistantReplyText,
    decodeStudioRustOptionalText,
    studioAssistantReplyTextIsDeferred,
    studioAgentResultTextIsRuntimePayload,
    normalizeStudioAgentResultText,
    studioAssistantTextFromRuntimeToolEvents,
    studioAgentTurnResultText,
    studioArtifactSourceTextFromAgentTurn,
  };
}

module.exports = {
  createStudioAgentTurnResultText,
};
