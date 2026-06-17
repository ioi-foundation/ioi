function createStudioAgentTurnRecoveryHelpers({
  collectStudioAgentEventsFromResponse,
  firstArray,
  stringValue,
  studioAgentTurnResultText,
  studioRuntimeEventIsRunningStepCompletion,
  studioRuntimeEventKind,
} = {}) {
  function studioTurnPromptText(turn = {}) {
    const direct = stringValue(
      turn.prompt ||
        turn.input ||
        turn.message ||
        turn.request?.prompt ||
        turn.request?.input ||
        turn.request?.message,
    );
    if (direct) {
      return direct;
    }
    const userTurn = firstArray(turn.conversation)
      .slice()
      .reverse()
      .find((item) => String(item?.role || item?.type || "").toLowerCase() === "user");
    if (userTurn) {
      return stringValue(userTurn.content || userTurn.text || userTurn.message);
    }
    const startedEvent = collectStudioAgentEventsFromResponse(turn)
      .find((event) => studioRuntimeEventKind(event).toLowerCase() === "turn.started");
    return stringValue(startedEvent?.payload?.prompt || startedEvent?.payload_summary?.prompt);
  }

  function studioTurnStartedAtMs(turn = {}) {
    const numeric = Number(
      turn.started_at_ms ||
        turn.startedAtMs ||
        turn.created_at_ms ||
        turn.createdAtMs ||
        0,
    );
    if (Number.isFinite(numeric) && numeric > 0) {
      return numeric;
    }
    const parsed = Date.parse(
      turn.started_at ||
        turn.startedAt ||
        turn.created_at ||
        turn.createdAt ||
        "",
    );
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function studioTurnMatchesSubmittedPrompt(turn = {}, prompt = "", submittedAtMs = 0) {
    const turnPrompt = studioTurnPromptText(turn);
    if (turnPrompt && prompt && turnPrompt === prompt) {
      return true;
    }
    const startedAtMs = studioTurnStartedAtMs(turn);
    return Boolean(startedAtMs && submittedAtMs && startedAtMs >= submittedAtMs - 2000);
  }

  function studioTurnLooksTerminal(turn = {}) {
    const events = collectStudioAgentEventsFromResponse(turn);
    const statusText = stringValue(turn.status || turn.state || "").toLowerCase();
    const resultText = studioAgentTurnResultText(turn, events);
    if (resultText) {
      return true;
    }
    if (events.some(studioRuntimeEventIsRunningStepCompletion)) {
      return false;
    }
    if (/blocked|failed|error|completed|paused|approval|waiting_for_approval/.test(statusText)) {
      return true;
    }
    return events.some((event) => /turn\.(completed|failed)|completed|failed|blocked/.test(studioRuntimeEventKind(event).toLowerCase()));
  }

  return {
    studioTurnLooksTerminal,
    studioTurnMatchesSubmittedPrompt,
    studioTurnPromptText,
    studioTurnStartedAtMs,
  };
}

function createStudioAgentTurnRecovery({
  fetchStudioThreadTurns,
  studioTurnMatchesSubmittedPrompt,
  studioTurnLooksTerminal,
  studioAgentTurnResultText,
  normalizeStudioAgentResultText,
  getStudioRuntimeProjection,
  firstArray,
  recoveryAttempts,
  recoveryPollMs,
}) {
  async function recoverStudioAgentTurnAfterSubmitTimeout({
    threadId,
    prompt,
    submittedAtMs,
    output,
    attempts = recoveryAttempts,
    pollMs = recoveryPollMs,
    timeoutMs = 5000,
    reasonLabel = "Agent POST timeout",
  }) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const turns = await fetchStudioThreadTurns(threadId, output, { timeoutMs });
      const turn = turns
        .slice()
        .reverse()
        .find((candidate) =>
          studioTurnMatchesSubmittedPrompt(candidate, prompt, submittedAtMs) &&
          studioTurnLooksTerminal(candidate),
        );
      if (turn) {
        output?.appendLine?.(`[ioi-studio] recovered completed daemon turn from projection after ${reasonLabel}.`);
        return turn;
      }
      if (attempt < attempts - 1) {
        await new Promise((resolve) => setTimeout(resolve, pollMs));
      }
    }
    return null;
  }

  function recoverStudioAgentTurnFromLiveEventsAfterSubmitTimeout({
    threadId,
    prompt,
    submittedAtMs,
    events = [],
  }) {
    const projection = getStudioRuntimeProjection();
    const eventText = studioAgentTurnResultText({ events }, events);
    const streamedText = normalizeStudioAgentResultText(projection.daemonAnswerStreamText);
    const resultText = eventText || streamedText;
    if (!resultText) {
      return null;
    }
    const recoveredTurnId = projection.turnId || `turn.recovered.${Date.now()}`;
    return {
      thread_id: threadId,
      threadId,
      turn_id: recoveredTurnId,
      turnId: recoveredTurnId,
      status: "completed",
      state: "completed",
      prompt,
      input: prompt,
      result: resultText,
      output: resultText,
      events: firstArray(events),
      recovered_from: "live_runtime_events_after_submit_timeout",
      recoveredFrom: "live_runtime_events_after_submit_timeout",
      started_at_ms: submittedAtMs,
      startedAtMs: submittedAtMs,
    };
  }

  return {
    recoverStudioAgentTurnAfterSubmitTimeout,
    recoverStudioAgentTurnFromLiveEventsAfterSubmitTimeout,
  };
}

module.exports = {
  createStudioAgentTurnRecovery,
  createStudioAgentTurnRecoveryHelpers,
};
