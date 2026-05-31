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
};
