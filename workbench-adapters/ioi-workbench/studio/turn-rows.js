"use strict";

function createStudioTurnRows({
  escapeHtml,
  formatStudioWorkDuration,
  getStudioRuntimeProjection,
  studioChatCodeExecutionRows,
  studioChatOutputRendererRows,
  studioConversationArtifactRows,
  studioDisplayTurnContent,
  studioManagedSessionRows,
  studioResponseMetricsRows,
  studioThinkingRows,
  studioTurnContentRows,
  studioTurnHasDocumentedWork,
  studioTurnSourceRows,
  studioWorkCommandOutputRows,
  studioWorkRecordDiffRows,
  studioWorkSummaryRows,
}) {
  function studioTurnRows() {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    return studioRuntimeProjection.turns.map((turn, index) => {
      const hasDocumentedWork = turn.role === "assistant" && studioTurnHasDocumentedWork(turn);
      const workRecord = hasDocumentedWork ? turn.workRecord : null;
      const displayContent = studioDisplayTurnContent(turn);
      return `
    <article class="studio-chat-turn studio-chat-turn--${escapeHtml(turn.role || "system")}" data-studio-turn-role="${escapeHtml(turn.role || "system")}" data-testid="${turn.role === "user" ? "studio-user-turn-immediate" : index === studioRuntimeProjection.turns.length - 1 ? "studio-latest-turn" : "studio-chat-turn"}"${turn.modelStream?.streamId && !turn.modelStream?.completed ? ` data-studio-stream-turn="${escapeHtml(turn.modelStream.streamId)}"` : ""} data-documented-work="${hasDocumentedWork ? "true" : "false"}">
      ${hasDocumentedWork ? `
        <details class="studio-run-status-bar" data-testid="studio-run-status-bar">
          <summary>
            <span class="studio-run-status-bar__check" aria-hidden="true">✓</span>
            <strong>${studioRuntimeProjection.status === "interrupted" ? "Stopped by operator" : `Worked for ${formatStudioWorkDuration(workRecord.durationMs)}`}</strong>
          </summary>
          <ul class="studio-run-status-bar__details" data-testid="studio-work-summary-lines">
            ${studioWorkSummaryRows(workRecord)}
          </ul>
          ${studioWorkCommandOutputRows(workRecord)}
          ${studioWorkRecordDiffRows(workRecord)}
        </details>
        ${studioManagedSessionRows(workRecord.sessionCards)}
      ` : ""}
      <div class="studio-chat-turn__avatar" aria-hidden="true">${escapeHtml(turn.role === "user" ? "hi" : (turn.role || "S").slice(0, 1).toUpperCase())}</div>
      <div class="studio-chat-turn__body${turn.role === "assistant" ? " studio-assistant-answer-card" : turn.role === "user" ? " studio-user-bubble" : ""}" ${turn.role === "assistant" ? 'data-testid="studio-assistant-answer-card"' : turn.role === "user" ? 'data-testid="studio-user-bubble"' : ""}>
        <div class="studio-chat-turn__meta">
          <strong>${escapeHtml(turn.role === "user" ? "You" : turn.role === "assistant" ? "Autopilot" : "System")}</strong>
          <span>${escapeHtml(turn.createdAt || "")}</span>
        </div>
        ${turn.role === "assistant" ? studioThinkingRows(turn) : ""}
        ${studioTurnContentRows(turn, displayContent)}
        ${turn.role === "assistant" ? studioTurnSourceRows(turn) : ""}
        ${turn.role === "assistant" ? studioConversationArtifactRows(turn.artifacts || workRecord?.artifactCards || []) : ""}
        ${turn.role === "assistant" ? studioChatOutputRendererRows(turn, index) : ""}
        ${turn.role === "assistant" ? studioChatCodeExecutionRows(turn, index) : ""}
        ${turn.role === "assistant" ? studioResponseMetricsRows(turn) : ""}
      </div>
    </article>
  `;
    }).join("");
  }

  return {
    studioTurnRows,
  };
}

module.exports = {
  createStudioTurnRows,
};
