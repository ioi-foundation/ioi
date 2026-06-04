"use strict";

function createStudioPendingView({
  compactStudioWhitespace,
  escapeHtml,
  firstArray,
  formatStudioWorkDuration,
  getStudioRuntimeProjection,
  studioPendingCommandOutputExcerpt,
  studioSourceChipRows,
  studioVisiblePendingStepDetail,
}) {
  function studioPendingWorklogRows() {
    const projection = getStudioRuntimeProjection();
    return firstArray(projection.pendingWorklog).map((step) => {
      const sourceChips = firstArray(step.sourceChips || step.source_chips || step.sources);
      const commandStep = /shell|terminal|command/.test([
        step.toolName,
        step.tool_name,
        step.toolId,
        step.tool_id,
        step.label,
        step.kind,
      ].map((value) => String(value || "").toLowerCase()).join(" "));
      const excerpt = commandStep
        ? studioPendingCommandOutputExcerpt(step, sourceChips[0]?.excerpt || "")
        : compactStudioWhitespace(step.excerptPreview || step.excerpt_preview || sourceChips[0]?.excerpt || "").slice(0, 260);
      const detail = studioVisiblePendingStepDetail(step.detail);
      const status = compactStudioWhitespace(step.status || "running").toLowerCase();
      const startedAtMs = Date.parse(step.at || "") || Date.now();
      const elapsedLabel = step.label === "Running command" && /running|started/.test(status)
        ? ` for ${formatStudioWorkDuration(Date.now() - startedAtMs)}`
        : "";
      return `
    <li data-status="${escapeHtml(step.status || "running")}" data-base-label="${escapeHtml(step.label || "")}" data-started-at-ms="${escapeHtml(String(startedAtMs))}">
      <p class="studio-pending-step__headline">${escapeHtml(`${step.label || ""}${elapsedLabel}`)}</p>
      ${detail ? `<span class="studio-pending-step__summary">${escapeHtml(detail)}</span>` : ""}
      ${sourceChips.length ? `<div class="studio-source-chip-list">${studioSourceChipRows(sourceChips, { limit: 6 })}</div>` : ""}
      ${excerpt ? commandStep
        ? `<pre class="studio-pending-step__excerpt studio-pending-step__command-output" data-testid="studio-pending-command-output">${escapeHtml(excerpt)}</pre>`
        : `<p class="studio-pending-step__excerpt">${escapeHtml(excerpt)}</p>`
      : ""}
    </li>
  `;
    }).join("");
  }

  function studioPendingProjectionRows() {
    const projection = getStudioRuntimeProjection();
    if (!projection.pending) {
      return "";
    }
    const startedAt = Number(projection.pendingStartedAtMs || Date.now());
    const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    return `
    <article
      class="studio-chat-turn studio-chat-turn--assistant studio-pending"
      data-testid="studio-pending-state"
      data-studio-turn-role="assistant"
      data-documented-work="false"
      data-pending-started-at-ms="${escapeHtml(String(startedAt))}"
    >
      <div class="studio-pending__line">
        <span class="studio-pending__dots" aria-hidden="true"><span></span><span></span><span></span></span>
        <strong data-testid="studio-pending-label">Thinking about your request · ${escapeHtml(String(elapsedSeconds))}s</strong>
      </div>
      <ol class="studio-pending__worklog" data-testid="studio-pending-worklog">
        ${studioPendingWorklogRows()}
      </ol>
    </article>
  `;
  }

  return {
    studioPendingProjectionRows,
    studioPendingWorklogRows,
  };
}

module.exports = {
  createStudioPendingView,
};
