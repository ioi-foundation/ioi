"use strict";

function defaultEscapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function defaultFirstArray(value) {
  return Array.isArray(value) ? value : [];
}

function createStudioManagedSessionView({
  escapeHtml = defaultEscapeHtml,
  firstArray = defaultFirstArray,
} = {}) {
  function studioWorkRecordWithSessionCards(workRecord, sessionCards = []) {
    const cards = firstArray(sessionCards).filter(Boolean);
    if (!cards.length) {
      return workRecord || null;
    }
    const existing =
      workRecord && typeof workRecord === "object" && !Array.isArray(workRecord)
        ? workRecord
        : {
            status: "completed",
            durationMs: 0,
            lines: [],
            summaryParts: [],
            activityLines: [],
            receiptRefs: [],
            stepCount: 0,
          };
    const hasSessionLine = firstArray(existing.lines).some((line) =>
      /\b(browser|computer).*live session\b/i.test(String(line || "")),
    );
    return {
      ...existing,
      status: existing.status || "completed",
      lines: hasSessionLine
        ? firstArray(existing.lines)
        : [
            ...firstArray(existing.lines),
            `Managed ${cards.length} browser/computer live session${cards.length === 1 ? "" : "s"}`,
          ],
      summaryParts: firstArray(existing.summaryParts),
      activityLines: firstArray(existing.activityLines),
      receiptRefs: firstArray(existing.receiptRefs),
      stepCount: Math.max(Number(existing.stepCount || 0) || 0, firstArray(existing.lines).length + 1),
      sessionCards: cards.slice(-3),
    };
  }

  function studioManagedSessionRows(cards = []) {
    const sessions = firstArray(cards).filter(Boolean);
    if (!sessions.length) {
      return "";
    }
    return `
    <section class="studio-managed-sessions" data-testid="studio-managed-sessions" aria-label="Browser and computer sessions">
      ${sessions.map((session) => {
        const controlState = session.controlState || session.control_state || "observe";
        const modeLabels = [
          ["sandbox_browser", "Sandbox browser"],
          ["local_browser", "Local browser"],
          ["desktop", "Desktop"],
        ];
        return `
          <article
            class="studio-managed-session-card studio-managed-session-card--${escapeHtml(session.kind || "sandbox_browser")}"
            data-testid="studio-managed-session-card"
            data-session-id="${escapeHtml(session.id || session.sessionId || "managed-session")}"
            data-session-kind="${escapeHtml(session.kind || "sandbox_browser")}"
            data-session-label="${escapeHtml(session.surfaceLabel || "Sandbox browser")}"
            data-session-status="${escapeHtml(session.status || "complete")}"
            data-control-state="${escapeHtml(controlState)}"
            data-session-expanded="false"
          >
            <header class="studio-managed-session-card__header">
              <span class="studio-status-dot studio-status-dot--${escapeHtml(session.status === "needs_user" || session.status === "waiting_for_user" ? "blocked" : "completed")}"></span>
              <div>
                <strong>${escapeHtml(session.surfaceLabel || "Sandbox browser")}</strong>
                <span>${escapeHtml(session.statusLabel || "Complete")} &#183; ${escapeHtml(session.lastTool || "computer-use")}</span>
              </div>
              <button type="button" data-testid="studio-managed-session-expand" data-studio-managed-session-expand aria-expanded="false">Expand</button>
            </header>
            <div class="studio-managed-session-preview" data-testid="studio-managed-session-compact-preview">
              <div class="studio-managed-session-preview__chrome" aria-hidden="true">
                <span></span><span></span><span></span>
              </div>
              <div class="studio-managed-session-preview__body">
                <strong>${escapeHtml(session.pageTitle || session.title || "Live session")}</strong>
                <span>${escapeHtml(session.url || session.detail || "Runtime-managed viewport")}</span>
                ${session.waitingForUser ? `<mark data-testid="studio-managed-session-waiting">Waiting for user</mark>` : ""}
              </div>
            </div>
            <div class="studio-managed-session-expanded" data-testid="studio-managed-session-expanded-view">
              <div class="studio-managed-session-mode-labels" data-testid="studio-managed-session-mode-labels">
                ${modeLabels.map(([kind, label]) => `
                  <span data-testid="studio-managed-session-mode-label" data-session-mode-label="${escapeHtml(kind)}" class="${kind === session.kind ? "is-active" : ""}">${escapeHtml(label)}</span>
                `).join("")}
              </div>
              <p>${escapeHtml(session.detail || "The runtime owns this browser/computer session. Observe by default, take over only when a manual step is needed, then return control to Agent.")}</p>
              <div class="studio-managed-session-controls" data-testid="studio-managed-session-controls">
                <button type="button" data-testid="studio-managed-session-observe" data-studio-managed-session-control="observe" aria-pressed="${controlState === "observe"}" class="${controlState === "observe" ? "is-active" : ""}">Observe</button>
                <button type="button" data-testid="studio-managed-session-take-over" data-studio-managed-session-control="take_over" aria-pressed="${controlState === "take_over"}" class="${controlState === "take_over" ? "is-active" : ""}">Take over</button>
                <button type="button" data-testid="studio-managed-session-return" data-studio-managed-session-control="return_agent" aria-pressed="${controlState === "return_agent"}" class="${controlState === "return_agent" ? "is-active" : ""}">Return control to Agent</button>
              </div>
            </div>
          </article>
        `;
      }).join("")}
    </section>
  `;
  }

  return {
    studioWorkRecordWithSessionCards,
    studioManagedSessionRows,
  };
}

module.exports = {
  createStudioManagedSessionView,
};
