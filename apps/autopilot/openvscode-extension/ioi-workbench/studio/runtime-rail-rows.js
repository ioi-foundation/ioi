"use strict";

function createStudioRuntimeRailRows({
  escapeHtml,
  getStudioRuntimeProjection,
  studioParityPlusPanelRowsFromRenderer,
}) {
  function projection() {
    return getStudioRuntimeProjection() || {};
  }

  function studioTimelineRows() {
    return (projection().timeline || []).slice(-8).map((item) => `
    <li>
      <span class="studio-status-dot studio-status-dot--${escapeHtml(item.status || "ready")}"></span>
      <strong>${escapeHtml(item.label || "Runtime event")}</strong>
      <span>${escapeHtml(item.detail || "")}</span>
    </li>
  `).join("");
  }

  function studioReceiptRows() {
    const runtimeProjection = projection();
    const receipts = (runtimeProjection.receipts || []).length > 0
      ? runtimeProjection.receipts.slice(-8)
      : [
          {
            id: "receipt.pending",
            kind: "pending",
            summary: "Receipts appear after daemon session, approval, or hunk decisions.",
          },
        ];
    return receipts.map((receipt) => `
    <li data-testid="studio-receipt-timeline-step">
      <strong>${escapeHtml(receipt.kind || "receipt")}</strong>
      <code>${escapeHtml(receipt.id || "pending")}</code>
      <span>${escapeHtml(receipt.summary || "")}</span>
    </li>
  `).join("");
  }

  function studioHistoryRows() {
    return (projection().history || []).slice(-5).map((item) => `
    <button type="button" class="studio-history-item" data-testid="studio-session-history-item">
      <strong>${escapeHtml(item.title || "Session")}</strong>
      <span>${escapeHtml([item.status, item.id].filter(Boolean).join(" · "))}</span>
    </button>
  `).join("");
  }

  function studioApprovalRows(approvalId = "approval_agent_studio_inline_diff_preview") {
    return (projection().approvals || []).slice(-5).map((approval) => `
    <section class="studio-approval studio-approval-inline-card" data-testid="studio-approval-gate" data-approval-id="${escapeHtml(approval.id || approvalId)}">
      <div>
        <strong data-testid="studio-approval-inline-card">${escapeHtml(approval.label || "Permission needed")}</strong>
        <span>${escapeHtml(approval.detail || "Agent needs permission before continuing.")}</span>
      </div>
      <mark>${escapeHtml(approval.status || "pending")}</mark>
    </section>
  `).join("");
  }

  function studioTerminalRows() {
    return (projection().terminal || []).slice(-6).map((item) => `
    <li>
      <strong>${escapeHtml(item.label || "Terminal")}</strong>
      <span>${escapeHtml(item.detail || "")}</span>
    </li>
  `).join("");
  }

  function studioReplayRows() {
    const replaySteps = (projection().replaySteps || []).slice(-8);
    if (replaySteps.length === 0) {
      return '<li data-testid="studio-replay-step-detail"><strong>Replay pending</strong><span>Daemon replay steps appear after runtime events are observed.</span></li>';
    }
    return replaySteps.map((step) => `
    <li data-testid="studio-replay-step-detail">
      <strong>${escapeHtml(step.kind || "runtime.event")}</strong>
      <code>${escapeHtml(step.id || "event")}</code>
      <span>${escapeHtml(step.summary || step.status || "")}</span>
    </li>
  `).join("");
  }

  function studioParityPlusPanelRows() {
    return studioParityPlusPanelRowsFromRenderer(projection());
  }

  return {
    studioApprovalRows,
    studioHistoryRows,
    studioParityPlusPanelRows,
    studioReceiptRows,
    studioReplayRows,
    studioTerminalRows,
    studioTimelineRows,
  };
}

module.exports = {
  createStudioRuntimeRailRows,
};
