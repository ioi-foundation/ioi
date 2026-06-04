"use strict";

function createStudioViewHelpers({ escapeHtml, now = () => Date.now() }) {
  function formatRelativeTime(timestampMs) {
    if (!timestampMs) {
      return "now";
    }
    const elapsed = Math.max(0, now() - timestampMs);
    const minutes = Math.floor(elapsed / 60_000);
    if (minutes < 1) {
      return "<1m ago";
    }
    if (minutes < 60) {
      return `${minutes}m ago`;
    }
    const hours = Math.floor(minutes / 60);
    const rem = minutes % 60;
    return rem > 0 ? `${hours}h ${rem}m ago` : `${hours}h ago`;
  }

  function commandPayloadAttr(payload) {
    return payload ? ` data-payload="${escapeHtml(JSON.stringify(payload))}"` : "";
  }

  function renderItems(items, emptyLabel, renderItem) {
    if (!items.length) {
      return `<div class="empty-state">${escapeHtml(emptyLabel)}</div>`;
    }
    return `<div class="stack">${items.map(renderItem).join("")}</div>`;
  }

  function renderCommandButton(action) {
    const payload =
      action && "payload" in action && action.payload != null
        ? commandPayloadAttr(action.payload)
        : "";
    return `<button class="action" data-command="${escapeHtml(action.command)}"${payload}>${escapeHtml(action.label)}</button>`;
  }

  function renderRuntimeSummary(state) {
    const summary = state.summary || {};
    const metrics = [
      ["Workflows", summary.workflowCount ?? 0],
      ["Runs", summary.runCount ?? 0],
      ["Artifacts", summary.artifactCount ?? 0],
      ["Connectors", summary.connectorCount ?? 0],
      ["Policy issues", summary.policyIssueCount ?? 0],
    ];
    return `
      <div class="runtime-strip" aria-label="IOI runtime snapshot">
        ${metrics
          .map(
            ([label, value]) => `
              <div class="runtime-strip__item">
                <span>${escapeHtml(label)}</span>
                <strong>${escapeHtml(value)}</strong>
              </div>
            `,
          )
          .join("")}
      </div>
    `;
  }

  function renderDiagnostics(state) {
    const diagnostics = state.diagnostics || [];
    if (!diagnostics.length) {
      return "";
    }
    return `
      <div class="diagnostics">
        <strong>Bridge diagnostics</strong>
        ${diagnostics
          .map(
            (item) => `
              <p><code>${escapeHtml(item.label)}</code> ${escapeHtml(item.message)}</p>
            `,
          )
          .join("")}
      </div>
    `;
  }

  return {
    commandPayloadAttr,
    formatRelativeTime,
    renderCommandButton,
    renderDiagnostics,
    renderItems,
    renderRuntimeSummary,
  };
}

module.exports = {
  createStudioViewHelpers,
};
