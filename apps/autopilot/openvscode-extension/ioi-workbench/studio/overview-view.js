"use strict";

function createStudioOverviewView({ commandPayloadAttr, escapeHtml }) {
  function overviewTone(value) {
    const normalized = String(value || "unknown").toLowerCase();
    if (/connected|ready|loaded|running|active|pass|available/.test(normalized)) {
      return "ready";
    }
    if (/blocked|failed|error|denied/.test(normalized)) {
      return "blocked";
    }
    if (/degraded|warning|starting|loading|pending/.test(normalized)) {
      return "warn";
    }
    return "muted";
  }

  function overviewPill(label, value, tone = overviewTone(value)) {
    return `
      <span class="overview-pill is-${escapeHtml(tone)}">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
      </span>
    `;
  }

  function renderOverviewAction({ label, description, command, payload, tone = "default" }) {
    return `
      <button
        class="overview-action is-${escapeHtml(tone)}"
        type="button"
        data-command="${escapeHtml(command)}"${commandPayloadAttr(payload)}
      >
        <span>${escapeHtml(label)}</span>
        <small>${escapeHtml(description)}</small>
      </button>
    `;
  }

  function renderOverviewRow(label, value, detail, tone = "muted") {
    return `
      <div class="overview-row">
        <span class="overview-row__label">${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
        <small class="is-${escapeHtml(tone)}">${escapeHtml(detail)}</small>
      </div>
    `;
  }

  return {
    overviewPill,
    overviewTone,
    renderOverviewAction,
    renderOverviewRow,
  };
}

module.exports = {
  createStudioOverviewView,
};
