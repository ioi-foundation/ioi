import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioPendingView } = require("./pending-view.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function createView(state) {
  return createStudioPendingView({
    compactStudioWhitespace: (value) => String(value || "").trim().replace(/\s+/g, " "),
    escapeHtml,
    firstArray: (value) => Array.isArray(value) ? value : [],
    formatStudioWorkDuration: () => "2s",
    getStudioRuntimeProjection: () => state,
    studioPendingCommandOutputExcerpt: (step, fallback) => step.stdout || fallback || "",
    studioSourceChipRows: (sources) => sources.map((source) => `<span>${escapeHtml(source.label || source.url || "")}</span>`).join(""),
    studioVisiblePendingStepDetail: (detail) => String(detail || "").replace("raw", "public"),
  });
}

test("pending view hides when projection is not pending", () => {
  const view = createView({ pending: false, pendingWorklog: [] });

  assert.equal(view.studioPendingProjectionRows(), "");
});

test("pending view renders pending state and worklog metadata", () => {
  const startedAt = Date.now() - 2000;
  const view = createView({
    pending: true,
    pendingStartedAtMs: startedAt,
    pendingWorklog: [{
      label: "Running command",
      status: "running",
      at: new Date(startedAt).toISOString(),
      detail: "raw detail",
      stdout: "npm test",
      sourceChips: [{ label: "Trace <1>" }],
      toolId: "shell__run",
    }],
  });

  const html = view.studioPendingProjectionRows();

  assert.match(html, /data-testid="studio-pending-state"/);
  assert.match(html, /Thinking about your request/);
  assert.match(html, /Running command for 2s/);
  assert.match(html, /public detail/);
  assert.match(html, /Trace &lt;1&gt;/);
  assert.match(html, /data-testid="studio-pending-command-output"/);
  assert.match(html, /npm test/);
});

test("pending view renders non-command excerpts as paragraphs", () => {
  const view = createView({
    pending: true,
    pendingStartedAtMs: Date.now(),
    pendingWorklog: [{
      label: "Reading sources",
      status: "completed",
      excerptPreview: "Found relevant docs",
    }],
  });

  const html = view.studioPendingProjectionRows();

  assert.match(html, /studio-pending-step__excerpt/);
  assert.match(html, /Found relevant docs/);
  assert.doesNotMatch(html, /studio-pending-step__command-output/);
});
