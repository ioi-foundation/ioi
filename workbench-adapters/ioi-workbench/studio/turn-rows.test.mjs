import assert from "node:assert/strict";
import { test } from "node:test";
import turnRowsModule from "./turn-rows.js";

const { createStudioTurnRows } = turnRowsModule;

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createRenderer(projection) {
  return createStudioTurnRows({
    escapeHtml,
    formatStudioWorkDuration: (durationMs) => `${durationMs}ms`,
    getStudioRuntimeProjection: () => projection,
    studioChatCodeExecutionRows: () => "<!-- code-execution -->",
    studioChatOutputRendererRows: () => "<!-- output-renderer -->",
    studioConversationArtifactRows: (artifacts) => `<span data-artifact-count="${artifacts.length}"></span>`,
    studioDisplayTurnContent: (turn) => turn.content,
    studioManagedSessionRows: (cards = []) => `<span data-session-count="${cards.length}"></span>`,
    studioResponseMetricsRows: () => "<!-- metrics -->",
    studioThinkingRows: () => "<!-- thinking -->",
    studioTurnContentRows: (_turn, displayContent) => `<p>${escapeHtml(displayContent)}</p>`,
    studioTurnHasDocumentedWork: (turn) => Boolean(turn.workRecord),
    studioTurnSourceRows: () => "<!-- sources -->",
    studioWorkCommandOutputRows: () => "<!-- command-output -->",
    studioWorkRecordDiffRows: () => "<!-- diff-rows -->",
    studioWorkSummaryRows: () => "<li>summary</li>",
  });
}

test("studio turn rows preserve user and latest assistant selectors", () => {
  const { studioTurnRows } = createRenderer({
    status: "completed",
    turns: [
      {
        role: "user",
        createdAt: "2026-06-04T00:00:00.000Z",
        content: "hello <operator>",
      },
      {
        role: "assistant",
        createdAt: "2026-06-04T00:00:01.000Z",
        content: "ready",
      },
    ],
  });

  const html = studioTurnRows();
  assert.match(html, /data-testid="studio-user-turn-immediate"/);
  assert.match(html, /data-testid="studio-latest-turn"/);
  assert.match(html, /studio-assistant-answer-card/);
  assert.match(html, /hello &lt;operator&gt;/);
});

test("studio turn rows render documented work without leaking unsafe role text", () => {
  const { studioTurnRows } = createRenderer({
    status: "interrupted",
    turns: [
      {
        role: "assistant<script>",
        createdAt: "2026-06-04T00:00:00.000Z",
        content: "ignored",
      },
      {
        role: "assistant",
        createdAt: "2026-06-04T00:00:01.000Z",
        content: "done",
        workRecord: {
          durationMs: 12,
          sessionCards: [{ id: "session-1" }],
          artifactCards: [{ id: "artifact-1" }],
        },
      },
    ],
  });

  const html = studioTurnRows();
  assert.match(html, /studio-chat-turn--assistant&lt;script&gt;/);
  assert.match(html, /data-documented-work="true"/);
  assert.match(html, /Stopped by operator/);
  assert.match(html, /data-session-count="1"/);
  assert.match(html, /data-artifact-count="1"/);
  assert.doesNotMatch(html, /assistant<script>/);
});
