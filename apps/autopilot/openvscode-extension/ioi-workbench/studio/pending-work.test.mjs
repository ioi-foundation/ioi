import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioPendingWorkProjection } = require("./pending-work.js");

function createProjection(overrides = {}) {
  const projection = {
    pendingWorklog: [],
    runtimeEventSeenIds: [],
    ...overrides,
  };
  const pending = createStudioPendingWorkProjection({
    stringValue: (value, fallback = "") => {
      if (value === null || value === undefined) return fallback;
      return typeof value === "string" ? value : String(value);
    },
    firstArray: (value) => (Array.isArray(value) ? value : []),
    compactStudioWhitespace: (value = "") => String(value || "").replace(/\s+/g, " ").trim(),
    sanitizeStudioPublicToolText: (value = "") => String(value || "").replace(/\/home\/[^ ]+/g, "<path>").trim(),
    studioPublicOutputBlock: (value = "", max = 6000) => String(value || "").replace(/\/tmp\/[^ ]+/g, "<tmp>").slice(0, max).trim(),
    humanizeStudioToolName: (value = "") => String(value || "").replace(/__/g, " "),
    studioSourceRefFromRecord: (record = {}) => record?.url ? { title: record.title || record.url, url: record.url } : null,
    studioRuntimeEventIdentity: (event = {}) => event.id || "",
    studioRuntimeEventToolName: (event = {}) => event.toolName || "",
    studioRuntimeEventKind: (event = {}) => event.kind || "",
    studioRuntimeToolEventDetail: (event = {}) => event.detail || "",
    studioRuntimeToolEventExcerpt: (event = {}) => event.excerpt || "",
    studioSourceRefsFromRuntimeEvent: (event = {}) => event.sources || [],
    studioFirstSourceExcerptFromEvent: (event = {}) => event.fallbackExcerpt || "",
    getProjection: () => projection,
  });
  return { pending, projection };
}

test("pending work projection filters abstract rows and normalizes concrete command output", () => {
  const { pending, projection } = createProjection();

  assert.equal(pending.normalizeStudioPendingWorkStep({
    label: "Governed agent run",
    detail: "receipts and traces",
    toolName: "model__route",
    kind: "tool.call",
  }), null);

  const step = pending.appendStudioPendingWorkStep({
    id: "cmd-1",
    label: "shell__run",
    detail: "npm test",
    toolName: "shell__run",
    kind: "tool.call",
    output: "ok from /tmp/private-run",
    sources: [{ title: "Build log", url: "https://example.test/log" }],
  });

  assert.equal(step.label, "shell__run");
  assert.equal(step.excerptPreview, "ok from <tmp>");
  assert.deepEqual(step.sourceChips, [{ title: "Build log", url: "https://example.test/log" }]);
  assert.equal(projection.pendingWorklog.length, 1);
});

test("pending work projection updates rows and preserves useful excerpts", () => {
  const { pending, projection } = createProjection();

  pending.appendStudioPendingWorkStep({
    id: "cmd-1",
    label: "shell__run",
    detail: "npm test",
    toolName: "shell__run",
    kind: "tool.call",
    output: "real compiler output",
  });
  pending.appendStudioPendingWorkStep({
    id: "cmd-1",
    label: "shell__run",
    detail: "status: completed",
    toolName: "shell__run",
    kind: "tool.completed",
    output: "Ran command",
  });

  assert.equal(projection.pendingWorklog.length, 1);
  assert.equal(projection.pendingWorklog[0].status, "running");
  assert.equal(projection.pendingWorklog[0].excerptPreview, "real compiler output");
});

test("pending work projection derives runtime-event rows and deduplicates seen ids", () => {
  const { pending, projection } = createProjection();
  const event = {
    id: "event-1",
    toolName: "web__read",
    kind: "tool.completed",
    detail: "example.test",
    excerpt: "source excerpt",
    sources: [{ title: "Example", url: "https://example.test" }],
  };

  const step = pending.studioPendingStepFromRuntimeEvent(event, {});

  assert.equal(step.label, "Read example.test");
  assert.equal(step.status, "completed");
  assert.equal(step.excerptPreview, "source excerpt");
  assert.equal(pending.studioRuntimeEventSeen(event), false);
  assert.equal(pending.markStudioRuntimeEventSeen(event), true);
  assert.equal(pending.markStudioRuntimeEventSeen(event), false);
  assert.deepEqual(projection.runtimeEventSeenIds, ["event-1"]);
});
