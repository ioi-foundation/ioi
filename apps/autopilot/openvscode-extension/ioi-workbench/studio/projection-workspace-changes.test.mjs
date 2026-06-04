import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioWorkspaceChangeProjection } = require("./projection-workspace-changes.js");

function stringValue(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function createHarness({ state = { threadId: "thread-1", diffHunks: [], runtimeCockpit: {} }, requestJson = async () => ({}) } = {}) {
  const outputLines = [];
  const harness = createStudioWorkspaceChangeProjection({
    compactStudioWhitespace: (value) => String(value || "").trim().replace(/\s+/g, " "),
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token-1",
    firstArray: (value) => Array.isArray(value) ? value : [],
    getStudioRuntimeProjection: () => state,
    requestJson,
    stringValue,
    workspaceSummary: () => ({ path: "/workspace/root" }),
  });
  return {
    harness,
    output: { appendLine: (line) => outputLines.push(line) },
    outputLines,
    state,
  };
}

test("workspace change inspection projects normalized hunk previews into runtime state", () => {
  const { harness, state } = createHarness();
  const previews = harness.applyStudioWorkspaceChangeReviewInspection({
    hunk_previews: [
      {
        change_id: "change-1",
        hunk_index: 2,
        path: "src/app.js",
        lifecycle: "needs_review",
        search_text: "- old",
        replace_text: "+ new",
        accept_available: true,
        reject_available: true,
        rollback_available: false,
        stale: true,
        stale_reason: "file changed",
      },
      { title: "ignored empty hunk" },
    ],
  });

  assert.equal(previews.length, 1);
  assert.equal(previews[0].id, "workspace-hunk-0");
  assert.equal(previews[0].changeId, "change-1");
  assert.equal(previews[0].hunkIndex, 2);
  assert.equal(previews[0].file, "src/app.js");
  assert.equal(previews[0].status, "needs_review");
  assert.equal(previews[0].before, "- old");
  assert.equal(previews[0].after, "+ new");
  assert.equal(previews[0].acceptAvailable, true);
  assert.equal(previews[0].rejectAvailable, true);
  assert.equal(previews[0].rollbackAvailable, false);
  assert.equal(previews[0].staleReason, "file changed");
  assert.deepEqual(state.diffHunks, previews);
  assert.equal(state.runtimeCockpit.inlineDiffOverlayObserved, true);
  assert.equal(state.runtimeCockpit.hunkNavigationObserved, true);
});

test("workspace change daemon refresh preserves route envelope and query", async () => {
  const requests = [];
  const { harness } = createHarness({
    requestJson: async (...args) => {
      requests.push(args);
      return {
        hunkPreviews: [
          {
            changeId: "change-2",
            file: "README.md",
            before: "before",
            after: "after",
          },
        ],
      };
    },
  });

  const previews = await harness.refreshStudioWorkspaceChangeReviewsFromDaemon();

  assert.equal(previews.length, 1);
  assert.equal(requests[0][0], "http://daemon.test");
  assert.equal(requests[0][1], "/v1/threads/thread-1/workspace-change-reviews?workspaceRoot=%2Fworkspace%2Froot");
  assert.deepEqual(requests[0][2], {
    token: "token-1",
    timeoutMs: 10000,
  });
});

test("workspace change refresh fails closed without endpoint errors leaking to UI state", async () => {
  const { harness, output, outputLines, state } = createHarness({
    requestJson: async () => {
      throw new Error("daemon unavailable");
    },
  });

  const previews = await harness.refreshStudioWorkspaceChangeReviewsFromDaemon(output);

  assert.deepEqual(previews, []);
  assert.deepEqual(state.diffHunks, []);
  assert.equal(outputLines.length, 1);
  assert.match(outputLines[0], /workspace change review inspection unavailable: daemon unavailable/);
});
