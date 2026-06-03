import test from "node:test";
import assert from "node:assert/strict";

import { normalizeWorkspaceChangeReviewInspection } from "./workspace-change-inspection.mjs";

test("workspace change inspection projects public hunk previews without receipt internals", () => {
  const inspection = normalizeWorkspaceChangeReviewInspection({
    threadId: "thread_one",
    sessionId: "session_one",
    agent: { runtimeProfile: "runtime_service" },
    bridgeResult: {
      workspace_change_reviews: [
        {
          change_id: "workspace_change:file__edit:1",
          lifecycle: "proposed",
          path: "src/app.js",
          hunk_count: 1,
          accept_available: true,
          reject_available: true,
          rollback_available: false,
          stale: false,
        },
      ],
      latest_trajectory: {
        workspace_changes: [
          {
            change_id: "workspace_change:file__edit:1",
            lifecycle: "proposed",
            path: "src/app.js",
            receipt_ref: "receipt_should_not_project",
            evidence_ref: "evidence_should_not_project",
            hunks: [
              {
                hunk_index: 0,
                kind: "replace",
                search_text: "export const label = 'old';",
                replace_text: "export const label = 'new';",
              },
            ],
          },
        ],
      },
    },
  });

  assert.equal(inspection.status, "ready");
  assert.equal(inspection.hunkPreviews.length, 1);
  assert.equal(inspection.hunkPreviews[0].changeId, "workspace_change:file__edit:1");
  assert.equal(inspection.hunkPreviews[0].file, "src/app.js");
  assert.equal(inspection.hunkPreviews[0].acceptAvailable, true);
  assert.equal(inspection.hunkPreviews[0].rejectAvailable, true);
  assert.match(inspection.hunkPreviews[0].before, /old/);
  assert.match(inspection.hunkPreviews[0].after, /new/);
  const rendered = JSON.stringify(inspection);
  assert.doesNotMatch(rendered, /receipt_should_not_project/);
  assert.doesNotMatch(rendered, /evidence_should_not_project/);
});

test("workspace change inspection accepts bridge top-level workspace change fallback", () => {
  const inspection = normalizeWorkspaceChangeReviewInspection({
    threadId: "thread_two",
    sessionId: "session_two",
    agent: { runtimeProfile: "runtime_service" },
    bridgeResult: {
      workspace_change_reviews: [
        {
          change_id: "workspace_change:file__edit:fallback",
          lifecycle: "applied",
          path: "src/format.mjs",
          hunk_count: 1,
          rollback_available: true,
        },
      ],
      workspace_changes: [
        {
          change_id: "workspace_change:file__edit:fallback",
          lifecycle: "applied",
          path: "src/format.mjs",
          hunks: [
            {
              hunk_index: 0,
              kind: "replace",
              search_text: "return (Number(cents) / 100).toFixed(2);",
              replace_text: "return '$' + (Number(cents) / 100).toFixed(2);",
            },
          ],
        },
      ],
    },
  });

  assert.equal(inspection.status, "ready");
  assert.equal(inspection.hunkPreviews.length, 1);
  assert.equal(inspection.hunkPreviews[0].rollbackAvailable, true);
  assert.match(inspection.hunkPreviews[0].before, /toFixed/);
  assert.match(inspection.hunkPreviews[0].after, /'\$'/);
});
