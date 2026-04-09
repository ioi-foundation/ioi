import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveInitialTriageSelection,
  resolveScorecardPreviewEnabled,
} from "./appShellState.ts";

test("resolveScorecardPreviewEnabled reads the preview query flag", () => {
  assert.equal(resolveScorecardPreviewEnabled(""), false);
  assert.equal(resolveScorecardPreviewEnabled("?scorecardPreview=0"), false);
  assert.equal(resolveScorecardPreviewEnabled("?scorecardPreview=1"), true);
  assert.equal(
    resolveScorecardPreviewEnabled("?foo=bar&scorecardPreview=1"),
    true,
  );
});

test("resolveInitialTriageSelection prefers focus suite and latest case", () => {
  assert.deepEqual(
    resolveInitialTriageSelection(
      [
        { suite: "WorkArena", focusCaseId: null },
        { suite: "Studio Artifacts", focusCaseId: "artifact-case-1" },
      ],
      [
        { suite: "OSWorld", caseId: "osworld-case-9" },
        { suite: "Studio Artifacts", caseId: "artifact-case-1" },
      ],
    ),
    {
      suite: "Studio Artifacts",
      caseId: "osworld-case-9",
    },
  );

  assert.deepEqual(resolveInitialTriageSelection([], []), {
    suite: "MiniWoB++",
    caseId: null,
  });
});
