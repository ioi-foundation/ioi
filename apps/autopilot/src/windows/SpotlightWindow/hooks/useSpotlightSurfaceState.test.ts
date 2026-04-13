import assert from "node:assert/strict";
import fs from "node:fs";

const hookSource = fs.readFileSync(
  new URL("./useSpotlightSurfaceState.ts", import.meta.url),
  "utf8",
);

assert.match(
  hookSource,
  /function shouldDisplayArtifactStatusPreview\(/,
  "studio surface state should centralize when artifact status previews stay expanded",
);

assert.match(
  hookSource,
  /normalizedKind === "token_stream"[\s\S]*preview\.isFinal[\s\S]*normalizedStatus === "completed" \|\| normalizedStatus === "recovered"[\s\S]*return false;/,
  "terminal direct-author token streams should collapse out of the status card once generation has completed",
);

assert.match(
  hookSource,
  /function selectArtifactStatusPreviews\(/,
  "studio surface state should centralize artifact preview precedence in one helper",
);

assert.match(
  hookSource,
  /const livePreview =\s*filteredExecutionChromeLivePreview \?\?\s*filteredExecutionChromeCodePreview \?\?\s*filteredArtifactThinkingPreview;/,
  "artifact preview precedence should prefer execution-envelope previews before falling back to narration snapshots",
);

assert.match(
  hookSource,
  /const codePreview =\s*filteredExecutionChromeCodePreview\?\.content[\s\S]*filteredExecutionChromeCodePreview\.content !== livePreview\?\.content[\s\S]*\? filteredExecutionChromeCodePreview[\s\S]*: null;/,
  "code preview should be suppressed when it would duplicate the selected live preview",
);

console.log("useSpotlightSurfaceState.test.ts: ok");
