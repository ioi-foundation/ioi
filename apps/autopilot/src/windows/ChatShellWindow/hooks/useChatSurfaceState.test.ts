import assert from "node:assert/strict";
import fs from "node:fs";

const hookSource = fs.readFileSync(
  new URL("./useChatSurfaceState.ts", import.meta.url),
  "utf8",
);

assert.match(
  hookSource,
  /function shouldDisplayArtifactStatusPreview\(/,
  "chat surface state should centralize when artifact status previews stay expanded",
);

assert.match(
  hookSource,
  /normalizedKind === "token_stream"[\s\S]*preview\.isFinal[\s\S]*normalizedStatus === "completed" \|\| normalizedStatus === "recovered"[\s\S]*return false;/,
  "terminal direct-author token streams should collapse out of the status card once generation has completed",
);

assert.match(
  hookSource,
  /function selectArtifactStatusPreviews\(/,
  "chat surface state should centralize artifact preview precedence in one helper",
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

assert.match(
  hookSource,
  /label: step\.label \|\| "Chat artifact step"[\s\S]*skillDiscoveryResolution\?\.rationale/,
  "artifact guidance labels should prefer explicit operator-step narration and keep runtime guidance as summary context",
);

assert.match(
  hookSource,
  /const hasSessionContent =\s*activeHistory\.length > 0 \|\|\s*chatEvents\.length > 0 \|\|\s*conversationTurns\.length > 0 \|\|\s*activeEvents\.length > 0 \|\|\s*activeArtifacts\.length > 0 \|\|\s*Boolean\(task\?\.chat_session\);/,
  "chat surface state should keep the session lane populated for receipt-driven artifact turns even when no assistant reply has landed yet",
);

assert.match(
  hookSource,
  /if \(task\?\.chat_session\?\.activeOperatorRun\) \{\s*return null;\s*\}/,
  "chat surface state should suppress the separate status card when the unified operator-run transcript is active",
);

console.log("useChatSurfaceState.test.ts: ok");
