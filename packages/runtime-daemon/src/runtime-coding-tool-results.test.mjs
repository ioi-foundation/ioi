import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createRuntimeCodingToolResultHelpers } from "./runtime-coding-tool-results.mjs";

function makeHelpers() {
  return createRuntimeCodingToolResultHelpers({
    CODING_TOOL_ARTIFACT_SCHEMA_VERSION: "artifact.v1",
    CODING_TOOL_RESULT_SCHEMA_VERSION: "result.v1",
    TERMINAL_EVENT_TYPES: new Set(["tool.completed", "tool.failed"]),
    normalizeArray: (value) => (Array.isArray(value) ? value : []),
    uniqueStrings: (values) => [...new Set(values.filter((value) => typeof value === "string" && value))],
    optionalString: (value) => (typeof value === "string" && value ? value : null),
    doctorHash: (value) => crypto.createHash("sha256").update(String(value)).digest("hex"),
    safeId: (value) => String(value ?? "unknown").replace(/[^a-zA-Z0-9_.:-]+/g, "_"),
  });
}

test("coding tool public result removes drafts and attaches artifact metadata", () => {
  const { codingToolResultWithoutDrafts } = makeHelpers();
  const publicResult = codingToolResultWithoutDrafts(
    {
      ok: true,
      artifactRefs: ["artifact_existing"],
      artifactDrafts: [{ content: "private draft" }],
      workspace_snapshot_drafts: [{ path: "private" }],
    },
    [
      {
        id: "artifact_new",
        thread_id: "thread_1",
        tool_name: "file.read",
        content_bytes: 12,
      },
    ],
  );

  assert.equal(publicResult.ok, true);
  assert.deepEqual(publicResult.artifactRefs, ["artifact_existing", "artifact_new"]);
  assert.equal(publicResult.artifactDrafts, undefined);
  assert.equal(publicResult.workspace_snapshot_drafts, undefined);
  assert.equal(publicResult.artifacts[0].schemaVersion, "artifact.v1");
  assert.equal(publicResult.artifacts[0].threadId, "thread_1");
});

test("coding tool artifact read result slices content and emits stable receipt refs", () => {
  const { codingToolArtifactReadResult } = makeHelpers();
  const result = codingToolArtifactReadResult(
    {
      id: "artifact/1",
      content: "abcdef",
      content_hash: "full_hash",
      media_type: "text/plain",
    },
    {
      offsetBytes: 2,
      lengthBytes: 3,
    },
  );

  assert.equal(result.schemaVersion, "artifact.v1");
  assert.equal(result.content, "cde");
  assert.equal(result.lengthBytes, 3);
  assert.equal(result.totalBytes, 6);
  assert.equal(result.truncated, true);
  assert.equal(result.fullContentHash, "full_hash");
  assert.match(result.receiptRefs[0], /^receipt_artifact_read_artifact_1_/);
});

test("coding tool command stream helpers preserve channel order and chunk long output", () => {
  const {
    codingToolCommandStreamChunks,
    codingToolCommandStreamRequested,
    splitCommandStreamText,
  } = makeHelpers();

  assert.equal(codingToolCommandStreamRequested({ input: { stream_output: true } }), true);
  assert.equal(codingToolCommandStreamRequested({ input: { stream_output: false } }), false);
  assert.deepEqual(splitCommandStreamText("a".repeat(801)).map((chunk) => chunk.length), [800, 1]);
  assert.deepEqual(codingToolCommandStreamChunks({ stdout: "ok", stderr: "warn" }), [
    { channel: "stdout", text: "ok" },
    { channel: "stderr", text: "warn" },
  ]);
});

test("terminal count uses injected terminal event vocabulary", () => {
  const { terminalCount } = makeHelpers();
  assert.equal(
    terminalCount([
      { type: "turn.started" },
      { type: "tool.completed" },
      { type: "tool.failed" },
    ]),
    2,
  );
});
