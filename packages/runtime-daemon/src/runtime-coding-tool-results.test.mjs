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
  });
}

test("coding tool public result removes drafts and attaches artifact metadata", () => {
  const { codingToolResultWithoutDrafts } = makeHelpers();
  const publicResult = codingToolResultWithoutDrafts(
    {
      ok: true,
      artifact_refs: ["artifact_existing"],
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
  assert.deepEqual(publicResult.artifact_refs, ["artifact_existing", "artifact_new"]);
  assert.equal(publicResult.artifactDrafts, undefined);
  assert.equal(publicResult.workspace_snapshot_drafts, undefined);
  assert.equal(publicResult.artifacts[0].schema_version, "artifact.v1");
  assert.equal(publicResult.artifacts[0].thread_id, "thread_1");
  for (const field of ["artifactRefs", "schemaVersion", "threadId", "contentBytes"]) {
    assert.equal(Object.hasOwn(publicResult, field), false);
    assert.equal(Object.hasOwn(publicResult.artifacts[0], field), false);
  }
});

test("coding tool artifact read result slices content without synthesizing JS receipt refs", () => {
  const { codingToolArtifactReadResult } = makeHelpers();
  const result = codingToolArtifactReadResult(
    {
      id: "artifact/1",
      content: "abcdef",
      content_hash: "full_hash",
      media_type: "text/plain",
      receipt_refs: ["receipt://artifact/admitted"],
    },
    {
      offset_bytes: 2,
      length_bytes: 3,
    },
  );

  assert.equal(result.schema_version, "artifact.v1");
  assert.equal(result.content, "cde");
  assert.equal(result.length_bytes, 3);
  assert.equal(result.total_bytes, 6);
  assert.equal(result.truncated, true);
  assert.equal(result.full_content_hash, "full_hash");
  assert.deepEqual(result.receipt_refs, ["receipt://artifact/admitted"]);
  for (const field of ["schemaVersion", "artifactRefs", "lengthBytes", "totalBytes", "fullContentHash", "receiptRefs"]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
});

test("coding tool artifact read result leaves omitted Rust receipt refs empty", () => {
  const { codingToolArtifactReadResult } = makeHelpers();
  const result = codingToolArtifactReadResult(
    {
      id: "artifact/1",
      content: "abcdef",
    },
    {
      offset_bytes: 0,
      length_bytes: 3,
    },
  );

  assert.deepEqual(result.receipt_refs, []);
});

test("coding tool command stream helpers preserve channel order and chunk long output", () => {
  const {
    codingToolCommandStreamChunks,
    codingToolCommandStreamRequested,
    splitCommandStreamText,
  } = makeHelpers();

  assert.equal(codingToolCommandStreamRequested({ input: { stream_output: true } }), true);
  assert.equal(codingToolCommandStreamRequested({ stream_output: true }), true);
  assert.equal(codingToolCommandStreamRequested({ command_stream: true }), true);
  assert.equal(codingToolCommandStreamRequested({ input: { stream_output: false } }), false);
  assert.equal(codingToolCommandStreamRequested({ streamOutput: true }), false);
  assert.equal(codingToolCommandStreamRequested({ commandStream: true }), false);
  assert.equal(codingToolCommandStreamRequested({ input: { streamOutput: true } }), false);
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
