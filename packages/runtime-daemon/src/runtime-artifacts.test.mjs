import assert from "node:assert/strict";
import test from "node:test";

import { artifact, createRunArtifactResolver } from "./runtime-artifacts.mjs";

test("artifact builds stable ids and serializes object content", () => {
  const record = artifact(
    "run_123",
    "trace.json",
    "application/json",
    "receipt_123",
    { status: "completed", count: 2 },
    "redacted",
  );

  assert.deepEqual(record, {
    id: "artifact_run_123_trace_json",
    runId: "run_123",
    name: "trace.json",
    mediaType: "application/json",
    redaction: "redacted",
    receiptId: "receipt_123",
    content: JSON.stringify({ status: "completed", count: 2 }, null, 2),
  });
});

test("artifact preserves string content without JSON encoding", () => {
  const record = artifact("run_123", "diff.patch", "text/x-diff", "receipt_123", "diff --git a b", "none");

  assert.equal(record.id, "artifact_run_123_diff_patch");
  assert.equal(record.content, "diff --git a b");
});

test("artifact resolver matches id, name, artifact refs, and artifact-prefixed refs", () => {
  const { resolveRunArtifact } = createRunArtifactResolver({
    normalizeArray: (value) => Array.isArray(value) ? value : [],
    optionalString: (value) => typeof value === "string" ? value.trim() || null : null,
  });
  const run = {
    artifacts: [
      { id: "artifact_run_123_trace_json", name: "trace.json" },
      { id: "artifact_run_123_scorecard_json", artifactRef: "scorecard:latest" },
      { id: "artifact_run_123_patch", artifact_ref: "artifact:patch:workspace.diff" },
    ],
  };

  assert.equal(resolveRunArtifact(run, "artifact_run_123_trace_json"), run.artifacts[0]);
  assert.equal(resolveRunArtifact(run, "trace.json"), run.artifacts[0]);
  assert.equal(resolveRunArtifact(run, "artifact:run_123_trace_json"), run.artifacts[0]);
  assert.equal(resolveRunArtifact(run, "scorecard:latest"), run.artifacts[1]);
  assert.equal(resolveRunArtifact(run, "artifact:patch:workspace.diff"), run.artifacts[2]);
  assert.equal(resolveRunArtifact(run, "missing"), null);
});

test("artifact resolver tolerates missing refs and non-array artifacts", () => {
  const { resolveRunArtifact } = createRunArtifactResolver();

  assert.equal(resolveRunArtifact({ artifacts: null }, ""), null);
  assert.equal(resolveRunArtifact({ artifacts: {} }, "trace.json"), null);
  assert.equal(resolveRunArtifact({}, null), null);
});
