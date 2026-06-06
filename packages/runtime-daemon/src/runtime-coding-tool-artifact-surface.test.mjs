import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createRuntimeCodingToolArtifactSurface } from "./runtime-coding-tool-artifact-surface.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

function policyError(message, details) {
  return runtimeError({ status: 403, code: "policy", message, details });
}

function createSurface(overrides = {}) {
  const writes = [];
  const surface = createRuntimeCodingToolArtifactSurface({
    notFound,
    policyError,
    runtimeError,
    now: () => "2026-06-04T14:00:00.000Z",
    ...overrides,
    writeJson(filePath, value) {
      writes.push({ filePath, value });
    },
  });
  return { surface, writes };
}

function createStore() {
  const events = [];
  return {
    codingArtifacts: new Map(),
    events,
    appendRuntimeEvent(record) {
      const event = {
        ...record,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
      };
      events.push(event);
      return event;
    },
    pathFor(...segments) {
      return path.join("/tmp/runtime-coding-tool-artifacts", ...segments);
    },
  };
}

const retiredArtifactRecordAliasKeys = [
  "schemaVersion",
  "threadId",
  "toolName",
  "toolCallId",
  "workspaceRoot",
  "mediaType",
  "receiptId",
  "contentBytes",
  "contentHash",
  "createdAt",
  "sourcePathHash",
  "sourcePathIncluded",
];

function assertNoRetiredArtifactRecordAliases(record) {
  for (const key of retiredArtifactRecordAliasKeys) {
    assert.equal(Object.hasOwn(record, key), false, `retired artifact record alias ${key} must be absent`);
  }
}

const retiredCommandStreamPayloadAliasKeys = [
  "streamId",
  "streamSeq",
  "outputText",
  "isFinal",
  "artifactRefs",
  "receiptRefs",
];

function assertNoRetiredCommandStreamPayloadAliases(payloadSummary) {
  for (const key of retiredCommandStreamPayloadAliasKeys) {
    assert.equal(Object.hasOwn(payloadSummary, key), false, `retired command-stream payload alias ${key} must be absent`);
  }
}

test("coding-tool artifact surface materializes drafts with stable artifact records", () => {
  const { surface, writes } = createSurface();
  const store = createStore();

  const records = surface.materializeCodingToolArtifactDrafts(store, {
    threadId: "thread_alpha",
    toolId: "file.read",
    toolCallId: "tool_call_alpha",
    workspaceRoot: "/workspace",
    receiptId: "receipt_alpha",
    result: {
      artifactDrafts: [
        {
          channel: "stdout",
          content: "hello",
          mediaType: "text/plain",
          name: "stdout.txt",
          redaction: "none",
        },
        null,
      ],
    },
  });

  assert.equal(records.length, 1);
  assert.equal(records[0].id, "artifact_coding_tool_tool_call_alpha_stdout");
  assert.equal(records[0].schema_version, "ioi.runtime.coding-tool-artifact.v1");
  assert.equal(records[0].thread_id, "thread_alpha");
  assert.equal(records[0].tool_call_id, "tool_call_alpha");
  assert.equal(records[0].content_bytes, 5);
  assert.equal(records[0].created_at, "2026-06-04T14:00:00.000Z");
  assertNoRetiredArtifactRecordAliases(records[0]);
  assert.equal(store.codingArtifacts.get(records[0].id), records[0]);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].filePath, "/tmp/runtime-coding-tool-artifacts/artifacts/artifact_coding_tool_tool_call_alpha_stdout.json");
  assertNoRetiredArtifactRecordAliases(writes[0].value);
});

test("coding-tool artifact surface reads artifacts inside the owning thread", () => {
  const { surface } = createSurface();
  const store = createStore();
  store.codingArtifacts.set("artifact_alpha", {
    id: "artifact_alpha",
    thread_id: "thread_alpha",
    tool_name: "file.read",
    tool_call_id: "tool_call_alpha",
    channel: "stdout",
    media_type: "text/plain",
    content: "abcdef",
    content_hash: "hash_full",
  });

  const result = surface.readCodingToolArtifact(store, "thread_alpha", "artifact_alpha", {
    offset_bytes: 1,
    length_bytes: 3,
  });

  assert.equal(result.schema_version, "ioi.runtime.coding-tool-artifact.v1");
  assert.equal(result.content, "bcd");
  assert.equal(result.total_bytes, 6);
  assert.equal(result.truncated, true);
  assert.deepEqual(result.artifact_refs, ["artifact_alpha"]);
  for (const field of ["schemaVersion", "totalBytes", "artifactRefs", "shellFallbackUsed"]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
  assert.throws(
    () => surface.readCodingToolArtifact(store, "thread_alpha", "artifact_alpha", { offsetBytes: 1 }),
    (error) =>
      error.status === 400 &&
      error.code === "artifact_read_range_aliases_retired" &&
      error.details.retired_aliases.includes("offsetBytes") &&
      Object.hasOwn(error.details, "offsetBytes") === false,
  );
});

test("coding-tool artifact surface blocks cross-thread reads", () => {
  const { surface } = createSurface();
  const store = createStore();
  store.codingArtifacts.set("artifact_alpha", {
    id: "artifact_alpha",
    thread_id: "thread_alpha",
    content: "secret",
  });

  assert.throws(
    () => surface.readCodingToolArtifact(store, "thread_beta", "artifact_alpha"),
    (error) => error.status === 403 && error.details.ownerThreadId === "thread_alpha",
  );
});

test("coding-tool artifact surface retrieves tool results by channel or artifact id", () => {
  const { surface } = createSurface();
  const store = createStore();
  store.codingArtifacts.set("artifact_b", {
    id: "artifact_b",
    thread_id: "thread_alpha",
    tool_call_id: "tool_call_alpha",
    channel: "stderr",
    content: "err",
  });
  store.codingArtifacts.set("artifact_a", {
    id: "artifact_a",
    thread_id: "thread_alpha",
    tool_call_id: "tool_call_alpha",
    channel: "stdout",
    content: "out",
  });

  const byChannel = surface.retrieveCodingToolResult(store, "thread_alpha", {
    tool_call_id: "tool_call_alpha",
    channel: "stderr",
  });
  assert.equal(byChannel.artifact_id, "artifact_b");
  assert.equal(byChannel.content, "err");
  assert.deepEqual(byChannel.available_artifacts.map((artifact) => artifact.artifact_id), ["artifact_b", "artifact_a"]);

  const byArtifact = surface.retrieveCodingToolResult(store, "thread_alpha", {
    artifact_id: "artifact_a",
    range: { max_bytes: 16 },
  });
  assert.equal(byArtifact.artifact_id, "artifact_a");
  assert.equal(byArtifact.shell_fallback_used, false);
  for (const field of ["artifactId", "availableArtifacts", "shellFallbackUsed"]) {
    assert.equal(Object.hasOwn(byChannel, field), false);
    assert.equal(Object.hasOwn(byArtifact, field), false);
  }

  assert.throws(
    () => surface.retrieveCodingToolResult(store, "thread_alpha", { toolCallId: "tool_call_alpha" }),
    (error) => error.status === 400 && error.code === "tool_retrieve_result_target_required",
  );
  assert.throws(
    () => surface.retrieveCodingToolResult(store, "thread_alpha", { artifactId: "artifact_a" }),
    (error) => error.status === 400 && error.code === "tool_retrieve_result_target_required",
  );
  assert.throws(
    () => surface.retrieveCodingToolResult(store, "thread_alpha", {
      artifact_id: "artifact_a",
      range: { maxBytes: 16 },
    }),
    (error) =>
      error.status === 400 &&
      error.code === "artifact_read_range_aliases_retired" &&
      error.details.retired_aliases.includes("maxBytes") &&
      Object.hasOwn(error.details, "maxBytes") === false,
  );
});

test("coding-tool artifact surface requires retrieve targets", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.throws(
    () => surface.retrieveCodingToolResult(store, "thread_alpha", {}),
    (error) => error.status === 400 && error.code === "tool_retrieve_result_target_required",
  );
});

test("coding-tool artifact surface appends command-stream event envelopes", () => {
  const { surface } = createSurface();
  const store = createStore();

  const events = surface.appendCodingToolCommandStreamEvents(store, {
    agent: { cwd: "/workspace" },
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    toolId: "shell.exec",
    toolCallId: "tool_call_alpha",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_alpha",
    request: { streamOutput: true, source: "operator" },
    result: {
      command: "npm test",
      stdout: "ok",
      stderr: "warn",
      truncated: true,
    },
    status: "completed",
    receiptRefs: ["receipt_alpha", "receipt_alpha"],
    artifactRefs: ["artifact_alpha"],
  });

  assert.equal(events.length, 3);
  assert.equal(store.events.length, 3);
  assert.equal(events[0].event_kind, "COMMAND_STREAM");
  assert.equal(events[0].source_event_kind, "CodingTool.Stream");
  assert.equal(events[0].payload_summary.channel, "stdout");
  assert.equal(events[0].payload_summary.output_text, "ok");
  assert.deepEqual(events[0].receipt_refs, ["receipt_alpha"]);
  assert.equal(events[1].payload_summary.channel, "stderr");
  assert.equal(events[2].status, "completed");
  assert.equal(events[2].payload_summary.channel, "control");
  assert.equal(events[2].payload_summary.is_final, true);
  assert.equal(events[2].payload_summary.stream_seq, 3);
  for (const event of events) {
    assertNoRetiredCommandStreamPayloadAliases(event.payload_summary);
  }
});

test("coding-tool artifact surface skips command-stream events without stream request", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.deepEqual(
    surface.appendCodingToolCommandStreamEvents(store, {
      agent: { cwd: "/workspace" },
      threadId: "thread_alpha",
      toolId: "shell.exec",
      toolCallId: "tool_call_alpha",
      result: { stdout: "ok" },
    }),
    [],
  );
  assert.equal(store.events.length, 0);
});

test("coding-tool artifact surface materializes visual GUI observation artifacts", () => {
  const { surface, writes } = createSurface();
  const store = createStore();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-visual-artifacts-"));
  fs.writeFileSync(path.join(cwd, "screenshot.png"), Buffer.from([1, 2, 3]));

  const result = surface.materializeVisualGuiObservationArtifacts(store, {
    threadId: "thread_alpha",
    toolId: "computer.visual_gui.observe",
    toolCallId: "tool_call_alpha",
    workspaceRoot: cwd,
    input: {
      screenshotPath: "screenshot.png",
      somRef: "artifact_existing_som",
    },
  });

  assert.deepEqual(result.artifactRefs, [
    "artifact_computer_use_visual_tool_call_alpha_visual-gui-screenshot",
  ]);
  assert.equal(result.metadata.screenshotRef, "artifact_computer_use_visual_tool_call_alpha_visual-gui-screenshot");
  assert.equal(result.metadata.somRef, undefined);
  assert.equal(result.artifacts[0].media_type, "image/png");
  assert.equal(result.artifacts[0].encoding, "base64");
  assert.equal(result.artifacts[0].content, Buffer.from([1, 2, 3]).toString("base64"));
  assert.equal(result.artifacts[0].source_path_included, false);
  assertNoRetiredArtifactRecordAliases(result.artifacts[0]);
  assert.equal(writes.length, 1);
  assertNoRetiredArtifactRecordAliases(writes[0].value);
});

test("coding-tool artifact surface skips visual GUI paths with explicit refs", () => {
  const { surface } = createSurface();
  const store = createStore();

  const result = surface.materializeVisualGuiObservationArtifacts(store, {
    threadId: "thread_alpha",
    toolId: "computer.visual_gui.observe",
    toolCallId: "tool_call_alpha",
    workspaceRoot: "/missing",
    input: {
      screenshotPath: "missing.png",
      screenshotRef: "artifact_existing",
    },
  });

  assert.deepEqual(result, { metadata: {}, artifactRefs: [], artifacts: [] });
});

test("coding-tool artifact surface fails closed for unreadable visual GUI artifacts", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.materializeVisualGuiObservationArtifacts(store, {
        threadId: "thread_alpha",
        toolId: "computer.visual_gui.observe",
        toolCallId: "tool_call_alpha",
        workspaceRoot: "/missing",
        input: { screenshotPath: "missing.png" },
      }),
    (error) => error.status === 400 && error.code === "computer_use_visual_artifact_unreadable",
  );
});

test("coding-tool artifact surface enforces visual GUI artifact size limit", () => {
  const { surface } = createSurface({ maxVisualArtifactBytes: 2 });
  const store = createStore();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-visual-artifacts-"));
  fs.writeFileSync(path.join(cwd, "screenshot.png"), Buffer.from([1, 2, 3]));

  assert.throws(
    () =>
      surface.materializeVisualGuiObservationArtifacts(store, {
        threadId: "thread_alpha",
        toolId: "computer.visual_gui.observe",
        toolCallId: "tool_call_alpha",
        workspaceRoot: cwd,
        input: { screenshotPath: "screenshot.png" },
      }),
    (error) =>
      error.status === 413 &&
      error.code === "computer_use_visual_artifact_too_large" &&
      error.details.maxBytes === 2,
  );
});
