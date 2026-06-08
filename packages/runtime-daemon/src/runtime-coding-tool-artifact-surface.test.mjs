import assert from "node:assert/strict";
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
  const artifactCommits = [];
  return {
    codingArtifacts: new Map(),
    events,
    artifactCommits,
    commitRuntimeArtifactState(request) {
      artifactCommits.push(request);
      return fakeArtifactStateCommit(request);
    },
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

function fakeArtifactStateCommit(request) {
  return {
    source: "rust_agentgres_runtime_artifact_state_commit_command",
    backend: "rust_agentgres_storage",
    record: {
      schema_version: "ioi.runtime_artifact_state_commit.v1",
      artifact_id: request.artifact_id,
      operation_kind: request.operation_kind,
      storage_backend_ref: request.storage_backend_ref,
      record: {
        record_path: `artifacts/${request.artifact_id}.json`,
        object_ref: `agentgres://runtime-state/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`,
        content_hash: "sha256:artifact-content",
        payload_refs: [`payload://runtime/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`],
        receipt_refs: request.receipt_refs,
        admission: { admission_hash: "sha256:artifact-admission" },
      },
      commit_hash: "sha256:artifact-commit",
    },
    storage_record: {
      record_path: `artifacts/${request.artifact_id}.json`,
      object_ref: `agentgres://runtime-state/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`,
      content_hash: "sha256:artifact-content",
      payload_refs: [`payload://runtime/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`],
      receipt_refs: request.receipt_refs,
      admission: { admission_hash: "sha256:artifact-admission" },
    },
    artifact_id: request.artifact_id,
    object_ref: `agentgres://runtime-state/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`,
    content_hash: "sha256:artifact-content",
    admission_hash: "sha256:artifact-admission",
    commit_hash: "sha256:artifact-commit",
    written_record: { record_path: `artifacts/${request.artifact_id}.json` },
  };
}

const retiredArtifactErrorDetailAliasKeys = [
  "threadId",
  "artifactId",
  "ownerThreadId",
  "toolCallId",
];

function assertNoRetiredArtifactErrorDetailAliases(details) {
  for (const key of retiredArtifactErrorDetailAliasKeys) {
    assert.equal(Object.hasOwn(details, key), false, `retired artifact error detail alias ${key} must be absent`);
  }
}

test("coding-tool artifact surface fails closed before JS artifact draft materialization", () => {
  const { surface, writes } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.materializeCodingToolArtifactDrafts(store, {
        threadId: "thread_alpha",
        toolId: "file.read",
        toolCallId: "tool_call_alpha",
        workspaceRoot: "/workspace",
        receiptId: "receipt_alpha",
        result: {
          artifact_drafts: [
            {
              channel: "stdout",
              content: "hello",
              media_type: "text/markdown",
              name: "stdout.txt",
              redaction: "none",
            },
          ],
        },
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_artifact_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_artifact");
      assert.equal(error.details.operation_kind, "artifact.coding_tool_draft");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.tool_call_id, "tool_call_alpha");
      assert.equal(error.details.artifact_draft_count, 1);
      assert.ok(error.details.evidence_refs.includes("coding_tool_artifact_draft_js_materializer_retired"));
      return true;
    },
  );
  assert.equal(store.codingArtifacts.size, 0);
  assert.equal(writes.length, 0);
  assert.equal(store.artifactCommits.length, 0);
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
  assert.throws(
    () => surface.readCodingToolArtifact(store, "thread_alpha", "missing_artifact"),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.artifact_id, "missing_artifact");
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
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
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.details.thread_id, "thread_beta");
      assert.equal(error.details.artifact_id, "artifact_alpha");
      assert.equal(error.details.owner_thread_id, "thread_alpha");
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
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
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "tool_retrieve_result_target_required");
      assert.equal(error.details.thread_id, "thread_alpha");
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () => surface.retrieveCodingToolResult(store, "thread_alpha", { artifactId: "artifact_a" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "tool_retrieve_result_target_required");
      assert.equal(error.details.thread_id, "thread_alpha");
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
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
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "tool_retrieve_result_target_required");
      assert.equal(error.details.thread_id, "thread_alpha");
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () => surface.retrieveCodingToolResult(store, "thread_alpha", { tool_call_id: "missing_tool_call" }),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.tool_call_id, "missing_tool_call");
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
  );
});

test("coding-tool artifact surface fails closed before JS command-stream event append", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.appendCodingToolCommandStreamEvents(store, {
        agent: { cwd: "/workspace" },
        threadId: "thread_alpha",
        turnId: "turn_alpha",
        toolId: "shell.exec",
        toolCallId: "tool_call_alpha",
        workflowGraphId: "graph_alpha",
        workflowNodeId: "node_alpha",
        request: { stream_output: true, source: "operator" },
        result: {
          command: "npm test",
          stdout: "ok",
          stderr: "warn",
          truncated: true,
        },
        status: "completed",
        receiptRefs: ["receipt_alpha", "receipt_alpha"],
        artifactRefs: ["artifact_alpha"],
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_artifact_rust_core_required");
      assert.equal(error.details.operation_kind, "artifact.command_stream");
      assert.equal(error.details.stream_chunk_count, 2);
      assert.deepEqual(error.details.receipt_refs, ["receipt_alpha"]);
      assert.ok(error.details.evidence_refs.includes("coding_tool_command_stream_js_event_append_retired"));
      return true;
    },
  );
  assert.equal(store.events.length, 0);
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

test("coding-tool artifact surface fails closed before JS visual GUI artifact materialization", () => {
  const { surface, writes } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.materializeVisualGuiObservationArtifacts(store, {
        threadId: "thread_alpha",
        toolId: "computer.visual_gui.observe",
        toolCallId: "tool_call_alpha",
        workspaceRoot: "/workspace",
        input: {
          screenshot_path: "screenshot.png",
          som_ref: "artifact_existing_som",
        },
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_artifact_rust_core_required");
      assert.equal(error.details.operation_kind, "artifact.visual_observation");
      assert.equal(error.details.has_screenshot_path, true);
      assert.ok(error.details.evidence_refs.includes("visual_observation_artifact_js_materializer_retired"));
      return true;
    },
  );
  assert.equal(writes.length, 0);
  assert.equal(store.artifactCommits.length, 0);
});

test("coding-tool artifact surface ignores retired visual GUI path aliases", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.materializeVisualGuiObservationArtifacts(store, {
        threadId: "thread_alpha",
        toolId: "computer.visual_gui.observe",
        toolCallId: "tool_call_alpha",
        workspaceRoot: "/workspace",
        input: {
          screenshotPath: "retired-screenshot.png",
          somPath: "retired-som.json",
          axPath: "retired-ax.json",
        },
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_artifact_rust_core_required");
      assert.equal(error.details.operation_kind, "artifact.visual_observation");
      assert.equal(error.details.has_screenshot_path, false);
      assert.equal(error.details.has_som_path, false);
      assert.equal(error.details.has_ax_path, false);
      assert.equal(Object.hasOwn(error.details, "screenshotPath"), false);
      assert.equal(Object.hasOwn(error.details, "somPath"), false);
      assert.equal(Object.hasOwn(error.details, "axPath"), false);
      return true;
    },
  );
  assert.equal(store.codingArtifacts.size, 0);
});

test("coding-tool artifact surface requires Rust core for visual GUI paths with explicit refs", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.materializeVisualGuiObservationArtifacts(store, {
        threadId: "thread_alpha",
        toolId: "computer.visual_gui.observe",
        toolCallId: "tool_call_alpha",
        workspaceRoot: "/missing",
        input: {
          screenshot_path: "missing.png",
          screenshot_ref: "artifact_existing",
        },
      }),
    (error) =>
      error.status === 501 &&
      error.code === "runtime_coding_tool_artifact_rust_core_required" &&
      error.details.operation_kind === "artifact.visual_observation",
  );
  assert.equal(store.codingArtifacts.size, 0);
});

test("coding-tool artifact surface fails closed before local visual GUI file reads", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.materializeVisualGuiObservationArtifacts(store, {
        threadId: "thread_alpha",
        toolId: "computer.visual_gui.observe",
          toolCallId: "tool_call_alpha",
          workspaceRoot: "/missing",
          input: { screenshot_path: "missing.png" },
        }),
    (error) =>
      error.status === 501 &&
      error.code === "runtime_coding_tool_artifact_rust_core_required" &&
      error.details.operation_kind === "artifact.visual_observation" &&
      Object.hasOwn(error.details, "source_path_hash") === false,
  );
  assert.equal(store.codingArtifacts.size, 0);
});

test("coding-tool artifact surface fails closed before JS visual GUI size checks", () => {
  const { surface } = createSurface({ maxVisualArtifactBytes: 2 });
  const store = createStore();

  assert.throws(
    () =>
      surface.materializeVisualGuiObservationArtifacts(store, {
        threadId: "thread_alpha",
        toolId: "computer.visual_gui.observe",
        toolCallId: "tool_call_alpha",
        workspaceRoot: "/workspace",
        input: { screenshot_path: "screenshot.png" },
      }),
    (error) =>
      error.status === 501 &&
      error.code === "runtime_coding_tool_artifact_rust_core_required" &&
      error.details.operation_kind === "artifact.visual_observation" &&
      Object.hasOwn(error.details, "max_bytes") === false &&
      Object.hasOwn(error.details, "content_bytes") === false,
  );
  assert.equal(store.codingArtifacts.size, 0);
});
