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
    stateDir: "/tmp/runtime-coding-tool-artifacts",
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
    source: "rust_agentgres_runtime_artifact_state_commit_protocol",
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

function rustProjectionError(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function createArtifactReadProjector(calls = [], artifactRecords = []) {
  return {
    projectRuntimeCodingToolArtifactRead(request) {
      calls.push(request);
      assertNoRetiredReadProjectionAliases(request);
      assert.equal(Object.hasOwn(request, "artifact_records"), false);
      if (request.operation === "artifact.read") {
        const artifactId = request.artifact_id ?? request.artifact_ref;
        if (!artifactId) rustProjectionError("artifact_read_id_required", "artifact.read requires artifact_id or artifact_ref.");
        const artifact = artifactRecords.find((record) => record.id === artifactId || record.artifact_id === artifactId);
        if (!artifact) rustProjectionError("runtime_coding_tool_artifact_read_not_found", `Artifact not found: ${artifactId}`);
        if (artifact.thread_id && artifact.thread_id !== request.thread_id) {
          rustProjectionError("runtime_coding_tool_artifact_read_cross_thread_blocked", "Artifact read blocked outside owning runtime thread.");
        }
        const result = fakeArtifactReadResult(artifact, request.range);
        return fakeProjection(request, result);
      }
      if (request.operation === "tool.retrieve_result") {
        const artifactId = request.query?.artifact_id ?? request.query?.artifact_ref;
        if (artifactId) {
          const artifact = artifactRecords.find((record) => record.id === artifactId || record.artifact_id === artifactId);
          if (!artifact) rustProjectionError("runtime_coding_tool_artifact_read_not_found", `Artifact not found: ${artifactId}`);
          if (artifact.thread_id && artifact.thread_id !== request.thread_id) {
            rustProjectionError("runtime_coding_tool_artifact_read_cross_thread_blocked", "Artifact read blocked outside owning runtime thread.");
          }
          return fakeProjection(request, fakeArtifactReadResult(artifact, request.query?.range));
        }
        const toolCallId = request.query?.tool_call_id;
        if (!toolCallId) rustProjectionError("tool_retrieve_result_target_required", "tool.retrieve_result requires tool_call_id or artifact_id.");
        const artifacts = artifactRecords
          .filter((record) => record.thread_id === request.thread_id && record.tool_call_id === toolCallId)
          .sort((left, right) => String(left.channel ?? "").localeCompare(String(right.channel ?? "")));
        if (!artifacts.length) rustProjectionError("runtime_coding_tool_result_artifact_not_found", `Tool result artifact not found: ${toolCallId}`);
        const channel = request.query?.channel;
        const artifact = artifacts.find((record) => record.channel === channel) ?? artifacts[0];
        const result = {
          ...fakeArtifactReadResult(artifact, request.query?.range),
          tool_call_id: toolCallId,
          available_artifacts: artifacts.map(fakeArtifactMetadata),
        };
        return fakeProjection(request, result);
      }
      rustProjectionError("runtime_coding_tool_artifact_read_projection_operation_invalid", "unsupported operation");
    },
  };
}

function assertNoRetiredReadProjectionAliases(request) {
  for (const value of [request, request.query, request.range, request.query?.range]) {
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    for (const alias of ["artifactId", "artifactRef", "toolCallId"]) {
      if (Object.hasOwn(value, alias)) {
        rustProjectionError("runtime_coding_tool_artifact_read_target_alias_retired", `retired alias ${alias}`);
      }
    }
    for (const alias of ["offsetBytes", "lengthBytes", "maxBytes"]) {
      if (Object.hasOwn(value, alias)) {
        rustProjectionError("artifact_read_range_aliases_retired", `retired alias ${alias}`);
      }
    }
  }
}

function fakeProjection(request, result) {
  return {
    source: "rust_runtime_coding_tool_artifact_read_projection_command",
    backend: "rust_policy",
    operation: request.operation,
    operation_kind: request.operation_kind,
    thread_id: request.thread_id,
    result,
    artifact_refs: result.artifact_refs ?? [],
    receipt_refs: result.receipt_refs ?? [],
    evidence_refs: ["coding_tool_artifact_read_projection_rust_owned"],
    projection_hash: "sha256:artifact-read-projection",
  };
}

function fakeArtifactMetadata(artifactRecord = {}) {
  return {
    schema_version: "ioi.runtime.coding-tool-artifact.v1",
    artifact_id: artifactRecord.id,
    thread_id: artifactRecord.thread_id ?? null,
    tool_name: artifactRecord.tool_name ?? null,
    tool_call_id: artifactRecord.tool_call_id ?? null,
    name: artifactRecord.name ?? null,
    channel: artifactRecord.channel ?? null,
    media_type: artifactRecord.media_type ?? "text/plain",
    content_bytes: Number(artifactRecord.content_bytes ?? 0),
    content_hash: artifactRecord.content_hash ?? null,
    receipt_id: artifactRecord.receipt_id ?? null,
    redaction: artifactRecord.redaction ?? "none",
    created_at: artifactRecord.created_at ?? null,
  };
}

function fakeArtifactReadResult(artifactRecord = {}, range = {}) {
  const content = String(artifactRecord.content ?? "");
  const buffer = Buffer.from(content, "utf8");
  const offsetBytes = Math.max(0, Math.min(buffer.byteLength, Number(range?.offset_bytes ?? 0) || 0));
  const lengthLimit = Math.max(1, Number(range?.length_bytes ?? range?.max_bytes ?? 64 * 1024) || 64 * 1024);
  const chunk = buffer.subarray(offsetBytes, Math.min(buffer.byteLength, offsetBytes + lengthLimit));
  const text = chunk.toString("utf8");
  return {
    ...fakeArtifactMetadata(artifactRecord),
    artifact_refs: [artifactRecord.id].filter(Boolean),
    offset_bytes: offsetBytes,
    length_bytes: chunk.byteLength,
    total_bytes: buffer.byteLength,
    content: text,
    content_hash: "sha256:chunk",
    full_content_hash: artifactRecord.content_hash ?? null,
    truncated: offsetBytes + chunk.byteLength < buffer.byteLength,
    receipt_refs: artifactRecord.receipt_refs ?? [],
    shell_fallback_used: false,
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

test("coding-tool artifact surface fails closed without Rust artifact draft planner", () => {
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
      assert.ok(error.details.evidence_refs.includes("rust_daemon_core_artifact_draft_plan_required"));
      return true;
    },
  );
  assert.equal(store.codingArtifacts.size, 0);
  assert.equal(writes.length, 0);
  assert.equal(store.artifactCommits.length, 0);
});

test("coding-tool artifact surface fails closed before cache mutation without Agentgres commit", () => {
  const plannerCalls = [];
  const { surface } = createSurface({
    contextPolicyCore: {
      planRuntimeCodingToolArtifactDrafts(request) {
        plannerCalls.push(request);
        return {
          operation_kind: "artifact.coding_tool_draft",
          artifact_records: [
            {
              schema_version: "ioi.runtime.coding-tool-artifact.v1",
              id: "artifact_rust_planned",
              thread_id: "thread_alpha",
              tool_name: "git.diff",
              tool_call_id: "tool_call_alpha",
              channel: "stdout",
              content: "hello",
              content_hash: "sha256:artifact-content",
              receipt_refs: ["receipt_alpha"],
              evidence_refs: ["coding_tool_artifact_draft_rust_owned"],
            },
          ],
        };
      },
    },
  });
  const store = createStore();
  delete store.commitRuntimeArtifactState;

  assert.throws(
    () =>
      surface.materializeCodingToolArtifactDrafts(store, {
        threadId: "thread_alpha",
        toolId: "git.diff",
        toolCallId: "tool_call_alpha",
        workspaceRoot: "/workspace",
        receiptId: "receipt_alpha",
        result: {
          artifact_drafts: [{ channel: "stdout", content: "hello" }],
        },
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_artifact_rust_core_required");
      assert.equal(error.details.source, "runtime.coding_tool_artifact_surface.agentgres_commit");
      return true;
    },
  );
  assert.equal(plannerCalls.length, 0);
  assert.equal(store.codingArtifacts.size, 0);
});

test("coding-tool artifact surface commits Rust-planned artifact drafts through Agentgres", () => {
  const plannerCalls = [];
  const { surface, writes } = createSurface({
    contextPolicyCore: {
      planRuntimeCodingToolArtifactDrafts(request) {
        plannerCalls.push(request);
        return {
          source: "rust_runtime_coding_tool_artifact_draft_plan_command",
          backend: "rust_policy",
          operation_kind: "artifact.coding_tool_draft",
          artifact_records: [
            {
              schema_version: "ioi.runtime.coding-tool-artifact.v1",
              id: "artifact_rust_planned",
              artifact_id: "artifact_rust_planned",
              source: "rust_runtime_coding_tool_artifact_draft_plan",
              thread_id: "thread_alpha",
              tool_name: "git.diff",
              tool_call_id: "tool_call_alpha",
              workspace_root: "/workspace",
              channel: "stdout",
              name: "stdout.txt",
              media_type: "text/plain",
              content: "hello from rust",
              content_bytes: 15,
              content_hash: "sha256:artifact-content",
              receipt_id: "receipt_alpha",
              receipt_refs: ["receipt_alpha"],
              evidence_refs: [
                "coding_tool_artifact_draft_rust_owned",
                "agentgres_artifact_state_truth_required",
              ],
            },
          ],
          artifact_refs: ["artifact_rust_planned"],
          receipt_refs: ["receipt_alpha"],
          evidence_refs: ["coding_tool_artifact_draft_rust_owned"],
        };
      },
    },
  });
  const store = createStore();

  const artifacts = surface.materializeCodingToolArtifactDrafts(store, {
    threadId: "thread_alpha",
    toolId: "git.diff",
    toolCallId: "tool_call_alpha",
    workspaceRoot: "/workspace",
    receiptId: "receipt_alpha",
    result: {
      artifactDrafts: [{ channel: "retired", content: "retired" }],
      artifact_drafts: [{ channel: "stdout", content: "hello from rust" }],
      receipt_refs: ["receipt_result_alpha"],
    },
  });

  assert.equal(plannerCalls.length, 1);
  assert.equal(plannerCalls[0].operation, "coding_tool_artifact_draft_materialization");
  assert.equal(plannerCalls[0].operation_kind, "artifact.coding_tool_draft");
  assert.equal(plannerCalls[0].thread_id, "thread_alpha");
  assert.equal(Object.hasOwn(plannerCalls[0].result, "artifactDrafts"), false);
  assert.equal(plannerCalls[0].artifact_drafts[0].content, "hello from rust");
  assert.equal(artifacts.length, 1);
  assert.equal(artifacts[0].id, "artifact_rust_planned");
  assert.equal(artifacts[0].artifact_state_commit_hash, "sha256:artifact-commit");
  assert.equal(store.codingArtifacts.get("artifact_rust_planned").content, "hello from rust");
  assert.equal(store.artifactCommits.length, 1);
  assert.equal(store.artifactCommits[0].operation_kind, "artifact.coding_tool_draft");
  assert.equal(store.artifactCommits[0].artifact.source, "rust_runtime_coding_tool_artifact_draft_plan");
  assert.deepEqual(store.artifactCommits[0].receipt_refs, ["receipt_alpha"]);
  assert.equal(writes.length, 0);
});

test("coding-tool artifact surface fails closed without Rust artifact read projector", () => {
  const { surface } = createSurface();
  const store = createStore();
  store.codingArtifacts.set("artifact_alpha", {
    id: "artifact_alpha",
    thread_id: "thread_alpha",
    content: "abcdef",
  });

  assert.throws(
    () => surface.readCodingToolArtifact(store, "thread_alpha", "artifact_alpha"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_artifact_rust_core_required");
      assert.equal(error.details.operation, "artifact.read");
      assert.equal(error.details.operation_kind, "artifact.read_projection");
      assert.ok(error.details.evidence_refs.includes("coding_tool_artifact_read_projection_rust_owned"));
      assert.ok(error.details.evidence_refs.includes("rust_daemon_core_artifact_read_projection_required"));
      return true;
    },
  );
});

test("coding-tool artifact surface reads artifacts inside the owning thread", () => {
  const projectionCalls = [];
  const artifactRecords = [{
    id: "artifact_alpha",
    thread_id: "thread_alpha",
    tool_name: "file.read",
    tool_call_id: "tool_call_alpha",
    channel: "stdout",
    media_type: "text/plain",
    content: "abcdef",
    content_hash: "hash_full",
    receipt_refs: ["receipt://artifact/admitted"],
  }];
  const { surface } = createSurface({ contextPolicyCore: createArtifactReadProjector(projectionCalls, artifactRecords) });
  const store = createStore();

  const result = surface.readCodingToolArtifact(store, "thread_alpha", "artifact_alpha", {
    offset_bytes: 1,
    length_bytes: 3,
  });

  assert.equal(result.schema_version, "ioi.runtime.coding-tool-artifact.v1");
  assert.equal(result.content, "bcd");
  assert.equal(result.total_bytes, 6);
  assert.equal(result.truncated, true);
  assert.deepEqual(result.artifact_refs, ["artifact_alpha"]);
  assert.deepEqual(result.receipt_refs, ["receipt://artifact/admitted"]);
  assert.equal(projectionCalls.length, 1);
  assert.equal(projectionCalls[0].operation, "artifact.read");
  assert.equal(projectionCalls[0].operation_kind, "artifact.read_projection");
  assert.equal(projectionCalls[0].state_dir, store.stateDir);
  assert.equal(Object.hasOwn(projectionCalls[0], "artifact_records"), false);
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
  const artifactRecords = [{
    id: "artifact_alpha",
    thread_id: "thread_alpha",
    content: "secret",
  }];
  const { surface } = createSurface({ contextPolicyCore: createArtifactReadProjector([], artifactRecords) });
  const store = createStore();

  assert.throws(
    () => surface.readCodingToolArtifact(store, "thread_beta", "artifact_alpha"),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.details.thread_id, "thread_beta");
      assert.equal(error.details.artifact_id, "artifact_alpha");
      assert.equal(error.details.owner_thread_id, null);
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
  );
});

test("coding-tool artifact surface retrieves tool results by channel or artifact id", () => {
  const projectionCalls = [];
  const artifactRecords = [{
    id: "artifact_b",
    thread_id: "thread_alpha",
    tool_call_id: "tool_call_alpha",
    channel: "stderr",
    content: "err",
  }, {
    id: "artifact_a",
    thread_id: "thread_alpha",
    tool_call_id: "tool_call_alpha",
    channel: "stdout",
    content: "out",
  }];
  const { surface } = createSurface({ contextPolicyCore: createArtifactReadProjector(projectionCalls, artifactRecords) });
  const store = createStore();

  const byChannel = surface.retrieveCodingToolResult(store, "thread_alpha", {
    tool_call_id: "tool_call_alpha",
    channel: "stderr",
  });
  assert.equal(byChannel.artifact_id, "artifact_b");
  assert.equal(byChannel.content, "err");
  assert.deepEqual(byChannel.available_artifacts.map((artifact) => artifact.artifact_id), ["artifact_b", "artifact_a"]);
  assert.equal(projectionCalls[0].operation, "tool.retrieve_result");
  assert.equal(projectionCalls[0].operation_kind, "tool.retrieve_result_projection");
  assert.equal(projectionCalls[0].state_dir, store.stateDir);
  assert.equal(Object.hasOwn(projectionCalls[0], "artifact_records"), false);

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
      assert.equal(error.code, "runtime_coding_tool_artifact_read_target_alias_retired");
      assert.equal(error.details.thread_id, "thread_alpha");
      assertNoRetiredArtifactErrorDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () => surface.retrieveCodingToolResult(store, "thread_alpha", { artifactId: "artifact_a" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "runtime_coding_tool_artifact_read_target_alias_retired");
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
  const { surface } = createSurface({ contextPolicyCore: createArtifactReadProjector() });
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

test("coding-tool artifact surface requires Rust command-stream event admission", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.admitCodingToolCommandStreamEvents(store, {
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
      assert.equal(error.details.operation, "coding_tool_command_stream_event_admission");
      assert.equal(error.details.operation_kind, "runtime.coding_tool_command_stream");
      assert.deepEqual(error.details.receipt_refs, ["receipt_alpha"]);
      assert.ok(error.details.evidence_refs.includes("coding_tool_command_stream_js_event_append_retired"));
      return true;
    },
  );
  assert.equal(store.events.length, 0);
});

test("coding-tool artifact surface admits command-stream events through Rust core", () => {
  const calls = [];
  const { surface } = createSurface({
    codingToolCommandStreamAdmissionForThread(store, request) {
      calls.push({ store, request });
      return {
        source: "rust_coding_tool_command_stream_admission_protocol",
        events: [
          {
            event_stream_id: request.event_stream_id,
            event_kind: "artifact.command_stream",
            event_id: "event_command_stream_1",
            seq: 7,
            idempotency_key: "thread:thread_alpha:coding-tool-command-stream:tool_call_alpha:0",
            state_root_after: "sha256:stream-after",
            payload_summary: {
              schema_version: "ioi.runtime.coding-tool-command-stream.v1",
              channel: "stdout",
              text: "ok",
            },
          },
        ],
      };
    },
  });
  const store = createStore();

  const events = surface.admitCodingToolCommandStreamEvents(store, {
    agent: { cwd: "/workspace" },
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    toolId: "test.run",
    toolCallId: "tool_call_alpha",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_alpha",
    request: { stream_output: true, source: "operator" },
    result: { stdout: "ok", stderr: "warn" },
    status: "completed",
    receiptRefs: ["receipt_alpha", "receipt_alpha"],
    artifactRefs: ["artifact_alpha"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].store, store);
  assert.equal(calls[0].request.event_stream_id, "thread_alpha:events");
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.tool_id, "test.run");
  assert.equal(calls[0].request.tool_call_id, "tool_call_alpha");
  assert.equal(calls[0].request.workflow_graph_id, "graph_alpha");
  assert.equal(calls[0].request.workflow_node_id, "node_alpha");
  assert.deepEqual(calls[0].request.receipt_refs, ["receipt_alpha"]);
  assert.deepEqual(calls[0].request.artifact_refs, ["artifact_alpha"]);
  assert.deepEqual(calls[0].request.result, { stdout: "ok", stderr: "warn" });
  assert.equal(events.length, 1);
  assert.equal(events[0].event_kind, "artifact.command_stream");
  assert.equal(events[0].state_root_after, "sha256:stream-after");
  assert.equal(store.events.length, 0);
});

test("coding-tool artifact surface skips command-stream events without stream request", () => {
  const { surface } = createSurface();
  const store = createStore();

  assert.deepEqual(
    surface.admitCodingToolCommandStreamEvents(store, {
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
