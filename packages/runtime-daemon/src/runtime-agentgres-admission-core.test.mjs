import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
  RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION,
  RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
  RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
  RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUST_AGENTGRES_STORAGE_BACKEND,
  RUST_RUNTIME_AGENTGRES_BACKEND,
  RuntimeAgentgresAdmissionCore,
  RuntimeAgentgresAdmissionCoreError,
  createRuntimeAgentgresAdmissionCore,
} from "./runtime-agentgres-admission-core.mjs";

function storageWriteRequest() {
  return {
    schema_version: "ioi.storage_backend_write_admission.v1",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    object_ref: "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
    content_hash: "sha256:run-state-json",
    artifact_refs: [],
    payload_refs: ["payload://runtime/runs/run_1/records/runs/run_1.json"],
    receipt_refs: ["receipt_policy"],
  };
}

function runtimeRun() {
  return {
    id: "run_1",
    agentId: "agent_1",
    status: "completed",
    mode: "send",
    objective: "Ship the runtime state slice",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [{ type: "started" }, { type: "completed" }],
    receipts: [{ id: "receipt_policy", kind: "policy_decision" }],
    artifacts: [{ id: "artifact_1", name: "result.txt", kind: "text" }],
  };
}

function commitRequest() {
  return {
    schema_version: "ioi.runtime_run_state_commit.v1",
    run_id: "run_1",
    operation_kind: "run.create",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    run: runtimeRun(),
    agent: {
      id: "agent_1",
      status: "active",
      runtime: "local",
    },
    canonical_projection: { runId: "run_1", projection: "canonical" },
  };
}

function agentCommitRequest() {
  return {
    schema_version: "ioi.runtime_agent_state_commit.v1",
    agent_id: "agent_1",
    operation_kind: "agent.create",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    agent: {
      id: "agent_1",
      status: "active",
      runtime: "local",
      updated_at: "2026-06-06T00:00:00.000Z",
      receipt_refs: ["receipt_agent"],
    },
  };
}

function memoryCommitRequest() {
  return {
    schema_version: "ioi.runtime_memory_state_commit.v1",
    memory_state_kind: "record",
    state_id: "memory_1",
    operation_kind: "memory.write",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    payload: {
      schemaVersion: "ioi.agent-runtime.memory.v1",
      id: "memory_1",
      object: "ioi.agent_memory_record",
      fact: "Remember the launch checklist.",
      threadId: "thread_1",
      agentId: "agent_1",
      receipt_refs: ["receipt_memory"],
    },
  };
}

function subagentCommitRequest() {
  return {
    schema_version: "ioi.runtime_subagent_state_commit.v1",
    subagent_id: "subagent_1",
    operation_kind: "subagent.wait",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    subagent: {
      subagent_id: "subagent_1",
      parent_thread_id: "thread_1",
      agent_id: "agent_1",
      lifecycle_status: "completed",
      updated_at: "2026-06-06T00:00:00.000Z",
      receipt_refs: ["receipt_subagent"],
    },
  };
}

function artifactCommitRequest() {
  return {
    schema_version: "ioi.runtime_artifact_state_commit.v1",
    artifact_id: "artifact_1",
    operation_kind: "artifact.coding_tool_draft",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    artifact: {
      schema_version: "ioi.runtime.coding-tool-artifact.v1",
      id: "artifact_1",
      thread_id: "thread_1",
      tool_name: "file.read",
      tool_call_id: "tool_call_1",
      channel: "stdout",
      media_type: "text/plain",
      receipt_id: "receipt_artifact",
      content: "hello",
      content_bytes: 5,
      content_hash: "sha256:content",
    },
  };
}

function modelMountRecordCommitRequest() {
  return {
    schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
    record_dir: "provider-health",
    record_id: "health.provider_openai",
    operation_kind: "model_mount.provider_health.write",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    record: {
      id: "health.provider_openai",
      provider_id: "provider.openai",
      status: "available",
      checked_at: "2026-06-04T00:00:00.000Z",
      receipt_id: "receipt_provider_health",
      evidence_refs: ["provider_http_health"],
    },
  };
}

function modelMountReceiptCommitRequest() {
  return {
    schema_version: "ioi.runtime_model_mount_receipt_state_commit.v1",
    receipt_id: "receipt_model_invocation",
    operation_kind: "model_mount.receipt.write",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    receipt: {
      id: "receipt_model_invocation",
      kind: "model_invocation",
      redaction: "redacted",
      evidenceRefs: ["rust_receipt_binder_core", "rust_agentgres_admission"],
      details: {
        model_mount_agentgres_operation_ref: "agentgres://model-mounting/accepted-receipts/op_1",
      },
    },
  };
}

function codingToolResultEventAdmissionRequest() {
  return {
    event: {
      event_stream_id: "thread_1:events",
      thread_id: "thread_1",
      turn_id: "turn_1",
      item_id: "turn_1:item:coding-tool:workspace.status:abc",
      idempotency_key: "thread:thread_1:coding-tool:tool_1",
      source: "runtime_auto",
      source_event_kind: "coding_tool.workspace.status",
      event_kind: "tool.completed",
      status: "completed",
      actor: "runtime",
      workspace_root: "/tmp/workspace",
      component_kind: "coding_tool",
      tool_call_id: "tool_1",
      receipt_refs: ["receipt_tool"],
      artifact_refs: [],
      payload_schema_version: "ioi.runtime.coding-tool-result.v1",
      payload_summary: {
        schema_version: "ioi.runtime.coding-tool-result.v1",
        event_kind: "CodingToolResult",
        tool_name: "workspace.status",
        tool_call_id: "tool_1",
        status: "completed",
        receipt_refs: ["receipt_tool"],
      },
    },
    latest_seq: 4,
    expected_head: "agentgres://runtime-events/thread_1_events/head/4",
  };
}

function codingToolCommandStreamAdmissionRequest() {
  return {
    event_stream_id: "thread_1:events",
    thread_id: "thread_1",
    turn_id: "turn_1",
    tool_id: "test.run",
    tool_call_id: "tool_1",
    workspace_root: "/tmp/workspace",
    workflow_graph_id: "graph_1",
    workflow_node_id: "node_1",
    source: "runtime_auto",
    status: "completed",
    request: { stream_output: true },
    result: { stdout: "ok", stderr: "warn" },
    latest_seq: 5,
    expected_head: "agentgres://runtime-events/thread_1_events/head/5",
    receipt_refs: ["receipt_tool"],
    artifact_refs: ["artifact_tool"],
  };
}

function runtimeThreadEventAdmissionRequest() {
  return {
    event: {
      event_stream_id: "thread_1:events",
      thread_id: "thread_1",
      turn_id: "turn_1",
      event_kind: "thread.message.created",
      event_id: "event_runtime_thread_1",
      seq: 5,
      receipt_refs: ["receipt_thread"],
      payload_refs: ["payload_thread"],
    },
    latest_seq: 4,
    expected_head: "agentgres://runtime-events/thread_1_events/head/4",
  };
}

function runtimeThreadEventProjectionRequest() {
  return {
    projection_kind: "thread.started",
    thread_id: "thread_1",
    event_stream_id: "thread_1:events",
    workspace_root: "/tmp/workspace",
    agent: { id: "agent_1", thread_id: "thread_1", status: "active" },
    runs: [{ id: "run_1", status: "completed" }],
    latest_seq: 4,
    expected_head: "agentgres://runtime-events/thread_1_events/head/4",
    existing_idempotency_keys: [],
  };
}

function runtimeThreadEventReplayRequest() {
  return {
    replay_kind: "stream",
    event_stream_id: "thread_1:events",
    cursor: { since_seq: 4 },
    events: [
      {
        event_id: "event_projected_1",
        event_stream_id: "thread_1:events",
        seq: 5,
        agentgres_operation_ref: "agentgres://runtime-events/thread_1_events/ops/event_projected_1",
        admission_hash: "sha256:admission",
      },
    ],
  };
}

function runtimeThreadTurnProjectionRequest() {
  return {
    projection_kind: "thread_turn",
    thread_id: "thread_1",
    turn_id: "turn_1",
    events: [{ event_id: "event_turn_1", seq: 1 }],
  };
}

function createCore(calls, responseForRequest) {
  return new RuntimeAgentgresAdmissionCore({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return responseForRequest(request);
    },
  });
}

function assertCommandEnvelope(request, operation, backend) {
  assert.equal(request.schema_version, RUNTIME_AGENTGRES_CORE_SCHEMA_VERSION);
  assert.equal(request.operation, operation);
  assert.equal(request.backend, backend);
}

test("runtime Agentgres core admits coding-tool result events through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_coding_tool_result_event_admission_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: true,
    event: { event_id: "event_coding_tool_1", seq: 5 },
    event_id: "event_coding_tool_1",
    admission_hash: "sha256:admission",
  }));

  const result = core.admitCodingToolResultEvent(codingToolResultEventAdmissionRequest());

  assertCommandEnvelope(calls[0].request, "admit_coding_tool_result_event", RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(result.event.event_id, "event_coding_tool_1");
});

test("runtime Agentgres core admits runtime thread events through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_runtime_thread_event_admission_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: true,
    event: { event_id: "event_runtime_thread_1", seq: 5 },
    event_id: "event_runtime_thread_1",
    admission_hash: "sha256:admission",
  }));

  const result = core.admitRuntimeThreadEvent(runtimeThreadEventAdmissionRequest());

  assertCommandEnvelope(calls[0].request, "admit_runtime_thread_event", RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(calls[0].request.request.schema_version, RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION);
  assert.equal(result.event.event_id, "event_runtime_thread_1");
});

test("runtime Agentgres core projects runtime thread events through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_runtime_thread_event_projection_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: true,
    events: [{ event_id: "event_projected_1", seq: 5 }],
    admissions: [{ event_id: "event_projected_1" }],
    event_count: 1,
    projection_hash: "sha256:projection",
  }));

  const result = core.projectRuntimeThreadEvents(runtimeThreadEventProjectionRequest());

  assertCommandEnvelope(calls[0].request, "project_runtime_thread_events", RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(calls[0].request.request.schema_version, RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION);
  assert.equal(result.events[0].event_id, "event_projected_1");
});

test("runtime Agentgres core replays runtime thread events through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_runtime_thread_event_replay_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: true,
    events: [{ event_id: "event_projected_1", seq: 5 }],
    event_count: 1,
    replay_hash: "sha256:replay",
  }));

  const result = core.projectRuntimeThreadEventReplay(runtimeThreadEventReplayRequest());

  assertCommandEnvelope(calls[0].request, "project_runtime_thread_event_replay", RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(calls[0].request.request.schema_version, RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION);
  assert.equal(result.events[0].event_id, "event_projected_1");
});

test("runtime Agentgres core projects runtime thread and turn records through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_runtime_thread_turn_projection_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: true,
    record: { thread_id: "thread_1", turn_id: "turn_1" },
    projection_hash: "sha256:turn-projection",
  }));

  const result = core.projectRuntimeThreadTurnProjection(runtimeThreadTurnProjectionRequest());

  assertCommandEnvelope(calls[0].request, "project_runtime_thread_turn_projection", RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(calls[0].request.request.schema_version, RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION);
  assert.equal(result.record.turn_id, "turn_1");
});

test("runtime Agentgres core admits coding-tool command-stream events through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_coding_tool_command_stream_admission_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: true,
    events: [{ event_id: "event_stream_1" }, { event_id: "event_stream_2" }],
    event_count: 2,
    admission_hash: "sha256:stream-admission",
  }));

  const result = core.admitCodingToolCommandStreamEvents(codingToolCommandStreamAdmissionRequest());

  assertCommandEnvelope(calls[0].request, "admit_coding_tool_command_stream_events", RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(result.events[0].event_id, "event_stream_1");
});

test("runtime Agentgres core sends runtime run-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_agentgres_runtime_run_state_commit_command",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create",
    commit_hash: "sha256:commit",
    written_records: [{ record_path: "runs/run_1.json" }],
  }));

  const result = core.commitRuntimeRunState("/tmp/ioi-state", commitRequest());

  assertCommandEnvelope(calls[0].request, "commit_runtime_run_state", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/tmp/ioi-state");
  assert.equal(calls[0].request.request.agent.id, "agent_1");
  assert.equal(result.commit_hash, "sha256:commit");
});

test("runtime Agentgres core sends storage write admission through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_agentgres_storage_write_admission_command",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    admission_hash: "sha256:storage-admission",
  }));

  const result = core.admitStorageBackendWrite(storageWriteRequest());

  assertCommandEnvelope(calls[0].request, "admit_storage_backend_write", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.object_ref, storageWriteRequest().object_ref);
  assert.equal(result.admission_hash, "sha256:storage-admission");
});

test("runtime Agentgres core sends runtime agent-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    source: "rust_agentgres_runtime_agent_state_commit_command",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    agent_id: "agent_1",
    commit_hash: "sha256:agent-commit",
    written_record: { record_path: "agents/agent_1.json" },
  }));

  const result = core.commitRuntimeAgentState("/tmp/ioi-state", agentCommitRequest());

  assertCommandEnvelope(calls[0].request, "commit_runtime_agent_state", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.agent_id, "agent_1");
  assert.equal(result.written_record.record_path, "agents/agent_1.json");
});

test("runtime Agentgres core sends runtime memory-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({ state_id: "memory_1", commit_hash: "sha256:memory-commit" }));

  const result = core.commitRuntimeMemoryState("/tmp/ioi-state", memoryCommitRequest());

  assertCommandEnvelope(calls[0].request, "commit_runtime_memory_state", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.state_id, "memory_1");
  assert.equal(result.commit_hash, "sha256:memory-commit");
});

test("runtime Agentgres core sends runtime subagent-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({ subagent_id: "subagent_1", commit_hash: "sha256:subagent-commit" }));

  const result = core.commitRuntimeSubagentState("/tmp/ioi-state", subagentCommitRequest());

  assertCommandEnvelope(calls[0].request, "commit_runtime_subagent_state", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.subagent_id, "subagent_1");
  assert.equal(result.commit_hash, "sha256:subagent-commit");
});

test("runtime Agentgres core sends runtime artifact-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({ artifact_id: "artifact_1", commit_hash: "sha256:artifact-commit" }));

  const result = core.commitRuntimeArtifactState("/tmp/ioi-state", artifactCommitRequest());

  assertCommandEnvelope(calls[0].request, "commit_runtime_artifact_state", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.artifact_id, "artifact_1");
  assert.equal(result.commit_hash, "sha256:artifact-commit");
});

test("runtime Agentgres core sends runtime model-mount record-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    record_dir: "provider-health",
    record_id: "health.provider_openai",
    commit_hash: "sha256:model-mount-record-commit",
  }));

  const result = core.commitRuntimeModelMountRecordState("/tmp/ioi-state", modelMountRecordCommitRequest());

  assertCommandEnvelope(calls[0].request, "commit_runtime_model_mount_record_state", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.record_dir, "provider-health");
  assert.equal(result.record_id, "health.provider_openai");
});

test("runtime Agentgres core sends runtime model-mount receipt-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const core = createCore(calls, () => ({
    receipt_id: "receipt_model_invocation",
    commit_hash: "sha256:model-mount-receipt-commit",
  }));

  const result = core.commitRuntimeModelMountReceiptState("/tmp/ioi-state", modelMountReceiptCommitRequest());

  assertCommandEnvelope(calls[0].request, "commit_runtime_model_mount_receipt_state", RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.receipt_id, "receipt_model_invocation");
  assert.equal(result.receipt_id, "receipt_model_invocation");
});

test("runtime Agentgres core returns Rust envelopes without JS normalization", () => {
  const rustEnvelope = {
    record: {},
    rust_only_field: "kept",
  };
  const core = createCore([], () => rustEnvelope);

  assert.deepEqual(core.admitStorageBackendWrite({}), rustEnvelope);
  assert.equal(Object.hasOwn(core.admitStorageBackendWrite({}), "source"), false);
  assert.equal(Object.hasOwn(core.admitStorageBackendWrite({}), "backend"), false);
  assert.equal(Object.hasOwn(core.admitStorageBackendWrite({}), "written_records"), false);
});

test("runtime Agentgres core uses daemon-level direct invoker", () => {
  const calls = [];
  const core = createRuntimeAgentgresAdmissionCore({
    daemonCoreInvoker(request) {
      calls.push(request);
      return { ok: true, result: { admitted: true, request_operation: request.operation } };
    },
  });

  const result = core.admitStorageBackendWrite(storageWriteRequest());

  assert.equal(calls.length, 1);
  assert.equal(result.request_operation, "admit_storage_backend_write");
});

test("runtime Agentgres core rejects retired compatibility options", () => {
  for (const options of [
    { command: "ioi-runtime-daemon-core" },
    { args: ["--json"] },
    { env: { IOI_RUNTIME_AGENTGRES_COMMAND: "ioi-runtime-daemon-core" } },
  ]) {
    assert.throws(
      () => createRuntimeAgentgresAdmissionCore(options),
      (error) =>
        error instanceof RuntimeAgentgresAdmissionCoreError &&
        error.code === "runtime_agentgres_admission_core_compatibility_option_retired",
    );
  }
});

test("runtime Agentgres core fails closed without direct invoker", () => {
  const core = createRuntimeAgentgresAdmissionCore();
  assert.throws(
    () => core.admitStorageBackendWrite(storageWriteRequest()),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionCoreError &&
      error.code === "runtime_agentgres_admission_core_direct_invoker_unconfigured",
  );
});

test("runtime Agentgres core surfaces Rust daemon-core rejection", () => {
  const core = createRuntimeAgentgresAdmissionCore({
    daemonCoreInvoker() {
      return {
        ok: false,
        error: {
          code: "agentgres_expected_head_required",
          message: "expected head is required",
        },
      };
    },
  });

  assert.throws(
    () => core.commitRuntimeRunState("/tmp/ioi-state", commitRequest()),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionCoreError &&
      error.code === "agentgres_expected_head_required",
  );
});
