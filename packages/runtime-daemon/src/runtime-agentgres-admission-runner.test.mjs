import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
  RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
  RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
  RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
  RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUST_AGENTGRES_STORAGE_BACKEND,
  RUST_RUNTIME_AGENTGRES_BACKEND,
  RuntimeAgentgresAdmissionRunnerError,
  RustRuntimeAgentgresAdmissionRunner,
  createRuntimeAgentgresAdmissionRunnerFromEnv,
  normalizeCodingToolCommandStreamAdmissionBridgeResult,
  normalizeCodingToolResultEventAdmissionBridgeResult,
  normalizeRuntimeAgentStateCommitBridgeResult,
  normalizeRuntimeArtifactStateCommitBridgeResult,
  normalizeRuntimeThreadEventAdmissionBridgeResult,
  normalizeRuntimeThreadEventProjectionBridgeResult,
  normalizeRuntimeThreadEventReplayBridgeResult,
  normalizeRuntimeThreadTurnProjectionBridgeResult,
  normalizeRuntimeMemoryStateCommitBridgeResult,
  normalizeRuntimeModelMountReceiptStateCommitBridgeResult,
  normalizeRuntimeModelMountRecordStateCommitBridgeResult,
  normalizeRuntimeRunStateCommitBridgeResult,
  normalizeRuntimeSubagentStateCommitBridgeResult,
  normalizeStorageBackendWriteBridgeResult,
} from "./runtime-agentgres-admission-runner.mjs";

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
    trace: {
      traceBundleId: "trace_bundle_1",
      taskState: { state: "done" },
      postconditions: [],
      semanticImpact: { impact: "local" },
      stopCondition: { reason: "done" },
      scorecard: { score: 1 },
      qualityLedger: { entries: [] },
    },
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
        model_mount_receipt_binding_ref: "sha256:binding",
        model_mount_accepted_receipt_append_hash: "sha256:append",
        model_mount_agentgres_operation_ref: "agentgres://model-mounting/accepted-receipts/op_1",
        model_mount_agentgres_admission_hash: "sha256:agentgres",
      },
    },
  };
}

function createRunner(calls, responseForRequest) {
  return new RustRuntimeAgentgresAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return responseForRequest(request);
    },
  });
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
      item_id: "turn_1:item:operator:mode",
      idempotency_key: "thread:thread_1:mode:review",
      source: "operator",
      source_event_kind: "OperatorControl.Mode",
      event_kind: "thread.mode_updated",
      status: "completed",
      actor: "operator",
      payload_schema_version: "ioi.runtime.thread-control.v1",
      payload_summary: {
        event_kind: "ThreadModeUpdated",
        receipt_refs: ["receipt_thread_control"],
      },
      receipt_refs: ["receipt_thread_control"],
      artifact_refs: [],
    },
    latest_seq: 4,
    expected_head: "agentgres://runtime-events/thread_1_events/head/4",
  };
}

function runtimeThreadEventProjectionRequest() {
  return {
    projection_kind: "thread",
    thread_id: "thread_1",
    event_stream_id: "thread_1:events",
    workspace_root: "/workspace",
    agent: {
      agent_id: "agent_1",
      status: "active",
      created_at: "2026-06-12T00:00:00.000Z",
      workspace_root: "/workspace",
      receipt_refs: ["receipt_agent_state"],
      model_route_receipt_id: "receipt_model_route",
    },
    runs: [{
      run_id: "run_1",
      turn_id: "turn_1",
      workspace_root: "/workspace",
      events: [{
        id: "event_run_started",
        type: "run_started",
        run_id: "run_1",
        created_at: "2026-06-12T00:00:01.000Z",
        data: {
          receipt_id: "receipt_run_policy",
        },
      }],
    }],
    latest_seq: 4,
    expected_head: "agentgres://runtime-events/thread_1_events/head/4",
    existing_idempotency_keys: ["thread:thread_1:started"],
  };
}

function runtimeThreadEventReplayRequest() {
  return {
    replay_kind: "turn",
    event_stream_id: "thread_1:events",
    turn_id: "turn_1",
    cursor: { since_seq: 4 },
    events: [{
      event_stream_id: "thread_1:events",
      thread_id: "thread_1",
      turn_id: "turn_1",
      event_id: "event_projected_1",
      seq: 5,
      event_kind: "turn.started",
      idempotency_key: "run:run_1:event:event_run_started",
      agentgres_operation_ref: "agentgres://runtime-events/thread_1_events/operations/event_projected_1",
      state_root_after: "sha256:after",
      resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
      projection_watermark: "runtime-events:thread_1:events:5",
      receipt_refs: ["receipt_run_policy"],
      payload_refs: ["payload://runtime-events/thread_1_events/events/event_projected_1"],
      artifact_refs: [],
    }],
  };
}

function runtimeThreadTurnProjectionRequest() {
  return {
    projection_kind: "thread",
    thread_schema_version: "ioi.runtime.thread.v1",
    thread_id: "thread_1",
    event_stream_id: "thread_1:events",
    session_id: "session:agent_1",
    fixture_profile: "fixture",
    runtime_profile: "runtime_service",
    agent: {
      agent_id: "agent_1",
      workspace_root: "/workspace",
      status: "active",
      model_id: "qwen",
      created_at: "2026-06-12T00:00:00.000Z",
      updated_at: "2026-06-12T00:00:01.000Z",
    },
    runs: [{
      run_id: "run_1",
      agent_id: "agent_1",
      objective: "Latest",
      status: "completed",
      created_at: "2026-06-12T00:00:01.000Z",
      updated_at: "2026-06-12T00:00:02.000Z",
    }],
    runtime_controls: {
      mode: "agent",
      approval_mode: "suggest",
      model: {},
    },
    usage_telemetry: { scope: "thread" },
    memory_count: 2,
    latest_seq: 5,
  };
}

test("runtime Agentgres runner admits coding-tool result events through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "rust_coding_tool_result_event_admission_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: true,
    record: {
      schema_version: "ioi.runtime.coding-tool-result-event-admission.v1",
      status: "admitted",
      operation_kind: "runtime.coding_tool_result_event",
      event_id: "event_coding_tool_1",
      seq: 5,
      operation_ref: "agentgres://runtime-events/thread_1_events/operations/event_coding_tool_1",
      state_root_before: "sha256:before",
      state_root_after: "sha256:after",
      resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
      projection_watermark: "runtime-events:thread_1:events:5",
      payload_refs: ["payload://runtime-events/thread_1_events/events/event_coding_tool_1"],
      receipt_refs: ["receipt_tool"],
      artifact_refs: [],
      rollback_refs: [],
      storage_admission: { admission_hash: "sha256:storage" },
      admission_hash: "sha256:admission",
      event: {
        ...request.request.event,
        event_id: "event_coding_tool_1",
        seq: 5,
        state_root_after: "sha256:after",
        resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
        payload_refs: ["payload://runtime-events/thread_1_events/events/event_coding_tool_1"],
      },
    },
  }));

  const result = runner.admitCodingToolResultEvent(codingToolResultEventAdmissionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_coding_tool_result_event");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.request.event.tool_call_id, "tool_1");
  assert.equal(calls[0].request.request.latest_seq, 4);
  assert.equal(result.admitted, true);
  assert.equal(result.event.event_id, "event_coding_tool_1");
  assert.equal(result.seq, 5);
  assert.equal(result.state_root_after, "sha256:after");
  assert.deepEqual(result.receipt_refs, ["receipt_tool"]);
  assert.equal(result.admission_hash, "sha256:admission");
});

test("coding-tool result-event admission normalizer exposes only Rust-returned event truth", () => {
  const result = normalizeCodingToolResultEventAdmissionBridgeResult({
    record: {
      status: "admitted",
      event_id: "event_record",
      seq: 7,
      receipt_refs: ["receipt_record"],
      event: {
        event_stream_id: "thread_1:events",
        event_id: "event_record",
        seq: 7,
        idempotency_key: "idem",
      },
    },
    admission_hash: "sha256:admission",
  });

  assert.equal(result.admitted, true);
  assert.equal(result.event.event_id, "event_record");
  assert.equal(result.seq, 7);
  assert.deepEqual(result.receipt_refs, ["receipt_record"]);
  assert.equal(result.admission_hash, "sha256:admission");
});

test("runtime Agentgres runner admits runtime thread events through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "rust_runtime_thread_event_admission_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: true,
    record: {
      schema_version: "ioi.runtime.thread-event-admission.v1",
      status: "admitted",
      operation_kind: "runtime.thread_event",
      event_id: "event_runtime_thread_1",
      seq: 5,
      operation_ref: "agentgres://runtime-events/thread_1_events/operations/event_runtime_thread_1",
      state_root_before: "sha256:before",
      state_root_after: "sha256:after",
      resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
      projection_watermark: "runtime-events:thread_1:events:5",
      payload_refs: ["payload://runtime-events/thread_1_events/events/event_runtime_thread_1"],
      receipt_refs: ["receipt_thread_control"],
      artifact_refs: [],
      rollback_refs: [],
      storage_admission: { admission_hash: "sha256:storage" },
      admission_hash: "sha256:admission",
      event: {
        ...request.request.event,
        event_id: "event_runtime_thread_1",
        seq: 5,
        state_root_after: "sha256:after",
        resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
        payload_refs: ["payload://runtime-events/thread_1_events/events/event_runtime_thread_1"],
      },
    },
  }));

  const result = runner.admitRuntimeThreadEvent(runtimeThreadEventAdmissionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_runtime_thread_event");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.request.event.event_kind, "thread.mode_updated");
  assert.equal(calls[0].request.request.latest_seq, 4);
  assert.equal(result.admitted, true);
  assert.equal(result.event.event_id, "event_runtime_thread_1");
  assert.equal(result.seq, 5);
  assert.equal(result.state_root_after, "sha256:after");
  assert.deepEqual(result.receipt_refs, ["receipt_thread_control"]);
  assert.equal(result.admission_hash, "sha256:admission");
});

test("runtime thread event admission normalizer exposes only Rust-returned event truth", () => {
  const result = normalizeRuntimeThreadEventAdmissionBridgeResult({
    record: {
      status: "admitted",
      event_id: "event_record",
      seq: 7,
      receipt_refs: ["receipt_record"],
      event: {
        event_stream_id: "thread_1:events",
        event_id: "event_record",
        seq: 7,
        idempotency_key: "idem",
      },
    },
    admission_hash: "sha256:admission",
  });

  assert.equal(result.source, "rust_runtime_thread_event_admission_command");
  assert.equal(result.admitted, true);
  assert.equal(result.event.event_id, "event_record");
  assert.equal(result.seq, 7);
  assert.deepEqual(result.receipt_refs, ["receipt_record"]);
  assert.equal(result.admission_hash, "sha256:admission");
  assert.equal(Object.hasOwn(result.event, "eventId"), false);
});

test("runtime Agentgres runner projects runtime thread events through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "rust_runtime_thread_event_projection_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: true,
    record: {
      schema_version: "ioi.runtime.thread-event-projection.v1",
      status: "projected",
      operation_kind: "runtime.thread_event_projection",
      projection_kind: "thread",
      event_count: 2,
      skipped_count: 1,
      resulting_seq: 6,
      resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
      state_root_after: "sha256:after",
      projection_watermark: "runtime-events:thread_1:events:6",
      receipt_refs: ["receipt_agent_state", "receipt_run_policy"],
      artifact_refs: [],
      payload_refs: ["payload://runtime-events/thread_1_events/events/event_projected_1"],
      projection_hash: "sha256:projection",
      admissions: [{ event_id: "event_projected_1" }],
      events: [{
        event_stream_id: "thread_1:events",
        event_id: "event_projected_1",
        seq: 5,
        event_kind: "turn.started",
        idempotency_key: "run:run_1:event:event_run_started",
      }],
    },
  }));

  const result = runner.projectRuntimeThreadEvents(runtimeThreadEventProjectionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "project_runtime_thread_events");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.request.projection_kind, "thread");
  assert.deepEqual(calls[0].request.request.existing_idempotency_keys, [
    "thread:thread_1:started",
  ]);
  assert.equal(result.projected, true);
  assert.equal(result.event_count, 2);
  assert.equal(result.skipped_count, 1);
  assert.equal(result.events[0].event_id, "event_projected_1");
  assert.equal(result.projection_hash, "sha256:projection");
});

test("runtime thread event projection normalizer exposes only Rust-returned projection truth", () => {
  const result = normalizeRuntimeThreadEventProjectionBridgeResult({
    record: {
      status: "projected",
      projection_kind: "run",
      event_count: 1,
      skipped_count: 0,
      receipt_refs: ["receipt_run_policy"],
      events: [{
        event_stream_id: "thread_1:events",
        event_id: "event_projected",
        seq: 9,
        event_kind: "turn.started",
      }],
    },
    projection_hash: "sha256:projection",
  });

  assert.equal(result.source, "rust_runtime_thread_event_projection_command");
  assert.equal(result.projected, true);
  assert.equal(result.projection_kind, "run");
  assert.equal(result.event_count, 1);
  assert.equal(result.events[0].event_id, "event_projected");
  assert.deepEqual(result.receipt_refs, ["receipt_run_policy"]);
  assert.equal(result.projection_hash, "sha256:projection");
  assert.equal(Object.hasOwn(result.events[0], "eventId"), false);
});

test("runtime Agentgres runner replays runtime thread events through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "rust_runtime_thread_event_replay_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: true,
    record: {
      schema_version: "ioi.runtime.thread-event-replay.v1",
      status: "projected",
      operation_kind: "runtime.thread_event_replay",
      replay_kind: "turn",
      event_count: 1,
      latest_seq: 5,
      cursor_seq: 4,
      resulting_seq: 5,
      resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
      state_root_after: "sha256:after",
      projection_watermark: "runtime-events:thread_1:events:5",
      receipt_refs: ["receipt_run_policy"],
      artifact_refs: [],
      payload_refs: ["payload://runtime-events/thread_1_events/events/event_projected_1"],
      replay_hash: "sha256:replay",
      events: request.request.events,
    },
  }));

  const result = runner.projectRuntimeThreadEventReplay(runtimeThreadEventReplayRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "project_runtime_thread_event_replay");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.request.replay_kind, "turn");
  assert.deepEqual(calls[0].request.request.cursor, { since_seq: 4 });
  assert.equal(result.projected, true);
  assert.equal(result.events[0].event_id, "event_projected_1");
  assert.equal(result.cursor_seq, 4);
  assert.deepEqual(result.receipt_refs, ["receipt_run_policy"]);
  assert.equal(result.replay_hash, "sha256:replay");
});

test("runtime thread event replay normalizer exposes only Rust-returned event truth", () => {
  const result = normalizeRuntimeThreadEventReplayBridgeResult({
    record: {
      status: "projected",
      replay_kind: "stream",
      event_count: 1,
      latest_seq: 7,
      cursor_seq: 6,
      receipt_refs: ["receipt_record"],
      replay_hash: "sha256:replay",
      events: [{
        event_stream_id: "thread_1:events",
        event_id: "event_record",
        seq: 7,
        idempotency_key: "idem",
      }],
    },
  });

  assert.equal(result.source, "rust_runtime_thread_event_replay_command");
  assert.equal(result.projected, true);
  assert.equal(result.replay_kind, "stream");
  assert.equal(result.events[0].event_id, "event_record");
  assert.equal(result.cursor_seq, 6);
  assert.deepEqual(result.receipt_refs, ["receipt_record"]);
  assert.equal(result.replay_hash, "sha256:replay");
  assert.equal(Object.hasOwn(result.events[0], "eventId"), false);
});

test("runtime Agentgres runner projects runtime thread and turn records through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "rust_runtime_thread_turn_projection_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    projected: true,
    projection: {
      schema_version: "ioi.runtime.thread-turn-projection.v1",
      status: "projected",
      operation_kind: "runtime.thread_turn_projection",
      projection_kind: "thread",
      thread_id: "thread_1",
      event_count: 0,
      latest_seq: 5,
      projection_hash: "sha256:projection",
      record: {
        schema_version: "ioi.runtime.thread.v1",
        thread_id: "thread_1",
        title: "Latest",
      },
    },
  }));

  const result = runner.projectRuntimeThreadTurnProjection(runtimeThreadTurnProjectionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "project_runtime_thread_turn_projection");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.request.projection_kind, "thread");
  assert.equal(calls[0].request.request.thread_id, "thread_1");
  assert.equal(result.projected, true);
  assert.equal(result.record.thread_id, "thread_1");
  assert.equal(result.projection_kind, "thread");
  assert.equal(result.projection_hash, "sha256:projection");
});

test("runtime thread and turn projection normalizer exposes only Rust-returned record truth", () => {
  const result = normalizeRuntimeThreadTurnProjectionBridgeResult({
    projection: {
      status: "projected",
      operation_kind: "runtime.thread_turn_projection",
      projection_kind: "turn",
      thread_id: "thread_1",
      turn_id: "turn_1",
      latest_seq: 7,
      projection_hash: "sha256:projection",
      record: {
        schema_version: "ioi.runtime.turn.v1",
        turn_id: "turn_1",
        seq_end: 7,
      },
    },
  });

  assert.equal(result.source, "rust_runtime_thread_turn_projection_command");
  assert.equal(result.projected, true);
  assert.equal(result.projection_kind, "turn");
  assert.equal(result.record.turn_id, "turn_1");
  assert.equal(result.latest_seq, 7);
  assert.equal(result.projection_hash, "sha256:projection");
  assert.equal(Object.hasOwn(result.record, "turnId"), false);
});

test("runtime Agentgres runner admits coding-tool command-stream events through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "rust_coding_tool_command_stream_admission_command",
    backend: RUST_RUNTIME_AGENTGRES_BACKEND,
    admitted: true,
    record: {
      schema_version: "ioi.runtime.coding-tool-command-stream-admission.v1",
      status: "admitted",
      operation_kind: "runtime.coding_tool_command_stream",
      event_count: 2,
      state_root_before: "sha256:before",
      state_root_after: "sha256:after",
      resulting_head: "agentgres://runtime-events/thread_1_events/head/after",
      projection_watermark: "runtime-events:thread_1:events:7",
      payload_refs: ["payload://runtime-events/thread_1_events/command-stream/event_stream_1"],
      receipt_refs: ["receipt_tool"],
      artifact_refs: ["artifact_tool"],
      storage_admissions: [{ admission_hash: "sha256:storage" }],
      admission_hash: "sha256:admission",
      events: [
        {
          event_stream_id: request.request.event_stream_id,
          event_kind: "artifact.command_stream",
          event_id: "event_stream_1",
          seq: 6,
          idempotency_key: "thread:thread_1:coding-tool-command-stream:tool_1:0",
          state_root_after: "sha256:mid",
        },
        {
          event_stream_id: request.request.event_stream_id,
          event_kind: "artifact.command_stream",
          event_id: "event_stream_2",
          seq: 7,
          idempotency_key: "thread:thread_1:coding-tool-command-stream:tool_1:1",
          state_root_after: "sha256:after",
        },
      ],
    },
  }));

  const result = runner.admitCodingToolCommandStreamEvents(codingToolCommandStreamAdmissionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_coding_tool_command_stream_events");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(
    calls[0].request.request.schema_version,
    CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.request.tool_call_id, "tool_1");
  assert.equal(calls[0].request.request.latest_seq, 5);
  assert.equal(result.admitted, true);
  assert.equal(result.events.length, 2);
  assert.equal(result.events[0].event_kind, "artifact.command_stream");
  assert.equal(result.event_count, 2);
  assert.equal(result.state_root_after, "sha256:after");
  assert.deepEqual(result.receipt_refs, ["receipt_tool"]);
  assert.equal(result.admission_hash, "sha256:admission");
});

test("coding-tool command-stream normalizer exposes only Rust-returned events", () => {
  const result = normalizeCodingToolCommandStreamAdmissionBridgeResult({
    record: {
      status: "admitted",
      event_count: 1,
      receipt_refs: ["receipt_record"],
      events: [
        {
          event_stream_id: "thread_1:events",
          event_id: "event_record",
          seq: 8,
          idempotency_key: "idem",
        },
      ],
    },
    admission_hash: "sha256:admission",
  });

  assert.equal(result.admitted, true);
  assert.equal(result.events[0].event_id, "event_record");
  assert.equal(result.event_count, 1);
  assert.deepEqual(result.receipt_refs, ["receipt_record"]);
  assert.equal(result.admission_hash, "sha256:admission");
});

test("runtime Agentgres runner sends runtime run-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      schema_version: "ioi.runtime_run_state_commit.v1",
      run_id: request.request.run_id,
      transition: {
        operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
        state_root_after: "sha256:after",
        resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
        transition_hash: "sha256:transition",
      },
      persistence: {
        materialization: {
          materialization_hash: "sha256:materialization",
        },
        storage_write_set: {
          write_set_hash: "sha256:write-set",
          records: [{ record_path: "runs/run_1.json" }],
        },
        persistence_hash: "sha256:persistence",
      },
      commit_hash: "sha256:commit",
    },
    operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
    state_root_after: "sha256:after",
    resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
    transition_hash: "sha256:transition",
    materialization_hash: "sha256:materialization",
    write_set_hash: "sha256:write-set",
    persistence_hash: "sha256:persistence",
    commit_hash: "sha256:commit",
    written_records: [{ record_path: "runs/run_1.json" }],
    evidence_refs: ["rust_agentgres_runtime_run_state_commit"],
  }));

  const result = runner.commitRuntimeRunState("/runtime-state", commitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_run_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.run_id, "run_1");
  assert.equal(calls[0].request.request.agent.id, "agent_1");
  assert.equal(Object.hasOwn(calls[0].request.request, "expected_heads"), false);
  assert.equal(Object.hasOwn(calls[0].request.request, "state_root_before"), false);
  assert.equal(Object.hasOwn(calls[0].request.request, "receipt_refs"), false);
  assert.equal(result.state_root_after, "sha256:after");
  assert.equal(result.resulting_head, "agentgres://runtime-state/runs/run_1/head/abcd");
  assert.equal(result.commit_hash, "sha256:commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_run_state_commit"]);
});

test("runtime Agentgres runner sends storage write admission through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, (request) => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      ...request.request,
      admission_hash: "sha256:storage-admission",
    },
    admission_hash: "sha256:storage-admission",
    evidence_refs: ["rust_agentgres_storage_write_admission"],
  }));

  const result = runner.admitStorageBackendWrite(storageWriteRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_storage_backend_write");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.storage_backend_ref, "storage://runtime-agentgres/local-json");
  assert.equal(result.admission_hash, "sha256:storage-admission");
  assert.equal(result.object_ref, "agentgres://runtime-state/runs/run_1/records/runs/run_1.json");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_storage_write_admission"]);
});

test("runtime Agentgres runner does not synthesize Rust-owned refs or evidence", () => {
  const storageWrite = normalizeStorageBackendWriteBridgeResult({ record: {} });
  assert.equal(storageWrite.artifact_refs, null);
  assert.equal(storageWrite.payload_refs, null);
  assert.equal(storageWrite.receipt_refs, null);
  assert.equal(storageWrite.evidence_refs, null);

  const runtimeRun = normalizeRuntimeRunStateCommitBridgeResult({ record: {} });
  assert.equal(runtimeRun.records, null);
  assert.equal(runtimeRun.written_records, null);
  assert.equal(runtimeRun.evidence_refs, null);

  for (const result of [
    normalizeRuntimeAgentStateCommitBridgeResult({ record: {} }),
    normalizeRuntimeMemoryStateCommitBridgeResult({ record: {} }),
    normalizeRuntimeSubagentStateCommitBridgeResult({ record: {} }),
    normalizeRuntimeArtifactStateCommitBridgeResult({ record: {} }),
    normalizeRuntimeModelMountRecordStateCommitBridgeResult({ record: {} }),
    normalizeRuntimeModelMountReceiptStateCommitBridgeResult({ record: {} }),
  ]) {
    assert.equal(result.payload_refs, null);
    assert.equal(result.receipt_refs, null);
    assert.equal(result.evidence_refs, null);
  }
});

test("runtime Agentgres runner sends runtime agent-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, () => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      schema_version: "ioi.runtime_agent_state_commit.v1",
      agent_id: "agent_1",
      operation_kind: "agent.create",
      storage_backend_ref: "storage://runtime-agentgres/local-json",
      record: {
        record_path: "agents/agent_1.json",
        object_ref: "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json",
        content_hash: "sha256:agent-content",
        payload_refs: ["payload://runtime/agents/agent_1/records/agents/agent_1.json"],
        receipt_refs: ["receipt_agent"],
        admission: {
          admission_hash: "sha256:agent-admission",
        },
      },
      commit_hash: "sha256:agent-commit",
    },
    agent_id: "agent_1",
    object_ref: "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json",
    content_hash: "sha256:agent-content",
    admission_hash: "sha256:agent-admission",
    commit_hash: "sha256:agent-commit",
    written_record: {
      record_path: "agents/agent_1.json",
    },
    evidence_refs: ["rust_agentgres_runtime_agent_state_commit"],
  }));

  const result = runner.commitRuntimeAgentState("/runtime-state", agentCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_agent_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.agent_id, "agent_1");
  assert.equal(result.agent_id, "agent_1");
  assert.equal(result.commit_hash, "sha256:agent-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_agent_state_commit"]);
});

test("runtime Agentgres runner sends runtime memory-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, () => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      schema_version: "ioi.runtime_memory_state_commit.v1",
      memory_state_kind: "record",
      state_id: "memory_1",
      operation_kind: "memory.write",
      storage_backend_ref: "storage://runtime-agentgres/local-json",
      record: {
        record_path: "memory-records/memory_1.json",
        object_ref: "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json",
        content_hash: "sha256:memory-content",
        payload_refs: ["payload://runtime/memory/record/memory_1/records/memory-records/memory_1.json"],
        receipt_refs: ["receipt_memory"],
        admission: {
          admission_hash: "sha256:memory-admission",
        },
      },
      commit_hash: "sha256:memory-commit",
    },
    memory_state_kind: "record",
    state_id: "memory_1",
    object_ref: "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json",
    content_hash: "sha256:memory-content",
    admission_hash: "sha256:memory-admission",
    commit_hash: "sha256:memory-commit",
    written_record: {
      record_path: "memory-records/memory_1.json",
    },
    evidence_refs: ["rust_agentgres_runtime_memory_state_commit"],
  }));

  const result = runner.commitRuntimeMemoryState("/runtime-state", memoryCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_memory_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.memory_state_kind, "record");
  assert.equal(calls[0].request.request.state_id, "memory_1");
  assert.equal(result.state_id, "memory_1");
  assert.equal(result.commit_hash, "sha256:memory-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_memory_state_commit"]);
});

test("runtime Agentgres runner sends runtime subagent-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, () => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      schema_version: "ioi.runtime_subagent_state_commit.v1",
      subagent_id: "subagent_1",
      operation_kind: "subagent.wait",
      storage_backend_ref: "storage://runtime-agentgres/local-json",
      record: {
        record_path: "subagents/subagent_1.json",
        object_ref: "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json",
        content_hash: "sha256:subagent-content",
        payload_refs: ["payload://runtime/subagents/subagent_1/records/subagents/subagent_1.json"],
        receipt_refs: ["receipt_subagent"],
        admission: {
          admission_hash: "sha256:subagent-admission",
        },
      },
      commit_hash: "sha256:subagent-commit",
    },
    subagent_id: "subagent_1",
    object_ref: "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json",
    content_hash: "sha256:subagent-content",
    admission_hash: "sha256:subagent-admission",
    commit_hash: "sha256:subagent-commit",
    written_record: {
      record_path: "subagents/subagent_1.json",
    },
    evidence_refs: ["rust_agentgres_runtime_subagent_state_commit"],
  }));

  const result = runner.commitRuntimeSubagentState("/runtime-state", subagentCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_subagent_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.subagent_id, "subagent_1");
  assert.equal(result.subagent_id, "subagent_1");
  assert.equal(result.commit_hash, "sha256:subagent-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_subagent_state_commit"]);
});

test("runtime Agentgres runner sends runtime artifact-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, () => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      schema_version: "ioi.runtime_artifact_state_commit.v1",
      artifact_id: "artifact_1",
      operation_kind: "artifact.coding_tool_draft",
      storage_backend_ref: "storage://runtime-agentgres/local-json",
      record: {
        record_path: "artifacts/artifact_1.json",
        object_ref: "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json",
        content_hash: "sha256:artifact-content",
        payload_refs: ["payload://runtime/artifacts/artifact_1/records/artifacts/artifact_1.json"],
        receipt_refs: ["receipt_artifact"],
        admission: {
          admission_hash: "sha256:artifact-admission",
        },
      },
      commit_hash: "sha256:artifact-commit",
    },
    artifact_id: "artifact_1",
    object_ref: "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json",
    content_hash: "sha256:artifact-content",
    admission_hash: "sha256:artifact-admission",
    commit_hash: "sha256:artifact-commit",
    written_record: {
      record_path: "artifacts/artifact_1.json",
    },
    evidence_refs: ["rust_agentgres_runtime_artifact_state_commit"],
  }));

  const result = runner.commitRuntimeArtifactState("/runtime-state", artifactCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_artifact_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.artifact_id, "artifact_1");
  assert.equal(result.artifact_id, "artifact_1");
  assert.equal(result.commit_hash, "sha256:artifact-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_artifact_state_commit"]);
});

test("runtime Agentgres runner sends runtime model-mount record-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, () => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
      record_dir: "provider-health",
      record_id: "health.provider_openai",
      operation_kind: "model_mount.provider_health.write",
      storage_backend_ref: "storage://runtime-agentgres/local-json",
      record: {
        record_path: "provider-health/health.provider_openai.json",
        object_ref: "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json",
        content_hash: "sha256:model-mount-record-content",
        payload_refs: ["payload://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json"],
        receipt_refs: ["receipt_provider_health"],
        admission: {
          admission_hash: "sha256:model-mount-record-admission",
        },
      },
      commit_hash: "sha256:model-mount-record-commit",
    },
    record_dir: "provider-health",
    record_id: "health.provider_openai",
    object_ref: "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json",
    content_hash: "sha256:model-mount-record-content",
    admission_hash: "sha256:model-mount-record-admission",
    commit_hash: "sha256:model-mount-record-commit",
    written_record: {
      record_path: "provider-health/health.provider_openai.json",
    },
    evidence_refs: ["rust_agentgres_runtime_model_mount_record_state_commit"],
  }));

  const result = runner.commitRuntimeModelMountRecordState("/runtime-state", modelMountRecordCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_model_mount_record_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.record_id, "health.provider_openai");
  assert.equal(result.record_dir, "provider-health");
  assert.equal(result.record_id, "health.provider_openai");
  assert.equal(result.commit_hash, "sha256:model-mount-record-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_model_mount_record_state_commit"]);
});

test("runtime Agentgres runner sends runtime model-mount receipt-state commit through direct daemon-core invoker", () => {
  const calls = [];
  const runner = createRunner(calls, () => ({
    source: "direct_daemon_core_api",
    backend: RUST_AGENTGRES_STORAGE_BACKEND,
    record: {
      schema_version: "ioi.runtime_model_mount_receipt_state_commit.v1",
      receipt_id: "receipt_model_invocation",
      operation_kind: "model_mount.receipt.write",
      storage_backend_ref: "storage://runtime-agentgres/local-json",
      record: {
        record_path: "receipts/receipt_model_invocation.json",
        object_ref:
          "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json",
        content_hash: "sha256:receipt-content",
        payload_refs: [
          "payload://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json",
        ],
        receipt_refs: ["receipt_model_invocation"],
        admission: {
          admission_hash: "sha256:receipt-admission",
        },
      },
      commit_hash: "sha256:receipt-commit",
    },
    receipt_id: "receipt_model_invocation",
    object_ref:
      "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json",
    content_hash: "sha256:receipt-content",
    admission_hash: "sha256:receipt-admission",
    commit_hash: "sha256:receipt-commit",
    written_record: {
      record_path: "receipts/receipt_model_invocation.json",
    },
    evidence_refs: ["rust_agentgres_runtime_model_mount_receipt_state_commit"],
  }));

  const result = runner.commitRuntimeModelMountReceiptState("/runtime-state", modelMountReceiptCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_model_mount_receipt_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.receipt_id, "receipt_model_invocation");
  assert.equal(result.receipt_id, "receipt_model_invocation");
  assert.equal(result.commit_hash, "sha256:receipt-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_model_mount_receipt_state_commit"]);
});

test("runtime Agentgres runner env uses daemon-level direct invoker", () => {
  const calls = [];
  const runner = createRuntimeAgentgresAdmissionRunnerFromEnv({
    IOI_RUNTIME_AGENTGRES_COMMAND_ARGS: "--retired-agentgres",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  }, {
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        source: "direct_daemon_core_api",
        backend: RUST_AGENTGRES_STORAGE_BACKEND,
        record: {
          ...request.request,
          admission_hash: "sha256:storage-admission",
        },
        admission_hash: "sha256:storage-admission",
      };
    },
  });

  const result = runner.admitStorageBackendWrite(storageWriteRequest());

  assert.equal(calls[0].request.operation, "admit_storage_backend_write");
  assert.equal(result.admission_hash, "sha256:storage-admission");
});

test("runtime Agentgres runner rejects retired daemon-core command env", () => {
  assert.throws(
    () =>
      createRuntimeAgentgresAdmissionRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_command_selection_retired",
  );
});

test("runtime Agentgres runner rejects retired Agentgres command env", () => {
  assert.throws(
    () =>
      createRuntimeAgentgresAdmissionRunnerFromEnv({
        IOI_RUNTIME_AGENTGRES_COMMAND: "retired-runtime-agentgres-bridge",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_command_selection_retired",
  );
});

test("runtime Agentgres runner command args env fails closed", () => {
  assert.throws(
    () =>
      createRuntimeAgentgresAdmissionRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json",
      }),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_command_args_retired",
  );
});

test("runtime Agentgres runner command args constructor option fails closed", () => {
  assert.throws(
    () => new RustRuntimeAgentgresAdmissionRunner({ args: ["--json"] }),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_command_args_retired",
  );
});

test("runtime Agentgres runner command constructor option fails closed", () => {
  assert.throws(
    () => new RustRuntimeAgentgresAdmissionRunner({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_command_selection_retired",
  );
});

test("runtime Agentgres runner fails closed without direct invoker", () => {
  const runner = new RustRuntimeAgentgresAdmissionRunner();

  assert.throws(
    () => runner.commitRuntimeRunState("/runtime-state", commitRequest()),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_admission_direct_invoker_unconfigured",
  );
});
