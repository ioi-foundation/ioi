import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRecordProjections } from "./runtime-record-projections.mjs";

const retiredRuntimeBridgeUsageAliasKeys = [
  "usageTelemetry",
  "runtimeUsage",
];

const retiredRuntimeBridgeMessageDataAliasKeys = [
  "eventKind",
  "workflowGraphId",
  "workflowNodeId",
  "componentKind",
  "payloadSchemaVersion",
  "runtimeEventId",
  "runtimeEventKind",
  "sourceEventKind",
  "receiptRefs",
  "artifactRefs",
  "policyDecisionRefs",
];

function assertMissingKeys(record, keys) {
  for (const key of keys) {
    assert.equal(Object.hasOwn(record, key), false, `retired alias key ${key} must be absent`);
  }
}

function projections(overrides = {}) {
  return createRuntimeRecordProjections({
    COMPUTER_USE_CONTRACT_SCHEMA_VERSION: "computer.v1",
    artifact: (runId, name, mediaType, receiptId, content, redaction) => ({
      id: `artifact_${name}`,
      runId,
      name,
      mediaType,
      receiptId,
      content,
      redaction,
    }),
    doctorHash: (value) => `hash_${String(value).length}`,
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    isComputerUseRunEventType: () => false,
    normalizeArray: (value) => (Array.isArray(value) ? value : []),
    optionalString: (value) => (typeof value === "string" && value.length > 0 ? value : null),
    runtimeSessionIdForAgent: (agent) => `session_${agent.id}`,
    runtimeUsageTelemetryForRun: () => ({
      object: "ioi.runtime_usage_telemetry",
      scope: "run",
      run_id: "run_bridge",
      thread_id: "thread_agent_bridge",
      total_tokens: 42,
    }),
    safeId: (value) => String(value ?? "none").replace(/[^a-zA-Z0-9_-]+/g, "_"),
    strategyForMode: () => "agent",
    taskFamilyForMode: () => "coding",
    terminalCount: (events) => events.length,
    threadIdForAgent: (agentId) => `thread_${agentId}`,
    turnIdForRun: (runId) => `turn_${runId}`,
    uniqueStrings: (values) => [...new Set(values.filter(Boolean).map(String))],
    ...overrides,
  });
}

test("runtime bridge run record emits canonical usage telemetry only", () => {
  const run = projections().runtimeBridgeRunRecord({
    agent: {
      id: "agent_bridge",
      runtimeProfile: "runtime_service",
    },
    projection: {
      runId: "run_bridge",
      turnId: "turn_bridge",
      mode: "send",
      prompt: "Inspect bridge usage",
      result: "Done",
      status: "completed",
      createdAt: "2026-06-05T00:00:00.000Z",
      updatedAt: "2026-06-05T00:00:01.000Z",
      stopReason: "complete",
      usage: { total_tokens: 42 },
      events: [],
    },
  });

  assert.equal(run.usage_telemetry, run.usage);
  assert.equal(run.trace.usage_telemetry, run.usage);
  assert.equal(run.trace.usage_telemetry.total_tokens, 42);
  assertMissingKeys(run, retiredRuntimeBridgeUsageAliasKeys);
  assertMissingKeys(run.trace, retiredRuntimeBridgeUsageAliasKeys);

  const traceArtifact = run.artifacts.find((artifact) => artifact.name === "trace.json");
  assert.ok(traceArtifact);
  assert.equal(traceArtifact.content.usage_telemetry, run.usage);
  assertMissingKeys(traceArtifact.content, retiredRuntimeBridgeUsageAliasKeys);
});

test("runtime bridge messages emit canonical event data fields only", () => {
  const [message] = projections().runtimeBridgeMessagesForProjection({
    agent: { id: "agent_bridge" },
    projection: {
      runId: "run_bridge",
      updatedAt: "2026-06-05T00:00:01.000Z",
      createdAt: "2026-06-05T00:00:00.000Z",
      events: [
        {
          event_id: "event-canonical",
          event_kind: "turn.completed",
          source_event_kind: "runtime.completed",
          workflow_graph_id: "graph-canonical",
          workflow_node_id: "node-canonical",
          component_kind: "runtime",
          payload_schema_version: "payload.v1",
          receipt_refs: ["receipt-canonical"],
          artifact_refs: ["artifact-canonical"],
          policy_decision_refs: ["policy-canonical"],
          payload_summary: {
            event_kind: "payload.canonical",
            eventKind: "payload.retired",
            workflow_graph_id: "graph-payload",
            workflowGraphId: "graph-payload-retired",
          },
        },
      ],
    },
  });

  assert.equal(message.data.event_kind, "payload.canonical");
  assert.equal(message.data.workflow_graph_id, "graph-canonical");
  assert.equal(message.data.workflow_node_id, "node-canonical");
  assert.equal(message.data.component_kind, "runtime");
  assert.equal(message.data.payload_schema_version, "payload.v1");
  assert.equal(message.data.runtime_event_id, "event-canonical");
  assert.equal(message.data.runtime_event_kind, "turn.completed");
  assert.equal(message.data.source_event_kind, "runtime.completed");
  assert.deepEqual(message.data.receipt_refs, ["receipt-canonical"]);
  assert.deepEqual(message.data.artifact_refs, ["artifact-canonical"]);
  assert.deepEqual(message.data.policy_decision_refs, ["policy-canonical"]);
  assertMissingKeys(message.data, retiredRuntimeBridgeMessageDataAliasKeys);
});

test("runtime bridge computer-use trace emits canonical projection fields only", () => {
  const runtime = projections({
    isComputerUseRunEventType: (type) => String(type).startsWith("computer_use_"),
  });
  const trace = runtime.runtimeBridgeComputerUseTrace({
    projection: {
      runId: "run_bridge",
      turnId: "turn_bridge",
      prompt: "Observe UI",
    },
    events: [
      {
        id: "event-one",
        type: "computer_use_observation",
        summary: "Observed UI",
        data: {
          runtime_event_id: "event-canonical",
          runtimeEventId: "event-retired",
          runtime_event_kind: "computer_use.observation",
          runtimeEventKind: "retired.kind",
          workflow_node_id: "node-canonical",
          workflowNodeId: "node-retired",
          component_kind: "computer_use",
          componentKind: "retired_component",
          receipt_refs: ["receipt-canonical"],
          receiptRefs: ["receipt-retired"],
          artifact_refs: ["artifact-canonical"],
          artifactRefs: ["artifact-retired"],
          observation_bundle: {
            observation_ref: "observation-one",
            target_index_ref: "target-one",
            lane: "native_browser",
            retention_mode: "local_redacted_artifacts",
          },
        },
      },
    ],
  });

  assert.equal(trace.run_id, "run_bridge");
  assert.equal(trace.event_count, 1);
  assert.equal(trace.events[0].runtime_event_id, "event-canonical");
  assert.equal(trace.events[0].workflow_node_id, "node-canonical");
  assert.deepEqual(trace.events[0].receipt_refs, ["receipt-canonical"]);
  assert.equal(trace.trajectory_bundle.entries[0].runtime_event_ref, "event-canonical");
  assert.equal(trace.trajectory_bundle.entries[0].workflow_node_id, "node-canonical");

  assertMissingKeys(trace, [
    "schemaVersion",
    "runId",
    "turnId",
    "eventCount",
    "environmentSelection",
    "runState",
    "observationBundle",
    "targetIndex",
    "affordanceGraph",
    "actionProposal",
    "actionReceipt",
    "outcomeContract",
    "commitGate",
    "recoveryPolicy",
    "humanHandoffState",
    "contractIngest",
    "retentionMode",
  ]);
  assertMissingKeys(trace.events[0], [
    "runtimeEventId",
    "runtimeEventKind",
    "workflowNodeId",
    "componentKind",
    "receiptRefs",
    "artifactRefs",
  ]);
});

test("runtime task job checklist records for run ignore embedded sidecar identity aliases", () => {
  const runtime = projections();
  const run = {
    id: "run_canonical",
    agentId: "agent_record",
    objective: "Project canonical records",
    mode: "send",
    status: "completed",
    createdAt: "2026-06-07T00:00:00.000Z",
    updatedAt: "2026-06-07T00:00:01.000Z",
    runtimeTask: {
      taskId: "task_retired_embedded",
      runId: "run_retired",
      status: "failed",
    },
    runtimeJob: {
      jobId: "job_retired_embedded",
      taskId: "task_retired_embedded",
      runId: "run_retired",
      status: "failed",
    },
    runtimeChecklist: {
      checklistId: "checklist_retired_embedded",
      jobId: "job_retired_embedded",
      taskId: "task_retired_embedded",
      runId: "run_retired",
      status: "failed",
    },
    trace: {
      qualityLedger: {
        taskFamily: "coding",
        selectedStrategy: "agent",
      },
    },
  };

  const task = runtime.runtimeTaskRecordForRun(run);
  const job = runtime.runtimeJobRecordForRun(run);
  const checklist = runtime.runtimeChecklistRecordForRun(run);

  assert.equal(task.taskId, "task_run_canonical");
  assert.equal(task.runId, "run_canonical");
  assert.equal(task.status, "completed");
  assert.equal(job.jobId, "job_run_canonical");
  assert.equal(job.taskId, "task_run_canonical");
  assert.equal(job.runId, "run_canonical");
  assert.equal(job.status, "completed");
  assert.equal(checklist.checklistId, "checklist_run_canonical");
  assert.equal(checklist.jobId, "job_run_canonical");
  assert.equal(checklist.taskId, "task_run_canonical");
  assert.equal(checklist.runId, "run_canonical");
  assert.equal(checklist.status, "completed");
});
