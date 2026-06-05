import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createRuntimeEventEnvelopeHelpers } from "./runtime-event-envelopes.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function helpers() {
  const computerUseTypes = new Set([
    "computer_use_observation",
    "computer_use_action_proposed",
    "computer_use_commit_gate",
  ]);
  return createRuntimeEventEnvelopeHelpers({
    COMPUTER_USE_CONTRACT_SCHEMA_VERSION: "computer.v1",
    DAEMON_FIXTURE_PROFILE: "fixture.local",
    LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION: "lsp.gate.v1",
    LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION: "lsp.inject.v1",
    RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION: "runtime.event.v1",
    RUN_EVENT_TO_TTI_EVENT: {
      delta: "message.delta",
      lsp_diagnostics_injected: "lsp.diagnostics.injected",
      policy_blocked: "policy.blocked",
    },
    artifactRefsForRunEvent: (event) =>
      event.type === "policy_blocked" ? ["diagnostics-blocking-gate.json"] : [],
    componentKindForRunEvent: (event) =>
      computerUseTypes.has(event.type) ? "computer_use_harness" : "runtime_thread",
    computerUseSourceEventKind: (type) => `ComputerUse.${type}`,
    doctorHash,
    eventStreamIdForThread: (threadId) => `events_${threadId}`,
    isComputerUseRunEventType: (type) => computerUseTypes.has(type),
    normalizeArray,
    payloadSummaryForRunEvent: (event) => ({
      event_kind: event.data?.eventKind ?? `Run.${event.type}`,
    }),
    policyDecisionRefsForRunEvent: (event) => normalizeArray(event.data?.policyDecisionRefs),
    receiptRefsForRunEvent: (event) => normalizeArray(event.data?.receiptRefs),
    runtimeBridgeComputerUseTrace: () => ({
      actionProposal: {
        proposal_ref: "proposal-one",
        target_ref: "target-one",
        policy_decision_ref: "policy-one",
        confirmation_required: true,
      },
      commitGate: {
        commit_gate_ref: "commit-one",
        authority_required: "operator",
      },
      outcomeContract: {
        outcome_ref: "outcome-one",
      },
    }),
    runtimeBridgeMessagesForProjection: ({ projection }) => projection.events,
    runtimeEventStatusForRunEvent: (event) =>
      event.type === "policy_blocked" ? "blocked" : "running",
    stringRecord: (value) =>
      Object.fromEntries(Object.entries(value ?? {}).map(([key, item]) => [
        key,
        typeof item === "string" ? item : JSON.stringify(item),
      ])),
    workflowNodeForRunEvent: (event) =>
      event.type === "policy_blocked" ? "runtime.lsp-diagnostics.blocking-gate" : "runtime.thread",
  });
}

test("runtime event envelopes inject missing computer-use derived events after observation", () => {
  const runtime = helpers();

  const events = runtime.insertRuntimeBridgeComputerUseDerivedEvents({
    projection: {
      runId: "run-one",
      turnId: "turn-one",
      createdAt: "2026-06-03T00:00:00.000Z",
      events: [
        { event_kind: "turn.started", id: "start" },
        { event_kind: "computer_use.observation", id: "observe" },
        { event_kind: "delta", id: "delta" },
      ],
    },
    agent: { cwd: "/workspace" },
    threadId: "thread-one",
  });

  assert.deepEqual(events.map((event) => event.event_kind), [
    "turn.started",
    "computer_use.observation",
    "computer_use.action_proposed",
    "computer_use.commit_gate",
    "delta",
  ]);
  assert.equal(events[2].event_stream_id, "events_thread-one");
  assert.equal(events[2].payload_schema_version, "computer.v1");
  assert.equal(events[2].payload.computer_use_proposal_ref, "proposal-one");
  assert.equal(events[2].status, "running");
  assert.deepEqual(events[2].policy_decision_refs, ["policy-one"]);
  assert.equal(events[3].payload.outcome_contract.outcome_ref, "outcome-one");
  assert.deepEqual(events[3].receipt_refs, ["receipt_run-one_runtime_bridge_computer_use_trace"]);
});

test("runtime event envelopes do not duplicate existing computer-use derived events", () => {
  const runtime = helpers();
  const inputEvents = [
    { event_kind: "computer_use.observation" },
    { event_kind: "computer_use.action_proposed" },
    { event_kind: "computer_use.commit_gate" },
  ];

  const events = runtime.insertRuntimeBridgeComputerUseDerivedEvents({
    projection: { runId: "run-one", turnId: "turn-one", events: inputEvents },
    agent: { cwd: "/workspace" },
    threadId: "thread-one",
  });

  assert.deepEqual(events, inputEvents);
  assert.notEqual(events, inputEvents);
});

test("tti envelopes preserve diagnostics and computer-use public envelopes", () => {
  const runtime = helpers();
  const diagnostics = runtime.ttiEnvelopeForRunEvent({
    event: {
      id: "event-one",
      type: "policy_blocked",
      runId: "run-one",
      createdAt: "2026-06-03T00:00:00.000Z",
      data: {
        reason: "post_edit_diagnostics_findings",
        policyDecisionRefs: ["policy-one"],
        receiptRefs: ["receipt-one"],
      },
    },
    threadId: "thread-one",
    turnId: "turn-one",
    workspaceRoot: "/workspace",
  });

  assert.equal(diagnostics.schema_version, "runtime.event.v1");
  assert.equal(diagnostics.event_stream_id, "events_thread-one");
  assert.equal(diagnostics.event_kind, "policy.blocked");
  assert.equal(diagnostics.source, "runtime_auto");
  assert.equal(diagnostics.source_event_kind, "LspDiagnostics.BlockingGate");
  assert.equal(diagnostics.payload_schema_version, "lsp.gate.v1");
  assert.deepEqual(diagnostics.policy_decision_refs, ["policy-one"]);
  assert.deepEqual(diagnostics.receipt_refs, ["receipt-one"]);
  assert.deepEqual(diagnostics.artifact_refs, ["diagnostics-blocking-gate.json"]);
  assert.equal(diagnostics.fixture_profile, "fixture.local");

  const computerUse = runtime.ttiEnvelopeForRunEvent({
    event: {
      id: "event-two",
      type: "computer_use_observation",
      runId: "run-one",
      createdAt: "2026-06-03T00:00:00.000Z",
      data: {},
    },
    threadId: "thread-one",
    turnId: "turn-one",
    workspaceRoot: "/workspace",
  });

  assert.equal(computerUse.payload_schema_version, "computer.v1");
  assert.equal(computerUse.source_event_kind, "ComputerUse.computer_use_observation");
  assert.equal(computerUse.component_kind, "computer_use_harness");
});

test("runtime event envelope normalization preserves canonical fields", () => {
  const runtime = helpers();

  const normalized = runtime.normalizeRuntimeEventEnvelope({
    event_stream_id: "events-thread-one",
    event_kind: "message.delta",
    created_at: "2026-06-03T00:00:00.000Z",
    payload: { text: "hello", nested: { ok: true } },
    artifact_refs: ["artifact-one"],
    receipt_refs: ["receipt-one"],
    fixture_profile: null,
  }, {
    seq: 7,
    parentSeq: 6,
    idempotencyKey: "idem-one",
  });

  assert.equal(normalized.schema_version, "runtime.event.v1");
  assert.equal(normalized.event_id, "events-thread-one:seq:00000007");
  assert.equal(normalized.seq, 7);
  assert.equal(normalized.parent_seq, 6);
  assert.equal(normalized.idempotency_key, "idem-one");
  assert.equal(normalized.source, "daemon_bridge");
  assert.deepEqual(normalized.payload, {
    text: "hello",
    nested: "{\"ok\":true}",
  });
  assert.deepEqual(normalized.artifact_refs, ["artifact-one"]);
  assert.deepEqual(normalized.receipt_refs, ["receipt-one"]);
  assert.equal(normalized.fixture_profile, null);
  const retiredEnvelopeAliasKeys = ["id", "event", "timestamp_ms"];
  for (const key of retiredEnvelopeAliasKeys) {
    assert.equal(Object.hasOwn(normalized, key), false);
  }
});
