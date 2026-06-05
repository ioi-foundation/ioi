import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeEventPayloadHelpers } from "./runtime-event-payloads.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).filter(Boolean).map(String))];
}

const retiredPayloadKeys = ["id", "type"].map((suffix) => ["legacy", "event", suffix].join("_"));

const retiredUsageSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "runId",
  "threadId",
  "turnId",
  "totalTokens",
  "inputTokens",
  "outputTokens",
  "estimatedCostUsd",
  "contextPressure",
  "contextPressureStatus",
  "workflowNodeId",
  "componentKind",
];

const retiredContextPressureDeltaSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "runId",
  "threadId",
  "turnId",
  "usageTotalTokens",
  "usageCostEstimateUsd",
  "usageContextPressure",
  "usageContextPressureStatus",
  "workflowNodeId",
  "componentKind",
];

const retiredContextPressureAlertSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "alertId",
  "alertLevel",
  "pressureStatus",
  "recommendedAction",
  "runId",
  "threadId",
  "turnId",
  "workflowNodeId",
  "componentKind",
];

const retiredUsageFinalSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "threadId",
  "turnId",
  "totalTokens",
  "inputTokens",
  "outputTokens",
  "estimatedCostUsd",
  "contextPressure",
  "contextPressureStatus",
  "workflowNodeId",
];

function legacyDataFor(keys) {
  return Object.fromEntries(keys.map((key) => [key, "legacy"]));
}

function helpers() {
  return createRuntimeEventPayloadHelpers({
    COMPUTER_USE_CONTRACT_SCHEMA_VERSION: "computer.v1",
    LSP_DIAGNOSTICS_INJECTION_NODE_ID: "runtime.lsp-diagnostics.inject",
    RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION: "context.alert.v1",
    RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION: "context.delta.v1",
    RUNTIME_USAGE_DELTA_SCHEMA_VERSION: "usage.delta.v1",
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION: "usage.final.v1",
    computerUseSourceEventKind: (type) => `ComputerUse.${type}`,
    isComputerUseRunEventType: (type) => type.startsWith("computer_use_"),
    memoryEventKind: (operation = "write") =>
      operation === "policy_update" ? "MemoryPolicy" : "AgentMemory",
    normalizeArray,
    uniqueStrings,
  });
}

test("runtime event payloads preserve computer-use and memory summaries", () => {
  const runtime = helpers();

  const computerUse = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "computer_use_observation",
    runId: "run-one",
    agentId: "agent-one",
    summary: "Observed page",
    data: {
      computer_use_step: "observe",
      computer_use_observation_ref: "observation-one",
      workflowNodeIds: ["node-one"],
      fail_closed_when_unavailable: true,
    },
  });

  assert.equal(computerUse.event_kind, "ComputerUse.computer_use_observation");
  assert.equal(computerUse.schema_version, "computer.v1");
  assert.equal(computerUse.computer_use_step, "observe");
  assert.equal(computerUse.computer_use_observation_ref, "observation-one");
  assert.deepEqual(computerUse.workflow_node_ids, ["node-one"]);
  assert.equal(computerUse.fail_closed_when_unavailable, true);
  assert.equal(computerUse.redaction, "computer_use_trace_safe");
  for (const key of retiredPayloadKeys) {
    assert.equal(Object.hasOwn(computerUse, key), false);
  }

  const memory = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "memory_update",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      operation: "policy_update",
      object: "ioi.agent_memory_policy",
      id: "policy-one",
      inheritedRecordIds: ["memory-one", "memory-two"],
      writeAllowed: false,
      writeBlockReason: "approval_required",
    },
  });

  assert.equal(memory.event_kind, "MemoryPolicy");
  assert.equal(memory.memory_operation, "policy_update");
  assert.equal(memory.memory_policy_id, "policy-one");
  assert.equal(memory.inherited_memory_count, 2);
  assert.equal(memory.write_allowed, false);
  assert.equal(memory.write_block_reason, "approval_required");
});

test("runtime event payloads preserve diagnostics injection and blocking gate aliases", () => {
  const runtime = helpers();

  const injected = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "lsp_diagnostics_injected",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      injectionId: "injection-one",
      diagnosticStatus: "findings",
      diagnosticCount: 3,
      injectedFindingCount: 2,
      omittedFindingCount: 1,
      diagnosticEventIds: ["diag-one"],
      rollback_refs: ["rollback-one"],
      workspace_snapshot_refs: ["snapshot-one"],
      source_tool_call_ids: ["tool-call-one"],
      findings: [{ message: "broken" }],
    },
  });

  assert.equal(injected.event_kind, "LspDiagnosticsInjected");
  assert.equal(injected.injection_id, "injection-one");
  assert.equal(injected.diagnostic_count, 3);
  assert.equal(injected.injected_finding_count, 2);
  assert.deepEqual(injected.rollback_refs, ["rollback-one"]);
  assert.deepEqual(injected.workspace_snapshot_refs, ["snapshot-one"]);
  assert.deepEqual(injected.source_tool_call_ids, ["tool-call-one"]);
  assert.equal(injected.workflow_node_id, "runtime.lsp-diagnostics.inject");
  assert.equal(injected.redaction, "lsp_diagnostics_safe");

  const blocked = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "policy_blocked",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      gateId: "gate-one",
      policyDecisionId: "policy-one",
      policy_decision_refs: ["policy-one", "policy-two"],
      reason: "post_edit_diagnostics_findings",
      requiresInput: true,
      recommendedNextActions: ["repair_retry"],
      repair_decisions: [{ action: "repair_retry" }],
    },
  });

  assert.equal(blocked.event_kind, "PolicyBlocked");
  assert.equal(blocked.gate_id, "gate-one");
  assert.deepEqual(blocked.policy_decision_refs, ["policy-one", "policy-two"]);
  assert.equal(blocked.requires_input, true);
  assert.deepEqual(blocked.recommended_next_actions, ["repair_retry"]);
  assert.deepEqual(blocked.repair_decisions, [{ action: "repair_retry" }]);
});

test("runtime event payloads preserve repository and runtime record summaries", () => {
  const runtime = helpers();

  const repo = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "repository_context",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      contextId: "repo-context-one",
      isGitRepository: true,
      branch: "main",
      status: { isDirty: true, counts: { staged: 1, unstaged: 2, untracked: 3 } },
      redaction: { profile: "repository_context_safe" },
    },
  });

  assert.equal(repo.event_kind, "RepositoryContext");
  assert.equal(repo.context_id, "repo-context-one");
  assert.equal(repo.is_git_repository, true);
  assert.equal(repo.is_dirty, true);
  assert.equal(repo.staged_count, 1);
  assert.equal(repo.unstaged_count, 2);
  assert.equal(repo.untracked_count, 3);

  const task = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "runtime_task",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      taskId: "task-one",
      status: "running",
      taskFamily: "coding",
      selectedStrategy: "agent",
      durable: true,
      replayable: true,
    },
  });

  assert.equal(task.event_kind, "RuntimeTaskRecord");
  assert.equal(task.task_id, "task-one");
  assert.equal(task.task_family, "coding");
  assert.equal(task.selected_strategy, "agent");
  assert.equal(task.durable, true);
  assert.equal(task.replayable, true);
});

test("runtime event payloads preserve usage and model route summaries", () => {
  const runtime = helpers();

  const usage = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "usage_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      stage: "completion_streamed",
      total_tokens: 42,
      input_tokens: 30,
      output_tokens: 12,
      context_pressure: 0.4,
      workflow_node_id: "runtime.usage-telemetry",
    },
  });

  assert.equal(usage.event_kind, "RuntimeUsageTelemetry.Delta");
  assert.equal(usage.schema_version, "usage.delta.v1");
  assert.equal(usage.stage, "completion_streamed");
  assert.equal(usage.total_tokens, 42);
  assert.equal(usage.context_pressure, 0.4);
  assert.equal(usage.redaction, "usage_telemetry_safe");
  assert.equal(Object.hasOwn(usage, "eventKind"), false);

  const legacyUsage = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-usage",
    type: "usage_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredUsageSummaryReaderAliasKeys),
  });

  assert.equal(legacyUsage.event_kind, "RuntimeUsageTelemetry.Delta");
  assert.equal(legacyUsage.schema_version, "usage.delta.v1");
  assert.equal(legacyUsage.run_id, null);
  assert.equal(legacyUsage.total_tokens, 0);
  assert.equal(legacyUsage.context_pressure, 0);
  assert.equal(legacyUsage.workflow_node_id, "runtime.usage-telemetry");

  const contextDelta = runtime.payloadSummaryForRunEvent({
    id: "event-context-delta",
    type: "context_pressure_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      usage_total_tokens: 42,
      usage_context_pressure: 0.4,
    },
  });

  assert.equal(contextDelta.event_kind, "RuntimeContextPressure.Delta");
  assert.equal(contextDelta.schema_version, "context.delta.v1");
  assert.equal(contextDelta.usage_total_tokens, 42);
  assert.equal(Object.hasOwn(contextDelta, "eventKind"), false);

  const legacyContextDelta = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-context-delta",
    type: "context_pressure_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredContextPressureDeltaSummaryReaderAliasKeys),
  });

  assert.equal(legacyContextDelta.event_kind, "RuntimeContextPressure.Delta");
  assert.equal(legacyContextDelta.schema_version, "context.delta.v1");
  assert.equal(legacyContextDelta.run_id, null);
  assert.equal(legacyContextDelta.usage_total_tokens, 0);
  assert.equal(legacyContextDelta.usage_context_pressure, 0);
  assert.equal(legacyContextDelta.workflow_node_id, "runtime.context-budget");

  const alert = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "context_pressure_alert",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      alert_id: "alert-one",
      alert_level: "warning",
      actions: ["compact"],
    },
  });

  assert.equal(alert.schema_version, "context.alert.v1");
  assert.equal(alert.alert_id, "alert-one");
  assert.deepEqual(alert.actions, ["compact"]);
  assert.equal(Object.hasOwn(alert, "eventKind"), false);

  const legacyAlert = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-alert",
    type: "context_pressure_alert",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredContextPressureAlertSummaryReaderAliasKeys),
  });

  assert.equal(legacyAlert.event_kind, "RuntimeContextPressure.Alert");
  assert.equal(legacyAlert.schema_version, "context.alert.v1");
  assert.equal(legacyAlert.alert_id, null);
  assert.equal(legacyAlert.pressure_status, null);
  assert.equal(legacyAlert.recommended_action, null);
  assert.equal(legacyAlert.workflow_node_id, "runtime.context-pressure-alert");

  const usageFinal = runtime.payloadSummaryForRunEvent({
    id: "event-usage-final",
    type: "usage_final",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      total_tokens: 42,
      input_tokens: 30,
      output_tokens: 12,
    },
  });

  assert.equal(usageFinal.event_kind, "RuntimeUsageTelemetry");
  assert.equal(usageFinal.schema_version, "usage.final.v1");
  assert.equal(usageFinal.total_tokens, 42);
  assert.equal(Object.hasOwn(usageFinal, "eventKind"), false);

  const legacyUsageFinal = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-usage-final",
    type: "usage_final",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredUsageFinalSummaryReaderAliasKeys),
  });

  assert.equal(legacyUsageFinal.event_kind, "RuntimeUsageTelemetry");
  assert.equal(legacyUsageFinal.schema_version, "usage.final.v1");
  assert.equal(legacyUsageFinal.thread_id, null);
  assert.equal(legacyUsageFinal.total_tokens, 0);
  assert.equal(legacyUsageFinal.context_pressure, null);
  assert.equal(legacyUsageFinal.workflow_node_id, "runtime.usage-telemetry");

  const route = runtime.payloadSummaryForRunEvent({
    id: "event-three",
    type: "model_route_decision",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      decisionId: "decision-one",
      routeId: "route.local-first",
      requestedModel: "qwen",
      selectedModel: "qwen",
      providerKind: "llama.cpp",
      fallbackTriggered: false,
    },
  });

  assert.equal(route.event_kind, "ModelRouteDecision");
  assert.equal(route.model_route_decision_id, "decision-one");
  assert.equal(route.route_id, "route.local-first");
  assert.equal(route.provider_kind, "llama.cpp");
  assert.equal(route.fallback_triggered, false);
  for (const key of retiredPayloadKeys) {
    assert.equal(Object.hasOwn(route, key), false);
  }
});
