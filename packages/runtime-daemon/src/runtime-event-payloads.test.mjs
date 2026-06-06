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

const retiredComputerUseSummaryAliasKeys = [
  "eventKind",
  "schemaVersion",
  "workflowGraphId",
  "workflowNodeId",
  "workflowNodeIds",
  "toolRef",
  "authorityScopes",
];

const retiredMemorySummaryAliasKeys = [
  "eventKind",
  "memoryRecordId",
  "memoryPolicyId",
  "workflowNodeId",
];

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
      event_kind: "ComputerUse.Observation",
      eventKind: "RetiredComputerUseEventKind",
      schema_version: "computer.v1",
      schemaVersion: "retired.computer.v1",
      computer_use_step: "observe",
      computer_use_observation_ref: "observation-one",
      workflow_graph_id: "workflow-one",
      workflowGraphId: "retired-workflow",
      workflow_node_id: "node-one",
      workflowNodeId: "retired-node",
      workflow_node_ids: ["node-one"],
      workflowNodeIds: ["retired-node"],
      tool_ref: "computer_use.observe",
      toolRef: "retired-tool",
      authority_scopes: ["computer_use.read"],
      authorityScopes: ["retired.scope"],
      fail_closed_when_unavailable: true,
    },
  });

  assert.equal(computerUse.event_kind, "ComputerUse.Observation");
  assert.equal(computerUse.schema_version, "computer.v1");
  assert.equal(computerUse.computer_use_step, "observe");
  assert.equal(computerUse.computer_use_observation_ref, "observation-one");
  assert.equal(computerUse.workflow_graph_id, "workflow-one");
  assert.equal(computerUse.workflow_node_id, "node-one");
  assert.deepEqual(computerUse.workflow_node_ids, ["node-one"]);
  assert.equal(computerUse.tool_ref, "computer_use.observe");
  assert.deepEqual(computerUse.authority_scopes, ["computer_use.read"]);
  assert.equal(computerUse.fail_closed_when_unavailable, true);
  assert.equal(computerUse.redaction, "computer_use_trace_safe");
  for (const key of retiredPayloadKeys) {
    assert.equal(Object.hasOwn(computerUse, key), false);
  }
  assert.equal(computerUse.workflow_node_ids.includes("retired-node"), false);
  assert.equal(computerUse.authority_scopes.includes("retired.scope"), false);
  for (const key of retiredComputerUseSummaryAliasKeys) {
    assert.equal(Object.hasOwn(computerUse, key), false);
  }

  const memory = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "memory_update",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "MemoryPolicy.Canonical",
      eventKind: "RetiredMemoryEventKind",
      operation: "policy_update",
      object: "ioi.agent_memory_policy",
      id: "policy-one",
      memory_record_id: "memory-one",
      memoryRecordId: "retired-memory",
      memory_policy_id: "policy-one",
      memoryPolicyId: "retired-policy",
      inherited_record_ids: ["memory-one", "memory-two"],
      write_allowed: false,
      write_block_reason: "approval_required",
      workflow_node_id: "memory.node",
      workflowNodeId: "retired.memory.node",
    },
  });

  assert.equal(memory.event_kind, "MemoryPolicy.Canonical");
  assert.equal(memory.memory_operation, "policy_update");
  assert.equal(memory.memory_record_id, "memory-one");
  assert.equal(memory.memory_policy_id, "policy-one");
  assert.equal(memory.workflow_node_id, "memory.node");
  assert.equal(memory.inherited_memory_count, 2);
  assert.equal(memory.write_allowed, false);
  assert.equal(memory.write_block_reason, "approval_required");
  assert.notEqual(memory.event_kind, "RetiredMemoryEventKind");
  assert.notEqual(memory.memory_record_id, "retired-memory");
  assert.notEqual(memory.memory_policy_id, "retired-policy");
  assert.notEqual(memory.workflow_node_id, "retired.memory.node");
  for (const key of retiredMemorySummaryAliasKeys) {
    assert.equal(Object.hasOwn(memory, key), false);
  }
});

test("runtime event payloads consume canonical diagnostics injection and blocking gate fields", () => {
  const runtime = helpers();

  const injected = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "lsp_diagnostics_injected",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      injection_id: "injection-one",
      diagnostic_status: "findings",
      diagnostic_count: 3,
      injected_finding_count: 2,
      omitted_finding_count: 1,
      diagnostic_event_ids: ["diag-one"],
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
      gate_id: "gate-one",
      policy_decision_id: "policy-one",
      policy_decision_refs: ["policy-one", "policy-two"],
      reason: "post_edit_diagnostics_findings",
      requires_input: true,
      recommended_next_actions: ["repair_retry"],
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
      decision_id: "decision-one",
      route_id: "route.local-first",
      requested_model: "qwen",
      selected_model: "qwen",
      provider_kind: "llama.cpp",
      fallback_triggered: true,
    },
  });

  assert.equal(route.event_kind, "ModelRouteDecision");
  assert.equal(route.model_route_decision_id, "decision-one");
  assert.equal(route.route_id, "route.local-first");
  assert.equal(route.provider_kind, "llama.cpp");
  assert.equal(route.fallback_triggered, true);
  for (const key of retiredPayloadKeys) {
    assert.equal(Object.hasOwn(route, key), false);
  }

  const legacyRoute = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-route",
    type: "model_route_decision",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      eventKind: "LegacyModelRouteDecision",
      decisionId: "decision-legacy",
      routeId: "route.legacy",
      requestedModel: "legacy-model",
      selectedModel: "legacy-selected",
      providerKind: "legacy-provider",
      fallbackTriggered: true,
    },
  });

  assert.equal(legacyRoute.event_kind, "ModelRouteDecision");
  assert.equal(legacyRoute.model_route_decision_id, null);
  assert.equal(legacyRoute.route_id, null);
  assert.equal(legacyRoute.provider_kind, null);
  assert.equal(legacyRoute.fallback_triggered, false);
});
