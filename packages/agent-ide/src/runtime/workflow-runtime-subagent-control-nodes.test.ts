import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_SUBAGENT_COMPONENT_KIND,
  RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION,
  RUNTIME_SUBAGENT_SOURCE,
  WORKFLOW_RUNTIME_SUBAGENT_CONTROL_SCHEMA_VERSION,
  createRuntimeSubagentControlRequest,
  createRuntimeSubagentControlRequestFromWorkflowNode,
} from "./workflow-runtime-subagent-control-nodes";

test("subagent spawn state node builds a role-aware daemon request", () => {
  const node = makeWorkflowNode("subagent-spawn", "state", "Spawn explorer", 100, 120, {
    stateKey: "subagents",
    stateOperation: "subagent_spawn",
    reducer: "append",
    subagentRole: "explore",
    subagentPrompt: "Map the runtime gap and return evidence.",
    subagentParentTurnId: "turn-parent",
    subagentModelRoute: "route.fast-coding",
    subagentToolPack: "coding",
    subagentForkContext: true,
    subagentMaxConcurrency: 3,
    subagentBudgetJson: "{\"maxTokens\":12000}",
    subagentOutputContractJson:
      "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RISKS\",\"BLOCKERS\",\"RECEIPTS\"]",
    subagentMergePolicy: "manual",
    subagentCancellationInheritance: "propagate",
  });

  const request = createRuntimeSubagentControlRequestFromWorkflowNode(
    node,
    { threadId: "thread subagent spawn" },
    { workflowGraphId: "workflow.subagent.spawn", actor: "workflow-author" },
  );

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_SUBAGENT_CONTROL_SCHEMA_VERSION);
  assert.equal(request.nodeType, "runtime_subagent");
  assert.equal(request.operation, "spawn");
  assert.equal(request.method, "POST");
  assert.equal(request.threadId, "thread subagent spawn");
  assert.equal(request.endpoint, "/v1/threads/thread%20subagent%20spawn/subagents");
  assert.equal(request.body?.source, RUNTIME_SUBAGENT_SOURCE);
  assert.equal(request.body?.actor, "workflow-author");
  assert.equal(request.body?.eventKind, RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION.spawn);
  assert.equal(request.body?.componentKind, RUNTIME_SUBAGENT_COMPONENT_KIND);
  assert.equal(request.body?.workflowGraphId, "workflow.subagent.spawn");
  assert.equal(request.body?.workflowNodeId, "runtime.subagent.spawn.explore");
  assert.equal(request.body?.parentThreadId, "thread subagent spawn");
  assert.equal(request.body?.parentTurnId, "turn-parent");
  assert.equal(request.body?.role, "explore");
  assert.equal(request.body?.prompt, "Map the runtime gap and return evidence.");
  assert.equal(request.body?.forkContext, true);
  assert.equal(request.body?.contextMode, "forked");
  assert.equal(request.body?.modelRouteId, "route.fast-coding");
  assert.equal(request.body?.toolPack, "coding");
  assert.equal(request.body?.maxConcurrency, 3);
  assert.deepEqual(request.body?.budget, { maxTokens: 12000 });
  assert.deepEqual(request.body?.outputContract, [
    "SUMMARY",
    "CHANGES",
    "EVIDENCE",
    "RISKS",
    "BLOCKERS",
    "RECEIPTS",
  ]);
  assert.equal(request.body?.mergePolicy, "manual");
  assert.equal(request.body?.cancellationInheritance, "propagate");
});

test("subagent delegate-summary request preserves context-pressure provenance", () => {
  const request = createRuntimeSubagentControlRequest({
    nodeId: "context-pressure-delegate-summary",
    operation: "spawn",
    threadId: "thread-context-pressure",
    parentTurnId: "turn-context-pressure",
    role: "review",
    prompt: "Summarize current context pressure and return receipts.",
    forkContext: true,
    toolPack: "coding",
    outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
    mergePolicy: "evidence_only",
    cancellationInheritance: "isolate",
    contextPressureAction: "delegate_summary",
    pressure: 0.74,
    pressureStatus: "elevated",
    alertId: "event-context-pressure-alert",
    sourceEventId: "event-context-pressure-delta",
    receiptRefs: ["receipt_context_pressure_alert"],
    policyDecisionRefs: ["policy_context_pressure_delegate_summary"],
    workflowGraphId: "workflow.context-pressure",
    workflowNodeId: "runtime.subagent.delegate-summary",
    actor: "operator",
  });

  assert.equal(request.operation, "spawn");
  assert.equal(request.body?.eventKind, RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION.spawn);
  assert.equal(request.body?.workflowNodeId, "runtime.subagent.delegate-summary");
  assert.equal(request.body?.parentTurnId, "turn-context-pressure");
  assert.equal(request.body?.role, "review");
  assert.equal(request.body?.forkContext, true);
  assert.equal(request.body?.contextPressureAction, "delegate_summary");
  assert.equal(request.body?.context_pressure_action, "delegate_summary");
  assert.equal(request.body?.pressure, 0.74);
  assert.equal(request.body?.contextPressure, 0.74);
  assert.equal(request.body?.pressureStatus, "elevated");
  assert.equal(request.body?.alertId, "event-context-pressure-alert");
  assert.equal(request.body?.sourceEventId, "event-context-pressure-delta");
  assert.deepEqual(request.body?.receiptRefs, ["receipt_context_pressure_alert"]);
  assert.deepEqual(request.body?.policyDecisionRefs, [
    "policy_context_pressure_delegate_summary",
  ]);
});

test("subagent spawn state node normalizes runtime telemetry summary as budget usage", () => {
  const node = makeWorkflowNode(
    "subagent-summary-budget",
    "state",
    "Spawn with summary budget",
    100,
    120,
    {
      stateKey: "subagents",
      stateOperation: "subagent_spawn",
      reducer: "append",
      subagentRole: "explore",
      subagentPrompt: "Continue only if the shared telemetry budget permits it.",
      subagentBudgetJson: JSON.stringify({ maxTokens: 750, maxCostUsd: 0.01 }),
      subagentBudgetUsageField: "runtimeTelemetrySummary",
      subagentOutputContractJson: "[\"SUMMARY\",\"EVIDENCE\",\"RECEIPTS\"]",
    },
  );

  const request = createRuntimeSubagentControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-summary-budget",
      runtimeTelemetrySummary: {
        schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
        status: "elevated",
        sourceKinds: ["runtime_usage_events", "tui_subagent_rows"],
        threadIds: ["thread-summary-budget"],
        turnIds: ["turn-summary"],
        workflowGraphIds: ["workflow.subagent.summary-budget"],
        workflowNodeIds: ["runtime.usage-telemetry"],
        eventIds: ["event-usage", "event-subagent"],
        latestSeq: 3,
        latestCursor: "events_thread:3",
        latestEventId: "event-subagent",
        runtimeEventCount: 3,
        usageEventCount: 1,
        contextPressureEventCount: 1,
        contextPressureAlertCount: 0,
        tuiRowCount: 1,
        usageRowCount: 1,
        costRowCount: 1,
        contextRowCount: 1,
        subagentRowCount: 1,
        totalTokens: 720,
        inputTokens: 430,
        outputTokens: 290,
        costEstimateUsd: 0.0042,
        contextPressure: 0.72,
        contextPressureStatus: "elevated",
        runCount: 1,
        subagentCount: 1,
        receiptRefs: ["receipt-summary"],
        policyDecisionRefs: ["policy-summary"],
      },
    },
    { workflowGraphId: "workflow.subagent.summary-budget" },
  );

  assert.deepEqual(request.body?.budget, { maxTokens: 750, maxCostUsd: 0.01 });
  const budgetUsageTelemetry = request.body?.budget_usage_telemetry as Record<
    string,
    unknown
  >;
  assert.equal(budgetUsageTelemetry.total_tokens, 720);
  assert.equal(budgetUsageTelemetry.estimated_cost_usd, 0.0042);
  assert.equal(budgetUsageTelemetry.context_pressure, 0.72);
  assert.equal(
    (budgetUsageTelemetry.source_counts as Record<string, unknown>).subagents,
    1,
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(request.body, "budgetUsageTelemetry"),
    false,
  );
});

test("subagent join state node builds a wait request with output contract gates", () => {
  const node = makeWorkflowNode("subagent-join", "state", "Join explorer", 100, 120, {
    stateKey: "subagents",
    stateOperation: "subagent_wait",
    reducer: "merge",
    subagentId: "agent-explorer-1",
    subagentWaitTimeoutMs: 150000,
    subagentOutputContractJson: "[\"SUMMARY\",\"EVIDENCE\",\"BLOCKERS\"]",
    subagentMergePolicy: "evidence_only",
  });

  const request = createRuntimeSubagentControlRequestFromWorkflowNode(
    node,
    { threadId: "thread-subagent-join" },
  );

  assert.equal(request.operation, "wait");
  assert.equal(request.method, "POST");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-subagent-join/subagents/agent-explorer-1/wait",
  );
  assert.equal(request.body?.eventKind, RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION.wait);
  assert.equal(request.body?.subagentId, "agent-explorer-1");
  assert.equal(request.body?.waitTimeoutMs, 150000);
  assert.deepEqual(request.body?.outputContract, [
    "SUMMARY",
    "EVIDENCE",
    "BLOCKERS",
  ]);
  assert.equal(request.body?.mergePolicy, "evidence_only");
});

test("subagent result and list nodes build read-only daemon requests", () => {
  const listNode = makeWorkflowNode("subagent-pool", "state", "Pool", 100, 120, {
    stateKey: "subagents",
    stateOperation: "subagent_list",
    reducer: "replace",
  });
  const resultNode = makeWorkflowNode("subagent-result", "state", "Result", 100, 120, {
    stateKey: "subagents",
    stateOperation: "subagent_result",
    reducer: "replace",
    subagentId: "agent-result-1",
  });

  const listRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
    listNode,
    { threadId: "thread-list" },
    { workflowGraphId: "workflow.subagent.pool" },
  );
  const resultRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
    resultNode,
    { threadId: "thread-result" },
  );

  assert.equal(listRequest.operation, "list");
  assert.equal(listRequest.method, "GET");
  assert.match(listRequest.endpoint, /^\/v1\/threads\/thread-list\/subagents\?/);
  assert.match(listRequest.endpoint, /source=react_flow/);
  assert.match(listRequest.endpoint, /role=general/);
  assert.equal(listRequest.body, null);
  assert.equal(resultRequest.operation, "result");
  assert.equal(resultRequest.method, "GET");
  assert.match(
    resultRequest.endpoint,
    /^\/v1\/threads\/thread-result\/subagents\/agent-result-1\/result\?/,
  );
  assert.equal(resultRequest.body, null);
});

test("subagent cancellation propagation node targets the parent fan-out route", () => {
  const node = makeWorkflowNode(
    "subagent-cancel-propagation",
    "state",
    "Cancel parent descendants",
    100,
    120,
    {
      stateKey: "subagents",
      stateOperation: "subagent_cancel_propagation",
      reducer: "replace",
      subagentInput: "workflow_parent_cancel",
      subagentCancellationInheritance: "propagate",
    },
  );

  const request = createRuntimeSubagentControlRequestFromWorkflowNode(
    node,
    { threadId: "thread-fanout" },
    { workflowGraphId: "workflow.subagent.fanout", actor: "workflow-author" },
  );

  assert.equal(request.operation, "propagate_cancel");
  assert.equal(request.method, "POST");
  assert.equal(request.subagentId, null);
  assert.equal(request.endpoint, "/v1/threads/thread-fanout/subagents/cancel");
  assert.equal(request.body?.eventKind, RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION.propagate_cancel);
  assert.equal(request.body?.workflowGraphId, "workflow.subagent.fanout");
  assert.equal(request.body?.workflowNodeId, "runtime.subagent.propagate_cancel.general");
  assert.equal(request.body?.reason, "workflow_parent_cancel");
  assert.equal(request.body?.cancellationReason, "workflow_parent_cancel");
});

test("subagent send, cancel, resume, and assign nodes target child lifecycle endpoints", () => {
  const operations = [
    ["subagent_send_input", "/input", "send_input"],
    ["subagent_cancel", "/cancel", "cancel"],
    ["subagent_resume", "/resume", "resume"],
    ["subagent_assign", "/assign", "assign"],
  ] as const;

  for (const [stateOperation, suffix, operation] of operations) {
    const node = makeWorkflowNode(`node-${operation}`, "state", operation, 100, 120, {
      stateKey: "subagents",
      stateOperation,
      reducer: "replace",
      subagentId: "agent-lifecycle-1",
      subagentRole: "verifier",
      subagentInput: "continue from latest receipt",
    });

    const request = createRuntimeSubagentControlRequestFromWorkflowNode(
      node,
      { threadId: "thread-lifecycle" },
    );

    assert.equal(request.operation, operation);
    assert.equal(request.method, "POST");
    assert.equal(
      request.endpoint,
      `/v1/threads/thread-lifecycle/subagents/agent-lifecycle-1${suffix}`,
    );
    assert.equal(request.body?.subagentId, "agent-lifecycle-1");
    assert.equal(
      request.body?.eventKind,
      RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION[operation],
    );
    assert.equal(request.body?.role, "verifier");
  }
});
