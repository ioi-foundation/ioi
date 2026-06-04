import crypto from "node:crypto";

import {
  RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
  RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import {
  contextBudgetUsageTelemetryFromRequest,
  evaluateCompactionPolicyDecision,
  evaluateContextBudgetPolicy,
} from "./threads/context-budget-policy.mjs";
import {
  eventStreamIdForThread,
  fixtureProfileForAgent,
  runtimeSessionIdForAgent,
  threadIdForAgent,
  turnIdForRun,
} from "./runtime-identifiers.mjs";
import {
  appendOperatorControl,
  operatorControlSource,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export function createRuntimeContextPolicySurface({
  RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION: compactionPolicySchemaVersion = RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
  RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION: contextBudgetSchemaVersion = RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
  appendOperatorControl: appendOperatorControlDep = appendOperatorControl,
  contextBudgetUsageTelemetryFromRequest: contextBudgetUsageTelemetryFromRequestDep = contextBudgetUsageTelemetryFromRequest,
  evaluateCompactionPolicyDecision: evaluateCompactionPolicyDecisionDep = evaluateCompactionPolicyDecision,
  evaluateContextBudgetPolicy: evaluateContextBudgetPolicyDep = evaluateContextBudgetPolicy,
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  fixtureProfileForAgent: fixtureProfileForAgentDep = fixtureProfileForAgent,
  operatorControlSource: operatorControlSourceDep = operatorControlSource,
  optionalString: optionalStringDep = optionalString,
  runtimeError,
  runtimeSessionIdForAgent: runtimeSessionIdForAgentDep = runtimeSessionIdForAgent,
  safeId: safeIdDep = safeId,
  threadIdForAgent: threadIdForAgentDep = threadIdForAgent,
  turnIdForRun: turnIdForRunDep = turnIdForRun,
} = {}) {
  return {
    compactThread(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const runs = store.listRuns(agent.id);
      const latestRun = runs.at(-1);
      const turnId =
        optionalStringDep(request.turn_id ?? request.turnId) ??
        (latestRun ? turnIdForRunDep(latestRun.id) : "");
      const source = operatorControlSourceDep(request.source);
      const requestedBy = optionalStringDep(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
      const reason =
        optionalStringDep(request.reason ?? request.message ?? request.input) ?? "operator requested context compaction";
      const scope = optionalStringDep(request.scope) ?? "thread";
      const now = new Date().toISOString();
      const streamId = eventStreamIdForThreadDep(threadId);
      const previousLatestSeq = store.latestRuntimeEventSeq(streamId);
      const compactHash = crypto
        .createHash("sha256")
        .update(`${reason}:${scope}`)
        .digest("hex")
        .slice(0, 16);
      const event = store.appendRuntimeEvent({
        event_stream_id: streamId,
        thread_id: threadId,
        turn_id: turnId,
        item_id: `${turnId || threadId}:item:context-compact:${compactHash}`,
        idempotency_key:
          request.idempotency_key ??
          request.idempotencyKey ??
          `thread:${threadId}:context.compact:${compactHash}`,
        source,
        source_event_kind: "OperatorControl.Compact",
        event_kind: "context.compacted",
        status: "completed",
        actor: "user",
        created_at: now,
        workspace_root: agent.cwd,
        workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
        workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.context-compact",
        component_kind: "context_compaction",
        payload_schema_version: "ioi.runtime.context-compaction.v1",
        payload: {
          event_kind: "OperatorControl.Compact",
          reason,
          scope,
          requested_by: requestedBy,
          control_surface: source,
          previous_latest_seq: previousLatestSeq,
          compacted_tokens: 0,
          agent_id: agent.id,
          thread_id: threadId,
          turn_id: turnId || null,
          run_id: latestRun?.id ?? null,
          session_id: runtimeSessionIdForAgentDep(agent),
        },
        receipt_refs: [`receipt_${latestRun?.id ?? agent.id}_context_compaction_${compactHash}`],
        policy_decision_refs: [`policy_${latestRun?.id ?? agent.id}_context_compaction_allow`],
        artifact_refs: [],
        rollback_refs: [],
        redaction_profile: "internal",
        fixture_profile: fixtureProfileForAgentDep(agent),
      });
      const control = {
        control: "compact",
        source,
        reason,
        scope,
        eventId: event.event_id,
        seq: event.seq,
        createdAt: event.created_at,
      };
      if (latestRun) {
        const updated = {
          ...latestRun,
          updatedAt: event.created_at,
          trace: {
            ...latestRun.trace,
            operatorControls: appendOperatorControlDep(latestRun.trace?.operatorControls, control),
            contextCompaction: {
              reason,
              scope,
              eventId: event.event_id,
              seq: event.seq,
              compactedTokens: 0,
            },
          },
          operatorControls: appendOperatorControlDep(latestRun.operatorControls, control),
        };
        store.runs.set(latestRun.id, updated);
        store.writeRun(updated, "thread.compact");
        return store.threadForAgent(agent);
      }
      const updatedAgent = { ...agent, updatedAt: event.created_at };
      store.agents.set(agent.id, updatedAgent);
      store.writeAgent(updatedAgent, "thread.compact");
      return store.threadForAgent(updatedAgent);
    },

    evaluateContextBudget(store, { threadId = null, runId = null, request = {} } = {}) {
      const requestedRunId = optionalStringDep(request.run_id ?? request.runId) ?? runId;
      const run = requestedRunId ? store.getRun(requestedRunId) : null;
      const requestedThreadId =
        optionalStringDep(request.thread_id ?? request.threadId) ??
        threadId ??
        (run ? threadIdForAgentDep(run.agentId) : null);
      const scope =
        optionalStringDep(request.scope) ??
        (requestedRunId ? "run" : requestedThreadId ? "thread" : "workflow");
      const usageTelemetry =
        contextBudgetUsageTelemetryFromRequestDep(request) ??
        (requestedRunId
          ? store.usageForRun(requestedRunId)
          : requestedThreadId
            ? store.usageForThread(requestedThreadId)
            : store.listUsage({ group_by: "thread" }));
      const result = evaluateContextBudgetPolicyDep({
        usageTelemetry,
        request: {
          ...request,
          scope,
          threadId: requestedThreadId,
          thread_id: requestedThreadId,
          runId: requestedRunId,
          run_id: requestedRunId,
        },
      });

      if (!requestedThreadId) return result;

      const agent = store.agentForThread(requestedThreadId);
      const latestRun = run ?? store.listRuns(agent.id).at(-1) ?? null;
      const now = new Date().toISOString();
      const eventKind =
        result.status === "blocked" ? "policy.blocked" : "context_budget.evaluated";
      const event = store.appendRuntimeEvent({
        event_stream_id: eventStreamIdForThreadDep(requestedThreadId),
        thread_id: requestedThreadId,
        turn_id: latestRun ? turnIdForRunDep(latestRun.id) : "",
        item_id: `${latestRun ? turnIdForRunDep(latestRun.id) : requestedThreadId}:item:context-budget:${safeIdDep(result.policy_decision_id)}`,
        idempotency_key:
          optionalStringDep(request.idempotency_key ?? request.idempotencyKey) ??
          `thread:${requestedThreadId}:context-budget:${safeIdDep(result.policy_decision_id)}`,
        source: operatorControlSourceDep(request.source),
        source_event_kind:
          optionalStringDep(request.eventKind ?? request.event_kind) ??
          "RuntimeContextBudget.Evaluate",
        event_kind: eventKind,
        status: result.status === "blocked" ? "blocked" : "completed",
        actor: optionalStringDep(request.actor) ?? "operator",
        created_at: now,
        workspace_root: agent.cwd,
        workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
        workflow_node_id:
          request.workflow_node_id ?? request.workflowNodeId ?? "runtime.context-budget",
        component_kind: "context_budget",
        payload_schema_version: contextBudgetSchemaVersion,
        payload_summary: result,
        receipt_refs: result.receipt_refs,
        policy_decision_refs: result.policy_decision_refs,
        artifact_refs: [],
        rollback_refs: [],
        redaction_profile: "internal",
        fixture_profile: fixtureProfileForAgentDep(agent),
      });
      return {
        ...result,
        event,
        event_id: event.event_id,
        eventId: event.event_id,
        seq: event.seq,
      };
    },

    evaluateCompactionPolicy(store, { threadId, request = {} } = {}) {
      const requestedThreadId =
        optionalStringDep(request.thread_id ?? request.threadId) ?? threadId;
      if (!requestedThreadId) {
        throw runtimeError({
          status: 400,
          code: "runtime_compaction_policy_thread_required",
          message: "Compaction policy evaluation requires a thread id.",
        });
      }
      const agent = store.agentForThread(requestedThreadId);
      const latestRun = store.listRuns(agent.id).at(-1) ?? null;
      const turnId =
        optionalStringDep(request.turn_id ?? request.turnId) ??
        (latestRun ? turnIdForRunDep(latestRun.id) : "");
      const result = evaluateCompactionPolicyDecisionDep({
        threadId: requestedThreadId,
        turnId,
        request,
      });
      const streamId = eventStreamIdForThreadDep(requestedThreadId);
      let compactEvent = null;
      if (
        result.action === "compact" &&
        result.approval_satisfied &&
        result.execute_compaction
      ) {
        const previousLatestSeq = store.latestRuntimeEventSeq(streamId);
        store.compactThread(requestedThreadId, {
          reason: result.compact_reason,
          scope: result.compact_scope,
          turn_id: turnId,
          source: request.source,
          actor: optionalStringDep(request.actor) ?? "operator",
          workflow_graph_id: result.workflow_graph_id,
          workflow_node_id: result.compact_workflow_node_id,
          idempotency_key:
            optionalStringDep(request.compact_idempotency_key ?? request.compactIdempotencyKey) ??
            `thread:${requestedThreadId}:compaction-policy:compact:${safeIdDep(result.policy_decision_id)}`,
        });
        compactEvent =
          store.runtimeEventsForStream(streamId, { sinceSeq: previousLatestSeq }).find(
            (event) => event.component_kind === "context_compaction",
          ) ?? null;
        result.compaction_executed = Boolean(compactEvent);
        result.compactionExecuted = result.compaction_executed;
        result.compaction_event_id = compactEvent?.event_id ?? null;
        result.compactionEventId = result.compaction_event_id;
        result.compaction_seq = compactEvent?.seq ?? null;
        result.compactionSeq = result.compaction_seq;
      }
      const now = new Date().toISOString();
      const eventKind =
        result.action === "stop"
          ? "policy.blocked"
          : result.action === "approval_required"
            ? "approval.required"
            : "compaction_policy.evaluated";
      const eventStatus =
        result.action === "stop"
          ? "blocked"
          : result.action === "approval_required"
            ? "waiting"
            : "completed";
      const event = store.appendRuntimeEvent({
        event_stream_id: streamId,
        thread_id: requestedThreadId,
        turn_id: turnId,
        item_id: `${turnId || requestedThreadId}:item:compaction-policy:${safeIdDep(result.policy_decision_id)}`,
        idempotency_key:
          optionalStringDep(request.idempotency_key ?? request.idempotencyKey) ??
          `thread:${requestedThreadId}:compaction-policy:${safeIdDep(result.policy_decision_id)}`,
        source: operatorControlSourceDep(request.source),
        source_event_kind:
          optionalStringDep(request.eventKind ?? request.event_kind) ??
          "RuntimeCompactionPolicy.Evaluate",
        event_kind: eventKind,
        status: eventStatus,
        actor: optionalStringDep(request.actor) ?? "operator",
        created_at: now,
        workspace_root: agent.cwd,
        workflow_graph_id: result.workflow_graph_id,
        workflow_node_id: result.workflow_node_id,
        approval_id: result.approval_id,
        component_kind: "compaction_policy",
        payload_schema_version: compactionPolicySchemaVersion,
        payload_summary: result,
        receipt_refs: result.receipt_refs,
        policy_decision_refs: result.policy_decision_refs,
        artifact_refs: compactEvent ? compactEvent.artifact_refs : [],
        rollback_refs: [],
        redaction_profile: "internal",
        fixture_profile: fixtureProfileForAgentDep(agent),
      });
      return {
        ...result,
        event,
        event_id: event.event_id,
        eventId: event.event_id,
        seq: event.seq,
      };
    },
  };
}
