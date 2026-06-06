import {
  RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
  RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import { createContextPolicyRunnerFromEnv } from "./runtime-context-policy-runner.mjs";
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
} from "./runtime-value-helpers.mjs";

export function createRuntimeContextPolicySurface({
  RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION: compactionPolicySchemaVersion = RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
  RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION: contextBudgetSchemaVersion = RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
  appendOperatorControl: appendOperatorControlDep = appendOperatorControl,
  contextPolicyRunner: contextPolicyRunnerDep = createContextPolicyRunnerFromEnv(),
  contextBudgetUsageTelemetryFromRequest: contextBudgetUsageTelemetryFromRequestDep = contextBudgetUsageTelemetryFromRequest,
  evaluateCompactionPolicyDecision: evaluateCompactionPolicyDecisionDep = evaluateCompactionPolicyDecision,
  evaluateContextBudgetPolicy: evaluateContextBudgetPolicyDep = evaluateContextBudgetPolicy,
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  fixtureProfileForAgent: fixtureProfileForAgentDep = fixtureProfileForAgent,
  operatorControlSource: operatorControlSourceDep = operatorControlSource,
  optionalString: optionalStringDep = optionalString,
  runtimeError,
  runtimeSessionIdForAgent: runtimeSessionIdForAgentDep = runtimeSessionIdForAgent,
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
      const now = new Date().toISOString();
      const streamId = eventStreamIdForThreadDep(threadId);
      const previousLatestSeq = store.latestRuntimeEventSeq(streamId);
      const plan = contextPolicyRunnerDep.planContextCompaction({
        thread_id: threadId,
        agent_id: agent.id,
        turn_id: turnId || null,
        run_id: latestRun?.id ?? null,
        session_id: runtimeSessionIdForAgentDep(agent),
        workspace_root: agent.cwd,
        reason: optionalStringDep(request.reason ?? request.message ?? request.input) ?? null,
        scope: optionalStringDep(request.scope) ?? null,
        source: optionalStringDep(request.source) ?? null,
        requested_by: optionalStringDep(request.actor ?? request.requested_by ?? request.requestedBy) ?? null,
        workflow_graph_id: optionalStringDep(request.workflow_graph_id ?? request.workflowGraphId) ?? null,
        workflow_node_id: optionalStringDep(request.workflow_node_id ?? request.workflowNodeId) ?? null,
        event_stream_id: streamId,
        previous_latest_seq: previousLatestSeq,
        idempotency_key: optionalStringDep(request.idempotency_key ?? request.idempotencyKey) ?? null,
      });
      const source = plan.event_source ?? operatorControlSourceDep(request.source);
      const reason =
        optionalStringDep(plan.reason ?? plan.payload?.reason) ?? "operator requested context compaction";
      const scope = optionalStringDep(plan.scope ?? plan.payload?.scope) ?? "thread";
      const event = store.appendRuntimeEvent({
        event_stream_id: streamId,
        thread_id: plan.thread_id ?? threadId,
        turn_id: plan.turn_id ?? turnId,
        item_id: plan.item_id,
        idempotency_key: plan.idempotency_key,
        source,
        source_event_kind: plan.source_event_kind,
        event_kind: plan.event_kind,
        status: "completed",
        actor: plan.actor ?? "user",
        created_at: now,
        workspace_root: plan.workspace_root ?? agent.cwd,
        workflow_graph_id: plan.workflow_graph_id ?? null,
        workflow_node_id: plan.workflow_node_id ?? "runtime.context-compact",
        component_kind: plan.component_kind,
        payload_schema_version: plan.payload_schema_version,
        payload: plan.payload,
        receipt_refs: plan.receipt_refs,
        policy_decision_refs: plan.policy_decision_refs,
        artifact_refs: plan.artifact_refs,
        rollback_refs: plan.rollback_refs,
        redaction_profile: plan.redaction_profile,
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
      let eventAgent = null;
      let eventLatestRun = run ?? null;
      if (requestedThreadId && !eventLatestRun) {
        eventAgent = store.agentForThread(requestedThreadId);
        eventLatestRun = store.listRuns(eventAgent.id).at(-1) ?? null;
      }
      const eventTurnId =
        optionalStringDep(request.turn_id ?? request.turnId) ??
        (eventLatestRun ? turnIdForRunDep(eventLatestRun.id) : null);
      const result = evaluateContextBudgetPolicyDep({
        usageTelemetry,
        request: {
          ...request,
          scope,
          threadId: requestedThreadId,
          thread_id: requestedThreadId,
          turnId: eventTurnId,
          turn_id: eventTurnId,
          runId: requestedRunId,
          run_id: requestedRunId,
        },
      });

      if (!requestedThreadId) return result;

      const agent = eventAgent ?? store.agentForThread(requestedThreadId);
      const now = new Date().toISOString();
      const event = store.appendRuntimeEvent({
        event_stream_id: eventStreamIdForThreadDep(requestedThreadId),
        thread_id: requestedThreadId,
        turn_id: eventTurnId ?? "",
        item_id: result.runtime_event_item_id,
        idempotency_key:
          optionalStringDep(request.idempotency_key ?? request.idempotencyKey) ??
          result.runtime_event_idempotency_key,
        source: operatorControlSourceDep(request.source),
        source_event_kind:
          optionalStringDep(request.eventKind ?? request.event_kind) ??
          "RuntimeContextBudget.Evaluate",
        event_kind: result.runtime_event_kind,
        status: result.runtime_event_status,
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
            result.compact_idempotency_key,
        });
        compactEvent =
          store.runtimeEventsForStream(streamId, { sinceSeq: previousLatestSeq }).find(
            (event) => event.component_kind === "context_compaction",
          ) ?? null;
        result.compaction_executed = Boolean(compactEvent);
        result.compaction_event_id = compactEvent?.event_id ?? null;
        result.compaction_seq = compactEvent?.seq ?? null;
      }
      const now = new Date().toISOString();
      const event = store.appendRuntimeEvent({
        event_stream_id: streamId,
        thread_id: requestedThreadId,
        turn_id: turnId,
        item_id: result.runtime_event_item_id,
        idempotency_key:
          optionalStringDep(request.idempotency_key ?? request.idempotencyKey) ??
          result.runtime_event_idempotency_key,
        source: operatorControlSourceDep(request.source),
        source_event_kind:
          optionalStringDep(request.eventKind ?? request.event_kind) ??
          "RuntimeCompactionPolicy.Evaluate",
        event_kind: result.runtime_event_kind,
        status: result.runtime_event_status,
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
