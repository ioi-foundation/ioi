import { eventStreamIdForThread } from "../runtime-identifiers.mjs";
import { runtimeError } from "../runtime-http-utils.mjs";
import { normalizeArray, objectRecord, optionalString } from "../runtime-value-helpers.mjs";

const THREAD_FORK_CONTROL_EVIDENCE_REFS = [
  "runtime_thread_fork_control_rust_owned",
  "runtime_thread_fork_event_rust_owned",
  "runtime_thread_fork_js_facade_retired",
  "agentgres_thread_fork_state_truth_required",
];

function stringRefs(values) {
  return normalizeArray(values).map((value) => String(value)).filter(Boolean);
}

function threadForkRunner(store, request = {}, deps = {}) {
  const runner = deps.contextPolicyCore;
  if (
    runner?.planRuntimeThreadForkControl &&
    typeof store?.writeAgent === "function" &&
    typeof store?.appendRuntimeEvent === "function" &&
    typeof store?.threadForAgent === "function"
  ) {
    return runner;
  }
  throw runtimeError({
    status: 501,
    code: "runtime_thread_fork_rust_core_required",
    message:
      "Runtime thread fork requires direct Rust daemon-core planning, Agentgres state commit, runtime-event admission, and projection.",
    details: {
      rust_core_boundary: "runtime.thread_fork_control",
      operation: "thread_fork",
      operation_kind: "thread.fork",
      thread_id: request.thread_id ?? null,
      idempotency_key: request.idempotency_key ?? null,
      evidence_refs: THREAD_FORK_CONTROL_EVIDENCE_REFS,
    },
  });
}

function threadForkRequestPayload(request = {}) {
  const payload = {};
  for (const key of [
    "source",
    "workspace_root",
    "turn_id",
    "event_id",
    "event_seed",
    "idempotency_key",
    "receipt_refs",
    "policy_decision_refs",
    "artifact_refs",
    "fixture_profile",
    "reason",
    "requested_by",
    "created_at",
    "workflow_graph_id",
    "workflow_node_id",
  ]) {
    if (Object.hasOwn(request, key)) payload[key] = request[key];
  }
  return payload;
}

function assertThreadForkPlan(planned = {}, { threadId }) {
  const record = objectRecord(planned);
  const event = objectRecord(record?.event);
  const agent = objectRecord(record?.agent);
  const thread = objectRecord(record?.thread);
  const forkedThreadId = optionalString(record?.forked_thread_id);
  const agentId = optionalString(record?.agent_id);
  if (record?.operation_kind !== "thread.fork") {
    throw runtimeError({
      status: 502,
      code: "runtime_thread_fork_control_operation_kind_invalid",
      message: "Rust thread-fork control returned an invalid operation kind.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
      },
    });
  }
  if (record?.thread_id !== threadId) {
    throw runtimeError({
      status: 502,
      code: "runtime_thread_fork_control_thread_mismatch",
      message: "Rust thread-fork control returned a different source thread.",
      details: {
        thread_id: threadId,
        planned_thread_id: record?.thread_id ?? null,
      },
    });
  }
  if (!agent || !agentId || optionalString(agent.id) !== agentId) {
    throw runtimeError({
      status: 502,
      code: "runtime_thread_fork_control_agent_invalid",
      message: "Rust thread-fork control returned an invalid forked agent.",
      details: {
        thread_id: threadId,
        agent_id: agentId ?? null,
      },
    });
  }
  if (!thread || !forkedThreadId || optionalString(thread.thread_id) !== forkedThreadId) {
    throw runtimeError({
      status: 502,
      code: "runtime_thread_fork_control_thread_projection_invalid",
      message: "Rust thread-fork control returned an invalid forked thread projection.",
      details: {
        thread_id: threadId,
        forked_thread_id: forkedThreadId ?? null,
      },
    });
  }
  if (optionalString(thread.agent_id) !== agentId) {
    throw runtimeError({
      status: 502,
      code: "runtime_thread_fork_control_thread_agent_mismatch",
      message: "Rust thread-fork control returned mismatched forked agent and thread ids.",
      details: {
        thread_id: threadId,
        forked_thread_id: forkedThreadId,
        agent_id: agentId,
        thread_agent_id: thread.agent_id ?? null,
      },
    });
  }
  if (!event || event.event_kind !== "thread.forked") {
    throw runtimeError({
      status: 502,
      code: "runtime_thread_fork_control_event_invalid",
      message: "Rust thread-fork control did not return a valid fork event.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
        forked_thread_id: forkedThreadId ?? null,
      },
    });
  }
  return { event, agent, thread };
}

function assertThreadForkProjection(projection, plannedThread, { threadId }) {
  const projected = objectRecord(projection);
  if (!projected || projected.thread_id !== plannedThread.thread_id) {
    throw runtimeError({
      status: 502,
      code: "runtime_thread_fork_projection_mismatch",
      message: "Rust thread-fork Agentgres projection returned a different forked thread.",
      details: {
        thread_id: threadId,
        forked_thread_id: plannedThread.thread_id ?? null,
        projected_thread_id: projected?.thread_id ?? null,
      },
    });
  }
  return projected;
}

async function sourceAgentForThread(store, threadId) {
  if (typeof store?.agentForThread !== "function") return null;
  return objectRecord(await store.agentForThread(threadId));
}

async function sourceThreadForAgent(store, sourceAgent, threadId) {
  if (typeof store?.threadForAgent === "function") {
    const projected = objectRecord(await store.threadForAgent(sourceAgent));
    if (projected) return projected;
  }
  return {
    thread_id: threadId,
    agent_id: sourceAgent.id,
    event_stream_id: eventStreamIdForThread(threadId),
  };
}

export function createThreadForkState() {
  async function forkThread(store, threadId, request = {}, deps = {}) {
    const normalizedRequest = objectRecord(request) ?? {};
    const runner = threadForkRunner(store, {
      thread_id: threadId,
      idempotency_key: optionalString(normalizedRequest.idempotency_key) ?? null,
    }, deps);
    const sourceAgent = await sourceAgentForThread(store, threadId);
    if (!sourceAgent) {
      throw runtimeError({
        status: 404,
        code: "runtime_thread_fork_source_agent_not_found",
        message: "Runtime thread fork could not find the source thread agent.",
        details: {
          rust_core_boundary: "runtime.thread_fork_control",
          operation: "thread_fork",
          operation_kind: "thread.fork",
          thread_id: threadId,
          evidence_refs: THREAD_FORK_CONTROL_EVIDENCE_REFS,
        },
      });
    }
    const sourceThread = await sourceThreadForAgent(store, sourceAgent, threadId);
    const requestPayload = threadForkRequestPayload(normalizedRequest);
    const eventStreamId = optionalString(sourceThread.event_stream_id) ?? eventStreamIdForThread(threadId);
    const planned = await runner.planRuntimeThreadForkControl({
      operation: "thread_fork",
      operation_kind: "thread.fork",
      thread_id: threadId,
      event_stream_id: eventStreamId,
      source_thread: {
        ...sourceThread,
        thread_id: optionalString(sourceThread.thread_id) ?? threadId,
        agent_id: optionalString(sourceThread.agent_id) ?? sourceAgent.id,
        event_stream_id: eventStreamId,
      },
      source_agent: sourceAgent,
      request: requestPayload,
      receipt_refs: stringRefs(normalizedRequest.receipt_refs),
      policy_decision_refs: stringRefs(normalizedRequest.policy_decision_refs),
      evidence_refs: THREAD_FORK_CONTROL_EVIDENCE_REFS,
    });
    const { event, agent, thread } = assertThreadForkPlan(planned, { threadId });
    store.writeAgent(agent, planned.operation_kind);
    if (typeof store.ensureThreadStartedEvent === "function") {
      await store.ensureThreadStartedEvent(agent);
    }
    const projection = assertThreadForkProjection(await store.threadForAgent(agent), thread, {
      threadId,
    });
    await store.appendRuntimeEvent(event);
    return projection;
  }

  return {
    forkThread,
  };
}
