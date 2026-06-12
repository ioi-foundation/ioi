export function appendRuntimeEvent(store, event, deps = {}) {
  const { runtimeError } = deps;
  const streamId = event.event_stream_id;
  const idempotencyKey = String(event.idempotency_key ?? event.event_id ?? "");
  if (typeof store.admitRuntimeThreadEventForThread === "function") {
    return store.admitRuntimeThreadEventForThread(store, { event });
  }
  throwRuntimeThreadEventRustCoreRequired(runtimeError, "runtime_event_append", "runtime.event.append", {
    event_stream_id: streamId ?? null,
    thread_id: event.thread_id ?? null,
    turn_id: event.turn_id ?? null,
    item_id: event.item_id ?? null,
    event_kind: event.event_kind ?? event.event ?? null,
    idempotency_key: idempotencyKey || null,
    evidence_refs: [
      "runtime_thread_event_js_append_retired",
      "rust_daemon_core_thread_event_admission_required",
      "agentgres_thread_event_truth_required",
    ],
  });
}

export function ensureThreadStartedEvent(store, agent, deps = {}) {
  const {
    runtimeError,
    threadIdForAgent,
  } = deps;
  const threadId = threadIdForAgent(agent.id);
  if (typeof store.projectRuntimeThreadEventsForThread === "function") {
    return store.projectRuntimeThreadEventsForThread(store, {
      projection_kind: "thread_started",
      agent,
    });
  }
  throwRuntimeThreadEventRustCoreRequired(runtimeError, "thread_started_event_admission", "thread.started", {
    agent_id: agent.id,
    thread_id: threadId,
    status: agent.status ?? null,
    model_route_receipt_id: agent.modelRouteReceiptId ?? null,
    evidence_refs: [
      "runtime_thread_started_js_projection_retired",
      "rust_daemon_core_thread_started_event_required",
      "agentgres_thread_event_truth_required",
    ],
  });
}

export function projectThreadEvents(store, agent, deps = {}) {
  const { isRuntimeBackedAgent, runtimeError } = deps;
  if (isRuntimeBackedAgent(agent)) return;
  if (typeof store.projectRuntimeThreadEventsForThread === "function") {
    return store.projectRuntimeThreadEventsForThread(store, {
      projection_kind: "thread",
      agent,
      runs: typeof store.listRuns === "function" ? store.listRuns(agent.id) : [],
    });
  }
  throwRuntimeThreadEventRustCoreRequired(runtimeError, "thread_event_projection", "runtime.thread_event_projection", {
    agent_id: agent.id,
    evidence_refs: [
      "runtime_thread_event_js_projection_retired",
      "rust_daemon_core_thread_event_projection_required",
      "agentgres_thread_event_truth_required",
    ],
  });
}

export function projectRunEvents(store, run, agent, deps = {}) {
  const {
    isRuntimeBackedAgent,
    runtimeError,
    threadIdForAgent,
    turnIdForRun,
  } = deps;
  if (isRuntimeBackedAgent(agent)) return;
  const threadId = threadIdForAgent(agent.id);
  const turnId = turnIdForRun(run.id);
  if (typeof store.projectRuntimeThreadEventsForThread === "function") {
    return store.projectRuntimeThreadEventsForThread(store, {
      projection_kind: "run",
      agent,
      runs: [run],
    });
  }
  throwRuntimeThreadEventRustCoreRequired(runtimeError, "run_event_projection", "runtime.run_event_projection", {
    agent_id: agent.id,
    run_id: run.id,
    thread_id: threadId,
    turn_id: turnId,
    event_count: Array.isArray(run.events) ? run.events.length : 0,
    evidence_refs: [
      "runtime_run_event_js_projection_retired",
      "rust_daemon_core_run_event_projection_required",
      "agentgres_thread_event_truth_required",
    ],
  });
}

export function runtimeEventsForStream(store, eventStreamId, cursor = {}, deps = {}) {
  const { runtimeError } = deps;
  if (typeof store.projectRuntimeThreadEventReplayForThread === "function") {
    const replay = store.projectRuntimeThreadEventReplayForThread(store, {
      replay_kind: "stream",
      event_stream_id: eventStreamId,
      cursor,
    });
    return Array.isArray(replay?.events) ? replay.events : [];
  }
  throwRuntimeThreadEventRustCoreRequired(runtimeError, "stream_event_replay", "runtime.thread_event_replay", {
    event_stream_id: eventStreamId,
    evidence_refs: [
      "runtime_thread_event_js_replay_retired",
      "rust_daemon_core_thread_event_replay_required",
      "agentgres_thread_event_truth_required",
    ],
  });
}

export function runtimeEventsForTurn(store, turnId, cursor = {}, deps = {}) {
  const { runtimeError } = deps;
  if (typeof store.projectRuntimeThreadEventReplayForThread === "function") {
    const replay = store.projectRuntimeThreadEventReplayForThread(store, {
      replay_kind: "turn",
      turn_id: turnId,
      cursor,
    });
    return Array.isArray(replay?.events) ? replay.events : [];
  }
  throwRuntimeThreadEventRustCoreRequired(runtimeError, "turn_event_replay", "runtime.thread_event_replay", {
    turn_id: turnId,
    evidence_refs: [
      "runtime_thread_event_js_replay_retired",
      "rust_daemon_core_thread_event_replay_required",
      "agentgres_thread_event_truth_required",
    ],
  });
}

export function runtimeCursorSeq(store, stream, cursor = {}, deps = {}) {
  const { runtimeError } = deps;
  const latestSeq = stream.events.at(-1)?.seq ?? 0;
  if (typeof cursor === "number") {
    return store.assertRuntimeCursorSeq(Number(cursor) || 0, latestSeq, {
      event_stream_id: stream.events.at(-1)?.event_stream_id ?? null,
      since_seq: Number(cursor) || 0,
    });
  }
  if (typeof cursor === "string") {
    return store.runtimeCursorSeq(stream, { last_event_id: cursor });
  }
  if (cursor.since_seq !== null && cursor.since_seq !== undefined) {
    return store.assertRuntimeCursorSeq(Number(cursor.since_seq) || 0, latestSeq, {
      event_stream_id: stream.events.at(-1)?.event_stream_id ?? null,
      since_seq: Number(cursor.since_seq) || 0,
    });
  }
  const last_event_id = String(cursor.last_event_id ?? "").trim();
  if (!last_event_id) return 0;
  if (/^\d+$/.test(last_event_id)) {
    return store.assertRuntimeCursorSeq(Number(last_event_id), latestSeq, {
      event_stream_id: stream.events.at(-1)?.event_stream_id ?? null,
      last_event_id,
    });
  }
  const match = stream.events.find((event) => event.event_id === last_event_id);
  if (match) return match.seq;
  throw runtimeError({
    status: 409,
    code: "event_cursor_out_of_range",
    message: "Runtime event cursor does not exist in this stream.",
    details: {
      event_stream_id: stream.events.at(-1)?.event_stream_id ?? null,
      last_event_id,
      latest_seq: latestSeq,
    },
  });
}

export function assertRuntimeCursorSeq(cursorSeq, latestSeq, details = {}, deps = {}) {
  const { runtimeError } = deps;
  if (cursorSeq > latestSeq) {
    throw runtimeError({
      status: 409,
      code: "event_cursor_out_of_range",
      message: "Runtime event cursor is beyond the latest committed sequence.",
      details: { ...details, since_seq: cursorSeq, latest_seq: latestSeq },
    });
  }
  return cursorSeq;
}

export function latestRuntimeEventSeq(store, eventStreamId) {
  return store.runtimeEventStream(eventStreamId).events.at(-1)?.seq ?? 0;
}

export function runtimeEventStream(store, eventStreamId) {
  const key = String(eventStreamId);
  let stream = store.runtimeEventStreams.get(key);
  if (!stream) {
    stream = { events: [], idempotency: new Map() };
    store.runtimeEventStreams.set(key, stream);
  }
  return stream;
}

export function registerRuntimeEvent(store, record) {
  const stream = store.runtimeEventStream(record.event_stream_id);
  if (stream.idempotency.has(record.idempotency_key)) return;
  stream.events.push(record);
  stream.events.sort((left, right) => left.seq - right.seq);
  stream.idempotency.set(record.idempotency_key, record);
}

export function runtimeEventStreamPath(store, eventStreamId, deps = {}) {
  const { runtimeEventStreamFileName } = deps;
  return store.pathFor("events", `${runtimeEventStreamFileName(eventStreamId)}.jsonl`);
}

function throwRuntimeThreadEventRustCoreRequired(runtimeError, operation, operationKind, details = {}) {
  throw runtimeError({
    status: 501,
    code: "runtime_thread_event_rust_core_required",
    message: "Runtime thread event admission requires direct Rust daemon-core admission and persistence.",
    details: {
      rust_core_boundary: "runtime.thread_event",
      operation,
      operation_kind: operationKind,
      ...details,
    },
  });
}
