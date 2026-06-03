export function appendRuntimeEvent(store, event, deps = {}) {
  const { fs, normalizeRuntimeEventEnvelope, runtimeError } = deps;
  const streamId = event.event_stream_id;
  if (!streamId) {
    throw runtimeError({
      status: 400,
      code: "runtime_event_stream_required",
      message: "Runtime events require event_stream_id.",
      details: { eventKind: event.event_kind ?? event.event ?? null },
    });
  }
  const stream = store.runtimeEventStream(streamId);
  const idempotencyKey = String(event.idempotency_key ?? event.event_id ?? "");
  if (!idempotencyKey) {
    throw runtimeError({
      status: 400,
      code: "runtime_event_idempotency_required",
      message: "Runtime events require idempotency_key.",
      details: { eventStreamId: streamId, eventKind: event.event_kind ?? event.event ?? null },
    });
  }
  const duplicate = stream.idempotency.get(idempotencyKey);
  if (duplicate) return duplicate;

  const seq = stream.events.length + 1;
  const record = normalizeRuntimeEventEnvelope(event, {
    seq,
    parentSeq: seq > 1 ? stream.events.at(-1).seq : null,
    idempotencyKey,
  });
  stream.events.push(record);
  stream.idempotency.set(record.idempotency_key, record);
  fs.appendFileSync(store.runtimeEventStreamPath(streamId), `${JSON.stringify(record)}\n`);
  return record;
}

export function ensureThreadStartedEvent(store, agent, deps = {}) {
  const {
    DAEMON_FIXTURE_PROFILE,
    RUNTIME_THREAD_SCHEMA_VERSION,
    eventStreamIdForThread,
    threadIdForAgent,
    threadStatusForAgent,
  } = deps;
  const threadId = threadIdForAgent(agent.id);
  return store.appendRuntimeEvent({
    event_stream_id: eventStreamIdForThread(threadId),
    thread_id: threadId,
    turn_id: "",
    item_id: `${threadId}:item:thread-started`,
    idempotency_key: `agent:${agent.id}:thread.started`,
    source: "daemon_bridge",
    source_event_kind: "agent.create",
    event_kind: "thread.started",
    status: threadStatusForAgent(agent.status),
    actor: "runtime",
    created_at: agent.createdAt,
    workspace_root: agent.cwd,
    component_kind: "runtime_thread",
    workflow_node_id: "runtime.runtime-thread",
    payload_schema_version: RUNTIME_THREAD_SCHEMA_VERSION,
    payload: {
      event_kind: "ThreadStarted",
      agent_id: agent.id,
      thread_id: threadId,
      status: threadStatusForAgent(agent.status),
    },
    artifact_refs: [],
    receipt_refs: [agent.modelRouteReceiptId].filter(Boolean),
    fixture_profile: DAEMON_FIXTURE_PROFILE,
  });
}

export function projectThreadEvents(store, agent, deps = {}) {
  const { isRuntimeBackedAgent } = deps;
  if (isRuntimeBackedAgent(agent)) return;
  store.ensureThreadStartedEvent(agent);
  for (const run of store.listRuns(agent.id)) {
    store.projectRunEvents(run, agent);
  }
}

export function projectRunEvents(store, run, agent, deps = {}) {
  const {
    isRuntimeBackedAgent,
    threadIdForAgent,
    ttiEnvelopeForRunEvent,
    turnIdForRun,
  } = deps;
  if (isRuntimeBackedAgent(agent)) return;
  const threadId = threadIdForAgent(agent.id);
  const turnId = turnIdForRun(run.id);
  for (const event of run.events) {
    store.appendRuntimeEvent(
      ttiEnvelopeForRunEvent({
        event,
        threadId,
        turnId,
        workspaceRoot: agent.cwd,
      }),
    );
  }
}

export function runtimeEventsForStream(store, eventStreamId, cursor = {}) {
  const stream = store.runtimeEventStream(eventStreamId);
  const cursorSeq = store.runtimeCursorSeq(stream, cursor);
  return stream.events.filter((event) => event.seq > cursorSeq);
}

export function runtimeEventsForTurn(store, turnId, cursor = {}) {
  const events = [...store.runtimeEventStreams.values()]
    .flatMap((stream) => stream.events)
    .filter((event) => event.turn_id === turnId)
    .sort((left, right) => left.seq - right.seq);
  if (!events.length) return [];
  const stream = store.runtimeEventStream(events[0].event_stream_id);
  const cursorSeq = store.runtimeCursorSeq(stream, cursor);
  return events.filter((event) => event.seq > cursorSeq);
}

export function runtimeCursorSeq(store, stream, cursor = {}, deps = {}) {
  const { runtimeError } = deps;
  const latestSeq = stream.events.at(-1)?.seq ?? 0;
  if (typeof cursor === "number") {
    return store.assertRuntimeCursorSeq(Number(cursor) || 0, latestSeq, {
      eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
      sinceSeq: Number(cursor) || 0,
    });
  }
  if (typeof cursor === "string") {
    return store.runtimeCursorSeq(stream, { lastEventId: cursor });
  }
  if (cursor.sinceSeq !== null && cursor.sinceSeq !== undefined) {
    return store.assertRuntimeCursorSeq(Number(cursor.sinceSeq) || 0, latestSeq, {
      eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
      sinceSeq: Number(cursor.sinceSeq) || 0,
    });
  }
  const lastEventId = String(cursor.lastEventId ?? "").trim();
  if (!lastEventId) return 0;
  if (/^\d+$/.test(lastEventId)) {
    return store.assertRuntimeCursorSeq(Number(lastEventId), latestSeq, {
      eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
      lastEventId,
    });
  }
  const match = stream.events.find((event) => event.event_id === lastEventId || event.id === lastEventId);
  if (match) return match.seq;
  throw runtimeError({
    status: 409,
    code: "event_cursor_out_of_range",
    message: "Runtime event cursor does not exist in this stream.",
    details: {
      eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
      lastEventId,
      latestSeq,
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
      details: { ...details, sinceSeq: cursorSeq, latestSeq },
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
