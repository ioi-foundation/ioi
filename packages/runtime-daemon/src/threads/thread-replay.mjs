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
