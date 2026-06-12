import {
  appendRuntimeEvent as appendRuntimeEventState,
  assertRuntimeCursorSeq as assertRuntimeCursorSeqState,
  ensureThreadStartedEvent as ensureThreadStartedEventState,
  latestRuntimeEventSeq as latestRuntimeEventSeqState,
  projectRunEvents as projectRunEventsState,
  projectThreadEvents as projectThreadEventsState,
  registerRuntimeEvent as registerRuntimeEventState,
  runtimeCursorSeq as runtimeCursorSeqState,
  runtimeEventsForStream as runtimeEventsForStreamState,
  runtimeEventsForTurn as runtimeEventsForTurnState,
  runtimeEventStream as runtimeEventStreamState,
  runtimeEventStreamPath as runtimeEventStreamPathState,
} from "./threads/thread-replay.mjs";

function defaultNotFound(message, details = {}) {
  const error = new Error(message);
  error.status = 404;
  error.details = details;
  return error;
}

export function createRuntimeThreadEventSurface({
  DAEMON_FIXTURE_PROFILE: daemonFixtureProfile,
  RUNTIME_THREAD_SCHEMA_VERSION: runtimeThreadSchemaVersion,
  appendRuntimeEvent: appendRuntimeEventDep = appendRuntimeEventState,
  assertRuntimeCursorSeq: assertRuntimeCursorSeqDep = assertRuntimeCursorSeqState,
  ensureThreadStartedEvent: ensureThreadStartedEventDep = ensureThreadStartedEventState,
  eventStreamIdForThread,
  fs,
  isRuntimeBackedAgent,
  latestRuntimeEventSeq: latestRuntimeEventSeqDep = latestRuntimeEventSeqState,
  normalizeRuntimeEventEnvelope,
  notFound = defaultNotFound,
  projectRunEvents: projectRunEventsDep = projectRunEventsState,
  projectThreadEvents: projectThreadEventsDep = projectThreadEventsState,
  registerRuntimeEvent: registerRuntimeEventDep = registerRuntimeEventState,
  runtimeCursorSeq: runtimeCursorSeqDep = runtimeCursorSeqState,
  runtimeError,
  runtimeEventsForStream: runtimeEventsForStreamDep = runtimeEventsForStreamState,
  runtimeEventsForTurn: runtimeEventsForTurnDep = runtimeEventsForTurnState,
  runtimeEventStream: runtimeEventStreamDep = runtimeEventStreamState,
  runtimeEventStreamFileName,
  runtimeEventStreamPath: runtimeEventStreamPathDep = runtimeEventStreamPathState,
  runtimeTurnIdForRun,
  threadIdForAgent,
  threadStatusForAgent,
  threadTurnProjection,
  turnIdForRun,
} = {}) {
  return {
    listTurns(store, threadId) {
      const agent = store.agentForThread(threadId);
      return store.listRuns(agent.id).map((run) => store.turnForRun(run));
    },
    getTurn(store, threadId, turnId) {
      const turn = this.listTurns(store, threadId).find(
        (candidate) => candidate.turn_id === turnId,
      );
      if (!turn) throw notFound(`Turn not found: ${turnId}`, { threadId, turnId });
      return turn;
    },
    eventsForThread(store, threadId, cursor = {}) {
      const agent = store.agentForThread(threadId);
      store.projectThreadEvents(agent);
      return store.runtimeEventsForStream(
        eventStreamIdForThread(threadIdForAgent(agent.id)),
        cursor,
      );
    },
    eventsForRun(store, runId, cursor = {}) {
      const run = store.getRun(runId);
      const agent = store.getAgent(run.agentId);
      store.projectThreadEvents(agent);
      return store.runtimeEventsForTurn(runtimeTurnIdForRun(run), cursor);
    },
    ensureThreadStartedEvent(store, agent) {
      return ensureThreadStartedEventDep(store, agent, {
        DAEMON_FIXTURE_PROFILE: daemonFixtureProfile,
        RUNTIME_THREAD_SCHEMA_VERSION: runtimeThreadSchemaVersion,
        eventStreamIdForThread,
        runtimeError,
        threadIdForAgent,
        threadStatusForAgent,
      });
    },
    projectThreadEvents(store, agent) {
      return projectThreadEventsDep(store, agent, { isRuntimeBackedAgent, runtimeError });
    },
    projectRunEvents(store, run, agent = store.getAgent(run.agentId)) {
      return projectRunEventsDep(store, run, agent, {
        isRuntimeBackedAgent,
        runtimeError,
        threadIdForAgent,
        turnIdForRun,
      });
    },
    appendRuntimeEvent(store, event) {
      return appendRuntimeEventDep(store, event, {
        fs,
        normalizeRuntimeEventEnvelope,
        runtimeError,
      });
    },
    runtimeEventsForStream(store, eventStreamId, cursor = {}) {
      return runtimeEventsForStreamDep(store, eventStreamId, cursor, { runtimeError });
    },
    runtimeEventsForTurn(store, turnId, cursor = {}) {
      return runtimeEventsForTurnDep(store, turnId, cursor, { runtimeError });
    },
    runtimeCursorSeq(store, stream, cursor = {}) {
      return runtimeCursorSeqDep(store, stream, cursor, { runtimeError });
    },
    assertRuntimeCursorSeq(cursorSeq, latestSeq, details = {}) {
      return assertRuntimeCursorSeqDep(cursorSeq, latestSeq, details, { runtimeError });
    },
    latestRuntimeEventSeq(store, eventStreamId) {
      return latestRuntimeEventSeqDep(store, eventStreamId);
    },
    runtimeEventStream(store, eventStreamId) {
      return runtimeEventStreamDep(store, eventStreamId);
    },
    registerRuntimeEvent(store, record) {
      return registerRuntimeEventDep(store, record);
    },
    runtimeEventStreamPath(store, eventStreamId) {
      return runtimeEventStreamPathDep(store, eventStreamId, {
        runtimeEventStreamFileName,
      });
    },
    threadForAgent(store, agent) {
      return threadTurnProjection.threadForAgent(store, agent);
    },
    turnForRun(store, run) {
      return threadTurnProjection.turnForRun(store, run);
    },
  };
}
