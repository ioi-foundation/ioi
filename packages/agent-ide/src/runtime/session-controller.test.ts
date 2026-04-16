import assert from "node:assert/strict";
import {
  mergeSessionSnapshotCollection,
  resolveNullProjectionRecoverySessionId,
  shouldRetainHydratedThreadCollections,
} from "./session-controller.ts";

const retainedRunningTask = {
  id: "session-123",
  session_id: "session-123",
  phase: "Running",
  current_step:
    "Session state is reconciling, but the first step was queued using the committed bootstrap nonce.",
  background_tasks: [],
};

const completedSessionSummary = {
  session_id: "session-123",
  title: "Currentness lookup",
  timestamp: Date.now(),
  phase: "Complete",
  current_step: "Ready for input",
  resume_hint: null,
  workspace_root: null,
};

const liveSessionSummary = {
  ...completedSessionSummary,
  phase: "Running",
  current_step: "Routing the request...",
};

assert.equal(
  resolveNullProjectionRecoverySessionId(retainedRunningTask, [
    completedSessionSummary,
  ]),
  "session-123",
);

assert.equal(
  resolveNullProjectionRecoverySessionId(retainedRunningTask, [liveSessionSummary]),
  null,
);

assert.equal(resolveNullProjectionRecoverySessionId(null, [completedSessionSummary]), null);

assert.equal(
  shouldRetainHydratedThreadCollections(
    { session_id: "session-123" },
    { session_id: "session-123" },
  ),
  true,
);

assert.equal(
  shouldRetainHydratedThreadCollections(
    { session_id: "session-123" },
    { session_id: "session-456" },
  ),
  false,
);

assert.deepEqual(
  mergeSessionSnapshotCollection(
    [{ event_id: "evt-1" }],
    [{ event_id: "evt-1" }, { event_id: "evt-2" }],
    (
      items: Array<{ event_id: string }>,
      next: { event_id: string },
    ) =>
      items.some((item) => item.event_id === next.event_id) ? items : [...items, next],
  ),
  [{ event_id: "evt-1" }, { event_id: "evt-2" }],
);

console.log("session-controller recovery tests passed");
