import { cancelRun } from "./runtime-run-cancellation.mjs";
import {
  controlManagedSessionForThread,
  inspectManagedSessionsForThread,
} from "./threads/managed-session-state.mjs";
import { createThreadForkState } from "./threads/thread-fork-state.mjs";
import {
  controlWorkspaceChangeForThread,
  inspectWorkspaceChangeReviewsForThread,
} from "./threads/workspace-change-state.mjs";

export function createRuntimeThreadAuxiliarySurface({
  threadForkState = createThreadForkState(),
} = {}) {
  return {
    async inspectManagedSessionsForThread(store, threadId, request = {}) {
      return inspectManagedSessionsForThread(store, threadId, request);
    },
    async inspectWorkspaceChangeReviewsForThread(store, threadId, request = {}) {
      return inspectWorkspaceChangeReviewsForThread(store, threadId, request);
    },
    async controlWorkspaceChangeForThread(store, threadId, request = {}) {
      return controlWorkspaceChangeForThread(store, threadId, request);
    },
    async controlManagedSessionForThread(store, threadId, request = {}) {
      return controlManagedSessionForThread(store, threadId, request);
    },
    forkThread(store, threadId, request = {}) {
      return threadForkState.forkThread(store, threadId, request);
    },
    cancelRun(store, runId) {
      return cancelRun(store, runId);
    },
  };
}
