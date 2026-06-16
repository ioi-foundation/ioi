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
  contextPolicyCore = null,
  threadForkState = createThreadForkState(),
} = {}) {
  const coreDeps = { contextPolicyCore };
  return {
    async inspectManagedSessionsForThread(store, threadId, request = {}) {
      return inspectManagedSessionsForThread(store, threadId, request, coreDeps);
    },
    async inspectWorkspaceChangeReviewsForThread(store, threadId, request = {}) {
      return inspectWorkspaceChangeReviewsForThread(store, threadId, request, coreDeps);
    },
    async controlWorkspaceChangeForThread(store, threadId, request = {}) {
      return controlWorkspaceChangeForThread(store, threadId, request, coreDeps);
    },
    async controlManagedSessionForThread(store, threadId, request = {}) {
      return controlManagedSessionForThread(store, threadId, request, coreDeps);
    },
    forkThread(store, threadId, request = {}) {
      return threadForkState.forkThread(store, threadId, request, coreDeps);
    },
    cancelRun(store, runId) {
      return cancelRun(store, runId);
    },
  };
}
