import {
  createNormalizedRuntimeChatSessionControllerStore,
} from "@ioi/agent-ide";
import type {
  AgentTask,
  AgentEvent,
  Artifact,
  SessionSummary,
} from "../types";
import {
  normalizeAgentTaskModel,
} from "../types";

const {
  useSessionControllerStore,
  bootstrapSessionController,
} =
  createNormalizedRuntimeChatSessionControllerStore<
    AgentTask,
    AgentEvent,
    Artifact,
    SessionSummary
  >({
    normalizeTask: normalizeAgentTaskModel,
    onBootstrapError: (error) => {
      console.error("Failed to bootstrap session controller:", error);
    },
  });

// Keep a tiny Autopilot-local alias so the desktop shells import one stable
// session surface while the package-owned controller remains canonical.
export const useAgentStore = useSessionControllerStore;
export const bootstrapAgentSession = bootstrapSessionController;
