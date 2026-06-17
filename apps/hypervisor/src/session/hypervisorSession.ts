import {
  createNormalizedChatSessionStore,
} from "@ioi/hypervisor-workbench";
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
  useSessionStore,
  connectSessionStore,
} =
  createNormalizedChatSessionStore<
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

// Keep a tiny Hypervisor-local session surface while the package-owned
// controller remains canonical.
export const useHypervisorSessionStore = useSessionStore;
export const bootstrapHypervisorSession = connectSessionStore;
