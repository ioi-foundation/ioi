// apps/autopilot/src/store/agentStore.ts
import { create } from "zustand";
import type { AgentStatus, AgentEvent, Artifact } from "../types";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type AgentPhase = "Idle" | "Running" | "Gate" | "Complete" | "Failed";

export interface GateInfo {
  title: string;
  description: string;
  risk: "low" | "medium" | "high";
}

export interface Receipt {
  duration: string;
  actions: number;
  cost?: string;
}

// [NEW] Sovereignty Context: Defines the active constraints on the agent
export interface PolicyContext {
  name: string; // e.g., "Finance Safe"
  mode: "strict" | "standard" | "elevated";
  constraints: string[]; // e.g., ["Read-Only", "Max Spend $0"]
}

// Hierarchical agent structure for SwarmViz
export interface SwarmAgent {
  id: string;
  parentId: string | null;
  name: string;
  role: string;
  status: AgentStatus; // "running", "completed", "failed", "requisition", etc.
  budget_used: number;
  budget_cap: number;
  current_thought?: string;
  artifacts_produced: number;
  estimated_cost: number;
  policy_hash: string;
  // Evolutionary Status
  generation?: number;
}

export interface ChatMessage {
  role: string;
  text: string;
  timestamp: number;
}

export interface AgentTask {
  id: string;
  session_id?: string;
  intent: string;
  agent: string;
  phase: AgentPhase;
  progress: number;
  total_steps: number;
  current_step: string;
  gate_info?: GateInfo;
  receipt?: Receipt;
  visual_hash?: string; // Added to match Rust backend

  // [NEW] Active Policy Snapshot for UI Badge
  policy?: PolicyContext;

  // [NEW] Visual State Flag for "Secure Enclave" Border
  is_secure_session?: boolean;

  // Hierarchical Swarm State
  swarm_tree: SwarmAgent[];

  // History source of truth
  history: ChatMessage[];

  // Glass-box canonical event stream + artifact index
  events: AgentEvent[];
  artifacts: Artifact[];
  run_bundle_id?: string;

  // Evolutionary Metadata
  generation: number; // The current generation count (0 = Genesis)
  lineage_id: string; // Unique hash of the agent's evolutionary branch
  fitness_score: number; // 0.0 - 1.0 score of the agent's performance
}

// Ghost Mode Trace Step
export interface GhostStep {
  device: string;
  description: string;
  timestamp: number;
}

interface AgentStore {
  task: AgentTask | null;
  receipts: Receipt[];
  events: AgentEvent[];
  artifacts: Artifact[];
  selectedArtifactId: string | null;
  // Ghost Mode Trace
  ghostTrace: GhostStep[];

  // [MODIFIED] Removed 'mode' argument
  startTask: (intent: string) => Promise<AgentTask | null>;

  updateTask: (task: AgentTask) => void;
  dismissTask: () => Promise<void>;
  showSpotlight: () => Promise<void>;
  hideSpotlight: () => Promise<void>;
  showStudio: () => Promise<void>;

  // Ghost Mode Actions
  addGhostStep: (step: GhostStep) => void;
  clearGhostTrace: () => void;

  // [NEW] Continue existing session
  continueTask: (sessionId: string, input: string) => Promise<void>;

  // [NEW] Reset state for a new conversation
  resetSession: () => void;
  // [NEW] Trigger new chat UI flow explicitly
  startNewSession: () => void;
  setSelectedArtifactId: (artifactId: string | null) => void;
  loadThreadEvents: (
    threadId: string,
    limit?: number,
    cursor?: number,
  ) => Promise<AgentEvent[]>;
  loadThreadArtifacts: (threadId: string) => Promise<Artifact[]>;
}

export const useAgentStore = create<AgentStore>((set, get) => ({
  task: null,
  receipts: [],
  events: [],
  artifacts: [],
  selectedArtifactId: null,
  ghostTrace: [],

  // [MODIFIED] Removed mode param. Defaults to "Agent" internally in backend.
  startTask: async (intent: string): Promise<AgentTask | null> => {
    try {
      const task = await invoke<AgentTask>("start_task", { intent });
      // Initialize evolutionary fields if missing from backend response (backward compat)
      if (task.generation === undefined) task.generation = 0;
      if (task.fitness_score === undefined) task.fitness_score = 0.0;
      if (!task.lineage_id) task.lineage_id = "genesis";
      if (!task.events) task.events = [];
      if (!task.artifacts) task.artifacts = [];

      set({ task, events: task.events, artifacts: task.artifacts });
      return task;
    } catch (e) {
      console.error("Failed to start task:", e);
      return null;
    }
  },

  updateTask: (task: AgentTask) => {
    if (!task.events) task.events = [];
    if (!task.artifacts) task.artifacts = [];
    set({ task, events: task.events, artifacts: task.artifacts });
  },

  dismissTask: async () => {
    await invoke("dismiss_task");
    set({ task: null, events: [], artifacts: [], selectedArtifactId: null });
  },

  showSpotlight: async () => invoke("show_spotlight"),
  hideSpotlight: async () => invoke("hide_spotlight"),

  showStudio: async () => invoke("show_studio"),

  // Ghost Mode Implementation
  addGhostStep: (step) =>
    set((state) => ({ ghostTrace: [...state.ghostTrace, step] })),
  clearGhostTrace: () => set({ ghostTrace: [] }),

  // [NEW] Continue existing session
  continueTask: async (sessionId: string, input: string) => {
    // 1. Optimistic Update
    const currentTask = get().task;
    if (currentTask) {
      const newHistory = [
        ...currentTask.history,
        { role: "user", text: input, timestamp: Date.now() },
      ];
      // Set phase to Running so spinner appears
      set({ task: { ...currentTask, history: newHistory, phase: "Running" } });
    }

    try {
      await invoke("continue_task", { sessionId, userInput: input });
    } catch (e) {
      console.error("Failed to continue task:", e);
      // 2. Rollback / Error State on Failure
      const task = get().task;
      if (task) {
        set({
          task: {
            ...task,
            phase: "Failed",
            current_step: `Failed to send: ${e}`,
          },
        });
      }
    }
  },

  // [NEW] Reset state for a new conversation
  resetSession: () => {
    set({
      task: null,
      receipts: [],
      ghostTrace: [],
      events: [],
      artifacts: [],
      selectedArtifactId: null,
    });
  },

  // [NEW] Alias for clarity in UI components
  startNewSession: () => {
    get().resetSession();
  },

  setSelectedArtifactId: (artifactId) =>
    set({ selectedArtifactId: artifactId }),

  loadThreadEvents: async (
    threadId: string,
    limit?: number,
    cursor?: number,
  ) => {
    const events = await invoke<AgentEvent[]>("get_thread_events", {
      threadId,
      thread_id: threadId,
      limit: limit ?? null,
      cursor: cursor ?? null,
    });
    set({ events });
    return events;
  },

  loadThreadArtifacts: async (threadId: string) => {
    const artifacts = await invoke<Artifact[]>("get_thread_artifacts", {
      threadId,
      thread_id: threadId,
    });
    set({ artifacts });
    return artifacts;
  },
}));

export async function initEventListeners() {
  await listen<AgentTask>("task-started", (e) =>
    useAgentStore.getState().updateTask(e.payload),
  );
  await listen<AgentTask>("task-updated", (e) =>
    useAgentStore.getState().updateTask(e.payload),
  );
  await listen<AgentTask>("task-completed", (e) =>
    useAgentStore.getState().updateTask(e.payload),
  );
  await listen("task-dismissed", () =>
    useAgentStore.setState({
      task: null,
      events: [],
      artifacts: [],
      selectedArtifactId: null,
    }),
  );

  await listen<AgentEvent>("agent-event", (e) => {
    useAgentStore.setState((state) => {
      const events = [...state.events, e.payload];
      const task = state.task
        ? {
            ...state.task,
            events: [...(state.task.events || []), e.payload],
          }
        : state.task;
      return { events, task };
    });
  });

  await listen<Artifact>("artifact-created", (e) => {
    useAgentStore.setState((state) => {
      const exists = state.artifacts.some(
        (a) => a.artifact_id === e.payload.artifact_id,
      );
      const artifacts = exists
        ? state.artifacts
        : [...state.artifacts, e.payload];
      const task = state.task
        ? {
            ...state.task,
            artifacts: state.task.artifacts.some(
              (a) => a.artifact_id === e.payload.artifact_id,
            )
              ? state.task.artifacts
              : [...(state.task.artifacts || []), e.payload],
          }
        : state.task;
      return { artifacts, task };
    });
  });

  // Listen for Ghost Inputs
  await listen("ghost-input", (e: any) => {
    useAgentStore.getState().addGhostStep({
      device: e.payload.device,
      description: e.payload.description,
      timestamp: Date.now(),
    });
  });

  // Load current task
  try {
    const task = await invoke<AgentTask | null>("get_current_task");
    if (task) {
      // Initialize evolutionary fields if missing from backend response (backward compat)
      if (task.generation === undefined) task.generation = 0;
      if (task.fitness_score === undefined) task.fitness_score = 0.0;
      if (!task.lineage_id) task.lineage_id = "genesis";
      if (!task.events) task.events = [];
      if (!task.artifacts) task.artifacts = [];
      useAgentStore.setState({
        task,
        events: task.events,
        artifacts: task.artifacts,
      });
    }
  } catch (e) {
    console.error("Failed to load task:", e);
  }
}
