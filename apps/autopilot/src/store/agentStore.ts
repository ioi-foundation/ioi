// apps/autopilot/src/store/agentStore.ts
import { create } from "zustand";
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

export interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: AgentPhase;
  progress: number;
  total_steps: number;
  current_step: string;
  gate_info?: GateInfo;
  receipt?: Receipt;
  visual_hash?: string; // Added to match Rust backend
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
  // Ghost Mode Trace
  ghostTrace: GhostStep[];
  
  startTask: (intent: string, mode: string) => Promise<AgentTask | null>; // [FIX] Add mode param
  updateTask: (task: AgentTask) => void;
  dismissTask: () => Promise<void>;
  showSpotlight: () => Promise<void>;
  hideSpotlight: () => Promise<void>;
  showStudio: () => Promise<void>;
  resizePill: (expanded: boolean) => Promise<void>;
  
  // Ghost Mode Actions
  addGhostStep: (step: GhostStep) => void;
  clearGhostTrace: () => void;
}

export const useAgentStore = create<AgentStore>((set) => ({
  task: null,
  receipts: [],
  ghostTrace: [],

  // [FIX] Pass mode to backend, default to "Agent" if not provided
  startTask: async (intent: string, mode: string = "Agent"): Promise<AgentTask | null> => {
    try {
      const task = await invoke<AgentTask>("start_task", { intent, mode });
      set({ task });
      return task;
    } catch (e) {
      console.error("Failed to start task:", e);
      return null;
    }
  },

  updateTask: (task: AgentTask) => set({ task }),

  dismissTask: async () => {
    await invoke("dismiss_task");
    set({ task: null });
  },

  showSpotlight: async () => invoke("show_spotlight"),
  hideSpotlight: async () => invoke("hide_spotlight"),
  showStudio: async () => invoke("show_studio"),
  resizePill: async (expanded: boolean) => invoke("resize_pill", { expanded }),

  // Ghost Mode Implementation
  addGhostStep: (step) => set((state) => ({ ghostTrace: [...state.ghostTrace, step] })),
  clearGhostTrace: () => set({ ghostTrace: [] }),
}));

export async function initEventListeners() {
  await listen<AgentTask>("task-started", (e) => useAgentStore.getState().updateTask(e.payload));
  await listen<AgentTask>("task-updated", (e) => useAgentStore.getState().updateTask(e.payload));
  await listen<AgentTask>("task-completed", (e) => useAgentStore.getState().updateTask(e.payload));
  await listen("task-dismissed", () => useAgentStore.setState({ task: null }));

  // Listen for Ghost Inputs
  await listen("ghost-input", (e: any) => {
      useAgentStore.getState().addGhostStep({
          device: e.payload.device,
          description: e.payload.description,
          timestamp: Date.now()
      });
  });

  // Load current task
  try {
    const task = await invoke<AgentTask | null>("get_current_task");
    if (task) useAgentStore.setState({ task });
  } catch (e) {
    console.error("Failed to load task:", e);
  }
}