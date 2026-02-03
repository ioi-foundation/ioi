// apps/autopilot/src/types.ts

// Import Graph Types from the shared package
// (Once installed, this will resolve to node_modules/@ioi/agent-ide/dist/...)
// For now, we will assume the build step handles this mapping.
import type { 
  Node, 
  Edge, 
  NodeLogic, 
  FirewallPolicy, 
  GraphGlobalConfig, 
  AgentConfiguration 
} from "@ioi/agent-ide/dist/types/graph"; // Path may vary depending on exports config

// Re-export for local consumption if needed, or update imports in Autopilot components
export type { Node, Edge, NodeLogic, FirewallPolicy, GraphGlobalConfig, AgentConfiguration };

// ============================================
// OS / Shell Types (Specific to Autopilot)
// ============================================

export type ExecutionMode = "local" | "session" | "settlement";

export type LiabilityLevel = 
  | "none"
  | "auditable"
  | "insured"
  | "proven";

export interface ChatMessage {
  role: string;
  text: string;
  timestamp: number;
}

export type AgentStatus = 
  | 'requisition'
  | 'pending'
  | 'negotiating'
  | 'running'
  | 'paused'
  | 'reviewing'
  | 'completed'
  | 'failed';

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

export interface PolicyContext {
  name: string;
  mode: "strict" | "standard" | "elevated";
  constraints: string[];
}

export interface SwarmAgent {
  id: string;
  parentId: string | null;
  name: string;
  role: string;
  status: AgentStatus;
  budget_used: number;
  budget_cap: number;
  policy_hash: string;
  estimated_cost?: number;
  current_thought?: string;
  artifacts_produced: number;
  generation?: number;
}

export interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: "Idle" | "Running" | "Gate" | "Complete" | "Failed";
  progress: number;
  total_steps: number;
  current_step: string;
  receipt?: Receipt;
  gate_info?: GateInfo;
  history: ChatMessage[];
  liability_level?: LiabilityLevel;
  generation: number;
  lineage_id: string;
  fitness_score: number;
  swarm_tree: SwarmAgent[];
  processed_steps: Set<string>;
  visual_hash?: string;
  pending_request_hash?: string;
  session_id?: string;
}

export interface SessionSummary {
    session_id: string;
    title: string;
    timestamp: number;
}

export interface MutationLogEntry {
    generation: number;
    parent_hash: string;
    child_hash: string;
    diff_summary: string;
    rationale: string;
    score_delta: number;
    timestamp: number;
}