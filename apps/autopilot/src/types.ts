// ============================================
// Graph & Canvas Types (Studio View)
// ============================================

export interface Node {
  id: string;
  type: string;
  name: string;
  x: number;
  y: number;
  status?: "idle" | "running" | "success" | "error";
  inputs?: string[];
  outputs?: string[];
  ioTypes?: { in: string; out: string };
  metrics?: { records: number; time: string };
  isGhost?: boolean;
  attested?: boolean;
}

export interface Edge {
  id: string;
  from: string;
  to: string;
  fromPort: string;
  toPort: string;
  type: "data" | "control";
  active?: boolean;
  volume?: number;
}

// ============================================
// Runtime Configuration Types
// ============================================

// Whitepaper Section 2.4: Execution Modes
export type ExecutionMode = "local" | "session" | "settlement";

// Whitepaper Section 12.3: Liability & bonding
export type LiabilityMode = "none" | "optional" | "required";

// ============================================
// Swarm & Multi-Agent Types (Spotlight View)
// ============================================

// [NEW] Chat message structure for persistent history
export interface ChatMessage {
  role: string; // 'user', 'agent', 'system', 'tool'
  text: string;
  timestamp: number;
}

// Lifecycle states for an autonomous agent in the swarm
export type AgentStatus = 
  | 'requisition'  // NEW: A "Hiring Request" waiting for User Signature (Delegation Certificate)
  | 'pending'      // Waiting for budget/approval
  | 'negotiating'  // Handshaking with Provider (Mode 1)
  | 'running'      // Active execution
  | 'reviewing'    // Waiting for Manager/User feedback
  | 'completed'    // Task finished, receipt generated
  | 'failed';      // Policy breach or runtime error

export interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: "Idle" | "Running" | "Gate" | "Complete" | "Failed";
  progress: number;
  total_steps: number;
  current_step: string;
  receipt?: { duration: string; actions: number; cost?: string };
  gate_info?: any;
  // [NEW] History of the conversation/execution trace
  history: ChatMessage[];
}

// Whitepaper Section 14.1: Manager-Worker Hierarchy
export interface SwarmAgent {
  id: string;
  parentId: string | null; // Null for Root Manager
  
  // Identity
  name: string;
  role: string; // e.g., "Planner", "Researcher", "Python Worker"
  
  // State
  status: AgentStatus;
  
  // Economic Physics (IOI Specifics)
  budget_used: number; // Labor Gas consumed
  budget_cap: number;  // Max Labor Gas authorized via Delegation Certificate
  policy_hash: string; // The constraint envelope (ActionRules)
  
  // The "Quote" from the Manager (only relevant during 'requisition' status)
  estimated_cost?: number;

  // Real-time Visibility (Visual Sovereignty)
  current_thought?: string;
  artifacts_produced: number;
}

// [NEW] Session Summary for sidebar list
export interface SessionSummary {
    session_id: string;
    title: string;
    timestamp: number;
}