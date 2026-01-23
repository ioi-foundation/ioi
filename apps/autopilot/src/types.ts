// ============================================
// Node Configuration Schemas (The Constitution)
// ============================================

/**
 * NodeLogic: The "Brain" of the node.
 * Defines the creative or functional execution parameters.
 * This is what the Agent *wants* to do.
 */
export interface NodeLogic {
  // --- Model Nodes ---
  provider?: string;      // e.g., "ollama", "openai", "anthropic"
  model?: string;         // e.g., "llama3", "gpt-4o"
  temperature?: number;   // 0.0 to 1.0
  systemPrompt?: string;  // The persona and instructions
  
  // --- Tool Nodes ---
  endpoint?: string;      // API URL
  method?: "GET" | "POST" | "PUT" | "DELETE";
  headers?: Record<string, string>;
  bodyTemplate?: string;  // JSON string with handlebars {{variable}} support
  timeoutMs?: number;

  // --- Trigger/Logic Nodes ---
  cronSchedule?: string;  // e.g., "*/5 * * * *"
  conditionScript?: string; // e.g., "input.risk > 0.5"
}

/**
 * NodeLaw: The "Firewall" of the node.
 * Defines the hard constraints and liabilities.
 * This is what the Agent is *allowed* to do.
 */
export interface NodeLaw {
  budgetCap?: number;           // Max USD spend per execution
  networkAllowlist?: string[];  // List of allowed DNS domains (e.g. "*.stripe.com")
  requireHumanGate?: boolean;   // If true, execution halts for "Hold to Sign"
  privacyLevel?: "none" | "masked" | "zero-knowledge"; // Data egress policy
  retryPolicy?: {
    maxAttempts: number;
    backoffMs: number;
  };
}

// ============================================
// Graph & Canvas Types (Studio View)
// ============================================

export interface Node extends Record<string, unknown> {
  id: string;
  type: string;
  name: string;
  x: number;
  y: number;

  // [NEW] The Sovereign Configuration
  // Optional to maintain backward compatibility with existing mock data
  config?: {
    logic: NodeLogic;
    law: NodeLaw;
  };

  // Execution Runtime State
  status?: "idle" | "running" | "success" | "error";
  metrics?: { records: number; time: string };
  
  // Graph Topology
  inputs?: string[];
  outputs?: string[];
  ioTypes?: { in: string; out: string };
  
  // Metadata
  isGhost?: boolean;    // Inferred from Ghost Mode observation
  attested?: boolean;   // Cryptographically signed policy
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
// Builder Configuration Types
// ============================================

export interface AgentConfiguration {
  name: string;
  description: string;
  instructions: string;
  model: string;
  temperature: number;
  tools: { id: string; name: string; desc: string; icon: string }[];
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

// Chat message structure for persistent history
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
  // History of the conversation/execution trace
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

// Session Summary for sidebar list
export interface SessionSummary {
    session_id: string;
    title: string;
    timestamp: number;
}
