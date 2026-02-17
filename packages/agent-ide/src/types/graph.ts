// packages/agent-ide/src/types/graph.ts

// ============================================
// Node Configuration Schemas
// ============================================

export interface NodeLogic {
  // --- Model Nodes ---
  provider?: string;
  model?: string;
  temperature?: number;
  systemPrompt?: string;
  
  // --- Tool Nodes ---
  endpoint?: string;
  method?: "GET" | "POST" | "PUT" | "DELETE";
  headers?: Record<string, string>;
  bodyTemplate?: string;
  timeoutMs?: number;

  // --- Dynamic MCP Tools ---
  tool_name?: string;
  arguments?: Record<string, any>;

  // --- Code / Function ---
  language?: "python" | "javascript" | "typescript" | "shell";
  code?: string;

  // --- Flow Control ---
  routes?: string[];
  routerInstruction?: string;
  durationMs?: number; // Wait block

  // --- Context ---
  variables?: Record<string, string>;

  // --- Triggers ---
  rssUrl?: string;
  cronSchedule?: string;
  
  // --- Retrieval ---
  query?: string;
  limit?: number;
  url?: string;
  max_chars?: number;

  // --- Logic ---
  conditionScript?: string;
}

export interface FirewallPolicy {
  budgetCap?: number;
  networkAllowlist?: string[];
  requireHumanGate?: boolean;
  privacyLevel?: "none" | "masked" | "zero-knowledge";
  retryPolicy?: {
    maxAttempts: number;
    backoffMs: number;
  };
}

// Alias for backward compatibility if needed
export type NodeLaw = FirewallPolicy;

// ============================================
// Graph Topology
// ============================================

export interface Node extends Record<string, unknown> {
  id: string;
  type: string;
  name: string;
  x: number;
  y: number;

  config?: {
    logic: NodeLogic;
    law: FirewallPolicy;
  };

  schema?: string; // JSON Schema for dynamic tools

  // Execution State (Visual feedback)
  status?: "idle" | "running" | "success" | "error" | "blocked";
  metrics?: { records: number; time: string };
  
  inputs?: string[];
  outputs?: string[];
  ioTypes?: { in: string; out: string };
  
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
  data?: Record<string, unknown>;
}

// ============================================
// File Format
// ============================================

export interface GraphGlobalConfig {
  env: string;
  policy: {
    maxBudget: number;
    maxSteps: number;
    timeoutMs: number;
  };
  contract: {
    developerBond: number;
    adjudicationRubric: string;
    validationSchema?: string;
  };
  meta: {
    name: string;
    description: string;
  };
}

export interface ProjectFile {
  version: string;
  nodes: any[]; // Simplified for storage
  edges: any[];
  global_config: GraphGlobalConfig;
}

export interface AgentConfiguration {
  name: string;
  description: string;
  instructions: string;
  model: string;
  temperature: number;
  tools: { id: string; name: string; desc: string; icon: string }[];
}
