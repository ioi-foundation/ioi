// apps/autopilot/src/components/RightPanel/types.ts

import { Node, Edge, NodeLogic, FirewallPolicy } from "../../types";

export interface GraphGlobalConfig {
  env: string;
  policy: {
    maxBudget: number;
    maxSteps: number;
    timeoutMs: number;
  };
  // [NEW] Service Level Agreement & Arbitration Settings
  // This maps to the Intent Contract Schema (ICS) defined in Whitepaper §2.3.1
  contract: {
    // Tier 2: Economic Liability
    // The amount of IOI tokens the developer stakes to back this agent's correctness.
    // If arbitration rules against the agent, this bond is slashed.
    developerBond: number; 
    
    // Tier 4: Adjudication Logic
    // Natural language instructions for the Arbitration Node (LLM Judge) to decide disputes.
    // Example: "The output must be valid JSON. It must not contain profanity."
    adjudicationRubric: string; 
    
    // Tier 3: Programmatic Validation (Optional)
    // A strict JSON Schema or ZK-Circuit identifier for objective verification.
    validationSchema?: string; 
  };
  meta: {
    name: string;
    description: string;
  };
}

export interface RightPanelProps {
  width: number;
  selectedNode: Node | null;
  // [NEW] Graph awareness for context suggestions
  nodes?: Node[]; 
  edges?: Edge[];
  
  onUpdateNode?: (nodeId: string, section: 'logic' | 'law', updates: Partial<NodeLogic> | Partial<FirewallPolicy>) => void;
  graphConfig?: GraphGlobalConfig;
  onUpdateGraph?: (updates: Partial<GraphGlobalConfig> | any) => void;
  upstreamData?: string;
  onRunComplete?: (nodeId: string, artifact: any) => void;
}

export type InspectorTab = "LOGIC" | "LAW" | "SIM" | "DNA";
// [UPDATED] Added CONTRACT to GraphTab union type
export type GraphTab = "ENV" | "POLICY" | "CONTRACT" | "META";