// apps/autopilot/src/components/RightPanel/types.ts

import { Node, Edge, NodeLogic, FirewallPolicy } from "../../types";

export interface GraphGlobalConfig {
  env: string;
  policy: {
    maxBudget: number;
    maxSteps: number;
    timeoutMs: number;
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
export type GraphTab = "ENV" | "POLICY" | "META";