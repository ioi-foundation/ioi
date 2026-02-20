// packages/agent-ide/src/runtime/agent-runtime.ts
import { GraphGlobalConfig, ProjectFile } from "../types/graph";

// Data needed to execute a graph
export interface GraphPayload {
  nodes: any[];
  edges: any[];
  global_config: GraphGlobalConfig;
  session_id?: string;
}

// Event received from the runtime
export interface GraphEvent {
  node_id: string;
  status: string;
  result?: {
    output: string;
    metrics?: any;
    input_snapshot?: any;
  };
  fitness_score?: number;
  generation?: number;
}

// Cache check result
export interface CacheResult {
  output: string;
  metrics?: any;
  input_snapshot?: any;
}

// Agent Summary for Dashboard
export interface AgentSummary {
  id: string;
  name: string;
  description: string;
  icon?: string;
  lastEdited?: string;
  model?: string;
}

// [NEW] Marketplace Types
export interface MarketplaceAgent {
  id: string;
  name: string;
  description: string;
  developer: string;   
  price: string;       
  rating?: number;     
  downloads?: number;  
  icon?: string;       
  requirements?: string; 
}

// Connector Types
export type ConnectorStatus = "connected" | "needs_auth" | "degraded" | "disabled";

export interface ConnectorSummary {
  id: string;
  name: string;
  provider: string;
  category: "communication" | "productivity" | "storage" | "developer";
  description: string;
  status: ConnectorStatus;
  authMode: "wallet_network_session" | "oauth" | "api_key";
  scopes: string[];
  lastSyncAtUtc?: string;
  notes?: string;
}

// Fleet Types
export interface Zone {
  id: string;
  name: string;
  type: "local" | "cloud" | "enclave";
  capacity: { used: number; total: number; unit: string };
  costPerHour: number;
}

export interface Container {
  id: string;
  name: string;
  image: string;
  zoneId: string;
  status: "running" | "stopped" | "error";
  metrics: {
    cpu: number; // 0-100%
    ram: number; // 0-100%
    vram?: number; // 0-100%
  };
  uptime: string;
}

export interface FleetState {
    zones: Zone[];
    containers: Container[];
}

// The Adapter Interface
export interface AgentRuntime {
  // Execution
  runGraph(payload: GraphPayload): Promise<void>;
  stopExecution(): Promise<void>;
  
  // Data & Tools
  getAvailableTools(): Promise<any[]>;
  checkNodeCache(nodeId: string, config: any, input: string): Promise<CacheResult | null>;
  
  // Unit Testing (Ephemeral Node Run)
  runNode(nodeType: string, config: any, input: string): Promise<any>;

  // Project Management
  loadProject(path?: string): Promise<ProjectFile | null>;
  saveProject(path: string, project: ProjectFile): Promise<void>;
  
  // Dashboard Management
  getAgents(): Promise<AgentSummary[]>;
  
  // Fleet Management
  getFleetState(): Promise<FleetState>;

  // [NEW] Marketplace Management
  getMarketplaceAgents(): Promise<MarketplaceAgent[]>;
  installAgent(agentId: string): Promise<void>;

  // Integrations / Connectors
  getConnectors?(): Promise<ConnectorSummary[]>;

  // Event Subscription
  onEvent(callback: (event: GraphEvent) => void): () => void;
}
