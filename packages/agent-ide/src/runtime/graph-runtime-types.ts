import type { GraphGlobalConfig, ProjectFile } from "../types/graph";

// Wire-format payload for graph execution requests.
export interface GraphPayload {
  nodes: any[];
  edges: any[];
  global_config: GraphGlobalConfig;
  session_id?: string;
}

// Wire-format event emitted while a graph is running.
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

export interface CacheResult {
  output: string;
  metrics?: any;
  input_snapshot?: any;
}

export interface GraphRuntimeModelOption {
  modelId: string;
  status: string;
  residency?: string;
  backendId?: string | null;
}

export interface GraphModelBindingCatalog {
  refreshedAtMs: number;
  models: GraphRuntimeModelOption[];
}

export interface GraphRuntimeCapabilityOption {
  capabilityId: string;
  familyId: string;
  label: string;
  status: string;
  availableCount: number;
  operatorSummary: string;
}

export interface GraphCapabilityCatalog {
  refreshedAtMs: number;
  capabilities: GraphRuntimeCapabilityOption[];
  activeIssueCount?: number;
}

export interface GraphExecutionRuntime {
  runGraph(payload: GraphPayload): Promise<void>;
  stopExecution(): Promise<void>;
  getAvailableTools(): Promise<any[]>;
  checkNodeCache(
    nodeId: string,
    config: any,
    input: string,
  ): Promise<CacheResult | null>;
  getGraphModelBindingCatalog?(): Promise<GraphModelBindingCatalog>;
  getGraphCapabilityCatalog?(): Promise<GraphCapabilityCatalog>;
  runNode(
    nodeType: string,
    config: any,
    input: string,
    globalConfig?: GraphGlobalConfig,
  ): Promise<any>;
  loadProject(path?: string): Promise<ProjectFile | null>;
  saveProject(path: string, project: ProjectFile): Promise<void>;
  onEvent(callback: (event: GraphEvent) => void): () => void;
}
