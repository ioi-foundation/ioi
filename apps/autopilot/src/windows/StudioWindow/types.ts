export interface NodeArtifact {
  output?: string;
  metrics?: any;
  timestamp: number;
  // [NEW] Explicit Input Snapshot for Data Observability
  // Stores the merged input context (JSON) this node received at execution time
  input_snapshot?: any;
}

export interface NodeArtifacts {
  [nodeId: string]: NodeArtifact;
}

export interface ExecutionLog {
  id: string;
  timestamp: string;
  level: "info" | "warn" | "error" | "debug";
  source: string;
  message: string;
}

export interface ExecutionStep {
  id: string;
  name: string;
  status: "running" | "success" | "blocked" | "error" | "idle";
  timestamp: string;
  duration?: string;
  dataCount?: number;
}

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