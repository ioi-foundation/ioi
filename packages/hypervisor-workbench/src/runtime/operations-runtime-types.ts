export interface AgentSummary {
  id: string;
  name: string;
  description: string;
  icon?: string;
  lastEdited?: string;
  model?: string;
}

export interface RuntimeCatalogEntry {
  id: string;
  name: string;
  description: string;
  ownerLabel: string;
  entryKind: string;
  runtimeNotes: string;
  statusLabel?: string;
  icon?: string;
}

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
    cpu: number;
    ram: number;
    vram?: number;
  };
  uptime: string;
}

export interface FleetState {
  zones: Zone[];
  containers: Container[];
}

export interface WorkbenchOperationsRuntime {
  getAgents(): Promise<AgentSummary[]>;
  getFleetState(): Promise<FleetState>;
  getRuntimeCatalogEntries(): Promise<RuntimeCatalogEntry[]>;
  stageRuntimeCatalogEntry(entryId: string, notes?: string): Promise<void>;
}
