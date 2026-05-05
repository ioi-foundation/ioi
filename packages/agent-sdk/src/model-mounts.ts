export type ModelProviderKind =
  | "local_folder"
  | "ioi_native_local"
  | "llama_cpp"
  | "lm_studio"
  | "ollama"
  | "vllm"
  | "openai_compatible"
  | "openai"
  | "anthropic"
  | "gemini"
  | "custom_http"
  | "depin_tee";

export type ModelCapability =
  | "chat"
  | "responses"
  | "code"
  | "structured_output"
  | "embeddings"
  | "vision"
  | "rerank";

export interface ModelLoadPolicy {
  mode:
    | "manual"
    | "on_demand"
    | "keep_warm"
    | "idle_evict"
    | "workflow_scoped"
    | "agent_scoped"
    | "memory_pressure_evict";
  idleTtlSeconds: number;
  autoEvict: boolean;
  memoryPressureEvict?: boolean;
}

export interface ModelHardwareEstimate {
  cpuCount?: number;
  totalMemoryBytes?: number;
  freeMemoryBytes?: number;
  platform?: string;
  arch?: string;
  memoryPressure?: "normal" | "high" | string;
  nvidiaSmi?: { available: boolean; path?: string; exitCode?: number | null; outputHash?: string };
  vulkanInfo?: { available: boolean; path?: string; exitCode?: number | null; outputHash?: string };
}

export interface ModelBackend {
  id: string;
  kind:
    | "fixture"
    | "native_local"
    | "llama_cpp"
    | "lm_studio"
    | "openai_compatible"
    | "ollama"
    | "vllm"
    | string;
  label: string;
  status: "available" | "configured" | "running" | "stopped" | "blocked" | "absent" | "degraded" | string;
  processStatus?: string | null;
  binaryPath?: string | null;
  baseUrl?: string | null;
  capabilities: ModelCapability[];
  supportedFormats?: string[];
  processLifecycle?: string[];
  hardware?: ModelHardwareEstimate;
  evidenceRefs: string[];
  checkedAt?: string;
  lastReceiptId?: string | null;
}

export interface ModelArtifact {
  id: string;
  providerId: string;
  modelId: string;
  displayName: string;
  family: string;
  format?: string | null;
  quantization: string | null;
  sizeBytes: number | null;
  checksum?: string | null;
  contextWindow: number | null;
  capabilities: ModelCapability[];
  privacyClass: "local_private" | "workspace" | "hosted" | "remote_confidential";
  source: string;
  artifactPath?: string | null;
  metadata?: Record<string, unknown>;
  state: "installed" | "available" | "provider_stopped" | "downloading" | "error";
  discoveredAt: string;
}

export interface ModelEndpoint {
  id: string;
  providerId: string;
  modelId: string;
  artifactId?: string | null;
  artifactPath?: string | null;
  apiFormat: string;
  driver?: "fixture" | "native_local" | "lm_studio" | "openai_compatible" | string;
  backendId?: string | null;
  baseUrl: string | null;
  capabilities: ModelCapability[];
  privacyClass: string;
  loadPolicy: ModelLoadPolicy;
  status: "mounted" | "unmounted" | "degraded";
  mountedAt: string;
}

export interface ModelInstance {
  id: string;
  endpointId: string;
  providerId: string;
  modelId: string;
  status: "loaded" | "unloaded" | "evicted" | "failed";
  backend: string;
  backendId?: string | null;
  driver?: "fixture" | "native_local" | "lm_studio" | "openai_compatible" | string;
  loadPolicy: ModelLoadPolicy;
  loadedAt: string;
  lastUsedAt: string;
  expiresAt: string | null;
  workflowScope?: string | null;
  agentScope?: string | null;
  providerEvidenceRefs?: string[];
}

export interface ModelProviderProfile {
  id: string;
  kind: ModelProviderKind;
  label: string;
  apiFormat: string;
  driver?: "fixture" | "lm_studio" | "openai_compatible" | string;
  baseUrl: string | null;
  status: "available" | "configured" | "running" | "stopped" | "blocked" | "absent" | "future";
  privacyClass: string;
  capabilities: ModelCapability[];
  secretRef?: string | { redacted: true; hash: string } | null;
  secretConfigured?: boolean;
  authScheme?: "bearer" | "raw" | "api_key" | string;
  authHeaderName?: string;
  discovery?: Record<string, unknown>;
}

export interface ModelRoute {
  id: string;
  role: string;
  description: string;
  privacy: string;
  quality: string;
  maxCostUsd: number;
  maxLatencyMs: number;
  providerEligibility: string[];
  fallback: string[];
  deniedProviders: string[];
  status: "active" | "disabled";
  lastSelectedModel: string | null;
  lastReceiptId: string | null;
}

export interface ModelLifecycleEvent {
  id: string;
  operation:
    | "model_import"
    | "model_mount"
    | "model_unmount"
    | "model_load"
    | "model_unload"
    | "model_download"
    | "model_idle_evict"
    | "provider_start"
    | "provider_stop";
  artifactId?: string;
  endpointId?: string;
  instanceId?: string;
  modelId?: string;
  providerId?: string;
  receiptId: string;
  createdAt: string;
}

export interface PermissionToken {
  id: string;
  audience: string;
  allowed: string[];
  denied: string[];
  expiresAt: string;
  revocationEpoch: number;
  grantId: string;
  createdAt: string;
  revokedAt: string | null;
  lastUsedAt?: string | null;
  lastUsedScope?: string | null;
  vaultRefs?: Record<string, unknown>;
  auditReceiptIds?: string[];
  receiptId: string | null;
}

export interface ModelInvocationReceipt {
  id: string;
  kind: "model_invocation";
  summary: string;
  redaction: "none" | "redacted";
  evidenceRefs: string[];
  createdAt: string;
  details: {
    routeId: string;
    routeReceiptId?: string;
    selectedModel: string;
    endpointId: string;
    providerId: string;
    instanceId: string;
    backend: string;
    backendId?: string | null;
    selectedBackend?: string | null;
    policyHash: string;
    grantId: string;
    tokenCount: {
      prompt_tokens: number;
      completion_tokens: number;
      total_tokens: number;
    };
    latencyMs: number;
    inputHash: string;
    outputHash: string;
    compatTranslation?: "chat_completions" | null;
    providerResponseKind?: string | null;
    backendEvidenceRefs?: string[];
    toolReceiptIds?: string[];
    ephemeralMcpServerIds?: string[];
  };
}

export interface ModelDownloadJob {
  id: string;
  artifactId: string;
  modelId: string;
  providerId: string;
  status: "queued" | "running" | "completed" | "failed" | "canceled";
  source: string;
  progress: number;
  bytesTotal?: number;
  bytesCompleted?: number;
  checksum?: string | null;
  targetPath?: string | null;
  failureReason?: string | null;
  receiptIds?: string[];
  createdAt: string;
  updatedAt: string;
  receiptId: string | null;
}

export interface RuntimeModelCatalogEntry {
  id: string;
  provider: string;
  cost: string;
  quality: string;
  capabilities?: ModelCapability[];
  privacyClass?: string;
  route?: string;
}

export interface WorkflowModelBinding {
  node: string;
  modelId: string | null;
  routeId: string;
  modelPolicy?: Record<string, unknown>;
  capability: ModelCapability | "mcp" | "receipt_gate";
  receiptRequired: boolean;
  daemonApi: string;
  selectedEndpointId?: string | null;
  lastReceiptId?: string | null;
}
