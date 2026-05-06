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
  | "rerank"
  | "tokenize"
  | "context_fit";

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
  process?: ModelBackendProcess | null;
}

export interface ModelBackendProcess {
  id: string;
  backendId: string;
  backendKind: string;
  status: "started" | "stopped" | "stale_recovered" | "degraded" | string;
  processStatus?: string;
  pidHash?: string | null;
  pidTracked?: string | null;
  startedAt?: string | null;
  stoppedAt?: string | null;
  lastHealthAt?: string | null;
  argsHash?: string | null;
  argsRedacted?: string[];
  startupTimeoutMs?: number | null;
  stale?: boolean;
  staleReason?: string | null;
  receiptId?: string | null;
  evidenceRefs?: string[];
}

export interface ModelRuntimeEngineDefaultLoadOptions {
  gpu?: string;
  contextLength?: number;
  parallel?: number;
  ttlSeconds?: number;
  identifier?: string;
}

export interface ModelRuntimeEngineProfile {
  id: string;
  engineId: string;
  label?: string | null;
  disabled: boolean;
  priority?: number | null;
  defaultLoadOptions: ModelRuntimeEngineDefaultLoadOptions;
  updatedAt: string;
  receiptId: string;
  source: string;
}

export interface ModelRuntimeEngine {
  id: string;
  kind: string;
  label: string;
  status: string;
  selected: boolean;
  modelFormat: string;
  source: string;
  processStatus?: string;
  checkedAt?: string;
  evidenceRefs?: string[];
  operatorProfile?: {
    configured: boolean;
    disabled: boolean;
    priority?: number | null;
    defaultLoadOptions: ModelRuntimeEngineDefaultLoadOptions;
    updatedAt?: string | null;
    receiptId?: string | null;
    source?: string;
  };
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
    | "runtime_engine_select"
    | "runtime_engine_update"
    | "runtime_engine_profile_remove"
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
    responseId?: string | null;
    previousResponseId?: string | null;
    continuation?: {
      mode: "new" | "matched" | "fallback_allowed" | string;
      previousResponseId?: string | null;
      fallbackAllowed?: boolean;
      mismatchFields?: string[];
    } | null;
  };
}

export interface ModelConversationState {
  id: string;
  object: "ioi.model_response_state";
  status: "completed" | "canceled" | "failed" | string;
  redaction: "redacted";
  createdAt: string;
  previousResponseId: string | null;
  rootResponseId: string;
  kind: string;
  routeId: string;
  endpointId: string;
  selectedModel: string;
  providerId: string;
  backendId?: string | null;
  instanceId?: string | null;
  receiptId: string;
  routeReceiptId?: string | null;
  streamReceiptId?: string | null;
  inputHash: string;
  outputHash: string;
  tokenCount: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  messageCount: number;
  continuation?: {
    mode: "new" | "matched" | "fallback_allowed" | string;
    previousResponseId?: string | null;
    fallbackAllowed?: boolean;
    mismatchFields?: string[];
  } | null;
  replay: {
    source: "redacted_conversation_state" | string;
    plaintextPersisted: false;
    previousResponseId: string | null;
  };
}

export interface TokenizerToken {
  index: number;
  text: string;
  token_id: number;
  byte_start: number;
  byte_end: number;
}

export interface TokenizerResult {
  schemaVersion: string;
  model: string;
  route_id: string;
  endpoint_id: string;
  provider_id: string;
  backend_id?: string | null;
  tokenizer: string;
  tokens: TokenizerToken[];
  token_count: number;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  receipt_id: string;
  route_receipt_id: string;
}

export interface TokenCountResult {
  schemaVersion: string;
  model: string;
  route_id: string;
  endpoint_id: string;
  provider_id: string;
  backend_id?: string | null;
  tokenizer: string;
  input_hash: string;
  token_count: number;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  receipt_id: string;
  route_receipt_id: string;
}

export interface ContextFitResult {
  schemaVersion: string;
  model: string;
  route_id: string;
  endpoint_id: string;
  provider_id: string;
  backend_id?: string | null;
  tokenizer: string;
  context_window: number;
  reserved_output_tokens: number;
  available_input_tokens: number;
  prompt_tokens: number;
  fits: boolean;
  overflow_tokens: number;
  truncation: {
    applied: boolean;
    strategy: "keep_tail" | string;
    omitted_token_estimate: number;
  };
  fitted_input: string;
  fitted_input_hash: string;
  receipt_id: string;
  route_receipt_id: string;
}

export interface ModelDownloadJob {
  id: string;
  artifactId: string;
  modelId: string;
  providerId: string;
  status: "queued" | "running" | "completed" | "failed" | "canceled";
  source: string;
  sourceHash?: string;
  sourceUrlHash?: string;
  sourceLabel?: string;
  progress: number;
  bytesTotal?: number;
  bytesCompleted?: number;
  checksum?: string | null;
  targetPath?: string | null;
  targetPathHash?: string | null;
  variant?: ModelCatalogEntry | Record<string, unknown>;
  downloadPolicy?: ModelDownloadPolicy;
  bandwidthLimitBps?: number | null;
  retryLimit?: number;
  resumeDownload?: boolean;
  attemptCount?: number | null;
  retryCount?: number | null;
  resumeMetadataPathHash?: string | null;
  transfer?: {
    status?: string;
    sourceHash?: string;
    partialPathHash?: string;
    targetPathHash?: string;
    resumeMetadataPathHash?: string;
    attemptCount?: number | null;
    retryCount?: number | null;
    retryLimit?: number | null;
    resume?: boolean;
    resumed?: boolean;
    bytesCompleted?: number;
    bytesTotal?: number;
    bandwidthLimitBps?: number | null;
    failureReason?: string | null;
  } | null;
  cleanupState?: string | null;
  projectedFreedBytes?: number;
  destructiveConfirmation?: {
    required: boolean;
    confirmed: boolean;
    action: string;
    source: string;
  };
  resumeOffset?: number;
  failureReason?: string | null;
  receiptIds?: string[];
  createdAt: string;
  updatedAt: string;
  receiptId: string | null;
}

export interface ModelCatalogProviderStatus {
  id: string;
  label?: string;
  status: "available" | "configured" | "gated" | "degraded" | string;
  gate?: string;
  downloadGate?: string;
  liveDownloadStatus?: "configured" | "gated" | string;
  formats?: string[];
  baseUrlHash?: string;
  manifestPathHash?: string;
  authVaultRefHash?: string;
  catalogAuthConfigured?: boolean;
  catalogAuthResolved?: boolean;
  catalogAuthScheme?: string;
  catalogAuthHeaderNameHash?: string | null;
  catalogAuthEvidenceRefs?: string[];
  oauthBoundary?: {
    configured?: boolean;
    status?: string;
    tokenExchange?: string;
    oauthSessionHash?: string | null;
    expiresAt?: string | null;
    scopes?: string[];
    refreshCount?: number;
    evidenceRefs?: string[];
  } | null;
  oauthSessionHash?: string | null;
  materialVaultRefHash?: string;
  configHash?: string;
  enabled?: boolean;
  materialConfigured?: boolean;
  materialPersistence?: string;
  runtimeMaterialStatus?: string;
  vaultMaterialSource?: string | null;
  providerId?: string | null;
  adapterPort?: string;
  operations?: string[];
  errorHash?: string | null;
  evidenceRefs?: string[];
}

export interface ModelCatalogStatus {
  schemaVersion: string;
  checkedAt: string;
  providers: ModelCatalogProviderStatus[];
  adapterBoundary?: {
    port: string;
    operations: string[];
    evidenceRefs: string[];
  };
  filters: {
    formats: string[];
    quantization: string[];
    compatibility: string[];
  };
  storage: {
    rootHash: string;
    totalBytes: number;
    quotaBytes: number | null;
    quotaStatus: "ok" | "over_quota" | string;
    fileCount: number;
    orphanCount: number;
    orphanBytes?: number;
    projectedFreedBytes?: number;
    destructiveActionsRequireUnload: boolean;
    evidenceRefs: string[];
  };
}

export interface ModelCatalogEntry {
  id: string;
  providerId: string;
  catalogProviderId?: string;
  modelId: string;
  family: string;
  architecture?: string | null;
  parameterCount?: string | null;
  format: string;
  quantization?: string | null;
  sizeBytes?: number | null;
  contextWindow?: number | null;
  sourceUrl: string;
  sourceUrlHash: string;
  sourceLabel: string;
  license?: string | null;
  compatibility: string[];
  tags?: string[];
  variantPath?: string;
  gatedBy?: string[];
  backendCompatibility?: Array<{
    backendKind: "native_local_fixture" | "llama_cpp" | "ollama" | "vllm" | string;
    score: number;
    status: "ready" | "compatible" | "degraded" | "unsupported" | string;
    reason: string;
  }>;
  downloadRisk?: {
    score: number;
    status: "low" | "medium" | "high" | "blocked" | string;
    reasons: string[];
    existingArtifactCollision: boolean;
    byteCapStatus?: "not_set" | "within_cap" | "over_cap" | string;
    storageStatus?: string;
  };
  benchmarkReadiness?: {
    chat: boolean;
    embeddings: boolean;
    rerank: boolean;
    vision: boolean;
    structuredOutput: boolean;
    hints: string[];
  };
  recommendation?: {
    score: number;
    label: "recommended" | "review" | "blocked" | string;
    reasons: string[];
    primaryBackend?: string | null;
  };
  selectionReceiptFields?: string[];
  discoveredAt: string;
}

export interface ModelDownloadPolicy {
  maxBytes?: number | null;
  bandwidthLimitBps?: number | null;
  retryLimit?: number;
  resume?: boolean;
  cleanupPartialOnCancel?: boolean;
  externalTransferRequired?: boolean;
  externalTransferApproved?: boolean;
  status?: "ready" | "blocked_approval_required" | string;
  approvalDecision?: {
    required: boolean;
    approved: boolean;
    source: string;
  };
  evidenceRefs?: string[];
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
