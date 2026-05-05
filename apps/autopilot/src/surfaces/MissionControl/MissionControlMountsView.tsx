import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import "./MissionControlMountsView.css";

type MountsTab = "server" | "backends" | "models" | "providers" | "downloads" | "tokens" | "routing" | "benchmarks" | "logs";
type StatusTone = "neutral" | "ready" | "muted" | "warn" | "blocked";
type ConnectionState = "offline" | "loading" | "connected" | "degraded";

interface ActionGuard {
  tone: StatusTone;
  label: string;
  reason: string;
  disabled: boolean;
}

interface ProviderProfile {
  id: string;
  label: string;
  kind: string;
  status: string;
  privacy: string;
  apiFormat: string;
  baseUrl: string;
  auth: string;
  authScheme: ProviderDraft["authScheme"];
  authHeaderName: string;
  authState: string;
  capabilities: string[];
  evidence: string;
  lastHealth: string;
  healthReceipt: string;
}

interface ProviderDraft {
  id: string;
  label: string;
  kind: string;
  apiFormat: string;
  baseUrl: string;
  privacyClass: string;
  capabilities: string;
  secretRef: string;
  vaultMaterial: string;
  authScheme: "bearer" | "api_key" | "raw";
  authHeaderName: string;
}

interface BackendPreview {
  id: string;
  label: string;
  kind: string;
  status: string;
  processStatus: string;
  binaryPath: string;
  baseUrl: string;
  formats: string[];
  capabilities: string[];
  evidence: string;
  memoryPressure: string;
  receipt: string;
}

interface ModelArtifact {
  id: string;
  name: string;
  provider: string;
  state: string;
  context: string;
  format: string;
  quantization: string;
  source: string;
  capabilities: string[];
}

interface ModelEndpoint {
  id: string;
  provider: string;
  apiFormat: string;
  baseUrl: string;
  modelId: string;
  privacy: string;
  loadPolicy: string;
  status: string;
  capabilities: string[];
}

interface ModelInstance {
  id: string;
  endpointId: string;
  modelId: string;
  status: string;
  backend: string;
  runtimeEngine: string;
  context: string;
  parallel: string;
  identifier: string;
  ttl: string;
}

interface ModelLoadDraft {
  modelId: string;
  mode: string;
  gpu: string;
  contextLength: string;
  parallel: string;
  ttlSeconds: string;
  identifier: string;
  estimateOnly: boolean;
}

interface MountsPickerSelection {
  modelId: string;
  providerId: string;
  endpointId: string;
  routeId: string;
  instanceId: string;
}

interface PermissionTokenPreview {
  id: string;
  audience: string;
  allowed: string[];
  denied: string[];
  expires: string;
  created: string;
  revoked: string;
  lastUsed: string;
  lastScope: string;
  state: string;
  grantId: string;
  receipt: string;
  vaultRefs: string[];
  auditReceipts: string[];
}

interface TokenDraft {
  audience: string;
  expiresHours: string;
  allowed: string;
  denied: string;
  grantId: string;
}

interface VaultRefPreview {
  hash: string;
  label: string;
  purpose: string;
  state: string;
  lastResolved: string;
}

interface VaultAdapterPreview {
  implementation: string;
  mode: string;
  configured: boolean;
  failClosed: boolean;
  keyConfigured: boolean;
  pathHash: string;
  plaintextPersistence: boolean;
  evidence: string[];
}

interface McpServerPreview {
  id: string;
  transport: string;
  allowedTools: string[];
  status: string;
  secrets: string;
}

interface RoutePolicyPreview {
  id: string;
  description: string;
  role: string;
  privacy: string;
  quality: string;
  maxCost: string;
  maxLatency: string;
  fallback: string;
  fallbackIds: string[];
  providerEligibility: string[];
  deniedProviders: string[];
  status: string;
  lastSelection: string;
  receipt: string;
}

interface RouteDraft {
  id: string;
  description: string;
  role: string;
  privacy: string;
  quality: string;
  maxCostUsd: string;
  maxLatencyMs: string;
  fallback: string;
  providerEligibility: string;
  deniedProviders: string;
  allowHostedFallback: boolean;
}

interface ReceiptPreview {
  id: string;
  kind: string;
  summary: string;
  redaction: string;
  evidence: string[];
  healthStatus: string;
  createdAt: string;
  routeId: string;
  endpointId: string;
  selectedModel: string;
  providerId: string;
  instanceId: string;
  backend: string;
  backendId: string;
  grantId: string;
  tokenCount: number;
  latencyMs: number;
  routeReceiptId: string;
  compatTranslation: string;
  policyHash: string;
  toolReceiptIds: string[];
  providerResponseKind: string;
}

interface BenchmarkDraft {
  prompt: string;
  samples: string;
  includeResponses: boolean;
  includeEmbeddings: boolean;
  maxCostUsd: string;
  privacy: string;
}

type ObservabilityDirection = "all" | "request" | "response";
type ObservabilityCategory = "all" | "server" | "provider" | "backend" | "model" | "route" | "mcp" | "vault" | "token" | "workflow";
type ObservabilityStatus = "all" | "ready" | "degraded" | "denied" | "failed";

interface ObservabilityFilters {
  direction: ObservabilityDirection;
  category: ObservabilityCategory;
  status: ObservabilityStatus;
  kind: string;
  entity: string;
  liveTail: boolean;
  payloadPreview: boolean;
}

interface ObservabilityEvent {
  id: string;
  direction: Exclude<ObservabilityDirection, "all">;
  category: Exclude<ObservabilityCategory, "all">;
  status: Exclude<ObservabilityStatus, "all">;
  kind: string;
  summary: string;
  entity: string;
  routeId: string;
  endpointId: string;
  providerId: string;
  backendId: string;
  receipt: ReceiptPreview;
  payload: Array<{ label: string; value: string }>;
}

interface HealthSummaryPreview {
  providerHealthCount: number;
  vaultHealthCount: number;
  blockedProviderHealthCount: number;
  latestReceiptId: string;
  latestStatus: string;
}

interface WorkflowNodePreview {
  node: string;
  routeId: string;
  receiptRequired: boolean;
}

interface RuntimeEnginePreview {
  id: string;
  label: string;
  kind: string;
  status: string;
  selected: boolean;
  modelFormat: string;
  source: string;
}

interface RuntimeSurveyPreview {
  status: string;
  checkedAt: string;
  cpu: string;
  ram: string;
  vram: string;
  memoryPressure: string;
  selectedEngine: string;
  receipt: string;
}

interface ServerPreview {
  status: string;
  gatewayStatus: string;
  controlStatus: string;
  lastServerOperation: string;
  lastServerOperationAt: string;
  lastServerReceiptId: string;
  nativeBaseUrl: string;
  openAiCompatibleBaseUrl: string;
  loadedInstances: number;
  mountedEndpoints: number;
  idleTtlSeconds: number;
  autoEvict: boolean;
  providerSummary: string;
}

interface CatalogProviderPreview {
  id: string;
  label: string;
  status: string;
  gate: string;
  liveDownloadStatus: string;
  downloadGate: string;
  formats: string[];
}

interface CatalogPreview {
  providers: CatalogProviderPreview[];
  formats: string[];
  quantization: string[];
  storageTotal: string;
  storageQuota: string;
  storageStatus: string;
  orphanCount: number;
  fileCount: number;
}

interface DownloadPreview {
  id: string;
  model: string;
  status: string;
  progress: string;
  sourceLabel: string;
  bytes: string;
  checksum: string;
  receipt: string;
}

interface CatalogSearchDraft {
  query: string;
  format: string;
  quantization: string;
  limit: string;
}

interface MountsWorkbenchData {
  server: ServerPreview;
  catalog: CatalogPreview;
  artifacts: ModelArtifact[];
  endpoints: ModelEndpoint[];
  instances: ModelInstance[];
  downloads: DownloadPreview[];
  backends: BackendPreview[];
  runtimeEngines: RuntimeEnginePreview[];
  runtimeSurvey: RuntimeSurveyPreview;
  providers: ProviderProfile[];
  tokens: PermissionTokenPreview[];
  vaultAdapter: VaultAdapterPreview;
  vaultRefs: VaultRefPreview[];
  mcpServers: McpServerPreview[];
  routes: RoutePolicyPreview[];
  workflowNodes: WorkflowNodePreview[];
  receipts: ReceiptPreview[];
  healthSummary: HealthSummaryPreview;
}

const READY_GUARD: ActionGuard = {
  tone: "ready",
  label: "ready",
  reason: "Action is available through the governed daemon path.",
  disabled: false,
};

const DEFAULT_DAEMON_ENDPOINT = "http://127.0.0.1:8765";
const ENDPOINT_STORAGE_KEY = "ioi.modelMounts.daemonEndpoint";

const defaultProviderDraft: ProviderDraft = {
  id: "provider.custom-http",
  label: "Custom HTTP",
  kind: "custom_http",
  apiFormat: "openai_compatible",
  baseUrl: "http://127.0.0.1:1234/v1",
  privacyClass: "workspace",
  capabilities: "chat,responses,embeddings",
  secretRef: "",
  vaultMaterial: "",
  authScheme: "bearer",
  authHeaderName: "authorization",
};

const defaultTokenDraft: TokenDraft = {
  audience: "autopilot-local-server",
  expiresHours: "24",
  allowed: [
    "model.chat:*",
    "model.responses:*",
    "model.embeddings:*",
    "model.load:*",
    "model.unload:*",
    "route.use:*",
    "mcp.import:*",
    "mcp.call:huggingface.model_search",
  ].join("\n"),
  denied: ["connector.gmail.send", "filesystem.write", "shell.exec"].join("\n"),
  grantId: "",
};

const defaultBenchmarkDraft: BenchmarkDraft = {
  prompt: "Compare this mounted model path with a short deterministic routing benchmark.",
  samples: "2",
  includeResponses: true,
  includeEmbeddings: true,
  maxCostUsd: "0.05",
  privacy: "local_only",
};

const defaultObservabilityFilters: ObservabilityFilters = {
  direction: "all",
  category: "all",
  status: "all",
  kind: "all",
  entity: "",
  liveTail: false,
  payloadPreview: true,
};

const tabs: Array<{ id: MountsTab; label: string }> = [
  { id: "server", label: "Local Server" },
  { id: "backends", label: "Backends" },
  { id: "models", label: "Models" },
  { id: "providers", label: "Providers" },
  { id: "downloads", label: "Downloads" },
  { id: "tokens", label: "Tokens & MCP" },
  { id: "routing", label: "Routing Policies" },
  { id: "benchmarks", label: "Benchmarks" },
  { id: "logs", label: "Logs / Receipts" },
];

const tabIds = tabs.map((tab) => tab.id);

function isMountsTab(value: unknown): value is MountsTab {
  return typeof value === "string" && tabIds.includes(value as MountsTab);
}

const fallbackData: MountsWorkbenchData = {
  server: {
    status: "offline fixture",
    gatewayStatus: "offline",
    controlStatus: "fixture",
    lastServerOperation: "fixture_projection",
    lastServerOperationAt: "not connected",
    lastServerReceiptId: "none",
    nativeBaseUrl: `${DEFAULT_DAEMON_ENDPOINT}/api/v1`,
    openAiCompatibleBaseUrl: `${DEFAULT_DAEMON_ENDPOINT}/v1`,
    loadedInstances: 1,
    mountedEndpoints: 2,
    idleTtlSeconds: 900,
    autoEvict: true,
    providerSummary: "fixture projection",
  },
  catalog: {
    providers: [
      {
        id: "catalog.fixture",
        label: "Fixture catalog",
        status: "available",
        gate: "always_on",
        liveDownloadStatus: "available",
        downloadGate: "fixture",
        formats: ["gguf"],
      },
      {
        id: "catalog.huggingface",
        label: "Hugging Face-compatible catalog",
        status: "gated",
        gate: "IOI_LIVE_MODEL_CATALOG",
        liveDownloadStatus: "gated",
        downloadGate: "IOI_LIVE_MODEL_DOWNLOAD",
        formats: ["gguf", "mlx", "safetensors"],
      },
    ],
    formats: ["gguf", "mlx", "safetensors"],
    quantization: ["Q4", "Q5", "Q8", "F16"],
    storageTotal: "unknown",
    storageQuota: "not configured",
    storageStatus: "ok",
    orphanCount: 0,
    fileCount: 0,
  },
  providers: [
    provider("provider.local.folder", "Local model folder", "local_folder", "available", "local_private", "fixture", "local://models", "no auth", [
      "chat",
      "embeddings",
      "structured_output",
      "rerank",
    ], "agentgres_model_registry_fixture"),
    provider("provider.autopilot.local", "Autopilot native local", "ioi_native_local", "available", "local_private", "ioi_native", "local://ioi-native/model-server", "no auth", [
      "chat",
      "responses",
      "embeddings",
      "structured_output",
      "rerank",
    ], "autopilot_native_local_backend_registry"),
    provider("provider.lmstudio", "LM Studio", "lm_studio", "stopped", "local_private", "openai_compatible", "http://127.0.0.1:1234/v1", "no auth", [
      "chat",
      "responses",
      "embeddings",
    ], "~/.local/bin/lm-studio.AppImage or ~/.lmstudio/bin/lms"),
    provider("provider.ollama", "Ollama", "ollama", "blocked", "local_private", "ollama", "http://127.0.0.1:11434", "no auth", [
      "chat",
      "embeddings",
    ], "OLLAMA_HOST"),
    provider("provider.openai-compatible", "OpenAI-compatible", "openai_compatible", "configured", "workspace", "openai_compatible", "http://127.0.0.1:1234/v1", "optional vault auth", [
      "chat",
      "responses",
      "embeddings",
    ], "OPENAI_COMPATIBLE_BASE_URL"),
    provider("provider.openai", "OpenAI BYOK", "openai", "blocked", "hosted", "openai", "vault reference required", "authorization / bearer / vault", [
      "chat",
      "responses",
      "embeddings",
    ], "vault secret reference required"),
    provider("provider.anthropic", "Anthropic BYOK", "anthropic", "blocked", "hosted", "anthropic", "vault reference required", "authorization / bearer / vault", [
      "chat",
      "code",
      "reasoning",
    ], "vault secret reference required"),
    provider("provider.gemini", "Gemini BYOK", "gemini", "blocked", "hosted", "gemini", "vault reference required", "authorization / bearer / vault", [
      "chat",
      "vision",
      "embeddings",
    ], "vault secret reference required"),
    provider("provider.custom-http", "Custom HTTP", "custom_http", "blocked", "workspace", "custom", "not configured", "configurable vault header", ["chat"], "operator provider config"),
    provider("provider.depin-tee", "DePIN / TEE", "depin_tee", "future", "remote_confidential", "runtime_contract", "future runtime profile", "attestation required", [
      "chat",
      "code",
      "receipts",
    ], "future_runtime_profile"),
  ],
  backends: [
    backend("backend.fixture", "Deterministic fixture backend", "fixture", "available", "stateless", "local://ioi-daemon/model-fixture", "fixture", ["fixture"], [
      "chat",
      "responses",
      "embeddings",
      "rerank",
    ], "deterministic_fixture", "normal", "none"),
    backend("backend.autopilot.native-local.fixture", "Autopilot native-local fixture", "native_local", "available", "supervised_fixture", "local://ioi-native/model-server", "fixture", [
      "gguf",
      "fixture",
    ], ["chat", "responses", "embeddings", "rerank"], "autopilot_native_local_backend_registry", "normal", "none"),
    backend("backend.llama-cpp", "llama.cpp native GGUF server", "llama_cpp", "blocked", "binary_absent", "http://127.0.0.1:8080/v1", "not configured", [
      "gguf",
    ], ["chat", "responses", "embeddings"], "IOI_LLAMA_CPP_SERVER_PATH", "normal", "none"),
    backend("backend.ollama", "Ollama local backend", "ollama", "blocked", "external_or_absent", "http://127.0.0.1:11434", "ollama", [
      "ollama_manifest",
    ], ["chat", "embeddings"], "OLLAMA_HOST", "normal", "none"),
    backend("backend.vllm", "vLLM OpenAI-compatible backend", "vllm", "blocked", "external_or_absent", "http://127.0.0.1:8000/v1", "vllm", [
      "safetensors",
      "hf_repository",
    ], ["chat", "responses", "embeddings"], "VLLM_BASE_URL", "normal", "none"),
    backend("backend.lmstudio", "LM Studio public provider", "lm_studio", "stopped", "external_provider", "http://127.0.0.1:1234/v1", "~/.lmstudio/bin/lms", [
      "lm_studio_catalog",
    ], ["chat", "responses", "embeddings"], "lm_studio_public_cli_or_server_probe", "normal", "none"),
  ],
  runtimeEngines: [
    runtimeEngine("backend.autopilot.native-local.fixture", "Autopilot native-local fixture", "native_local", "available", true, "gguf,fixture", "autopilot_backend_registry"),
    runtimeEngine("backend.llama-cpp", "llama.cpp native GGUF server", "llama_cpp", "blocked", false, "gguf", "autopilot_backend_registry"),
    runtimeEngine("lmstudio.runtime.cuda12", "LM Studio CUDA12 llama.cpp runtime", "lm_studio_runtime", "installed", true, "GGUF", "lm_studio_public_lms_runtime_ls"),
  ],
  runtimeSurvey: {
    status: "not_checked",
    checkedAt: "not checked",
    cpu: "x86_64 / probed on demand",
    ram: "available after survey",
    vram: "available after survey",
    memoryPressure: "normal",
    selectedEngine: "backend.autopilot.native-local.fixture",
    receipt: "none",
  },
  artifacts: [
    {
      id: "local.auto",
      name: "local:auto",
      provider: "provider.local.folder",
      state: "installed",
      context: "8k",
      format: "fixture",
      quantization: "fixture",
      source: "operator_import",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    },
    {
      id: "local.embedding.fixture",
      name: "local:embedding-fixture",
      provider: "provider.local.folder",
      state: "installed",
      context: "2k",
      format: "fixture",
      quantization: "fixture",
      source: "operator_import",
      capabilities: ["embeddings"],
    },
    {
      id: "autopilot.native.fixture",
      name: "autopilot:native-fixture",
      provider: "provider.autopilot.local",
      state: "installed",
      context: "8192",
      format: "gguf",
      quantization: "Q4_K_M",
      source: "native_local_fixture",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    },
    {
      id: "lmstudio.detected",
      name: "lmstudio:detected",
      provider: "provider.lmstudio",
      state: "provider_stopped",
      context: "unknown",
      format: "lm_studio",
      quantization: "observed",
      source: "lm_studio_public_lms",
      capabilities: ["chat", "responses", "embeddings"],
    },
  ],
  endpoints: [
    {
      id: "endpoint.local.auto",
      provider: "provider.local.folder",
      apiFormat: "ioi_fixture",
      baseUrl: "local://ioi-daemon/model-fixture",
      modelId: "local:auto",
      privacy: "local_private",
      loadPolicy: "on_demand / idle_evict 900s",
      status: "mounted",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    },
    {
      id: "endpoint.autopilot.native-fixture",
      provider: "provider.autopilot.local",
      apiFormat: "ioi_native",
      baseUrl: "local://ioi-native/model-server",
      modelId: "autopilot:native-fixture",
      privacy: "local_private",
      loadPolicy: "on_demand / idle_evict 900s",
      status: "mounted",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    },
    {
      id: "endpoint.lmstudio.detected",
      provider: "provider.lmstudio",
      apiFormat: "openai_compatible",
      baseUrl: "http://127.0.0.1:1234/v1",
      modelId: "lmstudio:detected",
      privacy: "local_private",
      loadPolicy: "manual when LM Studio is running",
      status: "degraded",
      capabilities: ["chat", "responses", "embeddings"],
    },
  ],
  instances: [
    {
      id: "instance.endpoint.local.auto",
      endpointId: "endpoint.local.auto",
      modelId: "local:auto",
      status: "loaded",
      backend: "ioi_fixture",
      runtimeEngine: "backend.fixture",
      context: "4096",
      parallel: "1",
      identifier: "local:auto",
      ttl: "expires on idle after 900s",
    },
  ],
  downloads: [
    { id: "download_job_fixture", model: "local:auto", status: "completed", progress: "100%", sourceLabel: "Fixture catalog", bytes: "unknown", checksum: "sha256 redacted", receipt: "receipt_model_lifecycle_*" },
    { id: "download_queue_empty", model: "queue", status: "empty", progress: "0 active jobs", sourceLabel: "No queued downloads", bytes: "0", checksum: "none", receipt: "none" },
  ],
  tokens: [
    {
      id: "grant_local_dev",
      audience: "autopilot-local-server",
      allowed: ["model.chat:*", "model.responses:*", "model.embeddings:*", "route.use:*", "mcp.call:huggingface.model_search"],
      denied: ["connector.gmail.send", "filesystem.write", "shell.exec"],
      expires: "24h",
      created: "fixture",
      revoked: "not revoked",
      lastUsed: "not used",
      lastScope: "none",
      state: "active",
      grantId: "grant_local_dev",
      receipt: "receipt_permission_token_*",
      vaultRefs: ["provider.openai-compatible.api-key"],
      auditReceipts: ["receipt_permission_token_*"],
    },
    {
      id: "grant_revoked_fixture",
      audience: "autopilot-local-server",
      allowed: ["model.chat:*"],
      denied: ["model.chat:*"],
      expires: "revoked",
      created: "fixture",
      revoked: "fixture revocation",
      lastUsed: "revoked",
      lastScope: "model.chat:*",
      state: "revoked",
      grantId: "grant_revoked_fixture",
      receipt: "receipt_permission_token_revocation_*",
      vaultRefs: [],
      auditReceipts: ["receipt_permission_token_revocation_*"],
    },
  ],
  vaultAdapter: {
    implementation: "runtime_memory",
    mode: "session-only runtime memory",
    configured: false,
    failClosed: false,
    keyConfigured: false,
    pathHash: "none",
    plaintextPersistence: false,
    evidence: ["VaultMaterialAdapter.runtimeMemory"],
  },
  vaultRefs: [
    {
      hash: "fixture",
      label: "Provider API key",
      purpose: "provider.auth:fixture",
      state: "metadata configured, needs runtime bind",
      lastResolved: "not resolved",
    },
  ],
  mcpServers: [
    {
      id: "mcp.huggingface",
      transport: "remote",
      allowedTools: ["model_search"],
      status: "registered",
      secrets: "vault reference redacted",
    },
    {
      id: "mcp.empty-json",
      transport: "none",
      allowedTools: [],
      status: "empty import accepted",
      secrets: "none",
    },
  ],
  routes: [
    route("route.local-first", "default", "local_or_enterprise", "adaptive", "$0.25", "endpoint.local.auto", "local:auto", "receipt_model_invocation_*"),
    route("route.native-local", "default", "local_only", "deterministic", "$0.00", "endpoint.autopilot.native-fixture", "autopilot:native-fixture", "receipt_model_invocation_*"),
    route("route.verifier.local", "verifier", "local_only", "deterministic", "$0.05", "endpoint.local.auto", "local:auto", "receipt_model_route_selection_*"),
    route("route.hosted-fallback", "planner", "local_or_enterprise", "high", "$0.25", "endpoint.local.auto -> provider.openai-compatible", "blocked by provider policy", "policy blocked"),
  ],
  workflowNodes: [
    "Model Call",
    "Structured Output",
    "Verifier",
    "Planner",
    "Embedding",
    "Reranker",
    "Vision",
    "Local Tool / MCP",
    "Model Router",
    "Receipt Gate",
  ].map((node) => ({ node, routeId: "route.local-first", receiptRequired: true })),
  receipts: [
    receipt("receipt_provider_health_fixture", "provider_health", "Provider provider.ollama health failed closed as blocked.", [
      "provider_health_vault_secret_required",
      "provider.ollama",
    ], "blocked"),
    receipt("receipt_vault_adapter_health_fixture", "vault_adapter_health", "Vault adapter health is ready.", [
      "VaultMaterialAdapter.runtimeMemory",
      "wallet.network_adapter_boundary",
    ], "ready"),
    receipt("receipt_model_lifecycle_*", "model_lifecycle", "mount, load, unload, download, import, and idle eviction state transitions", ["model_registry", "agentgres_canonical_operation_log"]),
    receipt("receipt_model_invocation_*", "model_invocation", "route, endpoint, instance, backend, policy hash, grant id, token counts, latency", ["model_router", "endpoint.local.auto", "wallet.network.capability_grant"], "unknown", {
      routeId: "route.local-first",
      endpointId: "endpoint.local.auto",
      selectedModel: "local:auto",
      providerId: "provider.local-folder",
      instanceId: "instance.local.auto.default",
      backend: "native_local_fixture",
      backendId: "backend.autopilot.native-local.fixture",
      grantId: "wallet.grant.fixture",
      tokenCount: 42,
      latencyMs: 24,
      routeReceiptId: "receipt_model_route_selection_*",
      compatTranslation: "none",
      policyHash: "fixture",
      toolReceiptIds: [],
      providerResponseKind: "chat",
    }),
    receipt("receipt_mcp_tool_invocation_*", "mcp_tool_invocation", "allowed MCP tool execution through RuntimeToolContract", ["RuntimeToolContract", "mcp.huggingface", "tool:model_search"]),
    receipt("receipt_permission_token_*", "permission_token", "scoped, expiring, revocable token with denied connector/filesystem/shell scopes", ["wallet.network.capability_grant", "wallet.network.revocation"]),
  ],
  healthSummary: {
    providerHealthCount: 1,
    vaultHealthCount: 1,
    blockedProviderHealthCount: 1,
    latestReceiptId: "receipt_vault_adapter_health_fixture",
    latestStatus: "ready",
  },
};

function provider(
  id: string,
  label: string,
  kind: string,
  status: string,
  privacy: string,
  apiFormat: string,
  baseUrl: string,
  auth: string,
  capabilities: string[],
  evidence: string,
  authScheme: ProviderDraft["authScheme"] = "bearer",
  authHeaderName = "authorization",
  authState = "not required",
  lastHealth = "not checked",
  healthReceipt = "none",
): ProviderProfile {
  return {
    id,
    label,
    kind,
    status,
    privacy,
    apiFormat,
    baseUrl,
    auth,
    authScheme,
    authHeaderName,
    authState,
    capabilities,
    evidence,
    lastHealth,
    healthReceipt,
  };
}

function backend(
  id: string,
  label: string,
  kind: string,
  status: string,
  processStatus: string,
  baseUrl: string,
  binaryPath: string,
  formats: string[],
  capabilities: string[],
  evidence: string,
  memoryPressure: string,
  receipt: string,
): BackendPreview {
  return { id, label, kind, status, processStatus, baseUrl, binaryPath, formats, capabilities, evidence, memoryPressure, receipt };
}

function runtimeEngine(
  id: string,
  label: string,
  kind: string,
  status: string,
  selected: boolean,
  modelFormat: string,
  source: string,
): RuntimeEnginePreview {
  return { id, label, kind, status, selected, modelFormat, source };
}

function route(
  id: string,
  role: string,
  privacy: string,
  quality: string,
  maxCost: string,
  fallback: string,
  lastSelection: string,
  receiptId: string,
): RoutePolicyPreview {
  return {
    id,
    description: "Operator-defined model route.",
    role,
    privacy,
    quality,
    maxCost,
    maxLatency: "30000ms",
    fallback,
    fallbackIds: fallback.split(" -> ").filter(Boolean),
    providerEligibility: [],
    deniedProviders: [],
    status: "active",
    lastSelection,
    receipt: receiptId,
  };
}

function receipt(
  id: string,
  kind: string,
  summary: string,
  evidence: string[],
  healthStatus = "unknown",
  details: Partial<ReceiptPreview> = {},
): ReceiptPreview {
  return {
    id,
    kind,
    summary,
    redaction: "redacted",
    evidence,
    healthStatus,
    createdAt: details.createdAt ?? "fixture",
    routeId: details.routeId ?? "none",
    endpointId: details.endpointId ?? "none",
    selectedModel: details.selectedModel ?? "none",
    providerId: details.providerId ?? "none",
    instanceId: details.instanceId ?? "none",
    backend: details.backend ?? "none",
    backendId: details.backendId ?? "none",
    grantId: details.grantId ?? "none",
    tokenCount: details.tokenCount ?? 0,
    latencyMs: details.latencyMs ?? 0,
    routeReceiptId: details.routeReceiptId ?? "none",
    compatTranslation: details.compatTranslation ?? "none",
    policyHash: details.policyHash ?? "none",
    toolReceiptIds: details.toolReceiptIds ?? [],
    providerResponseKind: details.providerResponseKind ?? "none",
  };
}

function healthSummaryFromReceipts(receipts: ReceiptPreview[]): HealthSummaryPreview {
  const providerHealthReceipts = receipts.filter((item) => item.kind === "provider_health");
  const vaultHealthReceipts = receipts.filter((item) => item.kind === "vault_adapter_health");
  const healthReceipts = receipts.filter((item) => item.kind === "provider_health" || item.kind === "vault_adapter_health");
  const blockedProviderHealthCount = providerHealthReceipts.filter((item) =>
    /^(blocked|degraded|failed|stopped|unavailable)$/i.test(item.healthStatus) || /blocked|degraded|failed closed/i.test(item.summary),
  ).length;
  const latestHealthReceipt = healthReceipts.at(-1);
  return {
    providerHealthCount: providerHealthReceipts.length,
    vaultHealthCount: vaultHealthReceipts.length,
    blockedProviderHealthCount,
    latestReceiptId: latestHealthReceipt?.id ?? "none",
    latestStatus: latestHealthReceipt?.healthStatus && latestHealthReceipt.healthStatus !== "unknown" ? latestHealthReceipt.healthStatus : "unknown",
  };
}

const emptyPickerSelection: MountsPickerSelection = {
  modelId: "",
  providerId: "",
  endpointId: "",
  routeId: "",
  instanceId: "",
};

function isLoadedInstance(instance: ModelInstance) {
  return instance.status === "loaded";
}

function normalizePickerSelection(data: MountsWorkbenchData, current: MountsPickerSelection): MountsPickerSelection {
  const selectedModelId = data.artifacts.some((artifact) => artifact.name === current.modelId)
    ? current.modelId
    : data.artifacts[0]?.name ?? "";
  const modelEndpoints = data.endpoints.filter((endpoint) => !selectedModelId || endpoint.modelId === selectedModelId);
  const endpointOptions = modelEndpoints.length > 0 ? modelEndpoints : data.endpoints;
  const selectedEndpointId = endpointOptions.some((endpoint) => endpoint.id === current.endpointId)
    ? current.endpointId
    : endpointOptions[0]?.id ?? "";
  const selectedEndpoint = data.endpoints.find((endpoint) => endpoint.id === selectedEndpointId);
  const selectedArtifact = data.artifacts.find((artifact) => artifact.name === selectedModelId);
  const selectedProviderId = data.providers.some((provider) => provider.id === current.providerId)
    ? current.providerId
    : selectedEndpoint?.provider ?? selectedArtifact?.provider ?? data.providers[0]?.id ?? "";
  const selectedRouteId = data.routes.some((routeItem) => routeItem.id === current.routeId)
    ? current.routeId
    : data.routes[0]?.id ?? "";
  const loadedInstances = data.instances.filter(isLoadedInstance);
  const instanceOptions = loadedInstances.length > 0 ? loadedInstances : data.instances;
  const selectedInstanceId = instanceOptions.some((instance) => instance.id === current.instanceId)
    ? current.instanceId
    : instanceOptions[0]?.id ?? "";
  return {
    modelId: selectedModelId,
    providerId: selectedProviderId,
    endpointId: selectedEndpointId,
    routeId: selectedRouteId,
    instanceId: selectedInstanceId,
  };
}

function pickerSelectionChanged(left: MountsPickerSelection, right: MountsPickerSelection) {
  return (
    left.modelId !== right.modelId ||
    left.providerId !== right.providerId ||
    left.endpointId !== right.endpointId ||
    left.routeId !== right.routeId ||
    left.instanceId !== right.instanceId
  );
}

function selectionReceiptText(receiptItem: ReceiptPreview) {
  return `${receiptItem.id} ${receiptItem.summary} ${receiptItem.evidence.join(" ")}`;
}

function modelSelectionDetails(data: MountsWorkbenchData, selection: MountsPickerSelection) {
  const artifact = data.artifacts.find((item) => item.name === selection.modelId);
  const endpoint = data.endpoints.find((item) => item.id === selection.endpointId);
  const provider = data.providers.find((item) => item.id === selection.providerId);
  const routeItem = data.routes.find((item) => item.id === selection.routeId);
  const loadedInstances = data.instances.filter(isLoadedInstance);
  const instance = loadedInstances.find((item) => item.id === selection.instanceId);
  const backend = data.backends.find((item) =>
    item.id === instance?.runtimeEngine || item.id === instance?.backend || item.kind === instance?.backend,
  );
  const runtimeEngine = data.runtimeEngines.find((item) => item.id === instance?.runtimeEngine);
  const relatedEndpoints = data.endpoints.filter((item) => item.modelId === selection.modelId);
  const relatedInstances = data.instances.filter((item) => item.modelId === selection.modelId || item.endpointId === selection.endpointId);
  const relatedDownloads = data.downloads.filter((item) => item.model === selection.modelId || item.model === artifact?.id);
  const needles = [selection.modelId, selection.endpointId, selection.instanceId, selection.routeId, provider?.id, backend?.id].filter(Boolean);
  const relatedReceipts = data.receipts
    .filter((receiptItem) => needles.some((needle) => selectionReceiptText(receiptItem).includes(String(needle))))
    .slice(-6);
  return {
    artifact,
    endpoint,
    provider,
    route: routeItem,
    instance,
    backend,
    runtimeEngine,
    relatedEndpoints,
    relatedInstances,
    relatedDownloads,
    relatedReceipts,
  };
}

function isBlockedStatus(status: string) {
  return /^(blocked|revoked|absent|failed|unavailable|denied|unauthorized|future)$/i.test(status);
}

function isDegradedStatus(status: string) {
  return /^(stopped|degraded|provider_stopped|offline fixture|unknown|not_checked)$/i.test(status);
}

function guardReady(label = "ready", reason = READY_GUARD.reason): ActionGuard {
  return { tone: "ready", label, reason, disabled: false };
}

function guardWarn(label: string, reason: string, disabled = false): ActionGuard {
  return { tone: "warn", label, reason, disabled };
}

function guardBlocked(label: string, reason: string): ActionGuard {
  return { tone: "blocked", label, reason, disabled: true };
}

function combineGuards(...guards: Array<ActionGuard | null | undefined>) {
  const active = guards.filter(Boolean) as ActionGuard[];
  return active.find((guard) => guard.disabled || guard.tone === "blocked") ?? active.find((guard) => guard.tone === "warn") ?? READY_GUARD;
}

function connectionActionGuard(state: ConnectionState, action = "action") {
  if (state === "connected") return guardReady("daemon ready", `${action} can reach the runtime daemon.`);
  if (state === "loading") return guardWarn("loading", "Daemon snapshot is loading; wait for the current refresh before running this action.", true);
  if (state === "degraded") return guardWarn("degraded", "Daemon snapshot is degraded; this action may fail until the endpoint refreshes.");
  return guardBlocked("daemon offline", "Daemon is disconnected, so governed action calls are blocked.");
}

function scopeMatches(pattern: string, scope: string) {
  if (pattern === "*" || pattern === scope) return true;
  if (pattern.endsWith(":*")) return scope.startsWith(pattern.slice(0, -1));
  return false;
}

function tokenExpired(token: PermissionTokenPreview) {
  if (/revoked|expired/i.test(`${token.state} ${token.expires}`)) return true;
  const timestamp = Date.parse(token.expires);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
}

function tokenScopeGuard(data: MountsWorkbenchData, hasSessionToken: boolean, scope: string) {
  const activeTokens = data.tokens.filter((token) => token.state === "active" && !tokenExpired(token));
  const expiredOrRevoked = data.tokens.length > 0 && activeTokens.length === 0 && data.tokens.some((token) => tokenExpired(token) || token.state === "revoked");
  const denied = activeTokens.find((token) => token.denied.some((pattern) => scopeMatches(pattern, scope)));
  if (denied) {
    return guardBlocked("denied scope", `${denied.id} denies ${scope}; the daemon will reject this action.`);
  }
  const allowed = activeTokens.find((token) => token.allowed.some((pattern) => scopeMatches(pattern, scope)));
  if (hasSessionToken && allowed) return guardReady("token ready", `${scope} is allowed by ${allowed.id}.`);
  if (hasSessionToken && expiredOrRevoked) return guardBlocked("token expired", `Projected grants are expired or revoked before ${scope}.`);
  if (!hasSessionToken) {
    return guardWarn("token on demand", `No raw session token is held; the action will mint an in-memory grant before requesting ${scope}.`);
  }
  return guardBlocked("scope missing", `No active capability grant in the projection allows ${scope}.`);
}

function capabilityGuard(capabilities: string[], capability: string, subject = "selection") {
  if (capabilities.includes(capability)) return guardReady("capability ready", `${subject} supports ${capability}.`);
  return guardBlocked("unsupported", `${subject} does not advertise ${capability}.`);
}

function providerGuard(provider: ProviderProfile | undefined, capability?: string, allowProbe = false) {
  if (!provider) return guardBlocked("provider missing", "No provider profile is selected.");
  const vaultBackedKinds = ["openai", "anthropic", "gemini", "custom_http", "depin_tee"];
  const requiresVault = vaultBackedKinds.includes(provider.kind) && /vault required|vault reference required/i.test(`${provider.authState} ${provider.baseUrl} ${provider.auth}`);
  if (requiresVault) {
    return allowProbe
      ? guardWarn("vault ref missing", `${provider.label} needs a vault ref before live provider calls are allowed.`)
      : guardBlocked("vault ref missing", `${provider.label} needs a vault ref before live provider calls are allowed.`);
  }
  if (isBlockedStatus(provider.status)) {
    return allowProbe
      ? guardWarn("provider blocked", `${provider.label} is ${provider.status}; health probes remain available.`)
      : guardBlocked("provider blocked", `${provider.label} is ${provider.status}.`);
  }
  if (isDegradedStatus(provider.status)) {
    return guardWarn("provider degraded", `${provider.label} is ${provider.status}; action may require provider start or reconfiguration.`);
  }
  if (capability) return capabilityGuard(provider.capabilities, capability, provider.label);
  return guardReady("provider ready", `${provider.label} is available.`);
}

function endpointGuard(data: MountsWorkbenchData, endpoint: ModelEndpoint | undefined, capability?: string) {
  if (!endpoint) return guardBlocked("endpoint missing", "No mounted endpoint is selected.");
  const providerItem = data.providers.find((provider) => provider.id === endpoint.provider);
  return combineGuards(
    providerGuard(providerItem, capability),
    isBlockedStatus(endpoint.status)
      ? guardBlocked("endpoint blocked", `${endpoint.id} is ${endpoint.status}.`)
      : isDegradedStatus(endpoint.status)
        ? guardWarn("endpoint degraded", `${endpoint.id} is ${endpoint.status}.`)
        : guardReady("endpoint ready", `${endpoint.id} is mounted.`),
    capability ? capabilityGuard(endpoint.capabilities, capability, endpoint.id) : null,
  );
}

function backendGuard(backend: BackendPreview | undefined, allowStart = false) {
  if (!backend) return guardBlocked("backend missing", "No backend is selected for this action.");
  if (isBlockedStatus(backend.status)) {
    return allowStart
      ? guardWarn("backend blocked", `${backend.label} is ${backend.status}; start/probe can attempt recovery.`)
      : guardBlocked("backend blocked", `${backend.label} is ${backend.status}.`);
  }
  if (isDegradedStatus(backend.status) || /absent|external_or_absent|binary_absent/i.test(backend.processStatus)) {
    return guardWarn("backend degraded", `${backend.label} is ${backend.status} / ${backend.processStatus}.`);
  }
  return guardReady("backend ready", `${backend.label} is available.`);
}

function runtimeEngineGuard(engine: RuntimeEnginePreview) {
  if (engine.selected) return guardWarn("already selected", `${engine.label} is already selected.`, true);
  if (isBlockedStatus(engine.status)) return guardBlocked("engine blocked", `${engine.label} is ${engine.status}.`);
  if (isDegradedStatus(engine.status)) return guardWarn("engine degraded", `${engine.label} is ${engine.status}.`);
  return guardReady("engine ready", `${engine.label} can be selected.`);
}

function modelArtifactGuard(data: MountsWorkbenchData, modelId: string) {
  const artifact = data.artifacts.find((item) => item.name === modelId || item.id === modelId);
  if (!modelId.trim()) return guardBlocked("model missing", "Choose a model before running this action.");
  if (!artifact) return guardWarn("unregistered", `${modelId} is not in the current artifact projection.`);
  if (isBlockedStatus(artifact.state)) return guardBlocked("artifact blocked", `${artifact.name} is ${artifact.state}.`);
  if (isDegradedStatus(artifact.state)) return guardWarn("artifact degraded", `${artifact.name} is ${artifact.state}.`);
  return guardReady("model ready", `${artifact.name} is installed.`);
}

function routePolicyGuard(data: MountsWorkbenchData, routeId: string, endpointId?: string, privacyOverride?: string) {
  const routeItem = data.routes.find((item) => item.id === routeId);
  if (!routeItem) return guardBlocked("route missing", "Choose a route before running this action.");
  const routeText = `${routeItem.status} ${routeItem.lastSelection} ${routeItem.receipt}`;
  if (/blocked|policy blocked/i.test(routeText)) return guardBlocked("policy blocked", `${routeItem.id} is currently policy blocked.`);
  const privacy = privacyOverride || routeItem.privacy;
  const fallbackIds = routeItem.fallbackIds.length > 0 ? routeItem.fallbackIds : csvList(routeItem.fallback);
  const endpointIds = endpointId ? [endpointId, ...fallbackIds] : fallbackIds;
  const hostedEndpoint = endpointIds
    .map((id) => data.endpoints.find((endpoint) => endpoint.id === id))
    .find((endpoint) => {
      const providerItem = data.providers.find((provider) => provider.id === endpoint?.provider);
      return providerItem?.privacy === "hosted";
    });
  if (hostedEndpoint && privacy === "local_only") {
    return guardBlocked("privacy blocked", `${routeItem.id} cannot use hosted endpoint ${hostedEndpoint.id} under local_only policy.`);
  }
  if (endpointId && fallbackIds.length > 0 && !fallbackIds.includes(endpointId)) {
    return guardWarn("fallback differs", `${endpointId} is not in ${routeItem.id}'s fallback order.`);
  }
  return guardReady("route ready", `${routeItem.id} is routable.`);
}

function selectedActionGuard(
  data: MountsWorkbenchData,
  selection: MountsPickerSelection,
  connectionState: ConnectionState,
  hasSessionToken: boolean,
  scope: string,
  capability?: string,
) {
  const details = modelSelectionDetails(data, selection);
  return combineGuards(
    connectionActionGuard(connectionState, scope),
    tokenScopeGuard(data, hasSessionToken, scope),
    modelArtifactGuard(data, selection.modelId),
    endpointGuard(data, details.endpoint, capability),
    routePolicyGuard(data, selection.routeId, selection.endpointId),
  );
}

function providerDraftGuard(draft: ProviderDraft) {
  if (!draft.id.trim()) return guardBlocked("id required", "Provider id is required.");
  if (["openai", "anthropic", "gemini", "custom_http"].includes(draft.kind) && !draft.secretRef.trim()) {
    return guardWarn("vault ref missing", `${draft.kind} should use a vault ref before live calls are allowed.`);
  }
  return guardReady("config ready", "Provider metadata can be saved without plaintext secrets.");
}

function vaultBindGuard(draft: ProviderDraft) {
  if (!draft.secretRef.trim()) return guardBlocked("vault ref missing", "Enter a vault ref before binding secret material.");
  if (!draft.vaultMaterial) return guardBlocked("material missing", "Enter session-only vault material to bind.");
  return guardReady("vault ready", "Vault material will be sent once and not persisted in UI state.");
}

function actionGuardLabel(guard: ActionGuard | undefined) {
  if (!guard || guard.tone === "ready") return null;
  return guard.label;
}

function modelInvocationReceipts(receipts: ReceiptPreview[]) {
  return receipts
    .filter((item) => item.kind === "model_invocation")
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
}

function benchmarkSummary(receipts: ReceiptPreview[]) {
  const invocations = modelInvocationReceipts(receipts);
  const latencies = invocations.map((item) => item.latencyMs).filter((value) => value > 0);
  const totalLatency = latencies.reduce((total, value) => total + value, 0);
  const totalTokens = invocations.reduce((total, item) => total + item.tokenCount, 0);
  return {
    invocations,
    latest: invocations.at(-1),
    totalTokens,
    averageLatencyMs: latencies.length > 0 ? Math.round(totalLatency / latencies.length) : 0,
  };
}

function formatLatency(value: number) {
  if (!value) return "unknown";
  return value >= 1000 ? `${(value / 1000).toFixed(2)}s` : `${value}ms`;
}

function receiptCategory(item: ReceiptPreview): ObservabilityEvent["category"] {
  const text = `${item.kind} ${item.summary} ${item.evidence.join(" ")}`.toLowerCase();
  if (text.includes("server")) return "server";
  if (text.includes("provider")) return "provider";
  if (text.includes("backend") || text.includes("runtime")) return "backend";
  if (text.includes("route")) return "route";
  if (text.includes("mcp") || text.includes("tool")) return "mcp";
  if (text.includes("vault")) return "vault";
  if (text.includes("permission") || text.includes("token") || text.includes("grant")) return "token";
  if (text.includes("workflow") || text.includes("receipt gate")) return "workflow";
  return "model";
}

function receiptDirection(item: ReceiptPreview): ObservabilityEvent["direction"] {
  if (item.kind.includes("selection") || item.kind.includes("import") || item.kind.includes("lifecycle")) return "request";
  return "response";
}

function receiptStatus(item: ReceiptPreview): ObservabilityEvent["status"] {
  const text = `${item.healthStatus} ${item.summary} ${item.evidence.join(" ")}`.toLowerCase();
  if (/denied|revoked|expired|permission|unauthorized|forbidden/.test(text)) return "denied";
  if (/failed|failure|error|blocked|unavailable|absent/.test(text)) return "failed";
  if (/degraded|stopped|unknown|warn/.test(text)) return "degraded";
  return "ready";
}

function receiptEntity(item: ReceiptPreview) {
  return [item.routeId, item.endpointId, item.providerId, item.backendId, item.selectedModel, item.instanceId]
    .filter((value) => value && value !== "none")
    .join(" / ") || item.evidence[0] || item.kind;
}

function redactedPayloadPreview(item: ReceiptPreview): ObservabilityEvent["payload"] {
  const rows = [
    ["route", item.routeId],
    ["endpoint", item.endpointId],
    ["provider", item.providerId],
    ["backend", item.backendId],
    ["model", item.selectedModel],
    ["grant", item.grantId],
    ["policy", item.policyHash],
    ["tokens", item.tokenCount ? String(item.tokenCount) : "redacted"],
    ["latency", formatLatency(item.latencyMs)],
    ["compat", item.compatTranslation],
    ["tools", item.toolReceiptIds.length > 0 ? item.toolReceiptIds.join(", ") : "none"],
  ];
  return rows
    .filter(([, value]) => value && value !== "none")
    .map(([label, value]) => ({ label, value }));
}

function observabilityEventsFromReceipts(receipts: ReceiptPreview[]): ObservabilityEvent[] {
  return receipts.map((item) => {
    const category = receiptCategory(item);
    const direction = receiptDirection(item);
    const status = receiptStatus(item);
    return {
      id: item.id,
      direction,
      category,
      status,
      kind: item.kind,
      summary: item.summary,
      entity: receiptEntity(item),
      routeId: item.routeId,
      endpointId: item.endpointId,
      providerId: item.providerId,
      backendId: item.backendId,
      receipt: item,
      payload: redactedPayloadPreview(item),
    };
  });
}

function filteredObservabilityEvents(receipts: ReceiptPreview[], filters: ObservabilityFilters) {
  const entityNeedle = filters.entity.trim().toLowerCase();
  return observabilityEventsFromReceipts(receipts).filter((event) => {
    if (filters.direction !== "all" && event.direction !== filters.direction) return false;
    if (filters.category !== "all" && event.category !== filters.category) return false;
    if (filters.status !== "all" && event.status !== filters.status) return false;
    if (filters.kind !== "all" && event.kind !== filters.kind) return false;
    if (entityNeedle) {
      const haystack = [
        event.id,
        event.summary,
        event.entity,
        event.routeId,
        event.endpointId,
        event.providerId,
        event.backendId,
        event.receipt.selectedModel,
      ].join(" ").toLowerCase();
      if (!haystack.includes(entityNeedle)) return false;
    }
    return true;
  });
}

function uniqueReceiptKinds(receipts: ReceiptPreview[]) {
  return Array.from(new Set(receipts.map((item) => item.kind))).sort();
}

function observabilitySummary(events: ObservabilityEvent[]) {
  return {
    total: events.length,
    requests: events.filter((event) => event.direction === "request").length,
    responses: events.filter((event) => event.direction === "response").length,
    problemCount: events.filter((event) => event.status === "degraded" || event.status === "denied" || event.status === "failed").length,
  };
}

function readInitialEndpoint() {
  try {
    const requested = new URLSearchParams(window.location.search).get("mountsEndpoint");
    if (requested) return requested;
    const envEndpoint = import.meta.env.VITE_AUTOPILOT_MOUNTS_DAEMON_ENDPOINT;
    if (typeof envEndpoint === "string" && envEndpoint.trim()) return envEndpoint.trim();
    return window.localStorage.getItem(ENDPOINT_STORAGE_KEY) ?? DEFAULT_DAEMON_ENDPOINT;
  } catch {
    return DEFAULT_DAEMON_ENDPOINT;
  }
}

function readInitialTab(): MountsTab {
  try {
    const requested = new URLSearchParams(window.location.search).get("mountsTab");
    if (isMountsTab(requested)) return requested;
    const envTab = import.meta.env.VITE_AUTOPILOT_MOUNTS_INITIAL_TAB;
    if (isMountsTab(envTab)) return envTab;
  } catch {
    // The default tab is enough if the URL cannot be inspected.
  }
  return "server";
}

function useModelMountsDaemon() {
  const [endpoint, setEndpointState] = useState(readInitialEndpoint);
  const [data, setData] = useState<MountsWorkbenchData>(fallbackData);
  const [connectionState, setConnectionState] = useState<ConnectionState>("offline");
  const [message, setMessage] = useState("Rendering offline fixture projection.");
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const setEndpoint = useCallback((nextEndpoint: string) => {
    setEndpointState(nextEndpoint);
    try {
      window.localStorage.setItem(ENDPOINT_STORAGE_KEY, nextEndpoint);
    } catch {
      // Endpoint persistence is optional; the workbench remains usable without it.
    }
  }, []);

  const requestJson = useCallback(
    async (routePath: string, options: { method?: string; body?: unknown; token?: string | null } = {}) => {
      const url = `${endpoint.replace(/\/+$/, "")}${routePath}`;
      const response = await fetch(url, {
        method: options.method ?? "GET",
        headers: {
          accept: "application/json",
          ...(options.body === undefined ? {} : { "content-type": "application/json" }),
          ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
        },
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      });
      const text = await response.text();
      const value = text ? JSON.parse(text) : null;
      if (!response.ok) {
        const error = new Error(errorMessage(value, routePath));
        (error as Error & { status?: number }).status = response.status;
        throw error;
      }
      return value;
    },
    [endpoint],
  );

  const refresh = useCallback(async () => {
    setConnectionState("loading");
    try {
      const snapshot = await requestJson("/api/v1/models");
      setData(normalizeSnapshot(snapshot, endpoint));
      setConnectionState("connected");
      setMessage("Daemon snapshot loaded.");
    } catch (error) {
      setData(fallbackData);
      setConnectionState("degraded");
      setMessage(error instanceof Error ? error.message : "Daemon snapshot unavailable.");
    }
  }, [endpoint, requestJson]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const runAction = useCallback(
    async (label: string, action: () => Promise<string | null | undefined>) => {
      setBusyAction(label);
      try {
        const nextMessage = await action();
        await refresh();
        if (nextMessage) setMessage(nextMessage);
      } catch (error) {
        setConnectionState("degraded");
        setMessage(error instanceof Error ? error.message : `${label} failed.`);
      } finally {
        setBusyAction(null);
      }
    },
    [refresh],
  );

  const issueToken = useCallback(async () => {
    const grant = await requestJson("/api/v1/tokens", {
      method: "POST",
      body: {
        audience: "autopilot-local-server",
        allowed: [
          "model.chat:*",
          "model.responses:*",
          "model.embeddings:*",
          "model.load:*",
          "model.unload:*",
          "model.mount:*",
          "model.download:*",
          "model.import:*",
          "model.delete:*",
          "server.control:*",
          "server.logs:*",
          "backend.control:*",
          "provider.write:*",
          "vault.write:*",
          "vault.read:*",
          "vault.delete:*",
          "route.write:*",
          "route.use:*",
          "mcp.import:*",
          "mcp.call:huggingface.model_search",
        ],
        denied: ["connector.gmail.send", "filesystem.write", "shell.exec"],
      },
    });
    if (typeof grant?.token !== "string") {
      throw new Error("Daemon did not return an ephemeral token.");
    }
    setSessionToken(grant.token);
    return grant.token;
  }, [requestJson]);

  const ensureToken = useCallback(async () => sessionToken ?? (await issueToken()), [issueToken, sessionToken]);

  return {
    endpoint,
    setEndpoint,
    data,
    connectionState,
    message,
    hasSessionToken: Boolean(sessionToken),
    sessionTokenLabel: sessionToken ? `${sessionToken.slice(0, 10)}...session` : "none",
    busyAction,
    refresh,
    actions: {
      issueToken: () =>
        runAction("issue-token", async () => {
          await issueToken();
          return "Session capability token issued in memory.";
        }),
      createTokenFromDraft: (draft: TokenDraft) =>
        runAction("token-create", async () => {
          const grant = await requestJson("/api/v1/tokens", {
            method: "POST",
            body: tokenDraftPayload(draft),
          });
          if (typeof grant?.token !== "string") {
            throw new Error("Daemon did not return an ephemeral token.");
          }
          setSessionToken(grant.token);
          const tokenId = stringValue(grant?.id, stringValue(grant?.public?.id, "capability grant"));
          return `${tokenId} created; raw token retained in memory for this session only.`;
        }),
      revokeTokenGrant: (tokenId: string) =>
        runAction("token-revoke", async () => {
          await requestJson(`/api/v1/tokens/${encodeURIComponent(tokenId)}`, { method: "DELETE" });
          return `${tokenId} revoked through the wallet authority boundary.`;
        }),
      startServer: () =>
        runAction("server-start", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/server/start", { method: "POST", token });
          return `Local server control is ${stringValue(result?.controlStatus, "running")}; receipt ${stringValue(result?.receiptId, "none")}.`;
        }),
      stopServer: () =>
        runAction("server-stop", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/server/stop", { method: "POST", token });
          return `Local server control is ${stringValue(result?.controlStatus, "stopped")}; receipt ${stringValue(result?.receiptId, "none")}.`;
        }),
      restartServer: () =>
        runAction("server-restart", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/server/restart", { method: "POST", token });
          return `Local server restart recorded; receipt ${stringValue(result?.receiptId, "none")}.`;
        }),
      tailServerLogs: () =>
        runAction("server-logs", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/server/logs?limit=20", { token });
          const count = Array.isArray(result?.records) ? result.records.length : 0;
          return `Read ${count} redacted server log record${count === 1 ? "" : "s"}; receipt ${stringValue(result?.receiptId, "none")}.`;
        }),
      probeNativeBackend: () =>
        runAction("backend-health", async () => {
          await requestJson("/api/v1/backends/backend.autopilot.native-local.fixture/health", {
            method: "POST",
          });
          return "Native-local backend health receipt recorded.";
        }),
      startNativeBackend: () =>
        runAction("backend-start", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/backends/backend.autopilot.native-local.fixture/start", {
            method: "POST",
            token,
          });
          return "Native-local backend start event recorded through the backend control path.";
        }),
      stopNativeBackend: () =>
        runAction("backend-stop", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/backends/backend.autopilot.native-local.fixture/stop", {
            method: "POST",
            token,
          });
          return "Native-local backend stop event recorded through the backend control path.";
        }),
      loadLocalModel: () =>
        runAction("load-local", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/models/load", {
            method: "POST",
            token,
            body: { model_id: "local:auto", load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true } },
          });
          return "local:auto loaded through the governed model path.";
        }),
      loadNativeLocalModel: () =>
        runAction("load-native-local", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/models/load", {
            method: "POST",
            token,
            body: {
              model_id: "autopilot:native-fixture",
              load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
            },
          });
          return "Autopilot native-local fixture loaded without LM Studio.";
        }),
      downloadFixture: () =>
        runAction("download-fixture", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/models/download", {
            method: "POST",
            token,
            body: {
              model_id: `autopilot:download-${Date.now()}`,
              provider_id: "provider.autopilot.local",
              source_url: "fixture://autopilot/native-local",
            },
          });
          return "Download lifecycle completed through queued, running, and completed receipts.";
        }),
      searchCatalog: (draft: CatalogSearchDraft) =>
        runAction("catalog-search", async () => {
          const params = new URLSearchParams({
            q: draft.query || "autopilot",
            format: draft.format,
            quantization: draft.quantization,
            limit: draft.limit || "20",
          });
          const result = await requestJson(`/api/v1/models/catalog/search?${params.toString()}`);
          const count = Array.isArray(result?.results) ? result.results.length : 0;
          const live = Array.isArray(result?.providers)
            ? result.providers.find((provider: any) => provider.id === "catalog.huggingface")
            : null;
          return `Catalog search found ${count} variant${count === 1 ? "" : "s"}; Hugging Face-compatible catalog is ${stringValue(live?.status, "unknown")}.`;
        }),
      importCatalogUrl: (sourceUrl: string) =>
        runAction("catalog-import-url", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/models/catalog/import-url", {
            method: "POST",
            token,
            body: { source_url: sourceUrl || "fixture://catalog/autopilot-native-3b-q4" },
          });
          return `Catalog URL import created ${stringValue(result?.download?.id, "a download job")}.`;
        }),
      cleanupStorage: () =>
        runAction("storage-cleanup", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/models/storage/cleanup", { method: "POST", token });
          return `Storage cleanup scanned ${numberValue(result?.scannedFileCount, 0)} model file${numberValue(result?.scannedFileCount, 0) === 1 ? "" : "s"}; ${numberValue(result?.orphanCount, 0)} orphan${numberValue(result?.orphanCount, 0) === 1 ? "" : "s"}.`;
        }),
      nativeChatProbe: () =>
        runAction("native-chat", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/chat", {
            method: "POST",
            token,
            body: { model: "local:auto", input: "Autopilot Mounts workbench probe" },
          });
          return "Native chat probe produced a model invocation receipt.";
        }),
      runBenchmark: (selection: MountsPickerSelection, draft: BenchmarkDraft) =>
        runAction("benchmark-run", async () => {
          const token = await ensureToken();
          const routeId = selection.routeId || "route.local-first";
          const modelId = selection.modelId || undefined;
          const prompt = draft.prompt.trim() || defaultBenchmarkDraft.prompt;
          const samples = Math.min(5, Math.max(1, Number.parseInt(draft.samples, 10) || 1));
          const modelPolicy = {
            privacy: draft.privacy,
            max_cost_usd: Number(draft.maxCostUsd || 0.05),
          };
          const receiptIds: string[] = [];
          const routeTest = await requestJson(`/api/v1/routes/${encodeURIComponent(routeId)}/test`, {
            method: "POST",
            token,
            body: { capability: "chat", model: modelId, model_policy: modelPolicy },
          });
          receiptIds.push(stringValue(routeTest?.receipt?.id, "route receipt"));
          for (let index = 0; index < samples; index += 1) {
            const chat = await requestJson("/api/v1/chat", {
              method: "POST",
              token,
              body: {
                route_id: routeId,
                model: modelId,
                input: `${prompt}\n\nBenchmark sample ${index + 1}/${samples}.`,
                model_policy: modelPolicy,
              },
            });
            receiptIds.push(stringValue(chat?.receipt_id, "chat receipt"));
          }
          if (draft.includeResponses) {
            const response = await requestJson("/api/v1/responses", {
              method: "POST",
              token,
              body: {
                route_id: routeId,
                model: modelId,
                input: `${prompt}\n\nBenchmark responses pass.`,
                model_policy: modelPolicy,
              },
            });
            receiptIds.push(stringValue(response?.receipt_id, "responses receipt"));
          }
          if (draft.includeEmbeddings) {
            const embedding = await requestJson("/api/v1/embeddings", {
              method: "POST",
              token,
              body: {
                route_id: routeId,
                model: modelId,
                input: [prompt, selection.endpointId || routeId],
                model_policy: modelPolicy,
              },
            });
            receiptIds.push(stringValue(embedding?.receipt_id, "embedding receipt"));
          }
          return `Benchmark completed for ${routeId}; ${receiptIds.length} receipt${receiptIds.length === 1 ? "" : "s"} recorded.`;
        }),
      ephemeralMcpProbe: () =>
        runAction("ephemeral-mcp", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/responses", {
            method: "POST",
            token,
            body: {
              route_id: "route.local-first",
              input: "Run an ephemeral MCP parity probe.",
              integrations: [
                {
                  type: "ephemeral_mcp",
                  server_label: "huggingface",
                  server_url: "https://example.invalid/mcp",
                  allowed_tools: ["model_search"],
                  headers: { authorization: "vault://mcp.huggingface/authorization" },
                },
              ],
            },
          });
          return "Ephemeral MCP integration produced linked tool and model receipts.";
        }),
      importMcpFixture: () =>
        runAction("mcp-import", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/mcp/import", {
            method: "POST",
            token,
            body: {
              mcpServers: {
                huggingface: {
                  url: "https://example.invalid/mcp",
                  allowed_tools: ["model_search"],
                  headers: { authorization: "vault://mcp.huggingface/authorization" },
                },
              },
            },
          });
          return "MCP fixture imported with allowed_tools narrowing.";
        }),
      testRoute: () =>
        runAction("route-test", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/routes/route.local-first/test", {
            method: "POST",
            token,
            body: { capability: "chat", model_policy: { privacy: "local_only" } },
          });
          return "Route test selected a local model and emitted a route receipt.";
        }),
      saveRouteDraft: (draft: RouteDraft) =>
        runAction("route-save", async () => {
          const token = await ensureToken();
          const routeResult = await requestJson("/api/v1/routes", {
            method: "POST",
            token,
            body: routeDraftPayload(draft),
          });
          return `${stringValue(routeResult?.id, draft.id)} saved through the governed route write path.`;
        }),
      testRouteDraft: (draft: RouteDraft, selection: MountsPickerSelection) =>
        runAction("route-editor-test", async () => {
          const token = await ensureToken();
          const routeId = draft.id.trim() || "route.local-first";
          await requestJson("/api/v1/routes", {
            method: "POST",
            token,
            body: routeDraftPayload(draft),
          });
          const result = await requestJson(`/api/v1/routes/${encodeURIComponent(routeId)}/test`, {
            method: "POST",
            token,
            body: {
              capability: "chat",
              model: selection.modelId || undefined,
              model_policy: {
                privacy: draft.privacy,
                allow_hosted_fallback: draft.allowHostedFallback,
              },
            },
          });
          const selected = stringValue(result?.selection?.endpoint?.modelId, "a model");
          const receiptId = stringValue(result?.receipt?.id, "recorded");
          return `${routeId} selected ${selected}; receipt ${receiptId}.`;
        }),
      workflowProbe: () =>
        runAction("workflow-probe", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/workflows/nodes/execute", {
            method: "POST",
            token,
            body: { node: "Model Router", model_policy: { privacy: "local_only" } },
          });
          await requestJson("/api/v1/workflows/nodes/execute", {
            method: "POST",
            token,
            body: { node: "Embedding", input: "workflow embedding probe", model_policy: { privacy: "local_only" } },
          });
          return "Workflow model router and embedding nodes executed through the daemon contract.";
        }),
      configureProvider: (draft: ProviderDraft) =>
        runAction("provider-configure", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/providers", {
            method: "POST",
            token,
            body: providerDraftPayload(draft),
          });
          return `${draft.id} configured with vault-backed auth metadata.`;
        }),
      bindVaultSecret: (draft: ProviderDraft) =>
        runAction("vault-bind", async () => {
          const token = await ensureToken();
          await requestJson("/api/v1/vault/refs", {
            method: "POST",
            token,
            body: {
              vault_ref: draft.secretRef.trim(),
              material: draft.vaultMaterial,
              purpose: `provider.auth:${draft.id.trim()}`,
              label: draft.label.trim() || draft.id.trim(),
            },
          });
          return `${draft.id} vault material bound in the local runtime vault.`;
        }),
      checkVaultAdapter: () =>
        runAction("vault-health", async () => {
          const token = await ensureToken();
          const health = await requestJson("/api/v1/vault/health", {
            method: "POST",
            token,
          });
          return `Vault adapter health probe returned ${stringValue(health?.status, "unknown")}.`;
        }),
      latestVaultHealth: () =>
        runAction("vault-health-latest", async () => {
          const token = await ensureToken();
          const latest = await requestJson("/api/v1/vault/health/latest", { token });
          const status = stringValue(latest?.health?.status, "unknown");
          const receiptId = stringValue(latest?.receipt?.id, "no receipt");
          return `Latest vault adapter health is ${status}; receipt ${receiptId}.`;
        }),
      testProviderHealth: (providerId: string) =>
        runAction("provider-health", async () => {
          await requestJson(`/api/v1/providers/${encodeURIComponent(providerId)}/health`, { method: "POST" });
          return `${providerId} health probe completed.`;
        }),
      latestProviderHealth: (providerId: string) =>
        runAction("provider-health-latest", async () => {
          const latest = await requestJson(`/api/v1/providers/${encodeURIComponent(providerId)}/health/latest`);
          const status = stringValue(latest?.health?.status, "unknown");
          const receiptId = stringValue(latest?.receipt?.id, "no receipt");
          return `${providerId} latest health is ${status}; receipt ${receiptId}.`;
        }),
      runHealthSweep: () =>
        runAction("health-sweep", async () => {
          const token = await ensureToken();
          const providerIds = healthSweepProviderTargets(data.providers);
          const backendIds = healthSweepBackendTargets(data.backends);
          const probes = [
            requestJson("/api/v1/vault/health", { method: "POST", token }),
            ...providerIds.map((providerId) =>
              requestJson(`/api/v1/providers/${encodeURIComponent(providerId)}/health`, { method: "POST" }),
            ),
            ...backendIds.map((backendId) =>
              requestJson(`/api/v1/backends/${encodeURIComponent(backendId)}/health`, { method: "POST" }),
            ),
          ];
          const results = await Promise.allSettled(probes);
          const succeeded = results.filter((result) => result.status === "fulfilled").length;
          const failed = results.length - succeeded;
          return `Health sweep recorded ${succeeded}/${results.length} probe${results.length === 1 ? "" : "s"}${failed > 0 ? `; ${failed} failed before projection.` : "."}`;
        }),
      runRuntimeSurvey: () =>
        runAction("runtime-survey", async () => {
          const survey = await requestJson("/api/v1/runtime/survey", { method: "POST" });
          const count = Array.isArray(survey?.engines) ? survey.engines.length : 0;
          const receiptId = stringValue(survey?.receiptId, "no receipt");
          return `Runtime survey captured ${count} engine profile${count === 1 ? "" : "s"}; receipt ${receiptId}.`;
        }),
      selectRuntimeEngine: (engineId: string) =>
        runAction("runtime-select", async () => {
          const selection = await requestJson("/api/v1/runtime/select", {
            method: "POST",
            body: { engine_id: engineId },
          });
          return `${stringValue(selection?.selectedEngineId, engineId)} selected for subsequent loads.`;
        }),
      loadModelWithOptions: (draft: ModelLoadDraft) =>
        runAction(draft.estimateOnly ? "load-estimate" : "load-options", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/models/load", {
            method: "POST",
            token,
            body: loadDraftBody(draft),
          });
          if (draft.estimateOnly) {
            return `${draft.modelId} estimate recorded; receipt ${stringValue(result?.receiptId, "none")}.`;
          }
          return `${draft.modelId} loaded as ${stringValue(result?.identifier, "default")} with context ${stringValue(result?.contextLength, "auto")}.`;
        }),
      loadPickerSelection: (selection: MountsPickerSelection) =>
        runAction("picker-load", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/models/load", {
            method: "POST",
            token,
            body: {
              model_id: selection.modelId,
              endpoint_id: selection.endpointId || undefined,
              route_id: selection.routeId || undefined,
              load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
              load_options: { identifier: selection.modelId ? `${selection.modelId}-picker` : "picker-load" },
            },
          });
          return `${stringValue(result?.modelId, selection.modelId)} loaded from picker; receipt ${stringValue(result?.receiptId, "recorded")}.`;
        }),
      unloadInstance: (instanceId: string) =>
        runAction("picker-unload", async () => {
          const token = await ensureToken();
          const result = await requestJson("/api/v1/models/unload", {
            method: "POST",
            token,
            body: { instance_id: instanceId },
          });
          return `${stringValue(result?.modelId, "Selected model")} unloaded; instance ${instanceId}.`;
        }),
      replayReceipt: (receiptId: string) =>
        runAction("receipt-replay", async () => {
          const replay = await requestJson(`/api/v1/receipts/${encodeURIComponent(receiptId)}/replay`);
          const kind = stringValue(replay?.receipt?.kind, "receipt");
          return `Replayed ${kind} receipt ${receiptId}.`;
        }),
      listProviderModels: (providerId: string) =>
        runAction("provider-models", async () => {
          const models = await requestJson(`/api/v1/providers/${encodeURIComponent(providerId)}/models`);
          const count = Array.isArray(models) ? models.length : 0;
          return `${providerId} returned ${count} provider model${count === 1 ? "" : "s"}.`;
        }),
    },
  };
}

function providerDraftPayload(draft: ProviderDraft) {
  const capabilities = draft.capabilities
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return {
    id: draft.id.trim(),
    label: draft.label.trim() || draft.id.trim(),
    kind: draft.kind,
    api_format: draft.apiFormat,
    base_url: draft.baseUrl.trim() || null,
    status: "configured",
    privacy_class: draft.privacyClass,
    capabilities,
    secret_ref: draft.secretRef.trim() || null,
    auth_scheme: draft.authScheme,
    auth_header_name: draft.authHeaderName.trim() || "authorization",
  };
}

function csvList(value: string) {
  return value
    .split(/,|\n| -> /)
    .map((item) => item.trim())
    .filter(Boolean);
}

function tokenScopeList(value: string) {
  return value
    .split(/,|\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function tokenDraftPayload(draft: TokenDraft) {
  const expiresHours = Math.max(1, Number(draft.expiresHours || 24));
  return {
    audience: draft.audience.trim() || "autopilot-local-server",
    allowed: tokenScopeList(draft.allowed),
    denied: tokenScopeList(draft.denied),
    expires_at: new Date(Date.now() + expiresHours * 60 * 60 * 1000).toISOString(),
    grant_id: draft.grantId.trim() || undefined,
  };
}

function tokenVaultRefLabels(value: unknown) {
  if (!value || typeof value !== "object") return [];
  return Object.entries(value as Record<string, unknown>).map(([purpose, refValue]) => {
    const refText = typeof refValue === "string" ? refValue : "vault reference";
    return `${purpose}:${refText}`;
  });
}

function routeDraftFromPolicy(policy: RoutePolicyPreview | undefined, selection: MountsPickerSelection): RouteDraft {
  const fallbackIds = policy?.fallbackIds?.length ? policy.fallbackIds : selection.endpointId ? [selection.endpointId] : ["endpoint.local.auto"];
  return {
    id: policy?.id ?? selection.routeId ?? "route.local-first",
    description: policy?.description ?? "Operator-defined model route.",
    role: policy?.role ?? "default",
    privacy: policy?.privacy ?? "local_or_enterprise",
    quality: policy?.quality ?? "adaptive",
    maxCostUsd: policy?.maxCost?.replace(/^\$/, "") ?? "0.25",
    maxLatencyMs: policy?.maxLatency?.replace(/ms$/, "") ?? "30000",
    fallback: fallbackIds.join(", "),
    providerEligibility: policy?.providerEligibility?.join(", ") ?? "",
    deniedProviders: policy?.deniedProviders?.join(", ") ?? "",
    allowHostedFallback: false,
  };
}

function routeDraftPayload(draft: RouteDraft) {
  return {
    id: draft.id.trim() || "route.local-first",
    description: draft.description.trim() || "Operator-defined model route.",
    role: draft.role.trim() || "default",
    privacy: draft.privacy,
    quality: draft.quality,
    max_cost_usd: Number(draft.maxCostUsd || 0),
    max_latency_ms: Number(draft.maxLatencyMs || 30000),
    fallback: csvList(draft.fallback),
    provider_eligibility: csvList(draft.providerEligibility),
    denied_providers: csvList(draft.deniedProviders),
    status: "active",
  };
}

function healthSweepProviderTargets(providers: ProviderProfile[]) {
  return providers.filter((provider) => provider.status !== "future").map((provider) => provider.id);
}

function healthSweepBackendTargets(backends: BackendPreview[]) {
  return backends.filter((backend) => backend.kind !== "future").map((backend) => backend.id);
}

function normalizeSnapshot(snapshot: any, endpoint: string): MountsWorkbenchData {
  const providers = arrayOf(snapshot?.providers).map((item) =>
    provider(
      stringValue(item.id, "provider.unknown"),
      stringValue(item.label, stringValue(item.id, "Provider")),
      stringValue(item.kind, "custom"),
      stringValue(item.status, "unknown"),
      stringValue(item.privacyClass, stringValue(item.privacy, "workspace")),
      stringValue(item.apiFormat, "unknown"),
      stringValue(item.baseUrl, "not configured"),
      providerAuthPreview(item),
      stringArray(item.capabilities),
      stringArray(item.discovery?.evidenceRefs).join(", ") || "daemon provider profile",
      providerAuthSchemeForUi(item?.authScheme),
      stringValue(item?.authHeaderName, "authorization"),
      providerVaultState(item),
      providerLastHealth(item),
      stringValue(item?.discovery?.lastHealthCheck?.receiptId, "none"),
    ),
  );
  const backends = arrayOf(snapshot?.backends).map((item) =>
    backend(
      stringValue(item.id, "backend.unknown"),
      stringValue(item.label, stringValue(item.id, "Backend")),
      stringValue(item.kind, "custom"),
      stringValue(item.status, "unknown"),
      stringValue(item.processStatus, "unknown"),
      stringValue(item.baseUrl, "not configured"),
      stringValue(item.binaryPath, "not configured"),
      stringArray(item.supportedFormats),
      stringArray(item.capabilities),
      stringArray(item.evidenceRefs).join(", ") || "backend registry",
      stringValue(item.hardware?.memoryPressure, "unknown"),
      stringValue(item.lastReceiptId, "none"),
    ),
  );
  const runtimeEngines = arrayOf(snapshot?.runtimeEngines).map((item) =>
    runtimeEngine(
      stringValue(item.id, "runtime.unknown"),
      stringValue(item.label, stringValue(item.id, "Runtime engine")),
      stringValue(item.kind, "runtime"),
      stringValue(item.status, "unknown"),
      Boolean(item.selected),
      stringValue(item.modelFormat, "unknown"),
      stringValue(item.source, "runtime_engine_registry"),
    ),
  );
  const endpoints = arrayOf(snapshot?.endpoints).map((item) => ({
    id: stringValue(item.id, "endpoint.unknown"),
    provider: stringValue(item.providerId, "provider.unknown"),
    apiFormat: stringValue(item.apiFormat, "unknown"),
    baseUrl: stringValue(item.baseUrl, "not configured"),
    modelId: stringValue(item.modelId, "unknown"),
    privacy: stringValue(item.privacyClass, "workspace"),
    loadPolicy: loadPolicyLabel(item.loadPolicy),
    status: stringValue(item.status, "unknown"),
    capabilities: stringArray(item.capabilities),
  }));
  const artifacts = arrayOf(snapshot?.artifacts).map((item) => ({
    id: stringValue(item.id, "model.unknown"),
    name: stringValue(item.modelId, stringValue(item.displayName, "unknown")),
    provider: stringValue(item.providerId, "provider.unknown"),
    state: stringValue(item.state, "unknown"),
    context: item.contextWindow ? `${item.contextWindow}` : "unknown",
    format: stringValue(item.format, "unknown"),
    quantization: stringValue(item.quantization, "unknown"),
    source: stringValue(item.source, "unknown"),
    capabilities: stringArray(item.capabilities),
  }));
  const instances = arrayOf(snapshot?.instances).map((item) => ({
    id: stringValue(item.id, "instance.unknown"),
    endpointId: stringValue(item.endpointId, "endpoint.unknown"),
    modelId: stringValue(item.modelId, "unknown"),
    status: stringValue(item.status, "unknown"),
    backend: stringValue(item.backend, "unknown"),
    runtimeEngine: stringValue(item.runtimeEngineId, stringValue(item.backendId, "unknown")),
    context: item.contextLength ? `${item.contextLength}` : stringValue(item.loadOptions?.contextLength, "auto"),
    parallel: item.parallelism ? `${item.parallelism}` : stringValue(item.loadOptions?.parallel, "auto"),
    identifier: stringValue(item.identifier, "default"),
    ttl: item.expiresAt ? `expires ${new Date(item.expiresAt).toLocaleTimeString()}` : "no idle expiry",
  }));
  const routes = arrayOf(snapshot?.routes).map((item) =>
    route(
      stringValue(item.id, "route.unknown"),
      stringValue(item.role, "default"),
      stringValue(item.privacy, "local_or_enterprise"),
      stringValue(item.quality, "adaptive"),
      item.maxCostUsd === undefined ? "unset" : `$${item.maxCostUsd}`,
      stringArray(item.fallback).join(" -> ") || "no fallback",
      stringValue(item.lastSelectedModel, "not tested"),
      stringValue(item.lastReceiptId, "none"),
    ),
  );
  for (const [index, item] of arrayOf(snapshot?.routes).entries()) {
    if (!routes[index]) continue;
    routes[index] = {
      ...routes[index],
      description: stringValue(item.description, routes[index].description),
      maxLatency: item.maxLatencyMs === undefined ? routes[index].maxLatency : `${item.maxLatencyMs}ms`,
      fallbackIds: stringArray(item.fallback),
      providerEligibility: stringArray(item.providerEligibility),
      deniedProviders: stringArray(item.deniedProviders),
      status: stringValue(item.status, routes[index].status),
    };
  }
  const receipts = arrayOf(snapshot?.receipts).map((item) =>
    receipt(
      stringValue(item.id, "receipt.unknown"),
      stringValue(item.kind, "receipt"),
      stringValue(item.summary, "Receipt recorded."),
      stringArray(item.evidenceRefs),
      stringValue(item?.details?.status, "unknown"),
      {
        createdAt: stringValue(item.createdAt, "unknown"),
        routeId: stringValue(item?.details?.routeId, "none"),
        endpointId: stringValue(item?.details?.endpointId, "none"),
        selectedModel: stringValue(item?.details?.selectedModel, "none"),
        providerId: stringValue(item?.details?.providerId, "none"),
        instanceId: stringValue(item?.details?.instanceId, "none"),
        backend: stringValue(item?.details?.backend, "none"),
        backendId: stringValue(item?.details?.backendId, stringValue(item?.details?.selectedBackend, "none")),
        grantId: stringValue(item?.details?.grantId, "none"),
        tokenCount: numberValue(item?.details?.tokenCount, 0),
        latencyMs: numberValue(item?.details?.latencyMs, 0),
        routeReceiptId: stringValue(item?.details?.routeReceiptId, "none"),
        compatTranslation: stringValue(item?.details?.compatTranslation, "none"),
        policyHash: stringValue(item?.details?.policyHash, "none"),
        toolReceiptIds: stringArray(item?.details?.toolReceiptIds),
        providerResponseKind: stringValue(item?.details?.providerResponseKind, "none"),
      },
    ),
  );
  return {
    server: {
      status: stringValue(snapshot?.server?.status, "unknown"),
      gatewayStatus: stringValue(snapshot?.server?.gatewayStatus, "unknown"),
      controlStatus: stringValue(snapshot?.server?.controlStatus, stringValue(snapshot?.server?.status, "unknown")),
      lastServerOperation: stringValue(snapshot?.server?.lastServerOperation, "none"),
      lastServerOperationAt: stringValue(snapshot?.server?.lastServerOperationAt, "not recorded"),
      lastServerReceiptId: stringValue(snapshot?.server?.lastServerReceiptId, "none"),
      nativeBaseUrl: stringValue(snapshot?.server?.nativeBaseUrl, `${endpoint}/api/v1`),
      openAiCompatibleBaseUrl: stringValue(snapshot?.server?.openAiCompatibleBaseUrl, `${endpoint}/v1`),
      loadedInstances: numberValue(snapshot?.server?.loadedInstances, instances.filter((item) => item.status === "loaded").length),
      mountedEndpoints: numberValue(snapshot?.server?.mountedEndpoints, endpoints.length),
      idleTtlSeconds: numberValue(snapshot?.server?.idleTtlSeconds, 900),
      autoEvict: Boolean(snapshot?.server?.autoEvict ?? true),
      providerSummary: `${numberValue(snapshot?.server?.providerStates?.available, 0)} available / ${numberValue(snapshot?.server?.providerStates?.degraded, 0)} degraded`,
    },
    catalog: normalizeCatalog(snapshot?.catalog),
    artifacts,
    endpoints,
    instances,
    downloads: arrayOf(snapshot?.downloads).map((item) => ({
      id: stringValue(item.id, "download.unknown"),
      model: stringValue(item.modelId, "unknown"),
      status: stringValue(item.status, "unknown"),
      progress: item.progress === undefined ? "unknown" : `${Math.round(Number(item.progress) * 100)}%`,
      sourceLabel: stringValue(item.sourceLabel, stringValue(item.source, "unknown source")),
      bytes: `${formatBytes(numberValue(item.bytesCompleted, 0))} / ${formatBytes(numberValue(item.bytesTotal, 0))}`,
      checksum: stringValue(item.checksum, "pending"),
      receipt: stringValue(item.receiptId, "none"),
    })),
    backends,
    runtimeEngines,
    runtimeSurvey: normalizeRuntimeSurvey(snapshot?.runtimeSurvey),
    providers,
    tokens: arrayOf(snapshot?.tokens).map((item) => ({
      id: stringValue(item.id, "grant.unknown"),
      audience: stringValue(item.audience, "autopilot-local-server"),
      allowed: stringArray(item.allowed),
      denied: stringArray(item.denied),
      expires: stringValue(item.expiresAt, "unknown"),
      created: stringValue(item.createdAt, "unknown"),
      revoked: stringValue(item.revokedAt, "not revoked"),
      lastUsed: stringValue(item.lastUsedAt, "not used"),
      lastScope: stringValue(item.lastUsedScope, "none"),
      state: item.revokedAt ? "revoked" : "active",
      grantId: stringValue(item.grantId, "wallet.grant.unknown"),
      receipt: stringValue(item.receiptId, "none"),
      vaultRefs: tokenVaultRefLabels(item.vaultRefs),
      auditReceipts: stringArray(item.auditReceiptIds),
    })),
    vaultAdapter: normalizeVaultAdapter(snapshot?.adapterBoundaries?.vault?.materialAdapter),
    vaultRefs: arrayOf(snapshot?.vaultRefs).map((item) => ({
      hash: stringValue(item.vaultRefHash, "unknown").slice(0, 12),
      label: stringValue(item.label, "Vault ref"),
      purpose: stringValue(item.purpose, "provider.auth"),
      state: vaultRefState(item),
      lastResolved: stringValue(item.lastResolvedAt, "not resolved"),
    })),
    mcpServers: arrayOf(snapshot?.mcpServers).map((item) => ({
      id: stringValue(item.id, "mcp.unknown"),
      transport: stringValue(item.transport, "stdio"),
      allowedTools: stringArray(item.allowedTools),
      status: stringValue(item.status, "registered"),
      secrets: Object.keys(item.secretRefs ?? {}).length > 0 ? "vault references" : "none",
    })),
    routes,
    workflowNodes: arrayOf(snapshot?.workflowNodes).map((item) => ({
      node: stringValue(item.node, "Workflow node"),
      routeId: stringValue(item.routeId, "route.local-first"),
      receiptRequired: Boolean(item.receiptRequired ?? true),
    })),
    receipts,
    healthSummary: healthSummaryFromReceipts(receipts),
  };
}

function errorMessage(value: unknown, routePath: string) {
  if (value && typeof value === "object") {
    const error = (value as { error?: { message?: unknown } }).error;
    if (typeof error?.message === "string") return error.message;
  }
  return `Daemon request failed for ${routePath}.`;
}

function providerAuthPreview(item: any) {
  const headerName = stringValue(item?.authHeaderName, "authorization");
  const scheme = stringValue(item?.authScheme, "bearer");
  const configured = Boolean(item?.secretConfigured);
  const required = Boolean(item?.vaultBoundary?.required);
  if (!required && !configured) return "no auth";
  return `${headerName} / ${scheme} / ${providerVaultState(item)}`;
}

function providerVaultState(item: any) {
  const configured = Boolean(item?.secretConfigured || item?.vaultBoundary?.configured);
  if (!configured) return "vault required";
  if (Boolean(item?.vaultBoundary?.resolvedMaterial || item?.vaultBoundary?.runtimeBound)) return "material bound";
  return "vault ref configured, material unbound";
}

function providerLastHealth(item: any) {
  const check = item?.discovery?.lastHealthCheck;
  if (!check) return "not checked";
  const status = stringValue(check.status, "unknown");
  const httpStatus = check.httpStatus ? ` / HTTP ${check.httpStatus}` : "";
  const failure = check.failureCode ? ` / ${check.failureCode}` : "";
  return `${status}${httpStatus}${failure}`;
}

function vaultRefState(item: any) {
  if (Boolean(item?.resolvedMaterial || item?.runtimeBound || item?.materialBound)) return "material bound in runtime session";
  if (Boolean(item?.configured)) return "metadata configured, needs runtime bind";
  return "removed";
}

function normalizeVaultAdapter(item: any): VaultAdapterPreview {
  const implementation = stringValue(item?.implementation, "runtime_memory");
  const configured = Boolean(item?.configured);
  const failClosed = Boolean(item?.failClosed);
  return {
    implementation,
    mode:
      implementation === "encrypted_keychain_vault_adapter"
        ? configured
          ? "restart-durable encrypted keychain"
          : failClosed
            ? "keychain configured but unavailable"
            : "keychain adapter inactive"
        : "session-only runtime memory",
    configured,
    failClosed,
    keyConfigured: Boolean(item?.keyConfigured),
    pathHash: stringValue(item?.pathHash, "none"),
    plaintextPersistence: Boolean(item?.plaintextPersistence ?? false),
    evidence: stringArray(item?.evidenceRefs),
  };
}

function normalizeRuntimeSurvey(item: any): RuntimeSurveyPreview {
  const hardware = item?.hardware ?? {};
  const lmStudio = item?.lmStudio ?? {};
  const accelerator = Array.isArray(lmStudio.accelerators) ? lmStudio.accelerators[0] : null;
  const selectedEngine = Array.isArray(item?.selectedEngines) && item.selectedEngines.length > 0
    ? String(item.selectedEngines[0])
    : stringValue(lmStudio.selectedRuntime, "not selected");
  return {
    status: stringValue(item?.status, item?.receiptId && item.receiptId !== "none" ? "checked" : "not_checked"),
    checkedAt: stringValue(item?.checkedAt, "not checked"),
    cpu: stringValue(lmStudio.cpu, `${stringValue(hardware.platform, "platform")} / ${stringValue(hardware.arch, "arch")} / ${numberValue(hardware.cpuCount, 0)} cores`),
    ram: stringValue(lmStudio.ram, formatBytes(numberValue(hardware.totalMemoryBytes, 0))),
    vram: accelerator ? `${stringValue(accelerator.label, "accelerator")} / ${stringValue(accelerator.vram, "unknown VRAM")}` : runtimeProbeState(hardware.nvidiaSmi),
    memoryPressure: stringValue(hardware.memoryPressure, "unknown"),
    selectedEngine,
    receipt: stringValue(item?.receiptId, "none"),
  };
}

function normalizeCatalog(value: any): CatalogPreview {
  const storage = value?.storage ?? {};
  return {
    providers: arrayOf(value?.providers).map((item) => ({
      id: stringValue(item.id, "catalog.unknown"),
      label: stringValue(item.label, stringValue(item.id, "Catalog provider")),
      status: stringValue(item.status, "unknown"),
      gate: stringValue(item.gate, "not gated"),
      liveDownloadStatus: stringValue(item.liveDownloadStatus, "unknown"),
      downloadGate: stringValue(item.downloadGate, "not gated"),
      formats: stringArray(item.formats),
    })),
    formats: stringArray(value?.filters?.formats),
    quantization: stringArray(value?.filters?.quantization),
    storageTotal: formatBytes(numberValue(storage.totalBytes, 0)),
    storageQuota: storage.quotaBytes ? formatBytes(numberValue(storage.quotaBytes, 0)) : "not configured",
    storageStatus: stringValue(storage.quotaStatus, "unknown"),
    orphanCount: numberValue(storage.orphanCount, 0),
    fileCount: numberValue(storage.fileCount, 0),
  };
}

function loadDraftBody(draft: ModelLoadDraft) {
  const ttlSeconds = Number(draft.ttlSeconds || 900);
  return {
    model_id: draft.modelId || "autopilot:native-fixture",
    load_policy: {
      mode: draft.mode || "on_demand",
      idleTtlSeconds: ttlSeconds,
      autoEvict: true,
    },
    load_options: {
      estimateOnly: draft.estimateOnly,
      gpu: draft.gpu || null,
      contextLength: draft.contextLength ? Number(draft.contextLength) : null,
      parallel: draft.parallel ? Number(draft.parallel) : null,
      ttlSeconds,
      identifier: draft.identifier || null,
    },
  };
}

function runtimeProbeState(value: any) {
  if (!value || typeof value !== "object") return "not probed";
  return value.available ? "available / output redacted" : "not available";
}

function providerAuthSchemeForUi(value: unknown): ProviderDraft["authScheme"] {
  if (value === "api_key" || value === "raw") return value;
  return "bearer";
}

function arrayOf(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown, fallback: string) {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function numberValue(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function formatBytes(value: number) {
  if (!value) return "unknown";
  const gib = value / 1024 / 1024 / 1024;
  return `${gib.toFixed(gib >= 10 ? 1 : 2)} GiB`;
}

function stringArray(value: unknown) {
  return Array.isArray(value) ? value.map(String) : [];
}

function loadPolicyLabel(value: any) {
  if (!value || typeof value !== "object") return "on_demand";
  const mode = stringValue(value.mode, "on_demand");
  const ttl = numberValue(value.idleTtlSeconds ?? value.idle_ttl_seconds, 900);
  return `${mode} / idle_evict ${ttl}s`;
}

function toneForStatus(status: string): StatusTone {
  if (["available", "configured", "mounted", "loaded", "active", "registered", "completed", "connected", "running"].includes(status)) {
    return "ready";
  }
  if (["blocked", "revoked", "absent", "failed"].includes(status)) {
    return "blocked";
  }
  if (["stopped", "degraded", "provider_stopped", "offline fixture"].includes(status)) {
    return "warn";
  }
  if (["future", "empty import accepted", "empty", "unknown", "loading"].includes(status)) {
    return "muted";
  }
  return "neutral";
}

function connectionTone(state: ConnectionState): StatusTone {
  if (state === "connected") return "ready";
  if (state === "loading") return "muted";
  if (state === "degraded") return "warn";
  return "blocked";
}

function StatusPill({ children, tone = "neutral" }: { children: string; tone?: StatusTone }) {
  return <span className={`model-mounts-pill is-${tone}`}>{children}</span>;
}

function ActionButton({
  children,
  onClick,
  disabled,
  guard,
  type = "button",
}: {
  children: string;
  onClick?: () => void;
  disabled?: boolean;
  guard?: ActionGuard;
  type?: "button" | "submit";
}) {
  const guardLabel = actionGuardLabel(guard);
  const isDisabled = disabled || guard?.disabled;
  return (
    <button
      type={type}
      className="model-mounts-action-button"
      onClick={onClick}
      disabled={isDisabled}
      title={guard?.reason}
      aria-label={guard ? `${children}: ${guard.reason}` : children}
      data-guard-tone={guard?.tone}
    >
      <span>{children}</span>
      {guardLabel ? <small className={`model-mounts-action-guard is-${guard?.tone}`}>{guardLabel}</small> : null}
    </button>
  );
}

function GuardFact({ label, guard }: { label: string; guard: ActionGuard }) {
  return (
    <div>
      <span>{label}</span>
      <strong>
        <StatusPill tone={guard.tone}>{guard.label}</StatusPill>
      </strong>
      <small>{guard.reason}</small>
    </div>
  );
}

function TagList({ items }: { items: string[] }) {
  return (
    <div className="model-mounts-tags">
      {items.map((item) => (
        <span key={item}>{item}</span>
      ))}
    </div>
  );
}

function EndpointRow({ endpoint }: { endpoint: ModelEndpoint }) {
  return (
    <article className="model-mounts-endpoint">
      <div className="model-mounts-endpoint-main">
        <div>
          <strong>{endpoint.id}</strong>
          <span>{endpoint.provider} / {endpoint.apiFormat}</span>
        </div>
        <StatusPill tone={toneForStatus(endpoint.status)}>{endpoint.status}</StatusPill>
      </div>
      <dl>
        <div>
          <dt>Model</dt>
          <dd>{endpoint.modelId}</dd>
        </div>
        <div>
          <dt>Base URL</dt>
          <dd>{endpoint.baseUrl}</dd>
        </div>
        <div>
          <dt>Load policy</dt>
          <dd>{endpoint.loadPolicy}</dd>
        </div>
        <div>
          <dt>Privacy</dt>
          <dd>{endpoint.privacy}</dd>
        </div>
      </dl>
      <TagList items={endpoint.capabilities} />
    </article>
  );
}

function ModelPickerStrip({
  data,
  selection,
  connectionState,
  hasSessionToken,
  onSelectionChange,
  onLoadSelection,
  onUnloadInstance,
  onToggleDetails,
  detailsOpen,
  compact,
  busy,
}: {
  data: MountsWorkbenchData;
  selection: MountsPickerSelection;
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onSelectionChange: (patch: Partial<MountsPickerSelection>) => void;
  onLoadSelection: () => void;
  onUnloadInstance: () => void;
  onToggleDetails: () => void;
  detailsOpen: boolean;
  compact?: boolean;
  busy: boolean;
}) {
  const endpointOptions = data.endpoints.filter((endpoint) => endpoint.modelId === selection.modelId);
  const visibleEndpoints = endpointOptions.length > 0 ? endpointOptions : data.endpoints;
  const loadedInstances = data.instances.filter(isLoadedInstance);
  const details = modelSelectionDetails(data, selection);
  const selectedArtifact = details.artifact;
  const selectedEndpoint = details.endpoint;
  const selectedProvider = details.provider;
  const selectedRoute = details.route;
  const selectedInstance = details.instance;
  const selectedReceipts = details.relatedReceipts.slice(-3);
  const loadGuard = selectedActionGuard(data, selection, connectionState, hasSessionToken, "model.load:*", "chat");
  const unloadGuard = combineGuards(
    connectionActionGuard(connectionState, "model.unload:*"),
    tokenScopeGuard(data, hasSessionToken, "model.unload:*"),
    selectedInstance ? guardReady("instance ready", `${selectedInstance.identifier} can be unloaded.`) : guardBlocked("instance missing", "No loaded instance is selected."),
  );
  const tokenGuard = tokenScopeGuard(data, hasSessionToken, "model.chat:*");
  const endpointReadiness = endpointGuard(data, selectedEndpoint, "chat");
  const routeReadiness = routePolicyGuard(data, selection.routeId, selection.endpointId);

  return (
    <section className="model-mounts-picker" aria-label="Quick model picker">
      <div className="model-mounts-picker-controls">
        <label>
          <span>Model</span>
          <select value={selection.modelId} onChange={(event) => onSelectionChange({ modelId: event.target.value })}>
            {data.artifacts.map((artifact) => (
              <option key={artifact.id} value={artifact.name}>{artifact.name}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Provider</span>
          <select value={selection.providerId} onChange={(event) => onSelectionChange({ providerId: event.target.value })}>
            {data.providers.map((providerItem) => (
              <option key={providerItem.id} value={providerItem.id}>{providerItem.label}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Endpoint</span>
          <select value={selection.endpointId} onChange={(event) => onSelectionChange({ endpointId: event.target.value })}>
            {visibleEndpoints.map((endpointItem) => (
              <option key={endpointItem.id} value={endpointItem.id}>{endpointItem.id}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Route</span>
          <select value={selection.routeId} onChange={(event) => onSelectionChange({ routeId: event.target.value })}>
            {data.routes.map((routeItem) => (
              <option key={routeItem.id} value={routeItem.id}>{routeItem.id}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Loaded instance</span>
          <select value={selection.instanceId} onChange={(event) => onSelectionChange({ instanceId: event.target.value })}>
            {loadedInstances.length === 0 ? <option value="">No loaded instances</option> : null}
            {loadedInstances.map((instanceItem) => (
              <option key={instanceItem.id} value={instanceItem.id}>{instanceItem.identifier} / {instanceItem.modelId}</option>
            ))}
          </select>
        </label>
        <div className="model-mounts-picker-actions">
          <ActionButton onClick={onLoadSelection} disabled={busy || !selection.modelId} guard={loadGuard}>Load selection</ActionButton>
          <ActionButton onClick={onUnloadInstance} disabled={busy || !selectedInstance} guard={unloadGuard}>Unload instance</ActionButton>
          <ActionButton onClick={onToggleDetails}>{detailsOpen ? "Hide details" : "Open details"}</ActionButton>
        </div>
      </div>

      <div className="model-mounts-action-readiness" aria-label="Action readiness states">
        <GuardFact label="Daemon" guard={connectionActionGuard(connectionState, "Mounts action")} />
        <GuardFact label="Token" guard={tokenGuard} />
        <GuardFact label="Endpoint" guard={endpointReadiness} />
        <GuardFact label="Route policy" guard={routeReadiness} />
      </div>

      {compact ? null : (
      <div className="model-mounts-picker-inspector" aria-label="Model selection inspector">
        <div>
          <span>Artifact</span>
          <strong>{selectedArtifact?.name ?? "none"}</strong>
          <small>{selectedArtifact ? `${selectedArtifact.format} / ${selectedArtifact.quantization} / ctx ${selectedArtifact.context}` : "No model selected"}</small>
        </div>
        <div>
          <span>Endpoint</span>
          <strong>{selectedEndpoint?.id ?? "none"}</strong>
          <small>{selectedEndpoint ? `${selectedEndpoint.apiFormat} / ${selectedEndpoint.loadPolicy}` : "No endpoint selected"}</small>
        </div>
        <div>
          <span>Provider</span>
          <strong>{selectedProvider?.label ?? "none"}</strong>
          <small>{selectedProvider ? `${selectedProvider.kind} / ${selectedProvider.status}` : "No provider selected"}</small>
        </div>
        <div>
          <span>Route</span>
          <strong>{selectedRoute?.id ?? "none"}</strong>
          <small>{selectedRoute ? `${selectedRoute.privacy} / fallback ${selectedRoute.fallback}` : "No route selected"}</small>
        </div>
        <div>
          <span>Instance</span>
          <strong>{selectedInstance?.identifier ?? "none loaded"}</strong>
          <small>{selectedInstance ? `${selectedInstance.backend} / ctx ${selectedInstance.context} / ${selectedInstance.ttl}` : "Load a model to inspect runtime state"}</small>
        </div>
        <div>
          <span>Receipts</span>
          <strong>{selectedReceipts.length > 0 ? selectedReceipts.at(-1)?.id : "none linked"}</strong>
          <small>{selectedReceipts.length > 0 ? selectedReceipts.map((receiptItem) => receiptItem.kind).join(", ") : "Recent linked receipts appear here"}</small>
        </div>
      </div>
      )}
    </section>
  );
}

function DetailFact({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="model-mounts-detail-fact">
      <span>{label}</span>
      <strong>{value}</strong>
      {note ? <small>{note}</small> : null}
    </div>
  );
}

function ModelDetailDrawer({
  data,
  selection,
  open,
  onClose,
}: {
  data: MountsWorkbenchData;
  selection: MountsPickerSelection;
  open: boolean;
  onClose: () => void;
}) {
  if (!open) return null;
  const details = modelSelectionDetails(data, selection);
  const artifact = details.artifact;
  const endpoint = details.endpoint;
  const provider = details.provider;
  const instance = details.instance;
  const backend = details.backend;
  const runtimeEngine = details.runtimeEngine;
  const routeItem = details.route;
  const receiptTrail = details.relatedReceipts.length > 0 ? details.relatedReceipts : data.receipts.slice(-4);
  const downloadTrail = details.relatedDownloads.length > 0 ? details.relatedDownloads : data.downloads.slice(0, 3);
  return (
    <aside className="model-mounts-detail-drawer" aria-label="Selected model detail drawer">
      <div className="model-mounts-detail-head">
        <div>
          <span className="model-mounts-kicker">Selected model detail</span>
          <h3>{artifact?.name ?? (selection.modelId || "No model selected")}</h3>
          <div className="model-mounts-tags">
            <span>{artifact?.format ?? "format unknown"}</span>
            <span>{artifact?.quantization ?? "quantization unknown"}</span>
            <span>{endpoint?.privacy ?? "privacy unknown"}</span>
          </div>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone={toneForStatus(artifact?.state ?? "unknown")}>{artifact?.state ?? "unknown"}</StatusPill>
          <StatusPill tone={toneForStatus(instance?.status ?? "empty")}>{instance?.status ?? "not loaded"}</StatusPill>
          <ActionButton onClick={onClose}>Close details</ActionButton>
        </div>
      </div>

      <div className="model-mounts-detail-grid">
        <section className="model-mounts-detail-section" aria-label="Artifact metadata">
          <h4>Artifact metadata</h4>
          <div className="model-mounts-detail-facts">
            <DetailFact label="Artifact id" value={artifact?.id ?? "unknown"} />
            <DetailFact label="Provider" value={artifact?.provider ?? provider?.id ?? "unknown"} note={provider?.label} />
            <DetailFact label="Source" value={artifact?.source ?? "unknown"} />
            <DetailFact label="Context" value={artifact?.context ?? "unknown"} />
          </div>
          <TagList items={artifact?.capabilities ?? []} />
        </section>

        <section className="model-mounts-detail-section" aria-label="Runtime binding">
          <h4>Runtime binding</h4>
          <div className="model-mounts-detail-facts">
            <DetailFact label="Endpoint" value={endpoint?.id ?? "none"} note={endpoint?.apiFormat} />
            <DetailFact label="Base URL" value={endpoint?.baseUrl ?? "not mounted"} />
            <DetailFact label="Backend" value={backend?.label ?? instance?.backend ?? "not loaded"} note={backend?.processStatus} />
            <DetailFact label="Runtime" value={runtimeEngine?.label ?? instance?.runtimeEngine ?? "not selected"} note={runtimeEngine?.status} />
            <DetailFact label="Instance" value={instance?.identifier ?? "not loaded"} note={instance ? `ctx ${instance.context} / p${instance.parallel} / ${instance.ttl}` : undefined} />
            <DetailFact label="Route" value={routeItem?.id ?? "none"} note={routeItem ? `${routeItem.privacy} / ${routeItem.quality}` : undefined} />
          </div>
        </section>

        <section className="model-mounts-detail-section" aria-label="Lifecycle history">
          <h4>Lifecycle history</h4>
          <div className="model-mounts-detail-list">
            {details.relatedEndpoints.map((item) => (
              <div key={item.id}>
                <strong>{item.id}</strong>
                <span>{item.status} / {item.loadPolicy}</span>
              </div>
            ))}
            {details.relatedInstances.map((item) => (
              <div key={item.id}>
                <strong>{item.identifier}</strong>
                <span>{item.status} / {item.backend} / {item.ttl}</span>
              </div>
            ))}
            {downloadTrail.map((item) => (
              <div key={item.id}>
                <strong>{item.model}</strong>
                <span>{item.status} / {item.progress}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="model-mounts-detail-section" aria-label="Receipt trail">
          <h4>Receipt trail</h4>
          <div className="model-mounts-detail-list">
            {receiptTrail.map((item) => (
              <div key={item.id}>
                <strong>{item.kind}</strong>
                <span>{item.id}</span>
                <small>{item.summary}</small>
              </div>
            ))}
          </div>
        </section>
      </div>
    </aside>
  );
}

function ServerPanel({
  data,
  endpoint,
  setEndpoint,
  connectionState,
  hasSessionToken,
  sessionTokenLabel,
  message,
  onRefresh,
  onIssueToken,
  onStartServer,
  onStopServer,
  onRestartServer,
  onTailServerLogs,
  onNativeChatProbe,
  onRunHealthSweep,
  busy,
}: {
  data: MountsWorkbenchData;
  endpoint: string;
  setEndpoint: (value: string) => void;
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  sessionTokenLabel: string;
  message: string;
  onRefresh: () => void;
  onIssueToken: () => void;
  onStartServer: () => void;
  onStopServer: () => void;
  onRestartServer: () => void;
  onTailServerLogs: () => void;
  onNativeChatProbe: () => void;
  onRunHealthSweep: () => void;
  busy: boolean;
}) {
  const serverConnectionGuard = connectionActionGuard(connectionState, "server control");
  const serverControlGuard = combineGuards(serverConnectionGuard, tokenScopeGuard(data, hasSessionToken, "server.control:*"));
  const serverLogsGuard = combineGuards(serverConnectionGuard, tokenScopeGuard(data, hasSessionToken, "server.logs:*"));
  const chatGuard = combineGuards(
    serverConnectionGuard,
    tokenScopeGuard(data, hasSessionToken, "model.chat:*"),
    data.endpoints.some((endpointItem) => endpointItem.capabilities.includes("chat"))
      ? guardReady("chat ready", "At least one mounted endpoint advertises chat.")
      : guardBlocked("chat missing", "No mounted endpoint advertises chat."),
  );
  const healthGuard = combineGuards(serverConnectionGuard, tokenScopeGuard(data, hasSessionToken, "vault.read:*"));
  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-server-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Developer / Local Server</span>
          <h3 id="model-mounts-server-title">Runtime gateway</h3>
        </div>
        <div className="model-mounts-actions" aria-label="Server state">
          <StatusPill tone={connectionTone(connectionState)}>{connectionState}</StatusPill>
          <StatusPill tone={toneForStatus(data.server.status)}>{data.server.status}</StatusPill>
          <StatusPill tone={toneForStatus(data.server.controlStatus)}>{data.server.controlStatus}</StatusPill>
          <StatusPill tone="ready">policy enforced</StatusPill>
        </div>
      </div>

      <div className="model-mounts-control-row">
        <label>
          <span>Daemon endpoint</span>
          <input value={endpoint} onChange={(event) => setEndpoint(event.target.value)} spellCheck={false} />
        </label>
        <div className="model-mounts-actions">
          <ActionButton onClick={onRefresh} disabled={busy}>Refresh</ActionButton>
          <ActionButton onClick={onIssueToken} disabled={busy} guard={serverConnectionGuard}>Issue token</ActionButton>
          <ActionButton onClick={onStartServer} disabled={busy} guard={serverControlGuard}>Start</ActionButton>
          <ActionButton onClick={onStopServer} disabled={busy} guard={serverControlGuard}>Stop</ActionButton>
          <ActionButton onClick={onRestartServer} disabled={busy} guard={serverControlGuard}>Restart</ActionButton>
          <ActionButton onClick={onTailServerLogs} disabled={busy} guard={serverLogsGuard}>Tail logs</ActionButton>
          <ActionButton onClick={onNativeChatProbe} disabled={busy} guard={chatGuard}>Native chat probe</ActionButton>
          <ActionButton onClick={onRunHealthSweep} disabled={busy} guard={healthGuard}>Run health sweep</ActionButton>
        </div>
      </div>

      <div className="model-mounts-server-grid">
        <div>
          <span>Status</span>
          <strong>{data.server.status}</strong>
        </div>
        <div>
          <span>Gateway</span>
          <strong>{data.server.gatewayStatus}</strong>
        </div>
        <div>
          <span>Control</span>
          <strong>{data.server.controlStatus}</strong>
        </div>
        <div>
          <span>Native API</span>
          <strong>{data.server.nativeBaseUrl}</strong>
        </div>
        <div>
          <span>OpenAI compatible</span>
          <strong>{data.server.openAiCompatibleBaseUrl}</strong>
        </div>
        <div>
          <span>Session token</span>
          <strong>{sessionTokenLabel}</strong>
        </div>
        <div>
          <span>Loaded now</span>
          <strong>{data.server.loadedInstances} instance(s)</strong>
        </div>
        <div>
          <span>Mounted endpoints</span>
          <strong>{data.server.mountedEndpoints} endpoint(s)</strong>
        </div>
        <div>
          <span>Idle TTL</span>
          <strong>{data.server.idleTtlSeconds}s / {data.server.autoEvict ? "auto-evict" : "manual"}</strong>
        </div>
        <div>
          <span>Providers</span>
          <strong>{data.server.providerSummary}</strong>
        </div>
        <div>
          <span>Last server op</span>
          <strong>{data.server.lastServerOperation}</strong>
        </div>
        <div>
          <span>Server receipt</span>
          <strong>{data.server.lastServerReceiptId}</strong>
        </div>
      </div>

      <HealthSummaryStrip summary={data.healthSummary} />

      <div className="model-mounts-notice">{message}</div>

      <div className="model-mounts-route-list" aria-label="Server routes">
        {[
          "GET /api/v1/server/status",
          "POST /api/v1/server/start",
          "POST /api/v1/server/stop",
          "POST /api/v1/server/restart",
          "GET /api/v1/server/logs",
          "GET /api/v1/server/events",
          "GET /api/v1/runtime/engines",
          "POST /api/v1/runtime/survey",
          "POST /api/v1/runtime/select",
          "GET /api/v1/backends",
          "POST /api/v1/backends/:id/health",
          "POST /api/v1/backends/:id/start",
          "POST /api/v1/backends/:id/stop",
          "GET /api/v1/backends/:id/logs",
          "GET /api/v1/models",
          "POST /api/v1/models/load",
          "POST /api/v1/models/unload",
          "POST /api/v1/models/download",
          "GET /api/v1/models/catalog/search",
          "POST /api/v1/models/catalog/import-url",
          "POST /api/v1/models/storage/cleanup",
          "DELETE /api/v1/models/:id",
          "POST /api/v1/models/download/cancel/:job_id",
          "POST /api/v1/models/download/:job_id/cancel",
          "GET /api/v1/vault/refs",
          "GET /api/v1/vault/status",
          "POST /api/v1/vault/health",
          "GET /api/v1/vault/health/latest",
          "POST /api/v1/vault/refs",
          "GET /api/v1/providers/:id/models",
          "GET /api/v1/providers/:id/loaded",
          "GET /api/v1/providers/:id/health/latest",
          "POST /api/v1/chat",
          "GET /v1/models",
          "POST /v1/chat/completions",
          "POST /api/v1/mcp/import",
          "POST /api/v1/workflows/nodes/execute",
          "GET /api/v1/receipts",
          "GET /api/v1/receipts/:id/replay",
          "GET /api/v1/projections/model-mounting",
        ].map((routePath) => (
          <code key={routePath}>{routePath}</code>
        ))}
      </div>
    </section>
  );
}

function HealthSummaryStrip({ summary }: { summary: HealthSummaryPreview }) {
  return (
    <div className="model-mounts-health-strip" aria-label="Health summary">
      <div>
        <span>Health summary</span>
        <strong>Receipts projection</strong>
      </div>
      <div>
        <span>Provider health receipts</span>
        <strong>{summary.providerHealthCount}</strong>
      </div>
      <div>
        <span>Vault health receipts</span>
        <strong>{summary.vaultHealthCount}</strong>
      </div>
      <div>
        <span>Blocked/degraded</span>
        <strong>
          <StatusPill tone={summary.blockedProviderHealthCount > 0 ? "blocked" : "ready"}>
            {String(summary.blockedProviderHealthCount)}
          </StatusPill>
        </strong>
      </div>
      <div>
        <span>Latest health receipt</span>
        <strong>
          <StatusPill tone={toneForStatus(summary.latestStatus)}>{summary.latestStatus}</StatusPill>
          <small>{summary.latestReceiptId}</small>
        </strong>
      </div>
    </div>
  );
}

function BackendsPanel({
  data,
  backends,
  runtimeEngines,
  runtimeSurvey,
  connectionState,
  hasSessionToken,
  onProbeNativeBackend,
  onStartNativeBackend,
  onStopNativeBackend,
  onRunRuntimeSurvey,
  onSelectRuntimeEngine,
  busy,
}: {
  data: MountsWorkbenchData;
  backends: BackendPreview[];
  runtimeEngines: RuntimeEnginePreview[];
  runtimeSurvey: RuntimeSurveyPreview;
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onProbeNativeBackend: () => void;
  onStartNativeBackend: () => void;
  onStopNativeBackend: () => void;
  onRunRuntimeSurvey: () => void;
  onSelectRuntimeEngine: (engineId: string) => void;
  busy: boolean;
}) {
  const nativeBackend = backends.find((backendItem) => backendItem.id === "backend.autopilot.native-local.fixture") ?? backends[0];
  const backendStartGuard = combineGuards(
    connectionActionGuard(connectionState, "backend start"),
    tokenScopeGuard(data, hasSessionToken, "backend.control:*"),
    backendGuard(nativeBackend, true),
  );
  const backendStopGuard = combineGuards(
    connectionActionGuard(connectionState, "backend stop"),
    tokenScopeGuard(data, hasSessionToken, "backend.control:*"),
    nativeBackend ? guardReady("backend selected", `${nativeBackend.label} can receive stop.`) : guardBlocked("backend missing", "No native backend is selected."),
  );
  const runtimeSurveyGuard = connectionActionGuard(connectionState, "runtime survey");
  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-backends-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Runtime engines</span>
          <h3 id="model-mounts-backends-title">Backend manager</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">Autopilot owned</StatusPill>
          <StatusPill tone="muted">live engines gated</StatusPill>
          <ActionButton onClick={onProbeNativeBackend} disabled={busy} guard={combineGuards(connectionActionGuard(connectionState, "backend health"), backendGuard(nativeBackend, true))}>Probe native backend</ActionButton>
          <ActionButton onClick={onStartNativeBackend} disabled={busy} guard={backendStartGuard}>Start native</ActionButton>
          <ActionButton onClick={onStopNativeBackend} disabled={busy} guard={backendStopGuard}>Stop native</ActionButton>
          <ActionButton onClick={onRunRuntimeSurvey} disabled={busy} guard={runtimeSurveyGuard}>Run runtime survey</ActionButton>
        </div>
      </div>

      <section className="model-mounts-workflow" aria-label="Runtime survey">
        <h4>Runtime survey</h4>
        <div className="model-mounts-server-grid">
          <div>
            <span>Status</span>
            <strong>{runtimeSurvey.status}</strong>
          </div>
          <div>
            <span>Selected engine</span>
            <strong>{runtimeSurvey.selectedEngine}</strong>
          </div>
          <div>
            <span>CPU</span>
            <strong>{runtimeSurvey.cpu}</strong>
          </div>
          <div>
            <span>RAM</span>
            <strong>{runtimeSurvey.ram}</strong>
          </div>
          <div>
            <span>GPU / VRAM</span>
            <strong>{runtimeSurvey.vram}</strong>
          </div>
          <div>
            <span>Memory pressure</span>
            <strong>{runtimeSurvey.memoryPressure}</strong>
          </div>
          <div>
            <span>Survey receipt</span>
            <strong>{runtimeSurvey.receipt}</strong>
          </div>
          <div>
            <span>Checked</span>
            <strong>{runtimeSurvey.checkedAt}</strong>
          </div>
        </div>
        <div className="model-mounts-list">
          {runtimeEngines.map((engine) => (
            <article key={engine.id} className="model-mounts-compact-row">
              <div>
                <strong>{engine.label}</strong>
                <span>{engine.kind} / {engine.modelFormat} / {engine.source}</span>
              </div>
              <StatusPill tone={engine.selected ? "ready" : toneForStatus(engine.status)}>{engine.selected ? "selected" : engine.status}</StatusPill>
              <ActionButton onClick={() => onSelectRuntimeEngine(engine.id)} disabled={busy || engine.selected} guard={combineGuards(connectionActionGuard(connectionState, "runtime select"), runtimeEngineGuard(engine))}>Select</ActionButton>
            </article>
          ))}
        </div>
      </section>

      <div className="model-mounts-provider-grid">
        {backends.map((item) => (
          <article key={item.id} className="model-mounts-provider">
            <div>
              <strong>{item.label}</strong>
              <span>{item.kind} / {item.processStatus}</span>
            </div>
            <StatusPill tone={toneForStatus(item.status)}>{item.status}</StatusPill>
            <dl>
              <div>
                <dt>Base URL</dt>
                <dd>{item.baseUrl}</dd>
              </div>
              <div>
                <dt>Binary</dt>
                <dd>{item.binaryPath}</dd>
              </div>
              <div>
                <dt>Pressure</dt>
                <dd>{item.memoryPressure}</dd>
              </div>
              <div>
                <dt>Receipt</dt>
                <dd>{item.receipt}</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{item.evidence}</dd>
              </div>
            </dl>
            <TagList items={[...item.formats.map((format) => `format:${format}`), ...item.capabilities]} />
          </article>
        ))}
      </div>
    </section>
  );
}

function ModelsPanel({
  data,
  connectionState,
  hasSessionToken,
  onLoadLocalModel,
  onLoadNativeLocalModel,
  onLoadModelWithOptions,
  onDownloadFixture,
  busy,
}: {
  data: MountsWorkbenchData;
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onLoadLocalModel: () => void;
  onLoadNativeLocalModel: () => void;
  onLoadModelWithOptions: (draft: ModelLoadDraft) => void;
  onDownloadFixture: () => void;
  busy: boolean;
}) {
  const [loadDraft, setLoadDraft] = useState<ModelLoadDraft>({
    modelId: "autopilot:native-fixture",
    mode: "on_demand",
    gpu: "auto",
    contextLength: "4096",
    parallel: "1",
    ttlSeconds: "900",
    identifier: "native-fixture-dev",
    estimateOnly: false,
  });
  const updateLoadDraft = (field: keyof ModelLoadDraft, value: string | boolean) => {
    setLoadDraft((current) => ({ ...current, [field]: value }));
  };
  const loadedInstances = data.instances.filter(isLoadedInstance);
  const localAutoSelection = normalizePickerSelection(data, { ...emptyPickerSelection, modelId: "local:auto", endpointId: "endpoint.local.auto", routeId: "route.local-first" });
  const nativeSelection = normalizePickerSelection(data, { ...emptyPickerSelection, modelId: "autopilot:native-fixture", endpointId: "endpoint.autopilot.native-fixture", routeId: "route.native-local" });
  const draftLoadGuard = combineGuards(
    connectionActionGuard(connectionState, "model.load:*"),
    tokenScopeGuard(data, hasSessionToken, "model.load:*"),
    modelArtifactGuard(data, loadDraft.modelId),
  );
  const downloadGuard = combineGuards(
    connectionActionGuard(connectionState, "model.download:*"),
    tokenScopeGuard(data, hasSessionToken, "model.download:*"),
  );
  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-models-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Registry / Endpoints / Instances</span>
          <h3 id="model-mounts-models-title">Mounted model workbench</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">registry first</StatusPill>
          <StatusPill tone="ready">router backed</StatusPill>
          <ActionButton onClick={onLoadLocalModel} disabled={busy} guard={selectedActionGuard(data, localAutoSelection, connectionState, hasSessionToken, "model.load:*", "chat")}>Load local:auto</ActionButton>
          <ActionButton onClick={onLoadNativeLocalModel} disabled={busy} guard={selectedActionGuard(data, nativeSelection, connectionState, hasSessionToken, "model.load:*", "chat")}>Load native-local</ActionButton>
          <ActionButton onClick={onDownloadFixture} disabled={busy} guard={downloadGuard}>Download fixture</ActionButton>
        </div>
      </div>

      <form
        className="model-mounts-provider-editor"
        onSubmit={(event) => {
          event.preventDefault();
          onLoadModelWithOptions(loadDraft);
        }}
      >
        <div className="model-mounts-provider-editor-grid">
          <label>
            <span>Model id</span>
            <input value={loadDraft.modelId} onChange={(event) => updateLoadDraft("modelId", event.target.value)} />
          </label>
          <label>
            <span>Mode</span>
            <select value={loadDraft.mode} onChange={(event) => updateLoadDraft("mode", event.target.value)}>
              <option value="on_demand">On demand</option>
              <option value="manual">Manual</option>
              <option value="keep_warm">Keep warm</option>
              <option value="idle_evict">Idle evict</option>
            </select>
          </label>
          <label>
            <span>GPU</span>
            <select value={loadDraft.gpu} onChange={(event) => updateLoadDraft("gpu", event.target.value)}>
              <option value="auto">Auto</option>
              <option value="max">Max</option>
              <option value="0">CPU</option>
            </select>
          </label>
          <label>
            <span>Context</span>
            <input inputMode="numeric" value={loadDraft.contextLength} onChange={(event) => updateLoadDraft("contextLength", event.target.value)} />
          </label>
          <label>
            <span>Parallel</span>
            <input inputMode="numeric" value={loadDraft.parallel} onChange={(event) => updateLoadDraft("parallel", event.target.value)} />
          </label>
          <label>
            <span>TTL seconds</span>
            <input inputMode="numeric" value={loadDraft.ttlSeconds} onChange={(event) => updateLoadDraft("ttlSeconds", event.target.value)} />
          </label>
          <label>
            <span>Identifier</span>
            <input value={loadDraft.identifier} onChange={(event) => updateLoadDraft("identifier", event.target.value)} />
          </label>
          <label className="model-mounts-checkbox">
            <input type="checkbox" checked={loadDraft.estimateOnly} onChange={(event) => updateLoadDraft("estimateOnly", event.target.checked)} />
            <span>Estimate only</span>
          </label>
        </div>
        <div className="model-mounts-form-actions">
          <ActionButton type="submit" disabled={busy} guard={draftLoadGuard}>{loadDraft.estimateOnly ? "Estimate load" : "Load with options"}</ActionButton>
        </div>
      </form>

      <div className="model-mounts-three-col">
        <section aria-label="Installed models">
          <h4>Installed</h4>
          <div className="model-mounts-list">
            {data.artifacts.map((artifact) => (
              <article key={artifact.id} className="model-mounts-compact-row">
                <div>
                  <strong>{artifact.name}</strong>
                  <span>{artifact.provider} / {artifact.quantization} / {artifact.context}</span>
                </div>
                <StatusPill tone={toneForStatus(artifact.state)}>{artifact.state}</StatusPill>
                <TagList items={artifact.capabilities} />
              </article>
            ))}
          </div>
        </section>

        <section aria-label="Mounted endpoints">
          <h4>Mounted endpoints</h4>
          <div className="model-mounts-endpoints">
            {data.endpoints.map((endpoint) => (
              <EndpointRow key={endpoint.id} endpoint={endpoint} />
            ))}
          </div>
        </section>

        <section aria-label="Loaded and downloads">
          <h4>Loaded now</h4>
          <div className="model-mounts-list">
            {loadedInstances.length === 0 ? (
              <p className="model-mounts-empty">No loaded instances.</p>
            ) : (
              loadedInstances.map((instance) => (
                <article key={instance.id} className="model-mounts-compact-row">
                  <div>
                    <strong>{instance.modelId}</strong>
                    <span>{instance.endpointId} / {instance.backend} / {instance.runtimeEngine}</span>
                  </div>
                  <StatusPill tone={toneForStatus(instance.status)}>{instance.status}</StatusPill>
                  <span className="model-mounts-row-note">{instance.identifier} / ctx {instance.context} / p{instance.parallel} / {instance.ttl}</span>
                </article>
              ))
            )}
          </div>
          <h4>Downloads</h4>
          <div className="model-mounts-list">
            {data.downloads.map((download) => (
              <article key={download.id} className="model-mounts-compact-row">
                <div>
                  <strong>{download.model}</strong>
                  <span>{download.id}</span>
                </div>
                <StatusPill tone={toneForStatus(download.status)}>{download.status}</StatusPill>
                <span className="model-mounts-row-note">{download.progress}</span>
              </article>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}

function DownloadsPanel({
  data,
  downloads,
  connectionState,
  hasSessionToken,
  onDownloadFixture,
  onSearchCatalog,
  onImportCatalogUrl,
  onCleanupStorage,
  busy,
}: {
  data: MountsWorkbenchData;
  downloads: MountsWorkbenchData["downloads"];
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onDownloadFixture: () => void;
  onSearchCatalog: (draft: CatalogSearchDraft) => void;
  onImportCatalogUrl: (sourceUrl: string) => void;
  onCleanupStorage: () => void;
  busy: boolean;
}) {
  const [draft, setDraft] = useState<CatalogSearchDraft>({ query: "autopilot", format: "gguf", quantization: "", limit: "20" });
  const [sourceUrl, setSourceUrl] = useState("fixture://catalog/autopilot-native-3b-q4");
  const updateDraft = (field: keyof CatalogSearchDraft, value: string) => setDraft((current) => ({ ...current, [field]: value }));
  const downloadGuard = combineGuards(connectionActionGuard(connectionState, "model.download:*"), tokenScopeGuard(data, hasSessionToken, "model.download:*"));
  const importGuard = combineGuards(
    connectionActionGuard(connectionState, "model.import:*"),
    tokenScopeGuard(data, hasSessionToken, "model.import:*"),
    sourceUrl.trim() ? guardReady("source ready", "Catalog URL is ready for governed import.") : guardBlocked("source missing", "Enter a source URL before importing."),
  );
  const cleanupGuard = combineGuards(connectionActionGuard(connectionState, "model.delete:*"), tokenScopeGuard(data, hasSessionToken, "model.delete:*"));
  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-downloads-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Artifact lifecycle</span>
          <h3 id="model-mounts-downloads-title">Download queue</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">receipted lifecycle</StatusPill>
          <StatusPill tone="ready">checksum tracked</StatusPill>
          <StatusPill tone={data.catalog.providers.some((provider) => provider.id === "catalog.huggingface" && provider.status !== "gated") ? "ready" : "muted"}>live catalog gated</StatusPill>
          <ActionButton onClick={onDownloadFixture} disabled={busy} guard={downloadGuard}>Download fixture</ActionButton>
          <ActionButton onClick={onCleanupStorage} disabled={busy} guard={cleanupGuard}>Scan cleanup</ActionButton>
        </div>
      </div>

      <div className="model-mounts-observability-summary" aria-label="Catalog and storage summary">
        <DetailFact label="Catalog gate" value={data.catalog.providers.find((provider) => provider.id === "catalog.huggingface")?.status ?? "unknown"} note="IOI_LIVE_MODEL_CATALOG" />
        <DetailFact label="Download gate" value={data.catalog.providers.find((provider) => provider.id === "catalog.huggingface")?.liveDownloadStatus ?? "unknown"} note="IOI_LIVE_MODEL_DOWNLOAD" />
        <DetailFact label="Storage" value={data.catalog.storageTotal} note={`${data.catalog.fileCount} files / ${data.catalog.orphanCount} orphan`} />
        <DetailFact label="Quota" value={data.catalog.storageStatus} note={data.catalog.storageQuota} />
      </div>

      <form
        className="model-mounts-provider-editor"
        onSubmit={(event) => {
          event.preventDefault();
          onSearchCatalog(draft);
        }}
      >
        <div className="model-mounts-provider-editor-grid">
          <label>
            <span>Catalog query</span>
            <input value={draft.query} onChange={(event) => updateDraft("query", event.target.value)} />
          </label>
          <label>
            <span>Format</span>
            <select value={draft.format} onChange={(event) => updateDraft("format", event.target.value)}>
              <option value="">Any format</option>
              {data.catalog.formats.map((format) => <option key={format} value={format}>{format}</option>)}
            </select>
          </label>
          <label>
            <span>Quantization</span>
            <input value={draft.quantization} onChange={(event) => updateDraft("quantization", event.target.value)} placeholder="Q4, Q8, F16" />
          </label>
          <label>
            <span>Result limit</span>
            <input value={draft.limit} onChange={(event) => updateDraft("limit", event.target.value)} inputMode="numeric" />
          </label>
          <label>
            <span>Source URL</span>
            <input value={sourceUrl} onChange={(event) => setSourceUrl(event.target.value)} />
          </label>
        </div>
        <div className="model-mounts-form-actions">
          <ActionButton type="submit" disabled={busy} guard={connectionActionGuard(connectionState, "catalog search")}>Search catalog</ActionButton>
          <ActionButton onClick={() => onImportCatalogUrl(sourceUrl)} disabled={busy} guard={importGuard}>Import URL</ActionButton>
        </div>
      </form>

      <div className="model-mounts-list">
        <div className="model-mounts-provider-grid" aria-label="Catalog providers">
          {data.catalog.providers.map((provider) => (
            <article key={provider.id} className="model-mounts-provider">
              <div>
                <strong>{provider.label}</strong>
                <span>{provider.id}</span>
              </div>
              <div className="model-mounts-tags">
                <StatusPill tone={toneForStatus(provider.status)}>{provider.status}</StatusPill>
                <span>{provider.gate}</span>
                <span>{provider.downloadGate}</span>
              </div>
              <span>{provider.formats.join(", ") || "formats unknown"}</span>
            </article>
          ))}
        </div>
        {downloads.length === 0 ? (
          <p className="model-mounts-empty">No download jobs in the current projection.</p>
        ) : (
          downloads.map((download) => (
            <article key={download.id} className="model-mounts-compact-row">
              <div>
                <strong>{download.model}</strong>
                <span>{download.id}</span>
                <span>{download.sourceLabel}</span>
              </div>
              <StatusPill tone={toneForStatus(download.status)}>{download.status}</StatusPill>
              <span className="model-mounts-row-note">{download.progress} / {download.bytes} / {download.receipt}</span>
            </article>
          ))
        )}
      </div>
    </section>
  );
}

function ProvidersPanel({
  data,
  providers,
  connectionState,
  hasSessionToken,
  onConfigureProvider,
  onBindVaultSecret,
  onProviderHealth,
  onLatestProviderHealth,
  onProviderModels,
  busy,
}: {
  data: MountsWorkbenchData;
  providers: ProviderProfile[];
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onConfigureProvider: (draft: ProviderDraft) => void;
  onBindVaultSecret: (draft: ProviderDraft) => void;
  onProviderHealth: (providerId: string) => void;
  onLatestProviderHealth: (providerId: string) => void;
  onProviderModels: (providerId: string) => void;
  busy: string | null;
}) {
  const [draft, setDraft] = useState<ProviderDraft>(defaultProviderDraft);
  const updateDraft = (field: keyof ProviderDraft, value: string) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };
  const providerBusy =
    busy === "provider-configure" ||
    busy === "vault-bind" ||
    busy === "provider-health" ||
    busy === "provider-health-latest" ||
    busy === "provider-models";
  const configureGuard = combineGuards(
    connectionActionGuard(connectionState, "provider.write:*"),
    tokenScopeGuard(data, hasSessionToken, "provider.write:*"),
    providerDraftGuard(draft),
  );
  const bindGuard = combineGuards(
    connectionActionGuard(connectionState, "vault.write:*"),
    tokenScopeGuard(data, hasSessionToken, "vault.write:*"),
    vaultBindGuard(draft),
  );
  const draftProvider = providers.find((provider) => provider.id === draft.id);
  const providerProbeGuard = combineGuards(connectionActionGuard(connectionState, "provider health"), providerGuard(draftProvider, undefined, true));
  const providerModelsGuard = combineGuards(connectionActionGuard(connectionState, "provider models"), providerGuard(draftProvider, "chat", true));
  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-providers-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Provider-neutral mounting</span>
          <h3 id="model-mounts-providers-title">Provider profiles</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">LM Studio is one profile</StatusPill>
          <StatusPill tone="muted">TEE later</StatusPill>
        </div>
      </div>

      <form
        className="model-mounts-provider-editor"
        onSubmit={(event) => {
          event.preventDefault();
          onConfigureProvider(draft);
        }}
      >
        <div className="model-mounts-provider-editor-grid">
          <label>
            <span>Provider id</span>
            <input value={draft.id} onChange={(event) => updateDraft("id", event.target.value)} />
          </label>
          <label>
            <span>Label</span>
            <input value={draft.label} onChange={(event) => updateDraft("label", event.target.value)} />
          </label>
          <label>
            <span>Kind</span>
            <select value={draft.kind} onChange={(event) => updateDraft("kind", event.target.value)}>
              <option value="custom_http">Custom HTTP</option>
              <option value="openai_compatible">OpenAI-compatible</option>
              <option value="openai">OpenAI BYOK</option>
              <option value="anthropic">Anthropic BYOK</option>
              <option value="gemini">Gemini BYOK</option>
            </select>
          </label>
          <label>
            <span>API format</span>
            <select value={draft.apiFormat} onChange={(event) => updateDraft("apiFormat", event.target.value)}>
              <option value="openai_compatible">OpenAI-compatible</option>
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="gemini">Gemini</option>
              <option value="custom">Custom</option>
            </select>
          </label>
          <label>
            <span>Base URL</span>
            <input value={draft.baseUrl} onChange={(event) => updateDraft("baseUrl", event.target.value)} />
          </label>
          <label>
            <span>Vault ref</span>
            <input
              value={draft.secretRef}
              onChange={(event) => updateDraft("secretRef", event.target.value)}
              placeholder="vault://provider/custom-http/api-key"
            />
          </label>
          <label>
            <span>Vault material</span>
            <input
              type="password"
              value={draft.vaultMaterial}
              onChange={(event) => updateDraft("vaultMaterial", event.target.value)}
              placeholder="session only"
            />
          </label>
          <label>
            <span>Auth scheme</span>
            <select value={draft.authScheme} onChange={(event) => updateDraft("authScheme", event.target.value)}>
              <option value="bearer">Bearer</option>
              <option value="api_key">API key</option>
              <option value="raw">Raw</option>
            </select>
          </label>
          <label>
            <span>Auth header</span>
            <input value={draft.authHeaderName} onChange={(event) => updateDraft("authHeaderName", event.target.value)} />
          </label>
          <label>
            <span>Privacy</span>
            <select value={draft.privacyClass} onChange={(event) => updateDraft("privacyClass", event.target.value)}>
              <option value="workspace">Workspace</option>
              <option value="local_private">Local private</option>
              <option value="hosted">Hosted</option>
              <option value="remote_confidential">Remote confidential</option>
            </select>
          </label>
          <label>
            <span>Capabilities</span>
            <input value={draft.capabilities} onChange={(event) => updateDraft("capabilities", event.target.value)} />
          </label>
        </div>
        <div className="model-mounts-actions">
          <ActionButton type="submit" disabled={providerBusy} guard={configureGuard}>
            Save provider
          </ActionButton>
          <ActionButton
            onClick={() => {
              onBindVaultSecret(draft);
              setDraft((current) => ({ ...current, vaultMaterial: "" }));
            }}
            disabled={providerBusy || !draft.secretRef.trim() || !draft.vaultMaterial}
            guard={bindGuard}
          >
            Bind vault secret
          </ActionButton>
          <ActionButton onClick={() => onProviderHealth(draft.id)} disabled={providerBusy} guard={providerProbeGuard}>
            Test health
          </ActionButton>
          <ActionButton onClick={() => onLatestProviderHealth(draft.id)} disabled={providerBusy} guard={providerProbeGuard}>
            Latest health
          </ActionButton>
          <ActionButton onClick={() => onProviderModels(draft.id)} disabled={providerBusy} guard={providerModelsGuard}>
            List models
          </ActionButton>
        </div>
      </form>

      <div className="model-mounts-provider-grid">
        {providers.map((item) => (
          <article key={item.id} className="model-mounts-provider">
            <div>
              <strong>{item.label}</strong>
              <span>{item.kind} / {item.apiFormat}</span>
            </div>
            <StatusPill tone={toneForStatus(item.status)}>{item.status}</StatusPill>
            <dl>
              <div>
                <dt>Privacy</dt>
                <dd>{item.privacy}</dd>
              </div>
              <div>
                <dt>Endpoint</dt>
                <dd>{item.baseUrl}</dd>
              </div>
              <div>
                <dt>Auth</dt>
                <dd>{item.auth}</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{item.evidence}</dd>
              </div>
              <div>
                <dt>Last health</dt>
                <dd>{item.lastHealth}</dd>
              </div>
              <div>
                <dt>Health receipt</dt>
                <dd>{item.healthReceipt}</dd>
              </div>
            </dl>
            <TagList items={item.capabilities} />
            <div className="model-mounts-card-actions">
              <ActionButton onClick={() => setDraft(providerDraftFromProfile(item))}>
                Edit
              </ActionButton>
              <ActionButton onClick={() => onProviderHealth(item.id)} disabled={providerBusy} guard={combineGuards(connectionActionGuard(connectionState, "provider health"), providerGuard(item, undefined, true))}>
                Health
              </ActionButton>
              <ActionButton onClick={() => onLatestProviderHealth(item.id)} disabled={providerBusy} guard={combineGuards(connectionActionGuard(connectionState, "provider latest health"), providerGuard(item, undefined, true))}>
                Latest health
              </ActionButton>
              <ActionButton onClick={() => onProviderModels(item.id)} disabled={providerBusy} guard={combineGuards(connectionActionGuard(connectionState, "provider models"), providerGuard(item, "chat", true))}>
                Models
              </ActionButton>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function providerDraftFromProfile(item: ProviderProfile): ProviderDraft {
  return {
    ...defaultProviderDraft,
    id: item.id,
    label: item.label,
    kind: item.kind,
    apiFormat: item.apiFormat,
    baseUrl: item.baseUrl === "not configured" || item.baseUrl === "vault reference required" ? "" : item.baseUrl,
    privacyClass: item.privacy,
    capabilities: item.capabilities.join(","),
    authScheme: item.authScheme,
    authHeaderName: item.authHeaderName,
    secretRef: "",
    vaultMaterial: "",
  };
}

function TokensPanel({
  data,
  connectionState,
  hasSessionToken,
  onCreateToken,
  onRevokeToken,
  onImportMcpFixture,
  onEphemeralMcpProbe,
  onCheckVaultAdapter,
  onLatestVaultHealth,
  busy,
}: {
  data: MountsWorkbenchData;
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onCreateToken: (draft: TokenDraft) => void;
  onRevokeToken: (tokenId: string) => void;
  onImportMcpFixture: () => void;
  onEphemeralMcpProbe: () => void;
  onCheckVaultAdapter: () => void;
  onLatestVaultHealth: () => void;
  busy: boolean;
}) {
  const [draft, setDraft] = useState<TokenDraft>(defaultTokenDraft);
  const allowedScopes = tokenScopeList(draft.allowed);
  const deniedScopes = tokenScopeList(draft.denied);
  const updateDraft = (field: keyof TokenDraft, value: string) => setDraft((current) => ({ ...current, [field]: value }));
  const submitTokenDraft = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onCreateToken(draft);
  };
  const connectionGuard = connectionActionGuard(connectionState, "capability token action");
  const mcpImportGuard = combineGuards(connectionGuard, tokenScopeGuard(data, hasSessionToken, "mcp.import:*"));
  const mcpCallGuard = combineGuards(
    connectionGuard,
    tokenScopeGuard(data, hasSessionToken, "mcp.call:huggingface.model_search"),
    data.mcpServers.some((server) => server.allowedTools.includes("model_search"))
      ? guardReady("tool allowed", "model_search is allowed by the current MCP projection.")
      : guardBlocked("tool denied", "No MCP server currently allows model_search."),
  );
  const vaultReadGuard = combineGuards(connectionGuard, tokenScopeGuard(data, hasSessionToken, "vault.read:*"));

  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-tokens-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">wallet.network capabilities</span>
          <h3 id="model-mounts-tokens-title">Permission tokens and governed MCP</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">scoped</StatusPill>
          <StatusPill tone="ready">revocable</StatusPill>
          <ActionButton onClick={onImportMcpFixture} disabled={busy} guard={mcpImportGuard}>Import MCP fixture</ActionButton>
          <ActionButton onClick={onEphemeralMcpProbe} disabled={busy} guard={mcpCallGuard}>Ephemeral MCP probe</ActionButton>
          <ActionButton onClick={onCheckVaultAdapter} disabled={busy} guard={vaultReadGuard}>Check adapter</ActionButton>
          <ActionButton onClick={onLatestVaultHealth} disabled={busy} guard={vaultReadGuard}>Latest vault health</ActionButton>
        </div>
      </div>

      <form className="model-mounts-token-editor" onSubmit={submitTokenDraft}>
        <div className="model-mounts-route-editor-head">
          <div>
            <h4>Token scope editor</h4>
            <span>Issue scoped, expiring grants for model, route, MCP, and vault calls. Raw token material stays in memory only.</span>
          </div>
          <div className="model-mounts-card-actions">
            <StatusPill tone="ready">session-only raw token</StatusPill>
            <ActionButton type="submit" disabled={busy} guard={connectionGuard}>Create session token</ActionButton>
          </div>
        </div>
        <div className="model-mounts-token-editor-grid">
          <label>
            <span>Audience</span>
            <input value={draft.audience} onChange={(event) => updateDraft("audience", event.target.value)} />
          </label>
          <label>
            <span>Expiry hours</span>
            <input type="number" min="1" max="720" value={draft.expiresHours} onChange={(event) => updateDraft("expiresHours", event.target.value)} />
          </label>
          <label>
            <span>Grant id override</span>
            <input value={draft.grantId} placeholder="wallet.grant.* generated by default" onChange={(event) => updateDraft("grantId", event.target.value)} />
          </label>
        </div>
        <div className="model-mounts-token-editor-scopes">
          <label>
            <span>Allowed scopes</span>
            <textarea value={draft.allowed} onChange={(event) => updateDraft("allowed", event.target.value)} rows={8} />
          </label>
          <label>
            <span>Denied scopes</span>
            <textarea value={draft.denied} onChange={(event) => updateDraft("denied", event.target.value)} rows={8} />
          </label>
        </div>
        <div className="model-mounts-token-editor-summary">
          <DetailFact label="Allowed" value={`${allowedScopes.length} scopes`} note={allowedScopes.slice(0, 2).join(", ") || "none"} />
          <DetailFact label="Denied" value={`${deniedScopes.length} scopes`} note={deniedScopes.slice(0, 2).join(", ") || "none"} />
          <DetailFact label="Persistence" value="grant hash only" note="Token values are not written to local or session storage." />
        </div>
      </form>

      <div className="model-mounts-token-layout">
        <section>
          <h4>Capability tokens</h4>
          <div className="model-mounts-list">
            {data.tokens.length === 0 ? (
              <p className="model-mounts-empty">No token grants returned by the daemon.</p>
            ) : (
              data.tokens.map((token) => (
                <article key={token.id} className="model-mounts-token">
                  <div className="model-mounts-token-head">
                    <div>
                      <strong>{token.id}</strong>
                      <span>{token.audience} / grant {token.grantId} / expires {token.expires}</span>
                      <span>created {token.created} / last used {token.lastUsed} / scope {token.lastScope}</span>
                    </div>
                    <div className="model-mounts-card-actions">
                      <StatusPill tone={toneForStatus(token.state)}>{token.state}</StatusPill>
                      <ActionButton
                        onClick={() => onRevokeToken(token.id)}
                        disabled={busy || token.state === "revoked"}
                        guard={combineGuards(connectionGuard, token.state === "revoked" ? guardWarn("already revoked", `${token.id} is already revoked.`, true) : guardReady("revocable", `${token.id} can be revoked.`))}
                      >
                        Revoke
                      </ActionButton>
                    </div>
                  </div>
                  <div className="model-mounts-scope-columns">
                    <div>
                      <span>Allowed</span>
                      <TagList items={token.allowed} />
                    </div>
                    <div>
                      <span>Denied</span>
                      <TagList items={token.denied} />
                    </div>
                  </div>
                  <dl>
                    <div>
                      <dt>Receipt</dt>
                      <dd>{token.receipt}</dd>
                    </div>
                    <div>
                      <dt>Revoked</dt>
                      <dd>{token.revoked}</dd>
                    </div>
                    <div>
                      <dt>Vault refs</dt>
                      <dd>{token.vaultRefs.join(", ") || "none"}</dd>
                    </div>
                    <div>
                      <dt>Audit receipts</dt>
                      <dd>{token.auditReceipts.join(", ") || "none"}</dd>
                    </div>
                  </dl>
                </article>
              ))
            )}
          </div>
        </section>

        <section>
          <h4>Vault adapter</h4>
          <article className="model-mounts-token">
            <div className="model-mounts-token-head">
              <div>
                <strong>{data.vaultAdapter.mode}</strong>
                <span>
                  {data.vaultAdapter.implementation} / path hash {data.vaultAdapter.pathHash} / key {data.vaultAdapter.keyConfigured ? "configured" : "not configured"}
                </span>
              </div>
              <StatusPill tone={data.vaultAdapter.failClosed ? "blocked" : data.vaultAdapter.configured ? "ready" : "warn"}>
                {data.vaultAdapter.failClosed ? "fail closed" : data.vaultAdapter.configured ? "restart durable" : "session only"}
              </StatusPill>
            </div>
            <dl>
              <div>
                <dt>Plaintext persistence</dt>
                <dd>{data.vaultAdapter.plaintextPersistence ? "blocked" : "disabled"}</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{data.vaultAdapter.evidence.join(", ") || "VaultMaterialAdapter.runtimeMemory"}</dd>
              </div>
            </dl>
          </article>

          <h4>MCP imports</h4>
          <div className="model-mounts-list">
            {data.mcpServers.map((server) => (
              <article key={server.id} className="model-mounts-token">
                <div className="model-mounts-token-head">
                  <div>
                    <strong>{server.id}</strong>
                    <span>{server.transport} / secrets {server.secrets}</span>
                  </div>
                  <StatusPill tone={toneForStatus(server.status)}>{server.status}</StatusPill>
                </div>
                {server.allowedTools.length > 0 ? (
                  <TagList items={server.allowedTools.map((tool) => `allowed:${tool}`)} />
                ) : (
                  <p className="model-mounts-empty">No tools exposed until discovery receipts narrow the allowlist.</p>
                )}
              </article>
            ))}
          </div>
          <h4>Vault refs</h4>
          <div className="model-mounts-list">
            {data.vaultRefs.length === 0 ? (
              <p className="model-mounts-empty">No vault ref metadata returned by the daemon.</p>
            ) : (
              data.vaultRefs.map((vaultRef) => (
                <article key={vaultRef.hash} className="model-mounts-token">
                  <div className="model-mounts-token-head">
                    <div>
                      <strong>{vaultRef.label}</strong>
                      <span>{vaultRef.purpose} / hash {vaultRef.hash} / last resolved {vaultRef.lastResolved}</span>
                    </div>
                    <StatusPill tone={vaultRef.state.startsWith("material bound") ? "ready" : vaultRef.state.includes("removed") ? "blocked" : "warn"}>
                      {vaultRef.state}
                    </StatusPill>
                  </div>
                </article>
              ))
            )}
          </div>
          <pre>{`{
  "mcpServers": {
    "huggingface": {
      "url": "https://example.invalid/mcp",
      "allowed_tools": ["model_search"],
      "headers": {
        "authorization": "vault://mcp.huggingface/authorization"
      }
    }
  }
}`}</pre>
        </section>
      </div>
    </section>
  );
}

function RoutingPanel({
  data,
  selection,
  connectionState,
  hasSessionToken,
  onTestRoute,
  onSaveRoute,
  onTestRouteDraft,
  onWorkflowProbe,
  busy,
}: {
  data: MountsWorkbenchData;
  selection: MountsPickerSelection;
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onTestRoute: () => void;
  onSaveRoute: (draft: RouteDraft) => void;
  onTestRouteDraft: (draft: RouteDraft, selection: MountsPickerSelection) => void;
  onWorkflowProbe: () => void;
  busy: boolean;
}) {
  const selectedPolicy = data.routes.find((policy) => policy.id === selection.routeId) ?? data.routes[0];
  const [draft, setDraft] = useState<RouteDraft>(() => routeDraftFromPolicy(selectedPolicy, selection));
  useEffect(() => {
    setDraft(routeDraftFromPolicy(selectedPolicy, selection));
  }, [selectedPolicy, selection]);
  const updateDraft = (field: keyof RouteDraft, value: string | boolean) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };
  const fallbackIds = csvList(draft.fallback);
  const fallbackEndpoints = fallbackIds
    .map((endpointId) => data.endpoints.find((endpoint) => endpoint.id === endpointId))
    .filter(Boolean);
  const hasSelectedEndpoint = Boolean(selection.endpointId && fallbackIds.includes(selection.endpointId));
  const hostedFallbackBlocked = fallbackEndpoints.some((endpoint) => {
    const providerItem = data.providers.find((provider) => provider.id === endpoint?.provider);
    return providerItem?.privacy === "hosted" && draft.privacy === "local_or_enterprise" && !draft.allowHostedFallback;
  });
  const routeUseGuard = combineGuards(
    connectionActionGuard(connectionState, "route.use:*"),
    tokenScopeGuard(data, hasSessionToken, "route.use:*"),
    routePolicyGuard(data, selection.routeId, selection.endpointId),
  );
  const routeWriteGuard = combineGuards(
    connectionActionGuard(connectionState, "route.write:*"),
    tokenScopeGuard(data, hasSessionToken, "route.write:*"),
    hostedFallbackBlocked ? guardBlocked("policy blocked", "Hosted fallback is blocked until explicitly allowed for this draft.") : guardReady("policy ready", "Draft policy can be saved."),
  );
  const routeDraftTestGuard = combineGuards(
    routeWriteGuard,
    tokenScopeGuard(data, hasSessionToken, "route.use:*"),
    hostedFallbackBlocked ? guardBlocked("privacy blocked", "Testing would use hosted fallback under a local/enterprise policy.") : guardReady("test ready", "Draft can be saved and route-tested."),
  );
  const workflowGuard = combineGuards(
    connectionActionGuard(connectionState, "workflow execution"),
    tokenScopeGuard(data, hasSessionToken, "route.use:*"),
    tokenScopeGuard(data, hasSessionToken, "model.embeddings:*"),
    routePolicyGuard(data, selection.routeId, selection.endpointId),
  );
  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-routing-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Model Router / Workflow</span>
          <h3 id="model-mounts-routing-title">Policies and node bindings</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">capability to route</StatusPill>
          <StatusPill tone="ready">receipt gate</StatusPill>
          <ActionButton onClick={onTestRoute} disabled={busy} guard={routeUseGuard}>Test route</ActionButton>
          <ActionButton onClick={onWorkflowProbe} disabled={busy} guard={workflowGuard}>Run workflow probe</ActionButton>
        </div>
      </div>

      <form
        className="model-mounts-route-editor"
        aria-label="Route policy editor"
        onSubmit={(event) => {
          event.preventDefault();
          onSaveRoute(draft);
        }}
      >
        <div className="model-mounts-route-editor-head">
          <div>
            <h4>Route editor</h4>
            <span>{selection.modelId || "selected model"} / {selection.endpointId || "selected endpoint"}</span>
          </div>
          <div className="model-mounts-actions">
            <StatusPill tone={hasSelectedEndpoint ? "ready" : "warn"}>{hasSelectedEndpoint ? "selected endpoint in fallback" : "fallback differs"}</StatusPill>
            <StatusPill tone={hostedFallbackBlocked ? "blocked" : "ready"}>{hostedFallbackBlocked ? "hosted blocked" : "policy routable"}</StatusPill>
            <ActionButton type="submit" disabled={busy} guard={routeWriteGuard}>Save route</ActionButton>
            <ActionButton onClick={() => onTestRouteDraft(draft, selection)} disabled={busy} guard={routeDraftTestGuard}>Save and test route</ActionButton>
          </div>
        </div>

        <div className="model-mounts-route-editor-grid">
          <label>
            <span>Route id</span>
            <input value={draft.id} onChange={(event) => updateDraft("id", event.target.value)} />
          </label>
          <label>
            <span>Role</span>
            <input value={draft.role} onChange={(event) => updateDraft("role", event.target.value)} />
          </label>
          <label>
            <span>Privacy</span>
            <select value={draft.privacy} onChange={(event) => updateDraft("privacy", event.target.value)}>
              <option value="local_only">Local only</option>
              <option value="local_or_enterprise">Local or enterprise</option>
              <option value="workspace">Workspace</option>
              <option value="hosted_allowed">Hosted allowed</option>
            </select>
          </label>
          <label>
            <span>Quality</span>
            <select value={draft.quality} onChange={(event) => updateDraft("quality", event.target.value)}>
              <option value="deterministic">Deterministic</option>
              <option value="adaptive">Adaptive</option>
              <option value="high">High</option>
              <option value="low_latency">Low latency</option>
            </select>
          </label>
          <label>
            <span>Max cost USD</span>
            <input inputMode="decimal" value={draft.maxCostUsd} onChange={(event) => updateDraft("maxCostUsd", event.target.value)} />
          </label>
          <label>
            <span>Max latency ms</span>
            <input inputMode="numeric" value={draft.maxLatencyMs} onChange={(event) => updateDraft("maxLatencyMs", event.target.value)} />
          </label>
          <label>
            <span>Fallback endpoints</span>
            <input value={draft.fallback} onChange={(event) => updateDraft("fallback", event.target.value)} />
          </label>
          <label>
            <span>Provider eligibility</span>
            <input placeholder="fixture, native_local" value={draft.providerEligibility} onChange={(event) => updateDraft("providerEligibility", event.target.value)} />
          </label>
          <label>
            <span>Denied providers</span>
            <input placeholder="openai, anthropic" value={draft.deniedProviders} onChange={(event) => updateDraft("deniedProviders", event.target.value)} />
          </label>
          <label className="model-mounts-checkbox">
            <input type="checkbox" checked={draft.allowHostedFallback} onChange={(event) => updateDraft("allowHostedFallback", event.target.checked)} />
            <span>Allow hosted fallback when testing</span>
          </label>
        </div>

        <div className="model-mounts-route-editor-summary">
          <DetailFact label="Last selection" value={selectedPolicy?.lastSelection ?? "not tested"} note={selectedPolicy?.receipt} />
          <DetailFact label="Fallback order" value={fallbackIds.join(" -> ") || "none"} note={`${fallbackEndpoints.length} mounted endpoint${fallbackEndpoints.length === 1 ? "" : "s"}`} />
          <DetailFact label="Selected route" value={selectedPolicy?.id ?? "none"} note={selectedPolicy?.status} />
        </div>
      </form>

      <div className="model-mounts-table" role="table" aria-label="Routing policies">
        <div role="row" className="model-mounts-table-head">
          <span role="columnheader">Route</span>
          <span role="columnheader">Privacy</span>
          <span role="columnheader">Quality</span>
          <span role="columnheader">Max cost</span>
          <span role="columnheader">Fallback</span>
          <span role="columnheader">Last receipt</span>
        </div>
        {data.routes.map((policy) => (
          <div role="row" key={policy.id}>
            <span role="cell">
              <strong>{policy.role}</strong>
              <small>{policy.id}</small>
            </span>
            <span role="cell">{policy.privacy}</span>
            <span role="cell">{policy.quality}</span>
            <span role="cell">{policy.maxCost}</span>
            <span role="cell">{policy.fallback}</span>
            <span role="cell">
              <strong>{policy.lastSelection}</strong>
              <small>{policy.receipt}</small>
            </span>
          </div>
        ))}
      </div>

      <section className="model-mounts-workflow" aria-label="Workflow node bindings">
        <h4>Workflow nodes</h4>
        <TagList
          items={data.workflowNodes.map((node) =>
            `${node.node} / ${node.routeId} / ${node.receiptRequired ? "receipt" : "no receipt"}`,
          )}
        />
      </section>
    </section>
  );
}

function BenchmarksPanel({
  data,
  selection,
  connectionState,
  hasSessionToken,
  onRunBenchmark,
  onReplayReceipt,
  busy,
}: {
  data: MountsWorkbenchData;
  selection: MountsPickerSelection;
  connectionState: ConnectionState;
  hasSessionToken: boolean;
  onRunBenchmark: (selection: MountsPickerSelection, draft: BenchmarkDraft) => void;
  onReplayReceipt: (receiptId: string) => void;
  busy: boolean;
}) {
  const [draft, setDraft] = useState<BenchmarkDraft>(defaultBenchmarkDraft);
  const { invocations, latest, totalTokens, averageLatencyMs } = benchmarkSummary(data.receipts);
  const visibleInvocations = [...invocations].reverse().slice(0, 8);
  const updateDraft = (field: keyof BenchmarkDraft, value: string | boolean) => setDraft((current) => ({ ...current, [field]: value }));
  const submitBenchmark = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onRunBenchmark(selection, draft);
  };
  const benchmarkGuard = combineGuards(
    selectedActionGuard(data, selection, connectionState, hasSessionToken, "model.chat:*", "chat"),
    tokenScopeGuard(data, hasSessionToken, "model.responses:*"),
    draft.includeEmbeddings ? tokenScopeGuard(data, hasSessionToken, "model.embeddings:*") : null,
    routePolicyGuard(data, selection.routeId, selection.endpointId, draft.privacy),
  );
  const replayGuard = connectionActionGuard(connectionState, "receipt replay");

  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-benchmarks-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Route quality telemetry</span>
          <h3 id="model-mounts-benchmarks-title">Benchmarks and results</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">receipt backed</StatusPill>
          <StatusPill tone={latest ? "ready" : "muted"}>{latest ? "results available" : "no runs"}</StatusPill>
          {latest ? <ActionButton onClick={() => onReplayReceipt(latest.id)} disabled={busy} guard={replayGuard}>Replay latest result</ActionButton> : null}
        </div>
      </div>

      <div className="model-mounts-benchmark-workbench">
        <form className="model-mounts-benchmark-editor" onSubmit={submitBenchmark}>
          <div className="model-mounts-route-editor-head">
            <div>
              <h4>Benchmark runner</h4>
              <span>{selection.modelId || "selected model"} / {selection.routeId || "selected route"} / {selection.endpointId || "selected endpoint"}</span>
            </div>
            <div className="model-mounts-card-actions">
              <StatusPill tone={benchmarkGuard.tone}>{benchmarkGuard.label}</StatusPill>
              <ActionButton type="submit" disabled={busy || !selection.routeId} guard={benchmarkGuard}>Run benchmark</ActionButton>
            </div>
          </div>
          <div className="model-mounts-benchmark-grid">
            <label>
              <span>Prompt</span>
              <textarea value={draft.prompt} onChange={(event) => updateDraft("prompt", event.target.value)} rows={4} />
            </label>
            <div className="model-mounts-benchmark-options">
              <label>
                <span>Samples</span>
                <input type="number" min="1" max="5" value={draft.samples} onChange={(event) => updateDraft("samples", event.target.value)} />
              </label>
              <label>
                <span>Max cost USD</span>
                <input inputMode="decimal" value={draft.maxCostUsd} onChange={(event) => updateDraft("maxCostUsd", event.target.value)} />
              </label>
              <label>
                <span>Privacy</span>
                <select value={draft.privacy} onChange={(event) => updateDraft("privacy", event.target.value)}>
                  <option value="local_only">Local only</option>
                  <option value="local_or_enterprise">Local or enterprise</option>
                  <option value="workspace">Workspace</option>
                </select>
              </label>
              <label className="model-mounts-checkbox">
                <input type="checkbox" checked={draft.includeResponses} onChange={(event) => updateDraft("includeResponses", event.target.checked)} />
                <span>Include Responses pass</span>
              </label>
              <label className="model-mounts-checkbox">
                <input type="checkbox" checked={draft.includeEmbeddings} onChange={(event) => updateDraft("includeEmbeddings", event.target.checked)} />
                <span>Include embeddings pass</span>
              </label>
            </div>
          </div>
        </form>

        <section className="model-mounts-benchmark-output" aria-label="Benchmark result summary">
          <div className="model-mounts-benchmark-scoreboard">
            <DetailFact label="Runs" value={`${invocations.length}`} note="model invocation receipts" />
            <DetailFact label="Avg latency" value={formatLatency(averageLatencyMs)} note={latest?.routeId ?? "no route yet"} />
            <DetailFact label="Tokens" value={`${totalTokens}`} note={latest?.grantId ?? "no grant yet"} />
            <DetailFact label="Backend" value={latest?.backendId ?? "none"} note={latest?.endpointId ?? "no endpoint yet"} />
          </div>

          <div className="model-mounts-benchmark-results" role="table" aria-label="Benchmark results">
            <div role="row" className="model-mounts-table-head">
              <span role="columnheader">Receipt</span>
              <span role="columnheader">Model</span>
              <span role="columnheader">Route</span>
              <span role="columnheader">Latency</span>
              <span role="columnheader">Tokens</span>
            </div>
            {visibleInvocations.length === 0 ? (
              <p className="model-mounts-empty">No benchmarkable model invocation receipts in the current projection.</p>
            ) : (
              visibleInvocations.map((item) => (
                <div role="row" key={item.id}>
                  <span role="cell">
                    <strong>{item.id}</strong>
                    <small>{item.createdAt}</small>
                  </span>
                  <span role="cell">
                    <strong>{item.selectedModel}</strong>
                    <small>{item.backendId}</small>
                  </span>
                  <span role="cell">
                    <strong>{item.routeId}</strong>
                    <small>{item.endpointId}</small>
                  </span>
                  <span role="cell">{formatLatency(item.latencyMs)}</span>
                  <span role="cell">
                    <strong>{String(item.tokenCount)}</strong>
                    <small>{item.toolReceiptIds.length} tools</small>
                  </span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </section>
  );
}

function LogsPanel({
  receipts,
  connectionState,
  onRefresh,
  onTailServerLogs,
  onReplayReceipt,
  busy,
}: {
  receipts: ReceiptPreview[];
  connectionState: ConnectionState;
  onRefresh: () => void;
  onTailServerLogs: () => void;
  onReplayReceipt: (receiptId: string) => void;
  busy: boolean;
}) {
  const [filters, setFilters] = useState<ObservabilityFilters>(defaultObservabilityFilters);
  const replayGuard = connectionActionGuard(connectionState, "receipt replay");
  const serverLogsGuard = connectionActionGuard(connectionState, "server log tail");
  const kinds = uniqueReceiptKinds(receipts);
  const events = filteredObservabilityEvents(receipts, filters);
  const visibleEvents = [...events].reverse().slice(0, 60);
  const summary = observabilitySummary(events);
  const updateFilter = (field: keyof ObservabilityFilters, value: string | boolean) => {
    setFilters((current) => ({ ...current, [field]: value }));
  };

  useEffect(() => {
    if (!filters.liveTail) return undefined;
    const timer = window.setInterval(onRefresh, 5000);
    return () => window.clearInterval(timer);
  }, [filters.liveTail, onRefresh]);

  return (
    <section className="model-mounts-panel" aria-labelledby="model-mounts-logs-title">
      <div className="model-mounts-panel-head">
        <div>
          <span className="model-mounts-kicker">Streaming observability</span>
          <h3 id="model-mounts-logs-title">Filtered logs, receipts, and redacted payloads</h3>
        </div>
        <div className="model-mounts-actions">
          <StatusPill tone="ready">redacted</StatusPill>
          <StatusPill tone={filters.liveTail ? "ready" : "muted"}>{filters.liveTail ? "live tail" : "manual refresh"}</StatusPill>
          <ActionButton onClick={onRefresh} disabled={busy} guard={connectionActionGuard(connectionState, "snapshot refresh")}>Refresh</ActionButton>
          <ActionButton onClick={onTailServerLogs} disabled={busy} guard={serverLogsGuard}>Tail server logs</ActionButton>
        </div>
      </div>

      <form className="model-mounts-observability-filters" aria-label="Observability filters" onSubmit={(event) => event.preventDefault()}>
        <label>
          <span>Direction</span>
          <select value={filters.direction} onChange={(event) => updateFilter("direction", event.target.value)}>
            <option value="all">All traffic</option>
            <option value="request">Requests</option>
            <option value="response">Responses</option>
          </select>
        </label>
        <label>
          <span>Category</span>
          <select value={filters.category} onChange={(event) => updateFilter("category", event.target.value)}>
            <option value="all">All categories</option>
            <option value="server">Server</option>
            <option value="provider">Provider</option>
            <option value="backend">Backend</option>
            <option value="model">Model</option>
            <option value="route">Route</option>
            <option value="mcp">MCP</option>
            <option value="vault">Vault</option>
            <option value="token">Token</option>
            <option value="workflow">Workflow</option>
          </select>
        </label>
        <label>
          <span>Status</span>
          <select value={filters.status} onChange={(event) => updateFilter("status", event.target.value)}>
            <option value="all">All states</option>
            <option value="ready">Ready</option>
            <option value="degraded">Degraded</option>
            <option value="denied">Denied</option>
            <option value="failed">Failed</option>
          </select>
        </label>
        <label>
          <span>Receipt kind</span>
          <select value={filters.kind} onChange={(event) => updateFilter("kind", event.target.value)}>
            <option value="all">All kinds</option>
            {kinds.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
          </select>
        </label>
        <label>
          <span>Route / endpoint / provider</span>
          <input value={filters.entity} onChange={(event) => updateFilter("entity", event.target.value)} placeholder="route.native-local, endpoint.local.auto, provider.lmstudio" />
        </label>
        <label className="model-mounts-checkbox">
          <input type="checkbox" checked={filters.liveTail} onChange={(event) => updateFilter("liveTail", event.target.checked)} />
          <span>Live tail</span>
        </label>
        <label className="model-mounts-checkbox">
          <input type="checkbox" checked={filters.payloadPreview} onChange={(event) => updateFilter("payloadPreview", event.target.checked)} />
          <span>Redacted payload preview</span>
        </label>
      </form>

      <div className="model-mounts-observability-summary" aria-label="Filtered observability summary">
        <DetailFact label="Visible events" value={`${summary.total}`} note="after filters" />
        <DetailFact label="Requests" value={`${summary.requests}`} note="route, lifecycle, import, selection" />
        <DetailFact label="Responses" value={`${summary.responses}`} note="model, MCP, provider, vault" />
        <DetailFact label="Needs attention" value={`${summary.problemCount}`} note="degraded, denied, failed" />
      </div>

      <div className="model-mounts-observability-stream" role="table" aria-label="Filtered observability stream">
        <div role="row" className="model-mounts-table-head">
          <span role="columnheader">Event</span>
          <span role="columnheader">Route / endpoint / provider</span>
          <span role="columnheader">Status</span>
          <span role="columnheader">Redacted payload</span>
          <span role="columnheader">Replay</span>
        </div>
        {visibleEvents.length === 0 ? (
          <p className="model-mounts-empty">No receipts match the current observability filters.</p>
        ) : (
          visibleEvents.map((event) => (
            <ObservabilityEventRow
              key={event.id}
              event={event}
              showPayload={filters.payloadPreview}
              onReplayReceipt={onReplayReceipt}
              replayGuard={replayGuard}
              busy={busy}
            />
          ))
        )}
      </div>
    </section>
  );
}

function ObservabilityEventRow({
  event,
  showPayload,
  onReplayReceipt,
  replayGuard,
  busy,
}: {
  event: ObservabilityEvent;
  showPayload: boolean;
  onReplayReceipt: (receiptId: string) => void;
  replayGuard: ActionGuard;
  busy: boolean;
}) {
  return (
    <div role="row" className="model-mounts-observability-row">
      <span role="cell">
        <strong>{event.kind}</strong>
        <small>{event.direction} / {event.category}</small>
        <small>{event.id}</small>
      </span>
      <span role="cell">
        <strong>{event.entity}</strong>
        <small>{event.summary}</small>
      </span>
      <span role="cell">
        <StatusPill tone={event.status === "ready" ? "ready" : event.status === "degraded" ? "warn" : "blocked"}>
          {event.status}
        </StatusPill>
      </span>
      <span role="cell">
        {showPayload && event.payload.length > 0 ? (
          <div className="model-mounts-observability-payload">
            {event.payload.slice(0, 6).map((item) => (
              <small key={item.label}>{item.label}: {item.value}</small>
            ))}
          </div>
        ) : (
          <small>payload hidden</small>
        )}
      </span>
      <span role="cell">
        <ActionButton onClick={() => onReplayReceipt(event.id)} disabled={busy} guard={replayGuard}>Replay</ActionButton>
      </span>
    </div>
  );
}

export function MissionControlMountsView() {
  const [activeTab, setActiveTab] = useState<MountsTab>(readInitialTab);
  const [pickerSelection, setPickerSelection] = useState<MountsPickerSelection>(emptyPickerSelection);
  const [detailDrawerOpen, setDetailDrawerOpen] = useState(true);
  const daemon = useModelMountsDaemon();
  const busy = Boolean(daemon.busyAction);
  useEffect(() => {
    setPickerSelection((current) => {
      const next = normalizePickerSelection(daemon.data, current);
      return pickerSelectionChanged(current, next) ? next : current;
    });
  }, [daemon.data]);
  const updatePickerSelection = useCallback(
    (patch: Partial<MountsPickerSelection>) => {
      setPickerSelection((current) => normalizePickerSelection(daemon.data, { ...current, ...patch }));
    },
    [daemon.data],
  );
  const visibleReceipts = useMemo(
    () => (daemon.data.receipts.length > 0 ? daemon.data.receipts : fallbackData.receipts),
    [daemon.data.receipts],
  );
  const detailDrawerVisible = detailDrawerOpen && activeTab === "models";
  const toggleModelDetails = useCallback(() => {
    if (activeTab !== "models") {
      setActiveTab("models");
      setDetailDrawerOpen(true);
      return;
    }
    setDetailDrawerOpen((current) => !current);
  }, [activeTab]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.metaKey) return;
      const index = event.altKey
        ? Number.parseInt(event.key, 10) - 1
        : /^F[1-9]$/.test(event.key)
          ? Number.parseInt(event.key.slice(1), 10) - 1
          : -1;
      const nextTab = tabs[index]?.id;
      if (!nextTab) return;
      event.preventDefault();
      setActiveTab(nextTab);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <div className="mission-control-view mission-control-view--mounts">
      <header className="mission-control-header mission-control-header--mounts">
        <div className="mission-control-header-copy mission-control-header-copy--mounts">
          <span className="mission-control-kicker">Models</span>
          <div className="mission-control-mounts-title-row">
            <h2>Model mounts</h2>
            <StatusPill tone="ready">router backed</StatusPill>
            <StatusPill tone="ready">capability gated</StatusPill>
            <StatusPill tone={connectionTone(daemon.connectionState)}>{daemon.connectionState}</StatusPill>
          </div>
        </div>
        <div className="mission-control-header-actions">
          <div
            className="mission-control-tabs mission-control-tabs--mounts"
            role="tablist"
            aria-label="Model mount surfaces"
          >
            {tabs.map((tab) => (
              <button
                type="button"
                key={tab.id}
                className={activeTab === tab.id ? "is-active" : ""}
                onClick={() => setActiveTab(tab.id)}
                role="tab"
                aria-selected={activeTab === tab.id}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      <ModelPickerStrip
        data={daemon.data}
        selection={pickerSelection}
        connectionState={daemon.connectionState}
        hasSessionToken={daemon.hasSessionToken}
        onSelectionChange={updatePickerSelection}
        onLoadSelection={() => daemon.actions.loadPickerSelection(pickerSelection)}
        onUnloadInstance={() => daemon.actions.unloadInstance(pickerSelection.instanceId)}
        onToggleDetails={toggleModelDetails}
        detailsOpen={detailDrawerVisible}
        compact={activeTab !== "models"}
        busy={busy}
      />

      <ModelDetailDrawer
        data={daemon.data}
        selection={pickerSelection}
        open={detailDrawerVisible}
        onClose={() => setDetailDrawerOpen(false)}
      />

      <main className="model-mounts-stage">
        {activeTab === "server" ? (
          <ServerPanel
            data={daemon.data}
            endpoint={daemon.endpoint}
            setEndpoint={daemon.setEndpoint}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            sessionTokenLabel={daemon.sessionTokenLabel}
            message={daemon.message}
            onRefresh={() => void daemon.refresh()}
            onIssueToken={daemon.actions.issueToken}
            onStartServer={daemon.actions.startServer}
            onStopServer={daemon.actions.stopServer}
            onRestartServer={daemon.actions.restartServer}
            onTailServerLogs={daemon.actions.tailServerLogs}
            onNativeChatProbe={daemon.actions.nativeChatProbe}
            onRunHealthSweep={daemon.actions.runHealthSweep}
            busy={busy}
          />
        ) : null}
        {activeTab === "backends" ? (
          <BackendsPanel
            data={daemon.data}
            backends={daemon.data.backends}
            runtimeEngines={daemon.data.runtimeEngines}
            runtimeSurvey={daemon.data.runtimeSurvey}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            onProbeNativeBackend={daemon.actions.probeNativeBackend}
            onStartNativeBackend={daemon.actions.startNativeBackend}
            onStopNativeBackend={daemon.actions.stopNativeBackend}
            onRunRuntimeSurvey={daemon.actions.runRuntimeSurvey}
            onSelectRuntimeEngine={daemon.actions.selectRuntimeEngine}
            busy={busy}
          />
        ) : null}
        {activeTab === "models" ? (
          <ModelsPanel
            data={daemon.data}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            onLoadLocalModel={daemon.actions.loadLocalModel}
            onLoadNativeLocalModel={daemon.actions.loadNativeLocalModel}
            onLoadModelWithOptions={daemon.actions.loadModelWithOptions}
            onDownloadFixture={daemon.actions.downloadFixture}
            busy={busy}
          />
        ) : null}
        {activeTab === "providers" ? (
          <ProvidersPanel
            data={daemon.data}
            providers={daemon.data.providers}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            onConfigureProvider={daemon.actions.configureProvider}
            onBindVaultSecret={daemon.actions.bindVaultSecret}
            onProviderHealth={daemon.actions.testProviderHealth}
            onLatestProviderHealth={daemon.actions.latestProviderHealth}
            onProviderModels={daemon.actions.listProviderModels}
            busy={daemon.busyAction}
          />
        ) : null}
        {activeTab === "downloads" ? (
          <DownloadsPanel
            data={daemon.data}
            downloads={daemon.data.downloads}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            onDownloadFixture={daemon.actions.downloadFixture}
            onSearchCatalog={daemon.actions.searchCatalog}
            onImportCatalogUrl={daemon.actions.importCatalogUrl}
            onCleanupStorage={daemon.actions.cleanupStorage}
            busy={busy}
          />
        ) : null}
        {activeTab === "tokens" ? (
          <TokensPanel
            data={daemon.data}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            onCreateToken={daemon.actions.createTokenFromDraft}
            onRevokeToken={daemon.actions.revokeTokenGrant}
            onImportMcpFixture={daemon.actions.importMcpFixture}
            onEphemeralMcpProbe={daemon.actions.ephemeralMcpProbe}
            onCheckVaultAdapter={daemon.actions.checkVaultAdapter}
            onLatestVaultHealth={daemon.actions.latestVaultHealth}
            busy={busy}
          />
        ) : null}
        {activeTab === "routing" ? (
          <RoutingPanel
            data={daemon.data}
            selection={pickerSelection}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            onTestRoute={daemon.actions.testRoute}
            onSaveRoute={daemon.actions.saveRouteDraft}
            onTestRouteDraft={daemon.actions.testRouteDraft}
            onWorkflowProbe={daemon.actions.workflowProbe}
            busy={busy}
          />
        ) : null}
        {activeTab === "benchmarks" ? (
          <BenchmarksPanel
            data={daemon.data}
            selection={pickerSelection}
            connectionState={daemon.connectionState}
            hasSessionToken={daemon.hasSessionToken}
            onRunBenchmark={daemon.actions.runBenchmark}
            onReplayReceipt={daemon.actions.replayReceipt}
            busy={busy}
          />
        ) : null}
        {activeTab === "logs" ? (
          <LogsPanel
            receipts={visibleReceipts}
            connectionState={daemon.connectionState}
            onRefresh={() => void daemon.refresh()}
            onTailServerLogs={daemon.actions.tailServerLogs}
            onReplayReceipt={daemon.actions.replayReceipt}
            busy={busy}
          />
        ) : null}
      </main>
    </div>
  );
}
