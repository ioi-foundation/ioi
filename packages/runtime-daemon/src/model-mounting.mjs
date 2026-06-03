import crypto from "node:crypto";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import * as routeDecision from "./model-mounting/route-decision.mjs";
import { modelCapabilities as buildModelCapabilities } from "./model-mounting/model-capability.mjs";
import { AgentgresModelMountingStore } from "./model-mounting/store.mjs";
import { modelMountingRelationSchemas } from "./model-mounting/schema-relations.mjs";
import {
  capabilityForWorkflowNode,
  nativeInvocationResponseShape,
  workflowKindForNode,
} from "./model-mounting/workflow-node.mjs";
import {
  workflowMemoryOptionsFromBody,
  workflowMemoryWriteBlockReason,
} from "./model-mounting/workflow-memory.mjs";
import {
  artifactList,
  downloadList,
  endpointList,
  instanceList,
  legacyModelList as legacyModelListProjection,
  modelCapabilityList,
  modelMountingSnapshot,
  oauthSessionList,
  oauthStateList,
  openAiModelList as openAiModelListProjection,
  productArtifactList,
  providerHealthList,
  providerList,
  routeList,
} from "./model-mounting/read-model.mjs";
import {
  isFixtureEndpointCandidate,
  isFixtureModelRecord,
} from "./model-mounting/fixture-policy.mjs";
import {
  assertDownloadPolicyAllowed,
  catalogApprovalDecision,
  destructiveConfirmationState,
  inferModelArchitecture,
  inferParameterCount,
  importTargetPath,
  listModelFiles,
  materializeImportArtifact,
  modelIdFromSourceUrl,
  normalizeDownloadPolicy,
  normalizeImportMode,
  sourceLabelForUrl,
} from "./model-mounting/catalog-helpers.mjs";
import {
  catalogVariantForSource,
  enrichCatalogEntry,
  huggingFaceCatalogEntries,
} from "./model-mounting/catalog-entries.mjs";
import { backendBindAddress, discoverAutopilotLlamaServer, llamaCppGpuLayersArg, llamaCppLibraryPathEnv } from "./model-mounting/local-runtime-engines.mjs";
import {
  providerHealthFailureStatus,
} from "./model-mounting/provider-transport-policy.mjs";
import {
  hostedProvider as hostedProviderFromRegistry,
  optionalString as optionalStringFromProviderRegistry,
  publicProvider as publicProviderFromRegistry,
  requiredString as requiredStringFromProviderRegistry,
} from "./model-mounting/provider-registry.mjs";
import {
  assertNoPlaintextProviderSecret,
  assertProviderVaultBoundary,
  normalizeProviderAuthHeaderName,
  normalizeProviderAuthScheme,
  providerAuthHeaders,
  providerHasVaultRef,
  providerRequiresVaultSecret,
  providerSecretInput,
  sanitizeVaultRefs,
} from "./model-mounting/provider-auth.mjs";
import {
  oauthBoundaryForSession,
  publicOAuthSession,
  publicOAuthState,
} from "./model-mounting/oauth-boundary.mjs";
import { OAuthCredentialProvider } from "./model-mounting/oauth-credential-provider.mjs";
import {
  assertConfigurableCatalogProvider,
  MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS,
  catalogProviderAuthHeaders,
  catalogProviderConfigUpdate,
  catalogProviderHasSourceMaterial,
  catalogProviderMaterialPurpose,
  catalogProviderMaterialVaultRef,
  catalogProviderRuntimeMaterialFromValue,
} from "./model-mounting/catalog-provider-config.mjs";
import {
  customHttpCatalogProviderPort,
  fixtureCatalogProviderPort,
  huggingFaceCatalogBaseUrl,
  huggingFaceCatalogProviderPort,
  localManifestCatalogProviderPort,
  ollamaCatalogProviderPort,
} from "./model-mounting/catalog-provider-ports.mjs";
import {
  deterministicTokenizeText,
  estimateTokens,
  inputText,
  normalizeLimit,
  normalizeUsage,
  parseJsonMaybe,
  summarizeProviderRequestBodyForTrace,
  truncate,
  truncateToEstimatedTokens,
} from "./model-mounting/provider-protocol.mjs";
import {
  estimateNativeLocalResources,
  findExecutable,
  hardwareSnapshot,
  inspectLocalArtifact,
  listFiles,
  lmStudioArtifact,
  parseLmStudioList,
  parseLmStudioProcessList,
  parseLmStudioRuntimeEngines,
  parseLmStudioRuntimeSurvey,
  parseLocalModelMetadata,
  readLines,
  runPublicCommand,
} from "./model-mounting/local-system-probes.mjs";
import {
  defaultBackendForProvider,
  driverForProviderKind,
  driverNameForProvider,
  modelInvocationCoalesceKey,
  supportsResponseState,
} from "./model-mounting/provider-driver-helpers.mjs";
import * as serverControl from "./model-mounting/server-control.mjs";
import {
  expiresAt,
  hasExplicitTtlOption,
  normalizeLoadOptions,
  normalizeLoadPolicy,
  normalizeRuntimeEngineDefaultLoadOptions,
} from "./model-mounting/load-policy.mjs";
import {
  FixtureModelProviderDriver,
  NativeLocalModelProviderDriver,
} from "./model-mounting/provider-local-drivers.mjs";
import { OpenAICompatibleModelProviderDriver } from "./model-mounting/provider-openai-compatible-driver.mjs";
import { OllamaModelProviderDriver } from "./model-mounting/provider-ollama-driver.mjs";
import {
  LlamaCppModelProviderDriver,
  VllmModelProviderDriver,
} from "./model-mounting/provider-openai-backend-drivers.mjs";
import { LmStudioModelProviderDriver } from "./model-mounting/provider-lm-studio-driver.mjs";
import { AgentgresWalletAuthority } from "./model-mounting/wallet-authority.mjs";
import {
  AgentgresVaultPort,
  configuredVaultMaterialAdapter,
} from "./model-mounting/vault-port.mjs";
import {
  buildAdapterBoundaries,
  buildAuthoritySnapshot,
  buildModelMountingProjection,
  buildModelRouteDecisions,
  buildProjectionSummary,
  buildReceiptReplay,
} from "./model-mounting/projections.mjs";
export {
  anthropicMessage,
  openAiChatCompletion,
  openAiCompletion,
  openAiEmbedding,
  openAiResponse,
} from "./model-mounting/protocol-responses.mjs";
import {
  isExecutable,
  listJson,
  notFound,
  readJson,
  runtimeError,
  safeFileName,
  safeId,
  writeJson,
  stableHash,
  redact,
  shouldRedactKey,
  emitRemoteBoundaryEvent,
  fileSha256,
  sleep,
  fetchWithTimeout,
  fileSizeIfExists,
  normalizeNonNegativeInteger,
  normalizeOptionalBytes,
  truthy,
  matchesAny,
  publicToken,
  publicMcpServer,
  hashToken,
  operationCount,
  publicVaultRefs,
  normalizeScopes,
} from "./model-mounting/io.mjs";
import {
  materializeFixtureDownload,
  materializeLiveDownload,
  materializeLiveDownloadAttempt,
  writeDownloadResumeMetadata,
  isRetriableDownloadFailure,
  downloadRetryBackoffMs,
  shouldRetainFailedDownloadPartial,
  failedDownloadCleanupState,
  cleanupPartialDownload,
  downloadFailureReason,
  publicDownloadSource,
} from "./model-mounting/download-helpers.mjs";
import {
  catalogAuthFailureFields,
  catalogAuthFailureStatus,
  catalogAuthProviderFields,
  catalogEntryWithAuth,
  catalogProviderConfigHealthFields,
  publicCatalogAuthEvidence,
  publicCatalogProviderConfig,
} from "./model-mounting/catalog-projections.mjs";
import {
  catalogProviderStatus,
  modelCatalogProviderPorts as buildModelCatalogProviderPorts,
} from "./model-mounting/catalog-registry.mjs";
import {
  internalFixtureModelsEnabled,
  liveModelCatalogEnabled,
  liveModelDownloadEnabled,
  lmStudioPublicCliEnabled,
  lmStudioRuntimeDiscoveryEnabled,
  modelCatalogTimeoutMs,
  modelDownloadTimeoutMs,
} from "./model-mounting/environment.mjs";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1", SECRET_REDACTION = "[REDACTED]";

export class ModelMountingState {
  constructor({ stateDir, cwd, appendOperation, homeDir, now = () => new Date(), vaultSecrets = {} }) {
    this.stateDir = path.resolve(stateDir);
    this.cwd = path.resolve(cwd ?? process.cwd());
    this.homeDir = path.resolve(homeDir ?? process.env.HOME ?? this.cwd);
    this.modelRoot = path.join(this.stateDir, "models");
    this.bootId = `daemon_boot_${crypto.randomUUID()}`;
    this.appendOperation = appendOperation;
    this.now = now;
    this.store = new AgentgresModelMountingStore({
      stateDir: this.stateDir,
      appendOperation: (kind, payload) => this.appendOperation?.(kind, payload),
    });
    this.walletAuthority = new AgentgresWalletAuthority({
      now: this.now,
      appendOperation: (kind, payload) => this.appendOperation?.(kind, payload),
    });
    this.vault = new AgentgresVaultPort({
      now: this.now,
      appendOperation: (kind, payload) => this.appendOperation?.(kind, payload),
      secrets: vaultSecrets,
      materialAdapter: configuredVaultMaterialAdapter({ now: this.now }),
    });
    this.oauthCredentialProvider = new OAuthCredentialProvider({
      now: this.now,
      vault: this.vault,
    });
    this.providers = new Map();
    this.backends = new Map();
    this.backendChildProcesses = new Map();
    this.backendProcesses = new Map();
    this.artifacts = new Map();
    this.endpoints = new Map();
    this.instances = new Map();
    this.routes = new Map();
    this.downloads = new Map();
    this.catalogProviderConfigs = new Map();
    this.catalogProviderRuntimeMaterials = new Map();
    this.oauthSessions = new Map();
    this.oauthStates = new Map();
    this.lastCatalogSearch = null;
    this.runtimeSelections = new Map();
    this.runtimeEngineProfiles = new Map();
    this.tokens = new Map();
    this.vaultRefs = new Map();
    this.mcpServers = new Map();
    this.conversations = new Map();
    this.inflightModelInvocations = new Map();
    this.ensureDirs();
    this.load();
    this.vault.loadMetadata([...this.vaultRefs.values()]);
    this.seedDefaults();
    this.writeAll();
  }

  close() {
    for (const [processId, child] of this.backendChildProcesses.entries()) {
      try {
        if (!child.killed) child.kill("SIGTERM");
      } catch {
        // Best-effort cleanup for subprocesses owned by this daemon boot.
      }
      this.backendChildProcesses.delete(processId);
    }
  }

  ensureDirs() {
    this.store.ensureDirs();
  }

  writeSchemaRelationSchemas() {
    return modelMountingRelationSchemas();
  }

  load() {
    this.loadMap("model-providers", this.providers);
    this.loadMap("model-backends", this.backends);
    this.loadMap("backend-processes", this.backendProcesses);
    this.loadMap("model-artifacts", this.artifacts);
    this.loadMap("model-endpoints", this.endpoints);
    this.loadMap("model-instances", this.instances);
    this.loadMap("model-routes", this.routes);
    this.loadMap("model-downloads", this.downloads);
    this.loadMap("model-catalog-providers", this.catalogProviderConfigs);
    this.loadMap("oauth-sessions", this.oauthSessions);
    this.loadMap("oauth-states", this.oauthStates);
    this.loadMap("runtime-preferences", this.runtimeSelections);
    this.loadMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    this.loadMap("tokens", this.tokens);
    this.loadMap("vault-refs", this.vaultRefs);
    this.loadMap("mcp-servers", this.mcpServers);
    this.loadMap("model-conversations", this.conversations);
  }

  loadMap(dir, map) {
    for (const filePath of listJson(path.join(this.stateDir, dir))) {
      const record = readJson(filePath);
      if (typeof record.id === "string") {
        map.set(record.id, record);
      }
    }
  }

  seedDefaults() {
    const checkedAt = this.nowIso();
    const localProvider = {
      id: "provider.local.folder",
      kind: "local_folder",
      label: "Local model folder",
      apiFormat: "fixture",
      driver: "fixture",
      baseUrl: "local://models",
      status: "available",
      privacyClass: "local_private",
      capabilities: ["chat", "embeddings", "structured_output", "rerank"],
      discovery: {
        checkedAt,
        evidenceRefs: ["agentgres_model_registry_fixture"],
      },
    };
    this.upsertDefault(this.providers, localProvider);

    const nativeLocalProvider = {
      id: "provider.autopilot.local",
      kind: "ioi_native_local",
      label: "Autopilot native local",
      apiFormat: "ioi_native",
      driver: "native_local",
      baseUrl: "local://ioi-native/model-server",
      status: "available",
      privacyClass: "local_private",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      discovery: {
        checkedAt,
        evidenceRefs: ["autopilot_native_local_backend_registry", "deterministic_native_local_fixture"],
      },
    };
    this.upsertDefault(this.providers, nativeLocalProvider);

    const lmStudioProvider = this.discoverLmStudioProvider(checkedAt);
    if (lmStudioProvider.discovery?.disabledByDefault) {
      this.pruneLmStudioPublicProjectionRecords();
    }
    if (!internalFixtureModelsEnabled()) {
      this.pruneInternalFixtureProjectionRecords();
    }
    this.providers.set(lmStudioProvider.id, {
      ...this.providers.get(lmStudioProvider.id),
      ...lmStudioProvider,
      discovery: lmStudioProvider.discovery,
    });

    const llamaBinary = process.env.IOI_LLAMA_CPP_SERVER_PATH ?? discoverAutopilotLlamaServer(this.homeDir) ?? findExecutable("llama-server");
    const vllmBinary = process.env.IOI_VLLM_BINARY ?? findExecutable("vllm");
    for (const provider of [
      {
        id: "provider.ollama",
        kind: "ollama",
        label: "Ollama",
        apiFormat: "ollama",
        driver: "ollama",
        baseUrl: process.env.OLLAMA_HOST ?? "http://127.0.0.1:11434",
        status: process.env.OLLAMA_HOST ? "configured" : "blocked",
        privacyClass: "local_private",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["OLLAMA_HOST"] },
      },
      {
        id: "provider.llama-cpp",
        kind: "llama_cpp",
        label: "llama.cpp",
        apiFormat: "openai_compatible",
        driver: "llama_cpp",
        baseUrl: process.env.IOI_LLAMA_CPP_BASE_URL ?? "http://127.0.0.1:8080/v1",
        status: process.env.IOI_LLAMA_CPP_BASE_URL || llamaBinary ? "configured" : "blocked",
        privacyClass: "local_private",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: {
          checkedAt,
          evidenceRefs: [
            "IOI_LLAMA_CPP_BASE_URL",
            "IOI_LLAMA_CPP_SERVER_PATH",
            ...(llamaBinary ? ["autopilot_llama_cpp_runtime_engine_detected"] : []),
          ],
          binaryPathHash: llamaBinary ? stableHash(llamaBinary) : null,
        },
      },
      {
        id: "provider.vllm",
        kind: "vllm",
        label: "vLLM",
        apiFormat: "openai_compatible",
        driver: "vllm",
        baseUrl: process.env.VLLM_BASE_URL ?? "http://127.0.0.1:8000/v1",
        status: process.env.VLLM_BASE_URL || vllmBinary ? "configured" : "blocked",
        privacyClass: "workspace",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["VLLM_BASE_URL", vllmBinary ? "vllm_binary_detected" : "IOI_VLLM_BINARY"] },
      },
      {
        id: "provider.openai-compatible",
        kind: "openai_compatible",
        label: "OpenAI-compatible endpoint",
        apiFormat: "openai_compatible",
        driver: "openai_compatible",
        baseUrl: process.env.OPENAI_COMPATIBLE_BASE_URL ?? "http://127.0.0.1:1234/v1",
        status: process.env.OPENAI_COMPATIBLE_BASE_URL ? "configured" : "blocked",
        privacyClass: "workspace",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["OPENAI_COMPATIBLE_BASE_URL"] },
      },
      hostedProvider("provider.openai", "OpenAI", "openai", process.env.OPENAI_API_KEY),
      hostedProvider("provider.anthropic", "Anthropic", "anthropic", process.env.ANTHROPIC_API_KEY),
      hostedProvider("provider.gemini", "Gemini", "gemini", process.env.GEMINI_API_KEY),
      {
        id: "provider.custom-http",
        kind: "custom_http",
        label: "Custom HTTP endpoint",
        apiFormat: "custom",
        driver: "openai_compatible",
        baseUrl: process.env.IOI_CUSTOM_MODEL_ENDPOINT ?? null,
        status: process.env.IOI_CUSTOM_MODEL_ENDPOINT ? "configured" : "blocked",
        privacyClass: "workspace",
        capabilities: ["chat"],
        discovery: { checkedAt, evidenceRefs: ["IOI_CUSTOM_MODEL_ENDPOINT"] },
      },
      {
        id: "provider.depin-tee",
        kind: "depin_tee",
        label: "DePIN / TEE runtime",
        apiFormat: "runtime_contract",
        driver: "fixture",
        baseUrl: null,
        status: "future",
        privacyClass: "remote_confidential",
        capabilities: ["chat", "code", "receipts"],
        discovery: { checkedAt, evidenceRefs: ["future_runtime_profile"] },
      },
    ]) {
      this.upsertDefault(this.providers, provider);
    }

    this.seedBackends(checkedAt);

    let nativeFixtureArtifact = null;
    if (internalFixtureModelsEnabled()) {
      this.upsertDefault(this.artifacts, {
        id: "local.auto",
        providerId: localProvider.id,
        modelId: "local:auto",
        displayName: "IOI local fixture model",
        family: "fixture",
        quantization: "fixture",
        sizeBytes: 0,
        contextWindow: 8192,
        capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
        privacyClass: "local_private",
        source: "deterministic_fixture",
        state: "installed",
        discoveredAt: checkedAt,
      });
      this.upsertDefault(this.artifacts, {
        id: "local.embedding.fixture",
        providerId: localProvider.id,
        modelId: "local:embedding-fixture",
        displayName: "IOI local embedding fixture",
        family: "fixture",
        quantization: "fixture",
        sizeBytes: 0,
        contextWindow: 2048,
        capabilities: ["embeddings"],
        privacyClass: "local_private",
        source: "deterministic_fixture",
        state: "installed",
        discoveredAt: checkedAt,
      });
      nativeFixtureArtifact = this.ensureNativeLocalFixtureArtifact(checkedAt);
      this.upsertDefault(this.artifacts, nativeFixtureArtifact);
    }
    const lmStudioArtifacts = this.discoverLmStudioArtifacts(lmStudioProvider, checkedAt);
    if (lmStudioArtifacts.length > 0) {
      for (const artifact of lmStudioArtifacts) {
        this.upsertDefault(this.artifacts, artifact);
      }
    } else if (lmStudioProvider.status !== "absent") {
      this.upsertDefault(this.artifacts, {
        id: "lmstudio.detected",
        providerId: lmStudioProvider.id,
        modelId: "lmstudio:detected",
        displayName: "LM Studio detected model slot",
        family: "lm-studio",
        quantization: "unknown",
        sizeBytes: null,
        contextWindow: null,
        capabilities: ["chat", "responses", "embeddings"],
        privacyClass: "local_private",
        source: "lm_studio_public_discovery",
        state: lmStudioProvider.status === "running" ? "available" : "provider_stopped",
        discoveredAt: checkedAt,
      });
    }
    if (internalFixtureModelsEnabled()) {
      this.upsertDefault(this.endpoints, {
        id: "endpoint.local.auto",
        providerId: localProvider.id,
        modelId: "local:auto",
        apiFormat: "ioi_fixture",
        driver: "fixture",
        baseUrl: "local://ioi-daemon/model-fixture",
        capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
        privacyClass: "local_private",
        loadPolicy: {
          mode: "on_demand",
          idleTtlSeconds: 900,
          autoEvict: true,
        },
        status: "mounted",
        mountedAt: checkedAt,
      });
      this.upsertDefault(this.endpoints, {
        id: "endpoint.autopilot.native-fixture",
        providerId: nativeLocalProvider.id,
        modelId: nativeFixtureArtifact.modelId,
        apiFormat: "ioi_native",
        driver: "native_local",
        baseUrl: "local://ioi-native/model-server",
        capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
        privacyClass: "local_private",
        loadPolicy: {
          mode: "on_demand",
          idleTtlSeconds: 900,
          autoEvict: true,
        },
        status: "mounted",
        mountedAt: checkedAt,
        backendRegistry: this.backendRegistry(),
      });
    }

    this.upsertDefault(this.routes, {
      id: "route.local-first",
      role: "default",
      description: "Local/private first route with hosted fallback blocked unless policy allows it.",
      privacy: "local_or_enterprise",
      quality: "adaptive",
      maxCostUsd: 0.25,
      maxLatencyMs: 30000,
      providerEligibility: ["local_folder", "lm_studio", "ollama", "vllm", "openai_compatible"],
      fallback: [],
      deniedProviders: ["openai", "anthropic", "gemini"],
      status: "active",
      lastSelectedModel: null,
      lastReceiptId: null,
    });
    this.upsertDefault(this.routes, {
      id: "route.native-local",
      role: "default",
      description: "Autopilot-native local route that does not require LM Studio.",
      privacy: "local_only",
      quality: "native_local",
      maxCostUsd: 0,
      maxLatencyMs: 30000,
      providerEligibility: ["ioi_native_local"],
      fallback: [],
      deniedProviders: ["openai", "anthropic", "gemini", "lm_studio"],
      status: "active",
      lastSelectedModel: null,
      lastReceiptId: null,
    });
  }

  ensureNativeLocalFixtureArtifact(checkedAt) {
    const fixtureDir = path.join(this.modelRoot, "native-fixture");
    const fixturePath = path.join(fixtureDir, "autopilot-native-fixture.Q4_K_M.gguf");
    fs.mkdirSync(fixtureDir, { recursive: true });
    if (!fs.existsSync(fixturePath)) {
      fs.writeFileSync(
        fixturePath,
        [
          "IOI deterministic native-local model fixture",
          "format=gguf",
          "family=autopilot-native",
          "quantization=Q4_K_M",
          "context=8192",
        ].join("\n"),
      );
    }
    const stats = fs.statSync(fixturePath);
    const metadata = parseLocalModelMetadata(fixturePath);
    return {
      id: "autopilot.native.fixture",
      providerId: "provider.autopilot.local",
      modelId: "autopilot:native-fixture",
      displayName: "Autopilot native local fixture",
      family: metadata.family ?? "autopilot-native",
      format: metadata.format ?? "gguf",
      quantization: metadata.quantization ?? "Q4_K_M",
      sizeBytes: stats.size,
      checksum: fileSha256(fixturePath),
      contextWindow: metadata.contextWindow ?? 8192,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      privacyClass: "local_private",
      source: "autopilot_native_local_fixture",
      state: "installed",
      artifactPath: fixturePath,
      backendRegistry: this.backendRegistry(),
      discoveredAt: checkedAt,
    };
  }

  upsertDefault(map, record) {
    if (!map.has(record.id)) {
      map.set(record.id, record);
    }
  }

  discoverLmStudioProvider(checkedAt) {
    const publicCliEnabled = lmStudioPublicCliEnabled();
    if (!publicCliEnabled && !process.env.LM_STUDIO_BASE_URL && !process.env.LM_STUDIO_URL) {
      return {
        id: "provider.lmstudio",
        kind: "lm_studio",
        label: "LM Studio",
        apiFormat: "openai_compatible",
        driver: "lm_studio",
        baseUrl: "http://127.0.0.1:1234/v1",
        status: "absent",
        privacyClass: "local_private",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: {
          checkedAt,
          evidenceRefs: ["lm_studio_public_cli_discovery_disabled"],
          publicCli: null,
          disabledByDefault: true,
        },
      };
    }
    const candidates = [
      process.env.IOI_LMS_PATH,
      path.join(this.homeDir, ".local/bin/lm-studio"),
      path.join(this.homeDir, ".local/bin/lm-studio.AppImage"),
      path.join(this.homeDir, ".lmstudio/bin/lms"),
    ].filter(Boolean);
    const executables = candidates.filter((candidate) => isExecutable(candidate));
    const lmsPath = candidates.find((candidate) => path.basename(candidate) === "lms" && isExecutable(candidate));
    const serverStatus = publicCliEnabled && lmsPath ? runPublicCommand(lmsPath, ["server", "status"]) : null;
    const serverStatusText = serverStatus?.stdout ?? serverStatus?.stderr ?? "";
    const baseUrl = process.env.LM_STUDIO_BASE_URL ?? process.env.LM_STUDIO_URL ?? "http://127.0.0.1:1234/v1";
    const status = serverStatusText.match(/\b(ON|RUNNING|STARTED)\b/i)
      ? "running"
      : process.env.LM_STUDIO_BASE_URL || process.env.LM_STUDIO_URL
        ? "configured"
        : executables.length > 0
        ? "stopped"
        : "absent";
    return {
      id: "provider.lmstudio",
      kind: "lm_studio",
      label: "LM Studio",
      apiFormat: "openai_compatible",
      driver: "lm_studio",
      baseUrl,
      status,
      privacyClass: "local_private",
      capabilities: ["chat", "responses", "embeddings"],
      discovery: {
        checkedAt,
        evidenceRefs: [
          publicCliEnabled ? "lm_studio_public_cli_or_server_probe" : "lm_studio_public_cli_discovery_disabled",
        ],
        executableCandidates: candidates,
        foundExecutables: publicCliEnabled ? executables : [],
        publicCli: publicCliEnabled && lmsPath
          ? {
              path: lmsPath,
              serverStatus: truncate(serverStatusText),
              exitCode: serverStatus?.status ?? null,
            }
          : null,
      },
    };
  }

  discoverLmStudioArtifacts(provider, checkedAt) {
    if (!lmStudioPublicCliEnabled()) return [];
    const lmsPath = provider.discovery?.publicCli?.path;
    if (!lmsPath) return [];
    const result = runPublicCommand(lmsPath, ["ls"]);
    if (!result || result.status !== 0) return [];
    return parseLmStudioList(result.stdout).map((model) => lmStudioArtifact(provider, model, checkedAt));
  }

  pruneLmStudioPublicProjectionRecords() {
    for (const [id, artifact] of this.artifacts.entries()) {
      if (
        artifact.providerId === "provider.lmstudio" ||
        String(id).startsWith("lmstudio.") ||
        String(artifact.source ?? "").startsWith("lm_studio_public")
      ) {
        this.artifacts.delete(id);
      }
    }
    const removedEndpointIds = new Set();
    for (const [id, endpoint] of this.endpoints.entries()) {
      if (endpoint.providerId === "provider.lmstudio" || String(id).includes("provider.lmstudio")) {
        removedEndpointIds.add(id);
        this.endpoints.delete(id);
      }
    }
    for (const [id, instance] of this.instances.entries()) {
      if (instance.providerId === "provider.lmstudio" || removedEndpointIds.has(instance.endpointId)) {
        this.instances.delete(id);
      }
    }
  }

  pruneInternalFixtureProjectionRecords() {
    const removedEndpointIds = new Set();
    const removedModelIds = new Set();
    for (const [id, artifact] of this.artifacts.entries()) {
      if (isFixtureModelRecord(artifact) || String(id).includes("fixture") || String(artifact.modelId ?? "").includes("local:auto")) {
        removedModelIds.add(artifact.modelId);
        this.artifacts.delete(id);
      }
    }
    for (const [id, endpoint] of this.endpoints.entries()) {
      if (
        isFixtureEndpointCandidate(endpoint, this.providers.get(endpoint.providerId)) ||
        String(id).includes("fixture") ||
        String(endpoint.modelId ?? "").includes("local:auto")
      ) {
        removedEndpointIds.add(id);
        removedModelIds.add(endpoint.modelId);
        this.endpoints.delete(id);
      }
    }
    for (const [id, instance] of this.instances.entries()) {
      if (
        removedEndpointIds.has(instance.endpointId) ||
        removedModelIds.has(instance.modelId) ||
        isFixtureModelRecord(instance)
      ) {
        this.instances.delete(id);
      }
    }
  }

  writeAll() {
    this.writeMap("model-providers", this.providers);
    this.writeMap("model-backends", this.backends);
    this.writeMap("backend-processes", this.backendProcesses);
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-endpoints", this.endpoints);
    this.writeMap("model-instances", this.instances);
    this.writeMap("model-routes", this.routes);
    this.writeMap("model-downloads", this.downloads);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("oauth-states", this.oauthStates);
    this.writeMap("runtime-preferences", this.runtimeSelections);
    this.writeMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    this.writeMap("tokens", this.tokens);
    this.writeVaultRefs();
    this.writeMap("mcp-servers", this.mcpServers);
    this.writeMap("model-conversations", this.conversations);
    this.writeProjection();
  }

  writeMap(dir, map) {
    this.store.writeMap(dir, map);
  }

  writeVaultRefs() {
    this.vaultRefs = new Map(this.vault.metadataRecords().map((record) => [record.id, record]));
    this.writeMap("vault-refs", this.vaultRefs);
  }

  serverStatus(baseUrl) {
    return serverControl.serverStatus(this, baseUrl, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverControlState() {
    return serverControl.serverControlState(this, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  writeServerControlState(state) {
    return serverControl.writeServerControlState(this, state);
  }

  serverStart(baseUrl) {
    return serverControl.serverStart(this, baseUrl, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverStop(baseUrl) {
    return serverControl.serverStop(this, baseUrl, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverRestart(baseUrl) {
    return serverControl.serverRestart(this, baseUrl, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  recordServerOperation(operation, status, baseUrl, details = {}) {
    return serverControl.recordServerOperation(this, operation, status, baseUrl, details, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverLogs(query = {}) {
    return serverControl.serverLogs(this, query, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverEvents(query = {}) {
    return serverControl.serverEvents(this, query, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverLogRecords({ limit = 80 } = {}) {
    return serverControl.serverLogRecords(this, { limit });
  }

  writeServerLog(event) {
    return serverControl.writeServerLog(this, event);
  }

  legacyModelList() {
    return legacyModelListProjection(this);
  }

  openAiModelList() {
    return openAiModelListProjection(this);
  }

  listArtifacts() {
    return artifactList(this);
  }

  listProductArtifacts() {
    return productArtifactList(this, {
      internalFixtureModelsEnabled,
      isFixtureModelRecord,
    });
  }

  listProviders() {
    return providerList(this, {
      providerHasVaultRef,
      publicProvider,
    });
  }

  listEndpoints() {
    return endpointList(this);
  }

  listInstances() {
    return instanceList(this);
  }

  listRoutes() {
    return routeList(this);
  }

  listModelCapabilities() {
    return modelCapabilityList(this, {
      buildModelCapabilities,
    });
  }

  listDownloads() {
    return downloadList(this);
  }

  listOAuthSessions() {
    return oauthSessionList(this, {
      publicOAuthSession,
    });
  }

  listOAuthStates() {
    return oauthStateList(this, {
      publicOAuthState,
    });
  }

  listProviderHealth() {
    return providerHealthList(this, {
      listJson,
      path,
      readJson,
    });
  }

  snapshot(baseUrl) {
    return modelMountingSnapshot(this, baseUrl, {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
  }

  authoritySnapshot(baseUrl) {
    return buildAuthoritySnapshot(this, baseUrl, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  projectionSummary() {
    return buildProjectionSummary(this.projection());
  }

  projection() {
    return buildModelMountingProjection(this, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  adapterBoundaries() {
    return buildAdapterBoundaries(this);
  }

  writeProjection() {
    if (this.writingProjection) return;
    this.writingProjection = true;
    try {
      this.store.writeProjection("model-mounting-canonical", this.projection());
    } finally {
      this.writingProjection = false;
    }
  }

  receiptReplay(receiptId) {
    return buildReceiptReplay(this, receiptId, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  modelRouteDecisions() {
    return buildModelRouteDecisions(this);
  }

  latestProviderHealth(providerId) {
    this.provider(providerId);
    const health = this.listProviderHealth()
      .filter((record) => record.providerId === providerId)
      .at(-1);
    if (!health?.receiptId) {
      throw notFound(`Provider health has not been checked: ${providerId}`, { providerId });
    }
    const receipt = this.getReceipt(health.receiptId);
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      source: "agentgres_provider_health_latest",
      providerId,
      health,
      receipt,
      replay: this.receiptReplay(receipt.id),
      projectionWatermark: operationCount(this.stateDir),
    };
  }

  latestVaultHealth() {
    const receipt = this.listReceipts()
      .filter((item) => item.kind === "vault_adapter_health")
      .at(-1);
    if (!receipt) {
      throw notFound("Vault adapter health has not been checked.", { receiptKind: "vault_adapter_health" });
    }
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      source: "agentgres_vault_health_latest",
      health: receipt.details,
      receipt,
      replay: this.receiptReplay(receipt.id),
      projectionWatermark: operationCount(this.stateDir),
    };
  }

  workflowNodeBindings() {
    return [
      "Model Call",
      "Structured Output",
      "Verifier",
      "Planner",
      "Embedding",
      "Reranker",
      "Vision",
      "Local Tool/MCP",
      "Model Router",
      "Receipt Gate",
    ].map((node) => ({
      node,
      modelId: null,
      supportsExplicitModelId: true,
      supportsModelPolicy: true,
      capability: capabilityForWorkflowNode(node),
      receiptRequired: true,
      routeId: "route.local-first",
      daemonApi: node === "Receipt Gate" ? "/api/v1/workflows/receipt-gate" : "/api/v1/workflows/nodes/execute",
    }));
  }

  getModel(id) {
    const artifact = [...this.artifacts.values()].find((item) => item.id === id || item.modelId === id);
    if (!artifact) {
      throw notFound(`Model not found: ${id}`, { modelId: id });
    }
    return artifact;
  }

  modelForProviderMount(modelId, provider, body = {}, now = this.nowIso()) {
    const artifact = [...this.artifacts.values()].find(
      (item) => item.id === modelId || (item.modelId === modelId && item.providerId === provider.id),
    );
    if (artifact) return artifact;
    const mounted = {
      id: `${safeId(provider.id)}.${safeId(modelId)}`,
      providerId: provider.id,
      modelId,
      displayName: body.display_name ?? body.displayName ?? modelId,
      family: body.family ?? provider.kind,
      quantization: body.quantization ?? null,
      sizeBytes: Number.isFinite(Number(body.size_bytes ?? body.sizeBytes)) ? Number(body.size_bytes ?? body.sizeBytes) : null,
      contextWindow: Number.isFinite(Number(body.context_window ?? body.contextWindow)) ? Number(body.context_window ?? body.contextWindow) : null,
      capabilities: normalizeScopes(body.capabilities, provider.capabilities ?? ["chat", "responses", "embeddings"]),
      privacyClass: body.privacy_class ?? body.privacyClass ?? provider.privacyClass,
      source: `${driverNameForProvider(provider)}_provider_direct_mount`,
      state: "available",
      discoveredAt: now,
    };
    this.artifacts.set(mounted.id, mounted);
    this.writeMap("model-artifacts", this.artifacts);
    return mounted;
  }

  catalogStatus() {
    const lastSearch = this.lastCatalogSearch;
    const providers = this.catalogProviderPorts().map((port) => catalogProviderStatus(port));
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      checkedAt: this.nowIso(),
      providers,
      adapterBoundary: {
        port: "ModelCatalogProviderPort",
        operations: ["search", "resolveVariant", "importUrl", "download", "health"],
        evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
      },
      filters: {
        formats: ["gguf", "mlx", "safetensors"],
        quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
        compatibility: ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
      },
      storage: this.storageSummary(),
      lastSearch: lastSearch
        ? {
            searchedAt: lastSearch.searchedAt,
            query: lastSearch.query,
            filters: lastSearch.filters,
            resultCount: lastSearch.results.length,
          }
        : null,
      results: lastSearch?.results ?? [],
    };
  }

  catalogProviderPorts() {
    return buildModelCatalogProviderPorts({
      state: this,
      fixtureCatalogProviderPort,
      localManifestCatalogProviderPort,
      ollamaCatalogProviderPort,
      huggingFaceCatalogProviderPort,
      customHttpCatalogProviderPort,
    });
  }

  listCatalogProviderConfigs() {
    return MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.map((providerId) =>
      publicCatalogProviderConfig(
        providerId,
        this.catalogProviderConfigs.get(providerId),
        this.catalogProviderRuntimeMaterial(providerId),
      ),
    );
  }

  getCatalogProviderConfig(providerId) {
    assertConfigurableCatalogProvider(providerId);
    const port = this.catalogProviderPorts().find((candidate) => candidate.id === providerId) ?? null;
    return {
      ...publicCatalogProviderConfig(
        providerId,
        this.catalogProviderConfigs.get(providerId),
        this.catalogProviderRuntimeMaterial(providerId),
      ),
      provider: port ? catalogProviderStatus(port) : null,
    };
  }

  configureCatalogProvider(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    const existing = this.catalogProviderConfigs.get(providerId);
    const update = catalogProviderConfigUpdate(providerId, body, existing, this.nowIso(), this);
    const { record, runtimeMaterial, evidenceRefs } = update;
    this.catalogProviderConfigs.set(providerId, record);
    if (runtimeMaterial) this.catalogProviderRuntimeMaterials.set(providerId, runtimeMaterial);
    else this.catalogProviderRuntimeMaterials.delete(providerId);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    const publicRecord = publicCatalogProviderConfig(providerId, record, this.catalogProviderRuntimeMaterial(providerId));
    const receipt = this.receipt("model_catalog_provider_configuration", {
      summary: `${providerId} catalog configuration updated through the governed catalog provider path.`,
      redaction: "redacted",
      evidenceRefs: ["ModelCatalogProviderPort.configure", providerId, ...evidenceRefs],
      details: publicRecord,
    });
    this.writeProjection();
    return {
      ...publicRecord,
      receiptId: receipt.id,
      provider: catalogProviderStatus(this.catalogProviderPorts().find((port) => port.id === providerId)),
    };
  }

  startCatalogProviderOAuth(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    const started = this.oauthCredentialProvider.startAuthorization({ providerId, body });
    this.oauthStates.set(started.state.id, started.state);
    const existing = this.catalogProviderConfigs.get(providerId);
    const update = catalogProviderConfigUpdate(
      providerId,
      {
        enabled: body.enabled ?? existing?.enabled ?? true,
        auth_scheme: "oauth2",
        auth_header_name: body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? "authorization",
      },
      existing,
      this.nowIso(),
      this,
    );
    this.catalogProviderConfigs.set(providerId, {
      ...update.record,
      oauthBoundary: {
        configured: false,
        status: "pending_authorization",
        tokenExchange: "OAuthCredentialProvider.startAuthorization",
        oauthStateHash: started.evidence.oauthStateHash,
        expiresAt: started.evidence.expiresAt,
        scopes: started.evidence.scopes,
        pkceRequired: started.evidence.pkceRequired,
        evidenceRefs: ["catalog_oauth_boundary", "VaultOAuthAuthorizationState"],
      },
      updatedAt: this.nowIso(),
    });
    if (update.runtimeMaterial) this.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
    this.writeMap("oauth-states", this.oauthStates);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const publicRecord = publicCatalogProviderConfig(
      providerId,
      this.catalogProviderConfigs.get(providerId),
      this.catalogProviderRuntimeMaterial(providerId),
    );
    const receipt = this.receipt("catalog_oauth_start", {
      summary: `${providerId} OAuth authorization started through PKCE and vault-bound state.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.startAuthorization", "VaultOAuthAuthorizationState", providerId],
      details: {
        providerId,
        oauthState: started.evidence,
        authorizationUrlHash: started.authorizationUrlHash,
        authorizationUrlRedacted: started.authorizationUrlRedacted,
        catalogProvider: publicRecord,
      },
    });
    this.writeProjection();
    return {
      ...publicRecord,
      oauthState: started.evidence,
      authorizationUrl: started.authorizationUrl,
      authorizationUrlRedacted: started.authorizationUrlRedacted,
      authorizationUrlHash: started.authorizationUrlHash,
      receiptId: receipt.id,
      provider: catalogProviderStatus(this.catalogProviderPorts().find((port) => port.id === providerId)),
    };
  }

  async completeCatalogProviderOAuth(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    const callbackState = requiredString(body.state ?? body.oauth_state ?? body.oauthState, "state");
    const stateId = body.state_id ?? body.stateId ?? null;
    const stateRecord = stateId
      ? this.oauthStates.get(String(stateId))
      : [...this.oauthStates.values()].find(
          (candidate) =>
            candidate.providerId === providerId &&
            candidate.status === "pending" &&
            candidate.stateHash === stableHash(callbackState),
        );
    const completed = await this.oauthCredentialProvider.completeAuthorization({ providerId, stateRecord, body });
    this.oauthStates.set(completed.state.id, completed.state);
    this.oauthSessions.set(completed.session.id, completed.session);
    const existing = this.catalogProviderConfigs.get(providerId);
    const update = catalogProviderConfigUpdate(
      providerId,
      {
        enabled: body.enabled ?? existing?.enabled ?? true,
        auth_scheme: "oauth2",
        auth_header_name: body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? "authorization",
        auth_vault_ref: completed.session.accessVaultRef,
        oauth_session_id: completed.session.id,
      },
      existing,
      this.nowIso(),
      this,
    );
    this.catalogProviderConfigs.set(providerId, update.record);
    if (update.runtimeMaterial) this.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
    this.writeMap("oauth-states", this.oauthStates);
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const publicRecord = publicCatalogProviderConfig(providerId, update.record, this.catalogProviderRuntimeMaterial(providerId));
    const receipt = this.receipt("catalog_oauth_callback", {
      summary: `${providerId} OAuth callback validated state and bound the session through vault refs.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.completeAuthorization", "VaultOAuthAuthorizationState", "VaultOAuthSession", providerId],
      details: {
        providerId,
        oauthState: completed.stateEvidence,
        oauthSession: completed.sessionEvidence,
        catalogProvider: publicRecord,
      },
    });
    this.writeProjection();
    return {
      ...publicRecord,
      oauthState: completed.stateEvidence,
      oauthSession: completed.sessionEvidence,
      receiptId: receipt.id,
      provider: catalogProviderStatus(this.catalogProviderPorts().find((port) => port.id === providerId)),
    };
  }

  async exchangeCatalogProviderOAuth(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    const { session, evidence } = await this.oauthCredentialProvider.exchangeAuthorizationCode({ providerId, body });
    this.oauthSessions.set(session.id, session);
    const existing = this.catalogProviderConfigs.get(providerId);
    const update = catalogProviderConfigUpdate(
      providerId,
      {
        enabled: body.enabled ?? existing?.enabled ?? true,
        auth_scheme: "oauth2",
        auth_header_name: body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? "authorization",
        auth_vault_ref: session.accessVaultRef,
        oauth_session_id: session.id,
      },
      existing,
      this.nowIso(),
      this,
    );
    this.catalogProviderConfigs.set(providerId, update.record);
    if (update.runtimeMaterial) this.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const publicRecord = publicCatalogProviderConfig(providerId, update.record, this.catalogProviderRuntimeMaterial(providerId));
    const receipt = this.receipt("catalog_oauth_exchange", {
      summary: `${providerId} OAuth session exchanged and bound through vault refs.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.exchangeAuthorizationCode", "VaultOAuthSession", providerId],
      details: {
        providerId,
        oauthSession: evidence,
        catalogProvider: publicRecord,
      },
    });
    this.writeProjection();
    return {
      ...publicRecord,
      oauthSession: evidence,
      receiptId: receipt.id,
      provider: catalogProviderStatus(this.catalogProviderPorts().find((port) => port.id === providerId)),
    };
  }

  async refreshCatalogProviderOAuth(providerId) {
    assertConfigurableCatalogProvider(providerId);
    const config = this.catalogProviderConfigs.get(providerId);
    const session = config?.oauthSessionId ? this.oauthSessions.get(config.oauthSessionId) : null;
    if (!session) {
      throw runtimeError({
        status: 404,
        code: "not_found",
        message: `OAuth session not found for catalog provider: ${providerId}`,
        details: { providerId, oauthSessionHash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
      });
    }
    const refreshed = await this.oauthCredentialProvider.refreshAccessToken(session);
    this.oauthSessions.set(refreshed.id, refreshed);
    this.catalogProviderConfigs.set(providerId, {
      ...config,
      oauthBoundary: oauthBoundaryForSession(refreshed, { refreshed: true }),
      updatedAt: this.nowIso(),
    });
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const receipt = this.receipt("catalog_oauth_refresh", {
      summary: `${providerId} OAuth session refreshed through vault refs.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.refreshAccessToken", "VaultOAuthSession", providerId],
      details: {
        providerId,
        oauthSession: publicOAuthSession(refreshed),
      },
    });
    this.writeProjection();
    return { oauthSession: publicOAuthSession(refreshed), receiptId: receipt.id };
  }

  revokeCatalogProviderOAuth(providerId) {
    assertConfigurableCatalogProvider(providerId);
    const config = this.catalogProviderConfigs.get(providerId);
    const session = config?.oauthSessionId ? this.oauthSessions.get(config.oauthSessionId) : null;
    if (!session) {
      throw runtimeError({
        status: 404,
        code: "not_found",
        message: `OAuth session not found for catalog provider: ${providerId}`,
        details: { providerId, oauthSessionHash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
      });
    }
    const revoked = this.oauthCredentialProvider.revokeSession(session);
    this.oauthSessions.set(revoked.id, revoked);
    this.catalogProviderConfigs.set(providerId, {
      ...config,
      oauthBoundary: oauthBoundaryForSession(revoked),
      updatedAt: this.nowIso(),
    });
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const receipt = this.receipt("catalog_oauth_revoke", {
      summary: `${providerId} OAuth session revoked through vault refs.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.revokeSession", "VaultOAuthSession", providerId],
      details: {
        providerId,
        oauthSession: publicOAuthSession(revoked),
      },
    });
    this.writeProjection();
    return { oauthSession: publicOAuthSession(revoked), receiptId: receipt.id };
  }

  catalogProviderConfig(providerId) {
    return this.catalogProviderConfigs.get(providerId) ?? null;
  }

  catalogProviderRuntimeMaterial(providerId) {
    const existing = this.catalogProviderRuntimeMaterials.get(providerId) ?? null;
    if (catalogProviderHasSourceMaterial(existing)) return existing;
    if (existing?.runtimeMaterialStatus === "missing_runtime_material" || existing?.runtimeMaterialStatus === "vault_material_unavailable") {
      return existing;
    }
    const config = this.catalogProviderConfigs.get(providerId) ?? null;
    if (!config?.materialConfigured && !config?.materialVaultRefHash) return existing;
    const vaultRef = catalogProviderMaterialVaultRef(providerId);
    const purpose = catalogProviderMaterialPurpose(providerId);
    try {
      const resolved = this.vault.resolveVaultRef(vaultRef, purpose);
      this.writeVaultRefs();
      if (!resolved.resolvedMaterial || typeof resolved.material !== "string" || !resolved.material.trim()) {
        const missing = {
          runtimeMaterialStatus: "missing_runtime_material",
          materialSource: resolved.materialSource ?? "unbound",
          materialVaultRefHash: resolved.vaultRefHash,
          evidenceRefs: normalizeScopes(resolved.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_provider_source_material_unbound"]),
        };
        this.catalogProviderRuntimeMaterials.set(providerId, missing);
        return missing;
      }
      const material = {
        ...catalogProviderRuntimeMaterialFromValue(providerId, resolved.material),
        runtimeMaterialStatus: "resolved_from_vault",
        materialSource: resolved.materialSource ?? "vault_material_adapter",
        materialVaultRefHash: resolved.vaultRefHash,
        evidenceRefs: normalizeScopes(resolved.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_provider_source_material_resolved"]),
      };
      this.catalogProviderRuntimeMaterials.set(providerId, material);
      return material;
    } catch (error) {
      const failed = {
        runtimeMaterialStatus: "vault_material_unavailable",
        materialSource: "unavailable",
        materialVaultRefHash: config.materialVaultRefHash ?? stableHash(vaultRef),
        errorHash: stableHash(error?.message ?? "catalog source vault resolution failed"),
        evidenceRefs: ["VaultPort.resolveVaultRef", "catalog_provider_source_material_fail_closed"],
      };
      this.catalogProviderRuntimeMaterials.set(providerId, failed);
      return failed;
    }
  }

  storageSummary() {
    const files = listModelFiles(this.modelRoot);
    const totalBytes = files.reduce((total, filePath) => total + fs.statSync(filePath).size, 0);
    const knownPaths = new Set([...this.artifacts.values()].map((artifact) => artifact.artifactPath).filter(Boolean));
    const orphanCount = files.filter((filePath) => !knownPaths.has(filePath)).length;
    const quotaBytes = Number(process.env.IOI_MODEL_STORAGE_QUOTA_BYTES ?? 0) || null;
    return {
      rootHash: stableHash(this.modelRoot),
      totalBytes,
      quotaBytes,
      quotaStatus: quotaBytes && totalBytes > quotaBytes ? "over_quota" : "ok",
      fileCount: files.length,
      orphanCount,
      destructiveActionsRequireUnload: true,
      evidenceRefs: ["model_storage_quota_boundary", "artifact_delete_unload_guard"],
    };
  }

  async catalogSearch(query = {}) {
    const searchedAt = this.nowIso();
    const text = String(query.q ?? query.query ?? "autopilot").trim().toLowerCase();
    const requestedFormat = query.format === undefined || query.format === "" ? null : String(query.format).toLowerCase();
    const requestedQuantization = query.quantization === undefined || query.quantization === "" ? null : String(query.quantization).toLowerCase();
    const limit = normalizeLimit(query.limit, 20, 100);
    const providerResults = [];
    for (const port of this.catalogProviderPorts()) {
      const result = await port.search({
        state: this,
        query: text,
        format: requestedFormat,
        quantization: requestedQuantization,
        limit,
        searchedAt,
      });
      providerResults.push({
        ...catalogProviderStatus(port, result),
        results: (Array.isArray(result.results) ? result.results : []).map((entry) => this.enrichCatalogEntry(entry)),
      });
    }
    const results = providerResults.flatMap((provider) => provider.results).slice(0, limit);
    const search = {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      searchedAt,
      query: text,
      filters: {
        format: requestedFormat,
        quantization: requestedQuantization,
        limit,
      },
      adapterBoundary: {
        port: "ModelCatalogProviderPort",
        operations: ["search", "resolveVariant", "importUrl", "download", "health"],
        evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
      },
      providers: providerResults.map(({ results: _results, ...provider }) => provider),
      results,
    };
    this.lastCatalogSearch = search;
    return search;
  }

  enrichCatalogEntry(entry, options = {}) {
    const storage = this.storageSummary();
    const artifacts = [...this.artifacts.values()];
    return enrichCatalogEntry(entry, {
      storage,
      artifacts,
      maxBytes: options.maxBytes ?? null,
    });
  }

  async searchHuggingFaceCatalog({ query, format, quantization, limit, searchedAt }) {
    const baseUrl = huggingFaceCatalogBaseUrl(this);
    const config = this.catalogProviderConfig("catalog.huggingface");
    const evidenceRefs = ["huggingface_catalog_adapter_boundary", "network_access_opt_in"];
    if (config?.enabled === false) {
      const fields = catalogProviderConfigHealthFields("catalog.huggingface", config, this.catalogProviderRuntimeMaterial("catalog.huggingface"));
      return { ...fields, status: "disabled", baseUrlHash: stableHash(baseUrl), evidenceRefs, results: [] };
    }
    if (!liveModelCatalogEnabled()) {
      return {
        ...catalogProviderConfigHealthFields("catalog.huggingface", config, this.catalogProviderRuntimeMaterial("catalog.huggingface")),
        status: "gated",
        baseUrlHash: stableHash(baseUrl),
        evidenceRefs,
        results: [],
      };
    }
    try {
      const auth = await catalogProviderAuthHeaders("catalog.huggingface", this);
      const url = new URL("/api/models", baseUrl);
      if (query) url.searchParams.set("search", query);
      url.searchParams.set("limit", String(limit));
      const response = await fetchWithTimeout(url, { timeoutMs: modelCatalogTimeoutMs(), headers: auth.headers });
      if (!response.ok) {
        return {
          status: "degraded",
          baseUrlHash: stableHash(baseUrl),
          ...catalogAuthProviderFields(auth.evidence),
          evidenceRefs: [...evidenceRefs, ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
          errorHash: stableHash(`http:${response.status}`),
          results: [],
        };
      }
      const payload = await response.json();
      const records = Array.isArray(payload) ? payload : Array.isArray(payload?.models) ? payload.models : Array.isArray(payload?.results) ? payload.results : [];
      const results = records
        .flatMap((record) => huggingFaceCatalogEntries(record, { baseUrl, searchedAt }))
        .filter((entry) => {
          if (format && entry.format !== format) return false;
          if (quantization && !String(entry.quantization ?? "").toLowerCase().includes(quantization)) return false;
          return true;
        })
        .slice(0, limit);
      return {
        status: "available",
        baseUrlHash: stableHash(baseUrl),
        ...catalogAuthProviderFields(auth.evidence),
        evidenceRefs: [...evidenceRefs, "huggingface_catalog_search", ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
        results: results.map((entry) => catalogEntryWithAuth(entry, auth.evidence)),
      };
    } catch (error) {
      return {
        status: catalogAuthFailureStatus(error),
        baseUrlHash: stableHash(baseUrl),
        evidenceRefs,
        ...catalogAuthFailureFields(error),
        errorHash: stableHash(error?.message ?? "catalog search failed"),
        results: [],
      };
    }
  }

  async catalogImportUrl(body = {}) {
    const sourceUrl = requiredString(body.source_url ?? body.sourceUrl ?? body.url, "source_url");
    const isFixture = sourceUrl.startsWith("fixture://");
    if (!isFixture && !liveModelCatalogEnabled()) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Live catalog imports are gated. Use fixture:// URLs or set IOI_LIVE_MODEL_CATALOG=1.",
        details: { sourceUrlHash: stableHash(sourceUrl), evidenceRefs: ["network_access_opt_in"] },
      });
    }
    if (!isFixture && !liveModelDownloadEnabled()) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Live catalog downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1 to materialize remote artifacts.",
        details: { sourceUrlHash: stableHash(sourceUrl), evidenceRefs: ["network_download_opt_in"] },
      });
    }
    const modelId = body.model_id ?? body.modelId ?? modelIdFromSourceUrl(sourceUrl);
    const lastCatalogEntry = this.lastCatalogSearch?.results?.find((entry) => entry.sourceUrl === sourceUrl || entry.sourceUrlHash === stableHash(sourceUrl));
    const variant = catalogVariantForSource(sourceUrl, { ...(lastCatalogEntry ?? {}), ...body });
    const receipt = this.lifecycleReceipt("model_catalog_import_url", {
      modelId,
      providerId: body.provider_id ?? body.providerId ?? "provider.autopilot.local",
      sourceUrlHash: stableHash(sourceUrl),
      sourceLabel: variant.sourceLabel,
      format: variant.format,
      quantization: variant.quantization,
      license: variant.license,
      compatibility: variant.compatibility,
      architecture: variant.architecture,
      parameterCount: variant.parameterCount,
      recommendation: variant.recommendation,
      backendCompatibility: variant.backendCompatibility,
      downloadRisk: variant.downloadRisk,
      benchmarkReadiness: variant.benchmarkReadiness,
      selectionReceiptFields: variant.selectionReceiptFields,
      catalogProviderId: variant.catalogProviderId,
      catalogAuth: publicCatalogAuthEvidence(variant.catalogAuth),
      approvalDecision: catalogApprovalDecision({ isFixture, body }),
      liveDownloadGate: isFixture ? "fixture" : "IOI_LIVE_MODEL_DOWNLOAD",
    });
    const download = await this.downloadModel({
      ...body,
      model_id: modelId,
      provider_id: body.provider_id ?? body.providerId ?? "provider.autopilot.local",
      source_url: sourceUrl,
      source_label: variant.sourceLabel,
      file_name: body.file_name ?? body.fileName ?? `${safeFileName(modelId)}.${variant.format}`,
      ...(isFixture
        ? {
            fixture_content:
              body.fixture_content ??
              body.fixtureContent ??
              [`family=${variant.family}`, `quantization=${variant.quantization}`, `context=${variant.contextWindow}`, ""].join("\n"),
          }
        : {}),
      format: variant.format,
      quantization: variant.quantization,
      family: variant.family,
      context_window: variant.contextWindow,
      license: variant.license,
      compatibility: variant.compatibility,
      architecture: variant.architecture,
      parameter_count: variant.parameterCount,
      recommendation_score: variant.recommendation?.score,
      download_risk_status: variant.downloadRisk?.status,
      backend_compatibility: variant.backendCompatibility,
      benchmark_readiness: variant.benchmarkReadiness,
      selection_receipt_fields: variant.selectionReceiptFields,
      transfer_approved: Boolean(body.transfer_approved ?? body.transferApproved ?? isFixture),
      variant_id: variant.id,
      catalog_provider_id: variant.catalogProviderId,
      catalog_receipt_id: receipt.id,
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: download.status,
      catalogReceiptId: receipt.id,
      download,
    };
  }

  importModel(body = {}) {
    const now = this.nowIso();
    const modelId = requiredString(body.model_id ?? body.modelId, "model_id");
    const sourcePath = body.path ?? body.source_path ?? body.sourcePath ?? body.local_path ?? body.localPath ?? null;
    const sourceInfo = sourcePath ? inspectLocalArtifact(sourcePath) : null;
    const importMode = normalizeImportMode(body.import_mode ?? body.importMode ?? body.mode ?? (sourceInfo ? "reference" : "operator"));
    if (importMode === "dry_run") {
      const targetPreview = sourceInfo ? importTargetPath(this.modelRoot, modelId, sourceInfo.path) : null;
      const metadata = sourceInfo ? parseLocalModelMetadata(sourceInfo.path) : {};
      const receipt = this.lifecycleReceipt("model_import_dry_run", {
        modelId,
        providerId: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
        sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
        targetPathHash: targetPreview ? stableHash(targetPreview) : null,
        importMode,
      });
      return {
        schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
        status: "dry_run",
        modelId,
        importMode,
        sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
        targetPathHash: targetPreview ? stableHash(targetPreview) : null,
        metadata,
        receiptId: receipt.id,
      };
    }
    const importedPath = sourceInfo ? materializeImportArtifact(this.modelRoot, modelId, sourceInfo.path, importMode) : null;
    const inspectedPath = importedPath ?? sourceInfo?.path ?? null;
    const importedInfo = inspectedPath ? inspectLocalArtifact(inspectedPath) : sourceInfo;
    const metadata = inspectedPath ? parseLocalModelMetadata(inspectedPath) : {};
    const artifact = {
      id: body.id ?? `import.${safeId(modelId)}`,
      providerId: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
      modelId,
      displayName: body.display_name ?? body.displayName ?? modelId,
      family: body.family ?? metadata.family ?? "imported",
      format: body.format ?? metadata.format ?? null,
      quantization: body.quantization ?? metadata.quantization ?? null,
      sizeBytes: body.size_bytes ?? body.sizeBytes ?? importedInfo?.sizeBytes ?? null,
      checksum: body.checksum ?? importedInfo?.checksum ?? null,
      contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
      capabilities: normalizeScopes(body.capabilities, ["chat"]),
      privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
      source: body.source ?? (sourceInfo ? "local_path_import" : "operator_import"),
      importMode,
      artifactPath: inspectedPath,
      metadata,
      backendRegistry: this.backendRegistry(),
      state: "installed",
      discoveredAt: now,
    };
    this.artifacts.set(artifact.id, artifact);
    this.writeMap("model-artifacts", this.artifacts);
    this.lifecycleReceipt("model_import", {
      artifactId: artifact.id,
      modelId: artifact.modelId,
      providerId: artifact.providerId,
      state: artifact.state,
      artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
      sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
      importMode,
      checksum: artifact.checksum,
    });
    this.writeProjection();
    return artifact;
  }

  mountEndpoint(body = {}) {
    const now = this.nowIso();
    const modelId = body.model_id ?? body.modelId;
    if (!modelId) {
      throw runtimeError({
        status: 400,
        code: "model_id_required",
        message: "Mounting a model endpoint requires an explicit model id.",
      });
    }
    const explicitProviderId = body.provider_id ?? body.providerId;
    const artifact = explicitProviderId ? null : this.getModel(modelId);
    const providerId = explicitProviderId ?? artifact.providerId;
    const provider = this.provider(providerId);
    const resolvedArtifact = artifact ?? this.modelForProviderMount(modelId, provider, body, now);
    const endpoint = {
      id: body.id ?? `endpoint.${safeId(providerId)}.${safeId(resolvedArtifact.modelId)}`,
      providerId,
      modelId: resolvedArtifact.modelId,
      apiFormat: body.api_format ?? body.apiFormat ?? provider.apiFormat,
      driver: body.driver ?? provider.driver ?? driverForProviderKind(provider.kind),
      baseUrl:
        body.base_url ??
        body.baseUrl ??
        provider.baseUrl ??
        ((body.driver ?? provider.driver ?? driverForProviderKind(provider.kind)) === "fixture"
          ? "local://ioi-daemon/model-fixture"
          : null),
      capabilities: normalizeScopes(body.capabilities, resolvedArtifact.capabilities),
      privacyClass: body.privacy_class ?? body.privacyClass ?? provider.privacyClass,
      artifactId: resolvedArtifact.id,
      artifactPath: resolvedArtifact.artifactPath ?? null,
      backendId: body.backend_id ?? body.backendId ?? defaultBackendForProvider(provider),
      loadPolicy: normalizeLoadPolicy(body.load_policy ?? body.loadPolicy),
      status: "mounted",
      mountedAt: now,
    };
    this.endpoints.set(endpoint.id, endpoint);
    this.writeMap("model-endpoints", this.endpoints);
    this.lifecycleReceipt("model_mount", {
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      loadPolicy: endpoint.loadPolicy,
    });
    return endpoint;
  }

  unmountEndpoint(body = {}) {
    const endpointId = requiredString(body.endpoint_id ?? body.endpointId ?? body.id, "endpoint_id");
    const endpoint = this.endpoint(endpointId);
    const updated = {
      ...endpoint,
      status: "unmounted",
      unmountedAt: this.nowIso(),
    };
    this.endpoints.set(endpointId, updated);
    this.writeMap("model-endpoints", this.endpoints);
    this.lifecycleReceipt("model_unmount", {
      endpointId,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
    });
    return updated;
  }

  async loadModel(body = {}) {
    const endpoint = this.resolveEndpoint(body.endpoint_id ?? body.endpointId, body.model_id ?? body.modelId);
    const provider = this.provider(endpoint.providerId);
    const loadPolicy = normalizeLoadPolicy(body.load_policy ?? body.loadPolicy ?? endpoint.loadPolicy);
    const runtimePreference = this.runtimePreferenceForEndpoint(endpoint);
    const requestLoadOptions = body.load_options ?? body.loadOptions ?? {};
    const runtimeDefaults = { ...this.runtimeDefaultLoadOptions(runtimePreference.selectedEngineId) };
    if ((body.load_policy ?? body.loadPolicy) && !hasExplicitTtlOption(body) && !hasExplicitTtlOption(requestLoadOptions)) {
      delete runtimeDefaults.ttlSeconds;
    }
    const loadOptions = normalizeLoadOptions(
      { ...runtimeDefaults, ...body, ...requestLoadOptions },
      loadPolicy,
    );
    if (loadOptions.ttlSeconds !== null) loadPolicy.idleTtlSeconds = loadOptions.ttlSeconds;
    const estimate = this.loadEstimate(endpoint, loadOptions, runtimePreference);
    if (loadOptions.estimateOnly) {
      const receipt = this.lifecycleReceipt("model_load_estimate", {
        endpointId: endpoint.id,
        modelId: endpoint.modelId,
        providerId: endpoint.providerId,
        backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
        runtimeEngineId: runtimePreference.selectedEngineId,
        runtimeEngineProfile: this.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null,
        loadPolicy,
        loadOptions,
        estimate,
      });
      return {
        schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
        status: "estimate_only",
        endpointId: endpoint.id,
        modelId: endpoint.modelId,
        providerId: endpoint.providerId,
        backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
        runtimeEngineId: runtimePreference.selectedEngineId,
        runtimeEngineProfile: this.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null,
        loadPolicy,
        loadOptions,
        estimate,
        receiptId: receipt.id,
      };
    }
    const driverResult = await this.driverForProvider(provider).load({
      state: this,
      provider,
      endpoint,
      body: { ...body, loadOptions, load_policy: loadPolicy },
    });
    const now = this.nowIso();
    const instance = {
      id: body.id ?? `instance.${safeId(endpoint.id)}.${Date.now()}`,
      endpointId: endpoint.id,
      providerId: endpoint.providerId,
      modelId: endpoint.modelId,
      status: "loaded",
      backend: driverResult.backend ?? endpoint.apiFormat,
      backendId: driverResult.backendId ?? endpoint.backendId ?? defaultBackendForProvider(provider),
      driver: driverNameForProvider(provider),
      loadPolicy,
      loadOptions,
      runtimeEngineId: runtimePreference.selectedEngineId,
      runtimeEngineProfile: this.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null,
      identifier: loadOptions.identifier ?? null,
      contextLength: loadOptions.contextLength ?? endpoint.contextWindow ?? null,
      parallelism: loadOptions.parallel ?? null,
      gpuOffload: loadOptions.gpu ?? null,
      estimate: driverResult.estimate ?? estimate,
      backendProcess: driverResult.process ?? null,
      backendProcessId: driverResult.process?.id ?? null,
      backendProcessPidHash: driverResult.process?.pidHash ?? null,
      loadedAt: now,
      lastUsedAt: now,
      expiresAt: expiresAt(now, loadPolicy),
      workflowScope: body.workflow_scope ?? body.workflowScope ?? null,
      agentScope: body.agent_scope ?? body.agentScope ?? null,
      providerEvidenceRefs: driverResult.evidenceRefs ?? [],
    };
    this.instances.set(instance.id, instance);
    this.supersedeLoadedInstances(endpoint.id, instance.id);
    this.writeMap("model-instances", this.instances);
    this.lifecycleReceipt("model_load", {
      instanceId: instance.id,
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      backendId: instance.backendId,
      runtimeEngineId: runtimePreference.selectedEngineId,
      loadPolicy,
      loadOptions,
      estimate: instance.estimate,
      providerEvidenceRefs: driverResult.evidenceRefs ?? [],
      backendProcess: driverResult.process ?? null,
      commandArgsHash: driverResult.commandArgsHash ?? null,
    });
    return instance;
  }

  loadEstimate(endpoint, loadOptions = {}, runtimePreference = this.runtimePreference()) {
    const provider = this.provider(endpoint.providerId);
    const artifact = this.getModel(endpoint.modelId);
    const nativeEstimate = estimateNativeLocalResources({
      ...artifact,
      contextWindow: loadOptions.contextLength ?? artifact.contextWindow,
    });
    return {
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
      runtimeEngineId: runtimePreference.selectedEngineId,
      contextLength: loadOptions.contextLength ?? nativeEstimate.contextWindow,
      parallelism: loadOptions.parallel ?? 1,
      gpuOffload: loadOptions.gpu ?? "auto",
      identifier: loadOptions.identifier ?? null,
      estimatedVramBytes: nativeEstimate.estimatedVramBytes,
      estimatedSizeBytes: nativeEstimate.sizeBytes,
      realInference: provider.kind !== "ioi_native_local" ? null : nativeEstimate.realInference,
      evidenceRefs: ["model_load_option_estimate", "runtime_engine_preference"],
    };
  }

  async unloadModel(body = {}) {
    const instanceId = body.instance_id ?? body.instanceId ?? body.id;
    const instance = instanceId
      ? this.instance(instanceId)
      : this.loadedInstanceForEndpoint(this.resolveEndpoint(body.endpoint_id ?? body.endpointId, body.model_id ?? body.modelId).id);
    const endpoint = this.endpoint(instance.endpointId);
    const provider = this.provider(instance.providerId);
    const driverResult = await this.driverForProvider(provider).unload({ state: this, provider, endpoint, instance, body });
    const updated = {
      ...instance,
      status: "unloaded",
      unloadedAt: this.nowIso(),
      providerEvidenceRefs: driverResult.evidenceRefs ?? instance.providerEvidenceRefs ?? [],
    };
    this.instances.set(instance.id, updated);
    this.writeMap("model-instances", this.instances);
    this.lifecycleReceipt("model_unload", {
      instanceId: instance.id,
      endpointId: instance.endpointId,
      modelId: instance.modelId,
      providerId: instance.providerId,
      providerEvidenceRefs: driverResult.evidenceRefs ?? [],
      backendProcess: driverResult.process ?? null,
    });
    return updated;
  }

  async downloadModel(body = {}) {
    const now = this.nowIso();
    const modelId = requiredString(body.model_id ?? body.modelId, "model_id");
    const providerId = body.provider_id ?? body.providerId ?? "provider.autopilot.local";
    const source = body.source_url ?? body.sourceUrl ?? body.source ?? "deterministic_fixture_download";
    const isFixture = String(source).startsWith("fixture://") || source === "deterministic_fixture_download";
    if (!isFixture && !liveModelDownloadEnabled()) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Live model downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1.",
        details: { sourceUrlHash: stableHash(source), evidenceRefs: ["network_download_opt_in"] },
      });
    }
    const sourceLabel = body.source_label ?? body.sourceLabel ?? sourceLabelForUrl(source);
    const variantMetadata = catalogVariantForSource(source, body);
    const catalogProviderId = body.catalog_provider_id ?? body.catalogProviderId ?? variantMetadata.catalogProviderId ?? null;
    const catalogAuth = !isFixture && catalogProviderId
      ? await catalogProviderAuthHeaders(catalogProviderId, this)
      : { headers: {}, evidence: null };
    const catalogAuthReceipt = publicCatalogAuthEvidence(catalogAuth.evidence);
    const targetDir = path.join(this.modelRoot, "downloads", safeFileName(modelId));
    const targetPath = path.join(targetDir, body.file_name ?? body.fileName ?? `${safeFileName(modelId)}.gguf`);
    const fixtureContent = String(body.fixture_content ?? body.fixtureContent ?? `deterministic model bytes for ${modelId}\n`);
    const bytesTotal = Number(body.bytes_total ?? body.bytesTotal ?? (isFixture ? Buffer.byteLength(fixtureContent) : 0));
    const maxBytes = normalizeOptionalBytes(body.max_bytes ?? body.maxBytes ?? process.env.IOI_MODEL_DOWNLOAD_MAX_BYTES);
    const downloadPolicy = normalizeDownloadPolicy(body, { isFixture, maxBytes, source });
    assertDownloadPolicyAllowed(downloadPolicy, source);
    const jobBase = {
      id: `download_job_${crypto.randomUUID()}`,
      modelId,
      providerId,
      source: publicDownloadSource(source),
      sourceHash: stableHash(source),
      sourceUrlHash: stableHash(source),
      sourceLabel,
      variant: variantMetadata,
      targetPath,
      targetPathHash: stableHash(targetPath),
      bytesTotal,
      bytesCompleted: 0,
      progress: 0,
      maxBytes,
      downloadPolicy,
      bandwidthLimitBps: downloadPolicy.bandwidthLimitBps,
      retryLimit: downloadPolicy.retryLimit,
      resumeDownload: downloadPolicy.resume,
      createdAt: now,
      updatedAt: now,
      receiptIds: [],
      receiptId: null,
    };
    const queuedReceipt = this.lifecycleReceipt("model_download_queued", {
      jobId: jobBase.id,
      modelId,
      providerId,
      sourceHash: stableHash(source),
      sourceLabel,
      variant: variantMetadata,
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
      recommendation: variantMetadata.recommendation,
      backendCompatibility: variantMetadata.backendCompatibility,
      downloadRisk: variantMetadata.downloadRisk,
      benchmarkReadiness: variantMetadata.benchmarkReadiness,
      selectionReceiptFields: variantMetadata.selectionReceiptFields,
      approvalDecision: downloadPolicy.approvalDecision,
      downloadPolicy,
      targetPathHash: stableHash(targetPath),
      maxBytes,
      downloadMode: isFixture ? "fixture" : "live_network",
    });
    if (truthy(body.fail ?? body.simulate_failure ?? body.simulateFailure)) {
      const failed = {
        ...jobBase,
        artifactId: null,
        status: "failed",
        failureReason: body.failure_reason ?? body.failureReason ?? "deterministic_fixture_failure",
        updatedAt: this.nowIso(),
        receiptIds: [queuedReceipt.id],
        receiptId: queuedReceipt.id,
      };
      const failedReceipt = this.lifecycleReceipt("model_download_failed", {
        jobId: failed.id,
        modelId,
        providerId,
        failureReason: failed.failureReason,
        downloadPolicy,
      });
      const storedFailed = { ...failed, receiptIds: [...failed.receiptIds, failedReceipt.id], receiptId: failedReceipt.id };
      this.downloads.set(storedFailed.id, storedFailed);
      this.writeMap("model-downloads", this.downloads);
      this.writeProjection();
      return storedFailed;
    }
    if (truthy(body.queued_only ?? body.queuedOnly)) {
      const queued = {
        ...jobBase,
        artifactId: null,
        status: "queued",
        receiptIds: [queuedReceipt.id],
        receiptId: queuedReceipt.id,
      };
      this.downloads.set(queued.id, queued);
      this.writeMap("model-downloads", this.downloads);
      this.writeProjection();
      return queued;
    }
    fs.mkdirSync(targetDir, { recursive: true });
    const runningReceipt = this.lifecycleReceipt("model_download_running", {
      jobId: jobBase.id,
      modelId,
      providerId,
      bytesTotal,
      bytesCompleted: 0,
      maxBytes,
      sourceHash: stableHash(source),
      sourceLabel,
      downloadMode: isFixture ? "fixture" : "live_network",
      downloadPolicy,
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
    });
    const transferReceiptIds = [];
    const recordTransferEvent = (operation, details = {}) => {
      const receipt = this.lifecycleReceipt(operation, {
        jobId: jobBase.id,
        modelId,
        providerId,
        sourceHash: stableHash(source),
        sourceLabel,
        targetPathHash: stableHash(targetPath),
        downloadMode: isFixture ? "fixture" : "live_network",
        downloadPolicy,
        catalogProviderId,
        catalogAuth: catalogAuthReceipt,
        ...details,
      });
      transferReceiptIds.push(receipt.id);
      return receipt;
    };
    let materialized;
    try {
      materialized = isFixture
        ? materializeFixtureDownload({ targetPath, fixtureContent })
        : await materializeLiveDownload({
            source,
            targetPath,
            expectedChecksum: body.checksum ?? body.expected_checksum ?? body.expectedChecksum ?? null,
            maxBytes,
            resume: downloadPolicy.resume,
            bandwidthLimitBps: downloadPolicy.bandwidthLimitBps,
            retryLimit: downloadPolicy.retryLimit,
            timeoutMs: modelDownloadTimeoutMs(),
            headers: catalogAuth.headers,
            onTransferEvent: recordTransferEvent,
          });
    } catch (error) {
      const failureReason = downloadFailureReason(error);
      const transfer = error?.downloadTransfer ?? null;
      const cleanupState = failedDownloadCleanupState(targetPath, {
        retainPartial: shouldRetainFailedDownloadPartial(downloadPolicy, failureReason),
      });
      const failedReceipt = this.lifecycleReceipt("model_download_failed", {
        jobId: jobBase.id,
        modelId,
        providerId,
        failureReason,
        sourceHash: stableHash(source),
        sourceLabel,
        errorHash: stableHash(error?.message ?? "download failed"),
        cleanupState,
        transfer,
        catalogProviderId,
        catalogAuth: catalogAuthReceipt,
        attemptCount: transfer?.attemptCount ?? null,
        retryCount: transfer?.retryCount ?? null,
        resumeMetadataPathHash: transfer?.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
        downloadPolicy,
      });
      const failed = {
        ...jobBase,
        artifactId: null,
        status: "failed",
        failureReason,
        cleanupState,
        transfer,
        attemptCount: transfer?.attemptCount ?? null,
        retryCount: transfer?.retryCount ?? null,
        resumeMetadataPathHash: transfer?.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
        updatedAt: this.nowIso(),
        receiptIds: [queuedReceipt.id, runningReceipt.id, ...transferReceiptIds, failedReceipt.id],
        receiptId: failedReceipt.id,
      };
      this.downloads.set(failed.id, failed);
      this.writeMap("model-downloads", this.downloads);
      this.writeProjection();
      return failed;
    }
    const checksum = materialized.checksum;
    const completedBytes = materialized.bytesCompleted;
    const metadata = parseLocalModelMetadata(targetPath);
    const artifact = this.artifacts.get(`download.${safeId(modelId)}`) ?? {
      id: `download.${safeId(modelId)}`,
      providerId,
      modelId,
      displayName: body.display_name ?? body.displayName ?? modelId,
      family: body.family ?? metadata.family ?? "download",
      format: body.format ?? variantMetadata.format ?? metadata.format ?? "gguf",
      quantization: body.quantization ?? variantMetadata.quantization ?? metadata.quantization ?? null,
      sizeBytes: completedBytes,
      checksum,
      contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
      capabilities: normalizeScopes(body.capabilities, ["chat"]),
      privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
      source: publicDownloadSource(source),
      sourceLabel,
      sourceUrlHash: stableHash(source),
      license: body.license ?? variantMetadata.license ?? null,
      compatibility: body.compatibility ?? variantMetadata.compatibility ?? [],
      artifactPath: targetPath,
      metadata,
      state: "installed",
      discoveredAt: now,
    };
    const job = {
      ...jobBase,
      artifactId: artifact.id,
      status: "completed",
      checksum,
      progress: 1,
      bytesTotal: materialized.bytesTotal || completedBytes,
      bytesCompleted: completedBytes,
      resumeOffset: materialized.resumeOffset ?? 0,
      attemptCount: materialized.attemptCount ?? 1,
      retryCount: materialized.retryCount ?? 0,
      resumeMetadataPathHash: materialized.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
      transfer: materialized.transfer ?? null,
      updatedAt: this.nowIso(),
      receiptIds: [queuedReceipt.id, runningReceipt.id, ...transferReceiptIds],
      receiptId: runningReceipt.id,
    };
    this.artifacts.set(artifact.id, artifact);
    this.downloads.set(job.id, job);
    const receipt = this.lifecycleReceipt("model_download_completed", {
      jobId: job.id,
      artifactId: artifact.id,
      modelId,
      providerId: artifact.providerId,
      bytesTotal: materialized.bytesTotal || completedBytes,
      bytesCompleted: completedBytes,
      maxBytes,
      checksum,
      sourceHash: stableHash(source),
      sourceLabel,
      variant: variantMetadata,
      recommendation: variantMetadata.recommendation,
      backendCompatibility: variantMetadata.backendCompatibility,
      downloadRisk: variantMetadata.downloadRisk,
      benchmarkReadiness: variantMetadata.benchmarkReadiness,
      selectionReceiptFields: variantMetadata.selectionReceiptFields,
      approvalDecision: downloadPolicy.approvalDecision,
      downloadPolicy,
      resumeOffset: materialized.resumeOffset ?? 0,
      attemptCount: materialized.attemptCount ?? 1,
      retryCount: materialized.retryCount ?? 0,
      resumeMetadataPathHash: materialized.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
      transfer: materialized.transfer ?? null,
      downloadMode: isFixture ? "fixture" : "live_network",
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
    });
    const completed = { ...job, receiptId: receipt.id, receiptIds: [...job.receiptIds, receipt.id] };
    this.downloads.set(completed.id, completed);
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-downloads", this.downloads);
    this.writeProjection();
    return completed;
  }

  cancelDownload(jobId, body = {}) {
    const job = this.downloadStatus(jobId);
    if (["completed", "failed", "canceled"].includes(job.status)) {
      return job;
    }
    const cleanupPartial = truthy(body.cleanup_partial ?? body.cleanupPartial ?? true);
    const destructiveConfirmation = destructiveConfirmationState(body, { required: cleanupPartial, action: "download_cancel_cleanup" });
    const partialPath = job.targetPath ? `${job.targetPath}.part` : null;
    const metadataPath = partialPath ? `${partialPath}.json` : null;
    const projectedFreedBytes = cleanupPartial
      ? fileSizeIfExists(job.targetPath) + fileSizeIfExists(partialPath) + fileSizeIfExists(metadataPath)
      : 0;
    let cleanupState = cleanupPartial ? "not_needed" : "retained_partial";
    if (cleanupPartial && job.targetPath) {
      cleanupState = cleanupPartialDownload(job.targetPath);
    }
    const receipt = this.lifecycleReceipt("model_download_canceled", {
      jobId,
      modelId: job.modelId,
      providerId: job.providerId,
      bytesCompleted: job.bytesCompleted,
      bytesTotal: job.bytesTotal,
      cleanupPartial,
      cleanupState,
      projectedFreedBytes,
      destructiveConfirmation,
      downloadPolicy: job.downloadPolicy ?? null,
    });
    const canceled = {
      ...job,
      status: "canceled",
      cleanupState,
      projectedFreedBytes,
      destructiveConfirmation,
      updatedAt: this.nowIso(),
      receiptId: receipt.id,
      receiptIds: [...(job.receiptIds ?? []), receipt.id],
    };
    this.downloads.set(jobId, canceled);
    this.writeMap("model-downloads", this.downloads);
    this.writeProjection();
    return canceled;
  }

  downloadStatus(jobId) {
    const job = this.downloads.get(jobId);
    if (!job) throw notFound(`Download job not found: ${jobId}`, { jobId });
    return job;
  }

  deleteModelArtifact(id, body = {}) {
    const artifact = this.getModel(id);
    const endpointIds = [...this.endpoints.values()].filter((endpoint) => endpoint.artifactId === artifact.id).map((endpoint) => endpoint.id);
    const instanceIds = [...this.instances.values()]
      .filter((instance) => endpointIds.includes(instance.endpointId) && instance.status === "loaded")
      .map((instance) => instance.id);
    const projectedFreedBytes = fileSizeIfExists(artifact.artifactPath);
    const destructiveConfirmation = destructiveConfirmationState(body, { required: projectedFreedBytes > 0 || endpointIds.length > 0, action: "model_artifact_delete" });
    if (truthy(body.dry_run ?? body.dryRun)) {
      const receipt = this.lifecycleReceipt("model_artifact_delete_dry_run", {
        artifactId: artifact.id,
        modelId: artifact.modelId,
        providerId: artifact.providerId,
        artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
        affectedEndpointIds: endpointIds,
        affectedInstanceIds: instanceIds,
        projectedFreedBytes,
        destructiveConfirmation,
      });
      return {
        schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
        status: "dry_run",
        artifactId: artifact.id,
        modelId: artifact.modelId,
        affectedEndpointIds: endpointIds,
        affectedInstanceIds: instanceIds,
        projectedFreedBytes,
        destructiveConfirmation,
        receiptId: receipt.id,
      };
    }
    if (instanceIds.length > 0) {
      throw runtimeError({
        status: 409,
        code: "conflict",
        message: "Model artifact is loaded. Unload linked instances before deleting it.",
        details: { artifactId: artifact.id, instanceIds },
      });
    }
    for (const endpointId of endpointIds) {
      const endpoint = this.endpoints.get(endpointId);
      this.endpoints.set(endpointId, { ...endpoint, status: "deleted_with_artifact", deletedAt: this.nowIso() });
    }
    this.artifacts.delete(artifact.id);
    fs.rmSync(path.join(this.stateDir, "model-artifacts", `${safeFileName(artifact.id)}.json`), { force: true });
    let cleanupState = "not_applicable";
    if (artifact.artifactPath && artifact.artifactPath.startsWith(this.modelRoot)) {
      try {
        fs.rmSync(artifact.artifactPath, { force: true });
        cleanupState = "removed";
      } catch {
        cleanupState = "failed";
      }
    }
    const receipt = this.lifecycleReceipt("model_artifact_delete", {
      artifactId: artifact.id,
      modelId: artifact.modelId,
      providerId: artifact.providerId,
      artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
      endpointIds,
      affectedEndpointIds: endpointIds,
      affectedInstanceIds: instanceIds,
      projectedFreedBytes,
      cleanupState,
      destructiveConfirmation,
    });
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-endpoints", this.endpoints);
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: "deleted",
      artifactId: artifact.id,
      modelId: artifact.modelId,
      cleanupState,
      affectedEndpointIds: endpointIds,
      affectedInstanceIds: instanceIds,
      projectedFreedBytes,
      destructiveConfirmation,
      receiptId: receipt.id,
    };
  }

  cleanupModelStorage(body = {}) {
    const knownPaths = new Set([...this.artifacts.values()].map((artifact) => artifact.artifactPath).filter(Boolean));
    const files = listModelFiles(this.modelRoot);
    const orphans = files.filter((filePath) => !knownPaths.has(filePath));
    const orphanBytes = orphans.reduce((total, filePath) => total + fileSizeIfExists(filePath), 0);
    const removeOrphans = truthy(body.remove_orphans ?? body.removeOrphans ?? false);
    const destructiveConfirmation = destructiveConfirmationState(body, { required: removeOrphans && orphans.length > 0, action: "model_storage_cleanup" });
    if (removeOrphans && destructiveConfirmation.required && !destructiveConfirmation.confirmed) {
      throw runtimeError({
        status: 409,
        code: "destructive_confirmation_required",
        message: "Confirm destructive cleanup before removing orphan model files.",
        details: { orphanCount: orphans.length, projectedFreedBytes: orphanBytes },
      });
    }
    let cleanupState = "scan_only";
    let cleanedBytes = 0;
    let removedOrphanCount = 0;
    if (removeOrphans) {
      cleanupState = "removed_orphans";
      for (const orphan of orphans) {
        const size = fileSizeIfExists(orphan);
        try {
          fs.rmSync(orphan, { force: true });
          cleanedBytes += size;
          removedOrphanCount += 1;
        } catch {
          cleanupState = "partial_cleanup_failed";
        }
      }
    }
    const receipt = this.lifecycleReceipt("model_storage_cleanup", {
      modelId: "model-storage",
      scannedFileCount: files.length,
      orphanCount: orphans.length,
      orphanPathHashes: orphans.map((filePath) => stableHash(filePath)),
      orphanBytes,
      removeOrphans,
      cleanedBytes,
      removedOrphanCount,
      projectedFreedBytes: orphanBytes,
      cleanupState,
      destructiveConfirmation,
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: removeOrphans ? "cleaned" : "scanned",
      scannedFileCount: files.length,
      orphanCount: orphans.length,
      orphanBytes,
      removeOrphans,
      cleanedBytes,
      removedOrphanCount,
      projectedFreedBytes: orphanBytes,
      cleanupState,
      destructiveConfirmation,
      receiptId: receipt.id,
    };
  }

  bindVaultRef(body = {}) {
    const vaultRef = requiredString(body.vault_ref ?? body.vaultRef, "vault_ref");
    const material = requiredString(body.material ?? body.secret ?? body.value, "material");
    const metadata = this.vault.bindVaultRef({
      vaultRef,
      material,
      purpose: body.purpose ?? "operator_provider_auth_binding",
      label: body.label ?? null,
    });
    this.writeVaultRefs();
    const receipt = this.receipt("vault_ref_binding", {
      summary: `Vault material bound for ${metadata.vaultRefHash}.`,
      redaction: "redacted",
      evidenceRefs: ["VaultPort.bindVaultRef", metadata.vaultRefHash],
      details: metadata,
    });
    this.writeProjection();
    return { ...metadata, receiptId: receipt.id };
  }

  listVaultRefs() {
    return this.vault.listVaultRefs();
  }

  vaultRefMetadata(body = {}) {
    const vaultRef = requiredString(body.vault_ref ?? body.vaultRef, "vault_ref");
    return this.vault.vaultRefMetadata(vaultRef);
  }

  vaultStatus() {
    return this.vault.adapterStatus();
  }

  vaultHealth() {
    const health = this.vault.health();
    const receipt = this.receipt("vault_adapter_health", {
      summary: `Vault adapter health is ${health.status}.`,
      redaction: "redacted",
      evidenceRefs: health.evidenceRefs,
      details: health,
    });
    return { ...health, receiptId: receipt.id };
  }

  removeVaultRef(body = {}) {
    const vaultRef = requiredString(body.vault_ref ?? body.vaultRef, "vault_ref");
    const metadata = this.vault.removeVaultRef(vaultRef, body.purpose ?? "operator_provider_auth_remove");
    this.writeVaultRefs();
    const receipt = this.receipt("vault_ref_removal", {
      summary: `Vault material removed for ${metadata.vaultRefHash}.`,
      redaction: "redacted",
      evidenceRefs: ["VaultPort.removeVaultRef", metadata.vaultRefHash],
      details: metadata,
    });
    this.writeProjection();
    return { ...metadata, receiptId: receipt.id };
  }

  createToken(body = {}) {
    const now = this.nowIso();
    const tokenValue = `ioi_mnt_${crypto.randomBytes(24).toString("base64url")}`;
    const token = this.walletAuthority.createGrant({
      id: `grant_${crypto.randomUUID()}`,
      audience: body.audience ?? "autopilot-local-server",
      allowed: normalizeScopes(body.allowed, [
        "model.chat:*",
        "model.responses:*",
        "model.embeddings:*",
        "model.tokenize:*",
        "model.context:*",
        "route.use:*",
      ]),
      denied: normalizeScopes(body.denied, ["connector.gmail.send", "filesystem.write", "shell.exec"]),
      expiresAt: body.expires_at ?? body.expiresAt ?? new Date(this.now().getTime() + 24 * 60 * 60 * 1000).toISOString(),
      revocationEpoch: Number(body.revocation_epoch ?? body.revocationEpoch ?? 0),
      grantId: body.grant_id ?? body.grantId ?? `wallet.grant.${crypto.randomUUID()}`,
      vaultRefs: sanitizeVaultRefs(body.vault_refs ?? body.vaultRefs ?? {}),
      auditReceiptIds: [],
      tokenHash: hashToken(tokenValue),
      createdAt: now,
      lastUsedAt: null,
      lastUsedScope: null,
      revokedAt: null,
      receiptId: null,
    });
    const receipt = this.receipt("permission_token", {
      summary: `Capability token ${token.id} created for ${token.audience}.`,
      redaction: "redacted",
      evidenceRefs: ["wallet.network.capability_grant", token.grantId],
      details: publicToken(token),
    });
    const stored = { ...token, receiptId: receipt.id };
    this.tokens.set(stored.id, stored);
    this.writeMap("tokens", this.tokens);
    return { ...publicToken(stored), token: tokenValue };
  }

  listTokens() {
    return [...this.tokens.values()]
      .map(publicToken)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  revokeToken(tokenId) {
    const token = this.tokens.get(tokenId);
    if (!token) throw notFound(`Token not found: ${tokenId}`, { tokenId });
    const revoked = this.walletAuthority.revokeGrant(token);
    this.tokens.set(tokenId, revoked);
    this.writeMap("tokens", this.tokens);
    this.receipt("permission_token_revocation", {
      summary: `Capability token ${tokenId} revoked.`,
      redaction: "redacted",
      evidenceRefs: ["wallet.network.revocation", token.grantId],
      details: publicToken(revoked),
    });
    return publicToken(revoked);
  }

  authorize(authorization, requiredScope) {
    if (!authorization || !authorization.startsWith("Bearer ")) {
      throw runtimeError({
        status: 401,
        code: "auth",
        message: "Bearer capability token is required for this model mounting operation.",
        details: { requiredScope },
      });
    }
    const tokenHash = hashToken(authorization.slice("Bearer ".length).trim());
    const token = [...this.tokens.values()].find((candidate) => candidate.tokenHash === tokenHash);
    if (!token) {
      throw runtimeError({
        status: 401,
        code: "auth",
        message: "Capability token was not recognized.",
        details: { requiredScope },
      });
    }
    const authorized = this.walletAuthority.authorizeScope(token, requiredScope);
    this.tokens.set(authorized.id, authorized);
    this.writeMap("tokens", this.tokens);
    return authorized;
  }

  upsertProvider(body = {}) {
    const checkedAt = this.nowIso();
    const id = body.id ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
    const existing = this.providers.get(id) ?? {};
    const kind = body.kind ?? existing.kind ?? "custom_http";
    const secretRef = this.normalizeProviderSecretRef(kind, body, existing.secretRef ?? null);
    const authScheme = normalizeProviderAuthScheme(body.auth_scheme ?? body.authScheme ?? existing.authScheme);
    const authHeaderName = normalizeProviderAuthHeaderName(
      body.auth_header_name ?? body.authHeaderName ?? existing.authHeaderName,
    );
    const requestedStatus = body.status ?? existing.status ?? "configured";
    const provider = {
      id,
      kind,
      label: body.label ?? existing.label ?? id,
      apiFormat: body.api_format ?? body.apiFormat ?? existing.apiFormat ?? "custom",
      driver: body.driver ?? existing.driver ?? driverForProviderKind(kind),
      baseUrl: body.base_url ?? body.baseUrl ?? existing.baseUrl ?? null,
      status: providerRequiresVaultSecret(kind) && !secretRef ? "blocked" : requestedStatus,
      privacyClass: body.privacy_class ?? body.privacyClass ?? existing.privacyClass ?? "workspace",
      capabilities: normalizeScopes(body.capabilities, existing.capabilities ?? ["chat"]),
      discovery: {
        ...existing.discovery,
        checkedAt,
        evidenceRefs: normalizeScopes(body.evidence_refs ?? body.evidenceRefs, existing.discovery?.evidenceRefs ?? ["operator_provider_config"]),
      },
      secretRef,
      authScheme,
      authHeaderName,
    };
    this.providers.set(provider.id, provider);
    this.writeMap("model-providers", this.providers);
    return publicProvider(provider);
  }

  normalizeProviderSecretRef(kind, body = {}, existingSecretRef = null) {
    assertNoPlaintextProviderSecret(body);
    const secretRef = providerSecretInput(body);
    const normalized = secretRef === undefined ? existingSecretRef : secretRef || null;
    if (normalized) this.walletAuthority.resolveVaultRef(normalized);
    if (providerRequiresVaultSecret(kind) && !normalized) return null;
    return normalized;
  }

  async providerHealth(providerId) {
    const provider = this.provider(providerId);
    const checkedAt = this.nowIso();
    try {
      const driverResult = await this.driverForProvider(provider).health(provider, { state: this });
      const status = driverResult.status ?? (provider.status === "configured" ? "available" : provider.status);
      const receipt = this.receipt("provider_health", {
        summary: `Provider ${providerId} health is ${status}.`,
        redaction: "redacted",
        evidenceRefs: driverResult.evidenceRefs ?? provider.discovery?.evidenceRefs ?? [],
        details: {
          providerId,
          providerKind: provider.kind,
          status,
          httpStatus: driverResult.httpStatus ?? null,
          authVaultRefHash: driverResult.authEvidence?.vaultRefHash ?? null,
          providerAuthEvidenceRefs: driverResult.authEvidence?.evidenceRefs ?? [],
          providerAuthHeaderNames: driverResult.authEvidence?.headerNames ?? [],
        },
      });
      const updated = {
        ...provider,
        status,
        discovery: {
          ...provider.discovery,
          checkedAt,
          lastHealthCheck: {
            status,
            evidenceRefs: driverResult.evidenceRefs ?? provider.discovery?.evidenceRefs ?? [],
            httpStatus: driverResult.httpStatus ?? null,
            authVaultRefHash: driverResult.authEvidence?.vaultRefHash ?? null,
            receiptId: receipt.id,
          },
          ...(driverResult.publicCli ? { publicCli: driverResult.publicCli } : {}),
        },
      };
      this.providers.set(providerId, updated);
      this.writeMap("model-providers", this.providers);
      writeJson(path.join(this.stateDir, "provider-health", `${safeFileName(providerId)}.json`), {
        id: `health.${safeId(providerId)}`,
        providerId,
        status,
        checkedAt,
        receiptId: receipt.id,
        evidenceRefs: driverResult.evidenceRefs ?? [],
      });
      this.writeProjection();
      return publicProvider(updated, providerHasVaultRef(updated) ? this.vault.vaultRefMetadata(updated.secretRef) : null);
    } catch (error) {
      const status = providerHealthFailureStatus(error);
      const failureDetails = error?.details && typeof error.details === "object" ? error.details : {};
      const evidenceRefs = normalizeScopes(failureDetails.evidenceRefs, [`provider_health_${error?.code ?? "runtime_error"}`]);
      const receipt = this.receipt("provider_health", {
        summary: `Provider ${providerId} health failed closed as ${status}.`,
        redaction: "redacted",
        evidenceRefs,
        details: {
          providerId,
          providerKind: provider.kind,
          status,
          failureCode: error?.code ?? "runtime",
          failureStatus: error?.status ?? 500,
          httpStatus: failureDetails.httpStatus ?? null,
          providerErrorHash: failureDetails.providerErrorHash ?? null,
          vaultRefConfigured: failureDetails.vaultRefConfigured ?? providerHasVaultRef(provider),
          authVaultRefHash: failureDetails.vaultRefHash ?? null,
          resolvedMaterial: failureDetails.resolvedMaterial ?? null,
        },
      });
      const updated = {
        ...provider,
        status,
        discovery: {
          ...provider.discovery,
          checkedAt,
          lastHealthCheck: {
            status,
            evidenceRefs,
            httpStatus: failureDetails.httpStatus ?? null,
            authVaultRefHash: failureDetails.vaultRefHash ?? null,
            failureCode: error?.code ?? "runtime",
            failureStatus: error?.status ?? 500,
            resolvedMaterial: failureDetails.resolvedMaterial ?? null,
            receiptId: receipt.id,
          },
        },
      };
      this.providers.set(providerId, updated);
      this.writeMap("model-providers", this.providers);
      writeJson(path.join(this.stateDir, "provider-health", `${safeFileName(providerId)}.json`), {
        id: `health.${safeId(providerId)}`,
        providerId,
        status,
        checkedAt,
        receiptId: receipt.id,
        failureCode: error?.code ?? "runtime",
        failureStatus: error?.status ?? 500,
        evidenceRefs,
      });
      this.writeProjection();
      error.details = {
        ...failureDetails,
        providerHealthStatus: status,
        providerHealthReceiptId: receipt.id,
      };
      throw error;
    }
  }

  async listProviderModels(providerId) {
    const provider = this.provider(providerId);
    const models = await this.driverForProvider(provider).listModels({ state: this, provider });
    for (const artifact of models) {
      this.artifacts.set(artifact.id, artifact);
    }
    if (models.length > 0) this.writeMap("model-artifacts", this.artifacts);
    const resolved = models.length > 0
      ? models
      : this.listArtifacts().filter((artifact) => artifact.providerId === providerId);
    this.lifecycleReceipt("provider_models_list", {
      providerId,
      modelId: provider.label,
      state: provider.status,
      modelCount: resolved.length,
      evidenceRefs: provider.discovery?.evidenceRefs ?? [],
    });
    return resolved;
  }

  async listProviderLoaded(providerId) {
    const provider = this.provider(providerId);
    const loaded = await this.driverForProvider(provider).listLoaded({ state: this, provider });
    const resolved = loaded.length > 0
      ? loaded
      : this.listInstances().filter((instance) => instance.providerId === providerId && instance.status === "loaded");
    this.lifecycleReceipt("provider_loaded_list", {
      providerId,
      modelId: provider.label,
      state: provider.status,
      loadedCount: resolved.length,
      evidenceRefs: provider.discovery?.evidenceRefs ?? [],
    });
    return resolved;
  }

  async startProvider(providerId) {
    const provider = this.provider(providerId);
    const driver = this.driverForProvider(provider);
    const result = typeof driver.start === "function"
      ? await driver.start({ state: this, provider })
      : { status: provider.status === "blocked" ? "blocked" : "available", evidenceRefs: ["provider_stateless_start"] };
    const updated = {
      ...provider,
      status: result.status ?? "available",
      discovery: {
        ...provider.discovery,
        checkedAt: this.nowIso(),
        lastStart: {
          status: result.status ?? "available",
          evidenceRefs: result.evidenceRefs ?? [],
        },
      },
    };
    this.providers.set(providerId, updated);
    this.writeMap("model-providers", this.providers);
    this.lifecycleReceipt("provider_start", {
      providerId,
      modelId: provider.label,
      state: updated.status,
      evidenceRefs: result.evidenceRefs ?? [],
    });
    return publicProvider(updated);
  }

  async stopProvider(providerId) {
    const provider = this.provider(providerId);
    const driver = this.driverForProvider(provider);
    const result = typeof driver.stop === "function"
      ? await driver.stop({ state: this, provider })
      : { status: "stopped", evidenceRefs: ["provider_stateless_stop"] };
    const updated = {
      ...provider,
      status: result.status ?? "stopped",
      discovery: {
        ...provider.discovery,
        checkedAt: this.nowIso(),
        lastStop: {
          status: result.status ?? "stopped",
          evidenceRefs: result.evidenceRefs ?? [],
        },
      },
    };
    this.providers.set(providerId, updated);
    this.writeMap("model-providers", this.providers);
    this.lifecycleReceipt("provider_stop", {
      providerId,
      modelId: provider.label,
      state: updated.status,
      evidenceRefs: result.evidenceRefs ?? [],
    });
    return publicProvider(updated);
  }

  upsertRoute(body = {}) {
    const id = body.id ?? `route.${safeId(body.role ?? "custom")}`;
    const route = {
      id,
      role: body.role ?? "custom",
      description: body.description ?? "Operator-defined model route.",
      privacy: body.privacy ?? "local_or_enterprise",
      quality: body.quality ?? "adaptive",
      maxCostUsd: Number(body.max_cost_usd ?? body.maxCostUsd ?? 0.25),
      maxLatencyMs: Number(body.max_latency_ms ?? body.maxLatencyMs ?? 30000),
      providerEligibility: normalizeScopes(body.provider_eligibility ?? body.providerEligibility, []),
      fallback: normalizeScopes(body.fallback, []),
      deniedProviders: normalizeScopes(body.denied_providers ?? body.deniedProviders, []),
      status: body.status ?? "active",
      lastSelectedModel: body.last_selected_model ?? body.lastSelectedModel ?? null,
      lastReceiptId: body.last_receipt_id ?? body.lastReceiptId ?? null,
    };
    this.routes.set(route.id, route);
    this.writeMap("model-routes", this.routes);
    return route;
  }

  routeSelectionReceipt(selection, { body = {}, capability = "chat", responseId = null, previousResponseId = null, evidenceRefs = [] } = {}) {
    const policy = body.model_policy ?? body.modelPolicy ?? {};
    const requestedModel = body.model ?? body.model_id ?? body.modelId ?? null;
    const workflow = routeDecision.workflowContextFromRouteRequest(body);
    const policyHash = stableHash(policy);
    const modelRouteDecision = routeDecision.createModelRouteDecision({
      route: selection.route,
      endpoint: selection.endpoint,
      provider: selection.provider,
      capability,
      policy,
      requestedModel,
      request: body,
      policyHash,
      workflow,
      responseId,
      previousResponseId,
      evaluatedCandidates: selection.evaluatedCandidates ?? [],
    });
    return this.receipt("model_route_selection", {
      summary: `Route ${selection.route.id} selected ${selection.endpoint.modelId}.`,
      redaction: "none",
      evidenceRefs: ["model_router", selection.route.id, selection.endpoint.id, ...evidenceRefs],
      details: {
        routeId: selection.route.id,
        selectedModel: selection.endpoint.modelId,
        endpointId: selection.endpoint.id,
        providerId: selection.endpoint.providerId,
        capability,
        policyHash,
        responseId,
        previousResponseId,
        modelRouteDecisionSchemaVersion: routeDecision.MODEL_ROUTE_DECISION_SCHEMA_VERSION,
        modelRouteDecisionEventKind: routeDecision.MODEL_ROUTE_DECISION_EVENT_KIND,
        modelRouteDecisionId: modelRouteDecision.decisionId,
        modelRouteDecision,
        ...workflow,
      },
    });
  }

  testRoute(routeId, body = {}) {
    const route = this.route(routeId);
    const capability = body.capability ?? "chat";
    const selection = this.selectRoute({
      modelId: body.model ?? body.model_id ?? body.modelId,
      routeId,
      capability,
      policy: body.model_policy ?? body.modelPolicy ?? {},
    });
    const receipt = this.routeSelectionReceipt(selection, { body: { ...body, route_id: routeId }, capability });
    const updatedRoute = {
      ...route,
      lastSelectedModel: selection.endpoint.modelId,
      lastReceiptId: receipt.id,
    };
    this.routes.set(routeId, updatedRoute);
    this.writeMap("model-routes", this.routes);
    return { route: updatedRoute, selection, receipt };
  }

  async invokeModel({ authorization, requiredScope, kind, body = {} }) {
    const token = this.authorize(authorization, requiredScope);
    const started = this.now().getTime();
    const input = inputText(body);
    const statefulInvocation = supportsResponseState(kind);
    const previousResponseId = statefulInvocation ? optionalString(body.previous_response_id ?? body.previousResponseId) : null;
    const previousState = previousResponseId ? this.conversationState(previousResponseId) : null;
    const responseId = statefulInvocation ? this.nextResponseId(body.response_id ?? body.responseId) : null;
    const capability =
      kind === "embeddings"
        ? "embeddings"
        : kind === "rerank"
          ? "rerank"
          : kind === "responses"
            ? "responses"
            : "chat";
    const selection = this.selectRoute({
      modelId: body.model,
      routeId: body.route_id ?? body.routeId,
      capability,
      policy: body.model_policy ?? body.modelPolicy ?? {},
    });
    const continuationSafety = this.validateContinuationSafety({ previousState, selection, body });
    const routeReceipt = this.routeSelectionReceipt(selection, { body, capability, responseId, previousResponseId });
    const providerBody = routeDecision.providerRequestBodyForRoute(body, selection.endpoint);
    const coalesceKey = modelInvocationCoalesceKey({
      kind,
      body,
      providerBody,
      input,
      token,
      selection,
      previousResponseId,
    });
    let providerExecution = coalesceKey ? this.inflightModelInvocations.get(coalesceKey) : null;
    const coalesced = Boolean(providerExecution);
    if (!providerExecution) {
      providerExecution = (async () => {
        const instance = await this.ensureLoaded(selection.endpoint);
        const ephemeralMcp = this.compileEphemeralMcpIntegrations({ authorization, body, input });
        const providerResult = await this.driverForProvider(selection.provider).invoke({
          state: this,
          provider: selection.provider,
          endpoint: selection.endpoint,
          instance,
          kind,
          body: providerBody,
          input,
          token,
        });
        return { instance, ephemeralMcp, providerResult };
      })();
      if (coalesceKey) {
        this.inflightModelInvocations.set(coalesceKey, providerExecution);
      }
    }
    let execution;
    try {
      execution = await providerExecution;
    } finally {
      if (coalesceKey && !coalesced) {
        this.inflightModelInvocations.delete(coalesceKey);
      }
    }
    const { instance, ephemeralMcp, providerResult } = execution;
    const outputText = providerResult.outputText;
    const latencyMs = Math.max(1, this.now().getTime() - started);
    const tokenCount = providerResult.tokenCount ?? estimateTokens(input, outputText);
    const receiptKind = coalesced ? "model_invocation_coalesced" : "model_invocation";
    const receipt = this.receipt(receiptKind, {
      summary: coalesced
        ? `${kind} invocation reused an identical in-flight request for ${selection.endpoint.modelId}.`
        : `${kind} invocation routed through ${selection.route.id} to ${selection.endpoint.modelId}.`,
      redaction: "redacted",
      evidenceRefs: [
        "model_router",
        ...(coalesced ? ["model_invocation_inflight_coalesced"] : []),
        routeReceipt.id,
        selection.route.id,
        selection.endpoint.id,
        instance.id,
        token.grantId,
        ...ephemeralMcp.evidenceRefs,
        ...(providerResult.providerAuthEvidenceRefs ?? []),
      ],
      details: {
        routeId: selection.route.id,
        routeReceiptId: routeReceipt.id,
        selectedModel: selection.endpoint.modelId,
        endpointId: selection.endpoint.id,
        providerId: selection.endpoint.providerId,
        instanceId: instance.id,
        backend: providerResult.backend ?? selection.endpoint.apiFormat,
        backendId: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
        selectedBackend: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
        policyHash: stableHash(body.model_policy ?? body.modelPolicy ?? {}),
        grantId: token.grantId,
        tokenCount,
        latencyMs,
        inputHash: stableHash(input),
        outputHash: stableHash(outputText),
        compatTranslation: providerResult.compatTranslation ?? null,
        providerResponseKind: providerResult.providerResponseKind ?? null,
        backendProcess: providerResult.backendProcess ?? instance.backendProcess ?? null,
        backendProcessId: providerResult.backendProcess?.id ?? instance.backendProcessId ?? null,
        backendProcessPidHash: providerResult.backendProcess?.pidHash ?? instance.backendProcessPidHash ?? null,
        backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
        authVaultRefHash: providerResult.authVaultRefHash ?? null,
        providerAuthEvidenceRefs: providerResult.providerAuthEvidenceRefs ?? [],
        providerAuthHeaderNames: providerResult.providerAuthHeaderNames ?? [],
        toolReceiptIds: ephemeralMcp.toolReceiptIds,
        ephemeralMcpServerIds: ephemeralMcp.serverIds,
        sendOptions: body.send_options ?? body.sendOptions ?? null,
        memory: body.memory ?? body.send_options?.memory ?? body.sendOptions?.memory ?? null,
        responseId,
        previousResponseId,
        continuation: continuationSafety,
        coalesced,
        coalesceKeyHash: coalesceKey ? stableHash(coalesceKey) : null,
      },
    });
    const conversationState = statefulInvocation
      ? this.recordConversationState({
          responseId,
          previousState,
          kind,
          input,
          outputText: providerResult.outputText ?? "",
          selection,
          instance,
          receipt,
          routeReceipt,
          tokenCount,
          streamReceiptId: null,
          status: "completed",
          continuationSafety,
        })
      : null;
    const route = {
      ...selection.route,
      lastSelectedModel: selection.endpoint.modelId,
      lastReceiptId: receipt.id,
    };
    this.routes.set(route.id, route);
    this.writeMap("model-routes", this.routes);
    return {
      kind,
      outputText,
      model: selection.endpoint.modelId,
      route,
      endpoint: selection.endpoint,
      instance,
      receipt,
      routeReceipt,
      tokenCount,
      providerResponse: providerResult.providerResponse ?? null,
      providerResponseKind: providerResult.providerResponseKind ?? null,
      compatTranslation: providerResult.compatTranslation ?? null,
      toolReceiptIds: ephemeralMcp.toolReceiptIds,
      responseId,
      previousResponseId,
      conversationState,
    };
  }

  modelTokenizerUtility({ authorization, requiredScope, body = {}, operation }) {
    const token = this.authorize(authorization, requiredScope);
    const input = inputText(body);
    const selection = this.selectRoute({
      modelId: body.model,
      routeId: body.route_id ?? body.routeId,
      capability: "chat",
      policy: body.model_policy ?? body.modelPolicy ?? {},
    });
    const routeReceipt = this.routeSelectionReceipt(selection, {
      body,
      capability: "tokenize",
      evidenceRefs: ["tokenizer_utility"],
    });
    const tokens = deterministicTokenizeText(input);
    const promptTokens = Math.max(1, tokens.length);
    const contextWindow = this.contextWindowForEndpoint(selection.endpoint, body);
    const receipt = this.receipt(operation === "context_fit" ? "model_context_fit" : "model_tokenization", {
      summary: `${operation} evaluated ${promptTokens} prompt tokens for ${selection.endpoint.modelId}.`,
      redaction: "redacted",
      evidenceRefs: ["tokenizer_estimator", routeReceipt.id, selection.route.id, selection.endpoint.id, token.grantId],
      details: {
        operation,
        routeId: selection.route.id,
        routeReceiptId: routeReceipt.id,
        selectedModel: selection.endpoint.modelId,
        endpointId: selection.endpoint.id,
        providerId: selection.endpoint.providerId,
        backendId: selection.endpoint.backendId ?? null,
        selectedBackend: selection.endpoint.backendId ?? null,
        grantId: token.grantId,
        estimator: "deterministic_context_estimator",
        tokenizerSource: "deterministic_estimator",
        inputHash: stableHash(input),
        tokenCount: {
          prompt_tokens: promptTokens,
          completion_tokens: 0,
          total_tokens: promptTokens,
        },
        contextWindow,
      },
    });
    const route = {
      ...selection.route,
      lastSelectedModel: selection.endpoint.modelId,
      lastReceiptId: receipt.id,
    };
    this.routes.set(route.id, route);
    this.writeMap("model-routes", this.routes);
    return { token, input, tokens, promptTokens, contextWindow, selection: { ...selection, route }, routeReceipt, receipt };
  }

  tokenizeModel({ authorization, requiredScope = "model.tokenize:*", body = {} }) {
    const utility = this.modelTokenizerUtility({ authorization, requiredScope, body, operation: "tokenize" });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      model: utility.selection.endpoint.modelId,
      route_id: utility.selection.route.id,
      endpoint_id: utility.selection.endpoint.id,
      provider_id: utility.selection.endpoint.providerId,
      backend_id: utility.selection.endpoint.backendId ?? null,
      tokenizer: "deterministic_context_estimator",
      tokens: utility.tokens,
      token_count: utility.promptTokens,
      usage: {
        prompt_tokens: utility.promptTokens,
        completion_tokens: 0,
        total_tokens: utility.promptTokens,
      },
      receipt_id: utility.receipt.id,
      route_receipt_id: utility.routeReceipt.id,
    };
  }

  countModelTokens({ authorization, requiredScope = "model.tokenize:*", body = {} }) {
    const utility = this.modelTokenizerUtility({ authorization, requiredScope, body, operation: "count_tokens" });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      model: utility.selection.endpoint.modelId,
      route_id: utility.selection.route.id,
      endpoint_id: utility.selection.endpoint.id,
      provider_id: utility.selection.endpoint.providerId,
      backend_id: utility.selection.endpoint.backendId ?? null,
      tokenizer: "deterministic_context_estimator",
      input_hash: stableHash(utility.input),
      token_count: utility.promptTokens,
      usage: {
        prompt_tokens: utility.promptTokens,
        completion_tokens: 0,
        total_tokens: utility.promptTokens,
      },
      receipt_id: utility.receipt.id,
      route_receipt_id: utility.routeReceipt.id,
    };
  }

  fitModelContext({ authorization, requiredScope = "model.context:*", body = {} }) {
    const utility = this.modelTokenizerUtility({ authorization, requiredScope, body, operation: "context_fit" });
    const reservedOutputTokens = normalizeNonNegativeInteger(
      body.max_output_tokens ?? body.maxOutputTokens ?? body.reserve_output_tokens ?? body.reserveOutputTokens,
      0,
    );
    const contextWindow = utility.contextWindow;
    const availableInputTokens = Math.max(0, contextWindow - reservedOutputTokens);
    const fits = utility.promptTokens <= availableInputTokens;
    const omittedTokenEstimate = fits ? 0 : utility.promptTokens - availableInputTokens;
    const fittedInput = fits ? utility.input : truncateToEstimatedTokens(utility.input, availableInputTokens);
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      model: utility.selection.endpoint.modelId,
      route_id: utility.selection.route.id,
      endpoint_id: utility.selection.endpoint.id,
      provider_id: utility.selection.endpoint.providerId,
      backend_id: utility.selection.endpoint.backendId ?? null,
      tokenizer: "deterministic_context_estimator",
      context_window: contextWindow,
      reserved_output_tokens: reservedOutputTokens,
      available_input_tokens: availableInputTokens,
      prompt_tokens: utility.promptTokens,
      fits,
      overflow_tokens: omittedTokenEstimate,
      truncation: {
        applied: !fits,
        strategy: "keep_tail",
        omitted_token_estimate: omittedTokenEstimate,
      },
      fitted_input: fittedInput,
      fitted_input_hash: stableHash(fittedInput),
      receipt_id: utility.receipt.id,
      route_receipt_id: utility.routeReceipt.id,
    };
  }

  contextWindowForEndpoint(endpoint, body = {}) {
    const explicit = Number(body.context_length ?? body.contextLength ?? body.context_window ?? body.contextWindow);
    if (Number.isFinite(explicit) && explicit > 0) return Math.floor(explicit);
    const artifact =
      (endpoint.artifactId ? this.artifacts.get(endpoint.artifactId) : null) ??
      [...this.artifacts.values()].find((candidate) => candidate.modelId === endpoint.modelId);
    const artifactContext = Number(artifact?.contextWindow ?? artifact?.metadata?.contextWindow ?? artifact?.metadata?.context);
    if (Number.isFinite(artifactContext) && artifactContext > 0) return Math.floor(artifactContext);
    return 4096;
  }

  nextResponseId(requested) {
    const responseId = optionalString(requested) ?? `resp_${crypto.randomUUID()}`;
    if (this.conversations.has(responseId)) {
      throw runtimeError({
        status: 409,
        code: "continuation",
        message: "response_id already exists.",
        details: { response_id: responseId },
      });
    }
    return responseId;
  }

  conversationState(responseId) {
    const state = this.conversations.get(responseId);
    if (!state) {
      throw runtimeError({
        status: 404,
        code: "continuation",
        message: "previous_response_id was not found.",
        details: { previous_response_id: responseId },
      });
    }
    return state;
  }

  validateContinuationSafety({ previousState, selection, body = {} }) {
    if (!previousState) {
      return { mode: "new", previousResponseId: null, fallbackAllowed: false, mismatchFields: [] };
    }
    const allowFallback = truthy(
      body.allow_continuation_fallback ??
        body.allowContinuationFallback ??
        body.allow_route_fallback ??
        body.allowRouteFallback,
    );
    const mismatchFields = [];
    if (previousState.routeId !== selection.route.id) mismatchFields.push("route_id");
    if (previousState.endpointId !== selection.endpoint.id) mismatchFields.push("endpoint_id");
    if (previousState.selectedModel !== selection.endpoint.modelId) mismatchFields.push("model");
    if (mismatchFields.length > 0 && !allowFallback) {
      throw runtimeError({
        status: 409,
        code: "continuation_route_mismatch",
        message: "Continuation would change the selected route, endpoint, or model without explicit fallback consent.",
        details: {
          previous_response_id: previousState.id,
          mismatch_fields: mismatchFields,
          required: "allow_continuation_fallback",
        },
      });
    }
    return {
      mode: mismatchFields.length > 0 ? "fallback_allowed" : "matched",
      previousResponseId: previousState.id,
      fallbackAllowed: allowFallback,
      mismatchFields,
    };
  }

  recordConversationState({
    responseId,
    previousState,
    kind,
    input,
    outputText,
    selection,
    instance,
    receipt,
    routeReceipt,
    tokenCount,
    streamReceiptId = null,
    status = "completed",
    continuationSafety = null,
  }) {
    const now = this.nowIso();
    const record = {
      id: responseId,
      object: "ioi.model_response_state",
      status,
      redaction: "redacted",
      createdAt: now,
      previousResponseId: previousState?.id ?? null,
      rootResponseId: previousState?.rootResponseId ?? previousState?.id ?? responseId,
      kind,
      routeId: selection.route.id,
      endpointId: selection.endpoint.id,
      selectedModel: selection.endpoint.modelId,
      providerId: selection.endpoint.providerId,
      backendId: instance?.backendId ?? selection.endpoint.backendId ?? null,
      instanceId: instance?.id ?? null,
      receiptId: receipt.id,
      routeReceiptId: routeReceipt?.id ?? null,
      streamReceiptId,
      inputHash: stableHash(input),
      outputHash: stableHash(outputText),
      tokenCount,
      messageCount: Number(previousState?.messageCount ?? 0) + 2,
      continuation: continuationSafety,
      replay: {
        source: "redacted_conversation_state",
        plaintextPersisted: false,
        previousResponseId: previousState?.id ?? null,
      },
    };
    this.conversations.set(record.id, record);
    this.writeMap("model-conversations", this.conversations);
    return record;
  }

  async startModelStream({ authorization, requiredScope, kind, body = {} }) {
    const token = this.authorize(authorization, requiredScope);
    const started = this.now().getTime();
    const input = inputText(body);
    const statefulInvocation = supportsResponseState(kind);
    const previousResponseId = statefulInvocation ? optionalString(body.previous_response_id ?? body.previousResponseId) : null;
    const previousState = previousResponseId ? this.conversationState(previousResponseId) : null;
    const responseId = statefulInvocation ? this.nextResponseId(body.response_id ?? body.responseId) : null;
    const capability =
      kind === "embeddings"
        ? "embeddings"
        : kind === "rerank"
          ? "rerank"
          : kind === "responses"
            ? "responses"
            : "chat";
    const selection = this.selectRoute({
      modelId: body.model,
      routeId: body.route_id ?? body.routeId,
      capability,
      policy: body.model_policy ?? body.modelPolicy ?? {},
    });
    const continuationSafety = this.validateContinuationSafety({ previousState, selection, body });
    const driver = this.driverForProvider(selection.provider);
    if (typeof driver.streamInvoke !== "function" || (typeof driver.supportsStream === "function" && !driver.supportsStream(kind))) {
      return {
        native: false,
        invocation: await this.invokeModel({ authorization, requiredScope, kind, body: { ...body, stream: false } }),
      };
    }
    const routeReceipt = this.routeSelectionReceipt(selection, { body, capability, responseId, previousResponseId });
    const instance = await this.ensureLoaded(selection.endpoint);
    const ephemeralMcp = this.compileEphemeralMcpIntegrations({ authorization, body, input });
    const providerBody = routeDecision.providerRequestBodyForRoute(body, selection.endpoint);
    this.appendOperation?.("model.provider_stream_request_shape", {
      providerId: selection.provider.id,
      providerKind: selection.provider.kind,
      endpointId: selection.endpoint.id,
      routeId: selection.route.id,
      capability,
      requestShape: summarizeProviderRequestBodyForTrace(providerBody),
      evidenceRefs: ["model_provider_stream_request_shape"],
    });
    const providerResult = await driver.streamInvoke({
      state: this,
      provider: selection.provider,
      endpoint: selection.endpoint,
      instance,
      kind,
      body: providerBody,
      input,
      token,
    });
    if (!providerResult?.stream) {
      return {
        native: false,
        invocation: await this.invokeModel({ authorization, requiredScope, kind, body: { ...body, stream: false } }),
      };
    }
    const outputText = "";
    const latencyMs = Math.max(1, this.now().getTime() - started);
    const tokenCount = providerResult.tokenCount ?? estimateTokens(input, outputText);
    const receipt = this.receipt("model_invocation", {
      summary: `${kind} invocation stream started through ${selection.route.id} to ${selection.endpoint.modelId}.`,
      redaction: "redacted",
      evidenceRefs: [
        "model_router",
        "provider_native_stream",
        routeReceipt.id,
        selection.route.id,
        selection.endpoint.id,
        instance.id,
        token.grantId,
        ...ephemeralMcp.evidenceRefs,
        ...(providerResult.providerAuthEvidenceRefs ?? []),
      ],
      details: {
        routeId: selection.route.id,
        routeReceiptId: routeReceipt.id,
        selectedModel: selection.endpoint.modelId,
        endpointId: selection.endpoint.id,
        providerId: selection.endpoint.providerId,
        instanceId: instance.id,
        backend: providerResult.backend ?? selection.endpoint.apiFormat,
        backendId: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
        selectedBackend: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
        policyHash: stableHash(body.model_policy ?? body.modelPolicy ?? {}),
        grantId: token.grantId,
        tokenCount,
        latencyMs,
        inputHash: stableHash(input),
        outputHash: stableHash(outputText),
        compatTranslation: providerResult.compatTranslation ?? null,
        providerResponseKind: providerResult.providerResponseKind ?? null,
        streamStatus: "started",
        streamSource: "provider_native",
        backendProcess: providerResult.backendProcess ?? instance.backendProcess ?? null,
        backendProcessId: providerResult.backendProcess?.id ?? instance.backendProcessId ?? null,
        backendProcessPidHash: providerResult.backendProcess?.pidHash ?? instance.backendProcessPidHash ?? null,
        backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
        authVaultRefHash: providerResult.authVaultRefHash ?? null,
        providerAuthEvidenceRefs: providerResult.providerAuthEvidenceRefs ?? [],
        providerAuthHeaderNames: providerResult.providerAuthHeaderNames ?? [],
        toolReceiptIds: ephemeralMcp.toolReceiptIds,
        ephemeralMcpServerIds: ephemeralMcp.serverIds,
        responseId,
        previousResponseId,
        continuation: continuationSafety,
      },
    });
    const route = {
      ...selection.route,
      lastSelectedModel: selection.endpoint.modelId,
      lastReceiptId: receipt.id,
    };
    this.routes.set(route.id, route);
    this.writeMap("model-routes", this.routes);
    const invocation = {
      kind,
      input,
      outputText,
      model: selection.endpoint.modelId,
      route,
      endpoint: selection.endpoint,
      instance,
      receipt,
      routeReceipt,
      tokenCount,
      providerResponse: null,
      providerResponseKind: providerResult.providerResponseKind ?? null,
      compatTranslation: providerResult.compatTranslation ?? null,
      toolReceiptIds: ephemeralMcp.toolReceiptIds,
      responseId,
      previousResponseId,
      previousConversationState: previousState,
      continuationSafety,
    };
    return {
      native: true,
      invocation,
      providerStream: providerResult.stream,
      abort: providerResult.abort,
      providerResult,
    };
  }

  recordModelStreamCompleted({ invocation, streamKind, outputText = "", providerUsage = null, chunksForwarded = 0, finishReason = null, providerResult = {} }) {
    const tokenCount = normalizeUsage(providerUsage, estimateTokens(invocation.input ?? "", outputText));
    const receipt = this.receipt("model_invocation_stream_completed", {
      summary: `${streamKind} stream completed for ${invocation.model}.`,
      redaction: "redacted",
      evidenceRefs: ["model_stream", streamKind, invocation.receipt.id, invocation.route.id, invocation.endpoint.id],
      details: {
        streamKind,
        streamSource: "provider_native",
        invocationReceiptId: invocation.receipt.id,
        routeId: invocation.route.id,
        selectedModel: invocation.model,
        endpointId: invocation.endpoint.id,
        providerId: invocation.endpoint.providerId,
        instanceId: invocation.instance.id,
        backendId: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
        selectedBackend: invocation.receipt.details?.selectedBackend ?? null,
        providerResponseKind: providerResult.providerResponseKind ?? invocation.providerResponseKind ?? null,
        backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
        toolReceiptIds: invocation.toolReceiptIds ?? [],
        tokenCount,
        outputHash: stableHash(outputText),
        chunksForwarded,
        finishReason,
        responseId: invocation.responseId ?? null,
        previousResponseId: invocation.previousResponseId ?? null,
      },
    });
    if (invocation.responseId) {
      invocation.conversationState = this.recordConversationState({
        responseId: invocation.responseId,
        previousState: invocation.previousConversationState ?? null,
        kind: invocation.kind,
        input: invocation.input ?? "",
        outputText,
        selection: {
          route: invocation.route,
          endpoint: invocation.endpoint,
          provider: null,
        },
        instance: invocation.instance,
        receipt: invocation.receipt,
        routeReceipt: invocation.routeReceipt,
        tokenCount,
        streamReceiptId: receipt.id,
        status: "completed",
        continuationSafety: invocation.continuationSafety ?? null,
      });
    }
    return receipt;
  }

  compileEphemeralMcpIntegrations({ authorization, body = {}, input }) {
    const integrations = Array.isArray(body.integrations) ? body.integrations : [];
    const ephemeral = integrations.filter((integration) => integration?.type === "ephemeral_mcp");
    const toolReceiptIds = [];
    const serverIds = [];
    const evidenceRefs = [];
    for (const integration of ephemeral) {
      const label = requiredString(integration.server_label ?? integration.serverLabel, "server_label");
      const server = this.normalizeMcpServer(label, {
        ...integration,
        url: integration.server_url ?? integration.serverUrl,
        allowed_tools: integration.allowed_tools ?? integration.allowedTools,
        source: "ephemeral_mcp",
      });
      const stored = {
        ...server,
        id: `mcp.ephemeral.${safeId(label)}.${stableHash(integration.server_url ?? integration.serverUrl ?? label).slice(0, 10)}`,
        status: "ephemeral_registered",
      };
      this.mcpServers.set(stored.id, stored);
      serverIds.push(stored.id);
      const serverReceipt = this.receipt("mcp_ephemeral_registration", {
        summary: `Ephemeral MCP server ${label} registered for one model request.`,
        redaction: "redacted",
        evidenceRefs: ["ephemeral_mcp", "RuntimeToolContract", stored.id],
        details: stored,
      });
      evidenceRefs.push(serverReceipt.id, stored.id);
      const allowedTools = stored.allowedTools.length > 0 ? stored.allowedTools : [];
      for (const tool of allowedTools) {
        const result = this.invokeMcpTool({
          authorization,
          body: {
            server_id: stored.id,
            tool,
            input: {
              source: "ephemeral_mcp",
              requestInputHash: stableHash(input),
            },
          },
        });
        toolReceiptIds.push(result.receipt.id);
        evidenceRefs.push(result.receipt.id);
      }
    }
    if (ephemeral.length > 0) {
      this.writeMap("mcp-servers", this.mcpServers);
    }
    return { toolReceiptIds, serverIds, evidenceRefs };
  }

  importMcpJson(body = {}) {
    const raw = body.mcp_json ?? body.mcpJson ?? body;
    const servers = raw.mcpServers ?? raw.servers ?? {};
    const imported = [];
    for (const [label, config] of Object.entries(servers)) {
      const server = this.normalizeMcpServer(label, config);
      this.mcpServers.set(server.id, server);
      imported.push(server);
      this.receipt("mcp_server_import", {
        summary: `MCP server ${label} imported with governed tool narrowing.`,
        redaction: "redacted",
        evidenceRefs: ["mcp.json", "RuntimeToolContract", server.id],
        details: server,
      });
    }
    this.writeMap("mcp-servers", this.mcpServers);
    return {
      imported,
      count: imported.length,
      empty: imported.length === 0,
    };
  }

  normalizeMcpServer(label, config = {}) {
    const id = `mcp.${safeId(label)}`;
    const allowedTools = normalizeScopes(
      config.allowed_tools ?? config.allowedTools,
      config.tools ? Object.keys(config.tools) : [],
    );
    for (const [key, value] of Object.entries(config.headers ?? config.env ?? {})) {
      this.walletAuthority.resolveVaultRef(String(value));
      if (!String(value).startsWith("vault://")) {
        throw runtimeError({
          status: 403,
          code: "policy",
          message: "MCP secrets must be vault refs.",
          details: { header: key },
        });
      }
    }
    const secretRefs = Object.fromEntries(
      Object.entries(config.headers ?? config.env ?? {}).map(([key]) => [key, `vault://${id}/${safeId(key)}`]),
    );
    return {
      id,
      label,
      transport: config.url || config.server_url || config.serverUrl ? "remote" : "stdio",
      command: config.command ?? null,
      args: Array.isArray(config.args) ? config.args : [],
      serverUrl: config.url ?? config.server_url ?? config.serverUrl ?? null,
      allowedTools,
      secretRefs,
      redactedHeaders: Object.fromEntries(Object.keys(config.headers ?? {}).map((key) => [key, SECRET_REDACTION])),
      status: "registered",
      source: config.source ?? "mcp.json",
      importedAt: this.nowIso(),
    };
  }

  listMcpServers() {
    return [...this.mcpServers.values()]
      .map(publicMcpServer)
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  listConversations() {
    return [...this.conversations.values()].sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")));
  }

  invokeMcpTool({ authorization, body = {} }) {
    const serverId = body.server_id ?? body.serverId ?? `mcp.${safeId(body.server_label ?? body.serverLabel ?? "")}`;
    const server = this.mcpServers.get(serverId);
    if (!server) throw notFound(`MCP server not found: ${serverId}`, { serverId });
    const tool = requiredString(body.tool, "tool");
    this.authorize(authorization, `mcp.call:${server.label}.${tool}`);
    if (server.allowedTools.length > 0 && !server.allowedTools.includes(tool)) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "MCP tool is not included in allowed_tools.",
        details: { serverId, tool },
      });
    }
    const receipt = this.receipt("mcp_tool_invocation", {
      summary: `MCP tool ${server.label}.${tool} executed through governed RuntimeToolContract path.`,
      redaction: "redacted",
      evidenceRefs: ["RuntimeToolContract", server.id, `tool:${tool}`],
      details: {
        serverId,
        tool,
        inputHash: stableHash(body.input ?? {}),
        outputHash: stableHash({ ok: true, tool }),
      },
    });
    return {
      server: server.label,
      tool,
      result: { ok: true, fixture: true, tool },
      receipt,
    };
  }

  async executeWorkflowNode({ authorization, body = {} }) {
    const node = requiredString(body.node ?? body.node_type ?? body.nodeType, "node");
    const capability = body.capability ?? capabilityForWorkflowNode(node);
    const memoryOptions = workflowMemoryOptionsFromBody(body);
    const base = {
      model: body.model_id ?? body.modelId ?? body.model,
      route_id: body.route_id ?? body.routeId,
      model_policy: body.model_policy ?? body.modelPolicy ?? {},
      input: body.input ?? body.prompt ?? "",
      messages: body.messages,
      max_tokens: body.max_tokens ?? body.maxTokens,
      temperature: body.temperature,
      workflow_graph_id: body.workflow_graph_id ?? body.workflowGraphId,
      workflow_node_id: body.workflow_node_id ?? body.workflowNodeId ?? body.node_id ?? body.nodeId,
      workflow_node_type: body.workflow_node_type ?? body.workflowNodeType ?? node,
    };
    if (memoryOptions) {
      base.memory = memoryOptions;
      base.send_options = { memory: memoryOptions };
    }
    if (node === "Model Router") {
      const routeId = base.route_id ?? "route.local-first";
      this.authorize(authorization, `route.use:${routeId}`);
      return {
        node,
        status: "selected",
        ...(this.testRoute(routeId, { ...base, capability })),
      };
    }
    if (node === "Local Tool/MCP" || node === "Local Tool / MCP") {
      return {
        node,
        status: "executed",
        ...(this.invokeMcpTool({ authorization, body: body.mcp ?? body })),
      };
    }
    if (node === "Receipt Gate") {
      return this.validateReceiptGate(body);
    }
    const kind = workflowKindForNode(node);
    const requiredScope =
      kind === "embeddings"
        ? "model.embeddings:*"
        : kind === "rerank"
          ? "model.rerank:*"
          : kind === "responses"
            ? "model.responses:*"
            : "model.chat:*";
    const memoryWriteBlockReason = workflowMemoryWriteBlockReason(memoryOptions);
    if (memoryWriteBlockReason) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Workflow memory write blocked by policy.",
        details: {
          reason: memoryWriteBlockReason,
          memory: memoryOptions,
          workflowNodeId: base.workflow_node_id ?? null,
        },
      });
    }
    const invocation = await this.invokeModel({
      authorization,
      requiredScope,
      kind,
      body: base,
    });
    return {
      node,
      status: "executed",
      capability,
      invocation: nativeInvocationResponseShape(invocation),
      receipt: invocation.receipt,
      routeReceipt: invocation.routeReceipt,
    };
  }

  validateReceiptGate(body = {}) {
    const receiptId = requiredString(body.receipt_id ?? body.receiptId, "receipt_id");
    const receipt = this.getReceipt(receiptId);
    const requiredRedaction = body.redaction ?? body.redaction_class ?? body.redactionClass;
    const requiredRouteId = body.route_id ?? body.routeId;
    const requiredSelectedModel = body.selected_model ?? body.selectedModel;
    const requiredSelectedEndpoint = body.selected_endpoint ?? body.selectedEndpoint ?? body.endpoint_id ?? body.endpointId;
    const requiredSelectedBackend = body.selected_backend ?? body.selectedBackend ?? body.backend_id ?? body.backendId;
    const requiredToolReceiptIds = normalizeScopes(
      body.required_tool_receipt_ids ?? body.requiredToolReceiptIds,
      [],
    );
    const failures = [];
    if (requiredRedaction && receipt.redaction !== requiredRedaction) {
      failures.push(`redaction:${receipt.redaction}`);
    }
    if (requiredRouteId && receipt.details?.routeId !== requiredRouteId) {
      failures.push(`route:${receipt.details?.routeId ?? "missing"}`);
    }
    if (requiredSelectedModel && receipt.details?.selectedModel !== requiredSelectedModel) {
      failures.push(`selected_model:${receipt.details?.selectedModel ?? "missing"}`);
    }
    if (requiredSelectedEndpoint && receipt.details?.endpointId !== requiredSelectedEndpoint) {
      failures.push(`endpoint:${receipt.details?.endpointId ?? "missing"}`);
    }
    if (requiredSelectedBackend && receipt.details?.backendId !== requiredSelectedBackend && receipt.details?.selectedBackend !== requiredSelectedBackend) {
      failures.push(`backend:${receipt.details?.backendId ?? receipt.details?.selectedBackend ?? "missing"}`);
    }
    const linkedToolReceiptIds = new Set(normalizeScopes(receipt.details?.toolReceiptIds, []));
    for (const toolReceiptId of requiredToolReceiptIds) {
      const toolReceipt = this.getReceipt(toolReceiptId);
      if (toolReceipt.kind !== "mcp_tool_invocation") {
        failures.push(`tool_receipt_kind:${toolReceiptId}`);
      }
      if (!linkedToolReceiptIds.has(toolReceiptId)) {
        failures.push(`tool_receipt_link:${toolReceiptId}`);
      }
    }
    if (failures.length > 0) {
      const blockedReceipt = this.receipt("workflow_receipt_gate_blocked", {
        summary: `Receipt Gate blocked ${receiptId}.`,
        redaction: "redacted",
        evidenceRefs: ["workflow_canvas", "Receipt Gate", receiptId, ...requiredToolReceiptIds],
        details: {
          receiptId,
          failures,
          routeId: receipt.details?.routeId ?? null,
          selectedModel: receipt.details?.selectedModel ?? null,
          endpointId: receipt.details?.endpointId ?? null,
          backendId: receipt.details?.backendId ?? receipt.details?.selectedBackend ?? null,
          requiredToolReceiptIds,
        },
      });
      throw runtimeError({
        status: 412,
        code: "policy",
        message: "Receipt Gate blocked downstream workflow execution.",
        details: { receiptId, failures, gateReceiptId: blockedReceipt.id },
      });
    }
    const gateReceipt = this.receipt("workflow_receipt_gate", {
      summary: `Receipt Gate accepted ${receiptId}.`,
      redaction: "redacted",
      evidenceRefs: ["workflow_canvas", "Receipt Gate", receiptId, ...requiredToolReceiptIds],
      details: {
        receiptId,
        routeId: receipt.details?.routeId ?? null,
        selectedModel: receipt.details?.selectedModel ?? null,
        endpointId: receipt.details?.endpointId ?? null,
        backendId: receipt.details?.backendId ?? receipt.details?.selectedBackend ?? null,
        requiredToolReceiptIds,
      },
    });
    return {
      node: "Receipt Gate",
      status: "passed",
      receipt,
      gateReceipt,
    };
  }

  listReceipts() {
    return this.store.listReceipts();
  }

  getReceipt(receiptId) {
    return this.store.getReceipt(receiptId);
  }

  lifecycleReceipt(operation, details) {
    return this.receipt("model_lifecycle", {
      summary: `${operation} recorded for ${details.modelId ?? details.endpointId ?? "model registry"}.`,
      redaction: "redacted",
      evidenceRefs: ["model_registry", "agentgres_canonical_operation_log", operation],
      details: { operation, ...details },
    });
  }

  receipt(kind, { summary, redaction, evidenceRefs, details }) {
    const receipt = {
      id: `receipt_${kind}_${crypto.randomUUID()}`,
      runId: null,
      kind,
      summary,
      redaction,
      evidenceRefs,
      createdAt: this.nowIso(),
      details: redact(details),
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    };
    this.store.writeReceipt(receipt);
    this.writeProjection();
    return receipt;
  }

  provider(providerId) {
    const provider = this.providers.get(providerId);
    if (!provider) throw notFound(`Provider not found: ${providerId}`, { providerId });
    return provider;
  }

  endpoint(endpointId) {
    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint || endpoint.status === "unmounted") {
      throw notFound(`Endpoint not found: ${endpointId}`, { endpointId });
    }
    return endpoint;
  }

  instance(instanceId) {
    const instance = this.instances.get(instanceId);
    if (!instance) throw notFound(`Model instance not found: ${instanceId}`, { instanceId });
    return instance;
  }

  route(routeId) {
    const route = this.routes.get(routeId);
    if (!route) throw notFound(`Route not found: ${routeId}`, { routeId });
    return route;
  }

  resolveEndpoint(endpointId, modelId) {
    if (endpointId) return this.endpoint(endpointId);
    if (modelId) {
      const endpoint = [...this.endpoints.values()].find(
        (candidate) => candidate.status !== "unmounted" && candidate.modelId === modelId,
      );
      if (endpoint) return endpoint;
      return this.mountEndpoint({ model_id: modelId });
    }
    throw runtimeError({
      status: 424,
      code: "product_model_unavailable",
      message: "No model endpoint was specified and no product model route fallback is configured.",
      details: { required: "endpoint_id_or_model_id" },
    });
  }

  endpointIdsForExplicitModel(route, modelId) {
    const matchingEndpoints = [...this.endpoints.values()].filter(
      (candidate) => candidate.status !== "unmounted" && candidate.modelId === modelId,
    );
    const routeFallbackMatches = normalizeScopes(route.fallback, []).filter((endpointId) =>
      matchingEndpoints.some((endpoint) => endpoint.id === endpointId),
    );
    const ordered = [...routeFallbackMatches];
    for (const endpoint of matchingEndpoints) {
      if (!ordered.includes(endpoint.id)) ordered.push(endpoint.id);
    }
    if (ordered.length > 0) return ordered;
    return [this.mountEndpoint({ model_id: modelId }).id];
  }

  selectRoute({ modelId, routeId, capability, policy }) {
    const route = this.routes.get(routeId ?? "route.local-first") ?? this.route("route.local-first");
    const explicitModelId = routeDecision.isAutoModelSelector(modelId) ? null : modelId;
    const fallback = explicitModelId
      ? this.endpointIdsForExplicitModel(route, explicitModelId)
      : route.fallback.length > 0
        ? route.fallback
        : [];
    const evaluatedCandidates = [];
    for (const endpointId of fallback) {
      const endpoint = this.endpoint(endpointId);
      const provider = this.provider(endpoint.providerId);
      const candidate = {
        endpointId,
        providerId: provider.id,
        providerKind: provider.kind,
        modelId: endpoint.modelId,
        status: "rejected",
        reason: null,
      };
      if (route.deniedProviders.includes(provider.kind)) {
        candidate.reason = "provider_denied_by_route";
        evaluatedCandidates.push(candidate);
        continue;
      }
      if (route.providerEligibility.length > 0 && !route.providerEligibility.includes(provider.kind)) {
        candidate.reason = "provider_not_eligible_for_route";
        evaluatedCandidates.push(candidate);
        continue;
      }
      if (truthy(policy?.deny_fixture_models ?? policy?.denyFixtureModels) && isFixtureEndpointCandidate(endpoint, provider)) {
        candidate.reason = "fixture_model_denied_by_product_policy";
        evaluatedCandidates.push(candidate);
        continue;
      }
      if (policy?.privacy === "local_only" && provider.privacyClass !== "local_private") {
        candidate.reason = "policy_requires_local_only";
        evaluatedCandidates.push(candidate);
        continue;
      }
      if (
        provider.privacyClass === "hosted" &&
        route.privacy === "local_or_enterprise" &&
        !truthy(policy?.allow_hosted_fallback ?? policy?.allowHostedFallback)
      ) {
        candidate.reason = "hosted_fallback_not_allowed";
        evaluatedCandidates.push(candidate);
        continue;
      }
      const costCeiling = Number(policy?.max_cost_usd ?? policy?.maxCostUsd ?? route.maxCostUsd ?? Infinity);
      const estimatedCost = Number(endpoint.estimatedCostUsd ?? provider.estimatedCostUsd ?? (provider.privacyClass === "hosted" ? 0.01 : 0));
      if (Number.isFinite(costCeiling) && estimatedCost > costCeiling) {
        candidate.reason = "estimated_cost_exceeds_policy";
        evaluatedCandidates.push(candidate);
        continue;
      }
      if (!endpoint.capabilities.includes(capability) && capability !== "chat") {
        candidate.reason = "capability_unavailable";
        evaluatedCandidates.push(candidate);
        continue;
      }
      evaluatedCandidates.push({ ...candidate, status: "selected", reason: "policy_allowed" });
      return { route, endpoint, provider, evaluatedCandidates };
    }
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "No model endpoint satisfied the route policy.",
      details: { routeId: route.id, capability, policy, evaluatedCandidates },
    });
  }

  async ensureLoaded(endpoint) {
    this.evictExpiredInstances();
    const existing = this.loadedInstanceForEndpoint(endpoint.id, false);
    if (existing) {
      const updated = {
        ...existing,
        lastUsedAt: this.nowIso(),
        expiresAt: expiresAt(this.nowIso(), existing.loadPolicy),
      };
      this.instances.set(updated.id, updated);
      this.writeMap("model-instances", this.instances);
      return updated;
    }
    return this.loadModel({ endpoint_id: endpoint.id, load_policy: endpoint.loadPolicy });
  }

  loadedInstanceForEndpoint(endpointId, failIfMissing = true) {
    const instance = [...this.instances.values()].find(
      (candidate) => candidate.endpointId === endpointId && candidate.status === "loaded",
    );
    if (!instance && failIfMissing) {
      throw notFound(`No loaded model instance for endpoint: ${endpointId}`, { endpointId });
    }
    return instance ?? null;
  }

  evictExpiredInstances() {
    const nowMs = this.now().getTime();
    let changed = false;
    for (const instance of this.instances.values()) {
      if (instance.status !== "loaded" || !instance.expiresAt || Date.parse(instance.expiresAt) > nowMs) {
        continue;
      }
      const evicted = {
        ...instance,
        status: "evicted",
        evictedAt: this.nowIso(),
        evictionReason: "idle_ttl",
      };
      this.instances.set(instance.id, evicted);
      changed = true;
      this.lifecycleReceipt("model_idle_evict", {
        instanceId: instance.id,
        endpointId: instance.endpointId,
        modelId: instance.modelId,
        providerId: instance.providerId,
      });
    }
    if (changed) {
      this.writeMap("model-instances", this.instances);
    }
  }

  coalesceLoadedInstances() {
    const loadedByEndpoint = new Map();
    for (const instance of this.instances.values()) {
      if (instance.status !== "loaded" || !instance.endpointId) continue;
      const current = loadedByEndpoint.get(instance.endpointId);
      if (!current || String(instance.loadedAt ?? "") > String(current.loadedAt ?? "")) {
        loadedByEndpoint.set(instance.endpointId, instance);
      }
    }
    let changed = false;
    for (const instance of this.instances.values()) {
      if (instance.status !== "loaded" || !instance.endpointId) continue;
      const keeper = loadedByEndpoint.get(instance.endpointId);
      if (!keeper || keeper.id === instance.id) continue;
      this.instances.set(instance.id, {
        ...instance,
        status: "superseded",
        supersededAt: this.nowIso(),
        supersededBy: keeper.id,
        supersededReason: "endpoint_reload",
      });
      changed = true;
    }
    if (changed) {
      this.writeMap("model-instances", this.instances);
    }
  }

  supersedeLoadedInstances(endpointId, keepInstanceId) {
    let changed = false;
    for (const instance of this.instances.values()) {
      if (instance.id === keepInstanceId || instance.endpointId !== endpointId || instance.status !== "loaded") continue;
      this.instances.set(instance.id, {
        ...instance,
        status: "superseded",
        supersededAt: this.nowIso(),
        supersededBy: keepInstanceId,
        supersededReason: "endpoint_reload",
      });
      changed = true;
    }
    return changed;
  }

  nowIso() {
    return this.now().toISOString();
  }

  seedBackends(checkedAt) {
    for (const backend of this.deriveBackendRegistry(checkedAt)) {
      const previous = this.backends.get(backend.id);
      this.backends.set(backend.id, previous ? { ...previous, ...backend } : backend);
    }
  }

  backendRegistry() {
    const derived = new Map(this.deriveBackendRegistry(this.nowIso()).map((backend) => [backend.id, backend]));
    for (const [id, backend] of this.backends.entries()) {
      derived.set(id, {
        ...derived.get(id),
        ...backend,
        hardware: backend.hardware ?? derived.get(id)?.hardware,
        evidenceRefs: backend.evidenceRefs ?? derived.get(id)?.evidenceRefs ?? [],
      });
    }
    return [...derived.values()]
      .map((backend) => {
        const processRecord = this.backendProcessForBackend(backend.id);
        return {
          ...backend,
          processStatus: processRecord?.processStatus ?? processRecord?.status ?? backend.processStatus,
          process: processRecord
            ? {
                id: processRecord.id,
                status: processRecord.status,
                processStatus: processRecord.processStatus ?? processRecord.status,
                pidHash: processRecord.pidHash ?? null,
                supervisorKind: processRecord.supervisorKind ?? null,
                spawned: Boolean(processRecord.spawned),
                spawnStatus: processRecord.spawnStatus ?? null,
                startedAt: processRecord.startedAt ?? null,
                stoppedAt: processRecord.stoppedAt ?? null,
                lastHealthAt: processRecord.lastHealthAt ?? null,
                argsHash: processRecord.argsHash ?? null,
                argsRedacted: processRecord.argsRedacted ?? [],
                startupTimeoutMs: processRecord.startupTimeoutMs ?? null,
                stale: Boolean(processRecord.stale),
                staleReason: processRecord.staleReason ?? null,
                receiptId: processRecord.lastReceiptId ?? null,
              }
            : null,
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  deriveBackendRegistry(checkedAt) {
    const hardware = hardwareSnapshot();
    const llamaBinary = process.env.IOI_LLAMA_CPP_SERVER_PATH ?? discoverAutopilotLlamaServer(this.homeDir) ?? findExecutable("llama-server");
    const ollamaBinary = process.env.IOI_OLLAMA_BINARY ?? findExecutable("ollama");
    const vllmBinary = process.env.IOI_VLLM_BINARY ?? findExecutable("vllm");
    return [
      {
        id: "backend.fixture",
        kind: "fixture",
        label: "Deterministic fixture backend",
        status: "available",
        processStatus: "stateless",
        binaryPath: null,
        baseUrl: "local://ioi-daemon/model-fixture",
        capabilities: ["chat", "responses", "embeddings", "rerank"],
        supportedFormats: ["fixture"],
        hardware,
        checkedAt,
        evidenceRefs: ["deterministic_fixture"],
      },
      {
        id: "backend.autopilot.native-local.fixture",
        kind: "native_local",
        label: "Autopilot native-local fixture",
        status: "available",
        processStatus: "supervised_fixture",
        binaryPath: null,
        baseUrl: "local://ioi-native/model-server",
        capabilities: ["chat", "responses", "embeddings", "rerank"],
        supportedFormats: ["gguf", "fixture"],
        processLifecycle: ["estimate", "load", "unload", "health", "logs", "invoke"],
        hardware,
        checkedAt,
        evidenceRefs: ["autopilot_native_local_backend_registry", "deterministic_native_local_fixture"],
      },
      {
        id: "backend.llama-cpp",
        kind: "llama_cpp",
        label: "llama.cpp native GGUF server",
        status: llamaBinary || process.env.IOI_LLAMA_CPP_BASE_URL ? "configured" : "blocked",
        processStatus: llamaBinary ? "binary_configured" : "binary_absent",
        binaryPath: llamaBinary,
        baseUrl: process.env.IOI_LLAMA_CPP_BASE_URL ?? "http://127.0.0.1:8080/v1",
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["gguf"],
        processLifecycle: ["estimate", "start", "stop", "health", "logs", "invoke"],
        hardware,
        checkedAt,
        evidenceRefs: ["IOI_LLAMA_CPP_SERVER_PATH", "llama_cpp_openai_compatible_server"],
      },
      {
        id: "backend.lmstudio",
        kind: "lm_studio",
        label: "LM Studio public provider",
        status: this.providers.get("provider.lmstudio")?.status ?? "unknown",
        processStatus: "external_provider",
        binaryPath: this.providers.get("provider.lmstudio")?.discovery?.publicCli?.path ?? null,
        baseUrl: this.providers.get("provider.lmstudio")?.baseUrl ?? "http://127.0.0.1:1234/v1",
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["lm_studio_catalog"],
        hardware,
        checkedAt,
        evidenceRefs: ["lm_studio_public_cli_or_server_probe"],
      },
      {
        id: "backend.openai-compatible",
        kind: "openai_compatible",
        label: "Generic OpenAI-compatible HTTP backend",
        status: this.providers.get("provider.openai-compatible")?.status ?? "configured_if_provider_available",
        processStatus: "stateless_http",
        binaryPath: null,
        baseUrl: this.providers.get("provider.openai-compatible")?.baseUrl ?? null,
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["http_endpoint"],
        hardware,
        checkedAt,
        evidenceRefs: ["openai_compatible_provider_profile"],
      },
      {
        id: "backend.ollama",
        kind: "ollama",
        label: "Ollama local backend",
        status: this.providers.get("provider.ollama")?.status ?? "blocked",
        processStatus: ollamaBinary ? "binary_configured" : "external_or_absent",
        binaryPath: ollamaBinary,
        baseUrl: this.providers.get("provider.ollama")?.baseUrl ?? "http://127.0.0.1:11434",
        capabilities: ["chat", "embeddings"],
        supportedFormats: ["ollama_manifest"],
        hardware,
        checkedAt,
        evidenceRefs: ["OLLAMA_HOST"],
      },
      {
        id: "backend.vllm",
        kind: "vllm",
        label: "vLLM OpenAI-compatible backend",
        status: this.providers.get("provider.vllm")?.status ?? "blocked",
        processStatus: vllmBinary ? "binary_configured" : "external_or_absent",
        binaryPath: vllmBinary,
        baseUrl: this.providers.get("provider.vllm")?.baseUrl ?? "http://127.0.0.1:8000/v1",
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["safetensors", "hf_repository"],
        hardware,
        checkedAt,
        evidenceRefs: ["VLLM_BASE_URL"],
      },
    ];
  }

  listBackends() {
    return this.backendRegistry();
  }

  listBackendProcesses() {
    return [...this.backendProcesses.values()]
      .map((processRecord) => this.reconciledBackendProcess(processRecord))
      .sort((left, right) => String(left.startedAt ?? "").localeCompare(String(right.startedAt ?? "")));
  }

  backendProcessForBackend(backendId) {
    const processes = this.listBackendProcesses().filter((processRecord) => processRecord.backendId === backendId);
    return processes.at(-1) ?? null;
  }

  reconciledBackendProcess(processRecord) {
    if (!processRecord) return null;
    if (processRecord.status === "started" && processRecord.bootId && processRecord.bootId !== this.bootId) {
      return {
        ...processRecord,
        status: "stale_recovered",
        processStatus: "stale_recovered",
        stale: true,
        staleReason: "daemon_boot_mismatch",
        evidenceRefs: [
          ...normalizeScopes(processRecord.evidenceRefs, []),
          "supervisor_stale_process_detection",
          "agentgres_process_projection_replay",
        ],
      };
    }
    return {
      stale: false,
      ...processRecord,
    };
  }

  runtimePreference() {
    const preference =
      this.runtimeSelections.get("default") ?? {
        id: "default",
        selectedEngineId: "backend.autopilot.native-local.fixture",
        selectedAt: null,
        receiptId: "none",
        source: "default_native_local_runtime",
      };
    return {
      ...preference,
      defaultLoadOptions: this.runtimeDefaultLoadOptions(preference.selectedEngineId),
    };
  }

  runtimePreferenceForEndpoint(endpoint = {}) {
    const preference = this.runtimePreference();
    const endpointBackendId = endpoint.backendId ?? null;
    if (!endpointBackendId || endpointBackendId === preference.selectedEngineId) return preference;
    if (!this.backendRegistry().some((backend) => backend.id === endpointBackendId)) return preference;
    return {
      ...preference,
      selectedEngineId: endpointBackendId,
      source: "endpoint_backend_runtime",
      endpointBackendId,
      defaultLoadOptions: this.runtimeDefaultLoadOptions(endpointBackendId),
    };
  }

  runtimeEngineProfile(engineId) {
    return this.runtimeEngineProfiles.get(engineId) ?? null;
  }

  listRuntimeEngineProfiles() {
    return [...this.runtimeEngineProfiles.values()].sort((left, right) => left.id.localeCompare(right.id));
  }

  runtimeDefaultLoadOptions(engineId) {
    const profile = this.runtimeEngineProfile(engineId);
    return profile?.defaultLoadOptions ?? {};
  }

  runtimeEngine(engineId) {
    const engine = this.listRuntimeEngines().find((item) => item.id === engineId);
    if (!engine) throw notFound(`Runtime engine not found: ${engineId}`, { engineId });
    return {
      ...engine,
      profile: this.runtimeEngineProfile(engineId),
      preference: this.runtimePreference().selectedEngineId === engineId ? this.runtimePreference() : null,
      loadedInstances: this.listInstances().filter((instance) => instance.runtimeEngineId === engineId || instance.backendId === engineId),
      latestReceipts: this.listReceipts()
        .filter((receipt) => receipt.details?.runtimeEngineId === engineId || receipt.details?.engineId === engineId || receipt.details?.backendId === engineId)
        .slice(-8),
    };
  }

  selectRuntimeEngine(body = {}) {
    const engineId = requiredString(body.engine_id ?? body.engineId ?? body.id, "engine_id");
    const checkedAt = this.nowIso();
    const engines = this.listRuntimeEngines();
    const engine = engines.find((item) => item.id === engineId);
    if (!engine) throw notFound(`Runtime engine not found: ${engineId}`, { engineId });
    if (engine.operatorProfile?.disabled) {
      throw runtimeError({
        status: 409,
        code: "runtime_engine_disabled",
        message: "Runtime engine is disabled by its operator profile.",
        details: { engineId, receiptId: engine.operatorProfile.receiptId ?? null },
      });
    }
    const receipt = this.lifecycleReceipt("runtime_engine_select", {
      engineId,
      engineKind: engine.kind,
      engineStatus: engine.status,
      source: engine.source,
      modelFormat: engine.modelFormat,
      defaultLoadOptions: engine.operatorProfile?.defaultLoadOptions ?? {},
      checkedAt,
    });
    const preference = {
      id: "default",
      selectedEngineId: engineId,
      selectedAt: checkedAt,
      receiptId: receipt.id,
      source: "operator_runtime_select",
      engineKind: engine.kind,
      engineLabel: engine.label,
      modelFormat: engine.modelFormat,
      defaultLoadOptions: engine.operatorProfile?.defaultLoadOptions ?? {},
    };
    this.runtimeSelections.set(preference.id, preference);
    this.writeMap("runtime-preferences", this.runtimeSelections);
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      ...preference,
    };
  }

  updateRuntimeEngine(engineId, body = {}) {
    const engine = this.runtimeEngine(engineId);
    const now = this.nowIso();
    const existing = this.runtimeEngineProfile(engineId) ?? {};
    const disabledValue = body.disabled ?? body.disable ?? existing.disabled ?? false;
    const defaultLoadOptions = normalizeRuntimeEngineDefaultLoadOptions(
      body.default_load_options ?? body.defaultLoadOptions ?? body.load_options ?? body.loadOptions ?? existing.defaultLoadOptions ?? {},
    );
    const receipt = this.lifecycleReceipt("runtime_engine_update", {
      engineId,
      engineKind: engine.kind,
      previousProfileHash: stableHash(existing),
      disabled: Boolean(disabledValue),
      priority: body.priority ?? existing.priority ?? null,
      defaultLoadOptions,
      evidenceRefs: ["operator_runtime_engine_profile", "runtime_engine_default_load_options"],
    });
    const profile = {
      id: engineId,
      engineId,
      label: body.label ?? body.operator_label ?? body.operatorLabel ?? existing.label ?? null,
      disabled: Boolean(disabledValue),
      priority: body.priority === undefined || body.priority === null || body.priority === ""
        ? existing.priority ?? null
        : Number(body.priority),
      defaultLoadOptions,
      updatedAt: now,
      receiptId: receipt.id,
      source: "operator_runtime_engine_profile",
    };
    this.runtimeEngineProfiles.set(engineId, profile);
    this.writeMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    if (profile.disabled && this.runtimePreference().selectedEngineId === engineId) {
      this.runtimeSelections.set("default", {
        id: "default",
        selectedEngineId: "backend.autopilot.native-local.fixture",
        selectedAt: now,
        receiptId: receipt.id,
        source: "operator_runtime_disable_reset",
        engineKind: "native_local",
        engineLabel: "Autopilot native-local fixture",
        modelFormat: "gguf,fixture",
        defaultLoadOptions: this.runtimeDefaultLoadOptions("backend.autopilot.native-local.fixture"),
      });
      this.writeMap("runtime-preferences", this.runtimeSelections);
    }
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      profile,
      engine: this.runtimeEngine(engineId),
      receiptId: receipt.id,
    };
  }

  removeRuntimeEngineOverride(engineId) {
    this.runtimeEngine(engineId);
    const existing = this.runtimeEngineProfile(engineId);
    const receipt = this.lifecycleReceipt("runtime_engine_profile_remove", {
      engineId,
      hadProfile: Boolean(existing),
      previousProfileHash: stableHash(existing ?? {}),
      evidenceRefs: ["operator_runtime_engine_profile_remove"],
    });
    this.runtimeEngineProfiles.delete(engineId);
    fs.rmSync(path.join(this.stateDir, "runtime-engine-profiles", `${safeFileName(engineId)}.json`), { force: true });
    this.writeMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    if (this.runtimePreference().selectedEngineId === engineId && existing?.disabled) {
      this.runtimeSelections.set("default", {
        id: "default",
        selectedEngineId: "backend.autopilot.native-local.fixture",
        selectedAt: this.nowIso(),
        receiptId: receipt.id,
        source: "operator_runtime_profile_remove_reset",
        engineKind: "native_local",
        engineLabel: "Autopilot native-local fixture",
        modelFormat: "gguf,fixture",
        defaultLoadOptions: this.runtimeDefaultLoadOptions("backend.autopilot.native-local.fixture"),
      });
      this.writeMap("runtime-preferences", this.runtimeSelections);
    }
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      engineId,
      removed: Boolean(existing),
      engine: this.runtimeEngine(engineId),
      receiptId: receipt.id,
    };
  }

  listRuntimeEngines() {
    const checkedAt = this.nowIso();
    const activeBackendIds = new Set(this.listInstances().map((instance) => instance.backendId).filter(Boolean));
    const runtimePreference = this.runtimePreference();
    const hasExplicitPreference = runtimePreference.receiptId !== "none";
    const backendEngines = this.backendRegistry().map((backend) => ({
      id: backend.id,
      kind: backend.kind,
      label: backend.label,
      status: backend.status,
      selected:
        runtimePreference.selectedEngineId === backend.id ||
        (!hasExplicitPreference &&
          (activeBackendIds.has(backend.id) ||
            (activeBackendIds.size === 0 && backend.id === "backend.autopilot.native-local.fixture"))),
      modelFormat: (backend.supportedFormats ?? []).join(",") || "unknown",
      source: "autopilot_backend_registry",
      processStatus: backend.processStatus ?? "unknown",
      checkedAt,
      evidenceRefs: backend.evidenceRefs ?? [],
    })).map((engine) => this.applyRuntimeEngineProfile(engine));
    const lmStudioEngines = this.lmStudioRuntimeEngines(checkedAt).map((engine) => ({
      ...engine,
      selected: runtimePreference.selectedEngineId === engine.id || (!hasExplicitPreference && engine.selected),
    })).map((engine) => this.applyRuntimeEngineProfile(engine));
    return [...backendEngines, ...lmStudioEngines].sort((left, right) => {
      const leftPriority = left.operatorProfile?.priority ?? 1000;
      const rightPriority = right.operatorProfile?.priority ?? 1000;
      if (leftPriority !== rightPriority) return leftPriority - rightPriority;
      return left.id.localeCompare(right.id);
    });
  }

  applyRuntimeEngineProfile(engine) {
    const profile = this.runtimeEngineProfile(engine.id);
    if (!profile) {
      return {
        ...engine,
        operatorProfile: {
          configured: false,
          disabled: false,
          priority: null,
          defaultLoadOptions: {},
          receiptId: null,
        },
      };
    }
    const disabled = Boolean(profile.disabled);
    return {
      ...engine,
      label: profile.label || engine.label,
      status: disabled ? "disabled" : engine.status,
      selected: disabled ? false : engine.selected,
      operatorProfile: {
        configured: true,
        disabled,
        priority: profile.priority ?? null,
        defaultLoadOptions: profile.defaultLoadOptions ?? {},
        updatedAt: profile.updatedAt ?? null,
        receiptId: profile.receiptId ?? null,
        source: profile.source ?? "operator_runtime_engine_profile",
      },
    };
  }

  runtimeSurvey() {
    const checkedAt = this.nowIso();
    const hardware = hardwareSnapshot();
    const engines = this.listRuntimeEngines();
    const lmStudio = this.lmStudioRuntimeSurvey(checkedAt);
    const runtimePreference = this.runtimePreference();
    const selectedEngines = engines.filter((engine) => engine.selected).map((engine) => engine.id);
    const receipt = this.receipt("runtime_survey", {
      summary: `Runtime survey captured ${engines.length} engine profile${engines.length === 1 ? "" : "s"}.`,
      redaction: "redacted",
      evidenceRefs: [
        "runtime_engine_registry",
        "hardware_snapshot",
        ...(lmStudio.status === "available" ? ["lm_studio_public_lms_runtime_survey"] : []),
      ],
      details: {
        checkedAt,
        engineCount: engines.length,
        selectedEngines,
        runtimePreference,
        hardware,
        lmStudio,
      },
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      checkedAt,
      engines,
      hardware,
      lmStudio,
      runtimePreference,
      receiptId: receipt.id,
    };
  }

  latestRuntimeSurvey() {
    const receipt = [...this.listReceipts()].reverse().find((item) => item.kind === "runtime_survey");
    if (!receipt) {
      return {
        status: "not_checked",
        receiptId: "none",
        checkedAt: null,
        engineCount: this.listRuntimeEngines().length,
        selectedEngines: [],
        runtimePreference: this.runtimePreference(),
        hardware: hardwareSnapshot(),
        lmStudio: { status: "not_checked", evidenceRefs: ["runtime_survey_not_checked"] },
      };
    }
    return {
      status: "checked",
      receiptId: receipt.id,
      checkedAt: receipt.details?.checkedAt ?? receipt.createdAt,
      engineCount: receipt.details?.engineCount ?? 0,
      selectedEngines: receipt.details?.selectedEngines ?? [],
      runtimePreference: receipt.details?.runtimePreference ?? this.runtimePreference(),
      hardware: receipt.details?.hardware ?? hardwareSnapshot(),
      lmStudio: receipt.details?.lmStudio ?? { status: "unknown" },
    };
  }

  lmStudioRuntimeEngines(checkedAt) {
    if (!lmStudioRuntimeDiscoveryEnabled()) return [];
    const provider = this.providers.get("provider.lmstudio");
    const lmsPath =
      provider?.discovery?.publicCli?.path ??
      process.env.IOI_LMS_PATH ??
      path.join(this.homeDir, ".lmstudio/bin/lms");
    if (!lmsPath || !isExecutable(lmsPath)) return [];
    const result = runPublicCommand(lmsPath, ["runtime", "ls"], { timeout: 2500 });
    if (result.status !== 0) return [];
    return parseLmStudioRuntimeEngines(result.stdout).map((engine) => ({
      ...engine,
      checkedAt,
      lmsPathHash: stableHash(lmsPath).slice(0, 16),
      outputHash: stableHash(result.stdout),
      evidenceRefs: ["lm_studio_public_lms_runtime_ls"],
    }));
  }

  lmStudioRuntimeSurvey(checkedAt) {
    if (!lmStudioRuntimeDiscoveryEnabled()) {
      return {
        status: "absent",
        checkedAt,
        evidenceRefs: ["lm_studio_public_runtime_discovery_disabled"],
      };
    }
    const provider = this.providers.get("provider.lmstudio");
    const lmsPath =
      provider?.discovery?.publicCli?.path ??
      process.env.IOI_LMS_PATH ??
      path.join(this.homeDir, ".lmstudio/bin/lms");
    if (!lmsPath || !isExecutable(lmsPath)) {
      return { status: "absent", checkedAt, evidenceRefs: ["lm_studio_public_lms_absent"] };
    }
    const result = runPublicCommand(lmsPath, ["runtime", "survey"], { timeout: 3000 });
    const parsed = parseLmStudioRuntimeSurvey(result.stdout);
    return {
      status: result.status === 0 ? "available" : "blocked",
      checkedAt,
      selectedRuntime: parsed.selectedRuntime,
      accelerators: parsed.accelerators,
      cpu: parsed.cpu,
      ram: parsed.ram,
      outputHash: stableHash(`${result.stdout}\n${result.stderr}`),
      exitCode: result.status,
      lmsPathHash: stableHash(lmsPath).slice(0, 16),
      evidenceRefs: ["lm_studio_public_lms_runtime_survey"],
      errorHash: result.status === 0 ? null : stableHash(result.stderr || result.error || "runtime survey failed"),
    };
  }

  backend(backendId) {
    const backend = this.backendRegistry().find((item) => item.id === backendId);
    if (!backend) throw notFound(`Model backend not found: ${backendId}`, { backendId });
    return backend;
  }

  backendProcessSnapshot(processRecord) {
    if (!processRecord) {
      return {
        status: "not_started",
        processStatus: "not_started",
        evidenceRefs: ["supervisor_process_not_started"],
      };
    }
    return {
      id: processRecord.id,
      backendId: processRecord.backendId,
      backendKind: processRecord.backendKind,
      status: processRecord.status,
      processStatus: processRecord.processStatus ?? processRecord.status,
      pidHash: processRecord.pidHash ?? null,
      pidTracked: processRecord.pidTracked ?? "process_ref_hash",
      supervisorKind: processRecord.supervisorKind ?? null,
      spawned: Boolean(processRecord.spawned),
      spawnStatus: processRecord.spawnStatus ?? null,
      startedAt: processRecord.startedAt ?? null,
      stoppedAt: processRecord.stoppedAt ?? null,
      lastHealthAt: processRecord.lastHealthAt ?? null,
      argsHash: processRecord.argsHash ?? null,
      argsRedacted: processRecord.argsRedacted ?? [],
      startupTimeoutMs: processRecord.startupTimeoutMs ?? null,
      healthProbe: processRecord.healthProbe ?? null,
      stale: Boolean(processRecord.stale),
      staleReason: processRecord.staleReason ?? null,
      evidenceRefs: processRecord.evidenceRefs ?? [],
    };
  }

  backendProcessArgs(backend, { endpoint = null, loadOptions = {} } = {}) {
    const artifactPathHash = endpoint?.artifactPath ? stableHash(endpoint.artifactPath).slice(0, 16) : null;
    const modelArg = endpoint?.modelId ?? "runtime-engine-profile";
    const contextLength = loadOptions.contextLength ?? this.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
    const parallel = loadOptions.parallel ?? this.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
    const gpu = loadOptions.gpu ?? this.runtimeDefaultLoadOptions(backend.id).gpu ?? null;
    const identifier = loadOptions.identifier ?? this.runtimeDefaultLoadOptions(backend.id).identifier ?? null;
    const args = [];
    if (backend.kind === "llama_cpp") {
      args.push("llama-server", "--model", artifactPathHash ? `artifact:${artifactPathHash}` : modelArg);
      if (contextLength) args.push("--ctx-size", String(contextLength));
      if (parallel) args.push("--parallel", String(parallel));
      if (gpu) args.push("--gpu-layers", llamaCppGpuLayersArg(gpu));
    } else if (backend.kind === "vllm") {
      args.push("vllm", "serve", artifactPathHash ? `artifact:${artifactPathHash}` : modelArg);
      if (contextLength) args.push("--max-model-len", String(contextLength));
      if (parallel) args.push("--tensor-parallel-size", String(parallel));
      if (loadOptions.dtype) args.push("--dtype", String(loadOptions.dtype));
      if (loadOptions.gpuMemoryUtilization) args.push("--gpu-memory-utilization", String(loadOptions.gpuMemoryUtilization));
    } else if (backend.kind === "ollama") {
      args.push("ollama", "serve");
    } else if (backend.kind === "native_local") {
      args.push("ioi-native-local-fixture", "--model", modelArg);
      if (contextLength) args.push("--context", String(contextLength));
      if (parallel) args.push("--parallel", String(parallel));
      if (gpu) args.push("--gpu", String(gpu));
    } else {
      args.push(String(backend.kind ?? "backend"), "--model", modelArg);
    }
    if (identifier) args.push("--identifier", stableHash(identifier).slice(0, 12));
    return args;
  }

  backendProcessSpawnArgs(backend, { endpoint = null, loadOptions = {} } = {}) {
    if (backend.kind === "ollama") return ["serve"];
    if (backend.kind === "vllm") {
      const args = ["serve", endpoint?.artifactPath ?? loadOptions.modelPath ?? loadOptions.model_path ?? endpoint?.modelId ?? loadOptions.model ?? "runtime-engine-profile"];
      const bind = backendBindAddress(backend.baseUrl);
      if (bind.host) args.push("--host", bind.host);
      if (bind.port) args.push("--port", String(bind.port));
      const contextLength = loadOptions.contextLength ?? loadOptions.maxModelLen ?? this.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
      const parallel = loadOptions.parallel ?? loadOptions.tensorParallelSize ?? this.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
      if (contextLength) args.push("--max-model-len", String(contextLength));
      if (parallel) args.push("--tensor-parallel-size", String(parallel));
      if (loadOptions.dtype) args.push("--dtype", String(loadOptions.dtype));
      if (loadOptions.gpuMemoryUtilization) args.push("--gpu-memory-utilization", String(loadOptions.gpuMemoryUtilization));
      return args;
    }
    if (backend.kind !== "llama_cpp") return this.backendProcessArgs(backend, { endpoint, loadOptions }).slice(1);
    const args = [];
    const modelPath = endpoint?.artifactPath ?? loadOptions.modelPath ?? loadOptions.model_path ?? null;
    if (modelPath) args.push("--model", modelPath);
    const contextLength = loadOptions.contextLength ?? this.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
    const parallel = loadOptions.parallel ?? this.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
    const gpu = loadOptions.gpu ?? this.runtimeDefaultLoadOptions(backend.id).gpu ?? null;
    if (contextLength) args.push("--ctx-size", String(contextLength));
    if (parallel) args.push("--parallel", String(parallel));
    if (gpu) args.push("--n-gpu-layers", llamaCppGpuLayersArg(gpu));
    const embeddingEnabled = loadOptions.embeddings ?? loadOptions.embedding ?? false;
    if (embeddingEnabled) args.push("--embedding");
    const bind = backendBindAddress(backend.baseUrl);
    if (bind.host) args.push("--host", bind.host);
    if (bind.port) args.push("--port", String(bind.port));
    return args;
  }

  ensureBackendProcess(backendId, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    const backend = this.backend(backendId);
    if (!this.backendSupportsSupervision(backend)) {
      return null;
    }
    const existing = this.backendProcessForBackend(backendId);
    if (existing?.status === "started") {
      return this.touchBackendProcess(existing, { endpoint, loadOptions, reason });
    }
    return this.startBackendProcess(backend, { endpoint, loadOptions, reason });
  }

  backendSupportsSupervision(backend) {
    return ["native_local", "llama_cpp", "ollama", "vllm"].includes(backend.kind);
  }

  touchBackendProcess(processRecord, { endpoint = null, loadOptions = {}, reason = "health_probe" } = {}) {
    const backend = this.backend(processRecord.backendId);
    const argsRedacted = this.backendProcessArgs(backend, { endpoint, loadOptions });
    const updated = {
      ...processRecord,
      status: processRecord.stale ? "stale_recovered" : processRecord.status,
      processStatus: processRecord.stale ? "stale_recovered" : processRecord.processStatus ?? processRecord.status,
      lastHealthAt: this.nowIso(),
      updatedAt: this.nowIso(),
      argsHash: stableHash(argsRedacted.join("\0")),
      argsRedacted,
      reason,
    };
    this.backendProcesses.set(updated.id, updated);
    this.writeMap("backend-processes", this.backendProcesses);
    return this.reconciledBackendProcess(updated);
  }

  startBackendProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    const now = this.nowIso();
    const argsRedacted = this.backendProcessArgs(backend, { endpoint, loadOptions });
    const processRef = `supervised://${safeId(backend.id)}/${crypto.randomUUID()}`;
    const childProcessInfo = this.spawnBackendChildProcess(backend, {
      endpoint,
      loadOptions,
      reason,
      processRef,
      argsRedacted,
    });
    const startupTimeoutMs = Number(loadOptions.startupTimeoutMs ?? process.env.IOI_MODEL_BACKEND_STARTUP_TIMEOUT_MS ?? 15000);
    const processRecord = {
      id: `backend_process_${safeId(backend.id)}_${Date.now()}`,
      backendId: backend.id,
      backendKind: backend.kind,
      status: "started",
      processStatus: "started",
      supervisorKind: backend.kind === "native_local" ? "deterministic_fixture_process" : "external_process",
      bootId: this.bootId,
      processRefHash: stableHash(processRef),
      pidHash: childProcessInfo.pidHash ?? stableHash(processRef).slice(0, 16),
      pidTracked: backend.kind === "native_local" ? "deterministic_fixture_process_ref" : "process_ref_hash",
      spawned: childProcessInfo.spawned,
      spawnStatus: childProcessInfo.status,
      spawnErrorHash: childProcessInfo.errorHash ?? null,
      childProcessKey: childProcessInfo.childProcessKey ?? null,
      baseUrl: backend.baseUrl ?? null,
      binaryPathHash: backend.binaryPath ? stableHash(backend.binaryPath) : null,
      argsRedacted,
      argsHash: stableHash(argsRedacted.join("\0")),
      loadOptions: redact(loadOptions),
      endpointId: endpoint?.id ?? null,
      modelId: endpoint?.modelId ?? null,
      startupTimeoutMs,
      healthProbe: backend.baseUrl ? `${backend.baseUrl}/health`.replace(/\/v1\/health$/, "/health") : "local://health",
      startedAt: now,
      updatedAt: now,
      lastHealthAt: now,
      stoppedAt: null,
      stale: false,
      reason,
      evidenceRefs: [
        "ModelBackendDriver.process_supervision",
        backend.kind === "native_local" ? "deterministic_native_local_fixture_process" : `${backend.kind}_process_supervisor`,
        "bounded_backend_log_capture",
        "startup_timeout_guard",
        ...childProcessInfo.evidenceRefs,
      ],
    };
    this.backendProcesses.set(processRecord.id, processRecord);
    this.writeMap("backend-processes", this.backendProcesses);
    this.writeBackendLog(backend.id, {
      backendId: backend.id,
      event: "backend_process_start",
      backendKind: backend.kind,
      processId: processRecord.id,
      pidHash: processRecord.pidHash,
      argsHash: processRecord.argsHash,
      reason,
    });
    return processRecord;
  }

  spawnBackendChildProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control", processRef, argsRedacted = [] } = {}) {
    if (!["llama_cpp", "ollama", "vllm"].includes(backend.kind)) {
      return { spawned: false, status: "not_required", evidenceRefs: [] };
    }
    if (!backend.binaryPath) {
      return { spawned: false, status: "binary_absent", evidenceRefs: [`${backend.kind}_binary_absent`] };
    }
    if (backend.kind === "llama_cpp" && !endpoint?.artifactPath && !loadOptions.modelPath && !loadOptions.model_path) {
      return {
        spawned: false,
        status: "waiting_for_model",
        evidenceRefs: ["llama_cpp_start_requires_model_artifact"],
      };
    }
    const spawnArgs = this.backendProcessSpawnArgs(backend, { endpoint, loadOptions });
    try {
      const child = childProcess.spawn(backend.binaryPath, spawnArgs, {
        cwd: this.cwd,
        env: {
          ...process.env,
          IOI_MODEL_BACKEND_BASE_URL: backend.baseUrl ?? "",
          IOI_MODEL_BACKEND_REASON: reason,
          ...(backend.kind === "llama_cpp" ? { LD_LIBRARY_PATH: llamaCppLibraryPathEnv(backend.binaryPath, process.env.LD_LIBRARY_PATH) } : {}),
          ...(backend.kind === "ollama" ? { OLLAMA_HOST: backend.baseUrl ?? "http://127.0.0.1:11434" } : {}),
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      const pidHash = stableHash(`${processRef}:${child.pid ?? "unknown"}`).slice(0, 16);
      const processKey = stableHash(`${backend.id}:${pidHash}:${Date.now()}`).slice(0, 16);
      this.backendChildProcesses.set(processKey, child);
      const recordOutput = (stream, chunk) => {
        this.writeBackendLog(backend.id, {
          backendId: backend.id,
          event: `backend_process_${stream}`,
          backendKind: backend.kind,
          pidHash,
          bytes: Buffer.byteLength(chunk),
          outputHash: stableHash(String(chunk)),
          argsHash: stableHash(argsRedacted.join("\0")),
        });
      };
      child.stdout?.on("data", (chunk) => recordOutput("stdout", chunk));
      child.stderr?.on("data", (chunk) => recordOutput("stderr", chunk));
      child.once("exit", (code, signal) => {
        this.backendChildProcesses.delete(processKey);
        const existing = this.backendProcessForBackend(backend.id);
        if (existing?.pidHash !== pidHash || existing.status === "stopped") return;
        const updated = {
          ...existing,
          status: code === 0 ? "exited" : "degraded",
          processStatus: code === 0 ? "exited" : "degraded",
          exitCode: code,
          signal,
          stoppedAt: this.nowIso(),
          updatedAt: this.nowIso(),
          evidenceRefs: [...normalizeScopes(existing.evidenceRefs, []), `${backend.kind}_process_exit_observed`],
        };
        this.backendProcesses.set(updated.id, updated);
        this.writeMap("backend-processes", this.backendProcesses);
        this.writeBackendLog(backend.id, {
          backendId: backend.id,
          event: "backend_process_exit",
          backendKind: backend.kind,
          pidHash,
          exitCode: code,
          signal,
        });
      });
      child.once("error", (error) => {
        this.writeBackendLog(backend.id, {
          backendId: backend.id,
          event: "backend_process_spawn_error",
          backendKind: backend.kind,
          pidHash,
          errorHash: stableHash(error?.message ?? "spawn error"),
        });
      });
      return {
        spawned: true,
        status: "spawned",
        pidHash,
        childProcessKey: processKey,
        evidenceRefs: [`${backend.kind}_binary_spawn`, `${backend.kind}_spawn_args_redacted`],
      };
    } catch (error) {
      return {
        spawned: false,
        status: "spawn_failed",
        errorHash: stableHash(error?.message ?? "spawn failed"),
        evidenceRefs: [`${backend.kind}_binary_spawn_failed`],
      };
    }
  }

  stopBackendProcess(backend, { reason = "runtime_control" } = {}) {
    const existing = this.backendProcessForBackend(backend.id);
    if (!existing) return null;
    const child = existing.childProcessKey ? this.backendChildProcesses.get(existing.childProcessKey) : null;
    if (child && !child.killed) {
      try {
        child.kill("SIGTERM");
      } catch {
        // Stop receipts record intent even if the subprocess has already exited.
      }
    }
    const updated = {
      ...existing,
      status: "stopped",
      processStatus: "stopped",
      stoppedAt: this.nowIso(),
      updatedAt: this.nowIso(),
      reason,
      evidenceRefs: [...normalizeScopes(existing.evidenceRefs, []), "clean_backend_stop"],
    };
    this.backendProcesses.set(updated.id, updated);
    this.writeMap("backend-processes", this.backendProcesses);
    this.writeBackendLog(backend.id, {
      backendId: backend.id,
      event: "backend_process_stop",
      backendKind: backend.kind,
      processId: updated.id,
      pidHash: updated.pidHash,
      reason,
    });
    return updated;
  }

  backendHealth(backendId) {
    const backend = this.backend(backendId);
    const checkedAt = this.nowIso();
    const processRecord = this.backendProcessForBackend(backendId);
    const status =
      backend.status === "blocked" || backend.status === "absent"
        ? backend.status
        : processRecord?.status === "stale_recovered"
          ? "degraded"
          : "available";
    const hardware = hardwareSnapshot();
    const processSnapshot = this.backendProcessSnapshot(processRecord);
    const receipt = this.lifecycleReceipt("backend_health", {
      backendId,
      modelId: backend.label,
      state: status,
      evidenceRefs: backend.evidenceRefs ?? [],
      hardware,
      process: processSnapshot,
    });
    const updated = {
      ...backend,
      status,
      checkedAt,
      lastReceiptId: receipt.id,
      lastHealthReceiptId: receipt.id,
      processStatus: processSnapshot.processStatus,
      process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
    };
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    return updated;
  }

  startBackend(backendId, body = {}) {
    const backend = this.backend(backendId);
    if (backend.status === "blocked" && !backend.binaryPath && !String(backend.baseUrl ?? "").startsWith("local://")) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Backend cannot be started until its binary path or base URL is configured.",
        details: { backendId, backendKind: backend.kind, evidenceRefs: backend.evidenceRefs ?? [] },
      });
    }
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? this.runtimeDefaultLoadOptions(backendId) ?? {});
    const processRecord = this.ensureBackendProcess(backendId, { loadOptions, reason: "backend_start" });
    const processSnapshot = this.backendProcessSnapshot(processRecord);
    const receipt = this.lifecycleReceipt("backend_start", {
      backendId,
      modelId: backend.label,
      state: "available",
      evidenceRefs: backend.evidenceRefs ?? [],
      process: processSnapshot,
    });
    const updated = {
      ...backend,
      status: "available",
      processStatus: processSnapshot.processStatus ?? (backend.processStatus === "stateless_http" ? "stateless_http" : "started"),
      process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
      startedAt: this.nowIso(),
      lastReceiptId: receipt.id,
    };
    if (processRecord?.id) {
      this.backendProcesses.set(processRecord.id, { ...processRecord, lastReceiptId: receipt.id });
      this.writeMap("backend-processes", this.backendProcesses);
    }
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    this.writeBackendLog(backendId, {
      backendId,
      event: "backend_start",
      backendKind: backend.kind,
      receiptId: receipt.id,
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    return updated;
  }

  stopBackend(backendId) {
    const backend = this.backend(backendId);
    const processRecord = this.stopBackendProcess(backend, { reason: "backend_stop" });
    const processSnapshot = this.backendProcessSnapshot(processRecord);
    const receipt = this.lifecycleReceipt("backend_stop", {
      backendId,
      modelId: backend.label,
      state: "stopped",
      evidenceRefs: backend.evidenceRefs ?? [],
      process: processSnapshot,
    });
    const updated = {
      ...backend,
      status: backend.kind === "fixture" ? "available" : "stopped",
      processStatus: backend.kind === "fixture" ? "stateless" : processSnapshot.processStatus ?? "stopped",
      process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
      stoppedAt: this.nowIso(),
      lastReceiptId: receipt.id,
    };
    if (processRecord?.id) {
      this.backendProcesses.set(processRecord.id, { ...processRecord, lastReceiptId: receipt.id });
      this.writeMap("backend-processes", this.backendProcesses);
    }
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    this.writeBackendLog(backendId, {
      backendId,
      event: "backend_stop",
      backendKind: backend.kind,
      receiptId: receipt.id,
    });
    return updated;
  }

  backendLogs(backendId) {
    this.backend(backendId);
    const logDir = path.join(this.stateDir, "backend-logs");
    const records = [];
    for (const filePath of listFiles(logDir, ".jsonl")) {
      for (const line of readLines(filePath)) {
        const record = parseJsonMaybe(line);
        if (record?.backendId === backendId || record?.backend === backendId || filePath.endsWith(`${safeFileName(backendId)}.jsonl`)) {
          records.push(record);
        }
      }
    }
    const resolved = records.sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? ""))).slice(-200);
    this.lifecycleReceipt("backend_logs_read", {
      backendId,
      modelId: this.backend(backendId).label,
      state: "read",
      logCount: resolved.length,
      evidenceRefs: ["backend_log_projection"],
    });
    return resolved;
  }

  writeBackendLog(endpointId, event) {
    const record = {
      id: `backend_log_${crypto.randomUUID()}`,
      endpointId,
      backendId: event.backendId ?? event.backend ?? endpointId,
      createdAt: this.nowIso(),
      ...redact(event),
    };
    const filePath = path.join(this.stateDir, "backend-logs", `${safeFileName(endpointId)}.jsonl`);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`);
    if (record.backendId && record.backendId !== endpointId) {
      const backendPath = path.join(this.stateDir, "backend-logs", `${safeFileName(record.backendId)}.jsonl`);
      fs.appendFileSync(backendPath, `${JSON.stringify(record)}\n`);
    }
    return record;
  }

  driverForProvider(provider) {
    const driver = driverNameForProvider(provider);
    if (driver === "native_local") return new NativeLocalModelProviderDriver();
    if (driver === "lm_studio") return new LmStudioModelProviderDriver({ state: this });
    if (driver === "llama_cpp") return new LlamaCppModelProviderDriver({ state: this });
    if (driver === "ollama") return new OllamaModelProviderDriver();
    if (driver === "vllm") return new VllmModelProviderDriver({ state: this });
    if (driver === "openai_compatible") return new OpenAICompatibleModelProviderDriver({ label: provider.kind });
    return new FixtureModelProviderDriver();
  }
}

function hostedProvider(id, label, apiFormat, secret) {
  return hostedProviderFromRegistry(id, label, apiFormat, secret);
}

function publicProvider(provider, vaultMetadata = null) {
  return publicProviderFromRegistry(provider, vaultMetadata, {
    providerHasVaultRef,
    providerRequiresVaultSecret,
    stableHash,
  });
}

function requiredString(value, field) {
  return requiredStringFromProviderRegistry(value, field, { runtimeError });
}

function optionalString(value) {
  return optionalStringFromProviderRegistry(value);
}
