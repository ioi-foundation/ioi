import crypto from "node:crypto";
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
  importModel as importModelState,
  mountEndpoint as mountEndpointState,
  unmountEndpoint as unmountEndpointState,
} from "./model-mounting/artifact-endpoint-operations.mjs";
import {
  loadEstimate as loadEstimateState,
  loadModel as loadModelState,
  unloadModel as unloadModelState,
} from "./model-mounting/model-loading-operations.mjs";
import {
  cancelDownload as cancelDownloadState,
  cleanupModelStorage as cleanupModelStorageState,
  deleteModelArtifact as deleteModelArtifactState,
  downloadStatus as downloadStatusState,
} from "./model-mounting/storage-operations.mjs";
import {
  contextWindowForEndpoint as contextWindowForEndpointState,
  countModelTokens as countModelTokensState,
  fitModelContext as fitModelContextState,
  modelTokenizerUtility as modelTokenizerUtilityState,
  tokenizeModel as tokenizeModelState,
} from "./model-mounting/tokenizer-operations.mjs";
import {
  compileEphemeralMcpIntegrations as compileEphemeralMcpIntegrationsState,
  executeWorkflowNode as executeWorkflowNodeState,
  importMcpJson as importMcpJsonState,
  invokeMcpTool as invokeMcpToolState,
  listMcpServers as listMcpServersState,
  normalizeMcpServer as normalizeMcpServerState,
} from "./model-mounting/mcp-workflow-operations.mjs";
import {
  conversationState as conversationStateRecord,
  listConversations as listConversationsState,
  nextResponseId as nextResponseIdState,
  recordConversationState as recordConversationStateRecord,
  recordModelStreamCompleted as recordModelStreamCompletedState,
} from "./model-mounting/conversation-operations.mjs";
import {
  endpoint as endpointState,
  ensureLoaded as ensureLoadedState,
  instance as instanceState,
  provider as providerState,
  resolveEndpoint as resolveEndpointState,
  route as routeState,
} from "./model-mounting/state-accessors.mjs";
import {
  catalogVariantForSource,
  enrichCatalogEntry,
  huggingFaceCatalogEntries,
} from "./model-mounting/catalog-entries.mjs";
import {
  catalogSearch as catalogSearchState,
  catalogStatus as catalogStatusState,
  enrichCatalogEntryForState,
  storageSummary as storageSummaryState,
} from "./model-mounting/catalog-operations.mjs";
import { backendBindAddress, discoverAutopilotLlamaServer, llamaCppGpuLayersArg, llamaCppLibraryPathEnv } from "./model-mounting/local-runtime-engines.mjs";
import {
  providerHealthFailureStatus,
} from "./model-mounting/provider-transport-policy.mjs";
import {
  listProviderLoaded as listProviderLoadedState,
  listProviderModels as listProviderModelsState,
  normalizeProviderSecretRef as normalizeProviderSecretRefState,
  providerHealth as providerHealthState,
  startProvider as startProviderState,
  stopProvider as stopProviderState,
  upsertProvider as upsertProviderState,
} from "./model-mounting/provider-operations.mjs";
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
  completeCatalogProviderOAuth as completeCatalogProviderOAuthState,
  exchangeCatalogProviderOAuth as exchangeCatalogProviderOAuthState,
  refreshCatalogProviderOAuth as refreshCatalogProviderOAuthState,
  revokeCatalogProviderOAuth as revokeCatalogProviderOAuthState,
  startCatalogProviderOAuth as startCatalogProviderOAuthState,
} from "./model-mounting/catalog-provider-oauth.mjs";
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
  coalesceLoadedInstances as coalesceLoadedInstancesState,
  evictExpiredInstances as evictExpiredInstancesState,
  loadedInstanceForEndpoint as loadedInstanceForEndpointState,
  supersedeLoadedInstances as supersedeLoadedInstancesState,
} from "./model-mounting/loaded-instances.mjs";
import {
  applyRuntimeEngineProfile as applyRuntimeEngineProfileState,
  listRuntimeEngineProfiles as listRuntimeEngineProfilesState,
  listRuntimeEngines as listRuntimeEnginesState,
  removeRuntimeEngineOverride as removeRuntimeEngineOverrideState,
  runtimeDefaultLoadOptions as runtimeDefaultLoadOptionsState,
  runtimeEngine as runtimeEngineState,
  runtimeEngineProfile as runtimeEngineProfileState,
  runtimePreference as runtimePreferenceState,
  runtimePreferenceForEndpoint as runtimePreferenceForEndpointState,
  selectRuntimeEngine as selectRuntimeEngineState,
  updateRuntimeEngine as updateRuntimeEngineState,
} from "./model-mounting/runtime-engines.mjs";
import {
  latestRuntimeSurvey as latestRuntimeSurveyState,
  lmStudioRuntimeEngines as lmStudioRuntimeEnginesState,
  lmStudioRuntimeSurvey as lmStudioRuntimeSurveyState,
  runtimeSurvey as runtimeSurveyState,
} from "./model-mounting/runtime-survey.mjs";
import {
  backend as backendState,
  backendProcessArgs as backendProcessArgsState,
  backendProcessSnapshot as backendProcessSnapshotState,
  backendProcessSpawnArgs as backendProcessSpawnArgsState,
  backendSupportsSupervision as backendSupportsSupervisionState,
} from "./model-mounting/backend-processes.mjs";
import {
  backendHealth as backendHealthState,
  backendLogs as backendLogsState,
  ensureBackendProcess as ensureBackendProcessState,
  spawnBackendChildProcess as spawnBackendChildProcessState,
  startBackend as startBackendState,
  startBackendProcess as startBackendProcessState,
  stopBackend as stopBackendState,
  stopBackendProcess as stopBackendProcessState,
  touchBackendProcess as touchBackendProcessState,
} from "./model-mounting/backend-lifecycle.mjs";
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
import {
  backendRegistryRecords,
  defaultRouteRecords,
  lmStudioDetectedArtifactRecord,
  localFixtureArtifactRecords,
  localFixtureEndpointRecord,
  localFolderProviderRecord,
  nativeFixtureEndpointRecord,
  nativeLocalProviderRecord,
  runtimeProviderRecords,
} from "./model-mounting/default-records.mjs";
import {
  discoverLmStudioArtifacts as discoverLmStudioArtifactsState,
  discoverLmStudioProvider as discoverLmStudioProviderState,
  ensureNativeLocalFixtureArtifact as ensureNativeLocalFixtureArtifactState,
  pruneInternalFixtureProjectionRecords as pruneInternalFixtureProjectionRecordsState,
  pruneLmStudioPublicProjectionRecords as pruneLmStudioPublicProjectionRecordsState,
} from "./model-mounting/default-discovery.mjs";
import { seedModelMountingDefaults } from "./model-mounting/state-seeding.mjs";
import {
  loadModelMountingMap,
  loadModelMountingMaps,
  writeAllModelMountingMaps,
  writeModelMountingMap,
  writeModelMountingVaultRefs,
} from "./model-mounting/state-persistence.mjs";
import {
  validateContinuationSafety as validateContinuationSafetyRule,
  validateReceiptGate as validateReceiptGateRule,
} from "./model-mounting/validation.mjs";
import {
  endpointIdsForExplicitModel as endpointIdsForExplicitModelRule,
  routeSelectionReceipt as routeSelectionReceiptRule,
  selectRoute as selectRouteRule,
  upsertRouteRecord,
} from "./model-mounting/routes.mjs";

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
    return loadModelMountingMaps(this, { listJson, readJson });
  }

  loadMap(dir, map) {
    return loadModelMountingMap(this, dir, map, { listJson, readJson });
  }

  seedDefaults() {
    return seedModelMountingDefaults(this, {
      defaultRouteRecords,
      discoverAutopilotLlamaServer,
      env: process.env,
      findExecutable,
      hostedProvider,
      internalFixtureModelsEnabled,
      lmStudioDetectedArtifactRecord,
      localFixtureArtifactRecords,
      localFixtureEndpointRecord,
      localFolderProviderRecord,
      nativeFixtureEndpointRecord,
      nativeLocalProviderRecord,
      runtimeProviderRecords,
      stableHash,
    });
  }

  ensureNativeLocalFixtureArtifact(checkedAt) {
    return ensureNativeLocalFixtureArtifactState(this, checkedAt, {
      fileSha256,
      parseLocalModelMetadata,
    });
  }

  upsertDefault(map, record) {
    if (!map.has(record.id)) {
      map.set(record.id, record);
    }
  }

  discoverLmStudioProvider(checkedAt) {
    return discoverLmStudioProviderState(this, checkedAt, {
      env: process.env,
      isExecutable,
      lmStudioPublicCliEnabled,
      runPublicCommand,
      truncate,
    });
  }

  discoverLmStudioArtifacts(provider, checkedAt) {
    return discoverLmStudioArtifactsState(this, provider, checkedAt, {
      lmStudioArtifact,
      lmStudioPublicCliEnabled,
      parseLmStudioList,
      runPublicCommand,
    });
  }

  pruneLmStudioPublicProjectionRecords() {
    return pruneLmStudioPublicProjectionRecordsState(this);
  }

  pruneInternalFixtureProjectionRecords() {
    return pruneInternalFixtureProjectionRecordsState(this, {
      isFixtureEndpointCandidate,
      isFixtureModelRecord,
    });
  }

  writeAll() {
    return writeAllModelMountingMaps(this);
  }

  writeMap(dir, map) {
    return writeModelMountingMap(this, dir, map);
  }

  writeVaultRefs() {
    return writeModelMountingVaultRefs(this);
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
    return catalogStatusState(this, {
      catalogProviderStatus,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
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
    return startCatalogProviderOAuthState(this, providerId, body, {
      assertConfigurableCatalogProvider,
      catalogProviderConfigUpdate,
      catalogProviderStatus,
      publicCatalogProviderConfig,
    });
  }

  async completeCatalogProviderOAuth(providerId, body = {}) {
    return completeCatalogProviderOAuthState(this, providerId, body, {
      assertConfigurableCatalogProvider,
      catalogProviderConfigUpdate,
      catalogProviderStatus,
      publicCatalogProviderConfig,
      requiredString,
      stableHash,
    });
  }

  async exchangeCatalogProviderOAuth(providerId, body = {}) {
    return exchangeCatalogProviderOAuthState(this, providerId, body, {
      assertConfigurableCatalogProvider,
      catalogProviderConfigUpdate,
      catalogProviderStatus,
      publicCatalogProviderConfig,
    });
  }

  async refreshCatalogProviderOAuth(providerId) {
    return refreshCatalogProviderOAuthState(this, providerId, {
      assertConfigurableCatalogProvider,
      oauthBoundaryForSession,
      publicOAuthSession,
      runtimeError,
      stableHash,
    });
  }

  revokeCatalogProviderOAuth(providerId) {
    return revokeCatalogProviderOAuthState(this, providerId, {
      assertConfigurableCatalogProvider,
      oauthBoundaryForSession,
      publicOAuthSession,
      runtimeError,
      stableHash,
    });
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
    return storageSummaryState(this, {
      env: process.env,
      listModelFiles,
      stableHash,
      statSync: fs.statSync,
    });
  }

  async catalogSearch(query = {}) {
    return catalogSearchState(this, query, {
      catalogProviderStatus,
      normalizeLimit,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
  }

  enrichCatalogEntry(entry, options = {}) {
    return enrichCatalogEntryForState(this, entry, options, {
      enrichCatalogEntry,
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
    return importModelState(this, body, {
      importTargetPath,
      inspectLocalArtifact,
      materializeImportArtifact,
      normalizeImportMode,
      normalizeScopes,
      parseLocalModelMetadata,
      requiredString,
      safeId,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
    });
  }

  mountEndpoint(body = {}) {
    return mountEndpointState(this, body, {
      defaultBackendForProvider,
      driverForProviderKind,
      normalizeLoadPolicy,
      normalizeScopes,
      runtimeError,
      safeId,
    });
  }

  unmountEndpoint(body = {}) {
    return unmountEndpointState(this, body, { requiredString });
  }

  async loadModel(body = {}) {
    return loadModelState(this, body, {
      defaultBackendForProvider,
      driverNameForProvider,
      expiresAt,
      hasExplicitTtlOption,
      normalizeLoadOptions,
      normalizeLoadPolicy,
      safeId,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
  }

  loadEstimate(endpoint, loadOptions = {}, runtimePreference = this.runtimePreference()) {
    return loadEstimateState(this, endpoint, loadOptions, runtimePreference, {
      defaultBackendForProvider,
      estimateNativeLocalResources,
    });
  }

  async unloadModel(body = {}) {
    return unloadModelState(this, body);
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
    return cancelDownloadState(this, jobId, body, {
      cleanupPartialDownload,
      destructiveConfirmationState,
      fileSizeIfExists,
      truthy,
    });
  }

  downloadStatus(jobId) {
    return downloadStatusState(this, jobId, { notFound });
  }

  deleteModelArtifact(id, body = {}) {
    return deleteModelArtifactState(this, id, body, {
      destructiveConfirmationState,
      fileSizeIfExists,
      runtimeError,
      safeFileName,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
      truthy,
    });
  }

  cleanupModelStorage(body = {}) {
    return cleanupModelStorageState(this, body, {
      destructiveConfirmationState,
      fileSizeIfExists,
      listModelFiles,
      runtimeError,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
      truthy,
    });
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
    return upsertProviderState(this, body, {
      driverForProviderKind,
      normalizeProviderAuthHeaderName,
      normalizeProviderAuthScheme,
      normalizeScopes,
      providerRequiresVaultSecret,
      publicProvider,
      safeId,
    });
  }

  normalizeProviderSecretRef(kind, body = {}, existingSecretRef = null) {
    return normalizeProviderSecretRefState(this, kind, body, existingSecretRef, {
      assertNoPlaintextProviderSecret,
      providerRequiresVaultSecret,
      providerSecretInput,
    });
  }

  async providerHealth(providerId) {
    return providerHealthState(this, providerId, {
      normalizeScopes,
      providerHasVaultRef,
      providerHealthFailureStatus,
      publicProvider,
      safeFileName,
      safeId,
      writeJson,
    });
  }

  async listProviderModels(providerId) {
    return listProviderModelsState(this, providerId);
  }

  async listProviderLoaded(providerId) {
    return listProviderLoadedState(this, providerId);
  }

  async startProvider(providerId) {
    return startProviderState(this, providerId, { publicProvider });
  }

  async stopProvider(providerId) {
    return stopProviderState(this, providerId, { publicProvider });
  }

  upsertRoute(body = {}) {
    const route = upsertRouteRecord(body, { normalizeScopes, safeId });
    this.routes.set(route.id, route);
    this.writeMap("model-routes", this.routes);
    return route;
  }

  routeSelectionReceipt(selection, { body = {}, capability = "chat", responseId = null, previousResponseId = null, evidenceRefs = [] } = {}) {
    return routeSelectionReceiptRule({
      body,
      capability,
      evidenceRefs,
      previousResponseId,
      receipt: (kind, payload) => this.receipt(kind, payload),
      responseId,
      routeDecision,
      selection,
      stableHash,
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
    return modelTokenizerUtilityState(this, { authorization, requiredScope, body, operation }, {
      deterministicTokenizeText,
      inputText,
      stableHash,
    });
  }

  tokenizeModel({ authorization, requiredScope = "model.tokenize:*", body = {} }) {
    return tokenizeModelState(this, { authorization, requiredScope, body }, { schemaVersion: MODEL_MOUNT_SCHEMA_VERSION });
  }

  countModelTokens({ authorization, requiredScope = "model.tokenize:*", body = {} }) {
    return countModelTokensState(this, { authorization, requiredScope, body }, {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
    });
  }

  fitModelContext({ authorization, requiredScope = "model.context:*", body = {} }) {
    return fitModelContextState(this, { authorization, requiredScope, body }, {
      normalizeNonNegativeInteger,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
      truncateToEstimatedTokens,
    });
  }

  contextWindowForEndpoint(endpoint, body = {}) {
    return contextWindowForEndpointState(this, endpoint, body);
  }

  nextResponseId(requested) {
    return nextResponseIdState(this, requested, {
      optionalString,
      randomUUID: () => crypto.randomUUID(),
      runtimeError,
    });
  }

  conversationState(responseId) {
    return conversationStateRecord(this, responseId, { runtimeError });
  }

  validateContinuationSafety({ previousState, selection, body = {} }) {
    return validateContinuationSafetyRule({
      body,
      previousState,
      runtimeError,
      selection,
      truthy,
    });
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
    return recordConversationStateRecord(this, {
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
      streamReceiptId,
      status,
      continuationSafety,
    }, { stableHash });
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
    return recordModelStreamCompletedState(this, { invocation, streamKind, outputText, providerUsage, chunksForwarded, finishReason, providerResult }, {
      estimateTokens,
      normalizeUsage,
      stableHash,
    });
  }

  compileEphemeralMcpIntegrations({ authorization, body = {}, input }) {
    return compileEphemeralMcpIntegrationsState(this, { authorization, body, input }, {
      requiredString,
      safeId,
      stableHash,
    });
  }

  importMcpJson(body = {}) {
    return importMcpJsonState(this, body);
  }

  normalizeMcpServer(label, config = {}) {
    return normalizeMcpServerState(this, label, config, {
      normalizeScopes,
      runtimeError,
      safeId,
      secretRedaction: SECRET_REDACTION,
    });
  }

  listMcpServers() {
    return listMcpServersState(this, { publicMcpServer });
  }

  listConversations() {
    return listConversationsState(this);
  }

  invokeMcpTool({ authorization, body = {} }) {
    return invokeMcpToolState(this, { authorization, body }, {
      notFound,
      requiredString,
      runtimeError,
      safeId,
      stableHash,
    });
  }

  async executeWorkflowNode({ authorization, body = {} }) {
    return executeWorkflowNodeState(this, { authorization, body }, {
      capabilityForWorkflowNode,
      nativeInvocationResponseShape,
      requiredString,
      runtimeError,
      workflowKindForNode,
      workflowMemoryOptionsFromBody,
      workflowMemoryWriteBlockReason,
    });
  }

  validateReceiptGate(body = {}) {
    return validateReceiptGateRule({
      body,
      getReceipt: (receiptId) => this.getReceipt(receiptId),
      normalizeScopes,
      receipt: (kind, payload) => this.receipt(kind, payload),
      requiredString,
      runtimeError,
    });
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
    return providerState(this, providerId, { notFound });
  }

  endpoint(endpointId) {
    return endpointState(this, endpointId, { notFound });
  }

  instance(instanceId) {
    return instanceState(this, instanceId, { notFound });
  }

  route(routeId) {
    return routeState(this, routeId, { notFound });
  }

  resolveEndpoint(endpointId, modelId) {
    return resolveEndpointState(this, endpointId, modelId, { runtimeError });
  }

  endpointIdsForExplicitModel(route, modelId) {
    return endpointIdsForExplicitModelRule({
      endpoints: this.endpoints,
      modelId,
      mountEndpoint: (body) => this.mountEndpoint(body),
      normalizeScopes,
      route,
    });
  }

  selectRoute({ modelId, routeId, capability, policy }) {
    return selectRouteRule({
      capability,
      endpoint: (endpointId) => this.endpoint(endpointId),
      endpointIdsForExplicitModel: (route, explicitModelId) => this.endpointIdsForExplicitModel(route, explicitModelId),
      isAutoModelSelector: routeDecision.isAutoModelSelector,
      isFixtureEndpointCandidate,
      modelId,
      policy,
      provider: (providerId) => this.provider(providerId),
      route: (id) => this.route(id),
      routeId,
      routes: this.routes,
      runtimeError,
      truthy,
    });
  }

  async ensureLoaded(endpoint) {
    return ensureLoadedState(this, endpoint, { expiresAt });
  }

  loadedInstanceForEndpoint(endpointId, failIfMissing = true) {
    return loadedInstanceForEndpointState(this, endpointId, failIfMissing, { notFound });
  }

  evictExpiredInstances() {
    return evictExpiredInstancesState(this);
  }

  coalesceLoadedInstances() {
    return coalesceLoadedInstancesState(this);
  }

  supersedeLoadedInstances(endpointId, keepInstanceId) {
    return supersedeLoadedInstancesState(this, endpointId, keepInstanceId);
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
    return backendRegistryRecords({
      checkedAt,
      hardware,
      llamaBinary,
      ollamaBinary,
      providers: this.providers,
      vllmBinary,
    });
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
    return runtimePreferenceState(this);
  }

  runtimePreferenceForEndpoint(endpoint = {}) {
    return runtimePreferenceForEndpointState(this, endpoint);
  }

  runtimeEngineProfile(engineId) {
    return runtimeEngineProfileState(this, engineId);
  }

  listRuntimeEngineProfiles() {
    return listRuntimeEngineProfilesState(this);
  }

  runtimeDefaultLoadOptions(engineId) {
    return runtimeDefaultLoadOptionsState(this, engineId);
  }

  runtimeEngine(engineId) {
    return runtimeEngineState(this, engineId, { notFound });
  }

  selectRuntimeEngine(body = {}) {
    return selectRuntimeEngineState(this, body, {
      notFound,
      requiredString,
      runtimeError,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
  }

  updateRuntimeEngine(engineId, body = {}) {
    return updateRuntimeEngineState(this, engineId, body, {
      normalizeRuntimeEngineDefaultLoadOptions,
      notFound,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
    });
  }

  removeRuntimeEngineOverride(engineId) {
    return removeRuntimeEngineOverrideState(this, engineId, {
      notFound,
      safeFileName,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
    });
  }

  listRuntimeEngines() {
    return listRuntimeEnginesState(this);
  }

  applyRuntimeEngineProfile(engine) {
    return applyRuntimeEngineProfileState(this, engine);
  }

  runtimeSurvey() {
    return runtimeSurveyState(this, {
      hardwareSnapshot,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
  }

  latestRuntimeSurvey() {
    return latestRuntimeSurveyState(this, { hardwareSnapshot });
  }

  lmStudioRuntimeEngines(checkedAt) {
    return lmStudioRuntimeEnginesState(this, checkedAt, {
      env: process.env,
      isExecutable,
      lmStudioRuntimeDiscoveryEnabled,
      parseLmStudioRuntimeEngines,
      runPublicCommand,
      stableHash,
    });
  }

  lmStudioRuntimeSurvey(checkedAt) {
    return lmStudioRuntimeSurveyState(this, checkedAt, {
      env: process.env,
      isExecutable,
      lmStudioRuntimeDiscoveryEnabled,
      parseLmStudioRuntimeSurvey,
      runPublicCommand,
      stableHash,
    });
  }

  backend(backendId) {
    return backendState(this, backendId, { notFound });
  }

  backendProcessSnapshot(processRecord) {
    return backendProcessSnapshotState(processRecord);
  }

  backendProcessArgs(backend, options = {}) {
    return backendProcessArgsState(this, backend, options, {
      llamaCppGpuLayersArg,
      stableHash,
    });
  }

  backendProcessSpawnArgs(backend, options = {}) {
    return backendProcessSpawnArgsState(this, backend, options, {
      backendBindAddress,
      llamaCppGpuLayersArg,
      stableHash,
    });
  }

  ensureBackendProcess(backendId, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    return ensureBackendProcessState(this, backendId, { endpoint, loadOptions, reason });
  }

  backendSupportsSupervision(backend) {
    return backendSupportsSupervisionState(backend);
  }

  touchBackendProcess(processRecord, { endpoint = null, loadOptions = {}, reason = "health_probe" } = {}) {
    return touchBackendProcessState(this, processRecord, { endpoint, loadOptions, reason }, {
      normalizeScopes,
      stableHash,
    });
  }

  startBackendProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    return startBackendProcessState(this, backend, { endpoint, loadOptions, reason }, {
      processEnv: process.env,
      redact,
      safeId,
      stableHash,
    });
  }

  spawnBackendChildProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control", processRef, argsRedacted = [] } = {}) {
    return spawnBackendChildProcessState(this, backend, { endpoint, loadOptions, reason, processRef, argsRedacted }, {
      llamaCppLibraryPathEnv,
      normalizeScopes,
      processEnv: process.env,
      stableHash,
    });
  }

  stopBackendProcess(backend, { reason = "runtime_control" } = {}) {
    return stopBackendProcessState(this, backend, { reason }, { normalizeScopes });
  }

  backendHealth(backendId) {
    return backendHealthState(this, backendId, { hardwareSnapshot });
  }

  startBackend(backendId, body = {}) {
    return startBackendState(this, backendId, body, { normalizeLoadOptions, runtimeError });
  }

  stopBackend(backendId) {
    return stopBackendState(this, backendId);
  }

  backendLogs(backendId) {
    return backendLogsState(this, backendId, {
      listFiles,
      parseJsonMaybe,
      readLines,
      safeFileName,
    });
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
