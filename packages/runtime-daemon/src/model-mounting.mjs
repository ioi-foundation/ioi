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
  createModelMountingReadProjectionFacade,
} from "./model-mounting/read-projection-facade.mjs";
import {
  isFixtureEndpointCandidate,
  isFixtureModelRecord,
} from "./model-mounting/fixture-policy.mjs";
import {
  destructiveConfirmationState,
  inferModelArchitecture,
  inferParameterCount,
  importTargetPath,
  listModelFiles,
  materializeImportArtifact,
  normalizeImportMode,
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
  invokeModel as invokeModelState,
  startModelStream as startModelStreamState,
} from "./model-mounting/model-invocation-operations.mjs";
import {
  endpoint as endpointState,
  ensureLoaded as ensureLoadedState,
  instance as instanceState,
  provider as providerState,
  resolveEndpoint as resolveEndpointState,
  route as routeState,
} from "./model-mounting/state-accessors.mjs";
import {
  backendProcessForBackend as backendProcessForBackendState,
  backendRegistry as backendRegistryState,
  deriveBackendRegistry as deriveBackendRegistryState,
  listBackendProcesses as listBackendProcessesState,
  reconciledBackendProcess as reconciledBackendProcessState,
  seedBackends as seedBackendsState,
  writeBackendLog as writeBackendLogState,
} from "./model-mounting/backend-registry-state.mjs";
import {
  enrichCatalogEntry,
  huggingFaceCatalogEntries,
} from "./model-mounting/catalog-entries.mjs";
import {
  catalogSearch as catalogSearchState,
  catalogStatus as catalogStatusState,
  enrichCatalogEntryForState,
  storageSummary as storageSummaryState,
} from "./model-mounting/catalog-operations.mjs";
import {
  catalogImportUrl as catalogImportUrlState,
  downloadModel as downloadModelState,
} from "./model-mounting/catalog-download-operations.mjs";
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
import { createProviderRegistryBindings } from "./model-mounting/provider-registry-bindings.mjs";
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
} from "./model-mounting/provider-driver-helpers.mjs";
import {
  driverForProvider as driverForProviderState,
} from "./model-mounting/provider-driver-factory.mjs";
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
import { AgentgresWalletAuthority } from "./model-mounting/wallet-authority.mjs";
import {
  AgentgresVaultPort,
  configuredVaultMaterialAdapter,
} from "./model-mounting/vault-port.mjs";
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
  materializeLiveDownloadAttempt,
  writeDownloadResumeMetadata,
  isRetriableDownloadFailure,
  downloadRetryBackoffMs,
  cleanupPartialDownload,
} from "./model-mounting/download-helpers.mjs";
import {
  catalogAuthFailureFields,
  catalogAuthFailureStatus,
  catalogAuthProviderFields,
  catalogEntryWithAuth,
  catalogProviderConfigHealthFields,
  publicCatalogProviderConfig,
} from "./model-mounting/catalog-projections.mjs";
import {
  catalogProviderStatus,
  modelCatalogProviderPorts as buildModelCatalogProviderPorts,
} from "./model-mounting/catalog-registry.mjs";
import {
  internalFixtureModelsEnabled,
  liveModelCatalogEnabled,
  lmStudioPublicCliEnabled,
  lmStudioRuntimeDiscoveryEnabled,
  modelCatalogTimeoutMs,
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
  testRoute as testRouteState,
  upsertRouteRecord,
} from "./model-mounting/routes.mjs";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1", SECRET_REDACTION = "[REDACTED]";
const {
  hostedProvider,
  optionalString,
  publicProvider,
  requiredString,
} = createProviderRegistryBindings({
  providerHasVaultRef,
  providerRequiresVaultSecret,
  runtimeError,
  stableHash,
});

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
    this.readProjectionFacade = createModelMountingReadProjectionFacade({
      buildModelCapabilities,
      internalFixtureModelsEnabled,
      isFixtureModelRecord,
      listJson,
      modelMountSchemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      path,
      providerHasVaultRef,
      publicOAuthSession,
      publicOAuthState,
      publicProvider,
      readJson,
    });
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
    return this.readProjectionFacade.legacyModelList(this);
  }

  openAiModelList() {
    return this.readProjectionFacade.openAiModelList(this);
  }

  listArtifacts() {
    return this.readProjectionFacade.listArtifacts(this);
  }

  listProductArtifacts() {
    return this.readProjectionFacade.listProductArtifacts(this);
  }

  listProviders() {
    return this.readProjectionFacade.listProviders(this);
  }

  listEndpoints() {
    return this.readProjectionFacade.listEndpoints(this);
  }

  listInstances() {
    return this.readProjectionFacade.listInstances(this);
  }

  listRoutes() {
    return this.readProjectionFacade.listRoutes(this);
  }

  listModelCapabilities() {
    return this.readProjectionFacade.listModelCapabilities(this);
  }

  listDownloads() {
    return this.readProjectionFacade.listDownloads(this);
  }

  listOAuthSessions() {
    return this.readProjectionFacade.listOAuthSessions(this);
  }

  listOAuthStates() {
    return this.readProjectionFacade.listOAuthStates(this);
  }

  listProviderHealth() {
    return this.readProjectionFacade.listProviderHealth(this);
  }

  snapshot(baseUrl) {
    return this.readProjectionFacade.snapshot(this, baseUrl);
  }

  authoritySnapshot(baseUrl) {
    return this.readProjectionFacade.authoritySnapshot(this, baseUrl);
  }

  projectionSummary() {
    return this.readProjectionFacade.projectionSummary(this);
  }

  projection() {
    return this.readProjectionFacade.projection(this);
  }

  adapterBoundaries() {
    return this.readProjectionFacade.adapterBoundaries(this);
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
    return this.readProjectionFacade.receiptReplay(this, receiptId);
  }

  modelRouteDecisions() {
    return this.readProjectionFacade.modelRouteDecisions(this);
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
    return catalogImportUrlState(this, body, {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
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
    return downloadModelState(this, body);
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
    return testRouteState(this, routeId, body);
  }

  async invokeModel({ authorization, requiredScope, kind, body = {} }) {
    return invokeModelState(this, { authorization, requiredScope, kind, body });
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
    return startModelStreamState(this, { authorization, requiredScope, kind, body });
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
    return seedBackendsState(this, checkedAt);
  }

  backendRegistry() {
    return backendRegistryState(this);
  }

  deriveBackendRegistry(checkedAt) {
    return deriveBackendRegistryState(this, checkedAt, {
      backendRegistryRecords,
      discoverAutopilotLlamaServer,
      findExecutable,
      hardwareSnapshot,
      processEnv: process.env,
    });
  }

  listBackends() {
    return this.backendRegistry();
  }

  listBackendProcesses() {
    return listBackendProcessesState(this);
  }

  backendProcessForBackend(backendId) {
    return backendProcessForBackendState(this, backendId);
  }

  reconciledBackendProcess(processRecord) {
    return reconciledBackendProcessState(this, processRecord, { normalizeScopes });
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
    return writeBackendLogState(this, endpointId, event, {
      randomUUID: () => crypto.randomUUID(),
      redact,
      safeFileName,
    });
  }

  driverForProvider(provider) {
    return driverForProviderState(this, provider);
  }
}
