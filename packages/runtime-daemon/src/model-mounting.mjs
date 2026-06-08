import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import * as routeDecision from "./model-mounting/route-decision.mjs";
import {
  createModelMountAdmissionRunnerFromEnv,
} from "./model-mounting/model-mount-admission-runner.mjs";
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
  bindVaultRef as bindVaultRefState,
  listVaultRefs as listVaultRefsState,
  removeVaultRef as removeVaultRefState,
  vaultHealth as vaultHealthState,
  vaultRefMetadata as vaultRefMetadataState,
  vaultStatus as vaultStatusState,
} from "./model-mounting/vault-operations.mjs";
import {
  authorize as authorizeState,
  createToken as createTokenState,
  listTokens as listTokensState,
  revokeToken as revokeTokenState,
} from "./model-mounting/capability-token-operations.mjs";
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
  getModel as getModelState,
  instance as instanceState,
  modelForProviderMount as modelForProviderMountState,
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
import { enrichCatalogEntry } from "./model-mounting/catalog-entries.mjs";
import {
  catalogSearch as catalogSearchState,
  catalogStatus as catalogStatusState,
  enrichCatalogEntryForState,
  storageSummary as storageSummaryState,
} from "./model-mounting/catalog-operations.mjs";
import {
  searchHuggingFaceCatalog as searchHuggingFaceCatalogState,
} from "./model-mounting/huggingface-catalog-search.mjs";
import {
  catalogImportUrl as catalogImportUrlState,
  downloadModel as downloadModelState,
} from "./model-mounting/catalog-download-operations.mjs";
import { discoverAutopilotLlamaServer, llamaCppLibraryPathEnv } from "./model-mounting/local-runtime-engines.mjs";
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
} from "./model-mounting/catalog-provider-config.mjs";
import {
  catalogProviderConfig as catalogProviderConfigState,
  catalogProviderRuntimeMaterial as catalogProviderRuntimeMaterialState,
  configureCatalogProvider as configureCatalogProviderState,
  getCatalogProviderConfig as getCatalogProviderConfigState,
  listCatalogProviderConfigs as listCatalogProviderConfigsState,
} from "./model-mounting/catalog-provider-configuration-operations.mjs";
import {
  customHttpCatalogProviderPort,
  fixtureCatalogProviderPort,
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
  backendProcessSnapshot as backendProcessSnapshotState,
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
  fileSizeIfExists,
  normalizeNonNegativeInteger,
  truthy,
  matchesAny,
  publicMcpServer,
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
import { publicCatalogProviderConfig } from "./model-mounting/catalog-projections.mjs";
import {
  catalogProviderStatus,
  modelCatalogProviderPorts as buildModelCatalogProviderPorts,
} from "./model-mounting/catalog-registry.mjs";
import {
  internalFixtureModelsEnabled,
  lmStudioPublicCliEnabled,
  lmStudioRuntimeDiscoveryEnabled,
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
  writeModelMountingMap,
  writeModelMountingVaultRefs,
} from "./model-mounting/state-persistence.mjs";
import {
  validateContinuationSafety as validateContinuationSafetyRule,
  validateReceiptGate as validateReceiptGateRule,
} from "./model-mounting/validation.mjs";
import {
  endpointIdsForExplicitModelForState,
  routeSelectionReceiptForState,
  selectRouteForState,
  testRoute as testRouteState,
  upsertRoute as upsertRouteState,
} from "./model-mounting/routes.mjs";
import {
  getReceipt as getReceiptState,
  lifecycleReceipt as lifecycleReceiptState,
  listReceipts as listReceiptsState,
  receipt as receiptState,
} from "./model-mounting/receipt-operations.mjs";

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
  constructor({
    stateDir,
    cwd,
    homeDir,
    now = () => new Date(),
    vaultSecrets = {},
    modelMountAdmissionRunner = null,
    commitRuntimeModelMountRecordState = null,
    commitRuntimeModelMountReceiptState = null,
  }) {
    this.stateDir = path.resolve(stateDir);
    this.cwd = path.resolve(cwd ?? process.cwd());
    this.homeDir = path.resolve(homeDir ?? process.env.HOME ?? this.cwd);
    this.modelRoot = path.join(this.stateDir, "models");
    this.bootId = `daemon_boot_${crypto.randomUUID()}`;
    this.now = now;
    this.modelMountAdmissionRunner =
      modelMountAdmissionRunner ?? createModelMountAdmissionRunnerFromEnv(process.env);
    this.commitRuntimeModelMountRecordState = commitRuntimeModelMountRecordState;
    this.store = new AgentgresModelMountingStore({
      stateDir: this.stateDir,
      commitRuntimeModelMountReceiptState,
    });
    this.walletAuthority = new AgentgresWalletAuthority({
      now: this.now,
    });
    this.vault = new AgentgresVaultPort({
      now: this.now,
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
      capabilityForWorkflowNode,
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
    this.writeProjection();
  }

  writeMap(dir, map) {
    return writeModelMountingMap(this, dir, map);
  }

  writeVaultRefs() {
    return writeModelMountingVaultRefs(this);
  }

  serverStatus(baseUrl) {
    return serverControl.serverStatus(this, baseUrl, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverControlState() {
    return serverControl.serverControlState(this, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  writeServerControlState(state) {
    return serverControl.writeServerControlState(this, state);
  }

  serverStart(baseUrl) {
    return serverControl.serverStart(this, baseUrl, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverStop(baseUrl) {
    return serverControl.serverStop(this, baseUrl, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverRestart(baseUrl) {
    return serverControl.serverRestart(this, baseUrl, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  recordServerOperation(operation, status, baseUrl, details = {}) {
    return serverControl.recordServerOperation(this, operation, status, baseUrl, details, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverLogs(query = {}) {
    return serverControl.serverLogs(this, query, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverEvents(query = {}) {
    return serverControl.serverEvents(this, query, { schema_version: MODEL_MOUNT_SCHEMA_VERSION });
  }

  serverLogRecords({ limit = 80 } = {}) {
    return serverControl.serverLogRecords(this, { limit });
  }

  writeServerLog(event) {
    return serverControl.writeServerLog(this, event);
  }

  runtimeModelCatalogList() {
    return this.readProjectionFacade.runtimeModelCatalogList(this);
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
    return this.readProjectionFacade.latestProviderHealth(this, providerId);
  }

  latestVaultHealth() {
    return this.readProjectionFacade.latestVaultHealth(this);
  }

  workflowNodeBindings() {
    return this.readProjectionFacade.workflowNodeBindings(this);
  }

  getModel(id) {
    return getModelState(this, id, { notFound });
  }

  modelForProviderMount(modelId, provider, body = {}, now = this.nowIso()) {
    return modelForProviderMountState(this, modelId, provider, body, now, {
      driverNameForProvider,
      normalizeScopes,
      safeId,
    });
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
    return listCatalogProviderConfigsState(this);
  }

  getCatalogProviderConfig(providerId) {
    return getCatalogProviderConfigState(this, providerId);
  }

  configureCatalogProvider(providerId, body = {}) {
    return configureCatalogProviderState(this, providerId, body);
  }

  startCatalogProviderOAuth(providerId, body = {}) {
    return startCatalogProviderOAuthState(this, providerId, body, {
      assertConfigurableCatalogProvider,
      catalogProviderStatus,
      publicCatalogProviderConfig,
    });
  }

  async completeCatalogProviderOAuth(providerId, body = {}) {
    return completeCatalogProviderOAuthState(this, providerId, body, {
      assertConfigurableCatalogProvider,
      catalogProviderStatus,
      publicCatalogProviderConfig,
      requiredString,
      stableHash,
    });
  }

  async exchangeCatalogProviderOAuth(providerId, body = {}) {
    return exchangeCatalogProviderOAuthState(this, providerId, body, {
      assertConfigurableCatalogProvider,
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
    return catalogProviderConfigState(this, providerId);
  }

  catalogProviderRuntimeMaterial(providerId) {
    return catalogProviderRuntimeMaterialState(this, providerId);
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
    return searchHuggingFaceCatalogState(this, { query, format, quantization, limit, searchedAt });
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
    return bindVaultRefState(this, body, { requiredString });
  }

  listVaultRefs() {
    return listVaultRefsState(this);
  }

  vaultRefMetadata(body = {}) {
    return vaultRefMetadataState(this, body, { requiredString });
  }

  vaultStatus() {
    return vaultStatusState(this);
  }

  vaultHealth() {
    return vaultHealthState(this);
  }

  removeVaultRef(body = {}) {
    return removeVaultRefState(this, body, { requiredString });
  }

  createToken(body = {}) {
    return createTokenState(this, body);
  }

  listTokens() {
    return listTokensState(this);
  }

  revokeToken(tokenId) {
    return revokeTokenState(this, tokenId);
  }

  authorize(authorization, requiredScope) {
    return authorizeState(this, authorization, requiredScope);
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
    return upsertRouteState(this, body, { normalizeScopes, safeId });
  }

  routeSelectionReceipt(selection, { body = {}, capability = "chat", responseId = null, previousResponseId = null, evidenceRefs = [] } = {}) {
    return routeSelectionReceiptForState(this, selection, {
      body,
      capability,
      evidenceRefs,
      previousResponseId,
      responseId,
    }, {
      routeDecision,
      stableHash,
    });
  }

  nextReceiptId(kind) {
    return `receipt_${kind}_${crypto.randomUUID()}`;
  }

  agentgresModelMountingHead() {
    const sequence = this.listReceipts().length;
    return this.modelMountAdmissionRunner.planAcceptedReceiptHead({
      schema_version: "ioi.model_mount.accepted_receipt_head.v1",
      sequence,
    });
  }

  admitModelMountRouteDecision(request) {
    return this.modelMountAdmissionRunner.admitRouteDecision(request);
  }

  admitModelMountInvocation(request) {
    return this.modelMountAdmissionRunner.admitInvocation(request);
  }

  admitModelMountProviderExecution(request) {
    return this.modelMountAdmissionRunner.admitProviderExecution(request);
  }

  planModelMountAcceptedReceiptTransition(request) {
    return this.modelMountAdmissionRunner.planAcceptedReceiptTransition(request);
  }

  executeModelMountProviderInvocation(request) {
    return this.modelMountAdmissionRunner.executeProviderInvocation(request);
  }

  executeModelMountProviderStreamInvocation(request) {
    return this.modelMountAdmissionRunner.executeProviderStreamInvocation(request);
  }

  planModelMountProviderLifecycle(request) {
    return this.modelMountAdmissionRunner.planProviderLifecycle(request);
  }

  planModelMountProviderInventory(request) {
    return this.modelMountAdmissionRunner.planProviderInventory(request);
  }

  planModelMountInstanceLifecycle(request) {
    return this.modelMountAdmissionRunner.planInstanceLifecycle(request);
  }

  admitModelMountProviderResult(request) {
    return this.modelMountAdmissionRunner.admitProviderResult(request);
  }

  bindModelMountInvocationReceipt(request) {
    return this.modelMountAdmissionRunner.bindInvocationReceipt(request);
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

  recordModelStreamCompleted({
    invocation,
    streamKind,
    outputText = "",
    providerUsage = null,
    chunksForwarded = 0,
    finishReason = null,
    providerResult = {},
    providerStreamShapeSummary = null,
  }) {
    return recordModelStreamCompletedState(this, {
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded,
      finishReason,
      providerResult,
      providerStreamShapeSummary,
    }, {
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
    return listReceiptsState(this);
  }

  getReceipt(receiptId) {
    return getReceiptState(this, receiptId);
  }

  lifecycleReceipt(operation, details) {
    return lifecycleReceiptState(this, operation, details);
  }

  receipt(kind, { id, summary, redaction, evidenceRefs, details }) {
    return receiptState(this, kind, { id, summary, redaction, evidenceRefs, details }, {
      randomUUID: () => crypto.randomUUID(),
      redact,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    });
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
    return endpointIdsForExplicitModelForState(this, route, modelId, { normalizeScopes });
  }

  selectRoute({ modelId, routeId, capability, policy }) {
    return selectRouteForState(this, { modelId, routeId, capability, policy }, {
      isAutoModelSelector: routeDecision.isAutoModelSelector,
      isFixtureEndpointCandidate,
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
      schema_version: MODEL_MOUNT_SCHEMA_VERSION,
    });
  }

  updateRuntimeEngine(engineId, body = {}) {
    return updateRuntimeEngineState(this, engineId, body, {
      normalizeRuntimeEngineDefaultLoadOptions,
      notFound,
      schema_version: MODEL_MOUNT_SCHEMA_VERSION,
      stableHash,
    });
  }

  removeRuntimeEngineOverride(engineId) {
    return removeRuntimeEngineOverrideState(this, engineId, {
      notFound,
      safeFileName,
      schema_version: MODEL_MOUNT_SCHEMA_VERSION,
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

  backendProcessPlan(backend, { endpoint = null, loadOptions = {} } = {}) {
    const defaults = this.runtimeDefaultLoadOptions(backend.id);
    const request = {
      schema_version: "ioi.model_mount.backend_process_plan.v1",
      backend_ref: backend.id,
      backend_kind: backend.kind,
      base_url: backend.baseUrl ?? null,
      model_ref: endpoint?.modelId ?? loadOptions.model ?? null,
      artifact_path: endpoint?.artifactPath ?? null,
      binary_configured: Boolean(backend.binaryPath),
      load_options: {
        context_length: loadOptions.context_length ?? defaults.context_length ?? null,
        max_model_len: loadOptions.max_model_len ?? null,
        parallel: loadOptions.parallel ?? defaults.parallel ?? null,
        tensor_parallel_size: loadOptions.tensor_parallel_size ?? null,
        gpu: loadOptions.gpu ?? defaults.gpu ?? null,
        dtype: loadOptions.dtype ?? null,
        gpu_memory_utilization: loadOptions.gpu_memory_utilization ?? null,
        identifier: loadOptions.identifier ?? defaults.identifier ?? null,
        embeddings: Boolean(loadOptions.embeddings ?? false),
        model_path: loadOptions.model_path ?? null,
        model: loadOptions.model ?? null,
      },
    };
    return this.modelMountAdmissionRunner.planBackendProcess(request);
  }

  backendProcessArgs(backend, options = {}) {
    return this.backendProcessPlan(backend, options).public_args;
  }

  backendProcessSpawnArgs(backend, options = {}) {
    return this.backendProcessPlan(backend, options).spawn_args;
  }

  ensureBackendProcess(backendId, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    return ensureBackendProcessState(this, backendId, { endpoint, loadOptions, reason });
  }

  backendSupportsSupervision(backend) {
    return this.backendProcessPlan(backend).supports_supervision;
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
