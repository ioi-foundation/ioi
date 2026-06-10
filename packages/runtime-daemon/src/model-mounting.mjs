import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  createModelMountAdmissionRunnerFromEnv,
} from "./model-mounting/model-mount-admission-runner.mjs";
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
import { discoverAutopilotLlamaServer, llamaCppLibraryPathEnv } from "./model-mounting/local-runtime-engines.mjs";
import {
  hostedProvider,
  optionalString,
  publicProvider as publicProviderFromRegistry,
  requiredString,
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
} from "./model-mounting/provider-auth.mjs";
import {
  MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS,
  assertConfigurableCatalogProvider,
  throwCatalogProviderControlRustCoreRequired,
} from "./model-mounting/catalog-provider-config.mjs";
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
  parseLocalModelMetadata,
  readLines,
  runPublicCommand,
} from "./model-mounting/local-system-probes.mjs";
import {
  defaultBackendForProvider,
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
  removeRuntimeEngineOverride as removeRuntimeEngineOverrideState,
  selectRuntimeEngine as selectRuntimeEngineState,
  updateRuntimeEngine as updateRuntimeEngineState,
} from "./model-mounting/runtime-engines.mjs";
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
  hashToken,
  publicToken,
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
import {
  modelCatalogProviderPorts as buildModelCatalogProviderPorts,
} from "./model-mounting/catalog-registry.mjs";
import {
  internalFixtureModelsEnabled,
  lmStudioPublicCliEnabled,
} from "./model-mounting/environment.mjs";
import {
  backendRegistryRecords,
  defaultRouteRecords,
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
  routeSelectionReceiptForState,
  throwModelRouteControlRustCoreRequired,
  testRoute as testRouteState,
  upsertRoute as upsertRouteState,
} from "./model-mounting/routes.mjs";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1", SECRET_REDACTION = "[REDACTED]";
const MODEL_LIFECYCLE_RECEIPT_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_lifecycle_receipt_js_facade_retired",
  "rust_daemon_core_model_lifecycle_receipt_required",
  "agentgres_model_lifecycle_receipt_truth_required",
];
const MODEL_CONVERSATION_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_conversation_state_js_facade_retired",
  "model_mount_stream_completion_js_facade_retired",
  "rust_daemon_core_model_conversation_required",
  "rust_daemon_core_model_stream_completion_required",
  "agentgres_model_conversation_truth_required",
];
const MCP_WORKFLOW_RUST_CORE_EVIDENCE_REFS = [
  "model_mount_mcp_workflow_js_facade_retired",
  "model_mount_mcp_import_js_facade_retired",
  "model_mount_ephemeral_mcp_registration_js_facade_retired",
  "model_mount_mcp_tool_invocation_js_facade_retired",
  "model_mount_workflow_node_execution_js_facade_retired",
  "model_mount_mcp_workflow_receipt_synthesis_js_retired",
  "model_mount_mcp_workflow_record_state_js_retired",
  "rust_daemon_core_model_mount_mcp_workflow_required",
  "agentgres_mcp_workflow_truth_required",
];
const RETIRED_WORKFLOW_NODE_EXECUTION_REQUEST_ALIASES = [
  "nodeType",
  "modelId",
  "routeId",
  "modelPolicy",
  "maxTokens",
  "workflowGraphId",
  "workflowNodeId",
  "nodeId",
  "node_id",
  "workflowNodeType",
];
const RETIRED_MCP_IMPORT_REQUEST_ALIASES = [
  "mcpJson",
  "mcpServers",
];
const CANONICAL_MCP_IMPORT_REQUEST_FIELDS = [
  "mcp_json",
  "mcp_servers",
  "servers",
];
const RETIRED_EPHEMERAL_MCP_INTEGRATION_ALIASES = [
  "serverLabel",
  "serverUrl",
  "allowedTools",
];
const CANONICAL_EPHEMERAL_MCP_INTEGRATION_FIELDS = [
  "server_label",
  "server_url",
  "allowed_tools",
];
const RETIRED_MCP_TOOL_INVOCATION_REQUEST_ALIASES = [
  "serverId",
  "server_label",
  "serverLabel",
];
const CANONICAL_MCP_TOOL_INVOCATION_REQUEST_FIELDS = [
  "server_id",
  "tool",
  "input",
];
const RETIRED_MCP_SERVER_CONFIG_ALIASES = [
  "serverUrl",
  "allowedTools",
];
const CANONICAL_MCP_SERVER_CONFIG_FIELDS = [
  "url",
  "server_url",
  "allowed_tools",
  "tools",
];
const RETIRED_PROVIDER_UPSERT_REQUEST_ALIASES = [
  "authScheme",
  "authHeaderName",
  "apiFormat",
  "baseUrl",
  "privacyClass",
  "evidenceRefs",
];
const CANONICAL_PROVIDER_UPSERT_REQUEST_FIELDS = [
  "auth_scheme",
  "auth_header_name",
  "api_format",
  "base_url",
  "privacy_class",
  "evidence_refs",
];
const RETIRED_MODEL_STORAGE_REQUEST_ALIASES = [
  "cleanupPartial",
  "dryRun",
  "removeOrphans",
];
const CANONICAL_MODEL_STORAGE_REQUEST_FIELDS = [
  "cleanup_partial",
  "dry_run",
  "remove_orphans",
];
const RETIRED_VAULT_OPERATION_REQUEST_ALIASES = [
  "vaultRef",
  "secret",
  "value",
];
const CANONICAL_VAULT_OPERATION_REQUEST_FIELDS = [
  "vault_ref",
  "material",
];
const RETIRED_MODEL_IMPORT_REQUEST_ALIASES = [
  "modelId",
  "sourcePath",
  "localPath",
  "importMode",
  "providerId",
  "displayName",
  "sizeBytes",
  "contextWindow",
  "privacyClass",
];
const CANONICAL_MODEL_IMPORT_REQUEST_FIELDS = [
  "model_id",
  "source_path",
  "local_path",
  "import_mode",
  "provider_id",
  "display_name",
  "size_bytes",
  "context_window",
  "privacy_class",
];
const RETIRED_ENDPOINT_MOUNT_REQUEST_ALIASES = [
  "modelId",
  "providerId",
  "apiFormat",
  "baseUrl",
  "privacyClass",
  "backendId",
  "loadPolicy",
];
const CANONICAL_ENDPOINT_MOUNT_REQUEST_FIELDS = [
  "model_id",
  "provider_id",
  "api_format",
  "base_url",
  "privacy_class",
  "backend_id",
  "load_policy",
];
const RETIRED_ENDPOINT_UNMOUNT_REQUEST_ALIASES = ["endpointId"];
const CANONICAL_ENDPOINT_UNMOUNT_REQUEST_FIELDS = ["endpoint_id"];
const RETIRED_MODEL_LOADING_REQUEST_ALIASES = [
  "endpointId",
  "modelId",
  "loadPolicy",
  "loadOptions",
  "workflowScope",
  "agentScope",
  "instanceId",
];
const CANONICAL_MODEL_LOADING_REQUEST_FIELDS = [
  "endpoint_id",
  "model_id",
  "load_policy",
  "load_options",
  "workflow_scope",
  "agent_scope",
  "instance_id",
];
const RETIRED_CATALOG_IMPORT_URL_REQUEST_ALIASES = [
  "sourceUrl",
  "modelId",
  "providerId",
  "fileName",
  "fixtureContent",
  "transferApproved",
];
const CANONICAL_CATALOG_IMPORT_URL_REQUEST_FIELDS = [
  "source_url",
  "model_id",
  "provider_id",
  "file_name",
  "fixture_content",
  "transfer_approved",
];
const RETIRED_MODEL_DOWNLOAD_IDENTITY_REQUEST_ALIASES = [
  "modelId",
  "providerId",
  "sourceUrl",
  "sourceLabel",
  "catalogProviderId",
  "fileName",
  "fixtureContent",
];
const CANONICAL_MODEL_DOWNLOAD_IDENTITY_REQUEST_FIELDS = [
  "model_id",
  "provider_id",
  "source_url",
  "source_label",
  "catalog_provider_id",
  "file_name",
  "fixture_content",
];
const RETIRED_MODEL_DOWNLOAD_CONTROL_REQUEST_ALIASES = [
  "bytesTotal",
  "maxBytes",
  "simulateFailure",
  "failureReason",
  "queuedOnly",
  "expectedChecksum",
];
const CANONICAL_MODEL_DOWNLOAD_CONTROL_REQUEST_FIELDS = [
  "bytes_total",
  "max_bytes",
  "simulate_failure",
  "failure_reason",
  "queued_only",
  "expected_checksum",
];
const RETIRED_MODEL_DOWNLOAD_METADATA_REQUEST_ALIASES = [
  "displayName",
  "contextWindow",
  "privacyClass",
];
const CANONICAL_MODEL_DOWNLOAD_METADATA_REQUEST_FIELDS = [
  "display_name",
  "context_window",
  "privacy_class",
];
const RETIRED_MODEL_TOKENIZER_REQUEST_ALIASES = [
  "routeId",
  "modelPolicy",
  "contextLength",
  "contextWindow",
  "maxOutputTokens",
  "reserveOutputTokens",
  "reserve_output_tokens",
];
const MODEL_TOKENIZER_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_tokenizer_js_facade_retired",
  "model_mount_context_fit_js_facade_retired",
  "rust_daemon_core_model_tokenizer_required",
  "rust_daemon_core_model_context_fit_required",
  "agentgres_model_tokenizer_truth_required",
];
function publicProvider(provider, vaultMetadata = null) {
  return publicProviderFromRegistry(provider, vaultMetadata, {
    providerHasVaultRef,
    providerRequiresVaultSecret,
    stableHash,
  });
}

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
      internalFixtureModelsEnabled,
      listJson,
      modelMountSchemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      hardwareSnapshot,
      path,
      readJson,
      readProjectionPlanner: this.modelMountAdmissionRunner,
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
    return this.readProjectionFacade.serverStatus(this, baseUrl);
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
      const plan = this.readProjectionFacade.canonicalProjectionWritePlan(this);
      this.store.writeProjection("model-mounting-canonical", plan.projection, {
        rustProjection: plan,
      });
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
      normalizeScopes,
      safeId,
    });
  }

  catalogStatus() {
    return this.readProjectionFacade.catalogStatus(this);
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
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_configuration.list",
      { configurable_provider_count: MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.length },
    );
  }

  getCatalogProviderConfig(providerId) {
    assertConfigurableCatalogProvider(providerId);
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_configuration.get",
      { provider_id: providerId },
    );
  }

  configureCatalogProvider(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_configuration.write",
      { provider_id: providerId, request_field_count: Object.keys(body ?? {}).length },
    );
  }

  startCatalogProviderOAuth(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_oauth.start",
      { provider_id: providerId, request_field_count: Object.keys(body ?? {}).length },
    );
  }

  async completeCatalogProviderOAuth(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    requiredString(body.state, "state");
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_oauth.callback",
      { provider_id: providerId, state_present: true },
    );
  }

  async exchangeCatalogProviderOAuth(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_oauth.exchange",
      { provider_id: providerId, request_field_count: Object.keys(body ?? {}).length },
    );
  }

  async refreshCatalogProviderOAuth(providerId) {
    assertConfigurableCatalogProvider(providerId);
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_oauth.refresh",
      { provider_id: providerId },
    );
  }

  revokeCatalogProviderOAuth(providerId) {
    assertConfigurableCatalogProvider(providerId);
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_oauth.revoke",
      { provider_id: providerId },
    );
  }

  catalogProviderConfig(providerId) {
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_configuration.read_private",
      { provider_id: providerId },
    );
  }

  catalogProviderRuntimeMaterial(providerId) {
    const existing = this.catalogProviderRuntimeMaterials.get(providerId) ?? null;
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_runtime_material.resolve",
      {
        provider_id: providerId,
        material_vault_ref_hash: existing?.materialVaultRefHash ?? null,
        material_configured: Boolean(
          existing?.manifestPath ||
            existing?.baseUrl ||
            existing?.materialVaultRefHash,
        ),
        runtime_material_status: existing?.runtimeMaterialStatus ?? "rust_core_projection_required",
      },
    );
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
    throw runtimeError({
      status: 501,
      code: "model_catalog_search_js_orchestrator_retired",
      message: "Model catalog search orchestration is retired in JS; use Rust daemon-core catalog search/projection.",
      details: {
        operation_kind: "model_catalog.search",
        rust_core_boundary: "model_mount.catalog_provider_search",
        request_field_count: Object.keys(query ?? {}).length,
        evidence_refs: [
          "model_catalog_search_js_orchestrator_retired",
          "rust_daemon_core_catalog_search_required",
          "agentgres_catalog_projection_required",
        ],
      },
    });
  }

  enrichCatalogEntry(entry, options = {}) {
    void entry;
    void options;
    throwCatalogVariantEnrichmentRetired();
  }

  async catalogImportUrl(body = {}) {
    assertCanonicalCatalogImportUrlRequestBody(body);
    const sourceUrl = requiredString(body.source_url ?? body.url, "source_url");
    throwCatalogDownloadRustCoreRequired(
      "model_mount.catalog.import_url",
      {
        source_url_hash: stableHash(sourceUrl),
        ...(body.model_id ? { model_id: body.model_id } : {}),
        ...(body.provider_id ? { provider_id: body.provider_id } : {}),
      },
    );
  }

  importModel(body = {}) {
    assertCanonicalModelImportRequestBody(body);
    const modelId = requiredString(body.model_id, "model_id");
    throwArtifactEndpointRustCoreRequired("model_mount.artifact.import", { model_id: modelId });
  }

  mountEndpoint(body = {}) {
    assertCanonicalEndpointMountRequestBody(body);
    const modelId = body.model_id;
    if (!modelId) {
      throw runtimeError({
        status: 400,
        code: "model_id_required",
        message: "Mounting a model endpoint requires an explicit model id.",
      });
    }
    throwArtifactEndpointRustCoreRequired("model_mount.endpoint.mount", { model_id: modelId });
  }

  unmountEndpoint(body = {}) {
    assertCanonicalEndpointUnmountRequestBody(body);
    const endpointId = requiredString(body.endpoint_id ?? body.id, "endpoint_id");
    throwArtifactEndpointRustCoreRequired("model_mount.endpoint.unmount", { endpoint_id: endpointId });
  }

  async loadModel(body = {}) {
    assertCanonicalModelLoadingRequestBody(body);
    const endpoint = this.resolveEndpoint(body.endpoint_id, body.model_id);
    const provider = this.provider(endpoint.providerId);
    const loadPolicy = normalizeLoadPolicy(body.load_policy ?? endpoint.loadPolicy);
    const runtimePreference = this.runtimePreferenceForEndpoint(endpoint);
    const requestLoadOptions = body.load_options ?? {};
    const runtimeDefaults = { ...this.runtimeDefaultLoadOptions(runtimePreference.selectedEngineId) };
    if (body.load_policy && !hasExplicitTtlOption(body) && !hasExplicitTtlOption(requestLoadOptions)) {
      delete runtimeDefaults.ttlSeconds;
    }
    const loadOptions = normalizeLoadOptions(
      { ...runtimeDefaults, ...body, ...requestLoadOptions },
      loadPolicy,
    );
    if (loadOptions.ttlSeconds !== null) loadPolicy.idleTtlSeconds = loadOptions.ttlSeconds;
    const estimate = this.loadEstimate(endpoint, loadOptions, runtimePreference);
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const runtimeEngineProfile = this.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null;
    if (loadOptions.estimateOnly) {
      return {
        schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
        status: "estimate_only",
        endpoint_id: endpoint.id,
        model_id: endpoint.modelId,
        provider_id: endpoint.providerId,
        provider_kind: provider.kind,
        backend_id: backendId,
        runtime_engine_id: runtimePreference.selectedEngineId,
        runtime_engine_profile: runtimeEngineProfile,
        load_policy: loadPolicy,
        load_options: loadOptions,
        estimate,
        receipt_id: null,
        evidence_refs: [
          "model_mount_model_loading_js_facade_retired",
          "model_load_estimate_projection_only",
        ],
      };
    }
    throwModelLoadingRustCoreRequired("model_load", provider, {
      operation_kind: "model_mount.instance.load",
      endpoint_id: endpoint.id,
      model_id: endpoint.modelId,
      backend_id: backendId,
    });
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
    assertCanonicalModelLoadingRequestBody(body);
    const instanceId = body.instance_id ?? body.id;
    const instance = instanceId
      ? this.instance(instanceId)
      : this.loadedInstanceForEndpoint(this.resolveEndpoint(body.endpoint_id, body.model_id).id);
    const endpoint = this.endpoint(instance.endpointId);
    const provider = this.provider(instance.providerId);
    throwModelLoadingRustCoreRequired("model_unload", provider, {
      operation_kind: "model_mount.instance.unload",
      instance_id: instance.id,
      endpoint_id: endpoint.id,
      model_id: instance.modelId,
      backend_id: instance.backendId ?? endpoint.backendId ?? null,
    });
  }

  async downloadModel(body = {}) {
    assertCanonicalModelDownloadIdentityRequestBody(body);
    assertCanonicalModelDownloadControlRequestBody(body);
    assertCanonicalModelDownloadMetadataRequestBody(body);
    const modelId = requiredString(body.model_id, "model_id");
    throwCatalogDownloadRustCoreRequired(
      "model_mount.download.queue",
      {
        model_id: modelId,
        ...(body.provider_id ? { provider_id: body.provider_id } : {}),
        ...(body.source_url ? { source_url_hash: stableHash(body.source_url) } : {}),
      },
    );
  }

  cancelDownload(jobId, body = {}) {
    assertCanonicalModelStorageRequestBody(body);
    throwModelStorageRustCoreRequired("model_mount.download.cancel", { job_id: jobId });
  }

  downloadStatus(jobId) {
    const job = this.downloads.get(jobId);
    if (!job) throw notFound(`Download job not found: ${jobId}`, { job_id: jobId });
    return job;
  }

  deleteModelArtifact(id, body = {}) {
    assertCanonicalModelStorageRequestBody(body);
    throwModelStorageRustCoreRequired("model_mount.artifact.delete", { artifact_id: id });
  }

  cleanupModelStorage(body = {}) {
    assertCanonicalModelStorageRequestBody(body);
    throwModelStorageRustCoreRequired("model_mount.storage.cleanup");
  }

  bindVaultRef(body = {}) {
    assertCanonicalVaultOperationRequestBody(body);
    const vaultRef = requiredString(body.vault_ref, "vault_ref");
    const material = requiredString(body.material, "material");
    throwVaultRustCoreRequired(
      "model_mount.vault_ref.bind",
      {
        vault_ref_hash_required: true,
        purpose: body.purpose ?? "operator_provider_auth_binding",
        label: body.label ?? null,
        request_fields: ["vault_ref", "material"],
        vault_ref_present: Boolean(vaultRef),
        material: material ? "[redacted]" : null,
      },
    );
  }

  listVaultRefs() {
    return this.vault.listVaultRefs();
  }

  vaultRefMetadata(body = {}) {
    assertCanonicalVaultOperationRequestBody(body);
    const vaultRef = requiredString(body.vault_ref, "vault_ref");
    return this.vault.vaultRefMetadata(vaultRef);
  }

  vaultStatus() {
    return this.vault.adapterStatus();
  }

  vaultHealth() {
    throwVaultRustCoreRequired("model_mount.vault.health");
  }

  removeVaultRef(body = {}) {
    assertCanonicalVaultOperationRequestBody(body);
    const vaultRef = requiredString(body.vault_ref, "vault_ref");
    throwVaultRustCoreRequired(
      "model_mount.vault_ref.remove",
      {
        vault_ref_hash_required: true,
        purpose: body.purpose ?? "operator_provider_auth_remove",
        vault_ref_present: Boolean(vaultRef),
      },
    );
  }

  createToken(body = {}) {
    throwCapabilityTokenRustCoreRequired(
      "model_mount.capability_token.create",
      {
        ...(body.audience ? { audience: body.audience } : {}),
        ...(body.grant_id ? { grant_id: body.grant_id } : {}),
      },
    );
  }

  listTokens() {
    return [...this.tokens.values()]
      .map(publicToken)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  revokeToken(tokenId) {
    if (!this.tokens.has(tokenId)) throw notFound(`Token not found: ${tokenId}`, { token_id: tokenId });
    throwCapabilityTokenRustCoreRequired(
      "model_mount.capability_token.revoke",
      { token_id: tokenId },
    );
  }

  authorize(authorization, requiredScope) {
    if (!authorization || !authorization.startsWith("Bearer ")) {
      throw runtimeError({
        status: 401,
        code: "auth",
        message: "Bearer capability token is required for this model mounting operation.",
        details: { required_scope: requiredScope },
      });
    }
    const tokenHash = hashToken(authorization.slice("Bearer ".length).trim());
    const token = [...this.tokens.values()].find((candidate) => candidate.tokenHash === tokenHash);
    if (!token) {
      throw runtimeError({
        status: 401,
        code: "auth",
        message: "Capability token was not recognized.",
        details: { required_scope: requiredScope },
      });
    }
    throwCapabilityTokenRustCoreRequired(
      "model_mount.capability_token.authorize",
      {
        token_id: token.id,
        grant_id: token.grantId ?? null,
        required_scope: requiredScope,
      },
    );
  }

  upsertProvider(body = {}) {
    assertCanonicalProviderUpsertRequestBody(body);
    const id = body.id ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
    const existing = this.providers.get(id) ?? {};
    const kind = body.kind ?? existing.kind ?? "custom_http";
    throw modelMountProviderControlRustCoreRequired({
      id,
      kind,
    }, "provider_upsert", {
      operation_kind: "model_mount.provider.write",
    });
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
    throwModelMountProviderHealthRustCoreRequired(provider, "provider_health", {
      operation_kind: "model_mount.provider.health",
    });
  }

  async listProviderModels(providerId) {
    const provider = this.provider(providerId);
    throwModelMountProviderInventoryRustCoreRequired(provider, "provider_models_list", {
      operation_kind: "model_mount.provider.inventory.list_models",
    });
  }

  async listProviderLoaded(providerId) {
    const provider = this.provider(providerId);
    throwModelMountProviderInventoryRustCoreRequired(provider, "provider_loaded_list", {
      operation_kind: "model_mount.provider.inventory.list_loaded",
    });
  }

  async startProvider(providerId) {
    const provider = this.provider(providerId);
    throw modelMountProviderControlRustCoreRequired(provider, "provider_start");
  }

  async stopProvider(providerId) {
    const provider = this.provider(providerId);
    throw modelMountProviderControlRustCoreRequired(provider, "provider_stop");
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
    void authorization;
    assertCanonicalModelTokenizerRequestBody(body);
    throw modelTokenizerRustCoreRequiredError({
      operation,
      model: body.model ?? null,
      route_id: body.route_id ?? null,
      requested_scope: requiredScope ?? null,
    });
  }

  tokenizeModel({ authorization, requiredScope = "model.tokenize:*", body = {} }) {
    return ModelMountingState.prototype.modelTokenizerUtility.call(this, {
      authorization,
      requiredScope,
      body,
      operation: "tokenize",
    });
  }

  countModelTokens({ authorization, requiredScope = "model.tokenize:*", body = {} }) {
    return ModelMountingState.prototype.modelTokenizerUtility.call(this, {
      authorization,
      requiredScope,
      body,
      operation: "count_tokens",
    });
  }

  fitModelContext({ authorization, requiredScope = "model.context:*", body = {} }) {
    return ModelMountingState.prototype.modelTokenizerUtility.call(this, {
      authorization,
      requiredScope,
      body,
      operation: "context_fit",
    });
  }

  contextWindowForEndpoint(endpoint, body = {}) {
    const explicit = Number(body.context_length);
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
    const record = this.conversations.get(responseId);
    if (!record) {
      throw runtimeError({
        status: 404,
        code: "continuation",
        message: "previous_response_id was not found.",
        details: { previous_response_id: responseId },
      });
    }
    return record;
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
    void input;
    void outputText;
    void selection;
    void instance;
    void tokenCount;
    void continuationSafety;
    throw modelConversationRustCoreRequiredError({
      operation: "model_conversation_state_write",
      response_id: responseId ?? null,
      previous_response_id: previousState?.id ?? null,
      receipt_id: receipt?.id ?? null,
      route_receipt_id: routeReceipt?.id ?? null,
      stream_receipt_id: streamReceiptId,
      kind,
      status,
    });
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
    void outputText;
    void providerUsage;
    throw modelConversationRustCoreRequiredError({
      operation: "model_stream_completion",
      stream_kind: streamKind,
      invocation_receipt_id: invocation?.receipt?.id ?? null,
      response_id: invocation?.responseId ?? null,
      previous_response_id: invocation?.previousResponseId ?? null,
      chunks_forwarded: chunksForwarded,
      finish_reason: finishReason,
      provider_response_kind: providerResult?.providerResponseKind ?? invocation?.providerResponseKind ?? null,
      has_provider_stream_shape_summary: Boolean(providerStreamShapeSummary),
    });
  }

  compileEphemeralMcpIntegrations({ authorization, body = {}, input }) {
    void authorization;
    void input;
    const integrations = Array.isArray(body.integrations) ? body.integrations : [];
    const ephemeral = integrations.filter((integration) => integration?.type === "ephemeral_mcp");
    for (const integration of ephemeral) {
      assertCanonicalEphemeralMcpIntegration(integration);
    }
    if (ephemeral.length > 0) {
      throwMcpWorkflowRustCoreRequired("model_mount.mcp_server.ephemeral_register", {
        integration_count: ephemeral.length,
      });
    }
    return { toolReceiptIds: [], serverIds: [], evidenceRefs: [] };
  }

  importMcpJson(body = {}) {
    assertCanonicalMcpImportRequestBody(body);
    throwMcpWorkflowRustCoreRequired("model_mount.mcp_server.import");
  }

  normalizeMcpServer(label, config = {}) {
    assertCanonicalMcpServerConfig(config);
    const id = `mcp.${safeId(label)}`;
    const allowedTools = normalizeScopes(
      config.allowed_tools,
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
      Object.entries(config.headers ?? config.env ?? {}).map(([key]) => [
        key,
        `vault://${id}/${safeId(key)}`,
      ]),
    );
    return {
      id,
      label,
      transport: config.url || config.server_url ? "remote" : "stdio",
      command: config.command ?? null,
      args: Array.isArray(config.args) ? config.args : [],
      serverUrl: config.url ?? config.server_url ?? null,
      allowedTools,
      secretRefs,
      redactedHeaders: Object.fromEntries(Object.keys(config.headers ?? {}).map((key) => [
        key,
        SECRET_REDACTION,
      ])),
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
    return [...this.conversations.values()].sort((left, right) =>
      String(left.created_at ?? "").localeCompare(String(right.created_at ?? "")),
    );
  }

  invokeMcpTool({ authorization, body = {} }) {
    void authorization;
    assertCanonicalMcpToolInvocationRequestBody(body);
    throwMcpWorkflowRustCoreRequired("model_mount.mcp_tool.invoke", {
      server_id: body.server_id ?? null,
      tool: body.tool ?? null,
    });
  }

  async executeWorkflowNode({ authorization, body = {} }) {
    void authorization;
    assertCanonicalWorkflowNodeExecutionRequestBody(body);
    throwMcpWorkflowRustCoreRequired("model_mount.workflow_node.execute", {
      node: body.node ?? body.node_type ?? null,
      workflow_graph_id: body.workflow_graph_id ?? null,
      workflow_node_id: body.workflow_node_id ?? null,
    });
  }

  validateReceiptGate(body = {}) {
    return validateReceiptGateRule({
      body,
      getReceipt: (receiptId) => this.getReceipt(receiptId),
      normalizeScopes,
      persistRustAuthoredReceipt: (record) => this.persistRustAuthoredReceipt(record),
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
    assertNoRetiredLifecycleSubjectAliases(details);
    throw modelLifecycleReceiptRustCoreRequiredError({
      operation,
      model_id: details.model_id ?? null,
      endpoint_id: details.endpoint_id ?? null,
      provider_id: details.provider_id ?? null,
      backend_id: details.backend_id ?? null,
    });
  }

  receipt(kind, { id, summary, redaction, evidenceRefs, details }) {
    void kind;
    void id;
    void summary;
    void redaction;
    void evidenceRefs;
    void details;
    throw modelMountJsReceiptCreationRetiredError();
  }

  persistRustAuthoredReceipt(record) {
    assertRustAuthoredReceiptRecord(record);
    this.store.writeReceipt(record);
    this.writeProjection();
    return record;
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
    throwModelRouteControlRustCoreRequired("model_mount.route.explicit_model_endpoints", {
      route_id: route?.id ?? null,
      model_id: modelId ?? null,
    });
  }

  selectRoute({ modelId, routeId, capability, policy }) {
    void policy;
    throwModelRouteControlRustCoreRequired("model_mount.route.select", {
      model_id: modelId ?? null,
      route_id: routeId ?? null,
      capability: capability ?? "chat",
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
    return this.readProjectionFacade.runtimePreferenceProjection(this);
  }

  runtimePreferenceForEndpoint(endpoint = {}) {
    return this.readProjectionFacade.runtimePreferenceForEndpointProjection(this, endpoint);
  }

  runtimeEngineProfile(engineId) {
    return this.readProjectionFacade.runtimeEngineProfileList(this)
      .find((profile) => profile.id === engineId) ?? null;
  }

  listRuntimeEngineProfiles() {
    return this.readProjectionFacade.runtimeEngineProfileList(this);
  }

  runtimeDefaultLoadOptions(engineId) {
    return this.readProjectionFacade.runtimeDefaultLoadOptionsProjection(this, engineId);
  }

  runtimeEngine(engineId) {
    return this.readProjectionFacade.runtimeEngineProjection(this, engineId);
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
    return this.readProjectionFacade.runtimeEngineList(this);
  }

  applyRuntimeEngineProfile(engine) {
    return applyRuntimeEngineProfileState(this, engine);
  }

  runtimeSurvey() {
    throwRuntimeSurveyRustCoreRequired({
      operation: "runtime_survey",
      operation_kind: "model_mount.runtime_survey.capture",
    });
  }

  latestRuntimeSurvey() {
    return this.readProjectionFacade.latestRuntimeSurvey(this);
  }

  backend(backendId) {
    const record = this.backendRegistry().find((item) => item.id === backendId);
    if (!record) throw notFound(`Model backend not found: ${backendId}`, { backend_id: backendId });
    return record;
  }

  backendProcessSnapshot(processRecord) {
    return backendProcessSnapshot(processRecord);
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
    const backend = this.backend(backendId);
    void endpoint;
    void loadOptions;
    throwBackendProcessSupervisorRetired("model_mount.backend_process.ensure", backend, { reason });
  }

  backendSupportsSupervision(backend) {
    return this.backendProcessPlan(backend).supports_supervision;
  }

  touchBackendProcess(processRecord, { endpoint = null, loadOptions = {}, reason = "health_probe" } = {}) {
    const backend = this.backend(processRecord.backendId);
    void endpoint;
    void loadOptions;
    throwBackendProcessSupervisorRetired("model_mount.backend_process.touch", backend, {
      process_id: processRecord?.id ?? null,
      reason,
    });
  }

  startBackendProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    void endpoint;
    void loadOptions;
    throwBackendProcessSupervisorRetired("model_mount.backend_process.start", backend, { reason });
  }

  spawnBackendChildProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control", processRef, argsRedacted = [] } = {}) {
    void endpoint;
    void loadOptions;
    void processRef;
    void argsRedacted;
    throwBackendProcessSupervisorRetired("model_mount.backend_process.spawn", backend, { reason });
  }

  stopBackendProcess(backend, { reason = "runtime_control" } = {}) {
    throwBackendProcessSupervisorRetired("model_mount.backend_process.stop", backend, { reason });
  }

  backendHealth(backendId) {
    const backend = this.backend(backendId);
    throwBackendLifecycleRustCoreRequired("model_mount.backend.health", backend);
  }

  startBackend(backendId, body = {}) {
    const backend = this.backend(backendId);
    void body;
    throwBackendLifecycleRustCoreRequired("model_mount.backend.start", backend);
  }

  stopBackend(backendId) {
    const backend = this.backend(backendId);
    throwBackendLifecycleRustCoreRequired("model_mount.backend.stop", backend);
  }

  backendLogs(backendId) {
    const backend = this.backend(backendId);
    throwBackendLifecycleRustCoreRequired("model_mount.backend.logs_read", backend);
  }

  writeBackendLog(endpointId, event) {
    return writeBackendLogState(this, endpointId, event, {
      randomUUID: () => crypto.randomUUID(),
      redact,
      safeFileName,
    });
  }

  driverForProvider(provider) {
    throwProviderDriverFactoryRetired(provider);
  }
}

function throwRuntimeSurveyRustCoreRequired(details = {}) {
  const error = new Error("Runtime survey capture requires direct Rust daemon-core model_mount projection support.");
  error.status = 501;
  error.code = "model_mount_runtime_survey_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.runtime_survey",
    ...details,
    evidence_refs: [
      "model_mount_runtime_survey_js_facade_retired",
      "rust_daemon_core_runtime_survey_required",
      "agentgres_runtime_survey_projection_required",
    ],
  };
  throw error;
}

function throwBackendLifecycleRustCoreRequired(operation_kind, backend) {
  throw runtimeError({
    status: 501,
    code: "model_mount_backend_lifecycle_rust_core_required",
    message: "Backend lifecycle facade control requires Rust daemon-core model_mount lifecycle ownership.",
    details: {
      backend_id: backend.id,
      backend_kind: backend.kind,
      operation_kind,
      rust_core_boundary: "model_mount.backend_lifecycle",
      evidence_refs: [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_lifecycle_required",
      ],
    },
  });
}

function backendProcessSupervisorRetiredError(operation_kind, backend = {}, details = {}) {
  const error = new Error("Backend process supervision requires Rust daemon-core model_mount lifecycle ownership.");
  error.status = 501;
  error.code = "model_mount_backend_process_supervisor_retired";
  error.details = {
    backend_id: backend?.id ?? null,
    backend_kind: backend?.kind ?? null,
    operation_kind,
    rust_core_boundary: "model_mount.backend_lifecycle",
    ...details,
    evidence_refs: [
      "js_backend_process_supervisor_retired",
      "rust_daemon_core_backend_process_required",
      "agentgres_backend_process_truth_required",
    ],
  };
  return error;
}

function throwBackendProcessSupervisorRetired(operation_kind, backend, details = {}) {
  throw backendProcessSupervisorRetiredError(operation_kind, backend, details);
}

function backendProcessSnapshot(processRecord) {
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

function throwProviderDriverFactoryRetired(provider = {}) {
  throw runtimeError({
    status: 501,
    code: "model_mount_provider_driver_factory_retired",
    message: "JS provider driver factory is retired; provider execution and control require Rust daemon-core model_mount APIs.",
    details: {
      provider_id: provider?.id ?? null,
      provider_kind: provider?.kind ?? null,
      operation_kind: "model_mount.provider.driver_factory",
      rust_core_boundary: "model_mount.provider_execution",
      evidence_refs: [
        "js_provider_driver_factory_retired",
        "rust_daemon_core_provider_execution_required",
        "agentgres_provider_execution_truth_required",
      ],
    },
  });
}

function assertCanonicalModelStorageRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_STORAGE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model storage request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_storage_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MODEL_STORAGE_REQUEST_FIELDS,
  };
  throw error;
}

function throwModelStorageRustCoreRequired(operation_kind, details = {}) {
  throw runtimeError({
    status: 501,
    code: "model_mount_storage_rust_core_required",
    message:
      "Model storage mutation facades require Rust daemon-core model_mount storage ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.storage",
      evidence_refs: [
        "public_model_storage_js_facade_retired",
        "rust_daemon_core_model_storage_required",
      ],
      ...details,
    },
  });
}

function throwCapabilityTokenRustCoreRequired(operation_kind, details = {}) {
  throw runtimeError({
    status: 501,
    code: "model_mount_capability_token_rust_core_required",
    message:
      "Capability token mutation and authorization facades require Rust daemon-core wallet authority ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.capability_token",
      evidence_refs: [
        "public_capability_token_js_facade_retired",
        "rust_daemon_core_wallet_authority_required",
      ],
      ...details,
    },
  });
}

function assertCanonicalVaultOperationRequestBody(body = {}) {
  const retiredAliases = RETIRED_VAULT_OPERATION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error("Vault operation request aliases are retired; use canonical snake_case request fields.");
  error.status = 400;
  error.code = "vault_operation_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_VAULT_OPERATION_REQUEST_FIELDS,
  };
  throw error;
}

function throwVaultRustCoreRequired(operation_kind, details = {}) {
  throw runtimeError({
    status: 501,
    code: "model_mount_vault_rust_core_required",
    message:
      "Vault mutation and health receipt facades require Rust daemon-core wallet/cTEE custody ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.vault",
      evidence_refs: [
        "public_vault_js_facade_retired",
        "rust_daemon_core_wallet_vault_required",
        "rust_daemon_core_ctee_custody_required",
      ],
      ...details,
    },
  });
}

function assertCanonicalModelImportRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_IMPORT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model import request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_import_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MODEL_IMPORT_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalEndpointMountRequestBody(body = {}) {
  const retiredAliases = RETIRED_ENDPOINT_MOUNT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model endpoint mount request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_endpoint_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_ENDPOINT_MOUNT_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalEndpointUnmountRequestBody(body = {}) {
  const retiredAliases = RETIRED_ENDPOINT_UNMOUNT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model endpoint unmount request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_unmount_endpoint_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_ENDPOINT_UNMOUNT_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalModelLoadingRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_LOADING_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model loading request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_loading_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MODEL_LOADING_REQUEST_FIELDS,
  };
  throw error;
}

function throwModelLoadingRustCoreRequired(operation, provider = {}, details = {}) {
  const error = new Error("Model load/unload requires a Rust model_mount provider lifecycle backend.");
  error.status = 501;
  error.code = "model_mount_model_loading_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.instance_lifecycle",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
    evidence_refs: [
      "model_mount_model_loading_js_facade_retired",
      "rust_daemon_core_instance_lifecycle_required",
      "agentgres_model_instance_record_truth_required",
    ],
  };
  throw error;
}

function throwArtifactEndpointRustCoreRequired(operation_kind, details = {}) {
  throw runtimeError({
    status: 501,
    code: "model_mount_artifact_endpoint_rust_core_required",
    message:
      "Artifact and endpoint mutation facades require Rust daemon-core model_mount artifact/endpoint ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.artifact_endpoint",
      evidence_refs: [
        "public_artifact_endpoint_js_facade_retired",
        "rust_daemon_core_artifact_endpoint_required",
      ],
      ...details,
    },
  });
}

function assertCanonicalCatalogImportUrlRequestBody(body = {}) {
  const retiredAliases = RETIRED_CATALOG_IMPORT_URL_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_catalog_import_url_request_aliases_retired",
    message: "Model catalog import URL request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_CATALOG_IMPORT_URL_REQUEST_FIELDS,
  });
}

function assertCanonicalModelDownloadIdentityRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_DOWNLOAD_IDENTITY_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_download_identity_request_aliases_retired",
    message: "Model download identity request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_MODEL_DOWNLOAD_IDENTITY_REQUEST_FIELDS,
  });
}

function assertCanonicalModelDownloadControlRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_DOWNLOAD_CONTROL_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_download_control_request_aliases_retired",
    message: "Model download control request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_MODEL_DOWNLOAD_CONTROL_REQUEST_FIELDS,
  });
}

function assertCanonicalModelDownloadMetadataRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_DOWNLOAD_METADATA_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_download_metadata_request_aliases_retired",
    message: "Model download metadata request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_MODEL_DOWNLOAD_METADATA_REQUEST_FIELDS,
  });
}

function requestAliasError({ code, message, retiredAliases, canonicalFields }) {
  const error = new Error(message);
  error.status = 400;
  error.code = code;
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: canonicalFields,
  };
  return error;
}

function throwCatalogDownloadRustCoreRequired(operation_kind, details = {}) {
  throw runtimeError({
    status: 501,
    code: "model_mount_catalog_download_rust_core_required",
    message:
      "Catalog import and download mutation facades require Rust daemon-core model_mount catalog/download ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.catalog_download",
      evidence_refs: [
        "public_catalog_download_js_facade_retired",
        "rust_daemon_core_catalog_download_required",
      ],
      ...details,
    },
  });
}

function throwCatalogVariantEnrichmentRetired() {
  throw runtimeError({
    status: 501,
    code: "model_catalog_variant_enrichment_js_retired",
    message: "Model catalog variant enrichment is retired in JS; use Rust daemon-core catalog projection/search.",
    details: {
      operation_kind: "model_catalog.variant_enrich",
      rust_core_boundary: "model_mount.catalog_variant_projection",
      evidence_refs: [
        "model_catalog_variant_enrichment_js_retired",
        "rust_daemon_core_catalog_variant_projection_required",
        "agentgres_catalog_projection_required",
      ],
    },
  });
}

function assertCanonicalModelTokenizerRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_TOKENIZER_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model tokenizer request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_tokenizer_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: ["route_id", "model_policy", "context_length", "max_output_tokens"],
  };
  throw error;
}

function modelTokenizerRustCoreRequiredError(details = {}) {
  const error = new Error(
    "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
  );
  error.status = 501;
  error.code = "model_mount_tokenizer_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.tokenizer",
    ...details,
    evidence_refs: MODEL_TOKENIZER_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}

function assertNoRetiredLifecycleSubjectAliases(details = {}) {
  const retiredAliases = ["modelId", "endpointId"].filter((field) => Object.hasOwn(details, field));
  if (retiredAliases.length === 0) return;
  const error = new Error("Model lifecycle receipt details must use canonical snake_case subject fields.");
  error.status = 409;
  error.code = "model_lifecycle_receipt_detail_aliases_retired";
  error.details = { retired_aliases: retiredAliases };
  throw error;
}

function assertRustAuthoredReceiptRecord(record = {}) {
  const evidenceRefs = Array.isArray(record.evidenceRefs) ? record.evidenceRefs : [];
  const details = record.details && typeof record.details === "object" ? record.details : {};
  const missing = [];
  if (!record.id) missing.push("id");
  if (!record.kind) missing.push("kind");
  if (!record.createdAt) missing.push("createdAt");
  if (!record.schemaVersion) missing.push("schemaVersion");
  if (!evidenceRefs.includes("rust_model_mount_core")) missing.push("evidenceRefs.rust_model_mount_core");
  if (!details.rust_daemon_core_receipt_author) missing.push("details.rust_daemon_core_receipt_author");
  if (!details.model_mount_route_decision_ref) missing.push("details.model_mount_route_decision_ref");
  if (missing.length === 0) return;
  const error = new Error("Model-mount receipt persistence requires a Rust-authored receipt record.");
  error.status = 502;
  error.code = "model_mount_rust_authored_receipt_required";
  error.details = { missing };
  throw error;
}

function modelMountJsReceiptCreationRetiredError() {
  const error = new Error("Model-mount receipt creation in JS is retired; Rust daemon core must author receipt records.");
  error.status = 501;
  error.code = "model_mount_js_receipt_creation_retired";
  error.details = {
    rust_core_boundary: "model_mount.receipt_authoring",
    evidence_refs: [
      "model_mount_js_receipt_creation_retired",
      "rust_daemon_core_model_mount_receipt_authoring_required",
      "agentgres_model_mount_receipt_truth_required",
    ],
  };
  return error;
}

function modelLifecycleReceiptRustCoreRequiredError(details = {}) {
  const error = new Error(
    "Model lifecycle receipts require direct Rust daemon-core admission, binding, and projection.",
  );
  error.status = 501;
  error.code = "model_mount_lifecycle_receipt_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.lifecycle_receipt",
    ...details,
    evidence_refs: MODEL_LIFECYCLE_RECEIPT_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}

function modelConversationRustCoreRequiredError(details = {}) {
  const error = new Error(
    "Model conversation state and stream completion finalization require direct Rust daemon-core admission and projection.",
  );
  error.status = 501;
  error.code = "model_mount_conversation_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.conversation",
    ...details,
    evidence_refs: MODEL_CONVERSATION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}

function assertCanonicalEphemeralMcpIntegration(integration = {}) {
  const retiredAliases = RETIRED_EPHEMERAL_MCP_INTEGRATION_ALIASES.filter((field) =>
    Object.prototype.hasOwnProperty.call(integration, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error("Ephemeral MCP integration uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_ephemeral_mcp_integration_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_EPHEMERAL_MCP_INTEGRATION_FIELDS,
  };
  throw error;
}

function assertCanonicalMcpImportRequestBody(body = {}) {
  const retiredAliases = RETIRED_MCP_IMPORT_REQUEST_ALIASES.filter((field) =>
    Object.prototype.hasOwnProperty.call(body, field),
  );
  const nestedRetiredAliases =
    body.mcp_json && typeof body.mcp_json === "object" && Object.prototype.hasOwnProperty.call(body.mcp_json, "mcpServers")
      ? ["mcp_json.mcpServers"]
      : [];
  if (retiredAliases.length === 0 && nestedRetiredAliases.length === 0) return;
  const error = new Error("MCP import request uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_mcp_import_request_aliases_retired";
  error.details = {
    retired_aliases: [...retiredAliases, ...nestedRetiredAliases],
    canonical_fields: CANONICAL_MCP_IMPORT_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalMcpServerConfig(config = {}) {
  const retiredAliases = RETIRED_MCP_SERVER_CONFIG_ALIASES.filter((field) =>
    Object.prototype.hasOwnProperty.call(config, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error("MCP server config uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_mcp_server_config_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MCP_SERVER_CONFIG_FIELDS,
  };
  throw error;
}

function assertCanonicalMcpToolInvocationRequestBody(body = {}) {
  const retiredAliases = RETIRED_MCP_TOOL_INVOCATION_REQUEST_ALIASES.filter((field) =>
    Object.prototype.hasOwnProperty.call(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error("MCP tool invocation request uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_mcp_tool_invocation_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MCP_TOOL_INVOCATION_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalWorkflowNodeExecutionRequestBody(body = {}) {
  const retiredAliases = RETIRED_WORKFLOW_NODE_EXECUTION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Workflow node execution request aliases are retired; use canonical request fields.",
  );
  error.status = 400;
  error.code = "model_mount_workflow_node_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: [
      "node",
      "node_type",
      "model",
      "model_id",
      "route_id",
      "model_policy",
      "max_tokens",
      "workflow_graph_id",
      "workflow_node_id",
      "workflow_node_type",
    ],
  };
  throw error;
}

function throwMcpWorkflowRustCoreRequired(operation_kind, details = {}) {
  throw runtimeError({
    status: 501,
    code: "model_mount_mcp_workflow_rust_core_required",
    message: "Model-mount MCP workflow mutation and execution require Rust daemon core.",
    details: {
      rust_core_boundary: "model_mount.mcp_workflow",
      operation_kind,
      ...details,
      evidence_refs: MCP_WORKFLOW_RUST_CORE_EVIDENCE_REFS,
    },
  });
}

function assertCanonicalProviderUpsertRequestBody(body = {}) {
  const retiredAliases = RETIRED_PROVIDER_UPSERT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "provider_upsert_request_aliases_retired",
    message: "Provider upsert request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_PROVIDER_UPSERT_REQUEST_FIELDS,
    },
  });
}

function modelMountProviderControlRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("Provider control requires direct Rust daemon-core support.");
  error.status = 501;
  error.code = "model_mount_provider_control_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_control",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    evidence_refs: [
      "model_mount_provider_control_js_facade_retired",
      "rust_daemon_core_provider_control_required",
      "wallet_network_vault_authority_required",
    ],
  };
  return error;
}

function throwModelMountProviderHealthRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("Provider health requires direct Rust daemon-core support.");
  error.status = 501;
  error.code = "model_mount_provider_health_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_health",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
    evidence_refs: [
      "model_mount_provider_health_js_facade_retired",
      "rust_daemon_core_provider_health_required",
      "agentgres_provider_health_record_truth_required",
    ],
  };
  throw error;
}

function throwModelMountProviderInventoryRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("Provider inventory reads require direct Rust daemon-core projection support.");
  error.status = 501;
  error.code = "model_mount_provider_inventory_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_inventory",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
    evidence_refs: [
      "model_mount_provider_inventory_js_facade_retired",
      "rust_daemon_core_provider_inventory_required",
      "agentgres_provider_inventory_projection_required",
    ],
  };
  throw error;
}
