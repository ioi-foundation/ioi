import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  createModelMountCore,
  RUST_MODEL_MOUNT_FIXTURE_INVENTORY_BACKEND,
  RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND,
  RUST_MODEL_MOUNT_HOSTED_PROVIDER_INVENTORY_BACKEND,
  RUST_MODEL_MOUNT_HOSTED_PROVIDER_LIFECYCLE_BACKEND,
  RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
  RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND,
  RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND,
} from "./model-mounting/model-mount-core.mjs";
import { AgentgresModelMountingStore } from "./model-mounting/store.mjs";
import { modelMountingRelationSchemas } from "./model-mounting/schema-relations.mjs";
import {
  workflowMemoryOptionsFromBody,
  workflowMemoryWriteBlockReason,
} from "./model-mounting/workflow-memory.mjs";
import {
  destructiveConfirmationState,
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
  optionalProvider as optionalProviderState,
  provider as providerState,
  resolveEndpoint as resolveEndpointState,
  route as routeState,
} from "./model-mounting/state-accessors.mjs";
import {
  writeBackendLog as writeBackendLogState,
} from "./model-mounting/backend-registry-state.mjs";
import { llamaCppLibraryPathEnv } from "./model-mounting/local-runtime-engines.mjs";
import {
  optionalString,
  requiredString,
} from "./model-mounting/provider-registry.mjs";
import {
  assertNoPlaintextProviderSecret,
  providerRequiresVaultSecret,
  providerSecretInput,
} from "./model-mounting/provider-auth.mjs";
import {
  catalogProviderControlPlanForState,
  catalogProviderControlResponse,
  commitCatalogProviderControlPlan,
} from "./model-mounting/catalog-provider-config.mjs";
import {
  capabilityTokenControlPlanForState,
  capabilityTokenControlResponse,
  commitCapabilityTokenControlPlan,
} from "./model-mounting/capability-token-control.mjs";
import {
  commitVaultControlPlan,
  vaultControlPlanForState,
  vaultControlResponse,
} from "./model-mounting/vault-control.mjs";
import {
  hardwareSnapshot,
} from "./model-mounting/local-system-probes.mjs";
import {
  expiresAt,
  hasExplicitTtlOption,
  normalizeLoadOptions,
  normalizeLoadPolicy,
} from "./model-mounting/load-policy.mjs";
import {
  coalesceLoadedInstances as coalesceLoadedInstancesState,
  evictExpiredInstances as evictExpiredInstancesState,
  loadedInstanceForEndpoint as loadedInstanceForEndpointState,
  supersedeLoadedInstances as supersedeLoadedInstancesState,
} from "./model-mounting/loaded-instances.mjs";
import { AgentgresWalletAuthority } from "./model-mounting/wallet-authority.mjs";
import {
  AgentgresVaultPort,
  configuredVaultMaterialAdapter,
} from "./model-mounting/vault-port.mjs";
import {
  isExecutable,
  notFound,
  runtimeError,
  safeFileName,
  safeId,
  writeJson,
  stableHash,
  redact,
  shouldRedactKey,
  emitRemoteBoundaryEvent,
  sleep,
  fileSizeIfExists,
  normalizeNonNegativeInteger,
  truthy,
  matchesAny,
  hashToken,
  normalizeScopes,
} from "./model-mounting/io.mjs";
import {
  writeModelMountingMap,
  writeModelMountingVaultRefs,
} from "./model-mounting/state-persistence.mjs";
import {
  validateContinuationSafety as validateContinuationSafetyRule,
  validateReceiptGate as validateReceiptGateRule,
} from "./model-mounting/validation.mjs";
import {
  commitRouteControlPlan as commitRouteControlPlanState,
  testRoute as testRouteState,
  upsertRoute as upsertRouteState,
} from "./model-mounting/routes.mjs";
import { commitModelMountRecordState } from "./model-mounting/record-state-commits.mjs";
import {
  commitTokenizerControlPlan as commitTokenizerControlPlanState,
  tokenizerControlResponse,
  tokenizerRequestForMountedState,
} from "./model-mounting/tokenizer-control.mjs";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1", SECRET_REDACTION = "[REDACTED]";
const MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION = "ioi.model_mount.route_control.v1";
const MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION = "ioi.model_mount.provider_control.v1";
const MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION =
  "ioi.model_mount.provider_auth_materialization.v1";
const MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION = "ioi.model_mount.provider_lifecycle.v1";
const MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION = "ioi.model_mount.provider_inventory.v1";
const MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION = "ioi.model_mount.instance_lifecycle.v1";
const MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION = "ioi.model_mount.artifact_endpoint.v1";
const MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION = "ioi.model_mount.storage_control.v1";
const MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION = "ioi.model_mount.mcp_workflow.v1";
const MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION = "ioi.model_mount.conversation_state.v1";
const MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION = "ioi.model_mount.stream_completion.v1";
const MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION = "ioi.model_mount.stream_cancel.v1";
const SERVER_CONTROL_RECORD_ID = "server-control.default";
const MCP_WORKFLOW_RUST_CORE_EVIDENCE_REFS = [
  "rust_daemon_core_model_mount_mcp_workflow",
  "agentgres_mcp_workflow_truth_required",
  "model_mount_mcp_workflow_js_facade_retired",
  "model_mount_mcp_import_js_facade_retired",
  "model_mount_ephemeral_mcp_registration_js_facade_retired",
  "model_mount_mcp_tool_invocation_js_facade_retired",
  "model_mount_workflow_node_execution_js_facade_retired",
  "model_mount_mcp_workflow_receipt_synthesis_js_retired",
  "model_mount_mcp_workflow_record_state_js_retired",
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
export class ModelMountingState {
  constructor({
    stateDir,
    cwd,
    homeDir,
    now = () => new Date(),
    vaultSecrets = {},
    modelMountCore = null,
    daemonCoreModelMountApi = null,
    commitRuntimeModelMountRecordState = null,
    commitRuntimeModelMountReceiptState = null,
  }) {
    this.stateDir = path.resolve(stateDir);
    this.cwd = path.resolve(cwd ?? process.cwd());
    this.homeDir = path.resolve(homeDir ?? process.env.HOME ?? this.cwd);
    this.modelRoot = path.join(this.stateDir, "models");
    this.bootId = `daemon_boot_${crypto.randomUUID()}`;
    this.now = now;
    this.modelMountCore =
      modelMountCore ??
      createModelMountCore({
        daemonCoreModelMountApi,
      });
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
    this.ensureDirs();
  }

  close() {}

  ensureDirs() {
    this.store.ensureDirs();
  }

  writeSchemaRelationSchemas() {
    return modelMountingRelationSchemas();
  }

  writeMap(dir, map) {
    return writeModelMountingMap(this, dir, map);
  }

  writeVaultRefs() {
    return writeModelMountingVaultRefs(this);
  }

  serverStatus(baseUrl) {
    return modelMountReadProjection(this, "server_status", { baseUrl });
  }

  serverControlState() {
    return {
      id: SERVER_CONTROL_RECORD_ID,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: "running",
      gatewayStatus: "running",
      operation: "server_status",
      updatedAt: null,
      receiptId: null,
      evidenceRefs: ["ioi_daemon_public_runtime_api"],
    };
  }

  writeServerControlState(controlState) {
    const record = {
      id: SERVER_CONTROL_RECORD_ID,
      ...controlState,
    };
    return commitServerControlForState(this, "model_mount.server_control.write", {
      server_control_id: record.id,
      receipt_id: record.receiptId ?? null,
      body: serverControlBody(record),
    });
  }

  serverStart(baseUrl) {
    return commitServerControlForState(this, "model_mount.server_control.start", {
      base_url: optionalString(baseUrl),
    });
  }

  serverStop(baseUrl) {
    return commitServerControlForState(this, "model_mount.server_control.stop", {
      base_url: optionalString(baseUrl),
    });
  }

  serverRestart(baseUrl) {
    return commitServerControlForState(this, "model_mount.server_control.restart", {
      base_url: optionalString(baseUrl),
    });
  }

  recordServerOperation(operation, status, baseUrl, details = {}) {
    return commitServerControlForState(this, "model_mount.server_control.record_operation", {
      operation: operation ?? null,
      status: status ?? null,
      base_url: baseUrl ?? null,
      ...details,
    });
  }

  serverLogs(query = {}) {
    return modelMountReadProjection(this, "server_logs", {
      serverLogQuery: canonicalModelMountServerLogQuery(query),
    });
  }

  serverEvents(query = {}) {
    return modelMountReadProjection(this, "server_events", {
      serverLogQuery: canonicalModelMountServerLogQuery(query),
    });
  }

  serverLogRecords({ limit = 80 } = {}) {
    return modelMountReadProjection(this, "server_log_records", {
      serverLogQuery: canonicalModelMountServerLogQuery({ limit }),
    });
  }

  writeServerLog(event) {
    return commitServerControlForState(this, "model_mount.server_control.log_append", {
      body: serverControlBody(event),
    });
  }

  runtimeModelCatalogList() {
    return modelMountReadProjection(this, "runtime_model_catalog");
  }

  openAiModelList() {
    return modelMountReadProjection(this, "open_ai_model_list");
  }

  listArtifacts() {
    return modelMountReadProjection(this, "artifacts");
  }

  listProductArtifacts() {
    return modelMountReadProjection(this, "product_artifacts");
  }

  listProviders() {
    return modelMountReadProjection(this, "providers");
  }

  listEndpoints() {
    return modelMountReadProjection(this, "endpoints");
  }

  listInstances() {
    return modelMountReadProjection(this, "instances");
  }

  listRoutes() {
    return modelMountReadProjection(this, "routes");
  }

  listModelCapabilities() {
    return modelMountReadProjection(this, "model_capabilities");
  }

  listDownloads() {
    return modelMountReadProjection(this, "downloads");
  }

  listOAuthSessions() {
    return modelMountReadProjection(this, "oauth_sessions");
  }

  listOAuthStates() {
    return modelMountReadProjection(this, "oauth_states");
  }

  listProviderHealth() {
    return modelMountReadProjection(this, "provider_health");
  }

  snapshot(baseUrl) {
    return modelMountReadProjection(this, "snapshot", { baseUrl });
  }

  authoritySnapshot(baseUrl) {
    return modelMountReadProjection(this, "authority_snapshot", { baseUrl });
  }

  projectionSummary() {
    return modelMountReadProjection(this, "projection_summary");
  }

  projection() {
    return modelMountReadProjection(this, "projection");
  }

  adapterBoundaries() {
    return modelMountReadProjection(this, "adapter_boundaries");
  }

  receiptReplay(receiptId) {
    return modelMountReadProjection(this, "receipt_replay", { receiptId });
  }

  modelRouteDecisions() {
    return modelMountReadProjection(this, "model_route_decisions");
  }

  modelRouteEndpointResolutions() {
    return modelMountReadProjection(this, "model_route_endpoint_resolutions");
  }

  providerInventoryRecords() {
    return modelMountReadProjection(this, "provider_inventory_records");
  }

  modelTokenizerRecords() {
    return modelMountReadProjection(this, "model_tokenizer_records");
  }

  latestProviderHealth(providerId) {
    try {
      return modelMountReadProjection(this, "latest_provider_health", { providerId });
    } catch (error) {
      throw translateLatestProviderHealthError(error, providerId);
    }
  }

  latestVaultHealth() {
    try {
      return modelMountReadProjection(this, "latest_vault_health");
    } catch (error) {
      throw translateLatestVaultHealthError(error);
    }
  }

  workflowNodeBindings() {
    return modelMountReadProjection(this, "workflow_bindings");
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
    return modelMountReadProjection(this, "catalog_status");
  }

  listCatalogProviderConfigs() {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_configuration.list",
    );
  }

  getCatalogProviderConfig(providerId) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_configuration.get",
      { providerId },
    );
  }

  configureCatalogProvider(providerId, body = {}) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_configuration.write",
      { providerId, body, requiredScope: `provider.write:${providerId}` },
    );
  }

  startCatalogProviderOAuth(providerId, body = {}) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_oauth.start",
      { providerId, body, requiredScope: `provider.write:${providerId}` },
    );
  }

  async completeCatalogProviderOAuth(providerId, body = {}) {
    requiredString(body.state, "state");
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_oauth.callback",
      { providerId, body, requiredScope: `provider.write:${providerId}` },
    );
  }

  async exchangeCatalogProviderOAuth(providerId, body = {}) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_oauth.exchange",
      { providerId, body, requiredScope: `provider.write:${providerId}` },
    );
  }

  async refreshCatalogProviderOAuth(providerId) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_oauth.refresh",
      { providerId, requiredScope: `provider.write:${providerId}` },
    );
  }

  revokeCatalogProviderOAuth(providerId) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_oauth.revoke",
      { providerId, requiredScope: `provider.write:${providerId}` },
    );
  }

  catalogProviderConfig(providerId) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_configuration.read_private",
      { providerId },
    );
  }

  catalogProviderRuntimeMaterial(providerId) {
    return planAndCommitCatalogProviderControl(
      this,
      "model_mount.catalog_provider_runtime_material.resolve",
      { providerId, requiredScope: `provider.read:${providerId}` },
    );
  }

  storageSummary() {
    return modelMountReadProjection(this, "storage_summary");
  }

  catalogSearch(query = {}) {
    return modelMountReadProjection(this, "catalog_search", {
      catalogQuery: canonicalModelMountCatalogSearchQuery(query),
    });
  }

  enrichCatalogEntry(entry, options = {}) {
    void entry;
    void options;
    throwCatalogVariantEnrichmentRetired();
  }

  async catalogImportUrl(body = {}) {
    assertCanonicalCatalogImportUrlRequestBody(body);
    const sourceUrl = requiredString(body.source_url, "source_url");
    return planAndCommitStorageControl(this, "model_mount.catalog.import_url", {
      body: storageControlBody({ ...body, source_url: sourceUrl }),
      requiredScope: body.model_id
        ? `model.catalog.import_url:${body.model_id}`
        : `model.catalog.import_url:${stableHash(sourceUrl)}`,
    });
  }

  importModel(body = {}) {
    assertCanonicalModelImportRequestBody(body);
    const modelId = requiredString(body.model_id, "model_id");
    return planAndCommitArtifactEndpoint(this, "model_mount.artifact.import", {
      body: artifactEndpointBody({ ...body, model_id: modelId }),
      requiredScope: `model.artifact.import:${modelId}`,
    });
  }

  mountEndpoint(body = {}) {
    assertCanonicalEndpointMountRequestBody(body);
    const modelId = requiredString(body.model_id, "model_id");
    return planAndCommitArtifactEndpoint(this, "model_mount.endpoint.mount", {
      body: artifactEndpointBody({ ...body, model_id: modelId }),
      requiredScope: `model.endpoint.mount:${modelId}`,
    });
  }

  unmountEndpoint(body = {}) {
    assertCanonicalEndpointUnmountRequestBody(body);
    const endpointId = requiredString(body.endpoint_id ?? body.id, "endpoint_id");
    return planAndCommitArtifactEndpoint(this, "model_mount.endpoint.unmount", {
      body: artifactEndpointBody({ ...body, endpoint_id: endpointId }),
      requiredScope: `model.endpoint.unmount:${endpointId}`,
    });
  }

  async loadModel(body = {}) {
    assertCanonicalModelLoadingRequestBody(body);
    const endpoint = this.resolveEndpoint(body.endpoint_id, body.model_id);
    const provider = this.provider(endpoint.providerId ?? endpoint.provider_id);
    const loadPolicy = normalizeLoadPolicy(body.load_policy ?? endpoint.load_policy);
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
    const backendId = endpoint.backendId ?? endpoint.backend_id ?? defaultBackendForProvider(provider);
    if (loadOptions.estimateOnly) {
      const lifecycle = planModelInstanceLifecycle(this, {
        action: "estimate",
        targetStatus: "estimated",
        endpoint,
        provider,
        backendId,
        instanceId: body.instance_id ?? body.id ?? defaultModelLoadEstimateId(endpoint, loadOptions),
        load_options: loadOptions,
        runtime_engine_id: runtimePreference.selectedEngineId,
        evidenceRefs: ["model_mount_model_load_estimate_rust_positive_api"],
      });
      return commitModelInstanceLifecycleRecordState(this, lifecycle, {
        operation_kind: "model_mount.instance.estimate",
      });
    }
    const providerLifecycle = planProviderLifecycle(this, provider, {
      action: "load",
      operation: "model_load",
      operation_kind: "model_mount.instance.load",
      endpoint,
    });
    const lifecycle = planModelInstanceLifecycle(this, {
      action: "load",
      targetStatus: "loaded",
      endpoint,
      provider,
      backendId,
      instanceId: body.instance_id ?? body.id ?? defaultModelInstanceId(endpoint, loadOptions),
      providerLifecycle,
      evidenceRefs: ["model_mount_model_loading_rust_positive_api"],
    });
    return commitModelInstanceLifecycleRecordState(this, lifecycle, {
      operation_kind: "model_mount.instance.load",
      providerLifecycle,
    });
  }

  async unloadModel(body = {}) {
    assertCanonicalModelLoadingRequestBody(body);
    const instanceId = body.instance_id ?? body.id;
    const instance = instanceId
      ? this.instance(instanceId)
      : this.loadedInstanceForEndpoint(this.resolveEndpoint(body.endpoint_id, body.model_id).id);
    const endpointId = instance.endpoint_id ?? instance.endpointId;
    const providerId = instance.provider_id ?? instance.providerId;
    const modelId = instance.model_id ?? instance.modelId;
    const endpoint = this.endpoint(endpointId);
    const provider = this.provider(providerId);
    const backendId = instance.backend_id ?? instance.backendId ?? endpoint.backend_id ?? endpoint.backendId ?? defaultBackendForProvider(provider);
    const providerLifecycle = planProviderLifecycle(this, provider, {
      action: "unload",
      operation: "model_unload",
      operation_kind: "model_mount.instance.unload",
      endpoint,
    });
    const lifecycle = planModelInstanceLifecycle(this, {
      action: "unload",
      targetStatus: "unloaded",
      endpoint,
      provider,
      instance,
      backendId,
      instanceId: instance.id,
      modelId,
      providerLifecycle,
      evidenceRefs: ["model_mount_model_unloading_rust_positive_api"],
    });
    return commitModelInstanceLifecycleRecordState(this, lifecycle, {
      operation_kind: "model_mount.instance.unload",
      providerLifecycle,
    });
  }

  async downloadModel(body = {}) {
    assertCanonicalModelDownloadIdentityRequestBody(body);
    assertCanonicalModelDownloadControlRequestBody(body);
    assertCanonicalModelDownloadMetadataRequestBody(body);
    const modelId = requiredString(body.model_id, "model_id");
    return planAndCommitStorageControl(this, "model_mount.download.queue", {
      body: storageControlBody({ ...body, model_id: modelId }),
      requiredScope: `model.download.queue:${modelId}`,
    });
  }

  cancelDownload(jobId, body = {}) {
    assertCanonicalModelStorageRequestBody(body);
    const downloadId = requiredString(jobId ?? body.job_id, "job_id");
    return planAndCommitStorageControl(this, "model_mount.download.cancel", {
      body: storageControlBody({ ...body, job_id: downloadId }),
      requiredScope: `model.download.cancel:${downloadId}`,
    });
  }

  downloadStatus(jobId) {
    try {
      return modelMountReadProjection(this, "download_status", { downloadId: jobId });
    } catch (error) {
      throw translateDownloadStatusError(error, jobId);
    }
  }

  deleteModelArtifact(id, body = {}) {
    assertCanonicalModelStorageRequestBody(body);
    const artifactId = requiredString(id ?? body.artifact_id, "artifact_id");
    return planAndCommitStorageControl(this, "model_mount.artifact.delete", {
      body: storageControlBody({ ...body, artifact_id: artifactId }),
      requiredScope: `model.artifact.delete:${artifactId}`,
    });
  }

  cleanupModelStorage(body = {}) {
    assertCanonicalModelStorageRequestBody(body);
    return planAndCommitStorageControl(this, "model_mount.storage.cleanup", {
      body: storageControlBody(body),
      requiredScope: "model.storage.cleanup",
    });
  }

  bindVaultRef(body = {}) {
    assertCanonicalVaultOperationRequestBody(body);
    const vaultRef = requiredString(body.vault_ref, "vault_ref");
    const material = requiredString(body.material, "material");
    return planAndCommitVaultControl(
      this,
      "model_mount.vault_ref.bind",
      {
        body,
        vaultRef,
        material,
      },
    );
  }

  listVaultRefs() {
    return planAndCommitVaultControl(this, "model_mount.vault_ref.list");
  }

  vaultRefMetadata(body = {}) {
    assertCanonicalVaultOperationRequestBody(body);
    const vaultRef = requiredString(body.vault_ref, "vault_ref");
    return planAndCommitVaultControl(
      this,
      "model_mount.vault_ref.metadata",
      { body, vaultRef },
    );
  }

  vaultStatus() {
    return planAndCommitVaultControl(this, "model_mount.vault.status");
  }

  vaultHealth() {
    return planAndCommitVaultControl(this, "model_mount.vault.health");
  }

  removeVaultRef(body = {}) {
    assertCanonicalVaultOperationRequestBody(body);
    const vaultRef = requiredString(body.vault_ref, "vault_ref");
    return planAndCommitVaultControl(
      this,
      "model_mount.vault_ref.remove",
      { body, vaultRef },
    );
  }

  createToken(body = {}) {
    return planAndCommitCapabilityTokenControl(
      this,
      "model_mount.capability_token.create",
      { body },
    );
  }

  listTokens() {
    return planAndCommitCapabilityTokenControl(this, "model_mount.capability_token.list");
  }

  revokeToken(tokenId) {
    return planAndCommitCapabilityTokenControl(
      this,
      "model_mount.capability_token.revoke",
      { tokenId: requiredString(tokenId, "token_id") },
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
    const token = authorization.slice("Bearer ".length).trim();
    if (!token) {
      throw runtimeError({
        status: 401,
        code: "auth",
        message: "Bearer capability token is required for this model mounting operation.",
        details: { required_scope: requiredScope },
      });
    }
    return planAndCommitCapabilityTokenControl(
      this,
      "model_mount.capability_token.authorize",
      {
        tokenHash: hashToken(token),
        requiredScope,
      },
    );
  }

  upsertProvider(body = {}) {
    assertCanonicalProviderUpsertRequestBody(body);
    assertNoPlaintextProviderSecret(body);
    const id = optionalString(body.id) ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
    const existing = optionalProviderState(this, id) ?? {};
    const kind = optionalString(body.kind) ?? optionalString(existing.kind) ?? "custom_http";
    const controlBody = providerControlBody(body, existing, { id, kind });
    const authMaterialization = planAndCommitProviderAuthMaterialization(
      this,
      "model_mount.provider_auth.materialize",
      {
        providerId: id,
        body: controlBody,
        custodyRef: optionalString(body.custody_ref) ?? optionalString(providerSecretInput(body)),
        requiredScope: `provider.auth:${id}`,
      },
    );
    if (authMaterialization) {
      controlBody.provider_auth_materialization_ref = authMaterialization.provider_auth_materialization_ref;
      controlBody.outbound_header_binding_ref = authMaterialization.outbound_header_binding_ref;
      controlBody.auth_header_materialization_status =
        authMaterialization.auth_header_materialization_status;
      controlBody.evidence_refs = uniqueModelMountRefs([
        ...(Array.isArray(controlBody.evidence_refs) ? controlBody.evidence_refs : []),
        ...(Array.isArray(authMaterialization.evidence_refs) ? authMaterialization.evidence_refs : []),
      ]);
    }
    return planAndCommitProviderControl(this, "model_mount.provider.write", {
      providerId: id,
      body: controlBody,
      custodyRef: optionalString(body.custody_ref) ?? optionalString(providerSecretInput(body)),
      requiredScope: `provider.write:${id}`,
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
    return planProviderLifecycle(this, provider, {
      action: "health",
      operation: "provider_health",
      operation_kind: "model_mount.provider.health",
      commitRecordState: true,
    });
  }

  async listProviderModels(providerId) {
    const provider = this.provider(providerId);
    return planProviderInventory(this, provider, {
      action: "list_models",
      operation: "provider_models_list",
      operation_kind: "model_mount.provider.inventory.list_models",
    });
  }

  async listProviderLoaded(providerId) {
    const provider = this.provider(providerId);
    return planProviderInventory(this, provider, {
      action: "list_loaded",
      operation: "provider_loaded_list",
      operation_kind: "model_mount.provider.inventory.list_loaded",
    });
  }

  async startProvider(providerId) {
    const provider = this.provider(providerId);
    return planProviderLifecycle(this, provider, {
      action: "load",
      operation: "provider_start",
      operation_kind: "model_mount.provider.start",
      commitRecordState: true,
    });
  }

  async stopProvider(providerId) {
    const provider = this.provider(providerId);
    return planProviderLifecycle(this, provider, {
      action: "unload",
      operation: "provider_stop",
      operation_kind: "model_mount.provider.stop",
      commitRecordState: true,
    });
  }

  upsertRoute(body = {}) {
    return upsertRouteState(this, body, { normalizeScopes, safeId });
  }

  nextReceiptId(kind) {
    return `receipt_${kind}_${crypto.randomUUID()}`;
  }

  agentgresModelMountingHead() {
    const sequence = this.listReceipts().length;
    return this.modelMountCore.planAcceptedReceiptHead({
      schema_version: "ioi.model_mount.accepted_receipt_head.v1",
      sequence,
    });
  }

  admitModelMountRouteDecision(request) {
    return this.modelMountCore.admitRouteDecision(request);
  }

  admitModelMountInvocation(request) {
    return this.modelMountCore.admitInvocation(request);
  }

  admitModelMountProviderExecution(request) {
    return this.modelMountCore.admitProviderExecution(request);
  }

  planModelMountAcceptedReceiptTransition(request) {
    return this.modelMountCore.planAcceptedReceiptTransition(request);
  }

  executeModelMountProviderInvocation(request) {
    return this.modelMountCore.executeProviderInvocation(request);
  }

  executeModelMountProviderStreamInvocation(request) {
    return this.modelMountCore.executeProviderStreamInvocation(request);
  }

  planModelMountProviderLifecycle(request) {
    return this.modelMountCore.planProviderLifecycle(request);
  }

  planModelMountProviderControl(request) {
    return this.modelMountCore.planProviderControl(request);
  }

  planModelMountProviderAuthMaterialization(request) {
    return this.modelMountCore.planProviderAuthMaterialization(request);
  }

  planProviderLifecycle(provider, options = {}) {
    return planProviderLifecycle(this, provider, options);
  }

  planModelMountProviderInventory(request) {
    return this.modelMountCore.planProviderInventory(request);
  }

  planModelMountInstanceLifecycle(request) {
    return this.modelMountCore.planInstanceLifecycle(request);
  }

  admitModelMountProviderResult(request) {
    return this.modelMountCore.admitProviderResult(request);
  }

  bindModelMountInvocationReceipt(request) {
    return this.modelMountCore.bindInvocationReceipt(request);
  }

  planBackendLifecycle(request) {
    if (typeof this.modelMountCore?.planBackendLifecycle !== "function") {
      throwBackendLifecycleRustCoreRequired({
        operation_kind: request?.operation_kind ?? "model_mount.backend_lifecycle",
        details: request?.body,
      });
    }
    return this.modelMountCore.planBackendLifecycle(request);
  }

  planRuntimeEngine(request) {
    if (typeof this.modelMountCore?.planRuntimeEngine !== "function") {
      throwRuntimeEngineRustCoreRequired({
        operation_kind: request?.operation_kind ?? "model_mount.runtime_engine",
        details: request?.body,
      });
    }
    return this.modelMountCore.planRuntimeEngine(request);
  }

  routeControlRequired(operation_kind, details = {}) {
    return this.modelMountCore.planRouteControlRequired({
      schema_version: "ioi.model_mount.route_control_required.v1",
      operation: "model_mount.route_control",
      operation_kind,
      source: "runtime-daemon.model_mounting.route_control",
      evidence_refs: [
        "model_mount_route_control_js_facade_retired",
        "rust_daemon_core_route_control_required",
        "agentgres_route_truth_required",
      ],
      details,
    });
  }

  planRouteControl(request) {
    return this.modelMountCore.planRouteControl(request);
  }

  planArtifactEndpoint(request) {
    if (typeof this.modelMountCore?.planArtifactEndpoint !== "function") {
      throwArtifactEndpointRustCoreRequired(
        request?.operation_kind ?? "model_mount.artifact_endpoint",
        {
          rust_core_api: "daemonCoreModelMountApi.planModelMountArtifactEndpoint",
        },
      );
    }
    return this.modelMountCore.planArtifactEndpoint(request);
  }

  planStorageControl(request) {
    if (typeof this.modelMountCore?.planStorageControl !== "function") {
      throwModelStorageRustCoreRequired(
        request?.operation_kind ?? "model_mount.storage_control",
        {
          rust_core_api: "plan_model_mount_storage_control",
        },
      );
    }
    return this.modelMountCore.planStorageControl(request);
  }

  planModelMountMcpWorkflow(request) {
    if (typeof this.modelMountCore?.planMcpWorkflow !== "function") {
      throwMcpWorkflowRustCoreRequired(request?.operation_kind ?? "model_mount.mcp_workflow", {
        rust_core_api: "plan_model_mount_mcp_workflow",
      });
    }
    return this.modelMountCore.planMcpWorkflow(request);
  }

  planCatalogProviderControl(request) {
    return this.modelMountCore.planCatalogProviderControl(request);
  }

  planCapabilityTokenControl(request) {
    return this.modelMountCore.planCapabilityTokenControl(request);
  }

  planVaultControl(request) {
    return this.modelMountCore.planVaultControl(request);
  }

  planServerControl(request) {
    if (typeof this.modelMountCore?.planServerControl !== "function") {
      throwServerControlRustCoreRequired({
        operation_kind: request?.operation_kind ?? "model_mount.server_control",
        details: request?.body,
      });
    }
    return this.modelMountCore.planServerControl(request);
  }

  planReceiptGate(request) {
    return this.modelMountCore.planReceiptGate(request);
  }

  planTokenizer(request) {
    return this.modelMountCore.planTokenizer(request);
  }

  planModelMountConversationState(request) {
    return this.modelMountCore.planConversationState(request);
  }

  planModelMountStreamCompletion(request) {
    return this.modelMountCore.planStreamCompletion(request);
  }

  planModelMountStreamCancel(request) {
    return this.modelMountCore.planStreamCancel(request);
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
    const requestBody = body && typeof body === "object" && !Array.isArray(body) ? body : {};
    const routeSelection = this.selectRoute({
      modelId: requestBody.model ?? requestBody.model_id ?? null,
      routeId: requestBody.route_id ?? "route.local-first",
      capability: requestBody.capability ?? "chat",
      policy: requestBody.model_policy,
      body: requestBody,
    });
    const plan = this.planTokenizer(tokenizerRequestForMountedState(this, {
      operation,
      body: requestBody,
      requiredScope,
      routeSelection,
    }));
    const commit = commitTokenizerControlPlanState(this, plan);
    return tokenizerControlResponse(plan, commit);
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

  nextResponseId(requested) {
    const responseId = optionalString(requested) ?? `resp_${crypto.randomUUID()}`;
    if (this.listConversations().some((record) => record?.id === responseId || record?.response_id === responseId)) {
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
    const record = this.listConversations().find((item) => item?.id === responseId || item?.response_id === responseId);
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
    const plan = this.planModelMountConversationState(modelConversationStateRequestForMountedState(this, {
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
    }));
    return commitModelConversationPlanRecordState(this, plan, {
      unconfiguredCode: "model_mount_conversation_state_record_state_commit_unconfigured",
      unconfiguredMessage:
        "Model conversation state writes require Rust Agentgres record-state commit before response truth can return.",
      invalidCode: "model_mount_conversation_state_record_state_commit_invalid",
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
    const currentHead = this.agentgresModelMountingHead();
    const receiptId = this.nextReceiptId("model_invocation_stream_completed");
    const plan = this.planModelMountStreamCompletion(modelStreamCompletionRequestForMountedState(this, {
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded,
      finishReason,
      providerResult,
      providerStreamShapeSummary,
      currentHead,
      receiptId,
    }));
    const conversation = commitModelConversationPlanRecordState(this, plan, {
      unconfiguredCode: "model_mount_stream_completion_record_state_commit_unconfigured",
      unconfiguredMessage:
        "Model stream completion requires Rust Agentgres conversation record-state commit before stream truth can return.",
      invalidCode: "model_mount_stream_completion_record_state_commit_invalid",
    });
    const receipt = this.persistRustAuthoredReceipt(plan.receipt);
    if (invocation && typeof invocation === "object") {
      invocation.conversationState = conversation.record;
      invocation.streamCompletionReceipt = receipt;
    }
    return {
      ...receipt,
      conversation_state: conversation.record,
      conversationState: conversation.record,
      stream_completion_hash: plan.stream_completion_hash,
      conversation_hash: plan.conversation_hash,
      record_commit: conversation.commit,
    };
  }

  recordModelStreamCanceled({
    invocation,
    streamKind,
    outputText = "",
    providerUsage = null,
    framesWritten = 0,
    cancelReason = "client_disconnect",
    providerResult = {},
    providerStreamShapeSummary = null,
  }) {
    const currentHead = this.agentgresModelMountingHead();
    const receiptId = this.nextReceiptId("model_invocation_stream_canceled");
    const plan = this.planModelMountStreamCancel(modelStreamCancelRequestForMountedState(this, {
      invocation,
      streamKind,
      outputText,
      providerUsage,
      framesWritten,
      cancelReason,
      providerResult,
      providerStreamShapeSummary,
      currentHead,
      receiptId,
    }));
    const conversation = commitModelConversationPlanRecordState(this, plan, {
      unconfiguredCode: "model_mount_stream_cancel_record_state_commit_unconfigured",
      unconfiguredMessage:
        "Model stream cancellation requires Rust Agentgres conversation record-state commit before stream truth can return.",
      invalidCode: "model_mount_stream_cancel_record_state_commit_invalid",
    });
    const receipt = this.persistRustAuthoredReceipt(plan.receipt);
    if (invocation && typeof invocation === "object") {
      invocation.conversationState = conversation.record;
      invocation.streamCancelReceipt = receipt;
    }
    return {
      ...receipt,
      conversation_state: conversation.record,
      conversationState: conversation.record,
      stream_cancel_hash: plan.stream_cancel_hash,
      conversation_hash: plan.conversation_hash,
      record_commit: conversation.commit,
    };
  }

  compileEphemeralMcpIntegrations({ authorization, body = {}, input }) {
    void authorization;
    const integrations = Array.isArray(body.integrations) ? body.integrations : [];
    const ephemeral = integrations.filter((integration) => integration?.type === "ephemeral_mcp");
    for (const integration of ephemeral) {
      assertCanonicalEphemeralMcpIntegration(integration);
    }
    if (ephemeral.length > 0) {
      const result = planAndCommitMcpWorkflow(this, "model_mount.mcp_server.ephemeral_register", {
        body: {
          integrations: ephemeral,
          input,
        },
        requiredScope: "model.mcp.ephemeral_register",
      });
      return {
        toolReceiptIds: Array.isArray(result.tool_receipt_ids) ? result.tool_receipt_ids : [],
        serverIds: Array.isArray(result.server_ids) ? result.server_ids : [],
        evidenceRefs: result.evidence_refs ?? [],
        commit: result.commit,
        record: result.record,
      };
    }
    return { toolReceiptIds: [], serverIds: [], evidenceRefs: [] };
  }

  importMcpJson(body = {}) {
    assertCanonicalMcpImportRequestBody(body);
    return planAndCommitMcpWorkflow(this, "model_mount.mcp_server.import", {
      body,
      requiredScope: "model.mcp.import",
    });
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
    return modelMountReadProjection(this, "mcp_servers");
  }

  listConversations() {
    return modelMountReadProjection(this, "model_conversation_states");
  }

  invokeMcpTool({ authorization, body = {} }) {
    void authorization;
    assertCanonicalMcpToolInvocationRequestBody(body);
    return planAndCommitMcpWorkflow(this, "model_mount.mcp_tool.invoke", {
      body,
      requiredScope: `model.mcp.tool.invoke:${body.server_id ?? "unknown"}:${body.tool ?? "unknown"}`,
    });
  }

  async executeWorkflowNode({ authorization, body = {} }) {
    void authorization;
    assertCanonicalWorkflowNodeExecutionRequestBody(body);
    return planAndCommitMcpWorkflow(this, "model_mount.workflow_node.execute", {
      body,
      requiredScope: `model.workflow_node.execute:${body.workflow_node_id ?? body.node ?? body.node_type ?? "unknown"}`,
    });
  }

  validateReceiptGate(body = {}) {
    return validateReceiptGateRule({
      body,
      getReceipt: (receiptId) => this.getReceipt(receiptId),
      normalizeScopes,
      nowIso: () => this.nowIso(),
      persistRustAuthoredReceipt: (record) => this.persistRustAuthoredReceipt(record),
      planReceiptGate: (request) => this.planReceiptGate(request),
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

  persistRustAuthoredReceipt(record) {
    return this.persistRustAuthoredReceiptWithCommit(record).receipt;
  }

  persistRustAuthoredReceiptWithCommit(record) {
    assertRustAuthoredReceiptRecord(record);
    const commit = this.store.writeReceipt(record);
    return { receipt: record, commit };
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
    const plan = this.planRouteControl(routeControlRequestForMountedState(this, {
      operation_kind: "model_mount.route.explicit_model_endpoints",
      route_id: route?.id ?? "route.local-first",
      body: { model_id: modelId ?? null },
      current_route: route ?? null,
    }));
    const commit = commitRouteControlPlanState(this, plan, {
      recordDir: plan.record_dir,
      record: plan.record,
      operation_kind: plan.operation_kind,
      receipt_refs: plan.receipt_refs,
      unconfiguredCode: "model_mount_route_endpoint_resolution_commit_unconfigured",
      unconfiguredMessage:
        "Model route explicit endpoint resolution requires Rust Agentgres record-state commit.",
      invalidCode: "model_mount_route_endpoint_resolution_commit_invalid",
    });
    void commit;
    return Array.isArray(plan.record?.endpoint_ids) ? plan.record.endpoint_ids : [];
  }

  selectRoute({ modelId, routeId, capability, policy, body = {} }) {
    const requestBody = body && typeof body === "object" && !Array.isArray(body) ? body : {};
    const selectedRouteId = routeId ?? requestBody.route_id ?? "route.local-first";
    const currentRoute = routeControlRouteForMountedState(this, selectedRouteId);
    const selectedModel = modelId ?? requestBody.model ?? requestBody.model_id ?? null;
    const selectedCapability = capability ?? requestBody.capability ?? "chat";
    const selectedPolicy = policy && typeof policy === "object" && !Array.isArray(policy)
      ? policy
      : requestBody.model_policy;
    const plan = this.planRouteControl(routeControlRequestForMountedState(this, {
      operation_kind: "model_mount.route.select",
      route_id: selectedRouteId,
      body: {
        ...requestBody,
        model: selectedModel,
        route_id: selectedRouteId,
        capability: selectedCapability,
        ...(selectedPolicy && typeof selectedPolicy === "object" && !Array.isArray(selectedPolicy)
          ? { model_policy: selectedPolicy }
          : {}),
      },
      current_route: currentRoute,
    }));
    const commit = commitRouteControlPlanState(this, plan, {
      recordDir: plan.record_dir,
      record: plan.record,
      operation_kind: plan.operation_kind,
      receipt_refs: plan.receipt_refs,
      unconfiguredCode: "model_mount_route_selection_commit_unconfigured",
      unconfiguredMessage:
        "Model route selection requires Rust Agentgres record-state commit before route truth can return.",
      invalidCode: "model_mount_route_selection_commit_invalid",
    });
    const routeReceipt = plan.record?.accepted_receipt_record ?? null;
    const receiptCommit = routeReceipt && typeof this.persistRustAuthoredReceipt === "function"
      ? this.persistRustAuthoredReceipt(routeReceipt)
      : null;
    return {
      route: plan.record?.route ?? null,
      endpoint: plan.record?.endpoint ?? null,
      provider: plan.record?.provider ?? null,
      route_decision: plan.record?.route_decision ?? null,
      route_receipt: routeReceipt,
      routeReceipt,
      route_control: {
        record_dir: plan.record_dir,
        record_id: plan.record_id,
        control_hash: plan.control_hash,
        commit,
        receipt_commit: receiptCommit,
      },
      rust_core_boundary: plan.rust_core_boundary,
      evidence_refs: plan.evidence_refs,
    };
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

  backendRegistry() {
    return modelMountReadProjection(this, "backends");
  }

  listBackends() {
    return modelMountReadProjection(this, "backends");
  }

  runtimePreference() {
    return modelMountReadProjection(this, "runtime_preference");
  }

  runtimePreferenceForEndpoint(endpoint = {}) {
    return modelMountReadProjection(this, "runtime_preference_for_endpoint", { endpoint });
  }

  runtimeEngineProfile(engineId) {
    return modelMountReadProjection(this, "runtime_engine_profiles")
      .find((profile) => profile.id === engineId) ?? null;
  }

  listRuntimeEngineProfiles() {
    return modelMountReadProjection(this, "runtime_engine_profiles");
  }

  runtimeDefaultLoadOptions(engineId) {
    return modelMountReadProjection(this, "runtime_default_load_options", { engineId });
  }

  runtimeEngine(engineId) {
    try {
      return modelMountReadProjection(this, "runtime_engine_detail", { engineId });
    } catch (error) {
      throw translateRuntimeEngineError(error, engineId);
    }
  }

  selectRuntimeEngine(body = {}) {
    const engineId = requiredString(body.engine_id, "engine_id");
    return commitRuntimeEngineForState(this, "model_mount.runtime_preference.write", {
      engine_id: engineId,
      body: runtimeEngineControlBody(body),
    });
  }

  updateRuntimeEngine(engineId, body = {}) {
    const resolvedEngineId = requiredString(engineId, "engine_id");
    return commitRuntimeEngineForState(this, "model_mount.runtime_engine_profile.write", {
      engine_id: resolvedEngineId,
      body: runtimeEngineControlBody({ ...body, engine_id: resolvedEngineId }),
    });
  }

  removeRuntimeEngineOverride(engineId) {
    const resolvedEngineId = requiredString(engineId, "engine_id");
    return commitRuntimeEngineForState(this, "model_mount.runtime_engine_profile.delete", {
      engine_id: resolvedEngineId,
    });
  }

  listRuntimeEngines() {
    return modelMountReadProjection(this, "runtime_engines");
  }

  runtimeSurvey() {
    const checkedAt = this.nowIso();
    const plan = planRuntimeSurveyForState(this, {
      schema_version: "ioi.model_mount.runtime_survey.v1",
      operation_kind: "model_mount.runtime_survey.capture",
      source: "runtime-daemon.model_mounting.runtime_survey",
      generated_at: checkedAt,
      state_dir: this.stateDir,
      body: {},
    });
    const { receipt, commit } = persistRuntimeSurveyReceiptForState(this, plan);
    const response = plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? { ...plan.public_response }
      : {};
    return {
      ...response,
      receiptId: receipt.id,
      receiptCommitHash: commit.commit_hash,
      receiptStateCommit: {
        source: commit.source ?? "rust_agentgres_runtime_model_mount_receipt_state_commit_protocol",
        objectRef: commit.object_ref,
        contentHash: commit.content_hash,
        admissionHash: commit.admission_hash,
        commitHash: commit.commit_hash,
        writtenRecord: commit.written_record,
      },
      evidenceRefs: Array.isArray(response.evidenceRefs)
        ? response.evidenceRefs
        : plan.evidence_refs,
    };
  }

  latestRuntimeSurvey() {
    return modelMountReadProjection(this, "latest_runtime_survey");
  }

  backend(backendId) {
    const record = this.backendRegistry().find((item) => item.id === backendId);
    if (!record) throw notFound(`Model backend not found: ${backendId}`, { backend_id: backendId });
    return record;
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
    return this.modelMountCore.planBackendProcess(request);
  }

  backendProcessArgs(backend, options = {}) {
    return this.backendProcessPlan(backend, options).public_args;
  }

  backendProcessSpawnArgs(backend, options = {}) {
    return this.backendProcessPlan(backend, options).spawn_args;
  }

  backendSupportsSupervision(backend) {
    return this.backendProcessPlan(backend).supports_supervision;
  }

  backendHealth(backendId) {
    const resolvedBackendId = requiredString(backendId, "backend_id");
    return commitBackendLifecycleForState(this, "model_mount.backend.health", {
      backend_id: resolvedBackendId,
    });
  }

  startBackend(backendId, body = {}) {
    const resolvedBackendId = requiredString(backendId, "backend_id");
    const source = body && typeof body === "object" && !Array.isArray(body) ? body : {};
    return commitBackendLifecycleForState(this, "model_mount.backend.start", {
      backend_id: resolvedBackendId,
      body: backendLifecycleControlBody({
        ...source,
        backend_id: resolvedBackendId,
        load_options: source.load_options ?? source.loadOptions,
      }),
    });
  }

  stopBackend(backendId) {
    const resolvedBackendId = requiredString(backendId, "backend_id");
    return commitBackendLifecycleForState(this, "model_mount.backend.stop", {
      backend_id: resolvedBackendId,
    });
  }

  backendLogs(backendId, query = {}) {
    const resolvedBackendId = requiredString(backendId, "backend_id");
    return modelMountReadProjection(this, "backend_logs", {
      backendLogQuery: canonicalModelMountBackendLogQuery(resolvedBackendId, query),
    });
  }

  writeBackendLog(endpointId, event) {
    return writeBackendLogState(this, endpointId, event, {
      randomUUID: () => crypto.randomUUID(),
      redact,
      safeFileName,
    });
  }
}

function planRuntimeSurveyForState(state, request) {
  const core = state?.modelMountCore;
  if (!core || typeof core.planRuntimeSurvey !== "function") {
    throwRuntimeSurveyRustCoreRequired({
      operation: "runtime_survey",
      operation_kind: "model_mount.runtime_survey.capture",
      missing: "modelMountCore.planRuntimeSurvey",
    });
  }
  return core.planRuntimeSurvey(request);
}

function persistRuntimeSurveyReceiptForState(state, plan = {}) {
  assertRuntimeSurveyPlanRustOwned(plan);
  if (!state?.store || typeof state.store.writeReceipt !== "function") {
    const error = new Error("Runtime survey receipt persistence requires Rust Agentgres receipt-state commit.");
    error.status = 500;
    error.code = "model_mount_runtime_survey_receipt_state_commit_unconfigured";
    error.details = {
      receipt_id: plan.receipt?.id ?? null,
      rust_core_boundary: "model_mount.runtime_survey",
      evidence_refs: [
        "model_mount_runtime_survey_js_facade_retired",
        "rust_daemon_core_runtime_survey",
        "agentgres_runtime_survey_truth_required",
      ],
    };
    throw error;
  }
  const commit = state.store.writeReceipt(plan.receipt);
  return { receipt: plan.receipt, commit };
}

function assertRuntimeSurveyPlanRustOwned(plan = {}) {
  const receipt = plan.receipt && typeof plan.receipt === "object" && !Array.isArray(plan.receipt)
    ? plan.receipt
    : null;
  const details = receipt?.details && typeof receipt.details === "object" && !Array.isArray(receipt.details)
    ? receipt.details
    : {};
  const evidenceRefs = Array.isArray(plan.evidence_refs) ? plan.evidence_refs : [];
  const receiptEvidenceRefs = Array.isArray(receipt?.evidenceRefs) ? receipt.evidenceRefs : [];
  const missing = [];
  if (plan.rust_core_boundary !== "model_mount.runtime_survey") missing.push("rust_core_boundary");
  if (plan.operation_kind !== "model_mount.runtime_survey.capture") missing.push("operation_kind");
  if (!plan.survey_hash) missing.push("survey_hash");
  if (!receipt) missing.push("receipt");
  if (receipt?.kind !== "runtime_survey") missing.push("receipt.kind");
  if (!receipt?.schemaVersion) missing.push("receipt.schemaVersion");
  if (!receipt?.createdAt) missing.push("receipt.createdAt");
  if (details.rust_daemon_core_receipt_author !== "model_mount.runtime_survey") {
    missing.push("receipt.details.rust_daemon_core_receipt_author");
  }
  for (const field of ["checked_at", "engine_count", "selected_engines", "runtime_preference", "hardware", "lm_studio", "runtime_survey_hash"]) {
    if (!Object.hasOwn(details, field)) missing.push(`receipt.details.${field}`);
  }
  for (const field of [
    ["js_hardware_probe_executed", false],
    ["js_runtime_engine_read_executed", false],
    ["js_lm_studio_probe_executed", false],
  ]) {
    if (details[field[0]] !== field[1]) missing.push(`receipt.details.${field[0]}_false`);
  }
  for (const evidenceRef of [
    "model_mount_runtime_survey_js_facade_retired",
    "rust_daemon_core_runtime_survey",
    "agentgres_runtime_survey_truth_required",
    "rust_model_mount_core",
  ]) {
    if (!evidenceRefs.includes(evidenceRef)) missing.push(`evidence_refs.${evidenceRef}`);
    if (!receiptEvidenceRefs.includes(evidenceRef)) missing.push(`receipt.evidenceRefs.${evidenceRef}`);
  }
  if (missing.length === 0) return;
  const error = new Error("Runtime survey capture requires a Rust-authored runtime_survey receipt plan.");
  error.status = 502;
  error.code = "model_mount_runtime_survey_plan_invalid";
  error.details = {
    missing,
    rust_core_boundary: "model_mount.runtime_survey",
    source: plan.source ?? null,
    backend: plan.backend ?? null,
  };
  throw error;
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

function throwBackendLifecycleRustCoreRequired(record = {}) {
  const details = record.details && typeof record.details === "object" && !Array.isArray(record.details)
    ? record.details
    : {};
  const evidenceRefs = Array.isArray(details.evidence_refs)
    ? details.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [
          "public_backend_lifecycle_js_facade_retired",
          "rust_daemon_core_backend_lifecycle",
          "agentgres_backend_lifecycle_truth_required",
        ];
  throw runtimeError({
    status: record.status_code ?? 501,
    code: record.code ?? "model_mount_backend_lifecycle_rust_core_required",
    message:
      record.message ??
      "Backend lifecycle facade control requires Rust daemon-core model_mount lifecycle ownership.",
    details: {
      ...details,
      operation_kind: details.operation_kind ?? record.operation_kind ?? "model_mount.backend_lifecycle",
      rust_core_boundary: details.rust_core_boundary ?? record.rust_core_boundary ?? "model_mount.backend_lifecycle",
      evidence_refs: evidenceRefs,
    },
  });
}

function commitBackendLifecycleForState(state, operation_kind, details = {}) {
  if (typeof state.planBackendLifecycle !== "function") {
    throwBackendLifecycleRustCoreRequired({
      operation_kind,
      details,
    });
  }
  const body = backendLifecycleControlBody({
    ...details,
    ...(details.body && typeof details.body === "object" && !Array.isArray(details.body) ? details.body : {}),
  });
  const plan = state.planBackendLifecycle({
    schema_version: "ioi.model_mount.backend_lifecycle.v1",
    operation_kind,
    backend_id: optionalString(details.backend_id) ?? optionalString(body.backend_id),
    backend_kind: optionalString(details.backend_kind) ?? optionalString(body.backend_kind),
    source: "runtime-daemon.model_mounting.backend_lifecycle",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    receipt_refs: uniqueModelMountRefs([
      details.receipt_id,
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
  });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_backend_lifecycle_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Backend lifecycle requires Rust Agentgres record-state commit before backend lifecycle truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.backend_lifecycle",
      operation_kind: plan.operation_kind ?? operation_kind,
    },
    invalidCode: "model_mount_backend_lifecycle_record_state_commit_invalid",
  });
  const publicResponse =
    plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? plan.public_response
      : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? plan.status ?? "planned",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt_refs: plan.receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
  };
}

function backendLifecycleControlBody(value = {}) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const body = {};
  for (const field of [
    "backend_id",
    "backend_kind",
    "receipt_id",
    "base_url",
    "status",
    "reason",
    "limit",
    "details",
    "load_options",
    "receipt_refs",
  ]) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) body[field] = source[field];
  }
  return body;
}

function throwServerControlRustCoreRequired(record = {}) {
  const details = record.details && typeof record.details === "object" && !Array.isArray(record.details)
    ? record.details
    : {};
  const evidenceRefs = Array.isArray(details.evidence_refs)
    ? details.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [
          "public_server_control_js_facade_retired",
          "rust_daemon_core_server_control",
          "agentgres_server_control_truth_required",
        ];
  throw runtimeError({
    status: record.status_code ?? 501,
    code: record.code ?? "model_mount_server_control_rust_core_required",
    message:
      record.message ??
      "Server-control facade requires Rust daemon-core model_mount server-control ownership.",
    details: {
      ...details,
      operation_kind: details.operation_kind ?? record.operation_kind ?? "model_mount.server_control",
      rust_core_boundary: details.rust_core_boundary ?? record.rust_core_boundary ?? "model_mount.server_control",
      evidence_refs: evidenceRefs,
    },
  });
}

function commitServerControlForState(state, operation_kind, details = {}) {
  if (typeof state.planServerControl !== "function") {
    throwServerControlRustCoreRequired({
      operation_kind,
      details,
    });
  }
  const body = serverControlBody({
    ...details,
    ...(details.body && typeof details.body === "object" && !Array.isArray(details.body) ? details.body : {}),
  });
  const plan = state.planServerControl({
    schema_version: "ioi.model_mount.server_control.v1",
    operation_kind,
    server_control_id: optionalString(details.server_control_id) ?? SERVER_CONTROL_RECORD_ID,
    source: "runtime-daemon.model_mounting.server_control",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    receipt_refs: uniqueModelMountRefs([
      details.receipt_id,
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
  });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_server_control_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Server control requires Rust Agentgres record-state commit before server-control truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.server_control",
      operation_kind: plan.operation_kind ?? operation_kind,
    },
    invalidCode: "model_mount_server_control_record_state_commit_invalid",
  });
  const publicResponse =
    plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? plan.public_response
      : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? plan.status ?? "planned",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt_refs: plan.receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
  };
}

function serverControlBody(value = {}) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const body = {};
  for (const field of [
    "server_control_id",
    "receipt_id",
    "base_url",
    "operation",
    "status",
    "reason",
    "limit",
    "event",
    "level",
    "message",
    "details",
    "receipt_refs",
  ]) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) body[field] = source[field];
  }
  return body;
}

function throwRuntimeEngineRustCoreRequired(record = {}) {
  const details = record.details && typeof record.details === "object" && !Array.isArray(record.details)
    ? record.details
    : {};
  const evidenceRefs = Array.isArray(details.evidence_refs)
    ? details.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [
          "public_runtime_engine_js_facade_retired",
          "rust_daemon_core_runtime_engine",
          "agentgres_runtime_engine_truth_required",
        ];
  throw runtimeError({
    status: record.status_code ?? 501,
    code: record.code ?? "model_mount_runtime_engine_rust_core_required",
    message:
      record.message ??
      "Runtime-engine mutation facade requires Rust daemon-core model_mount runtime-engine ownership.",
    details: {
      ...details,
      operation_kind: details.operation_kind ?? record.operation_kind ?? "model_mount.runtime_engine",
      rust_core_boundary: details.rust_core_boundary ?? record.rust_core_boundary ?? "model_mount.runtime_engine",
      evidence_refs: evidenceRefs,
    },
  });
}

function commitRuntimeEngineForState(state, operation_kind, details = {}) {
  if (typeof state.planRuntimeEngine !== "function") {
    throwRuntimeEngineRustCoreRequired({
      operation_kind,
      details,
    });
  }
  const body = runtimeEngineControlBody({
    ...details,
    ...(details.body && typeof details.body === "object" && !Array.isArray(details.body) ? details.body : {}),
  });
  const plan = state.planRuntimeEngine({
    schema_version: "ioi.model_mount.runtime_engine.v1",
    operation_kind,
    engine_id: optionalString(details.engine_id) ?? optionalString(body.engine_id),
    source: "runtime-daemon.model_mounting.runtime_engine",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    receipt_refs: uniqueModelMountRefs([
      details.receipt_id,
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
  });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_runtime_engine_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Runtime engine requires Rust Agentgres record-state commit before runtime-engine truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.runtime_engine",
      operation_kind: plan.operation_kind ?? operation_kind,
    },
    invalidCode: "model_mount_runtime_engine_record_state_commit_invalid",
  });
  const publicResponse =
    plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? plan.public_response
      : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? plan.status ?? "planned",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt_refs: plan.receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
  };
}

function runtimeEngineControlBody(value = {}) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const body = {};
  for (const field of [
    "engine_id",
    "receipt_id",
    "default_load_options",
    "operator_label",
    "details",
    "receipt_refs",
  ]) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) body[field] = source[field];
  }
  return body;
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
    code: "model_mount_storage_control_rust_core_required",
    message:
      "Model storage/download control requires Rust daemon-core model_mount storage-control ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.storage_control",
      evidence_refs: [
        "public_model_storage_js_facade_retired",
        "rust_daemon_core_model_storage",
        "agentgres_model_storage_truth_required",
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

function defaultBackendForProvider(provider = {}) {
  if (provider.kind === "ioi_native_local") return "backend.autopilot.native-local.fixture";
  if (provider.kind === "lm_studio") return "backend.lmstudio";
  if (provider.kind === "ollama") return "backend.ollama";
  if (provider.kind === "vllm") return "backend.vllm";
  if (provider.kind === "llama_cpp") return "backend.llama-cpp";
  if (["openai_compatible", "custom_http", "openai", "anthropic", "gemini"].includes(provider.kind)) {
    return "backend.openai-compatible";
  }
  return "backend.fixture";
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

function planAndCommitProviderControl(state, operation_kind, options = {}) {
  if (typeof state.planModelMountProviderControl !== "function") {
    throw modelMountProviderControlRustCoreRequired({
      id: options.providerId ?? null,
      kind: options.body?.kind ?? null,
    }, "provider_upsert", {
      operation_kind,
      rust_core_api: "plan_model_mount_provider_control",
    });
  }
  const body = providerControlCanonicalBody(options.body);
  const plan = state.planModelMountProviderControl({
    schema_version: MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
    operation_kind,
    provider_id: optionalString(options.providerId) ?? optionalString(body.id),
    source: "runtime-daemon.model_mounting.provider_control",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    receipt_refs: uniqueModelMountRefs([
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
    authority_grant_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : [],
    ),
    authority_receipt_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : [],
    ),
    custody_ref: optionalString(options.custodyRef) ?? optionalString(body.custody_ref),
    containment_ref: optionalString(options.containmentRef) ?? optionalString(body.containment_ref),
    required_scope: optionalString(options.requiredScope),
  });
  assertRustAuthoredProviderControlPlan(plan, { operation_kind });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_provider_control_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Provider control requires Rust Agentgres record-state commit before public provider truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.provider_control",
      operation_kind: plan.operation_kind ?? operation_kind,
      control_hash: plan.control_hash ?? null,
    },
    invalidCode: "model_mount_provider_control_record_state_commit_invalid",
  });
  return providerControlResponse(plan, commit);
}

function planAndCommitProviderAuthMaterialization(state, operation_kind, options = {}) {
  const body = options.body && typeof options.body === "object" && !Array.isArray(options.body)
    ? options.body
    : {};
  const secretRef = optionalString(options.vaultRef) ?? optionalString(body.secret_ref);
  if (!secretRef) return null;
  if (typeof state.planModelMountProviderAuthMaterialization !== "function") {
    throw runtimeError({
      status: 501,
      code: "model_mount_provider_auth_materialization_rust_core_required",
      message: "Provider auth materialization requires Rust daemon-core wallet/cTEE custody ownership.",
      details: {
        provider_id: options.providerId ?? body.id ?? null,
        operation_kind,
        rust_core_boundary: "model_mount.provider_auth_materialization",
        rust_core_api: "daemonCoreModelMountApi.planModelMountProviderAuthMaterialization",
      },
    });
  }
  const plan = state.planModelMountProviderAuthMaterialization({
    schema_version: MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION,
    operation_kind,
    provider_id: optionalString(options.providerId) ?? optionalString(body.id),
    provider_ref: optionalString(body.provider_ref) ??
      (optionalString(options.providerId) ? `provider://${optionalString(options.providerId)}` : null),
    provider_kind: optionalString(body.kind),
    auth_scheme: optionalString(body.auth_scheme),
    auth_header_name: optionalString(body.auth_header_name),
    vault_ref: secretRef,
    source: "runtime-daemon.model_mounting.provider_auth_materialization",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    receipt_refs: uniqueModelMountRefs([
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
    authority_grant_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : [],
    ),
    authority_receipt_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : [],
    ),
    custody_ref: optionalString(options.custodyRef) ?? optionalString(body.custody_ref) ?? secretRef,
    containment_ref: optionalString(options.containmentRef) ?? optionalString(body.containment_ref),
    required_scope: optionalString(options.requiredScope),
  });
  assertRustAuthoredProviderAuthMaterializationPlan(plan, { operation_kind });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_provider_auth_materialization_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Provider auth materialization requires Rust Agentgres record-state commit before provider truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.provider_auth_materialization",
      operation_kind: plan.operation_kind ?? operation_kind,
      materialization_hash: plan.materialization_hash ?? null,
    },
    invalidCode: "model_mount_provider_auth_materialization_record_state_commit_invalid",
  });
  return providerAuthMaterializationResponse(plan, commit);
}

function providerControlBody(body = {}, existing = {}, { id, kind } = {}) {
  const secretInput = providerSecretInput(body);
  const secretRef = secretInput === undefined
    ? optionalString(existing.secret_ref ?? existing.secretRef)
    : optionalString(secretInput);
  const apiFormat = optionalString(body.api_format ?? existing.api_format ?? existing.apiFormat) ??
    providerControlDefaultApiFormat(kind);
  const canonical = providerControlCanonicalBody(body);
  delete canonical.api_key_vault_ref;
  delete canonical.auth_vault_ref;
  return {
    ...canonical,
    id,
    kind,
    provider_ref: optionalString(body.provider_ref ?? existing.provider_ref) ?? `provider://${id}`,
    label: optionalString(body.label ?? existing.label) ?? id,
    status: optionalString(body.status ?? existing.status) ?? (secretRef ? "configured" : "available"),
    api_format: apiFormat,
    driver: optionalString(body.driver ?? existing.driver) ?? providerControlDefaultDriver(kind, apiFormat),
    base_url: optionalString(body.base_url ?? existing.base_url ?? existing.baseUrl),
    privacy_class: optionalString(body.privacy_class ?? existing.privacy_class ?? existing.privacyClass) ?? "workspace",
    capabilities: Array.isArray(body.capabilities)
      ? body.capabilities.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim())
      : Array.isArray(existing.capabilities)
        ? existing.capabilities.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim())
        : [],
    auth_scheme: optionalString(body.auth_scheme ?? existing.auth_scheme ?? existing.authScheme),
    auth_header_name: optionalString(body.auth_header_name ?? existing.auth_header_name ?? existing.authHeaderName),
    secret_ref: secretRef,
    provider_auth_materialization_ref: optionalString(
      body.provider_auth_materialization_ref ?? existing.provider_auth_materialization_ref,
    ),
    outbound_header_binding_ref: optionalString(
      body.outbound_header_binding_ref ?? existing.outbound_header_binding_ref,
    ),
    auth_header_materialization_status: optionalString(
      body.auth_header_materialization_status ?? existing.auth_header_materialization_status,
    ),
    evidence_refs: normalizeScopes(body.evidence_refs, existing.discovery?.evidenceRefs ?? []),
  };
}

function providerControlCanonicalBody(value = {}) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const body = {};
  for (const field of [
    "id",
    "provider_ref",
    "kind",
    "label",
    "status",
    "api_format",
    "driver",
    "base_url",
    "privacy_class",
    "capabilities",
    "auth_scheme",
    "auth_header_name",
    "secret_ref",
    "provider_auth_materialization_ref",
    "outbound_header_binding_ref",
    "auth_header_materialization_status",
    "api_key_vault_ref",
    "auth_vault_ref",
    "evidence_refs",
    "receipt_id",
    "receipt_refs",
    "authority_grant_refs",
    "authority_receipt_refs",
    "custody_ref",
    "containment_ref",
  ]) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) body[field] = source[field];
  }
  return body;
}

function providerControlDefaultApiFormat(kind) {
  if (kind === "local_folder") return "ioi_fixture";
  if (kind === "ioi_native_local") return "ioi_native";
  return kind ?? "custom";
}

function providerControlDefaultDriver(kind, apiFormat) {
  if (kind === "ioi_native_local" || apiFormat === "ioi_native") return "native_local";
  if (kind === "local_folder" || apiFormat === "ioi_fixture" || apiFormat === "fixture") return "fixture";
  if (["ollama", "vllm", "llama_cpp", "lm_studio"].includes(kind)) return kind;
  return "hosted_provider";
}

function assertRustAuthoredProviderControlPlan(plan = {}, options = {}) {
  const record = plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
    ? plan.record
    : {};
  const publicResponse = record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
    ? record.public_response
    : {};
  const evidenceRefs = Array.isArray(plan.evidence_refs) ? plan.evidence_refs : [];
  const recordEvidenceRefs = Array.isArray(record.evidence_refs) ? record.evidence_refs : [];
  const missing = [];
  const mismatches = [];
  if (plan.record_dir !== "model-providers") missing.push("record_dir");
  if (!plan.record_id) missing.push("record_id");
  if (record.id !== plan.record_id) mismatches.push("record.id");
  if (record.record_id !== plan.record_id) mismatches.push("record.record_id");
  if (record.object !== "ioi.model_mount_provider") missing.push("record.object");
  if (record.schema_version !== MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION) missing.push("record.schema_version");
  if (plan.operation_kind !== options.operation_kind) mismatches.push("operation_kind");
  if (plan.rust_core_boundary !== "model_mount.provider_control") missing.push("rust_core_boundary");
  if (!plan.control_hash) missing.push("control_hash");
  if (!plan.authority_hash) missing.push("authority_hash");
  if (record.plaintext_material_returned !== false) missing.push("record.plaintext_material_returned_false");
  if (publicResponse.private_material_returned !== false) missing.push("public_response.private_material_returned_false");
  if (publicResponse.plaintext_material_persisted !== false) {
    missing.push("public_response.plaintext_material_persisted_false");
  }
  for (const ref of [
    "rust_daemon_core_provider_control",
    "ctee_provider_custody_enforced",
    "agentgres_provider_control_truth_required",
  ]) {
    if (!evidenceRefs.includes(ref)) missing.push(`evidence_refs.${ref}`);
    if (!recordEvidenceRefs.includes(ref)) missing.push(`record.evidence_refs.${ref}`);
  }
  if (missing.length === 0 && mismatches.length === 0) return;
  throw runtimeError({
    status: 502,
    code: "model_mount_provider_control_plan_invalid",
    message: "Provider control facade requires a Rust-authored model_mount provider-control plan.",
    details: {
      operation_kind: options.operation_kind ?? null,
      missing,
      mismatches,
    },
  });
}

function providerControlResponse(plan, commit) {
  const record = plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
    ? plan.record
    : {};
  const publicResponse = record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
    ? record.public_response
    : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? "committed",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record,
    commit,
    receipt_refs: plan.receipt_refs,
    authority_grant_refs: plan.authority_grant_refs,
    authority_receipt_refs: plan.authority_receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
    authority_hash: plan.authority_hash,
    js_provider_map_write: false,
    js_vault_resolution: false,
    js_write_map: false,
  };
}

function assertRustAuthoredProviderAuthMaterializationPlan(plan = {}, options = {}) {
  const record = plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
    ? plan.record
    : {};
  const publicResponse = plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
    ? plan.public_response
    : record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
      ? record.public_response
      : {};
  const evidenceRefs = Array.isArray(plan.evidence_refs) ? plan.evidence_refs : [];
  const recordEvidenceRefs = Array.isArray(record.evidence_refs) ? record.evidence_refs : [];
  const missing = [];
  const mismatches = [];
  if (plan.record_dir !== "model-provider-auth-materializations") missing.push("record_dir");
  if (!plan.record_id) missing.push("record_id");
  if (record.id !== plan.record_id) mismatches.push("record.id");
  if (record.record_id !== plan.record_id) mismatches.push("record.record_id");
  if (record.object !== "ioi.model_mount_provider_auth_materialization") missing.push("record.object");
  if (record.schema_version !== MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION) {
    missing.push("record.schema_version");
  }
  if (plan.operation_kind !== options.operation_kind) mismatches.push("operation_kind");
  if (plan.rust_core_boundary !== "model_mount.provider_auth_materialization") missing.push("rust_core_boundary");
  if (!plan.materialization_hash) missing.push("materialization_hash");
  if (!plan.authority_hash) missing.push("authority_hash");
  if (record.auth_header_materialization_status !== "rust_ctee_outbound_header_bound") {
    missing.push("record.auth_header_materialization_status");
  }
  if (record.plaintext_secret_material_returned !== false) {
    missing.push("record.plaintext_secret_material_returned_false");
  }
  if (record.auth_header_value_returned !== false) missing.push("record.auth_header_value_returned_false");
  if (record.auth_header_value_persisted !== false) missing.push("record.auth_header_value_persisted_false");
  if (publicResponse.auth_header_value_returned !== false) {
    missing.push("public_response.auth_header_value_returned_false");
  }
  if (!record.outbound_header_binding_ref) missing.push("record.outbound_header_binding_ref");
  if (!record.provider_auth_materialization_ref) missing.push("record.provider_auth_materialization_ref");
  for (const ref of [
    "rust_daemon_core_provider_auth_materialization",
    "rust_provider_auth_materialization_bound",
    "wallet_network_provider_vault_ref_bound",
    "ctee_provider_auth_header_custody_enforced",
    "agentgres_provider_auth_materialization_truth_required",
  ]) {
    if (!evidenceRefs.includes(ref)) missing.push(`evidence_refs.${ref}`);
    if (!recordEvidenceRefs.includes(ref)) missing.push(`record.evidence_refs.${ref}`);
  }
  if (missing.length === 0 && mismatches.length === 0) return;
  throw runtimeError({
    status: 502,
    code: "model_mount_provider_auth_materialization_plan_invalid",
    message:
      "Provider auth materialization facade requires a Rust-authored wallet/cTEE outbound-header plan.",
    details: {
      operation_kind: options.operation_kind ?? null,
      missing,
      mismatches,
    },
  });
}

function providerAuthMaterializationResponse(plan, commit) {
  const record = plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
    ? plan.record
    : {};
  const publicResponse = plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
    ? plan.public_response
    : record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
      ? record.public_response
      : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? "materialized",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record,
    commit,
    receipt_refs: plan.receipt_refs,
    authority_grant_refs: plan.authority_grant_refs,
    authority_receipt_refs: plan.authority_receipt_refs,
    evidence_refs: plan.evidence_refs,
    materialization_hash: plan.materialization_hash,
    authority_hash: plan.authority_hash,
    js_auth_header_materialization: false,
    js_vault_resolution: false,
  };
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
        "rust_daemon_core_artifact_endpoint",
        "agentgres_artifact_endpoint_truth_required",
      ],
      ...details,
    },
  });
}

function planAndCommitArtifactEndpoint(state, operation_kind, options = {}) {
  if (typeof state.planArtifactEndpoint !== "function") {
    throwArtifactEndpointRustCoreRequired(operation_kind, {
      rust_core_api: "daemonCoreModelMountApi.planModelMountArtifactEndpoint",
    });
  }
  const body = artifactEndpointBody(options.body);
  const plan = state.planArtifactEndpoint({
    schema_version: MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
    operation_kind,
    source: "runtime-daemon.model_mounting.artifact_endpoint",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    receipt_refs: uniqueModelMountRefs([
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
    authority_grant_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : [],
    ),
    authority_receipt_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : [],
    ),
    custody_ref: optionalString(options.custodyRef) ?? optionalString(body.custody_ref),
    containment_ref: optionalString(options.containmentRef) ?? optionalString(body.containment_ref),
    required_scope: optionalString(options.requiredScope),
  });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_artifact_endpoint_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Artifact and endpoint mutation requires Rust Agentgres record-state commit before public model-mount truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.artifact_endpoint",
      operation_kind: plan.operation_kind ?? operation_kind,
    },
    invalidCode: "model_mount_artifact_endpoint_record_state_commit_invalid",
  });
  const publicResponse =
    plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? plan.public_response
      : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? "committed",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt_refs: plan.receipt_refs,
    authority_grant_refs: plan.authority_grant_refs,
    authority_receipt_refs: plan.authority_receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
    authority_hash: plan.authority_hash,
  };
}

function artifactEndpointBody(value = {}) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const body = {};
  for (const field of [
    "artifact_id",
    "endpoint_id",
    "model_id",
    "source_path",
    "local_path",
    "import_mode",
    "provider_id",
    "provider_kind",
    "display_name",
    "family",
    "quantization",
    "size_bytes",
    "context_window",
    "capabilities",
    "privacy_class",
    "api_format",
    "base_url",
    "backend_id",
    "driver",
    "load_policy",
    "receipt_id",
    "receipt_refs",
    "authority_grant_refs",
    "authority_receipt_refs",
    "custody_ref",
    "containment_ref",
  ]) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) body[field] = source[field];
  }
  return body;
}

function planAndCommitStorageControl(state, operation_kind, options = {}) {
  if (typeof state.planStorageControl !== "function") {
    throwModelStorageRustCoreRequired(operation_kind, {
      rust_core_api: "plan_model_mount_storage_control",
    });
  }
  const body = storageControlBody(options.body);
  const plan = state.planStorageControl({
    schema_version: MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION,
    operation_kind,
    source: "runtime-daemon.model_mounting.storage_control",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    receipt_refs: uniqueModelMountRefs([
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
    authority_grant_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : [],
    ),
    authority_receipt_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : [],
    ),
    custody_ref: optionalString(options.custodyRef) ?? optionalString(body.custody_ref),
    containment_ref: optionalString(options.containmentRef) ?? optionalString(body.containment_ref),
    required_scope: optionalString(options.requiredScope),
  });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_storage_control_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Model storage/download control requires Rust Agentgres record-state commit before public model-mount truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.storage_control",
      operation_kind: plan.operation_kind ?? operation_kind,
    },
    invalidCode: "model_mount_storage_control_record_state_commit_invalid",
  });
  const publicResponse =
    plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? plan.public_response
      : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? "committed",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt_refs: plan.receipt_refs,
    authority_grant_refs: plan.authority_grant_refs,
    authority_receipt_refs: plan.authority_receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
    authority_hash: plan.authority_hash,
  };
}

function planAndCommitMcpWorkflow(state, operation_kind, options = {}) {
  if (typeof state.planModelMountMcpWorkflow !== "function") {
    throwMcpWorkflowRustCoreRequired(operation_kind, {
      rust_core_api: "plan_model_mount_mcp_workflow",
    });
  }
  const body = mcpWorkflowBody(options.body);
  const plan = state.planModelMountMcpWorkflow({
    schema_version: MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION,
    operation_kind,
    source: "runtime-daemon.model_mounting.mcp_workflow",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    receipt_refs: uniqueModelMountRefs([
      body.receipt_id,
      ...(Array.isArray(body.receipt_refs) ? body.receipt_refs : []),
    ]),
    authority_grant_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : [],
    ),
    authority_receipt_refs: uniqueModelMountRefs(
      Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : [],
    ),
    custody_ref: optionalString(options.custodyRef) ?? optionalString(body.custody_ref),
    containment_ref: optionalString(options.containmentRef) ?? optionalString(body.containment_ref),
    required_scope: optionalString(options.requiredScope),
  });
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    unconfiguredCode: "model_mount_mcp_workflow_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Model-mount MCP workflow requires Rust Agentgres record-state commit before MCP truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.mcp_workflow",
      operation_kind: plan.operation_kind ?? operation_kind,
    },
    invalidCode: "model_mount_mcp_workflow_record_state_commit_invalid",
  });
  const receiptState = persistMcpWorkflowExecutionReceipt(state, plan);
  const publicResponse =
    plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? plan.public_response
      : {};
  return {
    ...publicResponse,
    status: publicResponse.status ?? plan.status ?? "committed",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt: receiptState?.receipt ?? null,
    receipt_commit: receiptState?.commit ?? null,
    receipt_state_commit: receiptState?.commit ?? null,
    receipt_refs: plan.receipt_refs,
    authority_grant_refs: plan.authority_grant_refs,
    authority_receipt_refs: plan.authority_receipt_refs,
    evidence_refs: plan.evidence_refs,
    workflow_hash: plan.workflow_hash,
    authority_hash: plan.authority_hash,
  };
}

function persistMcpWorkflowExecutionReceipt(state, plan = {}) {
  if (!["model_mount.mcp_tool.invoke", "model_mount.workflow_node.execute"].includes(plan.operation_kind)) {
    return null;
  }
  const receipt = plan.receipt && typeof plan.receipt === "object" && !Array.isArray(plan.receipt)
    ? plan.receipt
    : null;
  if (!receipt) {
    throw runtimeError({
      status: 502,
      code: "model_mount_mcp_execution_receipt_required",
      message: "Model-mount MCP execution requires a Rust-authored content receipt before truth can return.",
      details: {
        rust_core_boundary: plan.rust_core_boundary ?? "model_mount.mcp_workflow",
        operation_kind: plan.operation_kind ?? null,
        record_id: plan.record_id ?? null,
      },
    });
  }
  assertMcpWorkflowExecutionResultMaterialized(plan, receipt);
  if (typeof state.persistRustAuthoredReceiptWithCommit !== "function") {
    throw runtimeError({
      status: 500,
      code: "model_mount_mcp_execution_receipt_state_commit_unconfigured",
      message:
        "Model-mount MCP execution requires Rust Agentgres receipt-state commit before execution truth can return.",
      details: {
        rust_core_boundary: plan.rust_core_boundary ?? "model_mount.mcp_workflow",
        operation_kind: plan.operation_kind ?? null,
        receipt_id: receipt.id ?? null,
      },
    });
  }
  const persisted = state.persistRustAuthoredReceiptWithCommit(receipt);
  if (!persisted?.commit?.commit_hash) {
    throw runtimeError({
      status: 502,
      code: "model_mount_mcp_execution_receipt_state_commit_invalid",
      message: "Rust Agentgres MCP execution receipt-state commit returned without commit_hash.",
      details: {
        rust_core_boundary: plan.rust_core_boundary ?? "model_mount.mcp_workflow",
        operation_kind: plan.operation_kind ?? null,
        receipt_id: receipt.id ?? null,
      },
    });
  }
  return persisted;
}

function assertMcpWorkflowExecutionResultMaterialized(plan = {}, receipt = {}) {
  const publicResponse = plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
    ? plan.public_response
    : {};
  const details = receipt.details && typeof receipt.details === "object" && !Array.isArray(receipt.details)
    ? receipt.details
    : {};
  const stepModuleResult =
    details.model_mount_step_module_result &&
    typeof details.model_mount_step_module_result === "object" &&
    !Array.isArray(details.model_mount_step_module_result)
      ? details.model_mount_step_module_result
      : {};
  const resultPayload = publicResponse.result_payload;
  const missing = [];
  const mismatches = [];
  if (publicResponse.model_mount_mcp_result_materialized !== true) {
    missing.push("public_response.model_mount_mcp_result_materialized.rust_materialized");
  }
  if (publicResponse.model_mount_mcp_result_materialization_status === "rust_admitted_pending_transport_backend") {
    missing.push("public_response.model_mount_mcp_result_materialization_status.retired_pending_transport_backend");
  }
  if (publicResponse.model_mount_mcp_result_materialization_status !== "rust_materialized") {
    missing.push("public_response.model_mount_mcp_result_materialization_status.rust_materialized");
  }
  if (publicResponse.result_materialization_owner !== "rust_daemon_core.model_mount.mcp_workflow") {
    missing.push("public_response.result_materialization_owner");
  }
  if (!resultPayload || typeof resultPayload !== "object" || Array.isArray(resultPayload)) {
    missing.push("public_response.result_payload");
  }
  if (!optionalString(publicResponse.result_payload_hash)) {
    missing.push("public_response.result_payload_hash");
  }
  if (details.model_mount_mcp_result_materialized !== true) {
    missing.push("receipt.details.model_mount_mcp_result_materialized.rust_materialized");
  }
  if (details.model_mount_mcp_result_materialization_status === "rust_admitted_pending_transport_backend") {
    missing.push("receipt.details.model_mount_mcp_result_materialization_status.retired_pending_transport_backend");
  }
  if (details.model_mount_mcp_result_materialization_status !== "rust_materialized") {
    missing.push("receipt.details.model_mount_mcp_result_materialization_status.rust_materialized");
  }
  if (stepModuleResult.result_materialized !== true) {
    missing.push("receipt.details.model_mount_step_module_result.result_materialized_true");
  }
  if (optionalString(details.result_payload_hash) !== optionalString(publicResponse.result_payload_hash)) {
    mismatches.push("receipt.details.result_payload_hash");
  }
  if (optionalString(stepModuleResult.result_payload_hash) !== optionalString(publicResponse.result_payload_hash)) {
    mismatches.push("receipt.details.model_mount_step_module_result.result_payload_hash");
  }
  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 502,
      code: "model_mount_mcp_execution_result_materialization_required",
      message:
        "Model-mount MCP execution requires a Rust-materialized result payload before public execution truth can return.",
      details: {
        rust_core_boundary: plan.rust_core_boundary ?? "model_mount.mcp_workflow",
        operation_kind: plan.operation_kind ?? null,
        receipt_id: receipt.id ?? null,
        missing,
        mismatches,
      },
    });
  }
}

function mcpWorkflowBody(value = {}) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const body = {};
  for (const field of [
    "mcp_json",
    "mcp_servers",
    "servers",
    "integrations",
    "input",
    "server_id",
    "tool",
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
    "receipt_id",
    "receipt_refs",
    "authority_grant_refs",
    "authority_receipt_refs",
    "custody_ref",
    "containment_ref",
  ]) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) body[field] = source[field];
  }
  return body;
}

function storageControlBody(value = {}) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const body = {};
  for (const field of [
    "import_id",
    "download_id",
    "job_id",
    "artifact_id",
    "model_id",
    "provider_id",
    "catalog_provider_id",
    "source_url",
    "source_label",
    "file_name",
    "fixture_content",
    "transfer_approved",
    "bytes_total",
    "max_bytes",
    "simulate_failure",
    "failure_reason",
    "queued_only",
    "expected_checksum",
    "display_name",
    "context_window",
    "privacy_class",
    "cleanup_partial",
    "dry_run",
    "remove_orphans",
    "receipt_id",
    "receipt_refs",
    "authority_grant_refs",
    "authority_receipt_refs",
    "custody_ref",
  ]) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) body[field] = source[field];
  }
  return body;
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

function planAndCommitCatalogProviderControl(state, operation_kind, options = {}) {
  const plan = catalogProviderControlPlanForState(state, operation_kind, options);
  const commit = commitCatalogProviderControlPlan(state, plan);
  return catalogProviderControlResponse(plan, commit);
}

function planAndCommitCapabilityTokenControl(state, operation_kind, options = {}) {
  const plan = capabilityTokenControlPlanForState(state, operation_kind, options);
  const commit = commitCapabilityTokenControlPlan(state, plan);
  return capabilityTokenControlResponse(plan, commit);
}

function planAndCommitVaultControl(state, operation_kind, options = {}) {
  const plan = vaultControlPlanForState(state, operation_kind, options);
  const commit = commitVaultControlPlan(state, plan);
  return vaultControlResponse(plan, commit);
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

function assertRustAuthoredReceiptRecord(record = {}) {
  const evidenceRefs = Array.isArray(record.evidenceRefs) ? record.evidenceRefs : [];
  const details = record.details && typeof record.details === "object" ? record.details : {};
  const missing = [];
  const mcpExecutionReceipt = ["mcp_tool_invocation", "workflow_node_execution"].includes(record.kind);
  if (!record.id) missing.push("id");
  if (!record.kind) missing.push("kind");
  if (!record.createdAt) missing.push("createdAt");
  if (!record.schemaVersion) missing.push("schemaVersion");
  if (!evidenceRefs.includes("rust_model_mount_core")) missing.push("evidenceRefs.rust_model_mount_core");
  if (!details.rust_daemon_core_receipt_author) missing.push("details.rust_daemon_core_receipt_author");
  if (mcpExecutionReceipt) {
    if (details.rust_daemon_core_receipt_author !== "model_mount.mcp_workflow") {
      missing.push("details.rust_daemon_core_receipt_author.model_mount.mcp_workflow");
    }
    if (!evidenceRefs.includes("model_mount_mcp_execution_content_receipt_rust_owned")) {
      missing.push("evidenceRefs.model_mount_mcp_execution_content_receipt_rust_owned");
    }
    if (!details.model_mount_mcp_workflow_ref) missing.push("details.model_mount_mcp_workflow_ref");
    if (!details.model_mount_mcp_content_hash) missing.push("details.model_mount_mcp_content_hash");
    if (!details.model_mount_mcp_content_receipt_id) {
      missing.push("details.model_mount_mcp_content_receipt_id");
    }
  } else if (!details.model_mount_route_decision_ref) {
    missing.push("details.model_mount_route_decision_ref");
  }
  if (missing.length === 0) return;
  const error = new Error("Model-mount receipt persistence requires a Rust-authored receipt record.");
  error.status = 502;
  error.code = "model_mount_rust_authored_receipt_required";
  error.details = { missing };
  throw error;
}

function modelConversationStateRequestForMountedState(
  state,
  {
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
  } = {},
) {
  return {
    schema_version: MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION,
    operation: "model_conversation_state_write",
    response_id: requiredModelConversationString("response_id", responseId),
    previous_response_id: optionalString(previousState?.id),
    root_response_id:
      optionalString(previousState?.root_response_id) ??
      optionalString(previousState?.id) ??
      optionalString(responseId),
    previous_message_count: normalizedMessageCount(previousState?.message_count),
    kind: requiredModelConversationString("kind", kind),
    status: requiredModelConversationString("status", status),
    source: "runtime-daemon.model_mounting.conversation_state",
    generated_at: state.nowIso(),
    route_ref: requiredModelConversationString("route_ref", selection?.route?.id ?? previousState?.route_id),
    endpoint_ref: requiredModelConversationString(
      "endpoint_ref",
      selection?.endpoint?.id ?? previousState?.endpoint_id,
    ),
    provider_ref: requiredModelConversationString(
      "provider_ref",
      selection?.provider?.id ??
        selection?.endpoint?.provider_id ??
        selection?.endpoint?.providerId ??
        previousState?.provider_id,
    ),
    model_ref: requiredModelConversationString(
      "model_ref",
      selection?.endpoint?.model_id ??
        selection?.endpoint?.modelId ??
        previousState?.selected_model,
    ),
    instance_ref: optionalString(instance?.id ?? previousState?.instance_id),
    route_decision_ref: optionalString(
      routeReceipt?.details?.model_mount_route_decision_ref ??
        selection?.route_decision?.route_decision_ref ??
        previousState?.route_decision_ref,
    ),
    route_receipt_ref: modelMountReceiptRef(routeReceipt?.id),
    invocation_receipt_ref: modelMountReceiptRef(receipt?.id),
    stream_receipt_ref: modelMountReceiptRef(streamReceiptId),
    input_text: modelConversationText(input),
    output_text: modelConversationText(outputText),
    token_count: tokenCount ?? null,
    continuation_safety: continuationSafety ?? null,
    receipt_refs: uniqueModelMountRefs([
      modelMountReceiptRef(routeReceipt?.id),
      modelMountReceiptRef(receipt?.id),
      modelMountReceiptRef(streamReceiptId),
    ]),
  };
}

function modelStreamCompletionRequestForMountedState(
  state,
  {
    invocation,
    streamKind,
    outputText,
    providerUsage,
    chunksForwarded,
    finishReason,
    providerResult,
    providerStreamShapeSummary,
    currentHead,
    receiptId,
  } = {},
) {
  const routeReceipt = invocation?.routeReceipt;
  const receipt = invocation?.receipt;
  const endpoint = invocation?.endpoint ?? {};
  const route = invocation?.route ?? {};
  const previousState = invocation?.previousConversationState ?? null;
  return {
    schema_version: MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION,
    operation: "model_stream_completion",
    response_id: requiredModelConversationString("response_id", invocation?.responseId),
    previous_response_id: optionalString(invocation?.previousResponseId),
    root_response_id:
      optionalString(previousState?.root_response_id) ??
      optionalString(previousState?.id) ??
      optionalString(invocation?.responseId),
    previous_message_count: normalizedMessageCount(previousState?.message_count),
    kind: requiredModelConversationString("kind", invocation?.kind),
    stream_kind: requiredModelConversationString("stream_kind", streamKind),
    source: "runtime-daemon.model_mounting.stream_completion",
    generated_at: state.nowIso(),
    receipt_id: requiredModelConversationString("receipt_id", receiptId),
    current_sequence: normalizeNonNegativeInteger(currentHead?.sequence, 0),
    current_head_ref: requiredModelConversationString("current_head_ref", currentHead?.head_ref),
    current_state_root: requiredModelConversationString("current_state_root", currentHead?.state_root),
    invocation_receipt_ref: requiredModelConversationString(
      "invocation_receipt_ref",
      modelMountReceiptRef(receipt?.id),
    ),
    route_decision_ref: requiredModelConversationString(
      "route_decision_ref",
      routeReceipt?.details?.model_mount_route_decision_ref ??
        receipt?.details?.model_mount_route_decision_ref,
    ),
    route_receipt_ref: modelMountReceiptRef(routeReceipt?.id),
    route_ref: requiredModelConversationString("route_ref", route.id ?? receipt?.details?.route_id),
    endpoint_ref: requiredModelConversationString("endpoint_ref", endpoint.id ?? receipt?.details?.endpoint_id),
    provider_ref: requiredModelConversationString(
      "provider_ref",
      endpoint.provider_id ?? endpoint.providerId ?? receipt?.details?.provider_id,
    ),
    model_ref: requiredModelConversationString(
      "model_ref",
      endpoint.model_id ?? endpoint.modelId ?? invocation?.model ?? receipt?.details?.selected_model,
    ),
    instance_ref: optionalString(invocation?.instance?.id ?? receipt?.details?.instance_id),
    input_text: modelConversationText(invocation?.input),
    output_text: modelConversationText(outputText),
    token_count: invocation?.tokenCount ?? null,
    provider_usage: providerUsage ?? null,
    provider_result: providerResult ?? {},
    provider_stream_shape_summary: providerStreamShapeSummary ?? null,
    chunks_forwarded: normalizeNonNegativeInteger(chunksForwarded, 0),
    finish_reason: optionalString(finishReason),
    provider_response_kind: optionalString(
      providerResult?.provider_response_kind ??
        providerResult?.providerResponseKind ??
        invocation?.providerResponseKind,
    ),
    receipt_refs: uniqueModelMountRefs([
      modelMountReceiptRef(routeReceipt?.id),
      modelMountReceiptRef(receipt?.id),
      ...(invocation?.toolReceiptIds ?? []).map(modelMountReceiptRef),
      modelMountReceiptRef(receiptId),
    ]),
  };
}

function modelStreamCancelRequestForMountedState(
  state,
  {
    invocation,
    streamKind,
    outputText,
    providerUsage,
    framesWritten,
    cancelReason,
    providerResult,
    providerStreamShapeSummary,
    currentHead,
    receiptId,
  } = {},
) {
  const routeReceipt = invocation?.routeReceipt;
  const receipt = invocation?.receipt;
  const endpoint = invocation?.endpoint ?? {};
  const route = invocation?.route ?? {};
  const previousState = invocation?.previousConversationState ?? null;
  return {
    schema_version: MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION,
    operation: "model_stream_cancel",
    response_id: requiredModelConversationString("response_id", invocation?.responseId),
    previous_response_id: optionalString(invocation?.previousResponseId),
    root_response_id:
      optionalString(previousState?.root_response_id) ??
      optionalString(previousState?.id) ??
      optionalString(invocation?.responseId),
    previous_message_count: normalizedMessageCount(previousState?.message_count),
    kind: requiredModelConversationString("kind", invocation?.kind),
    stream_kind: requiredModelConversationString("stream_kind", streamKind),
    source: "runtime-daemon.model_mounting.stream_cancel",
    generated_at: state.nowIso(),
    receipt_id: requiredModelConversationString("receipt_id", receiptId),
    current_sequence: normalizeNonNegativeInteger(currentHead?.sequence, 0),
    current_head_ref: requiredModelConversationString("current_head_ref", currentHead?.head_ref),
    current_state_root: requiredModelConversationString("current_state_root", currentHead?.state_root),
    invocation_receipt_ref: requiredModelConversationString(
      "invocation_receipt_ref",
      modelMountReceiptRef(receipt?.id),
    ),
    route_decision_ref: requiredModelConversationString(
      "route_decision_ref",
      routeReceipt?.details?.model_mount_route_decision_ref ??
        receipt?.details?.model_mount_route_decision_ref,
    ),
    route_receipt_ref: modelMountReceiptRef(routeReceipt?.id),
    route_ref: requiredModelConversationString("route_ref", route.id ?? receipt?.details?.route_id),
    endpoint_ref: requiredModelConversationString("endpoint_ref", endpoint.id ?? receipt?.details?.endpoint_id),
    provider_ref: requiredModelConversationString(
      "provider_ref",
      endpoint.provider_id ?? endpoint.providerId ?? receipt?.details?.provider_id,
    ),
    model_ref: requiredModelConversationString(
      "model_ref",
      endpoint.model_id ?? endpoint.modelId ?? invocation?.model ?? receipt?.details?.selected_model,
    ),
    instance_ref: optionalString(invocation?.instance?.id ?? receipt?.details?.instance_id),
    input_text: modelConversationText(invocation?.input),
    output_text: modelConversationText(outputText),
    token_count: invocation?.tokenCount ?? null,
    provider_usage: providerUsage ?? null,
    provider_result: providerResult ?? {},
    provider_stream_shape_summary: providerStreamShapeSummary ?? null,
    frames_written: normalizeNonNegativeInteger(framesWritten, 0),
    cancel_reason: optionalString(cancelReason) ?? "client_disconnect",
    stream_source: optionalString(receipt?.details?.stream_source),
    provider_response_kind: optionalString(
      providerResult?.provider_response_kind ??
        providerResult?.providerResponseKind ??
        invocation?.providerResponseKind ??
        receipt?.details?.provider_response_kind,
    ),
    receipt_refs: uniqueModelMountRefs([
      modelMountReceiptRef(routeReceipt?.id),
      modelMountReceiptRef(receipt?.id),
      ...(invocation?.toolReceiptIds ?? []).map(modelMountReceiptRef),
      modelMountReceiptRef(receiptId),
    ]),
  };
}

function commitModelConversationPlanRecordState(
  state,
  plan,
  {
    unconfiguredCode,
    unconfiguredMessage,
    invalidCode,
  } = {},
) {
  assertRustModelConversationPlan(plan);
  const commit = commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs ?? [],
    unconfiguredCode,
    unconfiguredMessage,
    invalidCode,
  });
  return {
    ...plan.record,
    object: plan.record.object ?? "ioi.model_mount_conversation_state",
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt_refs: plan.receipt_refs,
    evidence_refs: plan.evidence_refs,
    conversation_hash: plan.conversation_hash,
    stream_completion_hash: plan.stream_completion_hash ?? null,
    rust_core_boundary: plan.rust_core_boundary,
    source: plan.source,
  };
}

function assertRustModelConversationPlan(plan = {}) {
  const evidenceRefs = Array.isArray(plan.evidence_refs) ? plan.evidence_refs : [];
  const missing = [];
  if (plan.rust_core_boundary !== "model_mount.conversation") missing.push("rust_core_boundary");
  if (plan.record_dir !== "model-conversations") missing.push("record_dir");
  if (!plan.record_id) missing.push("record_id");
  if (!plan.record || typeof plan.record !== "object") missing.push("record");
  if (plan.record?.id !== plan.record_id) missing.push("record.id");
  if (!plan.operation_kind) missing.push("operation_kind");
  if (!plan.conversation_hash) missing.push("conversation_hash");
  if (
    !evidenceRefs.includes("model_mount_conversation_state_rust_owned") &&
    !evidenceRefs.includes("model_mount_stream_completion_rust_owned") &&
    !evidenceRefs.includes("model_mount_stream_cancel_rust_owned")
  ) {
    missing.push("evidence_refs.model_mount_conversation_or_stream_rust_owned");
  }
  if (!evidenceRefs.includes("agentgres_model_conversation_truth_required")) {
    missing.push("evidence_refs.agentgres_model_conversation_truth_required");
  }
  if (
    evidenceRefs.includes("model_mount_conversation_state_rust_owned") &&
    !evidenceRefs.includes("rust_daemon_core_model_conversation_state")
  ) {
    missing.push("evidence_refs.rust_daemon_core_model_conversation_state");
  }
  if (
    evidenceRefs.includes("model_mount_stream_completion_rust_owned") &&
    !evidenceRefs.includes("rust_daemon_core_model_stream_completion")
  ) {
    missing.push("evidence_refs.rust_daemon_core_model_stream_completion");
  }
  if (
    evidenceRefs.includes("model_mount_stream_cancel_rust_owned") &&
    !evidenceRefs.includes("rust_daemon_core_model_stream_cancel")
  ) {
    missing.push("evidence_refs.rust_daemon_core_model_stream_cancel");
  }
  if (
    evidenceRefs.includes("model_mount_stream_cancel_rust_owned") &&
    !evidenceRefs.includes("agentgres_model_stream_cancel_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_model_stream_cancel_truth_required");
  }
  if (missing.length === 0) return;
  throw runtimeError({
    status: 502,
    code: "model_mount_conversation_plan_invalid",
    message: "Model conversation state requires a Rust-authored model_mount conversation plan.",
    details: {
      missing,
      source: plan.source ?? null,
      backend: plan.backend ?? null,
    },
  });
}

function requiredModelConversationString(field, value) {
  const normalized = optionalString(value);
  if (normalized) return normalized;
  throw runtimeError({
    status: 400,
    code: "model_mount_conversation_request_invalid",
    message: "Model conversation request is missing a required Rust-owned boundary field.",
    details: { field },
  });
}

function modelMountReceiptRef(value) {
  const normalized = optionalString(value);
  if (!normalized) return null;
  return normalized.includes("://") ? normalized : `receipt://${normalized}`;
}

function modelConversationText(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function normalizedMessageCount(value) {
  return Number.isInteger(value) && value >= 0 ? value : null;
}

function uniqueModelMountRefs(values = []) {
  const refs = [];
  for (const value of values) {
    const normalized = optionalString(value);
    if (normalized && !refs.includes(normalized)) refs.push(normalized);
  }
  return refs;
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

function planProviderLifecycle(state, provider, options = {}) {
  const request = modelMountProviderLifecycleRequest(state, provider, options);
  if (typeof state.planModelMountProviderLifecycle !== "function") {
    throwProviderLifecycleRustCoreRequired(provider, options.operation ?? "provider_lifecycle", {
      operation_kind: options.operation_kind ?? "model_mount.provider.lifecycle",
      rust_core_api: "plan_model_mount_provider_lifecycle",
    });
  }
  const result = state.planModelMountProviderLifecycle(request);
  assertRustAuthoredProviderLifecycleResult(result, options);
  if (!options.commitRecordState) return result;
  const commit = commitProviderLifecycleRecordState(state, result);
  const publicResponse =
    result.public_response && typeof result.public_response === "object" && !Array.isArray(result.public_response)
      ? result.public_response
      : {};
  return {
    ...publicResponse,
    ...result,
    status: result.status ?? publicResponse.status ?? result.result?.status ?? null,
    commit,
  };
}

function modelMountProviderLifecycleRequest(state, provider, options = {}) {
  const operation = options.operation ?? "provider_lifecycle";
  const action = options.action ?? "health";
  const operation_kind = options.operation_kind ?? "model_mount.provider.lifecycle";
  const executionBackend = providerLifecycleExecutionBackend(provider, { operation, operation_kind, action });
  if (!executionBackend) {
    throwProviderLifecycleRustCoreRequired(provider, operation, {
      operation_kind,
      unsupported_provider_lifecycle_backend: true,
    });
  }
  const subject = providerLifecycleSubject(state, provider, { operation, operation_kind, endpoint: options.endpoint });
  return {
    schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
    provider_ref: provider?.provider_ref ?? `provider://${provider?.id}`,
    provider_kind: provider?.kind ?? "",
    endpoint_ref: subject.endpoint_ref,
    model_ref: subject.model_ref,
    action,
    execution_backend: executionBackend,
    api_format: provider?.api_format ?? provider?.apiFormat ?? null,
    driver: provider?.driver ?? null,
    backend_ref: subject.backend_ref,
    provider_status: provider?.status ?? null,
    evidence_refs: providerLifecycleEvidenceRefs(provider, operation),
    process_evidence_refs: [],
    operation_kind,
    source: "runtime-daemon.model_mounting.provider_lifecycle",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    receipt_refs: uniqueModelMountRefs(
      Array.isArray(options.receipt_refs)
        ? options.receipt_refs
        : [options.receipt_refs],
    ),
  };
}

function providerLifecycleExecutionBackend(provider = {}, options = {}) {
  const providerKind = String(provider?.kind ?? "").trim();
  const driver = String(provider?.driver ?? "").trim();
  const apiFormat = String(provider?.api_format ?? provider?.apiFormat ?? "").trim();
  if (providerKind === "ioi_native_local" || driver === "native_local" || apiFormat === "ioi_native") {
    return RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND;
  }
  if (
    providerKind === "local_folder" ||
    driver === "fixture" ||
    apiFormat === "ioi_fixture" ||
    apiFormat === "fixture"
  ) {
    return RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND;
  }
  if (hostedProviderMetadata(provider) && hostedProviderLifecycleMetadataOperation(options)) {
    return RUST_MODEL_MOUNT_HOSTED_PROVIDER_LIFECYCLE_BACKEND;
  }
  return null;
}

function hostedProviderLifecycleMetadataOperation(options = {}) {
  const operationKind = String(options.operation_kind ?? "").trim();
  return operationKind === "model_mount.provider.lifecycle" || operationKind.startsWith("model_mount.provider.");
}

function providerLifecycleSubject(state, provider, options = {}) {
  const endpoint = options.endpoint ?? providerLifecycleEndpointForState(state, provider);
  const modelRef = endpoint?.model_ref ?? endpoint?.modelId ?? endpoint?.model_id ?? null;
  if (!endpoint || !endpoint.id || !modelRef || String(modelRef).trim().toLowerCase() === "auto") {
    if (hostedProviderMetadata(provider)) {
      const providerId = String(provider?.id ?? provider?.provider_id ?? "hosted").trim() || "hosted";
      const providerKind = String(provider?.kind ?? provider?.api_format ?? provider?.apiFormat ?? "hosted").trim() || "hosted";
      return {
        endpoint_ref: provider?.endpoint_ref ?? `endpoint://${providerId}/hosted-metadata`,
        model_ref: provider?.model_ref ?? `model://${providerKind}/hosted-metadata`,
        backend_ref: provider?.backend_ref ?? provider?.backend_id ?? provider?.backendId ?? `backend.hosted.${safeId(providerKind)}`,
      };
    }
    throwProviderLifecycleRustCoreRequired(provider, options.operation ?? "provider_lifecycle", {
      operation_kind: options.operation_kind ?? "model_mount.provider.lifecycle",
      missing: [
        ...(!endpoint || !endpoint.id ? ["endpoint_ref"] : []),
        ...(!modelRef || String(modelRef).trim().toLowerCase() === "auto" ? ["model_ref"] : []),
      ],
    });
  }
  return {
    endpoint_ref: endpoint.endpoint_ref ?? `endpoint://${endpoint.id}`,
    model_ref: endpoint.model_ref ?? `model://${modelRef}`,
    backend_ref: endpoint.backend_ref ?? endpoint.backendId ?? provider?.backend_ref ?? null,
  };
}

function providerLifecycleEndpointForState(state, provider) {
  const providerId = String(provider?.id ?? provider?.provider_id ?? "").trim();
  const providerRef = String(provider?.provider_ref ?? (providerId ? `provider://${providerId}` : "")).trim();
  if (!providerId && !providerRef) return null;
  return modelMountProjectionRecords(state, "listEndpoints").find(
    (candidate) =>
      candidate?.status !== "unmounted" &&
      (
        candidate?.providerId === providerId ||
        candidate?.provider_id === providerId ||
        candidate?.provider_ref === providerRef
      ),
  ) ?? null;
}

function providerLifecycleEvidenceRefs(provider = {}, operation) {
  return [
    "public_provider_lifecycle_rust_facade",
    ...(Array.isArray(provider?.discovery?.evidenceRefs) ? provider.discovery.evidenceRefs : []),
    operation,
  ].filter(Boolean);
}

function planProviderInventory(state, provider, options = {}) {
  const request = modelMountProviderInventoryRequest(provider, options);
  if (typeof state.planModelMountProviderInventory !== "function") {
    throwModelMountProviderInventoryRustCoreRequired(provider, options.operation ?? "provider_inventory", {
      operation_kind: options.operation_kind ?? "model_mount.provider.inventory",
      rust_core_api: "plan_model_mount_provider_inventory",
    });
  }
  const result = state.planModelMountProviderInventory(request);
  assertRustAuthoredProviderInventoryResult(result, options);
  const commit = commitProviderInventoryRecordState(state, result);
  return {
    ...result,
    commit,
  };
}

function modelMountProviderInventoryRequest(provider, options = {}) {
  const operation = options.operation ?? "provider_inventory";
  const action = options.action ?? "list_models";
  const operation_kind = options.operation_kind ?? "model_mount.provider.inventory";
  const executionBackend = providerInventoryExecutionBackend(provider);
  if (!executionBackend) {
    throwModelMountProviderInventoryRustCoreRequired(provider, operation, {
      operation_kind,
      unsupported_provider_inventory_backend: true,
    });
  }
  return {
    schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
    provider_ref: provider?.provider_ref ?? `provider://${provider?.id}`,
    provider_kind: provider?.kind ?? "",
    action,
    execution_backend: executionBackend,
    api_format: provider?.api_format ?? provider?.apiFormat ?? null,
    driver: provider?.driver ?? null,
    backend_ref: provider?.backend_ref ?? provider?.backend_id ?? provider?.backendId ?? null,
    provider_status: provider?.status ?? null,
    item_refs: providerInventoryItemRefs(provider, action),
    evidence_refs: providerInventoryEvidenceRefs(provider, operation),
  };
}

function providerInventoryExecutionBackend(provider = {}) {
  const providerKind = String(provider?.kind ?? "").trim();
  const driver = String(provider?.driver ?? "").trim();
  const apiFormat = String(provider?.api_format ?? provider?.apiFormat ?? "").trim();
  if (providerKind === "ioi_native_local" || driver === "native_local" || apiFormat === "ioi_native") {
    return RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND;
  }
  if (
    providerKind === "local_folder" ||
    driver === "fixture" ||
    apiFormat === "ioi_fixture" ||
    apiFormat === "fixture"
  ) {
    return RUST_MODEL_MOUNT_FIXTURE_INVENTORY_BACKEND;
  }
  if (hostedProviderMetadata(provider)) {
    return RUST_MODEL_MOUNT_HOSTED_PROVIDER_INVENTORY_BACKEND;
  }
  return null;
}

function hostedProviderMetadata(provider = {}) {
  const providerKind = String(provider?.kind ?? "").trim();
  const driver = String(provider?.driver ?? "").trim();
  const apiFormat = String(provider?.api_format ?? provider?.apiFormat ?? "").trim();
  return [
    "openai",
    "anthropic",
    "gemini",
    "custom_http",
    "openai_compatible",
    "ollama",
    "vllm",
    "llama_cpp",
    "lm_studio",
    "depin_tee",
  ].includes(providerKind) ||
    ["openai", "anthropic", "gemini", "custom", "openai_compatible", "ollama"].includes(apiFormat) ||
    ["openai_compatible", "hosted_provider", "hosted_provider_metadata"].includes(driver);
}

function providerInventoryItemRefs(provider = {}, action = "list_models") {
  const refs = action === "list_loaded"
    ? provider?.loaded_item_refs
    : provider?.item_refs;
  if (!Array.isArray(refs)) return [];
  return refs
    .map((value) => (typeof value === "string" ? value.trim() : ""))
    .filter(Boolean);
}

function providerInventoryEvidenceRefs(provider = {}, operation) {
  return [
    "public_provider_inventory_rust_facade",
    ...(Array.isArray(provider?.discovery?.evidenceRefs) ? provider.discovery.evidenceRefs : []),
    operation,
  ].filter(Boolean);
}

function assertRustAuthoredProviderInventoryResult(result = {}, options = {}) {
  const record = result.result && typeof result.result === "object" && !Array.isArray(result.result)
    ? result.result
    : {};
  const inventoryRecord = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : {};
  const publicResponse = result.public_response && typeof result.public_response === "object" && !Array.isArray(result.public_response)
    ? result.public_response
    : record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
      ? record.public_response
      : inventoryRecord.public_response && typeof inventoryRecord.public_response === "object" && !Array.isArray(inventoryRecord.public_response)
        ? inventoryRecord.public_response
        : null;
  const evidenceRefs = Array.isArray(result.evidence_refs)
    ? result.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [];
  const recordEvidenceRefs = Array.isArray(inventoryRecord.evidence_refs) ? inventoryRecord.evidence_refs : [];
  const itemRefs = Array.isArray(result.itemRefs)
    ? result.itemRefs
    : Array.isArray(record.item_refs)
      ? record.item_refs
      : null;
  const itemCount = result.itemCount ?? record.item_count;
  const inventory_hash = result.inventory_hash ?? record.inventory_hash ?? inventoryRecord.inventory_hash;
  const recordId = result.record_id ?? inventoryRecord.id ?? inventoryRecord.record_id;
  const operationKind = result.operation_kind ?? record.operation_kind ?? inventoryRecord.operation_kind;
  const rustCoreBoundary = result.rust_core_boundary ?? record.rust_core_boundary ?? inventoryRecord.rust_core_boundary;
  const transportContract =
    result.transport_contract && typeof result.transport_contract === "object" && !Array.isArray(result.transport_contract)
      ? result.transport_contract
      : record.transport_contract && typeof record.transport_contract === "object" && !Array.isArray(record.transport_contract)
        ? record.transport_contract
        : inventoryRecord.transport_contract && typeof inventoryRecord.transport_contract === "object" && !Array.isArray(inventoryRecord.transport_contract)
          ? inventoryRecord.transport_contract
          : null;
  const missing = [];
  const mismatches = [];
  if (!record.provider_ref) missing.push("result.provider_ref");
  if (!record.provider_kind) missing.push("result.provider_kind");
  if (!record.action) {
    missing.push("result.action");
  } else if (options.action && record.action !== options.action) {
    mismatches.push("result.action");
  }
  if (!inventory_hash) missing.push("inventory_hash");
  if (!result.executionBackend && !record.execution_backend) missing.push("execution_backend");
  if (!result.status && !record.status) missing.push("status");
  if (!Array.isArray(itemRefs)) missing.push("item_refs");
  if (itemCount === null || itemCount === undefined) missing.push("item_count");
  if (!operationKind) {
    missing.push("operation_kind");
  } else if (options.operation_kind && operationKind !== options.operation_kind) {
    mismatches.push("operation_kind");
  }
  if (rustCoreBoundary !== "model_mount.provider_inventory") missing.push("rust_core_boundary");
  if (result.record_dir !== "model-provider-inventory") missing.push("record_dir");
  if (!recordId) missing.push("record_id");
  if (!result.record || typeof result.record !== "object" || Array.isArray(result.record)) missing.push("record");
  if (inventoryRecord.id !== recordId) mismatches.push("record.id");
  if (inventoryRecord.record_id !== recordId) mismatches.push("record.record_id");
  if (inventoryRecord.object !== "ioi.model_mount_provider_inventory") missing.push("record.object");
  if (inventoryRecord.schema_version !== MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION) missing.push("record.schema_version");
  if (inventoryRecord.provider_ref !== record.provider_ref) mismatches.push("record.provider_ref");
  if (inventoryRecord.action !== record.action) mismatches.push("record.action");
  if (inventoryRecord.inventory_hash !== inventory_hash) mismatches.push("record.inventory_hash");
  if (inventoryRecord.rust_core_boundary !== "model_mount.provider_inventory") {
    missing.push("record.rust_core_boundary");
  }
  if (!transportContract) {
    missing.push("transport_contract");
  } else {
    if (transportContract.transport_execution_status !== "rust_materialized") {
      missing.push("transport_contract.transport_execution_status.rust_materialized");
    }
    if (transportContract.transport_execution_owner !== "rust_daemon_core.model_mount.provider_inventory") {
      missing.push("transport_contract.transport_execution_owner");
    }
    if (transportContract.plaintext_secret_material_returned !== false) {
      missing.push("transport_contract.plaintext_secret_material_returned_false");
    }
    assertRetiredProviderTransportProofFieldsAbsent(transportContract, "transport_contract", missing);
  }
  assertRetiredProviderTransportProofFieldsAbsent(result, "result", missing);
  assertRetiredProviderTransportProofFieldsAbsent(record, "result", missing);
  assertRetiredProviderTransportProofFieldsAbsent(inventoryRecord, "record", missing);
  assertRetiredProviderTransportProofFieldsAbsent(publicResponse, "public_response", missing);
  if (!Array.isArray(result.receipt_refs)) missing.push("receipt_refs");
  if (!evidenceRefs.includes("rust_model_mount_provider_inventory")) {
    missing.push("evidence_refs.rust_model_mount_provider_inventory");
  }
  if (!evidenceRefs.includes("agentgres_provider_inventory_truth_required")) {
    missing.push("evidence_refs.agentgres_provider_inventory_truth_required");
  }
  if (!recordEvidenceRefs.includes("rust_model_mount_provider_inventory")) {
    missing.push("record.evidence_refs.rust_model_mount_provider_inventory");
  }
  if (!recordEvidenceRefs.includes("agentgres_provider_inventory_truth_required")) {
    missing.push("record.evidence_refs.agentgres_provider_inventory_truth_required");
  }
  if (evidenceRefs.includes("hosted_provider_transport_not_executed")) {
    missing.push("evidence_refs.hosted_provider_transport_not_executed_retired");
  }
  if (recordEvidenceRefs.includes("hosted_provider_transport_not_executed")) {
    missing.push("record.evidence_refs.hosted_provider_transport_not_executed_retired");
  }
  if (missing.length === 0 && mismatches.length === 0) return;
  throw runtimeError({
    status: 502,
    code: "model_mount_provider_inventory_rust_result_required",
    message: "Provider inventory facade requires a Rust-authored model_mount provider inventory result.",
    details: {
      operation: options.operation ?? null,
      action: options.action ?? null,
      missing,
      mismatches,
    },
  });
}

function assertRetiredProviderTransportProofFieldsAbsent(record, path, missing) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return;
  for (const field of [
    "js_transport_invocation",
    "command_transport_fallback",
    "binary_bridge_fallback",
    "compatibility_fallback",
  ]) {
    if (Object.hasOwn(record, field)) missing.push(`${path}.${field}_retired`);
  }
}

function commitProviderInventoryRecordState(state, plan = {}) {
  return commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: Array.isArray(plan.receipt_refs) ? plan.receipt_refs : [],
    unconfiguredCode: "model_mount_provider_inventory_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Provider inventory requires Rust Agentgres record-state commit before inventory truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.provider_inventory",
      operation_kind: plan.operation_kind ?? null,
      inventory_hash: plan.inventory_hash ?? plan.result?.inventory_hash ?? null,
    },
    invalidCode: "model_mount_provider_inventory_record_state_commit_invalid",
  });
}

function assertRustAuthoredProviderLifecycleResult(result = {}, options = {}) {
  const record = result.result && typeof result.result === "object" && !Array.isArray(result.result)
    ? result.result
    : {};
  const lifecycleRecord = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : {};
  const publicResponse = result.public_response && typeof result.public_response === "object" && !Array.isArray(result.public_response)
    ? result.public_response
    : record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
      ? record.public_response
      : lifecycleRecord.public_response && typeof lifecycleRecord.public_response === "object" && !Array.isArray(lifecycleRecord.public_response)
        ? lifecycleRecord.public_response
        : null;
  const evidenceRefs = Array.isArray(result.evidence_refs)
    ? result.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [];
  const transportContract =
    result.transport_contract && typeof result.transport_contract === "object" && !Array.isArray(result.transport_contract)
      ? result.transport_contract
      : record.transport_contract && typeof record.transport_contract === "object" && !Array.isArray(record.transport_contract)
        ? record.transport_contract
        : lifecycleRecord.transport_contract && typeof lifecycleRecord.transport_contract === "object" && !Array.isArray(lifecycleRecord.transport_contract)
          ? lifecycleRecord.transport_contract
          : null;
  const missing = [];
  const mismatches = [];
  if (!result.lifecycle_hash && !record.lifecycle_hash) missing.push("lifecycle_hash");
  if (!evidenceRefs.includes("rust_model_mount_provider_lifecycle")) {
    missing.push("evidence_refs.rust_model_mount_provider_lifecycle");
  }
  if (options.commitRecordState && !evidenceRefs.includes("agentgres_provider_lifecycle_truth_required")) {
    missing.push("evidence_refs.agentgres_provider_lifecycle_truth_required");
  }
  if (!result.executionBackend && !record.execution_backend) missing.push("execution_backend");
  if (!result.status && !record.status) missing.push("status");
  if (!record.action) {
    missing.push("result.action");
  } else if (options.action && record.action !== options.action) {
    mismatches.push("result.action");
  }
  if (!transportContract) {
    missing.push("transport_contract");
  } else {
    if (transportContract.transport_execution_status !== "rust_materialized") {
      missing.push("transport_contract.transport_execution_status.rust_materialized");
    }
    if (transportContract.transport_execution_owner !== "rust_daemon_core.model_mount.provider_lifecycle") {
      missing.push("transport_contract.transport_execution_owner");
    }
    if (transportContract.plaintext_secret_material_returned !== false) {
      missing.push("transport_contract.plaintext_secret_material_returned_false");
    }
    assertRetiredProviderTransportProofFieldsAbsent(transportContract, "transport_contract", missing);
  }
  assertRetiredProviderTransportProofFieldsAbsent(result, "result", missing);
  assertRetiredProviderTransportProofFieldsAbsent(record, "result", missing);
  assertRetiredProviderTransportProofFieldsAbsent(lifecycleRecord, "record", missing);
  assertRetiredProviderTransportProofFieldsAbsent(publicResponse, "public_response", missing);
  if (evidenceRefs.includes("hosted_provider_transport_not_executed")) {
    missing.push("evidence_refs.hosted_provider_transport_not_executed_retired");
  }
  if (options.commitRecordState) {
    const lifecycleHash = result.lifecycle_hash ?? record.lifecycle_hash ?? lifecycleRecord.lifecycle_hash;
    const operationKind = result.operation_kind ?? record.operation_kind ?? lifecycleRecord.operation_kind;
    const rustCoreBoundary = result.rust_core_boundary ?? record.rust_core_boundary ?? lifecycleRecord.rust_core_boundary;
    const recordDir = result.record_dir ?? record.record_dir ?? lifecycleRecord.record_dir;
    const recordId = result.record_id ?? record.record_id ?? lifecycleRecord.record_id ?? lifecycleRecord.id;
    const recordEvidenceRefs = Array.isArray(lifecycleRecord.evidence_refs) ? lifecycleRecord.evidence_refs : [];
    if (!operationKind) {
      missing.push("operation_kind");
    } else if (options.operation_kind && operationKind !== options.operation_kind) {
      mismatches.push("operation_kind");
    }
    if (rustCoreBoundary !== "model_mount.provider_lifecycle") missing.push("rust_core_boundary");
    if (recordDir !== "model-provider-lifecycle-controls") missing.push("record_dir");
    if (!recordId) missing.push("record_id");
    if (!result.record || typeof result.record !== "object" || Array.isArray(result.record)) missing.push("record");
    if (lifecycleRecord.id !== recordId) mismatches.push("record.id");
    if (lifecycleRecord.record_id !== recordId) mismatches.push("record.record_id");
    if (lifecycleRecord.object !== "ioi.model_mount_provider_lifecycle") missing.push("record.object");
    if (lifecycleRecord.rust_core_boundary !== "model_mount.provider_lifecycle") {
      missing.push("record.rust_core_boundary");
    }
    if (lifecycleRecord.lifecycle_hash !== lifecycleHash) mismatches.push("record.lifecycle_hash");
    if (!Array.isArray(result.receipt_refs)) missing.push("receipt_refs");
    if (!recordEvidenceRefs.includes("rust_model_mount_provider_lifecycle")) {
      missing.push("record.evidence_refs.rust_model_mount_provider_lifecycle");
    }
    if (!recordEvidenceRefs.includes("agentgres_provider_lifecycle_truth_required")) {
      missing.push("record.evidence_refs.agentgres_provider_lifecycle_truth_required");
    }
    if (recordEvidenceRefs.includes("hosted_provider_transport_not_executed")) {
      missing.push("record.evidence_refs.hosted_provider_transport_not_executed_retired");
    }
  }
  if (missing.length === 0 && mismatches.length === 0) return;
  throw runtimeError({
    status: 502,
    code: "model_mount_provider_lifecycle_rust_result_required",
    message: "Provider lifecycle facade requires a Rust-authored model_mount provider lifecycle result.",
    details: {
      operation: options.operation ?? null,
      action: options.action ?? null,
      missing,
      mismatches,
    },
  });
}

function commitProviderLifecycleRecordState(state, plan = {}) {
  return commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: Array.isArray(plan.receipt_refs) ? plan.receipt_refs : [],
    unconfiguredCode: "model_mount_provider_lifecycle_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Provider lifecycle requires Rust Agentgres record-state commit before provider lifecycle truth can return.",
    unconfiguredDetails: {
      rust_core_boundary: plan.rust_core_boundary ?? "model_mount.provider_lifecycle",
      operation_kind: plan.operation_kind ?? null,
      lifecycle_hash: plan.lifecycle_hash ?? plan.result?.lifecycle_hash ?? null,
    },
    invalidCode: "model_mount_provider_lifecycle_record_state_commit_invalid",
  });
}

function planModelInstanceLifecycle(state, options = {}) {
  const request = modelMountInstanceLifecycleRequest(options);
  if (typeof state.planModelMountInstanceLifecycle !== "function") {
    throwModelLoadingRustCoreRequired(
      options.action === "estimate"
        ? "model_load_estimate"
        : options.action === "unload"
          ? "model_unload"
          : "model_load",
      options.provider,
      {
        operation_kind: `model_mount.instance.${options.action ?? "lifecycle"}`,
        rust_core_api: "plan_model_mount_instance_lifecycle",
        endpoint_id: options.endpoint?.id ?? options.endpoint?.endpoint_id ?? null,
        model_id: options.modelId ?? options.endpoint?.modelId ?? options.endpoint?.model_id ?? null,
        backend_id: options.backendId ?? null,
      },
    );
  }
  const result = state.planModelMountInstanceLifecycle(request);
  assertRustAuthoredModelInstanceLifecycleResult(result, options);
  return result;
}

function modelMountInstanceLifecycleRequest({
  action,
  targetStatus,
  endpoint = {},
  provider = {},
  instance = null,
  instanceId,
  modelId,
  backendId,
  providerLifecycle,
  load_options,
  runtime_engine_id,
  evidenceRefs = [],
} = {}) {
  const endpointId = requiredString(endpoint.id ?? endpoint.endpoint_id ?? endpoint.endpointId, "endpoint_id");
  const resolvedModelId = requiredString(
    modelId ?? instance?.model_id ?? instance?.modelId ?? endpoint.model_id ?? endpoint.modelId,
    "model_id",
  );
  const providerId = requiredString(
    instance?.provider_id ?? instance?.providerId ?? provider.id ?? endpoint.provider_id ?? endpoint.providerId,
    "provider_id",
  );
  const resolvedInstanceId = requiredString(instanceId ?? instance?.id, "instance_id");
  const resolvedBackendId = requiredString(
    backendId ?? instance?.backend_id ?? instance?.backendId ?? endpoint.backend_id ?? endpoint.backendId,
    "backend_id",
  );
  const driver = requiredString(provider.driver ?? provider.driver_ref ?? endpoint.driver, "driver");
  const provider_lifecycle_hash = action === "estimate"
    ? optionalProviderLifecycleHash(providerLifecycle)
    : requiredProviderLifecycleHash(providerLifecycle);
  const request = {
    schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
    instance_ref: resolvedInstanceId,
    endpoint_ref: endpointId,
    model_ref: resolvedModelId,
    provider_ref: providerId,
    action,
    target_status: targetStatus,
    execution_backend: RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
    backend_ref: resolvedBackendId,
    driver,
    provider_lifecycle_hash,
    evidence_refs: [
      ...new Set([
        "public_model_loading_rust_facade",
        ...evidenceRefs,
      ].filter(Boolean)),
    ],
  };
  if (action === "estimate") {
    request.runtime_engine_ref = runtime_engine_id ?? null;
    request.load_options = canonicalLoadEstimateOptions(load_options);
  }
  return request;
}

function requiredProviderLifecycleHash(providerLifecycle = {}) {
  const record = providerLifecycle.result && typeof providerLifecycle.result === "object" && !Array.isArray(providerLifecycle.result)
    ? providerLifecycle.result
    : {};
  const provider_lifecycle_hash = providerLifecycle.lifecycle_hash ?? record.lifecycle_hash;
  if (provider_lifecycle_hash) return provider_lifecycle_hash;
  throw runtimeError({
    status: 502,
    code: "model_mount_instance_lifecycle_provider_hash_required",
    message: "Model instance lifecycle requires a Rust provider lifecycle hash.",
    details: {
      rust_core_boundary: "model_mount.instance_lifecycle",
      provider_lifecycle_source: providerLifecycle.source ?? null,
    },
  });
}

function assertRustAuthoredModelInstanceLifecycleResult(result = {}, options = {}) {
  const record = result.result && typeof result.result === "object" && !Array.isArray(result.result)
    ? result.result
    : {};
  const evidenceRefs = Array.isArray(result.evidence_refs)
    ? result.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [];
  const missing = [];
  const mismatches = [];
  for (const field of ["id", "endpoint_id", "model_id", "provider_id", "instance_lifecycle_hash"]) {
    if (!record[field]) missing.push(`result.${field}`);
  }
  if (!result.executionBackend && !record.execution_backend) missing.push("execution_backend");
  if (!result.status && !record.status) missing.push("status");
  if (!evidenceRefs.includes("rust_model_mount_instance_lifecycle")) {
    missing.push("evidence_refs.rust_model_mount_instance_lifecycle");
  }
  if (options.action && record.action !== options.action) mismatches.push("result.action");
  if (options.targetStatus && record.status !== options.targetStatus) mismatches.push("result.status");
  if (missing.length === 0 && mismatches.length === 0) return;
  throw runtimeError({
    status: 502,
    code: "model_mount_instance_lifecycle_rust_result_required",
    message: "Model loading facade requires a Rust-authored model_mount instance lifecycle result.",
    details: {
      operation: options.action ?? null,
      target_status: options.targetStatus ?? null,
      missing,
      mismatches,
    },
  });
}

function optionalProviderLifecycleHash(providerLifecycle = {}) {
  const record = providerLifecycle.result && typeof providerLifecycle.result === "object" && !Array.isArray(providerLifecycle.result)
    ? providerLifecycle.result
    : {};
  return providerLifecycle.lifecycle_hash ?? record.lifecycle_hash ?? "";
}

function canonicalLoadEstimateOptions(load_options = {}) {
  return {
    estimate_only: true,
    ttl_seconds: load_options.ttlSeconds ?? null,
    parallel: load_options.parallel ?? null,
    gpu: load_options.gpu ?? null,
    context_length: load_options.contextLength ?? null,
    identifier: load_options.identifier ?? null,
  };
}

function commitModelInstanceLifecycleRecordState(
  state,
  lifecycle,
  { operation_kind, providerLifecycle } = {},
) {
  const record = lifecycle.result;
  const commit = commitModelMountRecordState(state, {
    recordDir: "model-instances",
    record,
    operation_kind,
    receipt_refs: [],
    unconfiguredCode: "model_mount_instance_lifecycle_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Model instance lifecycle requires Rust Agentgres record-state commit before public model-instance truth can return.",
    invalidCode: "model_mount_instance_lifecycle_record_state_commit_invalid",
  });
  return modelInstanceLifecycleResponse(lifecycle, commit, providerLifecycle);
}

function modelInstanceLifecycleResponse(lifecycle, commit, providerLifecycle = {}) {
  const record = lifecycle.result;
  return {
    ...record,
    object: "ioi.model_mount_instance",
    record_dir: "model-instances",
    record_id: record.id,
    record,
    commit,
    provider_lifecycle: providerLifecycle.result ?? null,
    provider_lifecycle_hash: lifecycle.provider_lifecycle_hash ?? record.provider_lifecycle_hash ?? null,
    instance_lifecycle_hash: lifecycle.instance_lifecycle_hash ?? record.instance_lifecycle_hash ?? null,
    evidence_refs: lifecycle.evidence_refs ?? record.evidence_refs ?? [],
  };
}

function defaultModelInstanceId(endpoint = {}, loadOptions = {}) {
  return `model_instance.${safeId(endpoint.id ?? "endpoint")}.${safeId(loadOptions.identifier ?? endpoint.modelId ?? endpoint.model_id ?? "model")}`;
}

function defaultModelLoadEstimateId(endpoint = {}, loadOptions = {}) {
  return `model_instance_estimate.${safeId(endpoint.id ?? "endpoint")}.${stableHash({
    model_id: endpoint.modelId ?? endpoint.model_id ?? null,
    context_length: loadOptions.contextLength ?? null,
    parallel: loadOptions.parallel ?? null,
    ttl_seconds: loadOptions.ttlSeconds ?? null,
    identifier: loadOptions.identifier ?? null,
  }).slice(0, 16)}`;
}

function throwProviderLifecycleRustCoreRequired(provider, operation, details = {}) {
  if (operation === "provider_health") {
    throwModelMountProviderHealthRustCoreRequired(provider, operation, details);
  }
  throw modelMountProviderControlRustCoreRequired(provider, operation, details);
}

function routeControlRequestForMountedState(
  state,
  {
    operation_kind,
    route_id,
    body = {},
    current_route = null,
  } = {},
) {
  return {
    schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION,
    operation_kind,
    source: "runtime-daemon.model_mounting.route_control",
    route_id,
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    current_route,
    endpoints: modelMountProjectionRecords(state, "listEndpoints"),
    providers: modelMountProjectionRecords(state, "listProviders"),
  };
}

function routeControlRouteForMountedState(state, routeId) {
  return modelMountProjectionRecords(state, "listRoutes").find(
    (record) =>
      record?.id === routeId ||
      record?.route_id === routeId ||
      record?.route_ref === routeId,
  ) ?? null;
}

function modelMountProjectionRecords(state, methodName) {
  const records = typeof state?.[methodName] === "function" ? state[methodName]() : [];
  return Array.isArray(records) ? records : [];
}

function modelMountReadProjection(
  state,
  projectionKind,
  {
    backendLogQuery = null,
    baseUrl = null,
    catalogQuery = null,
    downloadId = null,
    engineId = null,
    endpoint = null,
    providerId = null,
    receiptId = null,
    serverLogQuery = null,
  } = {},
) {
  const result = modelMountReadProjectionPlan(state, projectionKind, {
    backendLogQuery,
    baseUrl,
    catalogQuery,
    downloadId,
    engineId,
    endpoint,
    providerId,
    receiptId,
    serverLogQuery,
  });
  return result.projection;
}

function modelMountReadProjectionPlan(
  state,
  projectionKind,
  {
    backendLogQuery = null,
    baseUrl = null,
    catalogQuery = null,
    downloadId = null,
    engineId = null,
    endpoint = null,
    providerId = null,
    receiptId = null,
    serverLogQuery = null,
  } = {},
) {
  const planner = state?.modelMountCore;
  if (!planner || typeof planner.planReadProjection !== "function") {
    throwReadProjectionRustCoreRequired(projectionKind, {
      base_url: baseUrl,
      download_id: downloadId,
      engine_id: engineId,
      provider_id: providerId,
      receipt_id: receiptId,
    });
  }
  const result = planner.planReadProjection({
    projection_kind: projectionKind,
    schema_version: MODEL_MOUNT_SCHEMA_VERSION,
    generated_at: state.nowIso(),
    base_url: baseUrl,
    download_id: downloadId,
    engine_id: engineId,
    provider_id: providerId,
    receipt_id: receiptId,
    state_dir: modelMountReadProjectionStateDir(state, projectionKind),
    state: modelMountReadProjectionInput(state, baseUrl, projectionKind, {
      backendLogQuery,
      catalogQuery,
      engineId,
      endpoint,
      serverLogQuery,
    }),
  });
  if (!result || !Object.hasOwn(result, "projection")) {
    throwReadProjectionRustCoreRequired(projectionKind, {
      reason: "missing_rust_projection",
      source: result?.source ?? null,
      backend: result?.backend ?? null,
    });
  }
  return result;
}

function canonicalModelMountCatalogSearchQuery(query = {}) {
  const input = query && typeof query === "object" ? query : {};
  const canonical = {};
  for (const field of ["query", "format", "quantization", "provider_ref"]) {
    const value = input[field];
    if (typeof value === "string" && value.trim().length > 0) {
      canonical[field] = value.trim();
    }
  }
  const limit = Number.parseInt(String(input.limit ?? ""), 10);
  if (Number.isSafeInteger(limit) && limit > 0) {
    canonical.limit = Math.min(limit, 100);
  }
  return canonical;
}

function canonicalModelMountServerLogQuery(query = {}) {
  const input = query && typeof query === "object" ? query : {};
  const canonical = {};
  const limit = Number.parseInt(String(input.limit ?? ""), 10);
  if (Number.isSafeInteger(limit) && limit > 0) {
    canonical.limit = Math.min(limit, 500);
  }
  return canonical;
}

function canonicalModelMountBackendLogQuery(backendId, query = {}) {
  return {
    ...canonicalModelMountServerLogQuery(query),
    backend_id: backendId,
  };
}

function modelMountReadProjectionInput(
  state,
  baseUrl = null,
  projectionKind = "projection",
  {
    backendLogQuery = null,
    catalogQuery = null,
    engineId = null,
    endpoint = null,
    serverLogQuery = null,
  } = {},
) {
  void baseUrl;
  void engineId;
  void endpoint;
  if (
    projectionKind === "workflow_bindings" ||
    projectionKind === "runtime_engines" ||
    projectionKind === "runtime_engine_profiles" ||
    projectionKind === "runtime_preference" ||
    projectionKind === "runtime_preference_for_endpoint" ||
    projectionKind === "runtime_default_load_options" ||
    projectionKind === "runtime_engine_detail" ||
    projectionKind === "adapter_boundaries" ||
    projectionKind === "provider_inventory_records" ||
    projectionKind === "model_tokenizer_records" ||
    projectionKind === "model_route_decisions" ||
    projectionKind === "model_route_endpoint_resolutions" ||
    projectionKind === "download_status" ||
    projectionKind === "storage_summary" ||
    projectionKind === "projection_summary" ||
    projectionKind === "latest_vault_health" ||
    projectionKind === "latest_runtime_survey" ||
    projectionKind === "latest_provider_health" ||
    projectionKind === "model_conversation_states" ||
    projectionKind === "server_status" ||
    projectionKind === "catalog_status" ||
    projectionKind === "receipt_replay" ||
    projectionKind === "artifacts" ||
    projectionKind === "providers" ||
    projectionKind === "endpoints" ||
    projectionKind === "instances" ||
    projectionKind === "routes" ||
    projectionKind === "model_capabilities" ||
    projectionKind === "downloads" ||
    projectionKind === "backends" ||
    projectionKind === "mcp_servers" ||
    projectionKind === "product_artifacts" ||
    projectionKind === "runtime_model_catalog" ||
    projectionKind === "open_ai_model_list" ||
    projectionKind === "oauth_sessions" ||
    projectionKind === "oauth_states" ||
    projectionKind === "provider_health" ||
    projectionKind === "authority_snapshot" ||
    projectionKind === "snapshot" ||
    projectionKind === "projection"
  ) {
    return {};
  }
  if (
    projectionKind === "server_logs" ||
    projectionKind === "server_events" ||
    projectionKind === "server_log_records"
  ) {
    return { server_log_query: serverLogQuery ?? {} };
  }
  if (projectionKind === "backend_logs") {
    return { backend_log_query: backendLogQuery ?? {} };
  }
  if (projectionKind === "catalog_search") {
    return { catalog_search: catalogQuery ?? {} };
  }
  return {
    receipts: state.listReceipts(),
  };
}

function modelMountReadProjectionStateDir(state, projectionKind) {
  if (
    projectionKind !== "model_conversation_states" &&
    projectionKind !== "instances" &&
    projectionKind !== "provider_inventory_records" &&
    projectionKind !== "catalog_search" &&
    projectionKind !== "catalog_status" &&
    projectionKind !== "model_tokenizer_records" &&
    projectionKind !== "routes" &&
    projectionKind !== "model_capabilities" &&
    projectionKind !== "model_route_decisions" &&
    projectionKind !== "model_route_endpoint_resolutions" &&
    projectionKind !== "artifacts" &&
    projectionKind !== "product_artifacts" &&
    projectionKind !== "providers" &&
    projectionKind !== "endpoints" &&
    projectionKind !== "runtime_model_catalog" &&
    projectionKind !== "open_ai_model_list" &&
    projectionKind !== "downloads" &&
    projectionKind !== "download_status" &&
    projectionKind !== "storage_summary" &&
    projectionKind !== "backend_logs" &&
    projectionKind !== "server_status" &&
    projectionKind !== "server_logs" &&
    projectionKind !== "server_events" &&
    projectionKind !== "server_log_records" &&
    projectionKind !== "backends" &&
    projectionKind !== "mcp_servers" &&
    projectionKind !== "oauth_sessions" &&
    projectionKind !== "oauth_states" &&
    projectionKind !== "runtime_engines" &&
    projectionKind !== "runtime_engine_profiles" &&
    projectionKind !== "runtime_preference" &&
    projectionKind !== "runtime_preference_for_endpoint" &&
    projectionKind !== "runtime_default_load_options" &&
    projectionKind !== "runtime_engine_detail" &&
    projectionKind !== "snapshot" &&
    projectionKind !== "projection" &&
    projectionKind !== "projection_summary" &&
    projectionKind !== "receipt_replay" &&
    projectionKind !== "authority_snapshot" &&
    projectionKind !== "provider_health" &&
    projectionKind !== "latest_provider_health" &&
    projectionKind !== "latest_vault_health" &&
    projectionKind !== "latest_runtime_survey"
  ) return null;
  return typeof state?.stateDir === "string" && state.stateDir.trim().length > 0
    ? state.stateDir
    : null;
}

function throwReadProjectionRustCoreRequired(projectionKind, details = {}) {
  const error = new Error("Model-mount read projection requires Rust daemon-core projection ownership.");
  error.status = 501;
  error.code = "model_mount_read_projection_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.projection",
    projection_kind: projectionKind,
    ...details,
    evidence_refs: [
      "model_mount_js_read_projection_authoring_retired",
      "rust_daemon_core_model_mount_projection_required",
      "agentgres_model_mount_read_truth_required",
    ],
  };
  throw error;
}

function translateDownloadStatusError(error, jobId) {
  if (
    error?.code === "model_mount_download_not_found" ||
    error?.code === "model_mount_download_id_required"
  ) {
    return notFound(`Download job not found: ${jobId}`, { job_id: jobId });
  }
  throw error;
}

function translateLatestProviderHealthError(error, providerId) {
  if (
    error?.code === "model_mount_provider_not_found" ||
    error?.code === "model_mount_provider_health_not_found"
  ) {
    return notFound(`Provider health has not been checked: ${providerId}`, { providerId });
  }
  throw error;
}

function translateLatestVaultHealthError(error) {
  if (error?.code === "model_mount_vault_health_not_found") {
    return notFound("Vault adapter health has not been checked.", {
      receiptKind: "vault_adapter_health",
    });
  }
  throw error;
}

function translateRuntimeEngineError(error, engineId) {
  if (error?.code === "model_mount_runtime_engine_not_found") {
    return notFound(`Runtime engine not found: ${engineId}`, { engine_id: engineId });
  }
  throw error;
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
  const error = new Error("Provider inventory reads require Rust daemon-core record truth and replay support.");
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
      "agentgres_provider_inventory_truth_required",
      "agentgres_provider_inventory_replay_required",
    ],
  };
  throw error;
}
