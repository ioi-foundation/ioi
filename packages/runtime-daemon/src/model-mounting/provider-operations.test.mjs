import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState() {
  const state = {
    artifacts: new Map(),
    endpoints: new Map(),
    instances: new Map(),
    providers: new Map(),
    healthWrites: [],
    modelMountLifecycleRequests: [],
    modelMountInventoryRequests: [],
    modelMountProviderAuthMaterializationRequests: [],
    modelMountProviderControlRequests: [],
    endpointProjectionRecords: [],
    recordStateCommits: [],
    projections: 0,
    receipts: [],
    resolvedVaultRefs: [],
    writes: [],
    stateDir: "/state",
    now: "2026-06-03T22:00:00.000Z",
    drivers: new Map(),
    lifecycleReceipt(kind, details) {
      const receipt = { id: `lifecycle.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    listArtifacts() {
      return [...this.artifacts.values()];
    },
    listEndpoints() {
      return this.endpointProjectionRecords;
    },
    listInstances() {
      return [...this.instances.values()];
    },
    planModelMountProviderAuthMaterialization(request) {
      this.modelMountProviderAuthMaterializationRequests.push(JSON.parse(JSON.stringify(request)));
      const providerId = request.provider_id;
      const recordId = `${providerId}_auth_header`;
      const evidenceRefs = [
        "rust_daemon_core_provider_auth_materialization",
        "rust_provider_auth_materialization_bound",
        "wallet_network_provider_vault_ref_bound",
        "ctee_provider_auth_header_custody_enforced",
        "hosted_provider_auth_header_materialized_by_rust",
        "hosted_provider_plaintext_secret_not_returned",
        "agentgres_provider_auth_materialization_truth_required",
        "public_provider_auth_header_js_facade_retired",
        "rust_ctee_egress_resolver_bound",
        "ctee_outbound_egress_resolver_depth_bound",
      ];
      const publicResponse = {
        object: "ioi.model_mount_provider_auth_materialization",
        id: recordId,
        provider_id: providerId,
        provider_ref: request.provider_ref,
        provider_kind: request.provider_kind,
        auth_scheme: request.auth_scheme,
        auth_header_name: request.auth_header_name,
        auth_header_materialization_status: "rust_ctee_outbound_header_bound",
        outbound_header_binding_ref: `provider_auth_header://${recordId}#sha256:provider-auth-materialization`,
        provider_auth_materialization_ref:
          `agentgres://model-mounting/model-provider-auth-materializations/${recordId}`,
        ctee_egress_resolver_ref:
          `ctee://model-mount/egress-resolver/${recordId}#sha256:ctee-egress-resolver`,
        ctee_egress_resolver_hash: "sha256:ctee-egress-resolver",
        ctee_egress_resolution_status: "rust_ctee_outbound_egress_resolved",
        plaintext_secret_material_returned: false,
        auth_header_value_returned: false,
        auth_header_value_persisted: false,
      };
      const record = {
        ...publicResponse,
        record_id: recordId,
        schema_version: "ioi.model_mount.provider_auth_materialization.v1",
        status: "materialized",
        operation_kind: request.operation_kind,
        source: "rust_daemon_core.model_mount.provider_auth_materialization",
        rust_core_boundary: "model_mount.provider_auth_materialization",
        wallet_authority_boundary: "wallet.network.provider_auth",
        ctee_custody_boundary: "ctee.provider_auth_header",
        custody_policy: {
          no_plaintext_custody: true,
          private_material_resolved_by: "rust_daemon_core_ctee",
          outbound_header_materialized_by: "rust_daemon_core.model_mount.provider_auth_materialization",
          egress_resolver_owner: "rust_daemon_core.ctee.egress_resolver",
          egress_resolution_status: "rust_ctee_outbound_egress_resolved",
          js_private_material_readback_retired: true,
        },
        public_response: publicResponse,
        receipt_refs: request.receipt_refs,
        evidence_refs: evidenceRefs,
        materialization_hash: "provider-auth-materialization",
      };
      return {
        source: "rust_daemon_core.model_mount.provider_auth_materialization",
        plan: {
          schema_version: "ioi.model_mount.provider_auth_materialization_plan.v1",
          object: "ioi.model_mount_provider_auth_materialization_plan",
          status: "planned",
          rust_core_boundary: "model_mount.provider_auth_materialization",
          operation_kind: request.operation_kind,
          source: "runtime-daemon.model_mounting.provider_auth_materialization",
          record_dir: "model-provider-auth-materializations",
          record_id: recordId,
          record,
          public_response: publicResponse,
          receipt_refs: request.receipt_refs,
          authority_grant_refs: request.authority_grant_refs,
          authority_receipt_refs: request.authority_receipt_refs,
          evidence_refs: evidenceRefs,
          materialization_hash: "provider-auth-materialization",
          authority_hash: "sha256:provider-auth-authority",
        },
        record_dir: "model-provider-auth-materializations",
        record_id: recordId,
        record,
        public_response: publicResponse,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_auth_materialization",
        receipt_refs: request.receipt_refs,
        authority_grant_refs: request.authority_grant_refs,
        authority_receipt_refs: request.authority_receipt_refs,
        evidence_refs: evidenceRefs,
        materialization_hash: "provider-auth-materialization",
        authority_hash: "sha256:provider-auth-authority",
      };
    },
    planModelMountProviderControl(request) {
      this.modelMountProviderControlRequests.push(JSON.parse(JSON.stringify(request)));
      const body = request.body ?? {};
      const providerId = request.provider_id ?? body.id;
      const recordId = providerId;
      const evidenceRefs = [
        "rust_daemon_core_provider_control",
        "wallet_network_provider_control_authority_required",
        "wallet_network_vault_authority_required",
        "ctee_provider_custody_enforced",
        "agentgres_provider_control_truth_required",
        "public_provider_control_js_facade_retired",
      ];
      const publicResponse = {
        object: "ioi.model_mount_provider",
        id: providerId,
        provider_id: providerId,
        provider_ref: body.provider_ref ?? `provider://${providerId}`,
        kind: body.kind,
        label: body.label,
        status: body.status,
        api_format: body.api_format,
        driver: body.driver,
        base_url: body.base_url,
        privacy_class: body.privacy_class,
        capabilities: body.capabilities ?? [],
        auth_scheme: body.auth_scheme,
        auth_header_name: body.auth_header_name,
        secret_ref: body.secret_ref,
        provider_auth_materialization_ref: body.provider_auth_materialization_ref,
        outbound_header_binding_ref: body.outbound_header_binding_ref,
        auth_header_materialization_status: body.auth_header_materialization_status,
        ctee_egress_resolver_ref: body.ctee_egress_resolver_ref,
        ctee_egress_resolver_hash: body.ctee_egress_resolver_hash,
        ctee_egress_resolution_status: body.ctee_egress_resolution_status,
        auth_material_status: body.auth_header_materialization_status ??
          (body.secret_ref ? "wallet_vault_ref_bound" : "not_required"),
        private_material_returned: false,
        plaintext_material_persisted: false,
        authority_hash: "sha256:provider-control-authority",
        control_hash: "sha256:provider-control",
      };
      const record = {
        id: recordId,
        record_id: recordId,
        schema_version: "ioi.model_mount.provider_control.v1",
        object: "ioi.model_mount_provider",
        status: body.status,
        operation_kind: request.operation_kind,
        source: "rust_daemon_core.model_mount.provider_control",
        provider_id: providerId,
        provider_ref: publicResponse.provider_ref,
        kind: body.kind,
        label: body.label,
        api_format: body.api_format,
        driver: body.driver,
        base_url: body.base_url,
        privacy_class: body.privacy_class,
        capabilities: body.capabilities ?? [],
        auth_scheme: body.auth_scheme,
        auth_header_name: body.auth_header_name,
        secret_ref: body.secret_ref,
        provider_auth_materialization_ref: body.provider_auth_materialization_ref,
        outbound_header_binding_ref: body.outbound_header_binding_ref,
        auth_header_materialization_status: body.auth_header_materialization_status,
        ctee_egress_resolver_ref: body.ctee_egress_resolver_ref,
        ctee_egress_resolver_hash: body.ctee_egress_resolver_hash,
        ctee_egress_resolution_status: body.ctee_egress_resolution_status,
        rust_core_boundary: "model_mount.provider_control",
        wallet_authority_boundary: "wallet.network.provider_control",
        ctee_custody_boundary: "ctee.provider_material",
        plaintext_material_returned: false,
        custody_policy: {
          no_plaintext_custody: true,
          private_material_resolved_by: "rust_daemon_core_ctee",
          js_private_material_readback_retired: true,
          custody_ref: request.custody_ref,
        },
        authority: {
          authority_hash: "sha256:provider-control-authority",
          required_scope: request.required_scope,
          authority_grant_refs: request.authority_grant_refs,
          authority_receipt_refs: request.authority_receipt_refs,
        },
        public_response: publicResponse,
        receipt_refs: request.receipt_refs,
        evidence_refs: evidenceRefs,
        control_hash: "provider-control",
      };
      return {
        source: "rust_daemon_core.model_mount.provider_control",
        backend: "rust_model_mount_provider_control",
        plan: {
          schema_version: "ioi.model_mount.provider_control_plan.v1",
          object: "ioi.model_mount_provider_control_plan",
          status: "planned",
          rust_core_boundary: "model_mount.provider_control",
          operation_kind: request.operation_kind,
          source: "runtime-daemon.model_mounting.provider_control",
          record_dir: "model-providers",
          record_id: recordId,
          record,
          receipt_refs: request.receipt_refs,
          authority_grant_refs: request.authority_grant_refs,
          authority_receipt_refs: request.authority_receipt_refs,
          evidence_refs: evidenceRefs,
          control_hash: "provider-control",
          authority_hash: "sha256:provider-control-authority",
        },
        record_dir: "model-providers",
        record_id: recordId,
        record,
        public_response: publicResponse,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_control",
        receipt_refs: request.receipt_refs,
        authority_grant_refs: request.authority_grant_refs,
        authority_receipt_refs: request.authority_receipt_refs,
        evidence_refs: evidenceRefs,
        control_hash: "provider-control",
        authority_hash: "sha256:provider-control-authority",
      };
    },
    planModelMountProviderLifecycle(request) {
      this.modelMountLifecycleRequests.push(JSON.parse(JSON.stringify(request)));
      const nativeLocal = request.execution_backend === "rust_model_mount_native_local_lifecycle";
      const hostedProvider = request.execution_backend === "rust_model_mount_hosted_provider_lifecycle";
      const status = request.action === "load"
        ? "loaded"
        : request.action === "unload"
          ? "unloaded"
          : request.provider_status === "blocked"
            ? "blocked"
            : "available";
      const backendId = request.backend_ref ?? (nativeLocal
        ? "backend.autopilot.native-local.fixture"
        : hostedProvider
          ? `backend.hosted.${request.provider_kind}`
          : "backend.fixture");
      const backend = nativeLocal
        ? "autopilot.native_local.fixture"
        : hostedProvider
          ? (request.api_format ?? request.driver ?? "hosted_provider_metadata")
          : "ioi_fixture";
      const driver = nativeLocal
        ? "native_local"
        : hostedProvider
          ? "hosted_provider_metadata"
          : "fixture";
      const evidenceRefs = [
        "public_provider_lifecycle_js_facade_retired",
        "rust_model_mount_provider_lifecycle",
        "agentgres_provider_lifecycle_truth_required",
        nativeLocal
          ? "rust_model_mount_native_local_lifecycle_backend"
          : hostedProvider
            ? "rust_model_mount_hosted_provider_lifecycle_backend"
            : "rust_model_mount_fixture_lifecycle_backend",
        ...(hostedProvider
          ? [
            "rust_hosted_provider_metadata_transport_materialized",
            "ctee_hosted_provider_secret_not_exposed",
            "wallet_network_provider_transport_authority_bound",
            "wallet_network_provider_lifecycle_authority_required",
          ]
          : []),
      ];
      const transportContract = {
        transport_execution_status: "rust_materialized",
        transport_execution_owner: "rust_daemon_core.model_mount.provider_lifecycle",
        transport_materialization_kind: hostedProvider
          ? "hosted_provider_metadata_lifecycle"
          : nativeLocal
            ? "native_local_lifecycle"
            : "fixture_lifecycle",
        plaintext_secret_material_returned: false,
      };
      const record = {
        ...request,
        operation_kind: request.operation_kind,
        status,
        backend,
        backend_id: backendId,
        driver,
        lifecycle_hash: `sha256:${request.provider_ref}:${request.action}`,
        evidence_refs: evidenceRefs,
        transport_contract: transportContract,
        rust_core_boundary: "model_mount.provider_lifecycle",
        record_dir: "model-provider-lifecycle-controls",
        receipt_refs: [],
      };
      const recordId = `provider_lifecycle_${request.provider_ref.replace(/[^a-z0-9._-]+/gi, "_").replace(/^_+|_+$/g, "")}_${request.action}_test`;
      const providerLifecycleRecord = {
        id: recordId,
        record_id: recordId,
        object: "ioi.model_mount_provider_lifecycle",
        schema_version: "ioi.model_mount.provider_lifecycle_plan.v1",
        provider_ref: request.provider_ref,
        provider_kind: request.provider_kind,
        endpoint_ref: request.endpoint_ref,
        model_ref: request.model_ref,
        action: request.action,
        operation_kind: request.operation_kind,
        status,
        backend: record.backend,
        backend_id: backendId,
        driver: record.driver,
        execution_backend: request.execution_backend,
        transport_contract: transportContract,
        transport_execution_status: "rust_materialized",
        transport_execution_owner: "rust_daemon_core.model_mount.provider_lifecycle",
        transport_materialization_kind: transportContract.transport_materialization_kind,
        plaintext_secret_material_returned: false,
        lifecycle_hash: record.lifecycle_hash,
        record_dir: "model-provider-lifecycle-controls",
        receipt_refs: [record.lifecycle_hash],
        rust_core_boundary: "model_mount.provider_lifecycle",
        source: "rust_model_mount_provider_lifecycle_command",
        evidence_refs: record.evidence_refs,
      };
      const publicResponse = {
        object: "ioi.model_mount_provider_lifecycle",
        status,
        provider_ref: request.provider_ref,
        provider_kind: request.provider_kind,
        endpoint_ref: request.endpoint_ref,
        model_ref: request.model_ref,
        action: request.action,
        backend_id: backendId,
        provider_backend: record.backend,
        driver: record.driver,
        execution_backend: request.execution_backend,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_lifecycle",
        lifecycle_hash: record.lifecycle_hash,
        transport_contract: transportContract,
        transport_execution_status: "rust_materialized",
        js_provider_driver_call: false,
        js_provider_map_write: false,
        js_lifecycle_receipt: false,
        js_projection_write: false,
      };
      providerLifecycleRecord.public_response = publicResponse;
      record.record_id = recordId;
      record.record = providerLifecycleRecord;
      record.public_response = publicResponse;
      return {
        source: "rust_model_mount_provider_lifecycle_command",
        backend: request.execution_backend,
        result: record,
        status,
        backendId,
        providerBackend: record.backend,
        driver: record.driver,
        executionBackend: request.execution_backend,
        lifecycle_hash: record.lifecycle_hash,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_lifecycle",
        record_dir: "model-provider-lifecycle-controls",
        record_id: recordId,
        record: providerLifecycleRecord,
        public_response: publicResponse,
        receipt_refs: [],
        evidence_refs: record.evidence_refs,
        backendEvidenceRefs: record.evidence_refs,
      };
    },
    planModelMountProviderInventory(request) {
      this.modelMountInventoryRequests.push(JSON.parse(JSON.stringify(request)));
      const nativeLocal = request.execution_backend === "rust_model_mount_native_local_inventory";
      const hostedProvider = request.execution_backend === "rust_model_mount_hosted_provider_inventory";
      const itemRefs = Array.isArray(request.item_refs) ? request.item_refs : [];
      const backendId = request.backend_ref ?? (nativeLocal
        ? "backend.autopilot.native-local.fixture"
        : hostedProvider
          ? `backend.hosted.${request.provider_kind}`
          : "backend.fixture");
      const operationKind = request.action === "list_loaded"
        ? "model_mount.provider.inventory.list_loaded"
        : "model_mount.provider.inventory.list_models";
      const evidenceRefs = [
        "rust_model_mount_provider_inventory",
        "agentgres_provider_inventory_truth_required",
        nativeLocal
          ? "rust_model_mount_native_local_inventory_backend"
          : hostedProvider
            ? "rust_model_mount_hosted_provider_inventory_backend"
            : "rust_model_mount_fixture_inventory_backend",
        ...(hostedProvider
          ? [
            "rust_hosted_provider_metadata_transport_materialized",
            "ctee_hosted_provider_secret_not_exposed",
            "wallet_network_provider_transport_authority_bound",
            "wallet_network_provider_secret_boundary",
          ]
          : []),
      ];
      const transportContract = {
        transport_execution_status: "rust_materialized",
        transport_execution_owner: "rust_daemon_core.model_mount.provider_inventory",
        transport_materialization_kind: hostedProvider
          ? "hosted_provider_metadata"
          : nativeLocal
            ? "native_local_inventory"
            : "fixture_inventory",
        plaintext_secret_material_returned: false,
      };
      const inventoryHash = `sha256:${request.provider_ref}:${request.action}`;
      const recordId = `provider_inventory_${request.provider_ref.replace(/[^a-z0-9._-]+/gi, "_").replace(/^_+|_+$/g, "")}_${request.action}_test`;
      const providerInventoryRecord = {
        id: recordId,
        object: "ioi.model_mount_provider_inventory",
        schema_version: request.schema_version,
        provider_ref: request.provider_ref,
        provider_kind: request.provider_kind,
        action: request.action,
        operation_kind: operationKind,
        status: "listed",
        backend: nativeLocal
          ? "autopilot.native_local.fixture"
          : hostedProvider
            ? "hosted_provider_metadata"
            : "ioi_fixture",
        backend_id: backendId,
        driver: nativeLocal ? "native_local" : hostedProvider ? "hosted_provider_metadata" : "fixture",
        execution_backend: request.execution_backend,
        item_refs: itemRefs,
        item_count: itemRefs.length,
        transport_contract: transportContract,
        transport_execution_status: "rust_materialized",
        transport_execution_owner: "rust_daemon_core.model_mount.provider_inventory",
        transport_materialization_kind: transportContract.transport_materialization_kind,
        plaintext_secret_material_returned: false,
        inventory_hash: inventoryHash,
        record_dir: "model-provider-inventory",
        record_id: recordId,
        receipt_refs: [],
        rust_core_boundary: "model_mount.provider_inventory",
        source: "rust_model_mount_provider_inventory_command",
        evidence_refs: evidenceRefs,
      };
      const record = {
        ...request,
        operation_kind: operationKind,
        status: "listed",
        backend: nativeLocal
          ? "autopilot.native_local.fixture"
          : hostedProvider
            ? "hosted_provider_metadata"
            : "ioi_fixture",
        backend_id: backendId,
        driver: nativeLocal ? "native_local" : hostedProvider ? "hosted_provider_metadata" : "fixture",
        item_refs: itemRefs,
        item_count: itemRefs.length,
        transport_contract: transportContract,
        transport_execution_status: "rust_materialized",
        inventory_hash: inventoryHash,
        rust_core_boundary: "model_mount.provider_inventory",
        record_dir: "model-provider-inventory",
        record_id: recordId,
        record: providerInventoryRecord,
        receipt_refs: [],
        evidence_refs: evidenceRefs,
      };
      return {
        source: "rust_model_mount_provider_inventory_command",
        backend: request.execution_backend,
        result: record,
        status: "listed",
        backendId,
        providerBackend: record.backend,
        driver: record.driver,
        executionBackend: request.execution_backend,
        itemRefs,
        itemCount: itemRefs.length,
        transport_contract: transportContract,
        transport_execution_status: "rust_materialized",
        inventory_hash: inventoryHash,
        operation_kind: operationKind,
        rust_core_boundary: "model_mount.provider_inventory",
        record_dir: "model-provider-inventory",
        record_id: recordId,
        record: providerInventoryRecord,
        receipt_refs: [],
        evidence_refs: evidenceRefs,
        backendEvidenceRefs: evidenceRefs,
      };
    },
    nowIso() {
      return this.now;
    },
    normalizeProviderSecretRef(kind, body = {}, existingSecretRef = null) {
      return normalizeProviderSecretRef(this, kind, body, existingSecretRef, providerDeps());
    },
    provider(providerId) {
      return this.providers.get(providerId);
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, payload };
      this.receipts.push(receipt);
      return receipt;
    },
    vault: {
      vaultRefMetadata(vaultRef) {
        return { vaultRefHash: `vault-hash:${vaultRef}`, resolvedMaterial: true };
      },
    },
    walletAuthority: {
      resolveVaultRef: (vaultRef) => {
        state.resolvedVaultRefs.push(vaultRef);
        return { vaultRefHash: `vault-hash:${vaultRef}` };
      },
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        source: "rust_agentgres_runtime_model_mount_record_state_commit_protocol",
        backend: "rust_agentgres_storage",
        record: {
          schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
          record_dir: request.record_dir,
          record_id: request.record_id,
          operation_kind: request.operation_kind,
          storage_backend_ref: request.storage_backend_ref,
          record: {
            record_path: `${request.record_dir}/${request.record_id}.json`,
            object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
            content_hash: "sha256:model-mount-record-content",
            payload_refs: [`payload://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`],
            receipt_refs: request.receipt_refs,
            admission: { admission_hash: "sha256:model-mount-record-admission" },
          },
          commit_hash: "sha256:model-mount-record-commit",
        },
        storage_record: {
          record_path: `${request.record_dir}/${request.record_id}.json`,
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
          content_hash: "sha256:model-mount-record-content",
          payload_refs: [`payload://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`],
          receipt_refs: request.receipt_refs,
          admission: { admission_hash: "sha256:model-mount-record-admission" },
        },
        record_dir: request.record_dir,
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
        content_hash: "sha256:model-mount-record-content",
        admission_hash: "sha256:model-mount-record-admission",
        commit_hash: "sha256:model-mount-record-commit",
        written_record: { record_path: `${request.record_dir}/${request.record_id}.json` },
        evidence_refs: ["rust_agentgres_runtime_model_mount_record_state_commit"],
      };
    },
    writeProjection() {
      this.projections += 1;
    },
  };
  return state;
}

const deps = {
  assertNoPlaintextProviderSecret(body) {
    if (body.api_key || body.apiKey) throw new Error("plaintext provider secret");
  },
  normalizeScopes(value, fallback = []) {
    return Array.isArray(value) ? value : fallback;
  },
  providerHealthFailureStatus(error) {
    return error.status === 403 ? "blocked" : "degraded";
  },
  providerRequiresVaultSecret(kind) {
    return ["openai", "anthropic", "gemini"].includes(kind);
  },
  providerSecretInput(body) {
    if (Object.prototype.hasOwnProperty.call(body, "api_key_vault_ref")) return body.api_key_vault_ref;
    if (Object.prototype.hasOwnProperty.call(body, "auth_vault_ref")) return body.auth_vault_ref;
    if (Object.prototype.hasOwnProperty.call(body, "secret_ref")) return body.secret_ref;
    return undefined;
  },
  safeFileName(value) {
    return String(value).replace(/[^a-z0-9._-]+/gi, "_");
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, "_");
  },
  writeJson(filePath, value) {
    deps.healthWrites.push({ filePath, value });
  },
  healthWrites: [],
};

function providerDeps(overrides = {}) {
  deps.healthWrites = [];
  return { ...deps, ...overrides };
}

function upsertProvider(state, body = {}) {
  return ModelMountingState.prototype.upsertProvider.call(state, body);
}

function normalizeProviderSecretRef(state, kind, body = {}, existingSecretRef = null) {
  return ModelMountingState.prototype.normalizeProviderSecretRef.call(
    state,
    kind,
    body,
    existingSecretRef,
  );
}

function providerHealth(state, providerId) {
  return ModelMountingState.prototype.providerHealth.call(state, providerId);
}

function listProviderModels(state, providerId) {
  return ModelMountingState.prototype.listProviderModels.call(state, providerId);
}

function listProviderLoaded(state, providerId) {
  return ModelMountingState.prototype.listProviderLoaded.call(state, providerId);
}

function startProvider(state, providerId) {
  return ModelMountingState.prototype.startProvider.call(state, providerId);
}

function stopProvider(state, providerId) {
  return ModelMountingState.prototype.stopProvider.call(state, providerId);
}

test("mounted provider driver factory facade is deleted before JS driver allocation", () => {
  const state = fakeState();
  state.providers.set("provider.openai", {
    id: "provider.openai",
    kind: "openai",
    driver: "openai_compatible",
    status: "configured",
  });

  assert.equal(Object.hasOwn(ModelMountingState.prototype, "driverForProvider"), false);
  assert.equal(Object.hasOwn(state, "driverForProvider"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("provider upsert commits Rust provider-auth materialization and provider-control records without JS vault resolution or provider mutation", () => {
  const state = fakeState();

  const result = upsertProvider(
    state,
    {
      id: "provider.openai",
      kind: "openai",
      label: "OpenAI",
      api_key_vault_ref: "vault://provider/openai",
      auth_header_name: "X-API-Key",
      api_format: "openai",
      base_url: "https://api.openai.example/v1",
      privacy_class: "hosted_private",
      evidence_refs: ["operator_provider_config", "wallet.network.vault_ref_boundary"],
      capabilities: ["chat", "responses"],
    },
    providerDeps(),
  );

  assert.equal(state.modelMountProviderAuthMaterializationRequests.length, 1);
  assert.equal(
    state.modelMountProviderAuthMaterializationRequests[0].schema_version,
    "ioi.model_mount.provider_auth_materialization.v1",
  );
  assert.equal(
    state.modelMountProviderAuthMaterializationRequests[0].operation_kind,
    "model_mount.provider_auth.materialize",
  );
  assert.equal(state.modelMountProviderAuthMaterializationRequests[0].provider_id, "provider.openai");
  assert.equal(state.modelMountProviderAuthMaterializationRequests[0].provider_kind, "openai");
  assert.equal(state.modelMountProviderAuthMaterializationRequests[0].vault_ref, "vault://provider/openai");
  assert.equal(state.modelMountProviderAuthMaterializationRequests[0].auth_header_name, "X-API-Key");
  assert.equal(state.modelMountProviderControlRequests.length, 1);
  assert.equal(state.modelMountProviderControlRequests[0].schema_version, "ioi.model_mount.provider_control.v1");
  assert.equal(state.modelMountProviderControlRequests[0].operation_kind, "model_mount.provider.write");
  assert.equal(state.modelMountProviderControlRequests[0].provider_id, "provider.openai");
  assert.equal(state.modelMountProviderControlRequests[0].body.secret_ref, "vault://provider/openai");
  assert.equal(Object.hasOwn(state.modelMountProviderControlRequests[0].body, "api_key_vault_ref"), false);
  assert.equal(state.modelMountProviderControlRequests[0].body.auth_header_name, "X-API-Key");
  assert.equal(state.modelMountProviderControlRequests[0].body.api_format, "openai");
  assert.equal(
    state.modelMountProviderControlRequests[0].body.auth_header_materialization_status,
    "rust_ctee_outbound_header_bound",
  );
  assert.equal(
    state.modelMountProviderControlRequests[0].body.ctee_egress_resolver_ref,
    "ctee://model-mount/egress-resolver/provider.openai_auth_header#sha256:ctee-egress-resolver",
  );
  assert.equal(
    state.modelMountProviderControlRequests[0].body.ctee_egress_resolver_hash,
    "sha256:ctee-egress-resolver",
  );
  assert.equal(
    state.modelMountProviderControlRequests[0].body.ctee_egress_resolution_status,
    "rust_ctee_outbound_egress_resolved",
  );
  assert.equal(
    state.modelMountProviderControlRequests[0].body.evidence_refs.includes(
      "rust_provider_auth_materialization_bound",
    ),
    true,
  );
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].record_dir, "model-provider-auth-materializations");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider_auth.materialize");
  assert.equal(
    state.recordStateCommits[0].record.rust_core_boundary,
    "model_mount.provider_auth_materialization",
  );
  assert.equal(state.recordStateCommits[0].record.auth_header_value_returned, false);
  assert.equal(
    state.recordStateCommits[0].record.ctee_egress_resolution_status,
    "rust_ctee_outbound_egress_resolved",
  );
  assert.equal(
    state.recordStateCommits[0].record.evidence_refs.includes("rust_ctee_egress_resolver_bound"),
    true,
  );
  assert.equal(state.recordStateCommits[1].record_dir, "model-providers");
  assert.equal(state.recordStateCommits[1].record_id, "provider.openai");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.provider.write");
  assert.equal(state.recordStateCommits[1].record.rust_core_boundary, "model_mount.provider_control");
  assert.equal(
    state.recordStateCommits[1].record.ctee_egress_resolver_ref,
    "ctee://model-mount/egress-resolver/provider.openai_auth_header#sha256:ctee-egress-resolver",
  );
  assert.equal(state.recordStateCommits[1].record.plaintext_material_returned, false);
  assert.equal(result.rust_core_boundary, "model_mount.provider_control");
  assert.equal(result.record_dir, "model-providers");
  assert.equal(result.record_id, "provider.openai");
  assert.equal(result.auth_header_materialization_status, "rust_ctee_outbound_header_bound");
  assert.equal(
    result.ctee_egress_resolution_status,
    "rust_ctee_outbound_egress_resolved",
  );
  assert.equal(result.evidence_refs.includes("rust_daemon_core_provider_control"), true);
  assert.equal(result.private_material_returned, false);
  assert.equal(result.plaintext_material_persisted, false);
  assert.equal(result.js_provider_map_write, false);
  assert.equal(result.js_vault_resolution, false);
  assert.equal(result.js_write_map, false);
  assert.equal(result.evidence_refs.includes("agentgres_provider_control_truth_required"), true);
  assert.equal(state.providers.has("provider.openai"), false);
  assert.deepEqual(state.resolvedVaultRefs, []);
  assert.deepEqual(state.writes, []);
});

test("provider upsert fails closed without Rust Agentgres provider-auth materialization record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () =>
      upsertProvider(
        state,
        {
          id: "provider.openai",
          kind: "openai",
          label: "OpenAI",
          api_key_vault_ref: "vault://provider/openai",
          api_format: "openai",
        },
        providerDeps(),
      ),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_provider_auth_materialization_record_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-provider-auth-materializations");
      assert.equal(error.details.record_id, "provider.openai_auth_header");
      assert.equal(error.details.rust_core_boundary, "model_mount.provider_auth_materialization");
      assert.equal(error.details.operation_kind, "model_mount.provider_auth.materialize");
      return true;
    },
  );

  assert.equal(state.modelMountProviderAuthMaterializationRequests.length, 1);
  assert.equal(state.modelMountProviderControlRequests.length, 0);
  assert.deepEqual(state.resolvedVaultRefs, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.providers.has("provider.openai"), false);
});

test("provider upsert rejects retired request aliases before vault resolution or state write", () => {
  const state = fakeState();

  assert.throws(
    () =>
      upsertProvider(
        state,
        {
          id: "provider.openai",
          kind: "openai",
          api_key_vault_ref: "vault://provider/openai",
          authScheme: "api_key",
          authHeaderName: "X-API-Key",
          apiFormat: "openai",
          baseUrl: "https://api.openai.example/v1",
          privacyClass: "hosted_private",
          evidenceRefs: ["operator_provider_config"],
        },
        providerDeps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "provider_upsert_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authScheme",
        "authHeaderName",
        "apiFormat",
        "baseUrl",
        "privacyClass",
        "evidenceRefs",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "auth_scheme",
        "auth_header_name",
        "api_format",
        "base_url",
        "privacy_class",
        "evidence_refs",
      ]);
      return true;
    },
  );
  assert.deepEqual(state.resolvedVaultRefs, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.providers.has("provider.openai"), false);
});

test("provider secret normalization rejects plaintext and preserves existing vault refs", () => {
  const state = fakeState();

  assert.equal(
    normalizeProviderSecretRef(state, "openai", {}, "vault://provider/existing", providerDeps()),
    "vault://provider/existing",
  );
  assert.throws(
    () => normalizeProviderSecretRef(state, "openai", { api_key: "plain" }, null, providerDeps()),
    /Provider secrets and auth headers/,
  );
  assert.equal(normalizeProviderSecretRef(state, "openai", { secret_ref: "" }, null, providerDeps()), null);
});

test("provider health commits Rust provider-lifecycle record without JS driver, receipt, or provider write", async () => {
  const state = fakeState();
  let healthCalls = 0;
  state.providers.set("provider.fixture", {
    id: "provider.fixture",
    kind: "fixture",
    driver: "fixture",
    apiFormat: "ioi_fixture",
    label: "Fixture",
    status: "configured",
    secret_ref: "vault://provider/fixture",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.endpoints.set("endpoint.fixture", {
    id: "endpoint.fixture",
    providerId: "provider.fixture",
    modelId: "local:auto",
    status: "mounted",
  });
  state.endpointProjectionRecords.push({
    id: "endpoint.fixture",
    providerId: "provider.fixture",
    modelId: "local:auto",
    status: "mounted",
  });
  state.drivers.set("provider.fixture", {
    async health() {
      healthCalls += 1;
      return {
        status: "available",
        httpStatus: 200,
        evidenceRefs: ["provider_http_health"],
        authEvidence: {
          vaultRefHash: "vault-hash:provider",
          evidenceRefs: ["VaultPort.resolveVaultRef"],
          headerNames: ["authorization"],
        },
        model_mount_provider_lifecycle: {
          action: "health",
          status: "available",
          lifecycle_hash: "sha256:fixture-health",
          evidence_refs: ["rust_model_mount_provider_lifecycle"],
          execution_backend: "rust_model_mount_fixture_lifecycle",
          backend_id: "backend.fixture",
        },
      };
    },
  });

  const result = await providerHealth(state, "provider.fixture");

  assert.equal(healthCalls, 0);
  assert.equal(state.modelMountLifecycleRequests.length, 1);
  assert.equal(state.modelMountLifecycleRequests[0].schema_version, "ioi.model_mount.provider_lifecycle.v1");
  assert.equal(state.modelMountLifecycleRequests[0].provider_ref, "provider://provider.fixture");
  assert.equal(state.modelMountLifecycleRequests[0].provider_kind, "fixture");
  assert.equal(state.modelMountLifecycleRequests[0].endpoint_ref, "endpoint://endpoint.fixture");
  assert.equal(state.modelMountLifecycleRequests[0].model_ref, "model://local:auto");
  assert.equal(state.modelMountLifecycleRequests[0].action, "health");
  assert.equal(state.modelMountLifecycleRequests[0].execution_backend, "rust_model_mount_fixture_lifecycle");
  assert.equal(result.status, "available");
  assert.equal(result.result.action, "health");
  assert.equal(result.executionBackend, "rust_model_mount_fixture_lifecycle");
  assert.equal(result.operation_kind, "model_mount.provider.health");
  assert.equal(result.rust_core_boundary, "model_mount.provider_lifecycle");
  assert.equal(result.record_dir, "model-provider-lifecycle-controls");
  assert.equal(result.record.object, "ioi.model_mount_provider_lifecycle");
  assert.equal(result.record.rust_core_boundary, "model_mount.provider_lifecycle");
  assert.equal(result.public_response.js_provider_driver_call, false);
  assert.equal(result.commit.record_id, result.record_id);
  assert.equal(result.evidence_refs.includes("rust_model_mount_provider_lifecycle"), true);
  assert.equal(result.evidence_refs.includes("agentgres_provider_lifecycle_truth_required"), true);
  assert.equal(state.providers.get("provider.fixture").status, "configured");
  assert.equal(state.providers.get("provider.fixture").discovery.lastHealthCheck, undefined);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-provider-lifecycle-controls");
  assert.equal(state.recordStateCommits[0].record_id, result.record_id);
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.health");
  assert.equal(state.recordStateCommits[0].record.object, "ioi.model_mount_provider_lifecycle");
  assert.equal(state.recordStateCommits[0].record.rust_core_boundary, "model_mount.provider_lifecycle");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, []);
  assert.equal(state.projections, 0);
});

test("hosted provider health commits Rust metadata lifecycle records without JS driver execution", async () => {
  const state = fakeState();
  let healthCalls = 0;
  state.providers.set("provider.remote", {
    id: "provider.remote",
    kind: "custom_http",
    apiFormat: "openai_compatible",
    driver: "hosted_provider_metadata",
    label: "Remote",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.remote", {
    async health() {
      healthCalls += 1;
      const error = new Error("auth failed");
      error.status = 403;
      error.code = "policy";
      error.details = {
        http_status: 401,
        provider_error_hash: "hash:error",
        adapter: "remote_provider_adapter",
        evidence_refs: ["provider_auth_fail_closed"],
      };
      throw error;
    },
  });

  const result = await providerHealth(state, "provider.remote");

  assert.equal(healthCalls, 0);
  assert.equal(state.modelMountLifecycleRequests.length, 1);
  assert.equal(state.modelMountLifecycleRequests[0].execution_backend, "rust_model_mount_hosted_provider_lifecycle");
  assert.equal(state.modelMountLifecycleRequests[0].endpoint_ref, "endpoint://provider.remote/hosted-metadata");
  assert.equal(state.modelMountLifecycleRequests[0].model_ref, "model://custom_http/hosted-metadata");
  assert.equal(result.status, "available");
  assert.equal(result.executionBackend, "rust_model_mount_hosted_provider_lifecycle");
  assert.equal(result.driver, "hosted_provider_metadata");
  assert.equal(result.public_response.js_provider_driver_call, false);
  assert.equal(result.evidence_refs.includes("rust_model_mount_hosted_provider_lifecycle_backend"), true);
  assert.equal(result.evidence_refs.includes("rust_hosted_provider_metadata_transport_materialized"), true);
  assert.equal(result.evidence_refs.includes("hosted_provider_transport_not_executed"), false);
  assert.equal(result.transport_execution_status, "rust_materialized");
  assert.equal(result.public_response.transport_execution_status, "rust_materialized");
  assert.equal(Object.hasOwn(result.public_response, "command_transport_fallback"), false);
  assert.equal(Object.hasOwn(result.public_response.transport_contract, "command_transport_fallback"), false);
  assert.equal(result.record.transport_execution_owner, "rust_daemon_core.model_mount.provider_lifecycle");
  assert.equal(state.providers.get("provider.remote").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-provider-lifecycle-controls");
  assert.equal(state.recordStateCommits[0].record.rust_core_boundary, "model_mount.provider_lifecycle");
  assert.equal(state.recordStateCommits[0].record.execution_backend, "rust_model_mount_hosted_provider_lifecycle");
  assert.equal(state.projections, 0);
});

test("hosted provider health rejects retired transport fallback proof fields", async () => {
  const state = fakeState();
  const originalPlanProviderLifecycle = state.planModelMountProviderLifecycle.bind(state);
  state.planModelMountProviderLifecycle = function planWithRetiredFallbackField(request) {
    const result = originalPlanProviderLifecycle(request);
    result.public_response.command_transport_fallback = false;
    result.public_response.transport_contract.command_transport_fallback = false;
    result.record.command_transport_fallback = false;
    return result;
  };
  state.providers.set("provider.remote", {
    id: "provider.remote",
    kind: "custom_http",
    apiFormat: "openai_compatible",
    driver: "hosted_provider_metadata",
    label: "Remote",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });

  await assert.rejects(
    () => providerHealth(state, "provider.remote"),
    (error) => {
      assert.equal(error.code, "model_mount_provider_lifecycle_rust_result_required");
      assert.equal(error.details.missing.includes("transport_contract.command_transport_fallback_retired"), true);
      assert.equal(error.details.missing.includes("record.command_transport_fallback_retired"), true);
      assert.equal(error.details.missing.includes("public_response.command_transport_fallback_retired"), true);
      return true;
    },
  );
});

test("provider health requires Rust Agentgres provider-lifecycle record-state commit", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;
  state.providers.set("provider.fixture", {
    id: "provider.fixture",
    kind: "fixture",
    driver: "fixture",
    apiFormat: "ioi_fixture",
    label: "Fixture",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.endpoints.set("endpoint.fixture", {
    id: "endpoint.fixture",
    providerId: "provider.fixture",
    modelId: "local:auto",
    status: "mounted",
  });
  state.endpointProjectionRecords.push({
    id: "endpoint.fixture",
    providerId: "provider.fixture",
    modelId: "local:auto",
    status: "mounted",
  });
  state.drivers.set("provider.fixture", {
    async health() {
      return {
        status: "available",
        evidenceRefs: ["provider_http_health"],
        model_mount_provider_lifecycle: {
          action: "health",
          status: "available",
          lifecycle_hash: "sha256:fixture-health",
          evidence_refs: ["rust_model_mount_provider_lifecycle"],
          execution_backend: "rust_model_mount_fixture_lifecycle",
          backend_id: "backend.fixture",
        },
      };
    },
  });

  await assert.rejects(
    () => providerHealth(state, "provider.fixture"),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_provider_lifecycle_record_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-provider-lifecycle-controls");
      assert.equal(error.details.rust_core_boundary, "model_mount.provider_lifecycle");
      assert.equal(error.details.operation_kind, "model_mount.provider.health");
      assert.equal(error.details.lifecycle_hash, "sha256:provider://provider.fixture:health");
      return true;
    },
  );

  assert.equal(state.modelMountLifecycleRequests.length, 1);
  assert.equal(state.providers.get("provider.fixture").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
});

test("local provider health uses Rust native-local lifecycle planner without JS driver", async () => {
  const state = fakeState();
  let healthCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "configured",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.endpoints.set("endpoint.local", {
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "autopilot:native-fixture",
    status: "mounted",
  });
  state.endpointProjectionRecords.push({
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "autopilot:native-fixture",
    status: "mounted",
  });
  state.drivers.set("provider.local", {
    async health() {
      healthCalls += 1;
      return {
        status: "available",
        evidenceRefs: ["rust_model_mount_provider_lifecycle"],
        lifecycleHash: "sha256:health",
        model_mount_provider_lifecycle: {
          action: "health",
          status: "available",
          lifecycle_hash: "sha256:health",
          evidence_refs: ["rust_model_mount_provider_lifecycle"],
          execution_backend: "rust_model_mount_native_local_lifecycle",
          backend_id: "backend.native",
        },
      };
    },
  });

  const result = await providerHealth(state, "provider.local");

  assert.equal(healthCalls, 0);
  assert.equal(state.modelMountLifecycleRequests.length, 1);
  assert.equal(state.modelMountLifecycleRequests[0].action, "health");
  assert.equal(state.modelMountLifecycleRequests[0].execution_backend, "rust_model_mount_native_local_lifecycle");
  assert.equal(result.status, "available");
  assert.equal(result.executionBackend, "rust_model_mount_native_local_lifecycle");
  assert.equal(result.result.driver, "native_local");
  assert.equal(result.commit.record_id, result.record_id);
  assert.equal(result.record_dir, "model-provider-lifecycle-controls");
  assert.equal(state.providers.get("provider.local").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record.rust_core_boundary, "model_mount.provider_lifecycle");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.health");
  assert.equal(state.projections, 0);
});

test("provider lifecycle ignores map-only endpoints before Rust planning", async () => {
  const state = fakeState();
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "configured",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.endpoints.set("endpoint.map-only", {
    id: "endpoint.map-only",
    providerId: "provider.local",
    modelId: "autopilot:map-only",
    status: "mounted",
  });

  await assert.rejects(
    () => providerHealth(state, "provider.local"),
    (error) => {
      assert.equal(error.code, "model_mount_provider_health_rust_core_required");
      assert.equal(error.details.operation, "provider_health");
      assert.equal(error.details.operation_kind, "model_mount.provider.health");
      assert.deepEqual(error.details.missing, ["endpoint_ref", "model_ref"]);
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      return true;
    },
  );
  assert.deepEqual(state.modelMountLifecycleRequests, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.receipts, []);
});

test("local provider health fails closed when Rust lifecycle planner is unavailable", async () => {
  const state = fakeState();
  delete state.planModelMountProviderLifecycle;
  let healthCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "configured",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.endpoints.set("endpoint.local", {
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "autopilot:native-fixture",
    status: "mounted",
  });
  state.endpointProjectionRecords.push({
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "autopilot:native-fixture",
    status: "mounted",
  });
  state.drivers.set("provider.local", {
    async health() {
      healthCalls += 1;
      return { status: "available" };
    },
  });

  await assert.rejects(
    () => providerHealth(state, "provider.local"),
    (error) =>
      error.code === "model_mount_provider_health_rust_core_required" &&
      error.details.operation === "provider_health" &&
      error.details.rust_core_api === "plan_model_mount_provider_lifecycle" &&
      error.details.provider_id === "provider.local" &&
      Object.hasOwn(error.details, "providerId") === false,
  );
  assert.equal(healthCalls, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
});

test("provider inventory list routes through Rust inventory planner without JS driver or local fallback reads", async () => {
  const state = fakeState();
  let listModelCalls = 0;
  let listLoadedCalls = 0;
  let listArtifactsCalls = 0;
  let listInstancesCalls = 0;
  state.providers.set("provider.test", {
    id: "provider.test",
    kind: "local_folder",
    driver: "fixture",
    apiFormat: "ioi_fixture",
    label: "Fixture",
    status: "available",
    discovery: { evidenceRefs: ["fixture_provider"] },
  });
  state.artifacts.set("artifact.local", { id: "artifact.local", providerId: "provider.test" });
  state.instances.set("instance.local", { id: "instance.local", providerId: "provider.test", status: "loaded" });
  state.listArtifacts = () => {
    listArtifactsCalls += 1;
    return [...state.artifacts.values()];
  };
  state.listInstances = () => {
    listInstancesCalls += 1;
    return [...state.instances.values()];
  };
  state.drivers.set("provider.test", {
    async listModels() {
      listModelCalls += 1;
      return [];
    },
    async listLoaded() {
      listLoadedCalls += 1;
      return [];
    },
  });

  const models = await listProviderModels(state, "provider.test");
  const loaded = await listProviderLoaded(state, "provider.test");

  assert.equal(listModelCalls, 0);
  assert.equal(listLoadedCalls, 0);
  assert.equal(listArtifactsCalls, 0);
  assert.equal(listInstancesCalls, 0);
  assert.equal(state.modelMountInventoryRequests.length, 2);
  assert.equal(state.modelMountInventoryRequests[0].schema_version, "ioi.model_mount.provider_inventory.v1");
  assert.equal(state.modelMountInventoryRequests[0].provider_ref, "provider://provider.test");
  assert.equal(state.modelMountInventoryRequests[0].provider_kind, "local_folder");
  assert.equal(state.modelMountInventoryRequests[0].action, "list_models");
  assert.equal(state.modelMountInventoryRequests[0].execution_backend, "rust_model_mount_fixture_inventory");
  assert.deepEqual(state.modelMountInventoryRequests[0].item_refs, []);
  assert.equal(state.modelMountInventoryRequests[1].action, "list_loaded");
  assert.equal(state.modelMountInventoryRequests[1].execution_backend, "rust_model_mount_fixture_inventory");
  assert.equal(models.status, "listed");
  assert.equal(models.result.action, "list_models");
  assert.equal(models.executionBackend, "rust_model_mount_fixture_inventory");
  assert.deepEqual(models.itemRefs, []);
  assert.equal(models.itemCount, 0);
  assert.equal(models.evidence_refs.includes("rust_model_mount_provider_inventory"), true);
  assert.equal(models.evidence_refs.includes("agentgres_provider_inventory_truth_required"), true);
  assert.equal(models.record_dir, "model-provider-inventory");
  assert.equal(models.record_id.startsWith("provider_inventory_provider_provider.test_list_models_"), true);
  assert.equal(models.record.object, "ioi.model_mount_provider_inventory");
  assert.equal(models.record.rust_core_boundary, "model_mount.provider_inventory");
  assert.equal(models.operation_kind, "model_mount.provider.inventory.list_models");
  assert.equal(models.commit.record_id, models.record_id);
  assert.equal(loaded.status, "listed");
  assert.equal(loaded.result.action, "list_loaded");
  assert.equal(loaded.executionBackend, "rust_model_mount_fixture_inventory");
  assert.equal(loaded.inventory_hash, "sha256:provider://provider.test:list_loaded");
  assert.equal(loaded.record_dir, "model-provider-inventory");
  assert.equal(loaded.operation_kind, "model_mount.provider.inventory.list_loaded");
  assert.equal(Object.hasOwn(models.result, "providerId"), false);
  assert.equal(Object.hasOwn(models.result, "itemRefs"), false);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].record_dir, "model-provider-inventory");
  assert.equal(state.recordStateCommits[0].record_id, models.record_id);
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.inventory.list_models");
  assert.equal(state.recordStateCommits[0].record.object, "ioi.model_mount_provider_inventory");
  assert.equal(state.recordStateCommits[0].record.rust_core_boundary, "model_mount.provider_inventory");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, []);
  assert.equal(state.recordStateCommits[1].record_id, loaded.record_id);
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.provider.inventory.list_loaded");
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("hosted provider inventory commits Rust metadata records without JS driver execution", async () => {
  const state = fakeState();
  let listModelCalls = 0;
  let listLoadedCalls = 0;
  state.providers.set("provider.remote", {
    id: "provider.remote",
    kind: "custom_http",
    label: "Remote",
    status: "available",
    item_refs: ["model://remote/configured"],
    loaded_item_refs: ["model_instance://remote/configured"],
    discovery: { evidenceRefs: ["remote_provider"] },
  });
  state.drivers.set("provider.remote", {
    async listModels() {
      listModelCalls += 1;
      return [];
    },
    async listLoaded() {
      listLoadedCalls += 1;
      return [];
    },
  });

  const models = await listProviderModels(state, "provider.remote");
  const loaded = await listProviderLoaded(state, "provider.remote");

  assert.equal(listModelCalls, 0);
  assert.equal(listLoadedCalls, 0);
  assert.equal(state.modelMountInventoryRequests.length, 2);
  assert.equal(state.modelMountInventoryRequests[0].provider_ref, "provider://provider.remote");
  assert.equal(state.modelMountInventoryRequests[0].provider_kind, "custom_http");
  assert.equal(
    state.modelMountInventoryRequests[0].execution_backend,
    "rust_model_mount_hosted_provider_inventory",
  );
  assert.deepEqual(state.modelMountInventoryRequests[0].item_refs, ["model://remote/configured"]);
  assert.equal(state.modelMountInventoryRequests[1].action, "list_loaded");
  assert.deepEqual(state.modelMountInventoryRequests[1].item_refs, ["model_instance://remote/configured"]);
  assert.equal(models.status, "listed");
  assert.equal(models.executionBackend, "rust_model_mount_hosted_provider_inventory");
  assert.equal(models.result.driver, "hosted_provider_metadata");
  assert.equal(models.itemCount, 1);
  assert.equal(models.record.rust_core_boundary, "model_mount.provider_inventory");
  assert.equal(models.evidence_refs.includes("rust_model_mount_hosted_provider_inventory_backend"), true);
  assert.equal(models.evidence_refs.includes("rust_hosted_provider_metadata_transport_materialized"), true);
  assert.equal(models.evidence_refs.includes("hosted_provider_transport_not_executed"), false);
  assert.equal(models.transport_execution_status, "rust_materialized");
  assert.equal(models.record.transport_execution_owner, "rust_daemon_core.model_mount.provider_inventory");
  assert.equal(Object.hasOwn(models.record, "command_transport_fallback"), false);
  assert.equal(Object.hasOwn(models.record.transport_contract, "command_transport_fallback"), false);
  assert.equal(models.commit.record_id, models.record_id);
  assert.equal(loaded.status, "listed");
  assert.equal(loaded.operation_kind, "model_mount.provider.inventory.list_loaded");
  assert.equal(loaded.evidence_refs.includes("wallet_network_provider_secret_boundary"), true);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].record_dir, "model-provider-inventory");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.inventory.list_models");
  assert.equal(state.recordStateCommits[0].record.driver, "hosted_provider_metadata");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.provider.inventory.list_loaded");
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("hosted provider inventory rejects retired transport fallback proof fields", async () => {
  const state = fakeState();
  const originalPlanProviderInventory = state.planModelMountProviderInventory.bind(state);
  state.planModelMountProviderInventory = function planWithRetiredFallbackField(request) {
    const result = originalPlanProviderInventory(request);
    result.transport_contract.command_transport_fallback = false;
    result.record.command_transport_fallback = false;
    return result;
  };
  state.providers.set("provider.remote", {
    id: "provider.remote",
    kind: "custom_http",
    label: "Remote",
    status: "available",
    item_refs: ["model://remote/configured"],
    loaded_item_refs: ["model_instance://remote/configured"],
    discovery: { evidenceRefs: ["remote_provider"] },
  });

  await assert.rejects(
    () => listProviderModels(state, "provider.remote"),
    (error) => {
      assert.equal(error.code, "model_mount_provider_inventory_rust_result_required");
      assert.equal(error.details.missing.includes("transport_contract.command_transport_fallback_retired"), true);
      assert.equal(error.details.missing.includes("record.command_transport_fallback_retired"), true);
      return true;
    },
  );
});

test("local provider inventory uses Rust native-local inventory planner without JS driver", async () => {
  const state = fakeState();
  let listModelCalls = 0;
  let listLoadedCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "available",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async listModels() {
      listModelCalls += 1;
      return Object.assign([{ id: "artifact.native", providerId: "provider.local" }], {
        model_mount_provider_inventory: {
          action: "list_models",
          status: "listed",
          inventory_hash: "sha256:list-models",
          evidence_refs: ["rust_model_mount_provider_inventory"],
          execution_backend: "rust_model_mount_native_local_inventory",
          item_count: 1,
        },
      });
    },
    async listLoaded() {
      listLoadedCalls += 1;
      return Object.assign([{ id: "instance.native", providerId: "provider.local", status: "loaded" }], {
        model_mount_provider_inventory: {
          action: "list_loaded",
          status: "listed",
          inventory_hash: "sha256:list-loaded",
          evidence_refs: ["rust_model_mount_provider_inventory"],
          execution_backend: "rust_model_mount_native_local_inventory",
          item_count: 1,
        },
      });
    },
  });

  const models = await listProviderModels(state, "provider.local");
  const loaded = await listProviderLoaded(state, "provider.local");

  assert.equal(listModelCalls, 0);
  assert.equal(listLoadedCalls, 0);
  assert.equal(state.modelMountInventoryRequests.length, 2);
  assert.equal(state.modelMountInventoryRequests[0].action, "list_models");
  assert.equal(state.modelMountInventoryRequests[0].execution_backend, "rust_model_mount_native_local_inventory");
  assert.equal(state.modelMountInventoryRequests[1].action, "list_loaded");
  assert.equal(state.modelMountInventoryRequests[1].execution_backend, "rust_model_mount_native_local_inventory");
  assert.equal(models.status, "listed");
  assert.equal(models.executionBackend, "rust_model_mount_native_local_inventory");
  assert.equal(models.result.driver, "native_local");
  assert.equal(loaded.status, "listed");
  assert.equal(loaded.result.action, "list_loaded");
  assert.equal(loaded.evidence_refs.includes("rust_model_mount_native_local_inventory_backend"), true);
  assert.equal(loaded.record.object, "ioi.model_mount_provider_inventory");
  assert.equal(loaded.record.rust_core_boundary, "model_mount.provider_inventory");
  assert.equal(loaded.commit.record_id, loaded.record_id);
  assert.equal(state.artifacts.has("artifact.native"), false);
  assert.equal(state.instances.has("instance.native"), false);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].record_dir, "model-provider-inventory");
  assert.equal(state.recordStateCommits[0].record.rust_core_boundary, "model_mount.provider_inventory");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.provider.inventory.list_loaded");
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.projections, 0);
});

test("local provider inventory fails closed when Rust inventory planner is unavailable", async () => {
  const state = fakeState();
  delete state.planModelMountProviderInventory;
  let listModelCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "available",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async listModels() {
      listModelCalls += 1;
      return [{ id: "artifact.native", providerId: "provider.local" }];
    },
  });

  await assert.rejects(
    () => listProviderModels(state, "provider.local"),
    (error) =>
      error.code === "model_mount_provider_inventory_rust_core_required" &&
      error.details.rust_core_boundary === "model_mount.provider_inventory" &&
      error.details.operation === "provider_models_list" &&
      error.details.operation_kind === "model_mount.provider.inventory.list_models" &&
      error.details.rust_core_api === "plan_model_mount_provider_inventory" &&
      Object.hasOwn(error.details, "providerId") === false,
  );

  assert.equal(listModelCalls, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("provider inventory facade requires Rust Agentgres provider-inventory record-state commit", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;
  let listModelCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "available",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async listModels() {
      listModelCalls += 1;
      return Object.assign([{ id: "artifact.native", providerId: "provider.local", modelId: "native" }], {
        model_mount_provider_inventory: {
          action: "list_models",
          status: "listed",
          inventory_hash: "sha256:list-models",
          evidence_refs: ["rust_model_mount_provider_inventory"],
          execution_backend: "rust_model_mount_native_local_inventory",
          item_count: 1,
        },
      });
    },
  });

  await assert.rejects(
    () => listProviderModels(state, "provider.local"),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_provider_inventory_record_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-provider-inventory");
      assert.equal(error.details.rust_core_boundary, "model_mount.provider_inventory");
      assert.equal(error.details.operation_kind, "model_mount.provider.inventory.list_models");
      assert.equal(error.details.inventory_hash, "sha256:provider://provider.local:list_models");
      return true;
    },
  );

  assert.equal(listModelCalls, 0);
  assert.equal(state.artifacts.has("artifact.native"), false);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
});

test("hosted provider start and stop commit Rust metadata lifecycle records without JS driver execution", async () => {
  const state = fakeState();
  let startCalls = 0;
  let stopCalls = 0;
  state.providers.set("provider.custom", {
    id: "provider.custom",
    kind: "custom_http",
    apiFormat: "openai_compatible",
    driver: "hosted_provider_metadata",
    label: "Custom",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.custom", {
    async start() {
      startCalls += 1;
      return { status: "available" };
    },
    async stop() {
      stopCalls += 1;
      return { status: "stopped" };
    },
  });

  const startResult = await startProvider(state, "provider.custom");
  const stopResult = await stopProvider(state, "provider.custom");

  assert.equal(startCalls, 0);
  assert.equal(stopCalls, 0);
  assert.deepEqual(
    state.modelMountLifecycleRequests.map((request) => request.execution_backend),
    ["rust_model_mount_hosted_provider_lifecycle", "rust_model_mount_hosted_provider_lifecycle"],
  );
  assert.deepEqual(
    state.modelMountLifecycleRequests.map((request) => request.action),
    ["load", "unload"],
  );
  assert.equal(startResult.status, "loaded");
  assert.equal(stopResult.status, "unloaded");
  assert.equal(startResult.executionBackend, "rust_model_mount_hosted_provider_lifecycle");
  assert.equal(stopResult.executionBackend, "rust_model_mount_hosted_provider_lifecycle");
  assert.equal(startResult.public_response.js_provider_driver_call, false);
  assert.equal(stopResult.public_response.js_provider_driver_call, false);
  assert.equal(startResult.evidence_refs.includes("rust_model_mount_hosted_provider_lifecycle_backend"), true);
  assert.equal(stopResult.evidence_refs.includes("rust_hosted_provider_metadata_transport_materialized"), true);
  assert.equal(stopResult.evidence_refs.includes("hosted_provider_transport_not_executed"), false);
  assert.equal(stopResult.transport_execution_status, "rust_materialized");
  assert.equal(Object.hasOwn(stopResult.public_response, "binary_bridge_fallback"), false);
  assert.equal(Object.hasOwn(stopResult.public_response.transport_contract, "binary_bridge_fallback"), false);
  assert.equal(state.providers.get("provider.custom").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, 2);
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.record.execution_backend),
    ["rust_model_mount_hosted_provider_lifecycle", "rust_model_mount_hosted_provider_lifecycle"],
  );
  assert.deepEqual(state.writes, []);
});

test("local provider start and stop commit Rust native-local provider-lifecycle records", async () => {
  const state = fakeState();
  let startCalls = 0;
  let stopCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "configured",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.endpoints.set("endpoint.local", {
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "autopilot:native-fixture",
    status: "mounted",
  });
  state.endpointProjectionRecords.push({
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "autopilot:native-fixture",
    status: "mounted",
  });
  state.drivers.set("provider.local", {
    async start() {
      startCalls += 1;
      return { status: "available" };
    },
    async stop() {
      stopCalls += 1;
      return { status: "stopped" };
    },
  });

  const startResult = await startProvider(state, "provider.local");
  const stopResult = await stopProvider(state, "provider.local");

  assert.equal(startCalls, 0);
  assert.equal(stopCalls, 0);
  assert.equal(state.modelMountLifecycleRequests.length, 2);
  assert.deepEqual(
    state.modelMountLifecycleRequests.map((request) => request.action),
    ["load", "unload"],
  );
  assert.deepEqual(
    state.modelMountLifecycleRequests.map((request) => request.execution_backend),
    ["rust_model_mount_native_local_lifecycle", "rust_model_mount_native_local_lifecycle"],
  );
  assert.equal(startResult.status, "loaded");
  assert.equal(startResult.result.action, "load");
  assert.equal(startResult.operation_kind, "model_mount.provider.start");
  assert.equal(startResult.rust_core_boundary, "model_mount.provider_lifecycle");
  assert.equal(startResult.record_dir, "model-provider-lifecycle-controls");
  assert.equal(startResult.commit.record_id, startResult.record_id);
  assert.equal(stopResult.status, "unloaded");
  assert.equal(stopResult.result.action, "unload");
  assert.equal(stopResult.operation_kind, "model_mount.provider.stop");
  assert.equal(stopResult.commit.record_id, stopResult.record_id);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].record_dir, "model-provider-lifecycle-controls");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.start");
  assert.equal(state.recordStateCommits[0].record.rust_core_boundary, "model_mount.provider_lifecycle");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.provider.stop");
});
