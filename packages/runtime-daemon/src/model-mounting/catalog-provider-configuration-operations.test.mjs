import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function createState() {
  const calls = [];
  const receipts = [];
  const recordStateCommits = [];
  const state = {
    calls,
    receipts,
    recordStateCommits,
    catalogProviderConfigs: new Map(),
    catalogProviderRuntimeMaterials: new Map(),
    catalogProviderRuntimeMaterialCalls: 0,
    catalogProviderPorts() {
      calls.push({ name: "catalogProviderPorts" });
      return [
        {
          id: "catalog.custom_http",
          label: "Custom HTTP",
          status: "configured",
          formats: ["gguf"],
        },
      ];
    },
    nowIso() {
      return "2026-06-04T12:00:00.000Z";
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt-${receipts.length + 1}`, kind, ...payload };
      receipts.push(receipt);
      return receipt;
    },
    vault: {
      bindVaultRef(record) {
        calls.push({ name: "bindVaultRef", record });
        return {
          vaultRefHash: `hash:${record.vaultRef}`,
          materialSource: "runtime_memory",
          evidenceRefs: ["VaultPort.bindVaultRef"],
        };
      },
      resolveVaultRef(vaultRef, purpose) {
        calls.push({ name: "resolveVaultRef", vaultRef, purpose });
        return {
          resolvedMaterial: true,
          material: "https://catalog.example.test",
          materialSource: "vault_material_adapter",
          vaultRefHash: `hash:${vaultRef}`,
          evidenceRefs: ["VaultPort.resolveVaultRef"],
        };
      },
    },
    walletAuthority: {
      resolveVaultRef(vaultRef) {
        return { vaultRefHash: `hash:${vaultRef}` };
      },
    },
    writeMap(name, map) {
      calls.push({ name: "writeMap", mapName: name, size: map.size });
    },
    commitRuntimeModelMountRecordState(request) {
      recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.record_id}`,
        admission_hash: `sha256:admission:${request.record_id}`,
        commit_hash: `sha256:commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.record_id}`,
          },
        },
      };
    },
    writeProjection() {
      calls.push({ name: "writeProjection" });
    },
    writeVaultRefs() {
      calls.push({ name: "writeVaultRefs" });
    },
  };
  state.catalogProviderRuntimeMaterial = (providerId) => {
    state.catalogProviderRuntimeMaterialCalls += 1;
    return ModelMountingState.prototype.catalogProviderRuntimeMaterial.call(state, providerId);
  };
  return state;
}

test("catalog provider configuration list/get fail closed before JS public projection", () => {
  const state = createState();

  state.catalogProviderConfigs.set("catalog.custom_http", {
    id: "catalog.custom_http",
    enabled: true,
    baseUrlHash: "hash:base-url",
    updatedAt: state.nowIso(),
  });
  state.catalogProviderRuntimeMaterials.set("catalog.custom_http", {
    baseUrl: "https://catalog.example.test",
    runtimeMaterialStatus: "bound_runtime_session",
  });

  assert.throws(
    () => ModelMountingState.prototype.listCatalogProviderConfigs.call(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_configuration.list");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
      assert.equal(error.details.configurable_provider_count, 3);
      assert.deepEqual(error.details.evidence_refs, [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "configurableProviderCount"), false);
      return true;
    },
  );

  assert.throws(
    () => ModelMountingState.prototype.getCatalogProviderConfig.call(state, "catalog.custom_http"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_configuration.get");
      assert.equal(error.details.provider_id, "catalog.custom_http");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      return true;
    },
  );

  assert.throws(
    () => ModelMountingState.prototype.getCatalogProviderConfig.call(state, "catalog.fixture"),
    /not configurable/,
  );
  assert.equal(state.catalogProviderRuntimeMaterialCalls, 0);
  assert.equal(state.calls.some((call) => call.name === "catalogProviderPorts"), false);
  assert.equal(state.calls.some((call) => call.name === "writeMap"), false);
  assert.equal(state.calls.some((call) => call.name === "writeProjection"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("catalog provider configuration mutation facade fails closed until Rust core owns catalog provider control", () => {
  const state = createState();

  assert.throws(
    () =>
      ModelMountingState.prototype.configureCatalogProvider.call(state, "catalog.custom_http", {
        base_url: "https://catalog.example.test/",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_configuration.write");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
      assert.equal(error.details.provider_id, "catalog.custom_http");
      assert.deepEqual(error.details.evidence_refs, [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      return true;
    },
  );

  assert.equal(state.catalogProviderConfigs.has("catalog.custom_http"), false);
  assert.equal(state.catalogProviderRuntimeMaterials.has("catalog.custom_http"), false);
  assert.equal(state.calls.some((call) => call.name === "writeMap"), false);
  assert.equal(state.calls.some((call) => call.name === "writeProjection"), false);
  assert.equal(state.calls.some((call) => call.name === "bindVaultRef"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("catalog provider runtime material fails closed before JS vault resolution", () => {
  const state = createState();
  const providerId = "catalog.custom_http";
  let resolveCount = 0;
  let sourceMaterialProbeCount = 0;
  state.vault.resolveVaultRef = () => {
    resolveCount += 1;
    throw new Error("catalog source vault resolution should not run in JS");
  };
  state.catalogProviderConfigs.set(providerId, {
    id: providerId,
    materialConfigured: true,
    materialVaultRefHash: "known-material-hash",
  });

  assert.throws(
    () => ModelMountingState.prototype.catalogProviderRuntimeMaterial.call(state, providerId),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_runtime_material.resolve");
      assert.equal(error.details.provider_id, providerId);
      assert.equal(error.details.material_vault_ref_hash, null);
      assert.equal(error.details.material_configured, false);
      assert.equal(error.details.runtime_material_status, "rust_core_projection_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
      assert.deepEqual(error.details.evidence_refs, [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "materialVaultRefHash"), false);
      return true;
    },
  );
  assert.equal(resolveCount, 0);
  assert.equal(sourceMaterialProbeCount, 0);
  assert.equal(state.catalogProviderRuntimeMaterials.has(providerId), false);
  assert.equal(state.calls.some((call) => call.name === "resolveVaultRef"), false);
  assert.equal(state.calls.some((call) => call.name === "writeMap"), false);
  assert.equal(state.calls.some((call) => call.name === "writeProjection"), false);
  assert.equal(state.calls.some((call) => call.name === "writeVaultRefs"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);

  state.catalogProviderRuntimeMaterials.set(providerId, {
    baseUrl: "https://catalog.example.test",
    runtimeMaterialStatus: "bound_runtime_session",
    materialVaultRefHash: "hash-materialized",
  });
  assert.throws(
    () =>
      ModelMountingState.prototype.catalogProviderRuntimeMaterial.call(state, providerId),
    (error) => {
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_runtime_material.resolve");
      assert.equal(error.details.provider_id, providerId);
      assert.equal(error.details.material_vault_ref_hash, "hash-materialized");
      assert.equal(error.details.material_configured, true);
      assert.equal(error.details.runtime_material_status, "bound_runtime_session");
      return true;
    },
  );
  assert.equal(sourceMaterialProbeCount, 0);

  state.catalogProviderRuntimeMaterials.set(providerId, {
    runtimeMaterialStatus: "missing_runtime_material",
  });
  assert.throws(
    () => ModelMountingState.prototype.catalogProviderRuntimeMaterial.call(state, providerId),
    (error) => {
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.runtime_material_status, "missing_runtime_material");
      return true;
    },
  );
  assert.equal(resolveCount, 0);
});

test("private catalog provider config readback fails closed before JS map projection", () => {
  const state = createState();
  const providerId = "catalog.custom_http";
  state.catalogProviderConfigs.set(providerId, {
    id: providerId,
    enabled: true,
    materialConfigured: true,
    authVaultRefHash: "hash:vault://catalog/auth",
  });

  assert.throws(
    () => ModelMountingState.prototype.catalogProviderConfig.call(state, providerId),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_configuration.read_private");
      assert.equal(error.details.provider_id, providerId);
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
      assert.deepEqual(error.details.evidence_refs, [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      return true;
    },
  );
  assert.equal(state.calls.some((call) => call.name === "writeMap"), false);
  assert.equal(state.calls.some((call) => call.name === "writeProjection"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});
