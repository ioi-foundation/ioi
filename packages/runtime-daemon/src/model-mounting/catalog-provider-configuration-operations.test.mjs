import assert from "node:assert/strict";
import test from "node:test";

import {
  catalogProviderConfig,
  catalogProviderRuntimeMaterial,
  configureCatalogProvider,
  getCatalogProviderConfig,
  listCatalogProviderConfigs,
} from "./catalog-provider-configuration-operations.mjs";
import { catalogProviderMaterialVaultRef } from "./catalog-provider-config.mjs";

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
  state.catalogProviderRuntimeMaterial = (providerId) => catalogProviderRuntimeMaterial(state, providerId);
  return state;
}

test("catalog provider configuration operations list and get public records", () => {
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

  const listed = listCatalogProviderConfigs(state).find((record) => record.id === "catalog.custom_http");
  assert.equal(listed.runtimeMaterialStatus, "bound_runtime_session");

  const fetched = getCatalogProviderConfig(state, "catalog.custom_http");
  assert.equal(fetched.provider.adapterPort, "ModelCatalogProviderPort");
  assert.throws(() => getCatalogProviderConfig(state, "catalog.fixture"), /not configurable/);
});

test("catalog provider configuration mutation facade fails closed until Rust core owns catalog provider control", () => {
  const state = createState();

  assert.throws(
    () =>
      configureCatalogProvider(state, "catalog.custom_http", {
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

test("catalog provider runtime material resolves vault material and preserves fail-closed states", () => {
  const state = createState();
  const providerId = "catalog.custom_http";
  state.catalogProviderConfigs.set(providerId, {
    id: providerId,
    materialConfigured: true,
    materialVaultRefHash: "known-material-hash",
  });

  const resolved = catalogProviderRuntimeMaterial(state, providerId);
  assert.equal(resolved.baseUrl, "https://catalog.example.test");
  assert.equal(resolved.runtimeMaterialStatus, "resolved_from_vault");
  assert.equal(resolved.materialVaultRefHash, `hash:${catalogProviderMaterialVaultRef(providerId)}`);
  assert.equal(state.calls.some((call) => call.name === "writeVaultRefs"), true);

  state.catalogProviderRuntimeMaterials.delete(providerId);
  state.vault.resolveVaultRef = (vaultRef) => ({
    resolvedMaterial: false,
    material: "",
    materialSource: "unbound",
    vaultRefHash: `hash:${vaultRef}`,
    evidenceRefs: ["VaultPort.resolveVaultRef"],
  });
  const missing = catalogProviderRuntimeMaterial(state, providerId);
  assert.equal(missing.runtimeMaterialStatus, "missing_runtime_material");
  assert.equal(missing.materialSource, "unbound");

  state.catalogProviderRuntimeMaterials.delete(providerId);
  state.vault.resolveVaultRef = () => {
    throw new Error("keychain unavailable");
  };
  const failed = catalogProviderRuntimeMaterial(state, providerId);
  assert.equal(failed.runtimeMaterialStatus, "vault_material_unavailable");
  assert.equal(failed.materialVaultRefHash, "known-material-hash");
  assert.deepEqual(failed.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_provider_source_material_fail_closed"]);
});
