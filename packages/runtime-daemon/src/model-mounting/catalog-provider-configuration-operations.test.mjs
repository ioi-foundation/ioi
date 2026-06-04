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
  const state = {
    calls,
    receipts,
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

test("catalog provider configuration operations list, get, and configure public records", () => {
  const state = createState();

  const configured = configureCatalogProvider(state, "catalog.custom_http", {
    base_url: "https://catalog.example.test/",
  });

  assert.equal(configured.id, "catalog.custom_http");
  assert.equal(configured.enabled, true);
  assert.equal(configured.baseUrlHash !== null, true);
  assert.equal(configured.runtimeMaterialStatus, "bound_runtime_session");
  assert.equal(configured.receiptId, "receipt-1");
  assert.equal(configured.provider.id, "catalog.custom_http");
  assert.equal(catalogProviderConfig(state, "catalog.custom_http").id, "catalog.custom_http");
  assert.equal(state.catalogProviderRuntimeMaterials.get("catalog.custom_http").baseUrl, "https://catalog.example.test");
  assert.equal(
    state.calls.some((call) => call.name === "writeMap" && call.mapName === "model-catalog-providers"),
    true,
  );
  assert.equal(state.calls.some((call) => call.name === "writeProjection"), true);

  const listed = listCatalogProviderConfigs(state).find((record) => record.id === "catalog.custom_http");
  assert.equal(listed.runtimeMaterialStatus, "bound_runtime_session");

  const fetched = getCatalogProviderConfig(state, "catalog.custom_http");
  assert.equal(fetched.provider.adapterPort, "ModelCatalogProviderPort");
  assert.throws(() => getCatalogProviderConfig(state, "catalog.fixture"), /not configurable/);
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
