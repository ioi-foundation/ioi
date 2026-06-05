import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import {
  assertConfigurableCatalogProvider,
  catalogProviderAuthHeaders,
  catalogProviderConfigUpdate,
  catalogProviderMaterialVaultRef,
  catalogProviderRuntimeMaterialFromValue,
  normalizeCatalogAuthScheme,
} from "./catalog-provider-config.mjs";

function createState() {
  const bound = [];
  let writeVaultRefsCount = 0;
  return {
    bound,
    catalogProviderRuntimeMaterials: new Map(),
    oauthSessions: new Map(),
    catalogProviderConfigs: new Map(),
    walletAuthority: {
      resolveVaultRef(vaultRef) {
        return { vaultRefHash: `hash:${vaultRef}` };
      },
    },
    vault: {
      bindVaultRef(record) {
        bound.push(record);
        return {
          vaultRefHash: `hash:${record.vaultRef}`,
          materialSource: "runtime_memory",
          evidenceRefs: ["VaultPort.bindVaultRef"],
        };
      },
      resolveVaultRef(vaultRef, purpose) {
        return {
          vaultRefHash: `hash:${vaultRef}`,
          material: `material:${purpose}`,
          evidenceRefs: ["VaultPort.resolveVaultRef"],
        };
      },
    },
    writeVaultRefs() {
      writeVaultRefsCount += 1;
    },
    writeVaultRefsCount() {
      return writeVaultRefsCount;
    },
  };
}

test("catalog provider config updates bind source material to vault refs", () => {
  const state = createState();
  const update = catalogProviderConfigUpdate(
    "catalog.custom_http",
    {
      base_url: "https://catalog.example.test/",
      auth_vault_ref: "vault://catalog/auth",
      auth_header_name: "X-Catalog-Key",
    },
    null,
    "2026-06-03T12:00:00.000Z",
    state,
  );

  assert.equal(update.record.id, "catalog.custom_http");
  assert.equal(update.record.enabled, true);
  assert.equal(update.record.catalogAuthConfigured, true);
  assert.equal(update.record.catalogAuthHeaderName, "x-catalog-key");
  assert.equal(update.record.materialPersistence, "runtime_vault_binding");
  assert.equal(update.runtimeMaterial.baseUrl, "https://catalog.example.test");
  assert.equal(update.runtimeMaterial.runtimeMaterialStatus, "bound_runtime_session");
  assert.equal(state.bound[0].vaultRef, catalogProviderMaterialVaultRef("catalog.custom_http"));
  assert.equal(state.bound[0].material, "https://catalog.example.test");
  assert.equal(state.writeVaultRefsCount(), 1);
});

test("catalog provider auth headers resolve vault material without plaintext persistence", async () => {
  const state = createState();
  state.catalogProviderConfig = () => ({
    id: "catalog.custom_http",
    authVaultRef: "vault://catalog/auth",
    catalogAuthScheme: "api_key",
    catalogAuthHeaderName: "X-Catalog-Key",
  });

  const auth = await catalogProviderAuthHeaders("catalog.custom_http", state);

  assert.deepEqual(auth.headers, {
    "x-catalog-key": "material:catalog.auth:catalog.custom_http",
  });
  assert.equal(auth.evidence.authVaultRefHash, "hash:vault://catalog/auth");
  assert.equal(auth.evidence.resolvedMaterial, true);
  assert.deepEqual(auth.evidence.headerNames, ["x-catalog-key"]);
  assert.equal(state.writeVaultRefsCount(), 1);

  state.catalogProviderConfig = () => ({
    id: "catalog.custom_http",
    authVaultRefHash: "hash:vault://catalog/auth",
    catalogAuthScheme: "api_key",
    catalogAuthHeaderName: "X-Catalog-Key",
  });
  await assert.rejects(
    () => catalogProviderAuthHeaders("catalog.custom_http", state),
    (error) => {
      assert.match(error.message, /configured by hash only/);
      assert.equal(error.details.catalog_provider_id, "catalog.custom_http");
      assert.equal(error.details.auth_vault_ref_hash, "hash:vault://catalog/auth");
      assert.equal(error.details.resolved_material, false);
      assert.deepEqual(error.details.evidence_refs, ["catalog_auth_fail_closed", "vault_ref_required"]);
      assert.equal(Object.hasOwn(error.details, "catalogProviderId"), false);
      assert.equal(Object.hasOwn(error.details, "authVaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "resolvedMaterial"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );

  state.catalogProviderConfig = () => ({
    id: "catalog.custom_http",
    authVaultRef: "vault://catalog/missing-auth",
    authVaultRefHash: "hash:vault://catalog/missing-auth",
    catalogAuthScheme: "api_key",
    catalogAuthHeaderName: "X-Catalog-Key",
  });
  state.vault.resolveVaultRef = () => ({
    vaultRefHash: "hash:vault://catalog/missing-auth",
    resolvedMaterial: false,
    evidenceRefs: ["VaultPort.resolveVaultRef"],
  });
  await assert.rejects(
    () => catalogProviderAuthHeaders("catalog.custom_http", state),
    (error) => {
      assert.match(error.message, /no runtime vault material/);
      assert.equal(error.details.catalog_provider_id, "catalog.custom_http");
      assert.equal(error.details.auth_vault_ref_hash, "hash:vault://catalog/missing-auth");
      assert.equal(error.details.resolved_material, false);
      assert.equal(error.details.catalog_auth_scheme, "api_key");
      assert.equal(typeof error.details.catalog_auth_header_name_hash, "string");
      assert.deepEqual(error.details.evidence_refs, ["VaultPort.resolveVaultRef"]);
      assert.equal(Object.hasOwn(error.details, "catalogProviderId"), false);
      assert.equal(Object.hasOwn(error.details, "authVaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "resolvedMaterial"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthHeaderNameHash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
});

test("catalog provider auth supports OAuth session refresh projections", async () => {
  const state = createState();
  const refreshedSession = {
    id: "session-1",
    status: "active",
    scopes: ["read"],
    evidenceRefs: ["VaultOAuthSession"],
  };
  state.oauthSessions.set("session-1", { id: "session-1", status: "active" });
  state.catalogProviderConfigs.set("catalog.huggingface", {
    id: "catalog.huggingface",
    oauthSessionId: "session-1",
    catalogAuthScheme: "oauth2",
    catalogAuthHeaderName: "authorization",
  });
  state.catalogProviderConfig = () => state.catalogProviderConfigs.get("catalog.huggingface");
  const writes = [];
  state.writeMap = (name, value) => writes.push([name, value]);
  state.nowIso = () => "2026-06-03T12:00:00.000Z";
  state.oauthCredentialProvider = {
    async resolveAccessHeader(session, { headerName }) {
      assert.equal(session.id, "session-1");
      assert.equal(headerName, "authorization");
      return {
        refreshed: true,
        session: refreshedSession,
        headerValue: "Bearer refreshed",
        evidence: { oauthSessionHash: "hash-session", resolvedMaterial: true },
      };
    },
  };

  const auth = await catalogProviderAuthHeaders("catalog.huggingface", state);

  assert.deepEqual(auth.headers, { authorization: "Bearer refreshed" });
  assert.equal(state.oauthSessions.get("session-1"), refreshedSession);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthBoundary.status, "refreshed");
  assert.deepEqual(writes.map(([name]) => name), ["oauth-sessions", "model-catalog-providers"]);
  assert.equal(state.writeVaultRefsCount(), 1);
});

test("catalog provider config validates provider ids and auth schemes", () => {
  assert.doesNotThrow(() => assertConfigurableCatalogProvider("catalog.huggingface"));
  assert.throws(
    () => assertConfigurableCatalogProvider("catalog.fixture"),
    (error) => {
      assert.match(error.message, /not configurable/);
      assert.equal(error.details.provider_id, "catalog.fixture");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      return true;
    },
  );
  assert.equal(normalizeCatalogAuthScheme("api-key"), "api_key");
  assert.throws(
    () => normalizeCatalogAuthScheme("digest"),
    (error) => {
      assert.match(error.message, /bearer, raw, api_key, or oauth2/);
      assert.equal(error.details.auth_scheme, "digest");
      assert.equal(Object.hasOwn(error.details, "authScheme"), false);
      return true;
    },
  );
  assert.equal(
    catalogProviderRuntimeMaterialFromValue("catalog.local_manifest", "./manifest.json").manifestPath,
    path.resolve("./manifest.json"),
  );
});
