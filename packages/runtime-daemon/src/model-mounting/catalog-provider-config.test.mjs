import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import {
  assertConfigurableCatalogProvider,
  catalogProviderAuthConfig,
  catalogProviderAuthHeaders,
  catalogProviderConfigUpdate,
  catalogProviderMaterialVaultRef,
  catalogProviderRuntimeMaterialFromBody,
  catalogProviderRuntimeMaterialFromValue,
  normalizeCatalogAuthScheme,
} from "./catalog-provider-config.mjs";

function createState() {
  const bound = [];
  const recordStateCommits = [];
  let writeVaultRefsCount = 0;
  return {
    bound,
    recordStateCommits,
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
    commitRuntimeModelMountRecordState(request) {
      recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
        admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
      };
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

test("catalog provider source request aliases fail closed before vault binding", () => {
  const state = createState();

  assert.throws(
    () =>
      catalogProviderConfigUpdate(
        "catalog.local_manifest",
        { manifestPath: "./manifest.json" },
        null,
        "2026-06-03T12:00:00.000Z",
        state,
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_provider_source_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["manifestPath"]);
      assert.deepEqual(error.details.canonical_fields, ["manifest_path", "base_url"]);
      return true;
    },
  );
  assert.equal(state.bound.length, 0);
  assert.equal(state.writeVaultRefsCount(), 0);

  assert.throws(
    () =>
      catalogProviderRuntimeMaterialFromBody("catalog.custom_http", {
        baseUrl: "https://catalog.example.test",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_provider_source_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["baseUrl"]);
      assert.deepEqual(error.details.canonical_fields, ["manifest_path", "base_url"]);
      return true;
    },
  );
});

test("catalog provider auth request aliases fail closed before source or auth binding", () => {
  const state = createState();
  let authResolveCount = 0;
  state.walletAuthority.resolveVaultRef = (vaultRef) => {
    authResolveCount += 1;
    return { vaultRefHash: `hash:${vaultRef}` };
  };

  assert.throws(
    () =>
      catalogProviderConfigUpdate(
        "catalog.custom_http",
        {
          base_url: "https://catalog.example.test/",
          authVaultRef: "vault://catalog/auth",
          vault_ref: "vault://catalog/auth-alt",
          vaultRef: "vault://catalog/auth-alt-2",
          api_key_vault_ref: "vault://catalog/api-key",
          apiKeyVaultRef: "vault://catalog/api-key-2",
          authScheme: "api_key",
          authHeaderName: "X-Catalog-Key",
          oauthSessionId: "session-1",
        },
        null,
        "2026-06-03T12:00:00.000Z",
        state,
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_provider_auth_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authVaultRef",
        "vault_ref",
        "vaultRef",
        "api_key_vault_ref",
        "apiKeyVaultRef",
        "authScheme",
        "authHeaderName",
        "oauthSessionId",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "auth_vault_ref",
        "auth_scheme",
        "auth_header_name",
        "oauth_session_id",
      ]);
      return true;
    },
  );
  assert.equal(state.bound.length, 0);
  assert.equal(state.writeVaultRefsCount(), 0);
  assert.equal(authResolveCount, 0);

  assert.throws(
    () => catalogProviderAuthConfig("catalog.custom_http", { authHeaderName: "X-Catalog-Key" }, null, state),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_provider_auth_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["authHeaderName"]);
      return true;
    },
  );
  assert.equal(authResolveCount, 0);
});

test("catalog provider auth config accepts canonical request fields", () => {
  const state = createState();
  state.oauthSessions.set("session-1", {
    id: "session-1",
    status: "active",
    scopes: ["read"],
  });

  const auth = catalogProviderAuthConfig(
    "catalog.huggingface",
    {
      auth_vault_ref: "vault://catalog/auth",
      auth_scheme: "oauth2",
      auth_header_name: "X-Catalog-Key",
      oauth_session_id: "session-1",
    },
    null,
    state,
  );

  assert.equal(auth.authVaultRef, "vault://catalog/auth");
  assert.equal(auth.authVaultRefHash, "hash:vault://catalog/auth");
  assert.equal(auth.catalogAuthConfigured, true);
  assert.equal(auth.catalogAuthScheme, "oauth2");
  assert.equal(auth.catalogAuthHeaderName, "x-catalog-key");
  assert.equal(auth.oauthSessionId, "session-1");
  assert.equal(typeof auth.oauthSessionHash, "string");
  assert.equal(auth.oauthBoundary.status, "active");
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
  assert.deepEqual(state.oauthSessions.get("session-1"), {
    ...refreshedSession,
    providerId: "catalog.huggingface",
  });
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthBoundary.status, "refreshed");
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "oauth-sessions");
  assert.equal(state.recordStateCommits[0].record_id, "session-1");
  assert.equal(
    state.recordStateCommits[0].operation_kind,
    "model_mount.oauth_session.auth_header_refresh",
  );
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, []);
  assert.equal(state.recordStateCommits[1].record_dir, "model-catalog-providers");
  assert.equal(state.recordStateCommits[1].record_id, "catalog.huggingface");
  assert.equal(
    state.recordStateCommits[1].operation_kind,
    "model_mount.catalog_provider_auth_header.refresh",
  );
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, []);
  assert.equal(state.writeVaultRefsCount(), 1);
});

test("catalog provider auth refresh fails closed before provider config mutation without Rust Agentgres record-state commit", async () => {
  const state = createState();
  delete state.commitRuntimeModelMountRecordState;
  state.oauthSessions.set("session-1", { id: "session-1", status: "active" });
  state.catalogProviderConfigs.set("catalog.huggingface", {
    id: "catalog.huggingface",
    oauthSessionId: "session-1",
    catalogAuthScheme: "oauth2",
    catalogAuthHeaderName: "authorization",
  });
  state.catalogProviderConfig = () => state.catalogProviderConfigs.get("catalog.huggingface");
  state.nowIso = () => "2026-06-03T12:00:00.000Z";
  state.oauthCredentialProvider = {
    async resolveAccessHeader() {
      return {
        refreshed: true,
        session: { id: "session-1", status: "active", refreshCount: 1 },
        headerValue: "Bearer refreshed",
        evidence: { oauthSessionHash: "hash-session", resolvedMaterial: true },
      };
    },
  };

  await assert.rejects(
    () => catalogProviderAuthHeaders("catalog.huggingface", state),
    (error) => {
      assert.equal(error.code, "model_mount_oauth_session_commit_unconfigured");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.record_dir, "oauth-sessions");
      return true;
    },
  );

  assert.equal(state.oauthSessions.get("session-1").refreshCount, undefined);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthBoundary, undefined);
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
  assert.equal(
    catalogProviderRuntimeMaterialFromBody("catalog.local_manifest", { manifest_path: "./manifest.json" }).manifestPath,
    path.resolve("./manifest.json"),
  );
  assert.equal(
    catalogProviderRuntimeMaterialFromBody("catalog.custom_http", { base_url: "https://catalog.example.test/" }).baseUrl,
    "https://catalog.example.test",
  );
});
