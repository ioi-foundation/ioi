import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import {
  assertConfigurableCatalogProvider,
  catalogProviderAuthConfig,
  catalogProviderAuthHeaders,
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

test("catalog provider source request aliases fail closed before vault binding", () => {
  const state = createState();

  assert.throws(
    () =>
      catalogProviderRuntimeMaterialFromBody("catalog.local_manifest", {
        manifestPath: "./manifest.json",
      }),
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

  assert.throws(
    () =>
      catalogProviderRuntimeMaterialFromBody("catalog.local_manifest", {
        path: "./manifest.json",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_provider_source_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["path"]);
      assert.deepEqual(error.details.canonical_fields, ["manifest_path", "base_url"]);
      return true;
    },
  );

  assert.throws(
    () =>
      catalogProviderRuntimeMaterialFromBody("catalog.custom_http", {
        url: "https://catalog.example.test",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_provider_source_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["url"]);
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
      catalogProviderAuthConfig(
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

test("catalog provider auth headers fail closed before JS vault resolution", async () => {
  const state = createState();
  let resolveCount = 0;
  let configReadCount = 0;
  state.vault.resolveVaultRef = () => {
    resolveCount += 1;
    throw new Error("catalog auth vault resolution should not run in JS");
  };
  state.catalogProviderConfig = () => {
    configReadCount += 1;
    throw new Error("catalogProviderConfig must not feed catalog auth headers");
  };

  await assert.rejects(
    () => catalogProviderAuthHeaders("catalog.custom_http", state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_auth_header.resolve");
      assert.equal(error.details.provider_id, "catalog.custom_http");
      assert.equal(error.details.auth_configuration_status, "rust_core_projection_required");
      assert.equal(error.details.resolved_material, false);
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
      assert.deepEqual(error.details.evidence_refs, [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "catalogProviderId"), false);
      assert.equal(Object.hasOwn(error.details, "authVaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "auth_vault_ref_hash"), false);
      assert.equal(Object.hasOwn(error.details, "resolvedMaterial"), false);
      assert.equal(Object.hasOwn(error.details, "authScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalog_auth_scheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthHeaderNameHash"), false);
      assert.equal(Object.hasOwn(error.details, "catalog_auth_header_name_hash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
  assert.equal(configReadCount, 0);
  assert.equal(resolveCount, 0);
  assert.equal(state.writeVaultRefsCount(), 0);

  await assert.rejects(
    () => catalogProviderAuthHeaders("catalog.custom_http", state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_auth_header.resolve");
      assert.equal(error.details.provider_id, "catalog.custom_http");
      assert.equal(error.details.auth_configuration_status, "rust_core_projection_required");
      assert.equal(error.details.resolved_material, false);
      assert.equal(Object.hasOwn(error.details, "catalogProviderId"), false);
      assert.equal(Object.hasOwn(error.details, "authVaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "auth_vault_ref_hash"), false);
      assert.equal(Object.hasOwn(error.details, "resolvedMaterial"), false);
      assert.equal(Object.hasOwn(error.details, "authScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalog_auth_scheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthHeaderNameHash"), false);
      assert.equal(Object.hasOwn(error.details, "catalog_auth_header_name_hash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );

  await assert.rejects(
    () => catalogProviderAuthHeaders("catalog.custom_http", state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_auth_header.resolve");
      assert.equal(error.details.provider_id, "catalog.custom_http");
      assert.equal(error.details.auth_configuration_status, "rust_core_projection_required");
      assert.equal(error.details.resolved_material, false);
      assert.equal(Object.hasOwn(error.details, "catalogProviderId"), false);
      assert.equal(Object.hasOwn(error.details, "authVaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "auth_vault_ref_hash"), false);
      assert.equal(Object.hasOwn(error.details, "resolvedMaterial"), false);
      assert.equal(Object.hasOwn(error.details, "authScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalog_auth_scheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthHeaderNameHash"), false);
      assert.equal(Object.hasOwn(error.details, "catalog_auth_header_name_hash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
  assert.equal(configReadCount, 0);
  assert.equal(resolveCount, 0);
  assert.equal(state.writeVaultRefsCount(), 0);
});

test("catalog provider OAuth auth-header refresh facade fails closed before JS config or credential reads", async () => {
  const state = createState();
  let resolveAccessHeaderCount = 0;
  let configReadCount = 0;
  state.oauthSessions.set("session-1", { id: "session-1", status: "active" });
  state.catalogProviderConfigs.set("catalog.huggingface", {
    id: "catalog.huggingface",
    oauthSessionId: "session-1",
    oauthSessionHash: "hash:session-1",
    catalogAuthScheme: "oauth2",
    catalogAuthHeaderName: "authorization",
  });
  state.catalogProviderConfig = () => {
    configReadCount += 1;
    throw new Error("catalogProviderConfig must not feed OAuth auth-header refresh");
  };
  state.nowIso = () => "2026-06-03T12:00:00.000Z";
  state.oauthCredentialProvider = {
    async resolveAccessHeader() {
      resolveAccessHeaderCount += 1;
      throw new Error("OAuth access-header resolution should not run in JS");
    },
  };

  await assert.rejects(
    () => catalogProviderAuthHeaders("catalog.huggingface", state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog_provider_auth_header.resolve");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.auth_configuration_status, "rust_core_projection_required");
      assert.equal(error.details.resolved_material, false);
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
      assert.deepEqual(error.details.evidence_refs, [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      assert.equal(Object.hasOwn(error.details, "oauth_session_hash"), false);
      return true;
    },
  );

  assert.equal(configReadCount, 0);
  assert.equal(resolveAccessHeaderCount, 0);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.oauthSessions.get("session-1").refreshCount, undefined);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthBoundary, undefined);
  assert.equal(state.writeVaultRefsCount(), 0);
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
