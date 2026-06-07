import assert from "node:assert/strict";
import test from "node:test";

import {
  completeCatalogProviderOAuth,
  exchangeCatalogProviderOAuth,
  refreshCatalogProviderOAuth,
  revokeCatalogProviderOAuth,
  startCatalogProviderOAuth,
} from "./catalog-provider-oauth.mjs";

function fakeState() {
  const state = {
    catalogProviderConfigs: new Map(),
    catalogProviderRuntimeMaterials: new Map(),
    oauthSessions: new Map(),
    oauthStates: new Map(),
    projections: 0,
    receipts: [],
    recordStateCommits: [],
    writes: [],
    vaultWrites: 0,
    now: "2026-06-03T21:00:00.000Z",
    oauthCredentialProvider: {
      startAuthorization({ providerId }) {
        return {
          state: {
            id: "oauth-state-1",
            providerId,
            status: "pending",
            stateHash: "hash:callback-state",
          },
          evidence: {
            oauthStateHash: "hash:oauth-state-1",
            expiresAt: "2026-06-03T22:00:00.000Z",
            scopes: ["read"],
            pkceRequired: true,
          },
          authorizationUrl: "https://auth.example.test/authorize?state=secret",
          authorizationUrlRedacted: "https://auth.example.test/authorize?state=[REDACTED]",
          authorizationUrlHash: "hash:authorization-url",
        };
      },
      async completeAuthorization({ providerId, stateRecord }) {
        assert.equal(providerId, "catalog.huggingface");
        assert.equal(stateRecord.id, "oauth-state-1");
        return {
          state: { ...stateRecord, status: "completed", completedAt: state.now },
          stateEvidence: { id: stateRecord.id, status: "completed" },
          session: {
            id: "oauth-session-1",
            providerId,
            status: "active",
            accessVaultRef: "vault://oauth/access",
          },
          sessionEvidence: { id: "oauth-session-1", status: "active" },
        };
      },
      async exchangeAuthorizationCode({ providerId }) {
        return {
          session: {
            id: "oauth-session-exchange",
            providerId,
            status: "active",
            accessVaultRef: "vault://oauth/exchange",
          },
          evidence: { id: "oauth-session-exchange", status: "active" },
        };
      },
      async refreshAccessToken(session) {
        return {
          ...session,
          status: "active",
          refreshCount: Number(session.refreshCount ?? 0) + 1,
          lastRefreshedAt: state.now,
        };
      },
      revokeSession(session) {
        return {
          ...session,
          status: "revoked",
          revokedAt: state.now,
        };
      },
    },
    catalogProviderPorts() {
      return [{ id: "catalog.huggingface", status: "available" }];
    },
    catalogProviderRuntimeMaterial(providerId) {
      return this.catalogProviderRuntimeMaterials.get(providerId) ?? null;
    },
    nowIso() {
      return this.now;
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, payload };
      this.receipts.push(receipt);
      return receipt;
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
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
    writeProjection() {
      this.projections += 1;
    },
    writeVaultRefs() {
      this.vaultWrites += 1;
    },
  };
  return state;
}

const deps = {
  assertConfigurableCatalogProvider(providerId) {
    if (providerId !== "catalog.huggingface") throw new Error(`not configurable: ${providerId}`);
  },
  catalogProviderConfigUpdate(providerId, body, existing, updatedAt) {
    const record = {
      id: providerId,
      enabled: body.enabled,
      catalogAuthScheme: body.auth_scheme,
      catalogAuthHeaderName: body.auth_header_name,
      authVaultRef: body.auth_vault_ref ?? existing?.authVaultRef ?? null,
      oauthSessionId: body.oauth_session_id ?? existing?.oauthSessionId ?? null,
      updatedAt,
    };
    return {
      record,
      runtimeMaterial: { baseUrl: "https://catalog.example.test", runtimeMaterialStatus: "bound_runtime_session" },
      evidenceRefs: ["catalog_provider_config_metadata"],
    };
  },
  catalogProviderStatus(port) {
    return port ? { id: port.id, status: port.status } : null;
  },
  oauthBoundaryForSession(session, options = {}) {
    return {
      configured: session.status === "active",
      status: options.refreshed ? "refreshed" : session.status,
      oauthSessionHash: `hash:${session.id}`,
    };
  },
  publicCatalogProviderConfig(providerId, record, material) {
    return {
      id: providerId,
      enabled: record?.enabled ?? false,
      catalogAuthScheme: record?.catalogAuthScheme ?? null,
      oauthSessionId: record?.oauthSessionId ?? null,
      runtimeMaterialStatus: material?.runtimeMaterialStatus ?? null,
    };
  },
  publicOAuthSession(session) {
    return {
      id: session.id,
      status: session.status,
      refreshCount: Number(session.refreshCount ?? 0),
      revokedAt: session.revokedAt ?? null,
    };
  },
  requiredString(value, field) {
    if (typeof value !== "string" || !value) throw new Error(`missing ${field}`);
    return value;
  },
  runtimeError({ status, code, message, details }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    error.details = details;
    return error;
  },
  stableHash(value) {
    return `hash:${value}`;
  },
};

test("catalog OAuth start persists pending state, config boundary, and public receipt", () => {
  const state = fakeState();

  const result = startCatalogProviderOAuth(state, "catalog.huggingface", { authHeaderName: "Authorization" }, deps);

  assert.equal(result.id, "catalog.huggingface");
  assert.equal(result.oauthState.oauthStateHash, "hash:oauth-state-1");
  assert.equal(result.authorizationUrlHash, "hash:authorization-url");
  assert.equal(result.receiptId, "receipt.catalog_oauth_start.1");
  assert.equal(result.provider.status, "available");
  assert.equal(state.receipts[0].payload.details.provider_id, "catalog.huggingface");
  assert.equal(state.receipts[0].payload.details.oauth_state.oauthStateHash, "hash:oauth-state-1");
  assert.equal(state.receipts[0].payload.details.authorization_url_hash, "hash:authorization-url");
  assert.equal(state.receipts[0].payload.details.authorization_url_redacted, "https://auth.example.test/authorize?state=[REDACTED]");
  assert.equal(state.receipts[0].payload.details.catalog_provider.id, "catalog.huggingface");
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "oauthState"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "authorizationUrlHash"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "authorizationUrlRedacted"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "catalogProvider"), false);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthBoundary.status, "pending_authorization");
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-catalog-providers");
  assert.equal(state.recordStateCommits[0].record_id, "catalog.huggingface");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.catalog_provider_oauth.start");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.catalog_oauth_start.1"]);
  assert.equal(state.recordStateCommits[0].record.receiptId, "receipt.catalog_oauth_start.1");
  assert.equal(state.recordStateCommits[1].record_dir, "oauth-states");
  assert.equal(state.recordStateCommits[1].record_id, "oauth-state-1");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.oauth_state.start");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["receipt.catalog_oauth_start.1"]);
  assert.equal(state.recordStateCommits[1].record.receiptId, "receipt.catalog_oauth_start.1");
  assert.equal(state.vaultWrites, 1);
  assert.equal(state.projections, 1);
});

test("catalog OAuth callback finds pending state by hash and binds completed session", async () => {
  const state = fakeState();
  startCatalogProviderOAuth(state, "catalog.huggingface", {}, deps);

  const result = await completeCatalogProviderOAuth(state, "catalog.huggingface", { state: "callback-state" }, deps);

  assert.equal(result.oauthState.status, "completed");
  assert.equal(result.oauthSession.status, "active");
  assert.equal(result.receiptId, "receipt.catalog_oauth_callback.2");
  assert.equal(state.receipts.at(-1).payload.details.provider_id, "catalog.huggingface");
  assert.equal(state.receipts.at(-1).payload.details.oauth_state.status, "completed");
  assert.equal(state.receipts.at(-1).payload.details.oauth_session.status, "active");
  assert.equal(state.receipts.at(-1).payload.details.catalog_provider.id, "catalog.huggingface");
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "oauthState"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "oauthSession"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "catalogProvider"), false);
  assert.equal(state.oauthStates.get("oauth-state-1").status, "completed");
  assert.equal(state.oauthSessions.get("oauth-session-1").accessVaultRef, "vault://oauth/access");
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthSessionId, "oauth-session-1");
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits.slice(-3).map((commit) => commit.record_dir), [
    "model-catalog-providers",
    "oauth-states",
    "oauth-sessions",
  ]);
  assert.deepEqual(state.recordStateCommits.slice(-3).map((commit) => commit.operation_kind), [
    "model_mount.catalog_provider_oauth.callback",
    "model_mount.oauth_state.callback",
    "model_mount.oauth_session.callback",
  ]);
  assert.deepEqual(state.recordStateCommits.at(-1).receipt_refs, ["receipt.catalog_oauth_callback.2"]);
});

test("catalog OAuth exchange persists session and provider config", async () => {
  const state = fakeState();

  const result = await exchangeCatalogProviderOAuth(state, "catalog.huggingface", { code: "code-a" }, deps);

  assert.equal(result.oauthSession.id, "oauth-session-exchange");
  assert.equal(result.receiptId, "receipt.catalog_oauth_exchange.1");
  assert.equal(state.receipts[0].payload.details.provider_id, "catalog.huggingface");
  assert.equal(state.receipts[0].payload.details.oauth_session.id, "oauth-session-exchange");
  assert.equal(state.receipts[0].payload.details.catalog_provider.id, "catalog.huggingface");
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "oauthSession"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "catalogProvider"), false);
  assert.equal(state.oauthSessions.has("oauth-session-exchange"), true);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthSessionId, "oauth-session-exchange");
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.catalog_provider_oauth.exchange");
  assert.equal(state.recordStateCommits[1].record_dir, "oauth-sessions");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.oauth_session.exchange");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["receipt.catalog_oauth_exchange.1"]);
});

test("catalog OAuth refresh and revoke update session boundary records", async () => {
  const state = fakeState();
  state.catalogProviderConfigs.set("catalog.huggingface", { id: "catalog.huggingface", oauthSessionId: "oauth-session-1" });
  state.oauthSessions.set("oauth-session-1", { id: "oauth-session-1", status: "active", refreshCount: 0 });

  const refreshed = await refreshCatalogProviderOAuth(state, "catalog.huggingface", deps);
  assert.equal(refreshed.oauthSession.refreshCount, 1);
  assert.equal(refreshed.receiptId, "receipt.catalog_oauth_refresh.1");
  assert.equal(state.receipts[0].payload.details.provider_id, "catalog.huggingface");
  assert.equal(state.receipts[0].payload.details.oauth_session.refreshCount, 1);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "oauthSession"), false);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthBoundary.status, "refreshed");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.catalog_provider_oauth.refresh");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.catalog_oauth_refresh.1"]);
  assert.equal(state.recordStateCommits[1].record_dir, "oauth-sessions");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.oauth_session.refresh");

  const revoked = revokeCatalogProviderOAuth(state, "catalog.huggingface", deps);
  assert.equal(revoked.oauthSession.status, "revoked");
  assert.equal(revoked.receiptId, "receipt.catalog_oauth_revoke.2");
  assert.equal(state.receipts.at(-1).payload.details.provider_id, "catalog.huggingface");
  assert.equal(state.receipts.at(-1).payload.details.oauth_session.status, "revoked");
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "oauthSession"), false);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthBoundary.status, "revoked");
  assert.equal(state.recordStateCommits[2].operation_kind, "model_mount.catalog_provider_oauth.revoke");
  assert.equal(state.recordStateCommits[3].record_dir, "oauth-sessions");
  assert.equal(state.recordStateCommits[3].operation_kind, "model_mount.oauth_session.revoke");
  assert.deepEqual(state.recordStateCommits[3].receipt_refs, ["receipt.catalog_oauth_revoke.2"]);
  assert.deepEqual(state.writes, []);
  assert.equal(state.vaultWrites, 2);
});

test("catalog OAuth provider config updates fail closed without Rust Agentgres record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => startCatalogProviderOAuth(state, "catalog.huggingface", {}, deps),
    (error) => {
      assert.equal(error.code, "model_mount_catalog_provider_oauth_state_commit_unconfigured");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.record_dir, "model-catalog-providers");
      return true;
    },
  );

  assert.equal(state.catalogProviderConfigs.has("catalog.huggingface"), false);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
  assert.equal(state.vaultWrites, 0);
});

test("catalog OAuth state persistence fails closed before local state mutation without Rust Agentgres record-state commit", () => {
  const state = fakeState();
  state.commitRuntimeModelMountRecordState = (request) => {
    if (request.record_dir === "oauth-states") {
      const error = new Error("OAuth state commit disabled");
      error.status = 500;
      error.code = "model_mount_oauth_state_commit_unconfigured";
      error.details = {
        provider_id: request.record.providerId,
        record_dir: request.record_dir,
        record_id: request.record_id,
      };
      throw error;
    }
    return fakeState().commitRuntimeModelMountRecordState(request);
  };

  assert.throws(
    () => startCatalogProviderOAuth(state, "catalog.huggingface", {}, deps),
    (error) => {
      assert.equal(error.code, "model_mount_oauth_state_commit_unconfigured");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.record_dir, "oauth-states");
      return true;
    },
  );

  assert.equal(state.oauthStates.has("oauth-state-1"), false);
  assert.equal(state.catalogProviderConfigs.has("catalog.huggingface"), false);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
  assert.equal(state.vaultWrites, 0);
});

test("catalog OAuth session persistence fails closed before local session mutation without Rust Agentgres record-state commit", async () => {
  const state = fakeState();
  startCatalogProviderOAuth(state, "catalog.huggingface", {}, deps);
  state.commitRuntimeModelMountRecordState = (request) => {
    if (request.record_dir === "oauth-sessions") {
      const error = new Error("OAuth session commit disabled");
      error.status = 500;
      error.code = "model_mount_oauth_session_commit_unconfigured";
      error.details = {
        provider_id: request.record.providerId,
        record_dir: request.record_dir,
        record_id: request.record_id,
      };
      throw error;
    }
    return fakeState().commitRuntimeModelMountRecordState(request);
  };

  await assert.rejects(
    () => completeCatalogProviderOAuth(state, "catalog.huggingface", { state: "callback-state" }, deps),
    (error) => {
      assert.equal(error.code, "model_mount_oauth_session_commit_unconfigured");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.record_dir, "oauth-sessions");
      return true;
    },
  );

  assert.equal(state.oauthStates.get("oauth-state-1").status, "pending");
  assert.equal(state.oauthSessions.has("oauth-session-1"), false);
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").oauthSessionId, null);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 1);
  assert.equal(state.vaultWrites, 1);
});

test("catalog OAuth refresh fails closed when configured session is missing", async () => {
  const state = fakeState();
  state.catalogProviderConfigs.set("catalog.huggingface", { id: "catalog.huggingface", oauthSessionId: "missing-session" });

  await assert.rejects(
    () => refreshCatalogProviderOAuth(state, "catalog.huggingface", deps),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.oauth_session_hash, "hash:missing-session");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      return true;
    },
  );

  assert.throws(
    () => revokeCatalogProviderOAuth(state, "catalog.huggingface", deps),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.oauth_session_hash, "hash:missing-session");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      return true;
    },
  );
});
