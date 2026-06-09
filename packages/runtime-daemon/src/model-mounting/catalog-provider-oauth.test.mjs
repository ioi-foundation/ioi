import assert from "node:assert/strict";
import test from "node:test";

import {
  ModelMountingState,
} from "../model-mounting.mjs";

function fakeState() {
  return {
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
      startAuthorization() {
        throw new Error("oauth start should not run in JS");
      },
      async completeAuthorization() {
        throw new Error("oauth callback should not run in JS");
      },
      async exchangeAuthorizationCode() {
        throw new Error("oauth exchange should not run in JS");
      },
      async refreshAccessToken() {
        throw new Error("oauth refresh should not run in JS");
      },
      revokeSession() {
        throw new Error("oauth revoke should not run in JS");
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
      };
    },
    writeProjection() {
      this.projections += 1;
    },
    writeVaultRefs() {
      this.vaultWrites += 1;
    },
  };
}

function assertNoCatalogOAuthMutation(state) {
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
  assert.equal(state.vaultWrites, 0);
  assert.equal(state.catalogProviderConfigs.size, 0);
  assert.equal(state.oauthStates.size, 0);
  assert.equal(state.oauthSessions.size, 0);
}

function assertRustCoreRequired(error, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_catalog_provider_control_rust_core_required");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_control");
  assert.equal(error.details.provider_id, "catalog.huggingface");
  assert.deepEqual(error.details.evidence_refs, [
    "public_catalog_provider_control_js_facade_retired",
    "rust_daemon_core_catalog_provider_control_required",
    "rust_daemon_core_wallet_ctee_custody_required",
  ]);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  assert.equal(Object.hasOwn(error.details, "providerId"), false);
  return true;
}

test("catalog OAuth mutation facades fail closed until Rust core owns catalog provider control", async () => {
  const startState = fakeState();
  assert.throws(
    () => ModelMountingState.prototype.startCatalogProviderOAuth.call(
      startState,
      "catalog.huggingface",
      { auth_header_name: "authorization" },
    ),
    (error) => assertRustCoreRequired(error, "model_mount.catalog_provider_oauth.start"),
  );
  assertNoCatalogOAuthMutation(startState);

  const callbackState = fakeState();
  await assert.rejects(
    () => ModelMountingState.prototype.completeCatalogProviderOAuth.call(
      callbackState,
      "catalog.huggingface",
      { state: "callback-state" },
    ),
    (error) => {
      assertRustCoreRequired(error, "model_mount.catalog_provider_oauth.callback");
      assert.equal(error.details.state_present, true);
      return true;
    },
  );
  assertNoCatalogOAuthMutation(callbackState);

  const exchangeState = fakeState();
  await assert.rejects(
    () => ModelMountingState.prototype.exchangeCatalogProviderOAuth.call(
      exchangeState,
      "catalog.huggingface",
      { code: "code-a" },
    ),
    (error) => assertRustCoreRequired(error, "model_mount.catalog_provider_oauth.exchange"),
  );
  assertNoCatalogOAuthMutation(exchangeState);

  const refreshState = fakeState();
  await assert.rejects(
    () => ModelMountingState.prototype.refreshCatalogProviderOAuth.call(refreshState, "catalog.huggingface"),
    (error) => assertRustCoreRequired(error, "model_mount.catalog_provider_oauth.refresh"),
  );
  assertNoCatalogOAuthMutation(refreshState);

  const revokeState = fakeState();
  assert.throws(
    () => ModelMountingState.prototype.revokeCatalogProviderOAuth.call(revokeState, "catalog.huggingface"),
    (error) => assertRustCoreRequired(error, "model_mount.catalog_provider_oauth.revoke"),
  );
  assertNoCatalogOAuthMutation(revokeState);
});

test("catalog OAuth callback still validates required callback state before Rust boundary", async () => {
  const state = fakeState();

  await assert.rejects(
    () => ModelMountingState.prototype.completeCatalogProviderOAuth.call(state, "catalog.huggingface", {}),
    /state is required/,
  );
  assertNoCatalogOAuthMutation(state);
});

test("catalog OAuth callback rejects retired OAuth state compatibility aliases", async () => {
  for (const body of [
    { oauth_state: "callback-state" },
    { oauthState: "callback-state" },
  ]) {
    const state = fakeState();
    await assert.rejects(
      () => ModelMountingState.prototype.completeCatalogProviderOAuth.call(state, "catalog.huggingface", body),
      /state is required/,
    );
    assertNoCatalogOAuthMutation(state);
  }
});

test("catalog OAuth facades preserve configurable provider validation", () => {
  const state = fakeState();

  assert.throws(
    () => ModelMountingState.prototype.startCatalogProviderOAuth.call(state, "catalog.fixture", {}),
    /Catalog provider is not configurable: catalog.fixture/,
  );
  assertNoCatalogOAuthMutation(state);
});
