import assert from "node:assert/strict";
import test from "node:test";

import {
  ModelMountingState,
} from "../model-mounting.mjs";

const CATALOG_PROVIDER_EVIDENCE_REFS = [
  "rust_daemon_core_catalog_provider_control",
  "wallet_network_catalog_provider_authority_required",
  "ctee_catalog_provider_custody_enforced",
  "agentgres_catalog_provider_control_truth_required",
  "public_catalog_provider_control_js_facade_retired",
];

function fakeState() {
  const calls = [];
  const recordStateCommits = [];
  return {
    calls,
    recordStateCommits,
    catalogProviderConfigs: new Map(),
    catalogProviderRuntimeMaterials: new Map(),
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
      throw new Error("catalog provider ports should not run in JS");
    },
    catalogProviderRuntimeMaterial() {
      throw new Error("catalog runtime material should not resolve in JS");
    },
    nowIso() {
      return "2026-06-13T12:00:00.000Z";
    },
    planCatalogProviderControl(request) {
      calls.push({ name: "planCatalogProviderControl", request });
      return catalogProviderControlPlan(request);
    },
    writeMap() {
      throw new Error("catalog OAuth map writes should not run in JS");
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
    writeProjection() {
      throw new Error("catalog OAuth projections should not run in JS");
    },
    writeVaultRefs() {
      throw new Error("catalog OAuth vault metadata writes should not run in JS");
    },
  };
}

function catalogProviderControlPlan(request) {
  const recordId = `catalog_provider_control:${request.provider_id}:${request.operation_kind.split(".").at(-1)}`;
  const record = {
    id: recordId,
    record_id: recordId,
    object: "ioi.model_mount_catalog_provider_control",
    status: "planned",
    operation_kind: request.operation_kind,
    provider_id: request.provider_id,
    rust_core_boundary: "model_mount.catalog_provider_control",
    plaintext_material_returned: false,
    public_response: {
      object: `ioi.${request.operation_kind.replaceAll(".", "_")}`,
      provider_id: request.provider_id,
      status: "accepted",
      private_material_returned: false,
      plaintext_material_returned: false,
    },
    evidence_refs: CATALOG_PROVIDER_EVIDENCE_REFS,
    control_hash: `sha256:control:${recordId}`,
  };
  return {
    source: "rust_daemon_core.model_mount.catalog_provider_control",
    backend: "rust_model_mount_catalog_provider_control",
    plan: { record },
    record_dir: "model-catalog-provider-controls",
    record_id: recordId,
    record,
    operation_kind: request.operation_kind,
    rust_core_boundary: "model_mount.catalog_provider_control",
    receipt_refs: request.receipt_refs,
    authority_grant_refs: request.authority_grant_refs,
    authority_receipt_refs: request.authority_receipt_refs,
    evidence_refs: CATALOG_PROVIDER_EVIDENCE_REFS,
    control_hash: `sha256:control:${recordId}`,
    authority_hash: `sha256:authority:${recordId}`,
  };
}

function assertRustCatalogProviderControlResponse(result, operationKind) {
  assert.equal(result.status, "committed");
  assert.equal(result.operation_kind, operationKind);
  assert.equal(result.rust_core_boundary, "model_mount.catalog_provider_control");
  assert.equal(result.record_dir, "model-catalog-provider-controls");
  assert.equal(result.record.plaintext_material_returned, false);
  assert.equal(result.evidence_refs.includes("ctee_catalog_provider_custody_enforced"), true);
}

test("catalog OAuth operations commit Rust catalog-provider-control records", async () => {
  const state = fakeState();

  const start = ModelMountingState.prototype.startCatalogProviderOAuth.call(
    state,
    "catalog.huggingface",
    {
      auth_header_name: "authorization",
      authority_grant_refs: ["grant://wallet/provider-write"],
      authority_receipt_refs: ["receipt://wallet/provider-write"],
      custody_ref: "ctee://catalog-provider/huggingface",
    },
  );
  const callback = await ModelMountingState.prototype.completeCatalogProviderOAuth.call(
    state,
    "catalog.huggingface",
    { state: "callback-state" },
  );
  const exchange = await ModelMountingState.prototype.exchangeCatalogProviderOAuth.call(
    state,
    "catalog.huggingface",
    { code: "code-a" },
  );
  const refresh = await ModelMountingState.prototype.refreshCatalogProviderOAuth.call(
    state,
    "catalog.huggingface",
  );
  const revoke = ModelMountingState.prototype.revokeCatalogProviderOAuth.call(
    state,
    "catalog.huggingface",
  );

  assertRustCatalogProviderControlResponse(start, "model_mount.catalog_provider_oauth.start");
  assertRustCatalogProviderControlResponse(callback, "model_mount.catalog_provider_oauth.callback");
  assertRustCatalogProviderControlResponse(exchange, "model_mount.catalog_provider_oauth.exchange");
  assertRustCatalogProviderControlResponse(refresh, "model_mount.catalog_provider_oauth.refresh");
  assertRustCatalogProviderControlResponse(revoke, "model_mount.catalog_provider_oauth.revoke");
  assert.equal(state.calls.length, 5);
  assert.equal(state.recordStateCommits.length, 5);
  assert.deepEqual(
    state.calls.map((call) => call.request.operation_kind),
    [
      "model_mount.catalog_provider_oauth.start",
      "model_mount.catalog_provider_oauth.callback",
      "model_mount.catalog_provider_oauth.exchange",
      "model_mount.catalog_provider_oauth.refresh",
      "model_mount.catalog_provider_oauth.revoke",
    ],
  );
  assert.equal(state.calls[0].request.custody_ref, "ctee://catalog-provider/huggingface");
  assert.deepEqual(state.calls[0].request.authority_grant_refs, ["grant://wallet/provider-write"]);
  assert.deepEqual(state.calls[0].request.authority_receipt_refs, ["receipt://wallet/provider-write"]);
  assert.equal(Object.hasOwn(state, "oauthSessions"), false);
  assert.equal(Object.hasOwn(state, "oauthStates"), false);
});

test("catalog OAuth callback still validates required callback state before Rust boundary", async () => {
  const state = fakeState();

  await assert.rejects(
    () => ModelMountingState.prototype.completeCatalogProviderOAuth.call(state, "catalog.huggingface", {}),
    /state is required/,
  );
  assert.equal(state.calls.length, 0);
  assert.equal(state.recordStateCommits.length, 0);
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
    assert.equal(state.calls.length, 0);
    assert.equal(state.recordStateCommits.length, 0);
  }
});
