import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

const CATALOG_PROVIDER_EVIDENCE_REFS = [
  "rust_daemon_core_catalog_provider_control",
  "wallet_network_catalog_provider_authority_required",
  "ctee_catalog_provider_custody_enforced",
  "agentgres_catalog_provider_control_truth_required",
  "public_catalog_provider_control_js_facade_retired",
];

function createState() {
  const calls = [];
  const recordStateCommits = [];
  const state = {
    calls,
    recordStateCommits,
    catalogProviderConfigs: new Map(),
    catalogProviderRuntimeMaterials: new Map(),
    planCatalogProviderControl(request) {
      calls.push({ name: "planCatalogProviderControl", request });
      return catalogProviderControlPlan(request);
    },
    catalogProviderPorts() {
      throw new Error("catalog provider ports should not run in JS");
    },
    nowIso() {
      return "2026-06-13T12:00:00.000Z";
    },
    vault: {
      bindVaultRef() {
        throw new Error("catalog provider vault binding should not run in JS");
      },
      resolveVaultRef() {
        throw new Error("catalog provider vault resolution should not run in JS");
      },
    },
    walletAuthority: {
      resolveVaultRef() {
        throw new Error("catalog provider wallet vault resolution should not run in JS");
      },
    },
    writeMap() {
      throw new Error("catalog provider map writes should not run in JS");
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
      throw new Error("catalog provider projections should not run in JS");
    },
    writeVaultRefs() {
      throw new Error("catalog provider vault metadata writes should not run in JS");
    },
  };
  return state;
}

function catalogProviderControlPlan(request) {
  const providerSegment = request.provider_id ?? "all";
  const recordId = `catalog_provider_control:${providerSegment}:${request.operation_kind.split(".").at(-1)}`;
  const publicResponse = publicResponseForRequest(request);
  const record = {
    id: recordId,
    record_id: recordId,
    object: "ioi.model_mount_catalog_provider_control",
    status: "planned",
    operation_kind: request.operation_kind,
    provider_id: request.provider_id ?? null,
    rust_core_boundary: "model_mount.catalog_provider_control",
    wallet_authority_boundary: "wallet.network.catalog_provider_control",
    ctee_custody_boundary: "ctee.catalog_provider_material",
    plaintext_material_returned: false,
    public_response: publicResponse,
    evidence_refs: CATALOG_PROVIDER_EVIDENCE_REFS,
    control_hash: `sha256:control:${recordId}`,
    authority: {
      authority_hash: `sha256:authority:${recordId}`,
      authority_grant_refs: request.authority_grant_refs,
      authority_receipt_refs: request.authority_receipt_refs,
    },
  };
  return {
    source: "rust_model_mount_catalog_provider_control_command",
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

function publicResponseForRequest(request) {
  if (request.operation_kind === "model_mount.catalog_provider_configuration.list") {
    return {
      object: "ioi.model_catalog_provider_config_list",
      providers: [
        {
          id: "catalog.huggingface",
          provider_id: "catalog.huggingface",
          status: "rust_controlled",
          plaintext_material_returned: false,
        },
      ],
    };
  }
  return {
    object: request.operation_kind === "model_mount.catalog_provider_configuration.write"
      ? "ioi.model_catalog_provider_config_write"
      : "ioi.model_catalog_provider_config",
    provider_id: request.provider_id,
    status: "accepted",
    private_material_returned: false,
    plaintext_material_returned: false,
    authority_hash: `sha256:authority:catalog_provider_control:${request.provider_id}:${request.operation_kind.split(".").at(-1)}`,
  };
}

test("catalog provider config list/get/write commit Rust control records without JS projection", () => {
  const state = createState();
  state.catalogProviderConfigs.set("catalog.huggingface", { id: "catalog.huggingface", enabled: true });
  state.catalogProviderRuntimeMaterials.set("catalog.huggingface", {
    baseUrl: "https://huggingface.example.invalid",
    runtimeMaterialStatus: "bound_runtime_session",
  });

  const list = ModelMountingState.prototype.listCatalogProviderConfigs.call(state);
  const get = ModelMountingState.prototype.getCatalogProviderConfig.call(state, "catalog.huggingface");
  const write = ModelMountingState.prototype.configureCatalogProvider.call(state, "catalog.huggingface", {
    enabled: true,
    authority_grant_refs: ["grant://wallet/provider-write"],
    authority_receipt_refs: ["receipt://wallet/provider-write"],
    custody_ref: "ctee://catalog-provider/huggingface",
  });

  assert.equal(list.status, "committed");
  assert.equal(list.operation_kind, "model_mount.catalog_provider_configuration.list");
  assert.equal(list.rust_core_boundary, "model_mount.catalog_provider_control");
  assert.equal(list.providers[0].provider_id, "catalog.huggingface");
  assert.equal(get.operation_kind, "model_mount.catalog_provider_configuration.get");
  assert.equal(get.private_material_returned, false);
  assert.equal(write.operation_kind, "model_mount.catalog_provider_configuration.write");
  assert.equal(write.record.plaintext_material_returned, false);
  assert.deepEqual(write.authority_grant_refs, ["grant://wallet/provider-write"]);
  assert.deepEqual(write.authority_receipt_refs, ["receipt://wallet/provider-write"]);
  assert.equal(state.calls.length, 3);
  assert.equal(state.calls[2].request.provider_id, "catalog.huggingface");
  assert.equal(state.calls[2].request.custody_ref, "ctee://catalog-provider/huggingface");
  assert.equal(state.calls[2].request.body.enabled, true);
  assert.equal(state.recordStateCommits.length, 3);
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.record_dir),
    [
      "model-catalog-provider-controls",
      "model-catalog-provider-controls",
      "model-catalog-provider-controls",
    ],
  );
  assert.equal(state.recordStateCommits[2].operation_kind, "model_mount.catalog_provider_configuration.write");
  assert.equal(state.catalogProviderConfigs.get("catalog.huggingface").enabled, true);
});

test("private config and runtime material resolve through Rust cTEE control only", () => {
  const state = createState();
  state.catalogProviderConfigs.set("catalog.huggingface", {
    id: "catalog.huggingface",
    authVaultRefHash: "hash:vault://catalog/auth",
  });
  state.catalogProviderRuntimeMaterials.set("catalog.huggingface", {
    materialVaultRefHash: "hash:vault://catalog/source",
    runtimeMaterialStatus: "bound_runtime_session",
  });

  const privateConfig = ModelMountingState.prototype.catalogProviderConfig.call(state, "catalog.huggingface");
  const runtimeMaterial = ModelMountingState.prototype.catalogProviderRuntimeMaterial.call(state, "catalog.huggingface");

  assert.equal(privateConfig.operation_kind, "model_mount.catalog_provider_configuration.read_private");
  assert.equal(runtimeMaterial.operation_kind, "model_mount.catalog_provider_runtime_material.resolve");
  assert.equal(runtimeMaterial.record.plaintext_material_returned, false);
  assert.equal(state.calls.length, 2);
  assert.deepEqual(state.calls.map((call) => call.request.body), [{}, {}]);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.catalog_provider_runtime_material.resolve");
});
