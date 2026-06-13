import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";
import { stableHash } from "./io.mjs";

const VAULT_EVIDENCE_REFS = [
  "rust_daemon_core_vault_control",
  "wallet_network_vault_authority_required",
  "ctee_vault_custody_enforced",
  "agentgres_vault_truth_required",
  "public_vault_js_facade_retired",
];

function createState() {
  const calls = [];
  const planCalls = [];
  const recordStateCommits = [];
  return {
    calls,
    planCalls,
    recordStateCommits,
    stateDir: "/tmp/ioi-model-mount-state",
    vault: {
      bindVaultRef() {
        throw new Error("JS vault.bindVaultRef must not author public vault truth.");
      },
      listVaultRefs() {
        throw new Error("JS vault.listVaultRefs must not author public vault truth.");
      },
      vaultRefMetadata() {
        throw new Error("JS vault.vaultRefMetadata must not author public vault truth.");
      },
      adapterStatus() {
        throw new Error("JS vault.adapterStatus must not author public vault truth.");
      },
      health() {
        throw new Error("JS vault.health must not author public vault truth.");
      },
      removeVaultRef() {
        throw new Error("JS vault.removeVaultRef must not author public vault truth.");
      },
    },
    nowIso() {
      return "2026-06-13T12:00:00.000Z";
    },
    planVaultControl(request) {
      planCalls.push(request);
      return vaultControlPlan(request);
    },
    commitRuntimeModelMountRecordState(request) {
      recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:content:${request.record_id}`,
        admission_hash: `sha256:admission:${request.record_id}`,
        commit_hash: `sha256:commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:content:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.record_id}`,
          },
        },
      };
    },
  };
}

function vaultControlPlan(request) {
  const publicResponse = publicResponseFor(request);
  const recordId = `vault_control:${publicResponse.vault_ref_hash ?? "all"}:${request.operation_kind.split(".").at(-1)}`;
  const record = {
    id: recordId,
    record_id: recordId,
    object: "ioi.model_mount_vault_control",
    status: "planned",
    operation_kind: request.operation_kind,
    vault_ref_hash: publicResponse.vault_ref_hash ?? null,
    material_hash: request.material_hash ?? null,
    rust_core_boundary: "model_mount.vault",
    wallet_authority_boundary: "wallet.network.vault",
    ctee_custody_boundary: "ctee.vault_custody",
    vault_authority: {
      authority_hash: "sha256:vault-authority",
      vault_ref_hash: publicResponse.vault_ref_hash ?? null,
      material_hash: request.material_hash ?? null,
      authority_grant_refs: request.authority_grant_refs,
      authority_receipt_refs: request.authority_receipt_refs,
    },
    ctee_custody: {
      custody_ref: request.custody_ref ?? "ctee://vault/custom",
      plaintext_material_persisted: false,
      plaintext_material_returned: false,
      material_hash: request.material_hash ?? null,
    },
    public_response: publicResponse,
    receipt_refs: ["receipt://model_mount/vault/test"],
    evidence_refs: VAULT_EVIDENCE_REFS,
    control_hash: "sha256:vault-control",
    planned_at: request.generated_at,
  };
  return {
    schema_version: "ioi.model_mount.vault_control_plan.v1",
    object: "ioi.model_mount_vault_control_plan",
    status: "planned",
    rust_core_boundary: "model_mount.vault",
    operation_kind: request.operation_kind,
    source: request.source,
    record_dir: "vault-refs",
    record_id: recordId,
    record,
    public_response: publicResponse,
    receipt_refs: record.receipt_refs,
    authority_grant_refs: request.authority_grant_refs,
    authority_receipt_refs: request.authority_receipt_refs,
    evidence_refs: VAULT_EVIDENCE_REFS,
    control_hash: "sha256:vault-control",
    authority_hash: "sha256:vault-authority",
  };
}

function publicResponseFor(request) {
  if (request.operation_kind === "model_mount.vault_ref.list") {
    return {
      object: "ioi.model_mount_vault_ref_list",
      status: "projected",
      vault_refs: [vaultRefResponse("active", request)],
      count: 1,
      plaintext_material_persisted: false,
      plaintext_material_returned: false,
    };
  }
  if (request.operation_kind === "model_mount.vault.status") {
    return {
      object: "ioi.model_mount_vault_status",
      status: "available",
      configured: true,
      record_count: 1,
      plaintext_material_persisted: false,
      plaintext_material_returned: false,
    };
  }
  if (request.operation_kind === "model_mount.vault.health") {
    return {
      object: "ioi.model_mount_vault_health",
      status: "healthy",
      read_available: true,
      write_available: true,
      record_count: 1,
      plaintext_material_persisted: false,
      plaintext_material_returned: false,
    };
  }
  if (request.operation_kind === "model_mount.vault_ref.remove") {
    return vaultRefResponse("removed", request, { configured: false, material_bound: false });
  }
  if (request.operation_kind === "model_mount.vault_ref.metadata") {
    return vaultRefResponse("projected", request);
  }
  return vaultRefResponse("bound", request);
}

function vaultRefResponse(status, request, overrides = {}) {
  const vaultRefHash = stableHash(request.vault_ref ?? "vault://provider/custom/api-key");
  return {
    object: "ioi.model_mount_vault_ref",
    status,
    id: `vault_ref.${vaultRefHash}`,
    vault_ref_hash: vaultRefHash,
    vault_ref: { redacted: true, hash: vaultRefHash },
    label: request.body.label ?? "Custom auth",
    purpose: request.body.purpose ?? "provider.auth:custom",
    material_hash: request.material_hash ?? `sha256:${stableHash("custom-secret")}`,
    custody_ref: request.custody_ref ?? request.body.custody_ref ?? "ctee://vault/custom",
    configured: true,
    material_bound: true,
    resolved_material: false,
    requires_rebind: false,
    plaintext_material_persisted: false,
    plaintext_material_returned: false,
    ...overrides,
  };
}

test("vault bind/list/metadata/status/health/remove commit Rust wallet and cTEE custody records without JS vault truth", () => {
  const state = createState();

  const bound = ModelMountingState.prototype.bindVaultRef.call(state, {
    vault_ref: "vault://provider/custom/api-key",
    material: "custom-secret",
    purpose: "provider.auth:custom",
    label: "Custom auth",
    custody_ref: "ctee://vault/custom",
    authority_grant_refs: ["grant://wallet/vault"],
    authority_receipt_refs: ["receipt://wallet/vault"],
  });
  const listed = ModelMountingState.prototype.listVaultRefs.call(state);
  const metadata = ModelMountingState.prototype.vaultRefMetadata.call(state, {
    vault_ref: "vault://provider/custom/api-key",
  });
  const status = ModelMountingState.prototype.vaultStatus.call(state);
  const health = ModelMountingState.prototype.vaultHealth.call(state);
  const removed = ModelMountingState.prototype.removeVaultRef.call(state, {
    vault_ref: "vault://provider/custom/api-key",
    purpose: "operator_provider_auth_remove:test",
  });

  assert.equal(bound.status, "bound");
  assert.equal(listed.status, "projected");
  assert.equal(metadata.status, "projected");
  assert.equal(status.status, "available");
  assert.equal(health.status, "healthy");
  assert.equal(removed.status, "removed");
  assert.equal(bound.material, undefined);
  assert.equal(bound.record.public_response.material, undefined);
  assert.equal(bound.record.ctee_custody.plaintext_material_persisted, false);
  assert.equal(bound.record.ctee_custody.plaintext_material_returned, false);

  assert.deepEqual(
    state.planCalls.map((call) => call.operation_kind),
    [
      "model_mount.vault_ref.bind",
      "model_mount.vault_ref.list",
      "model_mount.vault_ref.metadata",
      "model_mount.vault.status",
      "model_mount.vault.health",
      "model_mount.vault_ref.remove",
    ],
  );
  assert.equal(state.planCalls[0].schema_version, "ioi.model_mount.vault_control.v1");
  assert.equal(state.planCalls[0].state_dir, state.stateDir);
  assert.equal(state.planCalls[0].vault_ref, "vault://provider/custom/api-key");
  assert.equal(state.planCalls[0].material_hash, `sha256:${stableHash("custom-secret")}`);
  assert.equal(Object.hasOwn(state.planCalls[0].body, "material"), false);
  assert.equal(Object.hasOwn(state.planCalls[0].body, "secret"), false);
  assert.equal(Object.hasOwn(state.planCalls[0].body, "value"), false);
  assert.deepEqual(state.planCalls[0].authority_grant_refs, ["grant://wallet/vault"]);
  assert.deepEqual(state.planCalls[0].authority_receipt_refs, ["receipt://wallet/vault"]);

  assert.equal(state.recordStateCommits.length, 6);
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.record_dir),
    ["vault-refs", "vault-refs", "vault-refs", "vault-refs", "vault-refs", "vault-refs"],
  );
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.operation_kind),
    state.planCalls.map((call) => call.operation_kind),
  );
  assert.equal(
    state.recordStateCommits.every((commit) => commit.record.public_response.material == null),
    true,
  );
  assert.equal(
    state.recordStateCommits.every(
      (commit) => commit.record.rust_core_boundary === "model_mount.vault",
    ),
    true,
  );
  assert.deepEqual(state.calls, []);
});

test("vault operations reject retired request aliases before Rust boundary", () => {
  const state = createState();

  assert.throws(
    () =>
      ModelMountingState.prototype.bindVaultRef.call(state, {
        vaultRef: "vault://provider/custom/api-key",
        secret: "custom-secret",
        value: "custom-secret-alt",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "vault_operation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["vaultRef", "secret", "value"]);
      assert.deepEqual(error.details.canonical_fields, ["vault_ref", "material"]);
      return true;
    },
  );
  assert.deepEqual(state.planCalls, []);

  assert.throws(
    () => ModelMountingState.prototype.vaultRefMetadata.call(
      state,
      { vaultRef: "vault://provider/custom/api-key" },
    ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "vault_operation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["vaultRef"]);
      return true;
    },
  );
  assert.deepEqual(state.planCalls, []);

  assert.throws(
    () => ModelMountingState.prototype.removeVaultRef.call(
      state,
      { vaultRef: "vault://provider/custom/api-key" },
    ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "vault_operation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["vaultRef"]);
      return true;
    },
  );
  assert.deepEqual(state.planCalls, []);
});

test("vault operations preserve required field errors before Rust boundary", () => {
  const state = createState();

  assert.throws(
    () => ModelMountingState.prototype.bindVaultRef.call(
      state,
      { vault_ref: "vault://provider/custom/api-key" },
    ),
    (error) => error.status === 400 && error.details.field === "material",
  );
  assert.throws(
    () => ModelMountingState.prototype.vaultRefMetadata.call(state, {}),
    (error) => error.status === 400 && error.details.field === "vault_ref",
  );
  assert.throws(
    () => ModelMountingState.prototype.removeVaultRef.call(state, {}),
    (error) => error.status === 400 && error.details.field === "vault_ref",
  );
  assert.deepEqual(state.planCalls, []);
  assert.deepEqual(state.recordStateCommits, []);
});
