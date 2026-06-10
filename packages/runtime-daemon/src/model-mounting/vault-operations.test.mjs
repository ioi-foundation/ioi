import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function createState() {
  const calls = [];
  const receipts = [];
  const metadata = new Map();
  const state = {
    calls,
    recordStateCommits: [],
    receipts,
    vault: {
      bindVaultRef(record) {
        calls.push({ name: "bindVaultRef", record });
        const result = {
          vaultRefHash: `hash:${record.vaultRef}`,
          id: `vault_ref.hash:${record.vaultRef}`,
          configured: true,
          label: record.label,
          purpose: record.purpose,
        };
        metadata.set(record.vaultRef, result);
        return result;
      },
      metadataRecords() {
        return [...metadata.values()];
      },
      listVaultRefs() {
        calls.push({ name: "listVaultRefs" });
        return [...metadata.values()];
      },
      vaultRefMetadata(vaultRef) {
        calls.push({ name: "vaultRefMetadata", vaultRef });
        return metadata.get(vaultRef) ?? null;
      },
      adapterStatus() {
        calls.push({ name: "adapterStatus" });
        return {
          implementation: "runtime_memory_vault",
          configured: true,
          failClosed: false,
        };
      },
      health() {
        calls.push({ name: "health" });
        return {
          status: "healthy",
          evidenceRefs: ["VaultPort.health"],
        };
      },
      removeVaultRef(vaultRef, purpose) {
        calls.push({ name: "removeVaultRef", vaultRef, purpose });
        const result = {
          vaultRefHash: `hash:${vaultRef}`,
          id: `vault_ref.hash:${vaultRef}`,
          configured: false,
          purpose,
        };
        metadata.set(vaultRef, result);
        return result;
      },
    },
    receipt(kind, payload) {
      const receipt = {
        id: `receipt-${receipts.length + 1}`,
        kind,
        ...payload,
      };
      receipts.push(receipt);
      return receipt;
    },
    commitRuntimeModelMountRecordState(request) {
      calls.push({ name: "commitRuntimeModelMountRecordState", request });
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
    writeVaultRefs() {
      calls.push({ name: "writeVaultRefs" });
    },
    writeProjection() {
      calls.push({ name: "writeProjection" });
    },
  };
  return state;
}

function assertNoVaultMutation(state) {
  assert.deepEqual(state.calls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
}

test("vault mutation and health receipt facades fail closed until Rust wallet/cTEE custody owns them", () => {
  const state = createState();

  assert.throws(
    () =>
      ModelMountingState.prototype.bindVaultRef.call(
        state,
        {
          vault_ref: "vault://provider/custom/api-key",
          material: "custom-secret",
          purpose: "provider.auth:custom",
          label: "Custom auth",
        },
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_vault_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.vault_ref.bind");
      assert.equal(error.details.rust_core_boundary, "model_mount.vault");
      assert.deepEqual(error.details.evidence_refs, [
        "public_vault_js_facade_retired",
        "rust_daemon_core_wallet_vault_required",
        "rust_daemon_core_ctee_custody_required",
      ]);
      assert.equal(error.details.vault_ref_hash_required, true);
      assert.equal(error.details.vault_ref_present, true);
      assert.equal(error.details.material, "[redacted]");
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "vaultRef"), false);
      return true;
    },
  );
  assertNoVaultMutation(state);

  assert.throws(
    () => ModelMountingState.prototype.vaultHealth.call(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_vault_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.vault.health");
      return true;
    },
  );
  assertNoVaultMutation(state);

  assert.throws(
    () =>
      ModelMountingState.prototype.removeVaultRef.call(
        state,
        {
          vault_ref: "vault://provider/custom/api-key",
          purpose: "operator_provider_auth_remove:test",
        },
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_vault_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.vault_ref.remove");
      assert.equal(error.details.vault_ref_hash_required, true);
      assert.equal(error.details.purpose, "operator_provider_auth_remove:test");
      assert.equal(error.details.vault_ref_present, true);
      return true;
    },
  );
  assertNoVaultMutation(state);
});

test("vault list, metadata, and status fail closed until Rust wallet/cTEE projection owns them", () => {
  const state = createState();
  state.vault.bindVaultRef({
    vaultRef: "vault://provider/custom/api-key",
    material: "custom-secret",
    purpose: "provider.auth:custom",
    label: "Custom auth",
  });
  state.calls.length = 0;

  assert.throws(
    () => ModelMountingState.prototype.listVaultRefs.call(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_vault_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.vault_ref.list");
      assert.equal(error.details.rust_core_boundary, "model_mount.vault");
      return true;
    },
  );
  assert.throws(
    () =>
      ModelMountingState.prototype.vaultRefMetadata.call(
        state,
        { vault_ref: "vault://provider/custom/api-key" },
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_vault_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.vault_ref.metadata");
      assert.equal(error.details.vault_ref_hash_required, true);
      assert.equal(error.details.vault_ref_present, true);
      return true;
    },
  );
  assert.throws(
    () => ModelMountingState.prototype.vaultStatus.call(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_vault_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.vault.status");
      return true;
    },
  );
  assert.deepEqual(state.calls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("vault operations reject retired request aliases before vault access", () => {
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
  assert.deepEqual(state.calls, []);

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
  assert.deepEqual(state.calls, []);

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
  assert.deepEqual(state.calls, []);
});

test("vault operations preserve required field errors", () => {
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
});
