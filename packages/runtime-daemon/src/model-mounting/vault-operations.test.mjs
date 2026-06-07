import assert from "node:assert/strict";
import test from "node:test";

import {
  bindVaultRef,
  listVaultRefs,
  removeVaultRef,
  vaultHealth,
  vaultRefMetadata,
  vaultStatus,
} from "./vault-operations.mjs";
import { writeModelMountingVaultRefs } from "./state-persistence.mjs";

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
      writeModelMountingVaultRefs(this);
    },
    writeProjection() {
      calls.push({ name: "writeProjection" });
    },
  };
  return state;
}

test("vault operations bind refs, persist metadata, and emit redacted receipts", () => {
  const state = createState();

  const result = bindVaultRef(state, {
    vault_ref: "vault://provider/custom/api-key",
    material: "custom-secret",
    purpose: "provider.auth:custom",
    label: "Custom auth",
  });

  assert.equal(result.vaultRefHash, "hash:vault://provider/custom/api-key");
  assert.equal(result.configured, true);
  assert.equal(result.receiptId, "receipt-1");
  assert.equal(state.receipts[0].kind, "vault_ref_binding");
  assert.equal(state.receipts[0].redaction, "redacted");
  assert.deepEqual(state.receipts[0].evidenceRefs, [
    "VaultPort.bindVaultRef",
    "hash:vault://provider/custom/api-key",
  ]);
  assert.deepEqual(
    state.calls.map((call) => call.name),
    ["bindVaultRef", "writeVaultRefs", "commitRuntimeModelMountRecordState", "writeProjection"],
  );
  assert.equal(state.recordStateCommits[0].record_dir, "vault-refs");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.vault_ref.write");

  assert.deepEqual(listVaultRefs(state), [{
    id: "vault_ref.hash:vault://provider/custom/api-key",
    vaultRefHash: "hash:vault://provider/custom/api-key",
    configured: true,
    label: "Custom auth",
    purpose: "provider.auth:custom",
  }]);
  assert.equal(
    vaultRefMetadata(state, { vault_ref: "vault://provider/custom/api-key" }).label,
    "Custom auth",
  );
});

test("vault operations project status, health receipt, and removal receipt", () => {
  const state = createState();
  bindVaultRef(state, {
    vault_ref: "vault://provider/custom/api-key",
    material: "custom-secret",
  });
  state.calls.length = 0;
  state.receipts.length = 0;

  const status = vaultStatus(state);
  assert.equal(status.implementation, "runtime_memory_vault");
  assert.equal(status.configured, true);

  const health = vaultHealth(state);
  assert.equal(health.status, "healthy");
  assert.equal(health.receiptId, "receipt-1");
  assert.equal(state.receipts[0].kind, "vault_adapter_health");
  assert.deepEqual(state.receipts[0].evidenceRefs, ["VaultPort.health"]);

  const removed = removeVaultRef(state, {
    vault_ref: "vault://provider/custom/api-key",
    purpose: "operator_provider_auth_remove:test",
  });
  assert.equal(removed.configured, false);
  assert.equal(removed.receiptId, "receipt-2");
  assert.equal(state.receipts[1].kind, "vault_ref_removal");
  assert.deepEqual(
    state.calls.map((call) => call.name),
    ["adapterStatus", "health", "removeVaultRef", "writeVaultRefs", "commitRuntimeModelMountRecordState", "writeProjection"],
  );
  assert.equal(listVaultRefs(state).length, 1);
  assert.equal(listVaultRefs(state)[0].configured, false);
});

test("vault operations reject retired request aliases before vault access", () => {
  const state = createState();

  assert.throws(
    () =>
      bindVaultRef(state, {
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
    () => vaultRefMetadata(state, { vaultRef: "vault://provider/custom/api-key" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "vault_operation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["vaultRef"]);
      return true;
    },
  );
  assert.deepEqual(state.calls, []);

  assert.throws(
    () => removeVaultRef(state, { vaultRef: "vault://provider/custom/api-key" }),
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
    () => bindVaultRef(state, { vault_ref: "vault://provider/custom/api-key" }),
    (error) => error.status === 400 && error.details.field === "material",
  );
  assert.throws(
    () => vaultRefMetadata(state, {}),
    (error) => error.status === 400 && error.details.field === "vault_ref",
  );
  assert.throws(
    () => removeVaultRef(state, {}),
    (error) => error.status === 400 && error.details.field === "vault_ref",
  );
});
