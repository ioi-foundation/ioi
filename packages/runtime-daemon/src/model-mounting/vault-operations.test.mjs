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

function createState() {
  const calls = [];
  const receipts = [];
  const metadata = new Map();
  const state = {
    calls,
    receipts,
    vault: {
      bindVaultRef(record) {
        calls.push({ name: "bindVaultRef", record });
        const result = {
          vaultRefHash: `hash:${record.vaultRef}`,
          configured: true,
          label: record.label,
          purpose: record.purpose,
        };
        metadata.set(record.vaultRef, result);
        return result;
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
        metadata.delete(vaultRef);
        return {
          vaultRefHash: `hash:${vaultRef}`,
          configured: false,
          purpose,
        };
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
    writeVaultRefs() {
      calls.push({ name: "writeVaultRefs" });
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
    vaultRef: "vault://provider/custom/api-key",
    secret: "custom-secret",
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
    ["bindVaultRef", "writeVaultRefs", "writeProjection"],
  );

  assert.deepEqual(listVaultRefs(state), [{
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
    vaultRef: "vault://provider/custom/api-key",
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
    vaultRef: "vault://provider/custom/api-key",
    purpose: "operator_provider_auth_remove:test",
  });
  assert.equal(removed.configured, false);
  assert.equal(removed.receiptId, "receipt-2");
  assert.equal(state.receipts[1].kind, "vault_ref_removal");
  assert.deepEqual(
    state.calls.map((call) => call.name),
    ["adapterStatus", "health", "removeVaultRef", "writeVaultRefs", "writeProjection"],
  );
  assert.equal(listVaultRefs(state).length, 0);
});

test("vault operations preserve required field errors", () => {
  const state = createState();

  assert.throws(
    () => bindVaultRef(state, { vaultRef: "vault://provider/custom/api-key" }),
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
