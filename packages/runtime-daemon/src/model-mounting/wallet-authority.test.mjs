import assert from "node:assert/strict";
import test from "node:test";

import { AgentgresWalletAuthority } from "./wallet-authority.mjs";

const now = new Date("2026-06-03T00:00:00.000Z");

function authority() {
  return new AgentgresWalletAuthority({
    now: () => now,
  });
}

test("wallet authority resolves vault refs without local operation append", () => {
  const wallet = authority();

  const vault = wallet.resolveVaultRef("vault://provider.openai/api-key");
  assert.equal(typeof vault.vaultRefHash, "string");
  assert.equal(vault.resolvedMaterial, false);
  assert.equal(JSON.stringify(vault).includes("vault://provider.openai/api-key"), false);
  assert.throws(
    () => wallet.resolveVaultRef("plain-secret"),
    (error) => {
      assert.match(error.message, /wallet\.network vault refs/);
      assert.equal(error.details.vault_ref, "[REDACTED]");
      assert.equal(Object.hasOwn(error.details, "vaultRef"), false);
      return true;
    },
  );
});

test("wallet authority adapter status reflects vault-ref boundary only", () => {
  const previous = process.env.IOI_WALLET_NETWORK_URL;
  try {
    delete process.env.IOI_WALLET_NETWORK_URL;
    const unconfigured = authority().adapterStatus();
    assert.equal(unconfigured.remoteAdapter.configured, false);
    assert.equal(unconfigured.implementation, "wallet_network_vault_ref_boundary");
    assert.deepEqual(unconfigured.methods, ["resolveVaultRef", "auditEvent"]);
    assert.deepEqual(unconfigured.evidenceRefs, ["wallet.network.vault_ref_boundary"]);

    process.env.IOI_WALLET_NETWORK_URL = "https://wallet.example";
    const status = authority().adapterStatus();
    assert.equal(status.remoteAdapter.configured, true);
    assert.equal(typeof status.remoteAdapter.urlHash, "string");
  } finally {
    if (previous === undefined) {
      delete process.env.IOI_WALLET_NETWORK_URL;
    } else {
      process.env.IOI_WALLET_NETWORK_URL = previous;
    }
  }
});
