import assert from "node:assert/strict";
import test from "node:test";

import { AgentgresWalletAuthority } from "./wallet-authority.mjs";

const now = new Date("2026-06-03T00:00:00.000Z");

function authority(operations = []) {
  return new AgentgresWalletAuthority({
    now: () => now,
    appendOperation: (kind, payload) => operations.push({ kind, payload }),
  });
}

function token(fields = {}) {
  return {
    id: "token-a",
    grantId: "grant-a",
    revocationEpoch: 0,
    allowed: ["model.chat:*"],
    denied: ["shell.exec"],
    expiresAt: "2026-06-04T00:00:00.000Z",
    vaultRefs: {},
    ...fields,
  };
}

test("wallet authority creates grants and records authorization use", () => {
  const operations = [];
  const wallet = authority(operations);
  const grant = wallet.createGrant(token());

  assert.equal(grant.authority, "agentgres_wallet_authority");
  assert.equal(grant.walletNetworkShape.grantId, "grant-a");
  assert.equal(operations[0].kind, "wallet.grant.create");

  const authorized = wallet.authorizeScope(grant, "model.chat:complete");
  assert.equal(authorized.lastUsedAt, "2026-06-03T00:00:00.000Z");
  assert.equal(authorized.lastUsedScope, "model.chat:complete");
  assert.ok(operations.some((operation) => operation.kind === "wallet.scope.authorize"));
});

test("wallet authority rejects denied, expired, and revoked grants", () => {
  const wallet = authority();

  assert.throws(
    () => wallet.authorizeScope(token(), "shell.exec"),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.match(error.message, /does not grant/);
      return true;
    },
  );

  assert.throws(
    () => wallet.authorizeScope(token({ expiresAt: "2026-06-02T00:00:00.000Z" }), "model.chat:complete"),
    (error) => {
      assert.equal(error.status, 403);
      assert.match(error.message, /expired/);
      return true;
    },
  );

  assert.throws(
    () => wallet.authorizeScope(token({ revokedAt: "2026-06-02T00:00:00.000Z" }), "model.chat:complete"),
    (error) => {
      assert.equal(error.status, 403);
      assert.match(error.message, /revoked/);
      return true;
    },
  );
});

test("wallet authority revokes grants and redacts vault refs in audit operations", () => {
  const operations = [];
  const wallet = authority(operations);
  const revoked = wallet.revokeGrant(token());

  assert.equal(revoked.revocationEpoch, 1);
  assert.equal(revoked.revokedAt, "2026-06-03T00:00:00.000Z");

  const vault = wallet.resolveVaultRef("vault://provider.openai/api-key");
  assert.equal(typeof vault.vaultRefHash, "string");
  assert.equal(vault.resolvedMaterial, false);

  const audit = operations.find((operation) => operation.kind === "wallet.vault.resolve");
  assert.ok(audit);
  assert.match(audit.payload.objectId, /^vault_ref_[a-f0-9]+$/);
  assert.equal(JSON.stringify(audit).includes("vault://provider.openai/api-key"), false);
});

test("wallet authority adapter status reflects remote boundary", () => {
  const previous = process.env.IOI_WALLET_NETWORK_URL;
  try {
    delete process.env.IOI_WALLET_NETWORK_URL;
    assert.equal(authority().adapterStatus().remoteAdapter.configured, false);

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
