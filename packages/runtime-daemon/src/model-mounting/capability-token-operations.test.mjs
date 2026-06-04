import assert from "node:assert/strict";
import test from "node:test";

import {
  authorize,
  createToken,
  listTokens,
  revokeToken,
} from "./capability-token-operations.mjs";

function createState() {
  const calls = [];
  const receipts = [];
  const now = new Date("2026-06-04T14:00:00.000Z");
  const state = {
    calls,
    receipts,
    tokens: new Map(),
    now: () => now,
    nowIso: () => now.toISOString(),
    walletAuthority: {
      createGrant(token) {
        calls.push({ name: "createGrant", token });
        return {
          ...token,
          authority: "agentgres_wallet_authority",
          walletNetworkShape: {
            grantId: token.grantId,
            revocationEpoch: token.revocationEpoch,
            vaultRefs: token.vaultRefs,
          },
        };
      },
      revokeGrant(token) {
        calls.push({ name: "revokeGrant", tokenId: token.id });
        return {
          ...token,
          revokedAt: "2026-06-04T14:00:00.000Z",
          revocationEpoch: Number(token.revocationEpoch ?? 0) + 1,
        };
      },
      authorizeScope(token, requiredScope) {
        calls.push({ name: "authorizeScope", tokenId: token.id, requiredScope });
        return {
          ...token,
          lastUsedAt: "2026-06-04T14:00:00.000Z",
          lastUsedScope: requiredScope,
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
    writeMap(dir, map) {
      calls.push({ name: "writeMap", dir, size: map.size });
    },
  };
  return state;
}

const deps = {
  generateTokenValue: () => "ioi_mnt_test_token",
  hashToken: (value) => `hash:${value}`,
  randomUUID: (() => {
    let index = 0;
    return () => {
      index += 1;
      return `uuid-${index}`;
    };
  })(),
};

test("capability token operations create public token envelopes and persist grants", () => {
  const state = createState();

  const result = createToken(state, {
    audience: "agent-studio",
    allowed: "model.chat:*",
    denied: ["shell.exec"],
    vaultRefs: {
      openai: "vault://provider.openai/api-key",
      unsafe: "plain-secret",
    },
    expiresAt: "2026-06-05T14:00:00.000Z",
  }, deps);
  const stored = state.tokens.get("grant_uuid-1");

  assert.equal(result.id, "grant_uuid-1");
  assert.equal(result.audience, "agent-studio");
  assert.deepEqual(result.allowed, ["model.chat:*"]);
  assert.deepEqual(result.denied, ["shell.exec"]);
  assert.equal(result.token, "ioi_mnt_test_token");
  assert.equal(result.receiptId, "receipt-1");
  assert.equal(result.tokenHash, undefined);
  assert.equal(JSON.stringify(result).includes("vault://provider.openai/api-key"), false);
  assert.equal(stored.tokenHash, "hash:ioi_mnt_test_token");
  assert.equal(stored.grantId, "wallet.grant.uuid-2");
  assert.equal(state.receipts[0].kind, "permission_token");
  assert.equal(state.receipts[0].redaction, "redacted");
  assert.deepEqual(state.receipts[0].evidenceRefs, [
    "wallet.network.capability_grant",
    "wallet.grant.uuid-2",
  ]);
  assert.equal(state.calls.some((call) => call.name === "writeMap" && call.dir === "tokens"), true);
});

test("capability token operations list, authorize, and revoke tokens", () => {
  const state = createState();
  const first = createToken(state, { audience: "b", expiresAt: "2026-06-05T14:00:00.000Z" }, deps);
  const second = createToken(
    state,
    {
      audience: "a",
      allowed: ["model.responses:*"],
      expiresAt: "2026-06-05T14:00:00.000Z",
    },
    {
      ...deps,
      generateTokenValue: () => "ioi_mnt_second",
    },
  );

  assert.deepEqual(listTokens(state).map((token) => token.id), [first.id, second.id]);

  const authorized = authorize(state, "Bearer ioi_mnt_second", "model.responses:create", {
    hashToken: (value) => `hash:${value}`,
  });
  assert.equal(authorized.id, second.id);
  assert.equal(authorized.lastUsedScope, "model.responses:create");
  assert.equal(state.tokens.get(second.id).lastUsedAt, "2026-06-04T14:00:00.000Z");

  const revoked = revokeToken(state, second.id);
  assert.equal(revoked.revocationEpoch, 1);
  assert.equal(revoked.revokedAt, "2026-06-04T14:00:00.000Z");
  assert.equal(state.receipts.at(-1).kind, "permission_token_revocation");
  assert.equal(state.receipts.at(-1).redaction, "redacted");
});

test("capability token operations preserve auth and not-found errors", () => {
  const state = createState();
  createToken(state, { expiresAt: "2026-06-05T14:00:00.000Z" }, deps);

  assert.throws(
    () => authorize(state, "", "model.chat:complete", { hashToken: (value) => `hash:${value}` }),
    (error) =>
      error.status === 401 &&
      error.code === "auth" &&
      error.details.requiredScope === "model.chat:complete",
  );
  assert.throws(
    () => authorize(state, "Bearer missing", "model.chat:complete", { hashToken: (value) => `hash:${value}` }),
    (error) =>
      error.status === 401 &&
      error.code === "auth" &&
      error.message === "Capability token was not recognized.",
  );
  assert.throws(
    () => revokeToken(state, "missing-token"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.tokenId === "missing-token",
  );
});
