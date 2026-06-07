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
  const recordStateCommits = [];
  const now = new Date("2026-06-04T14:00:00.000Z");
  const state = {
    calls,
    receipts,
    recordStateCommits,
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
    commitRuntimeModelMountRecordState(request) {
      recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.record_id}`,
        admission_hash: `admit:${request.record_id}`,
        commit_hash: `commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.record_id}`,
          admission: { admission_hash: `admit:${request.record_id}` },
        },
      };
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
  assert.equal(state.calls.some((call) => call.name === "writeMap" && call.dir === "tokens"), false);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "tokens");
  assert.equal(state.recordStateCommits[0].record_id, "grant_uuid-1");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.capability_token.create");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt-1"]);
  assert.equal(state.recordStateCommits[0].record.tokenHash, "hash:ioi_mnt_test_token");
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
  assert.equal(state.recordStateCommits.at(-1).operation_kind, "model_mount.capability_token.authorize");
  assert.deepEqual(state.recordStateCommits.at(-1).receipt_refs, [second.receiptId]);

  const revoked = revokeToken(state, second.id);
  assert.equal(revoked.revocationEpoch, 1);
  assert.equal(revoked.revokedAt, "2026-06-04T14:00:00.000Z");
  assert.equal(state.receipts.at(-1).kind, "permission_token_revocation");
  assert.equal(state.receipts.at(-1).redaction, "redacted");
  assert.equal(state.recordStateCommits.at(-1).operation_kind, "model_mount.capability_token.revoke");
  assert.deepEqual(state.recordStateCommits.at(-1).receipt_refs, [second.receiptId, "receipt-3"]);
  assert.deepEqual(state.tokens.get(second.id).auditReceiptIds, ["receipt-3"]);
});

test("capability token state persistence fails closed without Rust Agentgres record-state commit", () => {
  const state = createState();
  delete state.commitRuntimeModelMountRecordState;
  const localDeps = {
    ...deps,
    randomUUID: (() => {
      let index = 0;
      return () => {
        index += 1;
        return `local-uuid-${index}`;
      };
    })(),
  };

  assert.throws(
    () => createToken(state, { expiresAt: "2026-06-05T14:00:00.000Z" }, localDeps),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_capability_token_state_commit_unconfigured");
      assert.equal(error.details.token_id, "grant_local-uuid-1");
      assert.equal(error.details.grant_id, "wallet.grant.local-uuid-2");
      assert.equal(error.details.receipt_id, "receipt-1");
      assert.equal(Object.hasOwn(error.details, "tokenId"), false);
      assert.equal(Object.hasOwn(error.details, "grantId"), false);
      assert.equal(Object.hasOwn(error.details, "receiptId"), false);
      return true;
    },
  );
  assert.equal(state.tokens.size, 0);
});

test("capability token operations preserve auth and not-found errors", () => {
  const state = createState();
  createToken(state, { expiresAt: "2026-06-05T14:00:00.000Z" }, deps);

  assert.throws(
    () => authorize(state, "", "model.chat:complete", { hashToken: (value) => `hash:${value}` }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, "auth");
      assert.equal(error.details.required_scope, "model.chat:complete");
      assert.equal(Object.hasOwn(error.details, "requiredScope"), false);
      return true;
    },
  );
  assert.throws(
    () => authorize(state, "Bearer missing", "model.chat:complete", { hashToken: (value) => `hash:${value}` }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, "auth");
      assert.equal(error.message, "Capability token was not recognized.");
      assert.equal(error.details.required_scope, "model.chat:complete");
      assert.equal(Object.hasOwn(error.details, "requiredScope"), false);
      return true;
    },
  );
  assert.throws(
    () => revokeToken(state, "missing-token"),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      assert.equal(error.details.token_id, "missing-token");
      assert.equal(Object.hasOwn(error.details, "tokenId"), false);
      return true;
    },
  );
});
