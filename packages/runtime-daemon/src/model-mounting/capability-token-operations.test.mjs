import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";
import { hashToken } from "./io.mjs";

function createState() {
  const calls = [];
  const receipts = [];
  const recordStateCommits = [];
  const state = {
    calls,
    receipts,
    recordStateCommits,
    tokens: new Map(),
    nowIso() {
      this.timestamped = true;
      return "2026-06-04T14:00:00.000Z";
    },
    walletAuthority: {
      createGrant(token) {
        calls.push({ name: "createGrant", token });
        return token;
      },
      revokeGrant(token) {
        calls.push({ name: "revokeGrant", tokenId: token.id });
        return token;
      },
      authorizeScope(token, requiredScope) {
        calls.push({ name: "authorizeScope", tokenId: token.id, requiredScope });
        return token;
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
        commit_hash: `commit:${request.record_id}`,
      };
    },
  };
  return state;
}

function assertNoCapabilityTokenMutation(state) {
  assert.deepEqual(state.calls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.timestamped, undefined);
}

test("capability token mutation and authorization facades fail closed until Rust wallet authority owns them", () => {
  const createStateValue = createState();

  assert.throws(
    () =>
      ModelMountingState.prototype.createToken.call(
        createStateValue,
        {
          audience: "agent-studio",
          allowed: "model.chat:*",
          denied: ["shell.exec"],
          vault_refs: {
            openai: "vault://provider.openai/api-key",
          },
          expires_at: "2026-06-05T14:00:00.000Z",
          grant_id: "wallet.grant.test",
        },
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_capability_token_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.capability_token.create");
      assert.equal(error.details.rust_core_boundary, "model_mount.capability_token");
      assert.deepEqual(error.details.evidence_refs, [
        "public_capability_token_js_facade_retired",
        "rust_daemon_core_wallet_authority_required",
      ]);
      assert.equal(error.details.audience, "agent-studio");
      assert.equal(error.details.grant_id, "wallet.grant.test");
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      return true;
    },
  );
  assertNoCapabilityTokenMutation(createStateValue);
  assert.equal(createStateValue.tokens.size, 0);

  const token = {
    id: "grant-1",
    audience: "agent-studio",
    allowed: ["model.chat:*"],
    denied: [],
    tokenHash: hashToken("ioi_mnt_test_token"),
    grantId: "wallet.grant.test",
    createdAt: "2026-06-04T14:00:00.000Z",
  };

  const revokeStateValue = createState();
  revokeStateValue.tokens.set(token.id, token);
  assert.throws(
    () => ModelMountingState.prototype.revokeToken.call(revokeStateValue, token.id),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_capability_token_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.capability_token.revoke");
      assert.equal(error.details.token_id, token.id);
      return true;
    },
  );
  assertNoCapabilityTokenMutation(revokeStateValue);
  assert.equal(revokeStateValue.tokens.get(token.id), token);

  const authorizeStateValue = createState();
  authorizeStateValue.tokens.set(token.id, token);
  assert.throws(
    () => ModelMountingState.prototype.authorize.call(
      authorizeStateValue,
      "Bearer ioi_mnt_test_token",
      "model.chat:complete",
    ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_capability_token_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.capability_token.authorize");
      assert.equal(error.details.token_id, token.id);
      assert.equal(error.details.grant_id, "wallet.grant.test");
      assert.equal(error.details.required_scope, "model.chat:complete");
      assert.equal(Object.hasOwn(error.details, "requiredScope"), false);
      return true;
    },
  );
  assertNoCapabilityTokenMutation(authorizeStateValue);
  assert.equal(authorizeStateValue.tokens.get(token.id), token);
});

test("capability token list remains a read-only projection adapter", () => {
  const state = createState();
  state.tokens.set("grant-b", {
    id: "grant-b",
    createdAt: "2026-06-04T14:00:01.000Z",
    tokenHash: "hash:b",
  });
  state.tokens.set("grant-a", {
    id: "grant-a",
    createdAt: "2026-06-04T14:00:00.000Z",
    tokenHash: "hash:a",
  });

  assert.deepEqual(ModelMountingState.prototype.listTokens.call(state).map((token) => token.id), ["grant-a", "grant-b"]);
  assert.equal(
    ModelMountingState.prototype.listTokens.call(state).some((token) => Object.hasOwn(token, "tokenHash")),
    false,
  );
  assertNoCapabilityTokenMutation(state);
});

test("capability token authorization and revoke preserve auth and not-found errors", () => {
  const state = createState();

  assert.throws(
    () => ModelMountingState.prototype.authorize.call(state, "", "model.chat:complete"),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, "auth");
      assert.equal(error.details.required_scope, "model.chat:complete");
      assert.equal(Object.hasOwn(error.details, "requiredScope"), false);
      return true;
    },
  );
  assert.throws(
    () => ModelMountingState.prototype.authorize.call(state, "Bearer missing", "model.chat:complete"),
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
    () => ModelMountingState.prototype.revokeToken.call(state, "missing-token"),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      assert.equal(error.details.token_id, "missing-token");
      assert.equal(Object.hasOwn(error.details, "tokenId"), false);
      return true;
    },
  );
  assertNoCapabilityTokenMutation(state);
});
