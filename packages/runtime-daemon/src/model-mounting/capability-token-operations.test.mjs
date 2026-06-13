import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";
import { hashToken } from "./io.mjs";

const CAPABILITY_TOKEN_EVIDENCE_REFS = [
  "rust_daemon_core_capability_token_control",
  "wallet_network_capability_token_authority_required",
  "agentgres_capability_token_truth_required",
  "public_capability_token_js_facade_retired",
];

function createState() {
  const planCalls = [];
  const recordStateCommits = [];
  const legacyToken = {
    id: "legacy-js-token",
    tokenHash: "sha256:legacy-js-token",
  };
  const state = {
    planCalls,
    recordStateCommits,
    stateDir: "/tmp/ioi-model-mount-state",
    tokens: new Map([[legacyToken.id, legacyToken]]),
    walletAuthority: {
      createGrant() {
        throw new Error("JS walletAuthority.createGrant must not authorize capability tokens.");
      },
      revokeGrant() {
        throw new Error("JS walletAuthority.revokeGrant must not authorize capability tokens.");
      },
      authorizeScope() {
        throw new Error("JS walletAuthority.authorizeScope must not authorize capability tokens.");
      },
    },
    nowIso() {
      return "2026-06-13T12:00:00.000Z";
    },
    planCapabilityTokenControl(request) {
      planCalls.push(request);
      return capabilityTokenPlan(request);
    },
    commitRuntimeModelMountRecordState(request) {
      recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `model_mount://capability_token_control/${request.record_id}`,
        content_hash: `sha256:content:${request.record_id}`,
        admission_hash: `sha256:admission:${request.record_id}`,
        commit_hash: `sha256:commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `model_mount://capability_token_control/${request.record_id}`,
          content_hash: `sha256:content:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.record_id}`,
          },
        },
      };
    },
  };
  return { legacyToken, state };
}

function capabilityTokenPlan(request) {
  const tokenId = request.token_id ?? "capability_token:test";
  const basePublicResponse = publicResponseFor(request, tokenId);
  const recordPublicResponse = {
    ...basePublicResponse,
    plaintext_material_persisted: false,
  };
  delete recordPublicResponse.token;
  const recordId = `capability_token_control:${tokenId}:${request.operation_kind.split(".").at(-1)}`;
  const record = {
    id: recordId,
    record_id: recordId,
    object: "ioi.model_mount_capability_token_control",
    status: "planned",
    operation_kind: request.operation_kind,
    token_id: tokenId,
    token_hash: request.token_hash ?? hashToken("ioi_mnt_positive_token"),
    rust_core_boundary: "model_mount.capability_token",
    wallet_authority_boundary: "wallet.network.capability_token",
    capability_token_authority: {
      authority_hash: "sha256:capability-token-authority",
      required_scope: request.required_scope ?? null,
      authority_grant_refs: request.authority_grant_refs,
      authority_receipt_refs: request.authority_receipt_refs,
    },
    public_response: recordPublicResponse,
    receipt_refs: ["receipt://model_mount/capability_token/test"],
    evidence_refs: CAPABILITY_TOKEN_EVIDENCE_REFS,
    control_hash: "sha256:capability-token-control",
    planned_at: request.generated_at,
  };
  return {
    schema_version: "ioi.model_mount.capability_token_control_plan.v1",
    object: "ioi.model_mount_capability_token_control_plan",
    status: "planned",
    rust_core_boundary: "model_mount.capability_token",
    operation_kind: request.operation_kind,
    source: request.source,
    record_dir: "capability-tokens",
    record_id: recordId,
    record,
    public_response: basePublicResponse,
    receipt_refs: record.receipt_refs,
    authority_grant_refs: request.authority_grant_refs,
    authority_receipt_refs: request.authority_receipt_refs,
    evidence_refs: CAPABILITY_TOKEN_EVIDENCE_REFS,
    control_hash: "sha256:capability-token-control",
    authority_hash: "sha256:capability-token-authority",
  };
}

function publicResponseFor(request, tokenId) {
  if (request.operation_kind === "model_mount.capability_token.create") {
    return {
      object: "ioi.model_mount_capability_token",
      status: "issued",
      token_id: tokenId,
      token: "ioi_mnt_positive_token",
      token_material_returned_once: true,
      token_hash: hashToken("ioi_mnt_positive_token"),
      audience: request.body.audience,
      grant_id: request.body.grant_id,
      allowed_scopes: request.body.allowed,
      denied_scopes: request.body.denied,
    };
  }
  if (request.operation_kind === "model_mount.capability_token.list") {
    return {
      object: "ioi.model_mount_capability_token_list",
      status: "projected",
      tokens: [{ token_id: tokenId, status: "active" }],
    };
  }
  if (request.operation_kind === "model_mount.capability_token.authorize") {
    return {
      object: "ioi.model_mount_capability_token_authorization",
      status: "authorized",
      token_id: tokenId,
      required_scope: request.required_scope,
    };
  }
  return {
    object: "ioi.model_mount_capability_token_revocation",
    status: "revoked",
    token_id: tokenId,
  };
}

test("capability token create/list/authorize/revoke commit Rust wallet authority records without JS token truth", () => {
  const { legacyToken, state } = createState();

  const created = ModelMountingState.prototype.createToken.call(state, {
    audience: "agent-studio",
    allowed: ["model.chat:*"],
    denied: ["shell.exec"],
    expires_at: "2026-06-14T12:00:00.000Z",
    grant_id: "grant://wallet/capability",
    authority_grant_refs: ["grant://wallet/capability"],
    authority_receipt_refs: ["receipt://wallet/capability"],
  });
  const authorized = ModelMountingState.prototype.authorize.call(
    state,
    `Bearer ${created.token}`,
    "model.chat:complete",
  );
  const listed = ModelMountingState.prototype.listTokens.call(state);
  const revoked = ModelMountingState.prototype.revokeToken.call(state, created.token_id);

  assert.equal(created.status, "issued");
  assert.equal(created.token, "ioi_mnt_positive_token");
  assert.equal(created.record.public_response.token, undefined);
  assert.equal(created.record.public_response.plaintext_material_persisted, false);
  assert.equal(authorized.status, "authorized");
  assert.equal(listed.status, "projected");
  assert.equal(revoked.status, "revoked");

  assert.deepEqual(
    state.planCalls.map((call) => call.operation_kind),
    [
      "model_mount.capability_token.create",
      "model_mount.capability_token.authorize",
      "model_mount.capability_token.list",
      "model_mount.capability_token.revoke",
    ],
  );
  assert.equal(state.planCalls[0].schema_version, "ioi.model_mount.capability_token_control.v1");
  assert.equal(state.planCalls[0].state_dir, state.stateDir);
  assert.deepEqual(state.planCalls[0].authority_grant_refs, ["grant://wallet/capability"]);
  assert.deepEqual(state.planCalls[0].authority_receipt_refs, ["receipt://wallet/capability"]);
  assert.equal(state.planCalls[1].token_hash, hashToken("ioi_mnt_positive_token"));
  assert.equal(state.planCalls[1].required_scope, "model.chat:complete");
  assert.equal(state.planCalls[3].token_id, "capability_token:test");

  assert.equal(state.recordStateCommits.length, 4);
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.record_dir),
    ["capability-tokens", "capability-tokens", "capability-tokens", "capability-tokens"],
  );
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.operation_kind),
    state.planCalls.map((call) => call.operation_kind),
  );
  assert.equal(
    state.recordStateCommits.every((commit) => commit.record.public_response.token == null),
    true,
  );
  assert.equal(
    state.recordStateCommits.every(
      (commit) => commit.record.rust_core_boundary === "model_mount.capability_token",
    ),
    true,
  );
  assert.equal(state.tokens.size, 1);
  assert.equal(state.tokens.get(legacyToken.id), legacyToken);
});

test("capability token authorization preserves Bearer preflight before Rust boundary", () => {
  const { state } = createState();

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
    () => ModelMountingState.prototype.authorize.call(state, "Bearer ", "model.chat:complete"),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, "auth");
      assert.equal(error.details.required_scope, "model.chat:complete");
      return true;
    },
  );
  assert.deepEqual(state.planCalls, []);
  assert.deepEqual(state.recordStateCommits, []);
});
