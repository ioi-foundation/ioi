import assert from "node:assert/strict";
import test from "node:test";

import {
  EXTERNAL_CAPABILITY_AUTHORITY_RESPONSE_SCHEMA_VERSION,
  createRuntimeExternalCapabilityAuthoritySurface,
} from "./runtime-external-capability-authority-surface.mjs";

function authorityRequest() {
  return {
    schema_version: "ioi.external_capability_exit_authority.v1",
    exit_ref: "exit://aiip/slack-post-message",
    capability_ref: "capability://connector/slack.postMessage",
    target_ref: "aiip://workspace/channel/runtime",
    policy_hash: "sha256:external-capability-policy",
    idempotency_key: "idem:external-capability-exit",
    authority_grant_refs: [
      "wallet.network://grant/external-capability/slack-post-message",
    ],
    authority_receipt_refs: [
      "receipt://wallet.network/authority/slack-post-message",
    ],
  };
}

function store() {
  const calls = [];
  return {
    calls,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_surface" };
    },
    externalCapabilityAuthorityRunner: {
      authorizeExit(input) {
        calls.push({ name: "authorizeExit", input });
        return {
          source: "rust_external_capability_exit_authority_command",
          backend: "rust_authority",
          authority: {
            ...input,
            wallet_network_grant_refs: input.authority_grant_refs,
            authority_hash: "sha256:external-capability-authority",
          },
          wallet_network_grant_refs: input.authority_grant_refs,
          authority_receipt_refs: input.authority_receipt_refs,
          authority_hash: "sha256:external-capability-authority",
        };
      },
    },
  };
}

const EXTERNAL_CAPABILITY_AUTHORITY_CAMEL_ALIASES = [
  "schemaVersion",
  "exitAuthorized",
  "directTruthWriteAllowed",
  "threadId",
  "agentId",
  "exitRef",
  "capabilityRef",
  "targetRef",
  "policyHash",
  "idempotencyKey",
  "walletNetworkGrantRefs",
  "authorityReceiptRefs",
  "authorityHash",
];

test("external capability authority surface authorizes nested request through Rust runner", () => {
  const runtimeStore = store();
  const surface = createRuntimeExternalCapabilityAuthoritySurface();

  const result = surface.authorizeExternalCapabilityExit(runtimeStore, "thread_surface", {
    request: authorityRequest(),
  });

  assert.equal(result.schema_version, EXTERNAL_CAPABILITY_AUTHORITY_RESPONSE_SCHEMA_VERSION);
  assert.equal(result.status, "authorized");
  assert.equal(result.exit_authorized, true);
  assert.equal(result.direct_truth_write_allowed, false);
  assert.equal(result.thread_id, "thread_surface");
  assert.equal(result.agent_id, "agent_surface");
  assert.equal(result.exit_ref, "exit://aiip/slack-post-message");
  assert.equal(result.capability_ref, "capability://connector/slack.postMessage");
  assert.equal(result.target_ref, "aiip://workspace/channel/runtime");
  assert.equal(result.policy_hash, "sha256:external-capability-policy");
  assert.equal(result.idempotency_key, "idem:external-capability-exit");
  assert.deepEqual(result.wallet_network_grant_refs, [
    "wallet.network://grant/external-capability/slack-post-message",
  ]);
  assert.deepEqual(result.authority_receipt_refs, [
    "receipt://wallet.network/authority/slack-post-message",
  ]);
  assert.equal(result.authority_hash, "sha256:external-capability-authority");
  assert.deepEqual(runtimeStore.calls.map((call) => call.name), ["agentForThread", "authorizeExit"]);
});

test("external capability authority surface rejects retired aliases before Rust runner", () => {
  const runtimeStore = store();
  const surface = createRuntimeExternalCapabilityAuthoritySurface();

  assert.throws(
    () =>
      surface.authorizeExternalCapabilityExit(runtimeStore, "thread_surface", {
        authority_request: authorityRequest(),
        authorityRequest: authorityRequest(),
        capability_exit: authorityRequest(),
        capabilityExit: authorityRequest(),
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "external_capability_authority_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authorityRequest",
        "authority_request",
        "capabilityExit",
        "capability_exit",
      ]);
      assert.deepEqual(error.details.canonical_fields, ["request"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("external capability authority surface exposes only canonical snake_case fields", () => {
  const result = createRuntimeExternalCapabilityAuthoritySurface().authorizeExternalCapabilityExit(
    store(),
    "thread_surface",
    { request: authorityRequest() },
  );

  for (const key of EXTERNAL_CAPABILITY_AUTHORITY_CAMEL_ALIASES) {
    assert.equal(Object.hasOwn(result, key), false, `${key} must not be emitted`);
  }
});

test("external capability authority surface fails closed without request payload", () => {
  const surface = createRuntimeExternalCapabilityAuthoritySurface();

  assert.throws(
    () => surface.authorizeExternalCapabilityExit(store(), "thread_surface", {}),
    (error) => error.code === "external_capability_authority_request_required",
  );
});
