import assert from "node:assert/strict";
import test from "node:test";

import {
  EXTERNAL_CAPABILITY_AUTHORITY_CORE_SCHEMA_VERSION,
  RUNTIME_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
  RuntimeExternalCapabilityAuthorityCore,
  RuntimeExternalCapabilityAuthorityCoreError,
  createRuntimeExternalCapabilityAuthorityCore,
} from "./runtime-external-capability-authority-core.mjs";

function externalCapabilityExitRequest() {
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

function authorizedResult(request) {
  return {
    source: "rust_external_capability_exit_authority_command",
    backend: RUNTIME_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
    schema_version: "ioi.runtime.external_capability_authority.v1",
    object: "ioi.runtime_external_capability_authority",
    status: "authorized",
    exit_authorized: true,
    direct_truth_write_allowed: false,
    thread_id: request.thread_id,
    agent_id: request.agent_id,
    authority: {
      ...request.request,
      wallet_network_grant_refs: request.request.authority_grant_refs,
      authority_hash: "sha256:external-capability-authority",
    },
    wallet_network_grant_refs: request.request.authority_grant_refs,
    authority_receipt_refs: request.request.authority_receipt_refs,
    authority_hash: "sha256:external-capability-authority",
  };
}

test("external capability authority core calls direct Rust daemon-core wallet.network API", () => {
  const calls = [];
  const core = createRuntimeExternalCapabilityAuthorityCore({
    daemonCoreInvoker(request) {
      calls.push(request);
      return authorizedResult(request);
    },
  });

  const result = core.authorizeExit(externalCapabilityExitRequest(), {
    thread_id: "thread_external_capability_core",
    agent_id: "agent_external_capability_core",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].schema_version, EXTERNAL_CAPABILITY_AUTHORITY_CORE_SCHEMA_VERSION);
  assert.equal(calls[0].operation, "authorize_external_capability_exit");
  assert.equal(calls[0].backend, RUNTIME_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND);
  assert.equal(calls[0].thread_id, "thread_external_capability_core");
  assert.equal(calls[0].agent_id, "agent_external_capability_core");
  assert.equal(calls[0].request.exit_ref, "exit://aiip/slack-post-message");
  assert.equal(Object.hasOwn(calls[0].request, "exitRef"), false);
  assert.equal(Object.hasOwn(calls[0].request, "wallet_network_grant_refs"), false);
  assert.equal(result.schema_version, "ioi.runtime.external_capability_authority.v1");
  assert.equal(result.object, "ioi.runtime_external_capability_authority");
  assert.equal(result.status, "authorized");
  assert.equal(result.exit_authorized, true);
  assert.equal(result.direct_truth_write_allowed, false);
  assert.equal(result.thread_id, "thread_external_capability_core");
  assert.equal(result.agent_id, "agent_external_capability_core");
  assert.equal(result.source, "rust_external_capability_exit_authority_command");
  assert.equal(result.backend, RUNTIME_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND);
  assert.deepEqual(result.wallet_network_grant_refs, [
    "wallet.network://grant/external-capability/slack-post-message",
  ]);
  assert.deepEqual(result.authority_receipt_refs, [
    "receipt://wallet.network/authority/slack-post-message",
  ]);
  assert.equal(result.authority_hash, "sha256:external-capability-authority");
});

test("external capability authority core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    schema_version: "ioi.runtime.external_capability_authority.v1",
    authority: {
      exit_ref: "exit://aiip/slack-post-message",
    },
  };
  const core = createRuntimeExternalCapabilityAuthorityCore({
    daemonCoreInvoker() {
      return rustEnvelope;
    },
  });

  const result = core.authorizeExit(externalCapabilityExitRequest());

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "wallet_network_grant_refs"), false);
  assert.equal(Object.hasOwn(result, "authority_receipt_refs"), false);
  assert.equal(Object.hasOwn(result, "authority_hash"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
});

test("external capability authority core rejects retired compatibility options", () => {
  assert.throws(
    () => new RuntimeExternalCapabilityAuthorityCore({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeExternalCapabilityAuthorityCoreError &&
      error.code === "external_capability_authority_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeExternalCapabilityAuthorityCore({ args: ["--external-capability"] }),
    (error) =>
      error instanceof RuntimeExternalCapabilityAuthorityCoreError &&
      error.code === "external_capability_authority_core_compatibility_option_retired",
  );
});

test("external capability authority core rejects retired request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeExternalCapabilityAuthorityCore({
    daemonCoreInvoker() {
      calls.push("invoked");
      return {};
    },
  });
  const request = externalCapabilityExitRequest();

  assert.throws(
    () =>
      core.authorizeExit({
        ...request,
        request,
        authority_request: request,
        exitRef: request.exit_ref,
        walletNetworkGrantRefs: request.authority_grant_refs,
        wallet_network_grant_refs: request.authority_grant_refs,
        authority_hash: "sha256:client-authored-authority",
      }),
    (error) =>
      error.code === "external_capability_authority_core_request_fields_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("request") &&
      error.details.retired_aliases.includes("authority_request") &&
      error.details.retired_aliases.includes("exitRef") &&
      error.details.retired_aliases.includes("walletNetworkGrantRefs") &&
      error.details.retired_truth_fields.includes("wallet_network_grant_refs") &&
      error.details.retired_truth_fields.includes("authority_hash"),
  );
  assert.deepEqual(calls, []);
});

test("external capability authority core fails closed without direct daemon-core API", () => {
  const core = createRuntimeExternalCapabilityAuthorityCore({});

  assert.throws(
    () => core.authorizeExit(externalCapabilityExitRequest()),
    (error) => error.code === "external_capability_authority_core_direct_invoker_unconfigured",
  );
});

test("external capability authority core surfaces Rust wallet.network rejection", () => {
  const core = createRuntimeExternalCapabilityAuthorityCore({
    daemonCoreInvoker() {
      return {
        ok: false,
        error: {
          code: "external_capability_exit_authority_invalid",
          message: "MissingWalletNetworkAuthority",
        },
      };
    },
  });

  assert.throws(
    () => core.authorizeExit(externalCapabilityExitRequest()),
    (error) =>
      error.code === "external_capability_exit_authority_invalid" &&
      error.message === "MissingWalletNetworkAuthority",
  );
});
