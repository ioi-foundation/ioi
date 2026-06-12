import assert from "node:assert/strict";
import test from "node:test";

import {
  EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  ExternalCapabilityAuthorityRunnerError,
  RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
  RustExternalCapabilityAuthorityRunner,
  createExternalCapabilityAuthorityRunnerFromEnv,
  normalizeExternalCapabilityAuthorityBridgeResult,
} from "./runtime-external-capability-authority-runner.mjs";

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
    source: "direct_daemon_core_api",
    backend: RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
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

test("external capability authority runner sends Rust authority request through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustExternalCapabilityAuthorityRunner({
    daemonCoreInvoker(request) {
      calls.push(request);
      return authorizedResult(request);
    },
  });

  const result = runner.authorizeExit(externalCapabilityExitRequest(), {
    thread_id: "thread_runner",
    agent_id: "agent_runner",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].schema_version, EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].operation, "authorize_external_capability_exit");
  assert.equal(calls[0].backend, RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND);
  assert.equal(calls[0].thread_id, "thread_runner");
  assert.equal(calls[0].agent_id, "agent_runner");
  assert.equal(calls[0].request.exit_ref, "exit://aiip/slack-post-message");
  assert.equal(result.schema_version, "ioi.runtime.external_capability_authority.v1");
  assert.equal(result.object, "ioi.runtime_external_capability_authority");
  assert.equal(result.status, "authorized");
  assert.equal(result.exit_authorized, true);
  assert.equal(result.direct_truth_write_allowed, false);
  assert.equal(result.thread_id, "thread_runner");
  assert.equal(result.agent_id, "agent_runner");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.backend, RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND);
  assert.deepEqual(result.wallet_network_grant_refs, [
    "wallet.network://grant/external-capability/slack-post-message",
  ]);
  assert.deepEqual(result.authority_receipt_refs, [
    "receipt://wallet.network/authority/slack-post-message",
  ]);
  assert.equal(result.authority_hash, "sha256:external-capability-authority");
});

test("external capability authority runner env uses daemon-level direct invoker", () => {
  const calls = [];
  const runner = createExternalCapabilityAuthorityRunnerFromEnv({
    IOI_EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ARGS: "--retired-external",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  }, {
    daemonCoreInvoker(request) {
      calls.push(request);
      return authorizedResult(request);
    },
  });

  const result = runner.authorizeExit(externalCapabilityExitRequest());

  assert.equal(calls[0].operation, "authorize_external_capability_exit");
  assert.equal(result.source, "direct_daemon_core_api");
});

test("external capability authority runner rejects retired binary command env", () => {
  assert.throws(
    () =>
      createExternalCapabilityAuthorityRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_command_selection_retired",
  );
});

test("external capability authority runner rejects retired authority command env", () => {
  assert.throws(
    () =>
      createExternalCapabilityAuthorityRunnerFromEnv({
        IOI_EXTERNAL_CAPABILITY_AUTHORITY_COMMAND: "retired-external-capability-bridge",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_command_selection_retired",
  );
});

test("external capability authority runner command args env fails closed", () => {
  assert.throws(
    () =>
      createExternalCapabilityAuthorityRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json",
      }),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_command_args_retired",
  );
});

test("external capability authority runner does not synthesize product route envelope", () => {
  const result = normalizeExternalCapabilityAuthorityBridgeResult({
    source: "legacy_external_capability_authority_fixture",
    authority: {
      exit_ref: "exit://aiip/slack-post-message",
    },
  });

  assert.equal(result.schema_version, null);
  assert.equal(result.object, null);
  assert.equal(result.status, null);
  assert.equal(result.exit_authorized, null);
  assert.equal(result.direct_truth_write_allowed, null);
});

test("external capability authority runner command constructor option fails closed", () => {
  assert.throws(
    () => new RustExternalCapabilityAuthorityRunner({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_command_selection_retired",
  );
});

test("external capability authority runner command args constructor option fails closed", () => {
  assert.throws(
    () => new RustExternalCapabilityAuthorityRunner({ args: ["--json"] }),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_command_args_retired",
  );
});

test("external capability authority runner fails closed without direct invoker", () => {
  const runner = createExternalCapabilityAuthorityRunnerFromEnv({});

  assert.throws(
    () => runner.authorizeExit(externalCapabilityExitRequest()),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_direct_invoker_unconfigured",
  );
});

test("external capability authority runner surfaces Rust wallet.network rejection", () => {
  const runner = new RustExternalCapabilityAuthorityRunner({
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
    () => runner.authorizeExit(externalCapabilityExitRequest()),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_exit_authority_invalid" &&
      error.message === "MissingWalletNetworkAuthority",
  );
});
