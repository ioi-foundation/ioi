import assert from "node:assert/strict";
import test from "node:test";

import {
  EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ENV,
  EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  ExternalCapabilityAuthorityRunnerError,
  RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
  RustExternalCapabilityAuthorityRunner,
  createExternalCapabilityAuthorityRunnerFromEnv,
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

test("external capability authority runner sends Rust authority bridge request", () => {
  const calls = [];
  const runner = new RustExternalCapabilityAuthorityRunner({
    command: "mock-external-capability-authority-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_external_capability_exit_authority_command",
            backend: RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
            authority: {
              ...request.request,
              wallet_network_grant_refs: request.request.authority_grant_refs,
              authority_hash: "sha256:external-capability-authority",
            },
            wallet_network_grant_refs: request.request.authority_grant_refs,
            authority_receipt_refs: request.request.authority_receipt_refs,
            authority_hash: "sha256:external-capability-authority",
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.authorizeExit(externalCapabilityExitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-external-capability-authority-bridge");
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].request.schema_version, EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "authorize_external_capability_exit");
  assert.equal(calls[0].request.backend, RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND);
  assert.equal(calls[0].request.request.exit_ref, "exit://aiip/slack-post-message");
  assert.equal(result.source, "rust_external_capability_exit_authority_command");
  assert.equal(result.backend, RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND);
  assert.deepEqual(result.wallet_network_grant_refs, [
    "wallet.network://grant/external-capability/slack-post-message",
  ]);
  assert.deepEqual(result.authority_receipt_refs, [
    "receipt://wallet.network/authority/slack-post-message",
  ]);
  assert.equal(result.authority_hash, "sha256:external-capability-authority");
});

test("external capability authority runner env uses daemon-core command boundary", () => {
  const runner = createExternalCapabilityAuthorityRunnerFromEnv({
    [EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ENV]: "ioi-runtime-daemon-core",
    IOI_EXTERNAL_CAPABILITY_AUTHORITY_COMMAND: "retired-external-capability-bridge",
    IOI_EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ARGS: "--retired-external",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  });

  assert.equal(runner.command, "ioi-runtime-daemon-core");
});

test("external capability authority runner command args env fails closed", () => {
  assert.throws(
    () =>
      createExternalCapabilityAuthorityRunnerFromEnv({
        [EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ENV]: "ioi-runtime-daemon-core",
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json",
      }),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_command_args_retired",
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

test("external capability authority runner fails closed without command", () => {
  const runner = createExternalCapabilityAuthorityRunnerFromEnv({});

  assert.throws(
    () => runner.authorizeExit(externalCapabilityExitRequest()),
    (error) =>
      error instanceof ExternalCapabilityAuthorityRunnerError &&
      error.code === "external_capability_authority_bridge_unconfigured",
  );
});

test("external capability authority runner surfaces Rust wallet.network rejection", () => {
  const runner = new RustExternalCapabilityAuthorityRunner({
    command: "mock-external-capability-authority-bridge",
    spawnSyncImpl() {
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: false,
          error: {
            code: "external_capability_exit_authority_invalid",
            message: "MissingWalletNetworkAuthority",
          },
        }),
        stderr: "",
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
