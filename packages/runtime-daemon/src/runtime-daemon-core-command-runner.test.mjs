import assert from "node:assert/strict";
import test from "node:test";

import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

class TestCommandError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

function createTestInvoker(options = {}) {
  return createDaemonCoreCommandInvoker({
    ErrorClass: TestCommandError,
    env: "IOI_RUNTIME_DAEMON_CORE_COMMAND",
    unconfiguredMessage: "missing daemon-core command",
    unconfiguredCode: "missing_command",
    spawnFailedMessage: "spawn failed",
    spawnFailedCode: "spawn_failed",
    commandFailedMessage: "command failed",
    commandFailedCode: "command_failed",
    invalidJsonMessage: "invalid json",
    invalidJsonCode: "invalid_json",
    rejectedMessage: "rejected",
    rejectedCode: "rejected",
    ...options,
  });
}

test("direct daemon-core invoker bypasses temporary binary spawn", () => {
  const calls = [];
  const invoke = createTestInvoker({
    command: "temporary-binary",
    daemonCoreInvoker(request) {
      calls.push(request);
      return { source: "direct_daemon_core_api", accepted: true };
    },
    spawnSyncImpl() {
      throw new Error("spawn should not run when direct invoker exists");
    },
  });

  const result = invoke({ operation: "plan_direct", schema_version: "daemon.v1" });

  assert.deepEqual(calls, [{ operation: "plan_direct", schema_version: "daemon.v1" }]);
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.accepted, true);
});

test("retired mock result fallback does not bypass direct Rust seam", () => {
  const invoke = createTestInvoker({
    daemonCoreInvoker() {
      return { source: "direct_daemon_core_api" };
    },
    mockResult: { source: "legacy_mock" },
  });

  assert.equal(invoke({}).source, "direct_daemon_core_api");
});

test("retired mock result fallback fails closed without direct invoker or command", () => {
  const invoke = createTestInvoker({
    mockResult: { source: "legacy_mock" },
  });

  assert.throws(() => invoke({}), (error) => {
    assert.equal(error.code, "missing_command");
    return true;
  });
});

test("temporary binary spawn remains explicit migration fallback", () => {
  const invoke = createTestInvoker({
    command: "temporary-binary",
    spawnSyncImpl(command, args, options) {
      assert.equal(command, "temporary-binary");
      assert.deepEqual(args, []);
      assert.equal(options.input, "{\"operation\":\"spawn_fallback\"}\n");
      return {
        status: 0,
        stdout: JSON.stringify({ ok: true, result: { source: "temporary_binary" } }),
      };
    },
  });

  assert.equal(invoke({ operation: "spawn_fallback" }).source, "temporary_binary");
});

test("missing direct invoker and command still fails closed", () => {
  const invoke = createTestInvoker();

  assert.throws(() => invoke({}), (error) => {
    assert.equal(error.code, "missing_command");
    assert.equal(error.details.env, "IOI_RUNTIME_DAEMON_CORE_COMMAND");
    return true;
  });
});
