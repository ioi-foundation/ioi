import assert from "node:assert/strict";
import test from "node:test";

import {
  L1_SETTLEMENT_COMMAND_ENV,
  L1SettlementRunnerError,
  RustL1SettlementRunner,
  createL1SettlementRunnerFromEnv,
} from "./runtime-l1-settlement-runner.mjs";

function settlementAttempt() {
  return {
    schema_version: "ioi.l1_settlement_admission.v1",
    settlement_ref: "l1://settlement/marketplace-transaction",
    domain_ref: "domain://marketplace/services",
    state_root_ref: "state-root://agentgres/marketplace/after",
    trigger_refs: ["l1-trigger://service-contract/payment"],
    receipt_refs: ["receipt://local-settlement/payment"],
  };
}

test("L1 settlement runner sends admission bridge request", () => {
  const calls = [];
  const runner = new RustL1SettlementRunner({
    command: "mock-l1-settlement-bridge",
    spawnSyncImpl(command, args, options) {
      const bridgeRequest = JSON.parse(options.input);
      calls.push({ command, args, bridgeRequest });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_l1_settlement_guard_command",
            backend: "l1_settlement_guard",
            schema_version: "ioi.runtime.l1_settlement_admission.v1",
            object: "ioi.runtime_l1_settlement_admission",
            status: "admitted",
            settlement_admitted: true,
            thread_id: bridgeRequest.thread_id,
            agent_id: bridgeRequest.agent_id,
            record: {
              ...bridgeRequest.attempt,
              admission_hash: [1, 2, 3],
            },
            settlement_ref: bridgeRequest.attempt.settlement_ref,
            domain_ref: bridgeRequest.attempt.domain_ref,
            state_root_ref: bridgeRequest.attempt.state_root_ref,
            trigger_refs: bridgeRequest.attempt.trigger_refs,
            receipt_refs: bridgeRequest.attempt.receipt_refs,
            admission_hash: [1, 2, 3],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitAttempt(settlementAttempt(), {
    thread_id: "thread:l1-runner",
    agent_id: "agent:l1-runner",
  });

  assert.equal(calls[0].command, "mock-l1-settlement-bridge");
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].bridgeRequest.operation, "admit_l1_settlement_attempt");
  assert.equal(calls[0].bridgeRequest.backend, "l1_settlement_guard");
  assert.equal(calls[0].bridgeRequest.thread_id, "thread:l1-runner");
  assert.equal(calls[0].bridgeRequest.agent_id, "agent:l1-runner");
  assert.equal(calls[0].bridgeRequest.attempt.settlement_ref, "l1://settlement/marketplace-transaction");
  assert.deepEqual(calls[0].bridgeRequest.attempt.trigger_refs, [
    "l1-trigger://service-contract/payment",
  ]);
  assert.equal(result.source, "rust_l1_settlement_guard_command");
  assert.equal(result.schema_version, "ioi.runtime.l1_settlement_admission.v1");
  assert.equal(result.object, "ioi.runtime_l1_settlement_admission");
  assert.equal(result.status, "admitted");
  assert.equal(result.settlement_admitted, true);
  assert.equal(result.thread_id, "thread:l1-runner");
  assert.equal(result.agent_id, "agent:l1-runner");
  assert.equal(result.settlement_ref, "l1://settlement/marketplace-transaction");
  assert.deepEqual(result.receipt_refs, ["receipt://local-settlement/payment"]);
  assert.deepEqual(result.admission_hash, [1, 2, 3]);
});

test("L1 settlement runner does not synthesize Rust-owned trigger or receipt refs", () => {
  const runner = new RustL1SettlementRunner({
    command: "mock-l1-settlement-bridge",
    spawnSyncImpl() {
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            record: {},
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitAttempt(settlementAttempt());

  assert.equal(result.trigger_refs, null);
  assert.equal(result.receipt_refs, null);
});

test("L1 settlement runner env uses daemon-core command boundary", () => {
  const runner = createL1SettlementRunnerFromEnv({
    [L1_SETTLEMENT_COMMAND_ENV]: "ioi-runtime-daemon-core",
    IOI_L1_SETTLEMENT_COMMAND: "retired-l1-settlement-bridge",
    IOI_L1_SETTLEMENT_COMMAND_ARGS: "--retired-l1",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  });

  assert.equal(runner.command, "ioi-runtime-daemon-core");
});

test("L1 settlement runner command args env fails closed", () => {
  assert.throws(
    () =>
      createL1SettlementRunnerFromEnv({
        [L1_SETTLEMENT_COMMAND_ENV]: "ioi-runtime-daemon-core",
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--settlement",
      }),
    (error) =>
      error instanceof L1SettlementRunnerError &&
      error.code === "l1_settlement_command_args_retired",
  );
});

test("L1 settlement runner command args constructor option fails closed", () => {
  assert.throws(
    () => new RustL1SettlementRunner({ args: ["--settlement"] }),
    (error) =>
      error instanceof L1SettlementRunnerError &&
      error.code === "l1_settlement_command_args_retired",
  );
});

test("L1 settlement runner fails closed without command", () => {
  const runner = createL1SettlementRunnerFromEnv({});

  assert.throws(
    () => runner.admitAttempt(settlementAttempt()),
    (error) => error.code === "l1_settlement_bridge_unconfigured",
  );
});

test("L1 settlement runner surfaces Rust settlement rejection", () => {
  const runner = new RustL1SettlementRunner({
    command: "mock-l1-settlement-bridge",
    spawnSyncImpl() {
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: false,
          error: {
            code: "l1_settlement_admission_invalid",
            message: "MissingSettlementTrigger",
          },
        }),
        stderr: "",
      };
    },
  });

  assert.throws(
    () => runner.admitAttempt(settlementAttempt()),
    (error) =>
      error.code === "l1_settlement_admission_invalid" &&
      /MissingSettlementTrigger/.test(error.message),
  );
});
