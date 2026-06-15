import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_L1_SETTLEMENT_BACKEND,
  RuntimeL1SettlementCore,
  RuntimeL1SettlementCoreError,
  createRuntimeL1SettlementCore,
} from "./runtime-l1-settlement-core.mjs";

function settlementAttempt() {
  return {
    schema_version: "ioi.l1_settlement_admission.v1",
    settlement_ref: "l1://settlement/marketplace-transaction",
    domain_ref: "domain://marketplace/services",
    trigger_refs: ["l1-trigger://service-contract/payment"],
    receipt_refs: ["receipt://local-settlement/payment"],
  };
}

function admittedResult(attempt, context) {
  return {
    source: "rust_l1_settlement_guard_protocol",
    backend: RUNTIME_L1_SETTLEMENT_BACKEND,
    schema_version: "ioi.runtime.l1_settlement_admission.v1",
    object: "ioi.runtime_l1_settlement_admission",
    status: "admitted",
    settlement_admitted: true,
    thread_id: context.thread_id,
    agent_id: context.agent_id,
    record: {
      ...attempt,
      admission_hash: [1, 2, 3],
    },
    settlement_ref: attempt.settlement_ref,
    domain_ref: attempt.domain_ref,
    state_root_ref: "sha256:rust-derived-l1-state-root",
    trigger_refs: attempt.trigger_refs,
    receipt_refs: attempt.receipt_refs,
    admission_hash: [1, 2, 3],
  };
}

test("L1 settlement core calls typed Rust daemon-core trigger API", () => {
  const calls = [];
  const core = createRuntimeL1SettlementCore({
    daemonCoreGovernedAdmissionApi: {
      admitL1SettlementAttempt(attempt, context) {
        calls.push({ attempt, context });
        return admittedResult(attempt, context);
      },
    },
  });

  const result = core.admitAttempt(settlementAttempt(), {
    thread_id: "thread:l1-core",
    agent_id: "agent:l1-core",
  });

  assert.equal(calls[0].attempt.settlement_ref, "l1://settlement/marketplace-transaction");
  assert.equal(Object.hasOwn(calls[0].attempt, "state_root_ref"), false);
  assert.deepEqual(calls[0].attempt.trigger_refs, [
    "l1-trigger://service-contract/payment",
  ]);
  assert.equal(Object.hasOwn(calls[0].attempt, "settlementAttempt"), false);
  assert.deepEqual(calls[0].context, {
    thread_id: "thread:l1-core",
    agent_id: "agent:l1-core",
  });
  assert.equal(Object.hasOwn(calls[0], "operation"), false);
  assert.equal(Object.hasOwn(calls[0], "schema_version"), false);
  assert.equal(result.source, "rust_l1_settlement_guard_protocol");
  assert.equal(result.schema_version, "ioi.runtime.l1_settlement_admission.v1");
  assert.equal(result.object, "ioi.runtime_l1_settlement_admission");
  assert.equal(result.status, "admitted");
  assert.equal(result.settlement_admitted, true);
  assert.equal(result.thread_id, "thread:l1-core");
  assert.equal(result.agent_id, "agent:l1-core");
  assert.equal(result.settlement_ref, "l1://settlement/marketplace-transaction");
  assert.deepEqual(result.receipt_refs, ["receipt://local-settlement/payment"]);
  assert.deepEqual(result.admission_hash, [1, 2, 3]);
});

test("L1 settlement core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    schema_version: "ioi.runtime.l1_settlement_admission.v1",
    record: {},
  };
  const core = createRuntimeL1SettlementCore({
    daemonCoreGovernedAdmissionApi: {
      admitL1SettlementAttempt() {
        return rustEnvelope;
      },
    },
  });

  const result = core.admitAttempt(settlementAttempt());

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "trigger_refs"), false);
  assert.equal(Object.hasOwn(result, "receipt_refs"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
});

test("L1 settlement core rejects retired compatibility options", () => {
  assert.throws(
    () => new RuntimeL1SettlementCore({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeL1SettlementCoreError &&
      error.code === "l1_settlement_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeL1SettlementCore({ args: ["--settlement"] }),
    (error) =>
      error instanceof RuntimeL1SettlementCoreError &&
      error.code === "l1_settlement_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeL1SettlementCore({ daemonCoreInvoker() {} }),
    (error) =>
      error instanceof RuntimeL1SettlementCoreError &&
      error.code === "l1_settlement_core_compatibility_option_retired" &&
      error.details.retired_option === "daemonCoreInvoker",
  );
  assert.throws(
    () =>
      new RuntimeL1SettlementCore({
        daemonCoreApi: {
          admitL1SettlementAttempt() {},
        },
      }),
    (error) =>
      error instanceof RuntimeL1SettlementCoreError &&
      error.code === "l1_settlement_core_compatibility_option_retired" &&
      error.details.retired_option === "daemonCoreApi",
  );
});

test("L1 settlement core rejects retired bridge request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeL1SettlementCore({
    daemonCoreGovernedAdmissionApi: {
      admitL1SettlementAttempt() {
        calls.push("invoked");
        return {};
      },
    },
  });
  const attempt = settlementAttempt();

  assert.throws(
    () =>
      core.admitAttempt({
        ...attempt,
        settlementAttempt: attempt,
        settlement_attempt: attempt,
        stateRootRef: "state-root://retired",
        state_root_ref: "state-root://retired",
      }),
    (error) =>
      error.code === "l1_settlement_core_request_aliases_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("settlementAttempt") &&
      error.details.retired_aliases.includes("settlement_attempt") &&
      error.details.retired_aliases.includes("stateRootRef") &&
      error.details.retired_aliases.includes("state_root_ref") &&
      Object.hasOwn(error.details, "settlementAttempt") === false,
  );
  assert.deepEqual(calls, []);
});

test("L1 settlement core fails closed without typed daemon-core governed admission API", () => {
  const core = createRuntimeL1SettlementCore({});

  assert.throws(
    () => core.admitAttempt(settlementAttempt()),
    (error) =>
      error.code === "l1_settlement_core_direct_governed_admission_api_unconfigured",
  );
});

test("L1 settlement core surfaces Rust settlement rejection", () => {
  const core = createRuntimeL1SettlementCore({
    daemonCoreGovernedAdmissionApi: {
      admitL1SettlementAttempt() {
        return {
          ok: false,
          error: {
            code: "l1_settlement_admission_invalid",
            message: "MissingSettlementTrigger",
          },
        };
      },
    },
  });

  assert.throws(
    () => core.admitAttempt(settlementAttempt()),
    (error) =>
      error.code === "l1_settlement_admission_invalid" &&
      /MissingSettlementTrigger/.test(error.message),
  );
});
