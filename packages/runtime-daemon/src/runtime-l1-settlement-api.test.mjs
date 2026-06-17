import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeL1SettlementSurface } from "./runtime-l1-settlement-surface.mjs";

const L1_SETTLEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.l1_settlement_admission.v1";

function settlementAttempt() {
  return {
    schema_version: "ioi.l1_settlement_admission.v1",
    settlement_ref: "l1://settlement/marketplace-transaction",
    domain_ref: "domain://marketplace/services",
    trigger_refs: ["l1-trigger://service-contract/payment"],
    receipt_refs: ["receipt://local-settlement/payment"],
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
    l1SettlementCore: {
      admitAttempt(input, context) {
        calls.push({ name: "admitAttempt", input, context });
        return {
          schema_version: L1_SETTLEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
          object: "ioi.runtime_l1_settlement_admission",
          status: "admitted",
          settlement_admitted: true,
          thread_id: "thread_surface",
          agent_id: "agent_surface",
          source: "rust_l1_settlement_guard_protocol",
          backend: "l1_settlement_guard",
          record: {
            ...input,
            admission_hash: [1, 2, 3],
          },
          settlement_ref: input.settlement_ref,
          domain_ref: input.domain_ref,
          state_root_ref: "sha256:rust-derived-l1-state-root",
          trigger_refs: input.trigger_refs,
          receipt_refs: input.receipt_refs,
          admission_hash: [1, 2, 3],
        };
      },
    },
  };
}

const L1_SETTLEMENT_ADMISSION_CAMEL_ALIASES = [
  "schemaVersion",
  "settlementAdmitted",
  "threadId",
  "agentId",
  "settlementRef",
  "domainRef",
  "stateRootRef",
  "triggerRefs",
  "receiptRefs",
  "admissionHash",
];

test("L1 settlement surface admits nested attempt through Rust core", () => {
  const runtimeStore = store();
  const surface = createRuntimeL1SettlementSurface();

  const result = surface.admitL1SettlementAttempt(runtimeStore, "thread_surface", {
    attempt: settlementAttempt(),
  });

  assert.equal(result.schema_version, L1_SETTLEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION);
  assert.equal(result.status, "admitted");
  assert.equal(result.settlement_admitted, true);
  assert.equal(result.thread_id, "thread_surface");
  assert.equal(result.agent_id, "agent_surface");
  assert.equal(result.settlement_ref, "l1://settlement/marketplace-transaction");
  assert.equal(result.domain_ref, "domain://marketplace/services");
  assert.equal(result.state_root_ref, "sha256:rust-derived-l1-state-root");
  assert.deepEqual(result.trigger_refs, ["l1-trigger://service-contract/payment"]);
  assert.deepEqual(result.receipt_refs, ["receipt://local-settlement/payment"]);
  assert.deepEqual(result.admission_hash, [1, 2, 3]);
  assert.deepEqual(runtimeStore.calls[1], {
    name: "admitAttempt",
    input: settlementAttempt(),
    context: {
      thread_id: "thread_surface",
      agent_id: "agent_surface",
    },
  });
  assert.deepEqual(runtimeStore.calls.map((call) => call.name), ["agentForThread", "admitAttempt"]);
});

test("L1 settlement surface rejects client supplied state-root truth before Rust core", () => {
  const runtimeStore = store();
  const surface = createRuntimeL1SettlementSurface();

  assert.throws(
    () =>
      surface.admitL1SettlementAttempt(runtimeStore, "thread_surface", {
        attempt: {
          ...settlementAttempt(),
          state_root_ref: "state-root://client-supplied",
          stateRootRef: "state-root://client-supplied",
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "l1_settlement_state_root_truth_fields_retired");
      assert.deepEqual(error.details.retired_fields, ["stateRootRef", "state_root_ref"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("L1 settlement surface rejects retired request aliases before agent lookup or Rust core", () => {
  const runtimeStore = store();
  const surface = createRuntimeL1SettlementSurface();

  assert.throws(
    () =>
      surface.admitL1SettlementAttempt(runtimeStore, "thread_surface", {
        settlement_attempt: settlementAttempt(),
        settlementAttempt: settlementAttempt(),
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "l1_settlement_attempt_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["settlementAttempt", "settlement_attempt"]);
      assert.deepEqual(error.details.canonical_fields, ["attempt"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("L1 settlement surface exposes only canonical snake_case admission fields", () => {
  const result = createRuntimeL1SettlementSurface().admitL1SettlementAttempt(
    store(),
    "thread_surface",
    { attempt: settlementAttempt() },
  );

  for (const key of L1_SETTLEMENT_ADMISSION_CAMEL_ALIASES) {
    assert.equal(Object.hasOwn(result, key), false, `${key} must not be emitted`);
  }
});

test("L1 settlement surface fails closed without attempt payload", () => {
  const surface = createRuntimeL1SettlementSurface();

  assert.throws(
    () => surface.admitL1SettlementAttempt(store(), "thread_surface", {}),
    (error) => error.code === "l1_settlement_attempt_required",
  );
});
