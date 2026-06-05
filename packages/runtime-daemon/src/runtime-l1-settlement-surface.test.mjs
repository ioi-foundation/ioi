import assert from "node:assert/strict";
import test from "node:test";

import {
  L1_SETTLEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
  createRuntimeL1SettlementSurface,
} from "./runtime-l1-settlement-surface.mjs";

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

function store() {
  const calls = [];
  return {
    calls,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_surface" };
    },
    l1SettlementRunner: {
      admitAttempt(input) {
        calls.push({ name: "admitAttempt", input });
        return {
          source: "rust_l1_settlement_guard_command",
          backend: "l1_settlement_guard",
          record: {
            ...input,
            admission_hash: [1, 2, 3],
          },
          settlement_ref: input.settlement_ref,
          domain_ref: input.domain_ref,
          state_root_ref: input.state_root_ref,
          trigger_refs: input.trigger_refs,
          receipt_refs: input.receipt_refs,
          admission_hash: [1, 2, 3],
        };
      },
    },
  };
}

test("L1 settlement surface admits nested attempt through Rust runner", () => {
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
  assert.equal(result.state_root_ref, "state-root://agentgres/marketplace/after");
  assert.deepEqual(result.trigger_refs, ["l1-trigger://service-contract/payment"]);
  assert.deepEqual(result.receipt_refs, ["receipt://local-settlement/payment"]);
  assert.deepEqual(result.admission_hash, [1, 2, 3]);
  assert.deepEqual(runtimeStore.calls.map((call) => call.name), ["agentForThread", "admitAttempt"]);
});

test("L1 settlement surface fails closed without attempt payload", () => {
  const surface = createRuntimeL1SettlementSurface();

  assert.throws(
    () => surface.admitL1SettlementAttempt(store(), "thread_surface", {}),
    (error) => error.code === "l1_settlement_attempt_required",
  );
});
