import assert from "node:assert/strict";
import test from "node:test";

import {
  memoryRowsForStatus,
  memoryStatusForProjection,
  validateMemoryProjection,
} from "./memory-manager.mjs";

test("memory manager status and validation expose canonical fields only", () => {
  const projection = {
    policy: {
      id: "policy.thread",
      scope: "thread",
      injectionEnabled: true,
      readOnly: false,
      writeRequiresApproval: true,
    },
    paths: {},
    records: [
      {
        id: "memory.one",
        fact: "Remember the runtime boundary.",
        scope: "thread",
        memoryKey: "retired.key",
        memory_key: "canonical.key",
      },
    ],
  };
  const status = memoryStatusForProjection(projection);
  assert.equal(status.schema_version, "ioi.runtime.memory-manager-status.v1");
  assert.equal(status.record_count, 1);
  assert.deepEqual(status.memory_keys, ["canonical.key"]);
  for (const field of [
    "schemaVersion",
    "injectionEnabled",
    "readOnly",
    "writeRequiresApproval",
    "writeBlockedReason",
    "recordCount",
    "scopeCount",
    "memoryKeyCount",
    "memoryKeys",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(status, field), false);
  }

  const validation = validateMemoryProjection(projection);
  assert.equal(validation.schema_version, "ioi.runtime.memory-manager-validation.v1");
  assert.equal(validation.record_count, 1);
  for (const field of ["schemaVersion", "issueCount", "warningCount", "recordCount"]) {
    assert.equal(Object.hasOwn(validation, field), false);
  }
});

test("memory manager rows ignore retired identity and ref aliases", () => {
  const rows = memoryRowsForStatus({
    status: "ready",
    record_count: 1,
    thread_id: "thread.canonical",
    threadId: "thread.retired",
    receipt_refs: ["receipt.canonical"],
    receiptRefs: ["receipt.retired"],
    policy_decision_refs: ["policy.canonical"],
    policyDecisionRefs: ["policy.retired"],
    policy: {
      id: "policy.thread",
      threadId: "thread.policy.retired",
      scope: "thread",
    },
    records: [
      {
        id: "memory.one",
        fact: "Remember the runtime boundary.",
        threadId: "thread.record.retired",
        memoryKey: "memory.retired",
        workflowNodeId: "runtime.memory.retired",
      },
    ],
  });
  const recordRow = rows.find((row) => row.row_kind === "memory_record");
  assert.equal(recordRow.thread_id, "thread.canonical");
  assert.equal(recordRow.memory_key, null);
  assert.equal(recordRow.workflow_node_id, "runtime.memory");
  assert.deepEqual(recordRow.receipt_refs, ["receipt.canonical"]);
  assert.deepEqual(recordRow.policy_decision_refs, ["policy.canonical"]);
});

