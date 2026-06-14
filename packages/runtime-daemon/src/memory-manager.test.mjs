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
      injection_enabled: true,
      read_only: false,
      write_requires_approval: true,
    },
    paths: {
      records_path: "/state/memory",
      policies_path: "/state/policies",
    },
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
  const calls = [];
  const contextPolicyCore = {
    planMemoryManagerStatusProjection(request) {
      calls.push(["status", request]);
      return {
        schema_version: request.status_schema_version,
        object: "ioi.runtime_memory_manager_status",
        status: "ready",
        record_count: 1,
        memory_keys: ["canonical.key"],
      };
    },
    planMemoryManagerValidationProjection(request) {
      calls.push(["validation", request]);
      return {
        schema_version: request.validation_schema_version,
        object: "ioi.runtime_memory_manager_validation",
        ok: true,
        status: "pass",
        record_count: 1,
      };
    },
  };
  const status = memoryStatusForProjection(projection, { contextPolicyCore });
  assert.equal(status.schema_version, "ioi.runtime.memory-manager-status.v1");
  assert.equal(status.record_count, 1);
  assert.deepEqual(status.memory_keys, ["canonical.key"]);
  assert.equal(calls[0][0], "status");
  assert.equal(calls[0][1].projection, projection);
  assert.equal(calls[0][1].validation_schema_version, "ioi.runtime.memory-manager-validation.v1");
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

  const validation = validateMemoryProjection(projection, { contextPolicyCore });
  assert.equal(validation.schema_version, "ioi.runtime.memory-manager-validation.v1");
  assert.equal(validation.record_count, 1);
  assert.equal(calls[1][0], "validation");
  assert.equal(calls[1][1].projection, projection);
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
