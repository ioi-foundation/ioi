import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeMemoryHelpers } from "./runtime-memory-helpers.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function helpers() {
  return createRuntimeMemoryHelpers({ normalizeArray, optionalString, safeId });
}

test("memory helper policy aliases and write approvals preserve daemon behavior", () => {
  const runtime = helpers();

  assert.deepEqual(runtime.memoryPolicyOverrides({
    injection_enabled: false,
    read_only: true,
    write_requires_approval: true,
    subagent_inheritance: "explicit",
  }), {
    injectionEnabled: false,
    readOnly: true,
    writeRequiresApproval: true,
    subagentInheritance: "explicit",
  });

  assert.equal(runtime.memoryWriteBlockReason({ disabled: true }, {}, true), "memory_disabled");
  assert.equal(runtime.memoryWriteBlockReason({ readOnly: true }, {}, true), "memory_read_only");
  assert.equal(
    runtime.memoryWriteBlockReason({ writeRequiresApproval: true }, {}, true),
    "memory_write_requires_approval",
  );
  assert.equal(
    runtime.memoryWriteBlockReason({ writeRequiresApproval: true }, { approval_granted: true }, true),
    null,
  );
  assert.equal(runtime.memoryWriteBlockReason({ writeRequiresApproval: true }, {}, false), null);
});

test("memory helper operation names keep public event/control vocabulary stable", () => {
  const runtime = helpers();

  assert.equal(runtime.memoryEventKind("policy_update"), "MemoryPolicy");
  assert.equal(runtime.memoryControlKind("edit"), "memory_edit");
  assert.equal(runtime.memoryOperatorControlKind("delete"), "OperatorControl.MemoryDelete");
  assert.equal(runtime.memoryRuntimeEventKind("write"), "memory.write");
  assert.equal(runtime.memoryWorkflowNodeId("policy_update"), "runtime.memory-manager.policy");
  assert.equal(runtime.memoryMutationRowLabel("delete"), "Memory delete");
  assert.equal(runtime.memoryMutationRawInput("edit"), "/memory edit");
  assert.equal(
    runtime.memoryMutationSummary("policy_update", { policy: { id: "policy-one" } }),
    "Memory policy policy-one updated.",
  );
  assert.equal(runtime.memoryEventSummary("write"), "Memory write recorded");
});

test("subagent memory policy and receipt preserve inheritance evidence", () => {
  const runtime = helpers();

  const policy = runtime.subagentMemoryPolicy({
    agent: { id: "agent-one", cwd: "/workspace" },
    threadId: "thread-one",
    receiver: "worker",
    mode: "explicit",
    parentPolicy: {
      id: "memory-policy-parent",
      evidenceRefs: ["parent-ref"],
      redaction: "redacted",
    },
  });

  assert.equal(policy.id, "memory_policy_subagent_thread-one_worker");
  assert.equal(policy.targetType, "subagent");
  assert.equal(policy.writeRequiresApproval, true);
  assert.deepEqual(policy.policyRefs, ["memory-policy-parent"]);
  assert.deepEqual(policy.evidenceRefs, [
    "parent-ref",
    "subagent_memory_inheritance",
    "memory.policy.effective.subagent",
  ]);

  const receipt = runtime.subagentMemoryInheritanceReceipt("run-one", {
    mode: "explicit",
    subagentName: "worker",
    records: [{ id: "memory-one" }, { id: "memory-two" }],
    effectivePolicy: { redaction: "redacted" },
    evidenceRefs: ["memory-one"],
  });
  assert.equal(receipt.id, "receipt_run-one_subagent_memory_inheritance");
  assert.equal(receipt.redaction, "redacted");
  assert.match(receipt.summary, /exposed 2 record/);
});

test("subagent memory request helpers preserve receiver and inheritance selectors", () => {
  const runtime = helpers();

  assert.equal(runtime.subagentReceiverForRequest({ options: { subagentName: "worker" } }), "worker");
  assert.equal(runtime.subagentReceiverForRequest({ receiver: "  " }), null);
  assert.equal(runtime.normalizeSubagentInheritanceMode("full"), "full");
  assert.equal(runtime.normalizeSubagentInheritanceMode("invalid"), "explicit");
  assert.equal(runtime.shouldInheritSubagentMemory("none", { query: "fact" }), false);
  assert.equal(runtime.shouldInheritSubagentMemory("read_only", {}), true);
  assert.equal(runtime.shouldInheritSubagentMemory("explicit", {}), false);
  assert.equal(runtime.shouldInheritSubagentMemory("explicit", { memory_query: "fact" }), true);
  assert.equal(runtime.hasExplicitSubagentMemorySelector({ memory_key: "project" }), true);
  assert.equal(runtime.hasExplicitSubagentMemorySelector({}), false);
});

test("memory list filters normalize request aliases", () => {
  const runtime = helpers();
  assert.deepEqual(runtime.memoryListFilters({
    memory_scope: "thread",
    memory_key: "project",
    memory_query: "fact",
    memory_limit: 3,
    memory_redaction: "redacted",
  }), {
    scope: "thread",
    memoryKey: "project",
    query: "fact",
    limit: 3,
    redaction: "redacted",
  });
});
