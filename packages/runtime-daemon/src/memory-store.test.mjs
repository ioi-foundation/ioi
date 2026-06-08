import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentMemoryStore } from "./memory-store.mjs";

function tempStateDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ioi-memory-store-"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function seedMemoryRecord(stateDir, overrides = {}) {
  const id = overrides.id ?? "memory.canonical";
  const record = {
    schema_version: "ioi.agent-runtime.memory.v1",
    id,
    object: "ioi.agent_memory_record",
    scope: overrides.scope ?? "thread",
    fact: overrides.fact ?? "Remember the launch checklist.",
    memory_key: overrides.memory_key ?? "launch",
    agent_id: overrides.agent_id ?? "agent.memory",
    thread_id: overrides.thread_id ?? "thread.memory",
    workspace: overrides.workspace ?? "/workspace",
    workflow_graph_id: overrides.workflow_graph_id ?? "graph.memory",
    workflow_node_id: overrides.workflow_node_id ?? "node.memory",
    workflow_node_type: "Memory",
    source: "rust_agentgres_projection",
    redaction: "none",
    created_at: overrides.created_at ?? "2026-06-08T00:00:00.000Z",
    updated_at: overrides.updated_at ?? "2026-06-08T00:00:00.000Z",
    evidence_refs: ["rust_agentgres_runtime_memory_state_commit"],
  };
  writeJson(path.join(stateDir, "memory-records", `${id}.json`), record);
  return record;
}

function seedMemoryPolicy(stateDir, overrides = {}) {
  const id = overrides.id ?? "memory_policy_thread_thread.memory";
  const policy = {
    schema_version: "ioi.agent-runtime.memory-policy.v1",
    id,
    object: "ioi.agent_memory_policy",
    target_type: "thread",
    target_id: "thread.memory",
    agent_id: "agent.memory",
    thread_id: "thread.memory",
    workspace: "/workspace",
    disabled: false,
    injection_enabled: true,
    read_only: false,
    write_requires_approval: true,
    retention: "persistent",
    redaction: "none",
    subagent_inheritance: "explicit",
    scope: "thread",
    source: "rust_agentgres_projection",
    created_at: "2026-06-08T00:00:00.000Z",
    updated_at: "2026-06-08T00:00:00.000Z",
    evidence_refs: ["rust_agentgres_runtime_memory_state_commit"],
    ...overrides,
  };
  writeJson(path.join(stateDir, "memory-policies", `${id}.json`), policy);
  return policy;
}

function assertAgentMemoryStoreRustCoreRequired(error, {
  operation,
  operationKind,
  memoryId = null,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_memory_state_store_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.thread_memory_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  if (memoryId) assert.equal(error.details.memory_id, memoryId);
  for (const evidence of [
    "runtime_memory_state_store_js_mutation_retired",
    "agent_memory_store_write_js_writer_retired",
    "agent_memory_store_edit_js_writer_retired",
    "agent_memory_store_delete_js_writer_retired",
    "agent_memory_store_policy_js_writer_retired",
    "rust_daemon_core_thread_memory_control_required",
    "agentgres_thread_memory_state_truth_required",
  ]) {
    assert.equal(error.details.evidence_refs.includes(evidence), true, `missing evidence ${evidence}`);
  }
  for (const key of ["rustCoreBoundary", "operationKind", "memoryId", "evidenceRefs"]) {
    assert.equal(Object.hasOwn(error.details, key), false, `retired detail alias ${key} must be absent`);
  }
  return true;
}

test("agent memory store direct mutation writers fail closed before JS memory-state writes", () => {
  const stateDir = tempStateDir();
  try {
    const store = new AgentMemoryStore(stateDir, {
      commitRuntimeMemoryState() {
        throw new Error("commitRuntimeMemoryState must not be reached");
      },
    });

    assert.throws(
      () => store.remember({ text: "Remember the launch checklist." }),
      (error) =>
        assertAgentMemoryStoreRustCoreRequired(error, {
          operation: "memory_write",
          operationKind: "memory.write",
        }),
    );
    assert.throws(
      () => store.updateRecord({ id: "memory.canonical", text: "Edited" }),
      (error) =>
        assertAgentMemoryStoreRustCoreRequired(error, {
          operation: "memory_edit",
          operationKind: "memory.edit",
          memoryId: "memory.canonical",
        }),
    );
    assert.throws(
      () => store.deleteRecord({ id: "memory.canonical" }),
      (error) =>
        assertAgentMemoryStoreRustCoreRequired(error, {
          operation: "memory_delete",
          operationKind: "memory.delete",
          memoryId: "memory.canonical",
        }),
    );
    assert.throws(
      () => store.setPolicy({ target_type: "thread", target_id: "thread.memory", updates: { read_only: true } }),
      (error) =>
        assertAgentMemoryStoreRustCoreRequired(error, {
          operation: "memory_policy",
          operationKind: "memory.policy",
        }),
    );
    assert.throws(
      () => store.write({ id: "memory.canonical" }, { operation_kind: "memory.custom" }),
      (error) =>
        assertAgentMemoryStoreRustCoreRequired(error, {
          operation: "memory_write",
          operationKind: "memory.custom",
          memoryId: "memory.canonical",
        }),
    );
    assert.throws(
      () => store.writePolicy({ id: "memory_policy_thread_thread.memory" }, { operation_kind: "memory.policy.custom" }),
      (error) =>
        assertAgentMemoryStoreRustCoreRequired(error, {
          operation: "memory_policy",
          operationKind: "memory.policy.custom",
          memoryId: "memory_policy_thread_thread.memory",
        }),
    );
    assert.throws(
      () =>
        store.commitMemoryState({
          memory_state_kind: "record",
          state_id: "memory.canonical",
          operation_kind: "memory.state_commit",
          payload: { id: "memory.canonical" },
          receipt_refs: ["receipt_memory"],
        }),
      (error) =>
        assertAgentMemoryStoreRustCoreRequired(error, {
          operation: "memory_state_commit",
          operationKind: "memory.state_commit",
          memoryId: "memory.canonical",
        }),
    );

    assert.deepEqual(fs.readdirSync(path.join(stateDir, "memory-records")), []);
    assert.deepEqual(fs.readdirSync(path.join(stateDir, "memory-policies")), []);
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test("agent memory store projects canonical admitted memory without retired aliases", () => {
  const stateDir = tempStateDir();
  try {
    const record = seedMemoryRecord(stateDir);
    seedMemoryRecord(stateDir, {
      id: "memory.support",
      memory_key: "support",
      fact: "Remember the support checklist.",
      workflow_node_id: "node.support",
      created_at: "2026-06-08T00:01:00.000Z",
      updated_at: "2026-06-08T00:01:00.000Z",
    });
    seedMemoryPolicy(stateDir);
    const store = new AgentMemoryStore(stateDir);
    const agent = { id: "agent.memory", cwd: "/workspace" };
    store.records.set("memory.retired.alias", {
      id: "memory.retired.alias",
      scope: "thread",
      fact: "Retired alias record must not project.",
      threadId: "thread.memory",
      agentId: "agent.memory",
      memoryKey: "launch",
      workflowNodeId: "node.retired.only",
      createdAt: "2026-06-07T00:00:00.000Z",
    });

    assert.equal(store.list({ agent, threadId: "thread.memory", memory_key: "launch" }).length, 1);
    assert.equal(store.list({ agent, threadId: "thread.memory", memoryKey: "launch" }).length, 2);
    assert.equal(store.list({ agent, threadId: "thread.retired", memory_key: "launch" }).length, 0);
    assert.equal(store.list({ agent: { id: "agent.retired", cwd: "/workspace" }, memory_key: "launch" }).length, 0);
    assert.equal(store.list({ agent, threadId: "thread.memory", query: "node.memory" }).length, 1);
    assert.equal(store.list({ agent, threadId: "thread.memory", query: "node.retired" }).length, 0);
    const projection = store.projection({ agent, threadId: "thread.memory", filters: { memory_key: "launch" } });
    assert.equal(projection.filters.memory_key, "launch");
    assert.equal(Object.hasOwn(projection.filters, "memoryKey"), false);
    assert.equal(projection.records[0].id, record.id);
    assert.equal(projection.policy.write_requires_approval, true);
    assert.equal(projection.paths.records_path, path.join(stateDir, "memory-records"));
    assert.equal(projection.paths.policies_path, path.join(stateDir, "memory-policies"));
    assert.equal(projection.paths.effective_policy_id, "memory_policy_thread_thread.memory");

    for (const key of [
      "schemaVersion",
      "threadId",
      "agentId",
      "memoryKey",
      "workflowGraphId",
      "workflowNodeId",
      "workflowNodeType",
      "createdAt",
      "updatedAt",
      "evidenceRefs",
    ]) {
      assert.equal(Object.hasOwn(projection.records[0], key), false, `retired memory record alias ${key} must be absent`);
    }
    for (const key of [
      "schemaVersion",
      "targetType",
      "targetId",
      "agentId",
      "threadId",
      "injectionEnabled",
      "readOnly",
      "writeRequiresApproval",
      "subagentInheritance",
      "createdAt",
      "updatedAt",
      "evidenceRefs",
      "policyRefs",
    ]) {
      assert.equal(Object.hasOwn(projection.policy, key), false, `retired memory policy alias ${key} must be absent`);
    }
    for (const key of ["schemaVersion", "threadId", "agentId", "recordsPath", "policiesPath", "effectivePolicyId"]) {
      assert.equal(Object.hasOwn(projection.paths, key), false, `retired memory path alias ${key} must be absent`);
    }
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});
