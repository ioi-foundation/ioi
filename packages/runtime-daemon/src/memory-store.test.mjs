import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentMemoryStore } from "./memory-store.mjs";

function tempStateDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ioi-memory-store-"));
}

function fakeMemoryCommitter(stateDir, calls = []) {
  return function commitRuntimeMemoryState(request) {
    calls.push(request);
    const filePath = request.memory_state_kind === "policy"
      ? `memory-policies/${String(request.state_id).replace(/[^a-zA-Z0-9_.-]+/g, "_")}.json`
      : `memory-records/${request.state_id}.json`;
    const absolutePath = path.join(stateDir, filePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, `${JSON.stringify(request.payload, null, 2)}\n`);
    const objectRef = `agentgres://runtime-state/memory/${request.memory_state_kind}/${request.state_id}/records/${filePath}`;
    const payloadRefs = [`payload://runtime/memory/${request.memory_state_kind}/${request.state_id}/records/${filePath}`];
    return {
      source: "rust_agentgres_runtime_memory_state_commit_command",
      record: {
        schema_version: "ioi.runtime_memory_state_commit.v1",
        memory_state_kind: request.memory_state_kind,
        state_id: request.state_id,
        operation_kind: request.operation_kind,
        storage_backend_ref: request.storage_backend_ref,
        record: {
          record_path: filePath,
          object_ref: objectRef,
          content_hash: `sha256:${request.memory_state_kind}-content`,
          artifact_refs: [],
          payload_refs: payloadRefs,
          receipt_refs: request.receipt_refs,
          admission: {
            admission_hash: `sha256:${request.memory_state_kind}-admission`,
          },
        },
        commit_hash: `sha256:${request.memory_state_kind}-commit`,
      },
      memory_state_kind: request.memory_state_kind,
      state_id: request.state_id,
      object_ref: objectRef,
      content_hash: `sha256:${request.memory_state_kind}-content`,
      admission_hash: `sha256:${request.memory_state_kind}-admission`,
      commit_hash: `sha256:${request.memory_state_kind}-commit`,
      written_record: {
        record_path: filePath,
        object_ref: objectRef,
      },
      evidence_refs: ["rust_agentgres_runtime_memory_state_commit"],
    };
  };
}

test("agent memory store commits records, edits, and policies through Rust Agentgres without local operation append", () => {
  const stateDir = tempStateDir();
  const appended = [];
  const commits = [];
  try {
    const store = new AgentMemoryStore(stateDir, {
      appendOperation(kind, payload) {
        appended.push({ kind, payload });
      },
      commitRuntimeMemoryState: fakeMemoryCommitter(stateDir, commits),
    });
    const agent = { id: "agent.memory", cwd: "/workspace" };
    const remembered = store.remember({
      text: "Remember the launch checklist.",
      agent,
      threadId: "thread.memory",
      scope: "thread",
      workflow: { memory_key: "launch" },
    });
    store.remember({
      text: "Remember the support checklist.",
      agent,
      threadId: "thread.memory",
      scope: "thread",
      workflow: { memory_key: "support" },
    });

    assert.equal("appendOperation" in store, false);
    assert.equal(remembered.receipt.kind, "memory_write");
    assert.equal(fs.existsSync(path.join(store.memoryDir, `${remembered.record.id}.json`)), true);
    assert.equal(commits[0].schema_version, "ioi.runtime_memory_state_commit.v1");
    assert.equal(commits[0].memory_state_kind, "record");
    assert.equal(commits[0].operation_kind, "memory.write");
    assert.deepEqual(commits[0].receipt_refs, [remembered.receipt.id]);
    assert.equal(store.list({ agent, threadId: "thread.memory", memory_key: "launch" }).length, 1);
    assert.equal(store.list({ agent, threadId: "thread.memory", memoryKey: "launch" }).length, 2);
    assert.equal(store.projection({ agent, threadId: "thread.memory", filters: { memory_key: "launch" } }).filters.memory_key, "launch");
    assert.equal(
      Object.hasOwn(store.projection({ agent, threadId: "thread.memory", filters: { memory_key: "launch" } }).filters, "memoryKey"),
      false,
    );

    const edited = store.updateRecord({
      id: remembered.record.id,
      text: "Remember the updated launch checklist.",
    });
    assert.equal(edited.operation, "edit");
    assert.equal(commits.at(-1).operation_kind, "memory.edit");
    assert.deepEqual(commits.at(-1).receipt_refs, [edited.receipt.id]);
    assert.equal(store.records.get(remembered.record.id).fact, "Remember the updated launch checklist.");

    const policy = store.setPolicy({
      targetType: "thread",
      targetId: "thread.memory",
      agent,
      updates: { readOnly: true },
    });
    assert.equal(policy.operation, "policy_update");
    assert.equal(policy.policy.readOnly, true);
    assert.equal(commits.at(-1).memory_state_kind, "policy");
    assert.equal(commits.at(-1).operation_kind, "memory.policy");
    assert.deepEqual(commits.at(-1).receipt_refs, [policy.receipt.id]);

    const deleted = store.deleteRecord({ id: remembered.record.id });
    assert.equal(deleted.operation, "delete");
    assert.equal(fs.existsSync(path.join(store.memoryDir, `${remembered.record.id}.json`)), false);
    assert.deepEqual(appended, []);
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test("agent memory store fails closed without Rust Agentgres memory-state commit", () => {
  const stateDir = tempStateDir();
  try {
    const store = new AgentMemoryStore(stateDir);

    assert.throws(
      () => store.remember({ text: "Remember the launch checklist." }),
      /Memory persistence requires Rust Agentgres memory-state commit/,
    );
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});
