import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentMemoryStore } from "./memory-store.mjs";

function tempStateDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ioi-memory-store-"));
}

test("agent memory store writes records, edits, deletes, and policies without local operation append", () => {
  const stateDir = tempStateDir();
  const appended = [];
  try {
    const store = new AgentMemoryStore(stateDir, {
      appendOperation(kind, payload) {
        appended.push({ kind, payload });
      },
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
    assert.equal(store.records.get(remembered.record.id).fact, "Remember the updated launch checklist.");

    const policy = store.setPolicy({
      targetType: "thread",
      targetId: "thread.memory",
      agent,
      updates: { readOnly: true },
    });
    assert.equal(policy.operation, "policy_update");
    assert.equal(policy.policy.readOnly, true);

    const deleted = store.deleteRecord({ id: remembered.record.id });
    assert.equal(deleted.operation, "delete");
    assert.equal(fs.existsSync(path.join(store.memoryDir, `${remembered.record.id}.json`)), false);
    assert.deepEqual(appended, []);
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});
