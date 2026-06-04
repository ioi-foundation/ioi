import assert from "node:assert/strict";
import test from "node:test";

import { createRunMemoryResolution } from "./run-memory-resolution.mjs";

function createHarness({
  policy = { id: "policy-thread", injectionEnabled: true, disabled: false, readOnly: false },
  records = [{ id: "memory-one", fact: "Known fact" }],
  command = { kind: "none" },
} = {}) {
  const agent = { id: "agent-one", cwd: "/workspace" };
  const memoryOptionsForRequest = (request = {}) => request.memory ?? request.options?.memory ?? {};
  const helper = createRunMemoryResolution({
    memoryListFilters: (options = {}) => ({ query: options.query, redaction: options.redaction }),
    memoryOptionsForRequest,
    memoryPolicyOverrides: (options = {}) => options.policy ?? {},
    memoryWriteBlockReason: (effectivePolicy = {}, options = {}, requestedWrite = false) => {
      if (!requestedWrite) return null;
      if (effectivePolicy.disabled) return "memory_disabled";
      if (effectivePolicy.readOnly) return "memory_read_only";
      if (effectivePolicy.writeRequiresApproval && !options.writeApproved) return "memory_write_requires_approval";
      return null;
    },
    normalizeSubagentInheritanceMode: (value) => ["none", "explicit", "read_only", "full"].includes(value) ? value : "explicit",
    optionalString: (value) => {
      if (value === undefined || value === null) return undefined;
      const text = String(value).trim();
      return text ? text : undefined;
    },
    parseMemoryCommand: () => command,
    shouldInheritSubagentMemory: (mode, options = {}) => mode !== "none" && (mode !== "explicit" || Boolean(options.query)),
    subagentMemoryPolicy: ({ agent: policyAgent, threadId, parentPolicy, receiver, mode }) => ({
      ...parentPolicy,
      id: `policy-${threadId}-${receiver ?? "subagent"}`,
      agentId: policyAgent.id,
      threadId,
      disabled: mode === "none",
      readOnly: mode === "read_only",
      writeRequiresApproval: mode === "explicit",
      injectionEnabled: mode !== "none",
    }),
    subagentReceiverForRequest: (request = {}) => request.receiver ?? request.options?.receiver ?? null,
    threadIdForAgent: (agentId) => `thread-${agentId}`,
  });
  const writes = [];
  const mutations = [];
  const store = {
    memory: {
      pathProjection: () => ({ memoryPath: "/state/memory" }),
      effectivePolicy: () => policy,
      setPolicy: ({ updates, source }) => {
        const mutation = { receipt: { kind: "memory_policy" }, updates, source };
        mutations.push(mutation);
        return mutation;
      },
      list: (input) => records.map((record) => ({ ...record, query: input.query, redaction: input.redaction })),
    },
    rememberForAgent(_agent, input) {
      const write = { record: { id: `memory-${writes.length + 1}`, fact: input.text }, receipt: { kind: "memory_write" }, input };
      writes.push(write);
      return write;
    },
    updateMemoryRecord(id, input) {
      const mutation = { receipt: { kind: "memory_edit" }, id, input };
      mutations.push(mutation);
      return mutation;
    },
    deleteMemoryRecord(id, input) {
      const mutation = { receipt: { kind: "memory_delete" }, id, input };
      mutations.push(mutation);
      return mutation;
    },
    resolveSubagentMemoryInheritance(input) {
      return helper.resolveSubagentMemoryInheritance(store, input);
    },
  };
  return { agent, helper, mutations, store, writes };
}

test("run memory resolution injects matching records without writes", () => {
  const { agent, helper, store } = createHarness();

  const result = helper.resolveRunMemory(store, agent, { memory: { query: "Known" } }, "hello");

  assert.equal(result.command, "none");
  assert.equal(result.injected, true);
  assert.equal(result.records[0].id, "memory-one");
  assert.equal(result.records[0].query, "Known");
  assert.equal(result.paths.memoryPath, "/state/memory");
  assert.deepEqual(result.writes, []);
});

test("run memory resolution records remember commands unless policy blocks writes", () => {
  const { agent, helper, store, writes } = createHarness({
    command: { kind: "remember", text: "Remember this" },
  });

  const result = helper.resolveRunMemory(store, agent, { memory: { scope: "thread" } }, "#remember");

  assert.equal(result.command, "remember");
  assert.equal(result.injected, false);
  assert.equal(result.writes.length, 1);
  assert.equal(writes[0].input.text, "Remember this");
  assert.equal(writes[0].input.source, "chat_hash_remember");
  assert.equal(result.mutations[0].operation, "write");
});

test("run memory resolution disables injection and reports policy block reason", () => {
  const { agent, helper, store } = createHarness({
    policy: { id: "policy-disabled", disabled: true, injectionEnabled: false },
    command: { kind: "remember", text: "Blocked" },
  });

  const result = helper.resolveRunMemory(store, agent, {}, "#remember");

  assert.equal(result.disabled, true);
  assert.equal(result.injected, false);
  assert.equal(result.records.length, 0);
  assert.equal(result.policyBlockReason, "memory_disabled");
});

test("subagent memory inheritance projects inherited records and effective policy", () => {
  const { agent, helper, store } = createHarness();

  const result = helper.resolveSubagentMemoryInheritance(store, {
    agent,
    threadId: "thread-one",
    request: { mode: "handoff", receiver: "worker", memory: { subagentInheritance: "explicit", query: "Known" } },
    parentPolicy: { id: "policy-parent", subagentInheritance: "explicit", injectionEnabled: true },
  });

  assert.equal(result.schemaVersion, "ioi.agent-runtime.subagent-memory-inheritance.v1");
  assert.equal(result.subagentName, "worker");
  assert.equal(result.mode, "explicit");
  assert.equal(result.effectivePolicyId, "policy-thread-one-worker");
  assert.deepEqual(result.inheritedRecordIds, ["memory-one"]);
  assert.equal(result.writeAllowed, false);
  assert.ok(result.evidenceRefs.includes("subagent_memory_inheritance"));
});
