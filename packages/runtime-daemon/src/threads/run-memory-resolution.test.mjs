import assert from "node:assert/strict";
import test from "node:test";

import { createRunMemoryResolution } from "./run-memory-resolution.mjs";

function createHarness({
  policy = { id: "policy-thread", injection_enabled: true, disabled: false, read_only: false },
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
      if (effectivePolicy.read_only) return "memory_read_only";
      if (effectivePolicy.write_requires_approval && !options.write_approved) return "memory_write_requires_approval";
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
    subagentMemoryPolicy: ({ agent: policyAgent, threadId, parentPolicy, receiver, mode }) => {
      const {
        subagentInheritance,
        injectionEnabled,
        readOnly,
        writeRequiresApproval,
        ...canonicalParentPolicy
      } = parentPolicy;
      return {
        ...canonicalParentPolicy,
        id: `policy-${threadId}-${receiver ?? "subagent"}`,
        agent_id: policyAgent.id,
        thread_id: threadId,
        disabled: mode === "none",
        read_only: mode === "read_only",
        write_requires_approval: mode === "explicit",
        injection_enabled: mode !== "none",
      };
    },
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

function assertRunMemoryRustCoreRequired(error, {
  operation,
  threadId = "thread-agent-one",
  agentId = "agent-one",
  memoryId = null,
} = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_run_memory_mutation_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.thread_memory_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, "memory.run_resolution");
  assert.equal(error.details.thread_id, threadId);
  assert.equal(error.details.agent_id, agentId);
  if (memoryId) assert.equal(error.details.memory_id, memoryId);
  for (const evidence of [
    "runtime_run_memory_resolution_js_mutation_retired",
    "runtime_memory_state_store_js_mutation_retired",
    "rust_daemon_core_thread_memory_control_required",
    "agentgres_thread_memory_state_truth_required",
  ]) {
    assert.equal(error.details.evidence_refs.includes(evidence), true, `missing evidence ${evidence}`);
  }
  for (const key of ["rustCoreBoundary", "operationKind", "threadId", "agentId", "memoryId", "evidenceRefs"]) {
    assert.equal(Object.hasOwn(error.details, key), false, `retired detail alias ${key} must be absent`);
  }
  return true;
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

test("run memory resolution write commands fail closed before JS memory mutation", () => {
  const rememberHarness = createHarness({
    command: { kind: "remember", text: "Remember this" },
  });

  assert.throws(
    () => rememberHarness.helper.resolveRunMemory(
      rememberHarness.store,
      rememberHarness.agent,
      { memory: { scope: "thread" } },
      "#remember",
    ),
    (error) => assertRunMemoryRustCoreRequired(error, { operation: "memory_write" }),
  );

  const editHarness = createHarness({
    command: { kind: "edit", id: "memory-one", text: "Edited" },
  });
  assert.throws(
    () => editHarness.helper.resolveRunMemory(editHarness.store, editHarness.agent, {}, "#memory edit"),
    (error) => assertRunMemoryRustCoreRequired(error, { operation: "memory_edit", memoryId: "memory-one" }),
  );

  const deleteHarness = createHarness({
    command: { kind: "delete", id: "memory-one" },
  });
  assert.throws(
    () => deleteHarness.helper.resolveRunMemory(deleteHarness.store, deleteHarness.agent, {}, "#memory delete"),
    (error) => assertRunMemoryRustCoreRequired(error, { operation: "memory_delete", memoryId: "memory-one" }),
  );

  const requestedRememberHarness = createHarness();
  assert.throws(
    () => requestedRememberHarness.helper.resolveRunMemory(
      requestedRememberHarness.store,
      requestedRememberHarness.agent,
      { remember: "Remember from API" },
      "hello",
    ),
    (error) => assertRunMemoryRustCoreRequired(error, { operation: "memory_write" }),
  );

  for (const harness of [rememberHarness, editHarness, deleteHarness, requestedRememberHarness]) {
    assert.deepEqual(harness.writes, []);
    assert.deepEqual(harness.mutations, []);
  }
});

test("run memory resolution policy commands fail closed before JS policy mutation", () => {
  const { agent, helper, store, mutations } = createHarness({
    command: { kind: "disable" },
  });

  assert.throws(
    () => helper.resolveRunMemory(store, agent, {}, "/memory disable"),
    (error) => assertRunMemoryRustCoreRequired(error, { operation: "memory_disable" }),
  );

  assert.deepEqual(mutations, []);
});

test("run memory resolution ignores retired memory thread and approval aliases", () => {
  const { agent, helper, store, writes, mutations } = createHarness({
    policy: {
      id: "policy-approval",
      injection_enabled: true,
      disabled: false,
      read_only: false,
      write_requires_approval: true,
    },
    command: { kind: "remember", text: "Remember canonical thread" },
  });

  assert.throws(
    () =>
      helper.resolveRunMemory(
        store,
        agent,
        {
          memory: {
            threadId: "thread-retired",
            thread_id: "thread-canonical",
            writeApproved: true,
            write_approved: true,
          },
        },
        "#remember",
      ),
    (error) =>
      assertRunMemoryRustCoreRequired(error, {
        operation: "memory_write",
        threadId: "thread-canonical",
      }),
  );
  assert.deepEqual(writes, []);
  assert.deepEqual(mutations, []);

  const blockedHarness = createHarness({
    policy: {
      id: "policy-approval",
      injection_enabled: true,
      disabled: false,
      read_only: false,
      write_requires_approval: true,
    },
  });
  const blocked = blockedHarness.helper.resolveRunMemory(
    blockedHarness.store,
    blockedHarness.agent,
    { memory: { threadId: "thread-retired", writeApproved: true }, remember: "retired approval" },
    "hello",
  );

  assert.equal(blocked.policyBlockReason, "memory_write_requires_approval");
  assert.equal(blocked.writes.length, 0);
  assert.deepEqual(blockedHarness.writes, []);
  assert.deepEqual(blockedHarness.mutations, []);
});

test("run memory resolution disables injection and reports policy block reason", () => {
  const { agent, helper, store } = createHarness({
    policy: { id: "policy-disabled", disabled: true, injection_enabled: false },
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
    request: { mode: "handoff", receiver: "worker", memory: { subagent_inheritance: "explicit", query: "Known" } },
    parentPolicy: {
      id: "policy-parent",
      subagent_inheritance: "explicit",
      injection_enabled: true,
      subagentInheritance: "full",
      injectionEnabled: false,
    },
  });

  assert.equal(result.schema_version, "ioi.agent-runtime.subagent-memory-inheritance.v1");
  assert.equal(result.subagent_name, "worker");
  assert.equal(result.mode, "explicit");
  assert.equal(result.effective_policy_id, "policy-thread-one-worker");
  assert.deepEqual(result.inherited_record_ids, ["memory-one"]);
  assert.equal(result.write_allowed, false);
  assert.ok(result.evidence_refs.includes("subagent_memory_inheritance"));
  for (const field of [
    "schemaVersion",
    "parentAgentId",
    "subagentName",
    "threadId",
    "requestedMode",
    "parentPolicyId",
    "effectivePolicyId",
    "parentPolicy",
    "effectivePolicy",
    "inheritedRecordIds",
    "writeAllowed",
    "writeBlockReason",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
  for (const field of ["subagentInheritance", "injectionEnabled", "readOnly", "writeRequiresApproval"]) {
    assert.equal(Object.hasOwn(result.effective_policy, field), false);
  }
});

test("subagent memory inheritance ignores retired request aliases", () => {
  const { agent, helper, store } = createHarness();

  const result = helper.resolveSubagentMemoryInheritance(store, {
    agent,
    threadId: "thread-one",
    request: {
      mode: "handoff",
      receiver: "worker",
      memory: {
        subagentInheritance: "full",
        subagent_inheritance: "none",
        query: "Known",
      },
    },
    parentPolicy: { id: "policy-parent", subagent_inheritance: "explicit", injection_enabled: true },
  });

  assert.equal(result.mode, "none");
  assert.equal(result.requested_mode, "none");
  assert.deepEqual(result.inherited_record_ids, []);
});
