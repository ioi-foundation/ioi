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
  const calls = [];
  const writes = [];
  const mutations = [];
  let policyState = { ...policy };
  let recordsState = records.map((record) => ({ ...record }));
  const memoryControlResult = ({ operation, operation_kind, memory_state_kind, state_id, record = null, policy = null }) => ({
    schema_version: "ioi.runtime.memory-control-result.v1",
    object: "ioi.runtime_memory_control_result",
    status: "committed",
    operation,
    operation_kind,
    memory_state_kind,
    state_id,
    memory_id: memory_state_kind === "record" ? state_id : null,
    record,
    policy,
    receipt_refs: [`receipt_${state_id}`],
    evidence_refs: ["runtime_memory_control_rust_owned", "agentgres_thread_memory_state_truth_required"],
    commit: {
      object_ref: `agentgres://runtime-state/memory/${memory_state_kind}/${state_id}`,
      commit_hash: `sha256:${state_id}`,
    },
  });
  const store = {
    memory: {
      pathProjection: () => {
        throw new Error("run memory resolution must use Rust publicMemoryPathForThread");
      },
      effectivePolicy: () => {
        throw new Error("run memory resolution must use Rust publicMemoryPolicyForThread");
      },
      setPolicy: () => {
        throw new Error("run memory resolution must use Rust setMemoryPolicyForThread");
      },
      list: () => {
        throw new Error("run memory resolution must use Rust publicListMemoryForThread");
      },
    },
    threadMemorySurface: {
      publicMemoryPathForThread(_store, threadId) {
        calls.push({ method: "publicMemoryPathForThread", threadId });
        return { memoryPath: "/state/memory", thread_id: threadId };
      },
      publicMemoryPolicyForThread(_store, threadId) {
        calls.push({ method: "publicMemoryPolicyForThread", threadId });
        return { ...policyState, thread_id: threadId, agent_id: agent.id };
      },
      publicListMemoryForThread(_store, threadId, input = {}) {
        calls.push({ method: "publicListMemoryForThread", threadId, input });
        return {
          schema_version: "ioi.agent-runtime.memory.v1",
          object: "ioi.agent_memory_projection",
          thread_id: threadId,
          records: recordsState
            .filter((record) => record.status !== "deleted")
            .map((record) => ({ ...record, query: input.query, redaction: input.redaction })),
          total_matches: recordsState.filter((record) => record.status !== "deleted").length,
        };
      },
      rememberForAgent(_store, _agent, input) {
        calls.push({ method: "rememberForAgent", input });
        const record = {
          id: `memory-${writes.length + 1}`,
          fact: input.text,
          thread_id: input.threadId,
          agent_id: _agent.id,
          source: input.source,
          memory_key: input.workflow?.memory_key ?? null,
        };
        recordsState.push(record);
        const write = memoryControlResult({
          operation: "write",
          operation_kind: "memory.write",
          memory_state_kind: "record",
          state_id: record.id,
          record,
        });
        writes.push(write);
        return write;
      },
      updateMemoryForThread(_store, threadId, id, input) {
        calls.push({ method: "updateMemoryForThread", threadId, id, input });
        const record = {
          ...(recordsState.find((entry) => entry.id === id) ?? { id, thread_id: threadId, agent_id: agent.id }),
          fact: input.text,
          source: input.source,
        };
        recordsState = recordsState.filter((entry) => entry.id !== id).concat(record);
        const mutation = memoryControlResult({
          operation: "edit",
          operation_kind: "memory.edit",
          memory_state_kind: "record",
          state_id: id,
          record,
        });
        mutations.push(mutation);
        return mutation;
      },
      deleteMemoryForThread(_store, threadId, id, input) {
        calls.push({ method: "deleteMemoryForThread", threadId, id, input });
        const record = {
          ...(recordsState.find((entry) => entry.id === id) ?? { id, thread_id: threadId, agent_id: agent.id }),
          status: "deleted",
          source: input.source,
        };
        recordsState = recordsState.filter((entry) => entry.id !== id).concat(record);
        const mutation = memoryControlResult({
          operation: "delete",
          operation_kind: "memory.delete",
          memory_state_kind: "record",
          state_id: id,
          record,
        });
        mutations.push(mutation);
        return mutation;
      },
      setMemoryPolicyForThread(_store, threadId, input) {
        calls.push({ method: "setMemoryPolicyForThread", threadId, input });
        policyState = {
          ...policyState,
          ...input.policy,
          thread_id: threadId,
          agent_id: agent.id,
          source: input.source,
        };
        const mutation = memoryControlResult({
          operation: "policy",
          operation_kind: "memory.policy",
          memory_state_kind: "policy",
          state_id: `memory_policy_${threadId}`,
          policy: policyState,
        });
        mutations.push(mutation);
        return mutation;
      },
    },
    resolveSubagentMemoryInheritance(input) {
      return helper.resolveSubagentMemoryInheritance(store, input);
    },
  };
  return { agent, calls, helper, mutations, store, writes };
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
  const { agent, calls, helper, store } = createHarness();

  const result = helper.resolveRunMemory(store, agent, { memory: { query: "Known" } }, "hello");

  assert.equal(result.command, "none");
  assert.equal(result.injected, true);
  assert.equal(result.records[0].id, "memory-one");
  assert.equal(result.records[0].query, "Known");
  assert.equal(result.paths.memoryPath, "/state/memory");
  assert.deepEqual(result.writes, []);
  assert.deepEqual(calls.map((call) => call.method), [
    "publicMemoryPathForThread",
    "publicMemoryPolicyForThread",
    "publicListMemoryForThread",
  ]);
});

test("run memory resolution write commands use Rust memory control and Agentgres commit results", () => {
  const rememberHarness = createHarness({
    command: { kind: "remember", text: "Remember this" },
  });

  const remembered = rememberHarness.helper.resolveRunMemory(
    rememberHarness.store,
    rememberHarness.agent,
    { memory: { scope: "thread", memory_key: "launch" } },
    "#remember",
  );
  assert.equal(remembered.writes.length, 1);
  assert.equal(remembered.writes[0].record.fact, "Remember this");
  assert.equal(remembered.writes[0].receipt.kind, "memory_write");
  assert.equal(remembered.writes[0].record.memory_key, "launch");
  assert.equal(rememberHarness.calls.some((call) => call.method === "rememberForAgent"), true);

  const editHarness = createHarness({
    command: { kind: "edit", id: "memory-one", text: "Edited" },
  });
  const edited = editHarness.helper.resolveRunMemory(editHarness.store, editHarness.agent, {}, "#memory edit");
  assert.equal(edited.mutations[0].operation, "memory_edit");
  assert.equal(edited.mutations[0].record.fact, "Edited");
  assert.equal(editHarness.calls.some((call) => call.method === "updateMemoryForThread"), true);

  const deleteHarness = createHarness({
    command: { kind: "delete", id: "memory-one" },
  });
  const deleted = deleteHarness.helper.resolveRunMemory(deleteHarness.store, deleteHarness.agent, {}, "#memory delete");
  assert.equal(deleted.mutations[0].operation, "memory_delete");
  assert.equal(deleted.mutations[0].record.status, "deleted");
  assert.equal(deleteHarness.calls.some((call) => call.method === "deleteMemoryForThread"), true);

  const requestedRememberHarness = createHarness();
  const requested = requestedRememberHarness.helper.resolveRunMemory(
    requestedRememberHarness.store,
    requestedRememberHarness.agent,
    { remember: "Remember from API" },
    "hello",
  );
  assert.equal(requested.writes[0].record.fact, "Remember from API");

  for (const harness of [rememberHarness, editHarness, deleteHarness, requestedRememberHarness]) {
    assert.equal(harness.calls.some((call) => call.method === "publicMemoryPolicyForThread"), true);
    assert.equal(harness.calls.some((call) => call.method === "publicListMemoryForThread"), true);
  }
});

test("run memory resolution policy commands use Rust memory policy control", () => {
  const { agent, helper, store, mutations } = createHarness({
    command: { kind: "disable" },
  });

  const result = helper.resolveRunMemory(store, agent, {}, "/memory disable");

  assert.equal(result.policy.disabled, true);
  assert.equal(result.policy.injection_enabled, false);
  assert.equal(result.policyUpdates.length, 1);
  assert.equal(result.policyUpdates[0].operation, "memory_disable");
  assert.equal(mutations[0].operation, "policy");
});

test("run memory resolution ignores retired memory thread and approval aliases", () => {
  const { agent, calls, helper, store, writes } = createHarness({
    policy: {
      id: "policy-approval",
      injection_enabled: true,
      disabled: false,
      read_only: false,
      write_requires_approval: true,
    },
    command: { kind: "remember", text: "Remember canonical thread" },
  });

  const result = helper.resolveRunMemory(
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
  );
  assert.equal(result.writes.length, 1);
  assert.equal(writes.length, 1);
  assert.equal(calls.find((call) => call.method === "rememberForAgent").input.threadId, "thread-canonical");

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

test("run memory resolution fails closed before JS cache reads when Rust memory surface is missing", () => {
  const { agent, helper, store } = createHarness();
  store.threadMemorySurface = null;

  assert.throws(
    () => helper.resolveRunMemory(store, agent, {}, "hello"),
    (error) => assertRunMemoryRustCoreRequired(error, { operation: "memory_projection" }),
  );
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
