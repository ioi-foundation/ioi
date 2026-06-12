import assert from "node:assert/strict";
import { test } from "node:test";

import {
  agentForThread,
  deleteAgent,
  getAgent,
  getRun,
  inFlightRuntimeTurnKey,
  listAgents,
  listRuns,
  registerInFlightRuntimeTurn,
  resolveRunForThreadTurn,
  unregisterInFlightRuntimeTurn,
  updateAgent,
  usageForRun,
  usageForThread,
} from "./thread-store.mjs";

function deps(calls = []) {
  return {
    agentIdForThread(threadId) {
      return threadId.replace(/^thread_/, "agent_");
    },
    notFound(message, details) {
      const error = new Error(message);
      error.details = details;
      return error;
    },
    path: {
      join(...parts) {
        return parts.join("/");
      },
    },
    policyError(message, details) {
      const error = new Error(message);
      error.details = details;
      error.policy = true;
      return error;
    },
    runIdForTurn(turnId) {
      return turnId.replace(/^turn_/, "run_");
    },
    runtimeTurnIdForRun(run) {
      return run.runtimeTurnId ?? `turn_${run.id.replace(/^run_/, "")}`;
    },
    turnIdForRun(runId) {
      return `turn_${runId.replace(/^run_/, "")}`;
    },
  };
}

function fakeStore(options = {}) {
  const calls = [];
  return {
    agents: new Map(),
    calls,
    contextPolicyRunner: {
      planLifecycleAdmissionRequired(request = {}) {
        calls.push({ operation: "plan_lifecycle_admission_required", input: request });
        return lifecycleRequiredRecord(request);
      },
      planAgentStatusStateUpdate(request = {}) {
        calls.push({ operation: "plan_agent_status_state_update", input: request });
        if (Object.hasOwn(options, "agentStatusStateUpdate")) return options.agentStatusStateUpdate;
        return {
          status: "planned",
          operation_kind: request.operation_kind,
          agent: {
            ...request.agent,
            status: request.status,
            updatedAt: request.updated_at,
          },
        };
      },
      planAgentDeleteStateUpdate(request = {}) {
        calls.push({ operation: "plan_agent_delete_state_update", input: request });
        if (Object.hasOwn(options, "agentDeleteStateUpdate")) return options.agentDeleteStateUpdate;
        return {
          status: "planned",
          operation_kind: request.operation_kind,
          agent: {
            ...request.agent,
            status: "deleted",
            deletedAt: request.deleted_at,
            updatedAt: request.deleted_at,
          },
        };
      },
    },
    inFlightRuntimeTurns: new Map(),
    runs: new Map(),
    stateDir: "/state",
    subagents: new Map(),
    appendOperation(operationKind, payload) {
      this.calls.push({ operation: "append_operation", operationKind, payload });
    },
    agentForThread(threadId) {
      return agentForThread(this, threadId, deps(this.calls));
    },
    getAgent(agentId) {
      return getAgent(this, agentId, deps(this.calls));
    },
    getRun(runId) {
      return getRun(this, runId, deps(this.calls));
    },
    inFlightRuntimeTurnKey(threadId, turnId) {
      return inFlightRuntimeTurnKey(threadId, turnId);
    },
    listRuns(agentId) {
      return listRuns(this, agentId);
    },
    removeQuiet(file) {
      this.calls.push({ operation: "remove_quiet", file });
    },
    writeAgent(agent, operationKind) {
      this.calls.push({ operation: "write_agent", agent, operationKind });
      this.agents.set(agent.id, agent);
    },
  };
}

function lifecycleRequiredRecord(request) {
  const isDelete = request.operation === "agent_delete";
  return {
    source: "rust_lifecycle_admission_required_command",
    backend: "rust_policy",
    record: {
      status: "rust_core_required",
      status_code: 501,
      code: isDelete
        ? "runtime_agent_delete_rust_core_required"
        : "runtime_agent_status_control_rust_core_required",
      message: isDelete
        ? "Permanent agent deletion requires direct Rust daemon-core admission and persistence."
        : "Agent lifecycle/status control requires direct Rust daemon-core admission and projection.",
      details: {
        rust_core_boundary: isDelete ? "runtime.agent_delete" : "runtime.agent_status_control",
        operation: request.operation,
        operation_kind: request.operation_kind,
        agent_id: request.agent_id,
        requested_status: request.requested_status ?? null,
        requested_operation_kind: request.requested_operation_kind ?? null,
        evidence_refs: request.evidence_refs,
      },
    },
  };
}

function assertNoRetiredAgentStatusDetailAliases(details) {
  for (const key of ["rustCoreBoundary", "operationKind", "agentId", "requestedStatus", "evidenceRefs"]) {
    assert.equal(Object.hasOwn(details, key), false, `retired agent status detail alias ${key}`);
  }
}

function assertNoRetiredAgentDeleteDetailAliases(details) {
  for (const key of ["rustCoreBoundary", "operationKind", "agentId", "evidenceRefs", "runCount"]) {
    assert.equal(Object.hasOwn(details, key), false, `retired agent delete detail alias ${key}`);
  }
}

test("thread store lists and resolves agents", () => {
  const store = fakeStore();
  store.agents.set("agent_late", { id: "agent_late", createdAt: "2026-06-03T00:00:02.000Z" });
  store.agents.set("agent_early", { id: "agent_early", createdAt: "2026-06-03T00:00:01.000Z" });

  assert.deepEqual(listAgents(store).map((agent) => agent.id), ["agent_early", "agent_late"]);
  assert.equal(getAgent(store, "agent_early", deps()).id, "agent_early");
  assert.equal(agentForThread(store, "thread_early", deps()).id, "agent_early");
  assert.throws(
    () => getAgent(store, "agent_missing", deps()),
    (error) => {
      assert.equal(error.details.agentId, "agent_missing");
      return true;
    },
  );
});

test("thread store lists and resolves runs", () => {
  const store = fakeStore();
  store.runs.set("run_late", { id: "run_late", agentId: "agent_1", createdAt: "2026-06-03T00:00:02.000Z" });
  store.runs.set("run_other", { id: "run_other", agentId: "agent_2", createdAt: "2026-06-03T00:00:00.000Z" });
  store.runs.set("run_early", { id: "run_early", agentId: "agent_1", createdAt: "2026-06-03T00:00:01.000Z" });

  assert.deepEqual(listRuns(store, "agent_1").map((run) => run.id), ["run_early", "run_late"]);
  assert.deepEqual(listRuns(store).map((run) => run.id), ["run_other", "run_early", "run_late"]);
  assert.equal(getRun(store, "run_late", deps()).id, "run_late");
  assert.throws(
    () => getRun(store, "run_missing", deps()),
    (error) => {
      assert.equal(error.details.runId, "run_missing");
      return true;
    },
  );
});

test("thread store projects usage for run and thread", () => {
  const store = fakeStore();
  store.agents.set("agent_1", { id: "agent_1", createdAt: "2026-06-03T00:00:00.000Z" });
  store.runs.set("run_1", { id: "run_1", agentId: "agent_1", createdAt: "2026-06-03T00:00:01.000Z" });
  store.runs.set("run_2", { id: "run_2", agentId: "agent_1", createdAt: "2026-06-03T00:00:02.000Z" });
  store.subagents.set("subagent_1", { id: "subagent_1", parent_thread_id: "thread_1" });
  store.subagents.set("subagent_2", { id: "subagent_2", parent_thread_id: "thread_1" });
  store.subagents.set("subagent_retired", { id: "subagent_retired", parentThreadId: "thread_1" });
  store.subagents.set("subagent_other", { id: "subagent_other", parent_thread_id: "thread_other" });

  const usageDeps = {
    runtimeUsageTelemetryForRun({ run, agent, threadId }) {
      return { scope: "run", runId: run.id, agentId: agent.id, threadId };
    },
    runtimeUsageTelemetryForThread({ threadId, agent, runs, subagents }) {
      return {
        scope: "thread",
        threadId,
        agentId: agent.id,
        runIds: runs.map((run) => run.id),
        subagentIds: subagents.map((subagent) => subagent.id),
      };
    },
    threadIdForAgent(agentId) {
      return agentId.replace(/^agent_/, "thread_");
    },
  };

  assert.deepEqual(usageForRun(store, "run_1", usageDeps), {
    scope: "run",
    runId: "run_1",
    agentId: "agent_1",
    threadId: "thread_1",
  });
  assert.deepEqual(usageForThread(store, "thread_1", usageDeps), {
    scope: "thread",
    threadId: "thread_1",
    agentId: "agent_1",
    runIds: ["run_1", "run_2"],
    subagentIds: ["subagent_1", "subagent_2"],
  });
});

test("thread store updates agent status through Rust state planning and Agentgres commit", () => {
  const store = fakeStore();
  store.agents.set("agent_1", { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" });

  const agent = updateAgent(store, "agent_1", "archived", "agent.archive");

  assert.equal(agent.status, "archived");
  assert.equal(store.agents.get("agent_1").status, "archived");
  assert.equal(store.calls.some((call) => call.operation === "plan_lifecycle_admission_required"), false);
  assert.deepEqual(
    store.calls.filter((call) => call.operation === "plan_agent_status_state_update"),
    [{
      operation: "plan_agent_status_state_update",
      input: {
        agent: { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" },
        status: "archived",
        operation_kind: "agent.archive",
        updated_at: store.calls.find((call) => call.operation === "plan_agent_status_state_update").input.updated_at,
      },
    }],
  );
  assert.match(
    store.calls.find((call) => call.operation === "plan_agent_status_state_update").input.updated_at,
    /^\d{4}-\d{2}-\d{2}T/,
  );
  assert.deepEqual(
    store.calls.filter((call) => call.operation === "write_agent"),
    [{
      operation: "write_agent",
      agent,
      operationKind: "agent.archive",
    }],
  );
});

test("thread store agent status control fails closed without Rust status planner", () => {
  const store = fakeStore();
  store.contextPolicyRunner = {};
  store.agents.set("agent_1", { id: "agent_1", status: "active" });

  assert.throws(
    () => updateAgent(store, "agent_1", "archived", "agent.archive"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_agent_status_control_rust_core_required");
      assert.equal(error.details.agent_id, "agent_1");
      assert.equal(error.details.requested_status, "archived");
      assert.equal(error.details.requested_operation_kind, "agent.archive");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_agent_status_control_js_facade_retired",
        "runtime_agent_archive_js_facade_retired",
        "runtime_agent_unarchive_js_facade_retired",
        "runtime_agent_resume_js_facade_retired",
        "runtime_agent_close_js_facade_retired",
        "runtime_agent_reload_js_facade_retired",
        "rust_daemon_core_agent_status_control_required",
        "agentgres_agent_status_state_truth_required",
      ]);
      assertNoRetiredAgentStatusDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "plan_lifecycle_admission_required"), false);
  assert.equal(store.calls.some((call) => call.operation === "plan_agent_status_state_update"), false);
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store agent status control rejects missing Rust-planned agent", () => {
  const store = fakeStore({ agentStatusStateUpdate: { status: "planned", operation_kind: "agent.archive" } });
  store.agents.set("agent_1", { id: "agent_1", status: "active" });

  assert.throws(
    () => updateAgent(store, "agent_1", "archived", "agent.archive"),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "agent_status_state_update_agent_missing");
      assert.equal(error.details.agent_id, "agent_1");
      assert.equal(error.details.requested_status, "archived");
      assertNoRetiredAgentStatusDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store agent status control rejects mismatched Rust operation kind", () => {
  const store = fakeStore({
    agentStatusStateUpdate: {
      status: "planned",
      operation_kind: "agent.unarchive",
      agent: { id: "agent_1", status: "archived" },
    },
  });
  store.agents.set("agent_1", { id: "agent_1", status: "active" });

  assert.throws(
    () => updateAgent(store, "agent_1", "archived", "agent.archive"),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "agent_status_state_update_operation_kind_mismatch");
      assert.equal(error.details.expected_operation_kind, "agent.archive");
      assert.equal(error.details.actual_operation_kind, "agent.unarchive");
      assertNoRetiredAgentStatusDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store permanent delete commits Rust tombstone through Agentgres", () => {
  const store = fakeStore();
  store.agents.set("agent_1", { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" });
  store.runs.set("run_1", { id: "run_1", agentId: "agent_1" });

  const agent = deleteAgent(store, "agent_1", deps(store.calls));

  assert.equal(agent.status, "deleted");
  assert.equal(store.agents.get("agent_1").status, "deleted");
  assert.equal(store.calls.some((call) => call.operation === "plan_lifecycle_admission_required"), false);
  assert.deepEqual(
    store.calls.filter((call) => call.operation === "plan_agent_delete_state_update"),
    [{
      operation: "plan_agent_delete_state_update",
      input: {
        agent: { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" },
        operation_kind: "agent.delete",
        deleted_at: store.calls.find((call) => call.operation === "plan_agent_delete_state_update").input.deleted_at,
      },
    }],
  );
  assert.match(
    store.calls.find((call) => call.operation === "plan_agent_delete_state_update").input.deleted_at,
    /^\d{4}-\d{2}-\d{2}T/,
  );
  assert.deepEqual(
    store.calls.filter((call) => call.operation === "write_agent"),
    [{
      operation: "write_agent",
      agent,
      operationKind: "agent.delete",
    }],
  );
  assert.equal(store.calls.some((call) => call.operation === "remove_quiet"), false);
  assert.equal(store.calls.some((call) => call.operation === "append_operation"), false);
});

test("thread store permanent delete fails closed without Rust delete planner", () => {
  const store = fakeStore();
  store.contextPolicyRunner = {};
  store.agents.set("agent_1", { id: "agent_1", status: "active" });

  assert.throws(
    () => deleteAgent(store, "agent_1", deps(store.calls)),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_agent_delete_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.agent_delete");
      assert.equal(error.details.operation, "agent_delete");
      assert.equal(error.details.operation_kind, "agent_deletion");
      assert.equal(error.details.agent_id, "agent_1");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_agent_delete_js_facade_retired",
        "rust_daemon_core_agent_delete_required",
        "agentgres_agent_delete_state_truth_required",
      ]);
      assertNoRetiredAgentDeleteDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.agents.has("agent_1"), true);
  assert.equal(store.calls.some((call) => call.operation === "plan_lifecycle_admission_required"), false);
  assert.equal(store.calls.some((call) => call.operation === "plan_agent_delete_state_update"), false);
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store permanent delete rejects missing Rust tombstone agent", () => {
  const store = fakeStore({ agentDeleteStateUpdate: { status: "planned", operation_kind: "agent.delete" } });
  store.agents.set("agent_1", { id: "agent_1", status: "active" });

  assert.throws(
    () => deleteAgent(store, "agent_1", deps(store.calls)),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "agent_delete_state_update_agent_missing");
      assert.equal(error.details.agent_id, "agent_1");
      assertNoRetiredAgentDeleteDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store permanent delete rejects mismatched Rust operation kind", () => {
  const store = fakeStore({
    agentDeleteStateUpdate: {
      status: "planned",
      operation_kind: "agent.archive",
      agent: { id: "agent_1", status: "deleted", deletedAt: "2026-06-06T06:40:00.000Z" },
    },
  });
  store.agents.set("agent_1", { id: "agent_1", status: "active" });

  assert.throws(
    () => deleteAgent(store, "agent_1", deps(store.calls)),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "agent_delete_state_update_operation_kind_mismatch");
      assert.equal(error.details.expected_operation_kind, "agent.delete");
      assert.equal(error.details.actual_operation_kind, "agent.archive");
      assertNoRetiredAgentDeleteDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store permanent delete rejects incomplete Rust tombstone", () => {
  const store = fakeStore({
    agentDeleteStateUpdate: {
      status: "planned",
      operation_kind: "agent.delete",
      agent: { id: "agent_1", status: "active" },
    },
  });
  store.agents.set("agent_1", { id: "agent_1", status: "active" });

  assert.throws(
    () => deleteAgent(store, "agent_1", deps(store.calls)),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "agent_delete_state_update_tombstone_missing");
      assert.equal(error.details.expected_operation_kind, "agent.delete");
      assertNoRetiredAgentDeleteDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "remove_quiet"), false);
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store registers and resolves in-flight runtime turns", () => {
  const store = fakeStore();
  const agent = { id: "agent_1" };

  registerInFlightRuntimeTurn(store, {
    agent,
    threadId: "thread_1",
    turnId: "turn_1",
    request: { prompt: "hello" },
  }, deps());

  const resolved = resolveRunForThreadTurn(store, agent, "thread_1", "turn_1", deps());
  assert.equal(resolved.runId, "run_1");
  assert.equal(resolved.inFlight.prompt, "hello");

  unregisterInFlightRuntimeTurn(store, "thread_1", "turn_1");
  assert.equal(store.inFlightRuntimeTurns.size, 0);
});

test("thread store resolves direct and runtime turn runs", () => {
  const store = fakeStore();
  const agent = { id: "agent_1" };
  store.runs.set("run_1", { id: "run_1", agentId: "agent_1" });
  store.runs.set("run_runtime", { id: "run_runtime", agentId: "agent_1", runtimeTurnId: "turn_runtime" });

  assert.equal(resolveRunForThreadTurn(store, agent, "thread_1", "turn_1", deps()).runId, "run_1");
  assert.equal(resolveRunForThreadTurn(store, agent, "thread_1", "turn_runtime", deps()).runId, "run_runtime");
  assert.throws(
    () => resolveRunForThreadTurn(store, { id: "agent_other" }, "thread_1", "turn_1", deps()),
    (error) => {
      assert.equal(error.details.turnId, "turn_1");
      return true;
    },
  );
});
