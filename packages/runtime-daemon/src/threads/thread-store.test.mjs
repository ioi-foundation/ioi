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
    contextPolicyRunner:
      Object.hasOwn(options, "agentStatusStateUpdate")
        ? {
            planLifecycleAdmissionRequired(request = {}) {
              calls.push({ operation: "plan_lifecycle_admission_required", input: request });
              return lifecycleRequiredRecord(request);
            },
            planAgentStatusStateUpdate(request = {}) {
              calls.push({ operation: "plan_agent_status_state_update", input: request });
              return options.agentStatusStateUpdate;
            },
          }
        : {
            planLifecycleAdmissionRequired(request = {}) {
              calls.push({ operation: "plan_lifecycle_admission_required", input: request });
              return lifecycleRequiredRecord(request);
            },
            planAgentStatusStateUpdate(request = {}) {
              calls.push({ operation: "plan_agent_status_state_update", input: request });
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

test("thread store agent status facade fails closed before Rust planning or JS persistence", () => {
  const store = fakeStore();
  store.agents.set("agent_1", { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" });

  assert.throws(
    () => updateAgent(store, "agent_1", "archived", "agent.archive"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_agent_status_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.agent_status_control");
      assert.equal(error.details.operation, "agent_status_control");
      assert.equal(error.details.operation_kind, "agent_status_update");
      assert.equal(error.details.requested_operation_kind, "agent.archive");
      assert.equal(error.details.agent_id, "agent_1");
      assert.equal(error.details.requested_status, "archived");
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
  assert.deepEqual(
    store.calls.filter((call) => call.operation === "plan_lifecycle_admission_required"),
    [{
      operation: "plan_lifecycle_admission_required",
      input: {
        operation: "agent_status_control",
        operation_kind: "agent_status_update",
        agent_id: "agent_1",
        requested_status: "archived",
        requested_operation_kind: "agent.archive",
        evidence_refs: [
          "runtime_agent_status_control_js_facade_retired",
          "runtime_agent_archive_js_facade_retired",
          "runtime_agent_unarchive_js_facade_retired",
          "runtime_agent_resume_js_facade_retired",
          "runtime_agent_close_js_facade_retired",
          "runtime_agent_reload_js_facade_retired",
          "rust_daemon_core_agent_status_control_required",
          "agentgres_agent_status_state_truth_required",
        ],
      },
    }],
  );
  assert.equal(store.calls.some((call) => call.operation === "plan_agent_status_state_update"), false);
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
  assert.equal(store.agents.get("agent_1").status, "active");
});

test("thread store agent status facade fails closed without JS agent lookup", () => {
  const store = fakeStore();
  store.getAgent = () => {
    throw new Error("unexpected JS agent lookup");
  };

  assert.throws(
    () => updateAgent(store, "agent_1", "archived", "agent.archive"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_agent_status_control_rust_core_required");
      assert.equal(error.details.agent_id, "agent_1");
      assert.equal(error.details.requested_status, "archived");
      assert.equal(error.details.requested_operation_kind, "agent.archive");
      assertNoRetiredAgentStatusDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(
    store.calls.filter((call) => call.operation === "plan_lifecycle_admission_required").length,
    1,
  );
  assert.equal(store.calls.some((call) => call.operation === "plan_agent_status_state_update"), false);
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
});

test("thread store permanent delete facade fails closed before JS state mutation", () => {
  const store = fakeStore();
  store.agents.set("agent_1", { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" });
  store.runs.set("run_1", { id: "run_1", agentId: "agent_1" });

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
  assert.deepEqual(
    store.calls.filter((call) => call.operation === "plan_lifecycle_admission_required"),
    [{
      operation: "plan_lifecycle_admission_required",
      input: {
        operation: "agent_delete",
        operation_kind: "agent_deletion",
        agent_id: "agent_1",
        evidence_refs: [
          "runtime_agent_delete_js_facade_retired",
          "rust_daemon_core_agent_delete_required",
          "agentgres_agent_delete_state_truth_required",
        ],
      },
    }],
  );
  assert.equal(store.agents.has("agent_1"), true);
  assert.equal(store.calls.some((call) => call.operation === "remove_quiet"), false);
  assert.equal(store.calls.some((call) => call.operation === "append_operation"), false);
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
