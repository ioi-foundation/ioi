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

function fakeStore() {
  return {
    agents: new Map(),
    calls: [],
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
  store.subagents.set("subagent_2", { id: "subagent_2", parentThreadId: "thread_1" });
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

test("thread store updates and deletes agents without canonical runs", () => {
  const store = fakeStore();
  store.agents.set("agent_1", { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" });

  const updated = updateAgent(store, "agent_1", "archived", "agent.archive");
  assert.equal(updated.status, "archived");
  assert.equal(store.calls.at(-1).operationKind, "agent.archive");

  deleteAgent(store, "agent_1", deps(store.calls));
  assert.equal(store.agents.has("agent_1"), false);
  assert.equal(store.calls.some((call) => call.operationKind === "agent.delete"), true);
  assert.equal(store.calls.some((call) => call.operation === "remove_quiet"), true);
});

test("thread store blocks permanent delete when runs exist", () => {
  const store = fakeStore();
  store.agents.set("agent_1", { id: "agent_1", status: "active", createdAt: "2026-06-03T00:00:00.000Z" });
  store.runs.set("run_1", { id: "run_1", agentId: "agent_1" });

  assert.throws(
    () => deleteAgent(store, "agent_1", deps(store.calls)),
    (error) => {
      assert.equal(error.policy, true);
      assert.equal(error.details.runCount, 1);
      return true;
    },
  );
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
