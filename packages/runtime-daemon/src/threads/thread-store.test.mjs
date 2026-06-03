import assert from "node:assert/strict";
import { test } from "node:test";

import {
  agentForThread,
  deleteAgent,
  getAgent,
  inFlightRuntimeTurnKey,
  listAgents,
  registerInFlightRuntimeTurn,
  resolveRunForThreadTurn,
  unregisterInFlightRuntimeTurn,
  updateAgent,
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
    appendOperation(operationKind, payload) {
      this.calls.push({ operation: "append_operation", operationKind, payload });
    },
    getAgent(agentId) {
      return getAgent(this, agentId, deps(this.calls));
    },
    inFlightRuntimeTurnKey(threadId, turnId) {
      return inFlightRuntimeTurnKey(threadId, turnId);
    },
    listRuns(agentId) {
      return [...this.runs.values()].filter((run) => !agentId || run.agentId === agentId);
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
