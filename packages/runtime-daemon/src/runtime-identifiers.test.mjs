import assert from "node:assert/strict";
import test from "node:test";

import {
  agentIdForThread,
  eventStreamIdForThread,
  fixtureProfileForAgent,
  isRuntimeBackedAgent,
  lifecycleStatusForRun,
  runIdForTurn,
  runtimeSessionIdForAgent,
  runtimeTurnIdForRun,
  threadIdForAgent,
  threadStatusForAgent,
  turnIdForRun,
} from "./runtime-identifiers.mjs";
import { DAEMON_FIXTURE_PROFILE } from "./runtime-contract-constants.mjs";

test("runtime identity helpers preserve thread, agent, run, turn, and stream ids", () => {
  assert.equal(threadIdForAgent("agent_alpha"), "thread_alpha");
  assert.equal(threadIdForAgent("external_agent"), "thread_external_agent");
  assert.equal(agentIdForThread("thread_alpha"), "agent_alpha");
  assert.equal(agentIdForThread("external_thread"), "external_thread");
  assert.equal(turnIdForRun("run_alpha"), "turn_alpha");
  assert.equal(turnIdForRun("external_run"), "turn_external_run");
  assert.equal(runIdForTurn("turn_alpha"), "run_alpha");
  assert.equal(runIdForTurn("external_turn"), "run_external_turn");
  assert.equal(eventStreamIdForThread("thread_alpha"), "thread_alpha:events");
});

test("runtime identity helpers preserve session and fixture profile defaults", () => {
  assert.equal(runtimeSessionIdForAgent({ id: "agent_alpha" }), "agent_alpha");
  assert.equal(runtimeSessionIdForAgent({ id: "agent_alpha", runtimeSessionId: "session_alpha" }), "session_alpha");
  assert.equal(runtimeTurnIdForRun({ id: "run_alpha" }), "turn_alpha");
  assert.equal(runtimeTurnIdForRun({ id: "run_alpha", runtime_turn_id: "turn_runtime" }), "turn_runtime");
  assert.equal(fixtureProfileForAgent({}), DAEMON_FIXTURE_PROFILE);
  assert.equal(fixtureProfileForAgent({ fixtureProfile: null }), null);
});

test("runtime identity helpers normalize runtime and lifecycle statuses", () => {
  assert.equal(isRuntimeBackedAgent({ runtimeProfile: "runtime_service" }), true);
  assert.equal(isRuntimeBackedAgent({ runtime_profile: "runtime_service" }), true);
  assert.equal(isRuntimeBackedAgent({ runtimeProfile: "deterministic_fixture" }), false);
  assert.equal(threadStatusForAgent("closed"), "archived");
  assert.equal(threadStatusForAgent("error"), "failed");
  assert.equal(threadStatusForAgent("running"), "active");
  assert.equal(lifecycleStatusForRun("queued"), "queued");
  assert.equal(lifecycleStatusForRun("running"), "running");
  assert.equal(lifecycleStatusForRun("canceled"), "canceled");
  assert.equal(lifecycleStatusForRun("error"), "failed");
  assert.equal(lifecycleStatusForRun("blocked"), "waiting_for_input");
  assert.equal(lifecycleStatusForRun("completed"), "completed");
});
