import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRunHelpers } from "./runtime-run-helpers.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function helpers() {
  return createRuntimeRunHelpers({ normalizeArray });
}

test("runtime run helpers preserve mode task family and strategy vocabulary", () => {
  const runtime = helpers();

  assert.equal(runtime.taskFamilyForMode("plan"), "planning");
  assert.equal(runtime.strategyForMode("plan"), "daemon_plan_with_postconditions");
  assert.equal(runtime.taskFamilyForMode("dry_run"), "safety_preview");
  assert.equal(runtime.strategyForMode("handoff"), "daemon_handoff_with_state_preservation");
  assert.equal(runtime.taskFamilyForMode("learn"), "learning");
  assert.equal(runtime.strategyForMode("send"), "local_daemon_agentgres_execution");
  assert.equal(runtime.taskFamilyForMode("unknown"), "local_daemon_agentgres");
});

test("runtime run helpers preserve memory-specific result text", () => {
  const runtime = helpers();
  const agent = { cwd: "/workspace" };

  assert.equal(runtime.resultForMode("send", agent, "prompt", "sdk", { command: "disable" }), "Memory is disabled for this thread.");
  assert.equal(
    runtime.resultForMode("send", agent, "prompt", "sdk", {
      command: "path",
      paths: { recordsPath: "/tmp/records", policiesPath: "/tmp/policies" },
    }),
    "Memory records path: /tmp/records\nMemory policy path: /tmp/policies",
  );
  assert.equal(
    runtime.resultForMode("send", agent, "prompt", "sdk", {
      command: "remember",
      writes: [{ record: { fact: "fact one" } }, { record: { fact: "fact two" } }],
    }),
    "Remembered: fact one; fact two",
  );
  assert.equal(
    runtime.resultForMode("send", agent, "prompt", "sdk", {
      command: "show",
      records: [{ fact: "alpha" }, { fact: "beta" }],
    }),
    "Memory:\n- alpha\n- beta",
  );
});

test("runtime run helpers preserve capability sequence and event ids", () => {
  const runtime = helpers();

  assert.deepEqual(runtime.capabilitySequenceForMode("dry_run", {
    options: {
      mcpServerNames: ["filesystem"],
      skillNames: ["repo"],
      hookNames: ["preflight"],
    },
  }), [
    "authority_check",
    "policy_check",
    "task_state_write",
    "agentgres_operation_log",
    "trace_export",
    "canonical_replay",
    "mcp_containment",
    "skill_instruction_import",
    "runtime_event_hook",
    "side_effect_preview",
  ]);

  const event = runtime.makeEvent("run-one", "agent-one", 7, "runtime_task", "Task recorded", { ok: true });
  assert.equal(event.id, "run-one:event:007:runtime_task");
  assert.equal(event.run_id, "run-one");
  assert.equal(event.agent_id, "agent-one");
  assert.equal(event.cursor, "run-one:7");
  assert.equal(event.summary, "Task recorded");
  assert.deepEqual(event.data, { ok: true });
  assert.match(event.created_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(Object.hasOwn(event, "runId"), false);
  assert.equal(Object.hasOwn(event, "agentId"), false);
  assert.equal(Object.hasOwn(event, "createdAt"), false);
});
