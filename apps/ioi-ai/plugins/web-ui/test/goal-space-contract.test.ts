import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activationId,
  errorDetail,
  goalSpaceTabForKey,
  goalRunId,
  kernelOwnerBindings,
  outcomeRoomId,
  requiredKernelBindingsComplete,
} from "../src/goal-space-contract.ts";

test("Goal Space tabs implement the horizontal and vertical keyboard patterns", () => {
  assert.equal(goalSpaceTabForKey("goals", "ArrowRight"), "rooms");
  assert.equal(goalSpaceTabForKey("rooms", "ArrowLeft"), "goals");
  assert.equal(goalSpaceTabForKey("goals", "End"), "rooms");
  assert.equal(goalSpaceTabForKey("rooms", "Home"), "goals");
  assert.equal(goalSpaceTabForKey("goals", "Enter"), null);
});

test("canonical ids are accepted from refs while cross-family and malformed ids refuse", () => {
  assert.equal(goalRunId({ goal_ref: "goal://gr_123" }), "gr_123");
  assert.equal(outcomeRoomId({ outcome_room_id: "outcome-room://or_456" }), "or_456");
  assert.equal(activationId({ activation_id: "goal-run-activation://gra_789" }), "gra_789");
  assert.equal(goalRunId({ goal_ref: "outcome-room://or_456" }), null);
  assert.equal(goalRunId({ goal_ref: "goal://gr_bad/path" }), null);
});

test("execution readiness requires exact canonical owner fields and ignores legacy local session summaries", () => {
  const legacy = {
    invocation: {
      thread_ref: "thread://legacy",
      session_ref: "session:goalrun-local",
      launch_ref: "launch://legacy",
      harness_binding_ref: "binding://legacy",
    },
  };
  assert.equal(requiredKernelBindingsComplete(legacy), false);
  assert.deepEqual(
    kernelOwnerBindings(legacy)
      .slice(0, 5)
      .map((binding) => binding.value),
    [null, null, null, null, null],
  );

  const nestedImpostor = {
    error: {
      runtime_thread_event_ref: "agentgres://runtime-events/thread_1/operations/event_1",
      runtime_thread_fork_control_ref: "agentgres://runtime-events/thread_1/operations/fork_1",
      runtime_managed_session_control_ref: "agentgres://runtime-events/thread_1/operations/session_1",
      hypervisor_session_launch_recipe_admission_ref: "hypervisor-session-launch-recipe-admission:recipe_1",
      harness_session_binding_admission_ref: "harness-session-binding-admission:binding_1",
    },
  };
  assert.equal(requiredKernelBindingsComplete(nestedImpostor), false);

  const canonical = {
    runtime_thread_event_ref: "agentgres://runtime-events/thread_1/operations/event_1",
    runtime_thread_fork_control_ref: "agentgres://runtime-events/thread_1/operations/fork_1",
    runtime_managed_session_control_ref: "agentgres://runtime-events/thread_1/operations/session_1",
    hypervisor_session_launch_recipe_admission_ref: "hypervisor-session-launch-recipe-admission:recipe_1",
    harness_session_binding_admission_ref: "harness-session-binding-admission:binding_1",
  };
  assert.equal(requiredKernelBindingsComplete(canonical), true);
  assert.equal(
    requiredKernelBindingsComplete({
      ...canonical,
      harness_session_binding_admission_ref: "harness-session-binding://wrong",
    }),
    false,
  );
});

test("typed daemon errors retain nested codes, messages, and details", () => {
  assert.deepEqual(
    errorDetail({
      error: {
        code: "goal_run_execution_budget_exhausted",
        message: "zero invocation capacity",
        details: { effects_started: false },
      },
    }),
    {
      code: "goal_run_execution_budget_exhausted",
      message: "zero invocation capacity",
      details: { effects_started: false },
    },
  );
});
