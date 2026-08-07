import { test } from "node:test";
import assert from "node:assert/strict";
import {
  clearGoalActivationRecovery,
  createGoalActivationRecovery,
  readGoalActivationRecovery,
  writeGoalActivationRecovery,
} from "../src/goal-space-recovery.ts";

function memoryStorage() {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
    values,
  };
}

test("activation retry coordinates are durable before send and recoverable by activation id", () => {
  const storage = memoryStorage();
  const recovery = createGoalActivationRecovery(
    "alice",
    "Produce a verified outcome",
    ["bounded"],
    "ioi-ai-idem-1",
    "2026-08-06T20:00:00.000Z",
  );
  writeGoalActivationRecovery(storage, recovery);
  assert.deepEqual(readGoalActivationRecovery(storage, "alice"), recovery);
  recovery.activationId = "gra_123";
  writeGoalActivationRecovery(storage, recovery);
  assert.equal(readGoalActivationRecovery(storage, "alice")?.activationId, "gra_123");
});

test("recovery coordinates are principal-scoped and explicitly clearable", () => {
  const storage = memoryStorage();
  const recovery = createGoalActivationRecovery("alice", "A durable goal", [], "ioi-ai-idem-2");
  writeGoalActivationRecovery(storage, recovery);
  assert.equal(readGoalActivationRecovery(storage, "bob"), null);
  clearGoalActivationRecovery(storage, "alice");
  assert.equal(readGoalActivationRecovery(storage, "alice"), null);
});

test("malformed or cross-principal recovery bytes fail closed", () => {
  const storage = memoryStorage();
  storage.setItem(
    "ioi-ai:goal-activation-recovery:alice",
    JSON.stringify({
      schemaVersion: "ioi.ai.goal-activation-recovery.v1",
      principal: "mallory",
      idempotencyKey: "idem",
      goalText: "goal",
      constraints: [],
      activationId: "gra_1",
      createdAt: "now",
    }),
  );
  assert.equal(readGoalActivationRecovery(storage, "alice"), null);
  storage.setItem("ioi-ai:goal-activation-recovery:alice", "not-json");
  assert.equal(readGoalActivationRecovery(storage, "alice"), null);
});
