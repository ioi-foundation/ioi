import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const {
  refreshStudioReplayStepsFromProjection,
} = require("./projection-replay.js");

test("Studio replay projection combines recent runtime events and receipts", () => {
  const projection = {
    runtimeEvents: Array.from({ length: 10 }, (_, index) => ({
      id: `event-${index + 1}`,
      kind: "runtime.event",
      status: index === 9 ? "completed" : "observed",
      summary: `Event ${index + 1}`,
    })),
    receipts: Array.from({ length: 6 }, (_, index) => ({
      id: `receipt-${index + 1}`,
      kind: "runtime_receipt",
      summary: `Receipt ${index + 1}`,
    })),
    replaySteps: [],
    runtimeCockpit: {},
  };

  refreshStudioReplayStepsFromProjection(projection);

  assert.equal(projection.replaySteps.length, 12);
  assert.equal(projection.replaySteps[0].id, "event-5");
  assert.equal(projection.replaySteps.at(-1).id, "receipt-6");
  assert.equal(projection.replaySteps.at(-1).status, "receipted");
  assert.equal(projection.runtimeCockpit.receiptTimelinePerStepObserved, true);
  assert.equal(projection.runtimeCockpit.replayStepDetailObserved, true);
});

test("Studio replay projection tolerates sparse projection state", () => {
  const projection = {};
  refreshStudioReplayStepsFromProjection(projection);

  assert.deepEqual(projection.replaySteps, []);
  assert.deepEqual(projection.runtimeCockpit, {
    receiptTimelinePerStepObserved: false,
    replayStepDetailObserved: false,
  });

  assert.doesNotThrow(() => refreshStudioReplayStepsFromProjection(null));
});
