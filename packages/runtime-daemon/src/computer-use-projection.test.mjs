import assert from "node:assert/strict";
import test from "node:test";

import {
  computerUseProjectionForRun,
} from "./computer-use-projection.mjs";

test("computer-use projection accepts canonical computer_use_target_ref", () => {
  const projection = computerUseProjectionForRun({
    agent: { cwd: "/tmp/ioi-projection-test" },
    runId: "projection_canonical_target",
    prompt: "click the requested computer-use target",
    mode: "dry_run",
    selectedModel: "model_test",
    request: {
      metadata: {
        computer_use: true,
        computer_use_action_kind: "click",
        computer_use_target_ref: "target_requested",
      },
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_requested");
  assert.equal(projection.affordanceGraph.affordances[0].target_ref, "target_requested");
  assert.equal(projection.events.find((event) => event.type === "computer_use_action_proposed")
    .data.computer_use_target_ref, "target_requested");
});

test("computer-use projection ignores retired targetRef request alias", () => {
  const projection = computerUseProjectionForRun({
    agent: { cwd: "/tmp/ioi-projection-test" },
    runId: "projection_retired_target",
    prompt: "click the requested computer-use target",
    mode: "dry_run",
    selectedModel: "model_test",
    request: {
      metadata: {
        computer_use: true,
        computer_use_action_kind: "click",
        targetRef: "target_retired",
      },
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_projection_retired_target_document");
  assert.equal(projection.affordanceGraph.affordances[0].target_ref, "target_projection_retired_target_document");
  assert.equal(projection.events.find((event) => event.type === "computer_use_action_proposed")
    .data.computer_use_target_ref, "target_projection_retired_target_document");
});
