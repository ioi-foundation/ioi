import assert from "node:assert/strict";
import test from "node:test";

import {
  computerUseContractsFromSandboxFixture,
  sandboxFixtureRequested,
} from "./computer-use-sandbox-fixture.mjs";

test("sandbox fixture helper ignores retired camelCase aliases", () => {
  assert.equal(sandboxFixtureRequested({
    computerUseSandboxProvider: "local_fixture",
    computerUseSandboxFixture: true,
  }), false);
  assert.equal(sandboxFixtureRequested({
    computer_use_sandbox_provider: "local_fixture",
    computer_use_sandbox_fixture: true,
  }), true);

  const retiredAliasResult = computerUseContractsFromSandboxFixture({
    request: {
      metadata: {
        computerUseSandboxProvider: "local_fixture",
        computerUseSandboxFixture: true,
        computerUseSandboxImageRef: "image:retired",
        computerUseSandboxTaskRef: "task-retired",
      },
    },
    runId: "run_sandbox_retired_alias",
  });
  assert.equal(retiredAliasResult, null);

  const canonicalResult = computerUseContractsFromSandboxFixture({
    request: {
      metadata: {
        computer_use_sandbox_provider: "local_fixture",
        computer_use_sandbox_fixture: true,
        computer_use_sandbox_image_ref: "image:canonical",
        computer_use_sandbox_task_ref: "task-canonical",
      },
    },
    runId: "run_sandbox_canonical",
  });
  assert.ok(canonicalResult);
  assert.equal(canonicalResult.providerReceipt.image_ref, "image:canonical");
  assert.equal(canonicalResult.providerReceipt.task_ref, "task-canonical");
});
