import assert from "node:assert/strict";
import test from "node:test";
import {
  PRE_NEXT_LEG_COMMANDS,
  runPreNextLeg,
} from "./check-pre-next-leg.mjs";

test("pre-next-leg propagates a compositor-tier failure", () => {
  const seen = [];
  const status = runPreNextLeg({
    commands: PRE_NEXT_LEG_COMMANDS,
    runCommand(command, args) {
      const step = PRE_NEXT_LEG_COMMANDS.find(
        (candidate) =>
          candidate.command === command &&
          candidate.args.length === args.length &&
          candidate.args.every((argument, index) => argument === args[index]),
      );
      assert.ok(step, `unrecognized command fixture: ${command} ${args.join(" ")}`);
      seen.push(step.id);
      return { status: step.id === "compositor" ? 23 : 0 };
    },
  });

  assert.equal(status, 23);
  assert.deepEqual(seen, [
    "runtime-action-generator-check",
    "runtime-action-generator-regressions",
    "pre-next-leg-gate-regressions",
    "architecture-contract-bar",
    "architecture-docs",
    "conformance-docs",
    "readiness",
    "compositor",
  ]);
  assert.equal(seen.includes("runtime-layout"), false);
});
