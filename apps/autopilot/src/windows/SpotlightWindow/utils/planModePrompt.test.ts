import assert from "node:assert/strict";
import {
  PLAN_MODE_DIRECTIVE,
  buildPlanModeIntent,
  planModePlaceholder,
  planModeStatusCopy,
} from "./planModePrompt.ts";

assert.equal(buildPlanModeIntent("Ship the next slice", false), "Ship the next slice");

{
  const value = buildPlanModeIntent("Ship the next slice", true);
  assert.match(value, /Plan mode is active/i);
  assert.match(value, /Operator request:/i);
  assert.match(value, /Ship the next slice/);
}

assert.equal(buildPlanModeIntent("", true), "");
assert.equal(buildPlanModeIntent(PLAN_MODE_DIRECTIVE, true), PLAN_MODE_DIRECTIVE);
assert.match(planModePlaceholder(), /execution plan/i);
assert.match(planModeStatusCopy(), /plan drawer/i);
