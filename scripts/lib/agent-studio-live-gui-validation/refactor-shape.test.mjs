import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = process.cwd();

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function lineCount(source) {
  return source.split("\n").length;
}

test("live Agent Studio GUI validation runner is split from historical hardening wrapper", () => {
  const runner = read("scripts/run-autopilot-agent-studio-live-gui-validation.mjs");
  const wrapper = read("scripts/run-autopilot-agent-studio-chat-ux-hardening-goal.mjs");
  const promptSubmit = read("scripts/lib/agent-studio-live-gui-validation/prompt-submit.mjs");
  const scenarioRegistry = read("scripts/lib/autopilot-agent-studio-chat-scenarios.mjs");
  const lmStudioScenarios = read("scripts/lib/agent-studio-scenarios/lm-studio-parity-prompts.mjs");

  assert.match(wrapper, /Compatibility wrapper/);
  assert.match(wrapper, /run-autopilot-agent-studio-live-gui-validation\.mjs/);
  assert.match(runner, /createSubmitPrompt/);
  assert.doesNotMatch(runner, /async function submitPrompt/);
  assert.match(promptSubmit, /export function createSubmitPrompt/);
  assert.match(promptSubmit, /return submitPrompt/);
  assert.match(scenarioRegistry, /agent-studio-scenarios\/lm-studio-parity-prompts\.mjs/);
  assert.doesNotMatch(scenarioRegistry, /const LM_STUDIO_PARITY_PLUS_PROMPTS =/);
  assert.match(lmStudioScenarios, /export const LM_STUDIO_PARITY_PLUS_PROMPTS/);
  assert.ok(lineCount(runner) < 2_500, "live GUI validation runner should stay below the split checkpoint");
});
