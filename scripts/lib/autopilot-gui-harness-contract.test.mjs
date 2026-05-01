import assert from "node:assert/strict";
import test from "node:test";

import {
  AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
  autopilotGuiHarnessContract,
  buildBlockedAutopilotGuiHarnessResult,
  retainedQueryByScenario,
  validateAutopilotGuiHarnessResult,
} from "./autopilot-gui-harness-contract.mjs";

test("autopilot GUI harness contract preserves retained query pack", () => {
  const contract = autopilotGuiHarnessContract();
  assert.equal(contract.launchCommand, AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND);
  assert.equal(contract.requiredEnv.AUTOPILOT_LOCAL_GPU_DEV, "1");
  assert.equal(contract.retainedQueries.length, 8);
  assert.ok(retainedQueryByScenario("safety_boundary"));
  assert.ok(retainedQueryByScenario("probe_behavior"));
  assert.ok(retainedQueryByScenario("harness_dogfooding"));
});

test("clean chat UX contract forbids crude default evidence surfaces", () => {
  const contract = autopilotGuiHarnessContract();
  assert.ok(contract.cleanChatUxRequirements.includes("no_raw_receipt_dump"));
  assert.ok(contract.cleanChatUxRequirements.includes("no_default_facts_dashboard"));
  assert.ok(contract.cleanChatUxRequirements.includes("no_default_evidence_drawer"));
  assert.ok(contract.cleanChatUxRequirements.includes("collapsible_thinking"));
  assert.ok(contract.cleanChatUxRequirements.includes("collapsible_explored_files"));
  assert.ok(contract.cleanChatUxRequirements.includes("source_pills_reserved_for_search"));
});

test("GUI automation contract stays composer-only and forbids activity-bar clicks", () => {
  const contract = autopilotGuiHarnessContract();
  assert.equal(contract.guiAutomationClickPolicy.mode, "same-session-composer-only");
  assert.ok(contract.guiAutomationClickPolicy.safeZone.minWindowX >= 300);
  assert.ok(contract.guiAutomationClickPolicy.safeZone.minWindowY >= 120);
  assert.ok(contract.guiAutomationClickPolicy.forbiddenZones.includes("left_activity_bar"));
  assert.ok(contract.guiAutomationClickPolicy.forbiddenZones.includes("settings_activity_bar_icon"));
  assert.ok(contract.guiAutomationClickPolicy.forbiddenZones.includes("top_window_chrome"));
});

test("complete GUI harness result validates only when UI and runtime evidence agree", () => {
  const contract = autopilotGuiHarnessContract();
  const passing = {
    schemaVersion: contract.schemaVersion,
    launchCommand: contract.launchCommand,
    queryResults: contract.retainedQueries.map((query) => ({
      scenario: query.scenario,
      passed: true,
      runtimeEvidence: {
        matchedUserRequest: true,
        hasAssistantResponse: true,
        concatenatedPrompt: false,
      },
    })),
    artifacts: Object.fromEntries(contract.requiredArtifacts.map((artifact) => [artifact, true])),
    chatUx: Object.fromEntries(
      contract.cleanChatUxRequirements.map((requirement) => [requirement, true]),
    ),
    runtimeConsistency: Object.fromEntries(
      contract.runtimeConsistencyRequirements.map((requirement) => [requirement, true]),
    ),
  };

  assert.deepEqual(validateAutopilotGuiHarnessResult(passing), {
    ok: true,
    failures: [],
  });

  const failing = {
    ...passing,
    runtimeConsistency: {
      ...passing.runtimeConsistency,
      visible_output_matches_trace: false,
    },
  };
  const validation = validateAutopilotGuiHarnessResult(failing);
  assert.equal(validation.ok, false);
  assert.ok(
    validation.failures.includes(
      "runtime consistency requirement failed: visible_output_matches_trace",
    ),
  );
});

test("GUI harness rejects screenshot-only false positives", () => {
  const contract = autopilotGuiHarnessContract();
  const result = {
    schemaVersion: contract.schemaVersion,
    launchCommand: contract.launchCommand,
    queryResults: contract.retainedQueries.map((query) => ({
      scenario: query.scenario,
      passed: true,
      runtimeEvidence: {
        matchedUserRequest: query.scenario !== "safety_boundary",
        hasAssistantResponse: query.scenario !== "safety_boundary",
        concatenatedPrompt: query.scenario === "safety_boundary",
      },
    })),
    artifacts: Object.fromEntries(contract.requiredArtifacts.map((artifact) => [artifact, true])),
    chatUx: Object.fromEntries(
      contract.cleanChatUxRequirements.map((requirement) => [requirement, true]),
    ),
    runtimeConsistency: Object.fromEntries(
      contract.runtimeConsistencyRequirements.map((requirement) => [requirement, true]),
    ),
  };

  const validation = validateAutopilotGuiHarnessResult(result);
  assert.equal(validation.ok, false);
  assert.ok(
    validation.failures.includes(
      "retained query missing exact transcript request: safety_boundary",
    ),
  );
  assert.ok(
    validation.failures.includes("retained query missing assistant response: safety_boundary"),
  );
  assert.ok(
    validation.failures.includes(
      "retained query prompt concatenated with another request: safety_boundary",
    ),
  );
});

test("blocked result records external blocker without pretending validation passed", () => {
  const blocked = buildBlockedAutopilotGuiHarnessResult({
    reason: "missing xdotool",
    evidence: ["xdotool not found on PATH"],
  });
  const validation = validateAutopilotGuiHarnessResult(blocked);
  assert.equal(blocked.blocked, true);
  assert.equal(validation.ok, false);
  assert.ok(validation.failures.some((failure) => failure.includes("missing retained query")));
});
