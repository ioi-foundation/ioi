import assert from "node:assert/strict";
import test from "node:test";

import {
  computerUseContractsFromVisualObservation,
} from "./computer-use-visual-observation.mjs";

test("computer-use visual observation projects canonical target and affordance fields", () => {
  const contracts = computerUseContractsFromVisualObservation({
    runId: "run_visual_contract",
    request: {
      metadata: {
        computer_use_visual_observation: {
          screenshot_ref: "artifact_screenshot_one",
          coordinate_space_id: "screen_one",
          visual_targets: [
            {
              target_ref: "target_run",
              label: "Run button",
              role: "button",
              semantic_ids: ["run-button"],
              som_id: 7,
              available_actions: ["click"],
              bounds: {
                coordinate_space_id: "screen_one",
                x: 10,
                y: 20,
                width: 100,
                height: 40,
              },
            },
          ],
          visual_affordances: [
            {
              affordance_ref: "affordance_run_click",
              target_ref: "target_run",
              possible_action: "click",
              action_preconditions: ["fresh_observation"],
              action_confidence: 0.9,
              expected_state_transition: "button_clicked",
              risk_class: "external_effect",
              required_authority: "computer_use.visual_gui.act",
              required_confirmation: true,
              fallback_action_paths: ["reobserve"],
              invalidation_conditions: ["screenshot_hash_changed"],
            },
          ],
        },
      },
    },
  });

  assert.equal(contracts.targetIndex.targets[0].target_ref, "target_run");
  assert.deepEqual(contracts.targetIndex.targets[0].semantic_ids, ["run-button"]);
  assert.equal(contracts.targetIndex.targets[0].som_id, 7);
  assert.deepEqual(contracts.targetIndex.targets[0].available_actions, ["click"]);
  assert.equal(contracts.targetIndex.targets[0].bounds.coordinate_space_id, "screen_one");
  assert.equal(contracts.affordanceGraph.affordances[0].affordance_ref, "affordance_run_click");
  assert.equal(contracts.affordanceGraph.affordances[0].target_ref, "target_run");
  assert.equal(contracts.affordanceGraph.affordances[0].possible_action, "click");
  assert.deepEqual(contracts.affordanceGraph.affordances[0].action_preconditions, ["fresh_observation"]);
  assert.equal(contracts.affordanceGraph.affordances[0].action_confidence, 0.9);
  assert.equal(contracts.affordanceGraph.affordances[0].expected_state_transition, "button_clicked");
  assert.equal(contracts.affordanceGraph.affordances[0].risk_class, "external_effect");
  assert.equal(contracts.affordanceGraph.affordances[0].required_authority, "computer_use.visual_gui.act");
  assert.equal(contracts.affordanceGraph.affordances[0].required_confirmation, true);
  assert.deepEqual(contracts.affordanceGraph.affordances[0].fallback_action_paths, ["reobserve"]);
  assert.deepEqual(contracts.affordanceGraph.affordances[0].invalidation_conditions, ["screenshot_hash_changed"]);
});

test("computer-use visual observation ignores retired target and affordance aliases", () => {
  const contracts = computerUseContractsFromVisualObservation({
    runId: "run_visual_contract",
    request: {
      metadata: {
        computer_use_visual_observation: {
          screenshot_ref: "artifact_screenshot_one",
          coordinate_space_id: "screen_canonical",
          visual_targets: [
            {
              targetRef: "target_legacy",
              semanticIds: ["legacy-semantic"],
              somId: 9,
              availableActions: ["click"],
              bounds: {
                coordinateSpaceId: "screen_legacy",
                x: 10,
                y: 20,
                width: 100,
                height: 40,
              },
            },
          ],
          visual_affordances: [
            {
              affordanceRef: "affordance_legacy",
              targetRef: "target_legacy",
              possibleAction: "click",
              actionPreconditions: ["legacy_precondition"],
              actionConfidence: 0.9,
              expectedStateTransition: "legacy_transition",
              riskClass: "external_effect",
              requiredAuthority: "computer_use.visual_gui.act",
              requiredConfirmation: true,
              fallbackActionPaths: ["legacy_fallback"],
              invalidationConditions: ["legacy_invalidation"],
            },
          ],
        },
      },
    },
  });

  const target = contracts.targetIndex.targets[0];
  assert.equal(target.target_ref, "target_visual_1");
  assert.deepEqual(target.semantic_ids, []);
  assert.equal(target.som_id, null);
  assert.deepEqual(target.available_actions, ["inspect"]);
  assert.equal(target.bounds.coordinate_space_id, "screen_canonical");

  const affordance = contracts.affordanceGraph.affordances[0];
  assert.equal(affordance.affordance_ref, "affordance_run_visual_contract_visual_1");
  assert.equal(affordance.target_ref, "target_visual_1");
  assert.equal(affordance.possible_action, "inspect");
  assert.deepEqual(affordance.action_preconditions, []);
  assert.equal(affordance.action_confidence, 0.5);
  assert.equal(affordance.expected_state_transition, "no_external_effect");
  assert.equal(affordance.risk_class, "read_only");
  assert.equal(affordance.required_authority, "computer_use.visual_gui.read");
  assert.equal(affordance.required_confirmation, false);
  assert.deepEqual(affordance.fallback_action_paths, []);
  assert.deepEqual(affordance.invalidation_conditions, []);
});

test("computer-use visual observation ignores retired observation metadata aliases", () => {
  const contracts = computerUseContractsFromVisualObservation({
    runId: "run_visual_retired_metadata",
    request: {
      metadata: {
        computerUseVisualObservation: {
          screenshotRef: "artifact_retired_screenshot",
          somRef: "artifact_retired_som",
          axRef: "artifact_retired_ax",
          appName: "Retired App",
          windowTitle: "Retired Window",
          coordinateSpaceId: "screen_retired",
          viewportWidth: 800,
          viewportHeight: 600,
          redactionReportRef: "artifact_retired_redaction",
          freshnessMs: 10,
          detectedPatterns: ["retired_pattern"],
          visualTargets: [
            {
              target_ref: "target_retired",
              available_actions: ["click"],
            },
          ],
          visualAffordances: [
            {
              target_ref: "target_retired",
              possible_action: "click",
            },
          ],
        },
        screenshotRef: "artifact_retired_top_level_screenshot",
        visualTargets: [{ target_ref: "target_retired_top_level" }],
      },
    },
  });

  assert.equal(contracts, null);
});
