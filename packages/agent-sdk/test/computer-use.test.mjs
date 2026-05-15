import assert from "node:assert/strict";
import test from "node:test";

import {
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  computerActionHasGrounding,
  defaultComputerUseHarnessContract,
  isActionProposalReadyForExecution,
} from "../dist/index.js";

test("computer-use contract projection exposes three lanes and behavioral loop", () => {
  const contract = defaultComputerUseHarnessContract();
  assert.equal(contract.schema_version, COMPUTER_USE_CONTRACT_SCHEMA_VERSION);
  assert.deepEqual(contract.required_lanes, ["native_browser", "visual_gui", "sandboxed_hosted"]);
  assert.ok(contract.required_loop_steps.includes("select_environment"));
  assert.ok(contract.required_loop_steps.includes("build_affordance_graph"));
  assert.ok(contract.required_loop_steps.includes("commit_or_handoff"));
  assert.ok(contract.required_contracts.includes("ActionProposal"));
  assert.ok(contract.required_contracts.includes("ObservationRetentionMode"));
  assert.equal(contract.requires_action_proposal_before_execution, true);
  assert.equal(contract.forbids_shadow_runtime_truth, true);
});

test("computer-use helpers require policy-gated proposals and grounded actions", () => {
  assert.equal(
    isActionProposalReadyForExecution({
      proposal_ref: "proposal:1",
      proposed_by: "model",
      model_role: "grounder",
      normalized_action_candidate: "click",
      target_ref: "target:submit",
      confidence: 92,
      rationale_summary: "submit button",
      predicted_postcondition: "form submitted",
      risk_assessment: "external_effect",
    }),
    false,
  );

  assert.equal(
    isActionProposalReadyForExecution({
      proposal_ref: "proposal:1",
      proposed_by: "model",
      model_role: "grounder",
      normalized_action_candidate: "click",
      target_ref: "target:submit",
      confidence: 92,
      rationale_summary: "submit button",
      predicted_postcondition: "form submitted",
      risk_assessment: "external_effect",
      policy_decision_ref: "policy:approved",
    }),
    true,
  );

  assert.equal(
    computerActionHasGrounding({
      action_ref: "action:1",
      action_kind: "click",
      observation_ref: "obs:1",
      payload_summary: "click submit",
      expected_postcondition: "form submitted",
    }),
    false,
  );

  assert.equal(
    computerActionHasGrounding({
      action_ref: "action:1",
      action_kind: "click",
      observation_ref: "obs:1",
      target_ref: "target:submit",
      payload_summary: "click submit",
      expected_postcondition: "form submitted",
    }),
    true,
  );
});
