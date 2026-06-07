import assert from "node:assert/strict";
import test from "node:test";

import {
  computerUseProjectionForRun,
} from "./computer-use-projection.mjs";

test("computer-use projection accepts canonical computer_use_target_ref", () => {
  const projection = projectionFor({
    runId: "projection_canonical_target",
    metadata: {
      computer_use: true,
      computer_use_action_kind: "click",
      computer_use_target_ref: "target_requested",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_requested");
  assert.equal(projection.affordanceGraph.affordances[0].target_ref, "target_requested");
  assert.equal(projection.events.find((event) => event.type === "computer_use_action_proposed")
    .data.computer_use_target_ref, "target_requested");
});

test("computer-use projection ignores retired targetRef request alias", () => {
  const projection = projectionFor({
    runId: "projection_retired_target",
    metadata: {
      computer_use: true,
      computer_use_action_kind: "click",
      targetRef: "target_retired",
      computerUseTargetRef: "target_retired_computer_use",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_projection_retired_target_document");
  assert.equal(projection.affordanceGraph.affordances[0].target_ref, "target_projection_retired_target_document");
  assert.equal(projection.events.find((event) => event.type === "computer_use_action_proposed")
    .data.computer_use_target_ref, "target_projection_retired_target_document");
});

test("computer-use projection accepts canonical action and approval refs", () => {
  const projection = projectionFor({
    runId: "projection_canonical_action",
    metadata: {
      computer_use: true,
      computer_use_action_kind: "click",
      computer_use_approval_ref: "approval_computer_use",
      computer_use_target_ref: "target_requested",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_requested");
  assert.equal(projection.actionProposal.normalized_action_candidate, "click target_requested");
  assert.equal(projection.action, null);
  assert.equal(projection.actionReceipt, null);
  assert.equal(projection.policyDecision.action_kind, "click");
  assert.equal(projection.policyDecision.approval_ref, "approval_computer_use");
  assert.equal(projection.policyDecision.outcome, "blocked_executor_unavailable");
});

test("computer-use projection ignores retired actionKind and approvalRef aliases", () => {
  const projection = projectionFor({
    runId: "projection_retired_action",
    prompt: "inspect the requested computer-use target",
    metadata: {
      computer_use: true,
      actionKind: "click",
      approvalRef: "approval_retired",
      computerUseActionKind: "click",
      computerUseApprovalRef: "approval_retired_computer_use",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_projection_retired_action_document");
  assert.equal(projection.actionProposal.normalized_action_candidate, "inspect current page and summarize actionable targets");
  assert.equal(projection.action.action_kind, "inspect");
  assert.equal(projection.actionReceipt.status, "completed");
  assert.equal(projection.policyDecision.action_kind, "inspect");
  assert.equal(projection.policyDecision.approval_ref, null);
  assert.equal(projection.policyDecision.outcome, "approved_for_read_only_probe");
});

test("computer-use projection accepts canonical controlled relaunch metadata", () => {
  const projection = projectionFor({
    runId: "projection_canonical_controlled_relaunch",
    metadata: {
      computer_use: true,
      computer_use_lane: "native_browser",
      computer_use_session_mode: "controlled_relaunch",
      observation_retention_mode: "prompt_visible_summary_only",
      controlled_relaunch_broker: {
        broker_ref: "broker_canonical",
        adapter_id: "adapter_canonical",
        start_url: "https://example.test",
        profile_dir_ref: "profile_canonical",
        launch_plan_ref: "launch_plan_canonical",
        profile_provenance: "temporary_canonical",
        forbidden_authority: ["custom_forbidden"],
      },
    },
  });

  assert.equal(projection.environmentSelection.selected_session_mode, "controlled_relaunch");
  assert.equal(projection.environmentSelection.privacy_impact, "prompt_visible_summary_only");
  assert.equal(projection.lease.environment_ref, "native_browser:controlled_relaunch:broker_canonical");
  assert.equal(projection.lease.profile_provenance, "temporary_canonical");
  assert.equal(projection.lease.retention_mode, "prompt_visible_summary_only");
  assert.equal(projection.adapterContract.adapter_id, "adapter_canonical");
  const environmentEvent = projection.events.find((event) => event.type === "computer_use_environment_selected");
  assert.equal(environmentEvent.data.controlled_relaunch_broker.broker_ref, "broker_canonical");
  assert.equal(environmentEvent.data.controlled_relaunch_broker.launch_plan_ref, "launch_plan_canonical");
  assert.equal(environmentEvent.data.controlled_relaunch_broker.profile_dir_ref, "profile_canonical");
  assert.ok(environmentEvent.data.controlled_relaunch_broker.forbidden_authority.includes("custom_forbidden"));
});

test("computer-use projection ignores retired controlled relaunch aliases", () => {
  const projection = projectionFor({
    runId: "projection_retired_controlled_relaunch",
    metadata: {
      computer_use: true,
      computer_use_lane: "native_browser",
      computer_use_session_mode: "controlled_relaunch",
      observationRetentionMode: "prompt_visible_summary_only",
      controlledRelaunchBroker: {
        brokerRef: "broker_retired",
        adapterId: "adapter_retired",
        startUrl: "https://retired.example.test",
        profileDirRef: "profile_retired",
        launchPlanRef: "launch_plan_retired",
        profileProvenance: "retired_profile",
        forbiddenAuthority: ["retired_forbidden"],
      },
      controlledRelaunchBrokerRef: "broker_retired_field",
      controlledRelaunchLaunchReceipt: { launch_ref: "launch_retired" },
    },
  });

  assert.equal(projection.environmentSelection.privacy_impact, "no_persistence");
  assert.equal(projection.runState.blocker_state, "controlled_relaunch_broker_unavailable");
  assert.equal(projection.lease.status, "failed_closed");
  assert.equal(projection.lease.environment_ref, "native_browser:unavailable");
  assert.equal(projection.adapterContract, undefined);
  assert.equal(projection.events.some((event) => event.data.controlled_relaunch_broker), false);
});

function projectionFor({ runId, metadata, prompt = "click the requested computer-use target" }) {
  return computerUseProjectionForRun({
    agent: { cwd: "/tmp/ioi-projection-test" },
    runId,
    prompt,
    mode: "dry_run",
    selectedModel: "model_test",
    request: { metadata },
  });
}
