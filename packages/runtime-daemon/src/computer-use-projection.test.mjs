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

test("computer-use projection accepts canonical native-browser execution metadata", () => {
  const projection = projectionFor({
    runId: "projection_canonical_native_execution",
    metadata: {
      computer_use: true,
      computer_use_lane: "native_browser",
      computer_use_action_kind: "click",
      computer_use_approval_ref: "approval_native_execution",
      computer_use_native_browser_execution: {
        status: "completed",
        adapter_id: "adapter_native_execution",
        executor_ref: "executor_native_execution",
        after: {
          url: "https://executed.example.test",
          title: "Executed page",
          html_ref: "artifact:executed:dom",
        },
      },
    },
  });

  assert.equal(projection.policyDecision.outcome, "approved_after_confirmation");
  assert.equal(projection.action.action_kind, "click");
  assert.equal(projection.actionReceipt.status, "completed");
  assert.equal(projection.actionReceipt.adapter_id, "adapter_native_execution");
  assert.equal(projection.observation.url, "https://executed.example.test");
  assert.equal(projection.observation.title, "Executed page");
  assert.ok(projection.lease.evidence_refs.includes("executor_native_execution"));
});

test("computer-use projection ignores retired native-browser execution aliases", () => {
  const projection = projectionFor({
    runId: "projection_retired_native_execution",
    metadata: {
      computer_use: true,
      computer_use_lane: "native_browser",
      computer_use_action_kind: "click",
      computer_use_approval_ref: "approval_native_execution",
      computerUseNativeBrowserExecution: {
        status: "completed",
        adapter_id: "adapter_retired_execution",
        executor_ref: "executor_retired_execution",
        after: {
          url: "https://retired-executed.example.test",
          title: "Retired executed page",
          html_ref: "artifact:retired-executed:dom",
        },
      },
      computerUseExecutionResult: {
        status: "completed",
        adapter_id: "adapter_retired_generic_execution",
      },
    },
  });

  assert.equal(projection.policyDecision.outcome, "blocked_executor_unavailable");
  assert.equal(projection.action, null);
  assert.equal(projection.actionReceipt, null);
  assert.equal(projection.runState.blocker_state, "commit_gate_requires_confirmation");
  assert.notEqual(projection.observation.url, "https://retired-executed.example.test");
  assert.equal(projection.lease.evidence_refs.includes("executor_retired_execution"), false);
});

test("computer-use projection accepts canonical contract override metadata", () => {
  const projection = projectionFor({
    runId: "projection_canonical_contract_overrides",
    metadata: {
      computer_use: true,
      computer_use_observation_bundle: {
        observation_ref: "observation_canonical_override",
        target_index_ref: "target_index_canonical_override",
        title: "Canonical override title",
        screenshot_ref: "artifact:canonical:screenshot",
      },
      computer_use_target_index: {
        target_index_ref: "target_index_canonical_override",
        targets: [
          {
            target_ref: "target_canonical_override",
            label: "Canonical target",
            role: "button",
            semantic_ids: ["canonical-target"],
            available_actions: ["click"],
          },
        ],
      },
      computer_use_affordance_graph: {
        graph_ref: "affordance_canonical_override",
        target_index_ref: "target_index_canonical_override",
        affordances: [
          {
            target_ref: "target_canonical_override",
            possible_action: "click",
            confidence: 99,
          },
        ],
      },
      computer_use_adapter_contract: {
        adapter_id: "adapter_canonical_override",
        capabilities: ["canonical_override"],
      },
      computer_use_cleanup_receipt: {
        cleanup_ref: "cleanup_canonical_override",
        status: "completed",
      },
    },
  });

  assert.equal(projection.observation.observation_ref, "observation_canonical_override");
  assert.equal(projection.observation.title, "Canonical override title");
  assert.equal(projection.targetIndex.target_index_ref, "target_index_canonical_override");
  assert.equal(projection.targetIndex.targets[0].target_ref, "target_canonical_override");
  assert.equal(projection.affordanceGraph.graph_ref, "affordance_canonical_override");
  assert.equal(projection.adapterContract.adapter_id, "adapter_canonical_override");
  assert.equal(projection.cleanup.cleanup_ref, "cleanup_canonical_override");
});

test("computer-use projection ignores retired contract override aliases", () => {
  const projection = projectionFor({
    runId: "projection_retired_contract_overrides",
    metadata: {
      computer_use: true,
      computerUseObservationBundle: {
        observation_ref: "observation_retired_override",
        target_index_ref: "target_index_retired_override",
        title: "Retired override title",
      },
      computerUseTargetIndex: {
        target_index_ref: "target_index_retired_override",
        targets: [{ target_ref: "target_retired_override" }],
      },
      computerUseAffordanceGraph: {
        graph_ref: "affordance_retired_override",
      },
      computerUseAdapterContract: {
        adapter_id: "adapter_retired_override",
      },
      computerUseCleanupReceipt: {
        cleanup_ref: "cleanup_retired_override",
      },
      computerUseBrowserObservationArtifacts: {
        screenshot_ref: "artifact:retired:screenshot",
      },
      browserObservationArtifacts: {
        screenshot_ref: "artifact:retired:browser",
      },
    },
  });

  assert.notEqual(projection.observation.observation_ref, "observation_retired_override");
  assert.notEqual(projection.observation.title, "Retired override title");
  assert.notEqual(projection.targetIndex.target_index_ref, "target_index_retired_override");
  assert.notEqual(projection.targetIndex.targets[0].target_ref, "target_retired_override");
  assert.notEqual(projection.affordanceGraph.graph_ref, "affordance_retired_override");
  assert.notEqual(projection.adapterContract.adapter_id, "adapter_retired_override");
  assert.notEqual(projection.cleanup.cleanup_ref, "cleanup_retired_override");
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
