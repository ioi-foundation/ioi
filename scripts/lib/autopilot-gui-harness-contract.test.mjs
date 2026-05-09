import assert from "node:assert/strict";
import test from "node:test";

import {
  AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
  AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS,
  AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS,
  DEFAULT_LIVE_PROMOTION_INVARIANTS,
  autopilotGuiHarnessContract,
  buildBlockedAutopilotGuiHarnessResult,
  retainedQueryByScenario,
  validateAutopilotGuiHarnessResult,
  validateDefaultLivePromotionInvariants,
} from "./autopilot-gui-harness-contract.mjs";

function reviewedImportActivationApplyProof(overrides = {}) {
  const activationId =
    "activation:package-evidence-import-roundtrip-fork:validated-canary:default-agen";
  const rollbackTarget = "activation:default-agent-harness:blessed-readonly";
  const workerHandoffAttempt =
    "harness-worker-handoff:attempt:launch:harness-worker-session:package-evidence-import-roundtrip-fork";
  const base = {
    passed: true,
    clicked: true,
    activationAction: {
      activationIdPreview: activationId,
      blockerCount: 0,
      canaryStatus: "passed",
      disabled: false,
      evidenceReady: true,
      handoffDecision: "mintable",
      handoffPresent: true,
      mintable: true,
      present: true,
      rollbackTarget,
      workerBindingId: activationId,
    },
    activationResult: {
      activationId,
      applied: true,
      workflowActivationId: activationId,
      workflowActivationState: "validated",
      workerBindingActivationId: activationId,
      activationRecordWorkerBindingActivationId: activationId,
      rollbackTarget,
      revisionBindingActivationId: activationId,
      activationRecordRevisionBindingHash: "stable-fnv1a32:8cfd072b",
      rollbackRevisionBindingHash: "stable-fnv1a32:8cfd072b",
      latestAuditEventType: "activation_minted",
      latestAuditStatus: "applied",
      receiptRefs: ["activation-receipt:reviewed-import"],
      evidenceRefs: ["candidate:package-evidence-import-roundtrip-fork"],
      workerHandoffReceiptIds: ["harness-worker-handoff-receipt:launch"],
      workerHandoffNodeAttemptIds: [workerHandoffAttempt],
      workerHandoffReplayFixtureRefs: ["harness-worker-handoff:fixture:launch"],
    },
    workerHandoff: {
      deepLinkHash: `#harness-workbench?activationGateNodeAttemptId=${workerHandoffAttempt}`,
      selectedAttemptId: workerHandoffAttempt,
      selectedState: {
        "data-selected-activation-gate-id": "worker-handoff",
        "data-selected-activation-gate-node-attempt-id": workerHandoffAttempt,
      },
      timelineVisible: true,
    },
    incompleteAction: {
      disabled: true,
      mintable: false,
    },
  };
  return {
    ...base,
    ...overrides,
    activationAction: {
      ...base.activationAction,
      ...(overrides.activationAction ?? {}),
    },
    activationResult: {
      ...base.activationResult,
      ...(overrides.activationResult ?? {}),
    },
    workerHandoff: {
      ...base.workerHandoff,
      ...(overrides.workerHandoff ?? {}),
      selectedState: {
        ...base.workerHandoff.selectedState,
        ...(overrides.workerHandoff?.selectedState ?? {}),
      },
    },
    incompleteAction: {
      ...base.incompleteAction,
      ...(overrides.incompleteAction ?? {}),
    },
  };
}

function promotionInvariantUiAssertions(proof = reviewedImportActivationApplyProof()) {
  return {
    promotionTransitionLiveGui: {
      checks: {
        packageImportActivationApplyProof: true,
      },
      packageImportActivationApplyProof: proof,
    },
  };
}

test("autopilot GUI harness contract preserves retained query pack", () => {
  const contract = autopilotGuiHarnessContract();
  assert.equal(contract.launchCommand, AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND);
  assert.equal(contract.requiredEnv.AUTOPILOT_LOCAL_GPU_DEV, "1");
  assert.equal(contract.requiredEnv.AUTOPILOT_HARNESS_DEFAULT_PROMOTION, "1");
  assert.equal(contract.requiredEnv.AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT, "1");
  assert.equal(contract.retainedQueries.length, 8);
  assert.deepEqual(contract.providerGatedVisibleOutputRequiredScenarios, [
    ...AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS,
  ]);
  assert.deepEqual(contract.providerGatedVisibleOutputRequiredScenarios, [
    "retained_no_tool_answer",
    "retained_repo_grounded_answer",
    "retained_planning_without_mutation",
    "retained_mermaid_rendering",
    "retained_source_heavy_synthesis",
    "retained_probe_behavior",
    "retained_harness_dogfooding",
  ]);
  assert.deepEqual(contract.readOnlyCapabilityRoutingRequiredScenarios, [
    ...AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS,
  ]);
  assert.deepEqual(contract.readOnlyCapabilityRoutingRequiredScenarios, [
    "retained_repo_grounded_answer",
    "retained_source_heavy_synthesis",
    "retained_probe_behavior",
  ]);
  assert.deepEqual(contract.defaultLivePromotionInvariants, [
    ...DEFAULT_LIVE_PROMOTION_INVARIANTS,
  ]);
  assert.ok(retainedQueryByScenario("safety_boundary"));
  assert.equal(
    retainedQueryByScenario("safety_boundary").providerGatedVisibleOutputRequired,
    false,
  );
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

test("runtime consistency contract requires harness shadow proof", () => {
  const contract = autopilotGuiHarnessContract();
  assert.ok(contract.requiredArtifacts.includes("harness_shadow_run"));
  assert.ok(contract.requiredArtifacts.includes("harness_gated_cognition"));
  assert.ok(contract.requiredArtifacts.includes("harness_gated_routing_model"));
  assert.ok(contract.requiredArtifacts.includes("harness_gated_verification_output"));
  assert.ok(contract.requiredArtifacts.includes("harness_gated_authority_tooling"));
  assert.ok(contract.requiredArtifacts.includes("harness_fork_activation"));
  assert.ok(contract.requiredArtifacts.includes("harness_rollback_restore_canary"));
  assert.ok(contract.requiredArtifacts.includes("harness_rollback_restore_canary_ui"));
  assert.ok(contract.requiredArtifacts.includes("harness_package_evidence_manifest"));
  assert.ok(contract.requiredArtifacts.includes("harness_package_evidence_gate"));
  assert.ok(contract.requiredArtifacts.includes("harness_package_evidence_gate_click_proof"));
  assert.ok(contract.requiredArtifacts.includes("harness_package_evidence_import_roundtrip"));
  assert.ok(contract.requiredArtifacts.includes("harness_package_import_review_mode"));
  assert.ok(contract.requiredArtifacts.includes("harness_package_import_activation_handoff"));
  assert.ok(contract.requiredArtifacts.includes("harness_package_import_activation_apply"));
  assert.ok(contract.requiredArtifacts.includes("harness_promotion_transition_gui_behavior"));
  assert.ok(
    contract.requiredArtifacts.includes(
      "harness_promotion_transition_live_gui_interaction",
    ),
  );
  assert.ok(contract.requiredArtifacts.includes("harness_route_stateful_deep_link_replay"));
  assert.ok(contract.requiredArtifacts.includes("harness_cold_start_deep_link_restore"));
  assert.ok(contract.requiredArtifacts.includes("harness_revision_binding_deep_link_restore"));
  assert.ok(contract.requiredArtifacts.includes("harness_activation_blocker_deep_link_restore"));
  assert.ok(contract.requiredArtifacts.includes("harness_activation_audit_deep_link_restore"));
  assert.ok(contract.requiredArtifacts.includes("harness_activation_gate_deep_link_restore"));
  assert.ok(contract.requiredArtifacts.includes("harness_activation_gate_evidence_inspector"));
  assert.ok(
    contract.requiredArtifacts.includes(
      "harness_activation_gate_ref_deep_link_restore",
    ),
  );
  assert.ok(contract.requiredArtifacts.includes("harness_activation_gate_action_workbench"));
  assert.ok(contract.requiredArtifacts.includes("harness_activation_gate_action_click_proof"));
  assert.ok(
    contract.requiredArtifacts.includes(
      "harness_activation_gate_collect_evidence_click_proof",
    ),
  );
  assert.ok(
    contract.requiredArtifacts.includes(
      "harness_activation_gate_rollback_restore_click_proof",
    ),
  );
  assert.ok(contract.requiredArtifacts.includes("harness_activation_id_gate_click_proof"));
  assert.ok(contract.requiredArtifacts.includes("harness_canary_execution_boundary"));
  assert.ok(contract.requiredArtifacts.includes("harness_live_handoff"));
  assert.ok(contract.requiredArtifacts.includes("harness_selector_routing"));
  assert.ok(
    contract.requiredArtifacts.includes(
      "harness_selector_reviewed_import_activation_apply_invariant",
    ),
  );
  assert.ok(contract.requiredArtifacts.includes("harness_default_runtime_dispatch"));
  assert.ok(contract.requiredArtifacts.includes("harness_chat_runtime_binding"));
  assert.ok(contract.requiredArtifacts.includes("harness_live_turn_node_timeline"));
  assert.ok(
    contract.requiredArtifacts.includes("harness_authority_tooling_provider_catalog_live"),
  );
  assert.ok(
    contract.requiredArtifacts.includes("harness_authority_tooling_mcp_tool_catalog_live"),
  );
  assert.ok(
    contract.requiredArtifacts.includes("harness_authority_tooling_native_tool_catalog_live"),
  );
  assert.ok(
    contract.requiredArtifacts.includes("harness_authority_tooling_connector_catalog_live"),
  );
  assert.ok(
    contract.requiredArtifacts.includes(
      "harness_authority_tooling_wallet_capability_live_dry_run",
    ),
  );
  assert.ok(contract.requiredArtifacts.includes("harness_model_provider_gated_visible_output"));
  assert.ok(
    contract.requiredArtifacts.includes(
      "harness_model_provider_gated_visible_output_rollback_drill",
    ),
  );
  assert.ok(contract.requiredArtifacts.includes("harness_read_only_capability_routing"));
  assert.ok(contract.runtimeConsistencyRequirements.includes("harness_shadow_attempts_present"));
  assert.ok(contract.runtimeConsistencyRequirements.includes("harness_gated_cognition_present"));
  assert.ok(
    contract.runtimeConsistencyRequirements.includes("harness_gated_routing_model_present"),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_gated_verification_output_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_gated_authority_tooling_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes("harness_fork_activation_present"),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_rollback_restore_canary_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_rollback_restore_canary_receipts_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_audit_receipts_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_rollback_execution_receipts_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_rollback_restore_canary_ui_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_package_evidence_manifest_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_package_evidence_gate_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_package_evidence_gate_click_proof_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_package_evidence_import_roundtrip_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_package_import_review_mode_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_package_import_activation_handoff_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_package_import_activation_apply_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_promotion_transition_gui_behavior_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_promotion_transition_live_gui_interaction_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_route_stateful_deep_link_replay_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_cold_start_deep_link_restore_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_revision_binding_deep_link_restore_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_blocker_deep_link_restore_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_audit_deep_link_restore_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_gate_deep_link_restore_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_gate_evidence_inspector_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_gate_ref_deep_link_restore_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_gate_action_workbench_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_gate_action_click_proof_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_gate_collect_evidence_click_proof_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_gate_rollback_restore_click_proof_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_activation_id_gate_click_proof_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_canary_execution_boundary_present",
    ),
  );
  assert.ok(contract.runtimeConsistencyRequirements.includes("harness_live_handoff_present"));
  assert.ok(contract.runtimeConsistencyRequirements.includes("harness_selector_default_promoted"));
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_selector_live_promotion_readiness_gated",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_selector_reviewed_import_activation_apply_invariant_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_default_runtime_dispatch_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_live_promotion_readiness_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_chat_runtime_binding_matches_workflow_activation",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_live_turn_node_timeline_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_authority_tooling_provider_catalog_live_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_authority_tooling_mcp_tool_catalog_live_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_authority_tooling_native_tool_catalog_live_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_authority_tooling_connector_catalog_live_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_authority_tooling_wallet_capability_live_dry_run_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_model_provider_gated_visible_output_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_model_provider_gated_visible_output_rollback_drill_present",
    ),
  );
  assert.ok(
    contract.runtimeConsistencyRequirements.includes(
      "harness_read_only_capability_routing_present",
    ),
  );
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
    uiAssertions: promotionInvariantUiAssertions(),
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

test("default-live promotion requires reviewed import activation apply proof", () => {
  const passing = validateDefaultLivePromotionInvariants({
    uiAssertions: promotionInvariantUiAssertions(),
  });
  assert.deepEqual(passing, {
    ok: true,
    failures: [],
  });

  const missing = validateDefaultLivePromotionInvariants({});
  assert.equal(missing.ok, false);
  assert.ok(
    missing.failures.includes(
      "default live promotion invariant failed: reviewed import activation apply proof did not pass",
    ),
  );
  assert.ok(
    missing.failures.includes(
      "default live promotion invariant failed: Activate reviewed import was not clicked",
    ),
  );

  const invalidWorkerBinding = validateDefaultLivePromotionInvariants({
    uiAssertions: promotionInvariantUiAssertions(
      reviewedImportActivationApplyProof({
        activationResult: {
          workerBindingActivationId: "activation:wrong",
        },
      }),
    ),
  });
  assert.equal(invalidWorkerBinding.ok, false);
  assert.ok(
    invalidWorkerBinding.failures.includes(
      "default live promotion invariant failed: worker binding does not point at the minted activation id",
    ),
  );
});

test("complete GUI harness result rejects claimed promotion without embedded apply proof", () => {
  const contract = autopilotGuiHarnessContract();
  const claimed = {
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

  const validation = validateAutopilotGuiHarnessResult(claimed);
  assert.equal(validation.ok, false);
  assert.ok(
    validation.failures.includes(
      "default live promotion invariant failed: reviewed import activation apply proof did not pass",
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
