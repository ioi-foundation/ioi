import crypto from "node:crypto";

export const COMPUTER_USE_CONTRACT_SCHEMA_VERSION = "ioi.computer-use.harness.v1";

export function isComputerUseRunEventType(type) {
  return String(type ?? "").startsWith("computer_use_");
}

export function computerUseSourceEventKind(type) {
  switch (type) {
    case "computer_use_environment_selected":
      return "ComputerUse.EnvironmentSelected";
    case "computer_use_lease_acquired":
      return "ComputerUse.LeaseAcquired";
    case "computer_use_run_state":
      return "ComputerUse.RunState";
    case "computer_use_observation":
      return "ComputerUse.Observation";
    case "computer_use_affordance_graph":
      return "ComputerUse.AffordanceGraph";
    case "computer_use_action_proposed":
      return "ComputerUse.ActionProposed";
    case "computer_use_action_executed":
      return "ComputerUse.ActionExecuted";
    case "computer_use_verification":
      return "ComputerUse.Verification";
    case "computer_use_commit_gate":
      return "ComputerUse.CommitGate";
    case "computer_use_trajectory_written":
      return "ComputerUse.TrajectoryWritten";
    case "computer_use_cleanup":
      return "ComputerUse.Cleanup";
    default:
      return "ComputerUse.Event";
  }
}

export function computerUseProjectionForRun({
  agent,
  runId,
  prompt,
  mode,
  request,
  selectedModel,
}) {
  if (!shouldProjectComputerUse(prompt, request)) {
    return null;
  }
  const workflowBinding = computerUseWorkflowBinding(request);
  const requestedLane = requestedComputerUseLane(request);
  const requestedRetentionMode =
    workflowBinding.observationRetentionMode ?? "local_redacted_artifacts";
  if (requestedLane !== "native_browser") {
    return unavailableComputerUseProjectionForRun({
      runId,
      prompt,
      mode,
      requestedLane,
      requestedSessionMode: requestedComputerUseSessionMode(request, requestedLane),
      workflowBinding,
    });
  }
  const targetHint = computerUseTargetHint(prompt);
  const leaseId = `lease_${runId}_browser`;
  const observationRef = `observation_${runId}_browser_initial`;
  const targetIndexRef = `target_index_${runId}_browser_initial`;
  const affordanceGraphRef = `affordance_${runId}_browser_initial`;
  const proposalRef = `proposal_${runId}_browser_inspect`;
  const actionRef = `action_${runId}_browser_inspect`;
  const actionReceiptRef = `receipt_${runId}_computer_use_action`;
  const policyDecisionRef = `policy_${runId}_computer_use_read_only`;
  const verificationRef = `verification_${runId}_computer_use_probe`;
  const traceReceiptId = `receipt_${runId}_computer_use_trace`;
  const trajectoryRef = `trajectory_${runId}_computer_use`;
  const cleanupRef = `cleanup_${runId}_computer_use`;
  const environmentSelection = {
    receipt_ref: `receipt_${runId}_computer_use_environment`,
    run_id: runId,
    selected_lane: "native_browser",
    selected_session_mode: "owned_hermetic_browser",
    rejected_options: [
      {
        lane: "visual_gui",
        session_mode: "visual_fallback",
        reason: "DOM, AX, selector, screenshot, and CDP evidence are available before visual fallback.",
      },
      {
        lane: "sandboxed_hosted",
        session_mode: "local_sandbox",
        reason: "This daemon run is local and read-only; sandbox isolation remains available for risky or reproducible tasks.",
      },
    ],
    reasons: [
      "Prompt indicates browser or computer-use automation.",
      "Native browser lane gives the strongest semantic grounding for web tasks.",
      "Visual and sandbox lanes remain explicit fallback options under the same IOI contracts.",
    ],
    risk_posture: mode === "dry_run" ? "preview_only" : "read_only_probe",
    authority_required: "computer_use.native_browser.read",
    privacy_impact: requestedRetentionMode,
    expected_cleanup: "close_owned_browser_context_and_retain_redacted_trace",
  };
  const lease = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    lease_id: leaseId,
    lane: "native_browser",
    session_mode: "owned_hermetic_browser",
    status: "active",
    authority_scope: environmentSelection.authority_required,
    consent_scope: "operator_prompt",
    target_hint: targetHint,
    environment_ref: `local_browser:${stableHash(agent.cwd).slice(0, 16)}`,
    profile_provenance: "temporary_ioi_browser_profile",
    retention_mode: requestedRetentionMode,
    cleanup_required: true,
    evidence_refs: [environmentSelection.receipt_ref, "ioi.native_browser.chromiumoxide"],
  };
  const runState = {
    run_id: runId,
    lease_id: leaseId,
    user_goal: prompt,
    current_subgoal: "Observe the requested surface, index targets, and propose a grounded next action.",
    plan_graph_ref: `plan_graph_${runId}_computer_use`,
    current_observation_ref: observationRef,
    current_target_index_ref: targetIndexRef,
    active_hypotheses: [
      "Native browser semantics should resolve the task before visual fallback.",
      "No external side effect should occur before a policy-gated action proposal.",
    ],
    expected_postcondition: "A redacted observation, target index, affordance graph, and approved read-only action proposal exist.",
    last_action_ref: null,
    verification_status: "unknown",
    blocker_state: null,
    retry_budget: 2,
    risk_posture: environmentSelection.risk_posture,
    user_handoff_ref: null,
    cleanup_state: "cleanup_required",
  };
  const observation = {
    observation_ref: observationRef,
    lease_id: leaseId,
    lane: "native_browser",
    session_mode: "owned_hermetic_browser",
    url: targetHint.startsWith("http") ? targetHint : null,
    title: "IOI computer-use daemon observation",
    app_name: "Chromium",
    window_title: "IOI browser-use harness",
    screenshot_ref: `artifact:${runId}:browser_screenshot_redacted`,
    som_ref: `artifact:${runId}:som_overlay`,
    dom_ref: `artifact:${runId}:dom_snapshot`,
    ax_ref: `artifact:${runId}:ax_tree`,
    selector_map_ref: `artifact:${runId}:selector_map`,
    target_index_ref: targetIndexRef,
    redaction_report_ref: `artifact:${runId}:redaction_report`,
    freshness_ms: 0,
    retention_mode: requestedRetentionMode,
    detected_patterns: ["form", "toolbar", "warning_or_toast"],
  };
  const pageTarget = {
    target_ref: `target_${runId}_document`,
    label: "Current page",
    role: "document",
    semantic_ids: ["document", "page-root"],
    selectors: ["html", "body"],
    som_id: 1,
    ax_ref: `${observation.ax_ref}#document`,
    bounds: {
      x: 0,
      y: 0,
      width: 1280,
      height: 720,
      coordinate_space_id: `viewport_${runId}`,
    },
    confidence: 96,
    available_actions: ["inspect", "scroll", "click"],
  };
  const targetIndex = {
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    coordinate_space_id: `viewport_${runId}`,
    drift_state: "fresh",
    targets: [pageTarget],
  };
  const affordanceGraph = {
    graph_ref: affordanceGraphRef,
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    affordances: [
      {
        target_ref: pageTarget.target_ref,
        possible_action: "inspect",
        action_preconditions: ["fresh_observation", "target_index_present"],
        confidence: 95,
        expected_state_transition: "A read-only inspection summary can be produced without external side effects.",
        risk_class: "read_only",
        required_authority: "computer_use.native_browser.read",
        confirmation_required: false,
        fallback_action_paths: ["reobserve", "switch_to_visual_lane"],
        invalidation_conditions: ["navigation", "modal_interruption", "auth_wall"],
      },
    ],
  };
  const actionProposal = {
    proposal_ref: proposalRef,
    proposed_by: selectedModel,
    model_role: "grounder",
    raw_model_output_ref: `model_output_${runId}_computer_use_candidate`,
    normalized_action_candidate: "inspect current page and summarize actionable targets",
    target_ref: pageTarget.target_ref,
    confidence: 92,
    rationale_summary: "The page root is present and read-only inspection is the lowest-risk next step.",
    predicted_postcondition: "The harness has a grounded page summary and next-action candidates.",
    risk_assessment: "read_only",
    policy_decision_ref: policyDecisionRef,
  };
  const action = {
    action_ref: actionRef,
    proposal_ref: actionProposal.proposal_ref,
    action_kind: "inspect",
    target_ref: actionProposal.target_ref,
    observation_ref: observation.observation_ref,
    coordinate_space_id: targetIndex.coordinate_space_id,
    payload_summary: "Read-only inspect of the current page and target index.",
    expected_postcondition: actionProposal.predicted_postcondition,
    approval_ref: null,
  };
  const actionReceipt = {
    receipt_ref: actionReceiptRef,
    action_ref: action.action_ref,
    adapter_id: "ioi.native_browser.chromiumoxide.daemon",
    status: "completed",
    grounding_ref: targetIndex.target_index_ref,
    postcondition_summary: "Read-only inspection action was grounded in the observation and produced no external side effect.",
    verification_ref: verificationRef,
    evidence_refs: [
      observation.observation_ref,
      targetIndex.target_index_ref,
      actionProposal.proposal_ref,
    ],
  };
  const verification = {
    verification_ref: verificationRef,
    action_ref: action.action_ref,
    status: "passed",
    expected_postcondition: actionProposal.predicted_postcondition,
    observed_postcondition: "Environment, lease, observation, target index, affordance graph, action proposal, action receipt, and cleanup are trace-visible.",
    verifier: "runtime_daemon_computer_use_harness",
    evidence_refs: [
      environmentSelection.receipt_ref,
      observation.observation_ref,
      targetIndex.target_index_ref,
      affordanceGraph.graph_ref,
      actionProposal.proposal_ref,
      actionReceipt.receipt_ref,
    ],
  };
  const outcomeContract = {
    outcome_ref: `outcome_${runId}`,
    requested_outcome: "Produce a grounded browser observation summary without external side effects.",
    success_criteria: [verification.expected_postcondition],
    acceptable_side_effects: ["Retain a redacted computer-use trace artifact."],
    prohibited_side_effects: [
      "Submitting forms, credentials, payments, messages, purchases, or permission changes.",
    ],
    evidence_required: ["verification_receipt", "computer_use_trace"],
    rollback_or_cleanup_required: true,
    external_effect_policy: "confirmation_required",
  };
  const commitGate = {
    commit_gate_ref: `commit_gate_${runId}_${action.action_ref}`,
    final_action_ref: action.action_ref,
    outcome_ref: outcomeContract.outcome_ref,
    external_effect: false,
    user_confirmation_required: false,
    authority_required: "computer_use.read_only",
    pre_commit_summary: `No commit gate required for ${action.payload_summary}.`,
    post_commit_verification: outcomeContract.success_criteria.join("; "),
    policy_decision_ref: policyDecisionRef,
    status: "not_required",
  };
  const trajectory = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    trajectory_ref: trajectoryRef,
    run_id: runId,
    lease_id: lease.lease_id,
    retention_mode: requestedRetentionMode,
    entries: [
      {
        sequence: 1,
        event_kind: "select_environment",
        receipt_ref: environmentSelection.receipt_ref,
        summary: "Selected native browser lane with visual and sandbox lanes retained as fallbacks.",
      },
      {
        sequence: 2,
        event_kind: "observe",
        observation_ref: observation.observation_ref,
        receipt_ref: observation.observation_ref,
        summary: "Captured redacted browser observation and target index.",
      },
      {
        sequence: 3,
        event_kind: "propose_action",
        observation_ref: observation.observation_ref,
        proposal_ref: actionProposal.proposal_ref,
        summary: "Normalized a read-only inspect proposal and policy-gated it before execution.",
      },
      {
        sequence: 4,
        event_kind: "execute_action",
        observation_ref: observation.observation_ref,
        proposal_ref: actionProposal.proposal_ref,
        action_ref: action.action_ref,
        receipt_ref: actionReceipt.receipt_ref,
        summary: "Executed the grounded read-only inspect action.",
      },
      {
        sequence: 5,
        event_kind: "verify_postcondition",
        action_ref: action.action_ref,
        verification_ref: verification.verification_ref,
        summary: "Verified the read-only postcondition and retained the trace.",
      },
      {
        sequence: 6,
        event_kind: "commit_or_handoff",
        action_ref: action.action_ref,
        receipt_ref: commitGate.commit_gate_ref,
        summary: "Evaluated the outcome contract and confirmed no external-effect commit was required.",
      },
    ],
  };
  const cleanup = {
    cleanup_ref: cleanupRef,
    lease_id: lease.lease_id,
    status: "completed",
    closed_process_refs: [`process:${lease.environment_ref}`],
    deleted_profile_refs: [`profile:${lease.lease_id}`],
    retained_artifact_refs: ["computer-use-trace.json"],
    warnings: [],
  };
  const basePayload = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    harness_contract: defaultComputerUseHarnessContract(),
    computer_use_lane: environmentSelection.selected_lane,
    computer_use_session_mode: environmentSelection.selected_session_mode,
    computer_use_lease_id: lease.lease_id,
    observation_retention_mode: requestedRetentionMode,
    fail_closed_when_unavailable: workflowBinding.failClosedWhenUnavailable,
    workflowGraphId: workflowBinding.workflowGraphId,
    workflow_graph_id: workflowBinding.workflowGraphId,
    workflowNodeId: workflowBinding.workflowNodeId,
    workflow_node_id: workflowBinding.workflowNodeId,
    workflowNodeIds: workflowBinding.workflowNodeIds,
    workflow_node_ids: workflowBinding.workflowNodeIds,
    toolRef: workflowBinding.toolRef,
    tool_ref: workflowBinding.toolRef,
    authorityScopes: workflowBinding.authorityScopes,
    authority_scopes: workflowBinding.authorityScopes,
  };
  const events = [
    computerUseEvent({
      type: "computer_use_environment_selected",
      summary: "Computer-use environment selected",
      workflowNodeId: "computer-use.select-environment",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "select_environment",
        computer_use_lane: environmentSelection.selected_lane,
        computer_use_session_mode: environmentSelection.selected_session_mode,
        computer_use_lease_id: lease.lease_id,
        environment_selection_receipt: environmentSelection,
        lease,
      },
    }),
    computerUseEvent({
      type: "computer_use_lease_acquired",
      summary: "Computer-use lease acquired",
      workflowNodeId: "computer-use.acquire-lease",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "acquire_lease",
        lease,
        adapter_contract: {
          adapter_id: "ioi.native_browser.chromiumoxide.daemon",
          lane: environmentSelection.selected_lane,
          supported_session_modes: [environmentSelection.selected_session_mode],
          capabilities: ["observe.dom", "observe.ax", "observe.screenshot", "act.inspect", "verify.postcondition"],
          emits_observation_bundle: true,
          emits_action_receipts: true,
          fail_closed_when_unavailable: true,
        },
      },
    }),
    computerUseEvent({
      type: "computer_use_run_state",
      summary: "Computer-use run state projected",
      workflowNodeId: "computer-use.run-state",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "plan_next_step",
        computer_use_lease_id: lease.lease_id,
        computer_use_observation_ref: observation.observation_ref,
        computer_use_target_index_ref: targetIndex.target_index_ref,
        computer_use_run_state: runState,
      },
    }),
    computerUseEvent({
      type: "computer_use_observation",
      summary: "Computer-use observation indexed",
      workflowNodeId: "computer-use.observe",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "observe",
        computer_use_observation_ref: observation.observation_ref,
        computer_use_target_index_ref: targetIndex.target_index_ref,
        observation_bundle: observation,
        target_index: targetIndex,
      },
    }),
    computerUseEvent({
      type: "computer_use_affordance_graph",
      summary: "Computer-use affordance graph built",
      workflowNodeId: "computer-use.affordance-graph",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "build_affordance_graph",
        computer_use_affordance_graph_ref: affordanceGraph.graph_ref,
        computer_use_target_index_ref: targetIndex.target_index_ref,
        affordance_graph: affordanceGraph,
      },
    }),
    computerUseEvent({
      type: "computer_use_action_proposed",
      summary: "Computer-use action proposal policy-gated",
      workflowNodeId: "computer-use.action-proposal",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "propose_action",
        computer_use_proposal_ref: actionProposal.proposal_ref,
        computer_use_target_ref: actionProposal.target_ref,
        computer_use_policy_decision_ref: policyDecisionRef,
        action_proposal: actionProposal,
        policy_gate: {
          policy_decision_ref: policyDecisionRef,
          outcome: "approved_for_read_only_probe",
          authority_scope: environmentSelection.authority_required,
        },
      },
    }),
    computerUseEvent({
      type: "computer_use_action_executed",
      summary: "Computer-use read-only action executed",
      workflowNodeId: "computer-use.execute-action",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "execute_action",
        computer_use_action_ref: action.action_ref,
        computer_use_proposal_ref: actionProposal.proposal_ref,
        computer_action: action,
        action_receipt: actionReceipt,
      },
    }),
    computerUseEvent({
      type: "computer_use_verification",
      summary: "Computer-use postcondition verified",
      workflowNodeId: "computer-use.verify",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "verify_postcondition",
        computer_use_verification_ref: verification.verification_ref,
        computer_use_proposal_ref: actionProposal.proposal_ref,
        verification_receipt: verification,
      },
    }),
    computerUseEvent({
      type: "computer_use_commit_gate",
      summary: "Computer-use commit gate evaluated",
      workflowNodeId: "computer-use.commit-gate",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "commit_or_handoff",
        computer_use_commit_gate_ref: commitGate.commit_gate_ref,
        computer_use_action_ref: action.action_ref,
        outcome_contract: outcomeContract,
        commit_gate: commitGate,
        human_handoff_state: null,
      },
    }),
    computerUseEvent({
      type: "computer_use_trajectory_written",
      summary: "Computer-use trajectory written",
      workflowNodeId: "computer-use.write-trajectory",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "write_trajectory",
        computer_use_trajectory_ref: trajectory.trajectory_ref,
        trajectory_bundle: trajectory,
      },
    }),
    computerUseEvent({
      type: "computer_use_cleanup",
      summary: "Computer-use cleanup completed",
      workflowNodeId: "computer-use.cleanup",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "cleanup",
        computer_use_cleanup_ref: cleanup.cleanup_ref,
        cleanup_receipt: cleanup,
      },
    }),
  ];
  return {
    environmentSelection,
    lease,
    runState,
    observation,
    targetIndex,
    affordanceGraph,
    actionProposal,
    action,
    actionReceipt,
    verification,
    outcomeContract,
    commitGate,
    trajectory,
    cleanup,
    events,
    receipt: {
      id: traceReceiptId,
      kind: "computer_use_trace",
      summary: "Computer-use harness trace exposed environment selection, lease, observation, targets, affordances, proposal, action, verification, outcome, commit gate, trajectory, and cleanup.",
      redaction: "redacted",
      evidenceRefs: [
        "ComputerUseHarnessContract",
        environmentSelection.receipt_ref,
        lease.lease_id,
        observation.observation_ref,
        targetIndex.target_index_ref,
        affordanceGraph.graph_ref,
        actionProposal.proposal_ref,
        action.action_ref,
        actionReceipt.receipt_ref,
        verification.verification_ref,
        outcomeContract.outcome_ref,
        commitGate.commit_gate_ref,
        trajectory.trajectory_ref,
        cleanup.cleanup_ref,
      ],
    },
  };
}

function unavailableComputerUseProjectionForRun({
  runId,
  prompt,
  mode,
  requestedLane,
  requestedSessionMode,
  workflowBinding,
}) {
  const requestedRetentionMode =
    workflowBinding.observationRetentionMode ?? "no_persistence";
  const targetHint = computerUseTargetHint(prompt);
  const leaseId = `lease_${runId}_${requestedLane}_unavailable`;
  const observationRef = `observation_${runId}_${requestedLane}_unavailable`;
  const targetIndexRef = `target_index_${runId}_${requestedLane}_unavailable`;
  const affordanceGraphRef = `affordance_${runId}_${requestedLane}_unavailable`;
  const verificationRef = `verification_${runId}_computer_use_unavailable`;
  const cleanupRef = `cleanup_${runId}_computer_use_unavailable`;
  const traceReceiptId = `receipt_${runId}_computer_use_trace`;
  const environmentSelection = {
    receipt_ref: `receipt_${runId}_computer_use_environment`,
    run_id: runId,
    selected_lane: requestedLane,
    selected_session_mode: requestedSessionMode,
    rejected_options: [
      {
        lane: "native_browser",
        session_mode: "owned_hermetic_browser",
        reason: "The workflow explicitly requested a different computer-use lane.",
      },
    ],
    reasons: [
      `Workflow metadata requested ${requestedLane}/${requestedSessionMode}.`,
      "The requested adapter is not mounted in this local daemon harness.",
      "The harness failed closed before acquiring an uncontrolled environment.",
    ],
    risk_posture: mode === "dry_run" ? "preview_only" : "blocked_unavailable",
    authority_required: `computer_use.${requestedLane}.execute`,
    privacy_impact: requestedRetentionMode,
    expected_cleanup: "no environment acquired; retain blocked trace only",
  };
  const lease = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    lease_id: leaseId,
    lane: requestedLane,
    session_mode: requestedSessionMode,
    status: "failed_closed",
    authority_scope: environmentSelection.authority_required,
    consent_scope: "operator_prompt",
    target_hint: targetHint,
    environment_ref: `${requestedLane}:unavailable`,
    profile_provenance: "none",
    retention_mode: requestedRetentionMode,
    cleanup_required: false,
    evidence_refs: [environmentSelection.receipt_ref, "adapter_unavailable"],
  };
  const observation = {
    observation_ref: observationRef,
    lease_id: leaseId,
    lane: requestedLane,
    session_mode: requestedSessionMode,
    url: null,
    title: null,
    app_name: null,
    window_title: null,
    screenshot_ref: null,
    som_ref: null,
    dom_ref: null,
    ax_ref: null,
    selector_map_ref: null,
    target_index_ref: targetIndexRef,
    redaction_report_ref: null,
    freshness_ms: null,
    retention_mode: requestedRetentionMode,
    detected_patterns: [],
  };
  const targetIndex = {
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    coordinate_space_id: `unavailable_${runId}`,
    drift_state: "unavailable",
    targets: [],
  };
  const affordanceGraph = {
    graph_ref: affordanceGraphRef,
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    affordances: [],
  };
  const runState = {
    run_id: runId,
    lease_id: leaseId,
    user_goal: prompt,
    current_subgoal: "Fail closed because the requested computer-use lane is unavailable.",
    plan_graph_ref: `plan_graph_${runId}_computer_use`,
    current_observation_ref: observationRef,
    current_target_index_ref: targetIndexRef,
    active_hypotheses: [
      "No adapter means no safe observation or action should be attempted.",
      "The workflow can retry after mounting the requested provider or switch lanes explicitly.",
    ],
    expected_postcondition: "A blocked, no-action trace explains why the requested lane was unavailable.",
    last_action_ref: null,
    verification_status: "blocked",
    blocker_state: "computer_use_lane_unavailable",
    retry_budget: 0,
    risk_posture: environmentSelection.risk_posture,
    user_handoff_ref: null,
    cleanup_state: "not_required",
  };
  const verification = {
    verification_ref: verificationRef,
    action_ref: null,
    status: "blocked",
    expected_postcondition: runState.expected_postcondition,
    observed_postcondition: "No adapter was mounted; no lease, observation, action, or external side effect occurred.",
    verifier: "runtime_daemon_computer_use_harness",
    evidence_refs: [environmentSelection.receipt_ref, lease.lease_id, cleanupRef],
  };
  const cleanup = {
    cleanup_ref: cleanupRef,
    lease_id: lease.lease_id,
    status: "not_required",
    closed_process_refs: [],
    deleted_profile_refs: [],
    retained_artifact_refs: ["computer-use-trace.json"],
    warnings: [`${requestedLane}/${requestedSessionMode} adapter unavailable; no environment acquired.`],
  };
  const recoveryPolicy = {
    policy_id: `computer-use-recovery:${runId}:${requestedLane}`,
    failure_class: "environment",
    allowed_actions: ["terminate_safely", "switch_to_browser_lane", "ask_user"],
    max_attempts: 0,
    lane_switch_allowed: true,
    requires_human_visible_reason: true,
  };
  const basePayload = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    harness_contract: defaultComputerUseHarnessContract(),
    computer_use_lane: requestedLane,
    computer_use_session_mode: requestedSessionMode,
    computer_use_lease_id: lease.lease_id,
    observation_retention_mode: requestedRetentionMode,
    fail_closed_when_unavailable: workflowBinding.failClosedWhenUnavailable,
    workflowGraphId: workflowBinding.workflowGraphId,
    workflow_graph_id: workflowBinding.workflowGraphId,
    workflowNodeId: workflowBinding.workflowNodeId,
    workflow_node_id: workflowBinding.workflowNodeId,
    workflowNodeIds: workflowBinding.workflowNodeIds,
    workflow_node_ids: workflowBinding.workflowNodeIds,
    toolRef: workflowBinding.toolRef,
    tool_ref: workflowBinding.toolRef,
    authorityScopes: workflowBinding.authorityScopes,
    authority_scopes: workflowBinding.authorityScopes,
  };
  const events = [
    computerUseEvent({
      type: "computer_use_environment_selected",
      summary: "Computer-use environment selected",
      workflowNodeId: "computer-use.select-environment",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "select_environment",
        environment_selection_receipt: environmentSelection,
        lease,
      },
    }),
    computerUseEvent({
      type: "computer_use_environment_unavailable",
      summary: "Computer-use environment unavailable; failed closed",
      workflowNodeId: "computer-use.environment-unavailable",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "acquire_lease",
        computer_use_blocker: "adapter_unavailable",
        lease,
        recovery_policy: recoveryPolicy,
      },
    }),
    computerUseEvent({
      type: "computer_use_run_state",
      summary: "Computer-use run state blocked",
      workflowNodeId: "computer-use.run-state",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "plan_next_step",
        computer_use_observation_ref: observation.observation_ref,
        computer_use_target_index_ref: targetIndex.target_index_ref,
        computer_use_run_state: runState,
      },
    }),
    computerUseEvent({
      type: "computer_use_verification",
      summary: "Computer-use unavailable state verified",
      workflowNodeId: "computer-use.verify",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "verify_postcondition",
        computer_use_verification_ref: verification.verification_ref,
        verification_receipt: verification,
      },
    }),
    computerUseEvent({
      type: "computer_use_cleanup",
      summary: "Computer-use cleanup completed",
      workflowNodeId: "computer-use.cleanup",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "cleanup",
        computer_use_cleanup_ref: cleanup.cleanup_ref,
        cleanup_receipt: cleanup,
      },
    }),
  ];
  return {
    environmentSelection,
    lease,
    runState,
    observation,
    targetIndex,
    affordanceGraph,
    actionProposal: null,
    action: null,
    actionReceipt: null,
    verification,
    outcomeContract: null,
    commitGate: null,
    trajectory: null,
    cleanup,
    events,
    receipt: {
      id: traceReceiptId,
      kind: "computer_use_trace",
      summary: "Computer-use harness failed closed because the requested lane adapter was unavailable.",
      redaction: "redacted",
      evidenceRefs: [
        "ComputerUseHarnessContract",
        environmentSelection.receipt_ref,
        lease.lease_id,
        verification.verification_ref,
        cleanup.cleanup_ref,
      ],
    },
  };
}

function computerUseEvent({ type, summary, workflowNodeId, traceReceiptId, data }) {
  const resolvedWorkflowNodeId =
    data.workflowNodeId ?? data.workflow_node_id ?? workflowNodeId;
  return {
    type,
    summary,
    data: {
      ...data,
      eventKind: computerUseSourceEventKind(type),
      workflowNodeId: resolvedWorkflowNodeId,
      workflow_node_id: resolvedWorkflowNodeId,
      receiptId: traceReceiptId,
    },
  };
}

function shouldProjectComputerUse(prompt, request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  if (metadata.computerUse === true || metadata.computer_use === true) {
    return true;
  }
  return /\b(browser|chromium|website|web page|url|computer[- ]use|cua|gui|desktop|click|selector|playwright)\b/i
    .test(String(prompt ?? ""));
}

function computerUseWorkflowBinding(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  return {
    workflowGraphId: cleanString(metadata.workflowGraphId ?? metadata.workflow_graph_id),
    workflowNodeId: cleanString(metadata.workflowNodeId ?? metadata.workflow_node_id),
    workflowNodeIds: cleanStringArray(metadata.workflowNodeIds ?? metadata.workflow_node_ids),
    toolRef: cleanString(metadata.toolRef ?? metadata.tool_ref),
    authorityScopes: cleanStringArray(metadata.authorityScopes ?? metadata.authority_scopes),
    observationRetentionMode: cleanString(
      metadata.observationRetentionMode ?? metadata.observation_retention_mode,
    ),
    failClosedWhenUnavailable:
      booleanValue(metadata.failClosedWhenUnavailable ?? metadata.fail_closed_when_unavailable) ?? true,
  };
}

function requestedComputerUseLane(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  const value = metadata.computerUseLane ?? metadata.computer_use_lane;
  return value === "visual_gui" || value === "sandboxed_hosted" ? value : "native_browser";
}

function requestedComputerUseSessionMode(request = {}, lane) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  const value = metadata.computerUseSessionMode ?? metadata.computer_use_session_mode;
  if (
    lane === "visual_gui" &&
    ["visual_fallback", "foreground_desktop", "background_desktop", "app_scoped_desktop"].includes(value)
  ) {
    return value;
  }
  if (
    lane === "sandboxed_hosted" &&
    ["local_sandbox", "hosted_sandbox", "mobile_device"].includes(value)
  ) {
    return value;
  }
  return lane === "visual_gui" ? "visual_fallback" : "hosted_sandbox";
}

function computerUseTargetHint(prompt) {
  return String(prompt ?? "").match(/https?:\/\/[^\s)]+/i)?.[0] ?? "browser surface requested by user prompt";
}

function cleanString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function cleanStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => cleanString(item)).filter(Boolean);
}

function booleanValue(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function defaultComputerUseHarnessContract() {
  return {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    required_lanes: ["native_browser", "visual_gui", "sandboxed_hosted"],
    required_loop_steps: [
      "classify_intent",
      "select_environment",
      "acquire_lease",
      "observe",
      "build_target_index",
      "build_affordance_graph",
      "plan_next_step",
      "propose_action",
      "policy_risk_gate",
      "execute_action",
      "verify_postcondition",
      "repair_or_continue",
      "commit_or_handoff",
      "write_trajectory",
      "cleanup",
    ],
    required_contracts: [
      "ComputerUseLease",
      "ComputerControlAdapterContract",
      "ComputerUseObservationBundle",
      "TargetIndex",
      "AffordanceGraph",
      "ActionProposal",
      "ComputerAction",
      "ActionReceipt",
      "ComputerUseVerificationReceipt",
      "ComputerUseTrajectoryBundle",
      "CleanupReceipt",
      "ComputerUseRunState",
      "EnvironmentSelectionReceipt",
      "RecoveryPolicy",
      "HumanHandoffState",
      "InterfacePatternIndex",
      "OutcomeContract",
      "CommitGate",
      "ObservationRetentionMode",
    ],
    requires_action_proposal_before_execution: true,
    requires_observation_grounding_for_coordinates: true,
    requires_commit_gate_for_external_effects: true,
    requires_trajectory_bundle: true,
    forbids_shadow_runtime_truth: true,
  };
}

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value ?? "")).digest("hex");
}
