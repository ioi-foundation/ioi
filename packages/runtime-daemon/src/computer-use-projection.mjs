import crypto from "node:crypto";

import { computerUseContractsFromBrowserObservationArtifacts } from "./computer-use-browser-artifacts.mjs";
import { computerUseContractsFromSandboxFixture } from "./computer-use-sandbox-fixture.mjs";
import { computerUseContractsFromVisualObservation } from "./computer-use-visual-observation.mjs";

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
    case "computer_use_browser_discovery":
      return "ComputerUse.BrowserDiscovery";
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
  const controlledRelaunchBroker = controlledRelaunchBrokerForRequest(request);
  const controlledRelaunchLaunchReceipt = controlledRelaunchLaunchReceiptForRequest(request);
  const controlledRelaunchLaunchAttempted = Boolean(controlledRelaunchLaunchReceipt);
  const selectedLane = requestedLane;
  const selectedSessionMode = selectedLane === "native_browser"
    ? requestedComputerUseSessionMode(request, selectedLane)
    : requestedComputerUseSessionMode(request, selectedLane);
  const rawContractOverrides = computerUseContractOverrides(request);
  const referenceSuffix = selectedLane === "native_browser"
    ? "browser"
    : selectedLane === "visual_gui"
      ? "visual"
      : "sandbox";
  const leaseId = `lease_${runId}_${referenceSuffix}`;
  const observationRef =
    cleanString(rawContractOverrides.observationBundle?.observation_ref) ??
    `observation_${runId}_${referenceSuffix}_initial`;
  const targetIndexRef =
    cleanString(rawContractOverrides.targetIndex?.target_index_ref) ??
    cleanString(rawContractOverrides.observationBundle?.target_index_ref) ??
    `target_index_${runId}_${referenceSuffix}_initial`;
  const affordanceGraphRef =
    cleanString(rawContractOverrides.affordanceGraph?.graph_ref) ??
    `affordance_${runId}_${referenceSuffix}_initial`;
  const requestedActionKind = requestedComputerUseActionKind(request, prompt);
  const localVisualContracts = selectedLane === "visual_gui" && !rawContractOverrides.observationBundle
    ? computerUseContractsFromVisualObservation({
        request,
        runId,
        leaseId,
        observationRef,
        targetIndexRef,
        affordanceGraphRef,
        retentionMode: requestedRetentionMode,
        sessionMode: selectedSessionMode,
      })
    : null;
  const localSandboxContracts = selectedLane === "sandboxed_hosted" && !rawContractOverrides.observationBundle
    ? computerUseContractsFromSandboxFixture({
        request,
        runId,
        leaseId,
        observationRef,
        targetIndexRef,
        affordanceGraphRef,
        retentionMode: requestedRetentionMode,
        sessionMode: selectedSessionMode,
        actionKind: requestedActionKind,
      })
    : null;
  const contractOverrides = {
    ...rawContractOverrides,
    observationBundle:
      rawContractOverrides.observationBundle ??
      localVisualContracts?.observationBundle ??
      localSandboxContracts?.observationBundle ??
      null,
    targetIndex:
      rawContractOverrides.targetIndex ??
      localVisualContracts?.targetIndex ??
      localSandboxContracts?.targetIndex ??
      null,
    affordanceGraph:
      rawContractOverrides.affordanceGraph ??
      localVisualContracts?.affordanceGraph ??
      localSandboxContracts?.affordanceGraph ??
      null,
    adapterContract:
      rawContractOverrides.adapterContract ??
      localVisualContracts?.adapterContract ??
      localSandboxContracts?.adapterContract ??
      null,
    cleanupReceipt:
      rawContractOverrides.cleanupReceipt ??
      localVisualContracts?.cleanupReceipt ??
      localSandboxContracts?.cleanupReceipt ??
      null,
  };
  const hasBrowserObservationArtifacts =
    selectedLane === "native_browser" &&
    Boolean(contractOverrides.browserObservationArtifacts);
  const hasLocalVisualObservation = Boolean(localVisualContracts);
  const hasMountedContracts = Boolean(
    contractOverrides.observationBundle ||
    hasBrowserObservationArtifacts,
  );
  const controlledRelaunchUnavailable =
    selectedLane === "native_browser" &&
    selectedSessionMode === "controlled_relaunch" &&
    !controlledRelaunchBroker &&
    !controlledRelaunchLaunchAttempted &&
    !hasMountedContracts;
  if ((selectedLane !== "native_browser" || controlledRelaunchUnavailable) && !hasMountedContracts) {
    return unavailableComputerUseProjectionForRun({
      runId,
      prompt,
      mode,
      requestedLane: selectedLane,
      requestedSessionMode: selectedSessionMode,
      workflowBinding,
    });
  }
  if (
    selectedLane === "native_browser" &&
    selectedSessionMode === "controlled_relaunch" &&
    controlledRelaunchBroker &&
    !controlledRelaunchLaunchAttempted &&
    !hasMountedContracts
  ) {
    return controlledRelaunchProjectionForRun({
      agent,
      runId,
      prompt,
      mode,
      requestedRetentionMode,
      workflowBinding,
      controlledRelaunchBroker,
    });
  }
  const adapterContractOverride = contractOverrides.adapterContract;
  const cleanupOverride = contractOverrides.cleanupReceipt;
  const adapterId = cleanString(adapterContractOverride?.adapter_id) ??
    (hasMountedContracts
      ? `ioi.${selectedLane}.mounted_contract`
      : "ioi.native_browser.chromiumoxide.daemon");
  const targetHint = computerUseTargetHint(prompt);
  const effectiveTargetIndexRef =
    cleanString(contractOverrides.targetIndex?.target_index_ref) ??
    cleanString(contractOverrides.observationBundle?.target_index_ref) ??
    (hasBrowserObservationArtifacts ? `${observationRef}:target_index` : null) ??
    targetIndexRef;
  const effectiveAffordanceGraphRef =
    cleanString(contractOverrides.affordanceGraph?.graph_ref) ??
    (hasBrowserObservationArtifacts ? `${effectiveTargetIndexRef}:affordance_graph` : null) ??
    affordanceGraphRef;
  const browserArtifactContracts = hasBrowserObservationArtifacts
    ? computerUseContractsFromBrowserObservationArtifacts({
        artifacts: contractOverrides.browserObservationArtifacts,
        leaseId,
        observationRef,
        targetIndexRef: effectiveTargetIndexRef,
        affordanceGraphRef: effectiveAffordanceGraphRef,
        retentionMode: requestedRetentionMode,
        sessionMode: selectedSessionMode,
      })
    : null;
  const observationOverride =
    contractOverrides.observationBundle ?? browserArtifactContracts?.observationBundle ?? null;
  const targetIndexOverride =
    contractOverrides.targetIndex ?? browserArtifactContracts?.targetIndex ?? null;
  const affordanceGraphOverride =
    contractOverrides.affordanceGraph ?? browserArtifactContracts?.affordanceGraph ?? null;
  const contractIngest = contractOverrides.observationBundle
    ? hasLocalVisualObservation
      ? "local_visual_observation"
      : localSandboxContracts
        ? "local_sandbox_fixture"
      : "canonical_runtime_contract"
    : browserArtifactContracts
      ? "browser_observation_artifacts"
      : controlledRelaunchLaunchReceipt
        ? "controlled_relaunch_launch_receipt"
      : "synthetic_daemon_projection";
  const requestedActionIsReadOnly = computerUseActionKindIsReadOnly(requestedActionKind);
  const requestedActionApprovalRef = requestedComputerUseApprovalRef(request);
  const requestedActionHasApproval = !requestedActionIsReadOnly && requestedActionApprovalRef !== null;
  const requestedActionExecution = requestedComputerUseExecutionResult(request);
  const requestedActionExecutionAttempted = Boolean(requestedActionExecution);
  const requestedActionExecutionCompleted = requestedActionExecution?.status === "completed";
  const requestedActionExecutionBlocked =
    requestedActionExecutionAttempted && !requestedActionExecutionCompleted;
  const controlledRelaunchLaunchCompleted = controlledRelaunchLaunchReceipt?.status === "launched";
  const controlledRelaunchLaunchFailed =
    Boolean(controlledRelaunchLaunchReceipt) && !controlledRelaunchLaunchCompleted;
  const requestedActionWillExecute = requestedActionExecutionAttempted
    ? requestedActionExecutionCompleted
    : requestedActionIsReadOnly;
  const executionAdapterId = cleanString(requestedActionExecution?.adapter_id) ?? adapterId;
  const executionAfter = objectValue(requestedActionExecution?.after);
  const requestedActionAuthority = requestedActionIsReadOnly
    ? `computer_use.${selectedLane}.read`
    : `computer_use.${selectedLane}.act`;
  const requestedActionRisk = requestedActionIsReadOnly
    ? "read_only"
    : "possible_external_effect";
  const actionPolicySlug = requestedActionExecutionBlocked
    ? "executor_unavailable"
    : requestedActionIsReadOnly
      ? "read_only"
      : requestedActionExecutionCompleted
      ? "approved_external_effect"
      : requestedActionHasApproval
        ? "executor_unavailable"
      : "requires_confirmation";
  const proposalRef = `proposal_${runId}_browser_${requestedActionKind}`;
  const actionRef = `action_${runId}_browser_${requestedActionKind}`;
  const actionReceiptRef = `receipt_${runId}_computer_use_action`;
  const policyDecisionRef = requestedActionApprovalRef ?? `policy_${runId}_computer_use_${actionPolicySlug}`;
  const verificationRef = `verification_${runId}_computer_use_${requestedActionKind}`;
  const traceReceiptId = `receipt_${runId}_computer_use_trace`;
  const trajectoryRef = `trajectory_${runId}_computer_use`;
  const cleanupRef = `cleanup_${runId}_computer_use`;
  const rejectedOptions = selectedLane === "native_browser"
    ? [
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
      ]
    : [
        {
          lane: "native_browser",
          session_mode: "owned_hermetic_browser",
          reason: `Mounted ${selectedLane}/${selectedSessionMode} contracts were explicitly supplied by the runtime executor.`,
        },
      ];
  const environmentSelection = {
    receipt_ref: `receipt_${runId}_computer_use_environment`,
    run_id: runId,
    selected_lane: selectedLane,
    selected_session_mode: selectedSessionMode,
    rejected_options: rejectedOptions,
    reasons: [
      "Prompt indicates browser or computer-use automation.",
      controlledRelaunchLaunchCompleted
        ? "An explicit host-browser launch approval started a controlled browser with an isolated temporary profile and CDP endpoint."
        : controlledRelaunchLaunchFailed
          ? "Controlled relaunch launch authority was requested but failed closed before an attachable browser endpoint was acquired."
          : hasLocalVisualObservation
            ? "Local visual observation refs were supplied and compiled into IOI screenshot, SoM, accessibility, target, and affordance contracts."
            : hasMountedContracts
              ? `Mounted ${selectedLane}/${selectedSessionMode} contracts were supplied by the runtime executor.`
              : "Native browser lane gives the strongest semantic grounding for web tasks.",
      "Visual and sandbox lanes remain explicit fallback options under the same IOI contracts.",
    ],
    risk_posture: mode === "dry_run"
      ? "preview_only"
      : requestedActionIsReadOnly
        ? requestedActionExecutionBlocked
          ? "blocked_executor_unavailable"
          : "read_only_probe"
        : requestedActionExecutionCompleted
          ? "approved_external_effect"
          : requestedActionHasApproval
            ? "blocked_executor_unavailable"
          : "commit_confirmation_required",
    authority_required: requestedActionAuthority,
    privacy_impact: requestedRetentionMode,
    expected_cleanup: hasMountedContracts
      ? cleanupOverride
        ? "adapter_cleanup_receipt_supplied_and_redacted_trace_retained"
        : "release_mounted_executor_contract_and_retain_redacted_trace"
      : controlledRelaunchLaunchCompleted
        ? "terminate_controlled_browser_process_delete_temp_profile_and_retain_redacted_trace"
        : controlledRelaunchLaunchFailed
          ? "failed_launch_cleanup_receipt_supplied_and_redacted_trace_retained"
      : "close_owned_browser_context_and_retain_redacted_trace",
  };
  const lease = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    lease_id: leaseId,
    lane: selectedLane,
    session_mode: selectedSessionMode,
    status: controlledRelaunchLaunchFailed ? "failed_closed" : "active",
    authority_scope: environmentSelection.authority_required,
    consent_scope: controlledRelaunchLaunchReceipt
      ? "explicit_host_browser_launch_approval"
      : "operator_prompt",
    target_hint: targetHint,
    environment_ref: controlledRelaunchLaunchReceipt?.process_ref
      ? `${selectedLane}:${controlledRelaunchLaunchReceipt.process_ref}`
      : `${selectedLane}:${stableHash(agent.cwd).slice(0, 16)}`,
    profile_provenance: controlledRelaunchLaunchReceipt?.profile_provenance ??
      (hasMountedContracts ? "mounted_runtime_contract" : "temporary_ioi_browser_profile"),
    retention_mode: requestedRetentionMode,
    cleanup_required: !controlledRelaunchLaunchFailed,
    evidence_refs: compactValues([
      environmentSelection.receipt_ref,
      executionAdapterId,
      requestedActionExecution?.executor_ref,
      controlledRelaunchLaunchReceipt?.launch_ref,
      controlledRelaunchLaunchReceipt?.process_ref,
      controlledRelaunchLaunchReceipt?.profile_dir_ref,
    ]),
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
      controlledRelaunchLaunchCompleted
        ? "Controlled relaunch supplied an isolated temporary browser profile and CDP endpoint under explicit launch approval."
        : "Native browser semantics should resolve the task before visual fallback.",
      "No external side effect should occur before a policy-gated action proposal.",
    ],
    expected_postcondition: requestedActionIsReadOnly
      ? "A redacted observation, target index, affordance graph, and approved read-only action proposal exist."
      : requestedActionExecutionCompleted
        ? "A redacted observation, target index, affordance graph, approval-bound action, execution evidence, and verification receipt exist."
        : requestedActionHasApproval
          ? "A redacted observation, target index, affordance graph, and blocked execution receipt explain why no browser action ran."
        : "A redacted observation, target index, affordance graph, and confirmation-gated action proposal exist without execution.",
    last_action_ref: null,
    verification_status: requestedActionWillExecute
      ? "unknown"
      : requestedActionExecutionBlocked
        ? "blocked"
        : "requires_human",
    blocker_state: requestedActionWillExecute
      ? null
      : requestedActionExecutionBlocked
        ? "native_browser_executor_unavailable"
        : "commit_gate_requires_confirmation",
    retry_budget: 2,
    risk_posture: environmentSelection.risk_posture,
    user_handoff_ref: null,
    cleanup_state: "cleanup_required",
  };
  const observation = mergeObservationContract({
    observation_ref: observationRef,
    lease_id: leaseId,
    lane: selectedLane,
    session_mode: selectedSessionMode,
    url: cleanString(executionAfter?.url) ?? (targetHint.startsWith("http") ? targetHint : null),
    title: cleanString(executionAfter?.title) ?? "IOI computer-use daemon observation",
    app_name: "Chromium",
    window_title: "IOI browser-use harness",
    screenshot_ref: `artifact:${runId}:browser_screenshot_redacted`,
    som_ref: `artifact:${runId}:som_overlay`,
    dom_ref: cleanString(executionAfter?.html_ref) ?? `artifact:${runId}:dom_snapshot`,
    ax_ref: `artifact:${runId}:ax_tree`,
    selector_map_ref: `artifact:${runId}:selector_map`,
    target_index_ref: targetIndexRef,
    redaction_report_ref: `artifact:${runId}:redaction_report`,
    freshness_ms: 0,
    retention_mode: requestedRetentionMode,
    detected_patterns: ["form", "toolbar", "warning_or_toast"],
  }, observationOverride, leaseId, selectedLane, selectedSessionMode, requestedRetentionMode);
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
    available_actions: uniqueStrings(["inspect", "scroll", "click", requestedActionKind]),
  };
  const targetIndex = mergeTargetIndexContract({
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    coordinate_space_id: `viewport_${runId}`,
    drift_state: "fresh",
    targets: [pageTarget],
  }, targetIndexOverride, observation.observation_ref);
  const primaryTarget = targetIndex.targets[0] ?? pageTarget;
  const requestedTargetRef = requestedComputerUseTargetRef(request) ?? primaryTarget.target_ref;
  const normalizedActionCandidate = requestedActionKind === "inspect"
    ? selectedLane === "native_browser"
      ? "inspect current page and summarize actionable targets"
      : "inspect current visual surface and summarize actionable targets"
    : `${requestedActionKind} ${requestedTargetRef}`;
  const predictedPostcondition = requestedActionIsReadOnly
    ? "The harness has a grounded observation summary and next-action candidates."
    : requestedActionExecutionCompleted
      ? `The harness has a grounded ${requestedActionKind} action approved for execution, adapter evidence, and verified postcondition.`
      : requestedActionHasApproval
        ? `The harness has a grounded ${requestedActionKind} action and failed closed because the native browser executor was unavailable.`
      : `The harness has a grounded ${requestedActionKind} proposal and pauses before execution for confirmation.`;
  const affordanceGraph = mergeAffordanceGraphContract({
    graph_ref: affordanceGraphRef,
    target_index_ref: targetIndex.target_index_ref,
    observation_ref: observation.observation_ref,
    affordances: [
      {
        target_ref: requestedTargetRef,
        possible_action: requestedActionKind,
        action_preconditions: ["fresh_observation", "target_index_present"],
        confidence: requestedActionIsReadOnly ? 95 : requestedActionExecutionCompleted ? 90 : 88,
        expected_state_transition: requestedActionIsReadOnly
          ? "A read-only inspection summary can be produced without external side effects."
          : requestedActionExecutionCompleted
            ? `A ${requestedActionKind} action can proceed because approval ${requestedActionApprovalRef} is present.`
            : requestedActionHasApproval
              ? `A ${requestedActionKind} action was approved but blocked because the native browser executor was unavailable.`
            : `A ${requestedActionKind} action could change browser state and must be confirmed before execution.`,
        risk_class: requestedActionRisk,
        required_authority: requestedActionAuthority,
        confirmation_required: !requestedActionIsReadOnly,
        fallback_action_paths: ["reobserve", "switch_to_visual_lane"],
        invalidation_conditions: ["navigation", "modal_interruption", "auth_wall"],
      },
    ],
  }, affordanceGraphOverride, targetIndex.target_index_ref, observation.observation_ref);
  const actionProposal = {
    proposal_ref: proposalRef,
    proposed_by: selectedModel,
    model_role: "grounder",
    raw_model_output_ref: `model_output_${runId}_computer_use_candidate`,
    normalized_action_candidate: normalizedActionCandidate,
    target_ref: requestedTargetRef,
    confidence: requestedActionIsReadOnly ? 92 : requestedActionExecutionCompleted ? 89 : 86,
    rationale_summary: requestedActionIsReadOnly
      ? "The observed surface is present and read-only inspection is the lowest-risk next step."
      : requestedActionExecutionCompleted
        ? `The requested ${requestedActionKind} action is grounded to the current target index and approval ${requestedActionApprovalRef} is present.`
        : requestedActionHasApproval
          ? `The requested ${requestedActionKind} action is grounded and approved, but no native-browser executor completed it.`
        : `The requested ${requestedActionKind} action is grounded to the current target index and requires confirmation before execution.`,
    predicted_postcondition: predictedPostcondition,
    risk_assessment: requestedActionRisk,
    policy_decision_ref: policyDecisionRef,
  };
  const policyDecision = {
    policy_decision_ref: policyDecisionRef,
    proposal_ref: actionProposal.proposal_ref,
    action_kind: requestedActionKind,
    outcome: requestedActionExecutionBlocked
      ? "blocked_executor_unavailable"
      : requestedActionIsReadOnly
        ? "approved_for_read_only_probe"
        : requestedActionExecutionCompleted
          ? "approved_after_confirmation"
          : requestedActionHasApproval
            ? "blocked_executor_unavailable"
            : "requires_confirmation_before_execution",
    authority_scope: requestedActionAuthority,
    approval_ref: requestedActionApprovalRef,
    external_effect: !requestedActionIsReadOnly,
    fail_closed: requestedActionExecutionBlocked || (!requestedActionIsReadOnly && !requestedActionHasApproval),
    reasons: compactValues([
      requestedActionIsReadOnly
        ? "Read-only computer-use action can execute without external effects."
        : "Mutating computer-use action requires approval before execution.",
      requestedActionExecutionBlocked
        ? "Approved action could not execute because the adapter failed closed."
        : null,
      requestedActionExecutionCompleted
        ? "Approval and adapter execution evidence are present."
        : null,
    ]),
    evidence_refs: compactValues([
      observation.observation_ref,
      targetIndex.target_index_ref,
      actionProposal.proposal_ref,
      requestedActionApprovalRef,
      requestedActionExecution?.executor_ref,
      controlledRelaunchLaunchReceipt?.launch_ref,
    ]),
  };
  const action = requestedActionWillExecute
    ? {
        action_ref: actionRef,
        proposal_ref: actionProposal.proposal_ref,
        action_kind: requestedActionKind,
        target_ref: actionProposal.target_ref,
        observation_ref: observation.observation_ref,
        coordinate_space_id: targetIndex.coordinate_space_id,
        payload_summary: requestedActionKind === "inspect"
          ? "Read-only inspect of the current page and target index."
          : requestedActionExecutionCompleted
            ? `Approved ${requestedActionKind} ${requestedTargetRef} using ${requestedActionApprovalRef}.`
          : `${requestedActionKind} ${requestedTargetRef} without external side effects.`,
        expected_postcondition: actionProposal.predicted_postcondition,
        approval_ref: requestedActionApprovalRef,
      }
    : null;
  const actionReceipt = action
    ? {
        receipt_ref: actionReceiptRef,
        action_ref: action.action_ref,
        adapter_id: executionAdapterId,
        status: "completed",
        grounding_ref: targetIndex.target_index_ref,
        postcondition_summary: requestedActionIsReadOnly
          ? "Read-only computer-use action was grounded in the observation and produced no external side effect."
          : "Approved mutating browser action was grounded in the observation and executed by the native-browser CDP adapter after confirmation.",
        verification_ref: verificationRef,
        evidence_refs: compactValues([
          observation.observation_ref,
          targetIndex.target_index_ref,
          actionProposal.proposal_ref,
          ...(requestedActionExecution?.evidence_refs ?? []),
          requestedActionExecution?.executor_ref,
          controlledRelaunchLaunchReceipt?.launch_ref,
        ]),
        computer_use_execution_result: requestedActionExecution ?? null,
      }
    : null;
  const verification = {
    verification_ref: verificationRef,
    action_ref: action?.action_ref ?? null,
    status: requestedActionWillExecute
      ? "passed"
      : requestedActionExecutionBlocked
        ? "blocked"
        : "requires_human",
    expected_postcondition: actionProposal.predicted_postcondition,
    observed_postcondition: requestedActionExecutionBlocked
      ? `No browser action was executed because the executor failed closed: ${cleanString(requestedActionExecution?.error_summary) ?? "native browser executor unavailable"}.`
      : requestedActionIsReadOnly
        ? "Environment, lease, observation, target index, affordance graph, action proposal, action receipt, and cleanup are trace-visible."
        : requestedActionExecutionCompleted
        ? "Approval was present, the CDP adapter executed the grounded mutating browser action, and the post-action observation is trace-visible."
        : requestedActionHasApproval
          ? `Approval was present, but no mutating browser action was executed because the executor failed closed: ${cleanString(requestedActionExecution?.error_summary) ?? "native browser executor unavailable"}.`
      : "No mutating browser action was executed; the proposal is waiting on the commit gate confirmation.",
    verifier: "runtime_daemon_computer_use_harness",
    evidence_refs: compactValues([
      environmentSelection.receipt_ref,
      observation.observation_ref,
      targetIndex.target_index_ref,
      affordanceGraph.graph_ref,
      actionProposal.proposal_ref,
      actionReceipt?.receipt_ref,
      requestedActionExecution?.executor_ref,
      controlledRelaunchLaunchReceipt?.launch_ref,
    ]),
  };
  const outcomeContract = {
    outcome_ref: `outcome_${runId}`,
    requested_outcome: requestedActionExecutionBlocked
      ? `Block the grounded ${requestedActionKind} browser action because the native-browser executor was unavailable.`
      : requestedActionIsReadOnly
        ? "Produce a grounded computer-use observation summary without external side effects."
        : requestedActionExecutionCompleted
        ? `Execute the approved grounded ${requestedActionKind} browser action and verify the postcondition.`
        : requestedActionHasApproval
          ? `Block the approved grounded ${requestedActionKind} browser action because the native-browser executor was unavailable.`
        : `Prepare a grounded ${requestedActionKind} browser action and pause before external effects.`,
    success_criteria: [verification.expected_postcondition],
    acceptable_side_effects: ["Retain a redacted computer-use trace artifact."],
    prohibited_side_effects: [
      "Submitting forms, credentials, payments, messages, purchases, or permission changes.",
    ],
    evidence_required: ["verification_receipt", "computer_use_trace"],
    rollback_or_cleanup_required: true,
    external_effect_policy: "confirmation_required",
  };
  const commitGate = action
    ? {
        commit_gate_ref: `commit_gate_${runId}_${action.action_ref}`,
        final_action_ref: action.action_ref,
        outcome_ref: outcomeContract.outcome_ref,
        external_effect: !requestedActionIsReadOnly,
        user_confirmation_required: false,
        authority_required: requestedActionAuthority,
        pre_commit_summary: requestedActionIsReadOnly
          ? `No commit gate required for ${action.payload_summary}.`
          : `Approval ${requestedActionApprovalRef} authorized ${action.payload_summary}.`,
        post_commit_verification: outcomeContract.success_criteria.join("; "),
        policy_decision_ref: policyDecisionRef,
        status: requestedActionExecutionCompleted ? "completed" : "not_required",
      }
    : requestedActionExecutionBlocked
      ? {
          commit_gate_ref: `commit_gate_${runId}_${actionProposal.proposal_ref}`,
          final_action_ref: null,
          outcome_ref: outcomeContract.outcome_ref,
          external_effect: !requestedActionIsReadOnly,
          user_confirmation_required: false,
          authority_required: requestedActionAuthority,
          pre_commit_summary: requestedActionHasApproval
            ? `Approved ${actionProposal.normalized_action_candidate} could not execute because the native-browser executor was unavailable.`
            : `Explicit ${actionProposal.normalized_action_candidate} execution could not proceed because the native-browser executor was unavailable.`,
          post_commit_verification: outcomeContract.success_criteria.join("; "),
          policy_decision_ref: policyDecisionRef,
          status: "blocked",
        }
      : {
        commit_gate_ref: `commit_gate_${runId}_${actionProposal.proposal_ref}`,
        final_action_ref: null,
        outcome_ref: outcomeContract.outcome_ref,
        external_effect: true,
        user_confirmation_required: true,
        authority_required: "computer_use.external_effect",
        pre_commit_summary: `Review before executing ${actionProposal.normalized_action_candidate}.`,
        post_commit_verification: outcomeContract.success_criteria.join("; "),
        policy_decision_ref: policyDecisionRef,
        status: "pending_confirmation",
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
        summary: `Selected ${selectedLane}/${selectedSessionMode} lane with other computer-use lanes retained as fallbacks.`,
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
        summary: requestedActionIsReadOnly
          ? "Normalized a read-only proposal and policy-gated it before execution."
          : requestedActionExecutionCompleted
            ? "Normalized an approved mutating action proposal and captured adapter execution evidence."
            : requestedActionHasApproval
              ? "Normalized an approved mutating action proposal and failed closed because the adapter was unavailable."
              : "Normalized a mutating action proposal and stopped at the confirmation gate.",
      },
      ...(action && actionReceipt ? [{
        sequence: 4,
        event_kind: "execute_action",
        observation_ref: observation.observation_ref,
        proposal_ref: actionProposal.proposal_ref,
        action_ref: action.action_ref,
        receipt_ref: actionReceipt.receipt_ref,
        summary: requestedActionIsReadOnly
          ? "Executed the grounded read-only browser action."
          : "Executed the grounded mutating browser action through the CDP adapter.",
      }] : []),
      {
        sequence: action ? 5 : 4,
        event_kind: "verify_postcondition",
        action_ref: action?.action_ref ?? null,
        verification_ref: verification.verification_ref,
        summary: requestedActionIsReadOnly
          ? "Verified the read-only postcondition and retained the trace."
          : requestedActionExecutionCompleted
            ? "Verified the approved mutating action against CDP adapter evidence."
            : requestedActionHasApproval
              ? "Verified the approved mutating action failed closed before execution."
              : "Verified that no mutating action executed before confirmation.",
      },
      {
        sequence: action ? 6 : 5,
        event_kind: "commit_or_handoff",
        action_ref: action?.action_ref ?? null,
        receipt_ref: commitGate.commit_gate_ref,
        summary: requestedActionIsReadOnly
          ? "Evaluated the outcome contract and confirmed no external-effect commit was required."
          : requestedActionExecutionCompleted
            ? "Recorded the completed approval-bound commit gate."
            : requestedActionHasApproval
              ? "Recorded the blocked commit gate with executor-unavailable evidence."
              : "Paused at the commit gate until explicit approval is available.",
      },
    ],
  };
  const cleanup = mergeCleanupReceipt({
    cleanup_ref: cleanupRef,
    lease_id: lease.lease_id,
    status: "completed",
    closed_process_refs: hasMountedContracts ? [] : [`process:${lease.environment_ref}`],
    deleted_profile_refs: hasMountedContracts ? [] : [`profile:${lease.lease_id}`],
    retained_artifact_refs: ["computer-use-trace.json"],
    warnings: hasMountedContracts && !cleanupOverride
      ? ["mounted_executor_cleanup_receipt_not_supplied"]
      : controlledRelaunchLaunchCompleted && !cleanupOverride
        ? ["controlled_relaunch_cleanup_receipt_not_supplied"]
      : [],
  }, cleanupOverride, cleanupRef, lease.lease_id);
  const adapterContract = mergeAdapterContract({
    adapter_id: executionAdapterId,
    lane: environmentSelection.selected_lane,
    supported_session_modes: [environmentSelection.selected_session_mode],
    capabilities: [
      "observe.dom",
      "observe.ax",
      "observe.screenshot",
      `act.${requestedActionKind}`,
      "verify.postcondition",
      "cleanup",
      ...(controlledRelaunchLaunchReceipt ? ["broker.controlled_relaunch"] : []),
    ],
    emits_observation_bundle: true,
    emits_action_receipts: requestedActionWillExecute,
    emits_cleanup_receipts: true,
    fail_closed_when_unavailable: true,
  }, adapterContractOverride, selectedLane, selectedSessionMode);
  const basePayload = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    harness_contract: defaultComputerUseHarnessContract(),
    computer_use_lane: environmentSelection.selected_lane,
    computer_use_session_mode: environmentSelection.selected_session_mode,
    computer_use_lease_id: lease.lease_id,
    computer_use_contract_ingest: contractIngest,
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
    authorityScopes: uniqueStrings([requestedActionAuthority, ...workflowBinding.authorityScopes]),
    authority_scopes: uniqueStrings([requestedActionAuthority, ...workflowBinding.authorityScopes]),
    computer_use_action_kind: requestedActionKind,
    computer_use_external_effect: !requestedActionIsReadOnly,
    computer_use_approval_ref: requestedActionApprovalRef,
    computer_use_executor_ref: requestedActionExecution?.executor_ref ?? null,
    computer_use_executor_status: requestedActionExecution?.status ?? null,
    computer_use_executor_error_class: requestedActionExecution?.error_class ?? null,
    computer_use_controlled_relaunch_launch_ref:
      controlledRelaunchLaunchReceipt?.launch_ref ?? null,
    controlled_relaunch_launch_receipt: controlledRelaunchLaunchReceipt,
    controlled_relaunch_broker: controlledRelaunchBroker,
  };
  const actionExecutionEvents = action && actionReceipt
    ? [
        computerUseEvent({
          type: "computer_use_action_executed",
          summary: requestedActionIsReadOnly
            ? "Computer-use read-only action executed"
            : "Computer-use approved mutating action executed",
          workflowNodeId: "computer-use.execute-action",
          traceReceiptId,
          data: {
            ...basePayload,
            computer_use_step: "execute_action",
            computer_use_action_ref: action.action_ref,
            computer_use_proposal_ref: actionProposal.proposal_ref,
            computer_action: action,
            action_receipt: actionReceipt,
            computer_use_execution_result: requestedActionExecution,
            native_browser_execution_result: requestedActionExecution,
          },
        }),
      ]
    : [];
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
        adapter_contract: adapterContract,
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
          policy_decision_ref: policyDecision.policy_decision_ref,
          outcome: policyDecision.outcome,
          authority_scope: policyDecision.authority_scope,
          approval_ref: policyDecision.approval_ref,
          executor_ref: requestedActionExecution?.executor_ref ?? null,
          executor_status: requestedActionExecution?.status ?? null,
        },
        policy_decision_receipt: policyDecision,
      },
    }),
    ...actionExecutionEvents,
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
        computer_use_execution_result: requestedActionExecution,
        native_browser_execution_result: requestedActionExecution,
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
        computer_use_action_ref: action?.action_ref ?? null,
        outcome_contract: outcomeContract,
        commit_gate: commitGate,
        computer_use_execution_result: requestedActionExecution,
        native_browser_execution_result: requestedActionExecution,
        human_handoff_state: requestedActionWillExecute || requestedActionExecutionBlocked ? null : {
          handoff_ref: `handoff_${runId}_${requestedActionKind}`,
          reason: "mutating_browser_action_requires_confirmation",
          requested_user_action: `Approve or reject ${actionProposal.normalized_action_candidate}.`,
          forbidden_agent_actions: ["execute_mutating_browser_action_without_approval"],
          resume_condition: "A commit-gate approval receipt is present.",
          observation_after_resume_ref: null,
          timeout_policy: "pause_until_user_resumes_or_cancels",
          evidence_retention: requestedRetentionMode,
          status: "pending",
        },
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
    policyDecision,
    commitGate,
    trajectory,
    cleanup,
    adapterContract,
    controlledRelaunchLaunchReceipt,
    events,
    receipt: {
      id: traceReceiptId,
      kind: "computer_use_trace",
      summary: "Computer-use harness trace exposed environment selection, lease, observation, targets, affordances, proposal, action, verification, outcome, commit gate, trajectory, and cleanup.",
      redaction: "redacted",
      evidenceRefs: compactValues([
        "ComputerUseHarnessContract",
        environmentSelection.receipt_ref,
        lease.lease_id,
        observation.observation_ref,
        targetIndex.target_index_ref,
        affordanceGraph.graph_ref,
        actionProposal.proposal_ref,
        action?.action_ref,
        actionReceipt?.receipt_ref,
        verification.verification_ref,
        outcomeContract.outcome_ref,
        commitGate.commit_gate_ref,
        trajectory.trajectory_ref,
        cleanup.cleanup_ref,
        controlledRelaunchLaunchReceipt?.launch_ref,
      ]),
    },
  };
}

function controlledRelaunchProjectionForRun({
  agent,
  runId,
  prompt,
  mode,
  requestedRetentionMode,
  workflowBinding,
  controlledRelaunchBroker,
}) {
  const targetHint = computerUseTargetHint(prompt);
  const brokerRef = controlledRelaunchBroker.broker_ref;
  const leaseId = `lease_${runId}_controlled_relaunch`;
  const handoffRef = `handoff_${runId}_controlled_relaunch`;
  const verificationRef = `verification_${runId}_controlled_relaunch_handoff`;
  const cleanupRef = `cleanup_${runId}_controlled_relaunch`;
  const traceReceiptId = `receipt_${runId}_computer_use_trace`;
  const trajectoryRef = `trajectory_${runId}_controlled_relaunch`;
  const authorityScope = "computer_use.native_browser.controlled_relaunch";
  const environmentSelection = {
    receipt_ref: `receipt_${runId}_computer_use_environment`,
    run_id: runId,
    selected_lane: "native_browser",
    selected_session_mode: "controlled_relaunch",
    rejected_options: [
      {
        lane: "native_browser",
        session_mode: "owned_hermetic_browser",
        reason: "The workflow requested operator-visible controlled relaunch instead of an isolated fresh browser.",
      },
      {
        lane: "native_browser",
        session_mode: "attached_cdp",
        reason: "A CDP endpoint will be attached only after the brokered relaunch handoff completes.",
      },
    ],
    reasons: [
      "Prompt indicates browser or computer-use automation.",
      "Workflow supplied a controlled relaunch broker manifest.",
      "The daemon records the lease and handoff before any browser process or profile authority is used.",
    ],
    risk_posture: mode === "dry_run" ? "preview_only" : "controlled_relaunch_handoff_required",
    authority_required: authorityScope,
    privacy_impact: requestedRetentionMode,
    expected_cleanup: "cleanup pending until brokered relaunch handoff completes or is aborted",
  };
  const lease = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    lease_id: leaseId,
    lane: "native_browser",
    session_mode: "controlled_relaunch",
    status: "handoff_pending",
    authority_scope: authorityScope,
    consent_scope: "explicit_controlled_relaunch_broker",
    target_hint: targetHint,
    environment_ref: `native_browser:controlled_relaunch:${brokerRef}`,
    profile_provenance: controlledRelaunchBroker.profile_provenance,
    retention_mode: requestedRetentionMode,
    cleanup_required: true,
    evidence_refs: compactValues([
      environmentSelection.receipt_ref,
      brokerRef,
      handoffRef,
      controlledRelaunchBroker.launch_plan_ref,
    ]),
  };
  const humanHandoffState = {
    handoff_ref: handoffRef,
    reason: "controlled_relaunch_requires_operator_visible_browser_start",
    requested_user_action:
      "Review the relaunch plan, start the controlled browser, complete any auth wall manually, and resume with an attached CDP endpoint.",
    forbidden_agent_actions: [
      "copy_default_profile_without_consent",
      "harvest_credentials",
      "launch_unbrokered_browser_process",
      "execute_browser_actions_before_attach_verification",
    ],
    resume_condition: "A resumed run supplies a verified CDP endpoint or mounted observation bundle for this lease.",
    observation_after_resume_ref: null,
    timeout_policy: "pause_until_user_resumes_aborts_or_cleanup_runs",
    evidence_retention: requestedRetentionMode,
    status: "pending",
  };
  const runState = {
    run_id: runId,
    lease_id: leaseId,
    user_goal: prompt,
    current_subgoal: "Wait for the operator-visible controlled relaunch handoff to complete.",
    plan_graph_ref: `plan_graph_${runId}_controlled_relaunch`,
    current_observation_ref: null,
    current_target_index_ref: null,
    active_hypotheses: [
      "Controlled relaunch can preserve user-visible context without giving the agent uncontrolled profile authority.",
      "The next safe step is an operator handoff followed by an attached CDP observation.",
    ],
    expected_postcondition:
      "A controlled relaunch lease, handoff state, trajectory, and cleanup plan are recorded before browser action.",
    last_action_ref: null,
    verification_status: "requires_human",
    blocker_state: "controlled_relaunch_handoff_pending",
    retry_budget: 1,
    risk_posture: environmentSelection.risk_posture,
    user_handoff_ref: handoffRef,
    cleanup_state: "pending_handoff",
  };
  const verification = {
    verification_ref: verificationRef,
    action_ref: null,
    status: "requires_human",
    expected_postcondition: runState.expected_postcondition,
    observed_postcondition:
      "No browser observation or action has occurred; controlled relaunch is waiting on explicit operator handoff.",
    verifier: "runtime_daemon_computer_use_harness",
    evidence_refs: compactValues([environmentSelection.receipt_ref, lease.lease_id, handoffRef, brokerRef]),
  };
  const outcomeContract = {
    outcome_ref: `outcome_${runId}_controlled_relaunch`,
    requested_outcome: "Prepare controlled browser relaunch and pause before process/profile authority is used.",
    success_criteria: [
      "Controlled relaunch lease is recorded.",
      "Operator handoff forbids credential harvesting and unbrokered launch.",
      "Resume requires attached CDP or mounted observation evidence.",
    ],
    acceptable_side_effects: ["Retain a redacted controlled relaunch trace artifact."],
    prohibited_side_effects: [
      "Copying default browser profiles without consent.",
      "Starting untracked browser processes.",
      "Executing web actions before post-handoff observation.",
    ],
    evidence_required: ["environment_selection_receipt", "controlled_relaunch_handoff", "cleanup_receipt"],
    rollback_or_cleanup_required: true,
    external_effect_policy: "operator_handoff_required",
  };
  const commitGate = {
    commit_gate_ref: `commit_gate_${runId}_controlled_relaunch`,
    final_action_ref: null,
    outcome_ref: outcomeContract.outcome_ref,
    external_effect: true,
    user_confirmation_required: true,
    authority_required: authorityScope,
    pre_commit_summary: "Review and start the brokered controlled browser relaunch before IOI attaches.",
    post_commit_verification: "Resume must include attached CDP or mounted observation evidence.",
    policy_decision_ref: `policy_${runId}_controlled_relaunch_handoff`,
    status: "pending_confirmation",
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
        summary: "Selected controlled relaunch with an explicit broker manifest.",
      },
      {
        sequence: 2,
        event_kind: "acquire_lease",
        receipt_ref: lease.lease_id,
        summary: "Recorded a pending controlled relaunch lease before browser authority was used.",
      },
      {
        sequence: 3,
        event_kind: "commit_or_handoff",
        receipt_ref: handoffRef,
        summary: "Paused for operator-visible relaunch and auth handoff.",
      },
      {
        sequence: 4,
        event_kind: "verify_postcondition",
        verification_ref: verification.verification_ref,
        summary: "Verified that no browser action ran before handoff completion.",
      },
      {
        sequence: 5,
        event_kind: "cleanup",
        receipt_ref: cleanupRef,
        summary: "Recorded cleanup ownership for the pending relaunch lease.",
      },
    ],
  };
  const cleanup = {
    cleanup_ref: cleanupRef,
    lease_id: lease.lease_id,
    status: "pending_handoff",
    closed_process_refs: [],
    deleted_profile_refs: [],
    retained_artifact_refs: ["computer-use-trace.json"],
    warnings: ["controlled_relaunch_handoff_pending"],
  };
  const adapterContract = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    adapter_id: controlledRelaunchBroker.adapter_id,
    lane: "native_browser",
    supported_session_modes: ["controlled_relaunch", "attached_cdp"],
    capabilities: [
      "broker.controlled_relaunch",
      "handoff.operator_visible",
      "attach.cdp_after_relaunch",
      "verify.postcondition",
      "cleanup",
    ],
    emits_observation_bundle: false,
    emits_action_receipts: false,
    emits_cleanup_receipts: true,
    fail_closed_when_unavailable: true,
  };
  const basePayload = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    harness_contract: defaultComputerUseHarnessContract(),
    computer_use_lane: "native_browser",
    computer_use_session_mode: "controlled_relaunch",
    computer_use_lease_id: lease.lease_id,
    computer_use_contract_ingest: "controlled_relaunch_broker_manifest",
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
    authorityScopes: uniqueStrings([authorityScope, ...workflowBinding.authorityScopes]),
    authority_scopes: uniqueStrings([authorityScope, ...workflowBinding.authorityScopes]),
    controlled_relaunch_broker: controlledRelaunchBroker,
    controlled_relaunch_handoff_ref: handoffRef,
  };
  const events = [
    computerUseEvent({
      type: "computer_use_environment_selected",
      summary: "Computer-use controlled relaunch environment selected",
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
      type: "computer_use_lease_acquired",
      summary: "Computer-use controlled relaunch lease pending handoff",
      workflowNodeId: "computer-use.acquire-lease",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "acquire_lease",
        lease,
        adapter_contract: adapterContract,
      },
    }),
    computerUseEvent({
      type: "computer_use_run_state",
      summary: "Computer-use controlled relaunch run state projected",
      workflowNodeId: "computer-use.run-state",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "commit_or_handoff",
        computer_use_run_state: runState,
      },
    }),
    computerUseEvent({
      type: "computer_use_verification",
      summary: "Computer-use controlled relaunch handoff verified",
      workflowNodeId: "computer-use.verify",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "verify_postcondition",
        verification_receipt: verification,
      },
    }),
    computerUseEvent({
      type: "computer_use_commit_gate",
      summary: "Computer-use controlled relaunch handoff gate evaluated",
      workflowNodeId: "computer-use.commit-gate",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "commit_or_handoff",
        outcome_contract: outcomeContract,
        commit_gate: commitGate,
        human_handoff_state: humanHandoffState,
      },
    }),
    computerUseEvent({
      type: "computer_use_trajectory_written",
      summary: "Computer-use controlled relaunch trajectory written",
      workflowNodeId: "computer-use.write-trajectory",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "write_trajectory",
        trajectory_bundle: trajectory,
      },
    }),
    computerUseEvent({
      type: "computer_use_cleanup",
      summary: "Computer-use controlled relaunch cleanup pending handoff",
      workflowNodeId: "computer-use.cleanup",
      traceReceiptId,
      data: {
        ...basePayload,
        computer_use_step: "cleanup",
        cleanup_receipt: cleanup,
      },
    }),
  ];
  return {
    environmentSelection,
    lease,
    runState,
    observation: null,
    targetIndex: null,
    affordanceGraph: null,
    actionProposal: null,
    action: null,
    actionReceipt: null,
    verification,
    outcomeContract,
    policyDecision: null,
    commitGate,
    trajectory,
    cleanup,
    adapterContract,
    events,
    receipt: {
      id: traceReceiptId,
      kind: "computer_use_trace",
      summary: "Computer-use controlled relaunch trace recorded a brokered lease, handoff, trajectory, and cleanup plan.",
      redaction: "redacted",
      evidenceRefs: compactValues([
        "ComputerUseHarnessContract",
        environmentSelection.receipt_ref,
        lease.lease_id,
        handoffRef,
        verification.verification_ref,
        outcomeContract.outcome_ref,
        commitGate.commit_gate_ref,
        trajectory.trajectory_ref,
        cleanup.cleanup_ref,
      ]),
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
    rejected_options: unavailableRejectedOptions(requestedLane, requestedSessionMode),
    reasons: [
      `Workflow metadata requested ${requestedLane}/${requestedSessionMode}.`,
      requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch"
        ? "Controlled relaunch requires an explicit relaunch broker and user handoff before a browser environment can be acquired."
        : "The requested adapter is not mounted in this local daemon harness.",
      "The harness failed closed before acquiring an uncontrolled environment.",
    ],
    risk_posture: mode === "dry_run" ? "preview_only" : "blocked_unavailable",
    authority_required: requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch"
      ? "computer_use.native_browser.controlled_relaunch"
      : `computer_use.${requestedLane}.execute`,
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
    current_subgoal: requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch"
      ? "Fail closed because controlled relaunch is not yet brokered by the daemon."
      : "Fail closed because the requested computer-use lane is unavailable.",
    plan_graph_ref: `plan_graph_${runId}_computer_use`,
    current_observation_ref: observationRef,
    current_target_index_ref: targetIndexRef,
    active_hypotheses: [
      requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch"
        ? "No controlled relaunch broker means no safe profile or process handoff should be attempted."
        : "No adapter means no safe observation or action should be attempted.",
      "The workflow can retry after mounting the requested provider or switch lanes explicitly.",
    ],
    expected_postcondition: requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch"
      ? "A blocked, no-action trace explains why controlled relaunch requires a brokered user handoff."
      : "A blocked, no-action trace explains why the requested lane was unavailable.",
    last_action_ref: null,
    verification_status: "blocked",
    blocker_state: requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch"
      ? "controlled_relaunch_broker_unavailable"
      : "computer_use_lane_unavailable",
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
    warnings: [`${requestedLane}/${requestedSessionMode} unavailable; no environment acquired.`],
  };
  const recoveryPolicy = {
    policy_id: `computer-use-recovery:${runId}:${requestedLane}`,
    failure_class: "environment",
    allowed_actions: requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch"
      ? ["terminate_safely", "use_attached_cdp", "use_owned_browser", "ask_user"]
      : ["terminate_safely", "switch_to_browser_lane", "ask_user"],
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

function unavailableRejectedOptions(requestedLane, requestedSessionMode) {
  if (requestedLane === "native_browser" && requestedSessionMode === "controlled_relaunch") {
    return [
      {
        lane: "native_browser",
        session_mode: "owned_hermetic_browser",
        reason: "The workflow requested controlled relaunch instead of a fresh owned browser.",
      },
      {
        lane: "native_browser",
        session_mode: "attached_cdp",
        reason: "No explicit attached CDP endpoint was supplied for this controlled relaunch request.",
      },
    ];
  }
  return [
    {
      lane: "native_browser",
      session_mode: "owned_hermetic_browser",
      reason: "The workflow explicitly requested a different computer-use lane.",
    },
  ];
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
    observationRetentionMode: cleanString(metadata.observation_retention_mode),
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
    lane === "native_browser" &&
    ["owned_hermetic_browser", "attached_cdp", "controlled_relaunch", "discovery_only"].includes(value)
  ) {
    return value;
  }
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
  if (lane === "visual_gui") return "visual_fallback";
  if (lane === "sandboxed_hosted") return "hosted_sandbox";
  return "owned_hermetic_browser";
}

function controlledRelaunchBrokerForRequest(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  const explicit =
    objectValue(metadata.computer_use_controlled_relaunch_broker) ??
    objectValue(metadata.controlled_relaunch_broker);
  const brokerRef =
    cleanString(explicit?.broker_ref) ??
    cleanString(metadata.controlled_relaunch_broker_ref);
  if (!explicit && !brokerRef) return null;
  const startUrl =
    cleanString(explicit?.start_url) ??
    cleanString(metadata.controlled_relaunch_start_url) ??
    null;
  const profileDirRef =
    cleanString(explicit?.profile_dir_ref) ??
    cleanString(metadata.controlled_relaunch_profile_dir_ref) ??
    "profile:controlled_relaunch:temporary";
  const launchPlanRef =
    cleanString(explicit?.launch_plan_ref) ??
    cleanString(metadata.controlled_relaunch_launch_plan_ref) ??
    `${brokerRef ?? "controlled_relaunch_broker"}:launch_plan`;
  return {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    broker_ref: brokerRef ?? `broker_controlled_relaunch_${stableHash(JSON.stringify(metadata)).slice(0, 12)}`,
    adapter_id:
      cleanString(explicit?.adapter_id) ??
      "ioi.native_browser.controlled_relaunch_broker",
    launch_plan_ref: launchPlanRef,
    start_url: startUrl,
    profile_dir_ref: profileDirRef,
    profile_provenance:
      cleanString(explicit?.profile_provenance) ??
      "temporary_ioi_controlled_relaunch_profile",
    user_visible: booleanValue(explicit?.user_visible) ?? true,
    requires_operator_handoff:
      booleanValue(explicit?.requires_operator_handoff) ?? true,
    attach_after_relaunch: booleanValue(explicit?.attach_after_relaunch) ?? true,
    cleanup_required: booleanValue(explicit?.cleanup_required) ?? true,
    forbidden_authority: uniqueStrings([
      "copy_default_profile_without_consent",
      "harvest_credentials",
      "unbrokered_process_launch",
      ...cleanStringArray(explicit?.forbidden_authority),
    ]),
  };
}

function requestedComputerUseActionKind(request = {}, prompt = "") {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  const explicit = computerUseActionKindValue(metadata.computer_use_action_kind);
  if (explicit) return explicit;
  return computerUseActionKindFromText(prompt) ?? "inspect";
}

function requestedComputerUseTargetRef(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  return cleanString(metadata.computer_use_target_ref);
}

function requestedComputerUseApprovalRef(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  return cleanString(metadata.computer_use_approval_ref);
}

function requestedComputerUseExecutionResult(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  return objectValue(
    metadata.computerUseNativeBrowserExecution ??
      metadata.computer_use_native_browser_execution ??
      metadata.computerUseExecutionResult ??
      metadata.computer_use_execution_result,
  );
}

function controlledRelaunchLaunchReceiptForRequest(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  return objectValue(
    metadata.computer_use_controlled_relaunch_launch_receipt ??
      metadata.controlled_relaunch_launch_receipt,
  );
}

function computerUseActionKindValue(value) {
  const normalized = cleanString(value)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (!normalized) return null;
  if (normalized === "type" || normalized === "input_text") return "type_text";
  if (normalized === "keypress") return "key_press";
  if (normalized === "mouse_move") return "hover";
  return isComputerActionKind(normalized) ? normalized : null;
}

function computerUseActionKindFromText(text) {
  const normalized = String(text ?? "").trim().toLowerCase();
  if (/^click\b|\bclick\s+/.test(normalized)) return "click";
  if (/^type\b|\btype\s+|type_text|input\s+text/.test(normalized)) return "type_text";
  if (/^key\b|\bkey\s+|key_press|keypress|^press\b|\bpress\s+/.test(normalized)) return "key_press";
  if (/^scroll\b|\bscroll\s+/.test(normalized)) return "scroll";
  if (/^hover\b|\bhover\s+|mouse_move/.test(normalized)) return "hover";
  if (/^wait\b|\bwait\s+/.test(normalized)) return "wait";
  if (/^navigate\b|\bnavigate\s+|open\s+url/.test(normalized)) return "navigate";
  if (/^select\b|\bselect\s+/.test(normalized)) return "select";
  if (/^upload\b|\bupload\s+/.test(normalized)) return "upload";
  return null;
}

function isComputerActionKind(value) {
  return [
    "click",
    "type_text",
    "key_press",
    "scroll",
    "drag",
    "hover",
    "select",
    "upload",
    "clipboard",
    "wait",
    "shell",
    "mobile_gesture",
    "navigate",
    "inspect",
  ].includes(value);
}

function computerUseActionKindIsReadOnly(actionKind) {
  return ["inspect", "hover", "wait", "scroll"].includes(actionKind);
}

function computerUseTargetHint(prompt) {
  return String(prompt ?? "").match(/https?:\/\/[^\s)]+/i)?.[0] ?? "browser surface requested by user prompt";
}

function computerUseContractOverrides(request = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? {};
  return {
    observationBundle: objectValue(
      metadata.computerUseObservationBundle ??
      metadata.computer_use_observation_bundle,
    ),
    targetIndex: objectValue(
      metadata.computerUseTargetIndex ??
      metadata.computer_use_target_index,
    ),
    affordanceGraph: objectValue(
      metadata.computerUseAffordanceGraph ??
      metadata.computer_use_affordance_graph,
    ),
    adapterContract: objectValue(
      metadata.computerUseAdapterContract ??
      metadata.computer_use_adapter_contract,
    ),
    cleanupReceipt: objectValue(
      metadata.computerUseCleanupReceipt ??
      metadata.computer_use_cleanup_receipt,
    ),
    browserObservationArtifacts: objectValue(
      metadata.computerUseBrowserObservationArtifacts ??
      metadata.computer_use_browser_observation_artifacts ??
      metadata.browserObservationArtifacts ??
      metadata.browser_observation_artifacts,
    ),
  };
}

function mergeAdapterContract(base, override, lane, sessionMode) {
  if (!override) return base;
  return {
    ...base,
    ...override,
    adapter_id: cleanString(override.adapter_id) ?? base.adapter_id,
    lane: cleanString(override.lane) ?? lane,
    supported_session_modes: cleanStringArray(override.supported_session_modes).length > 0
      ? cleanStringArray(override.supported_session_modes)
      : [sessionMode],
    capabilities: cleanStringArray(override.capabilities).length > 0
      ? cleanStringArray(override.capabilities)
      : base.capabilities,
    emits_observation_bundle: booleanValue(override.emits_observation_bundle) ?? base.emits_observation_bundle,
    emits_action_receipts: booleanValue(override.emits_action_receipts) ?? base.emits_action_receipts,
    emits_cleanup_receipts: booleanValue(override.emits_cleanup_receipts) ?? base.emits_cleanup_receipts,
    fail_closed_when_unavailable: booleanValue(override.fail_closed_when_unavailable) ?? base.fail_closed_when_unavailable,
  };
}

function mergeCleanupReceipt(base, override, cleanupRef, leaseId) {
  if (!override) return base;
  return {
    ...base,
    ...override,
    cleanup_ref: cleanString(override.cleanup_ref) ?? cleanupRef,
    lease_id: cleanString(override.lease_id) ?? leaseId,
    status: cleanString(override.status) ?? base.status,
    closed_process_refs: cleanStringArray(override.closed_process_refs).length > 0
      ? cleanStringArray(override.closed_process_refs)
      : base.closed_process_refs,
    deleted_profile_refs: cleanStringArray(override.deleted_profile_refs).length > 0
      ? cleanStringArray(override.deleted_profile_refs)
      : base.deleted_profile_refs,
    retained_artifact_refs: cleanStringArray(override.retained_artifact_refs).length > 0
      ? cleanStringArray(override.retained_artifact_refs)
      : base.retained_artifact_refs,
    warnings: cleanStringArray(override.warnings),
  };
}

function mergeObservationContract(base, override, leaseId, lane, sessionMode, retentionMode) {
  if (!override) return base;
  return {
    ...base,
    ...override,
    observation_ref: cleanString(override.observation_ref) ?? base.observation_ref,
    lease_id: leaseId,
    lane,
    session_mode: sessionMode,
    target_index_ref: cleanString(override.target_index_ref) ?? base.target_index_ref,
    retention_mode: cleanString(override.retention_mode) ?? retentionMode,
    detected_patterns: cleanStringArray(override.detected_patterns).length > 0
      ? cleanStringArray(override.detected_patterns)
      : base.detected_patterns,
  };
}

function mergeTargetIndexContract(base, override, observationRef) {
  if (!override) return base;
  const targets = Array.isArray(override.targets) ? override.targets : base.targets;
  return {
    ...base,
    ...override,
    target_index_ref: cleanString(override.target_index_ref) ?? base.target_index_ref,
    observation_ref: observationRef,
    coordinate_space_id: cleanString(override.coordinate_space_id) ?? base.coordinate_space_id,
    drift_state: cleanString(override.drift_state) ?? base.drift_state,
    targets,
  };
}

function mergeAffordanceGraphContract(base, override, targetIndexRef, observationRef) {
  if (!override) return base;
  return {
    ...base,
    ...override,
    graph_ref: cleanString(override.graph_ref) ?? base.graph_ref,
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    affordances: Array.isArray(override.affordances) ? override.affordances : base.affordances,
  };
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function cleanString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function cleanStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => cleanString(item)).filter(Boolean);
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => cleanString(value)).filter(Boolean))];
}

function compactValues(values) {
  return values.filter(Boolean);
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
