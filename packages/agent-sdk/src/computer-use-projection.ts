import type { IOISDKMessage, RuntimeReceipt } from "./messages.js";
import type { SendOptions } from "./options.js";
import {
  computerUseContractsFromBrowserObservationArtifacts,
  type BrowserObservationArtifacts,
} from "./computer-use-browser-artifacts.js";
import { computerUseContractsFromSandboxFixture } from "./computer-use-sandbox-fixture.js";
import {
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  commitGateForComputerAction,
  defaultComputerUseHarnessContract,
  outcomeContractForGoal,
  type ActionProposal,
  type ActionReceipt,
  type AffordanceGraph,
  type CleanupReceipt,
  type CommitGate,
  type ComputerAction,
  type ComputerActionKind,
  type ComputerControlAdapterContract,
  type ComputerUseLane,
  type ComputerUseLease,
  type ComputerUseObservationBundle,
  type ComputerUsePolicyDecisionReceipt,
  type ComputerUseRunState,
  type ComputerUseSessionMode,
  type ComputerUseTrajectoryBundle,
  type ComputerUseVerificationReceipt,
  type EnvironmentSelectionReceipt,
  type ObservationRetentionMode,
  type OutcomeContract,
  type TargetIndex,
} from "./computer-use.js";

type RuntimeRunMode = "send" | "plan" | "dry_run" | "handoff" | "learn";

export interface MockComputerUseProjection {
  environmentSelection: EnvironmentSelectionReceipt;
  lease: ComputerUseLease;
  runState: ComputerUseRunState;
  observation: ComputerUseObservationBundle;
  targetIndex: TargetIndex;
  affordanceGraph: AffordanceGraph;
  actionProposal: ActionProposal | null;
  policyDecision: ComputerUsePolicyDecisionReceipt | null;
  action: ComputerAction | null;
  actionReceipt: ActionReceipt | null;
  verification: ComputerUseVerificationReceipt;
  outcomeContract: OutcomeContract | null;
  commitGate: CommitGate | null;
  trajectory: ComputerUseTrajectoryBundle | null;
  cleanup: CleanupReceipt;
  receipt: RuntimeReceipt;
  events: Array<{
    type: IOISDKMessage["type"];
    summary: string;
    data: Record<string, unknown>;
  }>;
}

export function mockComputerUseProjectionForRun({
  cwd,
  runId,
  prompt,
  mode,
  options,
  selectedModel,
}: {
  cwd: string;
  runId: string;
  prompt: string;
  mode: RuntimeRunMode;
  options: SendOptions;
  selectedModel: string;
}): MockComputerUseProjection | null {
  if (!shouldProjectComputerUse(prompt, options)) {
    return null;
  }
  const workflowBinding = computerUseWorkflowBinding(options.metadata);
  const requestedLane = requestedComputerUseLane(options.metadata);
  const requestedRetentionMode =
    workflowBinding.observationRetentionMode ?? "local_redacted_artifacts";
  const requestedSessionMode = requestedComputerUseSessionMode(options.metadata, requestedLane);
  const requestedActionKind = requestedComputerUseActionKind(options.metadata, prompt);
  const referenceSuffix = computerUseReferenceSuffix(requestedLane);
  const leaseId = `lease_${runId}_${referenceSuffix}`;
  const rawContractOverrides = computerUseContractOverrides(options.metadata);
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
  const localSandboxContracts = requestedLane === "sandboxed_hosted" && !rawContractOverrides.observationBundle
    ? computerUseContractsFromSandboxFixture({
        metadata: options.metadata,
        runId,
        leaseId,
        observationRef,
        targetIndexRef,
        affordanceGraphRef,
        retentionMode: requestedRetentionMode,
        sessionMode: requestedSessionMode,
        actionKind: requestedActionKind,
      })
    : null;
  const contractOverrides: ComputerUseContractOverrides = {
    ...rawContractOverrides,
    observationBundle:
      rawContractOverrides.observationBundle ?? localSandboxContracts?.observationBundle ?? null,
    targetIndex: rawContractOverrides.targetIndex ?? localSandboxContracts?.targetIndex ?? null,
    affordanceGraph:
      rawContractOverrides.affordanceGraph ?? localSandboxContracts?.affordanceGraph ?? null,
    adapterContract:
      rawContractOverrides.adapterContract ?? localSandboxContracts?.adapterContract ?? null,
    cleanupReceipt:
      rawContractOverrides.cleanupReceipt ?? localSandboxContracts?.cleanupReceipt ?? null,
  };
  if (requestedLane !== "native_browser" && !localSandboxContracts) {
    return mockUnavailableComputerUseProjectionForRun({
      runId,
      prompt,
      mode,
      requestedLane,
      requestedSessionMode,
      workflowBinding,
    });
  }
  const selectedLane = requestedLane;
  const selectedSessionMode = requestedSessionMode;
  const targetHint = computerUseTargetHint(prompt);
  const hasBrowserObservationArtifacts = Boolean(contractOverrides.browserObservationArtifacts);
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
      })
    : null;
  const observationOverride =
    contractOverrides.observationBundle ?? browserArtifactContracts?.observationBundle ?? null;
  const targetIndexOverride =
    contractOverrides.targetIndex ?? browserArtifactContracts?.targetIndex ?? null;
  const affordanceGraphOverride =
    contractOverrides.affordanceGraph ?? browserArtifactContracts?.affordanceGraph ?? null;
  const contractIngest = contractOverrides.observationBundle
    ? localSandboxContracts
      ? "local_sandbox_fixture"
      : "canonical_runtime_contract"
    : browserArtifactContracts
      ? "browser_observation_artifacts"
      : "synthetic_sdk_projection";
  const adapterContractOverride = contractOverrides.adapterContract;
  const cleanupOverride = contractOverrides.cleanupReceipt;
  const adapterId =
    cleanString(adapterContractOverride?.adapter_id) ??
    (localSandboxContracts
      ? "ioi.sandboxed_hosted.local_fixture"
      : "ioi.native_browser.chromiumoxide.mock");
  const requestedActionIsReadOnly = computerUseActionKindIsReadOnly(requestedActionKind);
  const requestedActionApprovalRef = requestedComputerUseApprovalRef(options.metadata);
  const requestedActionHasApproval = !requestedActionIsReadOnly && requestedActionApprovalRef !== null;
  const requestedActionWillExecute = requestedActionIsReadOnly || requestedActionHasApproval;
  const requestedActionAuthority = requestedActionIsReadOnly
    ? `computer_use.${selectedLane}.read`
    : `computer_use.${selectedLane}.act`;
  const requestedActionRisk = requestedActionIsReadOnly
    ? "read_only"
    : "possible_external_effect";
  const actionPolicySlug = requestedActionIsReadOnly
    ? "read_only"
    : requestedActionHasApproval
      ? "approved_external_effect"
      : "requires_confirmation";
  const proposalRef = `proposal_${runId}_${referenceSuffix}_${requestedActionKind}`;
  const actionRef = `action_${runId}_${referenceSuffix}_${requestedActionKind}`;
  const actionReceiptRef = `receipt_${runId}_computer_use_action`;
  const policyDecisionRef = requestedActionApprovalRef ?? `policy_${runId}_computer_use_${actionPolicySlug}`;
  const verificationRef = `verification_${runId}_computer_use_${requestedActionKind}`;
  const trajectoryRef = `trajectory_${runId}_computer_use`;
  const cleanupRef = `cleanup_${runId}_computer_use`;
  const environmentSelection: EnvironmentSelectionReceipt = {
    receipt_ref: `receipt_${runId}_computer_use_environment`,
    run_id: runId,
    selected_lane: selectedLane,
    selected_session_mode: selectedSessionMode,
    rejected_options: rejectedComputerUseOptionsForSdkProjection({
      selectedLane,
      selectedSessionMode,
      requestedActionIsReadOnly,
      localSandboxFixture: Boolean(localSandboxContracts),
    }),
    reasons: [
      "Prompt indicates browser or computer-use automation.",
      localSandboxContracts
        ? "Local deterministic sandbox fixture supplied provider-neutral observation, target, affordance, adapter, and cleanup contracts."
        : "Native browser lane gives the strongest semantic grounding for web tasks.",
      "Visual and sandbox lanes remain explicit fallback options under the same IOI contracts.",
    ],
    risk_posture: mode === "dry_run"
      ? "preview_only"
      : requestedActionIsReadOnly
        ? "read_only_probe"
        : requestedActionHasApproval
          ? "approved_external_effect"
          : "commit_confirmation_required",
    authority_required: requestedActionAuthority,
    privacy_impact: requestedRetentionMode,
    expected_cleanup: localSandboxContracts
      ? "cleanup_ephemeral_sandbox_fixture_and_retain_trace"
      : "close_owned_browser_context_and_retain_redacted_trace",
  };
  const lease: ComputerUseLease = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    lease_id: leaseId,
    lane: selectedLane,
    session_mode: selectedSessionMode,
    status: "active",
    authority_scope: environmentSelection.authority_required,
    consent_scope: "operator_prompt",
    target_hint: targetHint,
    environment_ref: localSandboxContracts
      ? `local_sandbox_fixture:${safeFileName(cwd)}`
      : `local_browser:${safeFileName(cwd)}`,
    profile_provenance: localSandboxContracts
      ? "ephemeral_local_sandbox_fixture"
      : "temporary_ioi_browser_profile",
    retention_mode: requestedRetentionMode,
    cleanup_required: true,
    evidence_refs: [
      environmentSelection.receipt_ref,
      localSandboxContracts ? "ioi.sandboxed_hosted.local_fixture" : "ioi.native_browser.chromiumoxide",
    ],
  };
  const runState: ComputerUseRunState = {
    run_id: runId,
    lease_id: leaseId,
    user_goal: prompt,
    current_subgoal: "Observe the requested surface, index targets, and propose a grounded next action.",
    plan_graph_ref: `plan_graph_${runId}_computer_use`,
    current_observation_ref: observationRef,
    current_target_index_ref: targetIndexRef,
    active_hypotheses: [
      localSandboxContracts
        ? "The local fixture sandbox should produce deterministic, replayable observation and cleanup evidence."
        : "Native browser semantics should resolve the task before visual fallback.",
      "No external side effect should occur before a policy-gated action proposal.",
    ],
    expected_postcondition: requestedActionIsReadOnly
      ? "A redacted observation, target index, affordance graph, and approved read-only action proposal exist."
      : requestedActionHasApproval
        ? "A redacted observation, target index, affordance graph, approval-bound action, and verification receipt exist."
        : "A redacted observation, target index, affordance graph, and confirmation-gated action proposal exist without execution.",
    last_action_ref: null,
    verification_status: requestedActionWillExecute ? "unknown" : "requires_human",
    blocker_state: requestedActionWillExecute ? null : "commit_gate_requires_confirmation",
    retry_budget: 2,
    risk_posture: environmentSelection.risk_posture,
    user_handoff_ref: null,
    cleanup_state: "cleanup_required",
  };
  const observation: ComputerUseObservationBundle = mergeObservationContract({
    observation_ref: observationRef,
    lease_id: leaseId,
    lane: selectedLane,
    session_mode: selectedSessionMode,
    url: targetHint.startsWith("http") ? targetHint : null,
    title: "IOI computer-use mock observation",
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
  }, observationOverride, leaseId, selectedLane, selectedSessionMode, requestedRetentionMode);
  const targetIndex: TargetIndex = mergeTargetIndexContract({
    target_index_ref: targetIndexRef,
    observation_ref: observation.observation_ref,
    coordinate_space_id: `viewport_${runId}`,
    drift_state: "fresh",
    targets: [
      {
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
        available_actions: uniqueComputerActionKinds(["inspect", "scroll", "click", requestedActionKind]),
      },
    ],
  }, targetIndexOverride, observation.observation_ref);
  const primaryTarget = targetIndex.targets[0];
  const requestedTargetRef =
    requestedComputerUseTargetRef(options.metadata) ?? primaryTarget.target_ref;
  const normalizedActionCandidate =
    requestedActionKind === "inspect"
      ? "inspect current surface and summarize actionable targets"
      : `${requestedActionKind} ${requestedTargetRef}`;
  const predictedPostcondition = requestedActionIsReadOnly
    ? "The harness has a grounded observation summary and next-action candidates."
    : requestedActionHasApproval
      ? `The harness has a grounded ${requestedActionKind} action approved for execution and verifies the postcondition.`
      : `The harness has a grounded ${requestedActionKind} proposal and pauses before execution for confirmation.`;
  const affordanceGraph: AffordanceGraph = mergeAffordanceGraphContract({
    graph_ref: affordanceGraphRef,
    target_index_ref: targetIndexRef,
    observation_ref: observation.observation_ref,
    affordances: [
      {
        target_ref: requestedTargetRef,
        possible_action: requestedActionKind,
        action_preconditions: ["fresh_observation", "target_index_present"],
        confidence: requestedActionIsReadOnly ? 95 : requestedActionHasApproval ? 90 : 88,
        expected_state_transition: requestedActionIsReadOnly
          ? "A read-only inspection summary can be produced without external side effects."
          : requestedActionHasApproval
            ? `A ${requestedActionKind} action can proceed because approval ${requestedActionApprovalRef} is present.`
            : `A ${requestedActionKind} action could change browser state and must be confirmed before execution.`,
        risk_class: requestedActionRisk,
        required_authority: requestedActionAuthority,
        confirmation_required: !requestedActionIsReadOnly,
        fallback_action_paths: ["reobserve", "switch_to_visual_lane"],
        invalidation_conditions: ["navigation", "modal_interruption", "auth_wall"],
      },
    ],
  }, affordanceGraphOverride, targetIndex.target_index_ref, observation.observation_ref);
  const actionProposal: ActionProposal = {
    proposal_ref: proposalRef,
    proposed_by: selectedModel,
    model_role: "grounder",
    raw_model_output_ref: `model_output_${runId}_computer_use_candidate`,
    normalized_action_candidate: normalizedActionCandidate,
    target_ref: requestedTargetRef,
    confidence: requestedActionIsReadOnly ? 92 : requestedActionHasApproval ? 89 : 86,
    rationale_summary: requestedActionIsReadOnly
      ? "The observed surface is present and read-only inspection is the lowest-risk next step."
      : requestedActionHasApproval
        ? `The requested ${requestedActionKind} action is grounded to the current target index and approval ${requestedActionApprovalRef} is present.`
        : `The requested ${requestedActionKind} action is grounded to the current target index and requires confirmation before execution.`,
    predicted_postcondition: predictedPostcondition,
    risk_assessment: requestedActionRisk,
    policy_decision_ref: policyDecisionRef,
  };
  const policyDecision: ComputerUsePolicyDecisionReceipt = {
    policy_decision_ref: policyDecisionRef,
    proposal_ref: actionProposal.proposal_ref,
    action_kind: requestedActionKind,
    outcome: requestedActionIsReadOnly
      ? "approved_for_read_only_probe"
      : requestedActionHasApproval
        ? "approved_after_confirmation"
        : "requires_confirmation_before_execution",
    authority_scope: requestedActionAuthority,
    approval_ref: requestedActionApprovalRef,
    external_effect: !requestedActionIsReadOnly,
    fail_closed: !requestedActionIsReadOnly && !requestedActionHasApproval,
    reasons: [
      requestedActionIsReadOnly
        ? "Read-only computer-use action can execute without external effects."
        : "Mutating computer-use action requires approval before execution.",
      ...(requestedActionHasApproval
        ? ["Approval evidence is present for the requested mutating action."]
        : []),
    ],
    evidence_refs: compactUnknowns([
      observation.observation_ref,
      targetIndex.target_index_ref,
      actionProposal.proposal_ref,
      requestedActionApprovalRef,
    ]),
  };
  const action: ComputerAction | null = requestedActionWillExecute
    ? {
        action_ref: actionRef,
        proposal_ref: actionProposal.proposal_ref,
        action_kind: requestedActionKind,
        target_ref: actionProposal.target_ref,
        observation_ref: observation.observation_ref,
        coordinate_space_id: targetIndex.coordinate_space_id,
        payload_summary: requestedActionKind === "inspect"
          ? "Read-only inspect of the current page and target index."
          : requestedActionHasApproval
            ? `Approved ${requestedActionKind} ${requestedTargetRef} using ${requestedActionApprovalRef}.`
          : `${requestedActionKind} ${requestedTargetRef} without external side effects.`,
        expected_postcondition: actionProposal.predicted_postcondition,
        approval_ref: requestedActionApprovalRef,
      }
    : null;
  const actionReceipt: ActionReceipt | null = action
    ? {
        receipt_ref: actionReceiptRef,
        action_ref: action.action_ref,
        adapter_id: adapterId,
        status: "completed",
        grounding_ref: targetIndex.target_index_ref,
        postcondition_summary: requestedActionIsReadOnly
          ? "Read-only computer-use action was grounded in the observation and produced no external side effect."
          : "Approved mutating browser action was grounded in the observation and executed after confirmation.",
        verification_ref: verificationRef,
        evidence_refs: [
          observation.observation_ref,
          targetIndex.target_index_ref,
          actionProposal.proposal_ref,
        ],
      }
    : null;
  const verification: ComputerUseVerificationReceipt = {
    verification_ref: verificationRef,
    action_ref: action?.action_ref ?? null,
    status: requestedActionWillExecute ? "passed" : "requires_human",
    expected_postcondition: actionProposal.predicted_postcondition,
    observed_postcondition: requestedActionIsReadOnly
      ? "Environment, lease, observation, target index, affordance graph, action proposal, action receipt, and cleanup are trace-visible."
      : requestedActionHasApproval
        ? "Approval was present, so the grounded mutating browser action executed and produced a verification receipt."
      : "No mutating browser action was executed; the proposal is waiting on the commit gate confirmation.",
    verifier: "sdk_mock_computer_use_harness",
    evidence_refs: compactUnknowns([
      environmentSelection.receipt_ref,
      observation.observation_ref,
      targetIndex.target_index_ref,
      affordanceGraph.graph_ref,
      actionProposal.proposal_ref,
      actionReceipt?.receipt_ref,
    ]),
  };
  const outcomeContract = outcomeContractForGoal({
    run_id: runId,
    requested_outcome: requestedActionIsReadOnly
      ? "Produce a grounded computer-use observation summary without external side effects."
      : requestedActionHasApproval
        ? `Execute the approved grounded ${requestedActionKind} browser action and verify the postcondition.`
        : `Prepare a grounded ${requestedActionKind} browser action and pause before external effects.`,
    success_criteria: [verification.expected_postcondition],
    acceptable_side_effects: ["Retain a redacted computer-use trace artifact."],
    prohibited_side_effects: [
      "Submitting forms, credentials, payments, messages, purchases, or permission changes.",
    ],
    evidence_required: ["verification_receipt", "computer_use_trace"],
    rollback_or_cleanup_required: true,
    external_effect_policy: "confirmation_required",
  });
  const commitGate: CommitGate = action
    ? commitGateForComputerAction({
        run_id: runId,
        action,
        outcome_contract: outcomeContract,
        proposal: actionProposal,
        status: requestedActionHasApproval ? "completed" : undefined,
      })
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
  const trajectory: ComputerUseTrajectoryBundle = {
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
        summary: "Selected native_browser lane with visual and sandbox lanes retained as fallbacks.",
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
          : "Normalized a mutating action proposal and stopped at the confirmation gate.",
      },
      ...(action && actionReceipt ? [{
        sequence: 4,
        event_kind: "execute_action",
        observation_ref: observation.observation_ref,
        proposal_ref: actionProposal.proposal_ref,
        action_ref: action.action_ref,
        receipt_ref: actionReceipt.receipt_ref,
        summary: "Executed the grounded read-only browser action.",
      }] : []),
      {
        sequence: action ? 5 : 4,
        event_kind: "verify_postcondition",
        action_ref: action?.action_ref ?? null,
        verification_ref: verification.verification_ref,
        summary: requestedActionIsReadOnly
          ? "Verified the read-only postcondition and retained the trace."
          : "Verified that no mutating action executed before confirmation.",
      },
      {
        sequence: action ? 6 : 5,
        event_kind: "commit_or_handoff",
        action_ref: action?.action_ref ?? null,
        receipt_ref: commitGate.commit_gate_ref,
        summary: requestedActionIsReadOnly
          ? "Evaluated the outcome contract and confirmed no external-effect commit was required."
          : "Paused at the commit gate until explicit approval is available.",
      },
    ],
  };
  const cleanup: CleanupReceipt = {
    cleanup_ref: cleanupRef,
    lease_id: lease.lease_id,
    status: "completed",
    closed_process_refs: localSandboxContracts ? [`sandbox_fixture:${runId}`] : [`process:${lease.environment_ref}`],
    deleted_profile_refs: localSandboxContracts
      ? [`sandbox_fixture_workspace:${runId}`]
      : [`profile:${lease.lease_id}`],
    retained_artifact_refs: ["computer-use-trace.json"],
    warnings: [],
    ...(cleanupOverride ?? {}),
  } as CleanupReceipt;
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
  };
  const actionExecutionEvents: MockComputerUseProjection["events"] = action && actionReceipt
    ? [
        computerUseProjectionEvent(
          "computer_use_action_executed",
          requestedActionIsReadOnly
            ? "Computer-use read-only action executed"
            : "Computer-use approved mutating action executed",
          {
          ...basePayload,
          computer_use_step: "execute_action",
          computer_use_action_ref: action.action_ref,
          computer_use_proposal_ref: actionProposal.proposal_ref,
          computer_action: action,
          action_receipt: actionReceipt,
          },
        ),
      ]
    : [];
  const events: MockComputerUseProjection["events"] = [
    computerUseProjectionEvent("computer_use_environment_selected", "Computer-use environment selected", {
      ...basePayload,
      computer_use_step: "select_environment",
      computer_use_lane: environmentSelection.selected_lane,
      computer_use_session_mode: environmentSelection.selected_session_mode,
      computer_use_lease_id: lease.lease_id,
      environment_selection_receipt: environmentSelection,
      lease,
    }),
    computerUseProjectionEvent("computer_use_lease_acquired", "Computer-use lease acquired", {
      ...basePayload,
      computer_use_step: "acquire_lease",
      lease,
      adapter_contract: {
        adapter_id: adapterId,
        lane: environmentSelection.selected_lane,
        supported_session_modes: [environmentSelection.selected_session_mode],
        capabilities:
          cleanStringArray(adapterContractOverride?.capabilities).length > 0
            ? cleanStringArray(adapterContractOverride?.capabilities)
            : localSandboxContracts
              ? [
                  "lease.local_fixture",
                  "observe.screenshot",
                  "observe.ax",
                  "observe.som",
                  `act.${requestedActionKind}`,
                  "verify.postcondition",
                  "cleanup.ephemeral_workspace",
                ]
              : ["observe.dom", "observe.ax", "observe.screenshot", `act.${requestedActionKind}`, "verify.postcondition"],
        emits_observation_bundle: true,
        emits_action_receipts: requestedActionIsReadOnly,
        emits_cleanup_receipts: true,
        fail_closed_when_unavailable: true,
        ...(adapterContractOverride ?? {}),
      },
    }),
    computerUseProjectionEvent("computer_use_run_state", "Computer-use run state projected", {
      ...basePayload,
      computer_use_step: "plan_next_step",
      computer_use_lease_id: lease.lease_id,
      computer_use_observation_ref: observation.observation_ref,
      computer_use_target_index_ref: targetIndex.target_index_ref,
      computer_use_run_state: runState,
    }),
    computerUseProjectionEvent("computer_use_observation", "Computer-use observation indexed", {
      ...basePayload,
      computer_use_step: "observe",
      computer_use_observation_ref: observation.observation_ref,
      computer_use_target_index_ref: targetIndex.target_index_ref,
      observation_bundle: observation,
      target_index: targetIndex,
    }),
    computerUseProjectionEvent("computer_use_affordance_graph", "Computer-use affordance graph built", {
      ...basePayload,
      computer_use_step: "build_affordance_graph",
      computer_use_affordance_graph_ref: affordanceGraph.graph_ref,
      computer_use_target_index_ref: targetIndex.target_index_ref,
      affordance_graph: affordanceGraph,
    }),
    computerUseProjectionEvent("computer_use_action_proposed", "Computer-use action proposal policy-gated", {
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
      },
      policy_decision_receipt: policyDecision,
    }),
    ...actionExecutionEvents,
    computerUseProjectionEvent("computer_use_verification", "Computer-use postcondition verified", {
      ...basePayload,
      computer_use_step: "verify_postcondition",
      computer_use_verification_ref: verification.verification_ref,
      computer_use_proposal_ref: actionProposal.proposal_ref,
      verification_receipt: verification,
    }),
    computerUseProjectionEvent("computer_use_commit_gate", "Computer-use commit gate evaluated", {
      ...basePayload,
      computer_use_step: "commit_or_handoff",
      computer_use_commit_gate_ref: commitGate.commit_gate_ref,
      computer_use_action_ref: action?.action_ref ?? null,
      outcome_contract: outcomeContract,
      commit_gate: commitGate,
      human_handoff_state: requestedActionWillExecute ? null : {
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
    }),
    computerUseProjectionEvent("computer_use_trajectory_written", "Computer-use trajectory written", {
      ...basePayload,
      computer_use_step: "write_trajectory",
      computer_use_trajectory_ref: trajectory.trajectory_ref,
      trajectory_bundle: trajectory,
    }),
    computerUseProjectionEvent("computer_use_cleanup", "Computer-use cleanup completed", {
      ...basePayload,
      computer_use_step: "cleanup",
      computer_use_cleanup_ref: cleanup.cleanup_ref,
      cleanup_receipt: cleanup,
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
    policyDecision,
    action,
    actionReceipt,
    verification,
    outcomeContract,
    commitGate,
    trajectory,
    cleanup,
    events,
    receipt: {
      id: `receipt_${runId}_computer_use_trace`,
      kind: "computer_use_trace",
      summary: "Computer-use harness trace exposed environment selection, lease, observation, targets, affordances, proposal, action, verification, outcome, commit gate, trajectory, and cleanup.",
      redaction: "redacted",
      evidenceRefs: compactUnknowns([
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
      ]),
    },
  };
}

function mockUnavailableComputerUseProjectionForRun({
  runId,
  prompt,
  mode,
  requestedLane,
  requestedSessionMode,
  workflowBinding,
}: {
  runId: string;
  prompt: string;
  mode: RuntimeRunMode;
  requestedLane: "visual_gui" | "sandboxed_hosted";
  requestedSessionMode: ComputerUseSessionMode;
  workflowBinding: ComputerUseWorkflowBinding;
}): MockComputerUseProjection {
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
  const environmentSelection: EnvironmentSelectionReceipt = {
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
      "The requested adapter is not mounted in this local SDK harness.",
      "The harness failed closed before acquiring an uncontrolled environment.",
    ],
    risk_posture: mode === "dry_run" ? "preview_only" : "blocked_unavailable",
    authority_required: `computer_use.${requestedLane}.execute`,
    privacy_impact: requestedRetentionMode,
    expected_cleanup: "no environment acquired; retain blocked trace only",
  };
  const lease: ComputerUseLease = {
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
  const observation: ComputerUseObservationBundle = {
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
  const targetIndex: TargetIndex = {
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    coordinate_space_id: `unavailable_${runId}`,
    drift_state: "unavailable",
    targets: [],
  };
  const affordanceGraph: AffordanceGraph = {
    graph_ref: affordanceGraphRef,
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    affordances: [],
  };
  const runState: ComputerUseRunState = {
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
  const verification: ComputerUseVerificationReceipt = {
    verification_ref: verificationRef,
    action_ref: null,
    status: "blocked",
    expected_postcondition: runState.expected_postcondition,
    observed_postcondition: "No adapter was mounted; no lease, observation, action, or external side effect occurred.",
    verifier: "sdk_mock_computer_use_harness",
    evidence_refs: [environmentSelection.receipt_ref, lease.lease_id, cleanupRef],
  };
  const cleanup: CleanupReceipt = {
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
  const events: MockComputerUseProjection["events"] = [
    computerUseProjectionEvent("computer_use_environment_selected", "Computer-use environment selected", {
      ...basePayload,
      computer_use_step: "select_environment",
      environment_selection_receipt: environmentSelection,
      lease,
    }),
    computerUseProjectionEvent("computer_use_environment_unavailable", "Computer-use environment unavailable; failed closed", {
      ...basePayload,
      computer_use_step: "acquire_lease",
      computer_use_blocker: "adapter_unavailable",
      lease,
      recovery_policy: recoveryPolicy,
    }),
    computerUseProjectionEvent("computer_use_run_state", "Computer-use run state blocked", {
      ...basePayload,
      computer_use_step: "plan_next_step",
      computer_use_observation_ref: observation.observation_ref,
      computer_use_target_index_ref: targetIndex.target_index_ref,
      computer_use_run_state: runState,
    }),
    computerUseProjectionEvent("computer_use_verification", "Computer-use unavailable state verified", {
      ...basePayload,
      computer_use_step: "verify_postcondition",
      computer_use_verification_ref: verification.verification_ref,
      verification_receipt: verification,
    }),
    computerUseProjectionEvent("computer_use_cleanup", "Computer-use cleanup completed", {
      ...basePayload,
      computer_use_step: "cleanup",
      computer_use_cleanup_ref: cleanup.cleanup_ref,
      cleanup_receipt: cleanup,
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
    policyDecision: null,
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

function computerUseProjectionEvent(
  type: IOISDKMessage["type"],
  summary: string,
  data: Record<string, unknown>,
): MockComputerUseProjection["events"][number] {
  return { type, summary, data };
}

interface ComputerUseWorkflowBinding {
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  workflowNodeIds: string[];
  toolRef: string | null;
  authorityScopes: string[];
  observationRetentionMode: ObservationRetentionMode | null;
  failClosedWhenUnavailable: boolean;
}

function computerUseWorkflowBinding(
  metadata: SendOptions["metadata"],
): ComputerUseWorkflowBinding {
  return {
    workflowGraphId: cleanString(
      metadata?.workflowGraphId ?? metadata?.workflow_graph_id,
    ),
    workflowNodeId: cleanString(
      metadata?.workflowNodeId ?? metadata?.workflow_node_id,
    ),
    workflowNodeIds: cleanStringArray(
      metadata?.workflowNodeIds ?? metadata?.workflow_node_ids,
    ),
    toolRef: cleanString(metadata?.toolRef ?? metadata?.tool_ref),
    authorityScopes: cleanStringArray(
      metadata?.authorityScopes ?? metadata?.authority_scopes,
    ),
    observationRetentionMode: observationRetentionModeValue(
      metadata?.observationRetentionMode ??
        metadata?.observation_retention_mode,
    ),
    failClosedWhenUnavailable:
      booleanValue(
        metadata?.failClosedWhenUnavailable ??
          metadata?.fail_closed_when_unavailable,
      ) ?? true,
  };
}

function shouldProjectComputerUse(prompt: string, options: SendOptions): boolean {
  if (options.metadata?.computerUse === true || options.metadata?.computer_use === true) {
    return true;
  }
  return /\b(browser|chromium|website|web page|url|computer[- ]use|cua|gui|desktop|click|selector|playwright)\b/i
    .test(prompt);
}

function requestedComputerUseLane(metadata: SendOptions["metadata"]): "native_browser" | "visual_gui" | "sandboxed_hosted" {
  const value = metadata?.computerUseLane ?? metadata?.computer_use_lane;
  return value === "visual_gui" || value === "sandboxed_hosted" ? value : "native_browser";
}

function computerUseReferenceSuffix(lane: ComputerUseLane): "browser" | "visual" | "sandbox" {
  if (lane === "visual_gui") return "visual";
  if (lane === "sandboxed_hosted") return "sandbox";
  return "browser";
}

function rejectedComputerUseOptionsForSdkProjection({
  selectedLane,
  selectedSessionMode,
  requestedActionIsReadOnly,
  localSandboxFixture,
}: {
  selectedLane: ComputerUseLane;
  selectedSessionMode: ComputerUseSessionMode;
  requestedActionIsReadOnly: boolean;
  localSandboxFixture: boolean;
}): EnvironmentSelectionReceipt["rejected_options"] {
  if (selectedLane === "native_browser") {
    return [
      {
        lane: "visual_gui",
        session_mode: "visual_fallback",
        reason: "DOM, AX, selector, screenshot, and CDP evidence are available before visual fallback.",
      },
      {
        lane: "sandboxed_hosted",
        session_mode: "local_sandbox",
        reason: requestedActionIsReadOnly
          ? "The mock SDK task is local and read-only; hosted isolation is retained for risky or reproducible runs."
          : "The SDK task is only proposing a mutating browser action; hosted isolation remains available before execution authority is granted.",
      },
    ];
  }
  return [
    {
      lane: "native_browser",
      session_mode: "owned_hermetic_browser",
      reason: localSandboxFixture
        ? "The workflow explicitly selected a provider-neutral sandbox fixture for deterministic local execution."
        : "The workflow explicitly requested a different computer-use lane.",
    },
    {
      lane: "visual_gui",
      session_mode: "visual_fallback",
      reason: `${selectedLane}/${selectedSessionMode} supplied canonical observation contracts without falling back to coordinate-only GUI control.`,
    },
  ];
}

function requestedComputerUseSessionMode(
  metadata: SendOptions["metadata"],
  lane: ComputerUseLane,
): ComputerUseSessionMode {
  const rawValue = metadata?.computerUseSessionMode ?? metadata?.computer_use_session_mode;
  const value = typeof rawValue === "string" ? rawValue : "";
  if (
    lane === "native_browser" &&
    (value === "owned_hermetic_browser" || value === "attached_browser" || value === "controlled_relaunch")
  ) {
    return value;
  }
  if (
    lane === "visual_gui" &&
    (value === "visual_fallback" ||
      value === "foreground_desktop" ||
      value === "background_desktop" ||
      value === "app_scoped_desktop")
  ) {
    return value;
  }
  if (
    lane === "sandboxed_hosted" &&
    (value === "local_sandbox" || value === "hosted_sandbox" || value === "mobile_device")
  ) {
    return value;
  }
  if (lane === "visual_gui") return "visual_fallback";
  if (lane === "sandboxed_hosted") return "hosted_sandbox";
  return "owned_hermetic_browser";
}

function requestedComputerUseActionKind(
  metadata: SendOptions["metadata"],
  prompt: string,
): ComputerActionKind {
  const rawValue =
    metadata?.computerUseActionKind ??
    metadata?.computer_use_action_kind ??
    metadata?.actionKind ??
    metadata?.action_kind;
  const explicit = computerUseActionKindValue(rawValue);
  if (explicit) return explicit;
  return computerUseActionKindFromText(prompt) ?? "inspect";
}

function requestedComputerUseTargetRef(metadata: SendOptions["metadata"]): string | null {
  return cleanString(
    metadata?.computerUseTargetRef ??
      metadata?.computer_use_target_ref ??
      metadata?.targetRef ??
      metadata?.target_ref,
  );
}

function requestedComputerUseApprovalRef(metadata: SendOptions["metadata"]): string | null {
  return cleanString(
    metadata?.computerUseApprovalRef ??
      metadata?.computer_use_approval_ref ??
      metadata?.approvalRef ??
      metadata?.approval_ref,
  );
}

function computerUseActionKindValue(value: unknown): ComputerActionKind | null {
  const normalized = cleanString(value)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (!normalized) return null;
  if (normalized === "type" || normalized === "input_text") return "type_text";
  if (normalized === "keypress") return "key_press";
  if (normalized === "mouse_move") return "hover";
  return isComputerActionKind(normalized) ? normalized : null;
}

function computerUseActionKindFromText(text: string): ComputerActionKind | null {
  const normalized = text.trim().toLowerCase();
  if (/^click\b|\bclick\s+/.test(normalized)) return "click";
  if (/^type\b|\btype\s+|type_text|input\s+text/.test(normalized)) return "type_text";
  if (/^scroll\b|\bscroll\s+/.test(normalized)) return "scroll";
  if (/^hover\b|\bhover\s+|mouse_move/.test(normalized)) return "hover";
  if (/^wait\b|\bwait\s+/.test(normalized)) return "wait";
  if (/^navigate\b|\bnavigate\s+|open\s+url/.test(normalized)) return "navigate";
  if (/^select\b|\bselect\s+/.test(normalized)) return "select";
  if (/^upload\b|\bupload\s+/.test(normalized)) return "upload";
  return null;
}

function isComputerActionKind(value: string): value is ComputerActionKind {
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

function computerUseActionKindIsReadOnly(actionKind: ComputerActionKind): boolean {
  return ["inspect", "hover", "wait", "scroll"].includes(actionKind);
}

function computerUseTargetHint(prompt: string): string {
  const url = String(prompt).match(/https?:\/\/[^\s)]+/i)?.[0];
  return url ?? "browser surface requested by user prompt";
}

interface ComputerUseContractOverrides {
  observationBundle: Partial<ComputerUseObservationBundle> | null;
  targetIndex: Partial<TargetIndex> | null;
  affordanceGraph: Partial<AffordanceGraph> | null;
  adapterContract: (Partial<ComputerControlAdapterContract> & Record<string, unknown>) | null;
  cleanupReceipt: Partial<CleanupReceipt> | null;
  browserObservationArtifacts: BrowserObservationArtifacts | null;
}

function computerUseContractOverrides(
  metadata: SendOptions["metadata"],
): ComputerUseContractOverrides {
  return {
    observationBundle: objectValue(
      metadata?.computerUseObservationBundle ??
        metadata?.computer_use_observation_bundle,
    ) as Partial<ComputerUseObservationBundle> | null,
    targetIndex: objectValue(
      metadata?.computerUseTargetIndex ??
        metadata?.computer_use_target_index,
    ) as Partial<TargetIndex> | null,
    affordanceGraph: objectValue(
      metadata?.computerUseAffordanceGraph ??
        metadata?.computer_use_affordance_graph,
    ) as Partial<AffordanceGraph> | null,
    adapterContract: objectValue(
      metadata?.computerUseAdapterContract ??
        metadata?.computer_use_adapter_contract,
    ) as (Partial<ComputerControlAdapterContract> & Record<string, unknown>) | null,
    cleanupReceipt: objectValue(
      metadata?.computerUseCleanupReceipt ??
        metadata?.computer_use_cleanup_receipt,
    ) as Partial<CleanupReceipt> | null,
    browserObservationArtifacts: objectValue(
      metadata?.computerUseBrowserObservationArtifacts ??
        metadata?.computer_use_browser_observation_artifacts ??
        metadata?.browserObservationArtifacts ??
        metadata?.browser_observation_artifacts,
    ) as BrowserObservationArtifacts | null,
  };
}

function mergeObservationContract(
  base: ComputerUseObservationBundle,
  override: Partial<ComputerUseObservationBundle> | null,
  leaseId: string,
  lane: ComputerUseLane,
  sessionMode: ComputerUseSessionMode,
  retentionMode: ObservationRetentionMode,
): ComputerUseObservationBundle {
  if (!override) return base;
  const detectedPatterns = cleanStringArray(override.detected_patterns);
  return {
    ...base,
    ...override,
    observation_ref: cleanString(override.observation_ref) ?? base.observation_ref,
    lease_id: leaseId,
    lane,
    session_mode: sessionMode,
    target_index_ref: cleanString(override.target_index_ref) ?? base.target_index_ref,
    retention_mode: observationRetentionModeValue(override.retention_mode) ?? retentionMode,
    detected_patterns: detectedPatterns.length > 0 ? detectedPatterns : base.detected_patterns,
  };
}

function mergeTargetIndexContract(
  base: TargetIndex,
  override: Partial<TargetIndex> | null,
  observationRef: string,
): TargetIndex {
  if (!override) return base;
  const targets = Array.isArray(override.targets) && override.targets.length > 0
    ? override.targets
    : base.targets;
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

function mergeAffordanceGraphContract(
  base: AffordanceGraph,
  override: Partial<AffordanceGraph> | null,
  targetIndexRef: string,
  observationRef: string,
): AffordanceGraph {
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

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function cleanStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => cleanString(item))
    .filter((item): item is string => Boolean(item));
}

function uniqueStrings(values: unknown[]): string[] {
  return [...new Set(values.map((value) => cleanString(value)).filter(Boolean) as string[])];
}

function uniqueComputerActionKinds(values: ComputerActionKind[]): ComputerActionKind[] {
  return [...new Set(values)];
}

function compactUnknowns<T>(values: Array<T | null | undefined | false | "">): T[] {
  return values.filter(Boolean) as T[];
}

function booleanValue(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function observationRetentionModeValue(
  value: unknown,
): ObservationRetentionMode | null {
  const cleaned = cleanString(value);
  return cleaned === "prompt_visible_summary_only" ||
    cleaned === "local_redacted_artifacts" ||
    cleaned === "local_raw_artifacts" ||
    cleaned === "encrypted_local_raw_artifacts" ||
    cleaned === "shareable_eval_artifacts" ||
    cleaned === "no_persistence"
    ? cleaned
    : null;
}

function safeFileName(value: string): string {
  return String(value).replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
