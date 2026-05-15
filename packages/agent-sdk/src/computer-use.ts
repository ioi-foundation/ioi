export const COMPUTER_USE_CONTRACT_SCHEMA_VERSION = "ioi.computer-use.harness.v1" as const;

export type ComputerUseLane = "native_browser" | "visual_gui" | "sandboxed_hosted";

export type ComputerUseSessionMode =
  | "owned_hermetic_browser"
  | "attached_browser"
  | "controlled_relaunch"
  | "visual_fallback"
  | "foreground_desktop"
  | "background_desktop"
  | "app_scoped_desktop"
  | "local_sandbox"
  | "hosted_sandbox"
  | "mobile_device";

export type ObservationRetentionMode =
  | "prompt_visible_summary_only"
  | "local_redacted_artifacts"
  | "local_raw_artifacts"
  | "encrypted_local_raw_artifacts"
  | "shareable_eval_artifacts"
  | "no_persistence";

export type ComputerActionKind =
  | "click"
  | "type_text"
  | "key_press"
  | "scroll"
  | "drag"
  | "hover"
  | "select"
  | "upload"
  | "clipboard"
  | "wait"
  | "shell"
  | "mobile_gesture"
  | "navigate"
  | "inspect";

export interface ComputerUseLease {
  schema_version: typeof COMPUTER_USE_CONTRACT_SCHEMA_VERSION | string;
  lease_id: string;
  lane: ComputerUseLane;
  session_mode: ComputerUseSessionMode;
  status: string;
  authority_scope: string;
  consent_scope: string;
  target_hint: string;
  environment_ref: string;
  profile_provenance: string;
  retention_mode: ObservationRetentionMode;
  cleanup_required: boolean;
  evidence_refs: unknown[];
}

export interface ComputerControlAdapterContract {
  schema_version: typeof COMPUTER_USE_CONTRACT_SCHEMA_VERSION | string;
  adapter_id: string;
  lane: ComputerUseLane;
  supported_session_modes: ComputerUseSessionMode[];
  capabilities: string[];
  emits_observation_bundle: boolean;
  emits_action_receipts: boolean;
  fail_closed_when_unavailable: boolean;
}

export interface ComputerUseObservationBundle {
  observation_ref: string;
  lease_id: string;
  lane: ComputerUseLane;
  session_mode: ComputerUseSessionMode;
  url?: string | null;
  title?: string | null;
  app_name?: string | null;
  window_title?: string | null;
  screenshot_ref?: string | null;
  som_ref?: string | null;
  dom_ref?: string | null;
  ax_ref?: string | null;
  selector_map_ref?: string | null;
  target_index_ref?: string | null;
  redaction_report_ref?: string | null;
  freshness_ms?: number | null;
  retention_mode: ObservationRetentionMode;
  detected_patterns: string[];
}

export interface ComputerUseTargetEntry {
  target_ref: string;
  label: string;
  role: string;
  semantic_ids: string[];
  selectors: string[];
  som_id?: number | null;
  ax_ref?: string | null;
  bounds?: unknown;
  confidence: number;
  available_actions: ComputerActionKind[];
}

export interface TargetIndex {
  target_index_ref: string;
  observation_ref: string;
  coordinate_space_id: string;
  drift_state: string;
  targets: ComputerUseTargetEntry[];
}

export interface AffordanceRecord {
  target_ref: string;
  possible_action: ComputerActionKind;
  action_preconditions: string[];
  confidence: number;
  expected_state_transition: string;
  risk_class: string;
  required_authority: string;
  confirmation_required: boolean;
  fallback_action_paths: string[];
  invalidation_conditions: string[];
}

export interface AffordanceGraph {
  graph_ref: string;
  target_index_ref: string;
  observation_ref: string;
  affordances: AffordanceRecord[];
}

export interface ActionProposal {
  proposal_ref: string;
  proposed_by: string;
  model_role: string;
  raw_model_output_ref?: string | null;
  normalized_action_candidate: string;
  target_ref?: string | null;
  confidence: number;
  rationale_summary: string;
  predicted_postcondition: string;
  risk_assessment: string;
  policy_decision_ref?: string | null;
}

export type ComputerUsePolicyDecisionOutcome =
  | "approved_for_read_only_probe"
  | "requires_confirmation_before_execution"
  | "approved_after_confirmation"
  | "blocked_executor_unavailable"
  | string;

export interface ComputerUsePolicyDecisionReceipt {
  policy_decision_ref: string;
  proposal_ref: string;
  action_kind: ComputerActionKind | string;
  outcome: ComputerUsePolicyDecisionOutcome;
  authority_scope: string;
  approval_ref?: string | null;
  external_effect: boolean;
  fail_closed: boolean;
  reasons: string[];
  evidence_refs: unknown[];
}

export type ComputerUseVerificationStatus = "passed" | "failed" | "requires_human" | "blocked" | "unknown";

export interface ComputerUseVerificationReceipt {
  verification_ref: string;
  action_ref?: string | null;
  status: ComputerUseVerificationStatus;
  expected_postcondition: string;
  observed_postcondition: string;
  verifier: string;
  evidence_refs: unknown[];
}

export interface ComputerUseRunState {
  run_id: string;
  lease_id: string;
  user_goal: string;
  current_subgoal: string;
  plan_graph_ref?: string | null;
  current_observation_ref?: string | null;
  current_target_index_ref?: string | null;
  active_hypotheses: string[];
  expected_postcondition: string;
  last_action_ref?: string | null;
  verification_status: ComputerUseVerificationStatus;
  blocker_state?: string | null;
  retry_budget: number;
  risk_posture: string;
  user_handoff_ref?: string | null;
  cleanup_state: string;
}

export type ComputerUseFailureClass =
  | "perception"
  | "grounding"
  | "planning"
  | "policy"
  | "execution"
  | "verification"
  | "environment"
  | "handoff"
  | "unknown";

export type ComputerUseFailureMode =
  | "visual_drift"
  | "target_not_found"
  | "no_effect_action"
  | "stale_observation"
  | "modal_interruption"
  | "auth_wall"
  | "navigation_loop"
  | "network_stall"
  | "browser_crash"
  | "sandbox_unavailable"
  | "policy_block"
  | "handoff_timeout"
  | "unknown";

export type ComputerUseRecoveryAction =
  | "reobserve"
  | "rebuild_target_index"
  | "switch_to_visual_fallback"
  | "switch_to_native_browser"
  | "ask_user"
  | "pause_for_auth"
  | "retry_action"
  | "rollback"
  | "terminate_safely"
  | "escalate_to_sandbox"
  | "mark_blocked";

export interface RecoveryPolicy {
  policy_ref: string;
  failure_class: ComputerUseFailureClass;
  failure_mode: ComputerUseFailureMode;
  allowed_actions: ComputerUseRecoveryAction[];
  disallowed_actions: string[];
  retry_budget_delta: number;
  requires_human_handoff: boolean;
  fail_closed: boolean;
  evidence_required: string[];
  rationale_summary: string;
}

export type HumanHandoffStatus = "pending" | "resumed" | "timeout" | "cancelled";

export interface HumanHandoffState {
  handoff_ref: string;
  reason: string;
  requested_user_action: string;
  forbidden_agent_actions: string[];
  resume_condition: string;
  observation_after_resume_ref?: string | null;
  timeout_policy: string;
  evidence_retention: ObservationRetentionMode;
  status: HumanHandoffStatus;
}

export type InterfacePatternKind =
  | "form"
  | "table"
  | "modal"
  | "canvas"
  | "graph"
  | "editor"
  | "terminal"
  | "file_picker"
  | "sidebar"
  | "toolbar"
  | "tabset"
  | "toast_or_warning"
  | "auth_wall"
  | "iframe"
  | "shadow_dom";

export interface InterfacePatternRecord {
  pattern_ref: string;
  pattern_kind: InterfacePatternKind;
  target_refs: string[];
  confidence: number;
  summary: string;
}

export interface InterfacePatternIndex {
  pattern_index_ref: string;
  observation_ref: string;
  patterns: InterfacePatternRecord[];
}

export type ComputerUseExternalEffectPolicy = "allowed" | "confirmation_required" | "prohibited";

export interface OutcomeContract {
  outcome_ref: string;
  requested_outcome: string;
  success_criteria: string[];
  acceptable_side_effects: string[];
  prohibited_side_effects: string[];
  evidence_required: string[];
  rollback_or_cleanup_required: boolean;
  external_effect_policy: ComputerUseExternalEffectPolicy;
}

export type CommitGateStatus = "not_required" | "pending_confirmation" | "approved" | "blocked" | "completed";

export interface CommitGate {
  commit_gate_ref: string;
  final_action_ref?: string | null;
  outcome_ref?: string | null;
  external_effect: boolean;
  user_confirmation_required: boolean;
  authority_required: string;
  pre_commit_summary: string;
  post_commit_verification: string;
  policy_decision_ref?: string | null;
  status: CommitGateStatus;
}

export interface EnvironmentOptionRejection {
  lane: ComputerUseLane;
  session_mode: ComputerUseSessionMode;
  reason: string;
}

export interface EnvironmentSelectionReceipt {
  receipt_ref: string;
  run_id: string;
  selected_lane: ComputerUseLane;
  selected_session_mode: ComputerUseSessionMode;
  rejected_options: EnvironmentOptionRejection[];
  reasons: string[];
  risk_posture: string;
  authority_required: string;
  privacy_impact: string;
  expected_cleanup: string;
}

export interface ComputerAction {
  action_ref: string;
  proposal_ref?: string | null;
  action_kind: ComputerActionKind;
  target_ref?: string | null;
  observation_ref: string;
  coordinate_space_id?: string | null;
  payload_summary: string;
  expected_postcondition: string;
  approval_ref?: string | null;
}

export interface ActionReceipt {
  receipt_ref: string;
  action_ref: string;
  adapter_id: string;
  status: string;
  grounding_ref: string;
  postcondition_summary: string;
  verification_ref?: string | null;
  evidence_refs: unknown[];
}

export interface ComputerUseTrajectoryEntry {
  sequence: number;
  event_kind: string;
  observation_ref?: string | null;
  proposal_ref?: string | null;
  action_ref?: string | null;
  receipt_ref?: string | null;
  verification_ref?: string | null;
  summary: string;
}

export interface ComputerUseTrajectoryBundle {
  schema_version: typeof COMPUTER_USE_CONTRACT_SCHEMA_VERSION | string;
  trajectory_ref: string;
  run_id: string;
  lease_id: string;
  entries: ComputerUseTrajectoryEntry[];
  retention_mode: ObservationRetentionMode;
}

export type ComputerUseTrajectoryEvalOutcome =
  | "passed"
  | "blocked"
  | "needs_human"
  | "failed"
  | "unknown";

export interface ComputerUseTrajectoryEvalProjection {
  schema_version: typeof COMPUTER_USE_CONTRACT_SCHEMA_VERSION | string;
  eval_ref: string;
  trajectory_ref: string | null;
  run_id: string | null;
  lane: ComputerUseLane | string | null;
  session_mode: ComputerUseSessionMode | string | null;
  outcome: ComputerUseTrajectoryEvalOutcome;
  score: number;
  failure_class: ComputerUseFailureClass;
  failure_mode: ComputerUseFailureMode;
  step_counts: Record<string, number>;
  missing_regression_gates: string[];
  evidence_refs: string[];
  summary: string;
}

export interface ComputerUseTrajectoryEvalInput {
  trace?: Record<string, unknown> | null;
  trajectory?: ComputerUseTrajectoryBundle | Record<string, unknown> | null;
}

export type ComputerUseHarnessPatchTarget =
  | "environment_planner"
  | "target_index"
  | "affordance_graph"
  | "policy_gate"
  | "verification"
  | "adapter"
  | "workflow_projection"
  | "evidence_retention";

export interface ComputerUseHarnessPatchProposal {
  patch_ref: string;
  target_surface: ComputerUseHarnessPatchTarget;
  change_summary: string;
  rationale: string;
  expected_regression_gates: string[];
  authority_required: string;
}

export interface ComputerUseShadowReplayPlan {
  replay_ref: string;
  status: "not_required" | "required_before_promotion";
  required_fixtures: string[];
  comparison_gates: string[];
}

export interface ComputerUsePromotionGateReceipt {
  promotion_ref: string;
  status: "not_required" | "blocked_pending_shadow_replay" | "blocked_external_adapter" | "eligible_after_shadow_replay";
  required_evidence: string[];
  summary: string;
}

export interface ComputerUseHarnessImprovementPlan {
  schema_version: typeof COMPUTER_USE_CONTRACT_SCHEMA_VERSION | string;
  plan_ref: string;
  eval_ref: string;
  trajectory_ref: string | null;
  run_id: string | null;
  outcome: ComputerUseTrajectoryEvalOutcome;
  failure_class: ComputerUseFailureClass;
  failure_mode: ComputerUseFailureMode;
  recovery_policy: RecoveryPolicy | null;
  patch_proposals: ComputerUseHarnessPatchProposal[];
  shadow_replay: ComputerUseShadowReplayPlan;
  promotion_gate: ComputerUsePromotionGateReceipt;
  residual_risks: string[];
  summary: string;
}

export interface ComputerUseHarnessImprovementInput {
  trace?: Record<string, unknown> | null;
  trajectory?: ComputerUseTrajectoryBundle | Record<string, unknown> | null;
  eval?: ComputerUseTrajectoryEvalProjection | null;
}

export interface CleanupReceipt {
  cleanup_ref: string;
  lease_id: string;
  status: string;
  closed_process_refs: string[];
  deleted_profile_refs: string[];
  retained_artifact_refs: string[];
  warnings: string[];
}

export interface ComputerUseHarnessContract {
  schema_version: typeof COMPUTER_USE_CONTRACT_SCHEMA_VERSION | string;
  required_lanes: ComputerUseLane[];
  required_loop_steps: string[];
  required_contracts: string[];
  requires_action_proposal_before_execution: boolean;
  requires_observation_grounding_for_coordinates: boolean;
  requires_commit_gate_for_external_effects: boolean;
  requires_trajectory_bundle: boolean;
  forbids_shadow_runtime_truth: boolean;
}

export type ComputerUseModelActionAdapterKind =
  | "openai_computer_use"
  | "ui_tars"
  | "generic_vlm";

export interface ComputerUseModelActionSafetyCheck {
  check_ref: string;
  source: ComputerUseModelActionAdapterKind | string;
  status: "passed" | "requires_approval" | "blocked" | "unknown";
  policy_decision_ref: string;
  summary: string;
}

export interface ComputerUseModelActionGrounding {
  observation_ref: string;
  target_index_ref?: string | null;
  coordinate_space_id?: string | null;
  target_ref?: string | null;
  coordinate?: { x: number; y: number } | null;
  grounding_status: "target_ref" | "coordinate" | "ungrounded";
}

export interface ComputerUseModelActionAdapterInput {
  adapter_kind: ComputerUseModelActionAdapterKind;
  run_id: string;
  raw_model_output: unknown;
  observation_ref: string;
  target_index?: TargetIndex | null;
  proposed_by?: string;
  model_role?: string;
  policy_decision_ref?: string;
  approval_ref?: string | null;
}

export interface ComputerUseModelActionAdapterResult {
  adapter_kind: ComputerUseModelActionAdapterKind;
  action_proposal: ActionProposal;
  computer_action: ComputerAction;
  grounding: ComputerUseModelActionGrounding;
  safety_checks: ComputerUseModelActionSafetyCheck[];
}

export interface ComputerUseRecoveryPolicyInput {
  run_id: string;
  failure_mode: ComputerUseFailureMode;
  failure_class?: ComputerUseFailureClass;
  lane?: ComputerUseLane;
  retry_budget?: number;
  fail_closed?: boolean;
  allowed_actions?: ComputerUseRecoveryAction[];
}

export interface HumanHandoffInput {
  run_id: string;
  reason: string;
  requested_user_action?: string;
  forbidden_agent_actions?: string[];
  resume_condition?: string;
  observation_after_resume_ref?: string | null;
  timeout_policy?: string;
  evidence_retention?: ObservationRetentionMode;
  status?: HumanHandoffStatus;
}

export interface OutcomeContractInput {
  run_id: string;
  requested_outcome: string;
  success_criteria?: string[];
  acceptable_side_effects?: string[];
  prohibited_side_effects?: string[];
  evidence_required?: string[];
  rollback_or_cleanup_required?: boolean;
  external_effect_policy?: ComputerUseExternalEffectPolicy;
}

export interface CommitGateInput {
  run_id: string;
  action: ComputerAction;
  outcome_contract?: OutcomeContract | null;
  proposal?: ActionProposal | null;
  policy_decision_ref?: string | null;
  external_effect?: boolean;
  status?: CommitGateStatus;
}

export function defaultComputerUseHarnessContract(): ComputerUseHarnessContract {
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

export function isActionProposalReadyForExecution(proposal: ActionProposal): boolean {
  return Boolean(
    proposal.target_ref?.trim() &&
      proposal.policy_decision_ref?.trim() &&
      proposal.predicted_postcondition.trim(),
  );
}

export function computerActionHasGrounding(action: ComputerAction): boolean {
  return Boolean(
    action.observation_ref.trim() &&
      (action.target_ref?.trim() || action.coordinate_space_id?.trim()),
  );
}

export function recoveryPolicyForComputerUseFailure(input: ComputerUseRecoveryPolicyInput): RecoveryPolicy {
  const failureClass = input.failure_class ?? failureClassForMode(input.failure_mode);
  const allowedActions = input.allowed_actions ?? defaultRecoveryActionsForFailure(input.failure_mode, input.lane);
  const requiresHumanHandoff = allowedActions.some((action) => action === "ask_user" || action === "pause_for_auth");
  const failClosed =
    input.fail_closed ??
    ["auth_wall", "policy_block", "sandbox_unavailable", "handoff_timeout"].includes(input.failure_mode);
  return {
    policy_ref: `recovery_policy_${safeComputerUseId(input.run_id)}_${input.failure_mode}`,
    failure_class: failureClass,
    failure_mode: input.failure_mode,
    allowed_actions: allowedActions,
    disallowed_actions: disallowedRecoveryActionsForFailure(input.failure_mode),
    retry_budget_delta: retryBudgetDeltaForFailure(input.failure_mode, input.retry_budget ?? 0),
    requires_human_handoff: requiresHumanHandoff,
    fail_closed: failClosed,
    evidence_required: evidenceForFailure(input.failure_mode),
    rationale_summary: recoveryRationale(input.failure_mode, failureClass, failClosed),
  };
}

export function humanHandoffForComputerUseBoundary(input: HumanHandoffInput): HumanHandoffState {
  return {
    handoff_ref: `handoff_${safeComputerUseId(input.run_id)}_${safeComputerUseId(input.reason)}`,
    reason: input.reason,
    requested_user_action:
      input.requested_user_action ??
      "Complete the sensitive or human-only step, then return control to the agent.",
    forbidden_agent_actions: input.forbidden_agent_actions ?? [
      "enter_secret",
      "solve_captcha",
      "submit_payment",
      "change_account_permissions",
    ],
    resume_condition: input.resume_condition ?? "A fresh observation confirms the user completed the handoff step.",
    observation_after_resume_ref: input.observation_after_resume_ref ?? null,
    timeout_policy: input.timeout_policy ?? "pause_until_user_resumes_or_cancels",
    evidence_retention: input.evidence_retention ?? "prompt_visible_summary_only",
    status: input.status ?? "pending",
  };
}

export function outcomeContractForGoal(input: OutcomeContractInput): OutcomeContract {
  return {
    outcome_ref: `outcome_${safeComputerUseId(input.run_id)}`,
    requested_outcome: input.requested_outcome,
    success_criteria: input.success_criteria ?? ["The requested UI state transition is observed and verified."],
    acceptable_side_effects: input.acceptable_side_effects ?? [],
    prohibited_side_effects: input.prohibited_side_effects ?? [
      "Submitting credentials, payments, messages, purchases, or permission changes without confirmation.",
    ],
    evidence_required: input.evidence_required ?? ["verification_receipt"],
    rollback_or_cleanup_required: input.rollback_or_cleanup_required ?? true,
    external_effect_policy: input.external_effect_policy ?? "confirmation_required",
  };
}

export function commitGateForComputerAction(input: CommitGateInput): CommitGate {
  const externalEffect = input.external_effect ?? computerActionHasExternalEffect(input.action);
  const externalPolicy = input.outcome_contract?.external_effect_policy ?? "confirmation_required";
  const policyDecisionRef =
    input.policy_decision_ref ??
    input.proposal?.policy_decision_ref ??
    input.action.approval_ref ??
    null;
  const status =
    input.status ??
    commitGateStatusForPolicy(externalEffect, externalPolicy, policyDecisionRef);
  return {
    commit_gate_ref: `commit_gate_${safeComputerUseId(input.run_id)}_${safeComputerUseId(input.action.action_ref)}`,
    final_action_ref: input.action.action_ref,
    outcome_ref: input.outcome_contract?.outcome_ref ?? null,
    external_effect: externalEffect,
    user_confirmation_required: externalEffect && externalPolicy !== "allowed",
    authority_required: externalEffect ? "computer_use.external_effect" : "computer_use.read_only",
    pre_commit_summary: externalEffect
      ? `Review before applying ${input.action.payload_summary}.`
      : `No commit gate required for ${input.action.payload_summary}.`,
    post_commit_verification:
      input.outcome_contract?.success_criteria.join("; ") ??
      input.action.expected_postcondition,
    policy_decision_ref: policyDecisionRef,
    status,
  };
}

export function commitGateRequiresConfirmation(gate: CommitGate): boolean {
  return gate.user_confirmation_required && gate.status === "pending_confirmation";
}

export function computerActionHasExternalEffect(action: ComputerAction): boolean {
  return riskAssessmentForComputerAction(action.action_kind) !== "read_only";
}

export function observationRetentionAllowsRawPersistence(mode: ObservationRetentionMode): boolean {
  return mode === "local_raw_artifacts" || mode === "encrypted_local_raw_artifacts";
}

export function evaluateComputerUseTrajectory(
  input: ComputerUseTrajectoryEvalInput,
): ComputerUseTrajectoryEvalProjection {
  const trace = recordValue(input.trace);
  const explicitTrajectory = recordValue(input.trajectory);
  const traceTrajectoryCandidate = recordValue(trace["trajectory"]);
  const traceTrajectory = Object.keys(traceTrajectoryCandidate).length > 0
    ? traceTrajectoryCandidate
    : recordValue(trace["trajectory_bundle"]);
  const trajectory = Object.keys(explicitTrajectory).length > 0
    ? explicitTrajectory
    : traceTrajectory;
  const entries = arrayValue(trajectory["entries"]).map((entry) =>
    recordValue(entry),
  );
  const stepCounts = entries.reduce<Record<string, number>>((counts, entry) => {
    const step = stringValue(entry["event_kind"]) ?? "unknown";
    counts[step] = (counts[step] ?? 0) + 1;
    return counts;
  }, {});
  const environmentSelection = recordValue(trace["environmentSelection"]) || recordValue(trace["environment_selection"]);
  const lease = recordValue(trace["lease"]);
  const runState = recordValue(trace["runState"]) || recordValue(trace["run_state"]);
  const observation = recordValue(trace["observation"]);
  const targetIndex = recordValue(trace["targetIndex"]) || recordValue(trace["target_index"]);
  const actionProposal = recordValue(trace["actionProposal"]) || recordValue(trace["action_proposal"]);
  const verification = recordValue(trace["verification"]) || recordValue(trace["verification_receipt"]);
  const cleanup = recordValue(trace["cleanup"]) || recordValue(trace["cleanup_receipt"]);
  const commitGate = recordValue(trace["commitGate"]) || recordValue(trace["commit_gate"]);
  const verificationStatus = stringValue(verification["status"]);
  const cleanupStatus = stringValue(cleanup["status"]);
  const blocker = stringValue(runState["blocker_state"]) ?? stringValue(trace["blocker_state"]);
  const commitGateStatus = stringValue(commitGate["status"]);
  const missingRegressionGates = regressionGatesForComputerUseTrace({
    environmentSelection,
    observation,
    targetIndex,
    actionProposal,
    verification,
    cleanup,
    stepCounts,
  });
  const outcome = trajectoryEvalOutcome({
    verificationStatus,
    cleanupStatus,
    blocker,
    commitGateStatus,
    missingRegressionGates,
  });
  const failure = trajectoryEvalFailure({
    outcome,
    verificationStatus,
    blocker,
    missingRegressionGates,
  });
  const runId =
    stringValue(trajectory["run_id"]) ??
    stringValue(runState["run_id"]) ??
    stringValue(environmentSelection["run_id"]);
  const trajectoryRef = stringValue(trajectory["trajectory_ref"]);
  const lane =
    stringValue(environmentSelection["selected_lane"]) ??
    stringValue(lease["lane"]) ??
    null;
  const sessionMode =
    stringValue(environmentSelection["selected_session_mode"]) ??
    stringValue(lease["session_mode"]) ??
    null;
  return {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    eval_ref: `computer_use_eval_${safeComputerUseId(runId ?? trajectoryRef ?? "trajectory")}`,
    trajectory_ref: trajectoryRef,
    run_id: runId,
    lane,
    session_mode: sessionMode,
    outcome,
    score: trajectoryEvalScore(outcome, missingRegressionGates.length),
    failure_class: failure.failureClass,
    failure_mode: failure.failureMode,
    step_counts: stepCounts,
    missing_regression_gates: missingRegressionGates,
    evidence_refs: trajectoryEvalEvidenceRefs({
      environmentSelection,
      observation,
      targetIndex,
      actionProposal,
      verification,
      cleanup,
      trajectory,
    }),
    summary: trajectoryEvalSummary(outcome, lane, sessionMode, blocker),
  };
}

export function planComputerUseHarnessImprovement(
  input: ComputerUseHarnessImprovementInput,
): ComputerUseHarnessImprovementPlan {
  const trajectoryEval =
    input.eval ??
    evaluateComputerUseTrajectory({
      trace: input.trace,
      trajectory: input.trajectory,
    });
  const runId = trajectoryEval.run_id ?? "trajectory";
  const patchProposals = harnessPatchProposalsForEval(trajectoryEval);
  const needsImprovement = trajectoryEval.outcome !== "passed" || trajectoryEval.missing_regression_gates.length > 0;
  const recoveryPolicy = needsImprovement
    ? recoveryPolicyForComputerUseFailure({
        run_id: runId,
        failure_mode: trajectoryEval.failure_mode,
        failure_class: trajectoryEval.failure_class,
        lane: computerUseLaneValue(trajectoryEval.lane),
        retry_budget: 1,
      })
    : null;
  const shadowReplay: ComputerUseShadowReplayPlan = {
    replay_ref: `computer_use_shadow_replay_${safeComputerUseId(runId)}`,
    status: needsImprovement ? "required_before_promotion" : "not_required",
    required_fixtures: needsImprovement
      ? shadowReplayFixturesForTrajectoryEval(trajectoryEval)
      : [],
    comparison_gates: needsImprovement
      ? [
          "same_observation_inputs",
          "same_policy_posture",
          "no_new_external_effects",
          "verification_status_improves",
          "cleanup_receipt_preserved",
        ]
      : [],
  };
  const promotionGate = promotionGateForImprovementPlan({
    runId,
    trajectoryEval,
    patchProposals,
    shadowReplay,
  });
  return {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    plan_ref: `computer_use_improvement_${safeComputerUseId(runId)}`,
    eval_ref: trajectoryEval.eval_ref,
    trajectory_ref: trajectoryEval.trajectory_ref,
    run_id: trajectoryEval.run_id,
    outcome: trajectoryEval.outcome,
    failure_class: trajectoryEval.failure_class,
    failure_mode: trajectoryEval.failure_mode,
    recovery_policy: recoveryPolicy,
    patch_proposals: patchProposals,
    shadow_replay: shadowReplay,
    promotion_gate: promotionGate,
    residual_risks: residualRisksForImprovementPlan(trajectoryEval, patchProposals),
    summary: improvementPlanSummary(trajectoryEval, patchProposals, promotionGate),
  };
}

export function compileComputerUseModelActionAdapter(
  input: ComputerUseModelActionAdapterInput,
): ComputerUseModelActionAdapterResult {
  const actionKind = modelActionKind(input.raw_model_output);
  const coordinate = modelActionCoordinate(input.raw_model_output);
  const explicitTargetRef = modelActionTargetRef(input.raw_model_output);
  const target = explicitTargetRef
    ? targetByRef(input.target_index, explicitTargetRef)
    : coordinate
      ? targetContainingCoordinate(input.target_index, coordinate)
      : null;
  const targetRef = explicitTargetRef ?? target?.target_ref ?? null;
  const coordinateSpaceId =
    input.target_index?.coordinate_space_id ??
    boundsValue(target?.bounds)?.coordinate_space_id ??
    null;
  const policyDecisionRef =
    input.policy_decision_ref ??
    `policy_${safeComputerUseId(input.run_id)}_${input.adapter_kind}_${actionKind}`;
  const riskAssessment = riskAssessmentForComputerAction(actionKind);
  const predictedPostcondition =
    modelActionPostcondition(input.raw_model_output) ??
    defaultPostconditionForComputerAction(actionKind, targetRef, coordinate);
  const proposal: ActionProposal = {
    proposal_ref: `proposal_${safeComputerUseId(input.run_id)}_${input.adapter_kind}_${actionKind}`,
    proposed_by: input.proposed_by ?? input.adapter_kind,
    model_role: input.model_role ?? "action_parser",
    raw_model_output_ref: `model_output_${safeComputerUseId(input.run_id)}_${input.adapter_kind}`,
    normalized_action_candidate: normalizedActionCandidate(actionKind, targetRef, coordinate),
    target_ref: targetRef,
    confidence: modelActionConfidence(input.raw_model_output) ?? confidenceForGrounding(targetRef, coordinate),
    rationale_summary:
      modelActionRationale(input.raw_model_output) ??
      rationaleForComputerAction(actionKind, targetRef, coordinate),
    predicted_postcondition: predictedPostcondition,
    risk_assessment: riskAssessment,
    policy_decision_ref: policyDecisionRef,
  };
  const action: ComputerAction = {
    action_ref: `action_${safeComputerUseId(input.run_id)}_${input.adapter_kind}_${actionKind}`,
    proposal_ref: proposal.proposal_ref,
    action_kind: actionKind,
    target_ref: targetRef,
    observation_ref: input.observation_ref,
    coordinate_space_id: coordinateSpaceId,
    payload_summary: normalizedActionCandidate(actionKind, targetRef, coordinate),
    expected_postcondition: predictedPostcondition,
    approval_ref:
      input.approval_ref ??
      (riskAssessment === "read_only" ? null : policyDecisionRef),
  };
  const groundingStatus: ComputerUseModelActionGrounding["grounding_status"] =
    targetRef ? "target_ref" : coordinateSpaceId ? "coordinate" : "ungrounded";
  return {
    adapter_kind: input.adapter_kind,
    action_proposal: proposal,
    computer_action: action,
    grounding: {
      observation_ref: input.observation_ref,
      target_index_ref: input.target_index?.target_index_ref ?? null,
      coordinate_space_id: coordinateSpaceId,
      target_ref: targetRef,
      coordinate,
      grounding_status: groundingStatus,
    },
    safety_checks: modelActionSafetyChecks(input.raw_model_output, input.adapter_kind, policyDecisionRef, riskAssessment),
  };
}

function modelActionKind(raw: unknown): ComputerActionKind {
  const record = recordValue(raw);
  const actionRecord = recordValue(record["action"]);
  const value =
    stringValue(actionRecord["type"]) ??
    stringValue(actionRecord["name"]) ??
    stringValue(record["type"]) ??
    stringValue(record["action"]) ??
    stringValue(record["name"]) ??
    actionKindFromText(typeof raw === "string" ? raw : stringValue(record["text"]) ?? stringValue(record["content"]));
  const normalized = String(value ?? "inspect").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (normalized === "type" || normalized === "input_text") return "type_text";
  if (normalized === "keypress") return "key_press";
  if (normalized === "mouse_move") return "hover";
  if (normalized === "noop" || normalized === "none") return "wait";
  if (isComputerActionKind(normalized)) return normalized;
  return "inspect";
}

function actionKindFromText(text: string | null | undefined): string | null {
  if (!text) return null;
  const normalized = text.trim().toLowerCase();
  if (/^click\b|click\s*\(/.test(normalized)) return "click";
  if (/^type\b|type_text|input\s+text/.test(normalized)) return "type_text";
  if (/^scroll\b/.test(normalized)) return "scroll";
  if (/^hover\b|mouse_move/.test(normalized)) return "hover";
  if (/^wait\b/.test(normalized)) return "wait";
  if (/^navigate\b|open\s+url/.test(normalized)) return "navigate";
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

function modelActionCoordinate(raw: unknown): { x: number; y: number } | null {
  const record = recordValue(raw);
  const actionRecord = recordValue(record["action"]);
  return (
    coordinateFromValue(actionRecord["coordinate"]) ??
    coordinateFromValue(actionRecord["coordinates"]) ??
    coordinateFromValue(actionRecord["position"]) ??
    coordinateFromXY(actionRecord["x"], actionRecord["y"]) ??
    coordinateFromValue(record["coordinate"]) ??
    coordinateFromValue(record["coordinates"]) ??
    coordinateFromValue(record["position"]) ??
    coordinateFromXY(record["x"], record["y"]) ??
    coordinateFromText(typeof raw === "string" ? raw : stringValue(record["text"]) ?? stringValue(record["content"]))
  );
}

function coordinateFromValue(value: unknown): { x: number; y: number } | null {
  if (Array.isArray(value) && value.length >= 2) {
    return coordinateFromXY(value[0], value[1]);
  }
  const record = recordValue(value);
  return coordinateFromXY(record["x"], record["y"]);
}

function coordinateFromXY(x: unknown, y: unknown): { x: number; y: number } | null {
  const numericX = numberValue(x);
  const numericY = numberValue(y);
  if (numericX === null || numericY === null) return null;
  return { x: numericX, y: numericY };
}

function coordinateFromText(text: string | null | undefined): { x: number; y: number } | null {
  if (!text) return null;
  const match = text.match(/(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)/);
  if (!match) return null;
  return { x: Number(match[1]), y: Number(match[2]) };
}

function modelActionTargetRef(raw: unknown): string | null {
  const record = recordValue(raw);
  const actionRecord = recordValue(record["action"]);
  return (
    stringValue(actionRecord["target_ref"]) ??
    stringValue(actionRecord["targetRef"]) ??
    stringValue(actionRecord["target"]) ??
    stringValue(record["target_ref"]) ??
    stringValue(record["targetRef"]) ??
    stringValue(record["target"])
  );
}

function modelActionConfidence(raw: unknown): number | null {
  const record = recordValue(raw);
  const actionRecord = recordValue(record["action"]);
  const value = numberValue(actionRecord["confidence"]) ?? numberValue(record["confidence"]);
  if (value === null) return null;
  return Math.max(0, Math.min(100, value <= 1 ? Math.round(value * 100) : Math.round(value)));
}

function modelActionRationale(raw: unknown): string | null {
  const record = recordValue(raw);
  return (
    stringValue(recordValue(record["action"])["rationale"]) ??
    stringValue(record["rationale"]) ??
    stringValue(record["reasoning"]) ??
    stringValue(record["summary"])
  );
}

function modelActionPostcondition(raw: unknown): string | null {
  const record = recordValue(raw);
  return (
    stringValue(recordValue(record["action"])["predicted_postcondition"]) ??
    stringValue(recordValue(record["action"])["expected_postcondition"]) ??
    stringValue(record["predicted_postcondition"]) ??
    stringValue(record["expected_postcondition"])
  );
}

function targetByRef(targetIndex: TargetIndex | null | undefined, targetRef: string): ComputerUseTargetEntry | null {
  return targetIndex?.targets.find((target) => target.target_ref === targetRef) ?? null;
}

function targetContainingCoordinate(
  targetIndex: TargetIndex | null | undefined,
  coordinate: { x: number; y: number },
): ComputerUseTargetEntry | null {
  return (
    targetIndex?.targets.find((target) => {
      const bounds = boundsValue(target.bounds);
      if (!bounds) return false;
      return (
        coordinate.x >= bounds.x &&
        coordinate.y >= bounds.y &&
        coordinate.x <= bounds.x + bounds.width &&
        coordinate.y <= bounds.y + bounds.height
      );
    }) ?? null
  );
}

function boundsValue(value: unknown): { x: number; y: number; width: number; height: number; coordinate_space_id?: string } | null {
  const record = recordValue(value);
  const x = numberValue(record["x"]);
  const y = numberValue(record["y"]);
  const width = numberValue(record["width"]);
  const height = numberValue(record["height"]);
  if (x === null || y === null || width === null || height === null) return null;
  return {
    x,
    y,
    width,
    height,
    coordinate_space_id: stringValue(record["coordinate_space_id"]) ?? stringValue(record["coordinateSpaceId"]) ?? undefined,
  };
}

function normalizedActionCandidate(
  actionKind: ComputerActionKind,
  targetRef: string | null,
  coordinate: { x: number; y: number } | null,
): string {
  if (targetRef) return `${actionKind} ${targetRef}`;
  if (coordinate) return `${actionKind} at (${coordinate.x}, ${coordinate.y})`;
  return actionKind;
}

function defaultPostconditionForComputerAction(
  actionKind: ComputerActionKind,
  targetRef: string | null,
  coordinate: { x: number; y: number } | null,
): string {
  return `The harness applies ${normalizedActionCandidate(actionKind, targetRef, coordinate)} and verifies the requested UI state transition.`;
}

function rationaleForComputerAction(
  actionKind: ComputerActionKind,
  targetRef: string | null,
  coordinate: { x: number; y: number } | null,
): string {
  if (targetRef) return `Model output resolved to target ${targetRef}.`;
  if (coordinate) return `Model output resolved to observation-bound coordinates (${coordinate.x}, ${coordinate.y}).`;
  return `Model output normalized to ${actionKind}; execution requires additional grounding before side effects.`;
}

function confidenceForGrounding(targetRef: string | null, coordinate: { x: number; y: number } | null): number {
  if (targetRef) return 90;
  if (coordinate) return 72;
  return 35;
}

function riskAssessmentForComputerAction(actionKind: ComputerActionKind): string {
  if (["inspect", "hover", "wait", "scroll"].includes(actionKind)) return "read_only";
  return "possible_external_effect";
}

function failureClassForMode(failureMode: ComputerUseFailureMode): ComputerUseFailureClass {
  if (failureMode === "visual_drift" || failureMode === "stale_observation") return "perception";
  if (failureMode === "target_not_found") return "grounding";
  if (failureMode === "navigation_loop") return "planning";
  if (failureMode === "policy_block") return "policy";
  if (failureMode === "no_effect_action" || failureMode === "modal_interruption") return "verification";
  if (failureMode === "network_stall" || failureMode === "browser_crash" || failureMode === "sandbox_unavailable") {
    return "environment";
  }
  if (failureMode === "auth_wall" || failureMode === "handoff_timeout") return "handoff";
  return "unknown";
}

function defaultRecoveryActionsForFailure(
  failureMode: ComputerUseFailureMode,
  lane: ComputerUseLane | undefined,
): ComputerUseRecoveryAction[] {
  if (failureMode === "visual_drift" || failureMode === "stale_observation") {
    return ["reobserve", "rebuild_target_index", "retry_action"];
  }
  if (failureMode === "target_not_found") {
    return lane === "native_browser"
      ? ["rebuild_target_index", "switch_to_visual_fallback", "ask_user"]
      : ["reobserve", "ask_user", "mark_blocked"];
  }
  if (failureMode === "auth_wall") return ["pause_for_auth", "reobserve", "mark_blocked"];
  if (failureMode === "policy_block") return ["ask_user", "rollback", "mark_blocked"];
  if (failureMode === "sandbox_unavailable") return ["switch_to_native_browser", "terminate_safely", "mark_blocked"];
  if (failureMode === "browser_crash" || failureMode === "network_stall") {
    return ["reobserve", "retry_action", "terminate_safely"];
  }
  if (failureMode === "navigation_loop" || failureMode === "modal_interruption") {
    return ["reobserve", "rollback", "ask_user"];
  }
  if (failureMode === "handoff_timeout") return ["ask_user", "terminate_safely", "mark_blocked"];
  return ["reobserve", "mark_blocked"];
}

function disallowedRecoveryActionsForFailure(failureMode: ComputerUseFailureMode): string[] {
  const disallowed = ["ignore_failure", "continue_without_verification"];
  if (failureMode === "auth_wall") return [...disallowed, "enter_secret", "solve_captcha"];
  if (failureMode === "policy_block") return [...disallowed, "bypass_policy", "execute_side_effect"];
  if (failureMode === "sandbox_unavailable") return [...disallowed, "silently_downgrade_to_unscoped_desktop"];
  return disallowed;
}

function retryBudgetDeltaForFailure(failureMode: ComputerUseFailureMode, retryBudget: number): number {
  if (["auth_wall", "policy_block", "sandbox_unavailable", "handoff_timeout"].includes(failureMode)) return 0;
  return retryBudget > 0 ? -1 : 0;
}

function evidenceForFailure(failureMode: ComputerUseFailureMode): string[] {
  if (failureMode === "auth_wall") return ["observation_bundle", "redacted_screenshot_or_summary", "handoff_state"];
  if (failureMode === "policy_block") return ["policy_decision", "action_proposal", "outcome_contract"];
  if (failureMode === "sandbox_unavailable") return ["environment_selection_receipt", "adapter_contract"];
  return ["observation_bundle", "verification_receipt"];
}

function recoveryRationale(
  failureMode: ComputerUseFailureMode,
  failureClass: ComputerUseFailureClass,
  failClosed: boolean,
): string {
  const posture = failClosed ? "The harness must fail closed until an allowed recovery path is selected." : "The harness may attempt a bounded repair.";
  return `${failureMode} is classified as ${failureClass}. ${posture}`;
}

function commitGateStatusForPolicy(
  externalEffect: boolean,
  externalPolicy: ComputerUseExternalEffectPolicy,
  policyDecisionRef: string | null,
): CommitGateStatus {
  if (!externalEffect) return "not_required";
  if (externalPolicy === "prohibited") return "blocked";
  if (externalPolicy === "allowed" && policyDecisionRef) return "approved";
  return "pending_confirmation";
}

function modelActionSafetyChecks(
  raw: unknown,
  adapterKind: ComputerUseModelActionAdapterKind,
  policyDecisionRef: string,
  riskAssessment: string,
): ComputerUseModelActionSafetyCheck[] {
  const record = recordValue(raw);
  const rawChecks = Array.isArray(record["safety_checks"])
    ? record["safety_checks"]
    : Array.isArray(record["safetyChecks"])
      ? record["safetyChecks"]
      : [];
  if (rawChecks.length === 0) {
    return [{
      check_ref: `${adapterKind}:policy:${riskAssessment}`,
      source: adapterKind,
      status: riskAssessment === "read_only" ? "passed" : "requires_approval",
      policy_decision_ref: policyDecisionRef,
      summary: riskAssessment === "read_only"
        ? "Read-only computer-use action can proceed under policy."
        : "External-effect computer-use action requires IOI policy approval before execution.",
    }];
  }
  return rawChecks.map((item, index) => {
    const check = recordValue(item);
    const status = safetyStatus(stringValue(check["status"]) ?? stringValue(check["decision"]));
    return {
      check_ref: stringValue(check["id"]) ?? stringValue(check["check_ref"]) ?? `${adapterKind}:safety:${index + 1}`,
      source: adapterKind,
      status,
      policy_decision_ref: policyDecisionRef,
      summary: stringValue(check["summary"]) ?? stringValue(check["message"]) ?? `Provider safety check ${index + 1}: ${status}.`,
    };
  });
}

function safetyStatus(value: string | null): ComputerUseModelActionSafetyCheck["status"] {
  if (value === "passed" || value === "allow" || value === "allowed") return "passed";
  if (value === "blocked" || value === "deny" || value === "denied") return "blocked";
  if (value === "requires_approval" || value === "review" || value === "confirm") return "requires_approval";
  return "unknown";
}

function regressionGatesForComputerUseTrace(input: {
  environmentSelection: Record<string, unknown>;
  observation: Record<string, unknown>;
  targetIndex: Record<string, unknown>;
  actionProposal: Record<string, unknown>;
  verification: Record<string, unknown>;
  cleanup: Record<string, unknown>;
  stepCounts: Record<string, number>;
}): string[] {
  const missing: string[] = [];
  if (!stringValue(input.environmentSelection["selected_lane"])) {
    missing.push("environment_selection");
  }
  if (!stringValue(input.observation["observation_ref"])) {
    missing.push("observation_bundle");
  }
  if (!stringValue(input.targetIndex["target_index_ref"])) {
    missing.push("target_index");
  }
  if (!stringValue(input.actionProposal["proposal_ref"])) {
    missing.push("action_proposal");
  }
  if (!stringValue(input.verification["verification_ref"])) {
    missing.push("verification_receipt");
  }
  if (!stringValue(input.cleanup["cleanup_ref"])) {
    missing.push("cleanup_receipt");
  }
  if (!input.stepCounts["propose_action"]) {
    missing.push("trajectory_propose_action_step");
  }
  return missing;
}

function trajectoryEvalOutcome(input: {
  verificationStatus: string | null;
  cleanupStatus: string | null;
  blocker: string | null;
  commitGateStatus: string | null;
  missingRegressionGates: string[];
}): ComputerUseTrajectoryEvalOutcome {
  if (input.missingRegressionGates.length > 0) return "unknown";
  if (input.verificationStatus === "passed") return "passed";
  if (input.verificationStatus === "blocked" || input.blocker) return "blocked";
  if (
    input.verificationStatus === "requires_human" ||
    input.commitGateStatus === "pending_confirmation" ||
    input.commitGateStatus === "requires_confirmation_before_execution"
  ) {
    return "needs_human";
  }
  if (input.verificationStatus === "failed" || input.cleanupStatus === "failed") {
    return "failed";
  }
  return "unknown";
}

function trajectoryEvalFailure(input: {
  outcome: ComputerUseTrajectoryEvalOutcome;
  verificationStatus: string | null;
  blocker: string | null;
  missingRegressionGates: string[];
}): {
  failureClass: ComputerUseFailureClass;
  failureMode: ComputerUseFailureMode;
} {
  if (input.outcome === "passed") {
    return { failureClass: "unknown", failureMode: "unknown" };
  }
  if (input.missingRegressionGates.includes("observation_bundle")) {
    return { failureClass: "perception", failureMode: "stale_observation" };
  }
  if (input.missingRegressionGates.includes("target_index")) {
    return { failureClass: "grounding", failureMode: "target_not_found" };
  }
  if (input.blocker?.includes("adapter") || input.blocker?.includes("executor")) {
    return { failureClass: "environment", failureMode: "sandbox_unavailable" };
  }
  if (input.blocker?.includes("policy") || input.verificationStatus === "blocked") {
    return { failureClass: "policy", failureMode: "policy_block" };
  }
  if (input.outcome === "needs_human") {
    return { failureClass: "handoff", failureMode: "handoff_timeout" };
  }
  if (input.outcome === "failed") {
    return { failureClass: "verification", failureMode: "no_effect_action" };
  }
  return { failureClass: "unknown", failureMode: "unknown" };
}

function trajectoryEvalScore(
  outcome: ComputerUseTrajectoryEvalOutcome,
  missingGateCount: number,
): number {
  if (missingGateCount > 0) return 0;
  if (outcome === "passed") return 1;
  if (outcome === "needs_human") return 0.75;
  if (outcome === "blocked") return 0.5;
  return 0;
}

function trajectoryEvalEvidenceRefs(input: {
  environmentSelection: Record<string, unknown>;
  observation: Record<string, unknown>;
  targetIndex: Record<string, unknown>;
  actionProposal: Record<string, unknown>;
  verification: Record<string, unknown>;
  cleanup: Record<string, unknown>;
  trajectory: Record<string, unknown>;
}): string[] {
  return [
    stringValue(input.environmentSelection["receipt_ref"]),
    stringValue(input.observation["observation_ref"]),
    stringValue(input.targetIndex["target_index_ref"]),
    stringValue(input.actionProposal["proposal_ref"]),
    stringValue(input.verification["verification_ref"]),
    stringValue(input.cleanup["cleanup_ref"]),
    stringValue(input.trajectory["trajectory_ref"]),
  ].filter((value): value is string => Boolean(value));
}

function trajectoryEvalSummary(
  outcome: ComputerUseTrajectoryEvalOutcome,
  lane: string | null,
  sessionMode: string | null,
  blocker: string | null,
): string {
  const surface = [lane, sessionMode].filter(Boolean).join("/") || "computer-use";
  if (outcome === "passed") return `${surface} trajectory passed regression gates.`;
  if (outcome === "needs_human") return `${surface} trajectory stopped at a human/commit boundary.`;
  if (outcome === "blocked") return `${surface} trajectory failed closed${blocker ? ` on ${blocker}` : ""}.`;
  if (outcome === "failed") return `${surface} trajectory failed verification.`;
  return `${surface} trajectory is incomplete for evaluation.`;
}

function harnessPatchProposalsForEval(
  trajectoryEval: ComputerUseTrajectoryEvalProjection,
): ComputerUseHarnessPatchProposal[] {
  if (trajectoryEval.outcome === "passed" && trajectoryEval.missing_regression_gates.length === 0) {
    return [];
  }
  const runId = safeComputerUseId(trajectoryEval.run_id ?? trajectoryEval.trajectory_ref ?? trajectoryEval.eval_ref);
  const proposals: ComputerUseHarnessPatchProposal[] = [];
  for (const missingGate of trajectoryEval.missing_regression_gates) {
    proposals.push({
      patch_ref: `patch_${runId}_regression_${safeComputerUseId(missingGate)}`,
      target_surface: patchTargetForMissingRegressionGate(missingGate),
      change_summary: `Restore missing regression evidence for ${missingGate}.`,
      rationale: "A trajectory cannot be promoted while required computer-use proof is absent.",
      expected_regression_gates: [missingGate],
      authority_required: "computer_use.harness.patch",
    });
  }
  if (proposals.length > 0) return proposals;
  const targetSurface = patchTargetForFailureMode(trajectoryEval.failure_mode);
  return [{
    patch_ref: `patch_${runId}_${trajectoryEval.failure_mode}`,
    target_surface: targetSurface,
    change_summary: patchSummaryForFailureMode(trajectoryEval.failure_mode),
    rationale: `${trajectoryEval.failure_mode} was classified as ${trajectoryEval.failure_class}; patch the harness surface that owns that failure before promotion.`,
    expected_regression_gates: expectedRegressionGatesForPatchTarget(targetSurface),
    authority_required: targetSurface === "adapter"
      ? "computer_use.adapter.mount_or_configure"
      : "computer_use.harness.patch",
  }];
}

function patchTargetForMissingRegressionGate(missingGate: string): ComputerUseHarnessPatchTarget {
  if (missingGate.includes("observation")) return "evidence_retention";
  if (missingGate.includes("target")) return "target_index";
  if (missingGate.includes("proposal")) return "affordance_graph";
  if (missingGate.includes("verification")) return "verification";
  if (missingGate.includes("cleanup")) return "adapter";
  return "workflow_projection";
}

function patchTargetForFailureMode(failureMode: ComputerUseFailureMode): ComputerUseHarnessPatchTarget {
  if (failureMode === "sandbox_unavailable" || failureMode === "browser_crash" || failureMode === "network_stall") {
    return "adapter";
  }
  if (failureMode === "target_not_found") return "target_index";
  if (failureMode === "stale_observation" || failureMode === "visual_drift") return "evidence_retention";
  if (failureMode === "policy_block" || failureMode === "handoff_timeout" || failureMode === "auth_wall") {
    return "policy_gate";
  }
  if (failureMode === "no_effect_action" || failureMode === "modal_interruption") return "verification";
  return "workflow_projection";
}

function patchSummaryForFailureMode(failureMode: ComputerUseFailureMode): string {
  switch (failureMode) {
    case "sandbox_unavailable":
      return "Mount or configure the requested sandbox/hosted adapter, or update environment planning to choose an available lane explicitly.";
    case "target_not_found":
      return "Improve target indexing and fallback grounding for the observed interface pattern.";
    case "stale_observation":
    case "visual_drift":
      return "Refresh observation capture and target-index invalidation before retrying actions.";
    case "policy_block":
      return "Surface the policy decision, required authority, and human approval path before action execution.";
    case "handoff_timeout":
    case "auth_wall":
      return "Make the human handoff resume condition and timeout policy explicit in the harness.";
    case "no_effect_action":
    case "modal_interruption":
      return "Strengthen postcondition verification and repair selection for no-effect or interrupted actions.";
    default:
      return "Add missing harness evidence and classify the failure before promotion.";
  }
}

function expectedRegressionGatesForPatchTarget(target: ComputerUseHarnessPatchTarget): string[] {
  if (target === "environment_planner" || target === "adapter") {
    return ["environment_selection", "cleanup_receipt"];
  }
  if (target === "target_index") return ["target_index", "trajectory_propose_action_step"];
  if (target === "affordance_graph") return ["action_proposal", "trajectory_propose_action_step"];
  if (target === "verification") return ["verification_receipt", "cleanup_receipt"];
  if (target === "policy_gate") return ["action_proposal", "verification_receipt"];
  if (target === "evidence_retention") return ["observation_bundle", "cleanup_receipt"];
  return ["trajectory_propose_action_step", "cleanup_receipt"];
}

function shadowReplayFixturesForTrajectoryEval(
  trajectoryEval: ComputerUseTrajectoryEvalProjection,
): string[] {
  return [
    trajectoryEval.trajectory_ref ? `trajectory:${trajectoryEval.trajectory_ref}` : null,
    trajectoryEval.lane ? `lane:${trajectoryEval.lane}` : null,
    trajectoryEval.session_mode ? `session:${trajectoryEval.session_mode}` : null,
    ...trajectoryEval.evidence_refs.map((ref) => `evidence:${ref}`),
  ].filter((value): value is string => Boolean(value));
}

function promotionGateForImprovementPlan(input: {
  runId: string;
  trajectoryEval: ComputerUseTrajectoryEvalProjection;
  patchProposals: ComputerUseHarnessPatchProposal[];
  shadowReplay: ComputerUseShadowReplayPlan;
}): ComputerUsePromotionGateReceipt {
  const promotionRef = `computer_use_promotion_${safeComputerUseId(input.runId)}`;
  if (input.patchProposals.length === 0) {
    return {
      promotion_ref: promotionRef,
      status: "not_required",
      required_evidence: [],
      summary: "Trajectory already passes regression gates; no harness patch promotion is required.",
    };
  }
  if (input.patchProposals.some((proposal) => proposal.target_surface === "adapter")) {
    return {
      promotion_ref: promotionRef,
      status: "blocked_external_adapter",
      required_evidence: ["adapter_contract", "cleanup_receipt", "shadow_replay_result"],
      summary: "Promotion is blocked until the required computer-use adapter evidence exists and passes shadow replay.",
    };
  }
  return {
    promotion_ref: promotionRef,
    status: "blocked_pending_shadow_replay",
    required_evidence: [
      "harness_patch_diff",
      "shadow_replay_result",
      "held_out_eval_result",
      ...input.shadowReplay.comparison_gates,
    ],
    summary: "Promotion is blocked until the proposed harness patch passes deterministic shadow replay and held-out eval gates.",
  };
}

function residualRisksForImprovementPlan(
  trajectoryEval: ComputerUseTrajectoryEvalProjection,
  patchProposals: ComputerUseHarnessPatchProposal[],
): string[] {
  if (patchProposals.length === 0) return [];
  return [
    trajectoryEval.failure_mode === "sandbox_unavailable"
      ? "Adapter availability may still depend on external provider credentials or host capacity."
      : null,
    trajectoryEval.outcome === "needs_human"
      ? "Human handoff timing may vary across replay environments."
      : null,
    "No harness patch should be promoted without replaying the original trajectory and at least one held-out fixture.",
  ].filter((value): value is string => Boolean(value));
}

function improvementPlanSummary(
  trajectoryEval: ComputerUseTrajectoryEvalProjection,
  patchProposals: ComputerUseHarnessPatchProposal[],
  promotionGate: ComputerUsePromotionGateReceipt,
): string {
  if (patchProposals.length === 0) {
    return `${trajectoryEval.eval_ref} passed; no trajectory-driven harness patch is needed.`;
  }
  return `${trajectoryEval.eval_ref} produced ${patchProposals.length} harness patch proposal(s); promotion status is ${promotionGate.status}.`;
}

function computerUseLaneValue(value: string | null): ComputerUseLane | undefined {
  if (value === "native_browser" || value === "visual_gui" || value === "sandboxed_hosted") return value;
  return undefined;
}

function safeComputerUseId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return null;
}
