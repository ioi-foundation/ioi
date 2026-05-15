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
