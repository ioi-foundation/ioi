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

function safeComputerUseId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]+/g, "_");
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
