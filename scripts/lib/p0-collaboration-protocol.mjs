import crypto from "node:crypto";

export const PROTOCOL_PATH =
  "docs/evidence/p0-collaboration-readiness/comparison-protocol.v1.json";
export const MANIFEST_PATH =
  "docs/evidence/p0-collaboration-readiness/manifest.json";

const fail = (message) => {
  throw new Error(`P0 comparison protocol invalid: ${message}`);
};

const equalJson = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function containsForbiddenResultKey(value) {
  if (Array.isArray(value)) return value.some(containsForbiddenResultKey);
  if (!value || typeof value !== "object") return false;
  const forbidden = new Set([
    "activated_at",
    "arm_results",
    "observed_results",
    "winner",
    "supported_claim",
  ]);
  return Object.entries(value).some(
    ([key, child]) => forbidden.has(key) || containsForbiddenResultKey(child),
  );
}

export function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function validateProtocol(protocol) {
  if (protocol.schema_version !== "ioi.evidence.local-collaboration-comparison-protocol.v1") {
    fail("unexpected schema_version");
  }
  if (protocol.status !== "frozen_not_activated") fail("protocol is not frozen and inactive");
  if (protocol.active_sequencer_stage_at_freeze !== "M0") fail("freeze stage must remain M0");
  if (
    protocol.activation?.activated !== false
    || protocol.activation?.activation_command_present !== false
    || protocol.activation?.claim_bearing_execution_permitted !== false
  ) {
    fail("activation posture must remain explicitly false");
  }
  if (protocol.authority_boundary?.terminal_qualification_owner_stage !== "M9") {
    fail("M9 must remain the terminal qualification owner");
  }
  if (protocol.authority_boundary?.conductor_posture !== "external_daemon_client") {
    fail("conductor must remain an external daemon client");
  }
  const forbiddenImplementations = [
    "swarm object",
    "swarm application",
    "peer runtime",
    "shared authority plane",
    "shared mutable canonical workspace",
    "conductor-owned truth",
  ];
  if (!equalJson(protocol.authority_boundary?.forbidden_implementations, forbiddenImplementations)) {
    fail("forbidden implementation census drifted");
  }

  if (protocol.cohort?.task_count !== 12) fail("matched cohort must contain exactly 12 tasks");
  const strata = protocol.cohort?.task_strata ?? [];
  if (strata.reduce((sum, stratum) => sum + stratum.count, 0) !== 12) {
    fail("task strata must total 12");
  }
  for (const field of [
    "same_exact_task_per_arm",
    "repository_base_and_fixture_hash_matched",
    "acceptance_rubric_hash_matched",
    "eligible_model_snapshot_matched",
    "eligible_task_tool_set_matched",
    "budget_envelope_matched",
    "held_out_verifier_profile_matched",
  ]) {
    if (protocol.cohort?.task_admission?.[field] !== true) fail(`unmatched cohort field ${field}`);
  }

  const arms = new Map((protocol.arms ?? []).map((arm) => [arm.arm_id, arm]));
  if (!equalJson([...arms.keys()], ["S1", "F-N", "D-R"])) fail("arm census or order drifted");
  const s1 = arms.get("S1");
  const fn = arms.get("F-N");
  const dr = arms.get("D-R");
  if (s1.goal_run_count_per_task !== 1 || s1.outcome_room_permitted !== false) {
    fail("S1 must remain one complete direct GoalRun with no room");
  }
  if (
    fn.goal_run_count_per_task !== 1
    || fn.outcome_room_permitted !== false
    || fn.fixed_n_implementers !== 2
    || fn.topology_kind !== "multi_context_review"
  ) {
    fail("F-N must remain the fixed two-implementer direct GoalRun topology");
  }
  if (
    dr.goal_run_count_per_task !== 1
    || dr.outcome_room_count_per_task !== 1
    || dr.participant_path_count !== 2
    || dr.bounds?.max_admitted_participants !== 2
    || dr.bounds?.max_open_claims_per_participant !== 1
    || dr.bounds?.max_attempts_per_claim !== 1
  ) {
    fail("D-R bounded topology drifted");
  }
  const roomChildren = [
    "participant",
    "frontier_item",
    "claim",
    "attempt",
    "finding",
    "verifier_challenge",
    "work_result",
    "outcome_delta",
  ];
  if (!equalJson(dr.permitted_room_children, roomChildren)) fail("D-R room-child census drifted");

  for (const [name, value] of Object.entries(
    protocol.matched_resources?.task_execution_budget_per_arm ?? {},
  )) {
    if (!Number.isSafeInteger(value) || value <= 0) fail(`invalid task budget ${name}`);
  }
  if (protocol.matched_resources?.held_out_verification_budget_per_arm?.max_effectful_tool_calls !== 0) {
    fail("held-out verifier must have zero effectful tool calls");
  }
  const guardrailNames = Object.keys(protocol.guardrails ?? {});
  if (!equalJson(guardrailNames, ["failure", "collapse", "privacy", "independence", "reliability", "economic"])) {
    fail("mandatory guardrail census drifted");
  }
  if (protocol.guardrails?.reliability?.evidence_completeness_required_for_claim !== 1) {
    fail("claim evidence completeness must remain 100 percent");
  }
  if (protocol.guardrails?.economic?.maximum_dr_cost_per_accepted_outcome_ratio_vs_strongest_control !== 1.5) {
    fail("economic guardrail drifted");
  }
  if (protocol.analysis_plan?.claim_ceiling !== "controlled_local_p0_signal_only") {
    fail("claim ceiling widened");
  }
  if (protocol.retention?.negative_evidence_deletion_permitted !== false) {
    fail("negative evidence must remain retained");
  }
  if (containsForbiddenResultKey(protocol)) fail("protocol contains activation or observed-result fields");
  return protocol;
}

export function validateManifest(manifest, protocolBytes) {
  if (manifest.schema_version !== "ioi.evidence.local-collaboration-protocol-manifest.v1") {
    fail("unexpected manifest schema_version");
  }
  if (manifest.protocol_path !== PROTOCOL_PATH) fail("manifest protocol path drifted");
  if (manifest.protocol_sha256 !== `sha256:${sha256(protocolBytes)}`) {
    fail("manifest does not bind the exact protocol bytes");
  }
  if (manifest.status !== "frozen_not_activated" || manifest.cohort_executed !== false) {
    fail("manifest activation posture drifted");
  }
  return manifest;
}
