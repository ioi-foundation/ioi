import crypto from "node:crypto";

const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};

const hash = (value) => `sha256:${crypto.createHash("sha256").update(canonical(value)).digest("hex")}`;
const sortedUnique = (values) => [...new Set(values)].sort();
const stateMaterial = (state) => {
  const copy = structuredClone(state);
  delete copy.trajectory_state_hash;
  return copy;
};

export function sealTrajectoryState(state) {
  return { ...state, trajectory_state_hash: hash(stateMaterial(state)) };
}

export function initialTrajectoryState({ owner_ref, bounded_system_ref, principal_ref, envelope_ancestor_refs, revocation_epoch, window_started_at, window_ends_at, now }) {
  return sealTrajectoryState({
    schema_version: "ioi.foundations.authority-trajectory-state.v1",
    trajectory_state_ref: `trajectory-state://${hash({ owner_ref, bounded_system_ref }).slice(7, 31)}`,
    owner_ref,
    bounded_system_ref,
    principal_ref,
    envelope_ancestor_refs: sortedUnique(envelope_ancestor_refs),
    revocation_epoch,
    window_started_at,
    window_ends_at,
    cumulative_spend_usd: 0,
    cumulative_deposit_usd: 0,
    active_resource_refs: [],
    provider_refs: [],
    destination_refs: [],
    data_class_refs: [],
    admitted_call_count: 0,
    failed_call_count: 0,
    admitted_events: [],
    derived_at: now,
  });
}

const result = (constraint_id, observed, limit, satisfied, evidence_refs = []) => ({
  constraint_id,
  satisfied,
  observed_value: String(observed),
  limit_value: String(limit),
  evidence_refs,
});

export function admitTrajectory({ state, expected_state_hash, candidate, policy, now }) {
  if (state.trajectory_state_hash !== hash(stateMaterial(state)) || expected_state_hash !== state.trajectory_state_hash) {
    return { decision: "deny", reason_codes: ["trajectory_state_conflict"], state_after: state };
  }
  const identityMatches = candidate.owner_ref === state.owner_ref
    && candidate.bounded_system_ref === state.bounded_system_ref
    && candidate.principal_ref === state.principal_ref
    && candidate.envelope_ancestor_refs.every((ref) => state.envelope_ancestor_refs.includes(ref));
  if (!identityMatches || candidate.revocation_epoch !== state.revocation_epoch) {
    return { decision: "deny", reason_codes: ["trajectory_scope_mismatch"], state_after: state };
  }

  const active = sortedUnique([...state.active_resource_refs, ...(candidate.opens_resource ? [candidate.resource_ref] : [])]);
  const providers = sortedUnique([...state.provider_refs, candidate.provider_ref]);
  const destinations = sortedUnique([...state.destination_refs, ...candidate.destination_refs]);
  const dataClasses = sortedUnique([...state.data_class_refs, ...candidate.data_class_refs]);
  const spend = state.cumulative_spend_usd + candidate.spend_reservation_usd;
  const deposit = state.cumulative_deposit_usd + candidate.deposit_reservation_usd;
  const calls = state.admitted_call_count + 1;
  const failures = state.failed_call_count + (candidate.failed ? 1 : 0);
  const constraints = [
    result("max_cumulative_spend_usd", spend, policy.max_cumulative_spend_usd, spend <= policy.max_cumulative_spend_usd),
    result("max_cumulative_deposit_usd", deposit, policy.max_cumulative_deposit_usd, deposit <= policy.max_cumulative_deposit_usd),
    result("max_active_resources", active.length, policy.max_active_resources, active.length <= policy.max_active_resources),
    result("max_provider_fanout", providers.length, policy.max_provider_fanout, providers.length <= policy.max_provider_fanout),
    result("max_destination_fanout", destinations.length, policy.max_destination_fanout, destinations.length <= policy.max_destination_fanout),
    result("max_failures", failures, policy.max_failures, failures <= policy.max_failures),
    result("max_calls", calls, policy.max_calls, calls <= policy.max_calls),
  ];
  const failed = constraints.filter((entry) => !entry.satisfied).map((entry) => entry.constraint_id);
  const semantic = sortedUnique(candidate.semantic_risk_evidence_refs || []);
  const decision = failed.length > 0 ? "deny" : semantic.length > 0 ? "step_up_required" : "admit";
  const reasonCodes = failed.length > 0 ? failed.map((name) => `trajectory_${name}_exceeded`) : semantic.length > 0 ? ["semantic_risk_requires_step_up"] : ["trajectory_within_policy"];
  let stateAfter = state;
  if (decision === "admit") {
    const event = { ref: candidate.candidate_operation_ref, hash: candidate.candidate_operation_hash };
    stateAfter = sealTrajectoryState({
      ...state,
      cumulative_spend_usd: spend,
      cumulative_deposit_usd: deposit,
      active_resource_refs: active,
      provider_refs: providers,
      destination_refs: destinations,
      data_class_refs: dataClasses,
      admitted_call_count: calls,
      failed_call_count: failures,
      admitted_events: [...state.admitted_events, event],
      derived_at: now,
    });
  }
  const decisionMaterial = {
    schema_version: "ioi.foundations.trajectory-admission-decision.v1",
    candidate_operation_ref: candidate.candidate_operation_ref,
    candidate_operation_hash: candidate.candidate_operation_hash,
    state_before_ref: state.trajectory_state_ref,
    state_before_hash: state.trajectory_state_hash,
    constraint_results: constraints,
    semantic_risk_evidence_refs: semantic,
    decision,
    reason_codes: reasonCodes,
    step_up_requirement_refs: decision === "step_up_required" ? policy.step_up_requirement_refs : [],
    policy_ref: policy.policy_ref,
    policy_hash: policy.policy_hash,
    state_after_ref: stateAfter.trajectory_state_ref,
    state_after_hash: stateAfter.trajectory_state_hash,
    policy_epoch: policy.policy_epoch,
    decided_at: now,
  };
  const decisionHash = hash(decisionMaterial);
  return {
    ...decisionMaterial,
    decision_ref: `trajectory-decision://${decisionHash.slice(7, 31)}`,
    decision_hash: decisionHash,
    state_after: stateAfter,
  };
}
