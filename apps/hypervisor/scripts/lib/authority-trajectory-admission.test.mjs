import assert from "node:assert/strict";
import test from "node:test";
import { admitTrajectory, initialTrajectoryState } from "./authority-trajectory-admission.mjs";

const sha = (character) => `sha256:${character.repeat(64)}`;
const now = "2026-08-22T10:00:00Z";
const envelope = "standing-envelope://acme/system/root";
const childA = "standing-envelope://acme/system/child-a";
const childB = "standing-envelope://acme/system/child-b";
const base = () => initialTrajectoryState({
  owner_ref: "org://acme",
  bounded_system_ref: "system://acme/research",
  principal_ref: "agentgres://acme/worker",
  envelope_ancestor_refs: [envelope, childA, childB],
  revocation_epoch: 1,
  window_started_at: now,
  window_ends_at: "2026-08-23T10:00:00Z",
  now,
});
const policy = {
  policy_ref: "policy://acme/trajectory/1",
  policy_hash: sha("a"),
  policy_epoch: 1,
  max_cumulative_spend_usd: 4,
  max_cumulative_deposit_usd: 4,
  max_active_resources: 4,
  max_provider_fanout: 2,
  max_destination_fanout: 2,
  max_failures: 2,
  max_calls: 40,
  step_up_requirement_refs: ["factor://acme/passkey"],
};
const candidate = (index, overrides = {}) => ({
  candidate_operation_ref: `provider-operation://candidate/${index}`,
  candidate_operation_hash: sha((index % 9 + 1).toString()),
  owner_ref: "org://acme",
  bounded_system_ref: "system://acme/research",
  principal_ref: "agentgres://acme/worker",
  envelope_ancestor_refs: [envelope, childA],
  revocation_epoch: 1,
  provider_ref: `provider://akash/${index % 2}`,
  resource_ref: `provider-resource://akash/${index}`,
  destination_refs: ["connector://approved/result"],
  data_class_refs: ["data-class://benchmark/public"],
  deposit_reservation_usd: 1,
  spend_reservation_usd: 1,
  opens_resource: true,
  failed: false,
  semantic_risk_evidence_refs: [],
  ...overrides,
});

test("cross-provider and descendant splitting cannot cross aggregate bounds", () => {
  let state = base();
  for (let index = 0; index < 4; index += 1) {
    const admitted = admitTrajectory({ state, expected_state_hash: state.trajectory_state_hash, candidate: candidate(index, { envelope_ancestor_refs: [envelope, index % 2 === 0 ? childA : childB] }), policy, now });
    assert.equal(admitted.decision, "admit");
    state = admitted.state_after;
  }
  const refused = admitTrajectory({ state, expected_state_hash: state.trajectory_state_hash, candidate: candidate(5, { envelope_ancestor_refs: [envelope, childB] }), policy, now });
  assert.equal(refused.decision, "deny");
  assert.ok(refused.reason_codes.includes("trajectory_max_cumulative_spend_usd_exceeded"));
  assert.equal(refused.state_after.trajectory_state_hash, state.trajectory_state_hash);
});

test("provider fanout and destination convergence refuse before effect", () => {
  let state = base();
  for (let index = 0; index < 2; index += 1) {
    const admitted = admitTrajectory({ state, expected_state_hash: state.trajectory_state_hash, candidate: candidate(index), policy, now });
    state = admitted.state_after;
  }
  const provider = admitTrajectory({ state, expected_state_hash: state.trajectory_state_hash, candidate: candidate(3, { provider_ref: "provider://akash/third" }), policy, now });
  assert.equal(provider.decision, "deny");
  assert.ok(provider.reason_codes.includes("trajectory_max_provider_fanout_exceeded"));
  const destination = admitTrajectory({ state, expected_state_hash: state.trajectory_state_hash, candidate: candidate(4, { destination_refs: ["connector://new/a", "connector://new/b"] }), policy, now });
  assert.equal(destination.decision, "deny");
  assert.ok(destination.reason_codes.includes("trajectory_max_destination_fanout_exceeded"));
});

test("stale state and semantic evidence never admit or widen", () => {
  const state = base();
  const stale = admitTrajectory({ state, expected_state_hash: sha("f"), candidate: candidate(1), policy, now });
  assert.deepEqual(stale.reason_codes, ["trajectory_state_conflict"]);
  const semantic = admitTrajectory({ state, expected_state_hash: state.trajectory_state_hash, candidate: candidate(1, { semantic_risk_evidence_refs: ["risk-evidence://novel-destination"] }), policy, now });
  assert.equal(semantic.decision, "step_up_required");
  assert.equal(semantic.state_after.trajectory_state_hash, state.trajectory_state_hash);
});
