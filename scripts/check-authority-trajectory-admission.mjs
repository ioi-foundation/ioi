#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const enginePath = join(repo, "apps/hypervisor/scripts/lib/authority-trajectory-admission.mjs");
const sha = (character) => `sha256:${character.repeat(64)}`;

async function probe(engine) {
  const failures = [];
  const now = "2026-08-22T10:00:00Z";
  const root = "standing-envelope://acme/root";
  const state = engine.initialTrajectoryState({
    owner_ref: "org://acme",
    bounded_system_ref: "system://acme/research",
    principal_ref: "agentgres://acme/worker",
    envelope_ancestor_refs: [root],
    revocation_epoch: 1,
    window_started_at: now,
    window_ends_at: "2026-08-23T10:00:00Z",
    now,
  });
  const policy = {
    policy_ref: "policy://acme/trajectory/1",
    policy_hash: sha("a"),
    policy_epoch: 1,
    max_cumulative_spend_usd: 1,
    max_cumulative_deposit_usd: 1,
    max_active_resources: 1,
    max_provider_fanout: 1,
    max_destination_fanout: 1,
    max_failures: 0,
    max_calls: 1,
    step_up_requirement_refs: ["factor://acme/passkey"],
  };
  const candidate = {
    candidate_operation_ref: "provider-operation://candidate/1",
    candidate_operation_hash: sha("b"),
    owner_ref: state.owner_ref,
    bounded_system_ref: state.bounded_system_ref,
    principal_ref: state.principal_ref,
    envelope_ancestor_refs: [root],
    revocation_epoch: 1,
    provider_ref: "provider://akash/one",
    resource_ref: "provider-resource://akash/one",
    destination_refs: ["connector://approved/result"],
    data_class_refs: ["data-class://benchmark/public"],
    deposit_reservation_usd: 1,
    spend_reservation_usd: 2,
    opens_resource: true,
    failed: false,
    semantic_risk_evidence_refs: [],
  };
  const overshoot = engine.admitTrajectory({ state, expected_state_hash: state.trajectory_state_hash, candidate, policy, now });
  if (overshoot.decision !== "deny") failures.push("spend_overshoot_admitted");
  const staleCandidate = { ...candidate, deposit_reservation_usd: 1, spend_reservation_usd: 1 };
  const stale = engine.admitTrajectory({ state, expected_state_hash: sha("f"), candidate: staleCandidate, policy, now });
  if (stale.decision !== "deny" || !stale.reason_codes.includes("trajectory_state_conflict")) failures.push("stale_state_admitted");
  const semantic = engine.admitTrajectory({
    state,
    expected_state_hash: state.trajectory_state_hash,
    candidate: { ...staleCandidate, semantic_risk_evidence_refs: ["risk-evidence://novel"] },
    policy,
    now,
  });
  if (semantic.decision !== "step_up_required") failures.push("semantic_signal_admitted");
  return failures;
}

const baseline = await import(`${pathToFileURL(enginePath)}?baseline=${Date.now()}`);
const baselineFailures = await probe(baseline);
if (baselineFailures.length > 0) {
  console.error(JSON.stringify({ check: "check:authority-trajectory-admission", verdict: "FAIL", failures: baselineFailures }, null, 2));
  process.exit(1);
}

if (process.argv.includes("--mutation")) {
  const source = readFileSync(enginePath, "utf8");
  const mutations = [
    {
      name: "cumulative_spend_ceiling_removed",
      expected: "spend_overshoot_admitted",
      source: source.replace("spend <= policy.max_cumulative_spend_usd", "true"),
    },
    {
      name: "optimistic_state_hash_removed",
      expected: "stale_state_admitted",
      source: source.replace("expected_state_hash !== state.trajectory_state_hash", "false"),
    },
    {
      name: "semantic_step_up_promoted_to_admit",
      expected: "semantic_signal_admitted",
      source: source.replace('semantic.length > 0 ? "step_up_required" : "admit"', 'semantic.length > 0 ? "admit" : "admit"'),
    },
  ];
  const survived = [];
  for (const mutation of mutations) {
    const encoded = Buffer.from(mutation.source).toString("base64");
    const mutated = await import(`data:text/javascript;base64,${encoded}#${mutation.name}`);
    const failures = await probe(mutated);
    if (!failures.includes(mutation.expected)) survived.push({ name: mutation.name, expected: mutation.expected, failures });
  }
  if (survived.length > 0) {
    console.error(JSON.stringify({ check: "mutate:authority-trajectory-admission", verdict: "FAIL", survived }, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify({
    check: "mutate:authority-trajectory-admission",
    verdict: "PASS",
    mutations: mutations.map(({ name, expected }) => ({ name, detected_by: expected })),
  }, null, 2));
} else {
  console.log(JSON.stringify({
    check: "check:authority-trajectory-admission",
    verdict: "PASS",
    properties: ["aggregate bounds", "optimistic state hash", "semantic evidence cannot admit"],
  }, null, 2));
}
