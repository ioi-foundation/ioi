#!/usr/bin/env node
// Adversarial eligibility held bar. Uses the real wallet.network CallService fixture and a
// fresh isolated daemon so proof-unavailable and expiry lanes do not extend the lifecycle
// verifier beyond the fixture service lifetime.

import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const results = [];
const ok = (name, pass, detail = "") => {
  results.push({ name, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}: ${name}${detail ? ` — ${detail}` : ""}`);
};
const names = (dir, family) => {
  try { return readdirSync(join(dir, family)).filter((name) => name.endsWith(".json")).sort(); }
  catch { return []; }
};
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const ROOM = {
  owner_or_sponsor_ref: "org://acme", objective_ref: "goal://eligibility-regressions",
  objective: "Refuse unsupported offer prerequisites and expired offer authority.", room_mode: "open_challenge",
  coordination_topology: "hosted_admission", stop_policy_ref: "policy://stop-on-budget",
  visibility_policy_ref: "policy://team-visible", participation_policy_ref: "policy://eligibility",
  privacy_policy_ref: "policy://no-pii", contribution_policy_ref: "policy://contribution-v1",
  coordination_policy_ref: "policy://coordination-v1", ordering_and_merge_policy_ref: "policy://ordered-admission",
  conflict_and_failover_policy_ref: "policy://host-failover", host_domain_ref: "domain://acme-host",
};

async function jsonCall(base, method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method, headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function governed(call, resolver, principal, path, body) {
  const challenge = await call("POST", path, body);
  const approval = challenge.body.error?.approval;
  if (!approval?.policy_hash || !approval?.request_hash) return { challenge, response: challenge };
  const wallet_approval_grant = resolver.mint(principal, approval.policy_hash, approval.request_hash);
  const response = await call("POST", path, { ...body, wallet_approval_grant });
  return { challenge, response };
}

async function admitParticipant(call, resolver, roomRef) {
  const submitted = await call("POST", "/v1/hypervisor/room-participation-requests", {
    outcome_room_ref: roomRef, requested_by_ref: "worker://independent-alloy-lab",
    coordination_topology: "hosted_admission", admission_owner_ref: "domain://acme-host",
    operator_and_home_domain_refs: ["org://lab", "domain://lab.example"],
    worker_composition_and_dependency_refs: ["worker://bounded-worker", "runtime://rt-ab"],
    capability_offer_refs: ["ai://cap-ab"], affiliation_and_independent_operation_evidence_refs: ["evidence://independent"],
    eligibility_evidence_refs: ["evidence://ev-ab"],
    accepted_verifier_settlement_dispute_and_contribution_policy_refs: ["policy://contribution-v1"],
  });
  const request = submitted.body.participation_request;
  const tail = request.participation_request_id.replace("participation-request://", "");
  const admitted = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/room-participation-requests/${tail}/admit`, {
    admitted_role: "resource_provider", operator_ref: "org://lab",
    home_domain_ref: "agentgres://domain/lab", expected_revision: 1,
  });
  if (admitted.response.status !== 200) throw new Error(JSON.stringify(admitted.response));
  return admitted.response.body.participant_lease;
}

const resourceBody = (roomRef, participantRef, overrides = {}) => ({
  outcome_room_ref: roomRef, provider_or_participant_ref: participantRef,
  resource_profile_ref: "resource://pool/eligibility-pool", capacity_and_availability_ref: "capacity://pool/eligibility-pool",
  locality_and_custody_refs: ["region://local"], trust_and_assurance_refs: ["evidence://ev-ab"],
  cost_ref: null, eligible_work_classes: ["task"], policy_constraint_refs: [],
  allocation_policy_ref: "policy://allocation-v1", queue_preemption_and_fairness_policy_ref: "policy://fair-v1",
  expires_at: null, coordination_topology: "hosted_admission", expected_revision: 0, ...overrides,
});

const capabilityBody = (roomRef, participantRef, overrides = {}) => ({
  outcome_room_ref: roomRef, provider_or_participant_ref: participantRef, participant_ref: participantRef,
  capability_descriptor_refs: ["capability://advertised/ai/cap-ab"], eligible_frontier_classes: ["task"],
  model_harness_tool_and_connector_refs: [], authority_and_context_requirements: [],
  privacy_cost_quality_and_latency_refs: ["benchmark://cap-ab"], availability_ref: null,
  coordination_topology: "hosted_admission", expected_revision: 0, ...overrides,
});

async function run() {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-offer-eligibility-regressions-"));
  let plane;
  try {
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const room = (await call("POST", "/v1/hypervisor/outcome-rooms", ROOM)).body.outcome_room;
    const roomRef = room.outcome_room_id;
    const roomTail = roomRef.replace("outcome-room://", "");
    const lease = await admitParticipant(call, resolver, roomRef);
    const pool = await call("POST", "/v1/hypervisor/resource/pools", {
      pool_id: "eligibility-pool", name: "Eligibility pool", provider: lease.participant_ref,
      capacity: { cpu: 8, memory_mb: 16384, storage_mb: 100000, gpu: 0 },
    });
    if (pool.status !== 200 || pool.body.pool?.provider !== lease.participant_ref) {
      throw new Error(JSON.stringify(pool));
    }

    const resourcePath = "/v1/hypervisor/resource-offers";
    const capabilityPath = "/v1/hypervisor/capability-offers";
    const cleanResource = await governed(call, resolver, lease.participant_ref, resourcePath, resourceBody(roomRef, lease.participant_lease_id));
    const policyResource = await governed(call, resolver, lease.participant_ref, resourcePath, resourceBody(roomRef, lease.participant_lease_id, {
      policy_constraint_refs: ["policy://no-pii"],
    }));
    const cleanCapability = await governed(call, resolver, lease.participant_ref, capabilityPath, capabilityBody(roomRef, lease.participant_lease_id));
    const scopedCapability = await governed(call, resolver, lease.participant_ref, capabilityPath, capabilityBody(roomRef, lease.participant_lease_id, {
      authority_and_context_requirements: ["scope:unresolved-capability-authority"],
    }));
    for (const result of [cleanResource, policyResource, cleanCapability, scopedCapability]) {
      if (result.response.status !== 201) throw new Error(JSON.stringify(result.response));
    }

    const roomLive = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const frontierResult = await governed(call, resolver, "domain://acme-host", "/v1/hypervisor/work-frontier-items", {
      outcome_room_ref: roomRef, item_kind: "task", objective: "Exercise exact offer eligibility.",
      dependency_refs: [], related_attempt_and_finding_refs: [], required_capability_refs: ["capability://advertised/ai/cap-ab"],
      required_context_resource_authority_and_evidence_refs: ["resource://pool/eligibility-pool", "evidence://ev-ab"],
      expected_value: 10, uncertainty: 0.1, priority: 100, duplication_policy: "exclusive", claimability: "open",
      max_concurrency: 1, expires_at: null, stop_condition_ref: "policy://done",
      coordination_topology: "hosted_admission", expected_revision: roomLive.revision,
    });
    const frontier = frontierResult.response.body.frontier_item;
    if (!frontier) throw new Error(JSON.stringify(frontierResult.response));

    const baseMatch = {
      outcome_room_ref: roomRef, frontier_item_ref: frontier.frontier_item_id,
      participant_ref: lease.participant_lease_id,
      resource_offer_refs: [cleanResource.response.body.offer.resource_offer_id],
      capability_offer_refs: [cleanCapability.response.body.offer.capability_offer_id],
      context_lease_refs: [], authority_resource_compute_data_budget_and_tool_lease_refs: [],
      coordination_topology: "hosted_admission", expected_revision: frontier.revision,
    };
    const receiptsBefore = names(dataDir, "resource-capability-offer-receipts").length;
    const scoped = await call("POST", "/v1/hypervisor/work-eligibility-matches", {
      ...baseMatch, capability_offer_refs: [scopedCapability.response.body.offer.capability_offer_id],
    });
    ok(
      "ELIGIBILITY: unresolved capability scope refuses with zero match/claim mutation",
      scoped.status === 501 && scoped.body.error?.code === "work_eligibility_requirement_proof_unavailable"
        && names(dataDir, "resource-capability-offer-receipts").length === receiptsBefore
        && names(dataDir, "work-claim-leases").length === 0,
      `${scoped.status}/${scoped.body.error?.code}`,
    );
    const policy = await call("POST", "/v1/hypervisor/work-eligibility-matches", {
      ...baseMatch, resource_offer_refs: [policyResource.response.body.offer.resource_offer_id],
    });
    ok(
      "ELIGIBILITY: resource policy constraint is not accepted as proof",
      policy.status === 501 && policy.body.error?.code === "work_eligibility_requirement_proof_unavailable"
        && names(dataDir, "resource-capability-offer-receipts").length === receiptsBefore
        && names(dataDir, "work-claim-leases").length === 0,
      `${policy.status}/${policy.body.error?.code}`,
    );

    const expiryAtMs = Number(frontierResult.response.body.frontier_receipt?.authority_resolved_at_ms) + 8_000;
    const expiringResource = await governed(call, resolver, lease.participant_ref, resourcePath, resourceBody(roomRef, lease.participant_lease_id, {
      expires_at: new Date(expiryAtMs).toISOString(),
    }));
    if (expiringResource.response.status !== 201) throw new Error(JSON.stringify(expiringResource.response));
    const matched = await governed(call, resolver, "domain://acme-host", "/v1/hypervisor/work-eligibility-matches", {
      ...baseMatch, resource_offer_refs: [expiringResource.response.body.offer.resource_offer_id],
    });
    const matchReceipt = matched.response.body.eligibility_match_receipt;
    if (matched.response.status !== 201 || Number(matchReceipt?.authority_resolved_at_ms) >= expiryAtMs) {
      throw new Error(`match-before-expiry precondition failed: ${JSON.stringify(matched.response)}`);
    }
    await delay(Math.max(0, expiryAtMs - Date.now() + 250));
    const claimsBefore = names(dataDir, "work-claim-leases").length;
    const claimReceiptsBefore = names(dataDir, "work-frontier-claim-receipts").length;
    const expired = await governed(call, resolver, lease.participant_ref, "/v1/hypervisor/work-claim-leases", {
      outcome_room_ref: roomRef, frontier_item_ref: frontier.frontier_item_id, claimant_ref: lease.participant_lease_id,
      eligibility_match_receipt_ref: matchReceipt.receipt_ref, bounded_scope_ref: "task://expired-offer-work",
      context_lease_refs: [], authority_resource_compute_data_budget_and_tool_lease_refs: [],
      duplicate_work_policy: "exclusive", heartbeat_ref: null, ttl_seconds: 600,
      coordination_topology: "hosted_admission", expected_revision: lease.revision,
    });
    ok(
      "ELIGIBILITY: match-before-expiry cannot authorize claim-after-expiry",
      expired.response.status === 409 && expired.response.body.error?.code === "work_claim_eligibility_offer_expired"
        && names(dataDir, "work-claim-leases").length === claimsBefore
        && names(dataDir, "work-frontier-claim-receipts").length === claimReceiptsBefore,
      `${expired.response.status}/${expired.response.body.error?.code}`,
    );
  } finally {
    if (plane) await plane.stop();
    await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

run().then(() => {
  const failed = results.filter((result) => !result.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) process.exitCode = 1;
}).catch((error) => { console.error(error?.stack || error); process.exitCode = 1; });
