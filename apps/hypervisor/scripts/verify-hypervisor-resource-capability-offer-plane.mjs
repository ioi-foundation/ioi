#!/usr/bin/env node
// Hosted ResourceOffer + CapabilityOffer + receipted eligibility held bar. Every positive
// governed decision uses the real wallet.network CallService fixture and pinned TLS/root proof.

import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
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

async function pollJson(call, path, accept, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await call("GET", path);
    if (accept(last)) return last;
    await delay(200);
  }
  return last;
}

const ROOM = {
  owner_or_sponsor_ref: "org://acme", objective_ref: "goal://offer-match-program",
  objective: "Match participant-backed offers to bounded room work.", room_mode: "open_challenge",
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
  if (!approval?.policy_hash || !approval?.request_hash) return { challenge, response: challenge, grant: null };
  const grant = resolver.mint(principal, approval.policy_hash, approval.request_hash);
  const response = await call("POST", path, { ...body, wallet_approval_grant: grant });
  return { challenge, response, grant };
}

async function admitParticipant(call, resolver, roomRef) {
  const submitted = await call("POST", "/v1/hypervisor/room-participation-requests", {
    outcome_room_ref: roomRef, requested_by_ref: "worker://independent-alloy-lab",
    coordination_topology: "hosted_admission", admission_owner_ref: "domain://acme-host",
    operator_and_home_domain_refs: ["org://lab", "domain://lab.example"],
    worker_composition_and_dependency_refs: ["worker://bounded-worker", "runtime://rt-ab"],
    capability_offer_refs: ["ai://cap-ab"],
    affiliation_and_independent_operation_evidence_refs: ["evidence://independent"],
    eligibility_evidence_refs: ["evidence://ev-ab"],
    accepted_verifier_settlement_dispute_and_contribution_policy_refs: ["policy://contribution-v1"],
  });
  const request = submitted.body.participation_request;
  const path = `/v1/hypervisor/room-participation-requests/${request.participation_request_id.replace("participation-request://", "")}/admit`;
  const admitted = await governed(call, resolver, "domain://acme-host", path, {
    admitted_role: "resource_provider", operator_ref: "org://lab",
    home_domain_ref: "agentgres://domain/lab", expected_revision: 1,
  });
  if (admitted.response.status !== 200) throw new Error(JSON.stringify(admitted.response));
  return admitted.response.body.participant_lease;
}

const resourceOfferBody = (roomRef, participantRef, overrides = {}) => ({
  outcome_room_ref: roomRef, provider_or_participant_ref: participantRef,
  resource_profile_ref: "resource://pool/offer-pool", capacity_and_availability_ref: "capacity://pool/offer-pool",
  locality_and_custody_refs: ["region://local"], trust_and_assurance_refs: ["evidence://ev-ab"],
  cost_ref: null, eligible_work_classes: ["task"], policy_constraint_refs: ["policy://no-pii"],
  allocation_policy_ref: "policy://allocation-v1", queue_preemption_and_fairness_policy_ref: "policy://fair-v1",
  expires_at: null, coordination_topology: "hosted_admission", expected_revision: 0, ...overrides,
});

const capabilityOfferBody = (roomRef, participantRef, overrides = {}) => ({
  outcome_room_ref: roomRef, provider_or_participant_ref: participantRef, participant_ref: participantRef,
  capability_descriptor_refs: ["capability://advertised/ai/cap-ab"], eligible_frontier_classes: ["task"],
  model_harness_tool_and_connector_refs: [], authority_and_context_requirements: [],
  privacy_cost_quality_and_latency_refs: ["benchmark://cap-ab"], availability_ref: null,
  coordination_topology: "hosted_admission", expected_revision: 0, ...overrides,
});

async function run() {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-offer-match-"));
  let plane;
  try {
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const room = (await call("POST", "/v1/hypervisor/outcome-rooms", ROOM)).body.outcome_room;
    const roomRef = room.outcome_room_id;
    const roomTail = roomRef.replace("outcome-room://", "");
    const lease = await admitParticipant(call, resolver, roomRef);
    ok("PARTICIPANT: real-wallet hosted admission is active", lease.status === "active", lease.status);

    const pool = await call("POST", "/v1/hypervisor/resource/pools", {
      pool_id: "offer-pool", name: "Offer pool", provider: lease.participant_ref,
      capacity: { cpu: 8, memory_mb: 16384, storage_mb: 100000, gpu: 0 },
    });
    ok("INVENTORY: resource profile resolves to provider-owned pool", pool.body.pool?.provider === lease.participant_ref);

    const resourcePath = "/v1/hypervisor/resource-offers";
    const resourceInput = resourceOfferBody(roomRef, lease.participant_lease_id);
    const resource = await governed(call, resolver, lease.participant_ref, resourcePath, resourceInput);
    ok("RESOURCE: participant publishes canonical inventory-backed offer", resource.response.status === 201 && /^resource-offer:\/\/rof_[0-9a-f]{64}$/.test(resource.response.body.offer?.resource_offer_id), `${resource.response.status}/${resource.response.body.error?.code || "ok"}`);
    const resourceOffer = resource.response.body.offer;
    ok("RESOURCE: receipt proves no allocation or execution grant", resource.response.body.offer_receipt?.bound_facts?.allocation_created === false && resource.response.body.offer_receipt?.bound_facts?.execution_authority_granted === false && names(dataDir, "allocation-decisions").length === 0);

    const capabilityPath = "/v1/hypervisor/capability-offers";
    const capabilityInput = capabilityOfferBody(roomRef, lease.participant_lease_id);
    const capabilityChallenge = await call("POST", capabilityPath, capabilityInput);
    const capabilityGrant = resolver.mint(lease.participant_ref, capabilityChallenge.body.error.approval.policy_hash, capabilityChallenge.body.error.approval.request_hash);
    const bodySwap = await call("POST", capabilityPath, { ...capabilityInput, eligible_frontier_classes: ["review_need"], wallet_approval_grant: capabilityGrant });
    ok("AUTHORITY: offer body swap at one revision refuses", bodySwap.status === 403 && bodySwap.body.error?.code === "capability_offer_participant_authority_required", `${bodySwap.status}/${bodySwap.body.error?.code}`);
    const capability = await call("POST", capabilityPath, { ...capabilityInput, wallet_approval_grant: capabilityGrant });
    const capabilityOffer = capability.body.offer;
    ok("CAPABILITY: participant publishes exact advertised capability", capability.status === 201 && /^capability-offer:\/\/cof_[0-9a-f]{64}$/.test(capabilityOffer?.capability_offer_id), `${capability.status}/${capability.body.error?.code || "ok"}`);

    const roomLive = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const frontierResult = await governed(call, resolver, "domain://acme-host", "/v1/hypervisor/work-frontier-items", {
      outcome_room_ref: roomRef, item_kind: "task", objective: "Use the offered capability and pool.",
      dependency_refs: [], related_attempt_and_finding_refs: [], required_capability_refs: ["capability://advertised/ai/cap-ab"],
      required_context_resource_authority_and_evidence_refs: ["resource://pool/offer-pool", "evidence://ev-ab"],
      expected_value: 10, uncertainty: 0.1, priority: 100, duplication_policy: "exclusive", claimability: "open",
      max_concurrency: 1, expires_at: null, stop_condition_ref: "policy://done",
      coordination_topology: "hosted_admission", expected_revision: roomLive.revision,
    });
    const frontier = frontierResult.response.body.frontier_item;
    if (!frontier) throw new Error(`frontier creation failed: ${JSON.stringify(frontierResult.response)}`);
    ok("FRONTIER: requirement-bearing item is admitted", frontier.required_capability_refs.length === 1 && frontier.required_context_resource_authority_and_evidence_refs.length === 2);

    const matchInput = {
      outcome_room_ref: roomRef, frontier_item_ref: frontier.frontier_item_id,
      participant_ref: lease.participant_lease_id, resource_offer_refs: [resourceOffer.resource_offer_id],
      capability_offer_refs: [capabilityOffer.capability_offer_id], context_lease_refs: [],
      authority_resource_compute_data_budget_and_tool_lease_refs: [], coordination_topology: "hosted_admission",
      expected_revision: frontier.revision,
    };
    const match = await governed(call, resolver, "domain://acme-host", "/v1/hypervisor/work-eligibility-matches", matchInput);
    const matchReceipt = match.response.body.eligibility_match_receipt;
    ok("MATCH: host admits exact complete requirement coverage", match.response.status === 201 && matchReceipt?.bound_facts?.requirement_coverage?.length === 3, `${match.response.status}/${match.response.body.error?.code || "ok"}`);
    ok("MATCH: receipt explicitly creates no allocation, execution authority, or claim", matchReceipt?.bound_facts?.allocation_created === false && matchReceipt?.bound_facts?.execution_authority_granted === false && matchReceipt?.bound_facts?.claim_created === false && names(dataDir, "work-claim-leases").length === 0);
    const receiptsBeforeRepeat = names(dataDir, "resource-capability-offer-receipts").length;
    const repeatedMatch = await governed(call, resolver, "domain://acme-host", "/v1/hypervisor/work-eligibility-matches", matchInput);
    ok(
      "MATCH: an identical authorized retry is idempotent and appends no competing receipt",
      repeatedMatch.response.status === 200
        && repeatedMatch.response.body.idempotent === true
        && repeatedMatch.response.body.eligibility_match_receipt?.receipt_ref === matchReceipt.receipt_ref
        && names(dataDir, "resource-capability-offer-receipts").length === receiptsBeforeRepeat,
      `${repeatedMatch.response.status}/${repeatedMatch.response.body.error?.code || "ok"}`,
    );

    const claimInput = {
      outcome_room_ref: roomRef, frontier_item_ref: frontier.frontier_item_id, claimant_ref: lease.participant_lease_id,
      eligibility_match_receipt_ref: matchReceipt.receipt_ref, bounded_scope_ref: "task://offered-work",
      context_lease_refs: [], authority_resource_compute_data_budget_and_tool_lease_refs: [],
      duplicate_work_policy: "exclusive", heartbeat_ref: null, ttl_seconds: 600,
      coordination_topology: "hosted_admission", expected_revision: lease.revision,
    };
    const claim = await governed(call, resolver, lease.participant_ref, "/v1/hypervisor/work-claim-leases", claimInput);
    ok("CLAIM: requirement-bearing frontier admits from reauthenticated exact match", claim.response.status === 201 && claim.response.body.work_claim?.eligibility_match_receipt_ref === matchReceipt.receipt_ref, `${claim.response.status}/${claim.response.body.error?.code || "ok"}`);
    const workClaim = claim.response.body.work_claim;

    const claimTail = workClaim.work_claim_id.replace("work-claim://", "");
    const release = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/work-claim-leases/${claimTail}/transition`, {
      transition: "release", reason: "eligibility journey complete", expected_revision: workClaim.revision,
    });
    ok("CLAIM: release preserves lineage and clears current claim", release.response.status === 200 && release.response.body.work_claim?.status === "released", `${release.response.status}/${release.response.body.error?.code || "ok"}`);

    const capabilityTail = capabilityOffer.capability_offer_id.replace("capability-offer://", "");
    const frontierAfterRelease = release.response.body.frontier_item;
    const leaseAfterRelease = (await call("GET", `/v1/hypervisor/room-participant-leases/${lease.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
    const rematch = await governed(call, resolver, "domain://acme-host", "/v1/hypervisor/work-eligibility-matches", {
      ...matchInput, expected_revision: frontierAfterRelease.revision,
    });
    const staleCandidateInput = {
      ...claimInput,
      eligibility_match_receipt_ref: rematch.response.body.eligibility_match_receipt?.receipt_ref,
      expected_revision: leaseAfterRelease.revision,
    };
    const withdrawnCapability = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/capability-offers/${capabilityTail}/transition`, { transition: "withdraw", expected_revision: capabilityOffer.revision });
    const staleClaim = await call("POST", "/v1/hypervisor/work-claim-leases", staleCandidateInput);
    ok("MATCH: withdrawn offer makes old receipt stale with zero new claim", withdrawnCapability.response.status === 200 && staleClaim.status === 409 && staleClaim.body.error?.code === "work_claim_eligibility_stale" && names(dataDir, "work-claim-leases").length === 1, `${staleClaim.status}/${staleClaim.body.error?.code}`);

    const resourceTail = resourceOffer.resource_offer_id.replace("resource-offer://", "");
    const withdrawnResource = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/resource-offers/${resourceTail}/transition`, { transition: "withdraw", expected_revision: resourceOffer.revision });
    ok("OFFERS: participant withdrawal is receipted without allocation", withdrawnResource.response.status === 200 && withdrawnResource.response.body.offer?.status === "withdrawn" && names(dataDir, "allocation-decisions").length === 0);

    const unreadableInput = capabilityOfferBody(roomRef, lease.participant_lease_id, { eligible_frontier_classes: ["review_need"] });
    const unreadableChallenge = await call("POST", capabilityPath, unreadableInput);
    const subject = String(unreadableChallenge.body.error?.message || "").match(/'(capability-offer:\/\/[^']+)'/)?.[1];
    const roomSlot = join(dataDir, "outcome-room-registry", `${roomTail}.json`);
    const roomBefore = readFileSync(roomSlot, "utf8");
    if (subject) mkdirSync(join(dataDir, "capability-offers", `${subject.replace("capability-offer://", "")}.json`), { recursive: true });
    const unreadableGrant = resolver.mint(lease.participant_ref, unreadableChallenge.body.error.approval.policy_hash, unreadableChallenge.body.error.approval.request_hash);
    const unreadable = await call("POST", capabilityPath, { ...unreadableInput, wallet_approval_grant: unreadableGrant });
    ok("STORAGE: unreadable occupied offer slot is typed uncertainty with zero room mutation", unreadable.status === 500 && unreadable.body.error?.code === "offer_registry_unreadable" && readFileSync(roomSlot, "utf8") === roomBefore, `${unreadable.status}/${unreadable.body.error?.code}`);
    if (subject) rmSync(join(dataDir, "capability-offers", `${subject.replace("capability-offer://", "")}.json`), { recursive: true, force: true });

    // Force the append-only receipt boundary after the complete successor, authority tuple, and
    // touched aggregate set have been sealed. A clean restart must reconstruct those exact bytes;
    // it may not mint a replacement decision from copied receipt fields.
    await plane.stop();
    plane = await startIsolatedPlane({
      serve: false,
      env: { ...resolver.env, IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "resource-capability-offer-receipts" },
      dataDir,
    });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const restartInput = capabilityOfferBody(roomRef, lease.participant_lease_id, {
      eligible_frontier_classes: ["review_need"],
    });
    const restartChallenge = await call("POST", capabilityPath, restartInput);
    const restartGrant = resolver.mint(
      lease.participant_ref,
      restartChallenge.body.error.approval.policy_hash,
      restartChallenge.body.error.approval.request_hash,
    );
    const pendingRestart = await call("POST", capabilityPath, {
      ...restartInput,
      wallet_approval_grant: restartGrant,
    });
    const pendingIntentName = names(dataDir, "resource-capability-offer-intents")[0];
    const pendingIntent = pendingIntentName
      ? JSON.parse(readFileSync(join(dataDir, "resource-capability-offer-intents", pendingIntentName), "utf8"))
      : null;
    ok(
      "FAULT: receipt durability failure returns typed pending with the exact authority tuple retained",
      pendingRestart.status === 500
        && pendingRestart.body.error?.code === "offer_pending_convergence"
        && pendingIntent?.receipt?.wallet_approval_grant?.approver_sig
        && pendingIntent?.receipt?.principal_authority_binding?.required_scope === "capability_offer.create",
      `${pendingRestart.status}/${pendingRestart.body.error?.code}`,
    );
    await plane.stop();
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const restartOfferRef = pendingIntent?.subject_ref;
    const restartTail = restartOfferRef?.replace("capability-offer://", "");
    const convergedRestart = restartTail
      ? await pollJson(
          call,
          `/v1/hypervisor/capability-offers/${restartTail}`,
          (result) => result.status === 200,
        )
      : null;
    const replayedOffer = restartTail
      ? JSON.parse(readFileSync(join(dataDir, "capability-offers", `${restartTail}.json`), "utf8"))
      : null;
    const replayedReceipt = pendingIntent?.receipt_tail
      ? JSON.parse(readFileSync(join(dataDir, "resource-capability-offer-receipts", `${pendingIntent.receipt_tail}.json`), "utf8"))
      : null;
    ok(
      "RESTART: boot reauthorizes and converges the sealed offer and receipt byte-exactly",
      convergedRestart?.status === 200
        && JSON.stringify(replayedOffer) === JSON.stringify(pendingIntent?.final_offer)
        && JSON.stringify(replayedReceipt) === JSON.stringify(pendingIntent?.receipt)
        && names(dataDir, "resource-capability-offer-intents").length === 0,
      `${convergedRestart?.status || "missing"}/intents=${names(dataDir, "resource-capability-offer-intents").length}`,
    );
    const withdrawnRestart = restartTail
      ? await governed(
          call,
          resolver,
          lease.participant_ref,
          `/v1/hypervisor/capability-offers/${restartTail}/transition`,
          { transition: "withdraw", expected_revision: replayedOffer?.revision },
        )
      : null;
    ok(
      "RESTART: converged offer remains governable and can be withdrawn before room close",
      withdrawnRestart?.response.status === 200 && withdrawnRestart.response.body.offer?.status === "withdrawn",
      `${withdrawnRestart?.response.status || "missing"}/${withdrawnRestart?.response.body.error?.code || "ok"}`,
    );

    const frontierTail = frontier.frontier_item_id.replace("frontier://", "");
    const closedFrontier = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/work-frontier-items/${frontierTail}/transition`, { transition: "close", expected_revision: release.response.body.frontier_item.revision });
    const leaseLive = (await call("GET", `/v1/hypervisor/room-participant-leases/${lease.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
    const retired = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/room-participant-leases/${lease.participant_lease_id.replace("participant-lease://", "")}/transition`, { transition: "retire", expected_revision: leaseLive.revision });
    const beforeClose = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const closedRoom = await call("POST", `/v1/hypervisor/outcome-rooms/${roomTail}/transition`, { transition: "close", expected_revision: beforeClose.revision });
    ok("ROOM: close succeeds after offers withdraw, work closes, and participant retires", closedFrontier.response.status === 200 && retired.response.status === 200 && closedRoom.status === 200, `${closedFrontier.response.status}/${retired.response.status}/${closedRoom.status}`);

    const overview = await call("GET", "/v1/hypervisor/work-eligibility-matches/overview");
    ok("OVERVIEW: authority is configured without claiming reachability", overview.body.authority?.status === "configured" && overview.body.authority?.reachability === "not_probed" && overview.body.allocation_created === false);
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
