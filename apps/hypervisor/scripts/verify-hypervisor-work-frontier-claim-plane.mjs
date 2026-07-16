#!/usr/bin/env node
// #76 held integration bar. Every positive governed decision traverses the real wallet.network
// CallService fixture through Hypervisor's signed capability client and pinned TLS/root proof.

import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const results = [];
const ok = (name, pass, detail = "") => {
  const result = { name, pass: !!pass, detail };
  results.push(result);
  console.log(`${result.pass ? "PASS" : "FAIL"}: ${name}${detail ? ` — ${detail}` : ""}`);
};

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const names = (dir, family) => {
  try { return readdirSync(join(dir, family)).filter((name) => name.endsWith(".json")).sort(); }
  catch { return []; }
};

async function pollJson(call, accept, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await call();
    if (accept(last)) return last;
    await delay(50);
  }
  return last;
}

async function startBlackholedRpc() {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    addr: `https://127.0.0.1:${server.address().port}`,
    async stop() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

const ROOM = {
  owner_or_sponsor_ref: "org://acme", objective_ref: "goal://frontier-program",
  objective: "Exercise a bounded hosted-room work frontier.", room_mode: "open_challenge",
  coordination_topology: "hosted_admission", stop_policy_ref: "policy://stop-on-budget",
  visibility_policy_ref: "policy://team-visible", participation_policy_ref: "policy://open-eligibility",
  privacy_policy_ref: "policy://no-pii", contribution_policy_ref: "policy://contribution-v1",
  coordination_policy_ref: "policy://coordination-v1", ordering_and_merge_policy_ref: "policy://ordered-admission",
  conflict_and_failover_policy_ref: "policy://host-failover", host_domain_ref: "domain://acme-host",
};

const requestBody = (roomRef, principal) => ({
  outcome_room_ref: roomRef, requested_by_ref: principal, coordination_topology: "hosted_admission",
  admission_owner_ref: "domain://acme-host", operator_and_home_domain_refs: ["org://lab", "domain://lab.example"],
  worker_composition_and_dependency_refs: ["worker://bounded-worker", "model_route://m1", "harness_profile:codex-local"],
  capability_offer_refs: ["capability-offer://repo"],
  affiliation_and_independent_operation_evidence_refs: ["evidence://independent"],
  eligibility_evidence_refs: ["evidence://eligible"],
  accepted_verifier_settlement_dispute_and_contribution_policy_refs: ["policy://contribution-v1"],
});

const frontierBody = (roomRef, overrides = {}) => ({
  outcome_room_ref: roomRef, item_kind: "task", objective: "Implement one bounded frontier unit.",
  dependency_refs: [], related_attempt_and_finding_refs: [], required_capability_refs: ["capability://repo-write"],
  required_context_resource_authority_and_evidence_refs: ["scope:repo.write", "resource://worktree"],
  expected_value: 10, uncertainty: 0.2, priority: 100,
  duplication_policy: "exclusive", claimability: "open", max_concurrency: 1,
  expires_at: null, stop_condition_ref: "policy://done", coordination_topology: "hosted_admission",
  ...overrides,
});

const claimBody = (roomRef, frontierRef, participantRef, overrides = {}) => ({
  outcome_room_ref: roomRef, frontier_item_ref: frontierRef, claimant_ref: participantRef,
  bounded_scope_ref: "task://frontier-unit", context_lease_refs: ["context_lease://room-context"],
  authority_resource_compute_data_budget_and_tool_lease_refs: ["grant://repo", "tool-lease://shell"],
  duplicate_work_policy: "exclusive", heartbeat_ref: null, ttl_seconds: 600,
  coordination_topology: "hosted_admission", ...overrides,
});

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

async function admitParticipant(call, resolver, roomRef, principal) {
  const submitted = await call("POST", "/v1/hypervisor/room-participation-requests", requestBody(roomRef, principal));
  const request = submitted.body.participation_request;
  const requestTail = request.participation_request_id.replace("participation-request://", "");
  const path = `/v1/hypervisor/room-participation-requests/${requestTail}/admit`;
  const body = {
    admitted_role: "implementer", operator_ref: "org://lab",
    home_domain_ref: "agentgres://domain/lab", expected_revision: 1,
  };
  const admitted = await governed(call, resolver, "domain://acme-host", path, body);
  if (admitted.response.status !== 200) {
    throw new Error(`participant admission failed: ${JSON.stringify(admitted.response)}`);
  }
  return admitted.response.body.participant_lease;
}

async function terminalParticipantWithClaim(call, resolver, lease, transition, claimRevision) {
  const leaseTail = lease.participant_lease_id.replace("participant-lease://", "");
  const path = `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`;
  const body = { transition, expected_revision: lease.revision, work_claim_expected_revision: claimRevision };
  const first = await call("POST", path, body);
  const participationGrant = resolver.mint(
    transition === "retire" ? lease.participant_ref : "domain://acme-host",
    first.body.error.approval.policy_hash,
    first.body.error.approval.request_hash,
  );
  const second = await call("POST", path, { ...body, wallet_approval_grant: participationGrant });
  const workGrant = resolver.mint(
    transition === "retire" ? lease.participant_ref : "domain://acme-host",
    second.body.error.approval.policy_hash,
    second.body.error.approval.request_hash,
  );
  return call("POST", path, {
    ...body, wallet_approval_grant: participationGrant, work_claim_wallet_approval_grant: workGrant,
  });
}

async function runDurabilityFaultLanes() {
  let resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const baseDir = mkdtempSync(join(tmpdir(), "ioi-work-frontier-fault-base-"));
  let basePlane;
  try {
    basePlane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir: baseDir });
    const baseCall = (method, path, body) => jsonCall(basePlane.daemonUrl, method, path, body);
    const room = (await baseCall("POST", "/v1/hypervisor/outcome-rooms", { ...ROOM, objective_ref: "goal://durability", objective: "Durability fault fixture." })).body.outcome_room;
    const lease = await admitParticipant(baseCall, resolver, room.outcome_room_id, "worker://independent-alloy-lab");
    const roomLive = (await baseCall("GET", `/v1/hypervisor/outcome-rooms/${room.outcome_room_id.replace("outcome-room://", "")}`)).body.outcome_room;
    const frontier = (await governed(baseCall, resolver, "domain://acme-host", "/v1/hypervisor/work-frontier-items", {
      ...frontierBody(room.outcome_room_id, { objective: "Fault one release boundary." }), expected_revision: roomLive.revision,
    })).response.body.frontier_item;
    const claim = (await governed(baseCall, resolver, lease.participant_ref, "/v1/hypervisor/work-claim-leases", {
      ...claimBody(room.outcome_room_id, frontier.frontier_item_id, lease.participant_lease_id), expected_revision: lease.revision,
    })).response.body.work_claim;
    const claimPath = `/v1/hypervisor/work-claim-leases/${claim.work_claim_id.replace("work-claim://", "")}/transition`;
    const releaseBody = { transition: "release", reason: "fault-boundary release", expected_revision: claim.revision };
    const releaseChallenge = await baseCall("POST", claimPath, releaseBody);
    const releaseGrant = resolver.mint(lease.participant_ref, releaseChallenge.body.error.approval.policy_hash, releaseChallenge.body.error.approval.request_hash);
    await basePlane.stop();
    basePlane = null;

    const releaseFaults = [
      ["intent", "work-frontier-claim-intents"],
      ["receipt", "work-frontier-claim-receipts"],
      ["participant stamp", "room-participant-leases"],
      ["frontier update", "work-frontier-items"],
    ];
    for (const [index, [label, family]] of releaseFaults.entries()) {
      const laneDir = mkdtempSync(join(tmpdir(), `ioi-work-frontier-${label.replaceAll(" ", "-")}-`));
      cpSync(baseDir, laneDir, { recursive: true });
      let lane;
      try {
        lane = await startIsolatedPlane({
          serve: false,
          env: { ...resolver.env, IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: family },
          dataDir: laneDir,
        });
        const pending = await jsonCall(lane.daemonUrl, "POST", claimPath, { ...releaseBody, wallet_approval_grant: releaseGrant });
        const intentName = names(laneDir, "work-frontier-claim-intents")[0];
        ok(`FAULT: ${label} failure returns typed pending with a durable intent`, pending.status === 500 && !!intentName && String(pending.body.error?.code || "").includes("pending_convergence"), `${pending.status}/${pending.body.error?.code}`);
        process.kill(lane.daemonPid, "SIGKILL");
        await lane.stop();
        lane = null;

        if (label === "intent") {
          const blackholeDir = mkdtempSync(join(tmpdir(), "ioi-work-frontier-blackhole-"));
          cpSync(laneDir, blackholeDir, { recursive: true });
          const intentPath = join(blackholeDir, "work-frontier-claim-intents", intentName);
          const before = readFileSync(intentPath, "utf8");
          const blackhole = await startBlackholedRpc();
          let blackholePlane;
          try {
            const started = Date.now();
            blackholePlane = await startIsolatedPlane({
              serve: false,
              env: {
                ...resolver.env,
                IOI_WALLET_NETWORK_RPC_ADDR: blackhole.addr,
                IOI_WALLET_NETWORK_RESOLUTION_TIMEOUT_MS: "5000",
                IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "6000",
              },
              dataDir: blackholeDir,
            });
            const readinessMs = Date.now() - started;
            const ready = await fetch(`${blackholePlane.daemonUrl}/readyz`);
            const overview = await jsonCall(blackholePlane.daemonUrl, "GET", "/v1/hypervisor/work-claim-leases/overview");
            const after = readFileSync(intentPath, "utf8");
            ok("READINESS: blackholed resolver cannot delay readiness, consume intent, or claim live reachability", ready.status === 200 && readinessMs < 2_500 && before === after && overview.body.pending_convergence_count === 1 && overview.body.authority?.status === "configured" && overview.body.authority?.reachability === "not_probed", `${readinessMs}ms/pending=${overview.body.pending_convergence_count}`);
          } finally {
            if (blackholePlane) await blackholePlane.stop();
            await blackhole.stop();
            rmSync(blackholeDir, { recursive: true, force: true });
          }
        }

        const sealedIntent = JSON.parse(readFileSync(join(laneDir, "work-frontier-claim-intents", intentName), "utf8"));
        lane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir: laneDir });
        const converged = await pollJson(
          () => jsonCall(lane.daemonUrl, "GET", claimPath.replace("/transition", "")),
          (response) => response.status === 200 && response.body.work_claim?.status === "released",
        );
        const finalClaim = JSON.parse(readFileSync(join(laneDir, "work-claim-leases", `${claim.work_claim_id.replace("work-claim://", "")}.json`), "utf8"));
        const finalFrontier = JSON.parse(readFileSync(join(laneDir, "work-frontier-items", `${frontier.frontier_item_id.replace("frontier://", "")}.json`), "utf8"));
        const finalParticipant = JSON.parse(readFileSync(join(laneDir, "room-participant-leases", `${lease.participant_lease_id.replace("participant-lease://", "")}.json`), "utf8"));
        const finalReceipt = JSON.parse(readFileSync(join(laneDir, "work-frontier-claim-receipts", `${sealedIntent.receipt_tail}.json`), "utf8"));
        ok(`REPLAY: ${label} fault converges every successor byte-exactly`, converged.status === 200 && names(laneDir, "work-frontier-claim-intents").length === 0 && JSON.stringify(finalClaim) === JSON.stringify(sealedIntent.final_claim) && JSON.stringify(finalFrontier) === JSON.stringify(sealedIntent.final_frontier) && JSON.stringify(finalParticipant) === JSON.stringify(sealedIntent.final_participant) && JSON.stringify(finalReceipt) === JSON.stringify(sealedIntent.receipt), `${converged.status}/intents=${names(laneDir, "work-frontier-claim-intents").length}`);
      } finally {
        if (lane) await lane.stop();
        rmSync(laneDir, { recursive: true, force: true });
      }
      if (index === 1) {
        await resolver.stop();
        resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
      }
    }

    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    const terminalDir = mkdtempSync(join(tmpdir(), "ioi-work-frontier-terminal-release-"));
    cpSync(baseDir, terminalDir, { recursive: true });
    let terminalPlane;
    try {
      terminalPlane = await startIsolatedPlane({
        serve: false,
        env: { ...resolver.env, IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "outcome-room-registry" },
        dataDir: terminalDir,
      });
      const terminalCall = (method, path, body) => jsonCall(terminalPlane.daemonUrl, method, path, body);
      const liveLease = (await terminalCall("GET", `/v1/hypervisor/room-participant-leases/${lease.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
      const pending = await terminalParticipantWithClaim(terminalCall, resolver, liveLease, "retire", claim.revision);
      const intentName = names(terminalDir, "work-frontier-claim-intents")[0];
      ok("FAULT: terminal room-release failure retains the compound work intent", pending.status === 500 && !!intentName, `${pending.status}/${pending.body.error?.code}`);
      process.kill(terminalPlane.daemonPid, "SIGKILL");
      await terminalPlane.stop();
      terminalPlane = null;
      terminalPlane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir: terminalDir });
      const participantPath = `/v1/hypervisor/room-participant-leases/${lease.participant_lease_id.replace("participant-lease://", "")}`;
      const converged = await pollJson(
        () => jsonCall(terminalPlane.daemonUrl, "GET", participantPath),
        (response) => response.body.participant_lease?.status === "retired" && response.body.participant_lease?.current_claim_ref === null && names(terminalDir, "work-frontier-claim-intents").length === 0,
      );
      const finalRoom = (await jsonCall(terminalPlane.daemonUrl, "GET", `/v1/hypervisor/outcome-rooms/${room.outcome_room_id.replace("outcome-room://", "")}`)).body.outcome_room;
      ok("REPLAY: one boot clears claim then terminal participant room slot", converged.body.participant_lease?.status === "retired" && (finalRoom.released_participant_lease_refs || []).includes(lease.participant_lease_id), `${converged.body.participant_lease?.status}/released=${(finalRoom.released_participant_lease_refs || []).includes(lease.participant_lease_id)}`);
    } finally {
      if (terminalPlane) await terminalPlane.stop();
      rmSync(terminalDir, { recursive: true, force: true });
    }
  } finally {
    if (basePlane) await basePlane.stop();
    await resolver.stop();
    rmSync(baseDir, { recursive: true, force: true });
  }
}

async function run({ includeFaults = true } = {}) {
  let resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-work-frontier-claim-"));
  let plane;
  try {
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    if (!plane) { console.log("BLOCKED: hypervisor-daemon binary not built"); process.exitCode = 2; return; }
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);

    const roomCreate = await call("POST", "/v1/hypervisor/outcome-rooms", ROOM);
    const room = roomCreate.body.outcome_room;
    const roomRef = room.outcome_room_id;
    const roomTail = roomRef.replace("outcome-room://", "");
    ok("ROOM: hosted room is admitted open", roomCreate.status === 201 && room.status === "open", `${roomCreate.status}/${room.status}`);

    const principals = ["worker://independent-alloy-lab", "worker://replication-lab-two", "worker://replication-lab-three"];
    const leases = [];
    for (const principal of principals) leases.push(await admitParticipant(call, resolver, roomRef, principal));
    const scopeLimitedLease = await admitParticipant(call, resolver, roomRef, "worker://frontier-only-lab");
    ok("PARTICIPANTS: three production-authenticated leases are active", leases.every((lease) => lease.status === "active"), leases.map((lease) => lease.status).join(","));

    let currentRoom = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const createPath = "/v1/hypervisor/work-frontier-items";
    const createInput = { ...frontierBody(roomRef), expected_revision: currentRoom.revision };
    const createChallenge = await call("POST", createPath, createInput);
    ok("AUTHORITY: frontier challenge binds host create scope", createChallenge.status === 403 && createChallenge.body.error?.required_scope === "work_frontier.create", `${createChallenge.status}/${createChallenge.body.error?.required_scope}`);
    const foreign = mintApprovalGrant({ seed: "08".repeat(32), policyHash: createChallenge.body.error.approval.policy_hash, requestHash: createChallenge.body.error.approval.request_hash });
    const foreignResponse = await call("POST", createPath, { ...createInput, wallet_approval_grant: foreign });
    ok("AUTHORITY: same-hash foreign frontier signer refuses with zero mutation", foreignResponse.status === 403 && foreignResponse.body.error?.code === "work_frontier_host_authority_required", `${foreignResponse.status}/${foreignResponse.body.error?.code}`);
    const hostCreateGrant = resolver.mint("domain://acme-host", createChallenge.body.error.approval.policy_hash, createChallenge.body.error.approval.request_hash);
    const created = await call("POST", createPath, { ...createInput, wallet_approval_grant: hostCreateGrant });
    let mainFrontier = created.body.frontier_item;
    const mainTail = mainFrontier.frontier_item_id.replace("frontier://", "");
    ok("FRONTIER: host creates canonical item and room backlink", created.status === 201 && /^frontier:\/\/wfi_[0-9a-f]{64}$/.test(mainFrontier.frontier_item_id) && mainFrontier.status === "open", `${created.status}/${mainFrontier.frontier_item_id}`);
    ok("FRONTIER: receipt retains exact scope/hash/snapshot coordinates", created.body.frontier_receipt?.principal_authority_binding?.required_scope === "work_frontier.create" && created.body.frontier_receipt?.authority_resolved_at_ms === mainFrontier.created_at_ms, `${created.body.frontier_receipt?.principal_authority_binding?.required_scope}/${created.body.frontier_receipt?.principal_authority_binding?.coordinates?.binding_version}`);

    const scopeRefusal = await governed(call, resolver, scopeLimitedLease.participant_ref, "/v1/hypervisor/work-claim-leases", {
      ...claimBody(roomRef, mainFrontier.frontier_item_id, scopeLimitedLease.participant_lease_id),
      expected_revision: scopeLimitedLease.revision,
    });
    const noScopeMutation = await call("GET", "/v1/hypervisor/work-claim-leases");
    ok("AUTHORITY: real wallet resolver refuses an authentic signer without work-claim scope", scopeRefusal.response.status === 403 && scopeRefusal.response.body.error?.code === "work_claim_authority_resolution_refused" && (noScopeMutation.body.work_claims || []).length === 0, `${scopeRefusal.response.status}/${scopeRefusal.response.body.error?.code}`);

    const otherRoomCreate = await call("POST", "/v1/hypervisor/outcome-rooms", { ...ROOM, objective_ref: "goal://cross-room-refusal", objective: "Cross-room refusal fixture." });
    const otherRoom = otherRoomCreate.body.outcome_room;
    const otherRoomTail = otherRoom.outcome_room_id.replace("outcome-room://", "");
    const crossRoom = await call("POST", "/v1/hypervisor/work-claim-leases", {
      ...claimBody(otherRoom.outcome_room_id, mainFrontier.frontier_item_id, leases[0].participant_lease_id),
      expected_revision: leases[0].revision,
    });
    const otherRoomClosed = await call("POST", `/v1/hypervisor/outcome-rooms/${otherRoomTail}/transition`, { transition: "close", expected_revision: otherRoom.revision });
    ok("INTEGRITY: cross-room claim refuses with zero mutation", crossRoom.status === 422 && otherRoomClosed.status === 200, `${crossRoom.status}/${crossRoom.body.error?.code}`);

    const inactiveTail = leases[1].participant_lease_id.replace("participant-lease://", "");
    const inactivePath = `/v1/hypervisor/room-participant-leases/${inactiveTail}/transition`;
    const slept = await governed(call, resolver, leases[1].participant_ref, inactivePath, { transition: "sleep", expected_revision: leases[1].revision });
    const sleepingLease = slept.response.body.participant_lease;
    const inactiveClaim = await call("POST", "/v1/hypervisor/work-claim-leases", {
      ...claimBody(roomRef, mainFrontier.frontier_item_id, sleepingLease.participant_lease_id),
      expected_revision: sleepingLease.revision,
    });
    const woke = await governed(call, resolver, leases[1].participant_ref, inactivePath, { transition: "wake", expected_revision: sleepingLease.revision });
    leases[1] = woke.response.body.participant_lease;
    ok("INTEGRITY: inactive participant refuses before authority with zero claim", inactiveClaim.status === 409 && leases[1].status === "active", `${inactiveClaim.status}/${inactiveClaim.body.error?.code}`);

    const secret = await call("POST", createPath, { ...frontierBody(roomRef, { nested: { api_token: "plaintext" } }), expected_revision: 0 });
    ok("VALIDATION: recursive secret-bearing payload refuses before authority", secret.status === 422 && secret.body.error?.code === "work_frontier_claim_plaintext_secret_rejected", `${secret.status}/${secret.body.error?.code}`);
    const planeOwned = await call("POST", createPath, { ...frontierBody(roomRef), frontier_item_id: "frontier://wfi_0000000000000000000000000000000000000000000000000000000000000000", status: "claimed", expected_revision: 0 });
    ok("VALIDATION: direct identity and derived claimed writes are forbidden", planeOwned.status === 422 && planeOwned.body.error?.code === "work_frontier_claim_field_plane_owned", `${planeOwned.status}/${planeOwned.body.error?.code}`);
    const stale = await call("POST", createPath, { ...frontierBody(roomRef, { objective: "stale" }), expected_revision: 0 });
    ok("REVISION: stale frontier create refuses", stale.status === 409 && stale.body.error?.code === "work_frontier_claim_stale_revision", `${stale.status}/${stale.body.error?.code}`);

    const acquirePath = "/v1/hypervisor/work-claim-leases";
    const firstClaimInput = { ...claimBody(roomRef, mainFrontier.frontier_item_id, leases[0].participant_lease_id), expected_revision: mainFrontier.revision };
    const firstAcquire = await governed(call, resolver, leases[0].participant_ref, acquirePath, firstClaimInput);
    let firstClaim = firstAcquire.response.body.work_claim;
    ok("CLAIM: participant acquires canonical bounded lease", firstAcquire.response.status === 201 && /^work-claim:\/\/wcl_[0-9a-f]{64}$/.test(firstClaim?.work_claim_id) && firstClaim?.status === "active", `${firstAcquire.response.status}/${firstClaim?.work_claim_id}`);
    ok("CLOCK: issue and expiry use authenticated wallet time", firstClaim?.issued_at_ms === firstAcquire.response.body.work_claim_receipt?.authority_resolved_at_ms && firstClaim?.expires_at_ms === firstClaim?.issued_at_ms + 600_000, `${firstClaim?.issued_at_ms}/${firstClaim?.expires_at_ms}`);
    const stampedLease = (await call("GET", `/v1/hypervisor/room-participant-leases/${leases[0].participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
    ok("CROSS-PLANE: participant owner seam stamps current claim", stampedLease.current_claim_ref === firstClaim.work_claim_id, stampedLease.current_claim_ref);

    const firstClaimTail = firstClaim.work_claim_id.replace("work-claim://", "");
    const firstTransitionPath = `/v1/hypervisor/work-claim-leases/${firstClaimTail}/transition`;
    const heartbeat = await governed(call, resolver, leases[0].participant_ref, firstTransitionPath, { transition: "heartbeat", heartbeat_ref: "heartbeat://one", expected_revision: 1 });
    firstClaim = heartbeat.response.body.work_claim;
    const renew = await governed(call, resolver, leases[0].participant_ref, firstTransitionPath, { transition: "renew", ttl_seconds: 900, expected_revision: 2 });
    firstClaim = renew.response.body.work_claim;
    ok("CLAIM: heartbeat and bounded renewal advance lineage", heartbeat.response.status === 200 && renew.response.status === 200 && firstClaim.renewal_count === 1 && firstClaim.revision === 3, `${heartbeat.response.status}/${renew.response.status}/${firstClaim.revision}`);
    const released = await governed(call, resolver, leases[0].participant_ref, firstTransitionPath, { transition: "release", reason: "switch to a clean reclaim", expected_revision: 3 });
    mainFrontier = released.response.body.frontier_item;
    ok("CLAIM: release clears participant and preserves historical claim ref", released.response.body.work_claim?.status === "released" && released.response.body.participant_lease?.current_claim_ref === null && mainFrontier.active_claim_refs.length === 0 && mainFrontier.claim_refs.includes(firstClaim.work_claim_id), `${released.response.status}/${released.response.body.work_claim?.status}`);

    const leaseAfterRelease = released.response.body.participant_lease;
    const staleGrant = await call("POST", acquirePath, {
      ...claimBody(roomRef, mainFrontier.frontier_item_id, leaseAfterRelease.participant_lease_id),
      expected_revision: leaseAfterRelease.revision,
      wallet_approval_grant: firstAcquire.grant,
    });
    ok("AUTHORITY: stale signed grant refuses against the new participant revision", staleGrant.status === 403 && staleGrant.body.error?.code === "work_claim_participant_authority_required", `${staleGrant.status}/${staleGrant.body.error?.code}`);

    const secondAcquire = await governed(call, resolver, leases[0].participant_ref, acquirePath, { ...claimBody(roomRef, mainFrontier.frontier_item_id, leases[0].participant_lease_id), expected_revision: mainFrontier.revision });
    const secondClaim = secondAcquire.response.body.work_claim;
    const secondPath = `/v1/hypervisor/work-claim-leases/${secondClaim.work_claim_id.replace("work-claim://", "")}/transition`;
    const completed = await governed(call, resolver, leases[0].participant_ref, secondPath, { transition: "complete", reason: "bounded work submitted for later verification", expected_revision: 1 });
    mainFrontier = completed.response.body.frontier_item;
    ok("CLAIM: completion moves frontier to verifying, never accepted", completed.response.body.work_claim?.status === "completed" && mainFrontier.status === "verifying" && mainFrontier.status !== "accepted", `${completed.response.body.work_claim?.status}/${mainFrontier.status}`);
    const accept = await call("POST", `/v1/hypervisor/work-frontier-items/${mainTail}/transition`, { transition: "accept", expected_revision: mainFrontier.revision });
    ok("FRONTIER: accepted remains typed unavailable", accept.status === 501 && accept.body.error?.code === "work_frontier_acceptance_unavailable", `${accept.status}/${accept.body.error?.code}`);

    // Keep the production client ceiling unchanged. Rotate the deterministic one-validator
    // fixture before its long-lived execution client becomes the limiting factor in this soak.
    await plane.stop();
    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);

    // Create an unresolved dependent item; claiming it must refuse with no claim mutation.
    currentRoom = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const dependentCreate = await governed(call, resolver, "domain://acme-host", createPath, {
      ...frontierBody(roomRef, { objective: "Wait for verification.", dependency_refs: [mainFrontier.frontier_item_id] }),
      expected_revision: currentRoom.revision,
    });
    if (dependentCreate.response.status !== 201) {
      throw new Error(`dependent frontier creation failed: ${dependentCreate.response.status}/${dependentCreate.response.body.error?.code}`);
    }
    let dependent = dependentCreate.response.body.frontier_item;
    const dependencyLease = (await call("GET", `/v1/hypervisor/room-participant-leases/${leases[0].participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
    const dependentAttempt = await governed(call, resolver, dependencyLease.participant_ref, acquirePath, { ...claimBody(roomRef, dependent.frontier_item_id, leases[0].participant_lease_id), expected_revision: dependencyLease.revision });
    ok("READINESS: unresolved dependency refuses with zero mutation", dependentAttempt.response.status === 409 && dependentAttempt.response.body.error?.code === "work_frontier_claim_dependencies_unresolved", `${dependentAttempt.response.status}/${dependentAttempt.response.body.error?.code}`);

    // Exclusive storm: grants are independently scoped; the room-scoped lock admits exactly one.
    currentRoom = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const exclusiveCreate = await governed(call, resolver, "domain://acme-host", createPath, { ...frontierBody(roomRef, { objective: "Exclusive storm." }), expected_revision: currentRoom.revision });
    let exclusive = exclusiveCreate.response.body.frontier_item;
    await plane.stop();
    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startIsolatedPlane({
      serve: false,
      env: { ...resolver.env, IOI_TEST_WORK_CLAIM_ACQUIRE_BARRIER: "1" },
      dataDir,
    });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const persistedMain = await call("GET", `/v1/hypervisor/work-frontier-items/${mainTail}`);
    ok("RESTART: frontier and completed claim lineage persist", persistedMain.status === 200 && persistedMain.body.frontier_item?.status === "verifying", `${persistedMain.status}/${persistedMain.body.frontier_item?.status}`);
    const exclusiveLeases = [];
    for (const lease of leases.slice(0, 2)) exclusiveLeases.push((await call("GET", `/v1/hypervisor/room-participant-leases/${lease.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease);
    const exclusiveInputs = exclusiveLeases.map((lease) => ({ ...claimBody(roomRef, exclusive.frontier_item_id, lease.participant_lease_id), expected_revision: lease.revision }));
    const exclusiveChallenges = [];
    for (let index = 0; index < 2; index += 1) exclusiveChallenges.push(await call("POST", acquirePath, exclusiveInputs[index]));
    const exclusiveResponses = await Promise.all(exclusiveInputs.map((input, index) => call("POST", acquirePath, {
      ...input, wallet_approval_grant: resolver.mint(exclusiveLeases[index].participant_ref, exclusiveChallenges[index].body.error.approval.policy_hash, exclusiveChallenges[index].body.error.approval.request_hash),
    })));
    const exclusiveWinners = exclusiveResponses.filter((response) => response.status === 201);
    ok("CONCURRENCY: exclusive storm admits exactly one claimant", exclusiveWinners.length === 1 && exclusiveResponses.filter((response) => response.status === 409).length === 1, exclusiveResponses.map((response) => response.status).join(","));
    const exclusiveWinner = exclusiveWinners[0].body.work_claim;
    const exclusiveWinnerLease = leases.find((lease) => lease.participant_lease_id === exclusiveWinner.claimant_ref);

    await plane.stop();
    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const exclusiveRelease = await governed(call, resolver, exclusiveWinnerLease.participant_ref, `/v1/hypervisor/work-claim-leases/${exclusiveWinner.work_claim_id.replace("work-claim://", "")}/transition`, { transition: "release", reason: "storm cleanup", expected_revision: 1 });
    exclusive = exclusiveRelease.response.body.frontier_item;

    // Bounded replication storm: all three have no current claim; exactly max_concurrency=2 win.
    currentRoom = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const replicatedCreate = await governed(call, resolver, "domain://acme-host", createPath, {
      ...frontierBody(roomRef, { objective: "Bounded replication storm.", duplication_policy: "allowed", max_concurrency: 2 }),
      expected_revision: currentRoom.revision,
    });
    if (!replicatedCreate.response.body.frontier_item) {
      throw new Error(`replicated frontier create failed: ${JSON.stringify(replicatedCreate)}`);
    }
    let replicated = replicatedCreate.response.body.frontier_item;
    await plane.stop();
    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startIsolatedPlane({
      serve: false,
      env: { ...resolver.env, IOI_TEST_WORK_CLAIM_ACQUIRE_BARRIER: "1" },
      dataDir,
    });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const replicationLeases = [];
    for (const lease of leases) replicationLeases.push((await call("GET", `/v1/hypervisor/room-participant-leases/${lease.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease);
    const replicationInputs = replicationLeases.map((lease) => ({ ...claimBody(roomRef, replicated.frontier_item_id, lease.participant_lease_id, { duplicate_work_policy: "allowed" }), expected_revision: lease.revision }));
    const replicationChallenges = [];
    for (const input of replicationInputs) replicationChallenges.push(await call("POST", acquirePath, input));
    const replicationResponses = await Promise.all(replicationInputs.map((input, index) => call("POST", acquirePath, {
      ...input, wallet_approval_grant: resolver.mint(replicationLeases[index].participant_ref, replicationChallenges[index].body.error.approval.policy_hash, replicationChallenges[index].body.error.approval.request_hash),
    })));
    const replicationWinners = replicationResponses.filter((response) => response.status === 201).map((response) => response.body.work_claim);
    ok("CONCURRENCY: bounded replication admits exactly max_concurrency", replicationWinners.length === 2 && replicationResponses.filter((response) => response.status === 409).length === 1, replicationResponses.map((response) => response.status).join(","));

    // Host revocation with a live claim performs the separately scoped claim revocation first.
    const revokedClaim = replicationWinners[0];
    let revokeLease = (await call("GET", `/v1/hypervisor/room-participant-leases/${revokedClaim.claimant_ref.replace("participant-lease://", "")}`)).body.participant_lease;
    const revoked = await terminalParticipantWithClaim(call, resolver, revokeLease, "revoke", revokedClaim.revision);
    ok("TERMINAL: host revocation clears its live claim before room slot", revoked.status === 200 && revoked.body.participant_lease?.status === "revoked" && revoked.body.participant_lease?.current_claim_ref === null && revoked.body.released_work_claim?.status === "revoked", `${revoked.status}/${revoked.body.released_work_claim?.status}`);
    replicated = revoked.body.frontier_item;

    const otherReplicatedClaim = replicationWinners[1];
    const otherLease = leases.find((lease) => lease.participant_lease_id === otherReplicatedClaim.claimant_ref);
    const otherRelease = await governed(call, resolver, otherLease.participant_ref, `/v1/hypervisor/work-claim-leases/${otherReplicatedClaim.work_claim_id.replace("work-claim://", "")}/transition`, { transition: "release", reason: "replication cleanup", expected_revision: 1 });
    replicated = otherRelease.response.body.frontier_item;

    await plane.stop();
    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);

    // Participant retirement with a live claim proves the symmetric automatic release.
    let retireLease = leases.find((lease) => lease.participant_lease_id !== revokedClaim.claimant_ref && lease.participant_lease_id !== otherReplicatedClaim.claimant_ref);
    retireLease = (await call("GET", `/v1/hypervisor/room-participant-leases/${retireLease.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
    const retirementAcquire = await governed(call, resolver, retireLease.participant_ref, acquirePath, { ...claimBody(roomRef, exclusive.frontier_item_id, retireLease.participant_lease_id), expected_revision: retireLease.revision });
    const retirementClaim = retirementAcquire.response.body.work_claim;
    exclusive = retirementAcquire.response.body.frontier_item;
    retireLease = retirementAcquire.response.body.participant_lease;
    const retired = await terminalParticipantWithClaim(call, resolver, retireLease, "retire", retirementClaim.revision);
    ok("TERMINAL: participant retirement releases claim before room slot", retired.status === 200 && retired.body.participant_lease?.status === "retired" && retired.body.participant_lease?.current_claim_ref === null && retired.body.released_work_claim?.status === "released", `${retired.status}/${retired.body.released_work_claim?.status}`);
    exclusive = retired.body.frontier_item;

    // Terminate the remaining active participant without a claim.
    const terminalIds = new Set([revoked.body.participant_lease.participant_lease_id, retired.body.participant_lease.participant_lease_id]);
    const remaining = leases.find((lease) => !terminalIds.has(lease.participant_lease_id));
    const remainingLive = (await call("GET", `/v1/hypervisor/room-participant-leases/${remaining.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
    const remainingRevoke = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/room-participant-leases/${remainingLive.participant_lease_id.replace("participant-lease://", "")}/transition`, { transition: "revoke", expected_revision: remainingLive.revision });
    ok("TERMINAL: claim-free revocation still releases room slot", remainingRevoke.response.status === 200 && remainingRevoke.response.body.participant_lease?.status === "revoked", `${remainingRevoke.response.status}/${remainingRevoke.response.body.participant_lease?.status}`);
    const scopeLimitedLive = (await call("GET", `/v1/hypervisor/room-participant-leases/${scopeLimitedLease.participant_lease_id.replace("participant-lease://", "")}`)).body.participant_lease;
    const scopeLimitedRevoke = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/room-participant-leases/${scopeLimitedLive.participant_lease_id.replace("participant-lease://", "")}/transition`, { transition: "revoke", expected_revision: scopeLimitedLive.revision });
    ok("TERMINAL: scope-limited refusal fixture also releases its room slot", scopeLimitedRevoke.response.status === 200 && scopeLimitedRevoke.response.body.participant_lease?.status === "revoked", `${scopeLimitedRevoke.response.status}/${scopeLimitedRevoke.response.body.participant_lease?.status}`);

    // Host closes every unresolved frontier item, then the room itself.
    const roomWithFrontier = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const blockedRoomClose = await call("POST", `/v1/hypervisor/outcome-rooms/${roomTail}/transition`, { transition: "close", expected_revision: roomWithFrontier.revision });
    ok("ROOM: close refuses while unresolved frontier work remains", blockedRoomClose.status === 409 && blockedRoomClose.body.error?.code === "outcome_room_close_blocked_frontier_claims", `${blockedRoomClose.status}/${blockedRoomClose.body.error?.code}`);
    const closeFrontier = async (frontier) => governed(call, resolver, "domain://acme-host", `/v1/hypervisor/work-frontier-items/${frontier.frontier_item_id.replace("frontier://", "")}/transition`, { transition: "close", expected_revision: frontier.revision });
    const mainClosed = await closeFrontier(mainFrontier);
    const dependentClosed = await closeFrontier(dependent);
    const exclusiveClosed = await closeFrontier(exclusive);
    const replicatedClosed = await closeFrontier(replicated);
    ok("FRONTIER: host closes all unresolved items after claims clear", [mainClosed, dependentClosed, exclusiveClosed, replicatedClosed].every((entry) => entry.response.status === 200 && entry.response.body.frontier_item?.status === "closed"), [mainClosed, dependentClosed, exclusiveClosed, replicatedClosed].map((entry) => entry.response.status).join(","));
    const roomBeforeClose = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const roomClosed = await call("POST", `/v1/hypervisor/outcome-rooms/${roomTail}/transition`, { transition: "close", expected_revision: roomBeforeClose.revision });
    ok("ROOM: close succeeds only after frontier, claims, and participants resolve", roomClosed.status === 200 && roomClosed.body.outcome_room?.status === "closed", `${roomClosed.status}/${roomClosed.body.outcome_room?.status}/${roomClosed.body.error?.code || ""}`);

    const frontierOverview = await call("GET", "/v1/hypervisor/work-frontier-items/overview");
    const claimOverview = await call("GET", "/v1/hypervisor/work-claim-leases/overview");
    ok("OVERVIEW: posture is configured without claiming reachability", frontierOverview.body.authority?.status === "configured" && frontierOverview.body.authority?.reachability === "not_probed" && claimOverview.body.local_system_time_is_authoritative === false, JSON.stringify({ frontier: frontierOverview.body.authority, clock: claimOverview.body.lease_clock }));

    await plane.stop();
    plane = null;
    await resolver.stop();
    resolver = null;
    if (includeFaults) await runDurabilityFaultLanes();
  } finally {
    if (plane) await plane.stop();
    if (resolver) await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

const verifierRun = process.argv.includes("--faults-only")
  ? runDurabilityFaultLanes()
  : run({ includeFaults: !process.argv.includes("--main-only") });

verifierRun.then(() => {
  const failed = results.filter((result) => !result.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) process.exitCode = 1;
}).catch((error) => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});
