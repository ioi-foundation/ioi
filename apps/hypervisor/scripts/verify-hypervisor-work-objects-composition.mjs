#!/usr/bin/env node
// R-177 S4b — the six work objects COMPOSED over the orchestration: WorkClaim, Attempt, Finding,
// VerifierChallenge, ResourceOffer and CapabilityOffer v4 admitted as application records under the
// bounded System through the generic record seam, with their coordinates taken from the composition
// (the orchestration's scope; an actor that is an accepted participation or a delegation of the
// coordinating thread) and never from a room or a lease.
//
// WHAT IS PROVED, on the isolated daemon and the REAL wallet.network fixture, through the built agent
// SDK and the built @ioi/ioi-ai-orchestration package: a claim by a delegation (a subagent the kernel
// lists under this orchestration's thread) and a claim by an accepted external participation each
// admit with the binding derived; the actor rules refuse a foreign thread's delegation, a subagent
// the kernel does not list, a participation not yet accepted, a participation that exited, no actor
// and both actors, each by name and each admitting nothing; an attempt freezes the frontier item and
// the claim as coordinates whose control hashes ARE the served records' seam-derived payload roots
// (re-derived offline) and is refused under a claim its actor does not hold; a finding is proposed
// by the attempt's actor and refused by the other; a challenge by the participation on the
// delegation's finding admits; a capability offer and a resource offer admit; a record that still
// carries a room member is refused by the seam as not registered-valid; a transition is a revision
// on the exact head by the record's own actor; restart; and the structural claim that the daemon's
// goal-orchestration planes know nothing of v4 — the records are served only through the seam.
//
// WHAT IS NOT CLAIMED. The room-hosted v3 planes still exist and are not retired by this gate (S4a/
// S4c); no settlement, verification or adjudication happens; the frontier item is the S1 contract's
// own fixture shape.

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import { bootstrapActiveSystem, exactGenesisBody, rebindGenesisBodySystem, recomputeReleaseHashes } from "./verify-hypervisor-system-sequence-zero-materialization.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const MUTATION = process.argv.includes("--mutation");
const SYSTEM_ID = "system://ioi/orchestration/s4b-proof";
const GENESIS_ID = "genesis://ioi/orchestration/s4b-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/orchestration/s4b-proof/v1";
const PACKAGE = "package://ioi/outcome-room"; // the fixture's exact genesis release package; the composition is package-neutral
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE_REF = "app-scope://ioi-ai/objective/s4b-proof";
const TERMS_ID = "terms://ioi/orchestration/s4b-proof/1";
const DISCOVERY_ID = "discovery://ioi/orchestration/s4b-proof/1";
const ALLOY = "worker://independent-alloy-lab";
const ALLOY_SYSTEM = "domain://independent-alloy-lab";
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: (["CollaborationRefusal", "WorkRefusal"].includes(error?.name) ? error.code : "") || daemonCode(error), message: String(error?.message ?? "").slice(0, 300) }; } };
const sha = (text) => `sha256:${createHash("sha256").update(text).digest("hex")}`;
const readFixture = (rel) => JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures", rel), "utf8"));
const stripBinding = (record) => { const { system_binding: _b, ...rest } = record; return rest; };

async function jsonCall(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, base), { method, headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }), ...headers } }, (response) => {
      const chunks = []; response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); const raw = Buffer.concat(chunks).toString("utf8"); let parsed = {}; try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { raw }; } resolve({ status: response.statusCode ?? 0, body: parsed }); });
    });
    const deadline = setTimeout(() => request.destroy(new Error(`HTTP timeout at ${method} ${path}`)), 1_800_000);
    request.on("error", (error) => { clearTimeout(deadline); reject(error); });
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

function genesisBody() {
  const body = exactGenesisBody();
  body.release.package_id = PACKAGE;
  body.release.manifest_id = `${PACKAGE}/release/sha256:${"5".repeat(64)}`;
  body.release.display_name = "Work-objects S4b verifier package";
  body.release.description = "Work objects composed over the orchestration under a bounded System.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/orchestration";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, { systemId: SYSTEM_ID, genesisId: GENESIS_ID, constitutionRef: CONSTITUTION_REF, deploymentProfileRef: `deployment-profile://ioi/orchestration/s4b-proof/local/revision/sha256:${"d".repeat(64)}`, orderingProfileRef: "ordering-profile://ioi/orchestration/s4b-proof/hosted", oracleProfileRef: "oracle-evidence-profile://ioi/orchestration/s4b-proof/fail-closed", lifecycleProfileRef: "lifecycle-profile://ioi/orchestration/s4b-proof/default" });
}

async function loadBuilt(rel, hint) {
  const dist = join(REPO, rel);
  requireValue(existsSync(dist), `BLOCKED: build ${hint} first`);
  return await import(pathToFileURL(dist).href);
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-work-objects-"));
  let resolver; let plane;
  try {
    const sdk = await loadBuilt("packages/agent-sdk/dist/index.js", "packages/agent-sdk (npm run build --workspace=@ioi/agent-sdk)");
    const app = await loadBuilt("packages/ioi-ai-orchestration/dist/index.js", "packages/ioi-ai-orchestration (npm run build --workspace=@ioi/ioi-ai-orchestration)");
    const { Orchestration, createRuntimeSubstrateClient } = sdk;
    const { COLLABORATION_CONTRACTS, Collaboration, WORK_CONTRACTS, Work, buildParticipationRequest, coordinateOf, delegationActor, generateSigner, participationActor, signerFromSeed, verifyFrozenCoordinates } = app;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "work-objects-operator-password", email: "work-objects@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    const clientFor = (url) => createRuntimeSubstrateClient({ endpoint: url, headers: operatorHeaders });

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", typeof active.source?.record?.governing_authority_ref === "string", JSON.stringify(active).slice(0, 300));

    // -- the orchestration, one delegation, one accepted participation, two frontier items ---------------------------------
    const host = generateSigner(SYSTEM_ID);
    const alloy = signerFromSeed(ALLOY, "09".repeat(32));
    const orchestration = await Orchestration.compose(clientFor(plane.daemonUrl), { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "S4b proof: work objects composed over the orchestration" });
    let collaboration = new Collaboration(orchestration, host);
    let work = new Work(orchestration);
    const worker = await orchestration.delegate({ prompt: "carry the first frontier item", role: "worker" });
    const delegation = delegationActor(orchestration.thread_id, worker.subagent_id);
    const termsBodyRoot = sha(JSON.stringify({ objective: "replicate the alloy result", version: "1.0.0" }));
    await collaboration.proposeTerms({ collaboration_terms_id: TERMS_ID, version: "1.0.0", predecessor_terms_ref: null, terms_body_hash_profile: "ioi.collaboration-terms-body.v1", terms_body_root: termsBodyRoot, proposed_by_ref: SYSTEM_ID, party_roles: [{ party_ref: SYSTEM_ID, role: "data_owner", acceptance_required: true }, { party_ref: ALLOY, role: "worker_provider", acceptance_required: true }], required_party_refs: [SYSTEM_ID, ALLOY] });
    await collaboration.acceptTerms(TERMS_ID, host);
    const termsActive = await refused(() => collaboration.acceptTerms(TERMS_ID, alloy));
    const acceptance = (await collaboration.terms(TERMS_ID)).admissions?.[2]?.receipt_ref ?? "receipt://unknown";
    await collaboration.publishDiscovery({ discovery_id: DISCOVERY_ID, publication_version: "1", public_goal_ref: "goal://ioi/orchestration/s4b-proof", public_objective: "Replicate the alloy result under exact terms", public_category_refs: ["ontology://materials/alloys"], coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, participation_channel_ref: "aiip://channel/ioi/orchestration/s4b-proof", collaboration_terms_ref: TERMS_ID });
    const draftRequest = (id) => buildParticipationRequest({ participation_request_id: `participation-request://ioi/orchestration/s4b-proof/${id}`, orchestration_ref: SCOPE_REF, discovery_ref: DISCOVERY_ID, coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, requester_system_ref: ALLOY_SYSTEM, collaboration_terms_ref: TERMS_ID, collaboration_terms_root: termsBodyRoot, terms_response: "accept" }, alloy);
    const p1 = draftRequest("alloy-1"); const p2 = draftRequest("alloy-2"); const p3 = draftRequest("alloy-3");
    await collaboration.admitParticipation(p1); await collaboration.decideParticipation(p1.participation_request_id, { accept: true, reason_code: "eligible" });
    await collaboration.admitParticipation(p2); await collaboration.decideParticipation(p2.participation_request_id, { accept: true, reason_code: "eligible" });
    await collaboration.exitParticipation(p2.participation_request_id, { reason_code: "left", bundle: { participant_state_bundle_id: "participant-state://ioi/orchestration/s4b-proof/alloy-2/1", participant_and_home_domain_refs: [ALLOY], source_admission_watermark_ref: `sha256:${"0".repeat(64)}`, candidate_refs: [], bundle_artifact_ref: "artifact://ioi/orchestration/s4b-proof/alloy-2/bundle" } });
    await collaboration.admitParticipation(p3); // submitted, never decided
    const participation = participationActor(p1.participation_request_id);
    const itemFixture = readFixture("work-frontier-item-v3/positive-admitted.json"); delete itemFixture.system_binding;
    const items = ["a", "b"].map((s) => ({ ...itemFixture, frontier_item_id: `frontier://ioi/orchestration/s4b-proof/${s}` }));
    for (const item of items) await orchestration.record({ contract_id: WORK_CONTRACTS.frontierItem, object_id: item.frontier_item_id, record: item });
    ok("PRECONDITION: an orchestration with one delegation (a subagent the kernel lists under its thread), one accepted participation, one exited participation, one undecided submission and two frontier items", termsActive.ok && typeof worker.subagent_id === "string" && (await orchestration.delegations()).subagents.some((s) => s.subagent_id === worker.subagent_id) && (await orchestration.records(WORK_CONTRACTS.frontierItem)).count === 2, JSON.stringify({ termsActive: termsActive.ok, worker: worker.subagent_id }).slice(0, 200));

    // -- claims ----------------------------------------------------------------------------------------------------------
    // The policy-shaped members take the registered fixture's own spellings: their patterns are the contract's, not this gate's to invent.
    const claimFixture = readFixture("work-claim-v4/positive-delegation-claim.json");
    const claimDraft = (id, itemRef, actor, claimant) => ({ work_claim_id: `work-claim://ioi/orchestration/s4b-proof/${id}`, frontier_item_ref: itemRef, claimant_ref: claimant, actor, collaboration_terms_ref: TERMS_ID, collaboration_terms_root: termsBodyRoot, terms_acceptance_ref: claimFixture.terms_acceptance_ref, contribution_policy_ref: claimFixture.contribution_policy_ref, settlement_profile_ref: claimFixture.settlement_profile_ref, bounded_scope_ref: claimFixture.bounded_scope_ref, duplicate_work_policy: "exclusive", expires_at: new Date(Date.now() + 3_600_000).toISOString() });
    const CLAIM_D = "work-claim://ioi/orchestration/s4b-proof/d1";
    const claimD = await refused(() => work.claim(claimDraft("d1", items[0].frontier_item_id, delegation, SYSTEM_ID)));
    const claimP = await refused(() => work.claim(claimDraft("p1", items[1].frontier_item_id, participation, ALLOY)));
    requireValue(claimD.ok && claimP.ok, `BLOCKED: the two reference claims did not admit: ${JSON.stringify({ claimD, claimP }).slice(0, 400)}`);
    ok("[claim] a claim by the delegation and a claim by the accepted participation each admit under the System through the seam with the binding derived, the orchestration as parent scope, and exactly one actor set", claimD.ok && claimP.ok && claimD.value.record?.delegation_ref === delegation.delegation_ref && claimD.value.record?.participation_ref === null && claimP.value.record?.participation_ref === p1.participation_request_id && claimP.value.record?.delegation_ref === null && claimD.value.record?.system_binding?.parent_scope_ref === SCOPE_REF, JSON.stringify({ claimD, claimP }).slice(0, 500));
    const foreign = await refused(() => work.claim(claimDraft("x1", items[0].frontier_item_id, delegationActor("thread_someone_else", worker.subagent_id), SYSTEM_ID)));
    const unknownSub = await refused(() => work.claim(claimDraft("x2", items[0].frontier_item_id, delegationActor(orchestration.thread_id, "agent_not_listed"), SYSTEM_ID)));
    const undecided = await refused(() => work.claim(claimDraft("x3", items[0].frontier_item_id, participationActor(p3.participation_request_id), ALLOY)));
    const exited = await refused(() => work.claim(claimDraft("x4", items[0].frontier_item_id, participationActor(p2.participation_request_id), ALLOY)));
    const none = await refused(() => work.claim(claimDraft("x5", items[0].frontier_item_id, { participation_ref: null, delegation_ref: null }, ALLOY)));
    const both = await refused(() => work.claim(claimDraft("x6", items[0].frontier_item_id, { participation_ref: p1.participation_request_id, delegation_ref: delegation.delegation_ref }, ALLOY)));
    const noItem = await refused(() => work.claim(claimDraft("x7", "frontier://ioi/orchestration/s4b-proof/absent", delegation, SYSTEM_ID)));
    ok("[actor] the composer refuses by name a foreign thread's delegation, a subagent the kernel does not list, a participation not yet accepted, a participation that exited, no actor, both actors, and a claim on a frontier item that is not under the orchestration — none admits", [foreign, unknownSub, undecided, exited, none, both, noItem].every((r) => !r.ok) && foreign.code === "work_actor_delegation_foreign_thread" && unknownSub.code === "work_actor_delegation_unknown" && undecided.code === "work_actor_participation_not_accepted" && exited.code === "work_actor_participation_exited" && none.code === "work_actor_required" && both.code === "work_actor_ambiguous" && noItem.code === "work_frontier_item_unknown" && (await orchestration.records(WORK_CONTRACTS.claim)).count === 2, JSON.stringify({ foreign: foreign.code, unknownSub: unknownSub.code, undecided: undecided.code, exited: exited.code, none: none.code, both: both.code, noItem: noItem.code }));

    // -- attempts: frozen coordinates ----------------------------------------------------------------------------------------
    const attemptBase = stripBinding(readFixture("attempt-v4/positive-delegation-attempt.json"));
    const attemptD = await refused(() => work.attempt({ attempt_id: "attempt://ioi/orchestration/s4b-proof/d1", actor: delegation, participant_ref: SYSTEM_ID, work_subject_ref: `work-claim://ioi/orchestration/s4b-proof/d1`, frontier_item_ref: items[0].frontier_item_id, work_claim_ref: CLAIM_D, base: attemptBase }));
    const servedItem = (await refused(() => work.read(WORK_CONTRACTS.frontierItem, items[0].frontier_item_id))).value ?? { current: null };
    const servedClaim = (await refused(() => work.read(WORK_CONTRACTS.claim, CLAIM_D))).value ?? { current: null };
    const coordinates = attemptD.value?.record?.bound_coordinates ?? {};
    const offline = attemptD.ok ? verifyFrozenCoordinates(attemptD.value.record, { frontier_item: { record: servedItem.current, ref: items[0].frontier_item_id }, work_claim: { record: servedClaim.current, ref: CLAIM_D } }) : { ok: false, findings: ["no attempt"] };
    ok("[attempt] the delegation's attempt under its own claim admits with the frontier item and the claim FROZEN as coordinates whose control hashes are the served records' seam-derived payload roots and whose orchestration is this one — re-derived offline from the served records", attemptD.ok && coordinates.frontier_item?.control_hash === servedItem.current?.system_binding?.payload_root && coordinates.work_claim?.control_hash === servedClaim.current?.system_binding?.payload_root && coordinates.frontier_item?.orchestration_ref === SCOPE_REF && offline.ok, JSON.stringify({ attemptD, coordinates, offline }).slice(0, 900));
    const wrongClaim = await refused(() => work.attempt({ attempt_id: "attempt://ioi/orchestration/s4b-proof/p-on-d", actor: participation, participant_ref: ALLOY, work_subject_ref: "work-claim://ioi/orchestration/s4b-proof/d1", frontier_item_ref: items[0].frontier_item_id, work_claim_ref: CLAIM_D, base: attemptBase }));
    ok("[attempt] an attempt under a claim its actor does not hold is refused by name and admits nothing", !wrongClaim.ok && wrongClaim.code === "work_attempt_claim_not_held_by_actor" && (await orchestration.records(WORK_CONTRACTS.attempt)).count === 1, JSON.stringify(wrongClaim).slice(0, 200));

    // -- findings and challenges -------------------------------------------------------------------------------------------
    const findingBase = stripBinding(readFixture("finding-v4/positive-delegation-finding.json"));
    const findingD = await refused(() => work.finding({ finding_id: "finding://ioi/orchestration/s4b-proof/d1", actor: delegation, attempt_ref: "attempt://ioi/orchestration/s4b-proof/d1", work_result_ref: "work-result://ioi/orchestration/s4b-proof/d1", participant_ref: SYSTEM_ID, proposed_by_ref: SYSTEM_ID, base: findingBase }));
    const findingP = await refused(() => work.finding({ finding_id: "finding://ioi/orchestration/s4b-proof/p-on-d", actor: participation, attempt_ref: "attempt://ioi/orchestration/s4b-proof/d1", work_result_ref: "work-result://ioi/orchestration/s4b-proof/d1", participant_ref: ALLOY, proposed_by_ref: ALLOY, base: findingBase }));
    const servedAttempt = (await refused(() => work.read(WORK_CONTRACTS.attempt, "attempt://ioi/orchestration/s4b-proof/d1"))).value ?? { current: null };
    ok("[finding] a finding by the attempt's own actor admits with the attempt frozen as a coordinate; a finding by the other actor is refused by name", findingD.ok && findingD.value.record?.bound_coordinates?.attempt?.control_hash === servedAttempt.current?.system_binding?.payload_root && !findingP.ok && findingP.code === "work_finding_actor_mismatch", JSON.stringify({ findingD: findingD.ok, findingP }).slice(0, 300));
    const challengeBase = stripBinding(readFixture("verifier-challenge-v4/positive-participation-challenge.json"));
    const challenge = await refused(() => work.challenge({ verifier_challenge_id: "verifier-challenge://ioi/orchestration/s4b-proof/p1", actor: participation, challenger_ref: ALLOY, challenged_ref: "finding://ioi/orchestration/s4b-proof/d1", base: challengeBase }));
    const challengeNothing = await refused(() => work.challenge({ verifier_challenge_id: "verifier-challenge://ioi/orchestration/s4b-proof/p2", actor: participation, challenger_ref: ALLOY, challenged_ref: "finding://ioi/orchestration/s4b-proof/absent", base: challengeBase }));
    ok("[challenge] the participation challenges the delegation's finding (admitted with the participation as actor); a challenge of a record not under the orchestration is refused by name", challenge.ok && challenge.value.record?.participation_ref === p1.participation_request_id && !challengeNothing.ok && challengeNothing.code === "work_challenged_unknown", JSON.stringify({ challenge: challenge.ok, challengeNothing }).slice(0, 300));
    const capBase = stripBinding(readFixture("capability-offer-v4/positive-participation-offer.json"));
    const resBase = stripBinding(readFixture("resource-offer-v4/positive-delegation-offer.json"));
    const capOffer = await refused(() => work.offer("capability", { id: "capability-offer://ioi/orchestration/s4b-proof/p1", actor: participation, base: capBase }));
    const resOffer = await refused(() => work.offer("resource", { id: "resource-offer://ioi/orchestration/s4b-proof/d1", actor: delegation, base: resBase }));
    ok("[offers] a capability offer by the participation and a resource offer by the delegation admit under the System, each with its actor and no lease", capOffer.ok && resOffer.ok && capOffer.value.record?.participation_ref === p1.participation_request_id && resOffer.value.record?.delegation_ref === delegation.delegation_ref && !("participant_lease_ref" in (capOffer.value.record ?? {})) && !("provider_participant_lease_ref" in (resOffer.value.record ?? {})), JSON.stringify({ capOffer: capOffer.ok, resOffer: resOffer.ok }).slice(0, 200));

    // -- the seam refuses a room member ------------------------------------------------------------------------------------
    const roomy = { ...stripBinding(claimD.value.record), work_claim_id: "work-claim://ioi/orchestration/s4b-proof/roomy", outcome_room_ref: "outcome-room://demo" };
    const roomyAdmit = await refused(() => orchestration.record({ contract_id: WORK_CONTRACTS.claim, object_id: roomy.work_claim_id, record: roomy }));
    ok("[vocabulary] a v4 record that still carries a room member is refused by the seam as not registered-valid: the composition's contracts know no room", !roomyAdmit.ok && roomyAdmit.code === "system_record_not_registered_valid", JSON.stringify(roomyAdmit).slice(0, 200));

    // -- transitions ---------------------------------------------------------------------------------------------------------
    const completed = await refused(() => work.transition(WORK_CONTRACTS.claim, CLAIM_D, { status: "completed" }, delegation));
    const byOther = await refused(() => work.transition(WORK_CONTRACTS.claim, CLAIM_D, { status: "released" }, participation));
    ok("[transition] a status transition is a successor revision on the exact head by the record's own actor; the other actor is refused by name", completed.ok && completed.value.record?.status === "completed" && (await work.read(WORK_CONTRACTS.claim, CLAIM_D)).revisions?.length === 2 && !byOther.ok && byOther.code === "work_transition_not_by_actor", JSON.stringify({ completed: completed.ok, byOther }).slice(0, 300));

    // -- restart ---------------------------------------------------------------------------------------------------------------
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    const reopened = Orchestration.open(clientFor(plane.daemonUrl), orchestration.handle());
    work = new Work(reopened);
    const afterClaim = (await refused(() => work.read(WORK_CONTRACTS.claim, CLAIM_D))).value ?? { current: null };
    const afterAttempt = (await refused(() => work.read(WORK_CONTRACTS.attempt, "attempt://ioi/orchestration/s4b-proof/d1"))).value ?? { current: null };
    const lateForeign = await refused(() => work.claim(claimDraft("x8", items[0].frontier_item_id, delegationActor("thread_someone_else", worker.subagent_id), SYSTEM_ID)));
    ok("[restart] a re-attached composer reads the claim (2 revisions) and the attempt (its frozen coordinates still re-deriving from the served records) from durable admissions, and the actor rules hold", afterClaim.revisions?.length === 2 && afterClaim.head === completed.value?.expected_head_for_successor && afterAttempt.current && verifyFrozenCoordinates(afterAttempt.current, { frontier_item: { record: servedItem.current, ref: items[0].frontier_item_id }, work_claim: { record: servedClaim.current, ref: CLAIM_D } }).ok && !lateForeign.ok && lateForeign.code === "work_actor_delegation_foreign_thread", JSON.stringify({ afterClaim: afterClaim.revisions?.length, lateForeign }).slice(0, 200));

    // -- structure ------------------------------------------------------------------------------------------------------------
    const workSource = readFileSync(join(REPO, "packages/ioi-ai-orchestration/src/work.ts"), "utf8");
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    const planes = ["attempt_finding_routes.rs", "verifier_challenge_routes.rs", "resource_capability_offer_routes.rs", "work_frontier_claim_routes.rs"].map((f) => readFileSync(join(REPO, "crates/node/src/bin/hypervisor_daemon_routes", f), "utf8")).join("\n");
    ok("[structure] the work objects are composed with no plane: the module names no room or lease, calls no goal-orchestration route, the router registers no route for a v4 contract, and the room-hosted planes know nothing of v4 (the records are served only through the seam)", !/\b(room|rooms)\b/iu.test(workSource) && !/participant[_ -]lease/iu.test(workSource) && !/goal-orchestration/u.test(workSource) && !/work-claim\/v4|attempt\/v4|finding\/v4|verifier-challenge\/v4|offer\/v4/u.test(routerSource) && !/AttemptV4|FindingV4|WorkClaimV4|VerifierChallengeV4|ResourceOfferV4|CapabilityOfferV4|\.v4"/u.test(planes), "");

    if (MUTATION) {
      ok("DRILL D1 — the coordinate oracle rejects a tampered control hash and a coordinate from another orchestration", !verifyFrozenCoordinates({ ...attemptD.value.record, bound_coordinates: { ...coordinates, work_claim: { ...coordinates.work_claim, control_hash: `sha256:${"9".repeat(64)}` } } }, { frontier_item: { record: servedItem.current, ref: items[0].frontier_item_id }, work_claim: { record: servedClaim.current, ref: CLAIM_D } }).ok && !verifyFrozenCoordinates({ ...attemptD.value.record, bound_coordinates: { ...coordinates, frontier_item: { ...coordinates.frontier_item, orchestration_ref: "app-scope://other" } } }, { frontier_item: { record: servedItem.current, ref: items[0].frontier_item_id }, work_claim: { record: servedClaim.current, ref: CLAIM_D } }).ok, "");
      ok("DRILL D2 — coordinateOf yields the served binding's payload root and refuses an unbound record", coordinateOf(servedItem.current, items[0].frontier_item_id).control_hash === servedItem.current.system_binding.payload_root && (() => { try { coordinateOf({ a: 1 }, "x"); return false; } catch (e) { return e.code === "work_coordinate_unbound"; } })(), "");
      ok("DRILL D3 — the refusal predicate reads a work refusal by its code and an admission as ok", foreign.code === "work_actor_delegation_foreign_thread" && claimD.ok, "");
    }
  } catch (error) {
    ok("the verifier completed", false, String(error?.stack || error).slice(0, 1200));
  } finally {
    try { await plane?.stop(); } catch {}
    try { await resolver?.stop(); } catch {}
    try { rmSync(dataDir, { recursive: true, force: true }); } catch {}
  }
  const passed = results.filter((r) => r.pass).length;
  console.log(`${passed}/${results.length} passed`);
  if (!MUTATION) emitVerifierCensus({ verifierId: "work-objects-composition", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  process.exit(passed === results.length ? 0 : 1);
}
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) run();
