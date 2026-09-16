#!/usr/bin/env node
// M11.2 / R-175 — portable exit and federated admission, COMPOSED over M11.1 (ACC-13 clauses 6 and 7).
//
// WHAT IS PROVED, on the isolated daemon and the REAL wallet.network fixture, through the built agent
// SDK and the built @ioi/ioi-ai-orchestration package: an accepted participant EXITS through a third
// revision of its participation record citing the least-disclosing state bundle produced with it and
// the seam receipt of the accepted revision it leaves from, and the orchestration CONTINUES (the
// coordinating thread stays active, a new record admits, another participant's head is unmoved, a
// new participant admits); the bundle verifies offline; an exit is refused for a submission and for a
// participant that already left. Federated admission is a DECLARED MODE: the discovery names the
// federation policy path as admission owner, a request under it admits, and its decision is refused
// without the adjudicator, with an adjudicator that is not a terms party, and with a key that is not
// the adjudicator's key of record; with the key of record the decision admits, is the policy path's,
// and its co-signature verifies offline. The mode fences hold: a hosted decision takes no adjudicator,
// a request cannot choose a mode the projection did not declare, and a federated request under
// terms not yet active is refused. Restart with a re-attached composer.
//
// WHAT IS NOT CLAIMED. No daemon route exists for any of this; the router is checked to register
// nothing for the successor contract. Cross-domain transport (AIIP bindings, M11.3) is not
// exercised: the requests are built by the party's signer in-process and handed to the host. The
// exited party's lineage refs are opaque strings here; that they resolve across a real domain
// boundary is M11.3's claim, not this gate's.

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
const SYSTEM_ID = "system://ioi/collaboration/m112-proof";
const GENESIS_ID = "genesis://ioi/collaboration/m112-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/collaboration/m112-proof/v1";
const PACKAGE = "package://ioi/outcome-room"; // the fixture's exact genesis release package; the composition is package-neutral
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE_REF = "app-scope://ioi-ai/objective/m112-proof";
const TERMS_ID = "terms://ioi/collaboration/m112-proof/1";
const TERMS_2_ID = "terms://ioi/collaboration/m112-proof/2";
const HOSTED_DISCOVERY = "discovery://ioi/collaboration/m112-proof/hosted";
const FEDERATED_DISCOVERY = "discovery://ioi/collaboration/m112-proof/federated";
const FEDERATION_POLICY = "policy://ioi/federation/materials/v1";
const ALLOY = "worker://independent-alloy-lab";
const ALLOY_SYSTEM = "domain://independent-alloy-lab";
const REPLICATION = "worker://replication-lab-two";
const REPLICATION_SYSTEM = "domain://replication-lab-two";
const FRONTIER_CONTRACT = "schema://ioi/applications/ioi-ai/work-frontier-item/v3";
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: (error?.name === "CollaborationRefusal" ? error.code : "") || daemonCode(error), message: String(error?.message ?? "").slice(0, 300) }; } };
const sha = (text) => `sha256:${createHash("sha256").update(text).digest("hex")}`;
const readFixture = (rel) => JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures", rel), "utf8"));

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
  body.release.display_name = "Portable-exit M11.2 verifier package";
  body.release.description = "Portable exit and federated admission composed over collaboration terms under a bounded System.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/collaboration";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, { systemId: SYSTEM_ID, genesisId: GENESIS_ID, constitutionRef: CONSTITUTION_REF, deploymentProfileRef: `deployment-profile://ioi/collaboration/m112-proof/local/revision/sha256:${"d".repeat(64)}`, orderingProfileRef: "ordering-profile://ioi/collaboration/m112-proof/hosted", oracleProfileRef: "oracle-evidence-profile://ioi/collaboration/m112-proof/fail-closed", lifecycleProfileRef: "lifecycle-profile://ioi/collaboration/m112-proof/default" });
}

async function loadBuilt(rel, hint) {
  const dist = join(REPO, rel);
  requireValue(existsSync(dist), `BLOCKED: build ${hint} first`);
  return await import(pathToFileURL(dist).href);
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-portable-exit-"));
  let resolver; let plane;
  try {
    const sdk = await loadBuilt("packages/agent-sdk/dist/index.js", "packages/agent-sdk (npm run build --workspace=@ioi/agent-sdk)");
    const app = await loadBuilt("packages/ioi-ai-orchestration/dist/index.js", "packages/ioi-ai-orchestration (npm run build --workspace=@ioi/ioi-ai-orchestration)");
    const { Orchestration, createRuntimeSubstrateClient } = sdk;
    const { COLLABORATION_CONTRACTS, Collaboration, buildParticipationRequest, deriveParticipationDecisionMaterialHash, generateSigner, signerFromSeed, verifyParticipationDecision, verifyStateBundle } = app;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "portable-exit-operator-password", email: "portable-exit@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    const clientFor = (url) => createRuntimeSubstrateClient({ endpoint: url, headers: operatorHeaders });

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", typeof active.source?.record?.governing_authority_ref === "string", JSON.stringify(active).slice(0, 300));

    const host = generateSigner(SYSTEM_ID);
    const alloy = signerFromSeed(ALLOY, "09".repeat(32));
    const replication = signerFromSeed(REPLICATION, "0a".repeat(32));
    const orchestration = await Orchestration.compose(clientFor(plane.daemonUrl), { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "M11.2 proof: portable exit and federated admission" });
    let collaboration = new Collaboration(orchestration, host);
    const count = async (contract) => (await orchestration.records(contract)).count;

    // -- terms with three parties: the host, the worker, and the federation adjudicator (role coordinator) ---
    const termsBodyRoot = sha(JSON.stringify({ objective: "replicate and adjudicate the alloy result", version: "1.0.0" }));
    const proposal = (id, root) => ({ collaboration_terms_id: id, version: "1.0.0", predecessor_terms_ref: null, terms_body_hash_profile: "ioi.collaboration-terms-body.v1", terms_body_root: root, proposed_by_ref: SYSTEM_ID,
      party_roles: [{ party_ref: SYSTEM_ID, role: "data_owner", acceptance_required: true }, { party_ref: ALLOY, role: "worker_provider", acceptance_required: true }, { party_ref: REPLICATION, role: "coordinator", acceptance_required: true }],
      required_party_refs: [SYSTEM_ID, ALLOY, REPLICATION] });
    await collaboration.proposeTerms(proposal(TERMS_ID, termsBodyRoot));
    await collaboration.acceptTerms(TERMS_ID, host);
    await collaboration.acceptTerms(TERMS_ID, alloy);
    const activated = await refused(() => collaboration.acceptTerms(TERMS_ID, replication));
    ok("PRECONDITION: terms with three required parties (host, worker, adjudicator with role coordinator) activate on the third exact-root acceptance", activated.ok && activated.value.activated === true, JSON.stringify(activated).slice(0, 300));
    const discoveryDraft = (id, topology, owner) => ({ discovery_id: id, publication_version: "1", public_goal_ref: "goal://ioi/collaboration/m112-proof", public_objective: "Replicate the alloy result under exact terms", public_category_refs: ["ontology://materials/alloys"], coordination_topology: topology, admission_owner_ref: owner, participation_channel_ref: `aiip://channel/ioi/collaboration/m112-proof/${topology}`, collaboration_terms_ref: TERMS_ID });
    const hosted = await refused(() => collaboration.publishDiscovery(discoveryDraft(HOSTED_DISCOVERY, "hosted_admission", SYSTEM_ID)));
    const federated = await refused(() => collaboration.publishDiscovery(discoveryDraft(FEDERATED_DISCOVERY, "federated_admission", FEDERATION_POLICY)));
    ok("PRECONDITION: two discoveries under the active terms — one hosted (the host System owns admission) and one federated (the federation policy path owns admission) — both admitted", hosted.ok && federated.ok && federated.value.record?.coordination_topology === "federated_admission" && federated.value.record?.admission_owner_ref === FEDERATION_POLICY, JSON.stringify({ hosted: hosted.ok, federated }).slice(0, 300));

    // -- clause 6: portable exit that does not end the orchestration ------------------------------------------
    const draft = (id, discovery, topology, owner, over = {}) => ({ participation_request_id: `participation-request://ioi/collaboration/m112-proof/${id}`, orchestration_ref: SCOPE_REF, discovery_ref: discovery, coordination_topology: topology, admission_owner_ref: owner, requester_system_ref: ALLOY_SYSTEM, collaboration_terms_ref: TERMS_ID, collaboration_terms_root: termsBodyRoot, terms_response: "accept", capability_offer_refs: ["capability-offer://independent-alloy-lab/replication"], eligibility_evidence_refs: ["evidence://independent-alloy-lab/conformance/1"], ...over });
    const h1 = buildParticipationRequest(draft("alloy-h1", HOSTED_DISCOVERY, "hosted_admission", SYSTEM_ID), alloy);
    const h2 = buildParticipationRequest(draft("alloy-h2", HOSTED_DISCOVERY, "hosted_admission", SYSTEM_ID), alloy);
    const h1Admitted = await refused(() => collaboration.admitParticipation(h1));
    const h2Admitted = await refused(() => collaboration.admitParticipation(h2));
    const hostedWithAdjudicator = await refused(() => collaboration.decideParticipation(h1.participation_request_id, { accept: true, reason_code: "eligible", adjudicator: replication }));
    ok("[fence] a HOSTED decision takes no adjudicator: offered one, the composer refuses by name and admits nothing", h1Admitted.ok && h2Admitted.ok && !hostedWithAdjudicator.ok && hostedWithAdjudicator.code === "hosted_decision_takes_no_adjudicator" && (await collaboration.participation(h1.participation_request_id)).revisions?.length === 1, JSON.stringify(hostedWithAdjudicator).slice(0, 300));
    const h1Decided = await refused(() => collaboration.decideParticipation(h1.participation_request_id, { accept: true, reason_code: "eligible" }));
    const h2Decided = await refused(() => collaboration.decideParticipation(h2.participation_request_id, { accept: true, reason_code: "eligible" }));
    const h2HeadBefore = (await collaboration.participation(h2.participation_request_id)).head;
    ok("[hosted] two hosted requests accepted by the host System itself (decided_by_ref = the declared admission owner, no adjudicator), each verifying offline", h1Decided.ok && h2Decided.ok && h1Decided.value.record?.decision?.decided_by_ref === SYSTEM_ID && h1Decided.value.record?.decision?.adjudicator_ref === null && verifyParticipationDecision(h1Decided.value.record).ok && verifyParticipationDecision(h2Decided.value.record).ok, JSON.stringify({ h1Decided, h2Decided }).slice(0, 400));
    const earlyExit = await refused(() => collaboration.exitParticipation("participation-request://ioi/collaboration/m112-proof/never-submitted", { reason_code: "leaving", bundle: { participant_state_bundle_id: "participant-state://ioi/collaboration/m112-proof/none", participant_and_home_domain_refs: [ALLOY], source_admission_watermark_ref: "sha256:" + "0".repeat(64), candidate_refs: [], bundle_artifact_ref: "artifact://none" } }));
    const candidates = [
      { slot: "preserved_contribution_attempt_finding_and_result_refs", ref: "attempt://ioi/collaboration/m112-proof/alloy/1", context_class: "contribution_lineage" },
      { slot: "preserved_receipt_acceptance_settlement_and_dispute_refs", ref: h1Admitted.value.receipt_ref, context_class: "receipt" },
      { slot: "preserved_receipt_acceptance_settlement_and_dispute_refs", ref: "dispute://ioi/collaboration/m112-proof/alloy/1", context_class: "dispute_history" },
      { slot: "portable_artifact_and_view_refs", ref: "vault://ioi/collaboration/m112-proof/api-key", context_class: "raw_secret" },
    ];
    const exited = await refused(() => collaboration.exitParticipation(h1.participation_request_id, { reason_code: "voluntary_retirement", bundle: { participant_state_bundle_id: "participant-state://ioi/collaboration/m112-proof/alloy/1", participant_and_home_domain_refs: [ALLOY, ALLOY_SYSTEM], source_admission_watermark_ref: h1Decided.value.expected_head_for_successor, candidate_refs: candidates, bundle_artifact_ref: "artifact://ioi/collaboration/m112-proof/alloy/bundle-1" } }));
    const h1Chain = await collaboration.participation(h1.participation_request_id);
    const exitRecord = h1Chain.current ?? {};
    const bundleRecord = exited.value?.bundle?.record ?? {};
    ok("[exit] the accepted participant EXITS through a third revision of its own record: the status stays accepted (acceptance is history), the exit is a fact on top of it citing the bundle produced with it (reason voluntary_retirement) and the seam receipt of the accepted revision it leaves from; the request hash is unchanged; an exit for a record that was never submitted is refused before the composer by the seam's own scope fence (nothing was ever bound under the caller's scope)", exited.ok && h1Chain.revisions?.length === 3 && exitRecord.status === "accepted" && exitRecord.exit?.status_at_exit === "accepted" && exitRecord.exit?.bundle_ref === "participant-state://ioi/collaboration/m112-proof/alloy/1" && exitRecord.exit?.receipt_ref === h1Decided.value?.receipt_ref && exitRecord.request_hash === h1.request_hash && bundleRecord.bundle_reason === "voluntary_retirement" && !earlyExit.ok && earlyExit.status === 403 && earlyExit.code === "request_resource_scope_required", JSON.stringify({ exited: exited.ok, revisions: h1Chain.revisions?.length, exit: exitRecord.exit, earlyExit }).slice(0, 600));
    ok("[exit] lineage, receipts and dispute history leave WITH the participant in a least-disclosing bundle that verifies offline: the contribution, receipt and dispute refs are carried, the raw-secret ref is not, hosted_database_access_required is false", verifyStateBundle(bundleRecord, host.publicKeyHex).ok && bundleRecord.preserved_contribution_attempt_finding_and_result_refs?.length === 1 && bundleRecord.preserved_receipt_acceptance_settlement_and_dispute_refs?.length === 2 && !JSON.stringify(bundleRecord).includes("vault://") && exited.value?.excluded?.length === 1 && bundleRecord.hosted_database_access_required === false, JSON.stringify(bundleRecord).slice(0, 400));
    const thread = await call("GET", `/v1/threads/${encodeURIComponent(orchestration.thread_id)}`, undefined);
    const fixture = readFixture("work-frontier-item-v3/positive-admitted.json"); delete fixture.system_binding;
    const item = { ...fixture, frontier_item_id: `frontier://m112-proof/${orchestration.thread_id}/after-exit` };
    const afterExitRecord = await refused(() => orchestration.record({ contract_id: FRONTIER_CONTRACT, object_id: item.frontier_item_id, record: item }));
    const h2HeadAfter = (await collaboration.participation(h2.participation_request_id)).head;
    const h3 = buildParticipationRequest(draft("alloy-h3", HOSTED_DISCOVERY, "hosted_admission", SYSTEM_ID), alloy);
    const h3Admitted = await refused(() => collaboration.admitParticipation(h3));
    ok("[exit] THE ORCHESTRATION CONTINUES: the coordinating thread is still active, a new typed record admits under it, the other participant's head is unmoved, and a new participation admits", thread.status === 200 && thread.body?.status === "active" && afterExitRecord.ok && h2HeadAfter === h2HeadBefore && h3Admitted.ok, JSON.stringify({ thread: thread.body?.status, afterExit: afterExitRecord.ok, h2: h2HeadAfter === h2HeadBefore, h3: h3Admitted.ok }));
    const exitAgain = await refused(() => collaboration.exitParticipation(h1.participation_request_id, { reason_code: "again", bundle: { participant_state_bundle_id: "participant-state://ioi/collaboration/m112-proof/alloy/2", participant_and_home_domain_refs: [ALLOY], source_admission_watermark_ref: h1Chain.head, candidate_refs: [], bundle_artifact_ref: "artifact://x" } }));
    const exitSubmitted = await refused(() => collaboration.exitParticipation(h3.participation_request_id, { reason_code: "early", bundle: { participant_state_bundle_id: "participant-state://ioi/collaboration/m112-proof/alloy/3", participant_and_home_domain_refs: [ALLOY], source_admission_watermark_ref: h1Chain.head, candidate_refs: [], bundle_artifact_ref: "artifact://x" } }));
    ok("[exit] a participant that already left cannot leave again, and a submission (not yet accepted) cannot exit — both refused by name, no second bundle", !exitAgain.ok && exitAgain.code === "participation_not_accepted" && !exitSubmitted.ok && exitSubmitted.code === "participation_not_accepted" && (await count(COLLABORATION_CONTRACTS.bundle)) === 1, JSON.stringify({ exitAgain, exitSubmitted }).slice(0, 300));

    // -- clause 7: federated admission, declared and enforced -------------------------------------------------------
    const modeMismatch = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft("alloy-mode", HOSTED_DISCOVERY, "federated_admission", FEDERATION_POLICY), alloy)));
    const ownerNotHost = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft("alloy-owner", HOSTED_DISCOVERY, "hosted_admission", "system://someone-else/orchestration"), alloy)));
    const ownerNotPolicy = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft("alloy-policy", FEDERATED_DISCOVERY, "federated_admission", SYSTEM_ID), alloy)));
    ok("[fence] THE MODE IS THE PROJECTION'S, NEVER THE REQUESTER'S: a federated request against the hosted projection, a hosted request naming another admission owner, and a federated request naming the host System instead of the policy path are each refused by name", !modeMismatch.ok && modeMismatch.code === "participation_mode_mismatch" && !ownerNotHost.ok && ownerNotHost.code === "hosted_admission_owner_not_the_host" && !ownerNotPolicy.ok && ownerNotPolicy.code === "federated_admission_owner_not_a_policy", JSON.stringify({ modeMismatch, ownerNotHost, ownerNotPolicy }).slice(0, 500));
    const f1 = buildParticipationRequest(draft("alloy-f1", FEDERATED_DISCOVERY, "federated_admission", FEDERATION_POLICY), alloy);
    const f1Admitted = await refused(() => collaboration.admitParticipation(f1));
    const alone = await refused(() => collaboration.decideParticipation(f1.participation_request_id, { accept: true, reason_code: "eligible" }));
    const stranger = await refused(() => collaboration.decideParticipation(f1.participation_request_id, { accept: true, reason_code: "eligible", adjudicator: generateSigner("worker://frontier-only-lab") }));
    const wrongKey = await refused(() => collaboration.decideParticipation(f1.participation_request_id, { accept: true, reason_code: "eligible", adjudicator: { signer_ref: REPLICATION, privateKey: generateSigner(REPLICATION).privateKey, publicKeyHex: generateSigner(REPLICATION).publicKeyHex } }));
    ok("[federated] a federated request admits, and its decision is UNREACHABLE by the host alone, by an adjudicator that is not a party of the terms, and by a key that is not the adjudicator's key of record — each refused by name, the record still submitted", f1Admitted.ok && !alone.ok && alone.code === "federated_decision_requires_adjudicator" && !stranger.ok && stranger.code === "federation_adjudicator_not_a_party" && !wrongKey.ok && wrongKey.code === "federation_adjudicator_key_mismatch" && (await collaboration.participation(f1.participation_request_id)).revisions?.length === 1, JSON.stringify({ alone, stranger, wrongKey }).slice(0, 500));
    const f1Decided = await refused(() => collaboration.decideParticipation(f1.participation_request_id, { accept: true, reason_code: "eligible", adjudicator: replication }));
    const fRecord = f1Decided.value?.record ?? {};
    const offline = verifyParticipationDecision(fRecord, replication.publicKeyHex);
    ok("[federated] with the adjudicator's key of record the decision admits as a revision: decided by the declared policy path (not the host), co-signed by the adjudicator over the decision material, and verifiable offline; a wrong key does not verify it", f1Decided.ok && fRecord.status === "accepted" && fRecord.decision?.decided_by_ref === FEDERATION_POLICY && fRecord.decision?.adjudicator_ref === REPLICATION && offline.ok && !verifyParticipationDecision(fRecord, generateSigner(REPLICATION).publicKeyHex).ok && fRecord.decision?.federation_signature?.signed_material_hash === deriveParticipationDecisionMaterialHash({ participation_request_id: f1.participation_request_id, request_hash: f1.request_hash, status: "accepted", decided_at: fRecord.decision.decided_at, admission_owner_ref: FEDERATION_POLICY }), JSON.stringify({ f1Decided: f1Decided.ok, decision: fRecord.decision, offline }).slice(0, 600));
    // unreachable without terms acceptance: a second terms record, proposed but not active, and a discovery cannot even be published under it
    await collaboration.proposeTerms(proposal(TERMS_2_ID, sha("second bargain")));
    const noDiscovery = await refused(() => collaboration.publishDiscovery({ ...discoveryDraft("discovery://ioi/collaboration/m112-proof/federated-2", "federated_admission", FEDERATION_POLICY), collaboration_terms_ref: TERMS_2_ID }));
    const staleTerms = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft("alloy-f2", FEDERATED_DISCOVERY, "federated_admission", FEDERATION_POLICY, { collaboration_terms_ref: TERMS_2_ID, collaboration_terms_root: sha("second bargain") }), alloy)));
    ok("[federated] UNREACHABLE WITHOUT TERMS ACCEPTANCE: under terms no party has accepted, no federated projection can be published and no federated request admits", !noDiscovery.ok && noDiscovery.code === "collaboration_terms_not_active" && !staleTerms.ok && staleTerms.code === "collaboration_terms_not_active", JSON.stringify({ noDiscovery, staleTerms }).slice(0, 300));

    // -- restart ------------------------------------------------------------------------------------------------------
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    const reopened = Orchestration.open(clientFor(plane.daemonUrl), orchestration.handle());
    collaboration = new Collaboration(reopened, host);
    const [h1After, fAfter, bundleAfter] = await Promise.all([collaboration.participation(h1.participation_request_id), collaboration.participation(f1.participation_request_id), collaboration.bundle("participant-state://ioi/collaboration/m112-proof/alloy/1")]);
    ok("[restart] a re-attached composer reads the exited participation (3 revisions, same head), the federated acceptance (2 revisions, co-signature verifying offline) and the bundle (verifying offline) from durable admissions", h1After.revisions?.length === 3 && h1After.head === h1Chain.head && h1After.current?.status === "accepted" && h1After.current?.exit !== null && fAfter.revisions?.length === 2 && verifyParticipationDecision(fAfter.current, replication.publicKeyHex).ok && verifyStateBundle(bundleAfter.current ?? {}, host.publicKeyHex).ok, JSON.stringify({ h1: h1After.head, f: fAfter.revisions?.length }).slice(0, 200));
    const lateAlone = await refused(() => collaboration.decideParticipation(h3.participation_request_id, { accept: true, reason_code: "eligible", adjudicator: replication }));
    ok("[restart] the hosted fence holds after restart", !lateAlone.ok && lateAlone.code === "hosted_decision_takes_no_adjudicator", JSON.stringify(lateAlone).slice(0, 200));

    // -- structure ------------------------------------------------------------------------------------------------------
    const appSource = readFileSync(join(REPO, "packages/ioi-ai-orchestration/src/collaboration.ts"), "utf8");
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    ok("[structure] exit and federated admission are application code with no plane: the package names no room or lease object, drives no goal-orchestration route, and the daemon registers no route for the participation successor", !/\b(room|rooms)\b/iu.test(appSource) && !/participant[_ -]lease/iu.test(appSource) && !/goal-orchestration/u.test(appSource) && !/orchestration-participation|portable-exit|state-bundle/u.test(routerSource), "");

    if (MUTATION) {
      ok("DRILL D1 — the decision oracle rejects a decision re-signed by another key and accepts the served one", !verifyParticipationDecision(fRecord, generateSigner(REPLICATION).publicKeyHex).ok && verifyParticipationDecision(fRecord, replication.publicKeyHex).ok, "");
      ok("DRILL D2 — the exit revision is refused as an exit target again and the bundle oracle rejects a smuggled ref", exitAgain.code === "participation_not_accepted" && !verifyStateBundle({ ...bundleRecord, portable_artifact_and_view_refs: ["vault://smuggled"] }, host.publicKeyHex).ok, "");
      ok("DRILL D3 — the refusal predicate reads a composer refusal by its code and an admission as ok", alone.code === "federated_decision_requires_adjudicator" && f1Decided.ok, "");
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
  if (!MUTATION) emitVerifierCensus({ verifierId: "aiip-portable-exit", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  process.exit(passed === results.length ? 0 : 1);
}
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) run();
