#!/usr/bin/env node
// R-172 S3 / M11.1 — collaboration terms, discovery and typed participation COMPOSED in the ioi.ai
// application over thread orchestration primitives and the System-record seam (ACC-13 clauses 1, 2,
// 3 and N1).
//
// WHAT IS PROVED, on the isolated daemon and the REAL wallet.network fixture, through the built
// agent SDK and the built @ioi-ai/orchestration package: CollaborationTerms v3 admitted under the
// bounded System with activation DERIVED from exact-root acceptances (a discovery publication is
// refused before every required party has accepted; the activation names the seam receipts of the
// acceptance revisions); an OrchestrationDiscovery projection admitted only under active terms, its
// state root recomputed and its host signature verified; an OrchestrationParticipationRequest built
// and signed by an external party, verified by the host against the key that party accepted the
// terms with, admitted, and DECIDED as a successor revision citing the submission's seam receipt;
// the same-system negative (a request from inside the host system_id is refused and admits nothing);
// forged, tampered, stale-root and unknown-signer requests refused by name; a ParticipantStateBundle
// produced least-disclosing (every excluded-class ref dropped), host-signed, and verified OFFLINE
// with nothing but the bundle and the host's key; restart with a re-attached composer.
//
// WHAT IS NOT CLAIMED. No daemon route exists for any of this and none is asserted: the router is
// checked to register nothing for the successor contracts. The parties' ed25519 keys are derived
// from the fixture's known seeds for determinism; their binding to wallet.network identities is not
// this gate's claim (the key of record is the key that accepted the terms). The crosswalk crossing
// (ACC-13 clause 4) and portable exit/federated admission (M11.2) are not exercised here.

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
const SYSTEM_ID = "system://ioi/collaboration/s3-proof";
const GENESIS_ID = "genesis://ioi/collaboration/s3-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/collaboration/s3-proof/v1";
const PACKAGE = "package://ioi/outcome-room"; // the fixture's exact genesis release package; the composition is package-neutral
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE_REF = "app-scope://ioi-ai/objective/s3-proof";
const TERMS_ID = "terms://ioi/collaboration/s3-proof/1";
const DISCOVERY_ID = "discovery://ioi/collaboration/s3-proof/1";
const ALLOY = "worker://independent-alloy-lab";
const ALLOY_SYSTEM = "domain://independent-alloy-lab";
const REPLICATION = "worker://replication-lab-two";
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: (error?.name === "CollaborationRefusal" ? error.code : "") || daemonCode(error), message: String(error?.message ?? "").slice(0, 300) }; } };
const sha = (text) => `sha256:${createHash("sha256").update(text).digest("hex")}`;
/** Key-order independent equality: the daemon serves objects with sorted keys, a re-derivation carries insertion order. */
const jcs = (value) => { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`; return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`; };

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
  body.release.display_name = "Collaboration S3 verifier package";
  body.release.description = "Collaboration terms, discovery and participation composed over thread primitives under a bounded System.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/collaboration";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, { systemId: SYSTEM_ID, genesisId: GENESIS_ID, constitutionRef: CONSTITUTION_REF, deploymentProfileRef: `deployment-profile://ioi/collaboration/s3-proof/local/revision/sha256:${"d".repeat(64)}`, orderingProfileRef: "ordering-profile://ioi/collaboration/s3-proof/hosted", oracleProfileRef: "oracle-evidence-profile://ioi/collaboration/s3-proof/fail-closed", lifecycleProfileRef: "lifecycle-profile://ioi/collaboration/s3-proof/default" });
}

async function loadBuilt(rel, hint) {
  const dist = join(REPO, rel);
  requireValue(existsSync(dist), `BLOCKED: build ${hint} first`);
  return await import(pathToFileURL(dist).href);
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-collaboration-"));
  let resolver; let plane;
  try {
    const sdk = await loadBuilt("packages/agent-sdk/dist/index.js", "packages/agent-sdk (npm run build --workspace=@ioi/agent-sdk)");
    const app = await loadBuilt("apps/ioi-ai/orchestration/dist/index.js", "apps/ioi-ai/orchestration (npm run build --workspace=@ioi-ai/orchestration)");
    const { Orchestration, createRuntimeSubstrateClient } = sdk;
    const { COLLABORATION_CONTRACTS, Collaboration, buildParticipationRequest, deriveBundleRoot, deriveDiscoveryStateRoot, deriveParticipationRequestHash, deriveTermsActivation, generateSigner, signerFromSeed, verifySignatureEnvelope, verifyStateBundle } = app;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "collaboration-operator-password", email: "collaboration@ioi.local" });
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
    const orchestration = await Orchestration.compose(clientFor(plane.daemonUrl), { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "S3 proof: collaboration composed over primitives" });
    let collaboration = new Collaboration(orchestration, host);
    const count = async (contract) => (await orchestration.records(contract)).count;

    // -- clause 1: terms precede the crossing --------------------------------------------------------------
    const termsBodyRoot = sha(JSON.stringify({ objective: "replicate the alloy result", version: "1.0.0" }));
    const proposed = await refused(() => collaboration.proposeTerms({
      collaboration_terms_id: TERMS_ID, version: "1.0.0", predecessor_terms_ref: null, terms_body_hash_profile: "ioi.collaboration-terms-body.v1", terms_body_root: termsBodyRoot,
      proposed_by_ref: SYSTEM_ID, party_roles: [{ party_ref: SYSTEM_ID, role: "coordinator", acceptance_required: true }, { party_ref: ALLOY, role: "worker_provider", acceptance_required: true }],
      required_party_refs: [SYSTEM_ID, ALLOY],
    }));
    ok("[terms] the proposal admits under the System through the record seam as an ordinary record: status proposed, no acceptances, activation null, binding derived with the composition's scope as parent", proposed.ok && proposed.value.record?.status === "proposed" && proposed.value.record?.activation === null && proposed.value.record?.system_binding?.parent_scope_ref === SCOPE_REF && proposed.value.record?.system_binding?.system_id === SYSTEM_ID, JSON.stringify(proposed).slice(0, 400));
    const discoveryDraft = { discovery_id: DISCOVERY_ID, publication_version: "1", public_goal_ref: "goal://ioi/collaboration/s3-proof", public_objective: "Replicate the alloy result under exact terms", public_category_refs: ["ontology://materials/alloys"], coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, participation_channel_ref: "aiip://channel/ioi/collaboration/s3-proof", collaboration_terms_ref: TERMS_ID };
    const early = await refused(() => collaboration.publishDiscovery(discoveryDraft));
    ok("[terms] NOTHING CROSSES BEFORE ACCEPTANCE: a discovery publication under proposed terms is refused by the composer by name and no discovery record is admitted", !early.ok && early.code === "collaboration_terms_not_active" && (await count(COLLABORATION_CONTRACTS.discovery)) === 0, JSON.stringify(early).slice(0, 300));
    const hostAccept = await refused(() => collaboration.acceptTerms(TERMS_ID, host));
    ok("[terms] the host's exact-root acceptance appends as a revision and does NOT activate: one required party is still missing", hostAccept.ok && hostAccept.value.activated === false && hostAccept.value.admitted.record?.status === "proposed" && hostAccept.value.admitted.record?.acceptances?.length === 1, JSON.stringify(hostAccept).slice(0, 300));
    const stillEarly = await refused(() => collaboration.publishDiscovery(discoveryDraft));
    ok("[terms] still nothing crosses with one acceptance of two", !stillEarly.ok && stillEarly.code === "collaboration_terms_not_active" && (await count(COLLABORATION_CONTRACTS.discovery)) === 0, JSON.stringify(stillEarly).slice(0, 200));
    const alloyAccept = await refused(() => collaboration.acceptTerms(TERMS_ID, alloy));
    const termsChain = await collaboration.terms(TERMS_ID);
    const activation = termsChain.current?.activation;
    const priorReceipts = (termsChain.admissions ?? []).slice(0, 2).map((a) => a.receipt_ref);
    ok("[terms] the second required party's acceptance ACTIVATES: activation is derived (unanimous, accepted_root = the terms root, accepted parties = exactly the two acceptors) and names the seam receipts of the two prior admissions; the chain holds three revisions", alloyAccept.ok && alloyAccept.value.activated === true && termsChain.current?.status === "active" && activation?.accepted_root === termsBodyRoot && JSON.stringify(activation?.accepted_party_refs) === JSON.stringify([SYSTEM_ID, ALLOY].sort()) && JSON.stringify(activation?.acceptance_receipt_refs) === JSON.stringify(priorReceipts) && priorReceipts.every((r) => typeof r === "string" && r.startsWith("receipt://")) && termsChain.revisions?.length === 3, JSON.stringify({ alloyAccept, activation, priorReceipts }).slice(0, 600));
    const rederived = deriveTermsActivation(termsChain.current, activation?.acceptance_receipt_refs ?? [], activation?.activated_at ?? "");
    ok("[terms] the served activation re-derives offline from the served acceptances (the composer authored nothing the record does not prove)", jcs(rederived) === jcs(activation) && termsChain.current?.acceptances?.every((a) => verifySignatureEnvelope(a.signature, a.signature.signed_material_hash)), "");
    const uninvited = await refused(() => collaboration.acceptTerms(TERMS_ID, replication));
    const twice = await refused(() => collaboration.acceptTerms(TERMS_ID, alloy));
    ok("[terms] an active bargain is not open for further acceptance, from a party the terms do not require or from one that already accepted — both refused by name, nothing admitted", !uninvited.ok && uninvited.code === "collaboration_terms_not_open_for_acceptance" && !twice.ok && twice.code === "collaboration_terms_not_open_for_acceptance" && (await collaboration.terms(TERMS_ID)).revisions?.length === 3, JSON.stringify({ uninvited, twice }).slice(0, 300));

    // -- clause 2: discovery is a projection ------------------------------------------------------------------
    const published = await refused(() => collaboration.publishDiscovery(discoveryDraft));
    const discovery = published.value?.record ?? {};
    ok("[discovery] under active terms the publication admits: discoverable, naming the exact active terms root, private_context_included false, every excluded context class listed, the state root recomputed offline and the host's signature verified over it", published.ok && discovery.status === "discoverable" && discovery.collaboration_terms_root === termsBodyRoot && discovery.private_context_included === false && discovery.excluded_context_classes?.length === 6 && deriveDiscoveryStateRoot(discovery) === discovery.discovery_state_root && verifySignatureEnvelope(discovery.signature, discovery.discovery_state_root, host.publicKeyHex) && discovery.system_binding?.parent_scope_ref === SCOPE_REF, JSON.stringify(published).slice(0, 500));

    // -- clause 3 + N1: participation ---------------------------------------------------------------------------
    const draft = (over = {}) => ({ participation_request_id: "participation-request://ioi/collaboration/s3-proof/alloy-1", orchestration_ref: SCOPE_REF, discovery_ref: DISCOVERY_ID, coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, requester_system_ref: ALLOY_SYSTEM, collaboration_terms_ref: TERMS_ID, collaboration_terms_root: termsBodyRoot, terms_response: "accept", capability_offer_refs: ["capability-offer://independent-alloy-lab/replication"], eligibility_evidence_refs: ["evidence://independent-alloy-lab/conformance/1"], ...over });
    const sameSystem = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft({ participation_request_id: "participation-request://ioi/collaboration/s3-proof/inside-1", requester_system_ref: SYSTEM_ID }), alloy)));
    ok("[N1] NO AIIP PATH INSIDE ONE SYSTEM: a request whose requester system is the host's own system_id is refused by the composer and admits nothing (work inside the System is a delegation, a subagent of the coordinating thread)", !sameSystem.ok && sameSystem.code === "same_system_participation_refused" && (await count(COLLABORATION_CONTRACTS.participation)) === 0, JSON.stringify(sameSystem).slice(0, 300));
    const unknownSigner = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft({ participation_request_id: "participation-request://ioi/collaboration/s3-proof/repl-1", requester_system_ref: "domain://replication-lab-two" }), replication)));
    const forged = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft(), { signer_ref: ALLOY, privateKey: generateSigner(ALLOY).privateKey, publicKeyHex: generateSigner(ALLOY).publicKeyHex })));
    const genuine = buildParticipationRequest(draft(), alloy);
    const tampered = await refused(() => collaboration.admitParticipation({ ...genuine, capability_offer_refs: [...genuine.capability_offer_refs, "capability-offer://independent-alloy-lab/added-after-signing"] }));
    const staleRoot = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft({ collaboration_terms_root: sha("another bargain") }), alloy)));
    ok("[participation] the host verifies against the KEY OF RECORD — the one the party accepted the terms with: a party with no acceptance has no key (unknown signer), a fresh key claiming the party's name does not verify (forged), a body edited after signing does not recompute (tampered), and a request naming a root that is not the active one is refused (stale root); none admits", !unknownSigner.ok && unknownSigner.code === "participation_signer_unknown" && !forged.ok && forged.code === "participation_signature_invalid" && !tampered.ok && tampered.code === "participation_request_hash_mismatch" && !staleRoot.ok && staleRoot.code === "collaboration_terms_root_mismatch" && (await count(COLLABORATION_CONTRACTS.participation)) === 0, JSON.stringify({ unknownSigner, forged, tampered, staleRoot }).slice(0, 600));
    const submitted = await refused(() => collaboration.admitParticipation(genuine));
    ok("[participation] the external party's genuine request admits as SUBMITTED with no decision: its hash recomputes, its signature verifies against the acceptance key, it names the discoverable projection and the active root, and the binding is derived", submitted.ok && submitted.value.record?.status === "submitted" && submitted.value.record?.decision === null && submitted.value.record?.request_hash === deriveParticipationRequestHash(genuine) && submitted.value.record?.system_binding?.parent_scope_ref === SCOPE_REF && typeof submitted.value.receipt_ref === "string", JSON.stringify(submitted).slice(0, 400));
    const decided = await refused(() => collaboration.decideParticipation(genuine.participation_request_id, { accept: true, reason_code: "terms_root_active_and_eligible" }));
    const partChain = await collaboration.participation(genuine.participation_request_id);
    ok("[participation] THE DECISION IS A REVISION, NOT AN OBJECT: accepted as the second revision of the same record, citing the seam receipt of the submission it answers; the request hash is unchanged; no lease, roster or membership object exists anywhere", decided.ok && decided.value.record?.status === "accepted" && decided.value.record?.decision?.receipt_ref === submitted.value?.receipt_ref && decided.value.record?.decision?.decided_by_ref === SYSTEM_ID && decided.value.record?.request_hash === genuine.request_hash && partChain.revisions?.length === 2 && partChain.head === decided.value.expected_head_for_successor, JSON.stringify({ decided, head: partChain.head }).slice(0, 500));
    const again = await refused(() => collaboration.decideParticipation(genuine.participation_request_id, { accept: false, reason_code: "changed_mind" }));
    ok("[participation] a decided request is not decided again", !again.ok && again.code === "participation_already_decided", JSON.stringify(again).slice(0, 200));

    // -- clause 3: the least-disclosing bundle -----------------------------------------------------------------
    const candidates = [
      { slot: "preserved_contribution_attempt_finding_and_result_refs", ref: "attempt://ioi/collaboration/s3-proof/alloy/1", context_class: "contribution_lineage" },
      { slot: "preserved_receipt_acceptance_settlement_and_dispute_refs", ref: submitted.value.receipt_ref, context_class: "receipt" },
      { slot: "portable_artifact_and_view_refs", ref: "artifact://ioi/collaboration/s3-proof/alloy/report", context_class: "portable_artifact" },
      { slot: "portable_artifact_and_view_refs", ref: "vault://ioi/collaboration/s3-proof/api-key", context_class: "raw_secret" },
      { slot: "lineage_and_supersession_refs", ref: "agentgres://ioi/collaboration/s3-proof/private-state", context_class: "private_orchestration_state" },
      { slot: "released_future_access_refs", ref: "context-lease://ioi/collaboration/s3-proof/alloy", context_class: "future_access" },
    ];
    const produced = await refused(() => collaboration.produceStateBundle({ participant_state_bundle_id: "participant-state://ioi/collaboration/s3-proof/alloy/1", participation_request_id: genuine.participation_request_id, participant_and_home_domain_refs: [ALLOY, ALLOY_SYSTEM], bundle_reason: "checkpoint", source_admission_watermark_ref: partChain.head, candidate_refs: candidates, bundle_artifact_ref: "artifact://ioi/collaboration/s3-proof/alloy/bundle-1" }));
    const bundle = produced.value?.admitted?.record ?? {};
    const bundleText = JSON.stringify(bundle);
    const offline = verifyStateBundle(bundle, host.publicKeyHex);
    ok("[bundle] the bundle is LEAST-DISCLOSING and VERIFIES OFFLINE: the raw-secret and private-state refs never enter it (the composer reports them excluded), every allowed ref lands in its slot, all seven excluded classes are listed, hosted_database_access_required is false, the root recomputes and the host's signature verifies with nothing but the bundle and the key", produced.ok && produced.value.excluded.length === 2 && !bundleText.includes("vault://") && !bundleText.includes("private-state") && bundle.portable_artifact_and_view_refs?.length === 1 && bundle.preserved_receipt_acceptance_settlement_and_dispute_refs?.[0] === submitted.value.receipt_ref && bundle.excluded_context_classes?.length === 7 && bundle.hosted_database_access_required === false && deriveBundleRoot(bundle) === bundle.bundle_root && offline.ok, JSON.stringify({ produced: produced.ok, excluded: produced.value?.excluded?.length, offline, bundle: bundleText.slice(0, 300) }).slice(0, 700));
    const wrongKey = verifyStateBundle(bundle, generateSigner(SYSTEM_ID).publicKeyHex);
    const smuggled = verifyStateBundle({ ...bundle, portable_artifact_and_view_refs: [...(bundle.portable_artifact_and_view_refs ?? []), "vault://smuggled"] }, host.publicKeyHex);
    ok("[bundle] offline verification refuses a bundle under another key claiming the host's name and a bundle with a ref added after signing", !wrongKey.ok && !smuggled.ok && smuggled.findings.some((f) => /bundle_root/u.test(f)), JSON.stringify({ wrongKey, smuggled }).slice(0, 300));
    const refusedRequest = buildParticipationRequest(draft({ participation_request_id: "participation-request://ioi/collaboration/s3-proof/alloy-2" }), alloy);
    await refused(() => collaboration.admitParticipation(refusedRequest));
    await refused(() => collaboration.decideParticipation(refusedRequest.participation_request_id, { accept: false, reason_code: "capacity" }));
    const noBundle = await refused(() => collaboration.produceStateBundle({ participant_state_bundle_id: "participant-state://ioi/collaboration/s3-proof/alloy/2", participation_request_id: refusedRequest.participation_request_id, participant_and_home_domain_refs: [ALLOY], bundle_reason: "checkpoint", source_admission_watermark_ref: partChain.head, candidate_refs: [], bundle_artifact_ref: "artifact://ioi/collaboration/s3-proof/alloy/bundle-2" }));
    ok("[bundle] a bundle is produced for an ACCEPTED participation only: a refused one gets none", !noBundle.ok && noBundle.code === "participation_not_accepted" && (await count(COLLABORATION_CONTRACTS.bundle)) === 1, JSON.stringify(noBundle).slice(0, 200));

    // -- restart ---------------------------------------------------------------------------------------------------
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    const reopened = Orchestration.open(clientFor(plane.daemonUrl), orchestration.handle());
    collaboration = new Collaboration(reopened, host);
    const [termsAfter, discAfter, partAfter, bundleAfter] = await Promise.all([collaboration.terms(TERMS_ID), collaboration.discovery(DISCOVERY_ID), collaboration.participation(genuine.participation_request_id), collaboration.bundle(bundle.participant_state_bundle_id)]);
    ok("[restart] a re-attached composer reads the same four chains from durable admissions: active terms (3 revisions), the discoverable projection, the accepted participation (2 revisions, same head) and the bundle, which still verifies offline", termsAfter.current?.status === "active" && termsAfter.revisions?.length === 3 && termsAfter.head === termsChain.head && discAfter.current?.status === "discoverable" && partAfter.revisions?.length === 2 && partAfter.head === partChain.head && verifyStateBundle(bundleAfter.current ?? {}, host.publicKeyHex).ok, JSON.stringify({ terms: termsAfter.head, part: partAfter.head }).slice(0, 300));
    const lateSame = await refused(() => collaboration.admitParticipation(buildParticipationRequest(draft({ participation_request_id: "participation-request://ioi/collaboration/s3-proof/inside-2", requester_system_ref: SYSTEM_ID }), alloy)));
    ok("[restart] the same-system negative holds after restart", !lateSame.ok && lateSame.code === "same_system_participation_refused", JSON.stringify(lateSame).slice(0, 200));

    // -- structure -------------------------------------------------------------------------------------------------
    const appSource = readFileSync(join(REPO, "apps/ioi-ai/orchestration/src/collaboration.ts"), "utf8");
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    ok("[structure] the composition is application code with no plane: the package names no room or participant lease, drives no goal-orchestration route, and the daemon registers no route for the successor contracts (orchestration-discovery, orchestration-participation-request, participant-state-bundle)", !/\b(room|rooms)\b/iu.test(appSource) && !/participant[_ -]lease/iu.test(appSource) && !/goal-orchestration/u.test(appSource) && !/orchestration-discovery|orchestration-participation|participant-state-bundle|state-bundle/u.test(routerSource), "");

    if (MUTATION) {
      ok("DRILL D1 — the three root oracles reject an edited body and accept the served one", deriveDiscoveryStateRoot({ ...discovery, public_objective: "edited" }) !== discovery.discovery_state_root && deriveParticipationRequestHash({ ...genuine, terms_response: "decline" }) !== genuine.request_hash && deriveBundleRoot({ ...bundle, issued_at: "2000-01-01T00:00:00Z" }) !== bundle.bundle_root && deriveBundleRoot(bundle) === bundle.bundle_root, "");
      ok("DRILL D2 — the activation oracle yields null when a required party is missing and re-derives the served activation otherwise", deriveTermsActivation({ ...termsChain.current, acceptances: termsChain.current.acceptances.slice(0, 1) }, [], "x") === null && jcs(deriveTermsActivation(termsChain.current, activation.acceptance_receipt_refs, activation.activated_at)) === jcs(activation), "");
      ok("DRILL D3 — the signature oracle rejects a wrong key and the refusal predicate reads a composer refusal by its code", !verifySignatureEnvelope(discovery.signature, discovery.discovery_state_root, generateSigner(SYSTEM_ID).publicKeyHex) && sameSystem.code === "same_system_participation_refused" && submitted.ok, "");
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
  if (!MUTATION) emitVerifierCensus({ verifierId: "aiip-collaboration-discovery", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  process.exit(passed === results.length ? 0 : 1);
}
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) run();
