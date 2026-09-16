#!/usr/bin/env node
// M11.3 / R-176 — standards bindings as REPLACEABLE TRANSPORTS for the collaboration crossing
// (ACC-13 clause 5): no completion state, task state or registry entry is read as IOI verification,
// acceptance or authority; a binding that cannot be swapped without changing the envelope is not a
// binding.
//
// WHAT IS PROVED, on the isolated daemon and the REAL wallet.network fixture, through the built agent
// SDK and the built @ioi/ioi-ai-orchestration package, against three in-process PEERS speaking the
// A2A, MCP and HTTP/JSON-RPC wire shapes: the SAME signed participation request crosses through all
// three bindings byte-identically (every transport receipt carries the same envelope hash; the host
// admits the first delivery and recognizes the other two as the same submission — one record, one
// revision, one head); a transport's "completed" / "isError:false" / JSON-RPC result leaves the record
// SUBMITTED until the host decides; a peer that alters the envelope in flight is refused by the
// adapter as not-a-binding and the host refuses what it received; a deprecated profile carries
// nothing; a directory that says "registered, reputation 0.99" grants no authority (a signer with no
// terms acceptance is still unknown); the decision is the host's own with no transport state on the
// chain; restart. The registered binding profiles are the contract's own positive fixtures.
//
// WHAT IS NOT CLAIMED. The peers are wire-shape stubs, not conformant A2A/MCP implementations; gRPC,
// OASF directory and chain/escrow bindings are represented by their registered profiles only;
// nothing here settles, verifies or adjudicates.

import { createServer } from "node:http";
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
const SYSTEM_ID = "system://ioi/collaboration/m113-proof";
const GENESIS_ID = "genesis://ioi/collaboration/m113-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/collaboration/m113-proof/v1";
const PACKAGE = "package://ioi/outcome-room"; // the fixture's exact genesis release package; the composition is package-neutral
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE_REF = "app-scope://ioi-ai/objective/m113-proof";
const TERMS_ID = "terms://ioi/collaboration/m113-proof/1";
const DISCOVERY_ID = "discovery://ioi/collaboration/m113-proof/1";
const ALLOY = "worker://independent-alloy-lab";
const ALLOY_SYSTEM = "domain://independent-alloy-lab";
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: (["CollaborationRefusal", "BindingRefusal"].includes(error?.name) ? error.code : "") || daemonCode(error), message: String(error?.message ?? "").slice(0, 300) }; } };
const readFixture = (rel) => JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures", rel), "utf8"));
const sha = (text) => `sha256:${createHashHex(text)}`;
import { createHash } from "node:crypto";
function createHashHex(text) { return createHash("sha256").update(text).digest("hex"); }

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
  body.release.display_name = "Binding-replaceability M11.3 verifier package";
  body.release.description = "Standards bindings as replaceable transports for the collaboration crossing.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/collaboration";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, { systemId: SYSTEM_ID, genesisId: GENESIS_ID, constitutionRef: CONSTITUTION_REF, deploymentProfileRef: `deployment-profile://ioi/collaboration/m113-proof/local/revision/sha256:${"d".repeat(64)}`, orderingProfileRef: "ordering-profile://ioi/collaboration/m113-proof/hosted", oracleProfileRef: "oracle-evidence-profile://ioi/collaboration/m113-proof/fail-closed", lifecycleProfileRef: "lifecycle-profile://ioi/collaboration/m113-proof/default" });
}

async function loadBuilt(rel, hint) {
  const dist = join(REPO, rel);
  requireValue(existsSync(dist), `BLOCKED: build ${hint} first`);
  return await import(pathToFileURL(dist).href);
}

/**
 * A peer speaking one wire shape. It hands every received envelope to `onEnvelope` (the receiving
 * application's own composer) and acknowledges with the hash of WHAT IT RECEIVED, so an adapter can
 * tell whether the transport carried the envelope unchanged. `tamper` simulates a binding that
 * rewrites the envelope in flight.
 */
function startPeer(shape, onEnvelope, { tamper = null } = {}) {
  const hashOf = (envelope) => sha(JSON.stringify(sortKeys({ domain: "ioi.aiip-crossing-envelope-jcs-sha256.v1", contract_id: envelope.contract_id, record: envelope.record })));
  const log = [];
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    let envelope = null;
    if (shape === "http_json_rpc" && req.url === "/rpc" && body.method === "aiip.deliver") envelope = body.params?.envelope;
    else if (shape === "a2a" && req.url === "/tasks/send") envelope = body.message?.parts?.find((p) => p.type === "data")?.data;
    else if (shape === "mcp" && req.url === "/mcp" && body.method === "tools/call" && body.params?.name === "aiip_deliver") envelope = body.params?.arguments;
    else if (shape === "directory" && req.url === "/registry/lookup") { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ registered: true, reputation: 0.99, agent: body.agent })); return; }
    if (!envelope) { res.writeHead(400, { "content-type": "application/json" }); res.end(JSON.stringify({ error: { message: "unsupported" } })); return; }
    if (tamper) envelope = tamper(envelope);
    const received_hash = hashOf(envelope);
    log.push({ shape, received_hash });
    const outcome = await onEnvelope(envelope);
    res.writeHead(200, { "content-type": "application/json" });
    if (shape === "http_json_rpc") res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { received_hash, state: outcome.ok ? "delivered" : "delivered_with_refusal" } }));
    else if (shape === "a2a") res.end(JSON.stringify({ id: body.id, status: { state: "completed" }, artifacts: [{ parts: [{ type: "data", data: { received_hash, host_outcome: outcome.ok ? "admitted" : outcome.code } }] }] }));
    else res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: JSON.stringify({ received_hash, host_outcome: outcome.ok ? "admitted" : outcome.code }) }], isError: false } }));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${server.address().port}`, log, stop: () => new Promise((r) => server.close(r)) })));
}
function sortKeys(value) { if (value === null || typeof value !== "object") return value; if (Array.isArray(value)) return value.map(sortKeys); return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])])); }

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-binding-"));
  let resolver; let plane; const peers = [];
  try {
    const sdk = await loadBuilt("packages/agent-sdk/dist/index.js", "packages/agent-sdk (npm run build --workspace=@ioi/agent-sdk)");
    const app = await loadBuilt("packages/ioi-ai-orchestration/dist/index.js", "packages/ioi-ai-orchestration (npm run build --workspace=@ioi/ioi-ai-orchestration)");
    const { Orchestration, createRuntimeSubstrateClient } = sdk;
    const { A2aBinding, COLLABORATION_CONTRACTS, Collaboration, HttpJsonRpcBinding, McpBinding, buildParticipationRequest, deriveCrossingEnvelopeHash, generateSigner, selectBinding, signerFromSeed } = app;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "binding-operator-password", email: "binding@ioi.local" });
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
    const orchestration = await Orchestration.compose(clientFor(plane.daemonUrl), { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "M11.3 proof: bindings are replaceable transports" });
    let collaboration = new Collaboration(orchestration, host);
    const termsBodyRoot = sha(JSON.stringify({ objective: "replicate the alloy result", version: "1.0.0" }));
    await collaboration.proposeTerms({ collaboration_terms_id: TERMS_ID, version: "1.0.0", predecessor_terms_ref: null, terms_body_hash_profile: "ioi.collaboration-terms-body.v1", terms_body_root: termsBodyRoot, proposed_by_ref: SYSTEM_ID, party_roles: [{ party_ref: SYSTEM_ID, role: "data_owner", acceptance_required: true }, { party_ref: ALLOY, role: "worker_provider", acceptance_required: true }], required_party_refs: [SYSTEM_ID, ALLOY] });
    await collaboration.acceptTerms(TERMS_ID, host);
    const activated = await refused(() => collaboration.acceptTerms(TERMS_ID, alloy));
    const published = await refused(() => collaboration.publishDiscovery({ discovery_id: DISCOVERY_ID, publication_version: "1", public_goal_ref: "goal://ioi/collaboration/m113-proof", public_objective: "Replicate the alloy result under exact terms", public_category_refs: ["ontology://materials/alloys"], coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, participation_channel_ref: "aiip://channel/ioi/collaboration/m113-proof", collaboration_terms_ref: TERMS_ID }));
    ok("PRECONDITION: active terms and a hosted discovery under them", activated.ok && activated.value.activated && published.ok, JSON.stringify({ activated, published: published.ok }).slice(0, 200));

    // -- the registered profiles are the contract's own fixtures --------------------------------------------------
    const profiles = ["positive-a2a-transport.json", "positive-mcp-transport.json", "positive-http-json-rpc-transport.json", "positive-native-aiip.json"].map((n) => readFixture(`aiip-external-protocol-binding-envelope-v1/${n}`));
    ok("[profiles] every registered non-native binding profile names what its states do NOT mean (assurance non-equivalences) and declares its lifecycle mapping; the profiles are the contract's own positive fixtures", profiles.filter((p) => p.protocol_kind !== "native_aiip").every((p) => p.assurance_non_equivalences.length > 0 && p.lifecycle_and_status_mapping_ref && p.status === "active"), JSON.stringify(profiles.map((p) => [p.protocol_kind, p.assurance_non_equivalences.length])));

    // -- the receiving application: every peer hands the envelope to the SAME composer -------------------------------
    const receive = async (envelope) => {
      if (envelope.contract_id !== COLLABORATION_CONTRACTS.participation) return { ok: false, code: "crossing_contract_unsupported" };
      return await refused(() => collaboration.admitParticipation(envelope.record));
    };
    const a2aPeer = await startPeer("a2a", receive); peers.push(a2aPeer);
    const mcpPeer = await startPeer("mcp", receive); peers.push(mcpPeer);
    const rpcPeer = await startPeer("http_json_rpc", receive); peers.push(rpcPeer);
    const tamperPeer = await startPeer("a2a", receive, { tamper: (e) => ({ ...e, record: { ...e.record, capability_offer_refs: [...(e.record.capability_offer_refs ?? []), "capability-offer://rewritten-in-flight"] } }) }); peers.push(tamperPeer);
    const directoryPeer = await startPeer("directory", receive); peers.push(directoryPeer);
    const bindings = {
      a2a: new A2aBinding(selectBinding(profiles, "a2a"), a2aPeer.url),
      mcp: new McpBinding(selectBinding(profiles, "mcp"), mcpPeer.url),
      http_json_rpc: new HttpJsonRpcBinding(selectBinding(profiles, "http_json_rpc"), rpcPeer.url),
    };
    const request = buildParticipationRequest({ participation_request_id: "participation-request://ioi/collaboration/m113-proof/alloy-1", orchestration_ref: SCOPE_REF, discovery_ref: DISCOVERY_ID, coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, requester_system_ref: ALLOY_SYSTEM, collaboration_terms_ref: TERMS_ID, collaboration_terms_root: termsBodyRoot, terms_response: "accept", capability_offer_refs: ["capability-offer://independent-alloy-lab/replication"], eligibility_evidence_refs: ["evidence://independent-alloy-lab/conformance/1"] }, alloy);
    const envelope = { contract_id: COLLABORATION_CONTRACTS.participation, record: request };
    const expectedHash = deriveCrossingEnvelopeHash(envelope);

    // -- substitution: the same envelope through three bindings ----------------------------------------------------------
    const viaA2a = await refused(() => bindings.a2a.deliver(envelope));
    const viaMcp = await refused(() => bindings.mcp.deliver(envelope));
    const viaRpc = await refused(() => bindings.http_json_rpc.deliver(envelope));
    const chain = await collaboration.participation(request.participation_request_id);
    ok("[substitution] the SAME signed request crosses through A2A, MCP and HTTP/JSON-RPC bindings byte-identically: every transport receipt carries the same envelope hash, and the host holds ONE record with ONE revision and ONE head — the first delivery admitted, the other two recognized as the same submission", viaA2a.ok && viaMcp.ok && viaRpc.ok && [viaA2a, viaMcp, viaRpc].every((r) => r.value.envelope_hash === expectedHash) && chain.revisions?.length === 1 && chain.current?.request_hash === request.request_hash && (await orchestration.records(COLLABORATION_CONTRACTS.participation)).count === 1, JSON.stringify({ viaA2a, viaMcp, viaRpc, revisions: chain.revisions?.length }).slice(0, 700));
    ok("[transport ≠ acceptance] A2A said `completed`, MCP said `isError:false`, JSON-RPC returned a result — and the record is still SUBMITTED with no decision: no completion state, task state or tool result is read as IOI acceptance", viaA2a.value?.transport_state === "completed" && viaMcp.value?.transport_state === "isError:false" && viaRpc.value?.transport_state === "delivered" && chain.current?.status === "submitted" && chain.current?.decision === null, JSON.stringify({ states: [viaA2a.value?.transport_state, viaMcp.value?.transport_state, viaRpc.value?.transport_state], status: chain.current?.status }));

    // -- a binding that alters the envelope is not a binding -----------------------------------------------------------------
    const request2 = buildParticipationRequest({ participation_request_id: "participation-request://ioi/collaboration/m113-proof/alloy-2", orchestration_ref: SCOPE_REF, discovery_ref: DISCOVERY_ID, coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, requester_system_ref: ALLOY_SYSTEM, collaboration_terms_ref: TERMS_ID, collaboration_terms_root: termsBodyRoot, terms_response: "accept" }, alloy);
    const tampering = new A2aBinding(selectBinding(profiles, "a2a"), tamperPeer.url);
    const viaTamper = await refused(() => tampering.deliver({ contract_id: COLLABORATION_CONTRACTS.participation, record: request2 }));
    const countAfterTamper = (await orchestration.records(COLLABORATION_CONTRACTS.participation)).count;
    ok("[not a binding] a peer that rewrites the envelope in flight: the adapter refuses by name (the received hash is not the envelope's) and the host refused what arrived (its hash no longer recomputes) — nothing admitted", !viaTamper.ok && viaTamper.code === "binding_altered_envelope" && countAfterTamper === 1 && tamperPeer.log.length === 1, JSON.stringify({ viaTamper, countAfterTamper }).slice(0, 300));
    const deprecated = { ...selectBinding(profiles, "a2a"), binding_id: "aiip-binding://ioi/a2a/v0", status: "deprecated" };
    const inactive = await refused(() => selectBinding([deprecated], "a2a"));
    const constructInactive = await refused(() => new A2aBinding(deprecated, a2aPeer.url));
    const equivalence = await refused(() => new McpBinding({ ...selectBinding(profiles, "mcp"), assurance_non_equivalences: [] }, mcpPeer.url));
    ok("[profiles] a deprecated profile carries nothing (refused at selection and at construction) and a non-native profile that records no non-equivalence is refused as claiming an equivalence", !inactive.ok && inactive.code === "binding_not_active" && !constructInactive.ok && constructInactive.code === "binding_not_active" && !equivalence.ok && equivalence.code === "binding_claims_equivalence", JSON.stringify({ inactive, constructInactive, equivalence }).slice(0, 400));

    // -- a registry entry is not authority ---------------------------------------------------------------------------------
    const stranger = generateSigner("worker://frontier-only-lab");
    const lookup = await jsonCall(directoryPeer.url, "POST", "/registry/lookup", { agent: stranger.signer_ref });
    const strangerRequest = buildParticipationRequest({ participation_request_id: "participation-request://ioi/collaboration/m113-proof/frontier-1", orchestration_ref: SCOPE_REF, discovery_ref: DISCOVERY_ID, coordination_topology: "hosted_admission", admission_owner_ref: SYSTEM_ID, requester_system_ref: "domain://frontier-only-lab", collaboration_terms_ref: TERMS_ID, collaboration_terms_root: termsBodyRoot, terms_response: "accept" }, stranger);
    const viaRpcStranger = await refused(() => bindings.http_json_rpc.deliver({ contract_id: COLLABORATION_CONTRACTS.participation, record: strangerRequest }));
    const strangerChain = await refused(() => collaboration.participation(strangerRequest.participation_request_id));
    ok("[registry ≠ authority] a directory that answers `registered: true, reputation 0.99` for a signer grants nothing: the transport carries the request faithfully and the host refuses it — the signer accepted no terms and has no key of record", lookup.body?.registered === true && lookup.body?.reputation === 0.99 && viaRpcStranger.ok && !strangerChain.ok && rpcPeer.log.length === 2 && (await orchestration.records(COLLABORATION_CONTRACTS.participation)).count === 1, JSON.stringify({ lookup: lookup.body, viaRpcStranger: viaRpcStranger.ok, strangerChain }).slice(0, 300));

    // -- the decision is the host's, and no transport state is on the chain -------------------------------------------------
    const decided = await refused(() => collaboration.decideParticipation(request.participation_request_id, { accept: true, reason_code: "eligible_after_host_review" }));
    const decidedText = JSON.stringify(decided.value?.record ?? {});
    ok("[decision] acceptance comes only from the host's own decision revision, after three transports had already reported completion; the record carries no binding, transport, task or registry member", decided.ok && decided.value.record?.status === "accepted" && decided.value.record?.decision?.reason_code === "eligible_after_host_review" && !/\b(binding_id|protocol_kind|transport_state|task_id|task_state|registry|reputation|received_hash)\b/u.test(decidedText), decidedText.slice(0, 300));

    // -- restart -----------------------------------------------------------------------------------------------------------
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    collaboration = new Collaboration(Orchestration.open(clientFor(plane.daemonUrl), orchestration.handle()), host);
    const after = await collaboration.participation(request.participation_request_id);
    const redelivered = await refused(() => bindings.mcp.deliver(envelope));
    ok("[restart] the accepted participation is reproduced from durable admissions (2 revisions, same head); a re-delivery of the original submission over another binding after the decision is recognized and changes nothing", after.revisions?.length === 2 && after.head === decided.value?.expected_head_for_successor && redelivered.ok && (await collaboration.participation(request.participation_request_id)).head === after.head, JSON.stringify({ after: after.head, redelivered }).slice(0, 300));

    // -- structure -----------------------------------------------------------------------------------------------------------
    const bindingsSource = readFileSync(join(REPO, "packages/ioi-ai-orchestration/src/bindings.ts"), "utf8");
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    ok("[structure] bindings are application-layer adapters with no plane: the module names no room or lease, imports no daemon route, and the daemon registers no route for the crossing (no aiip/a2a/mcp crossing route)", !/\b(room|rooms)\b/iu.test(bindingsSource) && !/participant[_ -]lease/iu.test(bindingsSource) && !/goal-orchestration|\/v1\/hypervisor\//u.test(bindingsSource) && !/"\/v1\/[^"]*(?:aiip|a2a|mcp-crossing)[^"]*"/u.test(routerSource), "");

    if (MUTATION) {
      ok("DRILL D1 — the envelope hash oracle changes when the record changes and holds when the transport changes", deriveCrossingEnvelopeHash({ ...envelope, record: { ...request, terms_response: "decline" } }) !== expectedHash && deriveCrossingEnvelopeHash(envelope) === expectedHash, "");
      ok("DRILL D2 — the tampering peer's receipt disagrees with the envelope hash and the honest peers' receipts agree", tamperPeer.log[0]?.received_hash !== deriveCrossingEnvelopeHash({ contract_id: COLLABORATION_CONTRACTS.participation, record: request2 }) && a2aPeer.log[0]?.received_hash === expectedHash, "");
      ok("DRILL D3 — the refusal predicate reads a binding refusal by its code and a delivery as ok", viaTamper.code === "binding_altered_envelope" && viaA2a.ok, "");
    }
  } catch (error) {
    ok("the verifier completed", false, String(error?.stack || error).slice(0, 1200));
  } finally {
    for (const peer of peers) { try { await peer.stop(); } catch {} }
    try { await plane?.stop(); } catch {}
    try { await resolver?.stop(); } catch {}
    try { rmSync(dataDir, { recursive: true, force: true }); } catch {}
  }
  const passed = results.filter((r) => r.pass).length;
  console.log(`${passed}/${results.length} passed`);
  if (!MUTATION) emitVerifierCensus({ verifierId: "aiip-binding-replaceability", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  process.exit(passed === results.length ? 0 : 1);
}
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) run();
