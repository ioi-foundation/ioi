#!/usr/bin/env node
// R-172 S2 — an orchestration COMPOSED from thread orchestration primitives, node-graph style.
//
// WHAT IS PROVED. Through the agent SDK's composer and the real daemon on the real wallet fixture:
// a coordinating thread is the root; delegations are subagents of that thread (ADR 0034); claims
// are exact-head, per-dimension reservations on the work-lifecycle plane (M04.10) whose first
// admission names the genesis head; the application's typed records admit under the bounded System
// through the system-record seam (R-172 S1) with the binding DERIVED and the application's own
// scope as parent; the graph is projected from the primitives' own reads, is deterministic, names
// its provenance, and is re-derived identically by a re-attached composer after a daemon restart.
//
// WHAT IS NOT CLAIMED. No coordination plane exists and none is asserted: no object is minted for
// the composition, no roster is served, no authority crosses. The subagents' RUNS are the kernel's
// (an isolated plane has no model behind them, so their run status is reported, not asserted). The
// application vocabulary contracts that still bind to OutcomeRoom members (attempt, finding, …)
// are NOT exercised here; their re-cut is a later slice, and this gate speaks only the
// frontier-item contract the S1 gate already proved.
//
// TWO DRIVEN-RUN FINDINGS this gate made reachable (fixed in the same cut, unit-tested in the route):
// the reservation route read no head on an empty stream and refused every first claim as "moved
// against <genesis>", and its stream tail carried a `/` outside the substrate's canonical alphabet
// so Agentgres refused every claim as CoordinatesNotCanonical. The M04.10 gate was structural.

import { mkdtempSync, readFileSync, readdirSync, rmSync, existsSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import { bootstrapActiveSystem, exactGenesisBody, rebindGenesisBodySystem, recomputeReleaseHashes } from "./verify-hypervisor-system-sequence-zero-materialization.mjs";
import { derivePayloadRoot as gatePayloadRoot } from "./verify-hypervisor-system-record-seam.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const MUTATION = process.argv.includes("--mutation");
const SYSTEM_ID = "system://ioi/orchestration/s2-proof";
const GENESIS_ID = "genesis://ioi/orchestration/s2-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/orchestration/s2-proof/v1";
const PACKAGE = "package://ioi/outcome-room"; // the fixture's exact genesis release package; the composition is package-neutral
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const CONTRACT = "schema://ioi/applications/ioi-ai/work-frontier-item/v3";
const SCOPE_REF = "app-scope://ioi-ai/objective/s2-proof";
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const readFixture = (rel) => JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures", rel), "utf8"));
/** The daemon's typed refusal as the SDK carries it: the raw body under details.daemon. */
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: daemonCode(error), message: String(error?.message ?? "") }; } };
let counter = 0; const key = (p) => `${p}-${Date.now()}-${++counter}`;

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
  body.release.display_name = "Orchestration S2 verifier package";
  body.release.description = "An orchestration composed from thread primitives under a bounded System.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/orchestration";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, { systemId: SYSTEM_ID, genesisId: GENESIS_ID, constitutionRef: CONSTITUTION_REF, deploymentProfileRef: `deployment-profile://ioi/orchestration/s2-proof/local/revision/sha256:${"d".repeat(64)}`, orderingProfileRef: "ordering-profile://ioi/orchestration/s2-proof/hosted", oracleProfileRef: "oracle-evidence-profile://ioi/orchestration/s2-proof/fail-closed", lifecycleProfileRef: "lifecycle-profile://ioi/orchestration/s2-proof/default" });
}

async function loadSdk() {
  const dist = join(REPO, "packages", "agent-sdk", "dist", "index.js");
  requireValue(existsSync(dist), "BLOCKED: build packages/agent-sdk first (npm run build --workspace=@ioi/agent-sdk)");
  return await import(pathToFileURL(dist).href);
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-orchestration-"));
  let resolver; let plane;
  try {
    const sdk = await loadSdk();
    const { Orchestration, RESERVATION_GENESIS_HEAD, createRuntimeSubstrateClient, deriveSystemRecordPayloadRoot, projectOrchestrationGraph, reservationStreamTail } = sdk;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "orchestration-operator-password", email: "orchestration@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    const clientFor = (url) => createRuntimeSubstrateClient({ endpoint: url, headers: operatorHeaders });
    let client = clientFor(plane.daemonUrl);

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", typeof active.source?.record?.governing_authority_ref === "string", JSON.stringify(active).slice(0, 300));

    // -- the root: a coordinating thread, kernel-owned -----------------------------------------------------
    const orchestration = await Orchestration.compose(client, { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "S2 proof: compose an orchestration from primitives" });
    const threadId = orchestration.thread_id;
    const thread = await call("GET", `/v1/threads/${encodeURIComponent(threadId)}`, undefined);
    ok("[root] composing creates a coordinating thread through POST /v1/threads and the kernel serves it back: the root of the graph is a thread record, not a coordination object", typeof threadId === "string" && threadId.length > 0 && thread.status === 200 && thread.body?.thread_id === threadId && thread.body?.status === "active", `${thread.status} ${JSON.stringify(thread.body).slice(0, 200)}`);

    // -- delegations: subagents of the root (ADR 0034) ----------------------------------------------------------
    const worker = await refused(() => orchestration.delegate({ prompt: "carry the first unit of work", role: "worker" }));
    const reviewer = await refused(() => orchestration.delegate({ prompt: "review the first unit of work", role: "reviewer" }));
    const listed = await orchestration.delegations();
    const subagentIds = (listed.subagents ?? []).map((s) => s.subagent_id);
    ok("[delegate] two delegations are two subagents of the coordinating thread (ADR 0034), each bound to it by parent_thread_id, distinct, and listed by the kernel under that thread", worker.ok && reviewer.ok && worker.value.parent_thread_id === threadId && reviewer.value.parent_thread_id === threadId && worker.value.subagent_id !== reviewer.value.subagent_id && worker.value.role === "worker" && reviewer.value.role === "reviewer" && subagentIds.includes(worker.value.subagent_id) && subagentIds.includes(reviewer.value.subagent_id), JSON.stringify({ worker, reviewer, subagentIds }).slice(0, 1400));
    console.log(`INFO  delegated runs (kernel-owned, no model behind an isolated plane): ${JSON.stringify((listed.subagents ?? []).map((s) => ({ id: s.subagent_id, run: s.run_id, status: s.lifecycle_status ?? s.status })))}`);

    // -- claims: exact-head reservations on the work-lifecycle plane (M04.10) -----------------------------------
    const chain = [`thread://${threadId}`, TENANT];
    const bounds = [{ ancestor_ref: `thread://${threadId}`, bound_units: 3 }, { ancestor_ref: TENANT, bound_units: 10 }];
    const claim = (n, over = {}) => ({ reservation_ref: `work-reservation://${TENANT}/${threadId}/concurrent-invocations/${n}`, work_ref: `work-run://${threadId}/${n}`, holder_ref: `thread://${threadId}`, dimension: "concurrent_invocations", reserved_units: 1, ancestor_chain: chain, ancestor_bounds: bounds, expires_at_ms: Date.now() + 3_600_000, ...over });
    ok("[claim] before any claim the composer names the genesis head for this chain's stream", orchestration.reservationHead(chain) === RESERVATION_GENESIS_HEAD, orchestration.reservationHead(chain));
    const first = await refused(() => orchestration.reserve(claim(1)));
    ok("[claim] the FIRST reservation on an empty stream admits against the genesis head (a real value, not an absence) and comes back with the stream's admitted head — the driven finding the route now answers", first.ok && first.value.admitted_head?.startsWith("sha256:") && first.value.admitted_head !== RESERVATION_GENESIS_HEAD && first.value.stream_tail === reservationStreamTail({ ancestor_chain: chain }), JSON.stringify(first).slice(0, 400));
    const stale = await refused(() => orchestration.reserve(claim(2, { expected_ancestor_head: RESERVATION_GENESIS_HEAD })));
    ok("[claim] a sibling computed against the genesis head after the first admission is refused by name (work_reservation_head_moved) and admits nothing", !stale.ok && stale.status === 409 && stale.code === "work_reservation_head_moved", JSON.stringify(stale).slice(0, 300));
    const second = await refused(() => orchestration.reserve(claim(2)));
    ok("[claim] the successor computed against the admitted head admits with a new head: the composer carries the head the daemon handed back, never one it invented", second.ok && second.value.admitted_head !== first.value.admitted_head && orchestration.reservationHead(chain) === second.value.admitted_head, JSON.stringify(second).slice(0, 300));
    const over = await refused(() => orchestration.reserve(claim(3, { reserved_units: 5 })));
    ok("[claim] a claim that would exceed the nearest ancestor's supplied bound is refused (409, a work_reservation_* code) — the ceilings are the ancestors' truth, checked by the kernel, never by the composer", !over.ok && over.status === 409 && /^work_reservation_/u.test(over.code), JSON.stringify(over).slice(0, 300));

    // -- records: typed application records under the System through the seam (S1) --------------------------
    const fixture = readFixture("work-frontier-item-v3/positive-admitted.json");
    delete fixture.system_binding;
    const itemA = { ...fixture, frontier_item_id: `frontier://orchestration/${threadId}/a` };
    const itemB = { ...fixture, frontier_item_id: `frontier://orchestration/${threadId}/b`, objective: `${fixture.objective} (b)` };
    const a1 = await refused(() => orchestration.record({ contract_id: CONTRACT, object_id: itemA.frontier_item_id, record: itemA }));
    const bindingA = a1.value?.record?.system_binding ?? {};
    ok("[record] a typed record admits under the System through the seam with the binding DERIVED — this System, the composition's own scope as parent, a payload root over the record — and no application field authored by the composer", a1.ok && a1.value.replayed === false && bindingA.system_id === SYSTEM_ID && bindingA.parent_scope_ref === SCOPE_REF && bindingA.payload_root === deriveSystemRecordPayloadRoot(itemA) && bindingA.payload_root === gatePayloadRoot(itemA) && typeof a1.value.expected_head_for_successor === "string", JSON.stringify(a1).slice(0, 500));
    const a1Replay = await refused(() => orchestration.record({ contract_id: CONTRACT, object_id: itemA.frontier_item_id, record: itemA, expected_head: null, idempotency_key: a1.value?.admission?.idempotency_key }));
    ok("[record] an exact retry under the same content-derived idempotency key replays the same admission (200, replayed, same head)", a1Replay.ok && a1Replay.value.replayed === true && a1Replay.value.expected_head_for_successor === a1.value?.expected_head_for_successor, JSON.stringify(a1Replay).slice(0, 300));
    const a2 = await refused(() => orchestration.record({ contract_id: CONTRACT, object_id: itemA.frontier_item_id, record: { ...itemA, objective: `${itemA.objective} (revised)` } }));
    ok("[record] a revision admits on the head the seam handed back, with a new head and a new payload root", a2.ok && a2.value.expected_head_for_successor !== a1.value?.expected_head_for_successor && a2.value.record?.system_binding?.payload_root !== bindingA.payload_root, JSON.stringify(a2).slice(0, 300));
    const b1 = await refused(() => orchestration.record({ contract_id: CONTRACT, object_id: itemB.frontier_item_id, record: itemB }));
    const chainA = await refused(() => orchestration.recordChain(CONTRACT, itemA.frontier_item_id));
    const underContract = await refused(() => orchestration.records(CONTRACT));
    ok("[record] the seam serves the chain (two revisions of A at its current head) and the current heads of both records under the contract", b1.ok && chainA.ok && chainA.value.revisions?.length === 2 && chainA.value.head === a2.value?.expected_head_for_successor && underContract.ok && underContract.value.count === 2 && underContract.value.records.every((r) => r.contract_id === CONTRACT), JSON.stringify({ chain: chainA.value?.revisions?.length, head: chainA.value?.head, count: underContract.value?.count }));

    // -- the graph: projected from the primitives' own reads ------------------------------------------------------
    const graph = await orchestration.graph();
    const kinds = (kind) => graph.nodes.filter((n) => n.kind === kind);
    const owners = new Set(graph.nodes.map((n) => n.owner));
    ok("[graph] the composed graph is a node graph rooted at the coordinating thread: one System node, one thread, two subagents, two reservations, two records; every edge joins two projected nodes; every node names the kernel or seam that owns its truth", graph.root === `thread:${threadId}` && kinds("system").length === 1 && kinds("thread").length === 1 && kinds("subagent").length === 2 && kinds("reservation").length === 2 && kinds("record").length === 2 && graph.edges.every((e) => graph.nodes.some((n) => n.id === e.from) && graph.nodes.some((n) => n.id === e.to)) && owners.size === 4 && [...owners].every((o) => ["system-genesis", "thread-kernel", "work-lifecycle-kernel", "system-record-seam"].includes(o)), JSON.stringify({ root: graph.root, kinds: graph.nodes.map((n) => n.kind), owners: [...owners] }));
    const recordNodes = kinds("record");
    ok("[graph] record nodes carry the seam's derived binding (the composition's scope as parent, the payload root) and the reservation nodes carry the admitted heads; the graph mints nothing and says so", recordNodes.every((n) => n.detail.parent_scope_ref === SCOPE_REF && typeof n.detail.payload_root === "string") && kinds("reservation").map((n) => n.detail.admitted_head).sort().join() === [first.value?.admitted_head, second.value?.admitted_head].sort().join() && /mints no object and grants no authority/u.test(graph.nonclaim), JSON.stringify(recordNodes.map((n) => n.detail)).slice(0, 400));
    const platformSurface = JSON.stringify({ keys: Object.keys(graph), kinds: graph.nodes.map((n) => n.kind), edges: graph.edges.map((e) => e.kind), owners: [...owners] });
    ok("[vocabulary] the platform-facing surface of the composition speaks primitives and graph words only: no application vocabulary names the graph's members", !/\b(room|rooms|participant|participants)\b/iu.test(platformSurface), platformSurface.slice(0, 300));

    // -- restart: a re-attached composer re-derives the same graph from the daemon ------------------------------
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    client = clientFor(plane.daemonUrl);
    const reopened = Orchestration.open(client, orchestration.handle());
    const again = await reopened.graph();
    const ids = (g, kind) => g.nodes.filter((n) => n.kind === kind).map((n) => n.id).sort();
    ok("[restart] after a daemon restart a re-attached composer (which remembers nothing but its handle) re-derives the same thread, the same two subagents and the same two records from durable admissions", ids(again, "thread").join() === ids(graph, "thread").join() && ids(again, "subagent").join() === ids(graph, "subagent").join() && ids(again, "record").join() === ids(graph, "record").join() && again.nodes.filter((n) => n.kind === "record").every((n) => graph.nodes.some((m) => m.id === n.id && m.detail.head === n.detail.head)), JSON.stringify({ before: graph.nodes.map((n) => n.id), after: again.nodes.map((n) => n.id) }).slice(0, 600));
    const third = await refused(() => reopened.reserve(claim(3, { expected_ancestor_head: second.value?.admitted_head })));
    const staleAfter = await refused(() => reopened.reserve(claim(4, { expected_ancestor_head: first.value?.admitted_head })));
    ok("[restart] the reservation stream persisted: a successor naming the pre-restart admitted head admits, one naming an older head is refused by name — the composer's reservation memory is a session convenience, the stream is the truth", reopened.reservations().length === 1 && third.ok && third.value.admitted_head !== second.value?.admitted_head && !staleAfter.ok && staleAfter.code === "work_reservation_head_moved", JSON.stringify({ third, staleAfter }).slice(0, 400));

    // -- structure -------------------------------------------------------------------------------------------------
    const sdkSource = readFileSync(join(REPO, "packages/agent-sdk/src/orchestration.ts"), "utf8");
    const clientSource = readFileSync(join(REPO, "packages/agent-sdk/src/substrate-client.ts"), "utf8");
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    ok("[structure] the composer is application-layer code over the primitives: it names no room or participant, holds no store, and drives only /v1/threads, /v1/threads/:id/subagents, the work-lifecycle reservation route and the System-record seam; the daemon registers no route for the composition itself (its goal-orchestration spine is R-172 migration input, not this composition)", !/\b(room|rooms|participant|participants)\b/iu.test(sdkSource) && !/localStorage|writeFileSync|mkdirSync/u.test(sdkSource) && /createThread\(/u.test(sdkSource) && /spawnSubagent\(/u.test(sdkSource) && /admitWorkReservation\(/u.test(sdkSource) && /admitSystemRecord\(/u.test(sdkSource) && /admitWorkReservation\(input: WorkReservationAdmitInput\)/u.test(clientSource) && !/"\/v1\/orchestrations?[\/"]/u.test(routerSource) && !/orchestration_composition|OrchestrationComposition/u.test(routerSource), "");

    if (MUTATION) {
      ok("DRILL D1 — the payload-root oracle: the SDK's derivation and the S1 gate's independent one agree on the served record and both reject an edited one", deriveSystemRecordPayloadRoot(itemA) === gatePayloadRoot(itemA) && deriveSystemRecordPayloadRoot({ ...itemA, objective: "edited" }) !== bindingA.payload_root, "");
      const shuffled = projectOrchestrationGraph({ system_id: SYSTEM_ID, scope_ref: SCOPE_REF, thread: thread.body, subagents: [...(listed.subagents ?? [])].reverse(), reservations: [second.value, first.value], records: [...underContract.value.records].reverse() });
      const straight = projectOrchestrationGraph({ system_id: SYSTEM_ID, scope_ref: SCOPE_REF, thread: thread.body, subagents: listed.subagents ?? [], reservations: [first.value, second.value], records: underContract.value.records });
      ok("DRILL D2 — the graph projection is order-independent: reversed inputs project byte-identical graphs", JSON.stringify(shuffled) === JSON.stringify(straight), "");
      ok("DRILL D3 — the refusal predicate reads an admitted reply as ok and a typed refusal as refused with its daemon code", first.ok && !stale.ok && stale.code === "work_reservation_head_moved" && daemonCode({ details: { daemon: { error: { code: "x" } } } }) === "x" && daemonCode({}) === "", "");
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
  if (!MUTATION) emitVerifierCensus({ verifierId: "orchestration-composition", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  process.exit(passed === results.length ? 0 : 1);
}
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) run();
