#!/usr/bin/env node
// R-185 (R-172 slice S4c-1) — the ioi.ai application's orchestrations RECORDED under a bounded System.
//
// WHAT IS PROVED. Through the built ioi-ai orchestration package, the agent SDK and the real daemon
// on the real wallet fixture: composing an orchestration creates its coordinating thread first
// (kernel-owned) and then admits ONE typed record for it — `applications/ioi-ai/orchestration/v1`,
// the successor of OutcomeRoom v2 — through the System-record seam with the binding derived and
// the composition scope derived from the id and from nothing else (a record whose scope names
// another orchestration is refused by the registered invariant); listing is the seam's list under
// the contract; opening re-attaches a handle on the coordinates the record carries; attaching and
// detaching a GoalRun and changing the status are revisions on the exact head, with a stale head
// refused by the seam by name and the composer's own rules refused by name; the graph is projected
// from the kernel's thread and subagents and the seam's records scoped to the orchestration; a
// daemon restart re-derives the same record and graph; and the daemon session the ioi.ai portal
// exchange mints reaches exactly the primitives this composition drives — threads, subagents, the
// Systems projection and the record seam — and none of a System's own genesis, activation or
// work-lifecycle routes.
//
// WHAT IS NOT CLAIMED. No daemon route serves an orchestration and none is asserted; no reciprocal
// write lands in a GoalRun (the GoalRun's own composition over the orchestration is slice S4d); the
// delegated run behind the one subagent is the kernel's and an isolated plane has no model behind
// it. The web application's own request path is proven by its route tests and smokes, not here;
// this gate proves the composition those routes consume and the daemon scope they run under.

import { createHash, createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
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
const SYSTEM_ID = "system://ioi/orchestration/s4c-records";
const GENESIS_ID = "genesis://ioi/orchestration/s4c-records/genesis";
const CONSTITUTION_REF = "constitution://ioi/orchestration/s4c-records/v1";
const PACKAGE = "package://ioi/outcome-room"; // the fixture's exact genesis release package; the composition is package-neutral
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const CONTRACT = "schema://ioi/applications/ioi-ai/orchestration/v1";
const SCOPE_PREFIX = "app-scope://ioi-ai/orchestration/";
const EXCHANGE = {
  secret: "orchestration-records-portal-exchange-secret-0123456789abcdef",
  issuer: "surface://ioi.ai/orchestration-records",
  audience: "daemon://hypervisor/orchestration-records",
  tenant_ref: "org://local",
};
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const readSchema = (rel) => JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas", rel), "utf8"));
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? error?.code ?? "";
const daemonMessage = (error) => error?.details?.daemon?.error?.message ?? error?.details?.daemon?.message ?? error?.message ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: daemonCode(error), message: String(daemonMessage(error)), composer: error?.name === "OrchestrationRefusal" }; } };
const stripBinding = (record) => { const { system_binding: _b, ...rest } = record; return rest; };
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
  body.release.manifest_id = `${PACKAGE}/release/sha256:${"7".repeat(64)}`;
  body.release.display_name = "Orchestration records S4c verifier package";
  body.release.description = "An orchestration recorded under a bounded System through the seam.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/orchestration";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, { systemId: SYSTEM_ID, genesisId: GENESIS_ID, constitutionRef: CONSTITUTION_REF, deploymentProfileRef: `deployment-profile://ioi/orchestration/s4c-records/local/revision/sha256:${"e".repeat(64)}`, orderingProfileRef: "ordering-profile://ioi/orchestration/s4c-records/hosted", oracleProfileRef: "oracle-evidence-profile://ioi/orchestration/s4c-records/fail-closed", lifecycleProfileRef: "lifecycle-profile://ioi/orchestration/s4c-records/default" });
}

async function loadBuilt(rel, hint) {
  const dist = join(REPO, rel);
  requireValue(existsSync(dist), `BLOCKED: build ${hint} first`);
  return await import(pathToFileURL(dist).href);
}

/** The exact assertion the ioi.ai BFF mints (server/portal-daemon-exchange.ts): HS256 over header.claims. */
function mintExchangeAssertion(principalId) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: EXCHANGE.issuer, aud: EXCHANGE.audience, sub: principalId, tenant_ref: EXCHANGE.tenant_ref, source_identity_hash: `sha256:${createHash("sha256").update("orchestration-records-portal-identity", "utf8").digest("hex")}`, iat: now, nbf: now, exp: now + 30, jti: randomBytes(24).toString("base64url") };
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "ioi-portal-daemon-exchange+jwt" }), "utf8").toString("base64url");
  const encodedClaims = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signature = createHmac("sha256", EXCHANGE.secret).update(`${header}.${encodedClaims}`, "utf8").digest("base64url");
  return `${header}.${encodedClaims}.${signature}`;
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-orchestration-records-"));
  let resolver; let plane;
  try {
    const sdk = await loadBuilt("packages/agent-sdk/dist/index.js", "packages/agent-sdk (npm run build --workspace=@ioi/agent-sdk)");
    const app = await loadBuilt("packages/ioi-ai-orchestration/dist/index.js", "packages/ioi-ai-orchestration (npm run build --workspace=@ioi/ioi-ai-orchestration)");
    const { createRuntimeSubstrateClient, deriveSystemRecordPayloadRoot, projectOrchestrationGraph } = sdk;
    const { Orchestrations, OrchestrationRefusal, ORCHESTRATION_CONTRACT, GOVERNANCE_SCALAR_REFS, GOVERNANCE_LIST_REFS, GOVERNANCE_NULLABLE_REFS, orchestrationIdTail, orchestrationScope } = app;
    const schema = readSchema("orchestration.v1.schema.json");
    const fixture = readSchema("fixtures/orchestration-v1/positive-open-hosted.json");
    const governance = Object.fromEntries([...GOVERNANCE_SCALAR_REFS, ...GOVERNANCE_LIST_REFS, ...GOVERNANCE_NULLABLE_REFS].map((member) => [member, fixture[member]]));

    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = {
      ...resolver.env,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY,
      IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces"),
      IOI_PORTAL_DAEMON_EXCHANGE_SECRET: EXCHANGE.secret,
      IOI_PORTAL_DAEMON_EXCHANGE_ISSUER: EXCHANGE.issuer,
      IOI_PORTAL_DAEMON_EXCHANGE_AUDIENCE: EXCHANGE.audience,
      IOI_PORTAL_DAEMON_EXCHANGE_TENANT_REF: EXCHANGE.tenant_ref,
    };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "orchestration-records-operator-password", email: "orchestration-records@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    const call = (method, path, body, headers = operatorHeaders) => jsonCall(plane.daemonUrl, method, path, body, headers);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const PRINCIPAL_ID = requireValue(operator.body?.principal?.principal_id, "operator identity missing");
    const OWNER = `user://${PRINCIPAL_ID}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    requireValue(TENANT === EXCHANGE.tenant_ref, `BLOCKED: the bootstrap operator's tenant is ${TENANT}, not the ${EXCHANGE.tenant_ref} the portal exchange is configured for`);
    const clientFor = (url, headers = operatorHeaders) => createRuntimeSubstrateClient({ endpoint: `${url.replace(/\/$/u, "")}/`, headers });
    let client = clientFor(plane.daemonUrl);
    const mintedIds = ["orc_s4c_first", "orc_s4c_second", "orc_s4c_third", "orc_s4c_fourth"];
    const composerFor = (c) => new Orchestrations(c, { system_id: SYSTEM_ID, owner_ref: TENANT }, { mintId: () => mintedIds.shift() ?? `orc_s4c_${Date.now()}` });
    let composer = composerFor(client);

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", typeof active.source?.record?.governing_authority_ref === "string", JSON.stringify(active).slice(0, 300));

    // -- compose: the coordinating thread first, then the one record that makes the handle durable --------------
    const draft = (objective, objectiveRef) => ({ objective, objective_ref: objectiveRef, mode: "private_goal", composed_by_ref: OWNER, governance });
    const first = await refused(() => composer.compose(draft("S4c proof: record one orchestration under the System", "goal://gr_s4c_first")));
    const firstRecord = first.value?.orchestration ?? {};
    const firstThread = first.ok ? await call("GET", `/v1/threads/${encodeURIComponent(first.value.handle.thread_id)}`, undefined) : { status: 0, body: {} };
    ok("[compose] composing creates the coordinating thread through POST /v1/threads (the kernel serves it back, active) and admits the orchestration record through the seam: the record names that thread as its root, its status is open, and it attaches no GoalRun yet", first.ok && firstThread.status === 200 && firstThread.body?.status === "active" && firstRecord.thread_ref === `thread://${first.value.handle.thread_id}` && firstRecord.status === "open" && Array.isArray(firstRecord.member_goal_run_refs) && firstRecord.member_goal_run_refs.length === 0 && firstRecord.orchestration_id === "orchestration://orc_s4c_first", JSON.stringify(first).slice(0, 600));
    const binding = firstRecord.system_binding ?? {};
    const stripped = stripBinding(firstRecord);
    ok("[compose] the seam derived the binding — this System, the composition scope as the parent scope, a payload root two independent oracles re-derive — and the composition scope is exactly the id's scope: neither authored by the composer nor invented by the daemon", binding.system_id === SYSTEM_ID && binding.parent_scope_ref === firstRecord.orchestration_ref && firstRecord.orchestration_ref === `${SCOPE_PREFIX}orc_s4c_first` && binding.payload_root === deriveSystemRecordPayloadRoot(stripped) && binding.payload_root === gatePayloadRoot(stripped) && /^sha256:[0-9a-f]{64}$/u.test(first.value?.head ?? "") && first.value?.head === first.value?.admitted?.expected_head_for_successor, JSON.stringify({ binding, head: first.value?.head }).slice(0, 400));
    ok("[compose] the admission carries the seam's receipt and Agentgres operation refs, and the served record carries exactly the registered contract's member set", /^receipt:\/\//u.test(first.value?.admitted?.receipt_ref ?? "") && /^agentgres:\/\//u.test(first.value?.admitted?.operation_ref ?? "") && JSON.stringify(Object.keys(firstRecord).sort()) === JSON.stringify([...schema.required].sort()), JSON.stringify({ receipt: first.value?.admitted?.receipt_ref, operation: first.value?.admitted?.operation_ref, members: Object.keys(firstRecord).sort() }).slice(0, 500));

    // -- the registered invariant is the daemon's, not the composer's -------------------------------------------
    const rogue = { ...stripped, orchestration_id: "orchestration://orc_s4c_rogue", orchestration_ref: firstRecord.orchestration_ref };
    const rogueAdmit = await refused(() => client.admitSystemRecord(SYSTEM_ID, { owner_ref: TENANT, idempotency_key: key("rogue"), contract_id: CONTRACT, object_id: rogue.orchestration_id, parent_scope_ref: rogue.orchestration_ref, record: rogue, expected_head: null }));
    ok("[contract] a record whose composition scope names ANOTHER orchestration's scope is refused by the seam through the registered invariant (orchestration.scope.names_its_own_id) — the derivation is the contract's, and it holds for any writer, not only this composer", !rogueAdmit.ok && rogueAdmit.status === 422 && /^system_record_/u.test(rogueAdmit.code) && /names_its_own_id/u.test(rogueAdmit.message), JSON.stringify(rogueAdmit).slice(0, 500));

    // -- list and open ---------------------------------------------------------------------------------------------
    const second = await refused(() => composer.compose(draft("S4c proof: a second orchestration under the same System", null)));
    const listed = await refused(() => composer.list());
    const foreign = await refused(() => client.listSystemRecords(SYSTEM_ID, "schema://ioi/applications/ioi-ai/work-frontier-item/v3"));
    ok("[list] listing is the seam's list under the contract: both orchestrations at their current heads with one revision each, and nothing under another contract", second.ok && listed.ok && listed.value.length === 2 && listed.value.every((e) => e.revisions === 1 && /^sha256:/u.test(e.head ?? "") && e.orchestration.schema_version === "ioi.applications.ioi-ai.orchestration.v1") && listed.value.map((e) => e.orchestration.orchestration_id).sort().join() === "orchestration://orc_s4c_first,orchestration://orc_s4c_second" && foreign.ok && foreign.value.count === 0, JSON.stringify({ listed: listed.value?.map((e) => [e.orchestration?.orchestration_id, e.revisions]), foreign: foreign.value?.count }).slice(0, 400));
    const opened = await refused(() => composer.open("orc_s4c_first"));
    ok("[open] re-attaching reads the chain and opens a handle on the coordinates the record carries — the same thread, the composition scope, the tenant owner scope — with the head the seam serves and the admission's receipt beside the one revision", opened.ok && opened.value.handle.thread_id === first.value?.handle.thread_id && opened.value.handle.scope_ref === firstRecord.orchestration_ref && opened.value.handle.owner_ref === TENANT && opened.value.head === first.value?.head && opened.value.revisions.length === 1 && /^receipt:\/\//u.test(opened.value.admissions[0]?.receipt_ref ?? ""), JSON.stringify({ thread: opened.value?.handle?.thread_id, head: opened.value?.head, revisions: opened.value?.revisions?.length, receipt: opened.value?.admissions?.[0]?.receipt_ref }).slice(0, 400));
    const absent = await refused(() => composer.open("orc_s4c_absent"));
    ok("[open] an orchestration the seam does not hold is refused by the SEAM's scope fence (403 request_resource_scope_required: no scope visible to this principal) and the composer passes that refusal through untouched — it claims neither absence nor existence, because the seam discloses neither", !absent.ok && !absent.composer && absent.status === 403 && absent.code === "request_resource_scope_required", JSON.stringify(absent).slice(0, 300));

    // -- membership: revisions on the exact head ------------------------------------------------------------------
    const attached = await refused(() => composer.attachGoalRun("orc_s4c_first", "goal://gr_s4c_first", first.value?.head));
    ok("[membership] attaching a GoalRun is a revision of the record on the exact head: the members now list it, the head moved, the binding kept the composition scope, and the seam receipted the revision", attached.ok && attached.value.action === "attach" && attached.value.orchestration.member_goal_run_refs.join() === "goal://gr_s4c_first" && attached.value.head !== first.value?.head && attached.value.orchestration.system_binding?.parent_scope_ref === firstRecord.orchestration_ref && /^receipt:\/\//u.test(attached.value.admitted?.receipt_ref ?? ""), JSON.stringify(attached).slice(0, 500));
    const stale = await refused(() => composer.attachGoalRun("orc_s4c_first", "goal://gr_s4c_other", first.value?.head));
    ok("[membership] a revision computed against the pre-attach head is refused by the SEAM by name (409 system_record_expected_head_conflict) and admits nothing — the composer pre-empts nothing; the stream is the truth", !stale.ok && !stale.composer && stale.status === 409 && stale.code === "system_record_expected_head_conflict", JSON.stringify(stale).slice(0, 300));
    const twice = await refused(() => composer.attachGoalRun("orc_s4c_first", "goal://gr_s4c_first", attached.value?.head));
    const malformed = await refused(() => composer.attachGoalRun("orc_s4c_first", "outcome-room://or_1", attached.value?.head));
    ok("[membership] the composer's own rules refuse by name before any daemon write: an already-attached GoalRun (orchestration_goal_run_already_attached) and a ref that is not a goal://gr_ ref (orchestration_goal_run_ref_malformed)", !twice.ok && twice.composer && twice.code === "orchestration_goal_run_already_attached" && !malformed.ok && malformed.composer && malformed.code === "orchestration_goal_run_ref_malformed", JSON.stringify({ twice, malformed }).slice(0, 400));
    ok("[membership] the reciprocal member is REPORTED, never hidden, and the report now names a RETIREMENT rather than a daemon refusal: R-190 stamped it on the GoalRun plane, R-192 (S5-1) retired that plane as an ioi.ai composition over the thread orchestration primitives, and the SDK refuses locally (410 goal_run_membership_route_retired) instead of probing a route the router would answer with an untyped 404 fallback. The seam revision stays durable either way \u2014 the membership lives there, and the composer never rolls it back for a stamp it cannot place",
      attached.value?.member_stamp?.stamped === false && attached.value?.member_stamp?.refusal?.status === 410 && attached.value?.member_stamp?.refusal?.code === "goal_run_membership_route_retired" && attached.value?.member_stamp?.orchestration_ref === "app-scope://ioi-ai/orchestration/orc_s4c_first",
      JSON.stringify(attached.value?.member_stamp ?? attached.error?.message ?? null));
    const detached = await refused(() => composer.detachGoalRun("orc_s4c_first", "goal://gr_s4c_first", attached.value?.head));
    const chain = await refused(() => composer.open("orc_s4c_first"));
    ok("[membership] detaching on the exact head empties the members and the chain now holds three revisions with three receipts, each revision keeping the same identity, root thread and composition scope", detached.ok && detached.value.orchestration.member_goal_run_refs.length === 0 && chain.ok && chain.value.revisions.length === 3 && chain.value.admissions.length === 3 && chain.value.head === detached.value.head && chain.value.revisions.every((r) => r.orchestration_id === "orchestration://orc_s4c_first" && r.thread_ref === firstRecord.thread_ref && r.orchestration_ref === firstRecord.orchestration_ref), JSON.stringify({ members: detached.value?.orchestration?.member_goal_run_refs, revisions: chain.value?.revisions?.length, admissions: chain.value?.admissions?.length }).slice(0, 300));

    // -- status: open ⇄ paused, closed is terminal -------------------------------------------------------------------
    const paused = await refused(() => composer.transition("orc_s4c_first", "paused", detached.value?.head));
    const reopened = await refused(() => composer.transition("orc_s4c_first", "open", paused.value?.head));
    const closed = await refused(() => composer.transition("orc_s4c_first", "closed", reopened.value?.head));
    const afterClose = await refused(() => composer.attachGoalRun("orc_s4c_first", "goal://gr_s4c_first", closed.value?.head));
    const reopenClosed = await refused(() => composer.transition("orc_s4c_first", "open", closed.value?.head));
    ok("[status] the status is a revision on the exact head — open → paused → open → closed — and closed is terminal: it refuses membership and further transitions by name (orchestration_closed) without a daemon write", paused.ok && paused.value.orchestration.status === "paused" && reopened.ok && reopened.value.orchestration.status === "open" && closed.ok && closed.value.orchestration.status === "closed" && !afterClose.ok && afterClose.composer && afterClose.code === "orchestration_closed" && !reopenClosed.ok && reopenClosed.composer && reopenClosed.code === "orchestration_closed", JSON.stringify({ paused: paused.value?.orchestration?.status, closed: closed.value?.orchestration?.status, afterClose, reopenClosed }).slice(0, 400));

    // -- the graph: the kernel's thread and subagents, the seam's records in THIS scope ------------------------------
    const secondOpened = await refused(() => composer.open("orc_s4c_second"));
    const worker = await refused(() => secondOpened.value.handle.delegate({ prompt: "carry the first unit of work", role: "worker" }));
    const graph = await refused(() => composer.graph("orc_s4c_second"));
    const kinds = (g, kind) => (g?.nodes ?? []).filter((n) => n.kind === kind);
    ok("[graph] the graph is projected from the primitives' own reads: rooted at the second orchestration's thread, one delegated subagent the kernel lists under it, exactly ONE record node — this orchestration's own record, scoped to its composition scope — and not the first orchestration's record; every node names the kernel or the seam as its owner", worker.ok && graph.ok && graph.value.root === `thread:${secondOpened.value.handle.thread_id}` && graph.value.scope_ref === `${SCOPE_PREFIX}orc_s4c_second` && kinds(graph.value, "thread").length === 1 && kinds(graph.value, "subagent").length === 1 && kinds(graph.value, "subagent")[0].ref === worker.value?.subagent_id && kinds(graph.value, "record").length === 1 && kinds(graph.value, "record")[0].detail.parent_scope_ref === `${SCOPE_PREFIX}orc_s4c_second` && graph.value.nodes.every((n) => ["system-genesis", "thread-kernel", "work-lifecycle-kernel", "system-record-seam"].includes(n.owner)) && /mints no object and grants no authority/u.test(graph.value.nonclaim), JSON.stringify({ root: graph.value?.root, kinds: graph.value?.nodes?.map((n) => n.kind), records: kinds(graph.value, "record").map((n) => n.detail.parent_scope_ref) }).slice(0, 500));

    // -- restart: the record and the graph are re-derived from durable admissions -----------------------------------
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    client = clientFor(plane.daemonUrl);
    composer = composerFor(client);
    const again = await refused(() => composer.open("orc_s4c_second"));
    const graphAgain = await refused(() => composer.graph("orc_s4c_second"));
    const ids = (g, kind) => kinds(g, kind).map((n) => n.id).sort().join();
    ok("[restart] after a daemon restart a fresh composer (which remembers nothing) re-opens the same record at the same head on the same thread, and the graph re-derives the same thread, subagent and record nodes from durable admissions", again.ok && again.value.head === secondOpened.value?.head && again.value.handle.thread_id === secondOpened.value?.handle.thread_id && graphAgain.ok && ids(graphAgain.value, "thread") === ids(graph.value, "thread") && ids(graphAgain.value, "subagent") === ids(graph.value, "subagent") && ids(graphAgain.value, "record") === ids(graph.value, "record"), JSON.stringify({ before: graph.value?.nodes?.map((n) => n.id), after: graphAgain.value?.nodes?.map((n) => n.id) }).slice(0, 600));

    // -- the portal session: the scope the ioi.ai web application runs under ---------------------------------------
    const exchange = await call("POST", "/v1/hypervisor/auth/portal-session-exchange", { assertion: mintExchangeAssertion(PRINCIPAL_ID) }, { "x-ioi-forwarded": "ioi-ai-exchange" });
    const portalToken = exchange.status === 200 ? exchange.body?.session_token : null;
    const portalHeaders = { authorization: `Bearer ${portalToken}`, "x-ioi-forwarded": "ioi-ai" };
    const portalWhoami = portalToken ? await call("GET", "/v1/hypervisor/auth/whoami", undefined, portalHeaders) : { status: 0, body: {} };
    ok("[portal] the deployment-local portal exchange the ioi.ai BFF performs mints a short-lived daemon session for the same principal and tenant, and whoami resolves it", exchange.status === 200 && typeof portalToken === "string" && portalToken.startsWith("ioi_sess_") && portalWhoami.status === 200 && portalWhoami.body?.principal?.principal_id === PRINCIPAL_ID && (portalWhoami.body?.principal?.tenant_refs ?? []).includes(EXCHANGE.tenant_ref), JSON.stringify({ exchange: exchange.status, body: exchange.body, whoami: portalWhoami.status }).slice(0, 400));
    const portalComposer = composerFor(clientFor(plane.daemonUrl, portalHeaders));
    const portalList = await refused(() => portalComposer.list());
    const portalGraph = await refused(() => portalComposer.graph("orc_s4c_second"));
    const portalComposed = await refused(() => portalComposer.compose(draft("S4c proof: composed under the portal session the ioi.ai web application holds", "goal://gr_s4c_portal")));
    const portalProjection = await call("GET", "/v1/hypervisor/autonomous-systems/projection", undefined, portalHeaders);
    ok("[portal] under that session the composition runs end to end — the seam's list, the chain and the kernel's thread and subagents behind the graph, a new coordinating thread and a new record admission — and the Systems projection the BFF enumerates Systems from answers", portalList.ok && portalList.value.length === 2 && portalGraph.ok && portalGraph.value.root === graph.value?.root && portalComposed.ok && portalComposed.value.orchestration.orchestration_id === "orchestration://orc_s4c_third" && portalProjection.status === 200 && Array.isArray(portalProjection.body?.systems) && portalProjection.body.systems.some((s) => s.system_id === SYSTEM_ID && s.status === "active"), JSON.stringify({ list: portalList.value?.length, graph: portalGraph.value?.root, composed: portalComposed.value?.orchestration?.orchestration_id, projection: portalProjection.status, systems: portalProjection.body?.systems, state: portalProjection.body?.state, error: portalList.ok ? null : portalList }).slice(0, 900));
    const portalStamp = await call("POST", "/v1/goal-orchestration/goal-runs/gr_s4c_absent/orchestration-membership", { orchestration_ref: "app-scope://ioi-ai/orchestration/orc_s4c_second" }, portalHeaders);
    ok("[portal] the retired goal-orchestration namespace is no longer in the portal session's scope at all (R-192, S5-1): the daemon serves nothing under /v1/goal-orchestration/ and the prefix left with the routes, so the reciprocal stamp is refused by the session's own route scope before any handler — never a 404 that would prove the prefix still granted",
      portalStamp.status === 403 && portalStamp.body?.code === "hypervisor.auth_session_route_scope_denied",
      `${portalStamp.status}/${portalStamp.body?.code ?? portalStamp.body?.error?.code}`);
    const deniedReservation = await call("POST", "/v1/hypervisor/work-lifecycle/reservations", {}, portalHeaders);
    const deniedSecrets = await call("GET", "/v1/hypervisor/secrets", undefined, portalHeaders);
    const deniedTurns = await call("GET", `/v1/threads/${encodeURIComponent(secondOpened.value?.handle.thread_id ?? "x")}/turns`, undefined, portalHeaders);
    const deniedSystems = await call("GET", "/v1/hypervisor/autonomous-systems", undefined, portalHeaders);
    const scopeDenied = (r) => r.status === 403 && r.body?.code === "hypervisor.auth_session_route_scope_denied";
    ok("[portal] the same session reaches NOTHING else: the work-lifecycle plane, secrets, a thread's turns and the System genesis route are refused by the session's route scope (403 hypervisor.auth_session_route_scope_denied) before any handler runs", scopeDenied(deniedReservation) && scopeDenied(deniedSecrets) && scopeDenied(deniedTurns) && scopeDenied(deniedSystems), JSON.stringify({ reservation: deniedReservation, secrets: deniedSecrets.status, turns: deniedTurns.status, systems: deniedSystems.status }).slice(0, 400));

    // -- structure -----------------------------------------------------------------------------------------------------
    const composerSource = readFileSync(join(REPO, "packages/ioi-ai-orchestration/src/orchestrations.ts"), "utf8");
    const bffSource = readFileSync(join(REPO, "apps/ioi-ai/plugins/web-ui/server/index.ts"), "utf8") + readFileSync(join(REPO, "apps/ioi-ai/plugins/web-ui/server/orchestration-routes.ts"), "utf8");
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    const sessionSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"), "utf8");
    ok("[structure] the composer is application-layer code over the primitives (it names no room or participant and drives only the thread, subagent and seam methods, never a reservation); the ioi.ai web application's server calls no daemon room route and imports the composition; the daemon registers no route for an orchestration; and the portal session mint names exactly the composition's exact routes and per-segment patterns", !/\b(room|rooms|participant|participants)\b/iu.test(composerSource) && /Orchestration\.compose\(/u.test(composerSource) && /Orchestration\.open\(/u.test(composerSource) && /listSystemRecords\(/u.test(composerSource) && /getSystemRecord\(/u.test(composerSource) && !/admitWorkReservation|\.reserve\(/u.test(composerSource) && !/goal-orchestration\/outcome-rooms/u.test(bffSource) && /ioi-ai-orchestration\/dist\/index\.js/u.test(bffSource) && !/"\/v1\/orchestrations?[\/"]/u.test(routerSource) && /"allowed_route_patterns": \[\s*"\/v1\/threads\/\*",\s*"\/v1\/threads\/\*\/subagents",\s*"\/v1\/hypervisor\/autonomous-systems\/\*\/records",\s*"\/v1\/hypervisor\/autonomous-systems\/\*\/records\/\*\/\*"\s*\]/u.test(sessionSource) && /"\/v1\/threads",\s*"\/v1\/hypervisor\/autonomous-systems\/projection"/u.test(sessionSource), "");

    if (MUTATION) {
      ok("DRILL D1 — the payload-root oracle: the SDK's derivation and the S1 gate's independent one agree on the served record and both reject an edited one", deriveSystemRecordPayloadRoot(stripped) === gatePayloadRoot(stripped) && deriveSystemRecordPayloadRoot({ ...stripped, objective: "edited" }) !== binding.payload_root, "");
      ok("DRILL D2 — the refusal predicate reads an admitted reply as ok, a daemon refusal with its daemon code, and a composer refusal as the composer's", first.ok && !stale.ok && !stale.composer && stale.code === "system_record_expected_head_conflict" && !twice.ok && twice.composer && daemonCode({ details: { daemon: { error: { code: "x" } } } }) === "x" && daemonCode({}) === "", "");
      ok("DRILL D3 — the id → scope derivation the invariant pins is the one the composer uses, and it refuses a foreign id", orchestrationScope(orchestrationIdTail(firstRecord.orchestration_id)) === firstRecord.orchestration_ref && orchestrationIdTail("outcome-room://or_1") === null, "");
      const shuffled = projectOrchestrationGraph({ system_id: SYSTEM_ID, scope_ref: `${SCOPE_PREFIX}orc_s4c_second`, thread: { thread_id: secondOpened.value.handle.thread_id }, subagents: [], reservations: [], records: [...(listed.value ?? [])].reverse().map((e) => ({ resource_ref: e.resource_ref, contract_id: CONTRACT, current: e.orchestration, head: e.head, revisions: e.revisions })) });
      const straight = projectOrchestrationGraph({ system_id: SYSTEM_ID, scope_ref: `${SCOPE_PREFIX}orc_s4c_second`, thread: { thread_id: secondOpened.value.handle.thread_id }, subagents: [], reservations: [], records: (listed.value ?? []).map((e) => ({ resource_ref: e.resource_ref, contract_id: CONTRACT, current: e.orchestration, head: e.head, revisions: e.revisions })) });
      ok("DRILL D4 — the graph projection is order-independent over the seam's records", JSON.stringify(shuffled) === JSON.stringify(straight), "");
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
  if (!MUTATION) emitVerifierCensus({ verifierId: "orchestration-records", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  process.exit(passed === results.length ? 0 : 1);
}
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) run();
