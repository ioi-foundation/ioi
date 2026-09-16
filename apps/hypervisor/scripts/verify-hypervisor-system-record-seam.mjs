#!/usr/bin/env node
// verify-hypervisor-system-record-seam.mjs — register R-172, slice S1: the generic contract-typed
// application-record seam under a bounded System. The platform guarantee M04.4 names as the
// generalized admitted-record contract and ADR 0030 names as "Agentgres operation-backed admission":
// any registered record whose shape carries a SystemScopedObjectBinding is admitted as an ordinary
// event_stream.* operation on the shared owner-scoped write path — exact heads, idempotent replay,
// receipts, the same tenant scope discipline every family uses — and the platform knows NO
// application vocabulary: it validates by contract id, derives the binding, keeps the chain.
//
// Driven against an isolated daemon and the REAL wallet.network fixture: the bounded System is
// admitted and activated through its governed genesis; a registered binding-carrying record is
// admitted with its binding derived and re-derived here; a successor on the exact head; a stale
// head; a replay; every typed refusal; a second principal's read refused by scope; restart.
//   --mutation  runs the drills D1–D3.

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import { bootstrapActiveSystem, exactGenesisBody, rebindGenesisBodySystem, recomputeReleaseHashes } from "./verify-hypervisor-system-sequence-zero-materialization.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const MUTATION = process.argv.includes("--mutation");
const SYSTEM_ID = "system://ioi/record-seam/s1-proof";
const GENESIS_ID = "genesis://ioi/record-seam/s1-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/record-seam/s1-proof/v1";
const PACKAGE = "package://ioi/outcome-room"; // the fixture's exact genesis release package; the seam is package-neutral
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const CONTRACT = "schema://ioi/applications/ioi-ai/work-frontier-item/v3";
const UNSCOPED_CONTRACT = "schema://ioi/applications/ioi-ai/goal-run/v1";
const ROUTE = `/v1/hypervisor/autonomous-systems/${encodeURIComponent(SYSTEM_ID)}/records`;
let OWNER = "user://local-operator";
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const jcs = (value) => { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`; return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`; };
const code = (body) => body?.error?.code ?? body?.code ?? "";
const message = (body) => body?.error?.message ?? body?.message ?? "";
const readFixture = (rel) => JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures", rel), "utf8"));
/** The seam's own slug: the first `://` becomes `-`, every other character outside [A-Za-z0-9_.-] becomes `.`. */
export const slug = (ref) => ref.replace("://", "-").replace(/[^A-Za-z0-9_.-]/gu, ".");
/** The binding's payload root: sha256 over the JCS of the record with `system_binding` present and null. */
export const derivePayloadRoot = (record) => `sha256:${createHash("sha256").update(jcs({ ...record, system_binding: null })).digest("hex")}`;
let counter = 0; const key = (p) => `${p}-${Date.now()}-${++counter}`;

async function jsonCall(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, base), { method, headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }), ...headers } }, (response) => {
      const chunks = []; response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); const raw = Buffer.concat(chunks).toString("utf8"); let parsed = {}; try { parsed = raw ? JSON.parse(raw) : {}; } catch {} resolve({ status: response.statusCode ?? 0, body: parsed }); });
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
  body.release.display_name = "Record-seam S1 verifier package";
  body.release.description = "The generic application-record seam under a bounded System.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/record-seam";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, { systemId: SYSTEM_ID, genesisId: GENESIS_ID, constitutionRef: CONSTITUTION_REF, deploymentProfileRef: `deployment-profile://ioi/record-seam/s1-proof/local/revision/sha256:${"d".repeat(64)}`, orderingProfileRef: "ordering-profile://ioi/record-seam/s1-proof/hosted", oracleProfileRef: "oracle-evidence-profile://ioi/record-seam/s1-proof/fail-closed", lifecycleProfileRef: "lifecycle-profile://ioi/record-seam/s1-proof/default" });
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-record-seam-"));
  let resolver; let plane;
  try {
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "record-seam-operator-password", email: "record-seam@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;

    // The record seam refuses a System that is not active BEFORE anything else is derived.
    const fixture = readFixture("work-frontier-item-v3/positive-admitted.json");
    delete fixture.system_binding;
    const record = { ...fixture, frontier_item_id: "frontier://record-seam/item-1" };
    const admitBody = (over = {}) => ({ owner_ref: TENANT, idempotency_key: key("rec"), contract_id: CONTRACT, object_id: record.frontier_item_id, parent_scope_ref: null, record, expected_head: null, ...over });
    const inactive = await call("POST", ROUTE, admitBody());
    ok("[system] a record under a System that is not active is refused by name before anything is derived", inactive.status === 409 && code(inactive.body) === "system_record_system_not_active", `${inactive.status} ${code(inactive.body)} ${message(inactive.body).slice(0, 160)}`);

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", typeof active.source?.record?.governing_authority_ref === "string", `${active.source?.record?.governing_authority_ref}`);

    // -- refusals by name, nothing written -------------------------------------------------------------
    const unknownField = await call("POST", ROUTE, admitBody({ receipt_ref: "receipt://authored" }));
    ok("[request] an unknown field is refused: the binding, the head and the receipts are derived, never authored", unknownField.status === 400 && code(unknownField.body) === "system_record_request_unknown_field", `${unknownField.status} ${code(unknownField.body)}`);
    const authored = await call("POST", ROUTE, admitBody({ record: { ...record, system_binding: { schema_version: "ioi.foundations.system-scoped-object-binding.v1", system_id: SYSTEM_ID, parent_scope_ref: SYSTEM_ID, proposed_or_issued_by_ref: "worker://forged", payload_root: `sha256:${"0".repeat(64)}`, created_at: "2026-09-16T00:00:00Z", updated_at: null } } }));
    ok("[binding] a caller-authored system_binding is refused, never corrected", authored.status === 422 && code(authored.body) === "system_record_binding_authored", `${authored.status} ${code(authored.body)}`);
    const identity = await call("POST", ROUTE, admitBody({ object_id: "frontier://record-seam/not-in-record" }));
    ok("[identity] an object_id the record does not carry as its own `*_id` member is refused: identity is the record's own", identity.status === 422 && code(identity.body) === "system_record_identity_unresolved", `${identity.status} ${code(identity.body)}`);
    const unknownContract = await call("POST", ROUTE, admitBody({ contract_id: "schema://ioi/applications/nobody/thing/v1" }));
    ok("[contract] an unregistered contract is refused by name", unknownContract.status === 422 && code(unknownContract.body) === "system_record_contract_unknown", `${unknownContract.status} ${code(unknownContract.body)}`);
    const goalRun = readFixture("goal-run-v1/positive-minimal.json");
    const unscoped = await call("POST", ROUTE, admitBody({ contract_id: UNSCOPED_CONTRACT, object_id: goalRun.goal_run_id, record: goalRun }));
    ok("[contract] a registered contract whose shape carries no SystemScopedObjectBinding has no place under a System: refused as unscoped", unscoped.status === 422 && code(unscoped.body) === "system_record_contract_unscoped", `${unscoped.status} ${code(unscoped.body)} ${message(unscoped.body).slice(0, 120)}`);
    const { objective: _dropped, ...broken } = record;
    const invalid = await call("POST", ROUTE, admitBody({ record: broken }));
    ok("[contract] a record that does not satisfy its registered contract is refused as not registered-valid", invalid.status === 422 && code(invalid.body) === "system_record_not_registered_valid", `${invalid.status} ${code(invalid.body)}`);

    // -- the first admission: binding derived, chain begun -----------------------------------------------
    const firstKey = key("first");
    const first = await call("POST", ROUTE, admitBody({ idempotency_key: firstKey }));
    const r1 = first.body?.record ?? {};
    const head1 = first.body?.expected_head_for_successor;
    ok("[admit] a registered binding-carrying record admits as an ordinary operation on the shared write path: the binding is DERIVED (this System, the System as parent scope, the resolved principal as issuer, a payload root re-derived here over the record with the binding absent), and the admission carries a head, a receipt and an operation ref", first.status === 201 && r1.system_binding?.system_id === SYSTEM_ID && r1.system_binding?.parent_scope_ref === SYSTEM_ID && r1.system_binding?.proposed_or_issued_by_ref === OWNER && r1.system_binding?.payload_root === derivePayloadRoot(record) && typeof head1 === "string" && head1.length > 0 && typeof first.body?.receipt_ref === "string" && typeof first.body?.operation_ref === "string" && first.body?.contract_id === CONTRACT, `${first.status} ${code(first.body)} ${message(first.body).slice(0, 200)} root=${r1.system_binding?.payload_root?.slice(0, 18)} vs ${derivePayloadRoot(record).slice(0, 18)} issuer=${r1.system_binding?.proposed_or_issued_by_ref}`);
    const replay = await call("POST", ROUTE, admitBody({ idempotency_key: firstKey }));
    ok("[admit] an exact retry replays the same admission (200, replayed, same head)", replay.status === 200 && replay.body?.replayed === true && replay.body?.expected_head_for_successor === head1, `${replay.status} ${code(replay.body)}`);
    const successor = await call("POST", ROUTE, admitBody({ record: { ...record, objective: `${record.objective} (revised)` }, expected_head: head1 }));
    const head2 = successor.body?.expected_head_for_successor;
    ok("[chain] a successor on the exact head admits with a new head and a new payload root", successor.status === 201 && head2 && head2 !== head1 && successor.body?.record?.objective === `${record.objective} (revised)` && successor.body?.record?.system_binding?.payload_root === derivePayloadRoot({ ...record, objective: `${record.objective} (revised)` }), `${successor.status} ${code(successor.body)} ${message(successor.body).slice(0, 160)}`);
    const stale = await call("POST", ROUTE, admitBody({ record: { ...record, objective: "stale" }, expected_head: head1 }));
    ok("[chain] a successor on a stale head is refused by name and writes nothing", stale.status === 409 && code(stale.body) === "system_record_expected_head_conflict", `${stale.status} ${code(stale.body)}`);
    const nullOnExisting = await call("POST", ROUTE, admitBody({ record: { ...record, objective: "null head" } }));
    ok("[chain] a genesis assertion (null head) over an existing record is refused: the stream already has admissions", nullOnExisting.status === 409 && code(nullOnExisting.body) === "system_record_expected_head_conflict", `${nullOnExisting.status} ${code(nullOnExisting.body)}`);

    // -- reads --------------------------------------------------------------------------------------------
    const getPath = `${ROUTE}/${encodeURIComponent(slug(CONTRACT))}/${encodeURIComponent(slug(record.frontier_item_id))}`;
    const got = await call("GET", getPath, undefined);
    const listed = await call("GET", `${ROUTE}?contract_id=${encodeURIComponent(CONTRACT)}`, undefined);
    ok("[reads] GET serves the record's chain (two revisions, the current head) and the list serves its current head under the contract", got.status === 200 && got.body?.revisions?.length === 2 && got.body?.head === head2 && got.body?.current?.objective === `${record.objective} (revised)` && listed.status === 200 && listed.body?.count === 1 && listed.body?.records?.[0]?.head === head2, `${got.status} rev=${got.body?.revisions?.length} ${listed.status} count=${listed.body?.count}`);

    // -- scope: a second principal of the same tenant is refused ------------------------------------------
    const created = await call("POST", "/v1/hypervisor/principals", { email: "record-seam-b@ioi.local", name: "Principal B", role: "member", password: "record-seam-b-password" });
    const pid = created.body?.principal?.principal_id ?? "";
    await call("POST", `/v1/hypervisor/principals/${pid}/tenant-memberships`, { tenant_ref: TENANT, expected_revision: 0, idempotency_key: "record-seam-grant-b", reason: "verifier fixture: a member who did not admit the record" });
    const login = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/login", { email: "record-seam-b@ioi.local", password: "record-seam-b-password" });
    const headersB = { authorization: `Bearer ${login.body?.session_token ?? ""}` };
    const gotB = await jsonCall(plane.daemonUrl, "GET", getPath, undefined, headersB);
    const listB = await jsonCall(plane.daemonUrl, "GET", ROUTE, undefined, headersB);
    const writeB = await jsonCall(plane.daemonUrl, "POST", ROUTE, admitBody({ record: { ...record, objective: "by B" }, expected_head: head2 }), headersB);
    ok("[scope] a second resolved principal of the same tenant neither reads nor advances the record: request scopes are principal-bound, the same discipline every family uses", login.status === 200 && gotB.status >= 400 && (listB.status === 200 ? listB.body?.count === 0 : listB.status >= 400) && writeB.status >= 400, `${login.status}/${gotB.status}/${listB.status}:${listB.body?.count}/${writeB.status} ${code(writeB.body)}`);

    // -- restart --------------------------------------------------------------------------------------------
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const after = await call("GET", getPath, undefined);
    ok("[restart] the chain is reproduced from durable admissions after a restart: same revisions, same head", after.status === 200 && after.body?.revisions?.length === 2 && after.body?.head === head2, `${after.status} rev=${after.body?.revisions?.length}`);

    // -- structure -----------------------------------------------------------------------------------------
    const src = readFileSync(join(REPO, "crates/node/src/bin/hypervisor_daemon_routes/system_record_routes.rs"), "utf8");
    ok("[structure] the platform seam knows no application vocabulary: its source names no room, participant, frontier or claim; it validates by contract id, derives the binding and admits through the shared owner-scoped write path", !/\broom\b|participant|frontier|claim/iu.test(src.replace(/\/\/.*$/gmu, "")) && src.includes("validate_architecture_contract(") && src.includes("derive_binding(") && src.includes("admit_owner_scoped_mutation(") && src.includes('"event_stream.system_record_admitted"'), "");

    if (MUTATION) {
      ok("DRILL D1 — the payload-root oracle rejects a record edited after admission and accepts the served one", derivePayloadRoot({ ...record, objective: "edited" }) !== r1.system_binding.payload_root && derivePayloadRoot(record) === r1.system_binding.payload_root, "");
      ok("DRILL D2 — the slug oracle matches the seam's resource spelling (GET served the record through it)", slug("schema://ioi/x/y/v3") === "schema-ioi.x.y.v3" && got.status === 200, "");
      ok("DRILL D3 — the refusal predicate reads a 201 as NOT refused and a 4xx with a code as refused", code(first.body) === "" && first.status === 201 && stale.status >= 400 && code(stale.body) !== "", "");
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
  if (!MUTATION) emitVerifierCensus({ verifierId: "system-record-seam", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  process.exit(passed === results.length ? 0 : 1);
}
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) run();
