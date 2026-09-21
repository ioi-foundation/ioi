#!/usr/bin/env node
// check:editor-challenge-relay — M08.12: the editor-side challenge relay (Hypervisor Guard), as a gate
// (docs/architecture/components/daemon-runtime/doctrine.md § Authority Gateway / Sidecar Profile;
// core-clients-surfaces.md § Sessions; register R-214, executing ADR 0008, R-212(3) and R-213).
//
// CANON. Models reason, IOI authorizes action; an adapter routes proposed actions into the daemon's one
// policy, authority, approval and receipt path and never owns authority. An effect initiated from an
// ATTACHED editor is relayed under the user's own identity; its refusal is parked through the App's
// spend-approval lane as the byte-derived card; the editor receives a typed notification carrying the
// challenge's coordinates and the decision links and nothing else. The relay holds no key, mints nothing,
// caches no grant, adds no decision path; the daemon's receipts are identical across attach surfaces.
//
// WHAT THIS RUNNER IS. The acceptance's demands are CLAUSES, each EXECUTED by one of this runner's own legs,
// by a floored gate that already proves it, or NAMED (a typed failure with an owner, or a SCHEDULED live leg
// with its exact prerequisite and ruling). The runner's own legs:
//   RELAY    — in-process over the tracked M03.9 challenge fixture with an injected daemon transport and a
//              grant projection: the attach authenticated by an active editor-open lease naming the service
//              (an unknown, inactive, wrong-action or foreign-service lease refused by name; an effect on
//              another environment refused), the parked record equal to the App lane's minus the attach
//              refs, a caller-supplied grant stripped, the notification's grammar (the challenge's hashes,
//              audience, receipt ref and preimage sha; run-bound links; no facet, preimage, grant or key),
//              the refusal park's notification (no approve link), the decision on the SAME lane endpoints,
//              and receipt parity over two fixture-finalized runs with its negative.
//   RENDER   — the extension's VS-Code-free renderer executed (node:test) over the notification grammar.
//   SOURCE   — the relay imports no authority module and no minter, reads no key path and no test-signer
//              flag, has zero mint call sites, writes no grant member; the lane's single mint site is
//              unchanged; the serve route sits behind the local-run cache admission (pins).
//   LANE     — full mode, the REAL relay: the wallet fixture beside an isolated daemon and the runner's own
//              serve; an attach tuple created IN the daemon (an environment, an editor service, an editor
//              access lease — no editor runtime); RELAY-PARK (the live deployment_intent effect relayed,
//              parked with the daemon's audience, the notification returned and persisted, the operator's
//              approve on the App card, the daemon's typed refusal); RELAY-PARITY (the simulator-mode create
//              driven through the relay AND through the App lane, both approved and admitted, the daemon's
//              receipts and admitted records compared member by member).
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills      CI-bound, seconds: the binding, RELAY, RENDER, SOURCE, the verdict rules, canon's binding.
//   --mutation    planted defects against the drills' oracles — each must go red.
//   (default)     the full gate: the drills, the LANE legs, then every executed gate inside the isolated-egress
//                 harness. Exit 0 pass, 2 named failure, 1 fail. Never spends.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "../apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import { PROVIDER_OPERATION_KIND, PROVIDER_OPS_PATH, decideRunApproval, getRun, runRecord, submitProviderOperation } from "../apps/hypervisor/scripts/ioi-agent-runs.mjs";
import { ADAPTER_KIND, EDITOR_ACCESS_ACTION, FORBIDDEN_NOTIFICATION_MEMBERS, NOTIFICATION_SCHEMA, buildEditorChallengeNotification, receiptParity, relayEditorEffect, verifyAttach, verifyNotificationGrammar } from "../apps/hypervisor/scripts/lib/editor-challenge-relay.mjs";
import { bootstrapToken, prepareProviderAccount, prepareSimulatorAccount } from "./lib/provider-challenge-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const FIXTURE = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m03-9-provider-challenge-fixture-2026-09-20.v1.json");
const CANON_DOCTRINE = path.join(ROOT, "docs", "architecture", "components", "daemon-runtime", "doctrine.md");
const CANON_SURFACES = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "core-clients-surfaces.md");
const CANON_WALLET = path.join(ROOT, "docs", "architecture", "components", "wallet-network", "doctrine.md");
const SERVE = path.join(APP_DIR, "scripts", "serve-product-ui.mjs");
const RUNS = path.join(APP_DIR, "scripts", "ioi-agent-runs.mjs");
const RELAY = path.join(APP_DIR, "scripts", "lib", "editor-challenge-relay.mjs");
const EXTENSION_DIR = path.join(ROOT, "packages", "hypervisor-adapter-targets", "code-editors", "vscode-extension");
const RENDERER = path.join(EXTENSION_DIR, "editor-context", "challenge-notification.js");
const RENDERER_TEST = path.join(EXTENSION_DIR, "editor-context", "challenge-notification.test.js");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const DEPLOYMENT_AUTHORITY_REF = "domain://acme-host";
const FIXTURE_APPROVER_SEED_HEX = "07".repeat(32);
const LIVE_PREREQ = "an owner-authorized Akash account with a funded deposit (IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, IOI_WALLET_SECRET_PASS) for the live admission through the relay; the pinned openvscode-server runtime (IOI_EDITOR_RUNTIME_URL, scripts/provision-hypervisor-vscode-browser-host.mjs) for a hosted-editor leg";
const LIVE_RULING = "R-139 (2026-09-14) and R-214 (2026-09-20): a missing credential or editor runtime blocks a live RUN, never the unit; the relay is proven spend-free on the daemon's typed refusal and the simulator-mode admission, with the attach created in the daemon";
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
const GRANT_MARKER = "APPROVER-SIG-MARKER-NEVER-ON-A-RECORD";

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const LANE = gate("check:spend-approval-lane", "spend-approval-lane", 20);
const CARD_FACETS = gate("check:approval-card-facets", "approval-card-facets", 20);
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const RELAY_LEG = self("relay");
const RENDER = self("render");
const SOURCE = self("source");
const RELAY_PARK = self("relay-park");
const RELAY_PARITY = self("relay-parity");

export const CLAUSES = [
  { n: 1, demand: "an effect initiated from an attached editor reaches the daemon under the user's own identity and its refusal parks through the App's lane as the byte-derived card", executed_by: [RELAY_LEG, RELAY_PARK, LANE] },
  { n: 2, demand: "the attach is authenticated by an active editor-open lease naming the editor service; an unknown, inactive, wrong-action or foreign lease, or an effect on another environment, is refused by name — the lease never authorizes the effect", executed_by: [RELAY_LEG, RELAY_PARK] },
  { n: 3, demand: "the blocked decision surfaces as a typed editor notification carrying the challenge's coordinates and the decision links, and never a facet, a preimage, a grant or a key", executed_by: [RELAY_LEG, RENDER, RELAY_PARK] },
  { n: 4, demand: "the notification deep-links the challenge to the operator's decision on the App card; the decision is taken there, through the lane's own endpoints, and the relay adds no decision path", executed_by: [RELAY_LEG, SOURCE, RELAY_PARK, CARD_FACETS] },
  { n: 5, demand: "the guard holds no keys, mints no authority and caches no grant", executed_by: [RELAY_LEG, SOURCE] },
  { n: 6, demand: "the admitted operation's receipts are identical to the App-initiated path, read back from the daemon", executed_by: [RELAY_LEG, RELAY_PARITY] },
  { n: 7, demand: "the editor renders the notification as a message with actions that open the App's decision, never an in-editor approval", executed_by: [RENDER], absence: { what: "the rendering in a REAL VS Code (the extension host wiring the renderer into a warning message and opening the deep link), the Electron packaged host and the JetBrains and SSH targets are not driven: the extension has no command or notification surface today and CI has no editor runtime", owner: "the VS Code extension host (a follow-on slice of M08.12); the pinned openvscode runtime leg is scheduled (clause 12)" } },
  { n: 8, demand: "the editor learns of the challenge through a channel the daemon or the App pushes", executed_by: [], absence: { what: "the relay returns the notification synchronously and keeps it on the run record; no daemon push or poll channel for challenges exists (editor-proxy-events and editor-receipts are write-only telemetry)", owner: "a daemon change (owner question, R-214)" } },
  { n: 9, demand: "an editor-initiated provider operation crosses the Authority Gateway action-request envelope as an ide_extension adapter", executed_by: [], absence: { what: "the Authority Gateway attach lane admits an ide_extension action request as requires_approval but executes SCM advance_target_ref only and refuses a wallet grant in its payload; the relay crosses the provider-ops route directly", owner: "the Authority Gateway execute adapter for provider ops (owner question, R-214)" } },
  { n: 10, demand: "Hypervisor Guard ships as its own sidecar packaging", executed_by: [], absence: { what: "the relay is a serve-hosted route and an App-side library; ADR 0008 names Hypervisor Guard as packaging for the IOI Authority Gateway adapters and forbids authority in either — the packaging is not built", owner: "packaging (owner question, R-214)" } },
  { n: 11, demand: "the relay's park is reachable beside Governance / Approvals and a denial produces a signed receipt", executed_by: [], absence: { what: "inherited from M08.11 and M03.9: no approvals-inbox plane reads the run record and no deny act exists on the authority node or the fixture", owner: "follow-on slices of M08.11 and M03.9 (owner questions, R-212/R-213)" } },
  { n: 12, demand: "the live admission through the relay, and a hosted-editor leg", executed_by: [], scheduled: { what: "the live direct-Akash deployment_intent create relayed from an attached editor, approved on the App card and ADMITTED with a daemon-issued proposal; and a leg on a host with the pinned openvscode-server runtime where the editor service is started and exposed and the relay is driven from the hosted editor's own terminal", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } },
];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.editor-challenge-relay-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], relay: null, render: null, source: null, relay_park: null, relay_parity: null, clauses: [], verdict: null, mutation: null };
let sink = results;
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  sink.push(row);
  if (sink === results) { evidence.drills.push({ ...row, at: new Date().toISOString() }); console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`); }
  return row.pass;
}
function blocked(reason) { console.error(`BLOCKED: ${reason}`); writeEvidence(); process.exit(2); }
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `editor-challenge-relay-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256File = (f) => (fs.existsSync(f) ? `sha256:${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}` : null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tick = () => new Promise((r) => setImmediate(r));

// ---- the in-process relay (stubbed daemon, grants and custody tier) ----------------------------------------
function stubTransport(script) {
  const calls = [];
  const transport = async (method, p, payload, headers) => { const n = calls.length; calls.push({ method, path: p, payload: structuredClone(payload ?? null), headers: { ...(headers || {}) } }); const reply = typeof script === "function" ? script(n, payload) : script[Math.min(n, script.length - 1)]; return structuredClone(reply); };
  return { transport, calls };
}
function stubTier() {
  const calls = { mint: [], record: [] };
  const grant = { schema_version: 1, grant_id: "grant_stub_0001", counter: 1, max_usages: 1, expires_at: 1850000000000, approver_sig: GRANT_MARKER };
  return { calls, grant, minter: async (args) => { calls.mint.push({ ...args }); return structuredClone(grant); }, recorder: async ({ grant: g, targetScope }) => { calls.record.push({ grant_id: g?.grant_id ?? null, targetScope }); return { recorder: "stub" }; } };
}
const PROPOSAL_REFUSAL = { status: 403, body: { ok: false, code: "provider_operation_proposal_ref_required", message: "a live provider effect requires an opaque daemon-issued operation_proposal_ref", receipt_ref: "agentgres://provider-receipt/prc_stub_proposal" } };
const admitted = (n) => ({ status: 200, body: { ok: true, outcome: "ok", receipt_ref: `agentgres://provider-receipt/prc_stub_ok_${n}`, capability_lease: { lease_id: `lease_stub_${n}`, grant_ref: `wallet.network://grant/approval/stub_${n}`, state: "exhausted", remaining_calls: 0 }, evidence: { deployment: { deployment_ref: `akash-deployment://akdep_stub_${n}`, dseq: `simdseq_stub_${n}`, execution_mode: "simulated_control_plane" }, live_provisioning_not_run: true } } });
const ATTACH = { editor_service_ref: "environment_service:editor_svc_stub", access_lease_ref: "wallet.network://grant/agr_editor_stub", session_ref: "session:stub", environment_ref: "env-approval-card-fixture" };
const GRANTS = [{ grant_id: "agr_editor_stub", grant_ref: "wallet.network://grant/agr_editor_stub", subject: "user://operator", action: EDITOR_ACCESS_ACTION, resources: ["environment:env-approval-card-fixture", "editor_service:svc_stub"], status: "active" }];

export async function relayLeg(fixtureChallenge) {
  const f = [];
  const body = { provider_id: "pacc_stub", op: "create", environment_ref: ATTACH.environment_ref, plan: { sdl_yaml: "version: \"2.0\"\n", deposit_usd: 1.0, ceiling_amount: "1000", ceiling_denom: "uact", auto_topup: false, provider_selector: { mode: "any_marketplace", selection: "lowest_qualified_bid" } }, owner_ref: "org://local", idempotency_key: "editor-relay-fixture", teardown_policy: "always_teardown_required" };
  const operator = { cookie: "ioi_session=ioi_sess_editor_user_stub" };
  // 1. the attach is authenticated, never authorizing
  for (const [label, grants, attach, code] of [
    ["unknown", [], ATTACH, "editor_attach_lease_unknown"],
    ["inactive", [{ ...GRANTS[0], status: "revoked" }], ATTACH, "editor_attach_lease_revoked"],
    ["wrong_action", [{ ...GRANTS[0], action: "provider.create" }], ATTACH, "editor_attach_lease_wrong_action"],
    ["foreign_service", [{ ...GRANTS[0], resources: ["environment:env-approval-card-fixture", "editor_service:svc_other"] }], ATTACH, "editor_attach_lease_foreign_service"],
    ["missing_refs", GRANTS, { editor_service_ref: "" }, "editor_attach_refs_required"],
  ]) {
    const t = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }]);
    const r = await relayEditorEffect({ body, attach, grants, daemonHeaders: operator, transport: t.transport });
    if (!(r.ok === false && r.error?.code === code && t.calls.length === 0)) f.push(`attach_${label}:${r.error?.code}:${t.calls.length}`);
  }
  const tEnv = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }]);
  const rEnv = await relayEditorEffect({ body: { ...body, environment_ref: "env-other" }, attach: ATTACH, grants: GRANTS, daemonHeaders: operator, transport: tEnv.transport });
  if (!(rEnv.ok === false && rEnv.error?.code === "editor_attach_environment_mismatch" && tEnv.calls.length === 0)) f.push(`attach_environment:${rEnv.error?.code}`);
  // 2. the relay parks the same record the App lane parks, minus the attach refs; the caller's grant is stripped
  const t1 = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }]);
  const relayed = await relayEditorEffect({ body: { ...body, wallet_approval_grant: { approver_sig: GRANT_MARKER } }, attach: ATTACH, grants: GRANTS, daemonHeaders: operator, transport: t1.transport, serveBase: "http://127.0.0.1:4173" });
  const run = getRun(relayed.run_id);
  if (!(relayed.ok && relayed.status === 202 && relayed.parked === true && relayed.byte_derived === true && relayed.relayed === true && relayed.notification)) f.push(`relay_reply:${JSON.stringify(relayed).slice(0, 120)}`);
  if (!(t1.calls.length === 1 && t1.calls[0].path === PROVIDER_OPS_PATH && t1.calls[0].headers.cookie === operator.cookie && !("wallet_approval_grant" in (t1.calls[0].payload ?? {})))) f.push("relay_transport_not_user_identity_or_grant_forwarded");
  const t2 = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }]);
  const viaApp = await submitProviderOperation({ body, daemonHeaders: operator, transport: t2.transport });
  const appRun = getRun(viaApp.run_id);
  const parity = receiptParity(runRecord(run)?.pending_approval ?? {}, runRecord(appRun)?.pending_approval ?? {});
  if (parity.length) f.push(`park_differs_from_app_lane:${parity.join("/")}`);
  if (run?.pendingApproval?.kind !== PROVIDER_OPERATION_KIND || stable(run?.pendingApproval?.challenge) !== stable(fixtureChallenge)) f.push("relay_park_not_whole_challenge");
  if (JSON.stringify(runRecord(run)).includes(GRANT_MARKER)) f.push("relay_record_carries_grant");
  if (stable(run?.relayedFrom) !== stable({ ...ATTACH })) f.push("relay_refs_not_kept");
  // 3. the notification grammar
  const n = relayed.notification;
  const grammar = verifyNotificationGrammar(n, fixtureChallenge, { runId: run?.id });
  if (grammar.length) f.push(`notification_grammar:${grammar.join("/")}`);
  if (!(n?.source_adapter?.adapter_kind === ADAPTER_KIND && n?.source_adapter?.editor_service_ref === ATTACH.editor_service_ref && n?.source_adapter?.access_lease_ref === ATTACH.access_lease_ref)) f.push("notification_source_adapter");
  if (!(n?.decision?.approve_url === `http://127.0.0.1:4173/__ioi/runs/${encodeURIComponent(run.id)}/approve` && n?.decision?.card_url === "http://127.0.0.1:4173/work/sessions")) f.push("notification_links");
  if (stable(run?.editorNotification) !== stable(n)) f.push("notification_not_on_run");
  const smuggled = { ...n, facets: [{ key: "deposit_usd", raw: "1.0" }] };
  if (!verifyNotificationGrammar(smuggled, fixtureChallenge).some((x) => x === "forbidden_member:facets")) f.push("grammar_accepts_facets");
  const wrongHash = { ...n, request_hash: `sha256:${"0".repeat(64)}` };
  if (!verifyNotificationGrammar(wrongHash, fixtureChallenge).includes("request_hash_not_the_challenges")) f.push("grammar_accepts_wrong_hash");
  // 4. the refusal park (no preimage): a notification without an approve link
  const stripped = structuredClone(fixtureChallenge); delete stripped.approval.request_preimage;
  const t3 = stubTransport([{ status: 501, body: stripped }]);
  const r3 = await relayEditorEffect({ body, attach: ATTACH, grants: GRANTS, daemonHeaders: operator, transport: t3.transport });
  if (!(r3.parked === true && r3.byte_derived === false && r3.notification?.state === "refused_not_byte_derived" && r3.notification?.decision?.approve_url === null && typeof r3.notification?.decision?.deny_url === "string")) f.push(`refusal_notification:${JSON.stringify(r3.notification?.decision)}`);
  if (verifyNotificationGrammar(r3.notification, stripped, { runId: r3.run_id }).length) f.push("refusal_notification_grammar");
  // 5. the decision is the lane's own: approve through decideRunApproval, the identical retry, the typed refusal
  const tier = stubTier();
  const t4 = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }, PROPOSAL_REFUSAL]);
  const r4 = await relayEditorEffect({ body, attach: ATTACH, grants: GRANTS, daemonHeaders: operator, transport: t4.transport });
  const decider = { cookie: "ioi_session=ioi_sess_operator_deciding" };
  const a4 = await decideRunApproval({ runId: r4.run_id, decision: "approve", daemonHeaders: decider, minter: tier.minter, recorder: tier.recorder, transport: t4.transport });
  await tick(); await sleep(20);
  const run4 = getRun(r4.run_id);
  if (!(a4.status === 202 && a4.kind === PROVIDER_OPERATION_KIND && tier.calls.mint.length === 1 && tier.calls.mint[0].requestHash === fixtureChallenge.approval.request_hash && t4.calls[1]?.path === PROVIDER_OPS_PATH && stable(t4.calls[1]?.payload) === stable({ ...body, wallet_approval_grant: tier.grant }) && run4?.status === "failed" && run4?.error === "provider_operation_proposal_ref_required")) f.push(`decision_not_the_lanes:${a4.status}/${run4?.status}/${run4?.error}`);
  if (JSON.stringify(runRecord(run4)).includes(GRANT_MARKER)) f.push("decided_record_carries_grant");
  // 6. receipt parity: the same operation admitted through the relay and through the App lane
  const tierA = stubTier(); const tierB = stubTier();
  const tA = stubTransport([{ status: 403, body: structuredClone(fixtureChallenge) }, admitted("a")]);
  const tB = stubTransport([{ status: 403, body: structuredClone(fixtureChallenge) }, admitted("b")]);
  const rA = await relayEditorEffect({ body, attach: ATTACH, grants: GRANTS, daemonHeaders: operator, transport: tA.transport });
  const rB = await submitProviderOperation({ body, daemonHeaders: operator, transport: tB.transport });
  await decideRunApproval({ runId: rA.run_id, decision: "approve", daemonHeaders: decider, minter: tierA.minter, recorder: tierA.recorder, transport: tA.transport });
  await decideRunApproval({ runId: rB.run_id, decision: "approve", daemonHeaders: decider, minter: tierB.minter, recorder: tierB.recorder, transport: tB.transport });
  await tick(); await sleep(20);
  const recA = runRecord(getRun(rA.run_id)); const recB = runRecord(getRun(rB.run_id));
  if (!(recA.status === "done" && recB.status === "done")) f.push(`parity_runs_not_done:${recA.status}/${recB.status}`);
  const pOp = receiptParity(recA.provider_operation, recB.provider_operation, { volatile: ["receipt_ref", "grant_ref", "capability_lease_ref", "evidence", "decided_at", "request"] });
  const pAuth = receiptParity(recA.authority, recB.authority, { volatile: ["grantId", "expiresAt", "mintedAt"] });
  if (pOp.length || pAuth.length) f.push(`parity:${[...pOp, ...pAuth].join("/")}`);
  const retryA = tA.calls[1]?.payload ?? {}; const retryB = tB.calls[1]?.payload ?? {};
  delete retryA.wallet_approval_grant; delete retryB.wallet_approval_grant;
  if (stable(retryA) !== stable(retryB)) f.push("parity_retries_differ");
  const negative = receiptParity(recA.provider_operation, { ...recB.provider_operation, outcome: "error", extra_member: 1 });
  if (!(negative.includes("value_differs:outcome") && negative.includes("member_only_in_second:extra_member"))) f.push("parity_negative_silent");
  return { findings: f, runs_driven: 9, notification_members: Object.keys(n ?? {}).sort() };
}
export function renderFindings() {
  const f = [];
  if (!fs.existsSync(RENDERER) || !fs.existsSync(RENDERER_TEST)) return ["renderer_missing"];
  const r = spawnSync("node", ["--test", RENDERER_TEST], { cwd: ROOT, encoding: "utf8", timeout: 120000 });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  const pass = Number(out.match(/^# pass (\d+)/mu)?.[1] ?? 0);
  const fail = Number(out.match(/^# fail (\d+)/mu)?.[1] ?? -1);
  if (r.status !== 0) f.push(`renderer_test_exit:${r.status}`);
  if (fail !== 0) f.push(`renderer_test_failures:${fail}`);
  if (pass < 3) f.push(`renderer_test_population:${pass}<3`);
  const src = fs.readFileSync(RENDERER, "utf8");
  if (/require\(["']vscode["']\)/u.test(src)) f.push("renderer_depends_on_vscode_host");
  if (/approve|deny/iu.test(src.replace(/never offers an in-editor approval|approve\/deny action|approving happens on the App/gu, ""))) f.push("renderer_offers_in_editor_decision");
  return f;
}
export function sourceFindings({ relay, runs, serve, extension }) {
  const f = [];
  if (/wallet-authority\.mjs|mint-approval-grant\.mjs/u.test(relay)) f.push("relay_imports_authority_module");
  if (/mintLocalApproverGrant|mintTestGrant|mintApprovalGrant/u.test(relay)) f.push("relay_names_a_minter");
  if (/IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH|IOI_WALLET_TEST_SIGNER|approverKey|seed/u.test(relay.replace(/FORBIDDEN_NOTIFICATION_MEMBERS = \[[^\]]*\]/u, ""))) f.push("relay_reads_key_material");
  if (/wallet_approval_grant\s*:/u.test(relay)) f.push("relay_writes_a_grant_member");
  if (!/submitProviderOperation\(\{ body, daemonHeaders/u.test(relay)) f.push("relay_bypasses_the_lane");
  if (/decideRunApproval/u.test(relay)) f.push("relay_carries_a_decision_path");
  if (!/export function verifyAttach/u.test(relay) || !/EDITOR_ACCESS_ACTION = "environment\.editor\.open"/u.test(relay)) f.push("relay_attach_verification_missing");
  const mintCalls = (runs.match(/mintLocalApproverGrant\(/gu) || []).length;
  if (mintCalls !== 1) f.push(`lane_mint_call_sites:${mintCalls}!=1`);
  if (!/pathname === "\/__ioi\/editor-relay\/provider-ops" && req\.method === "POST"/u.test(serve)) f.push("serve_relay_route_missing");
  if (!/pathname === "\/__ioi\/editor-relay\/provider-ops"[\s\S]{0,500}localRunCacheAdmission\(req\)/u.test(serve)) f.push("serve_relay_route_unadmitted");
  if (!/relayEditorEffect\(\{ body: payload\?\.body, attach: payload\?\.attach, grants/u.test(serve)) f.push("serve_relay_not_through_the_relay");
  if (/\/__ioi\/editor-relay\/(approve|deny|decide)/u.test(serve)) f.push("serve_relay_has_a_decision_route");
  if (!/renderChallengeNotification/u.test(extension)) f.push("extension_renderer_not_wired");
  return f;
}
export function bindingFindings(clauses, { rootPkg, appPkg, floors }) {
  const f = [];
  const seen = new Set();
  for (const c of clauses) {
    if (!Number.isInteger(c.n) || c.n < 1 || c.n > 12) f.push(`clause_out_of_range: ${c.n}`);
    if (seen.has(c.n)) f.push(`clause_duplicated: ${c.n}`);
    seen.add(c.n);
    if ((c.executed_by ?? []).length === 0 && !c.absence && !c.scheduled) f.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of c.executed_by ?? []) {
      if (g.kind === "app") {
        if (!appPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        const row = (floors.verifiers ?? []).find((r) => r.id === g.floor);
        if (!row) f.push(`clause_${c.n}_floor_missing: ${g.floor}`);
        else if (!(row.runtime_assertions >= 1) || row.npm_script !== g.script) f.push(`clause_${c.n}_floor_mismatch: ${g.floor}`);
      } else if (g.kind === "root") {
        if (!rootPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        if (!rootPkg.scripts?.[g.script.replace(/^check:/u, "mutate:")]) f.push(`clause_${c.n}_binds_undrilled_root_script: ${g.script}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
    if (c.scheduled && !(typeof c.scheduled.prerequisite === "string" && c.scheduled.prerequisite.length > 20 && typeof c.scheduled.ruling === "string" && /R-\d+/u.test(c.scheduled.ruling))) f.push(`clause_${c.n}_scheduled_without_prerequisite_or_ruling`);
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) f.push(`clause_missing: ${n}`);
  return f;
}
export function canonFindings(doctrine, surfaces, wallet) {
  const f = [];
  const d = doctrine.replace(/\s+/gu, " "); const s = surfaces.replace(/\s+/gu, " "); const w = wallet.replace(/\s+/gu, " ");
  const need = [["doctrine_relay", d, /An adapter that meets a wallet challenge relays it: the adapter holds no key, mints no authority and caches no grant/u], ["doctrine_gate", d, /`check:editor-challenge-relay`/u], ["surfaces_relay", s, /An effect initiated from an attached editor parks the same way through the editor challenge relay/u], ["surfaces_never", s, /never a facet, a grant or a key/u], ["surfaces_gate", s, /`check:editor-challenge-relay`/u], ["wallet_not_guardian", w, /An attached editor is not a GuardianSurface/u]];
  for (const [name, text, re] of need) if (!re.test(text)) f.push(`canon_${name}_missing`);
  return f;
}
export function verdict(rows) {
  const failures = []; const absences = []; const seen = new Set();
  for (const r of rows) {
    if (!Number.isInteger(r.n) || r.n < 1 || r.n > 12) { failures.push(`row_out_of_range:${r.n}`); continue; }
    if (seen.has(r.n)) failures.push(`row_duplicated:${r.n}`);
    seen.add(r.n);
    for (const g of r.executed ?? []) {
      if (g.status !== 0) failures.push(`clause_${r.n}_red: ${g.script} exit ${g.status}`);
      else if (!g.evidence || !g.evidence_sha256) failures.push(`clause_${r.n}_fabricated: ${g.script} reports success without evidence`);
      if (g.ledger && g.ledger.reach > 0) failures.push(`clause_${r.n}_undeclared_egress: ${g.script} reached ${g.ledger.reach} non-loopback destination(s)`);
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
    if (r.scheduled) { if (!(r.scheduled.prerequisite && r.scheduled.ruling)) failures.push(`clause_${r.n}_scheduled_without_prerequisite_or_ruling`); else absences.push({ n: r.n, what: `SCHEDULED-OUTSTANDING: ${r.scheduled.what}`, owner: `prerequisite: ${r.scheduled.prerequisite} · ${r.scheduled.ruling}` }); }
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- drills ------------------------------------------------------------------------------------------------
async function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(APP_DIR, "package.json"));
  const floors = readJson(FLOORS);
  const binding = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  ok("the acceptance's demands are bound: every executed clause names a real script with a pinned floor (app) or one of this runner's legs, every named failure carries its owner, the live legs are SCHEDULED with their exact prerequisite and ruling, clauses cover 1–12 exactly once", binding.length === 0, binding.join("; ") || "bound");
  if (!fs.existsSync(FIXTURE)) blocked(`challenge fixture absent at ${FIXTURE}`);
  const fixture = readJson(FIXTURE);
  const relay = await relayLeg(fixture.challenge);
  evidence.relay = relay;
  ok("RELAY: the attach is authenticated by an active editor-open lease naming the service (an unknown, revoked, wrong-action or foreign lease and an effect on another environment are refused by name with nothing submitted); the relay parks exactly what the App lane parks minus the attach refs, under the user's own identity, with a caller-supplied grant stripped and no grant on the record; the notification carries the challenge's hashes, audience, receipt ref and preimage sha and run-bound links to the App's decision and never a facet, preimage, grant or key (the grammar refuses a smuggled facet and a wrong hash); a challenge without a preimage yields a notification with no approve link; the decision is the lane's own (mint for the card's hashes, the identical retry, the daemon's typed refusal finalizing); and the same operation admitted through the relay and through the App lane leaves identical records — with the parity oracle's negative proven", relay.findings.length === 0, relay.findings.join("; ") || `${relay.runs_driven} runs driven; notification members ${relay.notification_members.join(",")}`);
  const render = renderFindings();
  evidence.render = render;
  ok("RENDER: the extension's VS-Code-free renderer executes here (node:test, 3+ cases): a notification becomes one message and the actions that open the App's decision, never an in-editor approval; it depends on no editor host", render.length === 0, render.join("; ") || "rendered");
  const src = sourceFindings({ relay: fs.readFileSync(RELAY, "utf8"), runs: fs.readFileSync(RUNS, "utf8"), serve: fs.readFileSync(SERVE, "utf8"), extension: fs.readFileSync(path.join(EXTENSION_DIR, "extension.js"), "utf8") });
  evidence.source = src;
  ok("SOURCE: the relay imports no authority module and no minter, names no minter, reads no key path or test-signer flag, writes no grant member, submits only through the lane and carries no decision path; the lane's single mint call site is unchanged; the serve's relay route sits behind the local-run cache admission, submits through the relay, and has no decision route of its own; the extension wires the renderer", src.length === 0, src.join("; ") || "pinned");
  const green = (n) => ({ n, executed: [{ script: `g${n}`, status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 0 }, executed_assertions: 5, floor_expected: 5 }] });
  const base = []; for (let n = 1; n <= 12; n += 1) base.push(green(n));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 8 ? { n: 8, absence: { what: "no daemon push channel for challenges", owner: "a daemon change" } } : r)));
  const withScheduled = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } } : r)));
  const scheduledNoRuling = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 1 ? { n: 1, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 6 ? { n: 6, executed: [{ script: "x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const reach = verdict(base.map((r) => (r.n === 4 ? { n: 4, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 1 } }] } : r)));
  const missing = verdict(base.filter((r) => r.n !== 5));
  ok("the verdict is a pure function of the clause rows: all executed green with no absence → PASS; a typed absence or a scheduled live leg → NAMED FAILURE; a scheduled leg without a ruling, a fabricated success row, a red gate, a reach beyond loopback or a missing clause → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && withScheduled.kind === "named_failure" && scheduledNoRuling.kind === "fail" && fabricated.kind === "fail" && red.kind === "fail" && reach.kind === "fail" && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${withScheduled.kind}/${scheduledNoRuling.kind}/${fabricated.kind}/${red.kind}/${reach.kind}/${missing.kind}`);
  const cf = canonFindings(fs.readFileSync(CANON_DOCTRINE, "utf8"), fs.readFileSync(CANON_SURFACES, "utf8"), fs.readFileSync(CANON_WALLET, "utf8"));
  ok("canon binds the gate: daemon-runtime/doctrine.md says an adapter that meets a wallet challenge relays it and holds no key, mints no authority and caches no grant; core-clients-surfaces.md says an effect from an attached editor parks the same way through the relay and the notification carries never a facet, a grant or a key; wallet-network/doctrine.md says an attached editor is not a GuardianSurface; the first two name check:editor-challenge-relay", cf.length === 0, cf.join("; ") || "read from the three canon owners");
  return { fixture };
}

// ---- mutation ---------------------------------------------------------------------------------------------
async function mutation() {
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(APP_DIR, "package.json"));
  const floors = readJson(FLOORS);
  let f = bindingFindings(CLAUSES.map((c) => (c.n === 1 ? { ...c, executed_by: [{ ...LANE, script: "check:a-script-that-does-not-exist" }] } : c)), { rootPkg, appPkg, floors });
  plant("a clause bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 12 ? { ...c, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : c)), { rootPkg, appPkg, floors });
  plant("the live legs scheduled without a ruling", f.some((x) => /scheduled_without_prerequisite_or_ruling/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.filter((c) => c.n !== 5), { rootPkg, appPkg, floors });
  plant("the no-keys clause silently dropped", f.some((x) => /clause_missing: 5/u.test(x)), f[0]);
  const fixture = readJson(FIXTURE);
  const clean = await relayLeg(fixture.challenge);
  plant("the positive control: the in-process relay over the fixture has no finding", clean.findings.length === 0, clean.findings.join("; ") || "clean");
  const forged = structuredClone(fixture.challenge); forged.approval.request_hash = `sha256:${"0".repeat(64)}`;
  f = (await relayLeg(forged)).findings;
  plant("a challenge whose request hash does not match its preimage (refused inside the relayed park by the card harness of the lane, and named by the grammar)", f.length > 0, f[0]);
  const n = buildEditorChallengeNotification({ id: "pop_x", status: "awaiting_operator_approval", pendingApproval: { kind: PROVIDER_OPERATION_KIND, challenge: fixture.challenge, policy_hash: fixture.challenge.approval.policy_hash, request_hash: fixture.challenge.approval.request_hash, audience: null, target_scope: fixture.challenge.approval.target_scope, required_scopes: [], receipt_ref: fixture.challenge.receipt_ref, request: { op: "create", environment_ref: "e", provider_id: "p" }, byte_derived: true } }, { refs: ATTACH });
  for (const [label, mutate, code] of [
    ["a notification that carries the preimage", (x) => { x.request_preimage = fixture.challenge.approval.request_preimage; }, "forbidden_member:request_preimage"],
    ["a notification that carries a grant", (x) => { x.wallet_approval_grant = { approver_sig: "x" }; }, "forbidden_member:wallet_approval_grant"],
    ["a notification whose deny link points at another run", (x) => { x.decision.deny_url = "/__ioi/runs/pop_other/deny"; }, "deny_link_not_run_bound"],
    ["a notification with a truncated request hash", (x) => { x.request_hash = x.request_hash.slice(0, 30); }, "request_hash_not_the_challenges"],
    ["a notification that carries a bearer session", (x) => { x.message = `${x.message} ioi_sess_abcdef`; }, "bearer_material"],
  ]) {
    const m = structuredClone(n); mutate(m);
    const g = verifyNotificationGrammar(m, fixture.challenge, { runId: "pop_x" });
    plant(label, g.includes(code), g[0]);
  }
  const a = verifyAttach({ editor_service_ref: ATTACH.editor_service_ref, access_lease_ref: ATTACH.access_lease_ref, session_ref: null, environment_ref: ATTACH.environment_ref }, [{ ...GRANTS[0], status: "expired" }]);
  plant("an expired attach lease accepted", a.ok === false && a.code === "editor_attach_lease_expired", a.code);
  const sources = { relay: fs.readFileSync(RELAY, "utf8"), runs: fs.readFileSync(RUNS, "utf8"), serve: fs.readFileSync(SERVE, "utf8"), extension: fs.readFileSync(path.join(EXTENSION_DIR, "extension.js"), "utf8") };
  f = sourceFindings({ ...sources, relay: `${sources.relay}\nimport { mintLocalApproverGrant } from "./wallet-authority.mjs";\n` });
  plant("a relay that imports the authority module (a second spine)", f.includes("relay_imports_authority_module"), f[0]);
  f = sourceFindings({ ...sources, relay: sources.relay.replace(/submitProviderOperation\(\{ body, daemonHeaders/u, "postDirect({ body, daemonHeaders") });
  plant("a relay that bypasses the lane", f.includes("relay_bypasses_the_lane"), f[0]);
  f = sourceFindings({ ...sources, relay: `${sources.relay}\nexport async function decideFromEditor(x) { return decideRunApproval(x); }\n` });
  plant("a relay that carries a decision path", f.includes("relay_carries_a_decision_path"), f[0]);
  f = sourceFindings({ ...sources, serve: sources.serve.replace(/pathname === "\/__ioi\/editor-relay\/provider-ops" && req\.method === "POST"/u, "pathname === \"/__ioi/editor-relay/provider-ops-x\" && req.method === \"POST\"") });
  plant("a serve without the relay route", f.includes("serve_relay_route_missing"), f[0]);
  f = sourceFindings({ ...sources, serve: `${sources.serve}\n// if (pathname === "/__ioi/editor-relay/approve") {}\n` });
  plant("a serve with a relay decision route", f.includes("serve_relay_has_a_decision_route"), f[0]);
  const p = receiptParity({ a: 1, b: { c: 2 } }, { a: 1, b: { c: 3 } });
  plant("the parity oracle on a nested value change", p.includes("value_differs:b"), p[0]);
  const c = canonFindings(fs.readFileSync(CANON_DOCTRINE, "utf8").replace(/`check:editor-challenge-relay`/gu, "`check:something-else`"), fs.readFileSync(CANON_SURFACES, "utf8"), fs.readFileSync(CANON_WALLET, "utf8"));
  plant("canon that no longer names the gate", c.includes("canon_doctrine_gate_missing"), c[0]);
  const fake = verdict(CLAUSES.map((x) => ({ n: x.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full gate: the REAL relay ------------------------------------------------------------------------
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };
async function laneLegs() {
  const fp = []; const fq = [];
  const out = { park: {}, parity: {} };
  const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ecr-"));
  let resolver = null; let plane = null; let serve = null;
  try {
    const fixtureBaseEnv = { ...sanitizedVerifierBaseEnv(process.env), IOI_M049_ORDERING_PROFILE: "Solo", IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: "900", IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1200000" };
    const t0 = Date.now();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv: fixtureBaseEnv, wallClockChain: true });
    out.fixture_ready_seconds = Math.round((Date.now() - t0) / 1000);
    const approverKeyPath = path.join(scratch, "deployment-local-approver.key");
    fs.writeFileSync(approverKeyPath, `${FIXTURE_APPROVER_SEED_HEX}\n`, { mode: 0o600 });
    plane = await startIsolatedPlane({ baseEnv: process.env, env: { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_HYPERVISOR_DAEMON_BINARY: binary, IOI_WALLET_TEST_SIGNER: "" } });
    if (!plane) { fp.push("isolated_plane_did_not_start"); return { park: { findings: fp }, parity: { findings: ["not_reached"] }, ...out }; }
    const DAEMON = plane.daemonUrl;
    const token = bootstrapToken(plane.dataDir);
    const boot = await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "editor-relay-pass-1", email: "editor-relay@ioi.local" }) });
    const bootBody = await boot.json().catch(() => ({}));
    const cookie = bootBody.session_token ? `ioi_session=${bootBody.session_token}` : "";
    if (!cookie) fp.push(`bootstrap:${boot.status}`);
    const servePort = await freePort(); const productUiPort = await freePort();
    const SERVE_URL = `http://127.0.0.1:${servePort}`;
    let serveLog = "";
    serve = spawn(process.execPath, [SERVE], { cwd: APP_DIR, env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(productUiPort), IOI_PRODUCT_UI_PUBLIC: path.join(APP_DIR, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH: approverKeyPath, IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR: path.join(resolver.resourceDir, "commands"), IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF }, stdio: ["ignore", "pipe", "pipe"] });
    serve.stdout.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-32000); });
    serve.stderr.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-32000); });
    if (!(await waitFor(`${SERVE_URL}/__ioi/login`, 90000))) fp.push("serve_did_not_start");
    const jd = (base, p, init = {}) => fetch(`${base}${p}`, { ...init, redirect: "manual", headers: { ...(init.body ? { "content-type": "application/json" } : {}), cookie, ...(init.headers || {}) } }).then(async (r) => { const text = await r.text(); let body = {}; try { body = text ? JSON.parse(text) : {}; } catch { body = {}; } return { status: r.status, body, text }; });
    const rec = (r) => r?.body?.run ?? r?.body ?? {};
    const record = async (id, ms = 15000) => { const until = Date.now() + ms; let last = null; while (Date.now() < until) { last = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(id)}`); if (last.status === 200 && last.body?.ok === true) return last; await sleep(250); } return last; };
    const settle = async (id, ms = 180000) => { const until = Date.now() + ms; let last = null; while (Date.now() < until) { last = await record(id); if (["done", "failed", "denied"].includes(rec(last).status)) return last; await sleep(1000); } return last; };
    // ---- the attach tuple, created IN the daemon (no editor runtime) ----------------------------------------
    const attachFor = async (environmentRef) => {
      const env = await jd(DAEMON, "/v1/hypervisor/environments", { method: "POST", body: JSON.stringify({ spec: {} }) });
      const envId = env.body?.environment?.id ?? env.body?.environment?.environment_id ?? env.body?.id ?? env.body?.environment_id ?? "";
      const svc = await jd(DAEMON, "/v1/hypervisor/editor-services", { method: "POST", body: JSON.stringify({ environment_id: envId, target_profile: "vscode-browser" }) });
      const serviceId = svc.body?.editorService?.service_id ?? "";
      const lease = await jd(DAEMON, "/v1/hypervisor/editor-access-leases", { method: "POST", body: JSON.stringify({ environment_id: envId, service_id: serviceId }) });
      const leaseRef = lease.body?.lease_ref ?? lease.body?.lease?.lease_ref ?? lease.body?.grant_ref ?? "";
      const grants = (await jd(DAEMON, "/v1/hypervisor/authority/grants")).body?.grants ?? [];
      return { envId, serviceId, leaseRef, grants, statuses: [env.status, svc.status, lease.status], attach: { editor_service_ref: `environment_service:editor_${serviceId}`, access_lease_ref: leaseRef, session_ref: null, environment_ref: environmentRef } };
    };
    // ---- RELAY-PARK: the live deployment_intent effect relayed from the attached editor ----------------------
    const prep = await prepareProviderAccount({ daemonUrl: DAEMON, cookie, tag: `relay-${Date.now().toString(36)}` });
    const at = await attachFor(prep.body.environment_ref);
    if (!(at.envId && at.serviceId && at.leaseRef)) fp.push(`attach_tuple:${at.statuses.join("/")}:${at.leaseRef}`);
    const attachOk = verifyAttach(at.attach, at.grants);
    if (!attachOk.ok) fp.push(`attach_verify:${attachOk.code}`);
    const foreign = await jd(SERVE_URL, "/__ioi/editor-relay/provider-ops", { method: "POST", body: JSON.stringify({ body: prep.body, attach: { ...at.attach, access_lease_ref: "wallet.network://grant/agr_does_not_exist" } }) });
    if (!(foreign.status === 403 && foreign.body?.error?.code === "editor_attach_lease_unknown")) fp.push(`foreign_attach:${foreign.status}:${foreign.body?.error?.code}`);
    const relayed = await jd(SERVE_URL, "/__ioi/editor-relay/provider-ops", { method: "POST", body: JSON.stringify({ body: prep.body, attach: at.attach }) });
    const runId = relayed.body?.run_id ?? "";
    if (!(relayed.status === 202 && relayed.body?.parked === true && relayed.body?.byte_derived === true && relayed.body?.relayed === true && runId)) fp.push(`relay:${relayed.status}:${JSON.stringify(relayed.body).slice(0, 160)}`);
    const parked = rec(await record(runId));
    const pending = parked.pending_approval ?? {};
    const challenge = pending.challenge ?? null;
    if (!(parked.status === "awaiting_operator_approval" && pending.kind === PROVIDER_OPERATION_KIND && challenge && typeof challenge.approval?.request_preimage === "string")) fp.push("durable_record_not_parked");
    if (!(typeof pending.audience === "string" && pending.audience === resolver.capabilityAccountId)) fp.push(`audience:${String(pending.audience).slice(0, 12)}`);
    const notification = relayed.body?.notification;
    const grammar = challenge ? verifyNotificationGrammar(notification, challenge, { runId }) : ["no_challenge"];
    if (grammar.length) fp.push(`notification:${grammar.join("/")}`);
    if (stable(parked.editor_notification) !== stable(notification)) fp.push("notification_not_persisted");
    if (JSON.stringify(parked).includes("wallet_approval_grant") || JSON.stringify(parked).includes(FIXTURE_APPROVER_SEED_HEX)) fp.push("record_carries_grant_or_key");
    const approveUrl = new URL(notification?.decision?.approve_url ?? "/x", SERVE_URL).pathname;
    const approve = await jd(SERVE_URL, approveUrl, { method: "POST", body: JSON.stringify({}) });
    if (!(approve.status === 202 && approve.body?.decision === "approved")) fp.push(`approve_via_link:${approve.status}:${JSON.stringify(approve.body).slice(0, 120)}`);
    const final = rec(await settle(runId));
    if (!(final.status === "failed" && final.error === "provider_operation_proposal_ref_required" && typeof final.provider_operation?.receipt_ref === "string")) fp.push(`typed_refusal:${final.status}/${final.error}`);
    const receipts = (await jd(DAEMON, "/v1/hypervisor/provider-receipts")).body?.receipts ?? [];
    const outcomes = receipts.filter((r) => r.environment_ref === prep.body.environment_ref).map((r) => r.outcome);
    if (!(outcomes.includes("authority_missing") && outcomes.includes("proposal_not_admitted"))) fp.push(`receipts:${outcomes.join(",")}`);
    out.park = { run_id: runId, audience: pending.audience, attach: at.attach, receipts: outcomes, refusal: final.error, notification_members: Object.keys(notification ?? {}).sort() };
    // ---- RELAY-PARITY: the same simulator-mode create through the relay and through the App lane -------------
    // One engaged Akash candidate source per daemon, and a refresh SUPERSEDES the previous quote batch: the
    // two operations run sequentially on the same account — the relay's first, settled, then a fresh
    // candidate for the App's — so neither quote expires under the other.
    const simA = await prepareSimulatorAccount({ daemonUrl: DAEMON, cookie, tag: `pa-${Date.now().toString(36)}`, scratch });
    if (simA.error) fq.push(`prepare:${simA.error}`);
    else {
      const atA = await attachFor(simA.body.environment_ref);
      const rA = await jd(SERVE_URL, "/__ioi/editor-relay/provider-ops", { method: "POST", body: JSON.stringify({ body: simA.body, attach: atA.attach }) });
      const idA = rA.body?.run_id ?? "";
      if (!(rA.status === 202 && rA.body?.parked && idA)) fq.push(`parity_submit_relay:${rA.status}:${JSON.stringify(rA.body).slice(0, 120)}`);
      const aA = await jd(SERVE_URL, `/__ioi/runs/${encodeURIComponent(idA)}/approve`, { method: "POST", body: JSON.stringify({}) });
      if (aA.status !== 202) fq.push(`parity_approve_relay:${aA.status}`);
      const fA = rec(await settle(idA));
      const simB = await prepareSimulatorAccount({ daemonUrl: DAEMON, cookie, tag: `pb-${Date.now().toString(36)}`, scratch, reuse: { account: simA.account, intent_ref: simA.intent_ref } });
      if (simB.error) fq.push(`prepare_b:${simB.error}`);
      const rB = simB.error ? { status: 0, body: {} } : await jd(SERVE_URL, "/__ioi/provider-ops", { method: "POST", body: JSON.stringify(simB.body) });
      const idB = rB.body?.run_id ?? "";
      if (!(rB.status === 202 && rB.body?.parked && idB)) fq.push(`parity_submit_app:${rB.status}:${JSON.stringify(rB.body).slice(0, 120)}`);
      const aB = idB ? await jd(SERVE_URL, `/__ioi/runs/${encodeURIComponent(idB)}/approve`, { method: "POST", body: JSON.stringify({}) }) : { status: 0 };
      if (aB.status !== 202) fq.push(`parity_approve_app:${aB.status}`);
      const fB = idB ? rec(await settle(idB)) : {};
      if (!(fA.status === "done" && fB.status === "done")) fq.push(`parity_admission:${fA.status}/${fA.error}/${fB.status}/${fB.error}`);
      const all = (await jd(DAEMON, "/v1/hypervisor/provider-receipts")).body?.receipts ?? [];
      const rcA = all.find((r) => r.receipt_ref === fA.provider_operation?.receipt_ref); const rcB = all.find((r) => r.receipt_ref === fB.provider_operation?.receipt_ref);
      const ops = (await jd(DAEMON, "/v1/hypervisor/provider-operations")).body?.operations ?? [];
      const opA = ops.find((o) => o.receipt_ref === fA.provider_operation?.receipt_ref); const opB = ops.find((o) => o.receipt_ref === fB.provider_operation?.receipt_ref);
      const volatile = ["receipt_id", "receipt_ref", "at", "operation_id", "grant_ref", "state_root", "environment_ref", "account_ref", "candidate_ref", "quote_ref", "idempotency_key", "lease_id", "issued_at", "exhausted_at", "expires_at", "admission_intent_ref", "request_hash", "policy_hash", "proposal_ref", "provider_operation_ref", "deployment_ref", "dseq", "bid_ref", "lease_ref", "record_id", "created_at", "provider_native", "revocation_ref", "resource_refs", "backing_provider", "proposal_consumption", "trajectory_admission", "budget_discovery", "spend_estimate", "cost_estimate"];
      const pr = receiptParity(rcA, rcB, { volatile }); const po = receiptParity(opA, opB, { volatile });
      const pa = receiptParity(fA.authority, fB.authority, { volatile: ["grantId", "expiresAt", "mintedAt", "policyHash", "requestHash"] });
      const pp = receiptParity(fA.provider_operation, fB.provider_operation, { volatile: [...volatile, "evidence", "decided_at", "capability_lease_ref", "request", "reason"] });
      if (!(rcA && rcB && rcA.outcome === "ok" && rcB.outcome === "ok")) fq.push(`parity_receipts_missing:${rcA?.outcome}/${rcB?.outcome}`);
      if (pr.length || po.length || pa.length || pp.length) fq.push(`parity:${[...pr, ...po, ...pa, ...pp].join("/")}`);
      const recon = (await jd(DAEMON, "/v1/hypervisor/provider-spend/reconciliation")).body;
      const expA = (recon?.rows ?? []).find((r) => r.environment_ref === simA.body.environment_ref); const expB = (recon?.rows ?? []).find((r) => r.environment_ref === simB.body.environment_ref);
      if (!(expA?.status === "open" && expB?.status === "open")) fq.push(`parity_exposure:${expA?.status}/${expB?.status}`);
      for (const [sim, id] of [[simA, idA], [simB, idB]]) {
        const del = await jd(SERVE_URL, "/__ioi/provider-ops", { method: "POST", body: JSON.stringify({ provider_id: sim.body.provider_id, op: "delete", environment_ref: sim.body.environment_ref, owner_ref: sim.body.owner_ref, idempotency_key: `${sim.body.idempotency_key}-delete` }) });
        if (del.body?.parked === true) await jd(SERVE_URL, `/__ioi/runs/${encodeURIComponent(del.body.run_id)}/approve`, { method: "POST", body: JSON.stringify({}) });
        if (del.body?.run_id) await settle(del.body.run_id);
        void id;
      }
      out.parity = { relay_run_id: idA, app_run_id: idB, receipt_members: Object.keys(rcA ?? {}).sort(), operation_members: Object.keys(opA ?? {}).sort(), receipt_a: rcA?.receipt_ref, receipt_b: rcB?.receipt_ref };
    }
    out.serve_log_tail = serveLog.slice(-600);
  } catch (error) {
    fp.push(`lane_crashed:${String(error?.message || error).slice(0, 160)}`);
  } finally {
    if (serve) { try { serve.kill("SIGTERM"); } catch { /* gone */ } }
    if (plane) { try { await plane.stop(); } catch { /* gone */ } }
    if (resolver?.stop) { try { await resolver.stop(); } catch { /* gone */ } }
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  return { park: { findings: fp, ...out.park }, parity: { findings: fq, ...out.parity }, fixture_ready_seconds: out.fixture_ready_seconds ?? null, serve_log_tail: out.serve_log_tail ?? null };
}
async function runGate(g, workDir, floors, n) {
  const label = `${n}-${(g.floor || g.script).replace(/[^A-Za-z0-9]+/gu, "-")}`;
  const censusDir = path.join(workDir, "census", label);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000" };
  const argvRun = ["npm", "run", "-s", g.script, ...(g.workspace ? [`--workspace=${g.workspace}`] : [])];
  const iso = await runIsolated({ label, argv: argvRun, cwd: ROOT, env, workDir, bridges: [], timeoutMs: g.minutes * 60_000 });
  const classified = classifyLedger(iso.ledger, { declaredHosts: [], declaredNames: [] });
  const logFile = path.join(workDir, `${label}.log`);
  const files = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((f) => f.endsWith(".json")).map((f) => path.join(censusDir, f)) : [];
  const evidenceFile = files[0] || (fs.existsSync(logFile) ? logFile : null);
  const floorRow = g.floor ? (floors.verifiers ?? []).find((r) => r.id === g.floor) : null;
  const censusJson = files[0] ? readJson(files[0]) : null;
  return { script: g.script, kind: g.kind, status: iso.status, seconds: iso.seconds, isolation: iso.isolation, ledger: { attempts: classified.counts?.attempts ?? 0, loopback: classified.counts?.loopback ?? 0, reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0) }, evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null, evidence_sha256: evidenceFile ? sha256File(evidenceFile) : null, executed_assertions: censusJson?.executed_assertions ?? null, floor_expected: floorRow?.runtime_assertions ?? null };
}
async function full() {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ecr-gate-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  console.log("\n# the REAL relay: an attach tuple created in an isolated daemon (no editor runtime), the wallet fixture, this runner's own serve");
  const lane = await laneLegs();
  evidence.relay_park = lane.park; evidence.relay_parity = lane.parity; evidence.fixture_ready_seconds = lane.fixture_ready_seconds;
  console.log(`  → RELAY-PARK ${lane.park.findings.length === 0 ? "attached, relayed, parked, notified, approved on the card, refused typed, receipts read back" : lane.park.findings.join("; ")}`);
  console.log(`  → RELAY-PARITY ${lane.parity.findings.length === 0 ? "the same operation admitted through the relay and the App; receipts, records and runs identical modulo identities" : lane.parity.findings.join("; ")}`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ relay: evidence.relay, render: evidence.render, source: evidence.source, relay_park: evidence.relay_park, relay_parity: evidence.relay_parity }, null, 2)}\n`);
  const legGreen = { "relay (this runner)": (evidence.relay?.findings?.length ?? 1) === 0, "render (this runner)": (evidence.render?.length ?? 1) === 0, "source (this runner)": (evidence.source?.length ?? 1) === 0, "relay-park (this runner)": lane.park.findings.length === 0, "relay-parity (this runner)": lane.parity.findings.length === 0 };
  const selfRun = (name) => ({ script: name, status: legGreen[name] ? 0 : 1, seconds: 0, isolation: "in-process", ledger: { attempts: 0, loopback: 0, reach: 0 }, evidence: path.relative(ROOT, selfEvidence), evidence_sha256: sha256File(selfEvidence), executed_assertions: null, floor_expected: null });
  const done = new Map(); const rows = [];
  for (const c of CLAUSES) {
    const row = { n: c.n, demand: c.demand, executed: [], absence: c.absence || null, scheduled: c.scheduled || null };
    for (const g of c.executed_by ?? []) {
      if (g.kind === "self") { row.executed.push(selfRun(g.script)); continue; }
      if (!done.has(g.script)) {
        console.log(`\n# ${g.script} — inside the harness (clause ${c.n})`);
        done.set(g.script, await runGate(g, workDir, floors, c.n));
        const r = done.get(g.script);
        console.log(`  → exit ${r.status} in ${r.seconds}s · ${r.executed_assertions ?? "?"}${r.floor_expected != null ? `/${r.floor_expected}` : ""} · ledger ${r.ledger.attempts} attempts, ${r.ledger.loopback} loopback, ${r.ledger.reach} reach`);
      }
      row.executed.push(done.get(g.script));
    }
    rows.push(row);
  }
  const v = verdict(rows);
  evidence.clauses = rows; evidence.verdict = v;
  console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
  for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 170)} → ${a.owner.slice(0, 120)}`);
  return v;
}

// ---- main -------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "editor-challenge-relay", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
