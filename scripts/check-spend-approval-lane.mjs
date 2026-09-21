#!/usr/bin/env node
// check:spend-approval-lane — M08.11: the Hypervisor App's spend-approval lane, as a gate
// (docs/architecture/components/hypervisor/core-clients-surfaces.md § Sessions; byo-provider-plane.md § The
// challenge carries the bytes that will execute; wallet-network/doctrine.md § The presentation is byte-derived;
// register R-213, executing R-212(3) and R-14).
//
// CANON. The App displays and routes; the custody tier signs. A provider operation submitted through the App
// goes to the daemon under the operator's own identity; the daemon's refusal — carrying the exact bytes its
// commitment hashes cover — PARKS a run on the operator's approval as the byte-derived card; the operator's
// decision hands off to the deployment's custody tier (the deployment-local operator key, R-14), which mints
// ONE one-use grant for exactly the card's hashes and records it on the authority node; the App retries the
// IDENTICAL request with the grant and renders the daemon's receipt, admitted operation and spend exposure.
// The App holds no grant bytes and signs nothing on its own act.
//
// WHAT THIS RUNNER IS. The acceptance's demands are CLAUSES, each EXECUTED by one of this runner's own legs,
// by a floored gate that already proves it, or NAMED (a typed failure with an owner, or a SCHEDULED live leg
// with its exact prerequisite and ruling). The runner's own legs:
//   PARK     — in-process: the lane's park and dispatch functions driven over the tracked M03.9 challenge
//              fixture with an injected daemon transport and custody tier: the parked record's shape (the whole
//              challenge, the exact request with any caller-supplied grant STRIPPED, the hashes, the audience,
//              the receipt ref, no grant), the card and the pane projection, the refusal park (no preimage →
//              deny only), the handoff (the minter called for exactly the card's hashes and audience, the grant
//              recorded, the IDENTICAL request retried with the grant under the operator's identity, the
//              daemon's typed answer finalizing the run, no grant bytes on the durable record, a second approve
//              refused, a tier that mints nothing leaving the run parked), deny.
//   SOURCE   — the serve's route and cache admission, the dispatch, the single mint call site, the stripped
//              grant, the test signer's flag, the pane's projection (pins).
//   LANE     — full mode, the REAL lane: the wallet fixture beside an isolated daemon under its env, the
//              runner's OWN serve with the fixture's approver seed as the deployment-local key → LANE-PARK: the
//              live deployment_intent request (a sealed fake credential, live mode at a dead loopback endpoint,
//              an external-spend budget) parks WITH the daemon's audience, the card on Work / Sessions passes
//              the diff harness against the DURABLE record, approve mints and records one grant and the retry
//              ends at the daemon's typed refusal (a live create without a daemon-issued proposal is refused
//              BEFORE any provider is contacted), both receipts read back, no grant bytes on the record;
//              LANE-ADMIT: the simulator-mode quote-gated create parks, is approved and ADMITTED spend-free
//              (receipt ok with the grant ref and the one-shot lease, a simulated deployment, no provisioning
//              run), the spend exposure opens on the daemon's reconciliation and Operations shows the receipt,
//              and a parked-and-approved delete closes the exposure.
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills      CI-bound, seconds: the binding, PARK, SOURCE, the verdict rules, canon's binding. No daemon,
//                 no network, no credential.
//   --mutation    planted defects against the drills' oracles — each must go red.
//   (default)     the full gate: the drills, the LANE legs, then every executed gate inside the isolated-egress
//                 harness. Exit 0 pass, 2 named failure, 1 fail. This runner never spends: no grant is ever
//                 presented on a live create with a proposal, and the simulator records no provisioning.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "../apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import { PROVIDER_OPERATION_KIND, PROVIDER_OPS_PATH, decideRunApproval, getRun, listRunsAwaitingApproval, runRecord, submitProviderOperation } from "../apps/hypervisor/scripts/ioi-agent-runs.mjs";
import { projectRunTimeline } from "../apps/hypervisor/scripts/ioi-run-timeline.mjs";
import { projectProviderChallenge, renderProviderFacetsCard, verifyRenderedFacets } from "../apps/hypervisor/scripts/lib/approval-card-facets.mjs";
import { bootstrapToken, prepareProviderAccount, prepareSimulatorAccount } from "./lib/provider-challenge-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const FIXTURE = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m03-9-provider-challenge-fixture-2026-09-20.v1.json");
const CANON_SURFACES = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "core-clients-surfaces.md");
const CANON_PLANE = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "byo-provider-plane.md");
const CANON_WALLET = path.join(ROOT, "docs", "architecture", "components", "wallet-network", "doctrine.md");
const SERVE = path.join(APP_DIR, "scripts", "serve-product-ui.mjs");
const RUNS = path.join(APP_DIR, "scripts", "ioi-agent-runs.mjs");
const TIMELINE = path.join(APP_DIR, "scripts", "ioi-run-timeline.mjs");
const WALLET_AUTHORITY = path.join(APP_DIR, "scripts", "lib", "wallet-authority.mjs");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const DEPLOYMENT_AUTHORITY_REF = "domain://acme-host";
const FIXTURE_APPROVER_SEED_HEX = "07".repeat(32);
const LIVE_PREREQ = "an owner-authorized Akash account with a funded deposit (IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, IOI_WALLET_SECRET_PASS) for the live deployment_intent admission, and a local model (Ollama) with the deployment-local authority node for the session-execute card — each authorized leg by leg";
const LIVE_RULING = "R-139 (2026-09-14) and R-213 (2026-09-20): a missing credential, model or authority node blocks a live RUN, never the unit; the lane is proven spend-free on the daemon's typed refusal and the simulator-mode admission";
const HASH = /^sha256:[0-9a-f]{64}$/u;
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
const GRANT_MARKER = "APPROVER-SIG-MARKER-NEVER-ON-A-RECORD";

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const CARD_FACETS = gate("check:approval-card-facets", "approval-card-facets", 20);
const SESSION_TRUTH = gate("check:session-truth-rebind", "session-truth-rebind", 20);
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PARK = self("park");
const SOURCE = self("source");
const LANE_PARK = self("lane-park");
const LANE_ADMIT = self("lane-admit");

export const CLAUSES = [
  { n: 1, demand: "the App submits a provider operation under the operator's own identity and PARKS the daemon's refusal as the byte-derived card: the whole challenge, the exact request, the hashes, the audience and the receipt ref — and no grant", executed_by: [PARK, LANE_PARK] },
  { n: 2, demand: "the card on Work / Sessions and the SPA session pane is the daemon's own challenge, verbatim, with the decision endpoints", executed_by: [PARK, LANE_PARK, CARD_FACETS, SESSION_TRUTH] },
  { n: 3, demand: "a challenge without a preimage parks as a refusal that can only be denied", executed_by: [PARK] },
  { n: 4, demand: "the custody tier mints ONE one-use grant for exactly the card's hashes and the challenge's audience and records it on the authority node", executed_by: [PARK, LANE_PARK] },
  { n: 5, demand: "the App retries the IDENTICAL request with the grant under the operator's identity, and the daemon's answer — admitted, or its typed refusal — finalizes the run", executed_by: [PARK, LANE_PARK, LANE_ADMIT] },
  { n: 6, demand: "the App holds no grant and signs nothing on its own act: a caller-supplied grant is stripped, the durable record carries the hashes and the grant id only, a tier that mints nothing leaves the run parked, a second approve is refused", executed_by: [PARK, SOURCE, LANE_PARK] },
  { n: 7, demand: "after admission the receipt, the admitted operation and the spend exposure are the daemon's, reflected on Operations and the reconciliation, and a parked-and-approved delete closes the exposure", executed_by: [LANE_ADMIT] },
  { n: 8, demand: "deny records the operator's refusal and mints nothing", executed_by: [PARK], absence: { what: "a denial produces no signed receipt anywhere: the serve's deny mints nothing and writes no daemon receipt, and no deny act exists on the authority node or the wallet fixture", owner: "a follow-on slice of M03.9 (owner question, R-212)" } },
  { n: 9, demand: "the handoff to a passkey step-up or a graduated wallet app", executed_by: [], absence: { what: "the alpha's custody tier is the deployment-local operator key (R-14): the App has no passkey prompt and the wallet-network prototype is a design mock; a passkey step-up or a graduated wallet app replaces the tier without changing the card", owner: "the graduated wallet app · the passkey tier (owner questions, R-212/R-213)" } },
  { n: 10, demand: "the parked operation is reachable beside Governance / Approvals", executed_by: [], absence: { what: "a parked provider operation lives on Work / Sessions and the SPA session pane; no approvals-inbox plane reads the run record, so Governance / Approvals carries no row or link for it", owner: "a follow-on slice of M08.11 (owner question, R-213)" } },
  { n: 11, demand: "the C4 proposal for a live create or redeploy is issued under the operator's session before the retry", executed_by: [], absence: { what: "the lane does not issue provider-operation proposals in this cut: the daemon's typed refusal (provider_operation_proposal_ref_required, receipt proposal_not_admitted) is the honest terminal of the live path here, reached before any provider is contacted", owner: "a follow-on slice of M08.11 (owner question, R-213); the live admission is scheduled (clause 12)" } },
  { n: 12, demand: "the live deployment_intent admission through the lane, and the session-execute card live", executed_by: [], scheduled: { what: "the live direct-Akash deployment_intent create parked, approved and ADMITTED through this lane with a daemon-issued proposal, reaching bid, lease, C6 readback, teardown and provider-confirmed settlement; and the session-execute card live under the deployment-local tier (check:alpha-journey, IOI_ALPHA_JOURNEY_AUTHORITY=deployment)", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } },
];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.spend-approval-lane-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], park: null, source: null, lane_park: null, lane_admit: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `spend-approval-lane-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256File = (f) => (fs.existsSync(f) ? `sha256:${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}` : null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tick = () => new Promise((r) => setImmediate(r));

// ---- the in-process lane (stubbed daemon and custody tier) ------------------------------------------------
function stubTransport(script) {
  const calls = [];
  const transport = async (method, p, payload, headers) => {
    const n = calls.length;
    calls.push({ method, path: p, payload: structuredClone(payload ?? null), headers: { ...(headers || {}) } });
    const reply = typeof script === "function" ? script(n, payload) : script[Math.min(n, script.length - 1)];
    return structuredClone(reply);
  };
  return { transport, calls };
}
function stubTier({ mint = true } = {}) {
  const calls = { mint: [], record: [] };
  const grant = { schema_version: 1, grant_id: "grant_stub_0001", counter: 1, max_usages: 1, expires_at: 1850000000000, approver_sig: GRANT_MARKER, request_hash: "stub", policy_hash: "stub", audience: "stub" };
  const minter = async (args) => { calls.mint.push({ ...args }); return mint ? structuredClone(grant) : null; };
  const recorder = async ({ grant: g, targetScope }) => { calls.record.push({ grant_id: g?.grant_id ?? null, targetScope, carried_marker: JSON.stringify(g).includes(GRANT_MARKER) }); return { recorder: "stub", request_hash: "stub" }; };
  return { minter, recorder, calls, grant };
}
const PROPOSAL_REFUSAL = { status: 403, body: { ok: false, reason: "provider_operation_proposal_ref_required", outcome: "proposal_not_admitted", receipt_ref: "agentgres://provider-receipt/prc_stub_proposal", admission_code: "provider_operation_proposal_ref_required" } };
const ADMITTED = { status: 200, body: { ok: true, outcome: "ok", receipt_ref: "agentgres://provider-receipt/prc_stub_ok", grant_ref: "wallet.network://grant/approval/stub", capability_lease: { lease_id: "lease_stub_0001", state: "exhausted", remaining_calls: 0 }, evidence: { deployment: { deployment_ref: "akash-deployment://akdep_stub", dseq: "simdseq_stub", execution_mode: "simulated_control_plane" } } } };

export async function parkLeg(fixtureChallenge) {
  const f = [];
  const out = {};
  const body = { provider_id: "pacc_stub", op: "create", environment_ref: "env-approval-card-fixture", plan: { sdl_yaml: "version: \"2.0\"\n", deposit_usd: 1.0, ceiling_amount: "1000", ceiling_denom: "uact", auto_topup: false, provider_selector: { mode: "any_marketplace", selection: "lowest_qualified_bid" } }, owner_ref: "org://local", idempotency_key: "approval-card-fixture", teardown_policy: "always_teardown_required", wallet_approval_grant: { schema_version: 1, approver_sig: GRANT_MARKER } };
  const expectedRequest = { ...body }; delete expectedRequest.wallet_approval_grant;
  const operator = { cookie: "ioi_session=ioi_sess_operator_stub" };
  // 1. park
  const t1 = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }]);
  const submitted = await submitProviderOperation({ body, daemonHeaders: operator, transport: t1.transport });
  const run = getRun(submitted.run_id);
  if (!(submitted.ok && submitted.status === 202 && submitted.parked === true && submitted.byte_derived === true)) f.push(`park_reply:${JSON.stringify(submitted).slice(0, 120)}`);
  if (run?.status !== "awaiting_operator_approval" || run?.pendingApproval?.kind !== PROVIDER_OPERATION_KIND) f.push("park_state");
  if (stable(run?.pendingApproval?.challenge) !== stable(fixtureChallenge)) f.push("park_challenge_not_whole");
  if (stable(run?.pendingApproval?.request) !== stable(expectedRequest)) f.push("park_request_not_identical_or_grant_not_stripped");
  if (run?.pendingApproval?.request_hash !== fixtureChallenge.approval.request_hash || run?.pendingApproval?.policy_hash !== fixtureChallenge.approval.policy_hash) f.push("park_hashes");
  if (run?.pendingApproval?.receipt_ref !== fixtureChallenge.receipt_ref) f.push("park_receipt_ref");
  if (run?.pendingApproval?.audience !== (fixtureChallenge.approval.audience ?? null)) f.push("park_audience");
  if (run?.authority?.grantId !== null || run?.authority?.requestHash !== fixtureChallenge.approval.request_hash) f.push("park_authority");
  if (JSON.stringify(runRecord(run)).includes(GRANT_MARKER)) f.push("park_record_carries_caller_grant");
  if (!(t1.calls.length === 1 && t1.calls[0].path === PROVIDER_OPS_PATH && t1.calls[0].headers.cookie === operator.cookie && stable(t1.calls[0].payload) === stable(expectedRequest))) f.push("park_transport_not_operator_identity_or_body");
  if (!listRunsAwaitingApproval().some((r) => r.id === run?.id)) f.push("park_not_listed_awaiting");
  const tl = projectRunTimeline(run, {})?.turns?.[0]?.approval;
  const projection = projectProviderChallenge(fixtureChallenge);
  if (!(tl?.state === "awaiting" && tl?.kind === PROVIDER_OPERATION_KIND && tl?.byteDerived === true && tl?.facets?.length === projection.facets.length && tl?.requestHash === projection.request_hash && tl?.approveUrl === `/__ioi/runs/${encodeURIComponent(run.id)}/approve`)) f.push("pane_projection");
  const html = renderProviderFacetsCard(projectProviderChallenge(run.pendingApproval.challenge), { approveUrl: tl?.approveUrl, denyUrl: tl?.denyUrl, returnTo: "/work/sessions" });
  const harness = verifyRenderedFacets(html, fixtureChallenge);
  if (harness.length) f.push(`card_harness:${harness.join("/")}`);
  out.parked_run_id = run?.id;
  // 2. the refusal park (no preimage): deny only
  const stripped = structuredClone(fixtureChallenge); delete stripped.approval.request_preimage;
  const t2 = stubTransport([{ status: 501, body: stripped }]);
  const s2 = await submitProviderOperation({ body, daemonHeaders: operator, transport: t2.transport });
  const r2 = getRun(s2.run_id);
  if (!(s2.parked === true && s2.byte_derived === false && r2?.pendingApproval?.byte_derived === false)) f.push("refusal_park");
  const a2 = await decideRunApproval({ runId: s2.run_id, decision: "approve", daemonHeaders: operator, ...stubTier().tierArgs?.() ?? {}, transport: t2.transport });
  if (!(a2.ok === false && a2.status === 409 && a2.error?.code === "challenge_not_byte_derived") || r2?.status !== "awaiting_operator_approval") f.push(`refusal_approve:${a2?.error?.code}`);
  const d2 = await decideRunApproval({ runId: s2.run_id, decision: "deny", reason: "not the bytes", daemonHeaders: operator });
  if (!(d2.ok === true && d2.decision === "denied" && r2?.status === "denied" && r2?.pendingApproval?.decision === "denied") || t2.calls.length !== 1) f.push("refusal_deny");
  const refusalHtml = renderProviderFacetsCard(projectProviderChallenge(stripped), { approveUrl: "/x", denyUrl: "/y" });
  if (!/data-ioi-provider-approval-refused="request_preimage_missing"/u.test(refusalHtml) || /Approve exactly this/u.test(refusalHtml)) f.push("refusal_card");
  // 3. the handoff: a tier that mints nothing leaves the run parked
  const noTier = stubTier({ mint: false });
  const t3 = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }]);
  const s3 = await submitProviderOperation({ body: expectedRequest, daemonHeaders: operator, transport: t3.transport });
  const a3 = await decideRunApproval({ runId: s3.run_id, decision: "approve", daemonHeaders: operator, minter: noTier.minter, recorder: noTier.recorder, transport: t3.transport });
  if (!(a3.status === 501 && a3.error?.code === "local_approver_not_configured" && getRun(s3.run_id)?.status === "awaiting_operator_approval" && noTier.calls.record.length === 0 && t3.calls.length === 1)) f.push("no_tier_still_parked");
  // 4. the handoff: mint for exactly the card's hashes, record, retry the IDENTICAL request, the typed refusal finalizes
  const tier = stubTier();
  const t4 = stubTransport([{ status: 501, body: structuredClone(fixtureChallenge) }, PROPOSAL_REFUSAL]);
  const s4 = await submitProviderOperation({ body: expectedRequest, daemonHeaders: operator, transport: t4.transport });
  const decider = { cookie: "ioi_session=ioi_sess_operator_deciding" };
  const a4 = await decideRunApproval({ runId: s4.run_id, decision: "approve", daemonHeaders: decider, minter: tier.minter, recorder: tier.recorder, transport: t4.transport });
  await tick(); await sleep(20);
  const r4 = getRun(s4.run_id);
  if (!(a4.ok === true && a4.status === 202 && a4.decision === "approved" && a4.kind === PROVIDER_OPERATION_KIND)) f.push(`handoff_reply:${JSON.stringify(a4).slice(0, 100)}`);
  if (!(tier.calls.mint.length === 1 && tier.calls.mint[0].policyHash === fixtureChallenge.approval.policy_hash && tier.calls.mint[0].requestHash === fixtureChallenge.approval.request_hash && tier.calls.mint[0].audience === (fixtureChallenge.approval.audience ?? null))) f.push("handoff_mint_not_the_cards_hashes");
  if (!(tier.calls.record.length === 1 && tier.calls.record[0].grant_id === "grant_stub_0001" && tier.calls.record[0].targetScope === fixtureChallenge.approval.target_scope && tier.calls.record[0].carried_marker)) f.push("handoff_not_recorded");
  const retry = t4.calls[1];
  if (!(t4.calls.length === 2 && retry?.path === PROVIDER_OPS_PATH && retry?.headers?.cookie === decider.cookie && stable(retry?.payload) === stable({ ...expectedRequest, wallet_approval_grant: tier.grant }))) f.push("retry_not_identical_request_with_grant_under_operator");
  if (!(r4?.status === "failed" && r4?.error === "provider_operation_proposal_ref_required" && r4?.providerOperation?.outcome === "proposal_not_admitted" && r4?.providerOperation?.receipt_ref === PROPOSAL_REFUSAL.body.receipt_ref)) f.push(`typed_refusal_not_finalized:${r4?.status}/${r4?.error}`);
  if (!(r4?.authority?.grantId === "grant_stub_0001" && r4?.authority?.approver === "deployment_local_operator" && r4?.authority?.requestHash === fixtureChallenge.approval.request_hash)) f.push("authority_record");
  const record = JSON.stringify(runRecord(r4));
  if (record.includes(GRANT_MARKER) || record.includes("wallet_approval_grant")) f.push("record_carries_grant_bytes");
  const again = await decideRunApproval({ runId: s4.run_id, decision: "approve", daemonHeaders: decider, minter: tier.minter, recorder: tier.recorder, transport: t4.transport });
  if (!(again.status === 409 && again.error?.code === "run_not_awaiting_approval" && tier.calls.mint.length === 1)) f.push("second_approve_not_refused");
  const tl4 = projectRunTimeline(r4, {})?.turns?.[0];
  if (!(tl4?.approval?.state === "approved" && tl4?.approval?.approveUrl === null && tl4?.providerOperation?.outcome === "proposal_not_admitted" && tl4?.providerOperation?.receiptRef === PROPOSAL_REFUSAL.body.receipt_ref)) f.push("pane_after_decision");
  // 5. admission (the daemon's ok answer) finalizes done with the receipt, the grant ref and the lease
  const tier5 = stubTier();
  const t5 = stubTransport([{ status: 403, body: structuredClone(fixtureChallenge) }, ADMITTED]);
  const s5 = await submitProviderOperation({ body: expectedRequest, daemonHeaders: operator, transport: t5.transport });
  await decideRunApproval({ runId: s5.run_id, decision: "approve", daemonHeaders: operator, minter: tier5.minter, recorder: tier5.recorder, transport: t5.transport });
  await tick(); await sleep(20);
  const r5 = getRun(s5.run_id);
  if (!(r5?.status === "done" && r5?.providerOperation?.ok === true && r5?.providerOperation?.receipt_ref === ADMITTED.body.receipt_ref && r5?.providerOperation?.grant_ref === ADMITTED.body.grant_ref && r5?.providerOperation?.capability_lease_ref === "lease_stub_0001")) f.push(`admitted_not_finalized:${r5?.status}`);
  if (JSON.stringify(runRecord(r5)).includes(GRANT_MARKER)) f.push("admitted_record_carries_grant");
  const tl5 = projectRunTimeline(r5, {})?.turns?.[0]?.providerOperation;
  if (!(tl5?.ok === true && tl5?.grantRef === ADMITTED.body.grant_ref && tl5?.capabilityLeaseRef === "lease_stub_0001")) f.push("pane_after_admission");
  // 6. an invalid submission and a non-challenge answer
  const bad = await submitProviderOperation({ body: { op: "create" }, daemonHeaders: operator, transport: t5.transport });
  if (!(bad.ok === false && bad.status === 400 && bad.error?.code === "provider_operation_request_invalid")) f.push("invalid_request_not_refused");
  const t6 = stubTransport([{ status: 422, body: { ok: false, code: "akash_live_marketplace_facets_required", reason: null } }]);
  const s6 = await submitProviderOperation({ body: expectedRequest, daemonHeaders: operator, transport: t6.transport });
  if (!(s6.parked === false && s6.ok === false && getRun(s6.run_id)?.status === "failed" && /akash_live_marketplace_facets_required|422/u.test(getRun(s6.run_id)?.error ?? ""))) f.push("non_challenge_not_finalized");
  return { findings: f, ...out, runs_driven: 6 };
}
export function sourceFindings({ serve, runs, timeline, walletAuthority }) {
  const f = [];
  const need = [
    ["serve_route", serve, /pathname === "\/__ioi\/provider-ops" && req\.method === "POST"/u],
    ["serve_cache_admission", serve, /pathname === "\/__ioi\/provider-ops"[\s\S]{0,400}localRunCacheAdmission\(req\)/u],
    ["serve_submits_through_the_lane", serve, /submitProviderOperation\(\{ body: payload, daemonHeaders: cacheAdmission\.headers \}\)/u],
    ["serve_imports_lane", serve, /submitProviderOperation \} from "\.\/ioi-agent-runs\.mjs"/u],
    ["runs_dispatch", runs, /pending\.kind === PROVIDER_OPERATION_KIND\) \{[\s\S]{0,600}transport\("POST", PROVIDER_OPS_PATH, \{ \.\.\.pending\.request, wallet_approval_grant: grant \}, runDaemonHeaders\(run, true\)\)/u],
    ["runs_byte_derived_guard", runs, /code: "challenge_not_byte_derived"/u],
    ["runs_strips_caller_grant", runs, /delete request\.wallet_approval_grant;/u],
    ["runs_default_tier", runs, /minter = mintLocalApproverGrant, recorder = recordLocalApproverGrant/u],
    ["runs_record_carries_no_grant", runs, /grantId: grant\?\.grant_id \|\| grant\?\.id \|\| grant\?\.approval_id \|\| null,/u],
    ["timeline_projects_operation", timeline, /providerOperation: run\.providerOperation \? \{/u],
    ["test_signer_flag_only", walletAuthority, /return process\.env\[TEST_SIGNER_FLAG\] === "1";/u],
  ];
  for (const [name, text, re] of need) if (!re.test(text)) f.push(`pin_${name}_missing`);
  const mintCalls = (runs.match(/mintLocalApproverGrant\(/gu) || []).length;
  if (mintCalls !== 1) f.push(`mint_call_sites:${mintCalls}!=1`);
  if (/wallet_approval_grant: grant \}\)[\s\S]{0,200}run\.grant = /u.test(runs) || /run\.pendingApproval\.grant|pendingApproval\.grant = /u.test(runs)) f.push("runs_caches_grant");
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
export function canonFindings(surfaces, plane, wallet) {
  const f = [];
  const s = surfaces.replace(/\s+/gu, " ");
  const p = plane.replace(/\s+/gu, " ");
  const w = wallet.replace(/\s+/gu, " ");
  const need = [["surfaces_park", s, /A blocked provider operation submitted through the App parks the same way/u], ["surfaces_handoff", s, /hands off to the deployment's custody tier/u], ["surfaces_no_grant", s, /the App holds no grant, signs nothing on its own act/u], ["surfaces_gate", s, /`check:spend-approval-lane`/u], ["plane_gate", p, /`check:spend-approval-lane`/u], ["plane_identical", p, /the App retries the identical request/u], ["wallet_guardian", w, /The Hypervisor App is a GuardianSurface projection under the `deployment_local_operator` tier/u], ["wallet_gate", w, /`check:spend-approval-lane`/u]];
  for (const [name, text, re] of need) if (!re.test(text)) f.push(`canon_${name}_missing`);
  return f;
}
export function verdict(rows) {
  const failures = [];
  const absences = [];
  const seen = new Set();
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
    if (r.not_executed) absences.push({ n: r.n, what: `not executed in this run: ${r.not_executed}`, owner: "this runner (on demand)" });
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
  const park = await parkLeg(fixture.challenge);
  evidence.park = park;
  ok("PARK: a provider operation submitted through the lane goes to the daemon under the operator's identity and the refusal PARKS a run as the byte-derived card — the whole challenge, the exact request with the caller-supplied grant STRIPPED, the hashes, the audience, the receipt ref, no grant; the pane projection and the card harness are clean; a challenge without a preimage parks as a refusal that a second approve cannot sign and deny closes; a tier that mints nothing leaves the run parked; the handoff mints for exactly the card's hashes and audience, records the grant, retries the IDENTICAL request with the grant under the deciding operator's identity, and the daemon's typed refusal or its admission finalizes the run with the receipt, the grant ref and the lease — no grant bytes on the durable record, a second approve refused, an invalid submission and a non-challenge answer each typed", park.findings.length === 0, park.findings.join("; ") || `${park.runs_driven} runs driven in-process`);
  const src = sourceFindings({ serve: fs.readFileSync(SERVE, "utf8"), runs: fs.readFileSync(RUNS, "utf8"), timeline: fs.readFileSync(TIMELINE, "utf8"), walletAuthority: fs.readFileSync(WALLET_AUTHORITY, "utf8") });
  evidence.source = src;
  ok("SOURCE: the serve exposes the lane behind the local-run cache admission and submits through it; the run module dispatches a parked provider operation to the provider-ops route with the identical request and the grant, strips a caller-supplied grant, refuses a non-byte-derived park, defaults to the deployment-local tier with exactly one mint call site and keeps only the grant id; the timeline projects the operation; the test signer mounts only under its flag", src.length === 0, src.join("; ") || "pinned");
  const green = (n) => ({ n, executed: [{ script: `g${n}`, status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 0 }, executed_assertions: 5, floor_expected: 5 }] });
  const base = []; for (let n = 1; n <= 12; n += 1) base.push(green(n));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 9 ? { n: 9, absence: { what: "no passkey prompt in the App", owner: "the passkey tier" } } : r)));
  const withScheduled = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } } : r)));
  const scheduledNoRuling = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 1 ? { n: 1, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 5 ? { n: 5, executed: [{ script: "x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const reach = verdict(base.map((r) => (r.n === 7 ? { n: 7, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 1 } }] } : r)));
  const missing = verdict(base.filter((r) => r.n !== 6));
  ok("the verdict is a pure function of the clause rows: all executed green with no absence → PASS; a typed absence or a scheduled live leg → NAMED FAILURE; a scheduled leg without a ruling, a fabricated success row, a red gate, a reach beyond loopback or a missing clause → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && withScheduled.kind === "named_failure" && scheduledNoRuling.kind === "fail" && fabricated.kind === "fail" && red.kind === "fail" && reach.kind === "fail" && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${withScheduled.kind}/${scheduledNoRuling.kind}/${fabricated.kind}/${red.kind}/${reach.kind}/${missing.kind}`);
  const cf = canonFindings(fs.readFileSync(CANON_SURFACES, "utf8"), fs.readFileSync(CANON_PLANE, "utf8"), fs.readFileSync(CANON_WALLET, "utf8"));
  ok("canon binds the gate: core-clients-surfaces.md says a blocked provider operation submitted through the App parks the same way, hands off to the deployment's custody tier, and the App holds no grant and signs nothing on its own act; byo-provider-plane.md says the App retries the identical request; wallet-network/doctrine.md names the App a GuardianSurface projection under the deployment-local tier; all three name check:spend-approval-lane", cf.length === 0, cf.join("; ") || "read from the three canon owners");
  return { fixture };
}

// ---- mutation ---------------------------------------------------------------------------------------------
async function mutation() {
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(APP_DIR, "package.json"));
  const floors = readJson(FLOORS);
  let f = bindingFindings(CLAUSES.map((c) => (c.n === 2 ? { ...c, executed_by: [{ ...CARD_FACETS, script: "check:a-script-that-does-not-exist" }] } : c)), { rootPkg, appPkg, floors });
  plant("a clause bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 12 ? { ...c, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : c)), { rootPkg, appPkg, floors });
  plant("the live legs scheduled without a ruling", f.some((x) => /scheduled_without_prerequisite_or_ruling/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.filter((c) => c.n !== 6), { rootPkg, appPkg, floors });
  plant("the no-grant clause silently dropped", f.some((x) => /clause_missing: 6/u.test(x)), f[0]);
  const fixture = readJson(FIXTURE);
  const clean = await parkLeg(fixture.challenge);
  plant("the positive control: the in-process lane over the fixture has no finding", clean.findings.length === 0, clean.findings.join("; ") || "clean");
  const tampered = structuredClone(fixture.challenge); tampered.approval.request_hash = `sha256:${"0".repeat(64)}`;
  f = (await parkLeg(tampered)).findings;
  plant("a challenge whose request hash does not match its preimage (the card harness refuses it inside the park)", f.some((x) => /card_harness:challenge:request_preimage_mismatch/u.test(x)), f.find((x) => /card_harness/u.test(x)));
  const sources = { serve: fs.readFileSync(SERVE, "utf8"), runs: fs.readFileSync(RUNS, "utf8"), timeline: fs.readFileSync(TIMELINE, "utf8"), walletAuthority: fs.readFileSync(WALLET_AUTHORITY, "utf8") };
  f = sourceFindings({ ...sources, runs: sources.runs.replace(/transport\("POST", PROVIDER_OPS_PATH, \{ \.\.\.pending\.request, wallet_approval_grant: grant \}, runDaemonHeaders\(run, true\)\)/u, "transport(\"POST\", execPath, { intent: pending.intent, wallet_approval_grant: grant }, runDaemonHeaders(run, true))") });
  plant("a dispatch that retries a parked provider operation on the session-execute route", f.includes("pin_runs_dispatch_missing"), f[0]);
  f = sourceFindings({ ...sources, runs: sources.runs.replace(/delete request\.wallet_approval_grant;/u, "") });
  plant("a lane that forwards a caller-supplied grant", f.includes("pin_runs_strips_caller_grant_missing"), f[0]);
  f = sourceFindings({ ...sources, runs: `${sources.runs}\nfunction shadow() { return mintLocalApproverGrant({}); }\n` });
  plant("a second mint call site in the run module", f.some((x) => /mint_call_sites:2/u.test(x)), f[0]);
  f = sourceFindings({ ...sources, runs: sources.runs.replace(/code: "challenge_not_byte_derived"/u, "code: \"something_else\"") });
  plant("a run module that would approve a park without a preimage", f.includes("pin_runs_byte_derived_guard_missing"), f[0]);
  f = sourceFindings({ ...sources, serve: sources.serve.replace(/pathname === "\/__ioi\/provider-ops" && req\.method === "POST"/u, "pathname === \"/__ioi/provider-ops-x\" && req.method === \"POST\"") });
  plant("a serve without the lane's route", f.includes("pin_serve_route_missing"), f[0]);
  f = sourceFindings({ ...sources, walletAuthority: sources.walletAuthority.replace(/return process\.env\[TEST_SIGNER_FLAG\] === "1";/u, "return true;") });
  plant("a test signer that mounts without its flag", f.includes("pin_test_signer_flag_only_missing"), f[0]);
  const c = canonFindings(fs.readFileSync(CANON_SURFACES, "utf8").replace(/`check:spend-approval-lane`/gu, "`check:something-else`"), fs.readFileSync(CANON_PLANE, "utf8"), fs.readFileSync(CANON_WALLET, "utf8"));
  plant("canon that no longer names the gate", c.includes("canon_surfaces_gate_missing"), c[0]);
  const fake = verdict(CLAUSES.map((x) => ({ n: x.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full gate: the REAL lane -------------------------------------------------------------------------
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };
async function laneLegs() {
  const findingsPark = [];
  const findingsAdmit = [];
  const out = { park: {}, admit: {} };
  const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-sal-"));
  let resolver = null; let plane = null; let serve = null;
  try {
    const fixtureBaseEnv = { ...sanitizedVerifierBaseEnv(process.env), IOI_M049_ORDERING_PROFILE: process.env.IOI_SAL_FIXTURE_ORDERING_PROFILE || "Solo", IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: "900", IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1200000" };
    const t0 = Date.now();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv: fixtureBaseEnv, wallClockChain: true });
    out.fixture_ready_seconds = Math.round((Date.now() - t0) / 1000);
    const approverKeyPath = path.join(scratch, "deployment-local-approver.key");
    fs.writeFileSync(approverKeyPath, `${FIXTURE_APPROVER_SEED_HEX}\n`, { mode: 0o600 });
    plane = await startIsolatedPlane({ baseEnv: process.env, env: { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_HYPERVISOR_DAEMON_BINARY: binary, IOI_WALLET_TEST_SIGNER: "" } });
    if (!plane) { findingsPark.push("isolated_plane_did_not_start"); return { park: { findings: findingsPark }, admit: { findings: ["not_reached"] }, ...out }; }
    const DAEMON = plane.daemonUrl;
    const token = bootstrapToken(plane.dataDir);
    const boot = await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "spend-approval-lane-pass-1", email: "spend-approval-lane@ioi.local" }) });
    const bootBody = await boot.json().catch(() => ({}));
    const cookie = bootBody.session_token ? `ioi_session=${bootBody.session_token}` : "";
    if (!cookie) findingsPark.push(`bootstrap:${boot.status}`);
    const servePort = await freePort(); const productUiPort = await freePort();
    const SERVE_URL = `http://127.0.0.1:${servePort}`;
    let serveLog = "";
    serve = spawn(process.execPath, [SERVE], { cwd: APP_DIR, env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(productUiPort), IOI_PRODUCT_UI_PUBLIC: path.join(APP_DIR, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH: approverKeyPath, IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR: path.join(resolver.resourceDir, "commands"), IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF }, stdio: ["ignore", "pipe", "pipe"] });
    serve.stdout.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-32000); });
    serve.stderr.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-32000); });
    if (!(await waitFor(`${SERVE_URL}/__ioi/login`, 90000))) findingsPark.push("serve_did_not_start");
    const jd = (base, p, init = {}) => fetch(`${base}${p}`, { ...init, redirect: "manual", headers: { ...(init.body ? { "content-type": "application/json" } : {}), cookie, ...(init.headers || {}) } }).then(async (r) => { const text = await r.text(); let body = {}; try { body = text ? JSON.parse(text) : {}; } catch { body = {}; } return { status: r.status, body, text }; });
    // The serve's write-through to the daemon is ordered per run but asynchronous: the durable record
    // appears milliseconds after the serve answers, so a read polls for it (the alpha journey's pattern).
    const record = async (id, ms = 15000) => { const until = Date.now() + ms; let last = null; while (Date.now() < until) { last = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(id)}`); if (last.status === 200 && last.body?.ok === true) return last; await sleep(250); } return last; };
    const rec = (r) => r?.body?.run ?? r?.body?.record ?? r?.body ?? {};
    const settle = async (id, ms = 180000) => { const until = Date.now() + ms; let last = null; while (Date.now() < until) { last = await record(id); const st = rec(last).status; if (["done", "failed", "denied"].includes(st)) return last; await sleep(1000); } return last; };
    // ---- LANE-PARK: the live deployment_intent request, parked with the daemon's audience --------------
    const prep = await prepareProviderAccount({ daemonUrl: DAEMON, cookie, tag: `park-${Date.now().toString(36)}` });
    const submitted = await jd(SERVE_URL, "/__ioi/provider-ops", { method: "POST", body: JSON.stringify(prep.body) });
    const runId = submitted.body?.run_id ?? "";
    if (!(submitted.status === 202 && submitted.body?.parked === true && submitted.body?.byte_derived === true && runId)) findingsPark.push(`submit:${submitted.status}:${JSON.stringify(submitted.body).slice(0, 160)}`);
    const parkedRecord = rec(await record(runId));
    const pending = parkedRecord.pending_approval ?? {};
    const challenge = pending.challenge ?? null;
    if (!(parkedRecord.status === "awaiting_operator_approval" && pending.kind === PROVIDER_OPERATION_KIND && challenge && typeof challenge.approval?.request_preimage === "string")) findingsPark.push("durable_record_not_parked_with_challenge");
    if (!(typeof pending.audience === "string" && /^[0-9a-f]{64}$/u.test(pending.audience) && pending.audience === resolver.capabilityAccountId)) findingsPark.push(`audience:${String(pending.audience).slice(0, 12)}`);
    if (stable(pending.request) !== stable(prep.body)) findingsPark.push("durable_request_not_identical");
    if (JSON.stringify(parkedRecord).includes("wallet_approval_grant")) findingsPark.push("durable_record_carries_grant");
    // The card renders on the served Sessions readout (canon: the Operations-owned inspection lane over the
    // same daemon records, reached from the canonical Work / Sessions route); the canonical route itself is
    // fetched too and recorded, whatever shell it serves today.
    const canonical = await jd(SERVE_URL, "/work/sessions");
    const sessions = await jd(SERVE_URL, "/__ioi/sessions", { headers: { "x-ioi-canonical-route": "/work/sessions" } });
    out.park.canonical_route = { status: canonical.status, carries_card: canonical.text.includes(`data-ioi-awaiting-approval="${runId}"`) };
    if (!(sessions.status === 200 && sessions.text.includes(`data-ioi-awaiting-approval="${runId}"`))) findingsPark.push(`sessions_readout:${sessions.status}`);
    const harness = challenge ? verifyRenderedFacets(sessions.text, challenge) : ["no_challenge"];
    if (harness.length) findingsPark.push(`sessions_card_harness:${harness.join("/")}`);
    const timeline = await jd(SERVE_URL, `/__ioi/agent-runs/${encodeURIComponent(runId)}/timeline`);
    const ap = timeline.body?.turns?.[0]?.approval;
    if (!(timeline.status === 200 && ap?.state === "awaiting" && ap?.kind === PROVIDER_OPERATION_KIND && ap?.byteDerived === true && ap?.audience === pending.audience && ap?.requestHash === pending.request_hash)) findingsPark.push("pane_timeline");
    const approve = await jd(SERVE_URL, `/__ioi/runs/${encodeURIComponent(runId)}/approve`, { method: "POST", body: JSON.stringify({}) });
    if (!(approve.status === 202 && approve.body?.decision === "approved" && approve.body?.kind === PROVIDER_OPERATION_KIND)) findingsPark.push(`approve:${approve.status}:${JSON.stringify(approve.body).slice(0, 160)}`);
    const final = rec(await settle(runId));
    // The daemon's refusal reply carries its typed code and the receipt ref; the receipt's outcome is read
    // back from the daemon's own receipt family below, not from the reply.
    if (!(final.status === "failed" && final.error === "provider_operation_proposal_ref_required" && typeof final.provider_operation?.receipt_ref === "string" && final.provider_operation?.status === 403)) findingsPark.push(`typed_refusal:${final.status}/${final.error}/${final.provider_operation?.status}`);
    // The minted v1 grant carries no id field (byte arrays under a signature); the run keeps the hashes,
    // the tier and the minting time — and never the grant.
    if (!(final.authority?.mintedAt && final.authority?.approver === "deployment_local_operator" && final.authority?.requestHash === pending.request_hash && final.pending_approval?.decision === "approved")) findingsPark.push("authority_after_decision");
    if (JSON.stringify(final).includes("wallet_approval_grant") || JSON.stringify(final).includes("approver_sig")) findingsPark.push("final_record_carries_grant_bytes");
    const receipts = (await jd(DAEMON, "/v1/hypervisor/provider-receipts")).body?.receipts ?? [];
    const mine = receipts.filter((r) => r.environment_ref === prep.body.environment_ref);
    const outcomes = mine.map((r) => r.outcome);
    if (!(outcomes.includes("authority_missing") && outcomes.includes("proposal_not_admitted"))) findingsPark.push(`receipts:${outcomes.join(",")}`);
    const refusalReceipt = mine.find((r) => r.receipt_ref === final.provider_operation?.receipt_ref);
    if (!(refusalReceipt && refusalReceipt.outcome === "proposal_not_admitted")) findingsPark.push(`refusal_receipt_not_the_daemons:${refusalReceipt?.outcome}`);
    const again = await jd(SERVE_URL, `/__ioi/runs/${encodeURIComponent(runId)}/approve`, { method: "POST", body: JSON.stringify({}) });
    if (again.status !== 409) findingsPark.push(`second_approve:${again.status}`);
    if (sessions.text.includes(FIXTURE_APPROVER_SEED_HEX) || timeline.text.includes(FIXTURE_APPROVER_SEED_HEX)) findingsPark.push("approver_key_on_a_page");
    out.park = { ...out.park, run_id: runId, request_hash: pending.request_hash, audience: pending.audience, receipts: outcomes, refusal: final.error, refusal_receipt_ref: final.provider_operation?.receipt_ref, approver: final.authority?.approver, minted_at: final.authority?.mintedAt };
    // ---- LANE-ADMIT: the simulator-mode quote-gated create, admitted spend-free ------------------------
    const sim = await prepareSimulatorAccount({ daemonUrl: DAEMON, cookie, tag: `admit-${Date.now().toString(36)}`, scratch });
    if (sim.error) findingsAdmit.push(`prepare:${sim.error}`);
    else {
      const s2 = await jd(SERVE_URL, "/__ioi/provider-ops", { method: "POST", body: JSON.stringify(sim.body) });
      const id2 = s2.body?.run_id ?? "";
      if (!(s2.status === 202 && s2.body?.parked === true && s2.body?.byte_derived === true && id2)) findingsAdmit.push(`submit:${s2.status}:${JSON.stringify(s2.body).slice(0, 200)}`);
      const p2 = rec(await record(id2)).pending_approval ?? {};
      const facets = p2.challenge?.lease_request_facets ?? {};
      if (!(facets.candidate_ref === sim.body.candidate_ref && facets.execution_mode === "simulated_control_plane" && facets.max_hourly_usd === sim.body.max_hourly_usd)) findingsAdmit.push(`facets:${JSON.stringify(facets).slice(0, 160)}`);
      const page2 = await jd(SERVE_URL, "/__ioi/sessions", { headers: { "x-ioi-canonical-route": "/work/sessions" } });
      const h2 = p2.challenge ? verifyRenderedFacets(page2.text, p2.challenge) : ["no_challenge"];
      if (h2.length) findingsAdmit.push(`card_harness:${h2.join("/")}`);
      const a2 = await jd(SERVE_URL, `/__ioi/runs/${encodeURIComponent(id2)}/approve`, { method: "POST", body: JSON.stringify({}) });
      if (a2.status !== 202) findingsAdmit.push(`approve:${a2.status}:${JSON.stringify(a2.body).slice(0, 160)}`);
      const f2 = rec(await settle(id2));
      const po = f2.provider_operation ?? {};
      if (!(f2.status === "done" && po.ok === true && typeof po.receipt_ref === "string" && typeof po.capability_lease_ref === "string")) findingsAdmit.push(`admission:${f2.status}/${f2.error}/${JSON.stringify(po).slice(0, 160)}`);
      const dseq = String(po.evidence?.deployment?.dseq ?? "");
      if (!dseq.startsWith("simdseq_") || po.evidence?.live_provisioning_not_run !== true) findingsAdmit.push(`not_simulated:${dseq}:${po.evidence?.live_provisioning_not_run}`);
      const rcpts = (await jd(DAEMON, "/v1/hypervisor/provider-receipts")).body?.receipts ?? [];
      const okReceipt = rcpts.find((r) => r.receipt_ref === po.receipt_ref);
      if (!(okReceipt && okReceipt.outcome === "ok" && okReceipt.environment_ref === sim.body.environment_ref && typeof okReceipt.grant_ref === "string" && okReceipt.grant_ref.length > 8)) findingsAdmit.push(`ok_receipt_not_the_daemons:${okReceipt?.outcome}:${okReceipt?.grant_ref}`);
      const recon = (await jd(DAEMON, "/v1/hypervisor/provider-spend/reconciliation")).body;
      const exposure = (recon?.rows ?? []).find((r) => r.environment_ref === sim.body.environment_ref);
      if (!(exposure && exposure.status === "open")) findingsAdmit.push(`exposure_not_open:${JSON.stringify(exposure ?? null).slice(0, 120)}`);
      const deployments = (await jd(DAEMON, "/v1/hypervisor/akash-deployments")).body?.deployments ?? [];
      if (!deployments.some((d) => d.environment_ref === sim.body.environment_ref && String(d.dseq) === dseq)) findingsAdmit.push("deployment_record_missing");
      // Operations renders the daemon's receipts (op, provider, outcome, target) and the spend reconciliation:
      // the admitted create's environment appears with its outcome and its open exposure.
      const operations = await jd(SERVE_URL, "/__ioi/operations");
      if (!(operations.status === 200 && operations.text.includes(sim.body.environment_ref))) findingsAdmit.push(`operations_page:${operations.status}:env_absent`);
      // the delete, through the same lane, closes the exposure
      // `delete` is not a wallet-gated mutation (it only reduces exposure): the lane finalizes it from the
      // daemon's direct answer; a daemon that DID challenge it would park it and the same approve would apply.
      const del = await jd(SERVE_URL, "/__ioi/provider-ops", { method: "POST", body: JSON.stringify({ provider_id: sim.body.provider_id, op: "delete", environment_ref: sim.body.environment_ref, owner_ref: sim.body.owner_ref, idempotency_key: `${sim.body.idempotency_key}-delete` }) });
      const id3 = del.body?.run_id ?? "";
      if (!id3) findingsAdmit.push(`delete_submit:${del.status}:${JSON.stringify(del.body).slice(0, 160)}`);
      if (del.body?.parked === true) {
        const a3 = await jd(SERVE_URL, `/__ioi/runs/${encodeURIComponent(id3)}/approve`, { method: "POST", body: JSON.stringify({}) });
        if (a3.status !== 202) findingsAdmit.push(`delete_approve:${a3.status}`);
      }
      const f3 = rec(await settle(id3));
      if (!(f3.status === "done" && f3.provider_operation?.ok === true && typeof f3.provider_operation?.receipt_ref === "string")) findingsAdmit.push(`delete_admission:${f3.status}/${f3.error}`);
      out.admit.delete_parked = del.body?.parked === true;
      const recon2 = (await jd(DAEMON, "/v1/hypervisor/provider-spend/reconciliation")).body;
      const exposure2 = (recon2?.rows ?? []).find((r) => r.environment_ref === sim.body.environment_ref);
      if (!(exposure2 && exposure2.status === "closed")) findingsAdmit.push(`exposure_not_closed:${exposure2?.status}`);
      out.admit = { run_id: id2, delete_run_id: id3, receipt_ref: po.receipt_ref, grant_ref: po.grant_ref, lease_ref: po.capability_lease_ref, dseq, exposure_after_create: exposure?.status, exposure_after_delete: exposure2?.status };
    }
    out.serve_log_tail = serveLog.slice(-600);
  } catch (error) {
    findingsPark.push(`lane_crashed:${String(error?.message || error).slice(0, 160)}`);
  } finally {
    if (serve) { try { serve.kill("SIGTERM"); } catch { /* gone */ } }
    if (plane) { try { await plane.stop(); } catch { /* gone */ } }
    if (resolver?.stop) { try { await resolver.stop(); } catch { /* gone */ } }
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  return { park: { findings: findingsPark, ...out.park }, admit: { findings: findingsAdmit, ...out.admit }, fixture_ready_seconds: out.fixture_ready_seconds ?? null, serve_log_tail: out.serve_log_tail ?? null };
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
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-sal-gate-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir, live_credentials_present: !!(process.env.IOI_C7_EMAIL && process.env.IOI_C7_PASSWORD_FILE) };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  console.log("\n# the REAL lane: the wallet fixture beside an isolated daemon and this runner's own serve (loopback; a sealed fake credential; the live path ends at the daemon's typed refusal, the simulator path admits without provisioning)");
  const lane = await laneLegs();
  evidence.lane_park = lane.park; evidence.lane_admit = lane.admit; evidence.fixture_ready_seconds = lane.fixture_ready_seconds;
  console.log(`  → LANE-PARK ${lane.park.findings.length === 0 ? "parked, carded, approved, refused typed, receipts read back" : lane.park.findings.join("; ")}`);
  console.log(`  → LANE-ADMIT ${lane.admit.findings.length === 0 ? "parked, carded, approved, ADMITTED, exposure opened and closed" : lane.admit.findings.join("; ")}`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ park: evidence.park, source: evidence.source, lane_park: evidence.lane_park, lane_admit: evidence.lane_admit }, null, 2)}\n`);
  const legGreen = { "park (this runner)": (evidence.park?.findings?.length ?? 1) === 0, "source (this runner)": (evidence.source?.length ?? 1) === 0, "lane-park (this runner)": lane.park.findings.length === 0, "lane-admit (this runner)": lane.admit.findings.length === 0 };
  const selfRun = (name) => ({ script: name, status: legGreen[name] ? 0 : 1, seconds: 0, isolation: "in-process", ledger: { attempts: 0, loopback: 0, reach: 0 }, evidence: path.relative(ROOT, selfEvidence), evidence_sha256: sha256File(selfEvidence), executed_assertions: null, floor_expected: null });
  const done = new Map();
  const rows = [];
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
  evidence.clauses = rows;
  evidence.verdict = v;
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
    emitVerifierCensus({ verifierId: "spend-approval-lane", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
