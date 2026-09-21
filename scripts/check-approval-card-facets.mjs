#!/usr/bin/env node
// check:approval-card-facets — M03.9: the approval surface renders the signed facts verbatim, as a gate
// (docs/architecture/components/hypervisor/byo-provider-plane.md § The challenge carries the bytes that
// will execute; docs/architecture/components/wallet-network/doctrine.md § The presentation is byte-derived;
// register R-212).
//
// CANON. What you sign is what executes: the daemon challenge carries `lease_request_facets` and, under
// `approval`, the exact bytes its policy and request hashes are the SHA-256 of (`policy_preimage`,
// `request_preimage`). A signing surface renders every hashed member FROM those bytes — the member's exact
// bytes, the full policy hash, request hash and grant audience — and re-derives the request hash before it
// signs. A paraphrased, truncated or locally reconstructed facet set is a defect; a challenge without a
// preimage is not signable byte-derived.
//
// WHAT THIS RUNNER IS. The acceptance's demands are CLAUSES, each EXECUTED by one of this runner's own legs,
// by a floored gate that already proves it, or NAMED (a typed failure with an owner, or a SCHEDULED live leg
// with its exact prerequisite and ruling). The runner's own legs run over a TRACKED, hash-committed challenge
// FIXTURE minted once by an isolated daemon (spend-free: a sealed fake credential, live mode at a dead
// loopback endpoint; the wallet gate refused the create before any provider call) and, in full mode, over a
// FRESH challenge from an isolated daemon this runner starts, cross-checked against the fixture:
//   FIXTURE     — intact before it is read (its sha256 re-derived), the preimage hashing to the request
//                 hash, the SDL hash re-derived from the plan's SDL bytes, no secret; and R-212's finding
//                 pinned: the hashed bytes carry members the echoed facets never did.
//   CARD        — the projection parses the preimage; the card renders every hashed member verbatim with the
//                 full commitments and audience; the diff harness is clean on it and names every plant.
//   REFUSAL     — a challenge without a preimage (the retained 2026-08-21 challenge, from M12.9's set), one
//                 whose preimage does not hash to its request hash, one whose echo re-states a member, one
//                 of another domain: each refused by code, rendered as a refusal with NO approve form.
//   SPA         — the session pane's projection carries the same bytes; the serve's renderer and the pane
//                 consume the grammar and truncate nothing (source pins).
//   SOURCE      — the daemon defines its hashes over the published preimages and publishes them (pins).
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills      CI-bound, seconds: the binding, the five legs, the grammar's own test suite, the verdict
//                 rules, canon's binding. No daemon, no network, no credential.
//   --mutation    planted defects against the drills' oracles — each must go red.
//   (default)     the full gate: the drills, a FRESH challenge from an isolated daemon cross-checked against
//                 the fixture, then every executed gate inside the isolated-egress harness. Exit 0 pass,
//                 2 named failure, 1 fail. This runner never presents a grant and never spends.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import { DEPLOYMENT_INTENT_MEMBERS, PROVIDER_APPROVAL_KIND, escHtml, projectProviderApprovalForTimeline, projectProviderChallenge, renderProviderFacetsCard, verifyRenderedFacets } from "../apps/hypervisor/scripts/lib/approval-card-facets.mjs";
import { projectRunTimeline } from "../apps/hypervisor/scripts/ioi-run-timeline.mjs";
import { FIXTURE_SCHEMA, bootstrapToken, mintProviderChallenge, sha as stableSha } from "./lib/provider-challenge-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(ROOT, "apps", "hypervisor", "verifier-floors.v1.json");
const FIXTURE = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m03-9-provider-challenge-fixture-2026-09-20.v1.json");
const RETAINED = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m12-9-c7-retained-bounded-live-effect-run-2026-09-20.v1.json");
const CANON_PLANE = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "byo-provider-plane.md");
const CANON_WALLET = path.join(ROOT, "docs", "architecture", "components", "wallet-network", "doctrine.md");
const LIFECYCLE = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "lifecycle_routes.rs");
const SERVE = path.join(ROOT, "apps", "hypervisor", "scripts", "serve-product-ui.mjs");
const TIMELINE = path.join(ROOT, "apps", "hypervisor", "scripts", "ioi-run-timeline.mjs");
const LIB_TEST = path.join(ROOT, "apps", "hypervisor", "scripts", "lib", "approval-card-facets.test.mjs");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const LIVE_PREREQ = "a local model (Ollama, IOI_ALPHA_MODEL) and the deployment-local authority node (M03.8), IOI_ALPHA_JOURNEY_AUTHORITY=deployment";
const LIVE_RULING = "R-139 (2026-09-14) and R-212 (2026-09-20): a missing local model or authority node blocks that RUN, never the unit; the card grammar is proven spend-free over daemon-minted bytes";
const HASH = /^sha256:[0-9a-f]{64}$/u;
const sha256Text = (t) => `sha256:${crypto.createHash("sha256").update(t, "utf8").digest("hex")}`;

// THE PINS: the members R-212 measured the hashed bytes carry beyond the echoed facets, and the one the
// echo carries that the hash never covers.
export const PREIMAGE_ONLY_MEMBERS = ["account_ref", "op", "environment_ref", "kind", "external_spend_posture"];
export const ECHO_ONLY_MEMBERS = ["sdl_yaml"];
export const HARNESS_PLANTS = ["facet_not_verbatim", "request_hash_not_verbatim", "audience_not_verbatim", "facet_missing_in_card", "facet_smuggled", "facet_duplicated"];
export const LIB_TEST_MIN = 7;

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const CUSTODY = gate("check:custody-proven-private-routes", "custody-proven-private-routes", 30);
const PROVENANCE = gate("check:provider-proposal-provenance", "provider-proposal-provenance", 30);
const C8 = gate("check:c8-bounded-live-effect-certificate", "c8-bounded-live-effect-certificate", 20);
const SESSION_TRUTH = gate("check:session-truth-rebind", "session-truth-rebind", 20);
const LANE = gate("check:spend-approval-lane", "spend-approval-lane", 20);
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const FIXTURE_LEG = self("fixture");
const CARD = self("card");
const REFUSAL = self("refusal");
const SPA = self("spa");
const SOURCE = self("source");
const FRESH = self("fresh challenge");
const LANE_OWNER = "M08.11 (the spend-approval lane — landed 2026-09-20 as check:spend-approval-lane, R-213; R-6 resolved by R-212: M03.9 owns the grammar and its oracle, M08.11 the routing)";

export const CLAUSES = [
  { n: 1, demand: "the challenge carries the exact bytes its commitment hashes cover — approval.request_preimage and approval.policy_preimage — and request_hash = sha256(request_preimage)", executed_by: [FIXTURE_LEG, SOURCE, FRESH] },
  { n: 2, demand: "the card renders every hashed facet member verbatim — the member's exact bytes — and, for a deployment_intent challenge, ceiling amount and denomination, deposit, provider selector, SDL hash, teardown policy and stage are all present", executed_by: [CARD, FRESH] },
  { n: 3, demand: "the card renders the full policy hash, request hash and grant audience; nothing is truncated", executed_by: [CARD, SPA] },
  { n: 4, demand: "the card is byte-derived, never re-stated: a challenge whose echoed facets differ from the hashed bytes, whose preimage does not hash to its request hash, or which carries no preimage is refused by code and rendered with no approve form", executed_by: [REFUSAL] },
  { n: 5, demand: "a paraphrased, truncated or locally reconstructed facet set is a defect the diff harness names by code", executed_by: [CARD] },
  { n: 6, demand: "the SPA session pane shows the same bytes: every facet, the full hashes and the full audience", executed_by: [SPA, SESSION_TRUTH] },
  { n: 7, demand: "the resolved principal signs and the daemon admits the grant for exactly those facets", executed_by: [CUSTODY, C8, PROVENANCE], absence: { what: "a provider-operation admission AFTER a rendered card is driven by no isolated gate: a live create reaches the provider's console (never loopback, never spend-free), and the simulator-mode admission lives only in the shared-daemon adapter done-bar; the retained 2026-08-21 run's challenge → grant → admitted one-shot lease is replayed by check:c8-bounded-live-effect-certificate, and fresh admissions under the real wallet fixture by check:custody-proven-private-routes", owner: "M09.10's isolated form · the scheduled alpha journey (clause 12)" } },
  { n: 8, demand: "sign or refuse, each with a receipt", executed_by: [CUSTODY], absence: { what: "a denial produces no signed receipt anywhere: the serve's deny mints nothing and writes no daemon receipt, and no deny act exists on the authority node or the wallet fixture", owner: "a follow-on slice of M03.9 (owner question, R-212)" } },
  { n: 9, demand: "the grant is delivered back to the requesting surface", executed_by: [], absence: { what: "the in-process serve delivers the grant it mints for session execute (the alpha journey); a graduated wallet app's handoff to the requesting surface does not exist — the wallet-network prototype is a design mock", owner: "the graduated wallet app (owner question, R-212)" } },
  { n: 10, demand: "the App parks a blocked provider operation as this card and hands it to the custody tier", executed_by: [LANE] },
  { n: 11, demand: "the facet lanes beyond the direct-Akash deployment_intent challenge (quote-gated adapters, storage archive operations) render byte-derived", executed_by: [], absence: { what: "the grammar reads any capability-lease preimage, but only the deployment_intent challenge is fixtured and drilled; the other lanes' members are not pinned", owner: "a follow-on slice of M03.9 (R-212(1))" } },
  { n: 12, demand: "the session-execute and custody cards live, under the deployment-local custody tier", executed_by: [], scheduled: { what: "check:alpha-journey with IOI_ALPHA_JOURNEY_AUTHORITY=deployment — the run parks on Work / Sessions and the SPA pane, the operator approves with the deployment-local key, the daemon admits and executes, the receipt binds", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } },
];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.approval-card-facets-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], fixture: null, card: null, refusal: null, spa: null, source: null, fresh: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `approval-card-facets-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256File = (f) => (fs.existsSync(f) ? `sha256:${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}` : null);
const SECRET_PATTERNS = [/"(?:password|session_token|api_key|sealed_token|recovery_material|mnemonic|private_key)"\s*:/iu, /ioi_sess_[A-Za-z0-9_-]+/u, /ioi_bootstrap_[A-Za-z0-9_-]+/u, /(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/u, /FAKE-AKASH-KEY/u];

// ---- oracles (pure) ---------------------------------------------------------------------------------------
export function fixtureFindings(fixture) {
  const f = [];
  if (fixture?.schema_version !== FIXTURE_SCHEMA) f.push("fixture_schema_invalid");
  const c = fixture?.challenge;
  if (!c || typeof c !== "object") { f.push("fixture_challenge_missing"); return f; }
  if (stableSha(c) !== fixture?.challenge_sha256) f.push("fixture_sha256_mismatch");
  if (![403, 501].includes(Number(fixture?.status))) f.push(`fixture_status_not_a_challenge:${fixture?.status}`);
  if (c.ok !== false || c.decision !== "blocked" || c.reason !== "provider_operation_authority_required") f.push("fixture_not_an_authority_refusal");
  const a = c.approval ?? {};
  if (typeof a.request_preimage !== "string" || !HASH.test(String(a.request_hash ?? "")) || sha256Text(a.request_preimage) !== a.request_hash) f.push("request_preimage_does_not_hash_to_request_hash");
  if (typeof a.policy_preimage !== "string" || !HASH.test(String(a.policy_hash ?? "")) || sha256Text(a.policy_preimage) !== a.policy_hash) f.push("policy_preimage_does_not_hash_to_policy_hash");
  const lrf = c.lease_request_facets ?? {};
  for (const m of DEPLOYMENT_INTENT_MEMBERS) if (!Object.hasOwn(lrf, m)) f.push(`echoed_facet_missing:${m}`);
  if (lrf.stage !== "deployment_intent" || lrf.execution_mode !== "live") f.push("fixture_not_a_live_deployment_intent");
  const sdl = fixture?.request_body?.plan?.sdl_yaml;
  if (typeof sdl !== "string" || sha256Text(sdl) !== lrf.sdl_hash) f.push("sdl_hash_not_derived_from_plan_bytes");
  if (!/^[0-9a-f]{40}$/u.test(String(fixture?.basis?.commit ?? "")) || !HASH.test(String(fixture?.basis?.daemon_binary_sha256 ?? ""))) f.push("fixture_basis_malformed");
  const serialized = JSON.stringify(fixture);
  if (SECRET_PATTERNS.some((p) => p.test(serialized))) f.push("fixture_secret_bearing");
  return f;
}
export function preimageShapeFindings(challenge) {
  const f = [];
  const projection = projectProviderChallenge(challenge);
  if (!projection.ok) return [`projection:${projection.findings.join("/")}`];
  const keys = new Set(projection.facets.map((x) => x.key));
  const echoed = new Set(Object.keys(challenge?.lease_request_facets ?? {}));
  for (const m of PREIMAGE_ONLY_MEMBERS) { if (!keys.has(m)) f.push(`preimage_lacks:${m}`); if (echoed.has(m)) f.push(`echo_carries:${m}`); }
  for (const m of ECHO_ONLY_MEMBERS) { if (keys.has(m)) f.push(`preimage_carries:${m}`); if (!echoed.has(m)) f.push(`echo_lacks:${m}`); }
  for (const m of DEPLOYMENT_INTENT_MEMBERS) if (!keys.has(m)) f.push(`preimage_lacks:${m}`);
  const deposit = projection.facets.find((x) => x.key === "deposit_usd");
  if (!deposit || !/\.\d/u.test(deposit.raw)) f.push("deposit_not_rendered_as_hashed_float");
  return f;
}
export function cardFindings(challenge) {
  const f = [];
  const projection = projectProviderChallenge(challenge);
  const html = renderProviderFacetsCard(projection, { approveUrl: "/__ioi/runs/r1/approve", denyUrl: "/__ioi/runs/r1/deny", returnTo: "/work/sessions" });
  const harness = verifyRenderedFacets(html, challenge);
  if (harness.length) f.push(...harness.map((x) => `harness:${x}`));
  if (!/Approve exactly this/u.test(html)) f.push("approve_form_missing");
  for (const m of DEPLOYMENT_INTENT_MEMBERS) if (!html.includes(`data-ioi-facet="${m}"`)) f.push(`card_lacks:${m}`);
  if (!html.includes(escHtml(projection.policy_hash ?? "")) || !html.includes(escHtml(projection.request_hash ?? ""))) f.push("commitments_not_whole");
  if (projection.audience != null && !html.includes(projection.audience)) f.push("audience_not_whole");
  return { findings: f, html, projection };
}
export function harnessPlants(challenge) {
  const { html, projection } = cardFindings(challenge);
  const rh = escHtml(projection.request_hash ?? "");
  const audience = projection.audience;
  const first = projection.facets[0]?.key;
  const raw = (key) => escHtml(projection.facets.find((x) => x.key === key)?.raw ?? "");
  const plants = [
    ["facet_not_verbatim", html.replace(`data-ioi-facet="deposit_usd"><code style="font-size:11px;white-space:pre-wrap;word-break:break-all">${raw("deposit_usd")}</code>`, `data-ioi-facet="deposit_usd"><code style="font-size:11px;white-space:pre-wrap;word-break:break-all">about one dollar</code>`)],
    ["request_hash_not_verbatim", html.replace(`<code data-ioi-request-hash style="font-size:10.5px">${rh}</code>`, `<code data-ioi-request-hash style="font-size:10.5px">${rh.slice(0, 24)}…</code>`)],
    ["audience_not_verbatim", audience != null ? html.replace(`<code data-ioi-audience style="font-size:10.5px">${escHtml(audience)}</code>`, `<code data-ioi-audience style="font-size:10.5px">${escHtml(audience).slice(0, 24)}…</code>`) : html.replace(/<code data-ioi-audience style="font-size:10.5px">[^<]*<\/code>/u, `<code data-ioi-audience style="font-size:10.5px">${"ab".repeat(32)}</code>`)],
    ["facet_missing_in_card", html.replace(new RegExp(`<dt>teardown_policy</dt><dd data-ioi-facet="teardown_policy">[\\s\\S]*?</dd>`, "u"), "")],
    ["facet_smuggled", html.replace("<dl data-ioi-facets", `<dl data-ioi-facets><dt>auto_topup_note</dt><dd data-ioi-facet="auto_topup_note"><code>never</code></dd></dl><dl`)],
    ["facet_duplicated", html.replace(`<dt>${escHtml(first)}</dt>`, `<dt>${escHtml(first)}</dt><dd data-ioi-facet="${escHtml(first)}"><code>${raw(first)}</code></dd><dt>${escHtml(first)}</dt>`)],
  ];
  return plants.map(([expected, mutated]) => { const found = verifyRenderedFacets(mutated, challenge); return { expected, detected: found.some((x) => x.startsWith(expected)), findings: found.slice(0, 3), changed: mutated !== html }; });
}
export function refusalFindings(challenge, retainedChallenge) {
  const f = [];
  const refuse = (label, c, expected) => {
    const p = projectProviderChallenge(c);
    if (p.ok || !p.findings.some((x) => x.startsWith(expected))) f.push(`${label}:not_refused:${p.findings.join("/") || "ok"}`);
    const html = renderProviderFacetsCard(p, { approveUrl: "/__ioi/runs/r1/approve", denyUrl: "/__ioi/runs/r1/deny" });
    if (!/data-ioi-provider-approval-refused=/u.test(html) || /Approve exactly this/u.test(html)) f.push(`${label}:approve_form_rendered`);
    const harness = verifyRenderedFacets(html, c);
    if (!harness.some((x) => x.startsWith(`challenge:${expected}`))) f.push(`${label}:harness_silent`);
  };
  refuse("retained_pre_r212", retainedChallenge, "request_preimage_missing");
  const wrong = structuredClone(challenge); wrong.approval.request_preimage = wrong.approval.request_preimage.replace("\"stage\":\"deployment_intent\"", "\"stage\":\"deployment_intent_edited\"");
  refuse("wrong_preimage", wrong, "request_preimage_mismatch");
  const restated = structuredClone(challenge); restated.lease_request_facets.deposit_usd = 0.5;
  refuse("restated_echo", restated, "facets_restated:deposit_usd");
  const other = structuredClone(challenge); other.approval.request_preimage = other.approval.request_preimage.replace("hypervisor.provider.op.request.v1", "hypervisor.session.execute.request.v1"); other.approval.request_hash = sha256Text(other.approval.request_preimage);
  refuse("other_domain", other, "request_domain_not_provider_op");
  const nopolicy = structuredClone(challenge); delete nopolicy.approval.policy_preimage;
  refuse("no_policy_preimage", nopolicy, "policy_preimage_missing");
  return f;
}
export function spaFindings(challenge, serveSource, timelineSource) {
  const f = [];
  const projection = projectProviderChallenge(challenge);
  const run = { id: "run_x", status: "awaiting_operator_approval", prompt: "deploy", sessionRef: null, pendingApproval: { kind: PROVIDER_APPROVAL_KIND, challenge, policy_hash: projection.policy_hash, request_hash: projection.request_hash, audience: projection.audience, required_scopes: projection.required_scopes, requested_at: "2026-09-20T00:00:00Z" } };
  const ap = projectRunTimeline(run, {})?.turns?.[0]?.approval;
  if (!ap || ap.state !== "awaiting" || ap.kind !== PROVIDER_APPROVAL_KIND) f.push("spa_projection_missing");
  else {
    if (ap.byteDerived !== true) f.push(`spa_not_byte_derived:${(ap.findings ?? []).join("/")}`);
    if (!Array.isArray(ap.facets) || ap.facets.length !== projection.facets.length || ap.facets.some((x, i) => x.key !== projection.facets[i].key || x.raw !== projection.facets[i].raw)) f.push("spa_facets_not_the_same_bytes");
    if (ap.requestHash !== projection.request_hash || ap.policyHash !== projection.policy_hash || ap.audience !== projection.audience) f.push("spa_commitments_differ");
    if (ap.preimageSha256 !== projection.preimage_sha256) f.push("spa_preimage_sha_differs");
    if (ap.approveUrl !== "/__ioi/runs/run_x/approve" || ap.denyUrl !== "/__ioi/runs/run_x/deny") f.push("spa_decision_endpoints_missing");
  }
  const t = projectProviderApprovalForTimeline({ kind: PROVIDER_APPROVAL_KIND, challenge: { approval: {} } });
  if (t.byteDerived !== false || !t.findings.includes("request_preimage_missing")) f.push("spa_projection_accepts_missing_preimage");
  if (!/from "\.\/lib\/approval-card-facets\.mjs"/u.test(serveSource) || !/renderProviderFacetsCard\(projectProviderChallenge\(p\.challenge\)/u.test(serveSource) || !/p\.kind === PROVIDER_APPROVAL_KIND/u.test(serveSource)) f.push("serve_does_not_render_the_grammar");
  if (/trunc\(ap\.audience/u.test(serveSource) || /trunc\(ap\.policyHash/u.test(serveSource) || /trunc\(ap\.requestHash/u.test(serveSource)) f.push("spa_pane_truncates_a_commitment");
  if (!/ap\.facets&&ap\.facets\.length/u.test(serveSource)) f.push("spa_pane_does_not_show_facets");
  if (!/projectProviderApprovalForTimeline\(run\.pendingApproval\)/u.test(timelineSource) || !/from "\.\/lib\/approval-card-facets\.mjs"/u.test(timelineSource)) f.push("timeline_does_not_project_the_grammar");
  return f;
}
export function sourceFindings(lifecycle) {
  const f = [];
  const need = [["request_preimage_fn", /pub\(crate\) fn capability_lease_request_preimage\(req: &CapabilityLeaseRequest\) -> String/u], ["policy_preimage_fn", /pub\(crate\) fn capability_lease_policy_preimage\(req: &CapabilityLeaseRequest\) -> String/u], ["request_hash_over_preimage", /sha256_hex_str\(&capability_lease_request_preimage\(req\)\)/u], ["policy_hash_over_preimage", /sha256_hex_str\(&capability_lease_policy_preimage\(req\)\)/u], ["challenge_publishes_request_preimage", /"request_preimage": capability_lease_request_preimage\(req\),/u], ["challenge_publishes_policy_preimage", /"policy_preimage": capability_lease_policy_preimage\(req\),/u], ["unit_test", /fn the_published_preimages_are_the_exact_bytes_the_hashes_commit_to\(\)/u]];
  for (const [name, re] of need) if (!re.test(lifecycle)) f.push(`daemon_${name}_missing`);
  return f;
}
export function libTestFindings(cwd = ROOT) {
  const r = spawnSync("node", ["--test", LIB_TEST], { cwd, encoding: "utf8", timeout: 120000 });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  const pass = Number(out.match(/^# pass (\d+)/mu)?.[1] ?? 0);
  const fail = Number(out.match(/^# fail (\d+)/mu)?.[1] ?? -1);
  const f = [];
  if (r.status !== 0) f.push(`lib_test_exit:${r.status}`);
  if (fail !== 0) f.push(`lib_test_failures:${fail}`);
  if (pass < LIB_TEST_MIN) f.push(`lib_test_population:${pass}<${LIB_TEST_MIN}`);
  return { findings: f, pass, fail, status: r.status };
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
export function canonFindings(plane, wallet) {
  const f = [];
  const p = plane.replace(/\s+/gu, " ");
  const w = wallet.replace(/\s+/gu, " ");
  const need = [["plane_names_gate", p, /`check:approval-card-facets`/u], ["plane_preimages", p, /`request_preimage` and `policy_preimage`, the exact JSON strings the request hash and the policy hash are the SHA-256 of/u], ["plane_wysiwyg", p, /what you sign is what executes/u], ["plane_defect", p, /A paraphrased, truncated or locally reconstructed facet set is a defect/u], ["plane_no_preimage", p, /a challenge that carries no preimage is not signable byte-derived/u], ["plane_lane_owner", p, /the lane that parks a blocked provider operation as a card in the App is the spend-approval lane's own unit/u], ["wallet_byte_derived", w, /The presentation is byte-derived/u], ["wallet_names_gate", w, /`check:approval-card-facets`/u]];
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
// The fresh challenge against the fixture: the daemon's rule is the same rule (the same members, the same
// domain, the SDL hash re-derived), and the two differ exactly where the account and environment differ.
export function freshFindings(fresh, fixture) {
  const f = [];
  const fc = fresh?.challenge ?? {};
  const xc = fixture?.challenge ?? {};
  if (![403, 501].includes(Number(fresh?.status))) f.push(`fresh_status_not_a_challenge:${fresh?.status}`);
  const fp = projectProviderChallenge(fc);
  const xp = projectProviderChallenge(xc);
  if (!fp.ok) { f.push(`fresh_projection:${fp.findings.join("/")}`); return f; }
  if (!xp.ok) { f.push(`fixture_projection:${xp.findings.join("/")}`); return f; }
  const fk = fp.facets.map((x) => x.key).join(",");
  const xk = xp.facets.map((x) => x.key).join(",");
  if (fk !== xk) f.push(`fresh_member_set_differs:${fk}!=${xk}`);
  if (fp.domain !== xp.domain) f.push("fresh_domain_differs");
  const differing = fp.facets.filter((x) => xp.facets.find((y) => y.key === x.key)?.raw !== x.raw).map((x) => x.key).sort();
  const allowed = ["account_ref", "environment_ref"];
  if (differing.some((k) => !allowed.includes(k))) f.push(`fresh_bytes_differ_beyond_identity:${differing.join(",")}`);
  if (!differing.includes("account_ref")) f.push("fresh_shares_the_fixture_account");
  if (fp.request_hash === xp.request_hash) f.push("fresh_hash_equals_fixture_hash");
  if (sha256Text(fresh?.request_body?.plan?.sdl_yaml ?? "") !== fc.lease_request_facets?.sdl_hash) f.push("fresh_sdl_hash_not_derived");
  if (JSON.stringify(Object.keys(fc.lease_request_facets ?? {}).sort()) !== JSON.stringify(Object.keys(xc.lease_request_facets ?? {}).sort())) f.push("fresh_echo_members_differ");
  return f;
}

// ---- drills ------------------------------------------------------------------------------------------------
function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  const binding = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  ok("the acceptance's demands are bound: every executed clause names a real script with a pinned floor (app) or one of this runner's legs, every named failure carries its owner, the live cards are SCHEDULED with their exact prerequisite and ruling, clauses cover 1–12 exactly once", binding.length === 0, binding.join("; ") || "bound");
  if (!fs.existsSync(FIXTURE)) blocked(`challenge fixture absent at ${FIXTURE} (mint it: node scripts/mint-provider-challenge-fixture.mjs)`);
  if (!fs.existsSync(RETAINED)) blocked(`retained record set absent at ${RETAINED}`);
  const fixture = readJson(FIXTURE);
  const ff = fixtureFindings(fixture);
  ok(`FIXTURE: the tracked daemon-minted challenge is intact before it is read (its sha256 re-derived), it is the wallet gate's authority refusal for a live deployment_intent create, approval.request_preimage hashes to approval.request_hash and approval.policy_preimage to approval.policy_hash, the SDL hash re-derives from the plan's own SDL bytes, and no secret or fake key is carried`, ff.length === 0, ff.join("; ") || `${fixture.challenge_sha256?.slice(0, 19)} · status ${fixture.status}`);
  const challenge = fixture.challenge;
  const shape = preimageShapeFindings(challenge);
  ok(`R-212's finding, pinned: the hashed bytes carry members the echoed lease_request_facets never did (${PREIMAGE_ONLY_MEMBERS.join(", ")}) and omit the raw SDL the echo carries — so only the preimage can be signed byte-derived; the deposit is rendered as the float the hash saw`, shape.length === 0, shape.join("; ") || `${projectProviderChallenge(challenge).facets.length} hashed members`);
  const card = cardFindings(challenge);
  evidence.fixture = { challenge_sha256: fixture.challenge_sha256, status: fixture.status, findings: ff, shape, hashed_members: card.projection.facets.map((x) => x.key) };
  ok(`CARD: the projection parses the preimage and the card renders every hashed member verbatim — ${card.projection.facets.length} members, each as its exact bytes — with ceiling amount and denomination, deposit, provider selector, SDL hash, teardown policy and stage present, the full policy hash, request hash and grant audience, and the approve form; the diff harness is clean on it`, card.findings.length === 0, card.findings.join("; ") || `${card.projection.facets.map((x) => x.key).join(",")}`);
  const plants = harnessPlants(challenge);
  evidence.card = { findings: card.findings, plants };
  ok(`CARD drill: the diff harness names each of ${HARNESS_PLANTS.length} plants on the rendered card by code — a paraphrased deposit, a truncated request hash, a truncated audience, a dropped member, a smuggled member, a duplicated member`, plants.length === HARNESS_PLANTS.length && plants.every((p) => p.detected && p.changed), plants.filter((p) => !(p.detected && p.changed)).map((p) => `${p.expected}:${p.findings.join("/") || "silent"}${p.changed ? "" : " (unchanged)"}`).join("; ") || `${plants.length}/${plants.length}`);
  const retained = readJson(RETAINED).runs[0].artifacts.challenge;
  const rf = refusalFindings(challenge, retained);
  evidence.refusal = rf;
  ok("REFUSAL: a challenge without a preimage (the retained 2026-08-21 challenge from M12.9's set), one whose preimage does not hash to its request hash, one whose echoed facets re-state a hashed member, one of another request domain and one without a policy preimage are each refused by code, rendered as a refusal with NO approve form, and named by the harness", rf.length === 0, rf.join("; ") || "5 refusals typed");
  const serveSource = fs.readFileSync(SERVE, "utf8");
  const timelineSource = fs.readFileSync(TIMELINE, "utf8");
  const sf = spaFindings(challenge, serveSource, timelineSource);
  evidence.spa = sf;
  ok("SPA: the session pane's projection carries the same bytes as the card (every facet raw, the full hashes, the full audience, the decision endpoints) and refuses a missing preimage; the serve renders the grammar for a parked provider operation and the pane truncates no commitment (source pins)", sf.length === 0, sf.join("; ") || "same bytes");
  const src = sourceFindings(fs.readFileSync(LIFECYCLE, "utf8"));
  evidence.source = src;
  ok("SOURCE: the daemon defines both commitment hashes over the published preimages and publishes request_preimage and policy_preimage on every capability-lease challenge, with its own unit test present (lifecycle_routes.rs pins)", src.length === 0, src.join("; ") || "pinned");
  const lt = libTestFindings();
  ok(`the grammar's own test suite executes here, as part of this one command: ${LIB_TEST_MIN}+ cases over a synthetic challenge built the way the daemon builds it (the float as hashed, the nested selector's bytes, every refusal and every harness code)`, lt.findings.length === 0, lt.findings.join("; ") || `${lt.pass} passed, ${lt.fail} failed`);
  const green = (n) => ({ n, executed: [{ script: `g${n}`, status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 0 }, executed_assertions: 5, floor_expected: 5 }] });
  const base = []; for (let n = 1; n <= 12; n += 1) base.push(green(n));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 10 ? { n: 10, absence: { what: "no App lane parks a provider operation", owner: LANE_OWNER } } : r)));
  const withScheduled = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } } : r)));
  const scheduledNoRuling = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 1 ? { n: 1, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 7 ? { n: 7, executed: [{ script: "x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const reach = verdict(base.map((r) => (r.n === 6 ? { n: 6, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 1 } }] } : r)));
  const missing = verdict(base.filter((r) => r.n !== 4));
  ok("the verdict is a pure function of the clause rows: all executed green with no absence → PASS; a typed absence or a scheduled live leg → NAMED FAILURE; a scheduled leg without a ruling, a fabricated success row, a red gate, a reach beyond loopback or a missing clause → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && withScheduled.kind === "named_failure" && scheduledNoRuling.kind === "fail" && fabricated.kind === "fail" && red.kind === "fail" && reach.kind === "fail" && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${withScheduled.kind}/${scheduledNoRuling.kind}/${fabricated.kind}/${red.kind}/${reach.kind}/${missing.kind}`);
  const cf = canonFindings(fs.readFileSync(CANON_PLANE, "utf8"), fs.readFileSync(CANON_WALLET, "utf8"));
  ok("canon binds the gate: byo-provider-plane.md says the challenge carries the two preimages the hashes are the SHA-256 of, that what you sign is what executes, that a paraphrased, truncated or locally reconstructed facet set is a defect and a challenge without a preimage is not signable byte-derived, names the lane's owner and the gate; wallet-network/doctrine.md says the presentation is byte-derived and names the gate", cf.length === 0, cf.join("; ") || "read from both canon owners");
  return { fixture };
}

// ---- mutation ---------------------------------------------------------------------------------------------
function mutation() {
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  let f = bindingFindings(CLAUSES.map((c) => (c.n === 7 ? { ...c, executed_by: [{ ...CUSTODY, script: "check:a-script-that-does-not-exist" }] } : c)), { rootPkg, appPkg, floors });
  plant("a clause bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 12 ? { ...c, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : c)), { rootPkg, appPkg, floors });
  plant("the live cards scheduled without a ruling", f.some((x) => /scheduled_without_prerequisite_or_ruling/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.filter((c) => c.n !== 4), { rootPkg, appPkg, floors });
  plant("the byte-derived refusal clause silently dropped", f.some((x) => /clause_missing: 4/u.test(x)), f[0]);
  const fixture = readJson(FIXTURE);
  const tampered = structuredClone(fixture); tampered.challenge.lease_request_facets.deposit_usd = 3;
  f = fixtureFindings(tampered);
  plant("a fixture whose challenge bytes were changed after commit (the echoed deposit altered)", f.includes("fixture_sha256_mismatch"), f[0]);
  const forged = structuredClone(fixture); forged.challenge.approval.request_preimage = forged.challenge.approval.request_preimage.replace("\"deposit_usd\":1.0", "\"deposit_usd\":9.0"); forged.challenge_sha256 = stableSha(forged.challenge);
  f = fixtureFindings(forged);
  plant("a fixture re-committed with a preimage that no longer hashes to its request hash", f.includes("request_preimage_does_not_hash_to_request_hash"), f[0]);
  const leaky = structuredClone(fixture); leaky.steps.push({ note: "ioi_sess_forbidden" }); leaky.challenge_sha256 = stableSha(leaky.challenge);
  f = fixtureFindings(leaky);
  plant("a bearer session re-committed into the fixture", f.includes("fixture_secret_bearing"), f[0]);
  const sdlSwapped = structuredClone(fixture); sdlSwapped.request_body.plan.sdl_yaml = `${sdlSwapped.request_body.plan.sdl_yaml}# edited\n`;
  f = fixtureFindings(sdlSwapped);
  plant("a plan whose SDL bytes no longer hash to the challenge's sdl_hash (a re-stated workload)", f.includes("sdl_hash_not_derived_from_plan_bytes"), f[0]);
  const challenge = fixture.challenge;
  const plants = harnessPlants(challenge);
  plant("the diff harness's own six plants on the rendered card", plants.every((p) => p.detected && p.changed), plants.filter((p) => !p.detected).map((p) => p.expected).join(",") || `${plants.length}/${plants.length}`);
  const echoed = structuredClone(challenge); echoed.lease_request_facets.account_ref = echoed.resource_refs[0];
  f = preimageShapeFindings(echoed);
  plant("an echo that carries a hashed-only member (the shape pin moves)", f.includes("echo_carries:account_ref"), f[0]);
  const serveSource = fs.readFileSync(SERVE, "utf8");
  const timelineSource = fs.readFileSync(TIMELINE, "utf8");
  f = spaFindings(challenge, serveSource.replace(/renderProviderFacetsCard\(projectProviderChallenge\(p\.challenge\)/gu, "renderSomethingElse(p.challenge"), timelineSource);
  plant("a serve that no longer renders the grammar for a parked provider operation", f.includes("serve_does_not_render_the_grammar"), f[0]);
  f = spaFindings(challenge, serveSource.replace(/apkv\.appendChild\(el\("dd",null,ap\.audience\)\)/u, "apkv.appendChild(el(\"dd\",null,trunc(ap.audience,24)))"), timelineSource);
  plant("a session pane that truncates the audience again", f.includes("spa_pane_truncates_a_commitment"), f[0]);
  f = spaFindings(challenge, serveSource, timelineSource.replace(/projectProviderApprovalForTimeline\(run\.pendingApproval\)/gu, "({})"));
  plant("a timeline projection that drops the facets", f.includes("timeline_does_not_project_the_grammar"), f[0]);
  const lifecycle = fs.readFileSync(LIFECYCLE, "utf8");
  f = sourceFindings(lifecycle.replace(/"request_preimage": capability_lease_request_preimage\(req\),/u, ""));
  plant("a daemon that stops publishing the request preimage", f.includes("daemon_challenge_publishes_request_preimage_missing"), f[0]);
  f = sourceFindings(lifecycle.replace(/sha256_hex_str\(&capability_lease_request_preimage\(req\)\)/u, "sha256_json_ref(&json!({}))"));
  plant("a daemon whose request hash is no longer defined over the published preimage (a second reconstruction)", f.includes("daemon_request_hash_over_preimage_missing"), f[0]);
  const c = canonFindings(fs.readFileSync(CANON_PLANE, "utf8").replace(/`check:approval-card-facets`/gu, "`check:something-else`"), fs.readFileSync(CANON_WALLET, "utf8"));
  plant("canon that no longer names the gate", c.includes("canon_plane_names_gate_missing"), c[0]);
  const fake = verdict(CLAUSES.map((x) => ({ n: x.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  const stale = { ...fixture, challenge: structuredClone(fixture.challenge) }; stale.challenge.approval.request_preimage = stale.challenge.approval.request_preimage.replace("\"kind\":\"akash\",", ""); stale.challenge.approval.request_hash = sha256Text(stale.challenge.approval.request_preimage);
  f = freshFindings({ status: fixture.status, challenge: fixture.challenge, request_body: fixture.request_body }, stale);
  plant("a fresh challenge whose hashed member set differs from the fixture's (a stale fixture, or a daemon whose rule moved)", f.some((x) => /fresh_member_set_differs/u.test(x)), f[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full gate ----------------------------------------------------------------------------------------
async function freshLeg(fixture) {
  const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  const plane = await startIsolatedPlane({ baseEnv: process.env, env: { IOI_HYPERVISOR_DAEMON_BINARY: binary } });
  if (!plane) return { findings: ["isolated_plane_did_not_start"], minted: null };
  try {
    const token = bootstrapToken(plane.dataDir);
    const boot = await fetch(`${plane.daemonUrl}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "approval-card-fresh-pass-1", email: "approval-card-fresh@ioi.local" }) });
    const bootBody = await boot.json().catch(() => ({}));
    const cookie = bootBody.session_token ? `ioi_session=${bootBody.session_token}` : "";
    const minted = await mintProviderChallenge({ daemonUrl: plane.daemonUrl, cookie, tag: `fresh-${Date.now().toString(36)}` });
    const findings = freshFindings(minted, fixture);
    const card = minted.challenge?.approval?.request_preimage ? cardFindings(minted.challenge) : { findings: ["fresh_has_no_preimage"], projection: null };
    if (card.findings.length) findings.push(...card.findings.map((x) => `fresh_card:${x}`));
    return { findings, minted: { status: minted.status, reason: minted.challenge?.reason ?? null, request_hash: minted.challenge?.approval?.request_hash ?? null, hashed_members: card.projection?.facets?.map((x) => x.key) ?? [], steps: minted.steps, daemon: plane.daemonUrl } };
  } finally {
    await plane.stop();
  }
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
async function full(fixture) {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-acf-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir, live_prerequisites_present: !!(process.env.IOI_ALPHA_JOURNEY_AUTHORITY === "deployment") };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  console.log("\n# a FRESH challenge from an isolated daemon this runner starts (loopback; a sealed fake credential; no grant, nothing spent), cross-checked against the fixture");
  const fresh = await freshLeg(fixture);
  evidence.fresh = fresh;
  console.log(`  → ${fresh.findings.length === 0 ? "same rule as the fixture" : fresh.findings.join("; ")} · status ${fresh.minted?.status ?? "?"} · ${fresh.minted?.hashed_members?.length ?? 0} hashed members`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ fixture: evidence.fixture, card: evidence.card, refusal: evidence.refusal, spa: evidence.spa, source: evidence.source, fresh: evidence.fresh }, null, 2)}\n`);
  const legGreen = { "fixture (this runner)": (evidence.fixture?.findings?.length ?? 1) === 0 && (evidence.fixture?.shape?.length ?? 1) === 0, "card (this runner)": (evidence.card?.findings?.length ?? 1) === 0 && (evidence.card?.plants ?? []).every((p) => p.detected), "refusal (this runner)": (evidence.refusal?.length ?? 1) === 0, "spa (this runner)": (evidence.spa?.length ?? 1) === 0, "source (this runner)": (evidence.source?.length ?? 1) === 0, "fresh challenge (this runner)": fresh.findings.length === 0 };
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
  if (MODE === "mutation") exit = mutation() ? 0 : 1;
  else {
    const { fixture } = drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "approval-card-facets", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(fixture); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
