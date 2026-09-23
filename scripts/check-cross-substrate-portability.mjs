#!/usr/bin/env node
// check:cross-substrate-portability — M09.10: multi-substrate authority and reconciliation
// portability, as a gate
// (docs/architecture/components/hypervisor/byo-provider-plane.md § Cross-Substrate Authority And
// Reconciliation Portability; ACC-14 clause 7; R-233).
//
// CANON. One exact content-addressed workload and result policy through two genuinely different
// substrate adapter families — one may be sovereign-local, at least one a separately authorized
// external live lane — without changing the authority, intent, outcome, reconciliation, cleanup,
// receipt or verifier contracts above the provider binding.
//
// THE SURVEY SHRANK THIS UNIT RATHER THAN GROWING IT, and the gate says so out loud. Measured
// 2026-09-22: `HypervisorWorkloadEffectReconciliationReceipt` has no member that can name a
// provider (operation counts are integers, disposition is a closed pair);
// `workload_effect_boundary.rs` names no provider in production at all; the eight candidate sources
// share one operation vocabulary. So "a provider-specific field cannot leak into a source-neutral
// authority decision" is TRUE BY CONSTRUCTION three ways over. Asserting it would be asserting
// something that cannot fail, and a gate full of unfalsifiable clauses is the thing this program
// keeps finding. Clause 5 therefore asserts those facts AS SOURCE FACTS and records what they are:
// structure, not proof.
//
// WHAT CAN FAIL IS AGREEMENT. Two legs can each produce a perfectly neutral receipt and still
// disagree about `disposition`, `cleanup_verified` or `original_effect_reinvoked` — and two
// independently-correct legs are exactly the case a per-leg assertion passes twice. So the unit's
// assertion is a DIFF, and clause 3 is the unit.
//
//   PURE    — the certificate pair in apps/hypervisor/scripts/lib/c7-c8-certificate.mjs over the
//             registered fixtures: the diff, the reason floor, the pair-of-legs rule, the seal.
//   SEAM    — the registered contract refuses at the wire, and the two laws a schema cannot state
//             (the families differ, the bindings differ) are portable invariants.
//   SOURCE  — the three structural facts above, read from the daemon's own source, plus the absence
//             of the trait canon claims and the single certificate spine.
//   LANE    — M09.6's floored `check:provider-neutral-live-transaction` executes the twelve lane
//             clauses; this unit writes none of them again.
//
//   --drills           CI-bound, seconds: PURE, SEAM, SOURCE, the binding and the verdict rules.
//   --mutation         planted defects against the certificate pair — each must go red.
//   (default)          the drills plus the composed lane gate. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/c7-c8-certificate.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "c7-c8-certificate.mjs");
const META = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const BOUNDARY = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "workload_effect_boundary.rs");
const DISPATCH = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "cloud_candidate_routes.rs");
const CANON = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "byo-provider-plane.md");
const FIXTURES = path.join(META, "fixtures", "cross-substrate-portability-certificate-v1");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-233";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SEAM = self("seam");
const SOURCE = self("source");
// COMPOSED IN ITS CI-BOUND FORM, which is the workspace `--drills` subset — the same form the
// floor pins and CI runs. The ROOT form is M09.6's full gate including its scheduled live branch,
// and composing that would make this gate wait on a credential it does not hold.
const LANE = { kind: "app", script: "check:provider-neutral-live-transaction", workspace: APP, floor: "provider-neutral-live-transaction", minutes: 6 };

/** The eight substrate adapter families, measured 2026-09-22 from the module names themselves. */
const FAMILIES = ["aws", "gcp", "azure", "k8s", "akash", "lambda", "runpod", "vast"];
/** The three functions every one of them exports. Measured — `pub(crate) fn` AND `pub(crate) async fn`. */
const ADAPTER_VOCABULARY = ["fetch_offers", "normalize_offers", "source_state"];

export const CLAUSES = [
  { n: 1, demand: "ONE EXACT CONTENT-ADDRESSED WORKLOAD CROSSED, not two that resemble each other: the certificate binds `workload_content_hash`, and the two legs' agreed `request_hash` is a hash rather than a label — legs whose workload hashes differ did not run the same thing however alike their refs read", executed_by: [SEAM, PURE] },
  { n: 2, demand: "TWO GENUINELY DIFFERENT FAMILIES, CHECKED AGAINST THE LEGS AND NOT AGAINST THE DOCUMENT'S OWN CLAIM: `substrate_families_differ` is const true on the wire, but a const is an assertion a record makes about itself, so the portable invariants compare leg one's family and binding to leg two's — a certificate over one family twice, or over one binding labelled as two, would satisfy every other rule here while the crossing never happened", executed_by: [SEAM, PURE] },
  { n: 3, demand: "THE ASSERTION IS A DIFF, WHICH IS THIS UNIT: the six members above the provider binding — request hash, disposition, observed phase, cleanup verified, original effect reinvoked, and the offline verifier's verdict — are IDENTICAL across the legs or no certificate is assembled at all. Two independently-correct legs can each produce a perfectly neutral receipt and still disagree, and that is precisely the case a per-leg assertion passes twice", executed_by: [PURE, SEAM] },
  { n: 4, demand: "A PERMITTED DIFFERENCE CARRIES THE REASON IT IS PERMITTED: each member that legitimately differs is named with a reason a reader can check, no member is named twice, and the list is never empty — the lease and isolation refs always differ across two real legs, so an empty list means the certificate was not assembled from two of them, and an unreasoned entry is where a real divergence would be parked", executed_by: [PURE, SEAM] },
  { n: 5, demand: "THE NEUTRALITY IS STRUCTURAL, AND THIS CLAUSE RECORDS THAT IT IS STRUCTURE AND NOT PROOF: the reconciliation receipt has no member that can name a provider, the effect boundary that writes it names none in production, and the eight adapters share one operation vocabulary. Each is read from source here so a regression would be caught — but none of them can fail while the code is shaped this way, so this clause is a TRIPWIRE and the unit's proof is clause 3", executed_by: [SOURCE] },
  { n: 6, demand: "THE LANE ITSELF IS NOT REWRITTEN HERE: typed admissible-provider selection, the verbatim-or-skipped quote, the committed intent root, execution through the daemon's dispatch, the outcome root, reconciliation on ambiguity, teardown to zero open exposure, provider-native billing readback, leg-by-leg authorization and both terminal branches are M09.6's twelve clauses, executed by its floored gate", executed_by: [LANE] },
  { n: 7, demand: "THE CROSSING IS SEALED OVER ITS OWN CONTENT: the certificate root recomputes over the legs, the agreed members and the reasoned differences together, so a later hand cannot move one leg's disposition to match the other's and leave a certificate that still reads as an observed agreement", executed_by: [PURE, SEAM] },
  { n: 8, demand: "NO SECOND CERTIFICATE SPINE: the assembler and validator live beside M09.6's branch in the one certificate library, sharing its canonicalisation and its discipline that a certificate is never assembled over what was not observed — a parallel library for the same kind of evidence is the second spine the structural law forbids", executed_by: [SOURCE, PURE] },
  { n: 9, demand: "THE SAME OFFLINE VERIFIER OVER BOTH BUNDLES, with no provider-specific code path: its verdict is one of the six invariant members, so a verifier that accepts one leg and rejects the other has found exactly the divergence this certificate exists to catch rather than reporting two separate results", executed_by: [PURE, SEAM] },
  { n: 10, demand: "A REFUSED CROSSING MINTS NO CERTIFICATE: a disagreement, a same-family pair, a shared binding or an unreasoned difference each return a typed non-success and `certificate: null` — never a certificate carrying a note about what was wrong with it, because a certificate with a caveat is read as a certificate", executed_by: [PURE] },
  { n: 11, demand: "THE SUBSTRATE VOCABULARY IS ONE, AND IT IS A CONVENTION RATHER THAN A STRUCTURE — said plainly because canon says otherwise: all eight candidate sources export `fetch_offers`, `normalize_offers` and `source_state`, and the dispatch is eight hardcoded calls with no trait over them, so the uniformity this unit relies on is held by hand and a ninth adapter could diverge without anything failing", executed_by: [SOURCE] },
  { n: 12, demand: "THE CERTIFICATE IS A REGISTERED CONTRACT, so every refusal above is one the estate can make at the wire and not only in this runner's own library", executed_by: [SEAM], absence: { what: "THE LIVE CROSSING IS SCHEDULED, AND THE TRAIT CANON CLAIMS IS ABSENT. (1) THE CROSSING. The deterministic lane here drives the certificate pair over registered fixtures and the composed lane gate; it does NOT stand up two substrates and run one workload across them, because that needs two separately authorized provider accounts and a funded deposit on at least one, authorized leg by leg. A missing credential blocks that RUN and never the unit (R-139), and M09.6's own scheduled live branch is in exactly this state — so this unit's scheduled check is the fresh two-substrate crossing with provider-native terminal readback on both sides, every resource and exposure closed, and the same offline verifier over each bundle. (2) THE TRAIT. `byo-provider-plane.md` describes \"one operation vocabulary over eight adapters behind one trait\", and there is no such trait: the dispatch in `cloud_candidate_routes.rs` is eight hardcoded `super::<family>_candidate_source::normalize_offers(` calls, and the only `*Provider*` traits in the tree are `ProviderTransport` (the inference seam, Ollama-only), `ProviderStrategy` and `ProviderClient`. Clause 11 asserts the vocabulary holds TODAY across all eight; it cannot make it structural, and extracting a trait across eight adapter families is not this unit's licence to take", owner: `two separately authorized provider accounts with a funded deposit for the live crossing, and the cloud-candidate plane's owner for the absent adapter trait (${OWNER_Q})` } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.cross-substrate-portability-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, seam: null, source: null, lane: null, verdict: null, mutation: null };
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  results.push(row);
  evidence.drills.push({ ...row, at: new Date().toISOString() });
  console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`);
  return row.pass;
}
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `cross-substrate-portability-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const fixture = (name) => readJson(path.join(FIXTURES, `${name}.json`));
const spoil = (record, mutate) => { const copy = JSON.parse(JSON.stringify(record)); mutate(copy); return copy; };

const POSITIVE = () => fixture("positive-sovereign-local-and-live-external");

/** Two legs in the shape the assembler takes, derived from the registered positive. */
function legsFrom(certificate, overrides = {}) {
  const observed = { ...certificate.invariant_members };
  const [a, b] = certificate.legs;
  return [
    { ...a, observed: { ...observed } },
    { ...b, observed: { ...observed, ...(overrides.rightObserved ?? {}) }, ...(overrides.right ?? {}) },
  ];
}
const assembleArgs = (certificate, overrides = {}) => ({
  certificateId: certificate.certificate_id,
  workloadRef: certificate.workload_ref,
  workloadContentHash: certificate.workload_content_hash,
  resultPolicyRef: certificate.result_policy_ref,
  legs: legsFrom(certificate, overrides),
  permittedDifferences: overrides.permittedDifferences ?? certificate.permitted_differences,
});

// ---- PURE ----------------------------------------------------------------------------------------------------
export function pureFindings(lib) {
  const f = [];
  const base = POSITIVE();

  // THE CLEAN CROSSING ASSEMBLES.
  const clean = lib.assembleCrossSubstratePortability(assembleArgs(base));
  if (!clean.ok) f.push(`assemble/clean: refused a clean crossing (${clean.failures.map((x) => x.code).join(",")})`);
  else if (lib.portabilityCertificateRoot(clean.certificate) !== clean.certificate.certificate_root) {
    f.push("assemble/clean: the assembled certificate does not recompute to its own root");
  }

  // THE DIFF IS THE UNIT. Each invariant member, one at a time, so no case masks another.
  for (const member of lib.PORTABILITY_INVARIANT_MEMBERS) {
    const differing = { [member]: member === "cleanup_verified" || member === "original_effect_reinvoked" ? !base.invariant_members[member] : "a-different-value" };
    const out = lib.assembleCrossSubstratePortability(assembleArgs(base, { rightObserved: differing }));
    if (out.ok) f.push(`diff/${member}: the legs disagreed on ${member} and a certificate was assembled anyway`);
    else if (!out.failures.some((x) => x.code === "legs_disagree" && x.detail.startsWith(`${member}:`))) {
      f.push(`diff/${member}: refused for some other reason than the legs disagreeing on ${member} (${out.failures.map((x) => x.code).join(",")})`);
    }
    if (out.certificate !== null) f.push(`diff/${member}: a refused crossing still produced a certificate`);
  }
  // A member a leg never reported is not agreement. BY MESSAGE: an undefined value also differs from
  // the other leg's, so the `!same` branch catches it too and a case asserting only "some finding
  // appeared" let the unreported-member branch be deleted without noticing.
  const silent = lib.assembleCrossSubstratePortability(assembleArgs(base, { rightObserved: { disposition: undefined } }));
  if (silent.ok) f.push("diff/unreported: a leg that never reported a member was read as agreeing on it");
  else if (!silent.failures.some((x) => /did not report this member at all/u.test(x.detail))) {
    f.push("diff/unreported: refused for some other reason than the leg never having reported the member");
  }

  // THE PAIR RULES.
  const sameFamily = lib.assembleCrossSubstratePortability(assembleArgs(base, { right: { substrate_family: base.legs[0].substrate_family } }));
  if (sameFamily.ok || !sameFamily.failures.some((x) => x.code === "same_substrate_family")) f.push("pair/same-family: one family twice was accepted as a crossing");
  const sameBinding = lib.assembleCrossSubstratePortability(assembleArgs(base, { right: { provider_binding_ref: base.legs[0].provider_binding_ref } }));
  if (sameBinding.ok || !sameBinding.failures.some((x) => x.code === "same_provider_binding")) f.push("pair/same-binding: one leg recorded twice was accepted as two");
  const onePair = lib.assembleCrossSubstratePortability({ ...assembleArgs(base), legs: [legsFrom(base)[0]] });
  if (onePair.ok || !onePair.failures.some((x) => x.code === "legs_not_a_pair")) f.push("pair/one-leg: a single leg was accepted as a crossing");

  // THE REASON FLOOR.
  const unreasoned = lib.assembleCrossSubstratePortability(assembleArgs(base, { permittedDifferences: [{ member: "legs[].capability_ref", reason: "differs" }] }));
  if (unreasoned.ok || !unreasoned.failures.some((x) => x.code === "unreasoned_difference")) f.push("reason/floor: a difference permitted with no reason a reader can check was accepted");
  const none = lib.assembleCrossSubstratePortability(assembleArgs(base, { permittedDifferences: [] }));
  if (none.ok || !none.failures.some((x) => x.code === "no_permitted_differences")) f.push("reason/empty: a crossing where nothing differed was accepted from two supposedly real legs");
  const twice = lib.assembleCrossSubstratePortability(assembleArgs(base, { permittedDifferences: [...base.permitted_differences, { member: base.permitted_differences[0].member, reason: "a second and weaker reason riding in behind the first" }] }));
  if (twice.ok || !twice.failures.some((x) => x.code === "difference_named_twice")) f.push("reason/twice: one member carried two reasons");

  // THE VALIDATOR READS A CERTIFICATE BACK BELIEVING NONE OF ITS OWN CLAIMS.
  const must = (what, out, shouldBeOk) => {
    if (out.ok !== shouldBeOk) f.push(`validate/${what}: ${shouldBeOk ? `refused a clean certificate (${out.failures.map((x) => x.code).join(",")})` : "accepted a spoiled one"}`);
  };
  // RE-SEALED, AND BY CODE. Spoiling a member also moves the root, so `root_does_not_recompute`
  // fires and a case asserting only "some finding appeared" is satisfied by it — which let four of
  // these checks be deleted while the drill stayed green. Re-sealing removes the root finding, so
  // the only thing left to catch each case is the check it is named for.
  const resealed = (mutate) => { const c = spoil(base, mutate); c.certificate_root = lib.portabilityCertificateRoot(c); return c; };
  const only = (what, certificate, code) => {
    const out = lib.validateCrossSubstratePortabilityCertificate(certificate);
    must(what, out, false);
    if (!out.failures.some((x) => x.code === code)) {
      f.push(`validate/${what}: refused with ${out.failures.map((x) => x.code).join(",") || "nothing"} rather than ${code}`);
    }
  };
  must("clean", lib.validateCrossSubstratePortabilityCertificate(base), true);
  must("two-live", lib.validateCrossSubstratePortabilityCertificate(fixture("positive-two-live-lanes-that-observed-no-effect")), true);
  only("claims-authority", resealed((c) => { c.grants_no_authority = false; }), "claims_authority");
  only("qualifies-another", resealed((c) => { c.qualifies_no_other_provider = false; }), "qualifies_another_provider");
  only("families-not-declared", resealed((c) => { c.substrate_families_differ = false; }), "families_not_declared_different");
  only("invariant-absent", resealed((c) => { delete c.invariant_members.original_effect_reinvoked; }), "invariant_member_absent");
  only("no-workload-hash", resealed((c) => { c.workload_content_hash = "not-a-hash"; }), "no_workload_content_hash");
  // The root check itself still needs a case, and this is the one that must NOT be re-sealed.
  only("root-moved", spoil(base, (c) => { c.invariant_members.cleanup_verified = false; }), "root_does_not_recompute");

  // BY MESSAGE, because the same-family certificate also fails its root if resealing is skipped, and
  // the case must isolate the check it is named for.
  const sameFamilyCert = fixture("negative-both-legs-the-same-family");
  const sameOut = lib.validateCrossSubstratePortabilityCertificate(sameFamilyCert);
  if (sameOut.ok || !sameOut.failures.some((x) => x.code === "same_substrate_family")) {
    f.push("validate/same-family: the const was believed instead of checked against the legs");
  }

  if (lib.PORTABILITY_INVARIANT_MEMBERS.length !== 6) f.push("vocabulary: six members must agree above the provider binding");
  return f;
}

// ---- SEAM ----------------------------------------------------------------------------------------------------
export function seamFindings({ registry, schema, invariants }) {
  const f = [];
  const row = registry.contracts.find((c) => c.contract_id === "schema://ioi/hypervisor/cross-substrate-portability-certificate/v1");
  if (!row) { f.push("the portability certificate is not a registered contract"); return f; }

  for (const member of ["substrate_families_differ", "grants_no_authority", "qualifies_no_other_provider"]) {
    if (schema.properties?.[member]?.const !== true) f.push(`${member} is not pinned on the wire`);
  }
  const legs = schema.properties?.legs ?? {};
  if (legs.minItems !== 2 || legs.maxItems !== 2) f.push("a crossing is exactly two legs; the contract admits a different count");
  const invariantMembers = schema.properties?.invariant_members?.required ?? [];
  for (const member of LIB.PORTABILITY_INVARIANT_MEMBERS) {
    if (!invariantMembers.includes(member)) f.push(`the contract does not require the agreed \`${member}\`, so a crossing could omit it`);
  }
  const reason = schema.properties?.permitted_differences?.items?.properties?.reason ?? {};
  if (!(reason.minLength >= 20)) f.push("a permitted difference's reason has no floor, so `differs` would pass as one");
  if ((schema.properties?.permitted_differences?.minItems ?? 0) < 1) f.push("the contract admits a crossing where nothing differed");
  if (schema.additionalProperties !== false) f.push("the certificate accepts additional members");
  if (schema.properties?.legs?.items?.properties?.substrate_family?.enum) {
    f.push("substrate_family is a closed enum, which is a second list to drift from the eight modules");
  }

  // THE TWO LAWS A SCHEMA CANNOT STATE.
  const ruleIds = invariants.rules.map((r) => r.rule_id);
  for (const rule of ["cross_substrate_portability_certificate.the_two_families_differ", "cross_substrate_portability_certificate.the_legs_are_distinct_bindings"]) {
    if (!ruleIds.includes(rule)) f.push(`${rule} is not a registered invariant, so the const is checked only against itself`);
  }

  // EVERY MATERIAL MEMBER REQUIRED — only the Rust golden oracle can otherwise see this.
  const root = invariants.rules.find((r) => r.expression.operator === "jcs_sha256_equals");
  if (!root) f.push("no root invariant");
  else for (const member of Object.keys(root.expression.material_fields)) {
    if (!schema.required.includes(member)) f.push(`\`${member}\` is material to the root and not required, so the projection may drop it`);
  }

  if (row.positive_fixture_refs.length < 2) f.push("fewer than two positive fixtures: the sovereign-local and two-live shapes are different crossings");
  if (row.negative_fixture_refs.length < 10) f.push(`${row.negative_fixture_refs.length} negative fixtures is too few to bound this shape`);
  for (const negative of row.negative_fixture_refs) {
    if (!["schema", "invariant"].includes(negative.expected_failure)) f.push(`${negative.path} is classified \`${negative.expected_failure}\``);
  }
  return f;
}

// ---- SOURCE --------------------------------------------------------------------------------------------------
export function sourceFindings({ receipt, boundary, dispatch, canon, lib }) {
  const f = [];

  // (1) THE RECEIPT CANNOT NAME A PROVIDER.
  const receiptText = JSON.stringify(receipt).toLowerCase();
  for (const token of ["provider_id", "provider_name", "provider_ref", ...FAMILIES]) {
    if (receiptText.includes(token)) f.push(`the reconciliation receipt can carry \`${token}\`, so a provider-specific field can reach a source-neutral record`);
  }

  // (2) THE BOUNDARY NAMES NO PROVIDER IN PRODUCTION. Test fixtures may; production may not.
  const cfgTest = boundary.indexOf("#[cfg(test)]");
  const production = cfgTest >= 0 ? boundary.slice(0, cfgTest) : boundary;
  for (const family of FAMILIES) {
    if (new RegExp(`\\b${family}\\b`, "iu").test(production)) f.push(`workload_effect_boundary.rs names \`${family}\` in production code`);
  }
  // Whitespace-normalised: the sentence wraps across a `//! ` continuation in the module header,
  // so a naive regex reports the rule missing when it is merely on two lines.
  const prose = boundary.replace(/\n\s*\/\/!?/gu, " ").replace(/\s+/gu, " ");
  if (!/never enter the guest envelope/u.test(prose)) f.push("the effect boundary no longer states that provider credentials never enter the guest envelope");

  // (3) ALL EIGHT ADAPTERS SHARE THE VOCABULARY, and the dispatch reaches every one of them.
  for (const family of FAMILIES) {
    const file = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", `${family}_candidate_source.rs`);
    if (!fs.existsSync(file)) { f.push(`no candidate source for \`${family}\``); continue; }
    const text = readText(file);
    for (const fn of ADAPTER_VOCABULARY) {
      if (!new RegExp(`pub\\(crate\\) (?:async )?fn ${fn}\\b`, "u").test(text)) f.push(`${family} does not export \`${fn}\`, so the operation vocabulary is no longer one`);
    }
    if (!dispatch.includes(`${family}_candidate_source::normalize_offers(`)) f.push(`the dispatch never reaches \`${family}\``);
  }

  // (4) NO SECOND CERTIFICATE SPINE.
  if (!/export function assembleCrossSubstratePortability/u.test(lib)) f.push("the assembler does not live in the one certificate library");
  if (!/export function sealCertificate/u.test(lib)) f.push("the portability pair has been split from M09.6's branch into a second spine");

  // (5) CANON'S BINDING, and the claim it makes that the code does not keep.
  if (!/Cross-Substrate Authority And Reconciliation Portability/u.test(canon)) f.push("canon no longer carries this unit's section");
  if (!/would be unfalsifiable/u.test(canon)) f.push("canon no longer records that the structural facts are unfalsifiable rather than proof");
  return f;
}

export function sourceInputs() {
  return {
    receipt: readJson(path.join(META, "hypervisor-workload-effect-reconciliation-receipt.v1.schema.json")),
    boundary: readText(BOUNDARY),
    dispatch: readText(DISPATCH),
    canon: readText(CANON),
    lib: readText(LIB_PATH),
  };
}

// ---- the binding ---------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const script of ["check:cross-substrate-portability", "mutate:cross-substrate-portability"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:cross-substrate-portability"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "cross-substrate-portability");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  // THE COMPOSED GATE MUST ITSELF BE FLOORED, or clause 6 delegates to something unpinned.
  const lane = (floors.verifiers ?? []).find((r) => r.id === LANE.floor);
  if (!lane) f.push(`composed_gate_unfloored:${LANE.floor}`);
  if (!/npm run check:cross-substrate-portability --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("ci_not_bound_in_the_recognised_form");
  if (!/mutate:cross-substrate-portability/u.test(ci)) f.push("ci_mutation_not_bound");
  if (!floorsGate.includes("check-cross-substrate-portability")) {
    f.push("floors_gate_does_not_recognise_this_runner: it is a `check-*` script and the floors gate discovers those from an explicit allow-list");
  }
  for (const clause of CLAUSES) {
    if (!clause.executed_by?.length && !clause.absence) f.push(`clause_${clause.n}_neither_executed_nor_named`);
    if (clause.absence && !clause.absence.owner) f.push(`clause_${clause.n}_absence_without_owner`);
  }
  if (CLAUSES.length !== 12) f.push(`clause_count:${CLAUSES.length}`);
  return f;
}

// ---- the verdict ---------------------------------------------------------------------------------------------
export function verdict(rows) {
  const failures = [];
  const absences = [];
  for (const clause of CLAUSES) {
    const row = rows.find((r) => r.n === clause.n);
    if (!row) { failures.push(`row_missing:${clause.n}`); continue; }
    if (row.fabricated) { failures.push(`clause_${clause.n}_fabricated: ${row.fabricated}`); continue; }
    if (row.below_floor) { failures.push(`clause_${clause.n}_below_floor: ${row.below_floor}`); continue; }
    if (row.red) { failures.push(`clause_${clause.n}_red: ${row.red}`); continue; }
    if (row.absent) absences.push({ n: clause.n, ...clause.absence });
  }
  if (failures.length) return { kind: "fail", failures, absences };
  if (absences.length) return { kind: "named_failure", failures, absences };
  return { kind: "pass", failures, absences };
}

// ---- run -----------------------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = pure;
  ok("PURE — the diff is the assertion: six members identical across the legs or NO certificate is assembled, each member isolated so no case masks another; one family twice, one binding twice and a single leg are each refused by their own code; a difference permitted with no reason a reader can check is refused; and the validator reads a certificate back believing none of its own claims", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const seam = seamFindings({
    registry: readJson(path.join(META, "architecture-contract-registry.v1.json")),
    schema: readJson(path.join(META, "cross-substrate-portability-certificate.v1.schema.json")),
    invariants: readJson(path.join(META, "invariants", "cross-substrate-portability-certificate.v1.invariants.json")),
  });
  evidence.seam = seam;
  ok("SEAM — the registered contract carries the law: exactly two legs, the six agreed members required, a 20-character floor on every permitted difference's reason, three consts on the wire, `substrate_family` left open because the families are modules and not an enum, every material member required so the projection cannot drop it, and the two laws a schema CANNOT state registered as portable invariants", seam.length === 0, seam.slice(0, 4).join(" ; "));

  const src = sourceFindings(sourceInputs());
  evidence.source = src;
  ok("SOURCE — the three structural facts, read from source as a TRIPWIRE rather than as proof: the reconciliation receipt has no member that can name a provider, the effect boundary names none in production (test fixtures excluded deliberately), and all eight candidate sources export the one vocabulary with the dispatch reaching every one — plus the single certificate spine and canon's own record that these facts are structure", src.length === 0, src.slice(0, 4).join(" ; "));

  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: readText(path.join(ROOT, ".github", "workflows", "ci.yml")),
    floorsGate: readText(path.join(APP_DIR, "scripts", "check-verifier-floors.mjs")),
  });
  ok("BINDING — the gate is floored with an existing source, CI-bound in the form the FLOORS GATE recognises, the gate it COMPOSES is itself floored so clause 6 does not delegate to something unpinned, and every clause is executed or named with an owner", binding.length === 0, binding.slice(0, 4).join(" ; "));

  const all = CLAUSES.map((c) => ({ n: c.n }));
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", verdict([{ n: 1 }]).kind === "fail");
  ok("VERDICT — twelve green rows with no absence is a PASS", verdict(all).kind === "pass");
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", verdict(all.map((r) => (r.n === 12 ? { ...r, absent: true } : r))).kind === "named_failure");
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", verdict(all.map((r) => (r.n === 1 ? { ...r, fabricated: "x" } : r))).kind === "fail");
  ok("VERDICT — a gate below its floor fails even at exit 0", verdict(all.map((r) => (r.n === 1 ? { ...r, below_floor: "x" } : r))).kind === "fail");

  return { pure, seam, src, binding };
}

async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cross-substrate-mutation-"));
  let planted = 0;
  let caught = 0;
  const mutate = async (what, transform) => {
    planted += 1;
    const file = path.join(dir, `m${planted}.mjs`);
    const text = transform(original);
    if (text === original) { console.log(`FAIL  mutation ${planted} (${what}) — the planted defect changed nothing`); return; }
    fs.writeFileSync(file, text);
    let findings = [];
    try { findings = pureFindings(await import(pathToFileURL(file).href)); } catch (error) { findings = [`threw:${error.message}`]; }
    const red = findings.length > 0;
    if (red) caught += 1;
    console.log(`${red ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${red ? "" : " SURVIVED"}`);
  };

  await mutate("DIFF — the legs need not agree at all", (t) => t.replace("  for (const row of disagreements) {", "  for (const row of []) {"));
  await mutate("DIFF — only the first member is compared", (t) => t.replace("  for (const member of PORTABILITY_INVARIANT_MEMBERS) {\n    const a = left?.[member];", "  for (const member of PORTABILITY_INVARIANT_MEMBERS.slice(0, 1)) {\n    const a = left?.[member];"));
  await mutate("DIFF — a member a leg never reported reads as agreement", (t) => t.replace("    if (a === undefined || b === undefined) {", "    if (false) {"));
  await mutate("DIFF — the comparison becomes reference equality of stringified nothing", (t) => t.replace("    if (!same(a, b)) rows.push(", "    if (false) rows.push("));
  await mutate("PAIR — one family twice is a crossing", (t) => t.replace("  if (left?.substrate_family && left.substrate_family === right?.substrate_family) {", "  if (false) {"));
  await mutate("PAIR — one binding twice is two legs", (t) => t.replace("  if (left?.provider_binding_ref && left.provider_binding_ref === right?.provider_binding_ref) {", "  if (false) {"));
  await mutate("PAIR — any number of legs will do", (t) => t.replace("  if (!Array.isArray(legs) || legs.length !== 2) {", "  if (false) {"));
  await mutate("REASON — `differs` passes as a reason", (t) => t.replace("entry.reason.trim().length < 20", "entry.reason.trim().length < 0"));
  await mutate("REASON — a crossing where nothing differed is fine", (t) => t.replace('if (differences.length === 0) fail("no_permitted_differences"', 'if (false) fail("no_permitted_differences"'));
  await mutate("REASON — one member may carry two reasons", (t) => t.replace('    if (seen.has(entry?.member)) fail("difference_named_twice"', '    if (false) fail("difference_named_twice"'));
  await mutate("REFUSAL — a refused crossing still mints a certificate", (t) => t.replace("  if (failures.length) return { ok: false, failures, certificate: null };\n\n  const certificate = {", "  if (false) return { ok: false, failures, certificate: null };\n\n  const certificate = {"));
  await mutate("SEAL — the root is computed over the wrong members", (t) => t.replace('"schema_version", "certificate_id", "workload_ref", "workload_content_hash", "result_policy_ref",', '"certificate_id", "workload_ref", "workload_content_hash", "result_policy_ref",'));
  await mutate("SEAL — the root stops covering the legs", (t) => t.replace('  "legs", "invariant_members", "permitted_differences", "substrate_families_differ",', '  "invariant_members", "permitted_differences", "substrate_families_differ",'));
  await mutate("VALIDATE — a certificate claiming authority reads clean", (t) => t.replace('if (certificate?.grants_no_authority !== true) fail("claims_authority"', 'if (false) fail("claims_authority"'));
  await mutate("VALIDATE — a certificate reaching past its two families reads clean", (t) => t.replace('if (certificate?.qualifies_no_other_provider !== true) fail("qualifies_another_provider"', 'if (false) fail("qualifies_another_provider"'));
  await mutate("VALIDATE — the const is believed instead of checked against the legs", (t) => t.replace("    if (legs[0]?.substrate_family === legs[1]?.substrate_family) fail(\"same_substrate_family\"", "    if (false) fail(\"same_substrate_family\""));
  await mutate("VALIDATE — an absent agreed member reads clean", (t) => t.replace("    if (certificate?.invariant_members?.[member] === undefined) fail(\"invariant_member_absent\"", "    if (false) fail(\"invariant_member_absent\""));
  await mutate("VALIDATE — the workload need not be content-addressed", (t) => t.replace('if (!hash(certificate?.workload_content_hash)) fail("no_workload_content_hash"', 'if (false) fail("no_workload_content_hash"'));
  await mutate("VALIDATE — a moved root reads clean", (t) => t.replace("  if (portabilityCertificateRoot(certificate) !== certificate?.certificate_root) {", "  if (false) {"));
  await mutate("VOCABULARY — the agreed set shrinks", (t) => t.replace('export const PORTABILITY_INVARIANT_MEMBERS = [\n  "request_hash",', 'export const PORTABILITY_INVARIANT_MEMBERS = [\n  // request_hash removed'));

  console.log(`\n${caught}/${planted} planted defects caught`);
  evidence.mutation = { planted, caught };
  return caught === planted;
}

async function main() {
  if (MODE === "mutation") {
    const green = await mutation();
    const file = writeEvidence();
    console.log(`evidence: ${path.relative(ROOT, file)}`);
    process.exit(green ? 0 : 1);
  }

  const { pure, seam, src, binding } = await drills();
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} drills passed`);
  emitVerifierCensus({ verifierId: "cross-substrate-portability", sourceUrl: import.meta.url, results });

  if (MODE === "drills") {
    const file = writeEvidence();
    console.log(`evidence: ${path.relative(ROOT, file)}`);
    process.exit(passed === results.length ? 0 : 1);
  }

  // ---- full: the composed lane gate --------------------------------------------------------------
  const { spawnSync } = await import("node:child_process");
  const lane = spawnSync("npm", ["run", LANE.script, `--workspace=${LANE.workspace}`], { cwd: ROOT, encoding: "utf8", timeout: LANE.minutes * 60_000 });
  // M09.6's gate exits 2 on ITS OWN named absence (the scheduled live branch), which is that gate
  // working — not a failure of this one. Only a hard failure or a crash is red here. A null status
  // is a timeout or a spawn error and is ALWAYS red: a composed gate that did not run is not a
  // composed gate that passed, and reporting it as `exit null` rather than as a miss is how a
  // delegation quietly becomes a hole.
  const timedOut = lane.status === null;
  const laneRed = timedOut || (lane.status !== 0 && lane.status !== 2);
  evidence.lane = { status: lane.status, timed_out: timedOut, named_absence_ok: lane.status === 2, stderr: String(lane.stderr ?? "").slice(0, 400) };
  console.log(`\n# LANE — ${LANE.script} ${timedOut ? `DID NOT COMPLETE within ${LANE.minutes}m (${lane.error?.message ?? "no status"})` : `exit ${lane.status}`}${lane.status === 2 ? " (its own named absence: the scheduled live branch)" : ""}`);

  const rows = CLAUSES.map((clause) => {
    const row = { n: clause.n };
    const red = [];
    if (clause.executed_by.some((e) => e.script.startsWith("pure")) && pure.length) red.push("PURE");
    if (clause.executed_by.some((e) => e.script.startsWith("seam")) && seam.length) red.push("SEAM");
    if (clause.executed_by.some((e) => e.script.startsWith("source")) && src.length) red.push("SOURCE");
    if (clause.executed_by.some((e) => e.kind === "app") && laneRed) red.push(`LANE(${LANE.script} ${timedOut ? `did not complete in ${LANE.minutes}m` : `exit ${lane.status}`})`);
    if (red.length) row.red = red.join("+");
    if (clause.absence) row.absent = true;
    return row;
  });
  if (binding.length) rows.find((r) => r.n === 12).red = `BINDING: ${binding.join("; ")}`;

  const result = verdict(rows);
  evidence.verdict = result;
  console.log(`\n=== VERDICT: ${result.kind.toUpperCase()}${result.failures.length ? ` — ${result.failures.join(" ; ")}` : ""}`);
  for (const absence of result.absences) console.log(`NAMED  clause ${absence.n}: ${absence.what}`);
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(result.kind === "pass" ? 0 : result.kind === "named_failure" ? 2 : 1);
}

main().catch((error) => { console.error(error); writeEvidence(); process.exit(1); });
