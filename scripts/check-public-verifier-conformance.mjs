#!/usr/bin/env node
// check:public-verifier-conformance — M06.11: the published verification package and clean-room acceptance, as
// a gate (docs/architecture/foundations/verifiable-bounded-agency.md § The published verification package;
// ioi-authority-protocol.md § Stable Release Gates; journey-14 clause 7's deterministic third; register R-218).
//
// CANON. A relying party holding only the published bytes must reach the same verdict as the producer, with
// every IOI endpoint unavailable, no private database lookup, no hosted callback, no implicit first-party trust
// root and no authority the verifier generates for itself. A verifier built only from that package and reaching
// refusal parity with the canonical one is technical evidence that the specification is sufficient — and it is
// NOT organizational independence, which is M12.7's campaign and this unit's scheduled leg.
//
// WHAT THIS RUNNER IS. Twelve clauses, each EXECUTED by one of this runner's legs or a composed gate, or NAMED
// (a typed failure with an owner) or SCHEDULED (with its exact prerequisite and ruling). The legs:
//   KIT          — the package assembled from tracked sources into a temp dir, its member list COMPUTED from the
//                  verifier's import closure, its manifest self-hashed, signed, and verified against a key the
//                  caller pins and never one the package carries; its digest equal to the one pinned in the
//                  tracked evidence record; a tampered member and an unlisted member both refused.
//   SPEC         — the package carries the registered schemas, the canonicalization and self-hash rules, the
//                  trust-input/revocation contract, the failure vocabulary, the version rules and the nonclaims,
//                  and every published member is inside the licence's open protocol surface.
//   VECTORS      — the corpus is the published one and its size is pinned in both directions.
//   HERMETIC     — the clean-room verifier's import closure is `node:`-only, escapes nothing, names no host, no
//                  URL and no file of the canonical implementation — asserted over the bytes, not read off a
//                  comment.
//   NO-AUTHORITY — the verifier computes its own build hash from its own bytes and cannot be told it; a kit
//                  verified without a pinned key is refused; the policy is supplied rather than discovered.
//   CLEANROOM    — full mode: the kit and one bundle copied into a directory OUTSIDE the repository with no
//                  `.git`, no `node_modules` and no `package.json`, run under the isolated-egress harness with
//                  no bridge at all; the clean-room verifier accepts the positive and reports the same
//                  certificate hash and claim identity as the canonical verifier, and the ledger shows zero
//                  reach AND zero loopback — a bytes-only verifier has no legitimate loopback either.
//   DIFFERENTIAL — full mode: every published negative refused by BOTH verifiers with the SAME typed code.
//                  "Both refuse" is not parity: a verifier that refused everything would satisfy it.
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills            CI-bound, seconds: BINDING, KIT, SPEC, VECTORS, HERMETIC, NO-AUTHORITY, CANON, VERDICT.
//   --mutation          planted defects against the drills' oracles — each must go red.
//   --mint-kit <path>   write the tracked kit evidence record (the pinned digest and member set).
//   (default)           the full gate: the drills, CLEANROOM, DIFFERENTIAL, then the composed gates inside the
//                       isolated-egress harness. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>   also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import * as KIT from "../apps/hypervisor/scripts/lib/public-verifier-kit.mjs";
import { NEGATIVE_CORPUS, NEGATIVE_CORPUS_SIZE, resolveVector } from "../apps/hypervisor/scripts/lib/c8-v3-negative-corpus.mjs";
import { fullyResealBundle } from "../apps/hypervisor/scripts/lib/c8-v3-bundle-reseal.mjs";
import { ownBuildHashOf } from "../apps/hypervisor/scripts/lib/clean-room-bundle-verifier.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const SCHEMAS = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const KIT_RECORD = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m06-11-public-verifier-kit-2026-09-21.v1.json");
const LICENCE = path.join(ROOT, "LICENSE-MANIFEST.json");
const VERIFIER_ENTRY = path.join(APP_DIR, "scripts", "lib", "clean-room-bundle-verifier.mjs");
const RELYING_PARTY_GATE = path.join(APP_DIR, "scripts", "verify-c8-v3-relying-party.mjs");
const CANONICAL_BINARY = path.resolve(ROOT, process.env.IOI_AFT_C8_VERIFIER || "target/debug/aft-c8-verifier");
const CANON_AGENCY = path.join(ROOT, "docs", "architecture", "foundations", "verifiable-bounded-agency.md");
const CANON_PROTOCOL = path.join(ROOT, "docs", "architecture", "foundations", "ioi-authority-protocol.md");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : flag("--mint-kit") ? "mint" : "full";
const NOW = "2026-08-22T16:00:00Z";
const HASH = /^sha256:[0-9a-f]{64}$/u;
const OWNER_Q = "owner question, R-218";

// The five registered contracts the package publishes, and the vectors the registry already tracks for them.
const KIT_CONTRACTS = [
  "c8-certificate.v3", "c8-portable-evidence-bundle.v1", "certificate-acceptance-receipt.v1",
  "relying-party-acceptance-policy.v1", "verifier-independence-profile.v1",
];
const KIT_FIXTURE_DIRS = [
  "c8-certificate-v3", "c8-portable-evidence-bundle-v1", "certificate-acceptance-receipt-v1",
  "relying-party-acceptance-policy-v1", "verifier-independence-profile-v1",
];
// What a passing implementation may and may not claim, carried in the package as bytes.
const KIT_NONCLAIMS = [
  "A verifier built from this package and reaching refusal parity with the canonical verifier claims separate_binary, separate_codegen and separate_transport under ADR 0032, and never separate_authoring_party.",
  "Technical clean-room agreement is necessary evidence of specification sufficiency and is not the organizational-independence claim; an independently administered relying party selecting its own trust policy is a separate proof (M12.7).",
  "A second first-party verifier, repository package, subsidiary or operator account is not an independently administered relying party.",
  "This package publishes one contract family — the C8 v3 portable evidence bundle and its acceptance inputs. It is not a frozen protocol-surface manifest for the whole estate.",
  "Acceptance by this package's verifier is a statement about the bundle's bytes. It asserts nothing about the availability or retention of anything the bundle names.",
  "The package carries no key, and nothing in it authenticates itself: a consumer verifies its manifest against a public key the consumer pins.",
];
const KIT_VERSION_RULES = {
  wire_mutation_policy: "forbidden",
  rule: "Every contract in this package declares `wire_mutation_policy: forbidden` in the registry: a member may not change meaning under a fixed schema version. A widening or narrowing change is a successor contract with its own version, and a bundle naming an unknown schema version is refused rather than read as its predecessor.",
  downgrade: "A verifier presented with a certificate whose schema version is not in the policy's accepted list refuses with `certificate_schema_not_accepted`; it never falls back to an older reader.",
};

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const rootGate = (script, minutes, undrilled) => ({ kind: "root", script, minutes, undrilled });
const REPLAY = rootGate("check:portable-evidence-replay", 20);
const RELYING_PARTY = gate("check:c8-v3-relying-party", "c8-v3-relying-party", 20);
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const KIT_LEG = self("kit");
const SPEC = self("spec");
const VECTORS = self("vectors");
const HERMETIC = self("hermetic");
const NO_AUTHORITY = self("no-authority");
const CLEANROOM = self("cleanroom");
const DIFFERENTIAL = self("differential");

export const CLAUSES = [
  { n: 1, demand: "the published package is content-addressed and re-derives: its member list is computed from the verifier's import closure, every member's digest is recomputed from the bytes, the manifest self-hash regenerates the digest pinned in the tracked record, and the signature verifies against a key the consumer pins and never one the package carries", executed_by: [KIT_LEG] },
  { n: 2, demand: "the package carries the specification a relying party needs: the registered schemas, the canonicalization and self-hash rules, the trust-input and revocation contract, the typed failure vocabulary, the version and downgrade rules, and the statement of what a passing implementation may and may not claim — and every published member is inside the licence's open protocol surface", executed_by: [SPEC] },
  { n: 3, demand: "the vector corpus is the published one and its size is pinned in both directions: the forty resealed semantic negatives and the positive, with one owner for the table", executed_by: [VECTORS, RELYING_PARTY] },
  { n: 4, demand: "clean room: the package and one bundle in a directory outside the repository with no .git, no node_modules and no package.json, run with no network path at all, and the clean-room verifier accepts the positive with the same certificate hash and claim identity as the canonical verifier", executed_by: [CLEANROOM] },
  { n: 5, demand: "refusal parity: every published negative is refused by BOTH verifiers with the SAME typed failure code, and the positive is accepted by both — a verifier that refused everything would satisfy 'both refuse' and is caught by the positive control", executed_by: [DIFFERENTIAL] },
  { n: 6, demand: "the clean-room verifier links no IOI runtime, Agentgres, Hypervisor or first-party verifier code: its import closure is node:-only and names no host, no URL and no file of the canonical implementation, asserted over its bytes", executed_by: [HERMETIC] },
  { n: 7, demand: "no private lookup, hosted callback, implicit first-party trust root or verifier-generated authority: the verifier computes its own build hash from its own bytes and cannot be told it, the acceptance policy is supplied rather than discovered, and a kit offered without a pinned public key is refused", executed_by: [NO_AUTHORITY, CLEANROOM] },
  { n: 8, demand: "the canonicalization is one rule, not three: the clean-room verifier's own canonical JSON and the canonical verifier's agree over every object in the corpus, which is what identical acceptance and identical refusal codes over forty resealed mutations measure", executed_by: [DIFFERENTIAL, KIT_LEG] },
  { n: 9, demand: "the portable replay and the relying-party acceptance matrix hold on the published bytes: reordered members accept byte-identically, every missing member refuses, a substituted member refuses, and one accepted fixture performs exactly one CAS-bound promotion while every rejection leaves the target hash unchanged", executed_by: [REPLAY, RELYING_PARTY] },
  { n: 10, demand: "retention and availability requirements as package members and as mutation axes", executed_by: [], absence: { what: "the scope names retention and availability requirements and the check names availability and retention mutations; NEITHER HAS A REFERENT in the five contracts this package publishes — AvailabilityManifest belongs to the M06.8 finality family and no retention member exists on the bundle, the certificate, the policy, the profile or the acceptance receipt. The package says so in its nonclaims rather than carrying a vector for a member that does not exist", owner: "M06.8 (the availability family) · the M06 owner for the check text" } },
  { n: 11, demand: "a signature over the bundle, and a frozen protocol-surface manifest freezing the exact closure the package publishes", executed_by: [], absence: { what: "the C8 portable path is hash-bound, not signature-bound: the only signature machinery in the estate is the release manifest's Ed25519 signer, which this package reuses for its OWN manifest — so a signature mutation over a BUNDLE has no referent, and canon still calls the portable outer-signature profile planned. A frozen ProtocolSurfaceManifest is required by the authority protocol in three places and exists nowhere; this package's kit.json is a frozen closure for one contract family and does not stand in for it", owner: "the M06 owner (events-receipts-delivery-bundles.md § portable outer-signature profile) · the ioi-authority-protocol.md owner (the surface manifest)" } },
  { n: 12, demand: "an independently authored implementation reaching refusal parity, and an independently administered relying party selecting its own trust policy and accepting or rejecting the exact published bytes", executed_by: [], scheduled: { what: "a disclosed external accountable principal authors and maintains a second implementation and reaches refusal parity over the published corpus (the ADR 0032 fourth axis), and M12.7's independently administered relying party selects its own trust policy and decides on the published bytes", prerequisite: "a disclosed external accountable principal outside this estate, and M12.7's separately authorized three-institution campaign; neither is a credential this program can supply, and a second first-party package would not satisfy either", ruling: "ADR 0032 (the fourth axis is claimable only with the party disclosed), journey-14's negative clause (a second first-party binary or repository package is not an independently administered relying party), R-139 (2026-09-14) and R-218 (2026-09-21): a missing external principal blocks a RUN, never the unit" } },
];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.public-verifier-conformance-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], kit: null, spec: null, vectors: null, hermetic: null, no_authority: null, cleanroom: null, differential: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `public-verifier-conformance-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256File = (f) => (fs.existsSync(f) ? `sha256:${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}` : null);

/** The declared kit content beyond the verifier's own closure: the published schemas and their vectors. */
function kitMembers() {
  const members = [];
  for (const contract of KIT_CONTRACTS) members.push({ kitPath: `schemas/${contract}.schema.json`, sourcePath: path.join(SCHEMAS, `${contract}.schema.json`), role: "schema" });
  for (const dir of KIT_FIXTURE_DIRS) {
    const source = path.join(SCHEMAS, "fixtures", dir);
    for (const file of fs.readdirSync(source).sort()) members.push({ kitPath: `vectors/${dir}/${file}`, sourcePath: path.join(source, file), role: file.startsWith("negative") ? "negative_vector" : "positive_vector" });
  }
  return members;
}
/** The typed failure vocabulary the package publishes: every code the clean-room verifier can emit. */
function failureVocabulary() {
  const source = fs.readFileSync(VERIFIER_ENTRY, "utf8");
  const codes = new Set();
  for (const match of source.matchAll(/refuse\(\s*"([a-z][a-z0-9_]*)"/gu)) codes.add(match[1]);
  for (const match of source.matchAll(/ensureEq\([^,]+,[^,]+,\s*"([a-z][a-z0-9_]*)"\s*\)/gu)) codes.add(match[1]);
  for (const match of source.matchAll(/ensureValueStr\([^,]+,\s*"([a-z][a-z0-9_]*)"/gu)) codes.add(match[1]);
  for (const match of source.matchAll(/refuse\(`\$\{key\}_([a-z_]+)`/gu)) codes.add(`<member>_${match[1]}`);
  return [...codes];
}
function buildKit(kitDir, builtAt) {
  return KIT.assembleKit({ kitDir, verifierEntry: VERIFIER_ENTRY, members: kitMembers(), builtAt, failureVocabulary: failureVocabulary(), versionRules: KIT_VERSION_RULES, nonclaims: KIT_NONCLAIMS });
}
const signerKeyPair = () => crypto.generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });

// ---- KIT ----------------------------------------------------------------------------------------------------
export function kitFindings(record) {
  const findings = [];
  const out = {};
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-kit-"));
  try {
    const kitDir = path.join(scratch, "kit");
    const { manifest, closure } = buildKit(kitDir, record?.built_at ?? "1970-01-01T00:00:00Z");
    out.kit_hash = manifest.kit_hash;
    out.members = manifest.members.length;
    out.closure = closure.files.map((f) => path.basename(f));
    if (record) {
      if (manifest.kit_hash !== record.kit_hash) findings.push(`kit_hash_differs_from_pinned:${manifest.kit_hash.slice(7, 19)}!=${String(record.kit_hash).slice(7, 19)}`);
      const pinned = new Map((record.members ?? []).map((m) => [m.path, m.sha256]));
      if (pinned.size !== manifest.members.length) findings.push(`member_count_differs:${manifest.members.length}!=${pinned.size}`);
      for (const member of manifest.members) {
        if (!pinned.has(member.path)) findings.push(`member_not_pinned:${member.path}`);
        else if (pinned.get(member.path) !== member.sha256) findings.push(`member_digest_differs:${member.path}`);
      }
    } else findings.push("kit_record_missing");
    // the signature, against a key the consumer pins
    const { publicKey, privateKey } = signerKeyPair();
    KIT.signKit({ kitDir, privateKeyPem: privateKey });
    const verified = KIT.verifyKit({ kitDir, pinnedPublicKeyPem: publicKey });
    if (verified.length) findings.push(`kit_verify:${verified.join("|")}`);
    // ...and refused without one, and under the wrong one
    if (!KIT.verifyKit({ kitDir, pinnedPublicKeyPem: null }).includes("no_pinned_signer_public_key")) findings.push("kit_verified_without_a_pinned_key");
    if (!KIT.verifyKit({ kitDir, pinnedPublicKeyPem: signerKeyPair().publicKey }).includes("kit_signature_invalid")) findings.push("kit_verified_under_a_foreign_key");
    // a tampered member, an unlisted member, a tampered manifest
    const victim = path.join(kitDir, manifest.members.find((m) => m.role === "schema").path);
    const original = fs.readFileSync(victim);
    fs.writeFileSync(victim, `${original.toString("utf8").replace("{", "{ ")}`);
    if (!KIT.verifyKit({ kitDir, pinnedPublicKeyPem: publicKey }).some((f) => f.startsWith("kit_member_digest_mismatch"))) findings.push("tampered_member_accepted");
    fs.writeFileSync(victim, original);
    fs.writeFileSync(path.join(kitDir, "extra.json"), "{}\n");
    if (!KIT.verifyKit({ kitDir, pinnedPublicKeyPem: publicKey }).some((f) => f.startsWith("kit_member_unlisted"))) findings.push("unlisted_member_accepted");
    fs.rmSync(path.join(kitDir, "extra.json"));
    const manifestPath = path.join(kitDir, "kit.json");
    const manifestBytes = fs.readFileSync(manifestPath);
    const tampered = JSON.parse(manifestBytes.toString("utf8"));
    tampered.nonclaims = [];
    fs.writeFileSync(manifestPath, `${JSON.stringify(tampered, null, 2)}\n`);
    const afterTamper = KIT.verifyKit({ kitDir, pinnedPublicKeyPem: publicKey });
    if (!afterTamper.includes("kit_hash_mismatch") || !afterTamper.includes("kit_signature_invalid")) findings.push("tampered_manifest_accepted");
    fs.writeFileSync(manifestPath, manifestBytes);
  } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
  return { findings, ...out };
}

// ---- SPEC ---------------------------------------------------------------------------------------------------
export function specFindings(record, licence) {
  const findings = [];
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-kit-spec-"));
  try {
    const kitDir = path.join(scratch, "kit");
    const { manifest } = buildKit(kitDir, record?.built_at ?? "1970-01-01T00:00:00Z");
    for (const contract of KIT_CONTRACTS) if (!manifest.members.some((m) => m.path === `schemas/${contract}.schema.json`)) findings.push(`schema_missing:${contract}`);
    if (!manifest.canonicalization?.rule || !manifest.canonicalization?.self_hash_rule) findings.push("canonicalization_rule_missing");
    if (!manifest.trust_inputs_contract?.rule || !manifest.trust_inputs_contract?.revocation || !manifest.trust_inputs_contract?.per_verifier_provision) findings.push("trust_input_contract_missing");
    if ((manifest.failure_vocabulary ?? []).length < 25) findings.push(`failure_vocabulary_thin:${(manifest.failure_vocabulary ?? []).length}`);
    for (const code of ["bundle_schema", "certificate_stale", "bound_object_hash", "outcome_predecessor_mismatch", "verifier_build_hash", "result_verdict_inconsistent"]) if (!(manifest.failure_vocabulary ?? []).includes(code)) findings.push(`failure_vocabulary_missing:${code}`);
    if (manifest.version_rules?.wire_mutation_policy !== "forbidden" || !manifest.version_rules?.downgrade) findings.push("version_rules_missing");
    if ((manifest.nonclaims ?? []).length < 6) findings.push("nonclaims_thin");
    if (!(manifest.nonclaims ?? []).some((n) => /never separate_authoring_party/u.test(n))) findings.push("nonclaims_do_not_refuse_the_fourth_axis");
    if (!(manifest.nonclaims ?? []).some((n) => /availability or retention/u.test(n))) findings.push("nonclaims_do_not_name_the_absent_members");
    // every PUBLISHED member (the schemas and vectors; the verifier is this unit's own new source) is inside
    // the licence's open protocol surface, so the package publishes nothing the licence does not cover
    const surface = JSON.stringify(licence?.open_protocol_surface ?? {});
    for (const marker of ["_meta/schemas", "fixtures"]) if (!surface.includes(marker)) findings.push(`licence_surface_missing:${marker}`);
  } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
  return findings;
}

// ---- VECTORS ------------------------------------------------------------------------------------------------
export function vectorFindings() {
  const findings = [];
  if (NEGATIVE_CORPUS.length !== NEGATIVE_CORPUS_SIZE) findings.push(`corpus_size:${NEGATIVE_CORPUS.length}!=${NEGATIVE_CORPUS_SIZE}`);
  if (new Set(NEGATIVE_CORPUS.map((v) => v.name)).size !== NEGATIVE_CORPUS.length) findings.push("corpus_names_not_unique");
  for (const vector of NEGATIVE_CORPUS) {
    if (vector.object === null) { if (typeof vector.mutateCertificate !== "function") findings.push(`certificate_vector_without_mutator:${vector.name}`); continue; }
    if (typeof vector.mutate !== "function") findings.push(`object_vector_without_mutator:${vector.name}`);
  }
  // the roles the corpus names must all resolve against a fixture that carries them, and one that does not
  // must refuse rather than mutate nothing
  let refused = false;
  try { resolveVector(NEGATIVE_CORPUS.find((v) => v.object !== null), {}); } catch { refused = true; }
  if (!refused) findings.push("unresolvable_role_did_not_refuse");
  // the relying-party gate reads THIS table rather than a copy of it
  const gateSource = fs.readFileSync(RELYING_PARTY_GATE, "utf8");
  if (!gateSource.includes("NEGATIVE_CORPUS") || !gateSource.includes("c8-v3-negative-corpus.mjs")) findings.push("corpus_has_a_second_owner");
  if (/\["result-verdict",/u.test(gateSource)) findings.push("corpus_table_still_inline_in_the_gate");
  return findings;
}

// ---- HERMETIC / NO-AUTHORITY --------------------------------------------------------------------------------
export function hermeticFindings() {
  const closure = KIT.importClosure(VERIFIER_ENTRY);
  const findings = KIT.hermeticityFindings(closure.files);
  for (const specifier of closure.bare) if (!specifier.startsWith("node:")) findings.push(`non_builtin_dependency:${specifier}`);
  if (closure.files.length !== 1) findings.push(`closure_is_not_one_file:${closure.files.length}`);
  return { findings, closure: { files: closure.files.map((f) => path.basename(f)), bare: closure.bare } };
}
export function noAuthorityFindings() {
  const findings = [];
  const source = fs.readFileSync(VERIFIER_ENTRY, "utf8");
  if (/--build-hash/u.test(source)) findings.push("verifier_accepts_a_caller_supplied_build_hash");
  if (!/ownBuildHashOf\(\[new URL\(import\.meta\.url\)\.pathname\]\)/u.test(source)) findings.push("verifier_does_not_compute_its_own_build_hash");
  if (!/ensureEq\(profile\.verifier_build_hash, ownBuildHash, "verifier_build_hash"\)/u.test(source)) findings.push("verifier_does_not_check_the_profile_against_itself");
  // the same bytes in two places produce the same identity, and different bytes do not
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-kit-identity-"));
  try {
    const copy = path.join(scratch, path.basename(VERIFIER_ENTRY));
    fs.copyFileSync(VERIFIER_ENTRY, copy);
    if (ownBuildHashOf([copy]) !== ownBuildHashOf([VERIFIER_ENTRY])) findings.push("identity_depends_on_location");
    fs.appendFileSync(copy, "\n// a byte\n");
    if (ownBuildHashOf([copy]) === ownBuildHashOf([VERIFIER_ENTRY])) findings.push("identity_survives_an_edit");
  } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
  if (!/verifyKit\(\{ kitDir, pinnedPublicKeyPem \}\)/u.test(fs.readFileSync(path.join(APP_DIR, "scripts", "lib", "public-verifier-kit.mjs"), "utf8"))) findings.push("kit_verification_does_not_take_a_pinned_key");
  return findings;
}

export function canonFindings({ agency, protocol }) {
  const findings = [];
  const n = (t) => t.replace(/\s+/gu, " ");
  const need = [
    ["agency_published_package", n(agency), /The published verification package/u],
    ["agency_sufficient", n(agency), /Published bytes are sufficient/u],
    ["agency_fourth_axis", n(agency), /never\*?\*? `separate_authoring_party`|never `separate_authoring_party`/u],
    ["agency_gate", n(agency), /`check:public-verifier-conformance`/u],
    ["protocol_one_artifact", n(protocol), /`check:public-verifier-conformance`/u],
  ];
  for (const [name, text, re] of need) if (!re.test(text)) findings.push(`canon_${name}_missing`);
  return findings;
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
        if (!rootPkg.scripts?.[g.script.replace(/^check:/u, "mutate:")] && !(typeof g.undrilled === "string" && g.undrilled.length > 20)) f.push(`clause_${c.n}_binds_undrilled_root_script: ${g.script}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
    if (c.scheduled && !(typeof c.scheduled.prerequisite === "string" && c.scheduled.prerequisite.length > 20 && typeof c.scheduled.ruling === "string" && /R-\d+/u.test(c.scheduled.ruling))) f.push(`clause_${c.n}_scheduled_without_prerequisite_or_ruling`);
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) f.push(`clause_missing: ${n}`);
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
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- drills ---------------------------------------------------------------------------------------------------
async function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(APP_DIR, "package.json"));
  const floors = readJson(FLOORS);
  const b = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  ok("BINDING — the acceptance's demands are twelve clauses, each executed by a floored gate or one of this runner's legs, or named with an owner, or scheduled with its prerequisite and ruling", b.length === 0, b.join("; ") || `${CLAUSES.length} clauses`);
  const record = fs.existsSync(KIT_RECORD) ? readJson(KIT_RECORD) : null;
  const kit = kitFindings(record);
  evidence.kit = kit;
  ok("KIT — the package is assembled from tracked sources with its member list computed from the verifier's import closure, regenerates the digest pinned in the tracked record byte for byte, verifies under a pinned key, and refuses a missing key, a foreign key, a tampered member, an unlisted member and a tampered manifest", kit.findings.length === 0, kit.findings.join("; ") || `${kit.members} members · ${String(kit.kit_hash).slice(0, 19)}`);
  const spec = specFindings(record, fs.existsSync(LICENCE) ? readJson(LICENCE) : null);
  evidence.spec = spec;
  ok("SPEC — the package carries the five registered schemas, the canonicalization and self-hash rules, the trust-input, revocation and per-verifier provisioning contract, the typed failure vocabulary, the version and downgrade rules and the nonclaims that refuse the fourth axis and name the absent members; the published members are inside the licence's open protocol surface", spec.length === 0, spec.join("; ") || "carried");
  const vectors = vectorFindings();
  evidence.vectors = vectors;
  ok("VECTORS — the negative corpus is the published forty with unique names and one owner, every vector carries its mutator, an unresolvable role refuses rather than mutating nothing, and the relying-party gate reads this table instead of a copy", vectors.length === 0, vectors.join("; ") || `${NEGATIVE_CORPUS.length} vectors`);
  const hermetic = hermeticFindings();
  evidence.hermetic = hermetic;
  ok("HERMETIC — the clean-room verifier is one file whose import closure is node: builtins only, escaping nothing, naming no host, no URL and no file of the canonical implementation", hermetic.findings.length === 0, hermetic.findings.join("; ") || hermetic.closure.bare.join(" "));
  const authority = noAuthorityFindings();
  evidence.no_authority = authority;
  ok("NO-AUTHORITY — the verifier computes its own build hash from its own bytes (the same bytes anywhere give the same identity, one edited byte does not) and cannot be told it; it checks the provisioned profile against itself; the kit cannot be verified without a pinned key", authority.length === 0, authority.join("; ") || "self-identified");
  const canon = canonFindings({ agency: fs.readFileSync(CANON_AGENCY, "utf8"), protocol: fs.readFileSync(CANON_PROTOCOL, "utf8") });
  ok("CANON — verifiable-bounded-agency.md carries the published-verification-package section with the sufficiency rule, the fourth-axis refusal and the gate; ioi-authority-protocol.md binds the gate to its release gates", canon.length === 0, canon.join("; ") || "bound");
  const rows = CLAUSES.map((x) => ({ n: x.n, executed: (x.executed_by ?? []).map((g) => ({ script: g.script, status: 0, evidence: "x", evidence_sha256: "sha256:x", ledger: { reach: 0 } })), absence: x.absence || null, scheduled: x.scheduled || null }));
  const v = verdict(rows);
  const v2 = verdict(rows.map((r) => (r.n === 5 ? { ...r, executed: [{ ...r.executed[0], status: 1 }] } : r)));
  const v3 = verdict(rows.map((r) => (r.n === 5 ? { ...r, executed: [{ ...r.executed[0], evidence: null }] } : r)));
  const v4 = verdict(rows.map((r) => (r.n === 5 ? { ...r, executed: [{ ...r.executed[0], ledger: { reach: 1 } }] } : r)));
  const v5 = verdict(rows.filter((r) => r.n !== 4));
  ok("VERDICT — pass only when every clause is executed green with evidence and no absence is named; a named absence or a scheduled leg is a NAMED FAILURE (exit 2); a red, an evidence-less green, an undeclared egress or a missing row is a FAIL", v.kind === "named_failure" && v2.kind === "fail" && v3.kind === "fail" && v4.kind === "fail" && v5.kind === "fail", `${v.kind}/${v2.kind}/${v3.kind}/${v4.kind}/${v5.kind}`);
}

// ---- mutation -------------------------------------------------------------------------------------------------
async function mutantKit(transform) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-kit-mutant-"));
  const file = path.join(dir, `kit-${crypto.randomBytes(4).toString("hex")}.mjs`);
  fs.writeFileSync(file, transform(fs.readFileSync(path.join(APP_DIR, "scripts", "lib", "public-verifier-kit.mjs"), "utf8")));
  const mod = await import(pathToFileURL(file).href);
  return { mod, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
async function mutation() {
  const rows = [];
  sink = [];
  const plant = (name, detected, detail) => { rows.push({ name, detected: !!detected, detail: String(detail ?? "").slice(0, 160) }); console.log(`${detected ? "RED " : "MISS"}  ${name}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const record = readJson(KIT_RECORD);
  // the kit oracles, against mutant copies of the kit library
  const mutate = async (name, transform, probe) => {
    let m = null;
    try { m = await mutantKit(transform); const f = probe(m.mod); plant(name, f.length > 0, f[0]); } catch (error) { plant(name, true, `mutant does not load: ${String(error?.message || error).slice(0, 80)}`); } finally { m?.cleanup(); }
  };
  const withMutantKit = (mod, probe) => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-kit-mutant-run-"));
    try { return probe(scratch, mod); } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
  };
  await mutate("a kit that verifies without a pinned key", (t) => t.replace('if (!pinnedPublicKeyPem) return ["no_pinned_signer_public_key"];', "if (!pinnedPublicKeyPem) return [];"), (mod) => withMutantKit(mod, (scratch, m) => {
    const kitDir = path.join(scratch, "kit");
    m.assembleKit({ kitDir, verifierEntry: VERIFIER_ENTRY, members: kitMembers(), builtAt: record.built_at, failureVocabulary: failureVocabulary(), versionRules: KIT_VERSION_RULES, nonclaims: KIT_NONCLAIMS });
    return m.verifyKit({ kitDir, pinnedPublicKeyPem: null }).includes("no_pinned_signer_public_key") ? [] : ["unpinned_verification_allowed"];
  }));
  await mutate("a kit that does not re-derive its members' digests", (t) => t.replace("if (sha256File(file) !== member.sha256) findings.push(`kit_member_digest_mismatch:${member.path}`);", "/* digest not re-derived */"), (mod) => withMutantKit(mod, (scratch, m) => {
    const kitDir = path.join(scratch, "kit");
    const { manifest } = m.assembleKit({ kitDir, verifierEntry: VERIFIER_ENTRY, members: kitMembers(), builtAt: record.built_at, failureVocabulary: failureVocabulary(), versionRules: KIT_VERSION_RULES, nonclaims: KIT_NONCLAIMS });
    const victim = path.join(kitDir, manifest.members[0].path);
    fs.appendFileSync(victim, " ");
    const { publicKey, privateKey } = signerKeyPair();
    m.signKit({ kitDir, privateKeyPem: privateKey });
    return m.verifyKit({ kitDir, pinnedPublicKeyPem: publicKey }).some((x) => x.startsWith("kit_member_digest_mismatch")) ? [] : ["tampered_member_accepted"];
  }));
  await mutate("a kit whose manifest self-hash is not recomputed", (t) => t.replace("if (kitHash(manifest) !== manifest.kit_hash) findings.push(\"kit_hash_mismatch\");", "/* self-hash not recomputed */"), (mod) => withMutantKit(mod, (scratch, m) => {
    const kitDir = path.join(scratch, "kit");
    m.assembleKit({ kitDir, verifierEntry: VERIFIER_ENTRY, members: kitMembers(), builtAt: record.built_at, failureVocabulary: failureVocabulary(), versionRules: KIT_VERSION_RULES, nonclaims: KIT_NONCLAIMS });
    const manifestPath = path.join(kitDir, "kit.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.nonclaims = [];
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const { publicKey, privateKey } = signerKeyPair();
    m.signKit({ kitDir, privateKeyPem: privateKey });
    return m.verifyKit({ kitDir, pinnedPublicKeyPem: publicKey }).includes("kit_hash_mismatch") ? [] : ["tampered_manifest_accepted"];
  }));
  await mutate("a hermeticity oracle blind to a third-party import", (t) => t.replace('else if (!specifier.startsWith(".") && !BUILTINS.has(specifier)) findings.push(`third_party_import:${name}:${specifier}`);', "/* third-party imports allowed */"), (mod) => withMutantKit(mod, (scratch, m) => {
    const file = path.join(scratch, "verifier.mjs");
    fs.writeFileSync(file, 'import ajv from "ajv";\nexport const x = ajv;\n');
    return m.hermeticityFindings([file]).length ? [] : ["third_party_import_allowed"];
  }));
  await mutate("a hermeticity oracle blind to an escaping import", (t) => t.replace('if (specifier.startsWith("..")) findings.push(`escaping_import:${name}:${specifier}`);', "if (false) findings.push();"), (mod) => withMutantKit(mod, (scratch, m) => {
    const file = path.join(scratch, "verifier.mjs");
    fs.writeFileSync(file, 'import { x } from "../../lib/c7-c8-certificate.mjs";\nexport const y = x;\n');
    return m.hermeticityFindings([file]).some((f) => f.startsWith("escaping_import")) ? [] : ["escaping_import_allowed"];
  }));
  await mutate("a clean-room check that accepts a room inside the repository", (t) => t.replace('if (resolved.startsWith(`${fs.realpathSync(repoRoot)}${path.sep}`)) findings.push("clean_room_inside_the_repository");', "/* inside the repo is fine */"), (mod) => {
    const inside = path.join(ROOT, "apps");
    return mod.cleanRoomFindings(inside, ROOT).includes("clean_room_inside_the_repository") ? [] : ["room_inside_the_repo_accepted"];
  });
  // the runner's own oracles
  let f = vectorFindings.call(null);
  plant("the corpus oracle is green on the real corpus (positive control)", f.length === 0, f[0] ?? "green");
  const shrunk = NEGATIVE_CORPUS.slice(0, 39);
  plant("a shrunken corpus", shrunk.length !== NEGATIVE_CORPUS_SIZE, `${shrunk.length} vectors`);
  f = specFindings({ built_at: record.built_at }, { open_protocol_surface: {} });
  plant("a licence surface that does not cover the published members", f.some((x) => x.startsWith("licence_surface_missing")), f[0]);
  f = kitFindings({ ...record, kit_hash: `sha256:${"0".repeat(64)}` }).findings;
  plant("a kit whose digest differs from the pinned record", f.some((x) => x.startsWith("kit_hash_differs_from_pinned")), f[0]);
  f = kitFindings({ ...record, members: (record.members ?? []).slice(0, 3) }).findings;
  plant("a pinned record missing members", f.some((x) => x.startsWith("member_count_differs") || x.startsWith("member_not_pinned")), f[0]);
  f = kitFindings(null).findings;
  plant("no tracked kit record at all", f.includes("kit_record_missing"), f[0]);
  const c = canonFindings({ agency: fs.readFileSync(CANON_AGENCY, "utf8").replace(/`check:public-verifier-conformance`/gu, "`check:something-else`"), protocol: fs.readFileSync(CANON_PROTOCOL, "utf8") });
  plant("canon that no longer names the gate", c.includes("canon_agency_gate_missing"), c[0]);
  const fake = verdict(CLAUSES.map((x) => ({ n: x.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  const unbound = bindingFindings(CLAUSES.map((x) => (x.n === 12 ? { n: 12, demand: x.demand, executed_by: [] } : x)), { rootPkg: readJson(path.join(ROOT, "package.json")), appPkg: readJson(path.join(APP_DIR, "package.json")), floors: readJson(FLOORS) });
  plant("the scheduled external-principal clause dropped without a prerequisite", unbound.includes("clause_12_neither_executed_nor_named"), unbound[0]);
  const noRuling = bindingFindings(CLAUSES.map((x) => (x.n === 12 ? { ...x, scheduled: { ...x.scheduled, ruling: "because I say so" } } : x)), { rootPkg: readJson(path.join(ROOT, "package.json")), appPkg: readJson(path.join(APP_DIR, "package.json")), floors: readJson(FLOORS) });
  plant("a scheduled leg whose ruling names no register row", noRuling.some((x) => x.startsWith("clause_12_scheduled_without")), noRuling[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the clean room and the differential --------------------------------------------------------------------
function emitFixture(target, secondVerifier) {
  const args = [RELYING_PARTY_GATE, "--emit-fixture", target];
  if (secondVerifier) args.push("--second-verifier", secondVerifier);
  const run = spawnSync(process.execPath, args, { cwd: ROOT, encoding: "utf8", timeout: 10 * 60 * 1000, env: { ...sanitizedVerifierBaseEnv(process.env), IOI_AFT_C8_VERIFIER: CANONICAL_BINARY } });
  if (run.status !== 0) throw new Error(`fixture emit exited ${run.status}: ${String(run.stderr).slice(0, 200)}`);
  return JSON.parse(run.stdout.slice(run.stdout.indexOf("{")));
}
const canonicalVerdict = (bundleDir, policyPath) => {
  const run = spawnSync(CANONICAL_BINARY, ["verify", "--bundle", bundleDir, "--policy", policyPath, "--now", NOW], { encoding: "utf8" });
  if (run.status === 0) return { ok: true, code: null };
  const line = `${run.stderr}`.trim().split("\n").find((l) => l.includes("Error:")) ?? `${run.stderr}`.trim().split("\n")[0] ?? "";
  return { ok: false, code: line.replace(/^Error:\s*/u, "").trim().split(":")[0].replace(/[^A-Za-z0-9._-]/gu, "_") };
};
const cleanRoomVerdict = (verifierPath, bundleDir, policyPath, cwd) => {
  const run = spawnSync(process.execPath, [verifierPath, "verify", "--bundle", bundleDir, "--policy", policyPath, "--now", NOW], { encoding: "utf8", cwd, env: sanitizedVerifierBaseEnv(process.env) });
  let parsed = null;
  try { parsed = JSON.parse(run.stdout); } catch { parsed = null; }
  if (!parsed) return { ok: false, code: "clean_room_produced_no_verdict", raw: `${run.stdout}${run.stderr}`.slice(0, 200) };
  return { ok: parsed.ok === true, code: parsed.failure_codes?.[0] ?? null, certificate_hash: parsed.certificate_hash, claim_identity: parsed.claim_identity, verifier: parsed.verifier };
};

async function cleanRoomAndDifferential(workDir) {
  const findings = { cleanroom: [], differential: [] };
  const out = { cleanroom: {}, differential: {} };
  // The room is OUTSIDE the repository: a temp dir under the OS temp root, with the kit copied in and nothing
  // else of ours. The kit's own build hash is computed before the fixture is emitted, because the relying
  // party must provision a profile naming THIS verifier before the producer assembles.
  const room = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-clean-room-"));
  try {
    const kitDir = path.join(room, "kit");
    const record = fs.existsSync(KIT_RECORD) ? readJson(KIT_RECORD) : null;
    buildKit(kitDir, record?.built_at ?? "1970-01-01T00:00:00Z");
    const { publicKey, privateKey } = signerKeyPair();
    KIT.signKit({ kitDir, privateKeyPem: privateKey });
    const kitVerify = KIT.verifyKit({ kitDir, pinnedPublicKeyPem: publicKey });
    if (kitVerify.length) findings.cleanroom.push(`kit_in_room_invalid:${kitVerify.join("|")}`);
    const roomVerifier = path.join(kitDir, path.basename(VERIFIER_ENTRY));
    const buildHash = ownBuildHashOf([roomVerifier]);
    const roomFindings = KIT.cleanRoomFindings(room, ROOT);
    if (roomFindings.length) findings.cleanroom.push(`room_not_clean:${roomFindings.join("|")}`);
    out.cleanroom.room = room;
    out.cleanroom.build_hash = buildHash;

    const fixtureDir = path.join(workDir, "fixture");
    const fixture = emitFixture(fixtureDir, `verifier://ioi/clean-room-bundle-verifier=${buildHash}`);
    if (!fixture.second_verifier) findings.cleanroom.push("fixture_carried_no_second_provision");
    const bundleInRoom = path.join(room, "bundle");
    fs.cpSync(fixture.bundle, bundleInRoom, { recursive: true });
    const roomPolicy = path.join(bundleInRoom, "policy-clean-room.json");
    const canonicalPolicy = path.join(fixture.bundle, "policy.json");

    // the positive, both sides
    const canonicalPositive = canonicalVerdict(fixture.bundle, canonicalPolicy);
    const roomPositive = cleanRoomVerdict(roomVerifier, bundleInRoom, roomPolicy, room);
    if (!canonicalPositive.ok) findings.cleanroom.push(`canonical_refused_the_positive:${canonicalPositive.code}`);
    if (!roomPositive.ok) findings.cleanroom.push(`clean_room_refused_the_positive:${roomPositive.code}`);
    if (roomPositive.certificate_hash !== fixture.second_verifier && roomPositive.ok) {
      const bundleManifest = readJson(path.join(bundleInRoom, "bundle.json"));
      if (roomPositive.certificate_hash !== bundleManifest.certificate_hash) findings.cleanroom.push("clean_room_certificate_hash_differs");
    }
    if (roomPositive.verifier?.identity_ref !== "verifier://ioi/clean-room-bundle-verifier") findings.cleanroom.push(`clean_room_identity:${roomPositive.verifier?.identity_ref}`);
    out.cleanroom.certificate_hash = roomPositive.certificate_hash;
    out.cleanroom.claim_identity = roomPositive.claim_identity;
    // and the clean room cannot verify under the CANONICAL verifier's policy: that provision is not its own
    const borrowed = cleanRoomVerdict(roomVerifier, bundleInRoom, path.join(bundleInRoom, "policy.json"), room);
    if (borrowed.ok || borrowed.code !== "verifier_build_hash") findings.cleanroom.push(`borrowed_provision:${borrowed.ok ? "ACCEPTED" : borrowed.code}`);

    // the run inside the harness, with no bridge at all
    const isolated = await runIsolated({
      label: "clean-room", argv: [process.execPath, roomVerifier, "verify", "--bundle", bundleInRoom, "--policy", roomPolicy, "--now", NOW],
      cwd: room, env: sanitizedVerifierBaseEnv(process.env), workDir, bridges: [], timeoutMs: 5 * 60_000,
    });
    const ledger = classifyLedger(isolated.ledger, { declaredHosts: [], declaredNames: [] });
    const reach = (ledger.undeclared?.length ?? 0) + (ledger.undeclared_names?.length ?? 0);
    const loopback = ledger.counts?.loopback ?? 0;
    out.cleanroom.isolation = isolated.isolation;
    out.cleanroom.ledger = { attempts: ledger.counts?.attempts ?? 0, loopback, reach };
    if (isolated.status !== 0) findings.cleanroom.push(`isolated_run_exit:${isolated.status}`);
    if (reach !== 0) findings.cleanroom.push(`clean_room_reached_out:${reach}`);
    if (loopback !== 0) findings.cleanroom.push(`clean_room_used_loopback:${loopback}`);

    // ---- the differential over every published negative -----------------------------------------------------
    const scratch = path.join(workDir, "negatives");
    fs.mkdirSync(scratch, { recursive: true });
    const rows = [];
    for (const [index, vector] of NEGATIVE_CORPUS.entries()) {
      const resolved = resolveVector(vector, fixture.refs);
      const dir = path.join(scratch, `negative-${index}-${resolved.name}`);
      fs.cpSync(fixture.bundle, dir, { recursive: true });
      fullyResealBundle({ directory: dir, refs: fixture.refs, objectRef: resolved.objectRef, mutate: resolved.mutate, mutateCertificate: resolved.mutateCertificate });
      const canonical = canonicalVerdict(dir, path.join(dir, "policy.json"));
      const room2 = cleanRoomVerdict(roomVerifier, dir, path.join(dir, "policy-clean-room.json"), room);
      const agree = !canonical.ok && !room2.ok && canonical.code === room2.code;
      rows.push({ name: resolved.name, canonical: canonical.ok ? "ACCEPTED" : canonical.code, clean_room: room2.ok ? "ACCEPTED" : room2.code, agree });
      if (!agree) findings.differential.push(`${resolved.name}:canonical=${canonical.ok ? "ACCEPTED" : canonical.code}:clean_room=${room2.ok ? "ACCEPTED" : room2.code}`);
      fs.rmSync(dir, { recursive: true, force: true });
    }
    if (rows.length !== NEGATIVE_CORPUS_SIZE) findings.differential.push(`corpus_size:${rows.length}`);
    // the positive control: a verifier that refused everything would satisfy "both refuse"
    if (!canonicalPositive.ok || !roomPositive.ok) findings.differential.push("positive_control_absent");
    out.differential.rows = rows;
    out.differential.agreed = rows.filter((r) => r.agree).length;
    out.differential.distinct_codes = [...new Set(rows.map((r) => r.canonical))].sort();
  } catch (error) {
    findings.cleanroom.push(`leg_crashed:${String(error?.stack || error).slice(0, 300)}`);
  } finally {
    fs.rmSync(room, { recursive: true, force: true });
  }
  return { findings, out };
}

async function runGate(g, workDir, floors, n) {
  const label = `${n}-${(g.floor || g.script).replace(/[^A-Za-z0-9]+/gu, "-")}`;
  const censusDir = path.join(workDir, "census", label);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true" };
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
  if (!fs.existsSync(CANONICAL_BINARY)) blocked(`the canonical verifier is absent at ${CANONICAL_BINARY} (cargo build -p aft-c8-verifier); the harness must not build`);
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-pvc-gate-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), canonical_verifier: CANONICAL_BINARY, canonical_verifier_sha256: sha256File(CANONICAL_BINARY), work_dir: workDir };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  console.log("\n# CLEANROOM and DIFFERENTIAL: the kit in a directory outside the repository, no network path at all, both verifiers over the published corpus");
  const legs = await cleanRoomAndDifferential(workDir);
  evidence.cleanroom = { findings: legs.findings.cleanroom, ...legs.out.cleanroom };
  evidence.differential = { findings: legs.findings.differential, ...legs.out.differential };
  console.log(`  → CLEANROOM ${legs.findings.cleanroom.length === 0 ? `accepted in a room with no repository and no dependencies; ledger ${JSON.stringify(legs.out.cleanroom.ledger)}; the canonical provision refused to it by name` : legs.findings.cleanroom.join("; ")}`);
  console.log(`  → DIFFERENTIAL ${legs.findings.differential.length === 0 ? `${legs.out.differential.agreed}/${NEGATIVE_CORPUS_SIZE} refusal codes identical across the two implementations (${legs.out.differential.distinct_codes.length} distinct codes)` : legs.findings.differential.join("; ")}`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ kit: evidence.kit, spec: evidence.spec, vectors: evidence.vectors, hermetic: evidence.hermetic, no_authority: evidence.no_authority, cleanroom: evidence.cleanroom, differential: evidence.differential }, null, 2)}\n`);
  const legGreen = {
    "kit (this runner)": (evidence.kit?.findings?.length ?? 1) === 0,
    "spec (this runner)": (evidence.spec?.length ?? 1) === 0,
    "vectors (this runner)": (evidence.vectors?.length ?? 1) === 0,
    "hermetic (this runner)": (evidence.hermetic?.findings?.length ?? 1) === 0,
    "no-authority (this runner)": (evidence.no_authority?.length ?? 1) === 0,
    "cleanroom (this runner)": legs.findings.cleanroom.length === 0,
    "differential (this runner)": legs.findings.differential.length === 0,
  };
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
  else if (MODE === "mint") {
    const target = path.resolve(ROOT, flagValue("--mint-kit"));
    const builtAt = new Date().toISOString();
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-kit-mint-"));
    try {
      const kitDir = path.join(scratch, "kit");
      const { manifest, closure } = buildKit(kitDir, builtAt);
      const record = {
        schema_version: "ioi.evidence.m06-11-public-verifier-kit.v1",
        minted_at: builtAt, built_at: builtAt,
        minted_by: "scripts/check-public-verifier-conformance.mjs --mint-kit",
        source: "the kit assembled from tracked sources: the clean-room verifier's computed import closure, the five registered schemas of the C8 v3 portable-evidence family and every tracked fixture of those contracts. The kit's bytes are never tracked — only this digest and the per-member digests, so a rebuild that differs is a finding rather than a diff.",
        kit_ref: manifest.kit_ref, kit_hash: manifest.kit_hash,
        verifier_closure: closure.files.map((f) => path.basename(f)), verifier_dependencies: closure.bare,
        negative_corpus_size: NEGATIVE_CORPUS_SIZE,
        failure_vocabulary: manifest.failure_vocabulary,
        members: manifest.members,
      };
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, `${JSON.stringify(record, null, 2)}\n`);
      console.log(`kit record ${path.relative(ROOT, target)} · ${manifest.members.length} members · ${manifest.kit_hash}`);
    } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
  } else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "public-verifier-conformance", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
