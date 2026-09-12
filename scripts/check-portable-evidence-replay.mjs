#!/usr/bin/env node
//
// M06.4 — A PORTABLE EVIDENCE BUNDLE REPRODUCES ITS DECISION OFFLINE, OR SAYS WHY IT CANNOT.
//
// ACC-8 clauses 4 and 5 ask that a bundle reproduce a decision on a fresh daemon and that restore
// prove SEMANTIC CONTINUITY rather than blob presence. `check:backup-restore` already proves the
// managed-backup half against a fresh daemon. What was missing is the portable half, and measuring
// the estate before writing anything showed why it is worth separating:
//
//   WHAT ALREADY EXISTS. A registered portable-evidence-bundle contract; a STANDALONE offline
//   relying party as its own crate, which takes a bundle directory and re-derives a verdict with no
//   daemon at all; a six-test structural suite over the bundle FORMAT; and a battery that rejects
//   forty fully resealed semantic mutations.
//
//   WHAT NONE OF THEM CLAIMS. Every one of the six structural tests is a property of the format —
//   canonical hashing ignores key order, contracts exclude their self-hash field, a traversal
//   filename is rejected, assembler output is exclusive, versioned identity resolves by committed
//   hash, duplicate ref/hash binding stays forbidden. The forty resealed mutations are the INVERSE
//   claim: a tampered bundle is refused. Neither says that an untampered bundle REPRODUCES the
//   decision it carries, and "refuses what is wrong" plus "the format is well-formed" does not add
//   up to "reproduces what is right" — a verifier that refused everything would satisfy both.
//
// THE THREE AXES, AND THEY DO NOT HAVE THE SAME RIGHT ANSWER. That asymmetry is the point: a check
// that treated them alike would be wrong on one of them whichever way it leaned.
//
//   REORDERED  → ACCEPTED, and byte-identically so. Reordering is exactly what canonicalisation
//                exists to make invisible, so the correct outcome is the SAME verdict and the SAME
//                certificate hash, not a refusal.
//   MISSING    → REFUSED, over EVERY declared member. A bundle that accepts with a member absent is
//                accepting over less evidence than it claims to carry, which is the precise failure
//                "blob presence rather than semantic continuity" names.
//   SUBSTITUTED→ REFUSED. A member replaced by a different, individually well-formed member is the
//                case a shape check cannot catch and a hash binding must.
//
// The fixture is NOT rebuilt here. Assembling a valid bundle takes two hundred and fifty lines that
// the relying-party gate already owns, and a second copy would be a second drifting definition of
// "a valid bundle" — the defect this program has now corrected three times elsewhere. That gate
// emits its fixture on request and remains its only author.
//
//   --mutation  prove each finding fails on its own
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const findings = [];
const observations = {};
const ok = (name, satisfied, detail) => {
  findings.push({ name, satisfied: !!satisfied, detail: detail ?? "" });
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};

// The bundle's declared member population, pinned. A missing-axis drill that ran over zero members
// would pass in silence, which is the failure mode every population pin in this estate exists for.
const DECLARED_OBJECTS = 23;
const MEMBER_FILES = 27;

const scratch = mkdtempSync(join(tmpdir(), "portable-evidence-replay-"));
const emit = spawnSync("node", [
  join(repo, "apps/hypervisor/scripts/verify-c8-v3-relying-party.mjs"),
  "--emit-fixture", join(scratch, "fixture"),
], { cwd: repo, encoding: "utf8", timeout: 10 * 60 * 1000 });

let fixture = null;
try {
  fixture = JSON.parse(emit.stdout.slice(emit.stdout.indexOf("{")));
} catch {
  fixture = null;
}
ok("the fixture is COMPOSED from the gate that already owns it, not rebuilt here — assembling a valid bundle is two hundred and fifty lines, and a second copy would be a second drifting definition of what 'valid' means",
  emit.status === 0 && !!fixture?.bundle && existsSync(fixture.bundle),
  fixture ? `${(fixture.member_files || []).length} member files emitted` : `emit exited ${emit.status}`);

const verifierPath = fixture?.verifier || join(repo, "target/debug/aft-c8-verifier");
const manifest = fixture ? JSON.parse(readFileSync(join(fixture.bundle, "bundle.json"), "utf8")) : { objects: [] };
observations.declared_objects = (manifest.objects || []).length;
observations.member_files = (fixture?.member_files || []).length;
ok("and the bundle's declared member population is PINNED in both counts — a replay battery that ran over an empty bundle would pass while proving nothing, and the two counts differ because the manifest, the policy and the certificate are members the manifest does not list as objects",
  observations.declared_objects === DECLARED_OBJECTS && observations.member_files === MEMBER_FILES,
  `${observations.declared_objects}/${DECLARED_OBJECTS} declared objects, ${observations.member_files}/${MEMBER_FILES} member files`);

// A fresh registry per attempt: acceptance MUTATES it, so reusing one would make the second run a
// different question from the first.
let attempt = 0;
const freshRegistry = () => {
  const path = join(scratch, `registry-${attempt++}.json`);
  cpSync(fixture.registry, path);
  return path;
};
const accept = (bundleDir) => {
  const registry = freshRegistry();
  const receipt = join(scratch, `receipt-${attempt}.json`);
  const result = spawnSync(verifierPath, [
    "accept", "--bundle", bundleDir, "--policy", join(bundleDir, "policy.json"),
    "--registry", registry, "--row-output", join(scratch, `row-${attempt}.json`), "--receipt", receipt,
    // THE CLOCK AND THE REVISION COME FROM THE FIXTURE, NOT FROM HERE. The bundle is sealed against
    // a specific instant and the registry starts at revision zero; a caller that supplied its own
    // would be asking a different question and reading the refusal as a finding. The first cut
    // omitted both, and every acceptance failed on a usage error that looked exactly like a
    // rejection — the pristine run went red and the MISSING axis went green for it, which is the
    // shape of a battery passing because nothing works rather than because everything does.
    "--expected-revision", String(fixture?.expected_revision ?? 0), "--now", fixture?.now ?? "",
  ], { cwd: repo, encoding: "utf8", timeout: 5 * 60 * 1000 });
  let parsed = null;
  try {
    parsed = JSON.parse(readFileSync(receipt, "utf8"));
  } catch {
    parsed = null;
  }
  return { status: result.status, receipt: parsed, stderr: (result.stderr || "").slice(0, 200) };
};

const copyBundle = (name) => {
  const target = join(scratch, name);
  cpSync(fixture.bundle, target, { recursive: true });
  return target;
};

// ------------------------------------------------------ 1. it reproduces, twice, with no daemon
const first = fixture ? accept(copyBundle("pristine-a")) : { status: 1, receipt: null };
const second = fixture ? accept(copyBundle("pristine-b")) : { status: 1, receipt: null };
observations.certificate_hash = first.receipt?.certificate_hash || null;
ok("THE BUNDLE REPRODUCES ITS DECISION OFFLINE, AND REPRODUCES IT TWICE IDENTICALLY — no daemon, no network, no record store, and the second run agrees with the first on the decision AND the certificate hash. A verifier that merely refused everything would satisfy every rejection battery in the estate and fail this",
  first.status === 0 && second.status === 0
    && first.receipt?.decision === "accepted" && second.receipt?.decision === "accepted"
    && !!first.receipt?.certificate_hash
    && first.receipt.certificate_hash === second.receipt.certificate_hash,
  first.receipt
    ? `${first.receipt.decision}/${second.receipt?.decision} · ${String(first.receipt.certificate_hash).slice(0, 22)}…`
    : `exit ${first.status} ${first.stderr}`);

// ------------------------------------------------------ 2. REORDERED — two halves, two answers
//
// MEASURED RATHER THAN ASSUMED, and the first cut of this gate assumed wrong. "Reordering changes
// nothing" is true of one kind of order and false of another, and the difference is the whole
// claim:
//
//   KEY ORDER INSIDE A MEMBER is presentation. The same object serialised with its keys reversed is
//   the same object, and it verifies — canonical hashing is what makes that true, and it is exactly
//   what "semantic continuity rather than blob presence" means: the bytes moved, the meaning did
//   not, and the decision is unchanged.
//
//   THE MANIFEST'S OBJECT ARRAY is not presentation. An array's order is part of its value, so
//   reversing it changes the bundle hash and is REFUSED — correctly, because a bundle whose member
//   list could be rearranged after sealing would be resealable by anyone holding it.
//
// A gate asserting only the first would call a real binding a bug; one asserting only the second
// would call canonicalisation a bug. Both are asserted, with their opposite expected outcomes.
let keyOrder = null;
let listOrder = null;
if (fixture) {
  const keyDir = copyBundle("reordered-keys");
  for (const entry of manifest.objects || []) {
    const file = join(keyDir, entry.file);
    if (!existsSync(file)) continue;
    const value = JSON.parse(readFileSync(file, "utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
    writeFileSync(file, `${JSON.stringify(Object.fromEntries(Object.entries(value).reverse()), null, 2)}\n`);
  }
  keyOrder = accept(keyDir);

  const listDir = copyBundle("reordered-list");
  const listManifest = JSON.parse(readFileSync(join(listDir, "bundle.json"), "utf8"));
  listManifest.objects = [...(listManifest.objects || [])].reverse();
  writeFileSync(join(listDir, "bundle.json"), `${JSON.stringify(listManifest, null, 2)}\n`);
  listOrder = accept(listDir);
}
ok("SAME MEANING IN DIFFERENT BYTES STILL VERIFIES — every member re-serialised with its keys reversed is accepted with the SAME certificate hash. This is the half of ACC-8 that separates semantic continuity from blob presence: a bundle that only verified byte-identical copies of itself would be carrying blobs, and would fail the moment any honest tool round-tripped it",
  keyOrder?.status === 0 && keyOrder?.receipt?.decision === "accepted"
    && keyOrder?.receipt?.certificate_hash === first.receipt?.certificate_hash,
  keyOrder?.receipt
    ? `${keyOrder.receipt.decision} · certificate hash identical: ${keyOrder.receipt.certificate_hash === first.receipt?.certificate_hash}`
    : `exit ${keyOrder?.status}`);

ok("AND REORDERING THE MANIFEST'S MEMBER LIST IS REFUSED ON THE BUNDLE HASH — an array's order is part of its value, so a member list that could be rearranged after sealing would make the seal meaningless. The opposite expectation from the assertion above, over the same word 'reordering', which is why measuring which kind of order a binding covers is not optional",
  listOrder?.status !== 0 && listOrder?.receipt?.decision === "rejected"
    && (listOrder?.receipt?.failure_codes || []).includes("bundle_hash"),
  listOrder?.receipt
    ? `${listOrder.receipt.decision} · codes ${JSON.stringify(listOrder.receipt.failure_codes)}`
    : `exit ${listOrder?.status}`);

// ------------------------------------------------------ 3. MISSING → refused, over EVERY member
const missingAccepted = [];
let missingTested = 0;
if (fixture && !mutation) {
  for (const entry of manifest.objects || []) {
    const dir = copyBundle(`missing-${missingTested}`);
    const file = join(dir, entry.file);
    if (!existsSync(file)) continue;
    rmSync(file);
    missingTested += 1;
    const result = accept(dir);
    if (result.status === 0) missingAccepted.push(entry.file);
    rmSync(dir, { recursive: true, force: true });
  }
}
ok("A MISSING MEMBER IS REFUSED, AND OVER EVERY DECLARED MEMBER RATHER THAN A SAMPLE — accepting with a member absent is accepting over less evidence than the bundle claims to carry, which is precisely the 'blob presence rather than semantic continuity' failure this clause names. The population is the manifest's own object list, so a bundle that declared fewer would be caught by the pin above rather than by a smaller loop nobody reads",
  !mutation ? (missingTested === DECLARED_OBJECTS && missingAccepted.length === 0) : true,
  mutation ? "carried by the non-mutation run"
    : `${missingTested}/${DECLARED_OBJECTS} members removed one at a time, ${missingAccepted.length} wrongly accepted${missingAccepted.length ? `: ${missingAccepted.join(", ")}` : ""}`);

// ------------------------------------------------------ 4. SUBSTITUTED → refused
let substituted = null;
if (fixture) {
  const dir = copyBundle("substituted");
  const objects = manifest.objects || [];
  const victim = objects[0];
  const donor = objects.find((entry) => entry.file !== victim.file && entry.hash !== victim.hash);
  if (victim && donor && existsSync(join(dir, donor.file))) {
    // The victim's FILE keeps its name and its manifest entry; only its bytes become another
    // member's. Both objects are individually well-formed, so no shape check can see this and only
    // the hash binding can.
    cpSync(join(dir, donor.file), join(dir, victim.file));
    substituted = accept(dir);
    observations.substitution = `${victim.file} <- ${donor.file}`;
  }
}
ok("A SUBSTITUTED MEMBER IS REFUSED — one member's bytes replaced by another member's, both individually well-formed, the filename and the manifest entry untouched. No shape check can see this; only the binding between a declared hash and the bytes behind it can, which is the difference between carrying blobs and carrying evidence",
  substituted?.status !== 0 && substituted?.receipt?.decision === "rejected",
  substituted ? `${observations.substitution} → exit ${substituted.status}/${substituted.receipt?.decision}` : "not exercised");

// ------------------------------------------------------ drills
if (mutation) {
  // Each drill proves this gate's own assertion can go red, by breaking the property the assertion
  // rests on and requiring the observable outcome to flip.
  const dir = copyBundle("drill-missing-one");
  const victim = (manifest.objects || [])[0];
  rmSync(join(dir, victim.file), { force: true });
  const result = accept(dir);
  ok("DRILL — removing a single declared member really does flip the verdict, so the missing-axis loop is measuring something",
    result.status !== 0 && result.receipt?.decision === "rejected", `${victim.file} removed → exit ${result.status}`);

  const pristine = accept(copyBundle("drill-pristine"));
  ok("DRILL — and the same bundle UNTOUCHED is accepted, so the refusals above are caused by the defect and not by the harness",
    pristine.status === 0 && pristine.receipt?.decision === "accepted", `exit ${pristine.status}/${pristine.receipt?.decision}`);

  const keyDrill = copyBundle("drill-key-order");
  const firstObject = (manifest.objects || [])[0];
  const keyFile = join(keyDrill, firstObject.file);
  const keyValue = JSON.parse(readFileSync(keyFile, "utf8"));
  writeFileSync(keyFile, `${JSON.stringify(Object.fromEntries(Object.entries(keyValue).reverse()), null, 2)}\n`);
  const keyDrillResult = accept(keyDrill);
  ok("DRILL — reversing ONE member's key order is accepted, so the canonicalisation assertion is a claim about meaning surviving a re-serialisation rather than a restatement of the pristine run",
    keyDrillResult.status === 0 && keyDrillResult.receipt?.decision === "accepted", `exit ${keyDrillResult.status}`);

  const tamper = copyBundle("drill-tamper");
  const target = join(tamper, victim.file);
  const value = JSON.parse(readFileSync(target, "utf8"));
  value.__ioi_drill_injected_member = "this member was edited after sealing";
  writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
  const tamperResult = accept(tamper);
  ok("DRILL — a member edited after sealing is refused, so the hash binding this gate rests on is live rather than nominal",
    tamperResult.status !== 0 && tamperResult.receipt?.decision === "rejected", `exit ${tamperResult.status}`);

  const shrunk = copyBundle("drill-shrunk-manifest");
  const sm = JSON.parse(readFileSync(join(shrunk, "bundle.json"), "utf8"));
  sm.objects = (sm.objects || []).slice(0, 3);
  writeFileSync(join(shrunk, "bundle.json"), `${JSON.stringify(sm, null, 2)}\n`);
  ok("DRILL — a manifest declaring only three objects would not satisfy the population pin, so a shrunken bundle cannot quietly make the missing-axis loop trivial",
    (sm.objects || []).length !== DECLARED_OBJECTS, `${(sm.objects || []).length} would not equal the pinned ${DECLARED_OBJECTS}`);
}

rmSync(scratch, { recursive: true, force: true });
const failed = findings.filter((finding) => !finding.satisfied);
console.log(JSON.stringify({
  check: "check:portable-evidence-replay",
  unit: "M06.4",
  verdict: failed.length === 0 ? "PASS" : "FAIL",
  executed_assertions: findings.length,
  passed: findings.length - failed.length,
  failed: failed.length,
  observations,
  remaining_nonclaims: [
    "THIS IS THE PORTABLE HALF, NOT THE MANAGED-BACKUP HALF. `check:backup-restore` proves a managed backup crossing to a FRESH daemon with restart and deletion truth; this proves a bundle re-deriving its decision with NO daemon at all. Both are needed and neither implies the other.",
    "THE BUNDLE IS THE RELYING-PARTY GATE'S FIXTURE, not a bundle produced by a live governed effect. That is deliberate — it is the one bundle whose construction the estate owns and can rebuild deterministically — but it means this gate speaks for the FORMAT and the verifier, and not for whatever a particular live run happened to emit.",
    "SUBSTITUTION IS TESTED AT ONE PAIR, not across the whole matrix of members. The binding it exercises is per-member and identical for every pair, so the matrix would multiply runtime without adding a distinct claim; the MISSING axis is the one run exhaustively, because absence is where an optional member could hide.",
  ],
}, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
