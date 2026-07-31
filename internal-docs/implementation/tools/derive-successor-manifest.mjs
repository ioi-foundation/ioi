#!/usr/bin/env node
// Derive the CANDIDATE SUCCESSOR to the frozen canon-overlay manifest.
//
//   node tools/derive-successor-manifest.mjs --write --out <path outside the estate>
//   node tools/derive-successor-manifest.mjs --check
//
// WHY A SUCCESSOR AND NOT AN APPEND
//
// The v1 manifest froze with `retired_members: []`. That list is not a defect
// and not an omission: it TRUTHFULLY RECORDS THE STATE FROZEN AT THAT DIGEST.
// Nothing was retired when it was frozen, so nothing belonged in it, and the
// two retirements decided afterwards do not rewrite what was true then.
//
// The rule this file replaces said the opposite — that retiring an overlay
// member requires "an explicit tombstone appended to the manifest's
// retired_members". That instruction contradicts the freeze that binds the same
// bytes: it directs an edit to a frozen body, and a freeze discharged by editing
// the thing it froze is not a freeze. The two rules could not both be followed.
//
// THE MODEL, STATED ONCE:
//
//   Retirement is recorded in the disposition/tombstone ledger and carried into
//   the next immutable manifest version. A frozen manifest is never edited.
//
// So retirement lives in program/canon-overlay-dispositions.v1.json, where it is
// derived, checked and tombstoned; and this file carries those decisions into a
// NEW immutable version that binds its predecessor by digest. v1 keeps saying
// what was true at v1. v2 says what is true at v2. Neither is edited to agree
// with the other, and the relationship between them is explicit rather than
// implied by a shared filename.
//
// WHAT THIS IS NOT
//
// It is a CANDIDATE. It is consumed by no tool, it admits no baseline, it
// discharges no hold, and admitting it is a baseline advance held by
// _archive/holds/certification-hold.v1.json. Generating it changes nothing about
// what canon currently binds.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  progress,
  readJson,
  sha256Text,
  writeJsonDeterministic,
} from "./lib/estate.mjs";

const OVERLAY_REL = "program/canon-overlay-manifest.v1.json";
const LEDGER_REL = "program/canon-overlay-dispositions.v1.json";
const SUCCESSOR_REL = "program/canon-overlay-manifest.successor.candidate.v2.json";
const CAS_REL = "_archive/evidence/cas";
const HOLD_REL = "_archive/holds/certification-hold.v1.json";

export const RETIREMENT_MODEL =
  "Retirement is recorded in the disposition/tombstone ledger and carried into the next immutable manifest version. A frozen manifest is never edited.";

// The superseded instruction, quoted so the correction can name what it
// corrects. It has exactly one permitted home in the emitted document and
// tools/check-successor-manifest.mjs scans every other byte for it.
export const SUPERSEDED_RETIREMENT_RULE = "appended to the manifest's retired_members";

export function selfDigest(doc, key) {
  const body = { ...doc };
  delete body[key];
  return sha256Text(JSON.stringify(body, null, 2));
}

function sha256Of(abs) {
  return sha256Text(fs.readFileSync(abs, "utf8"));
}

export function buildSuccessor({ manifest, manifestFileSha256, ledger, casHas }) {
  const retiredEntries = (ledger.entries ?? []).filter((e) => e.disposition === "retired");
  const retiredById = new Map(retiredEntries.map((e) => [e.id, e]));

  // EVERY identity is carried, at the digest v1 recorded. A successor that drops
  // an identity has removed a subject with no act; a successor that carries one
  // at a new digest has re-bound different bytes to an old name. Both are the
  // failures this enumeration exists to make impossible, so the digest is copied
  // from v1 and never recomputed from disk.
  const identities = (manifest.members ?? []).map((m) => {
    const retired = retiredById.get(m.id) ?? null;
    return {
      id: m.id,
      sha256: m.sha256,
      byte_count: m.byte_count,
      kind: m.kind,
      rule: m.rule,
      classification: m.classification,
      predecessor_sha256: m.sha256,
      lifecycle: retired ? "retired" : "active",
      ...(retired ? { retirement_ref: retired.id } : {}),
    };
  });

  const retiredMembers = retiredEntries
    .map((e) => {
      const member = (manifest.members ?? []).find((m) => m.id === e.id) ?? null;
      return {
        id: e.id,
        sha256: e.sha256,
        predecessor_sha256: member?.sha256 ?? null,
        recorded_in: `internal-docs/implementation/${LEDGER_REL}`,
        decision_source: e.decision_source ?? null,
        family_rule: e.family_rule ?? null,
        tombstone: e.tombstone ?? null,
        inbound_reference_proof: e.inbound_reference_proof ?? null,
        successor: e.successor ?? null,
        rationale: e.rationale ?? null,
        custodian: e.custodian ?? null,
        retained_bytes: {
          address: `cas://sha256/${e.sha256}`,
          retained: casHas(e.sha256),
          rule:
            "Retirement disposes of an IDENTITY, never of evidence. The bytes stay on disk at their frozen digest and stay content-addressed under _archive/evidence/cas/. A retirement whose bytes disappeared is a deletion wearing a tombstone.",
        },
      };
    })
    .sort((a, b) => (a.id < b.id ? -1 : 1));

  const doc = {
    evidence_format: "ioi.program.canon_overlay_manifest.v2",
    role:
      "The CANDIDATE successor to the frozen v1 canon-overlay manifest. It carries every identity v1 enumerated, at v1's own digests, and records which of them a tombstone has retired. It succeeds v1 by binding it; it never edits it.",
    state: "candidate_not_admitted",
    consumed_by_no_tool: true,
    admission_blocked_by:
      `${HOLD_REL} held action \`canon-impact --accept (no further baseline advancement)\`. Binding this successor into a canon baseline IS a baseline advance and is therefore held. Until then it is a proposal about what the next immutable version would say.`,
    generated_by:
      "node internal-docs/implementation/tools/derive-successor-manifest.mjs --write --out <path outside the estate>",
    derived_not_authored:
      "Every identity, digest, count and tombstone is copied from the frozen v1 manifest and the derived disposition ledger. Re-running --check re-derives and diffs byte-for-byte; a hand edit fails closed.",
    checked_by: "internal-docs/implementation/tools/check-successor-manifest.mjs",
    self_digest_rule:
      "manifest_sha256 = sha256 of JSON.stringify(this object with the manifest_sha256 key removed, null, 2), with no trailing newline. Recomputed on every check; a hand edit fails closed.",
    retirement_model: RETIREMENT_MODEL,
    // The ONE field permitted to contain the superseded phrasing, and it must
    // contain exactly that phrasing. A correction that may not quote what it
    // corrects is unreadable; a document that may quote it anywhere can
    // reintroduce it as governing text and call the reintroduction a citation.
    // So the quotation gets one named home and every other byte is scanned.
    superseded_instruction_verbatim: SUPERSEDED_RETIREMENT_RULE,
    superseded_instruction_status:
      "SUPERSEDED. Quoted here so the correction names what it corrects, and quoted ONLY here: tools/check-successor-manifest.mjs scans every other byte of this document for the same phrase and fails closed if it reappears.",
    why_the_predecessor_is_not_edited:
      "v1's `retired_members: []` TRUTHFULLY RECORDS THE STATE FROZEN AT THAT DIGEST. Nothing was retired when it froze, so nothing belonged in that list, and later retirement decisions do not rewrite history. Writing into that list would make a frozen body say something it did not say at its digest and would make the freeze that binds it a formality. The superseded instruction is quoted verbatim in superseded_instruction_verbatim above and is replaced by retirement_model wherever it appeared.",
    succession: {
      version: 2,
      relationship: "immutable_version_succession",
      predecessor: {
        path: `internal-docs/implementation/${OVERLAY_REL}`,
        version: 1,
        manifest_sha256: manifest.manifest_sha256,
        file_sha256: manifestFileSha256,
        frozen_on: manifest.frozen_on,
        frozen_at_commit: manifest.frozen_at_commit,
        member_count: manifest.member_count,
        retired_members_at_freeze: (manifest.retired_members ?? []).length,
        retired_members_at_freeze_is_true:
          "Zero, and correctly zero. It is the state at that digest, not an omission to be repaired.",
        never_edited:
          "Not one byte of the predecessor is changed by this successor existing. If v1's bytes move, this successor's predecessor binding stops resolving and the bar fails closed.",
      },
      successor: {
        path: `internal-docs/implementation/${SUCCESSOR_REL}`,
        version: 2,
        supersedes_on_admission:
          "Nothing yet. v1 remains the manifest a baseline binds until this candidate is admitted, and admission is held.",
      },
      what_changes_between_versions:
        "The lifecycle of two identities, from active to retired, and nothing else. No identity is added, none is removed, and no digest moves.",
      what_never_changes:
        "The identity set and every identity's digest. A version succession that quietly drops or re-digests a subject is a rewrite calling itself a version.",
    },
    bound_git_tree: manifest.bound_git_tree,
    member_classification_vocabulary: manifest.member_classification_vocabulary,
    lifecycle_vocabulary: {
      active:
        "The identity is carried forward and nothing has retired it. This is the default and it is never inferred from a member's absence.",
      retired:
        "A tombstone in the disposition ledger retired this IDENTITY, an inbound-reference proof showed nothing cited it, and the BYTES remain on disk and content-addressed. Retirement is of a name, never of evidence.",
    },
    absence_rule:
      "MISSING IGNORED BYTES ARE NOT DELETIONS. An identity absent from disk is reported as overlay_member_absent and never as a canon removal: it advances no baseline, retires no identity, and closes nothing. Retirement is recorded in the disposition/tombstone ledger and carried into the next immutable manifest version; a frozen manifest is never edited.",
    identity_preservation:
      "All 220 identities v1 enumerated are carried here at v1's own digests, retired ones included. A retired identity is NOT dropped from the enumeration: dropping it would make the retirement indistinguishable from a subject that was never there, which is the exact reading the absence rule refuses.",
    resurrection_rule:
      "A retired identity may return to `active` ONLY through an explicit, recorded act naming a ruling reference and a reason, listed in `resurrections` below. A retired identity that reappears as active with no such act is a SILENT RESURRECTION and fails closed: the tombstone would have been undone by nobody.",
    resurrections: [],
    tombstone_source: {
      path: `internal-docs/implementation/${LEDGER_REL}`,
      dispositions_sha256: ledger.dispositions_sha256,
      retired_entry_count: retiredEntries.length,
      role:
        "The ledger is where a retirement is DECIDED and tombstoned. This manifest is where the decision is CARRIED. The two must agree exactly; disagreement means one of them has been edited independently of the other.",
    },
    counts: {
      identities: identities.length,
      active: identities.filter((i) => i.lifecycle === "active").length,
      retired: identities.filter((i) => i.lifecycle === "retired").length,
    },
    nonclaim:
      "Carrying an identity asserts that v1 bound these bytes at this digest and that a tombstone did or did not retire the name. It makes no claim that the evidence is correct, current, or sufficient, grants no coverage to any canon subject, admits no baseline, and discharges no hold.",
    retired_member_count: retiredMembers.length,
    retired_members: retiredMembers,
    identity_count: identities.length,
    identities,
  };
  doc.manifest_sha256 = selfDigest(doc, "manifest_sha256");
  return doc;
}

function build() {
  const manifestAbs = path.join(ESTATE_ROOT, OVERLAY_REL);
  const casRoot = path.join(ESTATE_ROOT, CAS_REL);
  return buildSuccessor({
    manifest: readJson(manifestAbs),
    manifestFileSha256: sha256Of(manifestAbs),
    ledger: readJson(path.join(ESTATE_ROOT, LEDGER_REL)),
    casHas: (digest) => fs.existsSync(path.join(casRoot, digest)),
  });
}

function argValue(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? null : (process.argv[i + 1] ?? null);
}

function main() {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check");
  const out = argValue("out");
  if (!write && !check) {
    progress("usage: derive-successor-manifest.mjs --write --out <path outside the estate> | --check");
    process.exit(2);
  }

  const doc = build();

  if (write) {
    if (!out) {
      progress(
        "REFUSED: --out is required. A candidate successor to a frozen manifest enters the estate through a recorded promotion, never through a tool writing it in place.",
      );
      process.exit(1);
    }
    const resolved = path.resolve(out);
    if (resolved === ESTATE_ROOT || resolved.startsWith(`${ESTATE_ROOT}${path.sep}`)) {
      progress(`REFUSED: --out ${resolved} is INSIDE the canonical estate.`);
      process.exit(1);
    }
    writeJsonDeterministic(resolved, doc);
    progress(
      `wrote ${resolved}: ${doc.counts.identities} identities (${doc.counts.active} active, ${doc.counts.retired} retired); predecessor ${doc.succession.predecessor.manifest_sha256}; self ${doc.manifest_sha256}`,
    );
    progress(
      "  STAGED, NOT PROMOTED, NOT ADMITTED. It has no authority until a promotion event records it, and admission remains held.",
    );
    process.exit(0);
  }

  const abs = path.join(ESTATE_ROOT, SUCCESSOR_REL);
  if (!fs.existsSync(abs)) {
    progress(`${SUCCESSOR_REL} is missing; run --write --out <staging path> and promote it`);
    process.exit(1);
  }
  const same = fs.readFileSync(abs, "utf8") === `${JSON.stringify(doc, null, 2)}\n`;
  progress(
    same
      ? `${SUCCESSOR_REL} reproduces byte-for-byte (${doc.counts.identities} identities, ${doc.counts.retired} retired)`
      : `${SUCCESSOR_REL} does NOT reproduce from a fresh derivation`,
  );
  process.exit(same ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
