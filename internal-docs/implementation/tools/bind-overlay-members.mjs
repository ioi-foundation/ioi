#!/usr/bin/env node
// Derive the durable BINDING layer over the frozen canon overlay manifest.
//
//   node tools/bind-overlay-members.mjs --write    derive, retain, and write
//   node tools/bind-overlay-members.mjs --check    re-derive; byte-for-byte diff
//
// WHY A SECOND FILE AND NOT AN EDIT
//
// program/canon-overlay-manifest.v1.json ENUMERATES the 220 host-local durable
// evidence subjects a canon baseline must bind explicitly. It is correct, and it
// is a FROZEN subject in _archive/manifests/estate-freeze.v1.json: a freeze is
// discharged by a superseding freeze entry, never by editing the frozen body.
// So the missing binding axes are added BESIDE it, not inside it. The
// enumeration stays byte-intact and this file carries, for every member:
//
//   content digest       — re-verified against the bytes on disk
//   provenance           — where the bytes came from and what refs they are absent from
//   owner                — derived from the BOUND GIT TREE, or honestly unattributed
//   classification       — carried forward from the frozen manifest, never re-decided
//   retention/disposition— what happens to these bytes, or that nothing says
//   content address      — cas://sha256/<hex>, with the object actually retained
//
// DEDUPLICATION BY DIGEST IS ALLOWED; OMISSION IS NOT. Two members with the same
// bytes share one content-addressed object. A member with no binding is a defect
// and is reported as one — the 220 are not made to go away by being counted.
//
// WHAT THIS DOES NOT DO
//
// It does not advance a baseline, admit the successor candidate, wire anything
// into canon-impact, reclassify a subject, or grant coverage. Admission is the
// held action; this is the evidence admission would need.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  progress,
  readJson,
  REPO_ROOT,
  sha256File,
  sha256Text,
  writeJsonDeterministic,
} from "./lib/estate.mjs";

const OVERLAY_REL = "program/canon-overlay-manifest.v1.json";
const BINDINGS_REL = "program/canon-overlay-bindings.v1.json";
const CAS_REL = "_archive/evidence/cas";

export const OWNER_ATTRIBUTION_VOCABULARY = {
  tracked_producer:
    "At least one path in the BOUND GIT TREE literally names this evidence programme. That path is the producer of record: it is reproducible from git alone and it is not this evidence citing itself.",
  estate_record:
    "No tracked producer, but a record, ledger, or module in the private estate names the programme. Weaker than a tracked producer — the estate is host-local too — and recorded as such.",
  unattributed:
    "NOTHING in the bound git tree and NOTHING in the estate names this programme. The bytes are retained and addressable, and no accountable owner is derivable from either. This is an OPEN GAP, not a classification: it withholds attribution rather than asserting there is none to find.",
};

export const RETENTION_VOCABULARY = {
  retain_durable_pending_disposition:
    "Retained indefinitely because deleting evidence that certified past work is not reversible, AND because no retention policy, expiry, or disposition decision anywhere in canon or the estate names these bytes. The retention is a default, not a decision, and it is recorded as a default so that it can be decided.",
  retain_until_successor_admitted:
    "Retained until a named successor proof is admitted, at which point the disposition is re-taken.",
  disposition_recorded:
    "An explicit owner disposition exists for these bytes and is cited on the member.",
};

// --- derivation ------------------------------------------------------------

function programmeOf(id) {
  // docs/evidence/<programme>/<...>
  const parts = id.split("/");
  return parts.length >= 3 ? parts[2] : null;
}

// Producer search runs against the BOUND COMMIT, not the working tree: the
// binding must be reproducible from git on another host, and a working-tree
// search would let an uncommitted file attribute an owner.
function trackedProducers(commit, slug) {
  try {
    const out = execFileSync(
      "git",
      ["grep", "-l", "-F", "--", slug, commit, "--", ".", ":!docs/evidence"],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    return out
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => (l.startsWith(`${commit}:`) ? l.slice(commit.length + 1) : l))
      .sort();
  } catch {
    // git grep exits 1 when it matches nothing. No match is a real answer.
    return [];
  }
}

// SELF-ATTRIBUTION IS NOT ATTRIBUTION.
//
// Several estate files name every one of these programmes BY CONSTRUCTION: the
// overlay enumeration, this bindings layer, the successor baseline candidate
// (which lists all 990 subject ids), and the derived projections. Letting any
// of them count as an owner would attribute all 220 members to the very census
// that is asking who owns them — a census that answers its own question is a
// tautology, and the first draft of this tool produced exactly that: 194 of 220
// "owned" by the candidate baseline. Each exclusion is named with its reason so
// the list cannot quietly grow into a way of manufacturing attribution.
export const SELF_ENUMERATION_EXCLUSIONS = [
  {
    path: OVERLAY_REL,
    why: "The enumeration itself. It names every member because that is what it is.",
  },
  {
    path: BINDINGS_REL,
    why: "This file.",
  },
  {
    path: "program/canon-baseline-successor.candidate.v1.json",
    why:
      "A baseline candidate listing all 990 subject ids, of which these 220 are the overlay. It names them as subjects, not as an owner of the work they are evidence for.",
  },
  {
    path: "generated/",
    why:
      "Derived projections (canon-baseline, canon-impact). A projection of the subject set is not an owner of the subject.",
  },
  {
    path: "program/skip-taxonomy.v1.json",
    why:
      "Classifies the SKIPs these subjects emit. Classifying a withheld verification is not owning the evidence.",
  },
  {
    path: "program/canon-overlay-dispositions.v1.json",
    why:
      "The disposition ledger. It carries one entry per member because that is what it is, so counting it would answer THIS file's question with THAT file's output: 'is there a producer of record in the bound tree' would silently become 'has someone accepted custody', and all 220 would read as attributed the moment custody was recorded. The two questions are kept apart deliberately — the honest UNATTRIBUTED here is what the disposition layer exists beside, not something it is allowed to overwrite.",
  },
  {
    path: "program/canon-overlay-producer-evidence.v1.json",
    why:
      "The git-history input the disposition ledger is derived from. It names every member by construction, for the same reason and with the same consequence.",
  },
];

function isSelfEnumeration(rel) {
  return SELF_ENUMERATION_EXCLUSIONS.some((e) =>
    e.path.endsWith("/") ? rel.startsWith(e.path) : rel === e.path
  );
}

function estateReferences(slug) {
  const hits = [];
  const roots = ["work-items", "stages", "modules", "program", "evidence"];
  for (const root of roots) {
    const start = path.join(ESTATE_ROOT, root);
    if (!fs.existsSync(start)) continue;
    const stack = [start];
    while (stack.length > 0) {
      const dir = stack.pop();
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          stack.push(abs);
          continue;
        }
        if (!entry.isFile()) continue;
        if (!/\.(json|md|txt|log)$/u.test(entry.name)) continue;
        let text;
        try {
          text = fs.readFileSync(abs, "utf8");
        } catch {
          continue;
        }
        if (text.includes(slug)) {
          hits.push(path.relative(ESTATE_ROOT, abs));
        }
      }
    }
  }
  return hits.sort();
}

export function bindMember({ member, statSha256, programmeOwners }) {
  const programme = programmeOf(member.id);
  const owner = programmeOwners.get(programme) ?? {
    attribution: "unattributed",
    tracked_producers: [],
    estate_references: [],
  };
  return {
    id: member.id,
    sha256: member.sha256,
    byte_count: member.byte_count,
    // Carried forward, never re-decided here. Re-deciding a classification in a
    // binding layer would be a reclassification wearing a binding's clothes.
    classification: member.classification,
    classification_source: OVERLAY_REL,
    content_address: `cas://sha256/${member.sha256}`,
    digest_reverified: statSha256 === member.sha256,
    provenance: {
      evidence_programme: programme,
      in_bound_git_tree: member.in_bound_git_tree === true,
      on_origin_master: member.on_origin_master === true,
      present_on_any_ref: member.present_on_any_ref === true,
      derivation:
        "Enumerated by program/canon-overlay-manifest.v1.json at freeze; digest re-verified against the bytes on disk at binding time; ref-absence carried from the manifest's full object walk (git rev-list --all --objects -- docs/).",
    },
    owner: {
      attribution: owner.attribution,
      tracked_producers: owner.tracked_producers,
      estate_references: owner.estate_references,
      derivation:
        "git grep -l -F <evidence programme slug> <bound commit> -- . ':!docs/evidence', then a literal scan of the estate's records, stages, modules, program files, and evidence. Reproducible; never inferred from the evidence naming itself.",
    },
    retention: {
      class: "retain_durable_pending_disposition",
      expiry: null,
      disposition: null,
      why:
        "No retention policy, expiry, or disposition decision in canon or the estate names these bytes. The retention below is the default that follows from retaining evidence at all; it is not an owner decision and must not be read as one.",
    },
  };
}

// --- assembly --------------------------------------------------------------

export function bindingsDigest(doc) {
  const body = { ...doc };
  delete body.bindings_sha256;
  return sha256Text(JSON.stringify(body, null, 2));
}

function build({ retain }) {
  const manifest = readJson(path.join(ESTATE_ROOT, OVERLAY_REL));
  const commit = manifest.bound_git_tree.commit;
  const members = manifest.members ?? [];

  const programmes = [...new Set(members.map((m) => programmeOf(m.id)))].sort();
  const programmeOwners = new Map();
  for (const programme of programmes) {
    const tracked = trackedProducers(commit, programme);
    const estate = estateReferences(programme).filter(
      (rel) => !isSelfEnumeration(rel),
    );
    programmeOwners.set(programme, {
      attribution: tracked.length > 0
        ? "tracked_producer"
        : estate.length > 0
        ? "estate_record"
        : "unattributed",
      tracked_producers: tracked,
      estate_references: estate,
    });
  }

  const casRoot = path.join(ESTATE_ROOT, CAS_REL);
  if (retain) fs.mkdirSync(casRoot, { recursive: true });

  const bindings = [];
  const retained = new Set();
  const defects = [];
  for (const member of members) {
    const abs = path.join(REPO_ROOT, member.id);
    const present = fs.existsSync(abs);
    const statSha256 = present ? sha256File(abs) : null;
    if (!present) {
      defects.push(`${member.id}: absent from disk; cannot be retained`);
    } else if (statSha256 !== member.sha256) {
      defects.push(`${member.id}: bytes moved since the freeze`);
    } else if (retain && !retained.has(member.sha256)) {
      // Deduplication by digest: one object per distinct body. Written once and
      // never rewritten — a content-addressed object whose bytes change is a
      // contradiction, not an update.
      const target = path.join(casRoot, member.sha256);
      if (!fs.existsSync(target)) fs.copyFileSync(abs, target);
      retained.add(member.sha256);
    }
    bindings.push(bindMember({ member, statSha256, programmeOwners }));
  }

  const attribution = { tracked_producer: 0, estate_record: 0, unattributed: 0 };
  for (const b of bindings) attribution[b.owner.attribution] += 1;

  const doc = {
    evidence_format: "ioi.program.canon_overlay_bindings.v1",
    role:
      "The durable BINDING layer over program/canon-overlay-manifest.v1.json. The manifest says WHICH host-local bytes a baseline must bind; this file says, for each one, what its content address is, where it came from, who owns it, how long it is kept, and on whose authority — so that binding a subject is a record rather than a listing.",
    generated_by:
      "node internal-docs/implementation/tools/bind-overlay-members.mjs --write",
    derived_not_authored:
      "Every field is derived. Re-running --check re-derives and diffs byte-for-byte; a hand edit fails closed.",
    binds_manifest: {
      path: OVERLAY_REL,
      manifest_sha256: manifest.manifest_sha256,
      member_count: manifest.member_count,
      frozen_by: "_archive/manifests/estate-freeze.v1.json",
      never_edited:
        "The manifest is a frozen subject. This layer is additive: it adds axes beside the enumeration and changes not one byte of it.",
    },
    bound_git_tree: manifest.bound_git_tree,
    owner_attribution_vocabulary: OWNER_ATTRIBUTION_VOCABULARY,
    self_enumeration_exclusions: SELF_ENUMERATION_EXCLUSIONS,
    retention_vocabulary: RETENTION_VOCABULARY,
    content_address_store: {
      root: CAS_REL,
      reference_form: "cas://sha256/<hex>",
      deduplication:
        "By digest. Distinct members with identical bytes share one object. Deduplication is permitted; OMISSION IS NOT — every member carries a content address and every distinct digest is retained.",
      write_once:
        "An object is written once and never rewritten. A body that must change becomes a new address, and the superseding relationship is recorded by the referrer.",
    },
    counts: {
      members: bindings.length,
      distinct_digests: new Set(bindings.map((b) => b.sha256)).size,
      owner_attribution: attribution,
      retention_classes: { retain_durable_pending_disposition: bindings.length },
    },
    open_gap: {
      what: "owner attribution is incomplete",
      unattributed_members: attribution.unattributed,
      unattributed_programmes: programmes
        .filter((p) => programmeOwners.get(p).attribution === "unattributed")
        .sort(),
      why:
        "For these evidence programmes, nothing in the bound git tree and nothing in the private estate names the programme. The bytes are enumerated, digest-verified, content-addressed and retained; the accountable owner is not derivable. Recording the gap is the point — an unattributed member must read as unattributed, not be quietly assigned to whatever record happens to be nearby.",
      closes_when:
        "An owner names, per programme, the record or contract that these bytes are evidence FOR. That is an owner ruling and is not derivable by this tool.",
    },
    nonclaim:
      "Binding a member asserts that these exact bytes were enumerated, re-digested, addressed, and retained, and records what is known about their origin and ownership. It asserts nothing about whether the evidence is correct, current, sufficient, or still needed, grants no coverage to any canon subject, and advances no baseline.",
    bindings,
  };
  doc.bindings_sha256 = bindingsDigest(doc);
  return { doc, defects, retainedObjects: retained.size };
}

function main() {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check");
  if (!write && !check) {
    progress("usage: bind-overlay-members.mjs --write | --check");
    process.exit(2);
  }
  const { doc, defects, retainedObjects } = build({ retain: write });
  const abs = path.join(ESTATE_ROOT, BINDINGS_REL);

  if (write) {
    writeJsonDeterministic(abs, doc);
    progress(
      `bound ${doc.counts.members} overlay member(s); ${doc.counts.distinct_digests} distinct digest(s); ${retainedObjects} content-addressed object(s) retained this run; ${doc.counts.owner_attribution.unattributed} member(s) UNATTRIBUTED`,
    );
    for (const d of defects) progress(`  defect: ${d}`);
    process.exit(defects.length === 0 ? 0 : 1);
  }

  if (!fs.existsSync(abs)) {
    progress(`${BINDINGS_REL} is missing; run --write`);
    process.exit(1);
  }
  const onDisk = fs.readFileSync(abs, "utf8");
  const fresh = `${JSON.stringify(doc, null, 2)}\n`;
  const same = onDisk === fresh;
  progress(
    same
      ? `${BINDINGS_REL} reproduces byte-for-byte (${doc.counts.members} members)`
      : `${BINDINGS_REL} does NOT reproduce from a fresh derivation`,
  );
  process.exit(same && defects.length === 0 ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
