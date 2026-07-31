#!/usr/bin/env node
// Deterministic architecture-impact and orphan detection.
//
//   node tools/canon-impact.mjs            report against the recorded baseline
//   node tools/canon-impact.mjs --check    exit 1 on unexplained orphans or
//                                          unreviewed canon change
//   node tools/canon-impact.mjs --write    regenerate generated/canon-impact.v1.json
//   node tools/canon-impact.mjs --emit-review-manifest <path>
//                                          write a manifest skeleton naming exactly
//                                          the pending drift set, for a reviewer to fill
//   node tools/canon-impact.mjs --accept --review-manifest <path> --reviewer-ref <ref>
//                                          advance generated/canon-baseline.v1.json
//                                          against a reviewed, content-bound manifest
//   --root <dir>                           operate over a fixture repo (tests)
//   --estate <dir>                         operate over a fixture estate (tests)
//   --json                                 machine-readable output
//
// Design contract:
//   * The subject universe comes from the FILESYSTEM, never from an index file.
//   * Obligations are DATA in program/canon-map.v1.json, never a constant in this
//     file. There is no EXPECTED_OBLIGATION_COUNT here, by design.
//   * A subject with no map entry is an ORPHAN and fails closed.
//   * A changed subject digest yields a BOUNDED impact report naming exactly the
//     stages, modules, and work items that must be re-reviewed.
//   * Historical evidence under _archive/ is never invalidated by canon change.
//   * A dated migration record never blocks a later authorised transition: the
//     baseline advances by explicit --accept, and --accept records provenance
//     rather than rewriting any retained evidence.
//
// --accept CONTRACT (hardened 2026-07-29 after a review-accountability failure).
//
// The old --accept took no arguments. It rewrote the whole baseline to whatever
// the tree currently said, which made "make the bar green" indistinguishable
// from "the drift was reviewed" — and, on 2026-07-29, the two were in fact
// confused: 92 work-item canon_snapshots were mechanically restamped and the
// baseline was advanced with no review artifact of any kind. See
// _archive/attestations/canon-review-ledger.v1.md.
//
// --accept can no longer assert review by itself. It now requires ALL of:
//
//   1. --review-manifest <path>. A content-bound manifest of
//      evidence_format "ioi.program.canon_review_manifest.v1" that ENUMERATES
//      every pending subject by id with the baseline digest it is leaving and
//      the tree digest it is moving to. Accepting drift you did not enumerate
//      is therefore impossible: the manifest subject set must equal the pending
//      drift set EXACTLY. An extra subject refuses (manifest-extra-subject); a
//      missing subject refuses (manifest-missing-subject).
//   2. --reviewer-ref <ref>. An accountable reviewer identity. If the manifest
//      also carries reviewer_ref the two must agree. Placeholders refuse.
//   3. A per-subject disposition in the fixed vocabulary
//      (unaffected | successor_required | blocked) and a non-empty review_note.
//      A subject nobody wrote a sentence about has not been reviewed.
//   4. Digests that still match the tree. A manifest whose recorded tree digest
//      no longer matches the file it names is STALE and refuses
//      (manifest-stale-digest) — you reviewed a revision that no longer exists.
//   5. Something actually pending. --accept with an empty drift set refuses
//      rather than re-stamping a baseline that already agrees with the tree.
//
// Report mode needs no manifest and never writes: plain invocation and --check
// are read-only and unchanged. --write regenerates the impact PROJECTION only;
// it no longer touches the baseline, because a projection refresh is not review.
//
// Every acceptance appends one entry to
// _archive/attestations/canon-acceptances.v1.json — append-only, dense
// sequence, digest-bound, claim "canon_drift_reviewed_only" — in the same house
// style as _archive/attestations/record-reattestations.v1.json. The ledger
// records that drift was reviewed. It never claims implementation proof, and
// like every other projection here it changes no status.
//
// MANIFEST RETENTION (added 2026-07-29). --accept used to record the manifest's
// PATH, and the first two acceptances recorded `/tmp/...`. A digest bound to a
// body nobody can produce is not evidence. The reviewed body is now copied,
// before the ledger cites it, to
// _archive/attestations/review-manifests/<sha256>.json, and the entry records
// that CONTENT ADDRESS. The volatile path is kept only as
// review_manifest_path_at_acceptance, explicitly marked non-authoritative.
// tools/check-acceptance-integrity.mjs enforces the resolution.
//
// A `successor_required` disposition is not self-executing either: it owes an
// open hold in _archive/holds/open-successor-holds.v1.json, and --accept says
// so on the way out. See tools/check-open-successor-holds.mjs.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  finding,
  readJson,
  REPO_ROOT,
  report,
  sha256Text,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import {
  discoverCanonSubjects,
  mappableSubjects,
  readAdrStatus,
} from "./lib/canon-universe.mjs";

const CLASSIFICATIONS = new Set([
  "actively_sequenced",
  "planned",
  "future_gated",
  "non_build_doctrine",
  "conformance_only",
  "unresolved_canon_gap",
  "missing_implementation_coverage",
]);

// Classifications that must name at least one owning stage and one work item.
const REQUIRES_OWNERSHIP = new Set([
  "actively_sequenced",
  "planned",
  "future_gated",
]);

// Distinguishes a canon subject that CHANGED from one that is merely absent
// because this checkout is behind or ahead of origin/master. A refactor must
// never report branch provenance as a content defect, and must never let branch
// divergence pass as verified coverage — so both cases are reported, one as an
// error and one as an explicit SKIP.
let masterTreeCache = null;
function masterTree(repoRoot) {
  if (masterTreeCache) return masterTreeCache;
  try {
    masterTreeCache = new Set(
      execFileSync("git", ["ls-tree", "-r", "--name-only", "origin/master", "docs/"], {
        cwd: repoRoot,
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
      }).split("\n").filter(Boolean),
    );
  } catch {
    masterTreeCache = new Set();
  }
  return masterTreeCache;
}

function onMaster(repoRoot, rel) {
  return masterTree(repoRoot).has(rel);
}

// The frozen overlay manifest is read for MESSAGE ACCURACY while the successor
// baseline is unadmitted. It never grants coverage by itself. After the atomic
// release admits a successor baseline, a separate exact binding below may
// classify a subject as durable overlay evidence rather than architecture
// canon, but only when the admitted baseline, admitted manifest, and complete
// disposition ledger all agree on its identity and digest.
let overlayCache = null;
function overlayManifestMembers(estateRoot) {
  if (overlayCache) return overlayCache;
  overlayCache = new Map();
  const abs = path.join(estateRoot, "program", "canon-overlay-manifest.v1.json");
  if (!fs.existsSync(abs)) return overlayCache;
  try {
    for (const member of readJson(abs).members ?? []) {
      overlayCache.set(member.id, member.classification ?? null);
    }
  } catch {
    // A malformed manifest is the canonical-estate bar's finding, not this one's.
  }
  return overlayCache;
}

const OVERLAY_DISPOSITIONS = new Set([
  "assigned_existing_owner",
  "assigned_new_successor",
  "retained_nonclaim_evidence",
  "retired",
]);

export function admittedOverlayCoverage(estateRoot) {
  const covered = new Map();
  const baselineAbs = path.join(estateRoot, "program", "canon-baseline-successor.v1.json");
  const dispositionsAbs = path.join(estateRoot, "program", "canon-overlay-dispositions.v1.json");
  if (!fs.existsSync(baselineAbs) || !fs.existsSync(dispositionsAbs)) return covered;
  try {
    const baseline = readJson(baselineAbs);
    if (baseline.state !== "admitted" || baseline.consumed_by_no_tool !== false) return covered;
    const manifestRel = baseline.overlay?.manifest;
    if (typeof manifestRel !== "string" || manifestRel.includes("..")) return covered;
    const manifestAbs = path.join(estateRoot, manifestRel);
    if (!fs.existsSync(manifestAbs)) return covered;
    const manifest = readJson(manifestAbs);
    if (
      manifest.state !== "admitted" ||
      manifest.consumed_by_no_tool !== false ||
      baseline.overlay?.manifest_sha256 !== manifest.manifest_sha256
    ) return covered;
    const dispositions = readJson(dispositionsAbs);
    if (dispositions.counts?.by_disposition?.unattributed !== 0) return covered;
    const byDisposition = new Map((dispositions.entries ?? []).map((entry) => [entry.id, entry]));
    for (const identity of manifest.identities ?? []) {
      const disposition = byDisposition.get(identity.id);
      if (
        identity.classification === "host_local_durable_evidence" &&
        typeof identity.sha256 === "string" &&
        disposition?.sha256 === identity.sha256 &&
        OVERLAY_DISPOSITIONS.has(disposition.disposition)
      ) {
        covered.set(identity.id, {
          sha256: identity.sha256,
          lifecycle: identity.lifecycle,
          disposition: disposition.disposition,
        });
      }
    }
  } catch {
    // Malformed admission artifacts fail in their owning bars. They grant no
    // coverage here, so the ordinary orphan finding remains visible.
  }
  return covered;
}

function headCommit(repoRoot) {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
    }).trim();
  } catch {
    return "unknown";
  }
}

// The only dispositions a reviewer may record. Deliberately identical to the
// vocabulary of _archive/attestations/canon-review-ledger.v1.json, so a
// disposition written here means the same thing it means there.
const REVIEW_DISPOSITIONS = new Set([
  "unaffected",
  "successor_required",
  "blocked",
]);

const MANIFEST_FORMAT = "ioi.program.canon_review_manifest.v1";
const REVIEW_CLAIM = "canon_drift_reviewed_only";
const ACCEPTANCE_LEDGER_REL = ["_archive", "attestations", "canon-acceptances.v1.json"];
const REVIEW_MANIFEST_DIR_REL = ["_archive", "attestations", "review-manifests"];

// A reviewer_ref has to name somebody. These are the strings people type when
// they are not naming anybody.
const PLACEHOLDER = /^(todo|tbd|xxx+|n\/?a|none|unknown|reviewer|me|replace[-_ ]?me|\?+)$/iu;

function parseArgs(argv) {
  const out = {
    check: false,
    write: false,
    accept: false,
    json: false,
    root: null,
    estate: null,
    reviewManifest: null,
    reviewerRef: null,
    emitReviewManifest: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--check") out.check = true;
    else if (a === "--write") out.write = true;
    else if (a === "--accept") out.accept = true;
    else if (a === "--json") out.json = true;
    else if (a === "--root") out.root = argv[++i];
    else if (a === "--estate") out.estate = argv[++i];
    else if (a === "--review-manifest") out.reviewManifest = argv[++i];
    else if (a === "--reviewer-ref") out.reviewerRef = argv[++i];
    else if (a === "--emit-review-manifest") out.emitReviewManifest = argv[++i];
  }
  return out;
}

// The exact set of baseline entries an --accept would rewrite. This is the
// subject set a reviewer must enumerate, and nothing else is acceptable:
// a baseline advance that touches an entry the manifest never named is
// precisely the failure this contract exists to stop.
export function pendingDrift(result) {
  const baseline = result.baseline?.subjects ?? {};
  const onDisk = new Map(result.subjects.map((s) => [s.id, s.sha256]));
  const pending = [];

  for (const [id, sha256] of onDisk) {
    const previous = baseline[id];
    if (previous === undefined) {
      pending.push({ id, change: "added", baseline_sha256: null, tree_sha256: sha256 });
    } else if (previous !== sha256) {
      pending.push({ id, change: "changed", baseline_sha256: previous, tree_sha256: sha256 });
    }
  }
  for (const id of Object.keys(baseline)) {
    if (!onDisk.has(id)) {
      pending.push({
        id,
        change: "removed",
        baseline_sha256: baseline[id],
        tree_sha256: null,
      });
    }
  }
  return pending.sort((a, b) => a.id.localeCompare(b.id));
}

// Refuses on every axis independently, and reports them all, so a reviewer
// fixing one problem is not made to discover the next one run by run.
function validateReviewManifest({ manifestPath, reviewerRef, pending, estateRoot }) {
  const findings = [];
  const refuse = (check, message, extra = {}) =>
    findings.push(finding("error", check, message, extra));

  if (!manifestPath) {
    refuse(
      "accept-no-manifest",
      "--accept requires --review-manifest <path>. A baseline advance is not a review: name every pending canon subject, its digests, and what you decided about it. Start from `--emit-review-manifest <path>`.",
    );
    return { findings, manifest: null, digest: null };
  }

  const absolute = path.isAbsolute(manifestPath)
    ? manifestPath
    : path.resolve(process.cwd(), manifestPath);
  if (!fs.existsSync(absolute)) {
    refuse("manifest-missing", `review manifest does not exist: ${manifestPath}`);
    return { findings, manifest: null, digest: null };
  }

  let manifest;
  try {
    manifest = readJson(absolute);
  } catch {
    refuse("manifest-unreadable", `review manifest is not valid JSON: ${manifestPath}`);
    return { findings, manifest: null, digest: null };
  }
  const digest = sha256Text(fs.readFileSync(absolute, "utf8"));

  if (manifest.evidence_format !== MANIFEST_FORMAT) {
    refuse(
      "manifest-format",
      `review manifest declares evidence_format "${manifest.evidence_format}"; expected "${MANIFEST_FORMAT}"`,
    );
  }
  if (manifest.claim !== REVIEW_CLAIM) {
    refuse(
      "manifest-claim",
      `review manifest claims "${manifest.claim}"; a canon review manifest binds "${REVIEW_CLAIM}" and may not claim implementation proof, stage closure, or status change`,
    );
  }

  // --- accountable reviewer
  const declared = typeof manifest.reviewer_ref === "string"
    ? manifest.reviewer_ref.trim()
    : "";
  const supplied = typeof reviewerRef === "string" ? reviewerRef.trim() : "";
  if (!supplied) {
    refuse(
      "accept-no-reviewer",
      "--accept requires --reviewer-ref <ref>. An acceptance with nobody's name on it is not accountable to anyone.",
    );
  } else if (supplied.length < 8 || PLACEHOLDER.test(supplied)) {
    refuse(
      "reviewer-placeholder",
      `--reviewer-ref "${supplied}" does not name an accountable reviewer`,
    );
  }
  if (declared && supplied && declared !== supplied) {
    refuse(
      "reviewer-mismatch",
      `review manifest names reviewer_ref "${declared}" but --reviewer-ref supplied "${supplied}"; they must agree`,
    );
  }

  // --- exact set equality with the pending drift
  const subjects = Array.isArray(manifest.subjects) ? manifest.subjects : null;
  if (!subjects) {
    refuse("manifest-subjects", "review manifest carries no `subjects` array");
    return { findings, manifest, digest };
  }
  if (pending.length === 0) {
    refuse(
      "accept-nothing-pending",
      "no canon subject is pending review: the baseline already agrees with the tree. --accept records a review of drift; it is not a way to re-stamp an unchanged baseline.",
    );
  }

  const pendingById = new Map(pending.map((p) => [p.id, p]));
  const seen = new Set();
  for (const entry of subjects) {
    const id = entry?.id;
    if (typeof id !== "string" || id === "") {
      refuse("manifest-subject-id", "a manifest subject carries no `id`");
      continue;
    }
    if (seen.has(id)) {
      refuse("manifest-duplicate-subject", `review manifest names ${id} more than once`);
      continue;
    }
    seen.add(id);

    const expected = pendingById.get(id);
    if (!expected) {
      refuse(
        "manifest-extra-subject",
        `review manifest names ${id}, which is not pending review. A manifest that does not match the actual drift set cannot authorise a baseline advance.`,
        { subject: id },
      );
      continue;
    }
    if (entry.change !== expected.change) {
      refuse(
        "manifest-change-kind",
        `${id}: manifest records change "${entry.change}" but the pending drift is "${expected.change}"`,
        { subject: id },
      );
    }
    if ((entry.baseline_sha256 ?? null) !== expected.baseline_sha256) {
      refuse(
        "manifest-stale-digest",
        `${id}: manifest leaves baseline digest ${entry.baseline_sha256 ?? "null"} but the recorded baseline holds ${expected.baseline_sha256 ?? "null"}`,
        { subject: id },
      );
    }
    if ((entry.tree_sha256 ?? null) !== expected.tree_sha256) {
      refuse(
        "manifest-stale-digest",
        `${id}: manifest reviews tree digest ${entry.tree_sha256 ?? "null"} but the file now digests to ${expected.tree_sha256 ?? "null"}. The revision you reviewed is not the revision on disk.`,
        { subject: id },
      );
    }
    if (!REVIEW_DISPOSITIONS.has(entry.disposition)) {
      refuse(
        "manifest-disposition",
        `${id}: disposition "${entry.disposition ?? ""}" is not one of ${[...REVIEW_DISPOSITIONS].join(" | ")}`,
        { subject: id },
      );
    }
    const note = typeof entry.review_note === "string" ? entry.review_note.trim() : "";
    if (note.length < 24 || PLACEHOLDER.test(note)) {
      refuse(
        "manifest-review-note",
        `${id}: review_note is empty or a placeholder. A subject nobody wrote a sentence about has not been reviewed.`,
        { subject: id },
      );
    }
  }
  for (const p of pending) {
    if (!seen.has(p.id)) {
      refuse(
        "manifest-missing-subject",
        `${p.id} is pending review (${p.change}) and the manifest does not name it. Accepting drift you have not enumerated is refused.`,
        { subject: p.id },
      );
    }
  }

  if (estateRoot && manifest.subject_set_sha256) {
    const recomputed = sha256Text(
      JSON.stringify(subjects.map((s) => [s.id, s.baseline_sha256 ?? null, s.tree_sha256 ?? null])),
    );
    if (recomputed !== manifest.subject_set_sha256) {
      refuse(
        "manifest-set-digest",
        `review manifest declares subject_set_sha256 ${manifest.subject_set_sha256} but its own subjects recompute to ${recomputed}`,
      );
    }
  }

  return { findings, manifest, digest };
}

// The manifest BODY is retained under its own content address before the
// acceptance that cites it is written. The old --accept recorded a volatile
// path (`/tmp/review-manifest.json`): the digest bound a body no later reader
// could produce, which is an attestation nobody can re-derive. A path is a
// place; a content address is the evidence.
function retainReviewManifest({ estateRoot, manifestAbs, digest }) {
  const rel = `${REVIEW_MANIFEST_DIR_REL.join("/")}/${digest}.json`;
  const abs = path.join(estateRoot, ...REVIEW_MANIFEST_DIR_REL, `${digest}.json`);
  const bytes = fs.readFileSync(manifestAbs);
  if (fs.existsSync(abs)) {
    // Content-addressed: identical digest means identical bytes. If it does not,
    // the address is lying and nothing further may be written against it.
    const existing = fs.readFileSync(abs);
    if (!existing.equals(bytes)) {
      throw new Error(
        `content address collision: ${rel} already holds different bytes than the manifest presented for acceptance. Refusing to overwrite retained review evidence.`,
      );
    }
    return rel;
  }
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, bytes);
  const written = sha256Text(fs.readFileSync(abs, "utf8"));
  if (written !== digest) {
    throw new Error(
      `retained review manifest digests to ${written}, not ${digest}; refusing to record an address that does not resolve to the reviewed body`,
    );
  }
  return rel;
}

function appendAcceptanceLedger({ estateRoot, entry }) {
  const ledgerPath = path.join(estateRoot, ...ACCEPTANCE_LEDGER_REL);
  const ledger = fs.existsSync(ledgerPath)
    ? readJson(ledgerPath)
    : { evidence_format: "ioi.program.canon_acceptances.v1", entries: [] };
  ledger.rule =
    "Append-only. One entry per baseline advance. Each entry binds the review manifest by digest, names an accountable reviewer, and enumerates every canon subject whose baseline identity moved, with the disposition its reviewer recorded. An entry claims that drift was reviewed and nothing else: no implementation proof, no stage closure, no status change. Entries are never rewritten or reordered; the sequence is dense.";
  const existing = ledger.entries ?? [];
  // A gap or a reordering means an entry was rewritten or removed, which is the
  // history edit an append-only ledger exists to stop. Refuse the append rather
  // than writing a second entry on top of a corrupted chain.
  existing.forEach((e, index) => {
    if (e.sequence !== index + 1) {
      throw new Error(
        `canon-acceptances ledger entry ${index + 1} carries sequence ${e.sequence}; the ledger is append-only and its sequence must be dense and ordered. Refusing to append.`,
      );
    }
  });
  ledger.entries = [...existing, { ...entry, sequence: existing.length + 1 }];
  writeJsonDeterministic(ledgerPath, ledger);
  return ledgerPath;
}

export function computeImpact({ repoRoot, estateRoot }) {
  const mapPath = path.join(estateRoot, "program", "canon-map.v1.json");
  const baselinePath = path.join(
    estateRoot,
    "generated",
    "canon-baseline.v1.json",
  );
  const sequencePath = path.join(estateRoot, "program", "sequence.v1.json");

  const map = readJson(mapPath);
  const sequence = readJson(sequencePath);
  const baseline = fs.existsSync(baselinePath)
    ? readJson(baselinePath)
    : { subjects: {} };

  const subjects = discoverCanonSubjects({ repoRoot });
  const mappable = mappableSubjects(subjects);
  const entries = new Map(map.subjects.map((s) => [s.id, s]));

  const knownStages = new Set(sequence.stages.map((s) => s.id));
  const knownModules = new Set(sequence.modules.map((m) => m.id));
  const workItemDir = path.join(estateRoot, "work-items");
  const knownWorkItems = new Set();
  for (const sub of ["active", "proposed", ""]) {
    const dir = sub ? path.join(workItemDir, sub) : workItemDir;
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (f.endsWith(".v1.json")) knownWorkItems.add(f.replace(/\.v1\.json$/, ""));
    }
  }

  const findings = [];
  const impact = {
    added: [],
    removed: [],
    changed: [],
    unchanged_count: 0,
  };
  const affected = {
    stages: new Set(),
    modules: new Set(),
    work_items: new Set(),
    conformance_targets: new Set(),
    contract_families: new Set(),
  };

  // --- orphan detection: every mappable subject on disk needs a map entry
  //
  // The unmerged message used to say "so it is unmerged branch canon" for every
  // subject absent from origin/master. That was FALSE for 220 of them: they
  // appear in no commit on any ref, so they are not branch canon awaiting a
  // merge — they are host-local ignored bytes. The frozen overlay manifest
  // classifies them, so the message consults it and says which case this is.
  // Nothing in the frozen v1 manifest changes the finding level. Only a
  // separately admitted successor baseline + manifest + exact disposition can
  // prove that a subject is governed durable evidence outside the canon map.
  const overlayMembers = overlayManifestMembers(estateRoot);
  const admittedOverlay = admittedOverlayCoverage(estateRoot);
  for (const subject of mappable) {
    const entry = entries.get(subject.id);
    if (!entry) {
      const governedEvidence = admittedOverlay.get(subject.id);
      if (governedEvidence?.sha256 === subject.sha256) {
        continue;
      }
      const merged = onMaster(repoRoot, subject.id);
      const overlay = overlayMembers.get(subject.id) ?? null;
      findings.push(
        finding(
          merged ? "error" : "skip",
          "canon-orphan",
          merged
            ? `canon subject has no classification in program/canon-map.v1.json: ${subject.id}`
            : overlay
            ? `canon subject is a declared overlay member classified ${overlay}, not unmerged branch canon: ${subject.id}. It is on this host and in no commit on any ref, so no merge will ever classify it. It carries no classification. SKIP is not success and grants no coverage.`
            : `canon subject exists in this checkout but not on origin/master and is not a declared overlay member: ${subject.id}. It carries no classification. SKIP is not success and grants no coverage.`,
          { subject: subject.id, kind: subject.kind, overlay_classification: overlay },
        ),
      );
      impact.added.push({
        id: subject.id,
        kind: subject.kind,
        reason: "unclassified",
      });
      continue;
    }
    if (!CLASSIFICATIONS.has(entry.classification)) {
      findings.push(
        finding(
          "error",
          "canon-classification",
          `unknown classification "${entry.classification}" for ${subject.id}`,
          { subject: subject.id },
        ),
      );
    }
    if (REQUIRES_OWNERSHIP.has(entry.classification)) {
      if (!entry.stages || entry.stages.length === 0) {
        findings.push(
          finding(
            "error",
            "canon-ownership",
            `${entry.classification} subject names no owning stage: ${subject.id}`,
            { subject: subject.id },
          ),
        );
      }
      if (!entry.work_items || entry.work_items.length === 0) {
        findings.push(
          finding(
            "error",
            "canon-ownership",
            `${entry.classification} subject names no owning work item: ${subject.id}`,
            { subject: subject.id },
          ),
        );
      }
    }
    for (const stage of entry.stages ?? []) {
      if (!knownStages.has(stage)) {
        findings.push(
          finding(
            "error",
            "canon-binding",
            `${subject.id} names unknown stage ${stage}`,
            { subject: subject.id },
          ),
        );
      }
    }
    for (const mod of entry.modules ?? []) {
      if (!knownModules.has(mod)) {
        findings.push(
          finding(
            "error",
            "canon-binding",
            `${subject.id} names unknown module ${mod}`,
            { subject: subject.id },
          ),
        );
      }
    }
    for (const wi of entry.work_items ?? []) {
      if (!knownWorkItems.has(wi)) {
        findings.push(
          finding(
            "error",
            "canon-binding",
            `${subject.id} names unknown work item ${wi}`,
            { subject: subject.id },
          ),
        );
      }
    }
  }

  // --- entries whose subject no longer exists on disk
  const onDisk = new Set(subjects.map((s) => s.id));
  for (const entry of map.subjects) {
    if (!onDisk.has(entry.id)) {
      const merged = onMaster(repoRoot, entry.id);
      findings.push(
        finding(
          merged ? "skip" : "error",
          "canon-removed",
          merged
            ? `classified subject is absent from this checkout but present on origin/master: ${entry.id}. This is checkout divergence, not a canon removal. SKIP is not success.`
            : `program/canon-map.v1.json classifies a subject that no longer exists: ${entry.id}`,
          { subject: entry.id },
        ),
      );
      impact.removed.push({ id: entry.id, classification: entry.classification });
      for (const s of entry.stages ?? []) affected.stages.add(s);
      for (const m of entry.modules ?? []) affected.modules.add(m);
      for (const w of entry.work_items ?? []) affected.work_items.add(w);
    }
  }

  // --- digest drift: what changed since the reviewed baseline
  for (const subject of subjects) {
    const previous = baseline.subjects?.[subject.id];
    if (previous === undefined) {
      if (!impact.added.some((a) => a.id === subject.id)) {
        impact.added.push({ id: subject.id, kind: subject.kind, reason: "new" });
      }
      const entry = entries.get(subject.attaches_to ?? subject.id);
      if (entry) {
        for (const s of entry.stages ?? []) affected.stages.add(s);
        for (const m of entry.modules ?? []) affected.modules.add(m);
        for (const w of entry.work_items ?? []) affected.work_items.add(w);
      }
      continue;
    }
    if (previous !== subject.sha256) {
      const owner = subject.attaches_to ?? subject.id;
      const entry = entries.get(owner);
      impact.changed.push({
        id: subject.id,
        owning_subject: owner,
        classification: entry?.classification ?? "unclassified",
        was: previous,
        now: subject.sha256,
        review_required: {
          stages: entry?.stages ?? [],
          modules: entry?.modules ?? [],
          work_items: entry?.work_items ?? [],
          conformance_targets: entry?.conformance_targets ?? [],
          contract_families: entry?.contract_families ?? [],
        },
      });
      for (const s of entry?.stages ?? []) affected.stages.add(s);
      for (const m of entry?.modules ?? []) affected.modules.add(m);
      for (const w of entry?.work_items ?? []) affected.work_items.add(w);
      for (const c of entry?.conformance_targets ?? []) {
        affected.conformance_targets.add(c);
      }
      for (const c of entry?.contract_families ?? []) {
        affected.contract_families.add(c);
      }
    } else {
      impact.unchanged_count += 1;
    }
  }

  // --- registered contract coverage: every schema is a contract that must be owned
  const contractSubjects = mappable.filter((s) => s.kind === "contract_schema");
  for (const c of contractSubjects) {
    const entry = entries.get(c.id);
    if (entry && entry.classification === "actively_sequenced" &&
      (entry.contract_families ?? []).length === 0
    ) {
      findings.push(
        finding(
          "warn",
          "contract-family",
          `actively sequenced contract schema declares no contract family: ${c.id}`,
          { subject: c.id },
        ),
      );
    }
  }

  // --- accepted ADRs must be owned; superseded ADRs must not satisfy an obligation
  for (const adr of mappable.filter((s) => s.kind === "adr")) {
    const { status, accepted } = readAdrStatus(adr.id, { repoRoot });
    const entry = entries.get(adr.id);
    if (!entry) continue;
    if (accepted && entry.classification === "non_build_doctrine") {
      findings.push(
        finding(
          "warn",
          "adr-coverage",
          `accepted ADR classified non_build_doctrine: ${adr.id} (${status})`,
          { subject: adr.id },
        ),
      );
    }
    if (!accepted && entry.classification !== "non_build_doctrine") {
      findings.push(
        finding(
          "error",
          "adr-superseded",
          `superseded ADR must be non_build_doctrine, found ${entry.classification}: ${adr.id}`,
          { subject: adr.id },
        ),
      );
    }
  }

  // --- module orphan: a module no stage pulls is unbound doctrine
  const pulled = new Set(sequence.stages.flatMap((s) => s.pulled_modules ?? []));
  for (const mod of sequence.modules) {
    if (!pulled.has(mod.id)) {
      findings.push(
        finding(
          "error",
          "module-orphan",
          `module ${mod.id} is pulled by no stage; it would be unbound doctrine`,
          { module: mod.id },
        ),
      );
    }
  }

  const counts = {};
  for (const entry of map.subjects) {
    counts[entry.classification] = (counts[entry.classification] ?? 0) + 1;
  }

  return {
    findings,
    impact,
    baseline,
    affected: {
      stages: [...affected.stages].sort(),
      modules: [...affected.modules].sort(),
      work_items: [...affected.work_items].sort(),
      conformance_targets: [...affected.conformance_targets].sort(),
      contract_families: [...affected.contract_families].sort(),
    },
    subjects,
    mappable,
    classification_counts: counts,
    map,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const repoRoot = args.root ? path.resolve(args.root) : REPO_ROOT;
  const estateRoot = args.estate
    ? path.resolve(args.estate)
    : (args.root
      ? path.join(path.resolve(args.root), "internal-docs", "implementation")
      : ESTATE_ROOT);

  const result = computeImpact({ repoRoot, estateRoot });

  const projection = {
    evidence_format: "ioi.program.canon_impact.v1",
    projection_role:
      "Deterministic architecture-impact and orphan projection. Assigns review obligations only. It implements no behaviour, closes no work item, stage, or gate, and changes no status.",
    generator: {
      path: "internal-docs/implementation/tools/canon-impact.mjs",
      write_command:
        "node internal-docs/implementation/tools/canon-impact.mjs --write",
      check_command:
        "node internal-docs/implementation/tools/canon-impact.mjs --check",
      emit_review_manifest_command:
        "node internal-docs/implementation/tools/canon-impact.mjs --emit-review-manifest <path>",
      accept_command:
        "node internal-docs/implementation/tools/canon-impact.mjs --accept --review-manifest <path> --reviewer-ref <ref>",
      accept_contract:
        "--accept refuses without a content-bound review manifest whose subject set equals the pending drift set exactly, an accountable --reviewer-ref, a disposition and a written review_note per subject, and digests that still match the tree. Every acceptance appends one entry to _archive/attestations/canon-acceptances.v1.json.",
    },
    universe: {
      rule:
        "Subjects are discovered from the filesystem under the roots declared in tools/lib/canon-universe.mjs. No index file bounds the universe, so a new canon file is a detected addition rather than a silent omission.",
      discovered_subject_count: result.subjects.length,
      mappable_subject_count: result.mappable.length,
      attachment_count: result.subjects.length - result.mappable.length,
    },
    classification_counts: result.classification_counts,
    impact: {
      added: result.impact.added,
      removed: result.impact.removed,
      changed: result.impact.changed,
      unchanged_count: result.impact.unchanged_count,
    },
    review_required: result.affected,
    orphan_counts: {
      // Only ERROR-level findings are orphans. A SKIP means the subject is
      // unmerged branch canon, which is a provenance fact, not an orphan.
      unclassified_subjects: result.findings.filter((f) =>
        f.check === "canon-orphan" && f.level === "error"
      ).length,
      unmerged_branch_subjects: result.findings.filter((f) =>
        f.check === "canon-orphan" && f.level === "skip"
      ).length,
      removed_subjects: result.findings.filter((f) =>
        f.check === "canon-removed" && f.level === "error"
      ).length,
      absent_from_this_checkout: result.findings.filter((f) =>
        f.check === "canon-removed" && f.level === "skip"
      ).length,
      unbound_modules: result.findings.filter((f) => f.check === "module-orphan")
        .length,
    },
    nonclaims: [
      "A bounded impact report is a review assignment, not proof and not a status change.",
      "An unchanged digest proves only that bytes did not change; it does not prove the implementation satisfies the obligation.",
      "Retained evidence under _archive/ and docs/evidence/ is immutable for the commit and canon revision it certified. Canon change never invalidates it.",
    ],
  };

  if (args.write) {
    writeJsonDeterministic(
      path.join(estateRoot, "generated", "canon-impact.v1.json"),
      projection,
    );
  }

  const findings = [...result.findings];
  const pending = pendingDrift(result);

  // --- reviewer aid: the skeleton the reviewer fills in. Writes no baseline.
  if (args.emitReviewManifest) {
    const skeleton = {
      evidence_format: MANIFEST_FORMAT,
      manifest_role:
        "Content-bound enumeration of every canon subject pending baseline review, with the disposition and written reasoning of one accountable reviewer. Presenting this manifest to --accept advances the baseline. It closes no work item, certifies no stage, and changes no status.",
      claim: REVIEW_CLAIM,
      reviewer_ref: "",
      emitted_at_commit: headCommit(repoRoot),
      instructions: [
        `Fill reviewer_ref, and per subject a disposition (${[...REVIEW_DISPOSITIONS].join(" | ")}) and a review_note that argues it from what actually changed.`,
        "`unaffected` must be ARGUED. Say why this subject's change does not reach the stages, modules, and work items named in review_required below. An unargued `unaffected` is a mechanical accept with extra steps.",
        "Never rewrite a verified closure to absorb a semantic change: disposition it `successor_required` and open a successor record that states what must now be proven.",
        "Do not edit the ids or digests. They bind this manifest to one exact revision, and --accept refuses if they drift.",
      ],
      review_required: result.affected,
      subject_count: pending.length,
      subject_set_sha256: sha256Text(
        JSON.stringify(pending.map((p) => [p.id, p.baseline_sha256, p.tree_sha256])),
      ),
      subjects: pending.map((p) => ({ ...p, disposition: "", review_note: "" })),
    };
    const out = path.isAbsolute(args.emitReviewManifest)
      ? args.emitReviewManifest
      : path.resolve(process.cwd(), args.emitReviewManifest);
    writeJsonDeterministic(out, skeleton);
    process.stdout.write(
      `wrote review manifest skeleton: ${out} (${pending.length} pending subject(s))\n`,
    );
  }

  if (args.accept) {
    const { findings: manifestFindings, manifest, digest } = validateReviewManifest({
      manifestPath: args.reviewManifest,
      reviewerRef: args.reviewerRef,
      pending,
      estateRoot,
    });
    findings.push(...manifestFindings);

    if (manifestFindings.length > 0) {
      findings.push(
        finding(
          "error",
          "accept-refused",
          `baseline NOT advanced: ${manifestFindings.length} refusal(s) above. The baseline still records the last reviewed canon, which is the honest state.`,
        ),
      );
    } else {
      const subjects = {};
      for (const s of result.subjects) subjects[s.id] = s.sha256;
      const baselinePath = path.join(estateRoot, "generated", "canon-baseline.v1.json");
      const before = fs.existsSync(baselinePath) ? readJson(baselinePath) : null;
      const setDigest = sha256Text(JSON.stringify(Object.entries(subjects).sort()));

      // The ledger is written FIRST. If the acceptance cannot be recorded, the
      // baseline must not advance: a silently advanced baseline with no ledger
      // entry is exactly the unaccountable state this contract exists to stop.
      const dispositions = {};
      for (const s of manifest.subjects) {
        dispositions[s.disposition] = (dispositions[s.disposition] ?? 0) + 1;
      }
      // Retain the reviewed body BEFORE the ledger cites it, so no entry can
      // ever name evidence that was not kept.
      const manifestAbs = path.isAbsolute(args.reviewManifest)
        ? args.reviewManifest
        : path.resolve(process.cwd(), args.reviewManifest);
      const contentAddress = retainReviewManifest({
        estateRoot,
        manifestAbs,
        digest,
      });
      const ledgerPath = appendAcceptanceLedger({
        estateRoot,
        entry: {
          accepted_at_commit: headCommit(repoRoot),
          reviewer_ref: (args.reviewerRef ?? "").trim(),
          claim: REVIEW_CLAIM,
          review_manifest_content_address: contentAddress,
          review_manifest_path_at_acceptance: args.reviewManifest,
          review_manifest_path_is_not_authoritative: true,
          review_manifest_sha256: digest,
          subject_count: pending.length,
          dispositions,
          subjects_reviewed: manifest.subjects.map((s) => ({
            id: s.id,
            change: s.change,
            baseline_sha256: s.baseline_sha256 ?? null,
            tree_sha256: s.tree_sha256 ?? null,
            disposition: s.disposition,
          })),
          review_required: result.affected,
          baseline_subject_set_sha256_before: before?.subject_set_sha256 ?? null,
          baseline_subject_set_sha256_after: setDigest,
        },
      });

      writeJsonDeterministic(baselinePath, {
        evidence_format: "ioi.program.canon_baseline.v1",
        role:
          "Content-bound identities of every discovered canon subject at the moment they were last reviewed. Advancing this baseline records that a named reviewer enumerated and dispositioned every drifted subject; it never asserts that the implementation changed.",
        accepted_by_command:
          "node internal-docs/implementation/tools/canon-impact.mjs --accept --review-manifest <path> --reviewer-ref <ref>",
        accepted_under_review_manifest_content_address: contentAddress,
        accepted_under_review_manifest_sha256: digest,
        accepted_by_reviewer_ref: (args.reviewerRef ?? "").trim(),
        subject_count: result.subjects.length,
        subject_set_sha256: setDigest,
        subjects,
      });

      process.stdout.write(
        `accepted ${pending.length} reviewed canon subject(s) as ${
          Object.entries(dispositions).map(([k, v]) => `${k}=${v}`).join(" ")
        }; ledger: ${path.relative(estateRoot, ledgerPath)}; manifest retained at ${contentAddress}\n`,
      );
      if ((dispositions.successor_required ?? 0) > 0) {
        process.stdout.write(
          `${dispositions.successor_required} subject(s) were dispositioned successor_required; each one owes an open hold. Run: node internal-docs/implementation/tools/check-open-successor-holds.mjs --seed\n`,
        );
      }
    }
  }

  if (result.impact.changed.length > 0 && args.check) {
    findings.push(
      finding(
        "error",
        "canon-unreviewed",
        `${result.impact.changed.length} canon subject digest(s) changed since the reviewed baseline; review the named stages/modules/work items then run --accept`,
        { affected: result.affected },
      ),
    );
  }

  if (!args.json) {
    process.stdout.write(
      `canon universe: ${result.subjects.length} subjects (${result.mappable.length} classified, ${
        result.subjects.length - result.mappable.length
      } attachments)\n`,
    );
    process.stdout.write(
      `classifications: ${JSON.stringify(result.classification_counts)}\n`,
    );
    process.stdout.write(
      `impact: +${result.impact.added.length} -${result.impact.removed.length} ~${result.impact.changed.length} =${result.impact.unchanged_count}\n`,
    );
    if (
      result.affected.stages.length > 0 || result.affected.work_items.length > 0
    ) {
      process.stdout.write(
        `review required -> stages: ${
          result.affected.stages.join(", ") || "(none)"
        } | modules: ${
          result.affected.modules.join(", ") || "(none)"
        } | work items: ${result.affected.work_items.length}\n`,
      );
    }
  }

  const exit = report("canon-impact", findings, { json: args.json });
  process.exit(args.check || args.write || args.accept ? exit : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
