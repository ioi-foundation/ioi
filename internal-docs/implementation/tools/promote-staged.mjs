#!/usr/bin/env node
// THE PROMOTION EVENT. The only sanctioned path from private staging into the
// canonical estate's authoritative bytes.
//
//   node tools/promote-staged.mjs --from <absolute staging path> \
//                                 --to <estate-relative path> \
//                                 --reviewer-ref <ref> \
//                                 --reason "<why>" [--apply]
//
// Without --apply it reports exactly what it would do and writes nothing.
//
// WHY THIS EXISTS
//
// The estate is gitignored, so it has no diff of its own. Before this tool, a
// worktree could copy its staged bytes over an authoritative record and the only
// evidence would be that the record now said something else. Five copies of this
// tree exist on this host; four declared nothing about themselves and one
// declared its private staging INSIDE the canonical estate root.
//
// WHAT A PROMOTION IS, MECHANICALLY
//
//   1. The source is OUTSIDE the canonical estate. Promoting from inside it is
//      not a promotion, it is an edit with paperwork.
//   2. The reviewer and the reason are named. An unattributed promotion is a
//      file copy wearing a ledger entry.
//   3. The resulting body is retained content-addressed FIRST, so the ledger can
//      never cite a body that was not kept.
//   4. The event is appended, then the bytes are written. If the append fails
//      the estate is unchanged, which is the honest failure direction.
//
// WHAT IT REFUSES TO DECIDE
//
// Whether the promoted bytes are correct. It records custody, not merit.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  progress,
  readJson,
  sha256File,
  writeJsonDeterministic,
} from "./lib/estate.mjs";

const PROMOTIONS_REL = "_archive/attestations/estate-promotions.v1.json";
const CAS_REL = "_archive/evidence/cas";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? null : (process.argv[i + 1] ?? null);
}

function refuse(message) {
  progress(`REFUSED: ${message}`);
  process.exit(1);
}

function main() {
  const from = arg("from");
  const to = arg("to");
  const reviewerRef = (arg("reviewer-ref") ?? "").trim();
  const reason = (arg("reason") ?? "").trim();
  const apply = process.argv.includes("--apply");

  if (!from || !to) refuse("--from and --to are both required");
  if (!reviewerRef) refuse("--reviewer-ref is required; an unattributed promotion is a file copy wearing a ledger entry");
  if (!reason) refuse("--reason is required; a promotion with no stated reason cannot be reviewed later");

  const sourceAbs = path.resolve(from);
  const canonicalRoot = fs.realpathSync(ESTATE_ROOT);
  if (
    sourceAbs === canonicalRoot ||
    sourceAbs.startsWith(`${canonicalRoot}${path.sep}`)
  ) {
    refuse(
      `--from ${sourceAbs} is INSIDE the canonical estate. Promotion moves bytes from private staging into the estate; a source already inside it is an edit, and an edit does not become a promotion by being logged.`,
    );
  }
  if (!fs.existsSync(sourceAbs) || !fs.statSync(sourceAbs).isFile()) {
    refuse(`--from ${sourceAbs} is not a file`);
  }
  if (path.isAbsolute(to) || to.includes("..")) {
    refuse("--to must be a path relative to the estate root, with no parent traversal");
  }

  const targetAbs = path.join(ESTATE_ROOT, to);
  const sourceDigest = sha256File(sourceAbs);
  const priorDigest = fs.existsSync(targetAbs) ? sha256File(targetAbs) : null;

  const ledgerAbs = path.join(ESTATE_ROOT, PROMOTIONS_REL);
  if (!fs.existsSync(ledgerAbs)) {
    refuse(`${PROMOTIONS_REL} is absent; open the ledger before promoting anything into the estate`);
  }
  const ledger = readJson(ledgerAbs);
  const nextSequence = (ledger.promotions ?? []).length + 1;

  const event = {
    promotion_id: `prm-${String(nextSequence).padStart(4, "0")}`,
    sequence: nextSequence,
    at: new Date().toISOString(),
    target_path: to,
    source_path: sourceAbs,
    source_sha256: sourceDigest,
    prior_target_sha256: priorDigest,
    resulting_sha256: sourceDigest,
    reviewer_ref: reviewerRef,
    reason,
    claim_boundary:
      "Records that these bytes entered the canonical estate under this reviewer at this time. Asserts nothing about whether they are correct or sufficient.",
  };

  if (!apply) {
    progress(
      `DRY RUN — would promote ${sourceAbs}\n  -> ${to}\n  source ${sourceDigest}\n  replaces ${priorDigest ?? "(new file)"}\n  as ${event.promotion_id} by ${reviewerRef}\n  nothing written; re-run with --apply`,
    );
    process.exit(0);
  }

  // Retain BEFORE the ledger cites it, so no entry can ever name a body that
  // was not kept.
  const casAbs = path.join(ESTATE_ROOT, CAS_REL, sourceDigest);
  fs.mkdirSync(path.dirname(casAbs), { recursive: true });
  if (!fs.existsSync(casAbs)) fs.copyFileSync(sourceAbs, casAbs);

  // Append the event BEFORE the bytes move. If this write fails, the estate is
  // unchanged — an unrecorded promotion is worse than a refused one.
  ledger.promotions = [...(ledger.promotions ?? []), event];
  ledger.promotion_count = ledger.promotions.length;
  writeJsonDeterministic(ledgerAbs, ledger);

  fs.mkdirSync(path.dirname(targetAbs), { recursive: true });
  fs.copyFileSync(sourceAbs, targetAbs);

  progress(
    `${event.promotion_id}: promoted ${to} to ${sourceDigest} (was ${priorDigest ?? "absent"}); body retained at cas://sha256/${sourceDigest}; reviewer ${reviewerRef}`,
  );
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
