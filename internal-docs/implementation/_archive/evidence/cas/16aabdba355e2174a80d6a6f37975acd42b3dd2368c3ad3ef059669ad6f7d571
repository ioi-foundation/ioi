#!/usr/bin/env node
// Records a transition-owned filing move of an already promoted estate target.
// The predecessor path must be absent, the successor path present, and both
// byte identities content-addressed. This is a tombstoned relocation, not a
// silent deletion and not a second writable estate.
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

const LEDGER_REL = "_archive/attestations/estate-promotions.v1.json";
const CAS_REL = "_archive/evidence/cas";

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index < 0 ? null : process.argv[index + 1] ?? null;
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
  if (!from || !to || !reviewerRef || !reason) {
    refuse("--from, --to, --reviewer-ref, and --reason are required");
  }
  if ([from, to].some((value) => path.isAbsolute(value) || value.includes(".."))) {
    refuse("--from and --to must be estate-relative paths with no parent traversal");
  }
  const fromAbs = path.join(ESTATE_ROOT, from);
  const toAbs = path.join(ESTATE_ROOT, to);
  if (fs.existsSync(fromAbs)) refuse(`relocated predecessor still exists: ${from}`);
  if (!fs.existsSync(toAbs) || !fs.statSync(toAbs).isFile()) refuse(`successor is absent: ${to}`);

  const ledgerAbs = path.join(ESTATE_ROOT, LEDGER_REL);
  const ledger = readJson(ledgerAbs);
  const previous = [...(ledger.promotions ?? [])].reverse().find((event) => event.target_path === from);
  if (!previous || previous.event_kind === "relocation") {
    refuse(`${from} has no live prior promotion to relocate`);
  }
  const priorDigest = previous.resulting_sha256;
  const successorDigest = sha256File(toAbs);
  const successorCas = path.join(ESTATE_ROOT, CAS_REL, successorDigest);
  const priorCas = path.join(ESTATE_ROOT, CAS_REL, priorDigest);
  if (!fs.existsSync(priorCas)) refuse(`prior promoted bytes are absent from CAS: ${priorDigest}`);
  if (!fs.existsSync(successorCas) && apply) fs.copyFileSync(toAbs, successorCas);

  const sequence = (ledger.promotions ?? []).length + 1;
  const event = {
    promotion_id: `prm-${String(sequence).padStart(4, "0")}`,
    sequence,
    event_kind: "relocation",
    at: new Date().toISOString(),
    target_path: from,
    source_path: `transition://filing/${from}`,
    source_sha256: priorDigest,
    prior_target_sha256: priorDigest,
    resulting_sha256: null,
    successor_target_path: to,
    successor_sha256: successorDigest,
    reviewer_ref: reviewerRef,
    reason,
    claim_boundary: "Records that the status-authority transition refiled one exact record. It asserts no implementation merit or proof.",
  };
  if (!apply) {
    progress(`DRY RUN — would record ${from} -> ${to} as ${event.promotion_id}`);
    return;
  }
  ledger.promotions = [...(ledger.promotions ?? []), event];
  ledger.promotion_count = ledger.promotions.length;
  writeJsonDeterministic(ledgerAbs, ledger);
  progress(`${event.promotion_id}: recorded relocation ${from} -> ${to} at ${successorDigest}`);
}

main();
