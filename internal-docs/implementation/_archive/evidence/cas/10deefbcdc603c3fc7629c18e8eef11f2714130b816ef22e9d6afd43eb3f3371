#!/usr/bin/env node
// Release-closure bar for the 2026-07-29 successor repair.
//
// It deliberately does not invoke check-program: check-program owns the
// top-level conjunction and includes this bar. This checker owns the pieces
// that otherwise existed only in assembled prose: the exact successor set,
// the admitted baseline/generation, the hold state, and independent binding.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  readJson,
  report,
  sha256File,
} from "./lib/estate.mjs";
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";
import { openHolds, readHoldLedger } from "./lib/holds.mjs";
import { validateReleaseGeneration } from "./lib/release-generation.mjs";

const CONDITIONS_REL = "program/release-closure-conditions.v1.json";
const HOLD_REL = "_archive/holds/certification-hold.v1.json";
const DISPOSITIONS_REL = "program/canon-overlay-dispositions.v1.json";
const GENERATION_REL = "program/estate-generation.v1.json";
const REVIEW_REL = "_archive/attestations/release-review-bindings.v1.json";
const ADMITTED_BASELINE_REL = "program/canon-baseline-successor.v1.json";

function exists(rel) {
  return fs.existsSync(path.join(ESTATE_ROOT, rel));
}

function main() {
  const findings = [];
  if (!exists(CONDITIONS_REL)) {
    findings.push(finding("error", "closure-contract", `${CONDITIONS_REL} is absent`));
    process.exit(report("check-release-closure", findings, { json: process.argv.includes("--json") }));
  }
  const contract = readJson(path.join(ESTATE_ROOT, CONDITIONS_REL));
  const ids = contract.required_successor_work_item_ids ?? [];
  if (contract.condition_count !== 7 || (contract.conditions ?? []).length !== 7) {
    findings.push(finding("error", "closure-contract", "the authoritative closure contract must contain exactly seven conditions"));
  }
  if (new Set(ids).size !== ids.length || ids.length === 0) {
    findings.push(finding("error", "successor-set", "required successor ids are empty or duplicated"));
  }

  const records = new Map(loadWorkItems().map((r) => [r.work_item_id, r]));
  for (const id of ids) {
    const record = records.get(id);
    if (!record) {
      findings.push(finding("error", "successor-absent", `${id} does not resolve to a work-item record`));
      continue;
    }
    const status = statusAuthority(record).status;
    if (status !== "verified") {
      findings.push(finding("error", "successor-unadmitted", `${id} is ${status}, not verified`));
    }
  }

  const holds = openHolds(readHoldLedger());
  if (holds.length > 0) {
    findings.push(finding("error", "holds-open", `${holds.length} successor hold(s) remain open: ${holds.map((h) => h.hold_id).join(", ")}`));
  }

  if (exists(DISPOSITIONS_REL)) {
    const dispositions = readJson(path.join(ESTATE_ROOT, DISPOSITIONS_REL));
    const unattributed = dispositions.counts?.by_disposition?.unattributed;
    if (unattributed !== 0) {
      findings.push(finding("error", "overlay-unattributed", `overlay disposition census reports ${unattributed ?? "unknown"} unattributed member(s)`));
    }
  } else {
    findings.push(finding("error", "overlay-unattributed", `${DISPOSITIONS_REL} is absent`));
  }

  const hold = exists(HOLD_REL) ? readJson(path.join(ESTATE_ROOT, HOLD_REL)) : null;
  if (hold?.state !== "CLOSED") {
    findings.push(finding("error", "certification-hold", `certification hold state is ${hold?.state ?? "absent"}, not CLOSED`));
  }

  const generation = exists(GENERATION_REL) ? readJson(path.join(ESTATE_ROOT, GENERATION_REL)) : null;
  if (!generation) {
    findings.push(finding("error", "estate-generation", `${GENERATION_REL} is absent`));
  } else {
    const gitHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8" }).trim();
    const docsTree = execFileSync("git", ["rev-parse", "HEAD:docs"], { cwd: REPO_ROOT, encoding: "utf8" }).trim();
    if (generation.bound_git_tree?.commit !== gitHead || generation.bound_git_tree?.docs_tree_sha !== docsTree) {
      findings.push(finding("error", "estate-generation", "estate generation does not bind the current Git commit and docs tree"));
    }
    for (const message of validateReleaseGeneration(generation, { phase: "post" })) {
      findings.push(finding("error", "estate-generation", message));
    }
  }

  const baseline = exists(ADMITTED_BASELINE_REL) ? readJson(path.join(ESTATE_ROOT, ADMITTED_BASELINE_REL)) : null;
  if (baseline?.state !== "admitted" || baseline?.consumed_by_no_tool !== false) {
    findings.push(finding("error", "baseline-unadmitted", `${ADMITTED_BASELINE_REL} is absent or not admitted`));
  }

  const review = exists(REVIEW_REL) ? readJson(path.join(ESTATE_ROOT, REVIEW_REL)) : null;
  const binding = review?.bindings?.at(-1) ?? null;
  if (!binding) {
    findings.push(finding("error", "independent-review", `${REVIEW_REL} carries no binding`));
  } else if (!generation) {
    findings.push(finding("error", "independent-review", "review binding exists without an estate generation"));
  } else {
    const generationDigest = sha256File(path.join(ESTATE_ROOT, GENERATION_REL));
    if (binding.estate_generation_sha256 !== generationDigest) {
      findings.push(finding("error", "independent-review", "review binding does not bind the current estate generation bytes"));
    }
    if (typeof binding.reviewer_ref !== "string" || binding.reviewer_ref.length < 8 || binding.reviewer_ref === contract.authority) {
      findings.push(finding("error", "independent-review", "reviewer_ref is absent, placeholder-like, or identical to the implementation authority"));
    }
    if (binding.independent_of_implementation !== true) {
      findings.push(finding("error", "independent-review", "review binding does not affirm independence from implementation"));
    }
    if (binding.decision !== "approve_atomic_successor_batch") {
      findings.push(finding("error", "independent-review", "review binding does not approve the exact atomic successor batch"));
    }
    if (
      binding.git_commit !== generation.bound_git_tree?.commit ||
      binding.docs_tree_sha !== generation.bound_git_tree?.docs_tree_sha
    ) {
      findings.push(finding("error", "independent-review", "review binding Git tree does not match the reviewed generation"));
    }
  }

  process.exit(report("check-release-closure", findings, { json: process.argv.includes("--json") }));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
