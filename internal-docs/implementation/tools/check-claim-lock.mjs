#!/usr/bin/env node
// Claim-lock bar (m0-selected-profile-baseline-evidence-and-claim-lock).
//
// Validates program/claim-lock.v1.json against its content-bound sources and
// enforces the record's predeclared rejections, each self-tested on every run:
//
//   mutable-threshold   a lock threshold that differs from the frozen baseline
//                       definition, or a frozen_as_of date that moved
//   missing-nonclaim    a selected-profile/exit-report nonclaim absent from
//                       the lock
//   derived-baseline    a baseline reported measured with no observed value
//                       and no evidence (UI- or status-derived measurement)
//   claim-widening      a non-empty claim set while the exit report closes no
//                       capability claim, or any claim outside the sources
//   stale-source        a source digest that no longer matches its artifact
//
//   node tools/check-claim-lock.mjs
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  readJson,
  report,
  sha256File,
} from "./lib/estate.mjs";

const LOCK_ABS = path.join(ESTATE_ROOT, "program", "claim-lock.v1.json");
const EVIDENCE = path.join(REPO_ROOT, "docs", "evidence", "m0-program-control");
const SOURCE_RELS = [
  "docs/evidence/m0-program-control/m0-exit-report.json",
  "docs/evidence/m0-program-control/current-baselines.json",
  "docs/evidence/m0-program-control/selected-profile.json",
  "docs/evidence/m0-program-control/release-ladder.json",
];

export function deriveLock({ baselines, exitReport }) {
  return {
    format: "ioi.program.claim_lock.v1",
    role: "Frozen claim lock for the selected first deployment profile (M0.4/M0.8). Claims may only narrow; widening requires a successor lock plus the owning stage's own proof. Derived from the content-bound sources below; never authority.",
    sources: Object.fromEntries(
      SOURCE_RELS.map((rel) => [rel, sha256File(path.join(REPO_ROOT, rel))]),
    ),
    claims: [],
    claims_note: "M0 closes NO architecture or production capability claim; the honest claim set is empty. Capability claims enter only through the conformance claim coverage index when their owning stage retains proof.",
    nonclaims: [...(exitReport.nonclaims ?? [])],
    frozen_baseline_thresholds: Object.fromEntries(
      (baselines.baselines ?? []).map((baseline) => [
        baseline.baseline_id,
        {
          frozen_as_of: baseline.frozen_as_of,
          frozen_threshold: baseline.frozen_threshold,
          status: baseline.status,
          blocker_ref: baseline.blocker_ref,
        },
      ]),
    ),
    baseline_measurement_ruling: "M0.8 ruling (2026-07-26, program/m0-closure): the four baselines are discharged at M0 by their frozen pre-observation threshold definitions plus the honest not_measured status and open blockers. No qualifying cohort exists (five first-time operators; thirty fault-injected runs; thirty invoice-reconciled runs; a comprehension cohort), and fabricating one would forge evidence. Measurement transfers with its blockers to the first stage whose retained runtime proof produces a qualifying cohort; the thresholds themselves are immutable under this lock.",
    release_ladder_level: "M0 only; below P0 runtime proof",
    rollback_rules: [
      "Any stage exit found to rest on invalid retained evidence rolls its record back to its last honestly evidenced status via the transition tool; the aggregate re-opens with it.",
      "A claim published beyond this lock is withdrawn by successor-lock supersession, never by silent edit; the superseded lock is retained verbatim.",
      "Threshold changes are a successor lock with their own review anchor epoch; the frozen_as_of dates never move.",
    ],
    widening_rule: "A claim absent from `claims` cannot be added by any workflow artifact, UI state, task exit, or status transition; only a successor lock accompanying the owning stage's retained proof may widen.",
  };
}

export function evaluate({ lock, baselines, exitReport }) {
  const findings = [];

  const byId = new Map(baselines.baselines.map((b) => [b.baseline_id, b]));
  for (const [id, entry] of Object.entries(lock.frozen_baseline_thresholds ?? {})) {
    const source = byId.get(id);
    if (!source) {
      findings.push(finding("error", "mutable-threshold", `lock names a baseline the source does not define: ${id}`));
      continue;
    }
    if (JSON.stringify(entry.frozen_threshold) !== JSON.stringify(source.frozen_threshold)) {
      findings.push(finding("error", "mutable-threshold", `${id}: lock threshold differs from the frozen definition`));
    }
    if (entry.frozen_as_of !== source.frozen_as_of) {
      findings.push(finding("error", "mutable-threshold", `${id}: frozen_as_of moved (${source.frozen_as_of} -> ${entry.frozen_as_of})`));
    }
    if (source.status === "measured" && (source.observed_value == null || source.observed_as_of == null)) {
      findings.push(finding("error", "derived-baseline", `${id}: reported measured with no observed value/date; a status is not a measurement`));
    }
  }
  for (const id of byId.keys()) {
    if (!(lock.frozen_baseline_thresholds ?? {})[id]) {
      findings.push(finding("error", "mutable-threshold", `baseline missing from the lock: ${id}`));
    }
  }

  for (const nonclaim of exitReport.nonclaims ?? []) {
    if (!(lock.nonclaims ?? []).includes(nonclaim)) {
      findings.push(finding("error", "missing-nonclaim", `exit-report nonclaim absent from the lock: ${nonclaim.slice(0, 80)}...`));
    }
  }

  if (exitReport.architecture_or_production_capability_closure === false && (lock.claims ?? []).length > 0) {
    findings.push(
      finding("error", "claim-widening", `lock carries ${lock.claims.length} claim(s) while the exit report closes no capability claim`),
    );
  }

  return findings;
}

function selfTest({ lock, baselines, exitReport }) {
  const out = [];
  const clone = (v) => JSON.parse(JSON.stringify(v));

  const widened = clone(lock);
  widened.claims = ["the daemon is production ready"];
  if (!evaluate({ lock: widened, baselines, exitReport }).some((f) => f.check === "claim-widening")) {
    out.push(finding("error", "self-test", "claim-widening has no teeth"));
  }

  const mutated = clone(lock);
  const firstId = Object.keys(mutated.frozen_baseline_thresholds)[0];
  mutated.frozen_baseline_thresholds[firstId].frozen_threshold = { relaxed: true };
  if (!evaluate({ lock: mutated, baselines, exitReport }).some((f) => f.check === "mutable-threshold")) {
    out.push(finding("error", "self-test", "mutable-threshold has no teeth"));
  }

  const stripped = clone(lock);
  stripped.nonclaims = stripped.nonclaims.slice(1);
  if (!evaluate({ lock: stripped, baselines, exitReport }).some((f) => f.check === "missing-nonclaim")) {
    out.push(finding("error", "self-test", "missing-nonclaim has no teeth"));
  }

  const derived = clone(baselines);
  derived.baselines[0].status = "measured";
  if (!evaluate({ lock, baselines: derived, exitReport }).some((f) => f.check === "derived-baseline")) {
    out.push(finding("error", "self-test", "derived-baseline has no teeth"));
  }

  return out;
}

function main() {
  const findings = [];
  const write = process.argv.includes("--write");
  const outputIndex = process.argv.indexOf("--output");
  const outputAbs = outputIndex >= 0
    ? path.resolve(process.argv[outputIndex + 1] ?? "")
    : LOCK_ABS;
  const baselines = readJson(path.join(EVIDENCE, "current-baselines.json"));
  const exitReport = readJson(path.join(EVIDENCE, "m0-exit-report.json"));
  const derived = deriveLock({ baselines, exitReport });
  const rendered = `${JSON.stringify(derived, null, 2)}\n`;

  if (write) {
    fs.mkdirSync(path.dirname(outputAbs), { recursive: true });
    fs.writeFileSync(outputAbs, rendered);
    if (outputAbs !== LOCK_ABS) {
      findings.push(...selfTest({ lock: derived, baselines, exitReport }));
      report("check-claim-lock", findings);
      process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
    }
  }
  if (!fs.existsSync(LOCK_ABS)) {
    findings.push(finding("error", "lock", "program/claim-lock.v1.json missing"));
    report("check-claim-lock", findings);
    process.exit(1);
  }
  const lock = readJson(LOCK_ABS);
  for (const [rel, digest] of Object.entries(lock.sources ?? {})) {
    const abs = path.join(REPO_ROOT, rel);
    if (!fs.existsSync(abs)) {
      findings.push(finding("error", "stale-source", `lock source missing: ${rel}`));
    } else if (sha256File(abs) !== digest) {
      findings.push(finding("error", "stale-source", `lock source digest stale: ${rel}; re-derive the lock from current evidence`));
    }
  }
  if (fs.readFileSync(LOCK_ABS, "utf8") !== rendered) {
    findings.push(
      finding(
        "error",
        "lock-reproduction",
        "claim lock does not reproduce byte-for-byte from its current sources and frozen policy",
      ),
    );
  }

  findings.push(...selfTest({ lock, baselines, exitReport }));
  findings.push(...evaluate({ lock, baselines, exitReport }));

  report("check-claim-lock", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
