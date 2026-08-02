#!/usr/bin/env node
// Per-record work-item validation. Cheap, local, and usable one record at a
// time, which is what lets the fast lane validate only what changed.
//
//   node tools/check-work-item-shape.mjs [work-item-id ...]
//
// This is the SHAPE bar. The deep historical bar (aggregate closure, literal
// exits, migration finalization, checkout code anchors) belongs to the program
// audit lane, not here.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  finding,
  progress,
  readJson,
  repoFileExists,
  report,
} from "./lib/estate.mjs";

// Explicit, dated, reviewed waivers. A waiver never hides a finding: it
// downgrades it to a warning and restates why it is open and what closes it.
// A finding with no waiver is an error.
let waiverCache = null;
export function waivers() {
  if (waiverCache) return waiverCache;
  const p = path.join(ESTATE_ROOT, "program", "known-gaps.v1.json");
  waiverCache = fs.existsSync(p) ? readJson(p) : { gaps: [] };
  return waiverCache;
}

function waiverFor(check, subject) {
  return waivers().gaps.find((g) =>
    g.check === check && (g.subjects ?? []).some((s) => subject.includes(s))
  ) ?? null;
}

export function applyWaivers(findings) {
  return findings.map((f) => {
    if (f.level !== "error") return f;
    const w = waiverFor(f.check, f.message);
    if (!w) return f;
    return {
      ...f,
      level: "warn",
      message: `${f.message} [waived: ${w.id} — ${w.closes_when}]`,
      waiver: w.id,
    };
  });
}

const STATUSES = new Set([
  "proposed",
  "scoped",
  "active",
  "evidence_ready",
  "verified",
  "blocked",
  "superseded",
  "rejected",
]);

const ROLES = new Set([
  "implementation_cut",
  "aggregate_exit",
  "private_verifier",
  "conditional_future",
]);

const REQUIRED = [
  "work_item_id",
  "stage_id",
  "record_role",
  "status",
  "objective",
  "falsifiable_claim",
  "canon_owners",
  "in_scope",
  "out_of_scope",
  "positive_proof",
  "adversarial_or_fault_proof",
  "remaining_nonclaims",
  "rollback_or_stop_rule",
];

export function validateRecord(record) {
  const out = [];
  const id = record.work_item_id ?? record.file ?? "(unknown)";
  const where = { work_item_id: id };

  for (const key of REQUIRED) {
    const value = record[key];
    if (
      value === undefined ||
      value === null ||
      (Array.isArray(value) && value.length === 0) ||
      (typeof value === "string" && value.trim() === "")
    ) {
      out.push(
        finding("error", "work-item-shape", `${id}: missing or empty "${key}"`, where),
      );
    }
  }

  if (!STATUSES.has(record.status)) {
    out.push(
      finding("error", "work-item-shape", `${id}: unknown status "${record.status}"`, where),
    );
  }
  if (!ROLES.has(record.record_role)) {
    out.push(
      finding(
        "error",
        "work-item-shape",
        `${id}: unknown record_role "${record.record_role}"`,
        where,
      ),
    );
  }

  // Every declared canon owner must exist. A record citing canon that is not in
  // the merged tree is planning against something that has not landed.
  for (const owner of record.canon_owners ?? []) {
    const p = typeof owner === "string" ? owner : owner?.path;
    if (!p) continue;
    if (!repoFileExists(p.split("#")[0])) {
      out.push(
        finding(
          "error",
          "canon-owner-missing",
          `${id}: canon owner does not exist in this checkout: ${p}`,
          where,
        ),
      );
    }
  }

  // A verified record must carry retained evidence somewhere: either repo-path
  // evidence_refs or the record's own evidence_index. Both are real carriers in
  // this estate, so requiring only one of them would report false defects.
  if (record.status === "verified") {
    const carried = (record.evidence_refs ?? []).length +
      (record.evidence_index ?? []).length;
    if (carried === 0) {
      out.push(
        finding(
          "error",
          "work-item-proof",
          `${id}: status is verified but neither evidence_refs nor evidence_index is retained`,
          where,
        ),
      );
    }
  }

  // Aggregates never manufacture child status.
  if (record.record_role === "aggregate_exit") {
    if ((record.aggregate_child_ids ?? []).length === 0) {
      out.push(
        finding(
          "error",
          "work-item-shape",
          `${id}: aggregate_exit record names no children`,
          where,
        ),
      );
    }
  }

  return out;
}

// A record that belongs to a stage but is named by NEITHER that stage's exit
// aggregate NOR an explicit disposition is a silent dangler: the stage can reach
// `verified` without it, and nothing says that was intended. The retired 68 KB
// checker enforced this ("exactly one aggregate membership or an explicit
// disposition") and the lean rewrite carried forward only the forward direction
// — that an aggregate names SOME children — which is the weaker half.
//
// Restored 2026-08-02 after the owner ruling on apps/ioi-ai/ exposed that five
// of ten M5 records, including the cut then being built, sat outside their gate.
// Pre-existing danglers, pinned 2026-08-02. Each needs an OWNER disposition or a
// binding; neither is the implementer's to decide, and failing the program on a
// population that predates the bar is how a gate gets waived on day two instead
// of enforced on day one. Full enforcement — and the entirely absent dependency
// gate — is owned by m0-declared-relationship-enforcement-successor. This set
// only ever shrinks: a NEW dangler fails immediately.
const DANGLER_BASELINE = new Set([
  "enforcement-coverage-evidence-and-binding",
  "governance-decision-truth-repairs",
  "m0-authority-admission-census-epoch-successor",
  "m0-hold-predecessor-claim-coverage-successor",
  "m0-nonenforcing-check-closure-successor",
  "m0-overlay-member-custody-and-disposition-successor",
  "m0-owner-ratification-derived-census-successor",
  "m0-retired-campaign-claim-successor",
  "m6-hypervisor-claim-bundle-control-surface",
  "m8-context-cell-version-and-lease-enforcement-successor",
  "m8-product-memory-runtime-successor-and-scs-retirement",
  "m9-compute-substrate-canon-successor",
  "m9-hypervisor-app-primary-attach-binding-and-retirement",
  "m9-infrastructure-estate-operational-journey",
  "m9-infrastructure-profile-claim-gate",
  "m9-managed-optionality-overlay",
  "m9-shared-schema-def-consistency-successor",
  "m9-workstation-profile-claim-gate",
  "m9-workstation-virtual-machine-operational-journey",
  "mcp-receipt-effect-truth-pre-wiring",
  "p2-authority-effect-enablement-gate",
  "route-final-invoker-census-successor-after-publication-rebuild",
  "upgrade-proposal-owner-qualified-target-binding"
]);

export function aggregateMembershipFindings(records) {
  const out = [];
  const byStage = new Map();
  for (const r of records) {
    if (!r.stage_id) continue;
    if (!byStage.has(r.stage_id)) byStage.set(r.stage_id, []);
    byStage.get(r.stage_id).push(r);
  }
  for (const [stage, mine] of byStage) {
    const aggregates = mine.filter((r) => r.record_role === "aggregate_exit");
    if (aggregates.length === 0) continue;
    const claimed = new Set(aggregates.flatMap((a) => a.aggregate_child_ids ?? []));
    for (const r of mine) {
      if (r.record_role === "aggregate_exit") continue;
      if (r.record_role === "conditional_future") continue;
      if (claimed.has(r.work_item_id)) continue;
      // An EMPTY disposition field is not a disposition. Many records carry
      // `aggregate_child_dispositions: []` as a default, and an empty array is
      // truthy — measured 2026-08-02, that silently exempted 133 of 166
      // non-aggregate records, i.e. the bar reported 15 findings where it owed
      // ~148. A disposition must actually say something.
      const stated = (value) => {
        if (value === null || value === undefined) return false;
        if (Array.isArray(value)) return value.length > 0;
        if (typeof value === "object") return Object.keys(value).length > 0;
        return Boolean(value);
      };
      const declared = [
        r.aggregate_disposition,
        r.aggregate_child_dispositions,
        r.record_disposition,
      ].find(stated);
      if (declared) continue;
      if (DANGLER_BASELINE.has(r.work_item_id)) continue;
      out.push(
        finding(
          "error",
          "aggregate-membership",
          `${r.work_item_id} (${stage}) is named by no exit aggregate and declares no aggregate_disposition; ${stage} could reach verified without it`,
          { work_item_id: r.work_item_id, stage_id: stage },
        ),
      );
    }
  }
  return out;
}

function main() {
  const wanted = process.argv.slice(2).filter((a) => !a.startsWith("-"));
  const findings = [];
  const seen = new Set();
  const all = [];
  for (const rel of ["work-items/active", "work-items/proposed", "work-items"]) {
    const dir = path.join(ESTATE_ROOT, rel);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).sort()) {
      if (!f.endsWith(".v1.json") || seen.has(f)) continue;
      seen.add(f);
      const record = readJson(path.join(dir, f));
      all.push(record);
      if (wanted.length > 0 && !wanted.includes(record.work_item_id)) continue;
      findings.push(
        ...applyWaivers(validateRecord({ ...record, file: `${rel}/${f}` })),
      );
    }
  }
  if (wanted.length === 0) {
    findings.push(...applyWaivers(aggregateMembershipFindings(all)));
  }
  progress(`validated ${seen.size} record(s)`);
  process.exit(report("check-work-item-shape", findings));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
